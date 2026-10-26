#include "pch.h"
#include "LLMClient.h"
#include "JsonReader.h"
#include "Redactor.h"
#include "StringConv.h"

#include <windows.h>
#include <winhttp.h>
#include <algorithm>
#include <charconv>
#include <cmath>
#include <sstream>
#include <system_error>

#pragma comment(lib, "winhttp.lib")

// ---------------------------------------------------------------------------
// Debug logging
// ---------------------------------------------------------------------------
static void DebugLog(const char* msg)
{
    OutputDebugStringA("[LLMClient] ");
    OutputDebugStringA(msg);
    OutputDebugStringA("\n");
}

static void DebugLog(const std::string& msg) { DebugLog(msg.c_str()); }

// ---------------------------------------------------------------------------
// Simple JSON string escaping (no external JSON library)
// ---------------------------------------------------------------------------
static std::string EscapeJson(const std::string& s)
{
    std::string result;
    result.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
        case '"':  result += "\\\""; break;
        case '\\': result += "\\\\"; break;
        case '\n': result += "\\n";  break;
        case '\r': result += "\\r";  break;
        case '\t': result += "\\t";  break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", c);
                result += buf;
            }
            else {
                result += c;
            }
            break;
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------
LLMClient& GetLLMClient()
{
    static LLMClient instance;
    return instance;
}

// ---------------------------------------------------------------------------
// Config and error access (guarded)
// ---------------------------------------------------------------------------
void LLMClient::SetConfig(const LLMConfig& config)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_config = config;
}

LLMConfig LLMClient::GetConfig() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config;
}

std::string LLMClient::GetLastError() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_lastError;
}

void LLMClient::SetLastError(const std::string& error)
{
    DebugLog(error);
    std::lock_guard<std::mutex> lock(m_mutex);
    m_lastError = error;
}

// ---------------------------------------------------------------------------
// IsLoopbackEndpoint
// ---------------------------------------------------------------------------
bool IsLoopbackIPv4Literal(const std::wstring& host)
{
    // Parsed, not prefix-matched: "127.attacker.example" is a name that DNS can
    // point anywhere, and "127.1" or "0127.0.0.1" are spellings resolvers read in
    // different ways. Only the plain dotted quad counts.
    int parts[4] = {};
    int count = 0;
    size_t pos = 0;
    while (true) {
        size_t dot = host.find(L'.', pos);
        std::wstring part = host.substr(pos, dot == std::wstring::npos ? std::wstring::npos : dot - pos);
        if (count >= 4 || part.empty() || part.size() > 3) return false;
        if (part.size() > 1 && part[0] == L'0') return false;
        int value = 0;
        for (wchar_t c : part) {
            if (c < L'0' || c > L'9') return false;
            value = value * 10 + (c - L'0');
        }
        if (value > 255) return false;
        parts[count++] = value;
        if (dot == std::wstring::npos) break;
        pos = dot + 1;
    }
    return count == 4 && parts[0] == 127;
}

bool IsLoopbackEndpoint(const std::wstring& url)
{
    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(URL_COMPONENTS);

    wchar_t hostName[256] = {};
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = 256;

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &urlComp)) {
        return false;
    }

    std::wstring host(hostName, urlComp.dwHostNameLength);
    std::transform(host.begin(), host.end(), host.begin(), ::towlower);

    bool loopback = host == L"localhost" || host == L"::1" || host == L"[::1]" || IsLoopbackIPv4Literal(host);
    DebugLog("IsLoopbackEndpoint: host " + WideToUtf8(host) + (loopback ? " is this PC" : " is not this PC"));
    return loopback;
}

// ---------------------------------------------------------------------------
// BuildChatRequestJson: OpenAI-compatible JSON
// ---------------------------------------------------------------------------
std::string BuildChatRequestJson(const LLMConfig& config, const std::vector<LLMMessage>& messages)
{
    const LLMConfig defaults;
    double temperature = config.temperature;
    if (!std::isfinite(temperature)) {
        DebugLog("Temperature is not a finite number; the default is sent instead");
        temperature = defaults.temperature;
    }
    temperature = (std::min)(2.0, (std::max)(0.0, temperature));
    int maxTokens = config.maxTokens > 0 ? config.maxTokens : defaults.maxTokens;

    // to_chars never uses the C locale, so the decimal point is always '.'.
    char number[32] = {};
    auto written = std::to_chars(number, number + sizeof(number) - 1, temperature, std::chars_format::fixed, 3);
    std::string temperatureText = written.ec == std::errc() ? std::string(number, written.ptr) : std::string("0.3");

    std::string json;
    json += "{";
    json += "\"model\":\"" + EscapeJson(config.model) + "\",";
    json += "\"max_tokens\":" + std::to_string(maxTokens) + ",";
    json += "\"temperature\":" + temperatureText + ",";
    json += "\"messages\":[";
    for (size_t i = 0; i < messages.size(); i++) {
        if (i > 0) json += ",";
        json += "{\"role\":\"" + EscapeJson(messages[i].role) + "\","
                "\"content\":\"" + EscapeJson(messages[i].content) + "\"}";
    }
    json += "]}";
    return json;
}

// ---------------------------------------------------------------------------
// HttpPost: WinHTTP POST request
// ---------------------------------------------------------------------------
// Plain words for the WinHTTP errors people actually hit, with the code kept for support.
static std::string WinHttpErrorText(const char* step, DWORD code)
{
    std::string text;
    switch (code) {
    case ERROR_WINHTTP_CANNOT_CONNECT:
        text = "Could not connect to the AI server. Is it running? The address is in File > Settings > AI panel.";
        break;
    case ERROR_WINHTTP_TIMEOUT:
        text = "The AI server did not answer in time.";
        break;
    case ERROR_WINHTTP_NAME_NOT_RESOLVED:
        text = "The AI server's name could not be found. Check the address in File > Settings > AI panel.";
        break;
    case ERROR_WINHTTP_SECURE_FAILURE:
        text = "The secure (HTTPS) connection to the AI server failed. Its certificate may be invalid.";
        break;
    case ERROR_WINHTTP_CONNECTION_ERROR:
        text = "The connection to the AI server was closed before it answered.";
        break;
    case ERROR_WINHTTP_INVALID_SERVER_RESPONSE:
        text = "The AI server sent an answer that is not valid HTTP.";
        break;
    default:
        text = std::string(step) + " failed.";
        break;
    }
    return text + " (WinHTTP error " + std::to_string(code) + ")";
}

std::string LLMClient::HttpPost(const std::wstring& url, const std::string& body)
{
    DebugLog("HttpPost to: " + WideToUtf8(url));
    DebugLog("Request body length: " + std::to_string(body.size()));

    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(URL_COMPONENTS);

    wchar_t hostName[256] = {};
    wchar_t urlPath[1024] = {};
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = 256;
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = 1024;

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &urlComp)) {
        SetLastError("Failed to parse URL");
        return "";
    }

    HINTERNET hSession = WinHttpOpen(L"PhantomRecon/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        SetLastError(WinHttpErrorText("Starting the web client", ::GetLastError()));
        return "";
    }

    // Resolve 10s, connect 30s, send 60s, receive 120s (LLM replies can be slow)
    WinHttpSetTimeouts(hSession, 10000, 30000, 60000, 120000);

    HINTERNET hConnect = WinHttpConnect(hSession, hostName, urlComp.nPort, 0);
    if (!hConnect) {
        SetLastError(WinHttpErrorText("Connecting", ::GetLastError()));
        WinHttpCloseHandle(hSession);
        return "";
    }

    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", urlPath,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        SetLastError(WinHttpErrorText("Preparing the request", ::GetLastError()));
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    WinHttpAddRequestHeaders(hRequest, L"Content-Type: application/json",
        (DWORD)-1, WINHTTP_ADDREQ_FLAG_REPLACE | WINHTTP_ADDREQ_FLAG_ADD);

    BOOL sendResult = WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        (LPVOID)body.c_str(), (DWORD)body.size(),
        (DWORD)body.size(), 0);
    if (!sendResult) {
        SetLastError(WinHttpErrorText("Sending the request", ::GetLastError()));
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        SetLastError(WinHttpErrorText("Reading the answer", ::GetLastError()));
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    auto closeAll = [&]() {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
    };

    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(DWORD);
    if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX)) {
        SetLastError(WinHttpErrorText("Reading the answer's status code", ::GetLastError()));
        closeAll();
        return "";
    }
    DebugLog("HTTP status: " + std::to_string(statusCode));

    // The status decides how much is read: a whole answer up to the cap, or only the
    // start of an error page for the message.
    const bool success = statusCode == 200;
    const size_t limit = success ? kMaxAiReplyBytes : kMaxAiErrorBytes;
    std::string responseBody;
    bool overLimit = false;
    while (true) {
        DWORD bytesAvailable = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &bytesAvailable)) {
            SetLastError(WinHttpErrorText("Reading the answer", ::GetLastError()));
            closeAll();
            return "";
        }
        if (bytesAvailable == 0) break;
        if (responseBody.size() >= limit) {
            overLimit = true;
            break;
        }
        DWORD want = static_cast<DWORD>((std::min)({ static_cast<size_t>(bytesAvailable), limit - responseBody.size(),
                                                     static_cast<size_t>(64 * 1024) }));
        std::vector<char> buffer(want);
        DWORD bytesRead = 0;
        if (!WinHttpReadData(hRequest, buffer.data(), want, &bytesRead)) {
            SetLastError(WinHttpErrorText("Reading the answer", ::GetLastError()));
            closeAll();
            return "";
        }
        if (bytesRead == 0) break;
        responseBody.append(buffer.data(), bytesRead);
    }

    DebugLog("Response body length: " + std::to_string(responseBody.size()) + (overLimit ? " (more not read)" : ""));
    closeAll();

    if (!success) {
        SetLastError("HTTP " + std::to_string(statusCode) + ": " + responseBody + (overLimit ? " [...]" : ""));
        return "";
    }
    if (overLimit) {
        SetLastError("The AI server's answer is larger than " + std::to_string(kMaxAiReplyBytes / (1024 * 1024)) +
                     " MB, so it was not read.");
        return "";
    }
    if (responseBody.empty()) SetLastError("The AI server sent an empty answer.");
    return responseBody;
}

// ---------------------------------------------------------------------------
// ParseResponse: extract the assistant message from the OpenAI JSON response.
// Simple scanner, no external JSON lib.
// ---------------------------------------------------------------------------
bool ExtractChatReply(const std::string& responseBody, std::string& content, std::string& error)
{
    content.clear();
    error.clear();

    JsonValue root;
    std::string parseError;
    if (!ParseJson(responseBody, root, parseError)) {
        error = "The AI server's answer is not valid JSON (" + parseError + ").";
        return false;
    }
    if (!root.IsObject()) {
        error = "The AI server's answer is not a JSON object.";
        return false;
    }

    // An "error" member wins over anything else in the answer.
    const JsonValue* err = root.Find("error");
    if (err && !err->IsNull()) {
        std::string message;
        if (err->IsString()) message = err->text;
        else if (const JsonValue* m = err->Find("message")) message = m->IsString() ? m->text : "";
        error = "The AI server reported an error: " + (message.empty() ? std::string("no message given") : message);
        return false;
    }

    // { "choices": [ { "message": { "content": "..." } } ] }, read at that exact place only.
    const JsonValue* choices = root.Find("choices");
    const JsonValue* first = choices ? choices->At(0) : nullptr;
    if (!first || !first->IsObject()) {
        error = "The AI server's answer has no choices.";
        return false;
    }
    const JsonValue* message = first->Find("message");
    const JsonValue* value = (message && message->IsObject()) ? message->Find("content") : nullptr;
    if (!value) value = first->Find("text");   // older completions format
    if (!value) {
        error = "The AI server's answer has no message content.";
        return false;
    }

    if (value->IsString()) {
        content = value->text;
    }
    else if (value->IsArray()) {
        // Content as a list of parts: [{ "type": "text", "text": "..." }, ...]
        for (const JsonValue& part : value->items) {
            if (part.IsString()) content += part.text;
            else if (const JsonValue* t = part.Find("text")) {
                if (t->IsString()) content += t->text;
            }
        }
    }
    else if (!value->IsNull()) {
        error = "The AI server's message content is not text.";
        return false;
    }

    if (content.empty()) {
        error = "The AI server sent an empty answer.";
        return false;
    }
    return true;
}

std::string LLMClient::ParseResponse(const std::string& responseBody)
{
    std::string content;
    std::string error;
    if (!ExtractChatReply(responseBody, content, error)) {
        SetLastError(error);
        return "";
    }
    DebugLog("Parsed content length: " + std::to_string(content.size()));
    return content;
}

// ---------------------------------------------------------------------------
// SendChatCompletion
// ---------------------------------------------------------------------------
std::string LLMClient::SendChatCompletion(const std::vector<LLMMessage>& messages)
{
    LLMConfig config = GetConfig();   // one snapshot for the whole request

    // Redact and cap every message before it leaves the process, even for localhost.
    std::vector<LLMMessage> outgoing = messages;
    for (LLMMessage& m : outgoing) {
        std::wstring text = Utf8ToWide(m.content);
        if (config.redact) text = RedactText(text);
        size_t cap = config.maxPromptChars > 200 ? static_cast<size_t>(config.maxPromptChars) : 200;
        if (text.size() > cap) text = text.substr(0, cap) + L"\n[truncated by Phantom Recon]";
        m.content = WideToUtf8(text);
    }

    std::string body = BuildChatRequestJson(config, outgoing);
    std::string response = HttpPost(config.endpoint, body);
    if (response.empty()) return "";
    return ParseResponse(response);
}

// ---------------------------------------------------------------------------
// TestConnection
// ---------------------------------------------------------------------------
bool LLMClient::TestConnection()
{
    DebugLog("Testing connection to LLM endpoint");

    std::vector<LLMMessage> testMsgs = {
        { "user", "Reply with exactly: OK" }
    };

    std::string response = SendChatCompletion(testMsgs);
    bool ok = !response.empty();
    DebugLog(ok ? "Connection test: SUCCESS" : "Connection test: FAILED");
    return ok;
}

// ---------------------------------------------------------------------------
// Prompt builders
// ---------------------------------------------------------------------------
std::string BuildTriagePrompt(const std::wstring& filePath, double malwareScore,
    const std::wstring& signature, const std::wstring& packingStatus,
    int suspiciousImports, const std::wstring& sigWarnings,
    const std::wstring& packIndicators, double entropy)
{
    std::ostringstream prompt;
    prompt << "Analyze this file scan result from an endpoint security scanner. "
           << "Provide a threat assessment, explain what the indicators mean, "
           << "and recommend actions.\n\n";
    prompt << "File: " << WideToUtf8(filePath) << "\n";
    prompt << "Malware Score: " << malwareScore << "/10\n";
    prompt << "Signature: " << WideToUtf8(signature) << "\n";
    prompt << "Packing Status: " << WideToUtf8(packingStatus) << "\n";
    prompt << "Suspicious Imports: " << suspiciousImports << "\n";
    prompt << "Entropy: " << entropy << "\n";

    if (!sigWarnings.empty()) {
        prompt << "Signature Warnings: " << WideToUtf8(sigWarnings) << "\n";
    }
    if (!packIndicators.empty()) {
        prompt << "Packing Indicators: " << WideToUtf8(packIndicators) << "\n";
    }

    prompt << "\nProvide:\n"
           << "1. Threat level assessment (Critical/High/Medium/Low/Clean)\n"
           << "2. Explanation of what each indicator means\n"
           << "3. Whether this is likely malicious, suspicious, or benign\n"
           << "4. Recommended actions (quarantine, investigate, ignore, etc.)\n";

    return prompt.str();
}

std::string BuildScanSummaryPrompt(int totalFiles, int totalExecutables,
    int highRiskCount, int newFiles, int changedFiles, int missingFiles)
{
    std::ostringstream prompt;
    prompt << "Summarize and assess the results of an endpoint security scan:\n\n";
    prompt << "Total files scanned: " << totalFiles << "\n";
    prompt << "Executable files analyzed: " << totalExecutables << "\n";
    prompt << "High-risk files (score >= 7.0): " << highRiskCount << "\n";
    prompt << "New files (not in baseline): " << newFiles << "\n";
    prompt << "Changed files (modified since baseline): " << changedFiles << "\n";
    prompt << "Missing files (in baseline but gone): " << missingFiles << "\n\n";
    prompt << "Provide:\n"
           << "1. Overall risk assessment of the endpoint\n"
           << "2. Priority items to investigate\n"
           << "3. Recommended immediate actions\n"
           << "4. Recommendations for hardening\n";

    return prompt.str();
}

std::string BuildSecurityAuditPrompt(const std::string& auditSummary)
{
    std::ostringstream prompt;
    prompt << "Analyze this Windows endpoint security audit report. "
           << "Explain each finding, assess overall posture, "
           << "and provide prioritized remediation steps.\n\n";
    prompt << auditSummary << "\n\n";
    prompt << "Provide:\n"
           << "1. Overall security posture rating (Critical/Poor/Fair/Good/Excellent)\n"
           << "2. Top 3 most critical issues to fix immediately\n"
           << "3. Detailed remediation steps for each FAIL finding\n"
           << "4. Quick wins for improvement\n";

    return prompt.str();
}
