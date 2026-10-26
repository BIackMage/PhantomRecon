#include "pch.h"
#include "LLMClient.h"
#include "Redactor.h"
#include "StringConv.h"

#include <windows.h>
#include <winhttp.h>
#include <algorithm>
#include <sstream>

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

    if (host == L"localhost" || host == L"::1" || host == L"[::1]") return true;
    if (host.compare(0, 4, L"127.") == 0) return true;
    return false;
}

// ---------------------------------------------------------------------------
// BuildRequestBody: OpenAI-compatible JSON
// ---------------------------------------------------------------------------
std::string LLMClient::BuildRequestBody(const LLMConfig& config, const std::vector<LLMMessage>& messages)
{
    std::ostringstream json;
    json << "{";
    json << "\"model\":\"" << EscapeJson(config.model) << "\",";
    json << "\"max_tokens\":" << config.maxTokens << ",";
    json << "\"temperature\":" << config.temperature << ",";
    json << "\"messages\":[";

    for (size_t i = 0; i < messages.size(); i++) {
        if (i > 0) json << ",";
        json << "{\"role\":\"" << EscapeJson(messages[i].role) << "\","
             << "\"content\":\"" << EscapeJson(messages[i].content) << "\"}";
    }

    json << "]}";
    return json.str();
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

    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(DWORD);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX);
    DebugLog("HTTP status: " + std::to_string(statusCode));

    std::string responseBody;
    DWORD bytesAvailable = 0;
    DWORD bytesRead = 0;
    do {
        bytesAvailable = 0;
        WinHttpQueryDataAvailable(hRequest, &bytesAvailable);
        if (bytesAvailable > 0) {
            std::vector<char> buffer(bytesAvailable + 1, '\0');
            if (WinHttpReadData(hRequest, buffer.data(), bytesAvailable, &bytesRead)) {
                responseBody.append(buffer.data(), bytesRead);
            }
        }
    } while (bytesAvailable > 0);

    DebugLog("Response body length: " + std::to_string(responseBody.size()));

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    if (statusCode != 200) {
        SetLastError("HTTP " + std::to_string(statusCode) + ": " + responseBody);
        return "";
    }

    return responseBody;
}

// ---------------------------------------------------------------------------
// ParseResponse: extract the assistant message from the OpenAI JSON response.
// Simple scanner, no external JSON lib.
// ---------------------------------------------------------------------------
std::string LLMClient::ParseResponse(const std::string& responseBody)
{
    // OpenAI format: { "choices": [{ "message": { "content": "..." } }] }
    const std::string marker = "\"content\":";
    size_t pos = responseBody.find(marker);
    if (pos == std::string::npos) {
        const std::string marker2 = "\"content\": ";
        pos = responseBody.find(marker2);
        if (pos == std::string::npos) {
            SetLastError("Could not find 'content' in response");
            return "";
        }
        pos += marker2.size();
    }
    else {
        pos += marker.size();
    }

    while (pos < responseBody.size() && (responseBody[pos] == ' ' || responseBody[pos] == '\t'))
        pos++;

    if (pos >= responseBody.size() || responseBody[pos] != '"') {
        if (responseBody.substr(pos, 4) == "null") {
            return "";
        }
        SetLastError("Unexpected content format");
        return "";
    }

    pos++; // skip opening quote
    std::string content;
    while (pos < responseBody.size()) {
        char c = responseBody[pos];
        if (c == '"') break;
        if (c == '\\' && pos + 1 < responseBody.size()) {
            pos++;
            char next = responseBody[pos];
            switch (next) {
            case '"':  content += '"';  break;
            case '\\': content += '\\'; break;
            case 'n':  content += '\n'; break;
            case 'r':  content += '\r'; break;
            case 't':  content += '\t'; break;
            case '/':  content += '/';  break;
            default:   content += next; break;
            }
        }
        else {
            content += c;
        }
        pos++;
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

    std::string body = BuildRequestBody(config, outgoing);
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
