#include "pch.h"
#include "LLMClient.h"

#include <windows.h>
#include <winhttp.h>
#include <sstream>
#include <thread>

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

// Convert wstring to UTF-8
static std::string WideToUtf8(const std::wstring& wide)
{
    if (wide.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, NULL, 0, NULL, NULL);
    if (size <= 0) return "";
    std::string result(size - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, &result[0], size, NULL, NULL);
    return result;
}

// Convert UTF-8 to wstring
static std::wstring Utf8ToWide(const std::string& utf8)
{
    if (utf8.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, NULL, 0);
    if (size <= 0) return L"";
    std::wstring result(size - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &result[0], size);
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
// Constructor
// ---------------------------------------------------------------------------
LLMClient::LLMClient() {}

void LLMClient::SetConfig(const LLMConfig& config) { m_config = config; }
const LLMConfig& LLMClient::GetConfig() const { return m_config; }
std::string LLMClient::GetLastError() const { return m_lastError; }

// ---------------------------------------------------------------------------
// BuildRequestBody — construct OpenAI-compatible JSON
// ---------------------------------------------------------------------------
std::string LLMClient::BuildRequestBody(const std::vector<LLMMessage>& messages) const
{
    std::ostringstream json;
    json << "{";
    json << "\"model\":\"" << EscapeJson(m_config.model) << "\",";
    json << "\"max_tokens\":" << m_config.maxTokens << ",";
    json << "\"temperature\":" << m_config.temperature << ",";
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
// HttpPost — WinHTTP POST request
// ---------------------------------------------------------------------------
std::string LLMClient::HttpPost(const std::wstring& url, const std::string& body)
{
    DebugLog("HttpPost to: " + WideToUtf8(url));
    DebugLog("Request body length: " + std::to_string(body.size()));

    std::string result;

    // Parse URL components
    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(URL_COMPONENTS);

    wchar_t hostName[256] = {};
    wchar_t urlPath[1024] = {};
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = 256;
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = 1024;

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &urlComp)) {
        m_lastError = "Failed to parse URL";
        DebugLog(m_lastError);
        return "";
    }

    // Open WinHTTP session
    HINTERNET hSession = WinHttpOpen(L"PhantomRecon/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

    if (!hSession) {
        m_lastError = "WinHttpOpen failed: " + std::to_string(::GetLastError());
        DebugLog(m_lastError);
        return "";
    }

    // Set timeouts (30 second connect, 60 second read for LLM responses)
    WinHttpSetTimeouts(hSession, 10000, 30000, 60000, 120000);

    // Connect to host
    HINTERNET hConnect = WinHttpConnect(hSession, hostName, urlComp.nPort, 0);
    if (!hConnect) {
        m_lastError = "WinHttpConnect failed: " + std::to_string(::GetLastError());
        DebugLog(m_lastError);
        WinHttpCloseHandle(hSession);
        return "";
    }

    // Create request
    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", urlPath,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);

    if (!hRequest) {
        m_lastError = "WinHttpOpenRequest failed: " + std::to_string(::GetLastError());
        DebugLog(m_lastError);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    // Add content type header
    WinHttpAddRequestHeaders(hRequest, L"Content-Type: application/json",
        (DWORD)-1, WINHTTP_ADDREQ_FLAG_REPLACE | WINHTTP_ADDREQ_FLAG_ADD);

    // Send request
    BOOL sendResult = WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        (LPVOID)body.c_str(), (DWORD)body.size(),
        (DWORD)body.size(), 0);

    if (!sendResult) {
        m_lastError = "WinHttpSendRequest failed: " + std::to_string(::GetLastError());
        DebugLog(m_lastError);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    // Receive response
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        m_lastError = "WinHttpReceiveResponse failed: " + std::to_string(::GetLastError());
        DebugLog(m_lastError);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    // Check status code
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(DWORD);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX);

    DebugLog("HTTP status: " + std::to_string(statusCode));

    // Read response body
    DWORD bytesAvailable = 0;
    DWORD bytesRead = 0;
    std::string responseBody;

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

    // Cleanup
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    if (statusCode != 200) {
        m_lastError = "HTTP " + std::to_string(statusCode) + ": " + responseBody;
        DebugLog(m_lastError);
        return "";
    }

    return responseBody;
}

// ---------------------------------------------------------------------------
// ParseResponse — extract assistant message from OpenAI JSON response
// Simple parser (no external JSON lib)
// ---------------------------------------------------------------------------
std::string LLMClient::ParseResponse(const std::string& responseBody)
{
    // Look for "content":"..." in the response
    // OpenAI format: { "choices": [{ "message": { "content": "..." } }] }
    const std::string marker = "\"content\":";
    size_t pos = responseBody.find(marker);
    if (pos == std::string::npos) {
        // Try alternate: "content": " (with space)
        const std::string marker2 = "\"content\": ";
        pos = responseBody.find(marker2);
        if (pos == std::string::npos) {
            m_lastError = "Could not find 'content' in response";
            DebugLog(m_lastError);
            return "";
        }
        pos += marker2.size();
    }
    else {
        pos += marker.size();
    }

    // Skip whitespace
    while (pos < responseBody.size() && (responseBody[pos] == ' ' || responseBody[pos] == '\t'))
        pos++;

    if (pos >= responseBody.size() || responseBody[pos] != '"') {
        // Might be null
        if (responseBody.substr(pos, 4) == "null") {
            return "";
        }
        m_lastError = "Unexpected content format";
        DebugLog(m_lastError);
        return "";
    }

    // Parse the JSON string (handle escapes)
    pos++; // skip opening quote
    std::string content;
    while (pos < responseBody.size()) {
        char c = responseBody[pos];
        if (c == '"') break;  // end of string
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
// SendChatCompletion — synchronous
// ---------------------------------------------------------------------------
std::string LLMClient::SendChatCompletion(const std::vector<LLMMessage>& messages)
{
    std::string body = BuildRequestBody(messages);
    std::string response = HttpPost(m_config.endpoint, body);
    if (response.empty()) return "";
    return ParseResponse(response);
}

// ---------------------------------------------------------------------------
// SendChatCompletionAsync — fire-and-forget on a thread
// ---------------------------------------------------------------------------
void LLMClient::SendChatCompletionAsync(const std::vector<LLMMessage>& messages,
                                          LLMResponseCallback callback)
{
    // Capture by value for thread safety
    std::vector<LLMMessage> msgsCopy = messages;
    std::thread([this, msgsCopy, callback]() {
        std::string result = SendChatCompletion(msgsCopy);
        if (callback) {
            callback(result, true);
        }
    }).detach();
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
// Triage prompt builders
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
