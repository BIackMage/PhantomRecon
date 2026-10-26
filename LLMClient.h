#pragma once

#include <mutex>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// LLMClient: OpenAI-compatible chat completions over WinHTTP.
//
// Blocking only. Callers run it on the shared BackgroundWorker and post the
// result back to the UI (see AiSidebar.cpp). There is no detached async path.
//
// Thread safety: SetConfig / GetConfig / GetLastError are guarded, so the UI
// thread may change settings while a request is in flight on a worker. A
// request copies the config once when it starts.
// ---------------------------------------------------------------------------

// Default endpoint is the local machine only (LM Studio / Ollama style server on
// port 1234). Scan data never leaves the host unless the user changes this in Settings.
// This is the single source of truth for the default; AppSettings copies it.
struct LLMConfig {
    std::wstring endpoint = L"http://localhost:1234/v1/chat/completions";
    std::string  model    = "local-model";
    int          maxTokens = 2048;
    double       temperature = 0.3;  // Low temperature for factual analysis
};

struct LLMMessage {
    std::string role;     // "system", "user", "assistant"
    std::string content;
};

class LLMClient {
public:
    LLMClient() = default;
    LLMClient(const LLMClient&) = delete;
    LLMClient& operator=(const LLMClient&) = delete;

    void      SetConfig(const LLMConfig& config);
    LLMConfig GetConfig() const;

    // Send a chat completion request and block for the reply.
    // Returns the assistant's text, or an empty string on error (see GetLastError).
    std::string SendChatCompletion(const std::vector<LLMMessage>& messages);

    // Last error message from this client.
    std::string GetLastError() const;

    // Send a tiny prompt and report whether anything came back.
    bool TestConnection();

private:
    mutable std::mutex m_mutex;
    LLMConfig          m_config;
    std::string        m_lastError;

    void SetLastError(const std::string& error);

    static std::string BuildRequestBody(const LLMConfig& config, const std::vector<LLMMessage>& messages);
    std::string HttpPost(const std::wstring& url, const std::string& body);
    std::string ParseResponse(const std::string& responseBody);
};

// Global singleton
LLMClient& GetLLMClient();

// True when the URL's host is this machine (localhost, 127.x.x.x, ::1).
// Used by the sidebar to decide whether to ask before sending scan data.
bool IsLoopbackEndpoint(const std::wstring& url);

// ---------------------------------------------------------------------------
// Prompt builders
// ---------------------------------------------------------------------------

// Triage request for one file's scan results.
std::string BuildTriagePrompt(const std::wstring& filePath, double malwareScore,
    const std::wstring& signature, const std::wstring& packingStatus,
    int suspiciousImports, const std::wstring& sigWarnings,
    const std::wstring& packIndicators, double entropy);

// Summary request for a whole scan.
std::string BuildScanSummaryPrompt(int totalFiles, int totalExecutables,
    int highRiskCount, int newFiles, int changedFiles, int missingFiles);

// Explanation request for the posture audit text.
std::string BuildSecurityAuditPrompt(const std::string& auditSummary);
