#pragma once

#include <string>
#include <vector>
#include <functional>

// ---------------------------------------------------------------------------
// LLMClient — OpenAI-compatible API client for LLM triage/analysis.
// Sends scan data to a networked LLM endpoint for threat assessment.
// Uses WinHTTP for HTTP POST requests.
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

// Callback for streaming responses (called on background thread)
using LLMResponseCallback = std::function<void(const std::string& chunk, bool isDone)>;

class LLMClient {
public:
    LLMClient();

    // Configure the endpoint
    void SetConfig(const LLMConfig& config);
    const LLMConfig& GetConfig() const;

    // Send a chat completion request (blocking).
    // Returns the assistant's response, or empty string on error.
    std::string SendChatCompletion(const std::vector<LLMMessage>& messages);

    // Send a chat completion request (async, calls callback on response).
    void SendChatCompletionAsync(const std::vector<LLMMessage>& messages,
                                  LLMResponseCallback callback);

    // Get the last error message
    std::string GetLastError() const;

    // Check if the endpoint is reachable
    bool TestConnection();

private:
    LLMConfig m_config;
    std::string m_lastError;

    // Build the JSON request body
    std::string BuildRequestBody(const std::vector<LLMMessage>& messages) const;

    // Perform HTTP POST and return response body
    std::string HttpPost(const std::wstring& url, const std::string& body);

    // Parse the response JSON to extract the assistant message
    std::string ParseResponse(const std::string& responseBody);
};

// Global singleton
LLMClient& GetLLMClient();

// ---------------------------------------------------------------------------
// Helper: build a triage prompt from scan data
// ---------------------------------------------------------------------------

// Generate a triage request for a specific file's scan results
std::string BuildTriagePrompt(const std::wstring& filePath, double malwareScore,
    const std::wstring& signature, const std::wstring& packingStatus,
    int suspiciousImports, const std::wstring& sigWarnings,
    const std::wstring& packIndicators, double entropy);

// Generate a summary analysis prompt for the entire scan
std::string BuildScanSummaryPrompt(int totalFiles, int totalExecutables,
    int highRiskCount, int newFiles, int changedFiles, int missingFiles);

// Generate a security audit analysis prompt
std::string BuildSecurityAuditPrompt(const std::string& auditSummary);
