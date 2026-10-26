#pragma once

#include <string>

// ---------------------------------------------------------------------------
// AiConsent: when the AI panel may send data, and what the user is told first.
//
// Pure functions with no windows, so the tests can check every rule:
//   - an endpoint on this PC never needs a question;
//   - an approval belongs to the exact endpoint text it was given for, and a
//     different endpoint (even after Settings changes it back and forth) is
//     asked about again;
//   - the startup connection test only runs by itself for endpoints on this PC;
//   - the question says so when a remote address uses plain http.
// ---------------------------------------------------------------------------

enum class AiSendDecision {
    Local,            // the endpoint is on this PC: send without asking
    AlreadyApproved,  // the user approved exactly this endpoint earlier this session
    NeedsApproval,    // ask first
};

// approvedEndpoint is the exact endpoint text the user approved, "" when none.
AiSendDecision DecideAiSend(const std::wstring& endpoint, const std::wstring& approvedEndpoint);

// True when the address uses plain http:// (nothing is encrypted on the way).
bool IsPlainHttpEndpoint(const std::wstring& endpoint);

// True when the program may test the endpoint at startup without asking:
// only for an endpoint on this PC.
bool ShouldTestAiEndpointAtStartup(const std::wstring& endpoint);

// The question shown before scan data goes to a remote endpoint.
std::wstring BuildRemoteSendConsentText(const std::wstring& endpoint);

// Status line and chat text when the startup test was skipped for a remote endpoint.
std::wstring StartupTestSkippedStatus();
std::wstring StartupTestSkippedChatText(const std::wstring& endpoint);
