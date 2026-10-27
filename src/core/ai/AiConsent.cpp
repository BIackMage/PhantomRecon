#include "pch.h"
#include "AiConsent.h"

#include "DebugTrace.h"
#include "LLMClient.h"
#include "TextUtils.h"

AiSendDecision DecideAiSend(const std::wstring& endpoint, const std::wstring& approvedEndpoint)
{
    AiSendDecision decision = AiSendDecision::NeedsApproval;
    if (IsLoopbackEndpoint(endpoint)) {
        decision = AiSendDecision::Local;
    }
    else if (!approvedEndpoint.empty() && approvedEndpoint == endpoint) {
        decision = AiSendDecision::AlreadyApproved;
    }
    Trace(L"AiConsent", L"DecideAiSend " + endpoint + L": " +
        (decision == AiSendDecision::Local ? L"local"
         : decision == AiSendDecision::AlreadyApproved ? L"approved earlier" : L"ask first"));
    return decision;
}

bool IsPlainHttpEndpoint(const std::wstring& endpoint)
{
    bool plain = StartsWithI(TrimW(endpoint), L"http://");
    Trace(L"AiConsent", L"IsPlainHttpEndpoint " + endpoint + (plain ? L": yes" : L": no"));
    return plain;
}

bool ShouldTestAiEndpointAtStartup(const std::wstring& endpoint)
{
    bool local = IsLoopbackEndpoint(endpoint);
    Trace(L"AiConsent", L"ShouldTestAiEndpointAtStartup " + endpoint + (local ? L": yes (this PC)" : L": no (remote)"));
    return local;
}

std::wstring BuildRemoteSendConsentText(const std::wstring& endpoint)
{
    std::wstring text =
        L"The AI endpoint is not on this machine:\n\n" + endpoint + L"\n\n"
        L"Scan data will be sent there. That includes file paths, which can contain "
        L"user names and other details about this host.\n\n";
    if (IsPlainHttpEndpoint(endpoint)) {
        text += L"This address uses plain http://, so the data travels unencrypted. Anyone on the "
                L"network between this PC and the server can read it. Use an https:// address if "
                L"the server supports it.\n\n";
    }
    text += L"Send anyway? You will not be asked again for this address until the program closes. "
            L"If the address changes, you will be asked again.";
    Trace(L"AiConsent", L"BuildRemoteSendConsentText for " + endpoint);
    return text;
}

std::wstring StartupTestSkippedStatus()
{
    Trace(L"AiConsent", L"StartupTestSkippedStatus");
    return L"  Not tested (remote server)";
}

std::wstring StartupTestSkippedChatText(const std::wstring& endpoint)
{
    Trace(L"AiConsent", L"StartupTestSkippedChatText for " + endpoint);
    return L"[Info]: The AI address is not on this PC, so it was not contacted at startup:\r\n" + endpoint +
           L"\r\nTo check it, use Test Connection in File > Settings > AI panel.\r\n";
}
