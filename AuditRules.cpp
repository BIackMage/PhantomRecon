#include "pch.h"
#include "AuditRules.h"

#include "SecurityChecks.h"
#include "TextUtils.h"

#include <tbs.h>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[AuditRules] " + msg + L"\n").c_str());
}

// ---------------------------------------------------------------------------
// Security Center
// ---------------------------------------------------------------------------
bool SecurityCenterProductOn(unsigned long productState)
{
    bool on = ((productState >> 12) & 0xF) == 0x1;
    DebugLog(L"Security Center productState " + std::to_wstring(productState) + (on ? L" is on" : L" is off"));
    return on;
}

// ---------------------------------------------------------------------------
// Microsoft Defender
// ---------------------------------------------------------------------------
bool IsDefenderPrimaryMode(const std::wstring& amRunningMode)
{
    std::wstring mode = TrimW(amRunningMode);
    if (mode.empty()) return true;   // older builds do not report a mode
    if (ContainsI(mode, L"Normal")) return true;
    if (ContainsI(mode, L"Passive") || ContainsI(mode, L"EDR Block") || ContainsI(mode, L"Not running")) return false;
    DebugLog(L"Unknown AMRunningMode \"" + mode + L"\", judging Defender's own settings");
    return true;
}

DefenderSituation ClassifyDefender(const DefenderFacts& facts)
{
    bool primary = facts.statusOk && IsDefenderPrimaryMode(facts.runningMode);
    if (facts.otherProductOn && !primary) return DefenderSituation::OtherProduct;
    if (!facts.statusOk) return DefenderSituation::Unreadable;
    if (!primary) return DefenderSituation::PassiveNoProduct;
    DebugLog(L"Defender is the primary antivirus");
    return DefenderSituation::Primary;
}

std::wstring DefenderRealtimeStatus(const DefenderFacts& facts)
{
    DebugLog(L"Real-time gate: status " + std::wstring(facts.statusOk ? L"read" : L"unreadable") + L", Security Center " +
             (facts.securityCenterOk ? L"answered" : L"unavailable") + L", other product on " +
             (facts.otherProductOn ? L"yes" : L"no"));
    switch (ClassifyDefender(facts)) {
    case DefenderSituation::OtherProduct:
        return CHECK_PASS;
    case DefenderSituation::PassiveNoProduct:
    case DefenderSituation::Unreadable:
        // Security Center answered and lists nothing that is on: nothing is known to
        // protect this PC. Without Security Center (servers) nothing can be confirmed
        // either way, which is worth a warning but not a failure.
        return facts.securityCenterOk ? CHECK_FAIL : CHECK_WARNING;
    default:
        return L"";
    }
}

std::wstring DefenderSettingStatus(const DefenderFacts& facts)
{
    DebugLog(L"Setting gate for mode \"" + facts.runningMode + L"\"");
    return ClassifyDefender(facts) == DefenderSituation::Primary ? L"" : CHECK_NA;
}

std::wstring ControlledFolderAccessStatus(int mode, std::wstring* text)
{
    std::wstring t;
    std::wstring status;
    switch (mode) {
    case 0:
        status = CHECK_WARNING;
        t = L"Controlled folder access is off.";
        break;
    case 1:
        status = CHECK_PASS;
        t = L"Controlled folder access is on.";
        break;
    case 2:
        status = CHECK_INFO;
        t = L"Controlled folder access is in audit mode: it records what it would block.";
        break;
    case 3:
        status = CHECK_WARNING;
        t = L"Controlled folder access only blocks writes to disk sectors (mode 3). Protected folders are not guarded.";
        break;
    case 4:
        status = CHECK_WARNING;
        t = L"Controlled folder access only audits writes to disk sectors (mode 4). Protected folders are not guarded.";
        break;
    default:
        status = CHECK_WARNING;
        t = L"Controlled folder access reports an unknown mode (" + std::to_wstring(mode) + L").";
        break;
    }
    if (text) *text = t;
    DebugLog(L"Controlled folder access mode " + std::to_wstring(mode) + L" -> " + status);
    return status;
}

// ---------------------------------------------------------------------------
// UAC
// ---------------------------------------------------------------------------
bool UacUsesSecureDesktop(DWORD consentPromptBehaviorAdmin, DWORD promptOnSecureDesktop)
{
    bool secure = consentPromptBehaviorAdmin == 1 || consentPromptBehaviorAdmin == 2 || promptOnSecureDesktop != 0;
    DebugLog(L"UAC consent " + std::to_wstring(consentPromptBehaviorAdmin) + L", PromptOnSecureDesktop " +
             std::to_wstring(promptOnSecureDesktop) + (secure ? L" -> secure desktop" : L" -> normal desktop"));
    return secure;
}

// ---------------------------------------------------------------------------
// TPM
// ---------------------------------------------------------------------------
TbsOutcome ClassifyTbsResult(unsigned long tbsResult)
{
    DebugLog(L"TBS result " + std::to_wstring(tbsResult));
    switch (tbsResult) {
    case TBS_SUCCESS:
        return TbsOutcome::Present;
    case TBS_E_TPM_NOT_FOUND:
        return TbsOutcome::NoTpm;
    case TBS_E_SERVICE_NOT_RUNNING:
    case TBS_E_SERVICE_DISABLED:
    case TBS_E_SERVICE_START_PENDING:
        return TbsOutcome::ServiceUnavailable;
    default:
        return TbsOutcome::Error;
    }
}

std::wstring TpmStatusWithoutTbs(int tpmDriverDevices)
{
    DebugLog(L"TBS unavailable, TPM driver devices " + std::to_wstring(tpmDriverDevices));
    if (tpmDriverDevices == 0) return CHECK_FAIL;
    return CHECK_WARNING;
}

// ---------------------------------------------------------------------------
// Credential Guard
// ---------------------------------------------------------------------------
EditionSupport CredentialGuardEditionSupport(const std::wstring& editionIdIn)
{
    std::wstring e = ToLowerW(TrimW(editionIdIn));
    DebugLog(L"Credential Guard edition check for \"" + e + L"\"");
    if (e.empty()) return EditionSupport::Unknown;
    if (e.rfind(L"core", 0) == 0) return EditionSupport::NotSupported;   // Home, Home N, single language, China
    if (e.rfind(L"professionaleducation", 0) == 0) return EditionSupport::Supported;
    if (e.rfind(L"professionalworkstation", 0) == 0) return EditionSupport::Unknown;
    if (e == L"professional" || e == L"professionaln" || e == L"professionalcountryspecific" ||
        e == L"professionalsinglelanguage") {
        return EditionSupport::NotSupported;
    }
    if (e.rfind(L"enterprise", 0) == 0 || e.rfind(L"education", 0) == 0 || e.rfind(L"server", 0) == 0 ||
        e.rfind(L"iotenterprise", 0) == 0) {
        return EditionSupport::Supported;
    }
    return EditionSupport::Unknown;
}

// ---------------------------------------------------------------------------
// WPAD
// ---------------------------------------------------------------------------
std::wstring WpadStatus(bool settingsSaved, bool autoDetect, bool autoProxyServiceDisabled)
{
    DebugLog(L"WPAD saved " + std::to_wstring(settingsSaved) + L", auto-detect " + std::to_wstring(autoDetect) +
             L", service disabled " + std::to_wstring(autoProxyServiceDisabled));
    if (!settingsSaved) return CHECK_WARNING;   // the Windows default is detection on
    if (autoDetect && !autoProxyServiceDisabled) return CHECK_FAIL;
    if (autoDetect) return CHECK_WARNING;
    return CHECK_PASS;
}

// ---------------------------------------------------------------------------
// Security event log size
// ---------------------------------------------------------------------------
LogSize EffectiveSecurityLogSize(const LogSizeFacts& facts)
{
    LogSize size;
    if (facts.policyKb.set) {
        size.known = true;
        size.bytes = static_cast<unsigned long long>(facts.policyKb.value) * 1024ull;
        size.source = L"Group Policy";
    }
    else if (facts.channelKnown) {
        size.known = true;
        size.bytes = facts.channelBytes;
        size.source = L"log settings";
    }
    else if (facts.legacyBytes.set) {
        size.known = true;
        size.bytes = facts.legacyBytes.value;
        size.source = L"registry";
    }
    DebugLog(L"Security log size " +
             (size.known ? std::to_wstring(size.bytes) + L" bytes from " + size.source : std::wstring(L"unknown")));
    return size;
}

// ---------------------------------------------------------------------------
// Remote Desktop
// ---------------------------------------------------------------------------
RdpState EffectiveRdp(const RdpFacts& facts)
{
    RdpState state;
    if (facts.policyDeny.set) {
        state.enabled = facts.policyDeny.value == 0;
        state.enabledByPolicy = true;
    }
    else if (facts.localDeny.set) {
        state.enabled = facts.localDeny.value == 0;
    }
    if (facts.policyNla.set) {
        state.nlaRequired = facts.policyNla.value == 1;
        state.nlaByPolicy = true;
    }
    else if (facts.localNla.set) {
        state.nlaRequired = facts.localNla.value == 1;
    }
    DebugLog(L"RDP enabled " + std::to_wstring(state.enabled) + L" (policy " + std::to_wstring(state.enabledByPolicy) +
             L"), NLA " + std::to_wstring(state.nlaRequired) + L" (policy " + std::to_wstring(state.nlaByPolicy) + L")");
    return state;
}

// ---------------------------------------------------------------------------
// WinRM
// ---------------------------------------------------------------------------
std::wstring WinRmStatus(bool running, bool autoStart, int listeners, bool policyListeners)
{
    DebugLog(L"WinRM running " + std::to_wstring(running) + L", auto start " + std::to_wstring(autoStart) +
             L", listeners " + std::to_wstring(listeners) + L", policy listeners " + std::to_wstring(policyListeners));
    if (!running && !autoStart) return CHECK_PASS;   // nothing can accept a connection
    if (listeners > 0 || policyListeners) return CHECK_WARNING;
    if (listeners < 0) return CHECK_WARNING;          // could not see the listeners: do not claim it is closed
    return CHECK_PASS;
}

// ---------------------------------------------------------------------------
// Built-in Administrator
// ---------------------------------------------------------------------------
bool IsDefaultAdministratorName(const std::wstring& nameIn, const std::wstring& administratorsGroupName)
{
    std::wstring name = ToLowerW(TrimW(nameIn));
    DebugLog(L"Built-in Administrator name \"" + name + L"\", group \"" + administratorsGroupName + L"\"");
    if (name.empty()) return false;
    // Default names of the RID 500 account in Windows display languages. Written as
    // escapes so the source stays ASCII.
    static const wchar_t* const defaults[] = {
        L"administrator",                                                     // English, German, Dutch, Polish, ...
        L"administrateur",                                                    // French
        L"administrador",                                                     // Spanish, Portuguese
        L"amministratore",                                                    // Italian
        L"administrat\x00f6r",                                                // Swedish
        L"j\x00e4rjestelm\x00e4nvalvoja",                                     // Finnish
        L"rendszergazda",                                                     // Hungarian
        L"\x0430\x0434\x043c\x0438\x043d\x0438\x0441\x0442\x0440\x0430\x0442\x043e\x0440",   // Russian
        L"\x0430\x0434\x043c\x0456\x043d\x0456\x0441\x0442\x0440\x0430\x0442\x043e\x0440",   // Ukrainian
        L"\x03b4\x03b9\x03b1\x03c7\x03b5\x03b9\x03c1\x03b9\x03c3\x03c4\x03ae\x03c2",        // Greek
    };
    for (const wchar_t* d : defaults) {
        if (name == d) return true;
    }
    // Most languages name the group as the plural of the account
    // ("Administrateurs" / "Administrateur", "Administradores" / "Administrador").
    std::wstring group = ToLowerW(TrimW(administratorsGroupName));
    if (name.size() >= 5 && group.size() > name.size() && group.size() - name.size() <= 3 &&
        group.compare(0, name.size(), name) == 0) {
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Windows Firewall
// ---------------------------------------------------------------------------
std::wstring FirewallStatus(bool anyProfileOff, bool anyInboundAllowed, bool thirdPartyOn)
{
    DebugLog(L"Firewall profile off " + std::to_wstring(anyProfileOff) + L", inbound allowed " +
             std::to_wstring(anyInboundAllowed) + L", third-party firewall on " + std::to_wstring(thirdPartyOn));
    if ((anyProfileOff || anyInboundAllowed) && thirdPartyOn) return CHECK_NA;
    if (anyProfileOff || anyInboundAllowed) return CHECK_FAIL;
    return CHECK_PASS;
}
