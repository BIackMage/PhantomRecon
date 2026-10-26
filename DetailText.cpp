#include "pch.h"
#include "DetailText.h"

#include "AppPaths.h"
#include "AttackMapping.h"
#include "FileOrigin.h"
#include "HardeningScore.h"
#include "SystemInfo.h"
#include "TextUtils.h"

#include <algorithm>
#include <sstream>

static void AddCodes(std::vector<std::wstring>& codes, const std::wstring& joined)
{
    for (const std::wstring& part : SplitW(joined, L';')) {
        std::wstring code = IndicatorCode(part);
        if (code.size() < 3) continue;   // plain sentences have no upper-case code prefix
        if (std::find(codes.begin(), codes.end(), code) == codes.end()) codes.push_back(code);
    }
}

std::vector<std::wstring> RowIndicatorCodes(const ScanRow& row)
{
    const BaselineEntry& e = row.entry;
    std::vector<std::wstring> codes;
    AddCodes(codes, e.sigWarnings);
    AddCodes(codes, e.packIndicators);
    AddCodes(codes, e.originWarnings);
    AddCodes(codes, e.peAnomalies);
    AddCodes(codes, e.scriptIndicators);
    return codes;
}

static void Line(std::wstringstream& out, const wchar_t* label, const std::wstring& value)
{
    if (TrimW(value).empty()) return;
    out << L"  " << label << L": " << value << L"\n";
}

static void ListLines(std::wstringstream& out, const wchar_t* label, const std::wstring& joined)
{
    std::vector<std::wstring> parts = SplitW(joined, L';');
    if (parts.empty()) return;
    out << L"  " << label << L":\n";
    for (const std::wstring& p : parts) out << L"    - " << p << L"\n";
}

std::wstring BuildRowDetailText(const ScanRow& row)
{
    const BaselineEntry& e = row.entry;
    std::wstringstream out;

    out << FileNameOf(e.path) << L"\n";
    out << e.path << L"\n\n";

    out << L"Result\n";
    Line(out, L"Status", row.status);
    Line(out, L"Score", FormatFixed(e.malwareScore, 1) + L" out of 10");
    if (row.riskDelta != 0.0) {
        Line(out, L"Score change since the baseline", (row.riskDelta > 0 ? L"+" : L"") + FormatFixed(row.riskDelta, 1));
    }
    Line(out, L"What changed", row.changeDetails);
    if (e.knownGood) Line(out, L"Known good", L"yes, the SHA-256 is on your known-good list");
    out << L"\n";

    out << L"Identity\n";
    Line(out, L"Size", std::to_wstring(e.fileSize) + L" bytes");
    Line(out, L"SHA-256", e.sha256);
    Line(out, L"MD5", e.md5);
    Line(out, L"Import hash (imphash)", e.imphash);
    Line(out, L"Fuzzy hash (ssdeep)", e.ssdeep);
    Line(out, L"Version", e.version);
    Line(out, L"Developer", e.developer);
    Line(out, L"Read only", e.readOnly);
    Line(out, L"Hidden", e.hidden);
    Line(out, L"Permissions", e.permissions);
    out << L"\n";

    out << L"Signature\n";
    Line(out, L"Status", e.signature);
    Line(out, L"Type", e.signatureType);
    Line(out, L"Certificate thumbprint", e.thumbprint);
    Line(out, L"Issuer", e.issuer);
    Line(out, L"Root", e.rootCA);
    Line(out, L"Catalog signer", e.catalogSigner);
    Line(out, L"Revocation", e.revocation);
    ListLines(out, L"Warnings", e.sigWarnings);
    out << L"\n";

    bool isProgram = e.totalImports > 0 || !e.packingStatus.empty() || e.peTimestamp != 0;
    if (isProgram) {
        out << L"Program structure\n";
        Line(out, L"Packing", e.packingStatus);
        Line(out, L"Entropy", FormatFixed(e.entropy, 2) + L" (8.0 is the maximum; packed or encrypted data is near it)");
        Line(out, L"Imports", std::to_wstring(e.totalImports) + L" total, " + std::to_wstring(e.suspiciousImports) +
                              L" that malware also tends to use");
        if (e.rwxSections > 0) Line(out, L"Sections that are writable and executable", std::to_wstring(e.rwxSections));
        if (e.tlsCallbacks > 0) Line(out, L"TLS callbacks", std::to_wstring(e.tlsCallbacks));
        if (e.overlaySize > 0) {
            Line(out, L"Data after the last section", std::to_wstring(e.overlaySize) + L" bytes, entropy " +
                                                     FormatFixed(e.overlayEntropy, 2));
        }
        if (e.peTimestamp != 0) Line(out, L"Build time in the header", FormatUnixTime(static_cast<long long>(e.peTimestamp)));
        Line(out, L"Debug symbols path", e.pdbPath);
        ListLines(out, L"Packing indicators", e.packIndicators);
        ListLines(out, L"Header findings", e.peAnomalies);
        out << L"\n";
    }

    if (e.zoneId >= 0 || !e.altStreams.empty() || !e.originWarnings.empty()) {
        out << L"Where it came from\n";
        if (e.zoneId >= 0) Line(out, L"Download mark (zone)", std::to_wstring(e.zoneId) + L" = " + ZoneName(e.zoneId));
        Line(out, L"Downloaded from", e.zoneHostUrl);
        Line(out, L"Linked from", e.zoneReferrerUrl);
        ListLines(out, L"Extra data streams", e.altStreams);
        ListLines(out, L"Findings", e.originWarnings);
        out << L"\n";
    }

    if (e.scriptScore > 0.0 || !e.scriptIndicators.empty()) {
        out << L"Script\n";
        Line(out, L"Script score", FormatFixed(e.scriptScore, 1) + L" out of 10");
        ListLines(out, L"Lines worth a look", e.scriptIndicators);
        out << L"\n";
    }

    std::vector<std::wstring> techniques = SplitW(e.attackIds, L',');
    if (!techniques.empty()) {
        out << L"MITRE ATT&CK techniques these findings relate to\n";
        for (const std::wstring& id : techniques) {
            std::wstring name = AttackTechniqueName(id);
            out << L"  " << id << (name.empty() ? L"" : L"  " + name) << L"\n";
        }
        out << L"\n";
    }

    std::vector<std::wstring> codes = RowIndicatorCodes(row);
    bool header = false;
    for (const std::wstring& code : codes) {
        std::wstring explanation = ExplainIndicator(code);
        if (explanation.empty()) continue;
        if (!header) {
            out << L"What the findings mean\n";
            header = true;
        }
        out << L"  " << code << L": " << explanation << L"\n";
    }
    if (header) out << L"\n";

    out << L"A finding is a reason to look, not proof of harm. Compare with the vendor's\n"
           L"published hash, or upload the SHA-256 (not the file) to a reputation service you trust.\n";
    return out.str();
}

std::wstring BuildFindingDetailText(const CheckInfo& info, const SecurityCheckResult* result)
{
    std::wstringstream out;
    out << info.title << L"\n";
    out << L"Check id: " << info.id << L"    Category: " << info.category << L"\n";
    out << L"Status: " << (result ? result->status : std::wstring(L"not run yet")) << L"    Severity: "
        << SeverityName(info.severity) << L"\n";
    if (!info.attack.empty()) {
        out << L"MITRE ATT&CK:\n";
        for (const std::wstring& id : info.attack) {
            std::wstring name = AttackTechniqueName(id);
            out << L"  " << id << (name.empty() ? L"" : L"  " + name) << L"\n";
        }
    }
    if (!info.cisControls.empty()) out << L"CIS Controls v8: " << JoinW(info.cisControls, L", ") << L"\n";
    if (!info.cisBenchmark.empty()) out << L"CIS Benchmark: " << info.cisBenchmark << L"\n";
    out << L"\n";

    if (result && !result->detail.empty()) {
        out << L"What was found\n" << result->detail << L"\n\n";
    }
    out << L"What it means\n" << info.explanation << L"\n\n";
    out << L"How to fix it\n" << info.fix << L"\n\n";
    out << L"How to undo the fix\n" << info.undo << L"\n";
    return out.str();
}

std::wstring BuildAuditFindingsText(const std::vector<SecurityCheckResult>& results)
{
    struct Item {
        const SecurityCheckResult* result;
        const CheckInfo*           info;
    };
    std::vector<Item> items;
    for (const SecurityCheckResult& r : results) {
        if (r.status != CHECK_FAIL && r.status != CHECK_WARNING) continue;
        items.push_back({ &r, FindCheckInfo(r.id) });
    }
    std::stable_sort(items.begin(), items.end(), [](const Item& a, const Item& b) {
        bool aFail = a.result->status == CHECK_FAIL;
        bool bFail = b.result->status == CHECK_FAIL;
        if (aFail != bFail) return aFail;
        int sa = a.info ? static_cast<int>(a.info->severity) : 0;
        int sb = b.info ? static_cast<int>(b.info->severity) : 0;
        return sa > sb;
    });

    HardeningScore score = ComputeHardeningScore(results);
    std::wstringstream out;
    out << L"Hardening score " << score.score << L"/100 (" << score.label << L"): " << score.pass << L" pass, "
        << score.warn << L" warning, " << score.fail << L" fail.\n\n";
    for (const Item& item : items) {
        out << L"[" << item.result->status << L"] " << item.result->name;
        if (item.info) out << L" (severity " << SeverityName(item.info->severity) << L", id " << item.info->id << L")";
        out << L"\n";
        if (!item.result->detail.empty()) {
            // The AI and the clipboard get the start of long evidence; the findings
            // window shows all of it.
            const size_t maxEvidence = 2000;
            std::wstring evidence = item.result->detail;
            if (evidence.size() > maxEvidence) {
                evidence = evidence.substr(0, maxEvidence) + L"\n(evidence shortened; the findings window shows all of it)";
            }
            out << L"Evidence: " << evidence << L"\n";
        }
        if (item.info) out << L"Meaning: " << item.info->explanation << L"\n";
        out << L"\n";
    }
    if (items.empty()) out << L"No check failed or warned.\n";
    return out.str();
}

std::wstring TimeLeftText(int processed, int total, unsigned long long startTick, unsigned long long nowTick)
{
    if (total <= 0 || processed < 20 || processed >= total || startTick == 0 || nowTick <= startTick) return L"";
    unsigned long long elapsed = nowTick - startTick;
    if (elapsed < 3000) return L"";
    unsigned long long leftMs = elapsed * static_cast<unsigned long long>(total - processed) /
                                static_cast<unsigned long long>(processed);
    unsigned long long seconds = leftMs / 1000;
    if (seconds < 60) {
        unsigned long long rounded = seconds < 5 ? 5 : (seconds + 4) / 5 * 5;   // steps of 5 so it does not flicker
        return L"About " + std::to_wstring(rounded) + L" seconds left";
    }
    unsigned long long minutes = (seconds + 30) / 60;
    if (minutes < 120) return L"About " + std::to_wstring(minutes) + (minutes == 1 ? L" minute left" : L" minutes left");
    return L"About " + std::to_wstring((minutes + 30) / 60) + L" hours left";
}

std::wstring ToWindowsLineEnds(const std::wstring& text)
{
    std::wstring out;
    out.reserve(text.size() + text.size() / 20);
    for (size_t i = 0; i < text.size(); ++i) {
        wchar_t c = text[i];
        if (c == L'\n' && (i == 0 || text[i - 1] != L'\r')) out += L'\r';
        out += c;
    }
    return out;
}
