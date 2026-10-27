#include "pch.h"
#include "ScriptAnalysis.h"

#include "AppPaths.h"
#include "AttackMapping.h"
#include "FileAnalysis.h"
#include "FileIO.h"
#include "TextUtils.h"

#include <windows.h>
#include <wincrypt.h>
#include <algorithm>
#include <cmath>

#pragma comment(lib, "crypt32.lib")

bool IsScriptExtension(const std::wstring& ext)
{
    const wchar_t* exts[] = { L".ps1", L".psm1", L".psd1", L".bat", L".cmd", L".vbs", L".vbe",
                              L".js", L".jse", L".wsf", L".wsh", L".wsc", L".hta" };
    for (const wchar_t* e : exts) {
        if (ext == e) return true;
    }
    return false;
}

enum LangMask : unsigned {
    LANG_PS   = 1,
    LANG_BAT  = 2,
    LANG_VBS  = 4,
    LANG_JS   = 8,
    LANG_HTA  = 16,
    LANG_ANY  = 31,
};

static unsigned LanguageOf(const std::wstring& ext)
{
    if (ext == L".ps1" || ext == L".psm1" || ext == L".psd1") return LANG_PS;
    if (ext == L".bat" || ext == L".cmd") return LANG_BAT;
    if (ext == L".vbs" || ext == L".vbe") return LANG_VBS;
    if (ext == L".js" || ext == L".jse") return LANG_JS;
    if (ext == L".hta" || ext == L".wsf" || ext == L".wsh" || ext == L".wsc") return LANG_HTA | LANG_VBS | LANG_JS;
    return LANG_ANY;
}

struct Pattern {
    const wchar_t* code;
    const wchar_t* needle;     // lowercase
    double         weight;
    unsigned       languages;
};

// Any match of the needle (case-insensitive) raises the code once.
static const Pattern kPatterns[] = {
    { L"ENCODED_COMMAND",         L"-encodedcommand",               3.0, LANG_ANY },
    { L"ENCODED_COMMAND",         L" -enc ",                        3.0, LANG_ANY },
    { L"ENCODED_COMMAND",         L" -ec ",                         2.5, LANG_ANY },
    { L"INVOKE_EXPRESSION",       L"invoke-expression",             2.0, LANG_ANY },
    { L"INVOKE_EXPRESSION",       L"iex(",                          2.0, LANG_ANY },
    { L"INVOKE_EXPRESSION",       L"iex (",                         2.0, LANG_ANY },
    { L"INVOKE_EXPRESSION",       L"| iex",                         2.0, LANG_ANY },
    { L"INVOKE_EXPRESSION",       L"|iex",                          2.0, LANG_ANY },
    { L"DOWNLOAD_CRADLE",         L"downloadstring(",               2.5, LANG_ANY },
    { L"DOWNLOAD_CRADLE",         L"downloadfile(",                 2.0, LANG_ANY },
    { L"DOWNLOAD_CRADLE",         L"downloaddata(",                 2.0, LANG_ANY },
    { L"DOWNLOAD_CRADLE",         L"net.webclient",                 1.5, LANG_ANY },
    { L"DOWNLOAD_CRADLE",         L"invoke-webrequest",             1.0, LANG_ANY },
    { L"DOWNLOAD_CRADLE",         L"invoke-restmethod",             1.0, LANG_ANY },
    { L"DOWNLOAD_CRADLE",         L"start-bitstransfer",            1.5, LANG_ANY },
    { L"DOWNLOAD_CRADLE",         L"urldownloadtofile",             2.0, LANG_ANY },
    { L"HIDDEN_WINDOW",           L"-windowstyle hidden",           1.5, LANG_ANY },
    { L"HIDDEN_WINDOW",           L"-w hidden",                     1.5, LANG_ANY },
    { L"HIDDEN_WINDOW",           L"-win hidden",                   1.5, LANG_ANY },
    { L"EXECUTION_POLICY_BYPASS", L"-executionpolicy bypass",       1.5, LANG_ANY },
    { L"EXECUTION_POLICY_BYPASS", L"-ep bypass",                    1.5, LANG_ANY },
    { L"EXECUTION_POLICY_BYPASS", L"-exec bypass",                  1.5, LANG_ANY },
    { L"NO_PROFILE",              L"-noprofile",                    0.3, LANG_ANY },
    { L"NO_PROFILE",              L"-nop ",                         0.3, LANG_ANY },
    { L"REFLECTIVE_LOAD",         L"[reflection.assembly]::load",   3.0, LANG_ANY },
    { L"REFLECTIVE_LOAD",         L"[system.reflection.assembly]::load", 3.0, LANG_ANY },
    { L"ADD_TYPE",                L"add-type",                      0.8, LANG_PS },
    { L"CERTUTIL_ABUSE",          L"certutil -decode",              2.5, LANG_ANY },
    { L"CERTUTIL_ABUSE",          L"certutil.exe -decode",          2.5, LANG_ANY },
    { L"CERTUTIL_ABUSE",          L"-urlcache",                     2.5, LANG_ANY },
    { L"BITSADMIN_TRANSFER",      L"bitsadmin /transfer",           2.0, LANG_ANY },
    { L"MSHTA",                   L"mshta http",                    3.0, LANG_ANY },
    { L"MSHTA",                   L"mshta.exe http",                3.0, LANG_ANY },
    { L"MSHTA",                   L"mshta vbscript:",               3.0, LANG_ANY },
    { L"MSHTA",                   L"mshta javascript:",             3.0, LANG_ANY },
    { L"REGSVR32_SCRIPTLET",      L"/i:http",                       3.0, LANG_ANY },
    { L"REGSVR32_SCRIPTLET",      L"scrobj.dll",                    2.5, LANG_ANY },
    { L"RUNDLL32_SCRIPT",         L"rundll32 javascript:",          3.0, LANG_ANY },
    { L"RUNDLL32_SCRIPT",         L"rundll32.exe javascript:",      3.0, LANG_ANY },
    { L"WMIC_PROCESS_CREATE",     L"process call create",           2.0, LANG_ANY },
    { L"WSCRIPT_SHELL",           L"wscript.shell",                 1.0, LANG_VBS | LANG_JS | LANG_HTA },
    { L"SHELL_APPLICATION",       L"shell.application",             1.0, LANG_VBS | LANG_JS | LANG_HTA },
    { L"XMLHTTP",                 L"xmlhttp",                       1.0, LANG_VBS | LANG_JS | LANG_HTA },
    { L"XMLHTTP",                 L"winhttp.winhttprequest",        1.0, LANG_VBS | LANG_JS | LANG_HTA },
    { L"ADODB_STREAM",            L"adodb.stream",                  1.5, LANG_VBS | LANG_JS | LANG_HTA },
    { L"FILESYSTEMOBJECT",        L"scripting.filesystemobject",    0.3, LANG_VBS | LANG_JS | LANG_HTA },
    { L"ACTIVEXOBJECT",           L"activexobject",                 0.8, LANG_JS | LANG_HTA },
    { L"EVAL",                    L"eval(",                         1.0, LANG_JS | LANG_HTA },
    { L"EVAL",                    L"new function(",                 1.0, LANG_JS | LANG_HTA },
    { L"EVAL",                    L"execute(",                      1.0, LANG_VBS },
    { L"EVAL",                    L"executeglobal",                 1.5, LANG_VBS },
    { L"CHAR_CODE_OBFUSCATION",   L"string.fromcharcode",           1.5, LANG_JS | LANG_HTA },
    { L"DEFENDER_TAMPERING",      L"set-mppreference",              2.0, LANG_ANY },
    { L"DEFENDER_TAMPERING",      L"add-mppreference -exclusion",   3.0, LANG_ANY },
    { L"DEFENDER_TAMPERING",      L"disablerealtimemonitoring",     3.0, LANG_ANY },
    { L"SHADOW_COPY_DELETE",      L"vssadmin delete shadows",       4.0, LANG_ANY },
    { L"SHADOW_COPY_DELETE",      L"shadowcopy delete",             4.0, LANG_ANY },
    { L"SHADOW_COPY_DELETE",      L"wbadmin delete catalog",        3.0, LANG_ANY },
};

static size_t CountOf(const std::wstring& text, const std::wstring& needle)
{
    size_t count = 0;
    size_t pos = 0;
    while ((pos = text.find(needle, pos)) != std::wstring::npos) {
        ++count;
        pos += needle.size();
    }
    return count;
}

static bool IsBase64Char(wchar_t c)
{
    return (c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') || (c >= L'0' && c <= L'9') || c == L'+' || c == L'/' || c == L'=';
}

static bool IsHexChar(wchar_t c)
{
    return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F');
}

static bool DecodeBase64(const std::wstring& b64, std::vector<uint8_t>& out)
{
    DWORD size = 0;
    if (!CryptStringToBinaryW(b64.c_str(), static_cast<DWORD>(b64.size()), CRYPT_STRING_BASE64, NULL, &size, NULL, NULL) || size == 0) {
        return false;
    }
    out.resize(size);
    if (!CryptStringToBinaryW(b64.c_str(), static_cast<DWORD>(b64.size()), CRYPT_STRING_BASE64, out.data(), &size, NULL, NULL)) {
        return false;
    }
    out.resize(size);
    return true;
}

static double CharEntropy(const std::wstring& s)
{
    if (s.empty()) return 0.0;
    int counts[128] = {};
    int total = 0;
    for (wchar_t c : s) {
        if (c < 128) {
            counts[c]++;
            total++;
        }
    }
    if (total == 0) return 0.0;
    double e = 0.0;
    for (int i = 0; i < 128; ++i) {
        if (counts[i] > 0) {
            double p = static_cast<double>(counts[i]) / total;
            e -= p * std::log2(p);
        }
    }
    return e;
}

ScriptAnalysisResult AnalyzeScriptText(const std::wstring& original, const std::wstring& ext)
{
    ScriptAnalysisResult result;
    if (!IsScriptExtension(ext)) return result;   // analyzed stays false, as the header promises
    result.analyzed = true;
    unsigned lang = LanguageOf(ext);

    std::wstring text = ToLowerW(original);
    // Collapse caret escapes in batch so "p^o^w^e^r^s^h^e^l^l" still matches.
    std::wstring textNoCarets = text;
    if (lang & LANG_BAT) textNoCarets.erase(std::remove(textNoCarets.begin(), textNoCarets.end(), L'^'), textNoCarets.end());
    // Collapse PowerShell backticks the same way.
    if (lang & LANG_PS) textNoCarets.erase(std::remove(textNoCarets.begin(), textNoCarets.end(), L'`'), textNoCarets.end());

    double score = 0.0;
    std::vector<std::wstring> codesSeen;
    auto raise = [&](const std::wstring& code, double weight, const std::wstring& detail) {
        if (std::find(codesSeen.begin(), codesSeen.end(), code) != codesSeen.end()) return;
        codesSeen.push_back(code);
        score += weight;
        result.indicators.push_back(code + L": " + detail);
        std::wstring technique = AttackTechniqueForCode(code);
        if (!technique.empty()) AddUniqueTechniques(result.techniques, { technique });
    };

    for (const Pattern& p : kPatterns) {
        if (!(p.languages & lang)) continue;
        if (textNoCarets.find(p.needle) != std::wstring::npos) {
            raise(p.code, p.weight, std::wstring(L"contains \"") + p.needle + L"\"");
        }
    }

    // Character-code building
    size_t charCasts = CountOf(text, L"[char]");
    size_t chrCalls = CountOf(text, L"chr(") + CountOf(text, L"chrw(");
    if (charCasts >= 10 || chrCalls >= 10) {
        raise(L"CHAR_CODE_OBFUSCATION", 1.5, std::to_wstring(charCasts + chrCalls) + L" character-code conversions");
    }

    // Obfuscation by escape characters
    if (lang & LANG_PS) {
        size_t backticks = CountOf(text, L"`");
        if (backticks > 20 && static_cast<double>(backticks) / (text.size() + 1) > 0.01) {
            raise(L"BACKTICK_OBFUSCATION", 1.5, std::to_wstring(backticks) + L" backticks");
        }
    }
    if (lang & LANG_BAT) {
        size_t carets = CountOf(text, L"^");
        if (carets > 20 && static_cast<double>(carets) / (text.size() + 1) > 0.01) {
            raise(L"CARET_OBFUSCATION", 1.5, std::to_wstring(carets) + L" carets");
        }
    }

    // String concatenation density
    size_t concat = CountOf(text, L"'+'") + CountOf(text, L"\"+\"") + CountOf(text, L"\" & \"") + CountOf(text, L"\"&\"")
                  + CountOf(text, L"' + '") + CountOf(text, L"\" + \"");
    if (concat >= 20) {
        raise(L"STRING_CONCAT_OBFUSCATION", 1.5, std::to_wstring(concat) + L" glued string fragments");
    }

    // Symbol ratio
    if (text.size() > 500) {
        size_t alnum = 0, symbols = 0;
        for (wchar_t c : text) {
            if (iswalnum(c)) alnum++;
            else if (!iswspace(c)) symbols++;
        }
        if (symbols > 0 && static_cast<double>(symbols) / (alnum + symbols) > 0.45) {
            raise(L"HIGH_SYMBOL_RATIO", 1.0, L"more than 45% symbols");
        }
    }

    // Long base64, hex and decimal runs (on the original text so base64 case survives)
    size_t i = 0;
    bool base64Done = false, hexDone = false;
    while (i < original.size()) {
        if (!base64Done && IsBase64Char(original[i])) {
            size_t start = i;
            while (i < original.size() && IsBase64Char(original[i])) ++i;
            size_t len = i - start;
            if (len >= 100) {
                std::wstring run = original.substr(start, len);
                bool allHex = std::all_of(run.begin(), run.end(), [](wchar_t c) { return IsHexChar(c); });
                if (!allHex && CharEntropy(run) > 4.5) {
                    raise(L"BASE64_BLOB", 1.5, std::to_wstring(len) + L" character base64 block");
                    base64Done = true;
                    std::vector<uint8_t> decoded;
                    if (DecodeBase64(run, decoded) && decoded.size() >= 4) {
                        if (decoded[0] == 'M' && decoded[1] == 'Z') {
                            raise(L"BASE64_PE", 4.0, L"base64 block decodes to a Windows program");
                        }
                        else if (decoded[0] == 0x1F && decoded[1] == 0x8B) {
                            raise(L"GZIP_PAYLOAD", 2.0, L"base64 block decodes to gzip data");
                        }
                    }
                }
            }
            continue;
        }
        ++i;
    }
    i = 0;
    while (!hexDone && i < original.size()) {
        if (IsHexChar(original[i])) {
            size_t start = i;
            while (i < original.size() && IsHexChar(original[i])) ++i;
            if (i - start >= 200) {
                raise(L"HEX_BLOB", 1.5, std::to_wstring(i - start) + L" hex digits in a row");
                hexDone = true;
            }
            continue;
        }
        ++i;
    }
    {
        // Sequences like 72,101,108,108,111 (at least 50 numbers)
        size_t numbers = 0, best = 0;
        size_t k = 0;
        while (k < text.size()) {
            if (iswdigit(text[k])) {
                size_t start = k;
                while (k < text.size() && iswdigit(text[k])) ++k;
                bool smallNumber = (k - start) <= 3;
                size_t j = k;
                while (j < text.size() && text[j] == L' ') ++j;
                if (smallNumber && j < text.size() && text[j] == L',') {
                    numbers++;
                    best = (std::max)(best, numbers);
                    k = j + 1;
                    while (k < text.size() && text[k] == L' ') ++k;
                    continue;
                }
                if (smallNumber) numbers++;
                best = (std::max)(best, numbers);
                numbers = 0;
                continue;
            }
            numbers = 0;   // anything other than "digits ," ends the run
            ++k;
        }
        if (best >= 50) raise(L"DECIMAL_BYTE_ARRAY", 1.5, std::to_wstring(best) + L" comma-separated byte values");
    }

    // Random-looking identifiers in PowerShell ($names)
    if (lang & LANG_PS) {
        size_t vars = 0, random = 0;
        size_t k = 0;
        while ((k = text.find(L'$', k)) != std::wstring::npos) {
            size_t start = ++k;
            while (k < text.size() && (iswalnum(text[k]) || text[k] == L'_')) ++k;
            std::wstring name = text.substr(start, k - start);
            if (name.size() >= 6) {
                vars++;
                size_t vowels = std::count_if(name.begin(), name.end(), [](wchar_t c) { return wcschr(L"aeiou", c) != nullptr; });
                if (CharEntropy(name) > 3.0 && static_cast<double>(vowels) / name.size() < 0.2) random++;
            }
        }
        if (random > 10 && random * 10 > vars * 3) {
            raise(L"RANDOM_IDENTIFIERS", 1.0, std::to_wstring(random) + L" of " + std::to_wstring(vars) + L" variable names look random");
        }
    }

    result.score = (std::min)(score, 10.0);
    return result;
}

ScriptAnalysisResult AnalyzeScriptFile(const std::wstring& path)
{
    std::wstring ext = ExtensionOf(path);
    if (!IsScriptExtension(ext)) return ScriptAnalysisResult();

    std::wstring text;
    if (!ReadTextFile(path, text, 4 * 1024 * 1024)) {
        ScriptAnalysisResult r;
        r.analyzed = true;
        return r;
    }
    return AnalyzeScriptText(text, ext);
}
