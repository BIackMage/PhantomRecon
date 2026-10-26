#include "pch.h"
#include "FileAnalysis.h"

#include "AppPaths.h"
#include "DebugTrace.h"
#include "FileIO.h"
#include "TextUtils.h"

#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <wincrypt.h>
#include <sddl.h>
#include <aclapi.h>
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "advapi32.lib")

static void DebugLog(const std::wstring& msg)
{
    Trace(L"FileAnalysis", msg);
}

// ---------------------------------------------------------------------------
// Certificate helpers
// ---------------------------------------------------------------------------
static std::wstring BytesToHexW(const BYTE* data, DWORD len, bool colons)
{
    std::wstringstream ss;
    for (DWORD i = 0; i < len; i++) {
        ss << std::hex << std::setfill(L'0') << std::setw(2) << static_cast<unsigned int>(data[i]);
        if (colons && i + 1 < len) ss << L":";
    }
    return ss.str();
}

static std::wstring FileTimeToDateW(const FILETIME& ft)
{
    SYSTEMTIME st = {};
    FileTimeToSystemTime(&ft, &st);
    wchar_t buf[32];
    swprintf_s(buf, L"%04u-%02u-%02u", st.wYear, st.wMonth, st.wDay);
    return buf;
}

static std::wstring GetCertNameW(PCCERT_CONTEXT pCert, DWORD nameFlag)
{
    DWORD nameLen = CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, nameFlag, NULL, NULL, 0);
    if (nameLen <= 1) return L"N/A";
    std::vector<wchar_t> buf(nameLen);
    CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, nameFlag, NULL, buf.data(), nameLen);
    return buf.data();
}

static std::wstring GetCertThumbprintW(PCCERT_CONTEXT pCert)
{
    BYTE hash[20] = {};
    DWORD hashLen = sizeof(hash);
    if (CertGetCertificateContextProperty(pCert, CERT_HASH_PROP_ID, hash, &hashLen)) {
        return BytesToHexW(hash, hashLen, true);
    }
    return L"N/A";
}

static std::wstring SerialBlobToHexW(const CRYPT_INTEGER_BLOB& blob)
{
    std::wstringstream ss;
    for (DWORD i = blob.cbData; i > 0; i--) {
        ss << std::hex << std::setfill(L'0') << std::setw(2) << static_cast<unsigned int>(blob.pbData[i - 1]);
    }
    return ss.str();
}

// Open the signer certificate of a signed file (embedded Authenticode, or a .cat file).
// Caller frees the returned context. contentFlags: CERT_QUERY_CONTENT_FLAG_*.
static PCCERT_CONTEXT OpenSignerCertificate(const std::wstring& filePath, DWORD contentFlags,
                                            HCERTSTORE* storeOut)
{
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath.c_str(), contentFlags,
        CERT_QUERY_FORMAT_FLAG_BINARY, 0, &dwEncoding, &dwContentType, &dwFormatType,
        &hStore, &hMsg, NULL)) {
        return NULL;
    }
    // Some content types come back without a message or a store. Without both
    // there is no signer to read.
    if (!hMsg || !hStore) {
        if (hMsg) CryptMsgClose(hMsg);
        if (hStore) CertCloseStore(hStore, 0);
        return NULL;
    }

    PCCERT_CONTEXT pSignerCert = NULL;
    DWORD signerInfoSize = 0;
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &signerInfoSize);
    if (signerInfoSize > 0) {
        std::vector<BYTE> signerInfoBuf(signerInfoSize);
        CMSG_SIGNER_INFO* pSignerInfo = reinterpret_cast<CMSG_SIGNER_INFO*>(signerInfoBuf.data());
        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &signerInfoSize)) {
            CERT_INFO findInfo = {};
            findInfo.Issuer = pSignerInfo->Issuer;
            findInfo.SerialNumber = pSignerInfo->SerialNumber;
            pSignerCert = CertFindCertificateInStore(hStore, dwEncoding, 0, CERT_FIND_SUBJECT_CERT, &findInfo, NULL);
        }
    }

    CryptMsgClose(hMsg);
    if (pSignerCert && storeOut) {
        *storeOut = hStore;
    }
    else {
        CertCloseStore(hStore, 0);
    }
    return pSignerCert;
}

static bool HasEmbeddedSignature(const std::wstring& filePath)
{
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;
    BOOL ok = CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
        0, &dwEncoding, &dwContentType, &dwFormatType, &hStore, &hMsg, NULL);
    if (hMsg) CryptMsgClose(hMsg);
    if (hStore) CertCloseStore(hStore, 0);
    return ok != FALSE;
}

// ---------------------------------------------------------------------------
// Certificate chain analysis
// ---------------------------------------------------------------------------
static void AnalyzeCertChain(PCCERT_CONTEXT pSignerCert, SignatureInfo& info)
{
    CERT_CHAIN_PARA chainPara = {};
    chainPara.cbSize = sizeof(CERT_CHAIN_PARA);
    chainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;

    PCCERT_CHAIN_CONTEXT pChainContext = NULL;
    BOOL chainBuilt = CertGetCertificateChain(NULL, pSignerCert, NULL, NULL, &chainPara,
        CERT_CHAIN_CACHE_END_CERT, NULL, &pChainContext);

    if (!chainBuilt || !pChainContext) {
        info.chainTrusted = false;
        info.rootCA = L"Chain Build Failed";
        info.warnings.push_back(L"CHAIN_BUILD_FAILED: Could not build certificate chain");
        return;
    }

    DWORD chainErrorStatus = pChainContext->TrustStatus.dwErrorStatus;
    // Ignore "no revocation info" style bits here: revocation is reported separately.
    DWORD relevant = chainErrorStatus & ~(CERT_TRUST_REVOCATION_STATUS_UNKNOWN | CERT_TRUST_IS_OFFLINE_REVOCATION);
    info.chainTrusted = (relevant == CERT_TRUST_NO_ERROR);

    if (chainErrorStatus & CERT_TRUST_IS_NOT_SIGNATURE_VALID)
        info.warnings.push_back(L"CHAIN_SIGNATURE_INVALID: A certificate in the chain has an invalid signature");
    if (chainErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT)
        info.warnings.push_back(L"UNTRUSTED_ROOT: Root CA is not in the trusted root store");
    if (chainErrorStatus & CERT_TRUST_IS_PARTIAL_CHAIN)
        info.warnings.push_back(L"PARTIAL_CHAIN: Chain is incomplete, could not reach a trusted root");
    if (chainErrorStatus & CERT_TRUST_IS_NOT_TIME_VALID)
        info.warnings.push_back(L"EXPIRED_CERT: A certificate in the chain has expired");
    if (chainErrorStatus & CERT_TRUST_IS_REVOKED)
        info.warnings.push_back(L"REVOKED: A certificate in the chain has been revoked");

    if (pChainContext->cChain > 0) {
        PCERT_SIMPLE_CHAIN pSimpleChain = pChainContext->rgpChain[0];
        if (pSimpleChain->cElement > 0) {
            PCCERT_CONTEXT pRootCert = pSimpleChain->rgpElement[pSimpleChain->cElement - 1]->pCertContext;
            info.rootCA = GetCertNameW(pRootCert, 0);

            if (pSimpleChain->cElement == 1) {
                info.warnings.push_back(L"SELF_SIGNED: Certificate is self-signed (not issued by a CA)");
            }
            if (chainErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT) {
                info.warnings.push_back(L"POSSIBLE_CLONE: Signer claims to be \"" + info.signerName
                    + L"\" but chain root \"" + info.rootCA + L"\" is not a trusted CA");
            }
        }
    }

    CertFreeCertificateChain(pChainContext);
}

static void CheckSignerLocationMismatch(const std::wstring& filePath, const SignatureInfo& info,
                                        std::vector<std::wstring>& warnings)
{
    std::wstring lowerPath = ToLowerW(filePath);
    std::wstring signer = info.signerName != L"N/A" ? info.signerName : info.catalogSigner;

    bool isSystemDir = (lowerPath.find(L"\\windows\\system32\\") != std::wstring::npos
        || lowerPath.find(L"\\windows\\syswow64\\") != std::wstring::npos
        || lowerPath.find(L"\\windows\\winsxs\\") != std::wstring::npos);

    if (isSystemDir && !signer.empty() && signer != L"N/A" && !IsMicrosoftSignerName(signer)) {
        warnings.push_back(L"SIGNER_LOCATION_MISMATCH: File is in a Windows system directory but signed by \""
            + signer + L"\" (expected Microsoft)");
    }

    bool isSuspiciousDir = (lowerPath.find(L"\\temp\\") != std::wstring::npos
        || lowerPath.find(L"\\downloads\\") != std::wstring::npos
        || lowerPath.find(L"\\appdata\\local\\temp\\") != std::wstring::npos);
    if (isSuspiciousDir && info.signerName != L"N/A") {
        warnings.push_back(L"SIGNED_IN_TEMP: Signed executable found in a temporary or download directory");
    }
}

bool IsMicrosoftSignerName(const std::wstring& signer)
{
    return StartsWithI(signer, L"Microsoft ") || EqualsI(signer, L"Microsoft");
}

// ---------------------------------------------------------------------------
// Revocation cache (process-wide; see CLAUDE.md on singletons)
// ---------------------------------------------------------------------------
struct RevocationCacheEntry {
    std::wstring status;
    ULONGLONG    checkedAt = 0;   // FILETIME as 100 ns ticks
};

struct RevocationCacheState {
    std::mutex mutex;
    bool loaded = false;
    bool dirty = false;
    std::unordered_map<std::wstring, RevocationCacheEntry> entries;
};

static RevocationCacheState& RevocationCache()
{
    static RevocationCacheState state;
    return state;
}

static ULONGLONG NowTicks()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER li;
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    return li.QuadPart;
}

static const ULONGLONG kRevocationTtl = 24ULL * 3600ULL * 10000000ULL;   // 24 hours

static std::wstring RevocationCachePath()
{
    return AppFilePath(L"phantom_recon_revocation_cache.txt");
}

static void LoadRevocationCacheLocked(RevocationCacheState& state)
{
    if (state.loaded) return;
    state.loaded = true;
    std::wstring text;
    if (!ReadTextFile(RevocationCachePath(), text)) return;
    for (const std::wstring& line : SplitW(text, L'\n')) {
        std::vector<std::wstring> parts = SplitW(line, L'|', false);
        if (parts.size() != 3) continue;
        RevocationCacheEntry e;
        e.status = parts[1];
        e.checkedAt = _wcstoui64(parts[2].c_str(), NULL, 10);
        state.entries[parts[0]] = e;
    }
}

void SaveRevocationCache()
{
    RevocationCacheState& state = RevocationCache();
    std::lock_guard<std::mutex> lock(state.mutex);
    if (!state.dirty) return;
    std::wstring text;
    ULONGLONG now = NowTicks();
    for (const auto& pair : state.entries) {
        if (now - pair.second.checkedAt > kRevocationTtl) continue;
        text += pair.first + L"|" + pair.second.status + L"|" + std::to_wstring(pair.second.checkedAt) + L"\n";
    }
    if (WriteUtf8File(RevocationCachePath(), text)) {
        state.dirty = false;
    }
}

static bool LookupRevocation(const std::wstring& thumbprint, std::wstring& status)
{
    RevocationCacheState& state = RevocationCache();
    std::lock_guard<std::mutex> lock(state.mutex);
    LoadRevocationCacheLocked(state);
    auto it = state.entries.find(thumbprint);
    if (it == state.entries.end()) return false;
    if (NowTicks() - it->second.checkedAt > kRevocationTtl) return false;
    status = it->second.status;
    return true;
}

static void StoreRevocation(const std::wstring& thumbprint, const std::wstring& status)
{
    RevocationCacheState& state = RevocationCache();
    std::lock_guard<std::mutex> lock(state.mutex);
    LoadRevocationCacheLocked(state);
    state.entries[thumbprint] = RevocationCacheEntry{ status, NowTicks() };
    state.dirty = true;
}

static std::wstring CheckRevocation(const std::wstring& filePath, RevocationMode mode)
{
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath.c_str();

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA data = {};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
    if (mode == RevocationMode::CacheOnly) data.dwProvFlags |= WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG rc = WinVerifyTrust(NULL, &policy, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policy, &data);

    switch (rc) {
    case ERROR_SUCCESS:                 return L"Good";
    case CERT_E_REVOKED:                return L"REVOKED";
    case CRYPT_E_REVOKED:               return L"REVOKED";
    case CRYPT_E_REVOCATION_OFFLINE:    return L"Unknown (offline)";
    case CRYPT_E_NO_REVOCATION_CHECK:   return L"Unknown (no revocation information)";
    case CERT_E_REVOCATION_FAILURE:     return L"Unknown (offline)";
    default: {
        wchar_t buf[48];
        swprintf_s(buf, L"Unknown (0x%08X)", static_cast<unsigned int>(rc));
        return buf;
    }
    }
}

// ---------------------------------------------------------------------------
// Catalog verification
// ---------------------------------------------------------------------------
static bool VerifyViaCatalog(const std::wstring& filePath, SignatureInfo& info)
{
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    bool found = false;
    LPCWSTR algorithms[] = { BCRYPT_SHA256_ALGORITHM, NULL };
    for (LPCWSTR algorithm : algorithms) {
        HCATADMIN hCatAdmin = NULL;
        if (!CryptCATAdminAcquireContext2(&hCatAdmin, NULL, algorithm, NULL, 0)) continue;

        DWORD hashLen = 0;
        CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &hashLen, NULL, 0);
        if (hashLen == 0) {
            CryptCATAdminReleaseContext(hCatAdmin, 0);
            continue;
        }
        std::vector<BYTE> hash(hashLen);
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
        if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &hashLen, hash.data(), 0)) {
            CryptCATAdminReleaseContext(hCatAdmin, 0);
            continue;
        }

        DebugLog(L"Catalog lookup, hash length " + std::to_wstring(hashLen));
        HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash.data(), hashLen, 0, NULL);
        if (hCatInfo) {
            CATALOG_INFO catalogInfo = {};
            catalogInfo.cbStruct = sizeof(catalogInfo);
            if (CryptCATCatalogInfoFromContext(hCatInfo, &catalogInfo, 0)) {
                std::wstring tag = BytesToHexW(hash.data(), hashLen, false);
                std::transform(tag.begin(), tag.end(), tag.begin(), ::towupper);

                WINTRUST_CATALOG_INFO catalog = {};
                catalog.cbStruct = sizeof(catalog);
                catalog.pcwszCatalogFilePath = catalogInfo.wszCatalogFile;
                catalog.pcwszMemberFilePath = filePath.c_str();
                catalog.pcwszMemberTag = tag.c_str();
                catalog.pbCalculatedFileHash = hash.data();
                catalog.cbCalculatedFileHash = hashLen;
                catalog.hMemberFile = hFile;
                catalog.hCatAdmin = hCatAdmin;

                GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                WINTRUST_DATA data = {};
                data.cbStruct = sizeof(data);
                data.dwUIChoice = WTD_UI_NONE;
                data.fdwRevocationChecks = WTD_REVOKE_NONE;
                data.dwUnionChoice = WTD_CHOICE_CATALOG;
                data.pCatalog = &catalog;
                data.dwStateAction = WTD_STATEACTION_VERIFY;
                data.dwProvFlags = WTD_SAFER_FLAG;

                DebugLog(std::wstring(L"WinVerifyTrust (catalog): ") + catalogInfo.wszCatalogFile);
                LONG rc = WinVerifyTrust(NULL, &policy, &data);
                data.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(NULL, &policy, &data);
                DebugLog(L"Catalog verify result " + std::to_wstring(rc) + L", reading catalog signer");

                info.catalogFile = catalogInfo.wszCatalogFile;
                // A security catalog is a PKCS #7 signed message wrapping a trust list.
                PCCERT_CONTEXT catSigner = OpenSignerCertificate(info.catalogFile, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED, NULL);
                if (catSigner) {
                    info.catalogSigner = GetCertNameW(catSigner, 0);
                    CertFreeCertificateContext(catSigner);
                }

                if (rc == ERROR_SUCCESS) {
                    info.status = L"Signed (Valid)";
                    info.hashValid = true;
                    info.chainTrusted = true;
                }
                else {
                    wchar_t buf[48];
                    swprintf_s(buf, L"Signed (Catalog error 0x%08X)", static_cast<unsigned int>(rc));
                    info.status = buf;
                }
                info.signatureType = L"Catalog";
                found = true;
            }
            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
        }
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        if (found) break;
    }

    CloseHandle(hFile);
    return found;
}

// ---------------------------------------------------------------------------
// Full signature analysis
// ---------------------------------------------------------------------------
SignatureInfo AnalyzeFileSignature(const std::wstring& filePath, RevocationMode revocation)
{
    SignatureInfo info;
    info.signerName = L"N/A";
    info.issuerName = L"N/A";
    info.rootCA = L"N/A";
    info.thumbprint = L"N/A";
    info.serialNumber = L"N/A";
    info.signatureType = L"None";
    info.validFrom = L"N/A";
    info.validTo = L"N/A";
    info.revocation = L"Not checked";

    WINTRUST_FILE_INFO wtFileInfo = {};
    wtFileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    wtFileInfo.pcwszFilePath = filePath.c_str();

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA winTrustData = {};
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &wtFileInfo;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.dwProvFlags = WTD_SAFER_FLAG;

    DebugLog(L"WinVerifyTrust (file): " + filePath);
    LONG trustStatus = WinVerifyTrust(NULL, &policyGUID, &winTrustData);
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &winTrustData);

    switch (trustStatus) {
    case ERROR_SUCCESS:
        info.status = L"Signed (Valid)";
        info.hashValid = true;
        break;
    case TRUST_E_NOSIGNATURE:
    case TRUST_E_SUBJECT_FORM_UNKNOWN:
    case TRUST_E_PROVIDER_UNKNOWN:
        // No embedded signature. Windows' own files are usually signed through a catalog.
        if (VerifyViaCatalog(filePath, info)) {
            info.warnings.push_back(L"CATALOG_SIGNED: Signed through a Windows security catalog ("
                + (info.catalogSigner.empty() ? std::wstring(L"unknown signer") : info.catalogSigner) + L")");
            CheckSignerLocationMismatch(filePath, info, info.warnings);
        }
        else if (IsPackagedAppPath(filePath)) {
            // Store / MSIX apps are signed as a whole package (AppxSignature.p7x).
            // Windows checks that signature at install time and protects the folder,
            // so individual files carry no signature of their own.
            info.status = L"Signed (App package)";
            info.signatureType = L"Package";
            info.hashValid = true;
            info.chainTrusted = true;
            std::wstring rest = filePath.substr(filePath.find(L"\\WindowsApps\\") + 13);
            std::wstring package = rest.substr(0, rest.find(L'\\'));
            info.catalogSigner = package.rfind(L"Microsoft.", 0) == 0 || package.rfind(L"MicrosoftCorporationII.", 0) == 0
                ? L"Microsoft Corporation (app package)" : package;
            info.revocation = L"Not checked (app package)";
        }
        else {
            info.status = L"Unsigned";
        }
        return info;
    case TRUST_E_BAD_DIGEST:
        info.status = L"Signed (HASH MISMATCH)";
        info.hashValid = false;
        info.warnings.push_back(L"HASH_MISMATCH: File content does not match the signed hash. "
            L"Strong indicator of signature theft or file tampering.");
        break;
    case TRUST_E_EXPLICIT_DISTRUST:
        info.status = L"Signed (Distrusted)";
        info.warnings.push_back(L"EXPLICIT_DISTRUST: This certificate has been explicitly distrusted.");
        break;
    case TRUST_E_SUBJECT_NOT_TRUSTED:
        info.status = L"Signed (Untrusted)";
        info.hashValid = true;
        info.warnings.push_back(L"UNTRUSTED_SUBJECT: Signature present but the certificate is not trusted.");
        break;
    case CERT_E_UNTRUSTEDROOT:
        info.status = L"Signed (Untrusted Root)";
        info.hashValid = true;
        break;
    case CERT_E_EXPIRED:
        info.status = L"Signed (Expired)";
        info.hashValid = true;
        break;
    case CRYPT_E_SECURITY_SETTINGS:
        info.status = L"Signed (Blocked by Policy)";
        break;
    default:
        info.status = L"Signed (Verification Error: " + std::to_wstring(trustStatus) + L")";
        info.warnings.push_back(L"VERIFY_ERROR: WinVerifyTrust returned code " + std::to_wstring(trustStatus));
        break;
    }

    info.isEmbedded = HasEmbeddedSignature(filePath);
    info.signatureType = info.isEmbedded ? L"Embedded" : L"Catalog";

    if (info.isEmbedded) {
        HCERTSTORE hStore = NULL;
        PCCERT_CONTEXT pSignerCert = OpenSignerCertificate(filePath, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, &hStore);
        if (pSignerCert) {
            info.signerName = GetCertNameW(pSignerCert, 0);
            info.issuerName = GetCertNameW(pSignerCert, CERT_NAME_ISSUER_FLAG);
            info.thumbprint = GetCertThumbprintW(pSignerCert);
            info.serialNumber = SerialBlobToHexW(pSignerCert->pCertInfo->SerialNumber);
            info.validFrom = FileTimeToDateW(pSignerCert->pCertInfo->NotBefore);
            info.validTo = FileTimeToDateW(pSignerCert->pCertInfo->NotAfter);

            AnalyzeCertChain(pSignerCert, info);
            CheckSignerLocationMismatch(filePath, info, info.warnings);

            CertFreeCertificateContext(pSignerCert);
        }
        if (hStore) CertCloseStore(hStore, 0);
    }

    // Revocation: per signer certificate, cached for 24 hours.
    if (revocation != RevocationMode::Off && info.isEmbedded && info.thumbprint != L"N/A") {
        if (IsPortableMode() && revocation == RevocationMode::Online) revocation = RevocationMode::CacheOnly;
        std::wstring status;
        if (!LookupRevocation(info.thumbprint, status)) {
            status = CheckRevocation(filePath, revocation);
            StoreRevocation(info.thumbprint, status);
        }
        info.revocation = status;
        if (status == L"REVOKED") {
            bool already = false;
            for (const std::wstring& w : info.warnings) {
                if (w.rfind(L"REVOKED", 0) == 0) already = true;
            }
            if (!already) info.warnings.push_back(L"REVOKED: The signing certificate has been revoked");
        }
    }
    else if (info.signatureType == L"Catalog") {
        info.revocation = L"Not checked (catalog)";
    }

    return info;
}

// ---------------------------------------------------------------------------
// Cached summary for checks
// ---------------------------------------------------------------------------
struct SignatureSummaryCache {
    std::mutex mutex;
    std::unordered_map<std::wstring, SignatureSummary> entries;
};

static SignatureSummaryCache& SummaryCache()
{
    static SignatureSummaryCache cache;
    return cache;
}

SignatureSummary GetSignatureSummary(const std::wstring& filePath)
{
    std::wstring key = ToLowerW(filePath);
    {
        SignatureSummaryCache& cache = SummaryCache();
        std::lock_guard<std::mutex> lock(cache.mutex);
        auto it = cache.entries.find(key);
        if (it != cache.entries.end()) return it->second;
    }

    SignatureSummary summary;
    if (!FileExists(filePath)) {
        summary.status = L"File not found";
    }
    else {
        SignatureInfo info = AnalyzeFileSignature(ToExtendedPath(filePath), RevocationMode::Off);
        summary.status = info.status;
        summary.valid = info.status == L"Signed (Valid)" || info.status == L"Signed (App package)";
        if (info.signerName != L"N/A") summary.signer = info.signerName;
        else summary.signer = info.catalogSigner;
        summary.microsoft = summary.valid && IsMicrosoftSignerName(summary.signer);
    }

    SignatureSummaryCache& cache = SummaryCache();
    std::lock_guard<std::mutex> lock(cache.mutex);
    if (cache.entries.size() > 20000) cache.entries.clear();
    cache.entries[key] = summary;
    return summary;
}

std::wstring GetFileSignatureStatus(const std::wstring& filePath)
{
    return AnalyzeFileSignature(filePath).status;
}

std::wstring GetFileSignerName(const std::wstring& filePath)
{
    return AnalyzeFileSignature(filePath).signerName;
}

// ---------------------------------------------------------------------------
// Version info
// ---------------------------------------------------------------------------
static bool LoadVersionInfo(const std::wstring& filePath, std::vector<BYTE>& buffer)
{
    DWORD dummy = 0;
    DWORD size = GetFileVersionInfoSizeW(filePath.c_str(), &dummy);
    if (size == 0) return false;
    buffer.resize(size);
    return GetFileVersionInfoW(filePath.c_str(), 0, size, buffer.data()) != FALSE;
}

std::wstring GetFileVersion(const std::wstring& filePath)
{
    std::vector<BYTE> buffer;
    if (!LoadVersionInfo(filePath, buffer)) return L"N/A";

    VS_FIXEDFILEINFO* pFileInfo = nullptr;
    UINT len = 0;
    if (!VerQueryValueW(buffer.data(), L"\\", reinterpret_cast<LPVOID*>(&pFileInfo), &len)) return L"N/A";
    if (len == 0 || pFileInfo == nullptr) return L"N/A";

    std::wstringstream ss;
    ss << HIWORD(pFileInfo->dwFileVersionMS) << L"."
       << LOWORD(pFileInfo->dwFileVersionMS) << L"."
       << HIWORD(pFileInfo->dwFileVersionLS) << L"."
       << LOWORD(pFileInfo->dwFileVersionLS);
    return ss.str();
}

static std::wstring QueryVersionString(const std::wstring& filePath, const wchar_t* field)
{
    std::vector<BYTE> buffer;
    if (!LoadVersionInfo(filePath, buffer)) return L"";

    struct LANGANDCODEPAGE { WORD wLanguage; WORD wCodePage; };
    LANGANDCODEPAGE* pTranslate = nullptr;
    UINT cbTranslate = 0;
    if (!VerQueryValueW(buffer.data(), L"\\VarFileInfo\\Translation",
        reinterpret_cast<LPVOID*>(&pTranslate), &cbTranslate)) return L"";
    if (cbTranslate < sizeof(LANGANDCODEPAGE)) return L"";

    wchar_t subBlock[256];
    swprintf_s(subBlock, 256, L"\\StringFileInfo\\%04x%04x\\%s",
        pTranslate[0].wLanguage, pTranslate[0].wCodePage, field);

    LPVOID pValue = nullptr;
    UINT valueLen = 0;
    if (!VerQueryValueW(buffer.data(), subBlock, &pValue, &valueLen)) return L"";
    if (valueLen == 0 || !pValue) return L"";
    return AsciiPunctuation(std::wstring(static_cast<wchar_t*>(pValue)));
}

std::wstring GetFileDeveloper(const std::wstring& filePath)
{
    std::wstring company = QueryVersionString(filePath, L"CompanyName");
    return company.empty() ? L"Unknown" : company;
}

std::wstring GetFileProductName(const std::wstring& filePath)
{
    return QueryVersionString(filePath, L"ProductName");
}

// ---------------------------------------------------------------------------
// Size and entropy
// ---------------------------------------------------------------------------
int64_t GetFileSizeBytes(const std::wstring& filePath)
{
    WIN32_FILE_ATTRIBUTE_DATA info = {};
    if (!GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &info)) {
        DebugLog(L"GetFileSizeBytes failed: " + filePath);
        return -1;
    }
    ULARGE_INTEGER size;
    size.LowPart = info.nFileSizeLow;
    size.HighPart = info.nFileSizeHigh;
    return static_cast<int64_t>(size.QuadPart);
}

double CalculateBufferEntropy(const uint8_t* data, size_t length)
{
    if (length == 0) return 0.0;
    unsigned long long counts[256] = {};
    for (size_t i = 0; i < length; ++i) counts[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (counts[i] > 0) {
            double p = static_cast<double>(counts[i]) / static_cast<double>(length);
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}

double CalculateFileEntropy(const std::wstring& filePath)
{
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return 0.0;
    }

    unsigned long long counts[256] = {};
    unsigned long long total = 0;
    std::vector<BYTE> buffer(64 * 1024);
    DWORD bytesRead = 0;
    while (ReadFile(hFile, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, NULL) && bytesRead > 0) {
        for (DWORD i = 0; i < bytesRead; ++i) counts[buffer[i]]++;
        total += bytesRead;
    }
    CloseHandle(hFile);

    if (total == 0) return 0.0;

    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (counts[i] > 0) {
            double p = static_cast<double>(counts[i]) / static_cast<double>(total);
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}

// ---------------------------------------------------------------------------
// Attributes and permissions
// ---------------------------------------------------------------------------
std::wstring GetFileReadOnly(const std::wstring& filePath)
{
    DWORD attrs = GetFileAttributesW(filePath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return L"Error";
    return (attrs & FILE_ATTRIBUTE_READONLY) ? L"Yes" : L"No";
}

std::wstring GetFileHidden(const std::wstring& filePath)
{
    DWORD attrs = GetFileAttributesW(filePath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return L"Error";
    return (attrs & FILE_ATTRIBUTE_HIDDEN) ? L"Yes" : L"No";
}

std::wstring GetFilePermissions(const std::wstring& filePath)
{
    PSECURITY_DESCRIPTOR pSD = NULL;
    PSID pOwnerSid = NULL;
    PACL pDacl = NULL;

    DWORD result = GetNamedSecurityInfoW(filePath.c_str(), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &pOwnerSid, NULL, &pDacl, NULL, &pSD);
    if (result != ERROR_SUCCESS) {
        return L"Access Denied";
    }

    std::wstringstream ss;
    wchar_t ownerName[256] = {};
    wchar_t domainName[256] = {};
    DWORD ownerNameLen = 256;
    DWORD domainNameLen = 256;
    SID_NAME_USE sidType;

    if (LookupAccountSidW(NULL, pOwnerSid, ownerName, &ownerNameLen, domainName, &domainNameLen, &sidType)) {
        ss << domainName << L"\\" << ownerName;
    }
    else {
        LPWSTR sidStr = NULL;
        if (ConvertSidToStringSidW(pOwnerSid, &sidStr)) {
            ss << sidStr;
            LocalFree(sidStr);
        }
        else {
            ss << L"Unknown Owner";
        }
    }

    if (pDacl != NULL) {
        ACL_SIZE_INFORMATION aclInfo = {};
        if (GetAclInformation(pDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation)) {
            int allowCount = 0;
            int denyCount = 0;
            for (DWORD i = 0; i < aclInfo.AceCount; i++) {
                LPVOID pAce = NULL;
                if (GetAce(pDacl, i, &pAce)) {
                    ACE_HEADER* aceHeader = static_cast<ACE_HEADER*>(pAce);
                    if (aceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE) allowCount++;
                    else if (aceHeader->AceType == ACCESS_DENIED_ACE_TYPE) denyCount++;
                }
            }
            ss << L" [Allow:" << allowCount << L" Deny:" << denyCount << L"]";
        }
    }

    if (pSD) LocalFree(pSD);
    return ss.str();
}
