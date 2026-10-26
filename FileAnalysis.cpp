#include "pch.h"
#include "FileAnalysis.h"

#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <wincrypt.h>
#include <sstream>
#include <sddl.h>
#include <aclapi.h>
#include <iostream>
#include <algorithm>
#include <iomanip>
#include <cmath>
#include <vector>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "version.lib")


// ---------------------------------------------------------------------------
// Helpers for certificate field extraction
// ---------------------------------------------------------------------------

// Convert a byte array to a hex wstring
static std::wstring BytesToHexW(const BYTE* data, DWORD len)
{
    std::wstringstream ss;
    for (DWORD i = 0; i < len; i++) {
        ss << std::hex << std::setfill(L'0') << std::setw(2) << data[i];
        if (i + 1 < len) ss << L":";
    }
    return ss.str();
}

// Convert FILETIME to readable wstring
static std::wstring FileTimeToStringW(const FILETIME& ft)
{
    SYSTEMTIME st = {};
    FileTimeToSystemTime(&ft, &st);

    std::wstringstream ss;
    ss << st.wYear << L"-"
       << std::setfill(L'0') << std::setw(2) << st.wMonth << L"-"
       << std::setfill(L'0') << std::setw(2) << st.wDay;
    return ss.str();
}

// Get a certificate name string (subject or issuer)
static std::wstring GetCertNameW(PCCERT_CONTEXT pCert, DWORD nameFlag)
{
    DWORD nameLen = CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, nameFlag, NULL, NULL, 0);
    if (nameLen <= 1) return L"N/A";

    std::vector<wchar_t> buf(nameLen);
    CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, nameFlag, NULL, buf.data(), nameLen);
    return buf.data();
}

// Compute SHA1 thumbprint of a certificate
static std::wstring GetCertThumbprintW(PCCERT_CONTEXT pCert)
{
    BYTE hash[20] = {};
    DWORD hashLen = sizeof(hash);
    if (CertGetCertificateContextProperty(pCert, CERT_HASH_PROP_ID, hash, &hashLen)) {
        return BytesToHexW(hash, hashLen);
    }
    return L"N/A";
}

// Convert a CRYPT_INTEGER_BLOB (serial number) to hex string.
// Serial numbers are stored little-endian in the blob, display big-endian.
static std::wstring SerialBlobToHexW(const CRYPT_INTEGER_BLOB& blob)
{
    std::wstringstream ss;
    for (DWORD i = blob.cbData; i > 0; i--) {
        ss << std::hex << std::setfill(L'0') << std::setw(2) << blob.pbData[i - 1];
    }
    return ss.str();
}

// Known trusted root CA thumbprints (SHA1) — major CAs used by legitimate software publishers.
// This is a representative sample; in production you'd check the Windows trusted root store.
static const wchar_t* g_KnownTrustedRoots[] = {
    // Microsoft Root Certificate Authority 2010
    L"3b:1e:fd:3a:66:ea:45:b4:09:63:e0:5a:de:a2:c1:6e:c0:5f:ef:fb",
    // Microsoft Root Certificate Authority 2011
    L"8f:43:28:8a:d2:72:f3:10:3b:6f:b1:42:84:85:ea:30:48:c5:c4:f2",
    // DigiCert Assured ID Root CA
    L"05:63:b8:63:0d:62:d7:5a:bf:c2:50:da:d0:90:d1:4c:53:54:a4:b3",
    // DigiCert Global Root G2
    L"df:3c:24:f9:bf:d6:66:76:1b:26:80:73:01:e0:27:7c:87:28:eb:9f",
    // DigiCert Trusted Root G4
    L"dd:fb:16:cd:49:31:c9:73:a2:03:7d:3f:c8:3a:4d:7d:77:5d:05:e4",
    // GlobalSign Root CA
    L"b1:bc:96:8b:d4:f4:9d:62:2a:a8:9a:81:f2:15:01:52:a4:1d:82:9c",
    // VeriSign Class 3 Public Primary Certification Authority - G5
    L"4e:b6:d5:78:49:9b:1c:cf:5f:58:1e:ad:56:be:3d:9b:67:44:a5:e5",
    // Symantec / VeriSign Universal Root
    L"36:79:ca:35:66:87:72:30:4d:30:a5:fb:87:3b:0f:a7:7b:b7:0d:54",
    // Comodo / Sectigo RSA Certification Authority
    L"af:e5:d2:44:a8:d1:19:42:30:ff:47:9f:e2:f8:97:bb:cd:7a:8c:b4",
    // Let's Encrypt ISRG Root X1
    L"ca:bd:2a:79:a1:07:6a:31:f2:1d:25:36:35:cb:03:9d:43:29:a5:e8",
};
static const size_t g_KnownTrustedRootCount = sizeof(g_KnownTrustedRoots) / sizeof(g_KnownTrustedRoots[0]);

static bool IsKnownTrustedRoot(const std::wstring& thumbprint)
{
    for (size_t i = 0; i < g_KnownTrustedRootCount; i++) {
        if (_wcsicmp(thumbprint.c_str(), g_KnownTrustedRoots[i]) == 0)
            return true;
    }
    return false;
}


// ---------------------------------------------------------------------------
// Check if the file has an embedded Authenticode signature
// (as opposed to catalog-only signing)
// ---------------------------------------------------------------------------

static bool HasEmbeddedSignature(const std::wstring& filePath)
{
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;

    BOOL ok = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        filePath.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0, &dwEncoding, &dwContentType, &dwFormatType,
        &hStore, &hMsg, NULL);

    if (hMsg) CryptMsgClose(hMsg);
    if (hStore) CertCloseStore(hStore, 0);

    return ok != FALSE;
}


// ---------------------------------------------------------------------------
// Build the certificate chain and extract root CA info
// ---------------------------------------------------------------------------

static void AnalyzeCertChain(PCCERT_CONTEXT pSignerCert, SignatureInfo& info)
{
    CERT_CHAIN_PARA chainPara = {};
    chainPara.cbSize = sizeof(CERT_CHAIN_PARA);
    chainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;

    PCCERT_CHAIN_CONTEXT pChainContext = NULL;

    BOOL chainBuilt = CertGetCertificateChain(
        NULL,                // default chain engine
        pSignerCert,
        NULL,                // current time
        NULL,                // no additional store
        &chainPara,
        CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
        NULL,
        &pChainContext);

    if (!chainBuilt || !pChainContext) {
        info.chainTrusted = false;
        info.rootCA = L"Chain Build Failed";
        info.warnings.push_back(L"CHAIN_BUILD_FAILED: Could not build certificate chain");
        return;
    }

    // Check overall chain trust status
    DWORD chainErrorStatus = pChainContext->TrustStatus.dwErrorStatus;
    info.chainTrusted = (chainErrorStatus == CERT_TRUST_NO_ERROR);

    if (chainErrorStatus & CERT_TRUST_IS_NOT_SIGNATURE_VALID)
        info.warnings.push_back(L"CHAIN_SIGNATURE_INVALID: A certificate in the chain has an invalid signature");
    if (chainErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT)
        info.warnings.push_back(L"UNTRUSTED_ROOT: Root CA is NOT in the trusted root store (possible cert cloning)");
    if (chainErrorStatus & CERT_TRUST_IS_PARTIAL_CHAIN)
        info.warnings.push_back(L"PARTIAL_CHAIN: Chain is incomplete — could not reach a trusted root");
    if (chainErrorStatus & CERT_TRUST_IS_NOT_TIME_VALID)
        info.warnings.push_back(L"EXPIRED_CERT: A certificate in the chain has expired");
    if (chainErrorStatus & CERT_TRUST_IS_REVOKED)
        info.warnings.push_back(L"REVOKED: A certificate in the chain has been revoked");

    // Walk the first simple chain to find the root CA
    if (pChainContext->cChain > 0) {
        PCERT_SIMPLE_CHAIN pSimpleChain = pChainContext->rgpChain[0];
        if (pSimpleChain->cElement > 0) {
            // The last element in the chain is the root CA
            PCCERT_CONTEXT pRootCert = pSimpleChain->rgpElement[pSimpleChain->cElement - 1]->pCertContext;
            info.rootCA = GetCertNameW(pRootCert, 0);

            // Get root CA thumbprint and check against known list
            std::wstring rootThumbprint = GetCertThumbprintW(pRootCert);

            // Self-signed check: if chain has only 1 element, it's self-signed
            if (pSimpleChain->cElement == 1) {
                info.warnings.push_back(L"SELF_SIGNED: Certificate is self-signed (not issued by a CA)");
            }

            // Check if root is a known trusted CA
            if (!IsKnownTrustedRoot(rootThumbprint) && !(chainErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT)) {
                // It's in the Windows trust store but not in our known-good list.
                // Not necessarily bad, but worth noting for deeper analysis.
            }

            // Flag if the root is untrusted (strong indicator of cert cloning)
            if (chainErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT) {
                info.warnings.push_back(L"POSSIBLE_CLONE: Signer claims to be \"" + info.signerName
                    + L"\" but chain root \"" + info.rootCA + L"\" is NOT a trusted CA");
            }
        }
    }

    CertFreeCertificateChain(pChainContext);
}


// ---------------------------------------------------------------------------
// Cross-check: does the signer name match what we'd expect for the location?
// ---------------------------------------------------------------------------

static void CheckSignerLocationMismatch(const std::wstring& filePath, const SignatureInfo& info,
                                         std::vector<std::wstring>& warnings)
{
    std::wstring lowerPath = filePath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

    std::wstring lowerSigner = info.signerName;
    std::transform(lowerSigner.begin(), lowerSigner.end(), lowerSigner.begin(), ::towlower);

    // Files in Windows system directories should generally be signed by Microsoft
    bool isSystemDir = (lowerPath.find(L"\\windows\\system32\\") != std::wstring::npos
        || lowerPath.find(L"\\windows\\syswow64\\") != std::wstring::npos
        || lowerPath.find(L"\\windows\\winsxs\\") != std::wstring::npos);

    if (isSystemDir && lowerSigner.find(L"microsoft") == std::wstring::npos
        && info.signerName != L"N/A")
    {
        warnings.push_back(L"SIGNER_LOCATION_MISMATCH: File is in a Windows system directory but signed by \""
            + info.signerName + L"\" (expected Microsoft)");
    }

    // Files in temp/download directories that are signed could be legitimate,
    // but combined with other flags it's worth noting
    bool isSuspiciousDir = (lowerPath.find(L"\\temp\\") != std::wstring::npos
        || lowerPath.find(L"\\downloads\\") != std::wstring::npos
        || lowerPath.find(L"\\appdata\\local\\temp\\") != std::wstring::npos);

    if (isSuspiciousDir && info.signerName != L"N/A") {
        warnings.push_back(L"SIGNED_IN_TEMP: Signed executable found in suspicious directory");
    }
}


// ---------------------------------------------------------------------------
// Full signature analysis
// ---------------------------------------------------------------------------

SignatureInfo AnalyzeFileSignature(const std::wstring& filePath)
{
    SignatureInfo info = {};
    info.isEmbedded = false;
    info.chainTrusted = false;
    info.hashValid = false;
    info.signerName = L"N/A";
    info.issuerName = L"N/A";
    info.rootCA = L"N/A";
    info.thumbprint = L"N/A";
    info.serialNumber = L"N/A";
    info.signatureType = L"None";
    info.validFrom = L"N/A";
    info.validTo = L"N/A";

    // --- Step 1: WinVerifyTrust to check overall validity and hash integrity ---
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

    LONG trustStatus = WinVerifyTrust(NULL, &policyGUID, &winTrustData);

    // Close the verification state
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &winTrustData);

    switch (trustStatus) {
    case ERROR_SUCCESS:
        info.status = L"Signed (Valid)";
        info.hashValid = true;
        break;
    case TRUST_E_NOSIGNATURE:
        info.status = L"Unsigned";
        // No signature at all — nothing more to analyze
        return info;
    case TRUST_E_BAD_DIGEST:
        info.status = L"Signed (HASH MISMATCH)";
        info.hashValid = false;
        info.warnings.push_back(L"HASH_MISMATCH: File content does not match the signed hash. "
            L"This is a strong indicator of signature theft (e.g. SigThief) or file tampering.");
        break;
    case TRUST_E_EXPLICIT_DISTRUST:
        info.status = L"Signed (Distrusted)";
        info.warnings.push_back(L"EXPLICIT_DISTRUST: This certificate has been explicitly blacklisted.");
        break;
    case TRUST_E_SUBJECT_NOT_TRUSTED:
        info.status = L"Signed (Untrusted)";
        info.hashValid = true; // hash may be fine, but the cert isn't trusted
        info.warnings.push_back(L"UNTRUSTED_SUBJECT: Signature present but certificate is not trusted.");
        break;
    case CRYPT_E_SECURITY_SETTINGS:
        info.status = L"Signed (Blocked by Policy)";
        break;
    default:
        info.status = L"Signed (Verification Error: " + std::to_wstring(trustStatus) + L")";
        info.warnings.push_back(L"VERIFY_ERROR: WinVerifyTrust returned unexpected code " + std::to_wstring(trustStatus));
        break;
    }

    // --- Step 2: Check embedded vs catalog ---
    info.isEmbedded = HasEmbeddedSignature(filePath);
    info.signatureType = info.isEmbedded ? L"Embedded" : L"Catalog";

    if (!info.isEmbedded) {
        info.warnings.push_back(L"CATALOG_SIGNED: File uses catalog-based signing (not embedded Authenticode). "
            L"Catalog signing is normal for Windows OS files but unusual for third-party software.");
    }

    // --- Step 3: Extract certificate details from embedded signature ---
    if (info.isEmbedded) {
        HCERTSTORE hStore = NULL;
        HCRYPTMSG hMsg = NULL;
        DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;

        BOOL queryOk = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE, filePath.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0, &dwEncoding, &dwContentType, &dwFormatType,
            &hStore, &hMsg, NULL);

        if (queryOk) {
            // Get signer info
            DWORD signerInfoSize = 0;
            CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &signerInfoSize);

            if (signerInfoSize > 0) {
                std::vector<BYTE> signerInfoBuf(signerInfoSize);
                CMSG_SIGNER_INFO* pSignerInfo = reinterpret_cast<CMSG_SIGNER_INFO*>(signerInfoBuf.data());

                if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &signerInfoSize)) {
                    // Find signer certificate
                    CERT_INFO findInfo = {};
                    findInfo.Issuer = pSignerInfo->Issuer;
                    findInfo.SerialNumber = pSignerInfo->SerialNumber;

                    PCCERT_CONTEXT pSignerCert = CertFindCertificateInStore(
                        hStore, dwEncoding, 0, CERT_FIND_SUBJECT_CERT, &findInfo, NULL);

                    if (pSignerCert) {
                        // Extract all certificate fields
                        info.signerName = GetCertNameW(pSignerCert, 0);
                        info.issuerName = GetCertNameW(pSignerCert, CERT_NAME_ISSUER_FLAG);
                        info.thumbprint = GetCertThumbprintW(pSignerCert);
                        info.serialNumber = SerialBlobToHexW(pSignerCert->pCertInfo->SerialNumber);
                        info.validFrom = FileTimeToStringW(pSignerCert->pCertInfo->NotBefore);
                        info.validTo = FileTimeToStringW(pSignerCert->pCertInfo->NotAfter);

                        // --- Step 4: Build and analyze the certificate chain ---
                        AnalyzeCertChain(pSignerCert, info);

                        // --- Step 5: Cross-check signer vs file location ---
                        CheckSignerLocationMismatch(filePath, info, info.warnings);

                        CertFreeCertificateContext(pSignerCert);
                    }
                }
            }

            CryptMsgClose(hMsg);
            CertCloseStore(hStore, 0);
        }
    }

    return info;
}


// ---------------------------------------------------------------------------
// Backwards-compatible wrappers
// ---------------------------------------------------------------------------

std::wstring GetFileSignatureStatus(const std::wstring& filePath)
{
    SignatureInfo info = AnalyzeFileSignature(filePath);
    return info.status;
}

std::wstring GetFileSignerName(const std::wstring& filePath)
{
    SignatureInfo info = AnalyzeFileSignature(filePath);
    return info.signerName;
}


// ---------------------------------------------------------------------------
// Version info helpers (shared buffer loader)
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
    if (!VerQueryValueW(buffer.data(), L"\\", reinterpret_cast<LPVOID*>(&pFileInfo), &len))
        return L"N/A";
    if (len == 0 || pFileInfo == nullptr) return L"N/A";

    std::wstringstream ss;
    ss << HIWORD(pFileInfo->dwFileVersionMS) << L"."
       << LOWORD(pFileInfo->dwFileVersionMS) << L"."
       << HIWORD(pFileInfo->dwFileVersionLS) << L"."
       << LOWORD(pFileInfo->dwFileVersionLS);
    return ss.str();
}


std::wstring GetFileDeveloper(const std::wstring& filePath)
{
    std::vector<BYTE> buffer;
    if (!LoadVersionInfo(filePath, buffer)) return L"Unknown";

    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    };

    LANGANDCODEPAGE* pTranslate = nullptr;
    UINT cbTranslate = 0;

    if (!VerQueryValueW(buffer.data(), L"\\VarFileInfo\\Translation",
        reinterpret_cast<LPVOID*>(&pTranslate), &cbTranslate))
    {
        return L"Unknown";
    }
    if (cbTranslate < sizeof(LANGANDCODEPAGE)) return L"Unknown";

    wchar_t subBlock[256];
    swprintf_s(subBlock, 256, L"\\StringFileInfo\\%04x%04x\\CompanyName",
        pTranslate[0].wLanguage, pTranslate[0].wCodePage);

    LPVOID pCompanyName = nullptr;
    UINT companyNameLen = 0;
    if (!VerQueryValueW(buffer.data(), subBlock, &pCompanyName, &companyNameLen))
        return L"Unknown";
    if (companyNameLen == 0) return L"Unknown";

    return std::wstring(static_cast<wchar_t*>(pCompanyName));
}


// ---------------------------------------------------------------------------
// Size and entropy
// ---------------------------------------------------------------------------
int64_t GetFileSizeBytes(const std::wstring& filePath)
{
    WIN32_FILE_ATTRIBUTE_DATA info = {};
    if (!GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &info)) {
        OutputDebugStringW((L"[FileAnalysis] GetFileSizeBytes failed: " + filePath + L"\n").c_str());
        return -1;
    }
    ULARGE_INTEGER size;
    size.LowPart = info.nFileSizeLow;
    size.HighPart = info.nFileSizeHigh;
    return static_cast<int64_t>(size.QuadPart);
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
        for (DWORD i = 0; i < bytesRead; ++i) {
            counts[buffer[i]]++;
        }
        total += bytesRead;
    }
    CloseHandle(hFile);

    if (total == 0) {
        return 0.0;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (counts[i] > 0) {
            double probability = static_cast<double>(counts[i]) / static_cast<double>(total);
            entropy -= probability * std::log2(probability);
        }
    }
    return entropy;
}


// ---------------------------------------------------------------------------
// File attributes
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


// ---------------------------------------------------------------------------
// DACL / permissions summary
// ---------------------------------------------------------------------------

std::wstring GetFilePermissions(const std::wstring& filePath)
{
    PSECURITY_DESCRIPTOR pSD = NULL;
    PSID pOwnerSid = NULL;
    PACL pDacl = NULL;

    DWORD result = GetNamedSecurityInfoW(
        filePath.c_str(),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &pOwnerSid,
        NULL,
        &pDacl,
        NULL,
        &pSD);

    if (result != ERROR_SUCCESS) {
        return L"Access Denied";
    }

    std::wstringstream ss;

    // Resolve owner SID to account name
    wchar_t ownerName[256] = {};
    wchar_t domainName[256] = {};
    DWORD ownerNameLen = 256;
    DWORD domainNameLen = 256;
    SID_NAME_USE sidType;

    if (LookupAccountSidW(NULL, pOwnerSid, ownerName, &ownerNameLen, domainName, &domainNameLen, &sidType)) {
        ss << domainName << L"\\" << ownerName;
    }
    else {
        // Fall back to SID string
        LPWSTR sidStr = NULL;
        if (ConvertSidToStringSidW(pOwnerSid, &sidStr)) {
            ss << sidStr;
            LocalFree(sidStr);
        }
        else {
            ss << L"Unknown Owner";
        }
    }

    // Walk the DACL entries for a compact summary
    if (pDacl != NULL) {
        ACL_SIZE_INFORMATION aclInfo = {};
        if (GetAclInformation(pDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation)) {
            int allowCount = 0;
            int denyCount = 0;
            for (DWORD i = 0; i < aclInfo.AceCount; i++) {
                LPVOID pAce = NULL;
                if (GetAce(pDacl, i, &pAce)) {
                    ACE_HEADER* aceHeader = static_cast<ACE_HEADER*>(pAce);
                    if (aceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE)
                        allowCount++;
                    else if (aceHeader->AceType == ACCESS_DENIED_ACE_TYPE)
                        denyCount++;
                }
            }
            ss << L" [Allow:" << allowCount << L" Deny:" << denyCount << L"]";
        }
    }

    if (pSD) LocalFree(pSD);
    return ss.str();
}
