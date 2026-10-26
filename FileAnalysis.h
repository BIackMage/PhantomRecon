#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>

// ---------------------------------------------------------------------------
// FileAnalysis: signatures, certificate chains, revocation, version info,
// attributes, permissions, size and entropy for one file.
// ---------------------------------------------------------------------------

// How hard to try when checking whether a signing certificate was revoked.
enum class RevocationMode {
    Off = 0,        // never check
    CacheOnly = 1,  // use only what Windows already has cached (no network); offline-safe default
    Online = 2,     // allow Windows to download CRLs / OCSP answers (never used in portable mode)
};

// Detailed signature analysis result
struct SignatureInfo {
    std::wstring status;           // "Signed (Valid)", "Unsigned", "Signed (HASH MISMATCH)", ...
    std::wstring signerName;       // embedded signer, or "N/A"
    std::wstring issuerName;       // issuing CA name
    std::wstring rootCA;           // root CA in the chain
    std::wstring thumbprint;       // signer certificate SHA-1 thumbprint (hex with colons)
    std::wstring serialNumber;
    std::wstring signatureType;    // "Embedded", "Catalog" or "None"
    std::wstring validFrom;
    std::wstring validTo;
    std::wstring catalogFile;      // security catalog that covers the file (catalog-signed only)
    std::wstring catalogSigner;    // who signed that catalog
    std::wstring revocation;       // "Not checked", "Good", "REVOKED", "Unknown (offline)", "Unknown (...)"
    bool isEmbedded = false;
    bool chainTrusted = false;
    bool hashValid = false;
    std::vector<std::wstring> warnings;  // "CODE: detail"
};

// Full signature analysis. Unsigned files are also checked against the Windows
// security catalogs, so Windows' own catalog-signed files report as signed.
SignatureInfo AnalyzeFileSignature(const std::wstring& filePath, RevocationMode revocation = RevocationMode::Off);

// Cached, cheap summary for checks that only need "who signed this and is it valid".
struct SignatureSummary {
    std::wstring status;      // as SignatureInfo::status
    std::wstring signer;      // embedded signer, else catalog signer, else ""
    bool         valid = false;
    bool         microsoft = false;   // valid and signed by Microsoft
};
SignatureSummary GetSignatureSummary(const std::wstring& filePath);

// True when the signer name belongs to Microsoft.
bool IsMicrosoftSignerName(const std::wstring& signer);

// Write the revocation cache to disk (called at the end of a scan).
void SaveRevocationCache();

// Simple status string (backwards-compatible)
std::wstring GetFileSignatureStatus(const std::wstring& filePath);

// Signer name, "N/A" when unsigned
std::wstring GetFileSignerName(const std::wstring& filePath);

// File version "10.0.19041.1", "N/A" when absent
std::wstring GetFileVersion(const std::wstring& filePath);

// CompanyName, "Unknown" when absent
std::wstring GetFileDeveloper(const std::wstring& filePath);

// ProductName, "" when absent
std::wstring GetFileProductName(const std::wstring& filePath);

std::wstring GetFileReadOnly(const std::wstring& filePath);
std::wstring GetFileHidden(const std::wstring& filePath);

// Owner and allow / deny ACE count
std::wstring GetFilePermissions(const std::wstring& filePath);

// File size in bytes, or -1 if the file cannot be read.
int64_t GetFileSizeBytes(const std::wstring& filePath);

// Shannon entropy of the whole file in bits per byte (0.0 to 8.0). 0.0 if unreadable.
double CalculateFileEntropy(const std::wstring& filePath);

// Entropy of a buffer (bits per byte).
double CalculateBufferEntropy(const uint8_t* data, size_t length);
