#pragma once

#include <string>
#include <vector>
#include <windows.h>

// Detailed signature analysis result
struct SignatureInfo {
    std::wstring status;           // "Signed (Valid)", "Unsigned", "Signed (Hash Mismatch)", etc.
    std::wstring signerName;       // "Microsoft Corporation", "N/A", etc.
    std::wstring issuerName;       // Issuing CA name
    std::wstring rootCA;           // Root CA in the chain
    std::wstring thumbprint;       // Certificate SHA1 thumbprint (hex)
    std::wstring serialNumber;     // Certificate serial number
    std::wstring signatureType;    // "Embedded" or "Catalog"
    std::wstring validFrom;        // Certificate validity start
    std::wstring validTo;          // Certificate validity end
    bool isEmbedded;               // true = embedded Authenticode, false = catalog-signed or unsigned
    bool chainTrusted;             // true if chain resolves to a trusted root CA
    bool hashValid;                // true if the file hash matches the signature hash
    std::vector<std::wstring> warnings;  // suspicious indicators
};

// Full signature analysis — checks embedded vs catalog, chain trust,
// hash integrity, certificate details, and flags suspicious patterns.
SignatureInfo AnalyzeFileSignature(const std::wstring& filePath);

// Simple status string (backwards-compatible with the old GetFileSignatureStatus)
std::wstring GetFileSignatureStatus(const std::wstring& filePath);

// Extract the signer name from the Authenticode signature (e.g. "Microsoft Corporation")
// Returns "N/A" if no signature is present.
std::wstring GetFileSignerName(const std::wstring& filePath);

// File version string from the VS_FIXEDFILEINFO resource (e.g. "10.0.19041.1")
// Returns "N/A" if no version resource exists.
std::wstring GetFileVersion(const std::wstring& filePath);

// CompanyName from the StringFileInfo version resource
// Returns "Unknown" if not available.
std::wstring GetFileDeveloper(const std::wstring& filePath);

// File attribute checks
std::wstring GetFileReadOnly(const std::wstring& filePath);
std::wstring GetFileHidden(const std::wstring& filePath);

// DACL permissions summary (owner + access entries)
std::wstring GetFilePermissions(const std::wstring& filePath);
