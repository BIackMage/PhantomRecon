#include "pch.h"
#include "HashUtils.h"

#include <bcrypt.h>
#include <wincrypt.h>
#include <vector>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

// ---------------------------------------------------------------------------
// Debug logging
// ---------------------------------------------------------------------------
static void DebugLog(const wchar_t* msg)
{
    OutputDebugStringW(L"[HashUtils] ");
    OutputDebugStringW(msg);
    OutputDebugStringW(L"\n");
}

// ---------------------------------------------------------------------------
// ComputeFileMD5Hex: CryptoAPI MD5, 64 KB reads, lowercase hex out.
// MD5 is kept only because the .prbl baseline format and older CSVs carry it.
// ---------------------------------------------------------------------------
std::wstring ComputeFileMD5Hex(const std::wstring& filePath)
{
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DebugLog((L"MD5: failed to open file: " + filePath).c_str());
        return L"";
    }

    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        DebugLog(L"MD5: CryptAcquireContext failed");
        CloseHandle(hFile);
        return L"";
    }

    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        DebugLog(L"MD5: CryptCreateHash failed");
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return L"";
    }

    std::vector<BYTE> buffer(64 * 1024);
    DWORD bytesRead = 0;
    bool ok = true;
    while (ReadFile(hFile, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, NULL) && bytesRead > 0) {
        if (!CryptHashData(hHash, buffer.data(), bytesRead, 0)) {
            DebugLog(L"MD5: CryptHashData failed");
            ok = false;
            break;
        }
    }
    CloseHandle(hFile);

    std::wstring result;
    if (ok) {
        BYTE digest[16] = {};
        DWORD digestSize = sizeof(digest);
        if (CryptGetHashParam(hHash, HP_HASHVAL, digest, &digestSize, 0)) {
            std::wstringstream ss;
            ss << std::hex << std::setfill(L'0');
            for (DWORD i = 0; i < digestSize; ++i) {
                ss << std::setw(2) << static_cast<unsigned int>(digest[i]);
            }
            result = ss.str();
        }
        else {
            DebugLog(L"MD5: CryptGetHashParam failed");
        }
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
}

// ---------------------------------------------------------------------------
// ComputeFileSHA256 — BCrypt-based SHA-256 file hashing
// ---------------------------------------------------------------------------
std::wstring ComputeFileSHA256(const std::wstring& filePath)
{
    OutputDebugStringW((L"[HashUtils] ComputeFileSHA256: " + filePath + L"\n").c_str());

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = 0;
    std::wstring result;

    // Open the SHA-256 algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        DebugLog(L"BCryptOpenAlgorithmProvider failed");
        return L"";
    }

    // Query hash object size
    DWORD hashObjectSize = 0;
    DWORD dataSize = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PBYTE>(&hashObjectSize), sizeof(DWORD), &dataSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        DebugLog(L"BCryptGetProperty OBJECT_LENGTH failed");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return L"";
    }

    // Query hash output size (should be 32 bytes for SHA-256)
    DWORD hashSize = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
        reinterpret_cast<PBYTE>(&hashSize), sizeof(DWORD), &dataSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        DebugLog(L"BCryptGetProperty HASH_LENGTH failed");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return L"";
    }

    // Allocate hash object buffer
    std::vector<BYTE> hashObject(hashObjectSize);
    std::vector<BYTE> hashValue(hashSize);

    // Create the hash object
    status = BCryptCreateHash(hAlg, &hHash, hashObject.data(), hashObjectSize, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        DebugLog(L"BCryptCreateHash failed");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return L"";
    }

    // Open the file
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DebugLog(L"Failed to open file for hashing");
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return L"";
    }

    // Read file in chunks and feed to hash
    BYTE readBuffer[8192];
    DWORD bytesRead = 0;
    while (ReadFile(hFile, readBuffer, sizeof(readBuffer), &bytesRead, NULL) && bytesRead > 0) {
        status = BCryptHashData(hHash, readBuffer, bytesRead, 0);
        if (!BCRYPT_SUCCESS(status)) {
            DebugLog(L"BCryptHashData failed");
            CloseHandle(hFile);
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return L"";
        }
    }

    CloseHandle(hFile);

    // Finalize the hash
    status = BCryptFinishHash(hHash, hashValue.data(), hashSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        DebugLog(L"BCryptFinishHash failed");
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return L"";
    }

    // Convert to hex string
    std::wstringstream ss;
    for (DWORD i = 0; i < hashSize; i++) {
        ss << std::hex << std::setfill(L'0') << std::setw(2) << hashValue[i];
    }
    result = ss.str();

    // Cleanup
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return result;
}
