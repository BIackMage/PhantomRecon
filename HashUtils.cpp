#include "pch.h"
#include "HashUtils.h"

#include "AppPaths.h"

#include <bcrypt.h>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

// ---------------------------------------------------------------------------
// Debug logging
// ---------------------------------------------------------------------------
static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[HashUtils] " + msg + L"\n").c_str());
}

static std::wstring ToHex(const std::vector<BYTE>& bytes)
{
    static const wchar_t* digits = L"0123456789abcdef";
    std::wstring out;
    out.reserve(bytes.size() * 2);
    for (BYTE b : bytes) {
        out += digits[b >> 4];
        out += digits[b & 0x0F];
    }
    return out;
}

// One BCrypt hash object. Feed() as often as needed, then Finish().
class BCryptHasher {
public:
    explicit BCryptHasher(LPCWSTR algorithm)
    {
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&m_alg, algorithm, NULL, 0))) {
            DebugLog(L"BCryptOpenAlgorithmProvider failed");
            m_alg = NULL;
            return;
        }
        DWORD objectSize = 0;
        DWORD hashSize = 0;
        DWORD got = 0;
        if (!BCRYPT_SUCCESS(BCryptGetProperty(m_alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PBYTE>(&objectSize), sizeof(DWORD), &got, 0)) ||
            !BCRYPT_SUCCESS(BCryptGetProperty(m_alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PBYTE>(&hashSize), sizeof(DWORD), &got, 0))) {
            DebugLog(L"BCryptGetProperty failed");
            return;
        }
        m_object.resize(objectSize);
        m_digest.resize(hashSize);
        if (!BCRYPT_SUCCESS(BCryptCreateHash(m_alg, &m_hash, m_object.data(), objectSize, NULL, 0, 0))) {
            DebugLog(L"BCryptCreateHash failed");
            m_hash = NULL;
        }
    }

    ~BCryptHasher()
    {
        if (m_hash) BCryptDestroyHash(m_hash);
        if (m_alg) BCryptCloseAlgorithmProvider(m_alg, 0);
    }

    BCryptHasher(const BCryptHasher&) = delete;
    BCryptHasher& operator=(const BCryptHasher&) = delete;

    bool Ok() const { return m_hash != NULL; }

    bool Feed(const void* data, size_t size)
    {
        const BYTE* p = static_cast<const BYTE*>(data);
        while (size > 0) {
            ULONG chunk = size > 0x40000000 ? 0x40000000 : static_cast<ULONG>(size);
            if (!BCRYPT_SUCCESS(BCryptHashData(m_hash, const_cast<PUCHAR>(p), chunk, 0))) return false;
            p += chunk;
            size -= chunk;
        }
        return true;
    }

    std::wstring Finish()
    {
        if (!BCRYPT_SUCCESS(BCryptFinishHash(m_hash, m_digest.data(), static_cast<ULONG>(m_digest.size()), 0))) {
            return L"";
        }
        return ToHex(m_digest);
    }

private:
    BCRYPT_ALG_HANDLE  m_alg = NULL;
    BCRYPT_HASH_HANDLE m_hash = NULL;
    std::vector<BYTE>  m_object;
    std::vector<BYTE>  m_digest;
};

static std::wstring HashFile(const std::wstring& filePath, LPCWSTR algorithm)
{
    BCryptHasher hasher(algorithm);
    if (!hasher.Ok()) return L"";

    // ToExtendedPath leaves short and already prefixed paths alone, so deep paths open
    // here even when a caller passes the plain form.
    HANDLE hFile = CreateFileW(ToExtendedPath(filePath).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DebugLog(L"Cannot open for hashing: " + filePath + L" (error " + std::to_wstring(GetLastError()) + L")");
        return L"";
    }

    std::vector<BYTE> buffer(64 * 1024);
    bool ok = true;
    while (true) {
        DWORD bytesRead = 0;
        if (!ReadFile(hFile, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, NULL)) {
            // A read error is not the end of the file. Returning the digest of what was read
            // so far (often the empty-input digest) would look like a real, unchanged hash.
            DebugLog(L"Read failed while hashing (error " + std::to_wstring(GetLastError()) + L"): " + filePath);
            ok = false;
            break;
        }
        if (bytesRead == 0) break;   // end of file
        if (!hasher.Feed(buffer.data(), bytesRead)) {
            DebugLog(L"BCryptHashData failed: " + filePath);
            ok = false;
            break;
        }
    }
    CloseHandle(hFile);
    if (!ok) return L"";
    return hasher.Finish();
}

static std::wstring HashBuffer(const void* data, size_t size, LPCWSTR algorithm)
{
    BCryptHasher hasher(algorithm);
    if (!hasher.Ok()) return L"";
    if (size > 0 && !hasher.Feed(data, size)) return L"";
    return hasher.Finish();
}

std::wstring ComputeFileSHA256(const std::wstring& filePath)
{
    return HashFile(filePath, BCRYPT_SHA256_ALGORITHM);
}

std::wstring ComputeFileMD5Hex(const std::wstring& filePath)
{
    return HashFile(filePath, BCRYPT_MD5_ALGORITHM);
}

std::wstring ComputeBufferMD5Hex(const void* data, size_t size)
{
    return HashBuffer(data, size, BCRYPT_MD5_ALGORITHM);
}

std::wstring ComputeBufferSHA256Hex(const void* data, size_t size)
{
    return HashBuffer(data, size, BCRYPT_SHA256_ALGORITHM);
}
