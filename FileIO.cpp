#include "pch.h"
#include "FileIO.h"

#include "AppPaths.h"
#include "StringConv.h"

#include <windows.h>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[FileIO] " + msg + L"\n").c_str());
}

static bool WriteAll(HANDLE hFile, const void* data, size_t size)
{
    const uint8_t* p = static_cast<const uint8_t*>(data);
    while (size > 0) {
        DWORD chunk = size > 0x10000000 ? 0x10000000 : static_cast<DWORD>(size);
        DWORD written = 0;
        if (!WriteFile(hFile, p, chunk, &written, NULL) || written == 0) {
            return false;
        }
        p += written;
        size -= written;
    }
    return true;
}

bool WriteBinaryFile(const std::wstring& path, const void* data, size_t size)
{
    HANDLE hFile = CreateFileW(ToExtendedPath(path).c_str(), GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DebugLog(L"WriteBinaryFile: cannot create " + path + L" (error " + std::to_wstring(GetLastError()) + L")");
        return false;
    }
    bool ok = WriteAll(hFile, data, size);
    CloseHandle(hFile);
    return ok;
}

bool WriteUtf8File(const std::wstring& path, const std::wstring& text, bool withBom)
{
    std::string utf8 = WideToUtf8(text);
    std::string buffer;
    if (withBom) buffer = "\xEF\xBB\xBF";
    buffer += utf8;
    return WriteBinaryFile(path, buffer.data(), buffer.size());
}

bool AppendUtf8File(const std::wstring& path, const std::wstring& text,
                    const std::wstring& headerIfNew, bool withBom)
{
    HANDLE hFile = CreateFileW(ToExtendedPath(path).c_str(), FILE_APPEND_DATA | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DebugLog(L"AppendUtf8File: cannot open " + path + L" (error " + std::to_wstring(GetLastError()) + L")");
        return false;
    }

    LARGE_INTEGER size = {};
    GetFileSizeEx(hFile, &size);

    std::string buffer;
    if (size.QuadPart == 0) {
        if (withBom) buffer = "\xEF\xBB\xBF";
        if (!headerIfNew.empty()) buffer += WideToUtf8(headerIfNew);
    }
    buffer += WideToUtf8(text);

    bool ok = WriteAll(hFile, buffer.data(), buffer.size());
    CloseHandle(hFile);
    return ok;
}

bool ReadBinaryFile(const std::wstring& path, std::vector<uint8_t>& out, size_t maxBytes)
{
    out.clear();
    HANDLE hFile = CreateFileW(ToExtendedPath(path).c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(hFile, &size)) {
        CloseHandle(hFile);
        return false;
    }
    size_t toRead = static_cast<size_t>(size.QuadPart);
    if (toRead > maxBytes) toRead = maxBytes;

    out.resize(toRead);
    size_t done = 0;
    while (done < toRead) {
        DWORD chunk = (toRead - done) > 0x1000000 ? 0x1000000 : static_cast<DWORD>(toRead - done);
        DWORD got = 0;
        if (!ReadFile(hFile, out.data() + done, chunk, &got, NULL) || got == 0) break;
        done += got;
    }
    out.resize(done);
    CloseHandle(hFile);
    return true;
}

static bool IsValidUtf8(const uint8_t* data, size_t size)
{
    size_t i = 0;
    while (i < size) {
        uint8_t c = data[i];
        size_t extra = 0;
        if (c < 0x80) { i++; continue; }
        else if ((c & 0xE0) == 0xC0) extra = 1;
        else if ((c & 0xF0) == 0xE0) extra = 2;
        else if ((c & 0xF8) == 0xF0) extra = 3;
        else return false;
        // A sequence cut off by the end of the buffer is tolerated: the read may have been capped.
        if (i + extra >= size) return true;
        for (size_t k = 1; k <= extra; ++k) {
            if ((data[i + k] & 0xC0) != 0x80) return false;
        }
        i += extra + 1;
    }
    return true;
}

std::wstring DecodeTextBytes(const uint8_t* data, size_t size)
{
    if (size >= 2 && data[0] == 0xFF && data[1] == 0xFE) {
        size_t chars = (size - 2) / 2;
        return std::wstring(reinterpret_cast<const wchar_t*>(data + 2), chars);
    }
    if (size >= 2 && data[0] == 0xFE && data[1] == 0xFF) {
        std::wstring out;
        out.reserve((size - 2) / 2);
        for (size_t i = 2; i + 1 < size; i += 2) {
            out += static_cast<wchar_t>((data[i] << 8) | data[i + 1]);
        }
        return out;
    }
    size_t start = 0;
    if (size >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) start = 3;

    const uint8_t* p = data + start;
    size_t n = size - start;
    if (n == 0) return L"";

    UINT codePage = IsValidUtf8(p, n) ? CP_UTF8 : CP_ACP;
    int wideLen = MultiByteToWideChar(codePage, 0, reinterpret_cast<const char*>(p), static_cast<int>(n), NULL, 0);
    if (wideLen <= 0) {
        // Last resort: widen byte by byte so nothing is lost for pattern matching.
        std::wstring out;
        out.reserve(n);
        for (size_t i = 0; i < n; ++i) out += static_cast<wchar_t>(p[i]);
        return out;
    }
    std::wstring out(static_cast<size_t>(wideLen), L'\0');
    MultiByteToWideChar(codePage, 0, reinterpret_cast<const char*>(p), static_cast<int>(n), &out[0], wideLen);
    return out;
}

bool ReadTextFile(const std::wstring& path, std::wstring& out, size_t maxBytes)
{
    std::vector<uint8_t> bytes;
    if (!ReadBinaryFile(path, bytes, maxBytes)) {
        out.clear();
        return false;
    }
    out = DecodeTextBytes(bytes.data(), bytes.size());
    return true;
}
