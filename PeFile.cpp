#include "pch.h"
#include "PeFile.h"

#include "AppPaths.h"
#include "FileAnalysis.h"
#include "HashUtils.h"
#include "StringConv.h"
#include "TextUtils.h"

#include <windows.h>
#include <imagehlp.h>
#include <algorithm>
#include <cstring>

#pragma comment(lib, "imagehlp.lib")

// ---------------------------------------------------------------------------
// Bounds-checked view over the mapped bytes
// ---------------------------------------------------------------------------
class ByteView {
public:
    ByteView(const uint8_t* data, size_t size) : m_data(data), m_size(size) {}

    bool Has(uint64_t offset, uint64_t length) const
    {
        return offset <= m_size && length <= m_size - offset;
    }

    template <typename T>
    bool Read(uint64_t offset, T& out) const
    {
        if (!Has(offset, sizeof(T))) return false;
        std::memcpy(&out, m_data + offset, sizeof(T));
        return true;
    }

    std::string ReadAscii(uint64_t offset, size_t maxLen) const
    {
        std::string s;
        for (size_t i = 0; i < maxLen && offset + i < m_size; ++i) {
            char c = static_cast<char>(m_data[offset + i]);
            if (c == '\0') break;
            s += c;
        }
        return s;
    }

    const uint8_t* Ptr(uint64_t offset) const { return m_data + offset; }
    size_t Size() const { return m_size; }

private:
    const uint8_t* m_data;
    size_t         m_size;
};

static uint32_t RvaToOffset(const std::vector<PeSection>& sections, uint32_t rva, uint32_t sizeOfHeaders)
{
    if (rva < sizeOfHeaders) return rva;
    for (const PeSection& s : sections) {
        uint32_t span = (std::max)(s.virtualSize, s.rawSize);
        if (rva >= s.virtualAddress && rva < s.virtualAddress + span) {
            uint32_t delta = rva - s.virtualAddress;
            if (delta >= s.rawSize) return 0;   // in the zero-filled tail, not on disk
            return s.rawPointer + delta;
        }
    }
    return 0;
}

static bool OddSectionName(const char raw[8])
{
    bool empty = true;
    for (int i = 0; i < 8; ++i) {
        unsigned char c = static_cast<unsigned char>(raw[i]);
        if (c == 0) break;
        empty = false;
        if (c < 0x20 || c > 0x7E) return true;
    }
    return empty;
}

// ---------------------------------------------------------------------------
// The parse itself (may touch bad pages; called under __try)
// ---------------------------------------------------------------------------
static void ParseImpl(const uint8_t* data, size_t size, PeInfo& pe)
{
    ByteView v(data, size);
    pe.fileSize = static_cast<int64_t>(size);

    IMAGE_DOS_HEADER dos = {};
    if (!v.Read(0, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        pe.error = L"No MZ header";
        return;
    }
    if (dos.e_lfanew <= 0 || static_cast<uint64_t>(dos.e_lfanew) > size) {
        pe.error = L"Bad e_lfanew";
        return;
    }

    uint32_t ntOffset = static_cast<uint32_t>(dos.e_lfanew);
    DWORD signature = 0;
    if (!v.Read(ntOffset, signature) || signature != IMAGE_NT_SIGNATURE) {
        pe.error = L"No PE signature";
        return;
    }

    IMAGE_FILE_HEADER fh = {};
    uint32_t fhOffset = ntOffset + 4;
    if (!v.Read(fhOffset, fh)) {
        pe.error = L"Truncated file header";
        return;
    }
    pe.machine = fh.Machine;
    pe.timestamp = fh.TimeDateStamp;
    pe.isDll = (fh.Characteristics & IMAGE_FILE_DLL) != 0;
    if (fh.Characteristics & IMAGE_FILE_SYSTEM) pe.isDriver = true;

    uint32_t optOffset = fhOffset + sizeof(IMAGE_FILE_HEADER);
    WORD magic = 0;
    if (!v.Read(optOffset, magic)) {
        pe.error = L"Truncated optional header";
        return;
    }

    IMAGE_DATA_DIRECTORY dirs[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = {};
    DWORD numDirs = 0;
    uint32_t checksumOffset = 0;

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 opt = {};
        if (!v.Read(optOffset, opt)) {
            // A short optional header is legal; read what is there.
            size_t avail = (std::min)(static_cast<size_t>(fh.SizeOfOptionalHeader), sizeof(opt));
            if (!v.Has(optOffset, avail)) { pe.error = L"Truncated optional header"; return; }
            std::memcpy(&opt, v.Ptr(optOffset), avail);
        }
        pe.is64 = true;
        pe.imageBase = opt.ImageBase;
        pe.entryPointRva = opt.AddressOfEntryPoint;
        pe.subsystem = opt.Subsystem;
        pe.sizeOfHeaders = opt.SizeOfHeaders;
        pe.checksumHeader = opt.CheckSum;
        numDirs = (std::min)(static_cast<DWORD>(IMAGE_NUMBEROF_DIRECTORY_ENTRIES), opt.NumberOfRvaAndSizes);
        for (DWORD i = 0; i < numDirs; ++i) dirs[i] = opt.DataDirectory[i];
        checksumOffset = optOffset + offsetof(IMAGE_OPTIONAL_HEADER64, CheckSum);
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 opt = {};
        if (!v.Read(optOffset, opt)) {
            size_t avail = (std::min)(static_cast<size_t>(fh.SizeOfOptionalHeader), sizeof(opt));
            if (!v.Has(optOffset, avail)) { pe.error = L"Truncated optional header"; return; }
            std::memcpy(&opt, v.Ptr(optOffset), avail);
        }
        pe.is64 = false;
        pe.imageBase = opt.ImageBase;
        pe.entryPointRva = opt.AddressOfEntryPoint;
        pe.subsystem = opt.Subsystem;
        pe.sizeOfHeaders = opt.SizeOfHeaders;
        pe.checksumHeader = opt.CheckSum;
        numDirs = (std::min)(static_cast<DWORD>(IMAGE_NUMBEROF_DIRECTORY_ENTRIES), opt.NumberOfRvaAndSizes);
        for (DWORD i = 0; i < numDirs; ++i) dirs[i] = opt.DataDirectory[i];
        checksumOffset = optOffset + offsetof(IMAGE_OPTIONAL_HEADER32, CheckSum);
    }
    else {
        pe.error = L"Unknown optional header magic";
        return;
    }
    (void)checksumOffset;
    if (pe.subsystem == IMAGE_SUBSYSTEM_NATIVE) pe.isDriver = true;

    // Sections
    uint32_t secOffset = optOffset + fh.SizeOfOptionalHeader;
    WORD numSections = (std::min)(fh.NumberOfSections, static_cast<WORD>(96));
    int64_t lastRawEnd = pe.sizeOfHeaders;
    for (WORD i = 0; i < numSections; ++i) {
        IMAGE_SECTION_HEADER sh = {};
        if (!v.Read(secOffset + i * sizeof(IMAGE_SECTION_HEADER), sh)) break;
        PeSection s;
        char rawName[9] = {};
        std::memcpy(rawName, sh.Name, 8);
        s.name = rawName;
        s.nameHasOddChars = OddSectionName(reinterpret_cast<const char*>(sh.Name));
        s.virtualAddress = sh.VirtualAddress;
        s.virtualSize = sh.Misc.VirtualSize;
        s.rawPointer = sh.PointerToRawData;
        s.rawSize = sh.SizeOfRawData;
        s.characteristics = sh.Characteristics;
        if (s.rawSize > 0 && v.Has(s.rawPointer, 1)) {
            uint64_t sample = (std::min)(static_cast<uint64_t>(s.rawSize), static_cast<uint64_t>(4096));
            sample = (std::min)(sample, static_cast<uint64_t>(size - s.rawPointer));
            s.entropySample = CalculateBufferEntropy(v.Ptr(s.rawPointer), static_cast<size_t>(sample));
            int64_t end = static_cast<int64_t>(s.rawPointer) + s.rawSize;
            if (end > lastRawEnd) lastRawEnd = end;
        }
        pe.sections.push_back(s);
    }

    // Entry point bytes
    if (pe.entryPointRva != 0) {
        uint32_t epOffset = RvaToOffset(pe.sections, pe.entryPointRva, pe.sizeOfHeaders);
        if (epOffset != 0 && v.Has(epOffset, 16)) {
            pe.entryBytes.assign(v.Ptr(epOffset), v.Ptr(epOffset) + 16);
        }
    }

    // Imports
    if (numDirs > IMAGE_DIRECTORY_ENTRY_IMPORT && dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0) {
        uint32_t descOffset = RvaToOffset(pe.sections, dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pe.sizeOfHeaders);
        for (int d = 0; descOffset != 0 && d < 4096; ++d) {
            IMAGE_IMPORT_DESCRIPTOR desc = {};
            if (!v.Read(descOffset + d * sizeof(IMAGE_IMPORT_DESCRIPTOR), desc)) break;
            if (desc.OriginalFirstThunk == 0 && desc.FirstThunk == 0 && desc.Name == 0) break;

            std::string dllName;
            uint32_t nameOffset = RvaToOffset(pe.sections, desc.Name, pe.sizeOfHeaders);
            if (nameOffset != 0) dllName = v.ReadAscii(nameOffset, 256);

            uint32_t thunkRva = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk;
            uint32_t thunkOffset = RvaToOffset(pe.sections, thunkRva, pe.sizeOfHeaders);
            if (thunkOffset == 0) continue;

            for (int t = 0; t < 65536; ++t) {
                PeImport imp;
                imp.dll = dllName;
                if (pe.is64) {
                    ULONGLONG thunk = 0;
                    if (!v.Read(thunkOffset + t * 8ULL, thunk) || thunk == 0) break;
                    if (thunk & IMAGE_ORDINAL_FLAG64) {
                        imp.byOrdinal = true;
                        imp.ordinal = static_cast<uint16_t>(thunk & 0xFFFF);
                    }
                    else {
                        uint32_t hintOffset = RvaToOffset(pe.sections, static_cast<uint32_t>(thunk & 0x7FFFFFFF), pe.sizeOfHeaders);
                        if (hintOffset == 0) continue;
                        imp.function = v.ReadAscii(hintOffset + 2, 256);
                    }
                }
                else {
                    DWORD thunk = 0;
                    if (!v.Read(thunkOffset + t * 4ULL, thunk) || thunk == 0) break;
                    if (thunk & IMAGE_ORDINAL_FLAG32) {
                        imp.byOrdinal = true;
                        imp.ordinal = static_cast<uint16_t>(thunk & 0xFFFF);
                    }
                    else {
                        uint32_t hintOffset = RvaToOffset(pe.sections, thunk & 0x7FFFFFFF, pe.sizeOfHeaders);
                        if (hintOffset == 0) continue;
                        imp.function = v.ReadAscii(hintOffset + 2, 256);
                    }
                }
                if (imp.byOrdinal || !imp.function.empty()) pe.imports.push_back(imp);
            }
        }
    }

    // .NET
    if (numDirs > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR && dirs[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0) {
        pe.isDotNet = true;
    }

    // TLS callbacks
    if (numDirs > IMAGE_DIRECTORY_ENTRY_TLS && dirs[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0) {
        uint32_t tlsOffset = RvaToOffset(pe.sections, dirs[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress, pe.sizeOfHeaders);
        uint64_t callbacksVa = 0;
        if (tlsOffset != 0) {
            if (pe.is64) {
                IMAGE_TLS_DIRECTORY64 tls = {};
                if (v.Read(tlsOffset, tls)) callbacksVa = tls.AddressOfCallBacks;
            }
            else {
                IMAGE_TLS_DIRECTORY32 tls = {};
                if (v.Read(tlsOffset, tls)) callbacksVa = tls.AddressOfCallBacks;
            }
        }
        if (callbacksVa > pe.imageBase) {
            uint32_t cbRva = static_cast<uint32_t>(callbacksVa - pe.imageBase);
            uint32_t cbOffset = RvaToOffset(pe.sections, cbRva, pe.sizeOfHeaders);
            for (uint32_t i = 0; cbOffset != 0 && i < 64; ++i) {
                uint64_t cb = 0;
                if (pe.is64) {
                    if (!v.Read(cbOffset + i * 8ULL, cb)) break;
                }
                else {
                    uint32_t cb32 = 0;
                    if (!v.Read(cbOffset + i * 4ULL, cb32)) break;
                    cb = cb32;
                }
                if (cb == 0) break;
                pe.tlsCallbackCount++;
            }
        }
    }

    // Debug directory: PDB path and reproducible-build marker
    if (numDirs > IMAGE_DIRECTORY_ENTRY_DEBUG && dirs[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress != 0) {
        uint32_t dbgOffset = RvaToOffset(pe.sections, dirs[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress, pe.sizeOfHeaders);
        uint32_t count = dirs[IMAGE_DIRECTORY_ENTRY_DEBUG].Size / sizeof(IMAGE_DEBUG_DIRECTORY);
        for (uint32_t i = 0; dbgOffset != 0 && i < count && i < 32; ++i) {
            IMAGE_DEBUG_DIRECTORY dd = {};
            if (!v.Read(dbgOffset + i * sizeof(IMAGE_DEBUG_DIRECTORY), dd)) break;
            if (dd.Type == 16 /* IMAGE_DEBUG_TYPE_REPRO */) pe.isReproducible = true;
            if (dd.Type == IMAGE_DEBUG_TYPE_CODEVIEW && dd.PointerToRawData != 0 && v.Has(dd.PointerToRawData, 24)) {
                DWORD cvSig = 0;
                v.Read(dd.PointerToRawData, cvSig);
                if (cvSig == 0x53445352 /* 'RSDS' */) {
                    pe.pdbPath = v.ReadAscii(dd.PointerToRawData + 24, 1024);
                }
                else if (cvSig == 0x3031424E /* 'NB10' */) {
                    pe.pdbPath = v.ReadAscii(dd.PointerToRawData + 16, 1024);
                }
            }
        }
    }

    // Security directory: its "VirtualAddress" is a file offset
    if (numDirs > IMAGE_DIRECTORY_ENTRY_SECURITY) {
        pe.securityDirOffset = dirs[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
        pe.securityDirSize = dirs[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
    }

    // Overlay: bytes after the last section that are not the Authenticode blob
    pe.overlayOffset = lastRawEnd;
    int64_t overlayEnd = static_cast<int64_t>(size);
    if (pe.securityDirSize > 0 && static_cast<int64_t>(pe.securityDirOffset) >= lastRawEnd) {
        int64_t secEnd = static_cast<int64_t>(pe.securityDirOffset) + pe.securityDirSize;
        if (secEnd >= overlayEnd) overlayEnd = pe.securityDirOffset;   // signature is the tail
    }
    if (overlayEnd > lastRawEnd && lastRawEnd > 0) {
        pe.overlaySize = overlayEnd - lastRawEnd;
        size_t sample = static_cast<size_t>((std::min)(pe.overlaySize, static_cast<int64_t>(1024 * 1024)));
        pe.overlayEntropy = CalculateBufferEntropy(v.Ptr(lastRawEnd), sample);
        // Embedded program near the start of the overlay
        size_t scan = (std::min)(sample, static_cast<size_t>(4096));
        for (size_t i = 0; i + 64 < scan; ++i) {
            const uint8_t* p = v.Ptr(lastRawEnd + i);
            if (p[0] == 'M' && p[1] == 'Z') {
                IMAGE_DOS_HEADER inner = {};
                if (v.Read(lastRawEnd + i, inner) && inner.e_lfanew > 0 && inner.e_lfanew < 4096) {
                    DWORD innerSig = 0;
                    if (v.Read(lastRawEnd + i + inner.e_lfanew, innerSig) && innerSig == IMAGE_NT_SIGNATURE) {
                        pe.overlayHasPe = true;
                        break;
                    }
                }
            }
        }
    }

    pe.valid = true;
}

static bool SafeParse(const uint8_t* data, size_t size, PeInfo* pe)
{
    __try {
        ParseImpl(data, size, *pe);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool SafeChecksum(const uint8_t* data, size_t size, DWORD* header, DWORD* computed)
{
    __try {
        return CheckSumMappedFile(const_cast<uint8_t*>(data), static_cast<DWORD>(size), header, computed) != NULL;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

PeInfo ParsePeBuffer(const uint8_t* data, size_t size)
{
    PeInfo pe;
    if (!data || size < sizeof(IMAGE_DOS_HEADER)) {
        pe.error = L"Too small";
        return pe;
    }
    if (!SafeParse(data, size, &pe)) {
        pe = PeInfo();
        pe.error = L"Access fault while parsing";
        return pe;
    }
    if (pe.valid && size < 0xFFFFFFFFull) {
        DWORD header = 0;
        DWORD computed = 0;
        if (SafeChecksum(data, size, &header, &computed)) {
            pe.checksumComputed = computed;
            pe.checksumComputedOk = true;
        }
    }
    return pe;
}

PeInfo ParsePeFile(const std::wstring& path)
{
    PeInfo pe;
    HANDLE hFile = CreateFileW(ToExtendedPath(path).c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        pe.error = L"Cannot open file";
        return pe;
    }

    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(hFile, &size) || size.QuadPart < static_cast<LONGLONG>(sizeof(IMAGE_DOS_HEADER))) {
        CloseHandle(hFile);
        pe.error = L"Too small";
        return pe;
    }

    // Quick magic check before mapping
    WORD mz = 0;
    DWORD got = 0;
    if (!ReadFile(hFile, &mz, sizeof(mz), &got, NULL) || got != sizeof(mz) || mz != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hFile);
        pe.error = L"No MZ header";
        return pe;
    }

    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) {
        CloseHandle(hFile);
        pe.error = L"Cannot map file";
        return pe;
    }
    const uint8_t* view = static_cast<const uint8_t*>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
    if (!view) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        pe.error = L"Cannot map view";
        return pe;
    }

    pe = ParsePeBuffer(view, static_cast<size_t>(size.QuadPart));

    UnmapViewOfFile(view);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return pe;
}

// ---------------------------------------------------------------------------
// Imphash
// ---------------------------------------------------------------------------
std::string ImphashInput(const PeInfo& pe)
{
    std::string out;
    for (const PeImport& imp : pe.imports) {
        std::string lib = ToLowerA(imp.dll);
        size_t dot = lib.find_last_of('.');
        if (dot != std::string::npos) {
            std::string ext = lib.substr(dot + 1);
            if (ext == "dll" || ext == "ocx" || ext == "sys") lib = lib.substr(0, dot);
        }
        std::string fn = imp.byOrdinal ? ("ord" + std::to_string(imp.ordinal)) : ToLowerA(imp.function);
        if (!out.empty()) out += ",";
        out += lib + "." + fn;
    }
    return out;
}

std::wstring ComputeImphash(const PeInfo& pe)
{
    if (pe.imports.empty()) return L"";
    std::string input = ImphashInput(pe);
    return ComputeBufferMD5Hex(input.data(), input.size());
}

// ---------------------------------------------------------------------------
// Anomalies
// ---------------------------------------------------------------------------
std::vector<std::wstring> FindPeAnomalies(const PeInfo& pe, const std::wstring& filePathLower, int64_t nowUnixSeconds)
{
    std::vector<std::wstring> out;
    if (!pe.valid) return out;

    // Reproducible builds (most of Windows since 10) store a content hash in the
    // timestamp field, so its value says nothing about the build date.
    if (!pe.isReproducible) {
        const int64_t win32Epoch = 725846400;   // 1993-01-01, before Windows NT 3.1 shipped
        if (pe.timestamp == 0) {
            out.push_back(L"TIMESTAMP_ZERO: Build timestamp is zero");
        }
        else if (static_cast<int64_t>(pe.timestamp) > nowUnixSeconds + 86400) {
            out.push_back(L"TIMESTAMP_FUTURE: Build timestamp " + std::to_wstring(pe.timestamp) + L" is in the future");
        }
        else if (static_cast<int64_t>(pe.timestamp) < win32Epoch) {
            out.push_back(L"TIMESTAMP_ANCIENT: Build timestamp " + std::to_wstring(pe.timestamp) + L" is before 1993");
        }
    }

    if (pe.checksumComputedOk && pe.checksumHeader != 0 && pe.checksumHeader != pe.checksumComputed) {
        wchar_t buf[96];
        swprintf_s(buf, L"CHECKSUM_MISMATCH: Header says 0x%08X, file is 0x%08X",
            pe.checksumHeader, pe.checksumComputed);
        out.push_back(buf);
    }
    bool isSysFile = filePathLower.size() > 4 && filePathLower.compare(filePathLower.size() - 4, 4, L".sys") == 0;
    if ((pe.isDriver || isSysFile) && pe.checksumHeader == 0) {
        out.push_back(L"CHECKSUM_ZERO_DRIVER: Driver has no header checksum");
    }

    if (pe.tlsCallbackCount > 0) {
        out.push_back(L"TLS_CALLBACKS: " + std::to_wstring(pe.tlsCallbackCount) + L" callback(s) run before the entry point");
    }

    if (pe.overlaySize > 1024) {
        out.push_back(L"OVERLAY_DATA: " + std::to_wstring(pe.overlaySize) + L" bytes appended after the last section");
        if (pe.overlayEntropy > 7.2 && pe.overlaySize > 65536) {
            out.push_back(L"OVERLAY_HIGH_ENTROPY: Appended data entropy " + FormatFixed(pe.overlayEntropy, 2));
        }
    }
    if (pe.overlayHasPe) {
        out.push_back(L"OVERLAY_EMBEDDED_PE: Appended data contains another Windows program");
    }

    if (!pe.pdbPath.empty()) {
        std::wstring pdb = ToLowerW(Utf8ToWide(pe.pdbPath));
        if (pdb.find(L"\\users\\") != std::wstring::npos || pdb.find(L"\\documents and settings\\") != std::wstring::npos) {
            out.push_back(L"PDB_USER_PATH: Debug path " + Utf8ToWide(pe.pdbPath));
        }
        const wchar_t* words[] = { L"payload", L"dropper", L"loader", L"inject", L"shellcode", L"beacon",
                                   L"implant", L"stealer", L"crypter", L"keylog", L"ransom", L"rootkit" };
        for (const wchar_t* word : words) {
            if (pdb.find(word) != std::wstring::npos) {
                out.push_back(std::wstring(L"PDB_SUSPICIOUS_WORDS: Debug path contains \"") + word + L"\"");
                break;
            }
        }
    }

    if (pe.sections.size() > 10) {
        out.push_back(L"SECTION_COUNT_HIGH: " + std::to_wstring(pe.sections.size()) + L" sections");
    }
    for (const PeSection& s : pe.sections) {
        if (s.nameHasOddChars) {
            out.push_back(L"SECTION_NAME_ODD: A section has an empty or unprintable name");
            break;
        }
    }
    return out;
}
