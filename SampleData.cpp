#include "pch.h"
#include "SampleData.h"

#include "AppPaths.h"
#include "FileIO.h"
#include "ScanCore.h"
#include "TextUtils.h"

#include <windows.h>
#include <imagehlp.h>
#include <cstring>

#pragma comment(lib, "imagehlp.lib")

static const uint32_t kFileAlign = 0x200;
static const uint32_t kSectionAlign = 0x1000;
static const uint64_t kImageBase = 0x140000000ULL;

static uint32_t AlignUp(uint32_t v, uint32_t a)
{
    return (v + a - 1) & ~(a - 1);
}

template <typename T>
static void Put(std::vector<uint8_t>& buf, size_t offset, const T& value)
{
    if (buf.size() < offset + sizeof(T)) buf.resize(offset + sizeof(T), 0);
    std::memcpy(buf.data() + offset, &value, sizeof(T));
}

static void PutBytes(std::vector<uint8_t>& buf, size_t offset, const void* data, size_t size)
{
    if (buf.size() < offset + size) buf.resize(offset + size, 0);
    std::memcpy(buf.data() + offset, data, size);
}

static size_t AppendAligned(std::vector<uint8_t>& buf, size_t size, size_t align)
{
    size_t offset = (buf.size() + align - 1) & ~(align - 1);
    buf.resize(offset + size, 0);
    return offset;
}

std::vector<uint8_t> BuildSamplePe(const SamplePeSpec& spec)
{
    const uint32_t textRva = 0x1000;
    const uint32_t rdataRva = 0x2000;

    // ---- .rdata contents ----
    std::vector<uint8_t> rdata;
    size_t dllCount = spec.imports.size();
    size_t descOff = AppendAligned(rdata, (dllCount + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR), 8);

    std::vector<size_t> iltOff(dllCount), iatOff(dllCount), nameOff(dllCount);
    std::vector<std::vector<size_t>> hintOff(dllCount);
    for (size_t d = 0; d < dllCount; ++d) {
        iltOff[d] = AppendAligned(rdata, (spec.imports[d].second.size() + 1) * 8, 8);
        iatOff[d] = AppendAligned(rdata, (spec.imports[d].second.size() + 1) * 8, 8);
    }
    for (size_t d = 0; d < dllCount; ++d) {
        for (const std::string& fn : spec.imports[d].second) {
            size_t off = AppendAligned(rdata, 2 + fn.size() + 1, 2);
            PutBytes(rdata, off + 2, fn.c_str(), fn.size() + 1);
            hintOff[d].push_back(off);
        }
        nameOff[d] = AppendAligned(rdata, spec.imports[d].first.size() + 1, 2);
        PutBytes(rdata, nameOff[d], spec.imports[d].first.c_str(), spec.imports[d].first.size() + 1);
    }
    for (size_t d = 0; d < dllCount; ++d) {
        IMAGE_IMPORT_DESCRIPTOR desc = {};
        desc.OriginalFirstThunk = rdataRva + static_cast<uint32_t>(iltOff[d]);
        desc.Name = rdataRva + static_cast<uint32_t>(nameOff[d]);
        desc.FirstThunk = rdataRva + static_cast<uint32_t>(iatOff[d]);
        Put(rdata, descOff + d * sizeof(IMAGE_IMPORT_DESCRIPTOR), desc);
        for (size_t f = 0; f < hintOff[d].size(); ++f) {
            uint64_t thunk = rdataRva + hintOff[d][f];
            Put(rdata, iltOff[d] + f * 8, thunk);
            Put(rdata, iatOff[d] + f * 8, thunk);
        }
    }

    // Debug directory with a CodeView (RSDS) record
    size_t debugOff = AppendAligned(rdata, sizeof(IMAGE_DEBUG_DIRECTORY), 4);
    size_t cvOff = AppendAligned(rdata, 24 + spec.pdbPath.size() + 1, 4);
    {
        const char rsds[4] = { 'R', 'S', 'D', 'S' };
        PutBytes(rdata, cvOff, rsds, 4);
        uint8_t guid[16] = { 0x50, 0x52, 0x53, 0x41, 0x4D, 0x50, 0x4C, 0x45, 1, 2, 3, 4, 5, 6, 7, 8 };
        PutBytes(rdata, cvOff + 4, guid, 16);
        Put(rdata, cvOff + 20, static_cast<uint32_t>(1));
        PutBytes(rdata, cvOff + 24, spec.pdbPath.c_str(), spec.pdbPath.size() + 1);
    }

    // TLS directory and callback array
    size_t tlsOff = 0, cbOff = 0;
    if (spec.tlsCallbacks > 0) {
        tlsOff = AppendAligned(rdata, sizeof(IMAGE_TLS_DIRECTORY64), 8);
        cbOff = AppendAligned(rdata, (static_cast<size_t>(spec.tlsCallbacks) + 1) * 8, 8);
    }

    uint32_t rdataRaw = AlignUp(static_cast<uint32_t>(rdata.size()), kFileAlign);
    uint32_t rdataVirtual = static_cast<uint32_t>(rdata.size());
    uint32_t dataRva = AlignUp(rdataRva + rdataVirtual, kSectionAlign);

    if (spec.tlsCallbacks > 0) {
        IMAGE_TLS_DIRECTORY64 tls = {};
        tls.StartAddressOfRawData = kImageBase + dataRva + 0x100;
        tls.EndAddressOfRawData = kImageBase + dataRva + 0x108;
        tls.AddressOfIndex = kImageBase + dataRva;
        tls.AddressOfCallBacks = kImageBase + rdataRva + cbOff;
        Put(rdata, tlsOff, tls);
        for (int i = 0; i < spec.tlsCallbacks; ++i) {
            uint64_t va = kImageBase + textRva + 0x10;   // points at a "ret"
            Put(rdata, cbOff + static_cast<size_t>(i) * 8, va);
        }
    }

    // ---- headers ----
    const uint32_t headersSize = 0x400;
    const uint16_t sectionCount = 3;
    const uint32_t textRaw = kFileAlign;
    const uint32_t dataRaw = kFileAlign;
    const uint32_t textFile = headersSize;
    const uint32_t rdataFile = textFile + textRaw;
    const uint32_t dataFile = rdataFile + rdataRaw;
    const uint32_t sizeOfImage = AlignUp(dataRva + 0x200, kSectionAlign);

    // Debug directory now that rdata's file position is known
    {
        IMAGE_DEBUG_DIRECTORY dbg = {};
        dbg.TimeDateStamp = spec.timestamp;
        dbg.Type = IMAGE_DEBUG_TYPE_CODEVIEW;
        dbg.SizeOfData = static_cast<DWORD>(24 + spec.pdbPath.size() + 1);
        dbg.AddressOfRawData = rdataRva + static_cast<DWORD>(cvOff);
        dbg.PointerToRawData = rdataFile + static_cast<DWORD>(cvOff);
        Put(rdata, debugOff, dbg);
    }

    std::vector<uint8_t> image(dataFile + dataRaw, 0);

    IMAGE_DOS_HEADER dos = {};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    Put(image, 0, dos);
    const char stub[] = "This program cannot be run in DOS mode. Phantom Recon sample file.";
    PutBytes(image, 0x40, stub, sizeof(stub));

    Put(image, 0x80, static_cast<DWORD>(IMAGE_NT_SIGNATURE));
    IMAGE_FILE_HEADER fh = {};
    fh.Machine = IMAGE_FILE_MACHINE_AMD64;
    fh.NumberOfSections = sectionCount;
    fh.TimeDateStamp = spec.timestamp;
    fh.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    fh.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    Put(image, 0x84, fh);

    IMAGE_OPTIONAL_HEADER64 opt = {};
    opt.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    opt.MajorLinkerVersion = 14;
    opt.SizeOfCode = textRaw;
    opt.SizeOfInitializedData = rdataRaw + dataRaw;
    opt.AddressOfEntryPoint = textRva;
    opt.BaseOfCode = textRva;
    opt.ImageBase = kImageBase;
    opt.SectionAlignment = kSectionAlign;
    opt.FileAlignment = kFileAlign;
    opt.MajorOperatingSystemVersion = 6;
    opt.MajorSubsystemVersion = 6;
    opt.SizeOfImage = sizeOfImage;
    opt.SizeOfHeaders = headersSize;
    opt.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    opt.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE;
    opt.SizeOfStackReserve = 0x100000;
    opt.SizeOfStackCommit = 0x1000;
    opt.SizeOfHeapReserve = 0x100000;
    opt.SizeOfHeapCommit = 0x1000;
    opt.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = rdataRva + static_cast<DWORD>(descOff);
    opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = static_cast<DWORD>((dllCount + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR));
    opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = rdataRva + static_cast<DWORD>(debugOff);
    opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = sizeof(IMAGE_DEBUG_DIRECTORY);
    if (spec.tlsCallbacks > 0) {
        opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = rdataRva + static_cast<DWORD>(tlsOff);
        opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = sizeof(IMAGE_TLS_DIRECTORY64);
    }
    const size_t optOffset = 0x84 + sizeof(IMAGE_FILE_HEADER);
    Put(image, optOffset, opt);

    size_t secOffset = optOffset + sizeof(IMAGE_OPTIONAL_HEADER64);
    auto section = [&](int index, const char* name, uint32_t rva, uint32_t vsize, uint32_t rawPtr, uint32_t rawSize, DWORD flags) {
        IMAGE_SECTION_HEADER sh = {};
        std::memcpy(sh.Name, name, strlen(name));
        sh.VirtualAddress = rva;
        sh.Misc.VirtualSize = vsize;
        sh.PointerToRawData = rawPtr;
        sh.SizeOfRawData = rawSize;
        sh.Characteristics = flags;
        Put(image, secOffset + index * sizeof(IMAGE_SECTION_HEADER), sh);
    };
    DWORD textFlags = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    if (spec.writableCode) textFlags |= IMAGE_SCN_MEM_WRITE;
    section(0, ".text", textRva, 0x20, textFile, textRaw, textFlags);
    section(1, ".rdata", rdataRva, rdataVirtual, rdataFile, rdataRaw, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    section(2, ".data", dataRva, 0x200, dataFile, dataRaw, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);

    // Code: entry point and TLS callback are both a single "ret".
    image[textFile] = 0xC3;
    image[textFile + 0x10] = 0xC3;
    PutBytes(image, rdataFile, rdata.data(), rdata.size());

    // Overlay
    if (spec.overlayBytes > 0) {
        size_t start = image.size();
        image.resize(start + spec.overlayBytes);
        uint32_t x = 0x12345678;
        for (size_t i = 0; i < spec.overlayBytes; ++i) {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            image[start + i] = static_cast<uint8_t>(x & 0xFF);
        }
    }

    // Checksum over the finished file
    DWORD headerSum = 0, computed = 0;
    CheckSumMappedFile(image.data(), static_cast<DWORD>(image.size()), &headerSum, &computed);
    DWORD checksum = spec.checksumMode == 0 ? computed : (spec.checksumMode == 1 ? computed + 0x1234 : 0);
    Put(image, optOffset + offsetof(IMAGE_OPTIONAL_HEADER64, CheckSum), checksum);
    return image;
}

// ---------------------------------------------------------------------------
// Sample pack
// ---------------------------------------------------------------------------
static bool WriteStream(const std::wstring& path, const std::wstring& stream, const std::string& text)
{
    return WriteBinaryFile(path + L":" + stream, text.data(), text.size());
}

static bool FolderIsEmpty(const std::wstring& folder)
{
    WIN32_FIND_DATAW fd = {};
    HANDLE h = FindFirstFileW(JoinPath(folder, L"*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return true;
    bool empty = true;
    do {
        if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) {
            empty = false;
            break;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return empty;
}

SamplePackResult CreateSamplePack(const std::wstring& folderIn)
{
    SamplePackResult result;
    std::wstring folder = AbsolutePath(folderIn);
    result.folder = folder;
    if (DirectoryExists(folder) && !FolderIsEmpty(folder)) {
        result.error = L"The folder is not empty. Pick a new or empty folder so nothing of yours is overwritten.";
        return result;
    }
    if (!EnsureDirectory(folder)) {
        result.error = L"Could not create " + folder;
        return result;
    }

    auto writePe = [&](const std::wstring& name, const SamplePeSpec& spec) {
        std::vector<uint8_t> bytes = BuildSamplePe(spec);
        std::wstring path = JoinPath(folder, name);
        if (WriteBinaryFile(path, bytes.data(), bytes.size())) result.files.push_back(path);
        return path;
    };

    // Stage 1: what the baseline will see
    SamplePeSpec plain;
    writePe(L"plain_tool.exe", plain);
    writePe(L"will_change.exe", plain);
    writePe(L"will_be_removed.exe", plain);

    SamplePeSpec odd;
    odd.timestamp = 0xF0000000;          // year 2097: a future build date
    odd.checksumMode = 1;                // header checksum does not match the file
    odd.tlsCallbacks = 1;
    odd.writableCode = true;
    odd.overlayBytes = 128 * 1024;       // random-looking data appended
    writePe(L"odd_headers.exe", odd);

    std::wstring downloaded = writePe(L"downloaded_tool.exe", plain);
    WriteStream(downloaded, L"Zone.Identifier",
        "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.invalid/downloaded_tool.exe\r\n");

    std::wstring carrier = writePe(L"has_extra_stream.exe", plain);
    WriteStream(carrier, L"notes.txt", "Phantom Recon sample: an extra NTFS data stream with plain text in it.\r\n");

    std::wstring script = JoinPath(folder, L"sample_script.ps1");
    WriteUtf8File(script,
        L"# Phantom Recon sample script. It only prints a line.\r\n"
        L"# The commented line below is here so the script check has something to point at:\r\n"
        L"# Invoke-WebRequest https://example.invalid/readme.txt -OutFile readme.txt\r\n"
        L"Write-Output 'Phantom Recon sample script'\r\n");
    result.files.push_back(script);

    // Stage 2: baseline of the folder as it is now
    result.baselinePath = JoinPath(folder, L"demo_baseline.prbl");
    ScanOptions options;
    options.revocation = RevocationMode::Off;
    options.precount = false;
    ScanCallbacks callbacks;
    ScanSummary summary = RunScan(ScanMode::Baseline, folder, L"", nullptr, result.baselinePath, options, callbacks);
    if (!summary.baselineSaved) {
        result.error = L"The demo baseline could not be saved.";
        return result;
    }

    // Stage 3: change the folder so a Full Scan shows every status
    {
        std::vector<uint8_t> bytes;
        std::wstring changed = JoinPath(folder, L"will_change.exe");
        ReadBinaryFile(changed, bytes);
        const char extra[] = "appended after the baseline";
        bytes.insert(bytes.end(), extra, extra + sizeof(extra));
        WriteBinaryFile(changed, bytes.data(), bytes.size());
    }
    DeleteFileW(JoinPath(folder, L"will_be_removed.exe").c_str());
    writePe(L"appeared_later.exe", plain);

    std::wstring readme = JoinPath(folder, L"README_SAMPLES.txt");
    WriteUtf8File(readme,
        L"Phantom Recon sample pack\r\n"
        L"=========================\r\n\r\n"
        L"Every file here is harmless. The .exe files are tiny programs whose only code is \"return\".\r\n\r\n"
        L"Try it:\r\n"
        L"  1. File > Open Baseline (Set as Active)... and pick demo_baseline.prbl in this folder.\r\n"
        L"  2. Scans > Full Scan (Compare a Folder)... and pick this folder.\r\n"
        L"  (Help > Create Sample Pack does both steps for you.)\r\n\r\n"
        L"What you should see:\r\n"
        L"  plain_tool.exe        MATCH    unchanged since the baseline\r\n"
        L"  will_change.exe       CHANGED  bytes were appended after the baseline\r\n"
        L"  will_be_removed.exe   MISSING  deleted after the baseline\r\n"
        L"  appeared_later.exe    NEW      created after the baseline\r\n"
        L"  odd_headers.exe       MATCH, with header findings: future build date, wrong checksum,\r\n"
        L"                        an early-start callback, writable code, appended data\r\n"
        L"  downloaded_tool.exe   MATCH, marked as downloaded from the internet\r\n"
        L"  has_extra_stream.exe  MATCH, carries an extra NTFS data stream\r\n"
        L"  sample_script.ps1     MATCH, the script check points at the commented download line\r\n\r\n"
        L"Command line equivalent:\r\n"
        L"  PhantomReconCli.exe --full \"<this folder>\" --baseline \"<this folder>\\demo_baseline.prbl\" --report demo.html\r\n",
        true);
    result.files.push_back(readme);
    result.ok = true;
    return result;
}
