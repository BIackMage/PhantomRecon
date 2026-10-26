// Group 2 fixes (file analysis): import caps, ordinal imphash, raw-pointer
// rounding, overlay past 96 sections, .NET protectors, signature scoring and
// timestamps, revocation cache, offline signature checks, package paths,
// entropy sharing and long paths, version languages, stream caps, detail text.

#include "TestFramework.h"

#include "../AppPaths.h"
#include "../AttackMapping.h"
#include "../DetailText.h"
#include "../FileAnalysis.h"
#include "../FileIO.h"
#include "../FileOrigin.h"
#include "../MalwareScoring.h"
#include "../PeFile.h"
#include "../SampleData.h"
#include "../ScanCore.h"
#include "../ScoringConfig.h"
#include "../SystemInfo.h"
#include "../TextUtils.h"

#include <windows.h>
#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <vector>

namespace {

bool HasFinding(const std::vector<std::wstring>& findings, const std::wstring& code)
{
    for (const std::wstring& f : findings) {
        if (IndicatorCode(f) == code) return true;
    }
    return false;
}

bool HasIndicator(const std::vector<std::string>& indicators, const std::string& code)
{
    for (const std::string& s : indicators) {
        if (s.rfind(code + ":", 0) == 0) return true;
    }
    return false;
}

template <typename T>
void PutAt(std::vector<uint8_t>& buf, size_t offset, const T& value)
{
    if (buf.size() < offset + sizeof(T)) buf.resize(offset + sizeof(T), 0);
    std::memcpy(buf.data() + offset, &value, sizeof(T));
}

template <typename T>
T GetAt(const std::vector<uint8_t>& buf, size_t offset)
{
    T value = {};
    std::memcpy(&value, buf.data() + offset, sizeof(T));
    return value;
}

uint32_t AlignUp(uint32_t v, uint32_t a)
{
    return (v + a - 1) & ~(a - 1);
}

// Offsets inside a PE32+ image built by BuildSamplePe.
struct PeLayout {
    size_t fileHeader = 0;
    size_t optHeader = 0;
    size_t sectionTable = 0;
    WORD   sectionCount = 0;
};

PeLayout LayoutOf(const std::vector<uint8_t>& image)
{
    PeLayout l;
    LONG lfanew = GetAt<LONG>(image, offsetof(IMAGE_DOS_HEADER, e_lfanew));
    l.fileHeader = static_cast<size_t>(lfanew) + 4;
    IMAGE_FILE_HEADER fh = GetAt<IMAGE_FILE_HEADER>(image, l.fileHeader);
    l.optHeader = l.fileHeader + sizeof(IMAGE_FILE_HEADER);
    l.sectionTable = l.optHeader + fh.SizeOfOptionalHeader;
    l.sectionCount = fh.NumberOfSections;
    return l;
}

size_t SectionHeaderOffset(const PeLayout& l, int index)
{
    return l.sectionTable + static_cast<size_t>(index) * sizeof(IMAGE_SECTION_HEADER);
}

void SetDirectory(std::vector<uint8_t>& image, const PeLayout& l, int index, uint32_t rva, uint32_t size)
{
    size_t at = l.optHeader + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) + index * sizeof(IMAGE_DATA_DIRECTORY);
    IMAGE_DATA_DIRECTORY dir = { rva, size };
    PutAt(image, at, dir);
}

// Move the last section's raw data to the end of the file and fill it with
// blob. Returns the section's RVA, where the blob now lives.
uint32_t ReplaceLastSection(std::vector<uint8_t>& image, const std::vector<uint8_t>& blob)
{
    PeLayout l = LayoutOf(image);
    size_t shAt = SectionHeaderOffset(l, l.sectionCount - 1);
    IMAGE_SECTION_HEADER sh = GetAt<IMAGE_SECTION_HEADER>(image, shAt);
    uint32_t rawPtr = AlignUp(static_cast<uint32_t>(image.size()), 0x200);
    uint32_t rawSize = AlignUp(static_cast<uint32_t>(blob.size()), 0x200);
    image.resize(rawPtr + rawSize, 0);
    std::memcpy(image.data() + rawPtr, blob.data(), blob.size());
    sh.PointerToRawData = rawPtr;
    sh.SizeOfRawData = rawSize;
    sh.Misc.VirtualSize = static_cast<DWORD>(blob.size());
    PutAt(image, shAt, sh);
    return sh.VirtualAddress;
}

// A PE32+ with sectionCount sections of 0x200 bytes each, back to back after
// the headers, followed by overlayBytes of appended data.
std::vector<uint8_t> BuildManySectionPe(uint32_t sectionCount, size_t overlayBytes)
{
    const size_t fhAt = 0x84;
    const size_t optAt = fhAt + sizeof(IMAGE_FILE_HEADER);
    const size_t secAt = optAt + sizeof(IMAGE_OPTIONAL_HEADER64);
    uint32_t headers = AlignUp(static_cast<uint32_t>(secAt + sectionCount * sizeof(IMAGE_SECTION_HEADER)), 0x200);
    std::vector<uint8_t> image(headers + sectionCount * 0x200 + overlayBytes, 0);

    IMAGE_DOS_HEADER dos = {};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    PutAt(image, 0, dos);
    PutAt(image, 0x80, static_cast<DWORD>(IMAGE_NT_SIGNATURE));
    IMAGE_FILE_HEADER fh = {};
    fh.Machine = IMAGE_FILE_MACHINE_AMD64;
    fh.NumberOfSections = static_cast<WORD>(sectionCount);
    fh.TimeDateStamp = 0x65000000;
    fh.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    fh.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
    PutAt(image, fhAt, fh);
    IMAGE_OPTIONAL_HEADER64 opt = {};
    opt.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    opt.AddressOfEntryPoint = 0x1000;
    opt.ImageBase = 0x140000000ULL;
    opt.SectionAlignment = 0x1000;
    opt.FileAlignment = 0x200;
    opt.SizeOfImage = 0x1000 + sectionCount * 0x1000;
    opt.SizeOfHeaders = headers;
    opt.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    opt.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    PutAt(image, optAt, opt);
    for (uint32_t i = 0; i < sectionCount; ++i) {
        IMAGE_SECTION_HEADER sh = {};
        char name[9] = {};
        std::snprintf(name, sizeof(name), ".s%u", i);
        std::memcpy(sh.Name, name, std::strlen(name));
        sh.VirtualAddress = 0x1000 + i * 0x1000;
        sh.Misc.VirtualSize = 0x200;
        sh.PointerToRawData = headers + i * 0x200;
        sh.SizeOfRawData = 0x200;
        sh.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
        PutAt(image, secAt + i * sizeof(IMAGE_SECTION_HEADER), sh);
        image[sh.PointerToRawData] = static_cast<uint8_t>(i);
    }
    for (size_t i = 0; i < overlayBytes; ++i) image[headers + sectionCount * 0x200 + i] = static_cast<uint8_t>(i * 7);
    return image;
}

std::wstring TodayDate()
{
    SYSTEMTIME st = {};
    GetSystemTime(&st);
    wchar_t buf[16];
    swprintf_s(buf, L"%04u-%02u-%02u", st.wYear, st.wMonth, st.wDay);
    return buf;
}

// Embedded-signed programs in Windows' own folders, up to max of them.
std::vector<std::wstring> FindEmbeddedSignedFiles(size_t max, size_t scanLimit)
{
    std::vector<std::wstring> found;
    wchar_t sys[MAX_PATH] = {};
    GetSystemDirectoryW(sys, MAX_PATH);
    std::wstring pattern = std::wstring(sys) + L"\\*.exe";
    WIN32_FIND_DATAW fd = {};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return found;
    size_t scanned = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (++scanned > scanLimit) break;
        std::wstring path = std::wstring(sys) + L"\\" + fd.cFileName;
        SignatureInfo info = AnalyzeFileSignature(path, RevocationMode::Off);
        if (info.isEmbedded && info.status == L"Signed (Valid)" && info.thumbprint != L"N/A") found.push_back(path);
    } while (found.size() < max && FindNextFileW(h, &fd));
    FindClose(h);
    return found;
}

// ---- VS_VERSIONINFO builder for the version-language test ----
struct VerNode {
    std::wstring         key;
    std::vector<uint8_t> value;
    WORD                 valueLength = 0;   // WCHARs for text, bytes for binary
    WORD                 type = 1;          // 1 text, 0 binary
    std::vector<VerNode> children;
};

void Pad4(std::vector<uint8_t>& out)
{
    while (out.size() % 4) out.push_back(0);
}

std::vector<uint8_t> Serialize(const VerNode& n)
{
    std::vector<uint8_t> out(6, 0);
    const uint8_t* k = reinterpret_cast<const uint8_t*>(n.key.c_str());
    out.insert(out.end(), k, k + (n.key.size() + 1) * sizeof(wchar_t));
    Pad4(out);
    out.insert(out.end(), n.value.begin(), n.value.end());
    for (const VerNode& c : n.children) {
        Pad4(out);
        std::vector<uint8_t> child = Serialize(c);
        out.insert(out.end(), child.begin(), child.end());
    }
    WORD length = static_cast<WORD>(out.size());
    std::memcpy(out.data(), &length, 2);
    std::memcpy(out.data() + 2, &n.valueLength, 2);
    std::memcpy(out.data() + 4, &n.type, 2);
    return out;
}

VerNode TextNode(const std::wstring& key, const std::wstring& text)
{
    VerNode n;
    n.key = key;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(text.c_str());
    n.value.assign(p, p + (text.size() + 1) * sizeof(wchar_t));
    n.valueLength = static_cast<WORD>(text.size() + 1);
    n.type = 1;
    return n;
}

// Version resource whose Translation table names German first, while the only
// string table is US English. Windows Explorer finds the strings; a reader that
// tries only the first listed language does not.
std::vector<uint8_t> BuildVersionResource(const std::wstring& company)
{
    VerNode root;
    root.key = L"VS_VERSION_INFO";
    root.type = 0;
    VS_FIXEDFILEINFO ffi = {};
    ffi.dwSignature = 0xFEEF04BD;
    ffi.dwStrucVersion = 0x00010000;
    ffi.dwFileVersionMS = 0x00010002;
    ffi.dwFileVersionLS = 0x00030004;
    ffi.dwProductVersionMS = 0x00010002;
    ffi.dwProductVersionLS = 0x00030004;
    ffi.dwFileOS = VOS_NT_WINDOWS32;
    ffi.dwFileType = VFT_APP;
    const uint8_t* f = reinterpret_cast<const uint8_t*>(&ffi);
    root.value.assign(f, f + sizeof(ffi));
    root.valueLength = sizeof(ffi);

    VerNode table;
    table.key = L"040904b0";
    table.children.push_back(TextNode(L"CompanyName", company));
    table.children.push_back(TextNode(L"ProductName", L"Language Test"));
    VerNode sfi;
    sfi.key = L"StringFileInfo";
    sfi.children.push_back(table);

    VerNode var;
    var.key = L"Translation";
    var.type = 0;
    const WORD translation[4] = { 0x0407, 0x04B0, 0x040C, 0x04B0 };   // German, then French; neither has strings
    const uint8_t* t = reinterpret_cast<const uint8_t*>(translation);
    var.value.assign(t, t + sizeof(translation));
    var.valueLength = sizeof(translation);
    VerNode vfi;
    vfi.key = L"VarFileInfo";
    vfi.children.push_back(var);

    root.children.push_back(sfi);
    root.children.push_back(vfi);
    return Serialize(root);
}

bool CreateDeepDirectory(const std::wstring& extendedPath)
{
    for (size_t i = 7; i <= extendedPath.size(); ++i) {   // past "\\?\C:\"
        if (i == extendedPath.size() || extendedPath[i] == L'\\') {
            std::wstring part = extendedPath.substr(0, i);
            if (!CreateDirectoryW(part.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return false;
        }
    }
    return true;
}

} // namespace

// A3: a small hostile file must not ask for hundreds of millions of imports.
TEST(Fix_PeImportsAreCapped)
{
    std::vector<uint8_t> image = BuildSamplePe(SamplePeSpec());
    const uint32_t descriptors = 4096;
    const uint32_t thunks = 65535;
    const uint32_t thunkAt = 0x15000;
    const uint32_t nameAt = thunkAt + (thunks + 1) * 8;
    std::vector<uint8_t> blob(nameAt + 16, 0);
    std::memcpy(blob.data() + nameAt, "ws2_32.dll", 11);
    for (uint32_t t = 0; t < thunks; ++t) PutAt(blob, thunkAt + t * 8ULL, static_cast<uint64_t>(IMAGE_ORDINAL_FLAG64 | 4));

    PeLayout l = LayoutOf(image);
    IMAGE_SECTION_HEADER last = GetAt<IMAGE_SECTION_HEADER>(image, SectionHeaderOffset(l, l.sectionCount - 1));
    uint32_t va = last.VirtualAddress;
    for (uint32_t d = 0; d < descriptors; ++d) {
        IMAGE_IMPORT_DESCRIPTOR desc = {};
        desc.OriginalFirstThunk = va + thunkAt;
        desc.FirstThunk = va + thunkAt;
        desc.Name = va + nameAt;
        PutAt(blob, d * sizeof(IMAGE_IMPORT_DESCRIPTOR), desc);
    }
    REQUIRE(ReplaceLastSection(image, blob) == va);
    SetDirectory(image, l, IMAGE_DIRECTORY_ENTRY_IMPORT, va, (descriptors + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR));
    CHECK(image.size() < 1024 * 1024);

    ULONGLONG started = GetTickCount64();
    PeInfo pe = ParsePeBuffer(image.data(), image.size());
    ULONGLONG elapsed = GetTickCount64() - started;
    REQUIRE(pe.valid);
    CHECK(pe.importsTruncated);
    CHECK_EQ(pe.imports.size(), static_cast<size_t>(kMaxPeImportThunks));
    CHECK(elapsed < 5000);
    CHECK(HasFinding(FindPeAnomalies(pe, L"c:\\x\\huge.exe", 1790000000), L"IMPORT_TABLE_HUGE"));
    CHECK(!ExplainIndicator(L"IMPORT_TABLE_HUGE").empty());

    // A normal program is not touched by the cap.
    std::vector<uint8_t> plain = BuildSamplePe(SamplePeSpec());
    PeInfo normal = ParsePeBuffer(plain.data(), plain.size());
    REQUIRE(normal.valid);
    CHECK(!normal.importsTruncated);
    CHECK(!HasFinding(FindPeAnomalies(normal, L"c:\\x\\plain.exe", 1790000000), L"IMPORT_TABLE_HUGE"));
}

// D5: ordinal imports of ws2_32 / wsock32 / oleaut32 hash and score by name, as in pefile.
TEST(Fix_ImphashResolvesOrdinals)
{
    SamplePeSpec spec;
    spec.imports = {
        { "WS2_32.dll",   { "#4", "#115", "#23" } },
        { "WSOCK32.dll",  { "#19", "#11" } },   // wsock32's own table: 11 is inet_ntoa (ws2_32's 11 is inet_addr)
        { "OLEAUT32.dll", { "#2" } },
        { "other.dll",    { "#7" } },
        { "KERNEL32.dll", { "ExitProcess" } },
    };
    std::vector<uint8_t> image = BuildSamplePe(spec);
    PeInfo pe = ParsePeBuffer(image.data(), image.size());
    REQUIRE(pe.valid);
    REQUIRE(pe.imports.size() == 8);
    CHECK(pe.imports[0].byOrdinal);
    CHECK_EQ(pe.imports[0].ordinal, static_cast<uint16_t>(4));
    CHECK_EQ(ImphashInput(pe), std::string(
        "ws2_32.connect,ws2_32.wsastartup,ws2_32.socket,wsock32.send,wsock32.inet_ntoa,"
        "oleaut32.sysallocstring,other.ord7,kernel32.exitprocess"));
    // MD5 of that string, computed with pefile 2024.8.26's get_imphash rules.
    CHECK_EQ(ComputeImphash(pe), std::wstring(L"87531fc7a1ac3280eaa64fc8f3c98c65"));

    ImportScanResult r = ScanPEImports(pe);
    CHECK_EQ(r.totalImports, 8);   // every import counts, named or not
    auto flagged = [&r](const char* name) {
        return std::find(r.flaggedFunctions.begin(), r.flaggedFunctions.end(), name) != r.flaggedFunctions.end();
    };
    CHECK(flagged("connect"));
    CHECK(flagged("WSAStartup"));
    CHECK(flagged("send"));
    CHECK(std::find(r.flaggedCategories.begin(), r.flaggedCategories.end(), "network") != r.flaggedCategories.end());
}

// H: the loader reads a section from PointerToRawData rounded down to 512 bytes.
TEST(Fix_RawPointerRounding)
{
    std::vector<uint8_t> image = BuildSamplePe(SamplePeSpec());
    PeLayout l = LayoutOf(image);
    size_t rdataAt = SectionHeaderOffset(l, 1);
    IMAGE_SECTION_HEADER sh = GetAt<IMAGE_SECTION_HEADER>(image, rdataAt);
    REQUIRE(std::string(reinterpret_cast<const char*>(sh.Name), 6) == ".rdata");
    REQUIRE((sh.PointerToRawData & 0x1FF) == 0);
    sh.PointerToRawData += 0x1F;    // what the header says; Windows still reads from the rounded value
    PutAt(image, rdataAt, sh);

    PeInfo pe = ParsePeBuffer(image.data(), image.size());
    REQUIRE(pe.valid);
    CHECK_EQ(pe.sections[1].rawPointer, sh.PointerToRawData);
    CHECK_EQ(pe.sections[1].rawPointerLoaded, sh.PointerToRawData & ~0x1FFu);
    CHECK_EQ(ImphashInput(pe), std::string("kernel32.exitprocess,kernel32.getstdhandle,kernel32.writefile"));
    CHECK_EQ(pe.pdbPath, std::string("C:\\build\\sample\\sample.pdb"));
}

// H: section headers past the 96th still count for the overlay start.
TEST(Fix_OverlayCountsEverySection)
{
    std::vector<uint8_t> noOverlay = BuildManySectionPe(100, 0);
    PeInfo pe = ParsePeBuffer(noOverlay.data(), noOverlay.size());
    REQUIRE(pe.valid);
    CHECK_EQ(pe.sectionHeaderCount, 100u);
    CHECK_EQ(pe.sections.size(), static_cast<size_t>(kMaxPeSectionsKept));
    CHECK_EQ(pe.overlaySize, static_cast<int64_t>(0));
    std::vector<std::wstring> f = FindPeAnomalies(pe, L"c:\\x\\many.exe", 1790000000);
    CHECK(!HasFinding(f, L"OVERLAY_DATA"));
    bool countIs100 = false;
    for (const std::wstring& s : f) {
        if (s == L"SECTION_COUNT_HIGH: 100 sections") countIs100 = true;
    }
    CHECK(countIs100);

    std::vector<uint8_t> withOverlay = BuildManySectionPe(100, 4096);
    PeInfo po = ParsePeBuffer(withOverlay.data(), withOverlay.size());
    REQUIRE(po.valid);
    CHECK_EQ(po.overlaySize, static_cast<int64_t>(4096));
}

// H: ConfuserEx and SmartAssembly are found in the .NET metadata, not in section names.
TEST(Fix_DotNetProtectorNamed)
{
    auto build = [](const char* marker) {
        std::vector<uint8_t> image = BuildSamplePe(SamplePeSpec());
        PeLayout l = LayoutOf(image);
        uint32_t va = GetAt<IMAGE_SECTION_HEADER>(image, SectionHeaderOffset(l, l.sectionCount - 1)).VirtualAddress;
        std::vector<uint8_t> blob(0x400, 0);
        const uint32_t mdAt = 0x48;
        PutAt(blob, mdAt, static_cast<uint32_t>(0x424A5342));   // "BSJB"
        const char version[] = "v4.0.30319";
        std::memcpy(blob.data() + mdAt + 16, version, sizeof(version));
        size_t markerLen = std::strlen(marker);
        std::memcpy(blob.data() + 0x200, marker, markerLen);
        IMAGE_COR20_HEADER cor = {};
        cor.cb = sizeof(IMAGE_COR20_HEADER);
        cor.MajorRuntimeVersion = 2;
        cor.MetaData.VirtualAddress = va + mdAt;
        cor.MetaData.Size = 0x400 - mdAt;
        PutAt(blob, 0, cor);
        ReplaceLastSection(image, blob);
        SetDirectory(image, l, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, va, sizeof(IMAGE_COR20_HEADER));
        return image;
    };

    std::vector<uint8_t> confused = build("ConfusedByAttribute");
    PeInfo pc = ParsePeBuffer(confused.data(), confused.size());
    REQUIRE(pc.valid);
    CHECK(pc.isDotNet);
    CHECK_EQ(pc.dotNetProtector, std::string("ConfuserEx"));
    PackingAnalysisResult rc = AnalyzePEPacking(pc, 5.0, 3);
    CHECK_EQ(rc.detectedPacker, std::string("ConfuserEx"));
    CHECK(HasIndicator(rc.indicators, "DOTNET_PROTECTOR"));

    std::vector<uint8_t> smart = build("SmartAssembly.Attributes");
    PeInfo ps = ParsePeBuffer(smart.data(), smart.size());
    REQUIRE(ps.valid);
    CHECK_EQ(ps.dotNetProtector, std::string("SmartAssembly"));

    std::vector<uint8_t> plain = build("System.Runtime");
    PeInfo pp = ParsePeBuffer(plain.data(), plain.size());
    REQUIRE(pp.valid);
    CHECK(pp.isDotNet);
    CHECK(pp.dotNetProtector.empty());
    CHECK(!HasIndicator(AnalyzePEPacking(pp, 5.0, 3).indicators, "DOTNET_PROTECTOR"));
    CHECK(!ExplainIndicator(L"DOTNET_PROTECTOR").empty());
    CHECK_EQ(AttackTechniqueForCode(L"DOTNET_PROTECTOR"), std::wstring(L"T1027.002"));
}

// D2: only a real hash mismatch gets the hash-mismatch weight.
TEST(Fix_SignatureScoreOnlyForRealMismatch)
{
    const ScoringConfig& cfg = GetScoringConfig();
    SignatureInfo catalogError;
    catalogError.status = L"Signed (Catalog error 0x800B0109)";
    CHECK_EQ(SignatureAnomalyScore(catalogError), cfg.anomalies.untrusted_chain);

    SignatureInfo blocked;
    blocked.status = L"Signed (Blocked by Policy)";
    CHECK_EQ(SignatureAnomalyScore(blocked), cfg.anomalies.untrusted_chain);

    SignatureInfo mismatch;
    mismatch.status = L"Signed (HASH MISMATCH)";
    mismatch.hashMismatch = true;
    CHECK_EQ(SignatureAnomalyScore(mismatch), cfg.anomalies.hash_mismatch + cfg.anomalies.untrusted_chain);

    SignatureInfo unsignedFile;
    unsignedFile.status = L"Unsigned";
    CHECK_EQ(SignatureAnomalyScore(unsignedFile), 0.0);

    SignatureInfo good;
    good.status = L"Signed (Valid)";
    good.hashValid = true;
    good.chainTrusted = true;
    CHECK_EQ(SignatureAnomalyScore(good), 0.0);
}

// D2 and D3 on a real file: a tampered copy is a hash mismatch, and its result
// does not leak into the revocation verdict of the genuine file.
TEST(Fix_TamperedCopyAndRevocationCache)
{
    std::vector<std::wstring> signedFiles = FindEmbeddedSignedFiles(1, 400);
    if (signedFiles.empty()) {
        std::printf("    note: no embedded-signed program found in System32; tamper test not exercised\n");
        return;
    }
    const std::wstring original = signedFiles[0];
    std::vector<uint8_t> bytes;
    REQUIRE(ReadBinaryFile(original, bytes));
    PeInfo pe = ParsePeBuffer(bytes.data(), bytes.size());
    REQUIRE(pe.valid && !pe.sections.empty() && pe.sections[0].rawSize > 64);
    size_t flip = pe.sections[0].rawPointerLoaded + pe.sections[0].rawSize / 2;
    bytes[flip] ^= 0xFF;
    std::wstring copy = tf::TestDir() + L"tampered.exe";
    REQUIRE(WriteBinaryFile(copy, bytes.data(), bytes.size()));

    SignatureInfo tampered = AnalyzeFileSignature(copy, RevocationMode::CacheOnly);
    CHECK_EQ(tampered.status, std::wstring(L"Signed (HASH MISMATCH)"));
    CHECK(tampered.hashMismatch);
    CHECK(SignatureAnomalyScore(tampered) >= GetScoringConfig().anomalies.hash_mismatch);

    SignatureInfo genuine = AnalyzeFileSignature(original, RevocationMode::CacheOnly);
    CHECK_EQ(genuine.status, std::wstring(L"Signed (Valid)"));
    CHECK(!genuine.hashMismatch);
    CHECK_EQ(genuine.thumbprint, tampered.thumbprint);
    CHECK(genuine.revocation.rfind(L"Unknown (0x", 0) != 0);   // the old per-file WinVerifyTrust code leaked this
    CHECK_EQ(genuine.revocation, tampered.revocation);
}

// D1: an expired but timestamped signature is a good signature.
TEST(Fix_ExpiredTimestampedSignatureIsTrusted)
{
    const std::wstring today = TodayDate();
    int checked = 0;
    wchar_t sys[MAX_PATH] = {};
    GetSystemDirectoryW(sys, MAX_PATH);
    std::wstring roots[] = { std::wstring(sys) };
    for (const std::wstring& root : roots) {
        WIN32_FIND_DATAW fd = {};
        HANDLE h = FindFirstFileW((root + L"\\*.exe").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        size_t scanned = 0;
        do {
            if (++scanned > 800 || checked >= 3) break;
            std::wstring path = root + L"\\" + fd.cFileName;
            SignatureInfo info = AnalyzeFileSignature(path, RevocationMode::Off);
            if (!info.isEmbedded || info.status != L"Signed (Valid)") continue;
            if (info.validTo == L"N/A" || !(info.validTo < today)) continue;   // certificate still valid today
            checked++;
            CHECK(info.timestamped);
            CHECK(!info.timestamp.empty() && info.timestamp <= info.validTo);
            CHECK(info.chainTrusted);
            bool expiredWarning = false;
            for (const std::wstring& w : info.warnings) {
                if (IndicatorCode(w) == L"EXPIRED_CERT") expiredWarning = true;
            }
            CHECK(!expiredWarning);
            if (!info.chainTrusted) std::printf("    note: untrusted chain for %s\n", tf::Narrow(path).c_str());
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    std::printf("    note: %d expired, timestamped signatures checked\n", checked);
}

// A4: only Online (and never in portable mode) may use the network.
TEST(Fix_SignatureChecksOfflineByDefault)
{
    CHECK(!SignatureChecksMayUseNetwork(RevocationMode::Off));
    CHECK(!SignatureChecksMayUseNetwork(RevocationMode::CacheOnly));
    CHECK_EQ(SignatureChecksMayUseNetwork(RevocationMode::Online), !IsPortableMode());

    // Offline the embedded intermediates still complete the chain of a real signed file.
    std::vector<std::wstring> signedFiles = FindEmbeddedSignedFiles(2, 400);
    for (const std::wstring& path : signedFiles) {
        SignatureInfo info = AnalyzeFileSignature(path, RevocationMode::Off);
        CHECK(info.chainTrusted);
        for (const std::wstring& w : info.warnings) CHECK(IndicatorCode(w) != L"PARTIAL_CHAIN");
    }
}

// D3: the revocation verdict comes from the certificate chain bits.
TEST(Fix_RevocationStatusFromChainBits)
{
    CHECK_EQ(RevocationStatusFromChainError(CERT_TRUST_NO_ERROR), std::wstring(L"Good"));
    CHECK_EQ(RevocationStatusFromChainError(CERT_TRUST_IS_REVOKED | CERT_TRUST_IS_OFFLINE_REVOCATION), std::wstring(L"REVOKED"));
    CHECK_EQ(RevocationStatusFromChainError(CERT_TRUST_REVOCATION_STATUS_UNKNOWN | CERT_TRUST_IS_OFFLINE_REVOCATION),
             std::wstring(L"Unknown (offline)"));
    CHECK_EQ(RevocationStatusFromChainError(CERT_TRUST_REVOCATION_STATUS_UNKNOWN),
             std::wstring(L"Unknown (no revocation information)"));
    CHECK_EQ(RevocationStatusFromChainError(CERT_TRUST_IS_PARTIAL_CHAIN), std::wstring(L"Unknown (incomplete chain)"));
    // An expired certificate says nothing about revocation.
    CHECK_EQ(RevocationStatusFromChainError(CERT_TRUST_IS_NOT_TIME_VALID), std::wstring(L"Good"));
}

// D6: package names from long (\\?\) and lowercase WindowsApps paths.
TEST(Fix_PackagePathParsing)
{
    std::wstring pf = ExpandEnvironment(L"%ProgramFiles%");
    REQUIRE(!pf.empty() && pf.find(L'%') == std::wstring::npos);
    std::wstring pkg = L"Microsoft.WindowsCalculator_11.2405.2.0_x64__8wekyb3d8bbwe";
    CHECK_EQ(PackageNameFromPath(pf + L"\\WindowsApps\\" + pkg + L"\\CalculatorApp.exe"), pkg);
    CHECK_EQ(PackageNameFromPath(L"\\\\?\\" + pf + L"\\WindowsApps\\" + pkg + L"\\" + std::wstring(200, L'a') + L"\\x.dll"), pkg);
    CHECK_EQ(PackageNameFromPath(ToLowerW(pf) + L"\\windowsapps\\pkg_1.0_x64\\a.exe"), std::wstring(L"pkg_1.0_x64"));
    CHECK_EQ(PackageNameFromPath(pf + L"\\SomeApp\\app.exe"), std::wstring());
    CHECK_EQ(PackageNameFromPath(L"D:\\WindowsApps\\pkg\\app.exe"), std::wstring());
}

// D12 and I5: entropy of a file open for writing elsewhere, and of a path past MAX_PATH.
TEST(Fix_EntropySharingAndLongPaths)
{
    std::vector<uint8_t> two(4096);
    for (size_t i = 0; i < two.size(); ++i) two[i] = (i % 2) ? 'a' : 'b';
    std::wstring path = tf::TestDir() + L"open_for_write.log";
    REQUIRE(WriteBinaryFile(path, two.data(), two.size()));
    HANDLE writer = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, NULL);
    REQUIRE(writer != INVALID_HANDLE_VALUE);
    double e = CalculateFileEntropy(path);
    CloseHandle(writer);
    CHECK(e > 0.999 && e < 1.001);

    std::wstring deepDir = tf::TestDir();
    while (deepDir.size() < 300) deepDir += L"deep_folder_name_for_long_path_test\\";
    REQUIRE(CreateDeepDirectory(L"\\\\?\\" + deepDir.substr(0, deepDir.size() - 1)));
    std::wstring deepFile = deepDir + L"long.bin";
    REQUIRE(deepFile.size() > MAX_PATH);
    REQUIRE(WriteBinaryFile(ToExtendedPath(deepFile), two.data(), two.size()));
    double deep = CalculateFileEntropy(deepFile);
    CHECK(deep > 0.999 && deep < 1.001);
    CHECK_EQ(GetFileSizeBytes(deepFile), static_cast<int64_t>(two.size()));
}

// H: version strings are found when the first listed language has no string table.
TEST(Fix_VersionStringsInOtherLanguages)
{
    std::vector<uint8_t> image = BuildSamplePe(SamplePeSpec());
    std::wstring path = tf::TestDir() + L"versioned.exe";
    REQUIRE(WriteBinaryFile(path, image.data(), image.size()));
    std::vector<uint8_t> resource = BuildVersionResource(L"Fallback Language Corp");
    HANDLE update = BeginUpdateResourceW(path.c_str(), FALSE);
    REQUIRE(update != NULL);
    BOOL added = UpdateResourceW(update, RT_VERSION, MAKEINTRESOURCEW(VS_VERSION_INFO), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                                 resource.data(), static_cast<DWORD>(resource.size()));
    BOOL written = EndUpdateResourceW(update, added ? FALSE : TRUE);
    REQUIRE(added && written);

    CHECK_EQ(GetFileVersion(path), std::wstring(L"1.2.3.4"));
    CHECK_EQ(GetFileDeveloper(path), std::wstring(L"Fallback Language Corp"));
    CHECK_EQ(GetFileProductName(path), std::wstring(L"Language Test"));
}

// A8: a file with hundreds of streams yields bounded text fields.
TEST(Fix_AltStreamsAreBounded)
{
    std::vector<uint8_t> image = BuildSamplePe(SamplePeSpec());
    std::wstring path = tf::TestDir() + L"many_streams.exe";
    REQUIRE(WriteBinaryFile(path, image.data(), image.size()));
    const char script[] = "@echo off\r\npowershell -nop -c \"Write-Output hi\"\r\n";
    REQUIRE(WriteBinaryFile(path + L":first_hidden.cmd", script, sizeof(script) - 1));
    const int streamCount = 300;
    std::wstring longTail(200, L'n');
    for (int i = 0; i < streamCount; ++i) {
        std::wstring stream = path + L":s" + std::to_wstring(i) + L"_" + longTail;
        REQUIRE(WriteBinaryFile(stream, "x", 1));
    }

    FileOriginInfo origin = AnalyzeFileOrigin(path, true);
    CHECK_EQ(origin.streamCount, static_cast<int64_t>(streamCount + 1));
    CHECK_EQ(origin.streams.size(), kMaxOriginStreamsInspected);
    CHECK(HasFinding(origin.warnings, L"ADS_MANY"));
    CHECK(HasFinding(origin.warnings, L"ADS_EXECUTABLE"));
    CHECK(origin.warnings.size() <= kMaxOriginStreamWarnings + 3);

    ScanOptions options;
    options.revocation = RevocationMode::Off;
    options.computeFuzzyHash = false;
    BaselineEntry e = AnalyzeFile(path, options);
    CHECK(e.altStreams.size() < 16384);
    CHECK(e.altStreams.find(L"more streams not listed") != std::wstring::npos);
    CHECK(e.originWarnings.size() < 16384);
    CHECK(e.originWarnings.find(L"ADS_EXECUTABLE") != std::wstring::npos);
    CHECK(!ExplainIndicator(L"ADS_MANY").empty());
}

// H: scripts get no "Program structure" block; reproducible builds show no fake date.
TEST(Fix_DetailTextScriptsAndReproducibleBuilds)
{
    ScanRow script;
    script.status = L"NEW";
    script.entry.path = L"C:\\x\\run.ps1";
    script.entry.packingStatus = L"Not a PE file";
    script.entry.scriptScore = 2.0;
    script.entry.scriptIndicators = L"DOWNLOAD_CRADLE: contains \"invoke-webrequest\"";
    std::wstring scriptText = BuildRowDetailText(script);
    CHECK(scriptText.find(L"Program structure") == std::wstring::npos);
    CHECK(scriptText.find(L"Script\n") != std::wstring::npos);

    SamplePeSpec spec;
    spec.reproducible = true;
    spec.timestamp = 0xF1234567;   // a hash, which as a date would be in 2098
    std::vector<uint8_t> image = BuildSamplePe(spec);
    std::wstring path = tf::TestDir() + L"repro.exe";
    REQUIRE(WriteBinaryFile(path, image.data(), image.size()));
    ScanOptions options;
    options.revocation = RevocationMode::Off;
    options.computeFuzzyHash = false;
    ScanRow row;
    row.status = L"NEW";
    row.entry = AnalyzeFile(path, options);
    CHECK(row.entry.peAnomalies.find(L"REPRODUCIBLE_BUILD") != std::wstring::npos);
    CHECK(row.entry.peAnomalies.find(L"TIMESTAMP_FUTURE") == std::wstring::npos);
    std::wstring text = BuildRowDetailText(row);
    CHECK(text.find(L"Program structure") != std::wstring::npos);
    CHECK(text.find(L"not a date (reproducible build; the field holds the hash 0xF1234567)") != std::wstring::npos);
    CHECK(text.find(FormatUnixTime(static_cast<long long>(spec.timestamp))) == std::wstring::npos);
    CHECK(!ExplainIndicator(L"REPRODUCIBLE_BUILD").empty());

    ScanRow normal;
    normal.status = L"NEW";
    normal.entry.packingStatus = L"Not packed";
    normal.entry.peTimestamp = 0x65000000;
    CHECK(BuildRowDetailText(normal).find(FormatUnixTime(0x65000000LL)) != std::wstring::npos);
}
