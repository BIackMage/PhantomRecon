// Hashes, entropy, fuzzy hashing, PE parsing, import hash and header findings.

#include "TestFramework.h"

#include "../AppPaths.h"
#include "../FileAnalysis.h"
#include "../FileIO.h"
#include "../FuzzyHash.h"
#include "../HashUtils.h"
#include "../MalwareScoring.h"
#include "../PeFile.h"
#include "../SampleData.h"
#include "../TextUtils.h"

#include <windows.h>
#include <algorithm>
#include <vector>

static std::vector<uint8_t> Bytes(const char* text)
{
    return std::vector<uint8_t>(text, text + strlen(text));
}

static bool HasCode(const std::vector<std::wstring>& findings, const std::wstring& code)
{
    for (const std::wstring& f : findings) {
        if (f.rfind(code + L":", 0) == 0) return true;
    }
    return false;
}

TEST(Hash_KnownVectors)
{
    std::vector<uint8_t> abc = Bytes("abc");
    CHECK_EQ(ComputeBufferMD5Hex(abc.data(), abc.size()), std::wstring(L"900150983cd24fb0d6963f7d28e17f72"));
    CHECK_EQ(ComputeBufferSHA256Hex(abc.data(), abc.size()),
             std::wstring(L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK_EQ(ComputeBufferMD5Hex("", 0), std::wstring(L"d41d8cd98f00b204e9800998ecf8427e"));
    CHECK_EQ(ComputeBufferSHA256Hex("", 0),
             std::wstring(L"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

TEST(Hash_FileMatchesBuffer)
{
    // Larger than one 64 KB read block, so the streaming path is exercised.
    std::vector<uint8_t> data(200000);
    for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>((i * 31 + 7) & 0xFF);
    std::wstring path = tf::TestDir() + L"block.bin";
    REQUIRE(WriteBinaryFile(path, data.data(), data.size()));
    CHECK_EQ(ComputeFileSHA256(path), ComputeBufferSHA256Hex(data.data(), data.size()));
    CHECK_EQ(ComputeFileMD5Hex(path), ComputeBufferMD5Hex(data.data(), data.size()));
    CHECK_EQ(ComputeFileSHA256(tf::TestDir() + L"does_not_exist.bin"), std::wstring());
}

TEST(Entropy_Extremes)
{
    std::vector<uint8_t> zeros(4096, 0);
    CHECK(CalculateBufferEntropy(zeros.data(), zeros.size()) < 0.0001);

    std::vector<uint8_t> all(256 * 16);
    for (size_t i = 0; i < all.size(); ++i) all[i] = static_cast<uint8_t>(i & 0xFF);
    double e = CalculateBufferEntropy(all.data(), all.size());
    CHECK(e > 7.999 && e <= 8.0);

    std::vector<uint8_t> two(1000);
    for (size_t i = 0; i < two.size(); ++i) two[i] = (i % 2) ? 'a' : 'b';
    double e2 = CalculateBufferEntropy(two.data(), two.size());
    CHECK(e2 > 0.999 && e2 < 1.001);
}

static std::vector<uint8_t> Text(size_t size, uint32_t seed)
{
    // Word-like text so the rolling hash finds trigger points.
    static const char* words[] = { "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
                                   "india", "juliet", "kilo", "lima", "mike", "november", "oscar", "papa" };
    std::vector<uint8_t> out;
    uint32_t x = seed;
    while (out.size() < size) {
        x = x * 1103515245u + 12345u;
        const char* w = words[(x >> 16) & 15];
        out.insert(out.end(), w, w + strlen(w));
        out.push_back(' ');
    }
    out.resize(size);
    return out;
}

TEST(FuzzyHash_Properties)
{
    std::vector<uint8_t> a = Text(64 * 1024, 1);
    std::vector<uint8_t> edited = a;
    for (size_t i = 30000; i < 30040; ++i) edited[i] = 'Z';    // small edit in the middle
    std::vector<uint8_t> other = Text(64 * 1024, 999);

    std::wstring ha = ComputeFuzzyHashBuffer(a.data(), a.size());
    std::wstring he = ComputeFuzzyHashBuffer(edited.data(), edited.size());
    std::wstring ho = ComputeFuzzyHashBuffer(other.data(), other.size());
    REQUIRE(!ha.empty());

    // Format "blocksize:hash1:hash2"
    std::vector<std::wstring> parts = SplitW(ha, L':', false);
    REQUIRE(parts.size() == 3);
    CHECK(_wtoi(parts[0].c_str()) >= 3);

    CHECK_EQ(ComputeFuzzyHashBuffer(a.data(), a.size()), ha);   // deterministic
    CHECK_EQ(CompareFuzzyHashes(ha, ha), 100);
    int similar = CompareFuzzyHashes(ha, he);
    int unrelated = CompareFuzzyHashes(ha, ho);
    CHECK(similar >= 50);
    CHECK(unrelated < similar);
    CHECK_EQ(CompareFuzzyHashes(ha, L""), 0);
    CHECK_EQ(CompareFuzzyHashes(L"3:abc:def", L"3:\x00e9\x00e9\x00e9:x"), 0);   // non-ASCII is not a hash
}

TEST(Pe_SampleParses)
{
    SamplePeSpec spec;
    std::vector<uint8_t> image = BuildSamplePe(spec);
    PeInfo pe = ParsePeBuffer(image.data(), image.size());
    REQUIRE(pe.valid);
    CHECK(pe.is64);
    CHECK(!pe.isDll);
    CHECK_EQ(pe.sections.size(), static_cast<size_t>(3));
    CHECK_EQ(pe.timestamp, spec.timestamp);
    CHECK_EQ(pe.imports.size(), static_cast<size_t>(3));
    CHECK(pe.checksumComputedOk);
    CHECK_EQ(pe.checksumHeader, pe.checksumComputed);
    CHECK_EQ(pe.tlsCallbackCount, 0u);
    CHECK_EQ(pe.pdbPath, std::string("C:\\build\\sample\\sample.pdb"));
    CHECK_EQ(pe.overlaySize, static_cast<int64_t>(0));

    // pefile-style import hash input: lowercase, extension dropped, comma joined.
    CHECK_EQ(ImphashInput(pe), std::string("kernel32.exitprocess,kernel32.getstdhandle,kernel32.writefile"));
    std::string input = ImphashInput(pe);
    CHECK_EQ(ComputeImphash(pe), ComputeBufferMD5Hex(input.data(), input.size()));

    // A plain sample has no header findings (clock pinned to 2026).
    CHECK(FindPeAnomalies(pe, L"c:\\x\\plain.exe", 1790000000).empty());
}

TEST(Pe_OddHeadersAreFound)
{
    SamplePeSpec odd;
    odd.timestamp = 0xF0000000;
    odd.checksumMode = 1;
    odd.tlsCallbacks = 1;
    odd.writableCode = true;
    odd.overlayBytes = 128 * 1024;
    odd.pdbPath = "C:\\Users\\someone\\loader\\x.pdb";
    std::vector<uint8_t> image = BuildSamplePe(odd);
    PeInfo pe = ParsePeBuffer(image.data(), image.size());
    REQUIRE(pe.valid);
    CHECK_EQ(pe.tlsCallbackCount, 1u);
    CHECK_EQ(pe.overlaySize, static_cast<int64_t>(128 * 1024));
    CHECK(pe.overlayEntropy > 7.5);

    std::vector<std::wstring> f = FindPeAnomalies(pe, L"c:\\x\\odd.exe", 1790000000);
    CHECK(HasCode(f, L"TIMESTAMP_FUTURE"));
    CHECK(HasCode(f, L"CHECKSUM_MISMATCH"));
    CHECK(HasCode(f, L"TLS_CALLBACKS"));
    CHECK(HasCode(f, L"OVERLAY_DATA"));
    CHECK(HasCode(f, L"OVERLAY_HIGH_ENTROPY"));
    CHECK(HasCode(f, L"PDB_USER_PATH"));
    CHECK(HasCode(f, L"PDB_SUSPICIOUS_WORDS"));
    CHECK(!HasCode(f, L"TIMESTAMP_ZERO"));

    PackingAnalysisResult packing = AnalyzePEPacking(pe, 7.9, static_cast<int>(pe.imports.size()));
    CHECK_EQ(packing.writableExecSections, 1);

    SamplePeSpec zero;
    zero.timestamp = 0;
    zero.checksumMode = 2;
    std::vector<uint8_t> z = BuildSamplePe(zero);
    PeInfo pz = ParsePeBuffer(z.data(), z.size());
    REQUIRE(pz.valid);
    std::vector<std::wstring> fz = FindPeAnomalies(pz, L"c:\\x\\driver.sys", 1790000000);
    CHECK(HasCode(fz, L"TIMESTAMP_ZERO"));
    CHECK(HasCode(fz, L"CHECKSUM_ZERO_DRIVER"));
    CHECK(!HasCode(fz, L"CHECKSUM_MISMATCH"));   // a zero checksum is "not set", not "wrong"
}

TEST(Pe_GarbageIsRejected)
{
    std::vector<uint8_t> junk = Bytes("MZ this is not really a program at all");
    PeInfo pe = ParsePeBuffer(junk.data(), junk.size());
    CHECK(!pe.valid);
    CHECK(FindPeAnomalies(pe, L"x.exe", 1790000000).empty());

    // Truncate a real sample: the parser must fail cleanly, not crash, and what it
    // does report about a cut-off file must be true. The sample's headers start at
    // 0x80; the optional header ends at 0x188 and the three section headers (40 bytes
    // each) at 0x200. Section data starts at 0x400.
    std::vector<uint8_t> image = BuildSamplePe(SamplePeSpec());
    REQUIRE(image.size() > 0x800);
    for (size_t cut : { size_t(2), size_t(64), size_t(0x100), size_t(0x187) }) {
        PeInfo t = ParsePeBuffer(image.data(), cut);
        if (t.valid) tf::Fail(__FILE__, __LINE__, "a file cut at " + std::to_string(cut) + " bytes parsed as valid");
        CHECK(!t.error.empty());
    }
    struct Cut {
        size_t size;
        size_t sections;   // complete section headers inside the cut
    };
    for (Cut cut : { Cut{ 0x188, 0 }, Cut{ 0x1B0, 1 }, Cut{ 0x200, 3 }, Cut{ image.size() / 2, 3 }, Cut{ image.size() - 1, 3 } }) {
        PeInfo t = ParsePeBuffer(image.data(), cut.size);
        std::string at = " (cut at " + std::to_string(cut.size) + ")";
        if (!t.valid) {
            tf::Fail(__FILE__, __LINE__, "complete headers rejected" + at + ": " + tf::Narrow(t.error));
            continue;
        }
        if (t.sections.size() != cut.sections) tf::Fail(__FILE__, __LINE__, "sections " + std::to_string(t.sections.size()) + at);
        CHECK_EQ(t.sectionHeaderCount, static_cast<uint32_t>(cut.sections));
        CHECK_EQ(t.fileSize, static_cast<int64_t>(cut.size));
        // A file that ends inside its own sections has nothing appended after them.
        if (t.overlaySize != 0) tf::Fail(__FILE__, __LINE__, "overlay of " + std::to_string(t.overlaySize) + " bytes" + at);
    }
    CHECK(!ParsePeBuffer(nullptr, 0).valid);
}

TEST(Pe_ImportScoring)
{
    SamplePeSpec spec;
    spec.imports = { { "KERNEL32.dll", { "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "ExitProcess" } } };
    std::vector<uint8_t> image = BuildSamplePe(spec);
    PeInfo pe = ParsePeBuffer(image.data(), image.size());
    REQUIRE(pe.valid);
    ImportScanResult r = ScanPEImports(pe);
    CHECK_EQ(r.totalImports, 4);
    CHECK(r.suspiciousImportCount >= 3);
    REQUIRE(!r.techniques.empty());
    bool injection = false;
    for (const std::wstring& t : r.techniques) {
        if (t.rfind(L"T1055", 0) == 0) injection = true;   // Process Injection or a sub-technique
    }
    CHECK(injection);

    double withImports = CalculateMalwareScore(5.0, false, false, false, r);
    double clean = CalculateMalwareScore(5.0, false, false, false, ImportScanResult());
    double signedClean = CalculateMalwareScore(5.0, true, false, false, ImportScanResult());
    CHECK(withImports > clean);
    CHECK(clean > signedClean);    // unsigned adds the unsigned penalty
    CHECK(withImports <= 10.0);
}

TEST(Signature_SystemFileIsSigned)
{
    wchar_t sys[MAX_PATH] = {};
    GetSystemDirectoryW(sys, MAX_PATH);
    std::wstring notepad = std::wstring(sys) + L"\\notepad.exe";
    std::wstring kernel32 = std::wstring(sys) + L"\\kernel32.dll";
    std::wstring target = FileExists(notepad) ? notepad : kernel32;
    SignatureInfo info = AnalyzeFileSignature(target, RevocationMode::Off);
    CHECK(info.status.rfind(L"Signed", 0) == 0);
    CHECK(info.hashValid);
    CHECK(info.chainTrusted);
    SignatureSummary summary = GetSignatureSummary(target);
    CHECK(summary.valid);
    CHECK(summary.microsoft);

    // An unsigned file of our own.
    std::vector<uint8_t> image = BuildSamplePe(SamplePeSpec());
    std::wstring path = tf::TestDir() + L"unsigned.exe";
    REQUIRE(WriteBinaryFile(path, image.data(), image.size()));
    SignatureInfo unsignedInfo = AnalyzeFileSignature(path, RevocationMode::Off);
    CHECK_EQ(unsignedInfo.status, std::wstring(L"Unsigned"));
    CHECK(!GetSignatureSummary(path).valid);

    CHECK(IsMicrosoftSignerName(L"Microsoft Windows"));
    CHECK(IsMicrosoftSignerName(L"Microsoft Corporation"));
    CHECK(!IsMicrosoftSignerName(L"Microsoftt Fake Ltd"));
    CHECK(!IsMicrosoftSignerName(L"Not Microsoft"));
}
