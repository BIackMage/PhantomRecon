// Engine core fixes from the 2026-10-26 review: baseline file limits and loading, hashing
// on read errors, CSV formula guard and write and size failures, revoked Microsoft
// signatures, Fast Scan registry paths, scan roots, path keys, text decoding, the scoring
// INI and the fuzzy hash block size.

#include "TestFramework.h"

#include "../AppPaths.h"
#include "../Baseline.h"
#include "../FileIO.h"
#include "../FuzzyHash.h"
#include "../HashUtils.h"
#include "../KnownGood.h"
#include "../RegistryEnumerator.h"
#include "../SampleData.h"
#include "../ScanCore.h"
#include "../ScanCsv.h"
#include "../ScoringConfig.h"
#include "../TextUtils.h"

#include <windows.h>
#include <winioctl.h>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static BaselineEntry FixEntry(const std::wstring& path)
{
    BaselineEntry e;
    e.path = path;
    e.fileSize = 4096;
    e.md5 = L"0123456789abcdef0123456789abcdef";
    e.sha256 = std::wstring(64, L'a');
    e.signature = L"Unsigned";
    e.signatureType = L"None";
    e.version = L"1.0.0.0";
    e.developer = L"Example Ltd";
    e.readOnly = L"No";
    e.hidden = L"No";
    e.permissions = L"Owner: BUILTIN\\Administrators";
    e.entropy = 5.0;
    e.malwareScore = 1.0;
    e.packingStatus = L"Not packed";
    e.revocation = L"Not checked";
    return e;
}

static std::vector<uint8_t> Pattern(size_t size, uint32_t seed)
{
    std::vector<uint8_t> out(size);
    uint32_t x = seed ? seed : 1;
    for (size_t i = 0; i < size; ++i) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        out[i] = static_cast<uint8_t>(x);
    }
    return out;
}

static bool WriteBytes(const std::wstring& path, const std::vector<uint8_t>& bytes)
{
    return WriteBinaryFile(path, bytes.data(), bytes.size());
}

static bool HexToBytes(const std::wstring& hex, uint8_t* out, size_t count)
{
    if (hex.size() != count * 2) return false;
    for (size_t i = 0; i < count; ++i) {
        out[i] = static_cast<uint8_t>(std::stoi(tf::Narrow(hex.substr(i * 2, 2)), nullptr, 16));
    }
    return true;
}

// Recursive delete that works past MAX_PATH and removes junctions without entering them.
static void DeleteTreeLong(const std::wstring& path)
{
    std::wstring io = path.rfind(L"\\\\?\\", 0) == 0 ? path : L"\\\\?\\" + path;
    DWORD attrs = GetFileAttributesW(io.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return;
    if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        SetFileAttributesW(io.c_str(), FILE_ATTRIBUTE_NORMAL);
        DeleteFileW(io.c_str());
        return;
    }
    if (!(attrs & FILE_ATTRIBUTE_REPARSE_POINT)) {
        WIN32_FIND_DATAW fd = {};
        HANDLE h = FindFirstFileW((io + L"\\*").c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                DeleteTreeLong(io + L"\\" + fd.cFileName);
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
    }
    RemoveDirectoryW(io.c_str());
}

// A directory junction (no privilege needed), made the way mklink /J does.
static bool CreateJunction(const std::wstring& link, const std::wstring& target)
{
    if (!CreateDirectoryW(link.c_str(), NULL)) return false;
    HANDLE h = CreateFileW(link.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    std::wstring sub = L"\\??\\" + target;
    USHORT subBytes = static_cast<USHORT>(sub.size() * sizeof(wchar_t));
    USHORT printBytes = static_cast<USHORT>(target.size() * sizeof(wchar_t));
    USHORT dataLength = static_cast<USHORT>(8 + subBytes + 2 + printBytes + 2);
    std::vector<BYTE> buf(8 + static_cast<size_t>(dataLength), 0);
    DWORD tag = IO_REPARSE_TAG_MOUNT_POINT;
    USHORT subOffset = 0;
    USHORT printOffset = static_cast<USHORT>(subBytes + 2);
    memcpy(&buf[0], &tag, 4);
    memcpy(&buf[4], &dataLength, 2);
    memcpy(&buf[8], &subOffset, 2);
    memcpy(&buf[10], &subBytes, 2);
    memcpy(&buf[12], &printOffset, 2);
    memcpy(&buf[14], &printBytes, 2);
    memcpy(&buf[16], sub.c_str(), subBytes);
    memcpy(&buf[16 + subBytes + 2], target.c_str(), printBytes);
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, buf.data(), static_cast<DWORD>(buf.size()),
        NULL, 0, &returned, NULL);
    CloseHandle(h);
    return ok != FALSE;
}

// Holds an exclusive byte-range lock so reads and writes through other handles fail
// part way, the way a bad sector or a full disk would.
class RangeLock {
public:
    RangeLock(const std::wstring& path, DWORD offset, DWORD length)
        : m_length(length)
    {
        m_file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (m_file == INVALID_HANDLE_VALUE) return;
        m_overlapped.Offset = offset;
        m_locked = LockFileEx(m_file, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, length, 0, &m_overlapped) != FALSE;
    }
    ~RangeLock() { Release(); }
    RangeLock(const RangeLock&) = delete;
    RangeLock& operator=(const RangeLock&) = delete;

    bool Locked() const { return m_locked; }
    void Release()
    {
        if (m_locked) UnlockFileEx(m_file, 0, m_length, 0, &m_overlapped);
        m_locked = false;
        if (m_file != INVALID_HANDLE_VALUE) CloseHandle(m_file);
        m_file = INVALID_HANDLE_VALUE;
    }

private:
    HANDLE     m_file = INVALID_HANDLE_VALUE;
    OVERLAPPED m_overlapped = {};
    DWORD      m_length = 0;
    bool       m_locked = false;
};

// ---------------------------------------------------------------------------
// A8: the reader accepts what the writer writes
// ---------------------------------------------------------------------------
TEST(FixEngine_BaselineLongFieldsLoad)
{
    // 100,000 characters: over the old 65,536 reader limit (many alternate data streams).
    Baseline b;
    BaselineEntry e = FixEntry(L"C:\\Apps\\streams.exe");
    e.altStreams = std::wstring(100000, L'x');
    b.AddEntry(e);
    std::wstring path = tf::TestDir() + L"long.prbl";
    REQUIRE(b.SaveToFile(path));
    Baseline loaded;
    REQUIRE(loaded.LoadFromFile(path));
    const BaselineEntry* found = loaded.FindEntry(L"C:\\Apps\\streams.exe");
    REQUIRE(found != nullptr);
    CHECK_EQ(found->altStreams.size(), static_cast<size_t>(100000));
    CHECK(found->altStreams == e.altStreams);

    // Over the format limit: cut on write to exactly the limit, and the file still loads.
    Baseline big;
    BaselineEntry huge = FixEntry(L"C:\\Apps\\huge.exe");
    huge.altStreams = std::wstring(static_cast<size_t>(Baseline::MAX_STRING_CHARS) + 10, L'y');
    big.AddEntry(huge);
    std::wstring bigPath = tf::TestDir() + L"huge.prbl";
    REQUIRE(big.SaveToFile(bigPath));
    Baseline bigLoaded;
    REQUIRE(bigLoaded.LoadFromFile(bigPath));
    const BaselineEntry* h = bigLoaded.FindEntry(L"C:\\Apps\\huge.exe");
    REQUIRE(h != nullptr);
    CHECK_EQ(h->altStreams.size(), static_cast<size_t>(Baseline::MAX_STRING_CHARS));
    CHECK_EQ(h->md5, huge.md5);   // the fields after the long one are intact
}

// ---------------------------------------------------------------------------
// A9, I6, I5: a read error is never a hash; error texts are not comparable hashes
// ---------------------------------------------------------------------------
TEST(FixEngine_ReadErrorGivesNoHash)
{
    std::vector<uint8_t> data = Pattern(300 * 1024, 7);
    std::wstring path = tf::TestDir() + L"locked.bin";
    REQUIRE(WriteBytes(path, data));

    {
        RangeLock lock(path, 128 * 1024, 64 * 1024);
        REQUIRE(lock.Locked());
        CHECK_EQ(ComputeFileSHA256(path), std::wstring());
        CHECK_EQ(ComputeFileMD5Hex(path), std::wstring());
        std::vector<uint8_t> bytes = { 1, 2, 3 };
        CHECK(!ReadBinaryFile(path, bytes));
        CHECK(bytes.empty());
        std::wstring text = L"stale";
        CHECK(!ReadTextFile(path, text));
        CHECK(text.empty());
        CHECK(ComputeFuzzyHashFile(path).empty());
    }

    // Lock released: the real digests come back.
    CHECK_EQ(ComputeFileSHA256(path), ComputeBufferSHA256Hex(data.data(), data.size()));
    CHECK_EQ(ComputeFileMD5Hex(path), ComputeBufferMD5Hex(data.data(), data.size()));
    std::vector<uint8_t> back;
    REQUIRE(ReadBinaryFile(path, back));
    CHECK(back == data);
}

TEST(FixEngine_HashErrorTextIsNotAMatch)
{
    Baseline b;
    BaselineEntry unreadable = FixEntry(L"C:\\Apps\\busy.exe");
    unreadable.md5 = L"MD5 Checksum Error";
    unreadable.sha256 = L"SHA256 Checksum Error";
    b.AddEntry(unreadable);
    BaselineEntry good = FixEntry(L"C:\\Apps\\good.exe");
    b.AddEntry(good);

    // Same error text on both sides used to be a MATCH.
    ComparisonResult same = b.CompareEntry(unreadable);
    CHECK(same.status == BaselineStatus::Changed);
    CHECK(same.changeDetails.find(L"not verified") != std::wstring::npos);
    CHECK(same.changeDetails.find(L"MD5 changed") == std::wstring::npos);

    // A file that was readable before and cannot be hashed now.
    BaselineEntry nowUnreadable = good;
    nowUnreadable.md5 = L"MD5 Checksum Error";
    nowUnreadable.sha256 = L"SHA256 Checksum Error";
    ComparisonResult lost = b.CompareEntry(nowUnreadable);
    CHECK(lost.status == BaselineStatus::Changed);
    CHECK(lost.changeDetails.find(L"not verified") != std::wstring::npos);

    // Even a Microsoft-signed file with no digest is CHANGED, never UPDATED.
    Baseline ms;
    BaselineEntry msBase = FixEntry(L"C:\\Windows\\x.dll");
    msBase.signature = L"Signed (Valid) (Microsoft Windows)";
    ms.AddEntry(msBase);
    BaselineEntry msNow = msBase;
    msNow.sha256 = L"SHA256 Checksum Error";
    CHECK(ms.CompareEntry(msNow).status == BaselineStatus::Changed);

    // Control: identical digests still MATCH.
    CHECK(b.CompareEntry(good).status == BaselineStatus::Match);

    // The known-good list never matches an error text or a non-hex value.
    CHECK(!IsKnownGoodHash(L"SHA256 Checksum Error"));
    std::wstring list = tf::TestDir() + L"known.txt";
    std::wstring validHash = std::wstring(64, L'c');
    REQUIRE(WriteUtf8File(list, std::wstring(64, L'z') + L",bogus\r\n" + validHash + L",tool\r\n", false));
    CHECK_EQ(LoadKnownGoodList(list), static_cast<size_t>(1));
    CHECK(IsKnownGoodHash(validHash));
    CHECK(!IsKnownGoodHash(std::wstring(64, L'z')));
    LoadKnownGoodList(DefaultKnownGoodPath());   // put the process-wide list back
}

TEST(FixEngine_HashDeepPathWithoutPrefix)
{
    std::wstring top = tf::TestDir() + L"deep";
    std::wstring deep = top;
    while (deep.size() < 300) deep += L"\\abcdefghijklmnopqrstuvwxyz0123456789";
    REQUIRE(EnsureDirectory(deep));
    std::vector<uint8_t> data = Pattern(5000, 11);
    std::wstring file = deep + L"\\long.bin";
    REQUIRE(file.size() > MAX_PATH);
    REQUIRE(WriteBytes(file, data));
    CHECK_EQ(ComputeFileSHA256(file), ComputeBufferSHA256Hex(data.data(), data.size()));
    CHECK_EQ(ComputeFileMD5Hex(file), ComputeBufferMD5Hex(data.data(), data.size()));
    DeleteTreeLong(top);
}

// ---------------------------------------------------------------------------
// A10: CSV formula injection
// ---------------------------------------------------------------------------
TEST(FixEngine_CsvFormulaGuard)
{
    CHECK_EQ(CsvGuardFormula(L"=1+1"), std::wstring(L"'=1+1"));
    CHECK_EQ(CsvGuardFormula(L"+1"), std::wstring(L"'+1"));
    CHECK_EQ(CsvGuardFormula(L"-2"), std::wstring(L"'-2"));
    CHECK_EQ(CsvGuardFormula(L"@SUM(A1)"), std::wstring(L"'@SUM(A1)"));
    CHECK_EQ(CsvGuardFormula(L"\tx"), std::wstring(L"'\tx"));
    CHECK_EQ(CsvGuardFormula(L"Example Ltd"), std::wstring(L"Example Ltd"));
    CHECK_EQ(CsvGuardFormula(L"'plain"), std::wstring(L"'plain"));
    CHECK_EQ(CsvGuardFormula(L"'=x"), std::wstring(L"''=x"));
    for (const wchar_t* s : { L"=1+1", L"'=x", L"''@y", L"'plain", L"plain", L"-", L"'" }) {
        CHECK_EQ(CsvUnguardFormula(CsvGuardFormula(s)), std::wstring(s));
    }

    ScanRow r;
    r.entry = FixEntry(L"C:\\Apps\\evil.exe");
    r.entry.developer = L"=HYPERLINK(\"http://example.invalid/x\",\"Click\")";
    r.entry.version = L"+1.0";
    r.entry.issuer = L"@SUM(1+1)";
    r.entry.pdbPath = L"-2+3";
    r.entry.rootCA = L"'=already quoted";
    r.entry.zoneId = -1;
    r.status = L"CHANGED";
    r.riskDelta = -1.5;

    std::wstring path = tf::TestDir() + L"formula.csv";
    REQUIRE(ExportRowsToCsv(path, { r }));
    std::wstring raw;
    REQUIRE(ReadTextFile(path, raw));
    CHECK(raw.find(L"\"'=HYPERLINK(") != std::wstring::npos);
    CHECK(raw.find(L",=HYPERLINK") == std::wstring::npos);
    CHECK(raw.find(L",\"=HYPERLINK") == std::wstring::npos);
    CHECK(raw.find(L",'+1.0,") != std::wstring::npos);
    CHECK(raw.find(L",'@SUM(1+1),") != std::wstring::npos);
    CHECK(raw.find(L",'-2+3,") != std::wstring::npos);
    CHECK(raw.find(L",-1.5") != std::wstring::npos);    // numbers this program wrote stay numbers
    CHECK(raw.find(L",'-1.5") == std::wstring::npos);

    std::vector<ScanRow> back;
    REQUIRE(LoadRowsFromCsv(path, back));
    REQUIRE(back.size() == 1);
    CHECK_EQ(back[0].entry.developer, r.entry.developer);
    CHECK_EQ(back[0].entry.version, r.entry.version);
    CHECK_EQ(back[0].entry.issuer, r.entry.issuer);
    CHECK_EQ(back[0].entry.pdbPath, r.entry.pdbPath);
    CHECK_EQ(back[0].entry.rootCA, r.entry.rootCA);
    CHECK_EQ(back[0].entry.zoneId, -1);
    CHECK(back[0].riskDelta < -1.49 && back[0].riskDelta > -1.51);
}

// ---------------------------------------------------------------------------
// D8: an over-size CSV is refused, not loaded in part
// ---------------------------------------------------------------------------
TEST(FixEngine_CsvOverLimitRefused)
{
    // ReadTextFile reports the cut.
    std::wstring smallFile = tf::TestDir() + L"smallFile.txt";
    REQUIRE(WriteUtf8File(smallFile, L"0123456789", false));
    std::wstring text;
    bool truncated = false;
    REQUIRE(ReadTextFile(smallFile, text, 4, &truncated));
    CHECK(truncated);
    CHECK_EQ(text, std::wstring(L"0123"));
    REQUIRE(ReadTextFile(smallFile, text, 1024, &truncated));
    CHECK(!truncated);
    CHECK_EQ(text, std::wstring(L"0123456789"));

    // A 513 MB CSV (sparse, so it costs no disk space) is refused and rows is untouched.
    std::wstring path = tf::TestDir() + L"big.csv";
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    REQUIRE(h != INVALID_HANDLE_VALUE);
    const char header[] = "Path,MD5\r\nC:\\x.exe,ab\r\n";
    DWORD written = 0;
    WriteFile(h, header, static_cast<DWORD>(sizeof(header) - 1), &written, NULL);
    DWORD returned = 0;
    DeviceIoControl(h, FSCTL_SET_SPARSE, NULL, 0, NULL, 0, &returned, NULL);
    LARGE_INTEGER end;
    end.QuadPart = 513LL * 1024 * 1024;
    BOOL sized = SetFilePointerEx(h, end, NULL, FILE_BEGIN) && SetEndOfFile(h);
    CloseHandle(h);
    REQUIRE(sized);

    std::vector<ScanRow> rows(1);
    rows[0].entry.path = L"C:\\already\\there.exe";
    CHECK(!LoadRowsFromCsv(path, rows));
    CHECK_EQ(rows.size(), static_cast<size_t>(1));
    DeleteFileW(path.c_str());
}

// ---------------------------------------------------------------------------
// D9: a failed CSV write is reported and the cut-off file removed
// ---------------------------------------------------------------------------
TEST(FixEngine_CsvWriteFailureReported)
{
    std::wstring path = tf::TestDir() + L"fail.csv";
    {
        CsvWriter writer;
        REQUIRE(writer.Open(path));
        RangeLock lock(path, 0, 0x40000000);
        REQUIRE(lock.Locked());
        ScanRow r;
        r.entry = FixEntry(L"C:\\Apps\\a.exe");
        r.status = L"NEW";
        for (int i = 0; i < 400; ++i) writer.Write(r);   // more than the 64 KB buffer
        CHECK(writer.Failed());
        CHECK(!writer.Close());
        lock.Release();
    }
    CHECK(!FileExists(path));   // the incomplete file is gone

    // Control: the same rows without the lock write and close cleanly.
    {
        CsvWriter writer;
        REQUIRE(writer.Open(path));
        ScanRow r;
        r.entry = FixEntry(L"C:\\Apps\\a.exe");
        for (int i = 0; i < 400; ++i) writer.Write(r);
        CHECK(!writer.Failed());
        CHECK(writer.Close());
    }
    std::vector<ScanRow> rows;
    REQUIRE(LoadRowsFromCsv(path, rows));
    CHECK_EQ(rows.size(), static_cast<size_t>(400));

    // A scan whose CSV write fails reports csvFailed.
    std::wstring pack = tf::TestDir() + L"pack";
    REQUIRE(CreateSamplePack(pack).ok);
    std::wstring scanCsv = tf::TestDir() + L"scan.csv";
    std::unique_ptr<RangeLock> scanLock;
    ScanCallbacks cb;
    cb.onPhase = [&](const std::wstring&) {
        if (!scanLock) scanLock.reset(new RangeLock(scanCsv, 0, 0x40000000));
    };
    ScanOptions options;
    options.revocation = RevocationMode::Off;
    ScanSummary s = RunScan(ScanMode::Baseline, pack, scanCsv, nullptr, tf::TestDir() + L"scan.prbl", options, cb);
    REQUIRE(scanLock != nullptr);
    CHECK(scanLock->Locked());
    CHECK(s.csvFailed);
    CHECK(s.baselineSaved);   // the baseline does not depend on the CSV
    scanLock.reset();
    CHECK(!FileExists(scanCsv));
}

// ---------------------------------------------------------------------------
// D4: a revoked Microsoft certificate is not Microsoft-signed
// ---------------------------------------------------------------------------
TEST(FixEngine_RevokedMicrosoftIsNotTrusted)
{
    BaselineEntry ms = FixEntry(L"C:\\Tools\\new.dll");
    ms.signature = L"Signed (Valid) (Microsoft Corporation)";
    ms.signatureType = L"Embedded";
    ms.revocation = L"Good";
    CHECK(IsMicrosoftSignedEntry(ms));

    BaselineEntry revoked = ms;
    revoked.revocation = L"REVOKED";
    CHECK(!IsMicrosoftSignedEntry(revoked));
    BaselineEntry warned = ms;
    warned.sigWarnings = L"SIGNED_IN_TEMP: x; REVOKED: The signing certificate has been revoked";
    CHECK(!IsMicrosoftSignedEntry(warned));
    BaselineEntry similar = ms;
    similar.sigWarnings = L"REVOKED_SOMETHING_ELSE: not the revocation code";
    CHECK(IsMicrosoftSignedEntry(similar));

    Baseline empty;
    CHECK(empty.CompareEntry(ms).status == BaselineStatus::Known);
    CHECK(empty.CompareEntry(revoked).status == BaselineStatus::New);

    Baseline b;
    BaselineEntry old = FixEntry(L"C:\\Tools\\lib.dll");
    old.signature = L"Signed (Valid) (Microsoft Corporation)";
    old.revocation = L"Good";
    old.imphash = L"00112233445566778899aabbccddeeff";
    b.AddEntry(old);
    BaselineEntry patched = old;
    patched.md5 = L"fedcba9876543210fedcba9876543210";
    patched.sha256 = std::wstring(64, L'b');
    CHECK(b.CompareEntry(patched).status == BaselineStatus::Updated);
    patched.revocation = L"REVOKED";
    CHECK(b.CompareEntry(patched).status == BaselineStatus::Changed);
}

// ---------------------------------------------------------------------------
// D7: Fast Scan paths from the registry
// ---------------------------------------------------------------------------
TEST(FixEngine_RegistryProgramPaths)
{
    std::wstring root = tf::TestDir() + L"Program Files Test\\App Dir";
    REQUIRE(EnsureDirectory(root));
    std::vector<uint8_t> image = BuildSamplePe(SamplePeSpec());
    REQUIRE(WriteBytes(root + L"\\uninst.exe", image));
    REQUIRE(WriteBytes(root + L"\\main.exe", image));
    auto same = [](const std::wstring& a, const std::wstring& b) {
        return Baseline::NormalizePath(a) == Baseline::NormalizePath(b);
    };

    // Unquoted with spaces and arguments: used to be cut at the first space.
    CHECK(same(RegistryEnumerator::ExecutableFromCommandLine(root + L"\\uninst.exe /S /norestart"), root + L"\\uninst.exe"));
    CHECK(same(RegistryEnumerator::ExecutableFromCommandLine(root + L"\\uninst.exe"), root + L"\\uninst.exe"));
    CHECK(same(RegistryEnumerator::ExecutableFromCommandLine(L"  \"" + root + L"\\uninst.exe\" /S"), root + L"\\uninst.exe"));
    CHECK_EQ(RegistryEnumerator::ExecutableFromCommandLine(L"MsiExec.exe /X{11111111-2222-3333-4444-555555555555}"), std::wstring());
    CHECK_EQ(RegistryEnumerator::ExecutableFromCommandLine(root + L"\\missing.exe /S"), std::wstring());
    CHECK_EQ(RegistryEnumerator::ExecutableFromCommandLine(L""), std::wstring());

    // Quoted InstallLocation with a trailing backslash: used to be skipped.
    CHECK(same(RegistryEnumerator::CleanInstallLocation(L" \"" + root + L"\\\" "), root));
    CHECK(same(RegistryEnumerator::CleanInstallLocation(root + L"\\"), root));
    CHECK_EQ(RegistryEnumerator::CleanInstallLocation(L"relative\\folder"), std::wstring());

    // A junction inside the install folder is not followed.
    std::wstring outside = tf::TestDir() + L"elsewhere";
    REQUIRE(EnsureDirectory(outside));
    REQUIRE(WriteBytes(outside + L"\\linked.exe", image));
    std::wstring link = root + L"\\link";
    REQUIRE(CreateJunction(link, outside));
    REQUIRE(FileExists(link + L"\\linked.exe"));   // the junction works

    // A folder deeper than MAX_PATH inside the install folder.
    std::wstring deep = root + L"\\" + std::wstring(120, L'd') + L"\\" + std::wstring(120, L'e');
    REQUIRE(EnsureDirectory(deep));
    REQUIRE(WriteBytes(deep + L"\\deep.exe", image));
    REQUIRE((deep + L"\\deep.exe").size() > MAX_PATH);

    InstalledProgram p;
    p.displayName = L"Fix test program";
    p.installLocation = L"\"" + root + L"\\\"";
    p.uninstallString = root + L"\\uninst.exe /S";
    std::vector<std::wstring> found = RegistryEnumerator::GetExecutablePathsFromPrograms({ p }, 3);
    std::set<std::wstring> keys;
    for (const std::wstring& f : found) keys.insert(Baseline::NormalizePath(f));
    CHECK(keys.count(Baseline::NormalizePath(root + L"\\main.exe")) == 1);
    CHECK(keys.count(Baseline::NormalizePath(root + L"\\uninst.exe")) == 1);
    CHECK(keys.count(Baseline::NormalizePath(deep + L"\\deep.exe")) == 1);
    CHECK(keys.count(Baseline::NormalizePath(link + L"\\linked.exe")) == 0);
    CHECK_EQ(found.size(), static_cast<size_t>(3));

    RemoveDirectoryW(link.c_str());
    DeleteTreeLong(tf::TestDir() + L"Program Files Test");
}

// ---------------------------------------------------------------------------
// D10, D11: scan roots
// ---------------------------------------------------------------------------
TEST(FixEngine_DriveLetterRootIsTheDrive)
{
    // "C:" alone is C:'s current folder to Windows; as a scan root it means the drive.
    CHECK_EQ(NormalizeScanRoot(L"C:"), std::wstring(L"C:\\"));
    CHECK_EQ(NormalizeScanRoot(L"  c:  "), std::wstring(L"c:\\"));
    CHECK_EQ(NormalizeScanRoot(L"C:\\"), std::wstring(L"C:\\"));
    CHECK_EQ(NormalizeScanRoot(L"C:/Tools/"), std::wstring(L"C:\\Tools"));
    CHECK_EQ(NormalizeScanRoot(L""), std::wstring());

    std::vector<std::wstring> roots = SplitScanRoots(L"D:; d:\\ ;E:\\X\\");
    REQUIRE(roots.size() == 2);
    CHECK_EQ(roots[0], std::wstring(L"D:\\"));
    CHECK_EQ(roots[1], std::wstring(L"E:\\X"));
}

TEST(FixEngine_NestedRootsScannedOnce)
{
    std::wstring a = tf::TestDir() + L"pack";
    REQUIRE(CreateSamplePack(a).ok);
    REQUIRE(EnsureDirectory(a + L"\\sub"));
    REQUIRE(WriteBytes(a + L"\\sub\\inner.exe", BuildSamplePe(SamplePeSpec())));

    ScanOptions options;
    options.revocation = RevocationMode::Off;
    ScanCallbacks none;
    ScanSummary one = RunScan(ScanMode::Baseline, std::vector<std::wstring>{ a }, L"", nullptr,
        tf::TestDir() + L"one.prbl", options, none);
    REQUIRE(one.baselineSaved);
    REQUIRE(one.executables > 1);

    std::map<std::wstring, int> seen;
    ScanCallbacks count;
    count.onRow = [&](const ScanRow& r) { seen[Baseline::NormalizePath(r.entry.path)]++; };
    ScanSummary nested = RunScan(ScanMode::Baseline, std::vector<std::wstring>{ a, a + L"\\sub", a + L"\\", a + L"\\sub\\" },
        L"", nullptr, tf::TestDir() + L"nested.prbl", options, count);
    REQUIRE(nested.baselineSaved);
    CHECK_EQ(nested.executables, one.executables);
    CHECK_EQ(nested.filesProcessed, one.filesProcessed);
    CHECK_EQ(nested.totalFiles, one.totalFiles);
    CHECK_EQ(nested.baselineEntries, one.baselineEntries);
    CHECK_EQ(seen.size(), static_cast<size_t>(one.executables));
    for (const auto& pair : seen) CHECK_EQ(pair.second, 1);
    CHECK(seen.count(Baseline::NormalizePath(a + L"\\sub\\inner.exe")) == 1);
    CHECK(nested.root.find(L"; ") != std::wstring::npos);   // two roots kept, repeats dropped
    CHECK(nested.root.find(L"; ", nested.root.find(L"; ") + 2) == std::wstring::npos);
}

// ---------------------------------------------------------------------------
// I11: path keys
// ---------------------------------------------------------------------------
TEST(FixEngine_PathKeysAliases)
{
    CHECK_EQ(Baseline::NormalizePath(L"\\\\?\\C:\\Tools\\A.EXE"), Baseline::NormalizePath(L"c:/tools//a.exe"));
    CHECK_EQ(Baseline::NormalizePath(L"\\\\?\\UNC\\srv\\share\\a.exe"), std::wstring(L"\\\\srv\\share\\a.exe"));
    CHECK_EQ(Baseline::NormalizePath(L"\\\\srv\\share\\\\a.exe"), std::wstring(L"\\\\srv\\share\\a.exe"));
    CHECK_EQ(Baseline::NormalizePath(L"C:\\"), std::wstring(L"c:\\"));
    CHECK_EQ(Baseline::NormalizePath(L"C:\\Tools\\"), std::wstring(L"c:\\tools"));
    // Trailing dots stay: "a.exe." and "a.exe" can be two files on NTFS.
    CHECK(Baseline::NormalizePath(L"C:\\Tools\\a.exe.") != Baseline::NormalizePath(L"C:\\Tools\\a.exe"));

    Baseline b;
    b.AddEntry(FixEntry(L"\\\\?\\C:\\Tools\\Prefixed.exe"));
    CHECK(b.FindEntry(L"C:\\Tools\\prefixed.exe") != nullptr);

    // 8.3 short names, when the volume has them.
    std::wstring longDir = tf::TestDir() + L"A Long Folder Name For Short Names";
    REQUIRE(EnsureDirectory(longDir));
    std::wstring file = longDir + L"\\tool.exe";
    REQUIRE(WriteBytes(file, Pattern(100, 3)));
    wchar_t shortBuf[MAX_PATH] = {};
    DWORD n = GetShortPathNameW(longDir.c_str(), shortBuf, MAX_PATH);
    std::wstring shortDir(shortBuf, n < MAX_PATH ? n : 0);
    if (!shortDir.empty() && shortDir.find(L'~') != std::wstring::npos) {
        Baseline s;
        s.AddEntry(FixEntry(file));
        CHECK(s.FindEntry(shortDir + L"\\tool.exe") != nullptr);
        CHECK(s.CoversFolderOf(shortDir + L"\\other.exe"));
        // A file that no longer exists under a short folder name maps to the same key.
        CHECK_EQ(Baseline::NormalizePath(shortDir + L"\\gone.exe"), Baseline::NormalizePath(longDir + L"\\gone.exe"));
        CHECK_EQ(Baseline::NormalizePath(NormalizeScanRoot(shortDir)), Baseline::NormalizePath(longDir));
    }
    else {
        std::printf("    note: no 8.3 names on this volume, short-name checks not run\n");
    }
}

// ---------------------------------------------------------------------------
// H: ANSI decode, I15: unaligned UTF-16
// ---------------------------------------------------------------------------
TEST(FixEngine_DecodeTextEdges)
{
    // ANSI text whose last character is accented: was taken for cut-off UTF-8. (On a PC
    // whose ANSI code page is UTF-8 there is no separate ANSI decoding to check.)
    const bool acpIsUtf8 = GetACP() == CP_UTF8;
    const uint8_t ansi[] = { 'c', 'a', 'f', 0xE9 };
    wchar_t expected[8] = {};
    int got = MultiByteToWideChar(CP_ACP, 0, reinterpret_cast<const char*>(ansi), 4, expected, 8);
    REQUIRE(got > 0);
    std::wstring decoded = DecodeTextBytes(ansi, sizeof(ansi));
    CHECK_EQ(decoded, std::wstring(expected, static_cast<size_t>(got)));
    if (!acpIsUtf8) CHECK(decoded.find(static_cast<wchar_t>(0xFFFD)) == std::wstring::npos);

    // Real UTF-8 still decodes as UTF-8.
    const uint8_t utf8[] = { 'c', 'a', 'f', 0xC3, 0xA9 };
    CHECK_EQ(DecodeTextBytes(utf8, sizeof(utf8)), std::wstring(L"caf\x00E9"));

    // A capped read that cuts a UTF-8 character in half is still UTF-8.
    const uint8_t cut[] = { 0xC3, 0xA9, 'x', 0xE2, 0x82 };
    std::wstring cutText = DecodeTextBytes(cut, sizeof(cut), true);
    CHECK(cutText.rfind(L"\x00E9x", 0) == 0);
    // The same bytes from a whole file are not valid UTF-8.
    std::wstring wholeText = DecodeTextBytes(cut, sizeof(cut), false);
    if (!acpIsUtf8) CHECK(wholeText.rfind(L"\x00E9x", 0) != 0);

    // UTF-16 LE at an odd address (I15).
    std::vector<uint8_t> buffer = { 0x00, 0xFF, 0xFE, 'A', 0x00, 'B', 0x00, 0x3A, 0x26 };
    CHECK_EQ(DecodeTextBytes(buffer.data() + 1, buffer.size() - 1), std::wstring(L"AB\x263A"));
}

// ---------------------------------------------------------------------------
// H: scoring INI with a BOM, deleted INI restores defaults
// ---------------------------------------------------------------------------
TEST(FixEngine_ScoringIniEncodingsAndReset)
{
    const std::string body = "[entropy_thresholds]\nlevel1_score=0.9\n\n[revocation]\nrevoked=4\n";

    std::wstring bomPath = tf::TestDir() + L"bom.ini";
    std::string withBom = "\xEF\xBB\xBF" + body;
    REQUIRE(WriteBinaryFile(bomPath, withBom.data(), withBom.size()));
    ScoringConfig a;
    REQUIRE(a.LoadFromFile(bomPath));
    CHECK(std::fabs(a.entropy.level1_score - 0.9) < 1e-9);   // the first section counts
    CHECK(std::fabs(a.revocation.revoked - 4.0) < 1e-9);

    std::wstring utf16Path = tf::TestDir() + L"utf16.ini";
    std::vector<uint8_t> utf16 = { 0xFF, 0xFE };
    for (char c : body) {
        utf16.push_back(static_cast<uint8_t>(c));
        utf16.push_back(0);
    }
    REQUIRE(WriteBytes(utf16Path, utf16));
    ScoringConfig b;
    REQUIRE(b.LoadFromFile(utf16Path));
    CHECK(std::fabs(b.entropy.level1_score - 0.9) < 1e-9);
    CHECK(std::fabs(b.revocation.revoked - 4.0) < 1e-9);

    // ReloadScoringConfig always starts from defaults, so values from an INI that has
    // since been deleted do not survive. Expected = defaults, or the INI next to the exe
    // when one is there.
    ScoringConfig& global = GetScoringConfig();
    global.weights.unsigned_penalty = 9.5;
    global.SetAPIWeight("FixTestApi", 0.7);
    ReloadScoringConfig();
    ScoringConfig expected;
    std::wstring ini = AppFilePath(L"phantom_recon_scoring.ini");
    if (FileExists(ini)) expected.LoadFromFile(ini);
    CHECK(global.weights.unsigned_penalty == expected.weights.unsigned_penalty);
    CHECK(global.GetAPIWeight("FixTestApi") == expected.GetAPIWeight("FixTestApi"));
}

// ---------------------------------------------------------------------------
// H: baseline time in local time, failed load leaves the object alone
// ---------------------------------------------------------------------------
TEST(FixEngine_BaselineTimeIsLocal)
{
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER li;
    li.LowPart = now.dwLowDateTime;
    li.HighPart = now.dwHighDateTime;
    Baseline b;
    b.SetCreationTime(li.QuadPart);

    FILETIME localFt;
    REQUIRE(FileTimeToLocalFileTime(&now, &localFt));
    SYSTEMTIME st;
    REQUIRE(FileTimeToSystemTime(&localFt, &st));
    wchar_t buf[64];
    swprintf_s(buf, L"%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    CHECK_EQ(b.GetCreationTimeString(), std::wstring(buf));
    CHECK_EQ(Baseline().GetCreationTimeString(), std::wstring(L"Unknown"));
}

static bool WriteWithCount(const std::wstring& from, const std::wstring& to, uint64_t count)
{
    std::vector<uint8_t> bytes;
    if (!ReadBinaryFile(from, bytes) || bytes.size() < 40) return false;
    memcpy(bytes.data() + 8, &count, sizeof(count));
    std::wstring md5 = ComputeBufferMD5Hex(bytes.data(), bytes.size() - 16);
    if (!HexToBytes(md5, bytes.data() + bytes.size() - 16, 16)) return false;
    return WriteBytes(to, bytes);
}

TEST(FixEngine_FailedLoadKeepsBaseline)
{
    Baseline good;
    good.AddEntry(FixEntry(L"C:\\Keep\\a.exe"));
    good.SetCreationTime(132000000000000000ULL);
    std::wstring goodPath = tf::TestDir() + L"good.prbl";
    REQUIRE(good.SaveToFile(goodPath));

    Baseline other;
    other.AddEntry(FixEntry(L"C:\\Other\\b.exe"));
    other.AddEntry(FixEntry(L"C:\\Other\\c.exe"));
    other.SetCreationTime(133000000000000000ULL);
    std::wstring otherPath = tf::TestDir() + L"other.prbl";
    REQUIRE(other.SaveToFile(otherPath));

    // Valid checksum, but the header promises more entries than the file holds.
    std::wstring shortPath = tf::TestDir() + L"promises5.prbl";
    REQUIRE(WriteWithCount(otherPath, shortPath, 5));
    // And an implausible entry count.
    std::wstring hugePath = tf::TestDir() + L"promises60m.prbl";
    REQUIRE(WriteWithCount(otherPath, hugePath, 60000000ULL));

    for (const std::wstring& bad : { shortPath, hugePath }) {
        Baseline target;
        REQUIRE(target.LoadFromFile(goodPath));
        CHECK(!target.LoadFromFile(bad));
        CHECK_EQ(target.Count(), static_cast<size_t>(1));
        CHECK(target.FindEntry(L"C:\\Keep\\a.exe") != nullptr);
        CHECK(target.FindEntry(L"C:\\Other\\b.exe") == nullptr);
        CHECK_EQ(target.GetCreationTime(), 132000000000000000ULL);
        CHECK_EQ(target.LoadedVersion(), Baseline::BASELINE_VERSION);
        CHECK(target.CoversFolderOf(L"C:\\Keep\\x.exe"));
    }

    // Control: the unmodified file replaces it completely.
    Baseline target;
    REQUIRE(target.LoadFromFile(goodPath));
    REQUIRE(target.LoadFromFile(otherPath));
    CHECK_EQ(target.Count(), static_cast<size_t>(2));
    CHECK(target.FindEntry(L"C:\\Keep\\a.exe") == nullptr);
    CHECK(!target.CoversFolderOf(L"C:\\Keep\\x.exe"));
    CHECK_EQ(target.GetCreationTime(), 133000000000000000ULL);
}

// ---------------------------------------------------------------------------
// H: fuzzy hash block size and tail rules match ssdeep's fuzzy.c
// ---------------------------------------------------------------------------
namespace fuzzyref {

// A direct port of the digest logic of ssdeep's fuzzy.c (2.13+): all block sizes in one
// pass, forked lazily, digest chosen by walking down from the size guess. Written in
// that structure on purpose so it checks the product's retry-per-block-size code.
static const char* kB64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const uint32_t kInit = 0x28021967;
static const uint32_t kPrime = 0x01000193;
static const int kNum = 31;

struct BlockHash {
    uint32_t h = 0;
    uint32_t halfh = 0;
    char     digest[64] = {};
    uint32_t dindex = 0;
};

struct Result {
    std::wstring hash;
    bool         zeroTailSlot = false;   // roll sum 0 at the end and a stored slot was used
};

static uint32_t BlockSize(int i) { return 3u << i; }

static Result Digest(const uint8_t* data, size_t size)
{
    BlockHash bh[kNum];
    int bhend = 1;
    bh[0].h = kInit;
    bh[0].halfh = kInit;
    uint8_t window[7] = {};
    uint32_t r1 = 0, r2 = 0, r3 = 0, rn = 0;

    for (size_t k = 0; k < size; ++k) {
        uint8_t c = data[k];
        r2 -= r1;
        r2 += 7 * static_cast<uint32_t>(c);
        r1 += c;
        r1 -= window[rn];
        window[rn] = c;
        rn = (rn + 1) % 7;
        r3 <<= 5;
        r3 ^= c;
        uint32_t h = r1 + r2 + r3;

        for (int i = 0; i < bhend; ++i) {
            bh[i].h = (bh[i].h * kPrime) ^ c;
            bh[i].halfh = (bh[i].halfh * kPrime) ^ c;
        }
        for (int i = 0; i < bhend; ++i) {
            if (h % BlockSize(i) != BlockSize(i) - 1) break;
            if (bh[i].dindex == 0 && bhend < kNum) {
                BlockHash& n = bh[bhend];
                n.h = bh[bhend - 1].h;
                n.halfh = bh[bhend - 1].halfh;
                n.digest[0] = 0;
                n.dindex = 0;
                ++bhend;
            }
            bh[i].digest[bh[i].dindex] = kB64[bh[i].h % 64];
            if (bh[i].dindex < 63) {
                ++bh[i].dindex;
                bh[i].digest[bh[i].dindex] = 0;
                bh[i].h = kInit;
                if (bh[i].dindex < 32) bh[i].halfh = kInit;
            }
        }
    }

    uint32_t h = r1 + r2 + r3;
    int bi = 0;
    while (static_cast<uint64_t>(BlockSize(bi)) * 64 < size && bi < kNum - 1) ++bi;
    while (bi >= bhend) --bi;
    while (bi > 0 && bh[bi].dindex < 32) --bi;

    Result res;
    std::string out = std::to_string(BlockSize(bi)) + ":";
    out.append(bh[bi].digest, bh[bi].dindex);
    if (h != 0) out += kB64[bh[bi].h % 64];
    else if (bh[bi].digest[bh[bi].dindex] != 0) {
        out += bh[bi].digest[bh[bi].dindex];
        res.zeroTailSlot = true;
    }
    out += ":";
    if (bi < bhend - 1) {
        ++bi;
        uint32_t i = bh[bi].dindex;
        if (i > 31) i = 31;
        out.append(bh[bi].digest, i);
        if (h != 0) out += kB64[bh[bi].halfh % 64];
        else if (bh[bi].digest[i] != 0) {
            out += bh[bi].digest[i];
            res.zeroTailSlot = true;
        }
    }
    else if (h != 0) {
        out += kB64[bh[bi].h % 64];
    }
    res.hash = std::wstring(out.begin(), out.end());
    return res;
}

// The block size the code before the fix picked: it counted the tail character when
// deciding whether to halve. Kept here only to prove the corpus reaches that edge.
static uint32_t OldBlockSize(const uint8_t* data, size_t size)
{
    uint32_t blockSize = 3;
    while (static_cast<uint64_t>(blockSize) * 64 < size) blockSize *= 2;
    while (true) {
        uint32_t r1 = 0, r2 = 0, r3 = 0, rn = 0;
        uint8_t window[7] = {};
        size_t sig1 = 0;
        for (size_t k = 0; k < size; ++k) {
            uint8_t c = data[k];
            r2 -= r1;
            r2 += 7 * static_cast<uint32_t>(c);
            r1 += c;
            r1 -= window[rn];
            window[rn] = c;
            rn = (rn + 1) % 7;
            r3 <<= 5;
            r3 ^= c;
            uint32_t r = r1 + r2 + r3;
            if (r % blockSize == blockSize - 1 && sig1 < 63) ++sig1;
        }
        if (r1 + r2 + r3 != 0) ++sig1;
        if (blockSize > 3 && sig1 < 32) {
            blockSize /= 2;
            continue;
        }
        return blockSize;
    }
}

} // namespace fuzzyref

TEST(FixEngine_FuzzyHashMatchesSsdeepRules)
{
    int compared = 0, mismatches = 0, blockSizeEdges = 0, zeroTailSlots = 0;
    uint32_t seed = 0x1234567u;
    for (int k = 0; k < 700; ++k) {
        seed = seed * 1103515245u + 12345u;
        size_t size = 64 + (seed >> 8) % 24000;
        std::vector<uint8_t> data = Pattern(size, seed | 1u);
        if (k % 4 == 1) {
            for (uint8_t& b : data) b = static_cast<uint8_t>('a' + (b % 7));   // low-entropy text
        }
        if (k % 3 == 0) data.insert(data.end(), 32, 0);   // ends with a zero rolling hash

        std::wstring product = ComputeFuzzyHashBuffer(data.data(), data.size());
        fuzzyref::Result ref = fuzzyref::Digest(data.data(), data.size());
        ++compared;
        if (product != ref.hash) {
            if (mismatches < 3) {
                std::printf("    fuzzy mismatch size %zu: product %s, reference %s\n", data.size(),
                    tf::Narrow(product).c_str(), tf::Narrow(ref.hash).c_str());
            }
            ++mismatches;
        }
        uint32_t refBlockSize = static_cast<uint32_t>(_wtoi(ref.hash.c_str()));
        if (fuzzyref::OldBlockSize(data.data(), data.size()) != refBlockSize) ++blockSizeEdges;
        if (ref.zeroTailSlot) ++zeroTailSlots;
    }
    std::printf("    fuzzy corpus: %d compared, %d block-size edges, %d zero-tail slots\n",
        compared, blockSizeEdges, zeroTailSlots);
    CHECK_EQ(mismatches, 0);
    // The corpus must reach both rules that changed, or this test proves nothing.
    CHECK(blockSizeEdges > 0);
    CHECK(zeroTailSlots > 0);

    // Hand-checked shape: identical input gives an identical, well-formed hash.
    std::vector<uint8_t> text(5000);
    for (size_t i = 0; i < text.size(); ++i) text[i] = static_cast<uint8_t>("phantom recon "[i % 14]);
    std::wstring h1 = ComputeFuzzyHashBuffer(text.data(), text.size());
    CHECK_EQ(h1, fuzzyref::Digest(text.data(), text.size()).hash);
    CHECK_EQ(CompareFuzzyHashes(h1, h1), 100);
}
