// Baseline file format, comparison, the scan engine on the sample pack, CSV and the results model.

#include "TestFramework.h"

#include "AppPaths.h"
#include "Baseline.h"
#include "FileIO.h"
#include "ResultsModel.h"
#include "SampleData.h"
#include "ScanCore.h"
#include "ScanCsv.h"

#include <atomic>
#include <map>

static BaselineEntry MakeEntry(const std::wstring& path, const std::wstring& md5)
{
    BaselineEntry e;
    e.path = path;
    e.fileSize = 1234;
    e.md5 = md5;
    e.sha256 = std::wstring(64, md5.empty() ? L'0' : md5[0]);
    e.signature = L"Unsigned";
    e.signatureType = L"None";
    e.version = L"1.0.0.0";
    e.developer = L"Example, Inc.";
    e.readOnly = L"No";
    e.hidden = L"No";
    e.permissions = L"Owner: BUILTIN\\Administrators";
    e.entropy = 5.25;
    e.malwareScore = 2.5;
    e.packingStatus = L"Not packed";
    return e;
}

static void FillV3(BaselineEntry& e)
{
    e.catalogSigner = L"Microsoft Windows";
    e.revocation = L"Not checked";
    e.imphash = L"0123456789abcdef0123456789abcdef";
    e.ssdeep = L"3:abc:def";
    e.zoneId = 3;
    e.zoneHostUrl = L"https://example.invalid/a.exe";
    e.altStreams = L"notes.txt (12)";
    e.peTimestamp = 0x65000000;
    e.peAnomalies = L"TLS_CALLBACKS: 1 callback(s) run before the entry point";
    e.overlaySize = 4096;
    e.overlayEntropy = 7.5;
    e.tlsCallbacks = 1;
    e.pdbPath = L"C:\\build\\x.pdb";
    e.scriptScore = 1.5;
    e.attackIds = L"T1553.005, T1564.004";
    e.knownGood = true;
}

TEST(Baseline_RoundTripEveryVersion)
{
    Baseline b;
    BaselineEntry a = MakeEntry(L"C:\\Apps\\a.exe", L"aaaa");
    FillV3(a);
    b.AddEntry(a);
    b.AddEntry(MakeEntry(L"C:\\Apps\\b, with comma.exe", L"bbbb"));
    b.SetCreationTime(132000000000000000ULL);

    for (uint32_t version : { 1u, 2u, 3u }) {
        std::wstring path = tf::TestDir() + L"v" + std::to_wstring(version) + L".prbl";
        REQUIRE(b.SaveToFile(path, version));
        Baseline loaded;
        REQUIRE(loaded.LoadFromFile(path));
        CHECK_EQ(loaded.LoadedVersion(), version);
        CHECK_EQ(loaded.Count(), static_cast<size_t>(2));
        CHECK_EQ(loaded.GetCreationTime(), 132000000000000000ULL);
        const BaselineEntry* e = loaded.FindEntry(L"c:\\apps\\A.EXE");   // lookups ignore case
        REQUIRE(e != nullptr);
        CHECK_EQ(e->md5, std::wstring(L"aaaa"));
        CHECK_EQ(e->fileSize, static_cast<int64_t>(1234));
        CHECK(e->entropy > 5.24 && e->entropy < 5.26);
        CHECK_EQ(e->developer, std::wstring(L"Example, Inc."));
        if (version >= 2) CHECK_EQ(e->sha256, a.sha256);
        if (version >= 3) {
            CHECK_EQ(e->imphash, a.imphash);
            CHECK_EQ(e->ssdeep, a.ssdeep);
            CHECK_EQ(e->zoneId, 3);
            CHECK_EQ(e->zoneHostUrl, a.zoneHostUrl);
            CHECK_EQ(e->altStreams, a.altStreams);
            CHECK_EQ(e->peTimestamp, a.peTimestamp);
            CHECK_EQ(e->tlsCallbacks, 1);
            CHECK_EQ(e->attackIds, a.attackIds);
            CHECK(e->knownGood);
        }
        else {
            CHECK(e->imphash.empty());
            CHECK_EQ(e->zoneId, -1);
        }
    }
}

TEST(Baseline_TamperIsDetected)
{
    Baseline b;
    b.AddEntry(MakeEntry(L"C:\\Apps\\a.exe", L"aaaa"));
    std::wstring path = tf::TestDir() + L"t.prbl";
    REQUIRE(b.SaveToFile(path));

    std::vector<uint8_t> bytes;
    REQUIRE(ReadBinaryFile(path, bytes));
    REQUIRE(bytes.size() > 64);

    std::vector<uint8_t> flipped = bytes;
    flipped[bytes.size() / 2] ^= 0x01;
    std::wstring bad = tf::TestDir() + L"flipped.prbl";
    REQUIRE(WriteBinaryFile(bad, flipped.data(), flipped.size()));
    Baseline x;
    CHECK(!x.LoadFromFile(bad));

    std::vector<uint8_t> cut(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(bytes.size() - 5));
    std::wstring shortPath = tf::TestDir() + L"short.prbl";
    REQUIRE(WriteBinaryFile(shortPath, cut.data(), cut.size()));
    Baseline y;
    CHECK(!y.LoadFromFile(shortPath));

    std::vector<uint8_t> magic = bytes;
    magic[0] = 'X';
    std::wstring magicPath = tf::TestDir() + L"magic.prbl";
    REQUIRE(WriteBinaryFile(magicPath, magic.data(), magic.size()));
    Baseline z;
    CHECK(!z.LoadFromFile(magicPath));

    Baseline ok;
    CHECK(ok.LoadFromFile(path));
    CHECK(!ok.LoadFromFile(tf::TestDir() + L"missing.prbl"));
}

TEST(Baseline_CompareStatuses)
{
    Baseline b;
    BaselineEntry same = MakeEntry(L"C:\\a\\same.exe", L"1111");
    BaselineEntry edited = MakeEntry(L"C:\\a\\edited.exe", L"2222");
    BaselineEntry ms = MakeEntry(L"C:\\a\\msupdate.dll", L"3333");
    ms.signature = L"Signed (Valid) (Microsoft Windows)";
    ms.signatureType = L"Embedded";
    BaselineEntry relabel = MakeEntry(L"C:\\a\\relabel.dll", L"4444");   // a v2-era "Unsigned" catalog file
    b.AddEntry(same);
    b.AddEntry(edited);
    b.AddEntry(ms);
    b.AddEntry(relabel);

    CHECK(b.CompareEntry(same).status == BaselineStatus::Match);

    BaselineEntry editedNow = edited;
    editedNow.md5 = L"2223";
    editedNow.sha256 = std::wstring(64, L'9');
    editedNow.malwareScore = 4.0;
    ComparisonResult c = b.CompareEntry(editedNow);
    CHECK(c.status == BaselineStatus::Changed);
    CHECK(c.changeDetails.find(L"MD5 changed") != std::wstring::npos);
    CHECK(c.riskDelta > 1.49 && c.riskDelta < 1.51);

    BaselineEntry msNow = ms;
    msNow.md5 = L"3334";
    msNow.sha256 = std::wstring(64, L'8');
    msNow.version = L"1.0.0.1";
    CHECK(b.CompareEntry(msNow).status == BaselineStatus::Updated);

    BaselineEntry fresh = MakeEntry(L"C:\\a\\fresh.exe", L"5555");
    CHECK(b.CompareEntry(fresh).status == BaselineStatus::New);
    fresh.knownGood = true;
    CHECK(b.CompareEntry(fresh).status == BaselineStatus::Known);
    BaselineEntry freshMs = MakeEntry(L"C:\\a\\fresh2.dll", L"6666");
    freshMs.signature = L"Signed (Valid) (Microsoft Corporation)";
    CHECK(b.CompareEntry(freshMs).status == BaselineStatus::Known);
    BaselineEntry fakeMs = MakeEntry(L"C:\\a\\fresh3.dll", L"7777");
    fakeMs.signature = L"Signed (HASH MISMATCH) (Microsoft Corporation)";
    CHECK(b.CompareEntry(fakeMs).status == BaselineStatus::New);

    BaselineEntry relabelNow = relabel;
    relabelNow.signature = L"Signed (Valid)";
    relabelNow.signatureType = L"Catalog";
    CHECK(b.CompareEntry(relabelNow).status == BaselineStatus::Match);

    BaselineEntry permissions = same;
    permissions.permissions = L"Owner: Everyone";
    CHECK(b.CompareEntry(permissions).status == BaselineStatus::Changed);
}

TEST(Baseline_FoldersAndUnicodeCase)
{
    Baseline b;
    b.AddEntry(MakeEntry(L"C:\\Program Files\\Tool\\tool.exe", L"1"));
    b.AddEntry(MakeEntry(L"C:\\Users\\\x00C9MILE\\App\\app.exe", L"2"));   // capital E with acute accent

    CHECK(b.CoversFolderOf(L"c:\\program files\\tool\\other.dll"));
    CHECK(!b.CoversFolderOf(L"C:\\Program Files\\Elsewhere\\x.exe"));
    CHECK(!b.CoversFolderOf(L"C:\\Program Files\\Tool\\sub\\x.exe"));   // the folder itself, not below it

    // Lookups ignore case for accented letters too, as the file system does.
    CHECK(b.FindEntry(L"c:\\users\\\x00E9mile\\app\\APP.EXE") != nullptr);
    CHECK(b.CoversFolderOf(L"C:\\USERS\\\x00E9MILE\\APP\\new.exe"));

    // The folder index survives a save and load.
    std::wstring path = tf::TestDir() + L"folders.prbl";
    REQUIRE(b.SaveToFile(path));
    Baseline loaded;
    REQUIRE(loaded.LoadFromFile(path));
    CHECK(loaded.CoversFolderOf(L"C:\\Program Files\\Tool\\x.exe"));
    loaded.Clear();
    CHECK(!loaded.CoversFolderOf(L"C:\\Program Files\\Tool\\x.exe"));
}

TEST(Baseline_DiffTwoBaselines)
{
    Baseline older, newer;
    older.AddEntry(MakeEntry(L"C:\\a\\kept.exe", L"1"));
    older.AddEntry(MakeEntry(L"C:\\a\\gone.exe", L"2"));
    older.AddEntry(MakeEntry(L"C:\\a\\changed.exe", L"3"));
    newer.AddEntry(MakeEntry(L"C:\\a\\kept.exe", L"1"));
    newer.AddEntry(MakeEntry(L"C:\\a\\changed.exe", L"4"));
    newer.AddEntry(MakeEntry(L"C:\\a\\added.exe", L"5"));

    std::map<std::wstring, std::wstring> status;
    for (const ScanRow& r : DiffBaselines(older, newer, false)) status[FileNameOf(r.entry.path)] = r.status;
    CHECK_EQ(status.size(), static_cast<size_t>(3));
    CHECK_EQ(status[L"gone.exe"], std::wstring(L"MISSING"));
    CHECK_EQ(status[L"changed.exe"], std::wstring(L"CHANGED"));
    CHECK_EQ(status[L"added.exe"], std::wstring(L"NEW"));
    CHECK(status.find(L"kept.exe") == status.end());

    CHECK_EQ(DiffBaselines(older, newer, true).size(), static_cast<size_t>(4));
}

// The sample pack is the end-to-end fixture: a real folder, a real baseline,
// a real scan, with known answers.
TEST(Scan_SamplePackEveryStatus)
{
    std::wstring folder = tf::TestDir() + L"pack";
    SamplePackResult pack = CreateSamplePack(folder);
    REQUIRE(pack.ok);
    REQUIRE(FileExists(pack.baselinePath));

    Baseline baseline;
    REQUIRE(baseline.LoadFromFile(pack.baselinePath));
    CHECK_EQ(baseline.Count(), static_cast<size_t>(7));   // 6 programs + the script, before the changes

    ScanOptions options;
    options.revocation = RevocationMode::Off;
    std::wstring csv = tf::TestDir() + L"scan.csv";
    std::vector<ScanRow> rows;
    int totalSeen = -1;
    int filesSeen = 0;
    ScanCallbacks cb;
    cb.onRow = [&](const ScanRow& r) { rows.push_back(r); };
    cb.onTotal = [&](int t) { totalSeen = t; };
    cb.onFile = [&](const std::wstring&, const std::wstring&, bool) { ++filesSeen; };
    ScanSummary s = RunScan(ScanMode::FullScan, pack.folder, csv, &baseline, L"", options, cb);

    CHECK(!s.cancelled);
    CHECK(!s.csvFailed);
    CHECK_EQ(s.added, 1);
    CHECK_EQ(s.changed, 1);
    CHECK_EQ(s.missing, 1);
    CHECK_EQ(s.match, 5);
    CHECK_EQ(totalSeen, s.totalFiles);
    CHECK_EQ(filesSeen, s.filesProcessed);

    std::map<std::wstring, ScanRow> byName;
    for (const ScanRow& r : rows) byName[FileNameOf(r.entry.path)] = r;
    CHECK_EQ(byName[L"plain_tool.exe"].status, std::wstring(L"MATCH"));
    CHECK_EQ(byName[L"will_change.exe"].status, std::wstring(L"CHANGED"));
    CHECK_EQ(byName[L"will_be_removed.exe"].status, std::wstring(L"MISSING"));
    CHECK_EQ(byName[L"appeared_later.exe"].status, std::wstring(L"NEW"));

    const BaselineEntry& odd = byName[L"odd_headers.exe"].entry;
    CHECK(odd.peAnomalies.find(L"TIMESTAMP_FUTURE") != std::wstring::npos);
    CHECK(odd.peAnomalies.find(L"CHECKSUM_MISMATCH") != std::wstring::npos);
    CHECK_EQ(odd.tlsCallbacks, 1);
    CHECK(odd.rwxSections >= 1);
    CHECK(odd.malwareScore > byName[L"plain_tool.exe"].entry.malwareScore);

    const BaselineEntry& dl = byName[L"downloaded_tool.exe"].entry;
    CHECK_EQ(dl.zoneId, 3);
    CHECK(dl.originWarnings.find(L"MOTW_INTERNET") != std::wstring::npos);

    const BaselineEntry& carrier = byName[L"has_extra_stream.exe"].entry;
    CHECK(carrier.altStreams.find(L"notes.txt") != std::wstring::npos);

    const BaselineEntry& script = byName[L"sample_script.ps1"].entry;
    CHECK(script.scriptIndicators.find(L"DOWNLOAD_CRADLE") != std::wstring::npos);
    CHECK(script.scriptScore > 0.0);

    for (const ScanRow& r : rows) {
        CHECK_EQ(r.entry.sha256.size(), static_cast<size_t>(64));
        CHECK(r.entry.malwareScore >= 0.0 && r.entry.malwareScore <= 10.0);
    }

    // The CSV holds the same rows.
    std::vector<ScanRow> loaded;
    REQUIRE(LoadRowsFromCsv(csv, loaded));
    CHECK_EQ(loaded.size(), rows.size());
}

TEST(Scan_ExclusionsAndCancel)
{
    std::wstring folder = tf::TestDir() + L"pack";
    SamplePackResult pack = CreateSamplePack(folder);
    REQUIRE(pack.ok);

    ScanOptions options;
    options.revocation = RevocationMode::Off;
    ParseExclusions(L"*.ps1;odd_headers.exe;" + pack.folder + L"\\plain_tool.exe", options);
    CHECK(IsExcluded(pack.folder + L"\\x.PS1", false, options));
    CHECK(!IsExcluded(pack.folder + L"\\x.PS1", true, options));   // extensions never exclude folders
    CHECK(IsExcluded(L"C:\\anything\\odd_headers.exe\\inner.exe", false, options));

    // Baseline scan with exclusions: excluded files never enter the baseline.
    std::wstring basePath = tf::TestDir() + L"excluded.prbl";
    ScanCallbacks none;
    ScanSummary s = RunScan(ScanMode::Baseline, pack.folder, L"", nullptr, basePath, options, none);
    REQUIRE(s.baselineSaved);
    Baseline b;
    REQUIRE(b.LoadFromFile(basePath));
    CHECK(b.FindEntry(pack.folder + L"\\sample_script.ps1") == nullptr);
    CHECK(b.FindEntry(pack.folder + L"\\plain_tool.exe") == nullptr);
    CHECK(b.FindEntry(pack.folder + L"\\appeared_later.exe") != nullptr);

    // Cancel after the first file: no baseline is written, the old file stays.
    std::wstring keepPath = tf::TestDir() + L"keep.prbl";
    REQUIRE(WriteUtf8File(keepPath, L"old", false));
    std::atomic<int> files{0};
    ScanCallbacks cancel;
    cancel.onFile = [&](const std::wstring&, const std::wstring&, bool) { ++files; };
    cancel.isCancelled = [&]() { return files.load() >= 1; };
    ScanOptions plain;
    plain.revocation = RevocationMode::Off;
    ScanSummary c = RunScan(ScanMode::Baseline, pack.folder, L"", nullptr, keepPath, plain, cancel);
    CHECK(c.cancelled);
    CHECK(!c.baselineSaved);
    std::wstring text;
    REQUIRE(ReadTextFile(keepPath, text));
    CHECK_EQ(text, std::wstring(L"old"));

    // A cancelled comparison never reports MISSING (it did not look everywhere).
    Baseline demo;
    REQUIRE(demo.LoadFromFile(pack.baselinePath));
    files = 0;
    ScanSummary cc = RunScan(ScanMode::FullScan, pack.folder, L"", &demo, L"", plain, cancel);
    CHECK(cc.cancelled);
    CHECK_EQ(cc.missing, 0);
}

TEST(Scan_SeveralRootsAndMissingScope)
{
    std::wstring a = tf::TestDir() + L"pack";
    std::wstring b = tf::TestDir() + L"pack2";   // shares a prefix with "pack" on purpose
    REQUIRE(CreateSamplePack(a).ok);
    REQUIRE(EnsureDirectory(b));
    std::vector<uint8_t> image = BuildSamplePe(SamplePeSpec());
    std::wstring extra = b + L"\\other_tool.exe";
    REQUIRE(WriteBinaryFile(extra, image.data(), image.size()));

    ScanOptions options;
    options.revocation = RevocationMode::Off;
    ScanCallbacks none;
    std::wstring basePath = tf::TestDir() + L"two.prbl";
    ScanSummary s = RunScan(ScanMode::Baseline, std::vector<std::wstring>{ a, b }, L"", nullptr, basePath, options, none);
    REQUIRE(s.baselineSaved);
    CHECK_EQ(s.baselineEntries, static_cast<size_t>(8));   // 7 in the pack after its changes, 1 in pack2
    CHECK(s.root.find(L"pack2") != std::wstring::npos);

    REQUIRE(DeleteFileW(extra.c_str()));
    Baseline base;
    REQUIRE(base.LoadFromFile(basePath));

    // Scanning only the pack: the file gone from pack2 is outside the scan, so not MISSING.
    ScanSummary onlyA = RunScan(ScanMode::FullScan, a, L"", &base, L"", options, none);
    CHECK_EQ(onlyA.missing, 0);
    CHECK_EQ(onlyA.added, 0);
    CHECK_EQ(onlyA.changed, 0);
    CHECK_EQ(onlyA.match, 7);

    // Scanning both: now it is MISSING.
    ScanSummary both = RunScan(ScanMode::FullScan, std::vector<std::wstring>{ a, b }, L"", &base, L"", options, none);
    CHECK_EQ(both.missing, 1);
    CHECK_EQ(both.match, 7);

    std::vector<std::wstring> roots = SplitScanRoots(L" C:\\A\\ ; D:\\B;;c:\\a;E:\\ ");
    REQUIRE(roots.size() == 3);
    CHECK_EQ(roots[0], std::wstring(L"C:\\A"));
    CHECK_EQ(roots[1], std::wstring(L"D:\\B"));
    CHECK_EQ(roots[2], std::wstring(L"E:\\"));   // a drive root keeps its backslash
    CHECK(SplitScanRoots(L" ; ").empty());
}

TEST(Csv_RoundTripAwkwardText)
{
    ScanRow r;
    r.entry = MakeEntry(L"C:\\Odd \"quoted\", folder\\tool.exe", L"abcd");
    FillV3(r.entry);
    r.entry.signature = L"Signed (Valid) (Example, \"Quotes\" Ltd)";
    r.entry.sigWarnings = L"LINE\r\nBREAK: kept on one line";
    r.entry.developer = L"\x00c9diteur \x65e5\x672c";   // non-English text survives UTF-8
    r.status = L"CHANGED";
    r.changeDetails = L"MD5 changed; Size changed (1 -> 2)";
    r.riskDelta = -1.5;

    std::wstring path = tf::TestDir() + L"rows.csv";
    REQUIRE(ExportRowsToCsv(path, { r }));

    std::vector<uint8_t> raw;
    REQUIRE(ReadBinaryFile(path, raw));
    REQUIRE(raw.size() > 3);
    CHECK(raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF);   // BOM for Excel

    std::vector<ScanRow> back;
    REQUIRE(LoadRowsFromCsv(path, back));
    REQUIRE(back.size() == 1);
    const ScanRow& b = back[0];
    CHECK_EQ(b.entry.path, r.entry.path);
    CHECK_EQ(b.entry.signature, r.entry.signature);
    CHECK_EQ(b.entry.developer, r.entry.developer);
    CHECK_EQ(b.entry.sigWarnings, std::wstring(L"LINE  BREAK: kept on one line"));
    CHECK_EQ(b.entry.imphash, r.entry.imphash);
    CHECK_EQ(b.entry.zoneId, 3);
    CHECK_EQ(b.entry.attackIds, r.entry.attackIds);
    CHECK(b.entry.knownGood);
    CHECK_EQ(b.status, std::wstring(L"CHANGED"));
    CHECK_EQ(b.changeDetails, r.changeDetails);
    CHECK(b.riskDelta < -1.49 && b.riskDelta > -1.51);
    CHECK(b.entry.malwareScore > 2.49 && b.entry.malwareScore < 2.51);

    // An old 22-column CSV with no status column loads as LOADED.
    std::wstring old = tf::TestDir() + L"old.csv";
    REQUIRE(WriteUtf8File(old, L"Path,File Size,MD5\r\nC:\\x.exe,10,ab\r\n", false));
    std::vector<ScanRow> legacy;
    REQUIRE(LoadRowsFromCsv(old, legacy));
    REQUIRE(legacy.size() == 1);
    CHECK_EQ(legacy[0].status, std::wstring(L"LOADED"));
    CHECK_EQ(legacy[0].entry.fileSize, static_cast<int64_t>(10));

    std::vector<std::wstring> f = ParseCsvLine(L"a,\"b,c\",\"d\"\"e\",");
    REQUIRE(f.size() == 4);
    CHECK_EQ(f[1], std::wstring(L"b,c"));
    CHECK_EQ(f[2], std::wstring(L"d\"e"));
    CHECK_EQ(f[3], std::wstring(L""));
}

TEST(ResultsModel_FilterSearchSort)
{
    auto row = [](const wchar_t* path, const wchar_t* status, double score, int64_t size) {
        ScanRow r;
        r.entry.path = path;
        r.entry.malwareScore = score;
        r.entry.fileSize = size;
        r.entry.signature = L"Unsigned";
        r.entry.version = L"1.0";
        r.status = status;
        return r;
    };
    ResultsModel m;
    m.SetRows({
        row(L"C:\\a\\zeta.exe", L"MATCH", 1.0, 300),
        row(L"C:\\a\\alpha.exe", L"NEW", 8.0, 100),
        row(L"C:\\b\\Beta.dll", L"CHANGED", 4.5, 200),
        row(L"C:\\b\\gamma.exe", L"MISSING", 0.5, 50),
    });
    CHECK_EQ(m.ViewCount(), static_cast<size_t>(4));

    m.SetFilter(StatusFilter::NeedsReview);
    CHECK_EQ(m.ViewCount(), static_cast<size_t>(3));
    m.SetFilter(StatusFilter::HighScore);
    CHECK_EQ(m.ViewCount(), static_cast<size_t>(1));
    CHECK_EQ(m.CellText(0, ResultColumn::File), std::wstring(L"alpha.exe"));
    m.SetFilter(StatusFilter::MediumScore);
    CHECK_EQ(m.ViewCount(), static_cast<size_t>(2));
    m.SetFilter(StatusFilter::All);

    m.SetSearch(L"  BETA ");
    CHECK_EQ(m.ViewCount(), static_cast<size_t>(1));
    m.SetSearch(L"c:\\b\\");
    CHECK_EQ(m.ViewCount(), static_cast<size_t>(2));
    m.SetSearch(L"");

    m.SortBy(ResultColumn::Score);   // first click on Score: highest first
    CHECK_EQ(m.CellText(0, ResultColumn::File), std::wstring(L"alpha.exe"));
    CHECK_EQ(m.CellText(3, ResultColumn::File), std::wstring(L"gamma.exe"));
    m.SortBy(ResultColumn::Score);   // second click reverses
    CHECK_EQ(m.CellText(0, ResultColumn::File), std::wstring(L"gamma.exe"));

    m.SortBy(ResultColumn::File);
    CHECK_EQ(m.CellText(0, ResultColumn::File), std::wstring(L"alpha.exe"));
    CHECK_EQ(m.CellText(1, ResultColumn::File), std::wstring(L"Beta.dll"));   // case-insensitive
    m.SortBy(ResultColumn::Size, true);
    CHECK_EQ(m.CellText(0, ResultColumn::File), std::wstring(L"gamma.exe"));

    // Appending while sorted keeps the order.
    m.Append({ row(L"C:\\c\\aardvark.exe", L"NEW", 2.0, 75) });
    CHECK_EQ(m.ViewCount(), static_cast<size_t>(5));
    CHECK_EQ(m.CellText(1, ResultColumn::File), std::wstring(L"aardvark.exe"));

    CHECK_EQ(m.VisibleRows().size(), static_cast<size_t>(5));
    CHECK_EQ(m.CellText(99, ResultColumn::File), std::wstring(L""));
    CHECK_EQ(ResultsModel::CellTextFor(row(L"C:\\x.exe", L"NEW", 7.25, 2048), ResultColumn::Size), std::wstring(L"2 KB"));
    CHECK_EQ(ResultsModel::CellTextFor(row(L"C:\\x.exe", L"NEW", 7.26, 2048), ResultColumn::Score), std::wstring(L"7.3"));
}
