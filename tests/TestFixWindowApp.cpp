// Group 6 fixes (window app), the parts that live in the shared engine library:
// AI consent per endpoint and the startup test rule (A6, A7, I13, I14), finite
// temperature (E9), the settings INI stored as UTF-16 (F3), the results model
// keeping rows and selection straight while rows stream in sorted (F5, F12),
// type-ahead search in the list (F7), and the bounded worker join used at exit
// (F2, I9). The window-only parts were checked by running PhantomRecon.exe.

#include "TestFramework.h"

#include "../AiConsent.h"
#include "../BackgroundWorker.h"
#include "../ResultsModel.h"
#include "../SettingsValues.h"
#include "../TextUtils.h"

#include <windows.h>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <limits>
#include <thread>
#include <vector>

namespace {

ScanRow MakeRow(const std::wstring& path, const std::wstring& status, double score)
{
    ScanRow r;
    r.entry.path = path;
    r.entry.malwareScore = score;
    r.entry.fileSize = 1024;
    r.status = status;
    return r;
}

std::vector<std::wstring> ViewPaths(const ResultsModel& m)
{
    std::vector<std::wstring> out;
    for (size_t i = 0; i < m.ViewCount(); ++i) out.push_back(m.ViewRow(i).entry.path);
    return out;
}

// Deterministic pseudo-random rows with many equal scores and names, so ties matter.
std::vector<ScanRow> MakeRows(size_t count, unsigned seed)
{
    std::vector<ScanRow> rows;
    unsigned x = seed;
    const wchar_t* statuses[] = { L"NEW", L"CHANGED", L"MATCH", L"MISSING", L"KNOWN" };
    for (size_t i = 0; i < count; ++i) {
        x = x * 1103515245u + 12345u;
        double score = static_cast<double>((x >> 8) % 11);   // 0..10, lots of ties
        std::wstring name = L"file" + std::to_wstring((x >> 4) % 97) + L".exe";
        std::wstring path = L"C:\\dir" + std::to_wstring(i) + L"\\" + name;
        rows.push_back(MakeRow(path, statuses[(x >> 12) % 5], score));
    }
    return rows;
}

std::wstring ReadIni(const std::wstring& file, const wchar_t* section, const wchar_t* key)
{
    wchar_t buf[512] = {};
    GetPrivateProfileStringW(section, key, L"<missing>", buf, 512, file.c_str());
    return buf;
}

std::vector<unsigned char> FileBytes(const std::wstring& path)
{
    std::vector<unsigned char> bytes;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return bytes;
    unsigned char buf[4096];
    DWORD got = 0;
    while (ReadFile(h, buf, sizeof(buf), &got, NULL) && got > 0) bytes.insert(bytes.end(), buf, buf + got);
    CloseHandle(h);
    return bytes;
}

void WriteBytes(const std::wstring& path, const std::string& bytes)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(h, bytes.data(), static_cast<DWORD>(bytes.size()), &written, NULL);
    CloseHandle(h);
}

} // namespace

// A6: an approval belongs to the exact endpoint it was given for.
TEST(FixW_A6_ApprovalTiedToEndpoint)
{
    const std::wstring a = L"https://ai.example.com/v1/chat/completions";
    const std::wstring b = L"https://other.example.net/v1/chat/completions";

    CHECK(DecideAiSend(a, L"") == AiSendDecision::NeedsApproval);
    CHECK(DecideAiSend(a, a) == AiSendDecision::AlreadyApproved);
    CHECK(DecideAiSend(b, a) == AiSendDecision::NeedsApproval);           // approving A never approves B
    CHECK(DecideAiSend(L"https://AI.example.com/v1/chat/completions", a) == AiSendDecision::NeedsApproval);
    CHECK(DecideAiSend(a + L"?x=1", a) == AiSendDecision::NeedsApproval);
    CHECK(DecideAiSend(L"", L"") == AiSendDecision::NeedsApproval);       // nothing parses as local

    // This PC never needs a question, approved or not.
    CHECK(DecideAiSend(L"http://localhost:1234/v1/chat/completions", L"") == AiSendDecision::Local);
    CHECK(DecideAiSend(L"http://127.0.0.1:1234/v1/chat/completions", a) == AiSendDecision::Local);
    CHECK(DecideAiSend(L"http://[::1]:1234/v1/chat/completions", L"") == AiSendDecision::Local);
}

// A7 and I13: the startup connection test only runs by itself for this PC.
TEST(FixW_A7_StartupTestOnlyForThisPc)
{
    CHECK(ShouldTestAiEndpointAtStartup(L"http://localhost:1234/v1/chat/completions"));
    CHECK(ShouldTestAiEndpointAtStartup(L"http://127.0.0.1:11434/v1/chat/completions"));
    CHECK(ShouldTestAiEndpointAtStartup(L"http://[::1]:1234/v1/chat/completions"));
    CHECK(!ShouldTestAiEndpointAtStartup(L"http://192.168.1.10:1234/v1/chat/completions"));
    CHECK(!ShouldTestAiEndpointAtStartup(L"https://api.example.com/v1/chat/completions"));
    CHECK(!ShouldTestAiEndpointAtStartup(L"not a url"));

    std::wstring status = StartupTestSkippedStatus();
    CHECK(ContainsI(status, L"not tested"));
    std::wstring chat = StartupTestSkippedChatText(L"https://api.example.com/v1");
    CHECK(ContainsI(chat, L"https://api.example.com/v1"));
    CHECK(ContainsI(chat, L"Test Connection"));
    CHECK(ContainsI(chat, L"Settings"));
}

// I14: the question says so when a remote address uses plain http.
TEST(FixW_I14_PlainHttpWarning)
{
    CHECK(IsPlainHttpEndpoint(L"http://10.0.0.5:1234/v1/chat/completions"));
    CHECK(IsPlainHttpEndpoint(L"  HTTP://10.0.0.5/v1"));
    CHECK(!IsPlainHttpEndpoint(L"https://10.0.0.5/v1"));
    CHECK(!IsPlainHttpEndpoint(L"httpx://10.0.0.5/v1"));

    std::wstring plain = BuildRemoteSendConsentText(L"http://10.0.0.5:1234/v1/chat/completions");
    CHECK(ContainsI(plain, L"http://10.0.0.5:1234/v1/chat/completions"));
    CHECK(ContainsI(plain, L"unencrypted"));
    CHECK(ContainsI(plain, L"asked again"));

    std::wstring secure = BuildRemoteSendConsentText(L"https://ai.example.com/v1/chat/completions");
    CHECK(ContainsI(secure, L"https://ai.example.com/v1/chat/completions"));
    CHECK(!ContainsI(secure, L"unencrypted"));
}

// E9 (settings side): the temperature is always a finite number from 0 to 2.
TEST(FixW_E9_TemperatureAlwaysFinite)
{
    const double fallback = 0.3;
    CHECK_EQ(ParseTemperatureText(L"nan", fallback), fallback);
    CHECK_EQ(ParseTemperatureText(L"NaN", fallback), fallback);
    CHECK_EQ(ParseTemperatureText(L"inf", fallback), fallback);
    CHECK_EQ(ParseTemperatureText(L"-inf", fallback), fallback);
    CHECK_EQ(ParseTemperatureText(L"infinity", fallback), fallback);
    CHECK_EQ(ParseTemperatureText(L"1e999", fallback), fallback);    // overflows to infinity
    CHECK_EQ(ParseTemperatureText(L"abc", fallback), fallback);
    CHECK_EQ(ParseTemperatureText(L"", fallback), fallback);
    CHECK_EQ(ParseTemperatureText(L"0.7", fallback), 0.7);
    CHECK_EQ(ParseTemperatureText(L" 1.25 ", fallback), 1.25);
    CHECK_EQ(ParseTemperatureText(L"0", fallback), 0.0);
    CHECK_EQ(ParseTemperatureText(L"5", fallback), 2.0);
    CHECK_EQ(ParseTemperatureText(L"-1", fallback), 0.0);

    double nan = std::numeric_limits<double>::quiet_NaN();
    double inf = std::numeric_limits<double>::infinity();
    CHECK_EQ(SanitizeTemperature(nan, fallback), fallback);
    CHECK_EQ(SanitizeTemperature(inf, fallback), fallback);
    CHECK(std::isfinite(SanitizeTemperature(nan, nan)));               // even a bad fallback gives a number
    CHECK(std::isfinite(ParseTemperatureText(L"nan", inf)));
}

// F3: settings written through WritePrivateProfileStringW keep Cyrillic and CJK.
TEST(FixW_F3_SettingsIniKeepsUnicode)
{
    const std::wstring cyrillic = L"D:\\\x0414\x0430\x043D\x043D\x044B\x0435\\baseline.prbl";   // "Dannye"
    const std::wstring cjk = L"E:\\\x30C7\x30FC\x30BF\\reports";                               // "deta"

    // A missing file is created as UTF-16 LE with a BOM.
    std::wstring fresh = tf::TestDir() + L"fresh.ini";
    REQUIRE(EnsureUnicodeIniFile(fresh));
    std::vector<unsigned char> head = FileBytes(fresh);
    REQUIRE(head.size() >= 2);
    CHECK(head[0] == 0xFF && head[1] == 0xFE);
    REQUIRE(WritePrivateProfileStringW(L"Scan", L"BaselineFile", cyrillic.c_str(), fresh.c_str()));
    REQUIRE(WritePrivateProfileStringW(L"Scan", L"ReportsFolder", cjk.c_str(), fresh.c_str()));
    CHECK_EQ(ReadIni(fresh, L"Scan", L"BaselineFile"), cyrillic);
    CHECK_EQ(ReadIni(fresh, L"Scan", L"ReportsFolder"), cjk);

    // An existing ANSI file (what earlier versions wrote) is converted with its values kept.
    std::wstring old = tf::TestDir() + L"old.ini";
    WriteBytes(old, "[LLM]\r\nEndpoint=http://localhost:1234/v1/chat/completions\r\nTemperature=0.30\r\n"
                    "[Scan]\r\nFastScanDepth=3\r\n");
    REQUIRE(EnsureUnicodeIniFile(old));
    std::vector<unsigned char> oldHead = FileBytes(old);
    REQUIRE(oldHead.size() >= 2);
    CHECK(oldHead[0] == 0xFF && oldHead[1] == 0xFE);
    CHECK_EQ(ReadIni(old, L"LLM", L"Endpoint"), std::wstring(L"http://localhost:1234/v1/chat/completions"));
    CHECK_EQ(ReadIni(old, L"LLM", L"Temperature"), std::wstring(L"0.30"));
    CHECK_EQ(ReadIni(old, L"Scan", L"FastScanDepth"), std::wstring(L"3"));
    REQUIRE(WritePrivateProfileStringW(L"Scan", L"BaselineFile", cyrillic.c_str(), old.c_str()));
    CHECK_EQ(ReadIni(old, L"Scan", L"BaselineFile"), cyrillic);
    CHECK_EQ(ReadIni(old, L"Scan", L"FastScanDepth"), std::wstring(L"3"));

    // A second call leaves a UTF-16 file alone.
    std::vector<unsigned char> before = FileBytes(old);
    REQUIRE(EnsureUnicodeIniFile(old));
    CHECK(FileBytes(old) == before);

    // Control: without the fix, Windows writes ANSI and the name is lost (on any
    // code page that cannot hold both scripts, which is every non-UTF-8 one).
    if (GetACP() != CP_UTF8) {
        std::wstring ansi = tf::TestDir() + L"ansi.ini";
        WritePrivateProfileStringW(L"Scan", L"BaselineFile", cyrillic.c_str(), ansi.c_str());
        WritePrivateProfileStringW(L"Scan", L"ReportsFolder", cjk.c_str(), ansi.c_str());
        bool bothKept = ReadIni(ansi, L"Scan", L"BaselineFile") == cyrillic && ReadIni(ansi, L"Scan", L"ReportsFolder") == cjk;
        CHECK(!bothKept);
    }
}

// F12: rows appended to a sorted model end up exactly where a full re-sort puts
// them, ties included, for every column kind, with a filter and a search.
TEST(FixW_F12_SortedAppendMatchesFullSort)
{
    std::vector<ScanRow> all = MakeRows(3000, 7);
    struct Case { ResultColumn column; bool ascending; StatusFilter filter; const wchar_t* search; };
    const Case cases[] = {
        { ResultColumn::Score, false, StatusFilter::All, L"" },
        { ResultColumn::Score, true, StatusFilter::NeedsReview, L"" },
        { ResultColumn::File, true, StatusFilter::All, L"" },
        { ResultColumn::File, false, StatusFilter::All, L"file1" },
        { ResultColumn::Status, true, StatusFilter::MediumScore, L"" },
        { ResultColumn::Path, true, StatusFilter::All, L"dir2" },
    };
    const size_t batchSizes[] = { 1, 3, 50, 700 };   // small batches insert, large ones merge
    for (const Case& c : cases) {
        for (size_t batch : batchSizes) {
            ResultsModel streamed;
            streamed.SetFilter(c.filter);
            streamed.SetSearch(c.search);
            streamed.SortBy(c.column, c.ascending);
            for (size_t i = 0; i < all.size(); i += batch) {
                size_t end = (std::min)(all.size(), i + batch);
                streamed.Append(std::vector<ScanRow>(all.begin() + static_cast<std::ptrdiff_t>(i),
                                                     all.begin() + static_cast<std::ptrdiff_t>(end)));
            }
            ResultsModel whole;
            whole.SetFilter(c.filter);
            whole.SetSearch(c.search);
            whole.SetRows(all);
            whole.SortBy(c.column, c.ascending);
            CHECK(whole.ViewCount() > 0);
            CHECK_EQ(streamed.ViewCount(), whole.ViewCount());
            CHECK(ViewPaths(streamed) == ViewPaths(whole));
        }
    }
}

// F12: 100,000 rows streamed into a list sorted by name stay fast. The old code
// re-sorted every row on every batch (2,000 full sorts here).
TEST(FixW_F12_LargeSortedStreamIsFast)
{
    std::vector<ScanRow> all = MakeRows(100000, 11);
    ResultsModel m;
    m.SortBy(ResultColumn::File, true);
    auto start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < all.size(); i += 50) {
        m.Append(std::vector<ScanRow>(all.begin() + static_cast<std::ptrdiff_t>(i),
                                      all.begin() + static_cast<std::ptrdiff_t>(i + 50)));
    }
    double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    std::printf("    100000 rows in 2000 sorted batches: %.2f s\n", seconds);
    CHECK_EQ(m.ViewCount(), static_cast<size_t>(100000));
    CHECK(seconds < 20.0);
    for (size_t i = 1; i < m.ViewCount(); ++i) {
        if (_wcsicmp(ResultsModel::CellTextFor(m.ViewRow(i - 1), ResultColumn::File).c_str(),
                     ResultsModel::CellTextFor(m.ViewRow(i), ResultColumn::File).c_str()) > 0) {
            CHECK(!"view out of order");
            break;
        }
    }
}

// F5: a row keeps its identity (model index) while new rows move it in the view.
TEST(FixW_F5_SelectionFollowsTheSameFile)
{
    ResultsModel m;
    m.SortBy(ResultColumn::Score, false);   // highest score first
    m.Append({ MakeRow(L"C:\\a.exe", L"NEW", 5.0), MakeRow(L"C:\\b.exe", L"NEW", 3.0), MakeRow(L"C:\\c.exe", L"NEW", 1.0) });
    REQUIRE(m.ViewCount() == 3);
    CHECK_EQ(m.ViewRow(1).entry.path, std::wstring(L"C:\\b.exe"));

    size_t selected = 0;
    REQUIRE(m.ModelIndexOfView(1, selected));          // the user selects b.exe at row 1
    m.Append({ MakeRow(L"C:\\x.exe", L"NEW", 9.0), MakeRow(L"C:\\y.exe", L"NEW", 8.0) });
    int now = m.ViewIndexOfModel(selected);
    CHECK_EQ(now, 3);                                  // two higher scores went above it
    REQUIRE(now >= 0);
    CHECK_EQ(m.ViewRow(static_cast<size_t>(now)).entry.path, std::wstring(L"C:\\b.exe"));
    CHECK(m.ViewRow(1).entry.path != L"C:\\b.exe");    // the old row number is now another file

    size_t unused = 0;
    CHECK(!m.ModelIndexOfView(99, unused));
    m.SetFilter(StatusFilter::HighScore);              // b.exe (3.0) is filtered out
    CHECK_EQ(m.ViewIndexOfModel(selected), -1);
}

// F7: typing in the list finds a row by the start of its file name.
TEST(FixW_F7_TypeAheadFindsByFileName)
{
    ResultsModel m;
    m.Append({ MakeRow(L"C:\\p\\alpha.exe", L"NEW", 1.0), MakeRow(L"C:\\p\\Beta.dll", L"NEW", 1.0),
               MakeRow(L"C:\\p\\bravo.exe", L"NEW", 1.0), MakeRow(L"C:\\p\\charlie.ps1", L"NEW", 1.0) });
    CHECK_EQ(m.FindByFileName(L"b", 0, true, false), 1);
    CHECK_EQ(m.FindByFileName(L"B", 2, true, false), 2);          // next match after the current row
    CHECK_EQ(m.FindByFileName(L"b", 3, true, false), 1);          // wraps to the top
    CHECK_EQ(m.FindByFileName(L"b", 3, false, false), -1);        // no wrap, nothing below
    CHECK_EQ(m.FindByFileName(L"cha", 0, true, false), 3);
    CHECK_EQ(m.FindByFileName(L"BRAVO.EXE", 0, true, true), 2);   // exact, any case
    CHECK_EQ(m.FindByFileName(L"bravo", 0, true, true), -1);      // exact needs the whole name
    CHECK_EQ(m.FindByFileName(L"zzz", 0, true, false), -1);
    CHECK_EQ(m.FindByFileName(L"", 0, true, false), -1);
    CHECK_EQ(m.FindByFileName(L"a", 99, true, false), 0);         // start past the end wraps

    m.SortBy(ResultColumn::File, false);                          // view order is followed
    CHECK_EQ(m.ViewRow(0).entry.path, std::wstring(L"C:\\p\\charlie.ps1"));
    CHECK_EQ(m.FindByFileName(L"b", 0, true, false), 1);
    CHECK_EQ(m.ViewRow(1).entry.path, std::wstring(L"C:\\p\\bravo.exe"));

    ResultsModel empty;
    CHECK_EQ(empty.FindByFileName(L"a", 0, true, false), -1);
}

// F2 and I9: the exit waits a bounded time for a job stuck in a blocking call.
TEST(FixW_F2_JoinAllForIsBounded)
{
    BackgroundWorker idle;
    CHECK(idle.JoinAllFor(0));

    BackgroundWorker w;
    w.Run([]() { std::this_thread::sleep_for(std::chrono::milliseconds(1500)); });
    auto start = std::chrono::steady_clock::now();
    bool finished = w.JoinAllFor(100);
    double waited = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    CHECK(!finished);
    CHECK(waited < 1.0);
    CHECK_EQ(w.ActiveCount(), static_cast<size_t>(1));
    CHECK(w.JoinAllFor(10000));
    CHECK_EQ(w.ActiveCount(), static_cast<size_t>(0));

    BackgroundWorker quick;
    for (int i = 0; i < 4; ++i) quick.Run([]() { std::this_thread::sleep_for(std::chrono::milliseconds(20)); });
    CHECK(quick.JoinAllFor(5000));
}
