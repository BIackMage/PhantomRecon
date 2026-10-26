// Group 7 of the 2026-10-26 review: the test runner's data folder (G1), the JSON
// checker the report tests rely on (G10) and the release build settings (A12, I8).

#include "TestFramework.h"
#include "JsonCheck.h"

#include "../AppPaths.h"
#include "../FileIO.h"
#include "../PeFile.h"
#include "../ScanCore.h"
#include "../ScoringConfig.h"
#include "../TextUtils.h"

#include <windows.h>
#include <cmath>

namespace {

// Puts an environment variable back when the test ends, also when a REQUIRE stops it.
class EnvironmentGuard {
public:
    explicit EnvironmentGuard(const std::wstring& name) : name(name)
    {
        wchar_t buffer[32768] = {};
        DWORD n = GetEnvironmentVariableW(name.c_str(), buffer, 32768);
        had = n > 0 && n < 32768;
        if (had) value.assign(buffer, n);
    }
    ~EnvironmentGuard() { SetEnvironmentVariableW(name.c_str(), had ? value.c_str() : nullptr); }

private:
    std::wstring name;
    std::wstring value;
    bool had = false;
};

// Deletes a file when the test ends.
class FileGuard {
public:
    explicit FileGuard(std::wstring path) : path(std::move(path)) {}
    ~FileGuard() { DeleteFileW(path.c_str()); }

private:
    std::wstring path;
};

bool Accepts(const std::wstring& text)
{
    JsonCheck c(text);
    return c.Valid();
}

} // namespace

// ---------------------------------------------------------------------------
// G1: the program's data files come from the run's own folder, never from the exe's
// ---------------------------------------------------------------------------
TEST(FixTools_DataFolderOverride)
{
    std::wstring var = DataFolderEnvironmentName();
    CHECK_EQ(var, std::wstring(L"PHANTOMRECON_DATA_DIR"));
    REQUIRE(!tf::DataDir().empty());
    CHECK_EQ(AppFilePath(L"phantom_recon_scoring.ini"), tf::DataDir() + L"phantom_recon_scoring.ini");
    CHECK(!EqualsI(DirectoryOf(AppFilePath(L"x")), DirectoryOf(GetExePath())));

    EnvironmentGuard restore(var);
    // Only an existing absolute folder counts; anything else falls back to the exe folder.
    REQUIRE(SetEnvironmentVariableW(var.c_str(), L"relative\\folder"));
    CHECK_EQ(AppFilePath(L"x"), GetExeDirectory() + L"x");
    REQUIRE(SetEnvironmentVariableW(var.c_str(), (tf::TestDir() + L"does_not_exist").c_str()));
    CHECK_EQ(AppFilePath(L"x"), GetExeDirectory() + L"x");
    std::wstring noSlash = tf::TestDir().substr(0, tf::TestDir().size() - 1);
    REQUIRE(SetEnvironmentVariableW(var.c_str(), noSlash.c_str()));
    CHECK_EQ(AppFilePath(L"x"), tf::TestDir() + L"x");
    REQUIRE(SetEnvironmentVariableW(var.c_str(), nullptr));
    CHECK_EQ(AppFilePath(L"x"), GetExeDirectory() + L"x");
}

TEST(FixTools_ScoringIniComesFromDataFolder)
{
    // The data folder starts empty, so the process-wide weights are the defaults.
    ScoringConfig defaults;
    ReloadScoringConfig();
    CHECK(GetScoringConfig().weights.unsigned_penalty == defaults.weights.unsigned_penalty);

    // An INI in the data folder is the one that is read...
    std::wstring ini = tf::DataDir() + L"phantom_recon_scoring.ini";
    FileGuard cleanup(ini);
    std::string text = "[scoring_weights]\nunsigned_penalty=7.25\n";
    REQUIRE(WriteBinaryFile(ini, text.data(), text.size()));
    ReloadScoringConfig();
    CHECK(std::fabs(GetScoringConfig().weights.unsigned_penalty - 7.25) < 1e-9);

    // ...and removing it brings the defaults back for the tests that follow.
    REQUIRE(DeleteFileW(ini.c_str()));
    ReloadScoringConfig();
    CHECK(GetScoringConfig().weights.unsigned_penalty == defaults.weights.unsigned_penalty);
}

// ---------------------------------------------------------------------------
// G10: the JSON checker is strict and counts keys
// ---------------------------------------------------------------------------
TEST(FixTools_JsonCheckIsStrict)
{
    JsonCheck doc(L"{\"a\": 1, \"b\": [true, false, null, -0.5e+3], \"c\": {\"a\": \"x\\u00e9\"}, \"k\\u0065y\": \"\"}");
    REQUIRE(doc.Valid());
    CHECK_EQ(doc.KeyCount(L"a"), 2);
    CHECK_EQ(doc.KeyCount(L"b"), 1);
    CHECK(doc.HasKey(L"c"));
    CHECK(doc.HasKey(L"key"));             // escapes in keys are decoded
    CHECK_EQ(doc.KeyCount(L"zz"), 0);
    CHECK(doc.error.empty());

    // A temporary is safe: the checker keeps its own copy.
    JsonCheck temp(std::wstring(L"[1, 2]"));
    CHECK(temp.Valid());

    CHECK(Accepts(L"0"));
    CHECK(Accepts(L" \"\\uFF10\" "));       // an escape names any code point
    CHECK(!Accepts(L"\x0661"));             // ARABIC-INDIC DIGIT ONE is not a JSON digit
    CHECK(!Accepts(L"1\x0661"));
    CHECK(!Accepts(L"\xFF11"));             // FULLWIDTH DIGIT ONE
    CHECK(!Accepts(L"\"\\u\xFF10\xFF10\xFF10\xFF10\""));   // hex digits are ASCII too
    CHECK(!Accepts(L"01"));
    CHECK(!Accepts(L"[1,]"));
    CHECK(!Accepts(L"{\"a\" 1}"));
    CHECK(!Accepts(L"\"tab\there\""));      // raw control character in a string
    CHECK(!Accepts(L"\"\\x\""));
    CHECK(!Accepts(L"[1] [2]"));
    CHECK(!Accepts(L""));

    JsonCheck bad(L"{\"a\": tru}");
    CHECK(!bad.Valid());
    CHECK(!bad.error.empty());
}

// ---------------------------------------------------------------------------
// A12: the programs carry their own C runtime, so the zip runs on a clean PC
// ---------------------------------------------------------------------------
TEST(FixTools_StaticRuntime)
{
    PeInfo pe = ParsePeFile(GetExePath());
    REQUIRE(pe.valid);
    REQUIRE(!pe.imports.empty());
    bool kernel32 = false;
    for (const PeImport& imp : pe.imports) {
        std::string dll = ToLowerA(imp.dll);
        if (dll == "kernel32.dll") kernel32 = true;
        for (const char* runtime : { "vcruntime", "msvcp", "ucrtbase", "api-ms-win-crt-", "concrt", "vccorlib" }) {
            if (dll.rfind(runtime, 0) == 0) tf::Fail(__FILE__, __LINE__, "the tests link the C runtime DLL " + imp.dll);
        }
    }
    CHECK(kernel32);   // the import list was really read
}
