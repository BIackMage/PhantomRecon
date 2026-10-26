#pragma once

// ---------------------------------------------------------------------------
// TestFramework: a very small test runner with no outside dependencies.
//
//   TEST(Name) { CHECK(a == b); CHECK_EQ(a, b); REQUIRE(x); }
//
// CHECK records a failure and keeps going. REQUIRE stops the test. Every test
// runs in its own scratch folder (TestDir()), deleted afterwards. The runner
// prints one line per test and a total, and exits 1 when anything failed.
// ---------------------------------------------------------------------------

#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace tf {

struct TestCase {
    const char*           name;
    std::function<void()> body;
};

std::vector<TestCase>& Registry();

struct Registrar {
    Registrar(const char* name, std::function<void()> body) { Registry().push_back({ name, std::move(body) }); }
};

struct RequireFailed {};

void Fail(const char* file, int line, const std::string& message);
int  RunAll(const std::vector<std::string>& filters);

// Scratch folder for the running test, with a trailing backslash.
std::wstring TestDir();

// Narrow text for messages.
std::string Narrow(const std::wstring& s);
inline std::string Narrow(const std::string& s) { return s; }
inline std::string Narrow(const char* s) { return s ? s : ""; }
inline std::string Narrow(const wchar_t* s) { return s ? Narrow(std::wstring(s)) : ""; }

template <typename T>
std::string Show(const T& v)
{
    std::ostringstream ss;
    ss << v;
    return ss.str();
}
inline std::string Show(const std::wstring& v) { return "\"" + Narrow(v) + "\""; }
inline std::string Show(const std::string& v) { return "\"" + v + "\""; }
inline std::string Show(const wchar_t* v) { return "\"" + Narrow(v) + "\""; }
inline std::string Show(bool v) { return v ? "true" : "false"; }

} // namespace tf

#define TF_CONCAT2(a, b) a##b
#define TF_CONCAT(a, b) TF_CONCAT2(a, b)

#define TEST(name)                                                                  \
    static void TF_CONCAT(test_, name)();                                           \
    static tf::Registrar TF_CONCAT(reg_, name)(#name, TF_CONCAT(test_, name));      \
    static void TF_CONCAT(test_, name)()

#define CHECK(cond)                                                                 \
    do { if (!(cond)) tf::Fail(__FILE__, __LINE__, "CHECK(" #cond ")"); } while (0)

#define CHECK_EQ(a, b)                                                              \
    do {                                                                            \
        auto&& tf_a = (a);                                                          \
        auto&& tf_b = (b);                                                          \
        if (!(tf_a == tf_b))                                                        \
            tf::Fail(__FILE__, __LINE__, "CHECK_EQ(" #a ", " #b "): " +             \
                     tf::Show(tf_a) + " != " + tf::Show(tf_b));                     \
    } while (0)

#define REQUIRE(cond)                                                               \
    do {                                                                            \
        if (!(cond)) {                                                              \
            tf::Fail(__FILE__, __LINE__, "REQUIRE(" #cond ")");                     \
            throw tf::RequireFailed();                                              \
        }                                                                           \
    } while (0)
