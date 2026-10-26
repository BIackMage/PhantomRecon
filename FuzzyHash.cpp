#include "pch.h"
#include "FuzzyHash.h"

#include "FileIO.h"

#include <algorithm>
#include <string>
#include <vector>

// Constants from Andrew Tridgell's spamsum, as used by ssdeep.
static const uint32_t kRollingWindow = 7;
static const uint32_t kMinBlocksize  = 3;
static const uint32_t kHashPrime     = 0x01000193;
static const uint32_t kHashInit      = 0x28021967;
static const size_t   kSpamsumLength = 64;
static const char*    kB64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

struct RollState {
    uint8_t  window[kRollingWindow] = {};
    uint32_t h1 = 0;
    uint32_t h2 = 0;
    uint32_t h3 = 0;
    uint32_t n  = 0;

    uint32_t Roll(uint8_t c)
    {
        h2 -= h1;
        h2 += kRollingWindow * c;
        h1 += c;
        h1 -= window[n % kRollingWindow];
        window[n % kRollingWindow] = c;
        n++;
        h3 <<= 5;
        h3 ^= c;
        return h1 + h2 + h3;
    }

    uint32_t Sum() const { return h1 + h2 + h3; }
};

static uint32_t SumHash(uint8_t c, uint32_t h)
{
    return (h * kHashPrime) ^ c;
}

std::wstring ComputeFuzzyHashBuffer(const uint8_t* data, size_t size)
{
    if (!data || size < 4) return L"";

    uint32_t blockSize = kMinBlocksize;
    while (static_cast<uint64_t>(blockSize) * kSpamsumLength < size) blockSize *= 2;

    while (true) {
        RollState roll;
        uint32_t h1 = kHashInit;
        uint32_t h2 = kHashInit;
        std::string sig1;
        std::string sig2;

        for (size_t i = 0; i < size; ++i) {
            uint8_t c = data[i];
            uint32_t r = roll.Roll(c);
            h1 = SumHash(c, h1);
            h2 = SumHash(c, h2);

            if (r % blockSize == blockSize - 1) {
                if (sig1.size() < kSpamsumLength - 1) {
                    sig1 += kB64[h1 % 64];
                    h1 = kHashInit;
                }
            }
            if (r % (blockSize * 2) == (blockSize * 2) - 1) {
                if (sig2.size() < kSpamsumLength / 2 - 1) {
                    sig2 += kB64[h2 % 64];
                    h2 = kHashInit;
                }
            }
        }

        if (roll.Sum() != 0) {
            sig1 += kB64[h1 % 64];
            sig2 += kB64[h2 % 64];
        }

        if (blockSize > kMinBlocksize && sig1.size() < kSpamsumLength / 2) {
            blockSize /= 2;
            continue;
        }

        std::string out = std::to_string(blockSize) + ":" + sig1 + ":" + sig2;
        return std::wstring(out.begin(), out.end());
    }
}

std::wstring ComputeFuzzyHashFile(const std::wstring& path, size_t maxBytes)
{
    std::vector<uint8_t> bytes;
    if (!ReadBinaryFile(path, bytes, maxBytes)) return L"";
    return ComputeFuzzyHashBuffer(bytes.data(), bytes.size());
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

// Collapse runs of more than three identical characters (they carry no information).
static std::string EliminateSequences(const std::string& s)
{
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (i >= 3 && s[i] == s[i - 1] && s[i] == s[i - 2] && s[i] == s[i - 3]) continue;
        out += s[i];
    }
    return out;
}

static bool HasCommonSubstring(const std::string& a, const std::string& b)
{
    if (a.size() < kRollingWindow || b.size() < kRollingWindow) return false;
    for (size_t i = 0; i + kRollingWindow <= a.size(); ++i) {
        if (b.find(a.substr(i, kRollingWindow)) != std::string::npos) return true;
    }
    return false;
}

// Weighted edit distance: insert / delete 1, substitute 3, transpose 5 (spamsum weights).
static int EditDistance(const std::string& s, const std::string& t)
{
    const int insCost = 1, delCost = 1, subCost = 3, swapCost = 5;
    size_t n = s.size(), m = t.size();
    std::vector<std::vector<int>> d(n + 1, std::vector<int>(m + 1, 0));
    for (size_t i = 0; i <= n; ++i) d[i][0] = static_cast<int>(i) * delCost;
    for (size_t j = 0; j <= m; ++j) d[0][j] = static_cast<int>(j) * insCost;
    for (size_t i = 1; i <= n; ++i) {
        for (size_t j = 1; j <= m; ++j) {
            int cost = (s[i - 1] == t[j - 1]) ? 0 : subCost;
            int best = (std::min)({ d[i - 1][j] + delCost, d[i][j - 1] + insCost, d[i - 1][j - 1] + cost });
            if (i > 1 && j > 1 && s[i - 1] == t[j - 2] && s[i - 2] == t[j - 1]) {
                best = (std::min)(best, d[i - 2][j - 2] + swapCost);
            }
            d[i][j] = best;
        }
    }
    return d[n][m];
}

static int ScoreStrings(const std::string& s1, const std::string& s2, uint32_t blockSize)
{
    if (s1.empty() || s2.empty()) return 0;
    if (!HasCommonSubstring(s1, s2)) return 0;

    int dist = EditDistance(s1, s2);
    int len = static_cast<int>(s1.size() + s2.size());
    int score = (dist * static_cast<int>(kSpamsumLength)) / len;
    score = (100 * score) / static_cast<int>(kSpamsumLength);
    if (score >= 100) return 0;
    score = 100 - score;

    // Small block sizes cannot express high confidence for short signatures.
    uint32_t cap = (blockSize / kMinBlocksize) * static_cast<uint32_t>((std::min)(s1.size(), s2.size()));
    if (static_cast<uint32_t>(score) > cap) score = static_cast<int>(cap);
    return score;
}

// Fuzzy hash digits are base64 (ASCII). Anything else means the text is not a hash.
static bool AsciiOnly(const std::wstring& in, std::string& out)
{
    out.clear();
    out.reserve(in.size());
    for (wchar_t c : in) {
        if (c > 0x7F) return false;
        out.push_back(static_cast<char>(c));
    }
    return true;
}

static bool SplitHash(const std::wstring& h, uint32_t& blockSize, std::string& a, std::string& b)
{
    size_t c1 = h.find(L':');
    if (c1 == std::wstring::npos) return false;
    size_t c2 = h.find(L':', c1 + 1);
    if (c2 == std::wstring::npos) return false;
    blockSize = static_cast<uint32_t>(_wtoi(h.substr(0, c1).c_str()));
    if (!AsciiOnly(h.substr(c1 + 1, c2 - c1 - 1), a)) return false;
    if (!AsciiOnly(h.substr(c2 + 1), b)) return false;
    return blockSize > 0;
}

int CompareFuzzyHashes(const std::wstring& ha, const std::wstring& hb)
{
    if (ha.empty() || hb.empty()) return 0;
    if (ha == hb) return 100;

    uint32_t bs1 = 0, bs2 = 0;
    std::string a1, a2, b1, b2;
    if (!SplitHash(ha, bs1, a1, a2) || !SplitHash(hb, bs2, b1, b2)) return 0;

    if (bs1 != bs2 && bs1 != bs2 * 2 && bs2 != bs1 * 2) return 0;

    a1 = EliminateSequences(a1);
    a2 = EliminateSequences(a2);
    b1 = EliminateSequences(b1);
    b2 = EliminateSequences(b2);

    if (bs1 == bs2) {
        return (std::max)(ScoreStrings(a1, b1, bs1), ScoreStrings(a2, b2, bs1 * 2));
    }
    if (bs1 == bs2 * 2) {
        return ScoreStrings(a1, b2, bs1);
    }
    return ScoreStrings(a2, b1, bs2);
}
