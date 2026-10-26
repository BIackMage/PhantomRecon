#include "pch.h"
#include "KnownGood.h"

#include "AppPaths.h"
#include "FileIO.h"
#include "TextUtils.h"

#include <mutex>
#include <unordered_map>

struct KnownGoodState {
    std::mutex mutex;
    bool loaded = false;
    std::unordered_map<std::wstring, std::wstring> hashes;   // lowercase sha256 -> name
};

static KnownGoodState& State()
{
    static KnownGoodState state;
    return state;
}

std::wstring DefaultKnownGoodPath()
{
    return AppFilePath(L"known_good_sha256.txt");
}

static size_t LoadLocked(KnownGoodState& s, const std::wstring& path)
{
    s.hashes.clear();
    s.loaded = true;
    std::wstring text;
    if (!ReadTextFile(path, text)) return 0;
    for (const std::wstring& raw : SplitAnyW(text, L"\r\n")) {
        std::wstring line = TrimW(raw);
        if (line.empty() || line[0] == L'#') continue;
        std::wstring hash = line;
        std::wstring name;
        size_t comma = line.find_first_of(L",;\t ");
        if (comma != std::wstring::npos) {
            hash = line.substr(0, comma);
            name = TrimW(line.substr(comma + 1));
        }
        hash = ToLowerW(hash);
        if (hash.size() != 64) continue;
        s.hashes[hash] = name;
    }
    OutputDebugStringW((L"[KnownGood] loaded " + std::to_wstring(s.hashes.size()) + L" hashes from " + path + L"\n").c_str());
    return s.hashes.size();
}

size_t LoadKnownGoodList(const std::wstring& path)
{
    KnownGoodState& s = State();
    std::lock_guard<std::mutex> lock(s.mutex);
    return LoadLocked(s, path);
}

bool IsKnownGoodHash(const std::wstring& sha256)
{
    if (sha256.size() != 64) return false;
    KnownGoodState& s = State();
    std::lock_guard<std::mutex> lock(s.mutex);
    if (!s.loaded) LoadLocked(s, DefaultKnownGoodPath());
    return s.hashes.find(ToLowerW(sha256)) != s.hashes.end();
}

std::wstring KnownGoodName(const std::wstring& sha256)
{
    KnownGoodState& s = State();
    std::lock_guard<std::mutex> lock(s.mutex);
    if (!s.loaded) LoadLocked(s, DefaultKnownGoodPath());
    auto it = s.hashes.find(ToLowerW(sha256));
    return it == s.hashes.end() ? L"" : it->second;
}

size_t KnownGoodCount()
{
    KnownGoodState& s = State();
    std::lock_guard<std::mutex> lock(s.mutex);
    if (!s.loaded) LoadLocked(s, DefaultKnownGoodPath());
    return s.hashes.size();
}
