#pragma once

#include <map>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// WmiQuery: run a WQL query and get the requested properties back as text.
//
// Arrays are joined with "\n". Missing or NULL properties are absent from the
// row map. COM is initialised for the calling thread for the duration of the
// call (ComScope), so this is safe to call from worker threads.
// ---------------------------------------------------------------------------

using WmiRow = std::map<std::wstring, std::wstring>;

struct WmiResult {
    bool                ok = false;
    long                hresult = 0;     // HRESULT of the failing step when !ok
    std::wstring        error;           // readable description when !ok
    std::vector<WmiRow> rows;
};

WmiResult WmiQuery(const std::wstring& wmiNamespace, const std::wstring& wql,
                   const std::vector<std::wstring>& properties);

// RAII COM initialisation (multithreaded apartment). Tolerates an existing
// apartment of either kind on the thread.
class ComScope {
public:
    ComScope();
    ~ComScope();
    ComScope(const ComScope&) = delete;
    ComScope& operator=(const ComScope&) = delete;
    bool Ok() const { return m_ok; }
private:
    bool m_ok = false;
    bool m_uninit = false;
};
