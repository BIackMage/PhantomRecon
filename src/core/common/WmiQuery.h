#pragma once

#include <windows.h>
#include <oaidl.h>
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
    bool                timedOut = false; // a row did not arrive within kWmiRowTimeoutMs (ok is then false)
    long                hresult = 0;     // HRESULT of the failing step when !ok
    std::wstring        error;           // readable description when !ok
    std::vector<WmiRow> rows;            // rows read so far (may be partial when !ok)
};

// How long one row may take before the query counts as timed out.
const unsigned long kWmiRowTimeoutMs = 15000;

WmiResult WmiQuery(const std::wstring& wmiNamespace, const std::wstring& wql,
                   const std::vector<std::wstring>& properties);

// One IEnumWbemClassObject::Next result applied to result. True when a row came
// back and should be read; false at the end of the rows, on failure, and on
// WBEM_S_TIMEDOUT (which sets ok = false and timedOut = true). Exposed for tests.
bool WmiAcceptNextResult(long hr, unsigned long returned, const std::wstring& wql, WmiResult& result);

// A property value as text: arrays joined with "\n", booleans as True / False.
// Exposed for tests.
std::wstring WmiVariantToText(const VARIANT& v);

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
