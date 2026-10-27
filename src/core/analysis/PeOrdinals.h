#pragma once

#include <cstdint>
#include <string>

// ---------------------------------------------------------------------------
// PeOrdinals: names of functions that programs import by ordinal from
// ws2_32.dll, wsock32.dll and oleaut32.dll (one table each, wsock32's numbering
// differs from ws2_32's), as in pefile's ordlookup. The
// import hash and the suspicious-import scoring use them so an ordinal import
// of ws2_32!connect counts the same as an import by name.
// ---------------------------------------------------------------------------

// True when dllLower (lowercase, as written in the import table, e.g.
// "ws2_32.dll") is one of the DLLs with an ordinal table.
bool HasOrdinalTable(const std::string& dllLower);

// The function name for an ordinal, or nullptr when the DLL has no table or the
// table has no entry for that ordinal.
const char* LookupOrdinalName(const std::string& dllLower, uint16_t ordinal);
