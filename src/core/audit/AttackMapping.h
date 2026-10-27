#pragma once

#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// AttackMapping: MITRE ATT&CK technique names and the technique ids carried by
// file analysis findings (imports, packing, signature, header, script and origin
// indicators). Names follow ATT&CK Enterprise v16/v17.
// ---------------------------------------------------------------------------

// Technique name for an id such as "T1055.012". Empty when the id is unknown.
std::wstring AttackTechniqueName(const std::wstring& id);

// Every id with a name in the table (for validation in tests).
std::vector<std::wstring> KnownAttackTechniques();

// Technique for a finding code produced by file analysis, e.g. "HASH_MISMATCH",
// "PACKED", "TLS_CALLBACKS", "ENCODED_COMMAND", "MOTW_MISSING". Empty when none applies.
std::wstring AttackTechniqueForCode(const std::wstring& code);

// Add ids to a list without duplicates, keeping order.
void AddUniqueTechniques(std::vector<std::wstring>& target, const std::vector<std::wstring>& ids);

// Extract the code prefix of an indicator string: "TLS_CALLBACKS: 2 callbacks" -> "TLS_CALLBACKS".
std::wstring IndicatorCode(const std::wstring& indicator);

// Plain-language explanation of a finding code, for the detail window and reports.
std::wstring ExplainIndicator(const std::wstring& code);

// Build a MITRE ATT&CK Navigator layer (JSON) from technique ids with counts.
struct TechniqueCount {
    std::wstring id;
    int          count = 0;
    std::wstring comment;
};
std::wstring BuildNavigatorLayer(const std::wstring& layerName, const std::wstring& description,
                                 const std::vector<TechniqueCount>& techniques);
