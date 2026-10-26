#include "pch.h"
#include "ScoringConfig.h"

#include "StringConv.h"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <sstream>
#include <windows.h>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[ScoringConfig] " + msg + L"\n").c_str());
}

ScoringConfig& GetScoringConfig()
{
    static ScoringConfig instance;
    return instance;
}

ScoringConfig::ScoringConfig() {}

void ScoringConfig::ResetToDefaults()
{
    entropy = EntropyThresholds();
    weights = ScoringWeights();
    anomalies = AnomalyBumps();
    packing = PackingConfig();
    origin = OriginBumps();
    peAnomalies = PeAnomalyBumps();
    script = ScriptScoring();
    revocation = RevocationBumps();
    m_apiWeights.clear();
    m_issues.clear();
}

std::string ScoringConfig::TrimString(const std::string& s)
{
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

double ScoringConfig::ParseDouble(const std::string& s, double defaultVal)
{
    try {
        size_t used = 0;
        double v = std::stod(s, &used);
        if (used == 0) return defaultVal;
        return v;
    }
    catch (...) {
        return defaultVal;
    }
}

// A table of every named setting, so load, save and validate cannot drift.
struct SettingRef {
    const char* section;
    const char* key;
    double*     value;
    double      defaultValue;
    double      maxValue;      // values above this are clamped (0 = no maximum)
};

static std::vector<SettingRef> AllSettings(ScoringConfig& c)
{
    const EntropyThresholds e;
    const ScoringWeights w;
    const AnomalyBumps a;
    const PackingConfig p;
    const OriginBumps o;
    const PeAnomalyBumps pa;
    const ScriptScoring sc;
    const RevocationBumps r;
    return {
        { "entropy_thresholds", "level1_threshold", &c.entropy.level1_threshold, e.level1_threshold, 8.0 },
        { "entropy_thresholds", "level1_score",     &c.entropy.level1_score,     e.level1_score,     10.0 },
        { "entropy_thresholds", "level2_threshold", &c.entropy.level2_threshold, e.level2_threshold, 8.0 },
        { "entropy_thresholds", "level2_score",     &c.entropy.level2_score,     e.level2_score,     10.0 },
        { "entropy_thresholds", "level3_threshold", &c.entropy.level3_threshold, e.level3_threshold, 8.0 },
        { "entropy_thresholds", "level3_score",     &c.entropy.level3_score,     e.level3_score,     10.0 },
        { "entropy_thresholds", "level4_threshold", &c.entropy.level4_threshold, e.level4_threshold, 8.0 },
        { "entropy_thresholds", "level4_score",     &c.entropy.level4_score,     e.level4_score,     10.0 },
        { "scoring_weights", "unsigned_penalty",         &c.weights.unsigned_penalty,         w.unsigned_penalty,         10.0 },
        { "scoring_weights", "hidden_penalty",           &c.weights.hidden_penalty,           w.hidden_penalty,           10.0 },
        { "scoring_weights", "temp_dir_penalty",         &c.weights.temp_dir_penalty,         w.temp_dir_penalty,         10.0 },
        { "scoring_weights", "import_weight_multiplier", &c.weights.import_weight_multiplier, w.import_weight_multiplier, 10.0 },
        { "scoring_weights", "category_diversity_bonus", &c.weights.category_diversity_bonus, w.category_diversity_bonus, 10.0 },
        { "scoring_weights", "import_score_cap",         &c.weights.import_score_cap,         w.import_score_cap,         10.0 },
        { "scoring_weights", "score_cap",                &c.weights.score_cap,                w.score_cap,                100.0 },
        { "anomaly_bumps", "hash_mismatch",   &c.anomalies.hash_mismatch,   a.hash_mismatch,   10.0 },
        { "anomaly_bumps", "untrusted_chain", &c.anomalies.untrusted_chain, a.untrusted_chain, 10.0 },
        { "anomaly_bumps", "packing",         &c.anomalies.packing,         a.packing,         10.0 },
        { "anomaly_bumps", "rwx_sections",    &c.anomalies.rwx_sections,    a.rwx_sections,    10.0 },
        { "packing", "confidence_threshold", &c.packing.confidence_threshold, p.confidence_threshold, 1.0 },
        { "origin_bumps", "internet_unsigned", &c.origin.internet_unsigned, o.internet_unsigned, 10.0 },
        { "origin_bumps", "restricted_zone",   &c.origin.restricted_zone,   o.restricted_zone,   10.0 },
        { "origin_bumps", "executable_stream", &c.origin.executable_stream, o.executable_stream, 10.0 },
        { "origin_bumps", "motw_missing",      &c.origin.motw_missing,      o.motw_missing,      10.0 },
        { "pe_anomaly_bumps", "timestamp",            &c.peAnomalies.timestamp,            pa.timestamp,            10.0 },
        { "pe_anomaly_bumps", "checksum_mismatch",    &c.peAnomalies.checksum_mismatch,    pa.checksum_mismatch,    10.0 },
        { "pe_anomaly_bumps", "tls_callbacks",        &c.peAnomalies.tls_callbacks,        pa.tls_callbacks,        10.0 },
        { "pe_anomaly_bumps", "overlay_high_entropy", &c.peAnomalies.overlay_high_entropy, pa.overlay_high_entropy, 10.0 },
        { "pe_anomaly_bumps", "overlay_embedded_pe",  &c.peAnomalies.overlay_embedded_pe,  pa.overlay_embedded_pe,  10.0 },
        { "pe_anomaly_bumps", "pdb_suspicious",       &c.peAnomalies.pdb_suspicious,       pa.pdb_suspicious,       10.0 },
        { "pe_anomaly_bumps", "section_oddities",     &c.peAnomalies.section_oddities,     pa.section_oddities,     10.0 },
        { "pe_anomaly_bumps", "rlo_filename",         &c.peAnomalies.rlo_filename,         pa.rlo_filename,         10.0 },
        { "script", "weight_multiplier", &c.script.weight_multiplier, sc.weight_multiplier, 10.0 },
        { "script", "score_cap",         &c.script.score_cap,         sc.score_cap,         10.0 },
        { "revocation", "revoked", &c.revocation.revoked, r.revoked, 10.0 },
    };
}

std::vector<std::wstring> ScoringConfig::Validate()
{
    m_issues.clear();
    for (const SettingRef& s : AllSettings(*this)) {
        std::wstring name = Utf8ToWide(std::string(s.section) + "." + s.key);
        if (!std::isfinite(*s.value)) {
            m_issues.push_back(name + L" is not a number; using " + std::to_wstring(s.defaultValue));
            *s.value = s.defaultValue;
        }
        else if (*s.value < 0.0) {
            m_issues.push_back(name + L" was negative; set to 0");
            *s.value = 0.0;
        }
        else if (s.maxValue > 0.0 && *s.value > s.maxValue) {
            m_issues.push_back(name + L" above " + std::to_wstring(s.maxValue) + L"; clamped");
            *s.value = s.maxValue;
        }
    }
    // Thresholds must rise with the level.
    if (!(entropy.level1_threshold <= entropy.level2_threshold &&
          entropy.level2_threshold <= entropy.level3_threshold &&
          entropy.level3_threshold <= entropy.level4_threshold)) {
        m_issues.push_back(L"entropy thresholds were not in rising order; defaults restored");
        entropy = EntropyThresholds();
    }
    for (auto& pair : m_apiWeights) {
        if (!std::isfinite(pair.second) || pair.second < 0.0) {
            m_issues.push_back(L"api_weights." + Utf8ToWide(pair.first) + L" invalid; set to 0");
            pair.second = 0.0;
        }
        else if (pair.second > 1.0) {
            m_issues.push_back(L"api_weights." + Utf8ToWide(pair.first) + L" above 1.0; clamped");
            pair.second = 1.0;
        }
    }
    for (const std::wstring& issue : m_issues) DebugLog(L"Validation: " + issue);
    return m_issues;
}

bool ScoringConfig::LoadFromFile(const std::wstring& filePath)
{
    DebugLog(L"Loading config from: " + filePath);

    std::ifstream file(filePath);
    if (!file.is_open()) {
        DebugLog(L"Config file not found, using defaults");
        return false;
    }

    std::vector<SettingRef> settings = AllSettings(*this);
    std::string currentSection;
    std::string line;

    while (std::getline(file, line)) {
        line = TrimString(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;

        if (line[0] == '[') {
            size_t end = line.find(']');
            if (end != std::string::npos) {
                currentSection = TrimString(line.substr(1, end - 1));
                std::transform(currentSection.begin(), currentSection.end(), currentSection.begin(), ::tolower);
            }
            continue;
        }

        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = TrimString(line.substr(0, eq));
        std::string val = TrimString(line.substr(eq + 1));

        if (currentSection == "api_weights") {
            m_apiWeights[key] = ParseDouble(val, 0.0);
            continue;
        }
        for (SettingRef& s : settings) {
            if (currentSection == s.section && key == s.key) {
                *s.value = ParseDouble(val, *s.value);
                break;
            }
        }
    }

    Validate();
    DebugLog(L"Config loaded: " + std::to_wstring(m_apiWeights.size()) + L" API weight overrides, "
        + std::to_wstring(m_issues.size()) + L" validation issue(s)");
    return true;
}

bool ScoringConfig::SaveToFile(const std::wstring& filePath) const
{
    DebugLog(L"Saving config template to: " + filePath);

    std::ofstream file(filePath);
    if (!file.is_open()) {
        DebugLog(L"Failed to open file for writing");
        return false;
    }

    file << "# Phantom Recon Scoring Configuration\n";
    file << "# Edit values below to customize malware scoring behavior.\n";
    file << "# Negative values are treated as 0. Delete this file to revert to built-in defaults.\n";

    ScoringConfig& self = const_cast<ScoringConfig&>(*this);
    std::string lastSection;
    for (const SettingRef& s : AllSettings(self)) {
        if (lastSection != s.section) {
            file << "\n[" << s.section << "]\n";
            lastSection = s.section;
        }
        file << s.key << "=" << *s.value << "\n";
    }

    file << "\n# Override individual API weights below (0.0 to 1.0).\n";
    file << "# Only APIs listed here are overridden; unlisted APIs keep built-in defaults.\n";
    file << "[api_weights]\n";
    file << "# VirtualAllocEx=0.8\n";
    file << "# WriteProcessMemory=0.9\n";
    file << "# CreateRemoteThread=0.9\n";
    for (const auto& pair : m_apiWeights) {
        file << pair.first << "=" << pair.second << "\n";
    }

    DebugLog(L"Config template saved");
    return true;
}

double ScoringConfig::GetAPIWeight(const std::string& apiName) const
{
    auto it = m_apiWeights.find(apiName);
    return it != m_apiWeights.end() ? it->second : -1.0;
}

void ScoringConfig::SetAPIWeight(const std::string& apiName, double weight)
{
    m_apiWeights[apiName] = weight;
}
