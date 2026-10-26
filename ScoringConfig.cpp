#include "pch.h"
#include "ScoringConfig.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <windows.h>

// ---------------------------------------------------------------------------
// Debug logging
// ---------------------------------------------------------------------------
static void DebugLog(const wchar_t* msg)
{
    OutputDebugStringW(L"[ScoringConfig] ");
    OutputDebugStringW(msg);
    OutputDebugStringW(L"\n");
}

static void DebugLog(const std::wstring& msg) { DebugLog(msg.c_str()); }

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------
ScoringConfig& GetScoringConfig()
{
    static ScoringConfig instance;
    return instance;
}

// ---------------------------------------------------------------------------
// Constructor — all defaults set via member initializers in the header
// ---------------------------------------------------------------------------
ScoringConfig::ScoringConfig() {}

// ---------------------------------------------------------------------------
// Trim whitespace
// ---------------------------------------------------------------------------
std::string ScoringConfig::TrimString(const std::string& s)
{
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// ---------------------------------------------------------------------------
// Parse double with fallback
// ---------------------------------------------------------------------------
double ScoringConfig::ParseDouble(const std::string& s, double defaultVal)
{
    try {
        return std::stod(s);
    }
    catch (...) {
        return defaultVal;
    }
}

// ---------------------------------------------------------------------------
// LoadFromFile
// ---------------------------------------------------------------------------
bool ScoringConfig::LoadFromFile(const std::wstring& filePath)
{
    DebugLog(L"Loading config from: " + filePath);

    std::ifstream file(filePath);
    if (!file.is_open()) {
        DebugLog(L"Config file not found, using defaults");
        return false;
    }

    std::string currentSection;
    std::string line;
    int lineNum = 0;

    while (std::getline(file, line)) {
        lineNum++;
        line = TrimString(line);

        // Skip empty lines and comments
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }

        // Section header
        if (line[0] == '[') {
            size_t end = line.find(']');
            if (end != std::string::npos) {
                currentSection = TrimString(line.substr(1, end - 1));
                std::transform(currentSection.begin(), currentSection.end(),
                    currentSection.begin(), ::tolower);
            }
            continue;
        }

        // Key=Value pair
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = TrimString(line.substr(0, eq));
        std::string val = TrimString(line.substr(eq + 1));

        if (currentSection == "entropy_thresholds") {
            if      (key == "level1_threshold") entropy.level1_threshold = ParseDouble(val, entropy.level1_threshold);
            else if (key == "level1_score")     entropy.level1_score     = ParseDouble(val, entropy.level1_score);
            else if (key == "level2_threshold") entropy.level2_threshold = ParseDouble(val, entropy.level2_threshold);
            else if (key == "level2_score")     entropy.level2_score     = ParseDouble(val, entropy.level2_score);
            else if (key == "level3_threshold") entropy.level3_threshold = ParseDouble(val, entropy.level3_threshold);
            else if (key == "level3_score")     entropy.level3_score     = ParseDouble(val, entropy.level3_score);
            else if (key == "level4_threshold") entropy.level4_threshold = ParseDouble(val, entropy.level4_threshold);
            else if (key == "level4_score")     entropy.level4_score     = ParseDouble(val, entropy.level4_score);
        }
        else if (currentSection == "scoring_weights") {
            if      (key == "unsigned_penalty")         weights.unsigned_penalty         = ParseDouble(val, weights.unsigned_penalty);
            else if (key == "hidden_penalty")           weights.hidden_penalty           = ParseDouble(val, weights.hidden_penalty);
            else if (key == "temp_dir_penalty")         weights.temp_dir_penalty         = ParseDouble(val, weights.temp_dir_penalty);
            else if (key == "import_weight_multiplier") weights.import_weight_multiplier = ParseDouble(val, weights.import_weight_multiplier);
            else if (key == "category_diversity_bonus") weights.category_diversity_bonus = ParseDouble(val, weights.category_diversity_bonus);
            else if (key == "import_score_cap")         weights.import_score_cap         = ParseDouble(val, weights.import_score_cap);
            else if (key == "score_cap")                weights.score_cap                = ParseDouble(val, weights.score_cap);
        }
        else if (currentSection == "anomaly_bumps") {
            if      (key == "hash_mismatch")   anomalies.hash_mismatch   = ParseDouble(val, anomalies.hash_mismatch);
            else if (key == "untrusted_chain") anomalies.untrusted_chain = ParseDouble(val, anomalies.untrusted_chain);
            else if (key == "packing")         anomalies.packing         = ParseDouble(val, anomalies.packing);
            else if (key == "rwx_sections")    anomalies.rwx_sections    = ParseDouble(val, anomalies.rwx_sections);
        }
        else if (currentSection == "packing") {
            if (key == "confidence_threshold") packing.confidence_threshold = ParseDouble(val, packing.confidence_threshold);
        }
        else if (currentSection == "api_weights") {
            // API names are case-sensitive (Windows API names)
            m_apiWeights[key] = ParseDouble(val, 0.0);
        }
    }

    file.close();

    std::wstringstream ss;
    ss << L"Config loaded: " << m_apiWeights.size() << L" API weight overrides";
    DebugLog(ss.str());

    return true;
}

// ---------------------------------------------------------------------------
// SaveToFile — write current config as a template INI
// ---------------------------------------------------------------------------
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
    file << "# Delete this file to revert to built-in defaults.\n\n";

    file << "[entropy_thresholds]\n";
    file << "level1_threshold=" << entropy.level1_threshold << "\n";
    file << "level1_score="     << entropy.level1_score     << "\n";
    file << "level2_threshold=" << entropy.level2_threshold << "\n";
    file << "level2_score="     << entropy.level2_score     << "\n";
    file << "level3_threshold=" << entropy.level3_threshold << "\n";
    file << "level3_score="     << entropy.level3_score     << "\n";
    file << "level4_threshold=" << entropy.level4_threshold << "\n";
    file << "level4_score="     << entropy.level4_score     << "\n\n";

    file << "[scoring_weights]\n";
    file << "unsigned_penalty="         << weights.unsigned_penalty         << "\n";
    file << "hidden_penalty="           << weights.hidden_penalty           << "\n";
    file << "temp_dir_penalty="         << weights.temp_dir_penalty         << "\n";
    file << "import_weight_multiplier=" << weights.import_weight_multiplier << "\n";
    file << "category_diversity_bonus=" << weights.category_diversity_bonus << "\n";
    file << "import_score_cap="         << weights.import_score_cap         << "\n";
    file << "score_cap="                << weights.score_cap                << "\n\n";

    file << "[anomaly_bumps]\n";
    file << "hash_mismatch="   << anomalies.hash_mismatch   << "\n";
    file << "untrusted_chain=" << anomalies.untrusted_chain << "\n";
    file << "packing="         << anomalies.packing         << "\n";
    file << "rwx_sections="    << anomalies.rwx_sections    << "\n\n";

    file << "[packing]\n";
    file << "confidence_threshold=" << packing.confidence_threshold << "\n\n";

    file << "# Override individual API weights below.\n";
    file << "# Only APIs listed here will be overridden; unlisted APIs keep built-in defaults.\n";
    file << "# Format: APIName=weight (0.0 to 1.0)\n";
    file << "[api_weights]\n";
    file << "# VirtualAllocEx=0.8\n";
    file << "# WriteProcessMemory=0.9\n";
    file << "# CreateRemoteThread=0.9\n";

    // Write any currently-set overrides
    for (const auto& pair : m_apiWeights) {
        file << pair.first << "=" << pair.second << "\n";
    }

    file.close();
    DebugLog(L"Config template saved");
    return true;
}

// ---------------------------------------------------------------------------
// GetAPIWeight
// ---------------------------------------------------------------------------
double ScoringConfig::GetAPIWeight(const std::string& apiName) const
{
    auto it = m_apiWeights.find(apiName);
    if (it != m_apiWeights.end()) {
        return it->second;
    }
    return -1.0; // not overridden
}

// ---------------------------------------------------------------------------
// SetAPIWeight
// ---------------------------------------------------------------------------
void ScoringConfig::SetAPIWeight(const std::string& apiName, double weight)
{
    m_apiWeights[apiName] = weight;
}
