#pragma once

#include <string>
#include <unordered_map>
#include <vector>

// ---------------------------------------------------------------------------
// ScoringConfig: loads configurable scoring weights from an INI-style file.
//
// File format (phantom_recon_scoring.ini next to the exe):
//   [entropy_thresholds]  level1_threshold=6.5 ...
//   [scoring_weights]     unsigned_penalty=2.0 ...
//   [anomaly_bumps]       hash_mismatch=3.0 ...
//   [packing]             confidence_threshold=0.4
//   [origin_bumps]        internet_unsigned=2.0 ...
//   [pe_anomaly_bumps]    checksum_mismatch=1.0 ...
//   [script]              weight_multiplier=0.5 ...
//   [revocation]          revoked=2.0
//   [api_weights]         VirtualAllocEx=0.8 ...
//
// Every value is validated on load: negatives become 0, NaN and infinity fall
// back to the default, and the problems are listed in LastValidationIssues().
// ---------------------------------------------------------------------------

struct EntropyThresholds {
    double level1_threshold = 6.5;  double level1_score = 0.5;
    double level2_threshold = 6.8;  double level2_score = 1.0;
    double level3_threshold = 7.0;  double level3_score = 2.0;
    double level4_threshold = 7.5;  double level4_score = 2.5;
};

struct ScoringWeights {
    double unsigned_penalty         = 2.0;
    double hidden_penalty           = 1.0;
    double temp_dir_penalty         = 1.0;
    double import_weight_multiplier = 0.4;
    double category_diversity_bonus = 0.15;
    double import_score_cap         = 3.5;
    double score_cap                = 10.0;
};

struct AnomalyBumps {
    double hash_mismatch    = 3.0;
    double untrusted_chain  = 1.5;
    double packing          = 1.5;
    double rwx_sections     = 1.0;
};

struct PackingConfig {
    double confidence_threshold = 0.4;
};

struct OriginBumps {
    double internet_unsigned = 2.0;   // Mark of the Web zone 3 on an unsigned executable
    double restricted_zone   = 3.0;   // Mark of the Web zone 4
    double executable_stream = 2.0;   // program or script hidden in an alternate data stream
    double motw_missing      = 0.5;   // executable in Downloads / Desktop with no download mark
};

struct PeAnomalyBumps {
    double timestamp            = 0.5;
    double checksum_mismatch    = 1.0;
    double tls_callbacks        = 0.3;
    double overlay_high_entropy = 0.8;
    double overlay_embedded_pe  = 2.0;
    double pdb_suspicious       = 1.5;
    double section_oddities     = 0.5;
    double rlo_filename         = 3.0;
};

struct ScriptScoring {
    double weight_multiplier = 0.5;   // script score (0-10) * multiplier is added
    double score_cap         = 4.0;   // maximum contribution of the script score
};

struct RevocationBumps {
    double revoked = 2.0;
};

class ScoringConfig {
public:
    ScoringConfig();

    // Load from INI file. Returns true on success, false if the file is missing.
    // Defaults are kept for anything the file does not set.
    bool LoadFromFile(const std::wstring& filePath);

    // Write current config (including defaults) to an INI file.
    bool SaveToFile(const std::wstring& filePath) const;

    // Restore every built-in default and clear API overrides.
    void ResetToDefaults();

    // Clamp negatives and replace non-finite values. Returns the issues found.
    std::vector<std::wstring> Validate();
    const std::vector<std::wstring>& LastValidationIssues() const { return m_issues; }

    // Configured weight for an API name, or -1.0 if not overridden.
    double GetAPIWeight(const std::string& apiName) const;
    void SetAPIWeight(const std::string& apiName, double weight);

    EntropyThresholds entropy;
    ScoringWeights    weights;
    AnomalyBumps      anomalies;
    PackingConfig     packing;
    OriginBumps       origin;
    PeAnomalyBumps    peAnomalies;
    ScriptScoring     script;
    RevocationBumps   revocation;

private:
    std::unordered_map<std::string, double> m_apiWeights;
    std::vector<std::wstring>               m_issues;

    static std::string TrimString(const std::string& s);
    static double ParseDouble(const std::string& s, double defaultVal);
};

// Global singleton (loaded once at startup)
ScoringConfig& GetScoringConfig();
