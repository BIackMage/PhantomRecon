#pragma once

#include <string>
#include <unordered_map>

// ---------------------------------------------------------------------------
// ScoringConfig — loads configurable scoring weights from an INI-style file.
//
// File format (phantom_recon_scoring.ini):
//   [entropy_thresholds]
//   level1_threshold=6.5
//   level1_score=0.5
//   ...
//   [scoring_weights]
//   unsigned_penalty=2.0
//   ...
//   [anomaly_bumps]
//   hash_mismatch=3.0
//   ...
//   [packing]
//   confidence_threshold=0.4
//   ...
//   [api_weights]
//   VirtualAllocEx=0.8
//   ...
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

class ScoringConfig {
public:
    ScoringConfig();

    // Load from INI file. Returns true on success, false if file missing/invalid.
    // On failure, defaults are preserved (safe to use without a config file).
    bool LoadFromFile(const std::wstring& filePath);

    // Write current config (including defaults) to an INI file.
    // Useful for generating a template config.
    bool SaveToFile(const std::wstring& filePath) const;

    // Look up the weight for a specific API name.
    // Returns the configured weight, or -1.0 if not found.
    double GetAPIWeight(const std::string& apiName) const;

    // Set/override the weight for a specific API name.
    void SetAPIWeight(const std::string& apiName, double weight);

    // Public config sections (direct access for performance in hot paths)
    EntropyThresholds entropy;
    ScoringWeights    weights;
    AnomalyBumps      anomalies;
    PackingConfig     packing;

private:
    // API name -> weight override map
    std::unordered_map<std::string, double> m_apiWeights;

    // Parse helpers
    static std::string TrimString(const std::string& s);
    static double ParseDouble(const std::string& s, double defaultVal);
};

// Global singleton (loaded once at startup)
ScoringConfig& GetScoringConfig();
