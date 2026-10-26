#pragma once

#include <string>
#include <vector>
#include "SecurityChecks.h"

// ---------------------------------------------------------------------------
// HardeningScore: one number from 0 to 100 for the posture audit.
//
// Each check carries a weight from its severity (Critical 10, High 6,
// Medium 3, Low 1). PASS earns the full weight, WARNING half, FAIL nothing.
// INFO, N/A and ERROR results do not count either way. The score is the
// earned weight over the possible weight.
// ---------------------------------------------------------------------------

struct HardeningScore {
    int          score = 0;          // 0 - 100
    std::wstring label;              // Strong / Good / Fair / Weak
    int          counted = 0;        // checks that contributed
    int          pass = 0, warn = 0, fail = 0, info = 0, error = 0, notApplicable = 0;
    double       earned = 0.0;
    double       possible = 0.0;
};

HardeningScore ComputeHardeningScore(const std::vector<SecurityCheckResult>& results);

std::wstring HardeningLabel(int score);
