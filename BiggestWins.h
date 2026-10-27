#pragma once

#include <string>
#include <vector>

#include "CheckCatalog.h"
#include "SecurityChecks.h"

// ---------------------------------------------------------------------------
// BiggestWins: where to start. The scored FAIL and WARNING checks whose fix raises
// the hardening score the most, with the points each one adds.
//
// The gain of a check is the weight it would earn as PASS: its full severity weight
// for a FAIL, half of it for a WARNING (the score's own weights, HardeningScore.h).
// Order: the larger gain first; on a tie the higher severity, then the catalog's
// report order. Unscored checks, checks with weight 0 and checks the catalog does not
// know never appear.
//
// The total comes from ComputeHardeningScore itself: scoreAfter is the real score with
// every listed win turned to PASS, and totalPoints = scoreAfter - scoreBefore. That
// total is split over the wins by largest remainder of their exact shares
// (100 * gain / possible weight): the points add up exactly to the total, and a win
// never shows fewer points than one below it. A very small gain can show as +0.
// ---------------------------------------------------------------------------

struct ScoreWin {
    std::wstring id;
    std::wstring title;          // catalog title
    std::wstring status;         // FAIL or WARNING
    Severity     severity = Severity::Info;
    double       weight = 0.0;   // earned weight the fix adds
    int          points = 0;     // its share of totalPoints (whole points, they add up)
};

struct BiggestWinsResult {
    int scoreBefore = 0;
    int scoreAfter = 0;          // the score with every listed win turned to PASS
    int totalPoints = 0;         // scoreAfter - scoreBefore, the sum of the points
    std::vector<ScoreWin> wins;  // at most the limit given, best first
};

BiggestWinsResult ComputeBiggestWins(const std::vector<SecurityCheckResult>& results, size_t limit = 5);

// 1 for the first win, 0 when id is not in the list.
int BiggestWinRank(const BiggestWinsResult& wins, const std::wstring& id);

// "Fix these 5 and the score goes from 60 to 81." Empty when there is no win.
std::wstring BiggestWinsHeadline(const BiggestWinsResult& wins);

// The plain-text block for the console and the text report: a heading, the headline,
// one line per win ("  1. +7  User Account Control (hard.uac, FAIL)"). Lines end in
// lineEnd. Empty when there is no win.
std::wstring BiggestWinsText(const BiggestWinsResult& wins, const std::wstring& lineEnd);
