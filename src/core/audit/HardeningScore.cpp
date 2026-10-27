#include "pch.h"
#include "HardeningScore.h"

#include "CheckCatalog.h"

#include <cmath>

std::wstring HardeningLabel(int score)
{
    if (score >= 90) return L"Strong";
    if (score >= 75) return L"Good";
    if (score >= 50) return L"Fair";
    return L"Weak";
}

HardeningScore ComputeHardeningScore(const std::vector<SecurityCheckResult>& results)
{
    HardeningScore s;
    for (const SecurityCheckResult& r : results) {
        if (r.status == CHECK_PASS) s.pass++;
        else if (r.status == CHECK_WARNING) s.warn++;
        else if (r.status == CHECK_FAIL) s.fail++;
        else if (r.status == CHECK_NA) s.notApplicable++;
        else if (r.status == CHECK_ERROR) s.error++;
        else s.info++;

        const CheckInfo* info = FindCheckInfo(r.id);
        if (info && !info->scored) continue;   // counted above, never weighed (events, not settings)
        int weight = info ? SeverityWeight(info->severity) : 0;
        if (weight == 0) continue;

        double earned = -1.0;
        if (r.status == CHECK_PASS) earned = weight;
        else if (r.status == CHECK_WARNING) earned = weight / 2.0;
        else if (r.status == CHECK_FAIL) earned = 0.0;
        if (earned < 0.0) continue;

        s.counted++;
        s.earned += earned;
        s.possible += weight;
    }
    s.score = s.possible > 0.0 ? static_cast<int>(std::lround(100.0 * s.earned / s.possible)) : 0;
    s.label = s.possible > 0.0 ? HardeningLabel(s.score) : L"Not scored";
    return s;
}
