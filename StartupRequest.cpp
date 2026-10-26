#include "pch.h"
#include "StartupRequest.h"

#include "AppPaths.h"
#include "TextUtils.h"

StartupRequest ParseStartupArguments(const std::vector<std::wstring>& args)
{
    StartupRequest r;
    for (size_t i = 0; i < args.size(); ++i) {
        std::wstring lower = ToLowerW(args[i]);
        if (lower == L"--portable") continue;   // read by IsPortableMode()
        if (lower == L"--samples") {
            if (i + 1 < args.size()) r.samplesFolder = args[++i];
            else r.unknown.push_back(args[i] + L" (needs a folder)");
            continue;
        }
        std::wstring ext = ExtensionOf(args[i]);
        if (ext == L".csv" || ext == L".prbl") r.files.push_back(args[i]);
        else r.unknown.push_back(args[i]);
    }
    return r;
}
