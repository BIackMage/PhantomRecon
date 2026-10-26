#pragma once

#include <string>

// ---------------------------------------------------------------------------
// SettingsValues: checks for the values the window program keeps in
// phantom_recon_settings.ini. No windows, so the tests can reach them.
// ---------------------------------------------------------------------------

// The AI temperature from text typed in Settings or read from the INI. Text that
// is not a number, "nan" and "inf" give fallback; numbers are kept within 0 to 2.
// The result is always finite, so the request JSON stays valid.
double ParseTemperatureText(const std::wstring& text, double fallback);

// The same rule for a number already parsed.
double SanitizeTemperature(double value, double fallback);

// Make sure the INI file is stored as UTF-16 LE with a BOM before
// WritePrivateProfileStringW touches it. Windows writes INI files in the ANSI code
// page unless the file already starts with a UTF-16 BOM, which turns Cyrillic or
// CJK folder names into "?". A missing file is created with just the BOM; an
// existing ANSI or UTF-8 file is converted in place with its content kept.
// False when the file could not be read or written.
bool EnsureUnicodeIniFile(const std::wstring& path);
