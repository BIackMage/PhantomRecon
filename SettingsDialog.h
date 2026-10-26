#pragma once

#include <windows.h>
#include <string>
#include "LLMClient.h"

// ---------------------------------------------------------------------------
// SettingsDialog — modal settings dialog for configuring LLM connection
// and other application preferences.
//
// Displays:
//   - LLM endpoint URL
//   - Model name
//   - Max tokens
//   - Temperature
//   - Test Connection button with status feedback
//   - Save / Cancel buttons
//
// Settings are persisted to an INI file (phantom_recon_settings.ini).
// ---------------------------------------------------------------------------

struct AppSettings {
    // LLM configuration. Defaults come from LLMConfig so the two cannot drift.
    std::wstring llmEndpoint = LLMConfig{}.endpoint;
    std::string  llmModel = LLMConfig{}.model;
    int          llmMaxTokens = LLMConfig{}.maxTokens;
    double       llmTemperature = LLMConfig{}.temperature;
};

// Show the settings dialog (modal). Returns true if user saved changes.
bool ShowSettingsDialog(HWND hParent, HINSTANCE hInst);

// Load settings from INI file. Returns defaults if file doesn't exist.
AppSettings LoadAppSettings();

// Save settings to INI file.
void SaveAppSettings(const AppSettings& settings);

// Apply loaded settings to the LLM client singleton.
void ApplySettingsToLLMClient(const AppSettings& settings);

// Settings menu ID
#define ID_SETTINGS 32780
