#pragma once

#include <windows.h>
#include <string>
#include "BackgroundWorker.h"
#include "LLMClient.h"

// ---------------------------------------------------------------------------
// SettingsDialog: modal window for the LLM connection settings.
//
// Shows endpoint URL, model name, max tokens, temperature, a Test Connection
// button with a status line, and Save / Cancel. Settings persist to
// phantom_recon_settings.ini next to the exe.
//
// The connection test runs on the shared BackgroundWorker and posts
// WM_APP_STATUS_TEXT back to the dialog. The dialog never blocks the UI.
// ---------------------------------------------------------------------------

struct AppSettings {
    // LLM configuration. Defaults come from LLMConfig so the two cannot drift.
    std::wstring llmEndpoint = LLMConfig{}.endpoint;
    std::string  llmModel = LLMConfig{}.model;
    int          llmMaxTokens = LLMConfig{}.maxTokens;
    double       llmTemperature = LLMConfig{}.temperature;
};

// Show the settings dialog (modal). Returns true if the user saved changes.
bool ShowSettingsDialog(HWND hParent, HINSTANCE hInst, BackgroundWorker& worker);

// Load settings from the INI file. Returns defaults if the file does not exist.
AppSettings LoadAppSettings();

// Save settings to the INI file.
void SaveAppSettings(const AppSettings& settings);

// Apply loaded settings to the LLM client singleton.
void ApplySettingsToLLMClient(const AppSettings& settings);

// Settings menu ID (inserted into the File menu at runtime)
#define ID_SETTINGS 32780
