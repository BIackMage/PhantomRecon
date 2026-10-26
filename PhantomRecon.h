#pragma once


#include "framework.h"
#include "resource.h"
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <thread>
#include <tchar.h>
#include <Shlwapi.h>
#include <algorithm>
#include <fstream>
#include <ios>
#include <cstdio>
#include <wincrypt.h>
#include <atomic>
#include <mutex>
#include <iomanip>

#include "FileAnalysis.h"
#include "MalwareScoring.h"
#include "SecurityChecks.h"
#include "ScanTypes.h"
#include "Baseline.h"
#include "RegistryEnumerator.h"
#include "HashUtils.h"
#include "ScoringConfig.h"
#include "GuiComponents.h"
#include "AiSidebar.h"
#include "LLMClient.h"
#include "DarkMode.h"
#include "SettingsDialog.h"
#include <commdlg.h>
#include <commctrl.h>

#pragma comment(lib, "comctl32.lib")

#define MAX_LOADSTRING 100

// file structure... can expand later
struct FileInfo {
    std::wstring path;
    std::wstring baseName;
    std::wstring version;
};


// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name
std::vector<FileInfo> executableFiles;          // Global vector to store file information
HWND hSystemInfoTitle = NULL;                   // Handle for "System Information" title
HWND hSystemInfoLabel;                          // Handle for displaying scan info
HWND hOperationInfoTitle = NULL;                // Handle for "Current Operation Information" title
HWND hOperationInfoLabel;                       // Handle for displaying permanent info
HWND hProgressBar = NULL;                       // Handle for scan progress bar
HWND hResultsListView = NULL;                   // Handle for results ListView
extern std::wstring g_DefaultOutputPath = L"output.csv";        // Default output path (user picks via Save dialog)

// AI Sidebar state
AiSidebarState g_aiSidebar;

// Default baseline file path (alongside the executable)
extern std::wstring g_BaselineFilePath = L"phantom_recon_baseline.prbl";

// Global variables to keep track of counts (thread-safe)
std::atomic<int> totalFilesProcessed = 0;
std::atomic<int> totalExecutables = 0;
std::mutex scanStringMutex;  // Protects currentFile, currentFileFullPath, scanState
std::wstring currentFile;
std::wstring currentFileFullPath;
std::wstring scanState = L"Stopped";
std::atomic<bool> cancelScanRequested = false;

// Current loaded baseline (used by Full Scan and Fast Scan for comparison)
Baseline g_currentBaseline;
std::mutex g_baselineMutex;  // Protects g_currentBaseline

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);
void                ScanDirectory(const std::wstring& directory, HWND hWnd, ScanMode mode, Baseline* baseline);
void                ScanFileList(const std::vector<std::wstring>& filePaths, HWND hWnd, ScanMode mode, Baseline* baseline);
BaselineEntry       AnalyzeFile(const std::wstring& fullPath);
void                CreateTitlesAndLabels(HWND hWnd);
void                UpdateLabels(HWND hWnd);
void                StartScanInBackground(ScanMode mode, const std::wstring& directory, HWND hWnd);
void                CancelScan();
LRESULT CALLBACK    ButtonClickHandler(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
bool                PromptForOutputPath(HWND hWnd, std::wstring& outPath);
void                AppendToCSV(const std::wstring& data, const std::wstring& outputPath = g_DefaultOutputPath);
void                AppendToCSVWithComparison(const BaselineEntry& entry, const ComparisonResult& comparison,
                        const std::wstring& outputPath = g_DefaultOutputPath);
std::streampos      getFileSize(const std::wstring& filename);
bool                computeFileMD5(const std::wstring& filePath, BYTE** hash, DWORD* hashSize);
double              calculateEntropy(const std::wstring& filename);
void                UpdateSystem(HWND hWnd);
void                RunSecurityAuditInBackground(HWND hWnd);
