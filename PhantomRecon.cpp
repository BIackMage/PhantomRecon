// PhantomRecon.cpp : Defines the entry point for the application.
//

#include "pch.h"
#include "PhantomRecon.h"

// ---------------------------------------------------------------------------
// String conversion helpers (wstring <-> UTF-8 string)
// ---------------------------------------------------------------------------
static std::wstring ToWide(const std::string& s)
{
    if (s.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);
    if (size <= 0) return L"";
    std::wstring result(size - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &result[0], size);
    return result;
}

static std::string ToUtf8(const std::wstring& s)
{
    if (s.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, NULL, 0, NULL, NULL);
    if (size <= 0) return "";
    std::string result(size - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, &result[0], size, NULL, NULL);
    return result;
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // Initialize dark mode (must be before window creation)
    InitDarkMode();

    // Load scoring config (if file exists, otherwise use defaults)
    ScoringConfig& scoringCfg = GetScoringConfig();
    if (!scoringCfg.LoadFromFile(L"phantom_recon_scoring.ini")) {
        // No config file — generate a template for the user
        scoringCfg.SaveToFile(L"phantom_recon_scoring.ini");
        OutputDebugStringW(L"[PhantomRecon] Generated default scoring config template\n");
    }

    // Load app settings and apply to LLM client
    AppSettings appSettings = LoadAppSettings();
    ApplySettingsToLLMClient(appSettings);

    // Initialize global strings
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_PHANTOMRECON, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);
    RegisterAiSidebarClass(hInstance);

    // Perform application initialization:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_PHANTOMRECON));

    MSG msg;

    // Main message loop:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_PHANTOMRECON));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_PHANTOMRECON);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // Store instance handle in our global variable

   // Initialize common controls for ListView and ProgressBar
   InitGuiCommonControls();

   HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, 1000, 720, nullptr, nullptr, hInstance, nullptr);

   if (!hWnd)
   {
      return FALSE;
   }
   // Cancel button is created inside CreateTitlesAndLabels (next to progress bar)

   // Register the callback function for button click events
   //if (hwndButton != nullptr)
   //{
   //    SetWindowLongPtr(hwndButton, GWLP_WNDPROC, (LONG_PTR)ButtonClickHandler);
   //}

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE: Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_GETMINMAXINFO:
    {
        MINMAXINFO* mmInfo = (MINMAXINFO*)lParam;

        // Set minimum window size (main content only — AI panel is external)
        mmInfo->ptMinTrackSize.x = 800;
        mmInfo->ptMinTrackSize.y = 650;
    }
    break;
    case WM_MOVE:
    case WM_SIZE:
        RepositionAiSidebar(g_aiSidebar);
        break;
    case WM_CREATE:
    {
        CreateTitlesAndLabels(hWnd); // Create titles and labels when the window is created
        UpdateSystem(hWnd);          // Populate system info panel
        RunSecurityAuditInBackground(hWnd); // Run security audit and update panel when done

        // Create AI sidebar (slide-out panel on the right)
        CreateAiSidebar(hWnd, hInst, g_aiSidebar);

        // Add menu items to File and Scans menus programmatically
        {
            HMENU hMenuBar = GetMenu(hWnd);
            if (hMenuBar) {
                // File menu (index 0)
                HMENU hFileMenu = GetSubMenu(hMenuBar, 0);
                if (hFileMenu) {
                    // Insert items before Exit
                    InsertMenuW(hFileMenu, 0, MF_BYPOSITION | MF_STRING, ID_FILE_OPEN_SCAN, L"Open Scan Results...");
                    InsertMenuW(hFileMenu, 1, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
                    InsertMenuW(hFileMenu, 2, MF_BYPOSITION | MF_STRING, ID_FILE_OPEN_BASELINE, L"Open Baseline...");
                    InsertMenuW(hFileMenu, 3, MF_BYPOSITION | MF_STRING, ID_FILE_IMPORT_BASELINE, L"Import Baseline (Set as Active)...");
                    InsertMenuW(hFileMenu, 4, MF_BYPOSITION | MF_STRING, ID_FILE_EXPORT_BASELINE, L"Export Current Baseline...");
                    InsertMenuW(hFileMenu, 5, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
                    InsertMenuW(hFileMenu, 6, MF_BYPOSITION | MF_STRING, ID_SETTINGS, L"Settings...");
                    InsertMenuW(hFileMenu, 7, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
                }
            }
            DrawMenuBar(hWnd);
        }
        break;
    }
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // Parse the menu selections:
            switch (wmId)
            {
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;

            case ID_SETTINGS:
                ShowSettingsDialog(hWnd, hInst);
                break;

            // ----- File > Open Scan Results -----
            case ID_FILE_OPEN_SCAN:
            {
                std::wstring csvPath = BrowseForScanFile(hWnd);
                if (csvPath.empty()) break;

                std::vector<BaselineEntry> entries;
                std::vector<std::wstring> statuses;
                if (!ParseScanResultCSV(csvPath, entries, statuses)) {
                    MessageBox(hWnd, L"Failed to parse scan results file.", L"Error", MB_OK | MB_ICONERROR);
                    break;
                }

                ClearResultRows(hResultsListView);
                for (size_t i = 0; i < entries.size(); i++) {
                    AddResultRow(hResultsListView, entries[i], statuses[i]);
                }

                // Update operation info
                std::wstringstream ss;
                ss << L"Loaded " << entries.size() << L" results from:\n" << csvPath;
                SetWindowTextW(hOperationInfoLabel, ss.str().c_str());

                OutputDebugStringW((L"[PhantomRecon] Loaded " + std::to_wstring(entries.size()) + L" scan results from CSV\n").c_str());
                break;
            }

            // ----- File > Open Baseline (view / set as active for comparison) -----
            case ID_FILE_OPEN_BASELINE:
            {
                std::wstring baselinePath = BrowseForBaselineFile(hWnd);
                if (baselinePath.empty()) break;

                Baseline loadedBaseline;
                if (!loadedBaseline.LoadFromFile(baselinePath)) {
                    MessageBox(hWnd, L"Failed to load baseline file. It may be corrupted or an unsupported version.",
                        L"Error", MB_OK | MB_ICONERROR);
                    break;
                }

                // Set as active baseline
                {
                    std::lock_guard<std::mutex> lock(g_baselineMutex);
                    g_currentBaseline = loadedBaseline;
                }

                std::wstringstream ss;
                ss << L"Baseline loaded: " << loadedBaseline.Count() << L" entries\n"
                   << L"Created: " << loadedBaseline.GetCreationTimeString() << L"\n"
                   << L"Age: " << loadedBaseline.GetAgeDays() << L" days\n"
                   << L"Source: " << baselinePath;
                SetWindowTextW(hOperationInfoLabel, ss.str().c_str());

                if (loadedBaseline.IsOlderThan(30)) {
                    MessageBox(hWnd,
                        L"Warning: This baseline is more than 30 days old.\n"
                        L"Consider creating a fresh baseline for accurate comparisons.",
                        L"Baseline Age Warning", MB_OK | MB_ICONWARNING);
                }

                OutputDebugStringW((L"[PhantomRecon] Baseline opened: " + baselinePath +
                    L" (" + std::to_wstring(loadedBaseline.Count()) + L" entries)\n").c_str());
                break;
            }

            // ----- File > Import Baseline (copy to local active path) -----
            case ID_FILE_IMPORT_BASELINE:
            {
                std::wstring sourcePath = BrowseForBaselineFile(hWnd);
                if (sourcePath.empty()) break;

                // Validate it first
                Baseline importBaseline;
                if (!importBaseline.LoadFromFile(sourcePath)) {
                    MessageBox(hWnd, L"Failed to load baseline file. It may be corrupted or an unsupported version.",
                        L"Import Error", MB_OK | MB_ICONERROR);
                    break;
                }

                // Confirm overwrite if local baseline exists
                if (GetFileAttributesW(g_BaselineFilePath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                    int result = MessageBox(hWnd,
                        L"A local baseline already exists. Importing will replace it.\n\n"
                        L"Continue?",
                        L"Import Baseline", MB_YESNO | MB_ICONQUESTION);
                    if (result != IDYES) break;
                }

                // Copy file to the local baseline path
                if (!CopyFileW(sourcePath.c_str(), g_BaselineFilePath.c_str(), FALSE)) {
                    MessageBox(hWnd, L"Failed to copy baseline file to local directory.",
                        L"Import Error", MB_OK | MB_ICONERROR);
                    break;
                }

                // Set as active baseline
                {
                    std::lock_guard<std::mutex> lock(g_baselineMutex);
                    g_currentBaseline = importBaseline;
                }

                std::wstringstream ss;
                ss << L"Baseline imported: " << importBaseline.Count() << L" entries\n"
                   << L"Created: " << importBaseline.GetCreationTimeString() << L"\n"
                   << L"Source: " << sourcePath << L"\n"
                   << L"Saved to: " << g_BaselineFilePath;
                SetWindowTextW(hOperationInfoLabel, ss.str().c_str());

                MessageBox(hWnd,
                    (L"Baseline imported successfully.\n\n"
                    L"Entries: " + std::to_wstring(importBaseline.Count()) + L"\n"
                    L"Created: " + importBaseline.GetCreationTimeString() + L"\n\n"
                    L"This baseline is now active for Full Scan and Fast Scan comparisons.").c_str(),
                    L"Import Successful", MB_OK | MB_ICONINFORMATION);

                OutputDebugStringW((L"[PhantomRecon] Baseline imported from: " + sourcePath + L"\n").c_str());
                break;
            }

            // ----- File > Export Current Baseline -----
            case ID_FILE_EXPORT_BASELINE:
            {
                // Check if we have an active baseline
                std::lock_guard<std::mutex> lock(g_baselineMutex);
                if (g_currentBaseline.Count() == 0) {
                    // Try loading from default path
                    if (!g_currentBaseline.LoadFromFile(g_BaselineFilePath)) {
                        MessageBox(hWnd, L"No baseline is currently loaded.\n\n"
                            L"Run a Baseline Scan first, or open/import an existing baseline.",
                            L"No Baseline", MB_OK | MB_ICONWARNING);
                        break;
                    }
                }

                std::wstring exportPath = SaveBaselineFileDialog(hWnd);
                if (exportPath.empty()) break;

                if (!g_currentBaseline.SaveToFile(exportPath)) {
                    MessageBox(hWnd, L"Failed to export baseline file.",
                        L"Export Error", MB_OK | MB_ICONERROR);
                    break;
                }

                MessageBox(hWnd,
                    (L"Baseline exported successfully.\n\n"
                    L"Entries: " + std::to_wstring(g_currentBaseline.Count()) + L"\n"
                    L"Saved to: " + exportPath).c_str(),
                    L"Export Successful", MB_OK | MB_ICONINFORMATION);

                OutputDebugStringW((L"[PhantomRecon] Baseline exported to: " + exportPath + L"\n").c_str());
                break;
            }

            case ID_SCANS_BASELINE:
            {
                MessageBox(NULL, L"This will create a ground truth baseline of all executables on disk.\n\nOnly run this on a verified clean system!", L"Baseline Scan", MB_OK | MB_ICONINFORMATION);

                // Prompt for directory to scan
                std::wstring directoryToScan = BrowseForScanDirectory(hWnd);
                if (directoryToScan.empty()) break;

                // Prompt for output CSV location
                std::wstring outputPath;
                if (!PromptForOutputPath(hWnd, outputPath)) break;
                g_DefaultOutputPath = outputPath;

                StartScanInBackground(ScanMode::Baseline, directoryToScan, hWnd);
                break;
            }
            case ID_SCANS_FULLSCAN:
            {
                // Full Scan requires a baseline to compare against
                std::lock_guard<std::mutex> lock(g_baselineMutex);
                if (!g_currentBaseline.LoadFromFile(g_BaselineFilePath)) {
                    MessageBox(hWnd, L"No baseline found. Please run a Baseline Scan first on a known-clean system.",
                        L"Full Scan", MB_OK | MB_ICONWARNING);
                    break;
                }
                OutputDebugStringW(L"[PhantomRecon] Full Scan: loaded baseline with entries\n");

                // Warn if baseline is stale (>30 days old)
                if (g_currentBaseline.IsOlderThan(30)) {
                    std::wstringstream ageMsg;
                    ageMsg << L"Warning: Baseline is " << g_currentBaseline.GetAgeDays()
                           << L" days old (created " << g_currentBaseline.GetCreationTimeString() << L").\n\n"
                           << L"A stale baseline may produce inaccurate results.\n"
                           << L"Consider creating a fresh baseline on a verified clean system.\n\n"
                           << L"Continue with the existing baseline?";
                    if (MessageBox(hWnd, ageMsg.str().c_str(), L"Stale Baseline Warning",
                        MB_YESNO | MB_ICONWARNING) != IDYES) {
                        break;
                    }
                }

                // Prompt for directory to scan
                std::wstring directoryToScan = BrowseForScanDirectory(hWnd);
                if (directoryToScan.empty()) break;

                {
                    std::wstring outputPath;
                    if (!PromptForOutputPath(hWnd, outputPath)) break;
                    g_DefaultOutputPath = outputPath;
                }
                g_currentBaseline.ResetSeenFlags();
                StartScanInBackground(ScanMode::FullScan, directoryToScan, hWnd);
                break;
            }
            case ID_SCANS_FASTSCAN:
            {
                // Fast Scan requires a baseline to compare against
                std::lock_guard<std::mutex> lock(g_baselineMutex);
                if (!g_currentBaseline.LoadFromFile(g_BaselineFilePath)) {
                    MessageBox(hWnd, L"No baseline found. Please run a Baseline Scan first on a known-clean system.",
                        L"Fast Scan", MB_OK | MB_ICONWARNING);
                    break;
                }
                OutputDebugStringW(L"[PhantomRecon] Fast Scan: loaded baseline, enumerating installed programs\n");

                // Warn if baseline is stale (>30 days old)
                if (g_currentBaseline.IsOlderThan(30)) {
                    std::wstringstream ageMsg;
                    ageMsg << L"Warning: Baseline is " << g_currentBaseline.GetAgeDays()
                           << L" days old (created " << g_currentBaseline.GetCreationTimeString() << L").\n\n"
                           << L"A stale baseline may produce inaccurate results.\n"
                           << L"Consider creating a fresh baseline on a verified clean system.\n\n"
                           << L"Continue with the existing baseline?";
                    if (MessageBox(hWnd, ageMsg.str().c_str(), L"Stale Baseline Warning",
                        MB_YESNO | MB_ICONWARNING) != IDYES) {
                        break;
                    }
                }

                {
                    std::wstring outputPath;
                    if (!PromptForOutputPath(hWnd, outputPath)) break;
                    g_DefaultOutputPath = outputPath;
                }
                g_currentBaseline.ResetSeenFlags();
                StartScanInBackground(ScanMode::FastScan, L"", hWnd);
                break;
            }
            case ID_BUTTON_CANCEL:
                cancelScanRequested = true;
                break;

            // --- AI Sidebar buttons ---
            case ID_AI_TOGGLE:
                ToggleAiSidebar(g_aiSidebar);
                break;
            case ID_AI_SEND:
            {
                wchar_t inputText[2048] = {};
                GetWindowTextW(g_aiSidebar.hInputField, inputText, 2048);
                SendUserMessage(g_aiSidebar, inputText);
                break;
            }
            case ID_AI_TRIAGE:
            {
                // Triage the currently selected file in the results ListView
                if (hResultsListView) {
                    int sel = ListView_GetNextItem(hResultsListView, -1, LVNI_SELECTED);
                    if (sel >= 0) {
                        // Get the file path from column 0 (display name)
                        // For a full implementation, we'd store entries and look up by index
                        wchar_t pathBuf[512] = {};
                        ListView_GetItemText(hResultsListView, sel, 0, pathBuf, 512);
                        wchar_t scoreBuf[32] = {};
                        ListView_GetItemText(hResultsListView, sel, 2, scoreBuf, 32);
                        wchar_t sigBuf[256] = {};
                        ListView_GetItemText(hResultsListView, sel, 4, sigBuf, 256);
                        wchar_t packBuf[256] = {};
                        ListView_GetItemText(hResultsListView, sel, 5, packBuf, 256);

                        BaselineEntry triageEntry;
                        triageEntry.path = pathBuf;
                        triageEntry.malwareScore = _wtof(scoreBuf);
                        triageEntry.signature = sigBuf;
                        triageEntry.packingStatus = packBuf;
                        TriageSelectedFile(g_aiSidebar, triageEntry);
                    }
                    else {
                        AppendToChatDisplay(g_aiSidebar, L"\r\n[Info]: Select a file in the results list first.\r\n");
                    }
                }
                break;
            }
            case ID_AI_SUMMARY:
            {
                // Build a scan summary prompt
                AppendToChatDisplay(g_aiSidebar, L"\r\n[Summary]: Generating scan summary...\r\n");
                SetAiStatusText(g_aiSidebar, L"AI: Analyzing scan...");
                std::string prompt = BuildScanSummaryPrompt(
                    totalFilesProcessed.load(), totalExecutables.load(), 0, 0, 0, 0);

                std::thread([prompt]() {
                    std::vector<LLMMessage> messages = {
                        { "system", "You are a cybersecurity analyst. Analyze scan results concisely." },
                        { "user", prompt }
                    };
                    std::string response = GetLLMClient().SendChatCompletion(messages);
                    if (!response.empty()) {
                        std::wstring wResp = ToWide(response);
                        AppendToChatDisplay(g_aiSidebar, L"\r\n[AI Summary]:\r\n" + wResp + L"\r\n");
                    }
                    SetAiStatusText(g_aiSidebar, L"AI: Ready");
                }).detach();
                break;
            }
            case ID_AI_AUDIT:
            {
                // Run security audit through LLM
                AppendToChatDisplay(g_aiSidebar, L"\r\n[Audit]: Analyzing security audit...\r\n");
                SetAiStatusText(g_aiSidebar, L"AI: Analyzing audit...");

                std::thread([]() {
                    // Get current audit text from the system info label
                    wchar_t auditBuf[4096] = {};
                    GetWindowTextW(hSystemInfoLabel, auditBuf, 4096);
                    std::wstring auditText = auditBuf;
                    std::string auditUtf8 = ToUtf8(auditText);

                    std::string prompt = BuildSecurityAuditPrompt(auditUtf8);
                    std::vector<LLMMessage> messages = {
                        { "system", "You are a cybersecurity analyst. Analyze this audit report." },
                        { "user", prompt }
                    };
                    std::string response = GetLLMClient().SendChatCompletion(messages);
                    if (!response.empty()) {
                        std::wstring wResp = ToWide(response);
                        AppendToChatDisplay(g_aiSidebar, L"\r\n[AI Audit Analysis]:\r\n" + wResp + L"\r\n");
                    }
                    SetAiStatusText(g_aiSidebar, L"AI: Ready");
                }).detach();
                break;
            }
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            EndPaint(hWnd, &ps);
        }
        break;

    // --- Dark mode color handlers ---
    case WM_ERASEBKGND:
        return HandleDarkEraseBkgnd((HDC)wParam, hWnd);

    case WM_CTLCOLORSTATIC:
        return (LRESULT)HandleDarkCtlColorStatic((HDC)wParam);

    case WM_CTLCOLOREDIT:
        return (LRESULT)HandleDarkCtlColorEdit((HDC)wParam);

    case WM_CTLCOLORBTN:
        return (LRESULT)HandleDarkCtlColorBtn((HDC)wParam);

    case WM_NOTIFY:
    {
        LPNMHDR pnmh = reinterpret_cast<LPNMHDR>(lParam);
        if (pnmh->hwndFrom == hResultsListView && pnmh->code == NM_CUSTOMDRAW) {
            return HandleDarkResultsCustomDraw(lParam);
        }
        break;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}


// ---------------------------------------------------------------------------
// AnalyzeFile — run all analysis passes on a single file, return BaselineEntry
// This is the extracted core from the old ScanDirectory inline analysis.
// ---------------------------------------------------------------------------
BaselineEntry AnalyzeFile(const std::wstring& fullPath)
{
    OutputDebugStringW((L"[PhantomRecon] AnalyzeFile: " + fullPath + L"\n").c_str());

    BaselineEntry entry;
    entry.path = fullPath;

    // File size
    std::streampos fileSizePos = getFileSize(fullPath);
    entry.fileSize = static_cast<int64_t>(fileSizePos);

    // MD5 hash
    BYTE* hash = NULL;
    DWORD hashSize = 0;
    if (computeFileMD5(fullPath, &hash, &hashSize)) {
        for (DWORD i = 0; i < hashSize; ++i) {
            wchar_t hex[3];
            swprintf(hex, sizeof(hex), L"%02x", hash[i]);
            entry.md5 += hex;
        }
        free(hash);
    }
    else {
        entry.md5 = L"MD5 Checksum Error";
    }

    // SHA-256 hash
    entry.sha256 = ComputeFileSHA256(fullPath);
    if (entry.sha256.empty()) {
        entry.sha256 = L"SHA256 Checksum Error";
    }

    // Full signature analysis (single pass — extracts status, signer, chain, warnings)
    SignatureInfo sigInfo = AnalyzeFileSignature(fullPath);

    // Build signature column: status + signer name
    entry.signature = sigInfo.status;
    if (sigInfo.signerName != L"N/A") {
        entry.signature += L" (" + sigInfo.signerName + L")";
    }
    entry.signatureType = sigInfo.signatureType;
    entry.thumbprint = sigInfo.thumbprint;
    entry.issuer = sigInfo.issuerName;
    entry.rootCA = sigInfo.rootCA;

    // Build signature warnings string
    for (size_t w = 0; w < sigInfo.warnings.size(); w++) {
        if (w > 0) entry.sigWarnings += L"; ";
        entry.sigWarnings += sigInfo.warnings[w];
    }

    entry.version = GetFileVersion(fullPath);
    entry.developer = GetFileDeveloper(fullPath);
    entry.readOnly = GetFileReadOnly(fullPath);
    entry.hidden = GetFileHidden(fullPath);
    entry.permissions = GetFilePermissions(fullPath);
    entry.entropy = calculateEntropy(fullPath);

    // Static analysis: scan PE imports and compute malware score
    bool isSigned = sigInfo.hashValid && sigInfo.chainTrusted;
    bool isHidden = (entry.hidden == L"Yes");
    std::wstring lowerPath = fullPath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
    bool isInTempDir = (lowerPath.find(L"\\temp\\") != std::wstring::npos
        || lowerPath.find(L"\\tmp\\") != std::wstring::npos
        || lowerPath.find(L"\\appdata\\local\\temp\\") != std::wstring::npos
        || lowerPath.find(L"\\downloads\\") != std::wstring::npos);
    ImportScanResult importResult = ScanPEImports(fullPath);

    entry.totalImports = importResult.totalImports;
    entry.suspiciousImports = importResult.suspiciousImportCount;

    // Packing / encryption analysis
    PackingAnalysisResult packResult = AnalyzePEPacking(fullPath, entry.entropy, importResult.totalImports);

    double malwareScoreValue = CalculateMalwareScore(entry.entropy, isSigned, isHidden, isInTempDir, importResult);

    // Bump score for signature anomalies (configurable via ScoringConfig)
    const ScoringConfig& cfg = GetScoringConfig();
    if (!sigInfo.hashValid && sigInfo.status != L"Unsigned") {
        malwareScoreValue += cfg.anomalies.hash_mismatch;
    }
    if (!sigInfo.chainTrusted && sigInfo.status != L"Unsigned") {
        malwareScoreValue += cfg.anomalies.untrusted_chain;
    }

    // Bump score for packing indicators
    if (packResult.isPacked) {
        malwareScoreValue += cfg.anomalies.packing;
    }
    if (packResult.writableExecSections > 0) {
        malwareScoreValue += cfg.anomalies.rwx_sections;
    }
    if (malwareScoreValue > cfg.weights.score_cap) malwareScoreValue = cfg.weights.score_cap;

    entry.malwareScore = malwareScoreValue;
    entry.rwxSections = packResult.writableExecSections;

    // Build packing status string
    if (packResult.isPacked) {
        std::wstringstream ps;
        ps << L"PACKED (" << static_cast<int>(packResult.packingConfidence * 100) << L"% confidence)";
        if (!packResult.detectedPacker.empty()) {
            ps << L" [" << ToWide(packResult.detectedPacker) << L"]";
        }
        entry.packingStatus = ps.str();
    }
    else {
        entry.packingStatus = L"Not packed";
    }

    // Build packing indicators string
    for (size_t pi = 0; pi < packResult.indicators.size(); pi++) {
        if (pi > 0) entry.packIndicators += L"; ";
        entry.packIndicators += ToWide(packResult.indicators[pi]);
    }

    return entry;
}

// ---------------------------------------------------------------------------
// Helper: check if a filename has an executable/scriptable extension
// Any extension that can contain or execute code on Windows.
// ---------------------------------------------------------------------------
static bool IsExecutableExtension(const std::wstring& fileName)
{
    // Find the last dot to extract the extension
    size_t dotPos = fileName.find_last_of(L'.');
    if (dotPos == std::wstring::npos || dotPos == fileName.length() - 1) {
        return false;
    }

    std::wstring ext = fileName.substr(dotPos);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);

    // PE binaries
    if (ext == L".exe")  return true;
    if (ext == L".dll")  return true;
    if (ext == L".com")  return true;
    if (ext == L".scr")  return true;
    if (ext == L".sys")  return true;
    if (ext == L".drv")  return true;
    if (ext == L".cpl")  return true;
    if (ext == L".ocx")  return true;

    // Installers / packages
    if (ext == L".msi")  return true;
    if (ext == L".msp")  return true;
    if (ext == L".mst")  return true;

    // Windows shell scripts
    if (ext == L".bat")  return true;
    if (ext == L".cmd")  return true;
    if (ext == L".ps1")  return true;
    if (ext == L".psm1") return true;
    if (ext == L".psd1") return true;

    // VBScript / JScript (Windows Script Host)
    if (ext == L".vbs")  return true;
    if (ext == L".vbe")  return true;
    if (ext == L".js")   return true;
    if (ext == L".jse")  return true;
    if (ext == L".wsf")  return true;
    if (ext == L".wsh")  return true;
    if (ext == L".wsc")  return true;

    // HTML Application (full trust execution)
    if (ext == L".hta")  return true;

    // Legacy / shortcut-based execution
    if (ext == L".pif")  return true;
    if (ext == L".lnk")  return true;
    if (ext == L".inf")  return true;
    if (ext == L".reg")  return true;

    return false;
}

// ---------------------------------------------------------------------------
// Helper: get scan state label text based on mode
// ---------------------------------------------------------------------------
static std::wstring GetScanStateLabel(ScanMode mode)
{
    switch (mode) {
    case ScanMode::Baseline: return L"Baseline Scan Running...";
    case ScanMode::FullScan: return L"Full Scan Running...";
    case ScanMode::FastScan: return L"Fast Scan Running...";
    default: return L"Scanning...";
    }
}

// ---------------------------------------------------------------------------
// Recursive directory scan function (used by Baseline and Full Scan modes)
// ---------------------------------------------------------------------------
void ScanDirectory(const std::wstring& directory, HWND hWnd, ScanMode mode, Baseline* baseline)
{
    WIN32_FIND_DATA findData;
    HANDLE hFind = FindFirstFile((directory + L"\\*").c_str(), &findData);
    {
        std::lock_guard<std::mutex> lock(scanStringMutex);
        scanState = GetScanStateLabel(mode);
    }

    if (hFind != INVALID_HANDLE_VALUE)
    {
        do {
            if (cancelScanRequested)
                break;

            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                if (wcscmp(findData.cFileName, L".") != 0 && wcscmp(findData.cFileName, L"..") != 0)
                {
                    ScanDirectory(directory + L"\\" + findData.cFileName, hWnd, mode, baseline);
                }
            }
            else
            {
                totalFilesProcessed++;

                std::wstring localFullPath;
                {
                    std::lock_guard<std::mutex> lock(scanStringMutex);
                    currentFile = findData.cFileName;
                    wchar_t fullPath[MAX_PATH];
                    PathCombineW(fullPath, directory.c_str(), findData.cFileName);
                    currentFileFullPath = fullPath;
                    localFullPath = currentFileFullPath;
                }

                std::wstring fileName = findData.cFileName;
                if (IsExecutableExtension(fileName))
                {
                    totalExecutables++;

                    // Run full analysis
                    BaselineEntry entry = AnalyzeFile(localFullPath);

                    if (mode == ScanMode::Baseline) {
                        // Baseline mode: add to baseline, write basic CSV
                        if (baseline) {
                            baseline->AddEntry(entry);
                        }

                        // Format malware score for CSV
                        std::wstringstream msStream;
                        msStream << entry.malwareScore << L"/10";
                        if (entry.suspiciousImports > 0) {
                            msStream << L" (" << entry.suspiciousImports << L" suspicious imports)";
                        }

                        std::wstringstream outString;
                        outString << entry.path << L"," << entry.fileSize << L"," << entry.md5 << L","
                            << entry.sha256 << L","
                            << entry.signature << L"," << entry.signatureType << L","
                            << entry.thumbprint << L"," << entry.issuer << L","
                            << entry.rootCA << L","
                            << entry.version << L"," << entry.developer << L","
                            << entry.readOnly << L"," << entry.hidden << L"," << entry.permissions << L","
                            << entry.entropy << L"," << msStream.str() << L","
                            << entry.totalImports << L"," << entry.suspiciousImports << L","
                            << entry.packingStatus << L"," << entry.rwxSections << L","
                            << L"\"" << entry.sigWarnings << L"\","
                            << L"\"" << entry.packIndicators << L"\"";

                        AppendToCSV(outString.str());

                        // Add to results ListView
                        AddResultRow(hResultsListView, entry, L"BASELINE");
                        SetProgressPosition(hProgressBar, totalExecutables.load());
                    }
                    else if (mode == ScanMode::FullScan && baseline) {
                        // Full Scan mode: compare against baseline
                        ComparisonResult comparison = baseline->CompareEntry(entry);
                        baseline->MarkSeen(entry.path);
                        AppendToCSVWithComparison(entry, comparison);

                        // Add to results ListView with status
                        std::wstring statusStr;
                        switch (comparison.status) {
                        case BaselineStatus::Match:   statusStr = L"MATCH";   break;
                        case BaselineStatus::New:     statusStr = L"NEW";     break;
                        case BaselineStatus::Changed: statusStr = L"CHANGED"; break;
                        case BaselineStatus::Missing: statusStr = L"MISSING"; break;
                        }
                        AddResultRow(hResultsListView, entry, statusStr);
                        SetProgressPosition(hProgressBar, totalExecutables.load());
                    }
                }
            }
        } while (FindNextFile(hFind, &findData));

        FindClose(hFind);
    }

    UpdateLabels(hWnd);
}

// ---------------------------------------------------------------------------
// ScanFileList — scan a specific list of file paths (used by Fast Scan)
// ---------------------------------------------------------------------------
void ScanFileList(const std::vector<std::wstring>& filePaths, HWND hWnd, ScanMode mode, Baseline* baseline)
{
    OutputDebugStringW((L"[PhantomRecon] ScanFileList: scanning " +
        std::to_wstring(filePaths.size()) + L" files\n").c_str());

    {
        std::lock_guard<std::mutex> lock(scanStringMutex);
        scanState = GetScanStateLabel(mode);
    }

    for (const auto& filePath : filePaths) {
        if (cancelScanRequested)
            break;

        totalFilesProcessed++;

        {
            std::lock_guard<std::mutex> lock(scanStringMutex);
            // Extract just the filename for display
            size_t lastSlash = filePath.find_last_of(L'\\');
            currentFile = (lastSlash != std::wstring::npos) ? filePath.substr(lastSlash + 1) : filePath;
            currentFileFullPath = filePath;
        }

        // Verify file still exists
        DWORD attrs = GetFileAttributesW(filePath.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            continue;
        }

        if (IsExecutableExtension(filePath)) {
            totalExecutables++;

            BaselineEntry entry = AnalyzeFile(filePath);

            if (baseline) {
                ComparisonResult comparison = baseline->CompareEntry(entry);
                baseline->MarkSeen(entry.path);
                AppendToCSVWithComparison(entry, comparison);

                // Add to results ListView
                std::wstring statusStr;
                switch (comparison.status) {
                case BaselineStatus::Match:   statusStr = L"MATCH";   break;
                case BaselineStatus::New:     statusStr = L"NEW";     break;
                case BaselineStatus::Changed: statusStr = L"CHANGED"; break;
                case BaselineStatus::Missing: statusStr = L"MISSING"; break;
                }
                AddResultRow(hResultsListView, entry, statusStr);
                SetProgressPosition(hProgressBar, totalExecutables.load());
            }
        }

        UpdateLabels(hWnd);
    }

    UpdateLabels(hWnd);
}



std::wstring GetComputerName()
{
    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName) / sizeof(computerName[0]);
    GetComputerName(computerName, &size);
    return std::wstring(computerName);
}

std::wstring GetProcessorInfo()
{
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    // Example: Intel Core i7-10700K @ 3.80GHz (8 cores, 16 threads)
    std::wstringstream ss;
    ss << L"Processor: ";

    switch (sysInfo.wProcessorArchitecture)
    {
    case PROCESSOR_ARCHITECTURE_AMD64:
        ss << L"AMD64 (x64)";
        break;
    case PROCESSOR_ARCHITECTURE_ARM:
        ss << L"ARM";
        break;
    case PROCESSOR_ARCHITECTURE_ARM64:
        ss << L"ARM64";
        break;
    case PROCESSOR_ARCHITECTURE_IA64:
        ss << L"IA64";
        break;
    case PROCESSOR_ARCHITECTURE_INTEL:
        ss << L"Intel";
        break;
    default:
        ss << L"Unknown";
        break;
    }

    ss << L", Cores: " << sysInfo.dwNumberOfProcessors;
    return ss.str();
}

std::wstring GetRamInfo()
{
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(memInfo);
    GlobalMemoryStatusEx(&memInfo);

    // Example: RAM: 32 GB
    std::wstringstream ss;
    ss << L"RAM: " << (memInfo.ullTotalPhys / (1024 * 1024)) << L" MB";
    return ss.str();
}

std::wstring GetDiskSpaceInfo()
{
    ULARGE_INTEGER freeBytesAvailable;
    ULARGE_INTEGER totalNumberOfBytes;
    ULARGE_INTEGER totalNumberOfFreeBytes;

    GetDiskFreeSpaceEx(NULL, &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes);

    // Example: Disk Space: 500 GB (Used: 250 GB, Free: 250 GB)
    std::wstringstream ss;
    ss << L"Disk Space: "
        << (totalNumberOfBytes.QuadPart / (1024 * 1024 * 1024)) << L" GB"
        << L" (Used: " << ((totalNumberOfBytes.QuadPart - totalNumberOfFreeBytes.QuadPart) / (1024 * 1024 * 1024)) << L" GB"
        << L", Free: " << (totalNumberOfFreeBytes.QuadPart / (1024 * 1024 * 1024)) << L" GB)";
    return ss.str();
}


// Function to create static text controls for titles and labels
void CreateTitlesAndLabels(HWND hWnd)
{
    // Constants for column positions and widths
    int columnWidth = 360;  // Width of each column
    int columnHeight = 280; // Height of each column
    int columnMargin = 20;  // Margin between columns
    int leftColumnX = 20;   // X position of the left column
    int rightColumnX = leftColumnX + columnWidth + columnMargin; // X position of the right column
    int titleHeight = 20;   // Height of the title controls
    int buffer = 10;        // White buffer around the gray text boxes

    // Create "System Information" title
    hSystemInfoTitle = CreateWindowW(L"STATIC", L"System Information",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        leftColumnX, 10, columnWidth, titleHeight,
        hWnd, NULL, NULL, NULL);

    // Create "Current Operation Information" title
    hOperationInfoTitle = CreateWindowW(L"STATIC", L"Current Operation Information",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        rightColumnX, 10, columnWidth, titleHeight,
        hWnd, NULL, NULL, NULL);

    // Create "System Information" label
    hSystemInfoLabel = CreateWindowW(L"STATIC", L"CPU: \nRAM: \nDisk Space: ",
        WS_CHILD | WS_VISIBLE | SS_LEFT | WS_BORDER,
        leftColumnX + buffer, 40 + titleHeight + buffer, columnWidth - 2 * buffer, columnHeight - titleHeight - 2 * buffer,
        hWnd, NULL, NULL, NULL);

    // Create "Current Operation Information" label
    hOperationInfoLabel = CreateWindowW(L"STATIC", L"Scan Progress: \nFiles Processed: \nExecutable Files: ",
        WS_CHILD | WS_VISIBLE | SS_LEFT | WS_BORDER,
        rightColumnX + buffer, 40 + titleHeight + buffer, columnWidth - 2 * buffer, columnHeight - titleHeight - 2 * buffer,
        hWnd, NULL, NULL, NULL);

    // Create progress bar below the info panels
    int progressY = 40 + columnHeight + 10;
    int progressBarWidth = rightColumnX + columnWidth - leftColumnX - 170;  // leave room for cancel button
    hProgressBar = CreateScanProgressBar(hWnd, hInst, leftColumnX, progressY,
        progressBarWidth, 22);

    // Create Cancel button to the right of the progress bar
    CreateWindowW(L"BUTTON", L"Cancel Scan",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        leftColumnX + progressBarWidth + 10, progressY - 2, 150, 26,
        hWnd, (HMENU)ID_BUTTON_CANCEL, hInst, NULL);

    // Create results ListView below the progress bar
    int listViewY = progressY + 30;
    int listViewHeight = 300;
    hResultsListView = CreateResultsListView(hWnd, hInst, leftColumnX, listViewY,
        rightColumnX + columnWidth - leftColumnX, listViewHeight);

    // Apply dark mode to controls
    ApplyDarkModeToListView(hResultsListView);
    ApplyDarkModeToProgressBar(hProgressBar);
}


// Function to update system information in the UI
void UpdateSystem(HWND hWnd)
{
    std::wstringstream ss;
    ss << L"Computer: " << GetComputerName() << L"\n";
    ss << GetProcessorInfo() << L"\n";
    ss << GetRamInfo() << L"\n";
    ss << GetDiskSpaceInfo() << L"\n";

    SetWindowText(hSystemInfoLabel, ss.str().c_str());
}

// Run security audit on a background thread and update the system info panel with results
void RunSecurityAuditInBackground(HWND hWnd)
{
    std::thread auditThread([hWnd]() {
        std::vector<SecurityCheckResult> results = RunAllSecurityChecks();

        // Write full report to file
        WriteSecurityReport(L"security_audit_report.txt", results);

        // Build the system info text with security summary appended
        std::wstringstream ss;
        ss << L"Computer: " << GetComputerName() << L"\n";
        ss << GetProcessorInfo() << L"\n";
        ss << GetRamInfo() << L"\n";
        ss << GetDiskSpaceInfo() << L"\n\n";
        ss << GetSecuritySummary(results);

        // Update the UI label (SetWindowText is safe to call from any thread on STATIC controls)
        SetWindowText(hSystemInfoLabel, ss.str().c_str());
    });
    auditThread.detach();
}
// Function to update labels in the UI
void UpdateLabels(HWND hWnd)
{
    std::wstring localScanState;
    std::wstring localFileFullPath;
    {
        std::lock_guard<std::mutex> lock(scanStringMutex);

        // ensure we don't have double slashes in paths
        size_t pos = currentFileFullPath.find(L"\\\\");
        while (pos != std::wstring::npos) {
            currentFileFullPath.replace(pos, 2, L"\\");
            pos = currentFileFullPath.find(L"\\\\", pos + 1);
        }

        localScanState = scanState;
        localFileFullPath = currentFileFullPath;
    }

    // Construct new labels text
    std::wstring scanStateLabel = L"Current Scan State: " + localScanState;
    std::wstring processedLabel = L"Files Processed: " + std::to_wstring(totalFilesProcessed.load());
    std::wstring executablesLabel = L"Executable Files: " + std::to_wstring(totalExecutables.load());
    std::wstring currentFileLabel = L"Current File: " + localFileFullPath;

    // Update labels
    std::wstring labelText = scanStateLabel + L"\n" + processedLabel + L"\n" + executablesLabel + L"\n" + currentFileLabel + L"\n";
    SetWindowText(hOperationInfoLabel, labelText.c_str());
}



// Function to cancel the ongoing scan
void CancelScan()
{
    cancelScanRequested = true;
    std::lock_guard<std::mutex> lock(scanStringMutex);
    scanState = L"Stopped";
}


// Function to start scanning in a separate thread
void StartScanInBackground(ScanMode mode, const std::wstring& directory, HWND hWnd)
{
    // Reset the cancellation flag and counters before starting
    cancelScanRequested = false;
    totalFilesProcessed = 0;
    totalExecutables = 0;

    // Clear results and start progress bar
    ClearResultRows(hResultsListView);
    SetProgressMarquee(hProgressBar, true);

    OutputDebugStringW(L"[PhantomRecon] StartScanInBackground: launching scan thread\n");

    if (mode == ScanMode::FastScan) {
        // Fast Scan: enumerate installed programs from registry, then scan their executables
        std::thread scanThread([hWnd]() {
            OutputDebugStringW(L"[PhantomRecon] Fast Scan thread started\n");

            // Enumerate installed programs
            std::vector<InstalledProgram> programs = RegistryEnumerator::EnumerateInstalledPrograms();

            OutputDebugStringW((L"[PhantomRecon] Fast Scan: found " +
                std::to_wstring(programs.size()) + L" installed programs\n").c_str());

            // Resolve executable paths
            std::vector<std::wstring> exePaths = RegistryEnumerator::GetExecutablePathsFromPrograms(programs);

            OutputDebugStringW((L"[PhantomRecon] Fast Scan: resolved " +
                std::to_wstring(exePaths.size()) + L" executable paths\n").c_str());

            // Scan the file list with baseline comparison
            Baseline* baseline = nullptr;
            {
                std::lock_guard<std::mutex> lock(g_baselineMutex);
                baseline = &g_currentBaseline;
            }
            ScanFileList(exePaths, hWnd, ScanMode::FastScan, baseline);

            // A cancelled Fast Scan leaves most baseline entries unseen. The sweep below
            // would then report them all as MISSING. Skip it and label results as partial.
            if (cancelScanRequested) {
                OutputDebugStringW(L"[PhantomRecon] Fast Scan cancelled — MISSING sweep skipped (results are partial)\n");
                {
                    std::lock_guard<std::mutex> lock(scanStringMutex);
                    scanState = L"Fast Scan Cancelled (partial results)";
                }
                SetProgressMarquee(hProgressBar, false);
                UpdateLabels(hWnd);
                return;
            }

            // After scanning, report missing files (in baseline but not found by Fast Scan)
            {
                std::lock_guard<std::mutex> lock(g_baselineMutex);
                std::vector<const BaselineEntry*> missing = g_currentBaseline.GetUnseenEntries();
                for (const auto* entry : missing) {
                    ComparisonResult missingResult;
                    missingResult.status = BaselineStatus::Missing;
                    missingResult.changeDetails = L"File missing from disk (was in baseline)";
                    missingResult.riskDelta = 0.0;
                    AppendToCSVWithComparison(*entry, missingResult);
                }
                OutputDebugStringW((L"[PhantomRecon] Fast Scan: " +
                    std::to_wstring(missing.size()) + L" missing entries reported\n").c_str());
            }

            {
                std::lock_guard<std::mutex> lock(scanStringMutex);
                scanState = L"Fast Scan Completed!";
            }
            SetProgressMarquee(hProgressBar, false);
            UpdateLabels(hWnd);
        });
        scanThread.detach();
    }
    else {
        // Baseline or Full Scan: recursive directory scan
        std::thread scanThread([mode, directory, hWnd]() {
            OutputDebugStringW((L"[PhantomRecon] " +
                std::wstring(mode == ScanMode::Baseline ? L"Baseline" : L"Full") +
                L" Scan thread started\n").c_str());

            Baseline scanBaseline;
            Baseline* baselinePtr = nullptr;

            if (mode == ScanMode::Baseline) {
                // Baseline mode: we build a new baseline from scratch
                baselinePtr = &scanBaseline;
            }
            else if (mode == ScanMode::FullScan) {
                // Full Scan mode: compare against loaded global baseline
                std::lock_guard<std::mutex> lock(g_baselineMutex);
                baselinePtr = &g_currentBaseline;
            }

            ScanDirectory(directory, hWnd, mode, baselinePtr);

            if (mode == ScanMode::Baseline) {
                // A cancelled scan has only walked part of the disk. Writing it would replace
                // the ground truth with a truncated snapshot, and every file that was never
                // reached would be reported as NEW on the next Full Scan. Keep the old file.
                if (cancelScanRequested) {
                    OutputDebugStringW(L"[PhantomRecon] Baseline Scan cancelled — baseline NOT saved, existing file left untouched\n");
                    MessageBox(hWnd,
                        L"Baseline Scan cancelled.\n\n"
                        L"No baseline was written. Any existing baseline file is unchanged.",
                        L"Baseline Scan Cancelled", MB_OK | MB_ICONINFORMATION);
                    {
                        std::lock_guard<std::mutex> lock(scanStringMutex);
                        scanState = L"Baseline Scan Cancelled";
                    }
                    SetProgressMarquee(hProgressBar, false);
                    UpdateLabels(hWnd);
                    return;
                }

                // Save the completed baseline to disk
                if (scanBaseline.SaveToFile(g_BaselineFilePath)) {
                    std::wstringstream ss;
                    ss << L"Baseline saved: " << scanBaseline.Count() << L" entries\n"
                       << L"File: " << g_BaselineFilePath;
                    MessageBox(hWnd, ss.str().c_str(), L"Baseline Scan Complete", MB_OK | MB_ICONINFORMATION);
                }
                else {
                    MessageBox(hWnd, L"Failed to save baseline file!", L"Error", MB_OK | MB_ICONERROR);
                }
                {
                    std::lock_guard<std::mutex> lock(scanStringMutex);
                    scanState = L"Baseline Scan Completed!";
                }
                SetProgressMarquee(hProgressBar, false);
            }
            else if (mode == ScanMode::FullScan) {
                // Same trap as the baseline save: if the scan was cancelled, every baseline
                // entry we never got to is still unseen, and the sweep below would report it
                // as MISSING. Skip the sweep and label the results as partial.
                if (cancelScanRequested) {
                    OutputDebugStringW(L"[PhantomRecon] Full Scan cancelled — MISSING sweep skipped (results are partial)\n");
                    {
                        std::lock_guard<std::mutex> lock(scanStringMutex);
                        scanState = L"Full Scan Cancelled (partial results)";
                    }
                    SetProgressMarquee(hProgressBar, false);
                    UpdateLabels(hWnd);
                    return;
                }

                // Report missing files (in baseline but not found on disk)
                {
                    std::lock_guard<std::mutex> lock(g_baselineMutex);
                    std::vector<const BaselineEntry*> missing = g_currentBaseline.GetUnseenEntries();
                    for (const auto* entry : missing) {
                        ComparisonResult missingResult;
                        missingResult.status = BaselineStatus::Missing;
                        missingResult.changeDetails = L"File missing from disk (was in baseline)";
                        missingResult.riskDelta = 0.0;
                        AppendToCSVWithComparison(*entry, missingResult);
                    }
                    OutputDebugStringW((L"[PhantomRecon] Full Scan: " +
                        std::to_wstring(missing.size()) + L" missing entries reported\n").c_str());
                }
                {
                    std::lock_guard<std::mutex> lock(scanStringMutex);
                    scanState = L"Full Scan Completed!";
                }
                SetProgressMarquee(hProgressBar, false);
            }

            UpdateLabels(hWnd);
        });
        scanThread.detach();
    }
}


std::streampos getFileSize(const std::wstring& filename) {
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (!GetFileAttributesEx(filename.c_str(), GetFileExInfoStandard, &fileInfo)) {
        std::wcerr << L"Failed to get file attributes for: " << filename << std::endl;
        return -1;
    }

    ULARGE_INTEGER size;
    size.LowPart = fileInfo.nFileSizeLow;
    size.HighPart = fileInfo.nFileSizeHigh;

    return static_cast<std::streampos>(size.QuadPart);
}


// ---------------------------------------------------------------------------
// PromptForOutputPath — Show a Save File dialog for CSV output location
// ---------------------------------------------------------------------------
bool PromptForOutputPath(HWND hWnd, std::wstring& outPath)
{
    wchar_t szFile[MAX_PATH] = L"output.csv";

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(OPENFILENAMEW);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFilter = L"CSV Files (*.csv)\0*.csv\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Choose Output Location for Scan Results";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = L"csv";

    if (GetSaveFileNameW(&ofn)) {
        outPath = szFile;
        OutputDebugStringW((L"[PhantomRecon] Output path selected: " + outPath + L"\n").c_str());
        return true;
    }

    OutputDebugStringW(L"[PhantomRecon] Output path selection cancelled\n");
    return false;
}

void AppendToCSV(const std::wstring& dataToWrite, const std::wstring& outputPath) {
    std::wofstream outputFile(outputPath, std::ios_base::app);

    if (!outputFile.is_open()) {
        MessageBox(NULL, L"Failed to open output file for writing!", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Check if the file is empty
    outputFile.seekp(0, std::ios::end);
    bool fileIsEmpty = (outputFile.tellp() == 0);

    // Write header line for new file
    if (fileIsEmpty) {
        outputFile << L"Path,File Size,MD5,SHA-256,Signature,Signature Type,Cert Thumbprint,Issuer,Root CA,Version,Developer,Read Only,Hidden,Permissions,Entropy,Malware Score,Total Imports,Suspicious Imports,Packing Status,RWX Sections,Signature Warnings,Packing Indicators" << std::endl;
    }

    // Write dataToWrite to the file
    outputFile << dataToWrite << std::endl;

    outputFile.close();
}


// Write a BaselineEntry + ComparisonResult to CSV with 3 additional columns (Status, Change Details, Risk Delta)
void AppendToCSVWithComparison(const BaselineEntry& entry, const ComparisonResult& comparison,
    const std::wstring& outputPath)
{
    std::wofstream outputFile(outputPath, std::ios_base::app);

    if (!outputFile.is_open()) {
        OutputDebugStringW(L"[PhantomRecon] AppendToCSVWithComparison: failed to open output file\n");
        return;
    }

    // Check if the file is empty (write header with comparison columns)
    outputFile.seekp(0, std::ios::end);
    bool fileIsEmpty = (outputFile.tellp() == 0);

    if (fileIsEmpty) {
        outputFile << L"Path,File Size,MD5,SHA-256,Signature,Signature Type,Cert Thumbprint,Issuer,Root CA,"
                   << L"Version,Developer,Read Only,Hidden,Permissions,Entropy,Malware Score,"
                   << L"Total Imports,Suspicious Imports,Packing Status,RWX Sections,"
                   << L"Signature Warnings,Packing Indicators,"
                   << L"Baseline Status,Change Details,Risk Delta"
                   << std::endl;
    }

    // Status string
    std::wstring statusStr;
    switch (comparison.status) {
    case BaselineStatus::Match:   statusStr = L"MATCH";   break;
    case BaselineStatus::New:     statusStr = L"NEW";     break;
    case BaselineStatus::Changed: statusStr = L"CHANGED"; break;
    case BaselineStatus::Missing: statusStr = L"MISSING"; break;
    }

    // Format malware score
    std::wstringstream msStream;
    msStream << entry.malwareScore << L"/10";
    if (entry.suspiciousImports > 0) {
        msStream << L" (" << entry.suspiciousImports << L" suspicious imports)";
    }

    // Format risk delta
    std::wstringstream rdStream;
    if (comparison.riskDelta >= 0) rdStream << L"+";
    rdStream << std::fixed << std::setprecision(1) << comparison.riskDelta;

    outputFile << entry.path << L"," << entry.fileSize << L"," << entry.md5 << L","
        << entry.sha256 << L","
        << entry.signature << L"," << entry.signatureType << L","
        << entry.thumbprint << L"," << entry.issuer << L"," << entry.rootCA << L","
        << entry.version << L"," << entry.developer << L","
        << entry.readOnly << L"," << entry.hidden << L"," << entry.permissions << L","
        << entry.entropy << L"," << msStream.str() << L","
        << entry.totalImports << L"," << entry.suspiciousImports << L","
        << entry.packingStatus << L"," << entry.rwxSections << L","
        << L"\"" << entry.sigWarnings << L"\","
        << L"\"" << entry.packIndicators << L"\","
        << statusStr << L","
        << L"\"" << comparison.changeDetails << L"\","
        << rdStream.str()
        << std::endl;

    outputFile.close();
}


bool computeFileMD5(const std::wstring& filePath, BYTE** hash, DWORD* hashSize) {
    // Open the file
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Error opening file: " << GetLastError() << std::endl;
        return false;
    }

    // Initialize variables for hashing
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    BYTE rgbFile[1024];
    DWORD cbRead = 0;

    // Get handle to the crypto provider
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "Error acquiring crypto context: " << GetLastError() << std::endl;
        CloseHandle(hFile);
        return false;
    }

    // Create a new hash object
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        std::cerr << "Error creating hash object: " << GetLastError() << std::endl;
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return false;
    }

    // Read file and compute hash
    while (ReadFile(hFile, rgbFile, 1024, &cbRead, NULL) && cbRead != 0) {
        if (!CryptHashData(hHash, rgbFile, cbRead, 0)) {
            std::cerr << "Error hashing file data: " << GetLastError() << std::endl;
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            CloseHandle(hFile);
            return false;
        }
    }

    // Get the hash value size
    DWORD dwSize = sizeof(DWORD);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)hashSize, &dwSize, 0)) {
        std::cerr << "Error getting hash size: " << GetLastError() << std::endl;
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CloseHandle(hFile);
        return false;
    }

    // Allocate memory for the hash
    *hash = reinterpret_cast<BYTE*>(malloc(static_cast<size_t>(*hashSize)));
    if (*hash == nullptr) {
        std::cerr << "Memory allocation failed." << std::endl;
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CloseHandle(hFile);
        return false;
    }

    // Retrieve the hash value
    if (!CryptGetHashParam(hHash, HP_HASHVAL, *hash, hashSize, 0)) {
        std::cerr << "Error retrieving hash value: " << GetLastError() << std::endl;
        free(*hash);
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CloseHandle(hFile);
        return false;
    }

    // Cleanup
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    return true;
}

double calculateEntropy(const std::wstring& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        //std::cerr << "Error opening file: " << filename << std::endl;
        return 0.0;
    }

    // Array to count occurrences of each byte (0-255)
    std::vector<int> byteCounts(256, 0);
    int totalBytes = 0;

    // Read file byte by byte
    char byte;
    while (file.get(byte)) {
        byteCounts[static_cast<unsigned char>(byte)]++;
        totalBytes++;
    }

    file.close();

    // Calculate entropy
    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (byteCounts[i] > 0) {
            double probability = static_cast<double>(byteCounts[i]) / totalBytes;
            entropy -= probability * std::log2(probability);
        }
    }

    return entropy;
}