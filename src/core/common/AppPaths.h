#pragma once

#include <string>

// ---------------------------------------------------------------------------
// AppPaths: where Phantom Recon reads and writes, and path helpers.
//
// Every file the program writes lives next to the executable (or in a folder
// the user picked). Nothing depends on the current working directory, so a
// scheduled run or a double-click from Explorer behaves the same.
//
// Portable mode is not stored anywhere. It is true when any of these hold:
//   - the command line contains --portable
//   - a file named portable.flag sits next to the exe
//   - the exe runs from a removable drive
// In portable mode the program never creates scheduled tasks, never fetches
// revocation data online, and writes reports next to the exe.
// ---------------------------------------------------------------------------

// Folder that holds PhantomRecon.exe, with a trailing backslash.
std::wstring GetExeDirectory();

// Full path of the running executable.
std::wstring GetExePath();

// GetExeDirectory() + fileName: where the program's own data files live (scoring INI,
// known-good list, revocation cache, persistence snapshot, settings).
//
// Test hook: when the environment variable named by DataFolderEnvironmentName()
// (PHANTOMRECON_DATA_DIR) holds an existing absolute folder AND the running program is
// PhantomReconTests.exe, that folder is used instead of the exe folder. The test runner
// points it at its per-run temp folder so results never depend on files left next to
// the exe. PhantomRecon.exe and PhantomReconCli.exe ignore the variable.
std::wstring AppFilePath(const std::wstring& fileName);

// "PHANTOMRECON_DATA_DIR", the variable AppFilePath reads in the test program.
std::wstring DataFolderEnvironmentName();

// See the comment block above.
bool IsPortableMode();

// Default folder for reports: <exe dir>\reports. Created on demand by EnsureDirectory.
std::wstring DefaultReportsDirectory();

// Create a folder and every missing parent. True if it exists afterwards.
bool EnsureDirectory(const std::wstring& directory);

bool FileExists(const std::wstring& path);
bool DirectoryExists(const std::wstring& path);

// "C:\a\b.exe" -> "b.exe"
std::wstring FileNameOf(const std::wstring& path);

// "C:\a\b.exe" -> "C:\a"
std::wstring DirectoryOf(const std::wstring& path);

// Join with exactly one backslash between the parts.
std::wstring JoinPath(const std::wstring& directory, const std::wstring& name);

// Lowercase extension with the dot ("C:\x\Y.EXE" -> ".exe"), or "" when there is none.
std::wstring ExtensionOf(const std::wstring& path);

// Expand %VARIABLES%.
std::wstring ExpandEnvironment(const std::wstring& text);

// Prefix with \\?\ (or \\?\UNC\) when the path is long enough to hit MAX_PATH limits.
// Short paths are returned unchanged so normal behaviour is untouched.
std::wstring ToExtendedPath(const std::wstring& path);

// Make a path absolute (GetFullPathNameW). Returns the input on failure.
std::wstring AbsolutePath(const std::wstring& path);

// True when a normal user can write: Everyone, Authenticated Users, BUILTIN\Users or
// INTERACTIVE through the DACL, or the signed-in user's own non-elevated token. When
// this program runs elevated, the user's linked (non-elevated) token and the token of
// the desktop shell are asked instead, so folders in the user's own profile still
// count. For a folder "write" means it can create files in it (create-folder-only
// rights do not count); for a file it means it can change the contents. Changing the
// permissions or the owner counts as write. Deny entries are honoured.
// whoOut receives the principal that has the access, for reports.
bool LowPrivilegeWritable(const std::wstring& path, bool isDirectory, std::wstring* whoOut = nullptr);

// The DACL half of LowPrivilegeWritable on its own: would a standard user holding
// Everyone, Authenticated Users, BUILTIN\Users and INTERACTIVE get write access from
// this DACL (an ACL*, evaluated in order, allow and deny entries, generic rights
// mapped)? A null dacl means no DACL, which grants everyone full access.
bool DaclLetsLowPrivilegeGroupsWrite(const void* dacl, bool isDirectory, std::wstring* whoOut = nullptr);

// True when the path is in a place where ordinary users drop files: Temp, Downloads,
// Desktop (also when OneDrive or the user moved them), Public, the recycle bin, the
// folders under %SystemRoot% that normal users can write to, or a network share.
bool IsUserDropLocation(const std::wstring& path);

// True for paths inside the folders under %SystemRoot% that Windows itself lets normal
// users create files in: Tasks, Temp, Tracing, spool\drivers\color and similar.
bool IsUserWritableWindowsFolder(const std::wstring& path);

// True when the path is under %SystemRoot%, not in one of the folders above, and its
// own folder is not writable by normal users. Use this, not IsUnderWindowsDirectory,
// before trusting a file because of where it is.
bool IsProtectedWindowsPath(const std::wstring& path);

// True for files of Store / MSIX apps under Program Files\WindowsApps. Windows
// verifies the package signature at install time and protects these folders.
bool IsPackagedAppPath(const std::wstring& path);

// True when the path is under %SystemRoot%.
bool IsUnderWindowsDirectory(const std::wstring& path);

// True when the path is under Program Files or Program Files (x86).
bool IsUnderProgramFiles(const std::wstring& path);
