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

// GetExeDirectory() + fileName.
std::wstring AppFilePath(const std::wstring& fileName);

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

// True when the DACL lets a low-privilege principal write: Everyone, Authenticated
// Users, BUILTIN\Users, INTERACTIVE, or the current user. For a folder "write" means
// it can create files in it; for a file it means it can change the contents.
// whoOut receives the principal that has the access, for reports.
bool LowPrivilegeWritable(const std::wstring& path, bool isDirectory, std::wstring* whoOut = nullptr);

// True when the path is in a place where ordinary users drop files: Temp, Downloads,
// Desktop, Public, the recycle bin, or a network share.
bool IsUserDropLocation(const std::wstring& path);

// True for files of Store / MSIX apps under Program Files\WindowsApps. Windows
// verifies the package signature at install time and protects these folders.
bool IsPackagedAppPath(const std::wstring& path);

// True when the path is under %SystemRoot%.
bool IsUnderWindowsDirectory(const std::wstring& path);

// True when the path is under Program Files or Program Files (x86).
bool IsUnderProgramFiles(const std::wstring& path);
