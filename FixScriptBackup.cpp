#include "pch.h"
#include "FixScriptBackup.h"

#include "FixScript.h"
#include "TextUtils.h"

#include <windows.h>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[FixScriptBackup] " + msg + L"\n").c_str());
}

// ---------------------------------------------------------------------------
// The PowerShell. Constant text, ASCII, no double quotes (the tests parse every plan
// and require that no expandable string exists). Windows PowerShell 5.1 rules that
// shape it: @() of a generic List throws "Argument types do not match", so lists are
// passed on with .ToArray(); a function returns a list with the unary comma so the
// pipeline does not unroll it.
// ---------------------------------------------------------------------------

// Both scripts: hive and key access, and reading and writing the backup file.
static const wchar_t kCommonHelpers[] = LR"PS(function Get-PRHive([string]$Path) {
    if ($Path.StartsWith('HKLM:\', [StringComparison]::OrdinalIgnoreCase)) { return [Microsoft.Win32.Registry]::LocalMachine }
    if ($Path.StartsWith('HKCU:\', [StringComparison]::OrdinalIgnoreCase)) { return [Microsoft.Win32.Registry]::CurrentUser }
    throw ('Not a registry path this plan handles: ' + $Path)
}
function Open-PRKey([string]$Path, [bool]$Writable) {
    return (Get-PRHive $Path).OpenSubKey($Path.Substring(6), $Writable)
}
function Read-PRBackup {
    $list = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $backupPath)) { return ,$list }
    try {
        $text = [System.IO.File]::ReadAllText($backupPath, [System.Text.Encoding]::UTF8)
        if ($text.Trim().Length -gt 0) {
            $parsed = ConvertFrom-Json -InputObject $text
            foreach ($entry in $parsed) { $list.Add($entry) }
        }
    }
    catch { throw ('The backup file ' + $backupPath + ' cannot be read: ' + $_.Exception.Message) }
    return ,$list
}
function Write-PRBackup($List) {
    $json = ConvertTo-Json -InputObject $List.ToArray() -Depth 6
    [System.IO.File]::WriteAllText($backupPath, $json, (New-Object System.Text.UTF8Encoding($false)))
})PS";

// The fix script: read each declared value and the missing keys on its path, save
// them as one entry per step before the commands run.
static const wchar_t kSaveHelpers[] = LR"PS(function Get-PRValueState([string]$Key, [string]$Name) {
    $state = [ordered]@{ Key = $Key; Name = $Name; Existed = $false; Type = ''; Data = ''; Count = 0 }
    $k = Open-PRKey $Key $false
    if ($null -eq $k) { return [pscustomobject]$state }
    try {
        $found = $false
        foreach ($n in $k.GetValueNames()) { if ([string]::Equals($n, $Name, [StringComparison]::OrdinalIgnoreCase)) { $found = $true } }
        if ($found) {
            $kind = [string]$k.GetValueKind($Name)
            $raw = $k.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $state.Existed = $true
            $state.Type = $kind
            switch ($kind) {
                'DWord' { $state.Data = [string][BitConverter]::ToUInt32([BitConverter]::GetBytes([int32]$raw), 0) }
                'QWord' { $state.Data = [string][BitConverter]::ToUInt64([BitConverter]::GetBytes([int64]$raw), 0) }
                'String' { $state.Data = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes([string]$raw)) }
                'ExpandString' { $state.Data = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes([string]$raw)) }
                'MultiString' {
                    $parts = [string[]]$raw
                    $joined = ''
                    foreach ($p in $parts) { $joined += $p + [char]0 }
                    $state.Count = $parts.Length
                    $state.Data = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($joined))
                }
                'Binary' { if ($null -ne $raw) { $state.Data = [Convert]::ToBase64String([byte[]]$raw) } }
                'None' { if ($null -ne $raw) { $state.Data = [Convert]::ToBase64String([byte[]]$raw) } }
                default { throw ('The value ' + $Key + ' ' + $Name + ' has a registry type the backup cannot put back exactly (' + $kind + '), so nothing was changed.') }
            }
        }
    }
    finally { $k.Close() }
    return [pscustomobject]$state
}
function Get-PRMissingKeys([string]$Key) {
    $missing = New-Object System.Collections.Generic.List[string]
    $path = $Key
    while ($path.Length -gt 6) {
        $k = Open-PRKey $path $false
        if ($null -ne $k) { $k.Close(); break }
        $missing.Add($path)
        $cut = $path.LastIndexOf('\')
        if ($cut -le 5) { break }
        $path = $path.Substring(0, $cut)
    }
    return ,$missing
}
function Get-PRSubkeyPaths([string]$Key) {
    $paths = New-Object System.Collections.Generic.List[string]
    $k = Open-PRKey $Key $false
    if ($null -ne $k) {
        try { foreach ($n in $k.GetSubKeyNames()) { $paths.Add($Key + '\' + $n) } }
        finally { $k.Close() }
    }
    return ,$paths
}
function Save-PRBackup([string]$Step, [object[]]$Values) {
    $all = Read-PRBackup
    foreach ($entry in $all.ToArray()) {
        if ($entry.Step -ne $Step) { continue }
        if (-not $entry.Restored) {
            Write-Host ('Backup: kept from an earlier run, with the values from before the first fix (saved ' + $entry.Saved + ').')
            return
        }
        [void]$all.Remove($entry)
    }
    $states = New-Object System.Collections.Generic.List[object]
    $created = New-Object System.Collections.Generic.List[string]
    foreach ($v in $Values) {
        $keys = New-Object System.Collections.Generic.List[string]
        if ($v.EachSubkey) { $keys = Get-PRSubkeyPaths $v.Key } else { $keys.Add($v.Key) }
        foreach ($key in $keys) {
            $states.Add((Get-PRValueState $key $v.Name))
            foreach ($m in (Get-PRMissingKeys $key)) { if (-not $created.Contains($m)) { $created.Add($m) } }
        }
    }
    $all.Add([pscustomobject][ordered]@{ Step = $Step; Saved = (Get-Date).ToString('s'); Restored = ''; Values = $states.ToArray(); CreatedKeys = $created.ToArray() })
    Write-PRBackup $all
    Write-Host ('Backup: ' + $states.Count + ' registry value(s) saved to ' + $backupPath)
})PS";

// The undo script: check an entry against the step's own declared values, put the
// values back, remove the keys the fix created when they are empty, mark it restored.
static const wchar_t kRestoreHelpers[] = LR"PS(function Test-PRDeclared([string]$Key, [string]$Name, [object[]]$Values) {
    foreach ($v in $Values) {
        if (-not [string]::Equals($Name, $v.Name, [StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($v.EachSubkey) {
            $prefix = $v.Key + '\'
            if ($Key.Length -gt $prefix.Length -and $Key.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -and $Key.IndexOf('\', $prefix.Length) -lt 0) { return $true }
        }
        elseif ([string]::Equals($Key, $v.Key, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}
function Test-PRCreatedKey([string]$Key, [object[]]$Values) {
    if ($Key.Length -le 6) { return $false }
    foreach ($v in $Values) {
        if ($v.EachSubkey) { continue }
        if ([string]::Equals($Key, $v.Key, [StringComparison]::OrdinalIgnoreCase)) { return $true }
        if ($v.Key.StartsWith($Key + '\', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}
function Set-PRValueState($State) {
    $hive = Get-PRHive ([string]$State.Key)
    $sub = ([string]$State.Key).Substring(6)
    $name = [string]$State.Name
    if (-not $State.Existed) {
        $k = $hive.OpenSubKey($sub, $true)
        if ($null -ne $k) {
            try { $k.DeleteValue($name, $false) }
            finally { $k.Close() }
        }
        return
    }
    $data = [string]$State.Data
    $k = $hive.CreateSubKey($sub)
    try {
        switch ([string]$State.Type) {
            'DWord' { $k.SetValue($name, [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$data), 0), [Microsoft.Win32.RegistryValueKind]::DWord) }
            'QWord' { $k.SetValue($name, [BitConverter]::ToInt64([BitConverter]::GetBytes([uint64]$data), 0), [Microsoft.Win32.RegistryValueKind]::QWord) }
            'String' { $k.SetValue($name, [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($data)), [Microsoft.Win32.RegistryValueKind]::String) }
            'ExpandString' { $k.SetValue($name, [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($data)), [Microsoft.Win32.RegistryValueKind]::ExpandString) }
            'MultiString' {
                $parts = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($data)).Split([char]0)
                $list = [string[]]::new([int]$State.Count)
                for ($i = 0; $i -lt $list.Length; $i++) { $list[$i] = $parts[$i] }
                $k.SetValue($name, $list, [Microsoft.Win32.RegistryValueKind]::MultiString)
            }
            'Binary' { $k.SetValue($name, [byte[]][Convert]::FromBase64String($data), [Microsoft.Win32.RegistryValueKind]::Binary) }
            'None' { $k.SetValue($name, [byte[]][Convert]::FromBase64String($data), [Microsoft.Win32.RegistryValueKind]::None) }
            default { throw ('The backup holds a registry type this plan cannot write: ' + $State.Type) }
        }
    }
    finally { $k.Close() }
}
function Remove-PREmptyKey([string]$Path) {
    $k = Open-PRKey $Path $false
    if ($null -eq $k) { return }
    $empty = ($k.ValueCount -eq 0) -and ($k.SubKeyCount -eq 0)
    $k.Close()
    if ($empty) { (Get-PRHive $Path).DeleteSubKey($Path.Substring(6), $false) }
}
function Get-PRBackupState([string]$Step) {
    try { $all = Read-PRBackup }
    catch { return 'unreadable' }
    foreach ($entry in $all) {
        if ($entry.Step -ne $Step) { continue }
        if ($entry.Restored) { return 'restored' }
        return 'saved'
    }
    return 'none'
}
function Restore-PRBackup([string]$Step, [object[]]$Values) {
    $all = Read-PRBackup
    $entry = $null
    foreach ($e in $all) { if ($e.Step -eq $Step -and $null -eq $entry) { $entry = $e } }
    if ($null -eq $entry) { return 'none' }
    if ($entry.Restored) { return 'done' }
    foreach ($s in @($entry.Values)) {
        if (-not (Test-PRDeclared ([string]$s.Key) ([string]$s.Name) $Values)) { throw ('The backup names a registry value this step does not change, so nothing was put back: ' + $s.Key + ' ' + $s.Name) }
    }
    foreach ($c in @($entry.CreatedKeys)) {
        if (-not (Test-PRCreatedKey ([string]$c) $Values)) { throw ('The backup names a registry key this step does not create, so nothing was put back: ' + $c) }
    }
    foreach ($s in @($entry.Values)) { Set-PRValueState $s }
    foreach ($c in @(@($entry.CreatedKeys) | Sort-Object -Property Length -Descending)) { Remove-PREmptyKey ([string]$c) }
    $entry.Restored = (Get-Date).ToString('s')
    Write-PRBackup $all
    return 'restored'
})PS";

static void AppendBlock(std::vector<std::wstring>& out, const wchar_t* block)
{
    std::wstring line;
    for (const wchar_t* p = block; *p; ++p) {
        if (*p == L'\n') {
            out.push_back(line);
            line.clear();
        }
        else if (*p != L'\r') {
            line += *p;
        }
    }
    if (!line.empty()) out.push_back(line);
}

std::wstring BackupFileNameFor(const std::wstring& fixScriptName)
{
    if (fixScriptName.empty()) return L"phantom-recon-fix-backup.json";
    std::wstring stem = HasPs1Extension(fixScriptName) ? fixScriptName.substr(0, fixScriptName.size() - 4) : fixScriptName;
    return stem + L"-backup.json";
}

std::wstring BackupPathFor(const std::wstring& fixScriptPath)
{
    size_t slash = fixScriptPath.find_last_of(L"\\/");
    std::wstring folder = slash == std::wstring::npos ? L"" : fixScriptPath.substr(0, slash + 1);
    std::wstring name = slash == std::wstring::npos ? fixScriptPath : fixScriptPath.substr(slash + 1);
    return folder + BackupFileNameFor(name);
}

std::vector<std::wstring> BackupHelperLines(const std::wstring& backupFileName, bool undo)
{
    std::vector<std::wstring> out;
    out.push_back(undo ? L"# Registry backup: the fix plan saved the values its registry steps change here, and the"
                       : L"# Registry backup: before a registry step runs, the values it changes are saved here, so");
    out.push_back(undo ? L"# steps below put back exactly those values. Nothing from this PC is part of this text."
                       : L"# the undo plan can put them back exactly. Nothing from this PC is part of this text.");
    out.push_back(L"$backupFolder = $PSScriptRoot");
    out.push_back(L"if (-not $backupFolder) { $backupFolder = (Get-Location).Path }");
    out.push_back(L"$backupPath = Join-Path $backupFolder " + PowerShellQuote(backupFileName));
    AppendBlock(out, kCommonHelpers);
    AppendBlock(out, undo ? kRestoreHelpers : kSaveHelpers);
    DebugLog(std::wstring(undo ? L"Restore" : L"Save") + L" helpers written for " + backupFileName + L" (" +
             std::to_wstring(out.size()) + L" lines)");
    return out;
}

std::vector<std::wstring> RegistryValuesLines(const std::vector<RegistryValueRef>& values)
{
    std::vector<std::wstring> out;
    out.push_back(L"$registryValues = @(");
    for (const RegistryValueRef& v : values) {
        if (v.neverSaved) continue;   // a stored password is never copied into the backup file
        out.push_back(L"    @{ Key = " + PowerShellQuote(v.key) + L"; Name = " + PowerShellQuote(v.name) +
                      L"; EachSubkey = " + (v.eachSubkey ? L"$true" : L"$false") + L" }");
    }
    out.push_back(L")");
    return out;
}

std::wstring RegistryValueShown(const RegistryValueRef& value)
{
    return value.key + (value.eachSubkey ? L"\\<each subkey>" : L"") + L"  " + value.name +
           (value.neverSaved ? L"  (not saved: it can hold a password, so the undo leaves it as it is)" : L"");
}

bool HasSavedRegistryValues(const std::vector<RegistryValueRef>& values)
{
    for (const RegistryValueRef& v : values) {
        if (!v.neverSaved) return true;
    }
    return false;
}
