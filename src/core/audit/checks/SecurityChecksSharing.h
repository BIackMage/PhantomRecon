#pragma once

#include "SecurityChecks.h"
#include "HostRules.h"   // ShareFacts

// ---------------------------------------------------------------------------
// SecurityChecksSharing.cpp: what this PC opens to other computers. Shared
// folders and their permissions, guest and anonymous SMB access, and inbound
// firewall rules for public networks. Everything is read on this PC only; no
// other computer is contacted. Verdicts come from HostRules.cpp.
// ---------------------------------------------------------------------------

SecurityCheckResult CheckSharedFolders();     // net.shares
SecurityCheckResult CheckSmbGuestAccess();    // net.smbguest
SecurityCheckResult CheckFirewallRules();     // fw.rules

// The two ways net.shares reads the share list (name, path, type and share
// permissions; the folder permissions are not filled). The Server service
// (NetShareEnum level 502) answers administrators; the registry copy it keeps
// (LanmanServer\Shares and Shares\Security) is what a normal user gets. Exposed so the
// tests can compare them on one PC. False with error set when the list cannot be read.
bool ReadShareListFromServer(std::vector<ShareFacts>& out, std::wstring& error);
bool ReadShareListFromRegistry(std::vector<ShareFacts>& out, std::wstring& error);
