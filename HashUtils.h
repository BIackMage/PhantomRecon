#pragma once

#include <string>
#include <windows.h>

// ---------------------------------------------------------------------------
// HashUtils — file hashing utilities (SHA-256)
// Uses BCrypt (modern Windows CNG API) for SHA-256 computation.
// ---------------------------------------------------------------------------

// Compute SHA-256 of a file and return as lowercase hex string.
// Returns empty string on failure.
std::wstring ComputeFileSHA256(const std::wstring& filePath);
