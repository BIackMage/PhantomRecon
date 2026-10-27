#include "pch.h"
#include "AppMessages.h"

#include <string>
#include <vector>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW(L"[AppMessages] ");
    OutputDebugStringW(msg.c_str());
    OutputDebugStringW(L"\n");
}

bool HasAppPayload(UINT message)
{
    return message == WM_APP_SCAN_FINISHED || message == WM_APP_AUDIT_FINISHED ||
           message == WM_APP_AI_RESPONSE || message == WM_APP_STATUS_TEXT;
}

void DeleteAppPayload(UINT message, LPARAM lParam)
{
    if (lParam == 0) return;
    switch (message) {
    case WM_APP_SCAN_FINISHED:  delete reinterpret_cast<ScanFinishedPayload*>(lParam);  break;
    case WM_APP_AUDIT_FINISHED: delete reinterpret_cast<AuditFinishedPayload*>(lParam); break;
    case WM_APP_AI_RESPONSE:    delete reinterpret_cast<AiResponsePayload*>(lParam);    break;
    case WM_APP_STATUS_TEXT:    delete reinterpret_cast<std::wstring*>(lParam);         break;
    default:
        DebugLog(L"DeleteAppPayload: message " + std::to_wstring(message) + L" has no payload type");
        return;
    }
    DebugLog(L"Freed the payload of message " + std::to_wstring(message) + L", never handled");
}

PayloadTracker::~PayloadTracker()
{
    FreeRemaining();
}

void PayloadTracker::Posted(HWND target, UINT message, LPARAM payload)
{
    size_t live = 0;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_live[payload] = Entry{ target, message };
        live = m_live.size();
    }
    DebugLog(L"Posting message " + std::to_wstring(message) + L", payloads in flight: " + std::to_wstring(live));
}

bool PayloadTracker::Claim(LPARAM payload)
{
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        found = m_live.erase(payload) > 0;
    }
    if (!found) DebugLog(L"Claim: payload already freed");
    return found;
}

int PayloadTracker::FreeFor(HWND target)
{
    std::vector<std::pair<LPARAM, UINT>> orphans;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto it = m_live.begin(); it != m_live.end();) {
            if (it->second.target == target) {
                orphans.push_back({ it->first, it->second.message });
                it = m_live.erase(it);
            }
            else {
                ++it;
            }
        }
    }
    for (const auto& o : orphans) DeleteAppPayload(o.second, o.first);
    if (!orphans.empty()) {
        DebugLog(L"FreeFor: " + std::to_wstring(orphans.size()) + L" payload(s) posted to a window being destroyed");
    }
    return static_cast<int>(orphans.size());
}

int PayloadTracker::FreeRemaining()
{
    std::map<LPARAM, Entry> left;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        left.swap(m_live);
    }
    for (const auto& kv : left) DeleteAppPayload(kv.second.message, kv.first);
    if (!left.empty()) DebugLog(L"FreeRemaining: " + std::to_wstring(left.size()) + L" payload(s) never handled");
    return static_cast<int>(left.size());
}
