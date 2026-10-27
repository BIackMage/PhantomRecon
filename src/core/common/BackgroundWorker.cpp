#include "pch.h"
#include "BackgroundWorker.h"

#include <windows.h>
#include <string>

static void DebugLog(const wchar_t* msg)
{
    OutputDebugStringW(L"[BackgroundWorker] ");
    OutputDebugStringW(msg);
    OutputDebugStringW(L"\n");
}

BackgroundWorker::~BackgroundWorker()
{
    JoinAll();
}

void BackgroundWorker::Run(std::function<void()> job)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    ReapFinishedLocked();

    Slot slot;
    slot.finished = std::make_shared<std::atomic<bool>>(false);
    std::shared_ptr<std::atomic<bool>> finished = slot.finished;

    slot.thread = std::thread([job, finished]() {
        try {
            job();
        }
        catch (const std::exception& e) {
            std::string what = e.what();
            std::wstring wide(what.begin(), what.end());
            DebugLog((L"job threw std::exception: " + wide).c_str());
        }
        catch (...) {
            DebugLog(L"job threw a non-std exception");
        }
        finished->store(true);
    });

    m_slots.push_back(std::move(slot));
    DebugLog((L"job started, active=" + std::to_wstring(m_slots.size())).c_str());
}

void BackgroundWorker::JoinAll()
{
    std::vector<Slot> slots;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        slots.swap(m_slots);
    }

    if (!slots.empty()) {
        DebugLog((L"JoinAll waiting on " + std::to_wstring(slots.size()) + L" job(s)").c_str());
    }
    for (Slot& slot : slots) {
        if (slot.thread.joinable()) {
            slot.thread.join();
        }
    }
    if (!slots.empty()) {
        DebugLog(L"JoinAll complete");
    }
}

bool BackgroundWorker::JoinAllFor(unsigned long timeoutMs)
{
    ULONGLONG start = GetTickCount64();
    for (;;) {
        size_t left = 0;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            ReapFinishedLocked();
            left = m_slots.size();
        }
        if (left == 0) {
            DebugLog(L"JoinAllFor: every job returned");
            return true;
        }
        if (GetTickCount64() - start >= timeoutMs) {
            DebugLog((L"JoinAllFor: " + std::to_wstring(left) + L" job(s) still running after " +
                      std::to_wstring(timeoutMs) + L" ms").c_str());
            return false;
        }
        Sleep(20);
    }
}

size_t BackgroundWorker::ActiveCount()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    ReapFinishedLocked();
    return m_slots.size();
}

void BackgroundWorker::ReapFinishedLocked()
{
    for (size_t i = 0; i < m_slots.size();) {
        if (m_slots[i].finished->load()) {
            if (m_slots[i].thread.joinable()) {
                m_slots[i].thread.join();
            }
            m_slots.erase(m_slots.begin() + static_cast<std::ptrdiff_t>(i));
        }
        else {
            ++i;
        }
    }
}
