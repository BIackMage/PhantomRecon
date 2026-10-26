#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

// ---------------------------------------------------------------------------
// BackgroundWorker: every background thread in the app starts here and is
// joined here. Replaces std::thread(...).detach(), which left threads running
// into a destroyed window at exit.
//
// Run() starts a job on a new thread. Finished threads are reaped lazily on the
// next Run() or ActiveCount(). JoinAll() blocks until every job has returned;
// wWinMain calls it after the message loop. Jobs should check their cancel
// flag often enough that JoinAll does not stall the exit.
// ---------------------------------------------------------------------------

class BackgroundWorker {
public:
    BackgroundWorker() = default;
    ~BackgroundWorker();

    BackgroundWorker(const BackgroundWorker&) = delete;
    BackgroundWorker& operator=(const BackgroundWorker&) = delete;

    // Start a job. Exceptions escaping the job are caught and logged, never fatal.
    void Run(std::function<void()> job);

    // Block until every started job has returned.
    void JoinAll();

    // Wait at most timeoutMs for every job to return, joining the ones that did.
    // True when none is left. False when a job is still stuck in a blocking call
    // (a slow AI server, a file that takes long to hash); the caller decides what
    // to do, and wWinMain then ends the process instead of hanging invisibly.
    bool JoinAllFor(unsigned long timeoutMs);

    // Number of jobs still running.
    size_t ActiveCount();

private:
    struct Slot {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> finished;
    };

    std::mutex        m_mutex;
    std::vector<Slot> m_slots;

    // Join and drop every slot whose job has returned. Caller holds m_mutex.
    void ReapFinishedLocked();
};
