#pragma once

#include "AppState.h"

// ---------------------------------------------------------------------------
// AuditController: runs the posture audit on AppState::worker and applies the
// result on the UI thread.
//
// Start: UI thread. The audit thread writes AppState::audit progress fields and
// posts WM_APP_AUDIT_PROGRESS (coalesced) and, once, WM_APP_AUDIT_FINISHED with
// an AuditFinishedPayload. It never touches a window.
// ---------------------------------------------------------------------------

// Start the audit. Does nothing when one is already running.
void StartAuditInBackground(AppState& app);

// WM_APP_AUDIT_PROGRESS handler.
void OnAuditProgressMessage(AppState& app);

// WM_APP_AUDIT_FINISHED handler. Takes ownership of the payload.
void OnAuditFinishedMessage(AppState& app, AuditFinishedPayload* payload);
