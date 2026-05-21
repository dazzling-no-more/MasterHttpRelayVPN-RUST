package com.dazzlingnomore.mhrv

import com.dazzlingnomore.mhrv.VpnLifecycleGuards.PauseDecision
import com.dazzlingnomore.mhrv.VpnLifecycleGuards.ResumeDecision
import com.dazzlingnomore.mhrv.VpnLifecycleGuards.StartDecision
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Decision-matrix tests for [VpnLifecycleGuards]. The service's
 * pause / resume / stop / connect handlers each consult one of the
 * tryXxx methods; the failure modes that bit us in production review
 * (double-tap Resume, Pause-after-Stop, sticky restart resurrection)
 * are all encoded as transitions through these flags. Covering them
 * in isolation means we don't need Robolectric to verify the state
 * machine.
 */
class VpnLifecycleGuardsTest {
    @Test
    fun freshGuards_areNotPausedNotStopping() {
        val g = VpnLifecycleGuards()
        assertFalse(g.isPaused)
        assertFalse(g.isStopRequested)
    }

    // -- tryStart ----------------------------------------------------

    @Test
    fun tryStart_freshGuards_proceeds() {
        val g = VpnLifecycleGuards()
        assertEquals(StartDecision.PROCEED, g.tryStart(isRunning = false))
    }

    @Test
    fun tryStart_alreadyRunning_skips() {
        val g = VpnLifecycleGuards()
        // Simulate "running but not paused": Connect-while-running.
        assertEquals(StartDecision.ALREADY_RUNNING, g.tryStart(isRunning = true))
    }

    @Test
    fun tryStart_alreadyRunningButPaused_proceeds() {
        // Resume path: VpnState.isRunning may still be false, but even
        // if a stale true leaked through, paused state must let the
        // resume start go ahead.
        val g = VpnLifecycleGuards()
        g.tryPause() // marks paused
        assertEquals(StartDecision.PROCEED, g.tryStart(isRunning = true))
    }

    @Test
    fun tryStart_secondCallWithoutFinish_skips() {
        val g = VpnLifecycleGuards()
        assertEquals(StartDecision.PROCEED, g.tryStart(isRunning = false))
        // Double-tap Connect: second call is coalesced.
        assertEquals(StartDecision.ALREADY_STARTING, g.tryStart(isRunning = false))
    }

    @Test
    fun tryStart_afterFinish_proceedsAgain() {
        val g = VpnLifecycleGuards()
        g.tryStart(isRunning = false)
        g.finishStart()
        assertEquals(StartDecision.PROCEED, g.tryStart(isRunning = false))
    }

    @Test
    fun tryStart_afterStopRequested_neverProceeds() {
        val g = VpnLifecycleGuards()
        g.requestStop()
        assertEquals(StartDecision.STOPPING, g.tryStart(isRunning = false))
        assertEquals(StartDecision.STOPPING, g.tryStart(isRunning = true))
    }

    // -- tryPause ----------------------------------------------------

    @Test
    fun tryPause_freshGuards_proceedsAndMarksPaused() {
        val g = VpnLifecycleGuards()
        assertEquals(PauseDecision.PROCEED, g.tryPause())
        assertTrue(g.isPaused)
    }

    @Test
    fun tryPause_secondCall_isNoOp() {
        val g = VpnLifecycleGuards()
        g.tryPause()
        assertEquals(PauseDecision.ALREADY_PAUSED, g.tryPause())
    }

    @Test
    fun tryPause_afterStopRequested_skipsWithoutSettingPaused() {
        val g = VpnLifecycleGuards()
        g.requestStop()
        assertEquals(PauseDecision.STOPPING, g.tryPause())
        assertFalse("Pause must not flip isPaused after stop was requested", g.isPaused)
    }

    // -- tryResume ---------------------------------------------------

    @Test
    fun tryResume_whenNotPaused_skips() {
        val g = VpnLifecycleGuards()
        assertEquals(ResumeDecision.NOT_PAUSED, g.tryResume())
    }

    @Test
    fun tryResume_whenPaused_proceedsWithoutFlippingPausedFlag() {
        // Contract: tryResume signals user intent but does NOT mutate
        // pausedFlag --- the atomic paused→running transition happens
        // in tryStart's CAS. Splitting the steps means a Resume that
        // races a sibling Connect-from-app can't have one consume the
        // other's transition.
        val g = VpnLifecycleGuards()
        g.tryPause()
        assertEquals(ResumeDecision.PROCEED, g.tryResume())
        assertTrue("paused flag must stay set until tryStart claims", g.isPaused)
        // tryStart is the boundary that actually clears it.
        g.tryStart(isRunning = true)
        assertFalse(g.isPaused)
    }

    @Test
    fun tryResume_doubleTap_secondCallSkipsAfterStartClaims() {
        val g = VpnLifecycleGuards()
        g.tryPause()
        // First Resume signals intent; spawnStart's tryStart follows
        // and atomically clears pausedFlag as part of claiming the
        // starting slot.
        assertEquals(ResumeDecision.PROCEED, g.tryResume())
        assertEquals(StartDecision.PROCEED, g.tryStart(isRunning = true))
        // Second Resume tap arrives after the claim. pausedFlag is
        // now false, so it correctly no-ops.
        assertEquals(ResumeDecision.NOT_PAUSED, g.tryResume())
    }

    @Test
    fun tryResume_afterStopRequested_skipsEvenIfPaused() {
        val g = VpnLifecycleGuards()
        g.tryPause()
        g.requestStop()
        assertEquals(ResumeDecision.STOPPING, g.tryResume())
        // Paused flag is left as-is on the STOPPING branch; we never
        // proceed to a startEverything, so its value doesn't matter to
        // the lifecycle outcome, but document the observed state.
        assertTrue(g.isPaused)
    }

    // -- requestStop -------------------------------------------------

    @Test
    fun requestStop_isSticky() {
        val g = VpnLifecycleGuards()
        g.requestStop()
        assertTrue(g.isStopRequested)
        // No "unrequestStop" --- once stop is requested, every subsequent
        // tryXxx must observe STOPPING.
        assertEquals(StartDecision.STOPPING, g.tryStart(isRunning = false))
        assertEquals(PauseDecision.STOPPING, g.tryPause())
        assertEquals(ResumeDecision.STOPPING, g.tryResume())
    }

    @Test
    fun stopBeatsConcurrentResume_resumeDoesNotProceed() {
        // Pause-then-Stop scenario from production review: pause leaves
        // isPaused = true, then stop arrives. A later Resume tap should
        // not slip a startEverything past the stop.
        val g = VpnLifecycleGuards()
        g.tryPause()
        g.requestStop()
        assertEquals(ResumeDecision.STOPPING, g.tryResume())
    }

    @Test
    fun stopBeatsConcurrentConnect_startDoesNotProceed() {
        // Race: user taps Stop, then the OS sticky-restarts the service
        // and delivers a null-action intent (Connect path). spawnStart's
        // guard must skip.
        val g = VpnLifecycleGuards()
        g.requestStop()
        assertEquals(StartDecision.STOPPING, g.tryStart(isRunning = false))
    }

    // -- compound scenarios -----------------------------------------

    @Test
    fun pauseResumeCycle_endsInRunnableState() {
        val g = VpnLifecycleGuards()
        // Connect
        assertEquals(StartDecision.PROCEED, g.tryStart(isRunning = false))
        g.finishStart()
        // Pause
        assertEquals(PauseDecision.PROCEED, g.tryPause())
        // Resume signals intent; tryStart commits the transition.
        assertEquals(ResumeDecision.PROCEED, g.tryResume())
        assertEquals(StartDecision.PROCEED, g.tryStart(isRunning = true))
        g.finishStart()
        assertFalse(g.isPaused)
        // A subsequent Connect-while-running is a clean ALREADY_RUNNING.
        assertEquals(StartDecision.ALREADY_RUNNING, g.tryStart(isRunning = true))
    }

    @Test
    fun cancelPausedIntentClearsPaused() {
        // The pause body calls cancelPausedIntent() when its teardown
        // turned out to be a no-op (stale PAUSE intent, pause after
        // failed startup). After this, a future Resume tap correctly
        // no-ops --- there's nothing to resume.
        val g = VpnLifecycleGuards()
        g.tryPause()
        assertTrue(g.isPaused)
        g.cancelPausedIntent()
        assertFalse(g.isPaused)
        assertEquals(ResumeDecision.NOT_PAUSED, g.tryResume())
    }

    /**
     * Critical regression test: rapid Pause then Resume taps must
     * leave the service runnable, not stuck in a half-torn-down
     * state with a dead Resume button.
     *
     * The bug: tryResume used to flip pausedFlag false eagerly. If a
     * Resume followed a Pause before the pause
     * worker had run, spawnStart's tryStart then saw isRunning=true
     * (stale, pause's teardown not yet run) AND pausedFlag=false
     * (just cleared by tryResume) → ALREADY_RUNNING → bail. The
     * pause worker would then tear down native AND post a "Paused"
     * notification with a Resume button that NO LONGER WORKED
     * (pausedFlag was false, so future Resume taps saw NOT_PAUSED).
     *
     * Fix: tryResume doesn't mutate pausedFlag; tryStart does, but
     * it captures wasPaused at entry so the ALREADY_RUNNING check
     * still gets the right answer.
     */
    @Test
    fun rapidPauseThenResume_resumeStartProceedsDespiteStaleIsRunning() {
        val g = VpnLifecycleGuards()
        // Service is running, native side up, VpnState.isRunning = true.
        // User taps Pause: pausedFlag becomes true, pause worker queued.
        assertEquals(PauseDecision.PROCEED, g.tryPause())
        // User taps Resume before pause worker has run --- isRunning is
        // STILL true (stale).
        assertEquals(ResumeDecision.PROCEED, g.tryResume())
        // spawnStart's tryStart sees isRunning=true AND pausedFlag=true.
        // wasPaused capture means it doesn't hit ALREADY_RUNNING; it
        // PROCEEDs and clears pausedFlag atomically.
        val startDecision = g.tryStart(isRunning = true)
        assertEquals(StartDecision.PROCEED, startDecision)
        assertFalse("tryStart's claim must clear pausedFlag", g.isPaused)
    }

    /**
     * Companion to the rapid-Pause-Resume test: when the pause worker
     * finally runs after a concurrent Resume already claimed the
     * starting slot, its post-teardown notify gate must observe
     * pausedFlag=false (cleared by tryStart) and SKIP the paused
     * notification. Otherwise the worker would overwrite the
     * incoming RUNNING notification with a stale "Paused" claim.
     */
    @Test
    fun rapidPauseThenResume_pauseWorkerSkipsPausedNotifOnResumeClear() {
        val g = VpnLifecycleGuards()
        g.tryPause()
        // Resume + start claim happens before pause worker enters lock.
        g.tryResume()
        g.tryStart(isRunning = true)
        // Pause worker now enters its synchronized body, runs runTeardown
        // and checks gates. The pausedFlag-cleared gate sees false and
        // returns without notifying.
        assertFalse("pause worker's gate reads pausedFlag and must skip", g.isPaused)
    }

    /**
     * Connect-from-app while service is paused (no native state):
     * the else branch no longer calls clearPaused() — it relies on
     * tryStart's wasPaused capture to handle the transition.
     */
    @Test
    fun connectFromAppWhilePaused_proceedsAndClearsPaused() {
        val g = VpnLifecycleGuards()
        g.tryPause()
        // The Connect-from-app else branch in onStartCommand goes
        // straight to spawnStart, which calls tryStart with the live
        // isRunning value. After a completed pause teardown,
        // isRunning is false.
        assertEquals(StartDecision.PROCEED, g.tryStart(isRunning = false))
        assertFalse(g.isPaused)
    }

    /**
     * Connect-from-app racing a pending pause teardown: VpnState.isRunning
     * is still stale-true at the moment of Connect because the pause
     * worker hasn't ran yet. tryStart must NOT bail with
     * ALREADY_RUNNING — same wasPaused capture as Resume handles this.
     */
    @Test
    fun connectFromAppDuringPendingPauseTeardown_proceeds() {
        val g = VpnLifecycleGuards()
        g.tryPause()
        // isRunning is stale-true (pause worker queued but not run).
        assertEquals(StartDecision.PROCEED, g.tryStart(isRunning = true))
        assertFalse(g.isPaused)
    }

    // -- shouldStopSelfIfIdle ---------------------------------------

    @Test
    fun shouldStopSelfIfIdle_freshGuards_isTrue() {
        // A stale Pause/Resume PendingIntent reaches a brand-new
        // service instance: nothing running, nothing paused, nothing
        // starting, no stop pending. The service has no reason to
        // live and should release its "started" claim before the OS
        // is forced to clean up an invisible sticky service.
        val g = VpnLifecycleGuards()
        assertTrue(g.shouldStopSelfIfIdle(isRunning = false))
    }

    @Test
    fun shouldStopSelfIfIdle_whileRunning_isFalse() {
        // The service is up and serving traffic; a stale no-op
        // action must not knock it offline.
        val g = VpnLifecycleGuards()
        assertFalse(g.shouldStopSelfIfIdle(isRunning = true))
    }

    @Test
    fun shouldStopSelfIfIdle_whilePaused_isFalse() {
        // Paused service has a notification with a Resume button and
        // is the user's preserved state --- keep it alive.
        val g = VpnLifecycleGuards()
        g.tryPause()
        assertFalse(g.shouldStopSelfIfIdle(isRunning = false))
    }

    @Test
    fun shouldStopSelfIfIdle_whileStarting_isFalse() {
        // A Connect is in flight. A stale Resume arriving at the
        // same instant must not kill the genuine startup.
        val g = VpnLifecycleGuards()
        g.tryStart(isRunning = false)
        assertFalse(g.shouldStopSelfIfIdle(isRunning = false))
    }

    @Test
    fun shouldStopSelfIfIdle_whileStopping_isFalse() {
        // Stop has been requested; rahgozar-teardown will call stopSelf
        // when it's done. The no-op handler doesn't need to (and
        // shouldn't) double-call.
        val g = VpnLifecycleGuards()
        g.requestStop()
        assertFalse(g.shouldStopSelfIfIdle(isRunning = false))
    }

    /**
     * Cancellation boundary: spawnStart accepted the start (tryStart →
     * PROCEED), but before the worker thread actually entered
     * `startEverything`'s `synchronized` block, an `ACTION_STOP` arrived
     * and called `requestStop`. The worker's first action inside the
     * lock is to check `isStopRequested` and bail. This test pins that
     * contract.
     *
     * Without this guard, a queued rahgozar-start worker would acquire
     * lifecycleLock AFTER a quick teardown (which saw empty state and
     * released immediately) and proceed to call startForeground +
     * Native.startProxy, resurrecting a service the user already
     * Stopped.
     */
    @Test
    fun stopRequestedAfterWorkerLaunch_workerSeesStopFlag() {
        val g = VpnLifecycleGuards()
        // 1. spawnStart accepts the start request — worker is queued.
        assertEquals(StartDecision.PROCEED, g.tryStart(isRunning = false))
        // 2. ACTION_STOP arrives on main thread. Worker hasn't entered
        //    startEverything's synchronized block yet.
        g.requestStop()
        // 3. Worker finally reaches its first instruction inside the
        //    lock: the isStopRequested check. It must observe true and
        //    bail without calling startForeground / Native.startProxy.
        assertTrue("worker must see stop flag set during its check", g.isStopRequested)
        // 4. Worker exits via its finally, releasing the starting slot.
        //    Any subsequent (defensive) start attempt also sees STOPPING.
        g.finishStart()
        assertEquals(StartDecision.STOPPING, g.tryStart(isRunning = false))
    }

    /**
     * Sibling case: a start was in flight (or queued) and pause arrives
     * concurrently with stop. The pause's teardown thread must also see
     * stopRequested when it reaches its own gate (the "skip paused
     * notify" check), and the start must abort. End state: no
     * notifications, no running native side, isPaused doesn't matter.
     */
    @Test
    fun startAndPauseAndStop_compoundRace_allYieldToStop() {
        val g = VpnLifecycleGuards()
        assertEquals(StartDecision.PROCEED, g.tryStart(isRunning = false))
        // Pause arrives before worker enters the lock — accepted because
        // stopRequested isn't set yet.
        assertEquals(PauseDecision.PROCEED, g.tryPause())
        // Stop arrives next.
        g.requestStop()
        // The rahgozar-pause worker, after its teardown, checks isStopRequested
        // and skips its notify.
        assertTrue(g.isStopRequested)
        // The rahgozar-start worker enters the lock and bails the same way.
        // (Modeled as a guards.isStopRequested read; the actual call site
        // is inside startEverything's synchronized block.)
        assertTrue(g.isStopRequested)
        // Both workers finish their finally hooks.
        g.finishStart()
        // Subsequent connect attempts are sticky-rejected.
        assertEquals(StartDecision.STOPPING, g.tryStart(isRunning = false))
    }

    /**
     * Documents the per-generation worker-flag pattern used in
     * `RahgozarVpnService.startEverything` for tun2proxyRunning. Each
     * worker captures a FRESH `AtomicBoolean` and only mutates that
     * captured local in its finally; the service-side field is
     * reassigned on each fresh spawn. A zombie worker from a
     * previous generation (a teardown's join timed out, the native
     * code returned much later) writing through its captured local
     * therefore can't poison the field that the current
     * generation's teardown depends on.
     *
     * Pinned here as a behaviour-level unit test: the actual worker
     * spawn lives in the service body which needs instrumentation
     * to exercise. Verifying the pattern semantics directly is
     * cheap and documents the invariant a future maintainer must
     * not regress.
     */
    @Test
    fun perGenerationWorkerFlag_zombieFinallyDoesNotPoisonNewerGeneration() {
        var fieldFlag: AtomicBoolean = AtomicBoolean(false)
        // Gen 1 spawn: capture and assign a fresh AtomicBoolean.
        val gen1 = AtomicBoolean(true)
        fieldFlag = gen1
        // Teardown timed out joining gen 1; native code is still in
        // flight. A fresh Connect/Resume spawns gen 2, reassigning
        // the field.
        val gen2 = AtomicBoolean(true)
        fieldFlag = gen2
        // Gen 1's zombie finally finally runs many seconds later.
        // It writes ONLY through its captured local (gen1), not
        // through the field.
        gen1.set(false)
        // A subsequent teardown reads the field. The signal that gen
        // 2's worker is alive and needs Tun2proxy.stop() is intact.
        assertTrue("gen 1's zombie finally must not poison gen 2's flag", fieldFlag.get())
        // Sanity check: gen 1's local DID get cleared.
        assertFalse(gen1.get())
    }
}
