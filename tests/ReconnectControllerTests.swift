import Foundation

func testReconnectPolicyBackoffSchedule() {
    R.enter("ReconnectPolicy: exponential backoff with cap")
    let p = ReconnectPolicy(initialBackoff: 1, maxBackoff: 30, multiplier: 2, maxAttempts: 8)
    R.assertEqual(p.delay(beforeRetry: 1),  1.0,  "1st retry = initial backoff")
    R.assertEqual(p.delay(beforeRetry: 2),  2.0,  "2nd retry doubles")
    R.assertEqual(p.delay(beforeRetry: 3),  4.0,  "3rd retry quadruples")
    R.assertEqual(p.delay(beforeRetry: 4),  8.0,  "4th retry")
    R.assertEqual(p.delay(beforeRetry: 5),  16.0, "5th retry")
    R.assertEqual(p.delay(beforeRetry: 6),  30.0, "6th retry caps at maxBackoff")
    R.assertEqual(p.delay(beforeRetry: 99), 30.0, "far-future retry stays at cap")
}

func testReconnectPolicyZeroAttemptsRejected() {
    R.enter("ReconnectPolicy: enforces at least 1 attempt")
    let p = ReconnectPolicy(initialBackoff: 1, maxBackoff: 1, multiplier: 1, maxAttempts: 0)
    // The policy carries 0; controller below clamps to 1.
    R.assertEqual(p.maxAttempts, 0, "raw value preserved")
}

func testReconnectControllerFirstTrySuccess() async {
    R.enter("ReconnectController: succeeds on first attempt")
    let c = ReconnectController(policy: .default, sleep: { _ in })
    var calls = 0
    let outcome = await c.run { calls += 1 }
    R.assertEqual(calls, 1, "attempt called exactly once")
    R.assertEqual(outcome, .succeeded(attempts: 1), "reports 1 attempt")
}

func testReconnectControllerSucceedsAfterTransientFailures() async {
    R.enter("ReconnectController: succeeds after 2 transient failures")
    let p = ReconnectPolicy(initialBackoff: 1, maxBackoff: 30, multiplier: 2, maxAttempts: 8)
    var sleeps: [TimeInterval] = []
    let c = ReconnectController(policy: p, sleep: { sleeps.append($0) })
    var calls = 0
    let outcome = await c.run {
        calls += 1
        if calls < 3 { throw NSError(domain: "x", code: 1) }
    }
    R.assertEqual(calls, 3, "3 attempts (2 fail, 3rd succeeds)")
    R.assertEqual(outcome, .succeeded(attempts: 3), "outcome reports 3 attempts")
    R.assertEqual(sleeps, [1.0, 2.0], "slept between retries with backoff schedule")
}

func testReconnectControllerExhaustsAndCarriesLastError() async {
    R.enter("ReconnectController: exhausts after maxAttempts")
    let p = ReconnectPolicy(initialBackoff: 0.001, maxBackoff: 0.001, multiplier: 1, maxAttempts: 3)
    let c = ReconnectController(policy: p, sleep: { _ in })
    var calls = 0
    let outcome = await c.run {
        calls += 1
        throw NSError(domain: "boom", code: 1, userInfo: [NSLocalizedDescriptionKey: "kaboom"])
    }
    R.assertEqual(calls, 3, "tried exactly maxAttempts times")
    if case let .exhausted(attempts, lastError) = outcome {
        R.assertEqual(attempts, 3, "exhausted attempt count")
        R.assertTrue(lastError.contains("kaboom"), "exhaustion preserves last error string")
    } else {
        R.assertTrue(false, "expected .exhausted, got \(outcome)")
    }
}

func testReconnectControllerSleepScheduleAppliedBetweenRetriesOnly() async {
    R.enter("ReconnectController: sleep only between retries, not before first or after last")
    let p = ReconnectPolicy(initialBackoff: 1, maxBackoff: 30, multiplier: 2, maxAttempts: 4)
    var sleeps: [TimeInterval] = []
    let c = ReconnectController(policy: p, sleep: { sleeps.append($0) })
    var calls = 0
    _ = await c.run {
        calls += 1
        throw NSError(domain: "x", code: 1)
    }
    R.assertEqual(calls, 4, "tried 4 times")
    R.assertEqual(sleeps, [1.0, 2.0, 4.0], "exactly 3 sleeps with backoff")
}

func testReconnectControllerClampsZeroMaxAttemptsToOne() async {
    R.enter("ReconnectController: clamps maxAttempts<1 to 1 attempt")
    let p = ReconnectPolicy(initialBackoff: 0, maxBackoff: 0, multiplier: 1, maxAttempts: 0)
    let c = ReconnectController(policy: p, sleep: { _ in })
    var calls = 0
    let outcome = await c.run { calls += 1 }
    R.assertEqual(calls, 1, "still ran once even with maxAttempts=0")
    R.assertEqual(outcome, .succeeded(attempts: 1), "reports 1")
}
