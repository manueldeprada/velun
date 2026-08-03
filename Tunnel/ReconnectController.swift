import Foundation

public struct ReconnectPolicy: Equatable {
    public var initialBackoff: TimeInterval
    public var maxBackoff:     TimeInterval
    public var multiplier:     Double
    public var maxAttempts:    Int

    public init(initialBackoff: TimeInterval = 1.0,
                maxBackoff:     TimeInterval = 30.0,
                multiplier:     Double       = 2.0,
                maxAttempts:    Int          = 8) {
        self.initialBackoff = initialBackoff
        self.maxBackoff     = maxBackoff
        self.multiplier     = multiplier
        self.maxAttempts    = maxAttempts
    }

    public static let `default` = ReconnectPolicy()

    public func delay(beforeRetry n: Int) -> TimeInterval {
        guard n >= 1 else { return 0 }
        let raw = initialBackoff * pow(multiplier, Double(n - 1))
        return min(raw, maxBackoff)
    }
}

public enum ReconnectOutcome: Equatable {
    case succeeded(attempts: Int)
    case exhausted(attempts: Int, lastError: String)
}

public final class ReconnectController {
    private let policy: ReconnectPolicy
    private let sleep:  (TimeInterval) async -> Void

    public init(policy: ReconnectPolicy = .default,
                sleep: @escaping (TimeInterval) async -> Void
                    = { secs in try? await Task.sleep(nanoseconds: UInt64(secs * 1_000_000_000)) }) {
        self.policy = policy
        self.sleep  = sleep
    }

    public func run(_ attempt: () async throws -> Void) async -> ReconnectOutcome {
        let total = max(1, policy.maxAttempts)
        var lastErr = "unknown"
        for k in 1...total {
            if Task.isCancelled { return .exhausted(attempts: k - 1, lastError: "cancelled") }
            if k > 1 {
                await sleep(policy.delay(beforeRetry: k - 1))
                if Task.isCancelled { return .exhausted(attempts: k - 1, lastError: "cancelled") }
            }
            do {
                try await attempt()
                return .succeeded(attempts: k)
            } catch {
                lastErr = error.localizedDescription
            }
        }
        return .exhausted(attempts: total, lastError: lastErr)
    }
}
