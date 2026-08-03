import Foundation
import CryptoKit
import OSLog
import AppKit

private let licenseLog = Logger(subsystem: "com.manueldeprada.velun", category: "License")

// MARK: – License object

struct License: Codable, Equatable {
    let name:      String          // licensee
    let email:     String          // licensee email
    let issuedAt:  Date            // when the key was issued
    let expiresAt: Date?           // nil = perpetual
    let signature: String          // base64 Ed25519 signature over the canonical payload

    // Canonical signing payload — sorted-keys JSON of every field except `signature`.
    var signingPayload: Data? {
        var dict: [String: Any] = [
            "name":     name,
            "email":    email,
            "issuedAt": ISO8601DateFormatter().string(from: issuedAt),
        ]
        if let e = expiresAt {
            dict["expiresAt"] = ISO8601DateFormatter().string(from: e)
        }
        return try? JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys])
    }

    var isExpired: Bool {
        guard let e = expiresAt else { return false }
        return Date() > e
    }
}

// MARK: – Manager

@MainActor
final class AboutScreenManager: ObservableObject {

    private static let publicKeyB64 = "pNgujBd0grLuux7nTHII4e5evU9s94caBWmYVjEVGcY="

    private static let trialDays = 365
    private static let trialQuietUntilDaysRemaining = 30

    private static let verificationGraceDays = 14

    @Published private(set) var installAt: Date = .distantFuture
    @Published private(set) var license: License?
    @Published private(set) var lastVerifiedAt: Date?

    private var accessWatchTimer: Timer?
    private var lastAccessGranted: Bool = true

    init() {
        installAt = resolveInstallDate()
        license   = loadLicense()
        lastVerifiedAt = resolveLastVerifiedAt()
        lastAccessGranted = isAccessGranted
        accessWatchTimer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.enforceAccessGate() }
        }
        Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            await self?.verifyHeartbeat()
        }
    }

    func enforceAccessGate() {
        let granted = isAccessGranted
        if lastAccessGranted && !granted {
            VPNManager.shared.disconnectAll()
        }
        lastAccessGranted = granted
        // Republish so views observing trial countdown refresh on day rollover.
        objectWillChange.send()
    }

    // MARK: – Public state

    var hasLicense: Bool { license != nil && license?.isExpired == false }

    var isAccessGranted: Bool {
        if hasLicense { return true }
        return daysRemainingInTrial > 0
    }

    var isLicenseStale: Bool {
        guard hasLicense, let v = lastVerifiedAt else { return false }
        return Date().timeIntervalSince(v) > TimeInterval(Self.verificationGraceDays) * 86_400
    }

    var daysRemainingInTrial: Int {
        let elapsed = Date().timeIntervalSince(installAt)
        let remaining = TimeInterval(Self.trialDays * 86_400) - elapsed
        return max(0, Int(ceil(remaining / 86_400)))
    }

    var isInQuietTrialPeriod: Bool {
        !hasLicense && daysRemainingInTrial > Self.trialQuietUntilDaysRemaining
    }

    var shouldShowTrialBanner: Bool {
        guard !hasLicense, !isInQuietTrialPeriod else { return false }
        return daysRemainingInTrial > 0
    }

    var trialBannerText: String {
        let r = daysRemainingInTrial
        if r == 0 { return "Trial ended" }
        return "Trial: \(r) day\(r == 1 ? "" : "s") remaining"
    }

    var statusLabel: String {
        if let l = license, !l.isExpired {
            if let e = l.expiresAt {
                return "Licensed to \(l.email) (expires \(humanDate(e)))"
            }
            return "Licensed to \(l.email)"
        }
        if let l = license, l.isExpired {
            return "License expired (\(humanDate(l.expiresAt ?? .distantPast)))"
        }
        if isInQuietTrialPeriod { return "" }
        let r = daysRemainingInTrial
        if r > 0 { return "Trial: \(r) day\(r == 1 ? "" : "s") remaining" }
        return "Trial expired. License required"
    }

    // MARK: – Submit / remove

    enum SubmitResult: Equatable {
        case ok
        case parseError(String)
        case signatureInvalid
        case expired
        case serverRejected  // license has reached the per-license device limit
    }

    @discardableResult
    func submitLicense(_ text: String) async -> SubmitResult {
        let cleaned = text.trimmingCharacters(in: .whitespacesAndNewlines)

        let raw: Data
        if let direct = cleaned.data(using: .utf8),
           (try? JSONSerialization.jsonObject(with: direct)) != nil {
            raw = direct
        } else if let decoded = Data(base64Encoded: cleaned, options: .ignoreUnknownCharacters) {
            raw = decoded
        } else {
            return .parseError("Couldn't decode license. Paste the entire string you received.")
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let parsed: License
        do {
            parsed = try decoder.decode(License.self, from: raw)
        } catch {
            return .parseError(error.localizedDescription)
        }

        guard verify(parsed) else { return .signatureInvalid }
        if parsed.isExpired { return .expired }

        switch await checkActivation(blob: raw.base64EncodedString(), iid: Self.installID) {
        case .rejected:
            return .serverRejected
        case .confirmed:
            lastVerifiedAt = Date()
            writeLastVerifiedAt(lastVerifiedAt!)
        case .unknown:
            break   // fail-open for the buyer; grace clock starts once resolveLastVerifiedAt backfills it
        }

        license = parsed
        persistLicense(raw)
        licenseLog.info("License accepted for \(parsed.email, privacy: .public)")
        return .ok
    }

    @discardableResult
    func verifyHeartbeat() async -> Bool {
        guard hasLicense, let blob = KeychainHelper.getItem(account: Self.licenseKey) else { return true }
        switch await checkActivation(blob: blob, iid: Self.installID) {
        case .confirmed:
            lastVerifiedAt = Date()
            writeLastVerifiedAt(lastVerifiedAt!)
            return true
        case .rejected, .unknown:
            return false
        }
    }

    // MARK: – Server activation

    // Reuses the same install ID that Sparkle sends as ?iid= on update checks.
    private static let installIDKey = "velun.installationID"

    private static var installID: String {
        if let v = UserDefaults.standard.string(forKey: installIDKey) { return v }
        let new = UUID().uuidString.lowercased().replacingOccurrences(of: "-", with: "")
        UserDefaults.standard.set(new, forKey: installIDKey)
        return new
    }

    private enum ActivationResult {
        case confirmed          // server explicitly said {"ok":true}
        case rejected           // server explicitly said {"ok":false} (device limit)
        case unknown            // unreachable, non-200, or malformed — no proof either way
    }

    private func checkActivation(blob: String, iid: String) async -> ActivationResult {
        guard let url = URL(string: "https://store.manueldeprada.com/velun/api/activate.php") else { return .unknown }
        guard let body = try? JSONSerialization.data(withJSONObject: ["license": blob, "iid": iid]) else { return .unknown }
        var req = URLRequest(url: url, timeoutInterval: 10)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = body
        do {
            let (data, resp) = try await URLSession.shared.data(for: req)
            guard (resp as? HTTPURLResponse)?.statusCode == 200 else { return .unknown }
            guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let ok = json["ok"] as? Bool else { return .unknown }
            if !ok {
                licenseLog.warning("Activation rejected: \(json["reason"] as? String ?? "unknown", privacy: .public)")
                return .rejected
            }
            return .confirmed
        } catch {
            licenseLog.info("Activation check failed (\(error.localizedDescription, privacy: .public)) — fail-open")
            return .unknown
        }
    }

    func removeLicense() {
        license = nil
        lastVerifiedAt = nil
        KeychainHelper.removeItem(account: Self.licenseKey)
        KeychainHelper.removeItem(account: Self.verifiedKey)
        enforceAccessGate()
    }

    // MARK: – Verification

    private func verify(_ license: License) -> Bool {
        guard let pubKeyData = Data(base64Encoded: Self.publicKeyB64),
              let pubKey = try? Curve25519.Signing.PublicKey(rawRepresentation: pubKeyData),
              let payload = license.signingPayload,
              let sig = Data(base64Encoded: license.signature) else { return false }
        return pubKey.isValidSignature(sig, for: payload)
    }

    // MARK: – Persistence

    private static let licenseKey = "license-blob"

    private func loadLicense() -> License? {
        guard let s = KeychainHelper.getItem(account: Self.licenseKey),
              let data = Data(base64Encoded: s) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let lic = try? decoder.decode(License.self, from: data) else { return nil }
        return verify(lic) ? lic : nil
    }

    private func persistLicense(_ raw: Data) {
        KeychainHelper.setItem(raw.base64EncodedString(), account: Self.licenseKey)
    }

    // MARK: – Verification grace-window timestamp

    private static let verifiedKey = "license-verified-stamp"

    private func resolveLastVerifiedAt() -> Date? {
        guard hasLicense else { return nil }
        if let existing = readLastVerifiedAt() { return existing }
        let now = Date()
        writeLastVerifiedAt(now)
        return now
    }

    private func readLastVerifiedAt() -> Date? {
        guard let s = KeychainHelper.getItem(account: Self.verifiedKey) else { return nil }
        return parseTimestamp(s)
    }

    private func writeLastVerifiedAt(_ d: Date) {
        KeychainHelper.setItem(serializeTimestamp(d), account: Self.verifiedKey)
    }

    // MARK: – Install date (multi-source, take the earliest)

    private func resolveInstallDate() -> Date {
        let keychainDate    = readKeychainInstallDate()
        let appSupportDate  = readAppSupportInstallDate()
        let prefsDate       = readPrefsInstallDate()
        let candidates = [keychainDate, appSupportDate, prefsDate].compactMap { $0 }

        let resolved = candidates.min() ?? Date()
        writeKeychainInstallDate(resolved)
        writeAppSupportInstallDate(resolved)
        writePrefsInstallDate(resolved)
        licenseLog.info("Install date resolved: \(resolved.description, privacy: .public)")
        return resolved
    }

    private static let installKey = "install-stamp"

    private func readKeychainInstallDate() -> Date? {
        guard let s = KeychainHelper.getItem(account: Self.installKey) else { return nil }
        return parseTimestamp(s)
    }
    private func writeKeychainInstallDate(_ d: Date) {
        KeychainHelper.setItem(serializeTimestamp(d), account: Self.installKey)
    }

    private func readAppSupportInstallDate() -> Date? {
        let url = appSupportInstallURL()
        guard let s = try? String(contentsOf: url, encoding: .utf8) else { return nil }
        return parseTimestamp(s)
    }
    private func writeAppSupportInstallDate(_ d: Date) {
        let url = appSupportInstallURL()
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                 withIntermediateDirectories: true)
        try? serializeTimestamp(d).write(to: url, atomically: true, encoding: .utf8)
    }

    private func readPrefsInstallDate() -> Date? {
        guard let s = UserDefaults.standard.string(forKey: "velun.installStamp") else { return nil }
        return parseTimestamp(s)
    }
    private func writePrefsInstallDate(_ d: Date) {
        UserDefaults.standard.set(serializeTimestamp(d), forKey: "velun.installStamp")
    }

    private static let hmacKey = SymmetricKey(data: Data([
        0x6d, 0x70, 0x39, 0xf2, 0x12, 0x8a, 0x4b, 0xb1,
        0x91, 0x44, 0x77, 0xee, 0x53, 0x14, 0xc1, 0x8f,
        0xa0, 0x5e, 0xc8, 0x2e, 0x69, 0x9a, 0x77, 0x12,
        0x4d, 0x80, 0x16, 0x33, 0xa9, 0x67, 0x59, 0xea,
    ]))

    private func serializeTimestamp(_ d: Date) -> String {
        let secs = String(format: "%.0f", d.timeIntervalSince1970)
        let mac = HMAC<SHA256>.authenticationCode(for: Data(secs.utf8), using: Self.hmacKey)
        let macStr = Data(mac).base64EncodedString()
        return "\(secs)|\(macStr)"
    }

    private func parseTimestamp(_ s: String) -> Date? {
        let parts = s.split(separator: "|", maxSplits: 1).map(String.init)
        guard parts.count == 2,
              let secs = TimeInterval(parts[0]),
              let mac = Data(base64Encoded: parts[1]) else { return nil }
        let expected = HMAC<SHA256>.authenticationCode(for: Data(parts[0].utf8), using: Self.hmacKey)
        guard Data(expected) == mac else { return nil }
        return Date(timeIntervalSince1970: secs)
    }

    private func appSupportInstallURL() -> URL {
        let base = (try? FileManager.default.url(for: .applicationSupportDirectory,
                                                 in: .userDomainMask,
                                                 appropriateFor: nil,
                                                 create: true))
            ?? URL(fileURLWithPath: NSHomeDirectory())
                .appendingPathComponent("Library/Application Support")
        return base.appendingPathComponent("velun/.install")
    }

    private func humanDate(_ d: Date) -> String {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .none
        return f.string(from: d)
    }
}
