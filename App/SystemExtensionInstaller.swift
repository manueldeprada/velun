import Foundation
import SystemExtensions
import OSLog

private let log = Logger(subsystem: "com.manueldeprada.velun", category: "SystemExtension")

@MainActor
final class SystemExtensionInstaller: NSObject {
    enum Result {
        case completed
        case needsApproval
        /// OSSystemExtensionError.forbiddenBySystemPolicy (10).
        case blockedByPolicy
        /// OSSystemExtensionError.authorizationRequired (13): needs an admin.
        case needsAdminAuthorization
        case failed(String)
    }

    static let extensionIdentifier = "com.manueldeprada.velun.PacketTunnel"
    static let shared = SystemExtensionInstaller()

    private var pending: [(Result) -> Void] = []
    // Keep a strong reference so the request isn't released mid-flight.
    private var inflightRequest: OSSystemExtensionRequest?

    private(set) var sawPolicyDenial = false

    func activate(_ completion: @escaping (Result) -> Void) {
        if inflightRequest != nil {
            log.info("activate: queueing on in-flight request (callers=\(self.pending.count + 1))")
            pending.append(completion)
            return
        }
        pending.append(completion)
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        inflightRequest = request
        OSSystemExtensionManager.shared.submitRequest(request)
        log.info("Submitted activation request for \(Self.extensionIdentifier, privacy: .public)")
    }

    private func finish(_ result: Result) {
        let cbs = pending
        pending.removeAll()
        inflightRequest = nil
        for cb in cbs { cb(result) }
    }
}

extension SystemExtensionInstaller: OSSystemExtensionRequestDelegate {

    nonisolated func request(_ request: OSSystemExtensionRequest,
                             actionForReplacingExtension existing: OSSystemExtensionProperties,
                             withExtension ext: OSSystemExtensionProperties)
                             -> OSSystemExtensionRequest.ReplacementAction {
        log.info("Replacing existing extension v\(existing.bundleShortVersion, privacy: .public) with v\(ext.bundleShortVersion, privacy: .public)")
        return .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        log.info("Activation needs user approval — opening System Settings → Privacy & Security")
        Task { @MainActor in
            NotificationCenter.default.post(name: .velunDismissPopover, object: nil)
            self.finish(.needsApproval)
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest,
                             didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed:
            log.info("Activation completed")
            Task { @MainActor in self.finish(.completed) }
        case .willCompleteAfterReboot:
            log.info("Activation will complete after reboot")
            Task { @MainActor in self.finish(.failed("Activation will finish after a reboot.")) }
        @unknown default:
            log.error("Activation finished with unknown result: \(result.rawValue, privacy: .public)")
            Task { @MainActor in self.finish(.failed("Activation finished with unknown result.")) }
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest,
                             didFailWithError error: Error) {
        let ns = error as NSError
        let name = Self.codeName(ns)
        log.error("Activation failed: \(ns.domain, privacy: .public) \(ns.code, privacy: .public) (\(name, privacy: .public))")
        let result: Result
        if ns.domain == OSSystemExtensionErrorDomain,
           let code = OSSystemExtensionError.Code(rawValue: ns.code) {
            switch code {
            case .forbiddenBySystemPolicy: result = .blockedByPolicy
            case .authorizationRequired:   result = .needsAdminAuthorization
            default:                       result = .failed("\(name) (\(ns.code))")
            }
        } else {
            result = .failed(ns.localizedDescription)
        }
        Task { @MainActor in
            if case .blockedByPolicy = result { self.sawPolicyDenial = true }
            self.finish(result)
        }
    }

    nonisolated private static func codeName(_ ns: NSError) -> String {
        guard ns.domain == OSSystemExtensionErrorDomain,
              let code = OSSystemExtensionError.Code(rawValue: ns.code) else {
            return ns.localizedDescription
        }
        switch code {
        case .unknown:                          return "unknown failure"
        case .missingEntitlement:               return "missing entitlement"
        case .unsupportedParentBundleLocation:  return "app is in an unsupported location"
        case .extensionNotFound:                return "extension not found in the app bundle"
        case .extensionMissingIdentifier:       return "extension is missing its identifier"
        case .duplicateExtensionIdentifer:      return "duplicate extension identifier"
        case .unknownExtensionCategory:         return "unknown extension category"
        case .codeSignatureInvalid:             return "invalid code signature"
        case .validationFailed:                 return "validation failed"
        case .forbiddenBySystemPolicy:          return "forbidden by system policy"
        case .requestCanceled:                  return "request canceled"
        case .requestSuperseded:                return "request superseded"
        case .authorizationRequired:            return "administrator authorization required"
        @unknown default:                       return "unrecognized error \(ns.code)"
        }
    }
}
