import Foundation

enum TunnelExport {
    enum ImportError: LocalizedError {
        case notVelunURL
        case missingData
        case badBase64
        case decompressionFailed
        case notJSON
        case noURLs

        var errorDescription: String? {
            switch self {
            case .notVelunURL:         return "Not a velun://import URL."
            case .missingData:         return "URL is missing the data= payload."
            case .badBase64:           return "data= is not valid base64."
            case .decompressionFailed: return "Could not decompress the payload."
            case .notJSON:             return "Payload is not valid JSON."
            case .noURLs:              return "No velun://import URLs found in the input."
            }
        }
    }

    // MARK: – Export

    static func encodeURL(_ profile: VPNProfile, includeCredentials: Bool = false) -> URL {
        var d: [String: Any] = ["provider": profile.provider.rawValue]
        var hostQuery: String? = nil

        switch profile.config {
        case .sslVPN(let oc):
            hostQuery = oc.host
            if oc.port != 443           { d["port"]           = oc.port }
            if !oc.group.isEmpty        { d["group"]          = oc.group }
            if !oc.splitRoutes.isEmpty  { d["splitRoutes"]    = oc.splitRoutes }
            if oc.partialEnabled        { d["partialEnabled"] = true }
            if !oc.tunnelDomains.isEmpty { d["tunnelDomains"] = oc.tunnelDomains }
            if includeCredentials {
                let pw   = KeychainHelper.loadPassword(for: profile.id) ?? ""
                let totp = KeychainHelper.loadTOTP(for: profile.id)    ?? ""
                if !pw.isEmpty   { d["password"]   = pw }
                if !totp.isEmpty { d["totpSecret"] = totp }
            }
        case .wireguard(let wg):
            if !wg.splitRoutes.isEmpty  { d["splitRoutes"]    = wg.splitRoutes }
            if wg.partialEnabled        { d["partialEnabled"] = true }
            let confSource = wg.confText.isEmpty
                ? (KeychainHelper.loadWireGuardConf(for: profile.id) ?? "")
                : wg.confText
            let conf = includeCredentials ? confSource : strippedWireGuardConf(confSource)
            if !conf.isEmpty { d["wgConf"] = conf }
        }

        let json = (try? JSONSerialization.data(withJSONObject: d, options: [.sortedKeys])) ?? Data("{}".utf8)
        let payload = (try? (json as NSData).compressed(using: .zlib) as Data) ?? json
        let b64 = payload.base64EncodedString()

        var comps = URLComponents()
        comps.scheme = "velun"
        comps.host   = "import"
        var items: [URLQueryItem] = []
        if !profile.name.isEmpty { items.append(URLQueryItem(name: "name", value: profile.name)) }
        if let h = hostQuery, !h.isEmpty {
            items.append(URLQueryItem(name: "host", value: h))
        }
        items.append(URLQueryItem(name: "data", value: b64))
        comps.queryItems = items
        return comps.url!
    }

    static func encodeBlob(_ profiles: [VPNProfile], includeCredentials: Bool = false) -> String {
        profiles.map { encodeURL($0, includeCredentials: includeCredentials).absoluteString }
                .joined(separator: "\n")
    }

    private static func strippedWireGuardConf(_ conf: String) -> String {
        conf.components(separatedBy: .newlines)
            .filter { !$0.lowercased().trimmingCharacters(in: .whitespaces).hasPrefix("privatekey") }
            .joined(separator: "\n")
    }

    // MARK: – Import

    static func decodeURL(_ url: URL) throws -> VPNProfile {
        guard url.scheme == "velun", url.host?.lowercased() == "import" else {
            throw ImportError.notVelunURL
        }
        let comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
        let q = Dictionary(uniqueKeysWithValues:
            (comps?.queryItems ?? []).map { ($0.name.lowercased(), $0.value ?? "") })

        guard let b64 = q["data"], !b64.isEmpty else { throw ImportError.missingData }
        guard let raw = Data(base64Encoded: b64) else { throw ImportError.badBase64 }

        let json: Data
        if let d = try? (raw as NSData).decompressed(using: .zlib) as Data {
            json = d
        } else if (try? JSONSerialization.jsonObject(with: raw)) != nil {
            json = raw
        } else {
            throw ImportError.decompressionFailed
        }
        guard let dict = (try? JSONSerialization.jsonObject(with: json)) as? [String: Any] else {
            throw ImportError.notJSON
        }

        let nameQuery = q["name"] ?? ""
        let hostQuery = q["host"] ?? ""

        var p = VPNProfile()
        let providerRaw = (dict["provider"] as? String) ?? "anyconnect"
        p.provider = ProviderType(rawValue: providerRaw) ?? .anyConnect

        switch p.provider {
        case .wireguard:
            var wg = WireGuardConfig()
            wg.confText      = dict["wgConf"]      as? String ?? ""
            wg.splitRoutes   = dict["splitRoutes"] as? String ?? ""
            wg.partialEnabled = (dict["partialEnabled"] as? Bool) ?? !wg.splitRoutes.isEmpty
            p.config = .wireguard(wg)
            if !nameQuery.isEmpty {
                p.name = nameQuery
            } else if p.name == "New Connection" {
                p.name = "WireGuard tunnel"
            }
        default:
            var oc = SSLVPNFamilyConfig()
            oc.host         = hostQuery
            oc.port         = dict["port"]        as? Int    ?? 443
            oc.group        = dict["group"]       as? String ?? ""
            oc.splitRoutes  = dict["splitRoutes"] as? String ?? ""
            oc.partialEnabled = (dict["partialEnabled"] as? Bool) ?? !oc.splitRoutes.isEmpty
            oc.tunnelDomains = dict["tunnelDomains"] as? String ?? ""
            oc.password     = dict["password"]    as? String ?? ""
            oc.totpSecret   = dict["totpSecret"]  as? String ?? ""
            p.config = .sslVPN(oc)
            if !nameQuery.isEmpty {
                p.name = nameQuery
            } else if !oc.host.isEmpty {
                p.name = oc.host
            }
        }
        return p
    }

    static func decodeBlob(_ text: String) throws -> [VPNProfile] {
        var out: [VPNProfile] = []
        for line in text.components(separatedBy: .newlines) {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.isEmpty { continue }
            guard let url = URL(string: t), url.scheme == "velun" else { continue }
            out.append(try decodeURL(url))
        }
        if out.isEmpty { throw ImportError.noURLs }
        return out
    }
}
