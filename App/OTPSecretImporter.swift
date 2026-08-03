import Foundation

struct OTPAccount: Equatable {
    var name: String          // human-readable account, e.g. "alice@example.com"
    var issuer: String        // service name, e.g. "ACME"
    var secretBase32: String  // RFC 4648 base32, uppercase, no padding
    var algorithm: Algorithm = .sha1
    var digits: Int = 6
    var type: OTPType = .totp

    enum Algorithm: String { case sha1, sha256, sha512, md5 }
    enum OTPType:   String { case totp, hotp }

    /// "Issuer — name", or whichever side is non-empty.
    var displayLabel: String {
        if !issuer.isEmpty && !name.isEmpty { return "\(issuer): \(name)" }
        if !issuer.isEmpty                  { return issuer }
        if !name.isEmpty                    { return name }
        return "Account"
    }

    var isStandardTOTP: Bool {
        type == .totp && algorithm == .sha1 && digits == 6
    }
}

/// One-shot decoder for OTP-bearing QR-code strings.
enum OTPSecretImporter {
    enum ImportError: LocalizedError {
        case unsupportedScheme(String)
        case missingSecret
        case malformedURL
        case malformedMigrationData
        case noAccounts

        var errorDescription: String? {
            switch self {
            case .unsupportedScheme(let s):
                return "Not an OTP QR code (got scheme \"\(s)\"). Expected otpauth:// or otpauth-migration://."
            case .missingSecret:
                return "QR code has no `secret` parameter."
            case .malformedURL:
                return "Could not parse OTP URL."
            case .malformedMigrationData:
                return "Could not decode otpauth-migration data."
            case .noAccounts:
                return "QR code did not contain any accounts."
            }
        }
    }

    static func parse(_ raw: String) throws -> [OTPAccount] {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed) else { throw ImportError.malformedURL }
        switch url.scheme?.lowercased() {
        case "otpauth":           return [try parseOTPAuth(url)]
        case "otpauth-migration": return try parseMigration(url)
        case let other?:          throw ImportError.unsupportedScheme(other)
        case nil:                 throw ImportError.malformedURL
        }
    }

    // MARK: – otpauth://totp/Issuer:label?secret=BASE32&issuer=Issuer&...

    private static func parseOTPAuth(_ url: URL) throws -> OTPAccount {
        let comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
        let q = Dictionary(
            (comps?.queryItems ?? []).map { ($0.name.lowercased(), $0.value ?? "") },
            uniquingKeysWith: { a, _ in a }
        )
        guard let secret = q["secret"], !secret.isEmpty else { throw ImportError.missingSecret }

        // Path is "/[Issuer:]label". Strip leading slash, split on the first colon.
        let pathRaw = (comps?.path ?? "")
        let trimmedPath = pathRaw.hasPrefix("/") ? String(pathRaw.dropFirst()) : pathRaw
        let label = trimmedPath.removingPercentEncoding ?? trimmedPath
        var issuer = q["issuer"] ?? ""
        var name   = label
        if let colon = label.firstIndex(of: ":") {
            let pathIssuer = String(label[..<colon]).trimmingCharacters(in: .whitespaces)
            name = String(label[label.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            if issuer.isEmpty { issuer = pathIssuer }
        }

        let host = url.host?.lowercased() ?? ""        // "totp" or "hotp"
        let type: OTPAccount.OTPType = (host == "hotp") ? .hotp : .totp
        let alg: OTPAccount.Algorithm = {
            switch (q["algorithm"] ?? "sha1").lowercased() {
            case "sha256": return .sha256
            case "sha512": return .sha512
            case "md5":    return .md5
            default:       return .sha1
            }
        }()
        let digits = Int(q["digits"] ?? "") ?? 6
        let normalised = secret
            .components(separatedBy: .whitespacesAndNewlines).joined()
            .uppercased()
        return OTPAccount(name: name, issuer: issuer,
                          secretBase32: normalised,
                          algorithm: alg, digits: digits, type: type)
    }

    // MARK: – otpauth-migration://offline?data=<base64-protobuf>

    private static func parseMigration(_ url: URL) throws -> [OTPAccount] {
        guard
            let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
            let dataItem = comps.queryItems?.first(where: { $0.name == "data" }),
            let raw = dataItem.value, !raw.isEmpty
        else { throw ImportError.malformedURL }

        var b64 = raw
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let pad = b64.count % 4
        if pad != 0 { b64 += String(repeating: "=", count: 4 - pad) }

        guard let payload = Data(base64Encoded: b64) else {
            throw ImportError.malformedMigrationData
        }
        let accounts = try MigrationProtobuf.parse(payload)
        guard !accounts.isEmpty else { throw ImportError.noAccounts }
        return accounts
    }
}

private enum MigrationProtobuf {
    static func parse(_ data: Data) throws -> [OTPAccount] {
        var reader = ProtoReader(data: data)
        var accounts: [OTPAccount] = []
        while reader.hasMore {
            let (field, wire) = try reader.readTag()
            if field == 1, wire == .lengthDelimited {
                let sub = try reader.readBytes()
                if let acc = try parseAccount(sub) { accounts.append(acc) }
            } else {
                try reader.skip(wire: wire)
            }
        }
        return accounts
    }

    private static func parseAccount(_ data: Data) throws -> OTPAccount? {
        var reader = ProtoReader(data: data)
        var secret = Data()
        var name   = ""
        var issuer = ""
        var alg: OTPAccount.Algorithm = .sha1
        var digits = 6
        var type: OTPAccount.OTPType = .totp

        while reader.hasMore {
            let (field, wire) = try reader.readTag()
            switch (field, wire) {
            case (1, .lengthDelimited):
                secret = try reader.readBytes()
            case (2, .lengthDelimited):
                name = String(data: try reader.readBytes(), encoding: .utf8) ?? ""
            case (3, .lengthDelimited):
                issuer = String(data: try reader.readBytes(), encoding: .utf8) ?? ""
            case (4, .varint):
                let v = try reader.readVarint()
                switch v {
                case 2: alg = .sha256
                case 3: alg = .sha512
                case 4: alg = .md5
                default: alg = .sha1            // 0 (UNSPECIFIED) → default SHA1
                }
            case (5, .varint):
                let v = try reader.readVarint()
                digits = (v == 2) ? 8 : 6        // 0 (UNSPECIFIED) → default 6
            case (6, .varint):
                let v = try reader.readVarint()
                type = (v == 1) ? .hotp : .totp  // 0 (UNSPECIFIED) → default TOTP
            default:
                try reader.skip(wire: wire)
            }
        }

        if secret.isEmpty { return nil }
        return OTPAccount(name: name, issuer: issuer,
                          secretBase32: Base32.encode(secret),
                          algorithm: alg, digits: digits, type: type)
    }
}

private enum WireType: UInt64 {
    case varint           = 0
    case fixed64          = 1
    case lengthDelimited  = 2
    case startGroup       = 3
    case endGroup         = 4
    case fixed32          = 5
}

private struct ProtoReader {
    let data: Data
    var idx: Int = 0
    var hasMore: Bool { idx < data.count }

    mutating func readTag() throws -> (field: Int, wire: WireType) {
        let tag = try readVarint()
        guard let wire = WireType(rawValue: tag & 0x07) else {
            throw OTPSecretImporter.ImportError.malformedMigrationData
        }
        return (Int(tag >> 3), wire)
    }

    mutating func readVarint() throws -> UInt64 {
        var result: UInt64 = 0
        var shift: UInt64 = 0
        while idx < data.count {
            let b = data[data.startIndex + idx]
            idx += 1
            result |= UInt64(b & 0x7f) << shift
            if (b & 0x80) == 0 { return result }
            shift += 7
            if shift >= 64 { break }
        }
        throw OTPSecretImporter.ImportError.malformedMigrationData
    }

    mutating func readBytes() throws -> Data {
        let len = Int(try readVarint())
        guard len >= 0, idx &+ len <= data.count else {
            throw OTPSecretImporter.ImportError.malformedMigrationData
        }
        let start = data.startIndex + idx
        let slice = data[start..<(start + len)]
        idx += len
        return Data(slice)
    }

    mutating func skip(wire: WireType) throws {
        switch wire {
        case .varint:          _ = try readVarint()
        case .lengthDelimited: _ = try readBytes()
        case .fixed32:
            guard idx + 4 <= data.count else { throw OTPSecretImporter.ImportError.malformedMigrationData }
            idx += 4
        case .fixed64:
            guard idx + 8 <= data.count else { throw OTPSecretImporter.ImportError.malformedMigrationData }
            idx += 8
        case .startGroup, .endGroup:
            // proto3 has no groups; a real export will never include them.
            throw OTPSecretImporter.ImportError.malformedMigrationData
        }
    }
}

enum Base32 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    static func encode(_ data: Data) -> String {
        if data.isEmpty { return "" }
        var output = ""
        output.reserveCapacity((data.count * 8 + 4) / 5)
        var buffer: UInt64 = 0
        var bitsLeft = 0
        for b in data {
            buffer = (buffer << 8) | UInt64(b)
            bitsLeft += 8
            while bitsLeft >= 5 {
                bitsLeft -= 5
                let i = Int((buffer >> UInt64(bitsLeft)) & 0x1f)
                output.append(alphabet[i])
            }
        }
        if bitsLeft > 0 {
            let i = Int((buffer << UInt64(5 - bitsLeft)) & 0x1f)
            output.append(alphabet[i])
        }
        return output
    }
}
