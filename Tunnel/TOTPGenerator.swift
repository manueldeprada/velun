import Foundation
import CryptoKit

enum TOTPGenerator {
    static func generate(secret: String,
                         time: UInt64? = nil,
                         digits: Int = 6,
                         period: TimeInterval = 30) -> String {
        let raw = secret.hasPrefix("base32:") ? String(secret.dropFirst(7)) : secret
        let keyBytes = base32Decode(raw)
        guard !keyBytes.isEmpty else { return "000000" }

        let now: TimeInterval = time.map { TimeInterval($0) } ?? Date().timeIntervalSince1970
        let counter = UInt64(now / period)
        var bigEndian = counter.bigEndian
        let counterData = Data(bytes: &bigEndian, count: 8)

        let key  = SymmetricKey(data: keyBytes)
        let hmac = HMAC<Insecure.SHA1>.authenticationCode(for: counterData, using: key)
        let bytes = Array(hmac)

        let offset = Int(bytes[bytes.count - 1] & 0x0f)
        let code   = (Int(bytes[offset]     & 0x7f) << 24)
                   | (Int(bytes[offset + 1])         << 16)
                   | (Int(bytes[offset + 2])         <<  8)
                   |  Int(bytes[offset + 3])

        let divisor = Int(pow(10.0, Double(digits)))
        return String(format: "%0\(digits)d", code % divisor)
    }

    private static func base32Decode(_ input: String) -> Data {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        var result   = Data()
        var buffer: UInt64 = 0
        var bitsLeft = 0
        for ch in input.uppercased() {
            guard let idx = alphabet.firstIndex(of: ch) else { continue }
            let val = alphabet.distance(from: alphabet.startIndex, to: idx)
            buffer   = (buffer << 5) | UInt64(val)
            bitsLeft += 5
            if bitsLeft >= 8 {
                bitsLeft -= 8
                result.append(UInt8((buffer >> bitsLeft) & 0xff))
            }
        }
        return result
    }
}
