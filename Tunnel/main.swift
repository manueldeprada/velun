import Foundation
import NetworkExtension
import OSLog

private let stderrLog = Logger(subsystem: "com.manueldeprada.velun.PacketTunnel",
                               category: "stderr")

private func mirrorStderrToOSLog() {
    let pipe = Pipe()
    dup2(pipe.fileHandleForWriting.fileDescriptor, STDERR_FILENO)
    pipe.fileHandleForReading.readabilityHandler = { handle in
        let data = handle.availableData
        guard !data.isEmpty else { handle.readabilityHandler = nil; return }
        for line in String(decoding: data, as: UTF8.self).split(separator: "\n") {
            stderrLog.error("\(line, privacy: .public)")
        }
    }
}

mirrorStderrToOSLog()
autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
