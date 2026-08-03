import SwiftUI
import AVFoundation
import Vision
import AppKit

final class QRScannerCoordinator: NSObject, ObservableObject {

    enum AuthState { case checking, authorized, denied, noCamera }

    @Published var authState: AuthState = .checking
    @Published var lastScanned: String?
    @Published var failureMessage: String?

    let session = AVCaptureSession()
    private let videoOut = AVCaptureVideoDataOutput()
    private let videoQueue = DispatchQueue(label: "velun.qr.video", qos: .userInitiated)
    private var configured = false
    private var lastVisionRun: TimeInterval = 0   // accessed only on videoQueue

    private lazy var barcodeRequest: VNDetectBarcodesRequest = {
        let r = VNDetectBarcodesRequest()
        r.symbologies = [.qr]
        return r
    }()

    func requestPermissionAndStart() {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            authState = .authorized
            startSession()
        case .notDetermined:
            authState = .checking
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                DispatchQueue.main.async {
                    guard let self else { return }
                    if granted {
                        self.authState = .authorized
                        self.startSession()
                    } else {
                        self.authState = .denied
                    }
                }
            }
        case .denied, .restricted:
            authState = .denied
        @unknown default:
            authState = .denied
        }
    }

    func stop() {
        guard session.isRunning else { return }
        DispatchQueue.global(qos: .userInitiated).async { [session] in
            session.stopRunning()
        }
    }

    func resetLastScan() { lastScanned = nil }

    private func configureSessionIfNeeded() {
        guard !configured else { return }
        configured = true

        session.beginConfiguration()

        let discovery = AVCaptureDevice.DiscoverySession(
            deviceTypes: [.builtInWideAngleCamera],
            mediaType: .video,
            position: .unspecified
        )
        guard let device = discovery.devices.first ?? AVCaptureDevice.default(for: .video) else {
            session.commitConfiguration()
            authState = .noCamera
            return
        }

        do {
            let input = try AVCaptureDeviceInput(device: device)
            guard session.canAddInput(input) else {
                session.commitConfiguration()
                failureMessage = "Camera input could not be added to the capture session."
                return
            }
            session.addInput(input)
        } catch {
            session.commitConfiguration()
            failureMessage = "Failed to open camera: \(error.localizedDescription)"
            return
        }

        guard session.canAddOutput(videoOut) else {
            session.commitConfiguration()
            failureMessage = "Capture session does not accept the video data output."
            return
        }
        videoOut.videoSettings = [
            kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA
        ]
        videoOut.alwaysDiscardsLateVideoFrames = true
        videoOut.setSampleBufferDelegate(self, queue: videoQueue)
        session.addOutput(videoOut)

        session.commitConfiguration()
    }

    private func startSession() {
        configureSessionIfNeeded()
        guard failureMessage == nil, !session.isRunning else { return }
        DispatchQueue.global(qos: .userInitiated).async { [session] in
            session.startRunning()
        }
    }
}

extension QRScannerCoordinator: AVCaptureVideoDataOutputSampleBufferDelegate {
    func captureOutput(_ output: AVCaptureOutput,
                       didOutput sampleBuffer: CMSampleBuffer,
                       from connection: AVCaptureConnection) {
        let now = CACurrentMediaTime()
        if now - lastVisionRun < 0.20 { return }
        lastVisionRun = now

        guard let pixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
        let handler = VNImageRequestHandler(cvPixelBuffer: pixelBuffer, options: [:])
        do {
            try handler.perform([barcodeRequest])
        } catch {
            return
        }
        guard let results = barcodeRequest.results else { return }
        for r in results {
            if r.symbology == .qr, let payload = r.payloadStringValue {
                DispatchQueue.main.async { [weak self] in
                    guard let self, self.lastScanned == nil else { return }
                    self.lastScanned = payload
                }
                return
            }
        }
    }
}

// MARK: – AVCaptureVideoPreviewLayer-backed NSView wrapper.

private final class PreviewNSView: NSView {
    override func makeBackingLayer() -> CALayer {
        let layer = AVCaptureVideoPreviewLayer()
        layer.videoGravity = .resizeAspectFill
        return layer
    }
    var previewLayer: AVCaptureVideoPreviewLayer? {
        layer as? AVCaptureVideoPreviewLayer
    }
}

private struct CameraPreview: NSViewRepresentable {
    let session: AVCaptureSession

    func makeNSView(context: Context) -> PreviewNSView {
        let v = PreviewNSView()
        v.wantsLayer = true
        v.previewLayer?.session = session
        return v
    }
    func updateNSView(_ nsView: PreviewNSView, context: Context) {
        if nsView.previewLayer?.session !== session {
            nsView.previewLayer?.session = session
        }
    }
}

// MARK: – Sheet entry point.

struct QRScannerSheet: View {
    @Environment(\.dismiss) private var dismiss
    @StateObject private var coord = QRScannerCoordinator()
    @State private var pickerAccounts: [OTPAccount] = []
    @State private var importMessage: String?
    let onPicked: (OTPAccount) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "qrcode.viewfinder").font(.title2)
                Text("Scan TOTP QR code").font(.headline)
                Spacer()
            }

            Group {
                switch coord.authState {
                case .checking:    waitingForPermission
                case .denied:      deniedView
                case .noCamera:    noCameraView
                case .authorized:  scannerView
                }
            }

            if let msg = importMessage {
                Label(msg, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            } else if let msg = coord.failureMessage {
                Label(msg, systemImage: "video.slash.fill")
                    .font(.caption).foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            } else if pickerAccounts.isEmpty && coord.authState == .authorized {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Point the camera at the TOTP QR code from your authenticator app or your VPN provider.")
                        .font(.caption2).foregroundStyle(.secondary)
                    Text("Google Authenticator: tap **Transfer accounts** → **Export accounts** → select **ONLY** the VPN 2FA account → **Next** to display the QR.")
                        .font(.caption2).foregroundStyle(.tertiary)
                }
                .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(16)
        .frame(width: 480)
        .onAppear { coord.requestPermissionAndStart() }
        .onDisappear { coord.stop() }
        .onReceive(coord.$lastScanned.compactMap { $0 }) { handleScan($0) }
        .sheet(isPresented: pickerSheetBinding) {
            AccountPickerSheet(accounts: pickerAccounts) { picked in
                pickerAccounts = []
                onPicked(picked)
                dismiss()
            } onCancel: {
                pickerAccounts = []
                coord.resetLastScan()
            }
        }
    }

    private var pickerSheetBinding: Binding<Bool> {
        Binding(get: { !pickerAccounts.isEmpty },
                set: { if !$0 { pickerAccounts = [] } })
    }

    @ViewBuilder private var waitingForPermission: some View {
        VStack(spacing: 8) {
            ProgressView()
            Text("Waiting for camera permission…")
                .font(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, minHeight: 320)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color.black.opacity(0.05)))
    }

    @ViewBuilder private var deniedView: some View {
        VStack(spacing: 8) {
            Image(systemName: "video.slash").font(.largeTitle).foregroundStyle(.secondary)
            Text("Camera access denied").font(.headline)
            Text("Allow velun in System Settings → Privacy & Security → Camera, then reopen this sheet.")
                .font(.caption).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            Button("Open System Settings") {
                if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Camera") {
                    NSWorkspace.shared.open(url)
                }
            }
            .controlSize(.small)
        }
        .padding()
        .frame(maxWidth: .infinity, minHeight: 320)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color.black.opacity(0.05)))
    }

    @ViewBuilder private var noCameraView: some View {
        VStack(spacing: 8) {
            Image(systemName: "video.slash").font(.largeTitle).foregroundStyle(.secondary)
            Text("No camera found").font(.headline)
            Text("This Mac does not have a camera available to AVFoundation.")
                .font(.caption).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding()
        .frame(maxWidth: .infinity, minHeight: 320)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color.black.opacity(0.05)))
    }

    @ViewBuilder private var scannerView: some View {
        ZStack {
            CameraPreview(session: coord.session)
                .frame(height: 320)
                .clipShape(RoundedRectangle(cornerRadius: 8))
            // Subtle reticle to hint where the QR should be aimed.
            RoundedRectangle(cornerRadius: 12)
                .strokeBorder(Color.white.opacity(0.7), lineWidth: 2)
                .frame(width: 200, height: 200)
                .shadow(color: .black.opacity(0.4), radius: 4)
        }
    }

    private func handleScan(_ raw: String) {
        do {
            let accounts = try OTPSecretImporter.parse(raw)
            let usable = accounts.filter { $0.isStandardTOTP }
            let skipped = accounts.count - usable.count
            if usable.isEmpty {
                let suffix = (skipped > 0)
                    ? " (skipped \(skipped) non-SHA1/6-digit entries)"
                    : ""
                importMessage = "QR code contains no SHA1 / 6-digit TOTP accounts\(suffix)."
                coord.resetLastScan()
                return
            }
            coord.stop()
            importMessage = nil
            if usable.count == 1 {
                onPicked(usable[0])
                dismiss()
            } else {
                pickerAccounts = usable
            }
        } catch {
            importMessage = error.localizedDescription
            coord.resetLastScan()
        }
    }
}

// MARK: – Multi-account picker (for migration QRs with > 1 account).

private struct AccountPickerSheet: View {
    let accounts: [OTPAccount]
    let onPick: (OTPAccount) -> Void
    let onCancel: () -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Choose account to import").font(.headline)
            Text("\(accounts.count) accounts found in this QR code.")
                .font(.caption).foregroundStyle(.secondary)
            ScrollView {
                VStack(spacing: 4) {
                    ForEach(accounts.indices, id: \.self) { i in
                        Button {
                            onPick(accounts[i])
                            dismiss()
                        } label: {
                            HStack(spacing: 8) {
                                Image(systemName: "key.fill")
                                    .font(.caption).foregroundStyle(.secondary)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(accounts[i].displayLabel)
                                        .font(.subheadline).fontWeight(.medium)
                                    Text("\(accounts[i].digits)-digit \(accounts[i].algorithm.rawValue.uppercased()) TOTP")
                                        .font(.caption2).foregroundStyle(.secondary)
                                }
                                Spacer()
                                Image(systemName: "chevron.right")
                                    .font(.caption2).foregroundStyle(.tertiary)
                            }
                            .padding(.horizontal, 10).padding(.vertical, 8)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(RoundedRectangle(cornerRadius: 6)
                                .fill(Color.secondary.opacity(0.06)))
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            .frame(maxHeight: 280)
            HStack {
                Spacer()
                Button("Cancel") {
                    onCancel()
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
            }
        }
        .padding(16)
        .frame(width: 380)
    }
}
