import CryptoSwift
import Foundation
@preconcurrency import SwiftyBeaver

#if canImport(UIKit)
import UIKit
#endif

/// Client for registering an Apple device with SecNtfy and decrypting push payloads.
///
/// The public API remains source-compatible with SecNtfy 1.0.12. The instance is
/// safe to pass between isolation domains because all mutable state is protected by
/// `stateLock`; network operations only work with immutable snapshots of that state.
public final class SecNtfySwifty: @unchecked Sendable {
    private struct State: Sendable {
        var publicKey = ""
        var privateKey = ""
        var apiKey = ""
        var apnsToken = ""
        var apiURL = ""
        var bundleGroup = ""
        var deviceToken = ""
        var device = NTFY_Devices()
        var revision: UInt = 0
    }

    private struct Configuration: Sendable {
        let apiURL: String
        let apiKey: String
        let bundleGroup: String
        let deviceToken: String
        let device: NTFY_Devices
        let revision: UInt
    }

    private struct SynchronousResponse {
        let data: Data?
        let response: URLResponse?
        let error: Error?
    }

    private static let log = SwiftyBeaver.self
    private let stateLock = NSLock()
    private var state = State()

    @MainActor public static let shared = SecNtfySwifty()

    init() {}

    /// Loads persisted configuration and creates an RSA key pair when necessary.
    /// An explicitly supplied API URL always replaces the persisted URL.
    @MainActor
    public func initialize(apiUrl: String = "", bundleGroup: String = "de.sr.SecNtfy") {
        guard !bundleGroup.isEmpty,
              let userDefaults = UserDefaults(suiteName: bundleGroup) else {
            Self.log.error("SecNtfy initialization failed: App Group is unavailable")
            return
        }

        do {
            var publicKey = userDefaults.string(forKey: StorageKey.publicKey) ?? ""
            var privateKey = userDefaults.string(forKey: StorageKey.privateKey) ?? ""
            let persistedAPIURL = userDefaults.string(forKey: StorageKey.apiURL) ?? ""
            let resolvedAPIURL = apiUrl.isEmpty ? persistedAPIURL : apiUrl
            let deviceToken = userDefaults.string(forKey: StorageKey.deviceToken) ?? ""

            if publicKey.isEmpty || privateKey.isEmpty {
                let keyPair = try RSA(keySize: 2048)
                privateKey = try keyPair.externalRepresentation().base64EncodedString()
                publicKey = try keyPair.publicKeyExternalRepresentation().base64EncodedString()
                userDefaults.set(publicKey, forKey: StorageKey.publicKey)
                userDefaults.set(privateKey, forKey: StorageKey.privateKey)
            }

            if !apiUrl.isEmpty {
                userDefaults.set(apiUrl, forKey: StorageKey.apiURL)
            }

            withState { state in
                state.publicKey = publicKey
                state.privateKey = privateKey
                state.apiURL = resolvedAPIURL
                state.bundleGroup = bundleGroup
                state.deviceToken = deviceToken
                state.device.D_PublicKey = publicKey
                state.device.D_NTFY_Token = deviceToken
                state.revision &+= 1
            }

            if resolvedAPIURL.isEmpty {
                Self.log.warning("SecNtfy initialized without an API URL")
            } else {
                Self.log.info("SecNtfy initialized for App Group \(bundleGroup)")
            }
        } catch {
            Self.log.error("SecNtfy key initialization failed: \(error.localizedDescription)")
        }
    }

    /// Creates a fresh key pair and publishes its public key to the registered device.
    /// Local keys are only replaced after the server accepted the update.
    public func UpdateKeys() async -> Bool {
        let configuration = configurationSnapshot()
        guard !configuration.bundleGroup.isEmpty,
              !configuration.deviceToken.isEmpty,
              !configuration.device.D_OS_Version.isNilOrEmpty else {
            Self.log.error("SecNtfy key update failed: device is not registered")
            return false
        }

        do {
            let keyPair = try RSA(keySize: 2048)
            let privateKey = try keyPair.externalRepresentation().base64EncodedString()
            let publicKey = try keyPair.publicKeyExternalRepresentation().base64EncodedString()
            var device = configuration.device
            device.D_PublicKey = publicKey
            device.D_NTFY_Token = configuration.deviceToken

            let result = await updateDevice(device, configuration: configuration)
            guard result.error == nil else {
                Self.log.error("SecNtfy key update failed: \(result.error?.localizedDescription ?? "unknown error")")
                return false
            }

            guard let userDefaults = UserDefaults(suiteName: configuration.bundleGroup) else {
                Self.log.error("SecNtfy key update failed: App Group is unavailable")
                return false
            }

            userDefaults.set(publicKey, forKey: StorageKey.publicKey)
            userDefaults.set(privateKey, forKey: StorageKey.privateKey)

            withState { state in
                guard state.revision == configuration.revision else { return }
                state.publicKey = publicKey
                state.privateKey = privateKey
                state.device = device
                state.revision &+= 1
            }
            return true
        } catch {
            Self.log.error("SecNtfy key generation failed: \(error.localizedDescription)")
            return false
        }
    }

    @MainActor
    public func configure(apiKey: String) {
        #if os(iOS) || os(tvOS)
        var model = UIDevice.current.type.rawValue
        if model == Model.unrecognized.rawValue {
            model = UIDevice.current.name
        }
        let osVersion = UIDevice.current.systemVersion
        #elseif os(watchOS)
        let model = "Apple Watch"
        let osVersion = ProcessInfo.processInfo.operatingSystemVersionString
        #else
        let model = ProcessInfo.processInfo.hostName
        let osVersion = ProcessInfo.processInfo.operatingSystemVersionString
        #endif

        #if targetEnvironment(simulator)
        let isSimulator = true
        #else
        let isSimulator = false
        #endif

        #if DEBUG
        let isDebug = true
        #else
        let isDebug = false
        #endif

        let appVersion = Self.normalizedAppVersion(
            Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
            build: Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String
        )

        withState { state in
            state.apiKey = apiKey
            state.device = NTFY_Devices(
                D_ID: 0,
                D_APP_ID: 0,
                D_OS: 1,
                D_OS_Version: osVersion,
                D_Model: model,
                D_IsSimulator: isSimulator,
                D_IsDebug: isDebug,
                D_AppVersion: appVersion,
                D_APN_ID: state.apnsToken,
                D_Android_ID: "",
                D_PublicKey: state.publicKey,
                D_NTFY_Token: state.deviceToken
            )
            state.revision &+= 1
        }
        Self.log.info("SecNtfy configured for \(model), \(osVersion)")
    }

    public func getNtfyToken() async -> ResultHandler {
        let configuration = configurationSnapshot()
        guard !configuration.apiURL.isEmpty else {
            return ResultHandler(bundleGroup: configuration.bundleGroup, error: NtfyError.missingAPIURL)
        }
        guard !configuration.apiKey.isEmpty else {
            return ResultHandler(bundleGroup: configuration.bundleGroup, error: NtfyError.missingAPIKey)
        }
        guard !configuration.device.D_OS_Version.isNilOrEmpty else {
            return ResultHandler(bundleGroup: configuration.bundleGroup, error: NtfyError.noDevice)
        }

        let result = await postDevice(configuration.device, configuration: configuration)
        guard let token = result.token, !token.isEmpty else { return result }

        guard currentRevision == configuration.revision else {
            return ResultHandler(
                bundleGroup: configuration.bundleGroup,
                error: NtfyError.configurationChanged
            )
        }
        guard let userDefaults = UserDefaults(suiteName: configuration.bundleGroup) else {
            return ResultHandler(
                bundleGroup: configuration.bundleGroup,
                error: NtfyError.appGroupUnavailable
            )
        }

        userDefaults.set(token, forKey: StorageKey.deviceToken)
        withState { state in
            state.deviceToken = token
            state.device.D_NTFY_Token = token
        }
        return ResultHandler(token: token, bundleGroup: configuration.bundleGroup)
    }

    @MainActor
    func setDeviceToken(token: String) {
        withState { state in
            state.deviceToken = token
            state.device.D_NTFY_Token = token
            state.revision &+= 1
        }
    }

    /// Stores the APNs token even when `configure(apiKey:)` has not run yet.
    public func setApnsToken(apnsToken: String) {
        guard !apnsToken.isEmpty else { return }
        withState { state in
            state.apnsToken = apnsToken
            state.device.D_APN_ID = apnsToken
            state.revision &+= 1
        }
    }

    public func DecryptMessage(msg: String) -> String? {
        let privateKey = withState { $0.privateKey }
        guard let decrypted = Self.decrypt(msg, privateKey: privateKey) else {
            Self.log.error("SecNtfy message decryption failed")
            return nil
        }
        return decrypted
    }

    public func MessageReceived(msgId: String) async -> Bool {
        let configuration = configurationSnapshot()
        guard !configuration.deviceToken.isEmpty else {
            Self.log.error("SecNtfy receipt failed: device token is empty")
            return false
        }
        guard !msgId.isEmpty else {
            Self.log.error("SecNtfy receipt failed: message ID is empty")
            return false
        }

        do {
            let url = try Self.endpointURL(
                apiURL: configuration.apiURL,
                pathComponents: ["Message", "Receive", msgId]
            )
            var request = Self.request(url: url)
            request.setValue(configuration.deviceToken, forHTTPHeaderField: "X-NTFYME-DEVICE-KEY")
            let data = try await Self.responseData(for: request)
            let response = try JSONDecoder().decode(Response.self, from: data)
            return response.Status == 201
        } catch {
            Self.log.error("SecNtfy receipt failed: \(error.localizedDescription)")
            return false
        }
    }

    /// Synchronous compatibility API for notification-service implementations that
    /// cannot adopt async/await yet. New code should perform this request asynchronously.
    public static func OfflineMessageReceived(
        _ msgId: String,
        _ bundleGroup: String = "de.sr.SecNtfy"
    ) -> Bool {
        guard !msgId.isEmpty,
              let userDefaults = UserDefaults(suiteName: bundleGroup),
              let apiURL = userDefaults.string(forKey: StorageKey.apiURL),
              let deviceToken = userDefaults.string(forKey: StorageKey.deviceToken),
              !apiURL.isEmpty,
              !deviceToken.isEmpty else {
            log.error("SecNtfy offline receipt configuration is missing")
            return false
        }

        do {
            let url = try endpointURL(
                apiURL: apiURL,
                pathComponents: ["Message", "Receive", msgId]
            )
            var request = request(url: url, timeout: 5)
            request.setValue(deviceToken, forHTTPHeaderField: "X-NTFYME-DEVICE-KEY")

            let semaphore = DispatchSemaphore(value: 0)
            let responseBox = LockedBox<SynchronousResponse>()
            let task = URLSession.shared.dataTask(with: request) { data, response, error in
                responseBox.set(SynchronousResponse(data: data, response: response, error: error))
                semaphore.signal()
            }
            task.resume()

            guard semaphore.wait(timeout: .now() + 5) == .success else {
                task.cancel()
                log.error("SecNtfy offline receipt timed out")
                return false
            }
            guard let result = responseBox.get() else {
                log.error("SecNtfy offline receipt returned no response")
                return false
            }
            if let error = result.error { throw error }
            guard let data = result.data, let response = result.response else {
                throw NtfyError.invalidResponse
            }

            let validatedData = try validate(data: data, response: response)
            let decoded = try JSONDecoder().decode(Response.self, from: validatedData)
            return decoded.Status == 201
        } catch {
            log.error("SecNtfy offline receipt failed: \(error.localizedDescription)")
            return false
        }
    }

    public static func OfflineDecryption(
        _ msg: String,
        _ bundleGroup: String = "de.sr.SecNtfy"
    ) -> String? {
        guard let userDefaults = UserDefaults(suiteName: bundleGroup),
              let privateKey = userDefaults.string(forKey: StorageKey.privateKey),
              let decrypted = decrypt(msg, privateKey: privateKey) else {
            log.error("SecNtfy offline decryption failed")
            return nil
        }
        return decrypted
    }

    private func postDevice(
        _ device: NTFY_Devices,
        configuration: Configuration
    ) async -> ResultHandler {
        do {
            let url = try Self.endpointURL(
                apiURL: configuration.apiURL,
                pathComponents: ["App", "RegisterDevice"]
            )
            var request = Self.request(url: url)
            request.setValue(configuration.apiKey, forHTTPHeaderField: "X-NTFYME-AccessKey")
            request.httpBody = try JSONEncoder().encode(device)

            let data = try await Self.responseData(for: request)
            let response = try JSONDecoder().decode(Response.self, from: data)
            guard let token = response.Token, !token.isEmpty else {
                return ResultHandler(
                    bundleGroup: configuration.bundleGroup,
                    error: NtfyError.apiError(status: response.Status, message: response.Message)
                )
            }
            return ResultHandler(token: token, bundleGroup: configuration.bundleGroup)
        } catch {
            Self.log.error("SecNtfy device registration failed: \(error.localizedDescription)")
            return ResultHandler(bundleGroup: configuration.bundleGroup, error: error)
        }
    }

    private func updateDevice(
        _ device: NTFY_Devices,
        configuration: Configuration
    ) async -> ResultHandler {
        do {
            let url = try Self.endpointURL(
                apiURL: configuration.apiURL,
                pathComponents: ["Device", "Update"]
            )
            var request = Self.request(url: url)
            request.setValue(configuration.deviceToken, forHTTPHeaderField: "X-NTFYME-DEVICE-KEY")
            request.httpBody = try JSONEncoder().encode(device)

            let data = try await Self.responseData(for: request)
            let response = try JSONDecoder().decode(NTFYResponse.self, from: data)
            guard (200...299).contains(response.Status) || response.Message == "Device wurde aktualisiert!" else {
                return ResultHandler(
                    bundleGroup: configuration.bundleGroup,
                    error: NtfyError.apiError(status: response.Status, message: response.Message)
                )
            }
            return ResultHandler(token: response.Message, bundleGroup: configuration.bundleGroup)
        } catch {
            return ResultHandler(bundleGroup: configuration.bundleGroup, error: error)
        }
    }

    private func configurationSnapshot() -> Configuration {
        withState { state in
            Configuration(
                apiURL: state.apiURL,
                apiKey: state.apiKey,
                bundleGroup: state.bundleGroup,
                deviceToken: state.deviceToken,
                device: state.device,
                revision: state.revision
            )
        }
    }

    private var currentRevision: UInt {
        withState { $0.revision }
    }

    @discardableResult
    private func withState<T>(_ body: (inout State) throws -> T) rethrows -> T {
        stateLock.lock()
        defer { stateLock.unlock() }
        return try body(&state)
    }

    static func endpointURL(apiURL: String, pathComponents: [String]) throws -> URL {
        guard var url = URL(string: apiURL),
              let scheme = url.scheme?.lowercased(),
              scheme == "https" || scheme == "http",
              url.host != nil else {
            throw NtfyError.unsupportedURL
        }
        for component in pathComponents {
            url.appendPathComponent(component)
        }
        return url
    }

    static func normalizedAppVersion(_ value: String?, build: String? = nil) -> String? {
        guard let version = value?.trimmingCharacters(in: .whitespacesAndNewlines),
              !version.isEmpty,
              version.utf16.count <= 64 else {
            return nil
        }

        guard let build = build?.trimmingCharacters(in: .whitespacesAndNewlines),
              !build.isEmpty else {
            return version
        }

        let fullVersion = "\(version) (\(build))"
        return fullVersion.utf16.count <= 64 ? fullVersion : version
    }

    private static func request(url: URL, timeout: TimeInterval = 15) -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = timeout
        request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Accept")
        return request
    }

    private static func responseData(for request: URLRequest) async throws -> Data {
        let (data, response) = try await URLSession.shared.data(for: request)
        try Task.checkCancellation()
        return try validate(data: data, response: response)
    }

    private static func validate(data: Data, response: URLResponse) throws -> Data {
        guard let httpResponse = response as? HTTPURLResponse else {
            throw NtfyError.invalidResponse
        }
        guard (200...299).contains(httpResponse.statusCode) else {
            let message = (try? JSONDecoder().decode(Response.self, from: data).Message)
            throw NtfyError.httpStatus(httpResponse.statusCode, message: message)
        }
        return data
    }

    static func decrypt(_ message: String, privateKey: String) -> String? {
        guard !message.isEmpty,
              let privateKeyData = Data(base64Encoded: privateKey),
              let encodedMessage = Data(base64Encoded: message) else {
            return nil
        }

        do {
            let key = try RSA(rawRepresentation: privateKeyData)
            let clearData = try key.decrypt(Array(encodedMessage), variant: .pksc1v15)
            return String(data: Data(clearData), encoding: .utf8)
        } catch {
            return nil
        }
    }

}

private enum StorageKey {
    static let publicKey = "NTFY_PUB_KEY"
    static let privateKey = "NTFY_PRIV_KEY"
    static let apiURL = "NTFY_API_URL"
    static let deviceToken = "NTFY_DEVICE_TOKEN"
}

private extension Optional where Wrapped == String {
    var isNilOrEmpty: Bool { self?.isEmpty != false }
}

public final class LockedBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: T?

    public init() {}

    public func set(_ value: T?) {
        lock.lock()
        self.value = value
        lock.unlock()
    }

    public func get() -> T? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}
