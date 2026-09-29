import Foundation
import XCTest
@testable import SecNtfy

final class SecNtfyTests: XCTestCase {
    func testEndpointURLPreservesBasePathAndNormalizesSlash() throws {
        let url = try SecNtfySwifty.endpointURL(
            apiURL: "https://example.com/api/",
            pathComponents: ["Message", "Receive", "42"]
        )

        XCTAssertEqual(url.absoluteString, "https://example.com/api/Message/Receive/42")
    }

    func testEndpointURLRejectsUnsupportedURLs() {
        XCTAssertThrowsError(
            try SecNtfySwifty.endpointURL(
                apiURL: "file:///tmp/secntfy",
                pathComponents: ["App", "RegisterDevice"]
            )
        )
        XCTAssertThrowsError(
            try SecNtfySwifty.endpointURL(
                apiURL: "not a URL",
                pathComponents: ["App", "RegisterDevice"]
            )
        )
    }

    func testInvalidCiphertextReturnsNil() {
        XCTAssertNil(SecNtfySwifty.decrypt("not-base64", privateKey: "not-base64"))
        XCTAssertNil(SecNtfySwifty.decrypt("", privateKey: ""))
    }

    func testResultHandlerRoundTripKeepsPublicPayload() throws {
        let original = ResultHandler(
            token: "NTFY-DEVICE-123",
            bundleGroup: "group.example.test",
            error: NtfyError.invalidResponse
        )

        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(ResultHandler.self, from: data)

        XCTAssertEqual(decoded.token, original.token)
        XCTAssertEqual(decoded.bundleGroup, original.bundleGroup)
        XCTAssertNil(decoded.error)
    }

    func testDeviceRegistrationMetadataUsesBackendFieldNames() throws {
        let device = NTFY_Devices(
            D_ID: 0,
            D_APP_ID: 0,
            D_OS: 1,
            D_OS_Version: "27.0",
            D_Model: "iPhone Duo",
            D_IsSimulator: false,
            D_IsDebug: true,
            D_AppVersion: "1.2.0",
            D_APN_ID: "apns-token",
            D_Android_ID: "",
            D_PublicKey: "public-key",
            D_NTFY_Token: ""
        )

        let data = try JSONEncoder().encode(device)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])

        XCTAssertEqual(json["D_IsSimulator"] as? Bool, false)
        XCTAssertEqual(json["D_IsDebug"] as? Bool, true)
        XCTAssertEqual(json["D_AppVersion"] as? String, "1.2.0")
    }

    func testDeviceMetadataRemainsOptionalForLegacyPayloads() throws {
        let device = try JSONDecoder().decode(
            NTFY_Devices.self,
            from: Data(#"{"D_Model":"iPhone"}"#.utf8)
        )

        XCTAssertNil(device.D_IsSimulator)
        XCTAssertNil(device.D_IsDebug)
        XCTAssertNil(device.D_AppVersion)

        let encoded = try JSONEncoder().encode(device)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        XCTAssertNil(json["D_IsSimulator"])
        XCTAssertNil(json["D_IsDebug"])
        XCTAssertNil(json["D_AppVersion"])
    }

    func testAppVersionNormalizationMatchesBackendLimit() {
        XCTAssertEqual(SecNtfySwifty.normalizedAppVersion(" 1.2.0 "), "1.2.0")
        XCTAssertNil(SecNtfySwifty.normalizedAppVersion("  "))
        XCTAssertEqual(
            SecNtfySwifty.normalizedAppVersion(String(repeating: "a", count: 64)),
            String(repeating: "a", count: 64)
        )
        XCTAssertNil(SecNtfySwifty.normalizedAppVersion(String(repeating: "a", count: 65)))
        XCTAssertNil(SecNtfySwifty.normalizedAppVersion(String(repeating: "🙂", count: 33)))
    }

    @MainActor
    func testInitializePersistsAndUpdatesExplicitAPIURL() {
        let suiteName = "SecNtfyTests.\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: suiteName) else {
            XCTFail("Could not create isolated UserDefaults suite")
            return
        }
        defer { defaults.removePersistentDomain(forName: suiteName) }
        defaults.set("existing-public-key", forKey: "NTFY_PUB_KEY")
        defaults.set("existing-private-key", forKey: "NTFY_PRIV_KEY")

        let client = SecNtfySwifty()
        client.initialize(apiUrl: "https://first.example/api", bundleGroup: suiteName)

        XCTAssertFalse(defaults.string(forKey: "NTFY_PUB_KEY", default: "").isEmpty)
        XCTAssertFalse(defaults.string(forKey: "NTFY_PRIV_KEY", default: "").isEmpty)
        XCTAssertEqual(defaults.string(forKey: "NTFY_API_URL"), "https://first.example/api")

        client.initialize(apiUrl: "https://second.example/api", bundleGroup: suiteName)
        XCTAssertEqual(defaults.string(forKey: "NTFY_API_URL"), "https://second.example/api")
    }

    func testLockedBoxSupportsNilAndValue() {
        let box = LockedBox<String>()
        XCTAssertNil(box.get())
        box.set("value")
        XCTAssertEqual(box.get(), "value")
        box.set(nil)
        XCTAssertNil(box.get())
    }
}

private extension UserDefaults {
    func string(forKey key: String, default fallback: String) -> String {
        string(forKey: key) ?? fallback
    }
}
