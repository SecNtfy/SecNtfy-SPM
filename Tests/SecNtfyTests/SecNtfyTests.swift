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
