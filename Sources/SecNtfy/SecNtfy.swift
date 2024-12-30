// The Swift Programming Language
// https://docs.swift.org/swift-book

import Foundation
import SwiftyBeaver
import CryptoSwift

#if canImport(UIKit)
import UIKit
import SwiftUI
#elseif canImport(AppKit)
import AppKit
#endif


extension SecNtfySwifty: @unchecked Sendable {}

public class SecNtfySwifty {
    
    private var _publicKey = ""
    private var _privateKey = ""
    private var _apiKey = ""
    private var _apnsToken = ""
    private var _apiUrl = ""
    private var _bundleGroup = ""
    private var _deviceToken: String = ""
    private var _apnsToken: String = ""
    private var ntfyDevice: NTFY_Devices = NTFY_Devices()
    private static let log = SwiftyBeaver.self
    public static let shared = SecNtfySwifty()
    
    init() {
        // add log destinations. at least one is needed!
        let console = ConsoleDestination()  // log to Xcode Console
        let file = FileDestination()  // log to default swiftybeaver.log file
        console.format = "$DHH:mm:ss$d $L $M"
        // add the destinations to SwiftyBeaver
        SecNtfySwifty.log.addDestination(console)
        SecNtfySwifty.log.addDestination(file)
        SecNtfySwifty.log.info("♻️ - Init SecNtfySwifty")
    }
    
    @MainActor
    public func initialize(apiUrl: String = "", bundleGroup: String = "de.sr.SecNtfy") async {
        _bundleGroup = bundleGroup
        let userDefaults = UserDefaults(suiteName: bundleGroup)!
        
        do {
            _publicKey = userDefaults.string(forKey: "NTFY_PUB_KEY") ?? ""
            _privateKey = userDefaults.string(forKey: "NTFY_PRIV_KEY") ?? ""
            _apiUrl = userDefaults.string(forKey: "NTFY_API_URL") ?? ""
            _deviceToken = userDefaults.string(forKey: "NTFY_DEVICE_TOKEN") ?? ""
            
            if (_apiKey.isEmpty && !apiUrl.isEmpty) {
                _apiUrl = apiUrl
                userDefaults.set(_apiUrl, forKey: "NTFY_API_URL")
            }
            
            if (_apiUrl.count == 0 || bundleGroup.count == 0) {
                SecNtfySwifty.log.error("🔥 - The API URL or Bundle Group is empty")
            }
            
            SecNtfySwifty.log.info("♻️ - API URL \(_apiUrl)")
            SecNtfySwifty.log.info("♻️ - Bundle Group \(bundleGroup)")
            
            if (_publicKey.isEmpty || _privateKey.isEmpty) {
                SecNtfySwifty.log.info("♻️ - Start generating RSA keys")
                let keyPair = try RSA(keySize: 2048)
                SecNtfySwifty.log.info("♻️ - RSA keys generated")
                _privateKey = try keyPair.externalRepresentation().base64EncodedString()
                SecNtfySwifty.log.info("♻️ - get private key")
                _publicKey = try keyPair.publicKeyExternalRepresentation().base64EncodedString()
                SecNtfySwifty.log.info("♻️ - get public key")
                
                userDefaults.set(_publicKey, forKey: "NTFY_PUB_KEY")
                userDefaults.set(_privateKey, forKey: "NTFY_PRIV_KEY")
                SecNtfySwifty.log.info("♻️ - saved keys")
            }
            
            SecNtfySwifty.log.info("PubKey: \(_publicKey)")
            SecNtfySwifty.log.info("PrivKey: \(anonymiesString(input: _privateKey))")
            
        } catch {
            SecNtfySwifty.log.error("🔥 - \(error.localizedDescription)")
        }
    }
    
    @MainActor
    public func UpdateKeys() async -> Bool {
        let userDefaults = UserDefaults(suiteName: _bundleGroup)!
        do {
            if (!_publicKey.isEmpty || !_privateKey.isEmpty) {
                let keyPair = try RSA(keySize: 2048)
                _privateKey = try keyPair.externalRepresentation().base64EncodedString()
                _publicKey = try keyPair.publicKeyExternalRepresentation().base64EncodedString()
                ntfyDevice.D_PublicKey = _publicKey
                let result = await UpdateDevice(dev: ntfyDevice)
                
                var isSuccess = false
                if (result.token != nil && result.token == "Device wurde aktualisiert!") {
                    isSuccess = true
                    userDefaults.set(_publicKey, forKey: "NTFY_PUB_KEY")
                    userDefaults.set(_privateKey, forKey: "NTFY_PRIV_KEY")
                }
                else {
                    SecNtfySwifty.log.error("🔥 - \(result.token ?? "token is nil in UpdateDevice")")
                }
                return isSuccess
            }
        }
        catch {
            SecNtfySwifty.log.error("🔥 - \(error.localizedDescription)")
        }
        return false
    }
    
    @MainActor public func configure(apiKey: String) {
        _apiKey = apiKey
        var model = ""
        var osVersion = ""
        
#if os(iOS) || os(tvOS)
        model = UIDevice().type.rawValue
        if (model.contains("?unrecognized?")) {
            model = UIDevice.current.name
        }
        osVersion = "\(UIDevice.current.systemVersion)"
#else
        model = "Macbook"
        osVersion = "macOS"
#endif
        ntfyDevice = NTFY_Devices(D_ID: 0, D_APP_ID: 0, D_OS: 1, D_OS_Version: osVersion, D_Model: model, D_APN_ID: _apnsToken, D_Android_ID: "", D_PublicKey: _publicKey, D_NTFY_Token: "")
        
        SecNtfySwifty.log.info("Model: \(model)")
        SecNtfySwifty.log.info("OS: \(osVersion)")
        
        SecNtfySwifty.log.info("PubKey: \(_publicKey)")
        SecNtfySwifty.log.info("PrivKey: \(anonymiesString(input: _privateKey))")
    }
    
    @MainActor public func getNtfyToken() async -> ResultHandler {
        if (ntfyDevice.D_OS_Version?.count == 0) {
            return ResultHandler(token: nil, error: NtfyError.noDevice)
        }
        
        let result = await PostDevice(dev: ntfyDevice, appKey: _apiKey)
        
        let userDefaults = UserDefaults(suiteName: _bundleGroup)!
        if (result.token == nil) {
            return ResultHandler(token: result.token, error: result.error)
        }
        
        //ntfyDevice.D_NTFY_Token = ntfyToken
        let _dt = userDefaults.string(forKey: "NTFY_DEVICE_TOKEN") ?? ""
        if (result.token != nil && (_dt.isEmpty || _dt != result.token)) {
            userDefaults.set(result.token, forKey: "NTFY_DEVICE_TOKEN")
            _deviceToken = result.token ?? ""
        }
        
        return ResultHandler(token: result.token)
    }
    
    @MainActor func setDeviceToken(token: String) {
        _deviceToken = token
    }
    
    public func setApnsToken(apnsToken: String) {
        if (ntfyDevice.D_OS_Version?.count == 0) {
            return
        }
        SecNtfySwifty.log.info("\(anonymiesString(input: apnsToken))")
        _apnsToken = apnsToken
    }
    
    @MainActor func PostDevice(dev: NTFY_Devices, appKey: String) async -> ResultHandler {
        let urlString = "\(_apiUrl)/App/RegisterDevice"
        let bundle = _bundleGroup
        let JsonEncoder = JSONEncoder()
        let JsonDecoder = JSONDecoder()
        
        guard let url = URL(string: urlString) else {
            return ResultHandler(token: nil, bundleGroup: bundle, error: NtfyError.unsuppotedURL)
        }
        
        //print(appKey)
        //print(dev)
        
        do {
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")  // the request is JSON
            request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Accept")        // the expected response is also JSON
            request.setValue("\(appKey)", forHTTPHeaderField: "X-NTFYME-AccessKey")        // the expected response is also JSON
            JsonEncoder.outputFormatting = .prettyPrinted
            
            let jsonData = try JsonEncoder.encode(dev)
            request.httpBody = jsonData
            
            let (data, _) = try await URLSession.shared.data(for: request)
            let result = try JsonDecoder.decode(Response.self, from: data)
            SecNtfySwifty.log.info("♻️ - \(result.Message ?? "") \(result.Token ?? "")")
            ntfyDevice.D_NTFY_Token = result.Token
            return ResultHandler(token: result.Token, bundleGroup: bundle)
        } catch let error {
            SecNtfySwifty.log.error("🔥 - Failed to PostDevice \(error.localizedDescription)")
            print("Failed to PostDevice", error)
            return ResultHandler(token: nil, bundleGroup: bundle, error: error)
        }
    }
    
    @MainActor func UpdateDevice(dev: NTFY_Devices) async -> ResultHandler {
        let urlString = "\(_apiUrl)/Device/Update"
        let bundle = _bundleGroup
        let JsonEncoder = JSONEncoder()
        let JsonDecoder = JSONDecoder()
        
        guard let url = URL(string: urlString) else {
            return ResultHandler(token: nil, bundleGroup: bundle, error: NtfyError.unsuppotedURL)
        }
        
        do {
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")  // the request is JSON
            request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Accept")        // the expected response is also JSON
            request.setValue("\(dev.D_NTFY_Token ?? "")", forHTTPHeaderField: "X-NTFYME-DEVICE-KEY")        // the expected response is also JSON
            JsonEncoder.outputFormatting = .prettyPrinted
            
            let jsonData = try JsonEncoder.encode(dev)
            request.httpBody = jsonData
            
            let (data, _) = try await URLSession.shared.data(for: request)
            
            let result = try JsonDecoder.decode(NTFYResponse.self, from: data)
            SecNtfySwifty.log.info("♻️ - \(result.Message ?? "") \(result.Token ?? "")")
            return ResultHandler(token: result.Message, bundleGroup: bundle)
        } catch let error {
            SecNtfySwifty.log.error("🔥 - Failed to UpdateDevice \(error.localizedDescription)")
            print("Failed to UpdateDevice", error)
            return ResultHandler(token: nil, bundleGroup: bundle, error: error)
        }
    }
    
    public func DecryptMessage(msg: String) -> String? {
        var decryptedMsg = ""
        do {
            let privateKeyData = Data(base64Encoded: _privateKey)!
            let privateKey = try RSA(rawRepresentation: privateKeyData)
            let encodedMsg = Data(base64Encoded: msg)!
            let clearData = try privateKey.decrypt(encodedMsg.bytes, variant: .pksc1v15)
            
            decryptedMsg = String(data: Data(clearData), encoding: .utf8) ?? ""
            //            let privateKey = try PrivateKey(base64Encoded: _privateKey)
            //            let encrypted = try EncryptedMessage(base64Encoded: msg)
            //            let clear = try encrypted.decrypted(with: privateKey, padding: .PKCS1)
            //
            //            decryptedMsg = try clear.string(encoding: .utf8)
        } catch let error {
            SecNtfySwifty.log.error("🔥 - Failed to DecryptMessage \(error.localizedDescription)")
            return "🔥 - Failed to DecryptMessage \(error.localizedDescription)"
        }
        return decryptedMsg
    }
    
    @MainActor
    public func MessageReceived(msgId: String) async {
        let urlString = "\(_apiUrl)/Message/Receive/\(msgId)"
        
        let JsonEncoder = JSONEncoder()
        let JsonDecoder = JSONDecoder()
        
        if (_deviceToken.isEmpty) {
            SecNtfySwifty.log.error("🔥 - Device Token is Empty")
            return
        }
        
        if (msgId.isEmpty) {
            SecNtfySwifty.log.error("🔥 - MessageId is Empty")
            return
        }
        
        guard let url = URL(string: urlString) else {
            SecNtfySwifty.log.error("🔥 - URL is not valid!")
            return
        }
        
        do {
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")  // the request is JSON
            request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Accept")        // the expected response is also JSON
            request.setValue("\(_deviceToken)", forHTTPHeaderField: "X-NTFYME-DEVICE-KEY")        // the expected response is also JSON
            JsonEncoder.outputFormatting = .prettyPrinted
            
            let (data, _) = try await URLSession.shared.data(for: request)
            let result = try JsonDecoder.decode(Response.self, from: data)
            SecNtfySwifty.log.info("♻️ - \(result.Message ?? "") \(result.Token ?? "")")
        } catch let error {
            SecNtfySwifty.log.error("🔥 - Failed to MessageReceived \(error.localizedDescription)")
            return
        }
    }
    
    private func anonymiesString(input: String) -> String {
        guard input.count > 10 else {
            return input
        }
        
        let startIndex = input.startIndex
        let endIndex = input.endIndex
        
        // Extract the first three characters
        let firstThree = input[startIndex..<input.index(startIndex, offsetBy: 5)]
        
        // Extract the last five characters
        let lastFive = input[input.index(endIndex, offsetBy: -5)..<endIndex]
        
        // Create the processed string
        let processedString = "" + firstThree + "*****" + lastFive + ""
        
        return processedString
    }
}

