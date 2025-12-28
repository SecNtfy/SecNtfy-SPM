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
    private var ntfyDevice: NTFY_Devices = NTFY_Devices()
    private let log = SwiftyBeaver.self
    @MainActor public static let shared: SecNtfySwifty = getInstance()
    @MainActor private static var _instance: SecNtfySwifty?
    
    private init() {
        // add log destinations. at least one is needed!
        let console = ConsoleDestination()  // log to Xcode Console
        let file = FileDestination()  // log to default swiftybeaver.log file
        console.format = "$DHH:mm:ss$d $L $M"
        // add the destinations to SwiftyBeaver
        log.addDestination(console)
        log.addDestination(file)
        log.info("♻️ - Init SecNtfySwifty")
    }
    
    @MainActor
    private static func getInstance() -> SecNtfySwifty {
        
        if (_instance == nil) {
            _instance = SecNtfySwifty()
        }else {
            print("already init SecNtfySwifty")
        }
        return _instance!
    }
    
    @MainActor
    public func initialize(apiUrl: String = "", bundleGroup: String = "de.sr.SecNtfy") {
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
                log.error("🔥 - The API URL or Bundle Group is empty")
            }
            
            log.info("♻️ - API URL \(_apiUrl)")
            log.info("♻️ - Bundle Group \(bundleGroup)")
            
            if (_publicKey.isEmpty || _privateKey.isEmpty) {
                log.info("♻️ - Start generating RSA keys")
                let keyPair = try RSA(keySize: 2048)
                log.info("♻️ - RSA keys generated")
                _privateKey = try keyPair.externalRepresentation().base64EncodedString()
                log.info("♻️ - get private key")
                _publicKey = try keyPair.publicKeyExternalRepresentation().base64EncodedString()
                log.info("♻️ - get public key")
                
                userDefaults.set(_publicKey, forKey: "NTFY_PUB_KEY")
                userDefaults.set(_privateKey, forKey: "NTFY_PRIV_KEY")
                log.info("♻️ - saved keys")
            }
            
            log.info("PubKey: \(_publicKey)")
            log.info("PrivKey: \(anonymiesString(input: _privateKey))")
            
        } catch {
            log.error("🔥 - \(error.localizedDescription)")
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
                    log.error("🔥 - \(result.token ?? "token is nil in UpdateDevice")")
                }
                return isSuccess
            }
        }
        catch {
            log.error("🔥 - \(error.localizedDescription)")
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
        
        log.info("Model: \(model)")
        log.info("OS: \(osVersion)")
        
        log.info("PubKey: \(_publicKey)")
        log.info("PrivKey: \(anonymiesString(input: _privateKey))")
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
        log.info("\(anonymiesString(input: apnsToken))")
        _apnsToken = apnsToken
        ntfyDevice.D_APN_ID = apnsToken
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
            log.info("♻️ - \(result.Message ?? "") \(result.Token ?? "")")
            ntfyDevice.D_NTFY_Token = result.Token
            return ResultHandler(token: result.Token, bundleGroup: bundle)
        } catch let error {
            log.error("🔥 - Failed to PostDevice \(error.localizedDescription)")
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
            log.info("♻️ - \(result.Message ?? "") \(result.Token ?? "")")
            return ResultHandler(token: result.Message, bundleGroup: bundle)
        } catch let error {
            log.error("🔥 - Failed to UpdateDevice \(error.localizedDescription)")
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
            log.error("🔥 - Failed to DecryptMessage \(error.localizedDescription)")
            return "🔥 - Failed to DecryptMessage \(error.localizedDescription)"
        }
        return decryptedMsg
    }
    
    @MainActor
    public func MessageReceived(msgId: String) async -> Bool {
        let urlString = "\(_apiUrl)/Message/Receive/\(msgId)"
        
        let JsonEncoder = JSONEncoder()
        let JsonDecoder = JSONDecoder()
        
        if (_deviceToken.isEmpty) {
            log.error("🔥 - Device Token is Empty")
            return false
        }
        
        if (msgId.isEmpty) {
            log.error("🔥 - MessageId is Empty")
            return false
        }
        
        guard let url = URL(string: urlString) else {
            log.error("🔥 - URL is not valid!")
            return false
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
            log.info("♻️ - \(result.Message ?? "") \(result.Token ?? "")")
            return result.Status == 201
        } catch let error {
            log.error("🔥 - Failed to MessageReceived \(error.localizedDescription)")
            return false
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
    
    public static func OfflineMessageReceived(_ msgId: String, _ bundleGroup: String = "de.sr.SecNtfy") async -> Bool {
        var msgReceived = false
        
        let log = SwiftyBeaver.self
        let console = ConsoleDestination()  // log to Xcode Console
        let file = FileDestination()  // log to default swiftybeaver.log file
        console.format = "$DHH:mm:ss$d $L $M"
        // add the destinations to SwiftyBeaver
        log.addDestination(console)
        log.addDestination(file)
        log.info("♻️ - Init OfflineMessageReceived")
        
        do {
            let userDefaults = UserDefaults(suiteName: bundleGroup) ?? .standard
            
            if (userDefaults == UserDefaults.standard) {
                throw CryptionError.UserDefaultsError
            }
            
            let pubKey = userDefaults.string(forKey: "NTFY_PUB_KEY") ?? ""
            let privKey = userDefaults.string(forKey: "NTFY_PRIV_KEY") ?? ""
            let apiUrl = userDefaults.string(forKey: "NTFY_API_URL") ?? ""
            let deviceToken = userDefaults.string(forKey: "NTFY_DEVICE_TOKEN") ?? ""
            
            let urlString = "\(apiUrl)/Message/Receive/\(msgId)"
            
            let JsonEncoder = JSONEncoder()
            let JsonDecoder = JSONDecoder()
            
            if (deviceToken.isEmpty) {
                log.error("🔥 - Device Token is Empty")
                return false
            }
            
            if (msgId.isEmpty) {
                log.error("🔥 - MessageId is Empty")
                return false
            }
            
            guard let url = URL(string: urlString) else {
                log.error("🔥 - URL is not valid!")
                return false
            }
            
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")  // the request is JSON
            request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Accept")        // the expected response is also JSON
            request.setValue("\(deviceToken)", forHTTPHeaderField: "X-NTFYME-DEVICE-KEY")        // the expected response is also JSON
            JsonEncoder.outputFormatting = .prettyPrinted
            
            let (data, _) = try await URLSession.shared.data(for: request)
            let result = try JsonDecoder.decode(Response.self, from: data)
            log.info("♻️ - \(result.Message ?? "") \(result.Token ?? "")")
            msgReceived = result.Status == 201
            
        } catch CryptionError.UserDefaultsError {
            log.error("🔥 - OfflineMessageReceived: UserDefaults is standard bundleGroup not found or suiteName not found!")
        } catch let error {
            log.error("🔥 - OfflineMessageReceived: \(error.localizedDescription)")
            return false
        }
        
        return msgReceived
    }
    
    public static func OfflineDecryption(_ msg: String, _ bundleGroup: String = "de.sr.SecNtfy") -> String {
        
        var text = ""
        let log = SwiftyBeaver.self
        let console = ConsoleDestination()  // log to Xcode Console
        let file = FileDestination()  // log to default swiftybeaver.log file
        console.format = "$DHH:mm:ss$d $L $M"
        // add the destinations to SwiftyBeaver
        log.addDestination(console)
        log.addDestination(file)
        log.info("♻️ - Init OfflineDecryption")
        
        do {
            let userDefaults = UserDefaults(suiteName: bundleGroup) ?? .standard
            
            if (userDefaults == UserDefaults.standard) {
                throw CryptionError.UserDefaultsError
            }
            
            let pubKey = userDefaults.string(forKey: "NTFY_PUB_KEY") ?? ""
            let privKey = userDefaults.string(forKey: "NTFY_PRIV_KEY") ?? ""
            let apiUrl = userDefaults.string(forKey: "NTFY_API_URL") ?? ""
            let deviceToken = userDefaults.string(forKey: "NTFY_DEVICE_TOKEN") ?? ""
            
            let privateKeyData = Data(base64Encoded: privKey) ?? Data()
            if (privateKeyData.isEmpty) {
                throw CryptionError.EncodingBase64PrivateKeyError
            }
            let privateKey = try RSA(rawRepresentation: privateKeyData)
            let encodedMsg = Data(base64Encoded: msg) ?? Data()
            if (encodedMsg.isEmpty) {
                throw CryptionError.EncodingBase64Error
            }
            let clearData = try privateKey.decrypt(encodedMsg.bytes, variant: .pksc1v15)
            text = String(data: Data(clearData), encoding: .utf8) ?? ""
            
        } catch CryptionError.EncodingError {
            log.error("🔥 - OfflineDecryption: Encoding failed")
        } catch CryptionError.EncodingBase64PrivateKeyError {
            log.error("🔥 - OfflineDecryption: PrivateKey Base64 Data failed")
        } catch CryptionError.EncodingBase64Error {
            log.error("🔥 - OfflineDecryption: Message Base64 Data failed")
        } catch CryptionError.DecodingError {
            log.error("🔥 - OfflineDecryption: Decoding failed")
        } catch CryptionError.UserDefaultsError {
            log.error("🔥 - OfflineDecryption: UserDefaults is standard bundleGroup not found or suiteName not found!")
        } catch {
            log.error("🔥 - OfflineDecryption: failed")
        }
        return text
    }
}

enum CryptionError: Error {
    case EncodingError
    case EncodingBase64PrivateKeyError
    case EncodingBase64Error
    case DecodingError
    case UserDefaultsError
}
