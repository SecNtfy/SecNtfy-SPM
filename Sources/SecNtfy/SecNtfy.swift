// The Swift Programming Language
// https://docs.swift.org/swift-book

import Foundation
import SwiftyRSA
import SwiftyBeaver

#if canImport(UIKit)
import UIKit
import SwiftUI
#elseif canImport(AppKit)
import AppKit
#endif


public class SecNtfySwifty {
    
    @MainActor private static var _instance: SecNtfySwifty? = nil
    private var _publicKey = ""
    private var _privateKey = ""
    private var _apiKey = ""
    private var _apnsToken = ""
    private var _apiUrl = ""
    private var _bundleGroup = ""
    @MainActor private var _deviceToken: String = ""
    private var ntfyDevice: NTFY_Devices = NTFY_Devices()
    static let log = SwiftyBeaver.self
    
    init() { }
    
    @MainActor public static func getInstance() -> SecNtfySwifty {
        if (_instance == nil) {
            // add log destinations. at least one is needed!
            let console = ConsoleDestination()  // log to Xcode Console
            let file = FileDestination()  // log to default swiftybeaver.log file
            console.format = "$DHH:mm:ss$d $L $M"
            // add the destinations to SwiftyBeaver
            log.addDestination(console)
            log.addDestination(file)
            log.info("♻️ - instance nil, start init process")
            _instance = SecNtfySwifty()
        }
        log.info("♻️ - instance init")
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
                SecNtfySwifty.log.error("🔥 - The API URL or Bundle Group is empty")
            }
            
            SecNtfySwifty.log.info("♻️ - API URL \(_apiUrl)")
            SecNtfySwifty.log.info("♻️ - Bundle Group \(bundleGroup)")
            
            if (_publicKey.isEmpty || _privateKey.isEmpty) {
                let keyPair = try SwiftyRSA.generateRSAKeyPair(sizeInBits: 2048)
                _privateKey = try keyPair.privateKey.base64String()
                _publicKey = try keyPair.publicKey.base64String()
                
                userDefaults.set(_publicKey, forKey: "NTFY_PUB_KEY")
                userDefaults.set(_privateKey, forKey: "NTFY_PRIV_KEY")
            }
            
            SecNtfySwifty.log.info("PubKey: \(_publicKey)")
            SecNtfySwifty.log.info("PrivKey: \(anonymiesString(input: _privateKey))")
            
        } catch {
            SecNtfySwifty.log.error("🔥 - \(error.localizedDescription)")
        }
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
        ntfyDevice = NTFY_Devices(D_ID: 0, D_APP_ID: 0, D_OS: 1, D_OS_Version: osVersion, D_Model: model, D_APN_ID: "", D_Android_ID: "", D_PublicKey: _publicKey, D_NTFY_Token: "")
        
        SecNtfySwifty.log.info("Model: \(model)")
        SecNtfySwifty.log.info("OS: \(osVersion)")
        
        SecNtfySwifty.log.info("PubKey: \(_publicKey)")
        SecNtfySwifty.log.info("PrivKey: \(anonymiesString(input: _privateKey))")
    }
    
    @MainActor public func getNtfyToken(completionHandler: @escaping @Sendable (_ ntfyToken: String?, _ error: Error?) -> ()) {
        if (ntfyDevice.D_APP_ID == 0) {
            completionHandler(nil, NtfyError.noDevice)
        }
        PostDevice(dev: ntfyDevice, appKey: _apiKey) { ntfyToken, _bundleGroup, error in
            
            let userDefaults = UserDefaults(suiteName: _bundleGroup)!
            if (ntfyToken == nil) {
                completionHandler(ntfyToken, error)
            }
            
            //ntfyDevice.D_NTFY_Token = ntfyToken
            let _dt = userDefaults.string(forKey: "NTFY_DEVICE_TOKEN") ?? ""
            if (ntfyToken != nil && (_dt.isEmpty || _dt != ntfyToken)) {
                userDefaults.set(ntfyToken, forKey: "NTFY_DEVICE_TOKEN")
                Task { @MainActor in
                    self.setDeviceToken(token: ntfyToken!)
                }
            }
            
            completionHandler(ntfyToken, error)
        }
    }
    
    @MainActor func setDeviceToken(token: String) {
        _deviceToken = token
    }
    
    public func setApnsToken(apnsToken: String) {
        if (ntfyDevice.D_APP_ID == 0) {
            return
        }
        SecNtfySwifty.log.info("\(anonymiesString(input: apnsToken))")
        ntfyDevice.D_APN_ID = apnsToken
    }
    
    @MainActor func PostDevice(dev: NTFY_Devices, appKey: String, completionHandler: @MainActor @escaping @Sendable (_ ntfyToken: String?, _ bundleGroup: String, _ error: Error?) -> ()) {
        let urlString = "\(_apiUrl)/App/RegisterDevice"
        let bundle = _bundleGroup
        let JsonEncoder = JSONEncoder()
        let JsonDecoder = JSONDecoder()
        
        guard let url = URL(string: urlString) else {
            completionHandler(nil, _bundleGroup, NtfyError.unsuppotedURL)
            return
        }
        
        do {
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")  // the request is JSON
            request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Accept")        // the expected response is also JSON
            request.setValue("\(appKey)", forHTTPHeaderField: "X-NTFYME-AccessKey")        // the expected response is also JSON
            JsonEncoder.outputFormatting = .prettyPrinted
            
            let jsonData = try JsonEncoder.encode(dev)
            request.httpBody = jsonData
            
            let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
                Task {
                    do {
                        if error == nil {
                            let result = try JsonDecoder.decode(Response.self, from: data!)
                            SecNtfySwifty.log.error("♻️ - \(result.Message ?? "") \(result.Token ?? "") \(error?.localizedDescription ?? "")")
                            await completionHandler(result.Token, bundle, error)
                        } else {
                            SecNtfySwifty.log.error("🔥 - Failed task \(error!.localizedDescription)")
                            print("Failed task", error!)
                            await completionHandler(nil, bundle, error)
                            return
                        }
                    } catch let error {
                        SecNtfySwifty.log.error("🔥 - Failed task \(error.localizedDescription)")
                        print("Failed task", error)
                        await completionHandler(nil, bundle, error)
                        return
                    }
                }
            }
            
            task.resume()
        } catch let error {
            SecNtfySwifty.log.error("🔥 - Failed to PostDevice \(error.localizedDescription)")
            print("Failed to PostDevice", error)
            completionHandler(nil, _bundleGroup, error)
            return
        }
    }
    
    public func DecryptMessage(msg: String) -> String? {
        var decryptedMsg = ""
        do {
            let privateKey = try PrivateKey(base64Encoded: _privateKey)
            let encrypted = try EncryptedMessage(base64Encoded: msg)
            let clear = try encrypted.decrypted(with: privateKey, padding: .PKCS1)
            
            decryptedMsg = try clear.string(encoding: .utf8)
        } catch let error {
            SecNtfySwifty.log.error("🔥 - Failed to DecryptMessage \(error.localizedDescription)")
            return "🔥 - Failed to DecryptMessage \(error.localizedDescription)"
        }
        return decryptedMsg
    }
    
    @MainActor
    public func MessageReceived(msgId: String) {
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
            
            let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
                do {
                    if error == nil {
                        let result = try JsonDecoder.decode(Response.self, from: data!)
                        SecNtfySwifty.log.error("♻️ - \(result.Message ?? "") \(result.Token ?? "") \(error?.localizedDescription ?? "")")
                    } else {
                        SecNtfySwifty.log.error("🔥 - Failed task \(error!.localizedDescription)")
                        return
                    }
                } catch let error {
                    SecNtfySwifty.log.error("🔥 - Failed task \(error.localizedDescription)")
                    return
                }
            }
            
            task.resume()
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

