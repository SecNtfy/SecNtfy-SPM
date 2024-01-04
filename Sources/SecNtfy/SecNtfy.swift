// The Swift Programming Language
// https://docs.swift.org/swift-book

import Foundation
import SwiftyRSA
import Logging

#if canImport(UIKit)
import UIKit
import SwiftUI
#elseif canImport(AppKit)
import AppKit
#endif

public class SecNtfySwifty {
    private let JsonEncoder = JSONEncoder()
    private let JsonDecoder = JSONDecoder()
    private var userDefaults = UserDefaults.standard
    private var publicKey = ""
    private var privateKey = ""
    private var ntfyDevice: NTFY_Devices?
    private static var _instance: SecNtfySwifty? = nil;
    private var _apiKey = ""
    private var _apnsToken = ""
    
    static let logger = Logger(label: "de.sr.SecNtfy")
    
    init() { }
    
    public static func getInstance() -> SecNtfySwifty {
        if (_instance == nil) {
            logger.info("instance nilllll")
            _instance = SecNtfySwifty()
        }
        logger.info("instance init")
        return _instance!
    }
    
    public func initialize(bundleGroup: String) {
        userDefaults = UserDefaults(suiteName: bundleGroup)!
        
        do {
            publicKey = userDefaults.string(forKey: "NTFY_PUB_KEY") ?? ""
            privateKey = userDefaults.string(forKey: "NTFY_PRIV_KEY") ?? ""
            
            if (publicKey.count == 0 || privateKey.count == 0) {
                let keyPair = try SwiftyRSA.generateRSAKeyPair(sizeInBits: 256)
                privateKey = try keyPair.privateKey.pemString()
                publicKey = try keyPair.publicKey.pemString()
                
                userDefaults.set(publicKey, forKey: "NTFY_PUB_KEY")
                userDefaults.set(privateKey, forKey: "NTFY_PRIV_KEY")
            }
            
            SecNtfySwifty.logger.info("PubKey: \(publicKey)")
            SecNtfySwifty.logger.info("PrivKey: \(privateKey)")
            
        } catch {
            SecNtfySwifty.logger.error("\(error.localizedDescription)")
        }
    }
    
    public func configure(apiKey: String) {
        _apiKey = apiKey
        var model = ""
        var osVersion = ""
        
#if os(iOS) || os(tvOS)
        model = UIDevice.current.model
        if (model.contains("?unrecognized?")) {
            model = UIDevice.current.name
        }
        osVersion = "\(UIDevice.current.systemVersion)"
#else
        model = "Macbook"
        osVersion = "macOS"
#endif
        ntfyDevice = NTFY_Devices(D_ID: 0, D_APP_ID: 0, D_OS: 1, D_OS_Version: osVersion, D_Model: model, D_APN_ID: "", D_Android_ID: "", D_PublicKey: publicKey, D_NTFY_Token: "")
        
        SecNtfySwifty.logger.info("PubKey: \(publicKey)")
        SecNtfySwifty.logger.info("PrivKey: \(privateKey)")
    }
    
    public func getNtfyToken(completionHandler: @escaping (_ ntfyToken: String?, _ error: Error?) -> ()) {
        if (ntfyDevice == nil) {
            return
        }
        PostDevice(dev: ntfyDevice!, appKey: _apiKey) { [self] ntfyToken, error in
            if (ntfyToken == nil) {
                completionHandler(ntfyToken, error)
            }
            ntfyDevice?.D_NTFY_Token = ntfyToken
            completionHandler(ntfyToken, error)
        }
    }
    
    public func setApnsToken(apnsToken: String) {
        if (ntfyDevice == nil) {
            return
        }
        SecNtfySwifty.logger.info("\(apnsToken)")
        ntfyDevice?.D_APN_ID = apnsToken
    }
    
    func PostDevice(dev: NTFY_Devices, appKey: String, completionHandler: @escaping (_ ntfyToken: String?, _ error: Error?) -> ()) {
        let urlString = "http://localhost:5137/App/RegisterDevice"
        
        guard let url = URL(string: urlString) else {
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
            
            let task = URLSession.shared.dataTask(with: request) { [self] (data, response, error) in
                do {
                    if error == nil {
                        let result = try JsonDecoder.decode(Response.self, from: data!)
                        SecNtfySwifty.logger.error("\(result.Message) \(result.Token) \(error?.localizedDescription)")
                        completionHandler(result.Token, error)
                    } else {
                        SecNtfySwifty.logger.error("Failed task \(error!.localizedDescription)")
                        print("Failed task", error!)
                        completionHandler(nil, error)
                        return
                    }
                } catch let error {
                    SecNtfySwifty.logger.error("Failed task \(error.localizedDescription)")
                    print("Failed task", error)
                    completionHandler(nil, error)
                    return
                }
            }
            
            task.resume()
        } catch let error {
            SecNtfySwifty.logger.error("Failed to PostDevice \(error.localizedDescription)")
            print("Failed to PostDevice", error)
            completionHandler(nil, error)
            return
        }
    }
    
    public func DecryptMessage(msg: String) -> String {
        var decryptedMsg = ""
        do {
            let privateKey = try PrivateKey(pemEncoded: privateKey)
            let encrypted = try EncryptedMessage(base64Encoded: msg)
            let clear = try encrypted.decrypted(with: privateKey, padding: .PKCS1)
            
            let data = clear.data
            decryptedMsg = try clear.string(encoding: .utf8)
        } catch let error {
            SecNtfySwifty.logger.error("Failed to DecryptMessage \(error.localizedDescription)")
        }
        
        return decryptedMsg
    }
}

