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
    private let userDefaults = UserDefaults.standard
    private var publicKey = ""
    private var privateKey = ""
    private var ntfyDevice: NTFY_Devices?
    private var _apiKey = ""
    private var _apnsToken = ""
    
    let logger = Logger(label: "de.sr.SecNtfy")
    
    private var _instance: SecNtfySwifty? = nil;
    
    public func getInstance() -> SecNtfySwifty {
        if (_instance == nil) {
            _instance = SecNtfySwifty()
        }
        return _instance!
    }
    
    public init() { }
    
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
        
        do {
            publicKey = userDefaults.string(forKey: "NTFY_PUB_KEY") ?? ""
            privateKey = userDefaults.string(forKey: "NTFY_PRIV_KEY") ?? ""
            
            if (publicKey.count == 0 || privateKey.count == 0) {
                let keyPair = try SwiftyRSA.generateRSAKeyPair(sizeInBits: 2048)
                privateKey = try keyPair.privateKey.pemString()
                publicKey = try keyPair.publicKey.pemString()
                
                userDefaults.set(publicKey, forKey: "NTFY_PUB_KEY")
                userDefaults.set(privateKey, forKey: "NTFY_PRIV_KEY")
            }
            
            ntfyDevice = NTFY_Devices(D_ID: 0, D_APP_ID: 0, D_OS: 1, D_OS_Version: osVersion, D_Model: model, D_APN_ID: "", D_Android_ID: "", D_PublicKey: publicKey, D_NTFY_Token: "")
            
            logger.info("PubKey: \(publicKey)")
            logger.info("PrivKey: \(privateKey)")
            
        } catch {
            logger.error("\(error.localizedDescription)")
        }
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
        logger.info("\(apnsToken)")
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
                        logger.error("\(result.Message) \(result.Token) \(error?.localizedDescription)")
                        completionHandler(result.Token, error)
                    } else {
                        logger.error("Failed task \(error!.localizedDescription)")
                        print("Failed task", error!)
                        completionHandler(nil, error)
                        return
                    }
                } catch let error {
                    logger.error("Failed task \(error.localizedDescription)")
                    print("Failed task", error)
                    completionHandler(nil, error)
                    return
                }
            }
            
            task.resume()
        } catch let error {
            logger.error("Failed to PostDevice \(error.localizedDescription)")
            print("Failed to PostDevice", error)
            completionHandler(nil, error)
            return
        }
    }
}

