// The Swift Programming Language
// https://docs.swift.org/swift-book

import Foundation
import SwiftyRSA

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
    weak public var delegate: SecNtfyDelegate?
    
    public init() { }
    
    public func messaging() -> SecNtfySwifty {
        return SecNtfySwifty()
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
        osVersion = "\(UIDevice.current.systemName) \(UIDevice.current.systemVersion)"
#else
        model = "Macbook"
        osVersion = "macOS"
#endif
        
        do {
            publicKey = userDefaults.string(forKey: "NTFY_PUB_KEY") ?? ""
            privateKey = userDefaults.string(forKey: "NTFY_PRIV_KEY") ?? ""
            
            if (publicKey.count == 0 || privateKey.count == 0) {
                publicKey = try PublicKey(pemNamed: "public").pemString()
                privateKey = try PrivateKey(pemNamed: "private").pemString()
                
                userDefaults.set(publicKey, forKey: "NTFY_PUB_KEY")
                userDefaults.set(privateKey, forKey: "NTFY_PRIV_KEY")
            }
            
            ntfyDevice = NTFY_Devices(D_ID: 0, D_APP_ID: 0, D_OS: 1, D_OS_Version: osVersion, D_Model: model, D_APN_ID: "", D_Android_ID: "", D_PublicKey: publicKey, D_NTFY_Token: "")
        } catch {
            print(error)
        }
    }
    
    public func setApnsToken(apnsToken: String) {
        if (ntfyDevice == nil) {
            return
        }
        
        ntfyDevice?.D_APN_ID = apnsToken
        PostDevice(dev: ntfyDevice!, appKey: _apiKey)
    }
    
    func PostDevice(dev: NTFY_Devices, appKey: String) {
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
                        self.delegate?.messaging(didReceiveRegistrationToken: result.Token)
                    } else {
                        print("Failed task", error)
                        return
                    }
                } catch let error {
                    print("Failed task", error)
                    return
                }
            }
            
            task.resume()
        } catch let error {
            print("Failed to PostDevice", error)
            return
        }
    }
}

