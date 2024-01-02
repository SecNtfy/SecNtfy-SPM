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

@objcMembers
class SecNtfy: NSObject {
    private let JsonEncoder = JSONEncoder()
    private let JsonDecoder = JSONDecoder()
    private let userDefaults = UserDefaults.standard
    weak public var delegate: SecNtfyDelegate?
    
    
    public static func messaging() -> SecNtfy {
        return SecNtfy()
    }
    
    @Published public var apnsToken = "" {
        didSet{
            GetDeviceToken()
        }
    }
    
    @Published public var appKey = "" {
        didSet{
            //GetDeviceToken()
        }
    }
    
    private func GetDeviceToken() {
        var model = ""
        var osVersion = ""
        var result: Response? = nil
        
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
            let publicKey = try PublicKey(pemNamed: "public").pemString()
            let privateKey = try PrivateKey(pemNamed: "private").pemString()
            
            userDefaults.set(publicKey, forKey: "NTFY_PUB_KEY")
            userDefaults.set(privateKey, forKey: "NTFY_PRIV_KEY")
            
            let device = NTFY_Devices(D_ID: 0, D_APP_ID: 0, D_OS: 1, D_OS_Version: osVersion, D_Model: model, D_APN_ID: apnsToken, D_Android_ID: "", D_PublicKey: publicKey, D_NTFY_Token: "")
            PostDevice(dev: device, appKey: appKey)
        } catch {
            print(error)
        }
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
                    if let error = error { } else {
                        let result = try JsonDecoder.decode(Response.self, from: data!)
                        self.delegate?.messaging(didReceiveRegistrationToken: result.Token)
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
    
    /*private let userDefaults = UserDefaults.standard
     private var _appKey = ""
     @ObservedObject private var api: NetworkServices = NetworkServices()
     
     public init(apikey key: String) {
     let appKey = userDefaults.string(forKey: "NTFY_APP_KEY")
     if (appKey == nil) {
     userDefaults.set(key, forKey: "NTFY_APP_KEY")
     }
     _appKey = appKey ?? ""
     }
     
     public func messaging(handler: @escaping (_ devToken: String?)-> Void) async
     {
     var apnsToken: String = ""
     
     var model = ""
     var osVersion = ""
     var result: Response? = nil
     
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
     let publicKey = try PublicKey(pemNamed: "public").pemString()
     let privateKey = try PrivateKey(pemNamed: "private").pemString()
     
     userDefaults.set(publicKey, forKey: "NTFY_PUB_KEY")
     userDefaults.set(privateKey, forKey: "NTFY_PRIV_KEY")
     
     var device = NTFY_Devices(D_ID: 0, D_APP_ID: 0, D_OS: 1, D_OS_Version: osVersion, D_Model: model, D_APN_ID: apnsToken, D_Android_ID: "", D_PublicKey: publicKey, D_NTFY_Token: "")
     result = await api.PostDevice(dev: device, appKey: _appKey)
     
     print(result?.Token)
     
     handler(result?.Token)
     } catch {
     print(error)
     handler(nil)
     }
     }
     
     
     public func messaging() async -> String? {
     var apnsToken: String = ""
     
     var model = ""
     var osVersion = ""
     var result: Response? = nil
     
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
     let publicKey = try PublicKey(pemNamed: "public").pemString()
     let privateKey = try PrivateKey(pemNamed: "private").pemString()
     
     userDefaults.set(publicKey, forKey: "NTFY_PUB_KEY")
     userDefaults.set(privateKey, forKey: "NTFY_PRIV_KEY")
     
     var device = NTFY_Devices(D_ID: 0, D_APP_ID: 0, D_OS: 1, D_OS_Version: osVersion, D_Model: model, D_APN_ID: apnsToken, D_Android_ID: "", D_PublicKey: publicKey, D_NTFY_Token: "")
     result = await api.PostDevice(dev: device, appKey: _appKey)
     
     print(result?.Token)
     
     return result?.Token
     } catch {
     print(error)
     return ""
     }
     }*/
}

