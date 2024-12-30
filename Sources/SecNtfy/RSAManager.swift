import Foundation
import Security
import CryptoSwift

class RSAKeyManager {
    
    // MARK: - Key Generation
    func generateRSAKeyPair(for identifier: String) throws -> (privateKeyBase64: String, publicKeyBase64: String) {
        
        /// Starting with a CryptoSwift RSA Key
        let rsaKey = try RSA(keySize: 2048)

        /// Define your Keys attributes
        let attributes: [String:Any] = [
          kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
          kSecAttrKeyClass as String: kSecAttrKeyClassPrivate, // or kSecAttrKeyClassPublic
          kSecAttrKeySizeInBits as String: 1024, // The appropriate bits
          kSecAttrIsPermanent as String: false
        ]
        var error:Unmanaged<CFError>? = nil
        guard let rsaSecKey = try SecKeyCreateWithData(rsaKey.externalRepresentation() as CFData, attributes as CFDictionary, &error) else {
          /// Error constructing SecKey from raw key data
            throw NSError(domain: "KeyExportError", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to export keys"])
        }
        
        
//        
//        let uniqueTag = identifier.data(using: .utf8)!
//        
//        let attributes: [String: Any] = [
//            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
//            kSecAttrKeySizeInBits as String: 2048,
//            kSecPrivateKeyAttrs as String: [
//                kSecAttrIsPermanent as String: true,
//                kSecAttrApplicationTag as String: uniqueTag
//            ]
//        ]
//        
//        var error: Unmanaged<CFError>?
//        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
//            throw error!.takeRetainedValue() as Error
//        }
        
        guard let privateKeyBase64 = exportKeyAsBase64(key: rsaSecKey, isPrivate: true),
              let publicKeyBase64 = exportKeyAsBase64(key: rsaSecKey, isPrivate: false) else {
            throw NSError(domain: "KeyExportError", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to export keys"])
        }
        
        return (privateKeyBase64, publicKeyBase64)
    }
    
    // MARK: - Key Export
    private func exportKeyAsBase64(key: SecKey, isPrivate: Bool) -> String? {
        var error: Unmanaged<CFError>?
        var keyData: Data?
        
        if isPrivate {
            // Export private key
            guard let cfKeyData = SecKeyCopyExternalRepresentation(key, &error) else {
                print("Error exporting private key: \(error!.takeRetainedValue())")
                return nil
            }
            keyData = cfKeyData as Data
        } else {
            // Export public key (DER-encoded)
            guard let cfKeyData = SecKeyCopyExternalRepresentation(key, &error) else {
                print("Error exporting public key: \(error!.takeRetainedValue())")
                return nil
            }
            keyData = cfKeyData as Data
        }
        
        // Convert the raw key data to Base64 (usable for storage or transmission)
        return keyData?.base64EncodedString()
    }
    
    // MARK: - Key Retrieval
    private func getKey(with identifier: String, isPrivate: Bool) -> SecKey? {
        let uniqueTag = identifier.data(using: .utf8)!
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: uniqueTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnRef as String: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess else {
            print("Error retrieving key: \(status)")
            return nil
        }
        return (item as! SecKey)
    }
    
    // MARK: - Encryption
    func encrypt(message: String, usingPublicKeyFor identifier: String) throws -> String {
        guard let publicKey = getKey(with: identifier, isPrivate: false) else {
            throw NSError(domain: "EncryptionError", code: -1, userInfo: [NSLocalizedDescriptionKey: "Public key not found"])
        }
        
        let messageData = message.data(using: .utf8)!
        
        var error: Unmanaged<CFError>?
        guard let encryptedData = SecKeyCreateEncryptedData(publicKey,
                                                            SecKeyAlgorithm.rsaEncryptionPKCS1,
                                                            messageData as CFData,
                                                            &error) else {
            throw error!.takeRetainedValue() as Error
        }
        
        return (encryptedData as Data).base64EncodedString()
    }
    
    // MARK: - Decryption
    func decrypt(encryptedBase64: String, usingPrivateKeyFor identifier: String) throws -> String {
        guard let privateKey = getKey(with: identifier, isPrivate: true) else {
            throw NSError(domain: "DecryptionError", code: -1, userInfo: [NSLocalizedDescriptionKey: "Private key not found"])
        }
        
        guard let encryptedData = Data(base64Encoded: encryptedBase64) else {
            throw NSError(domain: "DecryptionError", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid Base64 encrypted string"])
        }
        
        var error: Unmanaged<CFError>?
        guard let decryptedData = SecKeyCreateDecryptedData(privateKey,
                                                            SecKeyAlgorithm.rsaEncryptionPKCS1,
                                                            encryptedData as CFData,
                                                            &error) else {
            throw error!.takeRetainedValue() as Error
        }
        
        return String(data: decryptedData as Data, encoding: .utf8)!
    }
}
