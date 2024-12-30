//
//  File.swift
//  SecNtfy
//
//  Created by Sebastian Rank on 30.12.24.
//

import Foundation
import Security

class RSAKeyManager {
    
    // MARK: - Key Generation
    func generateRSAKeyPair(for identifier: String) throws -> (privateKeyBase64: String, publicKeyBase64: String) {
        let uniqueTag = identifier.data(using: .utf8)!
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: uniqueTag
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        
        guard let privateKeyBase64 = exportKeyAsBase64(key: privateKey, isPrivate: true),
              let publicKeyBase64 = exportKeyAsBase64(key: privateKey, isPrivate: false) else {
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
    
    // MARK: - Export Public Key in PEM format
    func exportPublicKeyAsPEM(key: SecKey) -> String? {
        guard let keyBase64 = exportKeyAsBase64(key: key, isPrivate: false) else {
            return nil
        }
        
        let pemHeader = "-----BEGIN PUBLIC KEY-----\n"
        let pemFooter = "\n-----END PUBLIC KEY-----"
        
        var base64String = keyBase64
        while base64String.count > 64 {
            let range = base64String.index(base64String.startIndex, offsetBy: 64)..<base64String.index(base64String.startIndex, offsetBy: 128)
            let chunk = base64String[range]
            base64String = base64String.replacingCharacters(in: range, with: "\n\(chunk)")
        }
        
        return pemHeader + base64String + pemFooter
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
