//
//  File.swift
//  SecNtfy
//
//  Created by Sebastian Rank on 30.12.24.
//

import Foundation
import Security

// Helper function for ASN.1 encoding
struct ASN1 {
    static func encodePublicKey(modulus: Data, exponent: Data) -> Data {
        let sequence: [UInt8] = [
            0x30, 0x00, // Sequence tag and length placeholder
            0x02, 0x00, // Integer tag and length placeholder for modulus
            0x00, 0x00, // Modulus length placeholder
            0x02, 0x00, // Integer tag and length placeholder for exponent
            0x00, 0x00  // Exponent length placeholder
        ]
        
        // Encode the actual data (modulus and exponent)
        var data: [UInt8] = sequence
        // Append modulus and exponent
        data.append(contentsOf: modulus)
        data.append(contentsOf: exponent)
        
        return Data(data)
    }
    
    static func encodePrivateKey(modulus: Data, exponent: Data, privateExponent: Data) -> Data {
        let sequence: [UInt8] = [
            0x30, 0x00, // Sequence tag and length placeholder
            0x02, 0x00, // Integer tag and length placeholder for modulus
            0x00, 0x00, // Modulus length placeholder
            0x02, 0x00, // Integer tag and length placeholder for exponent
            0x00, 0x00, // Exponent length placeholder
            0x02, 0x00  // Private exponent placeholder
        ]
        
        var data: [UInt8] = sequence
        // Append modulus, exponent, and private exponent
        data.append(contentsOf: modulus)
        data.append(contentsOf: exponent)
        data.append(contentsOf: privateExponent)
        
        return Data(data)
    }
}

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
        
        // Export the private and public keys in ASN.1 format and then base64 encode
        guard let privateKeyBase64 = exportKeyAsASN1Base64(key: privateKey, isPrivate: true),
              let publicKeyBase64 = exportKeyAsASN1Base64(key: privateKey, isPrivate: false) else {
            throw NSError(domain: "KeyExportError", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to export keys"])
        }
        
        return (privateKeyBase64, publicKeyBase64)
    }
    
    // MARK: - Key Export (ASN.1 encoding)
    private func exportKeyAsASN1Base64(key: SecKey, isPrivate: Bool) -> String? {
        var error: Unmanaged<CFError>?
        var keyData: Data?
        
        if isPrivate {
            // Export private key in ASN.1 DER format
            guard let privateKey = SecKeyCopyExternalRepresentation(key, &error) else {
                print("Error exporting private key: \(error!.takeRetainedValue())")
                return nil
            }
            let privateKeyData = privateKey as Data
            
            // Example: Convert to ASN.1 DER (modulus, exponent, private exponent, etc.)
            let modulus = privateKeyData.prefix(256) // Example, extract modulus
            let exponent = privateKeyData.suffix(3)  // Example, extract exponent
            let privateExponent = privateKeyData.suffix(128) // Example, extract private exponent
            
            keyData = ASN1.encodePrivateKey(modulus: modulus, exponent: exponent, privateExponent: privateExponent)
            
        } else {
            // Export public key in ASN.1 DER format
            guard let publicKey = SecKeyCopyExternalRepresentation(key, &error) else {
                print("Error exporting public key: \(error!.takeRetainedValue())")
                return nil
            }
            let publicKeyData = publicKey as Data
            
            // Example: Convert to ASN.1 DER (modulus, exponent)
            let modulus = publicKeyData.prefix(256) // Example, extract modulus
            let exponent = publicKeyData.suffix(3)  // Example, extract exponent
            
            keyData = ASN1.encodePublicKey(modulus: modulus, exponent: exponent)
        }
        
        // Convert the ASN.1 encoded data to Base64
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
