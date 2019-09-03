//
//  KeyFactory.swift
//  SecureEnclaveKeychainHijinks
//
//  Created by David Wagner on 03/09/2019.
//  Copyright © 2019 David Wagner. All rights reserved.
//

import Foundation

struct KeyFactory {
    
    enum Error: Swift.Error {
        case notImplemented
        case accessControlCreationFailed(Swift.Error?)
        case keyDoesNotExist
        case keySearchFailed(OSStatus)
        case keyDeleteFailed(OSStatus)
        case keyCreationFailed(Swift.Error?)
    }
    
    let keychainAccessGroupProvider: KeychainAccessGroupProvider
    let permanent: Bool
    let tag: Data
    
    init(keychainAccessGroupProvider: KeychainAccessGroupProvider = KeychainAccessGroupProvider.default,
         permanent: Bool = true,
         tag: Data = Data("SecureEnclaveKeychainHijinks".utf8))
    {
        self.keychainAccessGroupProvider = keychainAccessGroupProvider
        self.permanent = permanent
        self.tag = tag
    }
    
    var keyExists: Bool {
        do {
            let _ = try findKeyRef()
        } catch KeyFactory.Error.keyDoesNotExist {
            return false
        } catch {
            print("Failed to get key ref: \(error)")
            return false
        }
        return true
    }

    func delete() throws {
        let query = self.baseQuery()
        let result = SecItemDelete(query as CFDictionary)
        guard result == errSecSuccess || result == errSecItemNotFound else {
            throw KeyFactory.Error.keyDeleteFailed(result)
        }
    }
    
    func make() throws -> Key {
        let attributes = try self.attributes()
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw KeyFactory.Error.keyCreationFailed(error?.takeRetainedValue())
        }
        
        return Key(underlying: key)
    }
    
    private func findKeyRef() throws -> SecKey {
        var query = baseQuery()
        query[kSecReturnRef as String] = true

        var item: CFTypeRef?
        let result = SecItemCopyMatching(query as CFDictionary, &item)
        
        if result == errSecItemNotFound {
            throw KeyFactory.Error.keyDoesNotExist
        }
        
        guard result == errSecSuccess else {
            throw KeyFactory.Error.keySearchFailed(result)
        }
        
        return item as! SecKey
    }

    private func attributes() throws -> [String: Any] {
        let access = try accessControl()
        return [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrAccessGroup as String: keychainAccessGroupProvider.keychainAccessGroup,
            kSecPrivateKeyAttrs as String : [
                kSecAttrIsPermanent as String: permanent,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access,
            ]
        ]
    }
    
    private func accessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .privateKeyUsage, &error) else {
            throw KeyFactory.Error.accessControlCreationFailed(error?.takeRetainedValue())
        }
        return access
    }
    
    private func baseQuery() -> [String: Any] {
        return [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessGroup as String: keychainAccessGroupProvider.keychainAccessGroup,
        ]
    }
}

struct Key {
    enum Error: Swift.Error {
        case couldNotCopyPublicKey
        case couldNotEncrypt(Swift.Error?)
        case couldNotDecrypt(Swift.Error?)
        case failed
    }
    
    let underlying: SecKey
    
    func exercise() throws {
        let message = Data("A Series Of Unlikely Explanations".utf8)
        let cipher = try encrypt(message)
        let decrypted = try decrypt(cipher)
        guard message == decrypted else {
            throw Key.Error.failed
        }
    }
    
    func encrypt(_ message: Data) throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(underlying) else {
            throw Key.Error.couldNotCopyPublicKey
        }
        
        var error: Unmanaged<CFError>?
        guard let cipher = SecKeyCreateEncryptedData(publicKey,
                                               .eciesEncryptionCofactorVariableIVX963SHA256AESGCM,
                                               message as CFData,
                                               &error) else
        {
            throw Key.Error.couldNotEncrypt(error?.takeRetainedValue())
        }
        
        return cipher as Data
    }
    
    func decrypt(_ cipher: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let message = SecKeyCreateDecryptedData(underlying,
                                                      .eciesEncryptionCofactorVariableIVX963SHA256AESGCM,
                                                      cipher as CFData,
                                                      &error) else
        {
            throw Key.Error.couldNotDecrypt(error?.takeRetainedValue())
        }
        
        return message as Data
    }
    
}
