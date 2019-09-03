//
//  Keychain.swift
//  SecureEnclaveKeychainHijinks
//
//  Created by David Wagner on 03/09/2019.
//  Copyright © 2019 David Wagner. All rights reserved.
//

import Foundation

struct Keychain {
    enum Error: Swift.Error {
        case failed(OSStatus)
        case failedToConvertItemAttributes
    }
    
    let keychainAccessGroupProvider: KeychainAccessGroupProvider
    
    private let allSecClasses = [
        kSecClassInternetPassword,
        kSecClassGenericPassword,
        kSecClassCertificate,
        kSecClassKey,
        kSecClassIdentity,
    ]
    
    init(keychainAccessGroupProvider: KeychainAccessGroupProvider = KeychainAccessGroupProvider.default) {
        self.keychainAccessGroupProvider = keychainAccessGroupProvider
    }

    func dump() throws -> [String] {
        var output = [String]()
        for secClass in allSecClasses {
            let query = attributesQueryFor(secClass: secClass)
            var item: CFTypeRef?
            let result = SecItemCopyMatching(query as CFDictionary, &item)
            if result == errSecItemNotFound {
                continue
            }
            
            guard result == errSecSuccess else {
                throw Keychain.Error.failed(result)
            }
            
            output.append(CFCopyDescription(item)! as String)
        }
        
        return output
    }
    
    func deleteAll() {
        for secClass in allSecClasses {
            let query: [String: Any] = [
                kSecAttrAccessGroup as String: keychainAccessGroupProvider.keychainAccessGroup,
                kSecClass as String: secClass
            ]
            let result = SecItemDelete(query as CFDictionary)
            if result != errSecSuccess && result != errSecItemNotFound {
                print("Failed to delete items for class \(secClass): \(result)")
            }
        }
    }
    
    private func attributesQueryFor(secClass: CFString) -> [String: Any] {
        return [
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecAttrAccessGroup as String: keychainAccessGroupProvider.keychainAccessGroup,
            kSecClass as String: secClass
        ]
    }
}

struct KeychainAccessGroupProvider {
    let keychainAccessGroup: String
    
    init(keychainAccessGroup: String) {
        self.keychainAccessGroup = keychainAccessGroup
    }
    
    static var `default`: KeychainAccessGroupProvider = {
        guard let prefix = Bundle.main.infoDictionary?["AppIdentifierPrefix"] as? String else {
            fatalError("Could not get AppIdentifierPrefix from main bundle info")
        }
        
        guard let bundleID = Bundle.main.infoDictionary?[kCFBundleIdentifierKey as String] as? String else {
            fatalError("Could not get CFBundleIdentifier from main bundle info")
        }
        
        let keychainAccessGroup = "\(prefix)\(bundleID)"
        
        return KeychainAccessGroupProvider(keychainAccessGroup: keychainAccessGroup)
    }()
}
