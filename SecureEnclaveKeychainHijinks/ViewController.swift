//
//  ViewController.swift
//  SecureEnclaveKeychainHijinks
//
//  Created by David Wagner on 03/09/2019.
//  Copyright © 2019 David Wagner. All rights reserved.
//

import UIKit

class ViewController: UIViewController {
    
    let keychain = Keychain()
    let permanentKeyFactory = KeyFactory(permanent: true)
    var permanentKey: Key?
    
    let transientKeyFactory = KeyFactory(permanent: false)
    var transientKey: Key?

    @IBAction func handleDumpKeychain(_ sender: UIButton) {
        do {
            let items = try keychain.dump()

            print("-----[Keychain dump]-----")
            print("Keychain: \(keychain.keychainAccessGroupProvider.keychainAccessGroup)")
            print("Items:")
            print("  \(items.joined(separator: ",\n  "))")
            print("-------------------------")
        } catch {
            print("Keychain dump failed: \(error)")
        }
    }
    
    @IBAction func handleCreateTransientKey(_ sender: UIButton) {
        print("Creating transient key")
        do {
            self.transientKey = try transientKeyFactory.make()
        } catch {
            print("Create transient key failed: \(error)")
        }
    }
    
    @IBAction func handleTransientExercise(_ sender: UIButton) {
        print("Exercising transient key")
        guard let key = transientKey else {
            print("Transient key not created this session")
            return
        }
        
        do {
            try key.exercise()
            print("OK")
        } catch {
            print("Transient key exercising failed: \(error)")
        }
    }

    @IBAction func handleCreatePermanenttKey(_ sender: UIButton) {
        print("Creating permanent key")
        do {
            self.permanentKey = try permanentKeyFactory.make()
        } catch {
            print("Create permanent key failed: \(error)")
        }
    }
    
    @IBAction func handlePermanentExercise(_ sender: UIButton) {
        print("Exercising permanent key")
        guard let key = permanentKey else {
            print("Permanent key not created this session")
            return
        }
        
        do {
            try key.exercise()
            print("OK")
        } catch {
            print("Permanent key exercising failed: \(error)")
        }
    }

    @IBAction func handleDeleteAllItems(_ sender: UIButton) {
        print("Deleting all items in \(keychain.keychainAccessGroupProvider.keychainAccessGroup)")
        keychain.deleteAll()
    }

    
}

