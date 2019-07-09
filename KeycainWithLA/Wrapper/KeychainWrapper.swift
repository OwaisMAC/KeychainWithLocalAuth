//
//  KeychainWrapper.swift
//  ECommerce
//
//  Created by Liangzan Chen on 4/19/16.
//  Copyright © 2016 Albertsons. All rights reserved.
//

import Foundation

import Security
import LocalAuthentication


/// The singleton class that wraps the implementation for accessing the Keychain
class KeychainWrapper {
    
    // MARK: Properties
    
    private let secMatchLimit: String! = kSecMatchLimit as String
    private let secReturnData: String! = kSecReturnData as String
    private let secReturnPersistentRef: String! = kSecReturnPersistentRef as String
    private let secValueData: String! = kSecValueData as String
    private let secAttrAccessible: String! = kSecAttrAccessible as String
    private let secClass: String! = kSecClass as String
    private let secAttrService: String! = kSecAttrService as String
    private let secAttrGeneric: String! = kSecAttrGeneric as String
    private let secAttrAccount: String! = kSecAttrAccount as String
    private let secAttrAccessGroup: String! = kSecAttrAccessGroup as String
    private let secAuthContext:String! = kSecUseAuthenticationContext as String
    private let secAccess:String! = kSecAttrAccessControl as String
    

    var serviceName = ""
    var accessGroup: String?
    
    // MARK: Singleton
    static let sharedInstance = KeychainWrapper()
    
    private init() {
        self.serviceName = Bundle.main.bundleIdentifier ?? "DeliveryApp"
    }

    
    // MARK: Private Helper
    
    /**
        Setup the query dictionary for accessing the keychain
    
            - Parameter keyName: the key name string to be queried
            - Returns: the query dictionary for the key name

    */
    private func setupQueryDictionaryForKey(_ keyName: String) -> [String : AnyObject] {
        

        /*  The query dictionary for accessing the keychain.
            It specifies that we are using a generic password
            rather than a certificate, internet password, and etc
        */
        var queryDictionary: [String : AnyObject] = [secClass: kSecClassGenericPassword]
        
        // Uniquely identify this keychain accessor
        queryDictionary[secAttrService] = self.serviceName as AnyObject?
        
        // Set the keychain access group if defined
        if let accessGroup = self.accessGroup {
            queryDictionary[secAttrAccessGroup] = accessGroup as AnyObject?
        }
        
        // Uniquely identify the account who will be accessing the keychain
        let encodedIdentifier: Data? = keyName.data(using: String.Encoding.utf8)
        queryDictionary[secAttrGeneric] = encodedIdentifier as AnyObject?
        queryDictionary[secAttrAccount] = encodedIdentifier as AnyObject?
        
        
        return queryDictionary
    }
    
    // MARK: Getters

    
    /**
        Query the data associated with the specified key name
    
            - Parameter keyName: the key name string to be queried
            - Throws: KeychainError if the query fails
            - Returns: an NSData object associated with the specified key name
    */
    func dataForKey(_ keyName: String) throws -> Data? {
        var queryDictionary = self.setupQueryDictionaryForKey(keyName)
        var result: CFTypeRef?
        
        // Limit search results to one
        queryDictionary[secMatchLimit] = kSecMatchLimitOne
        
        // Specify we want NSData/CFData returned
        queryDictionary[secReturnData] = kCFBooleanTrue

        // Search
        let status: OSStatus = withUnsafeMutablePointer(to: &result) {
            SecItemCopyMatching(queryDictionary as CFDictionary, UnsafeMutablePointer($0))
        }
        print(status)
//        if let error = KeychainError.keychainErrorForOSStatus(status) {
//            throw error
//        }
        
        return result as? Data
    }
    
    /**
        Query the string object associated with the specified key name
     
            - Parameter keyName: the key name string to be queried
            - Throws: KeychainError if the query fails
            - Returns: an NSData object associated with the specified key name
    */
    func stringForKey(_ keyName: String) throws -> String? {
        var result: String?
        do {
            let keychainData = try self.dataForKey(keyName)
            if keychainData != nil {
                result = String(data: keychainData!, encoding: String.Encoding.utf8) as String?
            }
            
        }
        catch let error {
            throw error
        }
        return result
    }
    

    /**
        Check if there is anything associated the specified key name
     
            - Parameter keyName: the key name string to be checked
            - Return: true if successful; false if failed

    */
    func hasValueForKey(_ keyName: String) -> Bool {
        if let _ = try? self.dataForKey(keyName) {
            return true
        } else {
            return false
        }
    }
    
    // MARK: Setters
    
    
    /**
        Update the data associated with the specified key in the Keychain
    
            - Parameters:
    
                - value: the NSData object to be associated with the specified key
                - keyName: the key name string to be updated
    
            - Throws: KeychainError if update fails
    
            - Return: none
    */
    func updateData(_ value: Data, forKey keyName: String) throws {
        let queryDictionary: [String:AnyObject] = self.setupQueryDictionaryForKey(keyName)
        let updateDictionary = [secValueData : value]
        
        // Update
        let status: OSStatus = SecItemUpdate(queryDictionary as CFDictionary, updateDictionary as CFDictionary)
        
//        if let error = KeychainError.keychainErrorForOSStatus(status) {
//            throw error
//        }
    }

    /**
        Set an NSData object to be associated with the specified key in the Keychain.
        If the key existed already, it will try to update the key with the NSData object.
     
            - Parameters:
     
                - value: the NSData object to be associated with the specified key
                - keyName: the key name string to be set
     
            - Throws: KeychainError if failed
     
            - Return: none
    */
    func setData(_ value: Data, forKey keyName: String) throws {
        var queryDictionary: [String:AnyObject] = self.setupQueryDictionaryForKey(keyName)
        
        let access = SecAccessControlCreateWithFlags(nil, // Use the default allocator.
            kSecAttrAccessibleAlways,
            .biometryAny,
            nil)
        
        queryDictionary[secValueData] = value as AnyObject?
        queryDictionary[secAccess] = access as AnyObject
        
        let status: OSStatus = SecItemAdd(queryDictionary as CFDictionary, nil)
        
        if let error = KeychainError.keychainErrorForOSStatus(status) {
            if error == .dupItemErr {
                do {
                    try self.updateData(value, forKey: keyName)
                }
                catch let updateError {
                    throw updateError
                }
            }
            else {
                throw error
            }
        }
    }
    
    
    /**
        Set a string object to be associated with the specified key in the Keychain.
        If the key existed already, it will try to update the key with the string object.
     
        - Parameters:
     
            - value: the string object to be associated with the specified key
            - keyName: the key name string to be set
     
            - Throws: KeychainError if failed
     
            - Return: none
    */
    func setString(_ value: String, forKey keyName: String) throws {
        if let data = value.data(using: String.Encoding.utf8) {
            do {
                try self.setData(data, forKey: keyName)
            }
            catch let error {
                throw error
            }
        }
    }
    
    /**
        Removed everything associated with the specified key in the Keychain
     
            - Parameter keyName: the key name string
     
            - Throws: KeychainError if failed
     
            - Returns: none
    */
    func removeObjectForKey(_ keyName: String) throws {
        let queryDictionary: [String:AnyObject] = self.setupQueryDictionaryForKey(keyName)
        

        let status: OSStatus =  SecItemDelete(queryDictionary as CFDictionary);
        
//        if let error = KeychainError.keychainErrorForOSStatus(status) {
//            throw error
//        }
    }

    
    /**
        Removed everything associated with the keychain wrapper service name
        which is the bundle identifier of the App by default
     
            - Throws: KeychainError if failed
            - Returns: None
    */
    func removeAllKeys() throws {
        var queryDictionary: [String : AnyObject] = [secClass : kSecClassGenericPassword]
        
        // Uniquely identify this keychain accessor
        queryDictionary[secAttrService] = self.serviceName as AnyObject?
        
        // Set the keychain access group if defined
        if let accessGroup = self.accessGroup {
            queryDictionary[secAttrAccessGroup] = accessGroup as AnyObject?
        }
        
        let status: OSStatus = SecItemDelete(queryDictionary as CFDictionary)
        
//        if let error = KeychainError.keychainErrorForOSStatus(status) {
//            throw error
//        }
    }

}
