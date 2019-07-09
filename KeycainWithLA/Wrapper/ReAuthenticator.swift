/*
//
//  ReAuthenticator.swift
//  ECommerce
//  ReAuthenticator holds the logic for when to reauthenticate and if required take ths steps to ensure that the user's personal info is protected
//  Created by Ganesh Reddiar on 2/22/17.
//  Copyright © 2017 Albertsons. All rights reserved.
//

import Foundation

class ReAuthenticator {
    
    static var instance = ReAuthenticator()
    
    //Last Time when the password was authenticated
    private var lastAuthenticatedTime:CFTimeInterval?
    
    //Configurable Session Time Out
    private static let kSessionTimeOut = 30 * 60 // In secs
    
    //Configurabe Number of Attempts Allowed
    private static let kAllowedAttempts = 5
    
    /**
    Checks if the session has timed out. Relies on absolute time rather than the device time zone. We use CACurrentMediaTime here
    - Returns: Bool Indicates if we need to reauthenticate.
    **/
    func shouldReAuthenticate() -> Bool {
        
        if let lastAuthTime = lastAuthenticatedTime {
            if (CACurrentMediaTime() - lastAuthTime) < (Double(ReAuthenticator.kSessionTimeOut)) {
                return false
            }
        }
        return true
    }
    
    /**
    Checks if the input key matches with the keychain password. 
    - Paremeter password: Input key
    - Returns: Bool if password matches with keychain
    **/
    func doesMatch(_ password:String) -> Bool {
        
        let authenticator = Authenticator.sharedInstance
        if let userId = authenticator.getUserIdFromKeychain(), let keychainPwd = authenticator.getPasswordFromKeychain(userId),  keychainPwd == password {
            return true
        }
        return false
    }
    
    /**
     Function to update the last auth time. Auth time is only in memory
     Current Business logic is to update when
     - User logs in 
     - User Reverifies password in Orders 
     - User Reverifies password in Delivery Info
    **/
    func updateLastAuthTime() {
        lastAuthenticatedTime = CACurrentMediaTime()
    }
    
    /**
     Function to clear the last auth time
     Auth time is only in memory
     Currently cleaned when :
     - User Logs out
    **/
    func cleanLastAuthTime() {
        lastAuthenticatedTime = nil
    }
    
    /**
     Function to check if the number of attempts has reached its threshold of maximum allowed attempts 
     - Parameter: attempt , number of times that user has tried
     - Returns: Bool , is Last Try
    **/
    func isLast(attempt:Int) -> Bool {
        return attempt > ReAuthenticator.kAllowedAttempts
    }
    
    /**
     Function to popToRoot View of Protected View Controller
     Needs to be called if the app moves to foreground or background
    **/
    func popToProtectedViewController() {
        
        if shouldReAuthenticate() { //check if session timed out
            
            var protectedViewController:UIViewController?
            
            let visibleView = UniversalActionController.shared.visibleView()
            
            if let navController = visibleView?.navigationController {
                for viewController in navController.viewControllers {
                    if viewController is ProtectedProtocol {
                        protectedViewController = viewController
                    }
                }
            }
            
            if visibleView is ProtectedProtocol {
                protectedViewController = visibleView
            }
        protectedViewController?.navigationController?.popToRootViewController(animated: false)
            let tabController = UIApplication.shared.delegate?.window??.rootViewController as? UITabBarController
            tabController?.selectedIndex = 0
          
        }
        
    }

}
*/
