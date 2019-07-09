/*
//
//  ProtectedProtocol.swift
//  ECommerce
//
//  Created by Ganesh Reddiar on 2/22/17.
//  Copyright © 2017 Albertsons. All rights reserved.
//

import Foundation
import LocalAuthentication

/** Closure to encompass logic of auth with the number of tries
Int:Number of attempts made to enter password,
String: Input authentication key (entered by user)
**/
typealias AttemptReAuthWithKey = ((Int,String) -> Bool)

// Interface to be implemented by view controller that needs password or may not need password but is protected
protocol ProtectedProtocol {
    
    func needsPassword() -> Bool
    func showProtectedView()
}

//Default implementation of the Protected Protocol
extension ProtectedProtocol {
    
    //Function that indicates if the user needs to reinter password or not
    func needsPassword() -> Bool {
       return ReAuthenticator.instance.shouldReAuthenticate()
    }
    
    /**Function to Display the Password Flow . Appends the logic of what happens if the authentication failed.
     
    ```
     Business logic
     If Successfully ReAuthenticated , continue with the flow 
     if Failed Authentication, give user chances(attempts defined in reauthenticator)
     if fails Authentication passes Max Allowed Retries , throw them to Sign in screen after logging them out
     ```
     
    -Parameters onView: View where password view needs to be shown
    -Parameters @escaping ()->(): Closure to execute when the pasword has been successfully reauthenticated. This should not capture the failed scenarios
    **/

    func showPassword(onView:UIView, reAuthenticated:@escaping ()->()) {
        var reAuthView : UIView?
        reAuthView = ReAuthView(showInView: onView)
        if let reAuthView = reAuthView, !UserPreference().isBiometricSettingOff(){
            let password = Authenticator.sharedInstance.getPasswordFromKeychain(Authenticator.sharedInstance.getUserIdFromKeychain() ?? " ")
            
        }
        let reAuthenticator = ReAuthenticator.instance
        let matchWithKey:AttemptReAuthWithKey = { (attemptCount, key) in
            if reAuthenticator.doesMatch(key) {
                ApptentiveEvents.instance.trackPasswordUnlock()
                reAuthenticator.updateLastAuthTime()
                reAuthView?.removeFromSuperview()
                reAuthenticated()
                return true
            }
            if reAuthenticator.isLast(attempt: attemptCount) {
                self.allReAuthAttemptsFailed()
                reAuthView?.removeFromSuperview()
                return true
            }
            return false
        }
        (reAuthView as? ReAuthView)?.match = matchWithKey
    }
    
   /**
    Did All Auth Attempts failed
    **/
    func allReAuthAttemptsFailed() {
        Authenticator.sharedInstance.signOut()
        (UIApplication.shared.delegate as? AppDelegate)?.showSignIn()
    }
    /**
     @method: authenticateUserUsingTouchId : Method that call the
     @params: productId:String
     @return:
     */
//    func authenticateUserUsingTouchId(reAuthenticated:@escaping ()->(), reAuthView: UIView) {
//        let context = LAContext()
//        var error: NSError?
//        var reasonString = ""
//        if context.canEvaluatePolicy(LAPolicy.deviceOwnerAuthenticationWithBiometrics, error: &error) {
//            if #available(iOS 11.0, *) {
//
//                reasonString =  context.biometryType == .touchID ? confirmFingerPrint: confirmFacePrint
//            } else {
//                reasonString = confirmFingerPrint
//            }
//            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reasonString, reply: {
//                (success: Bool, evalPolicyError: Error?) -> Void in
//
//                if success {
//                    ApptentiveEvents.instance.trackBiometricsUnlock()
//                    OperationQueue.main.addOperation({
//                        let reAuthenticator = ReAuthenticator.instance
//                        reAuthenticator.updateLastAuthTime()
//                        reAuthView.removeFromSuperview()
//                        reAuthenticated()
//                    })
//                }
//            })
//        }
//    }
}

extension LAContext {
    
    enum BiometricType: String {
        case none = "Unavailable"
        case touchID = "Touch ID"
        case faceID = "Face ID"
    }
    
    var biometricType: BiometricType {
        var error: NSError?
        
        guard self.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return .none
        }
        
        if #available(iOS 11.0, *) {
            switch self.biometryType {
            case .none:
                return .none
            case .touchID:
                return .touchID
            case .faceID:
                return .faceID
            }
        } else {
            return  self.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) ? .touchID : .none
        }
    }
}

*/
