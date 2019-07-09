/*
//
//  Authenticator.swift
//  ECommerce
//
//  Created by Liangzan Chen on 4/12/16.
//  Copyright © 2016 Albertsons. All rights reserved.
//

import Foundation
import ObjectMapper


let OktaRefreshErrorCode = "400"

enum UserType: String {
    case Guest = "g"
    case RegisteredUser = "rn"
    case RegisteredUserOrdered = "re"
}

/// The singleton for authentication
class Authenticator: ServiceProgressDelegate {
    
    // MARK: Properties

    /// indicating if there is an authentication in progress
    var isInProgress: Bool = false
    
    /// The AuthNewTokenProvider object is for sign-in or token renewal
    //var tokenProvider: AuthNewTokenProvider?
    var tokenProvider: ServiceProvider?         //declared the provider as base class to set OktaAuthNewTokenProvider or AuthNewTokenProvider based on the Okta flag.
    
    
    /// The UserProfileProvider object is for getting the profile for the user to sign in
    var userProfileProvider: UserProfileProvider?
        
    /// The array holds all the AuthenticatorDelegate objects that require callback about the authentication progress
    var delegates = [AuthenticatorDelegate]()
    
    /// The User object holds the information for the user if sign-in is successful
    private var user: User?
    
    
    /// The dictionary holds temporay information for the user in sign-in or token renewal progress
    private var userDict = [String : String]()
    
    /// The stack for pushing and popping the current action
    /// which will be used for Crittercism logging purpose
    private var actionStack = Stack<String>()
    
    var isSignedIn: Bool {
        get {
            if let _ =  Authenticator.sharedInstance.signedInUser() {
                return true
            }
            return false
        }
    }
    
    // MARK: Singleton
    static let sharedInstance = Authenticator()
    
    private init() {
        let defaults = UserDefaults.standard
        
        if let savedData = defaults.object(forKey: User.PropertyKey.signedInUserKey) as? Data,
            let savedUser = NSKeyedUnarchiver.unarchiveObject(with: savedData) as? User {
            self.user = savedUser
        }
        
        if let userId = self.getUserIdFromKeychain() {
            self.userDict[User.PropertyKey.userIdKey] = userId
            
            if let password = self.getPasswordFromKeychain(userId) {
                self.userDict[User.PropertyKey.passwordKey] = password
            }
        }
    }
    
    
    // MARK: Getter
    func signedInUser() -> User? {
        objc_sync_enter(self)
        
        defer {
            objc_sync_exit(self)
        }
        
        if let user = self.user {
            
            return user
        }
        else {
            let defaults = UserDefaults.standard
            
            if let savedData = defaults.object(forKey: User.PropertyKey.signedInUserKey) as? Data,
                let savedUser = NSKeyedUnarchiver.unarchiveObject(with: savedData) as? User {
                self.user = savedUser
                
            } else {
                
                UserPreference.setUserType(.Guest)
            }
            
            return self.user
        }
    }
    
    
    func getUserId() -> String?{
        if let userId = self.userDict[User.PropertyKey.userIdKey] {
            return userId
        }
        else {
            return self.getUserIdFromKeychain()
        }
    }
    
    // MARK: Saver
    func saveUser() {
        if let user = self.user {
            let savedData = NSKeyedArchiver.archivedData(withRootObject: user)
            let defaults = UserDefaults.standard
            defaults.set(savedData, forKey: User.PropertyKey.signedInUserKey)
            defaults.synchronize()
            
        }
    }
    
    
    func cleanup() {
        UserPreference().cleanAll()
        SharedCookies().deleteAll()
        // Authenticator.sharedInstance.cleanLastAuthTime()
        CartItem.itemCount = 0
        CartItem.shared?.refreshItemBadge()
        LocalDataManager().operationsOnSignOut()
    }
    
    // MARK: Sign Out
    func signOut() {
        (UIApplication.shared.delegate as? AppDelegate)?.guestSignInCompletionHandler = nil
        objc_sync_enter(self)
        
        defer {
            objc_sync_exit(self)
        }
        
        let action = UserActionEnum.SignOut.rawValue
        self.actionStack.push(action)
        AppLog.sharedInstance.beginUserflow(action)
        
        self.user = nil
        self.userDict = [String : String]()
        
        let defaults = UserDefaults.standard
        defaults.removeObject(forKey: User.PropertyKey.signedInUserKey)
        
        self.cleanup()
        do {
            try KeychainWrapper.sharedInstance.removeAllKeys()
        }
        catch let error {
            AppLog.sharedInstance.logError(error)
        }
        
        if(self.isInProgress) {
            for delegate in self.delegates {
                delegate.cancelled(self)
            }
            
            self.delegates.removeAll()
            self.isInProgress = false
        }
        
        if let action = self.actionStack.pop(){
            AppLog.sharedInstance.endUserflow(action)
        }
        //Setting the user type back to guest on signOut routine
        UserPreference.setUserType(.Guest)
        ErumsCartProvider.cartId = UserPreference.getGuestCartId()
    }
    

    // MARK: Authentication
    
    func validateToken(_ callbackDelegate: AuthenticatorDelegate) {
        
        objc_sync_enter(self)
        
        defer {
            objc_sync_exit(self)
        }
        
        if let token = self.user?.accessToken {
            if OktaUtility.isOktaTokenExpired(jwtToken: token) {
                //print("20180413 - Token expired")
                if !self.isInProgress {
                    if let refreshToken = self.user?.refreshToken {
                        //print("20180413 - Token expired - refresh token available")
                        self.delegates.append(callbackDelegate)
                        self.tokenProvider = OktaRefreshTokenProvider(refreshToken: refreshToken)  //TODO - replace this with refresh token
                        if let tokenProvider = self.tokenProvider {
                            //print("20180413 - Token expired - In refresh token provider")
                            //tell Crittercism what the user action is
                            let action = UserActionEnum.GetToken.rawValue
                            self.actionStack.push(action)
                            AppLog.sharedInstance.beginUserflow(action)
                            
                            tokenProvider.delegate = self
                            tokenProvider.run()
                            self.isInProgress = true
                        }
                        
                    }
                    else {
                        //print("20180413 - Token expired - refresh token ***NOT*** available")
                        let error = NSError(domain: ErrorDomain.Authentication, code: AuthenticationErrorCode.noUserProfile.rawValue, userInfo: nil)
                        callbackDelegate.failedWithError(self, error: error, service: self.tokenProvider)
                    }
                }
                else {
                    self.delegates.append(callbackDelegate)
                }
            }
            else {
                callbackDelegate.validatedTokenSuccessfully(self)
            }
        }  else { //okta not signed in yet
            if !self.isInProgress {
                if let userId = self.getUserIdFromKeychain(), let password = self.getPasswordFromKeychain(userId) {
                    self.tokenProvider = OktaAuthNProvider(userId: userId, password: password)
                    if let tokenProvider = self.tokenProvider {
                        //tell Crittercism what the user action is
                        let action = UserActionEnum.GetToken.rawValue
                        self.actionStack.push(action)
                        AppLog.sharedInstance.beginUserflow(action)
                        
                        tokenProvider.delegate = self
                        tokenProvider.run()
                        self.isInProgress = true
                    }
                }
            }
        }
    }
    
    func signIn(_ userId: String, password: String, callbackDelegate: AuthenticatorDelegate) {
        objc_sync_enter(self)
        
        defer {
            objc_sync_exit(self)
        }
        
        self.delegates.append(callbackDelegate)
        
        if !self.isInProgress {
            self.userDict[User.PropertyKey.userIdKey] = userId
            self.userDict[User.PropertyKey.passwordKey] = password
            
            //okta implementation
            //self.tokenProvider = AuthNewTokenProvider(userId: userId, password: password)
            self.tokenProvider = OktaAuthNProvider(userId: userId, password: password)
            if let tokenProvider = self.tokenProvider {
                //tell Crittercism what the user action is
                let action = UserActionEnum.GetToken.rawValue
                self.actionStack.push(action)
                AppLog.sharedInstance.beginUserflow(action)
                
                tokenProvider.delegate = self
                tokenProvider.run()
                self.isInProgress = true
            }
        }
    }
    
    // MARK: Keychain access
    
    func getUserIdFromKeychain() -> String?{
        var userId: String?
        
        do {
            userId = try KeychainWrapper.sharedInstance.stringForKey(User.PropertyKey.userIdKey)
        }
        catch let error {
            AppLog.sharedInstance.logError(error)
        }
        
        return userId
    }
    
    func getPasswordFromKeychain(_ userId: String) -> String? {
        var password: String?
        
        do {
            password = try KeychainWrapper.sharedInstance.stringForKey(userId)
        }
        catch let error {
            AppLog.sharedInstance.logError(error)
        }
        return password
    }
    
    func saveUserInfoToKeychain(_ userId: String, password: String) -> Bool {
        do {
            try KeychainWrapper.sharedInstance.setString(userId, forKey: User.PropertyKey.userIdKey)
            try KeychainWrapper.sharedInstance.setString(password, forKey: userId)
        }
        catch let error {
            AppLog.sharedInstance.logError(error)
            return false
        }
        
        return true
    }
    
    // MARK: ServiceProgressDelegate
    
    func serviceDidStart(_ service:ServiceProvider) {
        
    }
    
    
    func serviceDidFinishWithResponse(_ service:ServiceProvider, results:Any) {
        
        if (service is OktaAuthNProvider){
            if let dict = results as? [String: Any], let status = dict["status"] as? String, status == "PASSWORD_EXPIRED" {
                handleExpiredPasswordFlow()
            } else {
                handleOktaNewSignInFlow(results)
            }
        }
        else if (service is OktaRefreshTokenProvider) || (service is OktaAuthNewTokenProvider){
            handleOktaRefreshTokenFlow(results)
        }
        AppLog.sharedInstance.setCustomerData()
    }
    
    func serviceDidFail(_ service:ServiceProvider, error:Error) {
        
        if let action = self.actionStack.pop() {
            AppLog.sharedInstance.failUserflow(action)
            AppLog.sharedInstance.logError(error)
        }
        
        if let error = error as? ServiceError {
            AppLog.sharedInstance.logError(error)
            switch error {
            case ServiceError.oktaRefreshServiceProblem:
                showOktaRefreshError(error.info(), provider: service)
                return
            default:
                break
            }
        }
        
        for delegate in self.delegates {
            delegate.failedWithError(self, error: error as NSError, service: service)
        }
        
        self.delegates.removeAll()
        self.isInProgress = false;
        
    }

    private func showOktaRefreshError( _ info: [String : Any], provider: ServiceProvider) {
        if let title = info[key_title] as? String, let message = info[key_message] as? String {
            if let appDelegate = UIApplication.shared.delegate as? AppDelegate {
                appDelegate.handleLogoutWithOktaRefreshError(errorTitle: title, errorMessage: message, provider: provider)
            }
        }
    }
    
    private func handleJITMigrationFlow(_ results: Any){
        
        //This will happen when okta flag is true, OktaJit flag is true and response for IAAW is success after the JIT migration.
        //At this point the app needs to call the token endpoint to get the access token, refresh token etc.
        
        if let dict = results as? [String: Any], let _ = dict["token"] as? String, let oktaMigrationSuccessful = dict["oktaMigrationSuccessful"] as? Bool {
            if(oktaMigrationSuccessful) {
                if let userId = self.userDict[User.PropertyKey.userIdKey], let password = self.userDict[User.PropertyKey.passwordKey] {
                    self.tokenProvider = OktaAuthNewTokenProvider(userId: userId, password: password)
                    if let tokenProvider = self.tokenProvider{
                        //tell Crittercism what the user action is
                        let action = UserActionEnum.GetToken.rawValue
                        self.actionStack.push(action)
                        //CrittercismWrapper.sharedInstance.beginUserflow(action)
                        tokenProvider.delegate = self
                        tokenProvider.run()
                        self.isInProgress = true
                        
                    }
                }
            } else {
                //migration is not success
                handleUnknownErrorFlow()
            }
        }
    }
    
    private func handleOktaNewSignInFlow(_ results: Any){
            //This will happen when the Okta authn service is success and JIT migration is completed
            if let userId = self.userDict[User.PropertyKey.userIdKey], let password = self.userDict[User.PropertyKey.passwordKey] {
                self.tokenProvider = OktaAuthNewTokenProvider(userId: userId, password: password)
                if let tokenProvider = self.tokenProvider {
                    //tell Crittercism what the user action is
                    let action = UserActionEnum.GetToken.rawValue
                    self.actionStack.push(action)
                    tokenProvider.delegate = self
                    tokenProvider.run()
                    self.isInProgress = true
                }
            } else {
                //Wil happen if userId or password is nil
                handleUnknownErrorFlow()
            }
        }
    
    private func handleOktaRefreshTokenFlow(_ results:Any){
        //this case will happen when okta token end point is called and it is success
        
        if let action = self.actionStack.pop()  {
        //CrittercismWrapper.sharedInstance.endUserflow(action)
        AppLog.sharedInstance.endUserflow(action)
        }
        
        if let dict = results as? [String: Any], let token = dict["access_token"] as? String, let refrshToken = dict["refresh_token"] as? String {
            let tmpUser = OktaUtility.getUserProfileFromOktaToken(jwtToken: token, refreshToken: refrshToken)
            
            if let user = self.user{
                user.accessToken = tmpUser.accessToken
                user.refreshToken = tmpUser.refreshToken
                user.firstName = tmpUser.firstName
                user.lastName = tmpUser.lastName
                user.guid = tmpUser.guid
                user.hhid = tmpUser.hhid
                user.phoneNumber = tmpUser.phoneNumber
                user.coremaClubCard = tmpUser.coremaClubCard
                user.zipCode = tmpUser.zipCode
                user.storeId = tmpUser.storeId
                user.lastUpdateTime = Date()
                user.userId = tmpUser.userId
            }
                
            else {
                self.user = tmpUser
            }
            
        saveCriticalInfo()
            
        for delegate in self.delegates {
            delegate.signedInSuccessfully(self)
            delegate.validatedTokenSuccessfully(self)
            }
            self.delegates.removeAll()
            self.isInProgress = false;
        }
    }
    
    private func handleIAWFlow(_ results:Any){
        //IAAW flow
        if let action = self.actionStack.pop()  {
            AppLog.sharedInstance.endUserflow(action)
        }
        
        if let dict = results as? [String: Any], let token = dict["token"] as? String, let userProfile = dict["userAccount"] as? [String: Any] {
            
            let userProfileObject = Mapper<UserProfile>().map(JSON: userProfile)
            //creates the user object from the userProfileObject using the tokens provided.
            self.user = userProfileObject?.getUser(token: token, accessToken: self.user?.accessToken, refreshtoken: self.user?.refreshToken)
            
            saveCriticalInfo()
            
            for delegate in self.delegates {
                delegate.signedInSuccessfully(self)
                delegate.validatedTokenSuccessfully(self)
            }
            self.delegates.removeAll()
            self.isInProgress = false;
        }
    }
    
    private func handleExpiredPasswordFlow(){
        
        if let action = self.actionStack.pop()  {
            //CrittercismWrapper.sharedInstance.endUserflow(action)
            AppLog.sharedInstance.endUserflow(action)
        }
        
        self.isInProgress = false
        
        for delegate in self.delegates {
            delegate.passwordExpired()
        }
    }
    private func handleUnknownErrorFlow(){
        
        var infoDictionary = [String : String]()
        let authError: AuthenticationError = AuthenticationErrors.errors[AuthenticationErrors.errors.count - 1]
        var code: AuthenticationErrorCode = AuthenticationErrorCode.unauthorized
        infoDictionary["codeString"] = authError.errorCode
        infoDictionary[NSLocalizedDescriptionKey] = authError.errorMessage
        code = authError.errorType
        
        let error =  NSError(domain: ErrorDomain.Authentication, code: code.rawValue, userInfo:infoDictionary)
        
        
        if let action = self.actionStack.pop() {
            AppLog.sharedInstance.failUserflow(action)
            AppLog.sharedInstance.logError(error)
        }
        
        for delegate in self.delegates {
            delegate.failedWithError(self, error: error as NSError, service: self.tokenProvider)
        }

        self.delegates.removeAll()
        self.isInProgress = false;
    }
    
    private func saveCriticalInfo(){
        DispatchQueue.main.async { //save critical information from the main thread
            self.saveUser()
            let keychainUserId = self.getUserIdFromKeychain()
            if keychainUserId == nil, let userKey = self.userDict[User.PropertyKey.userIdKey], let passwordKey = self.userDict[User.PropertyKey.passwordKey] { //newly signed in user
                _ = self.saveUserInfoToKeychain(userKey, password: passwordKey)
            }
        }
    }
}
*/
