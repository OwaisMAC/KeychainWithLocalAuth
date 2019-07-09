//
//  ViewController.swift
//  KeycainWithLA
//
//  Created by Owais Munawar on 3/28/19.
//  Copyright © 2019 The Dev. All rights reserved.
//

import UIKit

class ViewController: UIViewController {
    
    let keyString = "key5"
    let valueString = "value5"
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
    }
    
    @IBAction func addKeychainValue(_ sender: Any) {
        do{
            try KeychainWrapper.sharedInstance.setString(valueString, forKey: keyString)
        }
        catch{ }
        
    }
    
    
    @IBAction func readKeychainValue(_ sender: Any) {
        let hasValue2 = KeychainWrapper.sharedInstance.hasValueForKey(keyString)
        if hasValue2{
            do{
                let value = try KeychainWrapper.sharedInstance.stringForKey(keyString)
                print("Value is: \(value)")
            }
            catch let error{
                print("Error is: \(error)")
            }
        }
    }
    

}



