//
//  File.swift
//  
//
//  Created by Sebastian Rank on 02.01.24.
//

import Foundation

public protocol SecNtfyDelegate: AnyObject {
    func messaging(didReceiveRegistrationToken devToken: String?)
}