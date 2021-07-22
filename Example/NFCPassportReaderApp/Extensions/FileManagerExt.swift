//
//  FileManagerExt.swift
//  NFCPassportReaderApp
//
//  Created by OCR Labs on 17/02/2021.
//  Copyright © 2021 OCR Labs. All rights reserved.
//

import SwiftUI

extension FileManager {
    static var cachesFolder : URL {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
    }
}

