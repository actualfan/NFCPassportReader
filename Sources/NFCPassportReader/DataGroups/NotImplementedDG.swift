//
//  NotImplementedDG.swift
//
//  Created by OCR Labs on 01/02/2021.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public class NotImplementedDG : DataGroup {
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
        datagroupType = .Unknown
    }
}

