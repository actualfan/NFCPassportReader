//
//  COM.swift
//
//  Created by OCR Labs on 01/02/2021.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public class COM : DataGroup {
    public private(set) var version : String = "Unknown"
    public private(set) var unicodeVersion : String = "Unknown"
    public private(set) var dataGroupsPresent : [String] = []
    
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
        datagroupType = .COM
    }
    
    override func parse(_ data: [UInt8]) throws {
        var tag = try getNextTag()
        if tag != 0x5F01 {
            throw NFCSDKError.InvalidResponse
        }
        
        var versionBytes = try getNextValue()
        if versionBytes.count == 4 {
            let aa = Int( String(cString: Array(versionBytes[0..<2] + [0]) )) ?? -1
            let bb = Int( String(cString: Array(versionBytes[2...] + [0])) ) ?? -1
            if aa != -1 && bb != -1 {
                version = "\(aa).\(bb)"
            }
        }
        tag = try getNextTag()
        if tag != 0x5F36 {
            throw NFCSDKError.InvalidResponse
        }
        
        versionBytes = try getNextValue()
        if versionBytes.count == 6 {
            let aa = Int( String(cString: Array(versionBytes[0..<2] + [0])) ) ?? -1
            let bb = Int( String(cString: Array(versionBytes[2..<4] + [0])) ) ?? -1
            let cc = Int( String(cString: Array(versionBytes[4...]) + [0]) ) ?? -1
            if aa != -1 && bb != -1 && cc != -1 {
                unicodeVersion = "\(aa).\(bb).\(cc)"
            }
        }
        
        tag = try getNextTag()
        if tag != 0x5C {
            throw NFCSDKError.InvalidResponse
        }
        
        let vals = try getNextValue()
        for v in vals {
            if let index = DataGroupParser.tags.firstIndex(of: v) {
                dataGroupsPresent.append( DataGroupParser.dataGroupNames[index] )
            }
        }
        Log.info( "DG Found - \(dataGroupsPresent)" )
    }
}
