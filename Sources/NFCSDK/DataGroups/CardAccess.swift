//
//  CardAccess.swift
//  NFCSDK
//
//  Created by OCR Labs on 03/03/2021.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public class CardAccess {
    private var asn1 : ASN1Item!
    public private(set) var securityInfos : [SecurityInfo] = [SecurityInfo]()
    
    var paceInfo : PACEInfo? {
        get {
            return (securityInfos.filter { ($0 as? PACEInfo) != nil }).first as? PACEInfo
        }
    }
    
    required init( _ data : [UInt8] ) throws {
        let p = SimpleASN1DumpParser()
        asn1 = try p.parse(data: Data(data))
        
        for i in 0 ..< asn1.getNumberOfChildren() {
            if let child = asn1.getChild(i),
               let secInfo = SecurityInfo.getInstance( object:child, body : data ) {
                securityInfos.append(secInfo)
            }
        }
    }
}
