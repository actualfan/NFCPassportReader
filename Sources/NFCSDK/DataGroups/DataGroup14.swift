//
//  DataGroup14.swift
//
//  Created by OCR Labs on 01/02/2021.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public class DataGroup14 : DataGroup {
    private var asn1 : ASN1Item!
    public private(set) var securityInfos : [SecurityInfo] = [SecurityInfo]()
    
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
        datagroupType = .DG14
    }
    
    override func parse(_ data: [UInt8]) throws {
        let p = SimpleASN1DumpParser()
        asn1 = try p.parse(data: Data(body))
        
        for i in 0 ..< asn1.getNumberOfChildren() {
            if let child = asn1.getChild(i),
               let secInfo = SecurityInfo.getInstance( object:child, body : body ) {
                securityInfos.append(secInfo)
            }
        }
    }
}
