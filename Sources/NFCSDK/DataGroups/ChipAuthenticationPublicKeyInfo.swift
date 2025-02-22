//
//  ChipAuthenticationPublicKeyInfo.swift
//  NFCSDK
//
//  Created by OCR Labs on 25/02/2021.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public class ChipAuthenticationPublicKeyInfo : SecurityInfo {
    var oid : String
    var pubKey : OpaquePointer
    var keyId : Int?
    
    
    static func checkRequiredIdentifier(_ oid : String) -> Bool {
        return ID_PK_DH_OID == oid
            || ID_PK_ECDH_OID == oid
    }
    
    init(oid:String, pubKey:OpaquePointer, keyId: Int? = nil) {
        self.oid = oid
        self.pubKey = pubKey
        self.keyId = keyId
    }
    
    public override func getObjectIdentifier() -> String {
        return oid
    }
    
    public override func getProtocolOIDString() -> String {
        return ChipAuthenticationPublicKeyInfo.toProtocolOIDString(oid:oid)
    }

    public func getKeyId() -> Int {
        return keyId ?? 0
    }
    

    private static func toProtocolOIDString(oid : String) -> String {
        if ID_PK_DH_OID == oid {
            return "id-PK-DH"
        }
        if ID_PK_ECDH_OID == oid {
            return "id-PK-ECDH"
        }
        
        return oid
    }

}
