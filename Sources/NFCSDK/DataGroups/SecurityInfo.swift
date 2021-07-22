//
//  SecurityInfo.swift
//  NFCSDK
//
//  Created by OCR Labs on 25/02/2021.
//

import Foundation
import OpenSSL

@available(iOS 13, macOS 10.15,*)
public class SecurityInfo {
    static let ID_AA_OID = "2.23.136.1.1.5"
    
    static let ID_PK_DH_OID = "0.4.0.127.0.7.2.2.1.1"
    static let ID_PK_ECDH_OID = "0.4.0.127.0.7.2.2.1.2"
    
    static let ID_CA_DH_3DES_CBC_CBC_OID = "0.4.0.127.0.7.2.2.3.1.1"
    static let ID_CA_ECDH_3DES_CBC_CBC_OID = "0.4.0.127.0.7.2.2.3.2.1"
    static let ID_CA_DH_AES_CBC_CMAC_128_OID = "0.4.0.127.0.7.2.2.3.1.2"
    static let ID_CA_DH_AES_CBC_CMAC_192_OID = "0.4.0.127.0.7.2.2.3.1.3"
    static let ID_CA_DH_AES_CBC_CMAC_256_OID = "0.4.0.127.0.7.2.2.3.1.4"
    static let ID_CA_ECDH_AES_CBC_CMAC_128_OID = "0.4.0.127.0.7.2.2.3.2.2"
    static let ID_CA_ECDH_AES_CBC_CMAC_192_OID = "0.4.0.127.0.7.2.2.3.2.3"
    static let ID_CA_ECDH_AES_CBC_CMAC_256_OID = "0.4.0.127.0.7.2.2.3.2.4"
    

    static let ID_BSI = "0.4.0.127.0.7"
    static let ID_PACE = ID_BSI + ".2.2.4"
    static let ID_PACE_DH_GM = ID_PACE + ".1"
    static let ID_PACE_DH_GM_3DES_CBC_CBC = ID_PACE_DH_GM + ".1";
    static let ID_PACE_DH_GM_AES_CBC_CMAC_128 = ID_PACE_DH_GM + ".2";
    static let ID_PACE_DH_GM_AES_CBC_CMAC_192 = ID_PACE_DH_GM + ".3";
    static let ID_PACE_DH_GM_AES_CBC_CMAC_256 = ID_PACE_DH_GM + ".4";
    
    static let ID_PACE_ECDH_GM = ID_PACE + ".2"
    static let ID_PACE_ECDH_GM_3DES_CBC_CBC = ID_PACE_ECDH_GM + ".1";
    static let ID_PACE_ECDH_GM_AES_CBC_CMAC_128 = ID_PACE_ECDH_GM + ".2";
    static let ID_PACE_ECDH_GM_AES_CBC_CMAC_192 = ID_PACE_ECDH_GM + ".3";
    static let ID_PACE_ECDH_GM_AES_CBC_CMAC_256 = ID_PACE_ECDH_GM + ".4";
    
    static let ID_PACE_DH_IM = ID_PACE + ".3"
    static let ID_PACE_DH_IM_3DES_CBC_CBC = ID_PACE_DH_IM + ".1";
    static let ID_PACE_DH_IM_AES_CBC_CMAC_128 = ID_PACE_DH_IM + ".2";
    static let ID_PACE_DH_IM_AES_CBC_CMAC_192 = ID_PACE_DH_IM + ".3";
    static let ID_PACE_DH_IM_AES_CBC_CMAC_256 = ID_PACE_DH_IM + ".4";
    
    static let ID_PACE_ECDH_IM = ID_PACE + ".4"
    static let ID_PACE_ECDH_IM_3DES_CBC_CBC = ID_PACE_ECDH_IM + ".1";
    static let ID_PACE_ECDH_IM_AES_CBC_CMAC_128 = ID_PACE_ECDH_IM + ".2";
    static let ID_PACE_ECDH_IM_AES_CBC_CMAC_192 = ID_PACE_ECDH_IM + ".3";
    static let ID_PACE_ECDH_IM_AES_CBC_CMAC_256 = ID_PACE_ECDH_IM + ".4";
    
    static let ID_PACE_ECDH_CAM = ID_PACE + ".6"
    static let ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 = ID_PACE_ECDH_CAM + ".2";
    static let ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 = ID_PACE_ECDH_CAM + ".3";
    static let ID_PACE_ECDH_CAM_AES_CBC_CMAC_256 = ID_PACE_ECDH_CAM + ".4";

    public func getObjectIdentifier() -> String {
        preconditionFailure("This method must be overridden")
    }
    
    public func getProtocolOIDString() -> String {
        preconditionFailure("This method must be overridden")
    }
    
    static func getInstance( object : ASN1Item, body: [UInt8] ) -> SecurityInfo? {
        let oid = object.getChild(0)?.value ?? ""
        let requiredData = object.getChild(1)!
        var optionalData : ASN1Item? = nil
        if (object.getNumberOfChildren() == 3) {
            optionalData = object.getChild(2)
        }
        
        if ChipAuthenticationPublicKeyInfo.checkRequiredIdentifier(oid) {
            
            let keyData : [UInt8] = [UInt8](body[requiredData.pos ..< requiredData.pos+requiredData.headerLen+requiredData.length])
            
            var subjectPublicKeyInfo : OpaquePointer? = nil
            let _ = keyData.withUnsafeBytes { (ptr) in
                var newPtr = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                
                subjectPublicKeyInfo = d2i_PUBKEY(nil, &newPtr, keyData.count)
            }
            
            if let subjectPublicKeyInfo = subjectPublicKeyInfo {
                                
                if optionalData == nil {
                    return ChipAuthenticationPublicKeyInfo(oid:oid, pubKey:subjectPublicKeyInfo);
                } else {
                    let keyId = Int(optionalData!.value)
                    return ChipAuthenticationPublicKeyInfo(oid:oid, pubKey:subjectPublicKeyInfo, keyId: keyId);
                }
                
            }
        } else if ChipAuthenticationInfo.checkRequiredIdentifier(oid) {
            let version = Int(requiredData.value) ?? -1
            if let optionalData = optionalData {
                let keyId = Int(optionalData.value)
                return ChipAuthenticationInfo(oid: oid, version: version, keyId: keyId);
            } else {
                return ChipAuthenticationInfo(oid: oid, version: version);
            }
        } else if PACEInfo.checkRequiredIdentifier(oid) {
            let version = Int(requiredData.value) ?? -1
            var parameterId : Int? = nil
            
            if let optionalData = optionalData {
                parameterId = Int(optionalData.value, radix:16)
            }
            return PACEInfo(oid: oid, version: version, parameterId: parameterId);
        }
        
        return nil
    }
}
