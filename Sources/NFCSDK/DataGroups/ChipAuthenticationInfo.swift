//
//  ChipAuthenticationInfo.swift
//  NFCSDK
//
//  Created by OCR Labs on 25/02/2021.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public class ChipAuthenticationInfo : SecurityInfo {
    
    var oid : String
    var version : Int
    var keyId : Int?
    
    static func checkRequiredIdentifier(_ oid : String) -> Bool {
        return ID_CA_DH_3DES_CBC_CBC_OID == oid
            || ID_CA_ECDH_3DES_CBC_CBC_OID == oid
            || ID_CA_DH_AES_CBC_CMAC_128_OID == oid
            || ID_CA_DH_AES_CBC_CMAC_192_OID == oid
            || ID_CA_DH_AES_CBC_CMAC_256_OID == oid
            || ID_CA_ECDH_AES_CBC_CMAC_128_OID == oid
            || ID_CA_ECDH_AES_CBC_CMAC_192_OID == oid
            || ID_CA_ECDH_AES_CBC_CMAC_256_OID == oid
    }
    
    init(oid: String, version: Int, keyId: Int? = nil) {
        self.oid = oid
        self.version = version
        self.keyId = keyId
    }
    
    public override func getObjectIdentifier() -> String {
        return oid
    }
    
    public override func getProtocolOIDString() -> String {
        return ChipAuthenticationInfo.toProtocolOIDString(oid:oid)
    }
    
    public func getKeyId() -> Int {
        return keyId ?? 0
    }
    
    public static func toKeyAgreementAlgorithm( oid : String ) throws -> String {
        if ID_CA_DH_3DES_CBC_CBC_OID == oid
            || ID_CA_DH_AES_CBC_CMAC_128_OID == oid
            || ID_CA_DH_AES_CBC_CMAC_192_OID == oid
            || ID_CA_DH_AES_CBC_CMAC_256_OID == oid {
            return "DH";
        } else if ID_CA_ECDH_3DES_CBC_CBC_OID == oid
                    || ID_CA_ECDH_AES_CBC_CMAC_128_OID == oid
                    || ID_CA_ECDH_AES_CBC_CMAC_192_OID == oid
                    || ID_CA_ECDH_AES_CBC_CMAC_256_OID == oid {
            return "ECDH";
        }
        
        throw NFCSDKError.InvalidDataPassed( "Unable to lookup key agreement algorithm - invalid oid" )
    }
    
    public static func toCipherAlgorithm( oid : String ) throws -> String {
        if ID_CA_DH_3DES_CBC_CBC_OID == oid
            || ID_CA_ECDH_3DES_CBC_CBC_OID == oid {
            return "DESede";
        } else if ID_CA_DH_AES_CBC_CMAC_128_OID == oid
                    || ID_CA_DH_AES_CBC_CMAC_192_OID == oid
                    || ID_CA_DH_AES_CBC_CMAC_256_OID == oid
                    || ID_CA_ECDH_AES_CBC_CMAC_128_OID == oid
                    || ID_CA_ECDH_AES_CBC_CMAC_192_OID == oid
                    || ID_CA_ECDH_AES_CBC_CMAC_256_OID == oid {
            return "AES";
        }
        throw NFCSDKError.InvalidDataPassed( "Unable to lookup cipher algorithm - invalid oid" )
    }
    
    public static func toKeyLength( oid : String ) throws -> Int {
        if ID_CA_DH_3DES_CBC_CBC_OID == oid
            || ID_CA_ECDH_3DES_CBC_CBC_OID == oid
            || ID_CA_DH_AES_CBC_CMAC_128_OID == oid
            || ID_CA_ECDH_AES_CBC_CMAC_128_OID == oid {
            return 128;
        } else if ID_CA_DH_AES_CBC_CMAC_192_OID == oid
                    || ID_CA_ECDH_AES_CBC_CMAC_192_OID == oid {
            return 192;
        } else if ID_CA_DH_AES_CBC_CMAC_256_OID == oid
                    || ID_CA_ECDH_AES_CBC_CMAC_256_OID == oid {
            return 256;
        }
        
        throw NFCSDKError.InvalidDataPassed( "Unable to get key length - invalid oid" )
    }
    
    private static func toProtocolOIDString(oid : String) -> String {
        if ID_CA_DH_3DES_CBC_CBC_OID == oid {
            return "id-CA-DH-3DES-CBC-CBC"
        }
        if ID_CA_DH_AES_CBC_CMAC_128_OID == oid {
            return "id-CA-DH-AES-CBC-CMAC-128"
        }
        if ID_CA_DH_AES_CBC_CMAC_192_OID == oid {
            return "id-CA-DH-AES-CBC-CMAC-192"
        }
        if ID_CA_DH_AES_CBC_CMAC_256_OID == oid {
            return "id-CA-DH-AES-CBC-CMAC-256"
        }
        if ID_CA_ECDH_3DES_CBC_CBC_OID == oid {
            return "id-CA-ECDH-3DES-CBC-CBC"
        }
        if ID_CA_ECDH_AES_CBC_CMAC_128_OID == oid {
            return "id-CA-ECDH-AES-CBC-CMAC-128"
        }
        if ID_CA_ECDH_AES_CBC_CMAC_192_OID == oid {
            return "id-CA-ECDH-AES-CBC-CMAC-192"
        }
        if ID_CA_ECDH_AES_CBC_CMAC_256_OID == oid {
            return "id-CA-ECDH-AES-CBC-CMAC-256"
        }
        
        return oid
    }
}
