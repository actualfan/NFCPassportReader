//
//  SecureMessagingSessionKeyGenerator.swift
//  NFCSDK
//
//  Created by OCR Labs on 25/02/2021.
//

import Foundation

import CryptoKit

@available(iOS 13, macOS 10.15, *)
class SecureMessagingSessionKeyGenerator {
    static let NO_PACE_KEY_REFERENCE : UInt8 = 0x00
    enum SMSMode : UInt8 {
        case ENC_MODE = 0x1;
        case MAC_MODE = 0x2;
        case PACE_MODE = 0x3;
    }
    
    func deriveKey( keySeed : [UInt8], mode : SMSMode) throws -> [UInt8] {
        return try deriveKey(keySeed: keySeed, cipherAlgName: "DESede", keyLength: 128, mode: mode);
    }
    
    func deriveKey(keySeed : [UInt8], cipherAlgName :String, keyLength : Int, mode : SMSMode) throws  -> [UInt8] {
        return try deriveKey(keySeed: keySeed, cipherAlgName: cipherAlgName, keyLength: keyLength, nonce: nil, mode: mode);
    }
    
    func deriveKey(keySeed : [UInt8], cipherAlgName :String, keyLength : Int, nonce : [UInt8]? = nil, mode : SMSMode) throws -> [UInt8]  {
        return try deriveKey(keySeed: keySeed, cipherAlgName: cipherAlgName, keyLength: keyLength, nonce: nonce, mode: mode, paceKeyReference: SecureMessagingSessionKeyGenerator.NO_PACE_KEY_REFERENCE);
    }

    func deriveKey(keySeed : [UInt8], cipherAlgName :String, keyLength : Int, nonce : [UInt8]?, mode : SMSMode, paceKeyReference : UInt8) throws ->  [UInt8] {
        let digestAlgo = try inferDigestAlgorithmFromCipherAlgorithmForKeyDerivation(cipherAlg: cipherAlgName, keyLength: keyLength);
        
        let modeArr : [UInt8] = [0x00, 0x00, 0x00, mode.rawValue]
        var dataEls = [Data(keySeed)]
        if let nonce = nonce {
            dataEls.append( Data(nonce) )
        }
        dataEls.append( Data(modeArr) )
        let hashResult = try getHash(algo: digestAlgo, dataElements: dataEls)
        
        var keyBytes : [UInt8]
        if cipherAlgName == "DESede" || cipherAlgName == "3DES" {
            switch(keyLength) {
                case 112, 128:
                    keyBytes = [UInt8](hashResult[0..<16] + hashResult[0..<8])
                    break;
                default:
                    throw NFCSDKError.InvalidDataPassed("Can only use DESede with 128-but key length")
            }
        } else if cipherAlgName.lowercased() == "aes" || cipherAlgName.lowercased().hasPrefix("aes") {
            switch(keyLength) {
                case 128:
                    keyBytes = [UInt8](hashResult[0..<16])
                case 192:
                    keyBytes = [UInt8](hashResult[0..<24])
                case 256:
                    keyBytes = [UInt8](hashResult[0..<32])
                default:
                    throw NFCSDKError.InvalidDataPassed("Can only use AES with 128-bit, 192-bit key or 256-bit length")
            }
        } else {
            throw NFCSDKError.InvalidDataPassed( "Unsupported cipher algorithm used" )
        }
        
        return keyBytes
    }
    
    func inferDigestAlgorithmFromCipherAlgorithmForKeyDerivation( cipherAlg : String, keyLength : Int) throws -> String {
        if cipherAlg == "DESede" || cipherAlg == "AES-128" {
            return "SHA1";
        }
        if cipherAlg == "AES" && keyLength == 128 {
            return "SHA1";
        }
        if cipherAlg == "AES-256" || cipherAlg ==  "AES-192" {
            return "SHA256";
        }
        if cipherAlg == "AES" && (keyLength == 192 || keyLength == 256) {
            return "SHA256";
        }
        
        throw NFCSDKError.InvalidDataPassed("Unsupported cipher algorithm or key length")
    }
    
    func  getHash(algo: String, dataElements:[Data] ) throws -> [UInt8] {
        var hash : [UInt8]
        
        let algo = algo.lowercased()
        if algo == "sha1" {
            var hasher = Insecure.SHA1()
            for d in dataElements {
                hasher.update( data:d )
            }
            hash = Array(hasher.finalize())
        } else if algo == "sha256" {
            var hasher = SHA256()
            for d in dataElements {
                hasher.update( data:d )
            }
            hash = Array(hasher.finalize())
        } else if algo == "sha384" {
            var hasher = SHA384()
            for d in dataElements {
                hasher.update( data:d )
            }
            hash = Array(hasher.finalize())
        } else if algo == "sha512" {
            var hasher = SHA512()
            for d in dataElements {
                hasher.update( data:d )
            }
            hash = Array(hasher.finalize())
        } else {
            throw NFCSDKError.InvalidHashAlgorithmSpecified
        }
        
        return hash
    }
}
