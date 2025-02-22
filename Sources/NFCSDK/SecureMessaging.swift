//
//  SecureMessaging.swift
//  NFCSDK
//
//  Created by OCR Labs on 09/06/2019.
//  Copyright © 2019 OCR Labs. All rights reserved.
//

import Foundation

public enum SecureMessagingSupportedAlgorithms {
    case DES
    case AES
}

#if !os(macOS)
import CoreNFC


@available(iOS 13, *)
public class SecureMessaging {
    private var ksenc : [UInt8]
    private var ksmac : [UInt8]
    private var ssc : [UInt8]
    private let algoName : SecureMessagingSupportedAlgorithms
    private let padLength : Int
    
    public init( encryptionAlgorithm : SecureMessagingSupportedAlgorithms = .DES, ksenc : [UInt8], ksmac : [UInt8], ssc : [UInt8]) {
        self.ksenc = ksenc
        self.ksmac = ksmac
        self.ssc = ssc
        self.algoName = encryptionAlgorithm
        self.padLength = algoName == .DES ? 8 : 16
    }

    func protect(apdu : NFCISO7816APDU ) throws -> NFCISO7816APDU {
    
        Log.verbose("\t\tSSC: " + binToHexRep(self.ssc))
        self.ssc = self.incSSC()
        let paddedSSC = algoName == .DES ? self.ssc : [UInt8](repeating: 0, count: 8) + ssc
        Log.verbose("\tIncrement SSC with 1")
        Log.verbose("\t\tSSC: " + binToHexRep(self.ssc))


        let cmdHeader = self.maskClassAndPad(apdu: apdu)
        var do87 : [UInt8] = []
        var do97 : [UInt8] = []
        
        var tmp = "Concatenate CmdHeader"
        if apdu.data != nil {
            tmp += " and DO87"
            do87 = try self.buildD087(apdu: apdu)
        }
        if apdu.expectedResponseLength > 0 && apdu.expectedResponseLength < 256 {
            tmp += " and DO97"
            do97 = try self.buildD097(apdu: apdu)
        }
        
        let M = cmdHeader + do87 + do97
        Log.verbose(tmp)
        Log.verbose("\tM: " + binToHexRep(M))
        
        Log.verbose("Compute MAC of M")
        
        let N = pad(paddedSSC + M, blockSize:padLength)
        Log.verbose("\tConcatenate SSC and M and add padding")
        Log.verbose("\t\tN: " + binToHexRep(N))

        var CC = mac(algoName: algoName, key: self.ksmac, msg: N)
        if CC.count > 8 {
            CC = [UInt8](CC[0..<8])
        }
        Log.verbose("\tCompute MAC over N with KSmac")
        Log.verbose("\t\tCC: " + binToHexRep(CC))
        
        let do8e = self.buildD08E(mac: CC)
        
        let size = do87.count + do97.count + do8e.count
        var dataSize: [UInt8]
        if size > 255 {
            dataSize = [0x00] + intToBin(size, pad: 4)
        } else {
            dataSize = intToBin(size)
        }
        var protectedAPDU = [UInt8](cmdHeader[0..<4]) + dataSize
        protectedAPDU += do87 + do97 + do8e
            
        if size > 255 {
            protectedAPDU += [0x00,0x00]
        } else {
            protectedAPDU += [0x00]
        }
        Log.verbose("Construct and send protected APDU")
        Log.verbose("\tProtectedAPDU: " + binToHexRep(protectedAPDU))
        
        let newAPDU = NFCISO7816APDU(data:Data(protectedAPDU))!
        return newAPDU
    }

    func unprotect(rapdu : ResponseAPDU ) throws -> ResponseAPDU {
        var needCC = false
        var do87 : [UInt8] = []
        var do87Data : [UInt8] = []
        var do99 : [UInt8] = []
        var offset = 0
        
        self.ssc = self.incSSC()
        let paddedSSC = algoName == .DES ? self.ssc : [UInt8](repeating: 0, count: 8) + ssc
        Log.verbose("\tIncrement SSC with 1")
        Log.verbose("\t\tSSC: " + binToHexRep(self.ssc))
                
        if(rapdu.sw1 != 0x90 || rapdu.sw2 != 0x00) {
            return rapdu
        }

        let rapduBin = rapdu.data + [rapdu.sw1, rapdu.sw2]
        Log.verbose("Receive response APDU of MRTD's chip")
        Log.verbose("\tRAPDU: " + binToHexRep(rapduBin))
        
        if rapduBin[0] == 0x87 {
            let (encDataLength, o) = try asn1Length([UInt8](rapduBin[1...]))
            offset = 1 + o
            
            if rapduBin[offset] != 0x1 {
                throw NFCSDKError.D087Malformed
            }
            
            do87 = [UInt8](rapduBin[0 ..< offset + Int(encDataLength)])
            do87Data = [UInt8](rapduBin[offset+1 ..< offset + Int(encDataLength)])
            offset += Int(encDataLength)
            needCC = true
        }
        
        do99 = [UInt8](rapduBin[offset..<offset+4])
        let sw1 = rapduBin[offset+2]
        let sw2 = rapduBin[offset+3]
        offset += 4
        needCC = true
        
        if do99[0] != 0x99 && do99[1] != 0x02 {
            return ResponseAPDU(data: [], sw1: sw1, sw2: sw2)
        }
        
        if rapduBin[offset] == 0x8E {
            let ccLength : Int = Int(binToHex(rapduBin[offset+1]))
            let CC = [UInt8](rapduBin[offset+2 ..< offset+2+ccLength])

            var tmp = ""
            if do87.count > 0 {
                tmp += " DO'87"
            }
            if do99.count > 0 {
                tmp += " DO'99"
            }
            Log.verbose("Verify RAPDU CC by computing MAC of" + tmp)
            
            let K = pad(paddedSSC + do87 + do99, blockSize:padLength)
            Log.verbose("\tConcatenate SSC and" + tmp + " and add padding")
            Log.verbose("\t\tK: " + binToHexRep(K))
            
            Log.verbose("\tCompute MAC with KSmac")
            var CCb = mac(algoName: algoName, key: self.ksmac, msg: K)
            if CCb.count > 8 {
                CCb = [UInt8](CC[0..<8])
            }
            Log.verbose("\t\tCC: " + binToHexRep(CCb))
            
            let res = (CC == CCb)
            Log.verbose("\tCompare CC with data of DO'8E of RAPDU")
            Log.verbose("\t\t\(binToHexRep(CC))  == \(binToHexRep(CCb)) ? \(res)")
            
            if !res {
                throw NFCSDKError.InvalidResponseChecksum
            }
        }
        else if needCC {
            throw NFCSDKError.MissingMandatoryFields
        }
        
        var data : [UInt8] = []
        if do87Data.count > 0 {
            
            let dec : [UInt8]
            if algoName == .DES {
                dec = tripleDESDecrypt(key: self.ksenc, message: do87Data, iv: [0,0,0,0,0,0,0,0])
            } else {
                let paddedssc = [UInt8](repeating: 0, count: 8) + ssc
                let iv = AESECBEncrypt(key: ksenc, message: paddedssc)
                dec = AESDecrypt(key: self.ksenc, message: do87Data, iv: iv)
            }

            data = unpad(dec)
            Log.verbose("Decrypt data of DO'87 with KSenc")
            Log.verbose("\tDecryptedData: " + binToHexRep(data))
        }
        
        Log.verbose("Unprotected APDU: [\(binToHexRep(data))] \(binToHexRep(sw1)) \(binToHexRep(sw2))" )
        return ResponseAPDU(data: data, sw1: sw1, sw2: sw2)
    }

    func maskClassAndPad(apdu : NFCISO7816APDU ) -> [UInt8] {
        Log.verbose("Mask class byte and pad command header")
        let res = pad([0x0c, apdu.instructionCode, apdu.p1Parameter, apdu.p2Parameter], blockSize: padLength)
        Log.verbose("\tCmdHeader: " + binToHexRep(res))
        return res
    }
    
    func buildD087(apdu : NFCISO7816APDU) throws -> [UInt8] {
        let cipher = [0x01] + self.padAndEncryptData(apdu)
        let res = try [0x87] + toAsn1Length(cipher.count) + cipher
        Log.verbose("Build DO'87")
        Log.verbose("\tDO87: " + binToHexRep(res))
        return res
    }
    
    func padAndEncryptData(_ apdu : NFCISO7816APDU) -> [UInt8] {
        let data = [UInt8](apdu.data!)
        let paddedData = pad( data, blockSize: padLength )
        
        let enc : [UInt8]
        if algoName == .DES {
            enc = tripleDESEncrypt(key: self.ksenc, message: paddedData, iv: [0,0,0,0,0,0,0,0])
        } else {
            let paddedssc = [UInt8](repeating: 0, count: 8) + ssc
            let iv = AESECBEncrypt(key: ksenc, message: paddedssc)
            enc = AESEncrypt(key: self.ksenc, message: paddedData, iv: iv)
        }
        
        Log.verbose("Pad data")
        Log.verbose("\tData: " + binToHexRep(paddedData))
        Log.verbose("Encrypt data with KSenc")
        Log.verbose("\tEncryptedData: " + binToHexRep(enc))
        return enc
    }
    
    func incSSC() -> [UInt8] {
        let val = binToHex(self.ssc) + 1
        
        return withUnsafeBytes(of: val.bigEndian, Array.init)
    }
    
    func buildD08E(mac : [UInt8]) -> [UInt8] {
        let res : [UInt8] = [0x8E, UInt8(mac.count)] + mac
        Log.verbose("Build DO'8E")
        Log.verbose("\tDO8E: \(binToHexRep(res))" )
        return res
    }

    func buildD097(apdu : NFCISO7816APDU) throws -> [UInt8] {
        let le = apdu.expectedResponseLength
        var binLe = intToBin(le)
        if (le == 256 || le == 65536) {
            binLe = [0x00] + (le > 256 ? [0x00] : [])
        }
        
        let res : [UInt8] = try [0x97] + toAsn1Length(binLe.count) + binLe
        Log.verbose("Build DO'97")
        Log.verbose("\tDO97: \(res)")
        return res
    }
    
}
#endif
