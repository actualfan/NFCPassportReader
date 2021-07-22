//
//  TagHandler.swift
//  NFCSDK
//
//  Created by OCR Labs on 09/06/2019.
//  Copyright © 2019 OCR Labs. All rights reserved.
//

import Foundation

#if !os(macOS)
import CoreNFC

@available(iOS 13, *)
public class TagReader {
    var tag : NFCISO7816Tag
    var secureMessaging : SecureMessaging?
    var maxDataLengthToRead : Int = 0xA0

    var progress : ((Int)->())?

    init( tag: NFCISO7816Tag ) {
        self.tag = tag
    }
    
    func overrideDataAmountToRead( newAmount : Int ) {
        maxDataLengthToRead = newAmount
    }
    
    func reduceDataReadingAmount() {
        if maxDataLengthToRead > 0xA0 {
            maxDataLengthToRead = 0xA0
        }
    }


    func readDataGroup( dataGroup: DataGroupId, completed: @escaping ([UInt8]?, NFCSDKError?)->() )  {
        guard let tag = dataGroup.getFileIDTag() else {
            completed(nil, NFCSDKError.UnsupportedDataGroup)
            return
        }
        
        selectFileAndRead(tag: tag, completed:completed )
    }
    
    func getChallenge( completed: @escaping (ResponseAPDU?, NFCSDKError?)->() ) {
        let cmd : NFCISO7816APDU = NFCISO7816APDU(instructionClass: 00, instructionCode: 0x84, p1Parameter: 0, p2Parameter: 0, data: Data(), expectedResponseLength: 8)
        
        send( cmd: cmd, completed: completed )
    }
    
    func doInternalAuthentication( challenge: [UInt8], completed: @escaping (ResponseAPDU?, NFCSDKError?)->() ) {
        let randNonce = Data(challenge)
        
        let cmd = NFCISO7816APDU(instructionClass: 00, instructionCode: 0x88, p1Parameter: 0, p2Parameter: 0, data: randNonce, expectedResponseLength: 256)

        send( cmd: cmd, completed: completed )
    }

    func doMutualAuthentication( cmdData : Data, completed: @escaping (ResponseAPDU?, NFCSDKError?)->() ) {
        let cmd : NFCISO7816APDU = NFCISO7816APDU(instructionClass: 00, instructionCode: 0x82, p1Parameter: 0, p2Parameter: 0, data: cmdData, expectedResponseLength: 256)

        send( cmd: cmd, completed: completed )
    }
    
    func sendMSEKAT( keyData : Data, idData: Data?, completed: @escaping (ResponseAPDU?, NFCSDKError?)->() ) {
        
        var data = keyData
        if let idData = idData {
            data += idData
        }
        
        let cmd : NFCISO7816APDU = NFCISO7816APDU(instructionClass: 00, instructionCode: 0x22, p1Parameter: 0x41, p2Parameter: 0xA6, data: data, expectedResponseLength: 256)
        
        send( cmd: cmd, completed: completed )
    }
    
    func sendMSESetATIntAuth( oid: String, keyId: Int?, completed: @escaping (ResponseAPDU?, NFCSDKError?)->() ) {
        
        let cmd : NFCISO7816APDU
        let oidBytes = oidToBytes(oid: oid, replaceTag: true)
        
        if let keyId = keyId, keyId != 0 {
            let keyIdBytes = wrapDO(b:0x84, arr:intToBytes(val:keyId, removePadding: true))
            let data = oidBytes + keyIdBytes
            
            cmd = NFCISO7816APDU(instructionClass: 00, instructionCode: 0x22, p1Parameter: 0x41, p2Parameter: 0xA4, data: Data(data), expectedResponseLength: 256)
            
        } else {
            cmd = NFCISO7816APDU(instructionClass: 00, instructionCode: 0x22, p1Parameter: 0x41, p2Parameter: 0xA4, data: Data(oidBytes), expectedResponseLength: 256)
        }
        
        send( cmd: cmd, completed: completed )
    }
    
    func sendMSESetATMutualAuth( oid: String, keyType: UInt8, completed: @escaping (ResponseAPDU?, NFCSDKError?)->() ) {
        
        let oidBytes = oidToBytes(oid: oid, replaceTag: true)
        let keyTypeBytes = wrapDO( b: 0x83, arr:[keyType])
        
        let data = oidBytes + keyTypeBytes
            
        let cmd = NFCISO7816APDU(instructionClass: 00, instructionCode: 0x22, p1Parameter: 0xC1, p2Parameter: 0xA4, data: Data(data), expectedResponseLength: 256)
        
        send( cmd: cmd, completed: completed )
    }
    

    func sendGeneralAuthenticate( data : [UInt8], lengthExpected : Int = 256, isLast: Bool, completed: @escaping (ResponseAPDU?, NFCSDKError?)->() ) {

        let wrappedData = wrapDO(b:0x7C, arr:data)
        let commandData = Data(wrappedData)
            
        let instructionClass : UInt8 = isLast ? 0x00 : 0x10
        let INS_BSI_GENERAL_AUTHENTICATE : UInt8 = 0x86
        
        let cmd : NFCISO7816APDU = NFCISO7816APDU(instructionClass: instructionClass, instructionCode: INS_BSI_GENERAL_AUTHENTICATE, p1Parameter: 0x00, p2Parameter: 0x00, data: commandData, expectedResponseLength: lengthExpected)
        send( cmd: cmd, completed: { [unowned self] (response, error) in
            if let error = error {
                if case NFCSDKError.ResponseError(_, let sw1, let sw2) = error,
                   sw1 == 0x67, sw2 == 0x00 {
                    
                    let cmd : NFCISO7816APDU = NFCISO7816APDU(instructionClass: instructionClass, instructionCode: INS_BSI_GENERAL_AUTHENTICATE, p1Parameter: 0x00, p2Parameter: 0x00, data: commandData, expectedResponseLength: 256)
                    send( cmd: cmd, completed: { (response, error) in
                        if let response = response {
                            do {
                                var retResponse = response
                                retResponse.data = try unwrapDO( tag:0x7c, wrappedData:retResponse.data)

                                completed( retResponse, nil)
                            } catch {
                                completed( nil, NFCSDKError.InvalidASN1Value)
                            }
                        } else {
                            completed( nil, error)
                        }
                    })
                } else {
                    completed( nil, error)
                }
            } else {
                if let response = response {
                    do {
                        var retResponse = response
                        retResponse.data = try unwrapDO( tag:0x7c, wrappedData:retResponse.data)
                        
                        completed( retResponse, nil)
                    } catch {
                        completed( nil, NFCSDKError.InvalidASN1Value)
                    }
                } else {
                    completed( nil, error)
                }
            }
        })
    }
    

    var header = [UInt8]()
    func selectFileAndRead( tag: [UInt8], completed: @escaping ([UInt8]?, NFCSDKError?)->() ) {
        selectFile(tag: tag ) { [unowned self] (resp,err) in
            if let error = err {
                completed( nil, error)
                return
            }
            
            let data : [UInt8] = [0x00, 0xB0, 0x00, 0x00, 0x00, 0x00,0x04]
            let cmd = NFCISO7816APDU(data:Data(data))!
            self.send( cmd: cmd ) { [unowned self] (resp,err) in
                guard let response = resp else {
                    completed( nil, err)
                    return
                }
                var leftToRead = 0
                
                let (len, o) = try! asn1Length([UInt8](response.data[1..<4]))
                leftToRead = Int(len)
                let offset = o + 1
                
                self.header = [UInt8](response.data[..<offset])

                Log.debug( "TagReader - Number of data bytes to read - \(leftToRead)" )
                self.readBinaryData(leftToRead: leftToRead, amountRead: offset, completed: completed)

            }
        }
    }

    func readCardAccess( completed: @escaping ([UInt8]?, NFCSDKError?)->() ) {
        let cmd : NFCISO7816APDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xA4, p1Parameter: 0x00, p2Parameter: 0x0C, data: Data([0x3f,0x00]), expectedResponseLength: 256)
        
        send( cmd: cmd) { response, error in
            if let error = error {
                completed( nil, error )
                return
            }
            
            self.selectFileAndRead(tag: [0x01,0x1C]) { data, error in
                completed( data, error)
            }
        }
    }
    
    func selectPassportApplication( completed: @escaping (ResponseAPDU?, NFCSDKError?)->() ) {
        Log.debug( "Re-selecting eMRTD Application" )
        let cmd : NFCISO7816APDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xA4, p1Parameter: 0x04, p2Parameter: 0x0C, data: Data([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]), expectedResponseLength: 256)
        
        self.send( cmd: cmd) { response, error in
            completed( response, nil)
        }

    }
    

    func selectFile( tag: [UInt8], completed: @escaping (ResponseAPDU?, NFCSDKError?)->() ) {
        
        let data : [UInt8] = [0x00, 0xA4, 0x02, 0x0C, 0x02] + tag
        let cmd = NFCISO7816APDU(data:Data(data))!
        
        send( cmd: cmd, completed: completed )
    }
    
    func readBinaryData( leftToRead: Int, amountRead : Int, completed: @escaping ([UInt8]?, NFCSDKError?)->() ) {
        var readAmount : Int = maxDataLengthToRead
        if maxDataLengthToRead != 256 && leftToRead < maxDataLengthToRead {
            readAmount = leftToRead
        }
        
        self.progress?( Int(Float(amountRead) / Float(leftToRead+amountRead ) * 100))
        let offset = intToBin(amountRead, pad:4)

        let cmd = NFCISO7816APDU(
            instructionClass: 00,
            instructionCode: 0xB0,
            p1Parameter: offset[0],
            p2Parameter: offset[1],
            data: Data(),
            expectedResponseLength: readAmount
        )

        Log.verbose( "TagReader - data bytes remaining: \(leftToRead), will read : \(readAmount)" )
        self.send( cmd: cmd ) { (resp,err) in
            guard let response = resp else {
                completed( nil, err)
                return
            }
            Log.verbose( "TagReader - got resp - \(response)" )
            self.header += response.data
            
            let remaining = leftToRead - response.data.count
            Log.verbose( "TagReader - Amount of data left to read - \(remaining)" )
            if remaining > 0 {
                self.readBinaryData(leftToRead: remaining, amountRead: amountRead + response.data.count, completed: completed )
            } else {
                completed( self.header, err )
            }
            
        }
    }

    
    func send( cmd: NFCISO7816APDU, completed: @escaping (ResponseAPDU?, NFCSDKError?)->() ) {
        
        Log.verbose( "TagReader - sending \(cmd)" )
        var toSend = cmd
        if let sm = secureMessaging {
            do {
                toSend = try sm.protect(apdu:cmd)
            } catch {
                completed( nil, NFCSDKError.UnableToProtectAPDU )
            }
            Log.verbose("TagReader - [SM] \(toSend)" )
        }

        tag.sendCommand(apdu: toSend) { [unowned self] (data, sw1, sw2, error) in
            if let error = error {
                Log.error( "TagReader - Error reading tag - \(error.localizedDescription))" )
                completed( nil, NFCSDKError.ResponseError( error.localizedDescription, sw1, sw2 ) )
            } else {
                Log.verbose( "TagReader - Received response" )
                var rep = ResponseAPDU(data: [UInt8](data), sw1: sw1, sw2: sw2)

                if let sm = self.secureMessaging {
                    do {
                        rep = try sm.unprotect(rapdu:rep)
                        Log.verbose(String(format:"TagReader [SM - unprotected] \(binToHexRep(rep.data, asArray:true)), sw1:0x%02x sw2:0x%02x", rep.sw1, rep.sw2) )
                    } catch {
                        completed( nil, NFCSDKError.UnableToUnprotectAPDU )
                        return
                    }
                } else {
                    Log.verbose(String(format:"TagReader [unprotected] \(binToHexRep(rep.data, asArray:true)), sw1:0x%02x sw2:0x%02x", rep.sw1, rep.sw2) )

                }
                
                if rep.sw1 == 0x90 && rep.sw2 == 0x00 {
                    completed( rep, nil )
                } else {
                    Log.error( "Error reading tag: sw1 - 0x\(binToHexRep(sw1)), sw2 - 0x\(binToHexRep(sw2))" )
                    let tagError: NFCSDKError
                    if (rep.sw1 == 0x63 && rep.sw2 == 0x00) {
                        tagError = NFCSDKError.InvalidMRZKey
                    } else {
                        let errorMsg = self.decodeError(sw1: rep.sw1, sw2: rep.sw2)
                        Log.error( "reason: \(errorMsg)" )
                        tagError = NFCSDKError.ResponseError( errorMsg, sw1, sw2 )
                    }
                    completed( nil, tagError)
                }
            }
        }
    }
    
    private func decodeError( sw1: UInt8, sw2:UInt8 ) -> String {

        let errors : [UInt8 : [UInt8:String]] = [
            0x62: [0x00:"No information given",
                   0x81:"Part of returned data may be corrupted",
                   0x82:"End of file/record reached before reading Le bytes",
                   0x83:"Selected file invalidated",
                   0x84:"FCI not formatted according to ISO7816-4 section 5.1.5"],
            
            0x63: [0x81:"File filled up by the last write",
                   0x82:"Card Key not supported",
                   0x83:"Reader Key not supported",
                   0x84:"Plain transmission not supported",
                   0x85:"Secured Transmission not supported",
                   0x86:"Volatile memory not available",
                   0x87:"Non Volatile memory not available",
                   0x88:"Key number not valid",
                   0x89:"Key length is not correct",
                   0xC:"Counter provided by X (valued from 0 to 15) (exact meaning depending on the command)"],
            0x65: [0x00:"No information given",
                   0x81:"Memory failure"],
            0x67: [0x00:"Wrong length"],
            0x68: [0x00:"No information given",
                   0x81:"Logical channel not supported",
                   0x82:"Secure messaging not supported",
                   0x83:"Last command of the chain expected",
                   0x84:"Command chaining not supported"],
            0x69: [0x00:"No information given",
                   0x81:"Command incompatible with file structure",
                   0x82:"Security status not satisfied",
                   0x83:"Authentication method blocked",
                   0x84:"Referenced data invalidated",
                   0x85:"Conditions of use not satisfied",
                   0x86:"Command not allowed (no current EF)",
                   0x87:"Expected SM data objects missing",
                   0x88:"SM data objects incorrect"],
            0x6A: [0x00:"No information given",
                   0x80:"Incorrect parameters in the data field",
                   0x81:"Function not supported",
                   0x82:"File not found",
                   0x83:"Record not found",
                   0x84:"Not enough memory space in the file",
                   0x85:"Lc inconsistent with TLV structure",
                   0x86:"Incorrect parameters P1-P2",
                   0x87:"Lc inconsistent with P1-P2",
                   0x88:"Referenced data not found"],
            0x6B: [0x00:"Wrong parameter(s) P1-P2]"],
            0x6D: [0x00:"Instruction code not supported or invalid"],
            0x6E: [0x00:"Class not supported"],
            0x6F: [0x00:"No precise diagnosis"],
            0x90: [0x00:"Success"]
        ]
        
        if sw1 == 0x61 {
            return "SW2 indicates the number of response bytes still available - (\(sw2) bytes still available)"
        } else if sw1 == 0x64 {
            return "State of non-volatile memory unchanged (SW2=00, other values are RFU)"
        } else if sw1 == 0x6C {
            return "Wrong length Le: SW2 indicates the exact length - (exact length :\(sw2))"
        }

        if let dict = errors[sw1], let errorMsg = dict[sw2] {
            return errorMsg
        }
        
        return "Unknown error - sw1: 0x\(binToHexRep(sw1)), sw2 - 0x\(binToHexRep(sw2)) "
    }
}

#endif
