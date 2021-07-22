//
//  PassportReader.swift
//  NFCSDK
//
//  Created by OCR Labs on 11/06/2019.
//  Copyright © 2019 OCR Labs. All rights reserved.
//

import Foundation

#if !os(macOS)
import UIKit
import CoreNFC

@available(iOS 13, *)
public class PassportReader : NSObject {
    private var passport : NFCPassportModel = NFCPassportModel()
    private var readerSession: NFCTagReaderSession?
    private var elementReadAttempts = 0
    private var currentlyReadingDataGroup : DataGroupId?
    
    private var dataGroupsToRead : [DataGroupId] = []
    private var readAllDatagroups = false
    private var skipSecureElements = true

    private var tagReader : TagReader?
    private var bacHandler : BACHandler?
    private var caHandler : ChipAuthenticationHandler?
    private var paceHandler : PACEHandler?
    private var mrzKey : String = ""
    private var dataAmountToReadOverride : Int? = nil
    
    private var scanCompletedHandler: ((NFCPassportModel?, NFCSDKError?)->())!
    private var nfcViewDisplayMessageHandler: ((NFCViewDisplayMessage) -> String?)?
    private var masterListURL : URL?
    private var shouldNotReportNextReaderSessionInvalidationErrorUserCanceled : Bool = false

    public var passiveAuthenticationUsesOpenSSL : Bool = false

    public init( logLevel: LogLevel = .info, masterListURL: URL? = nil ) {
        super.init()
        
        Log.logLevel = logLevel
        self.masterListURL = masterListURL
    }
    
    public func setMasterListURL( _ masterListURL : URL ) {
        self.masterListURL = masterListURL
    }
    
    public func overrideNFCDataAmountToRead( amount: Int ) {
        dataAmountToReadOverride = amount
    }
        
    public func readPassport( mrzKey : String, tags: [DataGroupId] = [], skipSecureElements :Bool = true, customDisplayMessage: ((NFCViewDisplayMessage) -> String?)? = nil, completed: @escaping (NFCPassportModel?, NFCSDKError?)->()) {
        self.passport = NFCPassportModel()
        self.mrzKey = mrzKey
        
        self.dataGroupsToRead.removeAll()
        self.dataGroupsToRead.append( contentsOf:tags)
        self.scanCompletedHandler = completed
        self.nfcViewDisplayMessageHandler = customDisplayMessage
        self.skipSecureElements = skipSecureElements
        self.currentlyReadingDataGroup = nil
        self.elementReadAttempts = 0
        self.bacHandler = nil
        self.caHandler = nil
        self.paceHandler = nil
        
        if self.dataGroupsToRead.count == 0 {
            self.dataGroupsToRead.append(contentsOf:[.COM, .SOD] )
            self.readAllDatagroups = true
        } else {
            self.readAllDatagroups = false
        }
        
        guard NFCNDEFReaderSession.readingAvailable else {
            scanCompletedHandler( nil, NFCSDKError.NFCNotSupported)
            return
        }
        
        if NFCTagReaderSession.readingAvailable {
            readerSession = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)

            self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.requestPresentPassport )
            readerSession?.begin()
        }
    }
}

@available(iOS 13, *)
extension PassportReader : NFCTagReaderSessionDelegate {
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        Log.debug( "tagReaderSessionDidBecomeActive" )
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        Log.debug( "tagReaderSession:didInvalidateWithError - \(error.localizedDescription)" )
        self.readerSession = nil

        if let readerError = error as? NFCReaderError, readerError.code == NFCReaderError.readerSessionInvalidationErrorUserCanceled
            && self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled {
            
            self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = false
        } else {
            var userError = NFCSDKError.UnexpectedError
            if let readerError = error as? NFCReaderError {
                Log.error( "tagReaderSession:didInvalidateWithError - Got NFCReaderError - \(readerError.localizedDescription)" )
                switch (readerError.code) {
                case NFCReaderError.readerSessionInvalidationErrorUserCanceled:
                    Log.error( "     - User cancelled session" )
                    userError = NFCSDKError.UserCanceled
                default:
                    Log.error( "     - some other error - \(readerError.localizedDescription)" )
                    userError = NFCSDKError.UnexpectedError
                }
            } else {
                Log.error( "tagReaderSession:didInvalidateWithError - Received error - \(error.localizedDescription)" )
            }
            self.scanCompletedHandler(nil, userError)
        }
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Log.debug( "tagReaderSession:didDetect - \(tags[0])" )
        if tags.count > 1 {
            Log.debug( "tagReaderSession:more than 1 tag detected! - \(tags)" )

            let errorMessage = NFCViewDisplayMessage.error(.MoreThanOneTagFound)
            self.invalidateSession(errorMessage: errorMessage, error: NFCSDKError.MoreThanOneTagFound)
            return
        }

        let tag = tags.first!
        var passportTag: NFCISO7816Tag
        switch tags.first! {
        case let .iso7816(tag):
            passportTag = tag
        default:
            Log.debug( "tagReaderSession:invalid tag detected!!!" )

            let errorMessage = NFCViewDisplayMessage.error(NFCSDKError.TagNotValid)
            self.invalidateSession(errorMessage:errorMessage, error: NFCSDKError.TagNotValid)
            return
        }
        
        
        Log.debug( "tagReaderSession:connecting to tag - \(tag)" )
        session.connect(to: tag) { [unowned self] (error: Error?) in
            if error != nil {
                Log.debug( "tagReaderSession:failed to connect to tag - \(error?.localizedDescription ?? "Unknown error")" )
                let errorMessage = NFCViewDisplayMessage.error(NFCSDKError.ConnectionError)
                self.invalidateSession(errorMessage: errorMessage, error: NFCSDKError.ConnectionError)
                return
            }
            
            Log.debug( "tagReaderSession:connected to tag - starting authentication" )
            self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.authenticatingWithPassport(0) )

            self.tagReader = TagReader(tag:passportTag)
            
            if let newAmount = self.dataAmountToReadOverride {
                self.tagReader?.overrideDataAmountToRead(newAmount: newAmount)
            }
            
            self.tagReader!.progress = { [unowned self] (progress) in
                if let dgId = self.currentlyReadingDataGroup {
                    self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, progress) )
                } else {
                    self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.authenticatingWithPassport(progress) )
                }
            }

            DispatchQueue.global().async {
                self.startReading( )
            }
        }
    }
    
    func updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage ) {
        self.readerSession?.alertMessage = self.nfcViewDisplayMessageHandler?(alertMessage) ?? alertMessage.description
    }
}

@available(iOS 13, *)
extension PassportReader {
    
    func startReading() {
        tagReader?.readCardAccess(completed: { [unowned self] data, error in
            var ca : CardAccess?
            if let data = data {
                print( "Read CardAccess - data \(binToHexRep(data))" )
                do {
                    ca = try CardAccess(data)
                } catch {
                    print( "Error reading CardAccess - \(error)" )
                }
            }
            
            if let cardAccess = ca {
                passport.cardAccess = cardAccess
                self.doPACEAuthentication( cardAccess: cardAccess)
            } else {
                tagReader?.selectPassportApplication(completed: { response, error in
                    self.doBACAuthentication()
                })
            }
        })
    }
    
    func doPACEAuthentication(cardAccess:CardAccess) {
        self.handlePACE(cardAccess:cardAccess, completed: { [weak self] error in
            if error == nil {
                Log.info( "PACE Successful" )
                self?.passport.PACEStatus = .success

                self?.tagReader?.selectPassportApplication(completed: { response, error in
                    
                    self?.startReadingDataGroups()
                })

            } else if let error = error {
                Log.info( "PACE Failed - \(error.localizedDescription)" )
                self?.passport.PACEStatus = .failed
                self?.tagReader?.selectPassportApplication(completed: { response, error in
                    self?.doBACAuthentication()
                })
            }
        })
    }
    
    func doBACAuthentication() {
        elementReadAttempts = 0
        self.currentlyReadingDataGroup = nil
        if passport.PACEStatus != .notDone {
            passport.PACEStatus = .failed
        }
        if passport.chipAuthenticationStatus != .notDone {
            passport.chipAuthenticationStatus = .failed
        }
        self.handleBAC(completed: { [weak self] error in
            if error == nil {
                Log.info( "BAC Successful" )
                self?.passport.BACStatus = .success
                self?.startReadingDataGroups()
            } else if let error = error {
                Log.info( "BAC Failed" )
                self?.passport.BACStatus = .failed
                let displayMessage = NFCViewDisplayMessage.error(error)
                self?.invalidateSession(errorMessage: displayMessage, error: error)
            }
        })
    }
    
    func startReadingDataGroups() {
        self.readNextDataGroup( ) { [weak self] error in
            if self?.dataGroupsToRead.count != 0 {
                DispatchQueue.global().async {
                    self?.doBACAuthentication()
                }
            } else {
                if let error = error {
                    self?.invalidateSession(errorMessage:NFCViewDisplayMessage.error(error), error: error)
                } else {
                    self?.updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage.successfulRead)
                    
                    self?.doActiveAuthenticationIfNeccessary() { [weak self] in
                        self?.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = true
                        self?.readerSession?.invalidate()
                        
                        self?.passport.verifyPassport(masterListURL: self?.masterListURL, useCMSVerification: self?.passiveAuthenticationUsesOpenSSL ?? false)
                        self?.scanCompletedHandler( self?.passport, nil )
                    }
                }
            }
        }

    }
    
    func invalidateSession(errorMessage: NFCViewDisplayMessage, error: NFCSDKError) {
        self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = true
        self.readerSession?.invalidate(errorMessage: self.nfcViewDisplayMessageHandler?(errorMessage) ?? errorMessage.description)
        self.scanCompletedHandler(nil, error)
    }

    func doActiveAuthenticationIfNeccessary( completed: @escaping ()->() ) {
        guard self.passport.activeAuthenticationSupported else {
            completed()
            return
        }
        
        Log.info( "Performing Active Authentication" )

        let challenge = generateRandomUInt8Array(8)
        self.tagReader?.doInternalAuthentication(challenge: challenge, completed: { (response, err) in
            if let response = response {
                self.passport.verifyActiveAuthentication( challenge:challenge, signature:response.data )
            }

            completed()
        })

    }
    
    func handleBAC( completed: @escaping (NFCSDKError?)->()) {
        guard let tagReader = self.tagReader else {
            completed(NFCSDKError.NoConnectedTag)
            return
        }
        
        Log.info( "Starting Basic Access Control (BAC)" )
        
        self.bacHandler = BACHandler( tagReader: tagReader )
        bacHandler?.performBACAndGetSessionKeys( mrzKey: mrzKey ) { error in
            self.bacHandler = nil
            completed(error)
        }
    }
    
    func handlePACE( cardAccess:CardAccess, completed: @escaping (NFCSDKError?)->()) {
        guard let tagReader = self.tagReader else {
            completed(NFCSDKError.NoConnectedTag)
            return
        }
        
        Log.info( "Starting Password Authenticated Connection Establishment (PACE)" )
        
        do {
            self.paceHandler = try PACEHandler( cardAccess: cardAccess, tagReader: tagReader )
            paceHandler?.doPACE(mrzKey: mrzKey ) { paceSucceeded in
                if paceSucceeded {
                    completed(nil)
                } else {
                    self.paceHandler = nil
                    completed(NFCSDKError.InvalidDataPassed("PACE Failed"))
                }
            }
        } catch let error as NFCSDKError {
            completed( error )
        } catch {
            completed( NFCSDKError.InvalidDataPassed(error.localizedDescription) )
        }
    }
    
    func readNextDataGroup( completedReadingGroups completed : @escaping (NFCSDKError?)->() ) {
        guard let tagReader = self.tagReader else { completed(NFCSDKError.NoConnectedTag ); return }
        if dataGroupsToRead.count == 0 {
            completed(nil)
            return
        }
        
        let dgId = dataGroupsToRead[0]
        self.currentlyReadingDataGroup = dgId
        Log.info( "Reading tag - \(dgId)" )
        elementReadAttempts += 1
        
        self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, 0) )
        tagReader.readDataGroup(dataGroup:dgId) { [unowned self] (response, err) in
            self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, 100) )
            if let response = response {
                
                var readNextDG = true
                do {
                    let dg = try DataGroupParser().parseDG(data: response)
                    self.passport.addDataGroup( dgId, dataGroup:dg )
                    
                    if let com = dg as? COM {
                        var dgsPresent = com.dataGroupsPresent.map { DataGroupId.getIDFromName(name:$0) }
                        var foundDGs : [DataGroupId] = [.COM]
                        if dgsPresent.contains( .DG14 ) {
                            foundDGs.append( .DG14 )
                            dgsPresent.removeAll { $0 == .DG14 }
                        }
                        foundDGs += [.SOD] + dgsPresent
                        if self.readAllDatagroups == true {
                            self.dataGroupsToRead = foundDGs
                        } else {
                            self.dataGroupsToRead = foundDGs.filter { dataGroupsToRead.contains($0) }
                        }
                        
                        if self.skipSecureElements {
                            self.dataGroupsToRead = self.dataGroupsToRead.filter { $0 != .DG3 && $0 != .DG4 }
                        }
                    } else if let dg14 = dg as? DataGroup14 {
                        self.caHandler = ChipAuthenticationHandler(dg14: dg14, tagReader: (self.tagReader)!)
                        
                        if caHandler?.isChipAuthenticationSupported ?? false {
                            
                            readNextDG = false
                            self.caHandler?.doChipAuthentication() { [unowned self] (success) in
                                self.passport.chipAuthenticationStatus = .success

                                self.readNextDataGroup(completedReadingGroups: completed)
                            }
                        }
                    }

                } catch let error as NFCSDKError {
                    Log.error( "TagError reading tag - \(error)" )
                } catch let error {
                    Log.error( "Unexpected error reading tag - \(error)" )
                }

                self.dataGroupsToRead.removeFirst()
                self.elementReadAttempts = 0
                if readNextDG {
                    self.readNextDataGroup(completedReadingGroups: completed)
                }
                
            } else {
                let errMsg = err?.value ?? "Unknown  error"
                Log.error( "ERROR - \(errMsg)" )
                if errMsg == "Session invalidated" || errMsg == "Class not supported" || errMsg == "Tag connection lost" || errMsg == "sw1 - 0x6A, sw2 - 0x82" {
                    if self.elementReadAttempts < 3 {
                        self.readNextDataGroup(completedReadingGroups: completed)
                    } else {
                        if self.caHandler != nil {
                            self.caHandler = nil
                            completed(nil)
                        } else {
                            self.dataGroupsToRead.removeAll()
                            completed( err )
                        }
                    }
                } else if errMsg == "Security status not satisfied" || errMsg == "File not found" {
                    self.dataGroupsToRead.removeFirst()
                    completed(nil)
                } else if errMsg == "SM data objects incorrect" || errMsg == "Class not supported" {
                    completed(nil)
                } else if errMsg.hasPrefix( "Wrong length" ) || errMsg.hasPrefix( "End of file" ) {
                    self.tagReader?.reduceDataReadingAmount()
                    completed(nil)
                } else {
                    if self.elementReadAttempts > 3 {
                        self.dataGroupsToRead.removeFirst()
                        self.elementReadAttempts = 0
                    }
                    self.readNextDataGroup(completedReadingGroups: completed)
                }
            }
        }
    }
}
#endif
