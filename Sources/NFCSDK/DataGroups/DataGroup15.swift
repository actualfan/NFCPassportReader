//
//  DataGroup15.swift
//
//  Created by OCR Labs on 01/02/2021.
//

import Foundation
import OpenSSL

@available(iOS 13, macOS 10.15, *)
public class DataGroup15 : DataGroup {
    
    public private(set) var rsaPublicKey : OpaquePointer?
    public private(set) var ecdsaPublicKey : OpaquePointer?
    
    deinit {
        if ( ecdsaPublicKey != nil ) {
            EVP_PKEY_free(ecdsaPublicKey);
        }
        if ( rsaPublicKey != nil ) {
            EVP_PKEY_free(rsaPublicKey);
        }
    }
    
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
        datagroupType = .DG15
    }
    
    
    override func parse(_ data: [UInt8]) throws {
        
        if let key = try? OpenSSLUtils.readECPublicKey( data:body ) {
            ecdsaPublicKey = key
        } else if let key = try? OpenSSLUtils.readRSAPublicKey( data:body ) {
            
            rsaPublicKey = key
        }
    }
}
