//
//  SOD.swift
//
//  Created by OCR Labs on 01/02/2021.
//

import Foundation
import OpenSSL


@available(iOS 13, macOS 10.15, *)
class SOD : DataGroup {
    
    public private(set) var pkcs7CertificateData : [UInt8] = []
    private var asn1 : ASN1Item!
    private var pubKey : OpaquePointer?
    
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
        self.pkcs7CertificateData = body
        datagroupType = .SOD
    }
    
    deinit {
        if ( pubKey != nil ) {
            EVP_PKEY_free(pubKey);
        }
    }

    override func parse(_ data: [UInt8]) throws {
        let p = SimpleASN1DumpParser()
        asn1 = try p.parse(data: Data(body))
    }
    
    func getPublicKey( ) throws -> OpaquePointer {
        
        if let key = pubKey {
            return key
        }
        
        let certs = try OpenSSLUtils.getX509CertificatesFromPKCS7(pkcs7Der:Data(pkcs7CertificateData))
        if let key = X509_get_pubkey (certs[0].cert) {
            pubKey = key
            return key
        }
        
        throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Unable to get public key")
    }
    
    
    func getEncapsulatedContent() throws -> Data {
        guard let signedData = asn1.getChild(1)?.getChild(0),
              let encContent = signedData.getChild(2)?.getChild(1),
              let content = encContent.getChild(0) else {
            
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        var sigData : Data?
        if content.type.hasPrefix("OCTET STRING" ) {
            sigData = Data(hexRepToBin( content.value ))
        }
        
        guard let ret = sigData else { throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("noDataReturned") }
        return ret
    }
    
    func getEncapsulatedContentDigestAlgorithm() throws -> String {
        guard let signedData = asn1.getChild(1)?.getChild(0),
              let digestAlgo = signedData.getChild(1)?.getChild(0)?.getChild(0) else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        return String(digestAlgo.value)
    }
    
    func getSignedAttributes( ) throws -> Data {
        
        guard let signedData = asn1.getChild(1)?.getChild(0),
              let signerInfo = signedData.getChild(4),
              let signedAttrs = signerInfo.getChild(0)?.getChild(3) else {
            
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        var bytes = [UInt8](self.pkcs7CertificateData[signedAttrs.pos ..< signedAttrs.pos + signedAttrs.headerLen + signedAttrs.length])
        
        if bytes[0] == 0xA0 {
            bytes[0] = 0x31
        }
        let signedAttribs = Data(bytes)
        
        return signedAttribs
    }
    
    func getMessageDigestFromSignedAttributes( ) throws -> Data {
        
        guard let signedData = asn1.getChild(1)?.getChild(0),
              let signerInfo = signedData.getChild(4),
              let signedAttrs = signerInfo.getChild(0)?.getChild(3) else {
            
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        var sigData : Data?
        for i in 0 ..< signedAttrs.getNumberOfChildren() {
            let attrObj = signedAttrs.getChild(i)
            if attrObj?.getChild(0)?.value == "messageDigest" {
                if let set = attrObj?.getChild(1),
                   let digestVal = set.getChild(0) {
                    
                    if digestVal.type.hasPrefix("OCTET STRING" ) {
                        sigData = Data(hexRepToBin( digestVal.value ) )
                    }
                }
            }
        }
        
        guard let messageDigest = sigData else { throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("No messageDigest Returned") }
        
        return messageDigest
    }
    
    func getSignature( ) throws -> Data {
        
        guard let signedData = asn1.getChild(1)?.getChild(0),
              let signerInfo = signedData.getChild(4),
              let signature = signerInfo.getChild(0)?.getChild(5) else {
            
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        var sigData : Data?
        if signature.type.hasPrefix("OCTET STRING" ) {
            sigData = Data(hexRepToBin( signature.value ))
        }
        
        guard let ret = sigData else { throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("noDataReturned") }
        return ret
    }
    
    func getSignatureAlgorithm( ) throws -> String {
        
        guard let signedData = asn1.getChild(1)?.getChild(0),
              let signerInfo = signedData.getChild(4),
              let signatureAlgo = signerInfo.getChild(0)?.getChild(4)?.getChild(0) else {
            
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        return signatureAlgo.value
    }
}
