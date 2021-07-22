//
//  OpenSSLUtils.swift
//  NFCSDK
//
//  Created by OCR Labs on 29/10/2019.
//

import Foundation
import OpenSSL
import CryptoTokenKit

@available(iOS 13, macOS 10.15, *)
public class OpenSSLUtils {
    private static var loaded = false
    
    public static func getOpenSSLError() -> String {
        
        guard let out = BIO_new(BIO_s_mem()) else { return "Unknown" }
        defer { BIO_free(out) }
        
        ERR_print_errors( out )
        let str = OpenSSLUtils.bioToString( bio:out )
        
        return str
    }
    
    static func bioToString( bio : OpaquePointer ) -> String {
        
        let len = BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nil)
        var buffer = [CChar](repeating: 0, count: len+1)
        BIO_read(bio, &buffer, Int32(len))
        
        buffer[len] = 0
        let ret = String(cString:buffer)
        return ret
    }
    
    static func X509ToPEM( x509: OpaquePointer ) -> String {
        
        let out = BIO_new(BIO_s_mem())!
        defer { BIO_free( out) }
        
        PEM_write_bio_X509(out, x509);
        let str = OpenSSLUtils.bioToString( bio:out )
        
        return str
    }
    
    static func pubKeyToPEM( pubKey: OpaquePointer ) -> String {
        
        let out = BIO_new(BIO_s_mem())!
        defer { BIO_free( out) }
        
        PEM_write_bio_PUBKEY(out, pubKey);
        let str = OpenSSLUtils.bioToString( bio:out )
        
        return str
    }
    
    static func privKeyToPEM( privKey: OpaquePointer ) -> String {
        
        let out = BIO_new(BIO_s_mem())!
        defer { BIO_free( out) }

        PEM_write_bio_PrivateKey(out, privKey, nil, nil, 0, nil, nil)
        let str = OpenSSLUtils.bioToString( bio:out )
        
        return str
    }
    
    static func pkcs7DataToPEM( pkcs7: Data ) -> String {
        
        let inf = BIO_new(BIO_s_mem())!
        defer { BIO_free( inf) }
        let out = BIO_new(BIO_s_mem())!
        defer { BIO_free( out) }
        
        let _ = pkcs7.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: Int8.self), Int32(pkcs7.count))
        }
        guard let p7 = d2i_PKCS7_bio(inf, nil) else { return "" }
        defer { PKCS7_free(p7) }
        
        PEM_write_bio_PKCS7(out, p7)
        let str = OpenSSLUtils.bioToString( bio:out )
        return str
    }
    
    
    static func getX509CertificatesFromPKCS7( pkcs7Der : Data ) throws -> [X509Wrapper] {
        
        guard let inf = BIO_new(BIO_s_mem()) else { throw OpenSSLError.UnableToGetX509CertificateFromPKCS7("Unable to allocate input buffer") }
        defer { BIO_free(inf) }
        let _ = pkcs7Der.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: Int8.self), Int32(pkcs7Der.count))
        }
        guard let p7 = d2i_PKCS7_bio(inf, nil) else { throw OpenSSLError.UnableToGetX509CertificateFromPKCS7("Unable to read PKCS7 DER data") }
        defer { PKCS7_free(p7) }
        
        var certs : OpaquePointer? = nil
        let i = OBJ_obj2nid(p7.pointee.type);
        switch (i) {
            case NID_pkcs7_signed:
                if let sign = p7.pointee.d.sign {
                    certs = sign.pointee.cert
                }
                break;
            case NID_pkcs7_signedAndEnveloped:
                if let signed_and_enveloped = p7.pointee.d.signed_and_enveloped {
                    certs = signed_and_enveloped.pointee.cert
                }
                break;
            default:
                break;
        }
        
        var ret = [X509Wrapper]()
        if let certs = certs  {
            let certCount = sk_X509_num(certs)
            for i in 0 ..< certCount {
                let x = sk_X509_value(certs, i);
                if let x509 = X509Wrapper(with:x) {
                    ret.append( x509 )
                }
            }
        }
        
        return ret
    }
    
    static func verifyTrustAndGetIssuerCertificate( x509 : X509Wrapper, CAFile : URL ) -> Result<X509Wrapper, OpenSSLError> {
                
        guard let cert_ctx = X509_STORE_new() else { return .failure(OpenSSLError.UnableToVerifyX509CertificateForSOD("Unable to create certificate store")) }
        defer { X509_STORE_free(cert_ctx) }
        
        X509_STORE_set_verify_cb(cert_ctx) { (ok, ctx) -> Int32 in
            let cert_error = X509_STORE_CTX_get_error(ctx)
            
            if ok == 0 {
                let errVal = X509_verify_cert_error_string(Int(cert_error))
                let val = errVal!.withMemoryRebound(to: CChar.self, capacity: 1000) { (ptr) in
                    return String(cString: ptr)
                }
                
                Log.error("error \(cert_error) at \(X509_STORE_CTX_get_error_depth(ctx)) depth lookup:\(val)" )
            }
            
            return ok;
        }
        
        guard let lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file()) else { return .failure(OpenSSLError.UnableToVerifyX509CertificateForSOD("Unable to add lookup to store")) }
        
        var rc = X509_LOOKUP_ctrl(lookup, X509_L_FILE_LOAD, CAFile.path, Int(X509_FILETYPE_PEM), nil)
        
        guard let store = X509_STORE_CTX_new() else {
            return .failure(OpenSSLError.UnableToVerifyX509CertificateForSOD("Unable to create new X509_STORE_CTX"))
        }
        defer { X509_STORE_CTX_free(store) }
        
        X509_STORE_set_flags(cert_ctx, 0)
        rc = X509_STORE_CTX_init(store, cert_ctx, x509.cert, nil)
        if rc == 0 {
            return .failure(OpenSSLError.UnableToVerifyX509CertificateForSOD("Unable to initialise X509_STORE_CTX"))
        }

        let i = X509_verify_cert(store);
        if i != 1 {
            let err = X509_STORE_CTX_get_error(store)
            
            return .failure(OpenSSLError.UnableToVerifyX509CertificateForSOD("Verification of certificate failed - errorCode \(err)"))
        }
        
        let chain = X509_STORE_CTX_get1_chain(store);
        let nrCertsInChain = sk_X509_num(chain)
        if nrCertsInChain > 1 {
            let cert = sk_X509_value(chain, nrCertsInChain-1)
            if let certWrapper = X509Wrapper(with: cert) {
                return .success( certWrapper )
            }
        }
        
        return .failure(OpenSSLError.UnableToVerifyX509CertificateForSOD("Unable to get issuer certificate - not found"))
    }
    
    
    static func verifyAndReturnSODEncapsulatedDataUsingCMS( sod : SOD ) throws -> Data {
        
        guard let inf = BIO_new(BIO_s_mem()) else { throw OpenSSLError.VerifyAndReturnSODEncapsulatedData("CMS - Unable to allocate input buffer") }
        defer { BIO_free(inf) }
        
        guard let out = BIO_new(BIO_s_mem()) else { throw OpenSSLError.VerifyAndReturnSODEncapsulatedData("CMS - Unable to allocate output buffer") }
        defer { BIO_free(out) }
        
        let _ = sod.body.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(sod.body.count))
        }
        
        guard let cms = d2i_CMS_bio(inf, nil) else {
            throw OpenSSLError.VerifyAndReturnSODEncapsulatedData("CMS - Verification of P7 failed - unable to create CMS")
        }
        defer { CMS_ContentInfo_free(cms) }
        
        let flags : UInt32 = UInt32(CMS_NO_SIGNER_CERT_VERIFY)
        
        if CMS_verify(cms, nil, nil, nil, out, flags) == 0 {
            throw OpenSSLError.VerifyAndReturnSODEncapsulatedData("CMS - Verification of P7 failed - unable to verify signature")
        }
        
        Log.debug("Verification successful\n");
        let len = BIO_ctrl(out, BIO_CTRL_PENDING, 0, nil)
        var buffer = [UInt8](repeating: 0, count: len)
        BIO_read(out, &buffer, Int32(len))
        let sigData = Data(buffer)
        
        return sigData
    }
    
    
    static func verifyAndReturnSODEncapsulatedData( sod : SOD ) throws -> Data {
        
        let encapsulatedContent = try sod.getEncapsulatedContent()
        let signedAttribsHashAlgo = try sod.getEncapsulatedContentDigestAlgorithm()
        let signedAttributes = try sod.getSignedAttributes()
        let messageDigest = try sod.getMessageDigestFromSignedAttributes()
        let signature = try sod.getSignature()
        let sigType = try sod.getSignatureAlgorithm()
        
        let pubKey = try sod.getPublicKey()
        
        let mdHash : Data = try Data(calcHash(data: [UInt8](encapsulatedContent), hashAlgorithm: signedAttribsHashAlgo))
        
        if messageDigest != mdHash {
            throw OpenSSLError.VerifyAndReturnSODEncapsulatedData("messageDigest Hash doesn't hatch that of the signed attributes")
        }
        
        if  !verifySignature( data : [UInt8](signedAttributes), signature : [UInt8](signature), pubKey : pubKey, digestType: sigType ) {
            
            throw OpenSSLError.VerifyAndReturnSODEncapsulatedData("Unable to verify signature for signed attributes")
        }
        
        return encapsulatedContent
    }
    
    static func ASN1Parse( data: Data ) throws -> String {
        
        guard let out = BIO_new(BIO_s_mem()) else { throw OpenSSLError.UnableToParseASN1("Unable to allocate output buffer") }
        defer { BIO_free(out) }
        
        var parsed : String = ""
        let _ = try data.withUnsafeBytes { (ptr) in
            let rc = ASN1_parse_dump(out, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), data.count, 0, 0)
            if rc == 0 {
                let str = OpenSSLUtils.getOpenSSLError()
                Log.debug( "Failed to parse ASN1 Data - \(str)" )
                throw OpenSSLError.UnableToParseASN1("Failed to parse ASN1 Data - \(str)")
            }
            
            parsed = bioToString(bio: out)
        }
        
        return parsed
    }
    
    
    
    static func readRSAPublicKey( data : [UInt8] ) throws -> OpaquePointer? {
        
        guard let inf = BIO_new(BIO_s_mem()) else { throw OpenSSLError.UnableToReadECPublicKey("Unable to allocate output buffer") }
        defer { BIO_free(inf) }
        
        let _ = data.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(data.count))
        }
        
        guard let rsakey = d2i_RSA_PUBKEY_bio(inf, nil) else { throw OpenSSLError.UnableToReadECPublicKey("Failed to load") }
        defer{ RSA_free(rsakey) }
        
        let key = EVP_PKEY_new()
        if EVP_PKEY_set1_RSA(key, rsakey) != 1 {
            EVP_PKEY_free(key)
            throw OpenSSLError.UnableToReadECPublicKey("Failed to load")
        }
        return key
    }
    
    static func decryptRSASignature( signature : Data, pubKey : OpaquePointer ) throws -> [UInt8] {
        
        let pad = RSA_NO_PADDING
        let rsa = EVP_PKEY_get1_RSA( pubKey )
        
        let keysize = RSA_size(rsa);
        var outputBuf = [UInt8](repeating: 0, count: Int(keysize))
        
        var outlen : Int32 = 0
        let _ = signature.withUnsafeBytes { (sigPtr) in
            let _ = outputBuf.withUnsafeMutableBytes { (outPtr) in
                outlen = RSA_public_decrypt(Int32(signature.count), sigPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), outPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), rsa, pad)
            }
        }
        
        if outlen == 0 {
            let error = OpenSSLUtils.getOpenSSLError()
            throw OpenSSLError.UnableToDecryptRSASignature( "RSA_public_decrypt failed - \(error)" )
        }
        
        return outputBuf
    }
    
    static func readECPublicKey( data : [UInt8] ) throws -> OpaquePointer? {
        
        guard let inf = BIO_new(BIO_s_mem()) else { throw OpenSSLError.UnableToReadECPublicKey("Unable to allocate output buffer") }
        defer { BIO_free(inf) }
        
        let _ = data.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(data.count))
        }
        
        guard let eckey = d2i_EC_PUBKEY_bio(inf, nil) else { throw OpenSSLError.UnableToReadECPublicKey("Failed to load") }
        defer{ EC_KEY_free(eckey) }
        
        guard let outf = BIO_new(BIO_s_mem()) else { throw OpenSSLError.UnableToReadECPublicKey("Unable to allocate output buffer") }
        defer { BIO_free(outf) }
        let _ = PEM_write_bio_EC_PUBKEY(outf, eckey);
        let pemKey = PEM_read_bio_PUBKEY(outf, nil, nil, nil)
        
        return pemKey
    }
    
    
    static func verifyECDSASignature( publicKey:OpaquePointer, signature: [UInt8], data: [UInt8] ) -> Bool {
                
        let ecsig = ECDSA_SIG_new()
        defer { ECDSA_SIG_free(ecsig) }
        let sigData = signature
        sigData.withUnsafeBufferPointer { (unsafeBufPtr) in
            let unsafePointer = unsafeBufPtr.baseAddress!
            let r = BN_bin2bn(unsafePointer, 32, nil)
            let s = BN_bin2bn(unsafePointer + 32, 32, nil)
            ECDSA_SIG_set0(ecsig, r, s)
        }
        let sigSize = i2d_ECDSA_SIG(ecsig, nil)
        var derBytes = [UInt8](repeating: 0, count: Int(sigSize))
        derBytes.withUnsafeMutableBufferPointer { (unsafeBufPtr) in
            var unsafePointer = unsafeBufPtr.baseAddress
            let _ = i2d_ECDSA_SIG(ecsig, &unsafePointer)
        }
        
        let rc = verifySignature(data: data, signature: derBytes, pubKey: publicKey, digestType: "")
        return rc
    }
    
    static func verifySignature( data : [UInt8], signature : [UInt8], pubKey : OpaquePointer, digestType: String ) -> Bool {
        
        var digest = "sha256"
        let digestType = digestType.lowercased()
        if digestType.contains( "sha1" ) {
            digest = "sha1"
        } else if digestType.contains( "sha224" ) {
            digest = "sha224"
        } else if digestType.contains( "sha256" ) || digestType.contains( "rsassapss" ) {
            digest = "sha256"
        } else if digestType.contains( "sha384" ) {
            digest = "sha384"
        } else if digestType.contains( "sha512" ) {
            digest = "sha512"
        }
        
        var fixedSignature = signature
        if digestType.contains( "ecdsa" ) {
            if let sequence = TKBERTLVRecord(from:Data(signature)),
               sequence.tag == 0x30,
               let intRecords = TKBERTLVRecord.sequenceOfRecords(from: sequence.value),
               intRecords.count == 2 {
                
                var newIntRecords = [TKTLVRecord]()
                if intRecords[0].value[0] == 0x00 {
                    newIntRecords.append( TKBERTLVRecord( tag: intRecords[0].tag, value: intRecords[0].value[1...]) )
                }
                if intRecords[1].value[0] == 0x00 {
                    newIntRecords.append( TKBERTLVRecord( tag: intRecords[1].tag, value: intRecords[1].value[1...]) )
                }

                if newIntRecords.count == 2 {
                    let newSequence = TKBERTLVRecord( tag: sequence.tag, records: newIntRecords)
                    fixedSignature = [UInt8](newSequence.data)
                }
            }
        }
        
        let md = EVP_get_digestbyname(digest)
        
        let ctx = EVP_MD_CTX_new()
        var pkey_ctx : OpaquePointer?

        defer{ EVP_MD_CTX_free( ctx) }
        
        var nRes = EVP_DigestVerifyInit(ctx, &pkey_ctx, md, nil, pubKey)
        if ( nRes != 1 ) {
            return false;
        }
        
        if digestType.contains( "rsassapss" ) {
            EVP_PKEY_CTX_ctrl_str(pkey_ctx, "rsa_padding_mode", "pss" )
            EVP_PKEY_CTX_ctrl_str(pkey_ctx, "rsa_pss_saltlen", "auto" )
        }
        
        nRes = EVP_DigestUpdate(ctx, data, data.count);
        if ( nRes != 1 ) {
            return false;
        }
        
        nRes = EVP_DigestVerifyFinal(ctx, fixedSignature, fixedSignature.count);
        if (nRes != 1) {
            return false;
        }
        
        return true
    }

    @available(iOS 13, macOS 10.15, *)
    static func generateAESCMAC( key: [UInt8], message : [UInt8] ) -> [UInt8] {
        let ctx = CMAC_CTX_new();
        defer { CMAC_CTX_free(ctx) }
        var key = key
        
        var mac = [UInt8](repeating: 0, count: 32)
        var maclen : Int = 0
        
        if key.count == 16 {
            CMAC_Init(ctx, &key, key.count, EVP_aes_128_cbc(), nil)
        } else if key.count == 24 {
            CMAC_Init(ctx, &key, key.count, EVP_aes_192_cbc(), nil)
        } else if key.count == 32 {
            CMAC_Init(ctx, &key, key.count, EVP_aes_256_cbc(), nil)
        }
        CMAC_Update(ctx, message, message.count);
        CMAC_Final(ctx, &mac, &maclen);
        
        Log.verbose( "aesMac - mac - \(binToHexRep(mac))" )
        
        return [UInt8](mac[0..<maclen])
    }
    
    @available(iOS 13, macOS 10.15, *)
    static func asn1EncodeOID (oid : String) -> [UInt8] {
        
        let obj = OBJ_txt2obj( oid.cString(using: .utf8), 1)
        let payloadLen = i2d_ASN1_OBJECT(obj, nil)
        
        var data  = [UInt8](repeating: 0, count: Int(payloadLen))
        
        let _ = data.withUnsafeMutableBytes { (ptr) in
            var newPtr = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self)
            _ = i2d_ASN1_OBJECT(obj, &newPtr)
        }
        
        return data
    }

    @available(iOS 13, macOS 10.15, *)
    public static func getPublicKeyData(from key:OpaquePointer) -> [UInt8]? {
        var data : [UInt8] = []
        let v = EVP_PKEY_base_id( key )
        if v == EVP_PKEY_DH || v == EVP_PKEY_DHX {
            guard let dh = EVP_PKEY_get0_DH(key) else {
                return nil
            }
            var dhPubKey : OpaquePointer?
            DH_get0_key(dh, &dhPubKey, nil)
            
            let nrBytes = (BN_num_bits(dhPubKey)+7)/8
            data = [UInt8](repeating: 0, count: Int(nrBytes))
            _ = BN_bn2bin(dhPubKey, &data)
        } else if v == EVP_PKEY_EC {
            
            guard let ec = EVP_PKEY_get0_EC_KEY(key),
                let ec_pub = EC_KEY_get0_public_key(ec),
                let ec_group = EC_KEY_get0_group(ec) else {
                return nil
            }
            
            let form = EC_KEY_get_conv_form(ec)
            let len = EC_POINT_point2oct(ec_group, ec_pub, form, nil, 0, nil)
            data = [UInt8](repeating: 0, count: Int(len))
            if len == 0 {
                return nil
            }
            _ = EC_POINT_point2oct(ec_group, ec_pub, form, &data, len, nil)
        }
        
        return data
    }
    
    @available(iOS 13, macOS 10.15, *)
    public static func decodePublicKeyFromBytes(pubKeyData: [UInt8], params: OpaquePointer) -> OpaquePointer? {
        var pubKey : OpaquePointer?
        
        let keyType = EVP_PKEY_base_id( params )
        if keyType == EVP_PKEY_DH || keyType == EVP_PKEY_DHX {
            
            let dhKey = DH_new()
            defer{ DH_free(dhKey) }
            
            let bn = BN_bin2bn(pubKeyData, Int32(pubKeyData.count), nil)
            DH_set0_key(dhKey, bn, nil)

            pubKey = EVP_PKEY_new()
            guard EVP_PKEY_set1_DH(pubKey, dhKey) == 1 else {
                return nil
            }
        } else {
            let ec = EVP_PKEY_get1_EC_KEY(params)
            let group = EC_KEY_get0_group(ec);
            let ecp = EC_POINT_new(group);
            let key = EC_KEY_new();
            defer {
                EC_KEY_free(ec)
                EC_POINT_free(ecp)
                EC_KEY_free(key)
            }
            
            guard EC_POINT_oct2point(group, ecp, pubKeyData, pubKeyData.count, nil) == 1,
                EC_KEY_set_group(key, group) == 1,
                EC_KEY_set_public_key(key, ecp) == 1 else {
                
                return nil
            }
            
            pubKey = EVP_PKEY_new()
            guard EVP_PKEY_set1_EC_KEY(pubKey, key) == 1 else {
                return nil
            }
        }
        
        return pubKey
    }
    

    public static func computeSharedSecret( privateKeyPair: OpaquePointer, publicKey: OpaquePointer ) -> [UInt8] {
        
        var secret : [UInt8]
        let keyType = EVP_PKEY_base_id( privateKeyPair )
        if keyType == EVP_PKEY_DH || keyType == EVP_PKEY_DHX {
            let dh = EVP_PKEY_get1_DH(privateKeyPair);
            
            let dh_pub = EVP_PKEY_get1_DH(publicKey)
            var bn = BN_new()
            DH_get0_key( dh_pub, &bn, nil )
            
            secret = [UInt8](repeating: 0, count: Int(DH_size(dh)))
            let len = DH_compute_key(&secret, bn, dh);
            
            Log.verbose( "OpenSSLUtils.computeSharedSecret - DH secret len - \(len)" )
        } else {
            let ctx = EVP_PKEY_CTX_new(privateKeyPair, nil)
            defer{ EVP_PKEY_CTX_free(ctx) }
            
            if EVP_PKEY_derive_init(ctx) != 1 {
                Log.error( "ERROR - \(OpenSSLUtils.getOpenSSLError())" )
            }
            
            if EVP_PKEY_derive_set_peer( ctx, publicKey ) != 1 {
                Log.error( "ERROR - \(OpenSSLUtils.getOpenSSLError())" )
            }
            
            var keyLen = 0
            if EVP_PKEY_derive(ctx, nil, &keyLen) != 1 {
                Log.error( "ERROR - \(OpenSSLUtils.getOpenSSLError())" )
            }
            
            secret = [UInt8](repeating: 0, count: keyLen)
            if EVP_PKEY_derive(ctx, &secret, &keyLen) != 1 {
                Log.error( "ERROR - \(OpenSSLUtils.getOpenSSLError())" )
            }
        }
        return secret
    }
    
}
