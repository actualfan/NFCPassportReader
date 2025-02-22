//
//  DataGroup2.swift
//
//  Created by OCR Labs on 01/02/2021.
//

import Foundation

#if !os(macOS)
import UIKit
#endif

@available(iOS 13, macOS 10.15, *)
public class DataGroup2 : DataGroup {
    public private(set) var nrImages : Int = 0
    public private(set) var versionNumber : Int = 0
    public private(set) var lengthOfRecord : Int = 0
    public private(set) var numberOfFacialImages : Int = 0
    public private(set) var facialRecordDataLength : Int = 0
    public private(set) var nrFeaturePoints : Int = 0
    public private(set) var gender : Int = 0
    public private(set) var eyeColor : Int = 0
    public private(set) var hairColor : Int = 0
    public private(set) var featureMask : Int = 0
    public private(set) var expression : Int = 0
    public private(set) var poseAngle : Int = 0
    public private(set) var poseAngleUncertainty : Int = 0
    public private(set) var faceImageType : Int = 0
    public private(set) var imageDataType : Int = 0
    public private(set) var imageWidth : Int = 0
    public private(set) var imageHeight : Int = 0
    public private(set) var imageColorSpace : Int = 0
    public private(set) var sourceType : Int = 0
    public private(set) var deviceType : Int = 0
    public private(set) var quality : Int = 0
    public private(set) var imageData : [UInt8] = []
    
    
#if !os(macOS)
func getImage() -> UIImage? {
        if imageData.count == 0 {
            return nil
        }
        
        let image = UIImage(data:Data(imageData) )
        return image
    }
#endif

    required init( _ data : [UInt8] ) throws {
        try super.init(data)
        datagroupType = .DG2
    }
    
    override func parse(_ data: [UInt8]) throws {
        var tag = try getNextTag()
        if tag != 0x7F61 {
            throw NFCSDKError.InvalidResponse
        }
        _ = try getNextLength()
        
        tag = try getNextTag()
        if  tag != 0x02 {
            throw NFCSDKError.InvalidResponse
        }
        nrImages = try Int(getNextValue()[0])
        
        tag = try getNextTag()
        if tag != 0x7F60 {
            throw NFCSDKError.InvalidResponse
        }
        _ = try getNextLength()
        
        tag = try getNextTag()
        if tag != 0xA1 {
            throw NFCSDKError.InvalidResponse
        }
        _ = try getNextValue()
        
        tag = try getNextTag()
        if tag != 0x5F2E && tag != 0x7F2E {
            throw NFCSDKError.InvalidResponse
        }
        let value = try getNextValue()
        
        try parseISO19794_5( data:value )
    }
    
    func parseISO19794_5( data : [UInt8] ) throws {
        if data[0] != 0x46 && data[1] != 0x41 && data[2] != 0x43 && data[3] != 0x00 {
            throw NFCSDKError.InvalidResponse
        }
        
        var offset = 4
        versionNumber = binToInt(data[offset..<offset+4])
        offset += 4
        lengthOfRecord = binToInt(data[offset..<offset+4])
        offset += 4
        numberOfFacialImages = binToInt(data[offset..<offset+2])
        offset += 2
        
        facialRecordDataLength = binToInt(data[offset..<offset+4])
        offset += 4
        nrFeaturePoints = binToInt(data[offset..<offset+2])
        offset += 2
        gender = binToInt(data[offset..<offset+1])
        offset += 1
        eyeColor = binToInt(data[offset..<offset+1])
        offset += 1
        hairColor = binToInt(data[offset..<offset+1])
        offset += 1
        featureMask = binToInt(data[offset..<offset+3])
        offset += 3
        expression = binToInt(data[offset..<offset+2])
        offset += 2
        poseAngle = binToInt(data[offset..<offset+3])
        offset += 3
        poseAngleUncertainty = binToInt(data[offset..<offset+3])
        offset += 3
        
        offset += nrFeaturePoints * 8
        
        faceImageType = binToInt(data[offset..<offset+1])
        offset += 1
        imageDataType = binToInt(data[offset..<offset+1])
        offset += 1
        imageWidth = binToInt(data[offset..<offset+2])
        offset += 2
        imageHeight = binToInt(data[offset..<offset+2])
        offset += 2
        imageColorSpace = binToInt(data[offset..<offset+1])
        offset += 1
        sourceType = binToInt(data[offset..<offset+1])
        offset += 1
        deviceType = binToInt(data[offset..<offset+2])
        offset += 2
        quality = binToInt(data[offset..<offset+2])
        offset += 2
        
        
        let jpegHeader : [UInt8] = [0xff,0xd8,0xff,0xe0,0x00,0x10,0x4a,0x46,0x49,0x46]
        let jpeg2000BitmapHeader : [UInt8] = [0x00,0x00,0x00,0x0c,0x6a,0x50,0x20,0x20,0x0d,0x0a]
        let jpeg2000CodestreamBitmapHeader : [UInt8] = [0xff,0x4f,0xff,0x51]
        
        if [UInt8](data[offset..<offset+jpegHeader.count]) != jpegHeader &&
            [UInt8](data[offset..<offset+jpeg2000BitmapHeader.count]) != jpeg2000BitmapHeader &&
            [UInt8](data[offset..<offset+jpeg2000CodestreamBitmapHeader.count]) != jpeg2000CodestreamBitmapHeader {
            throw NFCSDKError.UnknownImageFormat
        }
        
        imageData = [UInt8](data[offset...])
    }
}
