Pod::Spec.new do |spec|

  spec.name         = "NFCSDK"
  spec.version      = "1.1.4"
  spec.summary      = "This package handles reading an NFC Enabled passport using iOS 13 CoreNFC APIS"

  spec.homepage     = "https://github.com/actualfan/NFCSDK"
  spec.license      = "MIT"
  spec.author       = { "OCR Labs" => "leone.ma@ocrlabs.com" }
  spec.platform = :ios
  spec.ios.deployment_target = "12.0"

  spec.source       = { :git => "https://github.com/actualfan/NFCSDK.git", :tag => "#{spec.version}" }

  spec.source_files  = "Sources/**/*.{swift}"

  spec.swift_version = "5.0"

  spec.dependency "OpenSSL-Universal", '1.1.180'
  spec.xcconfig          = { 'OTHER_LDFLAGS' => '-weak_framework CryptoKit -weak_framework CoreNFC',
                             'ENABLE_BITCODE' => '"NO' }

  spec.pod_target_xcconfig = {
    'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64'
  }
  spec.user_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }

end
