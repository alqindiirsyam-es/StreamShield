#
#  Be sure to run `pod spec lint PalioLite.podspec' to ensure this is a
#  valid spec and to remove all comments including this before submitting the spec.
#
#  To learn more about Podspec attributes see https://guides.cocoapods.org/syntax/podspec.html
#  To see working Podspecs in the CocoaPods repo see https://github.com/CocoaPods/Specs/
#

Pod::Spec.new do |spec|
  spec.name         = "StreamShield"
  spec.version      = "1.0.0"
  spec.summary      = "StreamShield Framework"
  spec.description  = <<-DESC
  StreamShield Framework, embed Security features into your mobile apps within minutes...
                   DESC

  spec.homepage     = "https://nexilis.io/"
  spec.license      = "MIT"
  spec.author       = { "Yayan D Wicaksono" => "ya2n.wicaksono@gmail.com" }
  spec.ios.deployment_target = "14.0"
  spec.source       = { :path => '.' }
  spec.source_files = 'StreamShield/Source/**/*'
  spec.resource_bundles = { 'StreamShield' => ['StreamShield/Resource/**/*']}
  spec.swift_version = '5.5.1'
  spec.dependency 'nuSDKService', '4.0.7'
  spec.ios.vendored_frameworks = "StreamShield.framework"
  spec.pod_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64', 'ENABLE_BITCODE' => 'NO' }
  spec.user_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64', 'ENABLE_BITCODE' => 'NO' }
end
