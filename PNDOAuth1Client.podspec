Pod::Spec.new do |s|
  s.name             = 'PNDOAuth1Client'
  s.license          = 'Apache'
  s.version          = '0.6'
  s.summary          = 'A flexible AFNetworking client for authenticating OAuth 1.0 requests.'
  s.homepage         = 'https://github.com/pandamonia/PNDOAuth1Client'
  s.authors          = { 'Zachary Waldowski' => 'zwaldowski@gmail.com',
                         'Alexsander Akers' => 'a2@pandamonia.us' }
  s.source           = { :git => 'https://github.com/pandamonia/PNDOAuth1Client.git', :branch => 'master' }
  s.osx.source_files = 'PNDOAuth1Client/*.{h,m}', 'PNDOAuth1Client/Mac/*.{h,m}'
  s.ios.source_files = 'PNDOAuth1Client/*.{h,m}', 'PNDOAuth1Client/iOS/*.{h,m}'
  s.osx.resources    = 'PNDOAuth1Client/Mac/*.xib'
  s.ios.resources    = 'PNDOAuth1Client/iOS/*.xib'
  s.requires_arc     = true
  s.frameworks       = 'Security'
  s.dependency         'AFNetworking'
end
