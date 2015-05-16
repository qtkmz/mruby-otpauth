assert('OTPAuth#provisioning_uri; with issuer') do
  totp = OTPAuth::TOTP.new('base32_secret')
  assertion_string totp.provisioning_uri('test_label', 'test_issuer'),
    'otpauth://totp/test_label?secret=base32_secret&issuer=test_issuer'
end

assert('OTPAuth#provisioning_uri; no issuer') do
  totp = OTPAuth::TOTP.new('base32_secret')
  assertion_string totp.provisioning_uri('test_label'),
    'otpauth://totp/test_label?secret=base32_secret'
end

assert('OTPAuth#generate; algorithm => sha1') do
  totp = OTPAuth::TOTP.new(Base32.encode("Hello!\xDE\xAD\xBE\xEF"))
  assertion_string totp.generate(1234567890), '742275'
end

assert('OTPAuth#generate; algorithm => sha256') do
  totp = OTPAuth::TOTP.new(Base32.encode("Hello!\xDE\xAD\xBE\xEF"), :algorithm => 'sha256')
  assertion_string totp.generate(1234567890), '488545'
end

assert('OTPAuth#generate; algorithm => sha512') do
  totp = OTPAuth::TOTP.new(Base32.encode("Hello!\xDE\xAD\xBE\xEF"), :algorithm => 'sha512')
  assertion_string totp.generate(1234567890), '136418'
end

