module OTPAuth
  class TOTP
    T0 = 0
    TIME_FMT = '%016X'

    def initialize(base32_secret, options = {})
      @base32_secret = base32_secret
      @algorithm = options[:algorithm] || 'sha1'
      @digits = options[:digits] || 6
      @period = options[:period] || 30
    end

    def generate(timestamp = Time.now.gmtime.to_i)
      tc = calc_time_counter(timestamp)

      packed_time = [TIME_FMT % tc].pack('H*')
      secret = Base32.decode(@base32_secret)
      digest = Digest::HMAC.digest(packed_time, secret, to_crypto_type(@algorithm))
      digest_bin = digest.unpack('C*')
      offset = digest_bin[-1] & 0xf

      otp_bin =
        ((digest_bin[offset] & 0x7f) << 24) |
        ((digest_bin[offset + 1] & 0xff) << 16) |
        ((digest_bin[offset + 2] & 0xff) << 8) |
        (digest_bin[offset + 3] & 0xff)

      otp_fmt = '%%0%dd' % @digits
      otp_fmt % [otp_bin % (10 ** @digits)]
    end

    def provisioning_uri(label, issuer = '')
      if issuer.empty?
        'otpauth://totp/%s?secret=%s' % [label, @base32_secret]
      else
        'otpauth://totp/%s?secret=%s&issuer=%s' % [label, @base32_secret, issuer]
      end
    end

    private
    def calc_time_counter(time)
      ((time - T0) / @period).floor
    end

    def to_crypto_type(crypto)
      case crypto.downcase
      when 'sha256'
        Digest::SHA256
      when 'sha512'
        Digest::SHA512
      else
        # default or hmacsha1
        Digest::SHA1
      end
    end
  end
end
