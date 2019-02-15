require "openssl"
require "base64"

# A globally-unique, encrypted Nonce, known in the SQRL protocol as a "nut"
struct Sqrl::Nut
  class_property global_counter = 0_u32
  property aes_key_block : OpenSSL::Cipher

  def initialize
    @aes_key_block = OpenSSL::Cipher.new CIPHER_NAME
    @aes_key_block.random_key
  end

  def generate(remote_address : String) : String
    @aes_key_block.reset
    @aes_key_block.update data: parse_ip remote_address
    now = Bytes.new 4
    IO::ByteFormat::LittleEndian.encode Time.now.to_unix.to_u32, now
    @aes_key_block.update now
    counter_as_bytes = Bytes.new 4
    IO::ByteFormat::LittleEndian.encode int: global_counter += 1, bytes: counter_as_bytes
    @aes_key_block.update counter_as_bytes
    @aes_key_block.update Random::Secure.random_bytes 4
    Base64.urlsafe_encode @aes_key_block.final
  end

  # Gather 4 bytes of entropy from the given IP address.
  #
  # Only 4 bytes are used, even in the case of an IPv6 address, because that's
  # all an IPv4 address provides.
  private def parse_ip(address : String) : StaticArray(UInt8, 4)
    address = if address.includes? ']'
                       address.split(']').first.gsub('[', "")
                     else
                       address.split(':').first
                     end
    ip = Socket::IPAddress.new(address, port: 0)
    if ip.family.inet?
      bytes = ip.address.split('.').map { |byte| byte.to_u8 }
      StaticArray(UInt8, 4).new { |i| bytes[i] }
    elsif ip.family.inet6?
      split = ip.address.split(':')
      StaticArray(UInt8, 4).new { |i| split[i % 2].to_u8 << (i // 2) }
    end
  end

  abstract class Exception < ::Exception
  end

  class InvalidIPAddress < Exception
    def initialize(ip)
      super "#{ip.inspect} is not a valid IP Address!"
    end
  end
end
