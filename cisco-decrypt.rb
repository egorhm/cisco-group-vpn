require 'digest/sha1'
require 'openssl'
require 'optparse'

def hex_to_bin(data)
  data.scan(/../).map { |x| x.hex }.pack('c*')
end

def decrypt(data)
  if data.length < 48
    raise Exception.new("The data is too short")
  end

  data = hex_to_bin(data)

  key = data[0..19]
  sha_1 = data[20..39]
  pass = data[40..data.length]

  if sha_1 != Digest::SHA1.digest(pass)
    raise Exception.new("Broken string")
  end

  iv = key[0..7] #first 8 bytes

  arr = []

  arr << (key[19].unpack("C*")[0] + 1)
  p1 = key[0..18] + arr.pack('C')

  arr1 = []
  arr1 << (key[19].unpack("C*")[0] + 3)
  p2 = key[0..18] + arr1.pack('C')

  key_sha = Digest::SHA1.digest(p1)+Digest::SHA1.digest(p2)[0..3]

  cipher = OpenSSL::Cipher::Cipher.new("des3")
  cipher.key = key_sha
  cipher.iv = iv
  cipher_text = cipher.update(pass)
  cipher.decrypt

  cipher_text
end


options = {}

opt_parser = OptionParser.new do |opt|
  opt.banner = "Usage: cisco-solver COMMAND [MESSAGE]"
  opt.separator  ""
  opt.separator  "Options"

  opt.on("-d","--decrypt MESSAGE","specify the message to decrypt") do |message|
    options[:decrypt] = message
  end

  opt.on('-h', '--help', 'Displays Help') do
    puts opt
    exit
  end
end

opt_parser.parse!
puts decrypt(options[:decrypt]) if options[:decrypt]

