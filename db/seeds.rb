# This file should contain all the record creation needed to seed the database with its default values.
# The data can then be loaded with the rake db:seed (or created alongside the db with db:setup).
#
# Examples:
#
#   cities = City.create([{ name: 'Chicago' }, { name: 'Copenhagen' }])
#   Mayor.create(name: 'Emanuel', city: cities.first)
require 'openssl'
user = CreateAdminService.new.call
puts 'CREATED ADMIN USER: ' << user.email

Dir.mkdir('./ssl', 0700)
Dir.mkdir('./ssl/CA', 0700)
Dir.mkdir('./ssl/CA/certs', 0700)
Dir.mkdir('./ssl/CA/newcerts', 0700)
Dir.mkdir('./ssl/CA/private', 0700)
open "./ssl/CA/serial", 'w' do |io| io.write "01" end
open "./ssl/CA/index.txt", 'w' do |io| io.write "" end  

ca_key = OpenSSL::PKey::RSA.new 2048
ca_name = OpenSSL::X509::Name.parse 'CN=ca/DC=example'

ca_cert = OpenSSL::X509::Certificate.new
ca_cert.serial = 0
ca_cert.version = 2
ca_cert.not_before = Time.now
ca_cert.not_after = Time.now + 86400

ca_cert.public_key = ca_key.public_key
ca_cert.subject = ca_name
ca_cert.issuer = ca_name

extension_factory = OpenSSL::X509::ExtensionFactory.new
extension_factory.subject_certificate = ca_cert
extension_factory.issuer_certificate = ca_cert

ca_cert.add_extension    extension_factory.create_extension('subjectKeyIdentifier', 'hash')
ca_cert.add_extension    extension_factory.create_extension('basicConstraints', 'CA:TRUE', true)
ca_cert.add_extension    extension_factory.create_extension('keyUsage', 'cRLSign,keyCertSign', true)
ca_cert.sign ca_key, OpenSSL::Digest::SHA1.new
open './ssl/CA/cacert.pem', 'w' do |io|
  io.write ca_cert.to_pem
end
pass_phrase = Rails.application.secrets.pass_phrase
cipher = OpenSSL::Cipher.new 'AES-128-CBC'
key_secure = ca_key.export cipher, pass_phrase
open "./ssl/CA/private/cakey.pem", 'w' do |io| io.write key_secure end