class Users::RegistrationsController < Devise::RegistrationsController
  require 'openssl'
  def create
    super # continue to devise registration to CREATE user
    key = OpenSSL::PKey::RSA.new 2048
    #logger.debug "#{resource.email}"

    #open "private_key.pem", 'w' do |io| io.write key.to_pem end
    #open 'public_key.pem', 'w' do |io| io.write key.public_key.to_pem end
    
    csr = OpenSSL::X509::Request.new
    csr.version = 0
    csr.subject = OpenSSL::X509::Name.parse "CN=ca/DC=example"
    csr.public_key = key.public_key
    csr.sign key, OpenSSL::Digest::SHA1.new
    
    pass_phrase = Rails.application.secrets.pass_phrase
    ca_cert = OpenSSL::X509::Certificate.new File.read './ssl/CA/cacert.pem'
    cakey_pem = File.read './ssl/CA/private/cakey.pem'
    ca_key = OpenSSL::PKey::RSA.new cakey_pem, pass_phrase
    
    csr_cert = OpenSSL::X509::Certificate.new
    csr_cert.serial = 0
    csr_cert.version = 2
    csr_cert.not_before = Time.now
    csr_cert.not_after = Time.now + 600

    csr_cert.subject = csr.subject
    csr_cert.public_key = csr.public_key
    csr_cert.issuer = ca_cert.subject

    extension_factory = OpenSSL::X509::ExtensionFactory.new
    extension_factory.subject_certificate = csr_cert
    extension_factory.issuer_certificate = ca_cert

    csr_cert.add_extension    extension_factory.create_extension('basicConstraints', 'CA:FALSE')

    csr_cert.add_extension    extension_factory.create_extension('keyUsage', 'keyEncipherment,dataEncipherment,digitalSignature')

    csr_cert.add_extension    extension_factory.create_extension('subjectKeyIdentifier', 'hash')

    csr_cert.sign ca_key, OpenSSL::Digest::SHA1.new

    open "./ssl/CA/newcerts/#{resource.email}_cert.pem", 'w' do |io|
      io.write csr_cert.to_pem
    end
    open "./ssl/CA/private/#{resource.email}_private_key.pem", 'w' do |io|
      io.write key.to_pem 
    end
  end

  

end 