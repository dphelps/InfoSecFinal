module CertificateAuthority
  extend ActiveSupport::Concern
  
  def get_certificate(pkcs12_der, pass_word)
    pkcs12_cert = OpenSSL::PKCS12.new(pkcs12_der, pass_word)
    cert = pkcs12_cert.certificate
  end
  
  def update_certificate(old_user, new_user, pass_word)
    revoke_certificate(old_user, pass_word, 4)
    create_cert(new_user, pass_word)
  end
  
  def create_certificate(user, pass_word)
    create_cert(user, pass_word)
  end
  
  def revoke_certificate(user, pass_word, revoke_reason=4)
    pkcs12_der = File.read "./ssl/CA/newcerts/#{user.lastname}_#{user.firstname}_cert.p12"
    pkcs12_cert = OpenSSL::PKCS12.new(pkcs12_der, pass_word)
    cert = pkcs12_cert.certificate
    revoke_cert(user, cert.serial, revoke_reason)
  end
  
  private
  
  def generate_key
    @key = OpenSSL::PKey::RSA.new 2048
  end
  
  def generate_csr(subj="CN=ca/DC=example")
    @csr = OpenSSL::X509::Request.new
    @csr.version = 0
    @csr.subject = OpenSSL::X509::Name.parse subj
    @csr.public_key = @key.public_key
    @csr.sign @key, OpenSSL::Digest::SHA1.new
  end

  def setup_CA
    @pass_phrase = Rails.application.secrets.pass_phrase
    @pkcs12_der = File.read './ssl/CA/cacert.p12'
    @pkcs12_cert = OpenSSL::PKCS12.new(@pkcs12_der, @pass_phrase)
    @ca_cert = @pkcs12_cert.certificate    
    @ca_key = @pkcs12_cert.key
    #@ca_key = OpenSSL::PKey::RSA.new @cakey_pem, @pass_phrase    
  end

  def create_cert(user, pass_word)
    setup_CA
    generate_key
    generate_csr("CN=#{user.email}/DC=example")
    increment_serial
    @csr_cert = OpenSSL::X509::Certificate.new
    @csr_cert.serial = serial
    @csr_cert.version = 2
    @csr_cert.not_before = Time.now
    @csr_cert.not_after = Time.now + 600

    @csr_cert.subject = @csr.subject
    @csr_cert.public_key = @csr.public_key
    @csr_cert.issuer = @ca_cert.subject

    extension_factory = OpenSSL::X509::ExtensionFactory.new
    extension_factory.subject_certificate = @csr_cert
    extension_factory.issuer_certificate = @ca_cert
    @csr_cert.add_extension    extension_factory.create_extension('basicConstraints', 'CA:FALSE')
    @csr_cert.add_extension    extension_factory.create_extension('keyUsage', 'keyEncipherment,dataEncipherment,digitalSignature')
    @csr_cert.add_extension    extension_factory.create_extension('subjectKeyIdentifier', 'hash')
    @csr_cert.sign @ca_key, OpenSSL::Digest::SHA1.new
    open "./ssl/CA/newcerts/#{user.lastname}_#{user.firstname}_cert.p12", 'w:ASCII-8BIT' do |io|
      io.write OpenSSL::PKCS12.create(pass_word,"#{user.lastname}_#{user.firstname}",@key,@csr_cert).to_der
    end
  end
  
  def revoke_cert(user, serial, revoke_reason)
    setup_CA
    crl = OpenSSL::X509::CRL.new File.read "./ssl/CA/crl.pem" 
    File.rename("./ssl/CA/newcerts/#{user.lastname}_#{user.firstname}_cert.p12", "./ssl/CA/newcerts/revoked_#{user.lastname}_#{user.firstname}_cert.p12")
    digest = OpenSSL::Digest::SHA1.new
      crl.issuer = @ca_cert.subject
      crl.version = 1
      crl.last_update = Time.now
      crl.next_update = Time.now + 1600
        revoked = OpenSSL::X509::Revoked.new
        revoked.serial =serial
        revoked.time = Time.now
        enum = OpenSSL::ASN1::Enumerated(revoke_reason)
        ext = OpenSSL::X509::Extension.new("CRLReason", enum)
        revoked.add_extension(ext)
        crl.add_revoked(revoked)
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.issuer_certificate = @ca_cert
      ef.crl = crl
      crlnum = OpenSSL::ASN1::Integer(serial)
      crl.add_extension(OpenSSL::X509::Extension.new("crlNumber", crlnum))
#      extensions.each{|oid, value, critical|
#        crl.add_extension(ef.create_extension(oid, value, critical))
#      }
      crl.sign(@ca_key, digest)
      increment_revoked!
      open "./ssl/CA/crl.pem", 'w' do |io| 
        io.write crl.to_pem 
      end
  end
  
  def increment_revoked!
    revoked_count = File.read './ssl/CA/revoked'
    revoked_count = revoked_count.to_i
    revoked_count += 1
    open "./ssl/CA/revoked", 'w' do |io|
      io.write revoked_count
    end
  end
  
  def increment_serial
    s = File.read './ssl/CA/serial'
    s = s.to_i
    s += 1
    open "./ssl/CA/serial", 'w' do |io|
      io.write s
    end
  end
  
  def serial
    s = File.read './ssl/CA/serial'
    s = s.to_i
    s
  end
  
  def revoked_count
    revoked_count = File.read './ssl/CA/revoked'
    revoked_count = revoked_count.to_i
    revoked_count
  end
  
  def cert_valid(cert)
    setup_CA
    status = TRUE
    message = "Valid"
    if cert.issuer != @ca_cert.issuer 
      status=FALSE 
      message = "Wrong CA"
    end
    crl = OpenSSL::X509::CRL.new File.read "./ssl/CA/crl.pem" 
    crl.revoked.each do |r|
       if r.serial == cert.serial
         status=FALSE
         message = r.extensions[0].value
       end
    end
    return([status, message])
  end
end