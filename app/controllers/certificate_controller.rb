class CertificateController < ApplicationController
  include CertificateAuthority
  before_action :authenticate_user!
  
  def new
    pass_word = params[:password]
    if create_certificate(current_user, pass_word)
      redirect_to user_path(current_user), :notice => "Generated New Certificate"
    else
      redirect_to user_path(current_user), :alert => "Unable to Create Certificate!"
    end
  end

  def revoke
    reason = params[:revoke_reason]
    certificate_password = params[:certificate_password]
    logger.debug "HERE HERE HERE #{certificate_password}"
    if revoke_certificate(current_user, certificate_password, reason.to_i)
      redirect_to user_path(current_user), :notice => "Certificate Revoked"
    else
      redirect_to user_path(current_user), :alert => "Unable to Revoke Certificate!"
    end
  end

  def download
    send_file(
        "./ssl/CA/newcerts/#{current_user.lastname}_#{current_user.firstname}_cert.p12",
        filename: "#{current_user.lastname}_#{current_user.firstname}_cert.p12",
        type: "application/x-pkcs12"
      )
  end
  
  def status
    p = params[:pkcs12_cert]
    password = params[:password]
    pkcs12_cert = p.read
    cert = get_certificate(pkcs12_cert, password)
    check = cert_valid(cert)
    if check[0]
      redirect_to user_path(current_user), :notice => "Certificate is valid"
    else
      redirect_to user_path(current_user), :alert => "Certificate is NOT Valid (#{check[1]})"
    end    
  end
  
end
