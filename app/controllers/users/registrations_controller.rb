class Users::RegistrationsController < Devise::RegistrationsController
  require 'openssl'
  include CertificateAuthority
  
  def create
    super # continue to devise registration to CREATE user
    create_certificate(resource, resource.certificate_password)
  end

  def update
    super # continue to devise registration to UPDATE user
    update_certificate(current_user, resource, resource.certificate_password)
  end
  
  private
  
  def sign_up_params
    params.require(:user).permit(:uid, :firstname, :lastname, :email, :certificate_password, :password, :password_confirmation)
  end
  
  def account_update_params
    params.require(:user).permit(:uid, :firstname, :lastname, :email, :password, :password_confirmation, :current_password, :certificate_password)
  end
end 