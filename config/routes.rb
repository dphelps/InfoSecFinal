Rails.application.routes.draw do
  post 'certificate/new', to: 'certificate#new', as: 'new_certificate'
  post 'certificate/revoke', to: 'certificate#revoke', as: 'revoke_certificate'
  get 'certificate/download', to: 'certificate#download', as: 'download_certificate'
  post 'certificate/status', to: 'certificate#status', as: 'certificate_status'

  root to: 'visitors#index'
  devise_for :users, :controllers => { :registrations => 'users/registrations' }
  resources :users
end
