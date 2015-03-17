require 'devise_auth0_jwt_strategy/strategy'

if ENV['AUTH0_CLIENT_SECRET']
  puts "Wiring up Auth0 JWT Devise Strategy"

  ::Devise.setup do |config|

    config.warden do |manager|
      manager.strategies.add(:auth0jwt, Devise::Strategies::Auth0Jwt)
      manager.default_strategies(:scope => :user).unshift :auth0jwt
    end

  end

end
