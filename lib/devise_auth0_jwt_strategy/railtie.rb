module DeviseAuth0JwtStrategy
  class Railtie < Rails::Railtie
    initializer "devise_auth0_jwt_strategy.configure_rails_initialization" do
      print "Wiring up Auth0 JWT Devise Strategy..."

      ::Devise.setup do |config|

        config.warden do |manager|
          manager.strategies.add(:auth0jwt, ::Devise::Strategies::Auth0Jwt)
          manager.default_strategies(:scope => :user).unshift :auth0jwt

          puts manager.default_strategies.inspect
        end

      end

      print "done.\n"

    end
  end
end
