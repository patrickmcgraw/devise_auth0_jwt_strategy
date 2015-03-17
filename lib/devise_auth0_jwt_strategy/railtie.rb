module DeviseAuth0JwtStrategy
  class Railtie < Rails::Railtie
    initializer "devise_auth0_jwt_strategy.configure_rails_initialization" do
      print "Wiring up Auth0 JWT Devise Strategy..."
      if ENV['AUTH0_CLIENT_SECRET']

        ::Devise.setup do |config|

          config.warden do |manager|
            manager.strategies.add(:auth0jwt, Devise::Strategies::Auth0Jwt)
            manager.default_strategies(:scope => :user).unshift :auth0jwt
          end

        end

        print "done.\n"

      else
        print " no Auth0 Secret Found. Skipping..."

      end

    end
  end
end
