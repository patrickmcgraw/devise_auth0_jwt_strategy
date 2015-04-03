module DeviseAuth0JwtStrategy
  class Railtie < Rails::Railtie
    #initializer "devise_auth0_jwt_strategy.configure_rails_initialization" do
    config.after_initialize do
      print "Wiring up Auth0 JWT Devise Strategy..."
      if ENV['AUTH0_CLIENT_SECRET']

        Warden::Strategies.add(:auth0jwt, Devise::Strategies::Auth0Jwt)
        Devise.add_module(:auth0jwt, strategy: true, controller: :sessions)

        print "done.\n"

      else
        print " no Auth0 Secret Found. Skipping...\n"

      end

    end
  end
end
