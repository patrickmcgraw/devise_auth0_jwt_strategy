require 'jwt'
require 'devise'

module Devise
  module Strategies
    class Auth0Jwt < Base

      class ClaimInvalid < StandardError; end

      def auth0_client_secret
        ( ENV['AUTH0_CLIENT_SECRET'] || 0 )
      end

      def auth0_client_secret?
        ( !auth0_client_secret.nil? && auth0_client_secret != 0 )
      end

      def auth0_client_id
        ( ENV['AUTH0_CLIENT_ID'] || 0 )
      end

      def auth0_client_id?
        ( !auth0_client_id.nil? && auth0_client_id != 0 )
      end

      def valid_jwt_auth_header?(header_split)
        header_split.length == 2 &&
        header_split[0] == 'Bearer'
      end

      def jwt_from_auth_header
        return nil unless request.authorization

        authorization_split = request.authorization.split(' ')
        return nil unless valid_jwt_auth_header?(authorization_split)

        return authorization_split.last
      end

      def jwt_token
        # Check for params['jwt'] or token = request.headers['Authorization'].split(' ').last
        @jwt_token ||= ( params['jwt'] || jwt_from_auth_header )
      end

      def valid?
        ( auth0_client_secret? and auth0_client_id? and !!jwt_token )
      end

      def authenticate!

        if valid?
          # This will throw JWT::DecodeError if it fails
          payload, header = ::JWT.decode(@jwt_token,
            ::JWT.base64url_decode(auth0_client_secret))

          raise ClaimInvalid.new('JWT has the wrong client id') unless payload['aud'] == auth0_client_id
          raise ClaimInvalid.new('JWT has expired') unless payload['exp'].to_i > Time.now.to_i

          u = ::User.find_by_email(payload['email'])

          u.nil? ? fail!("Could not log in") : success!(u)

        else
          fail("No JWT token passed in")

        end

      rescue ClaimInvalid => e
        fail! e.message

      rescue ::JWT::DecodeError => e
        puts "JWT::DecodeError -- #{e.message}"
        fail!("JWT token is invalid. Please get a new token and try again.")
      end

    end
  end
end
