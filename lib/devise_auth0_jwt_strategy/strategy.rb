require 'jwt'
require 'devise'
require "request_store"

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

      # This login should be required on each request and not setup a session
      def store?
        false
      end

      def valid?
        ( auth0_client_secret? and auth0_client_id? and !!jwt_token )
      end

      def to_boolean(value)
        # Most calls to this will pass in nil so have this guard clause first
        # as a performance optimization
        return false if value.nil?

        # We interpret a boolean true or the lowercase normalize strings 'true', and 't'
        # as a true value
        return value if value == !!value
        return !!(['true', 't'].index(value.downcase)) if value.kind_of?(::String)

        # All others are always false
        return false
      end

      def decode_options
        # We will continue doing our own claim checks just for backwards compatibility
        {
          verify_expiration: false,
          verify_iat: false,
          verify_iss: false,
          verify_aud: false,
          verify_jti: false,
          verify_subj: false,
          verify_not_before: false
        }
      end

      def authenticate!

        if ENV['DEBUG_AUTH0_JWT']
          STDERR.puts ">>>>>>>>>>>>>>> DEBUG AUTH0 JWT"
          STDERR.puts "valid? #{valid?}"
          STDERR.puts @jwt_token
        end

        if valid?
          # Passing true will cause #decode to verify the token signature
          # This will throw JWT::DecodeError if it fails
          payload, header = ::JWT.decode(@jwt_token, auth0_client_secret, true, decode_options)

          STDERR.puts payload.inspect if ENV['DEBUG_AUTH0_JWT']

          raise ClaimInvalid.new('JWT has the wrong client id') unless payload['aud'] == auth0_client_id
          raise ClaimInvalid.new('JWT has expired') unless payload['exp'].to_i > Time.now.to_i

          u = ::User.find_for_devise_auth0_jwt_strategy(payload['email'])

          if u.nil?
            fail!("Could not log in")

          else
            u.ignore_timedout = true if u.respond_to?(:ignore_timedout=)
            u.ignore_active = to_boolean(payload['ignore_active']) if u.respond_to?(:ignore_active=)

            ::RequestStore.store[:jwt_scopes] = payload['scopes']

            success!(u)

          end

        else
          fail("No JWT token passed in")

        end

      rescue ClaimInvalid => e
        fail! e.message

      rescue ::JWT::DecodeError => e
        STDERR.puts "JWT::DecodeError -- #{e.message}"
        fail!("JWT token is invalid. Please get a new token and try again.")
      end

    end
  end
end
