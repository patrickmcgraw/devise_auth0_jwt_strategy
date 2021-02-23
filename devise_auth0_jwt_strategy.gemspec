Gem::Specification.new do |gem|
  gem.name          = 'devise_auth0_jwt_strategy'
  gem.version       = '0.0.12'
  gem.date          = '2015-03-10'
  gem.summary       = "Authenticate requests using an Auth0 JWT passed by HTTP header"
  gem.description   = gem.summary
  gem.authors       = ["Patrick McGraw"]
  gem.email         = 'pat@bloodhub.com'
  gem.files         = [ "lib/devise_auth0_jwt_strategy.rb",
                        "lib/devise_auth0_jwt_strategy/strategy.rb",
                        "lib/devise_auth0_jwt_strategy/railtie.rb" ]
  gem.homepage      = 'http://rubygems.org/gems/devise_auth0_jwt_strategy'
  gem.license       = 'MIT'
  gem.require_paths = ['lib']

  gem.add_dependency 'jwt', '>= 2.2.0'
  gem.add_dependency 'devise', '>= 3.4'
  gem.add_dependency 'request_store', '~> 1.3'

  gem.add_development_dependency 'rails', '>= 5.0.0'
  gem.add_development_dependency 'rspec-rails', '~> 3.7'
end
