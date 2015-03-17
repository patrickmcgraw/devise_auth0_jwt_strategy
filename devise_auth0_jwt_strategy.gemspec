Gem::Specification.new do |gem|
  gem.name          = 'devise_auth0_jwt_strategy'
  gem.version       = '0.0.1'
  gem.date          = '2015-03-10'
  gem.summary       = "Authenticate requests using an Aith0 JWT passed by HTTP header"
  gem.description   = gem.summary
  gem.authors       = ["Patrick McGraw"]
  gem.email         = 'patrick@mcgraw-tech.com'
  gem.files         = [ "lib/devise_auth0_jwt_strategy.rb",
                        "lib/devise_auth0_jwt_strategy/strategy.rb" ]
  gem.homepage      = 'http://rubygems.org/gems/devise_auth0_jwt_strategy'
  gem.license       = 'MIT'
  gem.require_paths = ['lib']

  gem.add_dependency 'rest-client', '~> 1.7.2'
  gem.add_dependency 'json', '~> 1.8.1'
  gem.add_dependency 'jwt', '~> 1.0.0'
  gem.add_dependency 'devise', '~> 3.4.1'

  gem.add_development_dependency 'rails', '>= 4.0.0'
  gem.add_development_dependency 'rspec-rails', '~> 3.0'
  gem.add_development_dependency 'sqlite3', '~> 1.0'
end
