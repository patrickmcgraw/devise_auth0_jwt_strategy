require 'spec_helper'
require_relative "../../../lib/devise_auth0_jwt_strategy/strategy"

RSpec.describe Devise::Strategies::Auth0Jwt do

  subject { Devise::Strategies::Auth0Jwt.new('arg1') }

  it { should respond_to :auth0_client_secret }
  it { should respond_to :auth0_client_secret? }
  it { should respond_to :auth0_client_id }
  it { should respond_to :auth0_client_id? }
  it { should respond_to :valid_jwt_auth_header? }
  it { should respond_to :jwt_from_auth_header }
  it { should respond_to :valid? }
  it { should respond_to :authenticate! }

  describe "#auth0_client_secret" do
    it "returns ENV['AUTH0_CLIENT_SECRET'] or 0" do
      old_secret = ENV['AUTH0_CLIENT_SECRET']
      ENV['AUTH0_CLIENT_SECRET'] = nil
      subject.auth0_client_secret.should == 0

      ENV['AUTH0_CLIENT_SECRET'] = 'secret'
      subject.auth0_client_secret.should == 'secret'

      ENV['AUTH0_CLIENT_SECRET'] = old_secret
    end
  end

  describe "#auth0_client_secret?" do
    context "when auth0_client_secret is nil" do
      it "should return false" do
        subject.stub(:auth0_client_secret).and_return(nil)
        subject.auth0_client_secret?.should eql(false)
      end
    end

    context "when auth0_client_secret is 0" do
      it "should return false" do
        subject.stub(:auth0_client_secret).and_return(0)
        subject.auth0_client_secret?.should eql(false)
      end
    end

    context "when auth0_client_secret is a string" do
      it "should return true" do
        subject.stub(:auth0_client_secret).and_return('some secret')
        subject.auth0_client_secret?.should eql(true)
      end
    end
  end

  describe "#auth0_client_id" do
    it "returns ENV['AUTH0_CLIENT_ID'] or 0" do
      old_id = ENV['AUTH0_CLIENT_ID']

      ENV['AUTH0_CLIENT_ID'] = nil
      subject.auth0_client_id.should == 0

      ENV['AUTH0_CLIENT_ID'] = 'secret'
      subject.auth0_client_id.should == 'secret'

      ENV['AUTH0_CLIENT_ID'] = old_id
    end
  end

  describe "#auth0_client_id?" do
    context "when auth0_client_id is nil" do
      it "should return false" do
        subject.stub(:auth0_client_id).and_return(nil)
        subject.auth0_client_id?.should eql(false)
      end
    end

    context "when auth0_client_id is 0" do
      it "should return false" do
        subject.stub(:auth0_client_id).and_return(0)
        subject.auth0_client_id?.should eql(false)
      end
    end

    context "when auth0_client_id is a string" do
      it "should return true" do
        subject.stub(:auth0_client_id).and_return('some secret')
        subject.auth0_client_id?.should eql(true)
      end
    end
  end

  describe "#valid_jwt_auth_header?" do
    context "when header_split is Bearer plus token" do
      it "should return true" do
        subject.valid_jwt_auth_header?(['Bearer', 'Mah Token']).should eql(true)
      end
    end

    context "when header_split is not Bearer plus token" do
      it "should return true" do
        subject.valid_jwt_auth_header?(['Auth', 'HTTP Basic']).should eql(false)
      end
    end
  end

  describe "#jwt_from_auth_header" do
    context "when the request has no authorization header" do
      before { subject.stub_chain(:request, :authorization).and_return(nil) }

      it "should return nil" do
        subject.jwt_from_auth_header.should be_nil
      end
    end

    context "when the request does not have a valid_jwt_auth_header?" do
      before { subject.stub_chain(:request, :authorization).and_return("Auth HTTP") }

      it "should return nil" do
        subject.jwt_from_auth_header.should be_nil
      end
    end

    context "when the request contains a properly formatted Bearer token auth header" do
      before { subject.stub_chain(:request, :authorization).and_return("Bearer Mah-Token") }

      it "should return the token" do
        subject.jwt_from_auth_header.should == 'Mah-Token'
      end
    end
  end

  describe "#jwt_token" do
    context "when params[:jwt] is not nil" do
      before { subject.stub(:params).and_return({'jwt' => 'mah token'}) }

      it "should return params[:jwt]" do
        subject.jwt_token.should == "mah token"
      end
    end

    context "when params[:jwt] is nil" do
      before { subject.stub(:params).and_return({}) }

      context "when jwt_from_auth_header is nil" do
        before { subject.stub(:jwt_from_auth_header).and_return(nil) }

        it "should return nil" do
          subject.jwt_token.should be_nil
        end
      end

      context "when jwt_from_auth_header is not nil" do
        before { subject.stub(:jwt_from_auth_header).and_return('mah token') }

        it "should return the jwt from the header" do
          subject.jwt_token.should == 'mah token'
        end
      end
    end
  end

  describe "#valid?" do
    context "when auth0_client_secret? is false" do
      before { subject.should_receive(:auth0_client_secret?).and_return(false) }

      it "should return false" do
        subject.valid?.should eql(false)
      end
    end

    context "when auth0_client_secret? is true" do
      before { subject.should_receive(:auth0_client_secret?).and_return(true) }

      context "when auth0_client_id? is false" do
        before { subject.should_receive(:auth0_client_id?).and_return(false) }

        it "should return false" do
          subject.valid?.should eql(false)
        end
      end

      context "when auth0_client_id? is true" do
        before { subject.should_receive(:auth0_client_id?).and_return(true) }

        context "when jwt_token is nil" do
          before { subject.should_receive(:jwt_token).and_return(nil) }

          it "should return false" do
            subject.valid?.should eql(false)
          end
        end

        context "when jwt_token is not nil" do
          before { subject.should_receive(:jwt_token).and_return('Mah Token') }

          it "should return true" do
            subject.valid?.should eql(true)
          end
        end
      end
    end
  end

  describe "#authenticate!" do
    context "when the request is not valid for auth0jwt strategy" do
      before { subject.should_receive(:valid?).and_return(false) }

      it "should fail the authentication" do
        ::JWT.should_not_receive(:decode)
        subject.should_receive(:fail).with("No JWT token passed in")
        subject.authenticate!
      end
    end

    context "when the request is valid for auth0jwt strategy" do
      before do
        ENV['AUTH0_CLIENT_ID'] = 'mah_id'
        ENV['AUTH0_CLIENT_SECRET'] = 'mah_secret'
        subject.instance_variable_set(:"@jwt_token", 'Mah-Token')
        subject.should_receive(:valid?).and_return(true)
        ::JWT.should_receive(:base64url_decode).with('mah_secret').and_return('mah_secret_no_base64')
      end

      context "when the JWT decode fails" do
        before do
          ::JWT.should_receive(:decode).
            with('Mah-Token', 'mah_secret_no_base64').
            and_raise(::JWT::DecodeError.new('Token Invalid'))
        end

        it "should fail! the authentication" do
          STDOUT.should_receive(:puts).with("JWT::DecodeError -- Token Invalid")
          subject.should_receive(:fail!).with("JWT token is invalid. Please get a new token and try again.")
          subject.authenticate!
        end
      end

      context "when the JWT decode succeeds" do
        before do
          ::JWT.should_receive(:decode).
            with('Mah-Token', 'mah_secret_no_base64').
            and_return([{'aud' => mock_aud, 'email' => 'bob@isyouruncle.com', 'exp' => mock_time}, 'some header'])
        end

        context "when aud is from the wrong client ID" do
          let(:mock_aud) { 'some wrong id' }
          let(:mock_time) { (Time.zone.now + 15.days).to_i }

          it "should fail! the authentication" do
            subject.should_receive(:fail!).with("JWT has the wrong client id")
            subject.authenticate!
          end
        end

        context "when aud is the correct client ID" do
          let(:mock_aud) { 'mah_id' }

          context "when the token is expired" do
            let(:mock_time) { (Time.zone.now - 15.days).to_i }

            it "should fail! the authentication" do
              subject.should_receive(:fail!).with("JWT has expired")
              subject.authenticate!
            end
          end

          context "when the token is not expired" do
            let(:mock_time) { (Time.zone.now + 15.days).to_i }

            context "when the user cannot be found by email" do
              before { ::User.should_receive(:find_by_email).with('bob@isyouruncle.com').and_return(nil) }

              it "should fail! the authentication" do
                subject.should_receive(:fail!).with("Could not log in")
                subject.authenticate!
              end
            end

            context "when the user is found by email" do
              let(:mock_user) { double(User) }
              before { ::User.should_receive(:find_by_email).with('bob@isyouruncle.com').and_return(mock_user) }

              it "should success! the authentication" do
                subject.should_receive(:success!).with(mock_user)
                subject.authenticate!
              end
            end
          end
        end
      end
    end
  end

end
