require 'spec_helper'
require_relative "../../../lib/devise_auth0_jwt_strategy/strategy"

RSpec.describe Devise::Strategies::Auth0Jwt do

  subject { Devise::Strategies::Auth0Jwt.new('arg1') }

  it { is_expected.to respond_to :auth0_client_secret }
  it { is_expected.to respond_to :auth0_client_secret? }
  it { is_expected.to respond_to :auth0_client_id }
  it { is_expected.to respond_to :auth0_client_id? }
  it { is_expected.to respond_to :valid_jwt_auth_header? }
  it { is_expected.to respond_to :jwt_from_auth_header }
  it { is_expected.to respond_to :store? }
  it { is_expected.to respond_to :valid? }
  it { is_expected.to respond_to :authenticate! }

  describe "#auth0_client_secret" do
    it "returns ENV['AUTH0_CLIENT_SECRET'] or 0" do
      old_secret = ENV['AUTH0_CLIENT_SECRET']
      ENV['AUTH0_CLIENT_SECRET'] = nil
      expect(subject.auth0_client_secret).to eql 0

      ENV['AUTH0_CLIENT_SECRET'] = 'secret'
      expect(subject.auth0_client_secret).to eql 'secret'

      ENV['AUTH0_CLIENT_SECRET'] = old_secret
    end
  end

  describe "#auth0_client_secret?" do
    context "when auth0_client_secret is nil" do
      it "should return false" do
        expect(subject).to receive(:auth0_client_secret).and_return(nil)
        expect(subject.auth0_client_secret?).to eql false
      end
    end

    context "when auth0_client_secret is 0" do
      it "should return false" do
        expect(subject).to receive(:auth0_client_secret).twice.and_return(0)
        expect(subject.auth0_client_secret?).to eql false
      end
    end

    context "when auth0_client_secret is a string" do
      it "should return true" do
        expect(subject).to receive(:auth0_client_secret).twice.and_return('some secret')
        expect(subject.auth0_client_secret?).to eql true
      end
    end
  end

  describe "#auth0_client_id" do
    it "returns ENV['AUTH0_CLIENT_ID'] or 0" do
      old_id = ENV['AUTH0_CLIENT_ID']

      ENV['AUTH0_CLIENT_ID'] = nil
      expect(subject.auth0_client_id).to eql 0

      ENV['AUTH0_CLIENT_ID'] = 'secret'
      expect(subject.auth0_client_id).to eql 'secret'

      ENV['AUTH0_CLIENT_ID'] = old_id
    end
  end

  describe "#auth0_client_id?" do
    context "when auth0_client_id is nil" do
      it "should return false" do
        expect(subject).to receive(:auth0_client_id).and_return(nil)
        expect(subject.auth0_client_id?).to eql false
      end
    end

    context "when auth0_client_id is 0" do
      it "should return false" do
        expect(subject).to receive(:auth0_client_id).twice.and_return(0)
        expect(subject.auth0_client_id?).to eql false
      end
    end

    context "when auth0_client_id is a string" do
      it "should return true" do
        expect(subject).to receive(:auth0_client_id).twice.and_return('some secret')
        expect(subject.auth0_client_id?).to eql true
      end
    end
  end

  describe "#valid_jwt_auth_header?" do
    context "when header_split is Bearer plus token" do
      it "should return true" do
        expect(subject.valid_jwt_auth_header?(['Bearer', 'Mah Token'])).to eql true
      end
    end

    context "when header_split is not Bearer plus token" do
      it "should return true" do
        expect(subject.valid_jwt_auth_header?(['Auth', 'HTTP Basic'])).to eql false
      end
    end
  end

  describe "#jwt_from_auth_header" do
    context "when the request has no authorization header" do
      before { allow(subject).to receive_message_chain(:request, :authorization).and_return(nil) }

      it "should return nil" do
        expect(subject.jwt_from_auth_header).to eql nil
      end
    end

    context "when the request does not have a valid_jwt_auth_header?" do
      before { allow(subject).to receive_message_chain(:request, :authorization).and_return("Auth HTTP") }

      it "should return nil" do
        expect(subject.jwt_from_auth_header).to eql nil
      end
    end

    context "when the request contains a properly formatted Bearer token auth header" do
      before { allow(subject).to receive_message_chain(:request, :authorization).and_return("Bearer Mah-Token") }

      it "should return the token" do
        expect(subject.jwt_from_auth_header).to eql 'Mah-Token'
      end
    end
  end

  describe "#jwt_token" do
    context "when params[:jwt] is not nil" do
      before { expect(subject).to receive(:params).and_return({'jwt' => 'mah token'}) }

      it "should return params[:jwt]" do
        expect(subject.jwt_token).to eql "mah token"
      end
    end

    context "when params[:jwt] is nil" do
      before { expect(subject).to receive(:params).and_return({}) }

      context "when jwt_from_auth_header is nil" do
        before { expect(subject).to receive(:jwt_from_auth_header).and_return(nil) }

        it "should return nil" do
          expect(subject.jwt_token).to eql nil
        end
      end

      context "when jwt_from_auth_header is not nil" do
        before { expect(subject).to receive(:jwt_from_auth_header).and_return('mah token') }

        it "should return the jwt from the header" do
          expect(subject.jwt_token).to eql 'mah token'
        end
      end
    end
  end

  describe "#store?" do
    it "returns false" do
      expect(subject.store?).to eql false
    end
  end

  describe "#valid?" do
    context "when auth0_client_secret? is false" do
      before { expect(subject).to receive(:auth0_client_secret?).and_return(false) }

      it "should return false" do
        expect(subject.valid?).to eql false
      end
    end

    context "when auth0_client_secret? is true" do
      before { expect(subject).to receive(:auth0_client_secret?).and_return(true) }

      context "when auth0_client_id? is false" do
        before { expect(subject).to receive(:auth0_client_id?).and_return(false) }

        it "should return false" do
          expect(subject.valid?).to eql false
        end
      end

      context "when auth0_client_id? is true" do
        before { expect(subject).to receive(:auth0_client_id?).and_return(true) }

        context "when jwt_token is nil" do
          before { expect(subject).to receive(:jwt_token).and_return(nil) }

          it "should return false" do
            expect(subject.valid?).to eql false
          end
        end

        context "when jwt_token is not nil" do
          before { expect(subject).to receive(:jwt_token).and_return('Mah Token') }

          it "should return true" do
            expect(subject.valid?).to eql true
          end
        end
      end
    end
  end

  describe "#to_boolean" do
    context "when value is nil" do
      it "returns false" do
        expect(subject.to_boolean(nil)).to eq(false)
      end
    end

    context "when value is false" do
      it "returns false" do
        expect(subject.to_boolean(false)).to eq(false)
      end
    end

    context "when value is true" do
      it "returns true" do
        expect(subject.to_boolean(true)).to eq(true)
      end
    end

    ['true', 't'].each do |truthy_string|
      context "when value is '#{truthy_string}'" do
        it "returns true" do
          expect(subject.to_boolean(truthy_string)).to eq(true)
        end
      end
    end

    ['false', 'f', 'fizzbuzz', 'rails'].each do |falsey_string|
      context "when value is '#{falsey_string}'" do
        it "returns false" do
          expect(subject.to_boolean(falsey_string)).to eq(false)
        end
      end
    end

    [Date.current, Time.zone.now, 1001].each do |falsey_value|
      context "when value is #{falsey_value}" do
        it "returns false" do
          expect(subject.to_boolean(falsey_value)).to eq(false)
        end
      end
    end
  end

  describe "#authenticate!" do
    context "when the request is not valid for auth0jwt strategy" do
      before { expect(subject).to receive(:valid?).and_return(false) }

      it "should fail the authentication" do
        expect(::JWT).to_not receive(:decode)
        expect(subject).to receive(:fail).with("No JWT token passed in")
        subject.authenticate!
      end
    end

    context "when the request is valid for auth0jwt strategy" do
      before do
        ENV['AUTH0_CLIENT_ID'] = 'mah_id'
        ENV['AUTH0_CLIENT_SECRET'] = 'mah_secret'
        subject.instance_variable_set(:"@jwt_token", 'Mah-Token')
        expect(subject).to receive(:valid?).and_return(true)
        expect(::JWT).to receive(:base64url_decode).with('mah_secret').and_return('mah_secret_no_base64')
      end

      context "when the JWT decode fails" do
        before do
          expect(::JWT).to receive(:decode).
            with('Mah-Token', 'mah_secret_no_base64').
            and_raise(::JWT::DecodeError.new('Token Invalid'))
        end

        it "should fail! the authentication" do
          expect(STDERR).to receive(:puts).with("JWT::DecodeError -- Token Invalid")
          expect(subject).to receive(:fail!).with("JWT token is invalid. Please get a new token and try again.")
          subject.authenticate!
        end
      end

      context "when the JWT decode succeeds" do
        before do
          expect(::JWT).to receive(:decode).
            with('Mah-Token', 'mah_secret_no_base64').
            and_return([{'aud' => mock_aud, 'email' => 'bob@isyouruncle.com', 'exp' => mock_time, 'ignore_active' => 'true'}, 'some header'])
        end

        context "when aud is from the wrong client ID" do
          let(:mock_aud) { 'some wrong id' }
          let(:mock_time) { (Time.zone.now + 15.days).to_i }

          it "should fail! the authentication" do
            expect(subject).to receive(:fail!).with("JWT has the wrong client id")
            subject.authenticate!
          end
        end

        context "when aud is the correct client ID" do
          let(:mock_aud) { 'mah_id' }

          context "when the token is expired" do
            let(:mock_time) { (Time.zone.now - 15.days).to_i }

            it "should fail! the authentication" do
              expect(subject).to receive(:fail!).with("JWT has expired")
              subject.authenticate!
            end
          end

          context "when the token is not expired" do
            let(:mock_time) { (Time.zone.now + 15.days).to_i }

            context "when the user cannot be found" do
              before { expect(::User).to receive(:find_for_devise_auth0_jwt_strategy).with('bob@isyouruncle.com').and_return(nil) }

              it "should fail! the authentication" do
                expect(subject).to receive(:fail!).with("Could not log in")
                subject.authenticate!
              end
            end

            context "when the user is found by email" do
              let(:mock_user) { User.new }
              before { expect(::User).to receive(:find_for_devise_auth0_jwt_strategy).with('bob@isyouruncle.com').and_return(mock_user) }

              it "should success! the authentication" do
                expect(subject).to receive(:success!).with(mock_user)
                subject.authenticate!

                expect(mock_user.ignore_timedout).to eq(true)
                expect(mock_user.ignore_active).to eq(true)
              end
            end
          end
        end
      end
    end
  end

end
