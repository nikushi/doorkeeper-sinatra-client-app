# coding: utf-8
# frozen_string_literal: true

require 'sinatra'
require 'sinatra/reloader'
require 'oauth2'
require 'pp'

enable :sessions

helpers do
  def h(text)
    Rack::Utils.escape_html(text)
  end
end

get '/' do
  "<a href=/login>login</a>"
end

client_id = ENV['CLIENT_ID']
client_secret = ENV['CLIENT_SECRET']
oauth2_scope = ENV.fetch('OAUTH2_SCOPE', 'public')
redirect_uri = 'http://localhost:4567/callback'
site= ENV.fetch('SITE', 'http://localhost:3000')
authorize_url_base = ENV.fetch('AUTHORIZE_URL_BASE', site + '/oauth')
token_url_base = ENV.fetch('TOKEN_URL_BASE', site + '/oauth')
oauth2_options = {
  site: site,
  authorize_url: authorize_url_base + '/authorize',
  token_url: token_url_base + '/token',
}

set :show_exceptions, :after_handler

error OAuth2::Error do
  e = env['sinatra.error']
  message = "#{e.code}: #{e.description}"
  "<a href=/login>login</a> <a href=/refresh>refresh</a><xmp>#{message}"
end

get '/login' do
  session[:state] = SecureRandom.hex(24)
  client = OAuth2::Client.new(client_id, client_secret, oauth2_options)
  redirect client.auth_code.authorize_url(redirect_uri: redirect_uri, state: session[:state], scope: oauth2_scope)
end

get '/callback' do
  halt "<a href=/login>login</a><xmp>#{params[:error]}: #{params[:error_description]}" if params.key?(:error) # deny
  halt '<a href=/login>login</a>' if session[:state] != params[:state]
  session.delete(:state)
  client = OAuth2::Client.new(client_id, client_secret, oauth2_options)
  token = client.auth_code.get_token(params[:code], redirect_uri: redirect_uri)
  session[:token] = token.to_hash
  redirect '/info'
end

get '/info' do
  client = OAuth2::Client.new(client_id, client_secret, oauth2_options)
  halt '<a href=/login>login</a>' unless session.key?(:token)
  token = OAuth2::AccessToken.from_hash(client, session[:token])
  # begin
  #   info_response = token.get("/#{doorkeeper_scope}/token/info").parsed
  # rescue OAuth2::Error => e
  #   info_response = "#{e.code}: #{e.description}"
  # end
  response = token.post(token_url_base + '/introspect', body: { token: token.token })
  response2 = token.post(token_url_base + '/introspect', body: { token: token.refresh_token })

  require 'json'
  begin
  res = token.get('http://api.lvh.me:3000/v1/me.json')
    me = JSON.parse(res.body)
  rescue OAuth2::Error => e
    me = { error: { code: e.code, description: e.description } }
  end
  PP.pp({
    expires_at: Time.at(token.expires_at),
    access_token: token.token,
    refresh_token: token.refresh_token,
    # info: info_response,
    me: me,
    introspect_access_token: response.parsed,
    introspect_refresh_token: response2.parsed,
  }, '<a href=/login>login</a> <a href=/refresh>refresh</a> <a href=/info>reload</a><xmp>'.dup)
end

get '/refresh' do
  client = OAuth2::Client.new(client_id, client_secret, oauth2_options)
  halt '<a href=/login>login</a>' unless session.key?(:token)
  token = OAuth2::AccessToken.from_hash(client, session[:token])
  token = token.refresh!
  session[:token] = token.to_hash
  redirect '/info'
end
