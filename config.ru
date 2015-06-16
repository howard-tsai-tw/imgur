#ENV['RACK_ENV'] = "production"

#require './app'

#run SinatraImgur


require "rubygems"
require "sinatra"

require File.expand_path '../app.rb', __FILE__

run SinatraImgur
