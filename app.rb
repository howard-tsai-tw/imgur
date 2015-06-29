require 'rubygems'
require 'sinatra'
require "sinatra/json"
require 'json'
require 'bundler'
require 'fileutils'
require "sinatra/logger"
Bundler.require

# load the Database and User model
require './model'

FUNCTION_SUCCESS = "success"
FUNCTION_FAILED = "error"
IMAGE_FOLDER = "/ROR/image/"

Warden::Strategies.add(:password) do
  def valid?
    params['user'] && params['user']['username'] && params['user']['password']
  end

  def authenticate!
    user = User.first(username: params['user']['username'])

    if user.nil?
      throw(:warden, message: "The username you entered does not exist.")
    elsif user.authenticate(params['user']['password'])
      success!(user)
    else
      throw(:warden, message: "The username and password combination ")
    end
  end
end

class SinatraImgur < Sinatra::Base

  enable :sessions
  register Sinatra::Flash
  register Sinatra::Contrib #important ==> refer to https://github.com/sinatra/sinatra-contrib
  register Sinatra::Logger
  set :environment, :production
  set :session_secret, "supersecret"
  set :root, './'
  set :logger_log_file, lambda { "./image.log" }
  set :logger_level, :info

  #puts settings.environment
  
  use Warden::Manager do |config|
    # Tell Warden how to save our User info into a session.
    # Sessions can only take strings, not Ruby code, we'll store
    # the User's `id`
    config.serialize_into_session{|user| user.id }
    # Now tell Warden how to take what we've stored in the session
    # and get a User from that information.
    config.serialize_from_session{|id| User.get(id) }

    config.scope_defaults :default,
      # "strategies" is an array of named methods with which to
      # attempt authentication. We have to define this later.
      strategies: [:password],
      # The action is a route to send the user to when
      # warden.authenticate! returns a false answer. We'll show
      # this route below.
      action: 'auth/unauthenticated'
    # When a user tries to log in and cannot, this specifies the
    # app to send the user to.
    config.failure_app = self
  end

  Warden::Manager.before_failure do |env,opts|
    env['REQUEST_METHOD'] = 'POST'
  end

  post '/add_new_user' do
    return_message = "success!!"
    user = params['user']
    password = params['password']
    newuser = params['newuser']
    newuserpw = params['newuserpw']

    #check is user & password
    if User.all(:username => user).first.nil?
      return_message = "Wrong user name #{user}!!"
      logger.info("ERROR, #{return_message}")
      return { :result => FUNCTION_FAILED, :message => return_message }.to_json
    end

    if User.all(:username => user).first.authenticate(password) != true
      return_message = "User:#{user}, wrong password!!"
      logger.info("ERROR, #{return_message}")
      return { :result => FUNCTION_FAILED, :message => return_message }.to_json
    end

    #check is new user name already exist
    if User.all(:username => newuser).first.nil? != true
      return_message = "User name #{newuser} already exist!!"
      logger.info("ERROR, #{return_message}")
      return { :result => FUNCTION_FAILED, :message => return_message }.to_json
    end

    newone = User.new(:username=>newuser, :password=>newuserpw)
    if newone.save != true
      return_message = "New user #{newuser} create failed!!"
      logger.info("ERROR, #{return_message}")
      return { :result => FUNCTION_FAILED, :message => return_message }.to_json
    else
      return_message = "New user #{newuser} create success!!"
      logger.info("SUCCESS, #{return_message}")
      return { :result => FUNCTION_SUCCESS, :message => return_message }.to_json
    end
  end

  post '/del_user' do
    return_message = "success!!"
    user = params['user']
    password = params['password']
    deluser = params['deluser']

    #check is user & password
    if User.all(:username => user).first.nil?
      return_message = "Wrong user name #{user}!!"
      logger.info("ERROR, #{return_message}")
      return { :result => FUNCTION_FAILED, :message => return_message }.to_json
    end

    if User.all(:username => user).first.authenticate(password) != true
      return_message = "User:#{user}, wrong password!!"
      logger.info("ERROR, #{return_message}")
      return { :result => FUNCTION_FAILED, :message => return_message }.to_json
    end

    if User.all(:username => deluser).first.nil? != true
      User.all(:username => deluser).first.destroy
      return_message = "User #{deluser} be deleted!!"
      logger.info("SUCCESS, #{return_message}")
      return { :result => FUNCTION_SUCCESS, :message => return_message }.to_json
    else
      return_message = "User #{deluser} non-exist!!"
      logger.info("ERROR, #{return_message}")
      return { :result => FUNCTION_FAILED, :message => return_message }.to_json
    end
  end
  
  post '/save_image' do
    return_message = "success!!"
    user = params['user']
    #password = params['password']
    album = params['album']

    #check is user exist
    if User.all(:username => user).first.nil?
      return_message = "Wrong user name #{user}!!"
      logger.info("ERROR, #{return_message}")
      return { :result => FUNCTION_FAILED, :message => return_message }.to_json
    end
    
    #check if any uplad file
    unless params[:file] && (tmpfile = params[:file][:tempfile]) && (name = params[:file][:filename])
      return_message = "No file upload!!"
      logger.info("ERROR, #{return_message}")
      return { :result => FUNCTION_FAILED, :message => return_message }.to_json
    end
    
    #create new image & path
    image = Image.new(:image_folder => IMAGE_FOLDER, :user=> user, :album=>album, :filename=>name, :createdate=>DateTime.now)
    if image.nil?
      return_message = "DB new Image failed, user:#{user}, album:#{album}, filename:#{name}!!"
      logger.info("ERROR, #{return_message}")
      return { :result => FUNCTION_FAILED, :message => return_message }.to_json
    else
      image.create_path
    end

    #check if folder exist & mkdir
    if  Dir::exists?(image.path) != true
      FileUtils::mkdir_p image.path
      if  Dir::exists?(image.path) != true
        return_message = "Folder #{image.path} create failed!!"
        logger.info("ERROR, #{return_message}")
        return { :result => FUNCTION_FAILED, :message => return_message }.to_json
      end
    end

    #save file and db
    begin
      file = File.open(image.path_name, 'wb')
      file.write(tmpfile.read) 

      if image.save != true
        orig_img = Image.all(:path_name => image.path_name)
        if orig_img != nil
          orig_img.update(:createdate=>DateTime.now)
        else
          return_message = "DB Image save failed, user:#{user}, album:#{album}, filename:#{name}!!"
          logger.info("ERROR, #{return_message}")
          return { :result => FUNCTION_FAILED, :message => return_message }.to_json
        end
      end      
    rescue IOError => e
      #some error occur, dir not writable etc.
      return_message = "File #{image.path_name} write failed!!"
      logger.info("ERROR, #{return_message}")      
      return { :result => FUNCTION_FAILED, :message => return_message }.to_json
    ensure
      file.close unless file.nil?
    end

    return_message = "Image #{image.path_name} Create Success!!"
    logger.info("SUCCESS, #{return_message}")
    return { :result => FUNCTION_SUCCESS, :message => return_message }.to_json

  end

  post '/save_image_test' do
    return_message = "success!!"
    user = params['user']
    #password = params['password']
    album = params['album']

    #check is user exist
    if User.all(:username => user).first.nil?
      return_message = "Wrong user name #{user}!!"
      logger.info("ERROR, #{return_message}")
      return { :result => FUNCTION_FAILED, :message => return_message }.to_json
    end

    #check if any uplad file
    tmpfile = params[:tmpfile]
    name = params[:filename]

    #create new image & path
    image = Image.new(:image_folder => IMAGE_FOLDER, :user=> user, :album=>album, :filename=>name, :createdate=>DateTime.now)
    if image.nil?
      return_message = "DB new Image failed, user:#{user}, album:#{album}, filename:#{name}!!"
      logger.info("ERROR, #{return_message}")
      return { :result => FUNCTION_FAILED, :message => return_message }.to_json
    else
        logger.info("ERROR12")

      image.create_path
    end

    #check if folder exist & mkdir
    if  Dir::exists?(image.path) != true
      FileUtils::mkdir_p image.path
      if  Dir::exists?(image.path) != true
        return_message = "Folder #{image.path} create failed!!"
        logger.info("ERROR, #{return_message}")
        return { :result => FUNCTION_FAILED, :message => return_message }.to_json
      end
    end

    #save file and db
    begin
      file = File.open(image.path_name, 'wb')
      file.write(tmpfile) 

      if image.save != true
        orig_img = Image.all(:path_name => image.path_name)
        if orig_img != nil
          orig_img.update(:createdate=>DateTime.now)
        else
          return_message = "DB Image save failed, user:#{user}, album:#{album}, filename:#{name}!!"
          logger.info("ERROR, #{return_message}")
          return { :result => FUNCTION_FAILED, :message => return_message }.to_json
        end
      end      
    rescue IOError => e
      #some error occur, dir not writable etc.
      return_message = "File #{image.path_name} write failed!!"
      logger.info("ERROR, #{return_message}")      
      return { :result => FUNCTION_FAILED, :message => return_message }.to_json
    ensure
      file.close unless file.nil?
    end

    return_message = "Image #{image.path_name} Create Success!!"
    logger.info("SUCCESS, #{return_message}")
    return { :result => FUNCTION_SUCCESS, :message => return_message }.to_json

  end


  get '/show_image' do
    @bresult = false
    @return_message = "success!!"
    user = params['user']
    #password = params['password']
    album = params['album']
    filename = params['filename']

    #check is user exist
    if User.all(:username => user).first.nil?
      @return_message = "Wrong user name #{user}!!"
      logger.info("ERROR, #{@return_message}")
      return erb :show_image
    end

    Img = Image.all(:user => user, :album => album, :filename => filename).first
    if Img.nil?
      @return_message = "No image for user:#{user}, album:#{album}!!"
      logger.info("ERROR, #{@return_message}")
      return erb :show_image
    end
    
    if File.exists?(Img.path_name)
      @bresult = true
      logger.info("SUCCESS, #{Img.path_name}")
      @imagetime = Img.createdate.strftime("%Y-%m-%d-%T")
      @user = user
      if album.nil? 
        @album = ''
      else
        @album = album
      end
      @filename = filename
    else
      @return_message = "Image file #{lastImg.path_name} not exist!!"
      Img.destroy
      logger.info("ERROR, #{return_message}")      
    end
    return erb :show_image
  end

  get '/show_latest_image' do
    @bresult = false
    @return_message = "success!!"
    user = params['user']
    album = params['album']

    #check is user exist
    if User.all(:username => user).first.nil?
      @return_message = "Wrong user name #{user}!!"
      logger.info("ERROR, #{@return_message}")
      return erb :show_latest_image
    end

    lastImg = Image.all(:user => user, :album => album, :order => [ :createdate.asc ]).last
    if lastImg.nil?
      @return_message = "No image for user:#{user}, album:#{album}!!"
      logger.info("ERROR, #{@return_message}")
      return erb :show_latest_image
    end
    
    if File.exists?(lastImg.path_name)
      @bresult = true
      logger.info("SUCCESS, #{lastImg.path_name}")
      @imagetime = lastImg.createdate.strftime("%Y-%m-%d-%T")
      @user = user
      if album.nil? 
        @album = ''
      else
        @album = album
      end
      @filename = lastImg.filename
    else
      @return_message = "Image file #{lastImg.path_name} not exist!!"
      lastImg.destroy
      logger.info("ERROR, #{return_message}")      
    end
    return erb :show_latest_image

  end

  #Get latest image by user & album
  #Input: user, album
  #Output:
  #  Success: "success", #{imagetime}, #{image}"
  #  Fail: "error", #{error_message} 
  get '/get_latest_image' do
    return_message = "success!!"
    user = params['user']
    album = params['album']

    #check is user exist
    if User.all(:username => user).first.nil?
      return_message = "Wrong user name #{user}!!"
      logger.info("ERROR, #{return_message}")
      return { :result => FUNCTION_FAILED, :message => return_message }.to_json
    end

    #lastImg = Image.all(:user => user, :album => album).last
    lastImg = Image.all(:user => user, :album => album, :order => [ :createdate.asc ]).last
    if lastImg.nil?
      return_message = "No image for user:#{user}, album:#{album}!!"
      logger.info("ERROR, #{return_message}")
      return { :result => FUNCTION_FAILED, :message => return_message }.to_json
    end
    
    if File.exists?(lastImg.path_name)
      content = File.read(lastImg.path_name)
      logger.info("SUCCESS, #{lastImg.path_name}")
      imagetime = lastImg.createdate.strftime("%Y-%m-%d-%T")
      return { :result => FUNCTION_SUCCESS, :imagetime => imagetime, :content => content }.to_json
    else
      return_message = "Image file #{lastImg.path_name} not exist!!"
      lastImg.destroy
      logger.info("ERROR, #{return_message}")      
      return { :result => FUNCTION_FAILED, :message => return_message }.to_json
    end

  end

  get '/get_latest_image_url' do
    return_message = "success!!"
    user = params['user']
    album = params['album']

    #check is user exist
    if User.all(:username => user).first.nil?
      return_message = "Wrong user name #{user}!!"
      logger.info("ERROR, #{return_message}")
      return { :result => FUNCTION_FAILED, :message => return_message }.to_json
    end

    lastImg = Image.all(:user => user, :album => album, :order => [ :createdate.asc ]).last
    if lastImg.nil?
      return_message = "No image for user:#{user}, album:#{album}!!"
      logger.info("ERROR, #{return_message}")
      return { :result => FUNCTION_FAILED, :message => return_message }.to_json
    end
    
    if File.exists?(lastImg.path_name)
      logger.info("SUCCESS, #{lastImg.path_name}")
      return { :result => FUNCTION_SUCCESS, :imageurl => "/images/upload/#{user}/#{album}/#{lastImg.filename}", :imagetime => lastImg.createdate }.to_json
    else
      return_message = "Image file #{lastImg.path_name} not exist!!"
      lastImg.destroy
      logger.info("ERROR, #{return_message}")      
      return { :result => FUNCTION_FAILED, :message => return_message }.to_json
    end
  end


  post '/save_images' do

     logger.info("save_images.....")      
        
    #puts params[:image][0]
    #puts params[:image][1]

    #@filename = params[:file][:filename]
    #file = params[:file][:tempfile]
    #type = params[:file][:type]

    #:type=>"image/jpeg"

    #puts @filename
    #puts file

    #@filename = params[:image][0][:filename]
    #file = params[:image][0][:tempfile]
    
    #File.open("./public/#{@filename}", 'wb') do |f|
    #  f.write(file.read)
    #end
    
    #erb :show_image
  end

  get '/' do
    erb :index
  end

  get '/auth/login' do
    erb :login
  end

  post '/auth/login' do
    env['warden'].authenticate!

    flash[:success] = env['warden'].message

    if session[:return_to].nil?
      redirect '/'
    else
      redirect session[:return_to]
    end
  end

  get '/auth/logout' do
    env['warden'].raw_session.inspect
    env['warden'].logout
    flash[:success] = 'Successfully logged out'
    redirect '/'
  end

  post '/auth/unauthenticated' do
    session[:return_to] = env['warden.options'][:attempted_path] if session[:return_to].nil?

    # Set the error and use a fallback if the message is not defined
    flash[:error] = env['warden.options'][:message] || "You must log in"
    redirect '/auth/login'
  end

  get '/protected' do
    env['warden'].authenticate!

    puts :current_user
    puts env['warden'].user.inspect
    puts env['warden'].inspect

    erb :protected
  end

  get '/admin' do
    #env['warden'].authenticate!

    erb :admin

  end

  get '/user' do
    env['warden'].authenticate!

    erb :user
  end
  
  get '/image' do
    #env['warden'].authenticate!

    erb :image
  end


  get '/list.json' do
    options = {
      search: params[:search],
      column: params[:iSortCol_0],
      direction: params[:sSortDir_0]
    }

    puts options[:search]
    puts options[:column]
    puts options[:direction]

    data = User.all.to_json

    puts data
    puts params[:sEcho]
    
    json({
      aaData: data,
      sEcho: params[:sEcho],
      iTotalRecords: User.count,
      iTotalDisplayRecords: User.count
    })
  end

end

