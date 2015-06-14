require 'rubygems'
require 'data_mapper'
require 'dm-sqlite-adapter'
require 'bcrypt'
#require 'dm-mysql-adapter'

DataMapper.setup(:default, "sqlite://#{Dir.pwd}/db.sqlite")
#DataMapper.setup(:default, "mysql://root:@localhost/imgdb")

class User
  include DataMapper::Resource
  include BCrypt

  #has n, :album_items

  property :id, Serial, key: true
  property :username, String, length: 128, :unique => true

  property :password, BCryptHash

  def authenticate(attempted_password)
    # The BCrypt class, which `self.password` is an instance of, has `==` defined to compare a
    # test plain text string to the encrypted string and converts `attempted_password` to a BCrypt
    # for the comparison.
    #
    # But don't take my word for it, check out the source: https://github.com/codahale/bcrypt-ruby/blob/master/lib/bcrypt/password.rb#L64-L67
    if self.password == attempted_password
      true
    else
      false
    end
  end
end

class Image
  include DataMapper::Resource

  #belongs_to :album_item, :key => true

  property :id, Serial, key: true
  property :image_folder, String, length: 128, :required => true
  property :user, String, length: 128, :required => true
  property :album, String, length: 128
  property :filename, String, length: 128, :required => true
  property :path, String, length: 512, :required => true
  property :path_name, String, length: 512, :required => true , :unique => true
  property :createdate, DateTime, :required => true

  def create_path
    if self.album.nil?
      self.path = self.image_folder + self.user
      self.path_name = self.image_folder + self.user + "/" + self.filename
    else
      self.path = self.image_folder + self.user + "/" + self.album
      self.path_name = self.image_folder + self.user + "/" + self.album + "/" +  self.filename
    end
    puts self.path 
  end
 
end

=begin
class AlbumItem
  include DataMapper::Resource

  belongs_to :user, :key => true
  has n, :images
  
  property :name, String, length: 128, :required => true

end
=end

# Tell DataMapper the models are done being defined
DataMapper.finalize

# Update the database to match the properties of User.
DataMapper.auto_upgrade!

# Create a test User
if User.count == 0
  @user = User.create(username: "admin")
  @user.password = "admin"
  @user.save
end
