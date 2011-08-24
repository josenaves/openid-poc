class AddOpenIdIdentityToUsers < ActiveRecord::Migration
  def self.up
    add_column :users, :openid_identity, :string
  end

  def self.down
    remove_column :users, :openid_identity
  end
end
