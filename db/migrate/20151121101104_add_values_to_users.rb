class AddValuesToUsers < ActiveRecord::Migration
  def change
    add_column :users, :uid, :string
    add_column :users, :lastname, :string
    add_column :users, :firstname, :string
  end
end
