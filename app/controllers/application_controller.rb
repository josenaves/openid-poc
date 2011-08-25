class ApplicationController < ActionController::Base
  protect_from_forgery
  
  private
  
  def authenticate?
    session[:user_id] != nil
  end
  
end
