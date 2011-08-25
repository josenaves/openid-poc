class ApplicationController < ActionController::Base
  before_filter :authenticate
  
  protect_from_forgery
  
  protected
  
  def authenticate
    if !session[:user_id] 
      redirect_to :controller => 'login', :notice => 'E preciso estar logado'
    end
  end
  
end
