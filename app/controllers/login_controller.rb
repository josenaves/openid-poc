require 'pathname'

require 'openid'
require 'openid/extensions/sreg'
require 'openid/store/filesystem'

class LoginController < ApplicationController
  
  skip_before_filter :authenticate, :only => [:new, :create]
  layout nil
  
  def index
  end
  
  def start
    begin
      identifier = params[:openid_identifier]
      if identifier.nil?
        flash[:error] = "Enter an OpenID identifier"
        redirect_to :action => 'index'
        return
      end
      oidreq = consumer.begin(identifier)
    rescue OpenID::OpenIDError => e
      flash[:error] = "Discovery failed for #{identifier}: #{e}"
      redirect_to :action => 'index'
      return
    end

    return_to = url_for :action => 'complete', :only_path => false
    realm = url_for :action => 'index', :id => nil, :only_path => false

    
    if oidreq.send_redirect?(realm, return_to, params[:immediate])
      redirect_to oidreq.redirect_url(realm, return_to, params[:immediate])
    else
      render :text => oidreq.html_markup(realm, return_to, params[:immediate], {'id' => 'openid_form'})
    end
  end

  def complete
    
    # FIXME - url_for some action is not necessarily the current URL.
    current_url = url_for(:action => 'complete', :only_path => false)
    parameters = params.reject{|k,v|request.path_parameters[k]}
    oidresp = consumer.complete(parameters, current_url)
    case oidresp.status
    when OpenID::Consumer::FAILURE
      if oidresp.display_identifier
        flash[:error] = ("Verification of #{oidresp.display_identifier}"\
                         " failed: #{oidresp.message}")
      else
        flash[:error] = "Verification failed: #{oidresp.message}"
      end
    when OpenID::Consumer::SUCCESS
      flash[:success] = ("Verification of #{oidresp.display_identifier} succeeded.")

    when OpenID::Consumer::SETUP_NEEDED
      flash[:alert] = "Immediate request failed - Setup Needed"
    when OpenID::Consumer::CANCEL
      flash[:alert] = "OpenID transaction cancelled."
    else
    end
    redirect_to :action => 'index'
  end

  private

  def consumer
    if @consumer.nil?
      dir = Pathname.new(Rails.root.to_s).join('db').join('cstore')
      store = OpenID::Store::Filesystem.new(dir)
      @consumer = OpenID::Consumer.new(session, store)
    end
    return @consumer
  end

end
