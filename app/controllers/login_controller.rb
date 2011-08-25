require 'pathname'

require 'openid'
require 'openid/extensions/sreg'
require 'openid/store/filesystem'

class LoginController < ApplicationController
    
  skip_before_filter :authenticate, :only => [:new, :create, :index, :logado, :start, :complete]
  layout nil
  
  def index
  end
  
  def logado
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
    if params[:use_sreg]
      sregreq = OpenID::SReg::Request.new
      # required fields
      sregreq.request_fields(['email','nickname'], true)
      # optional fields
      sregreq.request_fields(['dob', 'fullname'], false)
      oidreq.add_extension(sregreq)
      oidreq.return_to_args['did_sreg'] = 'y'
    end
    if params[:use_pape]
      papereq = OpenID::PAPE::Request.new
      papereq.add_policy_uri(OpenID::PAPE::AUTH_PHISHING_RESISTANT)
      papereq.max_auth_age = 2*60*60
      oidreq.add_extension(papereq)
      oidreq.return_to_args['did_pape'] = 'y'
    end
    
    if params[:force_post]
      oidreq.return_to_args['force_post']='x'*2048
    end
    
    return_to = url_for :controller => 'login', :action => 'complete', :only_path => false
    #realm = url_for :action => 'index', :id => nil, :only_path => false
    realm = return_to
    
    if oidreq.send_redirect?(realm, return_to, params[:immediate])
      redirect_to oidreq.redirect_url(realm, return_to, params[:immediate])
    else
      render :text => oidreq.html_markup(realm, return_to, params[:immediate], {'id' => 'openid_form'})
    end
    
  end
  

  def complete
    # FIXME - url_for some action is not necessarily the current URL.
    current_url = url_for :action => 'complete', :only_path => false
    
    puts "request.path_parameters: #{request.path_parameters}"
    puts "params (antes reject): #{params}"
    
    #parameters = params.reject{|k,v| request.path_parameters[k]}
    
    # IMPORTANTE PARA RAILS3
    parameters = params.reject{|k,v| ['controller','action'].include?(k) }
    #parameters = params.reject{|k,v| k == 'controller' || k =='action' }
    
    puts "parameters (apos reject): #{parameters}"
    

    oidresp = consumer.complete(parameters, current_url)
    
    puts "oidresp: #{oidresp.class}"
    puts "oidresp: #{oidresp}"
    
    puts "message: #{oidresp.message.class()}"
    puts "message: #{oidresp.message}"

    puts "signed_fields: #{oidresp.signed_fields.class}"
    puts "signed_fields: #{oidresp.signed_fields}"
    
    puts "oidresp.endpoint.display_identifier = #{oidresp.endpoint.display_identifier}"
    puts "oidresp.endpoint.to_s = #{oidresp.endpoint.to_s}"
    
    puts "-----------------"
    puts "oidresp.get_signed : "
    puts oidresp.get_signed "http://specs.openid.net/auth/2.0", "openid.identity"
    puts "-----------------"
    
    puts "parameters.class: #{parameters.class}"
    puts "parameters #{parameters}"
    
    case oidresp.status
    when OpenID::Consumer::FAILURE
      if oidresp.display_identifier
        flash[:error] = ("Verification of #{oidresp.display_identifier} failed: #{oidresp.message}")
      else
        flash[:error] = "Verification failed: #{oidresp.message}"
      end
    
    when OpenID::Consumer::SUCCESS
      flash[:success] = ("Verification of #{oidresp.display_identifier} succeeded.")

      #puts ">>>>>>>>>>>>>>>>>>>>>> oidresp['email'] = #{oidresp['email']}"
           
      if params[:did_sreg]
        sreg_resp = OpenID::SReg::Response.from_success_response(oidresp)
        sreg_message = "Simple Registration data was requested"
        
        if sreg_resp.empty?
          sreg_message << ", but none was returned."
        else
          sreg_message << ". The following data were sent:"
          sreg_resp.data.each { |k,v| sreg_message << "<br/><b>#{k}</b>: #{v}" }
          
          # pegar o email e o id
          puts "............................ sreg_resp.data['email'] = #{sreg_resp.data['email']}"
          puts "............................ parameters['openid.identity'] = #{parameters['openid.identity']}"
          
          identity = parameters['openid.identity']
          email = sreg_resp.data['email']
          
          # buscar o usuario no banco
          usuario = User.find_by_openid_identity(identity)
          puts "usuario #{usuario}"
          
          usuario = User.find_by_login(email)
          puts "usuario #{usuario}"
          
          if !usuario
            puts "Usuario e' nill"
          else
            puts "usuario.id #{usuario.id}"
            usuario.openid_identity = identity
            usuario.save
            
            session[:user_id] = usuario.id
            
            puts "session: #{session}"
          end
          
          
                 
        end
        flash[:sreg_results] = sreg_message
      end
      
      if params[:did_pape]
        pape_resp = OpenID::PAPE::Response.from_success_response(oidresp)
        pape_message = "A phishing resistant authentication method was requested"
        if pape_resp.auth_policies.member? OpenID::PAPE::AUTH_PHISHING_RESISTANT
          pape_message << ", and the server reported one."
        else
          pape_message << ", but the server did not report one."
        end
        if pape_resp.auth_time
          pape_message << "<br><b>Authentication time:</b> #{pape_resp.auth_time} seconds"
        end
        if pape_resp.nist_auth_level
          pape_message << "<br><b>NIST Auth Level:</b> #{pape_resp.nist_auth_level}"
        end
        flash[:pape_results] = pape_message
      end
      
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
      # utilizacao de openIDStore em banco
      store = ActiveRecordStore.new
      @consumer = OpenID::Consumer.new(session, store)
    end
    return @consumer
  end

end
