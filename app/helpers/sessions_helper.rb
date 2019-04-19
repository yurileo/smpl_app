module SessionsHelper
    # Осуществляет вход данного пользователя. 
    def log_in(user)
        session[:user_id] = user.id 
    end
    
    # Возвращает текущего вошедшего пользователя (если есть). 
    def current_user_func
    	if (user_id = session[:user_id])
        @current_user_var ||= User.find_by(id: user_id) 
    	elsif (user_id = cookies.signed[:user_id])
    		#raise # Если тест выполнится успешно, значит, эта ветвь не охвачена тестированием.
    		#print user
    		
    		user = User.find_by(id: user_id) 
    		if user && user.authenticated?(cookies[:remember_token])
    			log_in user
    			@current_user_var = user
    		end
    	end
    end

    # Возвращает true, если пользователь зарегистрирован, иначе возвращает false. 
    def logged_in?
        !current_user_func.nil? 
    end
    
    # Осуществляет выход текущего пользователя. 
    def log_out
    	forget(current_user_func)
      session.delete(:user_id)
      @current_user_var = nil 
    end
    
    # Запоминает пользователя в постоянном сеансе. 
    def remember(user)
    	user.remember
    	cookies.permanent.signed[:user_id] = user.id 
    	cookies.permanent[:remember_token] = user.remember_token
    end
    
    
    def forget(user)
    	user.forget
    	cookies.delete(:user_id)
    	cookies.delete(:remember_token)
    end

end
