class User < ApplicationRecord
    #self.table_name = 'dbo.users'
    attr_accessor :remember_token
    
    before_save {self.email = email.downcase}
    validates :name, presence: true, length: {maximum: 50 }
    validates :password, length: {minimum: 6 }
    VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i
    validates :email, presence: true, length: {maximum: 255 },
                            format: { with: VALID_EMAIL_REGEX },
                            uniqueness: {case_sensitive: false}
    has_secure_password
    
    # Возвращает дайджест для указанной строки
    def User.digest(string)
        cost = ActiveModel::SecurePassword.min_cost ? 
                            BCrypt::Engine::MIN_COST :
                            BCrypt::Engine.cost 
        BCrypt::Password.create(string, cost: cost)
    end
    
    # Возвращает случайный токен
    def User.new_token
        SecureRandom.urlsafe_base64 
    end
    
    
    def remember
        self.remember_token = User.new_token
        update_attribute(:remember_digest, User.digest(self.remember_token))
    end


    # Возвращает true, если указанный токен соответствует дайджесту
    def authenticated?(rememb_token)
        return false if remember_digest.nil?
        BCrypt::Password.new(remember_digest).is_password?(rememb_token) 
    end
    
    
    def forget
      update_attribute(:remember_digest, nil)  
    end


end
