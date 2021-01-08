########PASSWORD MANAGEMENT SYSTEM########

#Check password complexity - Checks whether the user defined password meets the complexity criteria such as lowercase, uppercase, number, specialcharacters, maxlength and minlength
#HIBP Check module - checks if the user supplied password is leaked in any of data breaches. Checks with the HIBP database and returns T/F

import pyhibp
from pyhibp import pwnedpasswords as pw
import bcrypt
import os
import string
from database_config import *
from json import load

#posixpath 
#Returns the directory component of the pathname and absolute version of the path 

basedir = os.path.abspath(os.path.dirname(__file__))
#print(basedir)

#For password decryption
#Creating a mapping object that represents the user’s environmental variables. 

encrypted_key = os.environ[current_env+'_encryptkey'].encode('utf-8')
complexity_file = os.environ[current_env+'_COMPLEX']


class Password:
    @staticmethod
    def check_hibp(password):
        
        #Setting the User-Agent to be used in subsequent calls sent to the HIBP API backend.
        
        pyhibp.set_user_agent(ua="PMS-User")

        # Check if a password has been disclosed in any of the data breaches

        resp = pw.is_password_breached(password=password)
        if resp:
            return True
        
        #Retrieves all available data classes from the HIBP API.
        #Returns a listing of all sites breached in the HIBP database.
        #Returns a single breach's information from the HIBP's database.
        resp = pyhibp.get_data_classes()
        resp = pyhibp.get_all_breaches()
        resp = pyhibp.get_single_breach(breach_name="Amazon")

        #Set an API key for use in all future calls to the pyhibp module which search the HIBP database by email address.
        HIBP_API_KEY = None

        if HIBP_API_KEY:
            #Set the API key prior to using the functions which require it.
            pyhibp.set_api_key(key=HIBP_API_KEY)

            #Get pastes affecting a given email address
            resp = pyhibp.get_pastes(email_address="admin@gmail.com")
            resp = pyhibp.get_account_breaches(account="admin@gmail.com", truncate_response=True)
    
            
    @staticmethod
    def check_complexity(password):
        with open(basedir +'/'+complexity_file, 'r') as file:
            criteria = load(file)
            spCharater = criteria['existSpecialCharacter']
            upperCase = criteria['existUpperCase']
            lowerCase = criteria['existLowerCase']
            number = criteria['existNumber']
            spCharaterList = criteria['specialCharaterList']
            maxLen = criteria['maxLength']
            minLen = criteria['minLength']
            charaterType = criteria['charaterType']
            
            #print (spCharater)
            
            if len(password) < minLen:
                return False, "Password policy not satisfied. Please make sure your password is at least " + str(minLen) + " characters"

            if len(password) > maxLen:
                return False, "Password policy not satisfied. Please make sure your password is atmost" + str(maxLen) + " characters"
            
            if number is True: 
                if any(str.isdigit(password) for password in password) != number:
                    return False, "Password policy not satisfied. Please make sure your password contains one number"
                else:
                    pass
                    
            if upperCase is True: 
                if any(password.isupper() for password in password) != upperCase:
                    return False, "Password policy not satisfied. Please make sure your password contains atleast one uppercase character"
                else:
                    pass

            if lowerCase is True:
                if  any(password.islower() for password in password) != lowerCase:
                        return False, "Password policy not satisfied. Please make sure your password contains atleast one lowercase character"
                else:
                    pass
                
            if spCharater  is True:
                if any(cha in spCharaterList for cha in password) != True:
                    return False, "Password policy not satisfied. Please make sure your password contains atleast one special charater"
                else:
                    pass
            
            if any(cha not in charaterType for cha in password):
                return False, "Please enter allowed characters only."
                
            else:
                return True, "Successful password!!"
        
    
    #bcrypt is based on the Blowfish block cipher cryptomatic algorithm and takes the form of an adaptive hash function.
    #bcrypt is extremely resistant to hacks, especially a type of password cracking called rainbow table.
    
    @staticmethod
    def password_hash(password):
        encoded_password = password.encode("utf-8")
        password_hashed = bcrypt.hashpw(encoded_password, bcrypt.gensalt())
        #print(password_hashed)
        return password_hashed

    @staticmethod
    def verify_password(hash_password,password):
        password_hash=hash_password.encode("utf-8")
        passsword_status =  bcrypt.checkpw(password_hash, password)
        return passsword_status

    @staticmethod
    def encrypt_password(password):
        key = encrypted_key
        BLOCK_SIZE = 32 
        plain_text = password
        data = plain_text.encode('utf-8')
        cipher = AES.new(key, AES.MODE_ECB)
        ciphered_text = cipher.encrypt(pad(data,BLOCK_SIZE))
        return ciphered_text


    def decrypt_pwd(cipher_text):
        cipher = AES.new(encrypted_key, AES.MODE_ECB)
        deciphered_bytes = cipher.decrypt(cipher_text)
        decrypted_data = deciphered_bytes.decode('utf-8')
        return ''.join(x for x in decrypted_data if x in string.printable)
   