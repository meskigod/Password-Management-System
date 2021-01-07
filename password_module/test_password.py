#########Unit test cases - Check Password ###########

#Testing password complexity
#Validate if a password matches the saved hash
#HIBP password leak status verification 
#Encrypt and Decrypt functions 

import unittest
from .password import Password as Password
class PasswordTest(unittest.TestCase):

    def setUp(self):
        self.password1 = 'password'
        
        self.password2 = '12345678'
        
        self.password3 = 'ABC123456'
        
        self.password4 = '!@#$AD'
        
        self.password5 = '12A&&#Abdgc@'
        
        self.password6 = '12A&&#Abdgc@12A&&#Abdgc@12A&&#Abdgc@'

    def test_complexity(self):
        self.assertEqual(Password.check_complexity(self.password1), (False, 'Password policy not satisfied. Please make sure your password contains one number'))

        self.assertEqual(Password.check_complexity(self.password1+'1A#ß'), (False, 'Please enter allowed characters only.'))
        
        self.assertEqual(Password.check_complexity(self.password1+'1'), (False, 'Password policy not satisfied. Please make sure your password contains atleast one uppercase character'))

        self.assertEqual(Password.check_complexity(self.password1+'3C'), (False, 'Password policy not satisfied. Please make sure your password contains atleast one special charater'))

        self.assertEqual(Password.check_complexity(self.password2+'F@'), (False, 'Password policy not satisfied. Please make sure your password contains atleast one lowercase character'))

        """self.assertEqual(Password.check_complexity(self.password6), (False, 'Password policy not satisfied. Please make sure your password is atmost 16 characters'))
        
        self.assertEqual(Password.check_complexity(self.password1+'1A#'), (True, 'Successful password!!'))"""

    def test_hibp(self):
        #Check if the created password is leaked or not
        #Returns true if password is leaked

        self.assertTrue(Password.check_hibp(self.password1))
        
        self.assertTrue(Password.check_hibp(self.password2))
        
        self.assertTrue(Password.check_hibp(self.password3))
        
        #return false since the password isnt leaked
        self.assertFalse(Password.check_hibp(self.password5))
 
    def test_password_validity(self):
        #check if the entered password and hash passwords are same 

        self.assertTrue(Password.verify_password(self.password1, Password.password_hash(self.password1)))#returns true - same passwords  
        
        self.assertTrue(Password.verify_password(self.password2, Password.password_hash(self.password2)))#returns true - same passwords
        
        self.assertFalse(Password.verify_password(self.password1, Password.password_hash(self.password4)))#returns false - different passwords  
        
        self.assertFalse(Password.verify_password(self.password3, Password.password_hash(self.password5)))#returns false - different passwords 

    
    def test_encrypt_decrypt_pwd(self):
        #testing encrypt and decrypt functions for passwords
          
        cipher_text = Password.encrypt_password(self.password5)
        
        self.assertTrue(type(cipher_text) == bytes) 
        
        decrypt_text = Password.decrypt_pwd(cipher_text)
        
        #same password encryption and decryption
        
        self.assertTrue(decrypt_text == self.password5)
        
        #different passwords
        
        self.assertFalse(decrypt_text == self.password4)
    

    def tearDown(self):
        pass   
   
if __name__ == '__main__':
    unittest.main()