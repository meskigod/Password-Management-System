###PMS Testing module###
#Following are the test cases written 
#Register as a new ADMIN user

#1. Check if the user can be logged in as admin
#2. Validity check - JWT token
#3. Update password complexity - check if the system allows for admin access only
#4. Force renew password when configuration changes

import requests
import unittest
import json
from json import dumps, loads, load
from app import app, db
from databases.password_models import Users
from password_module.password import Password

###admin@gmail.com
###a23eSP$rt5

class AppTest(unittest.TestCase):

#setting up the login parameters
    def setUp(self):
        self.app  = app.test_client()
        self.app.testing = True
        email = 'admin@gmail.com'
        password = Password.password_hash('a23eSP$rt5')
        role = 'ADMIN'
        username = 'admin'
        pwdcriteastatus = 1
        self.user = Users.add_new_user(username,password,email,role,pwdcriteastatus)
    
#Testing login function with correct username and login with admin access
    
    def test_login(self):
        response = self.app.post('/login', 
            data = dumps({
                "email":"admin@gmail.com",
                "password": "a23eSP$rt5",
            }), content_type='application/json'
        )
        reponse_data = loads(response.data)
        self.token = reponse_data['token']
        self.assertEqual(reponse_data["email"], "admin@gmail.com")
        self.assertEqual(response.status_code, 200)

#Testing when the admin tries to update the password complexity criteria without a valid session JWT token
#The test is check to whether the system does not allow the the user to change the criteria - Unauthorized access (401)
    
    def test_update_complexity_without_JWT_token(self):
        resp_login = self.app.post('/login', 
            data = dumps({
                "email":"admin@gmail.com",
                "password": "a23eSP$rt5",
            }),content_type='application/json'
        )
        reponse_data = loads(resp_login.data)
        self.token = reponse_data['token']

        response = self.app.post('/update_pwd_criteria',
            data = dumps({
                "charaterType": "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()?/.<>,{}[]:;|\\`'_-+= ",
                "existLowerCase": True,
                "existNumber": True,
                "existSpecialCharacter": True,
                "existUpperCase": True,
                "maxLength": 16,
                "minLength": 8,
                "specialCharaterList": "!@#$%^&*()?/.<>,{}[]:;|\\`'_-+="
            }),content_type='application/json'
            
        )
        self.assertEqual(response.status_code, 401)    
    
#Testing when the admin tries to update the password complexity criteria with a valid session JWT token
#The test is check to whether the system allows to change the criteria for admin users only - success (200)

    def test_update_complexity(self):
        resp_login = self.app.post('/login', 
            data = dumps({
                "email":"admin@gmail.com",
                "password": "a23eSP$rt5",
            }),content_type='application/json'
        )
        reponse_data = loads(resp_login.data)
        self.token = reponse_data['token']

        response = self.app.post('/update_pwd_criteria',
            data = dumps({
                "charaterType": "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()?/.<>,{}[]:;|\\`'_-+= ",
                "existLowerCase": True,
                "existNumber": True,
                "existSpecialCharacter": True,
                "existUpperCase": True,
                "maxLength": 16,
                "minLength": 8,
                "specialCharaterList": "!@#$%^&*()?/.<>,{}[]:;|\\`'_-+="
            }),content_type='application/json',headers={'x-access-tokens': self.token}
            
        )
        self.assertEqual(response.status_code, 200)
    
#Testing to check if the users receive notification to change the password when the complexity criteria changes. The user gets notification on his next login

#Message - "System adminstartor recently change the password policy. Please update the password!"

    def test_force_renew_password(self):
        response = self.app.post('/login', 
            data = dumps({
                "email":"admin@gmail.com",
                "password": "a23eSP$rt5",
            }), content_type='application/json'
        )
        reponse_data = loads(response.data)
        self.assertTrue(reponse_data["Message"], "System administrator recently change the password policy. Please update the password!")

    def tearDown(self): 
        db.session.query(Users).delete()


   
if __name__ == '__main__':
    unittest.main()