########PASSWORD MANAGEMENT SYSTEM########

##API MODULES##
#User Registration - To create new user
#Login functionality
#Create Legacy Applications - legacy applications for which password has to be managed
#Get All system users  
#Add passwords to the legacy applications
#Get all passwords for logged in users
#view password complexity criteria - for all users
#update password complexity criteria - for admin only

#Importing all required libraries and functionalities 

from password_module.password import Password
from database_config import *
from databases.password_models import Users
from databases.password_models import UserSchema
from databases.password_models import Passwords
from databases.password_models import PasswordSchema
from databases.password_models import LegacyApp
from databases.password_models import LegacyAppSchema
from password_module.password_complexity_criteria import PasswordComplexity


app.config['SECRET_KEY'] = os.environ[current_env+'_secretkey']

#JWT authentication uses the header and payload (base64 encoding) to create a token
#To validate REST endpoints, we use JWT (JSON Web Tokens). Without JWT, a user cannot access the system  
#When the user or admin access API via Postman, JWT token needs to be passed in the header section via 'x-access-tokens'

def token_required(f):
    @wraps(f)
    def dec(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']
        if not token:
            return jsonify({
                'Error Message': "Inserted Token is not valid!"
            }), 401
        try:

            token = jwt.decode(token, app.config['SECRET_KEY'],algorithms=["HS256"])
            return f(*args,  **kwargs)
        except:
            return jsonify({
                'Error Message': "Token expired! Please login to continue"
            }), 401

    return dec
##########################################

#It is necessary to validate the input. An attacker can bypass authentication or inject code if input not validated

def required_params(schema):
    def dec(fn):
 
        @wraps(fn)
        def wrap(*args, **kwargs):
            try:
                schema.load(request.get_json())
            except ValidationError as err:
                error = {
                    "status": "error",
                    "messages": err.messages
                }
                return jsonify(error), 400
            return fn(*args, **kwargs)
 
        return wrap
    return dec

##########################################

#User Registration module 
#User modes - Normal and administrator 
# User registration module
@app.route('/signup', methods=['POST'])
@required_params(UserSchema())
def register():

    try:
        request_data = request.get_json()
        username = str(request_data['username'])
        password = str(request_data['password'])
        email = request_data['email']
        role = "USER"
        pwdcriteastatus = 1
        #Check this email address is already exist or not
        user = Users.check_login(email)
        if user:
            error_message = "This email address is already registered!"
            return jsonify({
                'Error Meesage': error_message
            }), 401
        else:
            hibp_result = Password.check_hibp(password)
            is_complexity, complexity_result_msg = Password.check_complexity(
                password)
            hash_result = Password.password_hash(password)

            if is_complexity is False:
                return jsonify(Process='ERROR!', Process_Message=complexity_result_msg)

            elif hibp_result is True:
                return jsonify(Process='ERROR!', Process_Message='This password is already in HIBP Database.')

            else:
                # return jsonify(Process='SUCESS!', Process_Message='Good Password!')
                # return jsonify(hash_result)
                response = Users.add_new_user(
                    username, hash_result, email, role, pwdcriteastatus)
                return jsonify({"Message": "Succesfuly saved"}), 201


    except (KeyError, exceptions.BadRequest):
        return jsonify(Process='ERROR!', Process_Message='Your token is expired! Please login in again.')

##########################################

#User Login module
#Login modes - Normal and admin

@app.route('/login', methods=['POST'])
def login():
    json_data_request = request.get_json()
    #Get login details from the user
    email = json_data_request['email']
    password_check = json_data_request['password']
    user = Users.check_login(email)
    
    try:
        if user:
            #match the current user password with that saved in the database while registration
            cur_user_pwd = user.password
            #check if password complexity criteria changed
            cur_user_pwd_status = user.passwordCriteraStatus
            if cur_user_pwd_status == 0:
                Message = "The password policy was recently changed by the administrator. Please update the password!"
            else:
                Message = "Your password meet complexity."
            #validate the password if it is expired
            if Password.verify_password(password_check, cur_user_pwd):
                login_session['id'] = user.id
                expiry_date = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
                token = jwt.encode({"exp": expiry_date},app.config['SECRET_KEY'], algorithm="HS256").decode('utf-8')
                login_session['logged_in'] = True
                return jsonify({
                    'user-id': user.id,
                    'email': user.email,
                    'token': token,
                    'Message': Message

                }), 200
            else:
                error_message = "Your username or password is invalid. Please eneter the correct username or password"
                return jsonify({
                    'Error Message': error_message
                }), 401

        else:
            error_message = "Your username or password is invalid. Please eneter the correct username or password"
            return jsonify({
                'Error Message': error_message
            }), 401
    except (KeyError, exceptions.BadRequest):
        return jsonify(Process='ERROR!', Process_Message='Something went wrong! Please login in again')

##########################################

#Password module 
#The user creates the password for the legacy applications as per the app_id. The password is also verified if it is leaked in the HIBP database 

@app.route('/add_pwd_app', methods=['POST'])
@token_required
@required_params(PasswordSchema())
def add_new_pwd():
    try:
        #user is already logged in - so two parameters to be passed - app_id and app_pwd
        json_data_request = request.get_json()
        app_pwd = json_data_request['password']
        user_id = login_session['id']
        app_id = json_data_request['app_id']

        #check if the legacy application is created (admin rights only)
        application_exists = LegacyApp.check_app_id(app_id)
        if application_exists is True:
            #check hibp, check complexity and encrypt the password for safe storage
            hibp_compare = Password.check_hibp(app_pwd)
            complexity_criteria_check, comp_check_message = Password.check_complexity(app_pwd)
            encrypted_pwd = Password.encrypt_password(app_pwd)
            #return encrypted_pwd
            if complexity_criteria_check is False:
                return jsonify(Process='ERROR!', Process_Message=comp_check_message)

            elif hibp_compare is True:
                return jsonify(Process='ERROR!', Process_Message='Password leaked as it is found in HIBP database. Please try new password')

            else:
                response = Passwords.add_app_pwd(encrypted_pwd, user_id, app_id)
                return jsonify({"Message": "Password for the application saved successfully!"}), 201
        else:
            return jsonify({"Message": "The entered application does not exist. Please try again or contact the adminstrator"}), 401

    except (KeyError, exceptions.BadRequest):
        return jsonify(Process='ERROR!', Process_Message='Token expired! Please try logging in again')

##########################################

#Get all passwords module
#Get all passwords for applications for current logged in user 

@app.route('/get_all_pwds', methods=['GET'])
@token_required
def get_pwd():
    #get all application passwords for the current logged in user
    try:
        get_all_pass = Passwords.get_all_password(login_session['id'])
        response = make_response(jsonify({"status": get_all_pass}))
        return response
    except (KeyError, exceptions.BadRequest):
        return jsonify(Process='ERROR!', Process_Message='Token expired! Please try logging in again')

##########################################

#View all users module
#admin rights only

@app.route('/view_all_users', methods=['GET'])
@token_required
def view_all_users():
    try:
        #RBAC - Check if user is normal user or administrator
        check_user_role = Users.get_user_by_id(login_session['id'])
        #Get all the user passwords from the database
        if check_user_role:
            all_users = Users.get_all_users()
            all_users = make_response(jsonify({"status": all_users}))
            return all_users
        else:
            return jsonify({"Message": "You do not have the rights to perform this task"}), 401
    except (KeyError, exceptions.BadRequest):
        return jsonify(Process='ERROR!', Process_Message='Token expired! Please try logging in again')

##########################################

#Legacy Application module
#Create new legacy applications (admin rights only)
 
@app.route('/add_new_legacy_app', methods=['POST'])
@token_required
@required_params(LegacyAppSchema())
def add_legacy_app():
    try:
        json_data_request = request.get_json()
        app_name = json_data_request['app_name']
        url = json_data_request['url']
        description = json_data_request['description']
        check_user_role = Users.get_user_by_id(login_session['id'])
        #RBAC - check if logged in user is normal or admin
        if check_user_role:
            result = LegacyApp.add_new_legacy_app(app_name, url, description)
            return jsonify({"Message": "Application successfully saved"}), 201
        else:
            return jsonify({"Message": "Only Admin can create new applications"}), 401

    except (KeyError, exceptions.BadRequest):
        return jsonify(Process='ERROR!', Process_Message='Token expired! Please try logging in again')

##########################################

#Legacy Application list module
#Get list of all the legacy applications (admin rights only)

@app.route('/legacy_app_list', methods=['GET'])
@token_required
def get_legacy_app():
    #get all the app list in the database
    try:
        get_all_apps = LegacyApp.get_all_legacy_app()
        response = make_response(jsonify({"status": get_all_apps}))
        return response
    except (KeyError, exceptions.BadRequest):
        return jsonify(Process='ERROR!', Process_Message='Token expired! Please try logging in again')

##########################################

#Password complexity criteria module
#View password complexity criteria - for all users

@app.route('/get_pwd_criteria', methods=['POST', 'GET'])
def get_complexity():
    try:
        get_comp = PasswordComplexity.getComplexity()
        return get_comp
    except (KeyError, exceptions.BadRequest):
        return jsonify(Process='ERROR!', Process_Message='Token expired! Please try logging in again')

##########################################

#Update complexity criteria module
#Admin rights only

@app.route('/update_pwd_criteria', methods=['POST'])
@token_required
def update_complexity():
    request_data = request.get_json()
    charaterType = request_data['charaterType']
    existLowerCase = request_data['existLowerCase']
    existNumber = request_data['existNumber']
    existSpecialCharacter = request_data['existSpecialCharacter']
    existUpperCase = request_data['existUpperCase']
    maxLength = request_data['maxLength']
    minLength = request_data['minLength']
    specialCharaterList = request_data['specialCharaterList']
    try:
        data = {
            "charaterType": charaterType,
            "existLowerCase": existLowerCase,
            "existNumber": existNumber,
            "existSpecialCharacter": existSpecialCharacter,
            "existUpperCase": existUpperCase,
            "maxLength": maxLength,
            "minLength": minLength,
            "specialCharaterList": specialCharaterList
        }
        result = PasswordComplexity.updateComplexity(data)
        roleStatus = Users.get_user_by_id(login_session['id'])
        if roleStatus:
            if result is True:
                response = Users.update_user_status()
                # return response
                if response is True:
                    return jsonify({"Message": "Password complexity succesfully updated!"}), 200

            else:
                return jsonify({"Message": "Missing information, wrong keys or invalid JSON."}), 401
        else:
            return jsonify({"Message": "Only Admin can update password complexity"}), 401
    except (KeyError, exceptions.BadRequest):
        return jsonify(Process='ERROR!', Process_Message='Your token is expired! Please login in again.')

#admin login
def admin_login():
    result = Users.check_login("admin@gmail.com")
    if result is False:
        hashed_output = Password.password_hash('a23eSP$rt5')
        Users.add_admin_user("admin",hashed_output,"admin@gmail.com","ADMIN",1)

# Run server
if __name__ == '__main__':
    admin_login()
    app.run(debug=True)  
    
