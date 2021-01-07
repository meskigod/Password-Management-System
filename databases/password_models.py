########PASSWORD MANAGEMENT SYSTEM########


#defining Database classes

#importing all required libraries
from datetime import datetime
from database_config import *

#User defined libraries
from password_module.password import Password

#Create Legacy application model, database table and fields

class LegacyApp(db.Model):
    #Create a table
    __tablename__ = 'tbl_legacy_application_list'
    app_name = db.Column(db.String(128), nullable=False )
    id = db.Column(db.Integer, nullable=False, primary_key=True, unique=True)
    url = db.Column(db.String(128), nullable=False )
    description = db.Column(db.String(128), nullable=False )
    pwd = db.relationship('Passwords', back_populates="parent" , lazy='joined')

    #check if the application already exists in the PMS
    def check_app_id(app_id):
        exists = LegacyApp.query.filter_by(id=app_id).scalar()
        if exists is None:
            return False
        else:
            return True

    #add legacy application (admin rights only)    
    def add_new_legacy_app(_app_name,_url,_description):
        new_legacy_app = LegacyApp(app_name=_app_name,description=_description,url=_url)
        db.session.add(new_legacy_app)  
        db.session.commit()  
        return new_legacy_app

    #Get all legacy applications
    def get_all_legacy_app():
        return [LegacyApp.json(legacyApp) for legacyApp in LegacyApp.query.all()]

    #Converting a json object 
    def json(self):
        return {
            'id': self.id,
            'app_name': self.app_name
        }


#User  model, database user list table and fields

class Users(db.Model):
    #Create a table
    __tablename__ = 'tbl_users'
    username = db.Column(db.String(32))
    password = db.Column(db.String(128))
    email = db.Column(db.String(128))
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(20))
    passwordCriteraStatus = db.Column(db.Integer())
    
    #Create test admin
    def add_admin_user(_username,_password,_email,_role,_passwordCriteraStatus):
        new_user = Users(role=_role,username=_username,password=_password,email=_email,passwordCriteraStatus=_passwordCriteraStatus)
        db.session.add(new_user)  
        db.session.commit()  
        return new_user

    #Create new user and save in database
    def add_new_user(_username,_password,_email,_role,_passwordCriteraStatus):
        new_user = Users(role=_role,username=_username,password=_password,email=_email,passwordCriteraStatus=_passwordCriteraStatus)
        db.session.add(new_user)  
        db.session.commit()  
        return new_user
    
    #Get all users
    def get_all_users():
        user_list= [Users.json(userApp) for userApp in Users.query.all()]
        return user_list
    
    #Admin or normal user
    def get_user_by_id(_id):
        userIsExist = Users.query.filter_by(id=_id, role="ADMIN").first()
        if userIsExist is None:
            return False
        else:
            return True

    #Check if the email address exists in the database
    def check_login(_email):
        user = Users.query.filter_by(email=_email).first()
        if user is None:
            return False
        else:
            return user

    #When system admin change the password complexity, update the user pasword criteria status
    def update_user_status():
        update = db.session.query(Users).filter(Users.passwordCriteraStatus == 1).update({Users.passwordCriteraStatus:0}, synchronize_session = False)
        db.session.commit() 
        return True

    #Converting a json object  
    def json(self):
        return {
            'id': self.id,
            'username': self.username,
            #'password': "************",
            'email': self.email,
            'role': self.role
        }

#creating password models, add new password, get all current passwords

class Passwords(db.Model):

    #Create a table
    __tablename__ = 'tbl_app_password_list'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True, unique=True)
    password = db.Column(db.String(128))
    user_id = db.Column(db.Integer())
    app_id = db.Column(db.Integer(), db.ForeignKey('tbl_legacy_application_list.id'))
    parent = db.relationship("LegacyApp", back_populates="pwd")

    #Adding passwords to the legacy applications
    def add_app_pwd(_password,_user_id,_app_id):
        new_pwd = Passwords(password=_password, user_id=_user_id, app_id=_app_id)
        db.session.add(new_pwd) 
        db.session.commit()  
        return new_pwd

    #Get all passwords for current user
    def get_all_password(_user_id):
        result = [Passwords.json(record) for record in Passwords.query.filter(Passwords.user_id==_user_id).all()]
        return result

    
    #Converting a json object
    def json(self):
        return {
            'app_name': self.parent.app_name,
            'id': self.id,
            'password': Password.decrypt_pwd(self.password),
            'url': self.parent.url,
            'description': self.parent.description
        }


class UserSchema(Schema):
    username = fields.String(required=True)
    password = fields.String(required=True)
    email = fields.String(required=True)

#Implement Input Validation
class PasswordSchema(Schema):
    #App Id should be integer and required field
    app_id = fields.Integer(required=True)
    #Password should be String and required field
    password = fields.String(required=True)


class LegacyAppSchema(Schema):
    url = fields.String(required=True)
    description = fields.String(required=True)
    app_name = fields.String(required=True)

db.create_all()
