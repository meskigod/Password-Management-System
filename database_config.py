########PASSWORD MANAGEMENT SYSTEM########

#Configuration 
#exception libraries
#encryption libraries
#initializing the database

from flask import Flask, request, Response, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_json_schema import JsonSchema
from flask import session as login_session
from marshmallow import Schema, fields, ValidationError
from dotenv import load_dotenv
import jwt
import os
import json
import uuid
import datetime
from functools import wraps
from werkzeug import exceptions
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad


#Loading environment variables
load_dotenv()
current_env = os.environ['FLASK_ENV']

#init app
app = Flask(__name__)
schema = JsonSchema(app)
basedir = os.path.abspath(os.path.dirname(__file__))

#Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, os.environ[current_env+'_DB'])
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initializing our database
db = SQLAlchemy(app)