from database_config import *
from flask import Flask, request, jsonify
from json import load, dumps, dump
import os

#posixpath 
#Returns the directory component of the pathname and absolute version of the path 
basedir = os.path.abspath(os.path.dirname(__file__))

#Creating a mapping object that represents the user’s environmental variables. 
complexity_file = os.environ[current_env+'_COMPLEX']

class PasswordComplexity:

    @staticmethod
    def getComplexity():
        with open(basedir +'/'+ complexity_file, 'r') as file:
            criteria = load(file)
            return criteria


    def updateComplexity(data):
        with open(basedir +'/'+complexity_file, 'w') as file:
            json_object = data
            dump(json_object, file)
            file.close()  
            return True