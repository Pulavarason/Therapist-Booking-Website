import requests #pip install requests
import os
import database
import datetime
from flask import request,session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


def register_func():
    username = request.form['username']
    email = request.form['email']
    phone=request.form['phone']
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    users=database.getUsers()
    if email in users:
        return False
    if password != confirm_password:
        return 'not match'
    database.register_user(username,email,phone,password)
    
    return True


def login_user():
    email = request.form['email']
    password = request.form['password']

    # Fetch all usernames from the database
    users = database.getUserName()

    # Check if the email exists in the database
    if email not in users:
        return "not"
    
    # Get the stored password from the database for the provided email
    stored_password = database.getPassword(email)

    # Check for admin
    if email == 'sathwika695@gmail.com':
        if password == stored_password:
            session['email'] = email  # Set email in session for admin
            return "admin"
        else:
            return "invalid_admin_password"
    
    # Check for non-admin users
    if email != 'sathwika695@gmail.com':
        if password == stored_password:
            session['email'] = email  # Set email in session for regular users
            return "tuser"
        else:
            return "invalid_tuser_password"
    
    # Passwords don't match, deny login
    return False