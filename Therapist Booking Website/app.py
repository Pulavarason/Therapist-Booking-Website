
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
import re
from datetime import datetime

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://localhost:27017/Therapist'
app.config['SECRET_KEY'] = 'your_secret_key_here'

mongo = PyMongo(app)

@app.route('/')
def index():
    return render_template('index.html')

with app.app_context():
    # Admin user details
    admin_user = {
        "username": "pulavarson",
        "email": "pulav111@gmail.com",
        "password": generate_password_hash("blueboys123#"),  # Set your admin password here
        "role": "admin"  # Make sure the admin has the 'admin' role
    }

    # Check if the admin already exists in the database
    if not mongo.db.users.find_one({"email": admin_user['email']}):
        mongo.db.users.insert_one(admin_user)
        print("Admin user created successfully.")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Look for user in the 'users' collection
        user = mongo.db.users.find_one({'email': email})  # Check users first
        print("User found:", user)  # Debug: see what user is found

        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['email'] = user['email']
            print("Login successful for:", user['email'])  # Debug: successful login
            
            if user.get('role') == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password')
            print("Login failed for:", email)  # Debug: failed login
            return redirect(url_for('login'))

    return render_template('login.html')




@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        phone = request.form['phone']

        # Check if email or username already exists
        existing_user = mongo.db.users.find_one({'$or': [{'username': username}, {'email': email}]})
        if existing_user:
            flash('Username or Email already exists')
            return redirect(url_for('register'))

        # Validate password confirmation
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('register'))

        # Validate phone number
        if not re.match(r'^[0-9]{10}$', phone):
            flash('Invalid phone number format')
            return redirect(url_for('register'))

        # Hash the password and insert the new user
        hashed_password = generate_password_hash(password)
        new_user = {
            'username': username,
            'email': email,
            'password': hashed_password,
            'phone': phone
        }

        mongo.db.users.insert_one(new_user)
        flash('Registration successful! You can now log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        username = request.form.get('username')
        new_password = request.form.get('new-password')
        confirm_password = request.form.get('confirm-password')

        # Validate password confirmation
        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('forgot'))

        # Check if the admin exists
        user = mongo.db.users.find_one({'username': username})
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('forgot'))

        # Update the password
        hashed_password = generate_password_hash(new_password)
        mongo.db.users.update_one({'username': username}, {'$set': {'password': hashed_password}})
        
        flash('Password reset successfully! You can now log in with your new password.', 'success')
        return redirect(url_for('login'))

    return render_template('forgot.html')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html')
    else:
        flash('You need to login first.')
        return redirect(url_for('login'))
    

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'email' in session and mongo.db.users.find_one({'email': session['email'], 'role': 'admin'}):
        return render_template('admin_dashboard.html')
    else:
        flash('You must be an admin to access this page.')
        return redirect(url_for('login'))
        
    



@app.route('/book_appointment', methods=['POST'])
def book_appointment():
    # Get form data
    department = request.form.get('department')
    therapist = request.form.get('therapist')
    date = request.form.get('date')
    time = request.form.get('time')
    name = request.form.get('name')
    phone = request.form.get('phone')
    message = request.form.get('message')

    # Store data in MongoDB
    appointment_data = {
        'department': department,
        'therapist': therapist,
        'date': date,
        'time': time,
        'name': name,
        'phone': phone,
        'message': message,
        'created_at': datetime.now()
    }

    mongo.db.appointments.insert_one(appointment_data)

    
    return redirect(url_for('confirmation'))

@app.route('/confirmation')
def confirmation():
    return render_template('confirmation.html')

@app.route('/appoinment')
def appoinment():
    return render_template('appoinment.html')


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/service')
def service():
    return render_template('service.html')  
 


@app.route('/contact')
def contact():
    return render_template('contact.html')  

@app.route('/profile')
def profile():
    if 'username' in session:
        # Fetch the logged-in user's details from MongoDB
        user = mongo.db.users.find_one({'email': session['email']})
        
        if user:
            # Pass user details to the profile template
            return render_template('profile.html', user=user)
        else:
            flash('User not found.')
            return redirect(url_for('dashboard'))
    else:
        flash('You need to log in first.')
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))



if __name__ == '__main__':
    app.run(debug=True)