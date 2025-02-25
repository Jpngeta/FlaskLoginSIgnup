from flask import Flask, render_template, request, redirect, url_for, flash, session
from pymongo import MongoClient
from bson.objectid import ObjectId
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import datetime


app = Flask(__name__)
app.secret_key = "your_secret_key"

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["auth_db"]
users_collection = db["users"]
reset_tokens_collection = db["reset_tokens"]

# Email configuration 
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "jpngeta@gmail.com"
SMTP_PASSWORD = "rqqkfmklymmzlhmz"


# Routes
@app.route("/")
def home():
    return render_template("signup.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        address = request.form.get("address")
        phone_number = request.form.get("phone_number")
        registration_number = request.form.get("registration_number")

        # Check if user already exists
        if users_collection.find_one({"username": username}):
            flash("Username already exists!", "error")
            return redirect(url_for("signup"))

        # Insert new user with all provided details
        users_collection.insert_one({
            "username": username, 
            "password": password,
            "email": email,
            "address": address,
            "phone_number": phone_number,
            "registration_number": registration_number
        })
        
        flash("Signup successful! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Check if user exists
        user = users_collection.find_one({"username": username, "password": password})
        if user:
            # Set session variables if needed
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            
            flash("Login successful!", "success")
            return "Logged in successfully!"  
        else:
            flash("Invalid username or password!", "error")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        user = users_collection.find_one({"email": email})
        
        if user:
            # Generate a secure token
            token = secrets.token_urlsafe(32)
            expiry = datetime.datetime.now() + datetime.timedelta(hours=1)
            
            # Store token in database
            reset_tokens_collection.insert_one({
                "user_id": user["_id"],
                "token": token,
                "expiry": expiry
            })
            
            # Create reset link
            reset_link = url_for('reset_password', token=token, _external=True)
            
            # Send email
            send_password_reset_email(email, reset_link)
            
            flash("Password reset link has been sent to your email.", "success")
            return redirect(url_for("login"))
        else:
            flash("Email not found in our records.", "error")
    
    return render_template("forgot_password.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    # Check if token exists and is valid
    token_doc = reset_tokens_collection.find_one({
        "token": token,
        "expiry": {"$gt": datetime.datetime.now()}
    })
    
    if not token_doc:
        flash("Invalid or expired reset link.", "error")
        return redirect(url_for("login"))
    
    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")
        
        if new_password != confirm_password:
            flash("Passwords do not match!", "error")
            return render_template("reset_password.html", token=token)
        
        # Update user's password
        users_collection.update_one(
            {"_id": token_doc["user_id"]},
            {"$set": {"password": new_password}}
        )
        
        # Delete used token
        reset_tokens_collection.delete_one({"_id": token_doc["_id"]})
        
        flash("Password has been reset successfully! Please login with your new password.", "success")
        return redirect(url_for("login"))
    
    return render_template("reset_password.html", token=token)

@app.route("/search", methods=["GET", "POST"])
def search_contacts():
    if request.method == "POST":
        registration_number = request.form.get("registration_number")
        
        # Search for users with the given registration number
        user = users_collection.find_one({"registration_number": registration_number})
        
        if user:
            # Return contact details (excluding sensitive info)
            contact_info = {
                "username": user["username"],
                "email": user["email"],
                "phone_number": user.get("phone_number", ""),
                "address": user.get("address", "")
            }
            return render_template("search_results.html", contact=contact_info)
        else:
            flash("No user found with that registration number.", "error")
    
    return render_template("search_contacts.html")

def send_password_reset_email(email, reset_link):
    try:
        # Create email
        msg = MIMEMultipart()
        msg['From'] = SMTP_USERNAME
        msg['To'] = email
        msg['Subject'] = "Password Reset Request"
        
        body = f"""
        Hello,
        
        You have requested to reset your password. Please click the link below to reset your password:
        
        {reset_link}
        
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Connect to SMTP server and send email
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False

@app.route("/logout")
def logout():
    # Clear session data
    session.clear()
    flash("You have been logged out successfully!", "success")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)