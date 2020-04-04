import os
import csv
import urllib.parse

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

#from helpers import apology, login_required, lookup, usd
from helpers import apology, login_required, cityvalid, format, string_link

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///health.db")

@app.route("/")
def about():
    return render_template("about.html")

@app.route("/diseases")
def diseases():
    return render_template("diseases.html")

@app.route("/disease1")
def disease1():
    return render_template("cold.html")

@app.route("/disease2")
def disease2():
    return render_template("influenza.html")

@app.route("/disease3")
def disease3():
    return render_template("chickenpox.html")

@app.route("/disease4")
def disease4():
    return render_template("vascular.html")

@app.route("/disease5")
def disease5():
    return render_template("typhoid.html")

@app.route("/disease6")
def disease6():
    return render_template("insomnia.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    #Adapt from CS50 Finance

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/home")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")

    else:
        #Showing more customer care by greeting their first name
        first = request.form.get("first")
        last = request.form.get("last")
        state = request.form.get("state")
        city = request.form.get("city")

        #Check if inputs are filled
        if not first:
            return apology("You must provide a first name!")
        if not last:
            return apology("You must provide a last name!")
        if not state:
            return apology("You should provide your state!")
        if not city:
            return apology("You should provide your city!")

        #Check if city's name fits with state's name
        if not cityvalid(city, state):
            return apology("City does not exist and/or does not match the state name!")

        #Getting username, password and confirmation of password
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        #Check if these inputs are valid
        if not username:
            return apology("You must provide a username!")
        elif not password:
            return apology("You must provide a password!")
        elif not confirmation:
            return apology("You must retype your password!")
        elif password != confirmation:
            return apology("Your password and confirmation don't match!")

        find = db.execute("SELECT * FROM users WHERE username = :username", username = username)
        if (len(find) != 0):
            return apology("Username taken!")

        #Store the hash of the password the user inputs
        hash = generate_password_hash(password)

        #Re-adapt city name and state name the user inputs to fit with statements
        city = format(city)
        state = format(state)

        db.execute("INSERT INTO users (first, last, state, city, username, hash) VALUES (:first, :last, :state, :city, :username, :hash)",
                        first = first, last = last, state = state, city = city, username = username, hash = hash)
        return redirect("/login")

@app.route("/password", methods = ["GET", "POST"])
def change():
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username_exist"):
            return apology("must provide username")

        # Ensure password was submitted
        elif not request.form.get("old_password"):
            return apology("must provide existing password")

        elif not request.form.get("new_password"):
            return apology("must provide new password")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username_exist"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("old_password")):
            return apology("invalid username and/or password")

        #Creating a hash for the new password
        new_hash = generate_password_hash(request.form.get("new_password"))

        #Updating the database with new hash
        db.execute("UPDATE users SET hash = :hash WHERE username = :username", hash = new_hash, username = request.form.get("username_exist"))
        # Redirect user to home page
        return redirect("/login")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("password.html")

@app.route("/home")
def home():
    #Getting user's identification when logged in
    user_id = session['user_id']

    #Get first name of user
    namedict = db.execute("SELECT first FROM users WHERE id = :id", id = user_id)
    first = namedict[0]['first']

    #Get state of user
    statedict = db.execute("SELECT state FROM users WHERE id = :id", id = user_id)
    state = statedict[0]['state']

    #Get city of user
    citydict = db.execute("SELECT city FROM users WHERE id = :id", id = user_id)
    city = citydict[0]['city']

    #Re-adapt city name and state name to fit with statements
    state = format(state)
    city = format(city)

    return render_template("home.html", first = first, state = state, city = city)

@app.route("/search", methods = ["GET", "POST"])
def search():
    if request.method == "GET":
        return render_template("search.html")
    else:
        #Get user's information when logged in - to insert into the database
        user_id = session['user_id']

        #Get user's query
        state = request.form.get("state")
        city = request.form.get("city")

        #Check invalid inputs
        if not state:
            return apology("You must provide a state!")
        if not city:
            return apology("You must provide a city!")

        #Check if city name is valid - existing name and coherent with state
        if not cityvalid(city, state):
            return apology("City does not exist and/or does not match with state!")

        #Insert into health.db database, "searches" table
        db.execute("INSERT INTO searches (user_id, state, city, time) VALUES (:id, :state, :city, :time)", state = state, city = city,
                    time = datetime.now().strftime("%d/%m/%Y %H:%M:%S"), id = user_id)

        return render_template("searched.html", place = string_link(city, state), city = format(city), state = format(state))

@app.route("/history")
def history():
    user_id = session['user_id']
    history = db.execute("SELECT * FROM searches WHERE user_id = :id", id = user_id)

    #Showing customer care
    firstname_list = db.execute("SELECT first FROM users WHERE id = :id", id = user_id)

    for dict in history:
        dict['firstname'] = firstname_list[0]['first']

    return render_template("history.html", history = history)

@app.route("/general", methods = ["GET", "POST"])
def general():
    if request.method == "GET":
        return render_template("general.html")
    else:

        #Get state and city from user's query
        state = request.form.get("state")
        city = request.form.get("city")

        #Get entertainment site that user wants to browse
        place = request.form.get("place")

        #Check if inputs are filled
        if not state:
            return apology("You must enter a state!")
        if not city:
            return apology("You must enter a city!")
        if not place:
            return apology("You must choose an entertainment site!")

        #Check if city name is valid - existing name and coherent with state
        if not cityvalid(city, state):
            return apology("City does not exist and/or does not match with state!")

        #Generalization of string_link in helpers.py
        link = place + "+in"
        city_parse = city.split()
        state_parse = state.split()
        for i in range(len(city_parse)):
            link = link + "+" + city_parse[i]
        for i in range(len(state_parse)):
            link = link + "+" + state_parse[i]

        #Another string adaptation of "place" to put into statement
        place1 = place.lower()

        return render_template("postgeneral.html", link = link, place = format(place), city = format(city), state = format(state), place1 = place1)



