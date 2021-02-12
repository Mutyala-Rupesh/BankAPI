from common.database import Database
from models.user import User


from flask import Flask, render_template, request, session,jsonify
from flask_restful import Resource
import bcrypt

app = Flask(__name__)  # '__main__'
app.secret_key = "rupesh"

def cashWithUser(email):
    cash = User.find({
        "email":email
    })[0]["Own"]
    return cash

def debtWithUser(email):
    debt = User.find({
        "email":email
    })[0]["Debt"]
    return debt

def updateAccount(email, balance):
    User.update({
        "email": email
    },{
        "$set":{
            "Own": balance
        }
    })

def updateDebt(email, balance):
    User.update({
        "email": email
    },{
        "$set":{
            "Debt": balance
        }
    })

def generateReturnDictionary(status, msg):
    retJson = {
        "status": status,
        "msg": msg
    }
    return retJson

def UserExist(email):
    if User.find({"email":email}).count() == 0:
        return False
    else:
        return True

def verifyPw(email, password):
    if not UserExist(email):
        return False

    hashed_pw = User.find({
        "email":email
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False

def verifyCredentials(email, password):
    if not UserExist(email):
        return generateReturnDictionary(301, "Invalid email"), True

    correct_pw = verifyPw(email, password)

    if not correct_pw:
        return generateReturnDictionary(302, "Incorrect Password"), True

    return None, False

class Add(Resource):
    def post(self):
        postedData = request.get_json()

        email = postedData["email"]
        password = postedData["password"]
        money = postedData["amount"]

        retJson, error = verifyCredentials(email, password)
        if error:
            return jsonify(retJson)

        if money<=0:
            return jsonify(generateReturnDictionary(304, "The money amount entered must be greater than 0"))

        cash = cashWithUser(email)
        money-= 1 #Transaction fee
        #Add transaction fee to bank account
        bank_cash = cashWithUser("BANK")
        updateAccount("BANK", bank_cash+1)

        #Add remaining to user
        updateAccount(email, cash+money)

        return jsonify(generateReturnDictionary(200, "Amount Added Successfully to account"))

class Transfer(Resource):
    def post(self):
        postedData = request.get_json()

        email = postedData["email"]
        password = postedData["password"]
        to       = postedData["to"]
        money    = postedData["amount"]


        retJson, error = verifyCredentials(email, password)
        if error:
            return jsonify(retJson)

        cash = cashWithUser(email)
        if cash <= 0:
            return jsonify(generateReturnDictionary(303, "You are out of money, please Add Cash or take a loan"))

        if money<=0:
            return jsonify(generateReturnDictionary(304, "The money amount entered must be greater than 0"))

        if not UserExist(to):
            return jsonify(generateReturnDictionary(301, "Recieved email is invalid"))

        cash_from = cashWithUser(email)
        cash_to   = cashWithUser(to)
        bank_cash = cashWithUser("BANK")

        updateAccount("BANK", bank_cash+1)
        updateAccount(to, cash_to+money-1)
        updateAccount(email, cash_from - money)

        retJson = {
            "status":200,
            "msg": "Amount added successfully to account"
        }
        return jsonify(generateReturnDictionary(200, "Amount added successfully to account"))

class Balance(Resource):
    def post(self):
        postedData = request.get_json()

        email = postedData["email"]
        password = postedData["password"]

        retJson, error = verifyCredentials(email, password)
        if error:
            return jsonify(retJson)

        retJson = User.find({
            "email": email
        },{
            "Password": 0, #projection
            "_id":0
        })[0]

        return jsonify(retJson)

class TakeLoan(Resource):
    def post(self):
        postedData = request.get_json()

        email = postedData["email"]
        password = postedData["password"]
        money    = postedData["amount"]

        retJson, error = verifyCredentials(email, password)
        if error:
            return jsonify(retJson)

        cash = cashWithUser(email)
        debt = debtWithUser(email)
        updateAccount(email, cash+money)
        updateDebt(email, debt + money)

        return jsonify(generateReturnDictionary(200, "Loan Added to Your Account"))

class PayLoan(Resource):
    def post(self):
        postedData = request.get_json()

        email = postedData["email"]
        password = postedData["password"]
        money    = postedData["amount"]

        retJson, error = verifyCredentials(email, password)
        if error:
            return jsonify(retJson)

        cash = cashWithUser(email)

        if cash < money:
            return jsonify(generateReturnDictionary(303, "Not Enough Cash in your account"))

        debt = debtWithUser(email)
        updateAccount(email, cash-money)
        updateDebt(email, debt - money)

        return jsonify(generateReturnDictionary(200, "Loan Paid"))

@app.route("/")
def home_template():
    return render_template("home.html")


@app.route("/login")
def login_template():
    return render_template("login.html")


@app.route("/register")
def register_template():
    return render_template("register.html")


@app.before_first_request
def initialize_database():
    Database.initialize()


@app.route("/auth/login", methods=["POST"])
def login_user():
    email = request.form["email"]
    password = request.form["password"]

    if User.login_valid(email, password):
        User.login(email)
    else:
        session["email"] = None

    return render_template("profile.html", email=session["email"])


@app.route("/auth/register", methods=["POST"])
def register_user():
    email = request.form["email"]
    password = request.form["password"]

    User.register(email, password)

    return render_template("profile.html", email=session["email"])

@app.route("/logout")
def logout():
    return render_template("home.html")

@app.route("/add")
def Add():
    return render_template("add.html")


if __name__ == "__main__":
    app.run(port=4995, debug=True)