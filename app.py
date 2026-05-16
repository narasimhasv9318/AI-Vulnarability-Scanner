from flask import Flask, request, render_template
import os
import subprocess
import pickle
import yaml
from db import get_user
from auth import authenticate

app = Flask(__name__)

app.secret_key = "hardcoded-secret-key"


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/ping")
def ping():
    host = request.args.get("host")

    # COMMAND INJECTION
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)

    return result


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    # INSECURE AUTH
    if authenticate(username, password):
        return "Logged in"

    return "Unauthorized", 401


@app.route("/user")
def user():
    username = request.args.get("username")

    # SQL INJECTION
    user = get_user(username)

    return str(user)


@app.route("/deserialize", methods=["POST"])
def deserialize_data():

    # INSECURE DESERIALIZATION
    data = pickle.loads(request.data)

    return str(data)


@app.route("/yaml", methods=["POST"])
def yaml_load():

    # UNSAFE YAML LOAD
    data = yaml.load(request.data)

    return str(data)


@app.route("/read")
def read_file():
    filename = request.args.get("file")

    # PATH TRAVERSAL
    with open(filename, "r") as f:
        return f.read()


@app.route("/debug")
def debug_env():

    # SENSITIVE INFO DISCLOSURE
    return {
        "SECRET_KEY": os.environ.get("SECRET_KEY"),
        "DB_PASSWORD": os.environ.get("DB_PASSWORD")
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
