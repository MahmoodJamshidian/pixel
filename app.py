from flask import Flask, render_template, abort
from flask_restful import Api, Resource, marshal
from flask_sqlalchemy import SQLAlchemy
import os.path
import dotenv

# load settings
dotenv.load_dotenv()

# import database models and api blueprint
import models
import api

# initiate flask app
app = Flask(__name__)

# register api blueprint and set path of working
app.register_blueprint(api.app, url_prefix=f'/api/v{api.__version__}')

# initiate models to flask app
models.__init__(app)

# load a simple page
@app.route("/")
def index():
    return render_template("index.html")

# run application if it is main file 

if __name__ == "__main__":
    app.run(debug=True)