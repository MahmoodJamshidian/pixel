from flask import Flask, render_template, abort
import dotenv

# load settings
dotenv.load_dotenv()

# import database models and api blueprint
import models
import api
import ws

# initiate flask app
app = Flask(__name__)

# register api blueprint and set path of working
app.register_blueprint(api.app, url_prefix=f'/api/v{api.__version__}')
app.register_blueprint(ws.app, url_prefix=f'/ws/v{ws.__version__}')

# initiate models to flask app
models.__init__(app)
ws.__init__(app)

# load a simple page
@app.route("/")
def index():
    return render_template("test.html")

# run application if it is main file 

if __name__ == "__main__":
    app.run(debug=True)