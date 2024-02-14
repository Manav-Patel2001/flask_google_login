# import os
# import pathlib

# import requests
# from flask import Flask, session, abort, redirect, request
# from google.oauth2 import id_token
# from google_auth_oauthlib.flow import Flow
# from pip._vendor import cachecontrol
# import google.auth.transport.requests

# app = Flask("Google Login App")
# app.secret_key = "CodeSpecialist.com"

# os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# GOOGLE_CLIENT_ID = "711302179942-0mssr4n3uhdgv9lefpmqhvl1l2e6a7t9.apps.googleusercontent.com"
# client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

# flow = Flow.from_client_secrets_file(
#     client_secrets_file=client_secrets_file,
#     scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
#     redirect_uri="http://127.0.0.1:5000/callback"
# )


# def login_is_required(function):
#     def wrapper(*args, **kwargs):
#         if "google_id" not in session:
#             return abort(401)  # Authorization required
#         else:
#             return function()

#     return wrapper


# @app.route("/login")
# def login():
#     authorization_url, state = flow.authorization_url()
#     print("session['state']",session["state"])
#     print("auth url:",authorization_url)
#     session["state"] = state
#     return redirect(authorization_url)


# @app.route("/callback")
# def callback():
#     flow.fetch_token(authorization_response=request.url)
#     print("session['state']",session["state"])
#     print("Request::",request.args["state"])
#     if not session["state"] == request.args["state"]:
#         abort(500)  # State does not match!

#     credentials = flow.credentials
#     request_session = requests.session()
#     cached_session = cachecontrol.CacheControl(request_session)
#     token_request = google.auth.transport.requests.Request(session=cached_session)

#     id_info = id_token.verify_oauth2_token(
#         id_token=credentials._id_token,
#         request=token_request,
#         audience=GOOGLE_CLIENT_ID
#     )

#     session["google_id"] = id_info.get("sub")
#     session["name"] = id_info.get("name")
#     return redirect("/protected_area")


# @app.route("/logout")
# def logout():
#     session.clear()
#     return redirect("/")


# @app.route("/")
# def index():
#     return "Hello World <a href='/login'><button>Login</button></a>"


# @app.route("/protected_area")
# @login_is_required
# def protected_area():
#     return f"Hello {session['name']}! <br/> <a href='/logout'><button>Logout</button></a>"


# if __name__ == "__main__":
#     app.run(debug=True)
import os
import pathlib

import requests
from flask import Flask, session, abort, redirect, request, url_for,render_template
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from flask_oauthlib.client import OAuth
import google.auth.transport.requests
from flask_sqlalchemy import SQLAlchemy
# from werkzeug.urls import url_decode, url_encode
# from werkzeug.utils import quote as url_quote




app = Flask("SSO App")
app.secret_key = "CodeSpecialist.com"
# password = 'root'
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://root:MyNewPass@localhost/testdatabase"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# Google SSO Configurations
GOOGLE_CLIENT_ID = "711302179942-0mssr4n3uhdgv9lefpmqhvl1l2e6a7t9.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

# Facebook SSO Configurations
FACEBOOK_APP_ID = "your-facebook-app-id"
FACEBOOK_APP_SECRET = "your-facebook-app-secret"

oauth = OAuth(app)
facebook = oauth.remote_app(
    'facebook',
    consumer_key=FACEBOOK_APP_ID,
    consumer_secret=FACEBOOK_APP_SECRET,
    request_token_params={'scope': 'email'},
    base_url='https://graph.facebook.com/v12.0/',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth'
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return f"User('{self.email}')"
    

def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session and "facebook_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper



@app.route("/login")
def login():
    return render_template('login.html')


@app.route("/google_login")
def google_login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route("/facebook_login")
def facebook_login():
    return facebook.authorize(callback="http://127.0.0.1:5000/facebook_authorized")


@app.route("/facebook_authorized")
@facebook.authorized_handler
def facebook_authorized(resp):
    if resp is None or 'access_token' not in resp:
        return 'Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )
    session['facebook_token'] = (resp['access_token'], '')
    me = facebook.get('/me')
    session["facebook_id"] = me.data['id']
    session["name"] = me.data['name']
    return redirect("/protected_area")


@app.route("/callback")
def google_callback():
    flow.fetch_token(authorization_response=request.url)
    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    token_request = google.auth.transport.requests.Request(session=request_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    email = id_info.get("email")
    user = User(email=email)
    

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    print("name::",session["name"])
    db.session.add(user)
    db.session.commit()
    return redirect("/protected_area")
# @app.route("/google_signin")
# def google_signup():
#     authorization_url, state = flow.authorization_url(prompt="consent")
#     session["state"] = state
#     return redirect(authorization_url)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/logout_facebook")
def logout_facebook():
    session.pop('facebook_id', None)
    return redirect("/login")

@app.route("/protected_area")
@login_is_required
def protected_area():
    user = User.query.filter_by(email=session['name']).first()
    return render_template('protected_area.html', user=user)

if __name__ == "__main__":
    app.run(debug=True)
