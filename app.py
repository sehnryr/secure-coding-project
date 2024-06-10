from flask import Flask, request, jsonify, render_template_string
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity, set_access_cookies, set_refresh_cookies
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta, timezone
import pickle
from os import environ

flask_secret_key = environ.get('FLASK_SECRET')

db_user = environ.get('DB_USER')
db_password = environ.get('DB_PASSWORD')
db_host = environ.get('DB_HOST')
db_name = environ.get('DB_NAME')

admin_username = environ.get('ADMIN_USERNAME')
admin_password = environ.get('ADMIN_PASSWORD')

app = Flask(__name__)
app.config['SECRET_KEY'] = flask_secret_key
app.config["JWT_SECRET_KEY"] = flask_secret_key
app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies", "json", "query_string"]
app.config["JWT_COOKIE_SECURE"] = False
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{db_user}:{db_password}@{db_host}/{db_name}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

jwt = JWTManager(app)
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

def init_db():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username=admin_username).first():
            admin = User(username=admin_username, password=admin_password)
            db.session.add(admin)
            db.session.commit()

# Home page with links to all routes
@app.route('/')
def home():
    return '''
    <h1>Welcome to the Vulnerable Flask App</h1>
    <ul>
        <li><a href="/login">Login</a></li>
        <li><a href="/hello?name=World">Hello</a></li>
        <li><a href="/set_data">Set Data</a></li>
        <li><a href="/protected">Protected</a></li>
    </ul>
    '''

# Vulnerable route for SQL Injection
@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            access_token = create_access_token(identity=username)
            refresh_token = create_refresh_token(identity=username)

            response = jsonify(msg='Login Successful')
            set_access_cookies(response, access_token)
            set_refresh_cookies(response, refresh_token)
            return response
        return 'Login Failed', 401
    return '''
    <form method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    '''

# Route to refresh access token
@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify(access_token=access_token)

# Vulnerable route for XSS
@app.route('/hello', methods=['GET'])
def hello():
    name = request.args.get('name', 'World')
    return render_template_string("<h1>Hello, {{ name }}!</h1>", name=name)

# Vulnerable route for deserialization
@app.route('/set_data', methods=['POST', 'GET'])
def set_data():
    if request.method == 'POST':
        data = request.form['data']
        deserialized_data = pickle.loads(data.encode('latin1'))
        return jsonify({'data': deserialized_data})
    return '''
    <form method="post">
        Data: <input type="text" name="data"><br>
        <input type="submit" value="Set Data">
    </form>
    '''

# Secure JWT-protected route
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
