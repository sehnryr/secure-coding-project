from flask import Flask, make_response, request, jsonify, render_template_string
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity, set_access_cookies, set_refresh_cookies, unset_jwt_cookies
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
import pickle
from os import environ
from werkzeug.security import generate_password_hash, check_password_hash

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
    password = db.Column(db.String(200), nullable=False)

def init_db():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username=admin_username).first():
            hashed_password = generate_password_hash(admin_password)
            admin = User(username=admin_username, password=hashed_password)
            db.session.add(admin)
            db.session.commit()

# Home page with links to all routes
@app.route('/')
def home():
    return '''
    <h1>Welcome to the Vulnerable Flask App</h1>
    <ul>
        <li><a href="/login">Login</a></li>
        <li><a href="/logout">Logout</a></li>
        <li><a href="/refresh">Refresh</a></li>
        <li><a href="/hello?name=World">Hello</a></li>
        <li><a href="/protected">Protected</a></li>
        <li><a href="/deserialization">Deserialization</a></li>
    </ul>
    '''

# Vulnerable route for SQL Injection
@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
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

# Logout route to clear cookies
@app.route('/logout', methods=['GET'])
def logout():
    response = make_response(jsonify(msg='Logout Successful'))
    unset_jwt_cookies(response)
    return response

# Route to refresh access token
@app.route("/refresh", methods=['POST', 'GET'])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    response = make_response(jsonify(access_token=access_token))
    set_access_cookies(response, access_token)
    return response

# Vulnerable route for XSS
@app.route('/hello', methods=['GET'])
def hello():
    name = request.args.get('name', 'World')
    return render_template_string("<h1>Hello, {{ name }}!</h1>", name=name)

# Secure JWT-protected route
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

class Foo:
    attr1 = 1
    attr2 = 'foo'
    attr4 = [1, 2, 3]
    attr5 = {'a': 1, 'b': 2, 'c': 3}
    attr6 = None

types_whitelist = [int, str, list, dict] # , type(None)

# Route for deserializing data
@app.route('/deserialization', methods=['GET'])
def deserialization():
    # Serialize data
    serialized_data = pickle.dumps(Foo)

    # Deserialize data
    deserialized_data = pickle.loads(serialized_data)

    # If an attribute is not in the whitelist, return an error
    for k, v in deserialized_data.__dict__.items():
        # Skip private attributes
        if k.startswith('__'):
            continue
        if type(v) not in types_whitelist:
            return jsonify(error=f"Invalid type: {type(v)}"), 500

    return jsonify({
        "className": deserialized_data.__name__,
        "attributes": {k: v for k, v in deserialized_data.__dict__.items() if not k.startswith('__')}
    }), 200

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
