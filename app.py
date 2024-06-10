from flask import Flask, request, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
import jwt
from datetime import datetime, timedelta, timezone
import pickle
from os import environ

db_user = environ.get('DB_USER')
db_password = environ.get('DB_PASSWORD')
db_host = environ.get('DB_HOST')
db_name = environ.get('DB_NAME')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{db_user}:{db_password}@{db_host}/{db_name}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

def init_db():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password='admin')
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
            token = jwt.encode({'username': user[1], 'exp': datetime.now(timezone.utc) + timedelta(minutes=30)}, app.config['SECRET_KEY'])
            return jsonify({'token': token})
        return 'Login Failed', 401
    return '''
    <form method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    '''

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
def protected():
    token = request.headers.get('Authorization')
    if not token:
        return 'Missing token', 403
    try:
        jwt.decode(token, app.config['SECRET_KEY'])
    except jwt.ExpiredSignatureError:
        return 'Token expired', 403
    except jwt.InvalidTokenError:
        return 'Invalid token', 403
    return 'Protected content'

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
