# Secure Coding Project

```bash
docker compose up --build
```

## Modules

Each module needs to be adequately implemented to pass the learning outcome.

### Module 1 (15 points)

> Use tools OWASP ZAP and Burp Suite to scan your application for
> vulnerabilities. Choose three most significant vulnerabilities, document them,
> fix them and re-scan the application to prove that the vulnerabilities are
> fixed.

When running the OWASP ZAP scan, the following significant vulnerabilities were
found:

- Cross Site Scripting (Reflected)
- SQL Injection - MySQL
- Server Side Template Injection

![](./docs/image1.png)

Cross Site Scripting (Reflected) and Server Side Template Injection were fixed
by escaping the user input in the `/hello` route.

```python
# From
@app.route('/hello', methods=['GET'])
def hello():
    name = request.args.get('name', 'World')
    return render_template_string("<h1>Hello, {}!</h1>".format(name))

# To
@app.route('/hello', methods=['GET'])
def hello():
    name = request.args.get('name', 'World')
    return render_template_string("<h1>Hello, {{ name }}!</h1>", name=name)
```

SQL Injection was fixed by using SQLAlchemy's ORM to interact with the database.

```python
# From
@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db.session.execute(text(f"SELECT * FROM user WHERE username='{username}' AND password='{password}'")).fetchone()
        if user:
            token = jwt.encode({'username': user[1], 'exp': datetime.now(timezone.utc) + timedelta(minutes=30)}, app.config['SECRET_KEY'])
            return jsonify({'token': token})
        return 'Login Failed', 401
    ...

# To
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
    ...
```

![](./docs/image2.png)

### Module 2 (15 points)

> Use SonarQube tool and scan your application for the bugs. Choose three most
> significant bugs, document them, fix them and re-scan the application to prove
> that the bugs are fixed.

### Module 3 (15 points)

> Implement a JWT access and refresh token in your web application and document
> the example of token usage.

### Module 4 (15 points)

> Analyze the SQL injection vulnerability of your application with one of
> available tools online (for example: https://pentest-tools.com/website-vulnerability-scanning/sql-injection-scanner-online),
> document the potential bugs and describe the current way how the application
> protects it’s database from SQL injection attacks.

### Module 5 (15 points)

> Implement an example of serialization (if it does not exist in your
> application) and implement the deserialization protection based on
> whitelisting the classes that can be deserialized.

### Module 6 (13 points)

> Use the best practices in implementing authentication and authorization to
> prevent unauthorized access to confidential data.
