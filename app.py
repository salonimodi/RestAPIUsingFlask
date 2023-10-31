from flask import Flask, jsonify, render_template
from flask import request, redirect, url_for, session, abort, request
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from sqlalchemy import create_engine, inspect, insert, Select, text
from sqlalchemy import Column, Integer, String, Table
from sqlalchemy.orm import declarative_base, Session, sessionmaker, scoped_session
import pymysql
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
import jwt as jt
from datetime import timedelta
import json
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
import os

# Base class for SQLAlchemy
Base = declarative_base()

app = Flask(__name__)
app.permanent_session_lifetime = timedelta(minutes=10)

app.secret_key = "nasm12345"
# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "secretkey_nasm"
app.config["MAX_CONTENT_LENGTH"] = 4096 * 4096
app.config["UPLOAD_EXTENSIONS"] = [".jpg", ".png", ".pdf"]
app.config["UPLOAD_PATH"] = "media"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:nasm@localhost:3306/mydatabase'

# SQLAlchemy Engine to connect MySQL to flask applciation
engine = create_engine("mysql+pymysql://root:nasm@localhost:3306/mydatabase", echo=True)
db=scoped_session(sessionmaker(bind=engine))
db2 = SQLAlchemy(app)

jwt = JWTManager(app)

# Init function that creates a Users table if it does not already exits
def init():
    """Checks if the User table exists and creates one if not."""
    user_table = Table("Users", Base.metadata)
    if not inspect(engine).has_table("Users"):
        Base.metadata.create_all(engine)

        stmt1 = insert(Users).values(
            first_name="John", last_name="Doe", username="john.doe", password="john123"
        )
        stmt2 = insert(Users).values(
            first_name="Jane", last_name="Doe", username="jane.doe", password="doe12345"
        )
        stmt3 = insert(Users).values(username="admin", password="password")

        with engine.connect() as conn:
            result1 = conn.execute(stmt1)
            result2 = conn.execute(stmt2)
            result3 = conn.execute(stmt3)
            conn.commit()
    else:
        print("Users table already exists.")


# Users table
class Users(Base):
    __tablename__ = "Users"

    id = Column(Integer, primary_key=True)
    first_name = Column(String(255))
    last_name = Column(String(255))
    username = Column(String(255), unique=True, nullable=False)
    password = Column(String(255), nullable=False)

    def check_password(self, password):
        print("Checking Password .......")
        return check_password_hash(self.password, password)

    def to_json(self):
        return {
            "id": self.id,
            "username": self.username,
        }


# Prodcuts database
class Products(Base):
    __tablename__ = "PRODUCTS"

    product_id = Column(Integer, primary_key=True)
    product_name = Column(String(20))
    product_description = Column(String(255))
    barcode = Column(String(20))
    price = Column(Integer)

    def to_json(self):
        return {
            "product_id": self.product_id,
            "product_name": self.product_name,
            "product_description": self.product_description,
            "barcode": self.barcode,
            "price": self.price
        }


# List of required error handlers

# Bad Request Error
@app.errorhandler(400)
def bad_request(error):
    """Handle 400 Bad Request errors."""
    return jsonify(error=str(error)), 400

# Unauthorized Action Error
@app.errorhandler(401)
def unauthorized(error):
    """Handle 401 Unauthorized errors."""
    return jsonify(error=str(error)), 401

# Forbidden Error
@app.errorhandler(403)
def forbidden(error):
    """Handle 403 Forbidden errors."""
    return jsonify(error=str(error)), 403

# Page Not Found Error
@app.errorhandler(404)
def page_not_found(error):
    """Handle 404 Page Not Found errors."""
    return jsonify(error=str(error)), 404

# Internal Server Error
@app.errorhandler(500)
def internal_server_error(error):
    """Handle 500 Internal Server Error errors."""
    return jsonify(error=str(error)), 500


@app.route("/users", methods=["POST"])
def create_user():
    """Creates a new user in the database."""

    # Validate the request parameters
    first_name = request.json.get("first_name")
    last_name = request.json.get("last_name")
    username = request.json.get("username")
    password = request.json.get("password")

    if not username or not password:
        return jsonify(error="Missing required fields."), 400

    # Check if the username is unique
    session = Session(engine)
    user = session.query(Users).filter_by(username=username).first()
    if user:
        return jsonify(error="Username already taken."), 400

    # Create a new user object
    new_user = Users(
        first_name=first_name, last_name=last_name, username=username, password=password
    )

    # Add the new user object to the database
    session.add(new_user)
    session.commit()

    # Generate a JWT token for the new user
    token = jt.encode(
        {"id": new_user.id}, app.config["JWT_SECRET_KEY"], algorithm="HS256"
    )

    # Return the JWT token to the client
    return jsonify(token=token), 201


@app.route("/login", methods=["POST"])
def login():
    """Logs in a user and returns a JWT token."""

    # Get the username and password from the request
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    userid = db.execute(text("SELECT id FROM Users WHERE username=:username"), {"username": username}).fetchone()
    usernamedata = db.execute(text("SELECT username FROM Users WHERE username=:username"), {"username": username}).fetchone()
    passworddata = db.execute(text("SELECT password FROM Users WHERE username=:username"), {"username": username}).fetchone()

    if usernamedata is None:
        print("User Not Found")
        abort(401, "Invalid username or password.")
    else:
        for passwor_data in passworddata:
            if password ==passwor_data:
                session.permanent = True
                session['loggedin'] = True
                session['id'] = userid[0]
                session['username'] = usernamedata[0]

                # payload = {"identity": username}
                # token = jt.encode(payload, app.config["JWT_SECRET_KEY"], algorithm="HS256")
                access_token = create_access_token(identity=username)
                return jsonify(access_token=access_token)

            else:
                print("Incorrect password")
                abort(401, "Invalid username or password.")

    # Return the JWT token to the client
    return jsonify(token=token)

@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    """A protected endpoint that requires a valid JWT token to access."""

    # current_user = jt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
    current_user = get_jwt_identity()

    # Return a success response
    return jsonify(logged_in_as=current_user), 200

def role_required(role_name):
    def decorator(func):
        @wraps(func)
        def authorize(*args, **kwargs):
            username = request.json.get("username", None)
            if username != "admin":
                abort(401)
            return func(*args, **kwargs)
        # authorize.__name__ = func.__name__
        return authorize

    return decorator


@app.route("/admin-protected", methods=["POST"])
@role_required("admin")
def admin_view():
    # " this view is for admins only "

    # Get all user objects from the database
    print("Strting /admin-protected")
    users = Users.query.all()

    # Store the list of user objects in a variable
    user_accs = []
    for user in users:
        user_accs.append(user)

    print(user_accs)

    # Return the list of user objects as a JSON response
    return jsonify(user_accs), 201

@app.route("/insertdata", methods=["POST"])
@role_required("admin")
def insert_data():
    """Inserts data into the database, creating the table if it does not exist."""

    session = Session(engine)

    # Check if the table exists.
    if not inspect(session.bind).has_table('Products'):
        # Create the table.
        Products.__table__.create(session.bind)

    stmt1 = insert(Products).values(
        product_name="Phone", product_description="desc1", barcode="123", price=300
    )
    stmt2 = insert(Products).values(
        product_name="Laptop", product_description="desc2", barcode="456", price=400
    )
    stmt3 = insert(Products).values(
        product_name="Power bank", product_description="desc3", barcode="789", price=500
    )

    with engine.connect() as conn:
        result1 = conn.execute(stmt1)
        result2 = conn.execute(stmt2)
        result3 = conn.execute(stmt3)
        conn.commit()

    return jsonify("Data inserted successfully!")


@app.route("/uploadfile", methods=["POST"])
@jwt_required() # Requres JWT Token
def upload_files():
    """Uploads a file to the server."""

    # Get the uploaded file.
    uploaded_file = request.files["file1"]

    # Get the filename.
    filename = secure_filename(uploaded_file.filename)

    # Get the file extension.
    file_ext = ""
    if filename != "":
        file_ext = os.path.splitext(filename)[1]

    # Check if the file extension is allowed.
    if file_ext not in app.config["UPLOAD_EXTENSIONS"]:
        abort(400, "File Type Not Allowed")

    # Save the uploaded file.
    uploaded_file.save(os.path.join(app.config["UPLOAD_PATH"], filename))

    # Return a success response.
    return jsonify({"msg": "File Uploaded Successfully !"}), 200

@app.route("/public", methods=['GET'])
def public_route():
    # try:
    products = db2.session.query(Products).all()
    # except:
    #     return jsonify({"error": "An error occurred while retrieving the products."})

    objects = []
    for product in products:
        objects.append(product.to_json())

    return jsonify(objects)

# Run Flask app
if __name__ == "__main__":
    init()
    app.run(debug=True)
