# flask imports
import functools
from pydoc import doc
from apispec_webframeworks.flask import FlaskPlugin
from apispec.ext.marshmallow import MarshmallowPlugin
from apispec import APISpec
from flask import Flask, session,request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid # for public id
from werkzeug.security import generate_password_hash, check_password_hash
# imports for PyJWT authentication
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask_user import current_user, UserManager
from flask_swagger_ui import get_swaggerui_blueprint


# creates Flask object
app = Flask(__name__)
# configuration
app.config['SECRET_KEY'] = 'password123'
# database name
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['USER_ENABLE_EMAIL'] = False
app.config['USER_ENABLE_USERNAME'] = False

#swagger configs
SWAGGER_URL ='/swagger'
API_URL = '/static/swagger.json'
SWAGGER_BLUEPRINT = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config = {
        'app_name':"Access role API's"
    }
)
app.register_blueprint(SWAGGER_BLUEPRINT,url_prefix=SWAGGER_URL)
# creates SQLALCHEMY object
db = SQLAlchemy(app)


# Database ORMs
class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique = True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique = True)
    password = db.Column(db.String(80))
    # Relationships
    roles = db.relationship('Role', secondary='user_roles',backref=db.backref('users', lazy='dynamic'))

class Role(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), unique=True)

# Define UserRoles model
class UserRoles(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('role.id', ondelete='CASCADE'))

user_manager = UserManager(app, db, User)

# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message' : 'Token is missing'}), 401

        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query\
                .filter_by(public_id = data['public_id'])\
                .first()
            session['email'] = current_user.email
        except:
            return jsonify({
                'message' : 'Token is invalid'
            }), 401
        # returns the current logged in users contex to the routes
        return f(current_user, *args, **kwargs)

    return decorated


def roles_requires(*role_names):
    def decorator(original_route):
        @functools.wraps(original_route)
        def decorated_route(*args, **kwargs):
            output=[]
            user=User.query.filter_by(email=session['email']).first()
            roles=db.session.query(Role).join(UserRoles).filter(UserRoles.role_id==Role.id).filter(UserRoles.user_id==user.id).all()
            for role in roles:
                output.append(role.name)
            missing_roles=[]
            for role_name in role_names:
                if role_name not in output:
                    missing_roles.append(role_name)
            if missing_roles:
                return jsonify({
                'message' : 'Unauthorised user'
                 }), 401
            return original_route(*args, **kwargs)
        
        return decorated_route
    
    return decorator
    



# this route sends back list of users users
@app.route('/admin/users', methods =['GET'])
@token_required
@roles_requires('admin')
def get_all_users(current_user):
    # querying the database
    # for all the entries in it
    users = User.query.all()
    # converting the query objects
    # to list of jsons
    output = []
    roles=db.session.query(UserRoles).all()
    # for guest in guests:
    #     output1.append({'role':guest.name})
    for user in users:
        output1=[]
        roles=db.session.query(Role).join(UserRoles).filter(UserRoles.role_id==Role.id).filter(UserRoles.user_id==user.id).all()
        for role in roles:
            output1.append({'role':role.name})
        output.append({
            'id':user.id,
            'public_id': user.public_id,
            'name' : user.name,
            'email' : user.email,
            'roles' : output1
        })

    return jsonify({'users': output})

@app.route('/admin/user/role/add', methods =['POST'])
@token_required
@roles_requires('admin')
def make_user_admin(current_user):
    data=request.form
    user_id,role=data.get('user_id'),data.get('role_name')
    # for guest in guests:
    #     output1.append({'role':guest.name})
    if(user_id and role):
        user=User.query.filter_by(id=user_id).first()
        if(user):
            role=Role.query.filter_by(name=role).first()
            if(role):
                userrole=UserRoles.query.filter_by(user_id=user.id,role_id=role.id).first()
                if not userrole:
                    user.roles.append(role)
                    userrole1=UserRoles(user_id=user.id,role_id=role.id)
                    db.session.add(user,userrole1)
                    db.session.commit()
                else:
                    return jsonify({'message' : 'Role already exists for user'}), 202
            else:
                return jsonify({'message' : 'Invalid role'}), 202
        else:
            return jsonify({'message' : 'Invalid user'}), 202
        return jsonify({'message' : 'Role added to user'}), 201
    else:
        return jsonify({'message' : 'Missing input data'}), 400

@app.route('/user/',methods=['GET'])
@token_required
def get_user_detail(current_user):
    user=User.query.filter_by(id=current_user.id).first()
    output=[]
    output.append({
            'public_id': user.public_id,
            'name' : user.name,
            'email' : user.email,
        })
    return jsonify({'user': output})

@app.route('/user/<user_id>',methods=['GET'])
@token_required
@roles_requires('admin')
def get_specific_user_detail(current_user,user_id):
    user=User.query.filter_by(id=user_id).first()
    if(user):
        output=[]
        output.append({
            'public_id': user.public_id,
            'name' : user.name,
            'email' : user.email,
        })
        return jsonify({'user': output})
    else:
        return jsonify({'message':'invalid user'}) ,202

@app.route('/addRoleDB',methods=['POST'])
def addroledb():
    data=request.form
    role_id,role_name=data.get('id'),data.get('name')
    role=Role.query.filter_by(name=role_name).first()
    if not role:
        role=Role(id=role_id,name=role_name)
        db.session.add(role)
        db.session.commit()
        roles = Role.query.all()
        output = []
        for role in roles:
            output.append({'id':role.id,'name':role.name})
        return jsonify({'roles': output})
    else:
        return jsonify({'message' : 'Role exists'}), 202

# route for logging user in
@app.route('/login', methods =['POST'])
def login():
    # creates dictionary of form data
    auth = request.form
    if not auth or not auth.get('email') or not auth.get('password'):
        # returns 401 if any email or / and password is missing
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate' : 'Basic realm ="Login required !!"'}
        )
    user = User.query\
        .filter_by(email = auth.get('email'))\
        .first()

    if not user:
        # returns 401 if user does not exist
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
        )

    if check_password_hash(user.password, auth.get('password')):
        # generates the JWT Token
        output=[]
        roles=db.session.query(Role).join(UserRoles).filter(UserRoles.role_id==Role.id).filter(UserRoles.user_id==user.id).all()
        for role in roles:
                output.append(role.name)
        token = jwt.encode({
            'public_id': user.public_id,
            'exp' : datetime.utcnow() + timedelta(minutes = 30),
            'roles': output
        }, app.config['SECRET_KEY'])
        session['email'] = auth.get('email')
        return make_response(jsonify({'token' : token.decode('UTF-8')}), 201)
    # returns 403 if password is wrong
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
    )

# signup route
@app.route('/signup', methods =['POST'])
def signup():
    # creates a dictionary of the form data
    data = request.form

    # gets name, email and password
    name, email = data.get('name'), data.get('email')
    password = data.get('password')

    # checking for existing user
    user = User.query\
        .filter_by(email = email)\
        .first()
    if not user:
        # database ORM object
        user = User(
            public_id = str(uuid.uuid4()),
            name = name,
            email = email,
            password = generate_password_hash(password)
        )
        role=Role.query.filter_by(name="user").first()
        user.roles.append(role)
        userrole=UserRoles(user_id=user.id,role_id=role.id)
        # insert user
        db.session.add(user,userrole)
        db.session.commit()
        return jsonify({'message' : 'Successfully registered'}), 201
    else:
        # returns 202 if user already exists
        return jsonify({'message' : 'User already exists. Please Log in.'}), 202


@app.route('/check',methods=['GET'])
@token_required
@roles_requires('user')
def check(current_user):
    return make_response("working",201)
if __name__ == "__main__":
    # setting debug to True enables hot reload
    # and also provides a debugger shell
    # if you hit an error while running the server
    app.run(debug = True)
