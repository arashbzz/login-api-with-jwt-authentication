from flask import Flask, request
from flask_jwt_extended import (create_access_token,
                                get_jwt_identity,
                                jwt_required)
from werkzeug.security import check_password_hash, generate_password_hash
from config import Config
from flask_jwt_extended import JWTManager
import pymssql
from functools import wraps

'''initial flask app'''
app = Flask(__name__)
app.config.from_object(Config)
jwt_manager = JWTManager(app)  # library for making and checking JWT

'''connect to the server as a windows authentication'''
db = pymssql.connect(server=Config.server, database=Config.database)
cursor = db.cursor(as_dict=True)

''' function for checking hash '''


def check_password(database_pass, password):
    print(database_pass)
    print(generate_password_hash(password))
    return check_password_hash(database_pass, password)


''' decorator for checking input for json'''


def json_only(function):
    @wraps(function)
    def decorator(*args, **kwargs):
        if not request.is_json:
            return {'error': 'JSON Only!'}, 400
        return function(*args, **kwargs)

    return decorator


@app.route('/sign_up/', methods=['POST'])
@json_only
def create_user():
    args = request.get_json()
    try:
        username = args.get('username')
        password = generate_password_hash(args.get('password'))
        mobile = args.get('mobile')
        if len(args.get('password')) < 6:
            raise ValueError('password should be more than 6 character.')
        cursor.callproc('CreatePerson', (username, mobile, password))
        db.commit()

    except ValueError as e:
        return {'error': f'{e}'}, 400
    except pymssql._pymssql.DatabaseError:
        return {'error': 'Username is duplicated.'}, 400

    return {'message': 'Account created successfully'}, 201


@app.route('/login/', methods=['POST'])
@json_only
def login():
    args = request.get_json()

    username = args.get('username')
    password = args.get('password')

    cursor.callproc('FindPerson', (username,))
    user = None
    for row in cursor:
        user = row['name']
        database_pass = row['pass'].strip()

    if not user:
        return {'error': 'Username in not exist.'}, 403

    if not check_password(database_pass, str(password)):
        return {'error': 'Password does not match.'}, 403

    access_token = create_access_token(identity=user)

    return {'access_token': access_token, }, 200


@app.route('/access_to_name/', methods=['GET'])
@jwt_required()
def get_user():
    identity = get_jwt_identity()
    cursor.callproc('FindPerson', (identity,))

    for row in cursor:
        user = row['name']
        mobile = row['mobile']
    return {'username': user, 'mobile': mobile}
