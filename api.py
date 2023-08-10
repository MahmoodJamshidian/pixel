from flask_restful import Api, Resource, fields, marshal_with, marshal, abort
from flask_restful.reqparse import RequestParser, Namespace
from flask import Blueprint, request, current_app, url_for
from typing import List
from utils import *
import models

__version__ = '0.1'

# initate api blueprint and flask_restful api
app = Blueprint('api', __name__)
api = Api(app)

# define request parsers for recving data from request and formmat it
rp_user_get = RequestParser(bundle_errors=True)
rp_user_get.add_argument('id', type=int, help='id is the user\'s numeric identifier', required=False, location=['args'])
rp_user_get.add_argument('username', type=Validity.username, help='Username must be a string and between 5 and 20 characters', required=False, location=['args'])

rp_user_add = RequestParser(bundle_errors=True)
rp_user_add.add_argument('username', type=Validity.username, help="Username must be a string and between 5 and 20 characters", required=True, location=['json'])
rp_user_add.add_argument('first_name', type=Validity.first_name, help="First name is a string type and has a maximum of 30 characters", required=True, location=['json'])
rp_user_add.add_argument('last_name', type=Validity.last_name, help="Last name is a string type and has a maximum of 30 characters", required=False, location=['json'])
rp_user_add.add_argument('password', type=Validity.password, help="Password is a string type and has a minimum of 8 characters", location=['json'])

rp_user_update = RequestParser(bundle_errors=True)
rp_user_update.add_argument('id', type=int, help='id is the user\'s numeric identifier', required=True, location=['json'])
rp_user_update.add_argument('first_name', type=Validity.first_name, help="New first name is a string type and has a maximum of 30 characters", required=False, location=['json'])
rp_user_update.add_argument('last_name', type=Validity.last_name, help="New last name is a string type and has a maximum of 30 characters", required=False, location=['json'])

rp_user_delete = RequestParser(bundle_errors=True)
rp_user_delete.add_argument('id', type=int, help='id is the user\'s numeric identifier', required=True, location=['form', 'json'])

rp_user_search = RequestParser(bundle_errors=True)
rp_user_search.add_argument('username', type=Validity.username_search, help='Usernames cannot be longer than 20 characters', required=False, location=['args'])
rp_user_search.add_argument('first_name', type=Validity.first_name, help='First name is a string type and has a maximum of 30 characters', required=False, location=['args'])
rp_user_search.add_argument('last_name', type=Validity.last_name, help='Last name is a string type and has a maximum of 30 characters', required=False, location=['args'])

rp_user_login = RequestParser(bundle_errors=True)
rp_user_login.add_argument('username', type=Validity.username, help='Username is invalid', required=False, location=['json'])
rp_user_login.add_argument('password', type=Validity.password, help="Password is invalid", location=['json'])

# response fields for formatting response
f_project_get = {
    'id': fields.Integer,
    'status': fields.String,
    'last_modify': fields.DateTime,
    'private': fields.Boolean,
    'user_id': fields.Integer
}

f_user_get = {
    'id': fields.Integer,
    'username': fields.String,
    'first_name': fields.String,
    'last_name': fields.String,
}

f_user_list = {
    'count': fields.Integer,
    'resault': fields.List(fields.Nested(f_user_get))
}

f_user_full_get = {
    **f_user_get,
    'projects': fields.List(fields.Nested(f_project_get))
}

f_user_add = {
    'id': fields.Integer,
    'username': fields.String,
    'first_name': fields.String,
    'last_name': fields.String
}

f_user_update = f_user_add

f_user_delete = {}

# api access management class
class AccessControl:
    @staticmethod
    def auth(func):
        def wrapper(*args, **kwargs):
            if not (access_token:=request.headers.get('Authorization', '').split()) or access_token[0] != 'Bearer':
                abort(401, message="Your authentication failed. Please double check your information and try again.")

            token: models.AccessToken = models.AccessToken.query.filter(models.AccessToken.token==access_token[1]).first()

            if not token:
                abort(401, message="Your authentication failed. Please double check your information and try again.")
            if 'user' in func_parameters(func):
                kwargs['user'] = token.user
            return func(*args, **kwargs)
        return wrapper
    
    @staticmethod
    def unforced(func):
        def wrapper(*args, **kwargs):
            if 'user' in func_parameters(func) and (access_token:=request.headers.get('Authorization', '').split()) or access_token[0] != 'Bearer':
                token: models.AccessToken = models.AccessToken.query.filter(models.AccessToken.token==access_token[1]).first()
                if token:
                    kwargs['user'] = token.user
            func(*args, **kwargs)
        return wrapper    
    
    @staticmethod
    def just_self(func):
        def wrapper(*args, **kwaregs):
            if request.remote_addr != '127.0.0.1':
                abort(405)
            func(*args, **kwaregs)
        return wrapper

# User Resource class for add, get, update and delete users from database
class User(Resource):
    method_decorators = {'get': [AccessControl.unforced], 'post': [AccessControl.just_self], 'put': [AccessControl.just_self], 'delete': [AccessControl.just_self]}
    @marshal_with(f_user_full_get)
    def get(self, user: models.User = None):
        # get user by id or username (first priority with id)
        args: Namespace = rp_user_get.parse_args(strict=False)

        if (args['id'] is None) and (args['username'] is None):
            abort(400, message="At least one of the 'id' or 'username' arguments is required")
        
        target_user: models.User

        if args['id']:
            target_user = models.User.query.get(args['id'])
        else:
            target_user = models.User.query.filter(models.User.username==args['username']).first()

        if target_user:
            return target_user.to_dict(True, user is not None)
        else:
            abort(400, message="User not found")
    
    @marshal_with(f_user_add)
    def post(self):
        # add user and view create user information
        args: Namespace = rp_user_add.parse_args(strict=True)
        user: models.User = models.User.query.filter(models.User.username==args['username']).first()

        if not user:
            user = models.User(username=args['username'], first_name=args['first_name'], last_name=args['last_name'], password=sha256_hash(args['password']))
            models.db.add(user)
            models.db.save()
            return user.to_dict(True)
        
        abort(400, message="Username already exists")
    
    @marshal_with(f_user_update)
    def put(self):
        # update user information (first name and last name)
        args: Namespace = rp_user_update.parse_args(strict=True)
        user: models.User = models.User.query.get(args['id'])
        if not user:
            abort(400, message="Username is not exists")
        
        if args['first_name']:
            user.first_name = args['first_name']
        if args['last_name']:
            user.last_name = args['last_name']

        models.db.save()
        
        return user.to_dict(True)

    @marshal_with(f_user_delete)
    def delete(self):
        # remove user
        args: Namespace = rp_user_delete.parse_args(strict=False)
        user: models.User = models.User.query.get(args['id'])
        if not user:
            abort(400, message="User ID is not exists")
        
        models.db.remove(user)
        models.db.save()

# UserSearch Resource class for search user with username, first name or last name
class UserSearch(Resource):
    @marshal_with(f_user_list)
    def get(self):
        args: Namespace = rp_user_search.parse_args(strict=False)
        args = {key: f"%{val}%" for key, val in args.items() if val is not None}
        keys = dict(
            username=models.User.username,
            first_name=models.User.first_name,
            last_name=models.User.last_name
        )

        res: List[models.User] = models.User.query.filter(*operation(*purity2list(args, keys)[::-1], 'like')).all()

        return {
            'count': len(res),
            'resault': [user.to_dict() for user in res]
        }

# UserLogin for login (just frontend) and get account information
class UserLogin(Resource):
    method_decorators = {'get': [AccessControl.auth], 'post': [AccessControl.just_self]}
    @marshal_with(f_user_get)
    def get(self, user: models.User):
        return user.to_dict()

    @marshal_with(f_user_get)
    def post(self):
        args: Namespace = rp_user_login.parse_args(strict=True)
        user: models.User = models.User.query.filter(models.User.username==args['username'] and models.User.password==sha256_hash(args['password'])).first()

        if user:
            return user.to_dict()
        
        abort(400)

# add all resources and set endpoint
api.add_resource(User, "/user", endpoint='user')
api.add_resource(UserSearch, "/user/search", endpoint='user_search')
api.add_resource(UserLogin, "/user/login", endpoint='user_login')