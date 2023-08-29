from flask_restful import Api, Resource, fields, marshal_with, marshal, abort
from flask_restful.reqparse import RequestParser, Namespace
from flask import Blueprint, request, current_app, url_for
from sqlalchemy import and_
from typing import List
from utils import *
import datetime
import models
import os

USER_LOGON_EXPIRE_HOURS = int(os.environ['USER_LOGON_EXPIRE_HOURS'])

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
rp_user_add.add_argument('password', type=Validity.password, help="Password is a string type and has a minimum of 8 characters", required=True, location=['json'])

rp_user_update = RequestParser(bundle_errors=True)
rp_user_update.add_argument('id', type=Validity.integer, help='id is the user\'s numeric identifier', required=True, location=['json'])
rp_user_update.add_argument('first_name', type=Validity.first_name, help="New first name is a string type and has a maximum of 30 characters", required=False, location=['json'])
rp_user_update.add_argument('last_name', type=Validity.last_name, help="New last name is a string type and has a maximum of 30 characters", required=False, location=['json'])

rp_user_delete = RequestParser(bundle_errors=True)
rp_user_delete.add_argument('id', type=int, help='id is the user\'s numeric identifier', required=True, location=['form', 'json'])

rp_user_search = RequestParser(bundle_errors=True)
rp_user_search.add_argument('username', type=Validity.username_search, help='Usernames cannot be longer than 20 characters', required=False, location=['args'])
rp_user_search.add_argument('first_name', type=Validity.first_name, help='First name is a string type and has a maximum of 30 characters', required=False, location=['args'])
rp_user_search.add_argument('last_name', type=Validity.last_name, help='Last name is a string type and has a maximum of 30 characters', required=False, location=['args'])

rp_user_login = RequestParser(bundle_errors=True)
rp_user_login.add_argument('username', type=Validity.string, help='Username must be a string', required=True, location=['json'])
rp_user_login.add_argument('password', type=Validity.string, help="Password must be a string", required=True, location=['json'])

rp_project_get = RequestParser(bundle_errors=True)
rp_project_get.add_argument('id', type=int, help='id is the project\'s numeric identifier', required=True, location=['args'])

rp_project_add = RequestParser(bundle_errors=True)
rp_project_add.add_argument('name', type=Validity.project_name, help='Project name must be a string and between 5 and 30 characters', required=True, location=['json'])
rp_project_add.add_argument('private', type=Validity.boolean, help='Boolean value (true/false)', required=False, default=False, location=['json'])

rp_project_update = RequestParser()
rp_project_update.add_argument('id', type=Validity.integer, help='id is the project\'s numeric identifier', required=True, location=['json'])
rp_project_update.add_argument('name', type=Validity.project_name, help='Project name must be a string and between 5 and 30 characters', required=False, location=['json'])
rp_project_update.add_argument('private', type=Validity.boolean, help='Boolean value (true/false)', required=False, location=['json'])
rp_project_update.add_argument('is_open', type=Validity.boolean, help='Boolean value (true/false). false if you want to close project, true to reopen project', required=False, location=['json'])

rp_project_delete = RequestParser()
rp_project_delete.add_argument('id', type=Validity.integer, help='id is the project\'s numeric identifier', required=True, location=['json'])

# response fields for formatting response
f_project_get = {
    'id': fields.Integer,
    'name': fields.String,
    'is_open': fields.Boolean,
    'created_at': fields.DateTime,
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

f_project_full_get = {
    **f_project_get,
    'user': fields.Nested(f_user_get)
}

f_user_add = {
    'id': fields.Integer,
    'username': fields.String,
    'first_name': fields.String,
    'last_name': fields.String
}

f_access_token_data = {
    'token': fields.String,
    'expires_at': fields.String
}

f_user_login = {
    **f_user_get,
    'access_token': fields.Nested(f_access_token_data)
}

f_user_update = f_user_add

f_user_delete = {}

f_project_delete = {}

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
            if 'user' in func_parameters(func) and (access_token:=request.headers.get('Authorization', '').split()) and access_token[0] == 'Bearer':
                token: models.AccessToken = models.AccessToken.query.filter(models.AccessToken.token==access_token[1]).first()
                if token:
                    kwargs['user'] = token.user
            return func(*args, **kwargs)
        return wrapper
    
    @staticmethod
    def just_self(func):
        def wrapper(*args, **kwaregs):
            if request.remote_addr != '127.0.0.1':
                abort(405)
            return func(*args, **kwaregs)
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
            return target_user.to_dict(True, user == target_user)
        else:
            abort(400, message="User not found")
    
    @marshal_with(f_user_add)
    def post(self):
        # add user and view created user information
        args: Namespace = rp_user_add.parse_args(strict=True)
        user: models.User = models.User.query.filter(models.User.username==args['username']).first()

        if not user:
            user = models.User(username=args['username'], first_name=args['first_name'], last_name=args['last_name'], password=sha256_hash(args['password']))
            models.add(user)
            models.save()
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

        models.save()
        
        return user.to_dict(True)

    @marshal_with(f_user_delete)
    def delete(self):
        # remove user
        args: Namespace = rp_user_delete.parse_args(strict=False)
        user: models.User = models.User.query.get(args['id'])
        if not user:
            abort(400, message="User ID is not exists")
        
        models.remove(user)
        models.save()

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

        res: List[models.User] = models.User.query.filter(and_(*operation(*purity2list(args, keys)[::-1], 'like'))).all()

        return {
            'count': len(res),
            'resault': [user.to_dict() for user in res]
        }

# UserLogin for login (just frontend) and get account information
class UserLogin(Resource):
    method_decorators = {'get': [AccessControl.auth], 'post': [AccessControl.just_self]}
    @marshal_with(f_user_get)
    def get(self, user: models.User):
        # return user data
        return user.to_dict()

    @marshal_with(f_user_login)
    def post(self):
        # login user and create access token for communicate front-end and back-end
        args: Namespace = rp_user_login.parse_args(strict=True)
        user: models.User = models.User.query.filter(and_(models.User.username==args['username'], models.User.password==sha256_hash(args['password']))).first()

        if user:
            res: dict = user.to_dict()

            access_token = models.AccessToken(user_id=user.id, login_token=True, expires_at=datetime.datetime.utcnow()+datetime.timedelta(hours=USER_LOGON_EXPIRE_HOURS))
            models.add(access_token)
            models.save()
            
            res['access_token'] = {
                'token': access_token.token,
                'expires_at': access_token.expires_at
            }

            return res
        
        abort(400, message="Username or Password is incurrect")

class Project(Resource):
    method_decorators = {'get': [AccessControl.unforced], 'post': [AccessControl.auth], 'put': [AccessControl.auth], 'delete': [AccessControl.auth]}
    @marshal_with(f_project_full_get)
    def get(self, user: models.User = None):
        # get project by id or name (first priority with id)
        args: Namespace = rp_project_get.parse_args(strict=False)

        target_project: models.Project = models.Project.query.get(args['id'])
        
        if target_project and (target_project.private and target_project.user == user or not target_project.private):
            return target_project.to_dict(True)
        else:
            abort(400, message="Project not found")
    
    @marshal_with(f_project_full_get)
    def post(self, user: models.User):
        # add project and view created project information
        args: Namespace = rp_project_add.parse_args(strict=True)
        
        project: models.Project = models.Project.query.filter(and_(models.Project.user==user, models.Project.name==args['name'])).first()

        if not project:
            project = models.Project(name=args['name'], private=args['private'], user_id=user.id)
            models.add(project)
            models.save()
            return project.to_dict(True)
        
        abort(400, message="Project already exists")
    
    @marshal_with(f_project_full_get)
    def put(self, user: models.User):
        # update  project information and change project status (open/closed)
        args: Namespace = rp_project_update.parse_args()

        if (args['name'] is None) and (args['private'] is None) and (args['is_open'] is None):
            abort(400, message="At least one of the 'name', 'private' or 'is_open' arguments is required")
        
        project: models.Project = models.Project.query.get(args['id'])

        if not project:
            abort(404, message="Project not found")

        if project.private:
            if user != project.user:
                abort(404, message="Project not found")
        else:
            if user != project.user:
                abort(400, message="You don't have permission")
        
        if args['name'] is not None:
            project.name = args['name']
        if args['private'] is not None:
            project.private = args['private']
        if args['is_open'] is not None:
            project.is_open = args['is_open']
        
        models.save()

        return project.to_dict(True)
    
    @marshal_with(f_project_delete)
    def delete(self, user: models.User):
        # delete project
        args: Namespace = rp_project_delete.parse_args()

        project: models.Project = models.Project.query.get(args['id'])

        if not project:
            abort(404, message="Project not found")

        if project.private:
            if user != project.user:
                abort(404, message="Project not found")
        else:
            if user != project.user:
                abort(400, message="You don't have permission")
        
        models.remove(project)
        models.save()


# add all resources and set endpoint
api.add_resource(User, "/user", endpoint='user')
api.add_resource(UserSearch, "/user/search", endpoint='user_search')
api.add_resource(UserLogin, "/user/login", endpoint='user_login')
api.add_resource(Project, "/project", endpoint='project')