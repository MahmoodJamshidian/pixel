from flask_restful import Api, Resource, fields, marshal_with, marshal, abort
from flask_restful.reqparse import RequestParser, Namespace
from flask import Blueprint
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

# User Resource class for add, get, update and delete users from database
class User(Resource):
    @marshal_with(f_user_full_get)
    def get(self):
        # get user by id or username (first priority with id)
        args: Namespace = rp_user_get.parse_args(strict=False)

        if (args['id'] is None) and (args['username'] is None):
            abort(400, message="At least one of the 'id' or 'username' arguments is required")
        
        user: models.User

        if args['id']:
            user = models.User.query.get(args['id'])
        else:
            user = models.User.query.filter(models.User.username==args['username']).first()

        if user:
            return user.to_dict(True)
        else:
            abort(400, message="User not found")
    
    @marshal_with(f_user_add)
    def post(self):
        # add user and view create user information
        args: Namespace = rp_user_add.parse_args(strict=True)
        user: models.User = models.User.query.filter(models.User.username==args['username']).first()

        if not user:
            user = models.User(username=args['username'], first_name=args['first_name'], last_name=args['last_name'])
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

# add all resources and set endpoint
api.add_resource(User, "/user", endpoint='user')
api.add_resource(UserSearch, "/user/search", endpoint='user_search')
