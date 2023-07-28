from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from typing import Dict
from datetime import datetime
import os

# initiate sqlalchemy orm
db = SQLAlchemy()

# set easy access functions to add, delete and commit
db.save = lambda: db.session.commit()
db.add = lambda *args, **kwargs: db.session.add(*args, **kwargs)
db.remove = lambda obj: db.session.delete(obj)

# statuses that projects can have
PROJECT_STATUS=('starting', 'development', 'completed')

class Project: ...

# a custom class to simplify the task of converting data to a dictionary
class custom_model(db.Model):
    __abstract__ = True
    def to_dict(self, full=True) -> Dict:
        res = {}
        for column in self.__table__.columns:
            column_name = column.name
            column_value = getattr(self, column_name)
            res[column_name] = column_value
        if full:
            for relationship in self.__mapper__.relationships:
                    related_obj = getattr(self, relationship.key)
                    if related_obj is not None:
                        if relationship.uselist:
                            res[relationship.key] = [obj.to_dict(full=False) for obj in related_obj]
        return res

# users table
class User(custom_model):
    id: int = db.Column(db.Integer, primary_key=True)
    username: str = db.Column(db.String(20), unique=True, nullable=False)
    first_name: str = db.Column(db.String(30), nullable=False)
    last_name: str = db.Column(db.String(30), nullable=True)

# projects table
class Project(custom_model):
    id: int = db.Column(db.Integer, primary_key=True)
    status: int = db.Column(db.Integer, nullable=False)
    last_modify: datetime = db.Column(db.DateTime, default=datetime.utcnow)
    private: bool = db.Column(db.Boolean, default=False)
    user_id: int = db.Column(db.Integer, db.ForeignKey(User.id))
    user = db.relationship(User, backref='projects', lazy=True)

    # to convert number to string status
    def to_dict(self, full=True):
        res = custom_model.to_dict(self, full)
        res['status'] = PROJECT_STATUS[res['status']]
        return res
    
def __init__(flask_app: Flask):
    # set uri of database for sqlalchemy orm connection
    flask_app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["DB_URI"]
    flask_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # initiate sqlalchemy to flask application
    db.init_app(flask_app)
    with flask_app.app_context():
        # reset all table after run
        if int(os.environ['_DB_RESET']):
            db.drop_all()
        db.create_all()