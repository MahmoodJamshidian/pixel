from typing import Union, List, Dict, Tuple, Any
import inspect
import hashlib
import uuid

# validity class for check validity of request arguments
class Validity:
    @staticmethod
    def username(_val: Any):
        if type(_val) != str:
            raise ValueError("Username must be a string")
        if len(_val) < 5 or len(_val) > 20:
            raise ValueError("Username must be between 5 and 20 characters")
        return _val
    
    @staticmethod
    def first_name(_val: Any):
        if type(_val) != str:
            raise ValueError("First name must be a string")
        if len(_val) > 30:
            raise ValueError("First name must be less than or equal to 30 characters")
        return _val

    @staticmethod
    def last_name(_val: Any):
        if type(_val) != str:
            raise ValueError("Last name must be a string")
        if len(_val) > 30:
            raise ValueError("Last name must be less than or equal to 30 characters")
        return _val
    
    @staticmethod
    def username_search(_val: Any):
        if type(_val) != str:
            raise ValueError("Username must be a string")
        if len(_val) > 20:
            raise ValueError("Usernames cannot be longer than 20 characters")
        return _val
    
    @staticmethod
    def password(_val: Any):
        if type(_val) != str:
            raise ValueError("Password must be a string")
        if len(_val) < 8:
            raise ValueError("Password cannot be lesser than 8 characters")
        return _val
    
    @staticmethod
    def project_name(_val: Any):
        if type(_val) != str:
            raise ValueError("Project name must be a string")
        if len(_val) < 5 or len(_val) > 30:
            raise ValueError("Project name must be a string and between 5 and 30 characters")
        return _val
    
    @staticmethod
    def boolean(_val: Any):
        if type(_val) != bool:
            raise ValueError()
        return _val
    
    @staticmethod
    def string(_val: Any):
        if type(_val) != str:
            raise ValueError()
        return _val
    
    @staticmethod
    def integer(_val: Any):
        if type(_val) != int:
            raise ValueError()
        return _val

# for remove extra key and values from a dictionary
purity = lambda __form: {key: value for key, value in filter(lambda item: item[1] is not None, __form.items())}

# for combine two lists with a function of items in operatable list
# for example:
# operation([1, 5, 2], [4, 1, 5], '__add__') -> [5, 6, 7]
operation = lambda list1, list2, _op_name: [list1[i].__getattribute__(_op_name)(list2[i]) for i in range(len(list1))]

# for remove extra keys from two dictionaries and match between them
# for example:
# purity2list({
#     'b': 34,
#     'a': '23',
#     'c': None
#   }, {
#     'a': 20,
#     'b': 18,
#     'c': 16,
#     'd': 14
#   }) -> ([34, 23], [18, 20])
def purity2list(data: Dict, stencil: Dict) -> Tuple[List, List]:
    data_purity, stencil_crupped = [], []
    for key, val in purity(data).items():
        stencil_crupped.append(stencil[key])
        data_purity.append(val)
    return (data_purity, stencil_crupped)

# this function returns parameters of a function
def func_parameters(func):
    return inspect.signature(func).parameters

# returns the input hashed with sha256 encryption
def sha256_hash(_val: Union[bytes, str]):
    if type(_val) == str:
        _val = _val.encode()
    return hashlib.sha256(_val).hexdigest()

uuid4 = lambda: str(uuid.uuid4())