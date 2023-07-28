from typing import Union, List, Dict, Tuple

# validity class for check validity of request arguments
class Validity:
    @staticmethod
    def username(_val: Union[list, dict, str]):
        if type(_val) != str:
            raise ValueError("Username must be a string")
        if len(_val) < 5 or len(_val) > 20:
            raise ValueError("Username must be between 5 and 20 characters")
        return _val
    
    @staticmethod
    def first_name(_val: Union[list, dict, str]):
        if type(_val) != str:
            raise ValueError("First name must be a string")
        if len(_val) > 30:
            raise ValueError("First name must be less than or equal to 30 characters")
        return _val

    @staticmethod
    def last_name(_val: Union[list, dict, str]):
        if type(_val) != str:
            raise ValueError("Last name must be a string")
        if len(_val) > 30:
            raise ValueError("Last name must be less than or equal to 30 characters")
        return _val
    
    @staticmethod
    def username_search(_val: Union[list, dict, str]):
        if type(_val) != str:
            raise ValueError("Username must be a string")
        if len(_val) > 20:
            raise ValueError("Usernames cannot be longer than 20 characters")
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