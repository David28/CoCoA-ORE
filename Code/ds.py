from lib.ore_wrapper import OreVal
from tokens import *


class MyValue(object):
    def __init__(self, lineno, flowinfo, token, order, type, ore_params=None):
        self.lineno = lineno
        self.flowinfo = flowinfo
        self.token = token
        self.order = order
        self.type = type
        # Order Revealing Encryption
        if ore_params:
            self.lineno = OreVal(lineno, ore_params[0][0], ore_params[0][1])
            self.token = MyToken(token.type, OreVal(token.lineno, ore_params[0][0], ore_params[0][1]))

            self.flowinfo = OreVal(flowinfo, ore_params[1][0], ore_params[1][1])
            self.order = OreVal(order, ore_params[2][0], ore_params[2][1])
            self.type = OreVal(type, ore_params[3][0], ore_params[3][1])
            

    def get_line(self):
        return self.lineno

    def get_flow(self):
        return self.flowinfo

    def get_token(self):
        return self.token

    def get_order(self):
        return self.order

    def get_type(self):
        return self.type

    def __repr__(self):
        return f'MyValue({self.lineno}, {self.flowinfo}, {self.order}, {self.type},{self.token})'

    def _serialize(self):
        #have to indicate if we are using ore or not
        return ("ore;;" if isinstance(self.flowinfo, OreVal) else "") + str(self.lineno) + ";;" + str(self.flowinfo) + ";;" + self.token.type + ";;" + str(self.token.lineno) + ";;" + str(self.order) + ";;" + str(self.type)

    @classmethod
    def _deserialize(self, text):
        a = text.split(";;")
        if a[0] == "ore":
            return MyValue(OreVal(a[1]), OreVal(a[2]), MyToken(a[3], OreVal(a[4])), OreVal(a[5]), OreVal(a[6]))
        else:
            return MyValue(int(a[0]), int(a[1]), MyToken(a[2], int(a[3])), int(a[4]), int(a[5]))
# PASSOU DE {KEY: {LINE: TOK}} PARA {KEY: [OBJ(LINE, DEPTH, TOK)]}


class DataStructure(object):
    def __init__(self):
        self.data = {}

    def put(self, key, value):
        if key in self.data:
            self.data[key].append(value)
        else:
            self.data[key] = [value]

    def get(self, key):
        if not key in self.data:
            return None
        else:
            return self.data[key]
