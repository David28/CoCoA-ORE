from tokens import *


class MyValue(object):
    def __init__(self, lineno, flowinfo, token, order, type):
        self.lineno = lineno
        self.flowinfo = flowinfo
        self.token = token
        self.order = order
        self.type = type
        # ordem

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
        return str(self.lineno) + ";;" + str(self.flowinfo) + ";;" + self.token.type + ";;" + str(self.token.lineno) + ";;" + str(self.order) + ";;" + str(self.type)

    @classmethod
    def _deserialize(self, text):
        a = text.split(";;")
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
