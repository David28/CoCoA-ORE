######################################
#########Jorge Martins fc51033########
######################################

class MyToken(object):
    def __init__(self, type, lineno):
        self.type = type
        self.lineno = lineno

    def __repr__(self):
        return f'MyToken({self.type}, {self.lineno})'
