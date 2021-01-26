class c:
    gray = '\033[1;30m'
    red = '\033[1;31m'
    green = '\033[1;32m'
    yellow = '\033[1;33m'
    blue = '\033[1;34m'
    purple = '\033[1;35m'
    cyan = '\033[1;36m'
    white = '\033[1;37m'
    default = '\033[0m'

class Msg:
    error = "[ "+c.red+"ERROR"+c.default+" ] "
    warn = "[ "+c.yellow+"WARNING"+c.default+" ] "
    note = "[ "+c.blue+"NOTE"+c.default+" ] "
    @staticmethod
    def ferror(s):
        return "[ "+c.red+s+c.default+" ] "
    @staticmethod
    def fwarn(s):
        return "[ "+c.yellow+s+c.default+" ] "
    @staticmethod
    def fnote(s):
        return "[ "+c.blue+s+c.default+" ] "
    @staticmethod
    def fcyan(s):
        return "[ "+c.cyan+s+c.default+" ] "
    @staticmethod
    def fpurp(s):
        return "[ "+c.purple+s+c.default+" ] "
    @staticmethod
    def fsucc(s):
        return "[ "+c.green+s+c.default+" ] "