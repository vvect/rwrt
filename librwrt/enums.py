from enum import Enum


class FridaScriptRuntimes(Enum):
    DUK = 'duk'
    QJS = 'qjs'
    V8 = 'v8'


class FridaConnectionTypes(Enum):
    USB = 'usb'
    NETWORK = 'network'
    LOCAL = 'local'