#!/usr/bin/env python
"""
Python wrapper for Windows Debugger Engine API.
"""

import platform

from ctypes import *
#from comtypes.gen import DbgEng

if platform.architecture()[0] == '32bit':
    try:
        dbghelp = windll.LoadLibrary("lib/dbghelp.dll") 
        dbgeng = windll.LoadLibrary("lib/dbgeng.dll")
    except:
        print 'Can not load dbghelp.dll and dbgeng.dll,  '
else:
    try:
        dbghelp = windll.LoadLibrary("lib/dbghelp_x64.dll") 
        dbgeng = windll.LoadLibrary("lib/dbgeng_x64.dll")
     except:


DebugCreate = dbgeng.DebugCreate

class PyDbgX:

    def __init__(self):

        self.__debugClient = c_void_p()

        #hr = DebugCreate(, self.__debugClient)
        

if __name__ == '__main__':

    dbg = PyDbgX()
        