#!/usr/bin/env python
"""
Python wrapper for Windows Debugger Engine API.
"""

import platform

from ctypes import *
from comtypes.hresult import S_OK

try:
    from comtypes.gen import DbgEng
except ImportError:
    from comtypes.client import GetModule
    GetModule("helper/DbgEng.tlb")
    from comtypes.gen import DbgEng


if platform.architecture()[0] == '32bit':
    try:
        dbghelp = windll.LoadLibrary("lib/dbghelp.dll") 
        dbgeng = windll.LoadLibrary("lib/dbgeng.dll")
    except:
        print 'Can not load dbghelp.dll and dbgeng.dll'
elif platform.architecture()[0] == '64bit':
    try:
        dbghelp = windll.LoadLibrary("lib/dbghelp_x64.dll") 
        dbgeng = windll.LoadLibrary("lib/dbgeng_x64.dll")
    except:
         print 'Can not load dbghelp.dll and dbgeng.dll'
else:
    raise Exception('Unsupported system.')


DebugCreate = dbgeng.DebugCreate


class PyDbgX:

    def __init__(self):

        self.__debug_client = POINTER(DbgEng.IDebugClient)()
        
        hr = DebugCreate(byref(DbgEng.IDebugClient._iid_), byref(self.__debug_client))
        if S_OK != hr:
            raise Exception('DebugCreate() fail.')
        

if __name__ == '__main__':

    dbg = PyDbgX()
        