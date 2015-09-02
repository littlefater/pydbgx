#!/usr/bin/env python
"""
Python wrapper for Windows Debugger Engine API.
"""

import os
import platform


try:
    import ctypes
except ImportError:
    print 'Missing module: ctypes'
    exit(0)

try:
    import comtypes
except ImportError:
    print 'Missing module: comtypes'
    exit(0)


from ctypes import windll
from ctypes import c_ulong, POINTER
from ctypes import byref, create_string_buffer
from comtypes import COMError
from comtypes.hresult import S_OK, S_FALSE
from comtypes.automation import IID


try:
    from comtypes.gen import DbgEng
except ImportError:
    if os.path.isfile('helper/DbgEng.tlb'):
        from comtypes.client import GetModule
        GetModule('helper/DbgEng.tlb')
        from comtypes.gen import DbgEng
    else:
        print 'Please use the tools in the helper folder to generate the DbgEng.tlb file.'
        exit(0)


if False == os.path.isdir('lib'):
    os.mkdir('lib')
    print 'Missing dbghelp.dll and dbgeng.dll, please copy them to the lib/ folder.'
    exit(0)


if platform.architecture()[0] == '32bit':
    try:
        dbghelp = windll.LoadLibrary('lib/dbghelp.dll') 
        dbgeng = windll.LoadLibrary('lib/dbgeng.dll')
    except:
        print 'Can not load 32bit dbghelp.dll and dbgeng.dll.'
elif platform.architecture()[0] == '64bit':
    try:
        dbghelp = windll.LoadLibrary('lib/dbghelp_x64.dll') 
        dbgeng = windll.LoadLibrary('lib/dbgeng_x64.dll')
    except:
         print 'Can not load 64bit dbghelp.dll and dbgeng.dll.'
else:
    raise Exception('Unsupported system.')


DebugCreate = dbgeng.DebugCreate


########################################
DEBUG_ONLY_THIS_PROCESS = 0x00000002
########################################


class PyDbgX:
    """debugger class"""

    def __init__(self):
        """initiate the debugger"""

        self.__debug_client = POINTER(DbgEng.IDebugClient)()
        
        hr = DebugCreate(byref(DbgEng.IDebugClient._iid_), byref(self.__debug_client))
        if S_OK != hr:
            raise Exception('DebugCreate() fail.')

        self.__debug_control = self.__debug_client.QueryInterface(interface = DbgEng.IDebugControl)
        print self.__debug_control

        if None == self.__debug_control:
            raise Exception('Query IDebugControl fail.')

        print self.get_indentity()
        #print dir(self.__debug_client)

    def get_indentity(self):
        """IDebugClient::GetIdentity method"""

        buffer_size = 0x100
        identity_size = c_ulong(0)
        hr = self.__debug_client._IDebugClient__com_GetIdentity(None, buffer_size, byref(identity_size))
        if S_OK != hr:
            raise Exception('GetIdentity() fail.')

        buffer_size = identity_size.value + 1
        buffer = create_string_buffer(buffer_size)
        hr = self.__debug_client._IDebugClient__com_GetIdentity(buffer, buffer_size, byref(identity_size))
        if S_OK != hr:
            raise Exception('GetIdentity() fail.')
        
        return buffer.value
    
    def list_running_process(self):
        """List running processes"""

        server = 0
        count = 128
        ids = (c_ulong * count)()
        actual_count = c_ulong(0)
        hr = self.__debug_client._IDebugClient__com_GetRunningProcessSystemIds(server, ids, count, byref(actual_count))
        if S_OK != hr:
            raise Exception('GetRunningProcessSystemIds() fail.')

        print '*' * 30
        print 'Process Information'
        print '*' * 30
        
        for i in range(0, actual_count.value):
            
            print 'Process ID:', ids[i]
            
            try:
                flags  = DbgEng.DEBUG_PROC_DESC_NO_PATHS
                exename_size = 0x100
                exename = create_string_buffer(exename_size)
                actual_exename_size = c_ulong(0)
                description_size = 0x100
                description = create_string_buffer(description_size)
                actual_description_size = c_ulong(0)
                
                hr = self.__debug_client._IDebugClient__com_GetRunningProcessDescription(
                    server, ids[i], flags,
                    exename, exename_size, byref(actual_exename_size),
                    description, description_size, byref(actual_description_size))
                
                if S_OK != hr:
                    if S_FALSE == hr:
                        exename_size = actual_exename_size.value + 1
                        exename = create_string_buffer(exename_size)
                        description_size = actual_description_size.value + 1
                        description = create_string_buffer(description_size)
                        
                        hr = self.__debug_client._IDebugClient__com_GetRunningProcessDescription(
                            server, ids[i], flags,
                            exename, exename_size, byref(actual_exename_size),
                            description, description_size, byref(actual_description_size))
                        if S_OK != hr:
                            raise Exception('GetRunningProcessDescription() fail.')
                    else:
                        raise Exception('GetRunningProcessDescription() fail.')
                    
                print 'Process Name:', exename.value
                if actual_description_size.value > 1:
                    for desc in description.value.split('  '):
                        print desc
                
            except COMError:
                print 'No enough privilege to retrieve process information.'
            print '-' * 30
            
    def create_process(self, cmd, follow_child=False):
        """create target process"""

        if follow_child:
            flags = DbgEng.DEBUG_PROCESS
        else:
            flags = DEBUG_ONLY_THIS_PROCESS

        server = 0
        print self.__debug_client._IDebugClient__com_CreateProcess(server, cmd, 0)
        

if __name__ == '__main__':

    dbgx = PyDbgX()
    #dbgx.list_running_process()
    dbgx.create_process('d:\\Workspace\\GitHub\\pydbgx\\notepad.exe')