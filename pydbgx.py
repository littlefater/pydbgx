#!/usr/bin/env python
"""
Python wrapper for Windows Debugger Engine API.
"""

import os
import sys
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
from ctypes import c_ulong, c_void_p, POINTER
from ctypes import byref, create_string_buffer, pointer, cast

from comtypes import COMError
from comtypes.hresult import S_OK, S_FALSE
from comtypes.automation import IID, GUID


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
DEBUG_CREATE_PROCESS_NO_DEBUG_HEAP = 0x00000400
E_FAIL = 0x80004005L
E_PENDING = 0x8000000A
E_UNEXPECTED = 0x8000FFFF
INFINITE = 0xFFFFFFFF
########################################


class DebugEventCallbacksImpl(DbgEng.IDebugEventCallbacks):
    """event callback class"""

    _reg_clsid_ = GUID('{276EFA76-BAF4-4603-A328-A0A1D3C37BFF}')
    _reg_threading_ = 'Both'
    _reg_progid_ = 'DbgEngLib.DebugEventCallbacks.1'
    _reg_novers_progid_ = 'DbgEngLib.DebugEventCallbacks'
    _reg_desc_ = 'A do-nothing implementation of IDebugEventCallbacks'
    _reg_clsctx_ = comtypes.CLSCTX_INPROC_SERVER | comtypes.CLSCTX_LOCAL_SERVER

    def __init__(self, mask=0):
        super(DebugEventCallbacksImpl, self).__init__()
        self.__mask = mask

    def _IUnknown__com_AddRef(self):
        pass
    
    def _IUnknown__com_QueryInterface(self):
        pass
    
    def _IUnknown__com_Release(self):
        pass

    def _IDebugEventCallbacks__com_GetInterestMask(self):
        print 'GetInterestMask called.'
        return self.__mask
    
    def _IDebugEventCallbacks__com_Breakpoint(self, Bp):
        print 'Breakpoint called.'
        return DbgEnd.DEBUG_STATUS_NO_CHANGE

    def _IDebugEventCallbacks__com_Exception(self, Exception, FirstChance):
        print 'Exception called.'
        return DbgEnd.DEBUG_STATUS_NO_CHANGE

    def _IDebugEventCallbacks__com_CreateThread(self, Handle, DataOffset, StartOffset):
        print 'CreateThread called.'
        return DbgEnd.DEBUG_STATUS_NO_CHANGE

    def _IDebugEventCallbacks__com_ExitThread(self, ExitCode):
        print 'ExitThread called.'
        return DbgEnd.DEBUG_STATUS_NO_CHANGE
    
    def _IDebugEventCallbacks__com_CreateProcess(self, ImageFileHandle, Handle, BaseOffset, ModuleSize, ModuleName, ImageName, CheckSum, TimeDateStamp, InitialThreadHandle, ThreadDataOffset, StartOffset):
        print 'CreateProcess called.'
        return DbgEnd.DEBUG_STATUS_NO_CHANGE

    def _IDebugEventCallbacks__com_ExitProcess(self, ExitCode):
        return DbgEnd.DEBUG_STATUS_NO_CHANGE

    def _IDebugEventCallbacks__com_LoadModule(self, ImageFileHandle, BaseOffset, ModuleSize, ModuleName, ImageName, CheckSum, TimeDateStamp):
        return DbgEnd.DEBUG_STATUS_NO_CHANGE

    def _IDebugEventCallbacks__com_UnloadModule(self, ImageBaseName, BaseOffset):
        return DbgEnd.DEBUG_STATUS_NO_CHANGE
    
    def _IDebugEventCallbacks__com_SystemError(self, Error, Level):
        return DbgEnd.DEBUG_STATUS_NO_CHANGE

    def _IDebugEventCallbacks__com_SessionStatus(self, Status):
        return DbgEnd.DEBUG_STATUS_NO_CHANGE
    
    def _IDebugEventCallbacks__com_ChangeDebuggeeState(self, Flags, Argument):
        return S_OK
    
    def _IDebugEventCallbacks__com_ChangeEngineState(self, Flags, Argument):
        return S_OK
    
    def _IDebugEventCallbacks__com_ChangeSymbolState(self, Flags, Argument):
        return S_OK
    
    def GetInterestMask(self):
        '-no docstring-'
        print 'called'
        return self.__mask

    def Breakpoint(self, Bp):
        '-no docstring-'
        #return 

    def Exception(self, Exception, FirstChance):
        '-no docstring-'
        #return 

    def CreateThread(self, Handle, DataOffset, StartOffset):
        '-no docstring-'
        #return

    def ExitThread(self, ExitCode):
        '-no docstring-'
        #return

    def CreateProcess(self, ImageFileHandle, Handle, BaseOffset, ModuleSize, ModuleName, ImageName, CheckSum, TimeDateStamp, InitialThreadHandle, ThreadDataOffset, StartOffset):
        '-no docstring-'
        print 'test'
        #return 

    def ExitProcess(self, ExitCode):
        '-no docstring-'
        #return
        
    def LoadModule(self, ImageFileHandle, BaseOffset, ModuleSize, ModuleName, ImageName, CheckSum, TimeDateStamp):
        '-no docstring-'
        #return

    def UnloadModule(self, ImageBaseName, BaseOffset):
        '-no docstring-'
        #return 

    def SystemError(self, Error, Level):
        '-no docstring-'
        #return

    def SessionStatus(self, Status):
        '-no docstring-'
        #return

    def ChangeDebuggeeState(self, Flags, Argument):
        '-no docstring-'
        #return 
    
    def ChangeEngineState(self, Flags, Argument):
        '-no docstring-'
        #return
        
    def ChangeSymbolState(self, Flags, Argument):
        '-no docstring-'
        #return 

        
class PyDbgX:
    """debugger class"""

    def __init__(self):
        """initiate the debugger"""

        sys.stdout.write('[*] Initiate DebugClient: ')
        self.__debug_client = POINTER(DbgEng.IDebugClient)()
        hr = DebugCreate(byref(DbgEng.IDebugClient._iid_), byref(self.__debug_client))
        if S_OK != hr:
            raise Exception('DebugCreate() fail.')
        print 'Success'

        print '    Indentity:', self.get_indentity()
    
        sys.stdout.write('[*] Initiate DebugControl: ')
        self.__debug_control = self.__debug_client.QueryInterface(interface = DbgEng.IDebugControl)
        if None == self.__debug_control:
            raise Exception('Query IDebugControl fail.')
        print 'Success'

        print self.__debug_client.GetEventCallbacks()
        
        sys.stdout.write('[*] Set DebugEventCallbacks: ')
        event_callbacks = POINTER(DebugEventCallbacksImpl)()
        hr = self.__debug_client.SetEventCallbacks(event_callbacks)
        if S_OK != hr:
            raise Exception('SetEventCallbacks() fail.')
        print 'Success'
        
        print self.__debug_client.GetEventCallbacks()

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

        sys.stdout.write('[*] Create Process: ')
        if follow_child:
            flags = DbgEng.DEBUG_PROCESS
        else:
            flags = DEBUG_ONLY_THIS_PROCESS

        flags |= DEBUG_CREATE_PROCESS_NO_DEBUG_HEAP      # Prevents the debug heap from being used in the new process.
        server = 0
        hr = self.__debug_client._IDebugClient__com_CreateProcess(server, cmd, flags)
        if S_OK != hr:
            raise Exception('CreateProcess() fail.')
        print 'Success'   
        print '    Command:', cmd
        print '    Follow Child:', follow_child
        print '    Indentity:', self.get_indentity()

    def wait_for_event(self):
        """IDebugControl::WaitForEvent method"""
        
        print '[*] WaitForEvent'

        flags = 0
        timeout = INFINITE
        hr = self.__debug_control.WaitForEvent(flags, timeout)
        if S_OK == hr:
            print 'WaitForEvent OK'
        elif S_FALSE == hr:
            print 'WaitForEvent FALSE'
        elif E_FAIL == hr:
            print 'WaitForEvent FAIL'
        elif E_PENDING == hr:
            print 'WaitForEvent PENDING'
        elif E_UNEXPECTED == hr:
            print 'WaitForEvent UNEXPECTED'
        else:
            print 'WaitForEvent Unknow'

    def get_last_event(self):
        """IDebugControl::GetLastEventInformation method"""

        event_type = c_ulong(0)
        process_id = c_ulong(0)
        thread_id = c_ulong(0)
        extra_information_size = 0x1000
        extra_information = create_string_buffer(extra_information_size)
        extra_information_used = c_ulong(0)
        description_size = 0x1000
        description = create_string_buffer(description_size)
        description_used = c_ulong(0)
        
        hr = self.__debug_control._IDebugControl__com_GetLastEventInformation(
            byref(event_type), byref(process_id), byref(thread_id),
            extra_information, extra_information_size, byref(extra_information_used),
            description, description_size, byref(description_used))
        print hr
        if S_OK != hr:
            if S_FALSE == hr:
                extra_information_size = extra_information_used.value + 1
                extra_information = create_string_buffer(extra_information_size)
                description_size = description_used.value + 1
                description = create_string_buffer(description_size)
                
                hr = self.__debug_control._IDebugControl__com_GetLastEventInformation(
                    byref(event_type), byref(process_id), byref(thread_id),
                    extra_information, extra_information_size, byref(extra_information_used),
                    description, description_size, byref(description_used))

                if S_OK != hr:
                    raise Exception('GetLastEventInformation() fail.')
            else:
                raise Exception('GetLastEventInformation() fail.')
        

if __name__ == '__main__':

    dbgx = PyDbgX()
    #dbgx.list_running_process()
    dbgx.create_process('d:\\Workspace\\GitHub\\pydbgx\\notepad.exe')
    dbgx.wait_for_event()
    dbgx.get_last_event()