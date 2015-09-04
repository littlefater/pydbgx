#!/usr/bin/env python
"""
Python wrapper for Windows Debugger Engine API.
"""

import os
import sys
import logging
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

from comtypes import COMError, CoClass
from comtypes.hresult import S_OK, S_FALSE
from comtypes.automation import IID, GUID
from comtypes.client import GetModule


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
        exit(0)
elif platform.architecture()[0] == '64bit':
    try:
        dbghelp = windll.LoadLibrary('lib/dbghelp_x64.dll') 
        dbgeng = windll.LoadLibrary('lib/dbgeng_x64.dll')
    except:
         print 'Can not load 64bit dbghelp.dll and dbgeng.dll.'
         exit(0)
else:
    raise Exception('Unsupported system.')

try:
    DebugCreate = dbgeng.DebugCreate
except:
    print 'Can not locate DebugCreate() function from dbgeng.dll.'
    exit(0)


logger = logging.getLogger('pydbgx')
formatter = logging.Formatter('%(message)s')

LogLevel = logging.WARNING
if 2 == len(sys.argv):
    if 'debug' == sys.argv[1]:
        LogLevel = logging.DEBUG
        fh = logging.FileHandler('debug.log')
        fh.setLevel(LogLevel)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    elif 'info' == sys.argv[1]:
        LogLevel = logging.INFO

logger.setLevel(LogLevel)

ch = logging.StreamHandler()
ch.setLevel(LogLevel)

ch.setFormatter(formatter)
logger.addHandler(ch)


########################################
DEBUG_ONLY_THIS_PROCESS = 0x00000002
DEBUG_CREATE_PROCESS_NO_DEBUG_HEAP = 0x00000400
E_FAIL = 0x80004005
E_PENDING = 0x8000000A
E_UNEXPECTED = 0x8000FFFF
INFINITE = 0xFFFFFFFF
########################################


class DebugEventCallbacks(CoClass):
    """event callback class"""
    
    _reg_clsid_ = GUID('{276EFA76-BAF4-4603-A328-A0A1D3C37BFF}')
    _reg_threading_ = 'Both'
    _reg_progid_ = 'DbgEngLib.DebugEventCallbacks.1'
    _reg_novers_progid_ = 'DbgEngLib.DebugEventCallbacks'
    _reg_desc_ = 'An implementation of IDebugEventCallbacks'
    _reg_clsctx_ = comtypes.CLSCTX_INPROC_SERVER
    
    _com_interfaces_ = [DbgEng.IDebugEventCallbacks]
    
    def __init__(self, mask=0):
        super(DebugEventCallbacks, self).__init__()
        self.__mask = mask

    def GetInterestMask(self):
        logger.debug('[*] GetInterestMask Callback')
        logger.debug('[D] Mask: ' + str(self.__mask))
        return self.__mask
    
    def Breakpoint(self, Bp):
        logger.debug('[*] Breakpoint Callback')
        return DbgEng.DEBUG_STATUS_NO_CHANGE

    def Exception(self, Exception, FirstChance):
        logger.debug('[*] Exception Callback')
        return DbgEng.DEBUG_STATUS_BREAK

    def CreateThread(self, Handle, DataOffset, StartOffset):
        logger.debug('[*] CreateThread Callback')
        return DbgEng.DEBUG_STATUS_NO_CHANGE

    def ExitThread(self, ExitCode):
        logger.debug('[*] ExitThread Callback')
        logger.debug('[D] ExitCode: ' + str(ExitCode))
        return DbgEng.DEBUG_STATUS_NO_CHANGE

    def CreateProcess(self, ImageFileHandle, Handle, BaseOffset, ModuleSize,
                      ModuleName, ImageName, CheckSum, TimeDateStamp,
                      InitialThreadHandle, ThreadDataOffset, StartOffset):
        logger.debug('[*] CreateProcess Callback')
        logger.debug('[D] ImageFileHandle: ' + str(ImageFileHandle))
        logger.debug('[D] Handle: ' + str(Handle))
        logger.debug('[D] BaseOffset: ' + str(hex(BaseOffset)))
        logger.debug('[D] ModuleSize: ' + str(hex(ModuleSize)))
        logger.debug('[D] ModuleName: ' + ModuleName)
        logger.debug('[D] ImageName: ' + ImageName)
        logger.debug('[D] CheckSum: ' + str(hex(CheckSum)))
        logger.debug('[D] TimeDateStamp: ' + str(hex(TimeDateStamp)))
        logger.debug('[D] InitialThreadHandle: ' + str(hex(InitialThreadHandle)))
        logger.debug('[D] ThreadDataOffset: ' + str(hex(ThreadDataOffset)))
        logger.debug('[D] StartOffset: ' + str(hex(StartOffset)))
        return DbgEng.DEBUG_STATUS_BREAK

    def ExitProcess(self, ExitCode):
        logger.debug('[*] ExitProcess Callback')
        logger.debug('[D] ExitCode: ' + str(ExitCode))
        return DbgEng.DEBUG_STATUS_BREAK
        
    def LoadModule(self, ImageFileHandle, BaseOffset, ModuleSize, ModuleName, ImageName, CheckSum, TimeDateStamp):
        logger.debug('[*] LoadModule Callback')
        logger.debug('[D] ImageFileHandle: ' + str(ImageFileHandle))
        logger.debug('[D] BaseOffset: ' + str(hex(BaseOffset)))
        logger.debug('[D] ModuleSize: ' + str(hex(ModuleSize)))
        logger.debug('[D] ModuleName: ' + ModuleName)
        logger.debug('[D] ImageName: ' + ImageName)
        logger.debug('[D] CheckSum: ' + str(hex(CheckSum)))
        logger.debug('[D] TimeDateStamp: ' + str(hex(TimeDateStamp)))
        return DbgEng.DEBUG_STATUS_NO_CHANGE

    def UnloadModule(self, ImageBaseName, BaseOffset):
        logger.debug('[*] UnloadModule Callback')
        logger.debug('[D] ImageBaseName: ' + str(ImageBaseName))
        logger.debug('[D] BaseOffset: ' + str(hex(BaseOffset)))
        return DbgEng.DEBUG_STATUS_NO_CHANGE
    
    def SystemError(self, Error, Level):
        logger.debug('[*] SystemError Callbak')
        return DbgEng.DEBUG_STATUS_BREAK

    def SessionStatus(self, Status):
        logger.debug('[*] SessionStatus Callbak')
        logger.debug('[*] Status: ' + str(Status))
        return DbgEng.DEBUG_STATUS_NO_CHANGE

    def ChangeDebuggeeState(self, Flags, Argument):
        logger.debug('[*] ChangeDebuggeeState Callbak')
        logger.debug('[D] Flags: ' + str(Flags))
        logger.debug('[D] Argument: ' + str(Argument))
        return S_OK
    
    def ChangeEngineState(self, Flags, Argument):
        logger.debug('[*] ChangeEngineState Callback Callbak')
        logger.debug('[D] Flags: ' + str(Flags))
        logger.debug('[D] Argument: ' + str(Argument))
        return S_OK
    
    def ChangeSymbolState(self, Flags, Argument):
        logger.debug('[*] ChangeSymbolState Callback Callbak')
        logger.debug('[D] Flags: ' + str(Flags))
        logger.debug('[D] Argument: ' + str(Argument))
        return S_OK
    

class DebugOutputCallbacks(CoClass):
    """event callback class"""
    
    _reg_clsid_ = GUID('{72806FC2-B8D1-4970-9019-473A8C024659}')
    _reg_threading_ = 'Both'
    _reg_progid_ = 'DbgEngLib.DebugOutputCallbacks.1'
    _reg_novers_progid_ = 'DbgEngLib.DebugOutputCallbacks'
    _reg_desc_ = 'An implementation of IDebugOutputCallbacks'
    _reg_clsctx_ = comtypes.CLSCTX_INPROC_SERVER | comtypes.CLSCTX_LOCAL_SERVER
    
    _com_interfaces_ = [DbgEng.IDebugOutputCallbacks]

    def __init__(self):
        super(DebugOutputCallbacks, self).__init__()

    def Output(self, Mask, Text):
        logger.debug('[*] Output Callback')
        logger.debug('[I] Mask: ' + str(Mask))
        logger.debug('[I] Text:\r\n' + Text)
    
        
class PyDbgX:
    """debugger class"""

    def __init__(self, output=False):
        """initiate the debugger"""
        
        logger.info('[*] Initiate DebugClient')
        self.__debug_client = POINTER(DbgEng.IDebugClient)()
        hr = DebugCreate(byref(DbgEng.IDebugClient._iid_), byref(self.__debug_client))
        if S_OK != hr:
            raise Exception('DebugCreate() fail.')
        else:
            logger.info('[I] Initiate DebugClient Success')

        logger.debug('[D] Indentity: ' + self.get_indentity())
    
        logger.info('[*] Initiate DebugControl')
        self.__debug_control = self.__debug_client.QueryInterface(DbgEng.IDebugControl)
        if None == self.__debug_control:
            raise Exception('Query interface IDebugControl fail.')
        else:
            logger.info('[I] Initiate DebugControl Success')
        
        logger.info('[*] Set DebugEventCallbacks')
        mask = DbgEng.DEBUG_EVENT_BREAKPOINT | \
            DbgEng.DEBUG_EVENT_EXCEPTION | \
            DbgEng.DEBUG_EVENT_CREATE_THREAD | \
            DbgEng.DEBUG_EVENT_EXIT_THREAD | \
            DbgEng.DEBUG_EVENT_CREATE_PROCESS | \
            DbgEng.DEBUG_EVENT_EXIT_PROCESS | \
            DbgEng.DEBUG_EVENT_LOAD_MODULE | \
            DbgEng.DEBUG_EVENT_UNLOAD_MODULE | \
            DbgEng.DEBUG_EVENT_SYSTEM_ERROR | \
            DbgEng.DEBUG_EVENT_SESSION_STATUS
        '''
            DbgEng.DEBUG_EVENT_CHANGE_DEBUGGEE_STATE | \
            DbgEng.DEBUG_EVENT_CHANGE_ENGINE_STATE | \
            DbgEng.DEBUG_EVENT_CHANGE_SYMBOL_STATE
        '''
        event_callbacks = DebugEventCallbacks(mask)
        hr = self.__debug_client.SetEventCallbacks(event_callbacks)
        if S_OK != hr:
            raise Exception('SetEventCallbacks() fail.')
        else:
            logger.info('[I] Set DebugEventCallbacks Success')

        logger.debug('[D] EventCallbacks: ' + str(self.__debug_client.GetEventCallbacks()))

        if output:
            logger.info('[*] Set OutputCallbacks')
            output_callbacks = DebugOutputCallbacks()
            hr = self.__debug_client.SetOutputCallbacks(output_callbacks)
            if S_OK != hr:
                raise Exception('SetOutputCallbacks() fail.')
            else:
                logger.info('[I] Set OutputCallbacks Success')

            logger.debug('[D] OutputCallbacks: ' + str(self.__debug_client.GetOutputCallbacks()))
        
        
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

        logger.info('[*] Create Process')
        logger.info('[I] Command: ' + cmd)
        logger.info('[I] FollowChild: ' + str(follow_child))
        
        if follow_child:
            flags = DbgEng.DEBUG_PROCESS
        else:
            flags = DEBUG_ONLY_THIS_PROCESS

        flags |= DEBUG_CREATE_PROCESS_NO_DEBUG_HEAP      # Prevents the debug heap from being used in the new process.
        server = 0
        hr = self.__debug_client.CreateProcess(server, cmd, flags)
        if S_OK != hr:
            raise Exception('CreateProcess() fail.')
        else:
            logger.info('[I] Create Process Success')

        logger.debug('[D] Indentity: ' + self.get_indentity())

    def wait_for_event(self):
        """IDebugControl::WaitForEvent method"""

        logger.debug('[D] ExecStatus: ' + str(hex(self.__debug_control.GetExecutionStatus())))
        
        logger.info('[*] WaitForEvent')
        flags = DbgEng.DEBUG_WAIT_DEFAULT
        timeout = INFINITE
        while True:
            hr = self.__debug_control.WaitForEvent(flags, 1000)
            if S_OK == hr:
                logger.info('[I] WaitForEvent OK')
            elif S_FALSE == hr:
                logger.info('[I] WaitForEvent FALSE')
            elif E_FAIL == hr:
                raise Exception('WaitForEvent FAIL')
            elif E_PENDING == hr:
                logger.info('[I] WaitForEvent PENDING')
                break
            elif E_UNEXPECTED == hr:
                logger.info('[I] WaitForEvent UNEXPECTED')
                break
            else:
                raise Exception('WaitForEvent UNKNOWN')
            

    def get_last_event(self):
        """IDebugControl::GetLastEventInformation method"""

        logger.info('[*] Get Last Event')
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

        logger.info('[I] Type: ' + str(hex(event_type.value)))
        logger.info('[I] ProcessID: ' + str(hex(process_id.value)))
        logger.info('[I] ThreadID: ' + str(hex(thread_id.value)))
        if extra_information_used.value > 0:
            logger.info('[I] ExtraInformation: ' + extra_information.value)
        if description_used.value > 1:
            logger.info('[I] Description: ' + description.value)
        
        return event_type.value, process_id.value, thread_id.value
        

if __name__ == '__main__':

    dbgx = PyDbgX()
    #dbgx.list_running_process()
    dbgx.create_process('notepad.exe')
    dbgx.wait_for_event()
    dbgx.get_last_event()