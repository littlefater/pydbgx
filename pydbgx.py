#!/usr/bin/env python
"""
Python wrapper for Windows Debugger Engine API.
"""

import os
import sys
import struct
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
LogLevel = logging.WARNING
logger.setLevel(LogLevel)


########################################
DEBUG_PROCESS = 0x00000001
DEBUG_ONLY_THIS_PROCESS = 0x00000002
DEBUG_CREATE_PROCESS_NO_DEBUG_HEAP = 0x00000400
E_FAIL = 0x80004005
E_PENDING = 0x8000000A
E_UNEXPECTED = 0x8000FFFF
INFINITE = 0xFFFFFFFF
########################################


class DebugEventCallbacks(CoClass):
    """event callback class"""
    
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
        return DbgEng.DEBUG_STATUS_BREAK

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
    
    _com_interfaces_ = [DbgEng.IDebugOutputCallbacks]

    def __init__(self):
        super(DebugOutputCallbacks, self).__init__()

    def Output(self, Mask, Text):
        logger.debug('[*] Output Callback')
        logger.debug('[I] Mask: ' + str(Mask))
        logger.debug('[I] Text:\r\n' + Text)


class Registers:
    """registers class"""

    def __init__(self, debug_client):
        """initiate registers class"""
        
        self.__debug_client = debug_client
        self.__registers = debug_client.QueryInterface(DbgEng.IDebugRegisters)
        self.__number_registers = self.__registers.GetNumberRegisters()
        self.__regs = dict()
        self.__regs_index = dict()
        self.__update_regs()    

    def read(self, name):
        """read register value"""
        
        if self.__regs.has_key(name):
            return self.__regs[name]
        else:
            raise Execption('Invalid register name.')

    def set(self, name, value):
        """set register value"""
        
        if self.__regs.has_key(name):
            index = self.__regs_index[name]
            self.__set_reg_value_by_index(index, value)
            self.__update_regs()
        else:
            raise Execption('Invalid register name.')

    def get_frame(self):
        """IDebugRegisters::GetFrameOffset method"""

        return self.__registers.GetFrameOffset()

    def get_stack(self):
        """IDebugRegisters::GetStackOffset method"""

        return self.__registers.GetStackOffset()
            
    def __update_regs(self):
        """read all register values"""
        
        for i in range(0, self.__number_registers):
            reg_name = self.__get_reg_name_by_index(i)
            reg_value = self.__get_reg_value_by_index(i)
            self.__regs[reg_name] = reg_value
            self.__regs_index[reg_name] = i

    def __get_reg_name_by_index(self, index):
        """retrieve register name by index"""
        
        name_buffer_size = 0x100
        name_buffer = create_string_buffer(name_buffer_size)
        name_size = c_ulong(0)
        desc = POINTER(DbgEng._DEBUG_REGISTER_DESCRIPTION)()
        hr = self.__registers._IDebugRegisters__com_GetDescription(
            index, name_buffer, name_buffer_size, byref(name_size), desc)
        if S_OK != hr:
            if S_FALSE == hr:
                name_buffer_size = name_size.value + 1
                name_buffer = create_string_buffer(name_buffer_size)
                
                hr = self.__registers._IDebugRegisters__com_GetDescription(
                    index, name_buffer, name_buffer_size, byref(name_size), desc)

                if S_OK != hr:
                    raise Exception('GetDescription() fail.')
            else:
                raise Exception('GetDescription() fail.')

        if name_size.value > 0:
            return name_buffer.value
        return None

    def __get_reg_value_by_index(self, index):
        """retrieve register value by index"""
        
        debug_value = self.__registers.GetValue(index)
        union = debug_value.__getattribute__(debug_value._fields_[0][0])
        
        if debug_value.Type == DbgEng.DEBUG_VALUE_INT8:
            value = union.I8
        elif debug_value.Type == DbgEng.DEBUG_VALUE_INT16:
            value = union.I16
        elif debug_value.Type == DbgEng.DEBUG_VALUE_INT32:
            value = union.I32
        elif debug_value.Type == DbgEng.DEBUG_VALUE_INT64:
            value = union.__getattribute__(union._fields_[3][0]).I64
        elif debug_value.Type == DbgEng.DEBUG_VALUE_FLOAT32:
            value = union.F32
        elif debug_value.Type == DbgEng.DEBUG_VALUE_FLOAT64:
            value = union.F64
        elif debug_value.Type == DbgEng.DEBUG_VALUE_FLOAT80:
            value = union.F80Bytes
        elif debug_value.Type == DbgEng.DEBUG_VALUE_FLOAT128:
            value = union.F128Bytes
        else:
            value = 0
        
        return value

    def __set_reg_value_by_index(self, index, value):
        """set register value by index"""
        
        debug_value = self.__registers.GetValue(index)
        union = debug_value.__getattribute__(debug_value._fields_[0][0])
        
        if debug_value.Type == DbgEng.DEBUG_VALUE_INT8:
            union.I8 = value
        elif debug_value.Type == DbgEng.DEBUG_VALUE_INT16:
            union.I16 = value
        elif debug_value.Type == DbgEng.DEBUG_VALUE_INT32:
            union.I32 = value
        elif debug_value.Type == DbgEng.DEBUG_VALUE_INT64:
            union.__getattribute__(union._fields_[3][0]).I64 = value
        elif debug_value.Type == DbgEng.DEBUG_VALUE_FLOAT32:
            union.F32 = value
        elif debug_value.Type == DbgEng.DEBUG_VALUE_FLOAT64:
            union.F64 = value
        elif debug_value.Type == DbgEng.DEBUG_VALUE_FLOAT80:
            union.F80Bytes = value
        elif debug_value.Type == DbgEng.DEBUG_VALUE_FLOAT128:
            union.F128Bytes = value
        else:
            raise Exception('DEBUG_VALUE type not supportted.')
        
        print self.__registers.SetValue(index, debug_value)

        
class DataSpace:
    """data space class"""

    def __init__(self, debug_client):
        """initiate data space class"""

        self.__debug_client = debug_client
        self.__data_space = debug_client.QueryInterface(DbgEng.IDebugDataSpaces)
        
    def read_memory(self, offset, length):
        """read virtual address"""
        
        buffer = create_string_buffer(length+1)
        bytes_read = c_ulong(0)
        
        hr = self.__data_space._IDebugDataSpaces__com_ReadVirtual(offset, buffer, length, byref(bytes_read))
        if S_OK != hr:
            logger.warning('ReadVirtual() fail.')
            return None
        
        return buffer.raw[0:bytes_read.value]

    def read_wide_string(self, offset):
        """read wide string"""

        out_str = ''

        while True:
            data = self.read_memory(offset, 4)
            if data == None:
                break
            if data[1] != '\x00' or data[3] != '\x00':
                break
            if data[:2] == '\x00\x00':
                out_str += data[:2]
                break
            out_str += data
            if data[2:] == '\x00\x00':
                break
            offset += 4
            
        return out_str
        
    def write_memory(self, offset, buffer):
        """write virtual address"""
        pass

    def search(self):
        """search virtual address"""
        pass
    
        
class PyDbgX:
    """debugger class"""

    def __init__(self, event_cb=None, output=False):
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
        if self.__debug_control is None:
            raise Exception('Query interface IDebugControl fail.')
        else:
            logger.info('[I] Initiate DebugControl Success')
        
        logger.info('[*] Initiate DebugSystemObjects')
        self.__debug_system = self.__debug_client.QueryInterface(DbgEng.IDebugSystemObjects)
        if self.__debug_system is None:
            raise Exception('Query interface IDebugSystemObjects fail.')
        else:
            logger.info('[I] Initiate DebugSystemObjects Success')

        logger.info('[*] Set DebugEventCallbacks')
        if event_cb is None:
            mask = DbgEng.DEBUG_EVENT_CREATE_PROCESS | DbgEng.DEBUG_EVENT_BREAKPOINT
            '''
                DbgEng.DEBUG_EVENT_BREAKPOINT | \
                DbgEng.DEBUG_EVENT_EXCEPTION | \
                DbgEng.DEBUG_EVENT_CREATE_THREAD | \
                DbgEng.DEBUG_EVENT_EXIT_THREAD | \
                DbgEng.DEBUG_EVENT_CREATE_PROCESS | \
                DbgEng.DEBUG_EVENT_EXIT_PROCESS | \
                DbgEng.DEBUG_EVENT_LOAD_MODULE | \
                DbgEng.DEBUG_EVENT_UNLOAD_MODULE | \     
                DbgEng.DEBUG_EVENT_SYSTEM_ERROR | \
                DbgEng.DEBUG_EVENT_SESSION_STATUS | \
                DbgEng.DEBUG_EVENT_CHANGE_DEBUGGEE_STATE | \
                DbgEng.DEBUG_EVENT_CHANGE_ENGINE_STATE | \
                DbgEng.DEBUG_EVENT_CHANGE_SYMBOL_STATE
            '''
            event_callbacks = DebugEventCallbacks(mask)
        else:
            event_callbacks = event_cb
        
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

        self.__software_breakpoints = list()
        
        
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
            flags = DEBUG_PROCESS
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

    def active_process(self):
        flags = DbgEng.DEBUG_WAIT_DEFAULT
        timeout = 0
        hr = self.__debug_control.WaitForEvent(flags, timeout)
        if S_OK == hr:
            logger.debug('[D] WaitForEvent OK')
        elif S_FALSE == hr:
            logger.debug('[D] WaitForEvent FALSE')
        elif E_FAIL == hr:
            raise Exception('WaitForEvent FAIL')
        elif E_PENDING == hr:
            logger.debug('[D] WaitForEvent PENDING')
        elif E_UNEXPECTED == hr:
            raise Exception('WaitForEvent UNEXPECTED')
        else:
            raise Exception('WaitForEvent UNKNOWN')
        
        hr = self.__debug_control.Execute(DbgEng.DEBUG_OUTCTL_THIS_CLIENT, '|0s', DbgEng.DEBUG_EXECUTE_ECHO)
        if S_OK != hr:
            raise Exception('Execute() fail.')

    def set_software_breakpoint_addr(self, address):
        """set software breakpoint"""

        logger.debug('[D] Add breakpoint on address: ' + str(hex(address)))
        software_breakpoint = self.__debug_control.AddBreakpoint(DbgEng.DEBUG_BREAKPOINT_CODE, DbgEng.DEBUG_ANY_ID)
        if software_breakpoint is None:
            raise Exception('AddBreakpoint() fail.')

        hr = software_breakpoint.SetOffset(address)
        if S_OK != hr:
            raise Exception('SetOffset() fail.')

        hr = software_breakpoint.AddFlags(DbgEng.DEBUG_BREAKPOINT_ENABLED)
        if S_OK != hr:
            raise Exception('AddFlags() fail.')

        logger.debug('[D] Breakpoint: ' + str(software_breakpoint))

        self.__software_breakpoints.append(software_breakpoint)
    
    def set_software_breakpoint_exp(self, expression):
        """set software breakpoint expression"""

        logger.debug('[D] Add breakpoint expression: ' + expression)
        software_breakpoint = self.__debug_control.AddBreakpoint(DbgEng.DEBUG_BREAKPOINT_CODE, DbgEng.DEBUG_ANY_ID)
        if software_breakpoint is None:
            raise Exception('AddBreakpoint() fail.')

        hr = software_breakpoint.SetOffsetExpression(expression)
        if S_OK != hr:
            raise Exception('SetOffsetExpression() fail.')

        hr = software_breakpoint.AddFlags(DbgEng.DEBUG_BREAKPOINT_ENABLED)
        if S_OK != hr:
            raise Exception('AddFlags() fail.')

        logger.debug('[D] Breakpoint: ' + str(software_breakpoint))

        self.__software_breakpoints.append(software_breakpoint)

    def wait_for_event(self):
        """IDebugControl::WaitForEvent method"""

        logger.debug('[D] ExecStatus: ' + str(hex(self.__debug_control.GetExecutionStatus())))
        
        logger.info('[*] WaitForEvent')
        flags = DbgEng.DEBUG_WAIT_DEFAULT
        timeout = INFINITE
        while True:
            try:
                hr = self.__debug_control.WaitForEvent(flags, INFINITE)
            except COMError:
                print 'Unknown error.'
                exit(0)
            if S_OK == hr:
                logger.debug('[D] WaitForEvent OK')
            elif S_FALSE == hr:
                logger.debug('[D] WaitForEvent FALSE')
            elif E_FAIL == hr:
                raise Exception('WaitForEvent FAIL')
            elif E_PENDING == hr:
                logger.debug('[D] WaitForEvent PENDING')
                break
            elif E_UNEXPECTED == hr:
                logger.debug('[D] WaitForEvent UNEXPECTED')
                break
            else:
                raise Exception('WaitForEvent UNKNOWN')
            self.__debug_control.Execute(DbgEng.DEBUG_OUTCTL_THIS_CLIENT, '.lastevent', DbgEng.DEBUG_EXECUTE_ECHO)
            self.get_last_event()
            logger.debug('[D] ExitCode: ' + str(self.__debug_client.GetExitCode()))

    def list_event_filtes(self):
        """list event filtes"""

        specific_events, specific_exceptions, arbitrary_exceptions = self.__debug_control.GetNumberEventFilters()
        total = specific_events + specific_exceptions
        
        if total == 0:
            print 'No filters.'
            return

        for index in range(0, total):

            print 'Filter #' + str(index) + ':'

            buffer_size = 0x100
            buffer = create_string_buffer(buffer_size)
            text_size = c_ulong(0)
            hr = self.__debug_control._IDebugControl__com_GetEventFilterText(index,
                buffer,
                buffer_size,
                byref(text_size))
            if S_OK != hr:
                if S_FALSE == hr:
                    buffer_size = text_size.value + 1
                    buffer = create_string_buffer(buffer_size)
                    hr = self.__debug_control._IDebugControl__com_GetEventFilterText(index,
                        buffer,
                        buffer_size,
                        byref(text_size))
                    if S_OK != hr:
                        raise Exception('GetEventFilterText() fail.')
                else:
                    raise Exception('GetEventFilterText() fail.')
            if text_size.value > 1:
                print buffer.value
            
            buffer_size = 0x100
            buffer = create_string_buffer(buffer_size)
            command_size = c_ulong(0)
            hr = self.__debug_control._IDebugControl__com_GetEventFilterCommand(index,
                buffer,
                buffer_size,
                byref(command_size))
            if S_OK != hr:
                if S_FALSE == hr:
                    buffer_size = command_size.value + 1
                    buffer = create_string_buffer(buffer_size)
                    hr = self.__debug_control._IDebugControl__com_GetEventFilterCommand(index,
                        buffer,
                        buffer_size,
                        byref(command_size))
                    if S_OK != hr:
                        raise Exception('GetEventFilterCommand() fail.')
                else:
                    raise Exception('GetEventFilterCommand() fail.')
            if command_size.value > 1:
                print buffer.value

            try:
                buffer_size = 0x100
                buffer = create_string_buffer(buffer_size)
                argument_size = c_ulong(0)
                hr = self.__debug_control._IDebugControl__com_GetSpecificFilterArgument(index,
                    buffer,
                    buffer_size,
                    byref(argument_size))
                if S_OK != hr:
                    if S_FALSE == hr:
                        buffer_size = argument_size.value + 1
                        buffer = create_string_buffer(buffer_size)
                        hr = self.__debug_control._IDebugControl__com_GetSpecificFilterArgument(index,
                            buffer,
                            buffer_size,
                            byref(argument_size))
                        if S_OK != hr:
                            raise Exception('GetEventFilterArgument() fail.')
                    else:
                        raise Exception('GetEventFilterArgument() fail.')
                if argument_size.value > 1:
                    print buffer.value
            except COMError:
                pass

            print '-' * 30
    
    def get_last_event(self):
        """IDebugControl::GetLastEventInformation method"""

        logger.debug('[*] Get Last Event')
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

        logger.debug('[D] Type: ' + str(hex(event_type.value)))
        logger.debug('[D] ProcessID: ' + str(hex(process_id.value)))
        logger.debug('[D] ThreadID: ' + str(hex(thread_id.value)))
        if extra_information_used.value > 0:
            logger.debug('[D] ExtraInformation: ' + extra_information.value)
        if description_used.value > 1:
            logger.debug('[D] Description: ' + description.value)
        
        return event_type.value, process_id.value, thread_id.value
        

class MyclassDebugEventCallbacks(DebugEventCallbacks):

    def __init__(self, mask=0):
        super(DebugEventCallbacks, self).__init__()
        self.__mask = mask

    def GetInterestMask(self):
        logger.debug('[*] My GetInterestMask Callback')
        logger.debug('[D] Mask: ' + str(self.__mask))
        return self.__mask
    
    def Breakpoint(self, Bp):
        logger.debug('[*] My Breakpoint Callback')
        try:
            self.__handle_breakpoint(Bp)
        except Exception as e:
            print e
        return DbgEng.DEBUG_STATUS_BREAK
    
    def __handle_breakpoint(self, Bp):
        Param = Bp.GetParameters()
        if Param.BreakType == DbgEng.DEBUG_BREAKPOINT_CODE:
            
            print 'Breakpoint Hit Address:', hex(Param.Offset)
            
            buffer_size = Param.OffsetExpressionSize + 1
            buffer = create_string_buffer(buffer_size)
            expression_size = c_ulong(0)
            
            hr = Bp._IDebugBreakpoint__com_GetOffsetExpression(buffer, buffer_size, byref(expression_size))
            if S_OK != hr:
                raise Exception('GetOffsetExpression() fail.')
            
            if expression_size.value > 1:
                expression = buffer.value
                print 'Breakpoint Expression:', expression

                if -1 != expression.find('CreateFileW'):
                    debug_client = Bp.GetAdder()
                    r = Registers(debug_client)
                    esp = r.get_stack()
                    m = DataSpace(debug_client)
                    data = m.read_memory(esp+4, 4)
                    addr = struct.unpack('<I', data)[0]
                    data = m.read_wide_string(addr)
                    print 'File Created:', data.decode('utf16')


if __name__ == '__main__':

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

    mask = DbgEng.DEBUG_EVENT_BREAKPOINT
    event_callback = MyclassDebugEventCallbacks(mask)
    dbgx = PyDbgX(event_cb=event_callback)
    #dbgx = PyDbgX(output=True)
    #dbgx.list_running_process()
    dbgx.create_process('notepad.exe', True)
    dbgx.active_process()
    #dbgx.set_software_breakpoint_addr(0x01003689)
    dbgx.set_software_breakpoint_exp('kernel32!CreateFileW')
    dbgx.wait_for_event()