#!/usr/bin/env python
"""
Python wrapper for Windows Debugger Engine API.
"""

import os
import sys
import string
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


CurrentDir = os.path.dirname(os.path.abspath(__file__))
DbgEngTlb = os.path.join(CurrentDir, 'helper', 'DbgEng.tlb')


try:
    from comtypes.gen import DbgEng
except ImportError:
    if os.path.isfile(DbgEngTlb):
        from comtypes.client import GetModule
        GetModule(DbgEngTlb)
        from comtypes.gen import DbgEng
    else:
        print 'Please use the tools in the helper folder to generate the DbgEng.tlb file.'
        exit(0)


logger = logging.getLogger('pydbgx')
LogLevel = logging.WARNING
logger.setLevel(LogLevel)


DEBUG_PROCESS = 0x00000001
DEBUG_ONLY_THIS_PROCESS = 0x00000002
DEBUG_CREATE_PROCESS_NO_DEBUG_HEAP = 0x00000400
E_FAIL = 0x80004005
E_PENDING = 0x8000000A
E_UNEXPECTED = 0x8000FFFF
INFINITE = 0xFFFFFFFF
IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_MACHINE_AMD64 = 0x8664
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_TARGETS_INVALID = 0x40000000
PAGE_TARGETS_NO_UPDATE = 0x40000000
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400


ExecutionOption = {
    DbgEng.DEBUG_FILTER_BREAK: 'DEBUG_FILTER_BREAK',
    DbgEng.DEBUG_FILTER_SECOND_CHANCE_BREAK: 'DEBUG_FILTER_SECOND_CHANCE_BREAK',
    DbgEng.DEBUG_FILTER_OUTPUT: 'DEBUG_FILTER_OUTPUT',
    DbgEng.DEBUG_FILTER_IGNORE: 'DEBUG_FILTER_OUTPUT'}

ContinueOption = {
    DbgEng.DEBUG_FILTER_GO_HANDLED: 'DEBUG_FILTER_GO_HANDLED',
    DbgEng.DEBUG_FILTER_GO_NOT_HANDLED: 'DEBUG_FILTER_GO_NOT_HANDLED'}


LibFolder = os.path.join(CurrentDir, 'lib', 'x86')
LibFolder64 = os.path.join(CurrentDir, 'lib', 'x64')
DbgHelpDLL = os.path.join(LibFolder, 'dbghelp.dll')
DbgEngDLL = os.path.join(LibFolder, 'dbgeng.dll')
DbgHelpDLL64 = os.path.join(LibFolder64, 'dbghelp.dll')
DbgEngDLL64 = os.path.join(LibFolder64, 'dbgeng.dll')


if platform.architecture()[0] == '32bit':
    if False == os.path.isfile(DbgHelpDLL) or False == os.path.isfile(DbgEngDLL):
        if False == os.path.isdir(LibFolder):
            os.makedirs(LibFolder)
        print 'Missing dbghelp.dll and dbgeng.dll, please copy them to the "' + LibFolder + '" folder.'
        exit(0)
    try:
        dbghelp = windll.LoadLibrary(DbgHelpDLL) 
        dbgeng = windll.LoadLibrary(DbgEngDLL)
    except:
        print 'Can not load 32bit dbghelp.dll and dbgeng.dll.'
        exit(0)
elif platform.architecture()[0] == '64bit':
    if False == os.path.isfile(DbgHelpDLL64) or False == os.path.isfile(DbgEngDLL64):
        if False == os.path.isdir(LibFolder64):
            os.makedirs(LibFolder64)
        print 'Missing dbghelp.dll and dbgeng.dll, please copy them to the "' + LibFolder64 + '" folder.'
        exit(0)
    try:
        dbghelp = windll.LoadLibrary(DbgHelpDLL64) 
        dbgeng = windll.LoadLibrary(DbgEngDLL64)
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


class DebugEventCallbacks(CoClass):
    """IDebugEventCallbacks Implementation"""
    
    _com_interfaces_ = [DbgEng.IDebugEventCallbacks]
    
    def __init__(self, mask=0):
        """DebugEventCallbacks initialization"""
        
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
    """IDebugOutputCallbacks Implementation"""
    
    _com_interfaces_ = [DbgEng.IDebugOutputCallbacks]

    def __init__(self):
        """DebugOutputCallbacks initialization"""

        super(DebugOutputCallbacks, self).__init__()

    def Output(self, Mask, Text):
        logger.debug('[*] Output Callback')
        logger.debug('[I] Mask: ' + str(Mask))
        logger.debug('[I] Text:\r\n' + Text)


class Registers:
    """IDebugRegisters Wrapper"""

    def __init__(self, debug_client):
        """Registers initialization"""
        
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
    """IDebugDataSpaces Wrapper"""

    def __init__(self, debug_client):
        """DataSpace initialization"""

        self.__debug_client = debug_client
        self.__data_space = debug_client.QueryInterface(DbgEng.IDebugDataSpaces)
        self.__data_space2 = debug_client.QueryInterface(DbgEng.IDebugDataSpaces2)
        
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

    def read_ascii_string(self, offset):
        """read ascii string"""

        out_str = ''

        while True:
            data = self.read_memory(offset, 1)
            if data == None:
                break
            if data == '\x00':
                break
            if data not in string.printable:
                break
            out_str += data
            offset += 1
            
        return out_str
        
    def write_memory(self, offset, data):
        """write virtual address"""

        buffer = create_string_buffer(data)
        buffer_size = len(data)
        bytes_written = c_ulong(0)
        hr = self.__data_space._IDebugDataSpaces__com_WriteVirtual(offset, buffer, buffer_size, byref(bytes_written))
        if S_OK != hr:
            raise Exception('WriteVirtual() fail.')
        
        return bytes_written.value

    def search(self, offset, length, pattern):
        """search virtual address"""

        pattern_size = len(pattern)
        granularity = 1
        return self.__data_space.SearchVirtual(offset, length, pattern, pattern_size, granularity)

    def query_virtual(self, offset):
        """query the page information"""

        return self.__data_space2.QueryVirtual(offset)

    def can_write(self, offset):
        """query if the page contains the specified address has write privilege"""

        mem_info = self.query_virtual(offset)
        protect = mem_info.AllocationProtect
        
        if (PAGE_EXECUTE_READWRITE & protect) or (PAGE_READWRITE & protect):
            return True
        
        return False

    def can_read(self, offset):
        """query if the page contains the specified address has read privilege"""

        mem_info = self.query_virtual(offset)
        protect = mem_info.AllocationProtect
        
        if (PAGE_NOACCESS & protect) or (PAGE_GUARD & protect):
            return False

        return True


class DebugClient:
    """IDebugClient Wrapper"""
    
    def __init__(self):
        """DebugClient initialization"""

        self.__debug_create()


    def __debug_create(self):
        """create IDebugClient"""
        
        self.__idebug_client = POINTER(DbgEng.IDebugClient)()
        hr = DebugCreate(byref(DbgEng.IDebugClient._iid_), byref(self.__idebug_client))
        if S_OK != hr:
            raise Exception('DebugCreate() fail.')
        else:
            logger.debug('[D] DebugClient: ' + str(self.__idebug_client))

    def query_interface(self, interface):
        """IDebugClient::QueryInterface method"""

        return self.__idebug_client.QueryInterface(interface)


    def get_indentity(self):
        """IDebugClient::GetIdentity method"""

        buffer_size = 0x100
        identity_size = c_ulong(0)
        hr = self.__idebug_client._IDebugClient__com_GetIdentity(None, buffer_size, byref(identity_size))
        if S_OK != hr:
            raise Exception('GetIdentity() fail.')

        buffer_size = identity_size.value + 1
        buffer = create_string_buffer(buffer_size)
        hr = self.__idebug_client._IDebugClient__com_GetIdentity(buffer, buffer_size, byref(identity_size))
        if S_OK != hr:
            raise Exception('GetIdentity() fail.')
        
        return buffer.value

    def set_event_callbacks(self, event_callbacks):
        """IDebugClient::SetEventCallbacks method"""

        hr = self.__idebug_client.SetEventCallbacks(event_callbacks)
        if S_OK != hr:
            raise Exception('SetEventCallbacks() fail.')

    def get_event_callbacks(self):
        """IDebugClient::GetEventCallbacks method"""

        return self.__idebug_client.GetEventCallbacks()

    def set_output_callbacks(self, output_callbacks):
        """IDebugClient::SetOutputCallbacks method"""

        hr = self.__idebug_client.SetOutputCallbacks(output_callbacks)
        if S_OK != hr:
            raise Exception('SetOutputCallbacks() fail.')

    def get_output_callbacks(self):
        """IDebugClient::GetOutputCallbacks method"""

        return self.__idebug_client.GetOutputCallbacks()

    def get_running_process_ids(self):
        """IDebugClient::GetRunningProcessSystemIds method"""

        server = 0
        count = 256
        ids = (c_ulong * count)()
        actual_count = c_ulong(0)
        hr = self.__idebug_client._IDebugClient__com_GetRunningProcessSystemIds(server, ids, count, byref(actual_count))
        if S_OK != hr:
            raise Exception('GetRunningProcessSystemIds() fail.')

        return ids, actual_count.value

    def get_running_process_desc(self, sysid):
        """IDebugClient::GetRunningProcessDescription method"""

        try:
            server = 0
            flags  = DbgEng.DEBUG_PROC_DESC_NO_PATHS
            exename_size = 0x100
            exename = create_string_buffer(exename_size)
            actual_exename_size = c_ulong(0)
            description_size = 0x100
            description = create_string_buffer(description_size)
            actual_description_size = c_ulong(0)
                
            hr = self.__idebug_client._IDebugClient__com_GetRunningProcessDescription(
                server, sysid, flags,
                exename, exename_size, byref(actual_exename_size),
                description, description_size, byref(actual_description_size))
                
            if S_OK != hr:
                if S_FALSE == hr:
                    exename_size = actual_exename_size.value + 1
                    exename = create_string_buffer(exename_size)
                    description_size = actual_description_size.value + 1
                    description = create_string_buffer(description_size)
                        
                    hr = self.__idebug_client._IDebugClient__com_GetRunningProcessDescription(
                        server, sysid, flags,
                        exename, exename_size, byref(actual_exename_size),
                        description, description_size, byref(actual_description_size))
                    if S_OK != hr:
                        raise Exception('GetRunningProcessDescription() fail.')
                else:
                    raise Exception('GetRunningProcessDescription() fail.')
                    
        except COMError, msg:
            print 'No enough privilege to retrieve process information.'

        return exename.value, description.value

    def create_process(self, cmd, flags):
        """IDebugClient::CreateProcess method"""

        server = 0
        hr = self.__idebug_client.CreateProcess(server, cmd, flags)
        if S_OK != hr:
            raise Exception('CreateProcess() fail.')

    def terminate_process(self):
        """IDebugClient::TerminateProcesses method"""

        hr = self.__idebug_client.TerminateProcesses()
        if S_OK != hr:
            raise Exception('TerminateProcesses() fail.')

    def get_exit_code(self):
        """IDebugClient::GetExitCode method"""

        return self.__idebug_client.GetExitCode()


class DebugControl:
    """IDebugControl Wrapper"""

    def __init__(self, debug_client):
        """DebugControl initialization"""

        self.__idebug_control = debug_client.query_interface(DbgEng.IDebugControl)
        logger.debug('[D] DebugControl: ' + str(self.__idebug_control))

    def wait_for_event(self, timeout):
        """IDebugControl::WaitForEvent method"""

        flags = DbgEng.DEBUG_WAIT_DEFAULT
        hr = self.__idebug_control.WaitForEvent(flags, timeout)
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

    def execute(self, cmd):
        """IDebugControl::Execute method"""

        hr = self.__idebug_control.Execute(DbgEng.DEBUG_OUTCTL_THIS_CLIENT, cmd, DbgEng.DEBUG_EXECUTE_ECHO)
        if S_OK != hr:
            raise Exception('Execute() fail.')

    def add_breakpoint(self, type, desired_id):
        """IDebugControl::AddBreakpoint method"""

        return self.__idebug_control.AddBreakpoint(type, desired_id)

    def remove_breakpoint(self, breakpoint):
        """IDebugControl::RemoveBreakpoint method"""

        hr = self.__idebug_control.RemoveBreakpoint(breakpoint)
        if S_OK != hr:
            raise Exception('RemoveBreakpoint() fail.')

    def get_execution_status(self):
        """IDebugControl::GetExecutionStatus method"""

        return self.__idebug_control.GetExecutionStatus()

    def set_effective_processor_type(self, type):
        """IDebugControl::SetEffectiveProcessorType method"""
        
        logger.debug('[D] SetEffectiveProcessorType: ' + hex(type))
        hr = self.__idebug_control.SetEffectiveProcessorType(type)
        if S_OK != hr:
            raise Exception('SetEffectiveProcessorType() fail.')

    def get_effective_processor_type(self):
        """IDebugControl::GetEffectiveProcessorType method"""
        
        return self.__idebug_control.GetEffectiveProcessorType()

    def get_last_event(self):
        """IDebugControl::GetLastEventInformation method"""

        logger.debug('[*] Get LastEvent')
        event_type = c_ulong(0)
        process_id = c_ulong(0)
        thread_id = c_ulong(0)
        extra_information_size = 0x1000
        extra_information = create_string_buffer(extra_information_size)
        extra_information_used = c_ulong(0)
        description_size = 0x1000
        description = create_string_buffer(description_size)
        description_used = c_ulong(0)
        
        hr = self.__idebug_control._IDebugControl__com_GetLastEventInformation(
            byref(event_type), byref(process_id), byref(thread_id),
            extra_information, extra_information_size, byref(extra_information_used),
            description, description_size, byref(description_used))
        
        if S_OK != hr:
            if S_FALSE == hr:
                extra_information_size = extra_information_used.value + 1
                extra_information = create_string_buffer(extra_information_size)
                description_size = description_used.value + 1
                description = create_string_buffer(description_size)
                
                hr = self.__idebug_control._IDebugControl__com_GetLastEventInformation(
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
        if extra_information_used.value > 1:
            logger.debug('[D] ExtraInformation: ' + extra_information.value)
        if description_used.value > 1:
            logger.debug('[D] Description: ' + description.value)
        
        return event_type.value, process_id.value, thread_id.value, extra_information.value, description.value

    def get_number_event_filters(self):
        """IDebugControl::GetNumberEventFilters method"""

        return self.__idebug_control.GetNumberEventFilters()

    def get_event_filter_text(self, index):
        """IDebugControl::GetEventFilterText method"""

        buffer_size = 0x100
        buffer = create_string_buffer(buffer_size)
        text_size = c_ulong(0)
        
        hr = self.__idebug_control._IDebugControl__com_GetEventFilterText(
            index, buffer, buffer_size, byref(text_size))

        if S_OK != hr:
            if S_FALSE == hr:
                buffer_size = text_size.value + 1
                buffer = create_string_buffer(buffer_size)
                hr = self.__idebug_control._IDebugControl__com_GetEventFilterText(
                    index, buffer, buffer_size, byref(text_size))
                if S_OK != hr:
                    raise Exception('GetEventFilterText() fail.')
            else:
                raise Exception('GetEventFilterText() fail.')

        return buffer.value

    def get_event_filter_command(self, index):
        """IDebugControl::GetEventFilterCommand method"""

        buffer_size = 0x100
        buffer = create_string_buffer(buffer_size)
        command_size = c_ulong(0)
        
        hr = self.__idebug_control._IDebugControl__com_GetEventFilterCommand(
            index, buffer, buffer_size, byref(command_size))
        
        if S_OK != hr:
            if S_FALSE == hr:
                buffer_size = command_size.value + 1
                buffer = create_string_buffer(buffer_size)
                hr = self.__idebug_control._IDebugControl__com_GetEventFilterCommand(
                    index, buffer, buffer_size, byref(command_size))
                if S_OK != hr:
                    raise Exception('GetEventFilterCommand() fail.')
            else:
                raise Exception('GetEventFilterCommand() fail.')

        return buffer.value

    def get_specific_filter_argument(self, index):
        """IDebugControl::GetSpecificFilterArgument method"""
        
        try:
            buffer_size = 0x100
            buffer = create_string_buffer(buffer_size)
            argument_size = c_ulong(0)
            hr = self.__idebug_control._IDebugControl__com_GetSpecificFilterArgument(
                index, buffer, buffer_size, byref(argument_size))
            if S_OK != hr:
                if S_FALSE == hr:
                    buffer_size = argument_size.value + 1
                    buffer = create_string_buffer(buffer_size)
                    hr = self.__idebug_control._IDebugControl__com_GetSpecificFilterArgument(
                        index, buffer, buffer_size, byref(argument_size))
                    if S_OK != hr:
                        raise Exception('GetEventFilterArgument() fail.')
                else:
                    raise Exception('GetEventFilterArgument() fail.')
                
        except COMError, msg:
            return None

        return buffer.value

    def get_specific_filter_parameters(self, index):
        """IDebugControl::GetSpecificFilterParameters method"""

        try:
            count = 1
            return self.__idebug_control.GetSpecificFilterParameters(index, count)
        except COMError, msg:
            return None

    def set_specific_filter_parameters(self, index, parameter):
        """IDebugControl::SetSpecificFilterParameters method"""

        count = 1
        hr = self.__idebug_control.SetSpecificFilterParameters(index, count, parameter)
        if S_OK != hr:
            raise Exception('SetSpecificFilterParameters() fail.')

    def get_exception_filter_parameters(self, index):
        """IDebugControl::GetExceptionFilterParameters method"""

        try:
            count = 1
            codes = None
            return self.__idebug_control.GetExceptionFilterParameters(count, codes, index)
        except COMError, msg:
            return None

    def set_exception_filter_parameters(self, parameter):
        """IDebugControl::SetExceptionFilterParameters method"""
    
        count = 1
        hr = self.__idebug_control.SetExceptionFilterParameters(count, parameter)
        if S_OK != hr:
            raise Exception('SetExceptionFilterParameters() fail.')

    def get_exception_filter_second_command(self, index):
        """IDebugControl::GetExceptionFilterSecondCommand method"""

        buffer_size = 0x100
        buffer = create_string_buffer(buffer_size)
        command_size = c_ulong(0)
        
        hr = self.__idebug_control._IDebugControl__com_GetExceptionFilterSecondCommand(
            index, buffer, buffer_size, byref(command_size))
        
        if S_OK != hr:
            if S_FALSE == hr:
                buffer_size = command_size.value + 1
                buffer = create_string_buffer(buffer_size)
                hr = self.__idebug_control._IDebugControl__com_GetExceptionFilterSecondCommand(
                    index, buffer, buffer_size, byref(command_size))
                if S_OK != hr:
                    raise Exception('GetExceptionFilterSecondCommand() fail.')
            else:
                raise Exception('GetExceptionFilterSecondCommand() fail.')

        return buffer.value


class DebugSystem:
    """IDebugSystemObjects Wrapper"""

    def __init__(self, debug_client):
        """DebugSystem initialization"""

        self.__idebug_system = debug_client.query_interface(DbgEng.IDebugSystemObjects)
        logger.debug('[D] DebugSystemObjects: ' + str(self.__idebug_system))

    def get_number_process(self):
        """IDebugSystemObjects::GetNumberProcesses method"""

        return self.__idebug_system.GetNumberProcesses()

    def get_current_pid(self):
        """IDebugSystemObjects::GetCurrentProcessId method"""

        return self.__idebug_system.GetCurrentProcessId()

    def set_current_pid(self, pid):
        """IDebugSystemObjects::SetCurrentProcessId method"""

        hr = self.__idebug_system.SetCurrentProcessId(pid)
        if S_OK != hr:
            raise Exception('SetCurrentProcessId() fail.')

    def get_pid_by_index(self, index):
        """IDebugSystemObjects::GetProcessIdsByIndex method"""

        count = 1
        ids = (c_ulong * count)()
        hr = self.__idebug_system._IDebugSystemObjects__com_GetProcessIdsByIndex(index, count, ids, None)
        if S_OK != hr:
            raise Exception('GetProcessIdsByIndex() fail.')

        return ids[0]


class PyDbgX:
    """debugger class"""

    def __init__(self, event_cb=None, output_cb=None):
        """initialize the debugger"""
        
        logger.info('[*] Initialize DebugClient')
        self.__debug_client = DebugClient()
        logger.info('[I] Initialize DebugClient Success')
        
        logger.debug('[D] Indentity: ' + self.__debug_client.get_indentity())
        
        logger.info('[*] Initialize DebugControl')
        self.__debug_control = DebugControl(self.__debug_client)
        logger.info('[I] Initialize DebugControl Success')
        
        logger.info('[*] Initialize DebugSystemObjects')
        self.__debug_system = DebugSystem(self.__debug_client)
        logger.info('[I] Initialize DebugSystemObjects Success')
        
        logger.info('[*] Set DebugEventCallbacks')
        if event_cb is None:
            mask = DbgEng.DEBUG_EVENT_BREAKPOINT
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
        
        self.__debug_client.set_event_callbacks(event_cb)
        logger.info('[I] Set DebugEventCallbacks Success')
        
        logger.debug('[D] EventCallbacks: ' + str(self.__debug_client.get_event_callbacks()))
        
        if output_cb is not None:
            logger.info('[*] Set OutputCallbacks')
            
            if output_cb == 'default':
                output_callbacks = DebugOutputCallbacks()
            else:
                output_callbacks = output_cb

            self.__debug_client.set_output_callbacks(output_callbacks)
            logger.info('[I] Set OutputCallbacks Success')
            logger.debug('[D] OutputCallbacks: ' + str(self.__debug_client.get_output_callbacks()))

        self.__software_breakpoints = list()
    
    def list_running_process(self):
        """list running processes"""

        ids, actual_count = self.__debug_client.get_running_process_ids()

        print '*' * 30
        print 'Process Information'
        print '*' * 30
        
        for i in range(0, actual_count):
            
            print 'Process ID:', ids[i]

            exename, description = self.__debug_client.get_running_process_desc(ids[i])
            print 'Process Name:', exename
            if len(description) > 1:
                for desc in description.split('  '):
                    print desc
            
            print '-' * 30
    
    def create_process(self, cmd, follow_child=False, debug_heap=False):
        """create target process"""

        logger.info('[*] Create Process')
        logger.info('[I] Command: ' + cmd)
        logger.info('[I] FollowChild: ' + str(follow_child))
        
        if True == follow_child:
            flags = DEBUG_PROCESS
        else:
            flags = DEBUG_ONLY_THIS_PROCESS

        if False == debug_heap:
            flags |= DEBUG_CREATE_PROCESS_NO_DEBUG_HEAP      # Prevents the debug heap from being used in the new process.
        
        hr = self.__debug_client.create_process(cmd, flags)
        logger.info('[I] Create Process Success')

        logger.debug('[D] Indentity: ' + self.__debug_client.get_indentity())

    def set_effective_processor(self, processor_type):
        """set effective processor type"""

        if processor_type == 'x86':
            type = IMAGE_FILE_MACHINE_I386
        elif processor_type == 'x64':
            type = IMAGE_FILE_MACHINE_AMD64
        else:
            raise Exception('Unsupported type.')

        self.__debug_control.set_effective_processor_type(type)

    def active_process(self):
        """active process"""

        logger.debug('[*] Active Process')
        
        self.change_event_filter(
            'Initial breakpoint',
            DbgEng.DEBUG_FILTER_BREAK,
            DbgEng.DEBUG_FILTER_GO_HANDLED)
        
        self.__debug_control.wait_for_event(INFINITE)
        
        self.__debug_system.set_current_pid(0)
        
    def set_software_breakpoint_addr(self, address):
        """set software breakpoint"""

        logger.debug('[*] Add Breakpoint on Address: ' + str(hex(address)))
        software_breakpoint = self.__debug_control.add_breakpoint(DbgEng.DEBUG_BREAKPOINT_CODE, DbgEng.DEBUG_ANY_ID)
        logger.debug('[D] Breakpoint: ' + str(software_breakpoint))

        hr = software_breakpoint.SetOffset(address)
        if S_OK != hr:
            raise Exception('SetOffset() fail.')

        hr = software_breakpoint.AddFlags(DbgEng.DEBUG_BREAKPOINT_ENABLED)
        if S_OK != hr:
            raise Exception('AddFlags() fail.')

        self.__software_breakpoints.append(software_breakpoint)

        return software_breakpoint.GetId()
    
    def set_software_breakpoint_exp(self, expression):
        """set software breakpoint expression"""

        logger.debug('[*] Add Breakpoint Expression: ' + expression)
        software_breakpoint = self.__debug_control.add_breakpoint(DbgEng.DEBUG_BREAKPOINT_CODE, DbgEng.DEBUG_ANY_ID)
        logger.debug('[D] Breakpoint: ' + str(software_breakpoint))
        
        hr = software_breakpoint.SetOffsetExpression(expression)
        if S_OK != hr:
            raise Exception('SetOffsetExpression() fail.')

        hr = software_breakpoint.AddFlags(DbgEng.DEBUG_BREAKPOINT_ENABLED)
        if S_OK != hr:
            raise Exception('AddFlags() fail.')

        self.__software_breakpoints.append(software_breakpoint)

        return software_breakpoint.GetId()

    def remove_software_breakpoint_by_id(self, id):
        """remove software breakpoint by id"""

        for software_breakpoint in self.__software_breakpoints:
            if id == software_breakpoint.GetId():
                self.__debug_control.remove_breakpoint(software_breakpoint)
                logger.debug('[D] Remove Breakpoint #: ' + str(id))

    def list_event_filtes(self):
        """list event filtes"""

        print '*' * 30
        print 'Event Filtes'
        print '*' * 30

        specific_events, specific_exceptions, arbitrary_exceptions = self.__debug_control.get_number_event_filters()
        total = specific_events + specific_exceptions
        
        if total == 0:
            print 'No filters.'
            return

        for index in range(0, total):

            text = self.__debug_control.get_event_filter_text(index)
            if len(text) > 1:
                print 'Filter #' + str(index) + ': ' + text

            parameter = self.__debug_control.get_specific_filter_parameters(index)
            
            if parameter is not None:
                
                print 'ExecutionOption:', ExecutionOption[parameter.ExecutionOption]
                print 'ContinueOption:', ContinueOption[parameter.ContinueOption]
                
                if parameter.ArgumentSize > 1:
                    argument = self.__debug_control.get_specific_filter_argument(index)
                    print 'Argument:', argument
                    
                if parameter.CommandSize > 1:
                    command = self.__debug_control.get_event_filter_command(index)
                    print 'Command:', command
            else:
                parameter = self.__debug_control.get_exception_filter_parameters(index)
                if parameter is not None:
                    
                    print 'ExecutionOption:', ExecutionOption[parameter.ExecutionOption]
                    print 'ContinueOption:', ContinueOption[parameter.ContinueOption]
                    print 'ExceptionCode:', hex(parameter.ExceptionCode)
                        
                    if parameter.CommandSize > 1:
                        command = self.__debug_control.get_event_filter_command(index)
                        print 'Command:', command

                    if parameter.SecondCommandSize > 1:
                        command2 = self.__debug_control.get_exception_filter_second_command(index)
                        print 'SecondCommand:', command2
                        
            print '-' * 30

    def change_event_filter(self, name, execution_option, continue_option):
        """change event filter"""

        specific_events, specific_exceptions, arbitrary_exceptions = self.__debug_control.get_number_event_filters()
        total = specific_events + specific_exceptions
        
        if total == 0:
            raise Exception('No filters.')

        for index in range(0, total):

            text = self.__debug_control.get_event_filter_text(index)
            if text == name:
                
                parameter = self.__debug_control.get_specific_filter_parameters(index)  
                if parameter is not None:
                    parameter.ExecutionOption = execution_option
                    parameter.ContinueOption = continue_option
                    self.__debug_control.set_specific_filter_parameters(index, parameter)  
                    return True
                
                parameter = self.__debug_control.get_exception_filter_parameters(index)
                if parameter is not None: 
                    parameter.ExecutionOption = execution_option
                    parameter.ContinueOption = continue_option
                    self.__debug_control.set_exception_filter_parameters(parameter)
                    return True

                break
        
        return False

    def wait_for_event_ex(self):
        """debug loop"""

        logger.info('[*] WaitForEvent')
        logger.debug('[D] ExecStatus: ' + str(hex(self.__debug_control.get_execution_status())))
        logger.debug('[D] EffectiveProcessorType: ' + str(hex(self.__debug_control.get_effective_processor_type())))
        
        while True:
            try:
                self.__debug_control.wait_for_event(INFINITE)
            except COMError, msg:
                if -1 != str(msg).find('Catastrophic failure'):
                    logger.debug('[D] Process exit.')
                else:
                    print msg
                exit(0)

            self.__debug_control.get_last_event()
            logger.debug('[D] ExitCode: ' + str(self.__debug_client.get_exit_code()))

    def execute(self, cmd):
        """execute debug command"""

        logger.debug('[*] Execute: ' + cmd)
        self.__debug_control.execute(cmd)

    def terminate_process(self):
        """terminate process"""

        self.__debug_client.terminate_process()

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

    dbgx = PyDbgX()
    
    dbgx.list_running_process()
    
    dbgx.list_event_filtes()
    
    