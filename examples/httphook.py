#!/usr/bin/env python
"""
pydbgx example:
    Http API hook test.
"""

import os
import sys
import struct
import logging

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pydbgx import PyDbgX, DbgEng, DebugEventCallbacks, Registers, DataSpace

from ctypes import c_ulong
from ctypes import create_string_buffer, byref
from comtypes.hresult import S_OK, S_FALSE


class MyDebugEventCallbacks(DebugEventCallbacks):
    """DebugEventCallbacks"""

    def __init__(self, mask=0):
        """MyDebugEventCallbacks initialization"""

        super(DebugEventCallbacks, self).__init__()
        self.__mask = mask
        self.__pydbgx = None
        self.__bplist = dict()

    def bind_pydbgx(self, pydbgx):
        """bind pydbgx"""

        self.__pydbgx = pydbgx
        
    def GetInterestMask(self):
        """set interest mask"""

        logger.debug('[*] My GetInterestMask Callback')
        logger.debug('[D] mask: ' + str(hex(mask)))
        return self.__mask
    
    def Breakpoint(self, Bp):
        """Breakpoint callback"""

        logger.debug('[*] My Breakpoint Callback')
        try:
            self.__handle_breakpoint(Bp)
        except Exception as e:
            print e
        return DbgEng.DEBUG_STATUS_BREAK
    
    def __handle_breakpoint(self, Bp):
        """handle breakpoints"""

        Param = Bp.GetParameters()
        if Param.BreakType == DbgEng.DEBUG_BREAKPOINT_CODE:
            
            print 'Breakpoint:', hex(Param.Offset)
            
            buffer_size = Param.OffsetExpressionSize + 1
            buffer = create_string_buffer(buffer_size)
            expression_size = c_ulong(0)
            
            hr = Bp._IDebugBreakpoint__com_GetOffsetExpression(buffer, buffer_size, byref(expression_size))
            if S_OK != hr:
                raise Exception('GetOffsetExpression() fail.')
            
            if expression_size.value > 1:
                expression = buffer.value
                print 'Expression:', expression

                debug_client = Bp.GetAdder()
                r = Registers(debug_client)
                m = DataSpace(debug_client)
                esp = r.get_stack()
                logger.debug('[D] esp: ' + hex(esp))
                
                if -1 != expression.find('InternetOpenW'):
                    
                    data = m.read_memory(esp+0x04, 4)
                    param1 = struct.unpack('<I', data)[0]
                    logger.debug('[D] Parameter1: ' + hex(param1))
                    data = m.read_wide_string(param1)
                    print 'Agent:', data.decode('utf16')
                    
                    data = m.read_memory(esp+0x0C, 4)
                    param2 = struct.unpack('<I', data)[0]
                    logger.debug('[D] Parameter2: ' + hex(param2))
                    if 0 != param2:
                        data = m.read_wide_string(param2)
                        print 'ProxyName:', data.decode('utf16')
                        
                    data = m.read_memory(esp+0x10, 4)
                    param3 = struct.unpack('<I', data)[0]
                    logger.debug('[D] Parameter3: ' + hex(param3))
                    if 0 != param3:
                        data = m.read_wide_string(param3)
                        print 'ProxyBypass:', data.decode('utf16')

                if -1 != expression.find('InternetConnectW'):
                    
                    data = m.read_memory(esp+0x04, 4)
                    param1 = struct.unpack('<I', data)[0]
                    logger.debug('[D] Parameter1: ' + hex(param1))
                    print 'hInternet:', hex(param1)
                    
                    data = m.read_memory(esp+0x08, 4)
                    param2 = struct.unpack('<I', data)[0]
                    logger.debug('[D] Parameter2: ' + hex(param2))
                    if 0 != param2:
                        data = m.read_wide_string(param2)
                        print 'ServerName:', data.decode('utf16')
                        
                    data = m.read_memory(esp+0x0C, 4)
                    param3 = struct.unpack('<I', data)[0]
                    logger.debug('[D] Parameter3: ' + hex(param3))
                    print 'ServerPort:', param3

                    data = m.read_memory(esp+0x10, 4)
                    param4 = struct.unpack('<I', data)[0]
                    logger.debug('[D] Parameter4: ' + hex(param4))
                    if 0 != param4:
                        data = m.read_wide_string(param4)
                        print 'Username:', data.decode('utf16')

                    data = m.read_memory(esp+0x14, 4)
                    param5 = struct.unpack('<I', data)[0]
                    logger.debug('[D] Parameter5: ' + hex(param5))
                    if 0 != param5:
                        data = m.read_wide_string(param5)
                        print 'Password:', data.decode('utf16')
                        
                if -1 != expression.find('HttpOpenRequestW'):
                    
                    data = m.read_memory(esp+0x04, 4)
                    param1 = struct.unpack('<I', data)[0]
                    logger.debug('[D] Parameter1: ' + hex(param1))
                    print 'hConnect:', hex(param1)
                    
                    data = m.read_memory(esp+0x08, 4)
                    param2 = struct.unpack('<I', data)[0]
                    logger.debug('[D] Parameter2: ' + hex(param2))
                    if 0 != param2:
                        data = m.read_wide_string(param2)
                        print 'Verb:', data.decode('utf16')
                        
                    data = m.read_memory(esp+0x0C, 4)
                    param3 = struct.unpack('<I', data)[0]
                    logger.debug('[D] Parameter3: ' + hex(param3))
                    if 0 != param3:
                        data = m.read_wide_string(param3)
                        print 'ObjectName:', data.decode('utf16')
                    
                    data = m.read_memory(esp+0x10, 4)
                    param4 = struct.unpack('<I', data)[0]
                    logger.debug('[D] Parameter4: ' + hex(param4))
                    if 0 != param4:
                        data = m.read_wide_string(param4)
                        print 'Version:', data.decode('utf16')

                    data = m.read_memory(esp+0x14, 4)
                    param5 = struct.unpack('<I', data)[0]
                    logger.debug('[D] Parameter5: ' + hex(param5))
                    if 0 != param5:
                        data = m.read_wide_string(param5)
                        print 'Referer:', data.decode('utf16')

    def LoadModule(self, ImageFileHandle, BaseOffset, ModuleSize, ModuleName, ImageName, CheckSum, TimeDateStamp):
        """LoadModule callback"""

        logger.debug('[*] My LoadModule Callback')
        logger.debug('[D] Module Name: ' + ModuleName)
        try:
            if -1 != ModuleName.lower().find("wininet"):
                bpid = self.__pydbgx.set_software_breakpoint_exp(ModuleName + '!InternetOpenW')
                self.__bplist[bpid] = 'InternetOpenW'
                bpid = self.__pydbgx.set_software_breakpoint_exp(ModuleName + '!InternetConnectW')
                self.__bplist[bpid] = 'InternetConnectW'
                bpid = self.__pydbgx.set_software_breakpoint_exp(ModuleName + '!HttpOpenRequestW')
                self.__bplist[bpid] = 'HttpOpenRequestW'
        except Exception as e:
            print e
        return DbgEng.DEBUG_STATUS_NO_CHANGE


if __name__ == '__main__':
    """Main function"""

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
    
    # register our own event callbacks
    mask = DbgEng.DEBUG_EVENT_BREAKPOINT | DbgEng.DEBUG_EVENT_LOAD_MODULE
    event_callback = MyDebugEventCallbacks(mask)

    # initialize the debugger
    dbgx = PyDbgX(event_cb=event_callback)

    # bind PyDbgX instance to the event callbakcs
    event_callback.bind_pydbgx(dbgx)

    # create target process: iexplore.exe
    # note: can not debug x64 executable with 32 bit python
    dbgx.create_process('c:\\Program Files (x86)\\Internet Explorer\\iexplore.exe', True)

    # active the process
    dbgx.active_process()

    # set the effective processor to x86 if the target is a x86 application
    dbgx.set_effective_processor('x86')
    
    # wait for debug event
    dbgx.wait_for_event_ex()

