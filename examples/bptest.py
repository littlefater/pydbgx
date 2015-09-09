#!/usr/bin/env python
"""
pydbgx example:
    Breakpoint test.
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
    """event callbacks"""

    def __init__(self, mask=0):
        """initialize event callbacks"""

        super(DebugEventCallbacks, self).__init__()
        self.__mask = mask

    def GetInterestMask(self):
        """set interest mask"""

        return self.__mask
    
    def Breakpoint(self, Bp):
        """breakpoint callback"""

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

    # register out own event callbacks
    mask = DbgEng.DEBUG_EVENT_BREAKPOINT
    event_callback = MyDebugEventCallbacks(mask)

    # initialize the debugger
    dbgx = PyDbgX(event_cb=event_callback)

    # create target process: notepad.exe
    # the target should have same architecture as your python executable
    # do not debug x64 executable if you use 32 bit python!!!
    dbgx.create_process('notepad.exe', True)

    # active the process so that we can set breakpoints on it
    dbgx.active_process()

    # set a breakpoint on API CreateFileW
    dbgx.set_software_breakpoint_exp('kernel32!CreateFileW')

    # wait for debug event
    dbgx.wait_for_event()

