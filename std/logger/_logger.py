
from __future__ import print_function

import sys
import os
import re
import errno
import time
import traceback

from std.logger.const import *
from std.fault import Fault

LogFh = {}
LogBuffer = {}

StrLevels = {
             LOG_DEBUG:     "DEBUG"
            ,LOG_INFO:      "INFO"
            ,LOG_NOTICE:    "NOTICE"
            ,LOG_WARNING:   "WARNING"
            ,LOG_ERROR:     "ERROR"
            ,LOG_EXCEPTION: "EXCEPTION"
            ,LOG_ZERO:      "ZERO"
        }

reNewLine = re.compile('\n$')

def close_logs():
    log_fhs = LogFh.keys()
    for file in log_fhs:
        fh = LogFh[file]
        os.close(fh)
        del LogFh[file]
        try:
            del LogBuffer[file]
        except:
            pass

class Logger(object):

    def __init__(self, context):
        self.stub = LoggerStub()

        self.file = context.LOG.file()
        if self.file == None:
            raise Fault("No logfile name provided")
        
        log_file_dir = re.sub('\/[^\/]+$', '', self.file)
        try:
            os.stat(log_file_dir)
        except OSError as e:
            raise Fault("Logfile directory ["+log_file_dir+"] stat error: "+e.strerror, e.errno)

        self.level = context.LOG.level(LOG_NOTICE)
        self.debug = context.LOG.debug(DBG_NONE)
        self.show_pid = context.LOG.show_pid(False)
        self.hide_date = context.LOG.hide_date(False)
        self.hide_tag = context.LOG.hide_tag(False)

        if not self.hide_tag:
            self.tag = context.progname
        else:
            self.tag = "__undef__"
        
        self._open_log()


    def _open_log(self):
 
        try:
            return LogFh[self.file]
        except KeyError as e:
            pass
        
        level = LOG_DEBUG
        message = "Opened logfile "+self.file

        try:
            fh = os.open(self.file, os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NONBLOCK)
        except OSError as e:
            tb = traceback.extract_stack()
            (file, c_line, func, text) = tb[0]
            c_script = file.split("/")[-1]

            fh = sys.stderr.fileno()

            level = LOG_ERROR
            message = "["+c_script+"("+c_line+")]: Cannot open "+self.file+": "+e.strerror
        finally:
            LogFh[self.file] = fh
            LogBuffer[self.file] = "" 
            self(level, message)
            return fh

    def close_log(self):

        try:
            self(LOG_DEBUG, "Closing logfile "+self.file)
            fh = LogFh[self.file]
            os.close(fh)
            del LogFh[self.file]
        except KeyError as e:
            pass
        finally:
            del LogBuffer[self.file]

    def __call__(self, level='UNDEFINED', message="Message Missing", add_stacktrace=True):
       
        try:
            str_level = StrLevels[level]
        except KeyError as e:
            str_level = 'UNDEFINED'
       
        if level > self.level:
            return 0
       
        if \
            ((self.debug & DBG_STACK_ERR_WARN) \
                and ((level == LOG_WARNING) or (level == LOG_ERROR))) \
            or (level == LOG_EXCEPTION) \
            or (self.debug & DBG_STACK_ALL) \
            or (str_level == 'UNDEFINED') \
            :

            tb = traceback.extract_stack()
            tb.reverse()

            (file, c_line, func, text) = tb[1]
            most_recent = ' at {0:s} line {2:d}'.format(file, func, c_line)

            stack_trace = '\n'.join('\t{3:s} called at {0:s} line {2:d}'.\
                    format(file, func, c_line, text) for (file, c_line, func, text) in tb[2:])

            message += most_recent
            if stack_trace and add_stacktrace:
                message += ". Stack trace:\n"+stack_trace
        
        buf_list = [
            (not self.hide_date, time.ctime())
            ,(self.tag, "["+self.tag+"]")
            ,((self.debug & DBG_LOG_LEVEL), "["+str_level+"]")
            ,(self.show_pid, "["+str(os.getpid())+"]")
            ,(True, message)
        ]

        buf = " ".join(map(lambda x: x[1], filter(lambda x: x[0] and x[0] != "__undef__", buf_list)))
        
        if not reNewLine.search(buf):
            buf += "\n"

        fh = self._open_log()

        LogBuffer[self.file] += buf
        
        out_len = len(buf)
        out_count = 0
        while (out_count < out_len):
            try:
                out_count += os.write(fh, LogBuffer[self.file][out_count:])
            except OSError as e:
                if e.errno != errno.EINTR:
                    break
        LogBuffer[self.file] = LogBuffer[self.file][out_count:]


class LoggerStub(object):
    def __call__(self, level, message):
        print(message, file=sys.stderr)

