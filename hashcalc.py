#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# python version: 2.7.5 final, serial: 0

import argparse
import codecs
import fnmatch
import hashlib
# import inspect
import os
import re
import signal
import sys
import time
import traceback
import warnings
import zlib
try:
    import pyblake2
    IMPORT_PYBLAKE2 = True
except ImportError:
    IMPORT_PYBLAKE2 = False
try:
    import sha3
    IMPORT_SHA3 = True
except ImportError:
    IMPORT_SHA3 = False

from ctypes import c_uint
from tempfile import SpooledTemporaryFile as SplTmpFile


# exc should be the exception object
_EXC_ARG = lambda exc: ", ".join(str(s) for s in exc.args)
_EXC_MSG = lambda exc: "%s: %s" % (type(exc).__name__, _EXC_ARG(exc))

_REVR_SEQ = lambda seq: list(reversed(seq)) if isinstance(seq, list) \
                                            else (tuple(reversed(seq)) \
                                            if isinstance(seq, tuple) else seq)
"""
def extr_stack(frame):
    from types import FrameType
    if not isinstance(frame, FrameType):
        raise TypeError

    stack = traceback.extract_stack(frame, 1)[-1][:3]

    return _REVR_SEQ(stack)
# End of extr_stack
"""
# tb is a tuple like (filename, linenum, funcname), extract from traceback.
_TRBK_DICT = lambda tb, msg: dict(zip(('FILE', 'LINE', 'FUNC', 'MSG'), \
                                      tb + (msg,)))
"""
The following two functions could be used for debug purpose, like:
    print "%(FILE)s: %(FUNC)s(): %(LINE)s: DEBUG" % _EXTR_STK(sys._getframe())
    print "%(FILE)s: %(FUNC)s(): %(LINE)s: DEBUG" % _ISPT_INFO()
# frame should be the return value of sys._getframe()
_EXTR_STK = lambda frame: dict(zip(('FILE', 'LINE', 'FUNC'), \
                                   traceback.extract_stack(frame, 1)[-1][:3]))
_ISPT_INFO = lambda: dict(zip(('FILE', 'LINE', 'FUNC'), \
                              tuple(x for x in \
                              inspect.getframeinfo(inspect.stack()[1][0]))[:3]))
"""


class CustomError(Exception):
    pass
# End of CustomError


def cuserr(condition, *args):
    if not condition:
        raise CustomError(*args)
# End of chkcerr


class UsageHandler(object):
    """Handle usage message, msgid: 0~10 reserved."""

    USAGE_HEADER = 'usage: %(msg)s'
    SP = '\x20' * 4
    HR =  '-'
    USAGE_MSG = {
        1: '\n' + SP + 'Internal Error(%s)!',
        2: '\n' + SP + '%(msg)s',
        3: '\n' + SP + '%(FILE)s: %(FUNC)s(): %(LINE)d: %(MSG)s',
        11: '\n' + SP + 'Argument "%(varname)s" must be %(vartype)s type.',
        12: '\n' + SP + 'Invalid argument "%(varname)s": %(varval)s.',
        13: '\n' + SP + 'The value of "%(varname)s" must be between '\
            '%(start)s and %(end)s.',
        14: '\n' + SP + '"%(filepath)s" not exists or no privileges.',
        15: '\n' + SP + 'User canceled.',
        16: '\n' + SP + 'Invalid argument "%(varname)s": %(msg)s(%(varval)s).',
    }

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.USAGE_MSG = dict(self.USAGE_MSG)
    # End of __init__

    def __call__(self, msg_id=1, header=True, *args, **kwargs):
        try:
            message = self.USAGE_MSG[msg_id] % (kwargs or args)
        except StandardError:# as se:
            # kwargs doesn't match a variable in the message
            # at least get the core message out if something happened
            # exc_type, exc_obj, tb_obj = sys.exc_info()
            # tb_info = traceback.extract_tb(sys.exc_info()[-1])[-1][:3]
            # print self.USAGE_MSG[3] % _TRBK_DICT(tb_info, _EXC_MSG(se))
            message = self.USAGE_MSG[1] % (type(self).__name__)

        if header is True:
            return self.USAGE_HEADER % {'msg': message}
        else:
            return message
    # End of __call__
# End of UsageHandler


class MainUsageHandler(UsageHandler):
    """MainUsageHandler"""

    def __init__(self, *args, **kwargs):
        super(MainUsageHandler, self).__init__(*args, **kwargs)
        SP = self.SP
        messages = {
            101: '%(prog)s - 1.5.0 (Python 2.7.5 final) '\
                 'by Leonard Wei(gooxxgle.mail@gmail.com), 10 OCT 2014.',
            102: 'The path of the file that contains the hash '\
                 'info to verify or which the calculated hash info will '\
                 'be saved to. If ACTION is "v", this argument is a '\
                 '*MUST* argument. If ACTION is "c", this argument '\
                 'is optional and the hash result will be saved to the '\
                 'file specified instead of stdout. A line start with "*" '\
                 'is considered as comment.',
            103: 'If ACTION is "v", this argument is optional to '\
                 'specify the hash algorithm to use for verifying'\
                 '(default will use the extname to determine, '\
                 'described later). If ACTION is "c", this is a '\
                 '*MUST* argument to decide which hash algorithm '\
                 'will be used to calculate the hash. The '\
                 'valid arguments(the corresponding extension '\
                 'name) are "crc32"(*.sfv), "md5"(*.md5), "sha1"'\
                 '(*.sha1), "sha224"(*.sha224), "sha256"(*.sha256'\
                 '), "sha384"(*.sha384), "sha512"(*.sha512), "md4"(*.md4), '\
                 '"ed2k"(*.ed2k), "blake2b"(*.blake2b), '\
                 '"blake2s"(*.blake2s), "sha3_224"(*.sha3224), '\
                 '"sha3_256"(*.sha3256), "sha3_384"(*.sha3384), '\
                 '"sha3_512"(*.sha3512), "adler32"(*.sfva). This option '\
                 'could be used multiple times, but specify the same '\
                 'algorithm multiple times will only apply once.',
            104: 'The hash(es) of the file(s) needs to be calculated. '\
                 'This option could be used multiple times.',
            105: '\n' + SP + '.',
            106: 'If specified, return the hash code in uppercase. '\
                 'Only effective with ACTION "c".',
            107: 'If specified, calculate the hash of the given '\
                 'string(s) instead of file(s). This option could be '\
                 'used multiple times.',
            108: '"c" or "calculate" means calculate the hash of file(s)'\
                 ', "v" or "verify" means verify the hash of file(s).',
            109: '\n' + SP + 'When ACTION is "verify", the "-s", "-f", '\
                 '"-d" and "-S" options are not allowed.',
            110: '\n' + SP + 'When ACTION is "verify", the "-o" or "-l" '\
                 'option is required.',
            111: '\n' + SP + 'When ACTION is "calculate", the "-a" or "-X" '\
                 'option is required.',
            112: '\n' + SP + 'When ACTION is "calculate", at least one of '\
                 'the "-s", "-f", "-d" and "-S" options are required.',
            113: 'The hashes of the files under this directory will be '\
                 'calculated. This option could be used multiple times.',
            114: 'If specified, It will recursively searches all files '\
                 'under the directory and calculates the hashes. Only '\
                 'effective with the "-d" option. If the file is a symlink '\
                 'to a directory, it will be ignored.',
            115: 'Press Any Key to Continue...',
            116: 'The specified file must contain the path(s) of hash file. '\
                 'This is similar to "-o" option, but only available when '\
                 'ACTION is "v". Useful when the cli environment could not '\
                 'support unicode properly or batch verification. If both '\
                 '"-o" and "-l" are specified, it will first process the '\
                 'file specified by "-o", and then "-l". A line start with '\
                 '"*" is considered as a comment.',
            117: '\n' + SP + 'Option "-l" is only available with ACTION "v".',
            118: 'The encoding that would be used to decode the path or '\
                 'content of hash file or hash list, default will try to '\
                 'use the following encoding "utf-8", "utf-16", "ascii" and '\
                 '"cp950".',
            119: 'The specified file must contain the strings(start with '\
                 '"STRING="), paths of any files or directories. '\
                 'This is similar to a combination of the "-s", "-f" '\
                 'and "-d" option, but only available when ACTION is '\
                 '"c". Useful when the cli environment could not '\
                 'support unicode properly or for batch calculation.'\
                 ' If "-s", "-f" or "-d" are specified, it will also '\
                 'try to process them. A line start with "*" is '\
                 'considered as a comment. Note that if the list '\
                 'contains a line like "STRING=xxx" and a file/dir named '\
                 '"STRING=xxx" also exists, they will both be processed.',
            120: 'Save the output messages to the specified log file.',
            121: '\n' + SP + 'When action is "v" and only "-l" option is '\
                 'specified, the "-a" option is required(*allowed only once*'\
                 ', default algorithm if the extname is invalid).',
            122: 'Output to stdout, as well as any hash and/or log files.',
            123: 'When specified, just check the file existence and no '\
                 'hashes will be verified. Only effective with action "v".',
            124: 'Show all output result(default only show the "FAIL" and '\
                 '"Not Found"). Only effective with action "v".',
            125: 'If specified, extract the hash info from filenames '\
                 'instead of calculating. If option "-a" is also provided, '\
                 'only the first one would be used for the output format'\
                 '(default is crc32).',
            126: 'A regular expression pattern used for extraction. '\
                 'It must contain at least one group "(:P<hash>...)". '\
                 'Default pattern is "^.*(?:(?P<hlbk>\[)|(?P<hlpt>\())?'\
                 '(?:crc32[ _\-])?(?P<hash>[0-9A-Za-z]{8})(?(hlbk)\])'\
                 '(?(hlpt)\))(?:\[(?:[\w]{1,5})\])?'\
                 '\.[0-9A-Za-z]{2,4}$".',
            127: '\n' + SP + 'The module "%(module)s" must be installed '\
                 'before using the algorithm "%(algo)s".',
            128: 'This option provides a function which is "do the action '\
                 'on matched files". Accept a Unix shell-style wildcards '\
                 'to perform the file matching("*" matches everying. '\
                 '"?" matches any single character. "[seq]" matches any '\
                 'character in "seq". "[!seq]" matches any character not '\
                 'in "seq"). If the ACTION is "c", only effective with '\
                 'the "-d" and "-S"(if any directories specified) options. '\
                 'If the ACTION is "v", only verify those matched files.',
            129: 'This option is similar to the "-P" option, but accept a '\
                 'regular expression to perform the file matching. If the '\
                 '"-P" option is also given, this option takes precedence '\
                 'over it.',
            130: 'Alterative style for hash file. The file path of every '\
                 'line is the basename of the file, and the relative dir '\
                 'path will be put in the line above those lines which '\
                 'contain the path of files in the same directory.'\
                 'Only effective with ACTION "c". When ACTION is "v", '\
                 'the two styles are both acceptable but *DO NOT* mix '\
                 'them together in one hash file.',
            131: 'Put a directory header above the hash result of the '\
                 'files in the directory given by the option "-d". '\
                 'Only effective with ACTION "c".',
        }
        self.USAGE_MSG.update(messages)
    # End of __init__
# End of MainUsageHandler


class ProgressUsageHandler(UsageHandler):
    """ProgressUsageHandler"""

    def __init__(self, *args, **kwargs):
        super(ProgressUsageHandler, self).__init__(*args, **kwargs)
        SP = self.SP
        messages = {
            301: '\n' + SP + 'bar_style must be a list containing 5 single '\
                 'symbol.',
        }
        self.USAGE_MSG.update(messages)
    # End of __init__
# End of ProgressUsageHandler


class HashUsageHandler(UsageHandler):
    """HashUsageHandler"""

    def __init__(self, *args, **kwargs):
        super(HashUsageHandler, self).__init__(*args, **kwargs)
        SP = self.SP
        HR = self.HR * 15
        TITLE = 'Hash Calculator'
        HR_TITLE = HR * 2 + self.HR * len(TITLE)
        DEBUG = '\n' + HR + 'DEBUG' + HR + '\n'
        messages = {
            201: '\n' + SP + 'Invalid extension name of hash file: '\
                 '"%(extname)s".',
            202: '\n' + SP + 'When action is "v", the "src_strings", '\
                 '"src_files", "src_dirs and "src_list" are not allowed.',
            203: '\n' + SP + 'When action is "v", the "hash_path" or '\
                 '"hash_list" is required.',
            204: '\n' + SP + 'When action is "c", the "hash_algos" '\
                 'is required.',
            205: '\n' + SP + 'When action is "c", the "src_strings", '\
                 '"src_files", "src_dirs" or "src_list" are required.',
            206: '\n' + SP + 'The file specified in "%(varname)s" is a '\
                 'directory or the path is unable to write.',
            207: '\n' + SP + 'The file specified in "%(varname)s" already '\
                 'exists and could not get the write permission.',
            208: '\n' + SP + 'When action is "v" and only "hash_list" is '\
                 'specified, the "hash_algos" is required(*only one in the'\
                 'list*, default algorithm if the extname is invalid).',
            209: '"%(filepath)s" is not a directory.',
            210: '"%(filepath)s" is not found, not a file or unable to read.',
            211: 'UnicodeDecodeError: "%(string)r"',
            212: '\n' + SP + 'When action is "c", the "hash_list" '\
                 'is not allowed.',
            213: '\n' + SP + '"hash_algos" is invalid or specified more than '\
                 'once: %(varval)s.',
            214: '\n' + SP + 'The algorithm "%(algo)s" requires the module '\
                 '"%(module)s" to be installed and imported properly.',
            215: '\n' + SP + 'No files could be processed.',
            216: '%(exc)s: "%(filepath)s".',
            217: '"%(item)s" is neither a string, a file nor a directory.',
            230: HR + TITLE + HR,
            231: 'Start Date: %(stime)s\n\n' + HR_TITLE ,
            232: ('\n' + HR_TITLE + '\n%-4s: %s | %-9s: %s | %-5s: %s\n%-4s: '\
                 '%s | %-9s: %s\n%s: %s\n\n' + HR_TITLE )% \
                 ('OK', '%(ok)5d', 'Found', '%(found)5d', 'Total', \
                  '%(total)5d', 'FAIL', '%(fail)5d', 'Not Found', '%(nofnd)5d',
                  'Elapsed Time', '%(etime).1f seconds'),
            233: 'Output File: %(filepath)s',
            234: '%(result)s\t: %(filename)s',
            235: '"%(line)s" invalid format.',
            236: '"%(line)s" no matched hash.',
            251: '*WARNING* "%(filepath)s" already exists. Append, Overwrite '\
                 'or Quit(a/o/Q)? ',
            299: DEBUG + '%(msg)s' + DEBUG,
        }
        self.USAGE_MSG.update(messages)
    # End of __init__
# End of HashUsageHandler


class ProgressBar(object):
    """
    Print and update the progress bar on cli
    `prog_prec`:    If not specified, default is 0. 1 means the percentage
                    of progress would be 'nnn.n%', and 2 means 'nnn.nn%', ...
                    etc.
    `bar_len`:      Determine the total length of progress bar(this Argument
                    including the length of '[', ']' and percentage).
    `bar_style`:    A list to determine the style of progress bar. Default
                    ['[', '=', '>', '.', ']'] means '[==>.......]'.
    """

    _pb_usage = ProgressUsageHandler()
    _prog_prec = 0
    _prog_fmt = None
    _bar_len = 10
    _bar_style = ['[', '=', '>', '.', ']']
    output = False

    def __init__(self, prog_prec=None, bar_len=None, bar_style=None, \
                 output=False):
        if prog_prec:
            self._prog_prec = prog_prec
            cuserr(isinstance(self._prog_prec, int), self._pb_usage(11, \
                   varname='prog_prec', vartype='int'))
        prog_prec_len = 0 if self._prog_prec == 0 else 1 + self._prog_prec

        if bar_len:
            self._bar_len = bar_len - 7 - prog_prec_len
            cuserr(isinstance(self._bar_len, int), self._pb_usage(11, \
                   varname='bar_len', vartype='int'))

        if bar_style:
            self._bar_style = bar_style
            cuserr((isinstance(self._bar_style, list) and \
                   len(self._bar_style) == 5), self._pb_usage(301))
            for idx in range(5):
                if not isinstance(self._bar_style[idx], basestring):
                    self._bar_style[idx] = str(self._bar_style[idx])[0]
                self._bar_style[idx] = self._bar_style[idx][0]

        if isinstance(output, bool):
            self.output = output

        self._prog_fmt = '\r' + self._bar_style[0] + '%s' + \
                         self._bar_style[4] + ' %' + str(3 + prog_prec_len) \
                         + '.' + str(self._prog_prec) + 'f%%'
    # End of __init__

    def _print(self, obj):
        obj = obj if isinstance(obj, basestring) else str(obj)
        sys.stdout.write(obj)
        sys.stdout.flush()
    # End of _print

    def update(self, progress):
        cuserr(isinstance(progress, float), self._pb_usage(11, \
               varname='progress', vartype='float'))
        cuserr(not (progress < 0 or progress > 1), self._pb_usage(13, \
               varname='progress', start='0', end='1'))

        bar_ok = int(self._bar_len * progress)
        s = self._bar_style
        if bar_ok == 0 or bar_ok == self._bar_len:
            bar_gt = 0
        else:
            bar_ok -= 1
            bar_gt = 1
        prog_str = self._prog_fmt % (s[1] * bar_ok + s[2] * bar_gt + s[3] * \
                                     (self._bar_len - bar_ok - bar_gt), \
                                     progress * 100)
        if self.output:
            self._print(prog_str)
            if progress == 1:
                self._print('\r' + ' ' * len(prog_str) + '\r')
        else:
            return prog_str
    # End of update
# End of ProgressBar


class HashZlib(object):
    """Transform the hash function of zlib into hashlib-like class."""

    _hash_func = None
    _hash_code = None

    def __init__(self):
        if self._hash_func is None:
            self._hash_func = (lambda data, value=0: value)
            raise ValueError("_hash_func = None")
    # End of __init__

    def update(self, buf):
        self._hash_code = self._hash_func(buf, self._hash_code) \
                          if self._hash_code is not None \
                          else self._hash_func(buf)
    # End of update

    def hexdigest(self):
        return ("%.8x" % (c_uint(self._hash_code).value))
    # End of hexdigest
# End of HashZlib


class HashCRC32(HashZlib):
    """Transform the zlib.crc32 into hashlib-like class."""

    def __init__(self):
        self._hash_func = getattr(zlib, 'crc32')
        super(HashCRC32, self).__init__()
    # End of __init__
# End of HashCRC32


class HashAdler32(HashZlib):
    """Transform the zlib.adler32 into hashlib-like class."""

    def __init__(self):
        self._hash_func = getattr(zlib, 'adler32')
        super(HashAdler32, self).__init__()
    # End of __init__

    def concatenate(self, preChkSum, curChkSum, curBlkSize):
        """
        Concatenate the checksums calculated from two pieces of data in
        series into one.
        `preChkSum`:    checksum of previous(first) piece.
        `curChkSum`:    checksum of current(second) piece.
        `curBlkSize`:   block size of current(second) piece.
        """
        modnum = 65521
        calLowerBytes = lambda valChkSum: (c_uint(valChkSum - 1).value & 0xffff)

        if not (isinstance(preChkSum, (int, long)) \
                and isinstance(curChkSum, (int, long)) \
                and isinstance(curBlkSize, (int, long))):
            raise TypeError

        rstLowerBytes = (1 + calLowerBytes(preChkSum) + \
                         calLowerBytes(curChkSum)) % modnum
        rstUpperBytes = ((preChkSum >> 16) + (curChkSum >> 16) + \
                         calLowerBytes(preChkSum) * curBlkSize) % modnum

        return ((rstUpperBytes << 16) + rstLowerBytes)
    # End of concatenate

    def concatenate_list(self, lstChkSum, lstBlkSize):
        """
        Concatenate the checksums calculated from a series of data into one.
        """
        if not (isinstance(lstChkSum, (tuple, list)) \
                and isinstance(lstBlkSize, (tuple, list))):
            raise TypeError
        if len(lstChkSum) != len(lstBlkSize):
            raise ValueError

        rst = self.concatenate(lstChkSum[0], lstChkSum[1], lstBlkSize[1])
        for idx in range(2, len(lstChkSum)):
            rst = self.concatenate(rst, lstChkSum[idx], lstBlkSize[idx])

        return rst
    # End of concatenate_list
# End of HashAdler32


class eD2k(object):
    """eDonkey2000/eMule(md4 based)"""

    _hash_func_gen = None
    _hash_func = None
    _hash_code = None
    _chunk_size = 9728000
    _chunk_now = 0

    def __init__(self):
        self._hash_func_gen = getattr(hashlib, 'new')
        self._hash_func = self._hash_func_gen('md4')
        self._hash_code = []
    # End of __init__

    def update(self, buf):
        chunk_lack = 0
        buf_len = len(buf)
        buf_now = 0

        while (buf_now != buf_len):
            if (self._chunk_now + buf_len - buf_now) > self._chunk_size:
                chunk_lack = self._chunk_size - self._chunk_now
                self._hash_func.update(buf[buf_now:(buf_now + chunk_lack)])
                self._hash_code.append(self._hash_func.digest())
                self._chunk_now = 0
                self._hash_func = self._hash_func_gen('md4')
                buf_now += chunk_lack
            else:
                self._hash_func.update(buf[buf_now:])
                self._chunk_now += buf_len - buf_now
                buf_now = buf_len
                if self._chunk_now == self._chunk_size:
                    self._hash_code.append(self._hash_func.digest())
                    self._chunk_now = 0
                    self._hash_func = self._hash_func_gen('md4')
    # End of update

    def hexdigest(self):
        self._hash_code.append(self._hash_func.digest())

        if len(self._hash_code) > 1:
            final_md4 = self._hash_func_gen('md4')
            for code in self._hash_code:
                final_md4.update(code)

            return final_md4.hexdigest()

        return self._hash_func.hexdigest()
    # End of hexdigest
# End of eD2k


class HashCalculator(object):
    """
    My Hash Calculator
    `action`:       Argument "v" means verify, "c" means calculate.
    `src_strings`:  List of string(s).
    `src_files`:    List of file(s).
    `src_dirs`:     List of dir(s).
    `src_list`:     List of string(s), file(s) and dir(s).
    `recursive`:    If `src_dirs` is specified, it will process all files
                    under `src_dirs` recursively.
    `src_ptrn`:     The Unix shell-style wildcards pattern for the
                    file matching.
    `src_regex`:    The regex expression pattern for the file matching.
    `hash_algos`:   List of hash algorithm(s).
    `uppercase`:    Return uppercase hash code if True.
    `extract`:      Extract hash info from filename instead of calculating.
    `extr_ptrn`:    A regex pattern used for extraction. It must contain at
                    least one group "(?P<hash>...)"
    `altn_style`:   Alterative style for hash files. The difference between
                    this style and traditional one is that the file path of
                    every line is the basename of the file, not the relative
                    file path to the directory of the hash file. And the
                    relative dir path will be put in the line above those
                    lines which contain the path of files in the same
                    directory except those files in the same directory with
                    the hash file(they will all be on the top of the hash
                    file). The following is an example:
                        *** dir1/dir2/.../dirN ***
                        hash1 *file1
                        hash2 *file2
    `dir_header`:   Put a directory header above the hash result if True.
    `hash_path`:    Hash file path.
    `hash_list`:    Hash file list.
    `exist_only`:   Only check file existence when action is "v".
    `verbose`:      Show all output when action is "v", default only show
                    the "FAIL" and "Not Found".
    `encoding`:     Try to use the specified encoding to decode first.
    `hash_log`:     Save output messages to the specified file.
    `hash_buf_siz`: Hash buffer size when calculate. Default is 2MB
                    if the filesize less than 1GB, otherwise it is 4MB.
    `tee`:          If hash_path and/or hash_log are specified, it also output
                    to stdout.

    Note:
        1.On win32 platform, a dir/file name can not start/end with spaces,
        but on linux platform, this is acceptable. So I assumed that the
        names which the users inputted are exactly what they want, and
        display the error message while the dir/file could not be found
        rather than strip the spaces automatically.
    """

    _hash_usage = HashUsageHandler()
    _ptrn_file_ext = re.compile(r"^(?P<main>.+)(?P<sep>\.)(?P<ext>[^\n\.]+)$",
                                re.U)
    # While adding any new algorithms, the items in the following list need to
    # be modified:
    # _valid_hash_algos, _ext_map, _ptrn_hash_item, __init__(parsing the
    # `hash_algos`), _chk_algo_mod, _get_hash_obj
    _valid_hash_algos = ('crc32', 'md5', 'sha1', 'sha224', 'sha256', \
                         'sha384', 'sha512', 'md4', 'ed2k', 'blake2b', \
                         'blake2s', 'sha3_224', 'sha3_256', 'sha3_384', \
                         'sha3_512', 'adler32')
    _ext_map = dict(zip(('sfv', 'md5', 'sha1', 'sha224', 'sha256', \
                         'sha384', 'sha512', 'md4', 'ed2k', 'blake2b', \
                         'blake2s', 'sha3224', 'sha3256', 'sha3384', \
                         'sha3512', 'sfva'), \
                        _valid_hash_algos))
    _ptrn_hash_alnum = r"<hash>[0-9A-Za-z]"
    _ptrn_file_str = r"(?P<file>\x20*(?P<file_ns>[^\s]+"\
                     r"(?:[^\t\v\r\n\f]+[^\s])?)\x20*)"
    _ptrn_sep_str = r"\t+|\x20+"
    _ptrn_crc32_str = r"^%s(?:%s)\*?(?P%s{8})(?:\s*)$" \
                      % (_ptrn_file_str, _ptrn_sep_str, _ptrn_hash_alnum)
    _ptrn_hash_str = r"^(?P%s{%s})(?:%s)\*?%s(?:\s*)$" \
                     % (_ptrn_hash_alnum, "%s", _ptrn_sep_str, _ptrn_file_str)
    _ptrn_crc32 = re.compile(_ptrn_crc32_str, re.U)
    _ptrn_hash_8 = re.compile(_ptrn_hash_str % ("8"), re.U)
    _ptrn_hash_32 = re.compile(_ptrn_hash_str % ("32"), re.U)
    _ptrn_hash_40 = re.compile(_ptrn_hash_str % ("40"), re.U)
    _ptrn_hash_56 = re.compile(_ptrn_hash_str % ("56"), re.U)
    _ptrn_hash_64 = re.compile(_ptrn_hash_str % ("64"), re.U)
    _ptrn_hash_96 = re.compile(_ptrn_hash_str % ("96"), re.U)
    _ptrn_hash_128 = re.compile(_ptrn_hash_str % ("128"), re.U)
    _ptrn_hash_item = dict(zip(_valid_hash_algos, \
            (_ptrn_crc32, _ptrn_hash_32, _ptrn_hash_40, _ptrn_hash_56, \
             _ptrn_hash_64, _ptrn_hash_96, _ptrn_hash_128, _ptrn_hash_32, \
             _ptrn_hash_32, _ptrn_hash_128, _ptrn_hash_64, _ptrn_hash_56, \
             _ptrn_hash_64, _ptrn_hash_96, _ptrn_hash_128, _ptrn_hash_8)))
    _ptrn_file_line = re.compile(r"^%s$" % (_ptrn_file_str), re.U)
    _ptrn_str_line = re.compile(r"^STRING=(?P<string>[^\r\n]+)(?:[\r\n]*)$", \
                                re.U)
    _ptrn_empty_line = re.compile(r"^[\r\n]*$", re.U)
    _ptrn_err_line = re.compile(r"^[^\r\n]*", re.U)
    _ptrn_extr_chk = re.compile(r"\(\?P<hash>.*?\)")
    _ptrn_alt_sty_dir = re.compile(r"\*\*\*\x20(?P<dir>[^\t\v\r\n\f]+)\x20"\
                                   r"\*\*\*", re.U)
    _src_filter = None
    _def_enc = 'utf8'
    _encodings = ['utf8', 'utf16', 'ascii', 'cp950',]
    _fmt_hash_header = '*%(nl)s* %(header)s%(nl)s*%(nl)s'
    _fmt_alt_sty_hdr = '*** %(dir)s ***%(nl)s'
    _fmt_hash_rst_def = '%(hash)s *%(item)s%(nl)s'
    _fmt_hash_rst_crc32 = '%(item)s\t*%(hash)s%(nl)s'
    _fmt_hash_rst_str = '*"%(item)s"\t%(hash)s%(nl)s'
    # Use '\n' instead of os.linesep for better system compatible
    _newline = '\n'
    _log_flag = False
    _log_tmpfp = None
    _log_mode = 'a'
    _save_flag = False
    _save_mode = 'a'
    action = None
    src_strings = []
    src_files = []
    src_dirs = []
    src_ptrn = None
    recursive = False
    hash_algos = []
    uppercase = False
    hash_path = None
    hash_dir = None
    hash_list = None
    exist_only = False
    extract = False
    extr_ptrn = re.compile((r"^.*%(hlbp)s%(prefix)s%(hash)s%(hrbp)s"\
                            "%(suffix)s%(ext)s$" \
                            % {"hlbp": r"(?:(?P<hlbk>\[)|(?P<hlpt>\())?", \
                               "prefix": r"(?:crc32[\x20_\-])?", \
                               "hash": r"(?P<hash>[0-9A-Za-z]{8})", \
                               "hrbp": r"(?(hlbk)\])(?(hlpt)\))", \
                               "suffix": r"(?:\[(?:[\w]{1,5})\])?", \
                               "ext": r"\.[0-9A-Za-z]{2,4}"}), re.U)
    altn_style = False
    dir_header = False
    verbose = False
    vfy_files = []
    proc_ok = 0
    proc_fail = 0
    proc_found = 0
    proc_nofnd = 0
    hash_log = None
    hash_buf_siz = (2 << 20)
    # length of '[==========] 100%'
    prog_bar_len = 17
    line_limit = (77 - prog_bar_len)
    tee = False
    total_item = 0

    def _print(self, obj, fp=None, end='\n', ntee=False):
        """Determine the output to stdout or file"""
        obj = obj if isinstance(obj, basestring) else str(obj)
        end = end if isinstance(end, basestring) else '\n'
        ntee = ntee if isinstance(ntee, bool) else False

        if isinstance(fp, (file, SplTmpFile)):
            fp.write(obj + end)

        # if `ntee` is True, ignore the tee flag.
        if fp is None or (self.tee is True and ntee is False):
            sys.stdout.write(obj + end)
            sys.stdout.flush()
    # End of _print

    def _get_file_extname(self, filename, default_ext='', sep='.'):
        """
        Return the extension name of the file
        `filename`: 'hash.md5' or '/dir/hash.md5'
        `sep`:      split separator, default '.'
        """
        filename = os.path.basename(filename) or ''
        extname = default_ext

        if sep == '.':
            pat_file_ext_loc = self._ptrn_file_ext
        else:
            esc_sep = '\\' + sep
            pat_file_ext_loc = re.compile(r"^(?P<main>.+)(?P<sep>" + \
                                          esc_sep + r")(?P<ext>[^\n" + \
                                          esc_sep + r"]+)$")
        chk_ext_rst = pat_file_ext_loc.search(filename)
        if chk_ext_rst:
            chk_ext_rst = chk_ext_rst.groupdict()
            extname = chk_ext_rst['ext']
            filename = chk_ext_rst['main']

        return (filename, sep, extname)
    # End of _get_file_extname

    def _get_file_path(self, fdir, fpath):
        """Return the absolute path and check if the path is readable."""
        if os.path.isabs(fpath) is False:
            joined_path = os.path.abspath(os.path.join(fdir, fpath))
            if os.access(joined_path, os.R_OK) is True:
                fpath = joined_path

        return fpath
    # End of _get_file_path

    def _to_str(self, string, errors='ignore'):
        """Encode by default encoding if unicode"""
        if isinstance(string, unicode):
            return string.encode(self._def_enc, errors)
        elif isinstance(string, str):
            return string
        else:
            return str(string)
    # End of _to_str

    def _to_unicode(self, src_obj):
        """Transform the items in the given list object to Unicode."""
        def _to_unicode_utf16(item):
            nulstr = '\x00'

            if item.startswith(nulstr):
                item = item[1:]
            if item.endswith(('\r', '\n')):
                item = item + nulstr
            try:
                item = unicode(item, 'utf16')
            except UnicodeError:
                return None

            return item
        # End of _to_unicode_utf16

        def _to_unicode_single(item, encodings=None):
            decode_ok = False

            for encoding in encodings:
                try:
                    if not isinstance(item, unicode):
                        if not isinstance(item, str):
                            item = str(item)
                        # Try to solve the decoding issue for utf16.
                        if encoding == 'utf16':
                            enc_rst = _to_unicode_utf16(item)
                            if enc_rst is not None:
                                item = enc_rst
                                decode_ok = True
                                break
                        item = unicode(item, encoding)
                    decode_ok = True
                    break
                except UnicodeError:
                    decode_ok = False
                    continue

            if decode_ok is False:
                self._print(self._hash_usage(211, string=item), \
                            self._log_tmpfp)
                item = unicode(item, self._def_enc, errors='ignore')

            return item
        # End of _to_unicode_single

        src_obj_u = None

        if isinstance(src_obj, (list, tuple)):
            src_obj_u = []
            for item in src_obj:
                src_obj_u.append(self._to_unicode(item))
        elif isinstance(src_obj, dict):
            src_obj_u_keys = self._to_unicode(src_obj.keys())
            src_obj_u_vals = self._to_unicode(src_obj.values())
            src_obj_u = dict(zip(src_obj_u_keys, src_obj_u_vals))
        else:
            src_obj_u = _to_unicode_single(src_obj, self._encodings)

        return src_obj_u
    # End of _to_unicode

    def _get_file_list(self, fdir, root=None):
        """Get the file list under given directory."""
        if fdir is not None:
            root_flag = False
            if root is None:
                root_flag = True
                root = fdir

            if not isinstance(fdir, unicode):
                fdir = self._to_unicode(fdir)

            if os.path.isabs(fdir) is False:
                fdir = os.path.abspath(fdir)

            flist = []
            flist_sub = []

            if os.path.isdir(fdir) is False:
                self._print(self._hash_usage(209, filepath=\
                            self._to_str(fdir)), self._log_tmpfp)
                return (None, []) if root_flag is True else flist

            try:
                flist_tmp = os.listdir(fdir)
            except OSError as oe:
                flist_tmp = []
                self._print(self._hash_usage(216, exc=_EXC_MSG(oe), filepath=\
                            self._to_str(fdir)), self._log_tmpfp)
                return (None, []) if root_flag is True else flist

            flist_tmp.sort()
            for fitem in flist_tmp:
                fsubpath = self._get_file_path(fdir, fitem)
                # Here will not follow the symbolic link(dir) if recursive
                if os.path.isdir(fsubpath):
                    if self.recursive and os.path.islink(fsubpath) is False:
                        flist_sub.extend(self._get_file_list(fsubpath, root))
                elif os.path.isfile(fsubpath):
                    if self._src_filter(fitem) is False:
                        continue
                    if root_flag is True:
                        flist.append(fitem)
                    else:
                        flist.append(os.path.join(os.path.relpath(fdir, root),
                                                  fitem))
            flist.extend(flist_sub)
            return (fdir, flist) if root_flag is True else flist

        return (None, [])
    # End of _get_file_list

    def _parse_src_dirs(self, src_dirs):
        """Parse the list of the dirs"""
        if isinstance(src_dirs, list):
            for item in src_dirs:
                cuserr(isinstance(item, basestring), self._hash_usage(12, \
                       varname='src_dirs', varval=self._to_str(src_dirs)))
                self.src_dirs.append(self._get_file_list(item))
        else:
            self.src_dirs.append((None, []))
    # End of _parse_src_dirs

    def _parse_src_list(self, src_list):
        """Parse the list of strings, files and dirs"""
        if isinstance(src_list, basestring):
            src_list = os.path.abspath(self._to_unicode(src_list))
            cuserr((os.path.isfile(src_list) and \
                    os.access(src_list, os.R_OK)), \
                   self._hash_usage(210, filepath=self._to_str(src_list)))

            src_list_loc = os.path.dirname(src_list)
            src_list_strings = []
            src_list_files = []
            src_list_dirs = []
            with open(src_list, 'r') as fp:
                for line in fp:
                    line = self._to_unicode(line)
                    if line.startswith(u'*') is False \
                       and self._ptrn_empty_line.search(line) is None:
                        src_string = self._ptrn_str_line.search(line)
                        src_item = self._ptrn_file_line.search(line)
                        if src_string is None and src_item is None:
                            raise CustomError(self._hash_usage(235, line=\
                                              self._to_str(line)))

                        # if a line both matches the file/dir and string, add
                        # the item to those lists.
                        if src_string:
                            src_string = src_string.groupdict()['string']
                            src_list_strings.append(src_string)

                        if src_item:
                            src_item = src_item.groupdict()['file']
                            src_item = self._get_file_path(src_list_loc, \
                                                           src_item)
                            if os.path.isfile(src_item):
                                src_list_files.append(src_item)
                            elif os.path.isdir(src_item):
                                src_list_dirs.append(src_item)
                            elif src_string is None:
                                self._print(self._hash_usage(217, item=\
                                            self._to_str(src_item)), \
                                            self._log_tmpfp)

            src_list_strings.sort()
            src_list_files.sort()
            src_list_dirs.sort()
            self.src_strings.append((None, src_list_strings))
            self.src_files.append((src_list_loc, src_list_files))
            self._parse_src_dirs(src_list_dirs)
    # End of _parse_src_list

    def _chk_algo_mod(self, hash_algo):
        """Check whether the additional module is imported or not"""
        if hash_algo.startswith('blake'):
            return True if IMPORT_PYBLAKE2 else 'pyblake2'
        elif hash_algo.startswith('sha3_'):
            return True if IMPORT_SHA3 else 'sha3'
        else:
            return True
    # End of _chk_algo_mod

    def __init__(self, action, src_strings=None, src_files=None, \
                 src_dirs=None, src_list=None, recursive=None, \
                 src_ptrn=None, src_regex=None, hash_algos=None, \
                 uppercase=None, extract=None, extr_ptrn=None, \
                 altn_style=None, dir_header=None, \
                 hash_path=None, hash_list=None, \
                 exist_only=None, verbose=None, encoding=None, \
                 hash_log=None, hash_buf_siz=None, tee=None):
        """Initialize and parse all arguments."""
        # Parsing `encoding`
        if encoding:
            try:
                codecs.lookup(encoding)
                self._encodings.insert(0, encoding)
            except LookupError as le:
                raise CustomError(self._hash_usage(2, msg=_EXC_ARG(le)))

        # Parsing `hash_log`. right after parsing `encoding` in order to log
        # as many messages as possible
        if hash_log:
            hash_log = os.path.abspath(self._to_unicode(hash_log))
            cuserr(((not os.path.isdir(hash_log)) and \
                    os.access(os.path.dirname(hash_log), os.W_OK)), \
                   self._hash_usage(206, varname='hash_log'))
            self.hash_log = hash_log

            if os.access(self.hash_log, os.F_OK):
                cuserr(os.access(self.hash_log, os.W_OK), \
                       self._hash_usage(207, varname='hash_log'))
                usr_in = ''
                while usr_in.lower() not in ('a', 'o'):
                    usr_in = raw_input(self._hash_usage(251, False, \
                                       filepath=self._to_str(self.hash_log)))
                    cuserr((usr_in != '' and usr_in.lower() != 'q'), \
                           self._hash_usage(15))
                self._log_mode = 'a' if usr_in == 'a' else 'w'
            self._log_tmpfp = SplTmpFile()
            self._log_flag = True

        # Parsing `tee`
        if tee:
            cuserr(isinstance(tee, bool), self._hash_usage(11, \
                   varname='tee', vartype='bool'))
            self.tee = tee

        # Parsing `src_ptrn` and `src_regex`
        if src_regex:
            try:
                src_regex = re.compile(self._to_unicode(src_regex), re.U)
            except re.error as ree:
                raise CustomError(self._hash_usage(16, varname=\
                                  'src_regex', msg=_EXC_ARG(ree), \
                                  varval=self._to_str(src_regex)))
            self.src_ptrn = src_regex
            self._src_filter = lambda fn: True if self.src_ptrn.search(fn) \
                                                  is not None else False
        elif src_ptrn:
            cuserr(isinstance(src_ptrn, basestring), self._hash_usage(11, \
                   varname='src_ptrn', vartype='basestring'))
            self.src_ptrn = self._to_unicode(src_ptrn)
            self._src_filter = lambda fn: fnmatch.fnmatch(fn, self.src_ptrn)
        else:
            self._src_filter = lambda fn: True

        # Parsing `action`
        cuserr((action in ('c', 'v')), self._hash_usage(12, \
               varname='action', varval=self._to_str(action)))
        self.action = action
        if self.action == 'c':
            # Parsing `src_strings` and `src_files`
            cuserr((hash_list is None), self._hash_usage(212))
            cuserr((hash_algos is not None \
                    or extract is not None), self._hash_usage(204))
            cuserr((src_strings is not None or src_files is not None \
                    or src_dirs is not None or src_list is not None), \
                   self._hash_usage(205))
            self.src_strings.append((None, self._to_unicode((src_strings \
                                    if isinstance(src_strings, list) \
                                    else []))))
            self.src_files.append((os.getcwd(), self._to_unicode((src_files \
                                  if isinstance(src_files, list) else []))))
            self.src_strings[0][1].sort()
            self.src_files[0][1].sort()

            # Parsing `recursive`
            if recursive:
                cuserr(isinstance(recursive, bool), \
                       self._hash_usage(11, varname='recursive', \
                                        vartype='bool'))
                self.recursive = recursive

            # Parsing `src_dirs` and `src_list`
            self._parse_src_dirs((src_dirs if isinstance(src_dirs, list) \
                                           else []))
            self._parse_src_list(src_list)
            self.total_item += sum([len(ss[1]) for ss in self.src_strings]) + \
                               sum([len(sf[1]) for sf in self.src_files]) + \
                               sum([len(sd[1]) for sd in self.src_dirs])

            # Check if there are any srcs to process
            cuserr(self.total_item != 0, self._hash_usage(215))

            # Parsing `uppercase`
            if uppercase:
                cuserr(isinstance(uppercase, bool), self._hash_usage(11, \
                       varname='uppercase', vartype='bool'))
                self.uppercase = uppercase

            # Parsing `extract`
            if extract:
                cuserr(isinstance(extract, bool), self._hash_usage(11, \
                       varname='extract', vartype='bool'))
                self.extract = extract

            # Parsing `extr_ptrn`
            if extr_ptrn:
                try:
                    extr_ptrn = re.compile(self._to_unicode(extr_ptrn), re.U)
                    cuserr((self._ptrn_extr_chk.search(extr_ptrn.pattern) \
                            is not None), \
                           self._hash_usage(12, varname='extr_ptrn', varval=\
                                            self._to_str(extr_ptrn.pattern)))
                except re.error as ree:
                    raise CustomError(self._hash_usage(16, varname=\
                                      'extr_ptrn', msg=_EXC_ARG(ree), \
                                      varval=self._to_str(extr_ptrn)))
                self.extr_ptrn = extr_ptrn

            # Parsing `altn_style`
            if altn_style:
                cuserr(isinstance(altn_style, bool), self._hash_usage(11, \
                       varname='altn_style', vartype='bool'))
                self.altn_style = altn_style

            # Parsing `dir_header`
            if dir_header:
                cuserr(isinstance(dir_header, bool), self._hash_usage(11, \
                       varname='dir_header', vartype='bool'))
                self.dir_header = dir_header

            # Parsing `hash_path`
            if hash_path:
                hash_path = os.path.abspath(self._to_unicode(hash_path))
                hash_dir = os.path.dirname(hash_path)
                cuserr(((not os.path.isdir(hash_path)) and \
                        os.access(hash_dir, os.W_OK)), \
                       self._hash_usage(206, varname='hash_path'))
                self.hash_path = hash_path
                self.hash_dir = hash_dir

                if os.access(self.hash_path, os.F_OK):
                    cuserr(os.access(self.hash_path, os.W_OK), \
                           self._hash_usage(207, varname='hash_path'))
                    usr_in = ''
                    while usr_in.lower() not in ('a', 'o'):
                        usr_in = raw_input(self._hash_usage(251, False, \
                                        filepath=self._to_str(self.hash_path)))
                        cuserr((usr_in != '' and usr_in.lower() != 'q'), \
                               self._hash_usage(15))
                    self._save_mode = 'a' if usr_in == 'a' else 'w'
                self._save_flag = True

            # Parsing `hash_algos`
            if not isinstance(hash_algos, list):
                if self.extract is True:
                    hash_algos = [self._valid_hash_algos[0]]
                else:
                    cuserr(False, self._hash_usage(12, varname='hash_algos', \
                           varval=self._to_str(hash_algos)))

            chked_hash_algos = []
            for hash_algo in hash_algos:
                chk_mod_rst = ''
                if hash_algo in chked_hash_algos:
                    continue
                if hash_algo in self._valid_hash_algos:
                    chk_mod_rst = self._chk_algo_mod(hash_algo)
                    cuserr(chk_mod_rst is True, self._hash_usage(214, \
                           algo=hash_algo, module=chk_mod_rst))
                    chked_hash_algos.append(hash_algo)
                else:
                    raise CustomError(self._hash_usage(12, varname=\
                            'hash_algos', varval=self._to_str(hash_algo)))

            if self.extract is True:
                del chked_hash_algos[1:]
            self.hash_algos.extend(chked_hash_algos)
        else:
            cuserr((src_strings is None and src_files is None \
                    and src_dirs is None and src_list is None), \
                   self._hash_usage(202))

            cuserr((hash_path is not None or hash_list is not None), \
                   self._hash_usage(203))

            # Parsing `hash_path`
            if hash_path:
                hash_path = os.path.abspath(self._to_unicode(hash_path))
                cuserr((os.path.isfile(hash_path) and \
                        os.access(hash_path, os.R_OK)), \
                       self._hash_usage(210, filepath=\
                                        self._to_str(hash_path)))
                self.hash_path = hash_path
                self.hash_dir = os.path.dirname(self.hash_path)

            # Parsing `hash_list`
            if hash_list:
                hash_list = os.path.abspath(self._to_unicode(hash_list))
                cuserr((os.path.isfile(hash_list) and \
                        os.access(hash_list, os.R_OK)), \
                       self._hash_usage(210, filepath=\
                                        self._to_str(hash_list)))
                self.hash_list = hash_list
                cuserr((hash_path is not None or hash_algos is not None), \
                       self._hash_usage(208))

            # Parsing `exist_only`
            if exist_only:
                cuserr(isinstance(exist_only, bool), self._hash_usage(11, \
                       varname='exist_only', vartype='bool'))
                self.exist_only = exist_only

            # Parsing `verbose`
            if verbose:
                cuserr(isinstance(verbose, bool), self._hash_usage(11, \
                       varname='verbose', vartype='bool'))
                self.verbose = verbose

            # Parsing `hash_algos`
            if isinstance(hash_algos, list):
                if len(hash_algos) == 1 \
                   and hash_algos[0] in self._valid_hash_algos:
                    chk_mod_rst = self._chk_algo_mod(hash_algos[0])
                    cuserr(chk_mod_rst is True, self._hash_usage(214, \
                           algo=hash_algos[0], module=chk_mod_rst))
                    self.hash_algos.append(hash_algos[0])
                else:
                    raise CustomError(self._hash_usage(213, varval=\
                                      self._to_str(hash_algos)))
            elif hash_algos is None:
                hash_extname = self._get_file_extname(self.hash_path or '')[2]
                if hash_extname in self._ext_map:
                    self.hash_algos.append(self._ext_map[hash_extname])
                else:
                    raise CustomError(self._hash_usage(201, extname=\
                                      self._to_str(hash_extname)))
            else:
                raise CustomError(self._hash_usage(12, varname=\
                        'hash_algos', varval=self._to_str(hash_algos)))

        # Parsing `hash_buf_siz`
        if hash_buf_siz:
            cuserr(isinstance(hash_buf_siz, int), \
                   self._hash_usage(11, varname='hash_buf_siz', vartype='int'))
            self.hash_buf_siz = hash_buf_siz

        # Debug Message
        """
        VARS = dict(action=self.action, src_strings=self.src_strings, \
                src_files=self.src_files, src_dirs=self.src_dirs, \
                src_list=src_list, recursive=self.recursive, \
                src_ptrn=self.src_ptrn, _src_filter=self._src_filter, \
                hash_algos=self.hash_algos, uppercase=self.uppercase, \
                extract=self.extract, extr_ptrn=self.extr_ptrn.pattern, \
                hash_path=self.hash_path, hash_list=hash_list, \
                exist_only=self.exist_only, verbose=self.verbose, \
                encoding=encoding, newline=self._newline, \
                hash_log=self.hash_log, _log_flag=self._log_flag, \
                log_mode=self._log_mode, _save_flag=self._save_flag, \
                _save_mode=self._save_mode, hash_buf_siz=\
                self.hash_buf_siz, tee=self.tee, total_item=self.total_item)
        SORT_KEYS = VARS.keys()
        SORT_KEYS.sort()
        raise AssertionError(self._hash_usage(299, msg="\n".join("%s = %r" % \
                             (key, self._to_str(VARS.get(key))) \
                             for key in SORT_KEYS)))
        """
    # End of __init__

    def _get_hash_obj(self, hash_algo):
        """Return the object of hash algorithm"""
        if hash_algo == 'crc32':
            return HashCRC32()
        elif hash_algo == 'adler32':
            return HashAdler32()
        elif hash_algo == 'md4':
            return getattr(hashlib, 'new')('md4')
        elif hash_algo == 'ed2k':
            return eD2k()
        elif hash_algo.startswith('blake2'):
            return getattr(pyblake2, hash_algo)()
        elif hash_algo.startswith('sha3_'):
            return getattr(sha3, hash_algo)()
        else:
            return getattr(hashlib, hash_algo)()
    # End of _get_hash_obj

    def _calc_str_hash(self, string):
        """Calculate the hash of the given string."""
        bol_read = True
        sbuf = None
        str_siz = len(string)
        hash_buf_siz = str_siz if str_siz < self.hash_buf_siz \
                               else self.hash_buf_siz
        hash_objs = []
        hash_codes = []
        proc_pos = 0
        progress = 0
        prog_bar = ProgressBar(bar_len=self.prog_bar_len)
        PROG_SEP = ' | '
        PROG_END = '...'

        for hash_algo in self.hash_algos:
            hash_objs.append(self._get_hash_obj(hash_algo))

        str_siz = 1.0 if str_siz == 0 else float(str_siz)
        first = True
        strtext = PROG_SEP + self._to_str(string)
        strtext_len = len(strtext)
        if strtext_len > self.line_limit:
            strtext = strtext[:(self.line_limit - len(PROG_END))] + PROG_END
            strtext_len = self.line_limit
        while bol_read:
            sbuf = string[proc_pos:(proc_pos + hash_buf_siz)]
            for hash_obj in hash_objs:
                hash_obj.update(self._to_str(sbuf, 'strict'))
            proc_pos += len(sbuf)
            progress = proc_pos / str_siz
            prog_bar_text = prog_bar.update(progress)
            self._print(prog_bar_text, end='')
            if first:
                self._print(strtext, end='')
                first = False
            if not sbuf:
                bol_read = False
                if progress < 1.0:
                    prog_bar_text = prog_bar.update(1.0)
                    self._print(prog_bar_text, end='')
                self._print(('\r' + ' ' * (len(prog_bar_text) + \
                            strtext_len) + '\r'), end='')

        for hash_obj in hash_objs:
            hash_code = hash_obj.hexdigest()
            hash_codes.append(hash_code if not self.uppercase \
                                        else hash_code.upper())

        return dict(zip(self.hash_algos, hash_codes))
    # End of _calc_str_hash

    def _calc_file_hash(self, fpath):
        """Calculate the hash of the given file."""
        bol_read = True
        fpath = fpath if os.path.isabs(fpath) else os.path.abspath(fpath)
        fbuf = None
        file_siz = os.path.getsize(fpath)
        hash_buf_siz = self.hash_buf_siz if (file_siz >> 30) == 0 \
                                         else self.hash_buf_siz << 1
        hash_objs = []
        hash_codes = []
        proc_siz = 0
        progress = 0
        prog_bar = ProgressBar(bar_len=self.prog_bar_len)
        PROG_SEP = ' | '
        PROG_END = '...'

        for hash_algo in self.hash_algos:
            hash_objs.append(self._get_hash_obj(hash_algo))

        file_siz = 1.0 if file_siz == 0 else float(file_siz)
        with open(fpath, 'rb') as fp:
            first = True
            filetext = PROG_SEP + self._to_str(os.path.basename(fpath))
            filetext_len = len(filetext)
            if filetext_len > self.line_limit:
                filetext = filetext[:(self.line_limit - len(PROG_END))] \
                           + PROG_END
                filetext_len = self.line_limit
            while bol_read:
                fbuf = fp.read(hash_buf_siz)
                for hash_obj in hash_objs:
                    hash_obj.update(fbuf)
                proc_siz += len(fbuf)
                progress = proc_siz / file_siz
                prog_bar_text = prog_bar.update(progress)
                self._print(prog_bar_text, end='')
                if first:
                    self._print(filetext, end='')
                    first = False
                if not fbuf:
                    bol_read = False
                    if progress < 1.0:
                        prog_bar_text = prog_bar.update(1.0)
                        self._print(prog_bar_text, end='')
                    self._print(('\r' + ' ' * (len(prog_bar_text) + \
                                 filetext_len) + '\r'), end='')

        for hash_obj in hash_objs:
            hash_code = hash_obj.hexdigest()
            hash_codes.append(hash_code if not self.uppercase \
                                        else hash_code.upper())

        return dict(zip(self.hash_algos, hash_codes))
    # End of _calc_file_hash

    def _get_rst_fmt(self, hash_algo, index=1):
        """
        Return the corresponding output format.
        `index`:    Index of object list(strings, files, dirs)
        """
        rst_fmt = None

        if index == 0:
            rst_fmt = self._fmt_hash_rst_str
        else:
            if hash_algo == 'crc32':
                rst_fmt = self._fmt_hash_rst_crc32
            else:
                rst_fmt = self._fmt_hash_rst_def

        return rst_fmt
    # End of _get_rst_fmt

    def _calculate(self, tmp_fps=None, log_fp=None):
        """Calculate the hash according to the given arguments."""
        fp_ptr = None
        tmp_fps = {} if isinstance(tmp_fps, dict) is False else tmp_fps
        hash_rst = ''
        obj_list = (self.src_strings, self.src_files, self.src_dirs)
        calc_meth = (self._calc_str_hash, self._calc_file_hash, \
                     self._calc_file_hash)
        header_fmt = self._fmt_hash_header
        altn_hdr_fmt = self._fmt_alt_sty_hdr
        newline = self._newline

        for src_idx in range(len(obj_list)):
            for src_obj in obj_list[src_idx]:
                src_obj_dir = src_obj[0]
                src_header = (header_fmt % {'header': src_obj_dir, \
                                            'nl': newline}) \
                             if src_idx == 2 and self.dir_header else None
                src_hdr_ntee = False
                if src_header is not None:
                    if self._save_flag is True:
                        for hash_algo in self.hash_algos:
                            fp_ptr = tmp_fps.get(hash_algo)
                            self._print(self._to_str(src_header), fp_ptr, \
                                        '', src_hdr_ntee)
                            src_hdr_ntee = True
                    else:
                        self._print(self._to_str(src_header), log_fp, '')

                prev_relpath = curr_relpath = src_altn_hdr = None
                relpath_chgd = False
                for src_item in src_obj[1]:
                    if self.altn_style is False:
                        # Use basename as the text of the file obj
                        src_item_text = src_item if src_idx != 1 \
                                                 else os.path.basename(src_item)
                    else:
                        # Use basename as the text of the file and dir obj
                        src_item_text = src_item if src_idx == 0 \
                                                 else os.path.basename(src_item)
                        if src_idx == 2:
                            curr_relpath = os.path.dirname(src_item) or None
                            src_altn_hdr = (altn_hdr_fmt % {'nl': newline, \
                                            'dir': curr_relpath}) \
                                           if curr_relpath is not None else None
                            if curr_relpath != prev_relpath:
                                relpath_chgd = True
                                prev_relpath = curr_relpath
                            else:
                                relpath_chgd = False
                        else:
                            src_altn_hdr = None

                    if src_obj_dir is not None:
                        src_item = self._get_file_path(src_obj_dir, src_item)

                    if src_idx != 0 and not (os.path.isfile(src_item) and \
                                             os.access(src_item, os.R_OK)):
                        self._print(self._hash_usage(210, filepath=\
                                    self._to_str(src_item)), log_fp)
                        self.proc_nofnd += 1
                        continue

                    try:
                        hash_codes = calc_meth[src_idx](src_item)
                    except IOError:
                        self._print(self._hash_usage(234, False, filename=\
                                    self._to_str(src_item_text), result=\
                                    'FAIL'), log_fp)
                        self.proc_fail += 1
                        continue

                    src_altn_ntee = False
                    if src_altn_hdr is not None and relpath_chgd is True:
                        if self._save_flag is True:
                            for hash_algo in self.hash_algos:
                                fp_ptr = tmp_fps.get(hash_algo)
                                self._print(self._to_str(src_altn_hdr), \
                                            fp_ptr, '', src_altn_ntee)
                                src_altn_ntee = True
                        else:
                            self._print(self._to_str(src_altn_hdr), log_fp, '')

                    for hash_algo in self.hash_algos:
                        fp_ptr = tmp_fps.get(hash_algo) or log_fp
                        hash_rst = self._get_rst_fmt(hash_algo, src_idx) \
                                   % {'item': src_item_text, \
                                      'hash': hash_codes[hash_algo], \
                                      'nl': newline}
                        self._print(self._to_str(hash_rst), fp_ptr, '')

                    self.proc_ok += 1
                    hash_rst = ''
    # End of _calculate

    def _extract_hash(self, tmp_fps=None, log_fp=None):
        """Extract hash info from filenames."""
        fp_ptr = None
        tmp_fps = {} if isinstance(tmp_fps, dict) is False else tmp_fps
        hash_rst = ''
        obj_list = (self.src_strings, self.src_files, self.src_dirs)
        header_fmt = self._fmt_hash_header
        altn_hdr_fmt = self._fmt_alt_sty_hdr
        rst_fmt = self._get_rst_fmt(self.hash_algos[0])
        newline = self._newline

        for src_idx in range(len(obj_list)):
            for src_obj in obj_list[src_idx]:
                src_obj_dir = src_obj[0]
                src_header = (header_fmt % {'header': src_obj_dir, \
                                            'nl': newline}) \
                             if src_idx == 2 and self.dir_header else None
                if src_header is not None:
                    fp_ptr = tmp_fps.get(self.hash_algos[0]) or log_fp
                    self._print(self._to_str(src_header), fp_ptr, end='')

                prev_relpath = curr_relpath = src_altn_hdr = None
                relpath_chgd = False
                for src_item in src_obj[1]:
                    if self.altn_style is False:
                        # Use basename as the text of the file obj
                        src_item_text = src_item if src_idx != 1 \
                                                 else os.path.basename(src_item)
                    else:
                        # Use basename as the text of the file and dir obj
                        src_item_text = src_item if src_idx == 0 \
                                                 else os.path.basename(src_item)
                        if src_idx == 2:
                            curr_relpath = os.path.dirname(src_item) or None
                            src_altn_hdr = (altn_hdr_fmt % {'nl': newline, \
                                            'dir': curr_relpath}) \
                                           if curr_relpath is not None else None
                            if curr_relpath != prev_relpath:
                                relpath_chgd = True
                                prev_relpath = curr_relpath
                            else:
                                relpath_chgd = False
                        else:
                            src_altn_hdr = None

                    src_item = os.path.basename(src_item)
                    hash_code = self.extr_ptrn.search(src_item)
                    if hash_code:
                        fp_ptr = tmp_fps.get(self.hash_algos[0]) or log_fp
                        if src_altn_hdr is not None and relpath_chgd is True:
                            self._print(self._to_str(src_altn_hdr), fp_ptr, '')
                        hash_code = hash_code.groupdict()['hash']
                        hash_rst = rst_fmt % {'item': src_item_text, \
                                              'hash': hash_code \
                                                   if self.uppercase is False \
                                                   else hash_code.upper(),\
                                              'nl': newline}
                        self._print(self._to_str(hash_rst), fp_ptr, end='')
                        self.proc_ok += 1
                    else:
                        self._print(self._hash_usage(236, False, line=\
                                    self._to_str(src_item_text)), log_fp)
                        self.proc_fail += 1
    # End of _extract_hash

    def _verify(self, log_fp=None):
        """Verify the hash according to the given arguments."""
        VFY_RESULT = {1: 'Found', 2: 'OK', 3: 'FAIL'}

        with open(self.hash_path, 'r') as fp:
            self.vfy_files.append((None, []))
            for line in fp:
                line = self._to_unicode(line)
                if line.startswith(u'*') is True:
                    altn_dir = self._ptrn_alt_sty_dir.search(line)
                    if altn_dir:
                        self.vfy_files.append((altn_dir.groupdict()['dir'], []))
                elif self._ptrn_empty_line.search(line) is None:
                    self.vfy_files[-1][1].append(line)

        result = 3
        hash_algo = self.hash_algos[0]
        for altn_dir, items in self.vfy_files:
            for item in items:
                item_mch = self._ptrn_hash_item[hash_algo].search(item)
                if item_mch:
                    item_mch = item_mch.groupdict()
                    filetext = item_mch['file'] if altn_dir is None \
                               else os.path.join(altn_dir, item_mch['file'])
                    hash_val = item_mch['hash']
                    if self._src_filter(os.path.basename(filetext)) is False:
                        self.total_item -= 1
                        continue
                    filepath = self._get_file_path(self.hash_dir, filetext)
                else:
                    item_mch = self._ptrn_err_line.search(item)
                    item_mch = item_mch.group(0) if item_mch else item
                    self._print(self._hash_usage(235, False, line=\
                                self._to_str(item_mch)), log_fp)
                    self.proc_nofnd += 1
                    continue

                if os.path.isfile(filepath) and os.access(filepath, os.R_OK):
                    if self.exist_only:
                        result = 1
                        self.proc_found += 1
                    elif hash_val.lower() == \
                         self._calc_file_hash(filepath)[hash_algo]:
                        result = 2
                        self.proc_ok += 1
                    else:
                        result = 3
                        self.proc_fail += 1
                    if result == 3 or self.verbose:
                        self._print(self._hash_usage(234, False, filename=\
                                    self._to_str(filetext), result=\
                                    VFY_RESULT[result]), log_fp)
                else:
                    self._print(self._hash_usage(210, False, filepath=\
                                self._to_str(filetext)), log_fp)
                    self.proc_nofnd += 1

            self.total_item += len(items)
    # End of _verify

    def _verify_hash_list(self, log_fp):
        """Verify the hash according to the list"""
        hash_list_dir = os.path.dirname(self.hash_list)
        hash_list_u = []

        with open(self.hash_list, 'r') as fp:
            for line in fp:
                line = self._to_unicode(line)
                if line.startswith(u'*') is False \
                   and self._ptrn_empty_line.search(line) is None:
                    hash_file = self._ptrn_file_line.search(line)
                    if hash_file:
                        hash_file = hash_file.groupdict()
                        hash_list_u.append(hash_file['file'])
                    else:
                        self._print(self._hash_usage(235, False, \
                                    line=self._to_str(line)), log_fp)

        self.hash_algos.append(self.hash_algos[0])
        for item in hash_list_u:
            self.hash_path = self._get_file_path(hash_list_dir, item)
            if not (os.path.isfile(self.hash_path) and \
                    os.access(self.hash_path, os.R_OK)):
                self._print(self._hash_usage(210, False, filepath=\
                            self._to_str(self.hash_path)), log_fp)
                continue
            self.hash_dir = os.path.dirname(self.hash_path)

            hash_extname = self._get_file_extname(self.hash_path or '')[2]
            self.hash_algos[0] = self._ext_map[hash_extname] \
                                 if hash_extname in self._ext_map \
                                 else self.hash_algos[1]
            self.vfy_files[:] = []
            self._verify(log_fp)
        self.hash_algos[:] = self.hash_algos[-1:]
    # End of _verify_hash_list

    def __call__(self):
        try:
            tmp_fps = {}
            cnt_tmp_fps = 0
            log_fp = self._log_tmpfp

            self._print(self._hash_usage(230, False), log_fp)
            stime = time.time()
            self._print(self._hash_usage(231, False, stime=time.ctime(stime)),
                        log_fp)

            if self.action == 'c':
                calc_func = self._calculate if self.extract is False \
                                            else self._extract_hash
                if self._save_flag:
                    for hash_algo in self.hash_algos:
                        tmp_fps[hash_algo] = SplTmpFile()
                    cnt_tmp_fps = len(self.hash_algos)
                    calc_func(tmp_fps, log_fp)
                    self._print(self._hash_usage(233, filepath=\
                                self._to_str(self.hash_path)), log_fp)
                else:
                    calc_func(log_fp=log_fp)
            else:
                if self.hash_path:
                    self._verify(log_fp)
                if self.hash_list:
                    self._verify_hash_list(log_fp)

            self.proc_found += self.proc_ok + self.proc_fail
            etime = time.time() - stime
            self._print(self._hash_usage(232, False, ok=self.proc_ok, \
                        fail=self.proc_fail, found=self.proc_found, \
                        nofnd=self.proc_nofnd, total=self.total_item, \
                        etime=etime), log_fp)
        finally:
            if self._save_flag:
                with open(self.hash_path, self._save_mode) as fp:
                    for hash_algo in self.hash_algos:
                        tmp_fp = tmp_fps.get(hash_algo)
                        if isinstance(tmp_fp, SplTmpFile):
                            if 1 < cnt_tmp_fps:
                                tmp_fp.write(self._newline)
                                cnt_tmp_fps -= 1
                            tmp_fp.seek(0, os.SEEK_SET)
                            fp.write(tmp_fp.read())
                            tmp_fp.close()
            if isinstance(log_fp, SplTmpFile):
                log_fp.seek(0, os.SEEK_SET)
                with open(self.hash_log, self._log_mode) as fp:
                    fp.write(log_fp.read())
                log_fp.close()
    # End of __call__
# End of HashCalculator


class CharCatcher(object):
    """Get a single character from standard input."""

    _mod_msvcrt = None
    _mod_termios = None
    _mod_tty = None
    getch = None

    def _getch_unix(self):
        tty = self._mod_tty
        termios = self._mod_termios

        fd = sys.stdin.fileno()
        old_conf = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_conf)

        return ch
    # End of _getch_unix

    def _getch_win(self):
        msvcrt = self._mod_msvcrt

        return msvcrt.getch()
    # End of _getch_win

    def __init__(self):
        try:
            self._mod_msvcrt = __import__('msvcrt')
            self.getch = self._getch_win
        except ImportError:
            self._mod_termios = __import__('termios')
            self._mod_tty = __import__('tty')
            self.getch = self._getch_unix
    # End of __init__

    def __call__(self):
        return self.getch()
    # End of __call__
# End of CharCatcher


class HashCalcAction(argparse.Action):
    """For parsing arguments "ACTION" to HashCalculator."""

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values[0])
    # End of __call__
# End of HashCalcAction


def sig_int_handler(signum, frame):
    """Signal Handler for signal interrupt"""
    usage = UsageHandler()
    raise CustomError('\n' + usage(15))
# End of sig_int_handler

def main_parse_args(usage):
    """Parsing arguments for command line"""
    parser = argparse.ArgumentParser(\
             description='Calculate or verify the hash of file(s).')

    parser.add_argument('-s', '--string', dest='src_strings', \
                        metavar='SRC_STRING', action='append', \
                        help=usage(107, False))
    parser.add_argument('-f', '--file', dest='src_files', \
                        metavar='SRC_FILE', action='append', \
                        help=usage(104, False))
    parser.add_argument('-d', '--directory', dest='src_dirs', \
                        metavar='SRC_DIR', action='append', \
                        help=usage(113, False))
    parser.add_argument('-S', '--src-list', dest='src_list', \
                        metavar='SRC_LIST', help=usage(119, False))
    parser.add_argument('-r', '--recursive', dest='recursive', \
                        action='store_true', help=usage(114, False))
    parser.add_argument('-P', '--src-pattern', dest='src_ptrn', \
                        metavar='SRC_PATTERN', help=usage(128, False))
    parser.add_argument('-R', '--src-regex', dest='src_regex', \
                        metavar='SRC_REGEX', help=usage(129, False))
    parser.add_argument('-a', '--algorithm', \
                        choices=['crc32', 'md5', 'sha1', 'sha224', \
                                 'sha256', 'sha384', 'sha512', 'md4', \
                                 'ed2k', 'blake2b', 'blake2s', 'sha3_224', \
                                 'sha3_256', 'sha3_384', 'sha3_512', \
                                 'adler32'], \
                        dest='hash_algos', metavar='ALGORITHM', \
                        action='append', help=usage(103, False))
    parser.add_argument('-u', '--uppercase', dest='uppercase', \
                        action='store_true', help=usage(106, False))
    parser.add_argument('-X', '--extract', dest='extract', \
                        action='store_true', help=usage(125, False))
    parser.add_argument('-p', '--extr_ptrn', dest='extr_ptrn', \
                        metavar='PATTERN', help=usage(126, False))
    parser.add_argument('-A', '--alternative-style', dest='altn_style', \
                        action='store_true', help=usage(130, False))
    parser.add_argument('-H', '--directory-header', dest='dir_header', \
                        action='store_true', help=usage(131, False))
    parser.add_argument('-o', '--hash-path', dest='hash_path', \
                        metavar='HASH_PATH', help=usage(102, False))
    parser.add_argument('-l', '--hash-list', dest='hash_list', \
                        metavar='HASH_LIST', help=usage(116, False))
    parser.add_argument('-x', '--exist-only', dest='exist_only', \
                        action='store_true', help=usage(123, False))
    parser.add_argument('-v', '--verbose', dest='verbose', \
                        action='store_true', help=usage(124, False))
    parser.add_argument('-e', '--encoding', dest='encoding', \
                        metavar='ENCODING', help=usage(118, False))
    parser.add_argument('-L', '--log', dest='hash_log', \
                        metavar='HASH_LOG', help=usage(120, False))
    parser.add_argument('-t', '--tee', dest='tee', action='store_true', \
                        help=usage(122, False), required=False)
    parser.add_argument('-V', '--version', action='version', \
                        version=usage(101, False, prog='hashcalc'))
    parser.add_argument('action', choices=['c', 'calculate', 'v', 'verify'], \
                        metavar='ACTION', action=HashCalcAction, \
                        help=usage(108, False))

    return parser.parse_args()
# End of main_parse_args

def _main():
    """Main function to parsing arguments and error handling."""
    warnings.simplefilter('ignore')
    usage = MainUsageHandler()
    args = None
    rst = [True, '']
    def_enc = 'utf8'
    exc_type = None
    tb_info = None

    try:
        # Setup signal handler (SIGINT, Interrupt)
        signal.signal(signal.SIGINT, sig_int_handler)

        # Use module argparse to parse arguments.
        args = main_parse_args(usage)

        # Check arguments
        if args.action == 'c':
            cuserr((args.hash_algos is not None \
                    or args.extract is not False), usage(111))
            cuserr((args.src_strings is not None \
                    or args.src_files is not None \
                    or args.src_dirs is not None \
                    or args.src_list is not None), usage(112))
            cuserr((args.hash_list is None), usage(117))
        else:
            cuserr((args.src_strings is None \
                    and args.src_files is None \
                    and args.src_dirs is None \
                    and args.src_list is None), usage(109))
            cuserr((args.hash_path is not None \
                    or args.hash_list is not None), usage(110))
            if args.hash_list:
                cuserr((args.hash_path is not None \
                        or args.hash_algos is not None), usage(121))

        if args.hash_algos is not None:
            for hash_algo in args.hash_algos:
                cuserr((IMPORT_PYBLAKE2 \
                        or not hash_algo.startswith('blake2')), \
                       usage(127, module='pyblake2', algo=hash_algo))
                cuserr((IMPORT_SHA3 \
                        or not hash_algo.startswith('sha3_')), \
                       usage(127, module='sha3', algo=hash_algo))

        hashcalc_param = vars(args)
        hashcalc_param['hash_buf_siz'] = None

        # Create HashCalculator object and do the action
        hash_obj = HashCalculator(**hashcalc_param)
        hash_obj()
    except (StandardError, KeyboardInterrupt, CustomError) as se:
        rst[0] = False
        # exc_type, exc_obj, tb_obj = sys.exc_info()
        # NOTE(leonard): Uncomment the following two lines to show the full
        #                traceback info.
        # for tb_info in traceback.extract_tb(sys.exc_info()[-1]):
        #     print usage(3, False, **_TRBK_DICT(tb_info[:3], tb_info[-1]))[5:]
        exc_type = type(se)
        tb_info = traceback.extract_tb(sys.exc_info()[-1])[-1][:3]
        if exc_type in (CustomError, AssertionError):
            rst[1] = _EXC_ARG(se)
        elif exc_type is KeyboardInterrupt:
            rst[1] = '\n' + usage(15)
        else:
            rst[1] = usage(3, True, **_TRBK_DICT(tb_info, _EXC_MSG(se)))

    # Main Error Handling
    if rst[0] is False:
        print (rst[1] if not isinstance(rst[1], unicode) \
                      else rst[1].encode(def_enc, 'ignore'))
    else:
        print usage(115, False)
        (CharCatcher())()
# End of _main

if __name__ == '__main__':
    _main()
# End of __main__
