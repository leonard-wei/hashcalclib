#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# python version: 2.7.5 final, serial: 0

import argparse
import codecs
import hashlib
import os
import re
import signal
import sys
import time
import traceback
import warnings
import zlib

from ctypes import c_uint
from tempfile import SpooledTemporaryFile as SplTmpFile


class UsageHandler(object):
    """Handle usage message, msgid: 0~10 reserved."""

    USAGE_HEADER = 'usage: %(msg)s'
    SP = '\x20\x20\x20\x20'
    HR =  '-'
    USAGE_MSG = {
        1: '\n' + SP + 'Internal Error!',
        2: '\n' + SP + '%(msg)s',
        3: '\n' + SP + '%(filename)s, line %(line)s:\n' + SP + \
           '%(exctype)s: %(excmsg)s',
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
    # End of __init__

    def __call__(self, msg_id=1, header=True, **kwargs):
        try:
            message = self.USAGE_MSG[msg_id] % kwargs
        except StandardError:# as se:
            # kwargs doesn't match a variable in the message
            # at least get the core message out if something happened
            #exc_type, exc_obj, tb_obj = sys.exc_info()
            #tb_obj = traceback.extract_tb(sys.exc_info()[-1])[-1]
            #print self.USAGE_MSG[3] % {'filename': tb_obj[0], \
            #                           'line': str(tb_obj[1]), \
            #                           'exctype': type(se).__name__, \
            #                           'excmsg': (se.message or str(se.args))}
            message = self.USAGE_MSG[1]

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
            101: '%(prog)s - 1.2 (Python 2.7.5 final) '\
                 'by Leonard Wei(gooxxgle.mail@gmail.com), 24 JUL 2013.',
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
                 '), "sha384"(*.sha384), "sha512"(*.sha512). This option '\
                 'could be used multiple times, but specify the same '\
                 'algorithm multiple times will only apply once.',
            104: 'The file(s) need to be calculated their '\
                 'hash. This option could be used multiple times.',
            105: '\n' + SP + '.',
            106: 'If specified, return the hash code in uppercase. '\
                 'Only effective with ACTION "c".',
            107: 'If specified, calculate the hash of the given '\
                 'string(s) instead of file(s). This option could be '\
                 'used multiple times.',
            108: '"c" or "calculate" means calculate the hash of file(s)'\
                 ', "v" or "verify" means verify the hash of file(s).',
            109: '\n' + SP + 'When ACTION is "verify", the "-s", "-f", '\
                 '"-d" and "-L" options are not allowed.',
            110: '\n' + SP + 'When ACTION is "verify", the "-o" or "-l" '\
                 'option is required.',
            111: '\n' + SP + 'When ACTION is "calculate", the "-a" '\
                 'option is required.',
            112: '\n' + SP + 'When ACTION is "calculate", the "-s", '\
                 '"-f", "-d" and/or "-L" options are required.',
            113: 'The hashes of the files under this directory will be '\
                 'calculated. This option could be used multiple times.',
            114: 'If specified, It will recursively searches all files '\
                 'under the directory and calculates the hashes. Only '\
                 'effective with the "-d" option.',
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
                 'support unicode properly or batch Calculation.'\
                 ' If "-s", "-f" or "-d" are specified, it will also '\
                 'try to process them. A line start with "*" is '\
                 'considered as a comment.',
            120: 'Save the output messages to the specified log file',
            121: '\n' + SP + 'When action is "v" and only "-l" option is '\
                 'specified, the "-a" option is required.',
            122: 'Output to stdout, as well as any hash and/or log files.',
            123: 'When specified, just check the file existence and no '\
                 'hashes will be verified. Only effective with action "v"',
            124: 'Show all output result(default only show the "FAIL" and '\
                 '"Not Found"). Only effective with action "v".',
            125: 'If specified, extract the hash info from filenames '\
                 'instead of calculating.',
            126: 'A regular expression pattern used for extraction. '\
                 'It must contain at least one group "(:P<hash>...)". '\
                 'Default pattern is "^.*(?:(?P<hlbk>\[)|(?P<hlpt>\())?'\
                 '(?:crc32[ _\-])?(?P<hash>[0-9A-Za-z]{8})(?(hlbk)\])'\
                 '(?(hlpt)\))(?:\[(?:[\w]{1,5})\])?'\
                 '\.[0-9A-Za-z]{2,4}$"',
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
                 'specified, the "hash_algos"(*only one) is required.',
            209: '\n' + SP + '"%(filepath)s" is not a directory.',
            210: '"%(filepath)s" is not found, not a file or unable to read.',
            211: 'UnicodeDecodeError: "%(string)r"',
            212: '\n' + SP + 'When action is "c", the "hash_list" '\
                 'is not allowed.',
            213: '\n' + SP + '"hash_algos" is invalid or specified more than '\
                 'once: %(varval)s.',
            230: HR * 1 + TITLE + HR * 1,
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
            assert isinstance(self._prog_prec, int), self._pb_usage(11, \
                   varname='prog_prec', vartype='int')
        prog_prec_len = 0 if self._prog_prec == 0 else 1 + self._prog_prec

        if bar_len:
            self._bar_len = bar_len - 7 - prog_prec_len
            assert isinstance(self._bar_len, int), self._pb_usage(11, \
                   varname='bar_len', vartype='int')

        if bar_style:
            self._bar_style = bar_style
            assert (isinstance(self._bar_style, list) and \
                   len(self._bar_style) == 5), self._pb_usage(301)
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
        assert isinstance(progress, float), self._pb_usage(11, \
               varname='progress', vartype='float')
        assert not (progress < 0 or progress > 1), self._pb_usage(13, \
               varname='progress', start='0', end='1')

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


class HashCRC32(object):
    """Transform the zlib.crc32 into hashlib-like class."""

    _hash_func = None
    _hash_code = None

    def __init__(self):
        self._hash_func = getattr(zlib, 'crc32')
        self._hash_code = 0
    # End of __init__

    def update(self, buf):
        self._hash_code = self._hash_func(buf, self._hash_code)
    # End of update

    def hexdigest(self):
        return ("%.8x" % (c_uint(self._hash_code).value))
    # End of hexdigest
# End of HashCRC32


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
    `hash_algos`:   List of hash algorithm(s).
    `uppercase`:    Return uppercase hash code if True.
    `extract`:      Extract hash info from filename instead of calculating.
    `extr_patrn`:   A regex pattern used for extraction. It must contain at
                    least one group "(?P<hash>...)"
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
    """

    _hash_usage = HashUsageHandler()
    _pat_file_ext = re.compile(r"^(?P<main>.+)(?P<sep>\.)(?P<ext>[^\n\.]+)$", \
                               re.U)
    _valid_hash_algos = ('crc32', 'md5', 'sha1', 'sha224', 'sha256', \
                       'sha384', 'sha512')
    _ext_map = {
        'sfv': _valid_hash_algos[0],
        'md5': _valid_hash_algos[1],
        'sha1': _valid_hash_algos[2],
        'sha224': _valid_hash_algos[3],
        'sha256': _valid_hash_algos[4],
        'sha384': _valid_hash_algos[5],
        'sha512': _valid_hash_algos[6],
    }
    _pat_hash_str = r"<hash>[0-9A-Za-z]"
    _pat_file_str = r"<file>[^\t\v\r\n\f]+"
    _pat_sep_str = r"\t+|\x20+"
    _pat_crc32_str = r"^(?P%s)(?:%s)\*?(?P%s{8})(?:[\s]*)$" \
                     % (_pat_file_str, _pat_sep_str, _pat_hash_str)
    _pat_hashlib_str = r"^(?P%s{%s})(?:%s)\*?(?P%s)(?:[\s]*)$" \
                       % (_pat_hash_str, r"%s", _pat_sep_str, _pat_file_str)
    _pat_hash_item = {
        _valid_hash_algos[0]: re.compile(_pat_crc32_str, re.U),
        _valid_hash_algos[1]: re.compile(_pat_hashlib_str % ("32"), re.U),
        _valid_hash_algos[2]: re.compile(_pat_hashlib_str % ("40"), re.U),
        _valid_hash_algos[3]: re.compile(_pat_hashlib_str % ("56"), re.U),
        _valid_hash_algos[4]: re.compile(_pat_hashlib_str % ("64"), re.U),
        _valid_hash_algos[5]: re.compile(_pat_hashlib_str % ("96"), re.U),
        _valid_hash_algos[6]: re.compile(_pat_hashlib_str % ("128"), re.U),
    }
    _pat_file_line = re.compile((r"^(?P%s)(?:[\s]*)$" % (_pat_file_str)), re.U)
    _pat_string_line = re.compile(r"^STRING=(?P<string>[^\r\n]+)(?:[\r\n]*)$",
                                  re.U)
    _pat_empty_line = re.compile(r"^[\r\n]*$", re.U)
    _pat_err_line = re.compile(r"^[^\r\n]*", re.U)
    _pat_extr_check = re.compile(r"\(\?P<hash>.*?\)")
    _def_enc = 'utf8'
    _encodings = ['utf8', 'utf16', 'ascii', 'cp950',]
    _newline = os.linesep
    _log_flag = False
    _log_mode = 'a'
    _save_flag = False
    _save_mode = 'a'
    action = None
    src_strings = []
    src_files = []
    src_dirs = []
    recursive = False
    hash_algos = []
    uppercase = False
    hash_path = None
    hash_dir = None
    hash_list = None
    exist_only = False
    extract = False
    extr_patrn = re.compile((r"^.*%(hlbp)s%(prefix)s%(hash)s%(hrbp)s"\
                             "%(suffix)s%(ext)s$" % \
                             {"hlbp": r"(?:(?P<hlbk>\[)|(?P<hlpt>\())?", \
                              "prefix": r"(?:crc32[ _\-])?", \
                              "hash": r"(?P<hash>[0-9A-Za-z]{8})", \
                              "hrbp": r"(?(hlbk)\])(?(hlpt)\))", \
                              "suffix": r"(?:\[(?:[\w]{1,5})\])?", \
                              "ext": r"\.[0-9A-Za-z]{2,4}"}), re.U)
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

    def _print(self, obj, fp=None, end='\n'):
        """Determine the output to stdout or file"""
        obj = obj if isinstance(obj, basestring) else str(obj)
        end = end if isinstance(end, basestring) else '\n'

        if isinstance(fp, (file, SplTmpFile)):
            fp.write(obj + end)

        if fp is None or self.tee is True:
            sys.stdout.write(obj + end)
            sys.stdout.flush()
    # End of _print

    def _get_file_extname(self, filename, default_ext='', sep='.'):
        """
        Return the extension name of the file
        ``filename``: 'hash.md5' or '/dir/hash.md5
        ``sep``: split separator, default '.'
        """
        filename = os.path.basename(filename) or ''
        extname = default_ext

        if sep == '.':
            pat_file_ext_loc = self._pat_file_ext
        else:
            esc_sep = '\\' + sep
            pat_file_ext_loc = re.compile(r"^(?P<main>.+)(?P<sep>" + \
                                          esc_sep + ")(?P<ext>[^\n" + \
                                          esc_sep + "]+)$")
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
                self._hash_usage(211, string=item)
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
            if not isinstance(fdir, unicode):
                fdir = self._to_unicode(fdir)

            if os.path.isabs(fdir) is False:
                fdir = os.path.abspath(fdir)

            if os.path.isdir(fdir) is False:
                self._print(self._hash_usage(209, filepath=self._to_str(fdir)))
                return (None, [])

            root_flag = False
            if root is None:
                root_flag = True
                root = fdir

            flist = []
            flist_sub = []
            flist_tmp = os.listdir(fdir)
            flist_tmp.sort()
            for fitem in flist_tmp:
                fsubpath = self._get_file_path(fdir, fitem)
                # Here will not follow the symbolic link(dir) if recursive
                if os.path.isdir(fsubpath):
                    if self.recursive and os.path.islink(fsubpath) is False:
                        flist_sub.extend(self._get_file_list(fsubpath, root))
                elif os.path.isfile(fsubpath):
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
                if isinstance(item, basestring) is False:
                    continue
                self.src_dirs.append(self._get_file_list(item))
        else:
            self.src_dirs.append((None, []))
    # End of _parse_src_dirs

    def _parse_src_list(self, src_list):
        """Parse the list of strings, files and dirs"""
        if isinstance(src_list, basestring):
            src_list = os.path.abspath(self._to_unicode(src_list))
            assert (os.path.isfile(src_list) and \
                    os.access(src_list, os.R_OK)), \
                   self._hash_usage(210, filepath=self._to_str(src_list))

            src_list_loc = os.path.dirname(src_list)
            src_list_strings = []
            src_list_files = []
            src_list_dirs = []
            with open(src_list, 'r') as fp:
                for line in fp:
                    line = self._to_unicode(line)
                    if line.startswith(u'*') is False \
                       and self._pat_empty_line.search(line) is None:
                        src_item = self._pat_string_line.search(line)
                        if src_item:
                            src_item = src_item.groupdict()['string']
                            src_list_strings.append(src_item)
                            continue

                        src_item = self._pat_file_line.search(line)
                        if src_item:
                            src_item = src_item.groupdict()['file']
                            src_item = self._get_file_path(src_list_loc, \
                                                           src_item)
                            if os.path.isfile(src_item):
                                src_list_files.append(src_item)
                            elif os.path.isdir(src_item):
                                src_list_dirs.append(src_item)
                            else:
                                src_list_strings.append(src_item)
                            continue

                        raise AssertionError(self._hash_usage(235, line=\
                              self._to_str(line)))

            src_list_strings.sort()
            src_list_files.sort()
            src_list_dirs.sort()
            self.src_strings.append((None, src_list_strings))
            self.src_files.append((src_list_loc, src_list_files))
            self._parse_src_dirs(src_list_dirs)
    # End of _parse_src_list

    def __init__(self, action, src_strings=None, src_files=None, \
                 src_dirs=None, src_list=None, recursive=None, \
                 hash_algos=None, uppercase=None, extract=None, \
                 extr_patrn=None, hash_path=None, hash_list=None, \
                 exist_only=None, verbose=None, encoding=None, \
                 hash_log=None, hash_buf_siz=None, tee=None):
        """Initialize and parse all arguments."""
        # Parsing `encoding`
        if encoding:
            try:
                codecs.lookup(encoding)
                self._encodings.insert(0, encoding)
            except LookupError as le:
                raise AssertionError(self._hash_usage(2, msg=(le.message or \
                                                              str(le.args))))

        # Parsing `action`
        assert (action in ('c', 'v')), self._hash_usage(12, \
               varname='action', varval=self._to_str(action))
        self.action = action
        if self.action == 'c':
            # Parsing `src_strings`, `src_files`
            assert (hash_list is None), m_usage(212)
            assert (hash_algos is not None \
                    or extract is not None), m_usage(204)
            assert (src_strings is not None or src_files is not None \
                    or src_dirs is not None or src_list is not None), \
                   m_usage(205)
            self.src_strings.append((None, self._to_unicode((src_strings \
                                    if isinstance(src_strings, list) \
                                    else []))))
            self.src_files.append((os.getcwd(), self._to_unicode((src_files \
                                  if isinstance(src_files, list) else []))))
            self.src_strings[0][1].sort()
            self.src_files[0][1].sort()

            # Parsing `recursive`
            if recursive:
                assert isinstance(recursive, bool), \
                       self._hash_usage(11, varname='recursive', \
                                        vartype='bool')
                self.recursive = recursive

            # Parsing `src_dirs` and `src_list`
            self._parse_src_dirs((src_dirs if isinstance(src_dirs, list) \
                                           else []))
            self._parse_src_list(src_list)
            self.total_item += sum([len(ss[1]) for ss in self.src_strings]) + \
                               sum([len(sf[1]) for sf in self.src_files]) + \
                               sum([len(sd[1]) for sd in self.src_dirs])

            # Parsing `uppercase`
            if uppercase:
                assert isinstance(uppercase, bool), self._hash_usage(11, \
                       varname='uppercase', vartype='bool')
                self.uppercase = uppercase

            # Parsing `extract`
            if extract:
                assert isinstance(extract, bool), self._hash_usage(11, \
                       varname='extract', vartype='bool')
                self.extract = extract
                hash_algos = [self._valid_hash_algos[0]]

            # Parsing `extr_patrn`
            if extr_patrn:
                try:
                    extr_patrn = re.compile(self._to_unicode(extr_patrn), re.U)
                    assert (self._pat_extr_check.search(extr_patrn.pattern) \
                            is not None), \
                           self._hash_usage(12, varname='extr_patrn', varval=\
                                            self._to_str(extr_patrn.pattern))
                except re.error as ree:
                    raise AssertionError(self._hash_usage(16, varname=\
                            'extr_patrn', msg=(ree.message or str(ree.args)), \
                            varval=self._to_str(extr_patrn)))
                self.extr_patrn = extr_patrn

            # Parsing `hash_path`
            if hash_path:
                hash_path = os.path.abspath(self._to_unicode(hash_path))
                hash_dir = os.path.dirname(hash_path)
                assert ((not os.path.isdir(hash_path)) and \
                        os.access(hash_dir, os.W_OK)), \
                       self._hash_usage(206, varname='hash_path')
                self.hash_path = hash_path
                self.hash_dir = hash_dir

                if os.access(self.hash_path, os.F_OK):
                    assert os.access(self.hash_path, os.W_OK), \
                           self._hash_usage(207, varname='hash_path')
                    usr_in = ''
                    while usr_in.lower() not in ('a', 'o'):
                        usr_in = raw_input(self._hash_usage(251, False, \
                                        filepath=self._to_str(self.hash_path)))
                        assert (usr_in != '' and usr_in.lower() != 'q'), \
                               self._hash_usage(15)
                    self._save_mode = 'a' if usr_in == 'a' else 'w'
                self._save_flag = True

            # Parsing `hash_algos`
            assert isinstance(hash_algos, list), self._hash_usage(12, \
                   varname='hash_algos', varval=self._to_str(hash_algos))
            chked_hash_algos = []
            for hash_algo in hash_algos:
                if hash_algo in chked_hash_algos:
                    continue
                if hash_algo in self._valid_hash_algos:
                    chked_hash_algos.append(hash_algo)
                else:
                    raise AssertionError(self._hash_usage(12, varname=\
                                 'hash_algos', varval=self._to_str(hash_algo)))
            self.hash_algos.extend(chked_hash_algos)
        else:
            assert (src_strings is None and src_files is None \
                    and src_dirs is None and src_list is None), \
                   self._hash_usage(202)

            assert (hash_path is not None or hash_list is not None), \
                   self._hash_usage(203)

            # Parsing `hash_path`
            if hash_path:
                hash_path = os.path.abspath(self._to_unicode(hash_path))
                assert (os.path.isfile(hash_path) and \
                        os.access(hash_path, os.R_OK)), \
                       self._hash_usage(210, filepath=\
                                        self._to_str(hash_path))
                self.hash_path = hash_path
                self.hash_dir = os.path.dirname(self.hash_path)

            # Parsing `hash_list`
            if hash_list:
                hash_list = os.path.abspath(self._to_unicode(hash_list))
                assert (os.path.isfile(hash_list) and \
                        os.access(hash_list, os.R_OK)), \
                       self._hash_usage(210, filepath=\
                                        self._to_str(hash_list))
                self.hash_list = hash_list
                assert (hash_path is not None or hash_algos is not None), \
                       self._hash_usage(208)

            # Parsing `exist_only`
            if exist_only:
                assert isinstance(exist_only, bool), self._hash_usage(11, \
                       varname='exist_only', vartype='bool')
                self.exist_only = exist_only

            # Parsing `verbose`
            if verbose:
                assert isinstance(verbose, bool), self._hash_usage(11, \
                       varname='verbose', vartype='bool')
                self.verbose = verbose

            # Parsing `hash_algos`
            if isinstance(hash_algos, list):
                if len(hash_algos) == 1 \
                   and hash_algos[0] in self._valid_hash_algos:
                    self.hash_algos.append(hash_algos[0])
                else:
                    raise AssertionError(self._hash_usage(213, varval=\
                                         self._to_str(hash_algos)))
            elif hash_algos is None:
                hash_extname = self._get_file_extname(self.hash_path or '')[2]
                if hash_extname in self._ext_map:
                    self.hash_algos.append(self._ext_map[hash_extname])
                else:
                    raise AssertionError(self._hash_usage(201, extname=\
                                         self._to_str(hash_extname)))
            else:
                raise AssertionError(self._hash_usage(12, varname=\
                                'hash_algos', varval=self._to_str(hash_algos)))

        # Parsing `hash_buf_siz`
        if hash_buf_siz:
            assert isinstance(hash_buf_siz, int), \
                   self._hash_usage(11, varname='hash_buf_siz', vartype='int')
            self.hash_buf_siz = hash_buf_siz

        # Parsing `hash_log`
        if hash_log:
            hash_log = os.path.abspath(self._to_unicode(hash_log))
            assert ((not os.path.isdir(hash_log)) and \
                    os.access(os.path.dirname(hash_log), os.W_OK)), \
                   self._hash_usage(206, varname='hash_log')
            self.hash_log = hash_log

            if os.access(self.hash_log, os.F_OK):
                assert os.access(self.hash_log, os.W_OK), \
                       self._hash_usage(207, varname='hash_log')
                usr_in = ''
                while usr_in.lower() not in ('a', 'o'):
                    usr_in = raw_input(self._hash_usage(251, False, \
                                       filepath=self._to_str(self.hash_log)))
                    assert (usr_in != '' and usr_in.lower() != 'q'), \
                           self._hash_usage(15)
                self._log_mode = 'a' if usr_in == 'a' else 'w'
            self._log_flag = True

        # Parsing `tee`
        if tee:
            assert isinstance(tee, bool), self._hash_usage(11, \
                   varname='tee', vartype='bool')
            self.tee = tee

        # Debug Message
        """
        from pprint import pprint
        pprint(dict(action=self.action, src_strings=self.src_strings, \
                    src_files=self.src_files, src_dirs=self.src_dirs, \
                    src_list=src_list, recursive=self.recursive, \
                    hash_algos=self.hash_algos, uppercase=self.uppercase, \
                    extract=self.extract, extr_patrn=self.extr_patrn.pattern, \
                    hash_path=self.hash_path, hash_list=hash_list, \
                    exist_only=self.exist_only, verbose=self.verbose, \
                    encoding=encoding, newline=self._newline, \
                    hash_log=self.hash_log, _log_flag=self._log_flag, \
                    _log_mode=self._log_mode, _save_flag=self._save_flag, \
                    _save_mode=self._save_mode, hash_buf_siz=\
                    self.hash_buf_siz, tee=self.tee))
        raise AssertionError('-------DEBUG-------')
        """
    # End of __init__

    def _get_hash_obj(self, hash_algo):
        """Return the object of hash algorithm"""
        if hash_algo == 'crc32':
            return HashCRC32()
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

    def _calculate(self, tmp_fps=None, log_fp=None):
        """Calculate the hash according to the given arguments."""

        def _get_rst_fmt(hash_algo, index):
            """Return the corresponding output format."""
            rst_fmt = (
                '*"%(item)s"\t%(hash)s%(nl)s',
                ('%(item)s\t*%(hash)s%(nl)s' if hash_algo == 'crc32' \
                                             else '%(hash)s *%(item)s%(nl)s'),
                ('%(item)s\t*%(hash)s%(nl)s' if hash_algo == 'crc32' \
                                             else '%(hash)s *%(item)s%(nl)s'),
            )

            return rst_fmt[index]
        # End of _get_rst_fmt

        fp_ptr = None
        tmp_fps = {} if (tmp_fps is None \
                         or isinstance(tmp_fps, dict) is False) else tmp_fps
        hash_rst = ''
        obj_list = (self.src_strings, self.src_files, self.src_dirs)
        calc_meth = (self._calc_str_hash, self._calc_file_hash, \
                     self._calc_file_hash)
        header_fmt = '*%(nl)s* %(header)s%(nl)s*%(nl)s'
        newline = '\n'#self._newline

        for src_idx in range(len(obj_list)):
            for src_obj in obj_list[src_idx]:
                src_obj_dir = src_obj[0]
                src_header = (header_fmt % {'header': src_obj_dir, \
                                            'nl': newline}) \
                             if src_idx == 2 else None
                if src_header is not None:
                    fp_ptr = tmp_fps.get(self.hash_algos[0]) or log_fp
                    self._print(self._to_str(src_header), fp_ptr, end='')
                    src_header = fp_ptr = None

                for src_item in src_obj[1]:
                    src_item_text = src_item if src_idx != 1 \
                                             else os.path.basename(src_item)
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

                    for hash_algo in self.hash_algos:
                        fp_ptr = tmp_fps.get(hash_algo) or log_fp
                        hash_rst = _get_rst_fmt(hash_algo, src_idx) \
                                   % {'item': src_item_text, \
                                      'hash': hash_codes[hash_algo], \
                                      'nl': newline}
                        self._print(self._to_str(hash_rst), fp_ptr, end='')

                    self.proc_ok += 1
                    hash_rst = ''
    # End of _calculate

    def _extract_hash(self, tmp_fps=None, log_fp=None):
        """Extract hash info from filenames."""
        fp_ptr = None
        tmp_fps = {} if (tmp_fps is None \
                         or isinstance(tmp_fps, dict) is False) else tmp_fps
        hash_rst = ''
        obj_list = (self.src_strings, self.src_files, self.src_dirs)
        header_fmt = '*%(nl)s* %(header)s%(nl)s*%(nl)s'
        rst_fmt = '%(item)s\t*%(hash)s%(nl)s'
        newline = '\n'#self._newline

        for src_idx in range(len(obj_list)):
            for src_obj in obj_list[src_idx]:
                src_obj_dir = src_obj[0]
                src_header = (header_fmt % {'header': src_obj_dir, \
                                            'nl': newline}) \
                             if src_idx == 2 else None
                if src_header is not None:
                    fp_ptr = tmp_fps.get(self.hash_algos[0]) or log_fp
                    self._print(self._to_str(src_header), fp_ptr, end='')
                    src_header = fp_ptr = None

                for src_item in src_obj[1]:
                    src_item_text = src_item if src_idx != 1 \
                                             else os.path.basename(src_item)
                    src_item = os.path.basename(src_item)

                    hash_code = self.extr_patrn.search(src_item)
                    if hash_code:
                        fp_ptr = tmp_fps.get(self.hash_algos[0]) or log_fp
                        hash_code = hash_code.groupdict()['hash']
                        hash_rst = rst_fmt % {'item': src_item_text, \
                                              'hash': hash_code,\
                                              'nl': newline}
                        self._print(self._to_str(hash_rst), fp_ptr, end='')
                        self.proc_ok += 1
                    else:
                        self._print(self._hash_usage(236, False, line=\
                                    self._to_str(src_item_text)), log_fp)
                        self.proc_fail += 1
                    hash_rst = ''
    # End of _extract_hash

    def _verify(self, log_fp=None):
        """Verify the hash according to the given arguments."""
        VFY_RESULT = {1: 'Found', 2: 'OK', 3: 'FAIL'}

        with open(self.hash_path, 'r') as fp:
            for line in fp:
                line = self._to_unicode(line)
                if line.startswith(u'*') is False \
                   and self._pat_empty_line.search(line) is None:
                    self.vfy_files.append(line)

        result = 3
        hash_algo = self.hash_algos[0]
        for item in self.vfy_files:
            item_rst = self._pat_hash_item[hash_algo].search(item)
            if item_rst:
                item = item_rst.groupdict()
                filepath = self._get_file_path(self.hash_dir, item['file'])
                filetext = item['file']
            else:
                item_rst = self._pat_err_line.search(item)
                item = item_rst.group(0) if item_rst else item
                self._print(self._hash_usage(235, False, line=\
                            self._to_str(item)), log_fp)
                self.proc_nofnd += 1
                continue

            if os.path.isfile(self.hash_path) and os.access(filepath, os.R_OK):
                if self.exist_only:
                    result = 1
                    self.proc_found += 1
                elif item['hash'].lower() == \
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

        self.total_item += len(self.vfy_files)
    # End of _verify

    def _verify_hash_list(self, log_fp):
        """Verify the hash according to the list"""
        hash_list_dir = os.path.dirname(self.hash_list)
        hash_list_u = []
        with open(self.hash_list, 'r') as fp:
            for line in fp:
                line = self._to_unicode(line)
                if line.startswith(u'*') is False \
                   and self._pat_empty_line.search(line) is None:
                    hash_file = self._pat_file_line.search(line)
                    if hash_file:
                        hash_file = hash_file.groupdict()
                        hash_list_u.append(hash_file['file'])
                    else:
                        self._print(self._hash_usage(235, False, \
                                    line=self._to_str(line)), log_fp)

        for item in hash_list_u:
            self.hash_path = self._get_file_path(hash_list_dir, item)
            if not (os.path.isfile(self.hash_path) and \
                    os.access(self.hash_path, os.R_OK)):
                self._print(self._hash_usage(210, False, filepath=\
                            self._to_str(self.hash_path)), log_fp)
                continue
            self.hash_dir = os.path.dirname(self.hash_path)

            self.vfy_files = []
            self._verify(log_fp)
    # End of _verify_hash_list

    def __call__(self):
        try:
            tmp_fps = {}
            log_fp = SplTmpFile() if self._log_flag else None

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
    """Signal Handker for signal interrupt"""
    usage = UsageHandler()
    raise AssertionError('\n' + usage(15))
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
                        metavar='SRC_LIST', \
                        help=usage(119, False))
    parser.add_argument('-r', '--recursive', dest='recursive', \
                        action='store_true', help=usage(114, False))
    parser.add_argument('-a', '--algorithm', \
                        choices=['crc32', 'md5', 'sha1', 'sha224', \
                                 'sha256', 'sha384', 'sha512'], \
                        dest='hash_algos', metavar='ALGORITHM', \
                        action='append', help=usage(103, False))
    parser.add_argument('-u', '--uppercase', dest='uppercase', \
                        action='store_true', help=usage(106, False))
    parser.add_argument('-X', '--extract', dest='extract', \
                        action='store_true', help=usage(125, False))
    parser.add_argument('-p', '--extr_patrn', dest='extr_patrn', \
                        metavar='PATTERN', help=usage(126, False))
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
                        version=m_usage(101, False, prog='hashcalc'))
    parser.add_argument('action', choices=['c', 'calculate', 'v', 'verify'], \
                        metavar='ACTION', action=HashCalcAction, \
                        help=usage(108, False))

    return parser.parse_args()
# End of main_parse_args

if __name__ == '__main__':
    """Main function to parsing arguments and error handling."""
    warnings.simplefilter('ignore')
    m_usage = MainUsageHandler()
    m_rst = [True, '']
    m_def_enc = 'utf8'

    try:
        # Setup signal handler (SIGINT, Interrupt)
        signal.signal(signal.SIGINT, sig_int_handler)

        # Use module argparse to parse arguments.
        m_args = main_parse_args(m_usage)

        # Check arguments
        if m_args.action == 'c':
            assert (m_args.hash_algos is not None \
                    or m_args.extract is not None), m_usage(111)
            assert (m_args.src_strings is not None \
                    or m_args.src_files is not None \
                    or m_args.src_dirs is not None \
                    or m_args.src_list is not None), m_usage(112)
            assert (m_args.hash_list is None), m_usage(117)
        else:
            assert (m_args.src_strings is None and m_args.src_files is None \
                    and m_args.src_dirs is None and m_args.src_list is None), \
                   m_usage(109)
            assert (m_args.hash_path is not None or \
                   m_args.hash_list is not None), m_usage(110)
            if m_args.hash_list:
                assert (m_args.hash_path is not None or \
                       m_args.hash_algos is not None), m_usage(121)
        m_hashcalc_param = {
            'src_strings': m_args.src_strings,
            'src_files': m_args.src_files,
            'src_dirs': m_args.src_dirs,
            'src_list': m_args.src_list,
            'recursive': m_args.recursive,
            'hash_algos': m_args.hash_algos,
            'uppercase': m_args.uppercase,
            'extract': m_args.extract,
            'extr_patrn': m_args.extr_patrn,
            'hash_path': m_args.hash_path,
            'hash_list': m_args.hash_list,
            'exist_only': m_args.exist_only,
            'verbose': m_args.verbose,
            'encoding': m_args.encoding,
            'hash_log': m_args.hash_log,
            'action': m_args.action,
            'hash_buf_siz': None,
            'tee': m_args.tee,
        }

        # Create HashCalculator object and do the action
        m_hash_obj = HashCalculator(**m_hashcalc_param)
        m_hash_obj()
    except (StandardError, KeyboardInterrupt) as se:
        m_rst[0] = False
        #m_exc_type, m_exc_obj, m_tb_obj = sys.exc_info()
        # NOTE(leonard): Uncomment the following two lines to show the full
        #                traceback info.
        #from pprint import pprint
        #pprint(traceback.extract_tb(sys.exc_info()[-1]))
        m_tb_obj = traceback.extract_tb(sys.exc_info()[-1])[-1]
        m_exc_type = type(se)
        if m_exc_type is AssertionError:
            m_rst[1] = (se.message or str(se.args))
        elif m_exc_type is KeyboardInterrupt:
            m_rst[1] = '\n' + m_usage(15)
        else:
            m_rst[1] = m_usage(3, filename=m_tb_obj[0], \
                               line=str(m_tb_obj[1]), \
                               exctype=m_exc_type.__name__, \
                               excmsg=(se.message or str(se.args)))

    # Main Error Handling
    if m_rst[0] is False:
        print (m_rst[1] if not isinstance(m_rst[1], unicode) \
                        else m_rst[1].encode(m_def_enc, 'ignore'))
    else:
        print m_usage(115, False)
        m_getch = (CharCatcher())()
# End of __main__
