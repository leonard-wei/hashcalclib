#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# python version: 2.7.5 final, serial: 0

import argparse
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


class UsageHandler(object):
    """Handle usage message, msgid: 0~10 reserved."""

    USAGE_HEADER = 'usage: %(msg)s'
    SP = '\x20\x20\x20\x20'
    HR =  '----------'
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
            101: '%(prog)s - 1.0 (Python 2.7.5 final) '\
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
                 'will be used to calculate the file hash. The '\
                 'valid arguments(the corresponding extension '\
                 'name) are "crc32"(*.sfv), "md5"(*.md5), "sha1"'\
                 '(*.sha1), "sha224"(*.sha224), "sha256"(*.sha256'\
                 '), "sha384"(*.sha384), "sha512"(*.sha512).',
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
            115: '\nPress Any Key to Continue...',
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
            119: 'The specified must contain the strings(start with '\
                 '"STRING="), paths of any files or a directory. '\
                 'This is similar to a combination of the "-s", "-f" '\
                 'and "-d" option, but only available when ACTION is '\
                 '"c". Useful when the cli environment could not '\
                 'support unicode properly or batch Calculation.'\
                 ' If "-s", "-f" or "-d" are specified, it will also try to '\
                 'process them. Note that if the list file contain mutiple '\
                 'directory, it will only take the last one. And if "-d" is '\
                 'also specified, it will take precedence. '\
                 'A line start with "*" is considered as a comment.',
            120: 'Save the output messages to the specified log file',
            121: '\n' + SP + 'When action is "v" and only "-l" option is '\
                 'specified, the "-a" option is required.',
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
# End of MainUsageHandler


class HashUsageHandler(UsageHandler):
    """HashUsageHandler"""

    def __init__(self, *args, **kwargs):
        super(HashUsageHandler, self).__init__(*args, **kwargs)
        SP = self.SP
        HR = self.HR
        TITLE = 'Hash Calculator'
        HR_TITLE = HR * 2 + HR[0] * len(TITLE)
        messages = {
            201: '\n' + SP + 'Invalid extension name of hash file: '\
                 '"%(extname)s".',
            202: '\n' + SP + 'When action is "v", the "src_strings", '\
                 '"src_files", "src_dirs and "src_list" are not allowed.',
            203: '\n' + SP + 'When action is "v", the "hash_path" or '\
                 '"hash_list" is required.',
            204: '\n' + SP + 'When action is "c", the "hash_algo" '\
                 'is required.',
            205: '\n' + SP + 'When action is "c", the "src_strings", '\
                 '"src_files", "src_dirs" or "src_list" are required.',
            206: '\n' + SP + 'The file specified in "%(varname)s" is a '\
                 'directory or the path is unable to write.',
            207: '\n' + SP + 'The file specified in "%(varname)s" already '\
                 'exists and could not get the write permission.',
            208: '\n' + SP + 'When action is "v" and only "hash_list" is '\
                 'specified, the "hash_algo" is required.',
            209: '\n' + SP + 'The "src_dirs" must be a directory.',
            210: '"%(filepath)s" not found, not a file or no privileges.',
            211: 'UnicodeDecodeError: "%(string)r"',
            212: '\n' + SP + 'When action is "c", the "hash_list" '\
                 'is not allowed.',
            230: HR * 1 + TITLE + HR * 1,
            231: 'Start Date: %(stime)s\n\n' + HR_TITLE ,
            232: '\n' + HR_TITLE + '\nOK: %(ok)d | FAIL: %(fail)d | '\
                 'Total Items: %(total)d\nElapsed Time: %(etime).1f seconds',
            233: 'Output File: %(filepath)s',
            234: '%(result)s\t: %(filename)s',
            235: '"%(line)s" invalid format.',
            251: '*WARNING* "%(filepath)s" already exists. Append, Overwrite '\
                 'or Quit(a/o/Q)? ',
        }
        self.USAGE_MSG.update(messages)
    # End of __init__
# End of MainUsageHandler


class ProgressBar(object):
    """
    Print and update the progress bar on cli
    `prog_prec`:    If not specified, default is 0. 1 means the percentage
                    of progress would be 'nnn.n%', and 2 means 'nnn.nn%', ...
                    etc.
    `bar_len`:      Determine the length of progress bar.
    `bar_style`:    A list to determine the style of progress bar. Default
                    ['[', '=', '>', '.', ']'] means '[==>.......]'.
    """

    _pb_usage = ProgressUsageHandler()
    _prog_prec = 0
    _prog_fmt = None
    _bar_len = 10
    _bar_style = ['[', '=', '>', '.', ']']

    def __init__(self, prog_prec=None, bar_len=None, bar_style=None):
        if prog_prec:
            self._prog_prec = prog_prec
            assert isinstance(self._prog_prec, int), self._pb_usage(11, \
                   varname='prog_prec', vartype='int')
        if bar_len:
            self._bar_len = bar_len
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

        self._prog_fmt = '\r' + self._bar_style[0] + '%s' + \
                         self._bar_style[4] + ' %3.' + \
                         str(self._prog_prec) + 'f%%'
    # End of __init__

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
        sys.stdout.write(prog_str)
        sys.stdout.flush()
        #print "%3d%%\r\b" % (progress * 100)
        if progress == 1:
            sys.stdout.write('\r' + ' ' * len(prog_str) + '\r')
            sys.stdout.flush()
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
    `hash_algo`:    Hash algorithm.
    `uppercase`:    Return uppercase hash code if True,
    `hash_path`:    Hash file path.
    `hash_list`:    Hash file list.
    `encoding`:     Try to use the specified encoding to decode first.
    `hash_log`:     Save output messages to the specified file.
    `hash_buf_siz`: Hash buffer size when calculate, default is 1048576 bytes.
    """

    _hash_usage = HashUsageHandler()
    _pat_file_ext = re.compile(r"^(?P<main>.+)(?P<sep>\.)(?P<ext>[^\n\.]+)$")
    _valid_hash_algo = ('crc32', 'md5', 'sha1', 'sha224', 'sha256', \
                       'sha384', 'sha512')
    _ext_map = {
        'sfv': _valid_hash_algo[0],
        'md5': _valid_hash_algo[1],
        'sha1': _valid_hash_algo[2],
        'sha224': _valid_hash_algo[3],
        'sha256': _valid_hash_algo[4],
        'sha384': _valid_hash_algo[5],
        'sha512': _valid_hash_algo[6],
    }
    _pat_hash_str = r"<hash>[0-9A-Za-z]"
    _pat_file_str = r"<file>[^\?\t\v\r\n\f]+"
    _pat_sep_str = r"\t+|\x20+"
    _pat_crc32_str = r"^(?P%s)(?:%s)\*?(?P%s{8})(?:[\s]*)$" \
                     % (_pat_file_str, _pat_sep_str, _pat_hash_str)
    _pat_hashlib_str = r"^(?P%s{%s})(?:%s)\*?(?P%s)(?:[\s]*)$" \
                       % (_pat_hash_str, r"%s", _pat_sep_str, _pat_file_str)
    _pat_hash_item = {
        _valid_hash_algo[0]: re.compile(_pat_crc32_str, re.U),
        _valid_hash_algo[1]: re.compile(_pat_hashlib_str % ("32"), re.U),
        _valid_hash_algo[2]: re.compile(_pat_hashlib_str % ("40"), re.U),
        _valid_hash_algo[3]: re.compile(_pat_hashlib_str % ("56"), re.U),
        _valid_hash_algo[4]: re.compile(_pat_hashlib_str % ("64"), re.U),
        _valid_hash_algo[5]: re.compile(_pat_hashlib_str % ("96"), re.U),
        _valid_hash_algo[6]: re.compile(_pat_hashlib_str % ("128"), re.U),
    }
    _pat_file_line = re.compile((r"^(?P%s)(?:[\s]*)$" % (_pat_file_str)), re.U)
    _pat_string_line = re.compile(r"^STRING=(?P<string>[^\r\n]+)(?:[\r\n]*)$",
                                  re.U)
    _pat_empty_line = re.compile(r"^[\r\n]*$", re.U)
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
    hash_algo = None
    uppercase = False
    hash_path = None
    hash_dir = None
    hash_list = None
    vfy_files = []
    proc_ok = 0
    proc_fail = 0
    hash_log = None
    hash_buf_siz = (2 << 19)
    total_item = 0

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
        else:
            return string
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
                src_obj_u.append(_to_unicode_single(item, self._encodings))
        elif isinstance(src_obj, str):
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
            assert os.path.isdir(fdir), self._hash_usage(209)
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

        return (fdir, [])
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
            src_list = os.path.abspath(src_list)
            assert (os.path.isfile(src_list) and \
                    os.access(src_list, os.R_OK)), \
                   self._hash_usage(210, filepath=src_list)

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
            self.src_strings.append((None, src_list_strings))
            self.src_files.append((src_list_loc, src_list_files))
            self._parse_src_dirs(src_list_dirs)
    # End of _parse_src_list

    def __init__(self, action, src_strings=None, src_files=None, \
                 src_dirs=None, src_list=None, recursive=None, \
                 hash_algo=None, uppercase=None, hash_path=None, \
                 hash_list=None, encoding=None, hash_log=None, \
                 hash_buf_siz=None):
        """Initialize and check all arguments."""
        assert (action is not None), self._hash_usage(12, varname='action', \
                                                      varval=str(action))
        self.action = action

        if encoding:
            self._encodings.insert(0, encoding)

        if self.action == 'c':
            assert (hash_list is None), m_usage(212)
            assert not (hash_algo is None), m_usage(204)

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
            if recursive:
                assert isinstance(recursive, bool), \
                       self._hash_usage(11, varname='recursive', \
                                        vartype='bool')
                self.recursive = recursive
            self._parse_src_dirs((src_dirs if isinstance(src_dirs, list) \
                                           else []))
            self._parse_src_list(src_list)
            self.total_item += sum([len(ss[1]) for ss in self.src_strings]) + \
                               sum([len(sf[1]) for sf in self.src_files]) + \
                               sum([len(sd[1]) for sd in self.src_dirs])

            if uppercase:
                assert isinstance(uppercase, bool), self._hash_usage(11, \
                       varname='uppercase', vartype='bool')
                self.uppercase = uppercase

            if hash_path:
                if os.path.isabs(hash_path) is False:
                    hash_path = os.path.abspath(hash_path)
                self.hash_dir = os.path.dirname(hash_path)
                assert ((not os.path.isdir(hash_path)) and \
                        os.access(self.hash_dir, os.W_OK)), \
                       self._hash_usage(206, varname='hash_path')
                self.hash_path = hash_path
                if os.access(self.hash_path, os.F_OK):
                    assert os.access(self.hash_path, os.W_OK), \
                           self._hash_usage(207, varname='hash_path')
                    usr_in = ''
                    while usr_in.lower() not in ('a', 'o'):
                        usr_in = raw_input(self._hash_usage(251, False, \
                                           filepath=self.hash_path))
                        assert (usr_in != '' and usr_in.lower() != 'q'), \
                               self._hash_usage(15)
                    self._save_mode = 'a' if usr_in == 'a' else 'w'
                self._save_flag = True
        else:
            assert (src_strings is None and src_files is None \
                    and src_dirs is None and src_list is None), \
                   self._hash_usage(202)

            assert (hash_path is not None or hash_list is not None), \
                   self._hash_usage(203)
            if hash_path:
                self.hash_path = os.path.abspath(hash_path)
                assert (os.path.isfile(self.hash_path) and \
                        os.access(self.hash_path, os.R_OK)), \
                       self._hash_usage(210, filepath=self.hash_path)
                self.hash_dir = os.path.dirname(self.hash_path)
            if hash_list:
                self.hash_list = os.path.abspath(hash_list)
                assert (os.path.isfile(self.hash_list) and \
                        os.access(self.hash_list, os.R_OK)), \
                       self._hash_usage(210, filepath=self.hash_list)
                assert (hash_path is not None or hash_algo is not None), \
                       self._hash_usage(208)

        if hash_buf_siz:
            assert isinstance(hash_buf_siz, int), \
                   self._hash_usage(11, varname='hash_buf_siz', vartype='int')
            self.hash_buf_siz = hash_buf_siz

        if hash_algo in self._valid_hash_algo:
            self.hash_algo = hash_algo
        elif hash_algo is None:
            hash_extname = self._get_file_extname(self.hash_path or '')[2]
            if hash_extname in self._ext_map:
                self.hash_algo = self._ext_map[hash_extname]
            else:
                raise AssertionError(self._hash_usage(201, extname=\
                                                      str(hash_extname)))
        else:
            raise AssertionError(self._hash_usage(12, varname='hash_algo', \
                                                  varval=str(hash_algo)))

        if hash_log:
            if os.path.isabs(hash_log) is False:
                hash_log = os.path.abspath(hash_log)
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
                                       filepath=self.hash_log))
                    assert (usr_in != '' and usr_in.lower() != 'q'), \
                           self._hash_usage(15)
                self._log_mode = 'a' if usr_in == 'a' else 'w'
            self._log_flag = True
        # Debug Message
        """
        from pprint import pprint
        pprint(dict(action=self.action, src_strings=self.src_strings, \
                    src_files=self.src_files, src_dirs=self.src_dirs, \
                    src_list=str(src_list), recursive=self.recursive, \
                    hash_algo=self.hash_algo, uppercase=self.uppercase, \
                    hash_path=self.hash_path, hash_list=str(hash_list), \
                    encoding=str(encoding), newline=self._newline, \
                    hash_log=self.hash_log, _log_flag=self._log_flag, \
                    _log_mode=self._log_mode, _save_flag=self._save_flag, \
                    _save_mode=self._save_mode, \
                    hash_buf_siz=self.hash_buf_siz))
        raise AssertionError('-------DEBUG-------')
        """
    # End of __init__

    def _print(self, message, log_fp=None, newline=True):
        """Determine the output to stdout or log file"""
        nl = '\n' if newline else ''
        if log_fp:
            log_fp.write(message + nl)
        else:
            sys.stdout.write(message + nl)
            sys.stdout.flush()
    # End of _print

    def _calc_str_hash(self, string):
        """Calculate the hash of the given string."""
        bol_read = True
        sbuf = None
        str_siz = len(string)
        hash_buf_siz = str_siz if str_siz < self.hash_buf_siz \
                               else self.hash_buf_siz
        proc_pos = 0
        progress = 0
        prog_bar = ProgressBar(bar_len=20)

        str_siz = 1.0 if str_siz == 0 else float(str_siz)
        if self.hash_algo == 'crc32':
            hash_obj = HashCRC32()
        else:
            hash_obj = getattr(hashlib, self.hash_algo)()

        while bol_read:
            sbuf = string[proc_pos:(proc_pos + hash_buf_siz)]
            hash_obj.update(self._to_str(sbuf, 'strict'))
            proc_pos += len(sbuf)
            progress = proc_pos / str_siz
            prog_bar.update(progress)
            if not sbuf:
                bol_read = False
                if progress < 1.0:
                    prog_bar.update(1.0)

        hash_code = hash_obj.hexdigest()

        return hash_code if not self.uppercase else hash_code.upper()
    # End of _calc_file_hash

    def _calc_file_hash(self, fpath):
        """Calculate the hash of the given file."""
        bol_read = True
        fpath = fpath if os.path.isabs(fpath) else os.path.abspath(fpath)
        fbuf = None
        file_siz = os.path.getsize(fpath)
        hash_buf_siz = self.hash_buf_siz if (file_siz >> 30) == 0 \
                                         else self.hash_buf_siz << 1
        proc_siz = 0
        progress = 0
        prog_bar = ProgressBar(bar_len=20)

        file_siz = 1.0 if file_siz == 0 else float(file_siz)
        if self.hash_algo == 'crc32':
            hash_obj = HashCRC32()
        else:
            hash_obj = getattr(hashlib, self.hash_algo)()

        with open(fpath, 'rb') as fp:
            while bol_read:
                fbuf = fp.read(hash_buf_siz)
                hash_obj.update(fbuf)
                proc_siz += len(fbuf)
                progress = proc_siz / file_siz
                prog_bar.update(progress)
                if not fbuf:
                    bol_read = False
                    if progress < 1.0:
                        prog_bar.update(1.0)

        hash_code = hash_obj.hexdigest()

        return hash_code if not self.uppercase else hash_code.upper()
    # End of _calc_file_hash

    def _calculate(self, fp=None, log_fp=None):
        """Calculate the hash according to the given arguments."""
        hash_rst = None
        obj_list = (self.src_strings, self.src_files, self.src_dirs)
        calc_meth = (self._calc_str_hash, self._calc_file_hash, \
                     self._calc_file_hash)
        rst_fmt = (
            '*"%(item)s"\t%(hash)s%(nl)s',
            ('%(item)s\t*%(hash)s%(nl)s' if self.hash_algo == 'crc32' \
                                         else '%(hash)s *%(item)s%(nl)s'),
            ('%(item)s\t*%(hash)s%(nl)s' if self.hash_algo == 'crc32' \
                                         else '%(hash)s *%(item)s%(nl)s'),
        )
        header_fmt = '*%(nl)s* %(header)s%(nl)s*%(nl)s'
        newline = '\n'#self._newline

        for src_idx in range(len(obj_list)):
            for src_obj in obj_list[src_idx]:
                src_obj_dir = src_obj[0]
                src_header = (header_fmt % {'header': src_obj_dir, \
                                            'nl': newline}) \
                             if src_idx == 2 else None
                for src_item in src_obj[1]:
                    src_item_text = src_item if src_idx != 1 \
                                             else os.path.basename(src_item)
                    if src_obj_dir is not None:
                        src_item = self._get_file_path(src_obj_dir, src_item)
                    if src_idx != 0 and not (os.path.isfile(src_item) and \
                                             os.access(src_item, os.R_OK)):
                        self._print(self._hash_usage(210, filepath=\
                                    self._to_str(src_item)), log_fp)
                        self.proc_fail += 1
                        continue
                    hash_rst = rst_fmt[src_idx] \
                               % {'item': src_item_text, \
                                  'item_abs': src_item, \
                                  'hash': calc_meth[src_idx](src_item), \
                                  'nl': newline}
                    src_header = self._to_str(src_header)
                    hash_rst = self._to_str(hash_rst)
                    self.proc_ok += 1

                    if self._save_flag and fp:
                        if src_header is not None:
                            fp.write(src_header)
                            src_header = None
                        fp.write(hash_rst)
                    else:
                        if src_header is not None:
                            #sys.stdout.write(src_header)
                            self._print(src_header, log_fp, False)
                            src_header = None
                        #sys.stdout.write(hash_rst)
                        #sys.stdout.flush()
                        self._print(hash_rst, log_fp, False)
    # End of _calculate

    def _verify(self, log_fp=None):
        """Verify the hash according to the given arguments."""
        with open(self.hash_path, 'r') as fp:
            for line in fp:
                line = self._to_unicode(line)
                if line.startswith(u'*') is False \
                   and self._pat_empty_line.search(line) is None:
                    self.vfy_files.append(line)

        result = None
        for item in self.vfy_files:
            item_rst = self._pat_hash_item[self.hash_algo].search(item)
            if item_rst:
                item = item_rst.groupdict()
                filepath = self._get_file_path(self.hash_dir, item['file'])
                filetext = self._to_str(item['file'])
            else:
                self._print(self._hash_usage(235, False, line=\
                            self._to_str(item)), log_fp)
                self.proc_fail += 1
                continue
            if os.access(filepath, os.R_OK):
                if item['hash'].lower() == \
                   self._calc_file_hash(filepath):
                    result = 'OK'
                    self.proc_ok += 1
                else:
                    result = 'FAIL'
                    self.proc_fail += 1
                self._print(self._hash_usage(234, False, filename=filetext, \
                            result=result), log_fp)
            else:
                self._print(self._hash_usage(210, False, filepath=filetext), \
                            log_fp)
                self.proc_fail += 1
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
                        self._print(self._hash_usage(235, \
                                                     line=self._to_str(line)))

        for item in hash_list_u:
            self.hash_path = self._get_file_path(hash_list_dir, item)
            assert (os.path.isfile(self.hash_path) and \
                    os.access(self.hash_path, os.R_OK)), \
                   self._hash_usage(210, filepath=self._to_str(self.hash_path))
            self.hash_dir = os.path.dirname(self.hash_path)

            self.vfy_files = []
            self._verify(log_fp)
    # End of _verify_hash_list

    def __call__(self):
        try:
            log_fp = open(self.hash_log, self._log_mode) if self._log_flag \
                                                         else None

            self._print(self._hash_usage(230, False), log_fp)
            stime = time.time()
            self._print(self._hash_usage(231, False, stime=time.ctime(stime)),
                        log_fp)

            if self.action == 'c':
                if self._save_flag:
                    with open(self.hash_path, self._save_mode) as fp:
                        self._calculate(fp, log_fp)
                    self._print(self._hash_usage(233, filepath=\
                                self._to_str(self.hash_path)), log_fp)
                else:
                    self._calculate(log_fp=log_fp)
            else:
                if self.hash_path:
                    self._verify(log_fp)
                if self.hash_list:
                    self._verify_hash_list(log_fp)

            etime = time.time() - stime
            self._print(self._hash_usage(232, False, ok=self.proc_ok, \
                        fail=self.proc_fail, total=self.total_item, \
                        etime=etime), log_fp)
        finally:
            if log_fp:
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
    """Parsing arguments"""
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
                        dest='hash_algo', metavar='ALGORITHM', \
                        help=usage(103, False), required=False)
    parser.add_argument('-u', '--uppercase', dest='uppercase', \
                        action='store_true', help=usage(106, False))
    parser.add_argument('-o', '--hash-file', dest='hash_file', \
                        metavar='HASH_FILE', help=usage(102, False))
    parser.add_argument('-l', '--hash-list', dest='hash_list', \
                        metavar='HASH_LIST', help=usage(116, False))
    parser.add_argument('-e', '--encoding', dest='encoding', \
                        metavar='ENCODING', help=usage(118, False))
    parser.add_argument('-L', '--log', dest='hash_log', \
                        metavar='HASH_LOG', help=usage(120, False))
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
            assert not (m_args.hash_algo is None), m_usage(111)
            assert (m_args.src_strings is not None or m_args.src_files \
                   is not None or m_args.src_dirs is not None or \
                   m_args.src_list is not None), m_usage(112)
            assert (m_args.hash_list is None), m_usage(117)
        else:
            assert (m_args.src_strings is None and m_args.src_files is None \
                    and m_args.src_dirs is None and m_args.src_list is None), \
                   m_usage(109)
            assert (m_args.hash_file is not None or \
                   m_args.hash_list is not None), m_usage(110)
            if m_args.hash_list:
                assert (m_args.hash_file is not None or \
                       m_args.hash_algo is not None), m_usage(121)
        m_hashcalc_param = {
            'src_strings': m_args.src_strings,
            'src_files': m_args.src_files,
            'src_dirs': m_args.src_dirs,
            'src_list': m_args.src_list,
            'recursive': m_args.recursive,
            'hash_algo': m_args.hash_algo,
            'uppercase': m_args.uppercase,
            'hash_path': m_args.hash_file,
            'hash_list': m_args.hash_list,
            'encoding': m_args.encoding,
            'hash_log': m_args.hash_log,
            'action': m_args.action,
            'hash_buf_siz': None,
        }

        # Create HashCalculator object and do the action
        m_hash_obj = HashCalculator(**m_hashcalc_param)
        m_hash_obj()
    except (StandardError, KeyboardInterrupt) as se:
        m_rst[0] = False
        #m_exc_type, m_exc_obj, m_tb_obj = sys.exc_info()
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

    if m_rst[0] is False:
        print (m_rst[1] if not isinstance(m_rst[1], unicode) \
                        else m_rst[1].encode(m_def_enc, 'ignore'))
    else:
        print m_usage(115, False)
        m_getch = (CharCatcher())()
# End of __main__
