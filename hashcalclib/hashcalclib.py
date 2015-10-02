#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# python version: 2.7.5 final, serial: 0
# Author: Leonard Wei <gooxxgle.mail@gmail.com>

"""Hash calculation library

This module is an hash calculation library that:
    - calculate the input strings or files
    - output the result for later verification
    - supports two output format
    - both calculation and verification support file filter
    - supports many well-known hash algorithms
    - supports extracting the hash from file name

A simple usage example:
    1.
        hcKwargs = {
            'action': 'c',
            'algorithms': ['crc32', 'md5']
            'srcFiles': ['filename1', 'filename2'],
            'srcDirs': ['dir1', 'dir2'],
        }
        hcObj = HashCalculator(**hcKwargs)
        hcObj()
    2.
        hcObj = HashCalculator('c')
        hcObj.setAlgorithms(['crc32', 'md5'])
        hcObj.addSrcFiles(['filename1', 'filename2'])
        hcObj.addSrcDirs(['dir1', 'dir2'])
        hcObj.actAuto()
    3.
        hcObj = HashCalculator('v')
        hcObj.parseHashFile('hashfile.md5')
        hcObj.actAuto()

Instead of letting the class do all the jobs, you can get the result
and do whatever you want(the result would be a object of `HashStock`
class, see the section of the class for more details):
        hcObj = HashCalculator('c')
        hcObj.setAlgorithms(['crc32', 'md5'])
        hcObj.addSrcFiles(['filename1', 'filename2'])
        hcObj.addSrcDirs(['dir1', 'dir2'])
        hcObj.act()
        hcObj.getResult()

Note:
    1.If you want to add all files under a directory recursively,
      remember to call `setRecursive(True)` before you call
      `addSrcDirs()`.
"""

import codecs
import fnmatch
import hashlib
import inspect
import os
import re
import stat
import sys
import time
import zlib
from contextlib import closing
from ctypes import c_uint
from StringIO import StringIO
from tempfile import SpooledTemporaryFile as SpooledTmpFile

try:
    import pyblake2
    _isPyblake2Imported = True
except ImportError:
    _isPyblake2Imported = False
try:
    import sha3
    _isSha3Imported = True
except ImportError:
    _isSha3Imported = False

from commonutil import joinExceptionArgs, getExceptionMsg, str_, unicode_, \
                       getAbsPath, Enum, UsageHandler, ProgressBar


__all__ = [
    'BaseHashlib',
    'CRC32',
    'Adler32',
    'ED2k',
    'HashStock',
    'HashCalculator',
    'FileInfo',
]


class Error(Exception):
    """Base class for exceptions in this module."""
    pass
# end of Error


def affirm(condition, *args):
    """Like "assert" but raise the exceptions defined in this module."""
    if not condition:
        EXCEPTION_BASE_CLASS = Error
        argStartIdx = 0
        exceptionClass = EXCEPTION_BASE_CLASS

        if 0 < len(args) and inspect.isclass(args[0]) \
           and issubclass(args[0], EXCEPTION_BASE_CLASS):
            argStartIdx = 1
            exceptionClass = args[0]

        raise exceptionClass(*args[argStartIdx:])
# end of affirm


class BaseHashlib(object):
    """Use to transform other hash functions into hashlib-like class."""

    _hashFunc = None
    _hash = None
    digest_size = 0
    block_size = 0

    def __init__(self):
        if not callable(self._hashFunc):
            self._hashFunc = self._dummyHashFunc
            raise NotImplementedError('_hashFunc')
        else:
            self.update('')
    # end of __init__

    def _dummyHashFunc(self, data=0, value=0):
        pass
    # end of _dummyHashFunc

    def update(self, data):
        self._hash = self._hashFunc(data, self._hash) \
                     if self._hash is not None else self._hashFunc(data)
    # end of update

    def digest(self):
        hexStr = self.hexdigest()
        pack = __import__('struct').pack

        return ''.join(pack('B', int(hexStr[idx:idx + 2], 16)) \
                       for idx in range(0, len(hexStr), 2))
    # end of digest

    def hexdigest(self):
        return '%.8x' % (c_uint(self._hash).value)
    # end of hexdigest

    def copy(self):
        newObj = type(self)()
        newObj._hash = self._hash

        return newObj
    # end of copy
# end of BaseHashlib


class CRC32(BaseHashlib):
    """Transform the zlib.crc32 into hashlib-like class."""

    def __init__(self):
        self._hashFunc = getattr(zlib, 'crc32')
        self.digest_size = 4
        self.block_size = 4
        super(CRC32, self).__init__()
    # end of __init__
# end of CRC32


class Adler32(BaseHashlib):
    """Transform the zlib.adler32 into hashlib-like class."""

    _PRIME_NUM = 65521

    def __init__(self):
        self._hashFunc = getattr(zlib, 'adler32')
        self.digest_size = 4
        self.block_size = 4
        super(Adler32, self).__init__()
    # end of __init__

    def concatenate(self, initialHash, hashSegments):
        """
        Concatenate two hashes calculated from a continuous data
        into one.
        `initialHash`:  Either an integer or a hex string.
        `hashSegments`: It should be a list like:
                        [(hash1, dataSize1), (hash2, dataSize2), ...].
                        "dataSizeN" is the Nth data size in bytes(target
                        window length in the header of a delta file).
        """
        def checkArg(arg, isHash=True):
            if isinstance(arg, (int, long)):
                return arg
            elif isHash and isinstance(arg, basestring):
                return int(arg, 16)
            raise TypeError(arg)

        getLowWord = lambda dword: c_uint(dword - 1).value & 0xffff
        hashSegments = hashSegments if isinstance(hashSegments, list) else []
        currentHash = checkArg(initialHash)

        for nextHash, nextDataSize in hashSegments:
            nextHash = checkArg(nextHash)
            nextDataSize = checkArg(nextDataSize, False)
            lowWord = (1 + getLowWord(currentHash) + getLowWord(nextHash)) \
                      % self._PRIME_NUM
            highWord = ((currentHash >> 16) + (nextHash >> 16) \
                + getLowWord(currentHash) * nextDataSize) % self._PRIME_NUM
            currentHash = (highWord << 16) + lowWord

        return currentHash
    # end of concatenate
# end of Adler32


class ED2k(object):
    """eDonkey2000/eMule(md4 based)"""

    _CHUNK_SIZE = 9728000
    _newMd4Obj = None
    _hashObj = None
    _chunkHashes = None
    _chunkIdx = 0
    digest_size = 0
    block_size = 0

    def __init__(self):
        self._newMd4Obj = lambda: hashlib.new('md4')
        self._hashObj = self._newMd4Obj()
        self._chunkHashes = []
        self.digest_size = self._hashObj.digest_size
        self.block_size = self._hashObj.block_size
    # end of __init__

    def _updateChunkHash(self):
        self._chunkHashes.append(self._hashObj.digest())
        self._chunkIdx = 0
        self._hashObj = self._newMd4Obj()
    # end of _updateChunkHash

    def update(self, data):
        dataSize = len(data)
        remainingChunkSize = 0
        dataIdx = 0

        while dataIdx != dataSize:
            if (self._chunkIdx + dataSize - dataIdx) > self._CHUNK_SIZE:
                remainingChunkSize = self._CHUNK_SIZE - self._chunkIdx
                self._hashObj.update(data[dataIdx:(dataIdx + \
                                                   remainingChunkSize)])
                self._updateChunkHash()
                dataIdx += remainingChunkSize
            else:
                self._hashObj.update(data[dataIdx:])
                self._chunkIdx += dataSize - dataIdx
                dataIdx = dataSize
                if self._chunkIdx == self._CHUNK_SIZE:
                    self._updateChunkHash()
    # end of update

    def _getHashValue(self, valueType):
        if 1 < len(self._chunkHashes):
            md4Obj = self._newMd4Obj()
            for data in self._chunkHashes:
                md4Obj.update(data)
            md4Obj.update(self._hashObj.digest())

            return getattr(md4Obj, valueType)()

        return getattr(self._hashObj, valueType)()
    # end of _getHashValue

    def digest(self):
        return self._getHashValue('digest')
    # end of digest

    def hexdigest(self):
        return self._getHashValue('hexdigest')
    # end of hexdigest

    def copy(self):
        newObj = type(self)()
        newObj._chunkHashes.extend(self._chunkHashes)
        newObj._chunkIdx = self._chunkIdx
        newObj._hashObj = self._hashObj.copy()

        return newObj
    # end of copy
# end of ED2k


def _getHashObj(algorithm):
    """Return the object of hash algorithm"""
    obj = None

    if algorithm == 'crc32':
        obj = CRC32()
    elif algorithm == 'adler32':
        obj = Adler32()
    elif algorithm == 'md4':
        obj = getattr(hashlib, 'new')(algorithm)
    elif algorithm == 'ed2k':
        obj = ED2k()
    elif algorithm.startswith('blake2'):
        obj = getattr(pyblake2, algorithm)()
    elif algorithm.startswith('sha3_'):
        obj = getattr(sha3, algorithm)()
    else:
        obj = getattr(hashlib, algorithm)()

    return obj
# end of _getHashObj


class HashStockUsage(UsageHandler):
    """HashStockUsage"""

    def __init__(self):
        super(HashStockUsage, self).__init__()
        messages = {
            401: 'There are no groups. New a group first.',
            402: 'Group index out of range.',
            403: 'There are no sub groups. New a sub group first.',
            404: 'Sub group index out of range.',
        }
        self.MESSAGES.update(messages)
    # end of __init__
# end of HashStockUsage


class HashStock(object):
    """A class to store the result of hashes
    The structure of `_stock` is as following:
        [
            {
                'type_': 0..2
                'dirHeader': '*\n* dir\n*\n',
                'subGroups': [
                    {
                        'newOutputHeader': '*** dir ***\n',
                        'items': [
                            {
                                'item': 'text or file path',
                                'hashes': [
                                    (algorithm, hash),
                                    ...,
                                ]
                            },
                            ...,
                        ]
                    },
                    ...,
                ]
            },
            ...,
        ]

    A simple usage example:
        hashStock = HashStock()
        hashStock.newGroup('*\n* dir\n*\n', '2')
        hashStock.newSubGroup('*** dir ***\n')
        hashStock.addItem('filePath', [('crc32', '00000000')])
        hashStock.addItem(...)
    """

    _GROUPS_TYPE = Enum(('STR', 'FILE', 'DIR'))
    _usage = HashStockUsage()
    _stock = list()
    _currentGroupIdx = None
    _currentSubGroupIdx = None
    _totalGroups = 0
    _stdout = sys.stdout
    _newline = '\n'
    _hashRowFormatMap = {
        'str': ''.join(['*"%(item)s"\t%(hash)s', _newline]),
        'crc32': ''.join(['%(item)s\t*%(hash)s', _newline]),
        'default': ''.join(['%(hash)s *%(item)s', _newline])
    }

    def __init__(self):
        self.reset()
    # end of __init__

    def __len__(self):
        return self._totalGroups
    # end of __len__

    def _getHashRowText(self, item, hash_, algorithm, type_=_GROUPS_TYPE.STR):
        """Return the corresponding hash row text."""
        formatType = 'default'

        if type_ == self._GROUPS_TYPE.STR:
            formatType = 'str'
        elif algorithm == 'crc32':
            formatType = algorithm

        return self._hashRowFormatMap[formatType] \
               % {'item': item, 'hash': hash_}
    # end of _getHashRowText

    def newGroup(self, dirHeader='', type_=1):
        """New and return a new group."""
        affirm(isinstance(dirHeader, basestring), \
               self._usage(11, arg='dirHeader', type_='basestring'))
        affirm(isinstance(type_, int), \
               self._usage(11, arg='type_', type_='int'))

        self._stock.append(\
            dict(type_=type_, dirHeader=dirHeader, subGroups=list()))
        self._currentGroupIdx = self._totalGroups
        self._totalGroups += 1

        return self._stock[-1]
    # end of newGroup

    def getCurrentGroup(self):
        """Return the current group."""
        affirm(self._totalGroups != 0, self._usage(401))
        return self._stock[self._currentGroupIdx]
    # end of getCurrentGroup

    def getGroup(self, index):
        """Return the group of the index and set it to current group."""
        affirm(self._totalGroups != 0, self._usage(401))
        affirm(index < self._totalGroups, self._usage(402))
        self._currentGroupIdx = index
        return self._stock[self._currentGroupIdx]
    # end of getGroup

    def newSubGroup(self, newOutputHeader=''):
        """New and return a new sub group."""
        affirm(isinstance(newOutputHeader, basestring), \
               self._usage(11, arg='newOutputHeader', type_='basestring'))

        subGroups = self.getCurrentGroup()['subGroups']
        subGroups.append(\
            dict(newOutputHeader=newOutputHeader, items=list()))
        self._currentSubGroupIdx = len(subGroups) - 1

        return subGroups[-1]
    # end of newSubGroup

    def getCurrentSubGroup(self):
        """Return the current sub group."""
        subGroups = self.getCurrentGroup()['subGroups']
        totalSubGroup = len(subGroups)
        affirm(totalSubGroup != 0, self._usage(403))
        return subGroups[self._currentSubGroupIdx]
    # end of getCurrentSubGroup

    def getSubGroup(self, index):
        """
        Return the sub group of the index
        and set it to current sub group.
        """
        subGroups = self.getCurrentGroup()['subGroups']
        totalSubGroup = len(subGroups)
        affirm(totalSubGroup != 0, self._usage(403))
        affirm(index < totalSubGroup, self._usage(404))
        self._currentSubGroupIdx = index
        return subGroups[self._currentSubGroupIdx]
    # end of getSubGroup

    def addItem(self, item, hashes):
        """Add an item/hashes to current sub group."""
        affirm(isinstance(item, basestring), \
               self._usage(11, arg='item', type_='basestring'))
        affirm(isinstance(hashes, list) and hashes, \
               self._usage(11, arg='hashes', type_='list'))
        items = self.getCurrentSubGroup()['items']
        items.append(dict(item=item, hashes=hashes))
    # end of addItem

    def getStock(self):
        """Return the `_stock`."""
        return self._stock
    # end of getStock

    def print_(self, file_=None):
        """Print the `_stock` sequentially(default to stdout)."""
        if file_ is not None:
            affirm(isinstance(file_, (file, SpooledTmpFile)), \
                   self._usage(11, arg='file_', \
                               type_='file or TemporaryFile'))
            output = file_
        else:
            output = self._stdout

        for group in self._stock:
            dirHeader = group.get('dirHeader')
            type_ = group.get('type_')
            for subGroup in group['subGroups']:
                newOutputHeader = subGroup.get('newOutputHeader')
                for item in subGroup['items']:
                    for algorithm, hash_ in item['hashes']:
                        if dirHeader:
                            output.write(dirHeader)
                            dirHeader = ''
                        if newOutputHeader:
                            output.write(newOutputHeader)
                            newOutputHeader = ''
                        text = self._getHashRowText(\
                            item['item'], hash_, algorithm, type_)
                        output.write(text)
        output.flush()
    # end of print_

    def save(self, file_):
        """Save the sorted `_stock` to the specified file."""
        affirm(isinstance(file_, (file, SpooledTmpFile)), \
               self._usage(11, arg='file_', type_='file or TemporaryFile'))

        algorithms = []
        tmpFiles = {}
        for group in self._stock:
            dirHeader = group.get('dirHeader')
            type_ = group.get('type_')
            for subGroup in group['subGroups']:
                newOutputHeader = subGroup.get('newOutputHeader')
                for item in subGroup['items']:
                    for algorithm, hash_ in item['hashes']:
                        tmpFile = tmpFiles.get(algorithm)
                        if not tmpFile:
                            tmpFile = tmpFiles[algorithm] = SpooledTmpFile()
                            algorithms.append(algorithm)
                        if dirHeader:
                            tmpFile.write(dirHeader)
                        if newOutputHeader:
                            tmpFile.write(newOutputHeader)
                        tmpFile.write(\
                            self._getHashRowText(item['item'], hash_, \
                                                 algorithm, type_))
                    dirHeader = ''
                    newOutputHeader = ''

        newlineCount = len(algorithms) - 1
        for algorithm in algorithms:
            tmpFile = tmpFiles.get(algorithm)
            tmpFile.seek(0, os.SEEK_SET)
            file_.write(tmpFile.read())
            if 0 < newlineCount:
                file_.write(self._newline)
                newlineCount -= 1
        file_.flush()
    # end of save

    def reset(self):
        """Clear the `_stock`."""
        self._stock[:] = []
        self._currentGroupIdx = None
        self._currentSubGroupIdx = None
        self._totalGroups = 0
    # end of reset
# end of HashStock


class HashCalculatorUsage(UsageHandler):
    """HashCalculatorUsage"""

    def __init__(self):
        super(HashCalculatorUsage, self).__init__()
        HR15 = self.HR * 15
        TITLE = ''.join([HR15, 'Hash Calculator', HR15])
        HR = self.HR * len(TITLE)
        DEBUG = ''.join([HR15, 'DEBUG', HR15])
        messages = {
            201: 'Invalid extension name of hash file("%s") and '\
                 '`algorithms` is not given.',
            202: 'There are no hash algorithms. Call `setAlgorithms()` first.',
            203: '"%s" is a directory or the user has no write privilege.',
            204: '"%s" already exists and the user has no write privilege.',
            205: '"%s" is not a directory or no read privilege.',
            206: 'The algorithm "%(algorithm)s" requires the module '\
                 '"%(module)s" to be installed.',
            207: 'No files/strings could be processed.',
            208: '"%s" is neither a string, a file nor a directory.',
            209: '',
            210: '"%s" is not found, not a file or no read privilege.',
            230: '%s\nStart Date: %s\n\n%s' % (TITLE, '%s', HR),
            231: '\n%s\n%-4s: %s | %-9s: %s | %-5s: %s\n%-4s: %s '\
                 '| %-9s: %s\n%s: %s\n\n%s' \
                 % (HR, 'OK', '%(ok)5d', 'Found', '%(found)5d', 'Total', \
                    '%(total)5d', 'FAIL', '%(fail)5d', 'Not Found', \
                    '%(notfound)5d', 'Elapsed Time', '%(time).1f seconds', HR),
            232: 'Output File: %s',
            233: '"%s" invalid format.',
            234: '"%s" no matched hash.',
            240: 'Found\t: %s',
            241: 'OK\t: %s',
            242: 'FAIL\t: %s',
            251: '*WARNING* "%s" already exists. Append, Overwrite '\
                 'or Quit(a/o/Q)? ',
            299: '%s\n%s\n%s' % (DEBUG, '%s', DEBUG),
        }
        self.MESSAGES.update(messages)
    # end of __init__
# end of HashCalculatorUsage


class HashCalculator(object):
    """Hash Calculator
    `action`:   Action "c" means calculation, "e" means extraction,
                "v" means verification.
    `srcStrings`:
                List of string(s).
    `srcFiles`: List of file(s).
    `srcDirs`:  List of dir(s).
    `srcItemsFile`:
                List of string(s), file(s) and dir(s).
    `isRecursive`:
                If `srcDirs` is specified, it will process all files
                under `srcDirs` recursively.
    `unixFileFilterPattern`:
                The Unix shell-style wildcards pattern for the
                file filter.
    `regexFileFilterPattern`:
                The regex expression pattern for the file filter.
    `exclusiveDirs`:
                The directories will be ignored when it processes the
                `srcDirs` and `isRecursive` is True.
    `algorithms`:
                List of hash algorithm(s). Support algorithms: crc32,
                adler32, md5, sha1, sha224, sha256, sha384, sha512,
                md4, ed2k, blake2b, blake2s(need "pyblake2" module
                for blake2 algorithms), sha3_224, sha3_256, sha3_384,
                sha3_512(need "sha3" module for sha3 algorithms).
    `isUppercase`:
                Return uppercase hash code if True.
    `extractionPattern`:
                A regex pattern used for extraction. It must contain at
                least one group "(?P<hash>...)"
    `isNewOutputMode`:
                New output style for hash files. The difference between
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
    `hasDirHeader`:
                Put a directory header above the hash result if True.
    `hashFile`: The path of a hash file.
    `hashPathsFile`:
                The file contains the paths of hash files.
    `isExistenceOnly`:
                Only check file existence when action is "v".
    `isVerbose`:
                Show all output when action is "v", default only show
                the "FAIL" and "Not Found".
    `encoding`: Try to use the specified encoding to decode first.
    `logFile`:  Save output messages to the specified file.
    `fileBufSize`:
                The buffer size for file reading while calculating
                hash. It is 2MB if the file size less than 1GB,
                otherwise it is 4MB.
    `isTee`:    If hashFile and/or logFile are specified, it also
                output to stdout.
    `isSilent`: No output to stdout.

    Note:
        1.While adding any new algorithms, the following may need to
          be modified:
            _validAlgorithms
            _extnameMap
            _hashRowRegexMap
            _checkAlgorithmModule
            _getHashObj (global)
        2.On win32 platform, a dir/file name can not start/end with
          spaces, but on linux platform, this is acceptable. So I
          assumed that the names which the users inputted are exactly
          what they want, and display the error message while the
          dir/file could not be found rather than strip the spaces
          automatically.
    """

    _GROUPS_TYPE = Enum(('STR', 'FILE', 'DIR'))
    _VERIFIED_RESULT = Enum(('FOUND', 'OK', 'FAIL'))
    _usage = HashCalculatorUsage()
    # Use '\n' instead of os.linesep for better compatibility.
    _newline = '\n'
    _commentChar = u"*"
    _defaultEncoding = 'utf-8'
    _validAlgorithms = (
        'crc32', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
        'md4', 'ed2k', 'blake2b', 'blake2s', 'sha3_224', 'sha3_256',
        'sha3_384', 'sha3_512', 'adler32'
    )
    _validExtnames = (
        'sfv', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
        'md4', 'ed2k', 'blake2b', 'blake2s', 'sha3224', 'sha3256',
        'sha3384', 'sha3512', 'sfva'
    )
    _extnameMap = dict(zip(_validExtnames, _validAlgorithms))
    _extnameRegex = re.compile(\
        r"^(?P<main>.+)(?P<sep>\.)(?P<ext>[^\n\.]+)$", re.U)
    _alnumPattern = r"[0-9A-Za-z]"
    _pathPattern = \
        r"(?P<path>\x20*(?P<trimmedPath>[^\s]+(?:[^\t\v\r\n\f]+[^\s])?)\x20*)"
    _separatorPattern = r"\t+|\x20+"
    _CRC32RowPattern = r"^%s(?:%s)\*?(?P<hash>%s{8})(?:\s*)$" \
                       % (_pathPattern, _separatorPattern, _alnumPattern)
    _hashRowPattern = r"^(?P<hash>%s{%s})(?:%s)\*?%s(?:\s*)$" \
                      % (_alnumPattern, '%s', _separatorPattern, _pathPattern)
    _CRC32RowRegex = re.compile(_CRC32RowPattern, re.U)
    _hash8xRowRegex = re.compile(_hashRowPattern % ('8'), re.U)
    _hash32xRowRegex = re.compile(_hashRowPattern % ('32'), re.U)
    _hash40xRowRegex = re.compile(_hashRowPattern % ('40'), re.U)
    _hash56xRowRegex = re.compile(_hashRowPattern % ('56'), re.U)
    _hash64xRowRegex = re.compile(_hashRowPattern % ('64'), re.U)
    _hash96xRowRegex = re.compile(_hashRowPattern % ('96'), re.U)
    _hash128xRowRegex = re.compile(_hashRowPattern % ('128'), re.U)
    _hashRowRegexMap = dict(\
        zip(_validAlgorithms, \
            (_CRC32RowRegex, _hash32xRowRegex, _hash40xRowRegex, \
             _hash56xRowRegex, _hash64xRowRegex, _hash96xRowRegex, \
             _hash128xRowRegex, _hash32xRowRegex, _hash32xRowRegex, \
             _hash128xRowRegex, _hash64xRowRegex, _hash56xRowRegex, \
             _hash64xRowRegex, _hash96xRowRegex, _hash128xRowRegex, \
             _hash8xRowRegex)))
    _pathRowRegex = re.compile(r"^%s$" % (_pathPattern), re.U)
    _strRowRegex = re.compile(\
        r"^STRING=(?P<string>[^\r\n]+)(?:[\r\n]*)$", re.U)
    _emptyRowRegex = re.compile(r"^[\r\n]*$", re.U)
    _errorRowRegex = re.compile(r"^[^\r\n]*", re.U)
    _extractionPatternRegex = re.compile(r"\(\?P<hash>.*?\)")
    _extractionRegex = None
    _newOutputRowRegex = re.compile(\
        r"\*\*\*\x20(?P<dir>[^\t\v\r\n\f]+)\x20\*\*\*", re.U)
    _fileFilterRegex = None
    _dirHeaderFormat = '*%(nl)s* %(dir)s%(nl)s*%(nl)s' \
                        % {'nl': _newline, 'dir': '%s'}
    _newOutputHeaderFormat = ''.join(['*** %s ***', _newline])
    _logTmpFile = None
    _logFileMode = 'a'
    _hashFileMode = 'a'
    _isSilent = False
    _stdout = sys.stdout
    _srcStrings = []
    _srcFiles = []
    _srcDirs = []
    _filesToBeVerified = []
    _action = None
    _isRecursive = False
    _fileFilterPattern = None
    _exclusiveDirs = []
    _algorithms = []
    _isUppercase = False
    _extractionPattern = r"^.*(?:(?P<hlbk>\[)|(?P<hlpt>\())?"\
                         r"(?:crc32[\x20_\-])?" r"(?P<hash>%(alnum)s{8})"\
                         r"(?(hlbk)\])(?(hlpt)\))" r"(?:\[(?:[\w]{1,5})\])?"\
                         r"\.%(alnum)s{2,4}" % {'alnum': _alnumPattern}
    _isNewOutputMode = False
    _hasDirHeader = False
    _hashFile = None
    _isExistenceOnly = False
    _encoding = None
    _logFile = None
    _isVerbose = False
    _isTee = False
    _fileBufSize = (2 << 20)
    _progressBar = None
    _progressBarWidth = 0
    _showProgress = None
    _textWidth = 0
    _itemOK = 0
    _itemFail = 0
    _itemFound = 0
    _itemNotFound = 0
    _totalItems = 0
    _hashStock = HashStock()

    def _str(self, obj, errors='ignore'):
        return str_(obj, self._defaultEncoding, errors)
    # end of _str

    def _unicode(self, obj):
        return unicode_(obj, self._encoding or self._defaultEncoding)
    # end of _unicode

    def _print(self, obj, file_=None, end='\n'):
        """Print the object to stdout and/or file"""
        obj = self._str(obj)
        end = self._str(end) if isinstance(end, basestring) else '\n'
        text = ''.join([obj, end])

        if file_ is not None:
            affirm(isinstance(file_, (file, SpooledTmpFile)), \
                   self._usage(11, arg='file_', type_='file or TemporaryFile'))
            file_.write(text)

        if file_ is None or self._isTee:
            self._stdout.write(text)
            self._stdout.flush()
    # end of _print

    def _getExtname(self, filename, default='', separator='.'):
        """
        Return the extension name of the file
        `filename`: 'hash.md5' or '/dir/hash.md5'
        `separator`:
                    filename/extname separator, default '.'
        """
        filename = os.path.basename(filename) \
                   if isinstance(filename, basestring) else ''
        extname = default

        if separator == '.':
            extnameRegex = self._extnameRegex
        else:
            EscapedSeparator = '\\' + separator
            extnameRegex = re.compile(\
                r"^(?P<main>.+)(?P<sep>%(sep)s)(?P<ext>[^\n%(sep)s]+)$" \
                % {'sep': EscapedSeparator})
        extnameMatch = extnameRegex.search(filename)
        if extnameMatch:
            extnameMatch = extnameMatch.groupdict()
            extname = extnameMatch['ext']
            filename = extnameMatch['main']

        return (filename, separator, extname)
    # end of _getExtname

    def _computeItemsCount(self):
        """Compute the number of all items to be processed"""
        self._itemOK = 0
        self._itemFail = 0
        self._itemFound = 0
        self._itemNotFound = 0
        self._totalItems = 0

        if self._action == 'c' or self._action == 'e':
            self._totalItems += sum([len(ss[1]) for ss in self._srcStrings]) + \
                                sum([len(sf[1]) for sf in self._srcFiles]) + \
                                sum([len(sd[1]) for sd in self._srcDirs])
        else:
            self._totalItems += sum([len(vf[-1]) \
                                     for vf in self._filesToBeVerified])
    # end of _computeItemsCount

    def setSilent(self, isSilent):
        """Set `_isSilent` flag"""
        affirm(isinstance(isSilent, bool), \
               self._usage(11, arg='isSilent', type_='bool'))
        self._isSilent = isSilent
        if self._isSilent:
            self._stdout = open(os.devnull, 'w')
            if not self._logTmpFile:
                self._logTmpFile = SpooledTmpFile()
        else:
            self._stdout = sys.stdout
    # end of setSilent

    def setRecursive(self, isRecursive):
        """Set `_isRecursive` flag"""
        affirm(isinstance(isRecursive, bool), \
               self._usage(11, arg='isRecursive', type_='bool'))
        self._isRecursive = isRecursive
    # end of setRecursive

    def setUppercase(self, isUppercase):
        """Set `_isUppercase` flag"""
        affirm(isinstance(isUppercase, bool), \
               self._usage(11, arg='isUppercase', type_='bool'))
        self._isUppercase = isUppercase
    # end of setUppercase

    def setNewOutputMode(self, isNewOutputMode):
        """Set `_isNewOutputMode` flag"""
        affirm(isinstance(isNewOutputMode, bool), \
               self._usage(11, arg='isNewOutputMode', type_='bool'))
        self._isNewOutputMode = isNewOutputMode
    # end of setNewOutputMode

    def setDirHeader(self, hasDirHeader):
        """Set `_hasDirHeader` flag"""
        affirm(isinstance(hasDirHeader, bool), \
               self._usage(11, arg='hasDirHeader', type_='bool'))
        self._hasDirHeader = hasDirHeader
    # end of setDirHeader

    def setExistenceOnly(self, isExistenceOnly):
        """Set `_isExistenceOnly` flag"""
        affirm(isinstance(isExistenceOnly, bool), \
               self._usage(11, arg='isExistenceOnly', type_='bool'))
        self._isExistenceOnly = isExistenceOnly
    # end of setExistenceOnly

    def setVerbose(self, isVerbose):
        """Set `_isVerbose` flag"""
        affirm(isinstance(isVerbose, bool), \
               self._usage(11, var='isVerbose', type_='bool'))
        self._isVerbose = isVerbose
    # end of setVerbose

    def setTee(self, isTee):
        """Set `_isTee` flag"""
        affirm(isinstance(isTee, bool), \
               self._usage(11, arg='isTee', type_='bool'))
        self._isTee = isTee
    # end of setTee

    def setEncoding(self, encoding):
        """Set the `_encoding`"""
        affirm(isinstance(encoding, basestring), \
               self._usage(11, arg='encoding', type_='basestring'))

        try:
            codecs.lookup(encoding)
        except LookupError as le:
            raise Error(joinExceptionArgs(le))
        else:
            self._encoding = encoding
    # end of setEncoding

    def _selectFileMode(self, filePath):
        affirm(os.access(os.path.dirname(filePath), os.W_OK) \
               and not os.path.isdir(filePath), \
               self._usage(203, self._str(filePath)))

        mode = 'a'
        if os.access(filePath, os.F_OK):
            affirm(os.access(filePath, os.W_OK), \
                   self._usage(204, self._str(filePath)))
            input_ = ''
            while input_.lower() not in ('a', 'o'):
                input_ = raw_input(self._usage(251, self._str(filePath)))
                affirm(input_ != '' and input_.lower() != 'q', self._usage(15))
            if input_ == 'o':
                mode = 'w'

        return mode
    # end of _selectFileMode

    def setLogFile(self, logFile):
        """
        Set the path of log file. Call saveLog() after some operations
        to save the log to the specified file.
        """
        affirm(isinstance(logFile, basestring), \
               self._usage(11, arg='logFile', type_='basestring'))

        logFile = os.path.abspath(self._unicode(logFile))
        self._logFileMode = self._selectFileMode(logFile)
        self._logFile = logFile
        if self._logTmpFile:
            self._logTmpFile.close()
        self._logTmpFile = SpooledTmpFile()
    # end of setLogFile

    def clearLog(self):
        """Clear the content of current log."""
        if self._logTmpFile:
            self._logTmpFile.close()
            self._logTmpFile = SpooledTmpFile()
    # end of clearLog

    def getFileFilterPattern(self):
        return self._fileFilterPattern
    # end of getFileFilterPattern

    def setFileFilterPattern(self, unixFileFilterPattern=None, \
                             regexFileFilterPattern=None):
        """Call this function without args to disable the filter."""
        if regexFileFilterPattern is not None:
            affirm(isinstance(regexFileFilterPattern, basestring), \
                   self._usage(11, arg='regexFileFilterPattern', \
                               type_='basestring'))
            try:
                self._fileFilterRegex = re.compile(\
                    self._unicode(regexFileFilterPattern), re.U)
            except re.error as ree:
                raise Error(\
                    self._usage(16, var='regexFileFilterPattern', \
                                msg=joinExceptionArgs(ree), \
                                value=self._str(regexFileFilterPattern)))
            self._fileFilterPattern = self._fileFilterRegex.pattern
        elif unixFileFilterPattern is not None:
            affirm(isinstance(unixFileFilterPattern, basestring), \
                   self._usage(11, arg='unixFileFilterPattern', \
                               type_='basestring'))
            self._fileFilterPattern = self._unicode(unixFileFilterPattern)
            self._fileFilterRegex = None
        else:
            self._fileFilterPattern = None
            self._fileFilterRegex = None
    # end of setFileFilterPattern

    def setExclusiveDirs(self, exclusiveDirs):
        """Set the exclusive dirs."""
        affirm(isinstance(exclusiveDirs, list), \
               self._usage(11, arg='exclusiveDirs', type_='list'))
        self._exclusiveDirs[:] = []
        for dir_ in exclusiveDirs:
            affirm(isinstance(dir_, basestring), \
                   self._usage(12, arg='exclusiveDirs', \
                               value=self._str(exclusiveDirs)))
            self._exclusiveDirs.append(self._unicode(dir_))
    # end of setExclusiveDirs

    def setAction(self, action):
        """Set the `_action`"""
        affirm(action in ('c', 'v', 'e'), \
               self._usage(12, arg='action', value=self._str(action)))
        self._action = action
    # end of setAction

    def _checkAlgorithmModule(self, algorithm):
        """Check whether the required module is imported or not"""
        if algorithm.startswith('blake'):
            affirm(_isPyblake2Imported, \
                   self._usage(206, algorithm=algorithm, module='pyblake2'))
        elif algorithm.startswith('sha3_'):
            affirm(_isSha3Imported, \
                   self._usage(206, algorithm=algorithm, module='sha3'))
    # end of _checkAlgorithmModule

    def getAlgorithms(self):
        """Return the current algorithms."""
        return list(self._algorithms)
    # end of getAlgorithms

    def clearAlgorithms(self):
        """Delete all hash algorithms."""
        self._algorithms[:] = []
    # end of clearAlgorithms

    def addAlgorithm(self, algorithm):
        """Append the `algorithm` to the current algorithms."""
        affirm(algorithm in self._validAlgorithms, \
               self._usage(12, arg='algorithm', value=self._str(algorithm)))
        if algorithm not in self._algorithms:
            self._checkAlgorithmModule(algorithm)
            self._algorithms.append(algorithm)
    # end of addAlgorithm

    def delAlgorithm(self, algorithm):
        affirm(algorithm in self._validAlgorithms, \
               self._usage(12, arg='algorithm', value=self._str(algorithm)))
        if algorithm in self._algorithms:
            self._algorithms.remove(algorithm)
    # end of delAlgorithm

    def setAlgorithms(self, algorithms=None):
        """Set the hash algorithms."""
        if isinstance(algorithms, list) and algorithms:
            if self._action == 'e' or self._action == 'v':
                del algorithms[1:]
        elif self._action == 'e' and algorithms is None:
            algorithms = [self._validAlgorithms[0]]
        else:
            raise Error(self._usage(12, arg='algorithms', \
                                    value=self._str(algorithms)))

        self.clearAlgorithms()
        for algorithm in algorithms:
            self.addAlgorithm(algorithm)
    # end of setAlgorithms

    def setHashFile(self, hashFile):
        """Set the hash file for hash calculation and extraction"""
        affirm(isinstance(hashFile, basestring), \
               self._usage(11, arg='hashFile', type_='basestring'))

        hashFile = os.path.abspath(self._unicode(hashFile))
        self._hashFileMode = self._selectFileMode(hashFile)
        self._hashFile = hashFile
    # end of setHashFile

    def parseHashFile(self, hashFile):
        """Parse hash file for verification"""
        filePath = os.path.abspath(self._unicode(hashFile))
        affirm(os.path.isfile(filePath) \
               and os.access(filePath, os.R_OK), \
               self._usage(210, self._str(filePath)))

        fileDir = os.path.dirname(filePath)
        extname = self._getExtname(filePath)[2]
        if self._algorithms:
            algorithm = self._algorithms[0]
        elif extname in self._extnameMap:
            algorithm = self._extnameMap[extname]
        else:
            raise Error(\
                self._usage(201, self._str(os.path.basename(filePath))))

        with open(filePath, 'r') as file_:
            self._filesToBeVerified.append((fileDir, None, \
                                            algorithm, []))
            for line in file_:
                line = self._unicode(line)
                if line.startswith(self._commentChar):
                    newOutputRowMatch = self._newOutputRowRegex.search(line)
                    if newOutputRowMatch:
                        newOutputRowMatch = newOutputRowMatch.groupdict()
                        self._filesToBeVerified.append(\
                            (fileDir, newOutputRowMatch['dir'], \
                             algorithm, []))
                elif self._emptyRowRegex.search(line) is None:
                    self._filesToBeVerified[-1][-1].append(line)
    # end of parseHashFile

    def parseHashPathsFile(self, hashPathsFile):
        """Parse hash paths file for verification."""
        hashPathsFile = os.path.abspath(self._unicode(hashPathsFile))
        affirm(os.path.isfile(hashPathsFile) \
               and os.access(hashPathsFile, os.R_OK), \
               self._usage(210, self._str(hashPathsFile)))

        hashPathsFileDir = os.path.dirname(hashPathsFile)
        hashPaths = []
        with open(hashPathsFile, 'r') as file_:
            for line in file_:
                line = self._unicode(line)
                if (not line.startswith(self._commentChar)) \
                   and self._emptyRowRegex.search(line) is None:
                    pathRowMatch = self._pathRowRegex.search(line)
                    if pathRowMatch:
                        pathRowMatch = pathRowMatch.groupdict()
                        hashPaths.append(pathRowMatch['path'])
                    else:
                        self._print(self._usage(233, line), self._logTmpFile)

        for hashPath in hashPaths:
            self.parseHashFile(getAbsPath(hashPathsFileDir, hashPath))
    # end of parseHashPathsFile

    def _isFileMatched(self, filename):
        """
        Return True if the filename matches the pattern of the filter
        or there are no filters, otherwise return False.
        """
        if self._fileFilterRegex:
            if self._fileFilterRegex.search(filename):
                return True
            else:
                return False
        elif self._fileFilterPattern:
            return fnmatch.fnmatch(filename, self._fileFilterPattern)
        else:
            return True
    # end of _isFileMatched

    def _getFileList(self, dir_, root=None):
        """Get the list of all files under the given directory."""
        dir_ = os.path.abspath(self._unicode(dir_))
        affirm(os.path.isdir(dir_) and os.access(dir_, os.R_OK), \
               self._usage(205, self._str(dir_)))

        isRoot = False
        if root is None:
            isRoot = True
            root = dir_
        files = []
        subdirFiles = []
        items = os.listdir(dir_)
        items.sort()
        for item in items:
            itemAbsPath = getAbsPath(dir_, item)
            # Here will not follow the symbolic link of dir if recursive
            if os.path.isdir(itemAbsPath):
                if self._isRecursive and (not os.path.islink(itemAbsPath)) \
                   and item not in self._exclusiveDirs:
                    subdirFiles.extend(self._getFileList(itemAbsPath, root))
            elif os.path.isfile(itemAbsPath):
                if not self._isFileMatched(item):
                    continue
                if isRoot:
                    files.append(item)
                else:
                    files.append(os.path.join(os.path.relpath(dir_, root), \
                                              item))
        files.extend(subdirFiles)

        return (dir_, files) if isRoot else files
    # end of _getFileList

    def addSrcStrings(self, srcStrings):
        """Add the source strings"""
        affirm(isinstance(srcStrings, list), \
               self._usage(11, arg='srcStrings', type_='list'))

        srcStrsTmp = []
        for string in srcStrings:
            affirm(\
                isinstance(string, basestring), \
                self._usage(12, arg='srcStrings', value=self._str(srcStrings)))
            srcStrsTmp.append(self._str(self._unicode(string)))
        if srcStrsTmp:
            srcStrsTmp.sort()
            self._srcStrings.append((None, srcStrsTmp))
    # end of addSrcStrings

    def addSrcFiles(self, srcFiles):
        """Add the source files"""
        affirm(isinstance(srcFiles, list), \
               self._usage(11, arg='srcFiles', type_='list'))

        srcFilesTmp = []
        for file_ in srcFiles:
            affirm(isinstance(file_, basestring), \
                   self._usage(12, arg='srcFiles', value=self._str(srcFiles)))
            file_ = self._unicode(file_)
            if self._isFileMatched(os.path.basename(file_)):
                srcFilesTmp.append(file_)
        if srcFilesTmp:
            srcFilesTmp.sort()
            self._srcFiles.append((os.getcwd(), srcFilesTmp))
    # end of addSrcFiles

    def addSrcDirs(self, srcDirs):
        """Add the source directories"""
        affirm(isinstance(srcDirs, list), \
               self._usage(11, arg='srcDirs', type_='list'))

        for dir_ in srcDirs:
            affirm(isinstance(dir_, basestring), \
                   self._usage(12, arg='srcDirs', value=self._str(srcDirs)))
            fileListTmp = self._getFileList(dir_)
            if fileListTmp[1]:
                self._srcDirs.append(fileListTmp)
    # end of addSrcDirs

    def parseSrcItemsFile(self, srcItemsFile):
        """Parse the list of strings, files and dirs"""
        affirm(isinstance(srcItemsFile, basestring), \
               self._usage(11, arg='srcItemsFile', type_='basestring'))

        filePath = os.path.abspath(self._unicode(srcItemsFile))
        affirm(os.path.isfile(filePath) and os.access(filePath, os.R_OK), \
               self._usage(210, self._str(filePath)))

        fileDir = os.path.dirname(filePath)
        srcStrings = []
        srcFiles = []
        srcDirs = []
        with open(filePath, 'r') as file_:
            for line in file_:
                line = self._unicode(line)
                if self._emptyRowRegex.search(line) is None \
                   and not line.startswith(self._commentChar):
                    strRowMatch = self._strRowRegex.search(line)
                    pathRowMatch = self._pathRowRegex.search(line)
                    affirm(strRowMatch or pathRowMatch, \
                           self._usage(233, self._str(line)))
                    # If a line both matches the file/dir and
                    # string, add the item to those lists.
                    if strRowMatch:
                        strRowMatch = strRowMatch.groupdict()
                        srcStrings.append(strRowMatch['string'])

                    if pathRowMatch:
                        pathRowMatch = pathRowMatch.groupdict()
                        itemAbsPath = getAbsPath(fileDir, pathRowMatch['path'])
                        if os.path.isfile(itemAbsPath):
                            if self._isFileMatched(\
                                    os.path.basename(itemAbsPath)):
                                srcFiles.append(itemAbsPath)
                        elif os.path.isdir(itemAbsPath):
                            srcDirs.append(itemAbsPath)
                        elif strRowMatch is None:
                            self._print(self._usage(208, itemAbsPath), \
                                        self._logTmpFile)

        if srcStrings:
            srcStrings.sort()
            self._srcStrings.append((None, srcStrings))
        if srcFiles:
            srcFiles.sort()
            self._srcFiles.append((fileDir, srcFiles))
        srcDirs.sort()
        self.addSrcDirs(srcDirs)
    # end of parseSrcItemsFile

    def setExtractionPattern(self, extractionPattern=None):
        if extractionPattern is not None:
            affirm(self._extractionPatternRegex.search(extractionPattern), \
                   self._usage(12, arg='extractionPattern', \
                               value=self._str(extractionPattern)))
            try:
                self._extractionRegex = re.compile(\
                    self._unicode(extractionPattern), re.U)
            except re.error as ree:
                raise Error(\
                    self._usage(16, var='extractionPattern', \
                                msg=joinExceptionArgs(ree), \
                                value=self._str(extractionPattern)))
            self._extractionPattern = extractionPattern
        else:
            self._extractionRegex = re.compile(self._extractionPattern, \
                                               re.U)
    # end of setExtractionPattern

    def setFileBufSize(self, fileBufSize):
        affirm(isinstance(fileBufSize, int), \
               self._usage(11, arg='fileBufSize', type_='int'))
        affirm(fileBufSize > 0, self._usage(13, '`fileBufSize` > 0'))
        self._fileBufSize = fileBufSize
    # end of setFileBufSize

    def setupProgressBar(self, showProgressCallback=None):
        """
        Determine width of the progress bar and the width of the output
        text for console window. If you want to use your own progress bar,
        you must provide a callback function as the following prototype:
            def callback(progress, text)
            `progress` is the progress of a file being processed and
            `text` is its basename.
        """
        self._progressBarWidth = 17
        self._progressBar = ProgressBar(self._progressBarWidth)
        if callable(showProgressCallback):
            self._showProgress = showProgressCallback
        else:
            self._showProgress = self._printProgress
        try:
            windowWidth = int(os.environ['COLUMNS'])
        except (KeyError, ValueError):
            windowWidth = 80
        finally:
            self._textWidth = windowWidth - self._progressBarWidth - 1
    # end of setupProgressBar

    def clearSrcItems(self):
        """Clear all items to be calculated/extraction/verification"""
        self._srcStrings[:] = []
        self._srcFiles[:] = []
        self._srcDirs[:] = []
        self._filesToBeVerified[:] = []
    # end of clearSrcItems

    def reset(self):
        """
        Reset all flags, clear all items to be calculated/verified,
        clear all algorithms, and the action would be set to 'c'.
        """
        self.setSilent(False)
        self._isRecursive = False
        self._isUppercase = False
        self._isNewOutputMode = False
        self._hasDirHeader = False
        self._isExistenceOnly = False
        self._isVerbose = False
        self._isTee = False
        self.clearSrcItems()
        self._computeItemsCount()
        self.clearAlgorithms()
        self._action = 'c'
        self._hashStock.reset()
        self.clearLog()
    # end of reset

    def __init__(\
        self, action='c', srcStrings=None, srcFiles=None, srcDirs=None, \
        srcItemsFile=None, isRecursive=None, unixFileFilterPattern=None, \
        regexFileFilterPattern=None, exclusiveDirs=None, algorithms=None, \
        isUppercase=None, extractionPattern=None, isNewOutputMode=None, \
        hasDirHeader=None, hashFile=None, hashPathsFile=None, \
        isExistenceOnly=None, encoding=None, logFile=None, isVerbose=None, \
        isTee=None, isSilent=None, fileBufSize=None):
        """Initialize and parse all arguments."""
        # Parsing `isSilent`
        self.setSilent(isSilent or False)
        # Parsing `encoding`
        self.setEncoding(encoding or self._defaultEncoding)
        # Parsing `logFile`
        if logFile is not None:
            self.setLogFile(logFile)
        # Parsing `isRecursive`
        self.setRecursive(isRecursive or False)
        # Parsing `isUppercase`
        self.setUppercase(isUppercase or False)
        # Parsing `isNewOutputMode`
        self.setNewOutputMode(isNewOutputMode or False)
        # Parsing `hasDirHeader`
        self.setDirHeader(hasDirHeader or False)
        # Parsing `isExistenceOnly`
        self.setExistenceOnly(isExistenceOnly or False)
        # Parsing `isVerbose`
        self.setVerbose(isVerbose or False)
        # Parsing `isTee`
        self.setTee(isTee or False)
        # Parsing `unixFileFilterPattern` and `regexFileFilterPattern`
        self.setFileFilterPattern(unixFileFilterPattern, \
                                  regexFileFilterPattern)
        # Parsing `exclusiveDirs`
        if exclusiveDirs is not None:
            self.setExclusiveDirs(exclusiveDirs)
        # Parsing `action`
        self.setAction(action)
        # Parsing `algorithms`
        if algorithms is not None:
            self.setAlgorithms(algorithms)
        # Parsing `srcStrings`, `srcFiles`, `srcDirs` and `srcItemsFile`
        self.addSrcStrings(srcStrings or [])
        self.addSrcFiles(srcFiles or [])
        self.addSrcDirs(srcDirs or [])
        if srcItemsFile is not None:
            self.parseSrcItemsFile(srcItemsFile)
        # Parsing `extractionPattern`
        self.setExtractionPattern(extractionPattern)

        # Parsing `hashFile`
        if hashFile is not None:
            if self._action == 'v':
                self.parseHashFile(hashFile)
            else:
                self.setHashFile(hashFile)

        # Parsing `hashPathsFile`
        if hashPathsFile is not None:
            self.parseHashPathsFile(hashPathsFile)

        # Parsing `fileBufSize`
        if fileBufSize is not None:
            self.setFileBufSize(fileBufSize)

        self.setupProgressBar()

        # The following comment section is for debug purpose.
        """
        kwargs = dict(\
            _action=self._action, _srcStrings=self._srcStrings, \
            _srcFiles=self._srcFiles, _srcDirs=self._srcDirs, \
            srcItemsFile=srcItemsFile, _isRecursive=self._isRecursive, \
            unixFileFilterPattern=unixFileFilterPattern, \
            regexFileFilterPattern=regexFileFilterPattern, \
            exclusiveDirs=self._exclusiveDirs, \
            _algorithms=self._algorithms, _isUppercase=self._isUppercase, \
            _extractionPattern=self._extractionPattern, \
            _isNewOutputMode=self._isNewOutputMode, \
            _hasDirHeader=self._hasDirHeader, _hashFile=self._hashFile, \
            _hashFileMode=self._hashFileMode, hashPathsFile=hashPathsFile, \
            _isExistenceOnly=self._isExistenceOnly, _encoding=self._encoding, \
            _logFile=self._logFile, _logFileMode=self._logFileMode, \
            _isVerbose=self._isVerbose, _isTee=self._isTee, \
            _isSilent=self._isSilent, _fileBufSize=self._fileBufSize)
        sortedKeys = sorted(kwargs.keys())
        raise AssertionError(\
            self._usage(299, '\n'.join('%s = %r' \
            % (key, self._str(kwargs.get(key))) for key in sortedKeys)))
        """
    # end of __init__

    def _printProgress(self, progress, text):
        SEP_TEXT = ' | '
        END_TEXT = '...'
        progressBar = self._progressBar
        textWidth = self._textWidth - len(SEP_TEXT) - len(END_TEXT)

        if progress == 0.0:
            progressText = ''.join(\
                [progressBar.update(progress), SEP_TEXT, \
                 self._str(text[:textWidth]), \
                 END_TEXT if textWidth <= len(text) else ''])
        else:
            progressText = progressBar.update(progress)
        self._print(progressText, end='')
        if progress == 1.0:
            blankWidth = self._progressBarWidth + self._textWidth
            self._print(''.join(['\r', ' ' * blankWidth, '\r']), end='')
    # end of _printProgress

    def _calculateHash(self, file_, size=0):
        """Calculate the hash of the given file/StringIO object."""
        fileBuf = None
        fileSize = size if size != 0 else 1
        fileBufSize = self._fileBufSize if (size >> 30) == 0 \
                                        else self._fileBufSize << 1
        filePosition = 0
        hashObjs = []
        hashes = []
        progress = 0.0

        for algorithm in self._algorithms:
            hashObjs.append(_getHashObj(algorithm))

        affirm(fileBufSize > 0, self._usage(13, '`fileBufSize > 0`'))
        while filePosition < fileSize:
            yield (progress, None)
            fileBuf = file_.read(fileBufSize)
            for hashObj in hashObjs:
                hashObj.update(fileBuf)
            filePosition += len(fileBuf)
            if filePosition == 0:
                progress = 1.0
                break
            progress = float(filePosition) / float(fileSize)

        for hashObj in hashObjs:
            hash_ = hashObj.hexdigest()
            hashes.append(hash_ if not self._isUppercase else hash_.upper())

        yield (progress, dict(zip(self._algorithms, hashes)))
    # end of _calculateHash

    def _isFileAccessible(self, srcItem, srcItemText, isReadable=True):
        if os.path.isfile(srcItem) \
           and not (isReadable and not os.access(srcItem, os.R_OK)):
            return True
        else:
            self._print(self._usage(210, srcItemText), self._logTmpFile)
            self._itemNotFound += 1
            return False
    # end of _isFileAccessible

    def _extractHash(self, srcItem, srcItemText, groupsType=_GROUPS_TYPE.FILE):
        """Extract the hash of the given filename/string."""
        algorithm = self._algorithms[0]
        logFile = self._logTmpFile

        if groupsType != self._GROUPS_TYPE.STR:
            if not self._isFileAccessible(srcItem, srcItemText):
                return None

            text = os.path.basename(srcItem)
        else:
            text = srcItem
        self._itemFound += 1

        extractionMatch = self._extractionRegex.search(text)
        if extractionMatch:
            hash_ = extractionMatch.groupdict()['hash']
            hash_ = hash_.upper() if self._isUppercase else hash_.lower()
            return dict([(algorithm, self._str(hash_))])
        else:
            self._print(self._usage(234, srcItemText), logFile)
            self._itemFail += 1
            return None
    # end of _extractHash

    def _processSrcItem(self, srcItem, srcItemText, \
                        groupsType=_GROUPS_TYPE.FILE):
        size = 0
        text = ''
        hashes = {}
        logFile = self._logTmpFile

        if groupsType != self._GROUPS_TYPE.STR:
            if not self._isFileAccessible(srcItem, srcItemText):
                return None

            openFunc = lambda x: open(x, 'rb')
            size = os.path.getsize(srcItem)
            text = os.path.basename(srcItem)
        else:
            openFunc = lambda x: closing(StringIO(x))
            size = len(srcItem)
            text = srcItem
        self._itemFound += 1

        try:
            with openFunc(srcItem) as file_:
                for progress, hashesTmp in self._calculateHash(file_, size):
                    self._showProgress(progress, text)
                    if hashesTmp:
                        hashes.update(hashesTmp)
        except IOError as ioe:
            self._print(\
                self._usage(242, ', '.join([srcItemText, \
                                            getExceptionMsg(ioe)])), logFile)
            self._itemFail += 1
            return None

        return hashes
    # end of _processSrcItem

    def _calculate(self, processFunc):
        """Calculate the hash of file/string."""
        srcCollection = (self._srcStrings, self._srcFiles, self._srcDirs)
        hashStock = self._hashStock

        affirm(self._algorithms, self._usage(202))
        for groupsType in range(len(srcCollection)):
            for srcGroup in srcCollection[groupsType]:
                # If `_GROUPS_TYPE.DIR` and `_hasDirHeader`, set dirHeader
                srcItemDir = srcGroup[0]
                dirHeader = ''
                if groupsType == self._GROUPS_TYPE.DIR and self._hasDirHeader:
                    dirHeader = self._dirHeaderFormat % srcItemDir
                if len(srcGroup[1]) != 0:
                    hashStock.newGroup(self._str(dirHeader), groupsType)

                newOutputHeader = ''
                relpath = None
                lastRelpath = None
                hashes = None
                hashStock.newSubGroup(self._str(newOutputHeader))
                for srcItem in srcGroup[1]:
                    # If `_isNewOutputMode`, set the `newOutputHeader`.
                    if self._isNewOutputMode:
                        srcItemText = os.path.basename(srcItem) \
                                      if groupsType != self._GROUPS_TYPE.STR \
                                      else srcItem
                        newOutputHeader = ''
                        if groupsType == self._GROUPS_TYPE.DIR:
                            relpath = os.path.dirname(srcItem) or None
                            if relpath:
                                newOutputHeader = self._newOutputHeaderFormat \
                                                  % relpath
                    else:
                        srcItemText = os.path.basename(srcItem) \
                                      if groupsType == self._GROUPS_TYPE.FILE \
                                      else srcItem

                    # If `srcItemDir`, get file abspath
                    if srcItemDir is not None:
                        srcItem = getAbsPath(srcItemDir, srcItem)
                    hashes = processFunc(srcItem, srcItemText, groupsType)
                    if not hashes:
                        continue

                    # If `newOutputHeader` changed, new a sub group for it.
                    if relpath != lastRelpath:
                        lastRelpath = relpath
                        hashStock.newSubGroup(self._str(newOutputHeader))

                    # Add the result of a item to `_hashStock`.
                    hashStock.addItem(\
                        self._str(srcItemText), \
                        zip(self._algorithms, \
                            [hashes[a] for a in self._algorithms]))
                    self._itemOK += 1
    # end of _calculate

    def _verify(self):
        """Verify the hash according to the given arguments."""
        result = self._VERIFIED_RESULT.FAIL
        logFile = self._logTmpFile
        oldAlgorithms = self._algorithms[:]

        for hashFileDir, newOutputDir, algorithm, items \
                in self._filesToBeVerified:
            for item in items:
                hashRowMatch = self._hashRowRegexMap[algorithm].search(item)
                if hashRowMatch:
                    hashRowMatch = hashRowMatch.groupdict()
                    fileText = hashRowMatch['path'] if newOutputDir is None \
                               else os.path.join(newOutputDir, \
                                                 hashRowMatch['path'])
                    hash_ = hashRowMatch['hash'].upper() if self._isUppercase \
                            else hashRowMatch['hash'].lower()
                    if not self._isFileMatched(os.path.basename(fileText)):
                        self._totalItems -= 1
                        continue
                    filePath = getAbsPath(hashFileDir, fileText)
                else:
                    errorRowMatch = self._errorRowRegex.search(item)
                    errorRowMatch = errorRowMatch.group(0) if errorRowMatch \
                                    else item
                    self._print(self._usage(233, errorRowMatch), logFile)
                    self._itemNotFound += 1
                    continue

                self._algorithms[:] = [algorithm]
                if self._isExistenceOnly:
                    if not self._isFileAccessible(filePath, fileText, False):
                        continue
                    result = self._VERIFIED_RESULT.FOUND
                    self._itemFound += 1
                else:
                    hashes = self._processSrcItem(filePath, fileText)
                    if not hashes:
                        continue

                    if hash_ == hashes[algorithm]:
                        result = self._VERIFIED_RESULT.OK
                        self._itemOK += 1
                    else:
                        result = self._VERIFIED_RESULT.FAIL
                        self._itemFail += 1
                if result == self._VERIFIED_RESULT.FAIL or self._isVerbose:
                    # 240: 'Found', 241: 'OK', 242: 'FAIL'
                    self._print(self._usage(240 + result, fileText), logFile)

        self._algorithms[:] = oldAlgorithms
    # end of _verify

    def act(self):
        """Do the corresponding action according to the options."""
        self._hashStock.reset()
        self._computeItemsCount()
        affirm(self._totalItems != 0, self._usage(207))
        if self._action == 'c':
            self._calculate(self._processSrcItem)
        elif self._action == 'e':
            self._algorithms[:] = self._algorithms[:1] if self._algorithms \
                                  else self._validAlgorithms[:1]
            self._calculate(self._extractHash)
        else:
            self._verify()
    # end of act

    def getResult(self):
        """Return the (summary, logFile, _hashStock) for the result."""
        summary = dict(\
            ok=self._itemOK, fail=self._itemFail, found=self._itemFound, \
            notfound=self._itemNotFound, total=self._totalItems)
        hashStock = self._hashStock if self._action != 'v' else None
        return (summary, self._logTmpFile, hashStock)
    # end of getResult

    def saveResult(self, hashFile=None):
        """Save the hash result to the specified hash file."""
        if hashFile is not None:
            self.setHashFile(hashFile)

        if self._action != 'v' and self._hashFile:
            with open(self._hashFile, self._hashFileMode) as file_:
                self._hashStock.save(file_)
            self._hashFile = None
            self._hashFileMode = 'a'
    # end of saveResult

    def saveLog(self):
        """
        Save the log to the specified file. The log will output to stdout
        after this call.
        """
        if self._logFile:
            self._logTmpFile.seek(0, os.SEEK_SET)
            with open(self._logFile, self._logFileMode) as file_:
                file_.write(self._logTmpFile.read())
            self._logTmpFile.close()
            self._logTmpFile = None
            self._logFile = None
            self._logFileMode = 'a'
    # end of saveLog

    def actAuto(self):
        """
        Do all the work automatically, including action/output/save,
        according to the options.
        """
        logTmpFile = self._logTmpFile

        try:
            startTime = time.time()
            self._print(self._usage(230, time.ctime(startTime)), logTmpFile)
            self.act()
            if self._action != 'v':
                if self._hashFile:
                    if self._isTee:
                        self._hashStock.print_(self._stdout)
                    self._print(self._usage(232, self._hashFile), logTmpFile)
                elif self._logFile:
                    self._hashStock.print_(logTmpFile)
                    if self._isTee:
                        self._hashStock.print_(self._stdout)
                else:
                    self._hashStock.print_(self._stdout)
            elapsedTime = time.time() - startTime
            self._print(self._usage(231, ok=self._itemOK, fail=self._itemFail, \
                        found=self._itemFound, notfound=self._itemNotFound, \
                        total=self._totalItems, time=elapsedTime), logTmpFile)
        finally:
            self.saveResult()
            self.saveLog()
    # end of actAuto

    def __call__(self):
        self.actAuto()
    # end of __call__
# end of HashCalculator


class FileInfoUsage(UsageHandler):
    """ProgressBarUsage"""

    def __init__(self):
        super(FileInfoUsage, self).__init__()
        HR = self.HR * 46
        messages = {
            501: '"%s" is not found, not a directory or no read privilege.',
            502: '"%s" is a directory or the user has no write privilege.',
            503: '"%s" already exists and the user has no write privilege.',
            504: 'No results could be saved.',
            505: 'Invalid file format: the first line must be the '\
                 'absolute path of the directory that contains all files '\
                 'to be checked.',
            506: '"%s" is not found, not a file or no read privilege.',
            507: 'The module "%s" is required. Please make sure '\
                 'that it is installed properly.',
            530: '*Name\tAttributes\tSize\tFileCount',
            531: '%(path)s\t%(attributes)s\t%(size)s\t%(count)s',
            532: '*-------',
            533: '*Total %(dirs)s Folders, %(files)s Files, and %(bytes_)s '\
                 'B (%(unitBytes)s).',
            534: '*Mountpoint %(path)s: %(used)s used, %(available)s '\
                 'available.',
            535: '*Drive %(drive)s (%(label)s): %(used)s used, %(available)s '\
                 'available.',
            536: 'OK\t: %s',
            537: '!Size\t: %(path)s (%(filesize)d B != %(infosize)s B)',
            538: '!Found\t: %s',
            539: '%s\nFile: %s\n\n%s' % (HR, '%s', HR),
            540: '\n%s\n%-5s: %s | %-6s: %s | %-5s: %s\n%-5s: %s '\
                 '| %-6s: %s\n\n%s' \
                 % (HR, 'OK', '%(ok)6d', 'Found', '%(found)6d', 'Total', \
                    '%(total)6d', '!Size', '%(notsize)6d', \
                    '!Found', '%(notfound)6d', HR),
            541: '*%(comment)s',
            542: 'Invalid line format: "%s"',
            551: '*WARNING* "%s" already exists. Append, Overwrite '\
                 'or Quit(a/o/Q)? ',
        }
        self.MESSAGES.update(messages)
    # end of __init__
# end of FileInfoUsage


class FileInfo(object):
    """Get and check the file information (size, attributes).
    `isRecursive`:
                If `getFileInfo()` is called, it will process all files
                under the specified `dir_` recursively.
    `isSilent`: No output to stdout.
    `exclusiveDirs`:
                The directories will be ignored when `getFileInfo()` is called.
    `isVerbose`:
                Show all output when action is "v", default only show
                the "FAIL" and "Not Found".
    `encoding`: Try to use the specified encoding to decode first.
    """

    _TOTAL = Enum(('DIRS', 'FILES', 'SIZES', 'OK', 'NOTSIZE', \
                   'FOUND', 'NOTFOUND', 'COUNT'))
    _COLUMN = Enum(('PATH', 'ATTRIBUTES', 'SIZE', 'COUNT'))
    _usage = FileInfoUsage()
    _commentChar = u"*"
    _defaultEncoding = 'utf-8'
    _isSilent = False
    _isRecursive = False
    _exclusiveDirs = []
    _isVerbose = False
    _encoding = None
    _tmpFile = None
    _getAttributes = None
    # For windows file attributes
    _win32api = None
    _win32con = None
    _AttributesMap = None
    # For linux file modes
    _typeMap = None
    _modeRWXMap = None
    _modeSTMap = None
    _getDiskUsage = None
    _summary = [0, 0, 0, 0, 0, 0, 0, 0]
    _sizeUnits = ('B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB')
    _stdout = sys.stdout

    def _str(self, obj, errors='ignore'):
        return str_(obj, self._defaultEncoding, errors)
    # end of _str

    def _unicode(self, obj):
        return unicode_(obj, self._encoding or self._defaultEncoding)
    # end of _unicode

    def _print(self, obj, file_=None, end='\n'):
        """Print the object to stdout or file"""
        obj = self._str(obj)
        end = self._str(end) if isinstance(end, basestring) else '\n'
        text = ''.join([obj, end])

        if isinstance(file_, (file, SpooledTmpFile)):
            file_.write(text)
        else:
            self._stdout.write(text)
            self._stdout.flush()
    # end of _print

    def setExclusiveDirs(self, exclusiveDirs):
        """Set the exclusive dirs."""
        affirm(isinstance(exclusiveDirs, list), \
               self._usage(11, arg='exclusiveDirs', type_='list'))
        self._exclusiveDirs[:] = []
        for dir_ in exclusiveDirs:
            affirm(isinstance(dir_, basestring), \
                   self._usage(12, arg='exclusiveDirs', \
                               value=self._str(exclusiveDirs)))
            self._exclusiveDirs.append(self._unicode(dir_))
    # end of setExclusiveDirs

    def setSilent(self, isSilent):
        """Set `_isSilent` flag"""
        affirm(isinstance(isSilent, bool), \
               self._usage(11, arg='isSilent', type_='bool'))
        self._isSilent = isSilent
        if self._isSilent:
            self._stdout = open(os.devnull, 'w')
        else:
            self._stdout = sys.stdout
    # end of setSilent

    def setRecursive(self, isRecursive):
        """Set `_isRecursive` flag"""
        affirm(isinstance(isRecursive, bool), \
               self._usage(11, arg='isRecursive', type_='bool'))
        self._isRecursive = isRecursive
    # end of setRecursive

    def setVerbose(self, isVerbose):
        """Set `_isVerbose` flag"""
        affirm(isinstance(isVerbose, bool), \
               self._usage(11, var='isVerbose', type_='bool'))
        self._isVerbose = isVerbose
    # end of setVerbose

    def setEncoding(self, encoding):
        """Set the `_encoding`"""
        affirm(isinstance(encoding, basestring), \
               self._usage(11, arg='encoding', type_='basestring'))

        try:
            codecs.lookup(encoding)
        except LookupError as le:
            raise Error(joinExceptionArgs(le))
        else:
            self._encoding = encoding
    # end of setEncoding

    def __init__(self, isRecursive=None, isSilent=None, exclusiveDirs=None, \
                 isVerbose=None, encoding=None):
        self.setSilent(isSilent or False)
        self.setEncoding(encoding or self._defaultEncoding)
        self.setRecursive(isRecursive or False)
        self.setVerbose(isVerbose or False)
        if exclusiveDirs is not None:
            self.setExclusiveDirs(exclusiveDirs)
        if sys.platform.startswith('linux'):
            self._typeMap = (
                ('S_ISDIR', 'd'), ('S_ISCHR', 'c'), ('S_ISBLK', 'b'),
                ('S_ISREG', '-'), ('S_ISFIFO', 'p'), ('S_ISLNK', 'l'),
                ('S_ISSOCK', 's')
            )
            self._modeRWXMap = (
                ('S_IRUSR', 'r'), ('S_IWUSR', 'w'), ('S_IXUSR', 'x'),
                ('S_IRGRP', 'r'), ('S_IWGRP', 'w'), ('S_IXGRP', 'x'),
                ('S_IROTH', 'r'), ('S_IWOTH', 'w'), ('S_IXOTH', 'x')
            )
            self._modeSTMap = (
                ('S_ISUID', 's'), ('S_ISGID', 's'), ('S_ISVTX', 't')
            )
            self._getAttributes = self._getAttributesOnUnix
            self._getDiskUsage = self._getDiskUsageOnUnix
        elif sys.platform.startswith('win32'):
            try:
                self._win32api = __import__('win32api')
                self._win32con = __import__('win32con')
            except ImportError:
                raise Error(self._usage(507, 'pywin32 (win32api, win32con)'))
            winCon = self._win32con
            # FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_VIRTUAL
            # is reserved for system use.
            self._AttributesMap = (
                (winCon.FILE_ATTRIBUTE_ENCRYPTED, 'E'),
                (winCon.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, 'I'),
                (winCon.FILE_ATTRIBUTE_OFFLINE, 'O'),
                (winCon.FILE_ATTRIBUTE_COMPRESSED, 'C'),
                (winCon.FILE_ATTRIBUTE_REPARSE_POINT, 'L'),
                (winCon.FILE_ATTRIBUTE_SPARSE_FILE, 'P'),
                (winCon.FILE_ATTRIBUTE_TEMPORARY, 'T'),
                (winCon.FILE_ATTRIBUTE_NORMAL, 'N'),
                (winCon.FILE_ATTRIBUTE_ARCHIVE, 'A'),
                (winCon.FILE_ATTRIBUTE_DIRECTORY, 'D'),
                (winCon.FILE_ATTRIBUTE_SYSTEM, 'S'),
                (winCon.FILE_ATTRIBUTE_HIDDEN, 'H'),
                (winCon.FILE_ATTRIBUTE_READONLY, 'R'),
            )
            self._getAttributes = self._getAttributesOnWin
            self._getDiskUsage = self._getDiskUsageOnWin
        else:
            self._getAttributes = lambda x: '?'
            self._getDiskUsage = lambda x: ''
    # end of __init__

    def _getAttributesOnUnix(self, filePath):
        stMode = os.lstat(filePath).st_mode
        attributes = []

        for func, type_ in self._typeMap:
            if getattr(stat, func)(stMode):
                attributes.append(type_)
                break
        for var, mode in self._modeRWXMap:
            constant = getattr(stat, var)
            hasAttribute = True if stMode & constant == constant else False
            attributes.append(mode if hasAttribute else '-')
        execIdx = 3
        for var, mode in self._modeSTMap:
            constant = getattr(stat, var)
            hasAttribute = True if stMode & constant == constant else False
            if hasAttribute:
                if attributes[execIdx] == '-':
                    mode = mode.upper()
                attributes[execIdx] = mode
            execIdx += 3

        return ''.join(attributes)
    # end of _getAttributesOnUnix

    def _getAttributesOnWin(self, filePath):
        winApi = self._win32api
        attributesNum = winApi.GetFileAttributes(filePath)
        attributes = []

        for constant, attribute in self._AttributesMap:
            hasAttribute = True if attributesNum & constant == constant \
                                else False
            if hasAttribute:
                attributes.append(attribute)
        if not attributes:
            attributes.append('N')

        return ''.join(attributes)
    # end of _getAttributesOnWin

    def computeSizeUnit(self, size):
        units = self._sizeUnits
        divisor = float(2 << 9)
        unitIdx = 0

        while divisor <= size:
            size = size / divisor
            unitIdx += 1

        return '%.2f %s' % (size, units[unitIdx])
    # end of computeSizeUnit

    def _getDiskUsageOnUnix(self, filePath):
        statvfsObj = os.statvfs(filePath)
        blockSize = statvfsObj.f_bsize
        availableBytes = statvfsObj.f_bavail * blockSize
        usedBytes = statvfsObj.f_blocks * blockSize - availableBytes
        TOTAL = self._TOTAL
        summary = self._summary

        mountPath = filePath
        while not os.path.ismount(mountPath):
            mountPath = os.path.dirname(mountPath)

        resultUsage = self._usage(\
            533, dirs=summary[TOTAL.DIRS], files=summary[TOTAL.FILES], \
            bytes_=summary[TOTAL.SIZES], \
            unitBytes=self.computeSizeUnit(summary[TOTAL.SIZES]))
        diskUsage = self._usage(534, path=mountPath, \
                                used=self.computeSizeUnit(usedBytes), \
                                available=self.computeSizeUnit(availableBytes))

        return '\n'.join([resultUsage, diskUsage])
    # end of _getDiskUsageOnUnix

    def _getDiskUsageOnWin(self, filePath):
        winApi = self._win32api
        availableBytes, totalBytes = winApi.GetDiskFreeSpaceEx(filePath)[:2]
        usedBytes = totalBytes - availableBytes
        drive = os.path.splitdrive(filePath)[0]
        label = winApi.GetVolumeInformation(''.join([drive, '\\']))[0]
        TOTAL = self._TOTAL
        summary = self._summary

        resultUsage = self._usage(\
            533, dirs=summary[TOTAL.DIRS], files=summary[TOTAL.FILES], \
            bytes_=summary[TOTAL.SIZES], \
            unitBytes=self.computeSizeUnit(summary[TOTAL.SIZES]))
        diskUsage = self._usage(535, drive=drive, label=label, \
                                used=self.computeSizeUnit(usedBytes), \
                                available=self.computeSizeUnit(availableBytes))

        return '\n'.join([resultUsage, diskUsage])
    # end of _getDiskUsageOnWin

    def getFileInfo(self, dir_):
        """Get the file info of all files under the given directory."""
        dir_ = os.path.abspath(self._unicode(dir_))
        affirm(os.path.isdir(dir_) and os.access(dir_, os.R_OK), \
               self._usage(501, self._str(dir_)))

        self.clearResult()
        tmpFile = self._tmpFile
        TOTAL = self._TOTAL
        self._print(dir_, tmpFile)
        self._print(self._usage(530), tmpFile)
        dirs = [dir_]
        subdirs = []
        fileInfos = []
        while dirs:
            currentDir = dirs.pop(0)
            listDirError = None
            try:
                items = os.listdir(currentDir)
            except OSError as oe:
                listDirError = getExceptionMsg(oe)
                self._print(self._usage(2, listDirError))
                items = []
            items.sort()

            fileInfos.append(\
                dict(path=os.path.relpath(currentDir, dir_), size=0, count=0, \
                     attributes=self._getAttributes(currentDir)))
            for item in items:
                itemAbsPath = getAbsPath(currentDir, item)
                # Here will not follow the symbolic link of dir if recursive
                if os.path.isdir(itemAbsPath):
                    if self._isRecursive and item not in self._exclusiveDirs \
                       and not os.path.islink(itemAbsPath):
                        subdirs.append(itemAbsPath)
                        self._summary[TOTAL.DIRS] += 1
                elif os.path.isfile(itemAbsPath):
                    attributes = self._getAttributes(itemAbsPath)
                    size = os.path.getsize(itemAbsPath)
                    fileInfos.append(dict(path=item, attributes=attributes, \
                                          size=size, count=1))
                    fileInfos[0]['size'] += size
                    fileInfos[0]['count'] += 1
                    self._summary[TOTAL.FILES] += 1
                    self._summary[TOTAL.SIZES] += size
            dirs[:0] = subdirs
            subdirs[:] = []
            for fileInfo in fileInfos:
                self._print(self._usage(531, **fileInfo), tmpFile)
            if listDirError:
                self._print(self._usage(541, \
                            comment=self._unicode(listDirError)), tmpFile)
                listDirError = None
            self._print(self._usage(532), tmpFile)
            fileInfos[:] = []
        self._print(self._getDiskUsage(dir_), tmpFile)
        self._print(self._usage(532), tmpFile)
    # end of getFileInfo

    def checkFileInfo(self, filePath):
        """
        Check the existence/size of files listed in the given file
        generated by `getFileInfo()`.
        """
        def hasDirAttribute(attributes):
            if 'd' in attributes.lower():
                return True
            return False
        # end of hasDirAttribute

        filePath = os.path.abspath(self._unicode(filePath))
        affirm(os.path.isfile(filePath) and os.access(filePath, os.R_OK), \
               self._usage(506, self._str(filePath)))

        self.clearResult()
        tmpFile = self._tmpFile
        COLUMN = self._COLUMN
        TOTAL = self._TOTAL
        summary = self._summary

        with open(filePath, 'rb') as file_:
            root = self._unicode(\
                file_.readline()).rstrip(os.linesep).strip('\x20\t')
            affirm(os.path.isabs(root), self._usage(505))
            self._print(self._usage(539, filePath), tmpFile)
            dir_ = ''
            for line in file_:
                line = self._unicode(line)
                if line.startswith(self._commentChar):
                    continue

                line = line.rstrip(os.linesep).strip('\x20\t')
                items = line.split('\t')
                # To make sure the format of a line is correct, the count
                # of `items` must be 4.
                if len(items) != 4:
                    self._print(self._usage(542, line), tmpFile)
                    continue
                # Use dir attributes instead of os.path.isdir() to determine
                # whether the path is a dir or not to prevent an issue that
                # a file with the same name as its directory.
                if hasDirAttribute(items[COLUMN.ATTRIBUTES]):
                    dir_ = getAbsPath(root, items[COLUMN.PATH])
                    continue

                pathRow = getAbsPath(dir_, items[COLUMN.PATH])
                if os.path.isfile(pathRow):
                    size = os.path.getsize(pathRow)
                    if size == int(items[COLUMN.SIZE]):
                        self._summary[TOTAL.OK] += 1
                        if self._isVerbose:
                            self._print(self._usage(536, pathRow), tmpFile)
                    else:
                        self._summary[TOTAL.NOTSIZE] += 1
                        self._print(\
                            self._usage(537, path=pathRow, filesize=size, \
                                        infosize=items[COLUMN.SIZE]), tmpFile)
                else:
                    self._summary[TOTAL.NOTFOUND] += 1
                    self._print(self._usage(538, pathRow), tmpFile)

        summary[TOTAL.FOUND] = summary[TOTAL.OK] + summary[TOTAL.NOTSIZE]
        summary[TOTAL.COUNT] = summary[TOTAL.FOUND] + summary[TOTAL.NOTFOUND]
        self._print(self._usage(540, **dict(zip(('ok', 'notsize', 'found', \
                                'notfound', 'total'), summary[TOTAL.OK:]))), \
                    tmpFile)
    # end of checkFileInfo

    def _selectFileMode(self, filePath):
        affirm(os.access(os.path.dirname(filePath), os.W_OK) \
               and not os.path.isdir(filePath), \
               self._usage(502, self._str(filePath)))

        mode = 'a'
        if os.access(filePath, os.F_OK):
            affirm(os.access(filePath, os.W_OK), \
                   self._usage(503, self._str(filePath)))
            input_ = ''
            while input_.lower() not in ('a', 'o'):
                input_ = raw_input(self._usage(551, self._str(filePath)))
                affirm(input_ != '' and input_.lower() != 'q', self._usage(15))
            if input_ == 'o':
                mode = 'w'

        return mode
    # end of _selectFileMode

    def clearResult(self):
        """Clear result."""
        self._summary[:] = [0, 0, 0, 0, 0, 0, 0, 0]
        if isinstance(self._tmpFile, SpooledTmpFile):
            self._tmpFile.close()
        self._tmpFile = SpooledTmpFile()
    # end of clearResult

    def getResult(self):
        """Return the result (SpooledTemporaryFile object)."""
        tmpFile = self._tmpFile

        if isinstance(tmpFile, SpooledTmpFile):
            if not tmpFile.closed:
                tmpFile.seek(0, os.SEEK_SET)
            return tmpFile

        return None
    # end of getResult

    def save(self, filePath):
        """Save the hash result to the specified hash file."""
        affirm(isinstance(filePath, basestring), \
               self._usage(11, arg='filePath', type_='basestring'))
        tmpFile = self.getResult()
        affirm(isinstance(tmpFile, SpooledTmpFile), self._usage(504))
        affirm(not tmpFile.closed, self._usage(504))

        filePath = os.path.abspath(self._unicode(filePath))
        mode = self._selectFileMode(filePath)

        with open(filePath, mode) as file_:
            file_.write(tmpFile.read())
    # end of save
# end of FileInfo
