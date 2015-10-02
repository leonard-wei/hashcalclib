#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# python version: 2.7.5 final, serial: 0
# Author: Leonard Wei <gooxxgle.mail@gmail.com>

"""Common utilities"""

import codecs
import inspect
import os
import sys
import textwrap
import time

__all__ = [
    'joinExceptionArgs',
    'getExceptionMsg',
    'makeStackTraceDict',
    'str_',
    'unicode_',
    'getAbsPath',
    'Enum',
    'UsageHandler',
    'ProgressBar',
    'CharCatcher',
    'formatText'
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


def joinExceptionArgs(exc):
    """ `exc` should be the exception object"""
    return u", ".join(unicode_(s) for s in exc.args)
# end of joinExceptionArgs


def getExceptionMsg(exc):
    """ `exc` should be the exception object"""
    return u"%s: %s" % (type(exc).__name__, joinExceptionArgs(exc))
# end of getExceptionMsg


def makeStackTraceDict(stackTrace, msg='None'):
    """
    `stackTrace`:   A tuple like (filename, lineNo, functionName)
                    which is the first three elements of a stack trace
                    entry extracted from a traceback object.
    """
    return  dict(zip(('file', 'line', 'func', 'msg'), stackTrace + (msg,)))
# end of makeStackTraceDict


def str_(obj, encoding='utf-8', errors='ignore'):
    """Encode by default encoding if unicode"""
    if isinstance(obj, unicode):
        return obj.encode(encoding, errors)
    elif isinstance(obj, str):
        return obj
    else:
        return str(obj)
# end of str_


def _toUTF16(obj):
    nullChar = '\x00'

    if obj.startswith(nullChar):
        obj = obj[1:]
    if obj.endswith(('\r', '\n')):
        obj = obj + nullChar
    try:
        obj = unicode(obj, 'utf-16')
    except UnicodeError:
        return None

    return obj
# end of _toUTF16


def _processEncodings(encoding, encodings):
    sysEncoding = ''

    if isinstance(sys.stdin, file) \
       and isinstance(sys.stdin.encoding, basestring):
        sysEncoding = sys.stdin.encoding
        try:
            tmpEncoding = codecs.lookup(sysEncoding).name
        except LookupError:
            tmpEncoding = sys.getdefaultencoding()
        if tmpEncoding not in encodings:
            encodings.insert(0, tmpEncoding)

    if isinstance(encoding, basestring):
        try:
            tmpEncoding = codecs.lookup(encoding).name
            if tmpEncoding in encodings:
                encodings.remove(tmpEncoding)
            encodings.insert(0, tmpEncoding)
        except LookupError:
            tmpEncoding = ''
# end of _processEncodings


def unicode_(obj, encoding=None, errors='ignore'):
    """Transform the object to Unicode."""
    unicodeObj = None
    encodings = ['utf-8', 'utf-16', 'ascii']
    defaultEncoding = encodings[0]

    _processEncodings(encoding, encodings)

    if isinstance(obj, unicode):
        return obj
    elif isinstance(obj, (list, tuple, set, frozenset)):
        unicodeObj = []
        for item in obj:
            unicodeObj.append(unicode_(item, encoding))
        return type(obj)(unicodeObj)
    elif isinstance(obj, dict):
        objKeys = unicode_(obj.keys(), encoding)
        objValues = unicode_(obj.values(), encoding)
        unicodeObj = dict(zip(objKeys, objValues))
        return unicodeObj
    elif not isinstance(obj, str):
        obj = str(obj)

    isDecoded = False
    for encoding_ in encodings:
        # Try to solve the decoding issue for utf-16.
        if encoding_ == 'utf-16':
            unicodeObj = _toUTF16(obj)
            if unicodeObj is not None:
                isDecoded = True
                break
            continue
        try:
            unicodeObj = unicode(obj, encoding_)
            isDecoded = True
            break
        except UnicodeError:
            continue
    if not isDecoded:
        unicodeObj = unicode(obj, encoding or defaultEncoding, errors)

    return unicodeObj
# end of unicode_


def getAbsPath(dir_, path):
    """Return the joined absolute path."""
    if not os.path.isabs(path):
        return os.path.abspath(os.path.join(dir_, path))

    return path
# end of getAbsPath


class Enum(dict):
    """A class for the enumeration.
    `names`:    A tuple or list contains the symbolic names(strings).
    `values`:   The start value of the enumeration or a tuple(list) of
                all enumeration values corresponding to the given names.
    """

    def __init__(self, names=tuple(), values=0):
        if isinstance(values, int):
            items = tuple(enumerate(names, values))
        elif isinstance(values, (tuple, list)):
            items = zip(values, names)
        else:
            raise ValueError('`values` must be an integer, a tuple or a list.')
        for value, name in items:
            self.__dict__[name] = value
        super(Enum, self).__init__(self.__dict__)
    # end of __init__

    def __setitem__(self, name, value):
        self.__dict__[name] = value
        super(Enum, self).__setitem__(name, value)
    # end of __setitem__
# end of Enum


class UsageHandler(object):
    """Handle usage message, `msgid`: 0~10 reserved."""

    HR =  '-'
    MESSAGES = {
        1: 'Internal Error(%s)!',
        2: 'usage: %s',
        3: 'usage:\n\t%s',
        4: '%(file)s: %(func)s(): %(line)d: %(msg)s',
        11: 'Argument `%(arg)s` must be %(type_)s type.',
        12: 'Invalid argument `%(arg)s`: %(value)s.',
        13: 'The argument is out of range. The valid range is %s.',
        14: '"%(path)s" not exists or no privileges.',
        15: 'User canceled.',
        16: 'Invalid argument `%(var)s`: %(msg)s(%(value)s).',
    }

    def __init__(self):
        self.MESSAGES = dict(self.MESSAGES)
    # end of __init__

    def __call__(self, msgId, *args, **kwargs):
        try:
            message = self.MESSAGES[msgId] % (kwargs or args)
        except StandardError:
            # At least get the core message out if something wrong
            message = self.MESSAGES[1] % (type(self).__name__)

        return message
    # end of __call__
# end of UsageHandler


class ProgressBarUsage(UsageHandler):
    """ProgressBarUsage"""

    def __init__(self):
        super(ProgressBarUsage, self).__init__()
        messages = {
            301: '`barStyle` must be a list containing 5 items of '\
                 'single character.',
        }
        self.MESSAGES.update(messages)
    # end of __init__
# end of ProgressBarUsage


class ProgressBar(object):
    """Print and update the progress bar on cli
    `barWidth`:     Determine the width of progress bar(including the
                    length of '[', ']' and percentage. Default looks
                    like "[======>...] 100%"). Minimum value is 8.
    `barStyle`:     A list to determine the style of progress bar.
                    Default ['[', '=', '>', '.', ']'] looks like
                    "[======>...]".
    `dotPrecision`: If not specified, default is 0. 1 means the
                    percentage of progress would be "n.m%", and
                    2 means "n.mm%", ...etc.
    `isOutput`:     Either print the bar to stdout or return.
    """

    _usage = ProgressBarUsage()
    _lineWidth = 0
    _barWidth = 17
    _barStyle = ['[', '=', '>', '.', ']']
    _dotPrecision = 0
    _isOutput = False
    _barFormat = None
    _stdout = sys.stdout

    def __init__(self, barWidth=None, barStyle=None, dotPrecision=None, \
                 isOutput=False):
        try:
            windowWidth = int(os.environ['COLUMNS'])
        except (KeyError, ValueError):
            windowWidth = 80
        finally:
            self._lineWidth = windowWidth - 2

        if barWidth is not None:
            affirm(isinstance(barWidth, int), \
                   self._usage(11, arg='barWidth', type_='int'))
            affirm(8 <= barWidth and barWidth <= self._lineWidth, \
                   self._usage(13, '8 <= `barWidth` <= %d' % self._lineWidth))
            self._barWidth = barWidth

        if barStyle is not None:
            affirm(isinstance(barStyle, list) and len(barStyle) == 5, \
                   self._usage(301))
            self._barStyle = barStyle
            for idx in range(5):
                self._barStyle[idx] = str(self._barStyle[idx])[0]

        if dotPrecision is not None:
            affirm(isinstance(dotPrecision, int), \
                   self._usage(11, arg='dotPrecision', type_='int'))
            affirm(0 <= dotPrecision, \
                   self._usage(13, '`dotPrecision` >= 0'))
            self._dotPrecision = dotPrecision

        if isOutput is not None:
            affirm(isinstance(isOutput, bool), \
                   self._usage(11, arg='isOutput', type_='bool'))
            self._isOutput = isOutput

        self._barFormat = '\r' + self._barStyle[0] + '%s%s%s' + \
                          self._barStyle[4] + ' %*.*f%%'
    # end of __init__

    def _print(self, obj):
        obj = str_(obj)
        self._stdout.write(obj)
        self._stdout.flush()
    # end of _print

    def update(self, progress):
        """Return the progress bar text"""
        affirm(isinstance(progress, float), \
               self._usage(11, arg='progress', type_='float'))
        affirm(0 <= progress and progress <= 1, \
               self._usage(13, '0 <= `progress` <= 1'))

        numBarWidth = 3 + (self._dotPrecision + 1 \
                           if self._dotPrecision else 0)
        # 4 if the sum of len('['), len(']'), len(' ') and len('%')
        charBarWidth = self._barWidth - 4 - numBarWidth
        finished = int(charBarWidth * progress)
        barStyle = self._barStyle
        if 0 < finished and finished < charBarWidth:
            finished -= 1
            indicator = 1
        else:
            indicator = 0
        progressStr = self._barFormat % (\
            barStyle[1] * finished, barStyle[2] * indicator, \
            barStyle[3] * (charBarWidth - finished - indicator), \
            numBarWidth, self._dotPrecision, progress * 100)
        if self._isOutput:
            self._print(progressStr)
            if progress == 1.0:
                self._print('\r' + ' ' * len(progressStr) + '\r')
        else:
            return progressStr
    # end of update

    def demo(self, speed=10, isPausePerTen=True):
        for num in range(0, 101, 1):
            progress = num / 100.0
            self._print(self.update(progress))
            time.sleep(1.0 / speed)
            if isPausePerTen and num % 10 == 0:
                time.sleep(5.0 / speed)
            if progress == 1.0:
                print
    # end of demo
# end of ProgressBar


class CharCatcher(object):
    """Get a single character from standard input."""

    _msvcrtModule = None
    _termiosModule = None
    _ttyModule = None
    getChar = None

    def _getCharOnUnix(self):
        tty = self._ttyModule
        termios = self._termiosModule

        fd = sys.stdin.fileno()
        oldTtyAttr = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            char = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, oldTtyAttr)

        return char
    # end of _getCharOnUnix

    def _getCharOnWin(self):
        msvcrt = self._msvcrtModule

        return msvcrt.getch()
    # end of _getCharOnWin

    def __init__(self):
        try:
            self._msvcrtModule = __import__('msvcrt')
            self.getChar = self._getCharOnWin
        except ImportError:
            self._termiosModule = __import__('termios')
            self._ttyModule = __import__('tty')
            self.getChar = self._getCharOnUnix
    # end of __init__

    def __call__(self):
        return self.getChar()
    # end of __call__
# end of CharCatcher


def formatText(heading=None, *textGroup):
    titlePosition = 2
    textPosition = 24
    try:
        windowWidth = int(os.environ['COLUMNS'])
    except (KeyError, ValueError):
        windowWidth = 80
    finally:
        lineWidth = windowWidth - 2
    titleWidth = lineWidth - titlePosition
    textWidth = lineWidth - textPosition
    finalText = []

    if isinstance(heading, basestring):
        heading = textwrap.fill(heading, lineWidth)
        finalText.extend([heading, '\n'])

    for title, text in textGroup:
        title = textwrap.wrap(title, titleWidth)
        for line in title:
            finalText.append('%*s%s\n' % (titlePosition, '', line))
        text = textwrap.wrap(text, textWidth)
        for line in text:
            finalText.append('%*s%s\n' % (textPosition, '', line))

    return ''.join(finalText)
# end of formatText
