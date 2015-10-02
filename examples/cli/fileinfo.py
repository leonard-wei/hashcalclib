#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# python version: 2.7.5 final, serial: 0

import argparse
import os
import signal
import sys
import traceback
import warnings

from hashcalclib import __version__, __author__, __date__
from hashcalclib.hashcalclib import FileInfo, Error
from hashcalclib.commonutil import joinExceptionArgs, getExceptionMsg, \
                                   makeStackTraceDict, str_, UsageHandler, \
                                   CharCatcher, formatText


class CmdlineUsage(UsageHandler):
    """CmdlineUsage"""

    def __init__(self):
        super(CmdlineUsage, self).__init__()
        messages = {
            701: '%(program)s - %(version)s by %(author)s, %(date)s.',
            702: 'List or check the information of files.',
            703: '"l" or "list" means listing the information of files. '\
                 '"c" or "check" means checking the information of files.',
            704: 'The information of all files under this directory will '\
                 'be retrieved.',
            705: 'The information of all files listed in this file will be '\
                 'checked.',
            706: 'Save the result to the specified file.',
            707: 'If specified, It will recursively searches all files '\
                 'under the directory. Only effective with the ACTION "l". '\
                 'Any symlink to a subdir will be ignored.',
            708: 'Specify the directories that should be excluded. '\
                 'This option could be used multiple times.',
            709: 'Do not write anything to console.',
            710: 'Output to both the file and stdout.',
            711: 'Show all output result (default only shows the "!Size" '\
                 'and "!Found").',
            712: 'Show this help message and exit.',
            713: 'usage:\n\tWhen ACTION is "list", the "-d" option '\
                 'is required.',
            714: 'usage:\n\tWhen ACTION is "check", the "-f" option '\
                 'is required.',
            715: 'The encoding that would be used to decode the path or '\
                 'content of a file. Default will try to use the following '\
                 'encoding in sequence: "utf-8", "utf-16", "ascii", "cp950".',
            731: 'Press Any Key to Continue...',
            732: '"%s" is a directory or the user has no write privilege.',
            733: '"%s" already exists and the user has no write privilege.',
            734: '*WARNING* "%s" already exists. Append, Overwrite '\
                 'or Quit(a/o/Q)? ',
            791: '%(program)s l -d dir1 -r -o file1 -X dir2 -X dir3',
            792: 'List the information of all files under directory "dir1" '\
                 'recursively (excluding "dir2" and "dir3") and output the '\
                 'results to "file1".',
            793: '%(program)s c -f file2 -o file3 -v -t',
            794: 'Check those files listed in "file2" and output the '\
                 'results to both "file3" and stdout (all results).',
        }
        self.MESSAGES.update(messages)
    # end of __init__
# end of CmdlineUsage


class HashCalculatorAction(argparse.Action):
    """For parsing arguments "ACTION" to HashCalculator."""

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values[0])
    # end of __call__
# end of HashCalculatorAction


def parseCmdArgs(usage):
    """Parsing arguments for command line"""
    description = formatText(usage(702))
    program = os.path.basename(sys.argv[0])
    example = formatText('examples:', \
                         [usage(791, program=program), usage(792)], \
                         [usage(793, program=program), usage(794)])
    parser = argparse.ArgumentParser(
        description=description, epilog=example, add_help=False, \
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('action', choices=['l', 'list', 'c', 'check'], \
                        metavar='ACTION', action=HashCalculatorAction, \
                        help=usage(703))
    parser.add_argument('-d', '--directory', dest='dir_', metavar='DIR', \
                        help=usage(704))
    parser.add_argument('-f', '--file', dest='filePath', metavar='FILE', \
                        help=usage(705))
    parser.add_argument('-o', '--output-file', dest='outputPath', \
                        metavar='FILE', help=usage(706))
    parser.add_argument('-r', '--recursive', dest='isRecursive', \
                        action='store_true', help=usage(707))
    parser.add_argument('-X', '--exclude', dest='exclusiveDirs', \
                        action='append', metavar='DIR', help=usage(708))
    parser.add_argument('-e', '--encoding', dest='encoding', \
                        metavar='ENCODING', help=usage(715))
    parser.add_argument('-S', '--silent', dest='isSilent', \
                        action='store_true', help=usage(709))
    parser.add_argument('-t', '--tee', dest='isTee', \
                        action='store_true', help=usage(710))
    parser.add_argument('-v', '--verbose', dest='isVerbose', \
                        action='store_true', help=usage(711))
    parser.add_argument('-h', '--help', action='help', help=usage(712))
    parser.add_argument('-V', '--version', action='version', \
                        version=usage(701, program=program, \
                                      version=__version__, author=__author__, \
                                      date=__date__))

    return parser.parse_args()
# end of parseCmdArgs


def handleSigInt(signum, frame):
    """Signal Handler for signal interrupt"""
    usage = UsageHandler()
    raise Error('\n' + usage(15))
# end of handleSigInt


def _main():
    """Main function to parsing arguments and error handling."""
    warnings.simplefilter('ignore')
    usage = CmdlineUsage()
    args = None
    result = [True, '']
    defaultEncoding = 'utf8'
    exceptionType = None
    stackTrace = None

    try:
        # Setup signal handler (SIGINT, Interrupt)
        signal.signal(signal.SIGINT, handleSigInt)

        # Use module argparse to parse arguments.
        args = parseCmdArgs(usage)

        # Check arguments, create FileInfo object and do the action
        #__import__('pprint').pprint(vars(args))
        if args.action == 'l':
            assert args.dir_, usage(713)
            fileInfoObj = FileInfo(args.isRecursive, args.isSilent, \
                                   args.exclusiveDirs, encoding=args.encoding)
            fileInfoObj.getFileInfo(args.dir_)
        else:
            assert args.filePath, usage(714)
            fileInfoObj = FileInfo(isSilent=args.isSilent, \
                                   isVerbose=args.isVerbose, \
                                   encoding=args.encoding)
            fileInfoObj.checkFileInfo(args.filePath)

        if args.outputPath:
            fileInfoObj.save(args.outputPath)
            if args.isTee and not args.isSilent:
                print fileInfoObj.getResult().read()
        else:
            print fileInfoObj.getResult().read()
    except (StandardError, KeyboardInterrupt, Error) as exc:
        result[0] = False
        exceptionType = type(exc)
        stackTrace = traceback.extract_tb(sys.exc_info()[-1])[-1][:3]
        if exceptionType is Error:
            result[1] = usage(2, joinExceptionArgs(exc))
        elif exceptionType is AssertionError:
            result[1] = joinExceptionArgs(exc)
        elif exceptionType is KeyboardInterrupt:
            result[1] = '\n' + usage(15)
        else:
            result[1] = usage(4, **makeStackTraceDict(stackTrace, \
                              getExceptionMsg(exc)))

    # Main Error Handling
    if result[0] is False:
        print str_(result[1], defaultEncoding)
    elif not args.isSilent:
        print usage(731)
        (CharCatcher())()
# end of _main


if __name__ == '__main__':
    _main()
# end of __main__
