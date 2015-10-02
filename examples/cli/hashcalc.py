#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# python version: 2.7.5 final, serial: 0

import argparse
import os
import signal
import sys
import traceback
import warnings

from hashcalclib import __version__, __author__, __email__, __date__
from hashcalclib.hashcalclib import HashCalculator, Error
from hashcalclib.commonutil import joinExceptionArgs, getExceptionMsg, \
                                   makeStackTraceDict, str_, UsageHandler, \
                                   CharCatcher, formatText


class CmdlineUsage(UsageHandler):
    """CmdlineUsage"""

    def __init__(self):
        super(CmdlineUsage, self).__init__()
        messages = {
            101: '%(program)s - %(version)s by %(author)s <%(email)s>, '\
                 '%(date)s.',
            102: 'The path of the file that contains the hash info '\
                 'could be verified or which the calculated hash info will '\
                 'be saved to. If ACTION is "v", this argument is a '\
                 '*MUST* argument. If ACTION is "c", this argument '\
                 'is optional and the hash result will be saved to the '\
                 'file specified instead of console. A line start with "*" '\
                 'is considered as a comment.',
            103: 'If ACTION is "c", this is a *MUST* argument to decide '\
                 'which hash algorithm will be used to calculate the hash. '\
                 'If ACTION is "e", this argument is a optional to specify '\
                 'the output format of the extracted hash info. '\
                 'If ACTION is "v", this argument is optional to specify '\
                 'the hash algorithm to use for verification (default will '\
                 'use the extname to determine, described later). '\
                 'The valid arguments and the corresponding extnames (in '\
                 'parenthesis) are "crc32"(*.sfv), "md5"(*.md5), "sha1"'\
                 '(*.sha1), "sha224"(*.sha224), "sha256"(*.sha256'\
                 '), "sha384"(*.sha384), "sha512"(*.sha512), "md4"(*.md4), '\
                 '"ed2k"(*.ed2k), "blake2b"(*.blake2b), '\
                 '"blake2s"(*.blake2s), "sha3_224"(*.sha3224), '\
                 '"sha3_256"(*.sha3256), "sha3_384"(*.sha3384), '\
                 '"sha3_512"(*.sha3512), "adler32"(*.sfva). This option '\
                 'could be used multiple times, but specify the same '\
                 'algorithm multiple times will only apply once.',
            104: 'The files need to be calculated/extracted their hashes. '\
                 'This option could be used multiple times.',
            105: 'usage:\n\tWhen ACTION is "extract" or "verify", more '\
                 'than one "-a" option is not allowed.',
            106: 'If specified, return the hash code in uppercase. '\
                 'Only effective with ACTION "c" and "e".',
            107: 'If specified, calculate the hash of the given '\
                 'strings instead of files. This option could be '\
                 'used multiple times.',
            108: '"c" or "calculate" means calculating the hash of files. '\
                 '"e" or "extract" means extracting the hash from filenames. '\
                 '"v" or "verify" means verifying the hash of files. If '\
                 'ACTION is "V" and the "-a" option is not given, make sure '\
                 'the extnames of files specified by "-o" or "-O" option '\
                 'are in the support list (see the description of "-a" '\
                 'option for more details.',
            109: 'usage:\n\tWhen ACTION is "verify", the "-s", "-f", '\
                 '"-d" and "-i" options are not allowed.',
            110: 'usage:\n\tWhen ACTION is "verify", the "-o" or "-O" '\
                 'option is required.',
            111: 'usage:\n\tWhen ACTION is "calculate", the "-a" '\
                 'option is required.',
            112: 'usage:\n\tWhen ACTION is "calculate" or "extract", '\
                 'at least one of the "-s", "-f", "-d" and "-i" '\
                 'options are required.',
            113: 'All files under this directory will be calculated their '\
                 'hashes. This option could be used multiple times.',
            114: 'If specified, It will recursively searches all files '\
                 'under the directory and calculates their hashes. Only '\
                 'effective with the "-d" option. Any symlink to a '\
                 'subdir will be ignored.',
            115: 'Press Any Key to Continue...',
            116: 'The specified file must contain the paths of hash file. '\
                 'This is similar to "-o" option, but only available when '\
                 'ACTION is "v". Useful when the cli environment could not '\
                 'support unicode properly or batch verification. If both '\
                 '"-o" and "-O" are specified, it will first process the '\
                 'file specified by "-o", and then "-O". A line start with '\
                 '"*" is considered as a comment.',
            117: 'usage:\n\tOption "-O" is only available with ACTION "v".',
            118: 'The encoding that would be used to decode the path or '\
                 'content of a file. Default will try to use the following '\
                 'encoding in sequence: "utf-8", "utf-16", "ascii", "cp950".',
            119: 'The specified file must contain the strings (start with '\
                 '"STRING="), paths of any files or directories. '\
                 'This is similar to a combination of the "-s", "-f" '\
                 'and "-d" option, but only available when ACTION is '\
                 '"c". Useful when the cli environment could not '\
                 'support unicode properly or for batch calculation. '\
                 'The "-s", "-f" or "-d"  options could also be given '\
                 'as well. A line start with "*" is considered as a '\
                 'comment. Note that if the list contains a line like '\
                 '"STRING=xxx" and a file/dir named "STRING=xxx" also '\
                 'exists, they will both be processed.',
            120: '"%s" is a directory or the user has no write privilege.',
            121: '"%s" already exists and the user has no write privilege.',
            122: 'Output to stdout, as well as any hash and/or log files.',
            123: 'When specified, just check the existence of a file and no '\
                 'hashes will be verified. Only effective with action "v".',
            124: 'Show all output result (default only shows the "FAIL" and '\
                 '"Not Found"). Only effective with action "v".',
            125: '',
            126: 'A regular expression pattern used for extraction. '\
                 'It must contain at least one group "(:P<hash>...)". '\
                 'Default pattern is for "CRC32": '\
                 '"^.*(?:(?P<hlbk>\[)|(?P<hlpt>\())?(?:crc32[ _\-])?'\
                 '(?P<hash>[0-9A-Za-z]{8})(?(hlbk)\])(?(hlpt)\))'\
                 '(?:\[(?:[\w]{1,5})\])?\.[0-9A-Za-z]{2,4}$".',
            127: 'Save the output and usage to the specified log file.',
            128: 'This option provides a function which is "do the action '\
                 'on matched files". Accept a Unix shell-style wildcards '\
                 'to perform the file matching ("*" matches everying. '\
                 '"?" matches any single character. "[seq]" matches any '\
                 'character in "seq". "[!seq]" matches any character not '\
                 'in "seq").',
            129: 'This option is similar to the "-p" option, but accept a '\
                 'regular expression to perform the file matching. If the '\
                 '"-p" option is also given, this option takes precedence '\
                 'over it.',
            130: 'New output mode for hash file. The file path of every '\
                 'line is the basename of the file, and the relative dir '\
                 'path will be put in the line above those lines which '\
                 'contain the paths of files in the same directory. '\
                 'Only effective with ACTION "c" and "e". When ACTION '\
                 'is "v", the new and original format are both acceptable '\
                 'but *DO NOT* mix them together in one hash file. Also '\
                 'note that all files listed in the hash file must in the '\
                 'same directory where the hash file is located.',
            131: 'Put a directory header above the hash result of the '\
                 'files in the directory given by the option "-d". '\
                 'Only effective with ACTION "c" and "e".',
            132: 'Show this help message and exit.',
            133: 'Calculate, extract or verify the hashes.',
            134: 'Do not write anything to console.',
            135: '*WARNING* "%s" already exists. Append, Overwrite '\
                 'or Quit(a/o/Q)? ',
            136: 'Specify the directories that should be excluded("-r" '\
                 'option is given). This option could be used multiple times.',
            191: '%(program)s c -a crc32 -a md5 -u -f file1 -d dir1 -r'\
                 ' -o file2 -t',
            192: 'Calculate the hash of "file1" and all files under '\
                 'directory "dir1" recursively and the hash is uppercase. '\
                 'Also save the result to "file2" and output to stdout.',
            193: '%(program)s v -a md5 -o file3 -O file4 -p "*.ext"',
            194: 'Verify those files specified in "file3" and each file '\
                 'listed in "file4" whose filenames end with ".ext". '\
                 'Which algorithm to be selected is up to the extname '\
                 'of hashfile(e.g., "file3") and if the extname is not '\
                 'supported(e.g., "txt"), default algorithm will be "md5".',
            195: '%(program)s e -d dir2 -l file5',
            196: 'Extract the hash from the filenames of all files under '\
                 'directory "dir2". Save the log and result to "file5". '\
                 'Note that the default extraction pattern and output '\
                 'format are for "CRC32". If the pattern is changed for '\
                 '"MD5", the option "-a" must be given as "md5" explicitly.',
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
    description = formatText(usage(133))
    program = os.path.basename(sys.argv[0])
    example = formatText('examples:', \
                         [usage(191, program=program), usage(192)], \
                         [usage(193, program=program), usage(194)], \
                         [usage(195, program=program), usage(196)])
    parser = argparse.ArgumentParser(
        description=description, epilog=example, add_help=False, \
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('action', choices=['c', 'calculate', \
                                           'e', 'extract', \
                                           'v', 'verify',], \
                        metavar='ACTION', action=HashCalculatorAction, \
                        help=usage(108))
    parser.add_argument('-a', '--algorithm', dest='algorithms', \
                        choices=['crc32', 'md5', 'sha1', 'sha224', \
                                 'sha256', 'sha384', 'sha512', 'md4', \
                                 'ed2k', 'blake2b', 'blake2s', 'sha3_224', \
                                 'sha3_256', 'sha3_384', 'sha3_512', \
                                 'adler32'], \
                        metavar='ALGORITHM', \
                        action='append', help=usage(103))
    parser.add_argument('-s', '--string', dest='srcStrings', metavar='STRING', \
                        action='append', help=usage(107))
    parser.add_argument('-f', '--file', dest='srcFiles', metavar='FILE', \
                        action='append', help=usage(104))
    parser.add_argument('-d', '--directory', dest='srcDirs', metavar='DIR', \
                        action='append', help=usage(113))
    parser.add_argument('-i', '--src-items-file', dest='srcItemsFile', \
                        metavar='FILE', help=usage(119))
    parser.add_argument('-r', '--recursive', dest='isRecursive', \
                        action='store_true', help=usage(114))
    parser.add_argument('-u', '--uppercase', dest='isUppercase', \
                        action='store_true', help=usage(106))
    parser.add_argument('-n', '--new-output-mode', dest='isNewOutputMode', \
                        action='store_true', help=usage(130))
    parser.add_argument('-H', '--directory-header', dest='hasDirHeader', \
                        action='store_true', help=usage(131))
    parser.add_argument('-o', '--hash-file', dest='hashFile', \
                        metavar='FILE', help=usage(102))
    parser.add_argument('-O', '--hash-paths-file', dest='hashPathsFile', \
                        metavar='FILE', help=usage(116))
    parser.add_argument('-x', '--existence-only', dest='isExistenceOnly', \
                        action='store_true', help=usage(123))
    parser.add_argument('-P', '--extraction-pattern', metavar='PATTERN', \
                        dest='extractionPattern', help=usage(126))
    parser.add_argument('-e', '--encoding', dest='encoding', \
                        metavar='ENCODING', help=usage(118))
    parser.add_argument('-l', '--log', dest='logFile', \
                        metavar='FILE', help=usage(127))
    parser.add_argument('-p', '--unix-file-filter', metavar='PATTERN', \
                        dest='unixFileFilterPattern', help=usage(128))
    parser.add_argument('-R', '--regex-file-filter', metavar='PATTERN', \
                        dest='regexFileFilterPattern', help=usage(129))
    parser.add_argument('-X', '--exclude', dest='exclusiveDirs', \
                        action='append', metavar='DIR', help=usage(136))
    parser.add_argument('-S', '--silent', dest='isSilent', \
                        action='store_true', help=usage(134))
    parser.add_argument('-t', '--tee', dest='isTee', \
                        action='store_true', help=usage(122))
    parser.add_argument('-v', '--verbose', dest='isVerbose', \
                        action='store_true', help=usage(124))
    parser.add_argument('-h', '--help', action='help', help=usage(132))
    parser.add_argument('-V', '--version', action='version', \
                        version=usage(101, program=program, \
                                      version=__version__, author=__author__, \
                                      email=__email__, date=__date__))

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
    hashCalculatorKwargs = None
    result = [True, '']
    defaultEncoding = 'utf8'
    exceptionType = None
    stackTrace = None

    try:
        # Setup signal handler (SIGINT, Interrupt)
        signal.signal(signal.SIGINT, handleSigInt)

        # Use module argparse to parse arguments.
        args = parseCmdArgs(usage)

        # Check arguments
        #__import__('pprint').pprint(vars(args))
        if args.action == 'c'  or args.action == 'e':
            assert args.algorithms or args.action == 'e', usage(111)
            if args.action == 'e':
                assert len(args.algorithms or []) <= 1, usage(105)
            assert args.srcStrings or args.srcFiles or args.srcDirs \
                   or args.srcItemsFile , usage(112)
            assert not args.hashPathsFile, usage(117)
        else:
            assert len(args.algorithms or []) <= 1, usage(105)
            assert args.hashFile or args.hashPathsFile, usage(110)
            assert not (args.srcStrings or args.srcFiles or args.srcDirs \
                        or args.srcItemsFile), usage(109)

        # Create HashCalculator object and do the action
        hashCalculatorKwargs = vars(args)
        hashCalculatorKwargs['fileBufSize'] = None

        hashCalculatorObj = HashCalculator(**hashCalculatorKwargs)
        hashCalculatorObj.actAuto()
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
        print usage(115)
        (CharCatcher())()
# end of _main


if __name__ == '__main__':
    _main()
# end of __main__
