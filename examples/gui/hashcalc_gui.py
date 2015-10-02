#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# python version: 2.7.5 final, serial: 0

import codecs
import os
import sys
import wxversion
wxversion.select('2.8')
import wx
import wx.html
import ConfigParser
from contextlib import closing
from hashcalclib import __version__, __author__, __date__, __copyright__, \
                        __email__
from hashcalclib.hashcalclib import _isPyblake2Imported, _isSha3Imported, \
                                    HashCalculator, affirm, unicode_, str_, \
                                    Error as hashcalclibError
from hashcalclib.commonutil import UsageHandler, Enum, getExceptionMsg
from tempfile import SpooledTemporaryFile as SpooledTmpFile
from wx.lib.filebrowsebutton import DirBrowseButton


__all__ = [
    'setClipboardData',
    'getClipboardData',
    'getConfirmation',
    'HashCalculatorApp',
    'DirBrowseWindow',
    'FileTextDropTarget',
    'HtmlDialog',
    'SpecialPopupWindow',
]

_global_platformEnum = Enum(('LINUX', 'WINDOWS', 'CYGWIN', 'OTHER'))
if sys.platform.startswith('linux'):
    _global_platform = _global_platformEnum.LINUX
elif sys.platform.startswith('win32') or sys.platform.startswith('cygwin'):
    _global_platform = _global_platformEnum.WINDOWS
else:
    _global_platform = _global_platform.OTHER


def setClipboardData(self, text=''):
    """Put text in the clipboard."""
    textObj = wx.TextDataObject()

    textObj.SetText(text)
    if wx.TheClipboard.IsOpened() or wx.TheClipboard.Open():
        wx.TheClipboard.SetData(textObj)
        wx.TheClipboard.Close()
# end of setClipboardData

def getClipboardData(self):
    """Get filenames or text in the clipboard."""
    fileObj = wx.FileDataObject()
    filenames = None
    textObj = wx.TextDataObject()
    text = ""

    if wx.TheClipboard.IsOpened() or wx.TheClipboard.Open():
        if wx.TheClipboard.GetData(fileObj):
            filenames = fileObj.GetFilenames()
        elif wx.TheClipboard.GetData(textObj):
            text = textObj.GetText()
        wx.TheClipboard.Close()

    return filenames or text
# end of getClipboardData


class HashCalculatorGUIUsage(UsageHandler):
    """HashCalculatorGUIUsage"""
    program = 'HashCalculator GUI'
    mailSubject = 'HashCalculator%%20GUI%%20Report'

    def __init__(self):
        super(HashCalculatorGUIUsage, self).__init__()
        messages = {
            601: self.program,
            602: '<h3>%s&nbsp;%s</h3>%s<br>'\
                 'Python:&nbsp;%s,&nbsp;wxPython:&nbsp;%s<p>'\
                 '%s&nbsp;&lt;<a href="mailto:%s?Subject=%s">%s</a>&gt;<p>'\
                 '%s'\
                 % (self.program, __version__, __date__, \
                    sys.version.split()[0], wx.VERSION_STRING, \
                    __author__, __email__, self.mailSubject, \
                    __email__, __copyright__),
            611: 'Files/Dirs Dropped',
            612: 'Text Dropped',
            613: 'Complete',
            614: 'Copy to clipboard',
            615: 'Get from clipboard',
            616: 'Calculating...',
            617: 'There are no selected hash type!',
            618: 'Are you sure to abort?',
            619: 'Confirm',
            620: 'Close',
            621: u"\uff33\uff55\uff4d\uff4d\uff41\uff52\uff59\uff1a\n"\
                 u"\u3000\uff2f\uff2b\u3000\u3000\u3000\u3000\u3000\u3000"\
                 u"\u3000\uff1a%(ok)8d\n\u3000\uff26\uff21\uff29\uff2c"\
                 u"\u3000\u3000\u3000\u3000\u3000\uff1a%(fail)8d\n"\
                 u"\u3000\uff26\uff4f\uff55\uff4e\uff44\u3000\u3000\u3000"\
                 u"\u3000\uff1a%(found)8d\n\u3000\uff2e\uff4f\uff54\u3000"\
                 u"\uff26\uff4f\uff55\uff4e\uff44\uff1a%(notfound)8d\n"\
                 u"\u3000\uff34\uff4f\uff54\uff41\uff4c\u3000\u3000\u3000"\
                 u"\u3000\uff1a%(total)8d",
            622: 'About',
            623: 'Are you sure to exit?',
            624: 'Add Files',
            625: 'Files Added',
            626: 'Add Directory',
            627: 'Directory Added',
            628: 'Browse',
            629: 'Send event fail!',
            630: 'Select the hash type.',
            631: 'All output cleared.',
            632: 'Results Saved.',
            633: 'Verify Files',
            634: 'Files Loaded',
            635: 'Save Results',
            636: 'Input files or text are invalid!',
            637: 'Invalid hash file or extension name '\
                 '(try to select one hash type)!',
            699: wx.EmptyString,
            801: 'Add Files(&F)\tF2',
            802: 'Add Directory(&D)\tF3',
            803: 'Add Files Recursively(&R)',
            804: 'Clear All Output(&C)\tCtrl+X',
            805: 'Exit(&E)\tCtrl+F4',
            806: 'File(&F)',
            807: 'Copy Selected Items(&C)\tCtrl+C',
            808: 'Copy All Items(&A)\tShift+C',
            809: 'Edit(&E)',
            810: 'Select All(&A)',
            811: 'Deselect All(&D)',
            812: 'CRC32(&C)',
            813: 'MD5(&M)',
            814: 'SHA1(&S)',
            815: 'ADLER32(&L)',
            816: 'MD4(&4)',
            817: 'ED2K(&E)',
            818: 'SHA224(&2)',
            819: 'SHA256(&2)',
            820: 'SHA384(&2)',
            821: 'SHA512(&2)',
            822: 'BLAKE2b(&B)',
            823: 'BLAKE2s(&B)',
            824: 'SHA3_224(&3)',
            825: 'SHA3_256(&3)',
            826: 'SHA3_384(&3)',
            827: 'SHA3_512(&3)',
            828: 'Hash Type(&T)',
            829: 'Show Hashes In Uppercase(&U)',
            830: 'New Output Mode(&N)',
            831: 'Option(&O)',
            832: 'About(&A)',
            833: 'Help(&H)',
            834: 'Paste Items(&P)\tCtrl+V',
            835: 'Show Summary(&S)',
            836: 'Save Results(&S)\tCtrl+S',
            837: 'Verify Files(&V)\tF4',
            838: 'Check Existence Only(&X)',
            839: 'Show Hash Type Sequences(&E)',
        }
        self.MESSAGES.update(messages)
    # end of __init__
# end of HashCalculatorGUIUsage


_global_usage = HashCalculatorGUIUsage()


class HashCalculatorApp(wx.App):
    """The wx.app class for `HashCalculator`."""

    _usage = _global_usage
    _frame = None
    _title = _usage(601)

    def OnInit(self):
        self._frame = HashCalculatorMainFrame(None, title=self._title)
        self.SetTopWindow(self._frame)
        self._frame.Show()

        return True
    # end of OnInit
# end of HashCalculatorApp


class HashCalculatorMainFrame(wx.Frame):
    """Main frame of `HashCalculatorApp`."""

    _usage = _global_usage
    _frameName = 'MainFrame'
    _configParser = None
    _configPath = os.path.abspath(os.path.join(os.path.dirname(__file__), \
                                               'hashcalc_gui.cfg'))
    _config = None
    _frameMinSize = (320, 200)
    _iconPath = os.path.abspath(os.path.join(os.path.dirname(__file__), \
                                             'img/HC_icon.png'))
    _iconObj = None
    _mainMenu = None
    _mainMenuEnum = Enum(('FILE', 'EDIT', 'OPTION', 'HELP', 'MAIN'))
    _mainMenuItems = None
    _fileMenuEnum = Enum(('INDEX', 'ADDFILES', 'ADDDIR', 'RECURSIVE', \
                          'VERIFY', 'EXISTENCEONLY', 'SAVE', 'CLEAR', 'EXIT'))
    _editMenuEnum = Enum(('INDEX', 'COPYSELECTED', 'COPYALL', 'PASTE'))
    _optionMenuEnum = Enum(('INDEX', 'HASHTYPE', 'SHOWHASHTYPE', 'UPPERCASE', \
                            'NEWOUTPUTMODE', 'SUMMARY', 'OPTION'))
    _hashTypeMenuEnum = Enum(\
        ('INDEX', 'SELECTALL', 'DESELECTALL', 'CRC32', 'MD5', 'SHA1', \
         'ADLER32', 'MD4', 'ED2K', 'SHA224', 'SHA256', 'SHA384', 'SHA512', \
         'BLAKE2B', 'BLAKE2S', 'SHA3_224', 'SHA3_256', 'SHA3_384', 'SHA3_512'))
    _helpMenuEnum = Enum(('INDEX', 'ABOUT'))
    _panel = None
    _mainListBox = None
    _dropTarget = None
    _progressDialog = None
    _hashCalculator = None
    _totalItems = 0
    _totalProgress = 0
    _setClipboardData = setClipboardData
    _getClipboardData = getClipboardData
    _closeFrame = None
    _hasSummary = False

    def _loadConfig(self, encoding='utf-8'):
        """
        @return True if it loaded the config successfully. False if it may
                need trying another encoding to load the config. None if it
                failed to load the config.
        """
        menuEnum = self._hashTypeMenuEnum
        self._config = {
            'Position': (100, 100),
            'Size': (640, 400),
            'LastDirectory': os.getcwdu(),
            'HashType': [menuEnum.CRC32],
            'Recursive': False,
            'ExistenceOnly': False,
            'Uppercase': True,
            'NewOutputMode': False,
            'Summary': False,
        }
        config = self._config
        self._configParser = ConfigParser.SafeConfigParser()
        configParser = self._configParser

        # Make option case sensitive.
        configParser.optionxform = str
        try:
            # Try to use the correct encoding to load the config
            configParser.readfp(codecs.open(self._configPath, 'r', encoding))
        except StandardError as exc:
            print str_(getExceptionMsg(exc))
            return None if issubclass(type(exc), UnicodeError) else False

        # General Section
        section = 'General'
        try:
            value = configParser.get(section, 'Position')
            config['Position'] = tuple(int(x) for x in value.split(','))
            value = configParser.get(section, 'Size')
            config['Size'] = tuple(int(x) for x in value.split(','))
            config['LastDirectory'] = configParser.get(section, \
                                                       'LastDirectory')
            value = configParser.get(section, 'HashType')
            config['HashType'][:] = list(int(x) for x in value.split(',')) \
                                    if value else []
            config['Recursive'] = configParser.getboolean(section, 'Recursive')
            config['ExistenceOnly'] = configParser.getboolean(\
                section, 'ExistenceOnly')
            config['Uppercase'] = configParser.getboolean(section, 'Uppercase')
            config['NewOutputMode'] = configParser.getboolean(section, \
                                                              'NewOutputMode')
            config['Summary'] = configParser.getboolean(section, 'Summary')
        except (StandardError, ConfigParser.Error) as exc:
            print str_(getExceptionMsg(exc))
            return False

        # Check if it needs trying another encoding to load the config.
        if not os.access(config['LastDirectory'], os.F_OK):
            return None

        return True
    # end of _loadConfig

    def _saveConfig(self):
        configParser = self._configParser
        config = self._config

        # Remove all current sections
        for section in configParser.sections():
            configParser.remove_section(section)

        # General Section
        section = 'General'
        configParser.add_section(section)
        config['Position'] = tuple(self.GetPosition())
        config['Size'] = tuple(self.GetSize())
        for key, value in config.items():
            if isinstance(value, (tuple, list)):
                value = ','.join(str_(x) for x in value)
            else:
                value = str_(value)
            configParser.set(section, key, value)
        with open(self._configPath, 'wb') as file_:
            configParser.write(file_)
    # end of _saveConfig

    def _createMenuItem(self, items, menu, enum, type_, name, \
                        text, help_, callback, obj=None):
        """
        menuItems = [
            {
                id1: menuItem1,
                ...,
                idX: menuItemX,
            },
            (menuItem1, subMenuItems),
            ...,
            menuItemX,
            (
                subMenu1,
            ),
        ]
        """
        objID = wx.ID_ANY
        objIdx = len(items)
        typeEnum = Enum(('CheckItem', 'RadioItem', 'Item', \
                         'Menu', 'SubMenu', 'Separator'))
        appendFunc = getattr(menu, 'Append%s' % type_)

        if not type_ or typeEnum[type_] <= typeEnum.RadioItem:
            objID = wx.NewId()
            menuItem = appendFunc(objID, text)
        elif typeEnum[type_] == typeEnum.Item:
            menuItem = appendFunc(obj)
            objID = menuItem.Id
        elif typeEnum[type_] == typeEnum.Menu:
            objID = wx.NewId()
            menuItem = appendFunc(objID, text, obj, help_)
        elif typeEnum[type_] == typeEnum.SubMenu:
            menuItem = appendFunc(obj, text, help_)
            objID = menuItem.Id
        elif typeEnum[type_] == typeEnum.Separator:
            menuItem = appendFunc()
            return

        if callback:
            self.Bind(wx.EVT_MENU, callback, menuItem)
        items[enum.INDEX][objID] = menuItem
        items.append(menuItem)
        if not enum.has_key(name) or enum[name] != objIdx:
            enum[name] = objIdx
    # end of _createMenuItem

    def _createMenuItems(self, attributes, items, menu, enum):
        usage = self._usage

        for type_, name, usageID, helpID, callback, obj in attributes:
            self._createMenuItem(items, menu, enum, type_, name, \
                                 usage(usageID), usage(helpID), callback, obj)
    # end of _createMenuItems

    def _createMainMenu(self):
        self._mainMenu = wx.MenuBar()
        mainMenu = self._mainMenu
        self._mainMenuItems = []
        mainMenuItems = self._mainMenuItems
        usage = self._usage

        # Menu: File
        menuEnum = self._fileMenuEnum
        menuItems = [dict()]
        fileMenu = wx.Menu()
        self._createMenuItems(\
            (('', 'ADDFILES', 801, 699, self._addFiles, None), \
             ('', 'ADDDIR', 802, 699, self._addDir, None), \
             ('CheckItem', 'RECURSIVE', 803, 699, \
              self._setFileMenuOption, None), \
             ('Separator', '', 0, 0, None, None), \
             ('', 'VERIFY', 837, 699, self._verifyFiles, None), \
             ('CheckItem', 'EXISTENCEONLY', 838, 699, \
              self._setFileMenuOption, None), \
             ('Separator', '', 0, 0, None, None), \
             ('', 'SAVE', 836, 699, self._saveResults, None), \
             ('', 'CLEAR', 804, 699, self._clearOutput, None), \
             ('Separator', '', 0, 0, None, None), \
             ('', 'EXIT', 805, 699, self._closeFrame, None)), \
            menuItems, fileMenu, menuEnum)
        mainMenu.Append(fileMenu, usage(806))
        mainMenuItems.append(menuItems)

        # Menu: Edit
        menuEnum = self._editMenuEnum
        menuItems = [dict()]
        editMenu = wx.Menu()
        self._createMenuItems(\
            (('', 'COPYSELECTED', 807, 699, self._copySelectedItems, None),
             ('', 'COPYALL', 808, 699, self._copyAllItems, None),
             ('', 'PASTE', 834, 699, self._pasteItems, None)),
            menuItems, editMenu, menuEnum)
        mainMenu.Append(editMenu, usage(809))
        mainMenuItems.append(menuItems)

        # Menu: Option
        # SubMenu: Hash Type
        menuEnum = self._hashTypeMenuEnum
        subMenuItems = [[dict()]]
        hashTypeMenu = wx.Menu()
        self._createMenuItems(\
            (('', 'SELECTALL', 810, 699, self._selectAllHashType, None),
             ('', 'DESELECTALL', 811, 699, self._selectAllHashType, None),
             ('Separator', '', 0, 0, None, None),
             ('CheckItem', 'CRC32', 812, 699, self._selectHashType, None),
             ('CheckItem', 'MD5', 813, 699, self._selectHashType, None),
             ('CheckItem', 'SHA1', 814, 699, self._selectHashType, None),
             ('Separator', '', 0, 0, None, None),
             ('CheckItem', 'ADLER32', 815, 699, self._selectHashType, None),
             ('CheckItem', 'MD4', 816, 699, self._selectHashType, None),
             ('CheckItem', 'ED2K', 817, 699, self._selectHashType, None),
             ('Separator', '', 0, 0, None, None),
             ('CheckItem', 'SHA224', 818, 699, self._selectHashType, None),
             ('CheckItem', 'SHA256', 819, 699, self._selectHashType, None),
             ('CheckItem', 'SHA384', 820, 699, self._selectHashType, None),
             ('CheckItem', 'SHA512', 821, 699, self._selectHashType, None),
             ('Separator', '', 0, 0, None, None),
             ('CheckItem', 'BLAKE2B', 822, 699, self._selectHashType, None),
             ('CheckItem', 'BLAKE2S', 823, 699, self._selectHashType, None),
             ('Separator', '', 0, 0, None, None),
             ('CheckItem', 'SHA3_224', 824, 699, self._selectHashType, None),
             ('CheckItem', 'SHA3_256', 825, 699, self._selectHashType, None),
             ('CheckItem', 'SHA3_384', 826, 699, self._selectHashType, None),
             ('CheckItem', 'SHA3_512', 827, 699, self._selectHashType, None)), \
            subMenuItems[-1], hashTypeMenu, menuEnum)
        menuEnum = self._optionMenuEnum
        menuItems = [dict()]
        optionMenu = wx.Menu()
        self._createMenuItems(\
            (('Menu', 'HASHTYPE', 828, 630, None, hashTypeMenu),
             ('', 'SHOWHASHTYPE', 839, 699, self._showHashType, None), \
             ('CheckItem', 'UPPERCASE', 829, 699, \
              self._setOptionMenuOption, None),
             ('CheckItem', 'NEWOUTPUTMODE', 830, 699, \
              self._setOptionMenuOption, None),
             ('Separator', '', -1, -1, None, None), \
             ('CheckItem', 'SUMMARY', 835, 699, \
              self._setOptionMenuOption, None)),
            menuItems, optionMenu, menuEnum)
        menuItems[menuEnum.HASHTYPE] = (menuItems[menuEnum.HASHTYPE], \
                                        subMenuItems.pop(0))
        menuItems.append((None, hashTypeMenu))
        mainMenu.Append(optionMenu, usage(831))
        mainMenuItems.append(menuItems)

        # Menu: Help
        menuEnum = self._helpMenuEnum
        menuItems = [dict()]
        helpMenu = wx.Menu()
        self._createMenuItems(\
            (('', 'ABOUT', 832, 699, self._showAboutInfo, None),), \
            menuItems, helpMenu, menuEnum)
        mainMenu.Append(helpMenu, usage(833))
        mainMenuItems.append(menuItems)

        mainMenuItems.append((fileMenu, editMenu, optionMenu, helpMenu))
        self.SetMenuBar(mainMenu)
    # end of _createMainMenu

    def _initHashCalculator(self):
        hashCalculatorKwargs = {
            'action': 'c',
            'isSilent': True,
        }
        self._hashCalculator = HashCalculator(**hashCalculatorKwargs)
    # end of _initHashCalculator

    def _initOptions(self):
        eventHandler = self.GetEventHandler()
        mainMenuEnum = self._mainMenuEnum
        mainMenuItems = self._mainMenuItems
        mainMenus = mainMenuItems[mainMenuEnum.MAIN]
        config = self._config

        # File Menu
        menuEnum = self._fileMenuEnum
        menuItems = mainMenuItems[mainMenuEnum.FILE]
        if config['Recursive']:
            menuItem = menuItems[menuEnum.RECURSIVE]
            menuItem.Check(True)
            sendEvent(wx.wxEVT_COMMAND_MENU_SELECTED, menuItem.Id, \
                      mainMenus[mainMenuEnum.FILE], eventHandler)
        if config['ExistenceOnly']:
            menuItem = menuItems[menuEnum.EXISTENCEONLY]
            menuItem.Check(True)
            sendEvent(wx.wxEVT_COMMAND_MENU_SELECTED, menuItem.Id, \
                      mainMenus[mainMenuEnum.FILE], eventHandler)
        # With no results, disable save menu.
        self._enableSaveMenu(False)

        # Option Menu
        menuEnum = self._optionMenuEnum
        menuItems = mainMenuItems[mainMenuEnum.OPTION]
        if config['Uppercase']:
            menuItem = menuItems[menuEnum.UPPERCASE]
            menuItem.Check(True)
            sendEvent(wx.wxEVT_COMMAND_MENU_SELECTED, menuItem.Id, \
                      mainMenus[mainMenuEnum.OPTION], eventHandler)
        if config['NewOutputMode']:
            menuItem = menuItems[menuEnum.NEWOUTPUTMODE]
            menuItem.Check(True)
            sendEvent(wx.wxEVT_COMMAND_MENU_SELECTED, menuItem.Id, \
                      mainMenus[mainMenuEnum.OPTION], eventHandler)
        if config['Summary']:
            menuItem = menuItems[menuEnum.SUMMARY]
            menuItem.Check(True)
            sendEvent(wx.wxEVT_COMMAND_MENU_SELECTED, menuItem.Id, \
                      mainMenus[mainMenuEnum.OPTION], eventHandler)

        # Check hash module(disable if failed to import)
        menuEnum = self._hashTypeMenuEnum
        menuItems = mainMenuItems[mainMenuEnum.OPTION]\
                    [self._optionMenuEnum.HASHTYPE][1]
        menuItems[menuEnum.BLAKE2B].Enable(_isPyblake2Imported)
        menuItems[menuEnum.BLAKE2S].Enable(_isPyblake2Imported)
        menuItems[menuEnum.SHA3_224].Enable(_isSha3Imported)
        menuItems[menuEnum.SHA3_256].Enable(_isSha3Imported)
        menuItems[menuEnum.SHA3_384].Enable(_isSha3Imported)
        menuItems[menuEnum.SHA3_512].Enable(_isSha3Imported)

        # Hash Type Menu
        for idx in config['HashType']:
            menuItem = menuItems[idx]
            if menuItem.IsEnabled():
                menuItem.Check(True)
                sendEvent(wx.wxEVT_COMMAND_MENU_SELECTED, menuItem.Id, \
                          mainMenus[mainMenuEnum.OPTION], eventHandler)
    # end of _initOptions

    def __init__(self, parent, id_=wx.ID_ANY, title=_frameName, \
                 pos=wx.DefaultPosition, size=wx.DefaultSize, \
                 style=wx.DEFAULT_FRAME_STYLE, name=_frameName):
        # Init and load configurations.
        if not os.access(os.path.dirname(self._configPath), os.R_OK | os.W_OK):
            self._configPath = os.path.join(os.path.expanduser('~'), \
                                            'hashcalc_gui.cfg')
        if self._loadConfig(sys.stdin.encoding) is None:
            self._loadConfig()
        position = self._config['Position']
        size = self._config['Size']
        super(HashCalculatorMainFrame, self).__init__(\
            parent, id_, title, position, size, style, name)
        self.SetMinSize(self._frameMinSize)

        # Shortcut of wx.Frame.Close() for event binding
        self._closeFrame = lambda *x: self.Close()

        # Set the application icon.
        if os.path.islink(__file__):
            self._iconPath = os.path.abspath(os.path.join(os.path.dirname(\
                             os.path.realpath(__file__)), 'img/HC_icon.png'))
        if os.access(self._iconPath, os.R_OK):
            self._iconObj = wx.Icon(self._iconPath, wx.BITMAP_TYPE_PNG)
            self.SetIcon(self._iconObj)

        # Create main menu.
        self._createMainMenu()

        # Create status bar.
        self.CreateStatusBar()

        # Create main panel.
        self._panel = wx.Panel(self, wx.ID_ANY)

        # Create drop target.
        self._dropTarget = FileTextDropTarget(self._onFileDrop, \
                                              self._onTextDrop)

        # Create main listbox.
        style = wx.LB_EXTENDED | wx.LB_HSCROLL
        self._mainListBox = wx.ListBox(self._panel, choices=[], style=style)
        self._mainListBox.SetDropTarget(self._dropTarget)

        # Create sizer.
        flags = wx.ALL | wx.EXPAND | wx.CENTRE
        self._topSizer = wx.BoxSizer(wx.VERTICAL)
        self._topSizer.Add(self._mainListBox, 1, flags, 0)
        self._panel.SetSizer(self._topSizer)
        #self._topSizer.Fit(self)

        # Init the `HashCalculator` object.
        self._initHashCalculator()

        # Init the options from the configurations
        self._initOptions()

        # Bind events.
        self.Bind(wx.EVT_CLOSE, self._onClose, self)
        #self.Bind(wx.EVT_SIZE, self._onSize, self)
    # end of __init__

    def _addFiles(self, event):
        config = self._config
        style = wx.FD_OPEN | wx.FD_MULTIPLE | wx.FD_CHANGE_DIR
        dialog = wx.FileDialog(self, self._usage(624), style=style, \
                               defaultDir=config['LastDirectory'])
        if dialog.ShowModal() == wx.ID_OK:
            filePaths = dialog.GetPaths()
            config['LastDirectory'] = os.path.dirname(filePaths[0])
            self.SetStatusText(self._usage(625))
            self._calculateHashes(filePaths)
        if dialog:
            dialog.Destroy()
    # end of _addFiles

    def _addDir(self, event):
        config = self._config
        mainMenu = self._mainMenu
        mainMenuEnum  = self._mainMenuEnum
        menuEnum = self._fileMenuEnum
        menuItem = self._mainMenuItems[mainMenuEnum.FILE][menuEnum.RECURSIVE]
        eventHandler = self.GetEventHandler()
        style = wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER
        dialog = DirBrowseWindow(self.GetTopLevelParent(), self._usage(626), \
                                 style, config['LastDirectory'])
        """
        style = wx.DD_DEFAULT_STYLE | wx.DD_DIR_MUST_EXIST | wx.DD_CHANGE_DIR
        dialog = wx.DirDialog(self, self._usage(626), style=style)
        """
        if menuItem.IsChecked():
            dialog.checkRecursive()
        if dialog.ShowModal() == wx.ID_OK:
            menuItem.Check(dialog.isRecursiveChecked())
            sendEvent(\
                wx.wxEVT_COMMAND_MENU_SELECTED, menuItem.Id, \
                mainMenu.GetMenu(mainMenuEnum.FILE), eventHandler, \
                dialog.isRecursiveChecked())
            dirPath = dialog.GetPath()
            if os.path.isdir(dirPath):
                config['LastDirectory'] = dirPath
                self.SetStatusText(self._usage(627))
                self._calculateHashes([dirPath])
        if dialog:
            dialog.Destroy()
    # end of _addDir

    def _verifyFiles(self, event):
        config = self._config
        style = wx.FD_OPEN | wx.FD_MULTIPLE | wx.FD_CHANGE_DIR
        dialog = wx.FileDialog(self, self._usage(633), style=style, \
                               defaultDir=config['LastDirectory'])
        if dialog.ShowModal() == wx.ID_OK:
            filePaths = dialog.GetPaths()
            config['LastDirectory'] = os.path.dirname(filePaths[0])
            self.SetStatusText(self._usage(634))
            self._verifyHashes(filePaths)
        if dialog:
            dialog.Destroy()
    # end of _verifyFiles

    def _enableSaveMenu(self, isEnabled):
        menuEnum = self._fileMenuEnum
        menuItems = self._mainMenuItems[self._mainMenuEnum.FILE]
        menuItems[menuEnum.SAVE].Enable(isEnabled)
    # end of _enableSaveMenu

    def _saveResults(self, event):
        style = wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT | wx.FD_CHANGE_DIR
        dialog = wx.FileDialog(self, self._usage(635), style=style)
        if dialog.ShowModal() == wx.ID_OK:
            filePath = dialog.GetPath()
            with open(filePath, 'w') as file_:
                for item in self._mainListBox.GetItems():
                    file_.write(str_(item))
            self.SetStatusText(self._usage(632))
        if dialog:
            dialog.Destroy()
    # end of _saveResults

    def _setFileMenuOption(self, event):
        menuItemID = event.Id
        menuEnum = self._fileMenuEnum
        menuItems = self._mainMenuItems[self._mainMenuEnum.FILE]
        menuItem = menuItems[menuEnum.INDEX][menuItemID]
        hashCalculator = self._hashCalculator
        config = self._config

        if menuItemID == menuItems[menuEnum.RECURSIVE].Id:
            hashCalculator.setRecursive(menuItem.IsChecked())
            config['Recursive'] = menuItem.IsChecked()
        elif menuItemID == menuItems[menuEnum.EXISTENCEONLY].Id:
            hashCalculator.setExistenceOnly(menuItem.IsChecked())
            config['ExistenceOnly'] = menuItem.IsChecked()
    # end of _setFileMenuOption

    def _clearOutput(self, event):
        self._mainListBox.Clear()
        self._enableSaveMenu(False)
        self.SetStatusText(self._usage(631))
    # end of _clearOutput

    def _showHashType(self, event):
        hashCalculator = self._hashCalculator
        self.SetStatusText(' | '.join(hashCalculator.getAlgorithms()).upper())
    # end of _showHashType

    def _setOptionMenuOption(self, event):
        menuItems = self._mainMenuItems[self._mainMenuEnum.OPTION]
        menuEnum = self._optionMenuEnum
        menuItem = menuItems[menuEnum.INDEX][event.Id]
        hashCalculator = self._hashCalculator
        config = self._config

        if menuItem.Id == menuItems[menuEnum.UPPERCASE].Id:
            hashCalculator.setUppercase(menuItem.IsChecked())
            config['Uppercase'] = menuItem.IsChecked()
        elif menuItem.Id == menuItems[menuEnum.NEWOUTPUTMODE].Id:
            hashCalculator.setNewOutputMode(menuItem.IsChecked())
            config['NewOutputMode'] = menuItem.IsChecked()
        elif menuItem.Id == menuItems[menuEnum.SUMMARY].Id:
            self._hasSummary = menuItem.IsChecked()
            config['Summary'] = menuItem.IsChecked()
    # end of _setOptionMenuOption

    def _selectHashType(self, event):
        menuItems = self._mainMenuItems[self._mainMenuEnum.OPTION]\
                    [self._optionMenuEnum.HASHTYPE][1]
        menuEnum = self._hashTypeMenuEnum
        hashTypeItem = menuItems[menuEnum.INDEX][event.Id]
        algorithm = None
        algorithmEnum = None
        hashCalculator = self._hashCalculator
        config = self._config

        for enumStr, value in menuEnum.items():
            if value <= menuEnum.DESELECTALL:
                continue
            elif hashTypeItem.Id == menuItems[value].Id:
                algorithm = enumStr.lower()
                algorithmEnum = value
                break
        if hashTypeItem.IsChecked():
            hashCalculator.addAlgorithm(algorithm)
            if algorithmEnum not in config['HashType']:
                config['HashType'].append(algorithmEnum)
        else:
            hashCalculator.delAlgorithm(algorithm)
            if algorithmEnum in config['HashType']:
                config['HashType'].remove(algorithmEnum)
        self.SetStatusText(' | '.join(hashCalculator.getAlgorithms()).upper())
    # end of _selectHashType

    def _selectAllHashType(self, event):
        mainMenuEnum = self._mainMenuEnum
        mainMenus = self._mainMenuItems[mainMenuEnum.MAIN]
        menuItems = self._mainMenuItems[mainMenuEnum.OPTION]\
                    [self._optionMenuEnum.HASHTYPE][1]
        menuEnum = self._hashTypeMenuEnum
        menuItem = None
        eventHandler = self.GetEventHandler()
        hashCalculator = self._hashCalculator
        isSelectAll = True if event.Id == menuItems[menuEnum.SELECTALL].Id \
                           else False
        config = self._config

        hashCalculator.clearAlgorithms()
        config['HashType'][:] = []
        enumValues = menuEnum.values()
        enumValues.sort()
        for idx in enumValues[3:]:
            menuItem = menuItems[idx]
            if menuItem.IsEnabled():
                menuItem.Check(isSelectAll)
                sendEvent(\
                    wx.wxEVT_COMMAND_MENU_SELECTED, menuItem.Id, \
                    mainMenus[mainMenuEnum.OPTION], eventHandler, \
                    isSelectAll)
    # end of _selectAllHashType

    def _showAboutInfo(self, event):
        dialog = HtmlDialog(self.GetTopLevelParent(), self._usage(622), \
                            self._usage(602), (290, 200))
        dialog.ShowModal()
        if dialog:
            dialog.Destroy()
    # end of _showAboutInfo

    def _createProgressDialog(self):
        """Create the Progress Dialog."""
        title = self._usage(616)
        message = ''
        style = (wx.PD_AUTO_HIDE | wx.PD_APP_MODAL | wx.PD_CAN_ABORT \
                 | wx.PD_ELAPSED_TIME | wx.PD_ESTIMATED_TIME \
                 | wx.PD_REMAINING_TIME)
        self._progressDialog = wx.ProgressDialog(\
            title, message, maximum=101, parent=self, style=style)

        return self._progressDialog
    # end of _createProgressDialog

    def _showProgressCallback(self, progress, text):
        dialog = self._progressDialog
        progress = (progress * 100) if progress <= 1.0 else 100.0
        totalProgress = self._totalProgress + (progress / self._totalItems)
        continue_ = True

        self.SetStatusText('%3d%% | %s' % (progress, text))
        continue_ = dialog.Update(int(totalProgress), text)[0]
        if progress >= 100.0:
            self._totalProgress = totalProgress
        if not continue_:
            if getConfirmation(self.GetTopLevelParent(), \
                               self._usage(618), self._usage(619)):
                raise KeyboardInterrupt
            else:
                dialog.Resume()
    # end of _showProgressCallback

    def _parseSrcItems(self, files, text):
        hashCalculator = self._hashCalculator
        srcFiles = []
        srcDirs = []

        hashCalculator.clearSrcItems()
        if isinstance(files, list):
            for file_ in files:
                if os.path.isfile(file_):
                    srcFiles.append(file_)
                elif os.path.isdir(file_):
                    srcDirs.append(file_)
            try:
                hashCalculator.addSrcFiles(srcFiles)
                hashCalculator.addSrcDirs(srcDirs)
            except hashcalclibError as he:
                showError(self.GetTopLevelParent(), self._usage(636))
                print str_(getExceptionMsg(he))
                return False
        elif isinstance(text, basestring):
            try:
                hashCalculator.addSrcStrings([text])
            except hashcalclibError as he:
                showError(self.GetTopLevelParent(), self._usage(636))
                print str_(getExceptionMsg(he))
                return False
        else:
            showError(self.GetTopLevelParent(), self._usage(636))
            return False

        return True
    # end of _parseSrcItems

    def _calculateHashes(self, files=None, text=None):
        hashCalculator = self._hashCalculator
        if not hashCalculator.getAlgorithms():
            self.SetStatusText(self._usage(617))
            return False

        resultEnum = Enum(('SUMMARY', 'LOG', 'HASHSTOCK'))
        result = None

        hashCalculator.setAction('c')
        if not self._parseSrcItems(files, text):
            return False

        dialog = self._createProgressDialog()
        hashCalculator.setupProgressBar(self._showProgressCallback)
        try:
            hashCalculator._computeItemsCount()
            self._totalItems =  hashCalculator._totalItems
            self._totalProgress = 0.0
            hashCalculator.act()
            self.SetStatusText(self._usage(613))
        except KeyboardInterrupt:
            self.SetStatusText(self._usage(15))
        finally:
            result = hashCalculator.getResult()
            # Print log if any errors occurred
            result[resultEnum.LOG].seek(0, os.SEEK_SET)
            for line in result[resultEnum.LOG]:
                self._mainListBox.Append(unicode_(line))
            hashCalculator.clearLog()
            # Print hash result
            with closing(SpooledTmpFile()) as file_:
                result[resultEnum.HASHSTOCK].save(file_)
                file_.seek(0, os.SEEK_SET)
                for line in file_:
                    self._mainListBox.Append(unicode_(line))
            if result[resultEnum.SUMMARY]['total'] != 0:
                # If there are any results, enable save menu.
                self._enableSaveMenu(True)
            if dialog:
                dialog.Update(101)
                dialog.Destroy()
            if self._hasSummary:
                window = SpecialPopupWindow(\
                    self.GetTopLevelParent(), wx.SIMPLE_BORDER, \
                    self._usage(621, **result[resultEnum.SUMMARY]))
                window.Show()
    # end of _calculateHashes

    def _parseHashFiles(self, files):
        hashCalculator = self._hashCalculator

        hashCalculator.clearSrcItems()
        if isinstance(files, list):
            try:
                for file_ in files:
                    hashCalculator.parseHashFile(file_)
            except hashcalclibError as he:
                showError(self.GetTopLevelParent(), self._usage(637))
                print str_(getExceptionMsg(he))
                return False
        else:
            showError(self.GetTopLevelParent(), self._usage(637))
            return False

        return True
    # end of _parseHashFiles

    def _verifyHashes(self, files=None):
        hashCalculator = self._hashCalculator
        resultEnum = Enum(('SUMMARY', 'LOG', 'HASHSTOCK'))
        result = None

        hashCalculator.setAction('v')
        if not self._parseHashFiles(files):
            return False

        dialog = self._createProgressDialog()
        hashCalculator.setupProgressBar(self._showProgressCallback)
        try:
            hashCalculator._computeItemsCount()
            self._totalItems =  hashCalculator._totalItems
            self._totalProgress = 0.0
            hashCalculator.setVerbose(True)
            hashCalculator.act()
            hashCalculator.setVerbose(False)
            self.SetStatusText(self._usage(613))
        except KeyboardInterrupt:
            self.SetStatusText(self._usage(15))
        finally:
            result = hashCalculator.getResult()
            result[resultEnum.LOG].seek(0, os.SEEK_SET)
            for line in result[resultEnum.LOG]:
                self._mainListBox.Append(unicode_(line))
            hashCalculator.clearLog()
            if result[resultEnum.SUMMARY]['total'] != 0:
                # If there are any results, enable save menu.
                self._enableSaveMenu(True)
            if dialog:
                dialog.Update(101)
                dialog.Destroy()
            if self._hasSummary:
                window = SpecialPopupWindow(\
                    self.GetTopLevelParent(), wx.SIMPLE_BORDER, \
                    self._usage(621, **result[resultEnum.SUMMARY]))
                window.Show()
    # end of _verifyHashes

    def _onFileDrop(self, files):
        self.SetStatusText(self._usage(611))
        self._calculateHashes(files)
    # end of _onFileDrop

    def _onTextDrop(self, text):
        self.SetStatusText(self._usage(612))
        self._calculateHashes(None, text)
    # end of _onTextDrop

    def _copySelectedItems(self, event):
        text = ''
        for idx in self._mainListBox.GetSelections():
            text = ''.join([text, self._mainListBox.GetString(idx)])
        self._setClipboardData(text)
        self.SetStatusText(self._usage(614))
    # end of _copySelectedItems

    def _copyAllItems(self, event):
        text = ''
        for item in self._mainListBox.GetItems():
            text = ''.join([text, item])
        self._setClipboardData(text)
        self.SetStatusText(self._usage(614))
    # end of _copyAllItems

    def _pasteItems(self, event):
        data = self._getClipboardData()
        if isinstance(data, list):
            self._calculateHashes(data)
        elif isinstance(data, basestring):
            self._calculateHashes(None, data)
    # end of _pasteItems

    def _onSize(self, event):
        event.Skip()
    # end of _onSize

    def _onClose(self, event):
        try:
            if event.CanVeto():
                if not getConfirmation(self.GetTopLevelParent(), \
                                       self._usage(623), self._usage(619)):
                    event.Veto()
                    return
            # Save current configurations, window size, position, ..., etc.
            self._saveConfig()
        except (StandardError, ConfigParser.Error) as exc:
            print str_(getExceptionMsg(exc))

        # event.Skip()
        self.Destroy()
    # end of _onClose
# end of MainFrame


def sendEvent(eventType, targetID, eventObj, eventHandler, isSetInt=True, \
              eventClass=wx.CommandEvent):
    """Send a event manually."""
    usage = _global_usage
    event = eventClass(eventType, targetID)
    if isSetInt:
        event.SetInt(1)
    event.SetEventObject(eventObj)
    #wx.PostEvent(eventHandler, event)
    affirm(eventHandler.ProcessEvent(event), usage(629))
# end of sendEvent

def getConfirmation(parent, message, caption=''):
    style = wx.YES_NO | wx.ICON_QUESTION | wx.STAY_ON_TOP | wx.CENTRE
    dialog = wx.MessageDialog(parent, message, caption, style)
    decision = dialog.ShowModal()
    if dialog:
        dialog.Destroy()

    if decision == wx.ID_YES:
        return True
    else:
        return False
    """
    Input in other windows is still possible (modeless).
    return True if wx.MessageBox(message, caption, style, parent) == wx.YES \
                else False
    """
# end of getConfirmation

def showMessageDialog(parent, message, caption='', style=wx.OK):
    dialog = wx.MessageDialog(parent, message, caption, style)
    dialog.ShowModal()
    if dialog:
        dialog.Destroy()
# end of showMessageDialog

def showInformation(parent, message, caption=''):
    style = wx.OK | wx.ICON_INFORMATION | wx.STAY_ON_TOP | wx.CENTRE
    showMessageDialog(parent, message, caption, style)
# end of showInformation

def showError(parent, message, caption=''):
    style = wx.OK | wx.ICON_ERROR | wx.STAY_ON_TOP | wx.CENTRE
    showMessageDialog(parent, message, caption, style)
# end of showError


class DirBrowseWindow(wx.Dialog):
    """A window for browsing/selecting directory."""

    _usage = _global_usage
    _dirButton = None
    _checkbox = None

    def __init__(self, parent, title, style=wx.DEFAULT_DIALOG_STYLE, \
                 startDirectory=u"."):
        super(DirBrowseWindow, self).__init__(parent, title=title, style=style)
        self.SetMinSize((300, 150))
        self.Centre(wx.BOTH)

        panel = wx.Panel(self, wx.ID_ANY)
        self._dirButton = DirBrowseButton(\
            panel, wx.ID_ANY, labelText='', buttonText=self._usage(628), \
            dialogTitle=title, startDirectory=startDirectory, \
            dialogClass=wx.DirDialog, newDirectory=False)
        dirButton = self._dirButton
        self._checkbox = wx.CheckBox(panel, wx.ID_ANY, self._usage(803))
        checkbox = self._checkbox
        okButton = wx.Button(panel, wx.ID_OK)
        cancelButton = wx.Button(panel, wx.ID_CANCEL)

        flags = wx.ALL | wx.EXPAND
        topSizer = wx.BoxSizer(wx.VERTICAL)
        dirSubSizer = wx.BoxSizer(wx.HORIZONTAL)
        checkboxSubSizer = wx.BoxSizer(wx.HORIZONTAL)
        spaceSubSizer = wx.BoxSizer(wx.HORIZONTAL)
        buttonSubSizer = wx.StdDialogButtonSizer()
        dirSubSizer.Add(dirButton, 1, wx.ALL, 0)
        checkboxSubSizer.Add(checkbox, 0, wx.LEFT | wx.RIGHT, 7)
        buttonSubSizer.AddButton(okButton)
        buttonSubSizer.AddButton(cancelButton)
        buttonSubSizer.Realize()
        topSizer.Add(dirSubSizer, 0, flags, 5)
        topSizer.Add(checkboxSubSizer, 0, flags, 5)
        topSizer.Add(spaceSubSizer, 1, flags, 5)
        topSizer.Add(wx.StaticLine(panel), 0, flags, 5)
        topSizer.Add(buttonSubSizer, 0, flags, 5)
        panel.SetSizer(topSizer)
        self.SetSize((500, 150))
    # end of __init__

    def GetPath(self):
        """Return the selected directory path."""
        return self._dirButton.GetValue()
    # end of GetPath

    def isRecursiveChecked(self):
        """Return if the checkbox of Recursive is checked."""
        return self._checkbox.IsChecked()
    # end of isRecursiveChecked

    def checkRecursive(self, isChecked=True):
        """Check the checkbox of Recursive."""
        self._checkbox.SetValue(isChecked)
    # end of checkRecursive
# end of DirBrowseButton


class FileTextDropTarget(wx.PyDropTarget):
    """Drop target capable of accepting dropped files and text."""

    _fileCallback = None
    _textCallback = None
    _dataObj = None
    _fileDataObj = None
    _textDataObj = None

    def __init__(self, fileCallback, textCallback):
        affirm((callable(fileCallback) and callable(textCallback)))
        self._fileCallback = fileCallback
        self._textCallback = textCallback

        super(FileTextDropTarget, self).__init__()

        # Init the text and file data objects
        self._dataObj = wx.DataObjectComposite()
        self._fileDataObj = wx.FileDataObject()
        self._textDataObj = wx.TextDataObject()

        self._dataObj.Add(self._textDataObj, False)
        self._dataObj.Add(self._fileDataObj, True)
        self.SetDataObject(self._dataObj)
    # end of __init__

    def InitObjects(self):
        pass
    # end of InitObjects

    def OnData(self, x, y, default):
        """Called by the framewortk when data is dropped on target."""
        if self.GetData():
            format_ = self._dataObj.GetReceivedFormat()
            if format_.GetType() == wx.DF_FILENAME:
                self._fileCallback(self._fileDataObj.GetFilenames())
            else:
                self._textCallback(self._textDataObj.GetText())
    # end of OnData
# end of FileTextDropTarget


class HtmlWindow(wx.html.HtmlWindow):
    def __init__(self, parent, id_, pos=wx.DefaultPosition, \
                 size=wx.DefaultSize):
        super(HtmlWindow, self).__init__(parent, id_, pos, size)
        if "gtk2" in wx.PlatformInfo:
            self.SetStandardFonts()
    # end of __init__

    def OnLinkClicked(self, link):
        wx.LaunchDefaultBrowser(link.GetHref())
    # end of OnLinkClicked
# end of HtmlWindow


class HtmlDialog(wx.Dialog):
    """
    A dialog to show a HTML content,
    `parent`:   The parent of this dialog.
    `caption`:  The caption of this dialog.
    `htmlText`: The HTML content to show.
    `htmlSize`: Set the width and height to the appropriate values to show
                the content you want (or to avoid the scroll bar aside).
    `htmlOffset`:
                A tuple with two elements (width, height) to adjust the
                html window if you find the scroll bar still appeared.

    """

    _usage = _global_usage
    _parent = None
    _panel = None
    _window = None
    _button = None

    def __init__(self, parent, caption, htmlText, htmlSize, htmlOffset=(0, 0)):
        style = wx.DEFAULT_DIALOG_STYLE
        super(HtmlDialog, self).__init__(parent, wx.ID_ANY, caption, \
                                         style=style)

        self._panel = wx.Panel(self)
        panel = self._panel
        self._window = HtmlWindow(panel, wx.ID_ANY, (20, 0), htmlSize)
        window = self._window
        self._button = wx.Button(panel, wx.ID_OK, self._usage(620))
        button = self._button
        sizeBase = None
        buttonSize = button.GetSize()
        htmlOffset = tuple([x + 15 for x in htmlOffset])

        window.SetPage(htmlText)
        window.SetBackgroundColour(self.GetBackgroundColour())
        # For window size
        container = window.GetInternalRepresentation()
        sizeBase = wx.Size(container.GetWidth() + htmlOffset[0], \
                           container.GetHeight() + htmlOffset[1])
        window.SetSize(sizeBase)
        # For dialog and panel size
        sizeBase.SetWidth(\
            sizeBase.width + (20 \
            if _global_platform == _global_platformEnum.WINDOWS else 40))
        sizeBase.SetHeight(sizeBase.height + buttonSize.height + 10)
        self.SetClientSize(sizeBase)
        panel.SetSize(sizeBase)
        # Adjust positions
        button.SetPosition(\
            ((sizeBase.width - buttonSize.width) / 2, \
             sizeBase.height - buttonSize.height - 5))
        self.CentreOnParent(wx.BOTH)
        self.SetFocus()
    # end of __init__
# end of HtmlDialog


class SpecialPopupWindow(wx.PopupWindow):
    """
    This is a special kind of top level window that can be dragged
    with the left mouse button and closed with the right one. If there
    are tabs in the text, the actual ident space may not be the same
    on various platform.
    `parent`:   The parent of this window.
    `style`:    The style of this dialog.
    `text`:     The text to show.
    `center`:   Move the window to the center of its parent.
    """

    _usage = _global_usage
    _parent = None
    _panel = None
    _button = None
    _staticText = None
    _center = None
    _windowBackgroundColor = None
    _panelBackgroundColor = '#ADD9E6'   #'light blue'
    _oldMousePosition = None
    _oldWindowPosition = None

    def __init__(self, parent, style, text, center=True):
        super(SpecialPopupWindow, self).__init__(parent, style)

        self._parent = parent
        self._panel = wx.Panel(self)
        panel = self._panel
        self._button = wx.Button(panel, wx.ID_OK, self._usage(620))
        button = self._button
        self.setText(text)
        staticText = self._staticText
        if isinstance(center, bool) and center:
            self._center = center
        self._windowBackgroundColor = self.GetBackgroundColour()

        self.setBackgroundColor(self._panelBackgroundColor)
        self._autoAdjustWindow()
        button.Bind(wx.EVT_BUTTON, self._onMouseRightUp)
        panel.Bind(wx.EVT_LEFT_DOWN, self._onMouseLeftDown)
        panel.Bind(wx.EVT_MOTION, self._onMouseMotion)
        panel.Bind(wx.EVT_LEFT_UP, self._onMouseLeftUp)
        panel.Bind(wx.EVT_RIGHT_UP, self._onMouseRightUp)
        staticText.Bind(wx.EVT_LEFT_DOWN, self._onMouseLeftDown)
        staticText.Bind(wx.EVT_MOTION, self._onMouseMotion)
        staticText.Bind(wx.EVT_LEFT_UP, self._onMouseLeftUp)
        staticText.Bind(wx.EVT_RIGHT_UP, self._onMouseRightUp)

        wx.CallAfter(self.Refresh)
    # end of __init__

    def setText(self, text, isAutoAdjustment=True):
        if self._staticText is None:
            self._staticText = wx.StaticText(self._panel, 1, \
                                             text, pos=(10, 10))
        else:
            self._staticText.SetLabel(text)

        if isinstance(isAutoAdjustment, bool) and isAutoAdjustment:
            self._autoAdjustWindow()
    # end of _setText

    def setBackgroundColor(self, panelColor, windowColor=None):
        if isinstance(windowColor, basestring):
            self._windowBackgroundColor = windowColor
        else:
            windowColor = self._windowBackgroundColor
        self.SetBackgroundColour(windowColor)
        self._panel.SetBackgroundColour(panelColor)
    # end of setBackgroundColor

    def _autoAdjustWindow(self):
        panel = self._panel
        button = self._button
        staticText = self._staticText
        center = self._center
        sizeBase = staticText.GetBestSize()
        buttonSize = button.GetSize()

        # Set the width for the button if the `GetBestSize()` of the text
        # is too small.
        if sizeBase.width < buttonSize.width:
            sizeBase.SetWidth(buttonSize.width)
        staticText.SetSize(sizeBase)
        # Set the size of the window and panel for `staticText` and `button`
        sizeBase.SetWidth(sizeBase.width + 20)
        sizeBase.SetHeight(sizeBase.height + buttonSize.height + 30)
        panel.SetSize((sizeBase.width, sizeBase.height))
        self.SetSize((sizeBase.width, sizeBase.height))

        if center:
            self._centreOnParent()
        button.SetPosition(\
            ((sizeBase.width - buttonSize.width) / 2, \
             sizeBase.height - buttonSize.height - 5))
    # end of _autoAdjustWindow

    def _centreOnParent(self):
        parent = self._parent
        """
        On Windows platform, the Centre() would set the popup window to
        the position whose actual values of x and y axis are the offsets
        of the position of the parent and its centre. But the GetPosition()
        would return the position of that relative position plus the
        position of the parent. This makes the inconsistency on
        different platform. So we calculate the position manually.
        """
        # window.Centre(wx.BOTH)
        relativePosition = tuple(\
            [(x - y) / 2 for x, y in zip(parent.GetSize(), self.GetSize())])
        #    [(x, y + 24) for x, y in (self.GetPosition(),)])[0]
        self.Position(parent.GetPosition(), relativePosition)
    # end of _centreOnParent

    def _onMouseLeftDown(self, event):
        self.Refresh()
        self._oldMousePosition = \
            event.GetEventObject().ClientToScreen(event.GetPosition())
        self._oldWindowPosition = self.ClientToScreen((0, 0))
        self._panel.CaptureMouse()
    # end of _onMouseLeftDown

    def _onMouseMotion(self, event):
        if event.Dragging() and event.LeftIsDown():
            newMousePosition = \
                event.GetEventObject().ClientToScreen(event.GetPosition())
            newWindowX = self._oldWindowPosition.x + newMousePosition.x \
                         - self._oldMousePosition.x
            newWindowY = self._oldWindowPosition.y + newMousePosition.y - \
                         self._oldMousePosition.y
            self.Move((newWindowX, newWindowY))
    # end of _onMouseMotion

    def _onMouseLeftUp(self, event):
        if self._panel.HasCapture():
            self._panel.ReleaseMouse()
    # end of _onMouseLeftUp

    def _onMouseRightUp(self, event):
        self.Show(False)
        self.Destroy()
    # end of _onMouseRightUp
# end of SpecialPopupWindow


def _main():
    usage = _global_usage
    try:
        app = HashCalculatorApp(False)
        app.SetAppName(usage(601))

        app.MainLoop()
    except KeyboardInterrupt:
        sys.exit(0)
# end of _main

if __name__ == '__main__':
    _main()
# end of __main__

