#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# python version: 2.7.5 final, serial: 0

__version__ = '1.6.0a'

import os
import sys
import wx
from contextlib import closing
from tempfile import SpooledTemporaryFile as SpooledTmpFile

from hashcalclib import HashCalculator, affirm, unicode_
from commonutil import UsageHandler


class HashCalculatorGUIUsage(UsageHandler):
    """HashCalculatorGUIUsage"""

    def __init__(self):
        super(HashCalculatorGUIUsage, self).__init__()
        messages = {
            601: 'HashCalculatorGUI',
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
    _config = {
        'position': (300, 300),
        'size': (640, 400),
    }

    def OnInit(self):
        self._frame = MainFrame(None, title=self._title, \
                                pos=self._config['position'], \
                                size=self._config['size'])

        self.SetTopWindow(self._frame)
        self._frame.Show()

        return True
    # end of OnInit
# end of HashCalculatorApp


class MainFrame(wx.Frame):
    """Main frame of `HashCalculatorApp`."""

    _frameMinSize = (320, 200)
    _iconPath = os.path.abspath(os.path.join(os.path.dirname(__file__), \
                                             'img/HC_icon.png'))
    _iconObj = None
    _mainMenu = None
    _mainListBox = None
    _dropTarget = None
    _hashCalculator = None
    _wxExit = None

    def _createMainMenu(self):
        self._mainMenu = wx.MenuBar()
        fileMenu = wx.Menu()
        fileMenu.Append(wx.NewId(), 'Open(&O)')
        fileMenu.Append(wx.NewId(), 'Clear Output(&C)')
        self.Bind(wx.EVT_MENU, self._clearOutput, \
                  fileMenu.FindItemByPosition(1))
        fileMenu.AppendSeparator()
        fileMenu.Append(wx.NewId(), 'Exit(&X)')
        self.Bind(wx.EVT_MENU, self._wxExit, fileMenu.FindItemByPosition(3))
        self._mainMenu.Append(fileMenu, 'File(&F)')
        editMenu = wx.Menu()
        editMenu.Append(wx.NewId(), 'Copy Selected Items(&C)')
        self.Bind(wx.EVT_MENU, self._copySelectedItems, \
                  editMenu.FindItemByPosition(0))
        editMenu.Append(wx.NewId(), 'Copy All Items(&A)')
        self.Bind(wx.EVT_MENU, self._copyAllItems, \
                  editMenu.FindItemByPosition(1))
        self._mainMenu.Append(editMenu, 'Edit(&E)')
        optionMenu = wx.Menu()
        hashTypeMenu = wx.Menu()
        hashTypeMenu.AppendCheckItem(wx.NewId(), 'CRC32(&3)')
        hashTypeMenu.AppendCheckItem(wx.NewId(), 'MD5(&5)')
        hashTypeMenu.AppendCheckItem(wx.NewId(), 'SHA1(&1)')
        hashTypeMenu.AppendSeparator()
        hashTypeMenu.AppendCheckItem(wx.NewId(), 'MD4(&4)')
        hashTypeMenu.AppendCheckItem(wx.NewId(), 'ED2K(&2)')
        hashTypeMenu.AppendSeparator()
        hashTypeMenu.AppendCheckItem(wx.NewId(), 'SHA224(&4)')
        hashTypeMenu.AppendCheckItem(wx.NewId(), 'SHA256(&6)')
        hashTypeMenu.AppendCheckItem(wx.NewId(), 'SHA384(&8)')
        hashTypeMenu.AppendCheckItem(wx.NewId(), 'SHA512(&2)')
        optionMenu.AppendSubMenu(hashTypeMenu, 'Hash Type(&T)')
        self._mainMenu.Append(optionMenu, 'Option(&O)')
        helpMenu = wx.Menu()
        helpMenu.Append(wx.NewId(), 'About(&A)')
        self._mainMenu.Append(helpMenu, 'Help(&H)')
        self.SetMenuBar(self._mainMenu)
    # end of _createMainMenu

    def __init__(self, parent, fid=wx.ID_ANY, title='MainFrame', \
                 pos=wx.DefaultPosition, size=wx.DefaultSize, \
                 style=wx.DEFAULT_FRAME_STYLE, name='MainFrame'):
        super(MainFrame, self).__init__(parent, fid, title, pos, size, \
                                        style, name)

        # Application Icon
        if os.access(self._iconPath, os.R_OK):
            self._iconObj = wx.Icon(self._iconPath, wx.BITMAP_TYPE_PNG)
            self.SetIcon(self._iconObj)

        # Frame Size
        self.SetMinSize(self._frameMinSize)

        # Shortcut of wx.Exit()
        self._wxExit = lambda *x: wx.Exit()

        # Main Menu
        self._createMainMenu()

        # Drop target
        self._dropTarget = FileTextDropTarget(self._OnFileDrop, \
                                              self._OnTextDrop)

        # Main List
        self._mainListBox = wx.ListBox(self, choices=[])
        self._mainListBox.SetDropTarget(self._dropTarget)

        # Status Bar
        self.CreateStatusBar()

        # Init the HashCalculator Object
        hashCalculatorKwargs = {
            'action': 'c',
            'algorithms': ['md5', 'crc32'],
            'isUppercase': True,
            'isSilent': True,
        }
        self._hashCalculator = HashCalculator(**hashCalculatorKwargs)

        # Panel
        #self.panel = wx.Panel(self)
    # end of __init__

    def _clearOutput(self, event):
        self._mainListBox.Clear()
    # end of _clearOutput

    def _OnFileDrop(self, Files):
        srcFiles = []

        self.PushStatusText('Files Dropped')
        srcFiles[:] = Files
        self._hashCalculator.clearSrcItems()
        self._hashCalculator.addSrcFiles(srcFiles)
        self._hashCalculator.act()
        with closing(SpooledTmpFile()) as file_:
            self._hashCalculator.getResult()[2].save(file_)
            file_.seek(0, os.SEEK_SET)
            for line in file_:
                self._mainListBox.Append(unicode_(line))
        self.PushStatusText('Complete')
    # end of _OnFileDrop

    def _OnTextDrop(self, Text):
        srcStrings = []

        self.PushStatusText('Text Dropped')
        srcStrings.append(Text)
        self._hashCalculator.clearSrcItems()
        self._hashCalculator.addSrcStrings(srcStrings)
        self._hashCalculator.act()
        with closing(SpooledTmpFile()) as file_:
            self._hashCalculator.getResult()[2].save(file_)
            file_.seek(0, os.SEEK_SET)
            for line in file_:
                self._mainListBox.Append(unicode_(line))
        self.PushStatusText('Complete')
    # end of _OnTextDrop

    def _setClipboardText(self, text=''):
        """Put text in the clipboard."""
        textObj = wx.TextDataObject()

        textObj.SetText(text)
        if wx.TheClipboard.IsOpened() or wx.TheClipboard.Open():
            wx.TheClipboard.SetData(textObj)
            wx.TheClipboard.Close()
    # end of _setClipboardText

    def _getClipboardText(self):
        """Get text in the clipboard."""
        text = ""
        textObj = wx.TextDataObject()

        if wx.TheClipboard.IsOpened() or wx.TheClipboard.Open():
            if wx.TheClipboard.GetData(textObj):
                text = textObj.GetText()
            wx.TheClipboard.Close()

        return text
    # end of _getClipboardText

    def _copySelectedItems(self, event):
        text = ''
        for idx in self._mainListBox.GetSelections():
            text = ''.join([text, self._mainListBox.GetString(idx)])
        self._setClipboardText(text)
    # end of _copySelectedItems

    def _copyAllItems(self, event):
        text = ''
        for item in self._mainListBox.GetItems():
            text = ''.join([text, item])
        self._setClipboardText(text)
    # end of _copyAllItems
# end of MainFrame


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
