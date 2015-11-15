/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       UI.H
*
*  VERSION:     1.31
*
*  DATE:        12 Nov 2015
*
*  Common header file for the user interface.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define SplitterSize          3
#define SplitterMargin        80

typedef	struct _OE_LIST_ITEM {
	struct _OE_LIST_ITEM *Prev;
	HTREEITEM	TreeItem;
} OE_LIST_ITEM, *POE_LIST_ITEM;

typedef HWND(WINAPI *pfnHtmlHelpW)(
	_In_opt_ HWND hwndCaller,
	_In_ LPCWSTR pszFile,
	_In_ UINT uCommand,
	_In_ DWORD_PTR dwData
	);

#define PROGRAM_VERSION            L"1.3.2"
#define PROGRAM_NAME               L"Windows Object Explorer 64-bit"
#define PROFRAM_NAME_AND_TITLE     L"Object Explorer for Windows 7/8/8.1/10"
#define MAINWINDOWCLASSNAME        L"WinObjEx64Class"


#define T_PROPERTIES               L"Properties...\tEnter"
#define T_GOTOLINKTARGET           L"Go To Link Target\tCtrl+->"
#define T_RUNASADMIN               L"R&un as Administrator"
#define T_COPYTEXTROW              L"Copy Row Selection"
#define T_COPYVALUE                L"Copy Value Field Text"
#define T_SAVETOFILE               L"Save list to File"

#define WOBJ_MAX_DIALOGS 5

#define WOBJ_FINDDLG_IDX 0
#define WOBJ_PIPEDLG_IDX 1
#define WOBJ_USDDLG_IDX  2
#define WOBJ_PNDLG_IDX   3
#define WOBJ_SSDTDLG_IDX 4

HWND g_wobjDialogs[WOBJ_MAX_DIALOGS];

//global variables
BOOL            bSortInverse;
HWND            MainWindow, StatusBar, ObjectTree, ObjectList, ToolBar1, Splitter;
LPWSTR          CurrentObjectPath;
HIMAGELIST      TreeViewImages, ListViewImages, ToolBarMenuImages;
pfnHtmlHelpW    pHtmlHelpW;
