/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       UI.H
*
*  VERSION:     1.20
*
*  DATE:        23 July 2015
*
*  Common header file for the user interface.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#define SplitterSize			3L
#define SplitterMargin			80L

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

#define PROGRAM_VERSION				L"1.2.0"
#define PROGRAM_NAME				L"Windows Object Explorer 64-bit"
#define PROFRAM_NAME_AND_TITLE		L"Object Explorer for Windows 7/8/8.1/10"
#define MAINWINDOWCLASSNAME			L"WinObjAdvClass"


#define T_PROPERTIES				L"Properties...\tEnter"
#define T_GOTOLINKTARGET			L"Go To Link Target\tCtrl+->"
#define T_RUNASADMIN				L"R&un as Administrator"
#define T_COPYTEXTROW				L"Copy Row Selection"
#define T_COPYVALUE					L"Copy Value Field Text"


//global variables
BOOL			bSortInverse;
HWND			MainWindow, StatusBar, ObjectTree, ObjectList, ToolBar1, Splitter, FindDialog, PipeDialog, UsdDialog;
LPWSTR			CurrentObjectPath;
HIMAGELIST		TreeViewImages, ListViewImages, ToolBarMenuImages;
pfnHtmlHelpW	pHtmlHelpW;
