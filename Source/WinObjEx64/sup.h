/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2016
*
*  TITLE:       SUP.H
*
*  VERSION:     1.40
*
*  DATE:        13 Feb 2016
*
*  Common header file for the program support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#include <cfgmgr32.h>
#include <setupapi.h>

typedef struct _SAPIDBOBJ {
	LIST_ENTRY			sapiDBHead;
	HDEVINFO			hDevInfo;
	CRITICAL_SECTION	objCS;
} SAPIDBOBJ, *PSAPIDBOBJ;

typedef struct _ENUMICONINFO {
	HICON hIcon;
	INT cx, cy;
} ENUMICONINFO, *PENUMICONINFO;

//
// Type icons starts from 300
//
#define ID_FROM_VALUE(id) (id - 300)
#define ID_TO_VALUE(id) (id + 300)

#define GET_BIT(Integer, Bit) (((Integer) >> (Bit)) & 0x1)
#define SET_BIT(Integer, Bit) ((Integer) |= 1 << (Bit))
#define CLEAR_BIT(Integer, Bit) ((Integer) &= ~(1 << (Bit)))

/*
** Object Type Indexes Used By Program Only
*/

#define TYPE_DEVICE                 0
#define TYPE_DRIVER                 1
#define TYPE_SECTION                2
#define TYPE_PORT                   3
#define TYPE_SYMLINK                4
#define TYPE_KEY                    5
#define TYPE_EVENT                  6
#define TYPE_JOB                    7
#define TYPE_MUTANT                 8
#define TYPE_KEYEDEVENT             9
#define TYPE_TYPE                   10
#define TYPE_DIRECTORY              11
#define TYPE_WINSTATION             12
#define TYPE_CALLBACK               13
#define TYPE_SEMAPHORE              14
#define TYPE_WAITABLEPORT           15
#define TYPE_TIMER                  16
#define TYPE_SESSION                17
#define TYPE_CONTROLLER				18
#define TYPE_PROFILE				19
#define TYPE_EVENTPAIR				20
#define TYPE_DESKTOP                21
#define TYPE_FILE                   22
#define TYPE_WMIGUID                23
#define TYPE_DEBUGOBJECT            24
#define TYPE_IOCOMPLETION           25
#define TYPE_PROCESS                26
#define TYPE_ADAPTER                27
#define TYPE_TOKEN                  28
#define TYPE_ETWREGISTRATION        29
#define TYPE_THREAD			        30
#define TYPE_TMTX                   31
#define TYPE_TMTM                   32
#define TYPE_TMRM                   33
#define TYPE_TMEN                   34
#define TYPE_PCWOBJECT				35
#define TYPE_FLTCONN_PORT			36
#define TYPE_FLTCOMM_PORT			37
#define TYPE_POWER_REQUEST			38
#define TYPE_ETWCONSUMER			39
#define TYPE_TPWORKERFACTORY		40
#define TYPE_COMPOSITION			41
#define TYPE_IRTIMER				42
#define TYPE_DXGKSHAREDRES			43
#define TYPE_DXGKSHAREDSWAPCHAIN	44
#define TYPE_DXGKSHAREDSYNC			45
#define TYPE_UNKNOWN                46
#define TYPE_MAX					47

typedef struct _LANGANDCODEPAGE {
	WORD wLanguage;
	WORD wCodePage;
} LANGANDCODEPAGE, *LPTRANSLATE;

typedef struct _ENUM_PARAMS {
	PCWSTR	lpSubDirName;
	PVOID	scmSnapshot;
	SIZE_T	scmNumberOfEntries;
	PVOID	sapiDB;
} ENUM_PARAMS, *PENUM_PARAMS;

typedef struct _SAPIDBENTRY {
	LIST_ENTRY ListEntry;
	LPWSTR lpDeviceName;
	LPWSTR lpDeviceDesc;
} SAPIDBENTRY, *PSAPIDBENTRY;

extern LPCWSTR T_ObjectNames[TYPE_MAX];
extern ENUM_PARAMS	g_enumParams;
extern POBJECT_TYPES_INFORMATION g_pObjectTypesInfo;

//global variables
LPWSTR	g_lpKnownDlls32;
LPWSTR	g_lpKnownDlls64;

BOOL supInitTreeListForDump(
	_In_  HWND  hwndParent,
	_Inout_ ATOM *pTreeListAtom,
	_Inout_ HWND *pTreeListHwnd
	);

VOID supShowHelp(
	VOID
	);

BOOL supQueryObjectFromHandle(
	_In_ HANDLE hOject,
	_Inout_ ULONG_PTR *Address,
	_Inout_opt_ UCHAR *TypeIndex
	);

HICON supGetMainIcon(
	_In_ LPWSTR lpFileName,
	_In_ INT cx,
	_In_ INT cy
	);

void supCopyMemory(
	_Inout_ void *dest,
	_In_ size_t ccdest,
	_In_ const void *src,
	_In_ size_t ccsrc
	);

BOOL supUserIsFullAdmin(
	VOID
	);

BOOL supIsSymlink(
	INT iItem
	);

VOID supCenterWindow(
	HWND hwnd
	);

VOID supSetWaitCursor(
	BOOL fSet
	);

HIMAGELIST supLoadImageList(
	HINSTANCE hInst,
	UINT FirstId,
	UINT LastId
	);

UINT supGetObjectIndexByTypeName(
	_In_ LPCWSTR lpTypeName
	);

UINT supGetObjectNameIndexByTypeIndex(
	_In_ PVOID Object,
	_In_ UCHAR TypeIndex
	);

VOID supRunAsAdmin(
	VOID
	);

VOID supSetMenuIcon(
	HMENU hMenu,
	UINT Item,
	ULONG_PTR IconData
	);

VOID supHandleObjectPopupMenu(
	HWND hwnd,
	int iItem,
	LPPOINT point
	);

VOID supHandleTreePopupMenu(
	HWND hwnd,
	LPPOINT point
	);

VOID supCreateToolbarButtons(
	HWND hWndToolbar
	);

VOID supInit(
	BOOL IsFullAdmin
	);

VOID supShutdown(
	VOID
	);

PVOID supGetObjectTypesInfo(
	VOID
	);

VOID supShowProperties(
	_In_ HWND hwndDlg,
	_In_ LPWSTR lpFileName
	);

VOID supClipboardCopy(
	_In_ LPWSTR lpText,
	_In_ SIZE_T cbText
	);

BOOL supEnablePrivilege(
	_In_ DWORD	PrivilegeName,
	_In_ BOOL	fEnable
	);

BOOL WINAPI supEnumEnableChildWindows(
	_In_  HWND hwnd,
	_In_  LPARAM lParam
	);

BOOL WINAPI supEnumHideChildWindows(
	_In_  HWND hwnd,
	_In_  LPARAM lParam
	);

LPWSTR supGetItemText(
	_In_ HWND ListView,
	_In_ INT nItem,
	_In_ INT nSubItem,
	_Inout_opt_ PSIZE_T lpSize
	);

BOOL supQueryLinkTarget(
	_In_opt_	HANDLE hRootDirectory,
	_In_		PUNICODE_STRING ObjectName,
	_Inout_		LPWSTR Buffer,
	_In_		DWORD cbBuffer 
	);

BOOL supQuerySectionFileInfo(
	_In_opt_	HANDLE hRootDirectory,
	_In_		PUNICODE_STRING ObjectName,
	_Inout_		LPWSTR Buffer,
	_In_		DWORD ccBuffer 
	);

BOOL supQueryTypeInfo(
	_In_	LPWSTR lpTypeName,
	_Inout_	LPWSTR Buffer,
	_In_	DWORD ccBuffer 
	);

BOOL supQueryDriverDescription(
	_In_	LPWSTR lpDriverName,
	_In_	PVOID scmSnapshot,
	_In_	SIZE_T	scmNumberOfEntries,
	_Inout_	LPWSTR Buffer,
	_In_	DWORD ccBuffer 
	);

BOOL supQueryDeviceDescription(
	_In_	LPWSTR lpDeviceName,
	_In_	PVOID Snapshot,
	_Inout_	LPWSTR Buffer,
	_In_	DWORD ccBuffer  
	);

BOOL supQueryWinstationDescription(
	_In_	LPWSTR lpWindowStationName,
	_Inout_	LPWSTR Buffer,
	_In_	DWORD ccBuffer 
	);

BOOL supQueryProcessName(
	_In_	DWORD dwProcessId,
	_In_	PVOID ProcessList,
	_Inout_	LPWSTR Buffer,
	_In_	DWORD ccBuffer 
	);

BOOL supFindModuleNameByAddress(
	_In_	PRTL_PROCESS_MODULES pModulesList,
	_In_	PVOID Address,
	_Inout_	LPWSTR Buffer,
	_In_	DWORD ccBuffer
	);

ULONG supFindModuleEntryByAddress(
	_In_	PRTL_PROCESS_MODULES pModulesList,
	_In_	PVOID Address
	);

PVOID supGetSystemInfo(
	_In_ SYSTEM_INFORMATION_CLASS InfoClass
	);

HANDLE supOpenDirectory(
	_In_ LPWSTR lpDirectory
	);

HANDLE supOpenDirectoryForObject(
	_In_ LPWSTR lpObjectName,
	_In_ LPWSTR lpDirectory
	);

BOOL supDumpSyscallTableConverted(
	_In_ PKLDBGCONTEXT Context,
	_Inout_ PUTable *Table
	);

PVOID supCreateSCMSnapshot(
	PSIZE_T lpNumberOfEntries
	);

PVOID sapiCreateSetupDBSnapshot(
	VOID
	);

VOID supFreeSCMSnapshot(
	_In_ PVOID Snapshot
	);

VOID sapiFreeSnapshot(
	_In_ PVOID Snapshot
	);

VOID supQueryKnownDlls(
	VOID
	);

BOOL supSaveDialogExecute(
	_In_ HWND OwnerWindow,
	_Inout_ LPWSTR SaveFileName,
	_In_ LPWSTR lpDialogFilter
	);

ULONG_PTR supWriteBufferToFile(
	_In_ PWSTR lpFileName,
	_In_ PVOID Buffer,
	_In_ SIZE_T Size,
	_In_ BOOL Flush,
	_In_ BOOL Append
	);

#define PathFileExists(lpszPath) (GetFileAttributes(lpszPath) != (DWORD)-1)
