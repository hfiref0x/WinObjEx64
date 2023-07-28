/************************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2023
*  Translated from Microsoft sources/debugger or mentioned elsewhere.
*
*  TITLE:       NTUSER.H
*
*  VERSION:     1.19
*
*  DATE:        21 Jun 2023
*
*  Common header file for the NtUser API functions and definitions.
*
*  Only projects required API/definitions.
*
*  Depends on:    Windows.h
*                 NtStatus.h
*                 NtOs.h
*
*  Include:       Windows.h
*                 NtStatus.h
*                 NtOs.h
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
************************************************************************************/

#if defined (_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#pragma warning(push)
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 4214) // nonstandard extension used : bit field types other than int

#ifndef NTUSER_RTL
#define NTUSER_RTL

//
// NtUser definitions are incomplete and only valid for Windows 10 RS4+
//
enum HANDLE_TYPE {
    TYPE_FREE = 0,
    TYPE_WINDOW = 1,
    TYPE_MENU = 2,
    TYPE_CURSOR = 3,
    TYPE_SETWINDOWPOS = 4,
    TYPE_HOOK = 5,
    TYPE_CLIPDATA = 6,
    TYPE_CALLPROC = 7,
    TYPE_ACCELTABLE = 8,
    TYPE_DDEACCESS = 9,
    TYPE_DDECONV = 10,
    TYPE_DDEXACT = 11,
    TYPE_MONITOR = 12,
    TYPE_KBDLAYOUT = 13,
    TYPE_KBDFILE = 14,
    TYPE_WINEVENTHOOK = 15,
    TYPE_TIMER = 16,
    TYPE_INPUTCONTEXT = 17,
    TYPE_HIDDATA = 18,
    TYPE_DEVICEINFO = 19,
    TYPE_TOUCHINPUT = 20,
    TYPE_GESTUREINFO = 21,
    TYPE_CTYPES = 22,
    TYPE_GENERIC = 255
};

#define TIF_INCLEANUP               0x00000001
#define TIF_16BIT                   0x00000002
#define TIF_SYSTEMTHREAD            0x00000004
#define TIF_CSRSSTHREAD             0x00000008
#define TIF_TRACKRECTVISIBLE        0x00000010
#define TIF_ALLOWFOREGROUNDACTIVATE 0x00000020
#define TIF_DONTATTACHQUEUE         0x00000040
#define TIF_DONTJOURNALATTACH       0x00000080
#define TIF_WOW64                   0x00000100
#define TIF_INACTIVATEAPPMSG        0x00000200
#define TIF_SPINNING                0x00000400
#define TIF_PALETTEAWARE            0x00000800
#define TIF_SHAREDWOW               0x00001000
#define TIF_FIRSTIDLE               0x00002000
#define TIF_WAITFORINPUTIDLE        0x00004000
#define TIF_MOVESIZETRACKING        0x00008000
#define TIF_VDMAPP                  0x00010000
#define TIF_DOSEMULATOR             0x00020000
#define TIF_GLOBALHOOKER            0x00040000
#define TIF_DELAYEDEVENT            0x00080000
#define TIF_MSGPOSCHANGED           0x00100000
#define TIF_SHUTDOWNCOMPLETE        0x00200000
#define TIF_IGNOREPLAYBACKDELAY     0x00400000
#define TIF_ALLOWOTHERACCOUNTHOOK   0x00800000
#define TIF_GUITHREADINITIALIZED    0x02000000
#define TIF_DISABLEIME              0x04000000
#define TIF_INGETTEXTLENGTH         0x08000000
#define TIF_ANSILENGTH              0x10000000
#define TIF_DISABLEHOOKS            0x20000000

#define HANDLEF_DESTROY        0x01
#define HANDLEF_INDESTROY      0x02
#define HANDLEF_MARKED_OK      0x10
#define HANDLEF_GRANTED        0x20
#define HANDLEF_POOL           0x40
#define HANDLEF_VALID          0x7F

#if defined(__cplusplus)
extern "C" {
#endif

#ifdef _WIN32ULIB_PRESENT
#pragma comment(lib, "win32u.lib")
#endif

typedef struct _SERVERINFO {
    WORD wRIPFlags;
    WORD wSRVIFlags;
    WORD wRIPPID;
    WORD wRIPError;
    ULONG cHandleEntries; //+8 
    ULONG_PTR pDispInfo;
    // incomplete
} SERVERINFO, * PSERVERINFO;

typedef struct _HANDLEENTRY {
    HANDLE hWnd;
    HANDLE pti;
    PVOID rpdesk;
    BYTE bType;
    BYTE bFlags;
    USHORT wUniq;
} HANDLEENTRY, * PHANDLEENTRY;

typedef struct _tagWND {
    HANDLE hWnd;
    ULONG_PTR DesktopHeapOffset;
    ULONG_PTR UnknownFlags;
    DWORD dwExStyle;
    DWORD dwStyle;
    BYTE Spare[0x130];
} tagWND, * PWND; //sizeof 0x150

//win 11  v33 = HMAllocObject(v208, v255, v31, 328); 0x148

typedef struct _DESKINFO {
    PVOID rpdesk;
} DESKINFO, * PDESKINFO;

typedef struct _CLIENTINFO {
    ULONG_PTR CI_Flags;
    ULONG_PTR cSpins;
    DWORD dwExpWinVer;
    DWORD dwCompatFlags;
    DWORD dwCompatFlags2;
    DWORD dwTIFlags;
    PDESKINFO pDeskInfo;
    PVOID DesktopHeap;
    //incomplete
} CLIENTINFO, * PCLIENTINFO;

typedef struct _SHAREDINFO {
    PSERVERINFO	psi;
    PHANDLEENTRY aheList;
    ULONG HeEntrySize;
    // incomplete
} SHAREDINFO, * PSHAREDINFO;

#define HMINDEXBITS             0x0000FFFF      // bits where index is stored
#define HMUNIQSHIFT             16              // bits to shift uniqueness
#define HMUNIQBITS              0xFFFF          // valid uniqueness bits
#define HMUniqFromHandle(h)     ((WORD)((((ULONG_PTR)h) >> HMUNIQSHIFT) & HMUNIQBITS))
#define HMIndexFromHandle(h)    ((ULONG)(((ULONG_PTR)(h)) & HMINDEXBITS))
#define PtiFromHe(p)            (((PHANDLEENTRY)p)->pti)

typedef enum tagPROCESS_UICONTEXT {
    PROCESS_UICONTEXT_DESKTOP = 0,
    PROCESS_UICONTEXT_IMMERSIVE = 1,
    PROCESS_UICONTEXT_IMMERSIVE_BROKER = 2,
    PROCESS_UICONTEXT_IMMERSIVE_BROWSER = 3
} PROCESS_UICONTEXT;

typedef enum tagPROCESS_UI_FLAGS {
    PROCESS_UIF_NONE = 0,
    PROCESS_UIF_AUTHORING_MODE = 1,
    PROCESS_UIF_RESTRICTIONS_DISABLED = 2
} PROCESS_UI_FLAGS;

typedef struct tagPROCESS_UICONTEXT_INFORMATION {
    DWORD processUIContext; //PROCESS_UICONTEXT
    DWORD dwFlags; //PROCESS_UI_FLAGS
} PROCESS_UICONTEXT_INFORMATION, * PPROCESS_UICONTEXT_INFORMATION;


typedef HWINSTA(NTAPI* pfnNtUserOpenWindowStation)(
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ACCESS_MASK DesiredAccess);


#ifdef __cplusplus
}
#endif

#pragma warning(pop)

#endif NTUSER_RTL
