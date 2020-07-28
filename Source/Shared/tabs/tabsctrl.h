/*++

Copyright (c) 2015 (see AUTHORS.txt).

Module Name:

    tabctrl.h

Abstract:

    This file contains function prototypes/variables used by GUI tabs component.

    VERSION 2.0 (01.02.2015)

    WinObjEx64 version.

--*/

#pragma once

#ifndef _GUITABSUNIT_
#define _GUITABSUNIT_

#include <Windows.h>
#include <Windowsx.h>
#include <CommCtrl.h>
#include "ntos/ntos.h"

typedef struct _tagTABHDR* PTABHDR;

typedef VOID(CALLBACK* TABRESIZECALLBACK)(
    _In_ PTABHDR hdr);

typedef VOID(CALLBACK* TABSELCHANGECALLBACK)(
    _In_ PTABHDR hdr,
    _In_ INT SelectedPage);

typedef PVOID(CALLBACK* TABCALLBACK_ALLOCMEM)(
    _In_ SIZE_T size);

typedef BOOL(CALLBACK* TABCALLBACK_FREEMEM)(
    _In_ PVOID ptr);

typedef struct _TABENTRY {
    LIST_ENTRY ListEntry;
    INT TabIndex;
    INT ResId;
    DLGPROC DlgProc;
    PVOID UserParam; // sent as lParam to newly created page dialog
} TABENTRY, * PTABENTRY;

typedef struct _tagTABHDR {

    HWND hwndTab; //tab control window handle
    HWND hwndDisplay; //current page window handle
    RECT rcDisplay;

    HINSTANCE hInstance;
    INT tabsCount;

    HIMAGELIST hImageList;

    TABSELCHANGECALLBACK OnSelChange;
    TABRESIZECALLBACK OnResize;

    TABCALLBACK_ALLOCMEM MemAlloc;
    TABCALLBACK_FREEMEM FreeMem;

    LIST_ENTRY tabsHead;

    INT cxMargin;
    INT cyMargin;

} TABHDR, * PTABHDR;

PTABHDR TabCreateControl(
    _In_ HINSTANCE hInstance,
    _In_ HWND hParentWnd,
    _In_opt_ HIMAGELIST hImageList,
    _In_ TABSELCHANGECALLBACK OnSelChangeTab,
    _In_ TABRESIZECALLBACK OnResizeTab,
    _In_ TABCALLBACK_ALLOCMEM MemAlloc,
    _In_ TABCALLBACK_FREEMEM MemFree);

BOOL TabAddPage(
    _In_ PTABHDR hdr,
    _In_ INT ResId,
    _In_opt_ DLGPROC DlgProc,
    _In_ LPTSTR szCaption,
    _In_ INT iImage,
    _In_ LPARAM lParam);

BOOL TabDeletePage(
    _In_ PTABHDR hdr,
    _In_ INT TabIndex);

VOID TabDestroyControl(
    _In_ PTABHDR hdr);

VOID TabOnChangeTab(
    _In_ PTABHDR hdr,
    _In_ LPNMHDR pnmhdr);

VOID TabOnSelChanged(
    _In_ PTABHDR hdr);

VOID TabResizeTabWindow(
    _In_ PTABHDR hdr);

#endif /* _GUITABSUNIT_ */
