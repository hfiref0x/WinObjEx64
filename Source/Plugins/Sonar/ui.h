/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2020
*
*  TITLE:       UI.H
*
*  VERSION:     1.03
*
*  DATE:        10 July 2020
*
*  WinObjEx64 Sonar UI constants, definitions and includes.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "uxtheme.lib")

#define SONAR_WNDTITLE TEXT("Sonar")

#define WINOBJEX64_ACC_TABLE        166
#define WINOBJEX64_ICON_MAIN        174
#define WINOBJEX64_ICON_SORT_UP     6001
#define WINOBJEX64_ICON_SORT_DOWN   6002
#define WINOBJEX64_ACC_F5           40003
#define WINOBJEX64_OBJECT_PROP      40004

#define ID_MENU_COPY_VALUE 41008

#define Y_SPLITTER_SIZE 4
#define Y_SPLITTER_MIN  100

#define DefaultSystemDpi            96

#define SCALE_DPI_VALUE(Value, CurrentDPI) MulDiv(Value, CurrentDPI, DefaultSystemDpi)

typedef struct _TL_SUBITEMS_FIXED {
    ULONG       ColorFlags;
    COLORREF    BgColor;
    COLORREF    FontColor;
    PVOID       UserParam;
    ULONG       Count;
    LPTSTR      Text[2];
} TL_SUBITEMS_FIXED, * PTL_SUBITEMS_FIXED;

typedef struct _SONARCONTEXT {
    //
    // GUI context variables.
    //
    HWND MainWindow;
    HWND ListView;
    HWND TreeList;
    HWND StatusBar;
    HACCEL AccTable;
    HIMAGELIST ImageList;
    LONG lvColumnToSort;
    LONG lvColumnCount;
    BOOL bInverseSort;

    HANDLE PluginHeap;
    HANDLE WorkerThread;

    INT SplitterPosY;
    INT CapturePosY;
    INT SplitterMaxY;
    UINT CurrentDPI;

    //
    // NDIS related.
    //
    ULONG_PTR ndisProtocolList;
    ULONG ndisNextProtocolOffset;
    
    //
    // WinObjEx64 data and pointers.
    //
    WINOBJEX_PARAM_BLOCK ParamBlock;
} SONARCONTEXT, *PSONARCONTEXT;
