/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       LOG.C
*
*  VERSION:     1.87
*
*  DATE:        29 June 2020
*
*  Simplified log.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

WOBJ_LOG g_WinObjLog;
HWND g_hwndLogViewer = NULL;

/*
* logCreate
*
* Purpose:
*
* Initialize log structure.
*
*/
VOID logCreate()
{
    RtlSecureZeroMemory(&g_WinObjLog, sizeof(g_WinObjLog));

    g_WinObjLog.Entries = (WOBJ_LOG_ENTRY*)supVirtualAlloc(
        sizeof(WOBJ_LOG_ENTRY) * WOBJ_MAX_LOG_CAPACITY);
    if (g_WinObjLog.Entries) {
        InitializeCriticalSection(&g_WinObjLog.Lock);
        g_WinObjLog.Initialized = TRUE;
    }
}

/*
* logFree
*
* Purpose:
*
* Destroy log.
*
*/
VOID logFree()
{
    EnterCriticalSection(&g_WinObjLog.Lock);
    g_WinObjLog.Initialized = FALSE;
    g_WinObjLog.Count = 0;
    supVirtualFree(g_WinObjLog.Entries);
    LeaveCriticalSection(&g_WinObjLog.Lock);
    DeleteCriticalSection(&g_WinObjLog.Lock);
}

/*
* logAdd
*
* Purpose:
*
* Add entry to log.
*
* N.B. If entry count exceeds log capacity log will be overwritten.
*
*/
VOID logAdd(
    _In_ ULONG Type,
    _In_ WCHAR* Message
)
{
    ULONG Index;
    EnterCriticalSection(&g_WinObjLog.Lock);

    if (g_WinObjLog.Initialized) {

        Index = g_WinObjLog.Count;

        g_WinObjLog.Entries[Index].Type = Type;
        GetSystemTimeAsFileTime((PFILETIME)&g_WinObjLog.Entries[Index].LoggedTime);
        _strncpy(g_WinObjLog.Entries[Index].MessageData, WOBJ_MAX_MESSAGE, Message, WOBJ_MAX_MESSAGE);

        Index += 1;
        if (Index >= WOBJ_MAX_LOG_CAPACITY)
            Index = 0;

        g_WinObjLog.Count = Index;

    }

    LeaveCriticalSection(&g_WinObjLog.Lock);
}

/*
* logEnumEntries
*
* Purpose:
*
* Enumerate log entries.
*
*/
BOOL logEnumEntries(
    _In_ PLOGENUMERATECALLBACK EnumCallback,
    _In_ PVOID CallbackContext
)
{
    ULONG i;
    BOOL bResult = FALSE;

    if (EnumCallback == NULL)
        return FALSE;

    __try {
        EnterCriticalSection(&g_WinObjLog.Lock);

        if (g_WinObjLog.Initialized) {
            for (i = 0; i < g_WinObjLog.Count; i++) {
                if (!EnumCallback(&g_WinObjLog.Entries[i], CallbackContext))
                    break;
            }
        }

        bResult = TRUE;

    }
    __finally {
        LeaveCriticalSection(&g_WinObjLog.Lock);
    }

    return bResult;
}

/*
* LogViewerPrintEntry
*
* Purpose:
*
* Output entry to richedit.
*
*/
VOID LogViewerPrintEntry(
    _In_ HWND OutputWindow,
    _In_ LPWSTR lpTime,
    _In_ LPWSTR lpType,
    _In_ LPWSTR lpValue)
{
    LONG StartPos = 0;
    CHARRANGE SelectedRange;

    SendMessage(OutputWindow, EM_EXGETSEL, (WPARAM)0, (LPARAM)&SelectedRange);
    StartPos = SelectedRange.cpMin;

    if (StartPos) {
        SendMessage(OutputWindow, EM_REPLACESEL, (WPARAM)0, (LPARAM)L"\r\n");
        StartPos += 1;
    }

    SendMessage(OutputWindow, EM_REPLACESEL, (WPARAM)0, (LPARAM)lpTime);
    SendMessage(OutputWindow, EM_REPLACESEL, (WPARAM)0, (LPARAM)L" (");
    SendMessage(OutputWindow, EM_REPLACESEL, (WPARAM)0, (LPARAM)lpType);
    SendMessage(OutputWindow, EM_REPLACESEL, (WPARAM)0, (LPARAM)L"): ");
    SendMessage(OutputWindow, EM_REPLACESEL, (WPARAM)0, (LPARAM)lpValue);
}

/*
* LogViewerAddEntryCallback
*
* Purpose:
*
* Log entry enumeration callback.
*
*/
BOOL CALLBACK LogViewerAddEntryCallback(
    _In_ WOBJ_LOG_ENTRY* Entry,
    _In_ PVOID CallbackContext
)
{
    HWND hwndList = (HWND)CallbackContext;
    LPWSTR lpType;
    WCHAR szTime[64];

    FILETIME ConvertedTime;
    TIME_FIELDS TimeFields;

    RtlZeroMemory(szTime, sizeof(szTime));

    switch (Entry->Type) {
    case WOBJ_LOG_ENTRY_ERROR:
        lpType = TEXT("Error");
        break;
    case WOBJ_LOG_ENTRY_SUCCESS:
        lpType = TEXT("Success");
        break;
    case WOBJ_LOG_ENTRY_WARNING:
        lpType = TEXT("Warning");
        break;
    case WOBJ_LOG_ENTRY_INFORMATION:
        lpType = TEXT("Information");
        break;
    default:
        lpType = TEXT("Unspecified");
        break;
    }

    FileTimeToLocalFileTime((PFILETIME)&Entry->LoggedTime, (PFILETIME)&ConvertedTime);
    RtlSecureZeroMemory(&TimeFields, sizeof(TimeFields));
    RtlTimeToTimeFields((PLARGE_INTEGER)&ConvertedTime, (PTIME_FIELDS)&TimeFields);

    RtlStringCchPrintfSecure(szTime, 64,
        TEXT("%hd:%02hd:%02hd.%03hd"),
        TimeFields.Hour,
        TimeFields.Minute,
        TimeFields.Second,
        TimeFields.Milliseconds);

    LogViewerPrintEntry(hwndList, szTime, lpType, Entry->MessageData);

    return TRUE; //continue with next entry
}

/*
* LogViewerListLog
*
* Purpose:
*
* Ouput log entries.
*
*/
VOID LogViewerListLog(
    _In_ HWND hwndParent
)
{
    CHARRANGE CharRange;
    HWND hwndList = GetDlgItem(hwndParent, IDC_LOGLIST);

    //
    // Prepare RichEdit.
    //
    SendMessage(hwndList, EM_SETEVENTMASK, (WPARAM)0, (LPARAM)0);
    SendMessage(hwndList, WM_SETREDRAW, (WPARAM)0, (LPARAM)0);

    logEnumEntries(LogViewerAddEntryCallback, (PVOID)hwndList);

    //
    // End work with RichEdit.
    //

    SendMessage(hwndList, WM_SETREDRAW, (WPARAM)TRUE, (LPARAM)0);
    InvalidateRect(hwndList, NULL, TRUE);

    SendMessage(hwndList, EM_SETEVENTMASK, (WPARAM)0, (LPARAM)ENM_SELCHANGE);

    CharRange.cpMax = 0;
    CharRange.cpMin = 0;
    SendMessage(hwndList, EM_EXSETSEL, (WPARAM)0, (LPARAM)&CharRange);

    SetFocus(hwndList);
}

/*
* LogViewerCopyToClipboard
*
* Purpose:
*
* Copy log entries to the clipboard.
*
*/
VOID LogViewerCopyToClipboard(
    _In_ HWND hwndDlg
)
{
    SIZE_T BufferSize;
    PWCHAR Buffer;

    GETTEXTLENGTHEX gtl;
    GETTEXTEX gt;

    HWND hwndControl = GetDlgItem(hwndDlg, IDC_LOGLIST);

    gtl.flags = GTL_USECRLF;
    gtl.codepage = 1200;

    BufferSize = SendMessage(hwndControl, EM_GETTEXTLENGTHEX, (WPARAM)&gtl, 0);
    if (BufferSize) {

        BufferSize *= sizeof(WCHAR);

        Buffer = (PWCHAR)supHeapAlloc(BufferSize);
        if (Buffer) {

            gt.flags = GT_USECRLF;
            gt.cb = (ULONG)BufferSize;

            gt.codepage = 1200;
            gt.lpDefaultChar = NULL;
            gt.lpUsedDefChar = NULL;
            SendMessage(hwndControl, EM_GETTEXTEX, (WPARAM)&gt, (LPARAM)Buffer);

            supClipboardCopy(Buffer, BufferSize);

            supHeapFree(Buffer);
        }
    }
}

/*
* LogViewerDialogProc
*
* Purpose:
*
* LogViewer Dialog Window Dialog Procedure
*
* During WM_INITDIALOG centers window and initializes with current log entries.
*
*/
INT_PTR CALLBACK LogViewerDialogProc(
    _In_ HWND   hwndDlg,
    _In_ UINT   uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    UNREFERENCED_PARAMETER(lParam);

    switch (uMsg) {

    case WM_INITDIALOG:
        supCenterWindow(hwndDlg);
        LogViewerListLog(hwndDlg);
        break;

    case WM_DESTROY:
        g_hwndLogViewer = NULL;
        break;

    case WM_CLOSE:
        DestroyWindow(hwndDlg);
        break;

    case WM_COMMAND:

        switch (GET_WM_COMMAND_ID(wParam, lParam)) {
        case IDOK:
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            return 1;
        case ID_OBJECT_COPY:
            LogViewerCopyToClipboard(hwndDlg);
            break;

        default:
            break;
        }

    default:
        break;
    }
    return 0;
}

/*
* LogViewerShowDialog
*
* Purpose:
*
* Create and show log viewer window.
*
*/
VOID LogViewerShowDialog(
    _In_ HWND hwndParent)
{
    if (g_hwndLogViewer != NULL) {
        SetActiveWindow(g_hwndLogViewer);
        return;
    }

    if (!supRichEdit32Load()) {
        MessageBox(hwndParent, TEXT("Could not load RichEdit library"), NULL, MB_ICONERROR);
        return;
    }

    g_hwndLogViewer = CreateDialogParam(
        g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_LOGVIEWER),
        hwndParent,
        (DLGPROC)&LogViewerDialogProc,
        0);
}
