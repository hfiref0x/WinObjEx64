/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2023
*
*  TITLE:       LOG.C
*
*  VERSION:     2.03
*
*  DATE:        27 Jul 2023
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

static WOBJ_LOG g_WinObjLog;

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
        logAdd(EntryTypeInformation, TEXT("Program startup, log created"));
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
    _In_ WOBJ_ENTRY_TYPE EntryType,
    _In_ WCHAR* Message
)
{
    ULONG Index;
    EnterCriticalSection(&g_WinObjLog.Lock);

    if (g_WinObjLog.Initialized) {

        Index = g_WinObjLog.Count;

        g_WinObjLog.Entries[Index].Type = EntryType;
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
    _In_ HWND hwndRichEdit,
    _In_ LPWSTR lpMessage,
    _In_ BOOL bHighlight)
{
    LONG StartPos = 0;

    CHARFORMAT cf;
    CHARRANGE cr, sr;

    cr.cpMax = INT_MAX;
    cr.cpMin = INT_MAX;

    SendMessage(hwndRichEdit, EM_EXSETSEL, (WPARAM)0, (LPARAM)&cr);
    SendMessage(hwndRichEdit, EM_EXGETSEL, (WPARAM)0, (LPARAM)&sr);
    StartPos = sr.cpMin;

    if (bHighlight) {
        cf.cbSize = sizeof(CHARFORMAT);
        cf.dwMask = CFM_BOLD;
        SendMessage(hwndRichEdit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    }

    if (StartPos) {
        SendMessage(hwndRichEdit, EM_REPLACESEL, (WPARAM)0, (LPARAM)L"\r\n");
        StartPos += 2;
    }

    SendMessage(hwndRichEdit, EM_REPLACESEL, (WPARAM)0, (LPARAM)lpMessage);

    if (bHighlight) {
        cf.dwEffects = CFE_BOLD;
        cr.cpMin = StartPos;
        cr.cpMax = (LONG)_strlen(lpMessage) + StartPos + 1;
        SendMessage(hwndRichEdit, EM_EXSETSEL, (WPARAM)0, (LPARAM)&cr);
        SendMessage(hwndRichEdit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    }
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
    BOOL bHighlight = FALSE;
    HWND hwndList = (HWND)CallbackContext;
    TIME_FIELDS tFields = { 0, 0, 0, 0, 0, 0, 0, 0 };
    LPWSTR lpType;
    WCHAR szMessage[WOBJ_MAX_MESSAGE + 128];

    switch (Entry->Type) {
    case EntryTypeError:
        bHighlight = TRUE;
        lpType = TEXT("Error");
        break;
    case EntryTypeSuccess:
        lpType = TEXT("Success");
        break;
    case EntryTypeWarning:
        bHighlight = TRUE;
        lpType = TEXT("Warning");
        break;
    case EntryTypeInformation:
        lpType = TEXT("Information");
        break;
    default:
        lpType = TEXT("Unspecified");
        break;
    }

    szMessage[0] = 0;

    RtlTimeToTimeFields(&Entry->LoggedTime, &tFields);
    RtlStringCchPrintfSecure(szMessage,
        RTL_NUMBER_OF(szMessage),
        L"%02hd:%02hd:%02hd.%03hd (%ws): %ws",
        tFields.Hour,
        tFields.Minute,
        tFields.Second,
        tFields.Milliseconds,
        lpType,
        Entry->MessageData);

    LogViewerPrintEntry(hwndList, szMessage, bHighlight);

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
    CHARRANGE charRange;
    HWND hwndList = GetDlgItem(hwndParent, IDC_LOGLIST);
    PARAFORMAT ParaFormat;

    //
    // Prepare RichEdit.
    //
    SendMessage(hwndList, EM_SETEVENTMASK, (WPARAM)0, (LPARAM)0);
    SendMessage(hwndList, WM_SETREDRAW, (WPARAM)0, (LPARAM)0);

    RtlSecureZeroMemory(&ParaFormat, sizeof(ParaFormat));
    ParaFormat.cbSize = sizeof(ParaFormat);
    ParaFormat.cTabCount = 1;
    ParaFormat.dwMask = PFM_TABSTOPS;
    ParaFormat.rgxTabs[0] = 3500;
    SendMessage(hwndList, EM_SETPARAFORMAT, (WPARAM)0, (LPARAM)&ParaFormat);

    logEnumEntries(LogViewerAddEntryCallback, (PVOID)hwndList);

    //
    // End work with RichEdit.
    //

    SendMessage(hwndList, WM_SETREDRAW, (WPARAM)TRUE, (LPARAM)0);
    InvalidateRect(hwndList, NULL, TRUE);

    SendMessage(hwndList, EM_SETEVENTMASK, (WPARAM)0, (LPARAM)ENM_SELCHANGE);
    
    charRange.cpMax = 0;
    charRange.cpMin = 0;
    SendMessage(hwndList, EM_EXSETSEL, (WPARAM)0, (LPARAM)&charRange);

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
        return TRUE;

    case WM_COMMAND:

        switch (GET_WM_COMMAND_ID(wParam, lParam)) {
        case IDCANCEL:
            return EndDialog(hwndDlg, S_OK);
        case ID_OBJECT_COPY:
            LogViewerCopyToClipboard(hwndDlg);
            break;
        }

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
    if (!supRichEdit32Load()) {
        MessageBox(hwndParent, TEXT("Could not load RichEdit library"), NULL, MB_ICONERROR);
        return;
    }

    DialogBoxParam(
        g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_LOGVIEWER),
        hwndParent,
        (DLGPROC)&LogViewerDialogProc,
        0);

}
