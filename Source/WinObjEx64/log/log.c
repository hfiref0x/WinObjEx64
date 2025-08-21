/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2025
*
*  TITLE:       LOG.C
*
*  VERSION:     2.09
*
*  DATE:        20 Aug 2025
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

//
// Map entry type to text and highlight flag.
//
typedef struct _LOG_TYPE_MAP {
    WOBJ_ENTRY_TYPE Type;
    LPCWSTR TypeText;
    BOOL Highlight;
} LOG_TYPE_MAP;

static const LOG_TYPE_MAP g_LogTypeMap[] = {
    { EntryTypeError, L"Error", TRUE },
    { EntryTypeSuccess, L"Success", FALSE },
    { EntryTypeInformation, L"Information", FALSE },
    { EntryTypeWarning, L"Warning", TRUE }
};

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
    InitializeCriticalSection(&g_WinObjLog.Lock);
    g_WinObjLog.LockInitialized = TRUE;

    g_WinObjLog.Entries = (WOBJ_LOG_ENTRY*)supVirtualAlloc(
        sizeof(WOBJ_LOG_ENTRY) * WOBJ_MAX_LOG_CAPACITY);
    if (g_WinObjLog.Entries) {
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
    if (!g_WinObjLog.LockInitialized)
        return;

    EnterCriticalSection(&g_WinObjLog.Lock);
    g_WinObjLog.Initialized = FALSE;
    if (g_WinObjLog.Entries) {
        supVirtualFree(g_WinObjLog.Entries);
        g_WinObjLog.Entries = NULL;
    }
    g_WinObjLog.Count = 0;
    g_WinObjLog.TotalWritten = 0;
    LeaveCriticalSection(&g_WinObjLog.Lock);
    DeleteCriticalSection(&g_WinObjLog.Lock);
    g_WinObjLog.LockInitialized = FALSE;
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
    _In_ const WCHAR* Message
)
{
    ULONG Index;

    if (!g_WinObjLog.LockInitialized)
        return;

    EnterCriticalSection(&g_WinObjLog.Lock);

    if (g_WinObjLog.Initialized) {

        Index = g_WinObjLog.Count;

        g_WinObjLog.Entries[Index].Type = EntryType;
        GetSystemTimeAsFileTime((PFILETIME)&g_WinObjLog.Entries[Index].LoggedTime);
        _strncpy(g_WinObjLog.Entries[Index].MessageData,
            WOBJ_MAX_MESSAGE,
            Message ? Message : L"(null)",
            WOBJ_MAX_MESSAGE);

        Index += 1;
        if (Index >= WOBJ_MAX_LOG_CAPACITY)
            Index = 0;

        g_WinObjLog.Count = Index;
        g_WinObjLog.TotalWritten++;
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
    ULONG i, start, idx, cap, logicalCount;
    BOOL bResult = FALSE;

    if (EnumCallback == NULL)
        return FALSE;

    if (!g_WinObjLog.LockInitialized)
        return FALSE;

    __try {
        EnterCriticalSection(&g_WinObjLog.Lock);
        if (g_WinObjLog.Initialized && g_WinObjLog.Entries) {
            cap = WOBJ_MAX_LOG_CAPACITY;

            if (g_WinObjLog.TotalWritten < cap) {
                logicalCount = g_WinObjLog.Count;
                start = 0;
            }
            else {
                logicalCount = cap;
                start = g_WinObjLog.Count; // oldest entry index when wrapped
            }

            for (i = 0; i < logicalCount; i++) {
                idx = (start + i) % cap;
                if (!EnumCallback(&g_WinObjLog.Entries[idx], CallbackContext))
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
    LONG startPos, endPos;
    CHARFORMAT format;
    CHARRANGE range;

    // Move caret to end
    range.cpMax = range.cpMin = INT_MAX;
    SendMessage(hwndRichEdit, EM_EXSETSEL, 0, (LPARAM)&range);

    // Insert newline if not the first line
    if (SendMessage(hwndRichEdit, WM_GETTEXTLENGTH, 0, 0) > 0)
        SendMessage(hwndRichEdit, EM_REPLACESEL, 0, (LPARAM)L"\r\n");

    // After inserting newline, get start position for new entry
    SendMessage(hwndRichEdit, EM_EXGETSEL, 0, (LPARAM)&range);
    startPos = range.cpMin;

    // Insert the message
    SendMessage(hwndRichEdit, EM_REPLACESEL, 0, (LPARAM)lpMessage);

    // Get end position after message insertion
    SendMessage(hwndRichEdit, EM_EXGETSEL, 0, (LPARAM)&range);
    endPos = range.cpMin;

    // Select just inserted message
    range.cpMin = startPos;
    range.cpMax = endPos;
    SendMessage(hwndRichEdit, EM_EXSETSEL, 0, (LPARAM)&range);

    // Apply formatting (bold when highlight requested)
    RtlSecureZeroMemory(&format, sizeof(format));
    format.cbSize = sizeof(format);
    format.dwMask = CFM_BOLD;
    format.dwEffects = bHighlight ? CFE_BOLD : 0;
    SendMessage(hwndRichEdit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&format);
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
    BOOL bHighlight = FALSE, found = FALSE;
    SIZE_T j;
    HWND hwndList = (HWND)CallbackContext;
    TIME_FIELDS tFields = { 0, 0, 0, 0, 0, 0, 0, 0 };
    LPWSTR lpType = L"Unspecified";
    WCHAR szMessage[WOBJ_MAX_MESSAGE + 128];

    for (j = 0; j < RTL_NUMBER_OF(g_LogTypeMap); j++) {
        if (g_LogTypeMap[j].Type == Entry->Type) {
            lpType = (LPWSTR)g_LogTypeMap[j].TypeText;
            bHighlight = g_LogTypeMap[j].Highlight;
            found = TRUE;
            break;
        }
    }
    if (!found) {
        bHighlight = FALSE;
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
    SIZE_T BufferSizeChars, AllocSize;
    PWCHAR Buffer = NULL;

    GETTEXTLENGTHEX gtl;
    GETTEXTEX gt;

    HWND hwndControl = GetDlgItem(hwndDlg, IDC_LOGLIST);

    gtl.flags = GTL_USECRLF;
    gtl.codepage = 1200;

    BufferSizeChars = SendMessage(hwndControl, EM_GETTEXTLENGTHEX, (WPARAM)&gtl, 0);
    if (BufferSizeChars) {
        AllocSize = (BufferSizeChars + 1) * sizeof(WCHAR);
        Buffer = (PWCHAR)supHeapAlloc(AllocSize);
        if (Buffer) {

            gt.flags = GT_USECRLF;
            gt.cb = (ULONG)AllocSize;

            gt.codepage = 1200;
            gt.lpDefaultChar = NULL;
            gt.lpUsedDefChar = NULL;
            SendMessage(hwndControl, EM_GETTEXTEX, (WPARAM)&gt, (LPARAM)Buffer);

            Buffer[BufferSizeChars] = L'\0';

            supClipboardCopy(Buffer, AllocSize);

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
