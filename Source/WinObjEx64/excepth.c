/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2026
*
*  TITLE:       EXCEPTH.C
*
*  VERSION:     2.10
*
*  DATE:        10 Feb 2026
*
*  Exception handler routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include <DbgHelp.h>

typedef BOOL(WINAPI* pfnMiniDumpWriteDump)(
    _In_ HANDLE hProcess,
    _In_ DWORD ProcessId,
    _In_ HANDLE hFile,
    _In_ MINIDUMP_TYPE DumpType,
    _In_opt_ PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    _In_opt_ PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    _In_opt_ PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

pfnMiniDumpWriteDump pMiniDumpWriteDump;

/*
* exceptWriteDump
*
* Purpose:
*
* Writes minidump information to the file.
*
*/
BOOL exceptWriteDump(
    _In_ EXCEPTION_POINTERS* ExceptionPointers,
    _In_ LPCWSTR lpFileName
)
{
    BOOL bResult;
    HMODULE hDbgHelp;
    HANDLE hFile;
    WCHAR szFileName[MAX_PATH * 2];
    UINT cch;

    MINIDUMP_EXCEPTION_INFORMATION mdei;

    bResult = FALSE;
    hDbgHelp = GetModuleHandle(TEXT("dbghelp.dll"));
    if (hDbgHelp == NULL) {

        RtlSecureZeroMemory(szFileName, sizeof(szFileName));
        cch = GetSystemDirectory(szFileName, MAX_PATH);
        if (cch == 0 || cch > MAX_PATH)
            return FALSE;

        _strcat(szFileName, TEXT("\\dbghelp.dll"));

        hDbgHelp = LoadLibraryEx(szFileName, 0, 0);
        if (hDbgHelp == NULL)
            return FALSE;
    }

    pMiniDumpWriteDump = (pfnMiniDumpWriteDump)GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
    if (pMiniDumpWriteDump == NULL)
        return FALSE;

    hFile = CreateFile(lpFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        mdei.ThreadId = GetCurrentThreadId();
        mdei.ExceptionPointers = ExceptionPointers;
        mdei.ClientPointers = FALSE;
        bResult = pMiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, MiniDumpNormal, &mdei, NULL, NULL);
        CloseHandle(hFile);
    }
    return bResult;
}

/*
* exceptShowException
*
* Purpose:
*
* Output exception information to the user.
*
*/
VOID exceptShowException(
    _In_ EXCEPTION_POINTERS* ExceptionPointers,
    _In_ BOOL LastChance
)
{
    WCHAR szFileName[MAX_PATH * 2];
    WCHAR szMessage[2048];
    LPWSTR lpDescription;

    RtlSecureZeroMemory(&szMessage, sizeof(szMessage));
    RtlSecureZeroMemory(&szFileName, sizeof(szFileName));

    RtlStringCchPrintfSecure(szMessage,
        RTL_NUMBER_OF(szMessage),
        TEXT("Sorry, exception occured at address: \r\n0x%llX"),
        (ULONG_PTR)ExceptionPointers->ExceptionRecord->ExceptionAddress);

    if (ExceptionPointers->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        switch (ExceptionPointers->ExceptionRecord->ExceptionInformation[0]) {
        case 0:
            lpDescription = TEXT("read");
            break;
        case 1:
            lpDescription = TEXT("write");
            break;
        case 8:
            lpDescription = TEXT("execute");
            break;
        default:
            lpDescription = TEXT("access");
            break;
        }

        RtlStringCchPrintfSecure(_strend(szMessage),
            RTL_NUMBER_OF(szMessage) - _strlen(szMessage),
            TEXT("\r\n\nAttempt to %ws at address: \r\n0x%llX"),
            lpDescription,
            ExceptionPointers->ExceptionRecord->ExceptionInformation[1]);
    }

    GetCurrentDirectory(MAX_PATH, szFileName);
    _strcat(szFileName, TEXT("\\WinObjEx64."));
    ultostr(GetCurrentProcessId(), _strend(szFileName));
    _strcat(szFileName, TEXT("."));
    ultostr(GetCurrentThreadId(), _strend(szFileName));
    _strcat(szFileName, TEXT(".dmp"));

    if (exceptWriteDump(ExceptionPointers, szFileName)) {

        RtlStringCchPrintfSecure(_strend(szMessage),
            RTL_NUMBER_OF(szMessage) - _strlen(szMessage),
            TEXT("\r\n\nMinidump saved to %ws"),
            szFileName);
    }
    else {
        _strcat(szMessage, TEXT("\r\nAnd there is an error while saving minidump :("));
    }
    if (LastChance)
        _strcat(szMessage, TEXT("\r\n\nThe program will be terminated."));

    MessageBox(0, szMessage, NULL, MB_ICONERROR);
}

/*
* exceptFilterUnhandled
*
* Purpose:
*
* Default exception filter, processing AV with minidump if available.
*
*/
INT exceptFilterUnhandled(
    _In_ struct _EXCEPTION_POINTERS* ExceptionInfo
)
{
    WDrvProvRelease(&g_kdctx.DriverContext);
    exceptShowException(ExceptionInfo, TRUE);
    RtlExitUserProcess(ExceptionInfo->ExceptionRecord->ExceptionCode);
    return EXCEPTION_EXECUTE_HANDLER;
}

/*
* exceptFilter
*
* Purpose:
*
* Default exception filter, processing AV with minidump if available.
*
*/
INT exceptFilter(
    _In_ UINT ExceptionCode,
    _In_ EXCEPTION_POINTERS* ExceptionPointers
)
{
    if (ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        exceptShowException(ExceptionPointers, FALSE);
        return EXCEPTION_EXECUTE_HANDLER;
    }
    else {
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

/*
* exceptFilterWithLog
*
* Purpose:
*
* Exception filter with log.
*
*/
INT exceptFilterWithLog(
    _In_ UINT ExceptionCode,
    _In_opt_ EXCEPTION_POINTERS* ExceptionPointers
)
{
    supReportException(ExceptionCode, ExceptionPointers);
    return EXCEPTION_EXECUTE_HANDLER;
}
