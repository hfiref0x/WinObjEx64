/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       EXCEPTH.C
*
*  VERSION:     1.85
*
*  DATE:        05 Mar 2020
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
* Writes minidump information to the specified file.
*
*/
BOOL exceptWriteDump(
    _In_ EXCEPTION_POINTERS* ExceptionPointers,
    _In_ ULONGLONG IdFile
)
{
    BOOL    bResult;
    HMODULE hDbgHelp;
    HANDLE  hFile;
    WCHAR   szFileName[MAX_PATH * 2]; //-V1072

    MINIDUMP_EXCEPTION_INFORMATION mdei;

    bResult = FALSE;
    hDbgHelp = GetModuleHandle(TEXT("dbghelp.dll"));
    if (hDbgHelp == NULL) {
        RtlSecureZeroMemory(szFileName, sizeof(szFileName));
        _strcpy(szFileName, g_WinObj.szSystemDirectory);
        _strcat(szFileName, TEXT("\\dbghelp.dll"));

        hDbgHelp = LoadLibraryEx(szFileName, 0, 0);
        if (hDbgHelp == NULL)
            return bResult;
    }

    pMiniDumpWriteDump = (pfnMiniDumpWriteDump)GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
    if (pMiniDumpWriteDump == NULL)
        return bResult;

    RtlSecureZeroMemory(szFileName, sizeof(szFileName));
    _strcpy(szFileName, g_WinObj.szTempDirectory);
    _strcat(szFileName, TEXT("\\wobjex"));
    u64tostr(IdFile, _strend(szFileName));
    _strcat(szFileName, TEXT(".dmp"));

    hFile = CreateFile(szFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
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
    _In_ EXCEPTION_POINTERS* ExceptionPointers
)
{
    WCHAR     szMessage[MAX_PATH * 2];
    ULONGLONG IdFile;

    RtlSecureZeroMemory(&szMessage, sizeof(szMessage));
    _strcpy(szMessage, TEXT("Sorry, exception occurred at address: \r\n0x"));
    u64tohex((ULONG_PTR)ExceptionPointers->ExceptionRecord->ExceptionAddress, _strend(szMessage));

    if (ExceptionPointers->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        switch (ExceptionPointers->ExceptionRecord->ExceptionInformation[0]) {
        case 0:
            _strcat(szMessage, TEXT("\r\n\nAttempt to read at address: \r\n0x"));
            break;
        case 1:
            _strcat(szMessage, TEXT("\r\n\nAttempt to write at address: \r\n0x"));
            break;
        }
        u64tohex(ExceptionPointers->ExceptionRecord->ExceptionInformation[1], _strend(szMessage));
    }
    IdFile = GetTickCount64();

    if (exceptWriteDump(ExceptionPointers, IdFile)) {
        _strcat(szMessage, TEXT("\r\n\nMinidump wobjex"));
        u64tostr(IdFile, _strend(szMessage));
        _strcat(szMessage, TEXT(".dmp is in %TEMP% directory"));
    }
    else {
        _strcat(szMessage, TEXT("\r\n\nThere is an error while saving minidump."));
    }
    _strcat(szMessage, TEXT("\r\n\nPlease report this to the developers, thanks"));
    MessageBox(GetForegroundWindow(), szMessage, NULL, MB_ICONERROR);
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
        exceptShowException(ExceptionPointers);
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
