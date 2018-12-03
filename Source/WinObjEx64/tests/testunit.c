/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       TESTUNIT.C
*
*  VERSION:     1.70
*
*  DATE:        30 Nov 2018
*
*  Test code used while debug.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include <intrin.h>
#include <aclapi.h>


HANDLE g_TestIoCompletion = NULL, g_TestTransaction = NULL;
HANDLE g_TestNamespace = NULL, g_TestMutex = NULL;
HANDLE g_TestMailslot = NULL;
HANDLE g_DebugObject = NULL;
HANDLE g_TestJob = NULL;

VOID TestApiPort(
    VOID
)
{
}

VOID TestDebugObject(
    VOID
)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING    ustr = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\TestDebugObject");

    InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = NtCreateDebugObject(&g_DebugObject, DEBUG_ALL_ACCESS, &obja, 0);
    if (NT_SUCCESS(status)) {
        Beep(0, 0);
    }
}

VOID TestMailslot(
    VOID
)
{
    BOOL bCond = FALSE;
    NTSTATUS status;
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING    ustr = RTL_CONSTANT_STRING(L"\\Device\\Mailslot\\TestMailslot");
    IO_STATUS_BLOCK iost;
    LARGE_INTEGER readTimeout;
    PSID pEveryoneSID = NULL, pAdminSID = NULL;
    PACL pACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS ea[2];
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;

    do {

        //Everyone - GENERIC_READ
        if (!AllocateAndInitializeSid(&SIDAuthWorld, 1,
            SECURITY_WORLD_RID,
            0, 0, 0, 0, 0, 0, 0,
            &pEveryoneSID)) break;

        RtlSecureZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));
        ea[0].grfAccessPermissions = GENERIC_READ;
        ea[0].grfAccessMode = SET_ACCESS;
        ea[0].grfInheritance = NO_INHERITANCE;
        ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea[0].Trustee.ptstrName = (LPTSTR)pEveryoneSID;

        //Admin - GENERIC_ALL
        if (!AllocateAndInitializeSid(&SIDAuthNT, 2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &pAdminSID)) break;

        ea[1].grfAccessPermissions = GENERIC_ALL;
        ea[1].grfAccessMode = SET_ACCESS;
        ea[1].grfInheritance = NO_INHERITANCE;
        ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        ea[1].Trustee.ptstrName = (LPTSTR)pAdminSID;

        SetEntriesInAcl(2, ea, NULL, &pACL);

        pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR,
            SECURITY_DESCRIPTOR_MIN_LENGTH);
        if (pSD == NULL)
            break;

        if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
            break;

        if (!SetSecurityDescriptorDacl(
            pSD,
            TRUE,
            pACL,
            FALSE)) 
        {
            break;
        }

        readTimeout.HighPart = 0x7FFFFFFF;
        readTimeout.LowPart = 0xFFFFFFFF;

        InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, pSD);
        status = NtCreateMailslotFile(&g_TestMailslot,
            GENERIC_READ | SYNCHRONIZE | WRITE_DAC,
            &obja,
            &iost,
            FILE_CREATE,
            0,
            0,
            &readTimeout);
        if (NT_SUCCESS(status)) {
            __nop();
        }

    } while (bCond);

    if (pAdminSID) FreeSid(pAdminSID);
    if (pEveryoneSID) FreeSid(pEveryoneSID);
    if (pSD) LocalFree(pSD);
}

VOID TestPartition(
    VOID
)
{
    NTSTATUS status;
    HANDLE TargetHandle = NULL;
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING    ustr = RTL_CONSTANT_STRING(L"\\KernelObjects\\MemoryPartition0");

    if (g_ExtApiSet.NtOpenPartition != NULL) {

        InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = g_ExtApiSet.NtOpenPartition(&TargetHandle, MEMORY_PARTITION_QUERY_ACCESS, &obja);
        if (NT_SUCCESS(status)) {
            __nop();
            NtClose(TargetHandle);
        }
    }
}

VOID TestIoCompletion(
    VOID
)
{
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING    ustr = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\TestIoCompletion");

    //IoCompletion
    InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
    NtCreateIoCompletion(&g_TestIoCompletion, IO_COMPLETION_ALL_ACCESS, &obja, 100);
}


VOID TestTimer(
    VOID
)
{
    HANDLE        hTimer = NULL;
    LARGE_INTEGER liDueTime;

    liDueTime.QuadPart = -1000000000000LL;

    hTimer = CreateWaitableTimer(NULL, TRUE, L"Global\\TestTimer");
    if (hTimer) {
        SetWaitableTimer(hTimer, &liDueTime, 0, NULL, NULL, 0);
    }
}

VOID TestTransaction(
    VOID
)
{
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING    ustr = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\TestTransaction");

    //TmTx
    InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
    NtCreateTransaction(&g_TestTransaction, TRANSACTION_ALL_ACCESS, &obja, NULL, NULL, 0, 0, 0, NULL, NULL);
}

VOID TestPrivateNamespace(
    VOID
)
{
    BOOL                cond = FALSE;
    DWORD               LastError = 0;
    HANDLE              hBoundaryDescriptor = NULL, hBoundaryDescriptor2 = NULL;
    BYTE                localSID[SECURITY_MAX_SID_SIZE];
    DWORD               cbSID = sizeof(localSID);
    PSID                pLocalAdminSID = &localSID;
    PSID                pMediumILSID = &localSID;
    PSID                pWorldSid = &localSID;
    SECURITY_ATTRIBUTES sa;

    HANDLE hNamespace2, hMutex, hMutex2;

    NTSTATUS Status;

    OBJECT_ATTRIBUTES   obja;
    UNICODE_STRING      pnAlias = RTL_CONSTANT_STRING(L"NamespaceAlias");
    UNICODE_STRING      bdName1 = RTL_CONSTANT_STRING(L"TestBoundaryDescriptor1");
    UNICODE_STRING      bdName2 = RTL_CONSTANT_STRING(L"TestBoundaryDescriptor2");
    UNICODE_STRING      MutexName;

    do {
        RtlSecureZeroMemory(&localSID, sizeof(localSID));
        hBoundaryDescriptor = RtlCreateBoundaryDescriptor(&bdName1, 0);

        if (hBoundaryDescriptor == NULL) {
            break;
        }
        if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, pLocalAdminSID, &cbSID)) {
            break;
        }
        if (!NT_SUCCESS(RtlAddSIDToBoundaryDescriptor(&hBoundaryDescriptor, pLocalAdminSID))) {
            break;
        }
        cbSID = sizeof(localSID);
        if (!CreateWellKnownSid(WinWorldSid, NULL, pWorldSid, &cbSID)) {
            break;
        }
        if (!NT_SUCCESS(RtlAddSIDToBoundaryDescriptor(&hBoundaryDescriptor, pWorldSid))) {
            break;
        }
        cbSID = sizeof(localSID);
        if (!CreateWellKnownSid(WinMediumLabelSid, NULL, pMediumILSID, &cbSID)) {
            break;
        }
        if (!NT_SUCCESS(RtlAddIntegrityLabelToBoundaryDescriptor(&hBoundaryDescriptor, pMediumILSID))) {
            break;
        }

        RtlSecureZeroMemory(&sa, sizeof(sa));
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = FALSE;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
            TEXT("D:(A;;GA;;;BA)"),
            SDDL_REVISION_1, 
            &sa.lpSecurityDescriptor, 
            NULL)) 
        {
            break;
        }

        g_TestNamespace = CreatePrivateNamespace(&sa, hBoundaryDescriptor, TEXT("NamespaceAlias"));
        LastError = GetLastError();
        LocalFree(sa.lpSecurityDescriptor);
        RtlDeleteBoundaryDescriptor(hBoundaryDescriptor);
        hBoundaryDescriptor = NULL;

        if (g_TestNamespace == NULL) {
            break;
        }
        g_TestMutex = CreateMutex(NULL, FALSE, TEXT("NamespaceAlias\\TestMutex"));

//        hMutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE, TEXT("NamespaceAlias\\TestMutex"));
  //      if (hMutex) 
    //        CloseHandle(hMutex);


        RtlInitUnicodeString(&MutexName, TEXT("TestMutex"));
        InitializeObjectAttributes(&obja, &MutexName, OBJ_CASE_INSENSITIVE, g_TestNamespace, NULL);

        Status = NtOpenMutant(&hMutex, MUTANT_ALL_ACCESS, &obja);
        if (NT_SUCCESS(Status))
            NtClose(hMutex);

        //SECOND, checking another portion of MSDN bullshit.

        RtlSecureZeroMemory(&localSID, sizeof(localSID));
        hBoundaryDescriptor2 = RtlCreateBoundaryDescriptor(&bdName2, 0);

        if (hBoundaryDescriptor2 == NULL) {
            break;
        }

        cbSID = sizeof(localSID);
        if (!CreateWellKnownSid(WinWorldSid, NULL, pLocalAdminSID, &cbSID)) {
            break;
        }
      /*  if (!NT_SUCCESS(RtlAddSIDToBoundaryDescriptor(&hBoundaryDescriptor2, pLocalAdminSID))) {
            break;
        }*/

        RtlSecureZeroMemory(&sa, sizeof(sa));
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = FALSE;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
            TEXT("D:(A;;GA;;;BA)"),
            SDDL_REVISION_1,
            &sa.lpSecurityDescriptor,
            NULL))
        {
            break;
        }

        InitializeObjectAttributes(&obja, &pnAlias, OBJ_CASE_INSENSITIVE, NULL, sa.lpSecurityDescriptor);

        Status = NtCreatePrivateNamespace(
            &hNamespace2,
            MAXIMUM_ALLOWED,
            &obja,
            hBoundaryDescriptor2);

        //hNamespace2 = CreatePrivateNamespace(&sa, hBoundaryDescriptor2, TEXT("NamespaceAlias"));
        //LastError = GetLastError();
        LocalFree(sa.lpSecurityDescriptor);
        RtlDeleteBoundaryDescriptor(hBoundaryDescriptor2);
        hBoundaryDescriptor2 = NULL;

        if ((!NT_SUCCESS(Status)) || (hNamespace2 == NULL)) {
            break;
        }

        hMutex = CreateMutex(NULL, FALSE, TEXT("NamespaceAlias\\TestMutex"));




        hMutex2 = OpenMutex(MUTEX_ALL_ACCESS, FALSE, L"NamespaceAlias\\TestMutex");
        if (hMutex2) CloseHandle(hMutex2);

    } while (cond);

    if (hBoundaryDescriptor) RtlDeleteBoundaryDescriptor(hBoundaryDescriptor);
}

VOID TestException(
    VOID
)
{
    __try {
        *(PBYTE)(NULL) = 0;
    }
    __except (exceptFilter(GetExceptionCode(), GetExceptionInformation()))
    {
        __nop();
    }
}

#include "ui.h"

VOID TestWinsta(
    VOID
)
{
    NTSTATUS Status;
    HWINSTA hWinsta;
    PROP_OBJECT_INFO Context;

    //Context.lpCurrentObjectPath = L"\\Windows\\WindowStations";
    Context.lpCurrentObjectPath = L"\\Sessions\\1\\Windows\\WindowStations";
    Context.lpObjectName = L"Winsta0";

    hWinsta = OpenWindowStation(L"WinSta0", FALSE, WINSTA_ALL_ACCESS);

    //hWinsta = supOpenWindowStationFromContext(&Context, FALSE, READ_CONTROL);
    if (hWinsta) {
        CloseWindowStation(hWinsta);
        Status = RtlGetLastNtStatus();
        if (NT_SUCCESS(Status))
            Beep(0, 0);
    }
}

VOID TestJob()
{
    UINT i;
    WCHAR szBuffer[MAX_PATH + 1];

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    g_TestJob = CreateJobObject(NULL, L"Global\\TestJob");
    if (g_TestJob) {

        for (i = 0; i < 9; i++) {

            RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
            ExpandEnvironmentStrings(L"%ComSpec%", szBuffer, MAX_PATH);

            si.cb = sizeof(si);
            GetStartupInfo(&si);

            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;

            if (CreateProcess(
                szBuffer,
                NULL,
                NULL,
                NULL,
                FALSE,
                0,
                NULL,
                NULL,
                &si,
                &pi)) 
            {
                AssignProcessToJobObject(g_TestJob, pi.hProcess);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
        }
    }
}

VOID TestCall()
{

}

VOID TestStart(
    VOID
)
{
    TestCall();
    TestApiPort();
    TestDebugObject();
    TestMailslot();
    TestPartition();
    TestPrivateNamespace();
    TestIoCompletion();
    TestTimer();
    TestTransaction();
    TestWinsta();
    //TestJob();
}

VOID TestStop(
    VOID
)
{
    if (g_DebugObject) NtClose(g_DebugObject);
    if (g_TestIoCompletion) NtClose(g_TestIoCompletion);
    if (g_TestTransaction) NtClose(g_TestTransaction);

    if (g_TestMutex != NULL) {
        CloseHandle(g_TestMutex);
    }
    if (g_TestNamespace != NULL) {
        ClosePrivateNamespace(g_TestNamespace, PRIVATE_NAMESPACE_FLAG_DESTROY);
    }
    if (g_TestMailslot) {
        NtClose(g_TestMailslot);
    }
    if (g_TestJob) {
        TerminateJobObject(g_TestJob, 0);
        NtClose(g_TestJob);
    }
}
