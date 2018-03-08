/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       TESTUNIT.C
*
*  VERSION:     1.52
*
*  DATE:        08 Jan 2018
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
    UNICODE_STRING    ustr;

    ustr.Buffer = NULL;
    RtlInitUnicodeString(&ustr, L"\\BaseNamedObjects\\TestDebugObject");
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
    UNICODE_STRING    ustr;
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
        ea[0].grfAccessPermissions = GENERIC_ALL;
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

        InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION);

        if (!SetSecurityDescriptorDacl(pSD,
            TRUE,
            pACL,
            FALSE)) break;

        readTimeout.HighPart = 0x7FFFFFFF;
        readTimeout.LowPart = 0xFFFFFFFF;

        ustr.Buffer = NULL;
        RtlInitUnicodeString(&ustr, L"\\Device\\Mailslot\\TestMailslot");

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
}

VOID TestPartition(
    VOID
)
{
    NTSTATUS status;
    HANDLE TargetHandle = NULL;
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING    ustr;

    if (g_ExtApiSet.NtOpenPartition != NULL) {
        ustr.Buffer = NULL;
        RtlInitUnicodeString(&ustr, L"\\KernelObjects\\MemoryPartition0");
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
    UNICODE_STRING    ustr;

    //IoCompletion
    ustr.Buffer = NULL;
    RtlInitUnicodeString(&ustr, L"\\BaseNamedObjects\\TestIoCompletion");
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

    hTimer = CreateWaitableTimer(NULL, TRUE, L"TestTimer");
    if (hTimer) {
        SetWaitableTimer(hTimer, &liDueTime, 0, NULL, NULL, 0);
    }
}

VOID TestTransaction(
    VOID
)
{
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING    ustr;

    //TmTx
    ustr.Buffer = NULL;
    RtlInitUnicodeString(&ustr, L"\\BaseNamedObjects\\TestTransaction");
    InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
    NtCreateTransaction(&g_TestTransaction, TRANSACTION_ALL_ACCESS, &obja, NULL, NULL, 0, 0, 0, NULL, NULL);
}

VOID TestPrivateNamespace(
    VOID
)
{
    BOOL                cond = FALSE;
    HANDLE              hBoundaryDescriptor = NULL;
    SECURITY_ATTRIBUTES sa;
    BYTE                localAdminSID[SECURITY_MAX_SID_SIZE];
    PSID                pLocalAdminSID = &localAdminSID;
    DWORD               cbSID = sizeof(localAdminSID);
    CHAR                text[1000];

    do {
        RtlSecureZeroMemory(&localAdminSID, sizeof(localAdminSID));
        hBoundaryDescriptor = CreateBoundaryDescriptor(TEXT("TestBoundaryDescriptor"), 0);
        if (hBoundaryDescriptor == NULL) {
            break;
        }

        if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, pLocalAdminSID, &cbSID)) {
            break;
        }
        if (!AddSIDToBoundaryDescriptor(&hBoundaryDescriptor, pLocalAdminSID)) {
            break;
        }

        RtlSecureZeroMemory(&sa, sizeof(sa));
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = FALSE;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(TEXT("D:(A;;GA;;;BA)"),
            SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL)) {
            break;
        }

        g_TestNamespace = CreatePrivateNamespace(&sa, hBoundaryDescriptor, TEXT("Mynamespace2"));
        LocalFree(sa.lpSecurityDescriptor);

        if (g_TestNamespace == NULL) {
            ultostr_a(GetLastError(), text);
            OutputDebugStringA(text);
            break;
        }

        g_TestMutex = CreateMutex(NULL, FALSE, TEXT("Mynamespace2\\TestMutex"));

    } while (cond);
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

    Context.lpCurrentObjectPath = L"\\Windows\\WindowStations";
    //Context.lpCurrentObjectPath = L"\\Sessions\\1\\Windows\\WindowStations";
    Context.lpObjectName = L"Winsta0";

    hWinsta = supOpenWindowStationFromContext(&Context, FALSE, READ_CONTROL);
    if (hWinsta) {

        CloseWindowStation(hWinsta);
        Status = RtlGetLastNtStatus();
        if (NT_SUCCESS(Status))
            Beep(0, 0);
    }
}

VOID TestStart(
    VOID
)
{
    TestApiPort();
    TestDebugObject();
    TestMailslot();
    TestPartition();
    TestPrivateNamespace();
    TestIoCompletion();
    TestTimer();
    TestTransaction();
    TestWinsta();
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
}
