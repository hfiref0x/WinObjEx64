/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2023
*
*  TITLE:       TESTUNIT.C
*
*  VERSION:     2.03
*
*  DATE:        21 Jul 2023
*
*  Test code used while debug.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#define OEMRESOURCE

#include "global.h"
#include "ntos\ntldr.h"
#pragma warning(push)
#pragma warning(disable:28251) //Inconsistent annotation for any intrin, "feature" of the latest MSVC
#include <intrin.h>
#pragma warning(pop)
#include <aclapi.h>

HANDLE g_TestNamespace = NULL, g_TestMutex = NULL;
HANDLE g_TestMailslot = NULL;
HANDLE g_TestThread = NULL;
HANDLE g_TestPortThread = NULL;
HANDLE g_PortHandle;
PVOID g_MappedSection = NULL;
HANDLE g_SectionVaTest = NULL;
HANDLE g_ResourceManager = NULL;
HANDLE g_TestJob = NULL;

typedef struct _LPC_USER_MESSAGE {
    PORT_MESSAGE	Header;
    BYTE			Data[128];
} LPC_USER_MESSAGE, * PLPC_USER_MESSAGE;

typedef struct _QUERY_REQUEST {
    ULONG	Data;
} QUERY_REQUEST, * PQUERY_REQUEST;

#define WOBJEX_TEST_PORT L"\\Rpc Control\\WinObjEx_ServiceTestPort48429"

HANDLE TestGetPortHandle()
{
    return g_PortHandle;
}

typedef NTSTATUS (NTAPI* pfnNtCreateRegistryTransaction)(
    _Out_ PHANDLE Handle,
    _In_ ACCESS_MASK DesiredAccess, //generic + TRANSACTION_*
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ DWORD Flags);

VOID TestRegistryTransaction()
{
    NTSTATUS ntStatus;
    HANDLE hObject;
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING usName;
    pfnNtCreateRegistryTransaction NtCreateRegistryTransaction;
    HMODULE hNtdll;
    
    hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll) {

        NtCreateRegistryTransaction = (pfnNtCreateRegistryTransaction)GetProcAddress(hNtdll, "NtCreateRegistryTransaction");
        if (NtCreateRegistryTransaction != NULL) {

            RtlInitUnicodeString(&usName, L"\\RPC Control\\TestRegTransaction");
            InitializeObjectAttributes(&obja, &usName, OBJ_CASE_INSENSITIVE, NULL, NULL);
            ntStatus = NtCreateRegistryTransaction(&hObject, TRANSACTION_ALL_ACCESS, &obja, 0);
            if (NT_SUCCESS(ntStatus)) {
                __nop();
            }

        }

    }
}

VOID TestCreateBogusObjects()
{
    HANDLE        hTimer = NULL, hDirectory = NULL, hObject = NULL;
    LARGE_INTEGER liDueTime;
    LPWSTR lpName;
    SIZE_T l, i;
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING usName, usObject;

    WCHAR szBuffer[MAX_PATH + 1];

    liDueTime.QuadPart = -1000000000000LL;

    lpName = (LPWSTR)supHeapAlloc(UNICODE_STRING_MAX_BYTES);
    if (lpName) {
        _strcpy(lpName, L"\\BaseNamedObjects\\BogusLongName");
        l = _strlen(lpName);
        for (i = l; i < UNICODE_STRING_MAX_CHARS - l - 1; i++)
            lpName[i] = L't';

        RtlInitUnicodeString(&usName, lpName);
        InitializeObjectAttributes(&obja, &usName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        NtCreateTimer(&hTimer, TIMER_ALL_ACCESS, &obja, NotificationTimer);
        if (hTimer) {
            SetWaitableTimer(hTimer, &liDueTime, 0, NULL, NULL, 0);
        }

        supHeapFree(lpName);
    }

    _strcpy(szBuffer, L"\\BaseNamedObjects\\BogusEmbeddedNull");
    l = _strlen(szBuffer);
    szBuffer[l++] = 0;
    szBuffer[l++] = L't';
    szBuffer[l++] = L'e';
    szBuffer[l++] = L's';
    szBuffer[l++] = L't';

    l *= 2;

    usName.Buffer = szBuffer;
    usName.Length = (USHORT)l;
    usName.MaximumLength = usName.Length + sizeof(UNICODE_NULL);

    InitializeObjectAttributes(&obja, &usName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NtCreateTimer(&hTimer, TIMER_ALL_ACCESS, &obja, NotificationTimer);
    if (hTimer) SetWaitableTimer(hTimer, &liDueTime, 0, NULL, NULL, 0);

    _strcpy(szBuffer, L"\\RPC Control\\BogusEmbeddedNull");
    l = _strlen(szBuffer);
    szBuffer[l++] = 0;
    szBuffer[l++] = L't';
    szBuffer[l++] = L'e';
    szBuffer[l++] = L's';
    szBuffer[l++] = L't';

    l *= 2;

    usName.Buffer = szBuffer;
    usName.Length = (USHORT)l;
    usName.MaximumLength = usName.Length + sizeof(UNICODE_NULL);
    if (NT_SUCCESS(NtCreateDirectoryObject(&hDirectory, DIRECTORY_ALL_ACCESS, &obja))) {
        RtlInitUnicodeString(&usName, L"SomeTimer");
        obja.RootDirectory = hDirectory;
        if (NT_SUCCESS(NtCreateTimer(&hTimer, TIMER_ALL_ACCESS,
            &obja, NotificationTimer)))
        {
            if (hTimer) SetWaitableTimer(hTimer, &liDueTime, 0, NULL, NULL, 0);
        }
    }

    _strcpy(szBuffer, L"SurpriseDirectory");
    l = _strlen(szBuffer);
    szBuffer[l++] = 0;
    szBuffer[l++] = L't';
    szBuffer[l++] = L'e';
    szBuffer[l++] = L's';
    szBuffer[l++] = L't';
    szBuffer[l++] = 0;
    szBuffer[l++] = L'h';
    szBuffer[l++] = L'a';
    szBuffer[l++] = 0;
    szBuffer[l++] = 0;
    szBuffer[l++] = L'h';
    szBuffer[l++] = L'a';
    l *= 2;

    usName.Buffer = szBuffer;
    usName.Length = (USHORT)l;
    usName.MaximumLength = usName.Length + sizeof(UNICODE_NULL);
    obja.RootDirectory = hDirectory;
    if (NT_SUCCESS(NtCreateDirectoryObject(&hDirectory, DIRECTORY_ALL_ACCESS, &obja))) {
        RtlInitUnicodeString(&usObject, L"SurpriseTimer");
        obja.RootDirectory = hDirectory;
        obja.ObjectName = &usObject;
        if (NT_SUCCESS(NtCreateTimer(&hTimer, TIMER_ALL_ACCESS,
            &obja, NotificationTimer)))
        {
            if (hTimer) SetWaitableTimer(hTimer, &liDueTime, 0, NULL, NULL, 0);

            RtlInitUnicodeString(&usObject, L"\\RPC Control\\TestLink");
            InitializeObjectAttributes(&obja, &usObject, OBJ_CASE_INSENSITIVE, NULL, NULL);

            _strcpy(szBuffer, L"\\RPC Control\\BogusEmbeddedNull");
            l = _strlen(szBuffer);
            szBuffer[l++] = 0;
            szBuffer[l++] = L't';
            szBuffer[l++] = L'e';
            szBuffer[l++] = L's';
            szBuffer[l++] = L't';
            l *= 2;

            usName.Length = (USHORT)l;
            usName.MaximumLength = usName.Length + sizeof(UNICODE_NULL);

            NtCreateSymbolicLinkObject(&hObject, SYMBOLIC_LINK_ALL_ACCESS, &obja, &usName);

        }
    }

}

DWORD WINAPI LPCListener(LPVOID lpThreadParameter)
{
    NTSTATUS Status;
    LPC_USER_MESSAGE UserMessage;
    PQUERY_REQUEST QueryRequest;

    UNICODE_STRING PortName = RTL_CONSTANT_STRING(WOBJEX_TEST_PORT);
    OBJECT_ATTRIBUTES ObjectAttributes;

    HANDLE ConnectPort;

    UNREFERENCED_PARAMETER(lpThreadParameter);

    InitializeObjectAttributes(&ObjectAttributes, &PortName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = NtCreatePort(&g_PortHandle,
        &ObjectAttributes,
        0,
        sizeof(LPC_USER_MESSAGE),
        0);

    if (!NT_SUCCESS(Status)) {
        ExitThread(0);
    }

    do {

        RtlSecureZeroMemory(&UserMessage, sizeof(UserMessage));
        if (!NT_SUCCESS(NtListenPort(g_PortHandle, &UserMessage.Header)))
            break;

        ConnectPort = NULL;
        if (!NT_SUCCESS(NtAcceptConnectPort(&ConnectPort,
            NULL,
            &UserMessage.Header,
            TRUE,
            NULL,
            NULL)))
        {
            break;
        }

        if (NT_SUCCESS(NtCompleteConnectPort(ConnectPort))) {

            __try {

                RtlSecureZeroMemory(&UserMessage, sizeof(UserMessage));
                NtReplyWaitReceivePort(ConnectPort, NULL, NULL, &UserMessage.Header);

                QueryRequest = (PQUERY_REQUEST)&UserMessage.Data;
                kdDebugPrint("Data=%lx", QueryRequest->Data);
                if (QueryRequest->Data == 1)
                    break;

            }
            __except (WOBJ_EXCEPTION_FILTER_LOG) {
                __nop();
            }

        }

        NtClose(ConnectPort);

    } while (TRUE);

    NtClose(g_PortHandle);

    ExitThread(0);
}

VOID TestApiPort(
    VOID
)
{
    g_TestPortThread = supCreateThread((LPTHREAD_START_ROUTINE)LPCListener, NULL, 0);
}

VOID TestDebugObject(
    VOID
)
{
    HANDLE hObject = NULL;
    NTSTATUS status;
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING    ustr = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\TestDebugObject");

    InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = NtCreateDebugObject(&hObject, DEBUG_ALL_ACCESS, &obja, 0);
    if (NT_SUCCESS(status)) {
        __nop();
    }
}

VOID TestMailslot(
    VOID
)
{
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

    } while (FALSE);

    if (pAdminSID) FreeSid(pAdminSID);
    if (pEveryoneSID) FreeSid(pEveryoneSID);
    if (pSD) LocalFree(pSD);
}

VOID TestPartition(
    VOID
)
{
    HANDLE TargetHandle = NULL;
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING    ustr = RTL_CONSTANT_STRING(L"\\KernelObjects\\MemoryPartition0");

    if (g_ExtApiSet.NtOpenPartition != NULL) {

        InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
        g_ExtApiSet.NtOpenPartition(&TargetHandle, MEMORY_PARTITION_QUERY_ACCESS, &obja);

    }
}

VOID TestIoCompletion(
    VOID
)
{
    HANDLE hCompletion = NULL;
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING    ustr = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\TestIoCompletion");

    //IoCompletion
    InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
    NtCreateIoCompletion(&hCompletion, IO_COMPLETION_ALL_ACCESS, &obja, 100);
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

VOID TestTransactionResourceManager(
    VOID
)
{
    HANDLE hObject = NULL;
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING usName;
    GUID tmp;

    InitializeObjectAttributes(&obja, NULL, OBJ_CASE_INSENSITIVE, NULL, NULL);

    if (NT_SUCCESS(NtCreateTransactionManager(&hObject,
        TRANSACTIONMANAGER_ALL_ACCESS,
        &obja,
        NULL,
        TRANSACTION_MANAGER_VOLATILE,
        0)))
    {
        if (S_OK == CoCreateGuid(&tmp)) {
            RtlInitUnicodeString(&usName, L"\\BaseNamedObjects\\TestRm");
            obja.ObjectName = &usName;
            if (NT_SUCCESS(NtCreateResourceManager(&g_ResourceManager,
                RESOURCEMANAGER_ALL_ACCESS,
                hObject,
                &tmp,
                &obja,
                RESOURCE_MANAGER_VOLATILE,
                NULL)))
            {
                __nop();
            }
        }
    }
}

VOID TestTransaction(
    VOID
)
{
    HANDLE hObject;
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING    ustr = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\TestTransaction");

    //TmTx
    InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
    NtCreateTransaction(&hObject, TRANSACTION_ALL_ACCESS, &obja, NULL, NULL, 0, 0, 0, NULL, NULL);
}

VOID TestPrivateNamespace(
    VOID
)
{
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

    } while (FALSE);

    if (hBoundaryDescriptor) RtlDeleteBoundaryDescriptor(hBoundaryDescriptor);
}

VOID TestException(
    _In_ BOOL bNaked
)
{
    if (bNaked)
        *(PBYTE)(NULL) = 0;
    else {

        __try {
            *(PBYTE)(NULL) = 0;
        }
        __except (WOBJ_EXCEPTION_FILTER_LOG)
        {
            __nop();
        }
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

VOID TestPsObjectSecurity(
    _In_ BOOL bThread)
{
    DWORD dwErr;
    PACL EmptyDacl;
    HANDLE hObject;

    if (bThread)
        hObject = GetCurrentThread();
    else
        hObject = GetCurrentProcess();

    EmptyDacl = (PACL)supHeapAlloc(sizeof(ACL));
    if (EmptyDacl) {

        if (!InitializeAcl(
            EmptyDacl,
            sizeof(ACL),
            ACL_REVISION))
        {
            dwErr = GetLastError();
        }
        else {

            dwErr = SetSecurityInfo(hObject,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                NULL,
                NULL,
                EmptyDacl,
                NULL);
        }

        if (dwErr != ERROR_SUCCESS)
            __nop();

        supHeapFree(EmptyDacl);
    }
}

VOID TestDesktop(
    VOID
)
{
    HANDLE hDesktop;
    DWORD LastError = 0;

    hDesktop = CreateDesktop(TEXT("TestDesktop"), NULL, NULL, 0,
        DESKTOP_CREATEWINDOW | DESKTOP_SWITCHDESKTOP, NULL);

    if (hDesktop == NULL) {
        LastError = GetLastError();
        if (LastError != 0)
            __nop();
    }
}

DWORD WINAPI TokenImpersonationThreadProc(PVOID Parameter)
{

    ULONG i = 0;
    HANDLE hToken;

    UNREFERENCED_PARAMETER(Parameter);

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
        if (!ImpersonateLoggedOnUser(hToken))
            __nop();
        CloseHandle(hToken);
    }

    do {
        Sleep(1000);
        kdDebugPrint("WinObjEx64 test thread, %lu\r\n", GetCurrentThreadId());
        i += 1;
    } while (i < 1000);

    if (!RevertToSelf())
        __nop();
    ExitThread(0);
}

VOID TestThread()
{
    g_TestThread = supCreateThread((LPTHREAD_START_ROUTINE)TokenImpersonationThreadProc, NULL, 0);
}

VOID TestApiSetResolve()
{
    ULONG i;
    PVOID Data = NtCurrentPeb()->ApiSetMap;

    NTSTATUS Status;

    UNICODE_STRING ApiSetLibrary;
    UNICODE_STRING ParentLibrary;
    UNICODE_STRING ResolvedHostLibrary;

    LPWSTR ToResolve[] = {
        L"hui-ms-win-core-app-l1-2-3.dll",
        L"api-ms-win-nevedomaya-ebanaya-hyinua-l1-1-3.dll",
        L"api-ms-win-core-appinit-l1-1-0.dll",
        L"api-ms-win-core-com-private-l1-2-0",
        L"ext-ms-win-fs-clfs-l1-1-0.dll",
        L"ext-ms-win-core-app-package-registration-l1-1-1",
        L"ext-ms-win-shell-ntshrui-l1-1-0.dll",
        NULL,
        L"api-ms-win-core-psapi-l1-1-0.dll",
        L"api-ms-win-core-enclave-l1-1-1.dll",
        L"api-ms-onecoreuap-print-render-l1-1-0.dll",
        L"api-ms-win-deprecated-apis-advapi-l1-1-0.dll",
        L"api-ms-win-core-com-l2-1-1"
    };

    if (Data == NULL) {
        kdDebugPrint("APISET>>ApiSetMap is NULL\r\n");
        return;
    }

    for (i = 0; i < RTL_NUMBER_OF(ToResolve); i++) {

        RtlInitUnicodeString(&ApiSetLibrary, ToResolve[i]);
        RtlInitEmptyUnicodeString(&ResolvedHostLibrary, NULL, 0);

        Status = NtRawApiSetResolveLibrary(Data,
            &ApiSetLibrary,
            NULL,
            &ResolvedHostLibrary);

        if (NT_SUCCESS(Status)) {
            kdDebugPrint("APISET>> %wZ\r\n", &ResolvedHostLibrary);
            RtlFreeUnicodeString(&ResolvedHostLibrary);
        }
        else {
            kdDebugPrint("APISET>> NtRawApiSetResolveLibrary failed 0x%lx for %wZ\r\n", Status, &ApiSetLibrary);
        }
    }

    RtlInitUnicodeString(&ParentLibrary, L"kernel32.dll");
    RtlInitUnicodeString(&ApiSetLibrary, L"api-ms-win-core-processsecurity-l1-1-0.dll");

    Status = NtRawApiSetResolveLibrary(Data,
        &ApiSetLibrary,
        &ParentLibrary,
        &ResolvedHostLibrary);

    if (NT_SUCCESS(Status)) {
        kdDebugPrint("APISET>> Resolved apiset %wZ\r\n", &ResolvedHostLibrary);
        RtlFreeUnicodeString(&ResolvedHostLibrary);
    }
    else {
        kdDebugPrint("NtRawApiSetResolveLibrary failed 0x%lx\r\n", Status);
    }
}

BOOL CALLBACK EnumerateSLValueDescriptorCallback(
    _In_ SL_KMEM_CACHE_VALUE_DESCRIPTOR* CacheDescriptor,
    _In_opt_ PVOID Context
)
{
    WCHAR* EntryName;
    CHAR* EntryType;

    UNREFERENCED_PARAMETER(Context);

    EntryName = (PWCHAR)supHeapAlloc(CacheDescriptor->NameLength + sizeof(WCHAR));
    if (EntryName) {

        RtlCopyMemory(EntryName, CacheDescriptor->Name, CacheDescriptor->NameLength);

        switch (CacheDescriptor->Type) {
        case SL_DATA_SZ:
            EntryType = "SL_DATA_SZ";
            break;
        case SL_DATA_DWORD:
            EntryType = "SL_DATA_DWORD";
            break;
        case SL_DATA_BINARY:
            EntryType = "SL_DATA_BINARY";
            break;
        case SL_DATA_MULTI_SZ:
            EntryType = "SL_DATA_MULTI_SZ";
            break;
        case SL_DATA_SUM:
            EntryType = "SL_DATA_SUM";
            break;

        default:
            EntryType = "Unknown";
        }

        kdDebugPrint("%ws, %s\r\n", EntryName, EntryType);
        supHeapFree(EntryName);

    }
    return FALSE;
}

VOID TestLicenseCache()
{
    PVOID CacheData = supSLCacheRead();
    if (CacheData) {
        supSLCacheEnumerate(CacheData, EnumerateSLValueDescriptorCallback, NULL);
        supHeapFree(CacheData);
    }
}

WCHAR* g_szMapDlls[] = {
    L"\\??\\C:\\build\\temp\\win7pc\\test.dll",
    L"\\systemroot\\system32\\winnsi.dll",
    L"\\systemroot\\system32\\sxssrv.dll",
    L"\\systemroot\\system32\\sppwinob.dll",
    L"\\systemroot\\system32\\Microsoft.Bluetooth.Proxy.dll",
    L"\\systemroot\\system32\\ddp_ps.dll",
    L"\\systemroot\\system32\\BitsProxy.dll",
    L"\\systemroot\\system32\\xboxgipsynthetic.dll" //does not have VERSION_INFO
};

wchar_t* Tstp_filename(const wchar_t* f)
{
    wchar_t* p = (wchar_t*)f;

    if (f == 0)
        return 0;

    while (*f != (wchar_t)0) {
        if (*f == (wchar_t)'\\')
            p = (wchar_t*)f + 1;
        f++;
    }
    return p;
}

VOID TestSectionControlArea()
{
    NTSTATUS ntStatus;

    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING ustr;
    HANDLE sectionHandle;
    SIZE_T commitSize = PAGE_SIZE;
    PVOID baseAddress = NULL;
    LARGE_INTEGER liSectionSize;

    WCHAR szText[] = TEXT("This is text in our VA space");

    RtlInitUnicodeString(&ustr, L"\\BaseNamedObjects\\TestSectionVa");
    InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);

    liSectionSize.QuadPart = commitSize;

    ntStatus = NtCreateSection(&sectionHandle,
        SECTION_ALL_ACCESS,
        &obja,
        &liSectionSize,
        PAGE_READWRITE,
        SEC_COMMIT,
        NULL);

    if (NT_SUCCESS(ntStatus)) {

        if (NT_SUCCESS(NtMapViewOfSection(sectionHandle,
            NtCurrentProcess(),
            &baseAddress,
            0,
            commitSize,
            NULL,
            &commitSize,
            ViewUnmap,
            MEM_TOP_DOWN,
            PAGE_READWRITE)))
        {
            RtlCopyMemory(baseAddress, szText, sizeof(szText));
            g_MappedSection = baseAddress;
            g_SectionVaTest = sectionHandle;
        }
        else {

            NtClose(sectionHandle);
        }
    }
}

VOID TestSectionImage()
{
    OBJECT_ATTRIBUTES obja, dirObja;
    UNICODE_STRING ustr;
    IO_STATUS_BLOCK iost;

    NTSTATUS ntStatus;

    LPWSTR lpFileName;
    HANDLE sectionHandle = NULL, dirHandle = NULL, fileHandle = NULL;

    RtlInitUnicodeString(&ustr, L"\\RPC Control\\TestSectionImage");
    InitializeObjectAttributes(&dirObja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
    ntStatus = NtCreateDirectoryObject(&dirHandle, DIRECTORY_ALL_ACCESS, &dirObja);

    if (NT_SUCCESS(ntStatus)) {

        dirObja.RootDirectory = dirHandle;

        for (ULONG i = 0; i < RTL_NUMBER_OF(g_szMapDlls); i++) {

            RtlInitUnicodeString(&ustr, g_szMapDlls[i]);
            InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);

            ntStatus = NtOpenFile(&fileHandle,
                SYNCHRONIZE | FILE_EXECUTE,
                &obja,
                &iost,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

            if (NT_SUCCESS(ntStatus)) {

                lpFileName = (LPWSTR)Tstp_filename(g_szMapDlls[i]);

                RtlInitUnicodeString(&ustr, lpFileName);

                ntStatus = NtCreateSection(&sectionHandle,
                    SECTION_ALL_ACCESS,
                    &dirObja,
                    NULL,
                    PAGE_EXECUTE,
                    SEC_IMAGE,
                    fileHandle);

                if (NT_SUCCESS(ntStatus)) {
                    kdDebugPrint("Mapped\r\n");
                }

            }

        }
    }
}

/*

COMPATIBILITY WARNING:

DOES NOT PRESENT IN WIN7

*/

VOID TestShadowDirectory()
{
    OBJECT_ATTRIBUTES dirObja, obja;
    UNICODE_STRING ustr;
    HANDLE dirHandle, shadowDirHandle, testHandle, testHandle2;
    NTSTATUS ntStatus;

    //
    // Open BaseNamedObjects handle.
    //

    RtlInitUnicodeString(&ustr, L"\\BaseNamedObjects");
    InitializeObjectAttributes(&dirObja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
    ntStatus = NtOpenDirectoryObject(&shadowDirHandle, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &dirObja);

    if (NT_SUCCESS(ntStatus)) {

        //
        // Create test object (mutant) in \\BaseNamedObjects.
        //
        RtlInitUnicodeString(&ustr, L"TestObject");
        InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, shadowDirHandle, NULL);
        ntStatus = NtCreateMutant(&testHandle, MUTANT_ALL_ACCESS, &obja, FALSE);
        if (NT_SUCCESS(ntStatus)) {

            //
            // Create BaseNamedObjects\\New directory with shadow set to \\BaseNamedObjects
            //
            RtlInitUnicodeString(&ustr, L"\\BaseNamedObjects\\New");
            ntStatus = NtCreateDirectoryObjectEx(&dirHandle, DIRECTORY_ALL_ACCESS, &dirObja, shadowDirHandle, 0);
            if (NT_SUCCESS(ntStatus)) {

                //
                // Open "TestObject" in \\BaseNamedObjects\\New, 
                // since "New" has shadow set to \\BaseNamedObjects Windows will lookup this object first in shadow.
                //
                RtlInitUnicodeString(&ustr, L"\\BaseNamedObjects\\New\\TestObject");
                obja.RootDirectory = NULL;
                ntStatus = NtOpenMutant(&testHandle2, MUTANT_ALL_ACCESS, &obja);
                if (NT_SUCCESS(ntStatus)) {
                    __nop();
                }
            }
        }
        NtClose(shadowDirHandle);
    }
}

VOID TestAlpcPortOpen()
{
    HANDLE hObject = NULL;
    NTSTATUS ntStatus;
    UNICODE_STRING usName;

    RtlInitUnicodeString(&usName, WOBJEX_TEST_PORT);

    ntStatus = supOpenPortObjectByName(&hObject,
        PORT_ALL_ACCESS,
        &usName);

    if (NT_SUCCESS(ntStatus)) {
        NtClose(hObject);
    }
    else {
        kdDebugPrint("supOpenPortObjectByName failed with NTSTATUS 0x%lX", (ULONG)ntStatus);
    }
}

VOID PreHashTypes()
{
    ObManagerTest();
}

VOID TestSymbols()
{
    BOOL bStatus;
    ULONG dummy, i, j;
    ULONG64 var;
    PSYM_ENTRY pSymEntry;
    PSYMCONTEXT Context;
    PSYMPARSER SymParser;

    LPCWSTR testSymbols[] = {
        L"_POOL_TYPE",
        L"_RTL_USER_PROCESS_PARAMETERS",
        L"_PEB",
        L"INVALID_NOT_EXIST",
        L"_UNICODE_STRING",
        L"_STRING",
        L"_GDI_TEB_BATCH",
        L"_CONTROL_AREA",
        L"_IO_STATUS_BLOCK"
    };

    SYM_CHILD* pSymChild;

    WCHAR* pStrEnd;
    WCHAR* pOutput;

    if (!kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext))
        return;

    pOutput = (WCHAR*)supHeapAlloc(4 * MAX_SYM_NAME);
    if (pOutput == NULL)
        return;

    Context = (PSYMCONTEXT)g_kdctx.NtOsSymContext;
    if (Context) {

        SymParser = &Context->Parser;

        //
        // Test parser 
        // N.B. This is not fully functional dumper with fancy decorations.
        //

        for (i = 0; i < RTL_NUMBER_OF(testSymbols); i++) {
            pSymEntry = SymParser->DumpSymbolInformation(Context,
                testSymbols[i],
                &bStatus);

            if (pSymEntry == NULL) {
                _strcpy(pOutput, L"\r\n->");
                _strcat(pOutput, testSymbols[i]);
                _strcat(pOutput, L"<- failed to dump\r\n");
                OutputDebugStringW(pOutput);

            }
            else {

                _strcpy(pOutput, TEXT("\r\n"));
                _strcat(pOutput, pSymEntry->Name);
                _strcat(pOutput, TEXT("\r\n"));

                OutputDebugStringW(pOutput);

                for (j = 0; j < pSymEntry->ChildCount; j++) {

                    pOutput[0] = 0;

                    pSymChild = &pSymEntry->ChildEntries[j];

                    RtlStringCchPrintfSecure(&pOutput[0],
                        (MAX_SYM_NAME + 32) * 2,
                        TEXT("/* 0x%04lx: */\t%ws %ws"),
                        pSymChild->Offset,
                        pSymChild->TypeName,
                        pSymChild->Name);

                    pStrEnd = _strend(pOutput);

                    if (pSymChild->ElementsCount > 1) {

                        RtlStringCchPrintfSecure(pStrEnd,
                            32,
                            TEXT("[%llu]"),
                            pSymChild->ElementsCount);

                        pStrEnd = _strend(pOutput);

                    }

                    if (pSymChild->IsValuePresent) {

                        RtlStringCchPrintfSecure(pStrEnd,
                            32,
                            TEXT(" = %llu"),
                            pSymChild->Value);
                        pStrEnd = _strend(pOutput);
                    }

                    _strcat(pStrEnd, TEXT(";"));

                    if (pSymChild->IsBitField) {

                        pStrEnd = _strcat(pStrEnd, TEXT(" /* bit position: "));
                        ultostr(pSymChild->BitPosition, pStrEnd);
                        _strcat(pStrEnd, TEXT(" */"));
                        pStrEnd = _strend(pStrEnd);
                    }

                    _strcat(pStrEnd, TEXT("\r\n"));

                    OutputDebugStringW(pOutput);

                }

                supHeapFree(pSymEntry);
            }
        }

        dummy = SymParser->GetFieldOffset(Context,
            L"_EPROCESS",
            L"UniqueProcessId",
            &bStatus);

        if (bStatus) {

            DbgPrint("sym offset %lx\r\n", dummy);

        }

        var = 0;
        if (kdGetAddressFromSymbol(
            &g_kdctx,
            TEXT("ObHeaderCookie"),
            &var))
        {
            DbgPrint("ObHeaderCookie %p\r\n", (PVOID)var);
        }

    }

    supHeapFree(pOutput);
}

#include <wtsapi32.h>
#pragma comment(lib, "Wtsapi32.lib")

VOID TestSessions()
{
    DWORD sessionsCount, i;
    WTS_SESSION_INFO* pSessions;

    if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE,
        0,
        1,
        &pSessions,
        &sessionsCount))
    {
        for (i = 0; i < sessionsCount; i++) {
            kdDebugPrint("Session %lu: %ws\n", pSessions[i].SessionId, pSessions[i].pWinStationName);
        }
        WTSFreeMemory(pSessions);
    }
}

VOID TestCmControlVector()
{
    union {
        union {
            CM_SYSTEM_CONTROL_VECTOR_V1* v1;
            CM_SYSTEM_CONTROL_VECTOR_V2* v2;
        } Version;
        PBYTE Ref;
    } CmControlVector;

    SIZE_T size;

    CmControlVector.Ref = (PBYTE)kdQueryCmControlVector(&g_kdctx);

    if (g_NtBuildNumber >= NT_WIN10_REDSTONE4)
        size = sizeof(CM_SYSTEM_CONTROL_VECTOR_V2);
    else
        size = sizeof(CM_SYSTEM_CONTROL_VECTOR_V1);


    while (CmControlVector.Version.v1->KeyPath != NULL) {

        OutputDebugString(CmControlVector.Version.v1->KeyPath);
        OutputDebugString(L"\r\n");
        OutputDebugString(CmControlVector.Version.v1->ValueName);
        OutputDebugString(L"\r\n============\r\n");

        CmControlVector.Ref += size;
    }
}

VOID TestCall()
{
}

VOID TestObCallback()
{
    struct {
        ULONG Value1;
        ULONG Value2;
        HANDLE Pid1;
        HANDLE Pid2;
        BYTE Spare[392];
    } request;

    NTSTATUS ntStatus;
    DWORD procId1 = 3448;

    HANDLE deviceHandle = CreateFile(TEXT("\\\\.\\ImfObCallback"),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (deviceHandle != INVALID_HANDLE_VALUE) {

        ntStatus = supCallDriver(deviceHandle,
            0x22200C,
            NULL,
            0,
            NULL,
            0);

        if (NT_SUCCESS(ntStatus)) {

            RtlSecureZeroMemory(&request, sizeof(request));
            request.Pid1 = UlongToHandle(procId1);
            request.Pid2 = NULL;

            ntStatus = supCallDriver(deviceHandle,
                0x222008,
                &request,
                sizeof(request),
                NULL,
                0);

        }

        CloseHandle(deviceHandle);
    }
}

VOID TestStart(
    VOID
)
{
 //   TestCall();
 //   TestRegistryTransaction();
    //TestTransactionResourceManager();
 //   TestCreateBogusObjects();
    //TestCmControlVector();
 //   TestObCallback();
    //TestSectionControlArea();
    //TestSymbols();
    //TestSectionImage();
    //TestShadowDirectory();
    //TestPsObjectSecurity();
    //TestLicenseCache();
    //TestApiSetResolve();
    //TestDesktop();
    //TestApiPort();
    //TestAlpcPortOpen();
    //TestDebugObject();
    //TestMailslot();
    //TestPartition();
    //TestPrivateNamespace();
    //TestIoCompletion();
    //TestTimer();
    //TestTransaction();
    //TestSessions();
    //TestThread();
    PreHashTypes();
    //TestJob();
}

VOID TestStop(
    VOID
)
{
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

    if (g_TestThread) {
        TerminateThread(g_TestThread, 0);
        CloseHandle(g_TestThread);
    }
    if (g_TestPortThread) {
        TerminateThread(g_TestPortThread, 0);
        CloseHandle(g_TestPortThread);
    }
    if (g_MappedSection) {
        NtUnmapViewOfSection(NtCurrentProcess(), g_MappedSection);
    }
    if (g_SectionVaTest)
        NtClose(g_SectionVaTest);
}
