/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       TESTUNIT.C
*
*  VERSION:     1.31
*
*  DATE:        11 Nov 2015
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
#include "testunit.h"
#include <Sddl.h>

HANDLE g_TestIoCompletion = NULL, g_TestTransaction = NULL;
HANDLE g_TestNamespace = NULL, g_TestMutex = NULL;

VOID TestIoCompletion(
	VOID
	)
{
	OBJECT_ATTRIBUTES obja;
	UNICODE_STRING ustr;
	//IoCompletion
	RtlInitUnicodeString(&ustr, L"\\BaseNamedObjects\\TestCompletion");
	InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NtCreateIoCompletion(&g_TestIoCompletion, IO_COMPLETION_ALL_ACCESS, &obja, 100);
}


VOID TestTimer(
	VOID
	)
{
	HANDLE hTimer = NULL;
	LARGE_INTEGER liDueTime;

	liDueTime.QuadPart = -1000000000000LL;

	hTimer = CreateWaitableTimer(NULL, TRUE, L"TestTimer");
	SetWaitableTimer(hTimer, &liDueTime, 0, NULL, NULL, 0);
}

VOID TestTransaction(
	VOID
	)
{

	OBJECT_ATTRIBUTES obja;
	UNICODE_STRING ustr;
	//TmTx
	RtlInitUnicodeString(&ustr, L"\\BaseNamedObjects\\TestTransaction");
	InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NtCreateTransaction(&g_TestTransaction, TRANSACTION_ALL_ACCESS, &obja, NULL, NULL, 0, 0, 0, NULL, NULL);
}

VOID TestPrivateNamespace(
	VOID
	)
{
	HANDLE hBoundaryDescriptor = NULL;
	BOOL cond = FALSE;
	SECURITY_ATTRIBUTES sa;

	BYTE localAdminSID[SECURITY_MAX_SID_SIZE];
	PSID pLocalAdminSID = &localAdminSID;
	DWORD cbSID = sizeof(localAdminSID);
	CHAR text[1000];

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

VOID TestStart(
	VOID
	)
{
	TestPrivateNamespace();
	TestIoCompletion();
	TestTimer();
	TestTransaction();
}

VOID TestStop(
	VOID
	)
{
	if (g_TestIoCompletion) NtClose(g_TestIoCompletion);
	if (g_TestTransaction) NtClose(g_TestTransaction);

	if (g_TestMutex != NULL) {
		CloseHandle(g_TestMutex);
	}
	if (g_TestNamespace != NULL) {
		ClosePrivateNamespace(g_TestNamespace, PRIVATE_NAMESPACE_FLAG_DESTROY);
	}
}

