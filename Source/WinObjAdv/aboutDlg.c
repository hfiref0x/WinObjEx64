/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 
*
*  TITLE:       ABOUTDLG.C
*
*  VERSION:     1.11
*
*  DATE:        10 Mar 2015
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

#define T_SECUREBOOTSTATEKEY	L"System\\CurrentControlSet\\Control\\SecureBoot\\State"
#define T_SECUREBOOTSTATEVALUE	L"UEFISecureBootEnabled"

/*
* AboutDialogQuerySecureBootState
*
* Purpose:
*
* Query Firmware type and SecureBoot state if firmware is EFI.
*
*/
BOOL AboutDialogQuerySecureBootState(
	_In_ PBOOLEAN pbSecureBoot
	)
{
	BOOL cond = FALSE, bResult = FALSE;
	BOOLEAN bSecureBoot = FALSE;
	HKEY hKey;
	DWORD dwState, dwSize, returnLength;
	LRESULT lRet;

	//first attempt, query firmware environment variable, will not work if not fulladmin
	do {
		if (!supEnablePrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, TRUE))
			break;

		bSecureBoot = FALSE;
		returnLength = GetFirmwareEnvironmentVariable(L"SecureBoot", 
			L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}", &bSecureBoot, sizeof(BOOLEAN));
		supEnablePrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, FALSE);
		if (returnLength != 0) {
			if (pbSecureBoot) {
				*pbSecureBoot = bSecureBoot;
			}
			bResult = TRUE;
		}

	} while (cond);

	if (bResult) {
		return bResult;
	}

	//second attempt, query state from registry
	do {
		lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, T_SECUREBOOTSTATEKEY, 0, KEY_QUERY_VALUE, &hKey);
		if (lRet != ERROR_SUCCESS)
			break;

		dwState = 0;
		dwSize = sizeof(DWORD);
		lRet = RegQueryValueExW(hKey, T_SECUREBOOTSTATEVALUE, NULL, NULL, (LPBYTE)&dwState, &dwSize);
		if (lRet != ERROR_SUCCESS)
			break;

		if (pbSecureBoot) {
			*pbSecureBoot = (dwState == 1);
		}
		bResult = TRUE;

		RegCloseKey(hKey);

	} while (cond);

	return bResult;
}

/*
* AboutDialogInit
*
* Purpose:
*
* Displays program version and system information
*
*/
VOID AboutDialogInit(
	HWND hwndDlg
	)
{
	NTSTATUS status;
	WCHAR buf[MAX_PATH];
	BOOLEAN bSecureBoot = FALSE;
	ULONG returnLength;
	SYSTEM_BOOT_ENVIRONMENT_INFORMATION sbei;
	HANDLE hImage;

	SetDlgItemText(hwndDlg, ID_ABOUT_PROGRAM, PROFRAM_NAME_AND_TITLE);
	SetDlgItemText(hwndDlg, ID_ABOUT_BUILDINFO, PROGRAM_VERSION);

	hImage = LoadImage(g_hInstance, MAKEINTRESOURCE(IDI_ICON_MAIN), IMAGE_ICON, 48, 48, LR_SHARED);
	if (hImage) {
		SendMessage(GetDlgItem(hwndDlg, ID_ABOUT_ICON), STM_SETIMAGE, IMAGE_ICON, (LPARAM)hImage);
		DestroyIcon(hImage);
	}

	//remove class icon if any
	SetClassLongPtr(hwndDlg, GCLP_HICON, (LONG_PTR)NULL);

	RtlSecureZeroMemory(buf, sizeof(buf));
#if (_MSC_VER == 1800) //2013
#if (_MSC_FULL_VER == 180031101)
	_strcpy(buf, L"MSVC 2013 Update 4");
#elif (_MSC_FULL_VER == 180030723)
	_strcpy(buf, L"MSVC 2013 Update 3");
#elif (_MSC_FULL_VER == 180030501)
	_strcpy(buf, L"MSVC 2013 Update 2");
#elif (_MSC_FULL_VER < 180021005)
	_strcpy(buf, L"MSVC 2013 Preview/Beta/RC");
#else
	_strcpy(buf, L"MSVC 2013");
#endif
#else
	_strcpy(buf, L"Unknown Compiler");
#endif
	SetDlgItemText(hwndDlg, ID_ABOUT_COMPILERINFO, buf);

	RtlSecureZeroMemory(buf, sizeof(buf));
	MultiByteToWideChar(CP_ACP, 0, __DATE__, (INT)_strlen_a(__DATE__), _strend(buf), 40);
	_strcat(buf, TEXT(" "));
	MultiByteToWideChar(CP_ACP, 0, __TIME__, (INT)_strlen_a(__TIME__), _strend(buf), 40);
	SetDlgItemText(hwndDlg, ID_ABOUT_BUILDDATE, buf);

	// fill OS name
	wsprintfW(buf, L"Windows NT %1u.%1u (build %u",
		g_kdctx.osver.dwMajorVersion, g_kdctx.osver.dwMinorVersion, g_kdctx.osver.dwBuildNumber);
	if (g_kdctx.osver.szCSDVersion[0]) {
		wsprintfW(_strend(buf), L", %ws)", g_kdctx.osver.szCSDVersion);
	}
	else {
		_strcat(buf, L")");
	}
	SetDlgItemText(hwndDlg, ID_ABOUT_OSNAME, buf);

	// fill boot options
	RtlSecureZeroMemory(&buf, sizeof(buf));
	RtlSecureZeroMemory(&sbei, sizeof(sbei));
	status = NtQuerySystemInformation(SystemBootEnvironmentInformation, &sbei, sizeof(sbei), &returnLength);
	if (NT_SUCCESS(status)) {

		wsprintfW(buf, L"%ws mode",
			((sbei.FirmwareType == FirmwareTypeUefi) ? L"UEFI" : ((sbei.FirmwareType == FirmwareTypeBios) ? L"BIOS" : L"Unknown")));
	
		if (sbei.FirmwareType == FirmwareTypeUefi) {
			bSecureBoot = FALSE;
			if (AboutDialogQuerySecureBootState(&bSecureBoot)) {
				wsprintfW(_strend(buf), L" with%ws SecureBoot", (bSecureBoot == TRUE) ? L"" : L"out");
			}
		}
	}
	SetDlgItemText(hwndDlg, ID_ABOUT_ADVINFO, buf);

	SetFocus(GetDlgItem(hwndDlg, IDOK));
}

/*
* AboutDialogProc
*
* Purpose:
*
* About Dialog Window Dialog Procedure
*
* During WM_INITDIALOG centers window and initializes system info
*
*/
LRESULT CALLBACK AboutDialogProc(
	HWND hwndDlg,
	UINT uMsg,
	WPARAM wParam,
	LPARAM lParam
	)
{
	UNREFERENCED_PARAMETER(lParam);

	switch (uMsg) {

	case WM_INITDIALOG:
		supCenterWindow(hwndDlg);
		AboutDialogInit(hwndDlg);
		break;

	case WM_COMMAND:
		if ((LOWORD(wParam) == IDOK) || (LOWORD(wParam) == IDCANCEL))
			EndDialog(hwndDlg, S_OK);
		break;

	default:
		break;
	}
	return 0;
}
