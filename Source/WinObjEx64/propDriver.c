/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       PROPDRIVER.C
*
*  VERSION:     1.12
*
*  DATE:        26 May 2015
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "propDlg.h"
#include "propDriver.h"
#include "propDriverConsts.h"
#include "propObjectDump.h"

/*
* DriverShowChildWindows
*
* Purpose:
*
* Makes window controls visible/invisible 
*
*/
BOOL WINAPI DriverShowChildWindows(
	_In_  HWND hwnd,
	_In_  LPARAM lParam
	)
{
	ShowWindow(hwnd, (INT)lParam);
	return TRUE;
}

/*
* DriverSetInfo
*
* Purpose:
*
* Sets registry info for selected driver object
*
*/
VOID DriverSetInfo(
	PROP_OBJECT_INFO *Context,
	HWND hwndDlg
	)
{
	BOOL					cond = FALSE, bResult, fGroup, bRet;
	INT						nEndOfList, nEnd, nStart;
	DWORD					i, bytesNeeded, dwServices, dwGroups;
	LPWSTR					lpType;
	SC_HANDLE				SchSCManager;
	SC_HANDLE				schService;
	LPENUM_SERVICE_STATUS   lpDependencies = NULL;
	LPQUERY_SERVICE_CONFIG	psci;
	LPSERVICE_DESCRIPTION	psd;
	SERVICE_STATUS_PROCESS 	ssp;
	ENUM_SERVICE_STATUS     ess;
	WCHAR					szBuffer[MAX_PATH + 1];
	
	if (Context == NULL) {
		ShowWindow(GetDlgItem(hwndDlg, IDC_QUERYFAIL), TRUE);
		return;
	}

	__try {

		ShowWindow(GetDlgItem(hwndDlg, IDC_QUERYFAIL), FALSE);

		psci = NULL;
		SchSCManager = NULL;
		bResult = FALSE;

		do {
			SchSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
			if (SchSCManager == NULL) {
				break;
			}

			schService = OpenService(SchSCManager, Context->lpObjectName,
				SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS);
			if (schService == NULL) {
				break;
			}

			bytesNeeded = 0;
			bResult = QueryServiceConfig(schService, NULL, 0, &bytesNeeded);
			if ((bResult == FALSE) && (bytesNeeded == 0)) {
				break;
			}

			psci = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesNeeded);
			if (psci == NULL) {
				break;
			}

			//disable comboboxes
			EnableWindow(GetDlgItem(hwndDlg, IDC_SERVICE_DEPENDENTSERVICES), FALSE);
			EnableWindow(GetDlgItem(hwndDlg, IDC_SERVICE_DEPENDSONSERVICE), FALSE);
			EnableWindow(GetDlgItem(hwndDlg, IDC_SERVICE_DEPENDSONGROUP), FALSE);

			bResult = QueryServiceConfig(schService, psci, bytesNeeded, &bytesNeeded);
			if (bResult) {
				//set key name (identical to object name)
				SetDlgItemText(hwndDlg, IDC_SERVICE_KEYNAME, Context->lpObjectName);
				//set image path info
				SetDlgItemText(hwndDlg, IDC_SERVICE_IMAGEPATH, psci->lpBinaryPathName);
				//set display name
				SetDlgItemText(hwndDlg, IDC_SERVICE_DISPLAYNAME, psci->lpDisplayName);
				//set load order group
				SetDlgItemText(hwndDlg, IDC_SERVICE_LOADORDERGROUP, psci->lpLoadOrderGroup);

				//Service Type
				lpType = T_UnknownType;
				switch (psci->dwServiceType) {
				case SERVICE_KERNEL_DRIVER:
					lpType = L"Kernel-Mode Driver";
					break;
				case SERVICE_FILE_SYSTEM_DRIVER:
					lpType = L"File System Driver";
					break;
				case SERVICE_ADAPTER:
					lpType = L"Adapter";
					break;
				case SERVICE_RECOGNIZER_DRIVER:
					lpType = L"File System Recognizer";
					break;
				case SERVICE_WIN32_OWN_PROCESS:
					lpType = L"Own Process";
					break;
				case SERVICE_WIN32_SHARE_PROCESS:
					lpType = L"Share Process";
					break;
				case (SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS):
					lpType = L"Own Process (Interactive)";
					SetDlgItemText(hwndDlg, ID_SERVICE_NAME, psci->lpServiceStartName);
					break;
				case (SERVICE_WIN32_SHARE_PROCESS | SERVICE_INTERACTIVE_PROCESS):
					lpType = L"Share Process (Interactive)";
					SetDlgItemText(hwndDlg, ID_SERVICE_NAME, psci->lpServiceStartName);
					break;
				}
				SetDlgItemText(hwndDlg, ID_SERVICE_TYPE, lpType);

				//Start Type
				lpType = T_UnknownType;
				switch (psci->dwStartType) {
				case SERVICE_AUTO_START:
					lpType = L"Auto";
					break;
				case SERVICE_BOOT_START:
					lpType = L"Boot";
					break;
				case SERVICE_DEMAND_START:
					lpType = L"On Demand";
					break;
				case SERVICE_DISABLED:
					lpType = L"Disabled";
					break;
				case SERVICE_SYSTEM_START:
					lpType = L"System";
					break;
				}
				SetDlgItemText(hwndDlg, ID_SERVICE_START, lpType);

				//Error Control
				lpType = T_Unknown;
				switch (psci->dwErrorControl) {
				case SERVICE_ERROR_CRITICAL:
					lpType = L"Critical";
					break;
				case SERVICE_ERROR_IGNORE:
					lpType = L"Ignore";
					break;
				case SERVICE_ERROR_NORMAL:
					lpType = L"Normal";
					break;
				case SERVICE_ERROR_SEVERE:
					lpType = L"Severe";
					break;
				}
				SetDlgItemText(hwndDlg, ID_SERVICE_ERROR, lpType);

				//dwTagId
				if (psci->dwTagId) {
					RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
					ultostr(psci->dwTagId, szBuffer);
					SetDlgItemText(hwndDlg, ID_SERVICE_TAG, szBuffer);
				}
				else {
					//not assigned tag
					SetDlgItemText(hwndDlg, ID_SERVICE_TAG, L"");
				}

				//State
				RtlSecureZeroMemory(&ssp, sizeof(ssp));
				if (QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, 
					(LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) 
				{
					lpType = T_Unknown;
					switch (ssp.dwCurrentState) {
					case SERVICE_STOPPED:
						lpType = L"Stopped";
						break;
					case SERVICE_START_PENDING:
						lpType = L"Start Pending";
						break;
					case SERVICE_STOP_PENDING:
						lpType = L"Stop Pending";
						break;
					case SERVICE_RUNNING:
						lpType = L"Running";
						break;
					case SERVICE_CONTINUE_PENDING:
						lpType = L"Continue Pending";
						break;
					case SERVICE_PAUSE_PENDING:
						lpType = L"Pause Pending";
						break;
					case SERVICE_PAUSED:
						lpType = L"Paused";
						break;
					}
					SetDlgItemText(hwndDlg, ID_SERVICE_CURRENT, lpType);
				}
				else {
					SetDlgItemText(hwndDlg, ID_SERVICE_CURRENT, T_CannotQuery);
				}

				//Service Description
				bRet = FALSE;
				SetDlgItemText(hwndDlg, ID_SERVICE_DESCRIPTION, L"");
				bytesNeeded = 0x1000;
				psd = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesNeeded);
				if (psd) {				

					bRet = QueryServiceConfig2(schService, SERVICE_CONFIG_DESCRIPTION, 
						(LPBYTE)psd, bytesNeeded, &bytesNeeded);

					if ((bRet == FALSE) && (bytesNeeded != 0)) {
						HeapFree(GetProcessHeap(), 0, psd);
						psd = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesNeeded);
					}
					if (psd) {
						//set description or hide window
						bRet = QueryServiceConfig2(schService, SERVICE_CONFIG_DESCRIPTION, 
							(LPBYTE)psd, bytesNeeded, &bytesNeeded);

						if (bRet) {
							SetDlgItemText(hwndDlg, IDC_SERVICE_DESCRIPTION, psd->lpDescription);
						}
						HeapFree(GetProcessHeap(), 0, psd);
					}
				}
				if (bRet == FALSE) {
					//not enough memory, hide description window
					ShowWindow(GetDlgItem(hwndDlg, IDC_SERVICE_DESCRIPTION), SW_HIDE);
				}


				//Service Dependencies
				if (psci->lpDependencies) {

					//first list DependsOnService, DependsOnGroup

					nEndOfList = 0;
					nEnd = 0;
					nStart = 0;
					dwGroups = 0;
					dwServices = 0;

					//calc total number of symbols
					while ((psci->lpDependencies[nEndOfList] != L'\0') || (psci->lpDependencies[nEndOfList + 1] != L'\0'))
						nEndOfList++;

					if (nEndOfList > 0) {

						SendDlgItemMessage(hwndDlg, IDC_SERVICE_DEPENDSONGROUP, CB_RESETCONTENT, (WPARAM)0, (LPARAM)0);
						SendDlgItemMessage(hwndDlg, IDC_SERVICE_DEPENDSONSERVICE, CB_RESETCONTENT, (WPARAM)0, (LPARAM)0);

						//iterate through MULTI_SZ string
						do {
							while (psci->lpDependencies[nEnd] != L'\0') {
								nEnd++;
							}

							RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
							//maximum bytes that can be copied is sizeof(szBuffer)
							_strncpy(szBuffer, sizeof(szBuffer), &psci->lpDependencies[nStart], nEnd);

							//check if dependency is a group (has "+" before name)
							fGroup = (szBuffer[0] == SC_GROUP_IDENTIFIER);
							if (fGroup) {
								SendDlgItemMessage(hwndDlg, IDC_SERVICE_DEPENDSONGROUP, CB_ADDSTRING, 
									(WPARAM)0, (LPARAM)&szBuffer[1]);
								dwGroups++;
							}
							else {
								SendDlgItemMessage(hwndDlg, IDC_SERVICE_DEPENDSONSERVICE, CB_ADDSTRING, 
									(WPARAM)0, (LPARAM)&szBuffer);
								dwServices++;
							}
							nEnd++;
							nStart = nEnd;
						} while (nEnd < nEndOfList);

						//group present, enable combobox
						if (dwGroups > 0) {
							EnableWindow(GetDlgItem(hwndDlg, IDC_SERVICE_DEPENDSONGROUP), TRUE);
							SendDlgItemMessage(hwndDlg, IDC_SERVICE_DEPENDSONGROUP, CB_SETCURSEL, 
								(WPARAM)0, (LPARAM)0);
						}
						//service present, enable combobox
						if (dwServices > 0) {
							EnableWindow(GetDlgItem(hwndDlg, IDC_SERVICE_DEPENDSONSERVICE), TRUE);
							SendDlgItemMessage(hwndDlg, IDC_SERVICE_DEPENDSONSERVICE, CB_SETCURSEL, 
								(WPARAM)0, (LPARAM)0);
						}
					} //if (nEndOfList > 0)

					//second list services that depends on this service
					SendDlgItemMessage(hwndDlg, IDC_SERVICE_DEPENDENTSERVICES, CB_RESETCONTENT, 
						(WPARAM)0, (LPARAM)0);

					dwServices = 0;
					bytesNeeded = 1024;
					bRet = FALSE;

					//avoid SCM unexpected behaviour by using preallocated buffer
					lpDependencies = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesNeeded);
					if (lpDependencies) {
						bRet = EnumDependentServices(schService, SERVICE_STATE_ALL, lpDependencies, 
							bytesNeeded, &bytesNeeded, &dwServices);

						if (bRet && (GetLastError() == ERROR_MORE_DATA)) {
							//more memory needed for enum
							HeapFree(GetProcessHeap(), 0, lpDependencies);
							dwServices = 0;
							lpDependencies = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesNeeded);
							if (lpDependencies) {
								bRet = EnumDependentServices(schService, SERVICE_STATE_ALL,
									lpDependencies, bytesNeeded, &bytesNeeded,
									&dwServices);
							}
						}
						//list dependents
						if (bRet && dwServices) {
							for (i = 0; i < dwServices; i++) {
								ess = *(lpDependencies + i);
								SendDlgItemMessage(hwndDlg, IDC_SERVICE_DEPENDENTSERVICES, CB_ADDSTRING, 
									(WPARAM)0, (LPARAM)ess.lpServiceName);
							}
							//enable combobox and set current selection to the first item
							EnableWindow(GetDlgItem(hwndDlg, IDC_SERVICE_DEPENDENTSERVICES), TRUE);
							SendDlgItemMessage(hwndDlg, IDC_SERVICE_DEPENDENTSERVICES, CB_SETCURSEL, 
								(WPARAM)0, (LPARAM)0);
						}
						HeapFree(GetProcessHeap(), 0, lpDependencies);
					}
				} //if (psi->lpDependencies)
			} //bResult != FALSE

			CloseServiceHandle(schService);
		} while (cond);

		if (psci != NULL) {
			HeapFree(GetProcessHeap(), 0, psci);
		}

		if (SchSCManager) {
			CloseServiceHandle(SchSCManager);
		}

		if (bResult == FALSE) {
			EnumChildWindows(hwndDlg, DriverShowChildWindows, SW_HIDE);
			ShowWindow(GetDlgItem(hwndDlg, IDC_QUERYFAIL), SW_SHOW);
		}
		else {
			SetFocus(GetDlgItem(hwndDlg, ID_SERVICE_JUMPTOKEY));
		}

	}
	__except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
		EnumChildWindows(hwndDlg, DriverShowChildWindows, SW_HIDE);
		ShowWindow(GetDlgItem(hwndDlg, IDC_QUERYFAIL), SW_SHOW);
		return;
	}
}

/*
* DriverJumpToKey
*
* Purpose:
*
* JumpToKey button handler.
*
*/
VOID DriverJumpToKey(
	PROP_OBJECT_INFO *Context
	)
{
	BOOL				cond = FALSE;
	DWORD				dwProcessId;
	WCHAR				*ch, *ckey;
	HWND				regeditHwnd, regeditMainHwnd;
	SIZE_T				sz;
	LPWSTR				lpRegPath;
	HANDLE				hRegeditProcess; 
	SHELLEXECUTEINFO	seinfo;


	if (Context == NULL) {
		return;
	}

	hRegeditProcess = NULL;
	lpRegPath = NULL;

	do {

		//create regkeypath buffer to navigate for
		sz = (_strlen(Context->lpObjectName) * sizeof(WCHAR)) +
			(_strlen(REGISTRYSERVICESKEY) * sizeof(WCHAR)) +
			sizeof(UNICODE_NULL);

		lpRegPath = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
		if (lpRegPath == NULL) {
			break;
		}
		wsprintf(lpRegPath, REGISTRYSERVICESKEY, Context->lpObjectName);

		regeditHwnd = NULL;

		//open RegEdit
		regeditMainHwnd = FindWindow(REGEDITWNDCLASS, NULL);
		if (regeditMainHwnd == NULL)  {
			RtlSecureZeroMemory(&seinfo, sizeof(seinfo));
			seinfo.cbSize = sizeof(seinfo);
			seinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
			seinfo.lpVerb = L"open";
			seinfo.lpFile = L"regedit.exe";
			seinfo.nShow = SW_SHOWNORMAL;
			ShellExecuteEx(&seinfo);
			hRegeditProcess = seinfo.hProcess;
			if (hRegeditProcess == NULL) {
				break;
			}
			WaitForInputIdle(hRegeditProcess, 10000);
			regeditMainHwnd = FindWindow(REGEDITWNDCLASS, NULL);
		}
		else {
			//open regedit process for sync
			dwProcessId = 0;
			GetWindowThreadProcessId(regeditMainHwnd, &dwProcessId);
			hRegeditProcess = OpenProcess(SYNCHRONIZE, FALSE, dwProcessId);
		}
		//check if we failed to launch regedit
		if ((hRegeditProcess == NULL) || (regeditMainHwnd == NULL)) {
			break;
		}

		//restore regedit window
		if (IsIconic(regeditMainHwnd)) {
			ShowWindow(regeditMainHwnd, SW_RESTORE);
		}
		else {
			ShowWindow(regeditMainHwnd, SW_SHOW);
		}
		SetForegroundWindow(regeditMainHwnd);
		SetFocus(regeditMainHwnd);
		WaitForInputIdle(hRegeditProcess, 10000);

		//get treeview
		regeditHwnd = FindWindowEx(regeditMainHwnd, NULL, WC_TREEVIEW, NULL);
		if (regeditHwnd == NULL) {
			break;
		}

		//set focus on treeview
		SetForegroundWindow(regeditHwnd);
		SetFocus(regeditHwnd);

		//go to the tree root 
		SendMessage(regeditHwnd, WM_KEYDOWN, VK_HOME, 0);

		//open path
		for (ch = lpRegPath; *ch; ++ch)  {
			//expand if needed
			if (*ch == L'\\')  {
				SendMessage(regeditHwnd, WM_KEYDOWN, VK_RIGHT, 0);
				WaitForInputIdle(hRegeditProcess, 1000);
			}
			else {
				//select item
				ckey = (WCHAR*)CharUpper((LPWSTR)(UINT)*ch);
				SendMessage(regeditHwnd, WM_CHAR, (WPARAM)ckey, (LPARAM)0);
				WaitForInputIdle(hRegeditProcess, 1000);
			}
		}

		SetForegroundWindow(regeditMainHwnd);
		SetFocus(regeditMainHwnd);

	} while (cond);

	if (lpRegPath) {
		HeapFree(GetProcessHeap(), 0, lpRegPath);
	}
	if (hRegeditProcess) {
		CloseHandle(hRegeditProcess);
	}
}

/*
* DriverRegistryDialogProc
*
* Purpose:
*
* Registry page for Driver object
*
*/
INT_PTR CALLBACK DriverRegistryDialogProc(
	_In_  HWND hwndDlg,
	_In_  UINT uMsg,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
	)
{
	PROPSHEETPAGE *pSheet = NULL;
	PROP_OBJECT_INFO *Context = NULL;

	switch (uMsg) {

	case WM_SHOWWINDOW:
		if (wParam) {
			Context = GetProp(hwndDlg, T_PROPCONTEXT);
			DriverSetInfo(Context, hwndDlg);
		}
		return 1;
		break;

	case WM_INITDIALOG:
		pSheet = (PROPSHEETPAGE *)lParam;
		if (pSheet) {
			SetProp(hwndDlg, T_PROPCONTEXT, (HANDLE)pSheet->lParam);
		}
		return 1;
		break;

	case WM_COMMAND:
		if (LOWORD(wParam) == ID_SERVICE_JUMPTOKEY) {
			Context = GetProp(hwndDlg, T_PROPCONTEXT);
			DriverJumpToKey(Context);
		}
		return 1;
		break;

	case WM_DESTROY:
		RemoveProp(hwndDlg, T_PROPCONTEXT);
		break;

	}
	return 0;
}
