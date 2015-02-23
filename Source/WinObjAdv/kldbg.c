/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       KLDBG.C, based on KDSubmarine by Evilcry
*
*  VERSION:     1.00
*
*  DATE:        22 Feb 2015 
*
*  MINIMUM SUPPORTED OS WINDOWS 7
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include <Shlwapi.h>

//include for PathExists API
#pragma comment(lib, "shlwapi.lib")

//number of buckets in the object directory
#define NUMBEROFBUCKETS 0x25

/*
* ObGetObjectHeaderOffset
*
* Purpose:
*
* Query requested structure offset for the given mask
*
*
* Object In Memory Disposition
*
* POOL_HEADER
* OBJECT_HEADER_PROCESS_INFO
* OBJECT_HEADER_QUOTA_INFO
* OBJECT_HEADER_HANDLE_INFO
* OBJECT_HEADER_NAME_INFO
* OBJECT_HEADER_CREATOR_INFO
* OBJECT_HEADER
*
*/
BYTE ObGetObjectHeaderOffset(
	BYTE InfoMask, 
	OBJ_HEADER_INFO_FLAG Flag
	)
{
	BYTE OffsetMask, HeaderOffset = 0;

	if ((InfoMask & Flag) == 0)
		return 0;

	OffsetMask = InfoMask & (Flag | (Flag - 1));

	if ((OffsetMask & HeaderCreatorInfoFlag) != 0)
		HeaderOffset += (BYTE)sizeof(OBJECT_HEADER_CREATOR_INFO);

	if ((OffsetMask & HeaderNameInfoFlag) != 0)
		HeaderOffset += (BYTE)sizeof(OBJECT_HEADER_NAME_INFO);

	if ((OffsetMask & HeaderHandleInfoFlag) != 0)
		HeaderOffset += (BYTE)sizeof(OBJECT_HEADER_HANDLE_INFO);

	if ((OffsetMask & HeaderQuotaInfoFlag) != 0)
		HeaderOffset += (BYTE)sizeof(OBJECT_HEADER_QUOTA_INFO);

	if ((OffsetMask & HeaderProcessInfoFlag) != 0)
		HeaderOffset += (BYTE)sizeof(OBJECT_HEADER_PROCESS_INFO);

	return HeaderOffset;
}

/*
* ObHeaderToNameInfoAddress
*
* Purpose:
*
* Calculate address of name structure from object header flags and object address
*
*/
BOOL ObHeaderToNameInfoAddress(
	_In_ UCHAR ObjectInfoMask, 
	_In_ ULONG_PTR ObjectAddress,
	_Inout_ PULONG_PTR HeaderAddress,
	_In_ OBJ_HEADER_INFO_FLAG InfoFlag
	)
{
	ULONG_PTR Address;
	BYTE HeaderOffset;
	
	if (HeaderAddress == NULL)
		return FALSE;

	if (ObjectAddress < g_kdctx.SystemRangeStart)
		return FALSE;

	HeaderOffset = ObGetObjectHeaderOffset(ObjectInfoMask, InfoFlag);
	if (HeaderOffset == 0)
		return FALSE;

	Address = ObjectAddress - HeaderOffset;
	if (Address < g_kdctx.SystemRangeStart)
		return FALSE;
	
	*HeaderAddress = Address;
	return TRUE;
}

/*
* ObGetDirectoryObjectAddress
*
* Purpose:
*
* Obtain directory object kernel address by opening directory by name 
* and quering resulted handle in NtQuerySystemInformation(SystemHandleInformation) handle dump
*
*/
BOOL ObGetDirectoryObjectAddress(
	_In_opt_ LPWSTR lpDirectory,
	_Inout_ PULONG_PTR lpRootAddress,
	_Inout_opt_ PUCHAR lpTypeIndex
	)
{
	OBJECT_ATTRIBUTES	objattr;
	UNICODE_STRING		objname;
	HANDLE				hDirectory = NULL;
	NTSTATUS			status;
	BOOL				bFound = FALSE;
	LPWSTR				lpTarget;

	if (lpRootAddress == NULL)
		return bFound;

	if (lpDirectory == NULL) {
		lpTarget = L"\\";
	}
	else {
		lpTarget = lpDirectory;
	}
	RtlSecureZeroMemory(&objname, sizeof(objname));
	RtlInitUnicodeString(&objname, lpTarget);
	InitializeObjectAttributes(&objattr, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = NtOpenDirectoryObject(&hDirectory, FILE_LIST_DIRECTORY, &objattr);
	if (!NT_SUCCESS(status))
		return bFound;
	
	bFound = supQueryObjectFromHandle(hDirectory, lpRootAddress, lpTypeIndex);
	NtClose(hDirectory);
	return bFound;
}

/*
* ObQueryNameString
*
* Purpose:
*
* Reads object name from kernel memory
*
*/
LPWSTR ObQueryNameString(
	ULONG_PTR NameInfoAddress,
	PSIZE_T ReturnLength
	)
{
	ULONG fLen;
	LPWSTR lpObjectName;
	OBJECT_HEADER_NAME_INFO NameInfo;

	RtlSecureZeroMemory(&NameInfo, sizeof(OBJECT_HEADER_NAME_INFO));
	if (!kdReadSystemMemory(NameInfoAddress, &NameInfo, sizeof(OBJECT_HEADER_NAME_INFO)))
		return NULL;

	fLen = NameInfo.Name.Length + sizeof(UNICODE_NULL);
	lpObjectName = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fLen);
	if (lpObjectName == NULL)
		return NULL;

	NameInfoAddress = (ULONG_PTR)NameInfo.Name.Buffer;
	if (!kdReadSystemMemory(NameInfoAddress, lpObjectName, NameInfo.Name.Length)) {
		if (ReturnLength) {
			*ReturnLength = 0;
		}
		HeapFree(GetProcessHeap(), 0, lpObjectName);
		return NULL;
	}
	if (ReturnLength) {
		*ReturnLength = fLen;
	}
	return lpObjectName;
}

/*
* ObWalkDirectory
*
* Purpose:
*
* Walks given directory and looks for specified object inside
* Returned object must be freed wtih HeapFree when no longer needed.
*
*/
POBJINFO ObWalkDirectory(
	_In_ LPWSTR lpObjectToFind,
	_In_ ULONG_PTR DirectoryAddress
	)
{
	POBJINFO lpData;
	LPWSTR lpObjectName;

	OBJECT_HEADER ObjectHeader;
	OBJECT_DIRECTORY DirObject;
	OBJECT_DIRECTORY_ENTRY Entry;
	ULONG_PTR ObjectHeaderAddress, item0, item1, InfoHeaderAddress;

	BOOL bFound;

	INT c;
	SIZE_T retSize;

	__try {


		if (lpObjectToFind == NULL)
			return NULL;

		RtlSecureZeroMemory(&DirObject, sizeof(OBJECT_DIRECTORY));
		if (!kdReadSystemMemory(DirectoryAddress, &DirObject, sizeof(OBJECT_DIRECTORY))) {

#ifdef _DEBUG
			OutputDebugStringW(L"kdReadSystemMemory(DirectoryAddress) failed");
#endif
			return NULL;
		}

		lpObjectName = NULL;
		retSize = 0;
		bFound = FALSE;
		lpData = NULL;

		//check if root special case
		if (_strcmpiW(lpObjectToFind, L"\\") == 0) {

			//read object header
			RtlSecureZeroMemory(&ObjectHeader, sizeof(OBJECT_HEADER));
			ObjectHeaderAddress = (ULONG_PTR)OBJECT_TO_OBJECT_HEADER(DirectoryAddress);
			if (!kdReadSystemMemory(ObjectHeaderAddress, &ObjectHeader, sizeof(OBJECT_HEADER))) {

#ifdef _DEBUG
				OutputDebugStringW(L"kdReadSystemMemory(ObjectHeaderAddress) failed");
#endif

				return NULL;
			}

			lpData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(OBJINFO));
			if (lpData == NULL)
				return NULL;

			lpData->ObjectAddress = DirectoryAddress;
			lpData->HeaderAddress = ObjectHeaderAddress;

			//copy object header
			supCopyMemory(&lpData->ObjectHeader, sizeof(lpData->ObjectHeader), &ObjectHeader, sizeof(OBJECT_HEADER));

			//query and copy quota info
			InfoHeaderAddress = 0;
			if (ObHeaderToNameInfoAddress(ObjectHeader.InfoMask, ObjectHeaderAddress, &InfoHeaderAddress, HeaderQuotaInfoFlag)) {
				kdReadSystemMemory(ObjectHeaderAddress, &lpData->ObjectQuotaHeader, sizeof(OBJECT_HEADER_QUOTA_INFO));
			}
			return lpData;
		}

		//otherwise scan given object directory
		for (c = 0; c < NUMBEROFBUCKETS; c++) {

			item0 = (ULONG_PTR)DirObject.HashBuckets[c];
			if (item0 != 0) {

				item1 = item0;
				do {
					//read object directory entry
					RtlSecureZeroMemory(&Entry, sizeof(OBJECT_DIRECTORY_ENTRY));
					if (!kdReadSystemMemory(item1, &Entry, sizeof(OBJECT_DIRECTORY_ENTRY))) {

#ifdef _DEBUG
						OutputDebugStringW(L"kdReadSystemMemory(OBJECT_DIRECTORY_ENTRY) failed");
#endif
						break;
					}

					//read object header
					RtlSecureZeroMemory(&ObjectHeader, sizeof(OBJECT_HEADER));
					ObjectHeaderAddress = (ULONG_PTR)OBJECT_TO_OBJECT_HEADER(Entry.Object);
					if (!kdReadSystemMemory(ObjectHeaderAddress, &ObjectHeader, sizeof(OBJECT_HEADER))) {

#ifdef _DEBUG
						OutputDebugStringW(L"kdReadSystemMemory(ObjectHeaderAddress) failed");
#endif
						goto NextItem;
					}

					//check if object has name
					InfoHeaderAddress = 0;
					retSize = 0;
					if (!ObHeaderToNameInfoAddress(ObjectHeader.InfoMask, ObjectHeaderAddress, &InfoHeaderAddress, HeaderNameInfoFlag)) {
						goto NextItem;
					}

					//object has name, query it
					lpObjectName = ObQueryNameString(InfoHeaderAddress, &retSize);
					if ((lpObjectName == NULL) || (retSize == 0))
						goto NextItem;

					//compare full object names
					bFound = (_strcmpiW(lpObjectName, lpObjectToFind) == 0);
					HeapFree(GetProcessHeap(), 0, lpObjectName);
					if (bFound != TRUE) {
						goto NextItem;
					}
					//identical, allocate item info and copy it
					lpData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(OBJINFO));
					if (lpData) {

						lpData->ObjectAddress = (ULONG_PTR)Entry.Object;
						lpData->HeaderAddress = ObjectHeaderAddress;

						//copy object header
						supCopyMemory(&lpData->ObjectHeader, sizeof(OBJECT_HEADER), &ObjectHeader, sizeof(OBJECT_HEADER));
						//query and copy quota info
						InfoHeaderAddress = 0;
						if (ObHeaderToNameInfoAddress(ObjectHeader.InfoMask, ObjectHeaderAddress, &InfoHeaderAddress, HeaderQuotaInfoFlag)) {
							kdReadSystemMemory(InfoHeaderAddress, &lpData->ObjectQuotaHeader, sizeof(OBJECT_HEADER_QUOTA_INFO));
						}
					}

				NextItem:
					if (bFound)
						break;

					item1 = (ULONG_PTR)Entry.ChainLink;
				} while (item1 != 0);
			}
			if (bFound)
				break;
		}

	}
	__except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
		return NULL;
	}
	return lpData;
}


/*
* ObQueryObject
* 
* Purpose:
*
* Look for object inside specified directory
* If object is directory look for it in upper directory
* Returned object must be freed with HeapFree when no longer needed.
*
*/
POBJINFO ObQueryObject(
	_In_ LPWSTR lpDirectory,
	_In_ LPWSTR lpObjectName
	)
{
	ULONG_PTR DirectoryAddress;
	SIZE_T i, l, rdirLen, ldirSz;
	LPWSTR SingleDirName, LookupDirName;
	BOOL needFree = FALSE;
	
	if (
		(lpObjectName == NULL) ||
		(lpDirectory == NULL) ||
		(g_kdctx.hDevice == NULL)

		)
	{
		return NULL;
	}

	__try {

		LookupDirName = lpDirectory;

		//
		// 1) Check if object is directory self
		// Extract directory name and compare (case insensitive) with object name
		// Else go to 3
		//
		l = 0;
		rdirLen = _strlenW(lpDirectory);
		for (i = 0; i < rdirLen; i++) {
			if (lpDirectory[i] == '\\')
				l = i + 1;
		}
		SingleDirName = &lpDirectory[l];
		if (_strcmpiW(SingleDirName, lpObjectName) == 0) {
			//
			//  2) If we are looking for directory itself, move search directory up
			//  e.g. lpDirectory = \ObjectTypes, lpObjectName = ObjectTypes then lpDirectory = \ 
			//
			ldirSz = rdirLen * sizeof(WCHAR) + sizeof(UNICODE_NULL);
			LookupDirName = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ldirSz);
			if (LookupDirName == NULL)
				return NULL;

			needFree = TRUE;

			//special case for root 
			if (l == 1) l++;

			supCopyMemory(LookupDirName, ldirSz, lpDirectory, (l - 1) * sizeof(WCHAR));
		}
		
		//
		// 3) Get Directory address where we will look for object
		//
		DirectoryAddress = 0;
		if (ObGetDirectoryObjectAddress(LookupDirName, &DirectoryAddress, NULL)) {

			if (needFree)
				HeapFree(GetProcessHeap(), 0, LookupDirName);

			//
			// 4) Find object in directory by name (case insensitive)
			//
			return ObWalkDirectory(lpObjectName, DirectoryAddress);
		}
	}

	__except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
		return NULL;
	}
	return NULL;
}

/*
* ObDumpTypeInfo
*
* Purpose:
*
* Dumps Type header including initializer
*
*/
BOOL ObDumpTypeInfo(
	_In_ ULONG_PTR ObjectAddress,
	_Inout_ POBJECT_TYPE_COMPATIBLE ObjectTypeInfo
	)
{
	return kdReadSystemMemory(ObjectAddress, ObjectTypeInfo, sizeof(OBJECT_TYPE_COMPATIBLE));
}

/*
* ObWalkDirectoryRecursiveEx
*
* Purpose:
*
* Recursively dump Object Manager directories
*
*/
VOID ObWalkDirectoryRecursiveEx(
	BOOL fIsRoot,
	PLIST_ENTRY ListHead,
	LPWSTR lpRootDirectory,
	ULONG_PTR DirectoryAddress,
	UCHAR DirectoryTypeIndex
	)
{

	POBJREF lpListEntry;
	LPWSTR lpObjectName, lpDirectoryName;

	OBJECT_HEADER ObjectHeader;
	OBJECT_DIRECTORY DirObject;
	OBJECT_DIRECTORY_ENTRY Entry;
	ULONG_PTR ObjectHeaderAddress, item0, item1, InfoHeaderAddress;

	INT c;
	SIZE_T dirLen, fLen, rdirLen, retSize;

	RtlSecureZeroMemory(&DirObject, sizeof(OBJECT_DIRECTORY));
	if (!kdReadSystemMemory(DirectoryAddress, &DirObject, sizeof(OBJECT_DIRECTORY)))
		return;

	if (lpRootDirectory != NULL) {
		rdirLen = _strlenW(lpRootDirectory) * sizeof(WCHAR);
	}
	else {
		rdirLen = 0;
	}

	lpObjectName = NULL;
	retSize = 0;

	for (c = 0; c < NUMBEROFBUCKETS; c++) {

		item0 = (ULONG_PTR)DirObject.HashBuckets[c];
		if (item0 != 0) {
			item1 = item0;
			do {
				//read object directory entry
				RtlSecureZeroMemory(&Entry, sizeof(OBJECT_DIRECTORY_ENTRY));
				if (kdReadSystemMemory(item1, &Entry, sizeof(OBJECT_DIRECTORY_ENTRY))) {

					/*
					** Read object
					** First read header from directory entry object
					*/
					RtlSecureZeroMemory(&ObjectHeader, sizeof(OBJECT_HEADER));
					ObjectHeaderAddress = (ULONG_PTR)OBJECT_TO_OBJECT_HEADER(Entry.Object);
					if (kdReadSystemMemory(ObjectHeaderAddress, &ObjectHeader, sizeof(OBJECT_HEADER))) {

						/*
						** Second read object data
						*/
						//query name
						InfoHeaderAddress = 0;
						retSize = 0;
						if (ObHeaderToNameInfoAddress(ObjectHeader.InfoMask, ObjectHeaderAddress, &InfoHeaderAddress, HeaderNameInfoFlag)) {
							lpObjectName = ObQueryNameString(InfoHeaderAddress, &retSize);
						}

						//allocate list entry
						lpListEntry = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(OBJINFO));
						if (lpListEntry) {

							//save object address
							lpListEntry->ObjectAddress = (ULONG_PTR)Entry.Object;
							lpListEntry->HeaderAddress = ObjectHeaderAddress;

							//copy dir + name
							if (lpObjectName) {

								fLen = (_strlenW(lpObjectName) * sizeof(WCHAR)) +
									(2 * sizeof(WCHAR)) +
									rdirLen + sizeof(UNICODE_NULL);

								lpListEntry->ObjectName = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fLen);
								if (lpListEntry->ObjectName) {
									_strcpyW(lpListEntry->ObjectName, lpRootDirectory);
									if (fIsRoot != TRUE) {
										_strcatW(lpListEntry->ObjectName, L"\\");
									}
									_strcatW(lpListEntry->ObjectName, lpObjectName);
								}
							}

							InsertHeadList(ListHead, &lpListEntry->ListEntry);
						}

						//current object is directory
						if (ObjectHeader.TypeIndex == DirectoryTypeIndex) {

							/*
							** Build new directory string (old directory + \ + current)
							*/
							fLen = 0;
							if (lpObjectName) {
								fLen = retSize;
							}

							dirLen = fLen + rdirLen + (2 * sizeof(WCHAR)) + sizeof(UNICODE_NULL);
							lpDirectoryName = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dirLen);
							if (lpDirectoryName) {
								_strcpyW(lpDirectoryName, lpRootDirectory);
								if (fIsRoot != TRUE) {
									_strcatW(lpDirectoryName, L"\\");
								}
								if (lpObjectName) {
									_strcatW(lpDirectoryName, lpObjectName);
								}
							}

							ObWalkDirectoryRecursiveEx(FALSE, ListHead, lpDirectoryName, (ULONG_PTR)Entry.Object, DirectoryTypeIndex);

							if (lpDirectoryName) {
								HeapFree(GetProcessHeap(), 0, lpDirectoryName);
								lpDirectoryName = NULL;
							}
						}

						if (lpObjectName) {
							HeapFree(GetProcessHeap(), 0, lpObjectName);
							lpObjectName = NULL;
						}

					} //if (kdReadSystemMemory(ObjectHeaderAddress, &ObjectHeader, sizeof(OBJECT_HEADER)))

					item1 = (ULONG_PTR)Entry.ChainLink;

				} //if (kdReadSystemMemory(item1, &Entry, sizeof(OBJECT_DIRECTORY_ENTRY)))			
				else {
					item1 = 0;
				}
			} while (item1 != 0);
		}
	}
}

/*
* ObListCreate
*
* Purpose:
*
* Create list with object directory dumped info
*
* List must be destroyed with ObListDestroy after use.
*
*/
BOOL ObListCreate(
	_Inout_ PLIST_ENTRY ListHead
	)
{
	BOOL bResult;
	ULONG_PTR DirectoryRootAddress;
	UCHAR DirectoryTypeIndex;

	bResult = FALSE;
	if (g_kdctx.hDevice == NULL) {
		return bResult;
	}

	if (ListHead == NULL) {
		return bResult;
	}

	EnterCriticalSection(&g_kdctx.ListLock);

	__try {

		DirectoryTypeIndex = 0;
		DirectoryRootAddress = 0;
		if (ObGetDirectoryObjectAddress(NULL, &DirectoryRootAddress, &DirectoryTypeIndex)) {
			InitializeListHead(ListHead);
			ObWalkDirectoryRecursiveEx(TRUE, ListHead, L"\\", DirectoryRootAddress, DirectoryTypeIndex);
			bResult = TRUE;
		}

	}
	__except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
		bResult = FALSE;
	}

	LeaveCriticalSection(&g_kdctx.ListLock);

	return bResult;
}

/*
* ObListDestroy
*
* Purpose:
*
* Destroy list with object directory dumped info
*
*/
VOID ObListDestroy(
	_In_ PLIST_ENTRY ListHead
	)
{
	POBJREF ObjectEntry;

	if (ListHead == NULL)
		return;

	EnterCriticalSection(&g_kdctx.ListLock);

	while (!IsListEmpty(ListHead)) {
		if (ListHead->Flink == NULL)
			break;

		ObjectEntry = CONTAINING_RECORD(ListHead->Flink, OBJREF, ListEntry);
		RemoveEntryList(ListHead->Flink);
		if (ObjectEntry) {
			if (ObjectEntry->ObjectName) {
				HeapFree(GetProcessHeap(), 0, ObjectEntry->ObjectName);
			}
			HeapFree(GetProcessHeap(), 0, ObjectEntry);
		}
	}

	LeaveCriticalSection(&g_kdctx.ListLock);
}

/*
* ObListFindByAddress
*
* Purpose:
*
* Find object by address in object directory dump list.
* Do not free returned buffer, it is released in ObListDestroy.
*
*/
POBJREF ObListFindByAddress(
	_In_ PLIST_ENTRY ListHead,
	_In_ ULONG_PTR	 ObjectAddress
	)
{
	BOOL			bFound;
	POBJREF			ObjectInfo;
	PLIST_ENTRY		Entry;

	if (ListHead == NULL)
		return NULL;

	EnterCriticalSection(&g_kdctx.ListLock);

	ObjectInfo = NULL;
	bFound = FALSE;
	Entry = ListHead->Flink;
	while ((Entry != NULL) && (Entry != ListHead)) {
		ObjectInfo = CONTAINING_RECORD(Entry, OBJREF, ListEntry);
		if (ObjectInfo) {
			if (ObjectInfo->ObjectAddress == ObjectAddress) {
				bFound = TRUE;
				break;
			}
		}
		Entry = Entry->Flink;
	}

	LeaveCriticalSection(&g_kdctx.ListLock);
	return (bFound) ? ObjectInfo : NULL;
}

/*
* kdQueryIopInvalidDeviceRequest
*
* Purpose:
*
* Find IopInvalidDeviceRequest assuming Windows assigned it to WinDBG driver.
*
* Kldbgdrv only defined:
*    IRP_MJ_CREATE
*    IRP_MJ_CLOSE
*    IRP_MJ_DEVICE_CONTROL
*/
PVOID kdQueryIopInvalidDeviceRequest(
	VOID
	)
{
	PVOID			pHandler;
	POBJINFO		pSelfObj;
	ULONG_PTR		drvObjectAddress;
	DRIVER_OBJECT	drvObject;

	pHandler = NULL;
	pSelfObj = ObQueryObject(L"\\Driver", KLDBGDRV);
	if (pSelfObj) {
		drvObjectAddress = pSelfObj->ObjectAddress;
		RtlSecureZeroMemory(&drvObject, sizeof(drvObject));
		if (kdReadSystemMemory(drvObjectAddress, &drvObject, sizeof(drvObject))) {
			pHandler = drvObject.MajorFunction[IRP_MJ_CREATE_MAILSLOT];
		}
		HeapFree(GetProcessHeap(), 0, pSelfObj);
	}
	return pHandler;
}


/*
* kdIsDebugBoot
*
* Purpose:
*
* Perform check is the current OS booted with DEBUG flag
*
*/
BOOL kdIsDebugBoot(
	VOID
	)
{
	HKEY hKey;
	LPWSTR lpszBootOptions = NULL;
	LRESULT lRet;
	DWORD dwSize;
	BOOL cond = FALSE;
	BOOL bResult = FALSE;
	
	do {

		lRet = RegOpenKeyExW(HKEY_LOCAL_MACHINE, RegControlKey, 0, KEY_QUERY_VALUE, &hKey);
		if (lRet != ERROR_SUCCESS)
			break;

		dwSize = 0;
		lRet = RegQueryValueExW(hKey, RegStartOptionsValue, NULL, NULL, (LPBYTE)NULL, &dwSize);
		if (lRet != ERROR_SUCCESS)
			break;

		lpszBootOptions = HeapAlloc(GetProcessHeap(), 0, dwSize + sizeof(WCHAR));
		if (lpszBootOptions == NULL)
			break;

		RtlSecureZeroMemory(lpszBootOptions, dwSize + sizeof(WCHAR));

		lRet = RegQueryValueExW(hKey, RegStartOptionsValue, NULL, NULL, (LPBYTE)lpszBootOptions, &dwSize);
		if (lRet != ERROR_SUCCESS)
			break;

		if (_strstriW(lpszBootOptions, L"DEBUG") != NULL)
			bResult = TRUE;

		RegCloseKey(hKey);
		HeapFree(GetProcessHeap(), 0, lpszBootOptions);

	} while (cond);

	return bResult;
}

/*
* kdReadSystemMemory
*
* Purpose:
*
* Wrapper around SysDbgReadVirtual request to the KLDBGDRV
*
*/
BOOL kdReadSystemMemory(
	_In_ ULONG_PTR Address,
	_Inout_ PVOID Buffer,
	_In_ ULONG BufferSize
	)
{
	KLDBG kldbg;
	SYSDBG_VIRTUAL dbgRequest;
	DWORD bytesIO = 0;

	if (g_kdctx.hDevice == NULL)
		return FALSE;

	if ((Buffer == NULL) || (BufferSize == 0))
		return FALSE;

	if (Address < g_kdctx.SystemRangeStart)
		return FALSE;

	// fill parameters for KdSystemDebugControl
	dbgRequest.Address = (PVOID)Address;
	dbgRequest.Buffer = Buffer;
	dbgRequest.Request = BufferSize;

	// fill parameters for kldbgdrv ioctl
	kldbg.SysDbgRequest = SysDbgReadVirtual;
	kldbg.OutputBuffer = &dbgRequest;
	kldbg.OutputBufferSize = sizeof(SYSDBG_VIRTUAL);

	return DeviceIoControl(g_kdctx.hDevice, IOCTL_KD_PASS_THROUGH, &kldbg,
		sizeof(kldbg), &dbgRequest, sizeof(dbgRequest), &bytesIO, NULL);
}

/*
* kdInit
*
* Purpose:
*
* Extract KLDBGDRV from application resource
*
*/
BOOL kdExtractDriver(
	LPCTSTR lpExtractTo,
	LPCTSTR lpName,
	LPCTSTR lpType
	)
{
	HRSRC hResInfo = NULL;
	HGLOBAL hResData = NULL;
	PVOID pData;
	BOOL bResult = FALSE;
	DWORD dwSize = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;

	hResInfo = FindResource(g_hInstance, lpName, lpType);
	if (hResInfo == NULL) return bResult;

	dwSize = SizeofResource(g_hInstance, hResInfo);
	if (dwSize == 0) return bResult;

	hResData = LoadResource(g_hInstance, hResInfo);
	if (hResData == NULL) return bResult;

	pData = LockResource(hResData);
	if (pData) {
		hFile = CreateFile(lpExtractTo, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
		if (hFile != INVALID_HANDLE_VALUE) {
			bResult = WriteFile(hFile, pData, dwSize, &dwSize, NULL);
			CloseHandle(hFile);
		}
	}
	return bResult;
}

/*
* pkdQuerySystemInformation
*
* Purpose:
*
* Thread worker subroutine.
* Finds MmSystemRangeStart once during program startup.
*
*/
VOID pkdQuerySystemInformation(
	_In_ LPVOID lpParameter
	)
{
	BOOL						cond = FALSE;
	ULONG						rl = 0;
	PKLDBGCONTEXT				Context = (PKLDBGCONTEXT)lpParameter;
	PVOID						MappedKernel = NULL;
	ULONG_PTR					KernelBase = 0L, FuncAddress = 0L;
	PRTL_PROCESS_MODULES		miSpace = NULL;
	CHAR						KernelFullPathName[MAX_PATH * 2];

	do {

		miSpace = (PRTL_PROCESS_MODULES)VirtualAlloc(NULL, 1024 * 1024, 
			MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (miSpace == NULL) {
			break;
		}

		if (!NT_SUCCESS(NtQuerySystemInformation(SystemModuleInformation,
			miSpace, 1024 * 1024, &rl)))
		{
			break;
		}

		if (miSpace->NumberOfModules == 0) {
			break;
		}

		rl = GetSystemDirectoryA(KernelFullPathName, MAX_PATH);
		if (rl == 0) {
			break;
		}

		KernelFullPathName[rl] = (CHAR)'\\';
		_strcpyA(&KernelFullPathName[rl + 1],
			(const char*)&miSpace->Modules[0].FullPathName[miSpace->Modules[0].OffsetToFileName]);
		KernelBase = (ULONG_PTR)miSpace->Modules[0].ImageBase;
		VirtualFree(miSpace, 0, MEM_RELEASE);
		miSpace = NULL;

		MappedKernel = LoadLibraryExA(KernelFullPathName, NULL, DONT_RESOLVE_DLL_REFERENCES);
		if (MappedKernel == NULL) {
			break;
		}
		FuncAddress = (ULONG_PTR)GetProcAddress(MappedKernel, "MmSystemRangeStart");
		FuncAddress = KernelBase + FuncAddress - (ULONG_PTR)MappedKernel;
		kdReadSystemMemory(FuncAddress, &Context->SystemRangeStart, sizeof(ULONG_PTR));

	} while (cond);

	if (MappedKernel != NULL) {
		FreeLibrary(MappedKernel);
	}
	if (miSpace != NULL) {
		VirtualFree(miSpace, 0, MEM_RELEASE);
	}
}


/*
* pKdQueryProc
*
* Purpose:
*
* Thread worker, building objects list and quering other time consuming information.
*
* lpParameter must be a valid pointer to KLDBGCONTEXT global structure.
*
*/
DWORD WINAPI kdQueryProc(
	_In_  LPVOID lpParameter
	)
{
	BOOL			bResult = FALSE;
	PKLDBGCONTEXT	Context = (PKLDBGCONTEXT)lpParameter;


	//validate pointer
	if (Context == NULL) {
		return FALSE;
	}

	//check if this is initial call
	if (Context->SystemRangeStart == 0) {
		pkdQuerySystemInformation(Context);
	}

	//magic dump
	bResult = ObListCreate(&Context->ObjectList);
	return bResult;
}

/*
* kdInit
*
* Purpose:
*
* Enable Debug Privilege and open/load KLDBGDRV driver
*
* If there is no DEBUG mode OS flag or OS version is below than Windows 7 
* this routine only does nothing except object list cs initiailization 
* and global osver query. 
*
*/
VOID kdInit(
	BOOL IsFullAdmin
	)
{
	WCHAR szDrvPath[MAX_PATH * 2];

	RtlSecureZeroMemory(&g_kdctx, sizeof(g_kdctx));
	InitializeCriticalSection(&g_kdctx.ListLock);

	/*
	** Minimum supported client is windows 7
	*/
	RtlSecureZeroMemory(&g_kdctx.osver, sizeof(g_kdctx.osver));
	g_kdctx.osver.dwOSVersionInfoSize = sizeof(g_kdctx.osver);
	RtlGetVersion(&g_kdctx.osver);
	if (
		(g_kdctx.osver.dwMajorVersion < 6) || //any lower other vista
		((g_kdctx.osver.dwMajorVersion == 6) && (g_kdctx.osver.dwMinorVersion == 0))//vista
		)
	{
		return;
	}

	//only init ListLock and version info
	if (IsFullAdmin != TRUE)
		return;

	// check if system booted in the debug mode
	if (kdIsDebugBoot() != TRUE) 
		return;

	// test privilege assigned and continue to load/open kldbg driver
	if (supEnablePrivilege(SE_DEBUG_PRIVILEGE, TRUE)) {

		// try to open existing
		if (scmOpenDevice(KLDBGDRV, &g_kdctx.hDevice) != TRUE) {

			// no such device exist, construct filepath and check if driver already present
			RtlSecureZeroMemory(szDrvPath, sizeof(szDrvPath));
			if (GetSystemDirectory(szDrvPath, MAX_PATH)) {
				_strcatW(szDrvPath, KLDBGDRVSYS);

				// if no file exists, extract it to the drivers directory
				if (!PathFileExists(szDrvPath)) {
					kdExtractDriver(szDrvPath, MAKEINTRESOURCE(IDR_KDBGDRV), L"SYS");
				}
				// load service driver and open handle for it
				g_kdctx.IsOurLoad = scmLoadDeviceDriver(KLDBGDRV, szDrvPath, &g_kdctx.hDevice);
				if (g_kdctx.IsOurLoad) {
					// driver file is no longer needed
					DeleteFile(szDrvPath);
				}
			}
		}
	}

	//query global variable and dump object directory if driver support available.
	if (g_kdctx.hDevice != NULL) {
		g_kdctx.hThreadWorker = CreateThread(NULL, 0, kdQueryProc, &g_kdctx, 0, NULL);
		g_kdctx.IopInvalidDeviceRequest = kdQueryIopInvalidDeviceRequest();
	}
}

/*
* kdShutdown
*
* Purpose:
*
* Close handle to the driver and unload it if it was loaded by our program,
* destroy object list, delete list lock.
* This routine called once, during program shutdown.
*
*/
VOID kdShutdown(
	VOID
	)
{
	if (g_kdctx.hDevice == NULL)
		return;

	if (g_kdctx.hThreadWorker) {
		//give it a last chance to complete, elsewhere we don't care.
		WaitForSingleObject(g_kdctx.hThreadWorker, 1000);
		CloseHandle(g_kdctx.hThreadWorker);
		g_kdctx.hThreadWorker = NULL;
	}

	CloseHandle(g_kdctx.hDevice);
	g_kdctx.hDevice = NULL;

	ObListDestroy(&g_kdctx.ObjectList);

	DeleteCriticalSection(&g_kdctx.ListLock);

	// driver was loaded, unload it
	// windbg recreates service and drops file everytime when kernel debug starts
	if (g_kdctx.IsOurLoad) {
		scmUnloadDeviceDriver(KLDBGDRV);
	}
}