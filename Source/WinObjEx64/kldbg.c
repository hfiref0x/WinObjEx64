/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       KLDBG.C, based on KDSubmarine by Evilcry
*
*  VERSION:     1.33
*
*  DATE:        18 Nov 2015 
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
#include "ldasm\ldasm.h"

//include for PathFileExists API
#pragma comment(lib, "shlwapi.lib")

//number of buckets in the object directory
#define NUMBEROFBUCKETS 0x25

//ObpLookupNamespaceEntry signatures

BYTE NamespacePattern[] =  { 0x0F, 0xB6, 0x7A, 0x28, 0x48, 0x8D, 0x05 }; // 7600, 7601, 9600, 10240
BYTE NamespacePattern8[] = { 0x0F, 0xB6, 0x79, 0x28, 0x48, 0x8D, 0x05 }; // 9200 (8 failed even here)

//KiSystemServiceStartPattern signature

BYTE  KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };

#define MM_SYSTEM_RANGE_START_7 0xFFFF080000000000
#define MM_SYSTEM_RANGE_START_8 0xFFFF800000000000

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
* ObDecodeTypeIndex
*
* Purpose:
*
* Decode encoded type index bjects
*
* Limitation:
*
* Only for Win10+ use
*
*/
UCHAR ObDecodeTypeIndex(
	_In_ PVOID Object,
	_In_ UCHAR EncodedTypeIndex
	)
{
	POBJECT_HEADER ObjectHeader;
	UCHAR TypeIndex;

	if (g_kdctx.ObHeaderCookie == 0) {
		return EncodedTypeIndex;
	}

	ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
	TypeIndex = (EncodedTypeIndex ^ (UCHAR)((ULONG_PTR)ObjectHeader >> OBJECT_SHIFT) ^ g_kdctx.ObHeaderCookie);
	return TypeIndex;
}

/*
* ObFindHeaderCookie
*
* Purpose:
*
* Parse ObGetObjectType and extract object header cookie variable address
*
* Limitation:
*
* Only for Win10+ use
*
*/
UCHAR ObFindHeaderCookie(
	_In_ PKLDBGCONTEXT Context,
	_In_ ULONG_PTR MappedImageBase,
	_In_ ULONG_PTR KernelImageBase
	)
{
	UCHAR ObHeaderCookie = 0;
	BOOL cond = FALSE;
	ULONG_PTR Address = 0, KmAddress;

	UINT        c;
	LONG         rel = 0;
	ldasm_data	 ld;

	if (Context == NULL)
		return 0;

	__try {

		do {

			Address = (ULONG_PTR)GetProcAddress((PVOID)MappedImageBase, "ObGetObjectType");
			if (Address == 0) {
				break;
			}

			c = 0;
			do {
				//movzx   ecx, byte ptr cs:ObHeaderCookie
				if ((*(PBYTE)(Address + c) == 0x0f) &&
					(*(PBYTE)(Address + c + 1) == 0xb6) &&
					(*(PBYTE)(Address + c + 2) == 0x0d))
				{
					rel = *(PLONG)(Address + c + 3);
					break;
				}
				c += ldasm((void*)(Address + c), &ld, 1);
			} while (c < 256);
			KmAddress = Address + c + 7 + rel;

			KmAddress = KernelImageBase + KmAddress - MappedImageBase;

			if (KmAddress < Context->SystemRangeStart) {
				break;
			}

			if (!kdReadSystemMemory(KmAddress, &ObHeaderCookie, sizeof(ObHeaderCookie))) {
				break;
			}

		} while (cond);

	}
	__except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
		return 0;
	}

	return ObHeaderCookie;
}

/*
* ObFindObpPrivateNamespaceLookupTable
*
* Purpose:
*
* Locate and return address of namespace table.
*
* Limitation:
*
* OS dependent.
*
*/
PVOID ObFindObpPrivateNamespaceLookupTable(
	_In_ PKLDBGCONTEXT Context,
	_In_ ULONG_PTR MappedImageBase,
	_In_ ULONG MappedImageSize,
	_In_ ULONG_PTR KernelImageBase
	)
{
	BOOL       cond = FALSE, bFound;
	ULONG      c;
	PBYTE      Signature;
	ULONG      SignatureSize;

	LONG       rel = 0;
	ULONG_PTR  Address = 0L;
	ldasm_data ld;

	__try {

		if (
			(MappedImageBase == 0) ||
			(Context == NULL) ||
			(MappedImageSize == 0) ||
			(KernelImageBase == 0)
			)
		{ 
			return 0;
		}

		do {

			switch (Context->osver.dwBuildNumber) {

			case 9200:
				Signature = NamespacePattern8;
				SignatureSize = sizeof(NamespacePattern8);
				break;

			default:
				Signature = NamespacePattern;
				SignatureSize = sizeof(NamespacePattern);
				break;
			}

			bFound = FALSE;

			for (c = 0; c < MappedImageSize - SignatureSize; c++) {

				//find signature
				if (RtlCompareMemory(
					((PBYTE)MappedImageBase + c),
					Signature, SignatureSize) == SignatureSize)
				{
					bFound = TRUE;
					break;
				}
			}

			//signature not found
			if (bFound == FALSE) {
				Address = 0;
				return 0;
			}

			//set new scan position, signature contain next level search pattern, do not skip
			Address = MappedImageBase + c;
			c = 0;

			do {
				//lea rax, ObpPrivateNamespaceLookupTable
				if ((*(PBYTE)(Address + c) == 0x48) &&
					(*(PBYTE)(Address + c + 1) == 0x8d) &&
					(*(PBYTE)(Address + c + 2) == 0x05))
				{
					rel = *(PLONG)(Address + c + 3);
					break;
				}
				c += ldasm((void*)(Address + c), &ld, 1);
			} while (c < 128);

			Address = Address + c + 7 + rel;
			Address = KernelImageBase + Address - MappedImageBase;

			if (Address < g_kdctx.SystemRangeStart) {
				Address = 0;
				break;
			}

		} while (cond);

	}
	__except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
		return 0;
	}

	return (PVOID)Address;
}

/*
* kdFindKiServiceTable
*
* Purpose:
*
* Find system service table pointer from ntoskrnl image.
*
*/
VOID kdFindKiServiceTable(
	_In_ ULONG_PTR MappedImageBase,
	_In_ ULONG MappedImageSize,
	_In_ ULONG_PTR KernelImageBase,
	_Inout_ ULONG_PTR *KiServiceTablePtr,
	_Inout_ ULONG *KiServiceLimit
	)
{

	BOOL cond = FALSE, bFound = FALSE;
	ULONG_PTR Address = 0;
	UINT         c, SignatureSize;
	LONG         rel = 0;
	ldasm_data	 ld;
	KSERVICE_TABLE_DESCRIPTOR KeSystemDescriptorTable;

	if (
		(KiServiceLimit == NULL) ||
		(KiServiceTablePtr == NULL) ||
		(MappedImageSize == 0) ||
		(MappedImageBase == 0) ||
		(KernelImageBase == 0)
		)
	{
		return;
	}

	__try {

		do {

			SignatureSize = sizeof(KiSystemServiceStartPattern);

			for (c = 0; c < MappedImageSize - SignatureSize; c++) {

				//find  KiSystemServiceStart signature 
				if (RtlCompareMemory(
					((PBYTE)MappedImageBase + c),
					KiSystemServiceStartPattern, SignatureSize) == SignatureSize)
				{
					bFound = TRUE;
					break;
				}
			}

			if (bFound == FALSE)
				break;

			//set new scan position, next level search pattern not included, skip
			Address = MappedImageBase + c + SignatureSize;
			c = 0;

			do {
				//lea r10, KeServiceDescriptorTable
				if ((*(PBYTE)(Address + c) == 0x4c) &&
					(*(PBYTE)(Address + c + 1) == 0x8d) &&
					(*(PBYTE)(Address + c + 2) == 0x15))
				{
					rel = *(PLONG)(Address + c + 3);
					break;
				}
				c += ldasm((void*)(Address + c), &ld, 1);
			} while (c < 128);

			Address = Address + c + 7 + rel;
			Address = KernelImageBase + Address - MappedImageBase;

			if (Address < g_kdctx.SystemRangeStart)
				break;

			RtlSecureZeroMemory(&KeSystemDescriptorTable,
				sizeof(KeSystemDescriptorTable));

			if (!kdReadSystemMemory(Address,
				&KeSystemDescriptorTable, sizeof(KeSystemDescriptorTable)))
			{
				break;
			}

			*KiServiceLimit = KeSystemDescriptorTable.Limit;
			*KiServiceTablePtr = KeSystemDescriptorTable.Base;

		} while (cond);

	}
	__except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
		return;
	}
	return;
}

/*
* ObQuerySystemRangeStartValue
*
* Purpose:
*
* Read MmSystemRangeStart from kernel memory
*
*/
ULONG_PTR ObQuerySystemRangeStartValue(
	_In_ ULONG_PTR MappedImageBase,
	_In_ ULONG_PTR KernelImageBase
	)
{
	ULONG_PTR KmAddress, Value = 0;

	if ((MappedImageBase == 0) || (KernelImageBase == 0))
		return 0;

	KmAddress = (ULONG_PTR)GetProcAddress((HMODULE)MappedImageBase, "MmSystemRangeStart");
	if (KmAddress == 0) {
		return 0;
	}
	KmAddress = KernelImageBase + KmAddress - MappedImageBase;
	kdReadSystemMemory(KmAddress, &Value, sizeof(ULONG_PTR));
	return Value;
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
	status = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &objattr);
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
		if (_strcmpi(lpObjectToFind, L"\\") == 0) {

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
					bFound = (_strcmpi(lpObjectName, lpObjectToFind) == 0);
					HeapFree(GetProcessHeap(), 0, lpObjectName);
					if (bFound == FALSE) {
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
* Returned object memory must be released with HeapFree when object is no longer needed.
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
		rdirLen = _strlen(lpDirectory);
		for (i = 0; i < rdirLen; i++) {
			if (lpDirectory[i] == '\\')
				l = i + 1;
		}
		SingleDirName = &lpDirectory[l];
		if (_strcmpi(SingleDirName, lpObjectName) == 0) {
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
	UCHAR ObjectTypeIndex;

	SIZE_T dirLen, fLen, rdirLen, retSize;

	RtlSecureZeroMemory(&DirObject, sizeof(OBJECT_DIRECTORY));
	if (!kdReadSystemMemory(DirectoryAddress, &DirObject, sizeof(OBJECT_DIRECTORY)))
		return;

	if (lpRootDirectory != NULL) {
		rdirLen = _strlen(lpRootDirectory) * sizeof(WCHAR);
	}
	else {
		rdirLen = 0;
	}

	lpObjectName = NULL;
	retSize = 0;
	ObjectTypeIndex = 0;

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
						lpListEntry = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(OBJREF));
						if (lpListEntry) {

							//save object address
							lpListEntry->ObjectAddress = (ULONG_PTR)Entry.Object;
							lpListEntry->HeaderAddress = ObjectHeaderAddress;
							lpListEntry->TypeIndex = ObjectHeader.TypeIndex;

							//copy dir + name
							if (lpObjectName) {

								fLen = (_strlen(lpObjectName) * sizeof(WCHAR)) +
									(2 * sizeof(WCHAR)) +
									rdirLen + sizeof(UNICODE_NULL);

								lpListEntry->ObjectName = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fLen);
								if (lpListEntry->ObjectName) {
									_strcpy(lpListEntry->ObjectName, lpRootDirectory);
									if (fIsRoot == FALSE) {
										_strcat(lpListEntry->ObjectName, L"\\");
									}
									_strcat(lpListEntry->ObjectName, lpObjectName);
								}
							}

							InsertHeadList(ListHead, &lpListEntry->ListEntry);
						}

						//current object is directory
						ObjectTypeIndex = ObDecodeTypeIndex(Entry.Object, ObjectHeader.TypeIndex);
						if (ObjectTypeIndex == DirectoryTypeIndex) {

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
								_strcpy(lpDirectoryName, lpRootDirectory);
								if (fIsRoot == FALSE) {
									_strcat(lpDirectoryName, L"\\");
								}
								if (lpObjectName) {
									_strcat(lpDirectoryName, lpObjectName);
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
* ObWalkPrivateNamespaceTable
*
* Purpose:
*
* Dump Object Manager private namespace objects
*
*/
BOOL ObWalkPrivateNamespaceTable(
	_In_ PLIST_ENTRY ListHead,
	_In_ ULONG_PTR TableAddress
	)
{
	OBJECT_HEADER ObjectHeader;
	OBJECT_DIRECTORY DirObject;
	OBJECT_DIRECTORY_ENTRY Entry;

	ULONG_PTR ObjectHeaderAddress, item0, item1, InfoHeaderAddress, NameSpaceIdMax = 0L;

	OBJECT_NAMESPACE_LOOKUPTABLE LookupTable;
	OBJECT_NAMESPACE_ENTRY LookupEntry;
	PLIST_ENTRY Current, Head, FindEntry;

	POBJREF lpListEntry, ObjectInfo;
	LPWSTR lpObjectName = NULL;
	SIZE_T retSize = 0;
	INT c, d;

	BOOL EntryFound;

	if (
		(ListHead == NULL) ||
		(TableAddress == 0)
		) 
	{
		return FALSE;
	}

	//dump namespace lookup table
	RtlSecureZeroMemory(&LookupTable, sizeof(OBJECT_NAMESPACE_LOOKUPTABLE));
	if (!kdReadSystemMemory(TableAddress,
		&LookupTable, sizeof(OBJECT_NAMESPACE_LOOKUPTABLE)))
	{
		return FALSE;
	}

	//parse each element
	for (c = 0; c < NUMBEROFBUCKETS; c++) {

		Head = LookupTable.HashBuckets[c].Blink;
		Current = LookupTable.HashBuckets[c].Flink;

		do {
			RtlSecureZeroMemory(&LookupEntry, sizeof(OBJECT_NAMESPACE_ENTRY));
			if (!kdReadSystemMemory((ULONG_PTR)Current, &LookupEntry, sizeof(OBJECT_NAMESPACE_ENTRY))) {
				break;
			}
			Current = LookupEntry.ListEntry.Flink;
			if (Current == Head) {
				break;
			}

			//read namespace directory address
			RtlSecureZeroMemory(&DirObject, sizeof(OBJECT_DIRECTORY));
			if (!kdReadSystemMemory((ULONG_PTR)LookupEntry.NamespaceRootDirectory,
				&DirObject, sizeof(OBJECT_DIRECTORY)))
			{
				break;
			}

			//parse namespace directory
			for (d = 0; d < NUMBEROFBUCKETS; d++) {

				item0 = (ULONG_PTR)DirObject.HashBuckets[d];
				if (item0 != 0) {
					item1 = item0;
					do {
						//read object directory entry
						RtlSecureZeroMemory(&Entry, sizeof(OBJECT_DIRECTORY_ENTRY));
						if (kdReadSystemMemory(item1, &Entry, sizeof(OBJECT_DIRECTORY_ENTRY))) {

							RtlSecureZeroMemory(&ObjectHeader, sizeof(OBJECT_HEADER));
							ObjectHeaderAddress = (ULONG_PTR)OBJECT_TO_OBJECT_HEADER(Entry.Object);
							if (kdReadSystemMemory(ObjectHeaderAddress, &ObjectHeader, sizeof(OBJECT_HEADER))) {

								//query name
								InfoHeaderAddress = 0;
								retSize = 0;
								if (ObHeaderToNameInfoAddress(ObjectHeader.InfoMask, ObjectHeaderAddress, &InfoHeaderAddress, HeaderNameInfoFlag)) {
									lpObjectName = ObQueryNameString(InfoHeaderAddress, &retSize);
								}

								//allocate list entry
								lpListEntry = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(OBJREF));
								if (lpListEntry) {

									//save object address
									lpListEntry->ObjectAddress = (ULONG_PTR)Entry.Object;
									lpListEntry->HeaderAddress = ObjectHeaderAddress;
									lpListEntry->TypeIndex = ObjectHeader.TypeIndex;

									//save object namespace address
									lpListEntry->NamespaceDirectoryAddress = (ULONG_PTR)LookupEntry.NamespaceRootDirectory;

									//assign id
									EntryFound = FALSE;
									FindEntry = ListHead->Flink;
									while ((FindEntry != NULL) && (FindEntry != ListHead)) {
										ObjectInfo = CONTAINING_RECORD(FindEntry, OBJREF, ListEntry);
										if (ObjectInfo) {
											if (lpListEntry->NamespaceDirectoryAddress == ObjectInfo->NamespaceDirectoryAddress) {
												lpListEntry->NamespaceId = ObjectInfo->NamespaceId;
												EntryFound = TRUE;
												break;
											}
										}
										FindEntry = FindEntry->Flink;
									}
									if (EntryFound == FALSE) {
										lpListEntry->NamespaceId = NameSpaceIdMax++;
									}

									//copy object name
									if (lpObjectName) {
										lpListEntry->ObjectName = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, retSize);
										if (lpListEntry->ObjectName) {
											_strcpy(lpListEntry->ObjectName, lpObjectName);
										}
									}
									InsertHeadList(ListHead, &lpListEntry->ListEntry);
								}

								//free memory allocated for object name
								if (lpObjectName) {
									HeapFree(GetProcessHeap(), 0, lpObjectName);
									lpObjectName = NULL;
								}

							}

							item1 = (ULONG_PTR)Entry.ChainLink;
						}
						else {
							item1 = 0;
						}
					} while (item1 != 0);
				}
			}
		} while ((Current != NULL) && (Current != Head));
	}

	return (!IsListEmpty(ListHead));
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
* If specified will dump private namespace objects.
*
*/
BOOL ObListCreate(
	_Inout_ PLIST_ENTRY ListHead,
	_In_ BOOL fNamespace
	)
{
	BOOL bResult;

	bResult = FALSE;
	if (g_kdctx.hDevice == NULL) {
		return bResult;
	}

	if (ListHead == NULL) {
		return bResult;
	}

	EnterCriticalSection(&g_kdctx.ListLock);

	__try {
		
		InitializeListHead(ListHead);

		if ( fNamespace == FALSE ) {
			if (
				(g_kdctx.DirectoryRootAddress == 0) ||
				(g_kdctx.DirectoryTypeIndex == 0)
				)
			{
				if (!ObGetDirectoryObjectAddress(NULL, &g_kdctx.DirectoryRootAddress,
					&g_kdctx.DirectoryTypeIndex))
				{
					SetLastError(ERROR_INTERNAL_ERROR);
				}
			}

			if (
				(g_kdctx.DirectoryRootAddress != 0) &&
				(g_kdctx.DirectoryTypeIndex != 0)
				)
			{
				
				ObWalkDirectoryRecursiveEx(TRUE, ListHead, L"\\",
					g_kdctx.DirectoryRootAddress, g_kdctx.DirectoryTypeIndex);
				bResult = TRUE;
			}
		}
		else {

			if (g_kdctx.ObpPrivateNamespaceLookupTable != 0) {
				bResult = ObWalkPrivateNamespaceTable(ListHead, (ULONG_PTR)g_kdctx.ObpPrivateNamespaceLookupTable);
			}
			else {
				SetLastError(ERROR_INTERNAL_ERROR);
			}

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

	if (
		(g_kdctx.hDevice == NULL) ||
		(ListHead == NULL) 
		)
	{
		return;
	}

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
	SIZE_T memIO;
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

		memIO = dwSize + sizeof(WCHAR);
		lpszBootOptions = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, memIO);
		if (lpszBootOptions == NULL)
			break;

		lRet = RegQueryValueExW(hKey, RegStartOptionsValue, NULL, NULL, (LPBYTE)lpszBootOptions, &dwSize);
		if (lRet != ERROR_SUCCESS)
			break;

		if (_strstri(lpszBootOptions, L"DEBUG") != NULL)
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
	BOOL                      cond = FALSE;
	ULONG                     rl = 0;
	PKLDBGCONTEXT             Context = (PKLDBGCONTEXT)lpParameter;
	PVOID                     MappedKernel = NULL;
	ULONG_PTR                 KernelBase = 0L;
	PRTL_PROCESS_MODULES      miSpace = NULL;
	CHAR                      KernelFullPathName[MAX_PATH * 2];
	ULONG                     ModuleSize;
	PLIST_ENTRY               Head, Next;
	PLDR_DATA_TABLE_ENTRY     Entry;

	do {

		miSpace = supGetSystemInfo(SystemModuleInformation);
		if (miSpace == NULL) {
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
		_strcpy_a(&KernelFullPathName[rl + 1],
			(const char*)&miSpace->Modules[0].FullPathName[miSpace->Modules[0].OffsetToFileName]);
		KernelBase = (ULONG_PTR)miSpace->Modules[0].ImageBase;
		HeapFree(GetProcessHeap(), 0, miSpace);
		miSpace = NULL;

		MappedKernel = LoadLibraryExA(KernelFullPathName, NULL, DONT_RESOLVE_DLL_REFERENCES);
		if (MappedKernel == NULL) {
			break;
		}

		//find sizeof ntoskrnl image
		ModuleSize = 0;
		EnterCriticalSection((PRTL_CRITICAL_SECTION)NtCurrentPeb()->LoaderLock);
		Head = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
		Next = Head->Flink;

		while (Next != Head) {
			Entry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (Entry->DllBase == (PVOID)MappedKernel) {
				ModuleSize = (ULONG)Entry->SizeOfImage;
				break;
			}
			Next = Next->Flink;
		}
		LeaveCriticalSection((PRTL_CRITICAL_SECTION)NtCurrentPeb()->LoaderLock);

		//query MmSystemRangeStart value
		Context->SystemRangeStart = ObQuerySystemRangeStartValue((ULONG_PTR)MappedKernel, KernelBase);
		if (Context->SystemRangeStart == 0) {		
			if (Context->osver.dwBuildNumber < 9200) {
				Context->SystemRangeStart = MM_SYSTEM_RANGE_START_7;
			}
			else {
				Context->SystemRangeStart = MM_SYSTEM_RANGE_START_8;
			}
		}

		//find and remember ObHeaderCookie
		if (Context->osver.dwMajorVersion >= 10) {
			Context->ObHeaderCookie = ObFindHeaderCookie(Context, (ULONG_PTR)MappedKernel, KernelBase);
		}
		//find namespace table
		Context->ObpPrivateNamespaceLookupTable = ObFindObpPrivateNamespaceLookupTable(Context, (ULONG_PTR)MappedKernel, ModuleSize, KernelBase);

		//find KiServiceTable
		kdFindKiServiceTable((ULONG_PTR)MappedKernel, ModuleSize, KernelBase, &Context->KiServiceTableAddress, &Context->KiServiceLimit);


#ifdef _DEBUG
//		RtlSecureZeroMemory(&KernelFullPathName, sizeof(KernelFullPathName));
//		u64tohex_a((ULONG_PTR)Context->ObpPrivateNamespaceLookupTable, KernelFullPathName);
//		OutputDebugStringA(KernelFullPathName);
#endif

	} while (cond);

	if (MappedKernel != NULL) {
		FreeLibrary(MappedKernel);
	}
	if (miSpace != NULL) {
		HeapFree(GetProcessHeap(), 0, miSpace);
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
	bResult = ObListCreate(&Context->ObjectList, FALSE);
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
* this routine only query windows version to the global context variable.
*
*/
VOID kdInit(
	BOOL IsFullAdmin
	)
{
	WCHAR szDrvPath[MAX_PATH * 2];

	RtlSecureZeroMemory(&g_kdctx, sizeof(g_kdctx));

	//
	// Minimum supported client is windows 7
	// Query version info in global context and  
	// if version below Win7 - leave
	//
	g_kdctx.osver.dwOSVersionInfoSize = sizeof(g_kdctx.osver);
	RtlGetVersion(&g_kdctx.osver);
	if (
		(g_kdctx.osver.dwMajorVersion < 6) || //any lower other vista
		((g_kdctx.osver.dwMajorVersion == 6) && (g_kdctx.osver.dwMinorVersion == 0))//vista
		)
	{
		return;
	}

	ObGetDirectoryObjectAddress(NULL, &g_kdctx.DirectoryRootAddress, &g_kdctx.DirectoryTypeIndex);

	// no admin rights, leave
	if (IsFullAdmin == FALSE)
		return;

	// check if system booted in the debug mode
	if (kdIsDebugBoot() == FALSE) 
		return;

	// test privilege assigned and continue to load/open kldbg driver
	if (supEnablePrivilege(SE_DEBUG_PRIVILEGE, TRUE)) {

		// try to open existing
		if (scmOpenDevice(KLDBGDRV, &g_kdctx.hDevice) == FALSE) {

			// no such device exist, construct filepath and check if driver already present
			RtlSecureZeroMemory(szDrvPath, sizeof(szDrvPath));
			if (GetSystemDirectory(szDrvPath, MAX_PATH)) {
				_strcat(szDrvPath, KLDBGDRVSYS);

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
		InitializeCriticalSection(&g_kdctx.ListLock);
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
	DeleteCriticalSection(&g_kdctx.ListLock);

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

	// driver was loaded, unload it
	// windbg recreates service and drops file everytime when kernel debug starts
	if (g_kdctx.IsOurLoad) {
		scmUnloadDeviceDriver(KLDBGDRV);
	}
}
