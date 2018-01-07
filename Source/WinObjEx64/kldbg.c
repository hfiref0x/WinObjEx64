/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       KLDBG.C, based on KDSubmarine by Evilcry
*
*  VERSION:     1.52
*
*  DATE:        08 Jan 2018
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
#include "hde\hde64.h"

//number of buckets in the object directory
#define NUMBEROFBUCKETS 0x25

//ObpLookupNamespaceEntry signatures

BYTE NamespacePattern[] = { 0x0F, 0xB6, 0x7A, 0x28, 0x48, 0x8D, 0x05 }; // 7600, 7601, 9600, 10240
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
    _In_ BYTE InfoMask,
    _In_ OBJ_HEADER_INFO_FLAG Flag
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
    BYTE      HeaderOffset;
    ULONG_PTR Address;

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
* Decode object TypeIndex, encoding introduced in win10
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
    UCHAR          TypeIndex;
    POBJECT_HEADER ObjectHeader;

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
    BOOL       cond = FALSE;
    UCHAR      ObHeaderCookie = 0;
    ULONG_PTR  Address = 0, KmAddress;
    UINT       c;
    LONG       rel = 0;
    hde64s     hs;

    if (Context == NULL)
        return 0;

    __try {

        do {

            Address = (ULONG_PTR)GetProcAddress((PVOID)MappedImageBase, "ObGetObjectType");
            if (Address == 0) {
                break;
            }

            c = 0;
            RtlSecureZeroMemory(&hs, sizeof(hs));
            do {
                //movzx   ecx, byte ptr cs:ObHeaderCookie
                if ((*(PBYTE)(Address + c) == 0x0f) &&
                    (*(PBYTE)(Address + c + 1) == 0xb6) &&
                    (*(PBYTE)(Address + c + 2) == 0x0d))
                {
                    rel = *(PLONG)(Address + c + 3);
                    break;
                }

                hde64_disasm((void*)(Address + c), &hs);
                if (hs.flags & F_ERROR)
                    break;
                c += hs.len;

            } while (c < 256);
            KmAddress = Address + c + 7 + rel;

            KmAddress = KernelImageBase + KmAddress - MappedImageBase;

            if (!kdAddressInNtOsImage((PVOID)KmAddress))
                break;

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
    hde64s     hs;

    __try {

        do {

            switch (g_WinObj.osver.dwBuildNumber) {

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
                return 0;
            }

            //set new scan position, signature contain next level search pattern, do not skip
            Address = MappedImageBase + c;
            c = 0;

            RtlSecureZeroMemory(&hs, sizeof(hs));

            do {
                //lea rax, ObpPrivateNamespaceLookupTable
                if ((*(PBYTE)(Address + c) == 0x48) &&
                    (*(PBYTE)(Address + c + 1) == 0x8d) &&
                    (*(PBYTE)(Address + c + 2) == 0x05))
                {
                    rel = *(PLONG)(Address + c + 3);
                    break;
                }

                hde64_disasm((void*)(Address + c), &hs);
                if (hs.flags & F_ERROR)
                    break;
                c += hs.len;

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
    _In_ ULONG_PTR KernelImageBase,
    _Inout_ ULONG_PTR *KiServiceTablePtr,
    _Inout_ ULONG *KiServiceLimit
)
{
    BOOL         cond = FALSE, bFound = FALSE;
    UINT         c, SignatureSize;
    LONG         rel = 0;
    ULONG        i, SectionSize;
    ULONG_PTR    Address = 0, SectionBase = 0;
    hde64s       hs;

    PIMAGE_NT_HEADERS NtHeaders;
    IMAGE_SECTION_HEADER *SectionTableEntry;

    KSERVICE_TABLE_DESCRIPTOR KeSystemDescriptorTable;

    __try {

        do {

            NtHeaders = RtlImageNtHeader((PVOID)MappedImageBase);
            if (NtHeaders == NULL)
                break;

            SectionTableEntry = (PIMAGE_SECTION_HEADER)((PCHAR)NtHeaders +
                sizeof(ULONG) +
                sizeof(IMAGE_FILE_HEADER) +
                NtHeaders->FileHeader.SizeOfOptionalHeader);

            SectionBase = 0;
            SectionSize = 0;

            i = NtHeaders->FileHeader.NumberOfSections;
            while (i > 0) {
                if (*(PULONG)SectionTableEntry->Name == 'xet.')
                    if ((SectionTableEntry->Name[4] == 't') &&
                        (SectionTableEntry->Name[5] == 0))
                    {
                        SectionBase = ((ULONG_PTR)MappedImageBase + SectionTableEntry->VirtualAddress);
                        SectionSize = SectionTableEntry->Misc.VirtualSize;
                        break;
                    }
                i -= 1;
                SectionTableEntry += 1;
            }

            if ((SectionBase == 0) || (SectionSize == 0))
                break;

            SignatureSize = sizeof(KiSystemServiceStartPattern);
            if (SignatureSize > SectionSize)
                break;

            for (c = 0; c < SectionSize - SignatureSize; c++) {

                //find  KiSystemServiceStart signature 
                if (RtlCompareMemory(
                    ((PBYTE)SectionBase + c),
                    KiSystemServiceStartPattern, SignatureSize) == SignatureSize)
                {
                    bFound = TRUE;
                    break;
                }
            }

            if (bFound == FALSE)
                break;

            //set new scan position, next level search pattern not included, skip
            Address = SectionBase + c + SignatureSize;
            c = 0;
            RtlSecureZeroMemory(&hs, sizeof(hs));

            do {
                //lea r10, KeServiceDescriptorTable
                if ((*(PBYTE)(Address + c) == 0x4c) &&
                    (*(PBYTE)(Address + c + 1) == 0x8d) &&
                    (*(PBYTE)(Address + c + 2) == 0x15))
                {
                    rel = *(PLONG)(Address + c + 3);
                    break;
                }

                hde64_disasm((void*)(Address + c), &hs);
                if (hs.flags & F_ERROR)
                    break;
                c += hs.len;

            } while (c < 128);

            Address = Address + c + 7 + rel;
            Address = KernelImageBase + Address - MappedImageBase;

            if (!kdAddressInNtOsImage((PVOID)Address))
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
    _Inout_opt_ PUSHORT lpTypeIndex
)
{
    BOOL                bFound = FALSE;
    HANDLE              hDirectory = NULL;
    NTSTATUS            status;
    LPWSTR              lpTarget;
    OBJECT_ATTRIBUTES   objattr;
    UNICODE_STRING      objname;

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
* Reads object name from kernel memory, returned buffer must be freed with supHeapFree
*
*/
LPWSTR ObQueryNameString(
    _In_ ULONG_PTR NameInfoAddress,
    _Out_opt_ PSIZE_T ReturnLength
)
{
    ULONG  fLen;
    LPWSTR lpObjectName = NULL;

    OBJECT_HEADER_NAME_INFO NameInfo;

    if (ReturnLength)
        *ReturnLength = 0;

    RtlSecureZeroMemory(&NameInfo, sizeof(OBJECT_HEADER_NAME_INFO));
    if (kdReadSystemMemory(NameInfoAddress, &NameInfo, sizeof(OBJECT_HEADER_NAME_INFO))) {
        fLen = NameInfo.Name.Length + sizeof(UNICODE_NULL);
        lpObjectName = supHeapAlloc(fLen);
        if (lpObjectName != NULL) {
            NameInfoAddress = (ULONG_PTR)NameInfo.Name.Buffer;
            if (kdReadSystemMemory(NameInfoAddress, lpObjectName, NameInfo.Name.Length)) {
                if (ReturnLength)
                    *ReturnLength = fLen;
            }
            else {
                supHeapFree(lpObjectName);
                lpObjectName = NULL;
            }
        }
    }
    return lpObjectName;
}

/*
* ObWalkDirectory
*
* Purpose:
*
* Walks given directory and looks for specified object inside
* Returned object must be freed wtih supHeapFree when no longer needed.
*
*/
POBJINFO ObWalkDirectory(
    _In_ LPWSTR lpObjectToFind,
    _In_ ULONG_PTR DirectoryAddress
)
{
    BOOL      bFound;
    INT       c;
    SIZE_T    retSize;
    POBJINFO  lpData;
    LPWSTR    lpObjectName;
    ULONG_PTR ObjectHeaderAddress, item0, item1, InfoHeaderAddress;

    OBJECT_HEADER          ObjectHeader;
    OBJECT_DIRECTORY       DirObject;
    OBJECT_DIRECTORY_ENTRY Entry;

    __try {

        if (lpObjectToFind == NULL)
            return NULL;

        RtlSecureZeroMemory(&DirObject, sizeof(OBJECT_DIRECTORY));
        if (!kdReadSystemMemory(DirectoryAddress, &DirObject, sizeof(OBJECT_DIRECTORY))) {

#ifdef _DEBUG
            OutputDebugString(L"kdReadSystemMemory(DirectoryAddress) failed");
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
                OutputDebugString(L"kdReadSystemMemory(ObjectHeaderAddress) failed");
#endif

                return NULL;
            }

            lpData = supHeapAlloc(sizeof(OBJINFO));
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
                        OutputDebugString(L"kdReadSystemMemory(OBJECT_DIRECTORY_ENTRY) failed");
#endif
                        break;
                    }

                    //read object header
                    RtlSecureZeroMemory(&ObjectHeader, sizeof(OBJECT_HEADER));
                    ObjectHeaderAddress = (ULONG_PTR)OBJECT_TO_OBJECT_HEADER(Entry.Object);
                    if (!kdReadSystemMemory(ObjectHeaderAddress, &ObjectHeader, sizeof(OBJECT_HEADER))) {

#ifdef _DEBUG
                        OutputDebugString(L"kdReadSystemMemory(ObjectHeaderAddress) failed");
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
                    supHeapFree(lpObjectName);
                    if (bFound == FALSE) {
                        goto NextItem;
                    }
                    //identical, allocate item info and copy it
                    lpData = supHeapAlloc(sizeof(OBJINFO));
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
* Returned object memory must be released with supHeapFree when object is no longer needed.
*
*/
POBJINFO ObQueryObject(
    _In_ LPWSTR lpDirectory,
    _In_ LPWSTR lpObjectName
)
{
    BOOL       needFree = FALSE;
    ULONG_PTR  DirectoryAddress;
    SIZE_T     i, l, rdirLen, ldirSz;
    LPWSTR     SingleDirName, LookupDirName;

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
            LookupDirName = supHeapAlloc(ldirSz);
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
                supHeapFree(LookupDirName);

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
    _In_ BOOL fIsRoot,
    _In_ PLIST_ENTRY ListHead,
    _In_opt_ LPWSTR lpRootDirectory,
    _In_ ULONG_PTR DirectoryAddress,
    _In_ USHORT DirectoryTypeIndex
)
{
    UCHAR      ObjectTypeIndex;
    INT        c;
    SIZE_T     dirLen, fLen, rdirLen, retSize;
    ULONG_PTR  ObjectHeaderAddress, item0, item1, InfoHeaderAddress;
    POBJREF    lpListEntry;
    LPWSTR     lpObjectName, lpDirectoryName;

    OBJECT_HEADER ObjectHeader;
    OBJECT_DIRECTORY DirObject;
    OBJECT_DIRECTORY_ENTRY Entry;

    RtlSecureZeroMemory(&DirObject, sizeof(OBJECT_DIRECTORY));
    if (!kdReadSystemMemory(DirectoryAddress, &DirObject, sizeof(OBJECT_DIRECTORY)))
        return;

    if (lpRootDirectory != NULL) {
        rdirLen = (1 + _strlen(lpRootDirectory)) * sizeof(WCHAR);
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
                        lpListEntry = supHeapAlloc(sizeof(OBJREF));
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

                                lpListEntry->ObjectName = supHeapAlloc(fLen);
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
                            lpDirectoryName = supHeapAlloc(dirLen);
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
                                supHeapFree(lpDirectoryName);
                                lpDirectoryName = NULL;
                            }
                        }

                        if (lpObjectName) {
                            supHeapFree(lpObjectName);
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
    BOOL          EntryFound;
    INT           c, d;
    SIZE_T        retSize = 0;
    ULONG_PTR     ObjectHeaderAddress, item0, item1, InfoHeaderAddress, NameSpaceIdMax = 0L;
    PLIST_ENTRY   Current, Head, FindEntry;
    POBJREF       lpListEntry, ObjectInfo;
    LPWSTR        lpObjectName = NULL;

    OBJECT_HEADER                ObjectHeader;
    OBJECT_DIRECTORY             DirObject;
    OBJECT_DIRECTORY_ENTRY       Entry;
    OBJECT_NAMESPACE_LOOKUPTABLE LookupTable;
    OBJECT_NAMESPACE_ENTRY       LookupEntry;

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
                                lpListEntry = supHeapAlloc(sizeof(OBJREF));
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
                                        if (lpListEntry->NamespaceDirectoryAddress == ObjectInfo->NamespaceDirectoryAddress) {
                                            lpListEntry->NamespaceId = ObjectInfo->NamespaceId;
                                            EntryFound = TRUE;
                                            break;
                                        }
                                        FindEntry = FindEntry->Flink;
                                    }
                                    if (EntryFound == FALSE) {
                                        lpListEntry->NamespaceId = NameSpaceIdMax++;
                                    }

                                    //copy object name
                                    if (lpObjectName) {
                                        lpListEntry->ObjectName = supHeapAlloc(retSize);
                                        if (lpListEntry->ObjectName) {
                                            _strcpy(lpListEntry->ObjectName, lpObjectName);
                                        }
                                    }
                                    InsertHeadList(ListHead, &lpListEntry->ListEntry);
                                }

                                //free memory allocated for object name
                                if (lpObjectName) {
                                    supHeapFree(lpObjectName);
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

    RtlEnterCriticalSection(&g_kdctx.ListLock);

    __try {

        InitializeListHead(ListHead);

        if (fNamespace == FALSE) {
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

    RtlLeaveCriticalSection(&g_kdctx.ListLock);

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

    if (g_kdctx.hDevice == NULL)
        return;

    RtlEnterCriticalSection(&g_kdctx.ListLock);

    if (ListHead) {
        while (!IsListEmpty(ListHead)) {
            if (ListHead->Flink == NULL)
                break;

            ObjectEntry = CONTAINING_RECORD(ListHead->Flink, OBJREF, ListEntry);
            RemoveEntryList(ListHead->Flink);
            if (ObjectEntry->ObjectName) {
                supHeapFree(ObjectEntry->ObjectName);
            }
            supHeapFree(ObjectEntry);
        }
    }

    RtlLeaveCriticalSection(&g_kdctx.ListLock);
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
    BOOL         bFound;
    POBJREF      ObjectInfo;
    PLIST_ENTRY  Entry;

    if (ListHead == NULL)
        return NULL;

    RtlEnterCriticalSection(&g_kdctx.ListLock);

    ObjectInfo = NULL;
    bFound = FALSE;
    Entry = ListHead->Flink;
    while ((Entry != NULL) && (Entry != ListHead)) {
        ObjectInfo = CONTAINING_RECORD(Entry, OBJREF, ListEntry);
        if (ObjectInfo->ObjectAddress == ObjectAddress) {
            bFound = TRUE;
            break;
        }
        Entry = Entry->Flink;
    }

    RtlLeaveCriticalSection(&g_kdctx.ListLock);
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
    PVOID           pHandler;
    POBJINFO        pSelfObj;
    ULONG_PTR       drvObjectAddress;
    DRIVER_OBJECT   drvObject;

    pHandler = NULL;
    pSelfObj = ObQueryObject(L"\\Driver", KLDBGDRV);
    if (pSelfObj) {
        drvObjectAddress = pSelfObj->ObjectAddress;
        RtlSecureZeroMemory(&drvObject, sizeof(drvObject));
        if (kdReadSystemMemory(drvObjectAddress, &drvObject, sizeof(drvObject))) {
            pHandler = drvObject.MajorFunction[IRP_MJ_CREATE_MAILSLOT];

            //
            // IopInvalidDeviceRequest is a routine inside ntoskrnl.
            //
            if (!kdAddressInNtOsImage(pHandler))
                pHandler = NULL;
        }
        supHeapFree(pSelfObj);
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
    ULONG rl = 0;
    SYSTEM_KERNEL_DEBUGGER_INFORMATION kdInfo;

    RtlSecureZeroMemory(&kdInfo, sizeof(kdInfo));
    NtQuerySystemInformation(SystemKernelDebuggerInformation, &kdInfo, sizeof(kdInfo), &rl);
    return kdInfo.KernelDebuggerEnabled;
}

/*
* kdReadSystemMemoryEx
*
* Purpose:
*
* Wrapper around SysDbgReadVirtual request to the KLDBGDRV
*
*/
_Success_(return == TRUE)
BOOL kdReadSystemMemoryEx(
    _In_ ULONG_PTR Address,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG NumberOfBytesRead
)
{
    BOOL           bResult = FALSE;
    DWORD          bytesIO = 0;
    KLDBG          kldbg;
    SYSDBG_VIRTUAL dbgRequest;

    if (NumberOfBytesRead)
        *NumberOfBytesRead = 0;

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

    bResult = DeviceIoControl(g_kdctx.hDevice, IOCTL_KD_PASS_THROUGH, &kldbg,
        sizeof(kldbg), &dbgRequest, sizeof(dbgRequest), &bytesIO, NULL);

    if (NumberOfBytesRead)
        *NumberOfBytesRead = bytesIO;

    return bResult;
}

/*
* kdReadSystemMemory
*
* Purpose:
*
* Wrapper around kdReadSystemMemoryEx
*
*/
BOOL kdReadSystemMemory(
    _In_ ULONG_PTR Address,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize
)
{
    return kdReadSystemMemoryEx(Address, Buffer, BufferSize, NULL);
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
    _In_ LPCWSTR lpExtractTo,
    _In_ LPCWSTR lpName,
    _In_ LPCWSTR lpType
)
{
    HRSRC   hResInfo = NULL;
    HGLOBAL hResData = NULL;
    PVOID   pData;
    BOOL    bResult = FALSE;
    DWORD   dwSize = 0;
    HANDLE  hFile = INVALID_HANDLE_VALUE;

    hResInfo = FindResource(g_WinObj.hInstance, lpName, lpType);
    if (hResInfo == NULL) return bResult;

    dwSize = SizeofResource(g_WinObj.hInstance, hResInfo);
    if (dwSize == 0) return bResult;

    hResData = LoadResource(g_WinObj.hInstance, hResInfo);
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
*
*/
VOID pkdQuerySystemInformation(
    _In_ LPVOID lpParameter
)
{
    BOOL                    cond = FALSE;
    ULONG                   ModuleSize;
    PVOID                   MappedKernel = NULL;
    PKLDBGCONTEXT           Context = (PKLDBGCONTEXT)lpParameter;
    PIMAGE_NT_HEADERS       NtHeaders;
    PRTL_PROCESS_MODULES    miSpace = NULL;
    WCHAR                   NtOskrnlFullPathName[MAX_PATH * 2];

    do {

        miSpace = supGetSystemInfo(SystemModuleInformation);
        if (miSpace == NULL)
            break;

        if (miSpace->NumberOfModules == 0)
            break;

        Context->NtOsBase = miSpace->Modules[0].ImageBase; //loaded kernel base
        Context->NtOsSize = miSpace->Modules[0].ImageSize; //loaded kernel size

        _strcpy(NtOskrnlFullPathName, g_WinObj.szSystemDirectory);
        _strcat(NtOskrnlFullPathName, TEXT("\\"));
        MultiByteToWideChar(CP_ACP, 0,
            (LPCSTR)&miSpace->Modules[0].FullPathName[miSpace->Modules[0].OffsetToFileName],
            -1, _strend(NtOskrnlFullPathName), MAX_PATH);

        supHeapFree(miSpace);
        miSpace = NULL;

        MappedKernel = LoadLibraryEx(NtOskrnlFullPathName, NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (MappedKernel == NULL)
            break;

        //find and remember ObHeaderCookie
        if (g_WinObj.osver.dwMajorVersion >= 10) {
            
            Context->ObHeaderCookie = ObFindHeaderCookie(Context, 
                (ULONG_PTR)MappedKernel, 
                (ULONG_PTR)Context->NtOsBase);
        
        }

        NtHeaders = RtlImageNtHeader(MappedKernel);
        if (NtHeaders) {
            ModuleSize = NtHeaders->OptionalHeader.SizeOfImage;
            if (ModuleSize != 0) {

                //find KiServiceTable
                kdFindKiServiceTable((ULONG_PTR)MappedKernel, 
                    (ULONG_PTR)Context->NtOsBase, 
                    &Context->KiServiceTableAddress, 
                    &Context->KiServiceLimit);

                //find namespace table
                if (g_WinObj.osver.dwBuildNumber <= 10240) {
                    Context->ObpPrivateNamespaceLookupTable = ObFindObpPrivateNamespaceLookupTable( 
                        (ULONG_PTR)MappedKernel, 
                        ModuleSize, 
                        (ULONG_PTR)Context->NtOsBase);
                }
            }
        }

    } while (cond);

    if (MappedKernel != NULL) {
        FreeLibrary(MappedKernel);
    }
    if (miSpace != NULL) {
        supHeapFree(miSpace);
    }
}

/*
* kdAddressInNtOsImage
*
* Purpose:
*
* Test if given address in range of ntoskrnl.
*
*/
BOOL kdAddressInNtOsImage(
    _In_ PVOID Address
)
{
    return IN_REGION(Address, 
        g_kdctx.NtOsBase, 
        g_kdctx.NtOsSize);
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
    _In_ LPVOID lpParameter
)
{
    BOOL            bResult = FALSE;
    PKLDBGCONTEXT   Context = (PKLDBGCONTEXT)lpParameter;

    //validate pointer
    if (Context == NULL) {
        return FALSE;
    }

    //check if this is initial call
    if (Context->KiServiceTableAddress == 0) {
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
*/
VOID kdInit(
    BOOL IsFullAdmin
)
{
    WCHAR szDrvPath[MAX_PATH * 2];

    RtlSecureZeroMemory(&g_kdctx, sizeof(g_kdctx));

    //
    // Minimum supported client is windows 7
    // Query system range start value and if version below Win7 - leave
    //
    if (
        (g_WinObj.osver.dwMajorVersion < 6) || //any lower other vista
        ((g_WinObj.osver.dwMajorVersion == 6) && (g_WinObj.osver.dwMinorVersion == 0))//vista
        )
    {
        return;
    }

    ObGetDirectoryObjectAddress(NULL, &g_kdctx.DirectoryRootAddress, &g_kdctx.DirectoryTypeIndex);
    g_kdctx.SystemRangeStart = supQuerySystemRangeStart();
    if (g_kdctx.SystemRangeStart == 0) {
        if (g_WinObj.osver.dwBuildNumber < 9200) {
            g_kdctx.SystemRangeStart = MM_SYSTEM_RANGE_START_7;
        }
        else {
            g_kdctx.SystemRangeStart = MM_SYSTEM_RANGE_START_8;
        }
    }

    // no admin rights, leave
    if (IsFullAdmin == FALSE)
        return;


#ifndef _USE_OWN_DRIVER
    // check if system booted in the debug mode
    if (kdIsDebugBoot() == FALSE)
        return;
#endif

    // test privilege assigned and continue to load/open kldbg driver
    if (supEnablePrivilege(SE_DEBUG_PRIVILEGE, TRUE)) {

        // try to open existing
        if (scmOpenDevice(KLDBGDRV, &g_kdctx.hDevice) == FALSE) {

            // no such device exist, construct filepath and check if driver already present
            RtlSecureZeroMemory(szDrvPath, sizeof(szDrvPath));
            _strcpy(szDrvPath, g_WinObj.szSystemDirectory);
            _strcat(szDrvPath, KLDBGDRVSYS);

            // if no file exists, extract it to the drivers directory
            if (!PathFileExists(szDrvPath)) {
                kdExtractDriver(szDrvPath, MAKEINTRESOURCE(IDR_KDBGDRV), L"SYS");
            }
            // load service driver and open handle for it
            g_kdctx.IsOurLoad = scmLoadDeviceDriver(KLDBGDRV, szDrvPath, &g_kdctx.hDevice);
        }

    }

    //query global variable and dump object directory if driver support available.
    if (g_kdctx.hDevice != NULL) {
        RtlInitializeCriticalSection(&g_kdctx.ListLock);
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
    WCHAR szDrvPath[MAX_PATH];

    RtlDeleteCriticalSection(&g_kdctx.ListLock);

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

    //
    // Driver was loaded, unload it.
    // Windbg recreates service and drops file everytime when kernel debug starts.
    // Windbg behavior untested in win10.
    //
    if (g_kdctx.IsOurLoad) {
        scmUnloadDeviceDriver(KLDBGDRV);
        // driver file is no longer needed
        RtlSecureZeroMemory(&szDrvPath, sizeof(szDrvPath));
        _strcpy(szDrvPath, g_WinObj.szSystemDirectory);
        _strcat(szDrvPath, KLDBGDRVSYS);
        DeleteFile(szDrvPath);
    }
}
