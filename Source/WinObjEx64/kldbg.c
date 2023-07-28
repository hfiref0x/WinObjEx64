/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2023
*
*  TITLE:       KLDBG.C, based on KDSubmarine by Evilcry
*
*  VERSION:     2.03
*
*  DATE:        22 Jul 2023
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
#include "ntos\ntldr.h"
#include "hde\hde64.h"
#include "kldbg_patterns.h"
#include "ksymbols.h"

//
// Global variables
//

//Context
KLDBGCONTEXT g_kdctx;

//Build number
ULONG g_NtBuildNumber;

WCHAR g_ObNameNormalizationSymbol = OBJ_NAME_NORMALIZATION_SYMBOL;

//Callbacks
NOTIFICATION_CALLBACKS g_SystemCallbacks;

//Context private data
KLDBGPDATA g_kdpdata;

static UNICODE_STRING g_usObjectsRootDirectory = {
    sizeof(KM_OBJECTS_ROOT_DIRECTORY) - sizeof(WCHAR),
    sizeof(KM_OBJECTS_ROOT_DIRECTORY),
    KM_OBJECTS_ROOT_DIRECTORY
};

static UNICODE_STRING g_usDirectoryType = {
    sizeof(OBTYPE_NAME_DIRECTORY) - sizeof(WCHAR),
    sizeof(OBTYPE_NAME_DIRECTORY),
    OBTYPE_NAME_DIRECTORY
};

static UNICODE_STRING g_usObjectTypesDirectory = {
    sizeof(OBTYPES_DIRECTORY) - sizeof(WCHAR),
    sizeof(OBTYPES_DIRECTORY),
    OBTYPES_DIRECTORY
};

static UNICODE_STRING g_usGlobalRoot = {
    sizeof(OB_GLOBALROOT) - sizeof(WCHAR),
    sizeof(OB_GLOBALROOT),
    OB_GLOBALROOT
};

static UNICODE_STRING g_usGlobalNamespace = {
    sizeof(OB_GLOBALNAMESPACE) - sizeof(WCHAR),
    sizeof(OB_GLOBALNAMESPACE),
    OB_GLOBALNAMESPACE
};

/*
* ObGetPredefinedUnicodeString
*
* Purpose:
*
* Return pointer to constant unicode string by id.
*
*/
PUNICODE_STRING ObGetPredefinedUnicodeString(
    _In_ ULONG Index
)
{
    switch (Index) {
    case OBP_GLOBALNAMESPACE:
        return &g_usGlobalNamespace;
    case OBP_GLOBAL:
        return &g_usGlobalRoot;
    case OBP_OBTYPES:
        return &g_usObjectTypesDirectory;
    case OBP_DIRECTORY:
        return &g_usDirectoryType;
    case OBP_ROOT:
    default:
        return &g_usObjectsRootDirectory;
    }
}

/*
* ObFindAddress
*
* Purpose:
*
* Scan portion of code for specified instruction and extract address from it.
*
*/
ULONG_PTR ObFindAddress(
    _In_ ULONG_PTR ImageBase,
    _In_ ULONG_PTR MappedImageBase,
    _In_ ULONG ReqInstructionLength,
    _In_ PBYTE PtrCode,
    _In_ ULONG NumberOfBytes,
    _In_ PBYTE ScanPattern,
    _In_ ULONG ScanPatternSize)
{
    ULONG_PTR   Address;
    PBYTE       ptrCode = PtrCode;
    ULONG       Index = 0;
    LONG        Rel = 0;
    hde64s      hs;

    do {
        hde64_disasm((void*)(ptrCode + Index), &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == ReqInstructionLength) {

            if (ScanPatternSize == RtlCompareMemory(&ptrCode[Index],
                ScanPattern,
                ScanPatternSize))
            {
                Rel = *(PLONG)(ptrCode + Index + ScanPatternSize);
                break;
            }

        }
        Index += hs.len;

    } while (Index < NumberOfBytes);

    if (Rel == 0)
        return 0;

    Address = (ULONG_PTR)ptrCode + Index + hs.len + Rel;
    Address = ImageBase + Address - MappedImageBase;

    return Address;
}

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
* Various (version, dependent)
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
    _In_ ULONG_PTR ObjectHeaderAddress,
    _Inout_ PULONG_PTR HeaderInfoAddress,
    _In_ OBJ_HEADER_INFO_FLAG InfoFlag
)
{
    BYTE      HeaderOffset;
    ULONG_PTR Address;

    if (HeaderInfoAddress == NULL)
        return FALSE;

    if (ObjectHeaderAddress < g_kdctx.SystemRangeStart)
        return FALSE;

    HeaderOffset = ObGetObjectHeaderOffset(ObjectInfoMask, InfoFlag);
    if (HeaderOffset == 0)
        return FALSE;

    Address = ObjectHeaderAddress - HeaderOffset;
    if (Address < g_kdctx.SystemRangeStart)
        return FALSE;

    *HeaderInfoAddress = Address;
    return TRUE;
}

#ifndef STRSAFE_IGNORE_NULLS
#define STRSAFE_IGNORE_NULLS 0x00000100
#endif

/*
* ObIsValidUnicodeStringWorker
*
* Purpose:
*
* Validate UNICODE_STRING structure, from ntstrsafe.h usermode variant.
*
*/
NTSTATUS ObIsValidUnicodeStringWorker(
    _In_ PCUNICODE_STRING SourceString,
    _In_ CONST SIZE_T cchMax,
    _In_ DWORD dwFlags
)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;

    __try {

        //
        // Make it fail on null ptr if corresponding flag is specified.
        //
        if (SourceString || !(dwFlags & STRSAFE_IGNORE_NULLS)) {

            if ((SourceString->Buffer) &&
                !kdAddressInUserModeRange((PVOID)SourceString->Buffer))
            {
                return STATUS_INVALID_PARAMETER;
            }

            if (((SourceString->Length % sizeof(WCHAR)) != 0) ||
                ((SourceString->MaximumLength % sizeof(WCHAR)) != 0) ||
                (SourceString->Length > SourceString->MaximumLength) ||
                (SourceString->MaximumLength > (cchMax * sizeof(WCHAR))))
            {
                ntStatus = STATUS_INVALID_PARAMETER;
            }
            else if ((SourceString->Buffer == NULL) &&
                ((SourceString->Length != 0) || (SourceString->MaximumLength != 0)))
            {
                ntStatus = STATUS_INVALID_PARAMETER;
            }


        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }

    return ntStatus;
}

/*
* ObIsValidUnicodeString
*
* Purpose:
*
* Validate UNICODE_STRING structure contents.
*
*/
NTSTATUS ObIsValidUnicodeString(
    _In_ PCUNICODE_STRING SourceString
)
{
    return ObIsValidUnicodeStringWorker(SourceString, UNICODE_STRING_MAX_CHARS, 0);
}

/*
* ObIsValidUnicodeStringEx
*
* Purpose:
*
* Validate UNICODE_STRING structure contents.
*
*/
NTSTATUS ObIsValidUnicodeStringEx(
    _In_ PCUNICODE_STRING SourceString,
    _In_ DWORD dwFlags
)
{
    return ObIsValidUnicodeStringWorker(SourceString, UNICODE_STRING_MAX_CHARS, dwFlags);
}

/*
* ObCopyBoundaryDescriptor
*
* Purpose:
*
* Copy boundary descriptor from kernel to user.
* Use supHeapFree to free allocated buffer.
*
*/
NTSTATUS ObCopyBoundaryDescriptor(
    _In_ OBJECT_NAMESPACE_ENTRY* NamespaceLookupEntry,
    _Out_ POBJECT_BOUNDARY_DESCRIPTOR* BoundaryDescriptor,
    _Out_opt_ PULONG BoundaryDescriptorSize
)
{
    ULONG TotalSize;
    ULONG_PTR BoundaryDescriptorAddress;
    OBJECT_BOUNDARY_DESCRIPTOR BoundaryDescriptorHeader, * CopyDescriptor;

    *BoundaryDescriptor = NULL;

    BoundaryDescriptorAddress = (ULONG_PTR)RtlOffsetToPointer(NamespaceLookupEntry,
        sizeof(OBJECT_NAMESPACE_ENTRY));

    if (BoundaryDescriptorAddress < g_kdctx.SystemRangeStart)
        return STATUS_INVALID_PARAMETER;

    RtlSecureZeroMemory(&BoundaryDescriptorHeader, sizeof(BoundaryDescriptorHeader));

    //
    // Read header.
    //
    if (!kdReadSystemMemory(BoundaryDescriptorAddress,
        &BoundaryDescriptorHeader,
        sizeof(OBJECT_BOUNDARY_DESCRIPTOR)))
    {
        return STATUS_DEVICE_NOT_READY;
    }

    if (BoundaryDescriptorSize)
        *BoundaryDescriptorSize = 0;

    //
    // Validate header data.
    //
    TotalSize = BoundaryDescriptorHeader.TotalSize;

    if (TotalSize < sizeof(OBJECT_BOUNDARY_DESCRIPTOR))
        return STATUS_INVALID_PARAMETER;

    if (BoundaryDescriptorHeader.Version != KNOWN_BOUNDARY_DESCRIPTOR_VERSION)
        return STATUS_UNKNOWN_REVISION;

    if ((BoundaryDescriptorAddress + TotalSize) < BoundaryDescriptorAddress)
        return STATUS_INVALID_PARAMETER;

    //
    // Dump entire boundary descriptor.
    //
    CopyDescriptor = (OBJECT_BOUNDARY_DESCRIPTOR*)supHeapAlloc(TotalSize);
    if (CopyDescriptor == NULL)
        return STATUS_MEMORY_NOT_ALLOCATED;

    if (kdReadSystemMemory(BoundaryDescriptorAddress,
        CopyDescriptor,
        TotalSize))
    {
        *BoundaryDescriptor = CopyDescriptor;
        if (BoundaryDescriptorSize)
            *BoundaryDescriptorSize = TotalSize;
    }
    else {
        supHeapFree(CopyDescriptor);
        return STATUS_DEVICE_NOT_READY;
    }

    return STATUS_SUCCESS;
}

/*
* ObpValidateSidBuffer
*
* Purpose:
*
* Check if given SID is valid.
*
*/
BOOLEAN ObpValidateSidBuffer(
    PSID Sid,
    SIZE_T BufferSize
)
{
    PUCHAR Count;

    if (BufferSize < RtlLengthRequiredSid(0))
        return FALSE;

    Count = RtlSubAuthorityCountSid(Sid);
    if (BufferSize < RtlLengthRequiredSid(*Count))
        return FALSE;

    return RtlValidSid(Sid);
}

/*
* ObEnumerateBoundaryDescriptorEntries
*
* Purpose:
*
* Walk each boundary descriptor entry, validate it and run optional callback.
*
*/
NTSTATUS ObEnumerateBoundaryDescriptorEntries(
    _In_ OBJECT_BOUNDARY_DESCRIPTOR* BoundaryDescriptor,
    _In_ PENUMERATE_BOUNDARY_DESCRIPTOR_CALLBACK Callback,
    _In_opt_ PVOID Context
)
{
    ULONG EntrySize, TotalItems = 0, NameEntries = 0, IntegrityLabelEntries = 0;
    ULONG BoundaryDescriptorItems = 0;
    ULONG_PTR DataEnd;
    OBJECT_BOUNDARY_ENTRY* CurrentEntry, * NextEntry;

    __try {

        if (BoundaryDescriptor->TotalSize < sizeof(OBJECT_BOUNDARY_DESCRIPTOR))
            return STATUS_INVALID_PARAMETER;

        if (BoundaryDescriptor->Version != KNOWN_BOUNDARY_DESCRIPTOR_VERSION)
            return STATUS_INVALID_PARAMETER;

        DataEnd = (ULONG_PTR)RtlOffsetToPointer(BoundaryDescriptor,
            BoundaryDescriptor->TotalSize);

        if (DataEnd < (ULONG_PTR)BoundaryDescriptor)
            return STATUS_INVALID_PARAMETER;

        CurrentEntry = (OBJECT_BOUNDARY_ENTRY*)RtlOffsetToPointer(BoundaryDescriptor,
            sizeof(OBJECT_BOUNDARY_DESCRIPTOR));

        BoundaryDescriptorItems = BoundaryDescriptor->Items;

    }
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
        return GetExceptionCode();
    }

    do {
        __try {
            EntrySize = CurrentEntry->EntrySize;
            if (EntrySize < sizeof(OBJECT_BOUNDARY_ENTRY))
                return STATUS_INVALID_PARAMETER;

            TotalItems++;

            NextEntry = (OBJECT_BOUNDARY_ENTRY*)ALIGN_UP(((PBYTE)CurrentEntry + EntrySize), ULONG_PTR);

            if ((NextEntry < CurrentEntry) || ((ULONG_PTR)NextEntry > DataEnd))
                return STATUS_INVALID_PARAMETER;

            if (CurrentEntry->EntryType == OBNS_Name) {
                if (++NameEntries > MAX_BOUNDARY_DESCRIPTOR_NAME_ENTRIES)
                    return STATUS_DUPLICATE_NAME;
            }
            else

                if (CurrentEntry->EntryType == OBNS_SID) {
                    if (!ObpValidateSidBuffer((PSID)((PBYTE)CurrentEntry + sizeof(OBJECT_BOUNDARY_ENTRY)),
                        EntrySize - sizeof(OBJECT_BOUNDARY_ENTRY)))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }
                }
                else
                    if (CurrentEntry->EntryType == OBNS_IntegrityLabel) {
                        if (++IntegrityLabelEntries > MAX_BOUNDARY_DESCRIPTOR_IL_ENTRIES)
                            return STATUS_DUPLICATE_OBJECTID;
                    }
        }
        __except (WOBJ_EXCEPTION_FILTER_LOG) {
            return GetExceptionCode();
        }

        if (Callback(CurrentEntry, Context))
            return STATUS_SUCCESS;

        CurrentEntry = NextEntry;

    } while ((ULONG_PTR)CurrentEntry < (ULONG_PTR)DataEnd);

    return (TotalItems != BoundaryDescriptorItems) ? STATUS_INVALID_PARAMETER : STATUS_SUCCESS;
}

/*
* ObpDumpObjectWithSpecifiedSize
*
* Purpose:
*
* Return dumped object version aware.
*
* Use supVirtualFree to free returned buffer.
*
*/
PVOID ObpDumpObjectWithSpecifiedSize(
    _In_ ULONG_PTR ObjectAddress,
    _In_ ULONG ObjectSize,
    _In_ ULONG ObjectVersion,
    _Out_ PULONG OutSize,
    _Out_ PULONG OutVersion
)
{
    PVOID ObjectBuffer = NULL;
    ULONG BufferSize = ALIGN_UP_BY(ObjectSize, PAGE_SIZE);

    *OutSize = 0;
    *OutVersion = 0;

    if (ObjectAddress < g_kdctx.SystemRangeStart)
        return NULL;

    ObjectBuffer = supVirtualAlloc(BufferSize);
    if (ObjectBuffer) {
        if (kdReadSystemMemory(ObjectAddress,
            ObjectBuffer,
            (ULONG)ObjectSize))
        {
            *OutSize = ObjectSize;
            *OutVersion = ObjectVersion;
        }
        else {
            supVirtualFree(ObjectBuffer);
            ObjectBuffer = NULL;
        }
    }
    return ObjectBuffer;
}

/*
* ObDumpObjectTypeVersionAware
*
* Purpose:
*
* Return dumped OBJECT_TYPE object version aware.
*
* Use supVirtualFree to free returned buffer.
*
*/
PVOID ObDumpObjectTypeVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version
)
{
    ULONG objectSize = 0;
    ULONG objectVersion = 0;

    switch (g_NtBuildNumber) {
    case NT_WIN7_RTM:
    case NT_WIN7_SP1:
        objectSize = sizeof(OBJECT_TYPE_7);
        objectVersion = OBVERSION_OBJECT_TYPE_V1;
        break;
    case NT_WIN8_RTM:
    case NT_WIN8_BLUE:
    case NT_WIN10_THRESHOLD1:
    case NT_WIN10_THRESHOLD2:
        objectSize = sizeof(OBJECT_TYPE_8);
        objectVersion = OBVERSION_OBJECT_TYPE_V2;
        break;
    case NT_WIN10_REDSTONE1:
        objectSize = sizeof(OBJECT_TYPE_RS1);
        objectVersion = OBVERSION_OBJECT_TYPE_V3;
        break;
    default:
        objectSize = sizeof(OBJECT_TYPE_RS2);
        objectVersion = OBVERSION_OBJECT_TYPE_V4;
        break;
    }

    return ObpDumpObjectWithSpecifiedSize(ObjectAddress,
        objectSize,
        objectVersion,
        Size,
        Version);
}

/*
* ObDumpAlpcPortObjectVersionAware
*
* Purpose:
*
* Return dumped ALPC_PORT object version aware.
*
* Use supVirtualFree to free returned buffer.
*
*/
PVOID ObDumpAlpcPortObjectVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version
)
{
    ULONG objectSize = 0;
    ULONG objectVersion = 0;

    switch (g_NtBuildNumber) {
    case NT_WIN7_RTM:
    case NT_WIN7_SP1:
        objectSize = sizeof(ALPC_PORT_7600);
        objectVersion = OBVERSION_ALPCPORT_V1;
        break;
    case NT_WIN8_RTM:
        objectSize = sizeof(ALPC_PORT_9200);
        objectVersion = OBVERSION_ALPCPORT_V2;
        break;
    case NT_WIN8_BLUE:
        objectSize = sizeof(ALPC_PORT_9600);
        objectVersion = OBVERSION_ALPCPORT_V3;
        break;
    default:
        objectSize = sizeof(ALPC_PORT_10240);
        objectVersion = OBVERSION_ALPCPORT_V4;
        break;
    }

    return ObpDumpObjectWithSpecifiedSize(ObjectAddress,
        objectSize,
        objectVersion,
        Size,
        Version);
}

/*
* ObxDumpDirectoryObjectVersionAware
*
* Purpose:
*
* Return dumped OBJECT_DIRECTORY object version aware.
*
* Use supVirtualFree to free returned buffer.
*
*/
PVOID ObDumpDirectoryObjectVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version
)
{
    ULONG objectSize = 0;
    ULONG objectVersion = 0;

    switch (g_NtBuildNumber) {

    case NT_WIN7_RTM:
    case NT_WIN7_SP1:
    case NT_WIN8_RTM:
    case NT_WIN8_BLUE:
        objectSize = sizeof(OBJECT_DIRECTORY);
        objectVersion = OBVERSION_DIRECTORY_V1;
        break;

    case NT_WIN10_THRESHOLD1:
    case NT_WIN10_THRESHOLD2:
    case NT_WIN10_REDSTONE1:
        objectSize = sizeof(OBJECT_DIRECTORY_V2);
        objectVersion = OBVERSION_DIRECTORY_V2;
        break;

    default:
        objectSize = sizeof(OBJECT_DIRECTORY_V3);
        objectVersion = OBVERSION_DIRECTORY_V3;
        break;
    }

    return ObpDumpObjectWithSpecifiedSize(ObjectAddress,
        objectSize,
        objectVersion,
        Size,
        Version);
}

/*
* ObDumpSymbolicLinkObjectVersionAware
*
* Purpose:
*
* Return dumped OBJEC_SYMBOLIC_LINK object version aware.
*
* Use supVirtualFree to free returned buffer.
*
*/
PVOID ObDumpSymbolicLinkObjectVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version
)
{
    ULONG objectSize = 0;
    ULONG objectVersion = 0;

    switch (g_NtBuildNumber) {
    case NT_WIN7_RTM:
    case NT_WIN7_SP1:
    case NT_WIN8_RTM:
    case NT_WIN8_BLUE:
        objectSize = sizeof(OBJECT_SYMBOLIC_LINK_V1);
        objectVersion = OBVERSION_OBJECT_SYMBOLIC_LINK_V1;
        break;
    case NT_WIN10_THRESHOLD1:
    case NT_WIN10_THRESHOLD2:
        objectSize = sizeof(OBJECT_SYMBOLIC_LINK_V2);
        objectVersion = OBVERSION_OBJECT_SYMBOLIC_LINK_V2;
        break;
    case NT_WIN10_REDSTONE1:
        objectSize = sizeof(OBJECT_SYMBOLIC_LINK_V3);
        objectVersion = OBVERSION_OBJECT_SYMBOLIC_LINK_V3;
        break;
    case NT_WIN10_REDSTONE2:
    case NT_WIN10_REDSTONE3:
    case NT_WIN10_REDSTONE4:
    case NT_WIN10_REDSTONE5:
    case NT_WIN10_19H1:
    case NT_WIN10_19H2:
    case NT_WIN10_20H1:
    case NT_WIN10_20H2:
    case NT_WIN10_21H1:
    case NT_WIN10_21H2:
    case NT_WIN10_22H2:
        objectSize = sizeof(OBJECT_SYMBOLIC_LINK_V4);
        objectVersion = OBVERSION_OBJECT_SYMBOLIC_LINK_V4;
        break;
    case NT_WINSRV_21H1:
    case NT_WIN11_21H2:
    case NT_WIN11_22H2:
    default:
        objectSize = sizeof(OBJECT_SYMBOLIC_LINK_V5);
        objectVersion = OBVERSION_OBJECT_SYMBOLIC_LINK_V5;
        break;
    }

    return ObpDumpObjectWithSpecifiedSize(ObjectAddress,
        objectSize,
        objectVersion,
        Size,
        Version);
}

/*
* ObDumpDeviceMapVersionAware
*
* Purpose:
*
* Return dumped DEVICE_MAP structure version aware.
*
* Use supVirtualFree to free returned buffer.
*
*/
PVOID ObDumpDeviceMapVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version
)
{
    ULONG objectSize = 0;
    ULONG objectVersion = 0;

    if (g_NtBuildNumber >= NT_WIN7_RTM &&
        g_NtBuildNumber < NT_WIN10_REDSTONE1)
    {
        objectSize = sizeof(DEVICE_MAP_V1);
        objectVersion = OBVERSION_DEVICE_MAP_V1;
    }
    else
        if (g_NtBuildNumber >= NT_WIN10_REDSTONE1 &&
            g_NtBuildNumber < NT_WIN11_21H2)
        {
            objectSize = sizeof(DEVICE_MAP_V2);
            objectVersion = OBVERSION_DEVICE_MAP_V2;
        }
        else {
            objectSize = sizeof(DEVICE_MAP_V3);
            objectVersion = OBVERSION_DEVICE_MAP_V3;
        }

    return ObpDumpObjectWithSpecifiedSize(ObjectAddress,
        objectSize,
        objectVersion,
        Size,
        Version);
}

/*
* ObDumpDriverExtensionVersionAware
*
* Purpose:
*
* Return dumped DRIVER_EXTENSION structure version aware.
*
* Use supVirtualFree to free returned buffer.
*
*/
PVOID ObDumpDriverExtensionVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version
)
{
    ULONG objectSize = 0;
    ULONG objectVersion = 0;

    if (g_NtBuildNumber >= NT_WIN8_BLUE) {
        objectSize = sizeof(DRIVER_EXTENSION_V4);
        objectVersion = OBVERSION_DRIVER_EXTENSION_V4;
    }
    else {

        switch (g_NtBuildNumber) {
        case NT_WIN7_RTM:
        case NT_WIN7_SP1:
            objectSize = sizeof(DRIVER_EXTENSION_V2);
            objectVersion = OBVERSION_DRIVER_EXTENSION_V2;
            break;
        case NT_WIN8_RTM:
            objectSize = sizeof(DRIVER_EXTENSION_V3);
            objectVersion = OBVERSION_DRIVER_EXTENSION_V3;
            break;
        default:
            objectSize = sizeof(DRIVER_EXTENSION);
            objectVersion = OBVERSION_DRIVER_EXTENSION_V1;
            break;
        }
    }

    return ObpDumpObjectWithSpecifiedSize(ObjectAddress,
        objectSize,
        objectVersion,
        Size,
        Version);
}

/*
* ObDumpFltFilterObjectVersionAware
*
* Purpose:
*
* Return dumped FLT_FILTER structure version aware.
*
* Use supVirtualFree to free returned buffer.
*
*/
PVOID ObDumpFltFilterObjectVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version
)
{
    ULONG objectSize = 0;
    ULONG objectVersion = 0;

    if (g_NtBuildNumber >= NT_WIN7_RTM &&
        g_NtBuildNumber <= NT_WIN7_SP1)
    {
        objectSize = sizeof(FLT_FILTER_V1);
        objectVersion = OBVERSION_FLT_FILTER_V1;
    }
    else if (g_NtBuildNumber >= NT_WIN8_RTM &&
        g_NtBuildNumber <= NT_WIN8_BLUE)
    {
        objectSize = sizeof(FLT_FILTER_V2);
        objectVersion = OBVERSION_FLT_FILTER_V2;
    }
    else if (g_NtBuildNumber >= NT_WIN10_THRESHOLD1 &&
        g_NtBuildNumber < NT_WINSRV_21H1)
    {
        objectSize = sizeof(FLT_FILTER_V3);
        objectVersion = OBVERSION_FLT_FILTER_V3;
    }
    else {
        objectSize = sizeof(FLT_FILTER_V4);
        objectVersion = OBVERSION_FLT_FILTER_V4;
    }

    return ObpDumpObjectWithSpecifiedSize(ObjectAddress,
        objectSize,
        objectVersion,
        Size,
        Version);
}

/*
* kdDumpUnicodeString
*
* Purpose:
*
* Dump UNICODE_STRING from kernel space.
*
*/
_Success_(return)
BOOLEAN kdDumpUnicodeString(
    _In_ PUNICODE_STRING InputString,
    _Out_ PUNICODE_STRING OutputString,
    _Out_opt_ PVOID* ReferenceStringBuffer,
    _In_ BOOLEAN IsKernelPointer
)
{
    ULONG readBytes = 0;
    LPWSTR lpStringBuffer;
    UNICODE_STRING string;

    if (IsKernelPointer) {

        RtlInitEmptyUnicodeString(&string, NULL, 0);
        if (kdReadSystemMemoryEx((ULONG_PTR)InputString,
            &string,
            sizeof(UNICODE_STRING),
            &readBytes))
        {
            if (readBytes != sizeof(UNICODE_STRING))
                return FALSE;
        }
    }
    else {
        string = *InputString;
    }

    if (string.Length == 0 || string.MaximumLength == 0)
        return FALSE;

    lpStringBuffer = (LPWSTR)supHeapAlloc(string.Length + sizeof(UNICODE_NULL));
    if (lpStringBuffer) {

        if (kdReadSystemMemoryEx((ULONG_PTR)string.Buffer,
            lpStringBuffer,
            string.Length,
            &readBytes))
        {
            if (readBytes == string.Length) {

                OutputString->Buffer = lpStringBuffer;
                OutputString->Length = string.Length;
                OutputString->MaximumLength = string.MaximumLength;

                if (ReferenceStringBuffer)
                    *ReferenceStringBuffer = string.Buffer;

                return TRUE;
            }
        }

        supHeapFree(lpStringBuffer);
    }

    return FALSE;
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

    //
    // Cookie can be zero.
    //
    if (g_kdctx.Data->ObHeaderCookie.Valid == FALSE) {
        return EncodedTypeIndex;
    }

    ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
    TypeIndex = (EncodedTypeIndex ^
        (UCHAR)((ULONG_PTR)ObjectHeader >> OBJECT_SHIFT) ^
        g_kdctx.Data->ObHeaderCookie.Value);

    return TypeIndex;
}

/*
* ObpFindHeaderCookie
*
* Purpose:
*
* Parse ObGetObjectType and extract object header cookie variable address.
* Called once.
*
* Limitation:
*
* Only for Win10+ use
*
*/
BOOLEAN ObpFindHeaderCookie(
    _In_ PKLDBGCONTEXT Context
)
{
    UCHAR      cookieValue = 0;
    PBYTE      ptrCode;
    ULONG_PTR  lookupAddress;

    ULONG_PTR NtOsBase;
    HMODULE hNtOs;

    OBHEADER_COOKIE* Cookie;

    Cookie = &Context->Data->ObHeaderCookie;
    Cookie->Valid = FALSE;

    NtOsBase = (ULONG_PTR)Context->NtOsBase;
    hNtOs = (HMODULE)Context->NtOsImageMap;

    lookupAddress = 0;

    //
    // If symbols available, lookup address from them.
    //
    if (kdIsSymAvailable((PSYMCONTEXT)Context->NtOsSymContext)) {

        kdGetAddressFromSymbol(
            Context,
            KVAR_ObHeaderCookie,
            &lookupAddress);

    }

    //
    // No symbols available or there is an error, switch to signature search.
    //
    if (lookupAddress == 0) {

        ptrCode = (PBYTE)GetProcAddress(hNtOs, "ObGetObjectType");
        if (ptrCode) {

            lookupAddress = ObFindAddress(NtOsBase,
                (ULONG_PTR)hNtOs,
                IL_ObHeaderCookie,
                ptrCode,
                DA_ScanBytesObHeaderCookie,
                ObHeaderCookiePattern,
                sizeof(ObHeaderCookiePattern));

        }

        if (!kdAddressInNtOsImage((PVOID)lookupAddress))
            return FALSE;

    }

    if (kdReadSystemMemory(
        lookupAddress,
        &cookieValue,
        sizeof(cookieValue)))
    {
        Cookie->Valid = TRUE;
        Cookie->Value = cookieValue;
    }

    return Cookie->Valid;
}

/*
* ObpFindProcessObjectOffsets
*
* Purpose:
*
* Extract EPROCESS offsets from ntoskrnl routines.
*
*/
BOOLEAN ObpFindProcessObjectOffsets(
    _In_ PKLDBGCONTEXT Context
)
{
    PBYTE   ptrCode;

    HMODULE hNtOs;

    ULONG offsetValue;

    hde64s  hs;

    PEPROCESS_OFFSET pOffsetProcessId = &Context->Data->PsUniqueProcessId;
    PEPROCESS_OFFSET pOffsetImageName = &Context->Data->PsProcessImageName;

    hNtOs = (HMODULE)Context->NtOsImageMap;

    do {

        //
        // If symbols available try lookup field offset from them.
        //
        if (kdIsSymAvailable((PSYMCONTEXT)Context->NtOsSymContext)) {

            if (pOffsetProcessId->Valid == FALSE) {

                offsetValue = 0;
                if (kdGetFieldOffsetFromSymbol(
                    Context,
                    KSYM_EPROCESS,
                    KFLD_UniqueProcessId,
                    &offsetValue))
                {
                    pOffsetProcessId->OffsetValue = offsetValue;
                    pOffsetProcessId->Valid = TRUE;
                }

            }

            if (pOffsetImageName->Valid == FALSE) {

                offsetValue = 0;
                if (kdGetFieldOffsetFromSymbol(
                    Context,
                    KSYM_EPROCESS,
                    KFLD_ImageFileName,
                    &offsetValue))
                {
                    pOffsetImageName->OffsetValue = offsetValue;
                    pOffsetImageName->Valid = TRUE;
                }

            }
        }

        if (pOffsetProcessId->Valid == FALSE) {

            ptrCode = (PBYTE)GetProcAddress(hNtOs, "PsGetProcessId");
            if (ptrCode == NULL)
                break;

            hde64_disasm((void*)(ptrCode), &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len != 7)
                break;

            pOffsetProcessId->OffsetValue = *(PULONG)(ptrCode + 3);
            pOffsetProcessId->Valid = TRUE;

        }

        if (pOffsetImageName->Valid == FALSE) {

            ptrCode = (PBYTE)GetProcAddress(hNtOs, "PsGetProcessImageFileName");
            if (ptrCode == NULL)
                break;

            hde64_disasm((void*)(ptrCode), &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len != 7)
                break;

            pOffsetImageName->OffsetValue = *(PULONG)(ptrCode + 3);
            pOffsetImageName->Valid = TRUE;

        }

    } while (FALSE);

    return (pOffsetProcessId->Valid == TRUE && pOffsetImageName->Valid == TRUE);
}

/*
* ObFindPrivateNamespaceLookupTable2
*
* Purpose:
*
* Locate and return address of namespace table.
*
* Limitation:
*
* OS dependent, Windows 10 (RS1 - 19H1).
*
*/
PVOID ObFindPrivateNamespaceLookupTable2(
    _In_ PKLDBGCONTEXT Context
)
{
    ULONG_PTR varAddress = 0;

    PVOID   SectionBase;
    ULONG   SectionSize = 0;

    PBYTE   Signature;
    ULONG   SignatureSize;

    PBYTE   ptrCode = NULL;

    ESERVERSILO_GLOBALS PspHostSiloGlobals;

    HMODULE hNtOs = (HMODULE)Context->NtOsImageMap;

    do {

        //
        // Symbols lookup.
        //
        if (kdIsSymAvailable((PSYMCONTEXT)Context->NtOsSymContext)) {

            kdGetAddressFromSymbol(
                Context,
                KVAR_PspHostSiloGlobals,
                &varAddress);

        }

        //
        // Pattern search.
        //
        if (varAddress == 0) {

            //
            // Locate .text image section.
            //
            SectionBase = supLookupImageSectionByName(TEXT_SECTION,
                TEXT_SECTION_LEGNTH,
                (PVOID)hNtOs,
                &SectionSize);

            if (SectionBase == NULL || SectionSize == 0)
                break;

            //
            // Locate starting point for search ->
            // PsGetServerSiloServiceSessionId for RS4+ and PsGetServerSiloGlobals for RS1-RS3.
            //
            if (g_NtBuildNumber >= NT_WIN10_REDSTONE4) {

                ptrCode = (PBYTE)GetProcAddress(hNtOs, "PsGetServerSiloServiceSessionId");

            }
            else {

                switch (g_NtBuildNumber) {

                case NT_WIN10_REDSTONE1:
                    SignatureSize = sizeof(PsGetServerSiloGlobalsPattern_14393);
                    Signature = PsGetServerSiloGlobalsPattern_14393;
                    break;
                case NT_WIN10_REDSTONE2:
                case NT_WIN10_REDSTONE3:
                    SignatureSize = sizeof(PsGetServerSiloGlobalsPattern_15064_16299);
                    Signature = PsGetServerSiloGlobalsPattern_15064_16299;
                    break;
                default:
                    //
                    // We need to fail if this is unknown release.
                    //
                    return NULL;
                }

                ptrCode = (PBYTE)supFindPattern((PBYTE)SectionBase,
                    SectionSize,
                    Signature,
                    SignatureSize);
            }

            if (ptrCode == NULL)
                break;

            //
            // Find address to PspHostSiloGlobals in code.
            //
            varAddress = ObFindAddress((ULONG_PTR)Context->NtOsBase,
                (ULONG_PTR)hNtOs,
                IL_PspHostSiloGlobals,
                ptrCode,
                DA_ScanBytesPNSVariant1,
                LeaPattern_PNS,
                sizeof(LeaPattern_PNS));

            if (!kdAddressInNtOsImage((PVOID)varAddress))
                return NULL;

        }

        //
        // Dump PspHostSiloGlobals.
        //
        RtlSecureZeroMemory(&PspHostSiloGlobals, sizeof(PspHostSiloGlobals));

        if (kdReadSystemMemory(varAddress,
            &PspHostSiloGlobals,
            sizeof(PspHostSiloGlobals)))
        {
            //
            // Return adjusted address of PrivateNamespaceLookupTable.
            //
            varAddress += FIELD_OFFSET(OBP_SILODRIVERSTATE, PrivateNamespaceLookupTable);

        }
        else {
            varAddress = 0;
        }


    } while (FALSE);

    return (PVOID)varAddress;
}

/*
* ObFindPrivateNamespaceLookupTable
*
* Purpose:
*
* Locate and return address of private namespace table.
*
*/
PVOID ObFindPrivateNamespaceLookupTable(
    _In_ PKLDBGCONTEXT Context
)
{
    PBYTE      Signature;
    ULONG      SignatureSize;

    ULONG_PTR  Address = 0;

    PBYTE      ptrCode = NULL;
    PVOID      SectionBase;
    ULONG      SectionSize = 0;

    HMODULE hNtOs = (HMODULE)Context->NtOsImageMap;

    if (g_NtBuildNumber > NT_WIN10_THRESHOLD2)
        return ObFindPrivateNamespaceLookupTable2(Context);

    do {

        //
        // Locate PAGE image section.
        //
        SectionBase = supLookupImageSectionByName(PAGE_SECTION,
            PAGE_SECTION_LENGTH,
            (PVOID)hNtOs,
            &SectionSize);

        if ((SectionBase == 0) || (SectionSize == 0))
            break;

        switch (g_NtBuildNumber) {

        case NT_WIN8_RTM:
            Signature = NamespacePattern8;
            SignatureSize = sizeof(NamespacePattern8);
            break;

        default:
            Signature = NamespacePattern;
            SignatureSize = sizeof(NamespacePattern);
            break;
        }

        ptrCode = (PBYTE)supFindPattern((PBYTE)SectionBase,
            SectionSize,
            Signature,
            SignatureSize);

        if (ptrCode == NULL)
            break;

        Address = ObFindAddress((ULONG_PTR)Context->NtOsBase,
            (ULONG_PTR)hNtOs,
            IL_PspHostSiloGlobals,
            ptrCode,
            DA_ScanBytesPNSVariant2,
            LeaPattern_PNS,
            sizeof(LeaPattern_PNS));

        if (!kdAddressInNtOsImage((PVOID)Address)) {
            Address = 0;
            break;
        }

    } while (FALSE);

    return (PVOID)Address;
}

/*
* ObGetCallbackBlockRoutine
*
* Purpose:
*
* Read callback block routine from kernel and return function pointer.
*
*/
PVOID ObGetCallbackBlockRoutine(
    _In_ PVOID CallbackBlock
)
{
    EX_CALLBACK_ROUTINE_BLOCK readBlock;

    readBlock.Function = NULL;

    if (!kdReadSystemMemory((ULONG_PTR)CallbackBlock,
        &readBlock,
        sizeof(EX_CALLBACK_ROUTINE_BLOCK)))
    {
        return NULL;
    }
    else {
        return readBlock.Function;
    }
}

/*
* kdpFindKiServiceTableByPattern
*
* Purpose:
*
* Signature pattern based search for service table address.
*
*/
BOOL kdpFindKiServiceTableByPattern(
    _In_ ULONG_PTR MappedImageBase,
    _In_ ULONG_PTR KernelImageBase,
    _Out_ ULONG_PTR* Address
)
{
    ULONG signatureSize;
    ULONG sectionSize;
    ULONG_PTR lookupAddress = 0, varAddress = 0, sectionBase = 0;

    *Address = 0;

    //
    // Locate .text image section.
    //
    sectionBase = (ULONG_PTR)supLookupImageSectionByName(TEXT_SECTION,
        TEXT_SECTION_LEGNTH,
        (PVOID)MappedImageBase,
        &sectionSize);

    if (sectionBase == 0)
        return FALSE;

    signatureSize = sizeof(KiSystemServiceStartPattern);
    if (sectionSize < signatureSize)
        return FALSE;

    //
    // Find KiSystemServiceStart signature.
    //
    lookupAddress = (ULONG_PTR)supFindPattern(
        (PBYTE)sectionBase,
        sectionSize,
        (PBYTE)KiSystemServiceStartPattern,
        signatureSize);

    if (lookupAddress == 0)
        return FALSE;

    lookupAddress += signatureSize;

    //
    // Find KeServiceDescriptorTableShadow.
    //
    varAddress = ObFindAddress(KernelImageBase,
        (ULONG_PTR)MappedImageBase,
        IL_KeServiceDescriptorTableShadow,
        (PBYTE)lookupAddress,
        DA_ScanBytesKeServiceDescriptorTableShadow,
        LeaPattern_KeServiceDescriptorTableShadow,
        sizeof(LeaPattern_KeServiceDescriptorTableShadow));

    if (kdAddressInNtOsImage((PVOID)varAddress))
        *Address = varAddress;

    return TRUE;
}

/*
* kdFindServiceTable
*
* Purpose:
*
* Find system service table pointer from ntoskrnl image.
*
*/
BOOL kdFindKiServiceTable(
    _In_ ULONG_PTR MappedImageBase,
    _In_ ULONG_PTR KernelImageBase,
    _Inout_ KSERVICE_TABLE_DESCRIPTOR* ServiceTable
)
{
    ULONG_PTR varAddress = 0;

    //
    // If KeServiceDescriptorTableShadow was not extracted then extract it otherwise use ready address.
    //
    if (g_kdctx.Data->KeServiceDescriptorTableShadowPtr) {

        varAddress = g_kdctx.Data->KeServiceDescriptorTableShadowPtr;

    }
    else {

        //
        // Symbols lookup.
        //
        if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {

            kdGetAddressFromSymbol(
                &g_kdctx,
                KVAR_KeServiceDescriptorTableShadow,
                &varAddress);

        }

        //
        // Pattern search.
        //
        if (varAddress == 0) {

            if (!kdpFindKiServiceTableByPattern(MappedImageBase,
                KernelImageBase,
                &varAddress))
            {
                return FALSE;
            }

        }

        g_kdctx.Data->KeServiceDescriptorTableShadowPtr = varAddress;

    }

    return kdReadSystemMemory(
        varAddress,
        ServiceTable,
        sizeof(KSERVICE_TABLE_DESCRIPTOR));
}

/*
* ObQueryNameStringFromAddress
*
* Purpose:
*
* Reads object name from kernel memory if present.
*
* If HeapHandle is g_WinObj use supHeapFree to release allocated memory.
*
*/
_Success_(return)
BOOL ObQueryNameStringFromAddress(
    _In_ HANDLE HeapHandle,
    _In_ ULONG_PTR NameInfoAddress,
    _Out_ PUNICODE_STRING NameString
)
{
    SIZE_T allocLength;
    LPWSTR objectName = NULL;
    OBJECT_HEADER_NAME_INFO nameInfo;

    RtlSecureZeroMemory(&nameInfo, sizeof(OBJECT_HEADER_NAME_INFO));

    if (kdReadSystemMemory(NameInfoAddress,
        &nameInfo,
        sizeof(OBJECT_HEADER_NAME_INFO)))
    {
        if (nameInfo.Name.Length &&
            supUnicodeStringValid(&nameInfo.Name)) {

            allocLength = nameInfo.Name.Length;

            objectName = (LPWSTR)supHeapAllocEx(HeapHandle,
                allocLength + sizeof(UNICODE_NULL));

            if (objectName != NULL) {

                NameInfoAddress = (ULONG_PTR)nameInfo.Name.Buffer;

                if (kdReadSystemMemory(NameInfoAddress,
                    objectName,
                    nameInfo.Name.Length))
                {
                    NameString->Buffer = objectName;
                    NameString->Length = nameInfo.Name.Length;
                    NameString->MaximumLength = nameInfo.Name.MaximumLength;

                    return TRUE;
                }
                else {

                    supHeapFreeEx(HeapHandle,
                        objectName);

                    objectName = NULL;
                }

            }
        }

    }

    return FALSE;
}

/*
* ObpCopyObjectBasicInfo
*
* Purpose:
*
*   Read object related data from kernel to local user copy.
*   Returned object must be freed wtih supHeapFree when no longer needed.
*
* Parameters:
*
*   ObjectAddress - kernel address of object specified type (e.g. DRIVER_OBJECT).
*   ObjectHeaderAddress - OBJECT_HEADER structure kernel address.
*   ObjectHeaderAddressValid - if set then ObjectHeaderAddress in already converted form.
*   DumpedObjectHeader - pointer to OBJECT_HEADER structure previously dumped.
*
* Return Value:
*
*   Pointer to OBJINFO structure allocated from WinObjEx heap and filled with kernel data.
*
*/
POBEX_OBJECT_INFORMATION ObpCopyObjectBasicInfo(
    _In_ ULONG_PTR ObjectAddress,
    _In_ ULONG_PTR ObjectHeaderAddress,
    _In_ BOOL ObjectHeaderAddressValid,
    _In_opt_ POBJECT_HEADER DumpedObjectHeader
)
{
    ULONG_PTR HeaderAddress = 0, InfoHeaderAddress = 0;
    OBJECT_HEADER ObjectHeader, *pObjectHeader;
    POBEX_OBJECT_INFORMATION lpData = NULL;

    //
    // Convert object address to object header address.
    //
    if (ObjectHeaderAddressValid) {
        HeaderAddress = ObjectHeaderAddress;
    }
    else {
        HeaderAddress = (ULONG_PTR)OBJECT_TO_OBJECT_HEADER(ObjectAddress);
    }

    //
    // ObjectHeader already dumped, copy it.
    //
    if (DumpedObjectHeader) {
        pObjectHeader = DumpedObjectHeader;
    }
    else {
        //
        // ObjectHeader wasn't dumped, validate it address and do dump.
        //
        if (HeaderAddress < g_kdctx.SystemRangeStart)
            return NULL;

        //
        // Read OBJECT_HEADER.
        //
        RtlSecureZeroMemory(&ObjectHeader, sizeof(OBJECT_HEADER));

        if (!kdReadSystemMemory(HeaderAddress,
            &ObjectHeader,
            sizeof(OBJECT_HEADER)))
        {
            kdReportReadErrorSimple(__FUNCTIONW__, HeaderAddress, sizeof(OBJECT_HEADER));
            return NULL;
        }

        pObjectHeader = &ObjectHeader;
    }

    //
    // Allocate OBJINFO structure, exit on fail.
    //
    lpData = (POBEX_OBJECT_INFORMATION)supHeapAlloc(sizeof(OBEX_OBJECT_INFORMATION));
    if (lpData == NULL)
        return NULL;

    lpData->ObjectAddress = ObjectAddress;
    lpData->HeaderAddress = HeaderAddress;

    //
    // Copy object header.
    //
    RtlCopyMemory(&lpData->ObjectHeader,
        pObjectHeader,
        sizeof(OBJECT_HEADER));

    //
    // Query and copy quota info if exist.
    //
    InfoHeaderAddress = 0;

    if (ObHeaderToNameInfoAddress(pObjectHeader->InfoMask,
        HeaderAddress,
        &InfoHeaderAddress,
        HeaderQuotaInfoFlag))
    {
        kdReadSystemMemory(HeaderAddress,
            &lpData->ObjectQuotaHeader,
            sizeof(OBJECT_HEADER_QUOTA_INFO));
    }

    return lpData;
}

/*
* ObQueryObjectByAddress
*
* Purpose:
*
* Look for object at specified address.
* Returned object memory must be released with supHeapFree when object is no longer needed.
*
*/
POBEX_OBJECT_INFORMATION ObQueryObjectByAddress(
    _In_ ULONG_PTR ObjectAddress
)
{
    ULONG_PTR ObjectHeaderAddress;
    OBJECT_HEADER ObjectHeader;

    if (ObjectAddress < g_kdctx.SystemRangeStart)
        return NULL;

    if (!kdConnectDriver())
        return NULL;

    //
    // Read object header, fail is critical.
    //
    RtlSecureZeroMemory(&ObjectHeader, sizeof(OBJECT_HEADER));
    ObjectHeaderAddress = (ULONG_PTR)OBJECT_TO_OBJECT_HEADER(ObjectAddress);

    if (!kdReadSystemMemory(ObjectHeaderAddress,
        &ObjectHeader,
        sizeof(OBJECT_HEADER)))
    {
        kdReportReadErrorSimple(__FUNCTIONW__, ObjectHeaderAddress, sizeof(OBJECT_HEADER));
        return NULL;
    }

    return ObpCopyObjectBasicInfo(ObjectAddress,
        ObjectHeaderAddress,
        TRUE,
        &ObjectHeader);
}

/*
* ObpFindObjectInDirectory
*
* Purpose:
*
* Walks given directory and looks for specified object inside
* Returned object must be freed wtih supHeapFree when no longer needed.
*
* Note:
*
* OBJECT_DIRECTORY definition changed in Windows 10, however this doesn't require
* this routine change as we rely here only on HashBuckets which is on same offset.
*
*/
POBEX_OBJECT_INFORMATION ObpFindObjectInDirectory(
    _In_ PUNICODE_STRING ObjectName,
    _In_ ULONG_PTR DirectoryAddress
)
{
    BOOL bFound = FALSE;
    ULONG i;
    OBJECT_HEADER ObjectHeader;
    OBJECT_DIRECTORY DirectoryObject;
    OBJECT_DIRECTORY_ENTRY DirectoryEntry;

    ULONG_PTR ObjectHeaderAddress, HeadItem, LookupItem, InfoHeaderAddress;

    UNICODE_STRING NameString;

    RtlSecureZeroMemory(&DirectoryObject, sizeof(OBJECT_DIRECTORY));

    //
    // Read object directory at address.
    //
    if (!kdReadSystemMemory(DirectoryAddress,
        &DirectoryObject,
        sizeof(OBJECT_DIRECTORY)))
    {
        kdReportReadErrorSimple(__FUNCTIONW__, DirectoryAddress, sizeof(OBJECT_DIRECTORY));
        return NULL;
    }

    //
    // Check if root special case.
    //
    if (supIsRootDirectory(ObjectName)) {

        return ObpCopyObjectBasicInfo(DirectoryAddress,
            0,
            FALSE,
            NULL);

    }

    //
    // Not a root directory, scan given object directory.
    //
    for (i = 0; i < NUMBER_HASH_BUCKETS; i++) {

        HeadItem = (ULONG_PTR)DirectoryObject.HashBuckets[i];
        if (HeadItem != 0) {

            LookupItem = HeadItem;

            do {

                //
                // Read object directory entry, exit on fail.
                //
                RtlSecureZeroMemory(&DirectoryEntry, sizeof(OBJECT_DIRECTORY_ENTRY));

                if (!kdReadSystemMemory(LookupItem,
                    &DirectoryEntry,
                    sizeof(OBJECT_DIRECTORY_ENTRY)))
                {
                    kdReportReadErrorSimple(__FUNCTIONW__, LookupItem, sizeof(OBJECT_DIRECTORY_ENTRY));
                    break;
                }

                //
                // Read object header, skip entry on fail.
                //
                RtlSecureZeroMemory(&ObjectHeader, sizeof(OBJECT_HEADER));
                ObjectHeaderAddress = (ULONG_PTR)OBJECT_TO_OBJECT_HEADER(DirectoryEntry.Object);

                if (!kdReadSystemMemory(ObjectHeaderAddress,
                    &ObjectHeader,
                    sizeof(OBJECT_HEADER)))
                {
                    kdReportReadErrorSimple(__FUNCTIONW__, ObjectHeaderAddress, sizeof(OBJECT_HEADER));
                    goto NextItem;
                }

                //
                // Check if object has name, skip entry on fail.
                //
                InfoHeaderAddress = 0;

                if (!ObHeaderToNameInfoAddress(ObjectHeader.InfoMask,
                    ObjectHeaderAddress,
                    &InfoHeaderAddress,
                    HeaderNameInfoFlag))
                {
                    goto NextItem;
                }

                //
                // If object has name, query it.
                //
                if (ObQueryNameStringFromAddress(g_obexHeap,
                    InfoHeaderAddress,
                    &NameString))
                {
                    //
                    // Compare object name with what we look for.
                    //
                    bFound = RtlEqualUnicodeString(ObjectName, &NameString, TRUE);
                    supHeapFreeEx(g_obexHeap, NameString.Buffer);

                    if (bFound) {

                        return ObpCopyObjectBasicInfo(
                            (ULONG_PTR)DirectoryEntry.Object,
                            ObjectHeaderAddress,
                            TRUE,
                            &ObjectHeader);

                    }

                }

            NextItem:
                LookupItem = (ULONG_PTR)DirectoryEntry.ChainLink;

            } while (LookupItem != 0);


        } // HeadItem != 0
    } // for

    return NULL;
}
 
/*
* ObGetObjectAddressForDirectory
*
* Purpose:
*
* Obtain directory object kernel address by:
* 1) opening directory by name
* 2) quering resulted handle in NtQuerySystemInformation(SystemExtendedHandleInformation) handle dump
*
*/
_Success_(return)
BOOL ObGetObjectAddressForDirectory(
    _In_ PUNICODE_STRING DirectoryName,
    _Out_ PULONG_PTR lpRootAddress,
    _Out_opt_ PUSHORT lpTypeIndex
)
{
    BOOL bFound = FALSE;
    HANDLE hDirectory = NULL;

    if (!NT_SUCCESS(supOpenDirectoryEx(&hDirectory, NULL, DirectoryName, DIRECTORY_QUERY)))
        return FALSE;

    bFound = supQueryObjectFromHandle(hDirectory,
        lpRootAddress,
        lpTypeIndex);

    NtClose(hDirectory);
    
    return bFound;
}

/*
* ObQueryObjectInDirectory
*
* Purpose:
*
* Look for object inside specified directory.
* Returned object memory must be released with supHeapFree when object is no longer needed.
*
*/
POBEX_OBJECT_INFORMATION ObQueryObjectInDirectory(
    _In_ PUNICODE_STRING ObjectName,
    _In_ PUNICODE_STRING DirectoryName
)
{
    ULONG_PTR directoryAddress = 0;

    if (!kdConnectDriver())
        return NULL;

    if (!ObGetObjectAddressForDirectory(DirectoryName,
        &directoryAddress,
        NULL))
    {
        return NULL;
    }

    return ObpFindObjectInDirectory(ObjectName, directoryAddress);
}

/*
* ObGetProcessId
*
* Purpose:
*
* Read UniqueProcessId field from object of Process type.
*
*/
BOOL ObGetProcessId(
    _In_ ULONG_PTR ProcessObject,
    _Out_ PHANDLE UniqueProcessId
)
{
    ULONG_PTR kernelAddress;
    HANDLE processId = 0;

    *UniqueProcessId = NULL;

    if (g_kdctx.Data->PsUniqueProcessId.Valid == FALSE)
        return FALSE;

    kernelAddress = ProcessObject + g_kdctx.Data->PsUniqueProcessId.OffsetValue;

    if (!kdReadSystemMemory(kernelAddress, &processId, sizeof(processId)))
        return FALSE;

    *UniqueProcessId = processId;

    return TRUE;
}

/*
* ObGetProcessImageFileName
*
* Purpose:
*
* Read ImageFileName field from object of Process type.
*
*/
BOOL ObGetProcessImageFileName(
    _In_ ULONG_PTR ProcessObject,
    _Inout_ PUNICODE_STRING ImageFileName
)
{
    ULONG_PTR kernelAddress;
    CHAR szImageFileName[16];

    if (g_kdctx.Data->PsProcessImageName.Valid == FALSE)
        return FALSE;

    kernelAddress = ProcessObject + g_kdctx.Data->PsProcessImageName.OffsetValue;

    szImageFileName[0] = 0;

    if (!kdReadSystemMemory(kernelAddress, &szImageFileName, sizeof(szImageFileName)))
        return FALSE;

    return NT_SUCCESS(ntsupConvertToUnicode(szImageFileName, ImageFileName));
}

/*
* ObpEnumeratePrivateNamespaceTable
*
* Purpose:
*
* Enumerate Object Manager private namespace objects.
*
* Note:
*
* OBJECT_DIRECTORY definition changed in Windows 10, however this doesn't require
* this routine change as we rely here only on HashBuckets which is on same offset.
*
*/
BOOL ObpEnumeratePrivateNamespaceTable(
    _In_ ULONG_PTR TableAddress,
    _In_ PENUMERATE_PRIVATE_NAMESPACE_CALLBACK Callback,
    _In_opt_ PVOID Context
)
{
    BOOL          bStopEnumeration = FALSE;
    ULONG         i, j = 0;
    ULONG_PTR     ObjectHeaderAddress, HeadItem, LookupItem, InfoHeaderAddress;
    HANDLE        ListHeap = (HANDLE)Context;
    PLIST_ENTRY   Next, Head;
    LIST_ENTRY    ListEntry;
    POBJREF       ObjectEntry;

    OBJECT_HEADER                ObjectHeader;
    OBJECT_DIRECTORY             DirObject;
    OBJECT_DIRECTORY_ENTRY       Entry;
    OBJECT_NAMESPACE_LOOKUPTABLE LookupTable;
    OBJECT_NAMESPACE_ENTRY       LookupEntry;

    if (ListHeap == NULL)
        ListHeap = g_obexHeap;

    //
    // Dump namespace lookup table.
    //
    RtlSecureZeroMemory(&LookupTable, sizeof(OBJECT_NAMESPACE_LOOKUPTABLE));

    if (!kdReadSystemMemory(TableAddress,
        &LookupTable,
        sizeof(OBJECT_NAMESPACE_LOOKUPTABLE)))
    {
        return FALSE;
    }

    for (i = 0; i < NUMBER_HASH_BUCKETS; i++) {

        ListEntry = LookupTable.HashBuckets[i];

        Head = (PLIST_ENTRY)(TableAddress + (i * sizeof(LIST_ENTRY)));
        Next = ListEntry.Flink;

        while (Next != Head) {

            RtlSecureZeroMemory(&LookupEntry, sizeof(OBJECT_NAMESPACE_ENTRY));

            if (!kdReadSystemMemory((ULONG_PTR)Next,
                &LookupEntry,
                sizeof(OBJECT_NAMESPACE_ENTRY)))
            {
                break;
            }

            ListEntry = LookupEntry.ListEntry;

            RtlSecureZeroMemory(&DirObject, sizeof(OBJECT_DIRECTORY));

            if (!kdReadSystemMemory((ULONG_PTR)LookupEntry.NamespaceRootDirectory,
                &DirObject,
                sizeof(OBJECT_DIRECTORY)))
            {
                break;
            }

            for (j = 0; j < NUMBER_HASH_BUCKETS; j++) {

                HeadItem = (ULONG_PTR)DirObject.HashBuckets[j];
                if (HeadItem != 0) {

                    LookupItem = HeadItem;

                    do {

                        RtlSecureZeroMemory(&Entry, sizeof(OBJECT_DIRECTORY_ENTRY));

                        if (kdReadSystemMemory(LookupItem,
                            &Entry,
                            sizeof(OBJECT_DIRECTORY_ENTRY))) {

                            RtlSecureZeroMemory(&ObjectHeader, sizeof(OBJECT_HEADER));
                            ObjectHeaderAddress = (ULONG_PTR)OBJECT_TO_OBJECT_HEADER(Entry.Object);

                            if (kdReadSystemMemory(ObjectHeaderAddress,
                                &ObjectHeader,
                                sizeof(OBJECT_HEADER)))
                            {

                                //
                               // Allocate object entry
                               //
                                ObjectEntry = (POBJREF)supHeapAllocEx(ListHeap,
                                    sizeof(OBJREF));

                                if (ObjectEntry) {

                                    //
                                    // Save object address, header and type index.
                                    //
                                    ObjectEntry->ObjectAddress = (ULONG_PTR)Entry.Object;
                                    ObjectEntry->HeaderAddress = ObjectHeaderAddress;

                                    //
                                    // Save index as is (decoded if needed later).
                                    //
                                    ObjectEntry->TypeIndex = ObjectHeader.TypeIndex;

                                    //
                                    // Save object namespace/lookup entry address.
                                    //
                                    ObjectEntry->PrivateNamespace.NamespaceDirectoryAddress =
                                        (ULONG_PTR)LookupEntry.NamespaceRootDirectory;

                                    ObjectEntry->PrivateNamespace.NamespaceLookupEntry =
                                        (ULONG_PTR)Next;

                                    ObjectEntry->PrivateNamespace.SizeOfBoundaryInformation =
                                        LookupEntry.SizeOfBoundaryInformation;

                                    //
                                    // Query object name.
                                    //
                                    InfoHeaderAddress = 0;

                                    if (ObHeaderToNameInfoAddress(ObjectHeader.InfoMask,
                                        ObjectHeaderAddress,
                                        &InfoHeaderAddress,
                                        HeaderNameInfoFlag))
                                    {
                                        //
                                        // Copy object name if exist.
                                        //
                                        ObQueryNameStringFromAddress(ListHeap, InfoHeaderAddress, &ObjectEntry->Name);

                                    }

                                    bStopEnumeration = Callback(ObjectEntry, Context);
                                    if (bStopEnumeration)
                                        return TRUE;

                                } //if (ObjectEntry)
                            }
                            LookupItem = (ULONG_PTR)Entry.ChainLink;
                        }
                        else {
                            LookupItem = 0;
                        }
                    } while (LookupItem != 0);
                }
            }

            Next = ListEntry.Flink;
        }
    }

    return TRUE;
}

/*
* ObEnumeratePrivateNamespaceTable
*
* Purpose:
*
* Enumerate Object Manager private namespace objects.
*
*/
BOOL ObEnumeratePrivateNamespaceTable(
    _In_ PENUMERATE_PRIVATE_NAMESPACE_CALLBACK Callback,
    _In_opt_ PVOID Context
)
{
    if (!kdConnectDriver())
        return FALSE;

    if (g_kdctx.Data->PrivateNamespaceLookupTable == NULL)
        g_kdctx.Data->PrivateNamespaceLookupTable = ObFindPrivateNamespaceLookupTable(&g_kdctx);

    if (g_kdctx.Data->PrivateNamespaceLookupTable == NULL)
        return FALSE;

    return ObpEnumeratePrivateNamespaceTable(
        (ULONG_PTR)g_kdctx.Data->PrivateNamespaceLookupTable,
        Callback,
        Context);
}

typedef struct _OB_NAME_ELEMENT {
    LIST_ENTRY ListEntry;
    UNICODE_STRING Name;
} OB_NAME_ELEMENT, * POB_NAME_ELEMENT;

BOOL ObpAddNameElementEntry(
    _In_ PLIST_ENTRY ListHead,
    _In_ PUNICODE_STRING ElementName
)
{
    POB_NAME_ELEMENT pObElement;

    pObElement = (POB_NAME_ELEMENT)supHeapAlloc(sizeof(OB_NAME_ELEMENT));
    if (pObElement == NULL)
        return FALSE;

    pObElement->Name = *ElementName;

    InsertHeadList(ListHead, &pObElement->ListEntry);

    return TRUE;
}

BOOL ObpDumpNameElementSpecial(
    _In_ PLIST_ENTRY ListHead,
    _In_ LPWSTR SpecialElement,
    _In_ ULONG Size
)
{
    UNICODE_STRING element;

    element.Buffer = (PWSTR)supHeapAlloc(Size + sizeof(UNICODE_NULL));

    if (element.Buffer == NULL) {
        return FALSE;
    }
    
    _strcpy(element.Buffer, SpecialElement);
    element.Length = (USHORT)(Size - sizeof(UNICODE_NULL));
    element.MaximumLength = (USHORT)Size;

    if (!ObpAddNameElementEntry(ListHead, &element)) {
        supHeapFree(element.Buffer);
        return FALSE;
    }

    return TRUE;
}

BOOL ObpDumpNameElement(
    _In_ PLIST_ENTRY ListHead,
    _In_ POBJECT_HEADER_NAME_INFO NameInformation,
    _Out_ PSIZE_T ElementLength
)
{
    USHORT nameLength;
    LPWSTR stringBuffer;
    UNICODE_STRING element;

    *ElementLength = 0;

    nameLength = NameInformation->Name.Length;
    if (nameLength == 0)
        return FALSE;

    stringBuffer = (LPWSTR)supHeapAlloc(nameLength + sizeof(UNICODE_NULL));
    if (stringBuffer == NULL) {
        return FALSE;
    }

    if (!kdReadSystemMemory((ULONG_PTR)NameInformation->Name.Buffer,
        stringBuffer,
        nameLength))
    {
        supHeapFree(stringBuffer);
        return FALSE;
    }

    element.Buffer = stringBuffer;
    element.Length = nameLength;
    element.MaximumLength = nameLength + sizeof(UNICODE_NULL);

    if (!ObpAddNameElementEntry(ListHead, &element)) {
        supHeapFree(stringBuffer);
        return FALSE;
    }

    *ElementLength = nameLength;

    return TRUE;
}

SIZE_T ObpDumpObjectName(
    _In_ PLIST_ENTRY ListHead,
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG_PTR NextObject
)
{
    ULONG_PTR lookupObject = ObjectAddress;
    ULONG_PTR objectHeaderAddress;
    ULONG_PTR headerInfoAddress;
    OBJECT_HEADER objectHeader;
    OBJECT_HEADER_NAME_INFO nameInfo;
    SIZE_T pathLength = 0;

    *NextObject = 0;

    //
    // Process object first.
    //
    objectHeaderAddress = (ULONG_PTR)OBJECT_TO_OBJECT_HEADER(lookupObject);
    RtlSecureZeroMemory(&objectHeader, sizeof(OBJECT_HEADER));
    if (!kdReadSystemMemory(objectHeaderAddress,
        &objectHeader,
        sizeof(OBJECT_HEADER)))
    {
        //
        // Nothing to process, object header is not available.
        //
        return 0;
    }

    //
    // Query OBJECT_HEADER_NAME_INFO address
    //
    headerInfoAddress = 0;
    if (!ObHeaderToNameInfoAddress(objectHeader.InfoMask,
        objectHeaderAddress,
        &headerInfoAddress,
        HeaderNameInfoFlag))
    {
        //
        // Nothing to process, object is unnamed.
        //
        return 0;
    }

    //
    // Dump OBJECT_HEADER_NAME_INFO
    //
    RtlSecureZeroMemory(&nameInfo, sizeof(nameInfo));

    if (!kdReadSystemMemory(headerInfoAddress,
        &nameInfo,
        sizeof(nameInfo)))
    {
        ObpDumpNameElementSpecial(ListHead, OBP_ERROR_NAME_LITERAL, OBP_ERROR_NAME_LITERAL_SIZE);
        return OBP_ERROR_NAME_LITERAL_SIZE + sizeof(OBJ_NAME_PATH_SEPARATOR);
    }

    *NextObject = (ULONG_PTR)nameInfo.Directory;

    if (ObpDumpNameElement(ListHead, &nameInfo, &pathLength))
        return pathLength + sizeof(OBJ_NAME_PATH_SEPARATOR);

    return 0;
}

/*
* ObQueryFullNamespacePath
*
* Purpose:
*
* This routine if possible builds full object namespace path for given object.
*
*/
_Success_(return)
BOOL ObQueryFullNamespacePath(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PUNICODE_STRING Path
)
{
    BOOL bResult = FALSE;
    ULONG_PTR LookupObject = ObjectAddress, NextObject;
    LIST_ENTRY ListHead;
    PLIST_ENTRY Next;
    POB_NAME_ELEMENT pathElement;
    PWSTR stringBuffer = NULL, string;
    SIZE_T memIO, length;

    UNICODE_STRING resultPath;

    if (LookupObject == g_kdctx.DirectoryRootObject) {

        return supDuplicateUnicodeString(g_obexHeap,
            Path,
            ObGetPredefinedUnicodeString(OBP_ROOT));

    }

    InitializeListHead(&ListHead);
    memIO = 0;

    while ((LookupObject != g_kdctx.DirectoryRootObject) && (LookupObject != 0)) {

        NextObject = 0;
        memIO += ObpDumpObjectName(&ListHead, LookupObject, &NextObject);
        if (memIO > UNICODE_STRING_MAX_BYTES)
            break;

        LookupObject = NextObject;
    }

    //
    // Build path.
    //
    if (!IsListEmpty(&ListHead)) {

        stringBuffer = (PWSTR)supHeapAlloc(memIO + sizeof(UNICODE_NULL));
        if (stringBuffer) {

            resultPath.MaximumLength = (USHORT)memIO + sizeof(UNICODE_NULL);
            resultPath.Buffer = stringBuffer;

            string = stringBuffer;
            length = 0;

            Next = ListHead.Flink;
            while ((Next != NULL) && (Next != &ListHead)) {

                pathElement = CONTAINING_RECORD(Next, OB_NAME_ELEMENT, ListEntry);
                
                *string++ = OBJ_NAME_PATH_SEPARATOR; 
                length += sizeof(OBJ_NAME_PATH_SEPARATOR);
                
                RtlCopyMemory(string, pathElement->Name.Buffer, pathElement->Name.Length);
                string = (PWSTR)RtlOffsetToPointer(string, pathElement->Name.Length);
                length += pathElement->Name.Length;
                
                supFreeUnicodeString(g_obexHeap, &pathElement->Name);

                Next = Next->Flink;

            }

            resultPath.Length = (USHORT)length;
            *Path = resultPath;
            bResult = TRUE;
        }

    }

    return bResult;
}

/*
* kdConnectDriver
*
* Purpose:
*
* Acquire handle of helper driver device if possible.
*
*/
BOOLEAN kdConnectDriver(
    VOID)
{
    WDRV_PROVIDER *provider;

    if (kdIoDriverLoaded()) return TRUE;

    provider = g_kdctx.DriverContext.Provider;

    if (provider == NULL) return FALSE;

    return NT_SUCCESS(provider->Callbacks.OpenDriver(&g_kdctx.DriverContext));
}

/*
* kdIoDriverLoaded
*
* Purpose:
*
* Return state of helper driver.
*
* N.B.
*
*   If current token is not elevated admin token function return FALSE.
*   If device handle is already present function return TRUE.
*
*/
BOOLEAN kdIoDriverLoaded(
    VOID)
{
    if (g_kdctx.IsFullAdmin == FALSE)
        return FALSE;

    if (g_kdctx.DriverContext.DeviceHandle != NULL)
        return TRUE;

    return FALSE;
}

/*
* kdGetAlpcPortTypeIndex
*
* Purpose:
*
* Return type index of ALPC Port object.
*
*/
USHORT kdGetAlpcPortTypeIndex()
{
    USHORT typeIndex = MAXWORD;

    if (g_kdctx.Data->AlpcPortTypeIndex.Valid == FALSE)
        supQueryAlpcPortObjectTypeIndex(&g_kdctx.Data->AlpcPortTypeIndex);

    if (g_kdctx.Data->AlpcPortTypeIndex.Valid)
        typeIndex = g_kdctx.Data->AlpcPortTypeIndex.TypeIndex;

    return typeIndex;
}

/*
* kdQueryIopInvalidDeviceRequest
*
* Purpose:
*
* Find IopInvalidDeviceRequest.
*
* 1. If symbols available - lookup value from them;
*
* 2. If they are not or there is an error, assume Windows assigned value to our helper driver IRP_MJ_CREATE_MAILSLOT.
*
* wo/kldbgdrv/winio only defined:
*    IRP_MJ_CREATE
*    IRP_MJ_CLOSE
*    IRP_MJ_DEVICE_CONTROL
*
* rkhdrv 5+ versions does not define own IRP_MJ_CREATE_MAILSLOT
*
*/
PVOID kdQueryIopInvalidDeviceRequest(
    VOID
)
{
    PVOID           pHandler = NULL;
    ULONG_PTR       drvObjectAddress;
    DRIVER_OBJECT   drvObject;
    PWDRV_PROVIDER  drvProvider;

    POBEX_OBJECT_INFORMATION selfDriverObject;

    UNICODE_STRING usDirectory, usName;

    //
    // Lookup using symbols.
    //
    if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {

        kdGetAddressFromSymbol(
            &g_kdctx,
            KVAR_IopInvalidDeviceRequest,
            (ULONG_PTR*)&pHandler);

    }

    //
    // Lookup from our helper driver object.
    //
    if (pHandler == NULL) {

        drvProvider = g_kdctx.DriverContext.Provider;
        if (drvProvider) {

            RtlInitUnicodeString(&usName, drvProvider->DriverName);
            RtlInitUnicodeString(&usDirectory, L"\\Driver");
            selfDriverObject = ObQueryObjectInDirectory(&usName, &usDirectory);
            if (selfDriverObject) {

                drvObjectAddress = selfDriverObject->ObjectAddress;

                RtlSecureZeroMemory(&drvObject, sizeof(drvObject));

                if (kdReadSystemMemory(drvObjectAddress,
                    &drvObject,
                    sizeof(drvObject)))
                {
                    pHandler = drvObject.MajorFunction[IRP_MJ_CREATE_MAILSLOT];

                    //
                    // IopInvalidDeviceRequest is a routine inside ntoskrnl.
                    //
                    if (!kdAddressInNtOsImage(pHandler)) {
                        pHandler = NULL;
                    }
                }
                supHeapFree(selfDriverObject);
            }
        }
    }
    return pHandler;
}

/*
* kdReportErrorByFunction
*
* Purpose:
*
* Log details about failed function call.
*
*/
VOID kdReportErrorByFunction(
    _In_ LPCWSTR FunctionName,
    _In_ LPCWSTR ErrorMessage
)
{
    WCHAR szBuffer[WOBJ_MAX_MESSAGE];
    
    RtlStringCchPrintfSecure(szBuffer,
        ARRAYSIZE(szBuffer),
        TEXT("%ws, %ws"),
        FunctionName, ErrorMessage);

    logAdd(EntryTypeError,
        szBuffer);
}

/*
* kdReportReadErrorSimple
*
* Purpose:
*
* Log details about failed driver call without additional info.
*
*/
VOID kdReportReadErrorSimple(
    _In_ LPCWSTR FunctionName,
    _In_ ULONG_PTR KernelAddress,
    _In_ ULONG InputBufferLength
)
{
    WCHAR szBuffer[512];

    RtlStringCchPrintfSecure(szBuffer,
        ARRAYSIZE(szBuffer),
        TEXT("%ws read at 0x%llX, InputBufferLength 0x%lX"),
        FunctionName,
        KernelAddress,
        InputBufferLength);

    logAdd(EntryTypeError,
        szBuffer);
}

/*
* kdReportReadError
*
* Purpose:
*
* Log details about failed driver call.
*
*/
VOID kdReportReadError(
    _In_ LPCWSTR FunctionName,
    _In_ ULONG_PTR KernelAddress,
    _In_ ULONG InputBufferLength,
    _In_ NTSTATUS Status,
    _In_ PIO_STATUS_BLOCK Iosb
)
{
    WCHAR szBuffer[512];

    RtlStringCchPrintfSecure(szBuffer,
        RTL_NUMBER_OF(szBuffer),
        TEXT("%ws 0x%lX, read at 0x%llX, Iosb(0x%lX, 0x%lX), InputBufferLength 0x%lX"),
        FunctionName,
        Status,
        KernelAddress,
        Iosb->Status,
        Iosb->Information,
        InputBufferLength);

    logAdd(EntryTypeError,
        szBuffer);
}

/*
* kdReadSystemMemory2
*
* Purpose:
*
* Read system memory through driver callback.
*
*/
BOOL kdReadSystemMemory2(
    _In_opt_ LPCWSTR CallerFunction,
    _In_ ULONG_PTR Address,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG NumberOfBytesRead
)
{
    NTSTATUS ntStatus;
    ULONG numberOfBytesRead = 0;
    LPCWSTR lpSrcFunction;
    IO_STATUS_BLOCK iost;

    PWDRV_CONTEXT driverContext = &g_kdctx.DriverContext;

    if (NumberOfBytesRead)
        *NumberOfBytesRead = 0;

    if (driverContext->Provider == NULL) {
        return FALSE;
    }

    if (driverContext->Provider->Callbacks.ReadSystemMemory == NULL) {
        return FALSE;
    }

    BOOL bResult = driverContext->Provider->Callbacks.ReadSystemMemory(driverContext,
        Address,
        Buffer,
        BufferSize,
        &numberOfBytesRead);

    if (NumberOfBytesRead)
        *NumberOfBytesRead = numberOfBytesRead;

    if (CallerFunction)
        lpSrcFunction = CallerFunction;
    else
        lpSrcFunction = __FUNCTIONW__;

    ntStatus = driverContext->LastNtStatus;

    if (bResult == FALSE) {
        kdReportReadError(lpSrcFunction, Address, BufferSize, ntStatus, &driverContext->IoStatusBlock);
    }
    else {
        //
        // Incomplete read.
        //
        if (numberOfBytesRead != BufferSize) {
            iost.Status = STATUS_PARTIAL_COPY;
            iost.Information = numberOfBytesRead;
            kdReportReadError(lpSrcFunction, Address, BufferSize, ntStatus, &iost);
        }
    }

    return bResult;
}

/*
* kdLoadSymbolsForNtImage
*
* Purpose:
*
* Load symbols for OS mapped image.
*
*/
BOOL kdLoadSymbolsForNtImage(
    _In_ PSYMCONTEXT SymContext,
    _In_ LPCWSTR ImageFileName,
    _In_ PVOID ImageBase,
    _In_ DWORD SizeOfImage
)
{
    BOOL bResult = FALSE;

    if (SymContext == NULL)
        return FALSE;

    if (SymContext->ModuleBase != 0)
        return TRUE;

    supDisplayLoadBanner(TEXT("Please wait...\r\n"), TEXT("Symbols loading"));

    bResult = SymContext->Parser.LoadModule(
        SymContext,
        ImageFileName,
        (DWORD64)ImageBase,
        SizeOfImage);

    Sleep(100);
    supCloseLoadBanner();

    return bResult;
}

/*
* kdLoadNtKernelImage
*
* Purpose:
*
* Query ntoskrnl name, load it as image and prepare symbols.
*
*/
BOOL kdLoadNtKernelImage(
    _In_ PKLDBGCONTEXT Context
)
{
    PUCHAR pModuleName;
    PRTL_PROCESS_MODULES pModulesList = NULL;

    WCHAR szFileName[(4 + MAX_PATH) * 2];

    pModulesList = (PRTL_PROCESS_MODULES)supGetLoadedModulesList(NULL);
    if (pModulesList) {

        _strcpy(szFileName, g_WinObj.szSystemDirectory);
        _strcat(szFileName, TEXT("\\"));

        Context->NtOsBase = pModulesList->Modules[0].ImageBase; //loaded kernel base
        Context->NtOsSize = pModulesList->Modules[0].ImageSize; //loaded kernel size

        pModuleName = &pModulesList->Modules[0].FullPathName[
            pModulesList->Modules[0].OffsetToFileName];

        MultiByteToWideChar(
            CP_ACP,
            0,
            (LPCSTR)pModuleName,
            -1,
            _strend(szFileName),
            MAX_PATH);

        supHeapFree(pModulesList);

        Context->NtOsImageMap = LoadLibraryEx(
            szFileName,
            NULL,
            DONT_RESOLVE_DLL_REFERENCES);

        if (Context->NtOsImageMap) {
           
            kdLoadSymbolsForNtImage(
                (PSYMCONTEXT)g_kdctx.NtOsSymContext,
                szFileName,
                Context->NtOsImageMap,
                0);

        }

    }

    return (Context->NtOsImageMap != NULL);
}

/*
* kdQuerySystemInformation
*
* Purpose:
*
* Query required system information and offsets.
*
*/
BOOL kdQuerySystemInformation(
    _In_ PVOID lpParameter
)
{
    PKLDBGCONTEXT Context = (PKLDBGCONTEXT)lpParameter;

    if (Context->IsFullAdmin) {
        //
        // Query "\\" directory address and remember directory object type index.
        //
        ObGetObjectAddressForDirectory(ObGetPredefinedUnicodeString(OBP_ROOT),
            &Context->DirectoryRootObject,
            &Context->DirectoryTypeIndex);
    }

    //
    // Remember system range start value.
    //
    Context->SystemRangeStart = supQuerySystemRangeStart();
    if (Context->SystemRangeStart == 0) {
        if (g_NtBuildNumber < NT_WIN8_RTM) {
            Context->SystemRangeStart = MM_SYSTEM_RANGE_START_7;
        }
        else {
            Context->SystemRangeStart = MM_SYSTEM_RANGE_START_8;
        }
    }

    //
    // Query user mode accessible ranges.
    //
    if (!supQueryUserModeAccessibleRange(
        &Context->MinimumUserModeAddress,
        &Context->MaximumUserModeAddress))
    {
        Context->MinimumUserModeAddress = 0x10000;
        Context->MaximumUserModeAddress = 0x00007FFFFFFEFFFF;
    }

    supIsBootDriveVHD(&Context->IsOsDiskVhd);
    supGetFirmwareType(&Context->Data->FirmwareType);

    return kdLoadNtKernelImage(Context);
}

/*
* kdGetInstructionLength
*
* Purpose:
*
* Wrapper for hde64_disasm.
*
*/
UCHAR kdGetInstructionLength(
    _In_ PVOID ptrCode,
    _Out_ PULONG ptrFlags)
{
    hde64s  hs;

    __try {

        hde64_disasm((void*)ptrCode, &hs);
        if (hs.flags & F_ERROR) {
            *ptrFlags = hs.flags;
            return 0;
        }
        *ptrFlags = hs.flags;
        return hs.len;
    }
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
        return 0;
    }
}

/*
* kdpQueryMmUnloadedDrivers
*
* Purpose:
*
* Locate MmUnloadedDrivers array address.
*
*/
BOOLEAN kdpQueryMmUnloadedDrivers(
    _In_ PKLDBGCONTEXT Context
)
{
    HMODULE   hNtOs;
    ULONG_PTR NtOsBase, lookupAddress = 0;

    PBYTE     ptrCode, sigPattern;
    PVOID     SectionBase;
    ULONG     SectionSize = 0;

    ULONG     sigSize;

    ULONG     Index = 0, instLength = 0, tempOffset;
    LONG      relativeValue = 0;
    hde64s    hs;

    PKLDBG_SYSTEM_ADDRESS kdpMmUnloadedDrivers = &Context->Data->MmUnloadedDrivers;

    if (kdpMmUnloadedDrivers->Valid)
        return TRUE;

    NtOsBase = (ULONG_PTR)g_kdctx.NtOsBase;
    hNtOs = (HMODULE)g_kdctx.NtOsImageMap;

    do {

        //
        // Symbols lookup.
        //
        if (kdIsSymAvailable((PSYMCONTEXT)g_kdctx.NtOsSymContext)) {

            kdGetAddressFromSymbol(
                &g_kdctx,
                KVAR_MmUnloadedDrivers,
                &lookupAddress);

        }

        //
        // Pattern search.
        //
        if (lookupAddress == 0) {

            //
            // Locate PAGE image section.
            //
            SectionBase = supLookupImageSectionByName(PAGE_SECTION,
                PAGE_SECTION_LENGTH,
                (PVOID)hNtOs,
                &SectionSize);

            if ((SectionBase == 0) || (SectionSize == 0))
                break;

            if (g_NtBuildNumber < NT_WIN10_20H1) {

                if (g_NtBuildNumber == NT_WIN10_THRESHOLD1)
                    MiRememberUnloadedDriverPattern[0] = FIX_WIN10_THRESHOULD_REG;

                sigPattern = MiRememberUnloadedDriverPattern;
                sigSize = sizeof(MiRememberUnloadedDriverPattern);

            }
            else {

                //
                // Use 19041+ specific pattern as an array allocation code has been changed.
                //

                sigPattern = MiRememberUnloadedDriverPattern2;
                sigSize = sizeof(MiRememberUnloadedDriverPattern2);

            }

            ptrCode = (PBYTE)supFindPattern((PBYTE)SectionBase,
                SectionSize,
                sigPattern,
                sigSize);

            if (ptrCode == NULL)
                break;

            if (RtlPointerToOffset(SectionBase, ptrCode) + sigSize + 32 > SectionSize)
                break;

            Index = sigSize;
            tempOffset = 0;

            do {

                hde64_disasm(RtlOffsetToPointer(ptrCode, Index), &hs);
                if (hs.flags & F_ERROR)
                    break;

                instLength = hs.len;

                //
                // Call ExAlloc/MiAlloc
                //
                if (instLength == 5) {

                    if (ptrCode[Index] == 0xE8) {

                        //
                        // Fetch next instruction
                        //
                        tempOffset = Index + instLength;

                        hde64_disasm(RtlOffsetToPointer(ptrCode, tempOffset), &hs);
                        if (hs.flags & F_ERROR)
                            break;

                        //
                        // Must be MOV
                        //
                        if (hs.len == 7) {

                            if (ptrCode[tempOffset] == 0x48) {

                                Index = tempOffset;
                                instLength = hs.len;

                                relativeValue = *(PLONG)(ptrCode + tempOffset + (hs.len - 4));
                                break;

                            }

                        }
                    }

                }

                Index += instLength;

            } while (Index < 32);

            if ((relativeValue == 0) || (instLength == 0))
                break;

            //
            // Resolve MmUnloadedDrivers.
            //
            lookupAddress = kdAdjustAddressToNtOsBase((ULONG_PTR)ptrCode, Index, instLength, relativeValue);
            if (!kdAddressInNtOsImage((PVOID)lookupAddress))
                break;

        }

        //
        // Read ptr value.
        //
        if (!kdReadSystemMemory(lookupAddress, &lookupAddress, sizeof(ULONG_PTR)))
            break;

        //
        // Store resolved array address in the private data context.
        //
        kdpMmUnloadedDrivers->Address = lookupAddress;
        kdpMmUnloadedDrivers->Valid = TRUE;

    } while (FALSE);

    return kdpMmUnloadedDrivers->Valid;
}

/*
* kdEnumerateMmUnloadedDrivers
*
* Purpose:
*
* Locate unloaded drivers array and walk through it entries.
*
*/
BOOL kdEnumerateMmUnloadedDrivers(
    _In_ PENUMERATE_UNLOADED_DRIVERS_CALLBACK Callback,
    _In_opt_ PVOID Context
)
{
    BOOL                bResult = FALSE, bStopEnumeration = FALSE;
    HMODULE             hNtOs;
    ULONG_PTR           NtOsBase, lookupAddress = 0;

    ULONG               bytesRead = 0;

    PUNLOADED_DRIVERS   pvDrivers = NULL;
    PWCHAR              pwStaticBuffer = NULL;
    WORD                wMax, wLength;

    ULONG               cbData;

    ULONG               Index = 0;

    PKLDBG_SYSTEM_ADDRESS kdpMmUnloadedDrivers = &g_kdctx.Data->MmUnloadedDrivers;

    NtOsBase = (ULONG_PTR)g_kdctx.NtOsBase;
    hNtOs = (HMODULE)g_kdctx.NtOsImageMap;

    if (!kdpQueryMmUnloadedDrivers(&g_kdctx))
        return FALSE;

    pwStaticBuffer = (PWCHAR)supHeapAlloc(UNICODE_STRING_MAX_BYTES + sizeof(UNICODE_NULL));
    if (pwStaticBuffer == NULL)
        return FALSE;

    lookupAddress = kdpMmUnloadedDrivers->Address;

    //
    // Dump array to user mode.
    //
    cbData = MI_UNLOADED_DRIVERS * sizeof(UNLOADED_DRIVERS);
    pvDrivers = (PUNLOADED_DRIVERS)supHeapAlloc(cbData);
    if (pvDrivers) {

        bResult = kdReadSystemMemory(lookupAddress, pvDrivers, cbData);

        if (bResult) {

            for (Index = 0; Index < MI_UNLOADED_DRIVERS; Index++) {

                wMax = pvDrivers[Index].Name.MaximumLength;
                wLength = pvDrivers[Index].Name.Length;

                if ((wMax && wLength) && (wLength <= wMax)) {

                    lookupAddress = (ULONG_PTR)pvDrivers[Index].Name.Buffer;
                    bytesRead = wMax;
                    *pwStaticBuffer = 0;

                    if (!kdReadSystemMemoryEx(lookupAddress,
                        pwStaticBuffer,
                        bytesRead,
                        &bytesRead))
                    {
                        bResult = FALSE;
                        break;
                    }

                    pwStaticBuffer[bytesRead / sizeof(WCHAR)] = 0;

                    if (RtlCreateUnicodeString(&pvDrivers[Index].Name,
                        pwStaticBuffer))
                    {

                        if (Callback(&pvDrivers[Index], Context))
                            bStopEnumeration = TRUE;

                        RtlFreeUnicodeString(&pvDrivers[Index].Name);

                        if (bStopEnumeration)
                            break;
                    }
                }
            } //for

            supHeapFree(pvDrivers);

        }
    }

    supHeapFree(pwStaticBuffer);

    return bResult;
}

/*
* kdDestroyShimmedDriversList
*
* Purpose:
*
* Remove all items from shimmed drivers list and free memory.
*
*/
VOID kdDestroyShimmedDriversList(
    _In_ PKSE_ENGINE_DUMP KseEngineDump
)
{
    PLIST_ENTRY ListHead, Entry, NextEntry;
    KSE_SHIMMED_DRIVER* Item;

    ListHead = &KseEngineDump->ShimmedDriversDumpListHead;

    ASSERT_LIST_ENTRY_VALID(ListHead);

    if (IsListEmpty(ListHead))
        return;

    for (Entry = ListHead->Flink, NextEntry = Entry->Flink;
        Entry != ListHead;
        Entry = NextEntry, NextEntry = Entry->Flink)
    {
        Item = CONTAINING_RECORD(Entry, KSE_SHIMMED_DRIVER, ListEntry);
        RemoveEntryList(Entry);
        supHeapFree(Item);
    }
}

/*
* kdQueryKernelShims
*
* Purpose:
*
* Dump kernel shims information.
*
*/
BOOLEAN kdQueryKernelShims(
    _In_ PKLDBGCONTEXT Context,
    _In_ BOOLEAN RefreshList
)
{
    PBYTE      ptrCode;
    ULONG_PTR  lookupAddress = 0;

    BOOLEAN  KseEngineDumpValid = FALSE;

    ULONG_PTR NtOsBase;
    HMODULE hNtOs;

    ULONG_PTR KseShimmedDriversListHead;
    LIST_ENTRY ListEntry;
    KSE_SHIMMED_DRIVER* ShimmedDriver;

    PKSE_ENGINE_DUMP pKseEngineDump = &Context->Data->KseEngineDump;

    if (!kdConnectDriver())
        return FALSE;

    __try {

        //
        // If KseEngine not dumped, locate variable.
        //
        if (pKseEngineDump->Valid == FALSE) {

            //
            // If symbols available then lookup kernel variable address from them.
            //
            if (kdIsSymAvailable((PSYMCONTEXT)Context->NtOsSymContext)) {

                kdGetAddressFromSymbol(
                    Context,
                    KVAR_KseEngine,
                    &lookupAddress);

            }

            //
            // Lookup kernel variable address by pattern search.
            //
            if (lookupAddress == 0) {

                NtOsBase = (ULONG_PTR)Context->NtOsBase;
                hNtOs = (HMODULE)Context->NtOsImageMap;

                ptrCode = (PBYTE)GetProcAddress(hNtOs, "KseSetDeviceFlags");
                if (ptrCode == NULL) {
                    logAdd(EntryTypeError, TEXT("KseSetDeviceFlags not found"));
                    return FALSE;
                }

                lookupAddress = ObFindAddress(NtOsBase,
                    (ULONG_PTR)hNtOs,
                    IL_KseEngine,
                    ptrCode,
                    DA_ScanBytesKseEngine,
                    KseEnginePattern,
                    sizeof(KseEnginePattern));

                if (lookupAddress)
                    lookupAddress -= FIELD_OFFSET(KSE_ENGINE, State);

            }

            if (!kdAddressInNtOsImage((PVOID)lookupAddress)) {
                logAdd(EntryTypeError, TEXT("KseEngine address is invalid"));
                return FALSE;
            }

            pKseEngineDump->KseAddress = lookupAddress;
        }

        //
        // Reinitialize output list in case of refresh.
        //
        if (RefreshList) {
            kdDestroyShimmedDriversList(pKseEngineDump);
            InitializeListHead(&pKseEngineDump->ShimmedDriversDumpListHead);
        }

        //
        // Dump KseEngine double linked list.
        //

        KseShimmedDriversListHead = pKseEngineDump->KseAddress + FIELD_OFFSET(KSE_ENGINE, ShimmedDriversListHead);
        KseEngineDumpValid = TRUE;

        ListEntry.Blink = ListEntry.Flink = NULL;

        if (kdReadSystemMemory(KseShimmedDriversListHead,
            &ListEntry,
            sizeof(LIST_ENTRY)))
        {
            while ((ULONG_PTR)ListEntry.Flink != KseShimmedDriversListHead) {

                ShimmedDriver = (KSE_SHIMMED_DRIVER*)supHeapAlloc(sizeof(KSE_SHIMMED_DRIVER));
                if (ShimmedDriver == NULL) {
                    KseEngineDumpValid = FALSE;
                    break;
                }

                if (!kdReadSystemMemory((ULONG_PTR)ListEntry.Flink,
                    ShimmedDriver,
                    sizeof(KSE_SHIMMED_DRIVER)))
                {
                    supHeapFree(ShimmedDriver);
                    KseEngineDumpValid = FALSE;
                    logAdd(EntryTypeError, TEXT("KseEngine entry read error"));
                    break;
                }

                ListEntry.Flink = ShimmedDriver->ListEntry.Flink;
                InsertHeadList(&pKseEngineDump->ShimmedDriversDumpListHead, &ShimmedDriver->ListEntry);
            }
        }
        else {
            logAdd(EntryTypeError, TEXT("KseEngine->ShimmedDriversListHead read error"));
            KseEngineDumpValid = FALSE;
        }

        pKseEngineDump->Valid = KseEngineDumpValid;

    }
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
        return FALSE;
    }

    return KseEngineDumpValid;
}

/*
* kdQueryCmControlVector
*
* Purpose:
*
* Return address of CmControlVector data array in mapped kernel.
*
*/
PVOID kdQueryCmControlVector(
    _In_ PKLDBGCONTEXT Context
)
{
    ULONG i, Offset;
    ULONG SectionSize;
    ULONG_PTR PatternValue = 0, TestValue;
    PVOID CmControlVector = NULL;
    PBYTE SectionBase;
    PBYTE RefPointer;
    IMAGE_NT_HEADERS* NtHeaders = RtlImageNtHeader(Context->NtOsImageMap);
    IMAGE_SECTION_HEADER* SectionTableEntry;

    WCHAR szSignature[] = L"ProtectionMode";

    SectionTableEntry = IMAGE_FIRST_SECTION(NtHeaders);

    for (i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++, SectionTableEntry++) {

        SectionBase = (PBYTE)Context->NtOsImageMap + SectionTableEntry->VirtualAddress;
        SectionSize = SectionTableEntry->Misc.VirtualSize;

        PatternValue = (ULONG_PTR)supFindPattern(SectionBase,
            SectionSize,
            (CONST PBYTE)szSignature,
            sizeof(szSignature));

        if (PatternValue)
            break;
    }

    if (PatternValue == 0)
        return NULL;

    SectionTableEntry = IMAGE_FIRST_SECTION(NtHeaders);

    for (i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++, SectionTableEntry++) {

        SectionBase = (PBYTE)Context->NtOsImageMap + SectionTableEntry->VirtualAddress;
        SectionSize = SectionTableEntry->Misc.VirtualSize;
        for (Offset = 0; Offset < SectionSize - sizeof(ULONG_PTR); Offset++) {

            RefPointer = SectionBase + Offset;
            TestValue = *(PULONG_PTR)RefPointer;
            if (TestValue == PatternValue) {
                CmControlVector = RefPointer - sizeof(ULONG_PTR);
                break;
            }
        }

        if (CmControlVector)
            break;
    }

    return CmControlVector;
}

/*
* kdIsSymAvailable
*
* Purpose:
*
* Return TRUE if symbols context is initialized.
*
*/
BOOLEAN kdIsSymAvailable(
    _In_opt_ SYMCONTEXT* SymContext
)
{
    if (SymContext == NULL)
        return FALSE;

    if (SymContext->ModuleBase == 0)
        return FALSE;

    return TRUE;
}

/*
* kdGetFieldOffsetFromSymbol
*
* Purpose:
*
* Get field offset by it name of the ntoskrnl symbol and the offset.
*
*/
BOOL kdGetFieldOffsetFromSymbol(
    _In_ KLDBGCONTEXT* Context,
    _In_ LPCWSTR SymbolName,
    _In_ LPCWSTR FieldName,
    _Out_ ULONG* Offset
)
{
    BOOL bResult = FALSE;
    PSYMCONTEXT symContext = (PSYMCONTEXT)Context->NtOsSymContext;

    *Offset = 0;

    WCHAR szLog[WOBJ_MAX_MESSAGE - 1];

    szLog[0] = 0;
    RtlStringCchPrintfSecure(szLog,
        RTL_NUMBER_OF(szLog),
        TEXT("%ws: Retrieving field \"%ws\" offset for symbol \"%ws\""),
        __FUNCTIONW__,
        FieldName,
        SymbolName);

    logAdd(EntryTypeInformation, szLog);

    __try {

        *Offset = symContext->Parser.GetFieldOffset(
            symContext,
            SymbolName,
            FieldName,
            &bResult);

    }
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
        return FALSE;
    }

    szLog[0] = 0;
    RtlStringCchPrintfSecure(szLog,
        RTL_NUMBER_OF(szLog),
        TEXT("%ws(%ws): \"%ws->%ws\", offset 0x%lX"),
        __FUNCTIONW__,
        (bResult) ? L"SUCCESS" : L"FAIL",
        SymbolName,
        FieldName,
        *Offset);

    logAdd(EntryTypeInformation, szLog);

    return bResult;
}

/*
* kdGetAddressFromSymbolEx
*
* Purpose:
*
* Get fully adjusted address for symbol by it name.
*
*/
BOOL kdGetAddressFromSymbolEx(
    _In_ PSYMCONTEXT SymContext,
    _In_ LPCWSTR SymbolName,
    _In_ PVOID ImageBase,
    _In_ ULONG_PTR ImageSize,
    _Inout_ ULONG_PTR* Address
)
{
    BOOL bResult = FALSE;
    ULONG_PTR address;

    WCHAR szLog[WOBJ_MAX_MESSAGE - 1];

    szLog[0] = 0;
    RtlStringCchPrintfSecure(szLog,
        RTL_NUMBER_OF(szLog),
        TEXT("%ws: Retrieving address for symbol \"%ws\""),
        __FUNCTIONW__,
        SymbolName);

    logAdd(EntryTypeInformation, szLog);

    *Address = 0;

    //
    // Verify context data.
    //
    if (ImageBase == NULL || ImageSize == 0)
    {
        return FALSE;
    }

    __try {

        address = SymContext->Parser.LookupAddressBySymbol(
            SymContext,
            SymbolName,
            &bResult);

    }
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
        return FALSE;
    }

    if (bResult && address) {

        //
        // Adjust address to image base. 
        //
        address = (ULONG_PTR)ImageBase + address - SymContext->ModuleBase;

        //
        // Validate resulting address value.
        //
        if (IN_REGION(address,
            ImageBase,
            ImageSize))
        {
            *Address = address;
        }
        else {
            //
            // This is bogus address not in ntoskrnl range, bail out.
            //
            bResult = FALSE;
        }

    }

    szLog[0] = 0;
    RtlStringCchPrintfSecure(szLog,
        RTL_NUMBER_OF(szLog),
        TEXT("%ws(%ws): \"%ws\" address 0x%llX"),
        __FUNCTIONW__,
        (bResult) ? L"SUCCESS" : L"FAIL",
        SymbolName,
        address);

    logAdd(EntryTypeInformation, szLog);

    return bResult;
}

/*
* kdGetAddressFromSymbol
*
* Purpose:
*
* Get fully adjusted address for ntoskrnl symbol by it name.
*
*/
BOOL kdGetAddressFromSymbol(
    _In_ KLDBGCONTEXT* Context,
    _In_ LPCWSTR SymbolName,
    _Inout_ ULONG_PTR* Address
)
{
    PSYMCONTEXT symContext = (PSYMCONTEXT)Context->NtOsSymContext;

    return kdGetAddressFromSymbolEx(symContext,
        SymbolName,
        Context->NtOsBase,
        Context->NtOsSize,
        Address);

}

/*
* symCallbackReportEvent
*
* Purpose:
*
* Add event to the log and output it into optional callback.
*
*/
VOID symCallbackReportEvent(
    _In_ ULONG ActionCode,
    _In_ PIMAGEHLP_DEFERRED_SYMBOL_LOAD Action,
    _In_ PFNSUPSYMCALLBACK UserCallback
)
{
    WCHAR szText[MAX_PATH * 2];
    WOBJ_ENTRY_TYPE entryType = EntryTypeInformation;

    szText[0] = 0;

    switch (ActionCode) {

    case CBA_DEFERRED_SYMBOL_LOAD_START:

        RtlStringCchPrintfSecure(szText, RTL_NUMBER_OF(szText),
            TEXT("Loading symbols for 0x%p %ws..."),
            Action->BaseOfImage,
            Action->FileName);

        break;

    case CBA_DEFERRED_SYMBOL_LOAD_COMPLETE:

        RtlStringCchPrintfSecure(szText, RTL_NUMBER_OF(szText),
            TEXT("Loaded symbols for 0x%p %ws"),
            Action->BaseOfImage,
            Action->FileName);

        break;

    case CBA_DEFERRED_SYMBOL_LOAD_FAILURE:

        RtlStringCchPrintfSecure(szText, RTL_NUMBER_OF(szText),
            TEXT("*** ERROR: Could not load symbols for 0x%p %ws..."),
            Action->BaseOfImage,
            Action->FileName);

        entryType = EntryTypeError;

        break;

    }

    logAdd(entryType, szText);

    if (UserCallback)
        UserCallback(szText);
}

/*
* symCallbackProc
*
* Purpose:
*
* DbgHelp callback procedure used for tracking symbols loading during startup.
*
*/
BOOL CALLBACK symCallbackProc(
    _In_ HANDLE hProcess,
    _In_ ULONG ActionCode,
    _In_ ULONG64 CallbackData,
    _In_ ULONG64 UserContext
)
{
    UNREFERENCED_PARAMETER(hProcess);

    switch (ActionCode) {

    case CBA_DEFERRED_SYMBOL_LOAD_START:
    case CBA_DEFERRED_SYMBOL_LOAD_COMPLETE:
    case CBA_DEFERRED_SYMBOL_LOAD_FAILURE:

        symCallbackReportEvent(ActionCode, 
            (PIMAGEHLP_DEFERRED_SYMBOL_LOAD)CallbackData, 
            (PFNSUPSYMCALLBACK)UserContext);

        break;

    default:
        return FALSE;
    }

    return TRUE;
}

/*
* symInit
*
* Purpose:
*
* Create symbol parser context if dbghelp available, called once.
*
*/
BOOL symInit(
    _In_opt_ LPWSTR lpSymbolPath,
    _In_opt_ LPWSTR lpDbgHelpDll
)
{
    ULONG cch;

    WCHAR szFileName[MAX_PATH * 2];
    LPWSTR dbgHelpDll = lpDbgHelpDll;

    if (g_kdctx.NtOsSymContext != NULL)
        return TRUE;

   if (lpDbgHelpDll == NULL) {

        szFileName[0] = 0;
        cch = GetCurrentDirectory(MAX_PATH, szFileName);
        if (cch > 0 && cch < MAX_PATH) {
            supPathAddBackSlash(szFileName);
            _strcat(szFileName, TEXT("symdll\\dbghelp.dll"));
            if (!PathFileExists(szFileName))
                return FALSE;
        }
        else {
            return FALSE;
        }

        dbgHelpDll = szFileName;

    }

    if (SymGlobalsInit(
        SYMOPT_CASE_INSENSITIVE |
        SYMOPT_UNDNAME |
        SYMOPT_FAIL_CRITICAL_ERRORS |
        SYMOPT_EXACT_SYMBOLS |
        SYMOPT_AUTO_PUBLICS,
        NULL,
        dbgHelpDll,
        lpSymbolPath,
        g_WinObj.szSystemDirectory,
        g_WinObj.szTempDirectory,
        (PSYMBOL_REGISTERED_CALLBACK64)symCallbackProc,
        (ULONG64)supSymCallbackReportEvent))
    {
        g_kdctx.NtOsSymContext = (PVOID)SymParserCreate();
    }

    return (g_kdctx.NtOsSymContext != NULL);
}

/*
* symShutdown
*
* Purpose:
*
* Deallocate symbol parser context, called once.
*
*/
VOID symShutdown()
{
    PSYMCONTEXT Context = (PSYMCONTEXT)g_kdctx.NtOsSymContext;

    if (Context) {
        if (Context->ModuleBase)
            Context->Parser.UnloadModule(Context);
    }

    SymGlobalsFree();
}

/*
* kdCreateObjectTypesList
*
* Purpose:
*
* Create simple list of system object types.
*
*/
PVOID kdCreateObjectTypesList(
    VOID
)
{
    ULONG i;
    OBTYPE_LIST* list;
    POBJECT_TYPES_INFORMATION pObjectTypes = (POBJECT_TYPES_INFORMATION)supGetObjectTypesInfo();
    POBJECT_TYPE_INFORMATION pObject;

    union {
        union {
            POBJECT_TYPE_INFORMATION Object;
            POBJECT_TYPE_INFORMATION_V2 ObjectV2;
        } u1;
        PBYTE Ref;
    } ObjectTypeEntry;

    if (pObjectTypes == NULL)
        return NULL;

    list = (OBTYPE_LIST*)supHeapAlloc(
        sizeof(OBTYPE_LIST) +
        sizeof(OBTYPE_ENTRY) * pObjectTypes->NumberOfTypes);

    if (list) {

        list->Buffer = pObjectTypes;

        __try {

            pObject = OBJECT_TYPES_FIRST_ENTRY(pObjectTypes);

            for (i = 0; i < pObjectTypes->NumberOfTypes; i++) {

                ObjectTypeEntry.Ref = (PBYTE)pObject;

                if (g_NtBuildNumber >= NT_WIN8_RTM) {
                    list->Types[i].TypeIndex = ObjectTypeEntry.u1.ObjectV2->TypeIndex;
                    list->Types[i].TypeName = &ObjectTypeEntry.u1.ObjectV2->TypeName;
                    list->Types[i].PoolType = ObjectTypeEntry.u1.ObjectV2->PoolType;
                }
                else {
                    list->Types[i].TypeIndex = (i + 2);
                    list->Types[i].TypeName = &ObjectTypeEntry.u1.Object->TypeName;
                    list->Types[i].PoolType = ObjectTypeEntry.u1.Object->PoolType;
                }

                list->NumberOfTypes += 1;
                pObject = OBJECT_TYPES_NEXT_ENTRY(pObject);
            }

        }
        __except (WOBJ_EXCEPTION_FILTER_LOG) {
            return NULL;
        }

    }
    else {
        supHeapFree(pObjectTypes);
    }

    return list;
}

/*
* kdInit
*
* Purpose:
*
* Fire up KLDBG namespace and open/load helper driver.
*
*/
VOID kdInit(
    _In_ BOOLEAN IsFullAdmin
)
{
    NTSTATUS ntStatus;
    OBEX_CONFIG* obexConfig = supGetParametersBlock();
    WCHAR szBuffer[MAX_PATH * 2];
    LPWSTR lpSymbolPath = NULL, lpDbgHelpDll = NULL;

    RtlSecureZeroMemory(&g_kdctx, sizeof(g_kdctx));
    RtlSecureZeroMemory(&g_kdpdata, sizeof(g_kdpdata));
    RtlSecureZeroMemory(&g_SystemCallbacks, sizeof(g_SystemCallbacks));

    RtlSecureZeroMemory(obexConfig, sizeof(OBEX_CONFIG));

    if (supReadObexConfiguration(obexConfig)) {

        if (obexConfig->SymbolsDbgHelpDllValid) 
            lpDbgHelpDll = obexConfig->szSymbolsDbgHelpDll;

        if (obexConfig->SymbolsPathValid)
            lpSymbolPath = obexConfig->szSymbolsPath;

        if (obexConfig->szNormalizationSymbol != 0)
            g_ObNameNormalizationSymbol = obexConfig->szNormalizationSymbol;

    }

    g_kdctx.DriverContext.LoadStatus = STATUS_DRIVER_UNABLE_TO_LOAD;
    g_kdctx.DriverContext.OpenStatus = STATUS_UNSUCCESSFUL;

    g_kdctx.IsFullAdmin = IsFullAdmin;

    g_kdctx.Data = &g_kdpdata;

    g_kdctx.MitigationFlags.ASLRPolicy = TRUE;

    NtpLdrExceptionFilter = (PFNNTLDR_EXCEPT_FILTER)exceptFilterWithLog;

    InitializeListHead(&g_kdctx.Data->KseEngineDump.ShimmedDriversDumpListHead);

    g_kdctx.Data->ObjectTypesList = (POBTYPE_LIST)kdCreateObjectTypesList();

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

    //
    // Init symbol parser.
    //
    symInit(lpSymbolPath, lpDbgHelpDll);

    //
    // Enable debug privileges for newest Windows 11.
    // 
    if (IsFullAdmin) {
        g_kdctx.IsDebugPrivAssigned = supEnablePrivilegeWithCheck(SE_DEBUG_PRIVILEGE, TRUE);
    }

    //
    // Query global variables.
    //
    kdQuerySystemInformation(&g_kdctx);

    //
    // No admin rights, leave.
    //
    if (IsFullAdmin == FALSE)
        return;

    //
    // Find EPROCESS offsets.
    //
    ObpFindProcessObjectOffsets(&g_kdctx);

    switch (WDrvGetActiveProviderType())
    {
        //
        // If the current driver provider is WinDbg then check Windows debug mode.
        // This is required by WinDbg kldbgdrv.
        //
    case wdrvMicrosoft:
        if (supIsKdEnabled(NULL, NULL) == FALSE)
            return;
        break;

    case wdrvWinIo:
        g_kdctx.MitigationFlags.ImageLoad = TRUE;
        g_kdctx.MitigationFlags.ExtensionPointDisable = TRUE;
        g_kdctx.MitigationFlags.Signature = TRUE;
        g_kdctx.MitigationFlags.ASLRPolicy = TRUE;
        break;
    }

    //
    // Create driver provider context.
    //
    ntStatus = WDrvProvCreate(g_kdctx.Data->FirmwareType, &g_kdctx.DriverContext);
    if (!NT_SUCCESS(ntStatus)) {

        RtlStringCchPrintfSecure(szBuffer,
            MAX_PATH,
            TEXT("Could not open/load helper driver.\r\nSome features maybe unavailable, error code 0x%lX"),
            ntStatus);

        MessageBox(GetDesktopWindow(), szBuffer, PROGRAM_NAME, MB_ICONINFORMATION);
        logAdd(EntryTypeError, szBuffer);
    }

    //
    // Init driver relying variables.
    //
    if (kdIoDriverLoaded()) {

        //
        // Locate and remember ObHeaderCookie, routine require driver usage, do not move.
        //
        if (g_WinObj.osver.dwMajorVersion >= 10) {
            ObpFindHeaderCookie(&g_kdctx);
        }

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
    if (g_kdctx.Data->ObjectTypesList) {
        if (g_kdctx.Data->ObjectTypesList->Buffer)
            supHeapFree(g_kdctx.Data->ObjectTypesList->Buffer);
        supHeapFree(g_kdctx.Data->ObjectTypesList);
    }

    WDrvProvRelease(&g_kdctx.DriverContext);

    if (g_kdctx.NtOsImageMap) {
        FreeLibrary((HMODULE)g_kdctx.NtOsImageMap);
        g_kdctx.NtOsImageMap = NULL;
    }

    //
    // Deallocate symbols context if present.
    //
    symShutdown();
}
