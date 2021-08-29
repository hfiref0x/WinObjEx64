/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2021
*
*  TITLE:       KLDBG.C, based on KDSubmarine by Evilcry
*
*  VERSION:     1.91
*
*  DATE:        30 June 2021
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

//Callbacks
NOTIFICATION_CALLBACKS g_SystemCallbacks;

UCHAR ObpInfoMaskToOffset[0x100];

//Context private data
KLDBGPDATA g_kdpdata;

BOOL kdExtractDriver(
    _In_ WCHAR* szDriverPath);

VOID kdpRemoveDriverFile();


#ifdef _USE_OWN_DRIVER

/*
* kdpShowNtStatus
*
* Purpose:
*
* Output ntstatus message.
*
*/
VOID kdpShowNtStatus(
    _In_ LPCWSTR lpFunction,
    _In_ NTSTATUS ntStatus)
{
    WCHAR szBuffer[MAX_PATH + 1];

    RtlStringCchPrintfSecure(szBuffer, MAX_PATH, TEXT("%ws 0x%lx"),
        lpFunction,
        ntStatus);

    MessageBox(GetDesktopWindow(), szBuffer, NULL, MB_OK);
}

/*
* kdOpenHelperDevice
*
* Purpose:
*
* Open handle for helper driver.
*
* N.B.
* SE_DEBUG_PRIVILEGE is required to be assigned and enabled.
* It is checked on driver side for all supported driver variants.
*
*/
NTSTATUS kdOpenHelperDevice(
    _In_ LPCWSTR DriverName,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE DeviceHandle
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    UNICODE_STRING usDeviceLink;
    OBJECT_ATTRIBUTES obja;
    IO_STATUS_BLOCK iost;

    TCHAR szDeviceLink[MAX_PATH + 1];

    // assume failure
    if (DeviceHandle)
        *DeviceHandle = NULL;
    else
        return STATUS_INVALID_PARAMETER_2;

    if (DriverName) {

        RtlSecureZeroMemory(szDeviceLink, sizeof(szDeviceLink));

        if (RtlStringCchPrintfSecure(szDeviceLink,
            MAX_PATH,
            TEXT("\\DosDevices\\%wS"),
            DriverName) == -1)
        {
            return STATUS_INVALID_PARAMETER_1;
        }

        RtlInitUnicodeString(&usDeviceLink, szDeviceLink);
        InitializeObjectAttributes(&obja, &usDeviceLink, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = NtCreateFile(DeviceHandle,
            DesiredAccess,
            &obja,
            &iost,
            NULL,
            0,
            0,
            FILE_OPEN,
            0,
            NULL,
            0);

    }
    else {
        status = STATUS_INVALID_PARAMETER_1;
    }

    return status;
}

/*
* kdLoadHelperDriver
*
* Purpose:
*
* Install helper driver and load it.
*
* N.B.
* SE_LOAD_DRIVER_PRIVILEGE is required to be assigned and enabled.
*
*/
NTSTATUS kdLoadHelperDriver(
    _In_ LPCWSTR DriverName,
    _In_ LPCWSTR DriverPath
)
{
    NTSTATUS status;
    DWORD dwData, dwResult;
    HKEY keyHandle = NULL;
    SIZE_T keyOffset;
    UNICODE_STRING driverServiceName, driverImagePath;

    HANDLE deviceHandle = NULL;
    PACL pAcl = NULL;
    PSECURITY_DESCRIPTOR driverSD = NULL;

    WCHAR szBuffer[MAX_PATH + 1];

    if (DriverName == NULL)
        return STATUS_INVALID_PARAMETER_1;
    if (DriverPath == NULL)
        return STATUS_INVALID_PARAMETER_2;

    status = supCreateSystemAdminAccessSD(&driverSD, &pAcl);
    if (!NT_SUCCESS(status))
        return status;

    RtlInitEmptyUnicodeString(&driverImagePath, NULL, 0);
    if (!RtlDosPathNameToNtPathName_U(DriverPath,
        &driverImagePath,
        NULL,
        NULL))
    {
        supHeapFree(driverSD);
        if (pAcl) supHeapFree(pAcl);
        return STATUS_INVALID_PARAMETER_2;
    }

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

    keyOffset = RTL_NUMBER_OF(NT_REG_PREP);

    if (RtlStringCchPrintfSecure(szBuffer, MAX_PATH,
        DRIVER_REGKEY,
        NT_REG_PREP,
        DriverName) == -1)
    {
        status = STATUS_INVALID_PARAMETER_1;
        goto Cleanup;
    }

    if (ERROR_SUCCESS != RegCreateKeyEx(HKEY_LOCAL_MACHINE,
        &szBuffer[keyOffset],
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS,
        NULL,
        &keyHandle,
        NULL))
    {
        status = STATUS_ACCESS_DENIED;
        goto Cleanup;
    }

    dwResult = ERROR_SUCCESS;

    do {

        dwData = SERVICE_ERROR_NORMAL;
        dwResult = RegSetValueEx(keyHandle,
            TEXT("ErrorControl"),
            0,
            REG_DWORD,
            (BYTE*)&dwData,
            sizeof(dwData));
        if (dwResult != ERROR_SUCCESS)
            break;

        dwData = SERVICE_KERNEL_DRIVER;
        dwResult = RegSetValueEx(keyHandle,
            TEXT("Type"),
            0,
            REG_DWORD,
            (BYTE*)&dwData,
            sizeof(dwData));
        if (dwResult != ERROR_SUCCESS)
            break;

        dwData = SERVICE_DEMAND_START;
        dwResult = RegSetValueEx(keyHandle,
            TEXT("Start"),
            0,
            REG_DWORD,
            (BYTE*)&dwData,
            sizeof(dwData));

        if (dwResult != ERROR_SUCCESS)
            break;

        dwResult = RegSetValueEx(keyHandle,
            TEXT("DisplayName"),
            0,
            REG_SZ,
            (BYTE*)DriverName,
            (DWORD)((1 + _strlen(DriverName)) * sizeof(WCHAR)));
        if (dwResult != ERROR_SUCCESS)
            break;

        dwResult = RegSetValueEx(keyHandle,
            TEXT("ImagePath"),
            0,
            REG_EXPAND_SZ,
            (BYTE*)driverImagePath.Buffer,
            (DWORD)driverImagePath.Length + sizeof(UNICODE_NULL));

    } while (FALSE);

    RegCloseKey(keyHandle);

    if (dwResult != ERROR_SUCCESS) {
        status = STATUS_ACCESS_DENIED;
        goto Cleanup;
    }

    if (supEnablePrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE)) {

        RtlInitUnicodeString(&driverServiceName, szBuffer);
        status = NtLoadDriver(&driverServiceName);

        if (NT_SUCCESS(status)) {
            status = kdOpenHelperDevice(KLDBGDRV, WRITE_DAC, &deviceHandle);

            if (NT_SUCCESS(status)) {
                status = NtSetSecurityObject(deviceHandle,
                    DACL_SECURITY_INFORMATION,
                    driverSD);
                NtClose(deviceHandle);
            }
        }

        supEnablePrivilege(SE_LOAD_DRIVER_PRIVILEGE, FALSE);
    }
    else {
        status = STATUS_ACCESS_DENIED;
    }

Cleanup:
    supHeapFree(driverSD);
    if (pAcl) supHeapFree(pAcl);
    RtlFreeUnicodeString(&driverImagePath);
    return status;
}

/*
* kdpOpenLoadDriverPrivate
*
* Purpose:
*
* Open handle to helper driver device or load this driver.
*
*/
BOOLEAN kdpOpenLoadDriverPrivate(
    _In_ WCHAR* szDriverPath
)
{
    NTSTATUS ntStatus;

#ifdef _USE_WINIO
    //
    // Cannot use address translation on legacy boot.
    //
    if (g_kdctx.Data->FirmwareType != FirmwareTypeUefi) {
        g_kdctx.DriverOpenLoadStatus = (ULONG)STATUS_NOT_SUPPORTED;
        return FALSE;
    }
#endif

    //
    // First, try to open existing device.
    //
    ntStatus = kdOpenHelperDevice(KLDBGDRV,
        GENERIC_READ | GENERIC_WRITE,
        &g_kdctx.DeviceHandle);

    if (NT_SUCCESS(ntStatus)) {
        g_kdctx.DriverOpenLoadStatus = (ULONG)STATUS_SUCCESS;
        g_kdctx.IsOurLoad = FALSE;
        return TRUE;
    }

    //
    // Next, if device not opened, extract driver.
    //
    if (!kdExtractDriver(szDriverPath)) {
        g_kdctx.DriverOpenLoadStatus = (ULONG)STATUS_FILE_INVALID;
        return FALSE;
    }

    //
    // Install and load helper driver.
    //
    ntStatus = kdLoadHelperDriver(KLDBGDRV, szDriverPath);
    if (!NT_SUCCESS(ntStatus)) {
        g_kdctx.DriverOpenLoadStatus = (ULONG)ntStatus;
        return FALSE;
    }

    g_kdctx.IsOurLoad = TRUE;

    //
    // Finally, try to open drive device again.
    //
    ntStatus = kdOpenHelperDevice(KLDBGDRV,
        GENERIC_READ | GENERIC_WRITE,
        &g_kdctx.DeviceHandle);

    g_kdctx.DriverOpenLoadStatus = (ULONG)ntStatus;

    return NT_SUCCESS(ntStatus);
}

/*
* kdUnloadHelperDriver
*
* Purpose:
*
* Call driver unload and remove corresponding registry key.
*
* N.B.
* SE_LOAD_DRIVER_PRIVILEGE is required to be assigned and enabled.
*
*/
NTSTATUS kdUnloadHelperDriver(
    _In_ LPCWSTR DriverName,
    _In_ BOOLEAN fRemove
)
{
    NTSTATUS status;
    SIZE_T keyOffset;
    UNICODE_STRING driverServiceName;

    WCHAR szBuffer[MAX_PATH + 1];

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

    if (RtlStringCchPrintfSecure(szBuffer, MAX_PATH,
        DRIVER_REGKEY,
        NT_REG_PREP,
        DriverName) == -1)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (!supEnablePrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE))
        return STATUS_ACCESS_DENIED;

    keyOffset = RTL_NUMBER_OF(NT_REG_PREP);

    RtlInitUnicodeString(&driverServiceName, szBuffer);
    status = NtUnloadDriver(&driverServiceName);

    supEnablePrivilege(SE_LOAD_DRIVER_PRIVILEGE, FALSE);

    if (NT_SUCCESS(status)) {
        if (fRemove)
            supRegDeleteKeyRecursive(HKEY_LOCAL_MACHINE, &szBuffer[keyOffset]);
    }

    return status;
}

/*
* kdpUnloadHelperDriver
*
* Purpose:
*
* Unload helper driver, delete registry entry and delete driver file.
*
*/
VOID kdpUnloadHelperDriver()
{
    kdUnloadHelperDriver(KLDBGDRV, TRUE);
    kdpRemoveDriverFile();
}

#endif //_USE_OWN_DRIVER

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
* ObpInitInfoBlockOffsets
*
* Purpose:
*
* Initialize block offsets table for working with OBJECT_HEADER data.
*
* Note:
*
* ObpInfoMaskToOffset size depends on Windows version (Win7 = 64, Win10 = 256)
*
* 9200 (Windows 8 Blue)
* OBJECT_HEADER_AUDIT_INFO added
*
* 10586 (Windows 10 TH2)
* OBJECT_HEADER_HANDLE_REVOCATION_INFO added (size in ObpInitInfoBlockOffsets = 32)
*
* 14393 (Windows 10 RS1)
* OBJECT_HEADER_EXTENDED_INFO added and replaced OBJECT_HEADER_HANDLE_REVOCATION_INFO in ObpInitInfoBlockOffsets
* size = 16
*
* HANDLE_REVOCATION_INFO moved to OBJECT_FOOTER which is a part of OBJECT_HEADER_EXTENDED_INFO as pointer.
*
*/
VOID ObpInitInfoBlockOffsets()
{
    UCHAR* p = ObpInfoMaskToOffset;
    UINT i;
    UCHAR c;

    i = 0;

    do {
        c = 0;
        if (i & 1)
            c += sizeof(OBJECT_HEADER_CREATOR_INFO);
        if (i & 2)
            c += sizeof(OBJECT_HEADER_NAME_INFO);
        if (i & 4)
            c += sizeof(OBJECT_HEADER_HANDLE_INFO);
        if (i & 8)
            c += sizeof(OBJECT_HEADER_QUOTA_INFO);
        if (i & 0x10)
            c += sizeof(OBJECT_HEADER_PROCESS_INFO);

        if (i & 0x20) {
            // Padding?
            if (g_NtBuildNumber < NT_WIN8_RTM) {
                c += sizeof(OBJECT_HEADER_PADDING_INFO);
            }
            else {
                c += sizeof(OBJECT_HEADER_AUDIT_INFO);
            }
        }

        //OBJECT_HEADER_EXTENDED_INFO (OBJECT_HEADER_HANDLE_REVOCATION_INFO in NT_WIN10_THRESHOLD2)
        if (i & 0x40) {
            if (g_NtBuildNumber == NT_WIN10_THRESHOLD2)
                c += sizeof(OBJECT_HEADER_HANDLE_REVOCATION_INFO);
            else
                c += sizeof(OBJECT_HEADER_EXTENDED_INFO);
        }

        if (i & 0x80)
            c += sizeof(OBJECT_HEADER_PADDING_INFO);

        p[i] = c;
        i++;
    } while (i < 256);

    return;
}

/*
* ObGetObjectHeaderOffsetEx
*
* Purpose:
*
* Query requested structure offset for the given mask
*
*/
BYTE ObGetObjectHeaderOffsetEx(
    _In_ BYTE InfoMask,
    _In_ BYTE DesiredHeaderBit
)
{
    return ObpInfoMaskToOffset[InfoMask & (DesiredHeaderBit | (DesiredHeaderBit - 1))];
}

/*
* ObHeaderToNameInfoAddressEx
*
* Purpose:
*
* Calculate address of name structure from object header flags and object address using ObpInfoMaskToOffset.
*
*/
BOOL ObHeaderToNameInfoAddressEx(
    _In_ UCHAR ObjectInfoMask,
    _In_ ULONG_PTR ObjectAddress,
    _Inout_ PULONG_PTR HeaderAddress,
    _In_ BYTE DesiredHeaderBit
)
{
    BYTE      HeaderOffset;
    ULONG_PTR Address;

    if (HeaderAddress == NULL)
        return FALSE;

    if (ObjectAddress < g_kdctx.SystemRangeStart)
        return FALSE;

    HeaderOffset = ObGetObjectHeaderOffsetEx(ObjectInfoMask, DesiredHeaderBit);
    if (HeaderOffset == 0)
        return FALSE;

    Address = ObjectAddress - HeaderOffset;
    if (Address < g_kdctx.SystemRangeStart)
        return FALSE;

    *HeaderAddress = Address;
    return TRUE;
}

/*
* ObGetObjectHeaderOffset
*
* Purpose:
*
* Query requested structure offset for the given mask
*
*
* Object In Memory Disposition (Obsolete, see ObpInitInfoBlockOffsets comments)
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
    if (!kdReadSystemMemoryEx(BoundaryDescriptorAddress,
        &BoundaryDescriptorHeader,
        sizeof(OBJECT_BOUNDARY_DESCRIPTOR),
        NULL))
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

    if (kdReadSystemMemoryEx(BoundaryDescriptorAddress,
        CopyDescriptor,
        TotalSize,
        NULL))
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
    _In_opt_ PENUMERATE_BOUNDARY_DESCRIPTOR_CALLBACK Callback,
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

        if (Callback) {
            if (Callback(CurrentEntry, Context))
                return STATUS_SUCCESS;
        }

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
        objectVersion = 1;
        break;
    case NT_WIN8_RTM:
    case NT_WIN8_BLUE:
    case NT_WIN10_THRESHOLD1:
    case NT_WIN10_THRESHOLD2:
        objectSize = sizeof(OBJECT_TYPE_8);
        objectVersion = 2;
        break;
    case NT_WIN10_REDSTONE1:
        objectSize = sizeof(OBJECT_TYPE_RS1);
        objectVersion = 3;
        break;
    default:
        objectSize = sizeof(OBJECT_TYPE_RS2);
        objectVersion = 4;
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
        objectVersion = 1;
        break;
    case NT_WIN8_RTM:
        objectSize = sizeof(ALPC_PORT_9200);
        objectVersion = 2;
        break;
    case NT_WIN8_BLUE:
        objectSize = sizeof(ALPC_PORT_9600);
        objectVersion = 3;
        break;
    default:
        objectSize = sizeof(ALPC_PORT_10240);
        objectVersion = 4;
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
        objectVersion = 1;
        break;

    case NT_WIN10_THRESHOLD1:
    case NT_WIN10_THRESHOLD2:
    case NT_WIN10_REDSTONE1:
        objectSize = sizeof(OBJECT_DIRECTORY_V2);
        objectVersion = 2;
        break;

    default:
        objectSize = sizeof(OBJECT_DIRECTORY_V3);
        objectVersion = 3;
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
        objectVersion = 1;
        break;
    case NT_WIN10_THRESHOLD1:
    case NT_WIN10_THRESHOLD2:
        objectSize = sizeof(OBJECT_SYMBOLIC_LINK_V2);
        objectVersion = 2;
        break;
    case NT_WIN10_REDSTONE1:
        objectSize = sizeof(OBJECT_SYMBOLIC_LINK_V3);
        objectVersion = 3;
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
        objectSize = sizeof(OBJECT_SYMBOLIC_LINK_V4);
        objectVersion = 4;
        break;
    default:
        objectSize = sizeof(OBJECT_SYMBOLIC_LINK_V5);
        objectVersion = 5;
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

    switch (g_NtBuildNumber) {
    case NT_WIN7_RTM:
    case NT_WIN7_SP1:
    case NT_WIN8_RTM:
    case NT_WIN8_BLUE:
    case NT_WIN10_THRESHOLD1:
    case NT_WIN10_THRESHOLD2:
        objectSize = sizeof(DEVICE_MAP_V1);
        objectVersion = 1;
        break;
    case NT_WIN10_REDSTONE1:
    default:
        objectSize = sizeof(DEVICE_MAP_V2);
        objectVersion = 2;
        break;
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
        objectVersion = 4;
    }
    else {

        switch (g_NtBuildNumber) {
        case NT_WIN7_RTM:
        case NT_WIN7_SP1:
            objectSize = sizeof(DRIVER_EXTENSION_V2);
            objectVersion = 2;
            break;
        case NT_WIN8_RTM:
            objectSize = sizeof(DRIVER_EXTENSION_V3);
            objectVersion = 3;
            break;
        default:
            objectSize = sizeof(DRIVER_EXTENSION);
            objectVersion = 1;
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

    if (kdReadSystemMemoryEx(
        lookupAddress,
        &cookieValue,
        sizeof(cookieValue),
        NULL))
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

    return (pOffsetProcessId->Valid && pOffsetImageName->Valid);
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

        if (kdReadSystemMemoryEx(varAddress,
            &PspHostSiloGlobals,
            sizeof(PspHostSiloGlobals),
            NULL))
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
            PAGE_SECTION_LEGNTH,
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

    if (!kdReadSystemMemoryEx((ULONG_PTR)CallbackBlock,
        &readBlock,
        sizeof(EX_CALLBACK_ROUTINE_BLOCK),
        NULL))
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
    _Out_ ULONG_PTR *Address
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

    return kdReadSystemMemoryEx(
        varAddress,
        ServiceTable,
        sizeof(KSERVICE_TABLE_DESCRIPTOR),
        NULL);
}

/*
* ObGetDirectoryObjectAddress
*
* Purpose:
*
* Obtain directory object kernel address by:
* 1) opening directory by name
* 2) quering resulted handle in NtQuerySystemInformation(SystemExtendedHandleInformation) handle dump
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
    LPWSTR              lpTarget;

    if (lpRootAddress == NULL)
        return bFound;

    if (lpDirectory == NULL) {
        lpTarget = KM_OBJECTS_ROOT_DIRECTORY;
    }
    else {
        lpTarget = lpDirectory;
    }

    supOpenDirectory(&hDirectory, NULL, lpTarget, DIRECTORY_QUERY);
    if (hDirectory) {

        bFound = supQueryObjectFromHandle(hDirectory,
            lpRootAddress,
            lpTypeIndex);

        NtClose(hDirectory);
    }
    return bFound;
}

/*
* ObQueryNameString
*
* Purpose:
*
* Reads object name from kernel memory.
*
* If HeapHandle is g_WinObj use supHeapFree to release allocated memory.
*
*/
LPWSTR ObQueryNameString(
    _In_ ULONG_PTR NameInfoAddress,
    _Out_opt_ PSIZE_T ReturnLength,
    _In_ HANDLE HeapHandle
)
{
    SIZE_T allocLength;
    LPWSTR objectName = NULL;

    OBJECT_HEADER_NAME_INFO nameInfo;

    if (ReturnLength)
        *ReturnLength = 0;

    RtlSecureZeroMemory(&nameInfo, sizeof(OBJECT_HEADER_NAME_INFO));

    if (kdReadSystemMemoryEx(NameInfoAddress,
        &nameInfo,
        sizeof(OBJECT_HEADER_NAME_INFO),
        NULL))
    {
        if (nameInfo.Name.Length) {

            allocLength = nameInfo.Name.Length + sizeof(UNICODE_NULL);

            objectName = (LPWSTR)RtlAllocateHeap(HeapHandle,
                HEAP_ZERO_MEMORY,
                allocLength);

            if (objectName != NULL) {

                NameInfoAddress = (ULONG_PTR)nameInfo.Name.Buffer;

                if (kdReadSystemMemoryEx(NameInfoAddress,
                    objectName,
                    nameInfo.Name.Length,
                    NULL))
                {
                    if (ReturnLength)
                        *ReturnLength = allocLength;
                }
                else {

                    RtlFreeHeap(HeapHandle,
                        0,
                        objectName);

                    objectName = NULL;
                }

            }
        }
    }

    return objectName;
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
POBJINFO ObpCopyObjectBasicInfo(
    _In_ ULONG_PTR ObjectAddress,
    _In_ ULONG_PTR ObjectHeaderAddress,
    _In_ BOOL ObjectHeaderAddressValid,
    _In_opt_ POBJECT_HEADER DumpedObjectHeader
)
{
    ULONG_PTR       HeaderAddress = 0, InfoHeaderAddress = 0;
    POBJINFO        lpData = NULL;
    OBJECT_HEADER   ObjectHeader, * pObjectHeader;

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

        if (!kdReadSystemMemoryEx(HeaderAddress,
            &ObjectHeader,
            sizeof(OBJECT_HEADER),
            NULL))
        {
            kdDebugPrint("%s kdReadSystemMemoryEx(ObjectHeaderAddress) failed\r\n", __FUNCTION__);
            return NULL;
        }

        pObjectHeader = &ObjectHeader;
    }

    //
    // Allocate OBJINFO structure, exit on fail.
    //
    lpData = (POBJINFO)supHeapAlloc(sizeof(OBJINFO));
    if (lpData == NULL)
        return NULL;

    lpData->ObjectAddress = ObjectAddress;
    lpData->HeaderAddress = HeaderAddress;

    //
    // Copy object header.
    //
    supCopyMemory(&lpData->ObjectHeader,
        sizeof(OBJECT_HEADER),
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
        kdReadSystemMemoryEx(HeaderAddress,
            &lpData->ObjectQuotaHeader,
            sizeof(OBJECT_HEADER_QUOTA_INFO),
            NULL);
    }

    return lpData;
}

/*
* ObpWalkDirectory
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
POBJINFO ObpWalkDirectory(
    _In_ LPWSTR lpObjectToFind,
    _In_ ULONG_PTR DirectoryAddress
)
{
    BOOL      bFound = FALSE;
    UINT      BucketId;
    SIZE_T    retSize;
    LPWSTR    lpObjectName;
    ULONG_PTR ObjectHeaderAddress, HeadItem, LookupItem, InfoHeaderAddress;

    OBJECT_HEADER          ObjectHeader;
    OBJECT_DIRECTORY       DirectoryObject;
    OBJECT_DIRECTORY_ENTRY DirectoryEntry;

    __try {

        if (lpObjectToFind == NULL)
            return NULL;

        //
        // Read object directory at address.
        //
        RtlSecureZeroMemory(&DirectoryObject, sizeof(OBJECT_DIRECTORY));

        if (!kdReadSystemMemoryEx(DirectoryAddress,
            &DirectoryObject,
            sizeof(OBJECT_DIRECTORY),
            NULL))
        {
            kdDebugPrint("%s kdReadSystemMemoryEx(DirectoryAddress) failed\r\n", __FUNCTION__);
            return NULL;
        }

        //
        // Check if root special case.
        //
        if (_strcmpi(lpObjectToFind, KM_OBJECTS_ROOT_DIRECTORY) == 0) {

            return ObpCopyObjectBasicInfo(DirectoryAddress,
                0,
                FALSE,
                NULL);
        }

        //
        // Not a root directory, scan given object directory.
        //
        for (BucketId = 0; BucketId < NUMBER_HASH_BUCKETS; BucketId++) {

            HeadItem = (ULONG_PTR)DirectoryObject.HashBuckets[BucketId];
            if (HeadItem != 0) {

                LookupItem = HeadItem;

                do {

                    //
                    // Read object directory entry, exit on fail.
                    //
                    RtlSecureZeroMemory(&DirectoryEntry, sizeof(OBJECT_DIRECTORY_ENTRY));

                    if (!kdReadSystemMemoryEx(LookupItem,
                        &DirectoryEntry,
                        sizeof(OBJECT_DIRECTORY_ENTRY),
                        NULL))
                    {
                        kdDebugPrint("%s kdReadSystemMemoryEx(OBJECT_DIRECTORY_ENTRY(HashEntry)) failed\r\n", __FUNCTION__);
                        break;
                    }

                    //
                    // Read object header, skip entry on fail.
                    //
                    RtlSecureZeroMemory(&ObjectHeader, sizeof(OBJECT_HEADER));
                    ObjectHeaderAddress = (ULONG_PTR)OBJECT_TO_OBJECT_HEADER(DirectoryEntry.Object);

                    if (!kdReadSystemMemoryEx(ObjectHeaderAddress,
                        &ObjectHeader,
                        sizeof(OBJECT_HEADER),
                        NULL))
                    {
                        kdDebugPrint("%s kdReadSystemMemoryEx(ObjectHeaderAddress(Entry.Object)) failed\r\n", __FUNCTION__);
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
                    retSize = 0;
                    lpObjectName = ObQueryNameString(InfoHeaderAddress, &retSize, g_WinObj.Heap);
                    if ((lpObjectName != NULL) && (retSize != 0)) {

                        //
                        // Compare full object names.
                        //
                        bFound = (_strcmpi(lpObjectName, lpObjectToFind) == 0);
                        supHeapFree(lpObjectName);

                        //
                        // if they're identical, allocate item info and copy it.
                        //
                        if (bFound) {

                            return ObpCopyObjectBasicInfo((ULONG_PTR)DirectoryEntry.Object,
                                ObjectHeaderAddress,
                                TRUE,
                                &ObjectHeader);

                        }
                    }

                NextItem:
                    LookupItem = (ULONG_PTR)DirectoryEntry.ChainLink;

                } while (LookupItem != 0);
            }
        }

    }
    __except (WOBJ_EXCEPTION_FILTER) {
        return NULL;
    }
    return NULL;
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
POBJINFO ObQueryObjectByAddress(
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

    if (!kdReadSystemMemoryEx(ObjectHeaderAddress,
        &ObjectHeader,
        sizeof(OBJECT_HEADER),
        NULL))
    {
        kdDebugPrint("%s kdReadSystemMemoryEx(ObjectHeaderAddress(ObjectAddress)) failed\r\n", __FUNCTION__);
        return NULL;
    }

    return ObpCopyObjectBasicInfo(ObjectAddress,
        ObjectHeaderAddress,
        TRUE,
        &ObjectHeader);
}

/*
* ObQueryObject
*
* Purpose:
*
* Look for object inside specified directory.
* If object is directory look for it in upper directory.
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

    if (!kdConnectDriver())
        return NULL;

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
            if (lpDirectory[i] == TEXT('\\'))
                l = i + 1;
        }
        SingleDirName = &lpDirectory[l];
        if (_strcmpi(SingleDirName, lpObjectName) == 0) {
            //
            //  2) If we are looking for directory itself, move search directory up
            //  e.g. lpDirectory = \ObjectTypes, lpObjectName = ObjectTypes then lpDirectory = \ 
            //
            ldirSz = rdirLen * sizeof(WCHAR) + sizeof(UNICODE_NULL);
            LookupDirName = (LPWSTR)supHeapAlloc(ldirSz);
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
            return ObpWalkDirectory(lpObjectName, DirectoryAddress);

        }
    }

    __except (WOBJ_EXCEPTION_FILTER) {
        return NULL;
    }
    return NULL;
}

/*
* ObDumpTypeInfo
*
* Purpose:
*
* Dumps Type header including initializer.
*
*/
BOOL ObDumpTypeInfo(
    _In_ ULONG_PTR ObjectAddress,
    _Inout_ POBJECT_TYPE_COMPATIBLE ObjectTypeInfo
)
{
    return kdReadSystemMemoryEx(ObjectAddress,
        ObjectTypeInfo,
        sizeof(OBJECT_TYPE_COMPATIBLE),
        NULL);
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
* ObpWalkDirectoryRecursive
*
* Purpose:
*
* Recursively dump Object Manager directories.
*
* Note:
*
* OBJECT_DIRECTORY definition changed in Windows 10, however this doesn't require
* this routine change as we rely here only on HashBuckets which is on same offset.
*
*/
VOID ObpWalkDirectoryRecursive(
    _In_ BOOL fIsRoot,
    _In_ PLIST_ENTRY ListHead,
    _In_ HANDLE ListHeap,
    _In_opt_ LPWSTR lpRootDirectory,
    _In_ ULONG_PTR DirectoryAddress,
    _In_ USHORT DirectoryTypeIndex
)
{
    UCHAR      ObjectTypeIndex;
    UINT       BucketId;
    SIZE_T     dirLen, fLen, rdirLen, retSize;
    ULONG_PTR  ObjectHeaderAddress, HeadItem, LookupItem, InfoHeaderAddress;
    POBJREF    ObjectEntry;
    LPWSTR     lpObjectName, lpDirectoryName;

    OBJECT_HEADER           ObjectHeader;
    OBJECT_DIRECTORY        DirectoryObject;
    OBJECT_DIRECTORY_ENTRY  DirectoryEntry;

    RtlZeroMemory(&DirectoryObject, sizeof(OBJECT_DIRECTORY));

    if (!kdReadSystemMemoryEx(DirectoryAddress,
        &DirectoryObject,
        sizeof(OBJECT_DIRECTORY),
        NULL))
    {
        kdDebugPrint("%s kdReadSystemMemoryEx(DirectoryAddress) failed\r\n", __FUNCTION__);
        return;
    }

    if (lpRootDirectory != NULL) {
        rdirLen = (1 + _strlen(lpRootDirectory)) * sizeof(WCHAR);
    }
    else {
        rdirLen = 0;
    }

    lpObjectName = NULL;
    retSize = 0;
    ObjectTypeIndex = 0;

    for (BucketId = 0; BucketId < NUMBER_HASH_BUCKETS; BucketId++) {

        HeadItem = (ULONG_PTR)DirectoryObject.HashBuckets[BucketId];
        if (HeadItem != 0) {

            LookupItem = HeadItem;

            do {

                //
                // Read object directory entry.
                //
                RtlZeroMemory(&DirectoryEntry, sizeof(OBJECT_DIRECTORY_ENTRY));

                if (kdReadSystemMemoryEx(LookupItem,
                    &DirectoryEntry,
                    sizeof(OBJECT_DIRECTORY_ENTRY),
                    NULL))
                {

                    //
                    // Read object.
                    // First read header from directory entry object.
                    //
                    RtlZeroMemory(&ObjectHeader, sizeof(OBJECT_HEADER));
                    ObjectHeaderAddress = (ULONG_PTR)OBJECT_TO_OBJECT_HEADER(DirectoryEntry.Object);

                    if (kdReadSystemMemoryEx(ObjectHeaderAddress,
                        &ObjectHeader,
                        sizeof(OBJECT_HEADER),
                        NULL))
                    {

                        //
                        // Second read object data.
                        // Query object name.
                        //
                        InfoHeaderAddress = 0;
                        retSize = 0;
                        if (ObHeaderToNameInfoAddress(ObjectHeader.InfoMask,
                            ObjectHeaderAddress,
                            &InfoHeaderAddress,
                            HeaderNameInfoFlag))
                        {
                            lpObjectName = ObQueryNameString(InfoHeaderAddress,
                                &retSize,
                                g_WinObj.Heap);
                        }

                        //
                        // Allocate object entry.
                        //
                        ObjectEntry = (POBJREF)RtlAllocateHeap(ListHeap,
                            HEAP_ZERO_MEMORY,
                            sizeof(OBJREF));

                        if (ObjectEntry) {

                            //
                            // Save object address.
                            //
                            ObjectEntry->ObjectAddress = (ULONG_PTR)DirectoryEntry.Object;
                            ObjectEntry->HeaderAddress = ObjectHeaderAddress;
                            ObjectEntry->TypeIndex = ObjectHeader.TypeIndex;

                            //
                            // Copy dir + name.
                            //
                            if (lpObjectName) {

                                fLen = (_strlen(lpObjectName) * sizeof(WCHAR)) +
                                    (2 * sizeof(WCHAR)) +
                                    rdirLen + sizeof(UNICODE_NULL);

                                ObjectEntry->ObjectName = (LPWSTR)RtlAllocateHeap(ListHeap,
                                    HEAP_ZERO_MEMORY,
                                    fLen);

                                if (ObjectEntry->ObjectName) {
                                    _strcpy(ObjectEntry->ObjectName, lpRootDirectory);
                                    if (fIsRoot == FALSE) {
                                        _strcat(ObjectEntry->ObjectName, L"\\");
                                    }
                                    _strcat(ObjectEntry->ObjectName, lpObjectName);
                                }
                            }

                            InsertHeadList(ListHead, &ObjectEntry->ListEntry);
                        }

                        //
                        // Check if current object is a directory.
                        //
                        ObjectTypeIndex = ObDecodeTypeIndex(DirectoryEntry.Object, ObjectHeader.TypeIndex);
                        if (ObjectTypeIndex == DirectoryTypeIndex) {

                            //
                            // Build new directory string (old directory + \ + current).
                            //
                            fLen = 0;
                            if (lpObjectName) {
                                fLen = retSize;
                            }

                            dirLen = fLen + rdirLen + (2 * sizeof(WCHAR)) + sizeof(UNICODE_NULL);
                            lpDirectoryName = (LPWSTR)supHeapAlloc(dirLen);
                            if (lpDirectoryName) {
                                _strcpy(lpDirectoryName, lpRootDirectory);
                                if (fIsRoot == FALSE) {
                                    _strcat(lpDirectoryName, L"\\");
                                }
                                if (lpObjectName) {
                                    _strcat(lpDirectoryName, lpObjectName);
                                }
                            }

                            //
                            // Walk subdirectory.
                            //
                            ObpWalkDirectoryRecursive(FALSE,
                                ListHead,
                                ListHeap,
                                lpDirectoryName,
                                (ULONG_PTR)DirectoryEntry.Object,
                                DirectoryTypeIndex);

                            if (lpDirectoryName) {
                                supHeapFree(lpDirectoryName);
                                lpDirectoryName = NULL;
                            }
                        }

                        if (lpObjectName) {
                            supHeapFree(lpObjectName);
                            lpObjectName = NULL;
                        }

                    } //if (kdReadSystemMemoryEx(OBJECT_HEADER)

                    LookupItem = (ULONG_PTR)DirectoryEntry.ChainLink;

                } //if (kdReadSystemMemoryEx(OBJECT_DIRECTORY_ENTRY)			
                else {
                    LookupItem = 0;
                }

            } while (LookupItem != 0); // do
        }
    }
}

/*
* ObpWalkPrivateNamespaceTable
*
* Purpose:
*
* Dump Object Manager private namespace objects.
*
* Note:
*
* OBJECT_DIRECTORY definition changed in Windows 10, however this doesn't require
* this routine change as we rely here only on HashBuckets which is on same offset.
*
*/
BOOL ObpWalkPrivateNamespaceTable(
    _In_ PLIST_ENTRY ListHead,
    _In_ HANDLE ListHeap,
    _In_ ULONG_PTR TableAddress
)
{
    ULONG         i, j = 0;
    ULONG         objectsCount = 0;
    ULONG_PTR     ObjectHeaderAddress, HeadItem, LookupItem, InfoHeaderAddress;
    PLIST_ENTRY   Next, Head;
    LIST_ENTRY    ListEntry;
    POBJREF       ObjectEntry;

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

    //
    // Dump namespace lookup table.
    //
    RtlSecureZeroMemory(&LookupTable, sizeof(OBJECT_NAMESPACE_LOOKUPTABLE));

    if (!kdReadSystemMemoryEx(TableAddress,
        &LookupTable,
        sizeof(OBJECT_NAMESPACE_LOOKUPTABLE),
        NULL))
    {
        return FALSE;
    }

    for (i = 0; i < NUMBER_HASH_BUCKETS; i++) {

        ListEntry = LookupTable.HashBuckets[i];

        Head = (PLIST_ENTRY)(TableAddress + (i * sizeof(LIST_ENTRY)));
        Next = ListEntry.Flink;

        while (Next != Head) {

            RtlSecureZeroMemory(&LookupEntry, sizeof(OBJECT_NAMESPACE_ENTRY));

            if (!kdReadSystemMemoryEx((ULONG_PTR)Next,
                &LookupEntry,
                sizeof(OBJECT_NAMESPACE_ENTRY),
                NULL))
            {
                break;
            }

            ListEntry = LookupEntry.ListEntry;

            RtlSecureZeroMemory(&DirObject, sizeof(OBJECT_DIRECTORY));

            if (!kdReadSystemMemoryEx((ULONG_PTR)LookupEntry.NamespaceRootDirectory,
                &DirObject,
                sizeof(OBJECT_DIRECTORY),
                NULL))
            {
                break;
            }

            for (j = 0; j < NUMBER_HASH_BUCKETS; j++) {

                HeadItem = (ULONG_PTR)DirObject.HashBuckets[j];
                if (HeadItem != 0) {

                    LookupItem = HeadItem;

                    do {

                        RtlSecureZeroMemory(&Entry, sizeof(OBJECT_DIRECTORY_ENTRY));

                        if (kdReadSystemMemoryEx(LookupItem,
                            &Entry,
                            sizeof(OBJECT_DIRECTORY_ENTRY),
                            NULL)) {

                            RtlSecureZeroMemory(&ObjectHeader, sizeof(OBJECT_HEADER));
                            ObjectHeaderAddress = (ULONG_PTR)OBJECT_TO_OBJECT_HEADER(Entry.Object);

                            if (kdReadSystemMemoryEx(ObjectHeaderAddress,
                                &ObjectHeader,
                                sizeof(OBJECT_HEADER),
                                NULL))
                            {
                                //
                                // Allocate object entry
                                //
                                ObjectEntry = (POBJREF)RtlAllocateHeap(ListHeap,
                                    HEAP_ZERO_MEMORY,
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
                                        ObjectEntry->ObjectName = ObQueryNameString(InfoHeaderAddress,
                                            NULL,
                                            ListHeap);

                                    }

                                    objectsCount += 1;
                                    InsertHeadList(ListHead, &ObjectEntry->ListEntry);

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
    return (objectsCount > 0);
}

/*
* ObCollectionCreateInternal
*
* Purpose:
*
* Create collection of object directory dumped info.
*
* Collection must be destroyed with ObCollectionDestroy after use.
*
* If specified will dump private namespace objects.
*
*/
BOOL ObCollectionCreateInternal(
    _In_ POBJECT_COLLECTION Collection,
    _In_ BOOL fNamespace
)
{
    BOOL bResult = FALSE;

    Collection->Heap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);

    if (Collection->Heap == NULL)
        return FALSE;

    RtlSetHeapInformation(Collection->Heap, HeapEnableTerminationOnCorruption, NULL, 0);

    __try {

        InitializeListHead(&Collection->ListHead);

        if (fNamespace == FALSE) {
            if (
                (g_kdctx.DirectoryRootAddress == 0) ||
                (g_kdctx.DirectoryTypeIndex == 0)
                )
            {
                if (!ObGetDirectoryObjectAddress(NULL,
                    &g_kdctx.DirectoryRootAddress,
                    &g_kdctx.DirectoryTypeIndex))
                {
                    SetLastError(ERROR_INTERNAL_ERROR);
                    goto _FailWeLeave;
                }
            }

            if (
                (g_kdctx.DirectoryRootAddress != 0) &&
                (g_kdctx.DirectoryTypeIndex != 0)
                )
            {
                ObpWalkDirectoryRecursive(TRUE,
                    &Collection->ListHead,
                    Collection->Heap,
                    KM_OBJECTS_ROOT_DIRECTORY,
                    g_kdctx.DirectoryRootAddress,
                    g_kdctx.DirectoryTypeIndex);

                bResult = TRUE;
            }
        }
        else {

            if (g_kdctx.Data->PrivateNamespaceLookupTable == NULL)
                g_kdctx.Data->PrivateNamespaceLookupTable = ObFindPrivateNamespaceLookupTable(&g_kdctx);

            if (g_kdctx.Data->PrivateNamespaceLookupTable != NULL) {

                bResult = ObpWalkPrivateNamespaceTable(&Collection->ListHead,
                    Collection->Heap,
                    (ULONG_PTR)g_kdctx.Data->PrivateNamespaceLookupTable);

            }
            else {
                SetLastError(ERROR_INTERNAL_ERROR);
            }
        }

    }
    __except (WOBJ_EXCEPTION_FILTER) {
        bResult = FALSE;
    }

_FailWeLeave:

    return bResult;
}

/*
* ObCollectionCreate
*
* Purpose:
*
* Create collection of object directory dumped info.
*
* Collection must be destroyed with ObCollectionDestroy after use.
*
* Calls internal function.
*
*/
BOOL ObCollectionCreate(
    _In_ POBJECT_COLLECTION Collection,
    _In_ BOOL fNamespace,
    _In_ BOOL Locked
)
{
    BOOL bResult = FALSE;

    if (Collection == NULL)
        return bResult;

    if (!kdConnectDriver())
        return bResult;

    if (Locked) {
        bResult = ObCollectionCreateInternal(Collection, fNamespace);
    }
    else {
        EnterCriticalSection(&g_kdctx.ObCollectionLock);
        bResult = ObCollectionCreateInternal(Collection, fNamespace);
        LeaveCriticalSection(&g_kdctx.ObCollectionLock);
    }

    return bResult;
}

/*
* ObCollectionDestroy
*
* Purpose:
*
* Destroy collection with object directory dumped info
*
*/
VOID ObCollectionDestroy(
    _In_ POBJECT_COLLECTION Collection
)
{
    if (Collection == NULL)
        return;

    EnterCriticalSection(&g_kdctx.ObCollectionLock);

    if (Collection->Heap) {
        RtlDestroyHeap(Collection->Heap);
        Collection->Heap = NULL;
    }
    InitializeListHead(&Collection->ListHead);

    LeaveCriticalSection(&g_kdctx.ObCollectionLock);
}

/*
* ObCollectionEnumerate
*
* Purpose:
*
* Enumerate object collection and callback on each element.
*
*/
BOOL ObCollectionEnumerate(
    _In_ POBJECT_COLLECTION Collection,
    _In_ PENUMERATE_COLLECTION_CALLBACK Callback,
    _In_opt_ PVOID Context
)
{
    BOOL        bCancelled = FALSE;
    POBJREF     ObjectEntry = NULL;
    PLIST_ENTRY Head, Next;

    if ((Collection == NULL) || (Callback == NULL))
        return FALSE;

    EnterCriticalSection(&g_kdctx.ObCollectionLock);

    if (!IsListEmpty(&Collection->ListHead)) {
        Head = &Collection->ListHead;
        Next = Head->Flink;
        while ((Next != NULL) && (Next != Head)) {
            ObjectEntry = CONTAINING_RECORD(Next, OBJREF, ListEntry);
            bCancelled = Callback(ObjectEntry, Context);
            if (bCancelled)
                break;

            Next = Next->Flink;
        }
    }

    LeaveCriticalSection(&g_kdctx.ObCollectionLock);

    return (bCancelled == FALSE);
}

/*
* ObCollectionFindByAddress
*
* Purpose:
*
* Find object by address in object directory dump collection.
* Use supHeapFree to free memory.
*
*/
POBJREF ObCollectionFindByAddress(
    _In_ POBJECT_COLLECTION Collection,
    _In_ ULONG_PTR ObjectAddress,
    _In_ BOOLEAN fNamespace
)
{
    BOOL        IsCollectionPresent = FALSE;
    POBJREF     objectEntry = NULL, returnObject = NULL;
    PLIST_ENTRY Head, Next;

    if (Collection == NULL)
        return NULL;

    EnterCriticalSection(&g_kdctx.ObCollectionLock);

    if (IsListEmpty(&Collection->ListHead)) {
        IsCollectionPresent = ObCollectionCreate(Collection, fNamespace, TRUE);
    }
    else {
        IsCollectionPresent = TRUE;
    }

    if (IsCollectionPresent) {
        Head = &Collection->ListHead;
        Next = Head->Flink;
        while ((Next != NULL) && (Next != Head)) {
            objectEntry = CONTAINING_RECORD(Next, OBJREF, ListEntry);
            if (objectEntry->ObjectAddress == ObjectAddress) {

                returnObject = (POBJREF)supHeapAlloc(sizeof(OBJREF));
                if (returnObject) {
                    RtlCopyMemory(returnObject, objectEntry, sizeof(OBJREF));

                    returnObject->ObjectName = (LPWSTR)supHeapAlloc(
                        (1 + _strlen(objectEntry->ObjectName)) * sizeof(WCHAR));

                    if (returnObject->ObjectName) {
                        _strcpy(returnObject->ObjectName, objectEntry->ObjectName);
                    }

                }

                break;
            }
            Next = Next->Flink;
        }
    }

    LeaveCriticalSection(&g_kdctx.ObCollectionLock);

    return returnObject;
}

/*
* kdConnectDriver
*
* Purpose:
*
* Acquire handle of helper driver device if possible.
*
* N.B.
*
*   If device handle is already present function immediately return TRUE.
*   If current token is not elevated admin token function immediately return FALSE.
*   SE_DEBUG_PRIVILEGE is required, if it cannot be assigned function return FALSE.
*
*/
BOOLEAN kdConnectDriver(
    VOID)
{
    NTSTATUS status;
    HANDLE deviceHandle = NULL;
    UNICODE_STRING usDevice;
    OBJECT_ATTRIBUTES obja;
    IO_STATUS_BLOCK iost;

    WCHAR szDeviceName[100];

    if (g_kdctx.IsFullAdmin == FALSE)
        return FALSE;

    if (g_kdctx.DeviceHandle != NULL)
        return TRUE;

#ifdef _USE_WINIO
    //
    // Cannot use address translation on legacy boot.
    //
    if (g_kdctx.Data->FirmwareType != FirmwareTypeUefi) {
        g_kdctx.DriverOpenLoadStatus = (ULONG)STATUS_NOT_SUPPORTED;
        return FALSE;
    }
#endif

    if (supEnablePrivilege(SE_DEBUG_PRIVILEGE, TRUE)) {

        _strcpy(szDeviceName, TEXT("\\Device\\"));
        _strcat(szDeviceName, KLDBGDRV);
        RtlInitUnicodeString(&usDevice, szDeviceName);
        InitializeObjectAttributes(&obja, &usDevice, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = NtCreateFile(&deviceHandle,
            GENERIC_READ | GENERIC_WRITE,
            &obja,
            &iost,
            NULL,
            0,
            0,
            FILE_OPEN,
            0,
            NULL,
            0);

        if (NT_SUCCESS(status)) {
            g_kdctx.DeviceHandle = deviceHandle;
            g_kdctx.DriverConnectStatus = status;
            return TRUE;
        }
        else {
            supEnablePrivilege(SE_DEBUG_PRIVILEGE, FALSE);
            g_kdctx.DriverConnectStatus = status;
        }
    }

    return FALSE;
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
    POBJINFO        pSelfObj;
    ULONG_PTR       drvObjectAddress;
    DRIVER_OBJECT   drvObject;

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

        pSelfObj = ObQueryObject(L"\\Driver", KLDBGDRV);
        if (pSelfObj) {

            drvObjectAddress = pSelfObj->ObjectAddress;

            RtlSecureZeroMemory(&drvObject, sizeof(drvObject));

            if (kdReadSystemMemoryEx(drvObjectAddress,
                &drvObject,
                sizeof(drvObject),
                NULL))
            {
                pHandler = drvObject.MajorFunction[IRP_MJ_CREATE_MAILSLOT];

                //
                // IopInvalidDeviceRequest is a routine inside ntoskrnl.
                //
                if (!kdAddressInNtOsImage(pHandler))
                    pHandler = NULL;
            }
            supHeapFree(pSelfObj);
        }

    }
    return pHandler;
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
    _In_ LPWSTR FunctionName,
    _In_ ULONG_PTR KernelAddress,
    _In_ ULONG InputBufferLength,
    _In_ NTSTATUS Status,
    _In_ PIO_STATUS_BLOCK Iosb
)
{
    WCHAR szBuffer[512];

    RtlStringCchPrintfSecure(szBuffer,
        512,
        TEXT("%ws 0x%lX, read at 0x%llX, Iosb(0x%lX, 0x%lX), InputBufferLength 0x%lX"),
        FunctionName,
        Status,
        KernelAddress,
        Iosb->Status,
        Iosb->Information,
        InputBufferLength);

    logAdd(WOBJ_LOG_ENTRY_ERROR,
        szBuffer);
}

/*
* kdpReadSystemMemoryEx
*
* Purpose:
*
* Wrapper around SysDbgReadVirtual request to the KLDBGDRV
*
*/
BOOL kdpReadSystemMemoryEx(
    _In_ ULONG_PTR Address,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG NumberOfBytesRead
)
{
    NTSTATUS        status;
    KLDBG           kldbg;
    IO_STATUS_BLOCK iost;
    SYSDBG_VIRTUAL  dbgRequest;

    if (NumberOfBytesRead)
        *NumberOfBytesRead = 0;

    if ((Buffer == NULL) || (BufferSize == 0))
        return FALSE;

    if (Address < g_kdctx.SystemRangeStart)
        return FALSE;

    if (!kdConnectDriver())
        return FALSE;

    //
    // Fill parameters for KdSystemDebugControl.
    //
    dbgRequest.Address = (PVOID)Address;
    dbgRequest.Buffer = Buffer;
    dbgRequest.Request = BufferSize;

    //
    // Fill parameters for kldbgdrv ioctl.
    //
    kldbg.SysDbgRequest = SysDbgReadVirtual;
    kldbg.Buffer = &dbgRequest;
    kldbg.BufferSize = sizeof(SYSDBG_VIRTUAL);

    iost.Information = 0;
    iost.Status = 0;

    status = NtDeviceIoControlFile(g_kdctx.DeviceHandle,
        NULL,
        NULL,
        NULL,
        &iost,
        IOCTL_KD_PASS_THROUGH,
        &kldbg,
        sizeof(kldbg),
        &dbgRequest,
        sizeof(dbgRequest));

    if (status == STATUS_PENDING) {

        status = NtWaitForSingleObject(g_kdctx.DeviceHandle,
            FALSE,
            NULL);

        if (NT_SUCCESS(status))
            status = iost.Status;
    }

    if (NT_SUCCESS(status)) {

        if (NumberOfBytesRead)
            *NumberOfBytesRead = (ULONG)iost.Information;

        return TRUE;
    }
    else {
        //
        // We don't need this information in case of error.
        //
        if (!NT_ERROR(status)) {
            if (NumberOfBytesRead)
                *NumberOfBytesRead = (ULONG)iost.Information;
        }

        kdReportReadError(__FUNCTIONW__, Address, BufferSize, status, &iost);
        return FALSE;
    }
}

/*
* kdExtractDriverResource
*
* Purpose:
*
* Extract KLDBGDRV from application resource
*
*/
BOOL kdExtractDriverResource(
    _In_ LPCWSTR lpExtractTo,
    _In_ LPCWSTR lpName,
    _In_ LPCWSTR lpType
)
{
    HRSRC   hResInfo = NULL;
    HGLOBAL hResData = NULL;
    PVOID   pData;
    BOOL    bResult = FALSE;
    DWORD   dwSize = 0, dwLastError = ERROR_SUCCESS;
    HANDLE  hFile;

    hResInfo = FindResource(g_WinObj.hInstance, lpName, lpType);
    if (hResInfo == NULL) {
        SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND);
        return bResult;
    }

    dwSize = SizeofResource(g_WinObj.hInstance, hResInfo);
    if (dwSize == 0) {
        return bResult;
    }

    hResData = LoadResource(g_WinObj.hInstance, hResInfo);
    if (hResData == NULL) {
        return bResult;
    }

    pData = LockResource(hResData);
    if (pData == NULL) {
        return bResult;
    }

    hFile = CreateFile(lpExtractTo,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        0,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return bResult;
    }
    else {
        bResult = WriteFile(hFile, pData, dwSize, &dwSize, NULL);
        if (!bResult) dwLastError = GetLastError();
        CloseHandle(hFile);
    }

    SetLastError(dwLastError);
    return bResult;
}

/*
* kdExtractDriver
*
* Purpose:
*
* Save driver to system32\drivers from application resource.
*
* N.B. If driver already exist on disk function return TRUE.
* This is required for WinDBG compatibility.
*
*/
BOOL kdExtractDriver(
    _In_ WCHAR * szDriverPath
)
{
    BOOL bResult = FALSE;

    //
    // If no file exists, extract it to the drivers directory.
    //
    bResult = PathFileExists(szDriverPath);

    if (!bResult) {
        bResult = kdExtractDriverResource(szDriverPath, MAKEINTRESOURCE(IDR_KDBGDRV), L"SYS");
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
    _In_ LPCWSTR ImageFileName
)
{
    BOOL bResult = FALSE;
#ifndef _DEBUG
    HWND hwndBanner = NULL;
    WCHAR szText[(64 + MAX_PATH) * 2];
#endif

    if (SymContext == NULL)
        return FALSE;

    if (SymContext->ModuleBase != 0)
        return TRUE;

#ifndef _DEBUG
    __try {
        _strcpy(szText, TEXT("Please wait, loading symbols for "));
        _strcat(szText, ImageFileName);
        hwndBanner = supDisplayLoadBanner(NULL, szText, TEXT("Load symbols"), TRUE);
#endif

        bResult = SymContext->Parser.LoadModule(
            SymContext,
            ImageFileName,
            (DWORD64)0,
            (DWORD64)0);

#ifndef _DEBUG
    }
    __finally {
        if (hwndBanner) {
            Sleep(1000);
            supCloseLoadBanner(hwndBanner);
        }
    }
#endif
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
                szFileName);

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

    //
    // Query "\\" directory address and remember directory object type index.
    //
    ObGetDirectoryObjectAddress(NULL,
        &Context->DirectoryRootAddress,
        &Context->DirectoryTypeIndex);

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
* kdQueryMmUnloadedDrivers
*
* Purpose:
*
* Locate and dump kernel MmUnloadedDrivers array.
*
*/
BOOLEAN kdQueryMmUnloadedDrivers(
    _In_ PKLDBGCONTEXT Context,
    _Out_ PVOID* UnloadedDrivers
)
{
    BOOLEAN             bResult = FALSE;

    HMODULE             hNtOs;
    ULONG_PTR           NtOsBase, lookupAddress = 0;

    PBYTE               ptrCode, sigPattern;
    PVOID               SectionBase;
    ULONG               SectionSize = 0, bytesRead = 0;

    PUNLOADED_DRIVERS   pvDrivers = NULL;
    PWCHAR              pwStaticBuffer = NULL;
    WORD                wMax, wLength;

    ULONG               cbData, sigSize;

    ULONG               Index = 0, instLength = 0, tempOffset;
    LONG                relativeValue = 0;
    hde64s              hs;

    PKLDBG_SYSTEM_ADDRESS kdpMmUnloadedDrivers = &Context->Data->MmUnloadedDrivers;


    *UnloadedDrivers = NULL;

    NtOsBase = (ULONG_PTR)Context->NtOsBase;
    hNtOs = (HMODULE)Context->NtOsImageMap;

    do {

        pwStaticBuffer = (PWCHAR)supHeapAlloc(UNICODE_STRING_MAX_BYTES + sizeof(UNICODE_NULL));
        if (pwStaticBuffer == NULL)
            break;

        if (kdpMmUnloadedDrivers->Valid == FALSE) {

            //
            // Symbols lookup.
            //
            if (kdIsSymAvailable((PSYMCONTEXT)Context->NtOsSymContext)) {

                kdGetAddressFromSymbol(
                    Context,
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
                    PAGE_SECTION_LEGNTH,
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
            if (!kdReadSystemMemoryEx(lookupAddress, &lookupAddress, sizeof(ULONG_PTR), &bytesRead))
                break;

            //
            // Store resolved array address in the private data context.
            //
            kdpMmUnloadedDrivers->Address = lookupAddress;
            kdpMmUnloadedDrivers->Valid = TRUE;

        }
        else {

            //
            // Array address already resolved.
            //
            lookupAddress = kdpMmUnloadedDrivers->Address;
        }

        //
        // Dump array to user mode.
        //
        cbData = MI_UNLOADED_DRIVERS * sizeof(UNLOADED_DRIVERS);
        pvDrivers = (PUNLOADED_DRIVERS)supHeapAlloc(cbData);
        if (pvDrivers) {

            if (!kdReadSystemMemoryEx(lookupAddress, pvDrivers, cbData, &bytesRead))
                break;

            bResult = TRUE;

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

                    RtlCreateUnicodeString(&pvDrivers[Index].Name,
                        pwStaticBuffer);

                }
            }

        }

    } while (FALSE);

    if (bResult == FALSE) {
        if (pvDrivers) {

            for (Index = 0; Index < MI_UNLOADED_DRIVERS; Index++) {

                if (NT_SUCCESS(ObIsValidUnicodeString(&pvDrivers[Index].Name)))
                {
                    RtlFreeUnicodeString(&pvDrivers[Index].Name);
                }

            }

            supHeapFree(pvDrivers);
            pvDrivers = NULL;
        }
    }

    if (pwStaticBuffer)
        supHeapFree(pwStaticBuffer);

    *UnloadedDrivers = pvDrivers;

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
                    kdDebugPrint("Kse routine not found\r\n");
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
                kdDebugPrint("KseEngine address is invalid\r\n");
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

        if (kdReadSystemMemoryEx(KseShimmedDriversListHead,
            &ListEntry,
            sizeof(LIST_ENTRY),
            NULL))
        {
            while ((ULONG_PTR)ListEntry.Flink != KseShimmedDriversListHead) {

                ShimmedDriver = (KSE_SHIMMED_DRIVER*)supHeapAlloc(sizeof(KSE_SHIMMED_DRIVER));
                if (ShimmedDriver == NULL) {
                    KseEngineDumpValid = FALSE;
                    break;
                }

                if (!kdReadSystemMemoryEx((ULONG_PTR)ListEntry.Flink,
                    ShimmedDriver,
                    sizeof(KSE_SHIMMED_DRIVER),
                    NULL))
                {
                    supHeapFree(ShimmedDriver);
                    KseEngineDumpValid = FALSE;
                    kdDebugPrint("KseEngine entry read error\r\n");
                    break;
                }

                ListEntry.Flink = ShimmedDriver->ListEntry.Flink;
                InsertHeadList(&pKseEngineDump->ShimmedDriversDumpListHead, &ShimmedDriver->ListEntry);
            }
        }
        else {
            kdDebugPrint("KseEngine->ShimmedDriversListHead read error\r\n");
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
* kdpOpenLoadDriverPublic
*
* Purpose:
*
* Open handle to WINDBG driver device or load this driver.
*
*/
BOOLEAN kdpOpenLoadDriverPublic(
    _In_ WCHAR * szDriverPath
)
{
    BOOLEAN bResult;

    //
    // First, try to open existing device.
    //
    bResult = scmOpenDevice(KLDBGDRV,
        &g_kdctx.DeviceHandle,
        (PDWORD)&g_kdctx.DriverOpenLoadStatus);

    if (bResult) {
        return bResult;
    }

    //
    // Next, if device not opened, extract driver.
    //
    if (!kdExtractDriver(szDriverPath)) {
        g_kdctx.DriverOpenLoadStatus = GetLastError();
        return FALSE;
    }

    //
    // Finally, try to load driver ourself.
    //
    bResult = scmLoadDeviceDriver(KLDBGDRV,
        szDriverPath,
        &g_kdctx.DeviceHandle,
        (PDWORD)&g_kdctx.DriverOpenLoadStatus);

    g_kdctx.IsOurLoad = bResult;

    return bResult;
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
    _In_opt_ SYMCONTEXT *SymContext
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
        TEXT("%ws: Retrieving offset for symbol \"%ws\" field \"%ws\""),
        __FUNCTIONW__,
        SymbolName,
        FieldName);

    logAdd(WOBJ_LOG_ENTRY_INFORMATION, szLog);

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
        TEXT("%ws: Result %lu, field offset 0x%lX"),
        __FUNCTIONW__,
        bResult,
        *Offset);

    logAdd(WOBJ_LOG_ENTRY_INFORMATION, szLog);

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

    logAdd(WOBJ_LOG_ENTRY_INFORMATION, szLog);

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
        TEXT("%ws: Result %lu, address 0x%llX"),
        __FUNCTIONW__,
        bResult,
        address);

    logAdd(WOBJ_LOG_ENTRY_INFORMATION, szLog);

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
    BOOL bResult = FALSE;
    ULONG_PTR address = 0;
    PSYMCONTEXT symContext = (PSYMCONTEXT)Context->NtOsSymContext;

    *Address = 0;

    bResult = kdGetAddressFromSymbolEx(symContext,
        SymbolName,
        Context->NtOsBase,
        Context->NtOsSize,
        &address);

    if (bResult) {

        *Address = address;

    }

    return bResult;
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
    _In_opt_ ULONG64 CallbackData,
    _In_opt_ ULONG64 UserContext
)
{
    PIMAGEHLP_CBA_EVENT pEvent;

    UNREFERENCED_PARAMETER(hProcess);
    UNREFERENCED_PARAMETER(UserContext);

    switch (ActionCode) {

    case CBA_EVENT:
        if (CallbackData) {
            pEvent = (PIMAGEHLP_CBA_EVENT)CallbackData;
            if (pEvent->severity == sevInfo) {              
                if (pEvent->desc[0] > 0x20 && pEvent->desc[0] < 0x7f) {
                    supUpdateLoadBannerText(g_hwndBanner, pEvent->desc, TRUE);
                }
            }
        }
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
    VOID
)
{
    ULONG cch;

    WCHAR szFileName[MAX_PATH * 2];

    if (g_kdctx.NtOsSymContext != NULL)
        return TRUE;

    szFileName[0] = 0;
    cch = GetCurrentDirectory(MAX_PATH, szFileName);
    if (cch > 0 && cch < MAX_PATH) {

        supPathAddBackSlash(szFileName);

        _strcat(szFileName, TEXT("symdll\\dbghelp.dll"));

        if (PathFileExists(szFileName)) {

            if (SymGlobalsInit(
                SYMOPT_DEFERRED_LOADS |
                SYMOPT_SECURE |
                SYMOPT_EXACT_SYMBOLS |
                SYMOPT_DEBUG |
                SYMOPT_FAIL_CRITICAL_ERRORS,
                NULL,
                szFileName,
                NULL,
                g_WinObj.szSystemDirectory,
                g_WinObj.szTempDirectory,
                (PSYMBOL_REGISTERED_CALLBACK64)symCallbackProc,
                0))
            {
                g_kdctx.NtOsSymContext = (PVOID)SymParserCreate();
            }
        }

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
    BOOLEAN bLoadState;
    WCHAR szBuffer[MAX_PATH * 2];

    RtlSecureZeroMemory(&g_kdctx, sizeof(g_kdctx));
    RtlSecureZeroMemory(&g_kdpdata, sizeof(g_kdpdata));
    RtlSecureZeroMemory(&g_SystemCallbacks, sizeof(g_SystemCallbacks));

    g_kdctx.IsFullAdmin = IsFullAdmin;

    g_kdctx.Data = &g_kdpdata;

    NtpLdrExceptionFilter = (PFNNTLDR_EXCEPT_FILTER)exceptFilterWithLog;

    //
    // Default driver load status.
    //
    g_kdctx.DriverOpenLoadStatus = ERROR_NOT_CAPABLE;

    InitializeListHead(&g_kdctx.Data->KseEngineDump.ShimmedDriversDumpListHead);
    InitializeListHead(&g_kdctx.ObCollection.ListHead);
    RtlInitializeCriticalSection(&g_kdctx.ObCollectionLock);

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
    symInit();

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

    //
    // Helper drivers does not need DEBUG mode.
    //

#ifndef _USE_OWN_DRIVER
    //
    // Check if system booted in the debug mode.
    //
    if (ntsupIsKdEnabled(NULL, NULL) == FALSE)
        return;

#endif /* _USE_OWN_DRIVER */

    //
    // Build path to driver.
    //
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    _strcpy(szBuffer, g_WinObj.szSystemDirectory);
    _strcat(szBuffer, KLDBGDRVSYS);

    //
    // Test privilege assigned and continue to load/open kldbg driver.
    //
    if (supEnablePrivilege(SE_DEBUG_PRIVILEGE, TRUE)) {

#ifdef _USE_OWN_DRIVER

        bLoadState = kdpOpenLoadDriverPrivate(szBuffer);

#else

        bLoadState = kdpOpenLoadDriverPublic(szBuffer);

#endif

        if (bLoadState == FALSE) {

            RtlStringCchPrintfSecure(szBuffer,
                MAX_PATH,
                TEXT("Could not open/load helper driver.\r\nSome features maybe unavailable, error code 0x%lX"),
                g_kdctx.DriverOpenLoadStatus);

            MessageBox(GetDesktopWindow(), szBuffer, TEXT("WinObjEx64"), MB_ICONINFORMATION);

        }

    }

    //
    // Init driver relying variables.
    //
    if (g_kdctx.DeviceHandle != NULL) {
        //
        // Query Ob specific offsets.
        //
        ObpInitInfoBlockOffsets();

        //
        // Locate and remember ObHeaderCookie, routine require driver usage, do not move.
        //
        if (g_WinObj.osver.dwMajorVersion >= 10) {
            ObpFindHeaderCookie(&g_kdctx);
        }

    }

}

/*
* kdpRemoveDriverFile
*
* Purpose:
*
* Delete driver file.
*
*/
VOID kdpRemoveDriverFile()
{
    WCHAR szDrvPath[MAX_PATH * 2];

    //
    // Driver file is no longer needed - remove it from disk.
    //
    RtlSecureZeroMemory(&szDrvPath, sizeof(szDrvPath));
    _strcpy(szDrvPath, g_WinObj.szSystemDirectory);
    _strcat(szDrvPath, KLDBGDRVSYS);
    DeleteFile(szDrvPath);
}

/*
* kdpUnloadWindbgDriver
*
* Purpose:
*
* Unload driver, unregister and remove service and delete driver file.
*
*/
VOID kdpUnloadWindbgDriver()
{
    //
    // If we loaded Windbg driver - unload it, otherwise leave it as is.
    //
    if (g_kdctx.IsOurLoad) {
        //
        // Windbg recreates service and drops file everytime when kernel debug starts.
        //
        scmUnloadDeviceDriver(KLDBGDRV, NULL);
        kdpRemoveDriverFile();
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

    //
    // Close device handle and make it invalid.
    //
    if (g_kdctx.DeviceHandle) {
        CloseHandle(g_kdctx.DeviceHandle);
        g_kdctx.DeviceHandle = NULL;
    }

    //
    // Destroy collection if present.
    //
    ObCollectionDestroy(&g_kdctx.ObCollection);
    RtlDeleteCriticalSection(&g_kdctx.ObCollectionLock);

#ifdef _USE_OWN_DRIVER
    kdpUnloadHelperDriver();
#else
    kdpUnloadWindbgDriver();
#endif

    if (g_kdctx.NtOsImageMap) {
        FreeLibrary((HMODULE)g_kdctx.NtOsImageMap);
        g_kdctx.NtOsImageMap = NULL;
    }

    //
    // Deallocate symbols context if present.
    //
    symShutdown();
}
