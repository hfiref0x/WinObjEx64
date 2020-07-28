/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       KLDBG.C, based on KDSubmarine by Evilcry
*
*  VERSION:     1.87
*
*  DATE:        23 July 2020
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

//
// Global variables, declared as extern in kldbg.h
//

//Context
KLDBGCONTEXT g_kdctx;

//Build number
ULONG g_NtBuildNumber;

//Callbacks
NOTIFICATION_CALLBACKS g_SystemCallbacks;

UCHAR ObpInfoMaskToOffset[0x100];

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
    ULONG sdLength = 0;
    PSECURITY_DESCRIPTOR driverSD = NULL;

    WCHAR szBuffer[MAX_PATH + 1];

    if (DriverName == NULL)
        return STATUS_INVALID_PARAMETER_1;
    if (DriverPath == NULL)
        return STATUS_INVALID_PARAMETER_2;

    status = supCreateSystemAdminAccessSD(&driverSD, &sdLength);
    if (!NT_SUCCESS(status))
        return status;

    RtlInitEmptyUnicodeString(&driverImagePath, NULL, 0);
    if (!RtlDosPathNameToNtPathName_U(DriverPath,
        &driverImagePath,
        NULL,
        NULL))
    {
        supHeapFree(driverSD);
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
    RtlFreeUnicodeString(&driverImagePath);
    return status;
}

/*
* kdOpenLoadDriverPrivate
*
* Purpose:
*
* Open handle to helper driver device or load this driver.
*
*/
BOOL kdOpenLoadDriverPrivate(
    _In_ WCHAR* szDriverPath
)
{
    NTSTATUS ntStatus;

    //
    // First, try to open existing device.
    //
    ntStatus = kdOpenHelperDevice(KLDBGDRV,
        GENERIC_READ | GENERIC_WRITE,
        &g_kdctx.DeviceHandle);

    if (NT_SUCCESS(ntStatus)) {
        g_kdctx.DriverOpenLoadStatus = STATUS_SUCCESS;
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
        g_kdctx.DriverOpenLoadStatus = ntStatus;
        return FALSE;
    }

    g_kdctx.IsOurLoad = TRUE;

    //
    // Finally, try to open drive device again.
    //
    ntStatus = kdOpenHelperDevice(KLDBGDRV,
        GENERIC_READ | GENERIC_WRITE,
        &g_kdctx.DeviceHandle);

    g_kdctx.DriverOpenLoadStatus = ntStatus;

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
* Initialize block offfsets table for working with OBJECT_HEADER data.
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
_Success_(return != NULL)
PVOID ObpDumpObjectWithSpecifiedSize(
    _In_ ULONG_PTR ObjectAddress,
    _In_ ULONG ObjectSize,
    _In_ ULONG ObjectVersion,
    _Out_ PULONG ReadSize,
    _Out_ PULONG ReadVersion
)
{
    PVOID ObjectBuffer = NULL;
    ULONG BufferSize = ALIGN_UP_BY(ObjectSize, PAGE_SIZE);

    ObjectBuffer = supVirtualAlloc(BufferSize);
    if (ObjectBuffer == NULL) {
        return NULL;
    }

    if (!kdReadSystemMemory(ObjectAddress,
        ObjectBuffer,
        (ULONG)ObjectSize))
    {
        supVirtualFree(ObjectBuffer);
        return NULL;
    }

    if (ReadSize)
        *ReadSize = ObjectSize;
    if (ReadVersion)
        *ReadVersion = ObjectVersion;

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
    ULONG ObjectSize = 0;
    ULONG ObjectVersion = 0;

    //assume failure
    if (Size) *Size = 0;
    if (Version) *Version = 0;
    if (ObjectAddress < g_kdctx.SystemRangeStart)
        return NULL;

    switch (g_NtBuildNumber) {
    case NT_WIN7_RTM:
    case NT_WIN7_SP1:
        ObjectSize = sizeof(OBJECT_TYPE_7);
        ObjectVersion = 1;
        break;
    case NT_WIN8_RTM:
    case NT_WIN8_BLUE:
    case NT_WIN10_THRESHOLD1:
    case NT_WIN10_THRESHOLD2:
        ObjectSize = sizeof(OBJECT_TYPE_8);
        ObjectVersion = 2;
        break;
    case NT_WIN10_REDSTONE1:
        ObjectSize = sizeof(OBJECT_TYPE_RS1);
        ObjectVersion = 3;
        break;
    default:
        ObjectSize = sizeof(OBJECT_TYPE_RS2);
        ObjectVersion = 4;
        break;
    }

    return ObpDumpObjectWithSpecifiedSize(ObjectAddress,
        ObjectSize,
        ObjectVersion,
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
    ULONG ObjectSize = 0;
    ULONG ObjectVersion = 0;

    //assume failure
    if (Size) *Size = 0;
    if (Version) *Version = 0;
    if (ObjectAddress < g_kdctx.SystemRangeStart)
        return NULL;

    switch (g_NtBuildNumber) {
    case NT_WIN7_RTM:
    case NT_WIN7_SP1:
        ObjectSize = sizeof(ALPC_PORT_7600);
        ObjectVersion = 1;
        break;
    case NT_WIN8_RTM:
        ObjectSize = sizeof(ALPC_PORT_9200);
        ObjectVersion = 2;
        break;
    case NT_WIN8_BLUE:
        ObjectSize = sizeof(ALPC_PORT_9600);
        ObjectVersion = 3;
        break;
    default:
        ObjectSize = sizeof(ALPC_PORT_10240);
        ObjectVersion = 4;
        break;
    }

    return ObpDumpObjectWithSpecifiedSize(ObjectAddress,
        ObjectSize,
        ObjectVersion,
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
    ULONG ObjectVersion;
    ULONG ObjectSize = 0;

    //assume failure
    if (Size) *Size = 0;
    if (Version) *Version = 0;
    if (ObjectAddress < g_kdctx.SystemRangeStart)
        return NULL;

    switch (g_NtBuildNumber) {

    case NT_WIN7_RTM:
    case NT_WIN7_SP1:
    case NT_WIN8_RTM:
    case NT_WIN8_BLUE:
        ObjectVersion = 1;
        ObjectSize = sizeof(OBJECT_DIRECTORY);
        break;

    case NT_WIN10_THRESHOLD1:
    case NT_WIN10_THRESHOLD2:
    case NT_WIN10_REDSTONE1:
        ObjectVersion = 2;
        ObjectSize = sizeof(OBJECT_DIRECTORY_V2);
        break;

    default:
        ObjectVersion = 3;
        ObjectSize = sizeof(OBJECT_DIRECTORY_V3);
        break;
    }

    return ObpDumpObjectWithSpecifiedSize(ObjectAddress,
        ObjectSize,
        ObjectVersion,
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
    ULONG ObjectSize = 0;
    ULONG ObjectVersion = 0;

    //assume failure
    if (Size) *Size = 0;
    if (Version) *Version = 0;
    if (ObjectAddress < g_kdctx.SystemRangeStart)
        return NULL;

    switch (g_NtBuildNumber) {
    case NT_WIN7_RTM:
    case NT_WIN7_SP1:
    case NT_WIN8_RTM:
    case NT_WIN8_BLUE:
        ObjectSize = sizeof(OBJECT_SYMBOLIC_LINK_V1);
        ObjectVersion = 1;
        break;
    case NT_WIN10_THRESHOLD1:
    case NT_WIN10_THRESHOLD2:
        ObjectSize = sizeof(OBJECT_SYMBOLIC_LINK_V2);
        ObjectVersion = 2;
        break;
    case NT_WIN10_REDSTONE1:
        ObjectSize = sizeof(OBJECT_SYMBOLIC_LINK_V3);
        ObjectVersion = 3;
        break;
    case NT_WIN10_REDSTONE2:
    case NT_WIN10_REDSTONE3:
    case NT_WIN10_REDSTONE4:
    case NT_WIN10_REDSTONE5:
    case NT_WIN10_19H1:
    case NT_WIN10_19H2:
    case NT_WIN10_20H1:
    case NT_WIN10_20H2:
        ObjectSize = sizeof(OBJECT_SYMBOLIC_LINK_V4);
        ObjectVersion = 4;
        break;
    default:
        ObjectSize = sizeof(OBJECT_SYMBOLIC_LINK_V5);
        ObjectVersion = 5;
        break;
    }

    return ObpDumpObjectWithSpecifiedSize(ObjectAddress,
        ObjectSize,
        ObjectVersion,
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
    ULONG ObjectSize = 0;
    ULONG ObjectVersion = 0;

    //assume failure
    if (Size) *Size = 0;
    if (Version) *Version = 0;

    if (ObjectAddress < g_kdctx.SystemRangeStart)
        return NULL;

    switch (g_NtBuildNumber) {
    case NT_WIN7_RTM:
    case NT_WIN7_SP1:
    case NT_WIN8_RTM:
    case NT_WIN8_BLUE:
    case NT_WIN10_THRESHOLD1:
    case NT_WIN10_THRESHOLD2:
        ObjectSize = sizeof(DEVICE_MAP_V1);
        ObjectVersion = 1;
        break;
    case NT_WIN10_REDSTONE1:
    default:
        ObjectSize = sizeof(DEVICE_MAP_V2);
        ObjectVersion = 2;
        break;
    }

    return ObpDumpObjectWithSpecifiedSize(ObjectAddress,
        ObjectSize,
        ObjectVersion,
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
    ULONG ObjectSize = 0;
    ULONG ObjectVersion = 0;

    //assume failure
    if (Size) *Size = 0;
    if (Version) *Version = 0;

    if (ObjectAddress < g_kdctx.SystemRangeStart)
        return NULL;

    if (g_NtBuildNumber >= NT_WIN8_BLUE) {
        ObjectSize = sizeof(DRIVER_EXTENSION_V4);
        ObjectVersion = 4;
    }
    else {

        switch (g_NtBuildNumber) {
        case NT_WIN7_RTM:
        case NT_WIN7_SP1:
            ObjectSize = sizeof(DRIVER_EXTENSION_V2);
            ObjectVersion = 2;
            break;
        case NT_WIN8_RTM:
            ObjectSize = sizeof(DRIVER_EXTENSION_V3);
            ObjectVersion = 3;
            break;
        default:
            ObjectSize = sizeof(DRIVER_EXTENSION);
            ObjectVersion = 1;
            break;
        }
    }

    return ObpDumpObjectWithSpecifiedSize(ObjectAddress,
        ObjectSize,
        ObjectVersion,
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
    if (g_kdctx.ObHeaderCookie.Valid == FALSE) {
        return EncodedTypeIndex;
    }

    ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
    TypeIndex = (EncodedTypeIndex ^ (UCHAR)((ULONG_PTR)ObjectHeader >> OBJECT_SHIFT) ^ g_kdctx.ObHeaderCookie.Value);
    return TypeIndex;
}

/*
* ObpFindHeaderCookie
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
BOOLEAN ObpFindHeaderCookie(
    _In_ PKLDBGCONTEXT Context
)
{
    BOOLEAN    bResult = FALSE;
    UCHAR      cookieValue = 0;
    PBYTE      ptrCode;
    ULONG_PTR  Address;

    ULONG_PTR NtOsBase;
    HMODULE hNtOs;

    __try {

        Context->ObHeaderCookie.Valid = FALSE;
        NtOsBase = (ULONG_PTR)Context->NtOsBase;
        hNtOs = (HMODULE)Context->NtOsImageMap;

        do {

            ptrCode = (PBYTE)GetProcAddress(hNtOs, "ObGetObjectType");
            if (ptrCode == NULL)
                break;

            Address = ObFindAddress(NtOsBase,
                (ULONG_PTR)hNtOs,
                IL_ObHeaderCookie,
                ptrCode,
                DA_ScanBytesObHeaderCookie,
                ObHeaderCookiePattern,
                sizeof(ObHeaderCookiePattern));

            if (!kdAddressInNtOsImage((PVOID)Address))
                break;

            if (!kdReadSystemMemoryEx(
                Address,
                &cookieValue,
                sizeof(cookieValue),
                NULL))
            {
                break;
            }

            Context->ObHeaderCookie.Valid = TRUE;
            Context->ObHeaderCookie.Value = cookieValue;
            bResult = TRUE;

        } while (FALSE);

    }
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
        return FALSE;
    }

    return bResult;
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
    ULONG_PTR Address = 0;

    PVOID   SectionBase;
    ULONG   SectionSize = 0;

    PBYTE   Signature;
    ULONG   SignatureSize;

    PBYTE   ptrCode = NULL;

    ESERVERSILO_GLOBALS PspHostSiloGlobals;

    HMODULE hNtOs = (HMODULE)Context->NtOsImageMap;

    do {

        //
        // Locate .text image section.
        //
        SectionBase = supLookupImageSectionByName(TEXT_SECTION,
            TEXT_SECTION_LEGNTH,
            (PVOID)hNtOs,
            &SectionSize);

        if ((SectionBase == NULL) || (SectionSize == 0))
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
        Address = ObFindAddress((ULONG_PTR)Context->NtOsBase,
            (ULONG_PTR)hNtOs,
            IL_PspHostSiloGlobals,
            ptrCode,
            DA_ScanBytesPNSVariant1,
            LeaPattern_PNS,
            sizeof(LeaPattern_PNS));

        if (kdAddressInNtOsImage((PVOID)Address)) {
            //
            // Dump PspHostSiloGlobals.
            //
            RtlSecureZeroMemory(&PspHostSiloGlobals, sizeof(PspHostSiloGlobals));

            if (kdReadSystemMemoryEx(Address,
                &PspHostSiloGlobals,
                sizeof(PspHostSiloGlobals),
                NULL))
            {
                //
                // Return adjusted address of PrivateNamespaceLookupTable.
                //
                Address += FIELD_OFFSET(OBP_SILODRIVERSTATE, PrivateNamespaceLookupTable);

            }
        }

    } while (FALSE);

    return (PVOID)Address;
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
    _Out_ KSERVICE_TABLE_DESCRIPTOR * ServiceTable
)
{
    BOOL            bResult = FALSE;
    ULONG           SignatureSize;
    ULONG           SectionSize;
    ULONG_PTR       LookupAddress = 0, Address = 0, SectionBase = 0;

    KSERVICE_TABLE_DESCRIPTOR ServiceTableDescriptor[2];

    __try {

        //
        // Assume failure.
        //
        if (ServiceTable)
            RtlSecureZeroMemory(ServiceTable, sizeof(KSERVICE_TABLE_DESCRIPTOR));
        else
            return FALSE;

        do {

            //
            // If KeServiceDescriptorTableShadow is not extracted then extract it.
            //
            if (g_kdctx.KeServiceDescriptorTableShadowPtr == 0) {

                //
                // Locate .text image section.
                //
                SectionBase = (ULONG_PTR)supLookupImageSectionByName(TEXT_SECTION,
                    TEXT_SECTION_LEGNTH,
                    (PVOID)MappedImageBase,
                    &SectionSize);

                if ((SectionBase == 0) || (SectionSize == 0))
                    break;

                SignatureSize = sizeof(KiSystemServiceStartPattern);
                if (SignatureSize > SectionSize)
                    break;

                //
                // Find KiSystemServiceStart signature.
                //
                LookupAddress = (ULONG_PTR)supFindPattern((PBYTE)SectionBase,
                    SectionSize,
                    (PBYTE)KiSystemServiceStartPattern,
                    SignatureSize);

                if (LookupAddress == 0)
                    break;

                LookupAddress += SignatureSize;

                //
                // Find KeServiceDescriptorTableShadow.
                //
                Address = ObFindAddress(KernelImageBase,
                    (ULONG_PTR)MappedImageBase,
                    IL_KeServiceDescriptorTableShadow,
                    (PBYTE)LookupAddress,
                    DA_ScanBytesKeServiceDescriptorTableShadow,
                    LeaPattern_KeServiceDescriptorTableShadow,
                    sizeof(LeaPattern_KeServiceDescriptorTableShadow));

                if (!kdAddressInNtOsImage((PVOID)Address))
                    break;

                g_kdctx.KeServiceDescriptorTableShadowPtr = Address;

            }
            else {
                Address = g_kdctx.KeServiceDescriptorTableShadowPtr;
            }


            RtlSecureZeroMemory(&ServiceTableDescriptor,
                sizeof(ServiceTableDescriptor));

            if (!kdReadSystemMemoryEx(Address,
                &ServiceTableDescriptor,
                sizeof(ServiceTableDescriptor),
                NULL))
            {
                break;
            }

            RtlCopyMemory(ServiceTable,
                &ServiceTableDescriptor[0],
                sizeof(KSERVICE_TABLE_DESCRIPTOR));

            bResult = TRUE;

        } while (FALSE);

    }
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
        return FALSE;
    }
    return bResult;
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

    hDirectory = supOpenDirectory(NULL, lpTarget, DIRECTORY_QUERY);
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

            if (g_kdctx.PrivateNamespaceLookupTable == NULL)
                g_kdctx.PrivateNamespaceLookupTable = ObFindPrivateNamespaceLookupTable(&g_kdctx);

            if (g_kdctx.PrivateNamespaceLookupTable != NULL) {

                bResult = ObpWalkPrivateNamespaceTable(&Collection->ListHead,
                    Collection->Heap,
                    (ULONG_PTR)g_kdctx.PrivateNamespaceLookupTable);

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
            g_kdctx.DriverOpenStatus = status;
            return TRUE;
        }
        else {
            supEnablePrivilege(SE_DEBUG_PRIVILEGE, FALSE);
            g_kdctx.DriverOpenStatus = status;
        }
    }

    return FALSE;
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
    BOOL                    Result = FALSE;
    PUCHAR                  ModuleName;
    PKLDBGCONTEXT           Context = (PKLDBGCONTEXT)lpParameter;
    PVOID                   MappedKernel = NULL;
    PRTL_PROCESS_MODULES    SystemModules = NULL;
    WCHAR                   KernelFullPathName[MAX_PATH * 2];

    do {

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

        SystemModules = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation, NULL);
        if (SystemModules == NULL)
            break;

        if (SystemModules->NumberOfModules == 0)
            break;

        Context->NtOsBase = SystemModules->Modules[0].ImageBase; //loaded kernel base
        Context->NtOsSize = SystemModules->Modules[0].ImageSize; //loaded kernel size

        _strcpy(KernelFullPathName, g_WinObj.szSystemDirectory);
        _strcat(KernelFullPathName, TEXT("\\"));

        ModuleName = &SystemModules->Modules[0].FullPathName[SystemModules->Modules[0].OffsetToFileName];

        MultiByteToWideChar(
            CP_ACP,
            0,
            (LPCSTR)ModuleName,
            -1,
            _strend(KernelFullPathName),
            MAX_PATH);

        supHeapFree(SystemModules);
        SystemModules = NULL;

        MappedKernel = LoadLibraryEx(
            KernelFullPathName,
            NULL,
            DONT_RESOLVE_DLL_REFERENCES);

        if (MappedKernel == NULL)
            break;
        
        Context->NtOsImageMap = MappedKernel;

        Result = TRUE;

    } while (FALSE);

    if (SystemModules != NULL) {
        supHeapFree(SystemModules);
    }

    return Result;
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
* kdQueryWin32kApiSetTable
*
* Purpose:
*
* Locate address of win32k!Win32kApiSetTable structure.
*
* N.B.
* It would be much easier if MS will export this symbol.
*
*/
ULONG_PTR kdQueryWin32kApiSetTable(
    _In_ HMODULE hWin32k
)
{
    PBYTE	    ptrCode = (PBYTE)hWin32k;

    PVOID       SectionBase;
    ULONG       SectionSize = 0, Index;
    ULONG       instLength = 0, tempOffset;

    ULONG_PTR   tableAddress = 0;
    LONG        relativeValue = 0;
    hde64s      hs;

    __try {

        //
        // Locate .text image section as required variable is always in .text.
        //
        SectionBase = supLookupImageSectionByName(TEXT_SECTION,
            TEXT_SECTION_LEGNTH,
            (PVOID)hWin32k,
            &SectionSize);

        if ((SectionBase == 0) || (SectionSize == 0))
            return 0;

        Index = 0;
        ptrCode = (PBYTE)SectionBase;

        do {

            hde64_disasm((void*)(ptrCode + Index), &hs);
            if (hs.flags & F_ERROR)
                break;

            instLength = hs.len;

            //
            // Check if 3 byte length MOV.
            //
            if (instLength == IL_Win32kApiSetMov) {

                tempOffset = Index + 1; //+1 to skip rex prefix

                if (ptrCode[tempOffset] == 0x8B) {

                    tempOffset = Index + instLength;
                    hde64_disasm((void*)(ptrCode + tempOffset), &hs);
                    if (hs.flags & F_ERROR)
                        break;

                    //
                    // Check if next instruction is 7 bytes len LEA.
                    //
                    if (hs.len == IL_Win32kApiSetTable) {
                        if (ptrCode[tempOffset + 1] == 0x8D) {

                            //
                            // Update counters.
                            //
                            Index = tempOffset;
                            instLength = hs.len;

                            relativeValue = *(PLONG)(ptrCode + tempOffset + (hs.len - 4));
                            break;
                        }
                    }

                }
            }

            Index += instLength;

        } while (Index < SectionSize - 10);

        if ((relativeValue == 0) || (instLength == 0))
            return 0;

        tableAddress = (ULONG_PTR)ptrCode + Index + instLength + relativeValue;

    }
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
        return 0;
    }

    return tableAddress;
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
    ULONG_PTR  Address;

    BOOLEAN  KseEngineDumpValid = FALSE;

    ULONG_PTR NtOsBase;
    HMODULE hNtOs;

    ULONG_PTR KseShimmedDriversListHead;
    LIST_ENTRY ListEntry;
    KSE_SHIMMED_DRIVER* ShimmedDriver;

    if (!kdConnectDriver())
        return FALSE;

    __try {

        if (Context->KseEngineDump.Valid == FALSE) {
            NtOsBase = (ULONG_PTR)Context->NtOsBase;
            hNtOs = (HMODULE)Context->NtOsImageMap;

            ptrCode = (PBYTE)GetProcAddress(hNtOs, "KseSetDeviceFlags");
            if (ptrCode == NULL) {
                kdDebugPrint("Kse routine not found\r\n");
                return FALSE;
            }

            Address = ObFindAddress(NtOsBase,
                (ULONG_PTR)hNtOs,
                IL_KseEngine,
                ptrCode,
                DA_ScanBytesKseEngine,
                KseEnginePattern,
                sizeof(KseEnginePattern));

            if (Address == 0) {
                kdDebugPrint("KseEngine address not found\r\n");
                return FALSE;
            }

            Address -= FIELD_OFFSET(KSE_ENGINE, State);
            if (!kdAddressInNtOsImage((PVOID)Address)) {
                kdDebugPrint("KseEngine address is invalid\r\n");
                return FALSE;
            }

            Context->KseEngineDump.KseAddress = Address;
        }

        if (RefreshList) {
            supDestroyShimmedDriversList(&Context->KseEngineDump.ShimmedDriversDumpListHead);
            InitializeListHead(&Context->KseEngineDump.ShimmedDriversDumpListHead);
        }

        KseShimmedDriversListHead = Context->KseEngineDump.KseAddress + FIELD_OFFSET(KSE_ENGINE, ShimmedDriversListHead);
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
                InsertHeadList(&Context->KseEngineDump.ShimmedDriversDumpListHead, &ShimmedDriver->ListEntry);
            }
        }
        else {
            kdDebugPrint("KseEngine->ShimmedDriversListHead read error\r\n");
            KseEngineDumpValid = FALSE;
        }

        Context->KseEngineDump.Valid = KseEngineDumpValid;

    }
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
        return FALSE;
    }

    return KseEngineDumpValid;
}

/*
* kdOpenLoadDriverPublic
*
* Purpose:
*
* Open handle to WINDBG driver device or load this driver.
*
*/
BOOL kdOpenLoadDriverPublic(
    _In_ WCHAR * szDriverPath
)
{
    BOOL bResult;

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
* kdInit
*
* Purpose:
*
* Enable Debug Privilege and open/load KLDBGDRV driver
*
*/
VOID kdInit(
    _In_ BOOL IsFullAdmin
)
{
    BOOL bLoadState;
    WCHAR szBuffer[MAX_PATH * 2];

    RtlSecureZeroMemory(&g_kdctx, sizeof(g_kdctx));
    RtlSecureZeroMemory(&g_SystemCallbacks, sizeof(g_SystemCallbacks));

    g_kdctx.IsFullAdmin = IsFullAdmin;

    NtpLdrExceptionFilter = (PFNNTLDR_EXCEPT_FILTER)exceptFilterWithLog;

    //
    // Default driver load status.
    //
    g_kdctx.DriverOpenLoadStatus = ERROR_NOT_CAPABLE;

    InitializeListHead(&g_kdctx.KseEngineDump.ShimmedDriversDumpListHead);
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
    // Query global variables.
    //
    kdQuerySystemInformation(&g_kdctx);

    //
    // No admin rights, leave.
    //
    if (IsFullAdmin == FALSE)
        return;

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

        bLoadState = kdOpenLoadDriverPrivate(szBuffer);

#else

        bLoadState = kdOpenLoadDriverPublic(szBuffer);

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
            if (!ObpFindHeaderCookie(&g_kdctx))
                g_kdctx.ObHeaderCookie.Valid = FALSE;
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
}
