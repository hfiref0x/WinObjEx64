/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       DRVHELPER.C
*
*  VERSION:     1.84
*
*  DATE:        18 Feb 2020
*
*  WinIo based VM-through-PM reader, used only in private builds, WHQL.
*
*  Note:
*
*    WinObjEx64 apply multiple security mitigations when uses this driver.
*    WinIo is known to be vulnerable by design.
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
#include "ntos/halamd64.h"

#define PHY_ADDRESS_MASK                0x000ffffffffff000ull
#define PHY_ADDRESS_MASK_2MB_PAGES      0x000fffffffe00000ull
#define VADDR_ADDRESS_MASK_2MB_PAGES    0x00000000001fffffull
#define VADDR_ADDRESS_MASK_4KB_PAGES    0x0000000000000fffull
#define ENTRY_PRESENT_BIT               1
#define ENTRY_PAGE_SIZE_BIT             0x0000000000000080ull

#include "tinyaes/aes.h"

//
// AES key used by EneTechIo latest variants.
//
ULONG g_EneTechIoUnlockKey[4] = { 0x54454E45, 0x4E484345, 0x474F4C4F, 0x434E4959 };


int PwEntryToPhyAddr(ULONG_PTR entry, ULONG_PTR* phyaddr)
{
    if (entry & ENTRY_PRESENT_BIT) {
        *phyaddr = entry & PHY_ADDRESS_MASK;
        return 1;
    }

    return 0;
}

NTSTATUS PwVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ provQueryPML4 QueryPML4Routine,
    _In_ provReadPhysicalMemory ReadPhysicalMemoryRoutine,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    NTSTATUS    ntStatus;
    ULONG_PTR   pml4_cr3, selector, table, entry = 0;
    INT         r, shift;

    ntStatus = QueryPML4Routine(DeviceHandle, &pml4_cr3);
    if (!NT_SUCCESS(ntStatus))
        return ntStatus;

    table = pml4_cr3 & PHY_ADDRESS_MASK;

    for (r = 0; r < 4; r++) {

        shift = 39 - (r * 9);
        selector = (VirtualAddress >> shift) & 0x1ff;

        ntStatus = ReadPhysicalMemoryRoutine(DeviceHandle,
            table + selector * 8,
            &entry,
            sizeof(ULONG_PTR));

        if (!NT_SUCCESS(ntStatus))
            return ntStatus;

        if (PwEntryToPhyAddr(entry, &table) == 0)
            return STATUS_INTERNAL_ERROR;

        if ((r == 2) && ((entry & ENTRY_PAGE_SIZE_BIT) != 0)) {
            table &= PHY_ADDRESS_MASK_2MB_PAGES;
            table += VirtualAddress & VADDR_ADDRESS_MASK_2MB_PAGES;
            *PhysicalAddress = table;
            return STATUS_SUCCESS;
        }
    }

    table += VirtualAddress & VADDR_ADDRESS_MASK_4KB_PAGES;
    *PhysicalAddress = table;

    return STATUS_SUCCESS;
}

/*
* WinIoCallDriver
*
* Purpose:
*
* Call WinIo driver.
*
*/
NTSTATUS WinIoCallDriver(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG IoControlCode,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_opt_ PVOID OutputBuffer,
    _In_opt_ ULONG OutputBufferLength)
{
    IO_STATUS_BLOCK ioStatus;

    return NtDeviceIoControlFile(DeviceHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        IoControlCode,
        InputBuffer,
        InputBufferLength,
        OutputBuffer,
        OutputBufferLength);
}

/*
* WinIoMapMemory
*
* Purpose:
*
* Map physical memory through \Device\PhysicalMemory.
*
*/
NTSTATUS WinIoMapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes,
    _Out_ HANDLE* SectionHandle,
    _Out_ PVOID* ReferencedObject,
    _Out_ PVOID* MappedMemory)
{
    ULONG seconds;
    NTSTATUS ntStatus;
    AES_ctx ctx;
    WINIO_PHYSICAL_MEMORY_INFO_EX request;

    *SectionHandle = NULL;
    *ReferencedObject = NULL;

    RtlSecureZeroMemory(&ctx, sizeof(ctx));
    AES_init_ctx(&ctx, (uint8_t*)&g_EneTechIoUnlockKey);

    RtlSecureZeroMemory(&request, sizeof(request));
    request.CommitSize = NumberOfBytes;
    request.BusAddress = PhysicalAddress;

    seconds = supGetTimeAsSecondsSince1970();

    RtlCopyMemory(&request.EncryptedKey, (PVOID)&seconds, sizeof(seconds));
    AES_ECB_encrypt(&ctx, (UCHAR*)&request.EncryptedKey);

    ntStatus = WinIoCallDriver(DeviceHandle,
        IOCTL_WINIO_MAP_USER_PHYSICAL_MEMORY,
        &request,
        sizeof(request),
        &request,
        sizeof(request));

    if (NT_SUCCESS(ntStatus)) {
        *SectionHandle = request.SectionHandle;
        *ReferencedObject = request.ReferencedObject;
        *MappedMemory = request.BaseAddress;
    }

    return ntStatus;
}

/*
* WinIoUnmapMemory
*
* Purpose:
*
* Unmap previously mapped physical memory.
*
*/
NTSTATUS WinIoUnmapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID SectionToUnmap,
    _In_ HANDLE SectionHandle,
    _In_ PVOID ReferencedObject
)
{
    ULONG seconds;
    AES_ctx ctx;
    WINIO_PHYSICAL_MEMORY_INFO_EX request;

    RtlSecureZeroMemory(&ctx, sizeof(ctx));
    AES_init_ctx(&ctx, (uint8_t*)&g_EneTechIoUnlockKey);

    RtlSecureZeroMemory(&request, sizeof(request));
    request.BaseAddress = SectionToUnmap;
    request.ReferencedObject = ReferencedObject;
    request.SectionHandle = SectionHandle;

    seconds = supGetTimeAsSecondsSince1970();

    RtlCopyMemory(&request.EncryptedKey, (PVOID)&seconds, sizeof(ULONG));
    AES_ECB_encrypt(&ctx, (UCHAR*)&request.EncryptedKey);

    return WinIoCallDriver(DeviceHandle,
        IOCTL_WINIO_UNMAP_USER_PHYSICAL_MEMORY,
        &request,
        sizeof(request),
        &request,
        sizeof(request));

}

/*
* WinIoGetPML4FromLowStub1M
*
* Purpose:
*
* Search for PML4 (CR3) entry in low stub.
*
*/
ULONG_PTR WinIoGetPML4FromLowStub1M(
    _In_ ULONG_PTR pbLowStub1M)
{
    ULONG offset = 0;
    ULONG_PTR PML4 = 0;
    ULONG cr3_offset = FIELD_OFFSET(PROCESSOR_START_BLOCK, ProcessorState) +
        FIELD_OFFSET(KSPECIAL_REGISTERS, Cr3);

    SetLastError(ERROR_EXCEPTION_IN_SERVICE);

    __try {

        while (offset < 0x100000) {

            offset += 0x1000;

            if (0x00000001000600E9 != (0xffffffffffff00ff & *(UINT64*)(pbLowStub1M + offset))) //PROCESSOR_START_BLOCK->Jmp
                continue;

            if (0xfffff80000000000 != (0xfffff80000000003 & *(UINT64*)(pbLowStub1M + offset + FIELD_OFFSET(PROCESSOR_START_BLOCK, LmTarget))))
                continue;

            if (0xffffff0000000fff & *(UINT64*)(pbLowStub1M + offset + cr3_offset))
                continue;

            PML4 = *(UINT64*)(pbLowStub1M + offset + cr3_offset);
            break;
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }

    SetLastError(ERROR_SUCCESS);

    return PML4;
}

/*
* WinIoQueryPML4Value
*
* Purpose:
*
* Locate PML4.
*
*/
NTSTATUS WINAPI WinIoQueryPML4Value(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    ULONG_PTR PML4 = 0;

    PVOID pbLowStub1M = NULL;
    PVOID refObject = NULL;
    HANDLE sectionHandle = NULL;

    *Value = 0;

    do {

        ntStatus = WinIoMapMemory(DeviceHandle,
            0ULL,
            0x100000,
            &sectionHandle,
            &refObject,
            &pbLowStub1M);

        if (!NT_SUCCESS(ntStatus))
            break;

        if (pbLowStub1M == NULL) {
            ntStatus = STATUS_INTERNAL_ERROR;
            break;
        }

        PML4 = WinIoGetPML4FromLowStub1M((ULONG_PTR)pbLowStub1M);
        if (PML4)
            *Value = PML4;
        else
            *Value = 0;

        WinIoUnmapMemory(DeviceHandle,
            (PVOID)pbLowStub1M,
            sectionHandle,
            refObject);

        ntStatus = (PML4 != 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

    } while (FALSE);

    return ntStatus;
}

/*
* WinIoReadPhysicalMemory
*
* Purpose:
*
* Read physical memory through mapping.
*
*/
NTSTATUS WINAPI WinIoReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    NTSTATUS ntStatus;
    PVOID mappedSection = NULL;

    PVOID refObject = NULL;
    HANDLE sectionHandle = NULL;

    //
    // Map physical memory section.
    //
    ntStatus = WinIoMapMemory(DeviceHandle,
        PhysicalAddress,
        NumberOfBytes,
        &sectionHandle,
        &refObject,
        &mappedSection);

    if (NT_SUCCESS(ntStatus)) {

        __try {

            RtlCopyMemory(Buffer, mappedSection, NumberOfBytes);

        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ntStatus = GetExceptionCode();
        }

        //
        // Unmap physical memory section.
        //
        WinIoUnmapMemory(DeviceHandle,
            mappedSection,
            sectionHandle,
            refObject);

    }

    return ntStatus;
}

/*
* WinIoVirtualToPhysical
*
* Purpose:
*
* Translate virtual address to the physical.
*
*/
NTSTATUS WINAPI WinIoVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    if (PhysicalAddress)
        *PhysicalAddress = 0;
    else {
        return STATUS_INVALID_PARAMETER_3;
    }

    return PwVirtualToPhysical(DeviceHandle,
        WinIoQueryPML4Value,
        WinIoReadPhysicalMemory,
        VirtualAddress,
        PhysicalAddress);
}

/*
* WinIoReadKernelVirtualMemory
*
* Purpose:
*
* Read virtual memory.
*
*/
NTSTATUS WINAPI WinIoReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    NTSTATUS ntStatus;
    ULONG_PTR physicalAddress = 0;

    ntStatus = WinIoVirtualToPhysical(DeviceHandle,
        Address,
        &physicalAddress);

    if (NT_SUCCESS(ntStatus)) {

        ntStatus = WinIoReadPhysicalMemory(DeviceHandle,
            physicalAddress,
            Buffer,
            NumberOfBytes);

    }

    return ntStatus;
}

/*
* WinIoReadSystemMemoryEx
*
* Purpose:
*
* Read kernel virtual memory.
*
*/
BOOL WinIoReadSystemMemoryEx(
    _In_ ULONG_PTR Address,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG NumberOfBytesRead
)
{
    BOOL bResult = FALSE;
    IO_STATUS_BLOCK iost;
    NTSTATUS ntStatus;
    PVOID lockedBuffer = NULL;

    if (NumberOfBytesRead)
        *NumberOfBytesRead = 0;

    lockedBuffer = supVirtualAlloc(BufferSize);
    if (lockedBuffer) {

        if (VirtualLock(lockedBuffer, BufferSize)) {

            ntStatus = WinIoReadKernelVirtualMemory(g_kdctx.DeviceHandle,
                Address,
                lockedBuffer,
                BufferSize);

            if (!NT_SUCCESS(ntStatus)) {

                iost.Status = ntStatus;
                iost.Information = 0;

                if (g_kdctx.ShowKdError)
                    kdShowError(BufferSize, ntStatus, &iost);
                else
                    SetLastError(RtlNtStatusToDosError(ntStatus));
            }
            else {
                if (NumberOfBytesRead)
                    *NumberOfBytesRead = BufferSize;

                RtlCopyMemory(Buffer, lockedBuffer, BufferSize);

                bResult = TRUE;
            }

            VirtualUnlock(lockedBuffer, BufferSize);
        }

        supVirtualFree(lockedBuffer);
    }

    return bResult;
}
