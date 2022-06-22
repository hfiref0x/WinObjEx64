/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       WINIO.C
*
*  VERSION:     2.00
*
*  DATE:        19 Jun 2022
* 
*  WinIo based reader.
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
#include "winio.h"

typedef NTSTATUS(WINAPI* pfnMapMemory)(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes,
    _Out_ HANDLE* SectionHandle,
    _Out_ PVOID* ReferencedObject,
    _Out_ PVOID* MappedMemory);

typedef NTSTATUS(WINAPI* pfnUnmapMemory)(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID SectionToUnmap,
    _In_ HANDLE SectionHandle,
    _In_ PVOID ReferencedObject);

NTSTATUS WinIoUnmapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID SectionToUnmap,
    _In_ HANDLE SectionHandle,
    _In_ PVOID ReferencedObject);

NTSTATUS WinIoMapMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ ULONG NumberOfBytes,
    _Out_ HANDLE* SectionHandle,
    _Out_ PVOID* ReferencedObject,
    _Out_ PVOID* MappedMemory);

#define MapMemoryRoutine WinIoMapMemory
#define UnmapMemoryRoutine WinIoUnmapMemory

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
    NTSTATUS ntStatus;
    WINIO_PHYSICAL_MEMORY_INFO request;

    *SectionHandle = NULL;
    *ReferencedObject = NULL;

    RtlSecureZeroMemory(&request, sizeof(request));
    request.ViewSize = NumberOfBytes;
    request.BusAddress = PhysicalAddress;

    ntStatus = supCallDriver(DeviceHandle,
        WINIO_IOCTL_MAP,
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
    WINIO_PHYSICAL_MEMORY_INFO request;

    RtlSecureZeroMemory(&request, sizeof(request));
    request.BaseAddress = SectionToUnmap;
    request.ReferencedObject = ReferencedObject;
    request.SectionHandle = SectionHandle;

    return supCallDriver(DeviceHandle,
        WINIO_IOCTL_UNMAP,
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
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
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

        ntStatus = MapMemoryRoutine(DeviceHandle,
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

        UnmapMemoryRoutine(DeviceHandle,
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
    ntStatus = MapMemoryRoutine(DeviceHandle,
        PhysicalAddress,
        NumberOfBytes,
        &sectionHandle,
        &refObject,
        &mappedSection);

    if (NT_SUCCESS(ntStatus)) {

        __try {

            RtlCopyMemory(Buffer, mappedSection, NumberOfBytes);

        }
        __except (WOBJ_EXCEPTION_FILTER_LOG)
        {
            ntStatus = GetExceptionCode();
        }

        //
        // Unmap physical memory section.
        //
        UnmapMemoryRoutine(DeviceHandle,
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
* WinIoReadSystemMemory
*
* Purpose:
*
* Read kernel virtual memory.
*
*/
BOOL WinIoReadSystemMemory(
    _In_ WDRV_CONTEXT* Context,
    _In_ ULONG_PTR Address,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG NumberOfBytesRead
)
{
    BOOL bResult = FALSE;
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    PVOID lockedBuffer = NULL;

    if (NumberOfBytesRead)
        *NumberOfBytesRead = 0;

    if (Address >= g_kdctx.SystemRangeStart) {

        lockedBuffer = supVirtualAlloc(BufferSize);
        if (lockedBuffer) {

            if (VirtualLock(lockedBuffer, BufferSize)) {

                ntStatus = WinIoReadKernelVirtualMemory(Context->DeviceHandle,
                    Address,
                    lockedBuffer,
                    BufferSize);

                if (NT_SUCCESS(ntStatus)) {

                    if (NumberOfBytesRead)
                        *NumberOfBytesRead = BufferSize;

                    RtlCopyMemory(Buffer, lockedBuffer, BufferSize);

                    bResult = TRUE;
                }

                VirtualUnlock(lockedBuffer, BufferSize);
            }
            else {
                ntStatus = STATUS_NOT_LOCKED;
            }

            supVirtualFree(lockedBuffer);
        }
        else {
            ntStatus = STATUS_MEMORY_NOT_ALLOCATED;
        }
    }
    else {
        ntStatus = STATUS_INVALID_PARAMETER_2;
    }

    Context->LastNtStatus = ntStatus;
    Context->IoStatusBlock.Information = 0;
    Context->IoStatusBlock.Status = ntStatus;

    return bResult;
}
