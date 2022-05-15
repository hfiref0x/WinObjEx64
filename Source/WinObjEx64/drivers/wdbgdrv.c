/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       WDBGDRV.C
*
*  VERSION:     1.93
*
*  DATE:        22 Apr 2022
* 
*  MS WinDbg kldbgdrv based reader.
* 
*  Note:
* 
*    Windows Debug mode is required for using this driver.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "wdbgdrv.h"

/*
* WDbgpDrvReadSystemMemoryWithStatus
*
* Purpose:
*
* Wrapper around SysDbgReadVirtual request to the KLDBGDRV/WODBGDRV
*
*/
BOOL WDbgpDrvReadSystemMemoryWithStatus(
    _In_ WDRV_CONTEXT* Context,
    _In_ ULONG_PTR Address,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG NumberOfBytesRead,
    _Out_ NTSTATUS* Status,
    _Out_ PIO_STATUS_BLOCK IoStatus
)
{
    BOOL            bResult;
    NTSTATUS        ntStatus;
    KLDBG           kldbg;
    IO_STATUS_BLOCK iost;
    SYSDBG_VIRTUAL  dbgRequest;

    if (NumberOfBytesRead)
        *NumberOfBytesRead = 0;

    *Status = STATUS_UNSUCCESSFUL;
    IoStatus->Information = 0;
    IoStatus->Status = STATUS_UNSUCCESSFUL;

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

    ntStatus = NtDeviceIoControlFile(Context->DeviceHandle,
        NULL,
        NULL,
        NULL,
        &iost,
        IOCTL_KD_PASS_THROUGH,
        &kldbg,
        sizeof(kldbg),
        &dbgRequest,
        sizeof(dbgRequest));

    if (ntStatus == STATUS_PENDING) {

        ntStatus = NtWaitForSingleObject(Context->DeviceHandle,
            FALSE,
            NULL);

    }

    *Status = ntStatus;

    if (NT_SUCCESS(ntStatus))
        ntStatus = iost.Status;

    IoStatus->Information = iost.Information;
    IoStatus->Status = iost.Status;

    bResult = NT_SUCCESS(ntStatus);

    if (bResult) {

        if (NumberOfBytesRead)
            *NumberOfBytesRead = (ULONG)iost.Information;

    }
    else {
        //
        // We don't need this information in case of error.
        //
        if (!NT_ERROR(ntStatus)) {
            if (NumberOfBytesRead)
                *NumberOfBytesRead = (ULONG)iost.Information;
        }

    }

    return bResult;
}

/*
* WDbgDrvReadSystemMemory
*
* Purpose:
*
* Call internal WDbgpDrvReadSystemMemoryWithStatus.
*
*/
BOOL WDbgDrvReadSystemMemory(
    _In_ WDRV_CONTEXT* Context,
    _In_ ULONG_PTR Address,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG NumberOfBytesRead
)
{
    ULONG numberOfBytesRead = 0;

    if (NumberOfBytesRead)
        *NumberOfBytesRead = 0;

    if ((Buffer == NULL) ||
        (BufferSize == 0) ||
        (Address < g_kdctx.SystemRangeStart))
    {
        return FALSE;
    }

    BOOL bResult = WDbgpDrvReadSystemMemoryWithStatus(Context,
        Address,
        Buffer,
        BufferSize,
        &numberOfBytesRead,
        &Context->LastNtStatus,
        &Context->IoStatusBlock);

    if (NumberOfBytesRead)
        *NumberOfBytesRead = numberOfBytesRead;

    return bResult;
}
