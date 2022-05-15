/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       WDRVPRV.C
*
*  VERSION:     1.93
*
*  DATE:        22 Apr 2022
*
*  Driver providers abstraction layer.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "drivers/wdbgdrv.h"
#include "drivers/winio.h"

#ifdef _USE_OWN_DRIVER
#ifdef _USE_WINIO
#define WDRV_PROVIDER_TYPE wdrvWinIo
static WDRV_PROVIDER g_wdpEntry = {
    WINIO_DRV_NAME,
    WINIO_DEV_NAME,
    WDRVPROV_FLAGS_UEFI_REQUIRED | WDRVPROV_FLAGS_FORCE_SD,
    WDrvStartDriver,
    WDrvStopDriver,
    WDrvOpenDriver,
    NULL, //register
    NULL, //unregister
    NULL, //preopen
    WDrvProvPostOpen,
    WinIoReadSystemMemory
};
#else
#define WDRV_PROVIDER_TYPE wdrvWinObjEx64
static WDRV_PROVIDER g_wdpEntry = { 
    L"wodbgdrv",
    L"wodbgdrv",
    WDRVPROV_FLAGS_NONE,
    WDrvStartDriver,
    WDrvStopDriver,
    WDrvOpenDriver,
    NULL, //register
    NULL, //unregister
    NULL, //preopen
    NULL, //postopen
    WDbgDrvReadSystemMemory 
};
#endif
#else

#define WDRV_PROVIDER_TYPE wdrvMicrosoft
static WDRV_PROVIDER g_wdpEntry = {
    L"kldbgdrv",
    L"kldbgdrv",
    WDRVPROV_FLAGS_NONE,
    WDrvStartDriver,
    WDrvStopDriver,
    WDrvOpenDriver,
    NULL, //register
    NULL, //unregister
    NULL, //preopen
    NULL, //postopen
    WDbgDrvReadSystemMemory 
};
#endif

#define PHY_ADDRESS_MASK                0x000ffffffffff000ull
#define PHY_ADDRESS_MASK_2MB_PAGES      0x000fffffffe00000ull
#define VADDR_ADDRESS_MASK_2MB_PAGES    0x00000000001fffffull
#define VADDR_ADDRESS_MASK_4KB_PAGES    0x0000000000000fffull
#define ENTRY_PRESENT_BIT               1
#define ENTRY_PAGE_SIZE_BIT             0x0000000000000080ull


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

WDRVPRVTYPE WDrvGetActiveProviderType(
    VOID)
{
    return (WDRVPRVTYPE)WDRV_PROVIDER_TYPE;
}

/*
* WDrvProvPostOpen
*
* Purpose:
*
* Provider post-open driver generic callback.
*
*/
BOOL WINAPI WDrvProvPostOpen(
    _In_ PVOID Param
)
{
    WDRV_CONTEXT* Context = (WDRV_CONTEXT*)Param;
    PSECURITY_DESCRIPTOR driverSD = NULL;

    PACL defaultAcl = NULL;
    HANDLE deviceHandle;
    HANDLE strHandle = NULL;
    NTSTATUS ntStatus;

    deviceHandle = Context->DeviceHandle;

    //
    // Check if we need to forcebly set SD.
    //
    if (Context->Provider->ForceSD) {


        ntStatus = supCreateSystemAdminAccessSD(&driverSD, &defaultAcl);

        if (NT_SUCCESS(ntStatus)) {

            ntStatus = NtSetSecurityObject(deviceHandle,
                DACL_SECURITY_INFORMATION,
                driverSD);

            if (defaultAcl) supHeapFree(defaultAcl);
            supHeapFree(driverSD);

            if (NT_SUCCESS(ntStatus)) {

                //
                // Remove WRITE_DAC from result handle.
                //
                if (NT_SUCCESS(NtDuplicateObject(NtCurrentProcess(),
                    deviceHandle,
                    NtCurrentProcess(),
                    &strHandle,
                    GENERIC_WRITE | GENERIC_READ,
                    0,
                    0)))
                {
                    NtClose(deviceHandle);
                    deviceHandle = strHandle;
                }

            }

            Context->DeviceHandle = deviceHandle;

        }

    }

    return (deviceHandle != NULL);
}

/*
* WDrvExtractDriverResource
*
* Purpose:
*
* Extract driver from application resource
*
*/
BOOL WDrvExtractDriverResource(
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
* WDrvExtractDriver
*
* Purpose:
*
* Save driver to system32\drivers from application resource.
*
* N.B. If driver already exist on disk function return TRUE.
* This is required for WinDBG compatibility.
*
*/
BOOL WDrvExtractDriver(
    _In_ WCHAR* szDriverPath
)
{
    BOOL bResult = FALSE;

    //
    // If no file exists, extract it to the drivers directory.
    //
    bResult = PathFileExists(szDriverPath);

    if (!bResult) {
        bResult = WDrvExtractDriverResource(szDriverPath, MAKEINTRESOURCE(IDR_KDBGDRV), L"SYS");
    }

    return bResult;
}

/*
* WDrvLoadDriver
*
* Purpose:
*
* Load helper driver.
*
*/
NTSTATUS WDrvLoadDriver(
    _In_ PWDRV_CONTEXT Context
)
{
    NTSTATUS ntStatus;

    //
    // Build file path and write file to disk.
    //
    RtlStringCchPrintfSecure(Context->DriverFileName,
        ARRAYSIZE(Context->DriverFileName),
        L"%ws\\drivers\\%ws.sys",
        g_WinObj.szSystemDirectory,
        Context->Provider->DriverName);

    if (!WDrvExtractDriver(Context->DriverFileName)) {
        return STATUS_FILE_NOT_AVAILABLE;
    }

    ntStatus = supLoadDriverEx(Context->Provider->DriverName,
        Context->DriverFileName,
        TRUE,
        NULL,
        NULL);

    if (!NT_SUCCESS(ntStatus)) {
        DeleteFile(Context->DriverFileName);
    }

    return ntStatus;
}

/*
* WDrvOpenDriver
*
* Purpose:
*
* Open handle to driver device, run optional callbacks.
*
*/
NTSTATUS WDrvOpenDriver(
    _In_ PWDRV_CONTEXT Context
)
{
    NTSTATUS ntStatus;
    HANDLE deviceHandle = NULL;

    ULONG openFlags = GENERIC_WRITE | GENERIC_READ;

    if (Context->Provider->Callbacks.PreOpenDriver) {

        Context->Provider->Callbacks.PreOpenDriver((PVOID)Context);

    }

    if (Context->Provider->ForceSD)
        openFlags |= WRITE_DAC;

    ntStatus = supOpenDriver(Context->Provider->DeviceName,
        openFlags,
        &deviceHandle);

    if (NT_SUCCESS(ntStatus)) {
        Context->DeviceHandle = deviceHandle;

        if (Context->Provider->Callbacks.PostOpenDriver) {

            Context->Provider->Callbacks.PostOpenDriver((PVOID)Context);

        }

    }

    return ntStatus;
}

/*
* WDrvStartDriver
*
* Purpose:
*
* Load driver and open handle to it, run optional callbacks.
*
*/
NTSTATUS WDrvStartDriver(
    _In_ PWDRV_CONTEXT Context
)
{
    BOOL bLoaded = FALSE;
    NTSTATUS ntStatus = STATUS_SUCCESS;

    //
    // Check if driver already loaded.
    //
    if (supIsObjectExists((LPWSTR)L"\\Device", Context->Provider->DeviceName)) {

        Context->IsOurLoad = FALSE;
        bLoaded = TRUE;

    }
    else {

        ntStatus = WDrvLoadDriver(Context);
        bLoaded = NT_SUCCESS(ntStatus);
        Context->IsOurLoad = bLoaded;

    }

    if (bLoaded) {

        Context->LoadStatus = ntStatus;
        ntStatus = Context->Provider->Callbacks.OpenDriver(Context);
        Context->OpenStatus = ntStatus;
    }

    return ntStatus;
}

/*
* WDrvStopDriver
*
* Purpose:
*
* Stop driver, delete registry entry and remove driver file from disk.
*
*/
VOID WDrvStopDriver(
    _In_ PWDRV_CONTEXT Context
)
{
    NTSTATUS ntStatus;
    LPWSTR lpDriverName = Context->Provider->DriverName;
    LPWSTR lpFullFileName = Context->DriverFileName;

    ntStatus = supUnloadDriver(lpDriverName, TRUE);
    if (NT_SUCCESS(ntStatus)) {

        supDeleteFileWithWait(1000, 5, lpFullFileName);
    }
}

VOID WDrvFallBackOnLoad(
    _Inout_ PWDRV_CONTEXT* Context
)
{
    PWDRV_CONTEXT ctx = *Context;

    if (ctx->DeviceHandle)
        NtClose(ctx->DeviceHandle);

    ctx->Provider->Callbacks.StopDriver(ctx);

    supHeapFree(ctx);
    *Context = NULL;
}

/*
* WDrvProvCreate
*
* Purpose:
*
* Create driver provider instance.
*
* Note:
* SE_DEBUG_PRIVILEGE must be assigned.
*
*/
NTSTATUS WDrvProvCreate(
    _In_ FIRMWARE_TYPE FirmwareType,
    _Out_ PWDRV_CONTEXT Context
)
{
    NTSTATUS ntStatus;
    PWDRV_PROVIDER provider = NULL;

    //
    // Enable debug privilege.
    //
    if (!supEnablePrivilege(SE_DEBUG_PRIVILEGE, TRUE)) {
        return STATUS_PRIVILEGE_NOT_HELD;
    }

    provider = &g_wdpEntry;

    //
    // UEFI compat check.
    //
    if (provider->UefiRequired && (FirmwareType != FirmwareTypeUefi)) {
        return STATUS_NOT_SUPPORTED;
    }

    Context->Provider = provider;

    //
    // Load and open driver.
    //
    ntStatus = Context->Provider->Callbacks.StartDriver(Context);

    if (NT_SUCCESS(ntStatus)) {

        if (Context->Provider->Callbacks.RegisterDriver)
            if (!Context->Provider->Callbacks.RegisterDriver(Context->DeviceHandle,
                (PVOID)Context))
            {
                ntStatus = STATUS_INTERNAL_ERROR;
            }

    }

    return ntStatus;
}

/*
* WDrvProvRelease
*
* Purpose:
*
* Release driver provider instance.
*
*/
VOID WDrvProvRelease(
    _In_ PWDRV_CONTEXT Context
)
{
    PWDRV_PROVIDER provider;
    HANDLE deviceHandle;

    if (Context) {

        provider = Context->Provider;

        if (provider) {

            deviceHandle = Context->DeviceHandle;
            if (deviceHandle) {
                if (provider->Callbacks.UnregisterDriver)
                    provider->Callbacks.UnregisterDriver(deviceHandle,
                        (PVOID)Context);

                NtClose(deviceHandle);
            }

            if (provider->NoUnloadSupported == 0) {

                provider->Callbacks.StopDriver(Context);
            }
        }

        RtlSecureZeroMemory(Context, sizeof(WDRV_CONTEXT));

    }
}
