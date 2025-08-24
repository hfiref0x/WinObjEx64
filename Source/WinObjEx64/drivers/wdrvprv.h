/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022 - 2025
*
*  TITLE:       WDRVPRV.H
*
*  VERSION:     2.09
*
*  DATE:        20 Aug 2025
*
*  Common header file for WinObjEx64 driver providers.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef enum _WDRVPRVTYPE {
    // Microsoft WinDbg driver
    wdrvMicrosoft = 0,
    // WinObjEx64 driver
    wdrvWinObjEx64 = 1,
    // WinIO based driver
    wdrvWinIo = 2,
    // Rkhdrv series driver deprecated
    // Alice driver
    wdrvAlice = 4,
    // Ronova kernel driver
    wdrvRonova = 5,
    wdrvMax
} WDRVPRVTYPE;

//
// Providers abstraction interface.
//

typedef struct _WDRV_CONTEXT* PWDRV_CONTEXT;

//
// Prototype for read physical memory function.
//
typedef NTSTATUS(WINAPI* provReadPhysicalMemory)(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes);

//
// Prototype for query PML4 value function.
//
typedef NTSTATUS(WINAPI* provQueryPML4)(
    _In_ HANDLE DeviceHandle,
    _Out_ ULONG_PTR* Value);

//
// Prototype for read kernel virtual memory function.
//
typedef BOOL(WINAPI* provReadSystemMemory)(
    _In_ struct _WDRV_CONTEXT* Context,
    _In_ ULONG_PTR Address,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG NumberOfBytesRead);

//
// Prototype for driver registering/unlocking function.
//
typedef BOOL(WINAPI* provRegisterDriver)(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param);

//
// Prototype for driver unregistering function.
//
typedef BOOL(WINAPI* provUnregisterDriver)(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param);

//
// Prototype for driver specific pre-open actions.
//
typedef BOOL(WINAPI* provPreOpenDriver)(
    _In_opt_ PVOID Param
    );

//
// Prototype for driver specific post-open actions.
//
typedef BOOL(WINAPI* provPostOpenDriver)(
    _In_opt_ PVOID Param
    );

//
// Start/Stop/Open prototypes.
//
typedef NTSTATUS(WINAPI* provStartDriver)(
    _In_ struct _WDRV_CONTEXT* Context
    );
typedef void(WINAPI* provStopDriver)(
    _In_ struct _WDRV_CONTEXT* Context
    );
typedef NTSTATUS(WINAPI* provOpenDriver)(
    _In_ struct _WDRV_CONTEXT* Context
    );

//
// No optional provider flags specified, this is default value.
//
#define WDRVPROV_FLAGS_NONE                   0x00000000

//
// Provider requires UEFI firmware type.
//
#define WDRVPROV_FLAGS_UEFI_REQUIRED          0x00000001

//
// Set System/Admin-only security descriptor to the provider driver device.
//
#define WDRVPROV_FLAGS_FORCE_SD               0x00000002

//
// Do not unload, driver does not support this.
//
#define WDRVPROV_FLAGS_NO_UNLOAD_SUP          0x00000004


typedef struct _WDRV_PROVIDER {
    LPWSTR DriverName; // file name only
    LPWSTR DeviceName; // device name only

    union {
        ULONG Flags;
        struct {
            ULONG UefiRequired : 1;
            ULONG ForceSD : 1;
            ULONG NoUnloadSupported : 1;
            ULONG Reserved : 29;
        };
    };

    struct {
        provStartDriver StartDriver;
        provStopDriver StopDriver;
        provOpenDriver OpenDriver;

        provRegisterDriver RegisterDriver; //optional
        provUnregisterDriver UnregisterDriver; //optional

        provPreOpenDriver PreOpenDriver; //optional;
        provPostOpenDriver PostOpenDriver; //optional;

        provReadSystemMemory ReadSystemMemory;
    } Callbacks;

} WDRV_PROVIDER, * PWDRV_PROVIDER;

typedef struct _WDRV_CONTEXT {

    BOOL IsOurLoad;

    NTSTATUS LoadStatus;
    NTSTATUS OpenStatus;

    HANDLE DeviceHandle;
    PWDRV_PROVIDER Provider;

    //full file name to the driver
    WCHAR DriverFileName[MAX_PATH * 2];

    NTSTATUS LastNtStatus;
    IO_STATUS_BLOCK IoStatusBlock;

} WDRV_CONTEXT, * PWDRV_CONTEXT;

WDRVPRVTYPE WDrvGetActiveProviderType(
    VOID);

BOOL WINAPI WDrvProvPostOpen(
    _In_ PVOID Param);

NTSTATUS WDrvStartDriver(
    _In_ PWDRV_CONTEXT Context);

VOID WDrvStopDriver(
    _In_ PWDRV_CONTEXT Context);

NTSTATUS WDrvOpenDriver(
    _In_ PWDRV_CONTEXT Context);

NTSTATUS WDrvProvCreate(
    _In_ FIRMWARE_TYPE FirmwareType,
    _Out_ PWDRV_CONTEXT Context);

VOID WDrvProvRelease(
    _In_ PWDRV_CONTEXT Context);

NTSTATUS PwVirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ provQueryPML4 QueryPML4Routine,
    _In_ provReadPhysicalMemory ReadPhysicalMemoryRoutine,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress);
