/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2026
*
*  TITLE:       PLUGIN_DEF.H
*
*  VERSION:     1.13
*
*  DATE:        07 Mar 2026
*
*  Common header file for the plugin subsystem definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#ifndef PLUGIN_DEF_H
#define PLUGIN_DEF_H

#define WOBJ_PLUGIN_SYSTEM_VERSION 25006

//
// Plugin ABI/capabilities version
//
#define WINOBJEX_PLUGIN_ABI_VERSION 0x0100

//
// Plugin init routine name.
//
#define WINOBJEX_PLUGIN_EXPORT "PluginInit"

//
// Plugin text consts, must include terminating 0.
//
#define MAX_PLUGIN_NAME 32
#define MAX_AUTHORS_NAME 32
#define MAX_PLUGIN_DESCRIPTION 128

//
// VERSION_INFO "FileDescription" value used for validating plugin.
//
// Plugins prior to 1.87 had "WinObjEx64 Plugin" description field.
// Make a new one to distinguish them because changes in plugin system are too complex.
//
#define WINOBJEX_PLUGIN_DESCRIPTION TEXT("WinObjEx64 Plugin V1.2")

// Plugin run state

// Indicates that plugin is running or about to run
#define PLUGIN_RUNNING  0

// Indicates that plugin need to be stopped
#define PLUGIN_STOP     1

typedef struct _WINOBJEX_PLUGIN WINOBJEX_PLUGIN, * PWINOBJEX_PLUGIN;

typedef struct _WINOBJEX_PARAM_OBJECT {
    UNICODE_STRING Name;
    UNICODE_STRING Directory;
} WINOBJEX_PARAM_OBJECT, * PWINOBJEX_PARAM_OBJECT;

typedef BOOL(CALLBACK* pfnReadSystemMemoryEx)(
    _In_ ULONG_PTR Address,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG NumberOfBytesRead);

typedef UCHAR(CALLBACK* pfnGetInstructionLength)(
    _In_ PVOID ptrCode,
    _Out_ PULONG ptrFlags);

typedef NTSTATUS(*pfnOpenNamedObjectByType)(
    _Out_ HANDLE* ObjectHandle,
    _In_ ULONG TypeIndex,
    _In_ PUNICODE_STRING ObjectDirectory,
    _In_ PUNICODE_STRING ObjectName,
    _In_ ACCESS_MASK DesiredAccess);

typedef struct _WINOBJEX_PARAM_BLOCK {
    ULONG cbSize; 
    HWND ParentWindow;
    HINSTANCE Instance;
    ULONG_PTR SystemRangeStart;
    UINT CurrentDPI;
    RTL_OSVERSIONINFOW Version;
    WINOBJEX_PARAM_OBJECT Object; // used only by Context plugins during StartPlugin callback

    //sys callbacks
    pfnReadSystemMemoryEx ReadSystemMemoryEx;
    pfnGetInstructionLength GetInstructionLength;
    pfnOpenNamedObjectByType OpenNamedObjectByType;

    ULONG Reserved[8];
} WINOBJEX_PARAM_BLOCK, * PWINOBJEX_PARAM_BLOCK;

typedef enum _WINOBJEX_PLUGIN_STATE {
    PluginInitialization = 0,
    PluginStopped = 1,
    PluginRunning = 2,
    PluginError = 3,
    MaxPluginState
} WINOBJEX_PLUGIN_STATE;

typedef enum _WINOBJEX_PLUGIN_TYPE {
    DefaultPlugin = 0, // General purpose plugin (shown in main menu under "Plugins")
    ContextPlugin = 1, // Object type specific plugin (shown in popup menu for specified object types)
    InvalidPluginType
} WINOBJEX_PLUGIN_TYPE;

//
// Object type indexes for known types, must be in compliance with WOBJ_OBJECT_TYPE values.
//

#define PluginObjectTypeDevice                        0
#define PluginObjectTypeDriver                        1
#define PluginObjectTypeSection                       2
#define PluginObjectTypePort                          3
#define PluginObjectTypeSymbolicLink                  4
#define PluginObjectTypeKey                           5
#define PluginObjectTypeEvent                         6
#define PluginObjectTypeJob                           7
#define PluginObjectTypeMutant                        8
#define PluginObjectTypeKeyedEvent                    9
#define PluginObjectTypeType                          10
#define PluginObjectTypeDirectory                     11
#define PluginObjectTypeWinstation                    12
#define PluginObjectTypeCallback                      13
#define PluginObjectTypeSemaphore                     14
#define PluginObjectTypeWaitablePort                  15
#define PluginObjectTypeTimer                         16
#define PluginObjectTypeSession                       17
#define PluginObjectTypeController                    18
#define PluginObjectTypeProfile                       19
#define PluginObjectTypeEventPair                     20
#define PluginObjectTypeDesktop                       21
#define PluginObjectTypeFile                          22
#define PluginObjectTypeWMIGuid                       23
#define PluginObjectTypeDebugObject                   24
#define PluginObjectTypeIoCompletion                  25
#define PluginObjectTypeProcess                       26
#define PluginObjectTypeAdapter                       27
#define PluginObjectTypeToken                         28
#define PluginObjectTypeETWRegistration               29
#define PluginObjectTypeThread                        30
#define PluginObjectTypeTmTx                          31
#define PluginObjectTypeTmTm                          32
#define PluginObjectTypeTmRm                          33
#define PluginObjectTypeTmEn                          34
#define PluginObjectTypePcwObject                     35
#define PluginObjectTypeFltConnPort                   36
#define PluginObjectTypeFltComnPort                   37
#define PluginObjectTypePowerRequest                  38
#define PluginObjectTypeETWConsumer                   39
#define PluginObjectTypeTpWorkerFactory               40
#define PluginObjectTypeComposition                   41
#define PluginObjectTypeIRTimer                       42
#define PluginObjectTypeDxgkSharedResource            43
#define PluginObjectTypeDxgkSharedSwapChain           44
#define PluginObjectTypeDxgkSharedSyncObject          45
#define PluginObjectTypeDxgkCurrentDxgProcessObject   46
#define PluginObjectTypeDxgkCurrentDxgThreadObject    47
#define PluginObjectTypeDxgkDisplayManager            48
#define PluginObjectTypeDxgkDisplayMuxSwitch          49
#define PluginObjectTypeDxgkSharedBundle              50
#define PluginObjectTypeDxgkSharedProtectedSession    51
#define PluginObjectTypeDxgkComposition               52
#define PluginObjectTypeDxgkSharedKeyedMutex          53
#define PluginObjectTypeMemoryPartition               54
#define PluginObjectTypeRegistryTransaction           55
#define PluginObjectTypeDmaAdapter                    56
#define PluginObjectTypeDmaDomain                     57
#define PluginObjectTypeCoverageSampler               58
#define PluginObjectTypeActivationObject              59
#define PluginObjectTypeActivityReference             60
#define PluginObjectTypeCoreMessaging                 61
#define PluginObjectTypeRawInputManager               62
#define PluginObjectTypeWaitCompletionPacket          63
#define PluginObjectTypeIoCompletionReserve           64
#define PluginObjectTypeUserApcReserve                65
#define PluginObjectTypeIoRing                        66
#define PluginObjectTypeTerminal                      67
#define PluginObjectTypeTerminalEventQueue            68
#define PluginObjectTypeEnergyTracker                 69
#define PluginObjectTypeUnknown                       70
#define PluginObjectTypeAnyType                       0xfe
#define PluginObjectTypeNone                          0xff

#define PLUGIN_MAX_SUPPORTED_OBJECTS 0xff

typedef NTSTATUS(CALLBACK* pfnStartPlugin)(
    _In_ PWINOBJEX_PARAM_BLOCK ParamBlock);

typedef void(CALLBACK* pfnStopPlugin)(
    VOID);

typedef BOOLEAN(CALLBACK* pfnPluginInit)(
    _Inout_ PWINOBJEX_PLUGIN PluginData
    );

typedef void(CALLBACK* pfnStateChangeCallback)(
    _In_ WINOBJEX_PLUGIN* PluginData,
    _In_ WINOBJEX_PLUGIN_STATE NewState,
    _Reserved_ PVOID Reserved);

typedef BOOL(CALLBACK* pfnGuiInitCallback)(
    _In_ WINOBJEX_PLUGIN* PluginData,
    _In_ HINSTANCE PluginInstance,
    _In_ WNDPROC WndProc,
    _Reserved_ PVOID Reserved
    );

typedef VOID(CALLBACK* pfnGuiShutdownCallback)(
    _In_ WINOBJEX_PLUGIN* PluginData,
    _In_ HINSTANCE PluginInstance,
    _Reserved_ PVOID Reserved
    );

typedef struct _WINOBJEX_PLUGIN {
    ULONG cbSize;
    ULONG AbiVersion;
    union {
        ULONG Flags;
        struct {
            ULONG NeedAdmin : 1;
            ULONG NeedDriver : 1;
            ULONG SupportWine : 1;
            ULONG SupportMultipleInstances : 1;
            ULONG Reserved : 28;
        } u1;
    } Capabilities;
    WINOBJEX_PLUGIN_TYPE Type;
    WINOBJEX_PLUGIN_STATE State;
    WORD MajorVersion;
    WORD MinorVersion;
    ULONG RequiredPluginSystemVersion;
    UCHAR SupportedObjectsIds[PLUGIN_MAX_SUPPORTED_OBJECTS]; // Ignored if plugin Type is DefaultPlugin
    WCHAR Name[MAX_PLUGIN_NAME];
    WCHAR Authors[MAX_AUTHORS_NAME];
    WCHAR Description[MAX_PLUGIN_DESCRIPTION];
    pfnStartPlugin StartPlugin;
    pfnStopPlugin StopPlugin;
    pfnStateChangeCallback StateChangeCallback;
    pfnGuiInitCallback GuiInitCallback;
    pfnGuiShutdownCallback GuiShutdownCallback;

    ULONG Reserved[8];
} WINOBJEX_PLUGIN, * PWINOBJEX_PLUGIN;

typedef struct _WINOBJEX_PLUGIN_INTERNAL {
    LIST_ENTRY ListEntry;
    UINT Id;
    HMODULE Module;
    WINOBJEX_PLUGIN Plugin;
} WINOBJEX_PLUGIN_INTERNAL, * PWINOBJEX_PLUGIN_INTERNAL;

#endif /* PLUGIN_DEF_H */
