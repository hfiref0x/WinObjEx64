/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2020
*
*  TITLE:       PLUGINMNGR.H
*
*  VERSION:     1.87
*
*  DATE:        17 July 2020
*
*  Common header file for the plugin manager.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define WOBJ_PLUGIN_SYSTEM_VERSION 18712

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

#define ID_MENU_PLUGINS       60000
#define WINOBJEX_MAX_PLUGINS  20
#define ID_MENU_PLUGINS_MAX   (ID_MENU_PLUGINS + WINOBJEX_MAX_PLUGINS)

//
// VERSION_INFO "FileDescription" value used for validating plugin.
//
// Plugins prior to 1.87 had "WinObjEx64 Plugin" description field.
// Make a new one to distinguish them because changes in plugin system are too complex.
//
#define WINOBJEX_PLUGIN_DESCRIPTION TEXT("WinObjEx64 Plugin V1.1")

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
    _In_ LPWSTR ObjectDirectory,
    _In_opt_ LPWSTR ObjectName,
    _In_ ACCESS_MASK DesiredAccess);

typedef struct _WINOBJEX_PARAM_OBJECT {
    LPWSTR ObjectName;
    LPWSTR ObjectDirectory;
    PVOID Reserved;
} WINOBJEX_PARAM_OBJECT, * PWINOBJEX_PARAM_OBJECT;

typedef struct _WINOBJEX_PARAM_BLOCK {
    HWND ParentWindow;
    HINSTANCE Instance;
    ULONG_PTR SystemRangeStart;
    UINT CurrentDPI;
    RTL_OSVERSIONINFOW Version;
    WINOBJEX_PARAM_OBJECT Object; // used only by Context plugins during StartPlugin callback

    //sys
    pfnReadSystemMemoryEx ReadSystemMemoryEx;
    pfnGetInstructionLength GetInstructionLength;
    pfnOpenNamedObjectByType OpenNamedObjectByType;

} WINOBJEX_PARAM_BLOCK, * PWINOBJEX_PARAM_BLOCK;

typedef NTSTATUS(CALLBACK* pfnStartPlugin)(
    _In_ PWINOBJEX_PARAM_BLOCK ParamBlock);

typedef void(CALLBACK* pfnStopPlugin)(
    VOID);

typedef struct _WINOBJEX_PLUGIN WINOBJEX_PLUGIN;

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

#define PLUGIN_MAX_SUPPORTED_OBJECT_ID 0xff

typedef struct _WINOBJEX_PLUGIN {
    BOOLEAN NeedAdmin;
    BOOLEAN NeedDriver;
    BOOLEAN SupportWine;
    BOOLEAN SupportMultipleInstances;
    WINOBJEX_PLUGIN_TYPE Type;
    WINOBJEX_PLUGIN_STATE State;
    WORD MajorVersion;
    WORD MinorVersion;
    ULONG RequiredPluginSystemVersion;
    UCHAR SupportedObjectsIds[PLUGIN_MAX_SUPPORTED_OBJECT_ID]; // Ignored if plugin Type is DefaultPlugin
    WCHAR Name[MAX_PLUGIN_NAME];
    WCHAR Authors[MAX_AUTHORS_NAME];
    WCHAR Description[MAX_PLUGIN_DESCRIPTION];
    pfnStartPlugin StartPlugin;
    pfnStopPlugin StopPlugin;
    pfnStateChangeCallback StateChangeCallback;
    pfnGuiInitCallback GuiInitCallback;
    pfnGuiShutdownCallback GuiShutdownCallback;
} WINOBJEX_PLUGIN, * PWINOBJEX_PLUGIN;

typedef struct _WINOBJEX_PLUGIN_INTERNAL {
    LIST_ENTRY ListEntry;
    UINT Id;
    HMODULE Module;
    WINOBJEX_PLUGIN Plugin;
} WINOBJEX_PLUGIN_INTERNAL, * PWINOBJEX_PLUGIN_INTERNAL;

typedef BOOLEAN(CALLBACK* pfnPluginInit)(
    _Inout_ PWINOBJEX_PLUGIN PluginData
    );

VOID PmCreate(_In_ HWND MainWindow);
VOID PmDestroy();

VOID PmProcessEntry(
    _In_ HWND ParentWindow,
    _In_ UINT Id);

VOID PmBuildPluginPopupMenuByObjectType(
    _In_ HMENU ContextMenu,
    _In_ UCHAR ObjectType);

VOID PmViewPlugins(
    _In_ HWND ParentWindow);
