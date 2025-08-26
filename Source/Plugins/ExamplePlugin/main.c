/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2025
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.03
*
*  DATE:        22 Aug 2025
*
*  WinObjEx64 example and test plugin.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma warning(disable: 6258) //Using TerminateThread does not allow proper thread clean up.
#pragma warning(disable: 6320) //Exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER. This might mask exceptions that were not intended to be handled.

#define EXAMPLE_PLUGIN_MAJOR_VERSION 1
#define EXAMPLE_PLUGIN_MINOR_VERSION 2

#include <Windows.h>
#include <strsafe.h>

#pragma warning(push)
#pragma warning(disable: 4005)
#include <ntstatus.h>
#pragma warning(pop)
#include "ntos/ntos.h"
#include "plugin_def.h"

volatile DWORD g_pluginState = PLUGIN_RUNNING;
HANDLE g_threadHandle = NULL;
WINOBJEX_PARAM_BLOCK g_paramBlock;
WINOBJEX_PLUGIN* g_plugin = NULL;
HINSTANCE g_thisDll = NULL;

/*
* PluginThread
*
* Purpose:
*
* Plugin payload thread.
*
*/
DWORD WINAPI PluginThread(
    _In_ PVOID Parameter
)
{
    UNREFERENCED_PARAMETER(Parameter);

    MessageBox(GetDesktopWindow(), TEXT("This is message from example plugin, plugin will stop in 5 sec."), TEXT("ExamplePlugin"), MB_ICONINFORMATION);

    Sleep(5000);
    InterlockedExchange((PLONG)&g_pluginState, PLUGIN_STOP);

    if (g_plugin && g_plugin->StateChangeCallback)
        g_plugin->StateChangeCallback(g_plugin, PluginStopped, NULL);

    return 0;
}

/*
* StartPlugin
*
* Purpose:
*
* Run actual plugin code in dedicated thread.
*
* Parameters:
*   ParamBlock - Plugin parameters passed from WinObjEx64
*
* Return:
*   STATUS_SUCCESS - Plugin started successfully
*   STATUS_UNSUCCESSFUL - Failed to start plugin
*/
NTSTATUS CALLBACK StartPlugin(
    _In_ PWINOBJEX_PARAM_BLOCK ParamBlock
)
{
    DWORD threadId;
    NTSTATUS status;
    WINOBJEX_PLUGIN_STATE State = PluginInitialization;

    DbgPrint("StartPlugin called from thread 0x%lx\r\n", GetCurrentThreadId());

    if (ParamBlock == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(&g_paramBlock, ParamBlock, sizeof(WINOBJEX_PARAM_BLOCK));
    InterlockedExchange((PLONG)&g_pluginState, PLUGIN_RUNNING);
    
    g_threadHandle = CreateThread(
        NULL, 
        0, 
        (LPTHREAD_START_ROUTINE)PluginThread, 
        (PVOID)NULL, 0, 
        &threadId);

    if (g_threadHandle) {
        status = STATUS_SUCCESS;
        State = PluginRunning;
    }
    else {
        status = STATUS_UNSUCCESSFUL;
        State = PluginError;
    }

    if (g_plugin && g_plugin->StateChangeCallback)
        g_plugin->StateChangeCallback(g_plugin, State, NULL);

    return status;
}

/*
* StopPlugin
*
* Purpose:
*
* Stop plugin execution and cleanup resources.
*
*/
void CALLBACK StopPlugin(
    VOID
)
{
    DbgPrint("StopPlugin called from thread 0x%lx\r\n", GetCurrentThreadId());

    if (g_threadHandle) {

        InterlockedExchange((PLONG)&g_pluginState, PLUGIN_STOP);

        if (WaitForSingleObject(g_threadHandle, 1000) == WAIT_TIMEOUT) {
            DbgPrint("Wait timeout, terminating plugin thread, g_threadHandle = %llx\r\n", (ULONG_PTR)g_threadHandle);
            TerminateThread(g_threadHandle, 0);
        }
        else {
            DbgPrint("Wait success, plugin thread stopped, g_threadHandle = %llx\r\n", (ULONG_PTR)g_threadHandle);
        }

        CloseHandle(g_threadHandle);
        g_threadHandle = NULL;

        if (g_plugin && g_plugin->StateChangeCallback)
            g_plugin->StateChangeCallback(g_plugin, PluginStopped, NULL);
    }
}

/*
* PluginInit
*
* Purpose:
*
* Initialize plugin information for WinObjEx64.
*
* Parameters:
*   PluginData - Plugin data structure to be filled
*
* Return:
*   TRUE - Plugin initialized successfully
*   FALSE - Failed to initialize plugin
*/
BOOLEAN CALLBACK PluginInit(
    _Inout_ PWINOBJEX_PLUGIN PluginData
)
{
    // Don't initialize twice
    if (g_plugin) {
        return FALSE;
    }

    __try {
        if (PluginData == NULL) {
            return FALSE;
        }

        if (PluginData->cbSize < sizeof(WINOBJEX_PLUGIN)) {
            return FALSE;
        }

        if (PluginData->AbiVersion != WINOBJEX_PLUGIN_ABI_VERSION) {
            return FALSE;
        }

        //
        // Set plugin name to be displayed in WinObjEx64 UI.
        //
        StringCbCopy(PluginData->Name, sizeof(PluginData->Name), TEXT("Example Plugin"));

        //
        // Set authors.
        //
        StringCbCopy(PluginData->Authors, sizeof(PluginData->Authors), TEXT("UG North"));

        //
        // Set plugin description.
        //
        StringCbCopy(PluginData->Description, sizeof(PluginData->Description), 
            TEXT("WinObjEx64 example plugin."));

        //
        // Set required plugin system version.
        //
        PluginData->RequiredPluginSystemVersion = WOBJ_PLUGIN_SYSTEM_VERSION;

        //
        // Setup start/stop plugin callbacks.
        //
        PluginData->StartPlugin = (pfnStartPlugin)&StartPlugin;
        PluginData->StopPlugin = (pfnStopPlugin)&StopPlugin;

        //
        // Setup permissions.
        //
        PluginData->Capabilities.u1.NeedAdmin = FALSE;
        PluginData->Capabilities.u1.SupportWine = TRUE;
        PluginData->Capabilities.u1.NeedDriver = FALSE;

        PluginData->MajorVersion = EXAMPLE_PLUGIN_MAJOR_VERSION;
        PluginData->MinorVersion = EXAMPLE_PLUGIN_MINOR_VERSION;

        //
        // Set plugin type.
        //
        PluginData->Type = DefaultPlugin;

        g_plugin = PluginData;

        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("PluginInit exception thrown %lx\r\n", GetExceptionCode());
        return FALSE;
    }
}

/*
* DllMain
*
* Purpose:
*
* DLL entry point.
*
* Parameters:
*   hinstDLL - DLL instance handle
*   fdwReason - Reason for calling function
*   lpvReserved - Reserved
*
* Return:
*   TRUE - Always
*/
BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    lpvReserved
)
{
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_thisDll = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}
