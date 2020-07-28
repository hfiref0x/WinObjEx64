/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2020
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.01
*
*  DATE:        27 June 2020
*
*  WinObjEx64 example and test plugin.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include <Windows.h>
#include <strsafe.h>

#pragma warning(push)
#pragma warning(disable: 4005)
#include <ntstatus.h>
#pragma warning(pop)
#include "ntos/ntos.h"
#include "plugin_def.h"

volatile BOOL g_StopPlugin = FALSE;
HANDLE g_hThread = NULL;
WINOBJEX_PARAM_BLOCK g_ParamBlock;
WINOBJEX_PLUGIN* g_Plugin = NULL;
HINSTANCE g_ThisDLL = NULL;

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
    InterlockedExchange((PLONG)&g_StopPlugin, TRUE);

    if (g_Plugin->StateChangeCallback)
        g_Plugin->StateChangeCallback(g_Plugin, PluginStopped, NULL);

    ExitThread(0);
}

/*
* StartPlugin
*
* Purpose:
*
* Run actual plugin code in dedicated thread.
*
*/
NTSTATUS CALLBACK StartPlugin(
    _In_ PWINOBJEX_PARAM_BLOCK ParamBlock
)
{
    DWORD ThreadId;
    NTSTATUS Status;
    WINOBJEX_PLUGIN_STATE State = PluginInitialization;

    DbgPrint("StartPlugin called from thread 0x%lx\r\n", GetCurrentThreadId());

    RtlCopyMemory(&g_ParamBlock, ParamBlock, sizeof(WINOBJEX_PARAM_BLOCK));
    InterlockedExchange((PLONG)&g_StopPlugin, FALSE);
    g_hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PluginThread, (PVOID)NULL, 0, &ThreadId);
    if (g_hThread) {
        Status = STATUS_SUCCESS;
    }
    else {
        Status = STATUS_UNSUCCESSFUL;
    }

    if (NT_SUCCESS(Status))
        State = PluginRunning;
    else
        State = PluginError;

    if (g_Plugin->StateChangeCallback)
        g_Plugin->StateChangeCallback(g_Plugin, State, NULL);

    return Status;
}

/*
* StopPlugin
*
* Purpose:
*
* Stop plugin execution.
*
*/
void CALLBACK StopPlugin(
    VOID
)
{
    DbgPrint("StopPlugin called from thread 0x%lx\r\n", GetCurrentThreadId());

    if (g_hThread) {
        InterlockedExchange((PLONG)&g_StopPlugin, TRUE);
        if (WaitForSingleObject(g_hThread, 1000) == WAIT_TIMEOUT) {
            DbgPrint("Wait timeout, terminating plugin thread, g_hTread = %llx\r\n", g_hThread);
            TerminateThread(g_hThread, 0);
        }
        else {
            DbgPrint("Wait success, plugin thread stopped, g_Thread = %llx\r\n", g_hThread);
        }
        CloseHandle(g_hThread);
        g_hThread = NULL;

        if (g_Plugin->StateChangeCallback)
            g_Plugin->StateChangeCallback(g_Plugin, PluginStopped, NULL);
    }
}

/*
* PluginInit
*
* Purpose:
*
* Initialize plugin information for WinObjEx64.
*
*/
BOOLEAN CALLBACK PluginInit(
    _Inout_ PWINOBJEX_PLUGIN PluginData
)
{
    if (g_Plugin)
        return FALSE;

    __try {
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
        PluginData->NeedAdmin = FALSE;
        PluginData->SupportWine = TRUE;
        PluginData->NeedDriver = FALSE;

        PluginData->MajorVersion = 1;
        PluginData->MinorVersion = 1;

        //
        // Set plugin type.
        //
        PluginData->Type = DefaultPlugin;

        g_Plugin = PluginData;

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
* Dummy dll entrypoint.
*
*/
BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    lpvReserved
)
{
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_ThisDLL = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}
