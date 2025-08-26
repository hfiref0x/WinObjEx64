/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2025
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.21
*
*  DATE:        22 Aug 2025
*
*  WinObjEx64 ImageScope plugin.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

#define IMAGESCOPE_PLUGIN_MAJOR_VERSION 1
#define IMAGESCOPE_PLUGIN_MINOR_VERSION 2

//
// Dll instance.
//
HINSTANCE g_thisDll = NULL;

volatile DWORD g_pluginState = PLUGIN_RUNNING;

//
// Plugin entry.
//
WINOBJEX_PLUGIN* g_plugin = NULL;
volatile LONG g_refCount = 0;

/*
* PmpCopyObjectData
*
* Purpose:
*
* Create copies of object directory and name.
*
*/
BOOL PmpCopyObjectData(
    _In_ WINOBJEX_PARAM_OBJECT* Source,
    _In_ WINOBJEX_PARAM_OBJECT* Dest
)
{
    HANDLE HeapHandle = NtCurrentPeb()->ProcessHeap;

    return supDuplicateUnicodeString(HeapHandle, &Dest->Directory, &Source->Directory) &&
        supDuplicateUnicodeString(HeapHandle, &Dest->Name, &Source->Name);
}

/*
* PluginFreeGlobalResources
*
* Purpose:
*
* Plugin resources deallocation routine.
*
*/
VOID PluginFreeGlobalResources(
    _In_ GUI_CONTEXT* Context
)
{
    if (Context->SectionAddress) {
        NtUnmapViewOfSection(NtCurrentProcess(), Context->SectionAddress);
        Context->SectionAddress = NULL;
    }

    supFreeDuplicatedUnicodeString(NtCurrentPeb()->ProcessHeap,
        &Context->ParamBlock.Object.Directory, TRUE);

    supFreeDuplicatedUnicodeString(NtCurrentPeb()->ProcessHeap,
        &Context->ParamBlock.Object.Name, TRUE);
}

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
    ULONG uResult = 0;
    GUI_CONTEXT* context = (GUI_CONTEXT*)Parameter;

    if (context == NULL)
        return (DWORD)-1;

    InterlockedIncrement(&g_refCount);

    __try {
        if (g_plugin == NULL || g_plugin->GuiInitCallback == NULL) { // this is required callback
            kdDebugPrint("Gui init callback required\r\n");
            __leave;
        }

        if (!g_plugin->GuiInitCallback(g_plugin,
            g_thisDll,
            (WNDPROC)MainWindowProc,
            NULL))
        {
            kdDebugPrint("Gui init callback failure\r\n");
            __leave;
        }

        uResult = (ULONG)RunUI(context);
    }
    __finally {
        InterlockedDecrement(&g_refCount);
        PluginFreeGlobalResources(context);
        supHeapFree(context);
    }

    ExitThread(uResult);
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
    BOOL deallocateContext = FALSE;
    DWORD threadId;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    WINOBJEX_PLUGIN_STATE state = PluginInitialization;
    HANDLE workerThread, sectionHandle = NULL;
    GUI_CONTEXT* Context;

    WCHAR szError[100];

    Context = (GUI_CONTEXT*)supHeapAlloc(sizeof(GUI_CONTEXT));
    if (Context == NULL)
        return STATUS_MEMORY_NOT_ALLOCATED;

    __try {
        RtlCopyMemory(
            &Context->ParamBlock,
            ParamBlock,
            sizeof(WINOBJEX_PARAM_BLOCK));

        RtlZeroMemory(
            &Context->ParamBlock.Object,
            sizeof(WINOBJEX_PARAM_OBJECT));

        if (!PmpCopyObjectData(
            &ParamBlock->Object,
            &Context->ParamBlock.Object))
        {
            deallocateContext = TRUE;
            status = STATUS_MEMORY_NOT_ALLOCATED;
            __leave;
        }

        if (Context->ParamBlock.OpenNamedObjectByType == NULL) {
            deallocateContext = TRUE;
            status = STATUS_INVALID_PARAMETER;
            __leave;
        }

        status = Context->ParamBlock.OpenNamedObjectByType(
            &sectionHandle,
            ObjectTypeSection,
            &Context->ParamBlock.Object.Directory,
            &Context->ParamBlock.Object.Name,
            SECTION_QUERY | SECTION_MAP_READ);

        if (!NT_SUCCESS(status)) {
            StringCbPrintf(szError, sizeof(szError), TEXT("Could not open section, 0x%08X"), (ULONG)status);

            MessageBox(
                ParamBlock->ParentWindow,
                szError,
                T_PLUGIN_NAME,
                MB_ICONERROR);

            deallocateContext = TRUE;
            status = STATUS_SUCCESS;
            __leave;
        }

        // Map section
        status = supMapSection(
            sectionHandle,
            &Context->SectionAddress,
            &Context->SectionViewSize);

        NtClose(sectionHandle);
        sectionHandle = NULL;

        if (!NT_SUCCESS(status)) {

            if (status == STATUS_NOT_SUPPORTED) {
                MessageBox(ParamBlock->ParentWindow,
                    TEXT("This section does not represent mapped image, unable to continue."),
                    T_PLUGIN_NAME,
                    MB_ICONINFORMATION);
            }
            else {
                StringCbPrintf(szError, sizeof(szError), TEXT("Could not map section, 0x%08X"), (ULONG)status);
                MessageBox(ParamBlock->ParentWindow, szError,
                    T_PLUGIN_NAME,
                    MB_ICONERROR);
            }

            // Stop plugin if we cannot open section, but do not fail with error as we already displayed it.
            state = PluginStopped;
            deallocateContext = TRUE;
            status = STATUS_SUCCESS;
            __leave;
        }

        workerThread = CreateThread(
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)PluginThread,
            (PVOID)Context,
            0,
            &threadId);

        if (workerThread) {
            status = STATUS_SUCCESS;
            CloseHandle(workerThread);
            workerThread = NULL;
            state = PluginRunning;
        }
        else {
            status = STATUS_UNSUCCESSFUL;
            state = PluginError;
            deallocateContext = TRUE;
        }
    }
    __finally {
        if (sectionHandle) {
            NtClose(sectionHandle);
        }

        if (deallocateContext && Context) {
            supHeapFree(Context);
        }

        if (g_plugin && g_plugin->StateChangeCallback)
            g_plugin->StateChangeCallback(g_plugin, state, NULL);
    }
    return status;
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
    // Signal stop
    InterlockedExchange((PLONG)&g_pluginState, PLUGIN_STOP);

    // Wait for all references to be released
    while (InterlockedCompareExchange(&g_refCount, 0, 0) > 0)
        Sleep(50);

    if (g_plugin && g_plugin->GuiShutdownCallback)
        g_plugin->GuiShutdownCallback(g_plugin, g_thisDll, NULL);

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
        StringCbCopy(PluginData->Name, sizeof(PluginData->Name), TEXT("ImageScope"));

        //
        // Set authors.
        //
        StringCbCopy(PluginData->Authors, sizeof(PluginData->Authors), TEXT("UG North"));

        //
        // Set plugin description.
        //
        StringCbCopy(PluginData->Description, sizeof(PluginData->Description),
            TEXT("Display additional information for sections created from PE files."));

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
        // Setup capabilities.
        //
        PluginData->Capabilities.u1.NeedAdmin = FALSE;
        PluginData->Capabilities.u1.SupportWine = TRUE;
        PluginData->Capabilities.u1.NeedDriver = FALSE;
        PluginData->Capabilities.u1.SupportMultipleInstances = TRUE;

        PluginData->MajorVersion = IMAGESCOPE_PLUGIN_MAJOR_VERSION;
        PluginData->MinorVersion = IMAGESCOPE_PLUGIN_MINOR_VERSION;

        //
        // Set plugin type.
        //
        PluginData->Type = ContextPlugin;

        //
        // Set supported object type(s).
        //
        RtlFillMemory(
            PluginData->SupportedObjectsIds,
            sizeof(PluginData->SupportedObjectsIds),
            ObjectTypeNone);

        PluginData->SupportedObjectsIds[0] = ObjectTypeSection;

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
* Dll entry point.
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
        g_thisDll = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}
