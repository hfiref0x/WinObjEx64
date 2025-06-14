/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2025
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.20
*
*  DATE:        08 Jun 2025
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

//
// Dll instance.
//
HINSTANCE g_ThisDLL = NULL;

volatile DWORD g_PluginState = PLUGIN_RUNNING;

//
// Plugin entry.
//
WINOBJEX_PLUGIN* g_Plugin = NULL;
volatile LONG m_RefCount = 0;

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

    if (g_Plugin->StateChangeCallback)
        g_Plugin->StateChangeCallback(g_Plugin, PluginStopped, NULL);

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
    GUI_CONTEXT* Context = (GUI_CONTEXT*)Parameter;

    if (Context == NULL)
        return (DWORD)-1;

    InterlockedIncrement(&m_RefCount);

    __try {
        if (g_Plugin->GuiInitCallback == NULL) { // this is required callback
            kdDebugPrint("Gui init callback required\r\n");
            __leave;
        }

        if (!g_Plugin->GuiInitCallback(g_Plugin,
            g_ThisDLL,
            (WNDPROC)MainWindowProc,
            NULL))
        {
            kdDebugPrint("Gui init callback failure\r\n");
            __leave;
        }

        uResult = (ULONG)RunUI(Context);
    }
    __finally {
        InterlockedDecrement(&m_RefCount);
        PluginFreeGlobalResources(Context);
        supHeapFree(Context);
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
    DWORD ThreadId;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    WINOBJEX_PLUGIN_STATE State = PluginInitialization;
    HANDLE WorkerThread, SectionHandle = NULL;
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
            Status = STATUS_MEMORY_NOT_ALLOCATED;
            __leave;
        }

        Status = Context->ParamBlock.OpenNamedObjectByType(
            &SectionHandle,
            ObjectTypeSection,
            &Context->ParamBlock.Object.Directory,
            &Context->ParamBlock.Object.Name,
            SECTION_QUERY | SECTION_MAP_READ);

        if (!NT_SUCCESS(Status)) {

            StringCbPrintf(szError, 100, TEXT("Could not open section, 0x%lX"), Status);

            MessageBox(
                ParamBlock->ParentWindow,
                szError,
                T_PLUGIN_NAME,
                MB_ICONERROR);

            if (g_Plugin && g_Plugin->StateChangeCallback)
                g_Plugin->StateChangeCallback(g_Plugin, PluginStopped, NULL);

            deallocateContext = TRUE;
            Status = STATUS_SUCCESS;
            __leave;
        }

        // Map section
        Status = supMapSection(
            SectionHandle,
            &Context->SectionAddress,
            &Context->SectionViewSize);

        NtClose(SectionHandle);
        SectionHandle = NULL;

        if (!NT_SUCCESS(Status)) {

            if (Status == STATUS_NOT_SUPPORTED) {
                MessageBox(ParamBlock->ParentWindow,
                    TEXT("This section does not represent mapped image, unable to continue."),
                    T_PLUGIN_NAME,
                    MB_ICONINFORMATION);
            }
            else {
                StringCbPrintf(szError, 100, TEXT("Could not map section, 0x%lX"), Status);
                MessageBox(ParamBlock->ParentWindow, szError,
                    T_PLUGIN_NAME,
                    MB_ICONERROR);
            }

            // Stop plugin if we cannot open section, but do not fail with error as we already displayed it.
            if (g_Plugin && g_Plugin->StateChangeCallback)
                g_Plugin->StateChangeCallback(g_Plugin, PluginStopped, NULL);

            Status = STATUS_SUCCESS;
            deallocateContext = TRUE;
            __leave;
        }

        WorkerThread = CreateThread(
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)PluginThread,
            (PVOID)Context,
            0,
            &ThreadId);

        if (WorkerThread) {
            Status = STATUS_SUCCESS;
            CloseHandle(WorkerThread);
            WorkerThread = NULL;
            State = PluginRunning;
        }
        else {
            Status = STATUS_UNSUCCESSFUL;
            State = PluginError;
            deallocateContext = TRUE;
        }
    }
    __finally {
        if (SectionHandle) {
            NtClose(SectionHandle);
        }

        if (deallocateContext && Context) {
            supHeapFree(Context);
        }

        if (g_Plugin && g_Plugin->StateChangeCallback)
            g_Plugin->StateChangeCallback(g_Plugin, State, NULL);
    }
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
    // Signal stop
    InterlockedExchange((PLONG)&g_PluginState, PLUGIN_STOP);

    // Wait for all references to be released
    while (InterlockedCompareExchange(&m_RefCount, 0, 0) > 0)
        Sleep(50);

    if (g_Plugin && g_Plugin->GuiShutdownCallback)
        g_Plugin->GuiShutdownCallback(g_Plugin, g_ThisDLL, NULL);

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
        // Setup permissions.
        //
        PluginData->NeedAdmin = FALSE;
        PluginData->SupportWine = TRUE;
        PluginData->NeedDriver = FALSE;

        PluginData->SupportMultipleInstances = TRUE;

        PluginData->MajorVersion = 1;
        PluginData->MinorVersion = 1;

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
