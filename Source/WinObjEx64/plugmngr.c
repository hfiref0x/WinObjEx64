/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       PLUGMNGR.C
*
*  VERSION:     1.82
*
*  DATE:        02 Nov 2019
*
*  Plugin manager.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

LIST_ENTRY g_PluginsListHead;
UINT g_PluginCount = ID_MENU_PLUGINS;

/*
* PluginManagerDllIsPlugin
*
* Purpose:
*
* Validate plugin by version info description.
*
*/
BOOL PluginManagerDllIsPlugin(
    _In_ LPWSTR lpszPluginName
)
{
    BOOL bResult = FALSE;
    DWORD dwHandle, dwSize;
    PVOID versionInfo;
    LPTRANSLATE	lpTranslate = NULL;
    LPWSTR lpFileDescription;

    WCHAR szBuffer[100];

    dwSize = GetFileVersionInfoSizeEx(0, lpszPluginName, &dwHandle);
    if (dwSize) {
        versionInfo = supHeapAlloc((SIZE_T)dwSize);
        if (versionInfo) {

            if (GetFileVersionInfoEx(0, lpszPluginName, dwHandle, dwSize, versionInfo)) {

                dwSize = 0;
                if (VerQueryValue(versionInfo, VERSION_TRANSLATION, (LPVOID*)&lpTranslate, (PUINT)&dwSize)) {

                    rtl_swprintf_s(szBuffer, MAX_PATH, VERSION_DESCRIPTION,
                        lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);

                    lpFileDescription = NULL;
                    dwSize = 0;
                    if (VerQueryValue(versionInfo, szBuffer, (LPVOID*)&lpFileDescription, (PUINT)&dwSize)) {
                        bResult = (_strcmp(lpFileDescription, WINOBJEX_PLUGIN_DESCRIPTION) == 0);
                    }
                }
            }

            supHeapFree(versionInfo);
        }
    }

    return bResult;
}

/*
* PluginManagerStateChangeCallback
*
* Purpose:
*
* Callback to be called by plugins on state change events.
*
*/
VOID CALLBACK PluginManagerStateChangeCallback(
    _In_ PWINOBJEX_PLUGIN PluginData,
    _In_ WINOBJEX_PLUGIN_STATE NewState,
    _In_ PVOID Reserved)
{
    UNREFERENCED_PARAMETER(Reserved);

    __try {
        PluginData->State = NewState;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("StateChangeCallback exception %lx", GetExceptionCode());
    }
}

/*
* PluginManagerShowInitializationError
*
* Purpose:
*
* Output PluginInit error.
*
*/
VOID PluginManagerShowInitializationError(
    _In_ HWND ParentWindow,
    _In_ ULONG ErrorCode,
    _In_ LPWSTR FileName //limited to MAX_PATH as per WIN32_FIND_DATA
)
{
    WCHAR szMessage[1024];

    _strcpy(szMessage, TEXT("There is an error "));
    ultohex(ErrorCode, _strend(szMessage));
    _strcat(szMessage, TEXT(" while initializing plugin\r\n"));
    _strcat(szMessage, FileName);
    _strcat(szMessage, TEXT("\r\n\nThis plugin will be skipped."));
    MessageBox(ParentWindow, szMessage, NULL, MB_ICONERROR);
}

/*
* PluginManagerWorkerThread
*
* Purpose:
*
* Worker thread for building list of available plugins.
*
*/
DWORD WINAPI PluginManagerWorkerThread(
    _In_ PVOID Parameter
)
{
    BOOLEAN PluginInitialized;
    HWND MainWindow = (HWND)Parameter;
    BOOL MenuInitialized = FALSE;

    WCHAR szSearchDirectory[1024];
    WCHAR szPluginPath[1024];
    
    DWORD dwSize;

    SIZE_T Length;
    HANDLE hFile;
    WIN32_FIND_DATA fdata;

    HMENU hMainMenu = GetMenu(MainWindow), hPluginMenu = NULL;
    MENUITEMINFO MenuItem;

    WINOBJEX_PLUGIN_INTERNAL *PluginEntry;
    pfnPluginInit PluginInit;
    HMODULE hPlugin;

    InitializeListHead(&g_PluginsListHead);

    //
    // Query working directory.
    //
    RtlSecureZeroMemory(szSearchDirectory, sizeof(szSearchDirectory));
    dwSize = GetCurrentDirectory(MAX_PATH, szSearchDirectory);
    if ((dwSize == 0) || (dwSize > MAX_PATH))
        ExitThread((DWORD)-1);

    _strcat(szSearchDirectory, TEXT("\\plugins\\"));

    //
    // Build plugin path.
    //
    RtlSecureZeroMemory(szPluginPath, sizeof(szPluginPath));
    _strcpy(szPluginPath, szSearchDirectory);
    _strcat(szSearchDirectory, TEXT("*.dll"));

    Length = _strlen(szPluginPath);

    //
    // Look for dlls in the plugin subdirectory.
    //
    hFile = FindFirstFileEx(szSearchDirectory, FindExInfoBasic, &fdata, FindExSearchNameMatch, NULL, 0);
    if (hFile != INVALID_HANDLE_VALUE) {
        do {
            if (g_PluginCount >= WINOBJEX_MAX_PLUGINS)
                break;

            szPluginPath[Length] = 0;
            _strcat(szPluginPath, fdata.cFileName);

            //
            // Validate plugin dll.
            //
            if (!PluginManagerDllIsPlugin(szPluginPath)) {
                DbgPrint("Dll %ws is not a valid WinObjEx64 plugin\r\n", szPluginPath);
                continue;
            }

            //
            // Load library and query plugin export.
            //
            hPlugin = LoadLibraryEx(szPluginPath, NULL, 0);
            if (hPlugin) {
                PluginInit = (pfnPluginInit)GetProcAddress(hPlugin, WINOBJEX_PLUGIN_EXPORT);
                if (PluginInit) {

                    PluginEntry = (WINOBJEX_PLUGIN_INTERNAL*)supHeapAlloc(sizeof(WINOBJEX_PLUGIN_INTERNAL));
                    if (PluginEntry) {

                        //
                        // Initialize plugin and initialize main menu entry if not initialized.
                        //
                        __try {
                            PluginInitialized = PluginInit(&PluginEntry->Plugin);
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER) {
                            PluginManagerShowInitializationError(MainWindow, GetExceptionCode(), fdata.cFileName);
                            PluginInitialized = FALSE;
                        }

                        if (PluginInitialized) {

                            InsertHeadList(&g_PluginsListHead, &PluginEntry->ListEntry);
                            
                            //
                            // Set state change callback here.
                            //
                            PluginEntry->Plugin.StateChangeCallback = (pfnStateChangeCallback)&PluginManagerStateChangeCallback;
                            
                            //
                            // Remember plugin id.
                            //
                            PluginEntry->Id = g_PluginCount;
                            g_PluginCount += 1;

                            if (MenuInitialized == FALSE) {

                                hPluginMenu = CreatePopupMenu();
                                if (hPluginMenu) {

                                    RtlSecureZeroMemory(&MenuItem, sizeof(MenuItem));
                                    MenuItem.cbSize = sizeof(MenuItem);
                                    MenuItem.fMask = MIIM_SUBMENU | MIIM_STRING;
                                    MenuItem.dwTypeData = TEXT("Plugins");
                                    MenuItem.hSubMenu = hPluginMenu;

                                    MenuInitialized = InsertMenuItem(hMainMenu,
                                        GetMenuItemCount(hMainMenu) - 1,
                                        TRUE,
                                        &MenuItem);

                                    if (MenuInitialized)
                                        DrawMenuBar(MainWindow);

                                }
                            }

                            //
                            // Add menu entry.
                            //
                            if ((MenuInitialized) && (hPluginMenu)) {

                                RtlSecureZeroMemory(&MenuItem, sizeof(MenuItem));
                                MenuItem.cbSize = sizeof(MenuItem);
                                MenuItem.fMask = MIIM_STRING | MIIM_ID;
                                MenuItem.dwTypeData = PluginEntry->Plugin.Description;

                                //
                                // Associate menu entry id with plugin id for further searches.
                                //
                                MenuItem.wID = PluginEntry->Id;

                                InsertMenuItem(hPluginMenu,
                                    PluginEntry->Id,
                                    FALSE,
                                    &MenuItem);

                            }

                        }
                        else {
                            supHeapFree(PluginEntry);
                        }
                    }
                }
                else {
                    FreeLibrary(hPlugin);
                }
            }
        } while (FindNextFile(hFile, &fdata));
        FindClose(hFile);
    }

    ExitThread(0);
}

/*
* PluginManagerCreate
*
* Purpose:
*
* Create list of available plugins.
*
*/
VOID PluginManagerCreate(
    _In_ HWND MainWindow
)
{
    DWORD ThreadId;

    HANDLE hThread = CreateThread(NULL,
        0,
        (LPTHREAD_START_ROUTINE)PluginManagerWorkerThread,
        (PVOID)MainWindow,
        0,
        &ThreadId);

    if (hThread) CloseHandle(hThread);
}

/*
* PluginManagerDestroy
*
* Purpose:
*
* Destroy list of available plugins.
*
*/
VOID PluginManagerDestroy()
{
    PLIST_ENTRY Head, Next;
    WINOBJEX_PLUGIN_INTERNAL *PluginEntry;

    Head = &g_PluginsListHead;
    Next = Head->Flink;
    while ((Next != NULL) && (Next != Head)) {
        PluginEntry = CONTAINING_RECORD(Next, WINOBJEX_PLUGIN_INTERNAL, ListEntry);
        Next = Next->Flink;

        __try {
            PluginEntry->Plugin.StopPlugin();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            ;
        }
        supHeapFree(PluginEntry);
    }
}

/*
* PluginManagerGetEntryById
*
* Purpose:
*
* Lookup entry in plugins list by plugin id.
*
*/
WINOBJEX_PLUGIN_INTERNAL *PluginManagerGetEntryById(
    _In_ UINT Id
)
{
    PLIST_ENTRY Head, Next;
    WINOBJEX_PLUGIN_INTERNAL *PluginEntry;

    Head = &g_PluginsListHead;
    Next = Head->Flink;
    while ((Next != NULL) && (Next != Head)) {
        PluginEntry = CONTAINING_RECORD(Next, WINOBJEX_PLUGIN_INTERNAL, ListEntry);
        if (PluginEntry->Id == Id) {
            return PluginEntry;
        }
        Next = Next->Flink;
    }

    return NULL;
}

/*
* PluginManagerProcessEntry
*
* Purpose:
*
* Execute plugin code by plugin id.
*
*/
VOID PluginManagerProcessEntry(
    _In_ HWND ParentWindow,
    _In_ UINT Id
)
{
    NTSTATUS Status;
    WINOBJEX_PLUGIN_INTERNAL *PluginEntry;

    WINOBJEX_PARAM_BLOCK ParamBlock;

    WCHAR szMessage[200];

    __try {
        PluginEntry = PluginManagerGetEntryById(Id);
        if (PluginEntry) {

            if (PluginEntry->Plugin.State == PluginRunning) {

                _strcpy(szMessage, TEXT("The following plugin \""));
                _strcat(szMessage, PluginEntry->Plugin.Description);
                _strcat(szMessage, TEXT("\" reports it is already running.\r\n\nRestart it?"));

                if (MessageBox(ParentWindow,
                    szMessage,
                    PROGRAM_NAME,
                    MB_ICONQUESTION | MB_YESNO) == IDYES)
                {
                    //
                    // Force restart plugin.
                    //
                    __try {
                        PluginEntry->Plugin.StopPlugin();
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        _strcpy(szMessage, TEXT("There is an error during plugin stop, code = "));
                        ultohex(GetExceptionCode(), _strend(szMessage));
                        MessageBox(ParentWindow, szMessage, NULL, MB_ICONERROR);
                    }
                }
                else {
                    //
                    // Restart option not selected, leave.
                    //
                    return;
                }
            }

            //
            // Check plugin requirements.
            //

            if (g_WinObj.IsWine && PluginEntry->Plugin.SupportWine == FALSE) {
                MessageBox(ParentWindow, TEXT("This plugin does not support Wine"), PROGRAM_NAME, MB_ICONINFORMATION);
                return;
            }

            if (PluginEntry->Plugin.NeedAdmin && g_kdctx.IsFullAdmin == FALSE) {
                MessageBox(ParentWindow, TEXT("This plugin require administrator privileges"), PROGRAM_NAME, MB_ICONINFORMATION);
                return;
            }

            if (PluginEntry->Plugin.NeedDriver && g_kdctx.drvOpenLoadStatus != ERROR_SUCCESS) {
                MessageBox(ParentWindow, TEXT("This plugin require driver usage to run"), PROGRAM_NAME, MB_ICONINFORMATION);
                return;
            }
            
            RtlSecureZeroMemory(&ParamBlock, sizeof(ParamBlock));
            ParamBlock.ParentWindow = ParentWindow;
            ParamBlock.hInstance = g_WinObj.hInstance;
            ParamBlock.SystemRangeStart = g_kdctx.SystemRangeStart;

            //
            // Function pointers.
            // 
            // System
            //
            ParamBlock.GetSystemInfoEx = (pfnGetSystemInfoEx)&supGetSystemInfoEx;
            ParamBlock.ReadSystemMemoryEx = (pfnReadSystemMemoryEx)&kdReadSystemMemoryEx;
            ParamBlock.GetInstructionLength = (pfnGetInstructionLength)&kdGetInstructionLength;
            ParamBlock.FindModuleEntryByName = (pfnFindModuleEntryByName)&supFindModuleEntryByName;
            ParamBlock.FindModuleEntryByAddress = (pfnFindModuleEntryByAddress)&supFindModuleEntryByAddress;
            ParamBlock.FindModuleNameByAddress = (pfnFindModuleNameByAddress)&supFindModuleNameByAddress;
            ParamBlock.GetWin32FileName = (pfnGetWin32FileName)&supGetWin32FileName;

            //
            // UI related functions.
            //
            ParamBlock.uiGetMaxCompareTwoFixedStrings = (pfnuiGetMaxCompareTwoFixedStrings)&supGetMaxCompareTwoFixedStrings;
            ParamBlock.uiGetMaxOfTwoU64FromHex = (pfnuiGetMaxOfTwoU64FromHex)&supGetMaxOfTwoU64FromHex;
            ParamBlock.uiCopyTreeListSubItemValue = (pfnuiCopyTreeListSubItemValue)&supCopyTreeListSubItemValue;
            ParamBlock.uiCopyListViewSubItemValue = (pfnuiCopyListViewSubItemValue)&supCopyListViewSubItemValue;
            ParamBlock.uiShowFileProperties = (pfnuiShowFileProperties)&supShowProperties;
            ParamBlock.uiGetDPIValue = (pfnuiGetDPIValue)&supGetDPIValue;

            RtlCopyMemory(&ParamBlock.osver, &g_WinObj.osver, sizeof(RTL_OSVERSIONINFOW));

            Status = PluginEntry->Plugin.StartPlugin(&ParamBlock);

            if (!NT_SUCCESS(Status)) {
                _strcpy(szMessage, TEXT("Could not start plugin, error code 0x"));
                ultohex((ULONG)Status, _strend(szMessage));
                MessageBox(ParentWindow, szMessage, NULL, MB_ICONERROR);
            }

        }

    }
    __except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
        return;
    }
}
