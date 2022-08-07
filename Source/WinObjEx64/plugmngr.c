/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2022
*
*  TITLE:       PLUGMNGR.C
*
*  VERSION:     2.00
*
*  DATE:        07 Aug 2022
*
*  Plugin manager.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#define OEMRESOURCE
#include "global.h"

static LIST_ENTRY g_PluginsListHead;
volatile UINT g_PluginCount = 0;

static HANDLE PmDlgThreadHandle = NULL;
static FAST_EVENT PmDlgInitializedEvent = FAST_EVENT_INIT;

/*
* PmpReadSystemMemoryEx
*
* Purpose:
*
* Read system memory function wrapper for plugins.
*
*/
BOOL PmpReadSystemMemoryEx(
    _In_ ULONG_PTR Address,
    _Inout_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG NumberOfBytesRead
)
{
    return kdReadSystemMemory2(NULL, Address, Buffer, BufferSize, NumberOfBytesRead);
}

/*
* PmpOpenObjectByType
*
* Purpose:
*
* Open object by type (plugin version).
*
*/
NTSTATUS PmpOpenObjectByType(
    _Out_ HANDLE* ObjectHandle,
    _In_ ULONG TypeIndex,
    _In_ PUNICODE_STRING ObjectDirectory,
    _In_ PUNICODE_STRING ObjectName,
    _In_ ACCESS_MASK DesiredAccess
)
{
    __try {
        return supOpenNamedObjectByType(ObjectHandle,
            TypeIndex,
            ObjectDirectory,
            ObjectName,
            DesiredAccess);
    }
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
        return GetExceptionCode();
    }
}

/*
* PmpReportInvalidPlugin
*
* Purpose:
*
* Log invalid plugin load attempt.
*
*/
VOID PmpReportInvalidPlugin(
    _In_ LPWSTR lpszPluginFileName
)
{
    LPWSTR lpCombined;
    SIZE_T cbSize;

    cbSize = (MAX_PATH + _strlen(lpszPluginFileName)) * sizeof(WCHAR);

    lpCombined = (LPWSTR)supHeapAlloc(cbSize);
    if (lpCombined) {
        _strcpy(lpCombined, TEXT("File "));
        _strcat(lpCombined, lpszPluginFileName);
        _strcat(lpCombined, TEXT(" is not a valid WinObjEx64 plugin"));
        logAdd(EntryTypeInformation, lpCombined);
        supHeapFree(lpCombined);
    }
}

/*
* PmpIsValidPlugin
*
* Purpose:
*
* Validate plugin by version info description.
*
*/
BOOL PmpIsValidPlugin(
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

#pragma warning(push)
#pragma warning(disable: 6388) //disable warning regarding reserved parameter
            if (GetFileVersionInfoEx(0, lpszPluginName, dwHandle, dwSize, versionInfo)) {
#pragma warning(pop)

                dwSize = 0;

                if (VerQueryValue(
                    versionInfo,
                    T_VERSION_TRANSLATION,
                    (LPVOID*)&lpTranslate,
                    (PUINT)&dwSize))
                {

                    RtlStringCchPrintfSecure(
                        szBuffer,
                        MAX_PATH,
                        FORMAT_VERSION_DESCRIPTION,
                        lpTranslate[0].wLanguage,
                        lpTranslate[0].wCodePage);

                    lpFileDescription = NULL;
                    dwSize = 0;

                    if (VerQueryValue(
                        versionInfo,
                        szBuffer,
                        (LPVOID*)&lpFileDescription,
                        (PUINT)&dwSize))
                    {
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
* PmpStateChangeCallback
*
* Purpose:
*
* Callback to be called by plugins on state change events.
*
*/
VOID CALLBACK PmpStateChangeCallback(
    _In_ PWINOBJEX_PLUGIN PluginData,
    _In_ WINOBJEX_PLUGIN_STATE NewState,
    _Reserved_ PVOID Reserved)
{
    UNREFERENCED_PARAMETER(Reserved);

    __try {
        PluginData->State = NewState;
    }
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
        return;
    }
}

/*
* PmGuiShutdownCallback
*
* Purpose:
*
* Callback to be called by plugins uppon gui shutdown.
*
*/
VOID CALLBACK PmGuiShutdownCallback(
    _In_ WINOBJEX_PLUGIN* PluginData,
    _In_ HINSTANCE PluginInstance,
    _Reserved_ PVOID Reserved
)
{
    UNREFERENCED_PARAMETER(Reserved);

    WCHAR szClassName[100];

    RtlStringCchPrintfSecure(szClassName,
        RTL_NUMBER_OF(szClassName),
        TEXT("%wsWndClass"),
        PluginData->Name);

    UnregisterClass(szClassName, PluginInstance);
}

/*
* PmGuiInitCallback
*
* Purpose:
*
* Callback to be called by plugins uppon gui initialization.
*
*/
BOOL CALLBACK PmGuiInitCallback(
    _In_ WINOBJEX_PLUGIN* PluginData,
    _In_ HINSTANCE PluginInstance,
    _In_ WNDPROC WndProc,
    _Reserved_ PVOID Reserved
)
{
    ATOM classAtom;
    DWORD dwLastError;
    WNDCLASSEX  wincls;
    WCHAR szClassName[MAX_PLUGIN_NAME + sizeof(L"WndClass") + 1];

    UNREFERENCED_PARAMETER(Reserved);

    __try {

        RtlSecureZeroMemory(&szClassName, sizeof(szClassName));

        //
        // Register window class once.
        //
        RtlStringCchPrintfSecure(szClassName,
            RTL_NUMBER_OF(szClassName),
            TEXT("%wsWndClass"),
            PluginData->Name);

        RtlSecureZeroMemory(&wincls, sizeof(wincls));
        wincls.cbSize = sizeof(WNDCLASSEX);
        wincls.lpfnWndProc = WndProc;
        wincls.hInstance = PluginInstance;
        wincls.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wincls.lpszClassName = szClassName;

        wincls.hCursor = (HCURSOR)LoadImage(NULL,
            MAKEINTRESOURCE(OCR_SIZENS),
            IMAGE_CURSOR,
            0,
            0,
            LR_SHARED);

        wincls.hIcon = (HICON)LoadImage(
            g_WinObj.hInstance,
            MAKEINTRESOURCE(IDI_ICON_MAIN),
            IMAGE_ICON,
            0,
            0,
            LR_SHARED);

        classAtom = RegisterClassEx(&wincls);
        dwLastError = GetLastError();

        if ((classAtom == 0) && (dwLastError != ERROR_CLASS_ALREADY_EXISTS))
            kdDebugPrint("Could not register window class, err = %lu\r\n", dwLastError);

    }
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
        return FALSE;
    }

    return TRUE;
}

/*
* PmpShowInitializationError
*
* Purpose:
*
* Output PluginInit error.
*
*/
VOID PmpShowInitializationError(
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
* PmpWorkerThread
*
* Purpose:
*
* Worker thread for building list of available plugins.
*
*/
DWORD WINAPI PmpWorkerThread(
    _In_ PVOID Parameter
)
{
    BOOLEAN PluginInitialized;
    HWND ParentWindow = (HWND)Parameter;
    BOOL MenuInitialized = FALSE;

    WCHAR szSearchDirectory[1024];
    WCHAR szPluginPath[1024];

    DWORD dwSize;

    SIZE_T Length;
    HANDLE hFile;
    WIN32_FIND_DATA fdata;

    INT cMenu;
    HMENU hMainMenu = GetMenu(ParentWindow), hPluginMenu = NULL, hMenuFile;
    MENUITEMINFO MenuItem;

    WINOBJEX_PLUGIN_INTERNAL* PluginEntry;
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
            if (!PmpIsValidPlugin(szPluginPath)) {
                PmpReportInvalidPlugin(szPluginPath);
                continue;
            }

            //
            // Load library and query plugin export.
            //
            hPlugin = LoadLibraryEx(szPluginPath, NULL, 0);
            if (hPlugin) {

                PluginInit = (pfnPluginInit)GetProcAddress(hPlugin, WINOBJEX_PLUGIN_EXPORT);
                if (PluginInit == NULL) {
                    FreeLibrary(hPlugin);
                }
                else {

                    PluginEntry = (WINOBJEX_PLUGIN_INTERNAL*)supHeapAlloc(sizeof(WINOBJEX_PLUGIN_INTERNAL));
                    if (PluginEntry) {

                        //
                        // Initialize plugin and initialize main menu entry if not initialized.
                        //
                        __try {
                            PluginInitialized = PluginInit(&PluginEntry->Plugin);
                        }
                        __except (WOBJ_EXCEPTION_FILTER_LOG) {
                            PmpShowInitializationError(ParentWindow, GetExceptionCode(), fdata.cFileName);
                            PluginInitialized = FALSE;
                        }

                        if (PluginInitialized) {

                            InsertHeadList(&g_PluginsListHead, &PluginEntry->ListEntry);

                            //
                            // Set callbacks here.
                            //
                            PluginEntry->Plugin.StateChangeCallback = (pfnStateChangeCallback)&PmpStateChangeCallback;
                            PluginEntry->Plugin.GuiInitCallback = (pfnGuiInitCallback)&PmGuiInitCallback;
                            PluginEntry->Plugin.GuiShutdownCallback = (pfnGuiShutdownCallback)&PmGuiShutdownCallback;

                            //
                            // Remember plugin id.
                            //
                            PluginEntry->Id = ID_MENU_PLUGINS + g_PluginCount;
                            g_PluginCount += 1;

                            PluginEntry->Module = hPlugin;

                            //
                            // List general purpose plugins.
                            //
                            if (PluginEntry->Plugin.Type == DefaultPlugin) {

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
                                            DrawMenuBar(ParentWindow);

                                    }
                                }

                                //
                                // Add menu entry.
                                //
                                if ((MenuInitialized) && (hPluginMenu)) {

                                    RtlSecureZeroMemory(&MenuItem, sizeof(MenuItem));
                                    MenuItem.cbSize = sizeof(MenuItem);
                                    MenuItem.fMask = MIIM_STRING | MIIM_ID;
                                    MenuItem.dwTypeData = PluginEntry->Plugin.Name;

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
                        } // if PluginInitialized
                        else {
                            supHeapFree(PluginEntry);
                            FreeLibrary(hPlugin);
                        }
                    } //if PluginEntry
                    else {
                        FreeLibrary(hPlugin);
                    }
                }

            }

        } while (FindNextFile(hFile, &fdata));
        FindClose(hFile);
    }

    //
    // Must be called after plugin manager startup as plugins are not signed by MS.
    //
    supSetProcessMitigationImagesPolicy();

    if (g_PluginCount) {
        hMenuFile = GetSubMenu(hMainMenu, IDMM_FILE);
        if (hMenuFile) {
            cMenu = GetMenuItemCount(hMenuFile);
            InsertMenu(hMenuFile, cMenu - 1, MF_BYPOSITION, ID_FILE_VIEW_PLUGINS, T_VIEW_PLUGINS);
            InsertMenu(hMenuFile, cMenu, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
        }
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
VOID PmCreate(
    _In_ HWND ParentWindow
)
{
    HANDLE hThread = supCreateThread(
        (LPTHREAD_START_ROUTINE)PmpWorkerThread,
        (PVOID)ParentWindow,
        0);

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
VOID PmDestroy()
{
    PLIST_ENTRY Head, Next;
    WINOBJEX_PLUGIN_INTERNAL* PluginEntry;

    Head = &g_PluginsListHead;

    ASSERT_LIST_ENTRY_VALID(Head);
    if (IsListEmpty(Head))
        return;

    Next = Head->Flink;
    while ((Next != NULL) && (Next != Head)) {
        PluginEntry = CONTAINING_RECORD(Next, WINOBJEX_PLUGIN_INTERNAL, ListEntry);
        Next = Next->Flink;

        __try {
            if (PluginEntry->Plugin.StopPlugin)
                PluginEntry->Plugin.StopPlugin();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            ;
        }
        supHeapFree(PluginEntry);
    }
}

/*
* PmpGetEntryById
*
* Purpose:
*
* Lookup entry in plugins list by plugin id.
*
*/
WINOBJEX_PLUGIN_INTERNAL* PmpGetEntryById(
    _In_ UINT Id
)
{
    PLIST_ENTRY Head, Next;
    WINOBJEX_PLUGIN_INTERNAL* PluginEntry;

    Head = &g_PluginsListHead;

    ASSERT_LIST_ENTRY_VALID_ERROR_X(Head, NULL);
    if (IsListEmpty(Head))
        return NULL;

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
* PmpFreeObjectData
*
* Purpose:
*
* Free plugin object data.
*
*/
VOID PmpFreeObjectData(
    _In_ PWINOBJEX_PARAM_OBJECT ParamObject
)
{
    supFreeDuplicatedUnicodeString(g_obexHeap, &ParamObject->Directory, FALSE);
    supFreeDuplicatedUnicodeString(g_obexHeap, &ParamObject->Name, FALSE);
}

/*
* PmpAllocateObjectData
*
* Purpose:
*
* Allocate fields of plugin object and copy current object data.
*
*/
BOOL PmpAllocateObjectData(
    _In_ PWINOBJEX_PARAM_OBJECT ParamObject
)
{
    return supGetCurrentObjectPath(FALSE, &ParamObject->Directory) && 
        supGetCurrentObjectName(&ParamObject->Name);
}

/*
* PmProcessEntry
*
* Purpose:
*
* Handler for plugins activation.
*
*/
VOID PmProcessEntry(
    _In_ HWND ParentWindow,
    _In_ UINT Id
)
{
    NTSTATUS ntStatus;
    WINOBJEX_PLUGIN_INTERNAL* PluginEntry;

    WINOBJEX_PARAM_BLOCK ParamBlock;

    WCHAR szMessage[MAX_PATH];

    __try {
        PluginEntry = PmpGetEntryById(Id);
        if (PluginEntry) {

            if ((PluginEntry->Plugin.StartPlugin == NULL) ||
                (PluginEntry->Plugin.StopPlugin == NULL))
                return;

            if (!PluginEntry->Plugin.SupportMultipleInstances) {
                if (PluginEntry->Plugin.State == PluginRunning) {

                    _strcpy(szMessage, TEXT("The following plugin \""));
                    _strcat(szMessage, PluginEntry->Plugin.Name);
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
            }

            //
            // Check plugin requirements.
            //

            if (g_WinObj.IsWine && PluginEntry->Plugin.SupportWine == FALSE) {
                
                MessageBox(ParentWindow, 
                    TEXT("This plugin does not support Wine"), 
                    PROGRAM_NAME, MB_ICONINFORMATION);

                return;
            }

            if (PluginEntry->Plugin.NeedAdmin && g_kdctx.IsFullAdmin == FALSE) {
                
                MessageBox(ParentWindow, 
                    TEXT("This plugin requires administrator privileges and cannot be run.\n\nIf your account is in an Administrator group make sure you run WinObjEx64 elevated."), 
                    PROGRAM_NAME, MB_ICONINFORMATION);

                return;
            }

            if (PluginEntry->Plugin.NeedDriver && kdIoDriverLoaded() == FALSE) {
                
                MessageBox(ParentWindow, 
                    TEXT("This plugin requires driver usage to run"), 
                    PROGRAM_NAME, MB_ICONINFORMATION);

                return;
            }

            RtlSecureZeroMemory(&ParamBlock, sizeof(ParamBlock));

            //
            // Copy selected object data to plugin object.
            //
            if (PluginEntry->Plugin.Type == ContextPlugin) {

                if (!PmpAllocateObjectData(&ParamBlock.Object)) {
                    
                    MessageBox(ParentWindow, 
                        TEXT("Cannot allocate memory for plugin data"), 
                        PROGRAM_NAME, MB_ICONERROR);
                    
                    return;
                }
            }

            ParamBlock.ParentWindow = ParentWindow;
            ParamBlock.Instance = g_WinObj.hInstance;
            ParamBlock.SystemRangeStart = g_kdctx.SystemRangeStart;
            ParamBlock.CurrentDPI = g_WinObj.CurrentDPI;

            //
            // Function pointers.
            // 
            ParamBlock.ReadSystemMemoryEx = (pfnReadSystemMemoryEx)&PmpReadSystemMemoryEx;
            ParamBlock.GetInstructionLength = (pfnGetInstructionLength)&kdGetInstructionLength;
            ParamBlock.OpenNamedObjectByType = (pfnOpenNamedObjectByType)&PmpOpenObjectByType;

            //
            // Version.
            //
            ParamBlock.Version = g_WinObj.osver;

            ntStatus = PluginEntry->Plugin.StartPlugin(&ParamBlock);

            if (!NT_SUCCESS(ntStatus)) {
                _strcpy(szMessage, TEXT("Could not start plugin, error code 0x"));
                ultohex((ULONG)ntStatus, _strend(szMessage));
                MessageBox(ParentWindow, szMessage, NULL, MB_ICONERROR);
            }

            if (PluginEntry->Plugin.Type == ContextPlugin) {
                PmpFreeObjectData(&ParamBlock.Object);
            }

        }

    }
    __except (WOBJ_EXCEPTION_FILTER) {
        return;
    }
}

/*
* PmpIsSupportedObject
*
* Purpose:
*
* Return TRUE if the given object type is supported by plugin.
*
*/
BOOLEAN PmpIsSupportedObject(
    _In_ WINOBJEX_PLUGIN* Plugin,
    _In_ UCHAR ObjectType
)
{
    UCHAR i;

    if (Plugin->SupportedObjectsIds[0] == ObjectTypeAnyType)
        return TRUE;

    for (i = 0; i < PLUGIN_MAX_SUPPORTED_OBJECT_ID; i++)
        if (Plugin->SupportedObjectsIds[i] != ObjectTypeNone)
            if (Plugin->SupportedObjectsIds[i] == ObjectType)
                return TRUE;

    return FALSE;
}

/*
* PmBuildPluginPopupMenuByObjectType
*
* Purpose:
*
* Builds popup menu with plugins dedicated for currently selected object type.
*
*/
VOID PmBuildPluginPopupMenuByObjectType(
    _In_ HMENU ContextMenu,
    _In_ UCHAR ObjectType)
{
    BOOL bInitOk = FALSE;
    PLIST_ENTRY ptrHead, ptrNext;
    WINOBJEX_PLUGIN_INTERNAL* pluginEntry;
    MENUITEMINFO menuItem;

    ptrHead = &g_PluginsListHead;
    ptrNext = ptrHead->Flink;
    while ((ptrNext != NULL) && (ptrNext != ptrHead)) {
        pluginEntry = CONTAINING_RECORD(ptrNext, WINOBJEX_PLUGIN_INTERNAL, ListEntry);
        if (pluginEntry->Plugin.Type == ContextPlugin) {
            if (PmpIsSupportedObject(&pluginEntry->Plugin, ObjectType)) {

                //
                // Insert separator.
                //
                if (bInitOk == FALSE) {
                    RtlSecureZeroMemory(&menuItem, sizeof(menuItem));
                    menuItem.cbSize = sizeof(menuItem);
                    menuItem.fType = MFT_SEPARATOR;
                    menuItem.fMask = MIIM_TYPE;

                    bInitOk = InsertMenuItem(ContextMenu,
                        GetMenuItemCount(ContextMenu),
                        TRUE,
                        &menuItem);
                }

                RtlSecureZeroMemory(&menuItem, sizeof(menuItem));
                menuItem.cbSize = sizeof(menuItem);
                menuItem.fMask = MIIM_STRING | MIIM_ID;
                menuItem.dwTypeData = pluginEntry->Plugin.Name;

                //
                // Associate menu entry id with plugin id for further searches.
                //
                menuItem.wID = pluginEntry->Id;

                InsertMenuItem(ContextMenu,
                    pluginEntry->Id,
                    FALSE,
                    &menuItem);

            }
        }
        ptrNext = ptrNext->Flink;
    }

}

/*
* PmpEnumerateEntries
*
* Purpose:
*
* Fill listview with loaded plugins.
*
*/
VOID PmpEnumerateEntries(
    _In_ HWND hwndDlg)
{
    HWND ListView = GetDlgItem(hwndDlg, IDC_PLUGINLIST);
    PLIST_ENTRY Head, Next;
    WINOBJEX_PLUGIN_INTERNAL* PluginEntry;
    LPWSTR lpType;

    LVITEM  lvItem;
    INT lvItemIndex;
    WCHAR szBuffer[100];

    LVCOLUMNS_DATA columnData[] =
    {
        { L"Name", 200, LVCFMT_LEFT,  I_IMAGENONE },
        { L"Authors", 80, LVCFMT_CENTER,  I_IMAGENONE },
        { L"Type", 80, LVCFMT_CENTER,  I_IMAGENONE },
        { L"Version", 80, LVCFMT_CENTER,  I_IMAGENONE }
    };

    supSetListViewSettings(ListView,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP,
        FALSE,
        TRUE,
        NULL,
        0);

    supAddLVColumnsFromArray(
        ListView,
        columnData,
        RTL_NUMBER_OF(columnData));

    Head = &g_PluginsListHead;
    Next = Head->Flink;
    while ((Next != NULL) && (Next != Head)) {

        PluginEntry = CONTAINING_RECORD(Next, WINOBJEX_PLUGIN_INTERNAL, ListEntry);

        RtlSecureZeroMemory(&lvItem, sizeof(lvItem));
        lvItem.mask = LVIF_TEXT | LVIF_PARAM;
        lvItem.pszText = PluginEntry->Plugin.Name;
        lvItem.iItem = MAXINT;
        lvItem.lParam = (LPARAM)PluginEntry;
        lvItemIndex = ListView_InsertItem(ListView, &lvItem);

        lvItem.mask = LVIF_TEXT;
        lvItem.iSubItem = 1;
        lvItem.pszText = PluginEntry->Plugin.Authors;
        lvItem.iItem = lvItemIndex;
        ListView_SetItem(ListView, &lvItem);

        if (PluginEntry->Plugin.Type == DefaultPlugin)
            lpType = TEXT("Default");
        else if (PluginEntry->Plugin.Type == ContextPlugin)
            lpType = TEXT("Context");
        else
            lpType = T_UnknownType;

        lvItem.mask = LVIF_TEXT;
        lvItem.iSubItem = 2;
        lvItem.pszText = lpType;
        lvItem.iItem = lvItemIndex;
        ListView_SetItem(ListView, &lvItem);

        RtlStringCchPrintfSecure(szBuffer,
            100,
            TEXT("%lu.%lu"),
            PluginEntry->Plugin.MajorVersion,
            PluginEntry->Plugin.MinorVersion);

        lvItem.mask = LVIF_TEXT;
        lvItem.iSubItem = 3;
        lvItem.pszText = szBuffer;
        lvItem.iItem = lvItemIndex;
        ListView_SetItem(ListView, &lvItem);

        Next = Next->Flink;
    }
    SetFocus(GetDlgItem(hwndDlg, IDCANCEL));
}

/*
* PmpListSupportedObjectTypes
*
* Purpose:
*
* List plugin supported object types.
*
*/
VOID PmpListSupportedObjectTypes(
    _In_ HWND hwndCB,
    _In_ PWINOBJEX_PLUGIN Plugin
)
{
    UCHAR i;
    LPWSTR lpObjectType;

    if (Plugin->SupportedObjectsIds[0] == ObjectTypeAnyType) {
        lpObjectType = TEXT("Any");
        SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)lpObjectType);
    }
    else {

        for (i = 0; i < PLUGIN_MAX_SUPPORTED_OBJECT_ID; i++)
            if (Plugin->SupportedObjectsIds[i] != ObjectTypeNone) {
                lpObjectType = ObManagerGetNameByIndex((WOBJ_OBJECT_TYPE)Plugin->SupportedObjectsIds[i]);
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)lpObjectType);
            }

    }
}

/*
* PmpShowPluginInfo
*
* Purpose:
*
* Show selected plugin information.
*
*/
VOID PmpShowPluginInfo(
    _In_ HWND hwndDlg,
    _In_ HWND hwndListView,
    _In_ INT itemIndex
)
{
    PWINOBJEX_PLUGIN_INTERNAL PluginData = NULL;
    LPWSTR lpType;
    HWND hwndCB;
    INT nCount;

    WCHAR szModuleName[MAX_PATH + 1];

    if (!supGetListViewItemParam(hwndListView,
        itemIndex,
        (PVOID*)&PluginData))
    {
        return;
    }

    hwndCB = GetDlgItem(hwndDlg, IDC_PLUGIN_OBJECTTYPE);
    SendMessage(hwndCB, CB_RESETCONTENT, (WPARAM)0, (LPARAM)0);

    if (PluginData->Plugin.NeedAdmin)
        lpType = TEXT("Yes");
    else
        lpType = TEXT("No");

    SetDlgItemText(hwndDlg, IDC_PLUGIN_ADMIN, lpType);

    if (PluginData->Plugin.NeedDriver)
        lpType = TEXT("Yes");
    else
        lpType = TEXT("No");

    SetDlgItemText(hwndDlg, IDC_PLUGIN_DRIVER, lpType);

    if (PluginData->Plugin.SupportWine)
        lpType = TEXT("Yes");
    else
        lpType = TEXT("No");

    SetDlgItemText(hwndDlg, IDC_PLUGIN_WINE, lpType);

    if (PluginData->Plugin.SupportMultipleInstances)
        lpType = TEXT("Yes");
    else
        lpType = TEXT("No");

    SetDlgItemText(hwndDlg, IDC_PLUGIN_MINSTANCES, lpType);

    SetDlgItemText(hwndDlg, IDC_PLUGIN_DESC, PluginData->Plugin.Description);

    if (PluginData->Plugin.Type == ContextPlugin) {
        PmpListSupportedObjectTypes(hwndCB, &PluginData->Plugin);
    }

    nCount = (INT)SendMessage(hwndCB, CB_GETCOUNT, 0, 0);
    EnableWindow(hwndCB, (nCount > 0) ? TRUE : FALSE);
    SendMessage(hwndCB, CB_SETCURSEL, (WPARAM)0, (LPARAM)0);

    RtlSecureZeroMemory(szModuleName, sizeof(szModuleName));
    GetModuleFileName(PluginData->Module, (LPWSTR)&szModuleName, MAX_PATH);
    SetDlgItemText(hwndDlg, IDC_PLUGIN_FILENAME, szModuleName);
}

/*
* PmpHandleNotify
*
* Purpose:
*
* Plugin Manager dialog WM_NOTIFY handler.
*
*/
VOID PmpHandleNotify(
    _In_ HWND hwndDlg,
    _In_ LPARAM lParam
)
{
    LPNMLISTVIEW pListView = (LPNMLISTVIEW)lParam;


    if (pListView->hdr.idFrom != IDC_PLUGINLIST)
        return;

    switch (pListView->hdr.code) {

    case NM_CLICK:

        PmpShowPluginInfo(hwndDlg, 
            pListView->hdr.hwndFrom,
            pListView->iItem);

        break;

    case LVN_ITEMCHANGED:

        if ((pListView->uNewState & LVIS_SELECTED) &&
            !(pListView->uOldState & LVIS_SELECTED))
        {
            PmpShowPluginInfo(hwndDlg,
                pListView->hdr.hwndFrom,
                pListView->iItem);
        }

        break;

    }

}

/*
* PmpHandleSettingsChange
*
* Purpose:
*
* Handle global settings change.
*
*/
VOID PmpHandleSettingsChange(
    _In_ HWND hwndDlg
)
{
    DWORD lvExStyle;
    HWND hwndList = GetDlgItem(hwndDlg, IDC_PLUGINLIST);

    lvExStyle = ListView_GetExtendedListViewStyle(hwndList);
    if (g_WinObj.ListViewDisplayGrid)
        lvExStyle |= LVS_EX_GRIDLINES;
    else
        lvExStyle &= ~LVS_EX_GRIDLINES;

    ListView_SetExtendedListViewStyle(hwndList, lvExStyle);
}

/*
* PmpDialogProc
*
* Purpose:
*
* Plugin Manager Window dialog procedure.
*
*/
INT_PTR CALLBACK PmpDialogProc(
    _In_ HWND   hwndDlg,
    _In_ UINT   uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    if (uMsg == g_WinObj.SettingsChangeMessage) {
        PmpHandleSettingsChange(hwndDlg);
        return TRUE;
    }

    switch (uMsg) {

    case WM_INITDIALOG:
        supCenterWindowSpecifyParent(hwndDlg, g_hwndMain);
        PmpEnumerateEntries(hwndDlg);
        break;

    case WM_COMMAND:

        if (LOWORD(wParam) == IDCANCEL) {
            DestroyWindow(hwndDlg);
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    case WM_NOTIFY:
        PmpHandleNotify(hwndDlg, lParam);
        break;

    }

    return FALSE;
}

/*
* PmViewPluginsWorkerThread
*
* Purpose:
*
* Plugins view dialog worker thread.
*
*/
DWORD PmViewPluginsWorkerThread(
    _In_ PVOID Parameter
)
{
    BOOL bResult;
    MSG message;
    HWND hwndDlg;

    UNREFERENCED_PARAMETER(Parameter);

    hwndDlg = CreateDialogParam(g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_VIEWPLUGINS),
        0,
        &PmpDialogProc,
        0);

    supSetFastEvent(&PmDlgInitializedEvent);

    do {

        bResult = GetMessage(&message, NULL, 0, 0);
        if (bResult == -1)
            break;

        if (!IsDialogMessage(hwndDlg, &message)) {
            TranslateMessage(&message);
            DispatchMessage(&message);
        }

    } while (bResult != 0);

    supResetFastEvent(&PmDlgInitializedEvent);

    if (PmDlgThreadHandle) {
        NtClose(PmDlgThreadHandle);
        PmDlgThreadHandle = NULL;
    }

    return 0;
}

/*
* PmViewPlugins
*
* Purpose:
*
* Show plugins view dialog.
*
*/
VOID PmViewPlugins(
    VOID
)
{
    if (!PmDlgThreadHandle) {

        PmDlgThreadHandle = supCreateDialogWorkerThread(PmViewPluginsWorkerThread, NULL, 0);
        supWaitForFastEvent(&PmDlgInitializedEvent, NULL);

    }
}
