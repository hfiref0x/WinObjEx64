/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2023
*
*  TITLE:       EXTRASUSD.C
*
*  VERSION:     2.02
*
*  DATE:        15 May 2023
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "props.h"
#include "extras.h"
#include "treelist/treelist.h"

static EXTRASCONTEXT g_UsdDlgContext;
static HANDLE UsdDlgThreadHandle = NULL;
static FAST_EVENT UsdDlgInitializedEvent = FAST_EVENT_INIT;

LPWSTR T_PROCESSOR_FEATURES[] = {
    L"PF_FLOATING_POINT_PRECISION_ERRATA",
    L"PF_FLOATING_POINT_EMULATED",
    L"PF_COMPARE_EXCHANGE_DOUBLE",
    L"PF_MMX_INSTRUCTIONS_AVAILABLE",
    L"PF_PPC_MOVEMEM_64BIT_OK",
    L"PF_ALPHA_BYTE_INSTRUCTIONS",
    L"PF_XMMI_INSTRUCTIONS_AVAILABLE",
    L"PF_3DNOW_INSTRUCTIONS_AVAILABLE",
    L"PF_RDTSC_INSTRUCTION_AVAILABLE",
    L"PF_PAE_ENABLED",
    L"PF_XMMI64_INSTRUCTIONS_AVAILABLE",
    L"PF_SSE_DAZ_MODE_AVAILABLE",
    L"PF_NX_ENABLED",
    L"PF_SSE3_INSTRUCTIONS_AVAILABLE",
    L"PF_COMPARE_EXCHANGE128",
    L"PF_COMPARE64_EXCHANGE128",
    L"PF_CHANNELS_ENABLED",
    L"PF_XSAVE_ENABLED",
    L"PF_ARM_VFP_32_REGISTERS_AVAILABLE",
    L"PF_ARM_NEON_INSTRUCTIONS_AVAILABLE",
    L"PF_SECOND_LEVEL_ADDRESS_TRANSLATION",
    L"PF_VIRT_FIRMWARE_ENABLED",
    L"PF_RDWRFSGSBASE_AVAILABLE",
    L"PF_FASTFAIL_AVAILABLE",
    L"PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE",
    L"PF_ARM_64BIT_LOADSTORE_ATOMIC",
    L"PF_ARM_EXTERNAL_CACHE_AVAILABLE",
    L"PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE",
    L"PF_RDRAND_INSTRUCTION_AVAILABLE",
    L"PF_ARM_V8_INSTRUCTIONS_AVAILABLE",
    L"PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE",
    L"PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE",
    L"PF_RDTSCP_INSTRUCTION_AVAILABLE",
    L"PF_RDPID_INSTRUCTION_AVAILABLE",
    L"PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE",
    L"PF_MONITORX_INSTRUCTION_AVAILABLE",
    L"PF_SSSE3_INSTRUCTIONS_AVAILABLE",
    L"PF_SSE4_1_INSTRUCTIONS_AVAILABLE",
    L"PF_SSE4_2_INSTRUCTIONS_AVAILABLE",
    L"PF_AVX_INSTRUCTIONS_AVAILABLE",
    L"PF_AVX2_INSTRUCTIONS_AVAILABLE",
    L"PF_AVX512F_INSTRUCTIONS_AVAILABLE",
    L"PF_ERMS_AVAILABLE",
    L"PF_ARM_V82_DP_INSTRUCTIONS_AVAILABLE",
    L"PF_ARM_V83_JSCVT_INSTRUCTIONS_AVAILABLE"
};

LPCWSTR T_SharedDataFlagsW7[] = {
    L"DbgErrorPortPresent",
    L"DbgElevationEnabled",
    L"DbgVirtEnabled",
    L"DbgInstallerDetectEnabled",
    L"DbgSystemDllRelocated",
    L"DbgDynProcessorEnabled",
    L"DbgSEHValidationEnabled"
};

LPCWSTR T_SharedDataFlags[] = {
    L"DbgErrorPortPresent",
    L"DbgElevationEnabled",
    L"DbgVirtEnabled",
    L"DbgInstallerDetectEnabled",
    L"DbgLkgEnabled",
    L"DbgDynProcessorEnabled",
    L"DbgConsoleBrokerEnabled",
    L"DbgSecureBootEnabled",
    L"DbgMultiSessionSku",
    L"DbgMultiUsersInSessionSku",
    L"DbgStateSeparationEnabled"
};

VALUE_DESC SuiteMasks[] = {
    { L"ServerNT", VER_SERVER_NT },
    { L"WorkstationNT", VER_WORKSTATION_NT },
    { L"SmallBusiness", VER_SUITE_SMALLBUSINESS },
    { L"Enterprise", VER_SUITE_ENTERPRISE },
    { L"BackOffice", VER_SUITE_BACKOFFICE },
    { L"Communications", VER_SUITE_COMMUNICATIONS },
    { L"Terminal", VER_SUITE_TERMINAL },
    { L"SmallBussinessRestricted", VER_SUITE_SMALLBUSINESS_RESTRICTED },
    { L"EmbeddedNT", VER_SUITE_EMBEDDEDNT },
    { L"DataCenter", VER_SUITE_DATACENTER },
    { L"SingleUserTS", VER_SUITE_SINGLEUSERTS },
    { L"Personal", VER_SUITE_PERSONAL },
    { L"Blade", VER_SUITE_BLADE },
    { L"EmbeddedRestricted", VER_SUITE_EMBEDDED_RESTRICTED },
    { L"SecurityAppliance", VER_SUITE_SECURITY_APPLIANCE },
    { L"StorageServer", VER_SUITE_STORAGE_SERVER },
    { L"ComputeServer", VER_SUITE_COMPUTE_SERVER },
    { L"HomeServer", VER_SUITE_WH_SERVER },
    { L"MultiUserTS", VER_SUITE_MULTIUSERTS }
};


/*
* UsdDumpSharedRegion
*
* Purpose:
*
* Display dump of SharedData.
*
*/
VOID UsdDumpSharedRegion(
    _In_ HWND hwndParent
)
{
    BOOL                bAny = FALSE;
    UINT                i;
    DWORD               mask, cFlags;

    LPCWSTR* pvSharedFlagsDesc;

    HTREEITEM           h_tviRootItem, h_tviSubItem, h_tviLast = NULL;
    LPWSTR              lpType;
    TL_SUBITEMS_FIXED   subitems;
    TVITEMEX            itemex;
    WCHAR               szValue[MAX_PATH + 1];

    PKUSER_SHARED_DATA  pUserSharedData;


    do {

        pUserSharedData = (KUSER_SHARED_DATA* const)MM_SHARED_USER_DATA_VA;

        if (IsBadReadPtr(pUserSharedData, sizeof(KUSER_SHARED_DATA)))
            break;

        if (!supInitTreeListForDump(hwndParent, &g_UsdDlgContext.TreeList))
            break;

        //
        // KUSER_SHARED_DATA
        //

        h_tviRootItem = supTreeListAddItem(
            g_UsdDlgContext.TreeList,
            (HTREEITEM)NULL,
            TVIF_TEXT | TVIF_STATE,
            TVIS_EXPANDED,
            TVIS_EXPANDED,
            TEXT("KUSER_SHARED_DATA"),
            (PVOID)NULL);

        if (h_tviRootItem == NULL) {
            break;
        }

        //
        // NtSystemRoot
        //
        RtlSecureZeroMemory(&subitems, sizeof(subitems));
        subitems.Text[0] = pUserSharedData->NtSystemRoot;
        subitems.Count = 1;

        supTreeListAddItem(
            g_UsdDlgContext.TreeList,
            h_tviRootItem,
            TVIF_TEXT | TVIF_STATE,
            (UINT)0,
            (UINT)0,
            TEXT("NtSystemRoot"),
            &subitems);

        //
        // NtProductType
        //
        switch (pUserSharedData->NtProductType) {
        case NtProductWinNt:
            lpType = TEXT("NtProductWinNt");
            break;
        case NtProductLanManNt:
            lpType = TEXT("NtProductLanManNt");
            break;
        case NtProductServer:
            lpType = TEXT("NtProductServer");
            break;
        default:
            lpType = T_UnknownType;
            break;
        }

        propObDumpUlong(
            g_UsdDlgContext.TreeList,
            h_tviRootItem,
            TEXT("NtProductType"),
            lpType,
            pUserSharedData->NtProductType,
            FALSE,
            FALSE,
            (COLORREF)0,
            (COLORREF)0);

        propObDumpByte(
            g_UsdDlgContext.TreeList,
            h_tviRootItem,
            TEXT("ProductTypeIsValid"),
            (LPWSTR)NULL,
            pUserSharedData->ProductTypeIsValid,
            (COLORREF)0,
            (COLORREF)0,
            TRUE);

        //
        // NtMajorVersion
        //
        propObDumpUlong(
            g_UsdDlgContext.TreeList,
            h_tviRootItem,
            TEXT("NtMajorVersion"),
            (LPWSTR)NULL,
            pUserSharedData->NtMajorVersion,
            FALSE,
            FALSE,
            (COLORREF)0,
            (COLORREF)0);

        //
        // NtMinorVersion
        // 
        propObDumpUlong(
            g_UsdDlgContext.TreeList,
            h_tviRootItem,
            TEXT("NtMinorVersion"),
            (LPWSTR)NULL,
            pUserSharedData->NtMinorVersion,
            FALSE,
            FALSE,
            (COLORREF)0,
            (COLORREF)0);

        //
        // Prior to Windows 10 this field declared as reserved.
        //
        if (g_NtBuildNumber >= NT_WIN10_THRESHOLD1) {
            propObDumpUlong(
                g_UsdDlgContext.TreeList,
                h_tviRootItem,
                TEXT("NtBuildNumber"),
                (LPWSTR)NULL,
                pUserSharedData->NtBuildNumber,
                FALSE,
                FALSE,
                (COLORREF)0,
                (COLORREF)0);
        }

        //
        // ProcessorFeatures
        //
        h_tviSubItem = supTreeListAddItem(
            g_UsdDlgContext.TreeList,
            h_tviRootItem,
            TVIF_TEXT | TVIF_STATE,
            (UINT)0,
            (UINT)0,
            TEXT("ProcessorFeatures"),
            (PVOID)NULL);

        if (h_tviSubItem) {
            for (i = 0; i < PROCESSOR_FEATURE_MAX; i++) {
                if (pUserSharedData->ProcessorFeatures[i]) {
                    bAny = TRUE;
                    if (i >= RTL_NUMBER_OF(T_PROCESSOR_FEATURES)) {
                        lpType = T_Unknown;
                    }
                    else {
                        lpType = T_PROCESSOR_FEATURES[i];
                    }
                    RtlSecureZeroMemory(&subitems, sizeof(subitems));
                    RtlSecureZeroMemory(&szValue, sizeof(szValue));
                    ultostr(i, szValue);
                    subitems.Text[0] = szValue;
                    subitems.Text[1] = lpType;
                    subitems.Count = 2;
                    h_tviLast = supTreeListAddItem(
                        g_UsdDlgContext.TreeList,
                        h_tviSubItem,
                        TVIF_TEXT | TVIF_STATE,
                        (UINT)0,
                        (UINT)0,
                        (LPWSTR)T_EmptyString,
                        &subitems);
                }
            }

            //
            // Output dotted corner for processor features.
            //
            if (h_tviLast) {
                RtlSecureZeroMemory(&itemex, sizeof(itemex));

                itemex.hItem = h_tviLast;
                itemex.mask = TVIF_TEXT | TVIF_HANDLE;
                itemex.pszText = T_EMPTY;

                TreeList_SetTreeItem(g_UsdDlgContext.TreeList, &itemex, NULL);
            }

            if (bAny == FALSE) {
                RtlSecureZeroMemory(&subitems, sizeof(subitems));
                lpType = TEXT("-");
                _strcpy(szValue, TEXT("0"));
                subitems.Text[0] = szValue;
                subitems.Text[1] = lpType;
                subitems.Count = 2;
                supTreeListAddItem(
                    g_UsdDlgContext.TreeList,
                    h_tviSubItem,
                    TVIF_TEXT | TVIF_STATE,
                    (UINT)0,
                    (UINT)0,
                    (LPWSTR)T_EmptyString,
                    &subitems);
            }
        }

        //
        // AlternativeArchitecture
        //
        switch (pUserSharedData->AlternativeArchitecture) {
        case StandardDesign:
            lpType = TEXT("StandardDesign");
            break;
        case NEC98x86:
            lpType = TEXT("NEC98x86");
            break;
        default:
            lpType = T_UnknownType;
            break;
        }

        propObDumpUlong(
            g_UsdDlgContext.TreeList,
            h_tviRootItem,
            TEXT("AlternativeArchitecture"),
            lpType,
            pUserSharedData->AlternativeArchitecture,
            FALSE,
            FALSE,
            (COLORREF)0,
            (COLORREF)0);

        //
        // SuiteMask
        //
        RtlSecureZeroMemory(&subitems, sizeof(subitems));
        RtlSecureZeroMemory(&szValue, sizeof(szValue));
        szValue[0] = TEXT('0');
        szValue[1] = TEXT('x');
        ultohex(pUserSharedData->SuiteMask, &szValue[2]);
        subitems.Text[0] = szValue;
        subitems.Count = 1;

        h_tviSubItem = supTreeListAddItem(
            g_UsdDlgContext.TreeList,
            h_tviRootItem,
            TVIF_TEXT | TVIF_STATE,
            (UINT)0,
            (UINT)0,
            TEXT("SuiteMask"),
            &subitems);

        if (h_tviSubItem) {
            h_tviLast = NULL;
            mask = pUserSharedData->SuiteMask;
            for (i = 0; i < RTL_NUMBER_OF(SuiteMasks); i++) {
                if (mask & SuiteMasks[i].dwValue) {

                    RtlSecureZeroMemory(&subitems, sizeof(subitems));
                    RtlSecureZeroMemory(&szValue, sizeof(szValue));
                    szValue[0] = TEXT('0');
                    szValue[1] = TEXT('x');
                    ultohex(SuiteMasks[i].dwValue, &szValue[2]);
                    subitems.Text[0] = szValue;
                    subitems.Text[1] = SuiteMasks[i].lpDescription;
                    subitems.Count = 2;

                    h_tviLast = supTreeListAddItem(
                        g_UsdDlgContext.TreeList,
                        h_tviSubItem,
                        TVIF_TEXT | TVIF_STATE,
                        (UINT)0,
                        (UINT)0,
                        (LPWSTR)T_EmptyString,
                        &subitems);

                    mask &= ~SuiteMasks[i].dwValue;
                }
            }

            //
            // Output dotted corner for suite mask.
            //
            if (h_tviLast) {
                RtlSecureZeroMemory(&itemex, sizeof(itemex));

                itemex.hItem = h_tviLast;
                itemex.mask = TVIF_TEXT | TVIF_HANDLE;
                itemex.pszText = T_EMPTY;

                TreeList_SetTreeItem(g_UsdDlgContext.TreeList, &itemex, NULL);
            }
        }

        //
        // KdDebuggerEnabled
        //
        propObDumpByte(
            g_UsdDlgContext.TreeList,
            h_tviRootItem,
            TEXT("KdDebuggerEnabled"),
            (LPWSTR)NULL,
            pUserSharedData->KdDebuggerEnabled,
            (COLORREF)0,
            (COLORREF)0,
            TRUE);

        //
        // MitigationPolicies
        //

        if (g_NtBuildNumber < NT_WIN8_RTM) {

            propObDumpByte(
                g_UsdDlgContext.TreeList,
                h_tviRootItem,
                TEXT("NXSupportPolicy"),
                (LPWSTR)NULL,
                pUserSharedData->NXSupportPolicy,
                (COLORREF)0,
                (COLORREF)0,
                FALSE);

        }
        else {

            //
            // Expanded to more values starting from Windows 8+
            //

            RtlSecureZeroMemory(&subitems, sizeof(subitems));
            RtlSecureZeroMemory(szValue, sizeof(szValue));

            RtlStringCchPrintfSecure(szValue,
                MAX_PATH,
                TEXT("0x%02X"),
                pUserSharedData->MitigationPolicies);

            subitems.Text[0] = szValue;
            subitems.Count = 1;

            h_tviSubItem = supTreeListAddItem(
                g_UsdDlgContext.TreeList,
                h_tviRootItem,
                TVIF_TEXT | TVIF_STATE,
                (UINT)0,
                (UINT)0,
                TEXT("MitigationPolicies"),
                &subitems);

            if (h_tviSubItem) {

                propObDumpByte(
                    g_UsdDlgContext.TreeList,
                    h_tviSubItem,
                    TEXT("NXSupportPolicy"),
                    (LPWSTR)NULL,
                    pUserSharedData->NXSupportPolicy,
                    (COLORREF)0,
                    (COLORREF)0,
                    FALSE);

                propObDumpByte(
                    g_UsdDlgContext.TreeList,
                    h_tviSubItem,
                    TEXT("SEHValidationPolicy"),
                    (LPWSTR)NULL,
                    pUserSharedData->SEHValidationPolicy,
                    (COLORREF)0,
                    (COLORREF)0,
                    FALSE);


                propObDumpByte(
                    g_UsdDlgContext.TreeList,
                    h_tviSubItem,
                    TEXT("CurDirDevicesSkippedForDlls"),
                    (LPWSTR)NULL,
                    pUserSharedData->CurDirDevicesSkippedForDlls,
                    (COLORREF)0,
                    (COLORREF)0,
                    FALSE);
            }
        }

        //
        // ActiveConsoleId
        //
        propObDumpUlong(g_UsdDlgContext.TreeList,
            h_tviRootItem,
            TEXT("ActiveConsoleId"),
            NULL,
            pUserSharedData->ActiveConsoleId,
            TRUE,
            FALSE,
            (COLORREF)0,
            (COLORREF)0);

        //
        // SafeBootMode
        //
        propObDumpByte(
            g_UsdDlgContext.TreeList,
            h_tviRootItem,
            TEXT("SafeBootMode"),
            (LPWSTR)NULL,
            pUserSharedData->SafeBootMode,
            (COLORREF)0,
            (COLORREF)0,
            TRUE);

        //
        // SharedDataFlags
        //
        RtlSecureZeroMemory(&subitems, sizeof(subitems));
        RtlSecureZeroMemory(&szValue, sizeof(szValue));
        szValue[0] = TEXT('0');
        szValue[1] = TEXT('x');
        ultohex(pUserSharedData->SharedDataFlags, &szValue[2]);
        subitems.Text[0] = szValue;
        subitems.Count = 1;

        h_tviSubItem = supTreeListAddItem(
            g_UsdDlgContext.TreeList,
            h_tviRootItem,
            TVIF_TEXT | TVIF_STATE,
            (UINT)0,
            (UINT)0,
            TEXT("SharedDataFlags"),
            &subitems);

        if (h_tviSubItem) {

            h_tviLast = NULL;

            if (g_NtBuildNumber < NT_WIN8_RTM) {
                pvSharedFlagsDesc = T_SharedDataFlagsW7;
                cFlags = RTL_NUMBER_OF(T_SharedDataFlagsW7);
            }
            else {
                pvSharedFlagsDesc = T_SharedDataFlags;
                cFlags = RTL_NUMBER_OF(T_SharedDataFlags);
            }

            for (i = 0; i < cFlags; i++) {
                if (GET_BIT(pUserSharedData->SharedDataFlags, i)) {
                    RtlSecureZeroMemory(&subitems, sizeof(subitems));
                    RtlSecureZeroMemory(&szValue, sizeof(szValue));
                    _strcpy(szValue, TEXT("BitPos: "));
                    ultostr(i, _strend(szValue));
                    subitems.Text[0] = szValue;
                    subitems.Text[1] = (LPWSTR)pvSharedFlagsDesc[i];
                    subitems.Count = 2;
                    h_tviLast = supTreeListAddItem(
                        g_UsdDlgContext.TreeList,
                        h_tviSubItem,
                        TVIF_TEXT | TVIF_STATE,
                        (UINT)0,
                        (UINT)0,
                        (LPWSTR)T_EmptyString,
                        &subitems);
                }
            }

            //
            // Output dotted corner for shared data flags
            //
            if (h_tviLast) {
                RtlSecureZeroMemory(&itemex, sizeof(itemex));

                itemex.hItem = h_tviLast;
                itemex.mask = TVIF_TEXT | TVIF_HANDLE;
                itemex.pszText = T_EMPTY;

                TreeList_SetTreeItem(g_UsdDlgContext.TreeList, &itemex, NULL);
            }

        }

        //
        // Cookie
        //
        propObDumpUlong(g_UsdDlgContext.TreeList,
            h_tviRootItem,
            TEXT("Cookie"),
            NULL,
            pUserSharedData->Cookie,
            TRUE,
            FALSE,
            (COLORREF)0,
            (COLORREF)0);

        //
        // ActiveProcessorCount
        //
        propObDumpUlong(g_UsdDlgContext.TreeList,
            h_tviRootItem,
            TEXT("ActiveProcessorCount"),
            NULL,
            pUserSharedData->ActiveProcessorCount,
            FALSE,
            FALSE,
            (COLORREF)0,
            (COLORREF)0);

    } while (FALSE);
}

/*
* UsdDialogHandlePopupMenu
*
* Purpose:
*
* Treelist popup construction
*
*/
VOID UsdDialogHandlePopupMenu(
    _In_ HWND hwndDlg,
    _In_ LPARAM lParam
)
{
    HMENU hMenu;
    POINT pt1;

    if (GetCursorPos(&pt1) == FALSE)
        return;

    hMenu = CreatePopupMenu();
    if (hMenu) {

        if (supTreeListAddCopyValueItem(hMenu,
            g_UsdDlgContext.TreeList,
            ID_OBJECT_COPY,
            0,
            lParam,
            &g_UsdDlgContext.tlSubItemHit))
        {
            TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, pt1.x, pt1.y, 0, hwndDlg, NULL);
        }

        DestroyMenu(hMenu);

    }
}

/*
* UsdDialogOnInit
*
* Purpose:
*
* WM_INITDIALOG handler.
*
*/
VOID UsdDialogOnInit(
    _In_ HWND hwndDlg
)
{
    UsdDumpSharedRegion(hwndDlg);
    supCenterWindowSpecifyParent(hwndDlg, g_hwndMain);
}

/*
* UsdDialogProc
*
* Purpose:
*
* Usd Dialog Procedure
*
*/
INT_PTR CALLBACK UsdDialogProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam
)
{
    switch (uMsg) {

    case WM_INITDIALOG:
        UsdDialogOnInit(hwndDlg);
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    case WM_CLOSE:
        DestroyWindow(g_UsdDlgContext.TreeList);
        DestroyWindow(hwndDlg);
        break;

    case WM_COMMAND:

        switch (GET_WM_COMMAND_ID(wParam, lParam)) {
        case IDCANCEL:

            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            break;

        case ID_OBJECT_COPY:

            supTreeListCopyItemValueToClipboard(g_UsdDlgContext.TreeList,
                g_UsdDlgContext.tlSubItemHit);

            break;

        }

        break;

    case WM_CONTEXTMENU:

        UsdDialogHandlePopupMenu(hwndDlg, lParam);
        break;
    }

    return FALSE;
}

/*
* extrasCreateUsdDialog
*
* Purpose:
*
* Create and initialize Usd Dialog.
*
*/
DWORD extrasUsdDialogWorkerThread(
    _In_ PVOID Parameter
)
{
    BOOL bResult;
    MSG message;
    HWND hwndDlg;

    UNREFERENCED_PARAMETER(Parameter);

    hwndDlg = CreateDialogParam(g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_USD),
        0,
        &UsdDialogProc,
        0);

    g_UsdDlgContext.hwndDlg = hwndDlg;

    supSetFastEvent(&UsdDlgInitializedEvent);

    do {

        bResult = GetMessage(&message, NULL, 0, 0);
        if (bResult == -1)
            break;

        if (!IsDialogMessage(hwndDlg, &message)) {
            TranslateMessage(&message);
            DispatchMessage(&message);
        }

    } while (bResult != 0);

    supResetFastEvent(&UsdDlgInitializedEvent);

    if (UsdDlgThreadHandle) {
        NtClose(UsdDlgThreadHandle);
        UsdDlgThreadHandle = NULL;
    }

    return 0;
}

/*
* extrasCreateUsdDialog
*
* Purpose:
*
* Create and initialize Usd Dialog.
*
*/
VOID extrasCreateUsdDialog(
    VOID
)
{

    if (!UsdDlgThreadHandle) {

        RtlSecureZeroMemory(&g_UsdDlgContext, sizeof(g_UsdDlgContext));
        g_UsdDlgContext.tlSubItemHit = -1;

        UsdDlgThreadHandle = supCreateDialogWorkerThread(extrasUsdDialogWorkerThread, NULL, 0);
        supWaitForFastEvent(&UsdDlgInitializedEvent, NULL);

    }
}
