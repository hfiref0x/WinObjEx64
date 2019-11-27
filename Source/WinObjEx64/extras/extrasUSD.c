/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       EXTRASUSD.C
*
*  VERSION:     1.82
*
*  DATE:        09 Nov 2019
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "propObjectDump.h"
#include "extras.h"
#include "extrasUSD.h"
#include "treelist\treelist.h"

EXTRASCONTEXT DlgContext;

HWND UsdTreeList = NULL;

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
    DWORD               mask;

    HTREEITEM           h_tviRootItem, h_tviSubItem, h_tviLast = NULL;
    LPWSTR              lpType;
    TL_SUBITEMS_FIXED   subitems;
    TVITEMEX            itemex;
    WCHAR               szValue[MAX_PATH + 1];

    PKUSER_SHARED_DATA  pUserSharedData;
    HWND hwnd;


    do {

        pUserSharedData = (KUSER_SHARED_DATA * const)MM_SHARED_USER_DATA_VA;

        if (IsBadReadPtr(pUserSharedData, sizeof(KUSER_SHARED_DATA)))
            break;

        hwnd = GetDlgItem(hwndParent, ID_USDDUMPGROUPBOX);

        if (!supInitTreeListForDump(hwndParent, &UsdTreeList)) {
            break;
        }

        //
        //KUSER_SHARED_DATA
        //

        h_tviRootItem = TreeListAddItem(
            UsdTreeList,
            (HTREEITEM)NULL,
            TVIF_TEXT | TVIF_STATE,
            TVIS_EXPANDED,
            TVIS_EXPANDED,
            TEXT("KUSER_SHARED_DATA"),
            (PVOID)NULL);

        if (h_tviRootItem == NULL) {
            break;
        }

        //NtSystemRoot
        RtlSecureZeroMemory(&subitems, sizeof(subitems));
        subitems.Text[0] = pUserSharedData->NtSystemRoot;
        subitems.Count = 1;

        TreeListAddItem(
            UsdTreeList,
            h_tviRootItem,
            TVIF_TEXT | TVIF_STATE,
            (UINT)0,
            (UINT)0,
            TEXT("NtSystemRoot"),
            &subitems);

        //NtProductType
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
            UsdTreeList,
            h_tviRootItem,
            TEXT("NtProductType"),
            lpType,
            pUserSharedData->NtProductType,
            FALSE,
            FALSE,
            (COLORREF)0,
            (COLORREF)0);

        propObDumpByte(
            UsdTreeList,
            h_tviRootItem,
            TEXT("ProductTypeIsValid"),
            (LPWSTR)NULL,
            pUserSharedData->ProductTypeIsValid,
            (COLORREF)0,
            (COLORREF)0,
            TRUE);

        //Version
        propObDumpUlong(
            UsdTreeList,
            h_tviRootItem,
            TEXT("NtMajorVersion"),
            (LPWSTR)NULL,
            pUserSharedData->NtMajorVersion,
            FALSE,
            FALSE,
            (COLORREF)0,
            (COLORREF)0);

        propObDumpUlong(
            UsdTreeList,
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
        if (g_WinObj.osver.dwMajorVersion >= 10) {
            propObDumpUlong(
                UsdTreeList,
                h_tviRootItem,
                TEXT("NtBuildNumber"),
                (LPWSTR)NULL,
                pUserSharedData->NtBuildNumber,
                FALSE,
                FALSE,
                (COLORREF)0,
                (COLORREF)0);
        }

        //ProcessorFeatures
        h_tviSubItem = TreeListAddItem(
            UsdTreeList,
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
                    h_tviLast = TreeListAddItem(
                        UsdTreeList,
                        h_tviSubItem,
                        TVIF_TEXT | TVIF_STATE,
                        (UINT)0,
                        (UINT)0,
                        (LPWSTR)T_EmptyString,
                        &subitems);
                }
            }

            //
            // Output dotted corner.
            //
            if (h_tviLast) {
                RtlSecureZeroMemory(&itemex, sizeof(itemex));

                itemex.hItem = h_tviLast;
                itemex.mask = TVIF_TEXT | TVIF_HANDLE;
                itemex.pszText = T_EMPTY;

                TreeList_SetTreeItem(UsdTreeList, &itemex, NULL);
            }

            if (bAny == FALSE) {
                RtlSecureZeroMemory(&subitems, sizeof(subitems));
                lpType = TEXT("-");
                _strcpy(szValue, TEXT("0"));
                subitems.Text[0] = szValue;
                subitems.Text[1] = lpType;
                subitems.Count = 2;
                TreeListAddItem(
                    UsdTreeList,
                    h_tviSubItem,
                    TVIF_TEXT | TVIF_STATE,
                    (UINT)0,
                    (UINT)0,
                    (LPWSTR)T_EmptyString,
                    &subitems);
            }
        }

        //AlternativeArchitecture
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
            UsdTreeList,
            h_tviRootItem,
            TEXT("AlternativeArchitecture"),
            lpType,
            pUserSharedData->AlternativeArchitecture,
            FALSE,
            FALSE,
            (COLORREF)0,
            (COLORREF)0);

        //SuiteMask
        RtlSecureZeroMemory(&subitems, sizeof(subitems));
        RtlSecureZeroMemory(&szValue, sizeof(szValue));
        szValue[0] = TEXT('0');
        szValue[1] = TEXT('x');
        ultohex(pUserSharedData->SuiteMask, &szValue[2]);
        subitems.Text[0] = szValue;
        subitems.Count = 1;

        h_tviSubItem = TreeListAddItem(
            UsdTreeList,
            h_tviRootItem,
            TVIF_TEXT | TVIF_STATE,
            (UINT)0,
            (UINT)0,
            TEXT("SuiteMask"),
            &subitems);

        if (h_tviSubItem) {
            h_tviLast = NULL;
            mask = pUserSharedData->SuiteMask;
            for (i = 0; i < MAX_KNOWN_SUITEMASKS; i++) {
                if (mask & SuiteMasks[i].dwValue) {

                    RtlSecureZeroMemory(&subitems, sizeof(subitems));
                    RtlSecureZeroMemory(&szValue, sizeof(szValue));
                    szValue[0] = TEXT('0');
                    szValue[1] = TEXT('x');
                    ultohex(SuiteMasks[i].dwValue, &szValue[2]);
                    subitems.Text[0] = szValue;
                    subitems.Text[1] = SuiteMasks[i].lpDescription;
                    subitems.Count = 2;

                    h_tviLast = TreeListAddItem(
                        UsdTreeList,
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
            // Output dotted corner.
            //
            if (h_tviLast) {
                RtlSecureZeroMemory(&itemex, sizeof(itemex));

                itemex.hItem = h_tviLast;
                itemex.mask = TVIF_TEXT | TVIF_HANDLE;
                itemex.pszText = T_EMPTY;

                TreeList_SetTreeItem(UsdTreeList, &itemex, NULL);
            }
        }

        //KdDebuggerEnabled
        propObDumpByte(
            UsdTreeList,
            h_tviRootItem,
            TEXT("KdDebuggerEnabled"),
            (LPWSTR)NULL,
            pUserSharedData->KdDebuggerEnabled,
            (COLORREF)0,
            (COLORREF)0,
            TRUE);

        //MitigationPolicies

        if (g_NtBuildNumber < 9200) {

            propObDumpByte(
                UsdTreeList,
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
            // Expanded to more values starting from Windows 8+.
            //

            RtlSecureZeroMemory(&subitems, sizeof(subitems));
            RtlSecureZeroMemory(szValue, sizeof(szValue));

            rtl_swprintf_s(szValue, MAX_PATH, TEXT("0x%02X"), pUserSharedData->MitigationPolicies);

            subitems.Text[0] = szValue;
            subitems.Count = 1;

            h_tviSubItem = TreeListAddItem(
                UsdTreeList,
                h_tviRootItem,
                TVIF_TEXT | TVIF_STATE,
                (UINT)0,
                (UINT)0,
                TEXT("MitigationPolicies"),
                &subitems);

            if (h_tviSubItem) {

                propObDumpByte(
                    UsdTreeList,
                    h_tviSubItem,
                    TEXT("NXSupportPolicy"),
                    (LPWSTR)NULL,
                    pUserSharedData->NXSupportPolicy,
                    (COLORREF)0,
                    (COLORREF)0,
                    FALSE);

                propObDumpByte(
                    UsdTreeList,
                    h_tviSubItem,
                    TEXT("SEHValidationPolicy"),
                    (LPWSTR)NULL,
                    pUserSharedData->SEHValidationPolicy,
                    (COLORREF)0,
                    (COLORREF)0,
                    FALSE);


                propObDumpByte(
                    UsdTreeList,
                    h_tviSubItem,
                    TEXT("CurDirDevicesSkippedForDlls"),
                    (LPWSTR)NULL,
                    pUserSharedData->CurDirDevicesSkippedForDlls,
                    (COLORREF)0,
                    (COLORREF)0,
                    FALSE);
            }
        }

        //SafeBootMode
        propObDumpByte(
            UsdTreeList,
            h_tviRootItem,
            TEXT("SafeBootMode"),
            (LPWSTR)NULL,
            pUserSharedData->SafeBootMode,
            (COLORREF)0,
            (COLORREF)0,
            TRUE);

        //SharedDataFlags
        RtlSecureZeroMemory(&subitems, sizeof(subitems));
        RtlSecureZeroMemory(&szValue, sizeof(szValue));
        szValue[0] = TEXT('0');
        szValue[1] = TEXT('x');
        ultohex(pUserSharedData->SharedDataFlags, &szValue[2]);
        subitems.Text[0] = szValue;
        subitems.Count = 1;

        h_tviSubItem = TreeListAddItem(
            UsdTreeList,
            h_tviRootItem,
            TVIF_TEXT | TVIF_STATE,
            (UINT)0,
            (UINT)0,
            TEXT("SharedDataFlags"),
            &subitems);

        if (h_tviSubItem) {
            h_tviLast = NULL;
            for (i = 0; i < MAX_KNOWN_SHAREDDATAFLAGS; i++) {
                if (GET_BIT(pUserSharedData->SharedDataFlags, i)) {
                    RtlSecureZeroMemory(&subitems, sizeof(subitems));
                    RtlSecureZeroMemory(&szValue, sizeof(szValue));
                    _strcpy(szValue, TEXT("BitPos: "));
                    ultostr(i, _strend(szValue));
                    subitems.Text[0] = szValue;
                    subitems.Text[1] = (LPTSTR)T_SharedDataFlags[i];
                    subitems.Count = 2;
                    h_tviLast = TreeListAddItem(
                        UsdTreeList,
                        h_tviSubItem,
                        TVIF_TEXT | TVIF_STATE,
                        (UINT)0,
                        (UINT)0,
                        (LPWSTR)T_EmptyString,
                        &subitems);
                }
            }

            //
            // Output dotted corner.
            //
            if (h_tviLast) {
                RtlSecureZeroMemory(&itemex, sizeof(itemex));

                itemex.hItem = h_tviLast;
                itemex.mask = TVIF_TEXT | TVIF_HANDLE;
                itemex.pszText = T_EMPTY;

                TreeList_SetTreeItem(UsdTreeList, &itemex, NULL);
            }

        }

    } while (FALSE);
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
    UNREFERENCED_PARAMETER(lParam);

    switch (uMsg) {

    case WM_INITDIALOG:
        supCenterWindow(hwndDlg);
        break;

    case WM_CLOSE:
        DestroyWindow(UsdTreeList);
        DestroyWindow(hwndDlg);
        g_WinObj.AuxDialogs[wobjUSDDlgId] = NULL;
        return TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDCANCEL) {
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            return TRUE;
        }
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
VOID extrasCreateUsdDialog(
    _In_ HWND hwndParent
)
{
    //allow only one dialog
    if (g_WinObj.AuxDialogs[wobjUSDDlgId]) {
        SetActiveWindow(g_WinObj.AuxDialogs[wobjUSDDlgId]);
        return;
    }

    RtlSecureZeroMemory(&DlgContext, sizeof(DlgContext));
    DlgContext.hwndDlg = CreateDialogParam(g_WinObj.hInstance, MAKEINTRESOURCE(IDD_DIALOG_USD),
        hwndParent, &UsdDialogProc, 0);

    if (DlgContext.hwndDlg == NULL) {
        return;
    }

    g_WinObj.AuxDialogs[wobjUSDDlgId] = DlgContext.hwndDlg;

    UsdDumpSharedRegion(DlgContext.hwndDlg);
}
