/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       EXTRASUSD.C
*
*  VERSION:     1.52
*
*  DATE:        08 Jan 2018
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

EXTRASCONTEXT DlgContext;

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
    BOOL                  bCond = FALSE;
    INT                   i;
    DWORD                 mask;
    HWND                  UsdTreeList;
    ATOM                  UsdTreeListAtom;

    HTREEITEM             h_tviRootItem, h_tviSubItem;
    LPWSTR                lpType;
    TL_SUBITEMS_FIXED     subitems;
    WCHAR                 szValue[MAX_PATH + 1];

    PKUSER_SHARED_DATA    pUserSharedData;

    do {

        pUserSharedData = (KUSER_SHARED_DATA * const)MM_SHARED_USER_DATA_VA;

        if (IsBadReadPtr(pUserSharedData, sizeof(KUSER_SHARED_DATA)))
            break;

        UsdTreeList = 0;
        UsdTreeListAtom = 0;
        if (!supInitTreeListForDump(hwndParent, &UsdTreeListAtom, &UsdTreeList)) {
            break;
        }

        //
        //KUSER_SHARED_DATA
        //

        h_tviRootItem = TreeListAddItem(UsdTreeList,
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

        TreeListAddItem(UsdTreeList,
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

        ObDumpUlong(UsdTreeList,
            h_tviRootItem,
            TEXT("NtProductType"),
            lpType,
            pUserSharedData->NtProductType,
            FALSE,
            FALSE,
            (COLORREF)0,
            (COLORREF)0);

        ObDumpByte(UsdTreeList,
            h_tviRootItem,
            TEXT("ProductTypeIsValid"),
            (LPWSTR)NULL,
            pUserSharedData->ProductTypeIsValid,
            (COLORREF)0,
            (COLORREF)0,
            TRUE);

        //Version
        ObDumpUlong(UsdTreeList,
            h_tviRootItem,
            TEXT("NtMajorVersion"),
            (LPWSTR)NULL,
            pUserSharedData->NtMajorVersion,
            FALSE,
            FALSE,
            (COLORREF)0,
            (COLORREF)0);

        ObDumpUlong(UsdTreeList,
            h_tviRootItem,
            TEXT("NtMinorVersion"),
            (LPWSTR)NULL,
            pUserSharedData->NtMinorVersion,
            FALSE,
            FALSE,
            (COLORREF)0,
            (COLORREF)0);

        //ProcessorFeatures
        h_tviSubItem = TreeListAddItem(UsdTreeList,
            h_tviRootItem,
            TVIF_TEXT | TVIF_STATE,
            (UINT)0,
            (UINT)0,
            TEXT("ProcessorFeatures"),
            (PVOID)NULL);

        if (h_tviSubItem) {
            for (i = 0; i < PROCESSOR_FEATURE_MAX; i++) {
                if (pUserSharedData->ProcessorFeatures[i]) {
                    if (i > 32) {
                        lpType = T_Unknown;
                    }
                    else {
                        lpType = T_PROCESSOR_FEATURES[i];
                    }
                    RtlSecureZeroMemory(&subitems, sizeof(subitems));
                    RtlSecureZeroMemory(&szValue, sizeof(szValue));
                    itostr_w(i, szValue);
                    subitems.Text[0] = szValue;
                    subitems.Text[1] = lpType;
                    subitems.Count = 2;
                    TreeListAddItem(UsdTreeList,
                        h_tviSubItem,
                        TVIF_TEXT | TVIF_STATE,
                        (UINT)0,
                        (UINT)0,
                        (LPWSTR)NULL,
                        &subitems);
                }
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

        ObDumpUlong(UsdTreeList,
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
        szValue[0] = L'0';
        szValue[1] = L'x';
        ultohex_w(pUserSharedData->SuiteMask, &szValue[2]);
        subitems.Text[0] = szValue;
        subitems.Count = 1;

        h_tviSubItem = TreeListAddItem(UsdTreeList,
            h_tviRootItem,
            TVIF_TEXT | TVIF_STATE,
            (UINT)0,
            (UINT)0,
            TEXT("SuiteMask"),
            &subitems);

        if (h_tviSubItem) {
            mask = pUserSharedData->SuiteMask;
            for (i = 0; i < MAX_KNOWN_SUITEMASKS; i++) {
                if (mask & SuiteMasks[i].dwValue) {

                    RtlSecureZeroMemory(&subitems, sizeof(subitems));
                    RtlSecureZeroMemory(&szValue, sizeof(szValue));
                    szValue[0] = L'0';
                    szValue[1] = L'x';
                    ultohex_w(SuiteMasks[i].dwValue, &szValue[2]);
                    subitems.Text[0] = szValue;
                    subitems.Text[1] = SuiteMasks[i].lpDescription;
                    subitems.Count = 2;

                    TreeListAddItem(UsdTreeList,
                        h_tviSubItem,
                        TVIF_TEXT | TVIF_STATE,
                        (UINT)0,
                        (UINT)0,
                        (LPWSTR)NULL,
                        &subitems);

                    mask &= ~SuiteMasks[i].dwValue;
                }
            }
        }

        //KdDebuggerEnabled
        ObDumpByte(UsdTreeList,
            h_tviRootItem,
            TEXT("KdDebuggerEnabled"),
            (LPWSTR)NULL,
            pUserSharedData->KdDebuggerEnabled,
            (COLORREF)0,
            (COLORREF)0,
            TRUE);

        //MitigationPolicies
        ObDumpByte(UsdTreeList,
            h_tviRootItem,
            TEXT("MitigationPolicies"),
            (LPWSTR)NULL,
            pUserSharedData->MitigationPolicies,
            (COLORREF)0,
            (COLORREF)0,
            FALSE);

        //SafeBootMode
        ObDumpByte(UsdTreeList,
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
        szValue[0] = L'0';
        szValue[1] = L'x';
        ultohex_w(pUserSharedData->SharedDataFlags, &szValue[2]);
        subitems.Text[0] = szValue;
        subitems.Count = 1;

        h_tviSubItem = TreeListAddItem(UsdTreeList,
            h_tviRootItem,
            TVIF_TEXT | TVIF_STATE,
            (UINT)0,
            (UINT)0,
            TEXT("SharedDataFlags"),
            &subitems);

        if (h_tviSubItem) {
            for (i = 0; i < MAX_KNOWN_SHAREDDATAFLAGS; i++) {
                if (GET_BIT(pUserSharedData->SharedDataFlags, i)) {
                    RtlSecureZeroMemory(&subitems, sizeof(subitems));
                    RtlSecureZeroMemory(&szValue, sizeof(szValue));
                    _strcpy_w(szValue, L"BitPos: ");
                    itostr_w(i, _strend_w(szValue));
                    subitems.Text[0] = szValue;
                    subitems.Text[1] = (LPTSTR)T_SharedDataFlags[i];
                    subitems.Count = 2;
                    TreeListAddItem(UsdTreeList,
                        h_tviSubItem,
                        TVIF_TEXT | TVIF_STATE,
                        (UINT)0,
                        (UINT)0,
                        (LPWSTR)NULL,
                        &subitems);
                }
            }
        }

    } while (bCond);
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
        DestroyWindow(hwndDlg);
        g_WinObj.AuxDialogs[WOBJ_USDDLG_IDX] = NULL;
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
    if (g_WinObj.AuxDialogs[WOBJ_USDDLG_IDX]) {
        SetActiveWindow(g_WinObj.AuxDialogs[WOBJ_USDDLG_IDX]);
        return;
    }

    RtlSecureZeroMemory(&DlgContext, sizeof(DlgContext));
    DlgContext.hwndDlg = CreateDialogParam(g_WinObj.hInstance, MAKEINTRESOURCE(IDD_DIALOG_USD),
        hwndParent, &UsdDialogProc, 0);

    if (DlgContext.hwndDlg == NULL) {
        return;
    }

    g_WinObj.AuxDialogs[WOBJ_USDDLG_IDX] = DlgContext.hwndDlg;

    UsdDumpSharedRegion(DlgContext.hwndDlg);
}
