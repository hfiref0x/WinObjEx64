/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       PROPBASIC.C
*
*  VERSION:     1.73
*
*  DATE:        30 Mar 2019
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "propDlg.h"
#include "propBasicConsts.h"

/*
* propSetObjectHeaderAddressInfo
*
* Purpose:
*
* Set Object & Header address controls text.
*
*/
VOID propSetObjectHeaderAddressInfo(
    _In_ HWND hwndDlg,
    _In_ ULONG_PTR ObjectAddress,
    _In_ ULONG_PTR HeaderAddress
)
{
    WCHAR szBuffer[100];

    //Object Address
    if (ObjectAddress) {
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        szBuffer[0] = TEXT('0');
        szBuffer[1] = TEXT('x');
        u64tohex(ObjectAddress, &szBuffer[2]);
        SetDlgItemText(hwndDlg, ID_OBJECT_ADDR, szBuffer);
    }
    else {
        SetDlgItemText(hwndDlg, ID_OBJECT_ADDR, TEXT(""));
    }

    //Header Address
    if (HeaderAddress) {
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        szBuffer[0] = TEXT('0');
        szBuffer[1] = TEXT('x');
        u64tohex(HeaderAddress, &szBuffer[2]);
        SetDlgItemText(hwndDlg, ID_OBJECT_HEADER, szBuffer);
    }
    else {
        SetDlgItemText(hwndDlg, ID_OBJECT_HEADER, TEXT(""));
    }
}

/*
* propSetProcessMitigationsInfo
*
* Purpose:
*
* Set Process mitigation information if it specified for this object.
*
*/
VOID propSetProcessMitigationsInfo(
    _In_ HANDLE hProcess,
    _In_ BOOL wow64Process,
    _In_ HWND hwndDlg
)
{
    BOOL bQuery;
    LRESULT lResult;
    HWND hwndCB = GetDlgItem(hwndDlg, IDC_PROCESS_MITIGATIONS);
    PROCESS_MITIGATION_POLICIES_ALL Policies;

    WCHAR szBuffer[1000];

    RtlSecureZeroMemory(&Policies, sizeof(Policies));

    SendMessage(hwndCB, CB_RESETCONTENT, (WPARAM)0, (LPARAM)0);

    //
    // DEP state.
    //

    //
    // Always ON for 64bit.
    //
    bQuery = TRUE;
    Policies.DEPPolicy.Enable = 1;
    Policies.DEPPolicy.Permanent = 1;

    if (wow64Process) {
        Policies.DEPPolicy.Flags = 0;
        bQuery = supGetProcessDepState(hProcess,
            &Policies.DEPPolicy);
    }

    if (bQuery)
    {
        if (Policies.DEPPolicy.Flags) {
            _strcpy(szBuffer, TEXT("DEP "));
            if (Policies.DEPPolicy.Permanent)
                _strcat(szBuffer, TEXT("(Permanent)"));
            else {
                if (Policies.DEPPolicy.Enable) {
                    _strcat(szBuffer, TEXT("Enabled"));
                }
                else {
                    _strcat(szBuffer, TEXT("Disabled"));
                }
            }

            if (Policies.DEPPolicy.DisableAtlThunkEmulation)
                _strcat(szBuffer, TEXT(" (ATL thunk emulation is disabled)"));

            SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
        }
    }

    //
    // ASLR state.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessASLRPolicy,
        sizeof(PROCESS_MITIGATION_ASLR_POLICY),
        &Policies.ASLRPolicy))
    {
        if (Policies.ASLRPolicy.Flags) {
            _strcpy(szBuffer, TEXT("ASLR"));
            if (Policies.ASLRPolicy.EnableHighEntropy) _strcat(szBuffer, TEXT(" (High-Entropy)"));
            if (Policies.ASLRPolicy.EnableForceRelocateImages) _strcat(szBuffer, TEXT(" (Force Relocate)"));
            if (Policies.ASLRPolicy.EnableBottomUpRandomization) _strcat(szBuffer, TEXT(" (Bottom-Up)"));
            if (Policies.ASLRPolicy.DisallowStrippedImages) _strcat(szBuffer, TEXT(" (Disallow Stripped)"));
            SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
        }
    }

    //
    // Dynamic code.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessDynamicCodePolicy,
        sizeof(PROCESS_MITIGATION_DYNAMIC_CODE_POLICY_W10),
        &Policies.DynamicCodePolicy))
    {
        if (Policies.DynamicCodePolicy.Flags) {
            if (Policies.DynamicCodePolicy.ProhibitDynamicCode) {
                _strcpy(szBuffer, TEXT("Dynamic code -> Prohibited"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
            if (Policies.DynamicCodePolicy.AuditProhibitDynamicCode) {
                _strcpy(szBuffer, TEXT("Dynamic code -> Audit prohibit"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
            if (Policies.DynamicCodePolicy.AllowThreadOptOut) {
                _strcpy(szBuffer, TEXT("Dynamic code -> Allow thread opt out"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
            if (Policies.DynamicCodePolicy.AllowRemoteDowngrade) {
                _strcpy(szBuffer, TEXT("Dynamic code -> Allow remote downgrade"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
        }
    }

    //
    // Strict handle check.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessStrictHandleCheckPolicy,
        sizeof(PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY),
        &Policies.StrictHandleCheckPolicy))
    {
        if (Policies.StrictHandleCheckPolicy.Flags) {
            if (Policies.StrictHandleCheckPolicy.RaiseExceptionOnInvalidHandleReference) {
                _strcpy(szBuffer, TEXT("Strict handle checks -> Raise exception on invalid handle reference"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
            if (Policies.StrictHandleCheckPolicy.HandleExceptionsPermanentlyEnabled) {
                _strcpy(szBuffer, TEXT("Strict handle checks -> Handle exceptions permanently enabled"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
        }
    }

    //
    // System call disable.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessSystemCallDisablePolicy,
        sizeof(PPROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY),
        &Policies.SystemCallDisablePolicy))
    {
        if (Policies.SystemCallDisablePolicy.Flags) {
            if (Policies.SystemCallDisablePolicy.DisallowWin32kSystemCalls) {
                _strcpy(szBuffer, TEXT("SystemCallDisable -> Disallow Win32k calls"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
            if (Policies.SystemCallDisablePolicy.AuditDisallowWin32kSystemCalls) {
                _strcpy(szBuffer, TEXT("SystemCallDisable -> Audit disallow Win32k calls"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
        }
    }

    //
    // Extension point disable.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessExtensionPointDisablePolicy,
        sizeof(PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY),
        &Policies.ExtensionPointDisablePolicy))
    {
        if (Policies.ExtensionPointDisablePolicy.Flags) {
            if (Policies.ExtensionPointDisablePolicy.DisableExtensionPoints) {
                _strcpy(szBuffer, TEXT("Extension points disabled"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
        }
    }

    //
    // CFG.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessControlFlowGuardPolicy,
        sizeof(PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY_W10),
        &Policies.ControlFlowGuardPolicy))
    {
        if (Policies.ControlFlowGuardPolicy.Flags) {
            if (Policies.ControlFlowGuardPolicy.EnableControlFlowGuard) {
                _strcpy(szBuffer, TEXT("CF Guard"));

                if (Policies.ControlFlowGuardPolicy.EnableExportSuppression) {
                    _strcat(szBuffer, TEXT(" (Export Suppression)"));
                }
                if (Policies.ControlFlowGuardPolicy.StrictMode) {
                    _strcat(szBuffer, TEXT(" (Strict Mode)"));
                }
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
        }
    }

    //
    // Signature.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessSignaturePolicy,
        sizeof(PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_W10),
        &Policies.SignaturePolicy))
    {
        if (Policies.SignaturePolicy.Flags) {
            if (Policies.SignaturePolicy.MicrosoftSignedOnly) {
                _strcpy(szBuffer, TEXT("Signature -> Microsoft signed only"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
            if (Policies.SignaturePolicy.StoreSignedOnly) {
                _strcpy(szBuffer, TEXT("Signature -> Store signed only"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
            if (Policies.SignaturePolicy.AuditMicrosoftSignedOnly) {
                _strcpy(szBuffer, TEXT("Signature -> Audit Microsoft signed only"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
            if (Policies.SignaturePolicy.AuditStoreSignedOnly) {
                _strcpy(szBuffer, TEXT("Signature -> Audit Store signed only"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
            if (Policies.SignaturePolicy.MitigationOptIn) {
                _strcpy(szBuffer, TEXT("Signature -> Opt in"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
        }
    }

    //
    // Font disable.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessFontDisablePolicy,
        sizeof(PROCESS_MITIGATION_FONT_DISABLE_POLICY_W10),
        &Policies.FontDisablePolicy))
    {
        if (Policies.FontDisablePolicy.Flags) {
            if (Policies.FontDisablePolicy.DisableNonSystemFonts) {
                _strcpy(szBuffer, TEXT("Fonts -> Disable non system fonts"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
            if (Policies.FontDisablePolicy.AuditNonSystemFontLoading) {
                _strcpy(szBuffer, TEXT("Fonts -> Audit non system font loading"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
        }
    }

    //
    // Image load.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessImageLoadPolicy,
        sizeof(PROCESS_MITIGATION_IMAGE_LOAD_POLICY_W10),
        &Policies.ImageLoadPolicy))
    {
        if (Policies.ImageLoadPolicy.Flags) {
            if (Policies.ImageLoadPolicy.PreferSystem32Images) {
                _strcpy(szBuffer, TEXT("ImageLoad -> Prefer system32 images"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
            if (Policies.ImageLoadPolicy.NoRemoteImages) {
                _strcpy(szBuffer, TEXT("ImageLoad -> No remote images"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
            if (Policies.ImageLoadPolicy.NoLowMandatoryLabelImages) {
                _strcpy(szBuffer, TEXT("ImageLoad -> No low mandatory label images"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
            if (Policies.ImageLoadPolicy.AuditNoRemoteImages) {
                _strcpy(szBuffer, TEXT("ImageLoad -> Audit remote images"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
            if (Policies.ImageLoadPolicy.AuditNoLowMandatoryLabelImages) {
                _strcpy(szBuffer, TEXT("ImageLoad -> Audit no low mandatory label images"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
        }
    }

    //
    // Payload restriction.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessPayloadRestrictionPolicy,
        sizeof(PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY_W10),
        &Policies.PayloadRestrictionPolicy))
    {
        if (Policies.PayloadRestrictionPolicy.Flags) {

            if (Policies.PayloadRestrictionPolicy.EnableExportAddressFilter) {
                _strcpy(szBuffer, TEXT("PayloadRestriction -> Enable export address filter"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }

            if (Policies.PayloadRestrictionPolicy.AuditExportAddressFilter) {
                _strcpy(szBuffer, TEXT("PayloadRestriction -> Audit export address filter"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }

            if (Policies.PayloadRestrictionPolicy.EnableExportAddressFilterPlus) {
                _strcpy(szBuffer, TEXT("PayloadRestriction -> Enable export address filter plus"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }

            if (Policies.PayloadRestrictionPolicy.AuditExportAddressFilterPlus) {
                _strcpy(szBuffer, TEXT("PayloadRestriction -> Audit export address filter plus"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }

            if (Policies.PayloadRestrictionPolicy.EnableImportAddressFilter) {
                _strcpy(szBuffer, TEXT("PayloadRestriction -> Enable import address filter"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }

            if (Policies.PayloadRestrictionPolicy.AuditImportAddressFilter) {
                _strcpy(szBuffer, TEXT("PayloadRestriction -> Audit import address filter"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }

            if (Policies.PayloadRestrictionPolicy.EnableRopStackPivot) {
                _strcpy(szBuffer, TEXT("PayloadRestriction -> Enable rop stack pivot"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }

            if (Policies.PayloadRestrictionPolicy.AuditRopStackPivot) {
                _strcpy(szBuffer, TEXT("PayloadRestriction -> Audit rop stack pivot"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }

            if (Policies.PayloadRestrictionPolicy.EnableRopCallerCheck) {
                _strcpy(szBuffer, TEXT("PayloadRestriction -> Enable rop caller check"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }

            if (Policies.PayloadRestrictionPolicy.AuditRopCallerCheck) {
                _strcpy(szBuffer, TEXT("PayloadRestriction -> Audit rop caller check"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }

            if (Policies.PayloadRestrictionPolicy.EnableRopSimExec) {
                _strcpy(szBuffer, TEXT("PayloadRestriction -> Enable rop sim exec"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
             }

            if (Policies.PayloadRestrictionPolicy.AuditRopSimExec) {
                _strcpy(szBuffer, TEXT("PayloadRestriction -> Audit rop sim exec"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }

        }
    }

    //
    // Child process.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessChildProcessPolicy,
        sizeof(PROCESS_MITIGATION_CHILD_PROCESS_POLICY_W10),
        &Policies.ChildProcessPolicy))
    {
        if (Policies.ChildProcessPolicy.Flags) {
            if (Policies.ChildProcessPolicy.NoChildProcessCreation) {
                _strcpy(szBuffer, TEXT("ChildProcess -> No child process creation"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
            if (Policies.ChildProcessPolicy.AllowSecureProcessCreation) {
                _strcpy(szBuffer, TEXT("ChildProcess -> Allow secure process creation"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
            if (Policies.ChildProcessPolicy.AuditNoChildProcessCreation) {
                _strcpy(szBuffer, TEXT("ChildProcess -> Audit no child process creation"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
        }
    }

    //
    // Side channel.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessSideChannelIsolationPolicy,
        sizeof(PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY_W10),
        &Policies.SideChannelIsolationPolicy))
    {
        if (Policies.SideChannelIsolationPolicy.Flags) {
            if (Policies.SideChannelIsolationPolicy.DisablePageCombine) {
                _strcpy(szBuffer, TEXT("SideChannel -> Disable page combine"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
            if (Policies.SideChannelIsolationPolicy.IsolateSecurityDomain) {
                _strcpy(szBuffer, TEXT("SideChannel -> Isolate security domain"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
            if (Policies.SideChannelIsolationPolicy.SmtBranchTargetIsolation) {
                _strcpy(szBuffer, TEXT("SideChannel -> Smt branch target isolation"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }
            if (Policies.SideChannelIsolationPolicy.SpeculativeStoreBypassDisable) {
                _strcpy(szBuffer, TEXT("SideChannel -> Speculative store bypass disalbe"));
                SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
            }

        }
    }

    lResult = SendMessage(hwndCB, CB_GETCOUNT, 0, 0);
    if (lResult != CB_ERR) {
        if (lResult > 0) {
            EnableWindow(hwndCB, TRUE);
            SendMessage(hwndCB, CB_SETCURSEL, (WPARAM)0, (LPARAM)0);
        }
    }
}

/*
* propSetProcessTrustLabelInfo
*
* Purpose:
*
* Set Process Trust Label if it specified for this object.
*
*/
VOID propSetProcessTrustLabelInfo(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    BOOL bFail = TRUE;
    HANDLE hObject = NULL;

    ULONG ProtectionType = 0, ProtectionLevel = 0, i;

    LPWSTR lpType = TEXT(""), lpLevel = TEXT("");

    WCHAR szBuffer[0x100];

    //
    // Re-open current object as we need READ_CONTROL.
    //
    if (!propOpenCurrentObject(Context, &hObject, READ_CONTROL)) {
        SetDlgItemText(hwndDlg, ID_OBJECT_TRUSTLABEL, TEXT(""));
        return;
    }

    if (supQueryObjectTrustLabel(hObject,
        &ProtectionType,
        &ProtectionLevel))
    {
        szBuffer[0] = 0;

        for (i = 0; i < MAX_KNOWN_TRUSTLABEL_PROTECTIONTYPE; i++)
            if (TrustLabelProtectionType[i].dwValue == ProtectionType)
            {
                lpType = TrustLabelProtectionType[i].lpDescription;
                break;
            }

        for (i = 0; i < MAX_KNOWN_TRUSTLABEL_PROTECTIONLEVEL; i++)
            if (TrustLabelProtectionLevel[i].dwValue == ProtectionLevel)
            {
                lpLevel = TrustLabelProtectionLevel[i].lpDescription;
                break;
            }

        if ((lpType) && (lpLevel)) {
            _strcpy(szBuffer, lpType);
            _strcat(szBuffer, TEXT("-"));
            _strcat(szBuffer, lpLevel);

            ShowWindow(GetDlgItem(hwndDlg, ID_PTL_CAPTION), SW_SHOW);
            SetDlgItemText(hwndDlg, ID_OBJECT_TRUSTLABEL, szBuffer);
            bFail = FALSE;
        }
    }

    propCloseCurrentObject(Context, hObject);

    if (bFail) {
        ShowWindow(GetDlgItem(hwndDlg, ID_PTL_CAPTION), SW_HIDE);
        SetDlgItemText(hwndDlg, ID_OBJECT_TRUSTLABEL, TEXT(""));
    }
}

/*
* propSetDefaultInfo
*
* Purpose:
*
* Set information values for Basic page window, obtained from NtQueryObject calls
*
* ObjectBasicInformation and ObjectTypeInformation used
*
*/
VOID propSetDefaultInfo(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ HANDLE hObject
)
{
    BOOL     cond = FALSE;
    INT      i;
    HWND     hwndCB;
    NTSTATUS status;
    ULONG    bytesNeeded;
    WCHAR    szBuffer[100];

    OBJECT_BASIC_INFORMATION obi;
    POBJECT_TYPE_INFORMATION TypeInfo = NULL;

    if ((hObject == NULL) || (Context == NULL)) {
        return;
    }

    //
    // Query object basic information.
    //
    RtlSecureZeroMemory(&obi, sizeof(obi));
    status = NtQueryObject(hObject, ObjectBasicInformation, &obi,
        sizeof(OBJECT_BASIC_INFORMATION), &bytesNeeded);

    if (NT_SUCCESS(status)) {

        //Reference Count
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        u64tostr(obi.PointerCount, szBuffer);
        SetDlgItemText(hwndDlg, ID_OBJECT_REFC, szBuffer);

        //Handle Count
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        u64tostr(obi.HandleCount, szBuffer);
        SetDlgItemText(hwndDlg, ID_OBJECT_HANDLES, szBuffer);

        //NonPagedPoolCharge
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        u64tostr(obi.NonPagedPoolCharge, szBuffer);
        SetDlgItemText(hwndDlg, ID_OBJECT_NP_CHARGE, szBuffer);

        //PagedPoolCharge
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        u64tostr(obi.PagedPoolCharge, szBuffer);
        SetDlgItemText(hwndDlg, ID_OBJECT_PP_CHARGE, szBuffer);

        //Attributes
        hwndCB = GetDlgItem(hwndDlg, IDC_OBJECT_FLAGS);
        if (hwndCB) {
            SendMessage(hwndCB, CB_RESETCONTENT, (WPARAM)0, (LPARAM)0);
            EnableWindow(hwndCB, (obi.Attributes > 0) ? TRUE : FALSE);
            if (obi.Attributes != 0) {
                for (i = 0; i < 8; i++) {
                    if (GET_BIT(obi.Attributes, i)) SendMessage(hwndCB, CB_ADDSTRING,
                        (WPARAM)0, (LPARAM)T_ObjectFlags[i]);
                }
                SendMessage(hwndCB, CB_SETCURSEL, (WPARAM)0, (LPARAM)0);
            }
        }
    }

    //
    // Set flag bit for next usage on Type page.
    //
    do {

        bytesNeeded = 0;
        status = NtQueryObject(hObject, ObjectTypeInformation, NULL, 0, &bytesNeeded);
        if (bytesNeeded == 0) {
            SetLastError(RtlNtStatusToDosError(status));
            break;
        }

        TypeInfo = (POBJECT_TYPE_INFORMATION)supHeapAlloc(bytesNeeded + sizeof(ULONG_PTR));
        if (TypeInfo == NULL)
            break;

        status = NtQueryObject(hObject, ObjectTypeInformation, TypeInfo, bytesNeeded, &bytesNeeded);
        if (NT_SUCCESS(status)) {
            if (TypeInfo->SecurityRequired) {
                SET_BIT(Context->ObjectFlags, 3);
            }
            if (TypeInfo->MaintainHandleCount) {
                SET_BIT(Context->ObjectFlags, 4);
            }
        }
        else {
            SetLastError(RtlNtStatusToDosError(status));
        }

    } while (cond);

    if (TypeInfo) {
        supHeapFree(TypeInfo);
    }
}

/*
* propBasicQueryDirectory
*
* Purpose:
*
* Set information values for Directory object type
*
* No Additional info required
*
*/
VOID propBasicQueryDirectory(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    HANDLE hObject;

    if (Context == NULL) {
        return;
    }

    //
    // Open object directory and query info.
    //
    hObject = NULL;
    if (propOpenCurrentObject(Context, &hObject, DIRECTORY_QUERY)) {
        propSetDefaultInfo(Context, hwndDlg, hObject);
        propCloseCurrentObject(Context, hObject);
    }
}

/*
* propBasicQuerySemaphore
*
* Purpose:
*
* Set information values for Semaphore object type
*
* If ExtendedInfoAvailable is FALSE then it calls propSetDefaultInfo to set Basic page properties
*
*/
VOID propBasicQuerySemaphore(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable
)
{
    NTSTATUS  status;
    ULONG     bytesNeeded;
    HANDLE    hObject;
    WCHAR	  szBuffer[MAX_PATH + 1];

    SEMAPHORE_BASIC_INFORMATION sbi;

    SetDlgItemText(hwndDlg, ID_SEMAPHORECURRENT, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_SEMAPHOREMAXCOUNT, T_CannotQuery);

    if (Context == NULL) {
        return;
    }

    //
    // Open semaphore object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, SEMAPHORE_QUERY_STATE)) {
        return;
    }

    RtlSecureZeroMemory(&sbi, sizeof(SEMAPHORE_BASIC_INFORMATION));
    status = NtQuerySemaphore(hObject, SemaphoreBasicInformation, &sbi,
        sizeof(SEMAPHORE_BASIC_INFORMATION), &bytesNeeded);
    if (NT_SUCCESS(status)) {

        //Current count
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        ultostr(sbi.CurrentCount, szBuffer);
        SetDlgItemText(hwndDlg, ID_SEMAPHORECURRENT, szBuffer);

        //Maximum count
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        ultostr(sbi.MaximumCount, szBuffer);
        SetDlgItemText(hwndDlg, ID_SEMAPHOREMAXCOUNT, szBuffer);
    }

    //
    // Query object basic and type info if needed.
    //
    if (ExtendedInfoAvailable == FALSE) {
        propSetDefaultInfo(Context, hwndDlg, hObject);
    }

    propCloseCurrentObject(Context, hObject);
}

/*
* propBasicQueryIoCompletion
*
* Purpose:
*
* Set information values for IoCompletion object type
*
* If ExtendedInfoAvailable is FALSE then it calls propSetDefaultInfo to set Basic page properties
*
*/
VOID propBasicQueryIoCompletion(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable
)
{
    NTSTATUS status;
    ULONG    bytesNeeded;
    HANDLE   hObject;

    IO_COMPLETION_BASIC_INFORMATION iobi;

    SetDlgItemText(hwndDlg, ID_IOCOMPLETIONSTATE, T_CannotQuery);

    if (Context == NULL) {
        return;
    }

    //
    // Open IoCompletion object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, IO_COMPLETION_QUERY_STATE)) {
        return;
    }

    RtlSecureZeroMemory(&iobi, sizeof(IO_COMPLETION_BASIC_INFORMATION));
    status = NtQueryIoCompletion(hObject, IoCompletionBasicInformation, &iobi,
        sizeof(iobi), &bytesNeeded);

    if (NT_SUCCESS(status)) {
        SetDlgItemText(hwndDlg, ID_IOCOMPLETIONSTATE,
            (iobi.Depth > 0) ? TEXT("Signaled") : TEXT("Nonsignaled"));
    }

    //
    // Query object basic and type info if needed.
    //
    if (ExtendedInfoAvailable == FALSE) {
        propSetDefaultInfo(Context, hwndDlg, hObject);
    }

    propCloseCurrentObject(Context, hObject);
}

/*
* propBasicQueryTimer
*
* Purpose:
*
* Set information values for Timer object type
*
* If ExtendedInfoAvailable is FALSE then it calls propSetDefaultInfo to set Basic page properties
*
*/
VOID propBasicQueryTimer(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable
)
{
    NTSTATUS    status;
    ULONG       bytesNeeded;
    HANDLE      hObject;
    ULONGLONG   ConvertedSeconds, Hours;
    CSHORT      Minutes, Seconds;
    WCHAR       szBuffer[MAX_PATH + 1];

    TIMER_BASIC_INFORMATION tbi;

    SetDlgItemText(hwndDlg, ID_TIMERSTATE, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_TIMERREMAINING, T_CannotQuery);

    if (Context == NULL) {
        return;
    }

    //
    // Open Timer object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, TIMER_QUERY_STATE)) {
        return;
    }

    RtlSecureZeroMemory(&tbi, sizeof(TIMER_BASIC_INFORMATION));
    status = NtQueryTimer(hObject, TimerBasicInformation, &tbi,
        sizeof(TIMER_BASIC_INFORMATION), &bytesNeeded);

    if (NT_SUCCESS(status)) {

        //Timer state
        SetDlgItemText(hwndDlg, ID_TIMERSTATE,
            (tbi.TimerState) ? TEXT("Signaled") : TEXT("Nonsignaled"));

        if (tbi.TimerState != TRUE) {
            ConvertedSeconds = (tbi.RemainingTime.QuadPart / 10000000LL);
            Seconds = (CSHORT)(ConvertedSeconds % 60);
            Minutes = (CSHORT)((ConvertedSeconds / 60) % 60);
            Hours = ConvertedSeconds / 3600;

            //Timer remaining
            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            rtl_swprintf_s(szBuffer, MAX_PATH, FORMATTED_TIME_VALUE,
                Hours, Minutes, Seconds);

            SetDlgItemText(hwndDlg, ID_TIMERREMAINING, szBuffer);
        }
    }

    //
    // Query object basic and type info if needed.
    //
    if (ExtendedInfoAvailable == FALSE) {
        propSetDefaultInfo(Context, hwndDlg, hObject);
    }

    propCloseCurrentObject(Context, hObject);
}

/*
* propBasicQueryEvent
*
* Purpose:
*
* Set information values for Event object type
*
* If ExtendedInfoAvailable is FALSE then it calls propSetDefaultInfo to set Basic page properties
*
*/
VOID propBasicQueryEvent(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable
)
{
    NTSTATUS status;
    ULONG    bytesNeeded;
    HANDLE   hObject;
    LPWSTR   lpInfo;
    EVENT_BASIC_INFORMATION	ebi;

    SetDlgItemText(hwndDlg, ID_EVENTTYPE, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_EVENTSTATE, T_CannotQuery);

    if (Context == NULL) {
        return;
    }

    //
    // Open Event object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, EVENT_QUERY_STATE)) {
        return;
    }

    RtlSecureZeroMemory(&ebi, sizeof(EVENT_BASIC_INFORMATION));
    status = NtQueryEvent(hObject, EventBasicInformation, &ebi,
        sizeof(EVENT_BASIC_INFORMATION), &bytesNeeded);

    if (NT_SUCCESS(status)) {

        //Event type
        switch (ebi.EventType) {
        case NotificationEvent:
            lpInfo = TEXT("Notification");
            break;
        case SynchronizationEvent:
            lpInfo = TEXT("Synchronization");
            break;
        default:
            lpInfo = T_UnknownType;
            break;
        }
        SetDlgItemText(hwndDlg, ID_EVENTTYPE, lpInfo);

        //Event state
        switch (ebi.EventState) {
        case 0:
            lpInfo = TEXT("Nonsignaled");
            break;
        case 1:
            lpInfo = TEXT("Signaled");
            break;
        default:
            lpInfo = TEXT("UnknownState");
            break;
        }
        SetDlgItemText(hwndDlg, ID_EVENTSTATE, lpInfo);
    }

    //
    // Query object basic and type info if needed.
    //
    if (ExtendedInfoAvailable == FALSE) {
        propSetDefaultInfo(Context, hwndDlg, hObject);
    }

    propCloseCurrentObject(Context, hObject);
}

/*
* propBasicQuerySymlink
*
* Purpose:
*
* Set information values for SymbolicLink object type
*
* If ExtendedInfoAvailable is FALSE then it calls propSetDefaultInfo to set Basic page properties
*
*/
VOID propBasicQuerySymlink(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable
)
{
    NTSTATUS    status;
    ULONG       bytesNeeded;
    HANDLE      hObject;
    LPWSTR      lpLinkTarget;
    WCHAR       szBuffer[MAX_PATH + 1];

    OBJECT_BASIC_INFORMATION obi;

    SetDlgItemText(hwndDlg, ID_OBJECT_SYMLINK_TARGET, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_OBJECT_SYMLINK_CREATION, T_CannotQuery);

    if (Context == NULL) {
        return;
    }

    //
    // Open SymbolicLink object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, SYMBOLIC_LINK_QUERY)) {
        return;
    }

    //
    // Copy link target from main object list for performance reasons.
    // So we don't need to query same data again.
    //
    lpLinkTarget = Context->lpDescription;
    if (lpLinkTarget) {
        SetDlgItemText(hwndDlg, ID_OBJECT_SYMLINK_TARGET, lpLinkTarget);
    }

    //Query Link Creation Time
    RtlSecureZeroMemory(&obi, sizeof(OBJECT_BASIC_INFORMATION));

    status = NtQueryObject(hObject, ObjectBasicInformation, &obi,
        sizeof(OBJECT_BASIC_INFORMATION), &bytesNeeded);

    if (NT_SUCCESS(status)) {
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        if (supPrintTimeConverted(&obi.CreationTime, szBuffer, MAX_PATH))
            SetDlgItemText(hwndDlg, ID_OBJECT_SYMLINK_CREATION, szBuffer);
    }

    //
    // Query object basic and type info if needed.
    //
    if (ExtendedInfoAvailable == FALSE) {
        propSetDefaultInfo(Context, hwndDlg, hObject);
    }

    propCloseCurrentObject(Context, hObject);
}

/*
* propBasicQueryKey
*
* Purpose:
*
* Set information values for Key object type
*
* If ExtendedInfoAvailable is FALSE then it calls propSetDefaultInfo to set Basic page properties
*
*/
VOID propBasicQueryKey(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable
)
{
    NTSTATUS    status;
    ULONG       bytesNeeded;
    HANDLE      hObject;
    WCHAR       szBuffer[MAX_PATH];

    KEY_FULL_INFORMATION  kfi;

    SetDlgItemText(hwndDlg, ID_KEYSUBKEYS, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_KEYVALUES, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_KEYLASTWRITE, T_CannotQuery);

    if (Context == NULL) {
        return;
    }

    //
    // Open Key object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, KEY_QUERY_VALUE)) {
        return;
    }

    RtlSecureZeroMemory(&kfi, sizeof(KEY_FULL_INFORMATION));
    status = NtQueryKey(hObject, KeyFullInformation, &kfi,
        sizeof(KEY_FULL_INFORMATION), &bytesNeeded);

    if (NT_SUCCESS(status)) {

        //Subkeys count
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        ultostr(kfi.SubKeys, _strend(szBuffer));
        SetDlgItemText(hwndDlg, ID_KEYSUBKEYS, szBuffer);

        //Values count
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        ultostr(kfi.Values, _strend(szBuffer));
        SetDlgItemText(hwndDlg, ID_KEYVALUES, szBuffer);

        //LastWrite time
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        if (supPrintTimeConverted(&kfi.LastWriteTime, szBuffer, MAX_PATH))
            SetDlgItemText(hwndDlg, ID_KEYLASTWRITE, szBuffer);
    }

    //
    // Query object basic and type info if needed.
    //
    if (ExtendedInfoAvailable == FALSE) {
        propSetDefaultInfo(Context, hwndDlg, hObject);
    }

    propCloseCurrentObject(Context, hObject);
}

/*
* propBasicQueryMutant
*
* Purpose:
*
* Set information values for Mutant object type
*
* If ExtendedInfoAvailable is FALSE then it calls propSetDefaultInfo to set Basic page properties
*
*/
VOID propBasicQueryMutant(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable
)
{
    NTSTATUS status;
    ULONG    bytesNeeded;
    HANDLE   hObject;
    WCHAR    szBuffer[MAX_PATH];

    MUTANT_BASIC_INFORMATION mbi;

    SetDlgItemText(hwndDlg, ID_MUTANTABANDONED, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_MUTANTSTATE, T_CannotQuery);

    if (Context == NULL) {
        return;
    }

    //
    // Open Mutant object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, MUTANT_QUERY_STATE)) {
        return;
    }

    RtlSecureZeroMemory(&mbi, sizeof(MUTANT_BASIC_INFORMATION));

    status = NtQueryMutant(hObject, MutantBasicInformation, &mbi,
        sizeof(MUTANT_BASIC_INFORMATION), &bytesNeeded);
    if (NT_SUCCESS(status)) {

        //Abandoned
        SetDlgItemText(hwndDlg, ID_MUTANTABANDONED, (mbi.AbandonedState) ? TEXT("Yes") : TEXT("No"));

        //State
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        if (mbi.OwnedByCaller) {
            rtl_swprintf_s(szBuffer, MAX_PATH, TEXT("Held recursively %d times"), mbi.CurrentCount);
        }
        else {
            _strcpy(szBuffer, TEXT("Not Held"));
        }
        SetDlgItemText(hwndDlg, ID_MUTANTSTATE, szBuffer);
    }

    //
    // Query object basic and type info if needed.
    //
    if (ExtendedInfoAvailable == FALSE) {
        propSetDefaultInfo(Context, hwndDlg, hObject);
    }
    propCloseCurrentObject(Context, hObject);
}

#ifndef IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG
#define IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG 17
#endif

/*
* propBasicQuerySection
*
* Purpose:
*
* Set information values for Section object type
*
* If ExtendedInfoAvailable is FALSE then it calls propSetDefaultInfo to set Basic page properties
*
*/
VOID propBasicQuerySection(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable
)
{
    BOOL      bSet;
    NTSTATUS  status;
    HANDLE    hObject;
    SIZE_T    bytesNeeded;
    LPWSTR    lpType;
    WCHAR     szBuffer[MAX_PATH * 2];

    SECTION_BASIC_INFORMATION sbi;
    SECTION_IMAGE_INFORMATION sii;

    ENUMCHILDWNDDATA ChildWndData;

    SetDlgItemText(hwndDlg, ID_SECTION_ATTR, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_SECTIONSIZE, T_CannotQuery);

    if (Context == NULL) {
        return;
    }

    //
    // Open Section object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, SECTION_QUERY)) {
        return;
    }

    //this is for specific mars warning, mars doesn't recognize __stosb intrinsics
    szBuffer[0] = 0;

    //query basic information
    RtlSecureZeroMemory(&sbi, sizeof(SECTION_BASIC_INFORMATION));
    status = NtQuerySection(hObject, SectionBasicInformation, &sbi,
        sizeof(SECTION_BASIC_INFORMATION), &bytesNeeded);

    if (NT_SUCCESS(status)) {

        bSet = FALSE;
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        if (sbi.AllocationAttributes & SEC_BASED) {
            _strcat(szBuffer, TEXT("Based"));
            bSet = TRUE;
        }
        if (sbi.AllocationAttributes & SEC_NO_CHANGE) {
            if (bSet) _strcat(szBuffer, TEXT(" + "));
            _strcat(szBuffer, TEXT("NoChange"));
            bSet = TRUE;
        }
        if (sbi.AllocationAttributes & SEC_FILE) {
            if (bSet) _strcat(szBuffer, TEXT(" + "));
            _strcat(szBuffer, TEXT("File"));
            bSet = TRUE;
        }
        if (sbi.AllocationAttributes & SEC_IMAGE) {
            if (bSet) _strcat(szBuffer, TEXT(" + "));
            _strcat(szBuffer, TEXT("Image"));
            bSet = TRUE;
        }
        if (sbi.AllocationAttributes & SEC_RESERVE) {
            if (bSet) _strcat(szBuffer, TEXT(" + "));
            _strcat(szBuffer, TEXT("Reserve"));
            bSet = TRUE;
        }
        if (sbi.AllocationAttributes & SEC_COMMIT) {
            if (bSet) _strcat(szBuffer, TEXT(" + "));
            _strcat(szBuffer, TEXT("Commit"));
            bSet = TRUE;
        }
        if (sbi.AllocationAttributes & SEC_NOCACHE) {
            if (bSet) _strcat(szBuffer, TEXT(" + "));
            _strcat(szBuffer, TEXT("NoCache"));
            bSet = TRUE;
        }
        if (sbi.AllocationAttributes & SEC_GLOBAL) {
            if (bSet) _strcat(szBuffer, TEXT(" + "));
            _strcat(szBuffer, TEXT("Global"));
            bSet = TRUE;
        }
        if (sbi.AllocationAttributes & SEC_LARGE_PAGES) {
            if (bSet) _strcat(szBuffer, TEXT(" + "));
            _strcat(szBuffer, TEXT("LargePages"));
        }
        SetDlgItemText(hwndDlg, ID_SECTION_ATTR, szBuffer);

        //Size
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        rtl_swprintf_s(szBuffer, MAX_PATH, TEXT("0x%I64X"), sbi.MaximumSize.QuadPart);
        SetDlgItemText(hwndDlg, ID_SECTIONSIZE, szBuffer);

        //query image information
        if ((sbi.AllocationAttributes & SEC_IMAGE) && (sbi.AllocationAttributes & SEC_FILE)) {

            RtlSecureZeroMemory(&sii, sizeof(SECTION_IMAGE_INFORMATION));
            status = NtQuerySection(hObject, SectionImageInformation, &sii,
                sizeof(SECTION_IMAGE_INFORMATION), &bytesNeeded);

            if (NT_SUCCESS(status)) {

                //show hidden controls
                if (GetWindowRect(GetDlgItem(hwndDlg, ID_IMAGEINFO), &ChildWndData.Rect)) {
                    ChildWndData.nCmdShow = SW_SHOW;
                    EnumChildWindows(hwndDlg, supCallbackShowChildWindow, (LPARAM)&ChildWndData);
                }

                //Entry			
                RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
                rtl_swprintf_s(szBuffer, MAX_PATH, TEXT("0x%I64X"), (ULONG_PTR)sii.TransferAddress);
                SetDlgItemText(hwndDlg, ID_IMAGE_ENTRY, szBuffer);

                //Stack Reserve
                RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
                rtl_swprintf_s(szBuffer, MAX_PATH, TEXT("0x%I64X"), sii.MaximumStackSize);
                SetDlgItemText(hwndDlg, ID_IMAGE_STACKRESERVE, szBuffer);

                //Stack Commit
                RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
                rtl_swprintf_s(szBuffer, MAX_PATH, TEXT("0x%I64X"), sii.CommittedStackSize);
                SetDlgItemText(hwndDlg, ID_IMAGE_STACKCOMMIT, szBuffer);

                //Executable			
                SetDlgItemText(hwndDlg, ID_IMAGE_EXECUTABLE,
                    (sii.ImageContainsCode) ? TEXT("Yes") : TEXT("No"));

                //Subsystem
                lpType = TEXT("Unknown");
                switch (sii.SubSystemType) {
                case IMAGE_SUBSYSTEM_NATIVE:
                    lpType = TEXT("Native");
                    break;
                case IMAGE_SUBSYSTEM_WINDOWS_GUI:
                    lpType = TEXT("Windows GUI");
                    break;
                case IMAGE_SUBSYSTEM_WINDOWS_CUI:
                    lpType = TEXT("Windows Console");
                    break;
                case IMAGE_SUBSYSTEM_OS2_CUI:
                    lpType = TEXT("OS/2 Console");
                    break;
                case IMAGE_SUBSYSTEM_POSIX_CUI:
                    lpType = TEXT("Posix Console");
                    break;
                case IMAGE_SUBSYSTEM_XBOX:
                    lpType = TEXT("XBox");
                    break;
                case IMAGE_SUBSYSTEM_EFI_APPLICATION:
                    lpType = TEXT("EFI Application");
                    break;
                case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
                    lpType = TEXT("EFI Boot Service Driver");
                    break;
                case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
                    lpType = TEXT("EFI Runtime Driver");
                    break;
                case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
                    lpType = TEXT("Windows Boot Application");
                    break;
                case IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG:
                    lpType = TEXT("XBox Code Catalog");
                    break;
                }
                SetDlgItemText(hwndDlg, ID_IMAGE_SUBSYSTEM, lpType);

                //Major Version
                RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
                ultostr(sii.SubSystemMajorVersion, _strend(szBuffer));
                SetDlgItemText(hwndDlg, ID_IMAGE_MJV, szBuffer);

                //Minor Version
                RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
                ultostr(sii.SubSystemMinorVersion, _strend(szBuffer));
                SetDlgItemText(hwndDlg, ID_IMAGE_MNV, szBuffer);
            }
        }
    }

    //
    // Query object basic and type info if needed.
    //
    if (ExtendedInfoAvailable == FALSE) {
        propSetDefaultInfo(Context, hwndDlg, hObject);
    }
    propCloseCurrentObject(Context, hObject);
}

/*
* propBasicQueryWindowStation
*
* Purpose:
*
* Set information values for WindowStation object type (managed by win32k services)
*
* If ExtendedInfoAvailable is FALSE then it calls propSetDefaultInfo to set Basic page properties
*
*/
VOID propBasicQueryWindowStation(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable
)
{
    DWORD           bytesNeeded;
    HWINSTA         hObject;
    USEROBJECTFLAGS userFlags;

    SetDlgItemText(hwndDlg, ID_WINSTATIONVISIBLE, T_CannotQuery);

    if (Context == NULL) {
        return;
    }

    //
    // Open Winstation object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, (PHANDLE)&hObject, WINSTA_READATTRIBUTES)) {
        return;
    }

    RtlSecureZeroMemory(&userFlags, sizeof(userFlags));
    if (GetUserObjectInformation(hObject, UOI_FLAGS, &userFlags,
        sizeof(USEROBJECTFLAGS), &bytesNeeded))
    {
        SetDlgItemText(hwndDlg, ID_WINSTATIONVISIBLE,
            (userFlags.dwFlags & WSF_VISIBLE) ? TEXT("Yes") : TEXT("No"));
    }

    //
    // Query object basic and type info if needed.
    //
    if (ExtendedInfoAvailable == FALSE) {
        propSetDefaultInfo(Context, hwndDlg, hObject);
    }

    propCloseCurrentObject(Context, hObject);
}

/*
* propBasicQueryDriver
*
* Purpose:
*
* Set information values for Driver object type
*
* Viewing \Drivers subdirectory requires full access token
*
*/
VOID propBasicQueryDriver(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    LPWSTR lpItemText;
    ENUMCHILDWNDDATA ChildWndData;

    if (Context == NULL) {
        return;
    }

    //
    // For performance reasons instead of query again
    // we use description from main object list.
    //
    lpItemText = Context->lpDescription;
    if (lpItemText) {
        //show hidden controls
        if (GetWindowRect(GetDlgItem(hwndDlg, ID_DRIVERINFO), &ChildWndData.Rect)) {
            ChildWndData.nCmdShow = SW_SHOW;
            EnumChildWindows(hwndDlg, supCallbackShowChildWindow, (LPARAM)&ChildWndData);
        }
        SetDlgItemText(hwndDlg, ID_DRIVERDISPLAYNAME, lpItemText);
    }
}

/*
* propBasicQueryDevice
*
* Purpose:
*
* Set information values for Device object type
*
*/
VOID propBasicQueryDevice(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    LPWSTR lpItemText;
    ENUMCHILDWNDDATA ChildWndData;

    if (Context == NULL) {
        return;
    }

    //
    // For performance reasons instead of query again
    // we use description from main object list.
    //
    lpItemText = Context->lpDescription;
    if (lpItemText) {
        //show hidden controls
        if (GetWindowRect(GetDlgItem(hwndDlg, ID_DEVICEINFO), &ChildWndData.Rect)) {
            ChildWndData.nCmdShow = SW_SHOW;
            EnumChildWindows(hwndDlg, supCallbackShowChildWindow, (LPARAM)&ChildWndData);
        }
        SetDlgItemText(hwndDlg, ID_DEVICEDESCRIPTION, lpItemText);
    }
}

/*
* propBasicQueryMemoryPartition
*
* Purpose:
*
* Set information values for Partition object type
*
*/
VOID propBasicQueryMemoryPartition(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    HANDLE hObject;

    if (Context == NULL) {
        return;
    }

    //
    // Open Memory Partition object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, MEMORY_PARTITION_QUERY_ACCESS))
        return;

    //
    // Query object basic and type info if needed.
    //
    propSetDefaultInfo(Context, hwndDlg, hObject);
    propCloseCurrentObject(Context, hObject);
}

/*
* propBasicQueryProcess
*
* Purpose:
*
* Set information values for Process object type
*
*/
VOID propBasicQueryProcess(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable
)
{
    BOOL ProcessParametersRead = FALSE;
    BOOL RemotePebRead = FALSE;
    BOOL bSuccess = FALSE;

    ULONG i, BreakOnTermination = 0, memIO;
    HANDLE hObject;
    PROCESS_EXTENDED_BASIC_INFORMATION exbi;
    RTL_USER_PROCESS_PARAMETERS UserProcessParameters;
    PEB RemotePeb;

    PUNICODE_STRING dynUstr;
    SIZE_T readBytes;

    PS_PROTECTION PsProtection;

    HWND hwndCB;

    LPWSTR Name;
    PBYTE Buffer;
    WCHAR szBuffer[100];
    KERNEL_USER_TIMES KernelUserTimes;

    if (Context == NULL) {
        return;
    }

    //
    // Open Process object.
    //
    hObject = NULL;

    bSuccess = propOpenCurrentObject(Context, &hObject, MAXIMUM_ALLOWED);
    if (!bSuccess) {
        bSuccess = propOpenCurrentObject(Context, &hObject, PROCESS_QUERY_INFORMATION);
        if (!bSuccess) {
            bSuccess = propOpenCurrentObject(Context, &hObject, PROCESS_QUERY_LIMITED_INFORMATION);
        }
    }
    if (bSuccess) {

        RtlSecureZeroMemory(&UserProcessParameters, sizeof(UserProcessParameters));
        RtlSecureZeroMemory(&exbi, sizeof(exbi));

        exbi.Size = sizeof(PROCESS_EXTENDED_BASIC_INFORMATION);

        if (NT_SUCCESS(NtQueryInformationProcess(hObject,
            ProcessBasicInformation,
            (PVOID)&exbi,
            sizeof(PROCESS_EXTENDED_BASIC_INFORMATION),
            &i)))
        {
            //
            // Start time.
            //
            RtlSecureZeroMemory(&KernelUserTimes, sizeof(KERNEL_USER_TIMES));
            NtQueryInformationProcess(hObject, ProcessTimes, 
                (PVOID)&KernelUserTimes, sizeof(KERNEL_USER_TIMES), &i);

            SetDlgItemText(hwndDlg, IDC_PROCESS_STARTED, T_CannotQuery);

            RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
            if (supPrintTimeConverted(
                &KernelUserTimes.CreateTime,
                szBuffer,
                sizeof(szBuffer) / sizeof(szBuffer[0])))
            {
                SetDlgItemText(hwndDlg, IDC_PROCESS_STARTED, szBuffer);
            }

            //
            // Process type flags
            //
            hwndCB = GetDlgItem(hwndDlg, IDC_PROCESS_TYPE_FLAGS);

            EnableWindow(hwndCB, (exbi.Flags > 0) ? TRUE : FALSE);
            SendMessage(hwndCB, CB_RESETCONTENT, (WPARAM)0, (LPARAM)0);
            if (exbi.Flags > 0) {
                for (i = 0; i < MAX_KNOWN_PROCESS_TYPE_FLAGS; i++) {

                    if (GET_BIT(exbi.Flags, i))

                        SendMessage(hwndCB,
                            CB_ADDSTRING,
                            (WPARAM)0,
                            (LPARAM)T_ProcessTypeFlags[i]);
                }
                SendMessage(hwndCB, CB_SETCURSEL, (WPARAM)0, (LPARAM)0);
            }

            if (exbi.BasicInfo.PebBaseAddress) {

                RtlSecureZeroMemory(&RemotePeb, sizeof(PEB));

                RemotePebRead = NT_SUCCESS(NtReadVirtualMemory(
                    hObject,
                    exbi.BasicInfo.PebBaseAddress,
                    &RemotePeb,
                    sizeof(PEB),
                    &readBytes));

                if (RemotePebRead) {

                    ProcessParametersRead = (NT_SUCCESS(NtReadVirtualMemory(
                        hObject,
                        (PVOID)RemotePeb.ProcessParameters,
                        &UserProcessParameters,
                        sizeof(RTL_USER_PROCESS_PARAMETERS),
                        &readBytes)));
                }
            }
        }

        //
        // Process image file.
        //
        bSuccess = FALSE;
        memIO = 0;
        NtQueryInformationProcess(hObject, ProcessImageFileNameWin32, NULL, 0, &memIO);
        if (memIO) {

            Buffer = (PBYTE)supHeapAlloc((SIZE_T)memIO);
            if (Buffer) {

                if (NT_SUCCESS(NtQueryInformationProcess(
                    hObject,
                    ProcessImageFileNameWin32,
                    (PVOID)Buffer,
                    memIO,
                    &memIO)))
                {
                    dynUstr = (PUNICODE_STRING)Buffer;
                    if ((dynUstr->Length) && (dynUstr->MaximumLength)) {

                        Name = (LPWSTR)supHeapAlloc(sizeof(UNICODE_NULL) + dynUstr->MaximumLength);
                        if (Name) {

                            RtlCopyMemory(Name, dynUstr->Buffer, dynUstr->Length);
                            SetDlgItemText(hwndDlg, IDC_PROCESS_FILENAME, Name);
                            EnableWindow(GetDlgItem(hwndDlg, IDC_PROCESS_BROWSE), TRUE);
                            bSuccess = TRUE;

                            supHeapFree(Name);
                            Name = NULL;
                        }
                    }
                }
                supHeapFree(Buffer);
            }
        }

        if (bSuccess == FALSE) {
            SetDlgItemText(hwndDlg, IDC_PROCESS_FILENAME, T_COULD_NOT_QUERY);
        }

        //
        // Process Command Line.
        //
        bSuccess = FALSE;
        if (g_WinObj.osver.dwBuildNumber >= 9600) {
            //
            // Use new NtQIP info class to get command line.
            //
            memIO = 0;
            NtQueryInformationProcess(hObject, ProcessCommandLineInformation, NULL, 0, &memIO);
            if (memIO) {
                Buffer = (PBYTE)supHeapAlloc((SIZE_T)memIO);
                if (Buffer) {

                    if (NT_SUCCESS(NtQueryInformationProcess(
                        hObject,
                        ProcessCommandLineInformation,
                        (PVOID)Buffer,
                        memIO,
                        &memIO)))
                    {
                        dynUstr = (PUNICODE_STRING)Buffer;
                        if ((dynUstr->Length) && (dynUstr->MaximumLength)) {

                            Name = (LPWSTR)supHeapAlloc((SIZE_T)dynUstr->MaximumLength + sizeof(UNICODE_NULL));
                            if (Name) {

                                RtlCopyMemory(Name, dynUstr->Buffer, dynUstr->Length);

                                SetDlgItemText(hwndDlg, IDC_PROCESS_CMDLINE, Name);
                                bSuccess = TRUE;

                                supHeapFree(Name);
                                Name = NULL;
                            }
                        }
                    }
                    supHeapFree(Buffer);
                }
            }
        }
        else {
            //
            // Read command line from PEB.
            //
            if (ProcessParametersRead) {

                readBytes = UserProcessParameters.CommandLine.MaximumLength;
                Buffer = (PBYTE)supHeapAlloc(readBytes + sizeof(UNICODE_NULL));
                if (Buffer) {

                    if (NT_SUCCESS(NtReadVirtualMemory(
                        hObject,
                        UserProcessParameters.CommandLine.Buffer,
                        Buffer,
                        UserProcessParameters.CommandLine.Length,
                        &readBytes)))
                    {
                        SetDlgItemText(hwndDlg, IDC_PROCESS_CMDLINE, (LPCWSTR)Buffer);
                        bSuccess = TRUE;
                    }

                    supHeapFree(Buffer);
                }
            }
        }

        if (bSuccess == FALSE) {
            SetDlgItemText(hwndDlg, IDC_PROCESS_CMDLINE, T_COULD_NOT_QUERY);
        }

        //
        // Process Current Directory.
        //
        bSuccess = FALSE;
        if (ProcessParametersRead) {
            readBytes = UserProcessParameters.CurrentDirectory.DosPath.MaximumLength;
            Buffer = (PBYTE)supHeapAlloc(readBytes + sizeof(UNICODE_NULL));
            if (Buffer) {

                if (NT_SUCCESS(NtReadVirtualMemory(
                    hObject,
                    UserProcessParameters.CurrentDirectory.DosPath.Buffer,
                    Buffer,
                    readBytes,
                    &readBytes)))
                {
                    SetDlgItemText(hwndDlg, IDC_PROCESS_CURDIR, (LPCWSTR)Buffer);
                    bSuccess = TRUE;
                }

                supHeapFree(Buffer);
            }
        }

        if (bSuccess == FALSE) {
            SetDlgItemText(hwndDlg, IDC_PROCESS_CURDIR, T_COULD_NOT_QUERY);
        }

        //
        // Protection
        //
        PsProtection.Level = 0;
        if (NT_SUCCESS(NtQueryInformationProcess(
            hObject,
            ProcessProtectionInformation,
            &PsProtection,
            sizeof(ULONG),
            &i)))
        {
            if (PsProtection.Level) {

                if (PsProtection.Type < MAX_KNOWN_PS_PROTECTED_TYPE)
                    Name = T_PSPROTECTED_TYPE[PsProtection.Type];
                else
                    Name = T_Unknown;

                _strcpy(szBuffer, Name);
                _strcat(szBuffer, TEXT("-"));

                if (PsProtection.Signer < MAX_KNOWN_PS_PROTECTED_SIGNER)
                    Name = T_PSPROTECTED_SIGNER[PsProtection.Signer];
                else
                    Name = T_Unknown;

                _strcat(szBuffer, Name);

                SetDlgItemText(hwndDlg, IDC_PROCESS_PROTECTION, szBuffer);
            }
        }

        //
        // Critical Process
        //
        if (NT_SUCCESS(NtQueryInformationProcess(
            hObject,
            ProcessBreakOnTermination,
            &BreakOnTermination,
            sizeof(ULONG),
            &i)))
        {
            SetDlgItemText(hwndDlg, IDC_PROCESS_CRITICAL,
                (BreakOnTermination != 0) ? TEXT("Yes") : TEXT("No"));
        }

        //
        // Mitigations
        //
        propSetProcessMitigationsInfo(hObject, exbi.IsWow64Process, hwndDlg);

        //
        // Query object basic and type info if needed.
        //
        if (ExtendedInfoAvailable == FALSE) {
            propSetDefaultInfo(Context, hwndDlg, hObject);
        }
        propCloseCurrentObject(Context, hObject);
    }
}

/*
* propBasicQueryThread
*
* Purpose:
*
* Set information values for Thread object type
*
*/
VOID propBasicQueryThread(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable
)
{
    BOOL bSuccess;
    ULONG i, dummy;
    HANDLE hObject;
    
    TIME_FIELDS TimeFields;

    WCHAR szBuffer[100];

    PSYSTEM_THREAD_INFORMATION Thread;

    PROCESSOR_NUMBER IdealProcessor;

    if (Context == NULL) {
        return;
    }

    Thread = &Context->UnnamedObjectInfo.ThreadInformation;

    //
    // Open Thread object.
    //
    hObject = NULL;
    bSuccess = propOpenCurrentObject(Context, &hObject, MAXIMUM_ALLOWED);
    if (!bSuccess) {
        bSuccess = propOpenCurrentObject(Context, &hObject, THREAD_QUERY_INFORMATION);
        if (!bSuccess) {
            bSuccess = propOpenCurrentObject(Context, &hObject, THREAD_QUERY_LIMITED_INFORMATION);
        }
    }
    if (bSuccess) {

        //
        // Start time.
        //
        SetDlgItemText(hwndDlg, IDC_THREAD_STARTED, T_CannotQuery);

        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        if (supPrintTimeConverted(
            &Thread->CreateTime,
            szBuffer,
            sizeof(szBuffer) / sizeof(szBuffer[0])))
        {
            SetDlgItemText(hwndDlg, IDC_THREAD_STARTED, szBuffer);
        }

        //
        // Kernel/User time.
        //
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        RtlTimeToTimeFields(&Thread->KernelTime, &TimeFields);
        rtl_swprintf_s(szBuffer, MAX_PATH, FORMATTED_TIME_VALUE_MS,
            TimeFields.Hour,
            TimeFields.Minute,
            TimeFields.Second,
            TimeFields.Milliseconds);
        SetDlgItemText(hwndDlg, IDC_THREAD_KERNELTIME, szBuffer);

        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        RtlTimeToTimeFields(&Thread->UserTime, &TimeFields);
        rtl_swprintf_s(szBuffer, MAX_PATH, FORMATTED_TIME_VALUE_MS,
            TimeFields.Hour,
            TimeFields.Minute,
            TimeFields.Second,
            TimeFields.Milliseconds);
        SetDlgItemText(hwndDlg, IDC_THREAD_USERTIME, szBuffer);

        //
        // Context switches.
        //
        szBuffer[0] = 0;
        ultostr(Thread->ContextSwitchCount, szBuffer);
        SetDlgItemText(hwndDlg, IDC_THREAD_CONTEXTSWITCHES, szBuffer);

        //
        // Priority.
        //
        szBuffer[0] = 0;
        ultostr(Thread->BasePriority, szBuffer);
        SetDlgItemText(hwndDlg, IDC_THREAD_BASEPRIORITY, szBuffer);
        szBuffer[0] = 0;
        ultostr(Thread->Priority, szBuffer);
        SetDlgItemText(hwndDlg, IDC_THREAD_DYNPRIORITY, szBuffer);

        //
        // Ideal processor.
        //
        if (NT_SUCCESS(NtQueryInformationThread(hObject, ThreadIdealProcessorEx,
            (PVOID)&IdealProcessor, sizeof(PROCESSOR_NUMBER), &dummy)))
        {
            szBuffer[0] = 0;
            ultostr(IdealProcessor.Number, szBuffer);
            SetDlgItemText(hwndDlg, IDC_THREAD_IDEALPROCESSOR, szBuffer);
        }

        //
        // Is thread critical.
        //
        i = 0;
        if (NT_SUCCESS(NtQueryInformationThread(hObject, ThreadBreakOnTermination,
            (PVOID)&i, sizeof(ULONG), &dummy)))
        {
            SetDlgItemText(hwndDlg, IDC_THREAD_CRITICAL, (i > 0) ? TEXT("Yes") : TEXT("No"));
        }


        //
        // Query object basic and type info if needed.
        //
        if (ExtendedInfoAvailable == FALSE) {
            propSetDefaultInfo(Context, hwndDlg, hObject);
        }
        propCloseCurrentObject(Context, hObject);
    }
}

/*
* propBasicQueryAlpcPort
*
* Purpose:
*
* Set information values for AlpcPort object type
*
*/
VOID propBasicQueryAlpcPort(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    ULONG_PTR OwnerProcess;
    ULONG ObjectSize = 0, ObjectVersion = 0;
    PVOID ProcessList;

    WCHAR szBuffer[MAX_PATH * 2];

    union {
        union {
            ALPC_PORT_7600 *Port7600;
            ALPC_PORT_9200 *Port9200;
            ALPC_PORT_9600 *Port9600;
            ALPC_PORT_10240 *Port10240;
        } u1;
        PBYTE Ref;
    } AlpcPort;

    if (Context == NULL) {
        return;
    }

    AlpcPort.Ref = (PBYTE)ObDumpAlpcPortObjectVersionAware(Context->ObjectInfo.ObjectAddress,
        &ObjectSize,
        &ObjectVersion);

    if (AlpcPort.Ref == NULL)
        return;

    //
    // Determine owner process.
    //
    OwnerProcess = (ULONG_PTR)AlpcPort.u1.Port7600->OwnerProcess;
    if (OwnerProcess) {
        szBuffer[0] = L'0';
        szBuffer[1] = L'x';
        szBuffer[2] = 0;
        u64tohex(OwnerProcess, &szBuffer[2]);

        _strcat(szBuffer, TEXT(" ("));

        ProcessList = supGetSystemInfo(SystemProcessInformation, NULL);
        if (ProcessList) {

            if (!supQueryProcessNameByEPROCESS(
                OwnerProcess,
                ProcessList,
                _strend(szBuffer),
                MAX_PATH))
            {
                _strcat(szBuffer, T_CannotQuery);
            }
            supHeapFree(ProcessList);
        }
        else {
            _strcat(szBuffer, T_CannotQuery);
        }
        _strcat(szBuffer, TEXT(")"));
    }
    else {
        _strcpy(szBuffer, T_CannotQuery);
    }
    SetDlgItemText(hwndDlg, ID_ALPC_OWNERPROCESS, szBuffer);

    supVirtualFree(AlpcPort.Ref);
}

/*
* propBasicQueryJob
*
* Purpose:
*
* Set information values for Job object type
*
* If ExtendedInfoAvailable is FALSE then it calls propSetDefaultInfo to set Basic page properties
*
*/
VOID propBasicQueryJob(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable
)
{
    BOOL        cond = FALSE;
    DWORD       i;
    HWND        hwndCB;
    HANDLE      hObject;
    NTSTATUS    status;
    ULONG       bytesNeeded;
    ULONG_PTR   ProcessId;
    PVOID       ProcessList;
    WCHAR       szProcessName[MAX_PATH + 1];
    WCHAR       szBuffer[MAX_PATH * 2];
    TIME_FIELDS SystemTime;

    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION jbai;
    PJOBOBJECT_BASIC_PROCESS_ID_LIST       pJobProcList;

    SetDlgItemText(hwndDlg, ID_JOBTOTALPROCS, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_JOBACTIVEPROCS, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_JOBTERMINATEDPROCS, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_JOBTOTALUMTIME, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_JOBTOTALKMTIME, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_JOBTOTALPF, T_CannotQuery);

    if (Context == NULL) {
        return;
    }

    //
    // Open Job object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, JOB_OBJECT_QUERY)) {
        return;
    }

    //query basic information
    RtlSecureZeroMemory(&jbai, sizeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
    status = NtQueryInformationJobObject(hObject, JobObjectBasicAccountingInformation,
        &jbai, sizeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION), &bytesNeeded);
    if (NT_SUCCESS(status)) {

        //Total processes
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        ultostr(jbai.TotalProcesses, szBuffer);
        SetDlgItemText(hwndDlg, ID_JOBTOTALPROCS, szBuffer);

        //Active processes
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        ultostr(jbai.ActiveProcesses, szBuffer);
        SetDlgItemText(hwndDlg, ID_JOBACTIVEPROCS, szBuffer);

        //Terminated processes
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        ultostr(jbai.TotalTerminatedProcesses, szBuffer);
        SetDlgItemText(hwndDlg, ID_JOBTERMINATEDPROCS, szBuffer);

        //Total user time
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        RtlSecureZeroMemory(&SystemTime, sizeof(SystemTime));
        RtlTimeToTimeFields(&jbai.TotalUserTime, &SystemTime);
        rtl_swprintf_s(szBuffer, MAX_PATH, FORMATTED_TIME_VALUE_MS,
            SystemTime.Hour,
            SystemTime.Minute,
            SystemTime.Second,
            SystemTime.Milliseconds);
        SetDlgItemText(hwndDlg, ID_JOBTOTALUMTIME, szBuffer);

        //Total kernel time
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        RtlTimeToTimeFields(&jbai.TotalKernelTime, &SystemTime);
        rtl_swprintf_s(szBuffer, MAX_PATH, FORMATTED_TIME_VALUE_MS,
            SystemTime.Hour,
            SystemTime.Minute,
            SystemTime.Second,
            SystemTime.Milliseconds);
        SetDlgItemText(hwndDlg, ID_JOBTOTALKMTIME, szBuffer);

        //Page faults
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        ultostr(jbai.TotalPageFaultCount, szBuffer);
        SetDlgItemText(hwndDlg, ID_JOBTOTALPF, szBuffer);

        //Job process list
        pJobProcList = NULL;
        do {

            hwndCB = GetDlgItem(hwndDlg, IDC_JOB_PLIST);
            if (hwndCB == NULL)
                break;

            //allocate default size
            bytesNeeded = PAGE_SIZE;
            pJobProcList = (PJOBOBJECT_BASIC_PROCESS_ID_LIST)supVirtualAlloc(bytesNeeded);
            if (pJobProcList == NULL)
                break;

            //if buffer is not enough, reallocate it
            status = NtQueryInformationJobObject(hObject,
                JobObjectBasicProcessIdList,
                pJobProcList,
                bytesNeeded,
                &bytesNeeded);

            if (status == STATUS_BUFFER_OVERFLOW) {

                supVirtualFree(pJobProcList);
                pJobProcList = (PJOBOBJECT_BASIC_PROCESS_ID_LIST)supVirtualAlloc(bytesNeeded);
                if (pJobProcList == NULL)
                    break;

                status = NtQueryInformationJobObject(hObject,
                    JobObjectBasicProcessIdList,
                    pJobProcList,
                    bytesNeeded,
                    &bytesNeeded);

                if (!NT_SUCCESS(status))
                    break;
            }
            EnableWindow(hwndCB, (pJobProcList->NumberOfProcessIdsInList > 0) ? TRUE : FALSE);
            SendMessage(hwndCB, CB_RESETCONTENT, (WPARAM)0, (LPARAM)0);

            // 
            // If any present then output processes in the list.
            //
            if (pJobProcList->NumberOfProcessIdsInList > 0) {
                ProcessList = supGetSystemInfo(SystemProcessInformation, NULL);
                if (ProcessList) {
                    for (i = 0; i < pJobProcList->NumberOfProcessIdsInList; i++) {
                        ProcessId = pJobProcList->ProcessIdList[i];
                        RtlSecureZeroMemory(szProcessName, sizeof(szProcessName));

                        //
                        // Query process name.
                        //
                        if (!supQueryProcessName(
                            ProcessId,
                            ProcessList,
                            szProcessName,
                            MAX_PATH))
                        {
                            _strcpy(szProcessName, TEXT("UnknownProcess"));
                        }

                        //
                        // Build final string.
                        //
                        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
                        rtl_swprintf_s(szBuffer, sizeof(szBuffer) / sizeof(szBuffer[0]), 
                            TEXT("[0x%I64X:%I64u] %wS"), ProcessId, ProcessId, szProcessName);                       
                        
                        SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
                    }
                    SendMessage(hwndCB, CB_SETCURSEL, (WPARAM)0, (LPARAM)0);
                    supHeapFree(ProcessList);
                }
            }
        } while (cond);

        if (pJobProcList != NULL) {
            supVirtualFree(pJobProcList);
        }
    }

    //
    // Query object basic and type info if needed.
    //
    if (ExtendedInfoAvailable == FALSE) {
        propSetDefaultInfo(Context, hwndDlg, hObject);
    }
    propCloseCurrentObject(Context, hObject);
}

/*
* propBasicQuerySession
*
* Purpose:
*
* Set information values for Session object type
*
*/
VOID propBasicQuerySession(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    HANDLE hObject;

    if (Context == NULL) {
        return;
    }

    //
    // Open Session object.
    //
    hObject = NULL;
    if (!propOpenCurrentObject(Context, &hObject, MAXIMUM_ALLOWED)) {
        return;
    }

    //
    // Query object basic and type info if needed.
    //
    propSetDefaultInfo(Context, hwndDlg, hObject);

    propCloseCurrentObject(Context, hObject);
}

/*
* propSetBasicInfoEx
*
* Purpose:
*
* Set information values received with kldbgdrv help
*
*/
VOID propSetBasicInfoEx(
    _In_ HWND hwndDlg,
    _In_ POBJINFO InfoObject
)
{
    INT     i;
    HWND    hwndCB;
    WCHAR   szBuffer[MAX_PATH];

    if (InfoObject == NULL)
        return;

    //Object & Header Address
    propSetObjectHeaderAddressInfo(
        hwndDlg,
        InfoObject->ObjectAddress,
        InfoObject->HeaderAddress);

    //Reference Count
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    i64tostr(InfoObject->ObjectHeader.PointerCount, _strend(szBuffer));
    SetDlgItemText(hwndDlg, ID_OBJECT_REFC, szBuffer);

    //Handle Count
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    i64tostr(InfoObject->ObjectHeader.HandleCount, _strend(szBuffer));
    SetDlgItemText(hwndDlg, ID_OBJECT_HANDLES, szBuffer);

    //NonPagedPoolCharge
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    ultostr(InfoObject->ObjectQuotaHeader.NonPagedPoolCharge, szBuffer);
    SetDlgItemText(hwndDlg, ID_OBJECT_NP_CHARGE, szBuffer);

    //PagedPoolCharge
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    ultostr(InfoObject->ObjectQuotaHeader.PagedPoolCharge, _strend(szBuffer));
    SetDlgItemText(hwndDlg, ID_OBJECT_PP_CHARGE, szBuffer);

    //Attributes
    hwndCB = GetDlgItem(hwndDlg, IDC_OBJECT_FLAGS);
    if (hwndCB) {
        EnableWindow(hwndCB, (InfoObject->ObjectHeader.Flags > 0) ? TRUE : FALSE);
        SendMessage(hwndCB, CB_RESETCONTENT, (WPARAM)0, (LPARAM)0);
        if (InfoObject->ObjectHeader.Flags > 0) {
            for (i = 0; i < 8; i++) {

                if (GET_BIT(InfoObject->ObjectHeader.Flags, i))

                    SendMessage(hwndCB,
                        CB_ADDSTRING,
                        (WPARAM)0,
                        (LPARAM)T_ObjectFlags[i]);
            }
            SendMessage(hwndCB, CB_SETCURSEL, (WPARAM)0, (LPARAM)0);
        }
    }
}

/*
* propBasicQueryDesktop
*
* Purpose:
*
* Set information values for Desktop object type
*
* Support is very limited because of win32k type origin.
*
*/
VOID propBasicQueryDesktop(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    BOOL        bExtendedInfoAvailable;
    HANDLE      hDesktop;
    ULONG_PTR   ObjectAddress, HeaderAddress, InfoHeaderAddress;
    OBJINFO     InfoObject;

    if (Context == NULL) {
        return;
    }

    //
    // Open Desktop object.
    //
    // Restriction: 
    // This will open only current winsta desktops
    //
    hDesktop = NULL;
    if (!propOpenCurrentObject(Context, &hDesktop, DESKTOP_READOBJECTS)) {
        return;
    }

    bExtendedInfoAvailable = FALSE;
    ObjectAddress = 0;
    if (supQueryObjectFromHandle(hDesktop, &ObjectAddress, NULL)) {
        HeaderAddress = (ULONG_PTR)OBJECT_TO_OBJECT_HEADER(ObjectAddress);

        //
        // If we can use driver, query extended information.
        //
        if (kdConnectDriver()) {
            RtlSecureZeroMemory(&InfoObject, sizeof(InfoObject));
            InfoObject.HeaderAddress = HeaderAddress;
            InfoObject.ObjectAddress = ObjectAddress;
            //dump object header
            bExtendedInfoAvailable = kdReadSystemMemory(HeaderAddress,
                &InfoObject.ObjectHeader, sizeof(OBJECT_HEADER));
            if (bExtendedInfoAvailable) {
                //dump quota info
                InfoHeaderAddress = 0;
                if (ObHeaderToNameInfoAddress(InfoObject.ObjectHeader.InfoMask,
                    HeaderAddress, &InfoHeaderAddress, HeaderQuotaInfoFlag))
                {
                    kdReadSystemMemory(InfoHeaderAddress,
                        &InfoObject.ObjectQuotaHeader, sizeof(OBJECT_HEADER_QUOTA_INFO));
                }
                propSetBasicInfoEx(hwndDlg, &InfoObject);
            }
        }
        //cannot query extended info, output what we have
        if (bExtendedInfoAvailable == FALSE) {

            //Object and Header address
            propSetObjectHeaderAddressInfo(
                hwndDlg,
                ObjectAddress,
                HeaderAddress);

        }
    }

    //
    // Query object basic and type info if needed.
    //
    if (bExtendedInfoAvailable == FALSE) {
        propSetDefaultInfo(Context, hwndDlg, hDesktop);
    }
    propCloseCurrentObject(Context, (HANDLE)hDesktop);
}

/*
* propSetBasicInfo
*
* Purpose:
*
* Set information values for Basic properties page
*
*/
VOID propSetBasicInfo(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ HWND hwndDlg
)
{
    BOOL     ExtendedInfoAvailable = FALSE;
    POBJINFO InfoObject = NULL;

    if (Context == NULL) {
        return;
    }
    SetDlgItemText(hwndDlg, ID_OBJECT_NAME, Context->lpObjectName);
    SetDlgItemText(hwndDlg, ID_OBJECT_TYPE, Context->lpObjectType);

    //
    // Desktops should be parsed differently.
    //
    if (Context->TypeIndex != ObjectTypeDesktop) {

        //
        // Dump object information depending on context type.
        //
        switch (Context->ContextType) {

        case propPrivateNamespace:
            InfoObject = ObQueryObjectByAddress(Context->NamespaceInfo.ObjectAddress);
            break;

        case propUnnamed:
            InfoObject = ObQueryObjectByAddress(Context->UnnamedObjectInfo.ObjectAddress);
            break;

        default:
            InfoObject = ObQueryObject(Context->lpCurrentObjectPath, Context->lpObjectName);
            break;
        }

        ExtendedInfoAvailable = (InfoObject != NULL);
        if (InfoObject == NULL) {

            if (Context->ContextType == propUnnamed) {

                if (Context->UnnamedObjectInfo.ObjectAddress) {
                    propSetObjectHeaderAddressInfo(
                        hwndDlg,
                        Context->UnnamedObjectInfo.ObjectAddress,
                        (ULONG_PTR)OBJECT_TO_OBJECT_HEADER(Context->UnnamedObjectInfo.ObjectAddress));
                }
            }
            else {
                SetDlgItemText(hwndDlg, ID_OBJECT_ADDR, TEXT(""));
                SetDlgItemText(hwndDlg, ID_OBJECT_HEADER, TEXT(""));
            }
        }
        else {
            //make copy of received dump
            supCopyMemory(&Context->ObjectInfo, sizeof(OBJINFO), InfoObject, sizeof(OBJINFO));

            //
            // Set Object Address, Header Address, NP/PP Charge, RefCount, HandleCount, Attributes.
            //
            propSetBasicInfoEx(hwndDlg, InfoObject);

            //
            // Special case for AlpcPort object type.
            // The only information we can get is from driver here as we cannot open port directly.
            // 
            if (Context->TypeIndex == ObjectTypePort) {
                propBasicQueryAlpcPort(Context, hwndDlg);
            }

            supHeapFree(InfoObject);
        }
    }

    //
    // Query Basic Information extended fields per Type.
    // If extended info not available each routine should query basic info itself.
    //
    switch (Context->TypeIndex) {
    case ObjectTypeDirectory:
        //if TRUE skip this because directory is basic dialog and basic info already set
        if (ExtendedInfoAvailable == FALSE) {
            propBasicQueryDirectory(Context, hwndDlg);
        }

        //
        // Set process trust label information.
        //
        propSetProcessTrustLabelInfo(Context, hwndDlg);

        break;
    case ObjectTypeDriver:
        propBasicQueryDriver(Context, hwndDlg);
        break;
    case ObjectTypeDevice:
        propBasicQueryDevice(Context, hwndDlg);
        break;
    case ObjectTypeSymbolicLink:
        propBasicQuerySymlink(Context, hwndDlg, ExtendedInfoAvailable);
        break;
    case ObjectTypeKey:
        propBasicQueryKey(Context, hwndDlg, ExtendedInfoAvailable);
        break;
    case ObjectTypeMutant:
        propBasicQueryMutant(Context, hwndDlg, ExtendedInfoAvailable);
        break;
    case ObjectTypeEvent:
        propBasicQueryEvent(Context, hwndDlg, ExtendedInfoAvailable);
        break;
    case ObjectTypeTimer:
        propBasicQueryTimer(Context, hwndDlg, ExtendedInfoAvailable);
        break;
    case ObjectTypeSemaphore:
        propBasicQuerySemaphore(Context, hwndDlg, ExtendedInfoAvailable);
        break;
    case ObjectTypeSection:
        propBasicQuerySection(Context, hwndDlg, ExtendedInfoAvailable);
        break;
    case ObjectTypeWinstation:
        propBasicQueryWindowStation(Context, hwndDlg, ExtendedInfoAvailable);
        break;
    case ObjectTypeJob:
        propBasicQueryJob(Context, hwndDlg, ExtendedInfoAvailable);
        break;
    case ObjectTypeSession:
        propBasicQuerySession(Context, hwndDlg);
        break;
    case ObjectTypeDesktop:
        propBasicQueryDesktop(Context, hwndDlg);
        break;
    case ObjectTypeIoCompletion:
        propBasicQueryIoCompletion(Context, hwndDlg, ExtendedInfoAvailable);
        break;
    case ObjectTypeMemoryPartition:
        propBasicQueryMemoryPartition(Context, hwndDlg);
        break;
    case ObjectTypeProcess:
        propBasicQueryProcess(Context, hwndDlg, ExtendedInfoAvailable);
        break;
    case ObjectTypeThread:
        propBasicQueryThread(Context, hwndDlg, ExtendedInfoAvailable);
        break;
    }

}

/*
* BasicPropDialogOnCommand
*
* Purpose:
*
* Basic Properties Dialog WM_COMMAND handler.
*
*/
INT_PTR BasicPropDialogOnCommand(
    _In_  HWND hwndDlg,
    _In_  WPARAM wParam
)
{
    INT_PTR iResult = 0;
    SIZE_T bufferSize;
    PWCHAR lpImageFileName;
    HWND hwndImageFileName = GetDlgItem(hwndDlg, IDC_PROCESS_FILENAME);

    if (LOWORD(wParam) == IDC_PROCESS_BROWSE) {
        bufferSize = UNICODE_STRING_MAX_BYTES + 1;
        lpImageFileName = (LPWSTR)supHeapAlloc(bufferSize);
        if (lpImageFileName) {
            GetWindowText(hwndImageFileName, lpImageFileName, UNICODE_STRING_MAX_BYTES / sizeof(WCHAR));
            supJumpToFile(lpImageFileName);
            supHeapFree(lpImageFileName);
        }
        iResult = 1;
    }

    return iResult;
}

/*
* BasicPropDialogProc
*
* Purpose:
*
* Basic Properties Dialog Procedure
*
* WM_INITDIALOG - set context window prop.
* WM_SHOWWINDOW - when wParam is TRUE it sets "Basic" page object information.
* WM_COMMAND - handle specific controls commands.
* WM_DESTROY - remove context window prop.
*
*/
INT_PTR CALLBACK BasicPropDialogProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam
)
{
    HDC               hDc;
    PAINTSTRUCT       Paint;
    PROPSHEETPAGE    *pSheet = NULL;
    PROP_OBJECT_INFO *Context = NULL;

    switch (uMsg) {

    case WM_INITDIALOG:
        pSheet = (PROPSHEETPAGE *)lParam;
        if (pSheet) {
            SetProp(hwndDlg, T_PROPCONTEXT, (HANDLE)pSheet->lParam);
        }
        return 1;
        break;

    case WM_SHOWWINDOW:
        if (wParam) {
            Context = (PROP_OBJECT_INFO*)GetProp(hwndDlg, T_PROPCONTEXT);
            if (Context) {
                propSetBasicInfo(Context, hwndDlg);
            }
        }
        return 1;
        break;

    case WM_COMMAND:
        return BasicPropDialogOnCommand(hwndDlg, wParam);
        break;

    case WM_PAINT:

        Context = (PROP_OBJECT_INFO*)GetProp(hwndDlg, T_PROPCONTEXT);
        if (Context) {
            hDc = BeginPaint(hwndDlg, &Paint);
            if (hDc) {

                ImageList_Draw(g_ListViewImages, Context->TypeDescription->ImageIndex, hDc, 24, 34,
                    ILD_NORMAL | ILD_TRANSPARENT);

                EndPaint(hwndDlg, &Paint);
            }
        }
        return 1;
        break;

    case WM_DESTROY:
        RemoveProp(hwndDlg, T_PROPCONTEXT);
        break;

    }
    return 0;
}
