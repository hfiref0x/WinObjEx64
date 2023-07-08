/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2023
*
*  TITLE:       PROPBASIC.C
*
*  VERSION:     2.02
*
*  DATE:        10 Jul 2023
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

typedef VOID(CALLBACK* pfnPropQueryInfoRoutine)(
    _In_ PROP_OBJECT_INFO* Context,
    _In_ HWND hwndDlg,
    _In_ BOOL ExtendedInfoAvailable);

#define PROP_QUERY_INFORMATION_ROUTINE(n) VOID n(   \
    _In_ PROP_OBJECT_INFO* Context,                 \
    _In_ HWND hwndDlg,                              \
    _In_ BOOL ExtendedInfoAvailable)

//
// Forward.
//
VOID propSetBasicInfoEx(
    _In_ HWND hwndDlg,
    _In_ POBEX_OBJECT_INFORMATION InfoObject);

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
    WCHAR szBuffer[64];
    LPWSTR lpText;

    //
    // Object Address
    //
    if (ObjectAddress) {
        szBuffer[0] = TEXT('0');
        szBuffer[1] = TEXT('x');
        szBuffer[2] = 0;
        u64tohex(ObjectAddress, &szBuffer[2]);
        lpText = szBuffer;
    }
    else {
        lpText = T_EmptyString;
    }

    SetDlgItemText(hwndDlg, ID_OBJECT_ADDR, lpText);

    //
    // Header Address
    //
    if (HeaderAddress) {
        szBuffer[0] = TEXT('0');
        szBuffer[1] = TEXT('x');
        szBuffer[2] = 0;
        u64tohex(HeaderAddress, &szBuffer[2]);
        lpText = szBuffer;
    }
    else {
        lpText = T_EmptyString;
    }

    SetDlgItemText(hwndDlg, ID_OBJECT_HEADER, lpText);
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

    ComboBox_ResetContent(hwndCB);

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

            ComboBox_AddString(hwndCB, szBuffer);
        }
    }

    //
    // ASLR state.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessASLRPolicy,
        sizeof(Policies.ASLRPolicy),
        &Policies.ASLRPolicy))
    {
        if (Policies.ASLRPolicy.Flags) {
            _strcpy(szBuffer, TEXT("ASLR"));
            if (Policies.ASLRPolicy.EnableHighEntropy) _strcat(szBuffer, TEXT(" (High-Entropy)"));
            if (Policies.ASLRPolicy.EnableForceRelocateImages) _strcat(szBuffer, TEXT(" (Force Relocate)"));
            if (Policies.ASLRPolicy.EnableBottomUpRandomization) _strcat(szBuffer, TEXT(" (Bottom-Up)"));
            if (Policies.ASLRPolicy.DisallowStrippedImages) _strcat(szBuffer, TEXT(" (Disallow Stripped)"));
            ComboBox_AddString(hwndCB, szBuffer);
        }
    }

    //
    // Dynamic code.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessDynamicCodePolicy,
        sizeof(Policies.DynamicCodePolicy),
        &Policies.DynamicCodePolicy))
    {
        if (Policies.DynamicCodePolicy.Flags) {
            if (Policies.DynamicCodePolicy.ProhibitDynamicCode) {
                ComboBox_AddString(hwndCB, TEXT("Dynamic code prohibited"));
            }
            if (Policies.DynamicCodePolicy.AuditProhibitDynamicCode) {
                ComboBox_AddString(hwndCB, TEXT("Dynamic code audit prohibit"));
            }
            if (Policies.DynamicCodePolicy.AllowThreadOptOut) {
                ComboBox_AddString(hwndCB, TEXT("Dynamic code prohibited (per-thread)"));
            }
            if (Policies.DynamicCodePolicy.AllowRemoteDowngrade) {
                ComboBox_AddString(hwndCB, TEXT("Dynamic code downgradable"));
            }
        }
    }

    //
    // Strict handle check.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessStrictHandleCheckPolicy,
        sizeof(Policies.StrictHandleCheckPolicy),
        &Policies.StrictHandleCheckPolicy))
    {
        if (Policies.StrictHandleCheckPolicy.Flags) {
            if (Policies.StrictHandleCheckPolicy.RaiseExceptionOnInvalidHandleReference) {
                _strcpy(szBuffer, TEXT("Strict handle checks"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.StrictHandleCheckPolicy.HandleExceptionsPermanentlyEnabled) {
                _strcpy(szBuffer, TEXT("Handle exceptions permanently"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
        }
    }

    //
    // System call disable.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessSystemCallDisablePolicy,
        sizeof(Policies.SystemCallDisablePolicy),
        &Policies.SystemCallDisablePolicy))
    {
        if (Policies.SystemCallDisablePolicy.Flags) {
            if (Policies.SystemCallDisablePolicy.DisallowWin32kSystemCalls) {
                _strcpy(szBuffer, TEXT("Disallow Win32k system calls"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.SystemCallDisablePolicy.AuditDisallowWin32kSystemCalls) {
                _strcpy(szBuffer, TEXT("Disallow Win32k system calls (Audit)"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.SystemCallDisablePolicy.DisallowFsctlSystemCalls) {
                ComboBox_AddString(hwndCB, TEXT("Disallow Fsctl system calls"));
            }
            if (Policies.SystemCallDisablePolicy.AuditDisallowFsctlSystemCalls) {
                ComboBox_AddString(hwndCB, TEXT("Disallow Fsctl system calls (Audit)"));
            }
        }
    }

    //
    // Extension point disable.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessExtensionPointDisablePolicy,
        sizeof(Policies.ExtensionPointDisablePolicy),
        &Policies.ExtensionPointDisablePolicy))
    {
        if (Policies.ExtensionPointDisablePolicy.Flags) {
            if (Policies.ExtensionPointDisablePolicy.DisableExtensionPoints) {
                _strcpy(szBuffer, TEXT("Extension points disabled"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
        }
    }

    //
    // CFG.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessControlFlowGuardPolicy,
        sizeof(Policies.ControlFlowGuardPolicy),
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
                if (Policies.ControlFlowGuardPolicy.EnableXfg) {
                    _strcat(szBuffer, TEXT(" (Extended CF Guard)"));
                }
                if (Policies.ControlFlowGuardPolicy.EnableXfgAuditMode) {
                    _strcat(szBuffer, TEXT(" (Extended CF Guard audit)"));
                }

                ComboBox_AddString(hwndCB, szBuffer);
            }
        }
    }

    //
    // Signature.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessSignaturePolicy,
        sizeof(Policies.SignaturePolicy),
        &Policies.SignaturePolicy))
    {
        if (Policies.SignaturePolicy.Flags) {
            if (Policies.SignaturePolicy.MicrosoftSignedOnly) {
                _strcpy(szBuffer, TEXT("Signatures restricted (Microsoft only)"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.SignaturePolicy.StoreSignedOnly) {
                _strcpy(szBuffer, TEXT("Signatures restricted (Store only)"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.SignaturePolicy.AuditMicrosoftSignedOnly) {
                _strcpy(szBuffer, TEXT("Signatures restricted (Microsoft only, audit)"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.SignaturePolicy.AuditStoreSignedOnly) {
                _strcpy(szBuffer, TEXT("Signatures restricted (Store only, audit)"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.SignaturePolicy.MitigationOptIn) {
                _strcpy(szBuffer, TEXT("Signatures opt-in restriction"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
        }
    }

    //
    // Font disable.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessFontDisablePolicy,
        sizeof(Policies.FontDisablePolicy),
        &Policies.FontDisablePolicy))
    {
        if (Policies.FontDisablePolicy.Flags) {
            if (Policies.FontDisablePolicy.DisableNonSystemFonts) {
                _strcpy(szBuffer, TEXT("Non-system fonts disabled"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.FontDisablePolicy.AuditNonSystemFontLoading) {
                _strcpy(szBuffer, TEXT("Non system font loading audit"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
        }
    }

    //
    // Image load.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessImageLoadPolicy,
        sizeof(Policies.ImageLoadPolicy),
        &Policies.ImageLoadPolicy))
    {
        if (Policies.ImageLoadPolicy.Flags) {

            if (Policies.ImageLoadPolicy.PreferSystem32Images) {
                _strcpy(szBuffer, TEXT("Prefer system32 images"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.ImageLoadPolicy.NoRemoteImages) {
                _strcpy(szBuffer, TEXT("Resticted remote images"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.ImageLoadPolicy.NoLowMandatoryLabelImages) {
                _strcpy(szBuffer, TEXT("Restricted low mandatory label images"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.ImageLoadPolicy.AuditNoRemoteImages) {
                _strcpy(szBuffer, TEXT("Restricted remote images (Audit)"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.ImageLoadPolicy.AuditNoLowMandatoryLabelImages) {
                _strcpy(szBuffer, TEXT("Restricted low mandatory label images (Audit)"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
        }
    }

    //
    // Payload restriction.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessPayloadRestrictionPolicy,
        sizeof(Policies.PayloadRestrictionPolicy),
        &Policies.PayloadRestrictionPolicy))
    {
        if (Policies.PayloadRestrictionPolicy.Flags) {

            if (Policies.PayloadRestrictionPolicy.EnableExportAddressFilter) {
                _strcpy(szBuffer, TEXT("Enable export address filter"));
                ComboBox_AddString(hwndCB, szBuffer);
            }

            if (Policies.PayloadRestrictionPolicy.AuditExportAddressFilter) {
                _strcpy(szBuffer, TEXT("Audit export address filter"));
                ComboBox_AddString(hwndCB, szBuffer);
            }

            if (Policies.PayloadRestrictionPolicy.EnableExportAddressFilterPlus) {
                _strcpy(szBuffer, TEXT("Enable export address filter plus"));
                ComboBox_AddString(hwndCB, szBuffer);
            }

            if (Policies.PayloadRestrictionPolicy.AuditExportAddressFilterPlus) {
                _strcpy(szBuffer, TEXT("Audit export address filter plus"));
                ComboBox_AddString(hwndCB, szBuffer);
            }

            if (Policies.PayloadRestrictionPolicy.EnableImportAddressFilter) {
                _strcpy(szBuffer, TEXT("Enable import address filter"));
                ComboBox_AddString(hwndCB, szBuffer);
            }

            if (Policies.PayloadRestrictionPolicy.AuditImportAddressFilter) {
                _strcpy(szBuffer, TEXT("Audit import address filter"));
                ComboBox_AddString(hwndCB, szBuffer);
            }

            if (Policies.PayloadRestrictionPolicy.EnableRopStackPivot) {
                _strcpy(szBuffer, TEXT("Enable ROP stack pivot"));
                ComboBox_AddString(hwndCB, szBuffer);
            }

            if (Policies.PayloadRestrictionPolicy.AuditRopStackPivot) {
                _strcpy(szBuffer, TEXT("Audit ROP stack pivot"));
                ComboBox_AddString(hwndCB, szBuffer);
            }

            if (Policies.PayloadRestrictionPolicy.EnableRopCallerCheck) {
                _strcpy(szBuffer, TEXT("Enable ROP caller check"));
                ComboBox_AddString(hwndCB, szBuffer);
            }

            if (Policies.PayloadRestrictionPolicy.AuditRopCallerCheck) {
                _strcpy(szBuffer, TEXT("Audit ROP caller check"));
                ComboBox_AddString(hwndCB, szBuffer);
            }

            if (Policies.PayloadRestrictionPolicy.EnableRopSimExec) {
                _strcpy(szBuffer, TEXT("Enable ROP sim exec"));
                ComboBox_AddString(hwndCB, szBuffer);
            }

            if (Policies.PayloadRestrictionPolicy.AuditRopSimExec) {
                _strcpy(szBuffer, TEXT("Audit ROP sim exec"));
                ComboBox_AddString(hwndCB, szBuffer);
            }

        }
    }

    //
    // Child process.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessChildProcessPolicy,
        sizeof(Policies.ChildProcessPolicy),
        &Policies.ChildProcessPolicy))
    {
        if (Policies.ChildProcessPolicy.Flags) {
            if (Policies.ChildProcessPolicy.NoChildProcessCreation) {
                _strcpy(szBuffer, TEXT("No child process creation"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.ChildProcessPolicy.AllowSecureProcessCreation) {
                _strcpy(szBuffer, TEXT("Allow secure process creation"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.ChildProcessPolicy.AuditNoChildProcessCreation) {
                _strcpy(szBuffer, TEXT("Audit no child process creation"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
        }
    }

    //
    // Side channel.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessSideChannelIsolationPolicy,
        sizeof(Policies.SideChannelIsolationPolicy),
        &Policies.SideChannelIsolationPolicy))
    {
        if (Policies.SideChannelIsolationPolicy.Flags) {
            if (Policies.SideChannelIsolationPolicy.DisablePageCombine) {
                _strcpy(szBuffer, TEXT("Restricted page combining"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.SideChannelIsolationPolicy.IsolateSecurityDomain) {
                _strcpy(szBuffer, TEXT("Distinct security domain"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.SideChannelIsolationPolicy.SmtBranchTargetIsolation) {
                _strcpy(szBuffer, TEXT("SMT-thread branch target isolation"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.SideChannelIsolationPolicy.SpeculativeStoreBypassDisable) {
                _strcpy(szBuffer, TEXT("Memory disambiguation (SSBD)"));
                ComboBox_AddString(hwndCB, szBuffer);
            }

        }
    }

    //
    // User shadow stack.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessUserShadowStackPolicy,
        sizeof(Policies.UserShadowStackPolicy),
        &Policies.UserShadowStackPolicy))
    {
        if (Policies.UserShadowStackPolicy.Flags) {

            if (Policies.UserShadowStackPolicy.EnableUserShadowStack) {
                _strcpy(szBuffer, TEXT("Shadow Stack enabled"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.UserShadowStackPolicy.AuditUserShadowStack) {
                _strcpy(szBuffer, TEXT("Shadow Stack enabled (audit)"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.UserShadowStackPolicy.SetContextIpValidation) {
                _strcpy(szBuffer, TEXT("SetContextIpValidation enabled"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.UserShadowStackPolicy.AuditSetContextIpValidation) {
                _strcpy(szBuffer, TEXT("SetContextIpValidation (Audit)"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.UserShadowStackPolicy.EnableUserShadowStackStrictMode) {
                _strcpy(szBuffer, TEXT("Shadow Stack Strict Mode"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.UserShadowStackPolicy.BlockNonCetBinaries) {
                _strcpy(szBuffer, TEXT("Block Non Cet Binaries"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.UserShadowStackPolicy.BlockNonCetBinariesNonEhcont) {
                _strcpy(szBuffer, TEXT("Block Non Cet Binaries Non Ehcont"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.UserShadowStackPolicy.AuditBlockNonCetBinaries) {
                _strcpy(szBuffer, TEXT("Block Non CetBinaries (Audit)"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
            if (Policies.UserShadowStackPolicy.CetDynamicApisOutOfProcOnly) {
                _strcpy(szBuffer, TEXT("Cet Dynamic Apis Out Of Proc Only"));
                ComboBox_AddString(hwndCB, szBuffer);
            }

        }
    }

    //
    // Redirection Trust.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessRedirectionTrustPolicy,
        sizeof(Policies.RedirectionTrustPolicy),
        &Policies.RedirectionTrustPolicy))
    {
        if (Policies.RedirectionTrustPolicy.Flags) {

            if (Policies.RedirectionTrustPolicy.EnforceRedirectionTrust) {
                _strcpy(szBuffer, TEXT("Redirection Trust Enforced"));
                ComboBox_AddString(hwndCB, szBuffer);
            }

            if (Policies.RedirectionTrustPolicy.AuditRedirectionTrust) {
                _strcpy(szBuffer, TEXT("Redirection Trust (Audit)"));
                ComboBox_AddString(hwndCB, szBuffer);
            }
        }
    }

    //
    // User Pointer Auth Policy.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessUserPointerAuthPolicy,
        sizeof(Policies.UserPointerAuthPolicy),
        &Policies.UserPointerAuthPolicy))
    {
        if (Policies.UserPointerAuthPolicy.Flags) {

            if (Policies.UserPointerAuthPolicy.EnablePointerAuthUserIp) {
                _strcpy(szBuffer, TEXT("User Pointer Auth Policy enabled"));
                ComboBox_AddString(hwndCB, szBuffer);
            }

        }
    }

    //
    // SEHOPPolicy Policy.
    //
    if (supGetProcessMitigationPolicy(hProcess,
        (PROCESS_MITIGATION_POLICY)ProcessSEHOPPolicy,
        sizeof(Policies.SEHOPPolicy),
        &Policies.SEHOPPolicy))
    {
        if (Policies.SEHOPPolicy.Flags) {

            if (Policies.SEHOPPolicy.EnableSehop) {
                _strcpy(szBuffer, TEXT("Sehop enabled"));
                ComboBox_AddString(hwndCB, szBuffer);
            }

        }
    }
    
    lResult = ComboBox_GetCount(hwndCB);
    if (lResult != CB_ERR && lResult > 0) {
        EnableWindow(hwndCB, TRUE);
        ComboBox_SetCurSel(hwndCB, 0);
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
    _In_ PROP_OBJECT_INFO* Context,
    _In_ HWND hwndDlg
)
{
    BOOL bFail = TRUE;
    HANDLE hObject = NULL;

    ULONG ProtectionType = 0, ProtectionLevel = 0, i;

    LPWSTR lpType = T_EmptyString, lpLevel = T_EmptyString;

    WCHAR szBuffer[128];

    //
    // Re-open current object as we need READ_CONTROL.
    //
    if (!propOpenCurrentObject(Context, &hObject, READ_CONTROL)) {
        ShowWindow(GetDlgItem(hwndDlg, ID_OBJECT_TRUSTLABEL), SW_HIDE);
        return;
    }

    if (NT_SUCCESS(supQueryObjectTrustLabel(hObject,
        &ProtectionType,
        &ProtectionLevel)))
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
            ShowWindow(GetDlgItem(hwndDlg, ID_OBJECT_TRUSTLABEL), SW_SHOW);
            SetDlgItemText(hwndDlg, ID_OBJECT_TRUSTLABEL, szBuffer);
            bFail = FALSE;
        }
    }

    propCloseCurrentObject(Context, hObject);

    if (bFail) {
        ShowWindow(GetDlgItem(hwndDlg, ID_OBJECT_TRUSTLABEL), SW_HIDE);
        ShowWindow(GetDlgItem(hwndDlg, ID_PTL_CAPTION), SW_HIDE);
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
    _In_ PROP_OBJECT_INFO* Context,
    _In_ HWND hwndDlg,
    _In_ HANDLE hObject
)
{
    INT      i;
    HWND     hwndCB;
    NTSTATUS ntStatus;
    ULONG    returnLength;
    WCHAR    szBuffer[100];

    OBJECT_BASIC_INFORMATION obi;
    POBJECT_TYPE_INFORMATION TypeInfo = NULL;

    //
    // Query object basic information.
    //
    RtlSecureZeroMemory(&obi, sizeof(obi));

    ntStatus = NtQueryObject(hObject, 
        ObjectBasicInformation, 
        &obi,
        sizeof(OBJECT_BASIC_INFORMATION), 
        &returnLength);

    if (NT_SUCCESS(ntStatus)) {

        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

        //Reference Count
        u64tostr(obi.PointerCount, szBuffer);
        SetDlgItemText(hwndDlg, ID_OBJECT_REFC, szBuffer);

        //Handle Count
        szBuffer[0] = 0;
        u64tostr(obi.HandleCount, szBuffer);
        SetDlgItemText(hwndDlg, ID_OBJECT_HANDLES, szBuffer);

        //NonPagedPoolCharge
        szBuffer[0] = 0;
        u64tostr(obi.NonPagedPoolCharge, szBuffer);
        SetDlgItemText(hwndDlg, ID_OBJECT_NP_CHARGE, szBuffer);

        //PagedPoolCharge
        szBuffer[0] = 0;
        u64tostr(obi.PagedPoolCharge, szBuffer);
        SetDlgItemText(hwndDlg, ID_OBJECT_PP_CHARGE, szBuffer);

        //Attributes
        hwndCB = GetDlgItem(hwndDlg, IDC_OBJECT_FLAGS);
        if (hwndCB) {
            SendMessage(hwndCB, CB_RESETCONTENT, (WPARAM)0, (LPARAM)0);
            EnableWindow(hwndCB, (obi.Attributes > 0) ? TRUE : FALSE);
            if (obi.Attributes != 0) {
                for (i = 0; i < 8; i++) {
                    if (GET_BIT(obi.Attributes, i))
                        SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)T_ObjectFlags[i]);
                }
                SendMessage(hwndCB, CB_SETCURSEL, (WPARAM)0, (LPARAM)0);
            }
        }
    }

    //
    // Set flag bit for next usage on Type page.
    //
    ntStatus = supQueryObjectInformation(hObject,
        ObjectTypeInformation,
        &TypeInfo,
        NULL);

    if (NT_SUCCESS(ntStatus)) {

        if (TypeInfo->SecurityRequired) {
            SET_BIT(Context->ObjectFlags, 3);
        }
        if (TypeInfo->MaintainHandleCount) {
            SET_BIT(Context->ObjectFlags, 4);
        }

        supHeapFree(TypeInfo);
    }
    else {
        SetLastError(RtlNtStatusToDosError(ntStatus));
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
PROP_QUERY_INFORMATION_ROUTINE(propBasicQueryDirectory)
{
    HANDLE hObject = NULL;

    UNREFERENCED_PARAMETER(ExtendedInfoAvailable);

    //
    // Open object directory and query info.
    //
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
PROP_QUERY_INFORMATION_ROUTINE(propBasicQuerySemaphore)
{
    NTSTATUS  status;
    ULONG     bytesNeeded;
    HANDLE    hObject = NULL;
    WCHAR	  szBuffer[64];

    SEMAPHORE_BASIC_INFORMATION sbi;

    SetDlgItemText(hwndDlg, ID_SEMAPHORECURRENT, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_SEMAPHOREMAXCOUNT, T_CannotQuery);

    //
    // Open semaphore object.
    //
    if (!propOpenCurrentObject(Context, &hObject, SEMAPHORE_QUERY_STATE)) {
        return;
    }

    RtlSecureZeroMemory(&sbi, sizeof(SEMAPHORE_BASIC_INFORMATION));

    status = NtQuerySemaphore(hObject, 
        SemaphoreBasicInformation, 
        &sbi,
        sizeof(SEMAPHORE_BASIC_INFORMATION), 
        &bytesNeeded);

    if (NT_SUCCESS(status)) {

        //Current count
        szBuffer[0] = 0;
        RtlStringCchPrintfSecure(szBuffer, 64, 
            TEXT("0x%lX (%lu)"), 
            sbi.CurrentCount,
            sbi.CurrentCount);
        
        SetDlgItemText(hwndDlg, ID_SEMAPHORECURRENT, szBuffer);

        //Maximum count
        szBuffer[0] = 0;
        RtlStringCchPrintfSecure(szBuffer, 64, 
            TEXT("0x%lX (%lu)"), 
            sbi.MaximumCount,
            sbi.MaximumCount);

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
PROP_QUERY_INFORMATION_ROUTINE(propBasicQueryIoCompletion)
{
    NTSTATUS status;
    ULONG    bytesNeeded;
    HANDLE   hObject = NULL;

    IO_COMPLETION_BASIC_INFORMATION iobi;

    SetDlgItemText(hwndDlg, ID_IOCOMPLETIONSTATE, T_CannotQuery);

    //
    // Open IoCompletion object.
    //
    if (!propOpenCurrentObject(Context, &hObject, IO_COMPLETION_QUERY_STATE)) {
        return;
    }

    RtlSecureZeroMemory(&iobi, sizeof(IO_COMPLETION_BASIC_INFORMATION));
    
    status = NtQueryIoCompletion(hObject, 
        IoCompletionBasicInformation,
        &iobi,
        sizeof(iobi), 
        &bytesNeeded);

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
PROP_QUERY_INFORMATION_ROUTINE(propBasicQueryTimer)
{
    NTSTATUS    status;
    ULONG       bytesNeeded;
    HANDLE      hObject = NULL;
    ULONGLONG   ConvertedSeconds, Hours;
    CSHORT      Minutes, Seconds;
    WCHAR       szBuffer[MAX_PATH + 1];

    TIMER_BASIC_INFORMATION tbi;

    SetDlgItemText(hwndDlg, ID_TIMERSTATE, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_TIMERREMAINING, T_CannotQuery);

    //
    // Open Timer object.
    //
    if (!propOpenCurrentObject(Context, &hObject, TIMER_QUERY_STATE)) {
        return;
    }

    RtlSecureZeroMemory(&tbi, sizeof(TIMER_BASIC_INFORMATION));
    
    status = NtQueryTimer(hObject, 
        TimerBasicInformation, 
        &tbi,
        sizeof(TIMER_BASIC_INFORMATION), 
        &bytesNeeded);

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

            RtlStringCchPrintfSecure(szBuffer,
                MAX_PATH,
                FORMAT_TIME_VALUE,
                Hours,
                Minutes,
                Seconds);

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
PROP_QUERY_INFORMATION_ROUTINE(propBasicQueryEvent)
{
    NTSTATUS status;
    ULONG    bytesNeeded;
    HANDLE   hObject = NULL;
    LPWSTR   lpInfo;
    EVENT_BASIC_INFORMATION	ebi;

    SetDlgItemText(hwndDlg, ID_EVENTTYPE, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_EVENTSTATE, T_CannotQuery);

    //
    // Open Event object.
    //
    if (!propOpenCurrentObject(Context, &hObject, EVENT_QUERY_STATE)) {
        return;
    }

    RtlSecureZeroMemory(&ebi, sizeof(EVENT_BASIC_INFORMATION));
    
    status = NtQueryEvent(hObject, 
        EventBasicInformation, 
        &ebi,
        sizeof(EVENT_BASIC_INFORMATION), 
        &bytesNeeded);

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
PROP_QUERY_INFORMATION_ROUTINE(propBasicQuerySymlink)
{
    NTSTATUS    status;
    ULONG       bytesNeeded;
    HANDLE      hObject = NULL;
    WCHAR       szBuffer[MAX_PATH + 1];

    OBJECT_BASIC_INFORMATION obi;
    UNICODE_STRING objectName, normalizedName;

    SetDlgItemText(hwndDlg, ID_OBJECT_SYMLINK_TARGET, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_OBJECT_SYMLINK_CREATION, T_CannotQuery);

    //
    // Open SymbolicLink object.
    //
    if (!propOpenCurrentObject(Context, &hObject, SYMBOLIC_LINK_QUERY)) {
        return;
    }

    if (supCreateObjectPathFromElements(&Context->NtObjectName,
        &Context->NtObjectPath,
        &objectName,
        TRUE))
    {
        if (supResolveSymbolicLinkTargetNormalized(
            hObject,
            NULL,
            &objectName,
            &normalizedName))
        {
            SetDlgItemText(hwndDlg, ID_OBJECT_SYMLINK_TARGET, normalizedName.Buffer);
            supFreeDuplicatedUnicodeString(g_obexHeap, &normalizedName, FALSE);
        }

        supFreeDuplicatedUnicodeString(g_obexHeap, &objectName, FALSE);
    }
  
    //Query Link Creation Time
    RtlSecureZeroMemory(&obi, sizeof(OBJECT_BASIC_INFORMATION));

    status = NtQueryObject(hObject, 
        ObjectBasicInformation, 
        &obi,
        sizeof(OBJECT_BASIC_INFORMATION), 
        &bytesNeeded);

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
PROP_QUERY_INFORMATION_ROUTINE(propBasicQueryKey)
{
    NTSTATUS    status;
    ULONG       bytesNeeded;
    HANDLE      hObject = NULL;
    WCHAR       szBuffer[MAX_PATH];

    KEY_FULL_INFORMATION  kfi;

    SetDlgItemText(hwndDlg, ID_KEYSUBKEYS, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_KEYVALUES, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_KEYLASTWRITE, T_CannotQuery);

    //
    // Open Key object.
    //
    if (!propOpenCurrentObject(Context, &hObject, KEY_QUERY_VALUE)) {
        return;
    }

    RtlSecureZeroMemory(&kfi, sizeof(KEY_FULL_INFORMATION));
    
    status = NtQueryKey(hObject, 
        KeyFullInformation, 
        &kfi,
        sizeof(KEY_FULL_INFORMATION), 
        &bytesNeeded);

    if (NT_SUCCESS(status)) {

        //Subkeys count
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        ultostr(kfi.SubKeys, szBuffer);
        SetDlgItemText(hwndDlg, ID_KEYSUBKEYS, szBuffer);

        //Values count
        szBuffer[0] = 0;
        ultostr(kfi.Values, szBuffer);
        SetDlgItemText(hwndDlg, ID_KEYVALUES, szBuffer);

        //LastWrite time
        szBuffer[0] = 0;
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
PROP_QUERY_INFORMATION_ROUTINE(propBasicQueryMutant)
{
    NTSTATUS status;
    ULONG    bytesNeeded;
    HANDLE   hObject = NULL;
    WCHAR    szBuffer[MAX_PATH];

    MUTANT_BASIC_INFORMATION mbi;

    SetDlgItemText(hwndDlg, ID_MUTANTABANDONED, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_MUTANTSTATE, T_CannotQuery);

    //
    // Open Mutant object.
    //
    if (!propOpenCurrentObject(Context, &hObject, MUTANT_QUERY_STATE)) {
        return;
    }

    RtlSecureZeroMemory(&mbi, sizeof(MUTANT_BASIC_INFORMATION));

    status = NtQueryMutant(hObject, 
        MutantBasicInformation, 
        &mbi,
        sizeof(MUTANT_BASIC_INFORMATION), 
        &bytesNeeded);

    if (NT_SUCCESS(status)) {

        //
        // Show Abandoned state.
        //
        SetDlgItemText(hwndDlg, ID_MUTANTABANDONED, (mbi.AbandonedState) ? TEXT("Yes") : TEXT("No"));

        //
        // Show state.
        //
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        if (mbi.OwnedByCaller) {

            RtlStringCchPrintfSecure(szBuffer,
                MAX_PATH,
                TEXT("Held recursively %d times"),
                mbi.CurrentCount);

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
PROP_QUERY_INFORMATION_ROUTINE(propBasicQuerySection)
{
    BOOL      bSet;
    NTSTATUS  status;
    HANDLE    hObject = NULL;
    SIZE_T    bytesNeeded;
    LPWSTR    lpType;
    WCHAR     szBuffer[MAX_PATH * 2];

    SECTION_BASIC_INFORMATION sbi;
    SECTION_IMAGE_INFORMATION sii;

    ENUMCHILDWNDDATA ChildWndData;

    SetDlgItemText(hwndDlg, ID_SECTION_ATTR, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_SECTIONSIZE, T_CannotQuery);

    //
    // Open Section object.
    //
    if (!propOpenCurrentObject(Context, &hObject, SECTION_QUERY)) {
        return;
    }

    //query basic information
    RtlSecureZeroMemory(&sbi, sizeof(SECTION_BASIC_INFORMATION));

    status = NtQuerySection(hObject, 
        SectionBasicInformation,
        &sbi,
        sizeof(SECTION_BASIC_INFORMATION),
        &bytesNeeded);

    if (NT_SUCCESS(status)) {

        bSet = FALSE;
        szBuffer[0] = 0;
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
        szBuffer[0] = 0;
        RtlStringCchPrintfSecure(szBuffer,
            MAX_PATH,
            TEXT("0x%I64X"),
            sbi.MaximumSize.QuadPart);

        SetDlgItemText(hwndDlg, ID_SECTIONSIZE, szBuffer);

        //query image information
        if (supIsFileImageSection(sbi.AllocationAttributes)) {
            
            RtlSecureZeroMemory(&sii, sizeof(SECTION_IMAGE_INFORMATION));
            
            status = NtQuerySection(hObject, 
                SectionImageInformation, 
                &sii,
                sizeof(SECTION_IMAGE_INFORMATION), 
                &bytesNeeded);

            if (NT_SUCCESS(status)) {

                //show hidden controls
                if (GetWindowRect(GetDlgItem(hwndDlg, ID_IMAGEINFO), &ChildWndData.Rect)) {
                    ChildWndData.nCmdShow = SW_SHOW;
                    EnumChildWindows(hwndDlg, supCallbackShowChildWindow, (LPARAM)&ChildWndData);
                }

                //Entry			
                szBuffer[0] = 0;
                RtlStringCchPrintfSecure(szBuffer,
                    MAX_PATH,
                    TEXT("0x%I64X"),
                    (ULONG_PTR)sii.TransferAddress);

                SetDlgItemText(hwndDlg, ID_IMAGE_ENTRY, szBuffer);

                //Stack Reserve
                szBuffer[0] = 0;
                RtlStringCchPrintfSecure(szBuffer,
                    MAX_PATH,
                    TEXT("0x%I64X"),
                    sii.MaximumStackSize);

                SetDlgItemText(hwndDlg, ID_IMAGE_STACKRESERVE, szBuffer);

                //Stack Commit
                szBuffer[0] = 0;
                RtlStringCchPrintfSecure(szBuffer,
                    MAX_PATH,
                    TEXT("0x%I64X"),
                    sii.CommittedStackSize);

                SetDlgItemText(hwndDlg, ID_IMAGE_STACKCOMMIT, szBuffer);

                //Executable			
                SetDlgItemText(hwndDlg, ID_IMAGE_EXECUTABLE,
                    (sii.ImageContainsCode) ? TEXT("Yes") : TEXT("No"));

                //Subsystem               
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
                default:
                    lpType = T_Unknown;
                    break;
                }
                SetDlgItemText(hwndDlg, ID_IMAGE_SUBSYSTEM, lpType);

                //Major Version
                szBuffer[0] = 0;
                ultostr(sii.SubSystemMajorVersion, szBuffer);
                SetDlgItemText(hwndDlg, ID_IMAGE_MJV, szBuffer);

                //Minor Version
                szBuffer[0] = 0;
                ultostr(sii.SubSystemMinorVersion, szBuffer);
                SetDlgItemText(hwndDlg, ID_IMAGE_MNV, szBuffer);

                //Image Flags
                szBuffer[0] = 0;
                ultostr(sii.ImageFlags, szBuffer);
                SetDlgItemText(hwndDlg, ID_IMAGE_FLAGS, szBuffer);
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
PROP_QUERY_INFORMATION_ROUTINE(propBasicQueryWindowStation)
{
    DWORD           bytesNeeded;
    HWINSTA         hObject = NULL;
    USEROBJECTFLAGS userFlags;

    SetDlgItemText(hwndDlg, ID_WINSTATIONVISIBLE, T_CannotQuery);

    //
    // Open Winstation object.
    //
    if (!propOpenCurrentObject(Context, (PHANDLE)&hObject, WINSTA_READATTRIBUTES)) {
        return;
    }

    RtlSecureZeroMemory(&userFlags, sizeof(userFlags));

    if (GetUserObjectInformation(hObject, 
        UOI_FLAGS, 
        &userFlags,
        sizeof(USEROBJECTFLAGS), 
        &bytesNeeded))
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
PROP_QUERY_INFORMATION_ROUTINE(propBasicQueryDriver)
{
    ENUMCHILDWNDDATA ChildWndData;

    WCHAR szBuffer[MAX_PATH + 1];

    UNREFERENCED_PARAMETER(ExtendedInfoAvailable);

    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
    if (supQueryDriverDescription(Context->NtObjectName.Buffer,
        szBuffer,
        MAX_PATH))
    {
        //show hidden controls
        if (GetWindowRect(GetDlgItem(hwndDlg, ID_DRIVERINFO), &ChildWndData.Rect)) {
            ChildWndData.nCmdShow = SW_SHOW;
            EnumChildWindows(hwndDlg, supCallbackShowChildWindow, (LPARAM)&ChildWndData);
        }
        SetDlgItemText(hwndDlg, ID_DRIVERDISPLAYNAME, szBuffer);
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
PROP_QUERY_INFORMATION_ROUTINE(propBasicQueryDevice)
{
    ENUMCHILDWNDDATA ChildWndData;

    WCHAR szBuffer[MAX_PATH + 1];

    UNREFERENCED_PARAMETER(ExtendedInfoAvailable);

    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
    if (supQueryDeviceDescription(
        &Context->NtObjectPath,
        &Context->NtObjectName,
        szBuffer,
        MAX_PATH))
    {
        //show hidden controls
        if (GetWindowRect(GetDlgItem(hwndDlg, ID_DEVICEINFO), &ChildWndData.Rect)) {
            ChildWndData.nCmdShow = SW_SHOW;
            EnumChildWindows(hwndDlg, supCallbackShowChildWindow, (LPARAM)&ChildWndData);
        }
        SetDlgItemText(hwndDlg, ID_DEVICEDESCRIPTION, szBuffer);
    }

}

/*
* propBasicQueryMemoryPartition
*
* Purpose:
*
* Set information values for MemoryPartition object type
*
*/
PROP_QUERY_INFORMATION_ROUTINE(propBasicQueryMemoryPartition)
{
    HANDLE hObject = NULL;

    UNREFERENCED_PARAMETER(ExtendedInfoAvailable);

    //
    // Open Memory Partition object.
    //
    if (!propOpenCurrentObject(Context, &hObject, MEMORY_PARTITION_QUERY_ACCESS))
        return;

    //
    // Query object basic and type info if needed.
    //
    propSetDefaultInfo(Context, hwndDlg, hObject);
    propCloseCurrentObject(Context, hObject);
}

/*
* propBasicQueryRegistryTransaction
*
* Purpose:
*
* Set information values for RegistryTransaction object type
*
*/
PROP_QUERY_INFORMATION_ROUTINE(propBasicQueryRegistryTransaction)
{
    HANDLE hObject = NULL;

    UNREFERENCED_PARAMETER(ExtendedInfoAvailable);

    //
    // Open Registry Transaction object.
    //
    if (!propOpenCurrentObject(Context, &hObject, TRANSACTION_QUERY_INFORMATION))
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
PROP_QUERY_INFORMATION_ROUTINE(propBasicQueryProcess)
{
    BOOL ProcessParametersRead = FALSE;
    BOOL RemotePebRead = FALSE;
    BOOL bSuccess = FALSE;

    ULONG i, BreakOnTermination = 0;
    HANDLE hObject = NULL;
    PROCESS_EXTENDED_BASIC_INFORMATION exbi;
    RTL_USER_PROCESS_PARAMETERS UserProcessParameters;
    PEB RemotePeb;

    PUNICODE_STRING pusInformation = NULL;
    SIZE_T readBytes;

    PS_PROTECTION PsProtection;

    HWND hwndCB;

    LPWSTR Name;
    PBYTE Buffer;
    WCHAR szBuffer[100];
    KERNEL_USER_TIMES KernelUserTimes;

    //
    // Open Process object.
    //
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
                RTL_NUMBER_OF(szBuffer)))
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

        if (NT_SUCCESS(supQueryProcessInformation(hObject,
            ProcessImageFileNameWin32,
            &pusInformation,
            NULL)))
        {
            if ((pusInformation->Length) && (pusInformation->MaximumLength)) {

                Name = (LPWSTR)supHeapAlloc(sizeof(UNICODE_NULL) + pusInformation->MaximumLength);
                if (Name) {

                    RtlCopyMemory(Name, pusInformation->Buffer, pusInformation->Length);
                    SetDlgItemText(hwndDlg, IDC_PROCESS_FILENAME, Name);
                    EnableWindow(GetDlgItem(hwndDlg, IDC_PROCESS_BROWSE), TRUE);
                    bSuccess = TRUE;

                    supHeapFree(Name);
                    Name = NULL;
                }
            }

            supHeapFree(pusInformation);
        }

        if (bSuccess == FALSE) {
            SetDlgItemText(hwndDlg, IDC_PROCESS_FILENAME, T_COULD_NOT_QUERY);
        }

        //
        // Process Command Line.
        //
        bSuccess = FALSE;
        if (g_NtBuildNumber >= NT_WIN8_BLUE) {
            //
            // Use new NtQIP info class to get command line.
            //
            if (NT_SUCCESS(supQueryProcessInformation(hObject,
                ProcessCommandLineInformation,
                &pusInformation,
                NULL)))
            {
                if ((pusInformation->Length) && (pusInformation->MaximumLength)) {

                    Name = (LPWSTR)supHeapAlloc((SIZE_T)pusInformation->MaximumLength + sizeof(UNICODE_NULL));
                    if (Name) {

                        RtlCopyMemory(Name, pusInformation->Buffer, pusInformation->Length);

                        SetDlgItemText(hwndDlg, IDC_PROCESS_CMDLINE, Name);
                        bSuccess = TRUE;

                        supHeapFree(Name);
                        Name = NULL;
                    }
                }
                supHeapFree(pusInformation);
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
PROP_QUERY_INFORMATION_ROUTINE(propBasicQueryThread)
{
    BOOL bSuccess;
    ULONG ulCriticalThread, dummy;
    HANDLE hObject = NULL;

    WCHAR szBuffer[100];

    PSYSTEM_THREAD_INFORMATION Thread;
    LPWSTR TempBuffer;

    PROCESSOR_NUMBER IdealProcessor;
    THREAD_NAME_INFORMATION *NameInformation;


    Thread = &Context->u1.UnnamedObjectInfo.ThreadInformation;

    //
    // Open Thread object.
    //
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
            RTL_NUMBER_OF(szBuffer)))
        {
            SetDlgItemText(hwndDlg, IDC_THREAD_STARTED, szBuffer);
        }

        //
        // Kernel/User time.
        //
        szBuffer[0] = 0;
        supPrintTimeToBuffer(&Thread->KernelTime, szBuffer, RTL_NUMBER_OF(szBuffer));
        SetDlgItemText(hwndDlg, IDC_THREAD_KERNELTIME, szBuffer);

        szBuffer[0] = 0;
        supPrintTimeToBuffer(&Thread->UserTime, szBuffer, RTL_NUMBER_OF(szBuffer));
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
        if (NT_SUCCESS(NtQueryInformationThread(hObject, 
            ThreadIdealProcessorEx,
            (PVOID)&IdealProcessor, 
            sizeof(PROCESSOR_NUMBER), 
            &dummy)))
        {
            szBuffer[0] = 0;
            ultostr(IdealProcessor.Number, szBuffer);
            SetDlgItemText(hwndDlg, IDC_THREAD_IDEALPROCESSOR, szBuffer);
        }

        //
        // Is thread critical.
        //
        ulCriticalThread = 0;
        if (NT_SUCCESS(NtQueryInformationThread(hObject, 
            ThreadBreakOnTermination,
            (PVOID)&ulCriticalThread,
            sizeof(ULONG), 
            &dummy)))
        {
            SetDlgItemText(hwndDlg, IDC_THREAD_CRITICAL, 
                (ulCriticalThread > 0) ? TEXT("Yes") : TEXT("No"));
        }

        //
        // Thread name.
        //
        SetDlgItemText(hwndDlg, IDC_THREAD_NAME, T_CannotQuery);

        if (NT_SUCCESS(supQueryThreadInformation(hObject,
            ThreadNameInformation, &NameInformation, &dummy)))
        {
            if (NameInformation->ThreadName.Length && NameInformation->ThreadName.MaximumLength) {

                TempBuffer = (LPWSTR)supHeapAlloc(NameInformation->ThreadName.Length + sizeof(UNICODE_NULL));
                if (TempBuffer) {
                    RtlCopyMemory(TempBuffer, NameInformation->ThreadName.Buffer, NameInformation->ThreadName.Length);
                    TempBuffer[NameInformation->ThreadName.Length / sizeof(WCHAR)] = 0;
                    SetDlgItemText(hwndDlg, IDC_THREAD_NAME, TempBuffer);
                    supHeapFree(TempBuffer);
                }
                
            }

            supHeapFree(NameInformation);
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
PROP_QUERY_INFORMATION_ROUTINE(propBasicQueryAlpcPort)
{
    BOOL bQueryResult;
    ULONG_PTR ownerProcess;
    HANDLE ownerProcessId = 0;
    ULONG objectSize = 0, objectVersion = 0;
    UNICODE_STRING usImageFileName;
    PUNICODE_STRING pusFileName = NULL;
    LPWSTR lpProcessName, pEnd;
    SIZE_T cchBuffer;

    WCHAR szBuffer[MAX_PATH * 4];

    union {
        union {
            ALPC_PORT_7600* Port7600;
            ALPC_PORT_9200* Port9200;
            ALPC_PORT_9600* Port9600;
            ALPC_PORT_10240* Port10240;
        } u1;
        PBYTE Ref;
    } AlpcPort;

    UNREFERENCED_PARAMETER(ExtendedInfoAvailable);

    AlpcPort.Ref = (PBYTE)ObDumpAlpcPortObjectVersionAware(Context->ObjectInfo.ObjectAddress,
        &objectSize,
        &objectVersion);

    if (AlpcPort.Ref == NULL) {
        SetDlgItemText(hwndDlg, ID_ALPC_OWNERPROCESS, T_CannotQuery);
        return;
    }

    RtlInitEmptyUnicodeString(&usImageFileName, NULL, 0);

    //
    // Determine owner process.
    //
    ownerProcess = (ULONG_PTR)AlpcPort.u1.Port7600->OwnerProcess;
    if (ownerProcess) {
        szBuffer[0] = L'0';
        szBuffer[1] = L'x';
        szBuffer[2] = 0;
        u64tohex(ownerProcess, &szBuffer[2]);

        pEnd = _strcat(szBuffer, TEXT(" ("));

        bQueryResult = FALSE;
        lpProcessName = T_CannotQuery;

        if (ObGetProcessId(ownerProcess, &ownerProcessId)) {

            bQueryResult = NT_SUCCESS(supQueryProcessImageFileNameWin32(ownerProcessId,
                &pusFileName));

            if (bQueryResult) {

                if (pusFileName->Buffer && pusFileName->Length) {

                    lpProcessName = supExtractFileName(pusFileName->Buffer);

                }
                else {

                    bQueryResult = FALSE;

                }

            }

        }

        if (bQueryResult == FALSE) {

            if (ObGetProcessImageFileName(ownerProcess, &usImageFileName)) {

                lpProcessName = usImageFileName.Buffer;

            }

        }

        cchBuffer = RTL_NUMBER_OF(szBuffer) - _strlen(szBuffer) - 4;

        _strncpy(pEnd, cchBuffer, lpProcessName, _strlen(lpProcessName));

        _strcat(szBuffer, TEXT(")"));

        if (pusFileName)
            supHeapFree(pusFileName);

        if (usImageFileName.Buffer)
            RtlFreeUnicodeString(&usImageFileName);

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
PROP_QUERY_INFORMATION_ROUTINE(propBasicQueryJob)
{
    DWORD       i;
    HWND        hwndCB;
    HANDLE      hObject = NULL;
    NTSTATUS    status;
    ULONG       bytesNeeded;
    ULONG_PTR   ProcessId;
    PVOID       ProcessList;
    WCHAR       szProcessName[MAX_PATH + 1];
    WCHAR       szBuffer[MAX_PATH * 2];

    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION jbai;
    PJOBOBJECT_BASIC_PROCESS_ID_LIST       pJobProcList;

    SetDlgItemText(hwndDlg, ID_JOBTOTALPROCS, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_JOBACTIVEPROCS, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_JOBTERMINATEDPROCS, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_JOBTOTALUMTIME, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_JOBTOTALKMTIME, T_CannotQuery);
    SetDlgItemText(hwndDlg, ID_JOBTOTALPF, T_CannotQuery);

    //
    // Open Job object.
    //
    if (!propOpenCurrentObject(Context, &hObject, JOB_OBJECT_QUERY)) {
        return;
    }

    //query basic information
    RtlSecureZeroMemory(&jbai, sizeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));

    status = NtQueryInformationJobObject(hObject, 
        JobObjectBasicAccountingInformation,
        &jbai, 
        sizeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION), 
        &bytesNeeded);

    if (NT_SUCCESS(status)) {

        //Total processes
        szBuffer[0] = 0;
        ultostr(jbai.TotalProcesses, szBuffer);
        SetDlgItemText(hwndDlg, ID_JOBTOTALPROCS, szBuffer);

        //Active processes
        szBuffer[0] = 0;
        ultostr(jbai.ActiveProcesses, szBuffer);
        SetDlgItemText(hwndDlg, ID_JOBACTIVEPROCS, szBuffer);

        //Terminated processes
        szBuffer[0] = 0;
        ultostr(jbai.TotalTerminatedProcesses, szBuffer);
        SetDlgItemText(hwndDlg, ID_JOBTERMINATEDPROCS, szBuffer);

        //Total user time
        szBuffer[0] = 0;
        supPrintTimeToBuffer(&jbai.TotalUserTime, szBuffer, MAX_PATH);
        SetDlgItemText(hwndDlg, ID_JOBTOTALUMTIME, szBuffer);

        //Total kernel time
        szBuffer[0] = 0;
        supPrintTimeToBuffer(&jbai.TotalKernelTime, szBuffer, MAX_PATH);
        SetDlgItemText(hwndDlg, ID_JOBTOTALKMTIME, szBuffer);

        //This Period Total kernel time
        szBuffer[0] = 0;
        supPrintTimeToBuffer(&jbai.ThisPeriodTotalKernelTime, szBuffer, MAX_PATH);
        SetDlgItemText(hwndDlg, ID_JOBTPTOTALKMTIME, szBuffer);

        //This Period Total user time
        szBuffer[0] = 0;
        supPrintTimeToBuffer(&jbai.ThisPeriodTotalUserTime, szBuffer, MAX_PATH);
        SetDlgItemText(hwndDlg, ID_JOBTPTOTALUMTIME, szBuffer);

        //Page faults
        szBuffer[0] = 0;
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
                            _strcpy(szProcessName, T_UnknownProcess);
                        }

                        //
                        // Build final string.
                        //
                        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

                        RtlStringCchPrintfSecure(szBuffer,
                            RTL_NUMBER_OF(szBuffer),
                            TEXT("[0x%I64X:%I64u] %wS"),
                            ProcessId,
                            ProcessId,
                            szProcessName);

                        SendMessage(hwndCB, CB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
                    }
                    SendMessage(hwndCB, CB_SETCURSEL, (WPARAM)0, (LPARAM)0);
                    supHeapFree(ProcessList);
                }
            }
        } while (FALSE);

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
PROP_QUERY_INFORMATION_ROUTINE(propBasicQuerySession)
{
    HANDLE hObject = NULL;

    UNREFERENCED_PARAMETER(ExtendedInfoAvailable);

    //
    // Open Session object.
    //
    if (!propOpenCurrentObject(Context, &hObject, SESSION_QUERY_ACCESS)) {
        return;
    }

    //
    // Query object basic and type info if needed.
    //
    propSetDefaultInfo(Context, hwndDlg, hObject);

    propCloseCurrentObject(Context, hObject);
}

/*
* propFormatTokenAttribute
*
* Purpose:
*
* Convert token attributes to readable string.
*
*/
LPWSTR propFormatTokenAttribute(
    _In_ PTOKEN_SECURITY_ATTRIBUTE_V1 Attribute,
    _In_ ULONG ValueIndex
)
{
    BOOLEAN IsSimpleConvert = FALSE;
    LPWSTR  Result = NULL, TempString = NULL;
    PSID    TempSid;
    SIZE_T  ResultLength;
    
    UNICODE_STRING* TempUstringPtr;
    TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE* TempFQBNPtr;
    WCHAR szTemp[MAX_PATH];

    SIZE_T MinimumResultLength = 100;

    __try { //rely on private structures

        switch (Attribute->ValueType) {
        case TOKEN_SECURITY_ATTRIBUTE_TYPE_INT64:
            RtlSecureZeroMemory(szTemp, sizeof(szTemp));
            i64tostr(Attribute->Values.pInt64[ValueIndex], szTemp);
            IsSimpleConvert = TRUE;
            break;

        case TOKEN_SECURITY_ATTRIBUTE_TYPE_UINT64:
            RtlSecureZeroMemory(szTemp, sizeof(szTemp));
            u64tostr(Attribute->Values.pUint64[ValueIndex], szTemp);
            IsSimpleConvert = TRUE;
            break;

        case TOKEN_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
            if (Attribute->Values.pInt64[ValueIndex] != 0)
                _strcpy(szTemp, TEXT("True"));
            else
                _strcpy(szTemp, TEXT("False"));

            IsSimpleConvert = TRUE;
            break;

        case TOKEN_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
            _strcpy(szTemp, TEXT("(Octet String)"));
            IsSimpleConvert = TRUE;
            break;

        case TOKEN_SECURITY_ATTRIBUTE_TYPE_FQBN:
            TempFQBNPtr = &Attribute->Values.pFqbn[ValueIndex];
            ResultLength = TempFQBNPtr->Name.Length;
            if (ResultLength == 0)
                break;

            Result = (LPWSTR)supHeapAlloc(ResultLength + (MinimumResultLength * sizeof(WCHAR)));
            if (Result) {

                RtlStringCchPrintfSecure(Result,
                    MinimumResultLength,
                    TEXT("[%lu] Version %I64u: "),
                    ValueIndex,
                    Attribute->Values.pFqbn[ValueIndex].Version);

                RtlCopyMemory(_strend(Result),
                    TempFQBNPtr->Name.Buffer,
                    TempFQBNPtr->Name.Length);
            }
            break;

        case TOKEN_SECURITY_ATTRIBUTE_TYPE_SID:
            TempSid = Attribute->Values.pOctetString[ValueIndex].pValue;
            if (RtlValidSid(TempSid)) {
                if (ConvertSidToStringSid(TempSid, &TempString)) {
                    ResultLength = _strlen(TempString);
                    Result = (LPWSTR)supHeapAlloc((MinimumResultLength + ResultLength) * sizeof(WCHAR));
                    if (Result) {

                        RtlStringCchPrintfSecure(Result,
                            MinimumResultLength + ResultLength,
                            TEXT("[%lu] %s"),
                            ValueIndex,
                            TempString);

                    }
                    LocalFree(TempString);
                }
            }
            break;

        case TOKEN_SECURITY_ATTRIBUTE_TYPE_STRING:
            TempUstringPtr = &Attribute->Values.pString[ValueIndex];
            ResultLength = TempUstringPtr->Length;
            if (ResultLength == 0)
                break;

            Result = (LPWSTR)supHeapAlloc(ResultLength + (MinimumResultLength * sizeof(WCHAR)));
            if (Result) {

                RtlStringCchPrintfSecure(Result,
                    MinimumResultLength,
                    TEXT("[%lu] "),
                    ValueIndex);

                RtlCopyMemory(_strend(Result),
                    TempUstringPtr->Buffer,
                    TempUstringPtr->Length);
            }
            break;

        default:

            szTemp[0] = 0;
            RtlStringCchPrintfSecure(szTemp,
                MinimumResultLength,
                TEXT("(Unknown: %lu)"),
                Attribute->ValueType);

            IsSimpleConvert = TRUE;
            break;

        }

        if (IsSimpleConvert) {
            ResultLength = _strlen(szTemp);
            Result = (LPWSTR)supHeapAlloc((MinimumResultLength + ResultLength) * sizeof(WCHAR));
            if (Result) {

                RtlStringCchPrintfSecure(Result,
                    MinimumResultLength + ResultLength,
                    TEXT("[%lu] %s"),
                    ValueIndex,
                    szTemp);

            }
        }
    }
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
        return NULL;
    }
    return Result;
}

/*
* propBasicQueryToken
*
* Purpose:
*
* Set information values for Token object type
*
*/
PROP_QUERY_INFORMATION_ROUTINE(propBasicQueryToken)
{
    BOOLEAN bFlagSet = FALSE;
    HANDLE hObject = NULL;
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION SecurityAttributes;
    PTOKEN_SECURITY_ATTRIBUTE_V1 Attribute;
    ULONG ReturnLength = 0, i, j;

    TVINSERTSTRUCT TVItem;
    HTREEITEM RootItem;
    LPWSTR lpType;

    WCHAR szBuffer[MAX_PATH];

    HWND TreeView = GetDlgItem(hwndDlg, IDC_TOKEN_ATTRLIST);

    SetWindowTheme(TreeView, TEXT("Explorer"), NULL);
    TreeView_DeleteAllItems(TreeView);

    //
    // Open Token object.
    //
    if (!propOpenCurrentObject(Context, &hObject, TOKEN_QUERY)) {
        return;
    }

    //
    // List security attributes.
    //
    SecurityAttributes = (PTOKEN_SECURITY_ATTRIBUTES_INFORMATION)
        supGetTokenInfo(hObject, TokenSecurityAttributes, &ReturnLength);

    if (SecurityAttributes) {

        for (i = 0; i < SecurityAttributes->AttributeCount; i++) {

            Attribute = &SecurityAttributes->Attribute.pAttributeV1[i];

            //
            // Atribute Name (root element).
            //
            RtlSecureZeroMemory(&TVItem, sizeof(TVItem));
            TVItem.hParent = NULL;
            TVItem.item.mask = TVIF_TEXT | TVIF_STATE;
            TVItem.item.state = TVIS_EXPANDED;
            TVItem.item.stateMask = TVIS_EXPANDED;

            lpType = (LPWSTR)supHeapAlloc(Attribute->Name.Length + sizeof(UNICODE_NULL));
            if (lpType) {
                RtlCopyMemory(lpType, Attribute->Name.Buffer, Attribute->Name.Length);
                TVItem.item.pszText = lpType;
            }
            else
                TVItem.item.pszText = Attribute->Name.Buffer;
            RootItem = TreeView_InsertItem(TreeView, &TVItem);
            if (lpType) supHeapFree(lpType);

            //
            // Attribute ValueType
            //
            switch (Attribute->ValueType) {
            case TOKEN_SECURITY_ATTRIBUTE_TYPE_INVALID:
                lpType = T_Invalid;
                break;
            case TOKEN_SECURITY_ATTRIBUTE_TYPE_INT64:
                lpType = TEXT("Int64");
                break;
            case TOKEN_SECURITY_ATTRIBUTE_TYPE_UINT64:
                lpType = TEXT("UInt64");
                break;
            case TOKEN_SECURITY_ATTRIBUTE_TYPE_STRING:
                lpType = TEXT("String");
                break;
            case TOKEN_SECURITY_ATTRIBUTE_TYPE_FQBN:
                lpType = TEXT("FQBN");
                break;
            case TOKEN_SECURITY_ATTRIBUTE_TYPE_SID:
                lpType = TEXT("SID");
                break;
            case TOKEN_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
                lpType = TEXT("Boolean");
                break;
            case TOKEN_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
                lpType = TEXT("Octet string");
                break;
            default:
                lpType = T_Unknown;
                break;
            }
            _strcpy(szBuffer, TEXT("Type: "));
            _strcat(szBuffer, lpType);
            TVItem.hParent = RootItem;
            TVItem.item.mask = TVIF_TEXT;
            TVItem.item.pszText = szBuffer;
            TreeView_InsertItem(TreeView, &TVItem);

            //
            // Attribute Flags
            //
            _strcpy(szBuffer, TEXT("Flags: "));

            if (Attribute->Flags == 0) {
                _strcat(szBuffer, T_NoneValue);
            }
            else {

                _strcat(szBuffer, TEXT("("));
                ultohex(Attribute->Flags, _strend(szBuffer));
                _strcat(szBuffer, TEXT(") "));

                if (Attribute->Flags & TOKEN_SECURITY_ATTRIBUTE_NON_INHERITABLE) {
                    if (bFlagSet) _strcat(szBuffer, TEXT(", "));
                    _strcat(szBuffer, TEXT("Non-inheritable"));
                    bFlagSet = TRUE;
                }
                if (Attribute->Flags & TOKEN_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE) {
                    if (bFlagSet) _strcat(szBuffer, TEXT(", "));
                    _strcat(szBuffer, TEXT("Case-sensitive"));
                    bFlagSet = TRUE;
                }
                if (Attribute->Flags & TOKEN_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY) {
                    if (bFlagSet) _strcat(szBuffer, TEXT(", "));
                    _strcat(szBuffer, TEXT("Use for deny only"));
                    bFlagSet = TRUE;
                }
                if (Attribute->Flags & TOKEN_SECURITY_ATTRIBUTE_DISABLED_BY_DEFAULT) {
                    if (bFlagSet) _strcat(szBuffer, TEXT(", "));
                    _strcat(szBuffer, TEXT("Default disabled"));
                    bFlagSet = TRUE;
                }
                if (Attribute->Flags & TOKEN_SECURITY_ATTRIBUTE_DISABLED) {
                    if (bFlagSet) _strcat(szBuffer, TEXT(", "));
                    _strcat(szBuffer, TEXT("Disabled"));
                    bFlagSet = TRUE;
                }
                if (Attribute->Flags & TOKEN_SECURITY_ATTRIBUTE_MANDATORY) {
                    if (bFlagSet) _strcat(szBuffer, TEXT(", "));
                    _strcat(szBuffer, TEXT("Mandatory"));
                    bFlagSet = TRUE;
                }
                if (Attribute->Flags & TOKEN_SECURITY_ATTRIBUTE_COMPARE_IGNORE) {
                    if (bFlagSet) _strcat(szBuffer, TEXT(", "));
                    _strcat(szBuffer, TEXT("Compare-ignore"));
                }

            }
            TreeView_InsertItem(TreeView, &TVItem);

            _strcpy(szBuffer, TEXT("Values"));
            TVItem.hParent = RootItem;
            TVItem.item.mask = TVIF_TEXT | TVIF_STATE;
            TVItem.item.state = TVIS_EXPANDED;
            TVItem.item.stateMask = TVIS_EXPANDED;
            TVItem.item.pszText = szBuffer;
            RootItem = TreeView_InsertItem(TreeView, &TVItem);

            for (j = 0; j < Attribute->ValueCount; j++) {

                TVItem.hParent = RootItem;
                TVItem.item.mask = TVIF_TEXT;

                lpType = propFormatTokenAttribute(Attribute, j);
                if (lpType) {
                    TVItem.item.pszText = lpType;
                }
                else {
                    TVItem.item.pszText = T_InvalidValue;
                }

                TreeView_InsertItem(TreeView, &TVItem);

                if (lpType)
                    supHeapFree(lpType);

            }

        }

        supHeapFree(SecurityAttributes);
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
* propBasicQueryDesktop
*
* Purpose:
*
* Set information values for Desktop object type
*
* Support is very limited because of win32k type origin.
*
*/
PROP_QUERY_INFORMATION_ROUTINE(propBasicQueryDesktop)
{
    BOOL        bExtendedInfoAvailable;
    HANDLE      hDesktop = NULL;
    ULONG_PTR   ObjectAddress = 0, HeaderAddress = 0, InfoHeaderAddress = 0;

    OBEX_OBJECT_INFORMATION InfoObject;

    UNREFERENCED_PARAMETER(ExtendedInfoAvailable);

    //
    // Open Desktop object.
    //
    // Restriction: 
    // This will open only current winsta desktops
    //
    if (!propOpenCurrentObject(Context, &hDesktop, DESKTOP_READOBJECTS)) {
        return;
    }

    bExtendedInfoAvailable = FALSE;

    if (supQueryObjectFromHandle(hDesktop, &ObjectAddress, NULL)) {

        if (ObjectAddress)
            HeaderAddress = (ULONG_PTR)OBJECT_TO_OBJECT_HEADER(ObjectAddress);

        //
        // If we can use driver, query extended information.
        //
        if (HeaderAddress && kdConnectDriver()) {
            RtlSecureZeroMemory(&InfoObject, sizeof(InfoObject));
            InfoObject.HeaderAddress = HeaderAddress;
            InfoObject.ObjectAddress = ObjectAddress;

            //dump object header
            bExtendedInfoAvailable = kdReadSystemMemory(HeaderAddress,
                &InfoObject.ObjectHeader, 
                sizeof(OBJECT_HEADER));

            if (bExtendedInfoAvailable) {
                //dump quota info
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
* propSetBasicInfoEx
*
* Purpose:
*
* Set information values received with kldbgdrv help
*
*/
VOID propSetBasicInfoEx(
    _In_ HWND hwndDlg,
    _In_ POBEX_OBJECT_INFORMATION InfoObject
)
{
    INT     i;
    HWND    hwndCB;
    WCHAR   szBuffer[MAX_PATH];


    //Object & Header Address
    propSetObjectHeaderAddressInfo(
        hwndDlg,
        InfoObject->ObjectAddress,
        InfoObject->HeaderAddress);

    //Reference Count
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    i64tostr(InfoObject->ObjectHeader.PointerCount, szBuffer);
    SetDlgItemText(hwndDlg, ID_OBJECT_REFC, szBuffer);

    //Handle Count
    i64tostr(InfoObject->ObjectHeader.HandleCount, szBuffer);
    SetDlgItemText(hwndDlg, ID_OBJECT_HANDLES, szBuffer);

    //NonPagedPoolCharge
    ultostr(InfoObject->ObjectQuotaHeader.NonPagedPoolCharge, szBuffer);
    SetDlgItemText(hwndDlg, ID_OBJECT_NP_CHARGE, szBuffer);

    //PagedPoolCharge
    ultostr(InfoObject->ObjectQuotaHeader.PagedPoolCharge, szBuffer);
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
* propSetBasicInfo
*
* Purpose:
*
* Set information values for Basic properties page
*
*/
VOID propSetBasicInfo(
    _In_ PROP_OBJECT_INFO* Context,
    _In_ HWND hwndDlg
)
{
    BOOL ExtendedInfoAvailable = FALSE, bQueryTrustLabel = FALSE;
    POBEX_OBJECT_INFORMATION InfoObject = NULL;

    pfnPropQueryInfoRoutine propQueryInfoRoutine;

    UNICODE_STRING usObjectName;

    if (supNormalizeUnicodeStringForDisplay(g_obexHeap,
        &Context->NtObjectName,
        &usObjectName))
    {
        SetDlgItemText(hwndDlg, ID_OBJECT_NAME, usObjectName.Buffer);
        supFreeDuplicatedUnicodeString(g_obexHeap, &usObjectName, FALSE);
    }
    else {
        SetDlgItemText(hwndDlg, ID_OBJECT_NAME, Context->NtObjectName.Buffer);
    }

    SetDlgItemText(hwndDlg, ID_OBJECT_TYPE, Context->TypeDescription->Name);

    //
    // Desktops should be parsed differently.
    //
    if (Context->ObjectTypeIndex != ObjectTypeDesktop) {

        //
        // Dump object information depending on context type.
        //
        switch (Context->ContextType) {

        case propPrivateNamespace:
            InfoObject = ObQueryObjectByAddress(Context->u1.NamespaceInfo.ObjectAddress);
            break;

        case propUnnamed:
            InfoObject = ObQueryObjectByAddress(Context->u1.UnnamedObjectInfo.ObjectAddress);
            break;

        case propNormal:
        default:
            InfoObject = ObQueryObjectInDirectory(&Context->NtObjectName, &Context->NtObjectPath);
            break;
        }

        ExtendedInfoAvailable = (InfoObject != NULL);
        if (InfoObject == NULL) {

            if (Context->ContextType == propUnnamed) {

                if (Context->u1.UnnamedObjectInfo.ObjectAddress) {
                    propSetObjectHeaderAddressInfo(
                        hwndDlg,
                        Context->u1.UnnamedObjectInfo.ObjectAddress,
                        (ULONG_PTR)OBJECT_TO_OBJECT_HEADER(Context->u1.UnnamedObjectInfo.ObjectAddress));
                }
            }
            else {
                SetDlgItemText(hwndDlg, ID_OBJECT_ADDR, TEXT(""));
                SetDlgItemText(hwndDlg, ID_OBJECT_HEADER, TEXT(""));
            }
        }
        else {
            //make copy of received dump
            RtlCopyMemory(&Context->ObjectInfo, InfoObject, sizeof(OBEX_OBJECT_INFORMATION));

            //
            // Set Object Address, Header Address, NP/PP Charge, RefCount, HandleCount, Attributes.
            //
            propSetBasicInfoEx(hwndDlg, InfoObject);

            //
            // Special case for AlpcPort object type.
            // The only information we can get is from driver here as we cannot open port directly.
            // 
            if (Context->ObjectTypeIndex == ObjectTypePort) {
                propBasicQueryAlpcPort(Context, hwndDlg, FALSE);
            }

            supHeapFree(InfoObject);
        }
    }

    //
    // Query Basic Information extended fields per Type.
    // If extended info not available each routine should query basic info itself.
    //
    propQueryInfoRoutine = NULL;

    switch (Context->ObjectTypeIndex) {
    case ObjectTypeDirectory:
        bQueryTrustLabel = TRUE;
        //if TRUE skip this because directory is basic dialog and basic info already set
        if (ExtendedInfoAvailable == FALSE) {
            propQueryInfoRoutine = (pfnPropQueryInfoRoutine)propBasicQueryDirectory;
        }
        break;
    case ObjectTypeDriver:
        propQueryInfoRoutine = (pfnPropQueryInfoRoutine)propBasicQueryDriver;
        break;
    case ObjectTypeDevice:
        propQueryInfoRoutine = (pfnPropQueryInfoRoutine)propBasicQueryDevice;
        break;
    case ObjectTypeSymbolicLink:
        propQueryInfoRoutine = (pfnPropQueryInfoRoutine)propBasicQuerySymlink;
        break;
    case ObjectTypeKey:
        propQueryInfoRoutine = (pfnPropQueryInfoRoutine)propBasicQueryKey;
        break;
    case ObjectTypeMutant:
        propQueryInfoRoutine = (pfnPropQueryInfoRoutine)propBasicQueryMutant;
        break;
    case ObjectTypeEvent:
        propQueryInfoRoutine = (pfnPropQueryInfoRoutine)propBasicQueryEvent;
        break;
    case ObjectTypeTimer:
        propQueryInfoRoutine = (pfnPropQueryInfoRoutine)propBasicQueryTimer;
        break;
    case ObjectTypeSemaphore:
        propQueryInfoRoutine = (pfnPropQueryInfoRoutine)propBasicQuerySemaphore;
        break;
    case ObjectTypeSection:
        bQueryTrustLabel = TRUE;
        propQueryInfoRoutine = (pfnPropQueryInfoRoutine)propBasicQuerySection;
        break;
    case ObjectTypeWinstation:
        propQueryInfoRoutine = (pfnPropQueryInfoRoutine)propBasicQueryWindowStation;
        break;
    case ObjectTypeJob:
        propQueryInfoRoutine = (pfnPropQueryInfoRoutine)propBasicQueryJob;
        break;
    case ObjectTypeSession:
        propQueryInfoRoutine = (pfnPropQueryInfoRoutine)propBasicQuerySession;
        break;
    case ObjectTypeDesktop:
        propQueryInfoRoutine = (pfnPropQueryInfoRoutine)propBasicQueryDesktop;
        break;
    case ObjectTypeIoCompletion:
        propQueryInfoRoutine = (pfnPropQueryInfoRoutine)propBasicQueryIoCompletion;
        break;
    case ObjectTypeMemoryPartition:
        propQueryInfoRoutine = (pfnPropQueryInfoRoutine)propBasicQueryMemoryPartition;
        break;
    case ObjectTypeRegistryTransaction:
        propQueryInfoRoutine = (pfnPropQueryInfoRoutine)propBasicQueryRegistryTransaction;
        break;
    case ObjectTypeProcess:
        propQueryInfoRoutine = (pfnPropQueryInfoRoutine)propBasicQueryProcess;
        break;
    case ObjectTypeThread:
        propQueryInfoRoutine = (pfnPropQueryInfoRoutine)propBasicQueryThread;
        break;
    case ObjectTypeToken:
        propQueryInfoRoutine = (pfnPropQueryInfoRoutine)propBasicQueryToken;
        break;
    }

    //
    // Query object information by type.
    //
    if (propQueryInfoRoutine)
        propQueryInfoRoutine(Context, hwndDlg, ExtendedInfoAvailable);

    //
    // Set TrustLabel information for enabled object types.
    //
    if (bQueryTrustLabel)
        propSetProcessTrustLabelInfo(Context, hwndDlg);

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
* BasicPropDialogOnInit
*
* Purpose:
*
* Basic Properties Dialog WM_INITDIALOG handler.
*
*/
VOID BasicPropDialogOnInit(
    _In_  HWND hwndDlg,
    _In_  LPARAM lParam
)
{
    PROPSHEETPAGE* pSheet = NULL;

    pSheet = (PROPSHEETPAGE*)lParam;
    if (pSheet) {
        SetProp(hwndDlg, T_PROPCONTEXT, (HANDLE)pSheet->lParam);
        supLoadIconForObjectType(hwndDlg,
            (PROP_OBJECT_INFO*)pSheet->lParam,
            g_ListViewImages,
            FALSE);
    }
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
    PROP_OBJECT_INFO* Context = NULL;

    switch (uMsg) {

    case WM_INITDIALOG:
        BasicPropDialogOnInit(hwndDlg, lParam);
        return 1;

    case WM_SHOWWINDOW:
        if (wParam) {
            Context = (PROP_OBJECT_INFO*)GetProp(hwndDlg, T_PROPCONTEXT);
            if (Context) {
                propSetBasicInfo(Context, hwndDlg);
                return 1;
            }
        }
        break;

    case WM_COMMAND:
        return BasicPropDialogOnCommand(hwndDlg, wParam);

    case WM_DESTROY:
        RemoveProp(hwndDlg, T_PROPCONTEXT);
        break;

    }
    return 0;
}
