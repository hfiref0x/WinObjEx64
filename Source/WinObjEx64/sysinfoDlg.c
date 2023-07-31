/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022 - 2023
*
*  TITLE:       SYSINFODLG.C
*
*  VERSION:     2.03
*
*  DATE:        27 Jul 2023
* 
*  System Information Dialog.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

VALUE_DESC CodeIntegrityValuesList[] = {
    { L"CODEINTEGRITY_OPTION_ENABLED", CODEINTEGRITY_OPTION_ENABLED },
    { L"CODEINTEGRITY_OPTION_TESTSIGN", CODEINTEGRITY_OPTION_TESTSIGN },
    { L"CODEINTEGRITY_OPTION_UMCI_ENABLED", CODEINTEGRITY_OPTION_UMCI_ENABLED },
    { L"CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED", CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED },
    { L"CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED", CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED },
    { L"CODEINTEGRITY_OPTION_TEST_BUILD", CODEINTEGRITY_OPTION_TEST_BUILD },
    { L"CODEINTEGRITY_OPTION_PREPRODUCTION_BUILD", CODEINTEGRITY_OPTION_PREPRODUCTION_BUILD },
    { L"CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED", CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED },
    { L"CODEINTEGRITY_OPTION_FLIGHT_BUILD", CODEINTEGRITY_OPTION_FLIGHT_BUILD },
    { L"CODEINTEGRITY_OPTION_FLIGHTING_ENABLED", CODEINTEGRITY_OPTION_FLIGHTING_ENABLED },
    { L"CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED", CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED },
    { L"CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED", CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED },
    { L"CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED", CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED },
    { L"CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED", CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED },
    { L"CODEINTEGRITY_OPTION_WHQL_ENFORCEMENT_ENABLED", CODEINTEGRITY_OPTION_WHQL_ENFORCEMENT_ENABLED },
    { L"CODEINTEGRITY_OPTION_WHQL_AUDITMODE_ENABLED", CODEINTEGRITY_OPTION_WHQL_AUDITMODE_ENABLED }
};

/*
* AddParameterValue
*
* Purpose:
*
* Add text to the multiline richedit tabbed control.
*
*/
VOID AddParameterValue(
    _In_ HWND OutputWindow,
    _In_ LPCWSTR Parameter,
    _In_ LPCWSTR Value)
{
    LONG StartPos = 0;

    CHARFORMAT CharFormat;
    CHARRANGE CharRange, SelectedRange;

    CharRange.cpMax = INT_MAX;
    CharRange.cpMin = INT_MAX;

    SendMessage(OutputWindow, EM_EXSETSEL, (WPARAM)0, (LPARAM)&CharRange);
    SendMessage(OutputWindow, EM_EXGETSEL, (WPARAM)0, (LPARAM)&SelectedRange);
    StartPos = SelectedRange.cpMin;

    RtlSecureZeroMemory(&CharFormat, sizeof(CharFormat));
    CharFormat.cbSize = sizeof(CharFormat);
    CharFormat.dwMask = CFM_BOLD;
    CharFormat.dwEffects = 0;

    SendMessage(OutputWindow, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&CharFormat);

    if (StartPos) {
        SendMessage(OutputWindow, EM_REPLACESEL, (WPARAM)0, (LPARAM)L"\r\n");
        StartPos += 1;
    }

    SendMessage(OutputWindow, EM_REPLACESEL, (WPARAM)0, (LPARAM)Parameter);
    SendMessage(OutputWindow, EM_REPLACESEL, (WPARAM)0, (LPARAM)L"\t");
    SendMessage(OutputWindow, EM_REPLACESEL, (WPARAM)0, (LPARAM)Value);

    CharFormat.dwEffects = CFE_BOLD;

    CharRange.cpMin = StartPos;
    CharRange.cpMax = (LONG)_strlen(Parameter) + StartPos + 1;

    SendMessage(OutputWindow, EM_EXSETSEL, (WPARAM)0, (LPARAM)&CharRange);
    SendMessage(OutputWindow, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&CharFormat);
}

/*
* AddParameterValue64Hex
*
* Purpose:
*
* Add text to the multiline richedit tabbed control (hex value).
*
*/
VOID AddParameterValue64Hex(
    _In_ HWND OutputWindow,
    _In_ LPWSTR Parameter,
    _In_ ULONG_PTR Value)
{
    WCHAR szBuffer[32];

    szBuffer[0] = L'0';
    szBuffer[1] = L'x';
    szBuffer[2] = 0;
    u64tohex(Value, &szBuffer[2]);
    AddParameterValue(OutputWindow, Parameter, szBuffer);
}

/*
* AddParameterValue32Hex
*
* Purpose:
*
* Add text to the multiline richedit tabbed control (hex value).
*
*/
VOID AddParameterValue32Hex(
    _In_ HWND OutputWindow,
    _In_ LPWSTR Parameter,
    _In_ ULONG Value)
{
    WCHAR szBuffer[16];

    szBuffer[0] = L'0';
    szBuffer[1] = L'x';
    szBuffer[2] = 0;
    ultohex(Value, &szBuffer[2]);
    AddParameterValue(OutputWindow, Parameter, szBuffer);
}

/*
* AddParameterValueUlong
*
* Purpose:
*
* Add text to the multiline richedit tabbed control (ulong value).
*
*/
VOID AddParameterValueUlong(
    _In_ HWND OutputWindow,
    _In_ LPWSTR Parameter,
    _In_ ULONG Value)
{
    WCHAR szBuffer[16];

    szBuffer[0] = 0;
    ultostr(Value, szBuffer);
    AddParameterValue(OutputWindow, Parameter, szBuffer);
}

/*
* AddParameterValueBool
*
* Purpose:
*
* Add text to the multiline richedit tabbed control (bool value).
*
*/
VOID AddParameterValueBool(
    _In_ HWND OutputWindow,
    _In_ LPWSTR Parameter,
    _In_ BOOL Value)
{
    AddParameterValue(OutputWindow, Parameter, 
        (Value) ? TEXT("TRUE") : TEXT("FALSE"));
}

/*
* SysInfoCollectInformation
*
* Purpose:
*
* Build system information list including g_kdctx & g_WinObj data.
*
*/
VOID SysInfoCollectInformation(
    _In_ HWND hwndDlg
)
{
    BOOLEAN bCustomSignersAllowed;
    BOOLEAN bKdEnabled = FALSE, bKdAllowed = FALSE, bKdNotPresent = FALSE;
    LPWSTR lpType;
    ULONG Index, Value, SaveValue;

    PCHAR lpWineVersion;

    WCHAR szBuffer[MAX_PATH * 4], szWineVer[40];
    WCHAR szTemp[MAX_PATH];

    SYSTEM_CODEINTEGRITY_INFORMATION CodeIntegrity;
    SYSTEM_KERNEL_VA_SHADOW_INFORMATION KernelVaShadow;
    SYSTEM_SPECULATION_CONTROL_INFORMATION SpeculationControl;
    SYSTEM_VSM_PROTECTION_INFORMATION VsmProtectionInfo;
    SYSTEM_INFO SystemInfo;
    ULONG Dummy;

    FIRMWARE_TYPE fmType;
    LPWSTR lpFmType;

    HKEY hKey;
    DWORD dwType, cbData, dwValue;

    OBEX_CONFIG* obConfig = supGetParametersBlock();

    PARAFORMAT ParaFormat;
    CHARRANGE CharRange;

    HWND hwndOutput = GetDlgItem(hwndDlg, IDC_GLOBALS);

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    RtlSecureZeroMemory(szTemp, sizeof(szTemp));

    //
    // Prepare RichEdit.
    //
    SendMessage(hwndOutput, EM_SETEVENTMASK, (WPARAM)0, (LPARAM)0);
    SendMessage(hwndOutput, WM_SETREDRAW, (WPARAM)0, (LPARAM)0);

    RtlSecureZeroMemory(&ParaFormat, sizeof(ParaFormat));
    ParaFormat.cbSize = sizeof(ParaFormat);
    ParaFormat.cTabCount = 1;
    ParaFormat.dwMask = PFM_TABSTOPS;
    ParaFormat.rgxTabs[0] = 3500;
    SendMessage(hwndOutput, EM_SETPARAFORMAT, (WPARAM)0, (LPARAM)&ParaFormat);

    //
    // Collect information.

    //
    //
    // Generic environment information, WinObjEx64 version.
    //
    RtlStringCchPrintfSecure(szBuffer,
        100,
        TEXT("%lu.%lu.%lu"),
        PROGRAM_MAJOR_VERSION,
        PROGRAM_MINOR_VERSION,
        PROGRAM_REVISION_NUMBER);

    AddParameterValue(hwndOutput, TEXT("Windows Object Explorer 64"), szBuffer);

    //
    // OS version.
    //
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    if (g_WinObj.IsWine) {
        lpWineVersion = (PCHAR)GetWineVersion();
        RtlSecureZeroMemory(szWineVer, sizeof(szWineVer));
        if (0 == MultiByteToWideChar(CP_ACP, 0, lpWineVersion, (INT)_strlen_a(lpWineVersion),
            szWineVer, RTL_NUMBER_OF(szWineVer)))
        {
            _strcpy(szWineVer, TEXT("<unknown>"));
        }
        RtlStringCchPrintfSecure(szBuffer, MAX_PATH, TEXT("Wine v%ws, reported as "), szWineVer);
    }

    RtlStringCchPrintfSecure(_strend(szBuffer),
        100,
        TEXT("Windows NT %1u.%1u (build %u"),
        g_WinObj.osver.dwMajorVersion,
        g_WinObj.osver.dwMinorVersion,
        g_WinObj.osver.dwBuildNumber);

    if (g_WinObj.osver.szCSDVersion[0]) {
        _strcat(szBuffer, TEXT(", "));
        _strcat(szBuffer, g_WinObj.osver.szCSDVersion);
    }
    _strcat(szBuffer, TEXT(")"));

    AddParameterValue(hwndOutput, TEXT("System.OS"), szBuffer);

    //
    // CPU.
    //
    if (ERROR_SUCCESS == RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        TEXT("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"),
        0,
        KEY_QUERY_VALUE,
        &hKey))
    {
        RtlSecureZeroMemory(szTemp, sizeof(szTemp));
        szBuffer[0] = 0;

        cbData = 128;
        dwType = REG_NONE;
        if (ERROR_SUCCESS == RegQueryValueEx(
            hKey,
            TEXT("Identifier"),
            NULL,
            &dwType,
            (LPBYTE)&szTemp,
            &cbData))
        {
            _strcat(szBuffer, szTemp);
        }

        _strcat(szBuffer, TEXT(", "));

        cbData = 128;
        dwType = REG_NONE;
        if (ERROR_SUCCESS == RegQueryValueEx(
            hKey,
            TEXT("VendorIdentifier"),
            NULL,
            &dwType,
            (LPBYTE)&szTemp,
            &cbData))
        {
            _strcat(szBuffer, szTemp);
        }

        _strcat(szBuffer, TEXT(", "));

        cbData = sizeof(DWORD);
        dwType = REG_NONE;
        dwValue = 0;
        if (ERROR_SUCCESS == RegQueryValueEx(
            hKey,
            TEXT("~MHz"),
            NULL,
            &dwType,
            (LPBYTE)&dwValue,
            &cbData))
        {
            szTemp[0] = L'~';
            szTemp[1] = 0;
            ultostr(dwValue, &szTemp[1]);
            _strcat(szTemp, TEXT("MHz"));
            _strcat(szBuffer, szTemp);
        }

        AddParameterValue(hwndOutput, TEXT("Environment.Processor"), szBuffer);

        RegCloseKey(hKey);
    }

    GetSystemInfo(&SystemInfo);

    RtlStringCchPrintfSecure(szBuffer,
        MAX_PATH,
        TEXT("%lu, Mask 0x%08lX"),
        SystemInfo.dwNumberOfProcessors,
        SystemInfo.dwActiveProcessorMask);

    AddParameterValue(hwndOutput, TEXT("Environment.NumberOfProcessors"), szBuffer);

    AddParameterValueBool(hwndOutput, TEXT("Internal.IsFullAdmin"), g_kdctx.IsFullAdmin); //admin privileges available
    AddParameterValueBool(hwndOutput, TEXT("Internal.IsSecureBoot"), g_kdctx.IsSecureBoot); //secure boot enabled
    AddParameterValueBool(hwndOutput, TEXT("Internal.IsWine"), g_WinObj.IsWine);
    AddParameterValueBool(hwndOutput, TEXT("Internal.IsDebugPrivAssigned"), g_kdctx.IsDebugPrivAssigned);
    AddParameterValue32Hex(hwndOutput, TEXT("Internal.NameNormalizationSymbol"), (ULONG)g_ObNameNormalizationSymbol);

    if (obConfig->SymbolsDbgHelpDllValid) {
        AddParameterValue(hwndOutput, TEXT("Parameters.SymbolsDbgHelpDll"), obConfig->szSymbolsDbgHelpDll);
    }
    if (obConfig->SymbolsPathValid) {
        AddParameterValue(hwndOutput, TEXT("Parameters.SymbolsPath"), obConfig->szSymbolsPath);
    }

    AddParameterValueBool(hwndOutput, TEXT("MitigationFlags.ASLRPolicy"), g_kdctx.MitigationFlags.ASLRPolicy);
    AddParameterValueBool(hwndOutput, TEXT("MitigationFlags.DynamicCode"), g_kdctx.MitigationFlags.DynamicCode);
    AddParameterValueBool(hwndOutput, TEXT("MitigationFlags.ExtensionPointDisable"), g_kdctx.MitigationFlags.ExtensionPointDisable);
    AddParameterValueBool(hwndOutput, TEXT("MitigationFlags.ImageLoad"), g_kdctx.MitigationFlags.ImageLoad);
    AddParameterValueBool(hwndOutput, TEXT("MitigationFlags.Signature"), g_kdctx.MitigationFlags.Signature);

    //
    // Helper driver state.
    //
    AddParameterValue32Hex(hwndOutput, TEXT("Driver.LoadStatus"), g_kdctx.DriverContext.LoadStatus);
    AddParameterValue32Hex(hwndOutput, TEXT("Driver.OpenStatus"), g_kdctx.DriverContext.OpenStatus);
    AddParameterValueBool(hwndOutput, TEXT("Driver.IsOurLoad"), g_kdctx.DriverContext.IsOurLoad); //driver was loaded by our program instance

    switch (WDrvGetActiveProviderType()) {
    case wdrvAlice:
        lpType = L"Alice";
        break;
    case wdrvRkhDrv5:
        lpType = L"Rkhdrv5";
        break;
    case wdrvWinIo:
        lpType = L"WinIo";
        break;
    case wdrvWinObjEx64:
        lpType = L"WinObjEx64";
        break;
    case wdrvMicrosoft:
    default:
        lpType = L"Microsoft";
        break;
    }
    AddParameterValue(hwndOutput, TEXT("Driver.SelectedProvider"), lpType);

    //
    // Ntoskrnl
    //
    AddParameterValue64Hex(hwndOutput, TEXT("Loader.NtOsBase"), (ULONG_PTR)g_kdctx.NtOsBase);
    AddParameterValue64Hex(hwndOutput, TEXT("Loader.NtOsImageMap"), (ULONG_PTR)g_kdctx.NtOsImageMap);//mapped image address
    AddParameterValue32Hex(hwndOutput, TEXT("Loader.NtOsSize"), g_kdctx.NtOsSize);//mapped image size

    //
    // Ntoskrnl symbols
    //
    AddParameterValue64Hex(hwndOutput, TEXT("NtSymContext.ContextBase"), (ULONG_PTR)g_kdctx.NtOsSymContext);
    if (g_kdctx.NtOsSymContext) {
        AddParameterValue64Hex(hwndOutput, TEXT("NtSymContext.ModuleBase"), ((PSYMCONTEXT)g_kdctx.NtOsSymContext)->ModuleBase);
    }

    //
    // Product info
    //
    AddParameterValueBool(hwndOutput, TEXT("System.LTSC"), supIsLongTermServicingWindows());

    //
    // KD state
    //
    bKdEnabled = supIsKdEnabled(&bKdAllowed, &bKdNotPresent);
    AddParameterValueBool(hwndOutput, TEXT("System.KdEnabled"), bKdEnabled);
    AddParameterValueBool(hwndOutput, TEXT("System.KdAllowed"), bKdAllowed);
    AddParameterValueBool(hwndOutput, TEXT("System.KdNotPresent"), bKdNotPresent);

    //
    // Firmware type
    //
    fmType = g_kdctx.Data->FirmwareType;
    switch (fmType) {

    case FirmwareTypeBios:
        lpFmType = TEXT("BIOS");
        break;

    case FirmwareTypeUefi:
        lpFmType = TEXT("UEFI");
        break;

    default:
        lpFmType = TEXT("Unknown");
        break;
    }
    AddParameterValue(hwndOutput, TEXT("System.FirmwareType"), lpFmType);

    //
    // Is OS Disk VHD?
    //
    AddParameterValueBool(hwndOutput, TEXT("System.IsOsDiskVhd"), g_kdctx.IsOsDiskVhd);

    //
    // System ranges
    //
    AddParameterValue64Hex(hwndOutput, TEXT("System.SystemRangeStart"), (ULONG_PTR)g_kdctx.SystemRangeStart);
    AddParameterValue64Hex(hwndOutput, TEXT("System.MinimumUserModeAddress"), (ULONG_PTR)g_kdctx.MinimumUserModeAddress);
    AddParameterValue64Hex(hwndOutput, TEXT("System.MaximumUserModeAddress"), (ULONG_PTR)g_kdctx.MaximumUserModeAddress);

    if (g_kdctx.IsFullAdmin) {

        //
        // List kldbg data if there is something to show since this data fetched dynamically during usage.
        //
        AddParameterValueBool(hwndOutput, TEXT("System.ObHeaderCookieValid"), g_kdctx.Data->ObHeaderCookie.Valid);
        AddParameterValue32Hex(hwndOutput, TEXT("System.ObHeaderCookie"), g_kdctx.Data->ObHeaderCookie.Value);
        AddParameterValueUlong(hwndOutput, TEXT("System.DirectoryTypeIndex"), g_kdctx.DirectoryTypeIndex);

        if (g_kdctx.DirectoryRootObject)
            AddParameterValue64Hex(hwndOutput, TEXT("System.DirectoryRootObject"), g_kdctx.DirectoryRootObject);

        if (g_kdctx.Data->KeServiceDescriptorTable.Limit)
            AddParameterValueUlong(hwndOutput, TEXT("System.KiServiceLimit"), g_kdctx.Data->KeServiceDescriptorTable.Limit);

        if (g_kdctx.Data->KeServiceDescriptorTable.Base)
            AddParameterValue64Hex(hwndOutput, TEXT("System.KiServiceTableAddress"), (ULONG_PTR)g_kdctx.Data->KeServiceDescriptorTable.Base);

        if (g_kdctx.Data->IopInvalidDeviceRequest)
            AddParameterValue64Hex(hwndOutput, TEXT("System.IopInvalidDeviceRequest"), (ULONG_PTR)g_kdctx.Data->IopInvalidDeviceRequest);

        if (g_kdctx.Data->PrivateNamespaceLookupTable)
            AddParameterValue64Hex(hwndOutput, TEXT("System.PrivateNamespaceLookupTable"), (ULONG_PTR)g_kdctx.Data->PrivateNamespaceLookupTable);

    }
    //
    // List other data.
    //
    if (NT_SUCCESS(supCICustomKernelSignersAllowed(&bCustomSignersAllowed))) {
        AddParameterValueBool(hwndOutput, TEXT("System.CICustomKernelSignersAllowed"), bCustomSignersAllowed);
    }

    AddParameterValueUlong(hwndOutput, TEXT("System.DpiValue"), (ULONG)supGetDPIValue(NULL));

    CodeIntegrity.Length = sizeof(CodeIntegrity);
    CodeIntegrity.CodeIntegrityOptions = 0;
    if (NT_SUCCESS(NtQuerySystemInformation(
        SystemCodeIntegrityInformation,
        &CodeIntegrity,
        sizeof(CodeIntegrity),
        &Dummy)))
    {
        AddParameterValue32Hex(hwndOutput, TEXT("System.CodeIntegrityOptions"), CodeIntegrity.CodeIntegrityOptions);

        if (CodeIntegrity.CodeIntegrityOptions) {

            for (Index = 0; Index < RTL_NUMBER_OF(CodeIntegrityValuesList); Index++) {

                if (CodeIntegrity.CodeIntegrityOptions & CodeIntegrityValuesList[Index].dwValue) {
                    AddParameterValue(
                        hwndOutput,
                        TEXT("System.CodeIntegrityOption"),
                        CodeIntegrityValuesList[Index].lpDescription);
                    CodeIntegrity.CodeIntegrityOptions &= ~CodeIntegrityValuesList[Index].dwValue;
                }
            }

            if (CodeIntegrity.CodeIntegrityOptions) {
                Value = 1;
                SaveValue = CodeIntegrity.CodeIntegrityOptions;
                while (SaveValue) {
                    if (SaveValue & Value) {
                        AddParameterValue32Hex(hwndOutput, TEXT("System.CodeIntegrityOption(unknown)"), Value);
                        SaveValue &= ~Value;
                    }
                    Value *= 2;
                }
            }
        }
    }

    KernelVaShadow.Flags = 0;
    if (NT_SUCCESS(NtQuerySystemInformation(
        SystemKernelVaShadowInformation,
        &KernelVaShadow,
        sizeof(KernelVaShadow),
        &Dummy)))
    {
        AddParameterValue32Hex(hwndOutput, TEXT("System.KvaShadowFlags"), KernelVaShadow.Flags);
    }

    SpeculationControl.Flags = 0;
    if (NT_SUCCESS(NtQuerySystemInformation(
        SystemSpeculationControlInformation,
        &SpeculationControl,
        sizeof(SpeculationControl),
        &Dummy)))
    {
        AddParameterValue32Hex(hwndOutput, TEXT("System.SpeculationControlFlags"), SpeculationControl.Flags);
    }

    AddParameterValue(hwndOutput, TEXT("System.TempDirectory"), g_WinObj.szTempDirectory);
    AddParameterValue(hwndOutput, TEXT("System.WindowsDirectory"), g_WinObj.szWindowsDirectory);
    AddParameterValue(hwndOutput, TEXT("System.SystemDirectory"), g_WinObj.szSystemDirectory);
    AddParameterValue(hwndOutput, TEXT("System.ProgramDirectory"), g_WinObj.szProgramDirectory);

    RtlSecureZeroMemory(&VsmProtectionInfo, sizeof(VsmProtectionInfo));
    if (NT_SUCCESS(NtQuerySystemInformation(
        SystemVsmProtectionInformation,
        &VsmProtectionInfo,
        sizeof(VsmProtectionInfo),
        &Dummy)))
    {
        AddParameterValueBool(hwndOutput, TEXT("Vsm.DmaProtectionsAvailable"), VsmProtectionInfo.DmaProtectionsAvailable);
        AddParameterValueBool(hwndOutput, TEXT("Vsm.DmaProtectionsInUse"), VsmProtectionInfo.DmaProtectionsInUse);
        AddParameterValueBool(hwndOutput, TEXT("Vsm.HardwareMbecAvailable"), VsmProtectionInfo.HardwareMbecAvailable);
        AddParameterValueBool(hwndOutput, TEXT("Vsm.ApicVirtualizationAvailable"), VsmProtectionInfo.ApicVirtualizationAvailable);
    }

    //
    // End work with RichEdit.
    //
    SendMessage(hwndOutput, WM_SETREDRAW, (WPARAM)TRUE, (LPARAM)0);
    InvalidateRect(hwndOutput, NULL, TRUE);

    SendMessage(hwndOutput, EM_SETEVENTMASK, (WPARAM)0, (LPARAM)ENM_SELCHANGE);

    CharRange.cpMax = 0;
    CharRange.cpMin = 0;
    SendMessage(hwndOutput, EM_EXSETSEL, (WPARAM)0, (LPARAM)&CharRange);

    SetFocus(hwndOutput);
}

/*
* SysInfoCopyToClipboard
*
* Purpose:
*
* Copy text to the clipboard.
*
*/
VOID SysInfoCopyToClipboard(
    _In_ HWND hwndDlg
)
{
    SIZE_T BufferSize;
    PWCHAR Buffer;

    GETTEXTLENGTHEX gtl;
    GETTEXTEX gt;

    HWND hwndControl = GetDlgItem(hwndDlg, IDC_GLOBALS);

    gtl.flags = GTL_USECRLF;
    gtl.codepage = 1200;

    BufferSize = SendMessage(hwndControl, EM_GETTEXTLENGTHEX, (WPARAM)&gtl, 0);
    if (BufferSize) {

        BufferSize *= sizeof(WCHAR);

        Buffer = (PWCHAR)supHeapAlloc(BufferSize);
        if (Buffer) {

            gt.flags = GT_USECRLF;
            gt.cb = (ULONG)BufferSize;

            gt.codepage = 1200;
            gt.lpDefaultChar = NULL;
            gt.lpUsedDefChar = NULL;
            SendMessage(hwndControl, EM_GETTEXTEX, (WPARAM)&gt, (LPARAM)Buffer);

            supClipboardCopy(Buffer, BufferSize);

            supHeapFree(Buffer);
        }
    }
}

/*
* SysInfoDialogProc
*
* Purpose:
*
* System information dialog window procedure.
*
*/
LRESULT CALLBACK SysInfoDialogProc(
    _In_ HWND hwnd,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    UNREFERENCED_PARAMETER(lParam);

    switch (uMsg) {
    case WM_SHOWWINDOW:
        if (LOWORD(wParam)) {
            SysInfoCollectInformation(hwnd);
        }
        return TRUE;

    case WM_COMMAND:
        switch (GET_WM_COMMAND_ID(wParam, lParam)) {
        case IDC_GLOBALS_COPY:
            SysInfoCopyToClipboard(hwnd);
            break;
        case IDCANCEL:
            return EndDialog(hwnd, S_OK);
        }

    }
    return 0;
}

/*
* ShowSysInfoDialog
*
* Purpose:
*
* Prepare and show globals window.
*
*/
VOID ShowSysInfoDialog(
    _In_ HWND hwndParent
)
{
    if (!supRichEdit32Load()) {
        MessageBox(hwndParent, TEXT("Could not load RichEdit library"), NULL, MB_ICONERROR);
        return;
    }

    DialogBoxParam(g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_GLOBALS),
        hwndParent,
        (DLGPROC)&SysInfoDialogProc,
        (LPARAM)hwndParent);
}
