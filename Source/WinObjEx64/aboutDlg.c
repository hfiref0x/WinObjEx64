/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       ABOUTDLG.C
*
*  VERSION:     1.84
*
*  DATE:        22 Feb 2020
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "msvcver.h"
#include <Richedit.h>
#include "winedebug.h"

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
    { L"CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED", CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED }
};

/*
* AboutDialogInit
*
* Purpose:
*
* Displays program version and system information
*
*/
VOID AboutDialogInit(
    HWND hwndDlg
)
{
    BOOLEAN  bSecureBoot = FALSE;
    BOOLEAN  bHVCIEnabled = FALSE, bHVCIStrict = FALSE, bHVCIIUMEnabled = FALSE;
    ULONG    returnLength;
    NTSTATUS status;
    HANDLE   hImage;
    WCHAR    szBuffer[MAX_PATH];

    PCHAR    wine_ver, wine_str;

    SYSTEM_BOOT_ENVIRONMENT_INFORMATION sbei;
    SYSTEM_VHD_BOOT_INFORMATION* psvbi;

    SetDlgItemText(hwndDlg, ID_ABOUT_PROGRAM, PROFRAM_NAME_AND_TITLE);

    RtlStringCchPrintfSecure(szBuffer,
        MAX_PATH,
        TEXT("%lu.%lu.%lu"),
        PROGRAM_MAJOR_VERSION,
        PROGRAM_MINOR_VERSION,
        PROGRAM_REVISION_NUMBER);

    SetDlgItemText(hwndDlg, ID_ABOUT_BUILDINFO, szBuffer);

    //
    // Set dialog icon.
    //
    hImage = LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_MAIN), IMAGE_ICON, 48, 48, LR_SHARED);
    if (hImage) {
        SendMessage(GetDlgItem(hwndDlg, ID_ABOUT_ICON), STM_SETIMAGE, IMAGE_ICON, (LPARAM)hImage);
        DestroyIcon((HICON)hImage);
    }

    //
    // Remove class icon if any.
    //
    SetClassLongPtr(hwndDlg, GCLP_HICON, (LONG_PTR)NULL);

    //
    // Set compiler version and name.
    //
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    _strcpy(szBuffer, VC_VER);
    if (szBuffer[0] == 0) {
        _strcpy(szBuffer, TEXT("MSVC ("));
        ultostr(_MSC_FULL_VER, _strend(szBuffer));
        _strcat(szBuffer, TEXT(")"));
    }
#if defined(__cplusplus)
    _strcat(szBuffer, TEXT(" compiled as C++"));
#else
    _strcat(szBuffer, TEXT(" compiled as C"));
#endif

    SetDlgItemText(hwndDlg, ID_ABOUT_COMPILERINFO, szBuffer);

    //
    // Set build date and time.
    //
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    MultiByteToWideChar(CP_ACP, 0, __DATE__, (INT)_strlen_a(__DATE__), szBuffer, 40);
    _strcat(szBuffer, TEXT(" "));
    MultiByteToWideChar(CP_ACP, 0, __TIME__, (INT)_strlen_a(__TIME__), _strend(szBuffer), 40);
    SetDlgItemText(hwndDlg, ID_ABOUT_BUILDDATE, szBuffer);

    //
    // Fill OS name.
    //
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    if (g_WinObj.IsWine) {
        _strcpy(szBuffer, TEXT("Reported as "));
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

    //
    // Fill boot options.
    //   
    if (g_WinObj.IsWine) {
        wine_ver = (PCHAR)wine_get_version();
        wine_str = (PCHAR)supHeapAlloc(_strlen_a(wine_ver) + MAX_PATH);
        if (wine_str) {
            _strcpy_a(wine_str, "Wine ");
            _strcat_a(wine_str, wine_ver);
            SetDlgItemTextA(hwndDlg, ID_ABOUT_OSNAME, wine_str);
            supHeapFree(wine_str);
        }
        SetDlgItemText(hwndDlg, ID_ABOUT_ADVINFO, szBuffer);

    }
    else {
        SetDlgItemText(hwndDlg, ID_ABOUT_OSNAME, szBuffer);

        RtlSecureZeroMemory(&sbei, sizeof(sbei));
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));

        //
        // Query KD debugger enabled.
        //
        if (kdIsDebugBoot()) {
            _strcpy(szBuffer, TEXT("Debug, "));
        }

        //
        // Query VHD boot state if possible.
        //
        psvbi = (SYSTEM_VHD_BOOT_INFORMATION*)supHeapAlloc(PAGE_SIZE);
        if (psvbi) {
            status = NtQuerySystemInformation(SystemVhdBootInformation, psvbi, PAGE_SIZE, &returnLength);
            if (NT_SUCCESS(status)) {
                if (psvbi->OsDiskIsVhd) {
                    _strcat(szBuffer, TEXT("VHD, "));
                }
            }
            supHeapFree(psvbi);
        }

        //
        // Query firmware mode and SecureBoot state for UEFI.
        //
        status = NtQuerySystemInformation(SystemBootEnvironmentInformation, &sbei, sizeof(sbei), &returnLength);
        if (NT_SUCCESS(status)) {

            if (sbei.FirmwareType == FirmwareTypeUefi) {
                _strcat(szBuffer, TEXT("UEFI"));
            }
            else {
                if (sbei.FirmwareType == FirmwareTypeBios) {
                    _strcat(szBuffer, TEXT("BIOS"));
                }
                else {
                    _strcat(szBuffer, TEXT("Unknown"));
                }
            }

            if (sbei.FirmwareType == FirmwareTypeUefi) {
                bSecureBoot = FALSE;
                if (supQuerySecureBootState(&bSecureBoot)) {
                    _strcat(szBuffer, TEXT(" with"));
                    if (bSecureBoot == FALSE) {
                        _strcat(szBuffer, TEXT("out"));
                    }
                    _strcat(szBuffer, TEXT(" SecureBoot"));
                }
                g_kdctx.IsSecureBoot = bSecureBoot;

                if (bSecureBoot) {
                    if (supQueryHVCIState(&bHVCIEnabled, &bHVCIStrict, &bHVCIIUMEnabled)) {
                        if (bHVCIEnabled) {
                            _strcat(szBuffer, TEXT(", HVCI"));
                            if (bHVCIStrict)
                                _strcat(szBuffer, TEXT(" (strict)"));
                            if (bHVCIIUMEnabled)
                                _strcat(szBuffer, TEXT(", IUM"));
                        }
                    }
                }
            }
        }
        else {
            _strcpy(szBuffer, TEXT("Unknown"));
        }
        SetDlgItemText(hwndDlg, ID_ABOUT_ADVINFO, szBuffer);
    }

    SetFocus(GetDlgItem(hwndDlg, IDOK));
}

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
    _In_ LPWSTR Parameter,
    _In_ LPWSTR Value)
{
    LONG StartPos = 0;

    CHARFORMAT CharFormat;
    CHARRANGE CharRange, SelectedRange;

    CharRange.cpMax = 0x7FFFFFFF;
    CharRange.cpMin = 0x7FFFFFFF;

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
    SendMessage(OutputWindow, EM_REPLACESEL, (WPARAM)0, (LPARAM)L":\t");
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
* AboutDialogCollectGlobals
*
* Purpose:
*
* Build globals list (g_kdctx + g_WinObj).
*
*/
VOID AboutDialogCollectGlobals(
    _In_ HWND hwndDlg,
    _In_ HWND hwndParent
)
{
    BOOLEAN bCustomSignersAllowed;

    ULONG Index, Value, SaveValue;

    WCHAR szBuffer[MAX_PATH * 4];
    WCHAR szTemp[MAX_PATH];

    SYSTEM_CODEINTEGRITY_INFORMATION CodeIntegrity;
    SYSTEM_KERNEL_VA_SHADOW_INFORMATION KernelVaShadow;
    SYSTEM_SPECULATION_CONTROL_INFORMATION SpeculationControl;
    SYSTEM_INFO SystemInfo;
    ULONG Dummy;

    HKEY hKey;
    DWORD dwType, cbData, dwValue;

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
    GetDlgItemText(hwndParent, ID_ABOUT_OSNAME, szBuffer, MAX_PATH);
    AddParameterValue(hwndOutput, TEXT("Operation System"), szBuffer);

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

        AddParameterValue(hwndOutput, TEXT("Processor"), szBuffer);

        RegCloseKey(hKey);
    }

    GetSystemInfo(&SystemInfo);

    RtlStringCchPrintfSecure(szBuffer,
        MAX_PATH,
        TEXT("%lu, Mask 0x%08lX"),
        SystemInfo.dwNumberOfProcessors,
        SystemInfo.dwActiveProcessorMask);

    AddParameterValue(hwndOutput, TEXT("Number of Processors"), szBuffer);

    //
    // List g_kdctx.
    //
    szBuffer[0] = L'0';
    szBuffer[1] = L'x';
    szBuffer[2] = 0;
    ultohex(g_kdctx.DriverOpenLoadStatus, &szBuffer[2]);
    if (g_kdctx.DriverOpenLoadStatus == STATUS_SUCCESS) {
        _strcat(szBuffer, TEXT(" (reported as OK)"));
    }
    AddParameterValue(hwndOutput, TEXT("DriverOpenLoadStatus"), szBuffer);    
    
    AddParameterValue32Hex(hwndOutput, TEXT("DriverOpenStatus"), g_kdctx.DriverOpenStatus);

    AddParameterValueUlong(hwndOutput, TEXT("IsSecureBoot"), g_kdctx.IsSecureBoot);

    AddParameterValueUlong(hwndOutput, TEXT("IsFullAdmin"), g_kdctx.IsFullAdmin);

    AddParameterValueUlong(hwndOutput, TEXT("IsOurLoad"), g_kdctx.IsOurLoad);

    AddParameterValue64Hex(hwndOutput, TEXT("DirectoryRootAddress"), g_kdctx.DirectoryRootAddress);

    AddParameterValueUlong(hwndOutput, TEXT("DirectoryTypeIndex"), g_kdctx.DirectoryTypeIndex);

    AddParameterValue64Hex(hwndOutput, TEXT("KLDBG DeviceHandle"), (ULONG_PTR)g_kdctx.DeviceHandle);

    AddParameterValue64Hex(hwndOutput, TEXT("IopInvalidDeviceRequest"), (ULONG_PTR)g_kdctx.IopInvalidDeviceRequest);

    AddParameterValueUlong(hwndOutput, TEXT("KiServiceLimit"), g_kdctx.KeServiceDescriptorTable.Limit);

    AddParameterValue64Hex(hwndOutput, TEXT("KiServiceTableAddress"), (ULONG_PTR)g_kdctx.KeServiceDescriptorTable.Base);

    AddParameterValue64Hex(hwndOutput, TEXT("NtOsBase"), (ULONG_PTR)g_kdctx.NtOsBase);

    AddParameterValueUlong(hwndOutput, TEXT("NtOsSize"), g_kdctx.NtOsSize);

    AddParameterValue64Hex(hwndOutput, TEXT("NtOsImageMap"), (ULONG_PTR)g_kdctx.NtOsImageMap);

    AddParameterValueUlong(hwndOutput, TEXT("ObHeaderCookie"), g_kdctx.ObHeaderCookie);

    AddParameterValue64Hex(hwndOutput, TEXT("PrivateNamespaceLookupTable"), (ULONG_PTR)g_kdctx.PrivateNamespaceLookupTable);

    AddParameterValue64Hex(hwndOutput, TEXT("SystemRangeStart"), (ULONG_PTR)g_kdctx.SystemRangeStart);

    //
    // List g_WinObj (UI specific).
    //
    AddParameterValueUlong(hwndOutput, TEXT("UseExperimentalFeatures"), g_WinObj.UseExperimentalFeatures);
    AddParameterValueUlong(hwndOutput, TEXT("IsWine"), g_WinObj.IsWine);

    //
    // For MMIO usage.
    //
    AddParameterValueUlong(hwndOutput, TEXT("EnableFullMitigations"), g_WinObj.EnableFullMitigations);

    //
    // List other data.
    //
    if (NT_SUCCESS(supCICustomKernelSignersAllowed(&bCustomSignersAllowed))) {
        AddParameterValueUlong(hwndOutput, TEXT("CICustomKernelSignersAllowed"), (ULONG)bCustomSignersAllowed);
    }
    AddParameterValueUlong(hwndOutput, TEXT("DPI Value"), (ULONG)supGetDPIValue(NULL));

    CodeIntegrity.Length = sizeof(CodeIntegrity);
    CodeIntegrity.CodeIntegrityOptions = 0;
    if (NT_SUCCESS(NtQuerySystemInformation(
        SystemCodeIntegrityInformation,
        &CodeIntegrity,
        sizeof(CodeIntegrity),
        &Dummy)))
    {
        AddParameterValue32Hex(hwndOutput, TEXT("CI Options Value"), CodeIntegrity.CodeIntegrityOptions);

        if (CodeIntegrity.CodeIntegrityOptions) {

            for (Index = 0; Index < RTL_NUMBER_OF(CodeIntegrityValuesList); Index++) {

                if (CodeIntegrity.CodeIntegrityOptions & CodeIntegrityValuesList[Index].dwValue) {
                    AddParameterValue(
                        hwndOutput,
                        TEXT("CI Option"),
                        CodeIntegrityValuesList[Index].lpDescription);
                    CodeIntegrity.CodeIntegrityOptions &= ~CodeIntegrityValuesList[Index].dwValue;
                }
            }

            if (CodeIntegrity.CodeIntegrityOptions) {
                Value = 1;
                SaveValue = CodeIntegrity.CodeIntegrityOptions;
                while (SaveValue) {
                    if (SaveValue & Value) {
                        AddParameterValue32Hex(hwndOutput, TEXT("CI Option (unknown)"), Value);
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
        AddParameterValue32Hex(hwndOutput, TEXT("KvaShadow Flags"), KernelVaShadow.Flags);
    }

    SpeculationControl.Flags = 0;
    if (NT_SUCCESS(NtQuerySystemInformation(
        SystemSpeculationControlInformation,
        &SpeculationControl,
        sizeof(SpeculationControl),
        &Dummy)))
    {
        AddParameterValue32Hex(hwndOutput, TEXT("SpeculationControl Flags"), SpeculationControl.Flags);
    }

    AddParameterValue(hwndOutput, TEXT("TempDirectory"), g_WinObj.szTempDirectory);
    AddParameterValue(hwndOutput, TEXT("WindowsDirectory"), g_WinObj.szWindowsDirectory);
    AddParameterValue(hwndOutput, TEXT("SystemDirectory"), g_WinObj.szSystemDirectory);
    AddParameterValue(hwndOutput, TEXT("ProgramDirectory"), g_WinObj.szProgramDirectory);

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
* GlobalsCopyToClipboard
*
* Purpose:
*
* Copy globals to the clipboard.
*
*/
VOID GlobalsCopyToClipboard(
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
* GlobalsWindowProc
*
* Purpose:
*
* Globals dialog window procedure.
*
*/
LRESULT CALLBACK GlobalsWindowProc(
    _In_ HWND hwnd,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    HWND hwndParent = (HWND)lParam;

    switch (uMsg) {
    case WM_INITDIALOG:

        AboutDialogCollectGlobals(hwnd, hwndParent);
        break;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_GLOBALS_COPY:
            GlobalsCopyToClipboard(hwnd);
            break;
        case IDCANCEL:
            return EndDialog(hwnd, S_OK);
            break;
        default:
            break;
        }

    default:
        break;
    }
    return 0;
}

/*
* AboutDialogShowGlobals
*
* Purpose:
*
* Prepare and show globals window.
*
*/
VOID AboutDialogShowGlobals(
    _In_ HWND hwndParent
)
{
    HANDLE RichEditHandle;

    WCHAR szBuffer[MAX_PATH * 2];

    RichEditHandle = GetModuleHandle(T_RICHEDIT_LIB);
    if (RichEditHandle == NULL) {

        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));

        RtlStringCchPrintfSecure(szBuffer,
            sizeof(szBuffer) / sizeof(szBuffer[0]),
            TEXT("%s\\%s"),
            g_WinObj.szSystemDirectory,
            T_RICHEDIT_LIB);

        RichEditHandle = LoadLibraryEx(szBuffer, NULL, 0);
    }

    if (RichEditHandle == NULL)
        return;

    DialogBoxParam(g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_GLOBALS),
        hwndParent,
        (DLGPROC)&GlobalsWindowProc,
        (LPARAM)hwndParent);
}

/*
* AboutDialogProc
*
* Purpose:
*
* About Dialog Window Dialog Procedure
*
* During WM_INITDIALOG centers window and initializes system info
*
*/
INT_PTR CALLBACK AboutDialogProc(
    _In_ HWND   hwndDlg,
    _In_ UINT   uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    UNREFERENCED_PARAMETER(lParam);

    switch (uMsg) {

    case WM_INITDIALOG:
        supCenterWindow(hwndDlg);
        AboutDialogInit(hwndDlg);
        break;

    case WM_COMMAND:

        switch (LOWORD(wParam)) {
        case IDOK:
        case IDCANCEL:
            return EndDialog(hwndDlg, S_OK);
            break;
        case IDC_ABOUT_GLOBALS:
            AboutDialogShowGlobals(hwndDlg);
            break;
        default:
            break;
        }

    default:
        break;
    }
    return 0;
}
