/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2024
*
*  TITLE:       SUP.C
*
*  VERSION:     2.04
*
*  DATE:        12 Jan 2024
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "treelist/treelist.h"
#include "props/propTypeConsts.h"

#ifndef OBEX_DEFINE_GUID
#define OBEX_DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
     EXTERN_C const GUID DECLSPEC_SELECTANY name \
                = { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }  
#endif

OBEX_DEFINE_GUID(ShimDriverScope, 0xBC04AB45, 0xEA7E, 0x4A11, 0xA7, 0xBB, 0x97, 0x76, 0x15, 0xF4, 0xCA, 0xAE);
OBEX_DEFINE_GUID(ShimVersionLie1, 0x3E28B2D1, 0xE633, 0x408C, 0x8E, 0x9B, 0x2A, 0xFA, 0x6F, 0x47, 0xFC, 0xC3);
OBEX_DEFINE_GUID(ShimVersionLie2, 0x47712F55, 0xBD93, 0x43FC, 0x92, 0x48, 0xB9, 0xA8, 0x37, 0x10, 0x06, 0x6E);
OBEX_DEFINE_GUID(ShimVersionLie3, 0x21C4FB58, 0xD477, 0x4839, 0xA7, 0xEA, 0xAD, 0x69, 0x18, 0xFB, 0xC5, 0x18);
OBEX_DEFINE_GUID(ShimSkipDriverUnload, 0x3E8C2CA6, 0x34E2, 0x4DE6, 0x8A, 0x1E, 0x96, 0x92, 0xDD, 0x3E, 0x31, 0x6B);
OBEX_DEFINE_GUID(ShimZeroPool, 0x6B847429, 0xC430, 0x4682, 0xB5, 0x5F, 0xFD, 0x11, 0xA7, 0xB5, 0x54, 0x65);
OBEX_DEFINE_GUID(ShimClearPCIDBits, 0xB4678DFF, 0xBD3E, 0x46C9, 0x92, 0x3B, 0xB5, 0x73, 0x34, 0x83, 0xB0, 0xB3);
OBEX_DEFINE_GUID(ShimKaspersky, 0xB4678DFF, 0xCC3E, 0x46C9, 0x92, 0x3B, 0xB5, 0x73, 0x34, 0x83, 0xB0, 0xB3);
OBEX_DEFINE_GUID(ShimMemcpy, 0x8A2517C1, 0x35D6, 0x4CA8, 0x9E, 0xC8, 0x98, 0xA1, 0x27, 0x62, 0x89, 0x1B);
OBEX_DEFINE_GUID(ShimKernelPadSectionsOverride, 0x4F55C0DB, 0x73D3, 0x43F2, 0x97, 0x23, 0x8A, 0x9C, 0x7F, 0x79, 0xD3, 0x9D);
OBEX_DEFINE_GUID(ShimNdisVersionLie, 0x49691313, 0x1362, 0x4E75, 0x8C, 0x2A, 0x2D, 0xD7, 0x29, 0x28, 0xEB, 0xA5);
OBEX_DEFINE_GUID(ShimSrb, 0x434ABAFD, 0x08FA, 0x4C3D, 0xA8, 0x8D, 0xD0, 0x9A, 0x88, 0xE2, 0xAB, 0x17);
OBEX_DEFINE_GUID(ShimDeviceId, 0x0332EC62, 0x865A, 0x4A39, 0xB4, 0x8F, 0xCD, 0xA6, 0xE8, 0x55, 0xF4, 0x23);
OBEX_DEFINE_GUID(ShimATADeviceId, 0x26665D57, 0x2158, 0x4E4B, 0xA9, 0x59, 0xC9, 0x17, 0xD0, 0x3A, 0x0D, 0x7E);
OBEX_DEFINE_GUID(ShimBluetoothFilterPower, 0x6AD90DAD, 0xC144, 0x4E9D, 0xA0, 0xCF, 0xAE, 0x9F, 0xCB, 0x90, 0x1E, 0xBD);
OBEX_DEFINE_GUID(ShimUsbConexant, 0xFD8FD62E, 0x4D94, 0x4FC7, 0x8A, 0x68, 0xBF, 0xF7, 0x86, 0x5A, 0x70, 0x6B);
OBEX_DEFINE_GUID(ShimNokiaPCSuite, 0x7DD60997, 0x651F, 0x4ECB, 0xB8, 0x93, 0xBE, 0xC8, 0x05, 0x0F, 0x3B, 0xD7);
OBEX_DEFINE_GUID(ShimCetCompat, 0x31971B07, 0x71A4, 0x480A, 0x87, 0xA9, 0xD9, 0xD2, 0x76, 0x99, 0xA0, 0x7E);

SUP_SHIM_INFO KsepShimInformation[] = {
    { L"DriverScope", (GUID*)&ShimDriverScope, L"ETW event logger", L"ntos" },
    { L"VersionLie 7",  (GUID*)&ShimVersionLie1, L"Reports previous version of OS", L"ntos" },
    { L"VersionLie 8",  (GUID*)&ShimVersionLie2, L"Reports previous version of OS", L"ntos" },
    { L"VersionLie 8.1",  (GUID*)&ShimVersionLie3, L"Reports previous version of OS", L"ntos" },
    { L"SkipDriverUnload", (GUID*)&ShimSkipDriverUnload, L"Replaces driver unload with ETW hook", L"ntos" },
    { L"ZeroPool", (GUID*)&ShimZeroPool, L"ExAllocatePool hook that forces zeroes allocation", L"ntos" },
    { L"ClearPCIDBits", (GUID*)&ShimClearPCIDBits, L"Clears PCID bits for some ISV", L"ntos" },
    { L"Kaspersky", (GUID*)&ShimKaspersky, L"Kaspersky driver forced bugfix", L"ntos" },
    { L"memcpy", (GUID*)&ShimMemcpy, L"The memcpy hook to \"safer\" variant", L"ntos" },
    { L"KernelPadSectionsOverride", (GUID*)&ShimKernelPadSectionsOverride, L"Blocks drivers discardable section disposal", L"ntos" },
    { L"NdisVersionLie", (GUID*)&ShimNdisVersionLie, L"Reports NDIS version 6.40", L"ndis" },
    { L"SrbShim", (GUID*)&ShimSrb, L"SCSI request IOCTL_STORAGE_QUERY_PROPERTY compatibility hook", L"storport" },
    { L"DeviceIdShim", (GUID*)&ShimDeviceId, L"RAID compatibility shim", L"storport" },
    { L"ATADeviceIdShim", (GUID*)&ShimATADeviceId, L"SATA compatibility shim", L"storport" },
    { L"BluetoothFilterPowerShim", (GUID*)&ShimBluetoothFilterPower, L"Bluetooth filter driver compatibility shim", L"bthport" },
    { L"UsbConexantShim", (GUID*)&ShimUsbConexant, L"USB modem compatibility shim", L"usbd" },
    { L"NokiaShim", (GUID*)&ShimNokiaPCSuite, L"Nokia PC Suite compatibility shim", L"usbd" },
    { L"UserCetBasicModeAllowRetTargetNotCetCompat", (GUID*)&ShimCetCompat, L"Intel CET compatibility shim", L"ntos"}
};

LIST_ENTRY supShutdownListHead;
CRITICAL_SECTION supShutdownListLock;

HANDLE ObjectPathHeap = NULL;

OBEX_CONFIG g_LoadedParametersBlock;

//
// Setup info/SCM database.
//
SAPIDB g_sapiDB;
SCMDB g_scmDB;

HWND BannerWindow = NULL;

int __cdecl supxHandlesLookupCallback(
    void const* first,
    void const* second);

int __cdecl supxHandlesLookupCallback2(
    void const* first,
    void const* second);

/*
* supCreateHeap
*
* Purpose:
*
* Wrapper around RtlCreateHeap with statistics support.
*
*/
HANDLE supCreateHeap(
    _In_ ULONG HeapFlags,
    _In_ BOOL TerminateOnCorruption
)
{
    HANDLE heapHandle;

    heapHandle = RtlCreateHeap(HeapFlags, NULL, 0, 0, NULL, NULL);
    if (heapHandle == NULL)
        return NULL;

    if (TerminateOnCorruption && g_WinObj.IsWine == FALSE) {
        RtlSetHeapInformation(heapHandle, HeapEnableTerminationOnCorruption, NULL, 0);
    }

    OBEX_STATS_INC(TotalHeapsCreated);

    return heapHandle;
}

/*
* supDestroyHeap
*
* Purpose:
*
* Wrapper around RtlDestroyHeap with statistics support.
*
*/
BOOL supDestroyHeap(
    _In_ HANDLE HeapHandle
)
{
    BOOL bResult;

    bResult = (RtlDestroyHeap(HeapHandle) == NULL);
    if (bResult)
        OBEX_STATS_INC(TotalHeapsDestroyed);

    return bResult;
}

/*
* supHeapAllocEx
*
* Purpose:
*
* Wrapper for RtlAllocateHeap with statistics support.
*
*/
FORCEINLINE PVOID supHeapAllocEx(
    _In_ HANDLE Heap,
    _In_ SIZE_T Size
)
{
    PVOID Buffer;

#ifdef _DEBUG
    ULONG64 MaxHeapAllocatedBlockSize;
#endif

    Buffer = RtlAllocateHeap(Heap, HEAP_ZERO_MEMORY, Size);

    if (Buffer) {

        OBEX_STATS_INC(TotalHeapAlloc);
        OBEX_STATS_INC64(TotalHeapMemoryAllocated, Size);

#ifdef _DEBUG
        MaxHeapAllocatedBlockSize = g_WinObjStats.MaxHeapAllocatedBlockSize;

        while (1) {

            if (Size <= MaxHeapAllocatedBlockSize)
                break;

            MaxHeapAllocatedBlockSize = InterlockedCompareExchange64(
                (LONG64*)&g_WinObjStats.MaxHeapAllocatedBlockSize,
                (LONG64)Size,
                (LONG64)MaxHeapAllocatedBlockSize);

        }
#endif
    }

    return Buffer;
}

/*
* supHeapFreeEx
*
* Purpose:
*
* Wrapper for RtlFreeHeap with statistics support.
*
*/
FORCEINLINE BOOL supHeapFreeEx(
    _In_ HANDLE Heap,
    _In_ PVOID Memory
)
{
    BOOL Result;

    Result = RtlFreeHeap(Heap, 0, Memory);

    if (Result) {

        OBEX_STATS_INC(TotalHeapFree);

    }

    return Result;
}

/*
* supHeapAlloc
*
* Purpose:
*
* Wrapper for RtlAllocateHeap with WinObjEx heap.
*
*/
FORCEINLINE PVOID supHeapAlloc(
    _In_ SIZE_T Size)
{
    return supHeapAllocEx(g_obexHeap, Size);
}

/*
* supHeapFree
*
* Purpose:
*
* Wrapper for RtlFreeHeap with WinObjEx heap.
*
*/
FORCEINLINE BOOL supHeapFree(
    _In_ PVOID Memory)
{
    return supHeapFreeEx(g_obexHeap, Memory);
}

/*
* supGetDPIValue
*
* Purpose:
*
* Return DPI value for system or specific window (win10+).
*
*/
UINT supGetDPIValue(
    _In_opt_ HWND hWnd
)
{
    HDC hDc;

    UINT uDpi = DefaultSystemDpi;
    DPI_AWARENESS dpiAwareness;

    if (g_NtBuildNumber >= NT_WIN10_REDSTONE1) {

        dpiAwareness = g_ExtApiSet.GetAwarenessFromDpiAwarenessContext(
            g_ExtApiSet.GetThreadDpiAwarenessContext());

        switch (dpiAwareness) {

            // Scale the window to the system DPI
        case DPI_AWARENESS_SYSTEM_AWARE:
            uDpi = g_ExtApiSet.GetDpiForSystem();
            break;

            // Scale the window to the monitor DPI
        case DPI_AWARENESS_PER_MONITOR_AWARE:
            if (hWnd) uDpi = g_ExtApiSet.GetDpiForWindow(hWnd);
            break;
        }

    }
    else {
        hDc = GetDC(0);
        if (hDc) {
            uDpi = (UINT)GetDeviceCaps(hDc, LOGPIXELSX);
            ReleaseDC(0, hDc);
        }
    }

    return uDpi;
}

/*
* supTreeListEnableRedraw
*
* Purpose:
*
* Change treelist redraw state.
*
*/
VOID supTreeListEnableRedraw(
    _In_ HWND TreeList,
    _In_ BOOL fEnable
)
{
    if (fEnable) {
        TreeList_RedrawEnableAndUpdateNow(TreeList);
    }
    else {
        TreeList_RedrawDisable(TreeList);
    }
}

/*
* supTreeListAddItem
*
* Purpose:
*
* Insert new treelist item.
*
*/
HTREEITEM supTreeListAddItem(
    _In_ HWND TreeList,
    _In_opt_ HTREEITEM hParent,
    _In_ UINT mask,
    _In_ UINT state,
    _In_ UINT stateMask,
    _In_opt_ LPWSTR pszText,
    _In_opt_ PVOID subitems
)
{
    TVINSERTSTRUCT  tvitem;
    PTL_SUBITEMS    si = (PTL_SUBITEMS)subitems;

    RtlSecureZeroMemory(&tvitem, sizeof(tvitem));
    tvitem.hParent = hParent;
    tvitem.item.mask = mask;
    tvitem.item.state = state;
    tvitem.item.stateMask = stateMask;
    tvitem.item.pszText = pszText;
    tvitem.hInsertAfter = TVI_LAST;
    return TreeList_InsertTreeItem(TreeList, &tvitem, si);
}

/*
* supInitTreeListForDump
*
* Purpose:
*
* Intialize TreeList control for object dump sheet.
*
*/
BOOL supInitTreeListForDump(
    _In_ HWND hwndParent,
    _Out_ HWND* pTreeListHwnd
)
{
    HWND     TreeList, hWndGroupBox;
    HDITEM   hdritem;
    RECT     rc;

    UINT uDpi;
    INT dpiScaledX, dpiScaledY, iScaledWidth, iScaledHeight, iScaleSub;

    if (pTreeListHwnd == NULL) {
        return FALSE;
    }

    uDpi = supGetDPIValue(NULL);
    dpiScaledX = MulDiv(TreeListDumpObjWndPosX, uDpi, DefaultSystemDpi);
    dpiScaledY = MulDiv(TreeListDumpObjWndPosY, uDpi, DefaultSystemDpi);

    hWndGroupBox = GetDlgItem(hwndParent, ID_OBJECTDUMPGROUPBOX);
    GetWindowRect(hWndGroupBox, &rc);
    iScaleSub = MulDiv(TreeListDumpObjWndScaleSub, uDpi, DefaultSystemDpi);
    iScaledWidth = (rc.right - rc.left) - dpiScaledX - iScaleSub;
    iScaledHeight = (rc.bottom - rc.top) - dpiScaledY - iScaleSub;

    TreeList = CreateWindowEx(WS_EX_STATICEDGE, WC_TREELIST, NULL,
        WS_VISIBLE | WS_CHILD | WS_TABSTOP | TLSTYLE_COLAUTOEXPAND | TLSTYLE_LINKLINES,
        dpiScaledX, dpiScaledY,
        iScaledWidth, iScaledHeight, hwndParent, NULL, NULL, NULL);

    if (TreeList == NULL) {
        *pTreeListHwnd = NULL;
        return FALSE;
    }

    *pTreeListHwnd = TreeList;

    RtlSecureZeroMemory(&hdritem, sizeof(hdritem));
    hdritem.mask = HDI_FORMAT | HDI_TEXT | HDI_WIDTH;
    hdritem.fmt = HDF_LEFT | HDF_BITMAP_ON_RIGHT | HDF_STRING;
    hdritem.cxy = SCALE_DPI_VALUE(220, g_WinObj.CurrentDPI);
    hdritem.pszText = TEXT("Field");
    TreeList_InsertHeaderItem(TreeList, 0, &hdritem);
    hdritem.cxy = SCALE_DPI_VALUE(130, g_WinObj.CurrentDPI);
    hdritem.pszText = TEXT("Value");
    TreeList_InsertHeaderItem(TreeList, 1, &hdritem);
    hdritem.cxy = SCALE_DPI_VALUE(210, g_WinObj.CurrentDPI);
    hdritem.pszText = TEXT("Additional Information");
    TreeList_InsertHeaderItem(TreeList, 2, &hdritem);

    return TRUE;
}

/*
* supClipboardCopy
*
* Purpose:
*
* Copy text to the clipboard.
*
*/
VOID supClipboardCopy(
    _In_ LPCWSTR lpText,
    _In_ SIZE_T cbText
)
{
    LPWSTR  lptstrCopy;
    HGLOBAL hglbCopy;
    SIZE_T  dwSize;

    if (OpenClipboard(NULL)) {
        EmptyClipboard();
        dwSize = cbText + sizeof(UNICODE_NULL);
        hglbCopy = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, dwSize);
        if (hglbCopy != NULL) {
            lptstrCopy = (LPWSTR)GlobalLock(hglbCopy);
            if (lptstrCopy) {
                RtlCopyMemory(lptstrCopy, lpText, cbText);
            }
            GlobalUnlock(hglbCopy);
            if (!SetClipboardData(CF_UNICODETEXT, hglbCopy))
                GlobalFree(hglbCopy);
        }
        CloseClipboard();
    }
}

/*
* supQueryObjectFromHandleEx
*
* Purpose:
*
* Return object kernel address from handle in current process handle table.
* Handle table dump supplied as parameter.
*
*/
BOOL supQueryObjectFromHandleEx(
    _In_ PSYSTEM_HANDLE_INFORMATION_EX HandlesDump,
    _In_ HANDLE Object,
    _Out_opt_ ULONG_PTR* Address,
    _Out_opt_ USHORT* TypeIndex
)
{
    USHORT      objectTypeIndex = 0;
    BOOL        bFound = FALSE;
    DWORD       CurrentProcessId = GetCurrentProcessId();
    ULONG_PTR   i, objectAddress = 0;

    for (i = 0; i < HandlesDump->NumberOfHandles; i++) {
        if (HandlesDump->Handles[i].UniqueProcessId == (ULONG_PTR)CurrentProcessId) {
            if (HandlesDump->Handles[i].HandleValue == (ULONG_PTR)Object) {
                if (Address) {
                    objectAddress = (ULONG_PTR)HandlesDump->Handles[i].Object;
                }
                if (TypeIndex) {
                    objectTypeIndex = HandlesDump->Handles[i].ObjectTypeIndex;
                }
                bFound = TRUE;
                break;
            }
        }
    }

    if (Address)
        *Address = objectAddress;
    if (TypeIndex)
        *TypeIndex = objectTypeIndex;

    return bFound;
}

/*
* supQueryObjectFromHandle
*
* Purpose:
*
* Return object kernel address from handle in current process handle table.
*
*/
BOOL supQueryObjectFromHandle(
    _In_ HANDLE Object,
    _Out_ ULONG_PTR* Address,
    _Out_opt_ USHORT* TypeIndex
)
{
    BOOL bFound = FALSE;
    PSYSTEM_HANDLE_INFORMATION_EX pHandles;

    if (Address == NULL) {
        return bFound;
    }

    if (TypeIndex)
        *TypeIndex = 0;

    pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation, NULL);
    if (pHandles) {

        bFound = supQueryObjectFromHandleEx(pHandles,
            Object,
            Address,
            TypeIndex);

        supHeapFree(pHandles);
    }

    if (!bFound) *Address = 0;

    return bFound;
}

/*
* supDumpSyscallTableConverted
*
* Purpose:
*
* Read service table and convert it.
*
*/
BOOL supDumpSyscallTableConverted(
    _In_ ULONG_PTR ServiceTableAddress,
    _In_ ULONG ServiceLimit,
    _Out_ PUTable* Table
)
{
    ULONG   ServiceId, memIO;
    BOOL    bResult = FALSE;
    PULONG  ServiceTableDumped = NULL;
    PUTable ConvertedTable;

    LONG32 Offset;

    *Table = NULL;

    memIO = ServiceLimit * sizeof(ULONG);
    ServiceTableDumped = (PULONG)supHeapAlloc(memIO);
    if (ServiceTableDumped) {
        if (kdReadSystemMemory(
            ServiceTableAddress,
            (PVOID)ServiceTableDumped,
            memIO))
        {
            ConvertedTable = (PULONG_PTR)supHeapAlloc(ServiceLimit * sizeof(ULONG_PTR));

            if (ConvertedTable) {

                *Table = ConvertedTable;
                for (ServiceId = 0; ServiceId < ServiceLimit; ServiceId++) {
                    Offset = ((LONG32)ServiceTableDumped[ServiceId] >> 4);
                    ConvertedTable[ServiceId] = ServiceTableAddress + Offset;
                }
                bResult = TRUE;
            }
        }
        supHeapFree(ServiceTableDumped);
    }
    return bResult;
}

/*
* supShowHelp
*
* Purpose:
*
* Display help file if available.
*
*/
VOID supShowHelp(
    _In_ HWND ParentWindow
)
{
    DWORD   dwSize, dwType = 0;
    HKEY    hKey;
    LRESULT lRet;
    HMODULE hHtmlOcx;
    LPWSTR  s;
    WCHAR   szOcxPath[MAX_PATH + 1];
    WCHAR   szBuffer[MAX_PATH * 2];
    WCHAR   szHelpFile[MAX_PATH * 2];

    //
    //  Check if CHM file exist and remember filename.
    //
    RtlSecureZeroMemory(szHelpFile, sizeof(szHelpFile));
    if (!GetCurrentDirectory(MAX_PATH, szHelpFile)) {
        return;
    }
    _strcat(szHelpFile, L"\\winobjex64.chm");

    if (!PathFileExists(szHelpFile)) {
        s = (LPWSTR)supHeapAlloc((MAX_PATH + _strlen(szHelpFile)) * sizeof(WCHAR));
        if (s) {
            _strcpy(s, TEXT("Help file could not be found - "));
            _strcat(s, szHelpFile);
            MessageBox(ParentWindow, s, NULL, MB_ICONINFORMATION);
            supHeapFree(s);
        }
        return;
    }

    //
    // Query OCX path from registry.
    //
    RtlSecureZeroMemory(szOcxPath, sizeof(szOcxPath));
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    lRet = RegOpenKeyEx(HKEY_CLASSES_ROOT, HHCTRLOCXKEY, 0, KEY_QUERY_VALUE, &hKey);
    if (lRet == ERROR_SUCCESS) {
        dwSize = MAX_PATH * sizeof(WCHAR);
        lRet = RegQueryValueEx(hKey, L"", NULL, &dwType, (LPBYTE)szBuffer, &dwSize);
        RegCloseKey(hKey);

        if (lRet == ERROR_SUCCESS) {
            if (dwType == REG_EXPAND_SZ) {
                if (ExpandEnvironmentStrings(szBuffer, szOcxPath, MAX_PATH) == 0)
                    lRet = ERROR_SECRET_TOO_LONG;
            }
            else {
                _strncpy(szOcxPath, MAX_PATH, szBuffer, MAX_PATH);
            }
        }
    }
    if (lRet != ERROR_SUCCESS) {
        _strcpy(szOcxPath, HHCTRLOCX);
    }

    //
    // Load OCX and call help.
    //
    hHtmlOcx = GetModuleHandle(HHCTRLOCX);
    if (hHtmlOcx == NULL) {
        hHtmlOcx = LoadLibrary(szOcxPath);
        if (hHtmlOcx == NULL) {
            return;
        }
    }
    if (g_WinObj.HtmlHelpW == NULL) {
        g_WinObj.HtmlHelpW = (pfnHtmlHelpW)GetProcAddress(hHtmlOcx, MAKEINTRESOURCEA(0xF));
        if (g_WinObj.HtmlHelpW == NULL) {
            return;
        }
    }
    g_WinObj.HtmlHelpW(GetDesktopWindow(), szHelpFile, 0, 0);
}

/*
* supEnumIconCallback
*
* Purpose:
*
* Resource enumerator callback.
*
*/
BOOL supEnumIconCallback(
    _In_opt_ HMODULE hModule,
    _In_ LPCWSTR lpType,
    _In_ LPWSTR lpName,
    _In_ LONG_PTR lParam
)
{
    PENUMICONINFO pin;

    UNREFERENCED_PARAMETER(lpType);

    pin = (PENUMICONINFO)lParam;
    if (pin == NULL) {
        return FALSE;
    }

    pin->hIcon = (HICON)LoadImage(hModule, lpName, IMAGE_ICON, pin->cx, pin->cy, 0);
    return FALSE;
}

/*
* supGetMainIcon
*
* Purpose:
*
* Extract main icon if it exists in executable image.
*
*/
HICON supGetMainIcon(
    _In_ LPCWSTR lpFileName,
    _In_ INT cx,
    _In_ INT cy
)
{
    HMODULE      hModule;
    ENUMICONINFO pin;

    pin.cx = cx;
    pin.cy = cy;
    pin.hIcon = 0;

    hModule = LoadLibraryEx(lpFileName, 0, LOAD_LIBRARY_AS_DATAFILE);
    if (hModule != NULL) {
        EnumResourceNames(hModule, RT_GROUP_ICON, (ENUMRESNAMEPROC)&supEnumIconCallback,
            (LONG_PTR)&pin);
        FreeLibrary(hModule);
    }
    return pin.hIcon;
}

/*
* supFreeUnicodeString
*
* Purpose:
*
* Release memory allocated for string.
*
*/
_Success_(return)
BOOL supFreeUnicodeString(
    _In_ HANDLE HeapHandle,
    _Inout_ PUNICODE_STRING String
)
{
    if (String->Buffer) {
        return supHeapFreeEx(HeapHandle, String->Buffer);
    }
    return FALSE;
}

/*
* supFreeDuplicatedUnicodeString
*
* Purpose:
*
* Release memory allocated for duplicated string.
*
*/
_Success_(return)
BOOL supFreeDuplicatedUnicodeString(
    _In_ HANDLE HeapHandle,
    _Inout_ PUNICODE_STRING DuplicatedString,
    _In_ BOOL DoZeroMemory
)
{
    BOOL bResult = FALSE;
    if (DuplicatedString->Buffer) {
        bResult = supHeapFreeEx(HeapHandle, DuplicatedString->Buffer);
        if (DoZeroMemory) {
            DuplicatedString->Buffer = NULL;
            DuplicatedString->Length = DuplicatedString->MaximumLength = 0;
        }
    }
    return bResult;
}

/*
* supDuplicateUnicodeString
*
* Purpose:
*
* Duplicate existing UNICODE_STRING to another without RtlDuplicateUnicodeString.
* 
* Note: Use supFreeDuplicatedUnicodeString to release allocated memory.
*
*/
_Success_(return)
BOOL supDuplicateUnicodeString(
    _In_ HANDLE HeapHandle,
    _Out_ PUNICODE_STRING DestinationString,
    _In_ PUNICODE_STRING SourceString
)
{
    USHORT maxLength = SourceString->MaximumLength;
    PWCHAR strBuffer;

    if (maxLength == 0 || maxLength < SourceString->Length)
        return FALSE;

    strBuffer = (PWCHAR)supHeapAllocEx(HeapHandle, (SIZE_T)maxLength);
    if (strBuffer) {
        DestinationString->Buffer = strBuffer;
        DestinationString->MaximumLength = maxLength;
        RtlCopyUnicodeString(DestinationString, SourceString);
        return TRUE;
    }

    return FALSE;
}

/*
* supCreateObjectPathFromElements
*
* Purpose:
*
* Build object path with provided directory and name.
*
* Note: Use supFreeDuplicatedUnicodeString to release allocated memory.
*
*/
_Success_(return)
BOOL supCreateObjectPathFromElements(
    _In_ PUNICODE_STRING ObjectName,
    _In_ PUNICODE_STRING DirectoryName,
    _Out_ PUNICODE_STRING ObjectPath,
    _In_ BOOLEAN NullTerminate
)
{
    BOOL bResult = FALSE, bIsRootDirectory;
    PWSTR nameBuffer, string = NULL;
    ULONG memIO;
    USHORT bufferLength;

    //
    // Must be valid strings.
    //
    if (ObjectName->Length == 0 ||
        DirectoryName->Length == 0)
    {
        return FALSE;
    }

    bIsRootDirectory = supIsRootDirectory(DirectoryName);
    memIO = ObjectName->Length + DirectoryName->Length;

    if (!bIsRootDirectory)
        memIO += sizeof(OBJ_NAME_PATH_SEPARATOR);

    if (NullTerminate)
        memIO += sizeof(UNICODE_NULL);

    nameBuffer = (PWSTR)supHeapAlloc(memIO);
    string = nameBuffer;

    if (string) {

        RtlCopyMemory(string, DirectoryName->Buffer, DirectoryName->Length);
        string = (PWSTR)RtlOffsetToPointer(string, DirectoryName->Length);

        if (!supIsRootDirectory(ObjectName)) {

            if (!bIsRootDirectory)
                *string++ = OBJ_NAME_PATH_SEPARATOR;

            RtlCopyMemory(string, ObjectName->Buffer, ObjectName->Length);
            string = (PWSTR)RtlOffsetToPointer(string, ObjectName->Length);

        }

        if (NullTerminate)
            *string++ = UNICODE_NULL;

        bResult = TRUE;
    }

    bufferLength = (USHORT)((ULONG_PTR)string - (ULONG_PTR)nameBuffer);
    ObjectPath->Buffer = nameBuffer;
    if (NullTerminate)
        ObjectPath->Length = (USHORT)(bufferLength - sizeof(UNICODE_NULL));
    else
        ObjectPath->Length = (USHORT)bufferLength;

    ObjectPath->MaximumLength = (USHORT)memIO;

    return bResult;
}

/*
* supCreateObjectPathFromCurrentPath
*
* Purpose:
*
* Build string that include current directory and object name.
*
*/
_Success_(return)
BOOL supCreateObjectPathFromCurrentPath(
    _In_ PUNICODE_STRING ObjectName,
    _Out_ PUNICODE_STRING ObjectPath,
    _In_ BOOLEAN NullTerminate
)
{
    USHORT bufferLength;
    BOOL bResult = FALSE, bIsRootDirectory;
    PWSTR nameBuffer, string = NULL;
    ULONG memIO;
    UNICODE_STRING currentPath;

    if (ObjectName->Length == 0)
        return FALSE;

    //
    // If ObjectName is root, return root.
    //
    if (supIsRootDirectory(ObjectName)) {
        return supDuplicateUnicodeString(g_obexHeap, ObjectPath, ObjectName);
    }

    if (!supGetCurrentObjectPath(TRUE, &currentPath))
        return FALSE;

    bIsRootDirectory = supIsRootDirectory(&currentPath);

    memIO = ObjectName->Length + currentPath.Length;

    if (!bIsRootDirectory)
        memIO += sizeof(OBJ_NAME_PATH_SEPARATOR);

    if (NullTerminate)
        memIO += sizeof(UNICODE_NULL);

    nameBuffer = (PWSTR)supHeapAlloc(memIO);
    string = nameBuffer;

    if (string) {

        RtlCopyMemory(string, currentPath.Buffer, currentPath.Length);
        string = (PWSTR)RtlOffsetToPointer(string, currentPath.Length);

        if (!bIsRootDirectory)
            *string++ = OBJ_NAME_PATH_SEPARATOR;

        RtlCopyMemory(string, ObjectName->Buffer, ObjectName->Length);
        string = (PWSTR)RtlOffsetToPointer(string, ObjectName->Length);

        if (NullTerminate)
            *string++ = UNICODE_NULL;

        bResult = TRUE;
    }

    bufferLength = (USHORT)((ULONG_PTR)string - (ULONG_PTR)nameBuffer);
    ObjectPath->Buffer = nameBuffer;
    if (NullTerminate)
        ObjectPath->Length = (USHORT)(bufferLength - sizeof(UNICODE_NULL));
    else
        ObjectPath->Length = (USHORT)bufferLength;

    ObjectPath->MaximumLength = (USHORT)memIO;

    supFreeDuplicatedUnicodeString(g_obexHeap, &currentPath, FALSE);
    return bResult;
}

/*
* supSetWaitCursor
*
* Purpose:
*
* Sets cursor state.
*
*/
VOID supSetWaitCursor(
    _In_ BOOL fSet
)
{
    ShowCursor(fSet);
    SetCursor(LoadCursor(NULL, fSet ? IDC_WAIT : IDC_ARROW));
}

/*
* supSymCallbackReportEvent
*
* Purpose:
*
* Banner output callback for symbols loading.
*
*/
VOID CALLBACK supSymCallbackReportEvent(
    _In_ LPCWSTR EventText
)
{
    SendDlgItemMessage(BannerWindow, IDC_LOADING_MSG, EM_REPLACESEL, (WPARAM)0, (LPARAM)EventText);
    SendDlgItemMessage(BannerWindow, IDC_LOADING_MSG, EM_REPLACESEL, (WPARAM)0, (LPARAM)(LPWSTR)L"\r\n");
}

/*
* supxLoadBannerDialog
*
* Purpose:
*
* Wait window banner dialog procedure.
*
*/
INT_PTR CALLBACK supxLoadBannerDialog(
    _In_ HWND   hwndDlg,
    _In_ UINT   uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    SUP_BANNER_DATA* pvData;
    UNREFERENCED_PARAMETER(wParam);

    switch (uMsg) {

    case WM_INITDIALOG:

        if (lParam) {
            pvData = (SUP_BANNER_DATA*)lParam;
            SendDlgItemMessage(hwndDlg, IDC_LOADING_MSG, EM_SETLIMITTEXT, 0, 0);
            supCenterWindowPerScreen(hwndDlg);
            if (pvData->lpCaption) SetWindowText(hwndDlg, pvData->lpCaption);
            SendDlgItemMessage(hwndDlg, IDC_LOADING_MSG, EM_REPLACESEL, (WPARAM)0, (LPARAM)pvData->lpText);
        }
        return TRUE;

    case WM_CLOSE:
        DestroyWindow(hwndDlg);
        BannerWindow = NULL;
        break;

    }

    return FALSE;
}

/*
* supUpdateLoadBannerText
*
* Purpose:
*
* Set new text for banner window.
*
*/
VOID supUpdateLoadBannerText(
    _In_ LPCWSTR lpText,
    _In_ BOOL UseList
)
{
    if (BannerWindow) {
        if (UseList) {
            SendDlgItemMessage(BannerWindow, IDC_LOADING_MSG, EM_REPLACESEL, (WPARAM)0, (LPARAM)lpText);
            SendDlgItemMessage(BannerWindow, IDC_LOADING_MSG, EM_REPLACESEL, (WPARAM)0, (LPARAM)(LPWSTR)L"\r\n");
        }
        else {
            SetDlgItemText(BannerWindow, IDC_LOADING_MSG, lpText);
        }
    }

}

/*
* supDisplayLoadBanner
*
* Purpose:
*
* Display borderless banner window to inform user about operation that need some wait.
*
*/
VOID supDisplayLoadBanner(
    _In_ LPCWSTR lpMessage,
    _In_opt_ LPCWSTR lpCaption
)
{
    SUP_BANNER_DATA bannerData;

    bannerData.lpText = lpMessage;
    bannerData.lpCaption = lpCaption;

    BannerWindow = CreateDialogParam(
        g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_LOADLIST),
        0,
        supxLoadBannerDialog,
        (LPARAM)&bannerData);

    if (BannerWindow) {
        supSetWaitCursor(TRUE);
        SetCapture(BannerWindow);
    }
}

/*
* supCloseLoadBanner
*
* Purpose:
*
* End load banner display.
*
*/
VOID supCloseLoadBanner(
    VOID
)
{
    if (BannerWindow) {
        supSetWaitCursor(FALSE);
        ReleaseCapture();
        SendMessage(BannerWindow, WM_CLOSE, 0, 0);
    }
}

/*
* supCenterWindowSpecifyParent
*
* Purpose:
*
* Centers given window relative to it parent window.
*
*/
VOID supCenterWindowSpecifyParent(
    _In_ HWND hwnd,
    _In_opt_ HWND parent
)
{
    RECT rc, rcDlg, rcOwner;

    //center window
    if (parent) {
        GetWindowRect(parent, &rcOwner);
        GetWindowRect(hwnd, &rcDlg);
        CopyRect(&rc, &rcOwner);
        OffsetRect(&rcDlg, -rcDlg.left, -rcDlg.top);
        OffsetRect(&rc, -rc.left, -rc.top);
        OffsetRect(&rc, -rcDlg.right, -rcDlg.bottom);
        SetWindowPos(hwnd,
            HWND_TOP,
            rcOwner.left + (rc.right / 2),
            rcOwner.top + (rc.bottom / 2),
            0, 0,
            SWP_NOSIZE);
    }
}

/*
* supCenterWindow
*
* Purpose:
*
* Centers given window relative to it parent window.
*
*/
VOID supCenterWindow(
    _In_ HWND hwnd
)
{
    supCenterWindowSpecifyParent(hwnd, GetParent(hwnd));
}

/*
* supCenterWindowPerScreen
*
* Purpose:
*
* Centers given window relative to screen.
*
*/
VOID supCenterWindowPerScreen(
    _In_ HWND hwnd
)
{
    RECT rc;
    INT posX = GetSystemMetrics(SM_CXSCREEN);
    INT posY = GetSystemMetrics(SM_CYSCREEN);

    if (GetWindowRect(hwnd, &rc)) {

        posX = (posX - rc.right) / 2;
        posY = (posY - rc.bottom) / 2;

        SetWindowPos(hwnd,
            NULL,
            posX,
            posY,
            0,
            0,
            SWP_NOZORDER | SWP_NOSIZE);
    }
}

/*
* supGetTokenInfo
*
* Purpose:
*
* Returns buffer with token information by given TokenInformationClass.
*
* Returned buffer must be freed with supHeapFree after usage.
*
*/
PVOID supGetTokenInfo(
    _In_ HANDLE TokenHandle,
    _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
    _Out_opt_ PULONG ReturnLength
)
{
    PVOID Buffer = NULL;
    ULONG returnLength = 0;

    if (ReturnLength)
        *ReturnLength = 0;

    NtQueryInformationToken(TokenHandle,
        TokenInformationClass,
        NULL,
        0,
        &returnLength);

    Buffer = supHeapAlloc((SIZE_T)returnLength);
    if (Buffer) {

        if (NT_SUCCESS(NtQueryInformationToken(TokenHandle,
            TokenInformationClass,
            Buffer,
            returnLength,
            &returnLength)))
        {
            if (ReturnLength)
                *ReturnLength = returnLength;
            return Buffer;
        }
        else {
            supHeapFree(Buffer);
            return NULL;
        }
    }

    return Buffer;
}

/*
* supGetLoadedModulesList
*
* Purpose:
*
* Read list of loaded kernel modules.
*
* Returned buffer must be freed with supHeapFree after usage.
*
*/
PVOID supGetLoadedModulesList(
    _Out_opt_ PULONG ReturnLength
)
{
    return ntsupGetLoadedModulesListEx(FALSE,
        ReturnLength,
        (PNTSUPMEMALLOC)supHeapAlloc,
        (PNTSUPMEMFREE)supHeapFree);
}

/*
* supGetLoadedModulesList2
*
* Purpose:
*
* Read list of loaded kernel modules.
*
* Returned buffer must be freed with supHeapFree after usage.
*
*/
PVOID supGetLoadedModulesList2(
    _Out_opt_ PULONG ReturnLength
)
{
    return ntsupGetLoadedModulesListEx(TRUE,
        ReturnLength,
        (PNTSUPMEMALLOC)supHeapAlloc,
        (PNTSUPMEMFREE)supHeapFree);
}

/*
* supGetSystemInfo
*
* Purpose:
*
* Returns buffer with system information by given SystemInformationClass.
*
* Returned buffer must be freed with supHeapFree after usage.
*
*/
PVOID supGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_opt_ PULONG ReturnLength
)
{
    return ntsupGetSystemInfoEx(
        SystemInformationClass,
        ReturnLength,
        (PNTSUPMEMALLOC)supHeapAlloc,
        (PNTSUPMEMFREE)supHeapFree);
}

/*
* supxFreeObjectTypes
*
* Purpose:
*
* Free object types memory callback.
*
*/
BOOL CALLBACK supxFreeObjectTypes(
    _In_opt_ PVOID Context
)
{
    if (Context)
        supHeapFree(Context);

    return TRUE;
}

/*
* supGetObjectTypesInfo
*
* Purpose:
*
* Returns buffer with system types information.
*
* Returned buffer must be freed with supHeapFree after usage.
*
*/
PVOID supGetObjectTypesInfo(
    VOID
)
{
    PVOID       buffer = NULL;
    ULONG       bufferSize = 1024 * 16;
    NTSTATUS    ntStatus;
    ULONG       returnedLength = 0;

    buffer = supHeapAlloc((SIZE_T)bufferSize);
    if (buffer == NULL)
        return NULL;

    while ((ntStatus = NtQueryObject(
        NULL,
        ObjectTypesInformation,
        buffer,
        bufferSize,
        &returnedLength)) == STATUS_INFO_LENGTH_MISMATCH)
    {
        supHeapFree(buffer);
        bufferSize *= 2;

        if (bufferSize > (16 * 1024 * 1024))
            return NULL;

        buffer = supHeapAlloc((SIZE_T)bufferSize);
    }

    if (NT_SUCCESS(ntStatus)) {        
        return buffer;
    }

    if (buffer)
        supHeapFree(buffer);

    return NULL;
}

/*
* supGetItemText
*
* Purpose:
*
* Returns buffer with text from the given listview item.
*
* Returned buffer must be freed with supHeapFree after usage.
*
*/
LPWSTR supGetItemText(
    _In_ HWND ListView,
    _In_ INT nItem,
    _In_ INT nSubItem,
    _Out_opt_ PSIZE_T lpSize //length in bytes
)
{
    INT     len;
    LPARAM  sz = 0;
    LV_ITEM item;

    RtlSecureZeroMemory(&item, sizeof(item));

    item.iItem = nItem;
    item.iSubItem = nSubItem;
    len = 128;
    do {
        len *= 2;
        item.cchTextMax = len;
        if (item.pszText) {
            supHeapFree(item.pszText);
            item.pszText = NULL;
        }
        item.pszText = (LPWSTR)supHeapAlloc(len * sizeof(WCHAR));
        if (item.pszText == NULL) {
            sz = 0;
            break;
        }
        sz = SendMessage(ListView, LVM_GETITEMTEXT, (WPARAM)item.iItem, (LPARAM)&item);
    } while (sz == (LPARAM)len - 1);

    //empty string
    if (sz == 0) {
        if (item.pszText) {
            supHeapFree(item.pszText);
            item.pszText = NULL;
        }
    }

    if (lpSize) {
        *lpSize = sz * sizeof(WCHAR);
    }
    return item.pszText;
}

/*
* supGetItemText2
*
* Purpose:
*
* Returns text from the given listview item.
*
*/
LPWSTR supGetItemText2(
    _In_ HWND ListView,
    _In_ INT nItem,
    _In_ INT nSubItem,
    _In_ WCHAR* pszText,
    _In_ UINT cchText
)
{
    LV_ITEM item;

    RtlSecureZeroMemory(&item, sizeof(item));

    item.iItem = nItem;
    item.iSubItem = nSubItem;
    item.pszText = pszText;
    item.cchTextMax = (SIZE_T)cchText;
    SendMessage(ListView, LVM_GETITEMTEXT, (WPARAM)item.iItem, (LPARAM)&item);

    return item.pszText;
}

/*
* supLoadImageList
*
* Purpose:
*
* Create and load image list from icon resource type.
*
*/
HIMAGELIST supLoadImageList(
    _In_ HINSTANCE hInst,
    _In_ UINT FirstId,
    _In_ UINT LastId
)
{
    UINT       i;
    HIMAGELIST list;
    HICON      hIcon;

    list = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 2, 8);
    if (list) {
        for (i = FirstId; i <= LastId; i++) {
            hIcon = (HICON)LoadImage(hInst, MAKEINTRESOURCE(i), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
            if (hIcon) {
                ImageList_ReplaceIcon(list, -1, hIcon);
                DestroyIcon(hIcon);
            }
        }
    }
    return list;
}

/*
* supGetObjectNameIndexByTypeIndex
*
* Purpose:
*
* Returns object index of known type.
*
* Known type names listed in objects.c, objects.h
*
*/
WOBJ_OBJECT_TYPE supGetObjectNameIndexByTypeIndex(
    _In_ PVOID Object,
    _In_ UCHAR TypeIndex
)
{
    UINT   typeIndex;
    ULONG  i;
    POBTYPE_LIST objectTypesList;

    if (Object == NULL)
        return ObjectTypeUnknown;

    objectTypesList = g_kdctx.Data->ObjectTypesList;
    if (objectTypesList == NULL)
        return ObjectTypeUnknown;

    typeIndex = ObDecodeTypeIndex(Object, TypeIndex);
    for (i = 0; i < objectTypesList->NumberOfTypes; i++) {
        if (objectTypesList->Types[i].TypeIndex == typeIndex) {
            return ObManagerGetIndexByTypeName(
                objectTypesList->Types[i].TypeName->Buffer);

        }
    }

    return ObjectTypeUnknown;
}

/*
* supRunAsAdmin
*
* Purpose:
*
* Restarts application requesting full admin rights.
*
*/
VOID supRunAsAdmin(
    VOID
)
{
    SHELLEXECUTEINFO shinfo;
    WCHAR szPath[MAX_PATH + 1];

    RtlSecureZeroMemory(&szPath, sizeof(szPath));
    if (GetModuleFileName(NULL, szPath, MAX_PATH)) {
        RtlSecureZeroMemory(&shinfo, sizeof(shinfo));
        shinfo.cbSize = sizeof(shinfo);
        shinfo.lpVerb = TEXT("runas");
        shinfo.lpFile = szPath;
        shinfo.lpDirectory = g_WinObj.szProgramDirectory;
        shinfo.nShow = SW_SHOW;
        if (ShellExecuteEx(&shinfo)) {
            PostQuitMessage(0);
        }
    }
}

/*
* supShowProperties
*
* Purpose:
*
* Show file properties Windows dialog.
*
*/
VOID supShowProperties(
    _In_ HWND hwndDlg,
    _In_ LPWSTR lpFileName
)
{
    SHELLEXECUTEINFO shinfo;

    if (lpFileName == NULL) {
        return;
    }

    RtlSecureZeroMemory(&shinfo, sizeof(shinfo));
    shinfo.cbSize = sizeof(shinfo);
    shinfo.fMask = SEE_MASK_INVOKEIDLIST | SEE_MASK_FLAG_NO_UI;
    shinfo.hwnd = hwndDlg;
    shinfo.lpVerb = TEXT("properties");
    shinfo.lpFile = lpFileName;
    shinfo.nShow = SW_SHOWNORMAL;
    ShellExecuteEx(&shinfo);
}

/*
* supJumpToFile
*
* Purpose:
*
* Open explorer window for given path.
*
*/
VOID supJumpToFile(
    _In_ LPCWSTR lpFilePath
)
{
    LPITEMIDLIST pidList;
    HRESULT hr = E_FAIL;
    SIZE_T sz;
    LPWSTR lpCommand;
    WCHAR szExplorer[MAX_PATH * 2];

    pidList = ILCreateFromPath(lpFilePath);
    if (pidList) {
        hr = SHOpenFolderAndSelectItems(pidList, 0, NULL, 0);
        ILFree(pidList);
    }

    if (FAILED(hr)) {

        sz = MAX_PATH + _strlen(g_WinObj.szWindowsDirectory) + _strlen(lpFilePath);

        lpCommand = (LPWSTR)supHeapAlloc(sz * sizeof(WCHAR));
        if (lpCommand) {
            _strcpy(lpCommand, TEXT(" /select, \""));
            _strcat(lpCommand, lpFilePath);
            _strcat(lpCommand, TEXT("\""));

            _strcpy(szExplorer, g_WinObj.szWindowsDirectory);
            _strcat(szExplorer, TEXT("\\explorer.exe"));

            supShellExecInExplorerProcess(szExplorer, lpCommand);
            supHeapFree(lpCommand);
        }

    }
}

/*
* supObjectListGetObjectType
*
* Purpose:
*
* Return object type of given listview entry.
*
*/
WOBJ_OBJECT_TYPE supObjectListGetObjectType(
    _In_ HWND hwndList,
    _In_ INT iItem
)
{
    OBEX_ITEM* objectReference;

    LVITEM lvItem;

    lvItem.mask = LVIF_PARAM;
    lvItem.iItem = iItem;
    lvItem.iSubItem = 0;
    lvItem.lParam = 0;
    ListView_GetItem(hwndList, &lvItem);

    objectReference = (OBEX_ITEM*)lvItem.lParam;
    if (objectReference)
        return objectReference->TypeIndex;

    return ObjectTypeUnknown;
}

/*
* supSetGotoLinkTargetToolButtonState
*
* Purpose:
*
* Enable/Disable Go To Link Target tool button.
*
*/
VOID supSetGotoLinkTargetToolButtonState(
    _In_ HWND hwnd,
    _In_opt_ HWND hwndlv,
    _In_ INT iItem,
    _In_ BOOL bForce,
    _In_ BOOL bForceEnable
)
{
    UINT uEnable = MF_BYCOMMAND | MF_GRAYED;

    if (bForce) {
        if (bForceEnable)
            uEnable = MF_BYCOMMAND;
    }
    else {
        if (hwndlv) {
            if (ObjectTypeSymbolicLink == supObjectListGetObjectType(hwndlv, iItem)) {
                uEnable = MF_BYCOMMAND;
            }
        }
    }
    EnableMenuItem(GetSubMenu(GetMenu(hwnd), IDMM_OBJECT), ID_OBJECT_GOTOLINKTARGET, uEnable);
}

/*
* supTreeListAddCopyValueItem
*
* Purpose:
*
* Add copy to clipboard menu item depending on hit treelist header item.
*
*/
BOOL supTreeListAddCopyValueItem(
    _In_ HMENU hMenu,
    _In_ HWND hwndTreeList,
    _In_ UINT uId,
    _In_ UINT uPos,
    _In_ LPARAM lParam,
    _In_ INT *pSubItemHit
)
{
    HDHITTESTINFO hti;
    HD_ITEM hdItem;
    WCHAR szHeaderText[MAX_PATH + 1];
    WCHAR szItem[MAX_PATH * 2];

    *pSubItemHit = -1;

    hti.iItem = -1;
    hti.pt.x = LOWORD(lParam);
    hti.pt.y = HIWORD(lParam);
    ScreenToClient(hwndTreeList, &hti.pt);

    hti.pt.y = 1;
    if (TreeList_HeaderHittest(hwndTreeList, &hti) < 0)
        return FALSE;

    RtlSecureZeroMemory(&hdItem, sizeof(hdItem));

    szHeaderText[0] = 0;
    hdItem.mask = HDI_TEXT;

    hdItem.cchTextMax = sizeof(szHeaderText) - 1;

    hdItem.pszText = szHeaderText;
    if (TreeList_GetHeaderItem(hwndTreeList, hti.iItem, &hdItem)) {

        *pSubItemHit = hti.iItem;

        _strcpy(szItem, TEXT("Copy \""));
        _strcat(szItem, szHeaderText);
        _strcat(szItem, TEXT("\""));
        if (InsertMenu(hMenu, uPos, MF_BYCOMMAND, uId, szItem)) {
            return TRUE;
        }
    }

    return FALSE;
}

/*
* supListViewAddCopyValueItem
*
* Purpose:
*
* Add copy to clipboard menu item depending on hit column.
*
*/
BOOL supListViewAddCopyValueItem(
    _In_ HMENU hMenu,
    _In_ HWND hwndLv,
    _In_ UINT uId,
    _In_ UINT uPos,
    _In_ POINT* lpPoint,
    _Out_ INT* pItemHit,
    _Out_ INT* pColumnHit
)
{
    LVHITTESTINFO lvht;
    LVCOLUMN lvc;
    WCHAR szItem[MAX_PATH * 2];
    WCHAR szColumn[MAX_PATH + 1];

    *pColumnHit = -1;
    *pItemHit = -1;

    RtlSecureZeroMemory(&lvht, sizeof(lvht));
    lvht.pt.x = lpPoint->x;
    lvht.pt.y = lpPoint->y;
    ScreenToClient(hwndLv, &lvht.pt);
    if (ListView_SubItemHitTest(hwndLv, &lvht) == -1)
        return FALSE;

    RtlSecureZeroMemory(&lvc, sizeof(lvc));
    RtlSecureZeroMemory(&szColumn, sizeof(szColumn));

    lvc.mask = LVCF_TEXT;
    lvc.pszText = szColumn;
    lvc.cchTextMax = MAX_PATH;
    if (ListView_GetColumn(hwndLv, lvht.iSubItem, &lvc)) {
        _strcpy(szItem, TEXT("Copy \""));
        _strcat(szItem, szColumn);
        _strcat(szItem, TEXT("\""));
        if (InsertMenu(hMenu, uPos, MF_BYCOMMAND, uId, szItem)) {
            *pColumnHit = lvht.iSubItem;
            *pItemHit = lvht.iItem;
            return TRUE;
        }
    }

    return FALSE;
}

/*
* supTreeListCopyItemValueToClipboard
*
* Purpose:
*
* Copy selected treelist item text to the clipboard.
*
*/
BOOL supTreeListCopyItemValueToClipboard(
    _In_ HWND hwndTreeList,
    _In_ INT tlSubItemHit
)
{
    INT         nIndex;
    LPWSTR      lpCopyData = NULL;
    SIZE_T      cbCopyData = 0;
    TVITEMEX    itemex;
    WCHAR       szText[MAX_PATH + 1];

    TL_SUBITEMS_FIXED* pSubItems = NULL;

    szText[0] = 0;
    RtlSecureZeroMemory(&itemex, sizeof(itemex));
    itemex.mask = TVIF_TEXT;
    itemex.hItem = TreeList_GetSelection(hwndTreeList);
    itemex.pszText = szText;
    itemex.cchTextMax = MAX_PATH;

    if (TreeList_GetTreeItem(hwndTreeList, &itemex, &pSubItems)) {

        if ((tlSubItemHit > 0) && (pSubItems != NULL)) {

            nIndex = (tlSubItemHit - 1);
            if (nIndex < (INT)pSubItems->Count) {

                lpCopyData = pSubItems->Text[nIndex];
                cbCopyData = _strlen(lpCopyData) * sizeof(WCHAR);

            }

        }
        else {
            if (tlSubItemHit == 0) {
                lpCopyData = szText;
                cbCopyData = sizeof(szText);
            }
        }

        if (lpCopyData && cbCopyData) {
            supClipboardCopy(lpCopyData, cbCopyData);
            return TRUE;
        }
        else {
            if (OpenClipboard(NULL)) {
                EmptyClipboard();
                CloseClipboard();
            }
        }
    }

    return FALSE;
}

/*
* supListViewCopyItemValueToClipboard
*
* Purpose:
*
* Copy selected item text to the clipboard.
*
*/
BOOL supListViewCopyItemValueToClipboard(
    _In_ HWND hwndListView,
    _In_ INT iItem,
    _In_ INT iSubItem
)
{
    SIZE_T cbText;
    LPWSTR lpText;

    if ((iSubItem < 0) || (iItem < 0))
        return FALSE;

    lpText = supGetItemText(hwndListView,
        iItem,
        iSubItem,
        NULL);

    if (lpText) {
        cbText = _strlen(lpText) * sizeof(WCHAR);
        supClipboardCopy(lpText, cbText);
        supHeapFree(lpText);
        return TRUE;
    }
    else {
        if (OpenClipboard(NULL)) {
            EmptyClipboard();
            CloseClipboard();
        }
    }

    return FALSE;
}

/*
* supSetMenuIcon
*
* Purpose:
*
* Associates icon data with given menu item.
*
*/
VOID supSetMenuIcon(
    _In_ HMENU hMenu,
    _In_ UINT iItem,
    _In_ HICON hIcon
)
{
    MENUITEMINFO mii;
    RtlSecureZeroMemory(&mii, sizeof(mii));
    mii.cbSize = sizeof(mii);
    mii.fMask = MIIM_BITMAP | MIIM_DATA;
    mii.hbmpItem = HBMMENU_CALLBACK;
    mii.dwItemData = (ULONG_PTR)hIcon;
    SetMenuItemInfo(hMenu, iItem, FALSE, &mii);
}

/*
* supCreateToolbarButtons
*
* Purpose:
*
* Main window toolbar initialization.
*
*/
VOID supCreateToolbarButtons(
    _In_ HWND hWndToolbar,
    _In_ HIMAGELIST hImageList
)
{
    TBBUTTON tbButtons[] = {
        { 0, ID_OBJECT_PROPERTIES, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, -1 },
        { 10, 0, 0, BTNS_SEP, {0}, 0, -1 },
        { 1, ID_VIEW_REFRESH, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, -1 },
        { 7, ID_VIEW_DISPLAYGRID, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, -1 },
        { 10, 0, 0, BTNS_SEP, {0}, 0, -1 },
        { 2, ID_FIND_FINDOBJECT, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, -1 }
    };

    SendMessage(hWndToolbar, TB_SETIMAGELIST, 0, (LPARAM)hImageList);
    SendMessage(hWndToolbar, TB_LOADIMAGES, (WPARAM)IDB_STD_SMALL_COLOR, (LPARAM)HINST_COMMCTRL);
    SendMessage(hWndToolbar, TB_BUTTONSTRUCTSIZE, (WPARAM)sizeof(TBBUTTON), 0);
    SendMessage(hWndToolbar, TB_ADDBUTTONS, (WPARAM)RTL_NUMBER_OF(tbButtons), (LPARAM)&tbButtons);
    SendMessage(hWndToolbar, TB_AUTOSIZE, 0, 0);
}

/*
* supSetProcessMitigationImagesPolicy
*
* Purpose:
*
* Enable images policy mitigation.
*
* N.B. Must be called after plugin manager initialization.
*
*/
VOID supSetProcessMitigationImagesPolicy()
{
    PROCESS_MITIGATION_POLICY_INFORMATION policyInfo;

    if (g_kdctx.MitigationFlags.Signature) {

        policyInfo.Policy = (PROCESS_MITIGATION_POLICY)ProcessSignaturePolicy;
        policyInfo.SignaturePolicy.Flags = 0;
        policyInfo.SignaturePolicy.MicrosoftSignedOnly = TRUE;
        policyInfo.SignaturePolicy.MitigationOptIn = TRUE;

        NtSetInformationProcess(NtCurrentProcess(),
            ProcessMitigationPolicy,
            &policyInfo,
            sizeof(PROCESS_MITIGATION_POLICY_INFORMATION));

    }

    if (g_kdctx.MitigationFlags.ImageLoad) {

        policyInfo.Policy = (PROCESS_MITIGATION_POLICY)ProcessImageLoadPolicy;
        policyInfo.ImageLoadPolicy.Flags = 0;
        policyInfo.ImageLoadPolicy.PreferSystem32Images = TRUE;
        policyInfo.ImageLoadPolicy.NoLowMandatoryLabelImages = TRUE;

        NtSetInformationProcess(NtCurrentProcess(),
            ProcessMitigationPolicy,
            &policyInfo,
            sizeof(PROCESS_MITIGATION_POLICY_INFORMATION));

    }
}

/*
* supxSetProcessMitigationPolicies
*
* Purpose:
*
* Enable mitigations.
*
*/
VOID supxSetProcessMitigationPolicies()
{
    PROCESS_MITIGATION_POLICY_INFORMATION policyInfo;

    if (g_kdctx.MitigationFlags.ExtensionPointDisable) {

        policyInfo.Policy = (PROCESS_MITIGATION_POLICY)ProcessExtensionPointDisablePolicy;
        policyInfo.ExtensionPointDisablePolicy.Flags = 0;
        policyInfo.ExtensionPointDisablePolicy.DisableExtensionPoints = TRUE;

        NtSetInformationProcess(NtCurrentProcess(),
            ProcessMitigationPolicy,
            &policyInfo,
            sizeof(PROCESS_MITIGATION_POLICY_INFORMATION));

    }

    if (g_kdctx.MitigationFlags.ASLRPolicy) {
        policyInfo.Policy = (PROCESS_MITIGATION_POLICY)ProcessASLRPolicy;
        policyInfo.ASLRPolicy.Flags = 0;
        policyInfo.ASLRPolicy.EnableHighEntropy = TRUE;
        policyInfo.ASLRPolicy.EnableBottomUpRandomization = TRUE;
        policyInfo.ASLRPolicy.EnableForceRelocateImages = TRUE;

        NtSetInformationProcess(NtCurrentProcess(),
            ProcessMitigationPolicy,
            &policyInfo,
            sizeof(PROCESS_MITIGATION_POLICY_INFORMATION));
    }

    if (g_kdctx.MitigationFlags.DynamicCode) {

        //
        // Disabled due to multiple incompatibilities, including their own HtmlHelp functions
        // Fixes WOX2007-005.
        //
         if (g_NtBuildNumber > NT_WIN8_BLUE) {

             policyInfo.Policy = (PROCESS_MITIGATION_POLICY)ProcessDynamicCodePolicy;
             policyInfo.DynamicCodePolicy.Flags = 0;
             policyInfo.DynamicCodePolicy.ProhibitDynamicCode = TRUE;

             NtSetInformationProcess(NtCurrentProcess(),
                 ProcessMitigationPolicy,
                 &policyInfo,
                 sizeof(PROCESS_MITIGATION_POLICY_INFORMATION));

         }
    }
}

/*
* supxFreeCurrentObjectList
*
* Purpose:
*
* Destroy object path heap.
*
* Must be called once during program shutdown once
*
*/
BOOL supxFreeCurrentObjectList(
    _In_ PVOID Unused
)
{
    UNREFERENCED_PARAMETER(Unused);

    if (ObjectPathHeap)
        supDestroyHeap(ObjectPathHeap);

    return TRUE;
}

/*
* supInit
*
* Purpose:
*
* Initializes support subset related resources including kldbg subset.
*
* Must be called once during program startup
*
*/
VOID supInit(
    _In_ BOOLEAN IsFullAdmin
)
{
    WCHAR szError[200];
    NTSTATUS status;

    RtlInitializeCriticalSection(&supShutdownListLock);
    InitializeListHead(&supShutdownListHead);

    supxSetProcessMitigationPolicies();

#pragma warning(push)
#pragma warning(disable: 6031)
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
#pragma warning(pop)

    kdInit(IsFullAdmin);

    RtlInitializeCriticalSection(&g_sapiDB.Lock);
    RtlInitializeCriticalSection(&g_scmDB.Lock);

    if (IsFullAdmin) supCreateSCMSnapshot(SERVICE_DRIVER, NULL);
    sapiCreateSetupDBSnapshot();

    status = ExApiSetInit();
    if (!NT_SUCCESS(status)) {
        _strcpy(szError, TEXT("ExApiSetInit() failed, 0x"));
        ultohex(status, _strend(szError));
        logAdd(EntryTypeError, szError);
    }

    //
    // Remember current DPI value.
    // 
    g_WinObj.CurrentDPI = supGetDPIValue(NULL);
    supAddShutdownCallback(supxFreeCurrentObjectList, NULL);
}

/*
* supAddShutdownCallback
*
* Purpose:
*
* Allocate shutdown callback entry and insert it to the list.
*
*/
VOID supAddShutdownCallback(
    _In_ PSUPSHUTDOWNCALLBACK Callback,
    _In_opt_ PVOID Context
)
{
    SUP_SHUTDOWN_CALLBACK* entry;

    entry = (SUP_SHUTDOWN_CALLBACK*)supHeapAlloc(sizeof(SUP_SHUTDOWN_CALLBACK));
    if (entry == NULL)
        return;

    entry->Callback = Callback;
    entry->Context = Context;

    EnterCriticalSection(&supShutdownListLock);
    InsertHeadList(&supShutdownListHead, &entry->ListEntry);
    LeaveCriticalSection(&supShutdownListLock);
}

/*
* supxCallShutdownCallbacks
*
* Purpose:
*
* Call each shutdown callback entry and free list.
*
*/
VOID supxCallShutdownCallbacks(
    VOID
)
{
    PLIST_ENTRY entry, listHead, nextEntry;
    SUP_SHUTDOWN_CALLBACK* callback;

    EnterCriticalSection(&supShutdownListLock);

    listHead = &supShutdownListHead;

    for (entry = listHead->Flink, nextEntry = entry->Flink;
        entry != listHead;
        entry = nextEntry, nextEntry = entry->Flink)
    {
        callback = CONTAINING_RECORD(entry, SUP_SHUTDOWN_CALLBACK, ListEntry);
        callback->Callback(callback->Context);
        supHeapFree(callback);
    }

    LeaveCriticalSection(&supShutdownListLock);
}

/*
* supShutdown
*
* Purpose:
*
* Free support subset related resources.
*
* Must be called once at the end of program execution.
*
*/
VOID supShutdown(
    VOID
)
{
    kdShutdown();

    supFreeSCMSnapshot(NULL);
    sapiFreeSnapshot();

    RtlDeleteCriticalSection(&g_sapiDB.Lock);
    RtlDeleteCriticalSection(&g_scmDB.Lock);

    supxCallShutdownCallbacks();
    RtlDeleteCriticalSection(&supShutdownListLock);
}

/*
* supxEnumServicesStatus
*
* Purpose:
*
* Enumerate services status to the buffer.
*
*/
BOOL supxEnumServicesStatus(
    _In_ SC_HANDLE schSCManager,
    _In_ ULONG ServiceType,
    _Out_ PBYTE* Services,
    _Out_ DWORD* ServicesReturned
)
{
    LPBYTE servicesBuffer = NULL;
    DWORD dwSize = 64 * 1024, dwSizeNeeded = 0, dwNumServices = 0, dwResume = 0;
    DWORD dwError = ERROR_SUCCESS;
    DWORD cMaxLoops = 4, cLoop = 0;

    do {

        servicesBuffer = (LPBYTE)supHeapAlloc(dwSize);
        if (servicesBuffer == NULL)
            break;

        dwError = ERROR_SUCCESS;
        dwResume = 0;

        if (!EnumServicesStatusEx(
            schSCManager,
            SC_ENUM_PROCESS_INFO,
            ServiceType,
            SERVICE_STATE_ALL,
            servicesBuffer,
            dwSize,
            &dwSizeNeeded,
            &dwNumServices,
            &dwResume,
            NULL))
        {
            dwError = GetLastError();
            supHeapFree(servicesBuffer);
            dwSize += dwSizeNeeded;
        }

    } while ((dwError == ERROR_MORE_DATA) && (++cLoop < cMaxLoops));

    if ((dwError == ERROR_SUCCESS) && dwNumServices) {
        *ServicesReturned = dwNumServices;
        *Services = servicesBuffer;
    }
    else {
        if (servicesBuffer)
            supHeapFree(servicesBuffer);

        *ServicesReturned = 0;
        *Services = NULL;
    }

    return (dwNumServices > 0);
}

/*
* supCreateSCMSnapshot
*
* Purpose:
*
* Collects SCM information for drivers description.
*
* Use supFreeSCMSnapshot to free returned buffer.
*
*/
BOOL supCreateSCMSnapshot(
    _In_ ULONG ServiceType,
    _Out_opt_ SCMDB* Snapshot
)
{
    SC_HANDLE schSCManager;
    DWORD     dwNumServices = 0;
    PVOID     Services = NULL;

    if (Snapshot) {
        Snapshot->Entries = NULL;
        Snapshot->NumberOfEntries = 0;
    }

    schSCManager = OpenSCManager(NULL, NULL,
        SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);

    if (schSCManager) {

        if (supxEnumServicesStatus(schSCManager,
            ServiceType,
            (PBYTE*)&Services,
            &dwNumServices))
        {
            if (Snapshot) {
                Snapshot->Entries = Services;
                Snapshot->NumberOfEntries = dwNumServices;
            }
            else {
                EnterCriticalSection(&g_scmDB.Lock);
                g_scmDB.Entries = Services;
                g_scmDB.NumberOfEntries = dwNumServices;
                LeaveCriticalSection(&g_scmDB.Lock);
            }
        }

        CloseServiceHandle(schSCManager);
    }

    return (dwNumServices > 0);
}

/*
* supFreeSCMSnapshot
*
* Purpose:
*
* Destroys SCM snapshot buffer.
*
*/
VOID supFreeSCMSnapshot(
    _In_opt_ SCMDB* Snapshot)
{
    if (Snapshot) {
        if ((Snapshot->Entries) && (Snapshot->NumberOfEntries))
            supHeapFree(Snapshot->Entries);
        Snapshot->NumberOfEntries = 0;
        Snapshot->Entries = NULL;
    }
    else {
        EnterCriticalSection(&g_scmDB.Lock);
        supHeapFree(g_scmDB.Entries);
        g_scmDB.Entries = NULL;
        g_scmDB.NumberOfEntries = 0;
        LeaveCriticalSection(&g_scmDB.Lock);
    }
}

/*
* sapiQueryDeviceProperty
*
* Purpose:
*
* Query Device Propery from snapshot data.
*
*/
BOOL sapiQueryDeviceProperty(
    _In_ HANDLE SnapshotHeap,
    _In_ HDEVINFO hDevInfo,
    _In_ SP_DEVINFO_DATA* pDevInfoData,
    _In_ ULONG Property,
    _Out_ LPWSTR* PropertyBuffer,
    _Out_opt_ ULONG* PropertyBufferSize
)
{
    BOOL   result;
    DWORD  dataType = 0, dataSize, returnLength = 0;
    LPWSTR lpProperty;

    *PropertyBuffer = NULL;

    if (PropertyBufferSize)
        *PropertyBufferSize = 0;

    dataSize = (MAX_PATH * sizeof(WCHAR)) + sizeof(UNICODE_NULL);
    lpProperty = (LPWSTR)supHeapAllocEx(SnapshotHeap, dataSize);
    if (lpProperty == NULL)
        return FALSE;

    result = SetupDiGetDeviceRegistryProperty(hDevInfo,
        pDevInfoData,
        Property,
        &dataType,
        (PBYTE)lpProperty,
        dataSize,
        &returnLength);

    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {

        supHeapFreeEx(SnapshotHeap, lpProperty);
        dataSize = returnLength;
        lpProperty = (LPWSTR)supHeapAllocEx(SnapshotHeap, dataSize);
        if (lpProperty) {

            result = SetupDiGetDeviceRegistryProperty(hDevInfo,
                pDevInfoData,
                Property,
                &dataType,
                (PBYTE)lpProperty,
                dataSize,
                &returnLength);

        }

    }

    if (!result) {
        if (lpProperty) {
            supHeapFreeEx(SnapshotHeap, lpProperty);
            lpProperty = NULL;
        }
        dataSize = 0;
    }

    *PropertyBuffer = lpProperty;
    if (PropertyBufferSize)
        *PropertyBufferSize = dataSize;
    return result;
}

/*
* sapiCreateSetupDBSnapshot
*
* Purpose:
*
* Collects Setup API information to the linked list.
*
*/
BOOL sapiCreateSetupDBSnapshot(
    VOID
)
{
    BOOL            bResult = FALSE, bFailed = FALSE;
    DWORD           i, ReturnedDataSize = 0;
    SP_DEVINFO_DATA DeviceInfoData;
    PSAPIDBENTRY    Entry;
    HANDLE          Heap;
    HDEVINFO        hDevInfo;

    Heap = supCreateHeap(HEAP_GROWABLE, TRUE);
    if (Heap == NULL) {
        return FALSE;
    }

    g_sapiDB.HeapHandle = Heap;

    hDevInfo = SetupDiGetClassDevs(NULL, NULL, NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);
    if (hDevInfo != INVALID_HANDLE_VALUE) {

        InitializeListHead(&g_sapiDB.ListHead);

        RtlSecureZeroMemory(&DeviceInfoData, sizeof(DeviceInfoData));
        DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

        for (i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &DeviceInfoData); i++) {

            Entry = (PSAPIDBENTRY)supHeapAllocEx(Heap, sizeof(SAPIDBENTRY));
            if (Entry == NULL) {
                bFailed = TRUE;
                break;
            }

            //
            // Query Device Name.
            //
            sapiQueryDeviceProperty(Heap,
                hDevInfo,
                &DeviceInfoData,
                SPDRP_PHYSICAL_DEVICE_OBJECT_NAME,
                &Entry->lpDeviceName,
                &ReturnedDataSize);

            //
            // Query Device Description.
            //
            sapiQueryDeviceProperty(Heap,
                hDevInfo,
                &DeviceInfoData,
                SPDRP_DEVICEDESC,
                &Entry->lpDeviceDesc,
                &ReturnedDataSize);

            InsertHeadList(&g_sapiDB.ListHead, &Entry->ListEntry);

        }

        SetupDiDestroyDeviceInfoList(hDevInfo);

        if (bFailed == FALSE)
            bResult = TRUE;
    }

    if (bFailed) {
        supDestroyHeap(Heap);
        RtlSecureZeroMemory(&g_sapiDB, sizeof(g_sapiDB));
    }
    return bResult;
}

/*
* sapiFreeSnapshot
*
* Purpose:
*
* Destroys snapshot heap and zero linked list.
*
*/
VOID sapiFreeSnapshot(
    VOID
)
{
    EnterCriticalSection(&g_sapiDB.Lock);
    supDestroyHeap(g_sapiDB.HeapHandle);
    g_sapiDB.HeapHandle = NULL;
    g_sapiDB.ListHead.Blink = NULL;
    g_sapiDB.ListHead.Flink = NULL;
    LeaveCriticalSection(&g_sapiDB.Lock);
}

/*
* supCallbackShowChildWindow
*
* Purpose:
*
* Makes window controls (in)visible in the given rectangle type dialog
*
*/
BOOL WINAPI supCallbackShowChildWindow(
    _In_ HWND hwnd,
    _In_ LPARAM lParam
)
{
    RECT r1;
    ENUMCHILDWNDDATA* Data = (PENUMCHILDWNDDATA)lParam;

    if (GetWindowRect(hwnd, &r1)) {
        if (PtInRect(&Data->Rect, *(POINT*)&r1))
            ShowWindow(hwnd, Data->nCmdShow);
    }
    return TRUE;
}

/*
* supQueryWinstationDescription
*
* Purpose:
*
* Query predefined window station types, if found equal copy to buffer it friendly name.
*
* Input buffer size must be at least MAX_PATH size.
*
*/
BOOL supQueryWinstationDescription(
    _In_ LPCWSTR lpWindowStationName,
    _Inout_ LPWSTR Buffer,
    _In_ DWORD cchBuffer //size of buffer in chars
)
{
    BOOL    bFound = FALSE;
    LPCWSTR lpType = T_UnknownType;

    ULONG i;

    struct {
        LPCWSTR lpszWinSta;
        LPCWSTR lpszDesc;
    } lpWinstationDescriptions[] = {
        { T_WINSTA_SYSTEM, L"System" },
        { T_WINSTA_ANONYMOUS, L"Anonymous" },
        { T_WINSTA_LOCALSERVICE, L"Local Service" },
        { T_WINSTA_NETWORK_SERVICE, L"Network Service" }
    };

    if (lpWindowStationName == NULL ||
        cchBuffer < MAX_PATH)
    {
        return bFound;
    }

    for (i = 0; i < RTL_NUMBER_OF(lpWinstationDescriptions); i++) {

        bFound = (_strstri(lpWindowStationName,
            lpWinstationDescriptions[i].lpszWinSta) != NULL);

        if (bFound) {
            lpType = lpWinstationDescriptions[i].lpszDesc;
            break;
        }

    }

    _strcpy(Buffer, lpType);
    _strcat(Buffer, TEXT(" logon session"));

    return bFound;
}

/*
* supQueryTypeInfo
*
* Purpose:
*
* Query specific type info for output in listview.
*
* Input buffer size must be at least MAX_PATH size.
*
*/
BOOL supQueryTypeInfo(
    _In_ PUNICODE_STRING TypeName,
    _Inout_ LPWSTR Buffer,
    _In_ DWORD cchBuffer //size of buffer in chars
)
{
    BOOL  bResult = FALSE;
    ULONG i, nPool;

    POBTYPE_LIST objectTypesList;
    POBTYPE_ENTRY objectEntry;

    if (Buffer == NULL ||
        cchBuffer < MAX_PATH)
    {
        return FALSE;
    }

    objectTypesList = g_kdctx.Data->ObjectTypesList;
    if (objectTypesList == NULL)
        return FALSE;

    for (i = 0; i < objectTypesList->NumberOfTypes; i++) {

        objectEntry = &objectTypesList->Types[i];

        if (RtlEqualUnicodeString(objectEntry->TypeName, TypeName, TRUE)) {

            for (nPool = 0; nPool < MAX_KNOWN_POOL_TYPES; nPool++) {
                if (objectEntry->PoolType == a_PoolTypes[nPool].dwValue) {
                    _strncpy(Buffer,
                        cchBuffer,
                        a_PoolTypes[nPool].lpDescription,
                        _strlen(a_PoolTypes[nPool].lpDescription));
                    break;
                }
            }

            bResult = TRUE;
            break;
        }

    }

    return bResult;
}

/*
* supQueryDeviceDescription
*
* Purpose:
*
* Query device description from Setup API DB dump.
*
* Buffer should be at least MAX_PATH length in chars.
*
*/
BOOL supQueryDeviceDescription(
    _In_opt_ PUNICODE_STRING Path,
    _In_ PUNICODE_STRING Name,
    _Inout_ LPWSTR Buffer,
    _In_ DWORD cchBuffer //size of buffer in chars
)
{
    BOOL         bResult;
    PLIST_ENTRY  Entry;
    PSAPIDBENTRY Item;
    SIZE_T       deviceLength;

    UNICODE_STRING deviceName;

    bResult = FALSE;

    RtlInitEmptyUnicodeString(&deviceName, NULL, 0);

    if (Path == NULL) {
        if (!supCreateObjectPathFromCurrentPath(Name, &deviceName, TRUE))
            return FALSE;
    }
    else {
        if (!supCreateObjectPathFromElements(Name, Path, &deviceName, TRUE))
            return FALSE;
    }

    EnterCriticalSection(&g_sapiDB.Lock);

    //
    // Enumerate devices.
    //
    Entry = g_sapiDB.ListHead.Flink;
    while (Entry && Entry != &g_sapiDB.ListHead) {

        Item = CONTAINING_RECORD(Entry, SAPIDBENTRY, ListEntry);
        if (Item->lpDeviceName != NULL) {

            //
            // lpDeviceName expects to be zero terminated.
            //
            deviceLength = _strlen(deviceName.Buffer);

            if (_strncmpi(deviceName.Buffer, Item->lpDeviceName, deviceLength) == 0) {

                if (Item->lpDeviceDesc != NULL) {

                    _strncpy(
                        Buffer,
                        cchBuffer,
                        Item->lpDeviceDesc,
                        _strlen(Item->lpDeviceDesc));

                }
                bResult = TRUE;
                break;
            }
        }

        Entry = Entry->Flink;
    }

    LeaveCriticalSection(&g_sapiDB.Lock);

    supFreeDuplicatedUnicodeString(g_obexHeap, &deviceName, FALSE);
    return bResult;
}

/*
* supQueryDriverDescription
*
* Purpose:
*
* Query driver description from SCM dump or from file version info
*
* Buffer should be at least MAX_PATH length in chars.
*
*/
BOOL supQueryDriverDescription(
    _In_ LPCWSTR lpDriverName,
    _Inout_ LPWSTR Buffer,
    _In_ DWORD cchBuffer //size of buffer in chars
)
{
    BOOL    bResult;
    LPWSTR  lpServiceName = NULL;
    LPWSTR  lpDisplayName = NULL;
    LPWSTR  lpRegKey = NULL;
    SIZE_T  i, sz;

    PVOID   vinfo = NULL;
    DWORD   dwSize, dwHandle;
    LRESULT lRet;
    HKEY    hKey = NULL;

    WCHAR   szBuffer[MAX_PATH + 1];
    WCHAR   szImagePath[MAX_PATH + 1];

    LPTRANSLATE	                  lpTranslate = NULL;
    LPENUM_SERVICE_STATUS_PROCESS pInfo = NULL;

    bResult = FALSE;

    //
    // First attempt - look in SCM database.
    //

    RtlEnterCriticalSection(&g_scmDB.Lock);

    if (g_scmDB.Entries != NULL) {
        pInfo = (LPENUM_SERVICE_STATUS_PROCESS)g_scmDB.Entries;
        for (i = 0; i < g_scmDB.NumberOfEntries; i++) {

            lpServiceName = pInfo[i].lpServiceName;
            if (lpServiceName == NULL)
                continue;

            // not our driver - skip
            if (_strcmpi(lpServiceName, lpDriverName) != 0)
                continue;

            lpDisplayName = pInfo[i].lpDisplayName;
            if (lpDisplayName == NULL)
                continue;

            // driver has the same name as service - skip, there is no description available
            if (_strcmpi(lpDisplayName, lpDriverName) == 0)
                continue;

            sz = _strlen(lpDisplayName);
            _strncpy(Buffer, cchBuffer, lpDisplayName, sz);
            bResult = TRUE;
            break;
        }
    }

    RtlLeaveCriticalSection(&g_scmDB.Lock);

    // second attempt - query through registry and fs
    if (bResult == FALSE) {

        do {
            sz = _strlen(lpDriverName);
            if (sz == 0)
                break;

            sz += supServicesRegPathSize;
            sz = (1 + sz) * sizeof(WCHAR);

            lpRegKey = (LPWSTR)supHeapAlloc(sz);
            if (lpRegKey == NULL)
                break;

            _strcpy(lpRegKey, supServicesRegPath);
            _strcat(lpRegKey, lpDriverName);

            hKey = NULL;
            lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpRegKey, 0, KEY_QUERY_VALUE, &hKey);
            if (ERROR_SUCCESS != lRet)
                break;

            RtlSecureZeroMemory(szImagePath, sizeof(szImagePath));
            dwSize = sizeof(szImagePath) - sizeof(UNICODE_NULL);
            lRet = RegQueryValueEx(hKey, TEXT("ImagePath"), NULL, NULL, (LPBYTE)szImagePath, &dwSize);
            RegCloseKey(hKey);

            if (ERROR_SUCCESS == lRet) {

                dwHandle = 0;
                dwSize = GetFileVersionInfoSizeEx(0, szImagePath, &dwHandle);
                if (dwSize == 0)
                    break;

                // allocate memory for version_info structure
                vinfo = supHeapAlloc(dwSize);
                if (vinfo == NULL)
                    break;

                // query it from file
                if (!GetFileVersionInfoEx(0, szImagePath, 0, dwSize, vinfo))
                    break;

                // query codepage and language id info
                dwSize = 0;
                if (!VerQueryValue(vinfo, T_VERSION_TRANSLATION, (LPVOID*)&lpTranslate, (PUINT)&dwSize))
                    break;

                if (dwSize == 0)
                    break;

                // query filedescription from file with given codepage & language id
                RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

                RtlStringCchPrintfSecure(szBuffer,
                    MAX_PATH,
                    FORMAT_VERSION_DESCRIPTION,
                    lpTranslate[0].wLanguage,
                    lpTranslate[0].wCodePage);

                // finally query pointer to version_info filedescription block data
                lpDisplayName = NULL;
                dwSize = 0;
                bResult = VerQueryValue(vinfo, szBuffer, (LPVOID*)&lpDisplayName, (PUINT)&dwSize);
                if (bResult) {
                    _strncpy(Buffer, cchBuffer, lpDisplayName, dwSize);
                }

            }

        } while (FALSE);

        if (vinfo) {
            supHeapFree(vinfo);
        }
        if (lpRegKey) {
            supHeapFree(lpRegKey);
        }
    }
    return bResult;
}

/*
* supGetVersionInfoFromSection
*
* Purpose:
*
* Return RT_VERSION data and size in VERSION.DLL friendly view.
*
*/
BOOL supGetVersionInfoFromSection(
    _In_ HANDLE SectionHandle,
    _Out_opt_ PDWORD VersionInfoSize,
    _Out_ LPVOID* VersionData
)
{
    HANDLE sectionHandle = NULL;
    VERHEAD* pVerHead = NULL;
    ULONG_PTR idPath[3];
    PBYTE dataPtr = NULL, dllBase = NULL;
    PVOID versionPtr = NULL;
    SIZE_T dllVirtualSize = 0, verSize = 0;
    ULONG_PTR sizeOfData = 0;
    NTSTATUS ntStatus;
    DWORD dwTemp = 0;

    idPath[0] = (ULONG_PTR)RT_VERSION; //type
    idPath[1] = 1;                     //id
    idPath[2] = 0;                     //lang

    if (VersionInfoSize)
        *VersionInfoSize = 0;

    if (VersionData)
        *VersionData = NULL;
    else
        return FALSE; //this param is required

    __try {

        ntStatus = NtDuplicateObject(NtCurrentProcess(),
            SectionHandle,
            NtCurrentProcess(),
            &sectionHandle,
            SECTION_MAP_READ,
            0,
            0);

        if (!NT_SUCCESS(ntStatus)) {
            supReportAPIError(__FUNCTIONW__, ntStatus);
            __leave;
        }

        ntStatus = NtMapViewOfSection(sectionHandle, NtCurrentProcess(), (PVOID*)&dllBase,
            0, 0, NULL, &dllVirtualSize, ViewUnmap, 0, PAGE_READONLY);
        if (!NT_SUCCESS(ntStatus)) {
            supReportAPIError(__FUNCTIONW__, ntStatus);
            __leave;
        }

        ntStatus = LdrResSearchResource(dllBase, (ULONG_PTR*)&idPath, 3, 0,
            (LPVOID*)&dataPtr, (ULONG_PTR*)&sizeOfData, NULL, NULL);
        if (!NT_SUCCESS(ntStatus)) {
            if ((ntStatus != STATUS_RESOURCE_DATA_NOT_FOUND) &&
                (ntStatus != STATUS_RESOURCE_TYPE_NOT_FOUND) &&
                (ntStatus != STATUS_RESOURCE_NAME_NOT_FOUND))
            {
                supReportAPIError(__FUNCTIONW__, ntStatus);
            }
            __leave;
        }

        pVerHead = (VERHEAD*)dataPtr;
        if (pVerHead->wTotLen > sizeOfData) {
            supReportAPIError(__FUNCTIONW__, STATUS_INVALID_BUFFER_SIZE);
            __leave;
        }

        if (pVerHead->vsf.dwSignature != VS_FFI_SIGNATURE) {
            supReportAPIError(__FUNCTIONW__, STATUS_INVALID_IMAGE_FORMAT);
            __leave;
        }

        dwTemp = (DWORD)pVerHead->wTotLen;
        dwTemp = DWORDUP(dwTemp);

        verSize = ((ULONG_PTR)dwTemp * 2) + sizeof(VER2_SIG);

        if (VersionInfoSize)
            *VersionInfoSize = (DWORD)verSize;

        versionPtr = supHeapAlloc(verSize);
        if (versionPtr == NULL) {
            __leave;
        }

        RtlCopyMemory(versionPtr, pVerHead, dwTemp);

        //
        // Do as GetFileVersionInfo does.
        //
        *((PDWORD)((ULONG_PTR)versionPtr + dwTemp)) = VER2_SIG;

        *VersionData = versionPtr;

    }
    __finally {

        if (AbnormalTermination()) {

            dwTemp = 0;

            if (versionPtr)
                supHeapFree(versionPtr);

            supReportAbnormalTermination(__FUNCTIONW__);
        }

        if (dllBase)
            NtUnmapViewOfSection(NtCurrentProcess(), dllBase);

        if (sectionHandle)
            NtClose(sectionHandle);

    }

    return (dwTemp != 0);
}

/*
* supQuerySectionFileInfo
*
* Purpose:
*
* Query section object type File + Image description from version info block
*
* Buffer should be at least MAX_PATH length in chars.
*
*/
BOOL supQuerySectionFileInfo(
    _In_opt_ HANDLE RootDirectoryHandle,
    _In_ PUNICODE_STRING ObjectName,
    _Inout_ LPWSTR Buffer,
    _In_ DWORD ccBuffer //size of buffer in chars
)
{
    BOOL                        bResult;
    HANDLE                      hSection;
    PVOID                       vinfo;
    LPWSTR                      pcValue;
    LPTRANSLATE                 lpTranslate;
    SIZE_T                      cLength = 0;
    NTSTATUS                    status;
    DWORD                       dwInfoSize;
    OBJECT_ATTRIBUTES           Obja;
    SECTION_BASIC_INFORMATION   sbi;
    SECTION_IMAGE_INFORMATION   sii;
    WCHAR                       szQueryBlock[MAX_PATH + 1];

    bResult = FALSE;
    vinfo = NULL;
    hSection = NULL;

    do {
        //oleaut32.dll does not have FileDescription

        //  open section with query access
        InitializeObjectAttributes(&Obja, ObjectName, OBJ_CASE_INSENSITIVE, RootDirectoryHandle, NULL);
        status = NtOpenSection(&hSection, SECTION_QUERY, &Obja);
        if (!NT_SUCCESS(status))
            break;

        //  query section flags
        RtlSecureZeroMemory(&sbi, sizeof(sbi));
        status = NtQuerySection(hSection, SectionBasicInformation, (PVOID)&sbi, sizeof(sbi), &cLength);
        if (!NT_SUCCESS(status))
            break;

        //  check if section is SEC_IMAGE | SEC_FILE
        if (!((sbi.AllocationAttributes & SEC_IMAGE) && (sbi.AllocationAttributes & SEC_FILE)))
            break;

        // check image machine type
        RtlSecureZeroMemory(&sii, sizeof(sii));
        status = NtQuerySection(hSection, SectionImageInformation, (PVOID)&sii, sizeof(sii), &cLength);
        if (!NT_SUCCESS(status))
            break;

        if (!supGetVersionInfoFromSection(hSection, NULL, &vinfo))
            break;

        if (vinfo == NULL)
            break;

        // query codepage and language id info
        if (!VerQueryValue(vinfo, T_VERSION_TRANSLATION, (LPVOID*)&lpTranslate, (PUINT)&dwInfoSize))
            break;
        if (dwInfoSize == 0)
            break;

        // query filedescription from file with given codepage & language id
        RtlSecureZeroMemory(szQueryBlock, sizeof(szQueryBlock));

        RtlStringCchPrintfSecure(szQueryBlock,
            MAX_PATH,
            FORMAT_VERSION_DESCRIPTION,
            lpTranslate[0].wLanguage,
            lpTranslate[0].wCodePage);

        // finally query pointer to version_info filedescription block data
        pcValue = NULL;
        dwInfoSize = 0;
        bResult = VerQueryValue(vinfo, szQueryBlock, (LPVOID*)&pcValue, (PUINT)&dwInfoSize);
        if (bResult) {
            _strncpy(Buffer, ccBuffer, pcValue, dwInfoSize);
        }

    } while (FALSE);

    if (hSection) NtClose(hSection);
    if (vinfo) supHeapFree(vinfo);
    return bResult;
}

/*
* supSaveDialogExecute
*
* Purpose:
*
* Display SaveDialog.
*
*/
BOOL supSaveDialogExecute(
    _In_ HWND OwnerWindow,
    _Inout_ LPWSTR SaveFileName,
    _In_ LPCWSTR DialogFilter
)
{
    OPENFILENAME tag1;

    RtlSecureZeroMemory(&tag1, sizeof(OPENFILENAME));

    tag1.lStructSize = sizeof(OPENFILENAME);
    tag1.hwndOwner = OwnerWindow;
    tag1.lpstrFilter = DialogFilter;
    tag1.lpstrFile = SaveFileName;
    tag1.nMaxFile = MAX_PATH;
    tag1.lpstrInitialDir = NULL;
    tag1.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;

    return GetSaveFileName(&tag1);
}

/*
* supSetListViewSettings
*
* Purpose:
*
* Set listview imagelist, style flags and theme.
*
*/
VOID supSetListViewSettings(
    _In_ HWND hwndLV,
    _In_ DWORD dwExtendedStyle,
    _In_ BOOL fIgnoreGlobalSettings,
    _In_ BOOL fSetTheme,
    _In_opt_ HIMAGELIST hImageList,
    _In_ INT iImageList
)
{
    DWORD dwFlags = dwExtendedStyle;

    if (!fIgnoreGlobalSettings) {
        if (g_WinObj.ListViewDisplayGrid)
            dwFlags |= LVS_EX_GRIDLINES;
    }

    ListView_SetExtendedListViewStyle(hwndLV, dwFlags);

    if (hImageList) {
        ListView_SetImageList(hwndLV, hImageList, iImageList);
    }

    if (fSetTheme) {
        SetWindowTheme(hwndLV, TEXT("Explorer"), NULL);
    }
}

/*
* supGetStockIcon
*
* Purpose:
*
* Retrieve stock icon of given id.
*
*/
HICON supGetStockIcon(
    _In_ SHSTOCKICONID siid,
    _In_ UINT uFlags)
{
    SHSTOCKICONINFO sii;

    RtlSecureZeroMemory(&sii, sizeof(sii));
    sii.cbSize = sizeof(sii);

    if (SHGetStockIconInfo(siid, uFlags, &sii) == S_OK) {
        return sii.hIcon;
    }
    return NULL;
}

//
// Conversion buffer size
//
#define CONVERT_NTNAME_BUFFER_SIZE 512

/*
* supxConvertFileName
*
* Purpose:
*
* Translate Nt path name to Dos path name.
*
*/
BOOL supxConvertFileName(
    _In_ LPWSTR NtFileName,
    _Inout_ LPWSTR DosFileName,
    _In_ SIZE_T ccDosFileName
)
{
    BOOL bFound = FALSE;

    SIZE_T nLen;

    WCHAR szDrive[3];
    WCHAR szName[MAX_PATH];
    WCHAR szTemp[CONVERT_NTNAME_BUFFER_SIZE];
    WCHAR* pszTemp;

    //
    // All input parameters are validated by caller before.
    //

    //
    // Drive template.
    //
    szDrive[0] = L'X';
    szDrive[1] = L':';
    szDrive[2] = 0;

    //
    // Query array of logical disk drive strings.
    //
    szTemp[0] = 0;
    if (GetLogicalDriveStrings(RTL_NUMBER_OF(szTemp), szTemp) == 0)
        return FALSE;

    pszTemp = szTemp;

    do {

        //
        // Copy the drive letter to the template string.
        //
        *szDrive = *pszTemp;
        szName[0] = 0;

        //
        // Lookup each device name.
        //
        if (QueryDosDevice(szDrive, szName, MAX_PATH)) {

            nLen = _strlen(szName);

            if (nLen < MAX_PATH) {

                //
                // Match device name.
                //
                bFound = ((_strncmpi(NtFileName, szName, nLen) == 0)
                    && *(NtFileName + nLen) == L'\\');

                if (bFound) {

                    //
                    // Build output name.
                    //
                    RtlStringCchPrintfSecure(
                        DosFileName,
                        ccDosFileName,
                        TEXT("%ws%ws"),
                        szDrive,
                        NtFileName + nLen);

                }

            }

        }

        //
        // Go to the next NULL character, i.e. the next drive name.
        //
        while (*pszTemp++);

    } while (!bFound && *pszTemp);

    return bFound;
}

/*
* supGetWin32FileName
*
* Purpose:
*
* Query filename by handle.
*
*/
LPWSTR supGetWin32FileName(
    _In_ LPCWSTR NtFileName
)
{
    BOOL                bResult = FALSE;
    LPWSTR              lpWin32Name = NULL;
    NTSTATUS            ntStatus = STATUS_UNSUCCESSFUL;
    HANDLE              hFile = NULL;
    UNICODE_STRING      usNtFileName;
    OBJECT_ATTRIBUTES   obja;
    IO_STATUS_BLOCK     iost;
    ULONG               size;

    BYTE* Buffer = NULL;

    RtlInitUnicodeString(&usNtFileName, NtFileName);
    InitializeObjectAttributes(&obja, &usNtFileName, OBJ_CASE_INSENSITIVE, 0, NULL);

    do {

        ntStatus = NtCreateFile(&hFile,
            SYNCHRONIZE,
            &obja,
            &iost,
            NULL,
            0,
            FILE_SHARE_VALID_FLAGS,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            NULL, 0);

        if (!NT_SUCCESS(ntStatus))
            break;

        ntStatus = supQueryObjectInformation(hFile,
            ObjectNameInformation,
            &Buffer,
            NULL);

        if (!NT_SUCCESS(ntStatus))
            break;

        size = UNICODE_STRING_MAX_CHARS * sizeof(WCHAR);
        lpWin32Name = (LPWSTR)supHeapAlloc(size);

        if (lpWin32Name == NULL)
            break;

        bResult = supxConvertFileName(((POBJECT_NAME_INFORMATION)Buffer)->Name.Buffer,
            lpWin32Name,
            size / sizeof(WCHAR));

    } while (FALSE);

    if (Buffer) supHeapFree(Buffer);
    if (hFile) NtClose(hFile);
    if (bResult == FALSE && lpWin32Name) {
        supHeapFree(lpWin32Name);
        lpWin32Name = NULL;
    }

    return lpWin32Name;
}

/*
* supQuerySecureBootState
*
* Purpose:
*
* Query Firmware type and SecureBoot state if firmware is EFI.
*
*/
BOOLEAN supQuerySecureBootState(
    _Out_ PBOOLEAN pbSecureBoot
)
{
    BOOLEAN bSecureBoot = FALSE;
    HKEY    hKey;
    DWORD   dwState, dwSize, returnLength;
    LSTATUS lRet;

    SYSTEM_SECUREBOOT_INFORMATION sbi;

    if (pbSecureBoot)
        *pbSecureBoot = FALSE;

    //
    // 1) query firmware environment variable, will not work if not fulladmin.
    //
    if (supEnablePrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, TRUE)) {

        bSecureBoot = FALSE;

        returnLength = GetFirmwareEnvironmentVariable(
            L"SecureBoot",
            L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}",
            &bSecureBoot,
            sizeof(BOOLEAN));

        supEnablePrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, FALSE);
        if (returnLength != 0) {
            if (pbSecureBoot) {
                *pbSecureBoot = bSecureBoot;
            }
            return TRUE;
        }
    }

    //
    // 2) NtQSI(SystemSecureBootInformation).
    //
    RtlSecureZeroMemory(&sbi, sizeof(sbi));
    if (NT_SUCCESS(NtQuerySystemInformation(SystemSecureBootInformation,
        &sbi,
        sizeof(SYSTEM_SECUREBOOT_INFORMATION),
        &returnLength)))
    {
        if (sbi.SecureBootCapable == FALSE) {
            if (pbSecureBoot)
                *pbSecureBoot = FALSE;
        }
        else {
            if (pbSecureBoot)
                *pbSecureBoot = sbi.SecureBootEnabled;
        }

        return TRUE;
    }

    //
    // 3) Query state from registry.
    //
    hKey = NULL;
    lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, T_SECUREBOOTSTATEKEY, 0, KEY_QUERY_VALUE, &hKey);
    if (lRet == ERROR_SUCCESS) {
        dwState = 0;
        dwSize = sizeof(DWORD);
        lRet = RegQueryValueEx(hKey, T_SECUREBOOTSTATEVALUE, NULL, NULL, (LPBYTE)&dwState, &dwSize);
        RegCloseKey(hKey);

        if (lRet == ERROR_SUCCESS) {

            if (pbSecureBoot) {
                *pbSecureBoot = (dwState == 1);
            }
            return TRUE;
        }
    }

    //
    // 4) Query state from user shared data.
    //
    dwState = USER_SHARED_DATA->DbgSecureBootEnabled;
    if (pbSecureBoot) {
        *pbSecureBoot = (dwState == 1);
        return TRUE;
    }  

    return FALSE;
}

/*
* supxGetWindowStationName
*
* Purpose:
*
* Build current windows station object path based on SessionId value from PEB.
*
*/
BOOLEAN supxGetWindowStationName(
    _Out_ UNICODE_STRING* pusWinstaName
)
{
    LPWSTR WindowStationsDir = L"\\Windows\\WindowStations";
    LPWSTR SourceString;
    ULONG SessionId = NtCurrentPeb()->SessionId;

    WCHAR szWinsta[MAX_PATH];

    if (SessionId) {
        _strcpy(szWinsta, L"\\Sessions\\");
        ultostr(SessionId, _strend(szWinsta));
        _strcat(szWinsta, WindowStationsDir);
        SourceString = szWinsta;
    }
    else {
        SourceString = WindowStationsDir;
    }
    return RtlCreateUnicodeString(pusWinstaName, SourceString);
}

/*
* supOpenWindowStationFromContext
*
* Purpose:
*
* Open Window station with hardcoded object path check.
*
*/
HWINSTA supOpenWindowStationFromContext(
    _In_ PROP_OBJECT_INFO* Context,
    _In_ BOOL fInherit,
    _In_ ACCESS_MASK dwDesiredAccess)
{
    HWINSTA hObject = NULL;
    UNICODE_STRING CurrentWinstaDir;

    DWORD LastError = ERROR_ACCESS_DENIED;

    if (supxGetWindowStationName(&CurrentWinstaDir)) {
        if (RtlEqualUnicodeString(&Context->NtObjectPath, &CurrentWinstaDir, TRUE)) {
            hObject = OpenWindowStation(Context->NtObjectName.Buffer, fInherit, dwDesiredAccess);
            LastError = GetLastError();
        }
        RtlFreeUnicodeString(&CurrentWinstaDir);
    }

    SetLastError(LastError);
    return hObject;
}

/*
* supQueryObjectTrustLabel
*
* Purpose:
*
* Query object trust label protection origin and level.
*
* Note: hObject must be opened with READ_CONTROL.
*
*/
NTSTATUS supQueryObjectTrustLabel(
    _In_ HANDLE hObject,
    _Out_ PULONG ProtectionType,
    _Out_ PULONG ProtectionLevel)
{
    BOOLEAN                         saclPresent = FALSE, saclDefaulted = FALSE;
    ULONG                           i;
    NTSTATUS                        ntStatus;

    PSID                            aceSID;
    PACL                            sacl = NULL;
    PACE_HEADER                     aceHeader;
    PSYSTEM_PROCESS_TRUST_LABEL_ACE ace;

    ACL_SIZE_INFORMATION            aclSize;
    PSECURITY_DESCRIPTOR            pSD = NULL;

    *ProtectionType = 0;
    *ProtectionLevel = 0;

    do {

        //
        // Query Security Descriptor for given object.
        //

        ntStatus = supQuerySecurityInformation(hObject,
            PROCESS_TRUST_LABEL_SECURITY_INFORMATION,
            &pSD,
            NULL);

        if (!NT_SUCCESS(ntStatus)) {
            break;
        }

        //
        // Query SACL from SD.
        //
        ntStatus = RtlGetSaclSecurityDescriptor(pSD,
            &saclPresent,
            &sacl,
            &saclDefaulted);

        if (!NT_SUCCESS(ntStatus)) {
            break;
        }

        if (!sacl) {
            ntStatus = STATUS_INVALID_SID;
            break;
        }

        //
        // Query SACL size.
        //
        ntStatus = RtlQueryInformationAcl(sacl,
            &aclSize,
            sizeof(aclSize),
            AclSizeInformation);

        if (!NT_SUCCESS(ntStatus)) {
            break;
        }

        //
        // Locate trust label ace.
        //
        for (i = 0; i < aclSize.AceCount; i++) {
            if (NT_SUCCESS(RtlGetAce(sacl, i, (PVOID*)&aceHeader))) {
                if (aceHeader->AceType == SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE) {
                    ace = (SYSTEM_PROCESS_TRUST_LABEL_ACE*)aceHeader;
                    aceSID = (PSID)(&ace->SidStart);
                    *ProtectionType = *RtlSubAuthoritySid(aceSID, 0);
                    *ProtectionLevel = *RtlSubAuthoritySid(aceSID, 1);
                    ntStatus = STATUS_SUCCESS;
                    break;
                }
            }
        }

    } while (FALSE);

    if (pSD) supHeapFree(pSD);

    return ntStatus;
}

/*
* supQueryTokenUserSid
*
* Purpose:
*
* Return SID of given token.
*
* Use supHeapFree to free memory allocated for result.
*
*/
PSID supQueryTokenUserSid(
    _In_ HANDLE ProcessToken
)
{
    PSID resultSid = NULL;
    PTOKEN_USER ptu;
    NTSTATUS status;
    ULONG sidLength = 0, allocLength;

    status = NtQueryInformationToken(
        ProcessToken,
        TokenUser,
        NULL, 0, &sidLength);

    if (status == STATUS_BUFFER_TOO_SMALL) {

        ptu = (PTOKEN_USER)supHeapAlloc(sidLength);

        if (ptu) {

            status = NtQueryInformationToken(
                ProcessToken,
                TokenUser,
                ptu,
                sidLength,
                &sidLength);

            if (NT_SUCCESS(status)) {

                allocLength = SECURITY_MAX_SID_SIZE;
                if (sidLength > allocLength)
                    allocLength = sidLength;

                resultSid = (PSID)supHeapAlloc(allocLength);
                if (resultSid) {

                    status = RtlCopySid(
                        allocLength,
                        resultSid,
                        ptu->User.Sid);

                }
            }

            supHeapFree(ptu);
        }
    }

    return (NT_SUCCESS(status)) ? resultSid : NULL;
}

/*
* supQueryProcessSid
*
* Purpose:
*
* Return SID for the given process.
*
* Use supHeapFree to free memory allocated for result.
*
*/
PSID supQueryProcessSid(
    _In_ HANDLE ProcessHandle
)
{
    HANDLE processToken = NULL;
    PSID resultSid = NULL;

    if (NT_SUCCESS(NtOpenProcessToken(
        ProcessHandle,
        TOKEN_QUERY,
        &processToken)))
    {
        resultSid = supQueryTokenUserSid(processToken);

        NtClose(processToken);
    }

    return resultSid;
}

/*
* supIsImmersiveProcess
*
* Purpose:
*
* Wrapper for IsImmersiveProcess, since it is not present on Win7.
*
*/
BOOL supIsImmersiveProcess(
    _In_ HANDLE hProcess
)
{
    if (g_ExtApiSet.IsImmersiveProcess)
        return g_ExtApiSet.IsImmersiveProcess(hProcess);

    return FALSE;
}

/*
* supIsProtectedProcess
*
* Purpose:
*
* Check if given process is protected process.
*
*/
NTSTATUS supIsProtectedProcess(
    _In_ HANDLE hProcess,
    _Out_ PBOOL pbProtected
)
{
    NTSTATUS ntStatus;
    ULONG requredLength = 0;
    PROCESS_EXTENDED_BASIC_INFORMATION exbi;

    exbi.Size = sizeof(PROCESS_EXTENDED_BASIC_INFORMATION);
    ntStatus = NtQueryInformationProcess(hProcess, ProcessBasicInformation,
        &exbi, sizeof(exbi), &requredLength);
    
    if (NT_SUCCESS(ntStatus)) {
        *pbProtected  = (exbi.IsProtectedProcess != 0);
    }

    return ntStatus;
}

/*
* supIsLocalSystem
*
* Purpose:
*
* pbResult will be set to TRUE if current account is run by system user, FALSE otherwise.
*
* Function return operation status code.
*
*/
NTSTATUS supIsLocalSystem(
    _In_ HANDLE hToken,
    _Out_ PBOOL pbResult)
{
    BOOL                     bResult = FALSE;
    NTSTATUS                 status = STATUS_UNSUCCESSFUL;
    PSID                     SystemSid = NULL, TokenSid = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuth = SECURITY_NT_AUTHORITY;

    //
    // Assume failure.
    //
    if (pbResult)
        *pbResult = FALSE;

    //
    // Get current user SID.
    //
    TokenSid = supQueryTokenUserSid(hToken);
    if (TokenSid == NULL)
        return status;

    //
    // Get System SID.
    //
    status = RtlAllocateAndInitializeSid(
        &NtAuth,
        1,
        SECURITY_LOCAL_SYSTEM_RID,
        0, 0, 0, 0, 0, 0, 0,
        &SystemSid);

    if (NT_SUCCESS(status)) {

        //
        // Compare SIDs.
        //
        bResult = RtlEqualSid(TokenSid, SystemSid);
        RtlFreeSid(SystemSid);
    }

    supHeapFree(TokenSid);

    if (pbResult)
        *pbResult = bResult;

    return status;
}

/*
* supIsLocalServiceSid
*
* Purpose:
*
* Check if given sid is sid of local service.
*
*/
BOOLEAN supIsLocalServiceSid(
    _In_ PSID Sid
)
{
    SID sidLocalService = { SID_REVISION, 1, SECURITY_NT_AUTHORITY, { SECURITY_LOCAL_SERVICE_RID } };

    return RtlEqualSid(&sidLocalService, Sid);
}

/*
* supxGetSystemToken
*
* Purpose:
*
* Find winlogon process and duplicate it token.
*
*/
NTSTATUS supxGetSystemToken(
    _In_ PVOID ProcessList,
    _Out_ PHANDLE SystemToken)
{
    BOOL bSystemToken = FALSE, bEnabled = FALSE;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    ULONG NextEntryDelta = 0;
    HANDLE hObject = NULL;
    HANDLE hToken = NULL;

    ULONG WinlogonSessionId;
    UNICODE_STRING usWinlogon = RTL_CONSTANT_STRING(L"winlogon.exe");

    union {
        PSYSTEM_PROCESS_INFORMATION Process;
        PBYTE ListRef;
    } List;

    *SystemToken = NULL;

    WinlogonSessionId = WTSGetActiveConsoleSessionId();
    if (WinlogonSessionId == 0xFFFFFFFF)
        return STATUS_INVALID_SESSION;

    List.ListRef = (PBYTE)ProcessList;

    do {

        List.ListRef += NextEntryDelta;

        if (RtlEqualUnicodeString(&usWinlogon, &List.Process->ImageName, TRUE)) {

            if (List.Process->SessionId == WinlogonSessionId) {

                Status = supOpenProcess(
                    List.Process->UniqueProcessId,
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    &hObject);

                if (NT_SUCCESS(Status)) {

                    Status = NtOpenProcessToken(
                        hObject,
                        TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE | TOKEN_QUERY,
                        &hToken);

                    if (NT_SUCCESS(Status)) {

                        Status = supIsLocalSystem(hToken, &bSystemToken);

                        if (NT_SUCCESS(Status) && (bSystemToken)) {

                            Status = supPrivilegeEnabled(hToken, SE_TCB_PRIVILEGE, &bEnabled);
                            if (NT_SUCCESS(Status)) {
                                if (bEnabled) {
                                    NtClose(hObject);
                                    *SystemToken = hToken;
                                    return STATUS_SUCCESS;
                                }
                                else {
                                    Status = STATUS_PRIVILEGE_NOT_HELD;
                                }
                            }
                        }
                        NtClose(hToken);
                    }

                    NtClose(hObject);
                }

            }
        }

        NextEntryDelta = List.Process->NextEntryDelta;

    } while (NextEntryDelta);

    return Status;
}

/*
* supRunAsLocalSystem
*
* Purpose:
*
* Restart WinObjEx64 in local system account.
*
* Note: Elevated instance required.
*
*/
BOOL supRunAsLocalSystem(
    _In_ HWND hwndParent)
{
    BOOL bSuccess = FALSE;
    NTSTATUS Status;
    PVOID ProcessList;
    ULONG SessionId = NtCurrentPeb()->SessionId, dummy;

    HANDLE hSystemToken = NULL, hPrimaryToken = NULL, hImpersonationToken = NULL;

    BOOLEAN bThreadImpersonated = FALSE;

    PROCESS_INFORMATION pi;
    STARTUPINFO si;

    SECURITY_QUALITY_OF_SERVICE sqos;
    OBJECT_ATTRIBUTES obja;
    TOKEN_PRIVILEGES* TokenPrivileges;

    BYTE TokenPrivBufffer[sizeof(TOKEN_PRIVILEGES) +
        (1 * sizeof(LUID_AND_ATTRIBUTES))];

    WCHAR szApplication[MAX_PATH * 2];

    //
    // Remember our application name.
    //
    RtlSecureZeroMemory(szApplication, sizeof(szApplication));
    GetModuleFileName(NULL, szApplication, MAX_PATH);

    sqos.Length = sizeof(sqos);
    sqos.ImpersonationLevel = SecurityImpersonation;
    sqos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    sqos.EffectiveOnly = FALSE;
    InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
    obja.SecurityQualityOfService = &sqos;

    ProcessList = supGetSystemInfo(SystemProcessInformation, NULL);
    if (ProcessList == NULL) {
        MessageBox(
            hwndParent,
            TEXT("Could not allocate process list, abort."),
            PROGRAM_NAME,
            MB_ICONINFORMATION);

        return FALSE;
    }

    //
    // Get LocalSystem token from winlogon.
    //
    Status = supxGetSystemToken(ProcessList, &hSystemToken);

    supHeapFree(ProcessList);

    do {
        //
        // Check supxGetSystemToken result.
        //
        if (!NT_SUCCESS(Status) || (hSystemToken == NULL)) {

            supShowNtStatus(hwndParent,
                TEXT("No suitable system token found. Make sure you are running as administrator, code 0x"),
                Status);

            break;
        }

        //
        // Duplicate as impersonation token.
        //
        Status = NtDuplicateToken(
            hSystemToken,
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY |
            TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_PRIVILEGES,
            &obja,
            FALSE,
            TokenImpersonation,
            &hImpersonationToken);

        if (!NT_SUCCESS(Status)) {

            supShowNtStatus(hwndParent, TEXT("Error duplicating impersonation token, code 0x"), Status);
            break;
        }

        //
        // Duplicate as primary token.
        //
        Status = NtDuplicateToken(
            hSystemToken,
            TOKEN_ALL_ACCESS,
            &obja,
            FALSE,
            TokenPrimary,
            &hPrimaryToken);

        if (!NT_SUCCESS(Status)) {

            supShowNtStatus(hwndParent, TEXT("Error duplicating primary token, code 0x"), Status);
            break;
        }

        //
        // Impersonate system token.
        //
        Status = NtSetInformationThread(
            NtCurrentThread(),
            ThreadImpersonationToken,
            &hImpersonationToken,
            sizeof(HANDLE));

        if (!NT_SUCCESS(Status)) {

            supShowNtStatus(hwndParent, TEXT("Error while impersonating primary token, code 0x"), Status);
            break;
        }

        bThreadImpersonated = TRUE;

        //
        // Turn on AssignPrimaryToken privilege in impersonated token.
        //
        TokenPrivileges = (TOKEN_PRIVILEGES*)&TokenPrivBufffer;
        TokenPrivileges->PrivilegeCount = 1;
        TokenPrivileges->Privileges[0].Luid.LowPart = SE_ASSIGNPRIMARYTOKEN_PRIVILEGE;
        TokenPrivileges->Privileges[0].Luid.HighPart = 0;
        TokenPrivileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        Status = NtAdjustPrivilegesToken(
            hImpersonationToken,
            FALSE,
            TokenPrivileges,
            0,
            NULL,
            (PULONG)&dummy);

        if (!NT_SUCCESS(Status)) {
            supShowNtStatus(hwndParent, TEXT("Error adjusting token privileges, code 0x"), Status);
            break;
        }

        //
        // Set session id to primary token.
        //
        Status = NtSetInformationToken(
            hPrimaryToken,
            TokenSessionId,
            &SessionId,
            sizeof(ULONG));

        if (!NT_SUCCESS(Status)) {
            supShowNtStatus(hwndParent, TEXT("Error setting session id, code 0x"), Status);
            break;
        }

        si.cb = sizeof(si);
        GetStartupInfo(&si);

        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOWNORMAL;

        //
        // Run new instance with prepared primary token.
        //
        bSuccess = CreateProcessAsUser(
            hPrimaryToken,
            szApplication,
            NULL,
            NULL,
            NULL,
            FALSE,
            CREATE_DEFAULT_ERROR_MODE,
            NULL,
            g_WinObj.szProgramDirectory,
            &si,
            &pi);

        if (bSuccess) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        else {
            supShowLastError(hwndParent, TEXT("Run as LocalSystem"), GetLastError());
        }

    } while (FALSE);

    if (hImpersonationToken) {
        NtClose(hImpersonationToken);
    }

    //
    // Revert To Self.
    //
    if (bThreadImpersonated) {
        hImpersonationToken = NULL;
        NtSetInformationThread(
            NtCurrentThread(),
            ThreadImpersonationToken,
            (PVOID)&hImpersonationToken,
            sizeof(HANDLE));
    }

    if (hPrimaryToken) NtClose(hPrimaryToken);
    if (hSystemToken) NtClose(hSystemToken);

    //
    // Quit.
    //
    if (bSuccess)
        PostQuitMessage(0);

    return bSuccess;
}

/*
* supAddListViewColumn
*
* Purpose:
*
* Wrapper for ListView_InsertColumn.
*
*/
INT supAddListViewColumn(
    _In_ HWND ListViewHwnd,
    _In_ INT ColumnIndex,
    _In_ INT SubItemIndex,
    _In_ INT OrderIndex,
    _In_ INT ImageIndex,
    _In_ INT Format,
    _In_ LPWSTR Text,
    _In_ INT Width
)
{
    LVCOLUMN column;

    column.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT | LVCF_WIDTH | LVCF_ORDER | LVCF_IMAGE;
    column.fmt = Format;
    column.cx = SCALE_DPI_VALUE(Width, g_WinObj.CurrentDPI);
    column.pszText = Text;
    column.iSubItem = SubItemIndex;
    column.iOrder = OrderIndex;
    column.iImage = ImageIndex;

    return ListView_InsertColumn(ListViewHwnd, ColumnIndex, &column);
}

/*
* supUpdateLvColumnHeaderImage
*
* Purpose:
*
* Set new image for selected column and reset for all the rest.
*
*/
VOID supUpdateLvColumnHeaderImage(
    _In_ HWND ListView,
    _In_ INT NumberOfColumns,
    _In_ INT UpdateColumn,
    _In_ INT ImageIndex
)
{
    INT i;
    LVCOLUMN col;

    RtlSecureZeroMemory(&col, sizeof(col));
    col.mask = LVCF_IMAGE;

    for (i = 0; i < NumberOfColumns; i++) {
        if (i == UpdateColumn) {
            col.iImage = ImageIndex;
        }
        else {
            col.iImage = I_IMAGENONE;
        }
        ListView_SetColumn(ListView, i, &col);
    }
}

/*
* supGetMaxOfTwoUlongFromHex
*
* Purpose:
*
* Returned value used in listview comparer functions.
*
*/
INT supGetMaxOfTwoUlongFromHex(
    _In_ HWND ListView,
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort,
    _In_ BOOL Inverse
)
{
    INT       nResult;
    LPWSTR    lpItem1 = NULL, lpItem2 = NULL;
    ULONG     ad1, ad2;
    WCHAR     szText[MAX_TEXT_CONVERSION_ULONG64];

    RtlSecureZeroMemory(&szText, sizeof(szText));

    lpItem1 = supGetItemText2(
        ListView,
        (INT)lParam1,
        (INT)lParamSort,
        szText,
        MAX_TEXT_CONVERSION_ULONG64);

    ad1 = hextoul(&lpItem1[2]);

    RtlSecureZeroMemory(&szText, sizeof(szText));

    lpItem2 = supGetItemText2(
        ListView,
        (INT)lParam2,
        (INT)lParamSort,
        szText,
        MAX_TEXT_CONVERSION_ULONG64);

    ad2 = hextoul(&lpItem2[2]);

    if (Inverse)
        nResult = ad1 < ad2;
    else
        nResult = ad1 > ad2;

    return nResult;
}

/*
* supGetMaxOfTwoU64FromHex
*
* Purpose:
*
* Returned value used in listview comparer functions.
*
*/
INT supGetMaxOfTwoU64FromHex(
    _In_ HWND ListView,
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort,
    _In_ BOOL Inverse
)
{
    INT       nResult;
    LPWSTR    lpItem1 = NULL, lpItem2 = NULL;
    ULONG_PTR ad1, ad2;
    WCHAR     szText[MAX_TEXT_CONVERSION_ULONG64];

    RtlSecureZeroMemory(&szText, sizeof(szText));

    lpItem1 = supGetItemText2(
        ListView,
        (INT)lParam1,
        (INT)lParamSort,
        szText,
        MAX_TEXT_CONVERSION_ULONG64);

    ad1 = hextou64(&lpItem1[2]);

    RtlSecureZeroMemory(&szText, sizeof(szText));

    lpItem2 = supGetItemText2(
        ListView,
        (INT)lParam2,
        (INT)lParamSort,
        szText,
        MAX_TEXT_CONVERSION_ULONG64);

    ad2 = hextou64(&lpItem2[2]);

    if (Inverse)
        nResult = ad1 < ad2;
    else
        nResult = ad1 > ad2;

    return nResult;
}

/*
* supGetMaxOfTwoLongFromString
*
* Purpose:
*
* Returned value used in listview comparer functions.
*
*/
INT supGetMaxOfTwoLongFromString(
    _In_ HWND ListView,
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort,
    _In_ BOOL Inverse
)
{
    INT       nResult;
    LPWSTR    lpItem1 = NULL, lpItem2 = NULL;
    LONG_PTR  value1, value2;
    WCHAR     szText[MAX_TEXT_CONVERSION_ULONG64];

    RtlSecureZeroMemory(&szText, sizeof(szText));

    lpItem1 = supGetItemText2(
        ListView,
        (INT)lParam1,
        (INT)lParamSort,
        szText,
        MAX_TEXT_CONVERSION_ULONG64);

    value1 = strtoi64(lpItem1);

    RtlSecureZeroMemory(&szText, sizeof(szText));

    lpItem2 = supGetItemText2(
        ListView,
        (INT)lParam2,
        (INT)lParamSort,
        szText,
        MAX_TEXT_CONVERSION_ULONG64);

    value2 = strtoi64(lpItem2);

    if (Inverse)
        nResult = value1 < value2;
    else
        nResult = value1 > value2;

    return nResult;
}

/*
* supGetMaxOfTwoULongFromString
*
* Purpose:
*
* Returned value used in listview comparer functions.
*
*/
INT supGetMaxOfTwoULongFromString(
    _In_ HWND ListView,
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort,
    _In_ BOOL Inverse
)
{
    INT       nResult;
    LPWSTR    lpItem1 = NULL, lpItem2 = NULL;
    ULONG_PTR value1, value2;
    WCHAR     szText[MAX_TEXT_CONVERSION_ULONG64];

    RtlSecureZeroMemory(&szText, sizeof(szText));

    lpItem1 = supGetItemText2(
        ListView,
        (INT)lParam1,
        (INT)lParamSort,
        szText,
        MAX_TEXT_CONVERSION_ULONG64);

    value1 = strtou64(lpItem1);

    RtlSecureZeroMemory(&szText, sizeof(szText));

    lpItem2 = supGetItemText2(
        ListView,
        (INT)lParam2,
        (INT)lParamSort,
        szText,
        MAX_TEXT_CONVERSION_ULONG64);

    value2 = strtou64(lpItem2);

    if (Inverse)
        nResult = value1 < value2;
    else
        nResult = value1 > value2;

    return nResult;
}

/*
* supGetMaxCompareTwoFixedStrings
*
* Purpose:
*
* Returned value used in listview comparer functions.
*
*/
INT supGetMaxCompareTwoFixedStrings(
    _In_ HWND ListView,
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort,
    _In_ BOOL Inverse
)
{
    INT       nResult;
    LPWSTR    lpItem1 = NULL, lpItem2 = NULL, FirstToCompare, SecondToCompare;
    WCHAR     szString1[MAX_PATH + 1], szString2[MAX_PATH + 1];

    szString1[0] = 0;

    lpItem1 = supGetItemText2(
        ListView,
        (INT)lParam1,
        (INT)lParamSort,
        szString1,
        MAX_PATH);

    szString2[0] = 0;

    lpItem2 = supGetItemText2(
        ListView,
        (INT)lParam2,
        (INT)lParamSort,
        szString2,
        MAX_PATH);

    if (Inverse) {
        FirstToCompare = lpItem2;
        SecondToCompare = lpItem1;
    }
    else {
        FirstToCompare = lpItem1;
        SecondToCompare = lpItem2;
    }

    nResult = _strcmpi(FirstToCompare, SecondToCompare);

    return nResult;
}

/*
* supListViewBaseComparer
*
* Purpose:
*
* Base comparer for listviews.
*
*/
INT supListViewBaseComparer(
    _In_ HWND ListViewHandle,
    _In_ BOOL InverseSort,
    _In_ LPARAM FirstItem,
    _In_ LPARAM SecondItem,
    _In_ LPARAM ColumnToSort
)
{
    INT    nResult = 0;
    LPWSTR lpItem1 = NULL, lpItem2 = NULL, FirstToCompare, SecondToCompare;

    lpItem1 = supGetItemText(ListViewHandle, (INT)FirstItem, (INT)ColumnToSort, NULL);
    lpItem2 = supGetItemText(ListViewHandle, (INT)SecondItem, (INT)ColumnToSort, NULL);

    if ((lpItem1 == NULL) && (lpItem2 == NULL)) {
        nResult = 0;
        goto Done;
    }
    if ((lpItem1 == NULL) && (lpItem2 != NULL)) {
        nResult = (InverseSort) ? 1 : -1;
        goto Done;
    }
    if ((lpItem2 == NULL) && (lpItem1 != NULL)) {
        nResult = (InverseSort) ? -1 : 1;
        goto Done;
    }

    if (InverseSort) {
        FirstToCompare = lpItem2;
        SecondToCompare = lpItem1;
    }
    else {
        FirstToCompare = lpItem1;
        SecondToCompare = lpItem2;
    }

    nResult = _strcmpi(FirstToCompare, SecondToCompare);

Done:
    if (lpItem1) supHeapFree(lpItem1);
    if (lpItem2) supHeapFree(lpItem2);
    return nResult;
}

/*
* supOpenLinkedToken
*
* Purpose:
*
* Query token linked token handle.
*
*/
NTSTATUS supOpenLinkedToken(
    _In_ HANDLE TokenHandle,
    _Out_ PHANDLE LinkedTokenHandle
)
{
    ULONG rLen;
    NTSTATUS ntStatus;
    TOKEN_LINKED_TOKEN linkedToken;

    ntStatus = NtQueryInformationToken(
        TokenHandle,
        TokenLinkedToken,
        &linkedToken,
        sizeof(TOKEN_LINKED_TOKEN),
        &rLen);

    *LinkedTokenHandle = linkedToken.LinkedToken;

    return ntStatus;
}

/*
* supOpenTokenByParam
*
* Purpose:
*
* Open token handle with given desired access for process/thread.
*
*/
NTSTATUS supOpenTokenByParam(
    _In_ CLIENT_ID* ClientId,
    _In_ OBJECT_ATTRIBUTES* ObjectAttributes,
    _In_ ACCESS_MASK TokenDesiredAccess,
    _In_ BOOL IsThreadToken,
    _Out_ PHANDLE TokenHandle)
{
    NTSTATUS Status = STATUS_ACCESS_DENIED;
    HANDLE TokenOwnerHandle = NULL, ObjectHandle = NULL;

    *TokenHandle = NULL;

    if (IsThreadToken) {

        Status = NtOpenThread(&TokenOwnerHandle,
            THREAD_QUERY_INFORMATION,
            ObjectAttributes,
            ClientId);
        if (NT_SUCCESS(Status)) {
            Status = NtOpenThreadToken(TokenOwnerHandle, TokenDesiredAccess, FALSE, &ObjectHandle);
            NtClose(TokenOwnerHandle);
        }

    }
    else {

        Status = supOpenProcess(ClientId->UniqueProcess,
            PROCESS_QUERY_INFORMATION,
            &TokenOwnerHandle);
        if (NT_SUCCESS(Status)) {
            Status = NtOpenProcessToken(TokenOwnerHandle, TokenDesiredAccess, &ObjectHandle);
            NtClose(TokenOwnerHandle);
        }
    }

    *TokenHandle = ObjectHandle;

    return Status;
}

/*
* supOpenDeviceObject
*
* Purpose:
*
* Open handle for device object (NtOpenFile).
*
*/
NTSTATUS supOpenDeviceObject(
    _Out_ PHANDLE ObjectHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
)
{
    IO_STATUS_BLOCK iost;

    return NtOpenFile(ObjectHandle,
        DesiredAccess,
        ObjectAttributes,
        &iost,
        FILE_SHARE_VALID_FLAGS,
        0);
}

/*
* supOpenDeviceObjectEx
*
* Purpose:
*
* Open handle for device object (NtCreateFile).
*
*/
NTSTATUS supOpenDeviceObjectEx(
    _Out_ PHANDLE ObjectHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
)
{
    IO_STATUS_BLOCK iost;

    return NtCreateFile(ObjectHandle,
        DesiredAccess,
        ObjectAttributes,
        &iost,
        NULL,
        0,
        FILE_SHARE_VALID_FLAGS,
        FILE_OPEN,
        0,
        NULL,
        0);
}

BOOL supxCanOpenObjectType(
    _In_ UINT nTypeIndex
)
{
    UINT SupportedNamedTypes[] = {
        ObjectTypeDirectory,
        ObjectTypeDevice,
        ObjectTypeEvent,
        ObjectTypeEventPair,
        ObjectTypeIoCompletion,
        ObjectTypeJob,
        ObjectTypeKey,
        ObjectTypeKeyedEvent,
        ObjectTypeMutant,
        ObjectTypeMemoryPartition,
        ObjectTypePort,
        ObjectTypeRegistryTransaction,
        ObjectTypeSemaphore,
        ObjectTypeTimer,
        ObjectTypeSymbolicLink,
        ObjectTypeSection,
        ObjectTypeSession
    };

    UINT i;
    for (i = 0; i < RTL_NUMBER_OF(SupportedNamedTypes); i++) {
        if (SupportedNamedTypes[i] == nTypeIndex)
            return TRUE;
    }

    return FALSE;
}

/*
* supOpenNamedObjectByType
*
* Purpose:
*
* Open object of supported type and return handle to it.
*
* Supported types are list in SupportedNamedTypes array.
*
*/
NTSTATUS supOpenNamedObjectByType(
    _Out_ HANDLE* ObjectHandle,
    _In_ ULONG TypeIndex,
    _In_ PUNICODE_STRING ObjectDirectory,
    _In_ PUNICODE_STRING ObjectName,
    _In_ ACCESS_MASK DesiredAccess
)
{
    HANDLE rootHandle = NULL, objectHandle = NULL;
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    PNTOBJECTOPENPROCEDURE ObjectOpenProcedure = NULL;

    UNICODE_STRING portName;
    OBJECT_ATTRIBUTES obja;

    *ObjectHandle = NULL;

    if (ObjectDirectory == NULL)
        return STATUS_INVALID_PARAMETER_3;

    if (ObjectName == NULL)
        return STATUS_INVALID_PARAMETER_4;

    if (!supxCanOpenObjectType(TypeIndex))
        return STATUS_NOT_SUPPORTED;

    //
    // Special ALPC port case.
    //
    if (TypeIndex == ObjectTypePort) {

        RtlInitEmptyUnicodeString(&portName, NULL, 0);
        if (supCreateObjectPathFromElements(ObjectName,
            ObjectDirectory,
            &portName,
            TRUE))
        {
            //
            // Open port by name.
            //
            ntStatus = supOpenPortObjectByName(ObjectHandle,
                DesiredAccess,
                &portName);

            supHeapFree(portName.Buffer);
        }

        return ntStatus;
    }

    //
    // Handle directory type.
    //
    if (TypeIndex == ObjectTypeDirectory) {

        //
        // If this is root, then root rootHandle = NULL.
        //
        if (!supIsRootDirectory(ObjectName)) {
            //
            // Otherwise open directory that keep this object.
            //
            ntStatus = supOpenDirectoryEx(&rootHandle, NULL, ObjectDirectory, DIRECTORY_QUERY);
            if (!NT_SUCCESS(ntStatus))
                return ntStatus;
        }

        //
        // Open object in directory.
        //
        ntStatus = supOpenDirectoryEx(&objectHandle, rootHandle, ObjectName, DesiredAccess);

        if (rootHandle)
            NtClose(rootHandle);

        *ObjectHandle = objectHandle;
        return ntStatus;
    }

    //
    // Open directory which object belongs.
    //
    ntStatus = supOpenDirectoryEx(&rootHandle, NULL, ObjectDirectory, DIRECTORY_QUERY);
    if (!NT_SUCCESS(ntStatus)) {
        return ntStatus;
    }

    //
    // Select open object procedure.
    //
    switch (TypeIndex) {
    case ObjectTypeDevice:
        ObjectOpenProcedure = (PNTOBJECTOPENPROCEDURE)supOpenDeviceObject;
        break;

    case ObjectTypeMutant:
        ObjectOpenProcedure = (PNTOBJECTOPENPROCEDURE)NtOpenMutant;
        break;

    case ObjectTypeKey:
        ObjectOpenProcedure = (PNTOBJECTOPENPROCEDURE)NtOpenKey;
        break;

    case ObjectTypeSemaphore:
        ObjectOpenProcedure = (PNTOBJECTOPENPROCEDURE)NtOpenSemaphore;
        break;

    case ObjectTypeTimer:
        ObjectOpenProcedure = (PNTOBJECTOPENPROCEDURE)NtOpenTimer;
        break;

    case ObjectTypeEvent:
        ObjectOpenProcedure = (PNTOBJECTOPENPROCEDURE)NtOpenEvent;
        break;

    case ObjectTypeEventPair:
        ObjectOpenProcedure = (PNTOBJECTOPENPROCEDURE)NtOpenEventPair;
        break;

    case ObjectTypeKeyedEvent:
        ObjectOpenProcedure = (PNTOBJECTOPENPROCEDURE)NtOpenKeyedEvent;
        break;

    case ObjectTypeSymbolicLink:
        ObjectOpenProcedure = (PNTOBJECTOPENPROCEDURE)NtOpenSymbolicLinkObject;
        break;

    case ObjectTypeIoCompletion:
        ObjectOpenProcedure = (PNTOBJECTOPENPROCEDURE)NtOpenIoCompletion;
        break;

    case ObjectTypeSection:
        ObjectOpenProcedure = (PNTOBJECTOPENPROCEDURE)NtOpenSection;
        break;

    case ObjectTypeJob:
        ObjectOpenProcedure = (PNTOBJECTOPENPROCEDURE)NtOpenJobObject;
        break;

    case ObjectTypeSession:
        ObjectOpenProcedure = (PNTOBJECTOPENPROCEDURE)NtOpenSession;
        break;

    case ObjectTypeMemoryPartition:
        if (g_ExtApiSet.NtOpenPartition) {
            ObjectOpenProcedure = (PNTOBJECTOPENPROCEDURE)g_ExtApiSet.NtOpenPartition;
        }
        break;
    case ObjectTypeRegistryTransaction:
        if (g_ExtApiSet.NtOpenRegistryTransaction) {
            ObjectOpenProcedure = (PNTOBJECTOPENPROCEDURE)g_ExtApiSet.NtOpenRegistryTransaction;
        }
        break;
    default:
        ObjectOpenProcedure = NULL;
        break;
    }

    if (ObjectOpenProcedure == NULL) {

        ntStatus = STATUS_PROCEDURE_NOT_FOUND;

    }
    else {

        //
        // Open object of the given type.
        //
        InitializeObjectAttributes(&obja, ObjectName, OBJ_CASE_INSENSITIVE, rootHandle, NULL);

        ntStatus = ObjectOpenProcedure(
            &objectHandle,
            DesiredAccess,
            &obja);

        if (NT_SUCCESS(ntStatus))
            *ObjectHandle = objectHandle;
    }

    NtClose(rootHandle);

    return ntStatus;
}

/*
* supEnumHandleDump
*
* Purpose:
*
* Execute callback over each handle dump entry.
*
* Return TRUE if enumeration callback stops enumeration.
*
*/
BOOL supEnumHandleDump(
    _In_ PSYSTEM_HANDLE_INFORMATION_EX HandleDump,
    _In_ PENUMERATE_HANDLE_DUMP_CALLBACK EnumCallback,
    _In_ PVOID UserContext
)
{
    ULONG_PTR i;

    for (i = 0; i < HandleDump->NumberOfHandles; i++) {
        if (EnumCallback(&HandleDump->Handles[i],
            UserContext))
        {
            return TRUE;
        }
    }

    return FALSE;
}

/*
* supxEnumAlpcPortsCallback
*
* Purpose:
*
* Port handles enumeration callback.
*
*/
BOOL supxEnumAlpcPortsCallback(
    _In_ SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* HandleEntry,
    _In_opt_ PVOID UserContext)
{
    BOOL        fSelfProcess = FALSE, fAlloc = FALSE, bStopEnum = FALSE;
    ULONG       bufferSize = 4096;
    ULONG       returnedLength = 0;
    NTSTATUS    ntStatus;
    HANDLE      objectHandle = NULL, processHandle = NULL;
    BYTE        buffer[4096], * pBuffer = (PBYTE)&buffer;

    PALPCPORT_ENUM_CONTEXT enumContext = (PALPCPORT_ENUM_CONTEXT)UserContext;
    PUNICODE_STRING pusObjectName;

    do {

        if (enumContext == NULL)
            break;

        //
        // Not an ALPC port, skip.
        //
        if (HandleEntry->ObjectTypeIndex != enumContext->AlpcPortTypeIndex)
            break;

        //
        // Not our handle, open process.
        //
        if (HandleEntry->UniqueProcessId != GetCurrentProcessId()) {

            ntStatus = supOpenProcessEx((HANDLE)HandleEntry->UniqueProcessId,
                PROCESS_DUP_HANDLE,
                &processHandle);

            if (!NT_SUCCESS(ntStatus))
                break;

        }
        else {
            //
            // Our handle.
            //
            processHandle = NtCurrentProcess();
            fSelfProcess = TRUE;
        }

        //
        // Duplicate handle.
        //
        ntStatus = NtDuplicateObject(processHandle,
            (HANDLE)HandleEntry->HandleValue,
            NtCurrentProcess(),
            &objectHandle,
            STANDARD_RIGHTS_ALL,
            0,
            0);

        if (!fSelfProcess)
            NtClose(processHandle);

        if (!NT_SUCCESS(ntStatus))
            break;

        //
        // Query object name, static buffer used for performance.
        //
        ntStatus = NtQueryObject(objectHandle,
            ObjectNameInformation,
            pBuffer,
            bufferSize,
            &returnedLength);

        if (ntStatus == STATUS_INFO_LENGTH_MISMATCH) {

            pBuffer = (PBYTE)supHeapAlloc((SIZE_T)returnedLength);
            if (pBuffer) {

                fAlloc = TRUE;

                ntStatus = NtQueryObject(objectHandle,
                    ObjectNameInformation,
                    pBuffer,
                    returnedLength,
                    &returnedLength);

            }

        }

        if (NT_SUCCESS(ntStatus)) {

            pusObjectName = (PUNICODE_STRING)pBuffer;
            if (pusObjectName->Buffer && pusObjectName->Length) {

                if (RtlEqualUnicodeString(enumContext->ObjectName, pusObjectName, TRUE)) {
                    enumContext->ObjectHandle = objectHandle;
                    bStopEnum = TRUE;
                    break;
                }
            }

        }

        NtClose(objectHandle);

    } while (FALSE);

    if (fAlloc && pBuffer)
        supHeapFree(pBuffer);


    //
    // Do not stop enumeration until condition.
    //
    return bStopEnum;
}

/*
* supOpenPortObjectByName
*
* Purpose:
*
* Open handle for ALPC port object type with handle duplication.
*
* NOTE:
* Windows only gives you handle to the port in two cases:
*
* 1. When you create it (NtCreatePort and similar);
* 2. When you connect to the specified port.
*
*/
NTSTATUS supOpenPortObjectByName(
    _Out_ PHANDLE ObjectHandle,
    _In_ ACCESS_MASK DesiredAccess,
     _In_ PUNICODE_STRING ObjectName
)
{
    USHORT alpcPortTypeIndex;
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    PSYSTEM_HANDLE_INFORMATION_EX pHandles = NULL;
    ALPCPORT_ENUM_CONTEXT enumContext;

    if (ObjectHandle)
        *ObjectHandle = NULL;

    do {

        //
        // Allocate handle dump.
        //
        pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation,
            NULL);
        if (pHandles == NULL) {
            ntStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        //
        // Query AlpcPort type index.
        //
        alpcPortTypeIndex = kdGetAlpcPortTypeIndex();
        if (alpcPortTypeIndex == MAXWORD) {
            ntStatus = STATUS_PORT_UNREACHABLE;
            break;
        }

        //
        // Walk handle table looking for our named port.
        //
        enumContext.AlpcPortTypeIndex = alpcPortTypeIndex;
        enumContext.ObjectName = ObjectName;
        enumContext.ObjectHandle = NULL;

        if (supEnumHandleDump(pHandles,
            supxEnumAlpcPortsCallback,
            &enumContext))
        {
            if (enumContext.ObjectHandle) {

                //
                // Duplicate copy with requested desired access.
                //
                ntStatus = NtDuplicateObject(NtCurrentProcess(),
                    enumContext.ObjectHandle,
                    NtCurrentProcess(),
                    ObjectHandle,
                    DesiredAccess,
                    0,
                    0);

                NtClose(enumContext.ObjectHandle);

            }
            else {
                ntStatus = STATUS_INVALID_HANDLE;
            }
        }
        else {
            ntStatus = STATUS_PORT_CONNECTION_REFUSED;
        }

    } while (FALSE);

    if (pHandles)
        supHeapFree(pHandles);

    return ntStatus;
}

/*
* supOpenPortObjectFromContext
*
* Purpose:
*
* Open handle for ALPC port object type.
*
*/
NTSTATUS supOpenPortObjectFromContext(
    _Out_ PHANDLE ObjectHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PROP_OBJECT_INFO* Context
)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

    UNICODE_STRING portName;

    *ObjectHandle = NULL;

    RtlInitEmptyUnicodeString(&portName, NULL, 0);
    if (supCreateObjectPathFromElements(
        &Context->NtObjectName,
        &Context->NtObjectPath,
        &portName,
        TRUE))
    {
        ntStatus = supOpenPortObjectByName(ObjectHandle,
            DesiredAccess,
            &portName);

        supHeapFree(portName.Buffer);
    }
    else {
        ntStatus = STATUS_INSUFFICIENT_RESOURCES;
    }

    return ntStatus;
}

/*
* supOpenObjectFromContext
*
* Purpose:
*
* Return handle (query rights) for the given named object.
*
*/
HANDLE supOpenObjectFromContext(
    _In_ PROP_OBJECT_INFO* Context,
    _In_ OBJECT_ATTRIBUTES* ObjectAttributes,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ NTSTATUS* Status
)
{
    HANDLE hObject = NULL, hPrivateNamespace = NULL;
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES objaNamespace;

    if (Context->ContextType == propPrivateNamespace) {

        //
        // Open private namespace.
        //
        InitializeObjectAttributes(&objaNamespace, NULL, OBJ_CASE_INSENSITIVE, NULL, NULL);

        ntStatus = NtOpenPrivateNamespace(
            &hPrivateNamespace,
            MAXIMUM_ALLOWED,
            &objaNamespace,
            Context->u1.NamespaceInfo.BoundaryDescriptor);

        if (!NT_SUCCESS(ntStatus)) {
            *Status = ntStatus;
            return NULL;
        }

        //
        // Modify OBJECT_ATTRIBUTES RootDirectory.
        //
        ObjectAttributes->RootDirectory = hPrivateNamespace;
    }

    //
    // Open object of common type.
    //

    switch (Context->ObjectTypeIndex) {

    case ObjectTypeProcess:

        if (Context->ContextType == propUnnamed) {

            ntStatus = supOpenProcessEx(
                Context->u1.UnnamedObjectInfo.ClientId.UniqueProcess,
                PROCESS_ALL_ACCESS,
                &hObject);

        }
        else
            ntStatus = STATUS_INVALID_PARAMETER;

        break;

    case ObjectTypeThread:

        if (Context->ContextType == propUnnamed) {

            ntStatus = NtOpenThread(
                &hObject,
                DesiredAccess,
                ObjectAttributes,
                &Context->u1.UnnamedObjectInfo.ClientId);

        }
        else
            ntStatus = STATUS_INVALID_PARAMETER;

        break;

    case ObjectTypeToken:

        if (Context->ContextType == propUnnamed) {

            ntStatus = supOpenTokenByParam(
                &Context->u1.UnnamedObjectInfo.ClientId,
                ObjectAttributes,
                DesiredAccess,
                Context->u1.UnnamedObjectInfo.IsThreadToken,
                &hObject);

        }
        else
            ntStatus = STATUS_INVALID_PARAMETER;

        break;

    case ObjectTypeDevice:

        ntStatus = supOpenDeviceObjectEx(
            &hObject,
            DesiredAccess,
            ObjectAttributes);

        break;

    case ObjectTypeMutant:

        ntStatus = NtOpenMutant(
            &hObject,
            DesiredAccess,
            ObjectAttributes);

        break;

    case ObjectTypeKey:

        ntStatus = NtOpenKey(
            &hObject,
            DesiredAccess,
            ObjectAttributes);

        break;

    case ObjectTypeSemaphore:

        ntStatus = NtOpenSemaphore(
            &hObject,
            DesiredAccess,
            ObjectAttributes);

        break;

    case ObjectTypeTimer:

        ntStatus = NtOpenTimer(
            &hObject,
            DesiredAccess,
            ObjectAttributes);

        break;

    case ObjectTypeEvent:

        ntStatus = NtOpenEvent(
            &hObject,
            DesiredAccess,
            ObjectAttributes);

        break;

    case ObjectTypeEventPair:

        ntStatus = NtOpenEventPair(
            &hObject,
            DesiredAccess,
            ObjectAttributes);

        break;

    case ObjectTypeSymbolicLink:

        ntStatus = NtOpenSymbolicLinkObject(
            &hObject,
            DesiredAccess,
            ObjectAttributes);

        break;

    case ObjectTypeIoCompletion:

        ntStatus = NtOpenIoCompletion(
            &hObject,
            DesiredAccess,
            ObjectAttributes);

        break;

    case ObjectTypeSection:

        ntStatus = NtOpenSection(
            &hObject,
            DesiredAccess,
            ObjectAttributes);

        break;

    case ObjectTypeJob:

        ntStatus = NtOpenJobObject(
            &hObject,
            DesiredAccess,
            ObjectAttributes);

        break;

    case ObjectTypeSession:

        ntStatus = NtOpenSession(
            &hObject,
            DesiredAccess,
            ObjectAttributes);

        break;

    case ObjectTypeMemoryPartition:

        if (g_ExtApiSet.NtOpenPartition) {

            ntStatus = g_ExtApiSet.NtOpenPartition(
                &hObject,
                DesiredAccess,
                ObjectAttributes);

        }
        else
            ntStatus = STATUS_PROCEDURE_NOT_FOUND;

        break;

    case ObjectTypePort:

        ntStatus = supOpenPortObjectFromContext(
            &hObject,
            DesiredAccess,
            Context);

        break;

    case ObjectTypeRegistryTransaction:

        if (g_ExtApiSet.NtOpenRegistryTransaction) {

            ntStatus = g_ExtApiSet.NtOpenRegistryTransaction(
                &hObject,
                DesiredAccess,
                ObjectAttributes);
        }
        else
            ntStatus = STATUS_PROCEDURE_NOT_FOUND;

        break;

    default:
        ntStatus = STATUS_OBJECTID_NOT_FOUND;
        break;
    }

    *Status = ntStatus;

    if (hPrivateNamespace) NtClose(hPrivateNamespace);

    return hObject;
}

/*
* supCloseObjectFromContext
*
* Purpose:
*
* Close handle opened with propOpenCurrentObject.
*
*/
BOOL supCloseObjectFromContext(
    _In_ PROP_OBJECT_INFO* Context,
    _In_ HANDLE hObject
)
{
    BOOL bResult = FALSE;

    if (Context == NULL) {
        if (hObject != NULL)
            bResult = NT_SUCCESS(NtClose(hObject));
        return bResult;
    }

    else {

        switch (Context->ObjectTypeIndex) {
        case ObjectTypeWinstation:
            bResult = CloseWindowStation((HWINSTA)hObject);
            break;
        case ObjectTypeDesktop:
            bResult = CloseDesktop((HDESK)hObject);
            break;
        default:
            bResult = NT_SUCCESS(NtClose(hObject));
            break;
        }
    }

    return bResult;
}

/*
* supShowError
*
* Purpose:
*
* Display detailed last error to user.
*
*/
VOID supShowLastError(
    _In_ HWND hWnd,
    _In_ LPCWSTR Source,
    _In_ DWORD LastError
)
{
    LPWSTR lpMsgBuf = NULL;

    if (FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        LastError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&lpMsgBuf,
        0,
        NULL))
    {
        MessageBox(hWnd, lpMsgBuf, Source, MB_TOPMOST | MB_ICONERROR);
        LocalFree(lpMsgBuf);
    }
}

/*
* supShowNtStatus
*
* Purpose:
*
* Display detailed last nt status to user.
*
*/
VOID supShowNtStatus(
    _In_ HWND hWnd,
    _In_ LPCWSTR lpText,
    _In_ NTSTATUS Status
)
{
    PWCHAR lpMsg;
    SIZE_T Length = _strlen(lpText);
    lpMsg = (PWCHAR)supHeapAlloc(Length + 100);
    if (lpMsg) {
        _strcpy(lpMsg, lpText);
        ultohex((ULONG)Status, _strend(lpMsg));
        MessageBox(hWnd, lpMsg, PROGRAM_NAME, MB_ICONERROR);
        supHeapFree(lpMsg);
    }
    else {
        kdDebugPrint("Memory allocation failure\r\n");
    }
}

/*
* supFormatNtError
*
* Purpose:
*
* Format details about NT error to be displayed later.
*
* Uppon success use LocalFree on returned buffer.
*
*/
LPWSTR supFormatNtError(
    _In_ NTSTATUS NtError
)
{
    LPWSTR lpMessage = NULL;

    FormatMessage(
        FORMAT_MESSAGE_FROM_HMODULE |
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        (LPCVOID)GetModuleHandle(L"ntdll.dll"),
        NtError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&lpMessage,
        0,
        NULL);

    return lpMessage;
}

/*
* supBSearch
*
* Purpose:
*
* Binary search, https://github.com/torvalds/linux/blob/master/lib/bsearch.c
*
*/
PVOID supBSearch(
    _In_ PCVOID key,
    _In_ PCVOID base,
    _In_ SIZE_T num,
    _In_ SIZE_T size,
    _In_ int(*cmp)(
        _In_ PCVOID key,
        _In_ PCVOID elt
        )
)
{
    const char* pivot;
    int result;

    while (num > 0) {
        pivot = (char*)base + (num >> 1) * size;
        result = cmp(key, pivot);

        if (result == 0)
            return (void*)pivot;

        if (result > 0) {
            base = pivot + size;
            num--;
        }
        num >>= 1;
    }

    return NULL;
}

/*
* supGetProcessMitigationPolicy
*
* Purpose:
*
* Request process mitigation policy values.
*
*/
_Success_(return != FALSE)
BOOL supGetProcessMitigationPolicy(
    _In_ HANDLE hProcess,
    _In_ PROCESS_MITIGATION_POLICY Policy,
    _In_ SIZE_T Size,
    _Out_writes_bytes_(Size) PVOID Buffer
)
{
    ULONG Length = 0;
    PROCESS_MITIGATION_POLICY_RAW_DATA MitigationPolicy;

    if (Size == sizeof(DWORD)) {

        MitigationPolicy.Policy = (PROCESS_MITIGATION_POLICY)Policy;

        if (NT_SUCCESS(NtQueryInformationProcess(
            hProcess,
            ProcessMitigationPolicy,
            &MitigationPolicy,
            sizeof(PROCESS_MITIGATION_POLICY_RAW_DATA),
            &Length)))
        {
            RtlCopyMemory(Buffer, &MitigationPolicy.Value, Size);
            return TRUE;
        }

    }

    return FALSE;
}

/*
* supGetProcessDepState
*
* Purpose:
*
* Query DEP state for process from ProcessExecuteFlags.
*
*/
_Success_(return != FALSE)
BOOL supGetProcessDepState(
    _In_ HANDLE hProcess,
    _Out_ PPROCESS_MITIGATION_DEP_POLICY DepPolicy
)
{
    ULONG ExecuteFlags = 0;

    if (NT_SUCCESS(NtQueryInformationProcess(
        hProcess,
        ProcessExecuteFlags,
        (PVOID)&ExecuteFlags,
        sizeof(ULONG),
        NULL)))
    {
        if (ExecuteFlags & MEM_EXECUTE_OPTION_ENABLE)
            DepPolicy->Enable = 0;
        else
            DepPolicy->Enable = 1;

        if (ExecuteFlags & MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION)
            DepPolicy->DisableAtlThunkEmulation = 1;
        else
            DepPolicy->DisableAtlThunkEmulation = 0;

        if (ExecuteFlags & MEM_EXECUTE_OPTION_PERMANENT)
            DepPolicy->Permanent = 1;
        else
            DepPolicy->Permanent = 0;

        return TRUE;
    }

    return FALSE;
}

/*
* supDeviceIoControlProcExp
*
* Purpose:
*
* Send request to Process Explorer driver.
*
*/
NTSTATUS supDeviceIoControlProcExp(
    _In_ ULONG IoControlCode,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength
)
{
    NTSTATUS status;
    HANDLE deviceHandle = NULL;

    UNICODE_STRING usDevName = RTL_CONSTANT_STRING(T_DEVICE_PROCEXP152);
    OBJECT_ATTRIBUTES obja;
    IO_STATUS_BLOCK iost;

    if (g_kdctx.IsFullAdmin == FALSE)
        return STATUS_ACCESS_DENIED;

    InitializeObjectAttributes(&obja, &usDevName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateFile(
        &deviceHandle,
        GENERIC_READ | GENERIC_WRITE,
        &obja,
        &iost,
        NULL,
        0,
        0,
        FILE_OPEN,
        0,
        NULL,
        0);

    if (NT_SUCCESS(status)) {

        status = NtDeviceIoControlFile(
            deviceHandle,
            NULL,
            NULL,
            NULL,
            &iost,
            IoControlCode,
            InputBuffer,
            InputBufferLength,
            OutputBuffer,
            OutputBufferLength);

        NtClose(deviceHandle);
    }
    return status;
}

/*
* supOpenProcessEx
*
* Purpose:
*
* Open process via SysInternals Process Explorer driver.
*
* Desired access: PROCESS_ALL_ACCESS
*
*/
NTSTATUS supOpenProcessEx(
    _In_ HANDLE UniqueProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle
)
{
    NTSTATUS status;
    HANDLE processHandle = NULL;

    *ProcessHandle = NULL;

    status = supDeviceIoControlProcExp(
        (ULONG)IOCTL_PE_OPEN_PROCESS,
        (PVOID)&UniqueProcessId,
        sizeof(UniqueProcessId),
        (PVOID)&processHandle,
        sizeof(processHandle));

    if (!NT_SUCCESS(status)) {
        status = supOpenProcess(UniqueProcessId,
            DesiredAccess,
            &processHandle);
    }

    *ProcessHandle = processHandle;
    return status;
}

/*
* supOpenProcessTokenEx
*
* Purpose:
*
* Open process token via SysInternals Process Explorer driver.
*
* Desired access: TOKEN_QUERY
*
*/
NTSTATUS supOpenProcessTokenEx(
    _In_ HANDLE ProcessHandle,
    _Out_ PHANDLE TokenHandle
)
{
    NTSTATUS status;
    HANDLE tokenHandle = NULL;

    *TokenHandle = NULL;

    status = supDeviceIoControlProcExp(
        (ULONG)IOCTL_PE_OPEN_PROCESS_TOKEN,
        (PVOID)&ProcessHandle,
        sizeof(ProcessHandle),
        (PVOID)&tokenHandle,
        sizeof(tokenHandle));

    if (NT_SUCCESS(status))
        *TokenHandle = tokenHandle;

    return status;
}

/*
* supPrintTimeToBuffer
*
* Purpose:
*
* Print  time to string buffer.
*
*/
INT supPrintTimeToBuffer(
    _In_ PLARGE_INTEGER Time,
    _In_ WCHAR* lpszBuffer,
    _In_ SIZE_T cchBuffer
)
{
    TIME_FIELDS TimeFields = { 0, 0, 0, 0, 0, 0, 0, 0 };

    RtlTimeToTimeFields(Time, &TimeFields);

    return RtlStringCchPrintfSecure(lpszBuffer,
        cchBuffer,
        FORMAT_TIME_VALUE_MS,
        TimeFields.Hour,
        TimeFields.Minute,
        TimeFields.Second,
        TimeFields.Milliseconds);
}

/*
* supPrintTimeConverted
*
* Purpose:
*
* Print local converted time to string buffer.
*
*/
BOOL supPrintTimeConverted(
    _In_ PLARGE_INTEGER Time,
    _In_ WCHAR * lpszBuffer,
    _In_ SIZE_T cchBuffer
)
{
    FILETIME ConvertedTime = { 0, 0 };
    TIME_FIELDS TimeFields = { 0, 0, 0, 0, 0, 0, 0, 0 };
    LPCWSTR lpszMonths[12] = {
        L"Jan",
        L"Feb",
        L"Mar",
        L"Apr",
        L"May",
        L"Jun",
        L"Jul",
        L"Aug",
        L"Sep",
        L"Oct",
        L"Nov",
        L"Dec"
    };

    if (FileTimeToLocalFileTime((PFILETIME)Time, (PFILETIME)&ConvertedTime)) {
        RtlTimeToTimeFields((PLARGE_INTEGER)&ConvertedTime, (PTIME_FIELDS)&TimeFields);

        if (TimeFields.Month - 1 < 0) TimeFields.Month = 1;
        if (TimeFields.Month > 12) TimeFields.Month = 12;

        RtlStringCchPrintfSecure(
            lpszBuffer,
            cchBuffer,
            FORMAT_TIME_DATE_VALUE,
            TimeFields.Hour,
            TimeFields.Minute,
            TimeFields.Second,
            TimeFields.Day,
            lpszMonths[TimeFields.Month - 1],
            TimeFields.Year);

        return TRUE;
    }

    return FALSE;
}

/*
* supGetTreeViewItemParam
*
* Purpose:
*
* Return TreeView item associated parameter.
*
*/
_Success_(return)
BOOL supGetTreeViewItemParam(
    _In_ HWND hwndTreeView,
    _In_ HTREEITEM hTreeItem,
    _Out_ PVOID* outParam
)
{
    TV_ITEM tvi;

    RtlSecureZeroMemory(&tvi, sizeof(TV_ITEM));

    tvi.mask = TVIF_PARAM;
    tvi.hItem = hTreeItem;
    if (!TreeView_GetItem(hwndTreeView, &tvi))
        return FALSE;

    *outParam = (PVOID)tvi.lParam;

    return TRUE;
}

/*
* supGetListViewItemParam
*
* Purpose:
*
* Return ListView item associated parameter.
*
*/
_Success_(return)
BOOL supGetListViewItemParam(
    _In_ HWND hwndListView,
    _In_ INT itemIndex,
    _Out_ PVOID * outParam
)
{
    LVITEM lvItem;

    lvItem.mask = LVIF_PARAM;
    lvItem.iItem = itemIndex;
    lvItem.iSubItem = 0;
    lvItem.lParam = 0;

    if (!ListView_GetItem(hwndListView, &lvItem))
        return FALSE;

    *outParam = (PVOID)lvItem.lParam;

    return TRUE;
}

/*
* supSetMinMaxTrackSize
*
* Purpose:
*
* WM_GETMINMAXINFO handler for dialogs.
*
*/
VOID supSetMinMaxTrackSize(
    _In_ PMINMAXINFO MinMaxInfo,
    _In_ INT MinX,
    _In_ INT MinY,
    _In_ BOOL Scaled
)
{
    if (Scaled) {
        MinMaxInfo->ptMinTrackSize.x = SCALE_DPI_VALUE(MinX, g_WinObj.CurrentDPI);
        MinMaxInfo->ptMinTrackSize.y = SCALE_DPI_VALUE(MinY, g_WinObj.CurrentDPI);
    }
    else {
        MinMaxInfo->ptMinTrackSize.x = MinX;
        MinMaxInfo->ptMinTrackSize.y = MinY;
    }
}

/*
* supGetSidNameUse
*
* Purpose:
*
* Translate SidNameUse to string name.
*
*/
LPWSTR supGetSidNameUse(
    _In_ SID_NAME_USE SidNameUse
)
{
    ULONG nameUse = (ULONG)SidNameUse;

    switch (nameUse) {
    case sidTypeUser:
        return L"User";
    case sidTypeGroup:
        return L"Group";
    case sidTypeDomain:
        return L"Domain";
    case sidTypeAlias:
        return L"Alias";
    case sidTypeWellKnownGroup:
        return L"WellKnownGroup";
    case sidTypeDeletedAccount:
        return L"DeletedAccount";
    case sidTypeInvalid:
        return L"Invalid";
    case sidTypeComputer:
        return L"Computer";
    case sidTypeLogonSession:
        return L"LogonSession";
    case sidTypeLabel:
        return L"Label";
    case sidTypeUnknown:
    default:
        return T_Unknown;
    }
}

/*
* supIntegrityToString
*
* Purpose:
*
* Translate integrity level to string name.
*
*/
LPWSTR supIntegrityToString(
    _In_ DWORD IntegrityLevel
)
{
    LPWSTR lpValue = L"Unknown";

    if (IntegrityLevel == SECURITY_MANDATORY_UNTRUSTED_RID) {
        lpValue = L"Untrusted";
    }
    else if (IntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
        lpValue = L"Low";
    }
    else if (IntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
        IntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
    {
        if (IntegrityLevel == SECURITY_MANDATORY_MEDIUM_PLUS_RID)
            lpValue = L"MediumPlus";
        else
            lpValue = L"Medium";
    }
    else if (IntegrityLevel >= SECURITY_MANDATORY_HIGH_RID &&
        IntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
    {
        lpValue = L"High";
    }
    else if (IntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID &&
        IntegrityLevel < SECURITY_MANDATORY_PROTECTED_PROCESS_RID)
    {
        lpValue = L"System";
    }
    else if (IntegrityLevel >= SECURITY_MANDATORY_PROTECTED_PROCESS_RID)
    {
        lpValue = L"ProtectedProcess";
    }

    return lpValue;
}

/*
* supLookupSidUserAndDomainEx
*
* Purpose:
*
* Query user and domain name from given sid and policy handle.
*
*/
BOOL supLookupSidUserAndDomainEx(
    _In_ PSID Sid,
    _In_ LSA_HANDLE PolicyHandle,
    _Out_ LPWSTR* lpSidUserAndDomain
)
{
    BOOL bResult = FALSE;
    NTSTATUS Status;
    ULONG Length;
    LPWSTR UserAndDomainName = NULL, P;
    PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains = NULL;
    PLSA_TRANSLATED_NAME Names = NULL;

    *lpSidUserAndDomain = NULL;

    Status = LsaLookupSids(
        PolicyHandle,
        1,
        (PSID*)&Sid,
        (PLSA_REFERENCED_DOMAIN_LIST*)&ReferencedDomains,
        (PLSA_TRANSLATED_NAME*)&Names);

    if ((NT_SUCCESS(Status)) && (Status != STATUS_SOME_NOT_MAPPED)) {

        Length = 0;

        if ((ReferencedDomains != NULL) && (Names != NULL)) {

            Length = 4 + ReferencedDomains->Domains[0].Name.MaximumLength +
                Names->Name.MaximumLength;

            UserAndDomainName = (LPWSTR)supHeapAlloc(Length);
            if (UserAndDomainName) {
                P = UserAndDomainName;
                if (ReferencedDomains->Domains[0].Name.Length) {
                    RtlCopyMemory(UserAndDomainName,
                        ReferencedDomains->Domains[0].Name.Buffer,
                        ReferencedDomains->Domains[0].Name.Length);

                    P = _strcat(UserAndDomainName, TEXT("\\"));
                }

                RtlCopyMemory(P,
                    Names->Name.Buffer,
                    Names->Name.Length);

                *lpSidUserAndDomain = UserAndDomainName;
                bResult = TRUE;
            }
        }
        if (ReferencedDomains) LsaFreeMemory(ReferencedDomains);
        if (Names) LsaFreeMemory(Names);
    }

    return bResult;
}

/*
* supLookupSidUserAndDomain
*
* Purpose:
*
* Query user and domain name from given sid.
*
*/
BOOL supLookupSidUserAndDomain(
    _In_ PSID Sid,
    _Out_ LPWSTR * lpSidUserAndDomain
)
{
    BOOL bResult = FALSE;
    LSA_HANDLE PolicyHandle = NULL;

    *lpSidUserAndDomain = NULL;

    if (NT_SUCCESS(supLsaOpenMachinePolicy(POLICY_LOOKUP_NAMES,
        &PolicyHandle)))
    {
        bResult = supLookupSidUserAndDomainEx(Sid,
            PolicyHandle,
            lpSidUserAndDomain);

        LsaClose(PolicyHandle);
    }

    return bResult;
}

/*
* supLsaOpenMachinePolicy
*
* Purpose:
*
* Open local machine policy.
*
*/
NTSTATUS supLsaOpenMachinePolicy(
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PLSA_HANDLE PolicyHandle
)
{
    LSA_OBJECT_ATTRIBUTES lobja;
    SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;

    SecurityQualityOfService.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
    SecurityQualityOfService.ImpersonationLevel = SecurityImpersonation;
    SecurityQualityOfService.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    SecurityQualityOfService.EffectiveOnly = FALSE;

    InitializeObjectAttributes(
        &lobja,
        NULL,
        0L,
        NULL,
        NULL);

    lobja.SecurityQualityOfService = &SecurityQualityOfService;

    return LsaOpenPolicy(
        NULL,
        (PLSA_OBJECT_ATTRIBUTES)&lobja,
        DesiredAccess,
        PolicyHandle);
}

/*
* supxHandlesLookupCallback
*
* Purpose:
*
* qsort, bsearch callback.
*
*/
int __cdecl supxHandlesLookupCallback(
    void const* first,
    void const* second
)
{
    int i;
    PSUP_HANDLE_DUMP_ENTRY elem1 = (PSUP_HANDLE_DUMP_ENTRY)first;
    PSUP_HANDLE_DUMP_ENTRY elem2 = (PSUP_HANDLE_DUMP_ENTRY)second;

    if (elem1->HandleValue == elem2->HandleValue)
        i = 0;
    else
        if (elem1->HandleValue < elem2->HandleValue)
            i = -1;
        else
            i = 1;

    return i;
}

/*
* supxHandlesLookupCallback2
*
* Purpose:
*
* qsort, bsearch callback.
*
*/
int __cdecl supxHandlesLookupCallback2(
    void const* first,
    void const* second
)
{
    int i;
    PSUP_HANDLE_DUMP_ENTRY elem1 = (PSUP_HANDLE_DUMP_ENTRY)first;
    PSUP_HANDLE_DUMP_ENTRY elem2 = (PSUP_HANDLE_DUMP_ENTRY)second;
    
    ULONG_PTR FirstObject = (ULONG_PTR)elem1->Object;
    ULONG_PTR SecondObject = (ULONG_PTR)elem2->Object;

    if (FirstObject == SecondObject)
        i = 0;
    else
        if (FirstObject < SecondObject)
            i = -1;
        else
            i = 1;

    return i;
}

/*
* supHandlesCreateFilteredAndSortedList
*
* Purpose:
*
* Create sorted handles list of given process.
*
* Use supHeapFree to release allocated memory.
*
*/
PSUP_HANDLE_DUMP supHandlesCreateFilteredAndSortedList(
    _In_ ULONG_PTR FilterUniqueProcessId,
    _In_ BOOLEAN fObject
)
{
    PSYSTEM_HANDLE_INFORMATION_EX handleDump;
    PSUP_HANDLE_DUMP resultSnapshot;
    ULONG_PTR i, cLast = 0;

    ULONG returnLength = 0;
    SIZE_T stBufferSize;

    handleDump = (PSYSTEM_HANDLE_INFORMATION_EX)ntsupGetSystemInfoEx(
        SystemExtendedHandleInformation,
        &returnLength,
        (PNTSUPMEMALLOC)supHeapAlloc,
        (PNTSUPMEMFREE)supHeapFree);

    if (handleDump == NULL)
        return NULL;

    stBufferSize = sizeof(SUP_HANDLE_DUMP) +
        handleDump->NumberOfHandles * sizeof(PSUP_HANDLE_DUMP_ENTRY);

    resultSnapshot = (PSUP_HANDLE_DUMP)supHeapAlloc(stBufferSize);

    if (resultSnapshot) {
        for (i = 0; i < handleDump->NumberOfHandles; i++) {
            if (handleDump->Handles[i].UniqueProcessId == FilterUniqueProcessId) {
                resultSnapshot->Handles[cLast].Object = handleDump->Handles[i].Object;
                resultSnapshot->Handles[cLast].HandleValue = handleDump->Handles[i].HandleValue;
                cLast++;
            }
        }

        resultSnapshot->NumberOfHandles = cLast;

        RtlQuickSort((PVOID)&resultSnapshot->Handles,
            resultSnapshot->NumberOfHandles,
            sizeof(SUP_HANDLE_DUMP_ENTRY),
            (fObject) ? supxHandlesLookupCallback2 : supxHandlesLookupCallback);
    }

    supHeapFree(handleDump);

    return resultSnapshot;
}

/*
* supHandlesQueryObjectAddress
*
* Purpose:
*
* Find object address for given handle.
*
*/
BOOL supHandlesQueryObjectAddress(
    _In_ PSUP_HANDLE_DUMP SortedHandleList,
    _In_ HANDLE ObjectHandle,
    _Out_ PULONG_PTR ObjectAddress
)
{
    SUP_HANDLE_DUMP_ENTRY* SearchResult, SearchEntry;

    SearchEntry.HandleValue = (ULONG_PTR)ObjectHandle;

    SearchResult = (PSUP_HANDLE_DUMP_ENTRY)supBSearch(
        (PCVOID)&SearchEntry,
        SortedHandleList->Handles,
        SortedHandleList->NumberOfHandles,
        sizeof(SUP_HANDLE_DUMP_ENTRY),
        supxHandlesLookupCallback);

    if (SearchResult) {
        *ObjectAddress = (ULONG_PTR)SearchResult->Object;
        return TRUE;
    }

    *ObjectAddress = 0;
    return FALSE;
}

/*
* supPHLGetEntry
*
* Purpose:
*
* Return handle from handle list by process id.
*
*/
HANDLE supPHLGetEntry(
    _In_ PLIST_ENTRY ListHead,
    _In_ HANDLE UniqueProcessId
)
{
    PLIST_ENTRY Next, Head = ListHead;
    PHL_ENTRY* Item;

    if (!IsListEmpty(Head)) {
        Next = Head->Flink;
        while ((Next != NULL) && (Next != Head)) {
            Item = CONTAINING_RECORD(Next, PHL_ENTRY, ListEntry);
            if (Item->UniqueProcessId == UniqueProcessId)
                return Item->ProcessHandle;
            Next = Next->Flink;
        }
    }
    return NULL;
}

/*
* supPHLFree
*
* Purpose:
*
* Free list of handles.
*
*/
VOID supPHLFree(
    _In_ PLIST_ENTRY ListHead,
    _In_ BOOLEAN fClose
)
{
    PLIST_ENTRY Entry, NextEntry;
    PHL_ENTRY* Item;

    if (IsListEmpty(ListHead))
        return;

    for (Entry = ListHead->Flink, NextEntry = Entry->Flink;
        Entry != ListHead;
        Entry = NextEntry, NextEntry = Entry->Flink)
    {
        Item = CONTAINING_RECORD(Entry, PHL_ENTRY, ListEntry);
        RemoveEntryList(Entry);
        if (fClose) {
            if (Item->ProcessHandle)
                NtClose(Item->ProcessHandle);
        }
        supHeapFree(Item);
    }

}

/*
* supPHLCreate
*
* Purpose:
*
* Create simple handle list of running processes.
*
*/
BOOL supPHLCreate(
    _Inout_ PLIST_ENTRY ListHead,
    _In_ PBYTE ProcessList,
    _Out_ PULONG NumberOfProcesses,
    _Out_ PULONG NumberOfThreads
)
{
    ULONG NextEntryDelta = 0;
    ULONG numberOfThreads = 0, numberOfProcesses = 0;
    PHL_ENTRY* PsListItem;
    union {
        PSYSTEM_PROCESS_INFORMATION ProcessEntry;
        PBYTE ListRef;
    } List;

    List.ListRef = ProcessList;

    do {

        List.ListRef += NextEntryDelta;

        numberOfThreads += List.ProcessEntry->ThreadCount;
        numberOfProcesses += 1;
        NextEntryDelta = List.ProcessEntry->NextEntryDelta;

        PsListItem = (PHL_ENTRY*)supHeapAlloc(sizeof(PHL_ENTRY));
        if (PsListItem) {

            PsListItem->UniqueProcessId = List.ProcessEntry->UniqueProcessId;
            PsListItem->DataPtr = (PVOID)List.ProcessEntry;

            if (List.ProcessEntry->ThreadCount) {

                supOpenProcess(
                    List.ProcessEntry->UniqueProcessId,
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    &PsListItem->ProcessHandle);

            }

            InsertHeadList(ListHead, &PsListItem->ListEntry);

        }

    } while (NextEntryDelta);

    *NumberOfThreads = numberOfThreads;
    *NumberOfProcesses = numberOfProcesses;

    return ((numberOfProcesses > 0) && (numberOfThreads > 0));
}

/*
* supxEnumerateSLCacheValueDescriptors
*
* Purpose:
*
* Walk each SL cache value descriptor entry, validate it and run optional callback.
*
*/
NTSTATUS supxEnumerateSLCacheValueDescriptors(
    _In_ SL_KMEM_CACHE * Cache,
    _In_opt_ PENUMERATE_SL_CACHE_VALUE_DESCRIPTORS_CALLBACK Callback,
    _In_opt_ PVOID Context
)
{
    ULONG_PTR CurrentPosition, MaxPosition;
    SL_KMEM_CACHE_VALUE_DESCRIPTOR* CacheDescriptor;

    __try {

        if (Cache->TotalSize < sizeof(SL_KMEM_CACHE))
            return STATUS_INVALID_PARAMETER;

        if (Cache->Version != 1)
            return STATUS_INVALID_PARAMETER;

        MaxPosition = (ULONG_PTR)RtlOffsetToPointer(Cache, Cache->TotalSize);
        if (MaxPosition < (ULONG_PTR)Cache)
            return STATUS_INVALID_PARAMETER;

        CacheDescriptor = (SL_KMEM_CACHE_VALUE_DESCRIPTOR*)&Cache->Descriptors;
        CurrentPosition = (ULONG_PTR)CacheDescriptor;
        MaxPosition = (ULONG_PTR)RtlOffsetToPointer(CacheDescriptor, Cache->SizeOfData);

    }
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
        return GetExceptionCode();
    }

    do {
        __try {
            if ((CacheDescriptor->NameLength >= CacheDescriptor->Size) ||
                (CacheDescriptor->DataLength >= CacheDescriptor->Size))
            {
                return STATUS_INTERNAL_ERROR;
            }
        }
        __except (WOBJ_EXCEPTION_FILTER_LOG) {
            return GetExceptionCode();
        }

        if (Callback) {
            if (Callback(CacheDescriptor, Context))
                break;
        }

        __try {

            CurrentPosition += CacheDescriptor->Size;
            if (CurrentPosition >= MaxPosition)
                break;

            CacheDescriptor = (SL_KMEM_CACHE_VALUE_DESCRIPTOR*)RtlOffsetToPointer(CacheDescriptor, CacheDescriptor->Size);
        }
        __except (WOBJ_EXCEPTION_FILTER_LOG) {
            return GetExceptionCode();
        }

    } while (TRUE);

    return STATUS_SUCCESS;
}

/*
* supSLCacheRead
*
* Purpose:
*
* Read software licensing cache.
*
* N.B.
*
* Use supHeapFree to release allocated memory.
*
*/
PVOID supSLCacheRead(
    VOID)
{
    NTSTATUS Status;
    ULONG DataLength = 0;
    PVOID ReturnData = NULL;
    HANDLE KeyHandle = NULL;
    UNICODE_STRING ProductPolicyValue = RTL_CONSTANT_STRING(L"ProductPolicy");
    UNICODE_STRING ProductOptionsKey = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\System\\CurrentControlSet\\Control\\ProductOptions");
    OBJECT_ATTRIBUTES ObjectAttributes;

    KEY_VALUE_PARTIAL_INFORMATION* PolicyData;

    InitializeObjectAttributes(&ObjectAttributes, &ProductOptionsKey, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
        return NULL;

    Status = NtQueryValueKey(KeyHandle, &ProductPolicyValue,
        KeyValuePartialInformation, NULL, 0, &DataLength);

    if (Status == STATUS_BUFFER_TOO_SMALL) {
        PolicyData = (KEY_VALUE_PARTIAL_INFORMATION*)supHeapAlloc(DataLength + sizeof(KEY_VALUE_PARTIAL_INFORMATION));
        if (PolicyData) {

            Status = NtQueryValueKey(KeyHandle, 
                &ProductPolicyValue,
                KeyValuePartialInformation, 
                PolicyData, 
                DataLength, 
                &DataLength);

            if (NT_SUCCESS(Status) && (PolicyData->Type == REG_BINARY)) {
                ReturnData = PolicyData;
            }
            else {
                supHeapFree(PolicyData);
            }
        }
    }
    NtClose(KeyHandle);

    return ReturnData;
}

/*
* supSLCacheEnumerate
*
* Purpose:
*
* Enumerate SL value descriptors and run optional callback.
*
*/
BOOLEAN supSLCacheEnumerate(
    _In_ PVOID CacheData,
    _In_opt_ PENUMERATE_SL_CACHE_VALUE_DESCRIPTORS_CALLBACK Callback,
    _In_opt_ PVOID Context)
{
    SL_KMEM_CACHE* Cache;

    Cache = (SL_KMEM_CACHE*)((KEY_VALUE_PARTIAL_INFORMATION*)(CacheData))->Data;

    return NT_SUCCESS(supxEnumerateSLCacheValueDescriptors(
        Cache,
        Callback,
        Context));
}

/*
* supxGetShellViewForDesktop
*
* Purpose:
*
* Use the shell view for the desktop using the shell windows automation to find the
* desktop web browser and then grabs its view.
*
* N.B. Taken entirely from Windows SDK sample.
*
*/
HRESULT supxGetShellViewForDesktop(
    REFIID riid,
    void** ppv
)
{
    IShellWindows* psw;
    HRESULT hr;
    HWND hwnd;
    IDispatch* pdisp;
    IShellBrowser* psb;
    VARIANT vtEmpty;
    IShellView* psv;

    *ppv = NULL;

#ifdef __cplusplus

    hr = CoCreateInstance(CLSID_ShellWindows, NULL, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&psw));
    if (SUCCEEDED(hr))
    {
        VariantInit(&vtEmpty);

        if (S_OK == psw->FindWindowSW(&vtEmpty, &vtEmpty, SWC_DESKTOP, (long*)(LONG_PTR)&hwnd, SWFO_NEEDDISPATCH, &pdisp))
        {
            hr = IUnknown_QueryService(pdisp, SID_STopLevelBrowser, IID_PPV_ARGS(&psb));
            if (SUCCEEDED(hr))
            {

                hr = psb->QueryActiveShellView(&psv);
                if (SUCCEEDED(hr))
                {
                    hr = psv->QueryInterface(riid, ppv);
                    psv->Release();
                }
                psb->Release();
            }
            pdisp->Release();
        }
        else
        {
            hr = E_FAIL;
        }
        psw->Release();
    }

#else

    VariantInit(&vtEmpty);

    hr = CoCreateInstance(&CLSID_ShellWindows, NULL, CLSCTX_LOCAL_SERVER, &IID_IShellWindows, &psw);
    if (SUCCEEDED(hr))
    {
        if (S_OK == psw->lpVtbl->FindWindowSW(psw, &vtEmpty, &vtEmpty, SWC_DESKTOP, (long*)(LONG_PTR)&hwnd, SWFO_NEEDDISPATCH, &pdisp))
        {
            hr = IUnknown_QueryService((IUnknown*)pdisp, &SID_STopLevelBrowser, &IID_IShellBrowser, &psb);
            if (SUCCEEDED(hr))
            {
                hr = psb->lpVtbl->QueryActiveShellView(psb, &psv);
                if (SUCCEEDED(hr))
                {
                    hr = psv->lpVtbl->QueryInterface(psv, riid, ppv);
                    psv->lpVtbl->Release(psv);
                }
                psb->lpVtbl->Release(psb);
            }
            pdisp->lpVtbl->Release(pdisp);
        }
        else
        {
            hr = E_FAIL;
        }
        psw->lpVtbl->Release(psw);
    }

#endif
    return hr;
}

/*
* supxGetShellDispatchFromView
*
* Purpose:
*
* From a shell view object gets its automation interface and from that gets the shell
* application object that implements IShellDispatch2 and related interfaces.
*
* N.B. Taken entirely from Windows SDK sample.
*
*/
HRESULT supxGetShellDispatchFromView(IShellView * psv, REFIID riid, void** ppv)
{
    HRESULT hr;
    IDispatch* pdispBackground;
    IShellFolderViewDual* psfvd;
    IDispatch* pdisp;

    *ppv = NULL;

#ifdef __cplusplus

    hr = psv->GetItemObject(SVGIO_BACKGROUND, IID_PPV_ARGS(&pdispBackground));
    if (SUCCEEDED(hr))
    {
        hr = pdispBackground->QueryInterface(IID_PPV_ARGS(&psfvd));
        if (SUCCEEDED(hr))
        {
            hr = psfvd->get_Application(&pdisp);
            if (SUCCEEDED(hr))
            {
                hr = pdisp->QueryInterface(riid, ppv);
                pdisp->Release();
            }
            psfvd->Release();
        }
        pdispBackground->Release();
    }

#else

    hr = psv->lpVtbl->GetItemObject(psv, SVGIO_BACKGROUND, &IID_IDispatch, &pdispBackground);
    if (SUCCEEDED(hr))
    {
        hr = pdispBackground->lpVtbl->QueryInterface(pdispBackground, &IID_IShellFolderViewDual, &psfvd);
        if (SUCCEEDED(hr))
        {
            hr = psfvd->lpVtbl->get_Application(psfvd, &pdisp);
            if (SUCCEEDED(hr))
            {
                hr = pdisp->lpVtbl->QueryInterface(pdisp, riid, ppv);
                pdisp->lpVtbl->Release(pdisp);
            }
            psfvd->lpVtbl->Release(psfvd);
        }
        pdispBackground->lpVtbl->Release(pdispBackground);
    }

#endif
    return hr;
}

/*
* supShellExecInExplorerProcess
*
* Purpose:
*
* Run ShellExecute from Windows Explorer process through shell interfaces
* making it run with IL of Windows Explorer and not WinObjEx64.
*
*/
HRESULT supShellExecInExplorerProcess(
    _In_ PCWSTR pszFile,
    _In_opt_ PCWSTR pszArguments
)
{
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    IShellView* psv;
    IShellDispatch2* psd;
    BSTR bstrFile, bstrArgs = NULL;
    VARIANT vtEmpty, vtArgs;

    if (SUCCEEDED(hr)) {

#ifdef __cplusplus

        hr = supxGetShellViewForDesktop(IID_PPV_ARGS(&psv));
        if (SUCCEEDED(hr))
        {
            hr = supxGetShellDispatchFromView(psv, IID_PPV_ARGS(&psd));
            if (SUCCEEDED(hr))
            {
                bstrFile = SysAllocString(pszFile);
                hr = bstrFile ? S_OK : E_OUTOFMEMORY;
                if (SUCCEEDED(hr))
                {
                    VariantInit(&vtArgs);
                    VariantInit(&vtEmpty);

                    if (pszArguments) {
                        bstrArgs = SysAllocString(pszArguments);
                        hr = bstrArgs ? S_OK : E_OUTOFMEMORY;

                        if (SUCCEEDED(hr)) {
                            vtArgs.vt = VT_BSTR;
                            vtArgs.bstrVal = bstrArgs;

                            hr = psd->ShellExecuteW(bstrFile,
                                vtArgs, vtEmpty, vtEmpty, vtEmpty);

                            SysFreeString(bstrFile);
                        }
                    }
                    else {

                        hr = psd->ShellExecuteW(bstrFile,
                            vtEmpty, vtEmpty, vtEmpty, vtEmpty);

                    }

                }
                psd->Release();
            }
            psv->Release();
        }

#else
        hr = supxGetShellViewForDesktop(&IID_IShellView, &psv);
        if (SUCCEEDED(hr)) {
            hr = supxGetShellDispatchFromView(psv, &IID_IShellDispatch2, &psd);
            if (SUCCEEDED(hr))
            {
                bstrFile = SysAllocString(pszFile);
                hr = bstrFile ? S_OK : E_OUTOFMEMORY;
                if (SUCCEEDED(hr))
                {
                    VariantInit(&vtArgs);
                    VariantInit(&vtEmpty);

                    if (pszArguments) {

                        bstrArgs = SysAllocString(pszArguments);
                        hr = bstrArgs ? S_OK : E_OUTOFMEMORY;

                        if (SUCCEEDED(hr)) {
                            vtArgs.vt = VT_BSTR;
                            vtArgs.bstrVal = bstrArgs;

                            hr = psd->lpVtbl->ShellExecuteW(psd, bstrFile,
                                vtArgs, vtEmpty, vtEmpty, vtEmpty);

                            SysFreeString(bstrArgs);
                        }
                    }
                    else {

                        hr = psd->lpVtbl->ShellExecuteW(psd, bstrFile,
                            vtEmpty, vtEmpty, vtEmpty, vtEmpty);

                    }

                    SysFreeString(bstrFile);
                }

                psd->lpVtbl->Release(psd);
            }
            psv->lpVtbl->Release(psv);
        }
#endif
        CoUninitialize();
    }
    return hr;
}

/*
* supLoadIconForObjectType
*
* Purpose:
*
* Load icon for object (or its type) which properties is currently viewed.
*
*/
BOOLEAN supLoadIconForObjectType(
    _In_ HWND hwndDlg,
    _In_ PROP_OBJECT_INFO * Context,
    _In_ HIMAGELIST ImageList,
    _In_ BOOLEAN IsShadow)
{
    HICON hIcon;
    INT ImageIndex;

    if (IsShadow)
        ImageIndex = Context->ShadowTypeDescription->ImageIndex;
    else
        ImageIndex = Context->TypeDescription->ImageIndex;

    hIcon = ImageList_GetIcon(
        ImageList,
        ImageIndex,
        ILD_NORMAL | ILD_TRANSPARENT);

    if (hIcon) {

        SendDlgItemMessage(hwndDlg, ID_OBJECT_ICON,
            STM_SETIMAGE, IMAGE_ICON, (LPARAM)hIcon);

        if (IsShadow)
            Context->ObjectTypeIcon = hIcon;
        else
            Context->ObjectIcon = hIcon;

        return TRUE;
    }

    return FALSE;
}

/*
* supxDeleteKeyRecursive
*
* Purpose:
*
* Delete key and all it subkeys/values.
*
*/
BOOL supxDeleteKeyRecursive(
    _In_ HKEY hKeyRoot,
    _In_ LPWSTR lpSubKey)
{
    LPWSTR lpEnd;
    LONG lResult;
    DWORD dwSize;
    WCHAR szName[MAX_PATH + 1];
    HKEY hKey;
    FILETIME ftWrite;

    //
    // Attempt to delete key as is.
    //
    lResult = RegDeleteKey(hKeyRoot, lpSubKey);
    if (lResult == ERROR_SUCCESS)
        return TRUE;

    //
    // Try to open key to check if it exist.
    //
    lResult = RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);
    if (lResult != ERROR_SUCCESS) {
        if (lResult == ERROR_FILE_NOT_FOUND)
            return TRUE;
        else
            return FALSE;
    }

    //
    // Add slash to the key path if not present.
    //
    lpEnd = _strend(lpSubKey);
    if (*(lpEnd - 1) != TEXT('\\')) {
        *lpEnd++ = TEXT('\\');
        *lpEnd = TEXT('\0');
    }

    //
    // Enumerate subkeys and call this func for each.
    //
    dwSize = MAX_PATH;
    lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
        NULL, NULL, &ftWrite);

    if (lResult == ERROR_SUCCESS) {

        do {

            _strncpy(lpEnd, MAX_PATH, szName, MAX_PATH);

            if (!supxDeleteKeyRecursive(hKeyRoot, lpSubKey))
                break;

            dwSize = MAX_PATH;

            lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
                NULL, NULL, &ftWrite);

        } while (lResult == ERROR_SUCCESS);
    }

    lpEnd--;
    *lpEnd = TEXT('\0');

    RegCloseKey(hKey);

    //
    // Delete current key, all it subkeys should be already removed.
    //
    lResult = RegDeleteKey(hKeyRoot, lpSubKey);
    if (lResult == ERROR_SUCCESS)
        return TRUE;

    return FALSE;
}

/*
* supRegDeleteKeyRecursive
*
* Purpose:
*
* Delete key and all it subkeys/values.
*
* Remark:
*
* SubKey should not be longer than 260 chars.
*
*/
BOOL supRegDeleteKeyRecursive(
    _In_ HKEY hKeyRoot,
    _In_ LPCWSTR lpSubKey)
{
    WCHAR szKeyName[MAX_PATH * 2];
    RtlSecureZeroMemory(szKeyName, sizeof(szKeyName));
    _strncpy(szKeyName, MAX_PATH * 2, lpSubKey, MAX_PATH);
    return supxDeleteKeyRecursive(hKeyRoot, szKeyName);
}

/*
* supHashString
*
* Purpose:
*
* Create sdbm hash for given string.
*
* N.B. Case sensitive.
*
*/
ULONG supHashString(
    _In_ PCWSTR String,
    _In_ ULONG Length)
{
    ULONG hashValue = 0, nChars = Length;
    PCWSTR stringBuffer = String;

    while (nChars-- != 0)
        hashValue = (hashValue * 65599) + *stringBuffer++;

    return hashValue;
}

/*
* supHashStringAnsi
*
* Purpose:
*
* Create sdbm hash for given string.
*
* N.B. Case sensitive.
*
*/
ULONG supHashStringAnsi(
    _In_ PCSTR String,
    _In_ ULONG Length)
{
    ULONG hashValue = 0, nChars = Length;
    PCSTR stringBuffer = String;

    while (nChars-- != 0)
        hashValue = (hashValue * 65599) + *stringBuffer++;

    return hashValue;
}

/*
* supHashUnicodeString
*
* Purpose:
*
* Create sdbm hash for given UNICODE_STRING.
*
* N.B. Case sensitive.
*
*/
ULONG supHashUnicodeString(
    _In_ CONST UNICODE_STRING * String)
{
    return supHashString(String->Buffer, String->Length / sizeof(WCHAR));
}

/*
* supCreateSystemAdminAccessSD
*
* Purpose:
*
* Create security descriptor with Admin/System ACL set.
*
*/
NTSTATUS supCreateSystemAdminAccessSD(
    _Out_ PSECURITY_DESCRIPTOR* SecurityDescriptor,
    _Out_ PACL* DefaultAcl
)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    ULONG aclSize = 0;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PACL pAcl = NULL;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;

    UCHAR sidBuffer[2 * sizeof(SID)];

    *SecurityDescriptor = NULL;
    *DefaultAcl = NULL;

    do {

        RtlSecureZeroMemory(sidBuffer, sizeof(sidBuffer));

        securityDescriptor = (PSECURITY_DESCRIPTOR)supHeapAlloc(sizeof(SECURITY_DESCRIPTOR));
        if (securityDescriptor == NULL) {
            ntStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        aclSize += RtlLengthRequiredSid(1); //LocalSystem sid
        aclSize += RtlLengthRequiredSid(2); //Admin group sid
        aclSize += sizeof(ACL);
        aclSize += 2 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG));

        pAcl = (PACL)supHeapAlloc(aclSize);
        if (pAcl == NULL) {
            ntStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        ntStatus = RtlCreateAcl(pAcl, aclSize, ACL_REVISION);
        if (!NT_SUCCESS(ntStatus))
            break;

        //
        // Local System - Generic All.
        //
        RtlInitializeSid(sidBuffer, &ntAuthority, 1);
        *(RtlSubAuthoritySid(sidBuffer, 0)) = SECURITY_LOCAL_SYSTEM_RID;
        RtlAddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL, (PSID)sidBuffer);

        //
        // Admins - Generic All.
        //
        RtlInitializeSid(sidBuffer, &ntAuthority, 2);
        *(RtlSubAuthoritySid(sidBuffer, 0)) = SECURITY_BUILTIN_DOMAIN_RID;
        *(RtlSubAuthoritySid(sidBuffer, 1)) = DOMAIN_ALIAS_RID_ADMINS;
        RtlAddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL, (PSID)sidBuffer);

        ntStatus = RtlCreateSecurityDescriptor(securityDescriptor,
            SECURITY_DESCRIPTOR_REVISION1);
        if (!NT_SUCCESS(ntStatus))
            break;

        ntStatus = RtlSetDaclSecurityDescriptor(securityDescriptor,
            TRUE,
            pAcl,
            FALSE);

        if (!NT_SUCCESS(ntStatus))
            break;

        *SecurityDescriptor = securityDescriptor;
        *DefaultAcl = pAcl;

    } while (FALSE);

    if (!NT_SUCCESS(ntStatus)) {

        if (pAcl) supHeapFree(pAcl);

        if (securityDescriptor) {
            supHeapFree(securityDescriptor);
        }

        *SecurityDescriptor = NULL;
        *DefaultAcl = NULL;
    }

    return ntStatus;
}

/*
* supRichEdit32Load
*
* Purpose:
*
* Preload richedit32 library and classes.
*
*/
BOOL supRichEdit32Load()
{
    WCHAR szBuffer[MAX_PATH * 2];
    HMODULE hRichEdit;

    hRichEdit = GetModuleHandle(T_RICHEDIT_LIB);
    if (hRichEdit == NULL) {

        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));

        RtlStringCchPrintfSecure(szBuffer,
            sizeof(szBuffer) / sizeof(szBuffer[0]),
            TEXT("%s\\%s"),
            g_WinObj.szSystemDirectory,
            T_RICHEDIT_LIB);

        hRichEdit = LoadLibraryEx(szBuffer, NULL, 0);
    }

    return (hRichEdit != NULL);
}

/*
* supReportAbnormalTermination
*
* Purpose:
*
* Log abnormal terminations from try/finally blocks.
*
*/
VOID supReportAbnormalTermination(
    _In_ LPCWSTR FunctionName
)
{
    WCHAR szBuffer[512];

    _strcpy(szBuffer, TEXT("AbnormalTermination of "));
    _strcat(szBuffer, FunctionName);

    logAdd(EntryTypeError, szBuffer);
}

/*
* supReportException
*
* Purpose:
*
* Log details about exception.
*
*/
VOID supReportException(
    _In_ ULONG ExceptionCode,
    _In_opt_ PEXCEPTION_POINTERS ExceptionPointers
)
{
    WCHAR szBuffer[512];

    _strcpy(szBuffer, TEXT("Exception 0x"));
    ultohex(ExceptionCode, _strend(szBuffer));

    if (ExceptionPointers) {
        if (ExceptionCode == STATUS_ACCESS_VIOLATION) {
            switch (ExceptionPointers->ExceptionRecord->ExceptionInformation[0]) {
            case 0:
                _strcat(szBuffer, TEXT(", read at address: 0x"));
                break;
            case 1:
                _strcat(szBuffer, TEXT(", write at address: 0x"));
                break;
            }
            u64tohex(ExceptionPointers->ExceptionRecord->ExceptionInformation[1], _strend(szBuffer));
        }
    }

    logAdd(EntryTypeError, szBuffer);
}

/*
* supReportAPIError
*
* Purpose:
*
* Log details about failed API call.
*
*/
VOID supReportAPIError(
    _In_ LPCWSTR FunctionName,
    _In_ NTSTATUS NtStatus
)
{
    WCHAR szBuffer[512];

    RtlStringCchPrintfSecure(szBuffer,
        512,
        TEXT("%ws 0x%lX"),
        FunctionName,
        NtStatus);

    logAdd(EntryTypeError, szBuffer);
}

/*
* supIsFileImageSection
*
* Purpose:
*
* Return TRUE if section attributes include image and file flags.
*
*/
BOOLEAN supIsFileImageSection(
    _In_ ULONG AllocationAttributes)
{
    return ((AllocationAttributes & SEC_IMAGE) && (AllocationAttributes & SEC_FILE));
}

/*
* supIsDriverShimmed
*
* Purpose:
*
* Return TRUE if driver shimmed by KSE.
*
*/
BOOLEAN supIsDriverShimmed(
    _In_ PKSE_ENGINE_DUMP KseEngineDump,
    _In_ PVOID DriverBaseAddress,
    _Out_opt_ GUID* ShimGUID)
{
    PLIST_ENTRY Entry, NextEntry, ListHead;
    KSE_SHIMMED_DRIVER* ShimmedDriver;

    if (ShimGUID)
        *ShimGUID = GUID_NULL;

    if (KseEngineDump->Valid == FALSE)
        return FALSE;

    ListHead = &KseEngineDump->ShimmedDriversDumpListHead;

    ASSERT_LIST_ENTRY_VALID_BOOLEAN(ListHead);

    if (IsListEmpty(ListHead))
        return FALSE;

    for (Entry = ListHead->Flink, NextEntry = Entry->Flink;
        Entry != ListHead;
        Entry = NextEntry, NextEntry = Entry->Flink)
    {
        ShimmedDriver = CONTAINING_RECORD(Entry, KSE_SHIMMED_DRIVER, ListEntry);
        if (DriverBaseAddress == ShimmedDriver->DriverBaseAddress) {
            
            if (ShimGUID) {
                if (ShimmedDriver->ShimGuid)
                    kdReadSystemMemory((ULONG_PTR)ShimmedDriver->ShimGuid,
                    ShimGUID,
                    sizeof(GUID));
            }
            
            return TRUE;
        }
    }

    return FALSE;
}

/*
* supGetDriverShimInformation
*
* Purpose:
*
* Return TRUE if driver shimmed by KSE.
*
*/
SUP_SHIM_INFO* supGetDriverShimInformation(
    _In_ GUID ShimGuid
)
{
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(KsepShimInformation); i++) {
        if (sizeof(GUID) == RtlCompareMemory(
            (PVOID)KsepShimInformation[i].Guid,
            (PVOID)&ShimGuid,
            sizeof(GUID))) return &KsepShimInformation[i];
    }

    return NULL;
}

size_t supxEscStrlen(wchar_t* s)
{
    size_t  result = 2;
    wchar_t* s0 = s;

    while (*s)
    {
        if (*s == L'"')
            ++result;
        ++s;
    }

    return result + (s - s0);
}

wchar_t* supxEscStrcpy(wchar_t* dst, wchar_t* src)
{
    *(dst++) = L'"';

    while ((*dst = *src) != L'\0')
    {
        if (*src == L'"')
            *(++dst) = L'"';

        ++src;
        ++dst;
    }

    *(dst++) = L'"';
    *dst = L'\0';

    return dst;
}

/*
* supxListViewExportCSV
*
* Purpose:
*
* Export listview entries into file in csv format.
*
*/
BOOL supxListViewExportCSV(
    _In_ HWND List,
    _In_ PWCHAR FileName)
{
    HWND            hdr = ListView_GetHeader(List);
    int             pass, i, c, col_count = Header_GetItemCount(hdr), icount = 1 + ListView_GetItemCount(List);
    HDITEM          ih;
    LVITEM          lvi;
    PWCHAR          text, buffer0 = NULL, buffer = NULL;
    BOOL            result = FALSE;
    SIZE_T          total_lenght;
    DWORD           iobytes;
    HANDLE          f;

    text = (PWCHAR)supVirtualAlloc(32768 * sizeof(WCHAR));
    if (!text)
        return FALSE;

    RtlSecureZeroMemory(&ih, sizeof(HDITEM));
    RtlSecureZeroMemory(&lvi, sizeof(LVITEM));

    ih.pszText = lvi.pszText = text;
    ih.cchTextMax = lvi.cchTextMax = 32767;

    for (pass = 0; pass < 2; ++pass)
    {
        total_lenght = 0;

        for (i = 0; i < icount; ++i)
        {
            for (c = 0; c < col_count; ++c)
            {
                text[0] = L'\0';
                if (i == 0)
                {
                    ih.mask = HDI_TEXT | HDI_ORDER;
                    ih.iOrder = c;
                    Header_GetItem(hdr, c, &ih);
                }
                else
                {
                    lvi.mask = LVIF_TEXT;
                    lvi.iItem = i - 1;
                    lvi.iSubItem = c;
                    ListView_GetItem(List, &lvi);
                }
                total_lenght += supxEscStrlen(text) + 1;

                if (buffer)
                {
                    buffer = supxEscStrcpy(buffer, text);
                    if (c != col_count - 1)
                    {
                        *(buffer++) = L',';
                    }
                    else
                    {
                        *(buffer++) = L'\r';
                        *(buffer++) = L'\n';
                    }
                }
            }
            ++total_lenght;
        }

        if (buffer0 == NULL)
        {
            buffer0 = (PWCHAR)supVirtualAlloc((1 + total_lenght) * sizeof(WCHAR));
            if (!buffer0)
                break;
        }
        else
        {
            f = CreateFile(FileName,
                GENERIC_WRITE | SYNCHRONIZE,
                FILE_SHARE_READ,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL);

            if (f != INVALID_HANDLE_VALUE) {

                WriteFile(f, buffer0,
                    (DWORD)(total_lenght * sizeof(WCHAR)),
                    &iobytes, NULL);

                CloseHandle(f);
                result = TRUE;
            }
            supVirtualFree(buffer0);
        }
        buffer = buffer0;
    }

    supVirtualFree(text);
    return result;
}

/*
* supListViewExportToFile
*
* Purpose:
*
* Export listview contents to the specified file.
*
*/
BOOL supListViewExportToFile(
    _In_ LPCWSTR FileName,
    _In_ HWND WindowHandle,
    _In_ HWND ListView
)
{
    BOOL bResult = FALSE;
    WCHAR szExportFileName[MAX_PATH + 1];

    RtlSecureZeroMemory(&szExportFileName, sizeof(szExportFileName));

    _strcpy(szExportFileName, FileName);
    if (supSaveDialogExecute(WindowHandle,
        (LPWSTR)&szExportFileName,
        T_CSV_FILE_FILTER))
    {
        SetCapture(WindowHandle);
        supSetWaitCursor(TRUE);

        bResult = supxListViewExportCSV(ListView, szExportFileName);

        supSetWaitCursor(FALSE);
        ReleaseCapture();
    }

    return bResult;
}

/*
* supStatusBarSetText
*
* Purpose:
*
* Display status in status bar part.
*
*/
VOID supStatusBarSetText(
    _In_ HWND hwndStatusBar,
    _In_ WPARAM partIndex,
    _In_ LPCWSTR lpText
)
{
    SendMessage(hwndStatusBar, SB_SETTEXT, partIndex, (LPARAM)lpText);
}

/*
* supJumpToFileListView
*
* Purpose:
*
* Jump from listview to file on disk.
*
*/
VOID supJumpToFileListView(
    _In_ HWND hwndList,
    _In_ INT iFileNameColumn
)
{
    INT iPos;
    LPWSTR lpDriverName = NULL, lpConvertedName = NULL;
    SIZE_T sz;

    do {

        iPos = ListView_GetNextItem(hwndList, -1, LVNI_SELECTED);
        if (iPos < 0)
            break;

        lpConvertedName = (LPWSTR)supHeapAlloc(UNICODE_STRING_MAX_BYTES);
        if (lpConvertedName == NULL)
            break;

        sz = 0;
        lpDriverName = supGetItemText(hwndList, iPos, iFileNameColumn, &sz);
        if (lpDriverName == NULL)
            break;

        lpConvertedName = supGetWin32FileName(lpDriverName);
        if (lpConvertedName) {
            supJumpToFile(lpConvertedName);
            supHeapFree(lpConvertedName);
        }

    } while (FALSE);

    if (lpDriverName) supHeapFree(lpDriverName);
}

/*
* supQueryAlpcPortObjectTypeIndex
*
* Purpose:
*
* Create dummy WinObjEx ALPC port, remember it object type index and destroy port.
*
*/
VOID supQueryAlpcPortObjectTypeIndex(
    _In_ PVOID PortIndexData
)
{
    PALPCPORT_TYPE_INDEX portIndexData = (PALPCPORT_TYPE_INDEX)PortIndexData;
    NTSTATUS ntStatus;
    HANDLE portHandle = NULL;
    UNICODE_STRING portName = RTL_CONSTANT_STRING(L"\\Rpc Control\\WinObjEx64Port");
    OBJECT_ATTRIBUTES objectAttributes;
    PSYSTEM_HANDLE_INFORMATION_EX pHandles = NULL;

    ULONG sdLength;
    SID_IDENTIFIER_AUTHORITY WorldSidAuthority = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID SeWorldSid = NULL;
    PSID SeRestrictedSid = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL pDacl = NULL;

    do {

        SeWorldSid = supHeapAlloc(RtlLengthRequiredSid(1));
        if (SeWorldSid == NULL)
            break;

        RtlInitializeSid(SeWorldSid, &WorldSidAuthority, 1);
        *(RtlSubAuthoritySid(SeWorldSid, 0)) = SECURITY_WORLD_RID;

        ntStatus = RtlAllocateAndInitializeSid(&NtAuthority,
            1,
            SECURITY_RESTRICTED_CODE_RID,
            0, 0, 0, 0, 0, 0, 0,
            &SeRestrictedSid);

        if (!NT_SUCCESS(ntStatus))
            break;

        sdLength = SECURITY_DESCRIPTOR_MIN_LENGTH +
            (ULONG)sizeof(ACL) +
            (ULONG)(2 * sizeof(ACCESS_ALLOWED_ACE)) +
            RtlLengthSid(SeWorldSid) +
            RtlLengthSid(SeRestrictedSid) +
            8;

        pSD = supHeapAlloc(sdLength);
        if (pSD == NULL)
            break;

        pDacl = (PACL)((PCHAR)pSD + SECURITY_DESCRIPTOR_MIN_LENGTH);

        ntStatus = RtlCreateSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION);
        if (!NT_SUCCESS(ntStatus))
            break;

        ntStatus = RtlCreateAcl(pDacl, (ULONG)(sdLength - SECURITY_DESCRIPTOR_MIN_LENGTH), ACL_REVISION2);
        if (!NT_SUCCESS(ntStatus))
            break;

        ntStatus = RtlAddAccessAllowedAce(pDacl,
            ACL_REVISION2,
            PORT_ALL_ACCESS,
            SeWorldSid);

        if (!NT_SUCCESS(ntStatus))
            break;

        ntStatus = RtlAddAccessAllowedAce(pDacl,
            ACL_REVISION2,
            PORT_ALL_ACCESS,
            SeRestrictedSid);

        if (!NT_SUCCESS(ntStatus))
            break;

        ntStatus = RtlSetDaclSecurityDescriptor(pSD,
            TRUE,
            pDacl,
            FALSE);

        if (!NT_SUCCESS(ntStatus))
            break;

        InitializeObjectAttributes(&objectAttributes, &portName, OBJ_CASE_INSENSITIVE, NULL, pSD);

        ntStatus = NtCreatePort(&portHandle,
            &objectAttributes,
            0,
            sizeof(PORT_MESSAGE),
            0);

        if (NT_SUCCESS(ntStatus)) {

            pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation,
                NULL);
            if (pHandles) {

                //
                // Query ALPC port object type.
                //
                if (supQueryObjectFromHandleEx(pHandles,
                    portHandle,
                    NULL,
                    &portIndexData->TypeIndex))
                {
                    portIndexData->Valid = TRUE;
                }

                supHeapFree(pHandles);
            }

            //
            // Destroy port object.
            //
            NtClose(portHandle);
        }

    } while (FALSE);

    if (SeWorldSid) supHeapFree(SeWorldSid);
    if (SeRestrictedSid) RtlFreeSid(SeRestrictedSid);
    if (pSD) supHeapFree(pSD);

}

/*
* supQueryProcessImageFileNameWin32
*
* Purpose:
*
* Query Win32 process filename.
*
*/
NTSTATUS supQueryProcessImageFileNameWin32(
    _In_ HANDLE UniqueProcessId,
    _Out_ PUNICODE_STRING* ProcessImageFileName
)
{
    NTSTATUS ntStatus;
    HANDLE hProcess = NULL;

    *ProcessImageFileName = NULL;

    ntStatus = supOpenProcess(UniqueProcessId,
        PROCESS_QUERY_LIMITED_INFORMATION,
        &hProcess);

    if (NT_SUCCESS(ntStatus)) {

        ntStatus = supQueryProcessInformation(hProcess,
            ProcessImageFileNameWin32,
            ProcessImageFileName,
            NULL);

        NtClose(hProcess);

    }

    return ntStatus;
}

/*
* supQueryProcessImageFileNameByProcessId
*
* Purpose:
*
* Query process filename by process id in native format.
*
*/
NTSTATUS supQueryProcessImageFileNameByProcessId(
    _In_ HANDLE UniqueProcessId,
    _Out_ PUNICODE_STRING ProcessImageFileName
)
{
    return ntsupQueryProcessImageFileNameByProcessId(UniqueProcessId,
        ProcessImageFileName,
        (PNTSUPMEMALLOC)supHeapAlloc,
        (PNTSUPMEMFREE)supHeapFree);
}

/*
* supGetSidFromAce
*
* Purpose:
*
* Return Sid associated with Ace.
*
*/
PSID supGetSidFromAce(
    _In_ PACE_HEADER AceHeader
)
{
    PACCESS_ALLOWED_OBJECT_ACE paoa = (PACCESS_ALLOWED_OBJECT_ACE)AceHeader;

    if (AceHeader->AceType >= ACCESS_MIN_MS_OBJECT_ACE_TYPE &&
        AceHeader->AceType <= ACCESS_MAX_MS_OBJECT_ACE_TYPE)
    {
        switch (paoa->Flags & (ACE_OBJECT_TYPE_PRESENT | ACE_INHERITED_OBJECT_TYPE_PRESENT)) {
        case 0:
            return &((PACCESS_ALLOWED_OBJECT_ACE)AceHeader)->ObjectType;
        case ACE_OBJECT_TYPE_PRESENT:
        case ACE_INHERITED_OBJECT_TYPE_PRESENT:
            return &((PACCESS_ALLOWED_OBJECT_ACE)AceHeader)->InheritedObjectType;
        default:
            return &((PACCESS_ALLOWED_OBJECT_ACE)AceHeader)->SidStart;
        }
    }

    return &((PACCESS_ALLOWED_ACE)AceHeader)->SidStart;
}

/*
* supHandleContextMenuMsgForListView
*
* Purpose:
*
* WM_CONTEXT handler for dialogs with a listview.
*
*/
VOID supHandleContextMenuMsgForListView(
    _In_ HWND hwndDlg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam,
    _In_ HWND hwndControl,
    _In_ pfnPopupMenuHandler MenuHandler,
    _In_opt_ PVOID lpUserParam
)
{
    INT mark;
    RECT crc;

    if ((HWND)wParam == hwndControl) {

        mark = ListView_GetSelectionMark(hwndControl);

        RtlSecureZeroMemory(&crc, sizeof(crc));
        if (lParam == MAKELPARAM(-1, -1)) {
            ListView_GetItemRect(hwndControl, mark, &crc, TRUE);
            crc.top = crc.bottom;
            ClientToScreen(hwndControl, (LPPOINT)&crc);
        }
        else
            GetCursorPos((LPPOINT)&crc);

        MenuHandler(hwndDlg, (LPPOINT)&crc, lpUserParam);

    }
}

/*
* supAddLVColumnsFromArray
*
* Purpose:
*
* Add columns from array to the listview.
*
*/
ULONG supAddLVColumnsFromArray(
    _In_ HWND ListView,
    _In_ PLVCOLUMNS_DATA ColumnsData,
    _In_ ULONG NumberOfColumns
)
{
    ULONG iColumn;

    for (iColumn = 0; iColumn < NumberOfColumns; iColumn++) {

        if (-1 == supAddListViewColumn(ListView,
            iColumn,
            iColumn,
            iColumn,
            ColumnsData[iColumn].ImageIndex,
            ColumnsData[iColumn].Format,
            ColumnsData[iColumn].Name,
            ColumnsData[iColumn].Width))
        {
            break;
        }
    }

    return iColumn;
}

/*
* supExtractFileName
*
* Purpose:
*
* Return filename part from given path.
*
*/
wchar_t* supExtractFileName(
    _In_ const wchar_t* lpFullPath
)
{
    wchar_t* p = (wchar_t*)lpFullPath;

    if (lpFullPath == 0)
        return 0;

    while (*lpFullPath != (wchar_t)0) {
        if (*lpFullPath == (wchar_t)'\\')
            p = (wchar_t*)lpFullPath + 1;
        lpFullPath++;
    }
    return p;
}

/*
* supObjectDumpHandlePopupMenu
*
* Purpose:
*
* Object dump popup construction
*
*/
VOID supObjectDumpHandlePopupMenu(
    _In_ HWND hwndDlg,
    _In_ HWND hwndTreeList,
    _In_ INT *pSubItemHit,
    _In_ LPARAM lParam
)
{
    POINT pt1;
    HMENU hMenu;

    if (GetCursorPos(&pt1) == FALSE)
        return;

    hMenu = CreatePopupMenu();
    if (hMenu) {

        if (supTreeListAddCopyValueItem(hMenu,
            hwndTreeList,
            ID_OBJECT_COPY,
            0,
            lParam,
            pSubItemHit)) 
        {
            TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, pt1.x, pt1.y, 0, hwndDlg, NULL);
        }
        DestroyMenu(hMenu);
    }
}

/*
* supObDumpShowError
*
* Purpose:
*
* Hide all windows for given hwnd and display error text with custom text if specified.
*
*/
VOID supObDumpShowError(
    _In_ HWND hwndDlg,
    _In_opt_ LPWSTR lpMessageText
)
{
    ENUMCHILDWNDDATA ChildWndData;

    if (GetWindowRect(hwndDlg, &ChildWndData.Rect)) {
        ChildWndData.nCmdShow = SW_HIDE;
        EnumChildWindows(hwndDlg, supCallbackShowChildWindow, (LPARAM)&ChildWndData);
    }

    if (lpMessageText) {
        SetDlgItemText(hwndDlg, ID_OBJECTDUMPERROR, lpMessageText);
    }

    ShowWindow(GetDlgItem(hwndDlg, ID_OBJECTDUMPERROR), SW_SHOW);
}

/*
* supGetFirmwareType
*
* Purpose:
*
* Return firmware type.
*
*/
NTSTATUS supGetFirmwareType(
    _Out_ PFIRMWARE_TYPE FirmwareType
)
{
    NTSTATUS ntStatus;
    ULONG returnLength = 0;
    SYSTEM_BOOT_ENVIRONMENT_INFORMATION sbei;

    *FirmwareType = FirmwareTypeUnknown;

    RtlSecureZeroMemory(&sbei, sizeof(sbei));

    ntStatus = NtQuerySystemInformation(SystemBootEnvironmentInformation,
        &sbei,
        sizeof(sbei),
        &returnLength);

    if (NT_SUCCESS(ntStatus)) {
        *FirmwareType = sbei.FirmwareType;

    }

    return ntStatus;
}

/*
* supIsBootDriveVHD
*
* Purpose:
*
* Query if the current boot drive is VHD type.
*
*/
NTSTATUS supIsBootDriveVHD(
    _Out_ PBOOLEAN IsVHD
)
{
    NTSTATUS ntStatus;
    ULONG returnLength = 0;
    SYSTEM_VHD_BOOT_INFORMATION* psvbi;

    *IsVHD = FALSE;

    psvbi = (SYSTEM_VHD_BOOT_INFORMATION*)supHeapAlloc(PAGE_SIZE);
    if (psvbi) {
        ntStatus = NtQuerySystemInformation(SystemVhdBootInformation, psvbi, PAGE_SIZE, &returnLength);
        if (NT_SUCCESS(ntStatus)) {
            *IsVHD = psvbi->OsDiskIsVhd;
        }
        supHeapFree(psvbi);
    }
    else {
        ntStatus = STATUS_INSUFFICIENT_RESOURCES;
    }

    return ntStatus;
}

/*
* supPathAddBackSlash
*
* Purpose:
*
* Add trailing backslash to the path if it doesn't have one.
*
*/
LPWSTR supPathAddBackSlash(
    _In_ LPWSTR lpszPath
)
{
    SIZE_T nLength;
    LPWSTR lpszEnd, lpszPrev, lpszResult = NULL;

    nLength = _strlen(lpszPath);

    if (nLength) {

        lpszEnd = lpszPath + nLength;

        if (lpszPath == lpszEnd)
            lpszPrev = lpszPath;
        else
            lpszPrev = (LPWSTR)lpszEnd - 1;

        if (*lpszPrev != TEXT('\\')) {
            *lpszEnd++ = TEXT('\\');
            *lpszEnd = TEXT('\0');
        }

        lpszResult = lpszEnd;

    }

    return lpszResult;
}

__inline WCHAR nibbletoh(BYTE c, BOOLEAN upcase)
{
    if (c < 10)
        return L'0' + c;

    c -= 10;

    if (upcase)
        return L'A' + c;

    return L'a' + c;
}

/*
* supPrintHash
*
* Purpose:
*
* Output hash.
* Returned buffer must be freed with supHeapFree when no longer needed.
*
*/
LPWSTR supPrintHash(
    _In_reads_bytes_(Length) LPBYTE Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN UpcaseHex
)
{
    ULONG   c;
    PWCHAR  lpText;
    BYTE    x;

    lpText = (LPWSTR)supHeapAlloc(sizeof(WCHAR) + ((SIZE_T)Length * 2 * sizeof(WCHAR)));
    if (lpText) {

        for (c = 0; c < Length; ++c) {
            x = Buffer[c];

            lpText[c * 2] = nibbletoh(x >> 4, UpcaseHex);
            lpText[c * 2 + 1] = nibbletoh(x & 15, UpcaseHex);
        }
#pragma warning(push)
#pragma warning(disable: 6305)
        lpText[Length * 2] = 0;
#pragma warning(pop)
    }

    return lpText;
}

/*
* supDestroyFileViewInfo
*
* Purpose:
*
* Deallocate file view information resources.
*
*/
VOID supDestroyFileViewInfo(
    _In_ PFILE_VIEW_INFO ViewInformation
)
{
    if (ViewInformation->FileHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(ViewInformation->FileHandle);
        ViewInformation->FileHandle = INVALID_HANDLE_VALUE;
    }
    if (ViewInformation->SectionHandle) {
        NtClose(ViewInformation->SectionHandle);
        ViewInformation->SectionHandle = NULL;
    }
    if (ViewInformation->ViewBase) {
        if (NT_SUCCESS(NtUnmapViewOfSection(NtCurrentProcess(),
            ViewInformation->ViewBase)))
        {
            ViewInformation->ViewBase = NULL;
            ViewInformation->ViewSize = 0;
        }
    }

    ViewInformation->NtHeaders = NULL;
    ViewInformation->FileSize.QuadPart = 0;
}

#define PE_SIGNATURE_SIZE           4
#define RTL_MEG                     (1024UL * 1024UL)
#define RTLP_IMAGE_MAX_DOS_HEADER   (256UL * RTL_MEG)
#define MM_SIZE_OF_LARGEST_IMAGE    ((ULONG)0x77000000)
#define MM_MAXIMUM_IMAGE_HEADER     (2 * PAGE_SIZE)
#define MM_MAXIMUM_IMAGE_SECTIONS                       \
     ((MM_MAXIMUM_IMAGE_HEADER - (PAGE_SIZE + sizeof(IMAGE_NT_HEADERS))) /  \
            sizeof(IMAGE_SECTION_HEADER))

/*
* supxInitializeFileViewInfo
*
* Purpose:
*
* Open file for mapping, create section, remember file size.
*
*/
NTSTATUS supxInitializeFileViewInfo(
    _In_ PFILE_VIEW_INFO ViewInformation
)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    HANDLE fileHandle, sectionHandle = NULL;
    LARGE_INTEGER fileSize;

    fileSize.QuadPart = 0;
    fileHandle = CreateFile(ViewInformation->FileName,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_SUPPORTS_BLOCK_REFCOUNTING | FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (fileHandle != INVALID_HANDLE_VALUE) {

        if (!GetFileSizeEx(fileHandle, &fileSize)) {
            CloseHandle(fileHandle);
            fileHandle = INVALID_HANDLE_VALUE;
            ntStatus = STATUS_FILE_INVALID;
        }
        else {

            ntStatus = NtCreateSection(
                &sectionHandle,
                SECTION_QUERY | SECTION_MAP_READ,
                NULL,
                &fileSize,
                PAGE_READONLY,
                SEC_COMMIT,
                fileHandle);

            if (!NT_SUCCESS(ntStatus)) {
                CloseHandle(fileHandle);
                fileHandle = INVALID_HANDLE_VALUE;
            }

        }

    }
    else {
        ntStatus = STATUS_OBJECT_NAME_NOT_FOUND;
    }

    ViewInformation->Status = StatusOk;
    ViewInformation->FileHandle = fileHandle;
    ViewInformation->FileSize = fileSize;
    ViewInformation->SectionHandle = sectionHandle;

    return ntStatus;
}

/*
* supMapInputFileForRead
*
* Purpose:
*
* Create mapped section from input file.
*
*/
NTSTATUS supMapInputFileForRead(
    _In_ PFILE_VIEW_INFO ViewInformation,
    _In_ BOOLEAN PartialMap
)
{
    NTSTATUS ntStatus;
    SIZE_T viewSize;

    ntStatus = supxInitializeFileViewInfo(ViewInformation);
    if (!NT_SUCCESS(ntStatus))
        return ntStatus;

    if (PartialMap) {

        if (ViewInformation->FileSize.QuadPart < RTL_MEG)
            viewSize = (SIZE_T)ViewInformation->FileSize.QuadPart;
        else
            viewSize = (SIZE_T)RTL_MEG;

    }
    else {

        viewSize = (SIZE_T)ViewInformation->FileSize.QuadPart;

    }

    ntStatus = NtMapViewOfSection(ViewInformation->SectionHandle,
        NtCurrentProcess(),
        &ViewInformation->ViewBase,
        0,
        0,
        NULL,
        &viewSize,
        ViewShare,
        0,
        PAGE_READONLY);

    if (NT_SUCCESS(ntStatus))
        ViewInformation->ViewSize = viewSize;

    return ntStatus;
}

#pragma warning(push)
#pragma warning(disable: 4319)

/*
* supxValidateNtHeader
*
* Purpose:
*
* Common validation for file image header.
*
*/
BOOLEAN supxValidateNtHeader(
    _In_ PIMAGE_NT_HEADERS Header,
    _Out_ PIMAGE_VERIFY_STATUS VerifyStatus
)
{
    INT i;
    ULONG64 lastSectionVA;
    PIMAGE_NT_HEADERS32 pHdr32;
    PIMAGE_NT_HEADERS64 pHdr64;
    PIMAGE_SECTION_HEADER pSection;

    if (Header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {

        pHdr64 = (PIMAGE_NT_HEADERS64)(Header);

        if (((pHdr64->OptionalHeader.FileAlignment & 511) != 0) &&
            (pHdr64->OptionalHeader.FileAlignment != pHdr64->OptionalHeader.SectionAlignment))
        {
            *VerifyStatus = StatusBadFileAlignment;
            return FALSE;
        }

        if (pHdr64->OptionalHeader.FileAlignment == 0) {
            *VerifyStatus = StatusBadFileAlignment;
            return FALSE;
        }

        if (((pHdr64->OptionalHeader.SectionAlignment - 1) &
            pHdr64->OptionalHeader.SectionAlignment) != 0)
        {
            *VerifyStatus = StatusBadSectionAlignment;
            return FALSE;
        }

        if (((pHdr64->OptionalHeader.FileAlignment - 1) &
            pHdr64->OptionalHeader.FileAlignment) != 0)
        {
            *VerifyStatus = StatusBadFileAlignment;
            return FALSE;
        }

        if (pHdr64->OptionalHeader.SectionAlignment < pHdr64->OptionalHeader.FileAlignment) {
            *VerifyStatus = StatusBadSectionAlignment;
            return FALSE;
        }

        if (pHdr64->OptionalHeader.SizeOfImage > MM_SIZE_OF_LARGEST_IMAGE) {
            *VerifyStatus = StatusBadSizeOfImage;
            return FALSE;
        }

        if (pHdr64->FileHeader.NumberOfSections > MM_MAXIMUM_IMAGE_SECTIONS) {
            *VerifyStatus = StatusBadSectionCount;
            return FALSE;
        }

        if (pHdr64->FileHeader.Machine != IMAGE_FILE_MACHINE_IA64 &&
            pHdr64->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        {
            *VerifyStatus = StatusBadFileHeaderMachine;
            return FALSE;
        }

    }
    else if (Header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {

        pHdr32 = (PIMAGE_NT_HEADERS32)(Header);

        if (((pHdr32->OptionalHeader.FileAlignment & 511) != 0) &&
            (pHdr32->OptionalHeader.FileAlignment != pHdr32->OptionalHeader.SectionAlignment))
        {
            *VerifyStatus = StatusBadFileAlignment;
            return FALSE;
        }

        if (pHdr32->OptionalHeader.FileAlignment == 0) {
            *VerifyStatus = StatusBadFileAlignment;
            return FALSE;
        }

        if (((pHdr32->OptionalHeader.SectionAlignment - 1) &
            pHdr32->OptionalHeader.SectionAlignment) != 0)
        {
            *VerifyStatus = StatusBadSectionAlignment;
            return FALSE;
        }

        if (((pHdr32->OptionalHeader.FileAlignment - 1) &
            pHdr32->OptionalHeader.FileAlignment) != 0)
        {
            *VerifyStatus = StatusBadFileAlignment;
            return FALSE;
        }

        if (pHdr32->OptionalHeader.SectionAlignment < pHdr32->OptionalHeader.FileAlignment) {
            *VerifyStatus = StatusBadSectionAlignment;
            return FALSE;
        }

        if (pHdr32->OptionalHeader.SizeOfImage > MM_SIZE_OF_LARGEST_IMAGE) {
            *VerifyStatus = StatusBadSizeOfImage;
            return FALSE;
        }

        if (pHdr32->FileHeader.NumberOfSections > MM_MAXIMUM_IMAGE_SECTIONS) {
            *VerifyStatus = StatusBadSectionCount;
            return FALSE;
        }

        if ((pHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) &&
            !(pHdr32->FileHeader.Machine == IMAGE_FILE_MACHINE_I386))
        {
            *VerifyStatus = StatusBadFileHeaderMachine;
            return FALSE;
        }

    }
    else {
        *VerifyStatus = StatusBadOptionalHeaderMagic;
        return FALSE;
    }

    pSection = IMAGE_FIRST_SECTION(Header);

    lastSectionVA = (ULONG64)pSection->VirtualAddress;

    for (i = 0; i < Header->FileHeader.NumberOfSections; i++, pSection++) {

        if (pSection->VirtualAddress != lastSectionVA) {
            *VerifyStatus = StatusBadNtHeaders;
            return FALSE;
        }

        lastSectionVA += ALIGN_UP_BY(pSection->Misc.VirtualSize,
            Header->OptionalHeader.SectionAlignment);

    }

    if (lastSectionVA != Header->OptionalHeader.SizeOfImage) {
        *VerifyStatus = StatusBadNtHeaders;
        return FALSE;
    }

    *VerifyStatus = StatusOk;
    return TRUE;
}

#pragma warning(pop)

/*
* supIsValidImage
*
* Purpose:
*
* Check whatever image is in valid PE format.
*
*/
BOOLEAN supIsValidImage(
    _In_ PFILE_VIEW_INFO ViewInformation
)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ViewInformation->ViewBase;
    PIMAGE_NT_HEADERS ntHeaders = NULL;

    ViewInformation->Status = StatusUnknownError;

    __try {

        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            ViewInformation->Status = StatusBadDosMagic;
            return FALSE;
        }

        if (dosHeader->e_lfanew == 0 ||
            (ULONG)dosHeader->e_lfanew > ViewInformation->FileSize.LowPart ||
            (((ULONG)dosHeader->e_lfanew + PE_SIGNATURE_SIZE +
                (ULONG)sizeof(IMAGE_FILE_HEADER)) >= ViewInformation->FileSize.LowPart) ||
            dosHeader->e_lfanew >= RTLP_IMAGE_MAX_DOS_HEADER)
        {
            ViewInformation->Status = StatusBadNewExeOffset;
            return FALSE;
        }

        if (((ULONG)dosHeader->e_lfanew +
            sizeof(IMAGE_NT_HEADERS) +
            (16 * sizeof(IMAGE_SECTION_HEADER))) <= (ULONG)dosHeader->e_lfanew)
        {
            ViewInformation->Status = StatusBadNewExeOffset;
            return FALSE;
        }

        ntHeaders = (PIMAGE_NT_HEADERS)((PCHAR)ViewInformation->ViewBase + (ULONG)dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            ViewInformation->Status = StatusBadNtSignature;
            return FALSE;
        }

        if ((ULONG)dosHeader->e_lfanew >= ntHeaders->OptionalHeader.SizeOfImage) {
            ViewInformation->Status = StatusBadNewExeOffset;
            return FALSE;
        }

        if (ntHeaders->FileHeader.SizeOfOptionalHeader == 0 ||
            ntHeaders->FileHeader.SizeOfOptionalHeader & (sizeof(ULONG_PTR) - 1))
        {
            ViewInformation->Status = StatusBadOptionalHeader;
            return FALSE;
        }

        if (!(ntHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
            ViewInformation->Status = StatusBadFileHeaderCharacteristics;
            return FALSE;
        }

        if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 &&
            ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
        {
            ViewInformation->Status = StatusBadFileHeaderMachine;
            return FALSE;
        }

        return supxValidateNtHeader(ntHeaders, &ViewInformation->Status);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ViewInformation->Status = StatusExceptionOccurred;
        return FALSE;
    }
}

/*
* supxCreateDriverEntry
*
* Purpose:
*
* Creating registry entry for driver.
*
*/
NTSTATUS supxCreateDriverEntry(
    _In_opt_ LPCWSTR DriverPath,
    _In_ LPCWSTR KeyName
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD dwData, dwResult;
    HKEY keyHandle = NULL;
    UNICODE_STRING driverImagePath;

    RtlInitEmptyUnicodeString(&driverImagePath, NULL, 0);

    if (DriverPath) {
        if (!RtlDosPathNameToNtPathName_U(DriverPath,
            &driverImagePath,
            NULL,
            NULL))
        {
            return STATUS_INVALID_PARAMETER_2;
        }
    }

    if (ERROR_SUCCESS != RegCreateKeyEx(HKEY_LOCAL_MACHINE,
        KeyName,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS,
        NULL,
        &keyHandle,
        NULL))
    {
        status = STATUS_ACCESS_DENIED;
        goto Cleanup;
    }

    dwResult = ERROR_SUCCESS;

    do {

        dwData = SERVICE_ERROR_NORMAL;
        dwResult = RegSetValueEx(keyHandle,
            TEXT("ErrorControl"),
            0,
            REG_DWORD,
            (BYTE*)&dwData,
            sizeof(dwData));
        if (dwResult != ERROR_SUCCESS)
            break;

        dwData = SERVICE_KERNEL_DRIVER;
        dwResult = RegSetValueEx(keyHandle,
            TEXT("Type"),
            0,
            REG_DWORD,
            (BYTE*)&dwData,
            sizeof(dwData));
        if (dwResult != ERROR_SUCCESS)
            break;

        dwData = SERVICE_DEMAND_START;
        dwResult = RegSetValueEx(keyHandle,
            TEXT("Start"),
            0,
            REG_DWORD,
            (BYTE*)&dwData,
            sizeof(dwData));

        if (dwResult != ERROR_SUCCESS)
            break;

        if (DriverPath) {
            dwResult = RegSetValueEx(keyHandle,
                TEXT("ImagePath"),
                0,
                REG_EXPAND_SZ,
                (BYTE*)driverImagePath.Buffer,
                (DWORD)driverImagePath.Length + sizeof(UNICODE_NULL));
        }

    } while (FALSE);

    RegCloseKey(keyHandle);

    if (dwResult != ERROR_SUCCESS) {
        status = STATUS_ACCESS_DENIED;
    }
    else
    {
        status = STATUS_SUCCESS;
    }

Cleanup:
    if (DriverPath) {
        if (driverImagePath.Buffer) {
            RtlFreeUnicodeString(&driverImagePath);
        }
    }
    return status;
}

/*
* supLoadDriverEx
*
* Purpose:
*
* Install driver and load it.
*
* N.B.
* SE_LOAD_DRIVER_PRIVILEGE is required to be assigned and enabled.
*
*/
NTSTATUS supLoadDriverEx(
    _In_ LPCWSTR DriverName,
    _In_ LPCWSTR DriverPath,
    _In_ BOOLEAN UnloadPreviousInstance,
    _In_opt_ pfnLoadDriverCallback Callback,
    _In_opt_ PVOID CallbackParam
)
{
    SIZE_T keyOffset;
    NTSTATUS status;
    UNICODE_STRING driverServiceName;

    WCHAR szBuffer[MAX_PATH + 1];

    if (DriverName == NULL)
        return STATUS_INVALID_PARAMETER_1;
    if (DriverPath == NULL)
        return STATUS_INVALID_PARAMETER_2;

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

    keyOffset = RTL_NUMBER_OF(NT_REG_PREP);

    if (FAILED(RtlStringCchPrintfSecure(szBuffer, MAX_PATH,
        DRIVER_REGKEY,
        NT_REG_PREP,
        DriverName)))
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    status = supxCreateDriverEntry(DriverPath,
        &szBuffer[keyOffset]);

    if (!NT_SUCCESS(status))
        return status;

    RtlInitUnicodeString(&driverServiceName, szBuffer);

    if (Callback) {
        status = Callback(&driverServiceName, CallbackParam);
        if (!NT_SUCCESS(status))
            return status;
    }

    if (supEnablePrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE)) {

        status = NtLoadDriver(&driverServiceName);

        if (UnloadPreviousInstance) {
            if ((status == STATUS_IMAGE_ALREADY_LOADED) ||
                (status == STATUS_OBJECT_NAME_COLLISION) ||
                (status == STATUS_OBJECT_NAME_EXISTS))
            {
                status = NtUnloadDriver(&driverServiceName);
                if (NT_SUCCESS(status)) {
                    status = NtLoadDriver(&driverServiceName);
                }
            }
        }
        else {
            if (status == STATUS_OBJECT_NAME_EXISTS)
                status = STATUS_SUCCESS;
        }

        supEnablePrivilege(SE_LOAD_DRIVER_PRIVILEGE, FALSE);
    }
    else {
        status = STATUS_PRIVILEGE_NOT_HELD;
    }

    return status;
}

/*
* supLoadDriver
*
* Purpose:
*
* Install driver and load it.
*
* N.B.
* SE_LOAD_DRIVER_PRIVILEGE is required to be assigned and enabled.
*
*/
NTSTATUS supLoadDriver(
    _In_ LPCWSTR DriverName,
    _In_ LPCWSTR DriverPath,
    _In_ BOOLEAN UnloadPreviousInstance
)
{
    return supLoadDriverEx(DriverName,
        DriverPath,
        UnloadPreviousInstance,
        NULL,
        NULL);
}

/*
* supUnloadDriver
*
* Purpose:
*
* Call driver unload and remove corresponding registry key.
*
* N.B.
* SE_LOAD_DRIVER_PRIVILEGE is required to be assigned and enabled.
*
*/
NTSTATUS supUnloadDriver(
    _In_ LPCWSTR DriverName,
    _In_ BOOLEAN fRemove
)
{
    NTSTATUS status;
    SIZE_T keyOffset;
    UNICODE_STRING driverServiceName;

    WCHAR szBuffer[MAX_PATH + 1];

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

    if (FAILED(RtlStringCchPrintfSecure(szBuffer, MAX_PATH,
        DRIVER_REGKEY,
        NT_REG_PREP,
        DriverName)))
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    keyOffset = RTL_NUMBER_OF(NT_REG_PREP);

    status = supxCreateDriverEntry(NULL,
        &szBuffer[keyOffset]);

    if (!NT_SUCCESS(status))
        return status;

    if (supEnablePrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE)) {

        RtlInitUnicodeString(&driverServiceName, szBuffer);
        status = NtUnloadDriver(&driverServiceName);

        supEnablePrivilege(SE_LOAD_DRIVER_PRIVILEGE, FALSE);
    }
    else {
        status = STATUS_PRIVILEGE_NOT_HELD;
    }

    if (NT_SUCCESS(status)) {
        if (fRemove)
            supRegDeleteKeyRecursive(HKEY_LOCAL_MACHINE, &szBuffer[keyOffset]);
    }

    return status;
}

/*
* supOpenDriverEx
*
* Purpose:
*
* Open handle for driver.
*
*/
NTSTATUS supOpenDriverEx(
    _In_ LPCWSTR DriverName,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_opt_ PHANDLE DeviceHandle
)
{
    HANDLE deviceHandle = NULL;
    UNICODE_STRING usDeviceLink;
    OBJECT_ATTRIBUTES obja;
    IO_STATUS_BLOCK iost;

    NTSTATUS ntStatus;

    RtlInitUnicodeString(&usDeviceLink, DriverName);
    InitializeObjectAttributes(&obja, &usDeviceLink, OBJ_CASE_INSENSITIVE, NULL, NULL);

    ntStatus = NtCreateFile(&deviceHandle,
        DesiredAccess,
        &obja,
        &iost,
        NULL,
        0,
        0,
        FILE_OPEN,
        0,
        NULL,
        0);

    if (NT_SUCCESS(ntStatus)) {
        if (DeviceHandle)
            *DeviceHandle = deviceHandle;
    }

    return ntStatus;
}

/*
* supOpenDriver
*
* Purpose:
*
* Open handle for driver through \\DosDevices.
*
*/
NTSTATUS supOpenDriver(
    _In_ LPCWSTR DriverName,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE DeviceHandle
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    WCHAR szDeviceLink[MAX_PATH + 1];

    // assume failure
    if (DeviceHandle)
        *DeviceHandle = NULL;
    else
        return STATUS_INVALID_PARAMETER_2;

    if (DriverName) {

        RtlSecureZeroMemory(szDeviceLink, sizeof(szDeviceLink));

        if (FAILED(RtlStringCchPrintfSecure(szDeviceLink,
            MAX_PATH,
            TEXT("\\DosDevices\\%wS"),
            DriverName)))
        {
            return STATUS_INVALID_PARAMETER_1;
        }

        status = supOpenDriverEx(szDeviceLink,
            DesiredAccess,
            DeviceHandle);

        if (status == STATUS_OBJECT_NAME_NOT_FOUND ||
            status == STATUS_NO_SUCH_DEVICE)
        {

            //
            // Check the case when no symlink available.
            //

            RtlSecureZeroMemory(szDeviceLink, sizeof(szDeviceLink));

            if (FAILED(RtlStringCchPrintfSecure(szDeviceLink,
                MAX_PATH,
                TEXT("\\Device\\%wS"),
                DriverName)))
            {
                return STATUS_INVALID_PARAMETER_1;
            }

            status = supOpenDriverEx(szDeviceLink,
                DesiredAccess,
                DeviceHandle);

        }

    }
    else {
        status = STATUS_INVALID_PARAMETER_1;
    }

    return status;
}

/*
* supDeleteFileWithWait
*
* Purpose:
*
* Removes file from disk.
*
*/
BOOL supDeleteFileWithWait(
    _In_ ULONG WaitMilliseconds,
    _In_ ULONG NumberOfAttempts,
    _In_ LPCWSTR lpFileName
)
{
    ULONG retryCount = NumberOfAttempts;

    do {

        Sleep(WaitMilliseconds);
        if (DeleteFile(lpFileName)) {
            return TRUE;
        }

        retryCount--;

    } while (retryCount);

    return FALSE;
}

/*
* supCallDriver
*
* Purpose:
*
* Call driver.
*
*/
NTSTATUS supCallDriver(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG IoControlCode,
    _In_opt_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_opt_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength)
{
    IO_STATUS_BLOCK ioStatus;

    return NtDeviceIoControlFile(DeviceHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        IoControlCode,
        InputBuffer,
        InputBufferLength,
        OutputBuffer,
        OutputBufferLength);
}

/*
* supIsLongTermServicingWindows
*
* Purpose:
*
* Attempt to detect LTSC/LTSB product type.
*
*/
BOOLEAN supIsLongTermServicingWindows(
    VOID
)
{
    NTSTATUS ntStatus;
    ULONG dataLicense = 0, dataSize = 0, dataType = 0, i;

    UNICODE_STRING usLicenseValue = RTL_CONSTANT_STRING(L"Kernel-ProductInfo");

    DWORD suiteType[] = {
        PRODUCT_ENTERPRISE_S,              // LTSB/C
        PRODUCT_ENTERPRISE_S_N,            // LTSB/C N
        PRODUCT_ENTERPRISE_S_EVALUATION,   // LTSB/C Evaluation
        PRODUCT_ENTERPRISE_S_N_EVALUATION, // LTSB/C N Evaluation
        PRODUCT_IOTENTERPRISES             // IoT Enterprise LTSC
    };

    ntStatus = NtQueryLicenseValue(
        &usLicenseValue,
        &dataType,
        (PVOID)&dataLicense,
        sizeof(DWORD),
        &dataSize);

    if (NT_SUCCESS(ntStatus) &&
        dataType == REG_DWORD &&
        dataSize == sizeof(DWORD))
    {
        for (i = 0; i < RTL_NUMBER_OF(suiteType); i++) {
            if (dataLicense == suiteType[i]) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

/*
* supCreateThread
*
* Purpose:
*
* CreateThread wrapper.
*
*/
HANDLE supCreateThread(
    _In_ LPTHREAD_START_ROUTINE lpStartAddress,
    _In_opt_ __drv_aliasesMem LPVOID lpParameter,
    _In_ DWORD dwCreationFlags
)
{
    HANDLE threadHandle;
    
    threadHandle = CreateThread(NULL,
        0,
        lpStartAddress,
        lpParameter,
        dwCreationFlags,
        NULL);

    if (threadHandle) {
        OBEX_STATS_INC(TotalThreadsCreated);
    }

    return threadHandle;
}

/*
* supCreateDialogWorkerThread
*
* Purpose:
*
* Create thread dedicated for dialog with specified name.
*
*/
HANDLE supCreateDialogWorkerThread(
    _In_ LPTHREAD_START_ROUTINE lpStartAddress,
    _In_opt_ __drv_aliasesMem LPVOID lpParameter,
    _In_ DWORD dwCreationFlags
)
{
    WCHAR szBuffer[100];
    THREAD_NAME_INFORMATION tni;
    HANDLE threadHandle = supCreateThread(lpStartAddress, lpParameter, dwCreationFlags | CREATE_SUSPENDED);

    if (threadHandle) {

        RtlStringCchPrintfSecure(szBuffer, RTL_NUMBER_OF(szBuffer),
            TEXT("DialogWorker_%p"),
            lpStartAddress);

        RtlInitUnicodeString(&tni.ThreadName, szBuffer);
        NtSetInformationThread(threadHandle, ThreadNameInformation, (PVOID)&tni, sizeof(tni));

        ResumeThread(threadHandle);
    }

    return threadHandle;
}

/*
* supGetCurrentObjectPath
*
* Purpose:
*
* Build full path to current object.
*
* If IncludeName is FALSE then result path does not 
* include object name except for root directory.
*
* e.g.
* For \\              result will be \\
* For \\ABC           result will be \\
* For \\ABC\\DEF      result will be \\ABC
*
* If IncludeName is TRUE then result path *will* 
* include object name
* 
* e.g.
* For \\              result will be \\
* For \\ABC           result will be \\ABC
* For \\ABC\\DEF      result will be \\ABC\\DEF
*/
_Success_(return != FALSE)
BOOL supGetCurrentObjectPath(
    _In_ BOOLEAN IncludeName,
    _Out_ PUNICODE_STRING ObjectPath
)
{
    OBEX_PATH_ELEMENT* ObjectPathEntry;
    PLIST_ENTRY Head, Entry, FinalEntry, ObjectRootEntry = NULL;

    ULONG NameInfoSize, BufferLength;
    PWCH StringBuffer, ObjectName;

    PUNICODE_STRING String;

    RtlInitEmptyUnicodeString(ObjectPath, NULL, 0);

    if (IsListEmpty(&g_ObjectPathListHead))
        return FALSE;

    NameInfoSize = sizeof(UNICODE_NULL);

    Head = &g_ObjectPathListHead;
    Entry = Head->Blink;             // Beginning of path

    if (IncludeName) {
        FinalEntry = Head;
    }
    else {
        FinalEntry = Head->Flink;    // Current object name
    }

    ObjectRootEntry = Entry;
    while ((Entry) && (Entry != FinalEntry)) {

        ObjectPathEntry = CONTAINING_RECORD(Entry, OBEX_PATH_ELEMENT, ListEntry);
        NameInfoSize += ObjectPathEntry->Name.Length;

        //
        // If not last and first then add separator size.
        //
        if ((Entry != ObjectRootEntry) && (Entry->Blink != FinalEntry))
            NameInfoSize += sizeof(OBJ_NAME_PATH_SEPARATOR);

        Entry = Entry->Blink;
    }

    //
    // If this is root then leave.
    //
    if (NameInfoSize == sizeof(UNICODE_NULL)) {
        return supDuplicateUnicodeString(g_obexHeap, ObjectPath, ObGetPredefinedUnicodeString(OBP_ROOT));
    }

    ObjectName = (PWCH)supHeapAlloc(NameInfoSize);
    if (ObjectName == NULL)
        return FALSE;

    StringBuffer = ObjectName;

    Head = &g_ObjectPathListHead;
    Entry = Head->Blink;             // Beginning of path

    if (IncludeName) {
        FinalEntry = Head;
    }
    else {
        FinalEntry = Head->Flink;    // Current object name
    }

    ObjectRootEntry = Entry;
    while ((Entry) && (Entry != FinalEntry)) {

        ObjectPathEntry = CONTAINING_RECORD(Entry, OBEX_PATH_ELEMENT, ListEntry);

        String = &ObjectPathEntry->Name;

        RtlCopyMemory(StringBuffer, String->Buffer, String->Length);
        StringBuffer = (PWCH)((PCH)StringBuffer + String->Length);

        //
        // If not last and first then add separator.
        //
        if ((Entry != ObjectRootEntry) && (Entry->Blink != FinalEntry))
            *StringBuffer++ = OBJ_NAME_PATH_SEPARATOR;

        Entry = Entry->Blink;
    }

    *StringBuffer++ = UNICODE_NULL;

    BufferLength = (USHORT)((ULONG_PTR)StringBuffer - (ULONG_PTR)ObjectName);
    ObjectPath->Buffer = ObjectName;
    ObjectPath->Length = (USHORT)(BufferLength - sizeof(UNICODE_NULL));
    ObjectPath->MaximumLength = (USHORT)BufferLength;

    return TRUE;
}

/*
* supGetCurrentObjectName
*
* Purpose:
*
* Return name of currently selected object.
*
*/
_Success_(return)
BOOL supGetCurrentObjectName(
    _Out_ PUNICODE_STRING ObjectName
)
{
    OBEX_PATH_ELEMENT* entry = NULL;
    LIST_ENTRY* listEntry, * head;

    RtlInitEmptyUnicodeString(ObjectName, NULL, 0);

    if (IsListEmpty(&g_ObjectPathListHead))
        return FALSE;

    head = &g_ObjectPathListHead;
    listEntry = head->Flink;
    if (listEntry) {
        entry = CONTAINING_RECORD(listEntry, OBEX_PATH_ELEMENT, ListEntry);
        return supDuplicateUnicodeString(g_obexHeap, ObjectName, &entry->Name);
    }

    return FALSE;
}

/*
* supBuildCurrentObjectList
*
* Purpose:
*
* Create list of current object path elements including name.
*
*/
VOID supBuildCurrentObjectList(
    _In_ PVOID ListHead
)
{
    OBEX_ITEM* nextItem;
    OBEX_PATH_ELEMENT* entry = NULL;

    if (ObjectPathHeap)
        supDestroyHeap(ObjectPathHeap);

    ObjectPathHeap = supCreateHeap(HEAP_GROWABLE, TRUE);
    if (ObjectPathHeap == NULL)
        return;

    InitializeListHead(&g_ObjectPathListHead);

    nextItem = (OBEX_ITEM*)ListHead;
    while (nextItem) {
        entry = (OBEX_PATH_ELEMENT*)supHeapAllocEx(ObjectPathHeap, sizeof(OBEX_PATH_ELEMENT));
        if (entry) {
            entry->TypeIndex = nextItem->TypeIndex;
            supDuplicateUnicodeString(ObjectPathHeap, &entry->Name, &nextItem->Name);
            supDuplicateUnicodeString(ObjectPathHeap, &entry->TypeName, &nextItem->TypeName);
            InsertTailList(&g_ObjectPathListHead, &entry->ListEntry);
        }
        nextItem = nextItem->Prev;
    }

}

/*
* supNormalizeUnicodeStringForDisplay
*
* Purpose:
*
* Create a copy of unicode string, friendly for output.
*
*/
_Success_(return)
BOOL supNormalizeUnicodeStringForDisplay(
    _In_ HANDLE HeapHandle,
    _In_ PUNICODE_STRING SourceString,
    _Out_ PUNICODE_STRING NormalizedString
)
{
    PWCH stringBuffer, src, dst;
    ULONG i;

    stringBuffer = (PWCH)supHeapAllocEx(HeapHandle, 
        SourceString->Length + sizeof(UNICODE_NULL));
    
    if (stringBuffer) {

        dst = stringBuffer;
        src = SourceString->Buffer;

        i = SourceString->Length / sizeof(WCHAR);
        while (i--) {

            if (*src == 0)
                *dst = g_ObNameNormalizationSymbol;
            else
                *dst = *src;

            src++;
            dst++;
        }

        *dst = UNICODE_NULL;

        RtlInitUnicodeString(NormalizedString, stringBuffer);
        return TRUE;
    }

    return FALSE;
}

/*
* supDisplayCurrentObjectPath
*
* Purpose:
*
* Output current object path to the control.
*
*/
VOID supDisplayCurrentObjectPath(
    _In_ HWND hwnd,
    _In_opt_ PUNICODE_STRING Path,
    _In_ BOOLEAN NormalizePath
)
{
    BOOL bNeedFree = FALSE;
    UNICODE_STRING us, ns;

    if (Path) {
        us = *Path;
    }
    else {
        if (!supGetCurrentObjectPath(TRUE, &us))
            return;

        bNeedFree = TRUE;
    }

    if (NormalizePath) {
        if (supNormalizeUnicodeStringForDisplay(g_obexHeap, &us, &ns)) {

            SendMessage(hwnd, WM_SETTEXT, 0, (LPARAM)ns.Buffer);

            supFreeUnicodeString(g_obexHeap, &ns);
        }
    }
    else {
        SendMessage(hwnd, WM_SETTEXT, 0, (LPARAM)us.Buffer);
    }

    if (bNeedFree)
        supFreeDuplicatedUnicodeString(g_obexHeap, &us, FALSE);

}

/*
* supResolveSymbolicLinkTarget
*
* Purpose:
*
* Resolve symbolic link target and copy it to the supplied buffer.
*
* Return FALSE on error.
*
*/
_Success_(return)
BOOL supResolveSymbolicLinkTarget(
    _In_opt_ HANDLE LinkHandle,
    _In_opt_ HANDLE RootDirectoryHandle,
    _In_ PUNICODE_STRING LinkName,
    _Out_ PUNICODE_STRING LinkTarget
)
{
    BOOL bResult = FALSE;
    HANDLE hObject = NULL;
    ULONG rLen = 0;
    NTSTATUS ntStatus;
    UNICODE_STRING linkTarget;
    OBJECT_ATTRIBUTES obja;
    PWCH stringBuffer;

    if (LinkHandle == NULL) {
        //
        // There is no handle, open it.
        //
        InitializeObjectAttributes(&obja, LinkName, OBJ_CASE_INSENSITIVE, RootDirectoryHandle, NULL);
        if (!NT_SUCCESS(NtOpenSymbolicLinkObject(&hObject, SYMBOLIC_LINK_QUERY, &obja)))
            return FALSE;
    }
    else {
        hObject = LinkHandle;
    }

    RtlInitEmptyUnicodeString(&linkTarget, NULL, 0);
    ntStatus = NtQuerySymbolicLinkObject(hObject, &linkTarget, &rLen);

    if (ntStatus == STATUS_BUFFER_TOO_SMALL ||
        ntStatus == STATUS_BUFFER_OVERFLOW)
    {
        stringBuffer = (PWCH)supHeapAlloc(rLen + sizeof(UNICODE_NULL));
        if (stringBuffer) {

            linkTarget.Buffer = stringBuffer;
            linkTarget.Length = 0;
            linkTarget.MaximumLength = (USHORT)rLen;

            ntStatus = NtQuerySymbolicLinkObject(hObject, &linkTarget, &rLen);
            if (NT_SUCCESS(ntStatus)) {
                *LinkTarget = linkTarget;
                bResult = TRUE;
            }
            else {
                supHeapFree(stringBuffer);
            }

        }

    }

    //
    // If there is no input handle close what we opened.
    //
    if (LinkHandle == NULL) {
        if (hObject) NtClose(hObject);
    }

    return bResult;
}

/*
* supResolveSymbolicLinkTargetNormalized
*
* Purpose:
*
* Resolve symbolic link target in a GUI friendly output form.
*
* Return FALSE on error.
*
*/
_Success_(return)
BOOL supResolveSymbolicLinkTargetNormalized(
    _In_opt_ HANDLE LinkHandle,
    _In_opt_ HANDLE RootDirectoryHandle,
    _In_ PUNICODE_STRING LinkName,
    _Out_ PUNICODE_STRING NormalizedLinkTarget
)
{
    BOOL bResult;
    UNICODE_STRING linkTarget;

    if (!supResolveSymbolicLinkTarget(
        LinkHandle,
        RootDirectoryHandle,
        LinkName,
        &linkTarget))
    {
        return FALSE;
    }

    bResult = supNormalizeUnicodeStringForDisplay(g_obexHeap, &linkTarget, NormalizedLinkTarget);

    supFreeDuplicatedUnicodeString(g_obexHeap, &linkTarget, FALSE);

    return bResult;
}

/*
* supClipboardCopyUnicodeStringRaw
*
* Purpose:
*
* Copy UNICODE_STRING buffer to the clipboard as C array.
*
*/
VOID supClipboardCopyUnicodeStringRaw(
    _In_ PUNICODE_STRING String
)
{
    BYTE* src, * end;
    PWCH copyBuffer, dst;
    SIZE_T length;
    BYTE x;

    //
    // '0', 'x', ',', ' ', 'A', 'B' = 6 * sizeof(WCHAR)
    //
    length = 100 + ((SIZE_T)String->Length * 12);
    copyBuffer = (PWCH)supHeapAlloc(length);
    if (copyBuffer == NULL)
        return;

    _strcpy(copyBuffer, TEXT("unsigned char data["));
    ultostr(String->Length, _strend(copyBuffer));
    dst = _strcat(copyBuffer, TEXT("] = {"));

    src = (BYTE*)String->Buffer;
    end = (BYTE*)RtlOffsetToPointer(String->Buffer, String->Length);
    while (src < end) {

        *dst++ = '0';
        *dst++ = 'x';
        x = *src++;

        *dst++ = nibbletoh(x >> 4, TRUE);
        *dst++ = nibbletoh(x & 15, TRUE);

        if (src != end) {
            *dst++ = ',';
            *dst++ = ' ';
        }
    }

    *dst++ = 0;
    _strcat(copyBuffer, TEXT("}; "));

    supClipboardCopy(copyBuffer, _strlen(copyBuffer) * sizeof(WCHAR));
    supHeapFree(copyBuffer);
}

/*
* supFindUnicodeStringSubString
*
* Purpose:
*
* Return offset to substring if found and ULLONG_MAX instead.
* 
* Case Insensitive.
*
*/
SIZE_T supFindUnicodeStringSubString(
    _In_ PUNICODE_STRING String,
    _In_ PUNICODE_STRING SubString
)
{
    SIZE_T length1;
    SIZE_T length2;
    UNICODE_STRING string1;
    UNICODE_STRING string2;
    WCHAR c;
    SIZE_T i;

    if (SubString == NULL)
        return 0;

    length1 = String->Length / sizeof(WCHAR);
    length2 = SubString->Length / sizeof(WCHAR);

    if (length2 > length1)
        return ULLONG_MAX;

    if (length2 == 0)
        return 0;

    string1.Buffer = String->Buffer;
    string1.Length = SubString->Length - sizeof(WCHAR);
    string2.Buffer = SubString->Buffer;
    string2.Length = SubString->Length - sizeof(WCHAR);

    c = RtlUpcaseUnicodeChar(*string2.Buffer++);

    for (i = length1 - length2 + 1; i != 0; i--) {
        if (RtlUpcaseUnicodeChar(*string1.Buffer++) == c &&
            RtlEqualUnicodeString(&string1, &string2, TRUE))
        {
            return (ULONG_PTR)(string1.Buffer - String->Buffer - 1);
        }
    }

    return ULLONG_MAX;
}

/*
* supImageFixSections
*
* Purpose:
*
* Fix sections after dump.
*
*/
BOOL supImageFixSections(
    _In_ LPVOID Buffer
)
{
    PIMAGE_DOS_HEADER idh = NULL;
    PIMAGE_FILE_HEADER fh1 = NULL;
    PIMAGE_NT_HEADERS ImageHeaders = NULL;
    PIMAGE_SECTION_HEADER Section = NULL;
    DWORD vaddr, secalign, vsize, part;
    WORD i, c;

    __try {

        idh = (PIMAGE_DOS_HEADER)Buffer;
        fh1 = (PIMAGE_FILE_HEADER)((ULONG_PTR)Buffer + ((PIMAGE_DOS_HEADER)Buffer)->e_lfanew + sizeof(DWORD));
        if (fh1->Machine != IMAGE_FILE_MACHINE_AMD64) {
            return FALSE;
        }
        
        ImageHeaders = (PIMAGE_NT_HEADERS)((PBYTE)Buffer + idh->e_lfanew);
        Section = IMAGE_FIRST_SECTION(ImageHeaders);
        secalign = ImageHeaders->OptionalHeader.SectionAlignment;
        c = ImageHeaders->FileHeader.NumberOfSections;

        vaddr = Section->VirtualAddress;
        for (i = 0; i < c; i++) {

            //recalculate virtual size/address for each section
            vsize = Section->Misc.VirtualSize;
            part = vsize % secalign;
            if (part != 0) {
                vsize = vsize + secalign - part;
            }
            Section->SizeOfRawData = vsize;
            Section->PointerToRawData = vaddr;
            vaddr += vsize;
            Section = (PIMAGE_SECTION_HEADER)((PBYTE)Section + sizeof(IMAGE_SECTION_HEADER));
        }

    }
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
        return FALSE;
    }
    return TRUE;
}

/*
* supCloseKnownPropertiesDialog
*
* Purpose:
*
* Send WM_CLOSE to known properties dialog if it present.
*
*/
VOID supCloseKnownPropertiesDialog(
    _In_opt_ HWND hwndDlg
)
{
    if (hwndDlg)
        SendMessage(hwndDlg, WM_CLOSE, 0, 0);
}

/*
* supReadObexConfiguration
*
* Purpose:
*
* Reads program configuration data from registry if present.
*
*/
_Success_(return)
BOOL supReadObexConfiguration(
    _Out_ POBEX_CONFIG Configuration
)
{
    HKEY hKey;
    DWORD data = 0, cbData, dwType;
    WCHAR szBuffer[MAX_PATH + 1];
    WCHAR symbol;

    INT i;
    WCHAR szValidSymbols[] = {
        '!', '"', '#', '$', '%', '\'',
        '(', ')','*', '+',  '-', '.',
        ':', ';', '<', '>', '=', '?',
        '@', ']', '[', '^', '_', '`',
        '{', '}', '~' };

    Configuration->SymbolsPathValid = FALSE;
    Configuration->SymbolsDbgHelpDllValid = FALSE;
    Configuration->szNormalizationSymbol = OBJ_NAME_NORMALIZATION_SYMBOL;

    if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_CURRENT_USER, supObexConfiguration, 0, KEY_READ, &hKey)) {

        cbData = sizeof(DWORD);
        dwType = REG_DWORD;
        if (ERROR_SUCCESS == RegQueryValueEx(hKey, supObexNormalizationSymbol,
            NULL, &dwType, (LPBYTE)&data, &cbData))
        {
            if (dwType == REG_DWORD && cbData == sizeof(DWORD)) {
                symbol = (WCHAR)data;
                for (i = 0; i < RTL_NUMBER_OF(szValidSymbols); i++) {
                    if (szValidSymbols[i] == symbol) {
                        Configuration->szNormalizationSymbol = symbol;
                        break;
                    }
                }
            }
        }

        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        cbData = MAX_PATH * sizeof(WCHAR);
        dwType = REG_SZ;
        if (ERROR_SUCCESS == RegQueryValueEx(hKey, supObexSymPath,
            NULL, &dwType, (LPBYTE)&szBuffer, &cbData))
        {
            if (dwType == REG_SZ && cbData > sizeof(UNICODE_NULL)) {
                _strcpy(Configuration->szSymbolsPath, szBuffer);
                Configuration->SymbolsPathValid = TRUE;
            }
        }

        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        cbData = MAX_PATH * sizeof(WCHAR);
        dwType = REG_SZ;
        if (ERROR_SUCCESS == RegQueryValueEx(hKey, supObexSymDbgHelpDll,
            NULL, &dwType, (LPBYTE)&szBuffer, &cbData))
        {
            if (dwType == REG_SZ && cbData > sizeof(UNICODE_NULL)) {
                _strcpy(Configuration->szSymbolsDbgHelpDll, szBuffer);
                Configuration->SymbolsDbgHelpDllValid = TRUE;
            }
        }

        RegCloseKey(hKey);
        return TRUE;
    }

    return FALSE;
}

/*
* supGetParametersBlock
*
* Purpose:
*
* Return pointer to program parameters block.
*
*/
POBEX_CONFIG supGetParametersBlock(
    VOID)
{
    return &g_LoadedParametersBlock;
}

/*
* supCreateTrackingToolTip
*
* Purpose:
*
* Create tracking tooltip.
*
*/
HWND supCreateTrackingToolTip(
    _In_ INT toolID,
    _In_ HWND hwndOwner)
{
    HWND hwndTip;
    TOOLINFO toolInfo;

    hwndTip = CreateWindowEx(0, TOOLTIPS_CLASS, NULL,
        WS_POPUP,
        CW_USEDEFAULT, CW_USEDEFAULT,
        CW_USEDEFAULT, CW_USEDEFAULT,
        hwndOwner, NULL,
        g_WinObj.hInstance, NULL);

    if (hwndTip)
    {
        RtlSecureZeroMemory(&toolInfo, sizeof(toolInfo));
        toolInfo.cbSize = sizeof(toolInfo);
        toolInfo.hwnd = hwndOwner;
        toolInfo.uFlags = TTF_TRACK | TTF_ABSOLUTE;
        toolInfo.uId = (UINT_PTR)toolID;

        SendMessage(hwndTip, TTM_ADDTOOL, 0, (LPARAM)&toolInfo);
        SendMessage(hwndTip, TTM_SETMAXTIPWIDTH, 0, MAX_PATH * 2);
    }

    return hwndTip;
}

/*
* supIsPrivilegeEnabledForClient
*
* Purpose:
*
* Tests if given privilege is enabled for client.
*
*/
BOOL supIsPrivilegeEnabledForClient(
    _In_ ULONG Privilege
)
{
    BOOL bResult = FALSE;
    NTSTATUS ntStatus;
    HANDLE tokenHandle;

    //
    // Cannot use new fancy consts as this code must work pre Win10/11.
    // 

    ntStatus = NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_QUERY,
        &tokenHandle);

    if (NT_SUCCESS(ntStatus)) {
        ntStatus = supPrivilegeEnabled(tokenHandle, Privilege, &bResult);
        NtClose(tokenHandle);
    }

    RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
    return bResult;
}

/*
* supEnablePrivilegeWithCheck
*
* Purpose:
*
* Enable/Disable privilege with check if it was previously enabled.
*
*/
BOOLEAN supEnablePrivilegeWithCheck(
    _In_ ULONG Privilege,
    _In_ BOOLEAN Enable
)
{
    BOOLEAN bResult = FALSE, bWasEnabled = FALSE;
    NTSTATUS status;
    PRIVILEGE_SET privSet;
    ULONG returnLength;
    NTSTATUS ntStatus;
    HANDLE tokenHandle;
    PTOKEN_PRIVILEGES newState;
    UCHAR rawBuffer[sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES)];

    do {
        ntStatus = NtOpenProcessToken(
            NtCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &tokenHandle);

        if (!NT_SUCCESS(ntStatus))
            break;

        privSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
        privSet.PrivilegeCount = 1;
        privSet.Privilege[0].Luid.LowPart = Privilege;
        privSet.Privilege[0].Luid.HighPart = 0;
        privSet.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED;

        status = NtPrivilegeCheck(tokenHandle, &privSet, &bWasEnabled);

        //
        // Already enabled, leave.
        //
        if (Enable && bWasEnabled) {
            bResult = TRUE;
            break;
        }
        //
        // Already disabled, leave.
        //
        if (!Enable && !bWasEnabled) {
            bResult = TRUE;
            break;
        }

        newState = (PTOKEN_PRIVILEGES)rawBuffer;

        newState->PrivilegeCount = 1;
        newState->Privileges[0].Luid = RtlConvertUlongToLuid(Privilege);
        newState->Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0;

        ntStatus = NtAdjustPrivilegesToken(
            tokenHandle,
            FALSE,
            newState,
            sizeof(rawBuffer),
            NULL,
            &returnLength);

        if (ntStatus == STATUS_NOT_ALL_ASSIGNED) {
            ntStatus = STATUS_PRIVILEGE_NOT_HELD;
        }

    } while (FALSE);

    if (tokenHandle)
        NtClose(tokenHandle);

    RtlSetLastWin32Error(RtlNtStatusToDosError(ntStatus));
    return bResult;
}
