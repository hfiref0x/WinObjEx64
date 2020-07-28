/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       SUP.C
*
*  VERSION:     1.87
*
*  DATE:        22 July 2020
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "treelist\treelist.h"
#include "extras\extrasSSDT.h"

//
// Setup info database.
//
SAPIDB g_sapiDB;

//
// SCM info database.
//
SCMDB g_scmDB;

//
// Types collection.
//
POBJECT_TYPES_INFORMATION g_pObjectTypesInfo = NULL;

//#define _PROFILE_MEMORY_USAGE_


#ifdef _PROFILE_MEMORY_USAGE_
ULONG g_cHeapAlloc = 0;
#endif

int __cdecl supxHandlesLookupCallback(
    void const* first,
    void const* second);

int __cdecl supxHandlesLookupCallback2(
    void const* first,
    void const* second);

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
* supInitMSVCRT
*
* Purpose:
*
* Init MS CRT routines.
*
*/
BOOL supInitMSVCRT(
    VOID
)
{
    HMODULE DllHandle;

    DllHandle = GetModuleHandle(TEXT("ntdll.dll"));

    if (DllHandle) {
        rtl_swprintf_s = (pswprintf_s)GetProcAddress(DllHandle, "swprintf_s");
        rtl_qsort = (pqsort)GetProcAddress(DllHandle, "qsort");
    }

    if (rtl_swprintf_s == NULL ||
        rtl_qsort == NULL)
    {
        DllHandle = GetModuleHandle(TEXT("msvcrt.dll"));
        if (DllHandle == NULL)
            DllHandle = LoadLibraryEx(TEXT("msvcrt.dll"), NULL, 0);

        if (DllHandle) {
            rtl_swprintf_s = (pswprintf_s)GetProcAddress(DllHandle, "swprintf_s");
            rtl_qsort = (pqsort)GetProcAddress(DllHandle, "qsort");
        }
    }

    return ((rtl_swprintf_s != NULL) && (rtl_qsort != NULL));
}

/*
* supHeapAlloc
*
* Purpose:
*
* Wrapper for RtlAllocateHeap with WinObjEx heap.
*
*/
#ifndef _PROFILE_MEMORY_USAGE_
FORCEINLINE PVOID supHeapAlloc(
    _In_ SIZE_T Size)
{
    return RtlAllocateHeap(g_WinObj.Heap, HEAP_ZERO_MEMORY, Size);
}
#else
PVOID supHeapAlloc(
    _In_ SIZE_T Size)
{
    LONG x;
    DWORD LastError;
    PVOID Buffer = NULL;
    WCHAR szBuffer[100];

    Buffer = RtlAllocateHeap(g_WinObj.Heap, HEAP_ZERO_MEMORY, Size);
    LastError = GetLastError();

    if (Buffer) {

        x = InterlockedIncrement((PLONG)&g_cHeapAlloc);

        RtlStringCchPrintfSecure(szBuffer, 100,
            L"supHeapAlloc, block %p with size %llu, g_cHeapAlloc %x\r\n",
            Buffer, Size, x);

        OutputDebugString(szBuffer);
    }
    else {

        RtlStringCchPrintfSecure(szBuffer, 100,
            L"Allocation, block size %llu, FAILED\r\n",
            Size);

        OutputDebugString(szBuffer);
    }

    SetLastError(LastError);
    return Buffer;
}
#endif

/*
* supHeapFree
*
* Purpose:
*
* Wrapper for RtlFreeHeap with WinObjEx heap.
*
*/
#ifndef _PROFILE_MEMORY_USAGE_
FORCEINLINE BOOL supHeapFree(
    _In_ PVOID Memory)
{
    return RtlFreeHeap(g_WinObj.Heap, 0, Memory);
}
#else
BOOL supHeapFree(
    _In_ PVOID Memory)
{
    LONG x;
    BOOL bSuccess;
    DWORD LastError;
    WCHAR szBuffer[100];

    bSuccess = RtlFreeHeap(g_WinObj.Heap, 0, Memory);
    LastError = GetLastError();

    if (bSuccess) {

        x = InterlockedDecrement((PLONG)&g_cHeapAlloc);

        RtlStringCchPrintfSecure(szBuffer, 100,
            L"supHeapFree, block %p, g_cHeapAlloc %x\r\n",
            Memory, x);

        OutputDebugString(szBuffer);
    }
    else {

        RtlStringCchPrintfSecure(szBuffer, 100,
            L"supHeapFree, block %p, FAILED\r\n",
            Memory);

        OutputDebugString(szBuffer);
    }

    SetLastError(LastError);
    return bSuccess;
}
#endif

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
    _In_ LPWSTR lpText,
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
                supCopyMemory(lptstrCopy, dwSize, lpText, cbText);
            }
            GlobalUnlock(hglbCopy);
            if (!SetClipboardData(CF_UNICODETEXT, hglbCopy))
                GlobalFree(hglbCopy);
        }
        CloseClipboard();
    }
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
    BOOL   bFound = FALSE;
    DWORD  CurrentProcessId = GetCurrentProcessId();

    ULONG_PTR i;

    PSYSTEM_HANDLE_INFORMATION_EX pHandles;

    if (Address)
        *Address = 0;
    if (TypeIndex)
        *TypeIndex = 0;

    if (Address == NULL) {
        return bFound;
    }

    pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation, NULL);
    if (pHandles) {
        for (i = 0; i < pHandles->NumberOfHandles; i++) {
            if (pHandles->Handles[i].UniqueProcessId == (ULONG_PTR)CurrentProcessId) {
                if (pHandles->Handles[i].HandleValue == (ULONG_PTR)Object) {
                    *Address = (ULONG_PTR)pHandles->Handles[i].Object;
                    if (TypeIndex) {
                        *TypeIndex = pHandles->Handles[i].ObjectTypeIndex;
                    }
                    bFound = TRUE;
                    break;
                }
            }
        }
        supHeapFree(pHandles);
    }
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
    ULONG   ServiceId, memIO, bytesRead;
    BOOL    bResult = FALSE;
    PULONG  ServiceTableDumped = NULL;
    PUTable ConvertedTable;

    LONG32 Offset;

    *Table = NULL;

    memIO = ServiceLimit * sizeof(ULONG);
    ServiceTableDumped = (PULONG)supHeapAlloc(memIO);
    if (ServiceTableDumped) {
        bytesRead = 0;
        if (kdReadSystemMemoryEx(
            ServiceTableAddress,
            (PVOID)ServiceTableDumped,
            memIO,
            &bytesRead))
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
    _In_ LPWSTR lpFileName,
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
* supCopyMemory
*
* Purpose:
*
* Copies bytes between buffers.
*
* dest - Destination buffer
* cbdest - Destination buffer size in bytes
* src - Source buffer
* cbsrc - Source buffer size in bytes
*
*/
void supCopyMemory(
    _Inout_ void* dest,
    _In_ size_t cbdest,
    _In_ const void* src,
    _In_ size_t cbsrc
)
{
    char* d = (char*)dest;
    char* s = (char*)src;

    if ((dest == 0) || (src == 0) || (cbdest == 0))
        return;
    if (cbdest < cbsrc)
        cbsrc = cbdest;

    while (cbsrc > 0) {
        *d++ = *s++;
        cbsrc--;
    }
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
    UNREFERENCED_PARAMETER(wParam);

    switch (uMsg) {

    case WM_INITDIALOG:
        supCenterWindow(hwndDlg);

        if (lParam) {
            SetDlgItemText(hwndDlg, IDC_LOADING_MSG, (LPWSTR)lParam);
        }
        break;

    case WM_CLOSE:
        DestroyWindow(hwndDlg);
        break;

    default:
        break;
    }
    return 0;
}

/*
* supDisplayLoadBanner
*
* Purpose:
*
* Display borderless banner window to inform user about operation that need some wait.
*
*/
HWND supDisplayLoadBanner(
    _In_ HWND hwndParent,
    _In_ LPWSTR lpMessage
)
{
    return CreateDialogParam(
        g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_LOAD),
        hwndParent,
        supxLoadBannerDialog,
        (LPARAM)lpMessage);
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
    RECT rc, rcDlg, rcOwner;
    HWND hwndParent = GetParent(hwnd);

    //center window
    if (hwndParent) {
        GetWindowRect(hwndParent, &rcOwner);
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
    ULONG       bufferSize = 1024*16;
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
UINT supGetObjectNameIndexByTypeIndex(
    _In_ PVOID Object,
    _In_ UCHAR TypeIndex
)
{
    UINT   Index;
    ULONG  i;

    POBJECT_TYPE_INFORMATION pObject;

    union {
        union {
            POBJECT_TYPE_INFORMATION Object;
            POBJECT_TYPE_INFORMATION_V2 ObjectV2;
        } u1;
        PBYTE Ref;
    } ObjectTypeEntry;

    if (Object == NULL) {
        return ObjectTypeUnknown;
    }

    __try {

        Index = ObDecodeTypeIndex(Object, TypeIndex);

        if (g_WinObj.IsWine) {
            pObject = OBJECT_TYPES_FIRST_ENTRY_WINE(g_pObjectTypesInfo);
        }
        else {
            pObject = OBJECT_TYPES_FIRST_ENTRY(g_pObjectTypesInfo);
        }

        for (i = 0; i < g_pObjectTypesInfo->NumberOfTypes; i++) {
            if (g_NtBuildNumber >= NT_WIN8_RTM) {
                ObjectTypeEntry.Ref = (PBYTE)pObject;
                if (ObjectTypeEntry.u1.ObjectV2->TypeIndex == Index) {

                    return ObManagerGetIndexByTypeName(
                        pObject->TypeName.Buffer);

                }
            }
            else {
                if (i + 2 == Index) {

                    return ObManagerGetIndexByTypeName(
                        pObject->TypeName.Buffer);

                }
            }
            pObject = OBJECT_TYPES_NEXT_ENTRY(pObject);
        }
    }
    __except (WOBJ_EXCEPTION_FILTER) {
        return ObjectTypeUnknown;
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
    _In_ LPWSTR lpFilePath
)
{
    LPITEMIDLIST IIDL;

    if (lpFilePath == NULL)
        return;

    IIDL = ILCreateFromPath(lpFilePath);
    if (IIDL) {
        SHOpenFolderAndSelectItems(IIDL, 0, NULL, 0);
        ILFree(IIDL);
    }
}

/*
* supUserIsFullAdmin
*
* Purpose:
*
* Tests if the current user is admin with full access token.
*
*/
BOOL supUserIsFullAdmin(
    VOID
)
{
    BOOL     bResult = FALSE;
    HANDLE   hToken = NULL;
    NTSTATUS status;
    DWORD    i, Attributes;
    ULONG    ReturnLength = 0;

    PTOKEN_GROUPS pTkGroups;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup = NULL;

    hToken = supGetCurrentProcessToken();
    if (hToken == NULL)
        return FALSE;

    do {
        if (!NT_SUCCESS(RtlAllocateAndInitializeSid(
            &NtAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &AdministratorsGroup)))
        {
            break;
        }

        status = NtQueryInformationToken(hToken, TokenGroups, NULL, 0, &ReturnLength);
        if (status != STATUS_BUFFER_TOO_SMALL)
            break;

        pTkGroups = (PTOKEN_GROUPS)supHeapAlloc((SIZE_T)ReturnLength);
        if (pTkGroups == NULL)
            break;

        status = NtQueryInformationToken(hToken, TokenGroups, pTkGroups, ReturnLength, &ReturnLength);
        if (NT_SUCCESS(status)) {
            if (pTkGroups->GroupCount > 0)
                for (i = 0; i < pTkGroups->GroupCount; i++) {
                    Attributes = pTkGroups->Groups[i].Attributes;
                    if (RtlEqualSid(AdministratorsGroup, pTkGroups->Groups[i].Sid))
                        if (
                            (Attributes & SE_GROUP_ENABLED) &&
                            (!(Attributes & SE_GROUP_USE_FOR_DENY_ONLY))
                            )
                        {
                            bResult = TRUE;
                            break;
                        }
                }
        }
        supHeapFree(pTkGroups);

    } while (FALSE);

    if (AdministratorsGroup != NULL) {
        RtlFreeSid(AdministratorsGroup);
    }

    NtClose(hToken);
    return bResult;
}

/*
* supIsSymbolicLinkObject
*
* Purpose:
*
* Tests if the current item type is Symbolic link.
*
*/
BOOL supIsSymbolicLinkObject(
    _In_ HWND hwndList,
    _In_ INT iItem
)
{
    LVITEM lvItem;

    lvItem.mask = LVIF_PARAM;
    lvItem.iItem = iItem;
    lvItem.iSubItem = 0;
    lvItem.lParam = 0;
    ListView_GetItem(hwndList, &lvItem);

    return (lvItem.lParam == g_TypeSymbolicLink.Index);
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
    _In_opt_ INT iItem,
    _In_ BOOL bForce,
    _In_ BOOL bForceEnable
)
{
    UINT  uEnable = MF_BYCOMMAND | MF_GRAYED;

    if (bForce) {
        if (bForceEnable)
            uEnable = MF_BYCOMMAND;
    }
    else {
        if (hwndlv) {
            if (supIsSymbolicLinkObject(hwndlv, iItem)) {
                uEnable = MF_BYCOMMAND;
            }
        }
    }
    EnableMenuItem(GetSubMenu(GetMenu(hwnd), IDMM_OBJECT), ID_OBJECT_GOTOLINKTARGET, uEnable);
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
    _In_ UINT Item,
    _In_ ULONG_PTR IconData
)
{
    MENUITEMINFO mii;
    RtlSecureZeroMemory(&mii, sizeof(mii));
    mii.cbSize = sizeof(mii);
    mii.fMask = MIIM_BITMAP | MIIM_DATA;
    mii.hbmpItem = HBMMENU_CALLBACK;
    mii.dwItemData = IconData;
    SetMenuItemInfo(hMenu, Item, FALSE, &mii);
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
    _In_ HWND hWndToolbar
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

    SendMessage(hWndToolbar, TB_SETIMAGELIST, 0, (LPARAM)g_ToolBarMenuImages);
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

    if (g_WinObj.EnableFullMitigations) {

        policyInfo.Policy = (PROCESS_MITIGATION_POLICY)ProcessSignaturePolicy;
        policyInfo.SignaturePolicy.Flags = 0;
        policyInfo.SignaturePolicy.MicrosoftSignedOnly = TRUE;
        policyInfo.SignaturePolicy.MitigationOptIn = TRUE;

        NtSetInformationProcess(NtCurrentProcess(),
            ProcessMitigationPolicy,
            &policyInfo,
            sizeof(PROCESS_MITIGATION_POLICY_INFORMATION));

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

    if (g_WinObj.EnableFullMitigations) {

        policyInfo.Policy = (PROCESS_MITIGATION_POLICY)ProcessExtensionPointDisablePolicy;
        policyInfo.ExtensionPointDisablePolicy.Flags = 0;
        policyInfo.ExtensionPointDisablePolicy.DisableExtensionPoints = TRUE;

        NtSetInformationProcess(NtCurrentProcess(),
            ProcessMitigationPolicy,
            &policyInfo,
            sizeof(PROCESS_MITIGATION_POLICY_INFORMATION));

        policyInfo.Policy = (PROCESS_MITIGATION_POLICY)ProcessASLRPolicy;
        policyInfo.ASLRPolicy.Flags = 0;
        policyInfo.ASLRPolicy.EnableHighEntropy = TRUE;
        policyInfo.ASLRPolicy.EnableBottomUpRandomization = TRUE;
        policyInfo.ASLRPolicy.EnableForceRelocateImages = TRUE;

        NtSetInformationProcess(NtCurrentProcess(),
            ProcessMitigationPolicy,
            &policyInfo,
            sizeof(PROCESS_MITIGATION_POLICY_INFORMATION));
       /*
       // 
       // Disabled due to multiple incompatibilities, including their own HtmlHelp functions
       // Fixes WOX2007-005.
       //

        if (g_NtBuildNumber > 9600) {

            policyInfo.Policy = (PROCESS_MITIGATION_POLICY)ProcessDynamicCodePolicy;
            policyInfo.DynamicCodePolicy.Flags = 0;
            policyInfo.DynamicCodePolicy.ProhibitDynamicCode = TRUE;

            NtSetInformationProcess(NtCurrentProcess(),
                ProcessMitigationPolicy,
                &policyInfo,
                sizeof(PROCESS_MITIGATION_POLICY_INFORMATION));

        }
        */
    }
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
    _In_ BOOL IsFullAdmin
)
{
    WCHAR szError[200];
    NTSTATUS status;

    supxSetProcessMitigationPolicies();

#pragma warning(push)
#pragma warning(disable: 6031)
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
#pragma warning(pop)

    kdInit(IsFullAdmin);

    if (IsFullAdmin) {
        supCreateSCMSnapshot(SERVICE_DRIVER, NULL);
    }

    sapiCreateSetupDBSnapshot();
    g_pObjectTypesInfo = (POBJECT_TYPES_INFORMATION)supGetObjectTypesInfo();

    status = ExApiSetInit();
    if (!NT_SUCCESS(status)) {
        _strcpy(szError, TEXT("ExApiSetInit() failed, 0x"));
        ultohex(status, _strend(szError));
        logAdd(WOBJ_LOG_ENTRY_ERROR, szError);
    }

    //
    // Remember current DPI value.
    // 
    g_WinObj.CurrentDPI = supGetDPIValue(NULL);
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

    if (g_pObjectTypesInfo) supHeapFree(g_pObjectTypesInfo);

    SdtFreeGlobals();
}

/*
* supQueryProcessNameByEPROCESS
*
* Purpose:
*
* Lookups process name by given process object address.
*
* If nothing found return FALSE.
*
*/
BOOL supQueryProcessNameByEPROCESS(
    _In_ ULONG_PTR ValueOfEPROCESS,
    _In_ PVOID ProcessList,
    _Inout_ LPWSTR Buffer,
    _In_ DWORD ccBuffer //size of buffer in chars
)
{
    BOOL bFound = FALSE;
    DWORD  CurrentProcessId = GetCurrentProcessId();
    ULONG NextEntryDelta = 0, NumberOfProcesses = 0, i, j, ProcessListCount = 0;
    HANDLE hProcess = NULL;
    OBEX_PROCESS_LOOKUP_ENTRY* SavedProcessList;
    PSYSTEM_HANDLE_INFORMATION_EX pHandles;

    union {
        PSYSTEM_PROCESSES_INFORMATION Processes;
        PBYTE ListRef;
    } List;

    List.ListRef = (PBYTE)ProcessList;

    //
    // Calculate process handle list size.
    //
    do {

        List.ListRef += NextEntryDelta;

        if (List.Processes->ThreadCount)
            NumberOfProcesses += 1;

        NextEntryDelta = List.Processes->NextEntryDelta;

    } while (NextEntryDelta);

    List.ListRef = (PBYTE)ProcessList;

    ProcessListCount = 0;

    //
    // Build process handle list.
    //
    SavedProcessList = (OBEX_PROCESS_LOOKUP_ENTRY*)supHeapAlloc(NumberOfProcesses * sizeof(OBEX_PROCESS_LOOKUP_ENTRY));
    if (SavedProcessList) {

        NextEntryDelta = 0;

        do {
            List.ListRef += NextEntryDelta;

            if (List.Processes->ThreadCount) {

                if (NT_SUCCESS(supOpenProcess(List.Processes->UniqueProcessId,
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    &hProcess)))
                {
                    SavedProcessList[ProcessListCount].hProcess = hProcess;
                    SavedProcessList[ProcessListCount].EntryPtr = List.ListRef;
                    ProcessListCount += 1;
                }
            }
            NextEntryDelta = List.Processes->NextEntryDelta;
        } while (NextEntryDelta);

        //
        // Lookup this handles in system handle list.
        //
        pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation, NULL);
        if (pHandles) {
            for (i = 0; i < pHandles->NumberOfHandles; i++)
                if (pHandles->Handles[i].UniqueProcessId == (ULONG_PTR)CurrentProcessId) //current process id
                    for (j = 0; j < ProcessListCount; j++)
                        if (pHandles->Handles[i].HandleValue == (ULONG_PTR)SavedProcessList[j].hProcess) //same handle value
                            if ((ULONG_PTR)pHandles->Handles[i].Object == ValueOfEPROCESS) { //save object value

                                List.ListRef = SavedProcessList[j].EntryPtr;

                                _strncpy(
                                    Buffer,
                                    ccBuffer,
                                    List.Processes->ImageName.Buffer,
                                    List.Processes->ImageName.Length / sizeof(WCHAR));

                                bFound = TRUE;
                                break;
                            }

            supHeapFree(pHandles);
        }

        //
        // Destroy process handle list.
        //
        for (i = 0; i < ProcessListCount; i++) {
            if (SavedProcessList[i].hProcess)
                NtClose(SavedProcessList[i].hProcess);
        }

        supHeapFree(SavedProcessList);
    }

    return bFound;
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
    BOOL bResult = FALSE;
    LPBYTE servicesBuffer = NULL;
    DWORD dwSize = PAGE_SIZE, dwBytesNeeded = 0, dwServicesReturned = 0, c = 0;
    DWORD dwLastError = ERROR_SUCCESS;

    *Services = NULL;
    *ServicesReturned = 0;

    do {
        servicesBuffer = (LPBYTE)supVirtualAlloc(dwSize);
        if (servicesBuffer != NULL) {

            bResult = EnumServicesStatusEx(
                schSCManager,
                SC_ENUM_PROCESS_INFO,
                ServiceType,
                SERVICE_STATE_ALL,
                servicesBuffer,
                dwSize,
                &dwBytesNeeded,
                &dwServicesReturned,
                NULL,
                NULL);

            dwLastError = GetLastError();

        }
        else {
            return FALSE;
        }

        if (dwLastError == ERROR_MORE_DATA) {
            supVirtualFree(servicesBuffer);
            servicesBuffer = NULL;
            dwSize += dwBytesNeeded;
            c++;
            if (c > 20) {
                break;
            }
        }

    } while (dwLastError == ERROR_MORE_DATA);

    return bResult;
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
    BOOL      bResult = FALSE;
    SC_HANDLE schSCManager;
    DWORD     dwServicesReturned = 0;
    PVOID     Services = NULL;

    do {
        schSCManager = OpenSCManager(NULL,
            NULL,
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);

        if (schSCManager == NULL)
            break;

        bResult = supxEnumServicesStatus(schSCManager,
            ServiceType,
            (PBYTE*)&Services,
            &dwServicesReturned);

        if (!bResult)
            break;

        CloseServiceHandle(schSCManager);

    } while (FALSE);

    if (Snapshot) {
        Snapshot->Entries = Services;
        Snapshot->NumberOfEntries = dwServicesReturned;
    }
    else {
        EnterCriticalSection(&g_WinObj.Lock);
        g_scmDB.Entries = Services;
        g_scmDB.NumberOfEntries = dwServicesReturned;
        LeaveCriticalSection(&g_WinObj.Lock);
    }

    return bResult;
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
            supVirtualFree(Snapshot->Entries);
        Snapshot->NumberOfEntries = 0;
        Snapshot->Entries = NULL;
    }
    else {
        EnterCriticalSection(&g_WinObj.Lock);
        supVirtualFree(g_scmDB.Entries);
        g_scmDB.Entries = NULL;
        g_scmDB.NumberOfEntries = 0;
        LeaveCriticalSection(&g_WinObj.Lock);
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

    dataSize = (1 + MAX_PATH) * sizeof(WCHAR);
    lpProperty = (LPWSTR)RtlAllocateHeap(SnapshotHeap, HEAP_ZERO_MEMORY, dataSize);
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

        RtlFreeHeap(SnapshotHeap, 0, lpProperty);
        dataSize = returnLength;
        lpProperty = (LPWSTR)RtlAllocateHeap(SnapshotHeap, HEAP_ZERO_MEMORY, dataSize);
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
            RtlFreeHeap(SnapshotHeap, 0, lpProperty);
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

    Heap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
    if (Heap == NULL) {
        return FALSE;
    }

    if (g_WinObj.IsWine == FALSE) {
        RtlSetHeapInformation(Heap, HeapEnableTerminationOnCorruption, NULL, 0);
    }
    g_sapiDB.sapiHeap = Heap;

    hDevInfo = SetupDiGetClassDevs(NULL, NULL, NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);
    if (hDevInfo != INVALID_HANDLE_VALUE) {

        InitializeListHead(&g_sapiDB.ListHead);

        RtlSecureZeroMemory(&DeviceInfoData, sizeof(DeviceInfoData));
        DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

        for (i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &DeviceInfoData); i++) {

            Entry = (PSAPIDBENTRY)RtlAllocateHeap(Heap, HEAP_ZERO_MEMORY, sizeof(SAPIDBENTRY));
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
        RtlDestroyHeap(Heap);
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
    EnterCriticalSection(&g_WinObj.Lock);
    RtlDestroyHeap(g_sapiDB.sapiHeap);
    g_sapiDB.sapiHeap = NULL;
    g_sapiDB.ListHead.Blink = NULL;
    g_sapiDB.ListHead.Flink = NULL;
    LeaveCriticalSection(&g_WinObj.Lock);
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
    _In_ LPWSTR lpWindowStationName,
    _Inout_ LPWSTR Buffer,
    _In_ DWORD ccBuffer //size of buffer in chars
)
{
    BOOL   bFound = FALSE;
    LPWSTR lpType;

    ULONG entryId;

    if (lpWindowStationName == NULL) {
        SetLastError(ERROR_INVALID_NAME);
        return bFound;
    }

    if ((Buffer == NULL) || (ccBuffer < MAX_PATH)) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return bFound;
    }

    lpType = NULL;

    for (entryId = 0; entryId < MAX_KNOWN_WINSTA_DESCRIPTIONS; entryId++) {

        if (_strstri(lpWindowStationName,
            g_WinstaDescArray[entryId].lpszWinSta) != NULL)
        {
            lpType = g_WinstaDescArray[entryId].lpszDesc;
            bFound = TRUE;
            break;
        }

    }

    if (lpType == NULL)
        lpType = T_UnknownType;

    _strcpy(Buffer, lpType);
    _strcat(Buffer, TEXT(" logon session"));

    return bFound;
}

#include "props\propDlg.h"
#include "props\propTypeConsts.h"

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
    _In_ LPWSTR lpTypeName,
    _Inout_ LPWSTR Buffer,
    _In_ DWORD ccBuffer //size of buffer in chars
)
{
    BOOL  bResult = FALSE;
    ULONG i, nPool;

    POBJECT_TYPE_INFORMATION pObject;

    if (g_pObjectTypesInfo == NULL) {
        SetLastError(ERROR_INTERNAL_ERROR);
        return bResult;
    }
    if ((Buffer == NULL) || (ccBuffer < MAX_PATH)) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return bResult;
    }

    __try {

        if (g_WinObj.IsWine) {
            pObject = OBJECT_TYPES_FIRST_ENTRY_WINE(g_pObjectTypesInfo);
        }
        else {
            pObject = OBJECT_TYPES_FIRST_ENTRY(g_pObjectTypesInfo);
        }

        for (i = 0; i < g_pObjectTypesInfo->NumberOfTypes; i++) {
            if (_strncmpi(pObject->TypeName.Buffer,
                lpTypeName,
                pObject->TypeName.Length / sizeof(WCHAR)) == 0)
            {
                for (nPool = 0; nPool < MAX_KNOWN_POOL_TYPES; nPool++) {
                    if ((POOL_TYPE)pObject->PoolType == (POOL_TYPE)a_PoolTypes[nPool].dwValue) {

                        _strncpy(
                            Buffer, ccBuffer,
                            a_PoolTypes[nPool].lpDescription,
                            _strlen(a_PoolTypes[nPool].lpDescription)
                        );

                        break;
                    }
                }
                bResult = TRUE;
                break;
            }

            pObject = OBJECT_TYPES_NEXT_ENTRY(pObject);
        }

    }
    __except (WOBJ_EXCEPTION_FILTER) {
        return FALSE;
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
    _In_ LPWSTR lpDeviceName,
    _Inout_ LPWSTR Buffer,
    _In_ DWORD ccBuffer //size of buffer in chars
)
{
    BOOL         bResult, bIsRoot;
    SIZE_T       Length;
    LPWSTR       lpFullDeviceName = NULL;
    PLIST_ENTRY  Entry;
    PSAPIDBENTRY Item;

    bResult = FALSE;

    if ((ccBuffer < MAX_PATH) || (Buffer == NULL)) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return bResult;
    }

    //
    // Build full device path.
    //
    Length = (4 + _strlen(lpDeviceName) + _strlen(g_WinObj.CurrentObjectPath)) * sizeof(WCHAR);
    lpFullDeviceName = (LPWSTR)supHeapAlloc(Length);
    if (lpFullDeviceName != NULL) {

        // create full path device name for comparison
        _strcpy(lpFullDeviceName, g_WinObj.CurrentObjectPath);
        bIsRoot = (_strcmpi(g_WinObj.CurrentObjectPath, L"\\") == 0);
        if (bIsRoot == FALSE) {
            _strcat(lpFullDeviceName, L"\\");
        }
        _strcat(lpFullDeviceName, lpDeviceName);

        EnterCriticalSection(&g_WinObj.Lock);

        //
        // Enumerate devices.
        //
        Entry = g_sapiDB.ListHead.Flink;
        while (Entry && Entry != &g_sapiDB.ListHead) {

            Item = CONTAINING_RECORD(Entry, SAPIDBENTRY, ListEntry);
            if (Item->lpDeviceName != NULL) {
                if (_strcmpi(lpFullDeviceName, Item->lpDeviceName) == 0) {
                    if (Item->lpDeviceDesc != NULL) {

                        _strncpy(
                            Buffer,
                            ccBuffer,
                            Item->lpDeviceDesc,
                            _strlen(Item->lpDeviceDesc));

                    }
                    bResult = TRUE;
                    break;
                }
            }

            Entry = Entry->Flink;
        }

        LeaveCriticalSection(&g_WinObj.Lock);

        supHeapFree(lpFullDeviceName);
    }
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
    _In_ LPWSTR lpDriverName,
    _Inout_ LPWSTR Buffer,
    _In_ DWORD ccBuffer //size of buffer in chars
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

    if ((ccBuffer < MAX_PATH) || (Buffer == NULL)) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return bResult;
    }

    //
    // First attempt - look in SCM database.
    //

    RtlEnterCriticalSection(&g_WinObj.Lock);

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
            _strncpy(Buffer, ccBuffer, lpDisplayName, sz);
            bResult = TRUE;
            break;
        }
    }

    RtlLeaveCriticalSection(&g_WinObj.Lock);

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
                    _strncpy(Buffer, ccBuffer, lpDisplayName, dwSize);
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

    if ((ccBuffer < MAX_PATH) || (Buffer == NULL)) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return bResult;
    }

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
* supOpenDirectoryForObject
*
* Purpose:
*
* Open directory for given object, handle self case
*
*/
HANDLE supOpenDirectoryForObject(
    _In_ LPWSTR lpObjectName,
    _In_ LPWSTR lpDirectory
)
{
    BOOL   needFree = FALSE;
    HANDLE hDirectory;
    SIZE_T i, l, rdirLen, ldirSz;
    LPWSTR SingleDirName, LookupDirName;

    if (
        (lpObjectName == NULL) ||
        (lpDirectory == NULL)
        )
    {
        return NULL;
    }

    LookupDirName = lpDirectory;

    //
    // 1) Check if object is directory self
    // Extract directory name and compare (case insensitive) with object name
    // Else go to 3
    //
    l = 0;
    rdirLen = _strlen(lpDirectory);
    for (i = 0; i < rdirLen; i++) {
        if (lpDirectory[i] == '\\')
            l = i + 1;
    }
    SingleDirName = &lpDirectory[l];
    if (_strcmpi(SingleDirName, lpObjectName) == 0) {
        //
        //  2) If we are looking for directory, move search directory up
        //  e.g. lpDirectory = \ObjectTypes, lpObjectName = ObjectTypes then lpDirectory = \ 
        //
        ldirSz = rdirLen * sizeof(WCHAR) + sizeof(UNICODE_NULL);
        LookupDirName = (LPWSTR)supHeapAlloc(ldirSz);
        if (LookupDirName == NULL)
            return NULL;

        needFree = TRUE;

        //special case for root 
        if (l == 1) l++;

        supCopyMemory(LookupDirName, ldirSz, lpDirectory, (l - 1) * sizeof(WCHAR));
    }
    //
    // 3) Open directory
    //
    hDirectory = supOpenDirectory(NULL, LookupDirName, DIRECTORY_QUERY);

    if (needFree) {
        supHeapFree(LookupDirName);
    }

    return hDirectory;
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
    _In_ LPWSTR lpDialogFilter
)
{
    OPENFILENAME tag1;

    RtlSecureZeroMemory(&tag1, sizeof(OPENFILENAME));

    tag1.lStructSize = sizeof(OPENFILENAME);
    tag1.hwndOwner = OwnerWindow;
    tag1.lpstrFilter = lpDialogFilter;
    tag1.lpstrFile = SaveFileName;
    tag1.nMaxFile = MAX_PATH;
    tag1.lpstrInitialDir = NULL;
    tag1.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;

    return GetSaveFileName(&tag1);
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
    _In_ LPWSTR DosFileName,
    _In_ SIZE_T ccDosFileName
)
{
    BOOL    bSuccess = FALSE, bFound = FALSE;
    WCHAR   szDrive[3];
    WCHAR   szName[MAX_PATH + 1]; //for the device partition name
    WCHAR   szTemp[DBUFFER_SIZE]; //for the disk array
    UINT    uNameLen = 0;
    WCHAR* p;
    SIZE_T  l = 0, k = 0;

    if ((NtFileName == NULL) || (DosFileName == NULL) || (ccDosFileName < MAX_PATH))
        return bSuccess;

    szDrive[0] = L'X';
    szDrive[1] = L':';
    szDrive[2] = 0;

    RtlSecureZeroMemory(szTemp, sizeof(szTemp));

    uNameLen = GetLogicalDriveStrings(DBUFFER_SIZE - 1, szTemp);
    if (uNameLen == 0)
        return bSuccess;

    p = szTemp;

    do {

        *szDrive = *p;

        RtlSecureZeroMemory(szName, sizeof(szName));

        if (QueryDosDevice(szDrive, szName, MAX_PATH)) {

            uNameLen = (UINT)_strlen(szName);

            if (uNameLen < MAX_PATH) {

                bFound = (_strncmp(NtFileName, szName, uNameLen) == 0);

                if (bFound && *(NtFileName + uNameLen) == TEXT('\\')) {

                    _strcpy(DosFileName, szDrive);
                    l = _strlen(DosFileName);
                    k = _strlen(NtFileName);

                    _strncpy(&DosFileName[l],
                        ccDosFileName - l,
                        NtFileName + uNameLen,
                        k - uNameLen);

                    bSuccess = TRUE;
                    break;
                }
            }

        }

        while (*p++);

    } while (!bFound && *p); // end of string
    return bSuccess;
}

/*
* supGetWin32FileName
*
* Purpose:
*
* Query filename by handle.
*
* Input buffer must be at least MAX_PATH length.
*
*/
BOOL supGetWin32FileName(
    _In_ LPWSTR FileName,
    _Inout_ LPWSTR Win32FileName,
    _In_ SIZE_T ccWin32FileName
)
{
    BOOL                bResult = FALSE;
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    HANDLE              hFile = NULL;
    UNICODE_STRING      NtFileName;
    OBJECT_ATTRIBUTES   obja;
    IO_STATUS_BLOCK     iost;
    ULONG               memIO;
    BYTE* Buffer = NULL;

    if ((Win32FileName == NULL) || (ccWin32FileName < MAX_PATH)) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    do {

        RtlInitUnicodeString(&NtFileName, FileName);
        InitializeObjectAttributes(&obja, &NtFileName, OBJ_CASE_INSENSITIVE, 0, NULL);

        status = NtCreateFile(&hFile, SYNCHRONIZE, &obja, &iost, NULL, 0,
            FILE_SHARE_VALID_FLAGS, FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

        if (!NT_SUCCESS(status))
            break;

        memIO = 0;
        status = NtQueryObject(hFile, ObjectNameInformation, NULL, 0, &memIO);
        if (status != STATUS_INFO_LENGTH_MISMATCH)
            break;

        Buffer = (BYTE*)supHeapAlloc(memIO);
        if (Buffer == NULL)
            break;

        status = NtQueryObject(hFile, ObjectNameInformation, Buffer, memIO, NULL);
        if (!NT_SUCCESS(status))
            break;

        if (!supxConvertFileName(((PUNICODE_STRING)Buffer)->Buffer, Win32FileName, ccWin32FileName))
            break;

        bResult = TRUE;

    } while (FALSE);

    if (hFile)
        NtClose(hFile);

    if (Buffer != NULL)
        supHeapFree(Buffer);

    return bResult;
}

/*
* supIsWine
*
* Purpose:
*
* Detect Wine presense.
*
*/
BOOLEAN supIsWine(
    VOID
)
{
    return (is_wine() == 1);
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
    BOOLEAN bResult = FALSE;
    BOOLEAN bSecureBoot = FALSE;
    HKEY    hKey;
    DWORD   dwState, dwSize, returnLength;
    LSTATUS lRet;

    if (pbSecureBoot)
        *pbSecureBoot = FALSE;

    //
    // First attempt, query firmware environment variable, will not work if not fulladmin.
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
            bResult = TRUE;
        }
    }

    if (bResult) {
        return bResult;
    }

    //
    // Second attempt, query state from registry.
    //
    hKey = NULL;
    lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, T_SECUREBOOTSTATEKEY, 0, KEY_QUERY_VALUE, &hKey);
    if (lRet == ERROR_SUCCESS) {
        dwState = 0;
        dwSize = sizeof(DWORD);
        lRet = RegQueryValueEx(hKey, T_SECUREBOOTSTATEVALUE, NULL, NULL, (LPBYTE)&dwState, &dwSize);
        if (lRet == ERROR_SUCCESS) {

            if (pbSecureBoot) {
                *pbSecureBoot = (dwState == 1);
            }
            bResult = TRUE;
        }
        RegCloseKey(hKey);
    }

    if (bResult) {
        return bResult;
    }

    //
    // Third attempt, query state from user shared data.
    //
    dwState = USER_SHARED_DATA->DbgSecureBootEnabled;
    if (pbSecureBoot) {
        *pbSecureBoot = (dwState == 1);
    }
    bResult = TRUE;

    return bResult;
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
    UNICODE_STRING WinstaDir;

    DWORD LastError = ERROR_ACCESS_DENIED;

    if (supxGetWindowStationName(&CurrentWinstaDir)) {
        RtlInitUnicodeString(&WinstaDir, Context->lpCurrentObjectPath);
        if (RtlEqualUnicodeString(&WinstaDir, &CurrentWinstaDir, TRUE)) {
            hObject = OpenWindowStation(Context->lpObjectName, fInherit, dwDesiredAccess);
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
BOOL supQueryObjectTrustLabel(
    _In_ HANDLE hObject,
    _Out_ PULONG ProtectionType,
    _Out_ PULONG ProtectionLevel)
{
    BOOL                            bResult = FALSE;
    BOOLEAN                         saclPresent = FALSE, saclDefaulted = FALSE;
    ULONG                           i, Length = 0, returnLength = 0;

    NTSTATUS                        Status;

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
        Length = PAGE_SIZE;
        pSD = (PSECURITY_DESCRIPTOR)supHeapAlloc((SIZE_T)Length);
        if (pSD == NULL)
            break;

        Status = NtQuerySecurityObject(hObject,
            PROCESS_TRUST_LABEL_SECURITY_INFORMATION,
            pSD, Length, &returnLength);

        if (Status == STATUS_BUFFER_TOO_SMALL) {
            supHeapFree(pSD);

            pSD = (PSECURITY_DESCRIPTOR)supHeapAlloc((SIZE_T)returnLength);
            if (pSD == NULL)
                break;

            Status = NtQuerySecurityObject(hObject,
                PROCESS_TRUST_LABEL_SECURITY_INFORMATION,
                pSD, Length, &returnLength);
        }

        if (!NT_SUCCESS(Status))
            break;

        //
        // Query SACL from SD.
        //
        if (!NT_SUCCESS(RtlGetSaclSecurityDescriptor(pSD,
            &saclPresent,
            &sacl,
            &saclDefaulted))) break;

        if (!sacl)
            break;

        //
        // Query SACL size.
        //
        if (!NT_SUCCESS(RtlQueryInformationAcl(sacl,
            &aclSize,
            sizeof(aclSize),
            AclSizeInformation))) break;

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
                    bResult = TRUE;
                    break;
                }
            }
        }

    } while (FALSE);

    if (pSD) supHeapFree(pSD);

    return bResult;
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
        PSYSTEM_PROCESSES_INFORMATION Processes;
        PBYTE ListRef;
    } List;

    *SystemToken = NULL;

    WinlogonSessionId = WTSGetActiveConsoleSessionId();
    if (WinlogonSessionId == 0xFFFFFFFF)
        return STATUS_INVALID_SESSION;

    List.ListRef = (PBYTE)ProcessList;

    do {

        List.ListRef += NextEntryDelta;

        if (RtlEqualUnicodeString(&usWinlogon, &List.Processes->ImageName, TRUE)) {

            if (List.Processes->SessionId == WinlogonSessionId) {

                Status = supOpenProcess(
                    List.Processes->UniqueProcessId,
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

        NextEntryDelta = List.Processes->NextEntryDelta;

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
    // Optionally, enable debug privileges.
    // 
    supEnablePrivilege(SE_DEBUG_PRIVILEGE, TRUE);

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
        TokenPrivileges = (TOKEN_PRIVILEGES*)_alloca(sizeof(TOKEN_PRIVILEGES) +
            (1 * sizeof(LUID_AND_ATTRIBUTES)));

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
    WCHAR     szText[MAX_TEXT_CONVERSION_ULONG64 + 1];

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
    WCHAR     szText[MAX_TEXT_CONVERSION_ULONG64 + 1];

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
    WCHAR     szText[MAX_TEXT_CONVERSION_ULONG64 + 1];

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
* supOpenNamedObjectByType
*
* Purpose:
*
* Open object of supported type and return handle to it.
*
* Supported types are:
*
*  Directory (ObjectName parameter then ignored)
*  Device
*  Mutant
*  Key
*  Semaphore
*  Timer
*  Event
*  EventPair
*  SymbolicLink
*  IoCompletion
*  Section
*  Job
*  Session
*  MemoryPartition
*
*/
NTSTATUS supOpenNamedObjectByType(
    _Out_ HANDLE* ObjectHandle,
    _In_ ULONG TypeIndex,
    _In_ LPWSTR ObjectDirectory,
    _In_opt_ LPWSTR ObjectName,
    _In_ ACCESS_MASK DesiredAccess
)
{
    IO_STATUS_BLOCK iost;
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING ustr;
    HANDLE rootHandle = NULL, objectHandle = NULL;
    NTSTATUS ntStatus;

    *ObjectHandle = NULL;

    if (ObjectDirectory == NULL)
        return STATUS_INVALID_PARAMETER_3;

    if ((TypeIndex != ObjectTypeDirectory) &&
        (TypeIndex != ObjectTypeDevice) &&
        (TypeIndex != ObjectTypeMutant) &&
        (TypeIndex != ObjectTypeKey) &&
        (TypeIndex != ObjectTypeSemaphore) &&
        (TypeIndex != ObjectTypeTimer) &&
        (TypeIndex != ObjectTypeEvent) &&
        (TypeIndex != ObjectTypeEventPair) &&
        (TypeIndex != ObjectTypeSymbolicLink) &&
        (TypeIndex != ObjectTypeIoCompletion) &&
        (TypeIndex != ObjectTypeSection) &&
        (TypeIndex != ObjectTypeJob) &&
        (TypeIndex != ObjectTypeSession) &&
        (TypeIndex != ObjectTypeMemoryPartition))
    {
        return STATUS_INVALID_PARAMETER_2;
    }

    __try {

        RtlInitUnicodeString(&ustr, ObjectDirectory);
        InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);

        ntStatus = NtOpenDirectoryObject(&rootHandle, DIRECTORY_QUERY, &obja);

        if (!NT_SUCCESS(ntStatus))
            return ntStatus;

        if (ObjectName == NULL) {
            *ObjectHandle = rootHandle;
            return ntStatus;
        }

        RtlInitUnicodeString(&ustr, ObjectName);
        obja.RootDirectory = rootHandle;

        switch (TypeIndex) {
        case ObjectTypeDevice:
            ntStatus = NtCreateFile(&objectHandle, DesiredAccess, &obja, &iost, NULL, 0,
                FILE_SHARE_VALID_FLAGS, FILE_OPEN, 0, NULL, 0);
            break;

        case ObjectTypeMutant:
            ntStatus = NtOpenMutant(&objectHandle, DesiredAccess, &obja);
            break;

        case ObjectTypeKey:
            ntStatus = NtOpenKey(&objectHandle, DesiredAccess, &obja);
            break;

        case ObjectTypeSemaphore:
            ntStatus = NtOpenSemaphore(&objectHandle, DesiredAccess, &obja);
            break;

        case ObjectTypeTimer:
            ntStatus = NtOpenTimer(&objectHandle, DesiredAccess, &obja);
            break;

        case ObjectTypeEvent:
            ntStatus = NtOpenEvent(&objectHandle, DesiredAccess, &obja);
            break;

        case ObjectTypeEventPair:
            ntStatus = NtOpenEventPair(&objectHandle, DesiredAccess, &obja);
            break;

        case ObjectTypeSymbolicLink:
            ntStatus = NtOpenSymbolicLinkObject(&objectHandle, DesiredAccess, &obja);
            break;

        case ObjectTypeIoCompletion:
            ntStatus = NtOpenIoCompletion(&objectHandle, DesiredAccess, &obja);
            break;

        case ObjectTypeSection:
            ntStatus = NtOpenSection(&objectHandle, DesiredAccess, &obja);
            break;

        case ObjectTypeJob:
            ntStatus = NtOpenJobObject(&objectHandle, DesiredAccess, &obja);
            break;

        case ObjectTypeSession:
            ntStatus = NtOpenSession(&objectHandle, DesiredAccess, &obja);
            break;

        case ObjectTypeMemoryPartition:
            if (g_ExtApiSet.NtOpenPartition) {
                ntStatus = g_ExtApiSet.NtOpenPartition(&objectHandle, DesiredAccess, &obja);
            }
            else
                ntStatus = STATUS_PROCEDURE_NOT_FOUND;
            break;
        default:
            ntStatus = STATUS_INVALID_PARAMETER_2;
            break;
        }

        if (NT_SUCCESS(ntStatus))
            *ObjectHandle = objectHandle;

        NtClose(rootHandle);
    }
    __except (WOBJ_EXCEPTION_FILTER_LOG) {
        return STATUS_ACCESS_VIOLATION;
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
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    IO_STATUS_BLOCK iost;
    OBJECT_ATTRIBUTES objaNamespace;
    CLIENT_ID clientId;

    if (Context->ContextType == propPrivateNamespace) {

        //
        // Open private namespace.
        //
        InitializeObjectAttributes(&objaNamespace, NULL, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = NtOpenPrivateNamespace(
            &hPrivateNamespace,
            MAXIMUM_ALLOWED,
            &objaNamespace,
            Context->NamespaceInfo.BoundaryDescriptor);

        if (!NT_SUCCESS(status)) {
            *Status = status;
            return NULL;
        }

        //
        // Modify OBJECT_ATTRIBUTES RootDirectory.
        //
        ObjectAttributes->RootDirectory = hPrivateNamespace;
    }

    switch (Context->TypeIndex) {

    case ObjectTypeProcess:
        if (Context->ContextType == propUnnamed) {

            status = supOpenProcessEx(
                Context->UnnamedObjectInfo.ClientId.UniqueProcess,
                &hObject);

            if (!NT_SUCCESS(status)) {

                clientId.UniqueProcess = Context->UnnamedObjectInfo.ClientId.UniqueProcess;
                clientId.UniqueThread = NULL;

                status = NtOpenProcess(&hObject, DesiredAccess,
                    ObjectAttributes,
                    &clientId);
            }
        }
        else
            status = STATUS_INVALID_PARAMETER;

        break;

    case ObjectTypeThread:
        if (Context->ContextType == propUnnamed) {
            status = NtOpenThread(&hObject, DesiredAccess,
                ObjectAttributes,
                &Context->UnnamedObjectInfo.ClientId);
        }
        else
            status = STATUS_INVALID_PARAMETER;
        break;

    case ObjectTypeToken:
        if (Context->ContextType == propUnnamed) {
            status = supOpenTokenByParam(&Context->UnnamedObjectInfo.ClientId,
                ObjectAttributes,
                DesiredAccess,
                Context->UnnamedObjectInfo.IsThreadToken,
                &hObject);
        }
        else
            status = STATUS_INVALID_PARAMETER;
        break;

    case ObjectTypeDevice: //FILE_OBJECT
        status = NtCreateFile(&hObject, DesiredAccess, ObjectAttributes, &iost, NULL, 0,
            FILE_SHARE_VALID_FLAGS, FILE_OPEN, 0, NULL, 0);//generic access rights
        break;

    case ObjectTypeMutant:
        status = NtOpenMutant(&hObject, DesiredAccess, ObjectAttributes); //MUTANT_QUERY_STATE for query
        break;

    case ObjectTypeKey:
        status = NtOpenKey(&hObject, DesiredAccess, ObjectAttributes); //KEY_QUERY_VALUE for query
        break;

    case ObjectTypeSemaphore:
        status = NtOpenSemaphore(&hObject, DesiredAccess, ObjectAttributes); //SEMAPHORE_QUERY_STATE for query
        break;

    case ObjectTypeTimer:
        status = NtOpenTimer(&hObject, DesiredAccess, ObjectAttributes); //TIMER_QUERY_STATE for query
        break;

    case ObjectTypeEvent:
        status = NtOpenEvent(&hObject, DesiredAccess, ObjectAttributes); //EVENT_QUERY_STATE for query
        break;

    case ObjectTypeEventPair:
        status = NtOpenEventPair(&hObject, DesiredAccess, ObjectAttributes); //generic access
        break;

    case ObjectTypeSymbolicLink:
        status = NtOpenSymbolicLinkObject(&hObject, DesiredAccess, ObjectAttributes); //SYMBOLIC_LINK_QUERY for query
        break;

    case ObjectTypeIoCompletion:
        status = NtOpenIoCompletion(&hObject, DesiredAccess, ObjectAttributes); //IO_COMPLETION_QUERY_STATE for query
        break;

    case ObjectTypeSection:
        status = NtOpenSection(&hObject, DesiredAccess, ObjectAttributes); //SECTION_QUERY for query
        break;

    case ObjectTypeJob:
        status = NtOpenJobObject(&hObject, DesiredAccess, ObjectAttributes); //JOB_OBJECT_QUERY for query
        break;

    case ObjectTypeSession:
        status = NtOpenSession(&hObject, DesiredAccess, ObjectAttributes); //generic access
        break;

    case ObjectTypeMemoryPartition:
        if (g_ExtApiSet.NtOpenPartition) {
            status = g_ExtApiSet.NtOpenPartition(&hObject, DesiredAccess, ObjectAttributes); //MEMORY_PARTITION_QUERY_ACCESS for query 
        }
        else
            status = STATUS_PROCEDURE_NOT_FOUND;
        break;
    default:
        status = STATUS_OBJECTID_NOT_FOUND;
        break;
    }

    *Status = status;

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

        switch (Context->TypeIndex) {
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
    _In_ LPWSTR Source,
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
    _In_ LPWSTR lpText,
    _In_ NTSTATUS Status
)
{
    PTCHAR lpMsg;
    SIZE_T Length = _strlen(lpText);
    lpMsg = (PTCHAR)supHeapAlloc(Length + 100);
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
* supCopyTreeListSubItemValue
*
* Purpose:
*
* Copy treelist value to the clipboard.
*
*/
VOID supCopyTreeListSubItemValue(
    _In_ HWND TreeList,
    _In_ UINT ValueIndex
)
{
    SIZE_T             cbText;
    LPWSTR             lpText;
    TL_SUBITEMS_FIXED* subitems = NULL;
    TVITEMEX           itemex;
    WCHAR              textbuf[MAX_PATH + 1];

    __try {

        RtlSecureZeroMemory(&itemex, sizeof(itemex));
        RtlSecureZeroMemory(textbuf, sizeof(textbuf));
        itemex.mask = TVIF_TEXT;
        itemex.hItem = TreeList_GetSelection(TreeList);
        itemex.pszText = textbuf;
        itemex.cchTextMax = MAX_PATH;

        TreeList_GetTreeItem(TreeList, &itemex, &subitems);

        if (subitems) {
            if (ValueIndex < subitems->Count) {
                lpText = subitems->Text[ValueIndex];
                if (lpText) {
                    cbText = _strlen(lpText) * sizeof(WCHAR);
                    supClipboardCopy(lpText, cbText);
                }
            }
        }
    }
    __except (WOBJ_EXCEPTION_FILTER) {
        return;
    }
}

/*
* supCopyListViewSubItemValue
*
* Purpose:
*
* Copy listview value to the clipboard.
*
*/
VOID supCopyListViewSubItemValue(
    _In_ HWND ListView,
    _In_ UINT ValueIndex
)
{
    INT mark;
    SIZE_T cbText;
    LPWSTR lpText;

    mark = ListView_GetSelectionMark(ListView);

    lpText = supGetItemText(ListView, mark, ValueIndex, NULL);
    if (lpText) {
        cbText = _strlen(lpText) * sizeof(WCHAR);
        supClipboardCopy(lpText, cbText);
        supHeapFree(lpText);
    }
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

    if (NT_SUCCESS(status))
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
    FILETIME ConvertedTime;
    TIME_FIELDS TimeFields;

    if ((Time == NULL) || (lpszBuffer == NULL)) return 0;
    if (cchBuffer == 0) return 0;

    RtlSecureZeroMemory(&ConvertedTime, sizeof(ConvertedTime));
    if (FileTimeToLocalFileTime((PFILETIME)Time, (PFILETIME)&ConvertedTime)) {
        RtlSecureZeroMemory(&TimeFields, sizeof(TimeFields));
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
            g_szMonths[TimeFields.Month - 1],
            TimeFields.Year);

        return 1;
    }

    return 0;
}

/*
* supGetListViewItemParam
*
* Purpose:
*
* Return ListView item associated parameter.
*
*/
BOOL supGetListViewItemParam(
    _In_ HWND hwndListView,
    _In_ INT itemIndex,
    _Out_ PVOID * outParam
)
{
    LVITEM lvItem;

    *outParam = NULL;

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
    NTSTATUS Status;
    ULONG Length;
    LPWSTR UserAndDomainName = NULL, P;
    LSA_OBJECT_ATTRIBUTES lobja;
    LSA_HANDLE PolicyHandle = NULL;
    PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains = NULL;
    PLSA_TRANSLATED_NAME Names = NULL;
    SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;

    *lpSidUserAndDomain = NULL;

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

    if (NT_SUCCESS(LsaOpenPolicy(
        NULL,
        (PLSA_OBJECT_ATTRIBUTES)&lobja,
        POLICY_LOOKUP_NAMES,
        (PLSA_HANDLE)&PolicyHandle)))
    {
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
        LsaClose(PolicyHandle);
    }

    return bResult;
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
    PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX elem1 = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)first;
    PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX elem2 = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)second;

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
    PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX elem1 = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)first;
    PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX elem2 = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)second;

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
* Use supHandlesFreeList to release allocated memory.
*
*/
PSYSTEM_HANDLE_INFORMATION_EX supHandlesCreateFilteredAndSortedList(
    _In_ ULONG_PTR FilterUniqueProcessId,
    _In_ BOOLEAN fObject
)
{
    PSYSTEM_HANDLE_INFORMATION_EX resultSnapshot = NULL, handleDump;
    ULONG_PTR i, cLast = 0;

    ULONG returnLength = 0;
    SIZE_T stBufferSize;

    handleDump = (PSYSTEM_HANDLE_INFORMATION_EX)ntsupGetSystemInfoEx(
        SystemExtendedHandleInformation,
        &returnLength,
        supHeapAlloc,
        supHeapFree);

    if (handleDump == NULL)
        return NULL;

    stBufferSize = sizeof(SYSTEM_HANDLE_INFORMATION_EX) +
        handleDump->NumberOfHandles * sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX);

    resultSnapshot = (PSYSTEM_HANDLE_INFORMATION_EX)supHeapAlloc(stBufferSize);

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
            sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX),
            (fObject) ? supxHandlesLookupCallback2 : supxHandlesLookupCallback);
    }

    supHeapFree(handleDump);

    return resultSnapshot;
}

/*
* supHandlesFreeList
*
* Purpose:
*
* Free memory allocated for handle list.
*
*/
BOOL supHandlesFreeList(
    PSYSTEM_HANDLE_INFORMATION_EX SortedHandleList
)
{
    if (SortedHandleList) {
        
        return supHeapFree(SortedHandleList);
    }
    return FALSE;
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
    _In_ PSYSTEM_HANDLE_INFORMATION_EX SortedHandleList,
    _In_ HANDLE ObjectHandle,
    _Out_ PULONG_PTR ObjectAddress
)
{
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* SearchResult, SearchEntry;

    SearchEntry.HandleValue = (ULONG_PTR)ObjectHandle;

    SearchResult = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)supBSearch(
        (PCVOID)&SearchEntry,
        SortedHandleList->Handles,
        SortedHandleList->NumberOfHandles,
        sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX),
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
        PSYSTEM_PROCESSES_INFORMATION ProcessEntry;
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

    __try {

        InitializeObjectAttributes(&ObjectAttributes, &ProductOptionsKey, OBJ_CASE_INSENSITIVE, NULL, NULL);
        Status = NtOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
        if (!NT_SUCCESS(Status))
            return NULL;

        Status = NtQueryValueKey(KeyHandle, &ProductPolicyValue,
            KeyValuePartialInformation, NULL, 0, &DataLength);

        if (Status == STATUS_BUFFER_TOO_SMALL) {
            PolicyData = (KEY_VALUE_PARTIAL_INFORMATION*)supHeapAlloc(DataLength);
            if (PolicyData) {

                Status = NtQueryValueKey(KeyHandle, &ProductPolicyValue,
                    KeyValuePartialInformation, PolicyData, DataLength, &DataLength);

                if (NT_SUCCESS(Status) && (PolicyData->Type == REG_BINARY)) {
                    ReturnData = PolicyData;
                }
                else {
                    supHeapFree(PolicyData);
                }
            }
        }
        NtClose(KeyHandle);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }

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

    vtEmpty = {};
    hr = CoCreateInstance(CLSID_ShellWindows, NULL, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&psw));
    if (SUCCEEDED(hr))
    {
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

    vtEmpty.vt = VT_EMPTY;
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
* N.B. Taken entirely from Windows SDK sample.
*
*/
HRESULT WINAPI supShellExecInExplorerProcess(
    _In_ PCWSTR pszFile)
{
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    IShellView* psv;
    IShellDispatch2* psd;
    BSTR bstrFile;
    VARIANT vtEmpty;

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
                    vtEmpty = {};
                    hr = psd->ShellExecuteW(bstrFile, vtEmpty, vtEmpty, vtEmpty, vtEmpty);
                    SysFreeString(bstrFile);
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
                    vtEmpty.vt = VT_EMPTY;
                    hr = psd->lpVtbl->ShellExecuteW(psd, bstrFile, vtEmpty, vtEmpty, vtEmpty, vtEmpty);
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

        SendMessage(GetDlgItem(hwndDlg, ID_OBJECT_ICON), STM_SETIMAGE, IMAGE_ICON, (LPARAM)hIcon);

        if (IsShadow)
            Context->ObjectTypeIcon = hIcon;
        else
            Context->ObjectIcon = hIcon;

        return TRUE;
    }

    return FALSE;
}

/*
* supDestroyIconForObjectType
*
* Purpose:
*
* Destroy icon used to represent object (or its type) which properties is currently viewed.
*
*/
VOID supDestroyIconForObjectType(
    _In_ PROP_OBJECT_INFO * Context
)
{
    if (Context->IsType) {
        if (Context->ObjectTypeIcon) {
            DestroyIcon(Context->ObjectTypeIcon);
            Context->ObjectTypeIcon = NULL;
        }
    }
    if (Context->ObjectIcon) {
        DestroyIcon(Context->ObjectIcon);
        Context->ObjectIcon = NULL;
    }
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
        *lpEnd = TEXT('\\');
        lpEnd++;
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
    _In_ LPWSTR lpSubKey)
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
    _Out_ PSECURITY_DESCRIPTOR * SecurityDescriptor,
    _Out_opt_ PULONG Length
)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    PSID admSid = NULL;
    PSID sysSid = NULL;
    PACL sysAcl = NULL;
    ULONG daclSize = 0;

    PSECURITY_DESCRIPTOR securityDescriptor;

    SID_IDENTIFIER_AUTHORITY sidAuthority = SECURITY_NT_AUTHORITY;

    *SecurityDescriptor = NULL;

    if (Length)
        *Length = 0;

    do {

        securityDescriptor = (PSECURITY_DESCRIPTOR)supHeapAlloc(sizeof(SECURITY_DESCRIPTOR));
        if (securityDescriptor == NULL) {
            ntStatus = STATUS_MEMORY_NOT_ALLOCATED;
            break;
        }

        admSid = (PSID)supHeapAlloc(RtlLengthRequiredSid(2));
        if (admSid == NULL) {
            ntStatus = STATUS_MEMORY_NOT_ALLOCATED;
            break;
        }

        sysSid = (PSID)supHeapAlloc(RtlLengthRequiredSid(1));
        if (sysSid == NULL) {
            ntStatus = STATUS_MEMORY_NOT_ALLOCATED;
            break;
        }

        ntStatus = RtlInitializeSid(admSid, &sidAuthority, 2);
        if (NT_SUCCESS(ntStatus)) {
            *RtlSubAuthoritySid(admSid, 0) = SECURITY_BUILTIN_DOMAIN_RID;
            *RtlSubAuthoritySid(admSid, 1) = DOMAIN_ALIAS_RID_ADMINS;
        }
        else {
            break;
        }

        ntStatus = RtlInitializeSid(sysSid, &sidAuthority, 1);
        if (NT_SUCCESS(ntStatus)) {
            *RtlSubAuthoritySid(sysSid, 0) = SECURITY_LOCAL_SYSTEM_RID;
        }
        else {
            break;
        }

        daclSize = sizeof(ACL) +
            (2 * sizeof(ACCESS_ALLOWED_ACE)) +
            RtlLengthSid(admSid) + RtlLengthSid(sysSid) +
            SECURITY_DESCRIPTOR_MIN_LENGTH;

        sysAcl = (PACL)supHeapAlloc(daclSize);
        if (sysAcl == NULL) {
            ntStatus = STATUS_MEMORY_NOT_ALLOCATED;
            break;
        }

        ntStatus = RtlCreateAcl(sysAcl, (ULONG)(daclSize - SECURITY_DESCRIPTOR_MIN_LENGTH), (ULONG)ACL_REVISION);
        if (!NT_SUCCESS(ntStatus))
            break;

        ntStatus = RtlAddAccessAllowedAce(sysAcl,
            ACL_REVISION,
            GENERIC_ALL,
            sysSid);

        if (!NT_SUCCESS(ntStatus))
            break;

        ntStatus = RtlAddAccessAllowedAce(sysAcl,
            ACL_REVISION,
            GENERIC_ALL,
            admSid);

        if (!NT_SUCCESS(ntStatus))
            break;

        ntStatus = RtlCreateSecurityDescriptor(securityDescriptor,
            SECURITY_DESCRIPTOR_REVISION1);

        if (!NT_SUCCESS(ntStatus))
            break;

        ntStatus = RtlSetDaclSecurityDescriptor(securityDescriptor,
            TRUE,
            sysAcl,
            FALSE);

        if (!NT_SUCCESS(ntStatus))
            break;

        if (!RtlValidSecurityDescriptor(securityDescriptor))
            break;

        *SecurityDescriptor = securityDescriptor;

        if (Length)
            *Length = RtlLengthSecurityDescriptor(securityDescriptor);

    } while (FALSE);

    if (admSid != NULL) supHeapFree(admSid);
    if (sysSid != NULL) supHeapFree(sysSid);
    if (sysAcl != NULL) supHeapFree(sysAcl);

    if (!NT_SUCCESS(ntStatus)) {
        if (securityDescriptor != NULL)
            supHeapFree(securityDescriptor);
    }

    return ntStatus;
}

/*
* supGetTimeAsSecondsSince1970
*
* Purpose:
*
* Return seconds since 1970.
*
*/
ULONG supGetTimeAsSecondsSince1970(
    VOID
)
{
    LARGE_INTEGER fileTime;
    ULONG seconds = 0;

    GetSystemTimeAsFileTime((PFILETIME)&fileTime);
    RtlTimeToSecondsSince1970(&fileTime, &seconds);
    return seconds;
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
    _In_ LPWSTR FunctionName
)
{
    WCHAR szBuffer[512];

    _strcpy(szBuffer, TEXT("AbnormalTermination of "));
    _strcat(szBuffer, FunctionName);

    logAdd(WOBJ_LOG_ENTRY_ERROR,
        szBuffer);
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

    logAdd(WOBJ_LOG_ENTRY_ERROR,
        szBuffer);
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
    _In_ LPWSTR FunctionName,
    _In_ NTSTATUS NtStatus
)
{
    WCHAR szBuffer[512];

    RtlStringCchPrintfSecure(szBuffer,
        512,
        TEXT("%ws 0x%lX"),
        FunctionName,
        NtStatus);

    logAdd(WOBJ_LOG_ENTRY_ERROR,
        szBuffer);
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
    _In_ PVOID DriverBaseAddress)
{
    PLIST_ENTRY Entry, NextEntry, ListHead = &g_kdctx.KseEngineDump.ShimmedDriversDumpListHead;
    KSE_SHIMMED_DRIVER* ShimmedDriver;


    if (g_kdctx.KseEngineDump.Valid == FALSE)
        return FALSE;

    ASSERT_LIST_ENTRY_VALID_BOOLEAN(ListHead);

    if (IsListEmpty(ListHead))
        return FALSE;

    for (Entry = ListHead->Flink, NextEntry = Entry->Flink;
        Entry != ListHead;
        Entry = NextEntry, NextEntry = Entry->Flink)
    {
        ShimmedDriver = CONTAINING_RECORD(Entry, KSE_SHIMMED_DRIVER, ListEntry);
        if (DriverBaseAddress == ShimmedDriver->DriverBaseAddress)
            return TRUE;
    }

    return FALSE;
}

/*
* supDestroyShimmedDriversList
*
* Purpose:
*
* Remove all items from shimmed drivers list and free memory.
*
*/
VOID supDestroyShimmedDriversList(
    _In_ PLIST_ENTRY ListHead)
{
    PLIST_ENTRY Entry, NextEntry;
    KSE_SHIMMED_DRIVER* Item;

    ASSERT_LIST_ENTRY_VALID(ListHead);

    if (IsListEmpty(ListHead))
        return;

    for (Entry = ListHead->Flink, NextEntry = Entry->Flink;
        Entry != ListHead;
        Entry = NextEntry, NextEntry = Entry->Flink)
    {
        Item = CONTAINING_RECORD(Entry, KSE_SHIMMED_DRIVER, ListEntry);
        RemoveEntryList(Entry);
        supHeapFree(Item);
    }
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

    RtlZeroMemory(&ih, sizeof(HDITEM));
    RtlZeroMemory(&lvi, sizeof(LVITEM));

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
            f = CreateFile(FileName, GENERIC_WRITE | SYNCHRONIZE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (f != INVALID_HANDLE_VALUE)
            {
                WriteFile(f, buffer0, (DWORD)(total_lenght * sizeof(WCHAR)), &iobytes, NULL);
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
    _In_ LPWSTR FileName,
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
    _In_ LPWSTR lpText
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

        lpConvertedName = (LPWSTR)supHeapAlloc(UNICODE_STRING_MAX_CHARS + 1);
        if (lpConvertedName == NULL)
            break;

        sz = 0;
        lpDriverName = supGetItemText(hwndList, iPos, iFileNameColumn, &sz);
        if (lpDriverName == NULL)
            break;

        if (supGetWin32FileName(
            lpDriverName,
            lpConvertedName,
            UNICODE_STRING_MAX_CHARS))
        {
            supJumpToFile(lpConvertedName);
        }

    } while (FALSE);

    if (lpDriverName) supHeapFree(lpDriverName);
    if (lpConvertedName) supHeapFree(lpConvertedName);
}
