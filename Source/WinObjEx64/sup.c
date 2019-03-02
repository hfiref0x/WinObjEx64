/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       SUP.C
*
*  VERSION:     1.72
*
*  DATE:        09 Feb 2019
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
#include <cfgmgr32.h>
#include <setupapi.h>

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

//
// Dll path for known dlls.
//
LPWSTR	g_lpKnownDlls32;
LPWSTR	g_lpKnownDlls64;

#ifdef _DEBUG
ULONG g_cHeapAlloc = 0;
#endif

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

        _strcpy(szBuffer, L"Allocate buffer with size=");
        u64tostr((ULONG_PTR)Size, _strend(szBuffer));
        _strcat(szBuffer, L"\r\n");
        OutputDebugString(szBuffer);

        _strcpy(szBuffer, L"g_cHeapAlloc=");
        ultostr(x, _strend(szBuffer));
        _strcat(szBuffer, L"\r\n");
        OutputDebugString(szBuffer);
    }
    else {
        _strcpy(szBuffer, L"Allocate buffer with size=");
        u64tostr((ULONG_PTR)Size, _strend(szBuffer));
        _strcat(szBuffer, L"FAILED \r\n");
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
        _strcpy(szBuffer, L"Free buffer=0x");
        u64tohex((ULONG_PTR)Memory, _strend(szBuffer));
        _strcat(szBuffer, L"\r\n");
        OutputDebugString(szBuffer);

        _strcpy(szBuffer, L"g_cHeapAlloc=");
        ultostr(x, _strend(szBuffer));
        _strcat(szBuffer, L"\r\n");
        OutputDebugString(szBuffer);
    }
    else {
        _strcpy(szBuffer, L"Free buffer=0x");
        u64tohex((ULONG_PTR)Memory, _strend(szBuffer));
        _strcat(szBuffer, L" FAILED \r\n");
        OutputDebugString(szBuffer);
    }

    SetLastError(LastError);
    return bSuccess;
}
#endif

/*
* supVirtualAlloc
*
* Purpose:
*
* Wrapper for NtAllocateVirtualMemory.
*
*/
PVOID supVirtualAlloc(
    _In_ SIZE_T Size)
{
    NTSTATUS Status;
    PVOID Buffer = NULL;
    SIZE_T size;

    size = Size;
    Status = NtAllocateVirtualMemory(
        NtCurrentProcess(),
        &Buffer,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (NT_SUCCESS(Status)) {
        RtlSecureZeroMemory(Buffer, size);
        return Buffer;
    }

    SetLastError(RtlNtStatusToDosError(Status));
    return NULL;
}

/*
* supVirtualFree
*
* Purpose:
*
* Wrapper for NtFreeVirtualMemory.
*
*/
BOOL supVirtualFree(
    _In_ PVOID Memory)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    SIZE_T size = 0;

    if (Memory) {
        Status = NtFreeVirtualMemory(
            NtCurrentProcess(),
            &Memory,
            &size,
            MEM_RELEASE);
    }

    SetLastError(RtlNtStatusToDosError(Status));
    return NT_SUCCESS(Status);
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
    _Out_ ATOM *pTreeListAtom,
    _Out_ HWND *pTreeListHwnd
)
{
    ATOM     TreeListAtom;
    HWND     TreeList;
    HDITEM   hdritem;
    RECT     rc;

    if ((pTreeListAtom == NULL) || (pTreeListHwnd == NULL)) {
        return FALSE;
    }

    GetClientRect(hwndParent, &rc);
    TreeListAtom = InitializeTreeListControl();
    TreeList = CreateWindowEx(WS_EX_CLIENTEDGE, WC_TREELIST, NULL,
        WS_VISIBLE | WS_CHILD | WS_TABSTOP | TLSTYLE_COLAUTOEXPAND, 12, 20,
        rc.right - 24, rc.bottom - 30, hwndParent, NULL, NULL, NULL);

    if (TreeList == NULL) {
        UnregisterClass(MAKEINTATOM(TreeListAtom), g_WinObj.hInstance);
        *pTreeListHwnd = NULL;
        *pTreeListAtom = 0;
        return FALSE;
    }

    *pTreeListHwnd = TreeList;
    *pTreeListAtom = TreeListAtom;

    RtlSecureZeroMemory(&hdritem, sizeof(hdritem));
    hdritem.mask = HDI_FORMAT | HDI_TEXT | HDI_WIDTH;
    hdritem.fmt = HDF_LEFT | HDF_BITMAP_ON_RIGHT | HDF_STRING;
    hdritem.cxy = 220;
    hdritem.pszText = TEXT("Field");
    TreeList_InsertHeaderItem(TreeList, 0, &hdritem);
    hdritem.cxy = 130;
    hdritem.pszText = TEXT("Value");
    TreeList_InsertHeaderItem(TreeList, 1, &hdritem);
    hdritem.cxy = 200;
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
_Success_(return != FALSE)
BOOL supQueryObjectFromHandle(
    _In_ HANDLE hOject,
    _Out_ ULONG_PTR *Address,
    _Out_opt_ USHORT *TypeIndex
)
{
    BOOL   bFound = FALSE;
    ULONG_PTR i;
    DWORD  CurrentProcessId = GetCurrentProcessId();

    PSYSTEM_HANDLE_INFORMATION_EX pHandles;

    if (Address == NULL) {
        return bFound;
    }

    pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation);
    if (pHandles) {
        for (i = 0; i < pHandles->NumberOfHandles; i++) {
            if (pHandles->Handles[i].UniqueProcessId == (ULONG_PTR)CurrentProcessId) {
                if (pHandles->Handles[i].HandleValue == (ULONG_PTR)hOject) {
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
    _Out_ PUTable *Table
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
        s = (LPWSTR)supHeapAlloc((MAX_PATH * 2) + (_strlen(szHelpFile) * sizeof(WCHAR)));
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
    _Inout_ void *dest,
    _In_ size_t cbdest,
    _In_ const void *src,
    _In_ size_t cbsrc
)
{
    char *d = (char*)dest;
    char *s = (char*)src;

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
* supGetSystemInfo
*
* Purpose:
*
* Returns buffer with system information by given InfoClass.
*
* Returned buffer must be freed with supHeapFree after usage.
* Function will return error after 20 attempts.
*
*/
PVOID supGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS InfoClass
)
{
    INT         c = 0;
    PVOID       Buffer = NULL;
    ULONG       Size = 0x1000;
    NTSTATUS    status;
    ULONG       memIO;

    do {
        Buffer = supHeapAlloc((SIZE_T)Size);
        if (Buffer != NULL) {
            status = NtQuerySystemInformation(InfoClass, Buffer, Size, &memIO);
        }
        else {
            return NULL;
        }
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            supHeapFree(Buffer);
            Buffer = NULL;
            Size *= 2;
            c++;
            if (c > 20) {
                status = STATUS_SECRET_TOO_LONG;
                break;
            }
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (NT_SUCCESS(status)) {
        return Buffer;
    }

    if (Buffer) {
        supHeapFree(Buffer);
    }
    return NULL;
}

/*
* supGetObjectTypesInfo
*
* Purpose:
*
* Returns buffer with system types information.
*
* Returned buffer must be freed with supHeapFree after usage.
* Function will return error after 5 attempts.
*
*/
PVOID supGetObjectTypesInfo(
    VOID
)
{
    INT         c = 0;
    PVOID       Buffer = NULL;
    ULONG       Size = 0x2000;
    NTSTATUS    status;
    ULONG       memIO;

    do {
        Buffer = supHeapAlloc((SIZE_T)Size);
        if (Buffer != NULL) {
            status = NtQueryObject(NULL, ObjectTypesInformation, Buffer, Size, &memIO);
        }
        else {
            return NULL;
        }
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            supHeapFree(Buffer);
            Buffer = NULL;
            Size = memIO;
            c++;
            if (c > 5) {
                status = STATUS_SECRET_TOO_LONG;
                break;
            }
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (NT_SUCCESS(status)) {
        return Buffer;
    }

    if (Buffer) {
        supHeapFree(Buffer);
    }
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
    _Out_opt_ PSIZE_T lpSize
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
    _In_ LPWSTR pszText,
    _In_ UINT cbText
)
{
    LV_ITEM item;

    RtlSecureZeroMemory(&item, sizeof(item));

    item.iItem = nItem;
    item.iSubItem = nSubItem;
    item.pszText = pszText;
    item.cchTextMax = (SIZE_T)cbText;
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

    list = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, TYPE_LAST, 8);
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

        if (g_kdctx.IsWine) {
            pObject = OBJECT_TYPES_FIRST_ENTRY_WINE(g_pObjectTypesInfo);
        }
        else {
            pObject = OBJECT_TYPES_FIRST_ENTRY(g_pObjectTypesInfo);
        }

        for (i = 0; i < g_pObjectTypesInfo->NumberOfTypes; i++) {
            if (g_NtBuildNumber >= 9200) {
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
    __except (EXCEPTION_EXECUTE_HANDLER) {
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
        shinfo.nShow = SW_SHOW;
        if (g_WinObj.EnableExperimentalFeatures)
            shinfo.lpParameters = TEXT("-exp");
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
    BOOL     bResult = FALSE, cond = FALSE;
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

    } while (cond);

    if (AdministratorsGroup != NULL) {
        RtlFreeSid(AdministratorsGroup);
    }

    NtClose(hToken);
    return bResult;
}

/*
* supxIsSymlink
*
* Purpose:
*
* Tests if the current item type is Symbolic link.
*
*/
BOOL supxIsSymlink(
    _In_ HWND hwndList,
    _In_ INT iItem
)
{
    WCHAR ItemText[MAX_PATH + 1];
    RtlSecureZeroMemory(ItemText, sizeof(ItemText));
    ListView_GetItemText(hwndList, iItem, 1, ItemText, MAX_PATH);
    return (_strcmpi(ItemText, OBTYPE_NAME_SYMBOLIC_LINK) == 0);
}

/*
* supHandleTreePopupMenu
*
* Purpose:
*
* Object Tree popup menu builder.
*
*/
VOID supHandleTreePopupMenu(
    _In_ HWND hwnd,
    _In_ LPPOINT point
)
{
    HMENU hMenu;

    hMenu = CreatePopupMenu();
    if (hMenu) {
        InsertMenu(hMenu, 0, MF_BYCOMMAND, ID_OBJECT_PROPERTIES, T_PROPERTIES);

        supSetMenuIcon(hMenu, ID_OBJECT_PROPERTIES,
            (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 0));

        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, point->x, point->y, 0, hwnd, NULL);
        DestroyMenu(hMenu);
    }
}

/*
* supHandleObjectPopupMenu
*
* Purpose:
*
* Object List popup menu builder.
*
*/
VOID supHandleObjectPopupMenu(
    _In_ HWND hwnd,
    _In_ HWND hwndlv,
    _In_ INT iItem,
    _In_ LPPOINT point
)
{
    HMENU hMenu;
    UINT  uEnable = MF_BYCOMMAND | MF_GRAYED;

    hMenu = CreatePopupMenu();
    if (hMenu == NULL) return;

    InsertMenu(hMenu, 0, MF_BYCOMMAND, ID_OBJECT_PROPERTIES, T_PROPERTIES);

    supSetMenuIcon(hMenu, ID_OBJECT_PROPERTIES,
        (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ToolBarMenuImages, 0));

    if (supxIsSymlink(hwndlv, iItem)) {
        InsertMenu(hMenu, 1, MF_BYCOMMAND, ID_OBJECT_GOTOLINKTARGET, T_GOTOLINKTARGET);
        supSetMenuIcon(hMenu, ID_OBJECT_GOTOLINKTARGET,
            (ULONG_PTR)ImageList_ExtractIcon(g_WinObj.hInstance, g_ListViewImages, ID_FROM_VALUE(IDI_ICON_SYMLINK)));
        uEnable &= ~MF_GRAYED;
    }
    EnableMenuItem(GetSubMenu(GetMenu(hwnd), 2), ID_OBJECT_GOTOLINKTARGET, uEnable);

    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, point->x, point->y, 0, hwnd, NULL);
    DestroyMenu(hMenu);
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
    TBBUTTON tbButtons[5];

    RtlSecureZeroMemory(tbButtons, sizeof(tbButtons));

    tbButtons[0].iBitmap = 0;
    tbButtons[0].fsStyle = BTNS_BUTTON;
    tbButtons[0].idCommand = ID_OBJECT_PROPERTIES;
    tbButtons[0].fsState = TBSTATE_ENABLED;

    //separator
    tbButtons[1].fsStyle = BTNS_SEP;
    tbButtons[1].iBitmap = 10;

    tbButtons[2].iBitmap = 1;
    tbButtons[2].fsStyle = BTNS_BUTTON;
    tbButtons[2].idCommand = ID_VIEW_REFRESH;
    tbButtons[2].fsState = TBSTATE_ENABLED;

    //separator
    tbButtons[3].fsStyle = BTNS_SEP;
    tbButtons[3].iBitmap = 10;

    tbButtons[4].iBitmap = 2;
    tbButtons[4].fsStyle = BTNS_BUTTON;
    tbButtons[4].idCommand = ID_FIND_FINDOBJECT;
    tbButtons[4].fsState = TBSTATE_ENABLED;

    SendMessage(hWndToolbar, TB_SETIMAGELIST, 0, (LPARAM)g_ToolBarMenuImages);
    SendMessage(hWndToolbar, TB_LOADIMAGES, (WPARAM)IDB_STD_SMALL_COLOR, (LPARAM)HINST_COMMCTRL);

    SendMessage(hWndToolbar, TB_BUTTONSTRUCTSIZE,
        (WPARAM)sizeof(TBBUTTON), 0);
    SendMessage(hWndToolbar, TB_ADDBUTTONS, (WPARAM)4 + 1,
        (LPARAM)&tbButtons);

    SendMessage(hWndToolbar, TB_AUTOSIZE, 0, 0);
}

/*
* supxQueryKnownDllsLink
*
* Purpose:
*
* Expand KnownDlls symbolic link.
*
* Returns FALSE on any error.
*
*/
BOOL supxQueryKnownDllsLink(
    _In_ PUNICODE_STRING ObjectName,
    _In_ PVOID *lpKnownDllsBuffer
)
{
    BOOL                bResult = FALSE, cond = FALSE;
    HANDLE              hLink = NULL;
    SIZE_T              memIO;
    ULONG               bytesNeeded;
    NTSTATUS            status;
    UNICODE_STRING      KnownDlls;
    OBJECT_ATTRIBUTES   Obja;
    LPWSTR              lpDataBuffer = NULL;

    do {
        InitializeObjectAttributes(&Obja, ObjectName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = NtOpenSymbolicLinkObject(&hLink, SYMBOLIC_LINK_QUERY, &Obja);
        if (!NT_SUCCESS(status))
            break;

        KnownDlls.Buffer = NULL;
        KnownDlls.Length = 0;
        KnownDlls.MaximumLength = 0;
        bytesNeeded = 0;
        status = NtQuerySymbolicLinkObject(hLink, &KnownDlls, &bytesNeeded);
        if ((status != STATUS_BUFFER_TOO_SMALL) || (bytesNeeded == 0))
            break;

        if (bytesNeeded >= MAX_USTRING) {
            bytesNeeded = MAX_USTRING - sizeof(UNICODE_NULL);
        }

        memIO = bytesNeeded + sizeof(UNICODE_NULL);
        lpDataBuffer = (LPWSTR)supHeapAlloc(memIO);
        if (lpKnownDllsBuffer) {
            KnownDlls.Buffer = lpDataBuffer;
            KnownDlls.Length = (USHORT)bytesNeeded;
            KnownDlls.MaximumLength = (USHORT)bytesNeeded + sizeof(UNICODE_NULL);
            bResult = NT_SUCCESS(NtQuerySymbolicLinkObject(hLink, &KnownDlls, NULL));
            if (bResult) {
                *lpKnownDllsBuffer = lpDataBuffer;
            }
        }

    } while (cond);
    if (hLink != NULL) NtClose(hLink);
    return bResult;
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
    supQueryKnownDlls();
    kdInit(IsFullAdmin);

    if (IsFullAdmin) {
        supCreateSCMSnapshot(SERVICE_DRIVER, NULL);
    }

    sapiCreateSetupDBSnapshot();
    g_pObjectTypesInfo = (POBJECT_TYPES_INFORMATION)supGetObjectTypesInfo();

    ExApiSetInit();
}

/*
* supShutdown
*
* Purpose:
*
* Free support subset related resources.
*
* Must be called once in the end of program execution.
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
    if (g_lpKnownDlls32) supHeapFree(g_lpKnownDlls32);
    if (g_lpKnownDlls64) supHeapFree(g_lpKnownDlls64);
    if (g_pSDT) supHeapFree(g_pSDT);
    if (g_pSDTShadow) supHeapFree(g_pSDTShadow);
}

/*
* supQueryKnownDlls
*
* Purpose:
*
* Expand KnownDlls to global variables.
*
*/
VOID supQueryKnownDlls(
    VOID
)
{
    UNICODE_STRING KnownDlls;

    g_lpKnownDlls32 = NULL;
    g_lpKnownDlls64 = NULL;

    RtlInitUnicodeString(&KnownDlls, L"\\KnownDlls32\\KnownDllPath");
    supxQueryKnownDllsLink(&KnownDlls, (PVOID*)&g_lpKnownDlls32);
    RtlInitUnicodeString(&KnownDlls, L"\\KnownDlls\\KnownDllPath");
    supxQueryKnownDllsLink(&KnownDlls, (PVOID*)&g_lpKnownDlls64);
}

/*
* supEnablePrivilege
*
* Purpose:
*
* Enable/Disable given privilege.
*
* Return FALSE on any error.
*
*/
BOOL supEnablePrivilege(
    _In_ DWORD PrivilegeName,
    _In_ BOOL fEnable
)
{
    BOOL             bResult = FALSE;
    NTSTATUS         status;
    ULONG            dummy;
    HANDLE           hToken;
    TOKEN_PRIVILEGES TokenPrivileges;

    status = NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &hToken);

    if (!NT_SUCCESS(status)) {
        return bResult;
    }

    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Luid.LowPart = PrivilegeName;
    TokenPrivileges.Privileges[0].Luid.HighPart = 0;
    TokenPrivileges.Privileges[0].Attributes = (fEnable) ? SE_PRIVILEGE_ENABLED : 0;
    status = NtAdjustPrivilegesToken(hToken, FALSE, &TokenPrivileges,
        sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PULONG)&dummy);
    if (status == STATUS_NOT_ALL_ASSIGNED) {
        status = STATUS_PRIVILEGE_NOT_HELD;
    }
    bResult = NT_SUCCESS(status);
    NtClose(hToken);
    return bResult;
}

/*
* supQueryLinkTarget
*
* Purpose:
*
* Copying in the input buffer target of a symbolic link.
*
* Return FALSE on any error.
*
*/
BOOL supQueryLinkTarget(
    _In_opt_ HANDLE hRootDirectory,
    _In_ PUNICODE_STRING ObjectName,
    _Inout_ LPWSTR Buffer,
    _In_ DWORD cbBuffer //size of buffer in bytes
)
{
    BOOL                bResult = FALSE;
    HANDLE              hLink = NULL;
    DWORD               cLength = 0;
    NTSTATUS            status;
    UNICODE_STRING      InfoString;
    OBJECT_ATTRIBUTES   Obja;

    if ((cbBuffer == 0) || (Buffer == NULL)) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return bResult;
    }

    InitializeObjectAttributes(&Obja, ObjectName, OBJ_CASE_INSENSITIVE, hRootDirectory, NULL);
    status = NtOpenSymbolicLinkObject(&hLink, SYMBOLIC_LINK_QUERY, &Obja);
    if (!NT_SUCCESS(status) || (hLink == NULL)) {
        return bResult;
    }

    cLength = (DWORD)(cbBuffer - sizeof(UNICODE_NULL));
    if (cLength >= MAX_USTRING) {
        cLength = MAX_USTRING - sizeof(UNICODE_NULL);
    }

    InfoString.Buffer = Buffer;
    InfoString.Length = (USHORT)cLength;
    InfoString.MaximumLength = (USHORT)(cLength + sizeof(UNICODE_NULL));

    status = NtQuerySymbolicLinkObject(hLink, &InfoString, NULL);
    bResult = (NT_SUCCESS(status));
    NtClose(hLink);
    return bResult;
}

/*
* supQueryProcessName
*
* Purpose:
*
* Lookups process name by given process ID.
*
* If nothing found return FALSE.
*
*/
BOOL supQueryProcessName(
    _In_ ULONG_PTR dwProcessId,
    _In_ PVOID ProcessList,
    _Inout_ LPWSTR Buffer,
    _In_ DWORD ccBuffer //size of buffer in chars
)
{
    ULONG NextEntryDelta = 0;
    union {
        PSYSTEM_PROCESSES_INFORMATION Processes;
        PBYTE ListRef;
    } List;

    List.ListRef = (PBYTE)ProcessList;

    do {

        List.ListRef += NextEntryDelta;

        if ((ULONG_PTR)List.Processes->UniqueProcessId == dwProcessId) {

            _strncpy(
                Buffer,
                ccBuffer,
                List.Processes->ImageName.Buffer,
                List.Processes->ImageName.Length / sizeof(WCHAR));

            return TRUE;
        }

        NextEntryDelta = List.Processes->NextEntryDelta;

    } while (NextEntryDelta);

    return FALSE;
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
    OBEX_PROCESS_LOOKUP_ENTRY *SavedProcessList;
    PSYSTEM_HANDLE_INFORMATION_EX pHandles;

    union {
        PSYSTEM_PROCESSES_INFORMATION Processes;
        PBYTE ListRef;
    } List;

    OBJECT_ATTRIBUTES obja = RTL_INIT_OBJECT_ATTRIBUTES((PUNICODE_STRING)NULL, 0);

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
    NextEntryDelta = 0;

    //
    // Build process handle list.
    //
    SavedProcessList = (OBEX_PROCESS_LOOKUP_ENTRY*)supHeapAlloc(NumberOfProcesses * sizeof(OBEX_PROCESS_LOOKUP_ENTRY));
    if (SavedProcessList) {

        do {
            List.ListRef += NextEntryDelta;

            if (List.Processes->ThreadCount) {

                if (NT_SUCCESS(NtOpenProcess(
                    &hProcess,
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    &obja,
                    &List.Processes->Threads[0].ClientId)))
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
        pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation);
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
    _Out_opt_ SCMDB *Snapshot
)
{
    BOOL      cond = FALSE, bResult = FALSE;
    SC_HANDLE schSCManager;
    DWORD     dwBytesNeeded = 0, dwServicesReturned = 0, dwSize;
    PVOID     Services = NULL;

    do {
        schSCManager = OpenSCManager(NULL,
            NULL,
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE
        );

        if (schSCManager == NULL)
            break;

        //
        // Query required memory size for snapshot.
        //
        dwSize = PAGE_SIZE;
        Services = supVirtualAlloc(dwSize);
        if (Services == NULL)
            break;

        bResult = EnumServicesStatusEx(
            schSCManager,
            SC_ENUM_PROCESS_INFO,
            ServiceType,
            SERVICE_STATE_ALL,
            (LPBYTE)Services,
            dwSize,
            &dwBytesNeeded,
            &dwServicesReturned,
            NULL,
            NULL);

        if (bResult == FALSE) {
            if (GetLastError() == ERROR_MORE_DATA) {
                //
                // Allocate required buffer.
                //
                supVirtualFree(Services);
                dwSize = (DWORD)ALIGN_UP_BY(dwBytesNeeded + sizeof(ENUM_SERVICE_STATUS_PROCESS), PAGE_SIZE);
                Services = supVirtualAlloc(dwSize);
                if (Services == NULL)
                    break;

                bResult = EnumServicesStatusEx(
                    schSCManager,
                    SC_ENUM_PROCESS_INFO,
                    ServiceType,
                    SERVICE_STATE_ALL,
                    (LPBYTE)Services,
                    dwSize,
                    &dwBytesNeeded,
                    &dwServicesReturned,
                    NULL,
                    NULL);

                if (!bResult) {
                    supVirtualFree(Services);
                    Services = NULL;
                    dwServicesReturned = 0;
                    break;
                }
            } //ERROR_MORE_DATA
        } //bResult == FALSE;

        CloseServiceHandle(schSCManager);

    } while (cond);

    if (Snapshot) {
        Snapshot->Entries = Services;
        Snapshot->NumberOfEntries = dwServicesReturned;
    }
    else {
        RtlEnterCriticalSection(&g_WinObj.Lock);
        g_scmDB.Entries = Services;
        g_scmDB.NumberOfEntries = dwServicesReturned;
        RtlLeaveCriticalSection(&g_WinObj.Lock);
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
    _In_opt_ SCMDB *Snapshot)
{
    if (Snapshot) {
        if ((Snapshot->Entries) && (Snapshot->NumberOfEntries))
            supVirtualFree(Snapshot->Entries);
        Snapshot->NumberOfEntries = 0;
        Snapshot->Entries = NULL;
    }
    else {
        RtlEnterCriticalSection(&g_WinObj.Lock);
        supVirtualFree(g_scmDB.Entries);
        g_scmDB.Entries = NULL;
        g_scmDB.NumberOfEntries = 0;
        RtlLeaveCriticalSection(&g_WinObj.Lock);
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
    _In_ SP_DEVINFO_DATA *pDevInfoData,
    _In_ ULONG Property,
    _Out_ LPWSTR *PropertyBuffer,
    _Out_opt_ ULONG *PropertyBufferSize
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

    RtlSetHeapInformation(Heap, HeapEnableTerminationOnCorruption, NULL, 0);
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
    RtlEnterCriticalSection(&g_WinObj.Lock);
    RtlDestroyHeap(g_sapiDB.sapiHeap);
    g_sapiDB.sapiHeap = NULL;
    g_sapiDB.ListHead.Blink = NULL;
    g_sapiDB.ListHead.Flink = NULL;
    RtlLeaveCriticalSection(&g_WinObj.Lock);
}

/*
* supEnumEnableChildWindows
*
* Purpose:
*
* Makes window controls visible in the given rectangle type dialog
*
*/
BOOL WINAPI supEnumEnableChildWindows(
    _In_ HWND hwnd,
    _In_ LPARAM lParam
)
{
    RECT   r1;
    LPRECT lpRect = (LPRECT)lParam;

    if (GetWindowRect(hwnd, &r1)) {
        if (PtInRect(lpRect, *(POINT*)&r1))
            ShowWindow(hwnd, SW_SHOW);
    }
    return TRUE;
}

/*
* supEnumHideChildWindows
*
* Purpose:
*
* Makes window controls invisible in the given rectangle type dialog
*
*/
BOOL WINAPI supEnumHideChildWindows(
    _In_ HWND hwnd,
    _In_ LPARAM lParam
)
{
    RECT   r1;
    LPRECT lpRect = (LPRECT)lParam;

    if (GetWindowRect(hwnd, &r1)) {
        if (PtInRect(lpRect, *(POINT*)&r1))
            ShowWindow(hwnd, SW_HIDE);
    }
    return TRUE;
}

#define T_WINSTA_SYSTEM L"-0x0-3e7$"
#define T_WINSTA_ANONYMOUS L"-0x0-3e6$"
#define T_WINSTA_LOCALSERVICE L"-0x0-3e5$"
#define T_WINSTA_NETWORK_SERVICE L"-0x0-3e4$"

typedef struct _WINSTA_DESC_ARRAY {
    LPWSTR lpszWinSta;
    LPWSTR lpszDesc;
} WINSTA_DESC_ARRAY, *PWINSTA_DESC_ARRAY;

#define MAX_KNOWN_WINSTA_DESCRIPTIONS 4

WINSTA_DESC_ARRAY g_WinstaDescArray[MAX_KNOWN_WINSTA_DESCRIPTIONS] = {
    { T_WINSTA_SYSTEM, L"System" },
    { T_WINSTA_ANONYMOUS, L"Anonymous" },
    { T_WINSTA_LOCALSERVICE, L"Local Service" },
    { T_WINSTA_NETWORK_SERVICE, L"Network Service" }
};

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

/*
* supFindModuleEntryByName
*
* Purpose:
*
* Find Module entry for given name.
*
*/
PVOID supFindModuleEntryByName(
    _In_ PRTL_PROCESS_MODULES pModulesList,
    _In_ LPCSTR ModuleName
)
{
    ULONG i, c, off;
    LPSTR pModuleName;

    c = pModulesList->NumberOfModules;
    if (c == 0) {
        return NULL;
    }

    for (i = 0; i < c; i++) {
        off = pModulesList->Modules[i].OffsetToFileName;
        pModuleName = (LPSTR)&pModulesList->Modules[i].FullPathName[off];
        if (pModuleName) {

            if (_strcmpi_a(pModuleName, ModuleName) == 0)
                return &pModulesList->Modules[i];

        }
    }
    return NULL;
}

/*
* supFindModuleEntryByAddress
*
* Purpose:
*
* Find Module Entry for given Address.
*
*/
ULONG supFindModuleEntryByAddress(
    _In_ PRTL_PROCESS_MODULES pModulesList,
    _In_ PVOID Address
)
{
    ULONG i, c;

    c = pModulesList->NumberOfModules;
    if (c == 0) {
        return (ULONG)-1;
    }

    for (i = 0; i < c; i++) {
        if (
            IN_REGION(Address,
                pModulesList->Modules[i].ImageBase,
                pModulesList->Modules[i].ImageSize)
            )
        {
            return i;
        }
    }
    return (ULONG)-1;
}

/*
* supFindModuleNameByAddress
*
* Purpose:
*
* Find Module Name for given Address.
*
* Buffer must be at least MAX_PATH length.
*
*/
BOOL supFindModuleNameByAddress(
    _In_ PRTL_PROCESS_MODULES pModulesList,
    _In_ PVOID Address,
    _Inout_	LPWSTR Buffer,
    _In_ DWORD ccBuffer //size of buffer in chars
)
{
    ULONG i, c;
    WCHAR szBuffer[MAX_PATH + 1];

    PRTL_PROCESS_MODULE_INFORMATION pModule;

    if ((pModulesList == NULL) ||
        (Buffer == NULL) ||
        (ccBuffer < MAX_PATH))
    {
        return FALSE;
    }

    c = pModulesList->NumberOfModules;
    if (c == 0) {
        return FALSE;
    }

    for (i = 0; i < c; i++) {
        if (
            IN_REGION(Address,
                pModulesList->Modules[i].ImageBase,
                pModulesList->Modules[i].ImageSize)
            )
        {
            pModule = &pModulesList->Modules[i];

            RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));

            if (
                MultiByteToWideChar(CP_ACP, 0,
                (LPCSTR)&pModule->FullPathName[pModule->OffsetToFileName],
                    sizeof(pModule->FullPathName),
                    szBuffer,
                    MAX_PATH)
                )
            {
                _strncpy(Buffer, ccBuffer, szBuffer, _strlen(szBuffer));
                return TRUE;
            }
            else { //MultiByteToWideChar error
                return FALSE;
            }
        }
    }
    return FALSE;
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

        if (g_kdctx.IsWine) {
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
    __except (EXCEPTION_EXECUTE_HANDLER) {
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

        RtlEnterCriticalSection(&g_WinObj.Lock);

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

        RtlLeaveCriticalSection(&g_WinObj.Lock);

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
    BOOL    bResult, cond = FALSE;
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
            lRet = RegQueryValueEx(hKey, L"ImagePath", NULL, NULL, (LPBYTE)szImagePath, &dwSize);
            RegCloseKey(hKey);

            if (ERROR_SUCCESS == lRet) {

                dwHandle = 0;
                dwSize = GetFileVersionInfoSize(szImagePath, &dwHandle);
                if (dwSize == 0)
                    break;

                // allocate memory for version_info structure
                vinfo = supHeapAlloc(dwSize);
                if (vinfo == NULL)
                    break;

                // query it from file
                if (!GetFileVersionInfo(szImagePath, 0, dwSize, vinfo))
                    break;

                // query codepage and language id info
                dwSize = 0;
                if (!VerQueryValue(vinfo, VERSION_TRANSLATION, (LPVOID*)&lpTranslate, (PUINT)&dwSize))
                    break;

                if (dwSize == 0)
                    break;

                // query filedescription from file with given codepage & language id
                RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
                wsprintf(szBuffer, VERSION_DESCRIPTION,
                    lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);

                // finally query pointer to version_info filedescription block data
                lpDisplayName = NULL;
                dwSize = 0;
                bResult = VerQueryValue(vinfo, szBuffer, (LPVOID*)&lpDisplayName, (PUINT)&dwSize);
                if (bResult) {
                    _strncpy(Buffer, ccBuffer, lpDisplayName, dwSize);
                }

            }

        } while (cond);

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
    _In_opt_ HANDLE hRootDirectory,
    _In_ PUNICODE_STRING ObjectName,
    _Inout_ LPWSTR Buffer,
    _In_ DWORD ccBuffer //size of buffer in chars
)
{
    BOOL                        bResult, cond = FALSE;
    HANDLE                      hSection;
    PVOID                       vinfo;
    LPWSTR                      pcValue, lpszFileName, lpszKnownDlls;
    LPTRANSLATE                 lpTranslate;
    SIZE_T                      cLength = 0;
    NTSTATUS                    status;
    DWORD                       dwHandle = 0, dwSize, dwInfoSize;
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
    lpszFileName = NULL;
    hSection = NULL;
    lpszKnownDlls = NULL;

    do {
        //oleaut32.dll does not have FileDescription

        //  open section with query access
        InitializeObjectAttributes(&Obja, ObjectName, OBJ_CASE_INSENSITIVE, hRootDirectory, NULL);
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

        // select proper decoded KnownDlls path
        if (sii.Machine == IMAGE_FILE_MACHINE_I386) {
            lpszKnownDlls = g_lpKnownDlls32;
        }
        else if (sii.Machine == IMAGE_FILE_MACHINE_AMD64) {
            lpszKnownDlls = g_lpKnownDlls64;
        }

        // paranoid
        if (lpszKnownDlls == NULL) {
            RtlSecureZeroMemory(szQueryBlock, sizeof(szQueryBlock));
            _strcpy(szQueryBlock, g_WinObj.szSystemDirectory);
            lpszKnownDlls = szQueryBlock;
        }

        // allocate memory buffer to store full filename
        // KnownDlls + \\ + Object->Name + \0 
        cLength = (2 + _strlen(lpszKnownDlls) + _strlen(ObjectName->Buffer)) * sizeof(WCHAR);
        lpszFileName = (LPWSTR)supHeapAlloc(cLength);
        if (lpszFileName == NULL)
            break;

        // construct target filepath
        _strcpy(lpszFileName, lpszKnownDlls);
        _strcat(lpszFileName, L"\\");
        _strcat(lpszFileName, ObjectName->Buffer);

        // query size of version info
        dwSize = GetFileVersionInfoSize(lpszFileName, &dwHandle);
        if (dwSize == 0)
            break;

        // allocate memory for version_info structure
        vinfo = supHeapAlloc(dwSize);
        if (vinfo == NULL)
            break;

        // query it from file
        if (!GetFileVersionInfo(lpszFileName, 0, dwSize, vinfo))
            break;

        // query codepage and language id info
        if (!VerQueryValue(vinfo, VERSION_TRANSLATION, (LPVOID*)&lpTranslate, (PUINT)&dwInfoSize))
            break;
        if (dwInfoSize == 0)
            break;

        // query filedescription from file with given codepage & language id
        RtlSecureZeroMemory(szQueryBlock, sizeof(szQueryBlock));
        wsprintf(szQueryBlock, VERSION_DESCRIPTION,
            lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);

        // finally query pointer to version_info filedescription block data
        pcValue = NULL;
        dwInfoSize = 0;
        bResult = VerQueryValue(vinfo, szQueryBlock, (LPVOID*)&pcValue, (PUINT)&dwInfoSize);
        if (bResult) {
            _strncpy(Buffer, ccBuffer, pcValue, dwInfoSize);
        }

    } while (cond);

    if (hSection) NtClose(hSection);
    if (vinfo) supHeapFree(vinfo);
    if (lpszFileName) supHeapFree(lpszFileName);
    return bResult;
}

/*
* supOpenDirectory
*
* Purpose:
*
* Open directory handle with DIRECTORY_QUERY access
*
*/
HANDLE supOpenDirectory(
    _In_ LPWSTR lpDirectory
)
{
    HANDLE            hDirectory = NULL;
    UNICODE_STRING    ustr;
    OBJECT_ATTRIBUTES obja;

    RtlInitUnicodeString(&ustr, lpDirectory);
    InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);

    if (!NT_SUCCESS(NtOpenDirectoryObject(
        &hDirectory,
        DIRECTORY_QUERY,
        &obja)))
    {
        return NULL;
    }

    return hDirectory;
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
    hDirectory = supOpenDirectory(LookupDirName);

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
* Display SaveDialog
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
* supWriteBufferToFile
*
* Purpose:
*
* Create new file and write buffer to it.
*
*/
SIZE_T supWriteBufferToFile(
    _In_ PWSTR lpFileName,
    _In_ PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOL Flush,
    _In_ BOOL Append
)
{
    NTSTATUS           Status;
    DWORD              dwFlag;
    HANDLE             hFile = NULL;
    OBJECT_ATTRIBUTES  attr;
    UNICODE_STRING     NtFileName;
    IO_STATUS_BLOCK    IoStatus;
    LARGE_INTEGER      Position;
    ACCESS_MASK        DesiredAccess;
    PLARGE_INTEGER     pPosition = NULL;
    ULONG_PTR          nBlocks, BlockIndex;
    ULONG              BlockSize, RemainingSize;
    PBYTE              ptr = (PBYTE)Buffer;
    SIZE_T             BytesWritten = 0;

    if (RtlDosPathNameToNtPathName_U(lpFileName, &NtFileName, NULL, NULL) == FALSE)
        return 0;

    DesiredAccess = FILE_WRITE_ACCESS | SYNCHRONIZE;
    dwFlag = FILE_OVERWRITE_IF;

    if (Append != FALSE) {
        DesiredAccess |= FILE_READ_ACCESS;
        dwFlag = FILE_OPEN_IF;
    }

    InitializeObjectAttributes(&attr, &NtFileName, OBJ_CASE_INSENSITIVE, 0, NULL);

    __try {
        Status = NtCreateFile(&hFile, DesiredAccess, &attr,
            &IoStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, dwFlag,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

        if (!NT_SUCCESS(Status))
            __leave;

        pPosition = NULL;

        if (Append) {
            Position.LowPart = FILE_WRITE_TO_END_OF_FILE;
            Position.HighPart = -1;
            pPosition = &Position;
        }

        if (Size < 0x80000000) {
            BlockSize = (ULONG)Size;
            Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, BlockSize, pPosition, NULL);
            if (!NT_SUCCESS(Status))
                __leave;

            BytesWritten += IoStatus.Information;
        }
        else {
            BlockSize = 0x7FFFFFFF;
            nBlocks = (Size / BlockSize);
            for (BlockIndex = 0; BlockIndex < nBlocks; BlockIndex++) {

                Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, BlockSize, pPosition, NULL);
                if (!NT_SUCCESS(Status))
                    __leave;

                ptr += BlockSize;
                BytesWritten += IoStatus.Information;
            }
            RemainingSize = (ULONG)(Size % BlockSize);
            if (RemainingSize != 0) {
                Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, RemainingSize, pPosition, NULL);
                if (!NT_SUCCESS(Status))
                    __leave;
                BytesWritten += IoStatus.Information;
            }
        }
    }
    __finally {
        if (hFile != NULL) {
            if (Flush != FALSE) NtFlushBuffersFile(hFile, &IoStatus);
            NtClose(hFile);
        }
        RtlFreeUnicodeString(&NtFileName);
    }
    return BytesWritten;
}

/*
* supCreateSzGripWindow
*
* Purpose:
*
* Create size grip and attach it to owner window.
*
*/
HWND supCreateSzGripWindow(
    _In_ HWND hwndOwner
)
{
    HWND hwnd;
    RECT clientRect;

    GetClientRect(hwndOwner, &clientRect);
    clientRect.left = clientRect.right - GRIPPER_SIZE;
    clientRect.top = clientRect.bottom - GRIPPER_SIZE;

    hwnd = CreateWindowEx(0, WC_SCROLLBAR, NULL,
        WS_CHILD | WS_VISIBLE | SBS_SIZEGRIP | WS_CLIPSIBLINGS,
        clientRect.left, clientRect.top,
        GRIPPER_SIZE, GRIPPER_SIZE, hwndOwner, NULL, g_WinObj.hInstance, NULL);

    return hwnd;
}

/*
* supSzGripWindowOnResize
*
* Purpose:
*
* Must be called in WM_SIZE for sizegrip window proper reposition.
*
*/
VOID supSzGripWindowOnResize(
    _In_ HWND hwndOwner,
    _In_ HWND hwndSizeGrip
)
{
    RECT clientRect;

    GetClientRect(hwndOwner, &clientRect);
    SetWindowPos(hwndSizeGrip, NULL,
        clientRect.right - GRIPPER_SIZE, clientRect.bottom - GRIPPER_SIZE,
        GRIPPER_SIZE, GRIPPER_SIZE,
        SWP_NOZORDER | SWP_SHOWWINDOW);
}

/*
* supIsProcess32bit
*
* Purpose:
*
* Return TRUE if process is wow64.
*
*/
BOOL supIsProcess32bit(
    _In_ HANDLE hProcess
)
{
    NTSTATUS                           status;
    ULONG                              returnLength;
    PROCESS_EXTENDED_BASIC_INFORMATION pebi;

    RtlSecureZeroMemory(&pebi, sizeof(pebi));
    pebi.Size = sizeof(PROCESS_EXTENDED_BASIC_INFORMATION);

    status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pebi,
        sizeof(pebi),
        &returnLength);

    if (NT_SUCCESS(status)) {
        return (pebi.IsWow64Process == 1);
    }
    return FALSE;
}

/*
* supQuerySystemRangeStart
*
* Purpose:
*
* Return MmSystemRangeStart value.
*
*/
ULONG_PTR supQuerySystemRangeStart(
    VOID
)
{
    NTSTATUS  status;
    ULONG_PTR SystemRangeStart = 0;
    ULONG     memIO = 0;

    status = NtQuerySystemInformation(
        SystemRangeStartInformation,
        (PVOID)&SystemRangeStart,
        sizeof(ULONG_PTR),
        &memIO);

    if (!NT_SUCCESS(status)) {
        SetLastError(RtlNtStatusToDosError(status));
    }
    return SystemRangeStart;
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
    WCHAR  *p = szTemp;
    SIZE_T  l = 0, k = 0;

    if ((NtFileName == NULL) || (DosFileName == NULL) || (ccDosFileName < 4))
        return bSuccess;

    _strcpy(szDrive, TEXT(" :"));
    RtlSecureZeroMemory(szTemp, sizeof(szTemp));
    if (GetLogicalDriveStrings(DBUFFER_SIZE - 1, szTemp)) {
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
                        _strncpy(&DosFileName[l], ccDosFileName - l, NtFileName + uNameLen, k - uNameLen);

                        bSuccess = TRUE;
                        break;
                    }
                }
            }
            while (*p++);
        } while (!bFound && *p); // end of string
    }
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
    BOOL                bCond = FALSE, bResult = FALSE;
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    HANDLE              hFile = NULL;
    UNICODE_STRING      NtFileName;
    OBJECT_ATTRIBUTES   obja;
    IO_STATUS_BLOCK     iost;
    ULONG               memIO;
    BYTE               *Buffer = NULL;

    if ((Win32FileName == NULL) || (ccWin32FileName < MAX_PATH)) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    do {

        RtlInitUnicodeString(&NtFileName, FileName);
        InitializeObjectAttributes(&obja, &NtFileName, OBJ_CASE_INSENSITIVE, 0, NULL);

        status = NtCreateFile(&hFile, SYNCHRONIZE, &obja, &iost, NULL, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
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

    } while (bCond);

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
BOOL supIsWine(
    VOID
)
{
    HMODULE hNtdll;
    FARPROC  WineVersion = NULL;

    hNtdll = GetModuleHandle(TEXT("ntdll.dll"));

    if (hNtdll) {
        WineVersion = (FARPROC)GetProcAddress(hNtdll, "wine_get_version");
        if (WineVersion != NULL)
            return TRUE;
    }

    return FALSE;
}

/*
* supQuerySecureBootState
*
* Purpose:
*
* Query Firmware type and SecureBoot state if firmware is EFI.
*
*/
BOOL supQuerySecureBootState(
    _In_ PBOOLEAN pbSecureBoot
)
{
    BOOL    bResult = FALSE;
    BOOLEAN bSecureBoot = FALSE;
    HKEY    hKey;
    DWORD   dwState, dwSize, returnLength;
    LSTATUS lRet;

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
    _Out_ UNICODE_STRING *pusWinstaName
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
    _In_ PROP_OBJECT_INFO *Context,
    _In_ BOOL fInherit,
    _In_ ACCESS_MASK dwDesiredAccess)
{
    HWINSTA hObject = NULL;
    UNICODE_STRING CurrentWinstaDir;
    UNICODE_STRING WinstaDir;

    DWORD LastError = ERROR_SUCCESS;

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
* supOpenWindowStationFromContextEx
*
* Purpose:
*
* Open Window station bypass session check.
*
*/
HWINSTA supOpenWindowStationFromContextEx(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ BOOL fInherit,
    _In_ ACCESS_MASK dwDesiredAccess)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    HWINSTA hObject = NULL;
    HANDLE hRootDirectory = NULL;
    UNICODE_STRING CurrentWinstaDir;
    UNICODE_STRING WinstaDir;
    UNICODE_STRING WinstaName;
    OBJECT_ATTRIBUTES obja;

    if (supxGetWindowStationName(&CurrentWinstaDir)) {
        
        //
        // Same session, open as usual.
        //
        RtlInitUnicodeString(&WinstaDir, Context->lpCurrentObjectPath);
        if (RtlEqualUnicodeString(&WinstaDir, &CurrentWinstaDir, TRUE)) {
            hObject = OpenWindowStation(Context->lpObjectName, fInherit, dwDesiredAccess);
            if (hObject)
                Status = STATUS_SUCCESS;
        }
        else {
            
            //
            // Different session, use NtUserOpenWindowStation (doesn't work in Windows 10).
            //
            InitializeObjectAttributes(&obja, &WinstaDir, OBJ_CASE_INSENSITIVE, NULL, NULL);
            Status = NtOpenDirectoryObject(&hRootDirectory,
                DIRECTORY_TRAVERSE,
                &obja);
            
            if (NT_SUCCESS(Status)) {
                
                RtlInitUnicodeString(&WinstaName, Context->lpObjectName);
                InitializeObjectAttributes(&obja, &WinstaName, OBJ_CASE_INSENSITIVE, hRootDirectory, NULL);
                
                if (fInherit)
                    obja.Attributes |= OBJ_INHERIT;
                
                hObject = g_ExtApiSet.NtUserOpenWindowStation(&obja, dwDesiredAccess);

                Status = RtlGetLastNtStatus();
                NtClose(hRootDirectory);
            }
        }
        RtlFreeUnicodeString(&CurrentWinstaDir);
    }
    SetLastError(RtlNtStatusToDosErrorNoTeb(Status));
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
    BOOL                            bCond = FALSE, bResult = FALSE;
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

    } while (bCond);

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
    _In_ HANDLE hProcessToken
)
{
    PSID result = NULL;
    PTOKEN_USER ptu;
    NTSTATUS status;
    ULONG LengthNeeded = 0;

    status = NtQueryInformationToken(hProcessToken, TokenUser,
        NULL, 0, &LengthNeeded);

    if (status == STATUS_BUFFER_TOO_SMALL) {

        ptu = (PTOKEN_USER)supHeapAlloc(LengthNeeded);

        if (ptu) {

            status = NtQueryInformationToken(hProcessToken, TokenUser,
                ptu, LengthNeeded, &LengthNeeded);

            if (NT_SUCCESS(status)) {
                LengthNeeded = SECURITY_MAX_SID_SIZE;
                result = supHeapAlloc(LengthNeeded);
                if (result) {
                    status = RtlCopySid(LengthNeeded, result, ptu->User.Sid);
                }
            }

            supHeapFree(ptu);
        }
    }

    return (NT_SUCCESS(status)) ? result : NULL;
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
    _In_ HANDLE hProcess
)
{
    HANDLE hProcessToken = NULL;
    PSID result = NULL;

    if (NT_SUCCESS(NtOpenProcessToken(hProcess, TOKEN_QUERY, &hProcessToken))) {

        result = supQueryTokenUserSid(hProcessToken);

        NtClose(hProcessToken);
    }

    return result;
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

    TokenSid = supQueryTokenUserSid(hToken);
    if (TokenSid == NULL)
        return status;

    status = RtlAllocateAndInitializeSid(
        &NtAuth,
        1,
        SECURITY_LOCAL_SYSTEM_RID,
        0, 0, 0, 0, 0, 0, 0,
        &SystemSid);

    if (NT_SUCCESS(status)) {
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
* Find NT AUTHORITY\System process and duplicate it token.
*
*/
HANDLE supxGetSystemToken(
    PVOID ProcessList)
{
    BOOL bSystemToken = FALSE;
    ULONG NextEntryDelta = 0;
    HANDLE hObject = NULL;
    HANDLE hToken = NULL;

    OBJECT_ATTRIBUTES obja = RTL_INIT_OBJECT_ATTRIBUTES((PUNICODE_STRING)NULL, 0);

    union {
        PSYSTEM_PROCESSES_INFORMATION Processes;
        PBYTE ListRef;
    } List;

    List.ListRef = (PBYTE)ProcessList;

    do {

        List.ListRef += NextEntryDelta;

        if (List.Processes->ThreadCount &&
            List.Processes->InheritedFromUniqueProcessId)
        {
            if (NT_SUCCESS(NtOpenProcess(
                &hObject,
                PROCESS_QUERY_INFORMATION,
                &obja,
                &List.Processes->Threads[0].ClientId)))
            {

                if (NT_SUCCESS(NtOpenProcessToken(
                    hObject,
                    TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE | TOKEN_QUERY,
                    &hToken)))
                {
                    if (NT_SUCCESS(supIsLocalSystem(hToken, &bSystemToken))) {
                        if (bSystemToken) {
                            NtClose(hObject);
                            return hToken;
                        }
                    }
                    NtClose(hToken);
                }

                NtClose(hObject);
            }
        }

        NextEntryDelta = List.Processes->NextEntryDelta;

    } while (NextEntryDelta);


    return NULL;
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
    BOOL bCond = FALSE, bSuccess = FALSE;
    PVOID ProcessList;
    ULONG SessionId = NtCurrentPeb()->SessionId, dummy;

    HANDLE hSystemToken, hPrimaryToken = NULL, hImpersonationToken = NULL;

    BOOLEAN bThreadImpersonated = FALSE;

    PROCESS_INFORMATION pi;
    STARTUPINFO si;

    SECURITY_QUALITY_OF_SERVICE sqos;
    OBJECT_ATTRIBUTES obja;
    TOKEN_PRIVILEGES *TokenPrivileges;

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

    ProcessList = supGetSystemInfo(SystemProcessInformation);
    if (ProcessList == NULL)
        return FALSE;

    supEnablePrivilege(SE_DEBUG_PRIVILEGE, TRUE);

    //
    // Get LocalSystem token.
    //
    hSystemToken = supxGetSystemToken(ProcessList);

    supHeapFree(ProcessList);

    do {

        if (hSystemToken == NULL) {

            MessageBox(
                hwndParent,
                TEXT("No suitable system token found. Make sure you are running as administrator"),
                PROGRAM_NAME,
                MB_ICONINFORMATION);

            break;
        }

        //
        // Duplicate as impersonation token.
        //
        if (!NT_SUCCESS(NtDuplicateToken(
            hSystemToken,
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY |
            TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_PRIVILEGES,
            &obja,
            FALSE,
            TokenImpersonation,
            &hImpersonationToken)))
        {
            break;
        }

        //
        // Duplicate as primary token.
        //
        if (!NT_SUCCESS(NtDuplicateToken(
            hSystemToken,
            TOKEN_ALL_ACCESS,
            &obja,
            FALSE,
            TokenPrimary,
            &hPrimaryToken)))
        {
            break;
        }

        //
        // Impersonate system token.
        //
        if (!NT_SUCCESS(NtSetInformationThread(
            NtCurrentThread(),
            ThreadImpersonationToken,
            &hImpersonationToken,
            sizeof(HANDLE))))
        {
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

        if (!NT_SUCCESS(NtAdjustPrivilegesToken(
            hImpersonationToken,
            FALSE,
            TokenPrivileges,
            0,
            NULL,
            (PULONG)&dummy)))
        {
            break;
        }

        //
        // Set session id to primary token.
        //
        if (!NT_SUCCESS(NtSetInformationToken(
            hPrimaryToken,
            TokenSessionId,
            &SessionId,
            sizeof(ULONG))))
        {
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
            g_WinObj.EnableExperimentalFeatures ? GetCommandLine() : NULL,
            NULL,
            NULL,
            FALSE,
            CREATE_DEFAULT_ERROR_MODE,
            NULL,
            NULL,
            &si,
            &pi);

        if (bSuccess) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }

    } while (bCond);

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
* supGetCurrentProcessToken
*
* Purpose:
*
* Return current process token value with TOKEN_QUERY access right.
*
*/
HANDLE supGetCurrentProcessToken(
    VOID)
{
    HANDLE hToken = NULL;

    if (NT_SUCCESS(NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_QUERY,
        &hToken)))
    {
        return hToken;
    }
    return NULL;
}

/*
* supLookupImageSectionByName
*
* Purpose:
*
* Lookup section pointer and size for section name.
*
*/
PVOID supLookupImageSectionByName(
    _In_ CHAR* SectionName,
    _In_ ULONG SectionNameLength,
    _In_ PVOID DllBase,
    _Out_ PULONG SectionSize
)
{
    BOOLEAN bFound = FALSE;
    ULONG i;
    PVOID Section;
    IMAGE_NT_HEADERS *NtHeaders = RtlImageNtHeader(DllBase);
    IMAGE_SECTION_HEADER *SectionTableEntry;

    if (SectionSize)
        *SectionSize = 0;

    SectionTableEntry = (PIMAGE_SECTION_HEADER)((PCHAR)NtHeaders +
        sizeof(ULONG) +
        sizeof(IMAGE_FILE_HEADER) +
        NtHeaders->FileHeader.SizeOfOptionalHeader);

    //
    // Locate section.
    //
    i = NtHeaders->FileHeader.NumberOfSections;
    while (i > 0) {

        if (_strncmp_a(
            (CHAR*)SectionTableEntry->Name,
            SectionName,
            SectionNameLength) == 0)
        {
            bFound = TRUE;
            break;
        }

        i -= 1;
        SectionTableEntry += 1;
    }

    //
    // Section not found, abort scan.
    //
    if (!bFound)
        return NULL;

    Section = (PVOID)((ULONG_PTR)DllBase + SectionTableEntry->VirtualAddress);
    if (SectionSize)
        *SectionSize = SectionTableEntry->Misc.VirtualSize;

    return Section;
}

/*
* supFindPattern
*
* Purpose:
*
* Lookup pattern in buffer.
*
*/
PVOID supFindPattern(
    _In_ CONST PBYTE Buffer,
    _In_ SIZE_T BufferSize,
    _In_ CONST PBYTE Pattern,
    _In_ SIZE_T PatternSize
)
{
    PBYTE	p = Buffer;

    if (PatternSize == 0)
        return NULL;
    if (BufferSize < PatternSize)
        return NULL;
    BufferSize -= PatternSize;

    do {
        p = (PBYTE)memchr(p, Pattern[0], BufferSize - (p - Buffer));
        if (p == NULL)
            break;

        if (memcmp(p, Pattern, PatternSize) == 0)
            return p;

        p++;
    } while (BufferSize - (p - Buffer) > 0); //-V555

    return NULL;
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
    LPWSTR    lpItem1 = NULL, lpItem2 = NULL;
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

    if (Inverse)
        nResult = _strcmpi(lpItem2, lpItem1);
    else
        nResult = _strcmpi(lpItem1, lpItem2);

    return nResult;
}

/*
* supOpenNamedObjectFromContext
*
* Purpose:
*
* Return handle (query rights) for the given named object.
*
*/
HANDLE supOpenNamedObjectFromContext(
    _In_ PROP_OBJECT_INFO *Context,
    _In_ OBJECT_ATTRIBUTES *ObjectAttributes,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ NTSTATUS *Status
)
{
    HANDLE hObject = NULL, hPrivateNamespace = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    IO_STATUS_BLOCK iost;
    OBJECT_ATTRIBUTES objaNamespace;

    if (Context->IsPrivateNamespaceObject) {

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
    case ObjectTypeDevice: //FILE_OBJECT
        status = NtCreateFile(&hObject, DesiredAccess, ObjectAttributes, &iost, NULL, 0,
            FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, NULL, 0);//generic access rights
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
    _In_ PROP_OBJECT_INFO *Context,
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
            if (g_WinObj.EnableExperimentalFeatures) {
                bResult = NT_SUCCESS(NtClose(hObject));
            }
            else {
                bResult = CloseWindowStation((HWINSTA)hObject);
            }
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
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, LastError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&lpMsgBuf, 0, NULL))
    {
        MessageBox(hWnd, lpMsgBuf, Source, MB_TOPMOST | MB_ICONERROR);
        LocalFree(lpMsgBuf);
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
    TL_SUBITEMS_FIXED *subitems;
    TVITEMEX           itemex;
    WCHAR              textbuf[MAX_PATH + 1];

    __try {

        RtlSecureZeroMemory(&itemex, sizeof(itemex));
        RtlSecureZeroMemory(textbuf, sizeof(textbuf));
        subitems = NULL;
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
    __except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
        return;
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
    const char *pivot;
    int result;

    while (num > 0) {
        pivot = (char*)base + (num >> 1) * size;
        result = cmp(key, pivot);

        if (result == 0)
            return (void *)pivot;

        if (result > 0) {
            base = pivot + size;
            num--;
        }
        num >>= 1;
    }

    return NULL;
}
