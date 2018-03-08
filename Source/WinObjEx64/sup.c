/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       SUP.C
*
*  VERSION:     1.53
*
*  DATE:        07 Mar 2018
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "treelist.h"
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
#ifndef _DEBUG
PVOID FORCEINLINE supHeapAlloc(
    _In_ SIZE_T Size)
{
    return RtlAllocateHeap(g_WinObj.Heap, HEAP_ZERO_MEMORY, Size);
}
#else
PVOID supHeapAlloc(
    _In_ SIZE_T Size)
{
    LONG x;
    PVOID Buffer = NULL;
    WCHAR szBuffer[100];

    Buffer = RtlAllocateHeap(g_WinObj.Heap, HEAP_ZERO_MEMORY, Size);
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
#ifndef _DEBUG
BOOL FORCEINLINE supHeapFree(
    _In_ PVOID Memory)
{
    return RtlFreeHeap(g_WinObj.Heap, 0, Memory);
}
#else
BOOL supHeapFree(
    _In_ PVOID Memory)
{
    LONG x;
    WCHAR szBuffer[100];

    if (RtlFreeHeap(g_WinObj.Heap, 0, Memory)) {
        x = InterlockedDecrement((PLONG)&g_cHeapAlloc);
        _strcpy(szBuffer, L"Free buffer=0x");
        u64tohex((ULONG_PTR)Memory, _strend(szBuffer));
        _strcat(szBuffer, L"\r\n");
        OutputDebugString(szBuffer);

        _strcpy(szBuffer, L"g_cHeapAlloc=");
        ultostr(x, _strend(szBuffer));
        _strcat(szBuffer, L"\r\n");
        OutputDebugString(szBuffer);
        return TRUE;
    }
    else {
        _strcpy(szBuffer, L"Free buffer=0x");
        u64tohex((ULONG_PTR)Memory, _strend(szBuffer));
        _strcat(szBuffer, L" FAILED \r\n");
        OutputDebugString(szBuffer);
        return FALSE;
    }
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
    Status = NtAllocateVirtualMemory(NtCurrentProcess(),
        &Buffer,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (NT_SUCCESS(Status)) {
        RtlSecureZeroMemory(Buffer, size);
        return Buffer;
    }
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
        Status = NtFreeVirtualMemory(NtCurrentProcess(),
            &Memory,
            &size,
            MEM_RELEASE);
    }
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
            lptstrCopy = GlobalLock(hglbCopy);
            if (lptstrCopy) {
                supCopyMemory(lptstrCopy, dwSize, lpText, cbText);
            }
            GlobalUnlock(hglbCopy);
            SetClipboardData(CF_UNICODETEXT, hglbCopy);
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
    _In_ HANDLE hOject,
    _Out_ ULONG_PTR *Address,
    _Inout_opt_ USHORT *TypeIndex
)
{
    BOOL   bFound = FALSE;
    ULONG  i;
    DWORD  CurrentProcessId = GetCurrentProcessId();

    PSYSTEM_HANDLE_INFORMATION_EX pHandles;

    if (Address == NULL) {
        return bFound;
    }

    *Address = 0;

    pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation);
    if (pHandles) {
        for (i = 0; i < pHandles->NumberOfHandles; i++) {
            if (pHandles->Handles[i].UniqueProcessId == CurrentProcessId) {
                if (pHandles->Handles[i].HandleValue == (USHORT)(ULONG_PTR)hOject) {
                    if ((ULONG_PTR)pHandles->Handles[i].Object < g_kdctx.SystemRangeStart) {
                        if (TypeIndex) {
                            *TypeIndex = 0;
                        }
                    }
                    else {
                        *Address = (ULONG_PTR)pHandles->Handles[i].Object;
                        if (TypeIndex) {
                            *TypeIndex = pHandles->Handles[i].ObjectTypeIndex;
                        }
                        bFound = TRUE;
                    }
                    break;
                }
            }
        }
        supHeapFree(pHandles);
    }
    return bFound;
}

/*
* supxSyscallTableEntryToAddress
*
* Purpose:
*
* Translate KiServiceTable entry to the real function address.
*
*/
ULONG_PTR supxSyscallTableEntryToAddress(
    _In_ PULONG KiServiceTable,
    _In_ ULONG ServiceId,
    _In_ ULONG_PTR KiServiceTablePtr
)
{
    LONG32 Offset;

    Offset = ((LONG32)KiServiceTable[ServiceId] >> 4);
    return KiServiceTablePtr + Offset;
}

/*
* supDumpSyscallTableConverted
*
* Purpose:
*
* Read KiServiceTable and convert it.
*
*/
BOOL supDumpSyscallTableConverted(
    _In_ PKLDBGCONTEXT Context,
    _Inout_ PUTable *Table
)
{
    ULONG   ServiceId, memIO, bytesRead;
    BOOL    bResult = FALSE;
    PULONG  KiServiceTableDumped = NULL;
    PUTable ConvertedTable;

    __try {

        if ((Context->KiServiceTableAddress == 0) || (Context->KiServiceLimit == 0))
            __leave;

        memIO = (ULONG)(Context->KiServiceLimit * sizeof(ULONG_PTR));
        KiServiceTableDumped = (PULONG)supHeapAlloc(memIO);
        if (KiServiceTableDumped == NULL)
            __leave;

        bytesRead = 0;
        if (!kdReadSystemMemoryEx(Context->KiServiceTableAddress,
            (PVOID)KiServiceTableDumped,
            memIO,
            &bytesRead))
        {
            __leave;
        }

        if (bytesRead > 16) {
            ConvertedTable = (PULONG_PTR)supHeapAlloc(bytesRead);
            if (ConvertedTable) {
                *Table = ConvertedTable;
                for (ServiceId = 0; ServiceId < Context->KiServiceLimit; ServiceId++) {
                    ConvertedTable[ServiceId] = supxSyscallTableEntryToAddress(KiServiceTableDumped, 
                        ServiceId,
                        Context->KiServiceTableAddress);
                }
                bResult = TRUE;
            }
        }
    }
    __finally {
        if (KiServiceTableDumped != NULL) {
            supHeapFree(KiServiceTableDumped);
        }
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
    VOID
)
{
    DWORD   dwSize, dwType = 0;
    HKEY    hKey;
    LRESULT lRet;
    HANDLE  hHtmlOcx;
    WCHAR   szOcxPath[MAX_PATH + 1];
    WCHAR   szBuffer[MAX_PATH * 2];

    RtlSecureZeroMemory(&szOcxPath, sizeof(szOcxPath));
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

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    if (!GetCurrentDirectory(MAX_PATH, szBuffer)) {
        return;
    }
    _strcat(szBuffer, L"\\winobjex64.chm");

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
    g_WinObj.HtmlHelpW(GetDesktopWindow(), szBuffer, 0, 0);
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
    ULONG       Size = 0x1000;
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
        item.pszText = supHeapAlloc(len * sizeof(WCHAR));
        sz = SendMessage(ListView, LVM_GETITEMTEXT, (WPARAM)item.iItem, (LPARAM)&item);
    } while (sz == len - 1);

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

    list = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, TYPE_UNKNOWN, 8);
    if (list) {
        for (i = FirstId; i <= LastId; i++) {
            hIcon = LoadImage(hInst, MAKEINTRESOURCE(i), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
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
    BOOL   bFound = FALSE;

    POBJECT_TYPE_INFORMATION   pObject;
    POBJECT_TYPE_INFORMATION_8 pObject8;

    if (Object == NULL) {
        return TYPE_UNKNOWN;
    }

    __try {

        Index = ObDecodeTypeIndex(Object, TypeIndex);

        pObject = (POBJECT_TYPE_INFORMATION)&g_pObjectTypesInfo->TypeInformation;
        for (i = 0; i < g_pObjectTypesInfo->NumberOfTypes; i++) {

            if (g_WinObj.osver.dwBuildNumber >= 9200) {
                pObject8 = (POBJECT_TYPE_INFORMATION_8)pObject;
                if (pObject8->TypeIndex == Index) {
                    bFound = TRUE;
                }
            }
            else {
                if (i + 2 == Index) {
                    bFound = TRUE;
                }
            }

            if (bFound) {
                return supGetObjectIndexByTypeName(pObject->TypeName.Buffer);
            }

            pObject = (POBJECT_TYPE_INFORMATION)((PCHAR)(pObject + 1) +
                ALIGN_UP(pObject->TypeName.MaximumLength, sizeof(ULONG_PTR)));
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return TYPE_UNKNOWN;
    }
    return TYPE_UNKNOWN;
}

/*
* supGetObjectIndexByTypeName
*
* Purpose:
*
* Returns object index of known type.
*
* Known type names listed in objects.c, objects.h
*
*/
UINT supGetObjectIndexByTypeName(
    _In_ LPCWSTR lpTypeName
)
{
    UINT nIndex;

    if (lpTypeName == NULL) {
        return TYPE_UNKNOWN;
    }

    for (nIndex = TYPE_DEVICE; nIndex < TYPE_UNKNOWN; nIndex++) {
        if (_strcmpi(lpTypeName, g_lpObjectNames[nIndex]) == 0)
            return nIndex;
    }

    //
    // In Win8 the following Win32k object was named 
    // CompositionSurface, in Win8.1 MS renamed it to
    // Composition, handle this.
    //
    if (_strcmpi(lpTypeName, L"CompositionSurface") == 0) {
        return TYPE_COMPOSITION;
    }

    //
    // In Win10 TH1 the following ntos object was named 
    // NetworkNamespace, later in Win10 updates MS renamed it to
    // NdisCmState, handle this.
    //
/*    if (_strcmpi(lpTypeName, L"NetworkNamespace") == 0) {
        return TYPE_NDISCMSTATE;
    }*/

    return TYPE_UNKNOWN;
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

    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &hToken);
    if (!NT_SUCCESS(status))
        return bResult;

    do {
        if (!AllocateAndInitializeSid(
            &NtAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &AdministratorsGroup))
            break;

        status = NtQueryInformationToken(hToken, TokenGroups, NULL, 0, &ReturnLength);
        if (status != STATUS_BUFFER_TOO_SMALL)
            break;

        pTkGroups = supHeapAlloc((SIZE_T)ReturnLength);
        if (pTkGroups == NULL)
            break;

        status = NtQueryInformationToken(hToken, TokenGroups, pTkGroups, ReturnLength, &ReturnLength);
        if (NT_SUCCESS(status)) {
            if (pTkGroups->GroupCount > 0)
                for (i = 0; i < pTkGroups->GroupCount; i++) {
                    Attributes = pTkGroups->Groups[i].Attributes;
                    if (EqualSid(AdministratorsGroup, pTkGroups->Groups[i].Sid))
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
        FreeSid(AdministratorsGroup);
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
    return (_strcmpi(ItemText, g_lpObjectNames[TYPE_SYMLINK]) == 0);
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
        lpDataBuffer = supHeapAlloc(memIO);
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
* supxMapNtdllCopy
*
* Purpose:
*
* Load copy of ntdll from disk as image.
*
*/
VOID supxMapNtdllCopy(
    VOID
)
{
    HANDLE              hFile = NULL, hSection = NULL;
    PVOID               DllBase;
    SIZE_T              DllVirtualSize;
    NTSTATUS            status;
    OBJECT_ATTRIBUTES   attr;
    UNICODE_STRING      usFileName;
    IO_STATUS_BLOCK     iosb;

    WCHAR  szDllPath[MAX_PATH * 2];

    usFileName.Buffer = NULL;

    RtlSecureZeroMemory(szDllPath, sizeof(szDllPath));
    _strcpy(szDllPath, TEXT("\\??\\"));
    _strcat(szDllPath, g_WinObj.szSystemDirectory);
    _strcat(szDllPath, TEXT("\\ntdll.dll"));

    RtlInitUnicodeString(&usFileName, szDllPath);

    InitializeObjectAttributes(&attr, &usFileName,
        OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateFile(&hFile, SYNCHRONIZE | FILE_READ_DATA,
        &attr, &iosb, NULL, 0, FILE_SHARE_READ, FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (NT_SUCCESS(status)) {

        status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL,
            NULL, PAGE_READONLY, SEC_IMAGE, hFile);

        if (NT_SUCCESS(status)) {

            DllBase = NULL;
            DllVirtualSize = 0;
            status = NtMapViewOfSection(hSection, NtCurrentProcess(), &DllBase,
                0, 0, NULL, &DllVirtualSize, ViewUnmap, 0, PAGE_READONLY);
            
            if (NT_SUCCESS(status)) {
                g_WinObj.hNtdllModule = DllBase;
            }
            NtClose(hSection);
        }
        NtClose(hFile);
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
    _In_ BOOL IsFullAdmin,
    _In_ BOOL IsWine
)
{
    supQueryKnownDlls();
    kdInit(IsFullAdmin);

    if (IsFullAdmin) {
        supCreateSCMSnapshot();
        supxMapNtdllCopy();
    }

    sapiCreateSetupDBSnapshot();
    
    //
    // Quick Wine Staging fix. 
    // Under usual Wine NtQueryObject(ObjectTypesInformation) is not implemented.
    // We are okay with that.
    // But under Wine Staging this piece of code is implemented and it is broken.
    // So generally ban this call from Wine.
    //
    if (IsWine) {
        g_pObjectTypesInfo = NULL;
    }
    else {
        g_pObjectTypesInfo = supGetObjectTypesInfo();
    }

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

    supFreeSCMSnapshot();
    sapiFreeSnapshot();

    if (g_pObjectTypesInfo) supHeapFree(g_pObjectTypesInfo);
    if (g_lpKnownDlls32) supHeapFree(g_lpKnownDlls32);
    if (g_lpKnownDlls64) supHeapFree(g_lpKnownDlls64);
    if (g_SdtTable) supHeapFree(g_SdtTable);
    if (g_WinObj.hNtdllModule) {
        NtUnmapViewOfSection(NtCurrentProcess(), g_WinObj.hNtdllModule);
    }
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

    RtlSecureZeroMemory(&KnownDlls, sizeof(KnownDlls));
    RtlInitUnicodeString(&KnownDlls, L"\\KnownDlls32\\KnownDllPath");
    supxQueryKnownDllsLink(&KnownDlls, &g_lpKnownDlls32);
    RtlInitUnicodeString(&KnownDlls, L"\\KnownDlls\\KnownDllPath");
    supxQueryKnownDllsLink(&KnownDlls, &g_lpKnownDlls64);
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
        sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, NULL);
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
    PSYSTEM_PROCESSES_INFORMATION pList = ProcessList;

    if ((ProcessList == NULL) || (Buffer == NULL) || (ccBuffer == 0))
        return FALSE;

    for (;;) {
        if ((ULONG_PTR)pList->UniqueProcessId == dwProcessId) {
            _strncpy(Buffer, ccBuffer, pList->ImageName.Buffer, pList->ImageName.Length / sizeof(WCHAR));
            return TRUE;
        }
        if (pList->NextEntryDelta == 0)
            break;
        pList = (PSYSTEM_PROCESSES_INFORMATION)(((LPBYTE)pList) + pList->NextEntryDelta);
    }
    return FALSE;
}

/*
* supCreateSCMSnapshot
*
* Purpose:
*
* Collects SCM information for drivers description.
*
*/
BOOL supCreateSCMSnapshot(
    VOID
)
{
    BOOL      cond = FALSE, bResult = FALSE;
    SC_HANDLE schSCManager;
    DWORD     dwBytesNeeded = 0, dwServicesReturned = 0, dwSize, dwSlack;
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
        dwSize = 0x1000;
        Services = supVirtualAlloc(dwSize);
        if (Services == NULL)
            break;

        bResult = EnumServicesStatusEx(schSCManager, 
            SC_ENUM_PROCESS_INFO, 
            SERVICE_DRIVER,
            SERVICE_STATE_ALL, 
            Services, 
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
                dwSize = (DWORD)(dwBytesNeeded + sizeof(ENUM_SERVICE_STATUS_PROCESS));
                dwSlack = dwSize % 0x1000;
                if (dwSlack > 0) dwSize = dwSize + 0x1000 - dwSlack;

                Services = supVirtualAlloc(dwSize);
                if (Services == NULL)
                    break;

                bResult = EnumServicesStatusEx(schSCManager, 
                    SC_ENUM_PROCESS_INFO, 
                    SERVICE_DRIVER,
                    SERVICE_STATE_ALL, 
                    Services, 
                    dwSize, 
                    &dwBytesNeeded, 
                    &dwServicesReturned, 
                    NULL, 
                    NULL);

                if (!bResult){
                    supVirtualFree(Services);
                    Services = NULL;
                    dwServicesReturned = 0;
                    break;
                }
            } //ERROR_MORE_DATA
        } //bResult == FALSE;

        CloseServiceHandle(schSCManager);

    } while (cond);

    RtlEnterCriticalSection(&g_WinObj.Lock);
    g_scmDB.Entries = Services;
    g_scmDB.NumberOfEntries = dwServicesReturned;
    RtlLeaveCriticalSection(&g_WinObj.Lock);

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
    VOID)
{
    RtlEnterCriticalSection(&g_WinObj.Lock);
    supVirtualFree(g_scmDB.Entries);
    g_scmDB.Entries = NULL;
    g_scmDB.NumberOfEntries = 0;
    RtlLeaveCriticalSection(&g_WinObj.Lock);
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
    lpProperty = RtlAllocateHeap(SnapshotHeap, HEAP_ZERO_MEMORY, dataSize);
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
        lpProperty = RtlAllocateHeap(SnapshotHeap, HEAP_ZERO_MEMORY, dataSize);
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

            Entry = RtlAllocateHeap(Heap, HEAP_ZERO_MEMORY, sizeof(SAPIDBENTRY));
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
* supFindModuleEntryByAddress
*
* Purpose:
*
* Find Module Name for given Address.
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

        pObject = (POBJECT_TYPE_INFORMATION)&g_pObjectTypesInfo->TypeInformation;
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
            }
            if (bResult) {
                break;
            }
            //next entry located after the aligned type name buffer
            pObject = (POBJECT_TYPE_INFORMATION)((PCHAR)(pObject + 1) +
                ALIGN_UP(pObject->TypeName.MaximumLength, sizeof(ULONG_PTR)));
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
    lpFullDeviceName = supHeapAlloc(Length);
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
                        
                        _strncpy(Buffer, 
                            ccBuffer, 
                            Item->lpDeviceDesc, 
                            _strlen(Item->lpDeviceDesc)
                        );

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

            lpRegKey = supHeapAlloc(sz);
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
                if (!VerQueryValue(vinfo, VERSION_TRANSLATION, &lpTranslate, (PUINT)&dwSize))
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
                bResult = VerQueryValue(vinfo, szBuffer, &lpDisplayName, (PUINT)&dwSize);
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
        lpszFileName = supHeapAlloc(cLength);
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
        if (!VerQueryValue(vinfo, VERSION_TRANSLATION, &lpTranslate, (PUINT)&dwInfoSize))
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
        bResult = VerQueryValue(vinfo, szQueryBlock, &pcValue, (PUINT)&dwInfoSize);
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
    HANDLE            hDirectory;
    UNICODE_STRING    ustr;
    OBJECT_ATTRIBUTES obja;

    if (lpDirectory == NULL) {
        return NULL;
    }
    RtlSecureZeroMemory(&ustr, sizeof(ustr));
    RtlInitUnicodeString(&ustr, lpDirectory);
    InitializeObjectAttributes(&obja, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);

    hDirectory = NULL;
    NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &obja);

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
        LookupDirName = supHeapAlloc(ldirSz);
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
    
    status = NtQueryInformationProcess(hProcess, 
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

    status = NtQuerySystemInformation(SystemRangeStartInformation, 
        (PVOID)&SystemRangeStart, 
        sizeof(ULONG_PTR), 
        &memIO);

    if (!NT_SUCCESS(status)) {
        SetLastError(RtlNtStatusToDosError(status));
    }
    return SystemRangeStart;
}

/*
* supConvertFileName
*
* Purpose:
*
* Translate Nt path name to Dos path name.
*
*/
BOOL supConvertFileName(
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

        RtlSecureZeroMemory(&NtFileName, sizeof(NtFileName));
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

        Buffer = supHeapAlloc(memIO);
        if (Buffer == NULL)
            break;

        status = NtQueryObject(hFile, ObjectNameInformation, Buffer, memIO, NULL);
        if (!NT_SUCCESS(status))
            break;

        if (!supConvertFileName(((PUNICODE_STRING)Buffer)->Buffer, Win32FileName, ccWin32FileName))
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
    HANDLE hNtdll;
    FARPROC  WineVersion = NULL;

    hNtdll = GetModuleHandle(TEXT("ntdll.dll"));

    if (hNtdll) {
        WineVersion = (FARPROC)GetProcAddress(hNtdll, "wine_get_version");
        if (WineVersion != NULL)
            return TRUE;
    }

    return FALSE;
}

typedef union {
    WCHAR Name[sizeof(DWORD) / sizeof(WCHAR)];
    DWORD Alignment;
} DWORDALIGNEDNAME;

const DWORDALIGNEDNAME AddressNamePrefixLowCase = { L'0', L'x' };
const DWORDALIGNEDNAME AddressNamePrefixUpCase = { L'0', L'X' };
const UNICODE_STRING AddressNameLowCase = {
    sizeof(AddressNamePrefixLowCase),
    sizeof(AddressNamePrefixLowCase),
    (PWSTR)&AddressNamePrefixLowCase
};
const UNICODE_STRING AddressNameUpCase = {
    sizeof(AddressNamePrefixUpCase),
    sizeof(AddressNamePrefixUpCase),
    (PWSTR)&AddressNamePrefixUpCase
};

/*
* supIsAddressPrefix
*
* Purpose:
*
* Return offset to Address name in case if given lpName is in Address Prefix Format.
*
*/
USHORT supIsAddressPrefix(
    _In_ LPWSTR lpName,
    _In_ SIZE_T cbName
)
{
    if ((cbName >= AddressNameLowCase.Length) &&
        (*(PDWORD)(lpName) == AddressNamePrefixLowCase.Alignment))
    {
        return AddressNameLowCase.Length / sizeof(WCHAR);
    }
    if ((cbName >= AddressNameUpCase.Length) &&
        (*(PDWORD)(lpName) == AddressNamePrefixUpCase.Alignment))
    {
        return AddressNameUpCase.Length / sizeof(WCHAR);
    }

    return 0;
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

        returnLength = GetFirmwareEnvironmentVariable(L"SecureBoot",
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

    if (supxGetWindowStationName(&CurrentWinstaDir)) {
        RtlInitUnicodeString(&WinstaDir, Context->lpCurrentObjectPath);
        if (RtlEqualUnicodeString(&WinstaDir, &CurrentWinstaDir, TRUE)) {
            hObject = OpenWindowStation(Context->lpObjectName, fInherit, dwDesiredAccess);
        }
        RtlFreeUnicodeString(&CurrentWinstaDir);
    }

    return hObject;
}

