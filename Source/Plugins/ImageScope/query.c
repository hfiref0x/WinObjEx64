/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2025
*
*  TITLE:       QUERY.C
*
*  VERSION:     1.20
*
*  DATE:        14 Jun 2025
*
*  ImageScope main logic.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

ULONG_PTR FORCEINLINE ALIGN_UP_32(
    _In_ ULONG_PTR p)
{
    return (p + 3) & (~(ULONG_PTR)3);
}

BOOL PEImageEnumVarFileInfo(
    _In_ PIMGVSTRING hdr,
    _In_ PEnumVarInfoCallback vcallback,
    _In_opt_ PVOID cbparam)
{
    ULONG_PTR   vLimit = (ULONG_PTR)hdr + hdr->vshdr.wLength;
    PDWORD      value;
    DWORD       uZero = 0;

    for (
        // first child structure
        hdr = (PIMGVSTRING)ALIGN_UP_32((ULONG_PTR)hdr + sizeof(IMGVARINFO));
        (ULONG_PTR)hdr < vLimit;
        hdr = (PIMGVSTRING)ALIGN_UP_32((ULONG_PTR)hdr + hdr->vshdr.wLength))
    {
        if (hdr->vshdr.wValueLength == 0)
            value = &uZero;
        else
            value = (PDWORD)ALIGN_UP_32((ULONG_PTR)&hdr->szKey + (1 + wcslen(hdr->szKey)) * sizeof(WCHAR));

        if (!vcallback(hdr->szKey, *value, cbparam))
            return FALSE;
    }

    return TRUE;
}

BOOL PEImageEnumStrings(
    _In_ PIMGVSTRING hdr,
    _In_ PEnumStringInfoCallback callback,
    _In_ PWCHAR langId,
    _In_opt_ PVOID cbparam)
{
    ULONG_PTR   vLimit = (ULONG_PTR)hdr + hdr->vshdr.wLength;
    PWCHAR      value;

    for (
        // first child structure
        hdr = (PIMGVSTRING)ALIGN_UP_32((ULONG_PTR)hdr + sizeof(IMGSTRINGTABLE));
        (ULONG_PTR)hdr < vLimit;
        hdr = (PIMGVSTRING)ALIGN_UP_32((ULONG_PTR)hdr + hdr->vshdr.wLength))
    {
        if (hdr->vshdr.wValueLength == 0)
            value = L"";
        else
            value = (PWCHAR)ALIGN_UP_32((ULONG_PTR)&hdr->szKey + (1 + wcslen(hdr->szKey)) * sizeof(WCHAR));

        if (!callback(hdr->szKey, value, langId, cbparam))
            return FALSE;
    }

    return TRUE;
}

BOOL PEImageEnumStringFileInfo(
    _In_ PIMGSTRINGTABLE hdr,
    _In_ PEnumStringInfoCallback callback,
    _In_opt_ PVOID cbparam)
{
    ULONG_PTR   vLimit = (ULONG_PTR)hdr + hdr->vshdr.wLength;

    for (
        // first child structure
        hdr = (PIMGSTRINGTABLE)ALIGN_UP_32((ULONG_PTR)hdr + sizeof(IMGSTRINGINFO));
        (ULONG_PTR)hdr < vLimit;
        hdr = (PIMGSTRINGTABLE)ALIGN_UP_32((ULONG_PTR)hdr + hdr->vshdr.wLength))
    {
        if (!PEImageEnumStrings((PIMGVSTRING)hdr, callback, hdr->wIdKey, cbparam))
            return FALSE;
    }

    return TRUE;
}

/*
* PEImageEnumVersionFields
*
* Purpose:
*
* Enumerate version info fields in the given module.
*
*/
VS_FIXEDFILEINFO* PEImageEnumVersionFields(
    _In_ HMODULE module,
    _In_ PEnumStringInfoCallback scallback,
    _In_opt_ PEnumVarInfoCallback vcallback,
    _Inout_opt_ PVOID cbparam)
{
    HGLOBAL     rPtr = NULL;
    ULONG_PTR   vLimit, ids[3];

    VS_FIXEDFILEINFO* vinfo = NULL;
    PIMGVSVERSIONINFO   hdr;
    NTSTATUS status;
    SIZE_T dataSz = 0;

    if (!scallback)
        return NULL;

    __try {
        ids[0] = (ULONG_PTR)RT_VERSION;                     //type
        ids[1] = 1;                                         //id
        ids[2] = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL); //lang

        status = LdrResSearchResource(
            module,
            (ULONG_PTR*)&ids,
            3,
            0,
            (LPVOID*)&rPtr,
            (ULONG_PTR*)&dataSz,
            NULL,
            NULL);

        if (NT_SUCCESS(status)) {
            // root structure
            hdr = (PIMGVSVERSIONINFO)rPtr;
            if (hdr == NULL || dataSz < sizeof(IMGVSVERSIONINFO))
                __leave;

            vLimit = (ULONG_PTR)hdr + hdr->vshdr.wLength;

            if (hdr->vshdr.wValueLength)
                vinfo = (VS_FIXEDFILEINFO*)((ULONG_PTR)hdr + sizeof(IMGVSVERSIONINFO));

            for (
                // first child structure
                hdr = (PIMGVSVERSIONINFO)ALIGN_UP_32((ULONG_PTR)hdr + hdr->vshdr.wValueLength + sizeof(IMGVSVERSIONINFO));
                (ULONG_PTR)hdr < vLimit;
                hdr = (PIMGVSVERSIONINFO)ALIGN_UP_32((ULONG_PTR)hdr + hdr->vshdr.wLength))
            {
                if (_strcmp(hdr->wIdString, L"StringFileInfo") == 0) {
                    if (!PEImageEnumStringFileInfo((PIMGSTRINGTABLE)hdr, scallback, cbparam))
                        break;
                }

                if (vcallback) {
                    if ((_strcmp(hdr->wIdString, L"VarFileInfo") == 0)) {
                        if (!PEImageEnumVarFileInfo((PIMGVSTRING)hdr, vcallback, cbparam))
                            break;
                    }
                }
            }
        }
        else {
            SetLastError(RtlNtStatusToDosError(status));
        }
    }
    __finally {
        if (AbnormalTermination()) {
            SetLastError((DWORD)STATUS_ACCESS_VIOLATION);
            return NULL;
        }
    }

    return vinfo;
}

/*
* EnumImageStringsW
*
* Purpose:
*
* Enumerate printable unicode strings in the given buffer.
*
*/
PSTRING_PTR EnumImageStringsW(
    _In_ PVOID heapHandle,
    _In_ PWCHAR buffer,
    _In_ ULONG size
)
{
    ULONG       pos = 0, startPos, strSize;
    WCHAR       c;
    PSTRING_PTR newPtr, lastPtr = NULL, head = NULL;

    while (size > 0)
    {
        c = buffer[pos];
        startPos = pos;
        ++pos;
        size -= sizeof(WCHAR);

        if (((c >= L'A') && (c <= L'Z')) ||
            ((c >= L'a') && (c <= L'z')) ||
            ((c >= L'0') && (c <= L'9')) ||
            (c == L'(') || (c == L'<') || (c == L'\"') || (c == L'.') ||
            (c == L'%') || (c == L'{') || (c == L'\\') || (c == L'@'))
        {
            while (size > 0)
            {
                c = buffer[pos];

                if (!(((c >= 0x20) && (c <= 0x7f)) ||
                    (c == L'\r') ||
                    (c == L'\n') ||
                    (c == L'\t')))
                    break;

                if ((pos - startPos) >= 255)
                    break;

                ++pos;
                size -= sizeof(WCHAR);
            }

            strSize = pos - startPos;

            if (strSize > 2)
            {
                newPtr = RtlAllocateHeap(heapHandle, HEAP_ZERO_MEMORY, sizeof(STRING_PTR));
                if (newPtr) {
                    newPtr->length = strSize;
                    newPtr->pnext = NULL;
                    newPtr->ofpstr = startPos * sizeof(WCHAR);

                    if (lastPtr != NULL)
                        lastPtr->pnext = newPtr;
                    else
                        head = newPtr;

                    lastPtr = newPtr;
                }
            }
        }
    }

    return head;
}

/*
* EnumImageStringsA
*
* Purpose:
*
* Enumerate printable ansi strings in the given buffer.
*
*/
PSTRING_PTR EnumImageStringsA(
    _In_ PVOID heapHandle,
    _In_ PCHAR buffer,
    _In_ ULONG size
)
{
    ULONG       pos = 0, startPos, strSize;
    UCHAR       c;
    PSTRING_PTR newPtr, lastPtr = NULL, head = NULL;

    while (size > 0)
    {
        c = buffer[pos];
        startPos = pos;
        ++pos;
        --size;

        if (((c >= 'A') && (c <= 'Z')) ||
            ((c >= 'a') && (c <= 'z')) ||
            ((c >= '0') && (c <= '9')) ||
            (c == '(') || (c == '<') || (c == '\"') || (c == '.') ||
            (c == '%') || (c == '{') || (c == '\\') || (c == '@'))
        {
            while (size > 0)
            {
                c = buffer[pos];

                if (!(((c >= 0x20) && (c <= 0x7f)) ||
                    (c == '\r') ||
                    (c == '\n') ||
                    (c == '\t')))
                    break;

                if ((pos - startPos) >= 255)
                    break;

                ++pos;
                --size;
            }

            strSize = pos - startPos;

            if (strSize > 2)
            {
                newPtr = RtlAllocateHeap(heapHandle, HEAP_ZERO_MEMORY, sizeof(STRING_PTR));
                if (newPtr) {
                    newPtr->length = strSize;
                    newPtr->pnext = NULL;
                    newPtr->ofpstr = startPos;

                    if (lastPtr != NULL)
                        lastPtr->pnext = newPtr;
                    else
                        head = newPtr;

                    lastPtr = newPtr;
                }
            }
        }
    }

    return head;
}
