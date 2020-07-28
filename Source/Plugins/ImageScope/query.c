/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       QUERY.C
*
*  VERSION:     1.00
*
*  DATE:        04 July 2020
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
    ULONG_PTR   vlimit = (ULONG_PTR)hdr + hdr->vshdr.wLength;
    PDWORD      value;
    DWORD       uzero = 0;

    for (
        // first child structure
        hdr = (PIMGVSTRING)ALIGN_UP_32((ULONG_PTR)hdr + sizeof(IMGVARINFO));
        (ULONG_PTR)hdr < vlimit;
        hdr = (PIMGVSTRING)ALIGN_UP_32((ULONG_PTR)hdr + hdr->vshdr.wLength))
    {
        if (hdr->vshdr.wValueLength == 0)
            value = &uzero;
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
    _In_ PWCHAR langid,
    _In_opt_ PVOID cbparam)
{
    ULONG_PTR   vlimit = (ULONG_PTR)hdr + hdr->vshdr.wLength;
    PWCHAR      value;

    for (
        // first child structure
        hdr = (PIMGVSTRING)ALIGN_UP_32((ULONG_PTR)hdr + sizeof(IMGSTRINGTABLE));
        (ULONG_PTR)hdr < vlimit;
        hdr = (PIMGVSTRING)ALIGN_UP_32((ULONG_PTR)hdr + hdr->vshdr.wLength))
    {
        if (hdr->vshdr.wValueLength == 0)
            value = L"";
        else
            value = (PWCHAR)ALIGN_UP_32((ULONG_PTR)&hdr->szKey + (1 + wcslen(hdr->szKey)) * sizeof(WCHAR));

        if (!callback(hdr->szKey, value, langid, cbparam))
            return FALSE;
    }

    return TRUE;
}

BOOL PEImageEnumStringFileInfo(
    _In_ PIMGSTRINGTABLE hdr,
    _In_ PEnumStringInfoCallback callback,
    _In_opt_ PVOID cbparam)
{
    ULONG_PTR   vlimit = (ULONG_PTR)hdr + hdr->vshdr.wLength;

    for (
        // first child structure
        hdr = (PIMGSTRINGTABLE)ALIGN_UP_32((ULONG_PTR)hdr + sizeof(IMGSTRINGINFO));
        (ULONG_PTR)hdr < vlimit;
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
    HGLOBAL     rptr = NULL;
    ULONG_PTR   vlimit, ids[3];

    VS_FIXEDFILEINFO* vinfo = NULL;
    PIMGVSVERSIONINFO   hdr;
    NTSTATUS status;
    SIZE_T datasz = 0;

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
            (LPVOID*)&rptr,
            (ULONG_PTR*)&datasz,
            NULL,
            NULL);

        if (NT_SUCCESS(status)) {
            // root structure
            hdr = (PIMGVSVERSIONINFO)rptr;
            vlimit = (ULONG_PTR)hdr + hdr->vshdr.wLength;

            if (hdr->vshdr.wValueLength)
                vinfo = (VS_FIXEDFILEINFO*)((ULONG_PTR)hdr + sizeof(IMGVSVERSIONINFO));

            for (
                // first child structure
                hdr = (PIMGVSVERSIONINFO)ALIGN_UP_32((ULONG_PTR)hdr + hdr->vshdr.wValueLength + sizeof(IMGVSVERSIONINFO));
                (ULONG_PTR)hdr < vlimit;
                hdr = (PIMGVSVERSIONINFO)ALIGN_UP_32((ULONG_PTR)hdr + hdr->vshdr.wLength))
            {

                if (_strcmp(hdr->wIdString, L"StringFileInfo") == 0)
                    if (!PEImageEnumStringFileInfo((PIMGSTRINGTABLE)hdr, scallback, cbparam))
                        break;

                if (vcallback) {
                    if ((_strcmp(hdr->wIdString, L"VarFileInfo") == 0))
                        if (!PEImageEnumVarFileInfo((PIMGVSTRING)hdr, vcallback, cbparam))
                            break;
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
    _In_ PVOID HeapHandle,
    _In_ PWCHAR Buffer,
    _In_ ULONG Size
)
{
    ULONG           p = 0, p0, strsz;
    WCHAR            c;
    PSTRING_PTR     newptr, ptr0 = NULL, head = NULL;

    while (Size > 0)
    {
        c = Buffer[p];
        p0 = p;
        ++p;
        Size -= sizeof(WCHAR);

        if (((c >= L'A') && (c <= L'Z')) ||
            ((c >= L'a') && (c <= L'z')) ||
            ((c >= L'0') && (c <= L'9')) ||
            (c == L'(') || (c == L'<') || (c == L'\"') || (c == L'.') ||
            (c == L'%') || (c == L'{') || (c == L'\\') || (c == L'@'))
        {
            while (Size > 0)
            {
                c = Buffer[p];

                if (!(((c >= 0x20) && (c <= 0x7f)) ||
                    (c == L'\r') ||
                    (c == L'\n') ||
                    (c == L'\t')))
                    break;

                if ((p - p0) >= 255)
                    break;

                ++p;
                Size -= sizeof(WCHAR);
            }

            strsz = p - p0;

            if (strsz > 2)
            {
                newptr = RtlAllocateHeap(HeapHandle, HEAP_ZERO_MEMORY, sizeof(STRING_PTR));
                if (newptr) {
                    newptr->length = strsz;
                    newptr->pnext = NULL;
                    newptr->ofpstr = p0 * sizeof(WCHAR);

                    if (ptr0 != NULL)
                        ptr0->pnext = newptr;
                    else
                        head = newptr;

                    ptr0 = newptr;
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
    _In_ PVOID HeapHandle,
    _In_ PCHAR Buffer,
    _In_ ULONG Size
)
{
    ULONG           p = 0, p0, strsz;
    UCHAR            c;
    PSTRING_PTR     newptr, ptr0 = NULL, head = NULL;

    while (Size > 0)
    {
        c = Buffer[p];
        p0 = p;
        ++p;
        --Size;

        if (((c >= 'A') && (c <= 'Z')) ||
            ((c >= 'a') && (c <= 'z')) ||
            ((c >= '0') && (c <= '9')) ||
            (c == '(') || (c == '<') || (c == '\"') || (c == '.') ||
            (c == '%') || (c == '{') || (c == '\\') || (c == '@'))

        {
            while (Size > 0)
            {
                c = Buffer[p];

                if (!(((c >= 0x20) && (c <= 0x7f)) ||
                    (c == '\r') ||
                    (c == '\n') ||
                    (c == '\t')))
                    break;

                if ((p - p0) >= 255)
                    break;

                ++p;
                --Size;
            }

            strsz = p - p0;

            if (strsz > 2)
            {
                newptr = RtlAllocateHeap(HeapHandle, HEAP_ZERO_MEMORY, sizeof(STRING_PTR));
                if (newptr) {
                    newptr->length = strsz;
                    newptr->pnext = NULL;
                    newptr->ofpstr = p0;

                    if (ptr0 != NULL)
                        ptr0->pnext = newptr;
                    else
                        head = newptr;

                    ptr0 = newptr;
                }
            }
        }
    }

    return head;
}
