/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2025
*
*  TITLE:       QUERY.C
*
*  VERSION:     1.21
*
*  DATE:        22 Aug 2025
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

#define IMGSCOPE_MAX_EXTRACTED_STR 255

static inline BOOL IsWideStartChar(WCHAR c)
{
    return ((c >= L'A' && c <= L'Z') ||
        (c >= L'a' && c <= L'z') ||
        (c >= L'0' && c <= L'9') ||
        c == L'(' || c == L'<' || c == L'\"' ||
        c == L'.' || c == L'%' || c == L'{' ||
        c == L'\\' || c == L'@');
}

static inline BOOL IsWideContinueChar(WCHAR c)
{
    return (((c >= 0x20) && (c <= 0x7f)) ||
        c == L'\r' || c == L'\n' || c == L'\t');
}

static inline BOOL IsAnsiStartChar(UCHAR c)
{
    return ((c >= 'A' && c <= 'Z') ||
        (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') ||
        c == '(' || c == '<' || c == '\"' ||
        c == '.' || c == '%' || c == '{' ||
        c == '\\' || c == '@');
}

static inline BOOL IsAnsiContinueChar(UCHAR c)
{
    return (((c >= 0x20) && (c <= 0x7f)) ||
        c == '\r' || c == '\n' || c == '\t');
}

ULONG_PTR FORCEINLINE ALIGN_UP_32(
    _In_ ULONG_PTR p)
{
    return (p + 3) & (~(ULONG_PTR)3);
}

static inline BOOL IsRangeValid(
    _In_ SIZE_T BaseSize,
    _In_ SIZE_T Offset,
    _In_ SIZE_T Length
)
{
    SIZE_T start = Offset;
    SIZE_T len = Length;

    if (start >= BaseSize) return FALSE;
    if (len > BaseSize - start) return FALSE;
    return TRUE;
}

/*
* PEImageEnumVarFileInfo
*
* Purpose:
*
* Enumerate version info variables in the given module.
*
*/
BOOL PEImageEnumVarFileInfo(
    _In_ PIMGVSTRING hdr,
    _In_ PVOID BasePtr,
    _In_ SIZE_T BaseSize,
    _In_ PEnumVarInfoCallback vcallback,
    _In_opt_ PVOID cbparam)
{
    ULONG_PTR   vLimit;
    PDWORD      value;
    DWORD       uZero = 0;
    SIZE_T      hdrOffset;

    if (hdr == NULL || vcallback == NULL || BasePtr == NULL)
        return FALSE;

    hdrOffset = (SIZE_T)((ULONG_PTR)hdr - (ULONG_PTR)BasePtr);
    if (!IsRangeValid(BaseSize, hdrOffset, sizeof(IMGVARINFO)))
        return FALSE;

    if (!IsRangeValid(BaseSize, hdrOffset, hdr->vshdr.wLength))
        return FALSE;

    vLimit = (ULONG_PTR)hdr + hdr->vshdr.wLength;

    for (
        /* first child structure */
        hdr = (PIMGVSTRING)ALIGN_UP_32((ULONG_PTR)hdr + sizeof(IMGVARINFO));
        (ULONG_PTR)hdr < vLimit;
        hdr = (PIMGVSTRING)ALIGN_UP_32((ULONG_PTR)hdr + hdr->vshdr.wLength))
    {
        hdrOffset = (SIZE_T)((ULONG_PTR)hdr - (ULONG_PTR)BasePtr);
        if (!IsRangeValid(BaseSize, hdrOffset, sizeof(IMGVARINFO)))
            return FALSE;

        if (hdr->vshdr.wValueLength == 0) {
            value = &uZero;
        }
        else {
            SIZE_T valueOffset = (SIZE_T)((ULONG_PTR)&hdr->szKey - (ULONG_PTR)BasePtr);
            SIZE_T nameChars = (SIZE_T)(1 + wcslen(hdr->szKey));
            SIZE_T valuePtrOffset = valueOffset + nameChars * sizeof(WCHAR);
            valuePtrOffset = (SIZE_T)ALIGN_UP_32((ULONG_PTR)valuePtrOffset);
            if (!IsRangeValid(BaseSize, valuePtrOffset, sizeof(DWORD)))
                return FALSE;
            value = (PDWORD)RtlOffsetToPointer(BasePtr, (ULONG_PTR)valuePtrOffset);
        }

        if (!vcallback(hdr->szKey, *value, cbparam))
            return FALSE;
    }

    return TRUE;
}

/*
* PEImageEnumStrings
*
* Purpose:
*
* Enumerate strings in the given module.
*
*/
BOOL PEImageEnumStrings(
    _In_ PIMGVSTRING hdr,
    _In_ PVOID BasePtr,
    _In_ SIZE_T BaseSize,
    _In_ PEnumStringInfoCallback callback,
    _In_ PWCHAR langId,
    _In_opt_ PVOID cbparam)
{
    ULONG_PTR   vLimit;
    PWCHAR      value;
    SIZE_T      hdrOffset;
    SIZE_T      keyLenChars;

    if (hdr == NULL || callback == NULL || BasePtr == NULL)
        return FALSE;

    hdrOffset = (SIZE_T)((ULONG_PTR)hdr - (ULONG_PTR)BasePtr);
    if (!IsRangeValid(BaseSize, hdrOffset, sizeof(IMGSTRINGTABLE)))
        return FALSE;

    if (!IsRangeValid(BaseSize, hdrOffset, hdr->vshdr.wLength))
        return FALSE;

    vLimit = (ULONG_PTR)hdr + hdr->vshdr.wLength;

    for (
        /* first child structure */
        hdr = (PIMGVSTRING)ALIGN_UP_32((ULONG_PTR)hdr + sizeof(IMGSTRINGTABLE));
        (ULONG_PTR)hdr < vLimit;
        hdr = (PIMGVSTRING)ALIGN_UP_32((ULONG_PTR)hdr + hdr->vshdr.wLength))
    {
        hdrOffset = (SIZE_T)((ULONG_PTR)hdr - (ULONG_PTR)BasePtr);
        if (!IsRangeValid(BaseSize, hdrOffset, sizeof(IMGVARINFO)))
            return FALSE;

        if (hdr->vshdr.wValueLength == 0) {
            value = L"";
        }
        else {
            keyLenChars = 1 + wcslen(hdr->szKey);
            SIZE_T keyBytes = keyLenChars * sizeof(WCHAR);
            SIZE_T valuePtrOffset = (SIZE_T)((ULONG_PTR)&hdr->szKey - (ULONG_PTR)BasePtr) + keyBytes;
            valuePtrOffset = (SIZE_T)ALIGN_UP_32((ULONG_PTR)valuePtrOffset);
            if (!IsRangeValid(BaseSize, valuePtrOffset, (SIZE_T)hdr->vshdr.wValueLength))
                return FALSE;
            value = (PWCHAR)RtlOffsetToPointer(BasePtr, (ULONG_PTR)valuePtrOffset);
        }

        if (!callback(hdr->szKey, value, langId, cbparam))
            return FALSE;
    }

    return TRUE;
}

/*
* PEImageEnumStringFileInfo
*
* Purpose:
*
* Enumerate strings in version info in the given module.
*
*/
BOOL PEImageEnumStringFileInfo(
    _In_ PIMGSTRINGTABLE hdr,
    _In_ PVOID BasePtr,
    _In_ SIZE_T BaseSize,
    _In_ PEnumStringInfoCallback callback,
    _In_opt_ PVOID cbparam)
{
    ULONG_PTR   vLimit;
    SIZE_T      hdrOffset;

    if (hdr == NULL || callback == NULL || BasePtr == NULL)
        return FALSE;

    hdrOffset = (SIZE_T)((ULONG_PTR)hdr - (ULONG_PTR)BasePtr);
    if (!IsRangeValid(BaseSize, hdrOffset, sizeof(IMGSTRINGINFO)))
        return FALSE;

    if (!IsRangeValid(BaseSize, hdrOffset, hdr->vshdr.wLength))
        return FALSE;

    vLimit = (ULONG_PTR)hdr + hdr->vshdr.wLength;

    for (
        /* first child structure */
        hdr = (PIMGSTRINGTABLE)ALIGN_UP_32((ULONG_PTR)hdr + sizeof(IMGSTRINGINFO));
        (ULONG_PTR)hdr < vLimit;
        hdr = (PIMGSTRINGTABLE)ALIGN_UP_32((ULONG_PTR)hdr + hdr->vshdr.wLength))
    {
        hdrOffset = (SIZE_T)((ULONG_PTR)hdr - (ULONG_PTR)BasePtr);
        if (!IsRangeValid(BaseSize, hdrOffset, hdr->vshdr.wLength))
            return FALSE;

        if (!PEImageEnumStrings((PIMGVSTRING)hdr, BasePtr, BaseSize, callback, hdr->wIdKey, cbparam))
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
    ULONG_PTR   ids[3];
    VS_FIXEDFILEINFO* vinfo = NULL;
    PIMGVSVERSIONINFO   hdr;
    NTSTATUS status;
    SIZE_T dataSz = 0;
    ULONG_PTR vLimit;
    SIZE_T baseSize = 0;
    PVOID basePtr = NULL;

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
            hdr = (PIMGVSVERSIONINFO)rPtr;
            basePtr = rPtr;
            baseSize = dataSz;

            if (hdr == NULL || dataSz < sizeof(IMGVSVERSIONINFO)) {
                __leave;
            }

            /* validate root header length */
            if (!IsRangeValid(baseSize, 0, hdr->vshdr.wLength))
                __leave;

            vLimit = (ULONG_PTR)hdr + hdr->vshdr.wLength;

            if (hdr->vshdr.wValueLength)
                vinfo = (VS_FIXEDFILEINFO*)((ULONG_PTR)hdr + sizeof(IMGVSVERSIONINFO));

            for (
                /* first child structure */
                hdr = (PIMGVSVERSIONINFO)ALIGN_UP_32((ULONG_PTR)hdr + hdr->vshdr.wValueLength + sizeof(IMGVSVERSIONINFO));
                (ULONG_PTR)hdr < vLimit;
                hdr = (PIMGVSVERSIONINFO)ALIGN_UP_32((ULONG_PTR)hdr + hdr->vshdr.wLength))
            {
                SIZE_T hdrOffset = (SIZE_T)((ULONG_PTR)hdr - (ULONG_PTR)basePtr);
                if (!IsRangeValid(baseSize, hdrOffset, sizeof(IMGVSVERSIONINFO)))
                    break;

                if (!IsRangeValid(baseSize, hdrOffset, hdr->vshdr.wLength))
                    break;

                if (_strcmp(hdr->wIdString, L"StringFileInfo") == 0) {
                    if (!PEImageEnumStringFileInfo((PIMGSTRINGTABLE)hdr, basePtr, baseSize, scallback, cbparam))
                        break;
                }

                if (vcallback) {
                    if ((_strcmp(hdr->wIdString, L"VarFileInfo") == 0)) {
                        if (!PEImageEnumVarFileInfo((PIMGVSTRING)hdr, basePtr, baseSize, vcallback, cbparam))
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
            vinfo = NULL;
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
    _In_ ULONG sizeBytes
)
{
    if (heapHandle == NULL || buffer == NULL || sizeBytes < sizeof(WCHAR))
        return NULL;

    SIZE_T unitCount = sizeBytes / sizeof(WCHAR);
    PWCHAR p = buffer;
    PWCHAR end = buffer + unitCount;

    PSTRING_PTR head = NULL, last = NULL;

    while (p < end) {
        WCHAR c = *p;
        if (!IsWideStartChar(c)) {
            ++p;
            continue;
        }

        PWCHAR startPtr = p;
        SIZE_T len = 1;
        PWCHAR q = p + 1;
        while (q < end && len < IMGSCOPE_MAX_EXTRACTED_STR) {
            WCHAR cc = *q;
            if (!IsWideContinueChar(cc))
                break;
            ++q;
            ++len;
        }

        if (len > 2) {
            PSTRING_PTR node = RtlAllocateHeap(heapHandle, HEAP_ZERO_MEMORY, sizeof(STRING_PTR));
            if (node) {
                node->length = (ULONG)len;
                node->pnext = NULL;
                node->ofpstr = (ULONG)((ULONG_PTR)(startPtr - buffer) * sizeof(WCHAR));
                if (last)
                    last->pnext = node;
                else
                    head = node;
                last = node;
            }
        }

        p = (q > p) ? q : p + 1;
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
    if (heapHandle == NULL || buffer == NULL || size == 0)
        return NULL;

    PCHAR p = buffer;
    PCHAR end = buffer + size;

    PSTRING_PTR head = NULL, last = NULL;

    while (p < end) {
        UCHAR c = (UCHAR)*p;
        if (!IsAnsiStartChar(c)) {
            ++p;
            continue;
        }

        PCHAR startPtr = p;
        SIZE_T len = 1;
        PCHAR q = p + 1;
        while (q < end && len < IMGSCOPE_MAX_EXTRACTED_STR) {
            UCHAR cc = (UCHAR)*q;
            if (!IsAnsiContinueChar(cc))
                break;
            ++q;
            ++len;
        }

        if (len > 2) {
            PSTRING_PTR node = RtlAllocateHeap(heapHandle, HEAP_ZERO_MEMORY, sizeof(STRING_PTR));
            if (node) {
                node->length = (ULONG)len;
                node->pnext = NULL;
                node->ofpstr = (ULONG)(startPtr - buffer);
                if (last)
                    last->pnext = node;
                else
                    head = node;
                last = node;
            }
        }

        p = (q > p) ? q : p + 1;
    }

    return head;
}
