/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2021 - 2022
*
*  TITLE:       HASH.H
*
*  VERSION:     2.00
*
*  DATE:        19 Jun 2022
*
*  Header file for the hash support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#include <bcrypt.h>
#pragma comment(lib, "Bcrypt.lib")

typedef struct _CNG_CTX {
    PVOID Hash;
    PVOID HashObject;
    ULONG HashSize;
    ULONG HashObjectSize;
    BCRYPT_ALG_HANDLE AlgHandle;
    BCRYPT_HASH_HANDLE HashHandle;
    HANDLE HeapHandle;
} CNG_CTX, * PCNG_CTX;

NTSTATUS CreateHashContext(
    _In_ HANDLE HeapHandle,
    _In_ PCWSTR AlgId,
    _Out_ PCNG_CTX* Context);

VOID DestroyHashContext(
    _In_ PCNG_CTX Context);

NTSTATUS HashLoadFile(
    _In_ PFILE_VIEW_INFO ViewInformation,
    _In_ BOOLEAN PartialMap);

FORCEINLINE VOID HashUnloadFile(
    _In_ PFILE_VIEW_INFO ViewInformation
)
{
    supDestroyFileViewInfo(ViewInformation);
}

LPWSTR ComputeHashForFile(
    _In_ PFILE_VIEW_INFO ViewInformation,
    _In_ LPCWSTR lpAlgId,
    _In_ DWORD PageSize,
    _In_ HANDLE HeapHandle,
    _In_ BOOLEAN FirstPageHashOnly);
