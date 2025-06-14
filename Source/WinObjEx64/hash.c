/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2021 - 2025
*
*  TITLE:       HASH.C
*
*  VERSION:     2.08
*
*  DATE:        12 Jun 2025
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

#define DEFAULT_ALIGN_BYTES 8

/*
* CreateHashContext
*
* Purpose:
*
* Allocate CNG context for given algorithm
*
*/
NTSTATUS CreateHashContext(
    _In_ HANDLE HeapHandle,
    _In_ PCWSTR AlgId,
    _Out_ PCNG_CTX* Context
)
{
    NTSTATUS ntStatus;
    ULONG cbResult = 0;
    PCNG_CTX context;

    *Context = NULL;

    context = (PCNG_CTX)HeapAlloc(HeapHandle,
        HEAP_ZERO_MEMORY, sizeof(CNG_CTX));

    if (context == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    do {

        context->HeapHandle = HeapHandle;

        ntStatus = BCryptOpenAlgorithmProvider(&context->AlgHandle,
            AlgId,
            NULL,
            0);

        if (!NT_SUCCESS(ntStatus))
            break;

        ntStatus = BCryptGetProperty(context->AlgHandle,
            BCRYPT_OBJECT_LENGTH,
            (PUCHAR)&context->HashObjectSize,
            sizeof(ULONG),
            &cbResult,
            0);

        if (!NT_SUCCESS(ntStatus))
            break;

        ntStatus = BCryptGetProperty(context->AlgHandle,
            BCRYPT_HASH_LENGTH,
            (PUCHAR)&context->HashSize,
            sizeof(ULONG),
            &cbResult,
            0);

        if (!NT_SUCCESS(ntStatus))
            break;

        context->HashObject = (PVOID)HeapAlloc(HeapHandle,
            HEAP_ZERO_MEMORY,
            context->HashObjectSize);

        if (context->HashObject == NULL) {
            ntStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }


        context->Hash = (PVOID)HeapAlloc(HeapHandle,
            HEAP_ZERO_MEMORY,
            context->HashSize);

        if (context->Hash == NULL) {
            ntStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        ntStatus = BCryptCreateHash(context->AlgHandle,
            &context->HashHandle,
            (PUCHAR)context->HashObject,
            context->HashObjectSize,
            NULL,
            0,
            0);

        if (!NT_SUCCESS(ntStatus))
            break;

        *Context = context;
        return STATUS_SUCCESS;

    } while (FALSE);

    if (context->Hash) HeapFree(HeapHandle, 0, context->Hash);
    if (context->HashObject) HeapFree(HeapHandle, 0, context->HashObject);
    if (context->AlgHandle) BCryptCloseAlgorithmProvider(context->AlgHandle, 0);
    HeapFree(HeapHandle, 0, context);

    return ntStatus;
}

/*
* DestroyHashContext
*
* Purpose:
*
* Release all resources allocated for CNG context
*
*/
VOID DestroyHashContext(
    _In_ PCNG_CTX Context
)
{
    HANDLE heapHandle;

    if (!Context) return;

    heapHandle = Context->HeapHandle;

    if (Context->AlgHandle)
        BCryptCloseAlgorithmProvider(Context->AlgHandle, 0);
    if (Context->HashHandle)
        BCryptDestroyHash(Context->HashHandle);
    if (Context->Hash)
        HeapFree(heapHandle, 0, Context->Hash);
    if (Context->HashObject)
        HeapFree(heapHandle, 0, Context->HashObject);

    HeapFree(heapHandle, 0, Context);
}

/*
* HashpAddPad
*
* Purpose:
*
* Calculate hash for pad bytes
*
*/
NTSTATUS HashpAddPad(
    _In_ ULONG PaddingSize,
    _In_ PCNG_CTX HashContext)
{
    static const UCHAR zeroPad[DEFAULT_ALIGN_BYTES] = { 0 };
    NTSTATUS ntStatus = STATUS_SUCCESS;
    ULONG remainingPad = PaddingSize;
    ULONG blockSize;

    if (PaddingSize == 0)
        return STATUS_SUCCESS;

    while (remainingPad > 0) {
        blockSize = min(remainingPad, DEFAULT_ALIGN_BYTES);
        ntStatus = BCryptHashData(HashContext->HashHandle,
            (PUCHAR)zeroPad, blockSize, 0);

        if (!NT_SUCCESS(ntStatus))
            break;

        remainingPad -= blockSize;
    }

    return ntStatus;
}

/*
* HashpGetSizeOfHeaders
*
* Purpose:
*
* Return PE OptionalHeader size of headers
*
*/
DWORD HashpGetSizeOfHeaders(
    _In_ PIMAGE_NT_HEADERS NtHeaders
)
{
    switch (NtHeaders->OptionalHeader.Magic) {
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        return ((PIMAGE_OPTIONAL_HEADER64)&NtHeaders->OptionalHeader)->SizeOfHeaders;
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        return ((PIMAGE_OPTIONAL_HEADER32)&NtHeaders->OptionalHeader)->SizeOfHeaders;
    default:
        return 0;
    }
}

/*
* HashpGetExcludeRange
*
* Purpose:
*
* Retrieve data and offsets to be skipped during hash calculation
*
*/
BOOLEAN HashpGetExcludeRange(
    _In_ PFILE_VIEW_INFO ViewInformation
)
{
    ULONG securityOffset = 0, checksumOffset = 0, endOfLastSection, numberOfSections;
    PIMAGE_DATA_DIRECTORY dataDirectory = NULL;

    PIMAGE_SECTION_HEADER sectionTableEntry;
    PIMAGE_OPTIONAL_HEADER64 opt64 = NULL;
    PIMAGE_OPTIONAL_HEADER32 opt32 = NULL;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ViewInformation->ViewBase;

    switch (ViewInformation->NtHeaders->OptionalHeader.Magic) {

    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:

        checksumOffset = dosHeader->e_lfanew +
            UFIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader.CheckSum);
        securityOffset = dosHeader->e_lfanew +
            UFIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]);

        opt64 = (PIMAGE_OPTIONAL_HEADER64)&ViewInformation->NtHeaders->OptionalHeader;
        dataDirectory = &opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];

        break;

    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:

        checksumOffset = dosHeader->e_lfanew +
            UFIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader.CheckSum);
        securityOffset = dosHeader->e_lfanew +
            UFIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]);

        opt32 = (PIMAGE_OPTIONAL_HEADER32)&ViewInformation->NtHeaders->OptionalHeader;
        dataDirectory = &opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];

        break;

    default:
        ViewInformation->Status = StatusBadOptionalHeaderMagic;
        return FALSE;
    }

    if (dataDirectory->VirtualAddress) {

        numberOfSections = ViewInformation->NtHeaders->FileHeader.NumberOfSections;
        if (numberOfSections == 0) {
            ViewInformation->Status = StatusBadSectionCount;
            return FALSE;
        }

        sectionTableEntry = IMAGE_FIRST_SECTION(ViewInformation->NtHeaders);
        endOfLastSection = sectionTableEntry[numberOfSections - 1].PointerToRawData +
            sectionTableEntry[numberOfSections - 1].SizeOfRawData;

        if (dataDirectory->VirtualAddress < endOfLastSection) {
            ViewInformation->Status = StatusBadSecurityDirectoryVA;
            return FALSE;
        }

        if (dataDirectory->VirtualAddress >= ViewInformation->FileSize.LowPart) {
            ViewInformation->Status = StatusBadSecurityDirectoryVA;
            return FALSE;
        }

        if (dataDirectory->Size > (ViewInformation->FileSize.LowPart - dataDirectory->VirtualAddress)) {
            ViewInformation->Status = StatusBadSecurityDirectorySize;
            return FALSE;
        }

    }

    ViewInformation->ExcludeData.ChecksumOffset = checksumOffset;
    ViewInformation->ExcludeData.SecurityOffset = securityOffset;
    ViewInformation->ExcludeData.SecurityDirectory = dataDirectory;

    return TRUE;
}

/*
* HashLoadFile
*
* Purpose:
*
* Load PE file in memory and validate it structure
*
*/
NTSTATUS HashLoadFile(
    _In_ PFILE_VIEW_INFO ViewInformation,
    _In_ BOOLEAN PartialMap
)
{
    NTSTATUS ntStatus;

    ntStatus = supMapInputFileForRead(ViewInformation, PartialMap);
    if (NT_SUCCESS(ntStatus)) {
        ntStatus = STATUS_INVALID_IMAGE_FORMAT;
        if (supIsValidImage(ViewInformation)) {
            ViewInformation->NtHeaders = RtlImageNtHeader(ViewInformation->ViewBase);
            if (ViewInformation->NtHeaders) {
                if (HashpGetExcludeRange(ViewInformation)) {
                    return STATUS_SUCCESS;
                }
            }
            else {
                ViewInformation->Status = StatusBadNtHeaders;
            }
        }
    }
    supDestroyFileViewInfo(ViewInformation);
    return ntStatus;
}

/*
* CalculateFirstPageHash
*
* Purpose:
*
* Compute page hash for PE headers (WDAC compliant), buffer based processing
*
*/
BOOLEAN CalculateFirstPageHash(
    _In_ ULONG PageSize,
    _In_ PFILE_VIEW_INFO ViewInformation,
    _In_ PCNG_CTX HashContext
)
{
    ULONG offset;
    NTSTATUS ntStatus = STATUS_INVALID_IMAGE_FORMAT;
    ULONG sizeOfHeaders = HashpGetSizeOfHeaders(ViewInformation->NtHeaders);
    PVOID pvImage = ViewInformation->ViewBase;

    __try {
        offset = 0;

        while (offset < PageSize) {
            if (offset == ViewInformation->ExcludeData.ChecksumOffset)
                offset += RTL_FIELD_SIZE(IMAGE_OPTIONAL_HEADER, CheckSum);
            else if (offset == ViewInformation->ExcludeData.SecurityOffset)
                offset += sizeof(IMAGE_DATA_DIRECTORY);

            if (offset >= sizeOfHeaders)
                break;

            ntStatus = BCryptHashData(HashContext->HashHandle,
                (PUCHAR)RtlOffsetToPointer(pvImage, offset), sizeof(BYTE), 0);

            if (!NT_SUCCESS(ntStatus))
                return FALSE;

            offset += 1;
        }

        if (offset < PageSize) {
            ntStatus = HashpAddPad(PageSize - offset, HashContext);
            if (!NT_SUCCESS(ntStatus))
                return FALSE;
        }

        ntStatus = BCryptFinishHash(HashContext->HashHandle,
            (PUCHAR)HashContext->Hash,
            HashContext->HashSize,
            0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ViewInformation->Status = StatusExceptionOccurred;
        return FALSE;
    }

    return NT_SUCCESS(ntStatus);
}

/*
* CalculateAuthenticodeHash
*
* Purpose:
*
* Compute authenticode hash for image file
*
*/
BOOLEAN CalculateAuthenticodeHash(
    _In_ PFILE_VIEW_INFO ViewInformation,
    _In_ PCNG_CTX HashContext
)
{
    NTSTATUS ntStatus = STATUS_INVALID_IMAGE_FORMAT;
    ULONG securityOffset, checksumOffset, paddingSize;
    ULONG fileOffset = 0, dataSize;
    PVOID imageBase;
    PIMAGE_DATA_DIRECTORY dataDirectory;

    __try {

        imageBase = ViewInformation->ViewBase;
        checksumOffset = ViewInformation->ExcludeData.ChecksumOffset;
        securityOffset = ViewInformation->ExcludeData.SecurityOffset;
        dataDirectory = ViewInformation->ExcludeData.SecurityDirectory;

        // 1. Start of file to checksum
        ntStatus = BCryptHashData(HashContext->HashHandle,
            (PUCHAR)imageBase, checksumOffset, 0);

        if (NT_SUCCESS(ntStatus)) {

            // Skip checksum
            fileOffset = checksumOffset + RTL_FIELD_SIZE(IMAGE_OPTIONAL_HEADER, CheckSum);

            // 2. After checksum to security directory
            dataSize = securityOffset - fileOffset;
            ntStatus = BCryptHashData(HashContext->HashHandle,
                (PUCHAR)RtlOffsetToPointer(imageBase, fileOffset), dataSize, 0);

            if (NT_SUCCESS(ntStatus)) {

                // Skip security directory
                fileOffset = securityOffset + sizeof(IMAGE_DATA_DIRECTORY);

                // 3. After security directory to end or certificate table
                if (dataDirectory->VirtualAddress == 0) {
                    dataSize = ViewInformation->FileSize.LowPart - fileOffset;
                }
                else {
                    dataSize = dataDirectory->VirtualAddress - fileOffset;
                }

                ntStatus = BCryptHashData(HashContext->HashHandle,
                    (PUCHAR)RtlOffsetToPointer(imageBase, fileOffset), dataSize, 0);

                if (NT_SUCCESS(ntStatus)) {

                    // 4. Add padding if needed
                    paddingSize = (dataSize % DEFAULT_ALIGN_BYTES);
                    if (paddingSize) {
                        paddingSize = (DEFAULT_ALIGN_BYTES - paddingSize);
                        ntStatus = HashpAddPad(paddingSize, HashContext);
                        if (!NT_SUCCESS(ntStatus))
                            return FALSE;
                    }

                    ntStatus = BCryptFinishHash(HashContext->HashHandle,
                        (PUCHAR)HashContext->Hash,
                        HashContext->HashSize,
                        0);

                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ViewInformation->Status = StatusExceptionOccurred;
        return FALSE;
    }

    return NT_SUCCESS(ntStatus);
}

LPWSTR ComputeHashForFile(
    _In_ PFILE_VIEW_INFO ViewInformation,
    _In_ LPCWSTR lpAlgId,
    _In_ DWORD PageSize,
    _In_ HANDLE HeapHandle,
    _In_ BOOLEAN FirstPageHashOnly
)
{
    BOOLEAN bComputed;
    PCNG_CTX hashContext;
    LPWSTR lpszHash = NULL;

    if (NT_SUCCESS(CreateHashContext(HeapHandle, lpAlgId, &hashContext))) {

        bComputed = FirstPageHashOnly ?
            CalculateFirstPageHash(PageSize, ViewInformation, hashContext) :
            CalculateAuthenticodeHash(ViewInformation, hashContext);

        if (bComputed) {
            lpszHash = (LPWSTR)supPrintHash((PUCHAR)hashContext->Hash,
                hashContext->HashSize,
                TRUE);
        }

        DestroyHashContext(hashContext);
    }

    return lpszHash;
}
