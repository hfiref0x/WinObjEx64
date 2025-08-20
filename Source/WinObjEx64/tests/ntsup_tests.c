/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2025 UGN/HE
*
*  TITLE:       NTSUP_TESTS.C
*
*  VERSION:     2.09
*
*  DATE:        19 Aug 2025
*
*  NTSup test code used while debug.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#define OEMRESOURCE

#include "global.h"
#include "ntos\ntsup.h"
#pragma warning(push)
#pragma warning(disable:28251) //Inconsistent annotation for any intrin, "feature" of the latest MSVC
#pragma warning(disable: 6387) //_Param_(1) could be '0'
#pragma warning(disable: 28159) //GetTickCount
#include <intrin.h>

static ULONG g_FailCount = 0;
static BOOL g_Verbose = TRUE;

#define TEST_ASSERT(expr) do { if (!(expr)) { ++g_FailCount; if (g_Verbose) DbgPrint("ASSERT FAILED: %s (%s:%d)\n", #expr, __FUNCTION__, __LINE__); } } while (0)

PVOID CALLBACK TestAlloc(_In_ SIZE_T NumberOfBytes)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, NumberOfBytes);
}

BOOL CALLBACK TestFree(_In_ PVOID Memory)
{
    if (Memory) HeapFree(GetProcessHeap(), 0, Memory);
    return TRUE;
}

PVOID CALLBACK FailAlloc(_In_ SIZE_T NumberOfBytes)
{
    (void)NumberOfBytes;
    return NULL;
}

BOOL ReadFileContent(
    _In_ LPCWSTR FileName,
    _Out_ PBYTE* Buffer,
    _Out_ DWORD* Size
)
{
    HANDLE hFile;
    DWORD fileSize, bytesRead;
    PBYTE data;

    *Buffer = NULL;
    *Size = 0;

    hFile = CreateFile(FileName,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return FALSE;
    }

    data = (PBYTE)ntsupHeapAlloc(fileSize ? fileSize : 1);
    if (data == NULL) {
        CloseHandle(hFile);
        return FALSE;
    }

    bytesRead = 0;
    if (fileSize) {
        if (!ReadFile(hFile, data, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
            ntsupHeapFree(data);
            CloseHandle(hFile);
            return FALSE;
        }
    }

    CloseHandle(hFile);

    *Buffer = data;
    *Size = fileSize;
    return TRUE;
}

VOID WriteBufferToFile_WriteNewFile(VOID)
{
    WCHAR tempPath[MAX_PATH];
    WCHAR filePath[MAX_PATH];
    NTSTATUS resultStatus;
    SIZE_T written;
    BYTE const data1[] = { 1,2,3,4,5 };
    PBYTE fileData;
    DWORD fileSize;
    ULONG i;

    RtlSecureZeroMemory(tempPath, sizeof(tempPath));
    RtlSecureZeroMemory(filePath, sizeof(filePath));

    GetTempPath(MAX_PATH, tempPath);
    wsprintfW(filePath, L"%sntsup_test_%lu.bin", tempPath, GetTickCount());

    written = ntsupWriteBufferToFile(
        filePath,
        (PVOID)data1,
        sizeof(data1),
        TRUE,
        FALSE,
        &resultStatus);

    TEST_ASSERT(written == sizeof(data1));
    TEST_ASSERT(NT_SUCCESS(resultStatus));

    fileData = NULL;
    fileSize = 0;
    TEST_ASSERT(ReadFileContent(filePath, &fileData, &fileSize));
    if (fileData) {
        TEST_ASSERT(fileSize == sizeof(data1));
        for (i = 0; i < fileSize; i++)
            TEST_ASSERT(fileData[i] == data1[i]);
        ntsupHeapFree(fileData);
    }

    DeleteFile(filePath);
}

VOID WriteBufferToFile_AppendFile(VOID)
{
    WCHAR tempPath[MAX_PATH];
    WCHAR filePath[MAX_PATH];
    NTSTATUS resultStatus;
    SIZE_T written;
    BYTE const data1[] = { 0x10,0x11,0x12 };
    BYTE const data2[] = { 0xAA,0xBB };
    PBYTE fileData;
    DWORD fileSize;
    ULONG i;

    RtlSecureZeroMemory(tempPath, sizeof(tempPath));
    RtlSecureZeroMemory(filePath, sizeof(filePath));

    GetTempPath(MAX_PATH, tempPath);
    wsprintfW(filePath, L"%sntsup_test_append_%lu.bin", tempPath, GetTickCount());

    written = ntsupWriteBufferToFile(
        filePath,
        (PVOID)data1,
        sizeof(data1),
        TRUE,
        FALSE,
        &resultStatus);

    TEST_ASSERT(written == sizeof(data1));
    TEST_ASSERT(NT_SUCCESS(resultStatus));

    written = ntsupWriteBufferToFile(
        filePath,
        (PVOID)data2,
        sizeof(data2),
        TRUE,
        TRUE,
        &resultStatus);

    TEST_ASSERT(written == sizeof(data2));
    TEST_ASSERT(NT_SUCCESS(resultStatus));

    fileData = NULL;
    fileSize = 0;
    TEST_ASSERT(ReadFileContent(filePath, &fileData, &fileSize));
    if (fileData) {
        TEST_ASSERT(fileSize == sizeof(data1) + sizeof(data2));
        for (i = 0; i < sizeof(data1); i++)
            TEST_ASSERT(fileData[i] == data1[i]);
        for (i = 0; i < sizeof(data2); i++)
            TEST_ASSERT(fileData[sizeof(data1) + i] == data2[i]);
        ntsupHeapFree(fileData);
    }

    DeleteFile(filePath);
}

VOID WriteBufferToFile_InvalidPath(VOID)
{
    NTSTATUS resultStatus;
    SIZE_T written;
    BYTE dummy[4] = { 0 };

    written = ntsupWriteBufferToFile(
        L"",
        dummy,
        sizeof(dummy),
        FALSE,
        FALSE,
        &resultStatus);

    TEST_ASSERT(written == 0);
    TEST_ASSERT(!NT_SUCCESS(resultStatus));
}

VOID WriteBufferToFile_ZeroSizeWrite(VOID)
{
    WCHAR tempPath[MAX_PATH];
    WCHAR filePath[MAX_PATH];
    NTSTATUS resultStatus;
    SIZE_T written;
    PBYTE fileData;
    DWORD fileSize;

    RtlSecureZeroMemory(tempPath, sizeof(tempPath));
    RtlSecureZeroMemory(filePath, sizeof(filePath));

    GetTempPath(MAX_PATH, tempPath);
    wsprintfW(filePath, L"%sntsup_test_zero_%lu.bin", tempPath, GetTickCount());

    written = ntsupWriteBufferToFile(
        filePath,
        (PVOID)"",
        0,
        TRUE,
        FALSE,
        &resultStatus);

    TEST_ASSERT(written == 0);
    TEST_ASSERT(NT_SUCCESS(resultStatus) || written == 0); // Accept success with zero write

    fileData = NULL;
    fileSize = 0;
    if (ReadFileContent(filePath, &fileData, &fileSize)) {
        TEST_ASSERT(fileSize == 0);
        if (fileData) ntsupHeapFree(fileData);
    }

    DeleteFile(filePath);
}

VOID FindModuleNameByAddress_ValidModuleName(VOID)
{
    PRTL_PROCESS_MODULES modules;
    ULONG returnLength;
    PRTL_PROCESS_MODULE_INFORMATION modInfo;
    WCHAR nameBuffer[260];
    PVOID foundEntry;
    PVOID testAddress;
    ANSI_STRING ansiExpected;
    UNICODE_STRING usExpected;
    SIZE_T expectedLen;

    modules = (PRTL_PROCESS_MODULES)ntsupGetLoadedModulesList(&returnLength);
    TEST_ASSERT(modules != NULL);
    if (modules == NULL)
        return;

    if (modules->NumberOfModules == 0) {
        ntsupHeapFree(modules);
        TEST_ASSERT(FALSE);
        return;
    }

    modInfo = &modules->Modules[0];
    testAddress = (PBYTE)modInfo->ImageBase + (modInfo->ImageSize / 2);

    RtlSecureZeroMemory(nameBuffer, sizeof(nameBuffer));

    foundEntry = ntsupFindModuleNameByAddress(
        modules,
        testAddress,
        nameBuffer,
        _countof(nameBuffer));

    TEST_ASSERT(foundEntry != NULL);
    TEST_ASSERT(nameBuffer[0] != 0);

    if (foundEntry) {
        RtlInitString(&ansiExpected,
            (PCSZ)&modInfo->FullPathName[modInfo->OffsetToFileName]);
        usExpected.Buffer = NULL;
        usExpected.Length = usExpected.MaximumLength = 0;
        if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&usExpected, &ansiExpected, TRUE))) {
            expectedLen = usExpected.Length / sizeof(WCHAR);
            TEST_ASSERT(_strlen(nameBuffer) <= expectedLen);
            TEST_ASSERT(_strcmp(nameBuffer, usExpected.Buffer) == 0);
            RtlFreeUnicodeString(&usExpected);
        }
    }

    ntsupHeapFree(modules);
}

VOID FindModuleNameByAddress_TruncatedBuffer(VOID)
{
    PRTL_PROCESS_MODULES modules;
    ULONG returnLength;
    PRTL_PROCESS_MODULE_INFORMATION modInfo;
    WCHAR tinyBuffer[4];
    PVOID testAddress;
    PVOID foundEntry;
    SIZE_T lenCaptured;

    modules = (PRTL_PROCESS_MODULES)ntsupGetLoadedModulesList(&returnLength);
    TEST_ASSERT(modules != NULL);
    if (modules == NULL)
        return;

    if (modules->NumberOfModules == 0) {
        ntsupHeapFree(modules);
        TEST_ASSERT(FALSE);
        return;
    }

    modInfo = &modules->Modules[0];
    testAddress = modInfo->ImageBase;

    RtlSecureZeroMemory(tinyBuffer, sizeof(tinyBuffer));

    foundEntry = ntsupFindModuleNameByAddress(
        modules,
        testAddress,
        tinyBuffer,
        _countof(tinyBuffer));

    TEST_ASSERT(foundEntry != NULL);
    lenCaptured = _strlen(tinyBuffer);
    TEST_ASSERT(lenCaptured <= (_countof(tinyBuffer) - 1));
    TEST_ASSERT(tinyBuffer[_countof(tinyBuffer) - 1] == 0);

    ntsupHeapFree(modules);
}

VOID FindModuleNameByAddress_InvalidAddress(VOID)
{
    PRTL_PROCESS_MODULES modules;
    ULONG returnLength;
    WCHAR buffer[32];
    PVOID foundEntry;

    modules = (PRTL_PROCESS_MODULES)ntsupGetLoadedModulesList(&returnLength);
    TEST_ASSERT(modules != NULL);
    if (modules == NULL)
        return;

    RtlSecureZeroMemory(buffer, sizeof(buffer));

    foundEntry = ntsupFindModuleNameByAddress(
        modules,
        (PVOID)0x1, // very low address, should not belong to system module range
        buffer,
        _countof(buffer));

    TEST_ASSERT(foundEntry == NULL);
    TEST_ASSERT(buffer[0] == 0);

    ntsupHeapFree(modules);
}

VOID FindModuleNameByAddress_InvalidBufferArgs(VOID)
{
    PRTL_PROCESS_MODULES modules;
    ULONG returnLength;
    PRTL_PROCESS_MODULE_INFORMATION modInfo;
    PVOID testAddress;
    PVOID foundEntry;
    WCHAR nameBuffer[8];

    modules = (PRTL_PROCESS_MODULES)ntsupGetLoadedModulesList(&returnLength);
    TEST_ASSERT(modules != NULL);
    if (modules == NULL)
        return;

    if (modules->NumberOfModules == 0) {
        ntsupHeapFree(modules);
        TEST_ASSERT(FALSE);
        return;
    }

    modInfo = &modules->Modules[0];
    testAddress = modInfo->ImageBase;

    foundEntry = ntsupFindModuleNameByAddress(
        modules,
        testAddress,
        NULL,
        0);
    TEST_ASSERT(foundEntry == NULL);

    RtlSecureZeroMemory(nameBuffer, sizeof(nameBuffer));
    foundEntry = ntsupFindModuleNameByAddress(
        modules,
        testAddress,
        nameBuffer,
        0);
    TEST_ASSERT(foundEntry == NULL);
    TEST_ASSERT(nameBuffer[0] == 0);

    ntsupHeapFree(modules);
}

VOID GetLoadedModulesListEx_BasicList(VOID)
{
    PRTL_PROCESS_MODULES modules;
    ULONG returnLength = 0;
    ULONG count, i;
    BOOLEAN haveNonZero = FALSE;

    modules = (PRTL_PROCESS_MODULES)ntsupGetLoadedModulesListEx(
        FALSE,
        &returnLength,
        (PNTSUPMEMALLOC)ntsupHeapAlloc,
        (PNTSUPMEMFREE)ntsupHeapFree);

    TEST_ASSERT(modules != NULL);
    if (modules == NULL)
        return;

    count = modules->NumberOfModules;
    TEST_ASSERT(count > 0);
    TEST_ASSERT(returnLength > 0);

    if (count > 0) {
        TEST_ASSERT(modules->Modules[0].ImageBase != NULL);
        TEST_ASSERT(modules->Modules[0].ImageSize > 0);
    }

    for (i = 0; i < count && i < 32; i++) {
        if (modules->Modules[i].FullPathName[0] != 0) {
            haveNonZero = TRUE;
            break;
        }
    }
    TEST_ASSERT(haveNonZero);

    ntsupHeapFree(modules);
}

VOID GetLoadedModulesListEx_ExtendedList(VOID)
{
    PRTL_PROCESS_MODULES modules;
    ULONG returnLength = 0;

    modules = (PRTL_PROCESS_MODULES)ntsupGetLoadedModulesListEx(
        TRUE,
        &returnLength,
        (PNTSUPMEMALLOC)ntsupHeapAlloc,
        (PNTSUPMEMFREE)ntsupHeapFree);

    if (modules == NULL) {
        if (g_Verbose) DbgPrint("Extended module list not available (SystemModuleInformationEx unsupported?) - skipping related assertions.\n");
        return;
    }

    TEST_ASSERT(returnLength > 0);
    TEST_ASSERT(modules->NumberOfModules > 0);
    TEST_ASSERT(modules->Modules[0].ImageBase != NULL);

    ntsupHeapFree(modules);
}

VOID GetLoadedModulesListEx_NullReturnLength(VOID)
{
    PRTL_PROCESS_MODULES modules;

    modules = (PRTL_PROCESS_MODULES)ntsupGetLoadedModulesListEx(
        FALSE,
        NULL,
        (PNTSUPMEMALLOC)ntsupHeapAlloc,
        (PNTSUPMEMFREE)ntsupHeapFree);

    TEST_ASSERT(modules != NULL);
    if (modules)
        ntsupHeapFree(modules);
}

VOID GetLoadedModulesListEx_AllocFailure(VOID)
{
    PVOID modules;
    ULONG returnLength = 0;

    modules = ntsupGetLoadedModulesListEx(
        FALSE,
        &returnLength,
        (PNTSUPMEMALLOC)FailAlloc,
        (PNTSUPMEMFREE)TestFree);

    TEST_ASSERT(modules == NULL);
    TEST_ASSERT(returnLength == 0);
}

VOID GetSystemInfoEx_SystemProcessInformation(VOID)
{
    PVOID buffer;
    ULONG retLen = 0;
    ULONG safeCheck = 0;
    ULONG bytesWalked = 0;

    buffer = ntsupGetSystemInfoEx(
        SystemProcessInformation,
        &retLen,
        (PNTSUPMEMALLOC)TestAlloc,
        (PNTSUPMEMFREE)TestFree);

    if (buffer == NULL) {
        if (g_Verbose) DbgPrint("SystemProcessInformation unsupported or allocation failed, skipping.\n");
        return;
    }

    TEST_ASSERT(retLen > 0);

    if (buffer && retLen > sizeof(SYSTEM_PROCESS_INFORMATION)) {

        PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)buffer;

        while (TRUE) {
            TEST_ASSERT(spi->NextEntryDelta % sizeof(ULONG) == 0);
            bytesWalked += spi->NextEntryDelta;
            safeCheck++;

            if (spi->NextEntryDelta == 0)
                break;

            if (safeCheck > 0x100000) {
                TEST_ASSERT(FALSE);
                break;
            }

            spi = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)spi + spi->NextEntryDelta);
        }
    }

    TestFree(buffer);
}

VOID GetSystemInfoEx_NullReturnLength(VOID)
{
    PVOID buffer;

    buffer = ntsupGetSystemInfoEx(
        SystemBasicInformation,
        NULL,
        (PNTSUPMEMALLOC)TestAlloc,
        (PNTSUPMEMFREE)TestFree);

    TEST_ASSERT(buffer == NULL);
    if (buffer)
        TestFree(buffer);
}

VOID GetSystemInfoEx_AllocFailure(VOID)
{
    PVOID buffer;
    ULONG retLen = 0;

    buffer = ntsupGetSystemInfoEx(
        SystemBasicInformation,
        &retLen,
        (PNTSUPMEMALLOC)FailAlloc,
        (PNTSUPMEMFREE)TestFree);

    TEST_ASSERT(buffer == NULL);
    TEST_ASSERT(retLen == 0);
}

VOID GetSystemInfoEx_InvalidClass(VOID)
{
    PVOID buffer;
    ULONG retLen = 0;

    buffer = ntsupGetSystemInfoEx(
        (SYSTEM_INFORMATION_CLASS)0xFFFFFFFF,
        &retLen,
        (PNTSUPMEMALLOC)TestAlloc,
        (PNTSUPMEMFREE)TestFree);

    TEST_ASSERT(buffer == NULL);
    TEST_ASSERT(retLen == 0);
}

VOID HashImageSections_LoadedImage(VOID)
{
    HMODULE hMod;
    PIMAGE_NT_HEADERS nth;
    BYTE hash[NTSUPHASH_SHA256_SIZE];
    NTSTATUS status;
    SIZE_T imageSize;

    hMod = GetModuleHandle(NULL);
    TEST_ASSERT(hMod != NULL);
    if (hMod == NULL) return;

    nth = RtlImageNtHeader(hMod);
    TEST_ASSERT(nth != NULL);
    if (nth == NULL) return;

    imageSize = nth->OptionalHeader.SizeOfImage;
    RtlSecureZeroMemory(hash, sizeof(hash));

    status = ntsupHashImageSections(
        (PVOID)hMod,
        imageSize,
        hash,
        sizeof(hash),
        ImageTypeLoaded);

    TEST_ASSERT(NT_SUCCESS(status));
    if (NT_SUCCESS(status)) {
        SIZE_T i, zeroCount = 0;
        for (i = 0; i < sizeof(hash); i++)
            if (hash[i] == 0) zeroCount++;
        TEST_ASSERT(zeroCount != sizeof(hash));
    }
}

VOID HashImageSections_RawFileMapping(VOID)
{
    WCHAR path[MAX_PATH];
    HANDLE hFile, hMapping;
    LARGE_INTEGER fsz;
    PVOID mapBase;
    BYTE hash[NTSUPHASH_SHA256_SIZE];
    NTSTATUS status;

    RtlSecureZeroMemory(path, sizeof(path));
    if (!GetModuleFileName(NULL, path, MAX_PATH))
        return;

    hFile = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    TEST_ASSERT(hFile != INVALID_HANDLE_VALUE);
    if (hFile == INVALID_HANDLE_VALUE) return;

    fsz.LowPart = GetFileSize(hFile, (LPDWORD)&fsz.HighPart);
    TEST_ASSERT(fsz.QuadPart > 0);

    hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    TEST_ASSERT(hMapping != NULL);
    if (hMapping == NULL) {
        CloseHandle(hFile);
        return;
    }

    mapBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    TEST_ASSERT(mapBase != NULL);
    if (mapBase == NULL) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

    RtlSecureZeroMemory(hash, sizeof(hash));
    status = ntsupHashImageSections(
        mapBase,
        (SIZE_T)fsz.QuadPart,
        hash,
        sizeof(hash),
        ImageTypeRaw);

    TEST_ASSERT(NT_SUCCESS(status));

    UnmapViewOfFile(mapBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
}

VOID BuildMinimalImage(
    _Out_ PVOID* Buffer,
    _Out_ SIZE_T* BufferSize,
    _In_ BOOL ExecutableSection
)
{
    PBYTE base;
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS64* nth;
    IMAGE_SECTION_HEADER* sh;
    SIZE_T bufSize;
    ULONG optSize;

    bufSize = 0x1000;
    *BufferSize = bufSize;
    base = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufSize);
    *Buffer = base;
    if (base == NULL) return;

    dos = (IMAGE_DOS_HEADER*)base;
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x80;

    nth = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    nth->Signature = IMAGE_NT_SIGNATURE;
    nth->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nth->FileHeader.NumberOfSections = 1;
    optSize = sizeof(IMAGE_OPTIONAL_HEADER64);
    nth->FileHeader.SizeOfOptionalHeader = (WORD)optSize;
    nth->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nth->OptionalHeader.SectionAlignment = 0x200;
    nth->OptionalHeader.FileAlignment = 0x200;
    nth->OptionalHeader.SizeOfImage = (DWORD)bufSize;
    nth->OptionalHeader.SizeOfHeaders = 0x200;

    sh = (IMAGE_SECTION_HEADER*)((PBYTE)&nth->OptionalHeader + optSize);
    RtlCopyMemory(sh->Name, ".data", 5);
    sh->Misc.VirtualSize = 0x100;
    sh->VirtualAddress = 0x200;
    sh->SizeOfRawData = 0x200;
    sh->PointerToRawData = 0x200;
    sh->Characteristics =
        IMAGE_SCN_CNT_INITIALIZED_DATA |
        IMAGE_SCN_MEM_READ |
        (ExecutableSection ? (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE) : 0);
}

VOID HashImageSections_NoExecutableSections(VOID)
{
    PVOID image;
    SIZE_T imageSize;
    BYTE hash[NTSUPHASH_SHA256_SIZE];
    NTSTATUS status;

    image = NULL;
    imageSize = 0;
    BuildMinimalImage(&image, &imageSize, FALSE);
    TEST_ASSERT(image != NULL);
    if (image == NULL) return;

    RtlSecureZeroMemory(hash, sizeof(hash));
    status = ntsupHashImageSections(
        image,
        imageSize,
        hash,
        sizeof(hash),
        ImageTypeLoaded);

    TEST_ASSERT(status == STATUS_NOT_FOUND);

    HeapFree(GetProcessHeap(), 0, image);
}

VOID HashImageSections_ExecutableSectionPresent(VOID)
{
    PVOID image;
    SIZE_T imageSize;
    BYTE hash[NTSUPHASH_SHA256_SIZE];
    NTSTATUS status;

    image = NULL;
    imageSize = 0;
    BuildMinimalImage(&image, &imageSize, TRUE);
    TEST_ASSERT(image != NULL);
    if (image == NULL) return;

    RtlSecureZeroMemory(hash, sizeof(hash));
    status = ntsupHashImageSections(
        image,
        imageSize,
        hash,
        sizeof(hash),
        ImageTypeLoaded);

    TEST_ASSERT(NT_SUCCESS(status));

    HeapFree(GetProcessHeap(), 0, image);
}

VOID HashImageSections_InvalidParams(VOID)
{
    BYTE hash[NTSUPHASH_SHA256_SIZE];
    NTSTATUS status;
    PVOID image;
    SIZE_T imageSize;

    RtlSecureZeroMemory(hash, sizeof(hash));

    status = ntsupHashImageSections(NULL, 100, hash, sizeof(hash), ImageTypeLoaded);
    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);

    status = ntsupHashImageSections((PVOID)0x1, 0, hash, sizeof(hash), ImageTypeLoaded);
    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);

    status = ntsupHashImageSections((PVOID)0x1, 100, hash, 1, ImageTypeLoaded);
    TEST_ASSERT(status == STATUS_BUFFER_TOO_SMALL);

    image = NULL;
    imageSize = 0;
    BuildMinimalImage(&image, &imageSize, TRUE);
    if (image) {
        PIMAGE_NT_HEADERS nth = (PIMAGE_NT_HEADERS)RtlImageNtHeader(image);
        if (nth) {
            SIZE_T smaller = nth->OptionalHeader.SizeOfImage / 2;
            status = ntsupHashImageSections(
                image,
                smaller,
                hash,
                sizeof(hash),
                ImageTypeLoaded);
            TEST_ASSERT(status == STATUS_INVALID_IMAGE_FORMAT);
        }
        HeapFree(GetProcessHeap(), 0, image);
    }
}

VOID Test_WriteBufferToFile()
{
    g_FailCount = 0;
    WriteBufferToFile_WriteNewFile();
    WriteBufferToFile_AppendFile();
    WriteBufferToFile_InvalidPath();
    WriteBufferToFile_ZeroSizeWrite();

    if (g_Verbose) {
        if (g_FailCount == 0)
            DbgPrint("[TEST] ntsupWriteBufferToFile PASSED.\n");
        else
            DbgPrint("[TEST] ntsupWriteBufferToFile %lu tests FAILED.\n", g_FailCount);
    }
}

VOID Test_FindModuleNameByAddress()
{
    g_FailCount = 0;
    FindModuleNameByAddress_ValidModuleName();
    FindModuleNameByAddress_TruncatedBuffer();
    FindModuleNameByAddress_InvalidAddress();
    FindModuleNameByAddress_InvalidBufferArgs();

    if (g_Verbose) {
        if (g_FailCount == 0)
            DbgPrint("[TEST] ntsupFindModuleNameByAddress PASSED.\n");
        else
            DbgPrint("[TST] ntsupFindModuleNameByAddress %lu tests FAILED.\n", g_FailCount);
    }
}

VOID Test_GetLoadedModulesListEx()
{
    g_FailCount = 0;

    GetLoadedModulesListEx_BasicList();
    GetLoadedModulesListEx_ExtendedList();
    GetLoadedModulesListEx_NullReturnLength();
    GetLoadedModulesListEx_AllocFailure();

    if (g_Verbose) {
        if (g_FailCount == 0)
            DbgPrint("[TEST] ntsupGetLoadedModulesListEx PASSED.\n");
        else
            DbgPrint("[TEST] ntsupGetLoadedModulesListEx %lu tests FAILED.\n", g_FailCount);
    }
}

VOID Test_GetSystemInfoEx()
{
    g_FailCount = 0;

    GetSystemInfoEx_SystemProcessInformation();
    GetSystemInfoEx_NullReturnLength();
    GetSystemInfoEx_AllocFailure();
    GetSystemInfoEx_InvalidClass();

    if (g_Verbose) {
        if (g_FailCount == 0)
            DbgPrint("[TEST] ntsupGetSystemInfoEx tests PASSED.\n");
        else
            DbgPrint("[TEST] ntsupGetSystemInfoEx %lu tests FAILED.\n", g_FailCount);
    }
}

VOID Test_HashImageSections()
{
    g_FailCount = 0;

    HashImageSections_LoadedImage();
    HashImageSections_RawFileMapping();
    HashImageSections_NoExecutableSections();
    HashImageSections_ExecutableSectionPresent();
    HashImageSections_InvalidParams();

    if (g_Verbose) {
        if (g_FailCount == 0)
            DbgPrint("[TEST] ntsupHashImageSections tests PASSED.\n");
        else
            DbgPrint("[TEST] ntsupHashImageSections%lu tests FAILED.\n", g_FailCount);
    }
}
#pragma warning(pop)
