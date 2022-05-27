#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

//
// Search callback, return TRUE to stop search.
//
typedef BOOL(CALLBACK* pfnSearchCallback)(
    _In_ PBYTE Buffer,
    _In_ ULONG PatternSize,
    _In_opt_ PVOID CallbackContext
    );

typedef struct _SEARCH_PARAMS {
    PBYTE Buffer;
    DWORD BufferSize;
    PBYTE Pattern;
    DWORD PatternSize;
    PBYTE Mask;
    pfnSearchCallback Callback;
    PVOID CallbackContext;
} SEARCH_PARAMS, * PSEARCH_PARAMS;

DWORD SearchPattern(
    _In_ PSEARCH_PARAMS SearchParams
)
{
    PBYTE   p;
    DWORD   c, i, n;
    BOOLEAN found;
    BYTE    low, high;

    DWORD   bufferSize;

    if (SearchParams == NULL)
        return 0;

    if ((SearchParams->PatternSize == 0) || (SearchParams->PatternSize > SearchParams->BufferSize))
        return 0;

    bufferSize = SearchParams->BufferSize - SearchParams->PatternSize;

    for (n = 0, p = SearchParams->Buffer, c = 0; c <= bufferSize; ++p, ++c)
    {
        found = 1;
        for (i = 0; i < SearchParams->PatternSize; ++i)
        {
            low = p[i] & 0x0f;
            high = p[i] & 0xf0;

            if (SearchParams->Mask[i] & 0xf0)
            {
                if (high != (SearchParams->Pattern[i] & 0xf0))
                {
                    found = 0;
                    break;
                }
            }

            if (SearchParams->Mask[i] & 0x0f)
            {
                if (low != (SearchParams->Pattern[i] & 0x0f))
                {
                    found = 0;
                    break;
                }
            }

        }

        if (found) {

            if (SearchParams->Callback(p,
                SearchParams->PatternSize,
                SearchParams->CallbackContext))
            {
                return n + 1;
            }

            n++;
        }
    }

    return n;
}

#define MAX_DOS_HEADER (256 * (1024 * 1024))

PIMAGE_NT_HEADERS GetImageNtHeader(
    _In_ PVOID Base)
{
    PIMAGE_NT_HEADERS NtHeaders = NULL;
    if (Base != NULL && Base != (PVOID)-1) {
        __try {
            if ((((PIMAGE_DOS_HEADER)Base)->e_magic == IMAGE_DOS_SIGNATURE) &&
                (((ULONG)((PIMAGE_DOS_HEADER)Base)->e_lfanew) < MAX_DOS_HEADER)) {
                NtHeaders = (PIMAGE_NT_HEADERS)((PCHAR)Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
                if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
                    NtHeaders = NULL;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            NtHeaders = NULL;
        }
    }
    return NtHeaders;
}

PVOID LookupImageSectionByName(
    _In_ CHAR* SectionName,
    _In_ ULONG SectionNameLength,
    _In_ PVOID DllBase,
    _Out_ PULONG SectionSize
)
{
    BOOLEAN bFound = FALSE;
    ULONG i;
    PVOID Section;
    IMAGE_NT_HEADERS* NtHeaders = GetImageNtHeader(DllBase);
    IMAGE_SECTION_HEADER* SectionTableEntry;

    if (SectionSize)
        *SectionSize = 0;

    if (NtHeaders == NULL)
        return NULL;

    SectionTableEntry = (PIMAGE_SECTION_HEADER)((PCHAR)NtHeaders +
        sizeof(ULONG) +
        sizeof(IMAGE_FILE_HEADER) +
        NtHeaders->FileHeader.SizeOfOptionalHeader);

    i = NtHeaders->FileHeader.NumberOfSections;
    while (i > 0) {

        if (memcmp(
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

    if (!bFound)
        return NULL;

    Section = (PVOID)((ULONG_PTR)DllBase + SectionTableEntry->VirtualAddress);
    if (SectionSize)
        *SectionSize = SectionTableEntry->Misc.VirtualSize;

    return Section;
}

VOID UnmapInputFile(
    _In_ PVOID FileMapping
)
{
    if (FileMapping) UnmapViewOfFile(FileMapping);
}

PVOID MapInputFile(
    _In_ LPCTSTR lpFileName,
    _Out_ LARGE_INTEGER* liFileSize
)
{
    DWORD lastError = 0;
    HANDLE fileHandle, sectionHandle = NULL;
    PVOID pvImageBase = NULL;

    do {

        liFileSize->QuadPart = 0;

        fileHandle = CreateFile(lpFileName,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_SUPPORTS_BLOCK_REFCOUNTING | FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (fileHandle == INVALID_HANDLE_VALUE)
            break;

        if (!GetFileSizeEx(fileHandle, liFileSize))
            break;

        sectionHandle = CreateFileMapping(fileHandle, NULL,
            PAGE_READONLY | SEC_IMAGE,
            0,
            0,
            NULL);

        if (sectionHandle == NULL)
            break;

        pvImageBase = MapViewOfFile(
            sectionHandle,
            FILE_MAP_READ,
            0, 0, 0);

        if (pvImageBase == NULL)
            break;

    } while (FALSE);

    lastError = GetLastError();
    if (fileHandle != INVALID_HANDLE_VALUE) CloseHandle(fileHandle);
    if (sectionHandle) CloseHandle(sectionHandle);
    SetLastError(lastError);
    return pvImageBase;
}

int _isspace(int c)
{
    return (c == '\t' || c == '\n' ||
        c == '\v' || c == '\f' || c == '\r' || c == ' ' ? 1 : 0);
}

char* trimstring(
    _In_ const char* src,
    _In_ char* dst
)
{
    while (*src) {
        if (!_isspace(*src)) {
            *dst++ = *src;
        }
        src++;
    }
    *dst = 0;
    return dst;
}

size_t hex2bin(
    _In_ const char* src,
    _In_ unsigned char* dst)
{
    unsigned char value = 0;
    unsigned char c;
    size_t i = 0;

    while (*src) {

        c = *src;
        if (c >= '0' && c <= '9')
            value = (c - '0');
        else if (c >= 'A' && c <= 'F')
            value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
            value = (10 + (c - 'a'));
        else {
            if (_isspace(c)) {
                src++;
                continue;
            }
        }

        dst[i / 2] += value << (((i + 1) % 2) * 4);
        i++;
        src++;
    }

    return i / 2;
}

__inline TCHAR nibbletoh(BYTE c, BOOLEAN upcase)
{
    if (c < 10)
        return TEXT('0') + c;

    c -= 10;

    if (upcase)
        return TEXT('A') + c;

    return TEXT('a') + c;
}

LPTSTR PrintHex(
    _In_reads_bytes_(Length) LPBYTE Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN UpcaseHex
)
{
    ULONG   c;
    PTCHAR  lpText;
    BYTE    x;

    lpText = (LPTSTR)LocalAlloc(LPTR, sizeof(TCHAR) + ((SIZE_T)Length * 2 * sizeof(TCHAR)));
    if (lpText) {

        for (c = 0; c < Length; ++c) {
            x = Buffer[c];

            lpText[c * 2] = nibbletoh(x >> 4, UpcaseHex);
            lpText[c * 2 + 1] = nibbletoh(x & 15, UpcaseHex);
        }

        lpText[Length * 2] = 0;
    }

    return lpText;
}

BOOL CALLBACK SearchPatternCallback(
    _In_ PBYTE Buffer,
    _In_ ULONG PatternSize,
    _In_opt_ PVOID CallbackContext
)
{
    LPCSTR pszSection = (LPCSTR)CallbackContext;
    LPCSTR pszFound;
    pszFound = PrintHex(Buffer, PatternSize, TRUE);
    if (pszFound) {
        printf_s("%s: %p\t%s\r\n", pszSection, Buffer, pszFound);
        LocalFree((HLOCAL)pszFound);
    }
    return FALSE;
}

void ProcessFile(
    _In_ LPCSTR pszFileName,
    _In_ LPCSTR pszSection,
    _In_ LPCSTR pszPattern,
    _In_ LPCSTR pszMask)
{
    PVOID pvImageBase = NULL, pvSection;
    LARGE_INTEGER fileSize;
    SIZE_T nLen, patternLen, maskLen;
    ULONG sectionSize = 0;

    BYTE* pbPattern = NULL;
    BYTE* pbMask = NULL;

    DWORD patternSize, maskSize;

    SEARCH_PARAMS sparams;

    do {

        nLen = strlen(pszSection);
        if (nLen < 2) {
            printf_s("Section name %s is too short\r\n", pszSection);
            return;
        }

        patternLen = strlen(pszPattern);
        maskLen = strlen(pszMask);

        pbPattern = (BYTE*)LocalAlloc(LPTR, patternLen);
        pbMask = (BYTE*)LocalAlloc(LPTR, maskLen);
        if (pbPattern == NULL || pbMask == NULL) {
            printf_s("Could not allocate temporary buffer\r\n");
            break;
        }

        patternSize = (ULONG)hex2bin(pszPattern, pbPattern);
        maskSize = (ULONG)hex2bin(pszMask, pbMask);
        if (patternSize != maskSize) {
            printf_s("Pattern and mask must be the same size\r\n");
            break;
        }

        pvImageBase = MapInputFile(pszFileName, &fileSize);

        if (pvImageBase == NULL) {
            printf_s("Cannot map input file %s, GetLastError(%lx)", pszFileName, GetLastError());
            break;
        }

        pvSection = LookupImageSectionByName((CHAR*)pszSection, (ULONG)nLen, pvImageBase, &sectionSize);

        if (pvSection == NULL || sectionSize == 0) {
            printf_s("Section %s not found or has invalid size %lx", pszSection, sectionSize);
            break;
        }

        sparams.Buffer = (PBYTE)pvSection;
        sparams.BufferSize = sectionSize;
        sparams.Callback = SearchPatternCallback;
        sparams.CallbackContext = (PVOID)pszSection;
        sparams.Pattern = pbPattern;
        sparams.PatternSize = patternSize;
        sparams.Mask = pbMask;

        if (0 == SearchPattern(&sparams))
            printf_s("Nothing found, check input parameters!\r\n");

    } while (FALSE);

    if (pvImageBase) UnmapInputFile(pvImageBase);
    if (pbPattern) LocalFree(pbPattern);
    if (pbMask) LocalFree(pbMask);
}

int main(int argc, char* argv[])
{
    if (argc > 4) {
        printf_s("File %s, looking for:\r\n\tPattern:\t%s\r\n\tMask:\t\t%s\r\n\tSection:\t%s\r\n",
            argv[1],
            argv[3],
            argv[4],
            argv[2]);

        ProcessFile(argv[1], argv[2], argv[3], argv[4]);
    }
    else {
        printf_s("sp [File] [Section] [Pattern] [Mask]\r\n");
    }
    ExitProcess(0);
}
