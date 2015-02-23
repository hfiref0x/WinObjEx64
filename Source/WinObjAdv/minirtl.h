/*
Module name:
	minirtl.h

Description:
	header for conversion routines

Date:
	18 Feb 2015
*/

#ifndef _MINIRTL_
#define _MINIRTL_

#include <windows.h>

// dummy memset
void _mini_memzero(void *p, size_t size);

// string handling

size_t _strlenA(const char *s);
size_t _strlenW(const wchar_t *s);

char *_strendA(const char *s);
wchar_t *_strendW(const wchar_t *s);

char *_strcpyA(char *dest, const char *src);
wchar_t *_strcpyW(wchar_t *dest, const wchar_t *src);

char *_strncpyA(char *dest, size_t ccdest, const char *src, size_t ccsrc);
wchar_t *_strncpyW(wchar_t *dest, size_t ccdest, const wchar_t *src, size_t ccsrc);

char *_strcatA(char *dest, const char *src);
wchar_t *_strcatW(_Inout_z_ wchar_t *dest, const wchar_t *src);

//

char *_filenameA(const char *f);
wchar_t *_filenameW(const wchar_t *f);

char *_fileextA(const char *f);
wchar_t *_fileextW(const wchar_t *f);

char *_filename_noextA(char *dest, const char *f);
wchar_t *_filename_noextW(wchar_t *dest, const wchar_t *f);

// conversion unsigned long to string, returning string length
unsigned long ultostrA(unsigned long x, char *s);
unsigned long ultostrW(unsigned long x, wchar_t *s);

unsigned long itostrA(int x, char *s);
unsigned long i64tostrA(signed long long int x, char *s);
unsigned long i64tostrW(signed long long int x, wchar_t *s);

// conversion unsigned long to hex string
void ultohexA(unsigned long x, char *s);
void ultohexW(unsigned long x, wchar_t *s);

// conversion unsigned __int64 to string, returning string length
unsigned long u64tostrA(unsigned __int64 x, char *s);
unsigned long u64tostrW(unsigned __int64 x, wchar_t *s);

// conversion unsigned __int64 to hex string
void u64tohexA(unsigned __int64 x, char *s);
void u64tohexW(unsigned __int64 x, wchar_t *s);

// conversion string to unsigned long
unsigned long strtoulA(char *s);
unsigned long strtoulW(wchar_t *s);

// conversion string to unsigned __int64
unsigned __int64 strtou64A(char *s);
unsigned __int64 strtou64W(wchar_t *s);

// conversion hex string to unsigned __int64
unsigned __int64 hextou64A(char *s);
unsigned __int64 hextou64W(wchar_t *s);

int _strcmpiA(const char *s1, const char *s2);
int _strcmpiW(const wchar_t *s1, const wchar_t *s2);

int _strcmpA(const char *s1, const char *s2);
int _strcmpW(const wchar_t *s1, const wchar_t *s2);

int _strncmpA(const char *s1, const char *s2, size_t cchars);
int _strncmpW(const wchar_t *s1, const wchar_t *s2, size_t cchars);

int _strncmpiA(const char *s1, const char *s2, size_t cchars);
int _strncmpiW(const wchar_t *s1, const wchar_t *s2, size_t cchars);

wchar_t *_strstriW(const wchar_t *s, const wchar_t *sub_s);

char *ExtractFilePathA(const char *FileName, char *FilePath);
wchar_t *ExtractFilePathW(const wchar_t *FileName, wchar_t *FilePath);

BOOL GetCommandLineParamW (IN LPCWSTR CmdLine, IN ULONG ParamIndex, OUT LPWSTR Buffer, IN ULONG BufferSize, OUT PULONG ParamLen);
BOOL GetCommandLineParamA (IN LPCSTR CmdLine, IN ULONG ParamIndex, OUT LPSTR Buffer, IN	ULONG BufferSize, OUT PULONG ParamLen);
DWORD GetCurrentTimeAs1970Time();

#ifdef UNICODE
#define ultostr ultostrW
#define ultohex ultohexW
#define u64tostr u64tostrW
#define u64tohex u64tohexW
#define strtoul strtoulW
#define strtou64 strtou64W
#define hextou64 hextou64W

#define _strlen _strlenW
#define _strend _strendW
#define _strcpy _strcpyW
#define _strncpy _strncpyW
#define _strcat _strcatW
#define _strcmp _strcmpW
#define _strcmpi _strcmpiW
#define _strncmp _strncmpW
#define _strncmpi _strncmpiW

#define _filename _filenameW
#define _fileext _fileextW
#define _filename_noext _filename_noextW
#define GetCommandLineParam GetCommandLineParamW
#define ExtractFilePath ExtractFilePathW

#else
#define ultostr ultostrA
#define ultohex ultohexA
#define u64tostr u64tostrA
#define u64tohex u64tohexA
#define strtoul strtoulA
#define strtou64 strtou64A
#define hextou64 hextou64A

#define _strlen _strlenA
#define _strend _strendA
#define _strcpy _strcpyA
#define _strncpy _strncpyA
#define _strcat _strcatA
#define _strcmp _strcmpA
#define _strcmpi _strcmpiA
#define _strncmp _strncmpA
#define _strncmpi _strncmpiA

#define _filename _filenameA
#define _fileext _fileextA
#define _filename_noext _filename_noextA
#define GetCommandLineParam GetCommandLineParamA
#define ExtractFilePath ExtractFilePathA

#endif

#endif /* _MINIRTL_ */
