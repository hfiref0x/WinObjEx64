/*******************************************************************************
*
*  (C) COPYRIGHT H.E., 2015 - 2022
*
*  TITLE:       SYMPARSER.H
*
*  VERSION:     1.18
*
*  DATE:        05 Jun 2022
*
*  Header file of DbgHelp wrapper for symbols parser support.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

// Unicode version of functions
#define DBGHELP_TRANSLATE_TCHAR

// Non-default declarations enabled
#define _NO_CVCONST_H

#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

typedef enum _SymUdtKind {
    UdtStruct,
    UdtClass,
    UdtUnion,
    UdtInterface,
    UdtInvalid = 0xffff
} SymUdtKind;

typedef enum _SymBasicType {
    btNoType = 0,
    btVoid = 1,
    btChar = 2,
    btWChar = 3,
    btInt = 6,
    btUInt = 7,
    btFloat = 8,
    btBCD = 9,
    btBool = 10,
    btLong = 13,
    btULong = 14,
    btCurrency = 25,
    btDate = 26,
    btVariant = 27,
    btComplex = 28,
    btBit = 29,
    btBSTR = 30,
    btHresult = 31,
    btChar16 = 32,
    btChar32 = 33,
    btChar8 = 34,
    btMaxType = 0xffff
} SymBasicType;

typedef struct _SYM_CHILD {
    ULONG Offset;

    BOOL IsBitField;
    ULONG BitPosition;

    BOOL IsValuePresent; //Note, max 8 bytes long value supported
    DWORD64 Value;

    ULONG64 Size;
    ULONG64 ElementsCount;

    WCHAR TypeName[MAX_SYM_NAME];
    WCHAR Name[MAX_SYM_NAME];
} SYM_CHILD, * PSYM_CHILD;

typedef struct _SYM_ENTRY {
    ULONG Offset;
    ULONG ChildCount;

    ULONG64 Size;

    WCHAR Name[MAX_SYM_NAME];
    SYM_CHILD ChildEntries[ANYSIZE_ARRAY];
} SYM_ENTRY, * PSYM_ENTRY;

//
// Prototypes
//

//
// DbgHelp
//
typedef  DWORD(WINAPI* pfnSymSetOptions)(
    _In_ DWORD   SymOptions
    );

typedef BOOL(WINAPI* pfnSymInitializeW)(
    _In_ HANDLE hProcess,
    _In_opt_ PCWSTR UserSearchPath,
    _In_ BOOL fInvadeProcess);

typedef BOOL(WINAPI* pfnSymRegisterCallback64)(
    _In_ HANDLE hProcess,
    _In_ PSYMBOL_REGISTERED_CALLBACK64 CallbackFunction,
    _In_ ULONG64 UserContext);

typedef DWORD64(WINAPI* pfnSymLoadModuleExW)(
    _In_ HANDLE hProcess,
    _In_opt_ HANDLE hFile,
    _In_opt_ PCWSTR ImageName,
    _In_opt_ PCWSTR ModuleName,
    _In_ DWORD64 BaseOfDll,
    _In_ DWORD DllSize,
    _In_opt_ PMODLOAD_DATA Data,
    _In_ DWORD Flags);

typedef BOOL(WINAPI* pfnSymGetTypeInfo)(
    _In_ HANDLE hProcess,
    _In_ DWORD64 ModBase,
    _In_ ULONG TypeId,
    _In_ IMAGEHLP_SYMBOL_TYPE_INFO GetType,
    _Out_ PVOID pInfo);

typedef BOOL(WINAPI* pfnSymFromNameW)(
    _In_ HANDLE hProcess,
    _In_ PCWSTR Name,
    _Inout_ PSYMBOL_INFOW Symbol);

typedef BOOL(WINAPI* pfnSymFromAddrW)(
    _In_ HANDLE hProcess,
    _In_ DWORD64 Address,
    _In_ PDWORD64 Displacement,
    _Inout_ PSYMBOL_INFO Symbol);

typedef BOOL(WINAPI* pfnSymGetTypeFromNameW)(
    _In_ HANDLE hProcess,
    _In_ ULONG64 BaseOfDll,
    _In_ PCWSTR Name,
    _Inout_ PSYMBOL_INFOW Symbol);

typedef BOOL(WINAPI* pfnSymUnloadModule64)(
    _In_ HANDLE hProcess,
    _In_ DWORD64 BaseOfDll);

typedef BOOL(WINAPI* pfnSymCleanup)(
    _In_ HANDLE hProcess);

typedef struct _DBGHELP_PTRS {
    pfnSymSetOptions SymSetOptions;
    pfnSymInitializeW SymInitialize;
    pfnSymRegisterCallback64 SymRegisterCallback64;
    pfnSymLoadModuleExW SymLoadModuleEx;
    pfnSymGetTypeInfo SymGetTypeInfo;
    pfnSymFromNameW SymFromName;
    pfnSymFromAddrW SymFromAddr;
    pfnSymGetTypeFromNameW SymGetTypeFromName;
    pfnSymUnloadModule64 SymUnloadModule;
    pfnSymCleanup SymCleanup;
} DBGHELP_PTRS, * PDBGHELP_PTR;

//
// Symbol Parser
//
typedef struct _SYMCONTEXT* PSYMCONTEXT;

typedef BOOL(WINAPI* SPRegisterCallback)(
    _In_ PSYMCONTEXT Context,
    _In_ PSYMBOL_REGISTERED_CALLBACK64 CallbackFunction,
    _In_ ULONG64 UserContext);

typedef BOOL(WINAPI* SPLoadModule)(
    _In_ PSYMCONTEXT Context,
    _In_ LPCWSTR lpModulePath,
    _In_ DWORD64 BaseOfDll,
    _In_ DWORD SizeOfDll);

typedef BOOL(WINAPI* SPUnloadModule)(
    _In_ PSYMCONTEXT Context);

typedef SymBasicType(WINAPI* SPGetType)(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status);

typedef SymBasicType(WINAPI* SPGetBaseType)(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status);

typedef ULONG(WINAPI* SPGetTypeId)(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status);

typedef ULONG(WINAPI* SPGetArrayTypeId)(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status);

typedef ULONG64(WINAPI* SPGetSize)(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status);

typedef ULONG(WINAPI* SPGetOffset)(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status);

typedef ULONG(WINAPI* SPGetAddressOffset)(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status);

typedef ULONG(WINAPI* SPGetBitPosition)(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status);

typedef ULONG(WINAPI* SPGetChildrenCount)(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status);

typedef ULONG(WINAPI* SPGetTag)(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status);

typedef LPCWSTR(WINAPI* SPGetName)(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status);

typedef VARTYPE(WINAPI* SPGetValue)(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Inout_ VARIANT* Value,
    _Out_opt_ PBOOL Status);

typedef SymUdtKind(WINAPI* SPGetUDTKind)(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status);

typedef ULONG(WINAPI* SPGetCount)(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status);

typedef ULONG(WINAPI* SPGetCallingConvention)(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status);

typedef LPCWSTR(WINAPI* SPGetTypeName)(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PUINT64 BaseTypeSize,
    _Out_opt_ PBOOL Status);

typedef ULONG64(WINAPI* SPLookupAddressBySymbol)(
    _In_ PSYMCONTEXT Context,
    _In_ LPCWSTR SymbolName,
    _Out_opt_ PBOOL Status);

typedef ULONG(WINAPI* SPLookupSymbolByAddress)(
    _In_ PSYMCONTEXT Context,
    _In_ DWORD64 SymbolAddress,
    _In_ PDWORD64 Displacement,
    _Inout_ LPWSTR* SymbolName,
    _Out_opt_ PBOOL Status);

typedef ULONG(WINAPI* SPGetFieldOffset)(
    _In_ PSYMCONTEXT Context,
    _In_ LPCWSTR SymbolName,
    _In_ LPCWSTR FieldName,
    _Out_opt_ PBOOL Status);

typedef PSYM_ENTRY(WINAPI* SPDumpSymbolInformation)(
    _In_ PSYMCONTEXT Context,
    _In_ LPCWSTR SymbolName,
    _Out_opt_ PBOOL Status);

typedef struct _SYMPARSER {
    SPLoadModule LoadModule;
    SPUnloadModule UnloadModule;
    SPGetTag GetTag;
    SPGetSize GetSize;
    SPGetType GetType;
    SPGetName GetName;
    SPGetValue GetValue;
    SPGetCount GetCount;
    SPGetOffset GetOffset;
    SPGetTypeId GetTypeId;
    SPGetUDTKind GetUDTKind;
    SPGetBaseType GetBaseType;
    SPGetTypeName GetTypeName;
    SPGetBitPosition GetBitPosition;
    SPGetFieldOffset GetFieldOffset;
    SPGetArrayTypeId GetArrayTypeId;
    SPGetAddressOffset GetAddressOffset;
    SPGetChildrenCount GetChildrenCount;
    SPGetCallingConvention GetCallingConvention;
    SPDumpSymbolInformation DumpSymbolInformation;
    SPLookupAddressBySymbol LookupAddressBySymbol;
    SPLookupSymbolByAddress LookupSymbolByAddress;
} SYMPARSER, * PSYMPARSER;

typedef struct _SYMCONTEXT {
    DWORD64 ModuleBase;
    HANDLE ProcessHandle;
    DWORD SymLastError;
    DBGHELP_PTRS DbgHelp;
    SYMPARSER Parser;
} SYMCONTEXT, * PSYMCONTEXT;

BOOL SymGlobalsInit(
    _In_ DWORD SymOptions,
    _In_opt_ HANDLE ProcessHandle,
    _In_opt_ LPCWSTR lpDbgHelpPath,
    _In_opt_ LPCWSTR lpSymbolPath,
    _In_ LPCWSTR lpSystemPath,
    _In_ LPCWSTR lpTempPath,
    _In_opt_ PSYMBOL_REGISTERED_CALLBACK64 CallbackFunction,
    _In_ ULONG64 UserContext);

BOOL SymGlobalsFree();

PSYMCONTEXT SymParserCreate(VOID);

VOID SymParserDestroy(
    _In_ PSYMCONTEXT Context);
