/*******************************************************************************
*
*  (C) COPYRIGHT H.E., 2015 - 2022
*
*  TITLE:       SYMPARSER.C
*
*  VERSION:     1.18
*
*  DATE:        20 Jun 2021
*
*  DbgHelp wrapper for symbols parser support.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

/*++

 SymGlobalsInit
 +------------------------------------+
 C1 = SymParserCreate()
 C1->LoadModule(A)
 C2 = SymParserCreate()
 C2->LoadModule(B)
 ...
 C2->UnloadModule(B)
 C1->UnloadModule(A)
 ...
 SymParserDestroy(C2);
 SymParserDestroy(C1);
 ...
 +------------------------------------+
 SymGlobalsFree

--*/

#define DEFAULT_SYMPATH     L"Symbols*https://msdl.microsoft.com/download/symbols"
#define DEFAULT_DLL         L"DbgHelp.dll"

typedef struct _SYMGLOBALS {
    BOOL Initialized;
    ULONG Options;
    HANDLE ProcessHandle;
    HMODULE DllHandle;
    DBGHELP_PTRS ApiSet;
    WCHAR szSymbolsPath[MAX_PATH * 2];
} SYMGLOBALS, * PSYMGLOBALS;

static SYMGLOBALS g_SymGlobals;

typedef struct _BasicTypeMapElement {
    SymBasicType BasicType;
    ULONG Length;
    PCWSTR TypeName;
} BasicTypeMapElement, * PBasicTypeMapElement;

// from wbenny's pdbex
BasicTypeMapElement BasicTypeMapMSVC[] = {
    { btNoType,     0,      NULL                        },
    { btVoid,       0,      TEXT("void")                },
    { btChar,       1,      TEXT("char")                },
    { btChar8,      1,      TEXT("char8_t")             },
    { btChar16,     2,      TEXT("char16_t")            },
    { btChar32,     4,      TEXT("char32_t")            },
    { btWChar,      2,      TEXT("wchar_t")             },
    { btInt,        1,      TEXT("char")                },
    { btInt,        2,      TEXT("short")               },
    { btInt,        4,      TEXT("int")                 },
    { btInt,        8,      TEXT("__int64")             },
    { btInt,        16,     TEXT("__m128")              }, //SIMD
    { btUInt,       1,      TEXT("unsigned char")       },
    { btUInt,       2,      TEXT("unsigned short")      },
    { btUInt,       4,      TEXT("unsigned int")        },
    { btUInt,       8,      TEXT("unsigned __int64")    },
    { btUInt,       16,     TEXT("__m128")              }, //SIMD
    { btFloat,      4,      TEXT("float")               },
    { btFloat,      8,      TEXT("double")              },
    { btFloat,      10,     TEXT("long double")         },
    { btBCD,        0,      TEXT("BCD")                 },
    { btBool,       0,      TEXT("BOOL")                },
    { btLong,       4,      TEXT("long")                },
    { btULong,      4,      TEXT("unsigned long")       },
    { btCurrency,   0,      NULL                        },
    { btDate,       0,      TEXT("DATE")                },
    { btVariant,    0,      TEXT("VARIANT")             },
    { btComplex,    0,      NULL                        },
    { btBit,        0,      NULL                        },
    { btBSTR,       0,      TEXT("BSTR")                },
    { btHresult,    4,      TEXT("HRESULT")             },
    { btMaxType,    0,      NULL                        }
};

PCWSTR SympGetBasicTypeNameString(
    _In_ BasicTypeMapElement* TypeMap,
    _In_ SymBasicType BasicType,
    _In_ ULONG Length
)
{
    ULONG i;

    for (i = 0; TypeMap[i].BasicType != btMaxType; i++) {

        if (TypeMap[i].BasicType == BasicType) {

            if (TypeMap[i].Length == Length ||
                TypeMap[i].Length == 0)
            {
                return TypeMap[i].TypeName;
            }

        }

    }

    return NULL;
}

PCWSTR SympGetTypeNameString(
    _In_ SymBasicType BasicType,
    _In_ ULONG Length
)
{
    return SympGetBasicTypeNameString(
        BasicTypeMapMSVC,
        BasicType,
        Length);
}

/// <summary>
/// SymRegisterCallbackW64 wrapper
/// </summary>
/// <param name="Context"></param>
/// <param name="CallbackFunction"></param>
/// <param name="UserContext"></param>
/// <returns></returns>
BOOL SymParserRegisterCallback(
    _In_ PSYMCONTEXT Context,
    _In_ PSYMBOL_REGISTERED_CALLBACK64 CallbackFunction,
    _In_ ULONG64 UserContext
)
{
    return Context->DbgHelp.SymRegisterCallbackW64(
        Context->ProcessHandle,
        CallbackFunction,
        UserContext);
}

/// <summary>
/// SymLoadModuleExW wrapper
/// </summary>
/// <param name="Context"></param>
/// <param name="lpModulePath"></param>
/// <param name="BaseOfDll"></param>
/// <param name="SizeOfDll"></param>
/// <returns>Result of SymLoadModuleExW call</returns>
BOOL SymParserLoadModule(
    _In_ PSYMCONTEXT Context,
    _In_ LPCWSTR lpModulePath,
    _In_ DWORD64 BaseOfDll,
    _In_ DWORD SizeOfDll
)
{
    DWORD64 moduleBase;

    moduleBase = Context->DbgHelp.SymLoadModuleEx(
        Context->ProcessHandle,
        NULL,
        lpModulePath,
        NULL,
        BaseOfDll,
        SizeOfDll,
        NULL,
        0);

    Context->SymLastError = GetLastError();
    Context->ModuleBase = moduleBase;

    return (moduleBase != 0);
}

/// <summary>
/// SymUnloadModule64 wrapper
/// </summary>
/// <param name="Context"></param>
/// <returns>Result of SymUnloadModule64 call</returns>
BOOL SymParserUnloadModule(
    _In_ PSYMCONTEXT Context
)
{
    BOOL bStatus = Context->DbgHelp.SymUnloadModule(
        Context->ProcessHandle,
        Context->ModuleBase);

    Context->SymLastError = GetLastError();

    if (bStatus)
        Context->ModuleBase = 0;

    return bStatus;
}

/// <summary>
/// SymGetTypeInfo(TI_GET_TYPE) wrapper
/// </summary>
/// <param name="Context">Symbol parser context</param>
/// <param name="TypeIndex">Symbox type index</param>
/// <param name="Status">Optional, receive operation status</param>
/// <returns></returns>
SymBasicType SymParserGetType(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    ULONG symType = 0;

    BOOL bStatus = Context->DbgHelp.SymGetTypeInfo(
        Context->ProcessHandle,
        Context->ModuleBase,
        TypeIndex,
        TI_GET_TYPE,
        (PVOID)&symType);

    Context->SymLastError = GetLastError();

    if (Status)
        *Status = bStatus;

    return (SymBasicType)symType;
}

/// <summary>
/// SymGetTypeInfo(TI_GET_BASETYPE) wrapper
/// </summary>
/// <param name="Context">Symbol parser context</param>
/// <param name="TypeIndex">Symbox type index</param>
/// <param name="Status">Optional, receive operation status</param>
/// <returns></returns>
SymBasicType SymParserGetBaseType(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    ULONG symBaseType = 0;

    BOOL bStatus = Context->DbgHelp.SymGetTypeInfo(
        Context->ProcessHandle,
        Context->ModuleBase,
        TypeIndex,
        TI_GET_BASETYPE,
        (PVOID)&symBaseType);

    Context->SymLastError = GetLastError();

    if (Status)
        *Status = bStatus;

    return (SymBasicType)symBaseType;
}

/// <summary>
/// SymGetTypeInfo(TI_GET_TYPEID) wrapper
/// </summary>
/// <param name="Context">Symbol parser context</param>
/// <param name="TypeIndex">Symbox type index</param>
/// <param name="Status">Optional, receive operation status</param>
/// <returns></returns>
ULONG SymParserGetTypeId(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    ULONG typeId = 0;

    BOOL bStatus = Context->DbgHelp.SymGetTypeInfo(
        Context->ProcessHandle,
        Context->ModuleBase,
        TypeIndex,
        TI_GET_TYPEID,
        (PVOID)&typeId);

    Context->SymLastError = GetLastError();

    if (Status)
        *Status = bStatus;

    return typeId;
}

/// <summary>
/// SymGetTypeInfo(TI_GET_ARRAYINDEXTYPEID) wrapper
/// </summary>
/// <param name="Context">Symbol parser context</param>
/// <param name="TypeIndex">Symbox type index</param>
/// <param name="Status">Optional, receive operation status</param>
/// <returns></returns>
ULONG SymParserGetArrayTypeId(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    ULONG typeId = 0;

    BOOL bStatus = Context->DbgHelp.SymGetTypeInfo(
        Context->ProcessHandle,
        Context->ModuleBase,
        TypeIndex,
        TI_GET_ARRAYINDEXTYPEID,
        (PVOID)&typeId);

    Context->SymLastError = GetLastError();

    if (Status)
        *Status = bStatus;

    return typeId;
}

/// <summary>
/// SymGetTypeInfo(TI_GET_LENGTH) wrapper
/// </summary>
/// <param name="Context">Symbol parser context</param>
/// <param name="TypeIndex">Symbox type index</param>
/// <param name="Status">Optional, receive operation status</param>
/// <returns></returns>
ULONG64 SymParserGetSize(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    ULONG64 symSize = 0;

    BOOL bStatus = Context->DbgHelp.SymGetTypeInfo(
        Context->ProcessHandle,
        Context->ModuleBase,
        TypeIndex,
        TI_GET_LENGTH,
        (PVOID)&symSize);

    Context->SymLastError = GetLastError();

    if (Status)
        *Status = bStatus;

    return symSize;
}

/// <summary>
/// SymGetTypeInfo(TI_GET_OFFSET) wrapper
/// </summary>
/// <param name="Context">Symbol parser context</param>
/// <param name="TypeIndex">Symbox type index</param>
/// <param name="Status">Optional, receive operation status</param>
/// <returns></returns>
ULONG SymParserGetOffset(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    ULONG symOffset = 0;

    BOOL bStatus = Context->DbgHelp.SymGetTypeInfo(
        Context->ProcessHandle,
        Context->ModuleBase,
        TypeIndex,
        TI_GET_OFFSET,
        (PVOID)&symOffset);

    Context->SymLastError = GetLastError();

    if (Status)
        *Status = bStatus;

    return symOffset;
}

/// <summary>
/// SymGetTypeInfo(TI_GET_ADDRESSOFFSET) wrapper
/// </summary>
/// <param name="Context">Symbol parser context</param>
/// <param name="TypeIndex">Symbox type index</param>
/// <param name="Status">Optional, receive operation status</param>
/// <returns></returns>
ULONG SymParserGetAddressOffset(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    ULONG symOffset = 0;

    BOOL bStatus = Context->DbgHelp.SymGetTypeInfo(
        Context->ProcessHandle,
        Context->ModuleBase,
        TypeIndex,
        TI_GET_ADDRESSOFFSET,
        (PVOID)&symOffset);

    Context->SymLastError = GetLastError();

    if (Status)
        *Status = bStatus;

    return symOffset;
}

/// <summary>
/// SymGetTypeInfo(TI_GET_BITPOSITION) wrapper
/// </summary>
/// <param name="Context">Symbol parser context</param>
/// <param name="TypeIndex">Symbox type index</param>
/// <param name="Status">Optional, receive operation status</param>
/// <returns></returns>
ULONG SymParserGetBitPosition(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    ULONG bitPosition = 0;

    BOOL bStatus = Context->DbgHelp.SymGetTypeInfo(
        Context->ProcessHandle,
        Context->ModuleBase,
        TypeIndex,
        TI_GET_BITPOSITION,
        (PVOID)&bitPosition);

    Context->SymLastError = GetLastError();

    if (Status)
        *Status = bStatus;

    return bitPosition;
}

/// <summary>
/// SymGetTypeInfo(TI_GET_CHILDRENCOUNT) wrapper
/// </summary>
/// <param name="Context">Symbol parser context</param>
/// <param name="TypeIndex">Symbox type index</param>
/// <param name="Status">Optional, receive operation status</param>
/// <returns></returns>
ULONG SymParserGetChildrenCount(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    ULONG childCount = 0;

    BOOL bStatus = Context->DbgHelp.SymGetTypeInfo(
        Context->ProcessHandle,
        Context->ModuleBase,
        TypeIndex,
        TI_GET_CHILDRENCOUNT,
        (PVOID)&childCount);

    Context->SymLastError = GetLastError();

    if (Status)
        *Status = bStatus;

    return childCount;
}

/// <summary>
/// SymGetTypeInfo(TI_GET_SYMTAG) wrapper
/// </summary>
/// <param name="Context">Symbol parser context</param>
/// <param name="TypeIndex">Symbox type index</param>
/// <param name="Status">Optional, receive operation status</param>
/// <returns></returns>
ULONG SymParserGetTag(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    ULONG symTag = 0;

    BOOL bStatus = Context->DbgHelp.SymGetTypeInfo(
        Context->ProcessHandle,
        Context->ModuleBase,
        TypeIndex,
        TI_GET_SYMTAG,
        (PVOID)&symTag);

    Context->SymLastError = GetLastError();

    if (Status)
        *Status = bStatus;

    return symTag;
}

/// <summary>
/// SymGetTypeInfo(TI_GET_SYMNAME) wrapper
/// </summary>
/// <param name="Context">Symbol parser context</param>
/// <param name="TypeIndex">Symbox type index</param>
/// <param name="Status">Optional, receive operation status</param>
/// <returns>Symbol name string, use LocalFree to release string allocated memory</returns>
LPCWSTR SymParserGetName(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    LPCWSTR lpSymbolName = NULL;

    BOOL bStatus = Context->DbgHelp.SymGetTypeInfo(
        Context->ProcessHandle,
        Context->ModuleBase,
        TypeIndex,
        TI_GET_SYMNAME,
        (PVOID)&lpSymbolName);

    Context->SymLastError = GetLastError();

    if (Status)
        *Status = bStatus;

    return lpSymbolName;
}

/// <summary>
/// SymGetTypeInfo(TI_GET_VALUE) wrapper
/// </summary>
/// <param name="Context"></param>
/// <param name="TypeIndex"></param>
/// <param name="Value"></param>
/// <param name="Status"></param>
/// <returns></returns>
VARTYPE SymParserGetValue(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Inout_ VARIANT* Value,
    _Out_opt_ PBOOL Status
)
{
    VARTYPE varResult;

    VariantInit(Value);

    BOOL bStatus = Context->DbgHelp.SymGetTypeInfo(
        Context->ProcessHandle,
        Context->ModuleBase,
        TypeIndex,
        TI_GET_VALUE,
        (PVOID)Value);

    varResult = Value->vt;
    Context->SymLastError = GetLastError();

    if (Status)
        *Status = bStatus;

    return varResult;
}

/// <summary>
/// SymGetTypeInfo(TI_GET_UDTKIND) wrapper
/// </summary>
/// <param name="Context"></param>
/// <param name="TypeIndex"></param>
/// <param name="Status"></param>
/// <returns></returns>
SymUdtKind SymParserGetUDTKind(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    SymUdtKind udtKind = UdtInvalid;

    BOOL bStatus = Context->DbgHelp.SymGetTypeInfo(
        Context->ProcessHandle,
        Context->ModuleBase,
        TypeIndex,
        TI_GET_UDTKIND,
        (PVOID)&udtKind);

    Context->SymLastError = GetLastError();

    if (Status)
        *Status = bStatus;

    return udtKind;
}

/// <summary>
/// SymGetTypeInfo(TI_GET_COUNT) wrapper
/// </summary>
/// <param name="Context"></param>
/// <param name="TypeIndex"></param>
/// <param name="Status"></param>
/// <returns>Number of arguments (DIA Count)</returns>
ULONG SymParserGetCount(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    ULONG ulCount = 0;

    BOOL bStatus = Context->DbgHelp.SymGetTypeInfo(
        Context->ProcessHandle,
        Context->ModuleBase,
        TypeIndex,
        TI_GET_COUNT,
        (PVOID)&ulCount);

    Context->SymLastError = GetLastError();

    if (Status)
        *Status = bStatus;

    return ulCount;
}

/// <summary>
/// SymGetTypeInfo(TI_GET_CALLING_CONVENTION) wrapper
/// </summary>
/// <param name="Context"></param>
/// <param name="TypeIndex"></param>
/// <param name="Status"></param>
/// <returns>Calling convention id</returns>
ULONG SymParserGetCallingConvention(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    ULONG ulCallingConvention = 0;

    BOOL bStatus = Context->DbgHelp.SymGetTypeInfo(
        Context->ProcessHandle,
        Context->ModuleBase,
        TypeIndex,
        TI_GET_CALLING_CONVENTION,
        (PVOID)&ulCallingConvention);

    Context->SymLastError = GetLastError();

    if (Status)
        *Status = bStatus;

    return ulCallingConvention;
}

/// <summary>
/// Retrieve symbol type name
/// </summary>
/// <param name="Context"></param>
/// <param name="TypeIndex"></param>
/// <param name="BaseTypeSize"></param>
/// <param name="Status"></param>
/// <returns></returns>
LPCWSTR SymParserGetTypeName(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PUINT64 BaseTypeSize,
    _Out_opt_ PBOOL Status
)
{
    BOOL bResult = FALSE;
    SymUdtKind udtKind;
    ULONG64 nextTypeSize = 0, symSize;
    LPWSTR lpStringCopy;
    LPCWSTR lpSymbolTypeName = NULL, lpTemp = NULL;
    SIZE_T nLen;
    ULONG tagEnum, symType;

    symSize = Context->Parser.GetSize(
        Context,
        TypeIndex,
        Status);

    if (BaseTypeSize)
        *BaseTypeSize = symSize;

    lpSymbolTypeName = Context->Parser.GetName(
        Context,
        TypeIndex,
        Status);

    if (lpSymbolTypeName)
        return lpSymbolTypeName;

    tagEnum = Context->Parser.GetTag(
        Context,
        TypeIndex,
        Status);

    switch (tagEnum) {

        //
        // User defined type.
        //
    case SymTagUDT:

        udtKind = Context->Parser.GetUDTKind(
            Context,
            TypeIndex,
            &bResult);

        if (bResult) {

            switch (udtKind) {
            case UdtClass:
            case UdtInterface:
            case UdtUnion:

                lpSymbolTypeName = Context->Parser.GetName(
                    Context,
                    TypeIndex,
                    &bResult);

                break;

            default:

                lpStringCopy = (LPWSTR)LocalAlloc(LPTR, MAX_SYM_NAME);
                if (lpStringCopy) {
                    _strcpy(lpStringCopy, TEXT("UnknownType"));
                    lpSymbolTypeName = lpStringCopy;
                }

                break;
            }

        }

        if (Status)
            *Status = bResult;


        break;

        //
        // Type is a pointer, add * to end of the name.
        //
    case SymTagPointerType:

        symType = Context->Parser.GetTypeId(
            Context,
            TypeIndex,
            &bResult);

        if (bResult) {

            lpTemp = Context->Parser.GetTypeName(
                Context,
                symType,
                &nextTypeSize,
                &bResult);

            if (bResult && lpTemp) {

                nLen = _strlen(lpTemp);
                lpStringCopy = (LPWSTR)LocalAlloc(LPTR, (nLen + 2) * sizeof(WCHAR));
                if (lpStringCopy) {
                    _strcpy(lpStringCopy, lpTemp);
                    _strcat(lpStringCopy, L"*");
                    lpSymbolTypeName = lpStringCopy;
                }
                LocalFree((HLOCAL)lpTemp);
            }

        }

        if (Status)
            *Status = bResult;

        break;

    case SymTagBaseType:

        symType = Context->Parser.GetBaseType(
            Context,
            TypeIndex,
            &bResult);

        if (bResult) {

            //
            // Query basic type.
            // 
            // N.B. Basic type string is local variable make it copy to allocated buffer.
            //
            lpTemp = SympGetTypeNameString(
                (SymBasicType)symType,
                (ULONG)symSize);

            if (lpTemp) {
                nLen = _strlen(lpTemp);
                lpStringCopy = (LPWSTR)LocalAlloc(LPTR, (1 + nLen) * sizeof(WCHAR));
                if (lpStringCopy) {
                    _strcpy(lpStringCopy, lpTemp);
                    lpSymbolTypeName = lpStringCopy;
                }
            }

        }

        if (Status)
            *Status = bResult;

        break;

    case SymTagArrayType:
    case SymTagTypedef:
    default:

        symType = Context->Parser.GetTypeId(
            Context,
            TypeIndex,
            &bResult);

        if (bResult) {

            lpSymbolTypeName = Context->Parser.GetTypeName(
                Context,
                symType,
                BaseTypeSize,
                &bResult);

        }

        if (Status)
            *Status = bResult;

        break;
    }


    return lpSymbolTypeName;
}

/// <summary>
/// Lookup symbol address by it name
/// </summary>
/// <param name="Context"></param>
/// <param name="SymbolName"></param>
/// <param name="Status"></param>
/// <returns></returns>
ULONG64 SymParserLookupAddressBySymbol(
    _In_ PSYMCONTEXT Context,
    _In_ LPCWSTR SymbolName,
    _Out_opt_ PBOOL Status
)
{
    BOOL bStatus = FALSE;
    SIZE_T symSize;
    ULONG64 symAddress = 0;
    PSYMBOL_INFO symbolInfo = NULL;

    symSize = sizeof(SYMBOL_INFO);

    symbolInfo = (PSYMBOL_INFO)supHeapAlloc(symSize);
    if (symbolInfo) {

        symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbolInfo->MaxNameLen = 0; //name is not used

        bStatus = Context->DbgHelp.SymFromName(
            Context->ProcessHandle,
            SymbolName,
            symbolInfo);

        Context->SymLastError = GetLastError();

        if (bStatus)
            symAddress = symbolInfo->Address;

        supHeapFree(symbolInfo);
    }

    if (Status)
        *Status = bStatus;

    return symAddress;
}

/// <summary>
/// Lookup symbol name by it address
/// </summary>
/// <param name="Context"></param>
/// <param name="SymbolAddress"></param>
/// <param name="Displacement"></param>
/// <param name="SymbolName">
/// Pointer to variable to receive symbol name. 
/// Use LocalFree to release allocated memory
/// </param>
/// <param name="Status"></param>
/// <returns>Length of the symbol name</returns>
ULONG SymParserLookupSymbolByAddress(
    _In_ PSYMCONTEXT Context,
    _In_ DWORD64 SymbolAddress,
    _In_ PDWORD64 Displacement,
    _Inout_ LPWSTR* SymbolName,
    _Out_opt_ PBOOL Status
)
{
    BOOL bStatus = FALSE;
    ULONG nameLength = 0;
    SIZE_T symSize;
    LPWSTR symName = NULL;
    PSYMBOL_INFO symbolInfo = NULL;

    symSize = sizeof(SYMBOL_INFO) +
        MAX_SYM_NAME * sizeof(WCHAR);

    *SymbolName = NULL;

    symbolInfo = (PSYMBOL_INFO)supHeapAlloc(symSize);
    if (symbolInfo) {

        symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbolInfo->MaxNameLen = MAX_SYM_NAME;

        bStatus = Context->DbgHelp.SymFromAddr(
            Context->ProcessHandle,
            SymbolAddress,
            Displacement,
            symbolInfo);

        Context->SymLastError = GetLastError();

        if (bStatus) {

            if (symbolInfo->NameLen) {
                symName = (LPWSTR)LocalAlloc(LPTR, MAX_SYM_NAME + 1);
                if (symName) {

                    _strncpy(symName, MAX_SYM_NAME,
                        symbolInfo->Name,
                        symbolInfo->NameLen);

                    nameLength = (ULONG)_strlen(symName);

                    *SymbolName = symName;
                }
            }

        }

        supHeapFree(symbolInfo);
    }

    if (Status)
        *Status = bStatus;

    return nameLength;
}

/// <summary>
/// Return offset to the specified symbol field
/// </summary>
/// <param name="Context"></param>
/// <param name="SymbolName"></param>
/// <param name="FieldName"></param>
/// <param name="Status"></param>
/// <returns></returns>
ULONG SymParserGetFieldOffset(
    _In_ PSYMCONTEXT Context,
    _In_ LPCWSTR SymbolName,
    _In_ LPCWSTR FieldName,
    _Out_opt_ PBOOL Status
)
{
    BOOL bStatus = FALSE;
    ULONG symOffset = 0, rootIndex, childCount, childIndex;
    ULONG i;
    SIZE_T symSize;
    LPCWSTR lpSymbolName = NULL;
    PSYMBOL_INFO rootSymbolInfo = NULL;
    TI_FINDCHILDREN_PARAMS* childrenBuffer;
    TI_FINDCHILDREN_PARAMS* childEntry;

    do {
        symSize = sizeof(SYMBOL_INFO) +
            (MAX_SYM_NAME * sizeof(WCHAR));

        rootSymbolInfo = (PSYMBOL_INFO)supHeapAlloc(symSize);
        if (rootSymbolInfo == NULL)
            break;

        rootSymbolInfo->SizeOfStruct = (ULONG)symSize;
        rootSymbolInfo->MaxNameLen = MAX_SYM_NAME;

        bStatus = Context->DbgHelp.SymGetTypeFromName(
            Context->ProcessHandle,
            Context->ModuleBase,
            SymbolName,
            rootSymbolInfo);

        Context->SymLastError = GetLastError();

        if (!bStatus)
            break;

        rootIndex = rootSymbolInfo->Index;

        childCount = Context->Parser.GetChildrenCount(
            Context,
            rootIndex,
            &bStatus);

        if (!bStatus)
            break;

        if (childCount == 0) {
            bStatus = FALSE;
            break;
        }

        childrenBuffer = (TI_FINDCHILDREN_PARAMS*)supHeapAlloc(
            sizeof(TI_FINDCHILDREN_PARAMS) + childCount * sizeof(ULONG));

        if (childrenBuffer == NULL)
            break;

        childEntry = &childrenBuffer[0];
        childEntry->Count = childCount;

        bStatus = Context->DbgHelp.SymGetTypeInfo(
            Context->ProcessHandle,
            Context->ModuleBase,
            rootIndex,
            TI_FINDCHILDREN,
            childEntry);

        if (bStatus) {

            if (childEntry->Start > childCount) {
                bStatus = FALSE;
                break;
            }

            if (childEntry->Start)
                i = childEntry->Start;
            else
                i = 0;

            bStatus = FALSE;

            do {

                childIndex = childEntry->ChildId[i];
                lpSymbolName = Context->Parser.GetName(
                    Context,
                    childIndex,
                    NULL);
                if (lpSymbolName) {

                    bStatus = (_strcmpi(FieldName, lpSymbolName) == 0);

                    if (bStatus) {

                        symOffset = Context->Parser.GetOffset(
                            Context,
                            childIndex,
                            NULL);

                    }

                    LocalFree((HLOCAL)lpSymbolName);
                }

                i++;

            } while (!bStatus && i < childCount);

        }

        supHeapFree(childrenBuffer);

    } while (FALSE);

    if (rootSymbolInfo)
        supHeapFree(rootSymbolInfo);

    if (Status)
        *Status = bStatus;

    return symOffset;
}

/// <summary>
/// Read symbol type information including childrens
/// </summary>
/// <param name="Context"></param>
/// <param name="SymbolName"></param>
/// <param name="Status"></param>
/// <returns></returns>
PSYM_ENTRY SymParserDumpSymbolInformation(
    _In_ PSYMCONTEXT Context,
    _In_ LPCWSTR SymbolName,
    _Out_opt_ PBOOL Status
)
{
    BOOL bStatus = FALSE;
    ULONG rootIndex, childCount, childIndex, typeId, i;
    ULONG cNameUnknown = 0, cTypeUnknown = 0;
    SIZE_T symSize, nLen;
    ULONG64 baseTypeSize;
    LPCWSTR lpSymbolName = NULL;
    PSYM_ENTRY dumpEntry = NULL;
    PSYM_CHILD dumpChild = NULL;
    PSYMBOL_INFO rootSymbolInfo = NULL;
    TI_FINDCHILDREN_PARAMS* childrenBuffer;
    TI_FINDCHILDREN_PARAMS* childEntry;
    VARIANT value;
    VARTYPE valueType;

    do {

        symSize = sizeof(SYMBOL_INFO) +
            (MAX_SYM_NAME * sizeof(WCHAR));

        rootSymbolInfo = (PSYMBOL_INFO)supHeapAlloc(symSize);
        if (rootSymbolInfo == NULL)
            break;

        rootSymbolInfo->SizeOfStruct = (ULONG)symSize;
        rootSymbolInfo->MaxNameLen = MAX_SYM_NAME;

        bStatus = Context->DbgHelp.SymGetTypeFromName(
            Context->ProcessHandle,
            Context->ModuleBase,
            SymbolName,
            rootSymbolInfo);

        if (!bStatus)
            break;

        rootIndex = rootSymbolInfo->Index;

        childCount = Context->Parser.GetChildrenCount(
            Context,
            rootIndex,
            &bStatus);

        if (!bStatus)
            break;

        //
        // Fill result.
        //
        dumpEntry = (PSYM_ENTRY)supHeapAlloc(sizeof(SYM_ENTRY) +
            (sizeof(SYM_CHILD) * childCount));

        if (dumpEntry == NULL)
            break;

        dumpEntry->Size = rootSymbolInfo->Size;
        dumpEntry->Offset = 0;

        _strncpy(dumpEntry->Name,
            RTL_NUMBER_OF(dumpEntry->Name),
            rootSymbolInfo->Name,
            rootSymbolInfo->NameLen);

        if (childCount == 0)
            break;

        childrenBuffer = (TI_FINDCHILDREN_PARAMS*)supHeapAlloc(
            sizeof(TI_FINDCHILDREN_PARAMS) + childCount * sizeof(ULONG));

        if (childrenBuffer) {

            childEntry = &childrenBuffer[0];
            childEntry->Count = childCount;

            bStatus = Context->DbgHelp.SymGetTypeInfo(
                Context->ProcessHandle,
                Context->ModuleBase,
                rootIndex,
                TI_FINDCHILDREN,
                childEntry);

            if (bStatus) {

                dumpEntry->ChildCount = childCount;

                if (childEntry->Start)
                    i = childEntry->Start;
                else
                    i = 0;

                for (; i < childCount; i++) {

                    dumpChild = &dumpEntry->ChildEntries[i];
                    childIndex = childEntry->ChildId[i];

                    typeId = Context->Parser.GetTypeId(Context, childIndex, NULL);

                    dumpChild->Size = Context->Parser.GetSize(
                        Context,
                        typeId,
                        NULL);

                    dumpChild->Offset = Context->Parser.GetOffset(
                        Context,
                        childIndex,
                        NULL);

                    dumpChild->BitPosition = Context->Parser.GetBitPosition(
                        Context,
                        childIndex,
                        &dumpChild->IsBitField);

                    VariantInit(&value);

                    valueType = Context->Parser.GetValue(
                        Context,
                        childIndex,
                        &value,
                        &dumpChild->IsValuePresent);

                    switch (valueType) {
                    case VT_I1:
                        dumpChild->Value = value.cVal;
                        break;
                    case VT_I2:
                        dumpChild->Value = value.iVal;
                        break;
                    case VT_I4:
                    case VT_INT:
                        dumpChild->Value = value.intVal;
                        break;
                    case VT_UINT:
                    case VT_UI4:
                        dumpChild->Value = value.uintVal;
                        break;
                    case VT_UI1:
                        dumpChild->Value = value.bVal;
                        break;
                    case VT_UI2:
                        dumpChild->Value = value.uiVal;
                        break;
                    case VT_UI8:
                        dumpChild->Value = value.ullVal;
                        break;
                    case VT_INT_PTR:
                        dumpChild->Value = (DWORD64)value.pintVal;
                        break;
                    case VT_UINT_PTR:
                        dumpChild->Value = (DWORD64)value.puintVal;
                        break;
                    default:
                        dumpChild->Value = value.ullVal;
                        break;
                    }

                    VariantClear(&value);

                    //
                    // Child name.
                    //
                    lpSymbolName = Context->Parser.GetName(
                        Context,
                        childIndex,
                        NULL);

                    if (lpSymbolName) {

                        nLen = _strlen(lpSymbolName);

                        _strncpy(dumpChild->Name,
                            MAX_SYM_NAME,
                            lpSymbolName,
                            nLen);

                        LocalFree((HLOCAL)lpSymbolName);
                    }
                    else {
                        RtlStringCchPrintfSecure(dumpChild->Name,
                            MAX_SYM_NAME,
                            TEXT("Unknown%lu"),
                            cNameUnknown);

                        cNameUnknown += 1;
                    }

                    //
                    // Child type name.
                    //
                    baseTypeSize = 0;
                    lpSymbolName = Context->Parser.GetTypeName(
                        Context,
                        typeId,
                        &baseTypeSize,
                        Status);

                    if (lpSymbolName) {

                        nLen = _strlen(lpSymbolName);

                        _strncpy(dumpChild->TypeName,
                            MAX_SYM_NAME,
                            lpSymbolName,
                            nLen);

                        if (baseTypeSize == 0) {
                            dumpChild->ElementsCount = 1;
                        }
                        else {
                            dumpChild->ElementsCount = dumpChild->Size / baseTypeSize;
                        }


                        LocalFree((HLOCAL)lpSymbolName);
                    }
                    else {
                        RtlStringCchPrintfSecure(dumpChild->TypeName,
                            RTL_NUMBER_OF(dumpChild->TypeName),
                            TEXT("UNKNOWN%lu"),
                            cTypeUnknown);

                        cTypeUnknown += 1;
                    }

                }

            }

            supHeapFree(childrenBuffer);
        }


    } while (FALSE);

    if (!bStatus) {
        if (rootSymbolInfo) supHeapFree(rootSymbolInfo);
        if (dumpEntry) {
            supHeapFree(dumpEntry);
            dumpEntry = NULL;
        }
    }

    if (Status)
        *Status = bStatus;

    return dumpEntry;
}

BOOL SympInitPointers(
    _In_ HMODULE hDbgHelp,
    _Inout_ DBGHELP_PTRS* Ptrs
)
{
    BOOL bResult = TRUE;
    LPCSTR szFuncs[] = {
        "SymSetOptions",
        "SymInitializeW",
        "SymRegisterCallbackW64",
        "SymLoadModuleExW",
        "SymGetTypeInfo",
        "SymFromNameW",
        "SymFromAddrW",
        "SymGetTypeFromNameW",
        "SymUnloadModule64",
        "SymCleanup"
    };

    DWORD64 dwPtrs[sizeof(DBGHELP_PTRS) / sizeof(DWORD64)];

    UINT i;

    RtlSecureZeroMemory(dwPtrs, sizeof(dwPtrs));

    for (i = 0; i < RTL_NUMBER_OF(szFuncs); i++) {
        dwPtrs[i] = (DWORD64)GetProcAddress(hDbgHelp, szFuncs[i]);
        if (dwPtrs[i] == 0) {
            bResult = FALSE;
            break;
        }
    }

    if (bResult) {

        RtlCopyMemory(Ptrs, dwPtrs, sizeof(DBGHELP_PTRS));

    }

    return bResult;
}

/// <summary>
/// Create symbol parser context
/// </summary>
/// <returns>Pointer to allocated symbols context, use SymParserDestroy to deallocate it</returns>
PSYMCONTEXT SymParserCreate(
    VOID
)
{
    PSYMCONTEXT Context;
    
    if (g_SymGlobals.Initialized == FALSE)
        return NULL;

    Context = (PSYMCONTEXT)supHeapAlloc(sizeof(SYMCONTEXT));
    if (Context) {

        Context->DbgHelp = g_SymGlobals.ApiSet;
        Context->ProcessHandle = g_SymGlobals.ProcessHandle;
        Context->ModuleBase = 0;

        Context->Parser.GetChildrenCount = (SPGetChildrenCount)SymParserGetChildrenCount;
        Context->Parser.GetAddressOffset = (SPGetAddressOffset)SymParserGetAddressOffset;
        Context->Parser.GetArrayTypeId = (SPGetArrayTypeId)SymParserGetArrayTypeId;
        Context->Parser.GetBaseType = (SPGetBaseType)SymParserGetBaseType;
        Context->Parser.GetBitPosition = (SPGetBitPosition)SymParserGetBitPosition;
        Context->Parser.GetName = (SPGetName)SymParserGetName;
        Context->Parser.GetOffset = (SPGetOffset)SymParserGetOffset;
        Context->Parser.GetSize = (SPGetSize)SymParserGetSize;
        Context->Parser.GetTag = (SPGetTag)SymParserGetTag;
        Context->Parser.GetType = (SPGetType)SymParserGetType;
        Context->Parser.GetTypeId = (SPGetTypeId)SymParserGetTypeId;
        Context->Parser.GetTypeName = (SPGetTypeName)SymParserGetTypeName;
        Context->Parser.GetValue = (SPGetValue)SymParserGetValue;
        Context->Parser.GetCount = (SPGetCount)SymParserGetCount;
        Context->Parser.GetUDTKind = (SPGetUDTKind)SymParserGetUDTKind;
        Context->Parser.GetCallingConvention = (SPGetCallingConvention)SymParserGetCallingConvention;
        Context->Parser.GetFieldOffset = (SPGetFieldOffset)SymParserGetFieldOffset;
        Context->Parser.LoadModule = (SPLoadModule)SymParserLoadModule;
        Context->Parser.UnloadModule = (SPUnloadModule)SymParserUnloadModule;
        Context->Parser.LookupAddressBySymbol = (SPLookupAddressBySymbol)SymParserLookupAddressBySymbol;
        Context->Parser.LookupSymbolByAddress = (SPLookupSymbolByAddress)SymParserLookupSymbolByAddress;
        Context->Parser.DumpSymbolInformation = (SPDumpSymbolInformation)SymParserDumpSymbolInformation;

    }
    else {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    }

    return Context;
}

/// <summary>
/// Deallocates all resources and destroy symbol context.
/// </summary>
/// <param name="Context">Pointer to symbols context</param>
VOID SymParserDestroy(
    _In_ PSYMCONTEXT Context
)
{
    if (Context) {
        supHeapFree(Context);
    }
}

/// <summary>
/// Initialize global variables, called once.
/// </summary>
/// <param name="SymOptions"></param>
/// <param name="ProcessHandle"></param>
/// <param name="lpDbgHelpPath"></param>
/// <param name="lpSymbolPath"></param>
/// <param name="lpSystemPath">System32 directory, maximum length is MAX_PATH</param>
/// <param name="lpTempPath">Temp directory, maximum length is MAX_PATH</param>
/// <returns>TRUE on success</returns>
BOOL SymGlobalsInit(
    _In_ DWORD SymOptions,
    _In_opt_ HANDLE ProcessHandle,
    _In_opt_ LPCWSTR lpDbgHelpPath,
    _In_opt_ LPCWSTR lpSymbolPath,
    _In_ LPCWSTR lpSystemPath,
    _In_ LPCWSTR lpTempPath,
    _In_opt_ PSYMBOL_REGISTERED_CALLBACK64 CallbackFunction,
    _In_ ULONG64 UserContext
)
{
    BOOL bResult = FALSE;
    DWORD symOptions;
    HMODULE hDbg = NULL;
    LPWSTR locaDbgHelplPath = NULL;
    SIZE_T nLen;
    WCHAR szWinPath[MAX_PATH * 2];

    RtlSecureZeroMemory(&g_SymGlobals, sizeof(g_SymGlobals));

    //
    // Validate symbols path input length.
    //
    nLen = _strlen(lpSymbolPath);
    if (nLen >= RTL_NUMBER_OF(g_SymGlobals.szSymbolsPath)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    nLen = _strlen(lpTempPath);
    if (nLen > MAX_PATH) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    //
    // Prepare path and load dbghelp library.
    //
    if (lpDbgHelpPath) {

        locaDbgHelplPath = (LPWSTR)lpDbgHelpPath;

    }
    else {

        nLen = _strlen(lpSystemPath);
        if (nLen > MAX_PATH) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }

        RtlSecureZeroMemory(&szWinPath, sizeof(szWinPath));

        _strncpy(szWinPath,
            MAX_PATH,
            lpSystemPath,
            nLen);

        supPathAddBackSlash(szWinPath);
        _strcat(szWinPath, DEFAULT_DLL);

        locaDbgHelplPath = szWinPath;
    }

    hDbg = LoadLibraryEx(
        locaDbgHelplPath,
        NULL,
        0);

    if (hDbg == NULL)
        return FALSE;

    g_SymGlobals.DllHandle = hDbg;

    //
    // Init dbghelp pointers and allocate context.
    //
    RtlSecureZeroMemory(&g_SymGlobals.ApiSet, sizeof(DBGHELP_PTRS));

    if (SympInitPointers(hDbg, &g_SymGlobals.ApiSet)) {

        if (ProcessHandle == NULL) {
            g_SymGlobals.ProcessHandle = NtCurrentProcess();
        }
        else {
            g_SymGlobals.ProcessHandle = ProcessHandle;
        }

        if (lpSymbolPath) {
            _strcpy(g_SymGlobals.szSymbolsPath, lpSymbolPath);
        }
        else {

            RtlStringCchPrintfSecure(g_SymGlobals.szSymbolsPath,
                RTL_NUMBER_OF(g_SymGlobals.szSymbolsPath) - 1,
                TEXT("srv*%ws\\%ws"),
                lpTempPath,
                DEFAULT_SYMPATH);

        }

        symOptions = SymOptions;

        if (symOptions == 0) {
            symOptions = SYMOPT_DEFERRED_LOADS |
                SYMOPT_CASE_INSENSITIVE |
                SYMOPT_UNDNAME |
                SYMOPT_AUTO_PUBLICS;
        }

        g_SymGlobals.ApiSet.SymSetOptions(symOptions);

        g_SymGlobals.Options = symOptions;

        bResult = g_SymGlobals.ApiSet.SymInitializeW(
            g_SymGlobals.ProcessHandle,
            g_SymGlobals.szSymbolsPath,
            FALSE);

        if (bResult && CallbackFunction) {

            g_SymGlobals.ApiSet.SymRegisterCallbackW64(
                g_SymGlobals.ProcessHandle,
                CallbackFunction,
                UserContext);

        }

    }
    else {
        SetLastError(ERROR_PROC_NOT_FOUND);
    }

    if (!bResult)
    {
        FreeLibrary(hDbg);
        g_SymGlobals.DllHandle = NULL;
    }

    g_SymGlobals.Initialized = bResult;

    return bResult;
}

/// <summary>
/// Free allocated resources, called once.
/// </summary>
/// <returns></returns>
BOOL SymGlobalsFree()
{
    BOOL bResult = FALSE;

    if (g_SymGlobals.ApiSet.SymCleanup) {
        g_SymGlobals.ApiSet.SymCleanup(g_SymGlobals.ProcessHandle);

        if (g_SymGlobals.DllHandle)
            bResult = FreeLibrary(g_SymGlobals.DllHandle);

    }

    return bResult;
}
