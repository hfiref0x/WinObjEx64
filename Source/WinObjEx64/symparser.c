/*******************************************************************************
*
*  (C) COPYRIGHT H.E., 2015 - 2025
*
*  TITLE:       SYMPARSER.C
*
*  VERSION:     1.25
*
*  DATE:        13 Jun 2025
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
static const BasicTypeMapElement BasicTypeMapMSVC[] = {
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

/**
* Find the basic type name string from the type map
*
* @param TypeMap - Type mapping table
* @param BasicType - Basic type to look up
* @param Length - Type size in bytes
* @return Type name string or NULL if not found
*/
PCWSTR SympGetBasicTypeNameString(
    _In_ const BasicTypeMapElement* TypeMap,
    _In_ SymBasicType BasicType,
    _In_ ULONG Length
)
{
    ULONG i;
    for (i = 0; TypeMap[i].BasicType != btMaxType; i++) {
        if (TypeMap[i].BasicType == BasicType) {
            if (TypeMap[i].Length == Length || TypeMap[i].Length == 0) {
                return TypeMap[i].TypeName;
            }
        }
    }
    return NULL;
}

/**
* Get type name string for a basic type
*
* @param BasicType - Basic type to look up
* @param Length - Type size in bytes
* @return Type name string or NULL if not found
*/
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

/**
* Register callback for symbol operations
*
* @param Context - Symbol context
* @param CallbackFunction - Callback function pointer
* @param UserContext - User context to pass to callback
* @return TRUE on success, FALSE on failure
*/
BOOL SymParserRegisterCallback(
    _In_ PSYMCONTEXT Context,
    _In_ PSYMBOL_REGISTERED_CALLBACK64 CallbackFunction,
    _In_ ULONG64 UserContext
)
{
    if (!Context || !CallbackFunction)
        return FALSE;

    return Context->DbgHelp.SymRegisterCallbackW64(
        Context->ProcessHandle,
        CallbackFunction,
        UserContext);
}

/**
* Load module for symbol parsing
*
* @param Context - Symbol context
* @param lpModulePath - Module path
* @param BaseOfDll - Base address of module
* @param SizeOfDll - Size of module
* @return TRUE on success, FALSE on failure
*/
BOOL SymParserLoadModule(
    _In_ PSYMCONTEXT Context,
    _In_ LPCWSTR lpModulePath,
    _In_ DWORD64 BaseOfDll,
    _In_ DWORD SizeOfDll
)
{
    DWORD64 moduleBase;

    if (!Context || !lpModulePath)
        return FALSE;

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

/**
* Unload module from symbol context
*
* @param Context - Symbol context
* @return TRUE on success, FALSE on failure
*/
BOOL SymParserUnloadModule(
    _In_ PSYMCONTEXT Context
)
{
    BOOL bStatus;

    if (!Context || Context->ModuleBase == 0)
        return FALSE;

    bStatus = Context->DbgHelp.SymUnloadModule(
        Context->ProcessHandle,
        Context->ModuleBase);

    Context->SymLastError = GetLastError();

    if (bStatus)
        Context->ModuleBase = 0;

    return bStatus;
}

/**
 * Template function for safely retrieving type information
 *
 * @param Context - Symbol context
 * @param TypeIndex - Type index
 * @param GetType - Type of information to retrieve
 * @param OutputValue - Pointer to output value
 * @param Status - Optional output for status
 * @return TRUE if successful, FALSE otherwise
 */
BOOL SympGetTypeInfo(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _In_ IMAGEHLP_SYMBOL_TYPE_INFO GetType,
    _When_(return, _Post_valid_) _Pre_defensive_ PVOID OutputValue,
    _Out_opt_ PBOOL Status
)
{
    BOOL bSuccess = FALSE;

    // Parameter validation
    if (!Context || !OutputValue) {
        if (Status) *Status = FALSE;
        return FALSE;
    }

    // Check if module is loaded
    if (Context->ModuleBase == 0) {
        Context->SymLastError = ERROR_NOT_READY;
        if (Status) *Status = FALSE;
        return FALSE;
    }

    // Check if we have valid function pointer
    if (!Context->DbgHelp.SymGetTypeInfo) {
        Context->SymLastError = ERROR_INVALID_FUNCTION;
        if (Status) *Status = FALSE;
        return FALSE;
    }

    bSuccess = Context->DbgHelp.SymGetTypeInfo(
        Context->ProcessHandle,
        Context->ModuleBase,
        TypeIndex,
        GetType,
        OutputValue);

    Context->SymLastError = GetLastError();

    if (Status)
        *Status = bSuccess;

    return bSuccess;
}


/**
* Get symbol type
*
* @param Context - Symbol context
* @param TypeIndex - Type index
* @param Status - Optional status output
* @return Symbol type
*/
SymBasicType SymParserGetType(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    SymBasicType symType = btNoType;
    BOOL bSuccess = SympGetTypeInfo(Context, TypeIndex, TI_GET_TYPE, &symType, Status);

    if (!bSuccess)
        return btNoType;

    return symType;
}

/**
* Get symbol base type
*
* @param Context - Symbol context
* @param TypeIndex - Type index
* @param Status - Optional status output
* @return Symbol base type
*/
SymBasicType SymParserGetBaseType(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    SymBasicType symBaseType = btNoType;
    BOOL bSuccess = SympGetTypeInfo(Context, TypeIndex, TI_GET_BASETYPE, &symBaseType, Status);

    if (!bSuccess)
        return btNoType;

    return symBaseType;
}

/**
* Get symbol type ID
*
* @param Context - Symbol context
* @param TypeIndex - Type index
* @param Status - Optional status output
* @return Symbol type ID
*/
ULONG SymParserGetTypeId(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    ULONG typeId = 0;
    BOOL bSuccess = SympGetTypeInfo(Context, TypeIndex, TI_GET_TYPEID, &typeId, Status);

    if (!bSuccess)
        return 0;

    return typeId;
}

/**
* Get symbol array type ID
*
* @param Context - Symbol context
* @param TypeIndex - Type index
* @param Status - Optional status output
* @return Symbol array type ID
*/
ULONG SymParserGetArrayTypeId(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    ULONG typeId = 0;
    BOOL bSuccess = SympGetTypeInfo(Context, TypeIndex, TI_GET_ARRAYINDEXTYPEID, &typeId, Status);

    if (!bSuccess)
        return 0;

    return typeId;
}

/**
* Get symbol size
*
* @param Context - Symbol context
* @param TypeIndex - Type index
* @param Status - Optional status output
* @return Symbol size
*/
ULONG64 SymParserGetSize(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    ULONG64 symSize = 0;
    BOOL bSuccess = SympGetTypeInfo(Context, TypeIndex, TI_GET_LENGTH, &symSize, Status);

    if (!bSuccess)
        return 0;

    return symSize;
}

/**
* Get symbol offset
*
* @param Context - Symbol context
* @param TypeIndex - Type index
* @param Status - Optional status output
* @return Symbol offset
*/
ULONG SymParserGetOffset(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    ULONG symOffset = 0;
    BOOL bSuccess = SympGetTypeInfo(Context, TypeIndex, TI_GET_OFFSET, &symOffset, Status);

    if (!bSuccess)
        return 0;

    return symOffset;
}

/**
* Get symbol address offset
*
* @param Context - Symbol context
* @param TypeIndex - Type index
* @param Status - Optional status output
* @return Symbol address offset
*/
ULONG SymParserGetAddressOffset(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    ULONG symOffset = 0;
    BOOL bSuccess = SympGetTypeInfo(Context, TypeIndex, TI_GET_ADDRESSOFFSET, &symOffset, Status);

    if (!bSuccess)
        return 0;

    return symOffset;
}

/**
* Get symbol bit position
*
* @param Context - Symbol context
* @param TypeIndex - Type index
* @param Status - Optional status output
* @return Symbol bit position
*/
ULONG SymParserGetBitPosition(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    ULONG bitPosition = 0;
    BOOL bSuccess = SympGetTypeInfo(Context, TypeIndex, TI_GET_BITPOSITION, &bitPosition, Status);

    if (!bSuccess)
        return 0;

    return bitPosition;
}

/**
* Get symbol children count
*
* @param Context - Symbol context
* @param TypeIndex - Type index
* @param Status - Optional status output
* @return Symbol children count
*/
ULONG SymParserGetChildrenCount(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    ULONG childCount = 0;
    BOOL bSuccess = SympGetTypeInfo(Context, TypeIndex, TI_GET_CHILDRENCOUNT, &childCount, Status);

    if (!bSuccess)
        return 0;

    return childCount;
}

/**
* Get symbol tag
*
* @param Context - Symbol context
* @param TypeIndex - Type index
* @param Status - Optional status output
* @return Symbol tag
*/
ULONG SymParserGetTag(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    ULONG symTag = 0;
    BOOL bSuccess = SympGetTypeInfo(Context, TypeIndex, TI_GET_SYMTAG, &symTag, Status);

    if (!bSuccess)
        return 0;

    return symTag;
}

/**
* Get symbol name
*
* @param Context - Symbol context
* @param TypeIndex - Type index
* @param Status - Optional status output
* @return Symbol name (must be freed with LocalFree)
*/
_Ret_maybenull_ _Post_writable_byte_size_(MAX_SYM_NAME * sizeof(WCHAR))
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

/**
* Get symbol value
*
* @param Context - Symbol context
* @param TypeIndex - Type index
* @param Value - Output variant value
* @param Status - Optional status output
* @return Variant type
*/
VARTYPE SymParserGetValue(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Inout_ VARIANT * Value,
    _Out_opt_ PBOOL Status
)
{
    VARTYPE varResult;

    if (!Value) {
        if (Status) *Status = FALSE;
        return VT_EMPTY;
    }

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

/**
* Get symbol UDT kind
*
* @param Context - Symbol context
* @param TypeIndex - Type index
* @param Status - Optional status output
* @return UDT kind
*/
SymUdtKind SymParserGetUDTKind(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    SymUdtKind udtKind = UdtInvalid;
    BOOL bSuccess = SympGetTypeInfo(Context, TypeIndex, TI_GET_UDTKIND, &udtKind, Status);

    if (!bSuccess)
        return UdtInvalid;

    return udtKind;
}

/**
* Get symbol count
*
* @param Context - Symbol context
* @param TypeIndex - Type index
* @param Status - Optional status output
* @return Count value
*/
ULONG SymParserGetCount(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    ULONG ulCount = 0;
    BOOL bSuccess = SympGetTypeInfo(Context, TypeIndex, TI_GET_COUNT, &ulCount, Status);

    if (!bSuccess)
        return 0;

    return ulCount;
}

/**
* Get symbol calling convention
*
* @param Context - Symbol context
* @param TypeIndex - Type index
* @param Status - Optional status output
* @return Calling convention value
*/
ULONG SymParserGetCallingConvention(
    _In_ PSYMCONTEXT Context,
    _In_ ULONG TypeIndex,
    _Out_opt_ PBOOL Status
)
{
    ULONG ulCallingConvention = 0;
    BOOL bSuccess = SympGetTypeInfo(Context, TypeIndex, TI_GET_CALLING_CONVENTION, &ulCallingConvention, Status);

    if (!bSuccess)
        return 0;

    return ulCallingConvention;
}

/**
* Get type name for a symbol
*
* @param Context - Symbol context
* @param TypeIndex - Type index
* @param BaseTypeSize - Optional output for base type size
* @param Status - Optional status output
* @return Type name string (must be freed with LocalFree)
*/
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

    if (BaseTypeSize)
        *BaseTypeSize = 0;

    symSize = Context->Parser.GetSize(Context, TypeIndex, &bResult);
    if (!bResult) {
        if (Status) *Status = FALSE;
        return NULL;
    }

    if (BaseTypeSize)
        *BaseTypeSize = symSize;

    lpSymbolTypeName = Context->Parser.GetName(Context, TypeIndex, &bResult);
    if (lpSymbolTypeName) {
        if (Status) *Status = TRUE;
        return lpSymbolTypeName;
    }

    tagEnum = Context->Parser.GetTag(Context, TypeIndex, &bResult);
    if (!bResult) {
        if (Status) *Status = FALSE;
        return NULL;
    }

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
                    bResult = TRUE;
                }

                break;
            }

        }
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
        break;
    }

    if (Status)
        *Status = bResult;

    return lpSymbolTypeName;
}

/**
* Look up a symbol address by name
*
* @param Context - Symbol context
* @param SymbolName - Symbol name to look up
* @param Status - Optional status output
* @return Symbol address or 0 on failure
*/
ULONG64 SymParserLookupAddressBySymbol(
    _In_ PSYMCONTEXT Context,
    _In_ LPCWSTR SymbolName,
    _Out_opt_ PBOOL Status
)
{
    BOOL bStatus = FALSE;
    ULONG64 symAddress = 0;
    PSYMBOL_INFO symbolInfo = NULL;

    if (!Context || !SymbolName) {
        if (Status) *Status = FALSE;
        return 0;
    }

    symbolInfo = (PSYMBOL_INFO)supHeapAlloc(sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(WCHAR));
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

/**
* Look up a symbol name by address
*
* @param Context - Symbol context
* @param SymbolAddress - Address to look up
* @param Displacement - Output displacement
* @param SymbolName - Output symbol name pointer (must be freed with LocalFree)
* @param Status - Optional status output
* @return Length of symbol name
*/
ULONG SymParserLookupSymbolByAddress(
    _In_ PSYMCONTEXT Context,
    _In_ DWORD64 SymbolAddress,
    _In_ PDWORD64 Displacement,
    _Inout_ LPWSTR * SymbolName,
    _Out_opt_ PBOOL Status
)
{
    BOOL bStatus = FALSE;
    ULONG nameLength = 0;
    LPWSTR symName = NULL;
    PSYMBOL_INFO symbolInfo = NULL;

    if (!Context || !SymbolName || !Displacement) {
        if (Status) *Status = FALSE;
        return 0;
    }

    *SymbolName = NULL;

    symbolInfo = (PSYMBOL_INFO)supHeapAlloc(
        sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(WCHAR));
    if (symbolInfo) {
        symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbolInfo->MaxNameLen = MAX_SYM_NAME;

        bStatus = Context->DbgHelp.SymFromAddr(
            Context->ProcessHandle,
            SymbolAddress,
            Displacement,
            symbolInfo);

        Context->SymLastError = GetLastError();

        if (bStatus && symbolInfo->NameLen > 0) {
            symName = (LPWSTR)LocalAlloc(LPTR, MAX_SYM_NAME + 1);
            if (symName) {
                _strncpy(symName, MAX_SYM_NAME, symbolInfo->Name, symbolInfo->NameLen);
                nameLength = (ULONG)_strlen(symName);
                *SymbolName = symName;
            }
        }
        supHeapFree(symbolInfo);
    }

    if (Status)
        *Status = bStatus;

    return nameLength;
}

/**
* Get field offset from a structure
*
* @param Context - Symbol context
* @param SymbolName - Structure name
* @param FieldName - Field name
* @param Status - Optional status output
* @return Field offset or 0 on failure
*/
ULONG SymParserGetFieldOffset(
    _In_ PSYMCONTEXT Context,
    _In_ LPCWSTR SymbolName,
    _In_ LPCWSTR FieldName,
    _Out_opt_ PBOOL Status
)
{
    BOOL bStatus = FALSE;
    ULONG symOffset = 0, i;
    ULONG rootIndex = 0, childCount = 0, childIndex = 0;
    LPCWSTR lpSymbolName = NULL;
    PSYMBOL_INFO rootSymbolInfo = NULL;
    TI_FINDCHILDREN_PARAMS* childrenBuffer = NULL;

    if (!Context || !SymbolName || !FieldName) {
        if (Status) *Status = FALSE;
        return 0;
    }

    rootSymbolInfo = (PSYMBOL_INFO)supHeapAlloc(
        sizeof(SYMBOL_INFO) + (MAX_SYM_NAME * sizeof(WCHAR)));

    if (!rootSymbolInfo) {
        if (Status) *Status = FALSE;
        return 0;
    }

    rootSymbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
    rootSymbolInfo->MaxNameLen = MAX_SYM_NAME;

    bStatus = Context->DbgHelp.SymGetTypeFromName(
        Context->ProcessHandle,
        Context->ModuleBase,
        SymbolName,
        rootSymbolInfo);

    Context->SymLastError = GetLastError();

    if (!bStatus) {
        supHeapFree(rootSymbolInfo);
        if (Status) *Status = FALSE;
        return 0;
    }

    rootIndex = rootSymbolInfo->Index;
    childCount = Context->Parser.GetChildrenCount(
        Context,
        rootIndex,
        &bStatus);

    if (!bStatus || childCount == 0) {
        supHeapFree(rootSymbolInfo);
        if (Status) *Status = FALSE;
        return 0;
    }

    childrenBuffer = (TI_FINDCHILDREN_PARAMS*)supHeapAlloc(
        sizeof(TI_FINDCHILDREN_PARAMS) + childCount * sizeof(ULONG));

    if (!childrenBuffer) {
        supHeapFree(rootSymbolInfo);
        if (Status) *Status = FALSE;
        return 0;
    }

    childrenBuffer->Count = childCount;
    childrenBuffer->Start = 0;

    bStatus = Context->DbgHelp.SymGetTypeInfo(
        Context->ProcessHandle,
        Context->ModuleBase,
        rootIndex,
        TI_FINDCHILDREN,
        childrenBuffer);

    if (!bStatus) {
        supHeapFree(rootSymbolInfo);
        supHeapFree(childrenBuffer);
        if (Status) *Status = FALSE;
        return 0;
    }

    bStatus = FALSE;

    for (i = 0; i < childCount; i++) {
        childIndex = childrenBuffer->ChildId[i];
        lpSymbolName = Context->Parser.GetName(Context, childIndex, NULL);

        if (lpSymbolName) {
            bStatus = (_strcmpi(FieldName, lpSymbolName) == 0);

            if (bStatus) {
                symOffset = Context->Parser.GetOffset(Context, childIndex, NULL);
                LocalFree((HLOCAL)lpSymbolName);
                break;
            }

            LocalFree((HLOCAL)lpSymbolName);
        }
    }

    supHeapFree(rootSymbolInfo);
    supHeapFree(childrenBuffer);

    if (Status)
        *Status = bStatus;

    return symOffset;
}

/**
* Dump complete symbol information including all children
*
* @param Context - Symbol context
* @param SymbolName - Symbol name
* @param Status - Optional status output
* @return Symbol entry structure or NULL on failure (must be freed with supHeapFree)
*/
PSYM_ENTRY SymParserDumpSymbolInformation(
    _In_ PSYMCONTEXT Context,
    _In_ LPCWSTR SymbolName,
    _Out_opt_ PBOOL Status
)
{
    BOOL bStatus = FALSE;
    ULONG rootIndex, childCount, childIndex, typeId, i;
    ULONG cNameUnknown = 0, cTypeUnknown = 0;
    ULONG64 baseTypeSize;
    LPCWSTR lpSymbolName = NULL;
    PSYM_ENTRY dumpEntry = NULL;
    PSYM_CHILD dumpChild = NULL;
    PSYMBOL_INFO rootSymbolInfo = NULL;
    TI_FINDCHILDREN_PARAMS* childrenBuffer;
    TI_FINDCHILDREN_PARAMS* childEntry;
    VARIANT value;
    VARTYPE valueType;

    if (!Context || !SymbolName) {
        if (Status) *Status = FALSE;
        return NULL;
    }

    do {
        rootSymbolInfo = (PSYMBOL_INFO)supHeapAlloc(
            sizeof(SYMBOL_INFO) + (MAX_SYM_NAME * sizeof(WCHAR)));
        if (rootSymbolInfo == NULL)
            break;

        rootSymbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
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
                    lpSymbolName = Context->Parser.GetName(Context, childIndex, NULL);
                    if (lpSymbolName) {
                        _strncpy(dumpChild->Name, MAX_SYM_NAME, lpSymbolName, _strlen(lpSymbolName));
                        LocalFree((HLOCAL)lpSymbolName);
                    }
                    else {
                        RtlStringCchPrintfSecure(dumpChild->Name,
                            MAX_SYM_NAME,
                            TEXT("Unknown%lu"),
                            cNameUnknown++);
                    }

                    //
                    // Child type name.
                    //
                    baseTypeSize = 0;
                    lpSymbolName = Context->Parser.GetTypeName(Context, typeId, &baseTypeSize, NULL);
                    if (lpSymbolName) {
                        _strncpy(dumpChild->TypeName, MAX_SYM_NAME, lpSymbolName, _strlen(lpSymbolName));

                        // Calculate number of elements based on size
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
                            cTypeUnknown++);
                        dumpChild->ElementsCount = 1;
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

/**
* Initialize function pointers from DbgHelp DLL
*
* @param hDbgHelp - Handle to DbgHelp DLL
* @param Ptrs - Output structure for function pointers
* @return TRUE on success, FALSE on failure
*/
BOOL SympInitPointers(
    _In_ HMODULE hDbgHelp,
    _Inout_ DBGHELP_PTRS * Ptrs
)
{
    UINT i;
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

    if (!hDbgHelp || !Ptrs)
        return FALSE;

    RtlSecureZeroMemory(dwPtrs, sizeof(dwPtrs));

    for (i = 0; i < RTL_NUMBER_OF(szFuncs); i++) {
        dwPtrs[i] = (DWORD64)GetProcAddress(hDbgHelp, szFuncs[i]);
        if (dwPtrs[i] == 0) {
            return FALSE;
        }
    }

    RtlCopyMemory(Ptrs, dwPtrs, sizeof(DBGHELP_PTRS));
    return TRUE;
}

/**
* Create a symbol parser context
*
* @return Symbol context or NULL on failure (must be freed with SymParserDestroy)
*/
PSYMCONTEXT SymParserCreate(
    VOID
)
{
    PSYMCONTEXT Context;

    if (g_SymGlobals.Initialized == FALSE) {
        SetLastError(ERROR_NOT_READY);
        return NULL;
    }

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
        return NULL;
    }

    return Context;
}

/**
* Destroy a symbol parser context and free resources
*
* @param Context - Symbol context to destroy
*/
VOID SymParserDestroy(
    _In_ PSYMCONTEXT Context
)
{
    if (Context) {
        if (Context->ModuleBase != 0)
            SymParserUnloadModule(Context);
        supHeapFree(Context);
    }
}

/**
* Initialize global symbol parser environment
*
* @param SymOptions - Symbol options or 0 for default
* @param ProcessHandle - Process handle or NULL for current process
* @param lpDbgHelpPath - Path to DbgHelp.dll or NULL for default
* @param lpSymbolPath - Symbol path or NULL for default
* @param lpSystemPath - System32 directory
* @param lpTempPath - Temp directory for symbol cache
* @param CallbackFunction - Optional callback function
* @param UserContext - User context for callback
* @return TRUE on success, FALSE on failure
*/
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
    LPWSTR finalDbgHelpPath = NULL;
    WCHAR szDbgHelpPath[MAX_PATH * 2];

    if (!lpSystemPath || !lpTempPath) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    //
    // Validate symbols path input length.
    //
    if (_strlen(lpSystemPath) > MAX_PATH || _strlen(lpTempPath) > MAX_PATH) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (lpSymbolPath && _strlen(lpSymbolPath) >= RTL_NUMBER_OF(g_SymGlobals.szSymbolsPath)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    RtlSecureZeroMemory(&g_SymGlobals, sizeof(g_SymGlobals));

    //
    // Prepare path and load dbghelp library.
    //
    if (lpDbgHelpPath) {
        finalDbgHelpPath = (LPWSTR)lpDbgHelpPath;
    }
    else {
        // Construct path from system dir
        RtlSecureZeroMemory(szDbgHelpPath, sizeof(szDbgHelpPath));
        _strncpy(szDbgHelpPath, MAX_PATH, lpSystemPath, _strlen(lpSystemPath));
        supPathAddBackSlash(szDbgHelpPath);
        _strcat(szDbgHelpPath, DEFAULT_DLL);
        finalDbgHelpPath = szDbgHelpPath;
    }

    hDbg = LoadLibraryEx(finalDbgHelpPath, NULL, 0);
    if (hDbg == NULL)
        return FALSE;

    g_SymGlobals.DllHandle = hDbg;

    //
    // Init dbghelp pointers and allocate context.
    //
    if (SympInitPointers(hDbg, &g_SymGlobals.ApiSet)) {

        g_SymGlobals.ProcessHandle = (ProcessHandle == NULL) ?
            NtCurrentProcess() : ProcessHandle;

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

/**
* Free global symbol parser resources
*
* @return TRUE on success, FALSE on failure
*/
BOOL SymGlobalsFree()
{
    BOOL bResult = FALSE;

    if (!g_SymGlobals.Initialized)
        return FALSE;

    if (g_SymGlobals.ApiSet.SymCleanup) {
        g_SymGlobals.ApiSet.SymCleanup(g_SymGlobals.ProcessHandle);

        if (g_SymGlobals.DllHandle) {
            bResult = FreeLibrary(g_SymGlobals.DllHandle);
            g_SymGlobals.DllHandle = NULL;
        }
    }

    g_SymGlobals.Initialized = FALSE;
    return bResult;
}
