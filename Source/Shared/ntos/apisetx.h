/************************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2024, translated from Microsoft sources/debugger
*
*  TITLE:       APISETX.H
*
*  VERSION:     1.08
*
*  DATE:        16 Sep 2024
*
*  Common header file for the ApiSetSchema definitions.
*
*  Depends on:    ntos.h
*
*  Include:       ntos.h
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
************************************************************************************/

#pragma once

#ifndef APISETX
#define APISETX

//
// Copy-pasted from MS headers from the pre nerfed state.
//

#ifndef API_SET_SECTION_NAME
#define API_SET_SECTION_NAME            ".apiset"
#endif

#ifndef API_SET_SCHEMA_SUFFIX
#define API_SET_SCHEMA_SUFFIX           L".sys"
#endif

#define API_SET_PREFIX_API 0x2d004900500041 
#define API_SET_PREFIX_EXT 0x2d005400580045

#define API_SET_PREFIX_NAME_A           "API-"
#define API_SET_PREFIX_NAME_A_SIZE      (sizeof(API_SET_PREFIX_NAME_A) - sizeof(CHAR))
#define API_SET_PREFIX_NAME_U           TEXT(API_SET_PREFIX_NAME_A)
#define API_SET_PREFIX_NAME_U_SIZE      (sizeof(API_SET_PREFIX_NAME_U) - sizeof(WCHAR))
#define API_SET_PREFIX_NAME_LENGTH      (RTL_NUMBER_OF(API_SET_PREFIX_NAME_U) - 1)

#define API_SET_EXTENSION_NAME_A        "EXT-"
#define API_SET_EXTENSION_NAME_A_SIZE   (sizeof(API_SET_EXTENSION_NAME_A) - sizeof(CHAR))
#define API_SET_EXTENSION_NAME_U        TEXT(API_SET_EXTENSION_NAME_A)
#define API_SET_EXTENSION_NAME_U_SIZE   (sizeof(API_SET_EXTENSION_NAME_U) - sizeof(WCHAR))
#define API_SET_EXTENSION_NAME_LENGTH   (RTL_NUMBER_OF(API_SET_EXTENSION_NAME_U) - 1)

#define API_SET_SCHEMA_FLAGS_SEALED              0x00000001UL
#define API_SET_SCHEMA_FLAGS_HOST_EXTENSION      0x00000002UL

#define API_SET_SCHEMA_ENTRY_FLAGS_SEALED        0x00000001UL
#define API_SET_SCHEMA_ENTRY_FLAGS_EXTENSION     0x00000002UL

#ifndef API_SET_SCHEMA_VERSION_V2
#define API_SET_SCHEMA_VERSION_V2    2
#endif

#ifndef API_SET_SCHEMA_VERSION_V3
#define API_SET_SCHEMA_VERSION_V3    3  //private
#endif

#ifndef API_SET_SCHEMA_VERSION_V4
#define API_SET_SCHEMA_VERSION_V4    4
#endif

#ifndef API_SET_SCHEMA_VERSION_V6
#define API_SET_SCHEMA_VERSION_V6    6
#endif

#define API_SET_EMPTY_NAMESPACE_VALUE(ValueEntry) \
    ((ValueEntry->ValueOffset == 0) && (ValueEntry->ValueLength == 0) && \
    (ValueEntry->NameOffset == 0) && (ValueEntry->NameLength == 0))

#define API_SET_TO_UPPER_PREFIX(x) ((x) & 0xFFFFFFDFFFDFFFDFULL)

//
// Macro for APISET structures.
//
#define API_SET_TO_VALUE_ENTRY(Namespace, Entry, Index) \
    ((API_SET_VALUE_ENTRY_V6 *)RtlOffsetToPointer(Namespace, (Index) * sizeof(API_SET_VALUE_ENTRY_V6) + Entry->DataOffset))

#define API_SET_TO_VALUE_NAME(Namespace, Entry) \
    ((PWCHAR)RtlOffsetToPointer(Namespace, Entry->NameOffset))

#define API_SET_TO_HASH_ENTRY(Namespace, HashIndex) \
   ((API_SET_HASH_ENTRY_V6*)RtlOffsetToPointer(Namespace, Namespace->NamespaceHashesOffset + sizeof(ULONG64) * (HashIndex)))

#define API_SET_TO_NAMESPACE_ENTRY(Namespace, LookupHashEntry) \
   ((PAPI_SET_NAMESPACE_ENTRY_V6)RtlOffsetToPointer(Namespace, LookupHashEntry->NamespaceIndex * sizeof(API_SET_NAMESPACE_ENTRY_V6) + Namespace->NamespaceEntryOffset))

#define API_SET_TO_NAMESPACE_ENTRY_NAME(Namespace, NamespaceEntry) \
   ((PWCHAR)RtlOffsetToPointer(Namespace, NamespaceEntry->NameOffset))

// V2

typedef struct _API_SET_VALUE_ENTRY_V2 {
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_V2, *PAPI_SET_VALUE_ENTRY_V2;

typedef struct _API_SET_VALUE_ARRAY_V2 {
    ULONG Count;
    API_SET_VALUE_ENTRY_V2 Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY_V2, *PAPI_SET_VALUE_ARRAY_V2;

typedef struct _API_SET_NAMESPACE_ENTRY_V2 {
    ULONG NameOffset;
    ULONG NameLength;
    ULONG DataOffset;   // API_SET_VALUE_ARRAY
} API_SET_NAMESPACE_ENTRY_V2, *PAPI_SET_NAMESPACE_ENTRY_V2;

typedef struct _API_SET_NAMESPACE_ARRAY_V2 {
    ULONG Version;
    ULONG Count;
    _Field_size_full_(Count) API_SET_NAMESPACE_ENTRY_V2 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V2, *PAPI_SET_NAMESPACE_ARRAY_V2;

// V4

typedef struct _API_SET_VALUE_ENTRY_V4 {
    ULONG Flags;
    ULONG NameOffset;
    _Field_range_(0, UNICODE_STRING_MAX_BYTES) ULONG NameLength;
    ULONG ValueOffset;
    _Field_range_(0, UNICODE_STRING_MAX_BYTES) ULONG ValueLength;
} API_SET_VALUE_ENTRY_V4, *PAPI_SET_VALUE_ENTRY_V4;

_Struct_size_bytes_(FIELD_OFFSET(API_SET_VALUE_ARRAY_V4, Array) + (sizeof(API_SET_VALUE_ENTRY_V4) * Count))
typedef struct _API_SET_VALUE_ARRAY_V4 {
    ULONG Flags;
    ULONG Count;
    _Field_size_full_(Count) API_SET_VALUE_ENTRY_V4 Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY_V4, *PAPI_SET_VALUE_ARRAY_V4;

typedef struct _API_SET_NAMESPACE_ENTRY_V4 {
    ULONG Flags;
    ULONG NameOffset;
    _Field_range_(0, UNICODE_STRING_MAX_BYTES) ULONG NameLength;
    ULONG AliasOffset;
    _Field_range_(0, UNICODE_STRING_MAX_BYTES) ULONG AliasLength;
    ULONG DataOffset;   // API_SET_VALUE_ARRAY_V4
} API_SET_NAMESPACE_ENTRY_V4, *PAPI_SET_NAMESPACE_ENTRY_V4;

_Struct_size_bytes_(Size)
typedef struct _API_SET_NAMESPACE_ARRAY_V4 {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    _Field_size_full_(Count) API_SET_NAMESPACE_ENTRY_V4 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V4, *PAPI_SET_NAMESPACE_ARRAY_V4;

// V6

typedef struct _API_SET_HASH_ENTRY_V6 {
    ULONG Hash;
    ULONG NamespaceIndex;
} API_SET_HASH_ENTRY_V6, *PAPI_SET_HASH_ENTRY_V6;

typedef struct _API_SET_NAMESPACE_ENTRY_V6 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG HashNameLength; //size of name up to the last hyphen
    ULONG DataOffset;     //API_SET_VALUE_ENTRY_V6
    ULONG Count;          //number of API_SET_VALUE_ENTRY_V6 at DataOffset
} API_SET_NAMESPACE_ENTRY_V6, *PAPI_SET_NAMESPACE_ENTRY_V6;

typedef struct _API_SET_VALUE_ENTRY_V6 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_V6, *PAPI_SET_VALUE_ENTRY_V6;

_Struct_size_bytes_(Size)
typedef struct _API_SET_NAMESPACE_ARRAY_V6 {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG NamespaceEntryOffset;  //API_SET_NAMESPACE_ENTRY_V6
    ULONG NamespaceHashesOffset; //_API_SET_HASH_ENTRY_V6
    ULONG HashMultiplier;
} API_SET_NAMESPACE_ARRAY_V6, *PAPI_SET_NAMESPACE_ARRAY_V6;

typedef struct _API_SET_NAMESPACE {
    union {
        API_SET_NAMESPACE_ARRAY_V2 *v2;
        API_SET_NAMESPACE_ARRAY_V4 *v4;
        API_SET_NAMESPACE_ARRAY_V6 *v6;
    } Namespace;
} API_SET_NAMESPACE, *PAPI_SET_NAMESPACE;

#endif /* APISETX */
