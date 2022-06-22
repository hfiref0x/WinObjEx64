/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       PROPCOMMON.H
*
*  VERSION:     2.00
*
*  DATE:        19 Jun 2022
*
*  Common header file for the property sheet based dialogs.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

typedef enum _PROP_CONTEXT_TYPE {
    propNormal = 0,
    propPrivateNamespace = 1,
    propUnnamed = 2,
    propMax = 3
} PROP_CONTEXT_TYPE;

typedef struct _PROP_NAMESPACE_INFO {
    ULONG Reserved;
    ULONG SizeOfBoundaryDescriptor;
    OBJECT_BOUNDARY_DESCRIPTOR* BoundaryDescriptor;
    ULONG_PTR ObjectAddress;
} PROP_NAMESPACE_INFO, * PPROP_NAMESPACE_INFO;

typedef struct _PROP_UNNAMED_OBJECT_INFO {
    BOOL IsThreadToken;
    ULONG_PTR ObjectAddress;
    CLIENT_ID ClientId;
    SYSTEM_THREAD_INFORMATION ThreadInformation;
    UNICODE_STRING ImageName;
} PROP_UNNAMED_OBJECT_INFO, * PPROP_UNNAMED_OBJECT_INFO;

typedef struct _PROP_OBJECT_INFO {

    PROP_CONTEXT_TYPE ContextType;
    WOBJ_OBJECT_TYPE ObjectTypeIndex;

    //
    // Object specific flags
    //
    DWORD ObjectFlags;
   
    //
    // Unicode strings for object name/path where used.
    //
    UNICODE_STRING NtObjectName;
    UNICODE_STRING NtObjectPath;

    //
    // Context specific data.
    //
    PVOID ExtrasContext;

    //
    // Reference to object type description entry in global array.
    //
    WOBJ_TYPE_DESC* TypeDescription; 
    WOBJ_TYPE_DESC* ShadowTypeDescription; //valid only for types, same as TypeDescription for everything else.

    //
    // Icons assigned during runtime.
    //
    HICON ObjectIcon;
    HICON ObjectTypeIcon;

    OBEX_OBJECT_INFORMATION ObjectInfo; //object dump related structures

    //
    // Private namespace or unnamed object (process/thread/token) information.
    //
    union {
        PROP_NAMESPACE_INFO NamespaceInfo;
        PROP_UNNAMED_OBJECT_INFO UnnamedObjectInfo;
    } u1;

} PROP_OBJECT_INFO, * PPROP_OBJECT_INFO;

typedef struct _PROP_CONFIG {
    PROP_CONTEXT_TYPE ContextType;
    HWND hwndParent;

    WOBJ_OBJECT_TYPE ObjectTypeIndex;

    PUNICODE_STRING NtObjectName;
    PUNICODE_STRING NtObjectPath;

    union {
        PVOID ObjectData;
        union {
            PROP_NAMESPACE_INFO* NamespaceObject;
            PROP_UNNAMED_OBJECT_INFO* UnnamedObject;
        } u1;
    };
} PROP_CONFIG, * PPROP_CONFIG;

//open object method (propOpenCurrentObject)
typedef BOOL(CALLBACK* POPENOBJECTMETHOD)(
    _In_ PROP_OBJECT_INFO* Context,
    _Inout_ PHANDLE	phObject,
    _In_ ACCESS_MASK DesiredAccess
    );

//close object method (propCloseCurrentObject)
typedef VOID(CALLBACK* PCLOSEOBJECTMETHOD)(
    _In_ PROP_OBJECT_INFO* Context,
    _In_ HANDLE hObject
    );
