/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2025
*
*  TITLE:       LIST.H
*
*  VERSION:     2.09
*
*  DATE:        19 Aug 2025
*
*  Common header file for the program object listing logic.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef	struct _FO_LIST_ITEM {
    struct _FO_LIST_ITEM *Prev;
    UNICODE_STRING ObjectName;
    UNICODE_STRING ObjectType;
    WCHAR NameBuffer[2];
} FO_LIST_ITEM, *PFO_LIST_ITEM;

typedef struct _OBEX_ITEM {
    struct _OBEX_ITEM *Prev;
    WOBJ_OBJECT_TYPE TypeIndex;
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBEX_ITEM, * POBEX_ITEM;

typedef struct _OBEX_PATH_ELEMENT {
    LIST_ENTRY ListEntry;
    WOBJ_OBJECT_TYPE TypeIndex;
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBEX_PATH_ELEMENT, * POBEX_PATH_ELEMENT;

VOID ListHeapDestroy(
    VOID);

VOID ListToObject(
    _In_z_ LPWSTR ObjectName);

VOID ListObjectDirectoryTree(
    _In_ PUNICODE_STRING SubDirName,
    _In_opt_ HANDLE RootHandle,
    _In_opt_ HTREEITEM ViewRootHandle);

VOID FindObject(
    _In_ PUNICODE_STRING DirectoryName,
    _In_opt_ PUNICODE_STRING NameSubstring,
    _In_opt_ PUNICODE_STRING TypeName,
    _In_ PFO_LIST_ITEM *List);

VOID ListCurrentDirectoryObjects(
    _In_ HTREEITEM ViewRootHandle);
