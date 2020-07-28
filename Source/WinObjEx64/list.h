/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       LIST.H
*
*  VERSION:     1.87
*
*  DATE:        30 June 2020
*
*  Common header file main program logic.
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
    LPWSTR	ObjectName;
    LPWSTR	ObjectType;
    WCHAR	NameBuffer[2];
} FO_LIST_ITEM, *PFO_LIST_ITEM;

VOID ListToObject(
    _In_ LPWSTR ObjectName);

VOID ListObjectDirectoryTree(
    _In_ LPWSTR SubDirName,
    _In_opt_ HANDLE RootHandle,
    _In_opt_ HTREEITEM ViewRootHandle);

VOID FindObject(
    _In_ LPWSTR DirName,
    _In_opt_ LPWSTR NameSubstring,
    _In_opt_ LPWSTR TypeName,
    _In_ PFO_LIST_ITEM *List);

VOID ListObjectsInDirectory(
    _In_ LPWSTR lpObjectDirectory);
