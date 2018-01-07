/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       LIST.H
*
*  VERSION:     1.52
*
*  DATE:        08 Jan 2018
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
    _In_ LPWSTR ObjectName
);

VOID ListObjectDirectoryTree(
    _In_ LPWSTR SubDirName,
    _In_opt_ HANDLE RootHandle,
    _In_opt_ HTREEITEM ViewRootHandle
);

VOID AddListViewItem(
    _In_ HANDLE hObjectRootDirectory,
    _In_ POBJECT_DIRECTORY_INFORMATION objinf
);

VOID FindObject(
    _In_ LPWSTR DirName,
    _In_opt_ LPWSTR NameSubstring,
    _In_opt_ LPWSTR TypeName,
    _In_ PFO_LIST_ITEM *List
);

VOID ListObjectsInDirectory(
    _In_ LPWSTR lpObjectDirectory
);

VOID FORCEINLINE InitializeListHead(
    _In_ PLIST_ENTRY ListHead
)
{
    ListHead->Flink = ListHead->Blink = ListHead;
}

#define IsListEmpty(ListHead) \
    ((ListHead)->Flink == (ListHead))

BOOLEAN FORCEINLINE RemoveEntryList(
    _In_ PLIST_ENTRY Entry
)
{
    PLIST_ENTRY Blink;
    PLIST_ENTRY Flink;

    Flink = Entry->Flink;
    Blink = Entry->Blink;
    Blink->Flink = Flink;
    Flink->Blink = Blink;
    return (BOOLEAN)(Flink == Blink);
}

PLIST_ENTRY FORCEINLINE RemoveHeadList(
    _Inout_ PLIST_ENTRY ListHead
)
{
    PLIST_ENTRY Flink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Flink;
    Flink = Entry->Flink;
    ListHead->Flink = Flink;
    Flink->Blink = ListHead;
    return Entry;
}

VOID FORCEINLINE InsertHeadList(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ PLIST_ENTRY Entry
)
{
    PLIST_ENTRY Flink;

    Flink = ListHead->Flink;
    Entry->Flink = Flink;
    Entry->Blink = ListHead;
    Flink->Blink = Entry;
    ListHead->Flink = Entry;
}
