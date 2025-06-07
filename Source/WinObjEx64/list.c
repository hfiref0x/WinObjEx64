/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2025
*
*  TITLE:       LIST.C
*
*  VERSION:     2.08
*
*  DATE:        07 Jun 2025
* 
*  Program main object listing and search logic.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

HANDLE ListObjectsHeap = NULL;
HANDLE TreeObjectsHeap = NULL;

BOOLEAN ListHeapCreate(
    _Inout_ PHANDLE HeapHandle
)
{
    HANDLE handle;

    if (*HeapHandle)
        supDestroyHeap(*HeapHandle);

    handle = supCreateHeap(HEAP_GROWABLE, TRUE);
    *HeapHandle = handle;

    return (handle != NULL);
}

VOID ListHeapDestroy(
    VOID
)
{
    if (ListObjectsHeap) {
        supDestroyHeap(ListObjectsHeap);
        ListObjectsHeap = NULL;
    }

    if (TreeObjectsHeap) {
        supDestroyHeap(TreeObjectsHeap);
        TreeObjectsHeap = NULL;
    }
}

POBEX_ITEM AllocateObjectItem(
    _In_ HANDLE HeapHandle,
    _In_ WOBJ_OBJECT_TYPE TypeIndex,
    _In_ PUNICODE_STRING Name,
    _In_ PUNICODE_STRING TypeName,
    _In_opt_ OBEX_ITEM* Parent
)
{
    POBEX_ITEM item;

    item = (OBEX_ITEM*)supHeapAllocEx(HeapHandle, sizeof(OBEX_ITEM));
    if (item == NULL) {
        return NULL;
    }
    
    item->Prev = Parent;
    item->TypeIndex = TypeIndex;

    if (!supDuplicateUnicodeString(HeapHandle, &item->Name, Name)) {
        supHeapFreeEx(HeapHandle, item);
        return NULL;
    }

    if (!supDuplicateUnicodeString(HeapHandle, &item->TypeName, TypeName)) {
        supFreeDuplicatedUnicodeString(HeapHandle, &item->Name, FALSE);
        supHeapFreeEx(HeapHandle, item);
        return NULL;
    }

    return item;
}

/*
* GetNextSub
*
* Purpose:
*
* Returns next subitem in object full pathname.
*
*/
LPWSTR GetNextSub(
    _In_ LPWSTR ObjectFullPathName,
    _In_ LPWSTR Sub
)
{
    SIZE_T i;

    for (i = 0; (*ObjectFullPathName != 0) && (*ObjectFullPathName != L'\\')
        && (i < MAX_PATH); i++, ObjectFullPathName++)
    {
        Sub[i] = *ObjectFullPathName;
    }
    Sub[i] = 0;

    if (*ObjectFullPathName == L'\\')
        ObjectFullPathName++;

    return ObjectFullPathName;
}

/*
* ListToObject
*
* Purpose:
*
* Select and focus list view item by given object name.
*
*/
VOID ListToObject(
    _In_ LPWSTR ObjectName
)
{
    BOOL        currentfound = FALSE;
    INT         i, iSelectedItem;
    HTREEITEM   lastfound, item;
    LVITEM      lvitem;
    TVITEMEX    ritem;
    WCHAR       object[MAX_PATH + 1], sobject[MAX_PATH + 1];

    if (ObjectName == NULL)
        return;

    if (*ObjectName != L'\\')
        return;

    object[0] = 0;
    ObjectName++;
    item = TreeView_GetRoot(g_hwndObjectTree);
    lastfound = item;

    while ((item != NULL) && (*ObjectName != 0)) {

        item = TreeView_GetChild(g_hwndObjectTree, item);
        RtlSecureZeroMemory(object, sizeof(object));
        ObjectName = GetNextSub(ObjectName, object);
        currentfound = FALSE;

        do {
            RtlSecureZeroMemory(&ritem, sizeof(ritem));
            RtlSecureZeroMemory(&sobject, sizeof(sobject));
            ritem.mask = TVIF_TEXT;
            ritem.hItem = item;
            ritem.cchTextMax = MAX_PATH;
            ritem.pszText = sobject;

            if (!TreeView_GetItem(g_hwndObjectTree, &ritem))
                break;

            if (_strcmpi(sobject, object) == 0) {
                if (item)
                    lastfound = item;
                break;
            }

            item = TreeView_GetNextSibling(g_hwndObjectTree, item);
        } while (item != NULL);
    }

    TreeView_SelectItem(g_hwndObjectTree, lastfound);

    if (currentfound) // final target was a subdir
        return;

    for (i = 0; i < MAXINT; i++) {

        RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
        RtlSecureZeroMemory(&sobject, sizeof(sobject));
        lvitem.mask = LVIF_TEXT;
        lvitem.iItem = i;
        lvitem.cchTextMax = MAX_PATH;
        lvitem.pszText = sobject;
        if (!ListView_GetItem(g_hwndObjectList, &lvitem))
            break;

        if (_strcmpi(sobject, object) == 0) {

            iSelectedItem = ListView_GetSelectionMark(g_hwndObjectList);
            lvitem.mask = LVIF_STATE;
            lvitem.stateMask = LVIS_SELECTED | LVIS_FOCUSED;

            if (iSelectedItem >= 0) {
                lvitem.iItem = iSelectedItem;
                lvitem.state = 0;
                ListView_SetItem(g_hwndObjectList, &lvitem);
            }

            lvitem.iItem = i;
            lvitem.state = LVIS_SELECTED | LVIS_FOCUSED;
            ListView_SetItem(g_hwndObjectList, &lvitem);
            ListView_EnsureVisible(g_hwndObjectList, i, FALSE);
            ListView_SetSelectionMark(g_hwndObjectList, i);
            SetFocus(g_hwndObjectList);
            return;
        }
    }
}

/*
* AddTreeViewItem
*
* Purpose:
*
* Add item to the tree view.
*
*/
HTREEITEM AddTreeViewItem(
    _In_ HANDLE HeapHandle,
    _In_ PUNICODE_STRING ItemName,
    _In_opt_ HTREEITEM Root,
    _Inout_opt_ OBEX_ITEM** Parent
)
{
    BOOL bNeedFree = FALSE;
    HTREEITEM result;
    TVINSERTSTRUCT treeItem;
    OBEX_ITEM* objectRef;
    UNICODE_STRING objectName;

    bNeedFree = supNormalizeUnicodeStringForDisplay(g_obexHeap,
        ItemName,
        &objectName);

    if (!bNeedFree)
        objectName = *ItemName;

    RtlSecureZeroMemory(&treeItem, sizeof(treeItem));
    treeItem.hParent = Root;
    treeItem.item.mask = TVIF_TEXT | TVIF_SELECTEDIMAGE | TVIF_PARAM;
    if (Root == NULL) {
        treeItem.item.mask |= TVIF_STATE;
        treeItem.item.state = TVIS_EXPANDED;
        treeItem.item.stateMask = TVIS_EXPANDED;
    }

    treeItem.item.iSelectedImage = 1;

    treeItem.item.pszText = objectName.Buffer;

    objectRef = AllocateObjectItem(HeapHandle,
        ObjectTypeDirectory,
        ItemName,
        ObGetPredefinedUnicodeString(OBP_DIRECTORY),
        (Parent == NULL) ? NULL : *Parent);

    if (Parent) *Parent = objectRef;

    treeItem.item.lParam = (LPARAM)objectRef;

    result = TreeView_InsertItem(g_hwndObjectTree, &treeItem);
    if (result == NULL) {
        // Failed to insert item, clean up the allocated object
        supFreeDuplicatedUnicodeString(HeapHandle, &objectRef->Name, FALSE);
        supFreeDuplicatedUnicodeString(HeapHandle, &objectRef->TypeName, FALSE);
        supHeapFreeEx(HeapHandle, objectRef);
        if (Parent) *Parent = NULL;
    }

    if (bNeedFree)
        supFreeUnicodeString(g_obexHeap, &objectName);
    
    return result;
}

/*
* xxxListObjectDirectoryTree
*
* Purpose:
*
* List given directory to the treeview.
*
*/
VOID xxxListObjectDirectoryTree(
    _In_ HANDLE HeapHandle,
    _In_ PUNICODE_STRING SubDirName,
    _In_opt_ HANDLE RootHandle,
    _In_opt_ HTREEITEM ViewRootHandle,
    _In_opt_ OBEX_ITEM* Parent
)
{
    ULONG queryContext = 0, rLength;
    NTSTATUS ntStatus;
    HANDLE directoryHandle = NULL;
    OBEX_ITEM* prevItem = Parent;

    POBJECT_DIRECTORY_INFORMATION directoryEntry;

    ViewRootHandle = AddTreeViewItem(HeapHandle, SubDirName, ViewRootHandle, &prevItem);
    if (ViewRootHandle == NULL)
        return;

    supOpenDirectoryEx(&directoryHandle, RootHandle, SubDirName, DIRECTORY_QUERY);
    if (directoryHandle == NULL) {
        return;
    }
    __try {
        do {

            //
            // Wine implementation of NtQueryDirectoryObject interface is very basic and incomplete.
            // It doesn't work if no input buffer specified and does not return required buffer size.
            //
            if (g_WinObj.IsWine) {
                rLength = 1024 * 64;
            }
            else {

                //
                // Request required buffer length.
                //
                rLength = 0;
                ntStatus = NtQueryDirectoryObject(directoryHandle,
                    NULL,
                    0,
                    TRUE,
                    FALSE,
                    &queryContext,
                    &rLength);

                if (ntStatus != STATUS_BUFFER_TOO_SMALL)
                    break;
            }

            directoryEntry = (POBJECT_DIRECTORY_INFORMATION)supHeapAlloc((SIZE_T)rLength);
            if (directoryEntry == NULL)
                break;

            ntStatus = NtQueryDirectoryObject(directoryHandle,
                directoryEntry,
                rLength,
                TRUE,
                FALSE,
                &queryContext,
                &rLength);

            if (!NT_SUCCESS(ntStatus)) {
                supHeapFree(directoryEntry);
                break;
            }

            if (RtlEqualUnicodeString(
                &directoryEntry->TypeName,
                ObGetPredefinedUnicodeString(OBP_DIRECTORY),
                TRUE))
            {
                xxxListObjectDirectoryTree(HeapHandle,
                    &directoryEntry->Name,
                    directoryHandle,
                    ViewRootHandle,
                    prevItem);
            }

            supHeapFree(directoryEntry);

        } while (TRUE);
    }
    __finally {
        NtClose(directoryHandle);
    }
}

/*
* ListObjectDirectoryTree
*
* Purpose:
*
* List given directory to the treeview.
*
*/
VOID ListObjectDirectoryTree(
    _In_ PUNICODE_STRING SubDirName,
    _In_opt_ HANDLE RootHandle,
    _In_opt_ HTREEITEM ViewRootHandle
)
{
    ListHeapCreate(&TreeObjectsHeap);
    if (TreeObjectsHeap)
        xxxListObjectDirectoryTree(TreeObjectsHeap, SubDirName, RootHandle, ViewRootHandle, NULL);
}

/*
* AddListViewItem
*
* Purpose:
*
* Add item to the object listview.
*
*/
VOID AddListViewItem(
    _In_ HANDLE HeapHandle,
    _In_ HANDLE RootDirectoryHandle,
    _In_ POBJECT_DIRECTORY_INFORMATION Entry,
    _In_ OBEX_ITEM* Parent
)
{
    BOOL bFound = FALSE, bNameAllocated;
    INT lvItemIndex;
    PWSTR objectTypeName;
    LVITEM lvItem;
    WCHAR szBuffer[MAX_PATH + 1];

    WOBJ_TYPE_DESC* typeDesc;
    OBEX_ITEM* objRef;
    UNICODE_STRING objectName, normalizedLinkTarget;

    objectTypeName = Entry->TypeName.Buffer;
    typeDesc = ObManagerGetEntryByTypeName(objectTypeName);

    bNameAllocated = supNormalizeUnicodeStringForDisplay(g_obexHeap,
        &Entry->Name,
        &objectName);

    if (!bNameAllocated)
        objectName = Entry->Name;

    //
    // Object name column.
    //
    RtlSecureZeroMemory(&lvItem, sizeof(lvItem));
    lvItem.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
    lvItem.pszText = objectName.Buffer;
    lvItem.iItem = MAXINT;
    lvItem.iImage = typeDesc->ImageIndex;

    objRef = AllocateObjectItem(HeapHandle,
        typeDesc->Index,
        &Entry->Name,
        &Entry->TypeName,
        Parent);

    lvItem.lParam = (LPARAM)objRef;
    lvItemIndex = ListView_InsertItem(g_hwndObjectList, &lvItem);

    //
    // Object type column.
    //
    lvItem.mask = LVIF_TEXT;
    lvItem.iSubItem = 1;
    lvItem.pszText = objectTypeName;
    lvItem.iItem = lvItemIndex;
    ListView_SetItem(g_hwndObjectList, &lvItem);

    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));

    //
    // Special case for symbolic links as their link targets must be normalized before output.
    // Do not bFound to TRUE so we will fall through the end of routine.
    //
    if (typeDesc->NameHash == OBTYPE_HASH_SYMBOLIC_LINK) {

        if (supResolveSymbolicLinkTargetNormalized(
            NULL,
            RootDirectoryHandle,
            &Entry->Name,
            &normalizedLinkTarget))
        {
            lvItem.mask = LVIF_TEXT;
            lvItem.iSubItem = 2;
            lvItem.pszText = normalizedLinkTarget.Buffer;
            lvItem.iItem = lvItemIndex;
            ListView_SetItem(g_hwndObjectList, &lvItem);
            supFreeDuplicatedUnicodeString(g_obexHeap, &normalizedLinkTarget, FALSE);
        }

    }
    else {

        //
        // Look for object type in well known type names hashes.
        // If found - query information for additional description field.
        //

        switch (typeDesc->NameHash) {

        case OBTYPE_HASH_SECTION:

            bFound = supQuerySectionFileInfo(RootDirectoryHandle,
                &Entry->Name,
                szBuffer,
                MAX_PATH);

            break;

        case OBTYPE_HASH_DRIVER:

            bFound = supQueryDriverDescription(objectName.Buffer,
                szBuffer,
                MAX_PATH);

            break;

        case OBTYPE_HASH_DEVICE:

            bFound = supQueryDeviceDescription(NULL, 
                &Entry->Name,
                szBuffer,
                MAX_PATH);

            break;

        case OBTYPE_HASH_WINSTATION:

            bFound = supQueryWinstationDescription(objectName.Buffer,
                szBuffer,
                MAX_PATH);

            break;

        case OBTYPE_HASH_TYPE:

            bFound = supQueryTypeInfo(&Entry->Name,
                szBuffer,
                MAX_PATH);

            break;
        }
    }

    //
    // Finally add information column if something found.
    //
    if (bFound != FALSE) {
        lvItem.mask = LVIF_TEXT;
        lvItem.iSubItem = 2;
        lvItem.pszText = szBuffer;
        lvItem.iItem = lvItemIndex;
        ListView_SetItem(g_hwndObjectList, &lvItem);
    }

    if (bNameAllocated)
        supFreeUnicodeString(g_obexHeap, &objectName);
}

/*
* xxxListCurrentDirectoryObjects
*
* Purpose:
*
* List directory objects to the listview.
*
*/
VOID xxxListCurrentDirectoryObjects(
    _In_ HANDLE HeapHandle,
    _In_ OBEX_ITEM* Parent
)
{
    NTSTATUS ntStatus;
    ULONG queryContext = 0, rLength;
    HANDLE directoryHandle = NULL;
    UNICODE_STRING usDirectoryName;

    POBJECT_DIRECTORY_INFORMATION infoBuffer;

    ListView_DeleteAllItems(g_hwndObjectList);

    if (supGetCurrentObjectPath(TRUE, &usDirectoryName)) {
        supOpenDirectoryEx(&directoryHandle, NULL, &usDirectoryName, DIRECTORY_QUERY);
        supFreeDuplicatedUnicodeString(g_obexHeap, &usDirectoryName, FALSE);
    }

    if (directoryHandle == NULL)
        return;

    supListViewEnableRedraw(g_hwndObjectList, FALSE);

    do {

        //
        // Wine implementation of NtQueryDirectoryObject interface is very basic and incomplete.
        // It doesn't work if no input buffer specified and does not return required buffer size.
        //
        if (g_WinObj.IsWine) {
            rLength = 1024 * 64;
        }
        else {

            rLength = 0;

            ntStatus = NtQueryDirectoryObject(
                directoryHandle,
                NULL,
                0,
                TRUE,
                FALSE,
                &queryContext,
                &rLength);

            if (ntStatus != STATUS_BUFFER_TOO_SMALL)
                break;
        }

        infoBuffer = (POBJECT_DIRECTORY_INFORMATION)supHeapAlloc((SIZE_T)rLength);
        if (infoBuffer) {

            ntStatus = NtQueryDirectoryObject(
                directoryHandle,
                infoBuffer,
                rLength,
                TRUE,
                FALSE,
                &queryContext,
                &rLength);

            if (NT_SUCCESS(ntStatus)) {
                AddListViewItem(HeapHandle, directoryHandle, infoBuffer, Parent);
            }
            else {
                supHeapFree(infoBuffer);
                break;
            }

            supHeapFree(infoBuffer);

        }
        else {
            break;
        }

    } while (TRUE);

    supListViewEnableRedraw(g_hwndObjectList, TRUE);

    NtClose(directoryHandle);
}


/*
* ListCurrentDirectoryObjects
*
* Purpose:
*
* List directory objects to the listview.
*
*/
VOID ListCurrentDirectoryObjects(
    _In_ HTREEITEM ViewRootHandle
)
{
    OBEX_ITEM* objRef = NULL;

    ListHeapCreate(&ListObjectsHeap);
    if (ListObjectsHeap) {

        if (supGetTreeViewItemParam(g_hwndObjectTree,
            ViewRootHandle,
            (PVOID*)&objRef))
        {
            xxxListCurrentDirectoryObjects(ListObjectsHeap, objRef);
        }

    }
}

PFO_LIST_ITEM AllocateFoundItem(
    _In_ PFO_LIST_ITEM Previous,
    _In_ PUNICODE_STRING DirectoryName,
    _In_ POBJECT_DIRECTORY_INFORMATION InfoBuffer
)
{
    PFO_LIST_ITEM Item;
    SIZE_T BufferLength, TypeNameOffset;
    PWCH String, StringBuffer;

    BufferLength = sizeof(FO_LIST_ITEM) +
        InfoBuffer->Name.Length +
        InfoBuffer->TypeName.Length +
        DirectoryName->Length +
        OBJ_NAME_PATH_SEPARATOR_SIZE +
        2 * sizeof(UNICODE_NULL);

    Item = (PFO_LIST_ITEM)supHeapAlloc(BufferLength);
    if (Item == NULL) {
        return NULL;
    }

    Item->Prev = Previous;
    Item->ObjectName.Buffer = (PWSTR)Item->NameBuffer;

    TypeNameOffset = (SIZE_T)DirectoryName->Length +
        (SIZE_T)InfoBuffer->Name.Length +
        OBJ_NAME_PATH_SEPARATOR_SIZE +
        sizeof(UNICODE_NULL);

    //
    // Copy ObjectName.
    //
    Item->ObjectType.Buffer = (PWSTR)RtlOffsetToPointer(Item->NameBuffer, TypeNameOffset);
    StringBuffer = Item->ObjectName.Buffer;
    String = StringBuffer;

    RtlCopyMemory(String, DirectoryName->Buffer, DirectoryName->Length);
    String = (PWCH)RtlOffsetToPointer(Item->ObjectName.Buffer, DirectoryName->Length);

    //
    // Add separator if not root.
    //
    if (!supIsRootDirectory(DirectoryName))
        *String++ = OBJ_NAME_PATH_SEPARATOR;

    RtlCopyMemory(String, InfoBuffer->Name.Buffer, InfoBuffer->Name.Length);
    String = (PWCH)RtlOffsetToPointer(String, InfoBuffer->Name.Length);
    *String++ = UNICODE_NULL;

    //
    // Set new Length/MaximumLength to ObjectName.
    //
    BufferLength = (USHORT)((ULONG_PTR)String - (ULONG_PTR)StringBuffer);
    Item->ObjectName.Length = (USHORT)BufferLength - sizeof(WCHAR);
    Item->ObjectName.MaximumLength = (USHORT)BufferLength;

    //
    // Copy ObjectType.
    //
    StringBuffer = Item->ObjectType.Buffer;
    String = StringBuffer;

    RtlCopyMemory(String, InfoBuffer->TypeName.Buffer, InfoBuffer->TypeName.Length);
    String = (PWCH)RtlOffsetToPointer(String, InfoBuffer->TypeName.Length);
    *String++ = UNICODE_NULL;

    //
    // Set new Length/MaximumLength to ObjectType.
    //
    BufferLength = (USHORT)((ULONG_PTR)String - (ULONG_PTR)StringBuffer);
    Item->ObjectType.Length = (USHORT)BufferLength - sizeof(WCHAR);
    Item->ObjectType.MaximumLength = (USHORT)BufferLength;

    return Item;
}

/*
* FindObject
*
* Purpose:
*
* Find object by given name in object directory.
*
*/
VOID FindObject(
    _In_ PUNICODE_STRING DirectoryName,
    _In_opt_ PUNICODE_STRING NameSubstring,
    _In_opt_ PUNICODE_STRING TypeName,
    _In_ PFO_LIST_ITEM* List
)
{
    NTSTATUS status;
    ULONG ctx, rlen;
    HANDLE directoryHandle = NULL;

    PFO_LIST_ITEM Item;
    SIZE_T NameSize, BufferLength;
    PWCH ObjectName, String;
    UNICODE_STRING SubDirectory;

    POBJECT_DIRECTORY_INFORMATION InfoBuffer;

    supOpenDirectoryEx(&directoryHandle, NULL, DirectoryName, DIRECTORY_QUERY);
    if (directoryHandle == NULL)
        return;

    ctx = 0;
    do {
        //
        // Wine implementation of NtQueryDirectoryObject interface is very basic and incomplete.
        // It doesn't work if no input buffer specified and does not return required buffer size.
        //
        if (g_WinObj.IsWine != FALSE) {
            rlen = 1024 * 64;
        }
        else {
            rlen = 0;
            status = NtQueryDirectoryObject(directoryHandle, NULL, 0, TRUE, FALSE, &ctx, &rlen);
            if (status != STATUS_BUFFER_TOO_SMALL)
                break;
        }

        InfoBuffer = (POBJECT_DIRECTORY_INFORMATION)supHeapAlloc((SIZE_T)rlen);
        if (InfoBuffer == NULL)
            break;

        status = NtQueryDirectoryObject(directoryHandle, InfoBuffer, rlen, TRUE, FALSE, &ctx, &rlen);
        if (!NT_SUCCESS(status)) {
            supHeapFree(InfoBuffer);
            break;
        }

        if (TypeName) {

            if (RtlEqualUnicodeString(&InfoBuffer->TypeName, TypeName, TRUE)) {

                if (NameSubstring) {

                    if (ULLONG_MAX != supFindUnicodeStringSubString(&InfoBuffer->Name, NameSubstring)) {
                        Item = AllocateFoundItem(*List, DirectoryName, InfoBuffer);
                        if (Item == NULL)
                            break;

                        *List = Item;
                    }
                }
                else {
                    Item = AllocateFoundItem(*List, DirectoryName, InfoBuffer);
                    if (Item == NULL)
                        break;

                    *List = Item;
                }

            }

        }
        else { 
            if (NameSubstring) {
                if (ULLONG_MAX != supFindUnicodeStringSubString(&InfoBuffer->Name, NameSubstring)) {
                    Item = AllocateFoundItem(*List, DirectoryName, InfoBuffer);
                    if (Item == NULL)
                        break;

                    *List = Item;
                }
            }
            else {
                Item = AllocateFoundItem(*List, DirectoryName, InfoBuffer);
                if (Item == NULL)
                    break;

                *List = Item;
            }
        }

        //
        // If this is directory, go inside.
        //
        if (RtlEqualUnicodeString(&InfoBuffer->TypeName,
            ObGetPredefinedUnicodeString(OBP_DIRECTORY),
            TRUE))
        {
            NameSize = (SIZE_T)InfoBuffer->Name.Length +
                (SIZE_T)DirectoryName->Length +
                OBJ_NAME_PATH_SEPARATOR_SIZE +
                sizeof(UNICODE_NULL);

            ObjectName = (PWCH)supHeapAlloc(NameSize);
            if (ObjectName != NULL) {

                String = ObjectName;

                RtlCopyMemory(String, DirectoryName->Buffer, DirectoryName->Length);
                String = (PWCH)RtlOffsetToPointer(String, DirectoryName->Length);

                if (!supIsRootDirectory(DirectoryName))
                    *String++ = OBJ_NAME_PATH_SEPARATOR;

                RtlCopyMemory(String, InfoBuffer->Name.Buffer, InfoBuffer->Name.Length);
                String = (PWCH)RtlOffsetToPointer(String, InfoBuffer->Name.Length);
                *String++ = UNICODE_NULL;

                BufferLength = (USHORT)((ULONG_PTR)String - (ULONG_PTR)ObjectName);
                SubDirectory.Length = (USHORT)BufferLength - sizeof(WCHAR);
                SubDirectory.MaximumLength = (USHORT)BufferLength;
                SubDirectory.Buffer = ObjectName;

                FindObject(&SubDirectory, NameSubstring, TypeName, List);

                supHeapFree(ObjectName);
            }
        }

        supHeapFree(InfoBuffer);

    } while (TRUE);

    NtClose(directoryHandle);
}
