/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2025
*
*  TITLE:       LIST.C
*
*  VERSION:     2.08
*
*  DATE:        12 Jun 2025
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

/*
* AllocateObjectItem
*
* Purpose:
*
* Create an OBEX_ITEM.
*
*/
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
        if (objectRef != NULL) {
            supFreeDuplicatedUnicodeString(HeapHandle, &objectRef->Name, FALSE);
            supFreeDuplicatedUnicodeString(HeapHandle, &objectRef->TypeName, FALSE);
            supHeapFreeEx(HeapHandle, objectRef);
        }
        if (Parent) *Parent = NULL;
    }

    if (bNeedFree)
        supFreeUnicodeString(g_obexHeap, &objectName);

    return result;
}

/*
* AppendDirectoryPath
*
* Purpose:
*
* Helper function to construct full object path.
*
*/
BOOLEAN AppendDirectoryPath(
    _In_ PUNICODE_STRING DirectoryName,
    _In_ PUNICODE_STRING ObjectName,
    _Out_ PUNICODE_STRING FullPath
)
{
    SIZE_T pathLength, allocSize;
    PWCH target, source;

    // Calculate required buffer size
    pathLength = DirectoryName->Length;
    if (!supIsRootDirectory(DirectoryName))
        pathLength += OBJ_NAME_PATH_SEPARATOR_SIZE;

    pathLength += ObjectName->Length + sizeof(UNICODE_NULL);
    allocSize = pathLength;

    // Allocate buffer
    FullPath->Buffer = (PWSTR)supHeapAlloc(allocSize);
    if (!FullPath->Buffer)
        return FALSE;

    // Copy directory path
    target = FullPath->Buffer;
    source = DirectoryName->Buffer;
    RtlCopyMemory(target, source, DirectoryName->Length);
    target = (PWCH)RtlOffsetToPointer(target, DirectoryName->Length);

    // Add separator if not root
    if (!supIsRootDirectory(DirectoryName))
        *target++ = OBJ_NAME_PATH_SEPARATOR;

    // Copy object name
    RtlCopyMemory(target, ObjectName->Buffer, ObjectName->Length);
    target = (PWCH)RtlOffsetToPointer(target, ObjectName->Length);
    *target = UNICODE_NULL;

    // Set string properties
    FullPath->Length = (USHORT)(pathLength - sizeof(UNICODE_NULL));
    FullPath->MaximumLength = (USHORT)allocSize;

    return TRUE;
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

    // Suspend tree redraw for batch operations
    supDisableRedraw(g_hwndObjectTree);

    __try {
        do {
            directoryEntry = ObQueryObjectDirectory(directoryHandle, &queryContext, g_WinObj.IsWine, &rLength);
            if (directoryEntry == NULL)
                break;

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
        supEnableRedraw(g_hwndObjectTree);
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

    // Special case for symbolic links as their link targets must be normalized before output.
    // Do not set bFound to TRUE so we will fall through the end of routine.
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
        // Look for object type in well known type names hashes.
        // If found - query information for additional description field.
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

    // Finally add information column if something found.
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

    supDisableRedraw(g_hwndObjectList);

    do {
        infoBuffer = ObQueryObjectDirectory(directoryHandle, &queryContext, g_WinObj.IsWine, &rLength);
        if (infoBuffer) {
            AddListViewItem(HeapHandle, directoryHandle, infoBuffer, Parent);
            supHeapFree(infoBuffer);
        }
        else {
            break;
        }
    } while (TRUE);

    supEnableRedraw(g_hwndObjectList);

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

/*
* AllocateFoundItem
*
* Purpose:
*
* Allocate item for search dialog results.
*
*/
PFO_LIST_ITEM AllocateFoundItem(
    _In_ PFO_LIST_ITEM Previous,
    _In_ PUNICODE_STRING DirectoryName,
    _In_ POBJECT_DIRECTORY_INFORMATION InfoBuffer
)
{
    PFO_LIST_ITEM Item;
    SIZE_T BufferLength;
    UNICODE_STRING fullPath;

    // Calculate the full objectname path and store it in fullPath
    RtlInitEmptyUnicodeString(&fullPath, NULL, 0);
    if (!AppendDirectoryPath(DirectoryName, &InfoBuffer->Name, &fullPath)) {
        return NULL;
    }

    // Allocate memory for the item structure and string data
    BufferLength = sizeof(FO_LIST_ITEM) +
        fullPath.MaximumLength +
        InfoBuffer->TypeName.Length + sizeof(UNICODE_NULL);

    Item = (PFO_LIST_ITEM)supHeapAlloc(BufferLength);
    if (Item == NULL) {
        supHeapFree(fullPath.Buffer);
        return NULL;
    }

    // Setup the item
    Item->Prev = Previous;

    // Set up the ObjectName
    Item->ObjectName.Buffer = (PWSTR)Item->NameBuffer;
    Item->ObjectName.Length = fullPath.Length;
    Item->ObjectName.MaximumLength = fullPath.MaximumLength;
    RtlCopyMemory(Item->ObjectName.Buffer, fullPath.Buffer, fullPath.Length);
    Item->ObjectName.Buffer[fullPath.Length / sizeof(WCHAR)] = UNICODE_NULL;

    // Set up the ObjectType
    Item->ObjectType.Buffer = (PWSTR)(Item->NameBuffer + (fullPath.MaximumLength / sizeof(WCHAR)));
    Item->ObjectType.Length = InfoBuffer->TypeName.Length;
    Item->ObjectType.MaximumLength = InfoBuffer->TypeName.Length + sizeof(UNICODE_NULL);
    RtlCopyMemory(Item->ObjectType.Buffer, InfoBuffer->TypeName.Buffer, InfoBuffer->TypeName.Length);
    Item->ObjectType.Buffer[InfoBuffer->TypeName.Length / sizeof(WCHAR)] = UNICODE_NULL;

    // Free temporary buffer
    supHeapFree(fullPath.Buffer);

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
    ULONG ctx, rlen;
    HANDLE directoryHandle = NULL;

    PFO_LIST_ITEM item;
    UNICODE_STRING subDirectory;

    POBJECT_DIRECTORY_INFORMATION infoBuffer;

    supOpenDirectoryEx(&directoryHandle, NULL, DirectoryName, DIRECTORY_QUERY);
    if (directoryHandle == NULL)
        return;

    ctx = 0;
    do {
        infoBuffer = ObQueryObjectDirectory(directoryHandle, &ctx, g_WinObj.IsWine, &rlen);
        if (!infoBuffer)
            break;

        if (TypeName) {
            if (RtlEqualUnicodeString(&infoBuffer->TypeName, TypeName, TRUE)) {
                if (NameSubstring) {
                    if (ULLONG_MAX != supFindUnicodeStringSubString(&infoBuffer->Name, NameSubstring)) {
                        item = AllocateFoundItem(*List, DirectoryName, infoBuffer);
                        if (item) *List = item;
                    }
                }
                else {
                    item = AllocateFoundItem(*List, DirectoryName, infoBuffer);
                    if (item) *List = item;
                }
            }
        }
        else if (NameSubstring) {
            // Only name substring specified - check for substring
            if (ULLONG_MAX != supFindUnicodeStringSubString(&infoBuffer->Name, NameSubstring)) {
                item = AllocateFoundItem(*List, DirectoryName, infoBuffer);
                if (item) *List = item;
            }
        }
        else {
            // No filter specified - add all objects
            item = AllocateFoundItem(*List, DirectoryName, infoBuffer);
            if (item) *List = item;
        }

        // If this is directory, go inside.
        RtlInitEmptyUnicodeString(&subDirectory, NULL, 0);
        if (RtlEqualUnicodeString(&infoBuffer->TypeName,
            ObGetPredefinedUnicodeString(OBP_DIRECTORY),
            TRUE))
        {
            if (subDirectory.Buffer) {
                supHeapFree(subDirectory.Buffer);
                subDirectory.Buffer = NULL;
            }

            if (AppendDirectoryPath(DirectoryName, &infoBuffer->Name, &subDirectory)) {
                FindObject(&subDirectory, NameSubstring, TypeName, List);
                supHeapFree(subDirectory.Buffer);
                subDirectory.Buffer = NULL;
            }
        }

        supHeapFree(infoBuffer);

    } while (TRUE);

    NtClose(directoryHandle);
}
