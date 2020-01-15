/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       LIST.C
*
*  VERSION:     1.83
*
*  DATE:        05 Jan 2020
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

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

    for (i = 0; (*ObjectFullPathName != 0) && (*ObjectFullPathName != '\\')
        && (i < MAX_PATH); i++, ObjectFullPathName++)
    {
        Sub[i] = *ObjectFullPathName;
    }
    Sub[i] = 0;

    if (*ObjectFullPathName == '\\')
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

    if (*ObjectName != '\\')
        return;

    ObjectName++;
    item = TreeView_GetRoot(g_hwndObjectTree);
    lastfound = item;

    while ((item != NULL) && (*ObjectName != 0)) {

        item = TreeView_GetChild(g_hwndObjectTree, item);
        object[0] = 0; //mars workaround
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
    _In_ LPWSTR ItemName,
    _In_opt_ HTREEITEM Root
)
{
    TVINSERTSTRUCT	item;

    RtlSecureZeroMemory(&item, sizeof(item));
    item.hParent = Root;
    item.item.mask = TVIF_TEXT | TVIF_SELECTEDIMAGE;
    if (Root == NULL) {
        item.item.mask |= TVIF_STATE;
        item.item.state = TVIS_EXPANDED;
        item.item.stateMask = TVIS_EXPANDED;
    }
    item.item.iSelectedImage = 1;
    item.item.pszText = ItemName;

    return TreeView_InsertItem(g_hwndObjectTree, &item);
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
    _In_ LPWSTR SubDirName,
    _In_opt_ HANDLE RootHandle,
    _In_opt_ HTREEITEM ViewRootHandle
)
{
    NTSTATUS            ntStatus;
    ULONG               queryContext = 0, rLength;
    HANDLE              directoryHandle = NULL;

    POBJECT_DIRECTORY_INFORMATION directoryEntry;

    ViewRootHandle = AddTreeViewItem(SubDirName, ViewRootHandle);

    directoryHandle = supOpenDirectory(RootHandle, SubDirName, DIRECTORY_QUERY);
    if (directoryHandle == NULL)
        return;

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

        if (0 == _strncmpi(directoryEntry->TypeName.Buffer,
            OBTYPE_NAME_DIRECTORY,
            directoryEntry->TypeName.Length / sizeof(WCHAR)))
        {
            ListObjectDirectoryTree(
                directoryEntry->Name.Buffer,
                directoryHandle,
                ViewRootHandle);
        }

        supHeapFree(directoryEntry);

    } while (TRUE);

    NtClose(directoryHandle);
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
    _In_ HANDLE RootDirectoryHandle,
    _In_ POBJECT_DIRECTORY_INFORMATION DirectoryObjectEntry
)
{
    BOOL    bFound = FALSE;
    INT     lvItemIndex;
    PWSTR   objectTypeName, objectName;
    LVITEM  lvItem;
    WCHAR   szBuffer[MAX_PATH + 1];

    WOBJ_TYPE_DESC* typeDesc;

    if (!DirectoryObjectEntry) return;

    objectTypeName = DirectoryObjectEntry->TypeName.Buffer;
    typeDesc = ObManagerGetEntryByTypeName(objectTypeName);

    objectName = DirectoryObjectEntry->Name.Buffer;

    //
    // Object name column.
    //
    RtlSecureZeroMemory(&lvItem, sizeof(lvItem));
    lvItem.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
    lvItem.pszText = objectName;
    lvItem.iItem = MAXINT;
    lvItem.iImage = typeDesc->ImageIndex;
    lvItem.lParam = typeDesc->Index;
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
    // Look for object type in well known type names hashes.
    // If found - query information for additional description field.
    //

    switch (typeDesc->NameHash) {
    
    case OBTYPE_HASH_SYMBOLIC_LINK:
        
        bFound = supQueryLinkTarget(RootDirectoryHandle,
            &DirectoryObjectEntry->Name,
            szBuffer,
            MAX_PATH * sizeof(WCHAR));

        break;

    case OBTYPE_HASH_SECTION:
        
        bFound = supQuerySectionFileInfo(RootDirectoryHandle,
            &DirectoryObjectEntry->Name,
            szBuffer,
            MAX_PATH);

        break;

    case OBTYPE_HASH_DRIVER:

        bFound = supQueryDriverDescription(objectName,
            szBuffer,
            MAX_PATH);

        break;

    case OBTYPE_HASH_DEVICE:

        bFound = supQueryDeviceDescription(objectName,
            szBuffer,
            MAX_PATH);

        break;

    case OBTYPE_HASH_WINSTATION:

        bFound = supQueryWinstationDescription(objectName,
            szBuffer,
            MAX_PATH);

        break;

    case OBTYPE_HASH_TYPE:

        bFound = supQueryTypeInfo(objectName,
            szBuffer,
            MAX_PATH);

        break;

    default:
        break;
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
}

/*
* ListObjectsInDirectory
*
* Purpose:
*
* List given directory to the listview.
*
*/
VOID ListObjectsInDirectory(
    _In_ LPWSTR lpObjectDirectory
)
{
    NTSTATUS            ntStatus;
    ULONG               queryContext = 0, rLength;
    HANDLE              directoryHandle = NULL;

    POBJECT_DIRECTORY_INFORMATION objinf;

    ListView_DeleteAllItems(g_hwndObjectList);

    directoryHandle = supOpenDirectory(NULL, lpObjectDirectory, DIRECTORY_QUERY);
    if (directoryHandle == NULL)
        return;

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
            ntStatus = NtQueryDirectoryObject(directoryHandle, NULL, 0, TRUE, FALSE, &queryContext, &rLength);
            if (ntStatus != STATUS_BUFFER_TOO_SMALL)
                break;
        }

        objinf = (POBJECT_DIRECTORY_INFORMATION)supHeapAlloc((SIZE_T)rLength);
        if (objinf == NULL)
            break;

        ntStatus = NtQueryDirectoryObject(directoryHandle, objinf, rLength, TRUE, FALSE, &queryContext, &rLength);
        if (!NT_SUCCESS(ntStatus)) {
            supHeapFree(objinf);
            break;
        }

        AddListViewItem(directoryHandle, objinf);

        supHeapFree(objinf);

    } while (TRUE);

    NtClose(directoryHandle);
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
    _In_ LPWSTR DirName,
    _In_opt_ LPWSTR NameSubstring,
    _In_opt_ LPWSTR TypeName,
    _In_ PFO_LIST_ITEM* List
)
{
    NTSTATUS            status;
    ULONG               ctx, rlen;
    HANDLE              directoryHandle = NULL;
    SIZE_T              sdlen;
    LPWSTR              newdir;
    PFO_LIST_ITEM       tmp;

    POBJECT_DIRECTORY_INFORMATION objinf;

    directoryHandle = supOpenDirectory(NULL, DirName, DIRECTORY_QUERY);
    if (directoryHandle == NULL)
        return;

    sdlen = _strlen(DirName);

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

        objinf = (POBJECT_DIRECTORY_INFORMATION)supHeapAlloc((SIZE_T)rlen);
        if (objinf == NULL)
            break;

        status = NtQueryDirectoryObject(directoryHandle, objinf, rlen, TRUE, FALSE, &ctx, &rlen);
        if (!NT_SUCCESS(status)) {
            supHeapFree(objinf);
            break;
        }

        if ((_strstri(objinf->Name.Buffer, NameSubstring) != 0) || (NameSubstring == NULL))
            if ((_strcmpi(objinf->TypeName.Buffer, TypeName) == 0) || (TypeName == NULL)) {

                tmp = (PFO_LIST_ITEM)supHeapAlloc(sizeof(FO_LIST_ITEM) +
                    objinf->Name.Length +
                    objinf->TypeName.Length +
                    (sdlen + 4) * sizeof(WCHAR));

                if (tmp == NULL) {
                    supHeapFree(objinf);
                    break;
                }
                tmp->Prev = *List;
                tmp->ObjectName = tmp->NameBuffer;
                tmp->ObjectType = tmp->NameBuffer + sdlen + 2 + objinf->Name.Length / sizeof(WCHAR);
                _strcpy(tmp->ObjectName, DirName);
                if ((DirName[0] == '\\') && (DirName[1] == 0)) {
                    _strncpy(tmp->ObjectName + sdlen, 1 + objinf->Name.Length / sizeof(WCHAR),
                        objinf->Name.Buffer, objinf->Name.Length / sizeof(WCHAR));
                }
                else {
                    tmp->ObjectName[sdlen] = '\\';
                    _strncpy(tmp->ObjectName + sdlen + 1, 1 + objinf->Name.Length / sizeof(WCHAR),
                        objinf->Name.Buffer, objinf->Name.Length / sizeof(WCHAR));
                }
                _strncpy(tmp->ObjectType, 1 + objinf->TypeName.Length / sizeof(WCHAR),
                    objinf->TypeName.Buffer, objinf->TypeName.Length / sizeof(WCHAR));
                *List = tmp;
            };

        if (_strcmpi(objinf->TypeName.Buffer, OBTYPE_NAME_DIRECTORY) == 0) {

            newdir = (LPWSTR)supHeapAlloc((sdlen + 4) * sizeof(WCHAR) + objinf->Name.Length);
            if (newdir != NULL) {
                _strcpy(newdir, DirName);
                if ((DirName[0] == '\\') && (DirName[1] == 0)) {
                    _strncpy(newdir + sdlen, 1 + objinf->Name.Length / sizeof(WCHAR),
                        objinf->Name.Buffer, objinf->Name.Length / sizeof(WCHAR));
                }
                else {
                    newdir[sdlen] = '\\';
                    _strncpy(newdir + sdlen + 1, 1 + objinf->Name.Length / sizeof(WCHAR),
                        objinf->Name.Buffer, objinf->Name.Length / sizeof(WCHAR));
                }
                FindObject(newdir, NameSubstring, TypeName, List);
                supHeapFree(newdir);
            }
        }

        supHeapFree(objinf);

    } while (TRUE);

    NtClose(directoryHandle);
}
