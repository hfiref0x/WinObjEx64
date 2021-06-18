/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2021
*
*  TITLE:       PROPSECTION.C
*
*  VERSION:     1.90
*
*  DATE:        12 May 2021
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "propDlg.h"
#include "extras.h"
#include "propObjectDumpConsts.h"
#include "propObjectDump.h"

#define COLUMN_SECTION_VIEW_OBJECT   0
#define COLUMN_SECTION_VIEW_ADDRESS  1

typedef VOID(CALLBACK* POUTPUT_SECTION_CONTROL_AREA)(
    _In_ HWND TreeList,
    _In_ HTREEITEM RootItem,
    _In_ ULONG_PTR Address,
    _In_ PCONTROL_AREA_COMPAT ControlArea
    );

typedef VOID(CALLBACK* POUTPUT_SECTION_SEGMENT)(
    _In_ HWND TreeList,
    _In_ HTREEITEM RootItem,
    _In_ ULONG_PTR Address,
    _In_ PSEGMENT Segment,
    _In_ PCONTROL_AREA_COMPAT ControlArea
    );

typedef VOID(CALLBACK* POUTPUT_SECTION_MI_REVERSE_VIEW_MAP)(
    _In_ HWND TreeList,
    _In_ HTREEITEM RootItem,
    _In_ ULONG_PTR Address,
    _In_ PMI_REVERSE_VIEW_MAP ReserveViewMap
    );

typedef HTREEITEM(CALLBACK* POUTPUT_SECTION_CREATE_NODE)(
    _In_ HWND TreeList,
    _In_ LPWSTR Name,
    _In_opt_ LPWSTR FirstValue,
    _In_opt_ LPWSTR SecondValue);

//
// MMSECTION_FLAGS (as of Win10)
//
LPCWSTR T_SectionFlags[] = {
    L"BeingDeleted",
    L"BeingCreated",
    L"BeingPurged",
    L"NoModifiedWriting",
    L"FailAllIo",
    L"Image",
    L"Based",
    L"File",
    L"AttemptingDelete",
    L"PrefetchCreated",
    L"PhysicalMemory",
    L"ImageControlAreaOnRemovableMedia",
    L"Reserve",
    L"Commit",
    L"NoChange",
    L"WasPurged",
    L"UserReference",
    L"GlobalMemory",
    L"DeleteOnClose",
    L"FilePointerNull",
    L"PreferredNode",
    L"GlobalOnlyPerSession",
    L"UserWritable",
    L"SystemVaAllocated",
    L"PreferredFsCompressionBoundary",
    L"UsingFileExtents",
    L"PageSize64K"
};

BOOLEAN IsValidSegment(
    _In_ ULONG_PTR ControlAreaAddress,
    _In_ PSEGMENT Segment
)
{
    return ((ULONG_PTR)Segment->ControlArea == ControlAreaAddress);
}

/*
* SectionControlAreaOutput
*
* Purpose:
*
* Output basic CONTROL_AREA information to the treelist.
*
*/
VOID CALLBACK SectionControlAreaOutput(
    _In_ HWND TreeList,
    _In_ HTREEITEM RootItem,
    _In_ ULONG_PTR Address,
    _In_ PCONTROL_AREA_COMPAT ControlArea
)
{
    HTREEITEM treeItem, treeSubItem;
    PVOID fileObject;
    UINT i, j;

    treeItem = propObDumpAddress(TreeList,
        RootItem,
        TEXT("ControlArea"),
        T_PCONTROL_AREA,
        (PVOID)Address,
        0, 0);

    if (treeItem) {

        propObDumpAddress(TreeList,
            treeItem,
            TEXT("Segment"),
            T_PSEGMENT,
            (PVOID)ControlArea->Segment,
            0, 0);

        propObDumpListEntry(TreeList,
            treeItem,
            TEXT("ListHead"),
            &ControlArea->ListHead);

        propObDumpUlong64(TreeList,
            treeItem,
            TEXT("NumberOfSectionReferences"),
            NULL,
            ControlArea->NumberOfSectionReferences,
            TRUE,
            0, 0);

        propObDumpUlong64(TreeList,
            treeItem,
            TEXT("NumberOfPfnReferences"),
            NULL,
            ControlArea->NumberOfPfnReferences,
            TRUE,
            0, 0);

        propObDumpUlong64(TreeList,
            treeItem,
            TEXT("NumberOfMappedViews"),
            NULL,
            ControlArea->NumberOfMappedViews,
            TRUE,
            0, 0);

        propObDumpUlong64(TreeList,
            treeItem,
            TEXT("NumberOfUserReferences"),
            NULL,
            ControlArea->NumberOfUserReferences,
            TRUE,
            0, 0);

        treeSubItem = propObDumpUlong(TreeList,
            treeItem,
            TEXT("u.LongFlags"),
            NULL,
            ControlArea->u.LongFlags,
            TRUE,
            FALSE,
            0, 0);

        if (treeSubItem) {

            i = 0;
            j = 0;
            do {

                if (i == 20) {

                    //
                    // This flag is 6 bits.
                    //
                    propObDumpUlong(TreeList,
                        treeSubItem,
                        (LPWSTR)T_SectionFlags[20],
                        NULL,
                        (ULONG)ControlArea->u.Flags.PreferredNode,
                        TRUE,
                        FALSE,
                        0, 0);

                    i += 6;

                }
                else {

                    propObDumpByte(TreeList,
                        treeSubItem,
                        (LPWSTR)T_SectionFlags[j],
                        NULL,
                        GET_BIT(ControlArea->u.LongFlags, i),
                        0, 0,
                        FALSE);

                    i += 1;
                }

                j++;

            } while (i < 32);

        }

        //
        // These flags are way too variadic even between Win10 releases.
        //
        propObDumpUlong(TreeList,
            treeItem,
            TEXT("u1.LongFlags"),
            NULL,
            ControlArea->u1.LongFlags,
            TRUE,
            FALSE,
            0, 0);

        fileObject = ObGetObjectFastReference(ControlArea->FilePointer);

        propObDumpAddress(TreeList,
            treeItem,
            TEXT("FilePointer"),
            T_PFILE_OBJECT,
            fileObject,
            0, 0);

    }

}

/*
* SectionSegmentOutput
*
* Purpose:
*
* Output basic SEGMENT information to the treelist.
*
*/
VOID CALLBACK SectionSegmentOutput(
    _In_ HWND TreeList,
    _In_ HTREEITEM RootItem,
    _In_ ULONG_PTR Address,
    _In_ PSEGMENT Segment,
    _In_ PCONTROL_AREA_COMPAT ControlArea
)
{
    HTREEITEM nodeRootItem, subItem;
    LPWSTR lpFieldName;
    LPWSTR lpDesc;

    nodeRootItem = propObDumpAddress(TreeList,
        RootItem,
        TEXT("Segment"),
        T_PSEGMENT,
        (PVOID)Address,
        0, 0);

    if (nodeRootItem) {

        subItem = propObDumpSetString(TreeList,
            nodeRootItem,
            TEXT("SegmentFlags"),
            T_SEGMENT_FLAGS,
            NULL,
            0, 0);

        if (subItem) {

            propObDumpUlong(TreeList,
                subItem,
                TEXT("Short0"),
                NULL,
                Segment->SegmentFlags.Short0,
                TRUE,
                TRUE,
                0, 0);

            propObDumpByte(TreeList,
                subItem,
                TEXT("UChar1"),
                NULL,
                Segment->SegmentFlags.UChar1,
                0, 0,
                FALSE);

            propObDumpByte(TreeList,
                subItem,
                TEXT("UChar2"),
                NULL,
                Segment->SegmentFlags.UChar2,
                0, 0,
                FALSE);

        }

        lpFieldName = TEXT("FirstMappedVa");
        lpDesc = T_EmptyString;

        if (ControlArea->u.Flags.Image)
        {
            lpFieldName = TEXT("ImageInformation");
            lpDesc = T_PMI_SECTION_IMAGE_INFORMATION;
        }

        propObDumpAddress(TreeList,
            nodeRootItem,
            lpFieldName,
            lpDesc,
            (PVOID)Segment->u3.FirstMappedVa,
            0, 0);

    }
}

/*
* SectionMiReverseViewMapOutput
*
* Purpose:
*
* Output basic MI_REVERSE_VIEW_MAP information to the treelist.
*
*/
VOID CALLBACK SectionMiReverseViewMapOutput(
    _In_ HWND TreeList,
    _In_ HTREEITEM RootItem,
    _In_ ULONG_PTR Address,
    _In_ PMI_REVERSE_VIEW_MAP ReverseViewMap
)
{
    BOOL bExtQuery = FALSE;
    ULONG_PTR viewMapType;
    HTREEITEM treeItem;
    HANDLE processId;
    ULONG_PTR kernelAddress;
    PUNICODE_STRING pusFileName = NULL;
    LPWSTR lpProcessName = NULL, lpFieldName = NULL;

    UNICODE_STRING usImageFileName;

    //
    // MI_REVERSE_VIEW_MAP
    //
    treeItem = propObDumpAddress(TreeList,
        RootItem,
        TEXT("ViewMap"),
        T_PMI_REVERSE_VIEW_MAP,
        (PVOID)Address,
        0, 0);

    if (treeItem) {

        //
        // MI_REVERSE_VIEW_MAP->Type
        //
        propObDumpUlong(TreeList,
            treeItem,
            TEXT("Type"),
            NULL,
            ReverseViewMap->u1.Type,
            FALSE,
            FALSE,
            0, 0);

        RtlInitEmptyUnicodeString(&usImageFileName, NULL, 0);

        viewMapType = ReverseViewMap->u1.Type;
        kernelAddress = (ULONG_PTR)ReverseViewMap->u1.VadsProcess & ~viewMapType;

        switch (viewMapType) {

        case VIEW_MAP_TYPE_PROCESS:

            //
            // Process map view.
            //
            lpFieldName = TEXT("VadsProcess");


            if (ObGetProcessId(kernelAddress, &processId)) {

                bExtQuery = NT_SUCCESS(supQueryProcessImageFileNameWin32(processId, &pusFileName));

                if (bExtQuery) {

                    if (pusFileName->Buffer && pusFileName->Length) {

                        lpProcessName = supExtractFileName(pusFileName->Buffer);

                    }
                    else {
                        bExtQuery = FALSE;
                    }

                }

            }

            if (bExtQuery == FALSE) {

                if (ObGetProcessImageFileName(kernelAddress, &usImageFileName)) {
                    lpProcessName = usImageFileName.Buffer;
                }
                else {
                    lpProcessName = T_Unknown;
                }

            }

            break;

        case VIEW_MAP_TYPE_SESSION:

            //
            // MMVIEW
            //

            //
            // Session view.
            //
            lpFieldName = TEXT("SessionViewVa");
            break;

        case VIEW_MAP_TYPE_SYSTEM_CACHE:

            //
            // MI_IMAGE_ENTRY_IN_SESSION
            //

            //
            // System cache view.
            //
            lpFieldName = TEXT("SystemCacheVa");
            break;

        default:
            //
            // Unknown.
            //
            lpFieldName = TEXT("Unrecognized");
            break;

        }

        propObDumpAddress(TreeList,
            treeItem,
            lpFieldName,
            lpProcessName,
            (PVOID)kernelAddress,
            0, 0);

        if (ReverseViewMap->u1.Type == VIEW_MAP_TYPE_PROCESS) {
            if (pusFileName)
                supHeapFree(pusFileName);

            if (usImageFileName.Buffer)
                RtlFreeUnicodeString(&usImageFileName);
        }
    }
}

/*
* SectionObjectCreateNode
*
* Purpose:
*
* Create a new node for output construction.
*
*/
HTREEITEM CALLBACK SectionObjectCreateNode(
    _In_ HWND TreeList,
    _In_ LPWSTR Name,
    _In_opt_ LPWSTR FirstValue,
    _In_opt_ LPWSTR SecondValue
)
{
    TL_SUBITEMS_FIXED subitems;

    RtlSecureZeroMemory(&subitems, sizeof(subitems));

    subitems.Count = 2;

    if (FirstValue) {       
        subitems.Text[0] = FirstValue;
    }
    else {
        subitems.Text[0] = T_EmptyString;
    }

    if (SecondValue) {
        subitems.Text[1] = SecondValue;
    }
    else {
        subitems.Text[1] = T_EmptyString;
    }

    return supTreeListAddItem(TreeList,
        NULL,
        TVIF_TEXT | TVIF_STATE,
        TVIS_EXPANDED,
        TVIS_EXPANDED,
        Name,
        &subitems);
}

#define SECTION_ENUM_MEMORY_READ_FAILURE    1
#define SECTION_ENUM_CORRUPT_SEGMENT        2
#define SECTION_ENUM_UNSUPPORTED_FLAGS      3

/*
* SectionObjectEnumerateFields
*
* Purpose:
*
* Enum section object basic information.
*
*/
ULONG SectionObjectEnumerateFields(
    _In_ HWND TreeList,
    _In_ ULONG_PTR SectionObject,
    _In_ HTREEITEM RootItem,
    _In_ POUTPUT_SECTION_CREATE_NODE CreateNodeCallback,
    _In_ POUTPUT_SECTION_CONTROL_AREA ControlAreaOutput,
    _In_ POUTPUT_SECTION_SEGMENT SegmentOutput,
    _In_ POUTPUT_SECTION_MI_REVERSE_VIEW_MAP MiReverseMapOutput
)
{
    ULONG ulResult = ERROR_SUCCESS;
    ULONG_PTR numberOfMappedViews;
    ULONG_PTR viewLinksHead, kernelAddress;
    HTREEITEM mapViewRoot;

    SECTION_COMPAT dumpedSection;
    SEGMENT dumpedSegment;
    CONTROL_AREA_COMPAT dumpedControlArea;
    MI_REVERSE_VIEW_MAP dumpedViewMap;
    //MMVAD dumpedVad;
    LIST_ENTRY viewLinks;

    do {
        //
        // Dump _SECTION structure.
        //
        RtlSecureZeroMemory(&dumpedSection, sizeof(dumpedSection));
        if (!kdReadSystemMemory(SectionObject,
            &dumpedSection,
            sizeof(dumpedSection)))
        {
            ulResult = SECTION_ENUM_MEMORY_READ_FAILURE;
            break;
        }

        if (dumpedSection.u1.RemoteDataFileObject ||
            dumpedSection.u1.RemoteImageFileObject)
        {
            ulResult = SECTION_ENUM_UNSUPPORTED_FLAGS;
            break;
        }

        //
        // Dump CONTROL_AREA
        //
        RtlSecureZeroMemory(&dumpedControlArea, sizeof(dumpedControlArea));
        if (!kdReadSystemMemory((ULONG_PTR)dumpedSection.u1.ControlArea,
            &dumpedControlArea,
            sizeof(dumpedControlArea)))
        {
            ulResult = SECTION_ENUM_MEMORY_READ_FAILURE;
            break;
        }

        //
        // Dump ControlArea->SEGMENT
        //
        RtlSecureZeroMemory(&dumpedSegment, sizeof(dumpedSegment));
        if (!kdReadSystemMemory((ULONG_PTR)dumpedControlArea.Segment,
            &dumpedSegment,
            sizeof(dumpedSegment)))
        {
            ulResult = SECTION_ENUM_MEMORY_READ_FAILURE;
            break;
        }

        if (!IsValidSegment((ULONG_PTR)dumpedSection.u1.ControlArea,
            &dumpedSegment))
        {
            ulResult = SECTION_ENUM_CORRUPT_SEGMENT;
            break;
        }

        numberOfMappedViews = dumpedControlArea.NumberOfMappedViews;

        ControlAreaOutput(TreeList,
            RootItem,
            (ULONG_PTR)dumpedSection.u1.ControlArea,
            &dumpedControlArea);

        SegmentOutput(TreeList,
            RootItem,
            (ULONG_PTR)dumpedControlArea.Segment,
            &dumpedSegment,
            &dumpedControlArea);

        if (numberOfMappedViews) {

            mapViewRoot = CreateNodeCallback(TreeList,
                TEXT("ReverseViewMap"),
                NULL, 
                T_PMI_REVERSE_VIEW_MAP);

            if (mapViewRoot) {

                viewLinks = dumpedControlArea.ListHead;
                viewLinksHead = (ULONG_PTR)dumpedSection.u1.ControlArea + FIELD_OFFSET(CONTROL_AREA_COMPAT, ListHead);

                //
                // Ignore all errors from this.
                //
                ulResult = ERROR_SUCCESS;

                //
                // Walk list entries.
                //
                while ((ULONG_PTR)viewLinks.Flink != viewLinksHead && numberOfMappedViews) {

                    RtlSecureZeroMemory(&dumpedViewMap, sizeof(dumpedViewMap));
                    kernelAddress = (ULONG_PTR)viewLinks.Flink;
                    if (!kdReadSystemMemory(kernelAddress,
                        &dumpedViewMap,
                        sizeof(dumpedViewMap)))
                    {
                        break;
                    }

                    /*kernelAddress -= FIELD_OFFSET(MMVAD, ViewLinks);

                     RtlSecureZeroMemory(&dumpedVad, sizeof(dumpedVad));
                     if (!kdReadSystemMemory(kernelAddress,
                         &dumpedVad,
                         sizeof(dumpedVad)))
                     {
                         break;
                     }*/

                    MiReverseMapOutput(TreeList,
                        mapViewRoot,
                        (ULONG_PTR)viewLinks.Flink,
                        &dumpedViewMap);

                    //
                    // Next entry.
                    //
                    viewLinks = dumpedViewMap.ViewLinks;
                    if (viewLinks.Flink == NULL)
                        break;

                    numberOfMappedViews--;
                }

            }
        }

    } while (FALSE);

    return ulResult;
}

/*
* SectionPropertiesCreate
*
* Purpose:
*
* Initialize information view.
* Called once.
*
*/
VOID SectionPropertiesCreate(
    _In_ HWND hwndDlg,
    _In_ PROP_OBJECT_INFO* ObjectContext,
    _In_ EXTRASCONTEXT* DlgContext
)
{
    ULONG ulResult;
    HTREEITEM rootItem;
    LPWSTR lpError = NULL;

    if (supInitTreeListForDump(hwndDlg, &DlgContext->TreeList)) {

        supTreeListEnableRedraw(DlgContext->TreeList, FALSE);

        rootItem = SectionObjectCreateNode(DlgContext->TreeList,
            TEXT("SECTION"),
            NULL,
            NULL);

        if (rootItem) {

            ulResult = SectionObjectEnumerateFields(DlgContext->TreeList,
                ObjectContext->ObjectInfo.ObjectAddress,
                rootItem,
                (POUTPUT_SECTION_CREATE_NODE)SectionObjectCreateNode,
                (POUTPUT_SECTION_CONTROL_AREA)SectionControlAreaOutput,
                (POUTPUT_SECTION_SEGMENT)SectionSegmentOutput,
                (POUTPUT_SECTION_MI_REVERSE_VIEW_MAP)SectionMiReverseViewMapOutput);

            if (ERROR_SUCCESS != ulResult)
            {
                switch (ulResult) {

                case SECTION_ENUM_MEMORY_READ_FAILURE:
                    lpError = TEXT("Memory could not be read or unspecified read error.");
                    break;

                case SECTION_ENUM_CORRUPT_SEGMENT:
                    lpError = TEXT("SEGMENT is corrupt or paged out - bad control area backlink.");
                    break;

                case SECTION_ENUM_UNSUPPORTED_FLAGS:
                    lpError = TEXT("Object flags are not supported.");
                    break;

                default:
                    break;
                }
                supObDumpShowError(hwndDlg, lpError);
            }

        }

        supTreeListEnableRedraw(DlgContext->TreeList, TRUE);

    }
}

/*
* SectionPropertiesDialogProc
*
* Purpose:
*
* Section object properties page.
*
*/
INT_PTR CALLBACK SectionPropertiesDialogProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    PROPSHEETPAGE* pSheet;
    EXTRASCONTEXT* pDlgContext = NULL;

    switch (uMsg) {

    case WM_CONTEXTMENU:
        supObjectDumpHandlePopupMenu(hwndDlg);
        break;

    case WM_COMMAND:

        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);

        switch (GET_WM_COMMAND_ID(wParam, lParam)) {

        case ID_OBJECT_COPY:
            if (pDlgContext) {

                supCopyTreeListSubItemValue(pDlgContext->TreeList,
                    COLUMN_SECTION_VIEW_OBJECT);

            }
            break;

        case ID_ADDINFO_COPY:
            if (pDlgContext) {

                supCopyTreeListSubItemValue(pDlgContext->TreeList,
                    COLUMN_SECTION_VIEW_ADDRESS);

            }
            break;

        default:
            break;
        }

        break;

    case WM_DESTROY:
        pDlgContext = (EXTRASCONTEXT*)RemoveProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            DestroyWindow(pDlgContext->TreeList);
            supHeapFree(pDlgContext);
        }
        RemoveProp(hwndDlg, T_PROPCONTEXT);
        break;

    case WM_INITDIALOG:
        pSheet = (PROPSHEETPAGE*)lParam;
        if (pSheet) {
            SetProp(hwndDlg, T_PROPCONTEXT, (HANDLE)pSheet->lParam);
            pDlgContext = (EXTRASCONTEXT*)supHeapAlloc(sizeof(EXTRASCONTEXT));
            if (pDlgContext) {
                SetProp(hwndDlg, T_DLGCONTEXT, (HANDLE)pDlgContext);
                SectionPropertiesCreate(hwndDlg, (PROP_OBJECT_INFO*)pSheet->lParam, pDlgContext);
            }
        }
        break;

    default:
        return FALSE;

    }
    return TRUE;
}
