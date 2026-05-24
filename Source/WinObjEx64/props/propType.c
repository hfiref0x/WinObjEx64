/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2026
*
*  TITLE:       PROPTYPE.C
*
*  VERSION:     2.11
*
*  DATE:        21 May 2026
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "propTypeConsts.h"

/*
* propSetTypeFlagValue
*
* Purpose:
*
* Add value to the access rights listview
*
*/
VOID propSetTypeFlagValue(
    _In_ HWND	hListView,
    _In_ LPWSTR lpFlag,
    _In_ DWORD	Value
)
{
    INT    nIndex;
    LVITEM lvitem;
    WCHAR  szBuffer[MAX_PATH];

    if (lpFlag == NULL)
        return;

    RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
    lvitem.mask = LVIF_TEXT;
    lvitem.pszText = lpFlag;
    lvitem.iItem = MAXINT;
    nIndex = ListView_InsertItem(hListView, &lvitem);
    if (nIndex == -1)
        return;

    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
    szBuffer[0] = L'0';
    szBuffer[1] = L'x';
    ultohex(Value, &szBuffer[2]);

    lvitem.iSubItem = 1;
    lvitem.pszText = szBuffer;
    lvitem.iItem = nIndex;
    ListView_SetItem(hListView, &lvitem);
}

/*
* propSetTypeDecodeValue
*
* Purpose:
*
* Decode Access Right Attributes depending on object type
*
*/
VOID propSetTypeDecodeValue(
    _In_ HWND hListView,
    _In_ DWORD Value,
    _In_ INT TypeIndex
)
{
    INT	        i, Count, bitIndex;
    DWORD       u, remaining, specific;
    PVALUE_DESC Desc = NULL;

    switch (TypeIndex) {

    case ObjectTypeWMIGuid:
        Desc = a_WmiGuidProp;
        Count = RTL_NUMBER_OF(a_WmiGuidProp);
        break;

    case ObjectTypeWinstation:
        Desc = a_WinstaProp;
        Count = RTL_NUMBER_OF(a_WinstaProp);
        break;

    case ObjectTypeToken:
        Desc = a_TokenProp;
        Count = RTL_NUMBER_OF(a_TokenProp);
        break;

    case ObjectTypeThread:
        Desc = a_ThreadProp;
        Count = RTL_NUMBER_OF(a_ThreadProp);
        break;

    case ObjectTypeIRTimer:
    case ObjectTypeTimer:
        Desc = a_TimerProp;
        Count = RTL_NUMBER_OF(a_TimerProp);
        break;

    case ObjectTypeProcess:
        Desc = a_ProcessProp;
        Count = RTL_NUMBER_OF(a_ProcessProp);
        break;

    case ObjectTypeKeyedEvent:
        Desc = a_KeyedEventProp;
        Count = RTL_NUMBER_OF(a_KeyedEventProp);
        break;

    case ObjectTypeJob:
        Desc = a_JobProp;
        Count = RTL_NUMBER_OF(a_JobProp);
        break;

    case ObjectTypeSession:
        Desc = a_SessionProp;
        Count = RTL_NUMBER_OF(a_SessionProp);
        break;

    case ObjectTypeDesktop:
        Desc = a_DesktopObjectProp;
        Count = RTL_NUMBER_OF(a_DesktopObjectProp);
        break;

    case ObjectTypeDebugObject:
        Desc = a_DebugObjectProp;
        Count = RTL_NUMBER_OF(a_DebugObjectProp);
        break;

    case ObjectTypeCallback:
        Desc = a_CallbackProp;
        Count = RTL_NUMBER_OF(a_CallbackProp);
        break;

    case ObjectTypeAdapter:
    case ObjectTypeController:
    case ObjectTypeDevice:
    case ObjectTypeDriver:
    case ObjectTypeFile:
        Desc = a_FileProp;
        Count = RTL_NUMBER_OF(a_FileProp);
        break;

    case ObjectTypeKey:
        Desc = a_KeyProp;
        Count = RTL_NUMBER_OF(a_KeyProp);
        break;

    case ObjectTypeType:
        Desc = a_TypeProp;
        Count = RTL_NUMBER_OF(a_TypeProp);
        break;

    case ObjectTypeSymbolicLink:
        Desc = a_SymLinkProp;
        Count = RTL_NUMBER_OF(a_SymLinkProp);
        break;

    case ObjectTypeDirectory:
        Desc = a_DirProp;
        Count = RTL_NUMBER_OF(a_DirProp);
        break;

    case ObjectTypeEvent:
        Desc = a_EventProp;
        Count = RTL_NUMBER_OF(a_EventProp);
        break;

    case ObjectTypeMutant:
        Desc = a_MutantProp;
        Count = RTL_NUMBER_OF(a_MutantProp);
        break;

        //all ports
    case ObjectTypeFltComnPort:
    case ObjectTypeFltConnPort:
    case ObjectTypeWaitablePort:
    case ObjectTypePort:
        Desc = a_PortProp;
        Count = RTL_NUMBER_OF(a_PortProp);
        break;

    case ObjectTypeProfile:
        Desc = a_ProfileProp;
        Count = RTL_NUMBER_OF(a_ProfileProp);
        break;

    case ObjectTypeSection:
        Desc = a_SectionProp;
        Count = RTL_NUMBER_OF(a_SectionProp);
        break;

    case ObjectTypeSemaphore:
        Desc = a_SemaphoreProp;
        Count = RTL_NUMBER_OF(a_SemaphoreProp);
        break;

    case ObjectTypeIoCompletion:
    case ObjectTypeIoCompletionReserve:
        Desc = a_IoCompletionProp;
        Count = RTL_NUMBER_OF(a_IoCompletionProp);
        break;

        //RegistryTransaction/Transaction Object
    case ObjectTypeRegistryTransaction:
    case ObjectTypeTmTx:
        Desc = a_TmTxProp;
        Count = RTL_NUMBER_OF(a_TmTxProp);
        break;

        //Transaction Resource Manager Object
    case ObjectTypeTmRm:
        Desc = a_TmRmProp;
        Count = RTL_NUMBER_OF(a_TmRmProp);
        break;

        //Transaction Enlistment Object 
    case ObjectTypeTmEn:
        Desc = a_TmEnProp;
        Count = RTL_NUMBER_OF(a_TmEnProp);
        break;

        //Transaction Manager Object
    case ObjectTypeTmTm:
        Desc = a_TmTmProp;
        Count = RTL_NUMBER_OF(a_TmTmProp);
        break;

    case ObjectTypeTpWorkerFactory:
        Desc = a_TpwfProp;
        Count = RTL_NUMBER_OF(a_TpwfProp);
        break;

    case ObjectTypePcwObject:
        Desc = a_PcwProp;
        Count = RTL_NUMBER_OF(a_PcwProp);
        break;

    case ObjectTypeComposition:
        Desc = a_CompositionProp;
        Count = RTL_NUMBER_OF(a_CompositionProp);
        break;

        //Parition object
    case ObjectTypeMemoryPartition:
        Desc = a_MemPartProp;
        Count = RTL_NUMBER_OF(a_MemPartProp);
        break;

    default:
        Count = 0;
        break;
    }

    remaining = Value;

    //list for selected type
    if (Desc) {
        for (i = 0; i < Count; i++) {
            if (remaining & Desc[i].dwValue) {
                propSetTypeFlagValue(hListView, Desc[i].lpDescription, Desc[i].dwValue);
                remaining &= ~Desc[i].dwValue;
            }
        }
    }

    //list Standard Access Rights if anything left
    if (remaining != 0) {
        Desc = a_Standard;
        Count = RTL_NUMBER_OF(a_Standard);
        for (i = 0; i < Count; i++) {
            if (remaining & Desc[i].dwValue) {
                propSetTypeFlagValue(hListView, Desc[i].lpDescription, Desc[i].dwValue);
                remaining &= ~Desc[i].dwValue;
            }
        }
    }

    specific = remaining & SPECIFIC_RIGHTS_ALL;
    if (specific != 0) {
        propSetTypeFlagValue(hListView, a_Specific[0].lpDescription, specific);
        remaining &= ~SPECIFIC_RIGHTS_ALL;
    }

    //list any remaining unknown bits
    if (remaining != 0) {
        for (bitIndex = 0; bitIndex < 32 && remaining != 0; bitIndex++) {
            u = (1U << bitIndex);
            if (remaining & u) {
                propSetTypeFlagValue(hListView, T_Unknown, u);
                remaining &= ~u;
            }
        }
    }
}

/*
* propSetTypeFlags
*
* Purpose:
*
* Set object type flags descriptions at the Type page
*
*/
VOID propSetTypeFlags(
    HWND hwndDlg,
    DWORD ObjectFlags
)
{
    INT  i;
    HWND hwndCB;
    BOOL bObjectFlagsSet = FALSE;

    hwndCB = GetDlgItem(hwndDlg, IDC_TYPE_FLAGS);
    if (hwndCB) {
        bObjectFlagsSet = (ObjectFlags != 0);
        EnableWindow(hwndCB, bObjectFlagsSet);
        SendMessage(hwndCB, CB_RESETCONTENT, (WPARAM)0, (LPARAM)0);
        if (bObjectFlagsSet) {
            EnableWindow(hwndCB, TRUE);
            for (i = 0; i < 8; i++)
                if (GET_BIT(ObjectFlags, i)) {

                    SendMessage(hwndCB,
                        CB_ADDSTRING,
                        (WPARAM)0,
                        (LPARAM)T_ObjectTypeFlags[i]);
                }

            SendMessage(hwndCB, CB_SETCURSEL, (WPARAM)0, (LPARAM)0);
        }
    }
}

/*
* propSetTypeAttributes
*
* Purpose:
*
* List attributes depending on object type
*
*/
VOID propSetTypeAttributes(
    _In_ HWND hwndDlg,
    _In_ POBJECT_TYPE_COMPATIBLE ObjectTypeDump
)
{
    LRESULT nIndex;
    HWND    hListAttrbites;
    WCHAR   szBuffer[MAX_PATH + 1];

    if (ObjectTypeDump == NULL)
        return;

    hListAttrbites = GetDlgItem(hwndDlg, ID_TYPE_ATTRLIST);
    if (hListAttrbites == NULL)
        return;

    SendMessage(hListAttrbites, LB_RESETCONTENT, (WPARAM)0, (LPARAM)0);

    //Invalid attributes
    nIndex = SendMessage(hListAttrbites, LB_ADDSTRING, (WPARAM)0, (LPARAM)&T_InvalidAttributes);
    SendMessage(hListAttrbites, LB_SETITEMDATA, (WPARAM)nIndex,
        (LPARAM)ObjectTypeDump->TypeInfo.InvalidAttributes);

    _strcpy(szBuffer, T_FORMATTED_ATTRIBUTE);
    ultohex(ObjectTypeDump->TypeInfo.InvalidAttributes, _strend(szBuffer));
    SendMessage(hListAttrbites, LB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);

    //Valid access
    nIndex = SendMessage(hListAttrbites, LB_ADDSTRING, (WPARAM)0, (LPARAM)&T_ValidAccess);
    SendMessage(hListAttrbites, LB_SETITEMDATA, (WPARAM)nIndex,
        (LPARAM)ObjectTypeDump->TypeInfo.ValidAccessMask);

    _strcpy(szBuffer, T_FORMATTED_ATTRIBUTE);
    ultohex(ObjectTypeDump->TypeInfo.ValidAccessMask, _strend(szBuffer));
    SendMessage(hListAttrbites, LB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);

    //Generic Read
    nIndex = SendMessage(hListAttrbites, LB_ADDSTRING, (WPARAM)0, (LPARAM)&T_GenericRead);
    SendMessage(hListAttrbites, LB_SETITEMDATA, (WPARAM)nIndex,
        (LPARAM)ObjectTypeDump->TypeInfo.GenericMapping.GenericRead);

    _strcpy(szBuffer, T_FORMATTED_ATTRIBUTE);
    ultohex(ObjectTypeDump->TypeInfo.GenericMapping.GenericRead, _strend(szBuffer));
    SendMessage(hListAttrbites, LB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);

    //Generic Write
    nIndex = SendMessage(hListAttrbites, LB_ADDSTRING, (WPARAM)0, (LPARAM)&T_GenericWrite);
    SendMessage(hListAttrbites, LB_SETITEMDATA, (WPARAM)nIndex,
        (LPARAM)ObjectTypeDump->TypeInfo.GenericMapping.GenericWrite);

    _strcpy(szBuffer, T_FORMATTED_ATTRIBUTE);
    ultohex(ObjectTypeDump->TypeInfo.GenericMapping.GenericWrite, _strend(szBuffer));
    SendMessage(hListAttrbites, LB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);

    //Generic Execute
    nIndex = SendMessage(hListAttrbites, LB_ADDSTRING, (WPARAM)0, (LPARAM)&T_GenericExecute);
    SendMessage(hListAttrbites, LB_SETITEMDATA, (WPARAM)nIndex,
        (LPARAM)ObjectTypeDump->TypeInfo.GenericMapping.GenericExecute);

    _strcpy(szBuffer, T_FORMATTED_ATTRIBUTE);
    ultohex(ObjectTypeDump->TypeInfo.GenericMapping.GenericExecute, _strend(szBuffer));
    SendMessage(hListAttrbites, LB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);

    //Generic All
    nIndex = SendMessage(hListAttrbites, LB_ADDSTRING, (WPARAM)0, (LPARAM)&T_GenericAll);
    SendMessage(hListAttrbites, LB_SETITEMDATA, (WPARAM)nIndex,
        (LPARAM)ObjectTypeDump->TypeInfo.GenericMapping.GenericAll);

    _strcpy(szBuffer, T_FORMATTED_ATTRIBUTE);
    ultohex(ObjectTypeDump->TypeInfo.GenericMapping.GenericAll, _strend(szBuffer));
    SendMessage(hListAttrbites, LB_ADDSTRING, (WPARAM)0, (LPARAM)&szBuffer);
}

/*
* propSetTypeDecodedAttributes
*
* Purpose:
*
* Handler for listbox with access rights and invalid attributes click
*
*/
VOID propSetTypeDecodedAttributes(
    _In_ PROP_OBJECT_INFO* Context,
    _In_ HWND hwndDlg
)
{
    HWND            hListRights, hListAttrbites;
    LRESULT         curSel;
    DWORD           i, dwFlags;

    hListRights = GetDlgItem(hwndDlg, ID_TYPE_ACL_LIST);
    if (hListRights == NULL) {
        return;
    }

    ListView_DeleteAllItems(hListRights);

    hListAttrbites = GetDlgItem(hwndDlg, ID_TYPE_ATTRLIST);
    if (hListAttrbites == NULL) {
        return;
    }

    curSel = SendMessage(hListAttrbites, LB_GETCURSEL, (WPARAM)0, (LPARAM)0);
    if (curSel == LB_ERR)
        return;

    if (curSel % 2 != 0) {
        curSel--;
        SendMessage(hListAttrbites, LB_SETCURSEL, (WPARAM)curSel, (LPARAM)0);
    }

    dwFlags = (DWORD)SendMessage(hListAttrbites, LB_GETITEMDATA, (WPARAM)curSel, (LPARAM)0);
    if (dwFlags == 0)
        return;

    //
    // Depending on selection, decode attributes to the list.
    //
    if (curSel == 0) {

        //
        // List all known attributes.
        //
        for (i = 0; i < RTL_NUMBER_OF(a_ObjProp); i++) {
            if (dwFlags & a_ObjProp[i].dwValue) {
                propSetTypeFlagValue(hListRights, a_ObjProp[i].lpDescription, a_ObjProp[i].dwValue);
                dwFlags &= ~a_ObjProp[i].dwValue;
            }
        }

        //
        // List any other.
        //
        if (dwFlags != 0) {
            propSetTypeFlagValue(hListRights, T_Unknown, dwFlags);
        }
    }
    else {
        propSetTypeDecodeValue(hListRights, dwFlags, Context->ShadowTypeDescription->Index);
    }
}

/*
* propSetTypeListView
*
* Purpose:
*
* Create listview for object access rights enumeration.
*
* This routine must be called once.
*
*/
VOID propSetTypeListView(
    _In_ HWND hwndDlg
)
{
    HWND hListRights;

    hListRights = GetDlgItem(hwndDlg, ID_TYPE_ACL_LIST);
    if (hListRights == NULL)
        return;

    supSetListViewSettings(hListRights,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP,
        TRUE, //override global settings for this listview
        TRUE,
        NULL,
        0);

    supAddListViewColumn(hListRights, 0, 0, 0,
        I_IMAGENONE,
        LVCFMT_LEFT,
        TEXT("Flag"), 190);

    supAddListViewColumn(hListRights, 1, 1, 1,
        I_IMAGENONE,
        LVCFMT_LEFT,
        TEXT("Value"), 80);
}

/*
* propQueryTypeInfo
*
* Purpose:
*
* Query Type information depending on object type.
*
* Used if object dumped info not available (restricted user, no driver etc).
*
*/
_Success_(return)
BOOL propQueryTypeInfo(
    _In_ PUNICODE_STRING ObjectType,
    _Out_ POBJECT_TYPE_COMPATIBLE Information
)
{
    BOOL     bResult = FALSE;
    ULONG    i;

    POBJECT_TYPES_INFORMATION pObjectTypes = NULL;
    POBJECT_TYPE_INFORMATION  pObject;

    pObjectTypes = (POBJECT_TYPES_INFORMATION)supGetObjectTypesInfo();
    if (pObjectTypes == NULL)
        return FALSE;

    pObject = OBJECT_TYPES_FIRST_ENTRY(pObjectTypes);

    __try {

        //
        // Warning: older Wine/Staging incorrectly implement memory structure layout for this structure and therefore will crash.            
        //
        for (i = 0; i < pObjectTypes->NumberOfTypes; i++) {

            if (RtlEqualUnicodeString(ObjectType, &pObject->TypeName, TRUE)) {
                Information->TotalNumberOfHandles = pObject->TotalNumberOfHandles;
                Information->TotalNumberOfObjects = pObject->TotalNumberOfObjects;
                Information->TypeInfo.InvalidAttributes = pObject->InvalidAttributes;
                Information->TypeInfo.GenericMapping = pObject->GenericMapping;
                Information->TypeInfo.ValidAccessMask = pObject->ValidAccessMask;
                Information->TypeInfo.DefaultNonPagedPoolCharge = pObject->DefaultNonPagedPoolCharge;
                Information->TypeInfo.DefaultPagedPoolCharge = pObject->DefaultPagedPoolCharge;
                Information->HighWaterNumberOfHandles = pObject->HighWaterNumberOfHandles;
                Information->HighWaterNumberOfObjects = pObject->HighWaterNumberOfObjects;
                Information->TypeInfo.PoolType = (POOL_TYPE)pObject->PoolType;
                if (pObject->SecurityRequired) {
                    SET_BIT(Information->TypeInfo.ObjectTypeFlags, 3);
                }
                if (pObject->MaintainHandleCount) {
                    SET_BIT(Information->TypeInfo.ObjectTypeFlags, 4);
                }
                bResult = TRUE;
                break;
            }
            pObject = OBJECT_TYPES_NEXT_ENTRY(pObject);
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        supReportAbnormalTermination(__FUNCTIONW__);
        return FALSE;
    }

    supHeapFree(pObjectTypes);
    return bResult;
}

/*
* propSetTypeInfo
*
* Purpose:
*
* Set type information depending on object name or type
* Handle special case when user selected \ObjectTypes to provide per type information
*
*/
VOID propSetTypeInfo(
    _In_ PROP_OBJECT_INFO * Context,
    _In_ HWND hwndDlg
)
{
    BOOL bOkay;
    WOBJ_OBJECT_TYPE RealTypeIndex;
    INT i;
    LPCWSTR lpTypeDescription = NULL;
    OBJECT_TYPE_COMPATIBLE ObjectTypeDump;
    WCHAR szConvertBuffer[64];
    WCHAR szType[MAX_PATH * 2];

    POBEX_OBJECT_INFORMATION pObject = NULL;
    UNICODE_STRING usName;

    lpTypeDescription = Context->TypeDescription->Name;

    RealTypeIndex = Context->ShadowTypeDescription->Index;
    if (RealTypeIndex > ObjectTypeUnknown) {
        RealTypeIndex = ObjectTypeUnknown;
    }

    //if type is not known set it description to it type name
    if (RealTypeIndex != ObjectTypeUnknown) {

        //set description
        RtlSecureZeroMemory(&szType, sizeof(szType));
        if (LoadString(
            g_WinObj.hInstance,
            Context->TypeDescription->ResourceStringId,
            szType,
            RTL_NUMBER_OF(szType)))
        {
            lpTypeDescription = szType;
        }

    }

    //check if we have object address and dump object
    if (Context->ObjectInfo.ObjectAddress == 0) {
        propSetTypeFlags(hwndDlg, Context->ObjectFlags);
    }

    //
    // Handle special case.
    // Current object is Type object, display Type Info.
    //
    bOkay = FALSE;
    RtlSecureZeroMemory(&ObjectTypeDump, sizeof(ObjectTypeDump));
    if (Context->ObjectTypeIndex == ObjectTypeType) {

        //query object by name, thus were giving us proper object type dump
        pObject = ObQueryObjectInDirectory(
            &Context->NtObjectName,
            ObGetPredefinedUnicodeString(OBP_OBTYPES));

        //cannot query, no driver or other error, try second method
        if (pObject == NULL) {
            bOkay = propQueryTypeInfo(&Context->NtObjectName, &ObjectTypeDump);
        }

        //if type is not known set it description to it type name
        if (RealTypeIndex == ObjectTypeUnknown) {
            lpTypeDescription = Context->NtObjectName.Buffer;
        }
        else {
            //set description
            RtlSecureZeroMemory(&szType, sizeof(szType));
            if (LoadString(
                g_WinObj.hInstance,
                Context->ShadowTypeDescription->ResourceStringId,
                szType,
                RTL_NUMBER_OF(szType)))
            {
                lpTypeDescription = szType;
            }
            else {
                lpTypeDescription = Context->TypeDescription->Name;
            }
        }
    }
    else {

        //
        // Query object type object.
        //
        pObject = ObQueryObjectInDirectory(
            &Context->NtObjectName,
            ObGetPredefinedUnicodeString(OBP_OBTYPES));

        //
        // If we cannot query because of no driver or other error, try second method.
        //
        if (pObject == NULL) {
            RtlInitUnicodeString(&usName, Context->TypeDescription->Name);
            bOkay = propQueryTypeInfo(&usName, &ObjectTypeDump);
        }

    }

    //
    // Set description label.
    //
    SetDlgItemText(hwndDlg, ID_TYPE_DESCRIPTION, lpTypeDescription);

    //
    // Driver info available, dump type.
    //
    if (pObject != NULL) {
        
        bOkay = kdReadSystemMemory(pObject->ObjectAddress, 
            &ObjectTypeDump, 
            sizeof(OBJECT_TYPE_COMPATIBLE));

        supHeapFree(pObject);
    }

    if (bOkay) {
        RtlSecureZeroMemory(szConvertBuffer, sizeof(szConvertBuffer));

        //Object count
        u64tostr(ObjectTypeDump.TotalNumberOfObjects, szConvertBuffer);
        SetDlgItemText(hwndDlg, ID_TYPE_COUNT, szConvertBuffer);

        //Handle count
        szConvertBuffer[0] = 0;
        u64tostr(ObjectTypeDump.TotalNumberOfHandles, szConvertBuffer);
        SetDlgItemText(hwndDlg, ID_TYPE_HANDLECOUNT, szConvertBuffer);

        //Peek object count
        szConvertBuffer[0] = 0;
        u64tostr(ObjectTypeDump.HighWaterNumberOfObjects, szConvertBuffer);
        SetDlgItemText(hwndDlg, ID_TYPE_PEAKCOUNT, szConvertBuffer);

        //Peek handle count
        szConvertBuffer[0] = 0;
        u64tostr(ObjectTypeDump.HighWaterNumberOfHandles, szConvertBuffer);
        SetDlgItemText(hwndDlg, ID_TYPE_PEAKHANDLECOUNT, szConvertBuffer);

        //PoolType
        lpTypeDescription = T_Unknown;
        for (i = 0; i < RTL_NUMBER_OF(a_PoolTypes); i++) {
            if (ObjectTypeDump.TypeInfo.PoolType == (POOL_TYPE)a_PoolTypes[i].dwValue) {
                lpTypeDescription = a_PoolTypes[i].lpDescription;
                break;
            }
        }
        SetDlgItemText(hwndDlg, ID_TYPE_POOLTYPE, lpTypeDescription);

        //Default NonPagedPoolCharge
        szConvertBuffer[0] = 0;
        u64tostr(ObjectTypeDump.TypeInfo.DefaultNonPagedPoolCharge, szConvertBuffer);
        SetDlgItemText(hwndDlg, ID_TYPE_NPCHARGE, szConvertBuffer);

        //Default PagedPoolCharge
        szConvertBuffer[0] = 0;
        u64tostr(ObjectTypeDump.TypeInfo.DefaultPagedPoolCharge, szConvertBuffer);
        SetDlgItemText(hwndDlg, ID_TYPE_PPCHARGE, szConvertBuffer);

        //Type flags
        propSetTypeFlags(hwndDlg, ObjectTypeDump.TypeInfo.ObjectTypeFlags);

        //Access rights
        propSetTypeAttributes(hwndDlg, &ObjectTypeDump);
    }
}

/*
* TypePropDialogOnInit
*
* Purpose:
*
* Type Dialog WM_INITDIALOG handler.
*
*/
VOID TypePropDialogOnInit(
    _In_  HWND hwndDlg,
    _In_  LPARAM lParam)
{
    PROPSHEETPAGE* pSheet = NULL;

    pSheet = (PROPSHEETPAGE*)lParam;
    if (pSheet) {
        SetProp(hwndDlg, T_PROPCONTEXT, (HANDLE)pSheet->lParam);
        supLoadIconForObjectType(hwndDlg,
            (PROP_OBJECT_INFO*)pSheet->lParam,
            g_ListViewImages,
            TRUE);
    }
    propSetTypeListView(hwndDlg);
}

/*
* TypePropDialogProc
*
* Purpose:
*
* Type Properties Dialog Procedure
*
* WM_SHOWWINDOW - when wParam is TRUE it sets "Type" page object information.
* WM_INITDIALOG - initialize object attributes listview, set context window prop.
* WM_DESTROY - remove context window prop.
*
*/
INT_PTR CALLBACK TypePropDialogProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    PROP_OBJECT_INFO* Context = NULL;

    switch (uMsg) {
    case WM_SHOWWINDOW:
        Context = (PROP_OBJECT_INFO*)GetProp(hwndDlg, T_PROPCONTEXT);
        if (Context) {
            //show window
            if (wParam) {
                propSetTypeInfo(Context, hwndDlg);
                SendDlgItemMessage(hwndDlg, ID_TYPE_ATTRLIST, LB_SETCURSEL,
                    (WPARAM)0, (LPARAM)0);
                SendMessage(hwndDlg, WM_COMMAND,
                    MAKEWPARAM(ID_TYPE_ATTRLIST, LBN_SELCHANGE), 0);
            }
        }
        return 1;

    case WM_INITDIALOG:
        TypePropDialogOnInit(hwndDlg, lParam);
        return 1;

    case WM_COMMAND:
        if (LOWORD(wParam) == ID_TYPE_ATTRLIST) {
            if (HIWORD(wParam) == LBN_SELCHANGE) {
                Context = (PROP_OBJECT_INFO*)GetProp(hwndDlg, T_PROPCONTEXT);
                if (Context) {
                    propSetTypeDecodedAttributes(Context, hwndDlg);
                }
            }
        }
        return 1;

    case WM_DESTROY:
        RemoveProp(hwndDlg, T_PROPCONTEXT);
        break;
    }
    return 0;
}
