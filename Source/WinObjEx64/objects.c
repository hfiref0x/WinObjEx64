/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2022
*
*  TITLE:       OBJECTS.C
*
*  VERSION:     2.01
*
*  DATE:        18 Dec 2022
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

WOBJ_TYPE_DESC g_TypeUnknown = { OBTYPE_NAME_UNKNOWN, 0, ObjectTypeUnknown, IDI_ICON_UNKNOWN, IDS_DESC_UNKNOWN };

WOBJ_TYPE_DESC g_TypeActivationObject = { L"ActivationObject", 0xde960015, ObjectTypeActivationObject, IDI_ICON_ACTIVATIONOBJECT, IDS_DESC_ACTIVATIONOBJECT };
WOBJ_TYPE_DESC g_TypeActivityReference = { L"ActivityReference", 0x44db295c, ObjectTypeActivityReference, IDI_ICON_ACTIVITYREFERENCE, IDS_DESC_ACTIVITYREFERENCE };
WOBJ_TYPE_DESC g_TypeAdapter = { L"Adapter", 0x5b4bfe0f, ObjectTypeAdapter, IDI_ICON_ADAPTER, IDS_DESC_ADAPTER };
WOBJ_TYPE_DESC g_TypePort = { L"ALPC Port", 0xfc99f003, ObjectTypePort, IDI_ICON_PORT, IDS_DESC_PORT };
WOBJ_TYPE_DESC g_TypeCallback = { L"Callback", 0xd619e0a5, ObjectTypeCallback, IDI_ICON_CALLBACK, IDS_DESC_CALLBACK };
WOBJ_TYPE_DESC g_TypeComposition = { L"Composition", 0xf009caea, ObjectTypeComposition, IDI_ICON_DXOBJECT, IDS_DESC_COMPOSITION };
WOBJ_TYPE_DESC g_TypeController = { L"Controller", 0x38a0df3c, ObjectTypeController, IDI_ICON_CONTROLLER, IDS_DESC_CONTROLLER };
WOBJ_TYPE_DESC g_TypeCoreMessaging = { L"CoreMessaging", 0x86bcebe5, ObjectTypeCoreMessaging, IDI_ICON_COREMESSAGING, IDS_DESC_COREMESSAGING };
WOBJ_TYPE_DESC g_TypeCoverageSampler = { L"CoverageSampler", 0xb6a0f960, ObjectTypeCoverageSampler, IDI_ICON_COVERAGESAMPLER, IDS_DESC_COVERAGESAMPLER };
WOBJ_TYPE_DESC g_TypeCpuPartition = { L"CpuPartition", 0xafdf1c82, ObjectTypeCpuPartition, IDI_ICON_CPUPARTITION, IDS_DESC_CPUPARTITION };
WOBJ_TYPE_DESC g_TypeDebugObject = { L"DebugObject", 0x8282e52, ObjectTypeDebugObject, IDI_ICON_DEBUGOBJECT, IDS_DESC_DEBUGOBJECT };
WOBJ_TYPE_DESC g_TypeDesktop = { OBTYPE_NAME_DESKTOP, 0xd1ffc79c, ObjectTypeDesktop, IDI_ICON_DESKTOP, IDS_DESC_DESKTOP };
WOBJ_TYPE_DESC g_TypeDevice = { L"Device", OBTYPE_HASH_DEVICE, ObjectTypeDevice, IDI_ICON_DEVICE, IDS_DESC_DEVICE };
WOBJ_TYPE_DESC g_TypeDirectory = { OBTYPE_NAME_DIRECTORY, OBTYPE_HASH_DIRECTORY, ObjectTypeDirectory, IDI_ICON_DIRECTORY, IDS_DESC_DIRECTORY };
WOBJ_TYPE_DESC g_TypeDmaAdapter = { L"DmaAdapter", 0x2201d697, ObjectTypeDmaAdapter, IDI_ICON_HALDMA, IDS_DESC_DMAADAPTER };
WOBJ_TYPE_DESC g_TypeDmaDomain = { L"DmaDomain", 0xfe7e671c, ObjectTypeDmaDomain, IDI_ICON_HALDMA, IDS_DESC_DMADOMAIN };
WOBJ_TYPE_DESC g_TypeDriver = { L"Driver", OBTYPE_HASH_DRIVER, ObjectTypeDriver, IDI_ICON_DRIVER, IDS_DESC_DRIVER };
WOBJ_TYPE_DESC g_TypeDxgkCompositionObject = { L"DxgkCompositionObject", 0xf2bf1f91, ObjectTypeDxgkComposition, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_COMPOSITION_OBJECT };
WOBJ_TYPE_DESC g_TypeDxgkCurrentDxgProcessObject = { L"DxgkCurrentDxgProcessObject", 0xc27e9d7c, ObjectTypeDxgkCurrentDxgProcessObject, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_CURRENT_DXG_PROCESS_OBJECT };
WOBJ_TYPE_DESC g_TypeDxgkCurrentDxgThreadObject = { L"DxgkCurrentDxgThreadObject", 0xc8d07f5b, ObjectTypeDxgkCurrentDxgThreadObject, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_CURRENT_DXG_THREAD_OBJECT };
WOBJ_TYPE_DESC g_TypeDxgkDisplayManagerObject = { L"DxgkDisplayManagerObject", 0x5afc4062, ObjectTypeDxgkDisplayManager, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_DISPLAY_MANAGER_OBJECT };
WOBJ_TYPE_DESC g_TypeDxgkSharedBundleObject = { L"DxgkSharedBundleObject", 0xf7e4ab9e, ObjectTypeDxgkSharedBundle, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_SHARED_BUNDLE_OBJECT };
WOBJ_TYPE_DESC g_TypeDxgkSharedKeyedMutexObject = { L"DxgkSharedKeyedMutexObject", 0xd6c628fd, ObjectTypeDxgkSharedKeyedMutex, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_SHARED_KEYED_MUTEX_OBJECT };
WOBJ_TYPE_DESC g_TypeDxgkSharedProtectedSessionObject = { L"DxgkSharedProtectedSessionObject", 0xa9676f44, ObjectTypeDxgkSharedProtectedSession, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_SHARED_PROTECTED_SESSION_OBJECT };
WOBJ_TYPE_DESC g_TypeDxgkSharedResource = { L"DxgkSharedResource", 0x632e6c2b, ObjectTypeDxgkSharedResource, IDI_ICON_DXOBJECT, IDS_DESC_DXGKSHAREDRES };
WOBJ_TYPE_DESC g_TypeDxgkSharedSwapChainObject = { L"DxgkSharedSwapChainObject", 0xf5053210, ObjectTypeDxgkSharedSwapChain, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_SHARED_SWAPCHAIN };
WOBJ_TYPE_DESC g_TypeDxgkSharedSyncObject = { L"DxgkSharedSyncObject", 0xa29968d7, ObjectTypeDxgkSharedSyncObject, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_SHARED_SYNC };
WOBJ_TYPE_DESC g_TypeEnergyTracker = { L"EnergyTracker", 0x4dcec6d0, ObjectTypeEnergyTracker, IDI_ICON_ENERGYTRACKER, IDS_DESC_ENERGYTRACKER };
WOBJ_TYPE_DESC g_TypeEtwConsumer = { L"EtwConsumer", 0x31a53abe, ObjectTypeETWConsumer, IDI_ICON_ETWCONSUMER, IDS_DESC_ETWCONSUMER };
WOBJ_TYPE_DESC g_TypeEtwRegistration = { L"EtwRegistration", 0x89b06481, ObjectTypeETWRegistration, IDI_ICON_ETWREGISTRATION, IDS_DESC_ETWREGISTRATION };
WOBJ_TYPE_DESC g_TypeEtwSessionDemuxEntry = { L"EtwSessionDemuxEntry", 0x4ce2d111, ObjectTypeEtwSessionDemuxEntry, IDI_ICON_ETWSESSIONDEMUXENTRY, IDS_DESC_ETWSESSIONDEMUXENTRY };
WOBJ_TYPE_DESC g_TypeEvent = { L"Event", 0xf3040cba, ObjectTypeEvent, IDI_ICON_EVENT, IDS_DESC_EVENT };
WOBJ_TYPE_DESC g_TypeEventPair = { L"EventPair", 0x97834894, ObjectTypeEventPair, IDI_ICON_EVENTPAIR, IDS_DESC_EVENTPAIR };
WOBJ_TYPE_DESC g_TypeFile = { OBTYPE_NAME_FILE, 0xecfd8b1c, ObjectTypeFile, IDI_ICON_FILE, IDS_DESC_FILE };
WOBJ_TYPE_DESC g_TypeFilterCommunicationPort = { L"FilterCommunicationPort", 0x7849195f, ObjectTypeFltComnPort, IDI_ICON_FLTCOMMPORT, IDS_DESC_FLT_COMM_PORT };
WOBJ_TYPE_DESC g_TypeFilterConnectionPort = { L"FilterConnectionPort", 0x4598bf7, ObjectTypeFltConnPort, IDI_ICON_FLTCONNPORT, IDS_DESC_FLT_CONN_PORT };
WOBJ_TYPE_DESC g_TypeIoCompletion = { L"IoCompletion", 0xbc81c342, ObjectTypeIoCompletion, IDI_ICON_IOCOMPLETION, IDS_DESC_IOCOMPLETION };
WOBJ_TYPE_DESC g_TypeIoCompletionReserve = { L"IoCompletionReserve", 0xca6e211a, ObjectTypeIoCompletionReserve, IDI_ICON_IOCOMPLETION, IDS_DESC_IOCOMPLETIONRESERVE };
WOBJ_TYPE_DESC g_TypeIoRing = { L"IoRing", 0xe17640f6, ObjectTypeIoRing, IDI_ICON_IORING, IDS_DESC_IORING };
WOBJ_TYPE_DESC g_TypeIRTimer = { L"IRTimer", 0xc161a6dc, ObjectTypeIRTimer, IDI_ICON_IRTIMER, IDS_DESC_IRTIMER };
WOBJ_TYPE_DESC g_TypeJob = { L"Job", 0x24df96fd, ObjectTypeJob, IDI_ICON_JOB, IDS_DESC_JOB };
WOBJ_TYPE_DESC g_TypeKey = { L"Key", 0x2553a41f, ObjectTypeKey, IDI_ICON_KEY, IDS_DESC_KEY };
WOBJ_TYPE_DESC g_TypeKeyedEvent = { L"KeyedEvent", 0x6c3a045c, ObjectTypeKeyedEvent, IDI_ICON_KEYEDEVENT, IDS_DESC_KEYEDEVENT };
WOBJ_TYPE_DESC g_TypeMutant = { L"Mutant", 0xfba93d5b, ObjectTypeMutant, IDI_ICON_MUTANT, IDS_DESC_MUTANT };
WOBJ_TYPE_DESC g_TypeNdisCmState = { L"NdisCmState", 0x28077967, ObjectTypeNdisCmState, IDI_ICON_NDISCMSTATE, IDS_DESC_NDISCMSTATE };
WOBJ_TYPE_DESC g_TypePartition = { L"Partition", 0x5227054a, ObjectTypeMemoryPartition, IDI_ICON_MEMORYPARTITION, IDS_DESC_MEMORY_PARTITION };
WOBJ_TYPE_DESC g_TypePcwObject = { L"PcwObject", 0xe3f801c3, ObjectTypePcwObject, IDI_ICON_PCWOBJECT, IDS_DESC_PCWOBJECT };
WOBJ_TYPE_DESC g_TypePowerRequest = { L"PowerRequest", 0xb5a1b3ea, ObjectTypePowerRequest, IDI_ICON_POWERREQUEST, IDS_DESC_POWERREQUEST };
WOBJ_TYPE_DESC g_TypeProcess = { OBTYPE_NAME_PROCESS, 0x70fcfc4f, ObjectTypeProcess, IDI_ICON_PROCESS, IDS_DESC_PROCESS };
WOBJ_TYPE_DESC g_TypeProcessStateChange = { L"ProcessStateChange", 0x6fd57b92, ObjectTypeProcessStateChange, IDI_ICON_PROCESSSTATECHANGE, IDS_DESC_PROCESSSTATECHANGE };
WOBJ_TYPE_DESC g_TypeProfile = { L"Profile", 0xfe82aac9, ObjectTypeProfile, IDI_ICON_PROFILE, IDS_DESC_PROFILE };
WOBJ_TYPE_DESC g_TypePsSiloContextNonPaged = { L"PsSiloContextNonPaged", 0xe2c391fb, ObjectTypePsSiloContextNonPaged, IDI_ICON_PSSILOCONTEXT, IDS_DESC_PSSILOCONTEXTNP };
WOBJ_TYPE_DESC g_TypePsSiloContextPaged = { L"PsSiloContextPaged", 0x8f91f0a2, ObjectTypePsSiloContextPaged, IDI_ICON_PSSILOCONTEXT, IDS_DESC_PSSILOCONTEXT };
WOBJ_TYPE_DESC g_TypeRawInputManager = { L"RawInputManager", 0xf28870cb, ObjectTypeRawInputManager, IDI_ICON_RAWINPUTMANAGER, IDS_DESC_RAWINPUTMANAGER };
WOBJ_TYPE_DESC g_TypeRegistryTransaction = { L"RegistryTransaction", 0xba530c61, ObjectTypeRegistryTransaction, IDI_ICON_KEY, IDS_DESC_REGISTRY_TRANSACTION };
WOBJ_TYPE_DESC g_TypeSchedulerSharedData = { L"SchedulerSharedData", 0xa4930ca, ObjectTypeSchedulerSharedData, IDI_ICON_SCHEDULERSHAREDDATA, IDS_DESC_SCHEDULERSHAREDDATA };
WOBJ_TYPE_DESC g_TypeSection = { L"Section", OBTYPE_HASH_SECTION, ObjectTypeSection, IDI_ICON_SECTION, IDS_DESC_SECTION };
WOBJ_TYPE_DESC g_TypeSemaphore = { L"Semaphore", 0x33b553e4, ObjectTypeSemaphore, IDI_ICON_SEMAPHORE, IDS_DESC_SEMAPHORE };
WOBJ_TYPE_DESC g_TypeSession = { L"Session", 0xcd4f9c96, ObjectTypeSession, IDI_ICON_SESSION, IDS_DESC_SESSION };
WOBJ_TYPE_DESC g_TypeSymbolicLink = { L"SymbolicLink", OBTYPE_HASH_SYMBOLIC_LINK, ObjectTypeSymbolicLink, IDI_ICON_SYMLINK, IDS_DESC_SYMLINK };
WOBJ_TYPE_DESC g_TypeTerminal = { L"Terminal", 0x17fd8d1c, ObjectTypeTerminal, IDI_ICON_TERMINAL, IDS_DESC_TERMINAL };
WOBJ_TYPE_DESC g_TypeTerminalEventQueue = { L"TerminalEventQueue", 0x87c5d493, ObjectTypeTerminalEventQueue, IDI_ICON_TERMINALEVENTQUEUE, IDS_DESC_TERMINALEVENTQUEUE };
WOBJ_TYPE_DESC g_TypeThread = { OBTYPE_NAME_THREAD, 0xc8bcac4a, ObjectTypeThread, IDI_ICON_THREAD, IDS_DESC_THREAD };
WOBJ_TYPE_DESC g_TypeThreadStateChange = { L"ThreadStateChange", 0x88afedd7, ObjectTypeThreadStateChange, IDI_ICON_THREADSTATECHANGE, IDS_DESC_THREADSTATECHANGE };
WOBJ_TYPE_DESC g_TypeTimer = { L"Timer", 0x94ec7de5, ObjectTypeTimer, IDI_ICON_TIMER, IDS_DESC_TIMER };
WOBJ_TYPE_DESC g_TypeTmEn = { L"TmEn", 0x7a2e2a02, ObjectTypeTmEn, IDI_ICON_TMEN, IDS_DESC_TMEN };
WOBJ_TYPE_DESC g_TypeTmRm = { L"TmRm", 0x7a3b2d34, ObjectTypeTmRm, IDI_ICON_TMRM, IDS_DESC_TMRM };
WOBJ_TYPE_DESC g_TypeTmTm = { L"TmTm", 0x7a3d2db2, ObjectTypeTmTm, IDI_ICON_TMTM, IDS_DESC_TMTM };
WOBJ_TYPE_DESC g_TypeTmTx = { L"TmTx", 0x7a3d2dbd, ObjectTypeTmTx, IDI_ICON_TMTX, IDS_DESC_TMTX };
WOBJ_TYPE_DESC g_TypeToken = { OBTYPE_NAME_TOKEN, 0xab194359, ObjectTypeToken, IDI_ICON_TOKEN, IDS_DESC_TOKEN };
WOBJ_TYPE_DESC g_TypeTpWorkerFactory = { L"TpWorkerFactory", 0x84a8cd0, ObjectTypeTpWorkerFactory, IDI_ICON_TPWORKERFACTORY,IDS_DESC_TPWORKERFACTORY };
WOBJ_TYPE_DESC g_TypeType = { L"Type", OBTYPE_HASH_TYPE, ObjectTypeType, IDI_ICON_TYPE, IDS_DESC_TYPE };
WOBJ_TYPE_DESC g_TypeUserApcReserve = { L"UserApcReserve", 0xa3fa2453, ObjectTypeUserApcReserve, IDI_ICON_USERAPCRESERVE, IDS_DESC_USERAPCRESERVE };
WOBJ_TYPE_DESC g_TypeVirtualKey = { L"VirtualKey", 0x77158ef4, ObjectTypeVirtualKey, IDI_ICON_VIRTUALKEY, IDS_DESC_VIRTUALKEY };
WOBJ_TYPE_DESC g_TypeVRegConfigurationContext = { L"VRegConfigurationContext", 0x783eeab7, ObjectTypeVRegConfigurationContext, IDI_ICON_VREGCFGCTX, IDS_DESC_VREGCFGCTX };
WOBJ_TYPE_DESC g_TypeWaitablePort = { L"WaitablePort", 0x66debaf0, ObjectTypeWaitablePort, IDI_ICON_WAITABLEPORT, IDS_DESC_WAITABLEPORT };
WOBJ_TYPE_DESC g_TypeWaitCompletionPacket = { L"WaitCompletionPacket", 0xdaa80e19, ObjectTypeWaitCompletionPacket, IDI_ICON_WAITCOMPLETIONPACKET, IDS_DESC_WAITCOMPLETIONPACKET };
WOBJ_TYPE_DESC g_TypeWinstation = { L"WindowStation", OBTYPE_HASH_WINSTATION, ObjectTypeWinstation, IDI_ICON_WINSTATION, IDS_DESC_WINSTATION };
WOBJ_TYPE_DESC g_TypeWmiGuid = { L"WmiGuid", 0x36d9823c, ObjectTypeWMIGuid, IDI_ICON_WMIGUID, IDS_DESC_WMIGUID };

//
// Array items must be always sorted by object type name.
//
static WOBJ_TYPE_DESC* gpObjectTypes[] = {
    &g_TypeActivationObject,
    &g_TypeActivityReference,
    &g_TypeAdapter,
    &g_TypePort,
    &g_TypeCallback,
    &g_TypeComposition,
    &g_TypeController,
    &g_TypeCoreMessaging,
    &g_TypeCoverageSampler,
    &g_TypeCpuPartition,
    &g_TypeDebugObject,
    &g_TypeDesktop,
    &g_TypeDevice,
    &g_TypeDirectory,
    &g_TypeDmaAdapter,
    &g_TypeDmaDomain,
    &g_TypeDriver,
    &g_TypeDxgkCompositionObject,
    &g_TypeDxgkCurrentDxgProcessObject,
    &g_TypeDxgkCurrentDxgThreadObject,
    &g_TypeDxgkDisplayManagerObject,
    &g_TypeDxgkSharedBundleObject,
    &g_TypeDxgkSharedKeyedMutexObject,
    &g_TypeDxgkSharedProtectedSessionObject,
    &g_TypeDxgkSharedResource,
    &g_TypeDxgkSharedSwapChainObject,
    &g_TypeDxgkSharedSyncObject,
    &g_TypeEnergyTracker,
    &g_TypeEtwConsumer,
    &g_TypeEtwRegistration,
    &g_TypeEtwSessionDemuxEntry,
    &g_TypeEvent,
    &g_TypeEventPair,
    &g_TypeFile,
    &g_TypeFilterCommunicationPort,
    &g_TypeFilterConnectionPort,
    &g_TypeIoCompletion,
    &g_TypeIoCompletionReserve,
    &g_TypeIoRing,
    &g_TypeIRTimer,
    &g_TypeJob,
    &g_TypeKey,
    &g_TypeKeyedEvent,
    &g_TypeMutant,
    &g_TypeNdisCmState,
    &g_TypePartition,
    &g_TypePcwObject,
    &g_TypePowerRequest,
    &g_TypeProcess,
    &g_TypeProcessStateChange,
    &g_TypeProfile,
    &g_TypePsSiloContextNonPaged,
    &g_TypePsSiloContextPaged,
    &g_TypeRawInputManager,
    &g_TypeRegistryTransaction,
    &g_TypeSchedulerSharedData,
    &g_TypeSection,
    &g_TypeSemaphore,
    &g_TypeSession,
    &g_TypeSymbolicLink,
    &g_TypeTerminal,
    &g_TypeTerminalEventQueue,
    &g_TypeThread,
    &g_TypeThreadStateChange,
    &g_TypeTimer,
    &g_TypeTmEn,
    &g_TypeTmRm,
    &g_TypeTmTm,
    &g_TypeTmTx,
    &g_TypeToken,
    &g_TypeTpWorkerFactory,
    &g_TypeType,
    &g_TypeUserApcReserve,
    &g_TypeVirtualKey,
    &g_TypeVRegConfigurationContext,
    &g_TypeWaitablePort,
    &g_TypeWaitCompletionPacket,
    &g_TypeWinstation,
    &g_TypeWmiGuid
};

//
// Number of items in gpObjectTypes array, RTL_NUMBER_OF(gpObjectTypes)
//
ULONG g_ObjectTypesCount = RTL_NUMBER_OF(gpObjectTypes);

/*
* ObManagerComparerName
*
* Purpose:
*
* Support comparer routine to work with objects array.
*
*/
INT ObManagerComparerName(
    _In_ PCVOID FirstObject,
    _In_ PCVOID SecondObject
)
{
    WOBJ_TYPE_DESC* firstObject = (WOBJ_TYPE_DESC*)FirstObject;
    WOBJ_TYPE_DESC* secondObject = *(WOBJ_TYPE_DESC**)SecondObject;

    if (firstObject == secondObject)
        return 0;

    return (_strcmpi(firstObject->Name, secondObject->Name));
}

/*
* ObManagerGetNameByIndex
*
* Purpose:
*
* Returns object name by index of known type.
*
*/
LPWSTR ObManagerGetNameByIndex(
    _In_ WOBJ_OBJECT_TYPE TypeIndex
)
{
    ULONG nIndex;

    for (nIndex = 0; nIndex < g_ObjectTypesCount; nIndex++) {
        if (gpObjectTypes[nIndex]->Index == TypeIndex)
            return gpObjectTypes[nIndex]->Name;
    }

    return OBTYPE_NAME_UNKNOWN;
}

/*
* ObManagerGetImageIndexByTypeIndex
*
* Purpose:
*
* Returns object image index by index of known type.
*
*
*/
UINT ObManagerGetImageIndexByTypeIndex(
    _In_ WOBJ_OBJECT_TYPE TypeIndex
)
{
    ULONG i;

    for (i = 0; i < g_ObjectTypesCount; i++) {
        if (gpObjectTypes[i]->Index == TypeIndex)
            return gpObjectTypes[i]->ImageIndex;
    }

    return ObjectTypeUnknown;
}

/*
* ObManagerGetEntryByTypeIndex
*
* Purpose:
*
* Returns object entry by type index.
*
*/
WOBJ_TYPE_DESC* ObManagerGetEntryByTypeIndex(
    _In_ WOBJ_OBJECT_TYPE TypeIndex
)
{
    ULONG i;

    for (i = 0; i < g_ObjectTypesCount; i++) {
        if (gpObjectTypes[i]->Index == TypeIndex)
            return gpObjectTypes[i];
    }

    return &g_TypeUnknown;
}

/*
* ObManagerGetEntryByTypeName
*
* Purpose:
*
* Returns object description entry by type name.
*
*/
WOBJ_TYPE_DESC* ObManagerGetEntryByTypeName(
    _In_opt_ LPCWSTR lpTypeName
)
{
    WOBJ_TYPE_DESC searchItem;
    WOBJ_TYPE_DESC* result;
    PVOID lookupItem;

    if (lpTypeName == NULL) {
        return &g_TypeUnknown;
    }

    searchItem.Name = (LPWSTR)lpTypeName;

    lookupItem = supBSearch((PCVOID)&searchItem,
        (PCVOID)gpObjectTypes,
        g_ObjectTypesCount,
        sizeof(PVOID),
        ObManagerComparerName);

    if (lookupItem == NULL) {
        result = &g_TypeUnknown;
    }
    else {
        result = *(WOBJ_TYPE_DESC**)lookupItem;
    }

    return result;
}

/*
* ObManagerGetIndexByTypeName
*
* Purpose:
*
* Returns object index of known type.
*
*/
WOBJ_OBJECT_TYPE ObManagerGetIndexByTypeName(
    _In_opt_ LPCWSTR lpTypeName
)
{
    WOBJ_TYPE_DESC* lookupItem = ObManagerGetEntryByTypeName(lpTypeName);

    return lookupItem->Index;
}

/*
* ObManagerGetImageIndexByTypeName
*
* Purpose:
*
* Returns object image index of known type.
*
*/
UINT ObManagerGetImageIndexByTypeName(
    _In_opt_ LPCWSTR lpTypeName
)
{
    WOBJ_TYPE_DESC* lookupItem = ObManagerGetEntryByTypeName(lpTypeName);

    return lookupItem->ImageIndex;
}

/*
* ObManagerLoadImageForType
*
* Purpose:
*
* Load image of the given id.
*
*/
INT ObManagerLoadImageForType(
    _In_ HIMAGELIST ImageList,
    _In_ INT ResourceImageId
)
{
    INT ImageIndex = I_IMAGENONE;
    HICON hIcon;

    hIcon = (HICON)LoadImage(g_WinObj.hInstance,
        MAKEINTRESOURCE(ResourceImageId),
        IMAGE_ICON,
        16,
        16,
        LR_DEFAULTCOLOR);

    if (hIcon) {
        ImageIndex = ImageList_ReplaceIcon(ImageList, -1, hIcon);
        DestroyIcon(hIcon);
    }

    return ImageIndex;
}

/*
* ObManagerLoadImageList
*
* Purpose:
*
* Create and load image list from icon resource type.
*
*/
HIMAGELIST ObManagerLoadImageList(
    VOID
)
{
    UINT       i;
    HIMAGELIST ImageList;

    ImageList = ImageList_Create(
        16,
        16,
        ILC_COLOR32 | ILC_MASK,
        g_ObjectTypesCount,
        8);

    if (ImageList) {

        for (i = 0; i < g_ObjectTypesCount; i++) {

            gpObjectTypes[i]->ImageIndex = ObManagerLoadImageForType(ImageList,
                gpObjectTypes[i]->ResourceImageId);

        }

        g_TypeUnknown.ImageIndex = ObManagerLoadImageForType(ImageList,
            g_TypeUnknown.ResourceImageId);

    }
    return ImageList;
}

PVOID ObManagerTable()
{
    return (PVOID)gpObjectTypes;
}

VOID ObManagerTest()
{
    ULONG hashValue;

    UINT i;

    for (i = 0; i < g_ObjectTypesCount; i++)
        kdDebugPrint("%ws\r\n", gpObjectTypes[i]->Name);

    for (i = 0; i < g_ObjectTypesCount; i++) {

        hashValue = supHashString(gpObjectTypes[i]->Name, (ULONG)_strlen(gpObjectTypes[i]->Name));
        kdDebugPrint("%ws = 0x%lx\r\n", gpObjectTypes[i]->Name, hashValue);
        if (hashValue != gpObjectTypes[i]->NameHash)
            MessageBox(GetDesktopWindow(), L"Wrong type hash", gpObjectTypes[i]->Name, MB_OK);

    }
}
