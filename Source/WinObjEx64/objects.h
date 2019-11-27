/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019
*
*  TITLE:       OBJECTS.H
*
*  VERSION:     1.82
*
*  DATE:        13 Nov 2019
*
*  Header file for internal Windows object types handling.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

//
// Object Type Indexes Used By Program Only 
// NOT RELATED TO REAL OBJECTS INDEXES
// ObjectTypeUnknown and ObjectTypeMax always end this list
//
typedef enum _WOBJ_OBJECT_TYPE {
    ObjectTypeDevice = 0,
    ObjectTypeDriver = 1,
    ObjectTypeSection = 2,
    ObjectTypePort = 3,
    ObjectTypeSymbolicLink = 4,
    ObjectTypeKey = 5,
    ObjectTypeEvent = 6,
    ObjectTypeJob = 7,
    ObjectTypeMutant = 8,
    ObjectTypeKeyedEvent = 9,
    ObjectTypeType = 10,
    ObjectTypeDirectory = 11,
    ObjectTypeWinstation = 12,
    ObjectTypeCallback = 13,
    ObjectTypeSemaphore = 14,
    ObjectTypeWaitablePort = 15,
    ObjectTypeTimer = 16,
    ObjectTypeSession = 17,
    ObjectTypeController = 18,
    ObjectTypeProfile = 19,
    ObjectTypeEventPair = 20,
    ObjectTypeDesktop = 21,
    ObjectTypeFile = 22,
    ObjectTypeWMIGuid = 23,
    ObjectTypeDebugObject = 24,
    ObjectTypeIoCompletion = 25,
    ObjectTypeProcess = 26,
    ObjectTypeAdapter = 27,
    ObjectTypeToken = 28,
    ObjectTypeETWRegistration = 29,
    ObjectTypeThread = 30,
    ObjectTypeTmTx = 31,
    ObjectTypeTmTm = 32,
    ObjectTypeTmRm = 33,
    ObjectTypeTmEn = 34,
    ObjectTypePcwObject = 35,
    ObjectTypeFltConnPort = 36,
    ObjectTypeFltComnPort = 37,
    ObjectTypePowerRequest = 38,
    ObjectTypeETWConsumer = 39,
    ObjectTypeTpWorkerFactory = 40,
    ObjectTypeComposition = 41,
    ObjectTypeIRTimer = 42,
    ObjectTypeDxgkSharedResource = 43,
    ObjectTypeDxgkSharedSwapChain = 44,
    ObjectTypeDxgkSharedSyncObject = 45,
    ObjectTypeDxgkCurrentDxgProcessObject = 46,
    ObjectTypeDxgkCurrentDxgThreadObject = 47,
    ObjectTypeDxgkDisplayManager = 48,
    ObjectTypeDxgkSharedBundle = 49,
    ObjectTypeDxgkSharedProtectedSession = 50,
    ObjectTypeDxgkComposition = 51,
    ObjectTypeDxgkSharedKeyedMutex = 52,
    ObjectTypeMemoryPartition = 53,
    ObjectTypeRegistryTransaction = 54,
    ObjectTypeDmaAdapter = 55,
    ObjectTypeDmaDomain = 56,
    ObjectTypeUnknown = 57,
    ObjectTypeMax
} WOBJ_OBJECT_TYPE;

typedef struct _WOBJ_TYPE_DESC {
    LPWSTR Name;
    WOBJ_OBJECT_TYPE Index; //object type
    INT ResourceImageId; //resouce id for icon
    INT ResourceStringId; //resource id in stringtable
    INT ImageIndex; //individual image id for each object type (maybe the same for few objects)
} WOBJ_TYPE_DESC, *PWOBJ_TYPE_DESC;

#define OBTYPE_NAME_DESKTOP         L"Desktop"
#define OBTYPE_NAME_DEVICE          L"Device"
#define OBTYPE_NAME_DRIVER          L"Driver"
#define OBTYPE_NAME_DIRECTORY       L"Directory"
#define OBTYPE_NAME_FILE            L"File"
#define OBTYPE_NAME_PROCESS         L"Process"
#define OBTYPE_NAME_SECTION         L"Section"
#define OBTYPE_NAME_SYMBOLIC_LINK   L"SymbolicLink"
#define OBTYPE_NAME_THREAD          L"Thread"
#define OBTYPE_NAME_TOKEN           L"Token"
#define OBTYPE_NAME_TYPE            L"Type"
#define OBTYPE_NAME_WINSTATION      L"WindowStation"
#define OBTYPE_NAME_UNKNOWN         L""

static WOBJ_TYPE_DESC g_TypeUnknown = { OBTYPE_NAME_UNKNOWN, ObjectTypeUnknown, IDI_ICON_UNKNOWN, IDS_DESC_UNKNOWN };

//
// Handled object types.
//
// Sorted in alphabetical order.
//
static WOBJ_TYPE_DESC g_ObjectTypes[] = {
    //{ L"ActivationObject", ObjectTypeActivationObject, IDI_ICON_ACTIVATIONOBJECT, IDS_DESC_ACTIVATIONOBJECT },
    //{ L"ActivityReference", ObjectTypeActivityReference, IDI_ICON_ACTIVITYREFERENCE, IDS_DESC_ACTIVITYREFERENCE },
    { L"Adapter", ObjectTypeAdapter, IDI_ICON_ADAPTER, IDS_DESC_ADAPTER },
    { L"ALPC Port", ObjectTypePort, IDI_ICON_PORT, IDS_DESC_PORT },
    { L"Callback", ObjectTypeCallback, IDI_ICON_CALLBACK, IDS_DESC_CALLBACK },
    { L"Composition", ObjectTypeComposition, IDI_ICON_COMPOSITION, IDS_DESC_COMPOSITION },
    { L"Controller", ObjectTypeController, IDI_ICON_CONTROLLER, IDS_DESC_CONTROLLER },
    //{ L"CoreMessaging", ObjectTypeCoreMessaging, IDI_ICON_COREMESSAGING, IDS_DESC_COREMESSAGING },
    //{ L"CoverageSampler", ObjectTypeCoverageSampler, IDI_ICON_COVERAGESAMPLER, IDS_DESC_COVERAGESAMPLER },
    { L"DebugObject", ObjectTypeDebugObject, IDI_ICON_DEBUGOBJECT, IDS_DESC_DEBUGOBJECT },
    { OBTYPE_NAME_DESKTOP, ObjectTypeDesktop, IDI_ICON_DESKTOP, IDS_DESC_DESKTOP },
    { OBTYPE_NAME_DEVICE, ObjectTypeDevice, IDI_ICON_DEVICE, IDS_DESC_DEVICE },
    { OBTYPE_NAME_DIRECTORY, ObjectTypeDirectory, IDI_ICON_DIRECTORY, IDS_DESC_DIRECTORY },
    { L"DmaAdapter", ObjectTypeDmaAdapter, IDI_ICON_HALDMA, IDS_DESC_DMAADAPTER },
    { L"DmaDomain", ObjectTypeDmaDomain, IDI_ICON_HALDMA, IDS_DESC_DMADOMAIN },
    { OBTYPE_NAME_DRIVER, ObjectTypeDriver, IDI_ICON_DRIVER, IDS_DESC_DRIVER },
    { L"DxgkCompositionObject", ObjectTypeDxgkComposition, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_COMPOSITION_OBJECT },
    { L"DxgkCurrentDxgProcessObject", ObjectTypeDxgkCurrentDxgProcessObject, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_CURRENT_DXG_PROCESS_OBJECT },
    { L"DxgkCurrentDxgThreadObject", ObjectTypeDxgkCurrentDxgThreadObject, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_CURRENT_DXG_THREAD_OBJECT },
    { L"DxgkDisplayManagerObject", ObjectTypeDxgkDisplayManager, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_DISPLAY_MANAGER_OBJECT },
    { L"DxgkSharedBundleObject", ObjectTypeDxgkSharedBundle, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_SHARED_BUNDLE_OBJECT },
    { L"DxgkSharedKeyedMutexObject", ObjectTypeDxgkSharedKeyedMutex, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_SHARED_KEYED_MUTEX_OBJECT},
    { L"DxgkSharedProtectedSessionObject", ObjectTypeDxgkSharedProtectedSession, IDI_ICON_DXOBJECT, IDS_DESC_DXGK_SHARED_PROTECTED_SESSION_OBJECT },
    { L"DxgkSharedResource", ObjectTypeDxgkSharedResource, IDI_ICON_DXOBJECT, IDS_DESC_DXGKSHAREDRES },
    { L"DxgkSharedSwapChainObject", ObjectTypeDxgkSharedSwapChain, IDI_ICON_DXOBJECT, IDS_DESC_DXGKSHAREDSWAPCHAIN },
    { L"DxgkSharedSyncObject", ObjectTypeDxgkSharedSyncObject, IDI_ICON_DXOBJECT, IDS_DESC_DXGKSHAREDSYNC },
    { L"EtwConsumer", ObjectTypeETWConsumer, IDI_ICON_ETWCONSUMER, IDS_DESC_ETWCONSUMER },
    { L"EtwRegistration", ObjectTypeETWRegistration, IDI_ICON_ETWREGISTRATION, IDS_DESC_ETWREGISTRATION },
    // { L"EtwSessionDemuxEntry", ObjectTypeEtwSessionDemuxEntry, IDI_ICON_ETWSESSIONDEMUXENTRY, IDS_DESC_ETWSESSIONDEMUXENTRY },
    { L"Event", ObjectTypeEvent, IDI_ICON_EVENT, IDS_DESC_EVENT },
    { L"EventPair", ObjectTypeEventPair, IDI_ICON_EVENTPAIR, IDS_DESC_EVENTPAIR },
    { OBTYPE_NAME_FILE, ObjectTypeFile, IDI_ICON_FILE, IDS_DESC_FILE },
    { L"FilterCommunicationPort", ObjectTypeFltComnPort, IDI_ICON_FLTCOMMPORT, IDS_DESC_FLT_COMM_PORT },
    { L"FilterConnectionPort", ObjectTypeFltConnPort, IDI_ICON_FLTCONNPORT, IDS_DESC_FLT_CONN_PORT },
    { L"IoCompletion", ObjectTypeIoCompletion, IDI_ICON_IOCOMPLETION, IDS_DESC_IOCOMPLETION },
    //{ L"IoCompletionReserve", ObjectTypeIoCompletionReserve, IDI_ICON_IOCOMPLETION_RESERVE, IDS_DESC_IOCOMPLETION_RESERVE },
    { L"IRTimer", ObjectTypeIRTimer, IDI_ICON_IRTIMER, IDS_DESC_IRTIMER },
    { L"Job", ObjectTypeJob, IDI_ICON_JOB, IDS_DESC_JOB },
    { L"Key", ObjectTypeKey, IDI_ICON_KEY, IDS_DESC_KEY },
    { L"KeyedEvent", ObjectTypeKeyedEvent, IDI_ICON_KEYEDEVENT, IDS_DESC_KEYEDEVENT },
    { L"Mutant", ObjectTypeMutant, IDI_ICON_MUTANT, IDS_DESC_MUTANT },
    //{ L"NdisCmState", ObjectTypeNdisCmState, IDI_ICON_NDISCMSTATE, IDS_DESC_NDISCMSTATE },
    { L"Partition", ObjectTypeMemoryPartition, IDI_ICON_MEMORYPARTITION, IDS_DESC_MEMORY_PARTITION },
    { L"PcwObject", ObjectTypePcwObject, IDI_ICON_PCWOBJECT, IDS_DESC_PCWOBJECT },
    { L"PowerRequest", ObjectTypePowerRequest, IDI_ICON_POWERREQUEST, IDS_DESC_POWERREQUEST },
    { OBTYPE_NAME_PROCESS, ObjectTypeProcess, IDI_ICON_PROCESS, IDS_DESC_PROCESS },
    { L"Profile", ObjectTypeProfile, IDI_ICON_PROFILE, IDS_DESC_PROFILE },
    //{ L"PsSiloContextNonPaged", ObjectTypePsSiloContextNonPaged, IDI_ICON_PSSILOCONTEXT, IDS_DESC_PSSILOCONTEXTNP },
    //{ L"PsSiloContextPaged", ObjectTypePsSiloContextPaged, IDI_ICON_PSSILOCONTEXT, IDS_DESC_PSSILOCONTEXT },
    //{ L"RawInputManager", ObjectTypeRawInputManager, IDI_ICON_RAWINPUTMANAGER, IDS_DESC_RAW_INPUT_MANAGER },
    { L"RegistryTransaction", ObjectTypeRegistryTransaction, IDI_ICON_KEY, IDS_DESC_REGISTRY_TRANSACTION },
    { OBTYPE_NAME_SECTION, ObjectTypeSection, IDI_ICON_SECTION, IDS_DESC_SECTION },
    { L"Semaphore", ObjectTypeSemaphore, IDI_ICON_SEMAPHORE, IDS_DESC_SEMAPHORE },
    { L"Session", ObjectTypeSession, IDI_ICON_SESSION, IDS_DESC_SESSION },
    { OBTYPE_NAME_SYMBOLIC_LINK, ObjectTypeSymbolicLink, IDI_ICON_SYMLINK, IDS_DESC_SYMLINK },
    { OBTYPE_NAME_THREAD, ObjectTypeThread, IDI_ICON_THREAD, IDS_DESC_THREAD },
    { L"Timer", ObjectTypeTimer, IDI_ICON_TIMER, IDS_DESC_TIMER },
    { L"TmEn", ObjectTypeTmEn, IDI_ICON_TMEN, IDS_DESC_TMEN },
    { L"TmRm", ObjectTypeTmRm, IDI_ICON_TMRM, IDS_DESC_TMRM },
    { L"TmTm", ObjectTypeTmTm, IDI_ICON_TMTM, IDS_DESC_TMTM },
    { L"TmTx", ObjectTypeTmTx, IDI_ICON_TMTX, IDS_DESC_TMTX },
    { OBTYPE_NAME_TOKEN, ObjectTypeToken, IDI_ICON_TOKEN, IDS_DESC_TOKEN },
    { L"TpWorkerFactory", ObjectTypeTpWorkerFactory, IDI_ICON_TPWORKERFACTORY,IDS_DESC_TPWORKERFACTORY },
    { OBTYPE_NAME_TYPE, ObjectTypeType, IDI_ICON_TYPE, IDS_DESC_TYPE },
    //{ L"UserApcReserve", ObjectTypeUserApcReserve, IDI_ICON_USERAPCRESERVE, IDS_DESC_USERAPCRESERVE },
    //{ L"VirtualKey", ObjectTypeVirtualKey, IDI_ICON_VIRTUALKEY, IDS_DESC_VIRTUALKEY },
    //{ L"VRegConfigurationContext", ObjectTypeVREGCFGCTX, IDI_ICON_VREGCFGCTX, IDS_DESC_VREGCFGCTX },
    { L"WaitablePort", ObjectTypeWaitablePort, IDI_ICON_WAITABLEPORT, IDS_DESC_WAITABLEPORT },
    //{ L"WaitCompletionPacket", ObjectTypeWaitCompletionPacket, IDI_ICON_WAITCOMPLETIONPACKET, IDS_DESC_WAITCOMPLETIONPACKET },
    { OBTYPE_NAME_WINSTATION, ObjectTypeWinstation, IDI_ICON_WINSTATION, IDS_DESC_WINSTATION },
    { L"WmiGuid", ObjectTypeWMIGuid, IDI_ICON_WMIGUID, IDS_DESC_WMIGUID }
};

//
// ImageList icon index used from range TYPE_FIRST - TYPE_LAST
//
#define TYPE_FIRST 0
#define TYPE_LAST RTL_NUMBER_OF(g_ObjectTypes)


HIMAGELIST ObManagerLoadImageList(
    VOID);

UINT ObManagerGetImageIndexByTypeIndex(
    _In_ ULONG TypeIndex);

UINT ObManagerGetImageIndexByTypeName(
    _In_opt_ LPCWSTR lpTypeName);


UINT ObManagerGetIndexByTypeName(
    _In_opt_ LPCWSTR lpTypeName);

LPWSTR ObManagerGetNameByIndex(
    _In_ ULONG TypeIndex);

WOBJ_TYPE_DESC *ObManagerGetEntryByTypeName(
    _In_opt_ LPCWSTR lpTypeName);
