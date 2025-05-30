/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2025
*
*  TITLE:       OBJECTS.H
*
*  VERSION:     2.07
*
*  DATE:        11 May 2025
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
//
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
    ObjectTypeDxgkDisplayMuxSwitch = 49,
    ObjectTypeDxgkSharedBundle = 50,
    ObjectTypeDxgkSharedProtectedSession = 51,
    ObjectTypeDxgkComposition = 52,
    ObjectTypeDxgkSharedKeyedMutex = 53,
    ObjectTypeMemoryPartition = 54,
    ObjectTypeRegistryTransaction = 55,
    ObjectTypeDmaAdapter = 56,
    ObjectTypeDmaDomain = 57,
    ObjectTypeCoverageSampler = 58,
    ObjectTypeActivationObject = 59,
    ObjectTypeActivityReference = 60,
    ObjectTypeCoreMessaging = 61,
    ObjectTypeRawInputManager = 62,
    ObjectTypeWaitCompletionPacket = 63,
    ObjectTypeIoCompletionReserve = 64,
    ObjectTypeUserApcReserve = 65,
    ObjectTypeIoRing = 66,
    ObjectTypeTerminal = 67,
    ObjectTypeTerminalEventQueue = 68,
    ObjectTypeEnergyTracker = 69,
    ObjectTypeUnknown = 70,
    ObjectTypeEtwSessionDemuxEntry = ObjectTypeUnknown,
    ObjectTypeNdisCmState = ObjectTypeUnknown,
    ObjectTypePsSiloContextNonPaged = ObjectTypeUnknown,
    ObjectTypePsSiloContextPaged = ObjectTypeUnknown,
    ObjectTypeVirtualKey = ObjectTypeUnknown,
    ObjectTypeVRegConfigurationContext = ObjectTypeUnknown,
    ObjectTypeProcessStateChange = ObjectTypeUnknown,
    ObjectTypeThreadStateChange = ObjectTypeUnknown,
    ObjectTypeCpuPartition = ObjectTypeUnknown,
    ObjectTypeSchedulerSharedData = ObjectTypeUnknown,
    ObjectTypeCrossVmEvent = ObjectTypeUnknown,
    ObjectTypeCrossVmMutant = ObjectTypeUnknown,
    ObjectTypeMax
} WOBJ_OBJECT_TYPE;

typedef struct _WOBJ_TYPE_DESC {
    // Object type name.
    LPWSTR Name;

    // Hash of object name.
    ULONG NameHash;

    // Object type index.
    WOBJ_OBJECT_TYPE Index; 

    // Resouce id for icon.
    INT ResourceImageId; 
    
    // Resource id in stringtable.
    INT ResourceStringId; 
    
    // Individual image id for each object type (maybe the same for few objects).
    INT ImageIndex;
} WOBJ_TYPE_DESC, *PWOBJ_TYPE_DESC;

#define OBTYPE_NAME_DESKTOP         L"Desktop"
#define OBTYPE_NAME_DIRECTORY       L"Directory"
#define OBTYPE_NAME_FILE            L"File"
#define OBTYPE_NAME_PROCESS         L"Process"
#define OBTYPE_NAME_THREAD          L"Thread"
#define OBTYPE_NAME_TOKEN           L"Token"
#define OBTYPE_NAME_UNKNOWN         L""

//
// Well known type name(case sensitive) hashes.
//
// Generated by supHashUnicodeString.
//
#define OBTYPE_HASH_SYMBOLIC_LINK   0x7f82e7ac
#define OBTYPE_HASH_SECTION         0xbd107d45
#define OBTYPE_HASH_DRIVER          0x72d80048
#define OBTYPE_HASH_DEVICE          0x5646fcd6
#define OBTYPE_HASH_WINSTATION      0x1551ade4
#define OBTYPE_HASH_TYPE            0x8041ee9a
#define OBTYPE_HASH_DIRECTORY       0xa4531c4d

//
// For plugins support.
//
#define ObjectTypeAnyType 0xfe
#define ObjectTypeNone 0xff

//
// Unused id's
//
#define UNUSED_IDI_ICON IDI_ICON_UNKNOWN
#define UNUSED_IDS_DESC IDS_DESC_UNKNOWN

#define IDI_ICON_IORING UNUSED_IDI_ICON
#define IDI_ICON_ACTIVATIONOBJECT UNUSED_IDI_ICON
#define IDI_ICON_ACTIVITYREFERENCE UNUSED_IDI_ICON
#define IDI_ICON_COREMESSAGING UNUSED_IDI_ICON
#define IDI_ICON_COVERAGESAMPLER UNUSED_IDI_ICON
#define IDI_ICON_RAWINPUTMANAGER UNUSED_IDI_ICON
#define IDI_ICON_WAITCOMPLETIONPACKET UNUSED_IDI_ICON
#define IDI_ICON_IOCOMPLETION_RESERVE UNUSED_IDI_ICON
#define IDI_ICON_USERAPCRESERVE UNUSED_IDI_ICON
#define IDI_ICON_ENERGYTRACKER UNUSED_IDI_ICON

#define IDI_ICON_TERMINAL UNUSED_IDI_ICON
#define IDI_ICON_TERMINALEVENTQUEUE UNUSED_IDI_ICON

#define IDI_ICON_ETWSESSIONDEMUXENTRY UNUSED_IDI_ICON
#define IDS_DESC_ETWSESSIONDEMUXENTRY UNUSED_IDS_DESC

#define IDI_ICON_NDISCMSTATE UNUSED_IDI_ICON
#define IDS_DESC_NDISCMSTATE UNUSED_IDS_DESC

#define IDI_ICON_PSSILOCONTEXT UNUSED_IDI_ICON
#define IDS_DESC_PSSILOCONTEXT UNUSED_IDS_DESC

#define IDS_DESC_PSSILOCONTEXTNP UNUSED_IDS_DESC

#define IDI_ICON_VIRTUALKEY UNUSED_IDI_ICON
#define IDS_DESC_VIRTUALKEY UNUSED_IDS_DESC

#define IDI_ICON_VREGCFGCTX UNUSED_IDI_ICON
#define IDS_DESC_VREGCFGCTX UNUSED_IDS_DESC

#define IDI_ICON_PROCESSSTATECHANGE UNUSED_IDI_ICON
#define IDS_DESC_PROCESSSTATECHANGE UNUSED_IDS_DESC

#define IDI_ICON_THREADSTATECHANGE UNUSED_IDI_ICON
#define IDS_DESC_THREADSTATECHANGE UNUSED_IDS_DESC

#define IDI_ICON_CPUPARTITION UNUSED_IDI_ICON
#define IDS_DESC_CPUPARTITION UNUSED_IDS_DESC

#define IDI_ICON_SCHEDULERSHAREDDATA UNUSED_IDI_ICON
#define IDS_DESC_SCHEDULERSHAREDDATA UNUSED_IDS_DESC

#define IDI_ICON_CROSSVMEVENT UNUSED_IDI_ICON
#define IDS_DESC_CROSSVMEVENT UNUSED_IDS_DESC

#define IDI_ICON_CROSSVMMUTANT UNUSED_IDI_ICON
#define IDS_DESC_CROSSVMMUTANT UNUSED_IDS_DESC

extern WOBJ_TYPE_DESC g_TypeUnknown;
extern WOBJ_TYPE_DESC g_TypeSymbolicLink;
extern WOBJ_TYPE_DESC g_TypeDevice;
extern WOBJ_TYPE_DESC g_TypeDriver;
extern WOBJ_TYPE_DESC g_TypeKey;
extern WOBJ_TYPE_DESC g_TypeToken;
extern ULONG g_ObjectTypesCount;

HIMAGELIST ObManagerLoadImageList(
    VOID);

UINT ObManagerGetImageIndexByTypeName(
    _In_opt_ LPCWSTR lpTypeName);

WOBJ_OBJECT_TYPE ObManagerGetIndexByTypeName(
    _In_opt_ LPCWSTR lpTypeName);

LPWSTR ObManagerGetNameByIndex(
    _In_ WOBJ_OBJECT_TYPE TypeIndex);

WOBJ_TYPE_DESC* ObManagerGetEntryByTypeIndex(
    _In_ WOBJ_OBJECT_TYPE TypeIndex);

WOBJ_TYPE_DESC *ObManagerGetEntryByTypeName(
    _In_opt_ LPCWSTR lpTypeName);

PVOID ObManagerTable();

VOID ObManagerTest();
