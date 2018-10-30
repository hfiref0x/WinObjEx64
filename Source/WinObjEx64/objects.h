/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       OBJECTS.H
*
*  VERSION:     1.60
*
*  DATE:        24 Oct 2018
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
// Description Resource Id string table starting index
//
// Actual id = TYPE_DESCRIPTION_START_INDEX + TYPE_*
//
#define TYPE_DESCRIPTION_START_INDEX    100

//
// Image Resource Id table starting index
//
// Actual id = TYPE_RESOURCE_IMAGE_INDEX_START + ObjectType.ImageIndex
//
#define TYPE_RESOURCE_IMAGE_INDEX_START 300

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
    ObjectTypeMemoryPartition = 47,
    ObjectTypeUnknown = 48,
    ObjectTypeMax
} WOBJ_OBJECT_TYPE;

typedef struct _WOBJ_TYPE_DESC {
    LPWSTR Name;
    WOBJ_OBJECT_TYPE Index;
    WOBJ_OBJECT_TYPE ImageIndex; //different object types may share same images (e.g. Dxgk*)
} WOBJ_TYPE_DESC, *PWOBJ_TYPE_DESC;

//
// ImageList icon index used from range TYPE_FIRST - TYPE_LAST
//
#define TYPE_FIRST ObjectTypeDevice
#define TYPE_LAST ObjectTypeUnknown

#define DIRECTX_SHARED_IMAGE_INDEX ObjectTypeDxgkSharedResource

static const WOBJ_TYPE_DESC g_ObjectTypes[] = {
    { L"Device", ObjectTypeDevice, ObjectTypeDevice },
    { L"Driver", ObjectTypeDriver, ObjectTypeDriver },
    { L"Section", ObjectTypeSection, ObjectTypeSection },
    { L"ALPC Port", ObjectTypePort, ObjectTypePort },
    { L"SymbolicLink", ObjectTypeSymbolicLink, ObjectTypeSymbolicLink },
    { L"Key", ObjectTypeKey, ObjectTypeKey },
    { L"Event", ObjectTypeEvent, ObjectTypeEvent },
    { L"Job", ObjectTypeJob, ObjectTypeJob },
    { L"Mutant", ObjectTypeMutant, ObjectTypeMutant },
    { L"KeyedEvent", ObjectTypeKeyedEvent, ObjectTypeKeyedEvent },
    { L"Type", ObjectTypeType, ObjectTypeType },
    { L"Directory", ObjectTypeDirectory, ObjectTypeDirectory },
    { L"WindowStation", ObjectTypeWinstation, ObjectTypeWinstation },
    { L"Callback", ObjectTypeCallback, ObjectTypeCallback },
    { L"Semaphore", ObjectTypeSemaphore, ObjectTypeSemaphore },
    { L"WaitablePort", ObjectTypeWaitablePort, ObjectTypeWaitablePort },
    { L"Timer", ObjectTypeTimer, ObjectTypeTimer },
    { L"Session", ObjectTypeSession, ObjectTypeSession },
    { L"Controller", ObjectTypeController, ObjectTypeController },
    { L"Profile", ObjectTypeProfile, ObjectTypeProfile },
    { L"EventPair", ObjectTypeEventPair, ObjectTypeEventPair },
    { L"Desktop", ObjectTypeDesktop, ObjectTypeDesktop },
    { L"File", ObjectTypeFile, ObjectTypeFile },
    { L"WMIGuid", ObjectTypeWMIGuid, ObjectTypeWMIGuid },
    { L"DebugObject", ObjectTypeDebugObject, ObjectTypeDebugObject },
    { L"IoCompletion", ObjectTypeIoCompletion, ObjectTypeIoCompletion },
    { L"Process", ObjectTypeProcess, ObjectTypeProcess },
    { L"Adapter", ObjectTypeAdapter, ObjectTypeAdapter },
    { L"Token", ObjectTypeToken, ObjectTypeToken },
    { L"EtwRegistration", ObjectTypeETWRegistration, ObjectTypeETWRegistration },
    { L"Thread", ObjectTypeThread, ObjectTypeThread },
    { L"TmTx", ObjectTypeTmTx, ObjectTypeTmTx },
    { L"TmTm", ObjectTypeTmTm, ObjectTypeTmTm },
    { L"TmRm", ObjectTypeTmRm, ObjectTypeTmRm },
    { L"TmEn", ObjectTypeTmEn, ObjectTypeTmEn },
    { L"PcwObject", ObjectTypePcwObject, ObjectTypePcwObject },
    { L"FilterConnectionPort", ObjectTypeFltConnPort, ObjectTypeFltConnPort },
    { L"FilterCommunicationPort", ObjectTypeFltComnPort, ObjectTypeFltComnPort },
    { L"PowerRequest", ObjectTypePowerRequest, ObjectTypePowerRequest },
    { L"EtwConsumer", ObjectTypeETWConsumer, ObjectTypeETWConsumer },
    { L"TpWorkerFactory", ObjectTypeTpWorkerFactory, ObjectTypeTpWorkerFactory },
    { L"Composition", ObjectTypeComposition, ObjectTypeComposition },
    { L"IRTimer", ObjectTypeIRTimer, ObjectTypeIRTimer },
    { L"DxgkSharedResource", ObjectTypeDxgkSharedResource, DIRECTX_SHARED_IMAGE_INDEX },
    { L"DxgkSharedSwapChainObject", ObjectTypeDxgkSharedSwapChain, DIRECTX_SHARED_IMAGE_INDEX },
    { L"DxgkSharedSyncObject", ObjectTypeDxgkSharedSyncObject, DIRECTX_SHARED_IMAGE_INDEX },
    { L"DxgkCurrentDxgProcessObject", ObjectTypeDxgkCurrentDxgProcessObject, DIRECTX_SHARED_IMAGE_INDEX },
    { L"Partition", ObjectTypeMemoryPartition, ObjectTypeMemoryPartition },
    { L"", ObjectTypeUnknown, ObjectTypeUnknown }
};

HIMAGELIST ObManagerLoadImageList(
    VOID);

UINT ObManagerGetIndexByTypeName(
    _In_ LPCWSTR lpTypeName);

LPWSTR ObManagerGetNameByIndex(
    _In_ ULONG TypeIndex);

UINT ObManagerGetImageIndexByTypeName(
    _In_ LPCWSTR lpTypeName);

UINT ObManagerGetImageIndexByTypeIndex(
    _In_ ULONG TypeIndex);
