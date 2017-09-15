/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017
*
*  TITLE:       OBJECTS.C
*
*  VERSION:     1.50
*
*  DATE:        20 June 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

//Known object type names

LPCWSTR g_lpObjectNames[TYPE_MAX] = {
    L"Device",                              //0
    L"Driver",                              //1
    L"Section",                             //2
    L"ALPC Port",                           //3
    L"SymbolicLink",                        //4
    L"Key",                                 //5
    L"Event",                               //6
    L"Job",                                 //7
    L"Mutant",                              //8
    L"KeyedEvent",                          //9
    L"Type",                                //10
    L"Directory",                           //11
    L"WindowStation",                       //12
    L"Callback",                            //13
    L"Semaphore",                           //14
    L"WaitablePort",                        //15
    L"Timer",                               //16
    L"Session",                             //17
    L"Controller",                          //18
    L"Profile",                             //19
    L"EventPair",                           //20
    L"Desktop",                             //21
    L"File",                                //22
    L"WMIGuid",                             //23
    L"DebugObject",                         //24
    L"IoCompletion",                        //25
    L"Process",                             //26
    L"Adapter",                             //27
    L"Token",                               //28
    L"EtwRegistration",                     //29
    L"Thread",                              //30
    L"TmTx",                                //31
    L"TmTm",                                //32
    L"TmRm",                                //33
    L"TmEn",                                //34
    L"PcwObject",                           //35
    L"FilterConnectionPort",                //36
    L"FilterCommunicationPort",             //37
    L"PowerRequest",                        //38
    L"EtwConsumer",                         //39
    L"TpWorkerFactory",                     //40
    L"Composition",                         //41
    L"IRTimer",                             //42
    L"DxgkSharedResource",                  //43
    L"DxgkSharedSwapChainObject",           //44
    L"DxgkSharedSyncObject",                //45
    L"DxgkCurrentDxgProcessObject",         //46
    L"Partition",                           //47
    L""                                     //48 final index must be always TYPE_UNKNOWN
};

//
// Future use
//
/*

ActivityReference
CoreMessagining
DmaAdapter
DmaDomain
DxgkDisplayManagerObject
DxgkSharedBundleObject
DxgkSharedProtectedSessionObject
EnergyTracker
EtwSessionDemuxEntry
IoCompletionReserve
NdisCmState
PsSiloContextNonPaged
PsSiloContextPaged
RawInputManager
RegistryTransaction
UserApcReserve
VirtualKey
VRegConfigurationContext
WaitCompletionPacket

*/
