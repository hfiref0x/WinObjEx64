/************************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019, translated from Microsoft sources/symbols with help of pdbex
*
*  TITLE:       NDIS.H
*
*  VERSION:     1.00
*
*  DATE:        03 July 2019
*
*  Common header file for the NDIS related definitions/structures.
*
*  Depends on:    ntos.h
*
*  Include:       ntos.h
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
************************************************************************************/
#pragma once

#ifndef NDIS_RTL
#define NDIS_RTL


//
// NDIS_RTL HEADER BEGIN
//

#if defined(__cplusplus)
extern "C" {
#endif

#pragma warning(push)
#pragma warning(disable: 4201) // nonstandard extension used: nameless struct/union
#pragma warning(disable: 4214) // nonstandard extension used : bit field types other than int


//
// Basic types from MS ndis.h
//

typedef struct _NDIS_OBJECT_HEADER
{
    UCHAR Type;
    UCHAR Revision;
    USHORT Size;
} NDIS_OBJECT_HEADER, *PNDIS_OBJECT_HEADER;

// NdisAllocateSpinLock

typedef struct _NDIS_SPIN_LOCK
{
    KSPIN_LOCK  SpinLock;
    KIRQL       OldIrql;
} NDIS_SPIN_LOCK, *PNDIS_SPIN_LOCK;

typedef struct _REFERENCE
{
    unsigned __int64 SpinLock;
    unsigned short ReferenceCount;
    UCHAR Closing;
    char __PADDING__[5];
} REFERENCE, *PREFERENCE;

typedef struct _REFERENCE_EX
{
    unsigned __int64 SpinLock;
    unsigned short ReferenceCount;
    UCHAR Closing;
    UCHAR ZeroBased;
    long Padding_188;
    struct NDIS_REFCOUNT_HANDLE__* RefCountTracker;
} REFERENCE_EX, *PREFERENCE_EX; /* size: 0x0018 */

typedef VOID
(*PWORKER_THREAD_ROUTINE)(
    IN PVOID Parameter
    );

typedef struct _WORK_QUEUE_ITEM
{
    LIST_ENTRY             List;
    PWORKER_THREAD_ROUTINE WorkerRoutine;
    __volatile PVOID       Parameter;
} WORK_QUEUE_ITEM, *PWORK_QUEUE_ITEM;

struct _NDIS_WORK_ITEM;
typedef
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID NDIS_PROC_CALLBACK(
    _In_ struct _NDIS_WORK_ITEM * WorkItem,
    _In_opt_ PVOID Context);
typedef NDIS_PROC_CALLBACK *NDIS_PROC;

typedef struct _NDIS_WORK_ITEM
{
    PVOID           Context;
    NDIS_PROC       Routine;
    UCHAR           WrapperReserved[8 * sizeof(PVOID)];
} NDIS_WORK_ITEM, *PNDIS_WORK_ITEM;

typedef struct _NDIS_EVENT
{
    KEVENT      Event;
} NDIS_EVENT, *PNDIS_EVENT;

typedef struct _QUEUED_CLOSE {
    int Status;
    long Padding_274;
    WORK_QUEUE_ITEM WorkItem;
} QUEUED_CLOSE, *PQUEUED_CLOSE;

typedef enum _NDIS_PARAMETER_TYPE
{
    NdisParameterInteger,
    NdisParameterHexInteger,
    NdisParameterString,
    NdisParameterMultiString,
    NdisParameterBinary
} NDIS_PARAMETER_TYPE, *PNDIS_PARAMETER_TYPE;

typedef enum _NDIS_PROCESSOR_TYPE
{
    NdisProcessorX86,
    NdisProcessorMips,
    NdisProcessorAlpha,
    NdisProcessorPpc,
    NdisProcessorAmd64,
    NdisProcessorIA64,
    NdisProcessorArm,
    NdisProcessorArm64
} NDIS_PROCESSOR_TYPE, *PNDIS_PROCESSOR_TYPE;

typedef enum _NDIS_NDIS5_DRIVER_STATE
{
    Ndis5StateUnused = 0,
    Ndis5StatePaused = 1,
    Ndis5StateRunning = 2,
} NDIS_NDIS5_DRIVER_STATE, *PNDIS_NDIS5_DRIVER_STATE;

typedef enum _NDIS_OPEN_STATE
{
    NdisOpenStateRunning = 0,
    NdisOpenStatePausing = 1,
    NdisOpenStatePaused = 2,
    NdisOpenStateRestarting = 3,
} NDIS_OPEN_STATE, *PNDIS_OPEN_STATE;

typedef enum _NDIS_OPEN_UNBIND_REASON
{
    UnbindReasonNotUnbinding = 0,
    UnbindReasonCloseMiniportBindings = 1,
    UnbindReasonCloseAllBindingsOnProtocol = 2,
    UnbindReasonCloseMiniportBindingsForPause = 3,
    UnbindReasonHandleProtocolReconfigNotification = 4,
    UnbindReasonHandleProtocolUnbindNotification = 5,
    UnbindReasonPnPNotifyAllTransports = 6,
    UnbindReasonPnPNotifyBinding = 7,
} NDIS_OPEN_UNBIND_REASON, *PNDIS_OPEN_UNBIND_REASON;

typedef enum _INTERFACE_TYPE {
    InterfaceTypeUndefined = -1,
    Internal,
    Isa,
    Eisa,
    MicroChannel,
    TurboChannel,
    PCIBus,
    VMEBus,
    NuBus,
    PCMCIABus,
    CBus,
    MPIBus,
    MPSABus,
    ProcessorInternal,
    InternalPowerBus,
    PNPISABus,
    PNPBus,
    Vmcs,
    ACPIBus,
    MaximumInterfaceType
} INTERFACE_TYPE, *PINTERFACE_TYPE;

typedef enum _NDIS_INTERFACE_TYPE
{
    NdisInterfaceInternal = Internal,
    NdisInterfaceIsa = Isa,
    NdisInterfaceEisa = Eisa,
    NdisInterfaceMca = MicroChannel,
    NdisInterfaceTurboChannel = TurboChannel,
    NdisInterfacePci = PCIBus,
    NdisInterfacePcMcia = PCMCIABus,
    NdisInterfaceCBus = CBus,
    NdisInterfaceMPIBus = MPIBus,
    NdisInterfaceMPSABus = MPSABus,
    NdisInterfaceProcessorInternal = ProcessorInternal,
    NdisInterfaceInternalPowerBus = InternalPowerBus,
    NdisInterfacePNPISABus = PNPISABus,
    NdisInterfacePNPBus = PNPBus,
    NdisInterfaceUSB,
    NdisInterfaceIrda,
    NdisInterface1394,
    NdisMaximumInterfaceType
} NDIS_INTERFACE_TYPE, *PNDIS_INTERFACE_TYPE;

typedef struct _NDIS_CO_CALL_MANAGER_OPTIONAL_HANDLERS
{
    NDIS_OBJECT_HEADER Header;
    ULONG Reserved;
    PVOID CmCreateVcHandler;
    PVOID CmDeleteVcHandler;
    PVOID CmOpenAfHandler;
    PVOID CmCloseAfHandler;
    PVOID CmRegisterSapHandler;
    PVOID CmDeregisterSapHandler;
    PVOID CmMakeCallHandler;
    PVOID CmCloseCallHandler;
    PVOID CmIncomingCallCompleteHandler;
    PVOID CmAddPartyHandler;
    PVOID CmDropPartyHandler;
    PVOID CmActivateVcCompleteHandler;
    PVOID CmDeactivateVcCompleteHandler;
    PVOID CmModifyCallQoSHandler;
    PVOID CmOidRequestHandler;
    PVOID CmOidRequestCompleteHandler;
    PVOID CmNotifyCloseAfCompleteHandler;
} NDIS_CO_CALL_MANAGER_OPTIONAL_HANDLERS, *PNDIS_CO_CALL_MANAGER_OPTIONAL_HANDLERS;

typedef struct _NDIS_CO_CLIENT_OPTIONAL_HANDLERS {
    NDIS_OBJECT_HEADER Header;
    ULONG Reserved;
    PVOID ClCreateVcHandler;
    PVOID ClDeleteVcHandler;
    PVOID ClOidRequestHandler;
    PVOID ClOidRequestCompleteHandler;
    PVOID ClOpenAfCompleteHandlerEx;
    PVOID ClCloseAfCompleteHandler;
    PVOID ClRegisterSapCompleteHandler;
    PVOID ClDeregisterSapCompleteHandler;
    PVOID ClMakeCallCompleteHandler;
    PVOID ClModifyCallQoSCompleteHandler;
    PVOID ClCloseCallCompleteHandler;
    PVOID ClAddPartyCompleteHandler;
    PVOID ClDropPartyCompleteHandler;
    PVOID ClIncomingCallHandler;
    PVOID ClIncomingCallQoSChangeHandler;
    PVOID ClIncomingCloseCallHandler;
    PVOID ClIncomingDropPartyHandler;
    PVOID ClCallConnectedHandler;
    PVOID ClNotifyCloseAfHandler;
} NDIS_CO_CLIENT_OPTIONAL_HANDLERS, *PNDIS_CO_CLIENT_OPTIONAL_HANDLERS;

typedef struct _NDIS_PM_PARAMETERS
{
    NDIS_OBJECT_HEADER Header;
    ULONG              EnabledWoLPacketPatterns;
    ULONG              EnabledProtocolOffloads;
    ULONG              WakeUpFlags;
    ULONG              MediaSpecificWakeUpEvents;
} NDIS_PM_PARAMETERS, *PNDIS_PM_PARAMETERS;

typedef struct _NDIS_PM_PARAMETERS_7601
{
    /* 0x0000 */ NDIS_OBJECT_HEADER Header;
    /* 0x0004 */ ULONG EnabledWoLPacketPatterns;
    /* 0x0008 */ ULONG EnabledProtocolOffloads;
    /* 0x000c */ ULONG WakeUpFlags;
} NDIS_PM_PARAMETERS_7601, *PNDIS_PM_PARAMETERS_7601; /* size: 0x0010 */

typedef enum _NDIS_OPEN_TRANSLATION_STATE
{
    OpenDontXlate = 0,
    OpenXlateExceptSends = 1,
    OpenXlateAll = 2,
} NDIS_OPEN_TRANSLATION_STATE, *PNDIS_OPEN_TRANSLATION_STATE;

//
// NDIS Win10 RS6+ specific
//

typedef enum _PKTMON_PACKET_TYPE
{
    PktMonPayload_Unknown = 0,
    PktMonPayload_Ethernet = 1,
    PktMonPayload_WiFi = 2,
    PktMonPayload_MBB = 3,
} PKTMON_PACKET_TYPE, *PPKTMON_PACKET_TYPE;

typedef struct _PKTMON_COMPONENT_CONTEXT
{
    /* 0x0000 */ PVOID CompHandle;
    /* 0x0008 */ PKTMON_PACKET_TYPE PacketType;
    struct /* bitfield */
    {
        /* 0x000c */ int FlowEnabled : 1; /* bit position: 0 */
        /* 0x000c */ int DropEnabled : 1; /* bit position: 1 */
    }; /* bitfield */
} PKTMON_COMPONENT_CONTEXT, *PPKTMON_COMPONENT_CONTEXT; /* size: 0x0010 */

typedef struct _PKTMON_EDGE_CONTEXT
{
    /* 0x0000 */ PVOID EdgeHandle;
    /* 0x0008 */ PKTMON_COMPONENT_CONTEXT* CompContext;
    /* 0x0010 */ PKTMON_PACKET_TYPE PacketType;
    /* 0x0014 */ long __PADDING__[1];
} PKTMON_EDGE_CONTEXT, *PPKTMON_EDGE_CONTEXT; /* size: 0x0018 */

typedef struct _NDIS_OPEN_BLOCK_7601 {
    union
    {
        /* 0x0000 */ PVOID MacHandle;
        /* 0x0000 */ NDIS_OBJECT_HEADER Header;
    }; /* size: 0x0008 */
    /* 0x0008 */ PVOID BindingHandle;
    /* 0x0010 */ struct _NDIS_MINIPORT_BLOCK* MiniportHandle;
    /* 0x0018 */ struct _NDIS_PROTOCOL_BLOCK* ProtocolHandle;
    /* 0x0020 */ PVOID ProtocolBindingContext;
    /* 0x0028 */ PVOID NextSendHandler;
    /* 0x0030 */ PVOID NextSendContext;
    /* 0x0038 */ PVOID MiniportAdapterContext;
    /* 0x0040 */ UCHAR Reserved1;
    /* 0x0041 */ UCHAR CallingFromNdis6Protocol;
    /* 0x0042 */ UCHAR Reserved3;
    /* 0x0043 */ UCHAR Reserved4;
    /* 0x0044 */ ULONG Padding1;
    /* 0x0048 */ PVOID NextReturnNetBufferListsHandler;
    /* 0x0050 */ unsigned __int64 Reserved5;
    /* 0x0058 */ PVOID NextReturnNetBufferListsContext;
    union
    {
        /* 0x0060 */ PVOID SendHandler;
        /* 0x0060 */ PVOID WanSendHandler;
    }; /* size: 0x0008 */
    /* 0x0068 */ PVOID TransferDataHandler;
    /* 0x0070 */ PVOID SendCompleteHandler;
    /* 0x0078 */ PVOID TransferDataCompleteHandler;
    /* 0x0080 */ PVOID ReceiveHandler;
    /* 0x0088 */ PVOID ReceiveCompleteHandler;
    /* 0x0090 */ PVOID WanReceiveHandler;
    /* 0x0098 */ PVOID RequestCompleteHandler;
    /* 0x00a0 */ PVOID ReceivePacketHandler;
    /* 0x00a8 */ PVOID SendPacketsHandler;
    /* 0x00b0 */ PVOID ResetHandler;
    /* 0x00b8 */ PVOID RequestHandler;
    /* 0x00c0 */ PVOID OidRequestHandler;
    /* 0x00c8 */ PVOID ResetCompleteHandler;
    union
    {
        /* 0x00d0 */ PVOID StatusHandler;
        /* 0x00d0 */ PVOID StatusHandlerEx;
    }; /* size: 0x0008 */
    /* 0x00d8 */ PVOID StatusCompleteHandler;
    /* 0x00e0 */ ULONG Flags;
    /* 0x00e4 */ LONG References;
    /* 0x00e8 */ unsigned __int64 SpinLock;
    /* 0x00f0 */ PVOID FilterHandle;
    /* 0x00f8 */ UINT FrameTypeArraySize;
    /* 0x00fc */ USHORT FrameTypeArray[4];
    /* 0x0104 */ ULONG ProtocolOptions;
    /* 0x0108 */ ULONG CurrentLookahead;
    /* 0x010c */ ULONG Padding2;
    /* 0x0110 */ PVOID WSendHandler;
    /* 0x0118 */ PVOID WTransferDataHandler;
    /* 0x0120 */ PVOID WSendPacketsHandler;
    /* 0x0128 */ PVOID CancelSendPacketsHandler;
    /* 0x0130 */ ULONG WakeUpEnable;
    /* 0x0134 */ NDIS_PM_PARAMETERS_7601 PMCurrentParameters;
    /* 0x0144 */ ULONG Padding3;
    /* 0x0148 */ struct _KEVENT* CloseCompleteEvent;
    /* 0x0150 */ struct _QUEUED_CLOSE QC;
    /* 0x0178 */ long AfReferences;
    /* 0x017c */ long Padding_278;
    /* 0x0180 */ struct _NDIS_OPEN_BLOCK* NextGlobalOpen;
    /* 0x0188 */ struct _NDIS_OPEN_BLOCK* MiniportNextOpen;
    /* 0x0190 */ struct _NDIS_OPEN_BLOCK* ProtocolNextOpen;
    /* 0x0198 */ struct _UNICODE_STRING* BindDeviceName;
    /* 0x01a0 */ struct _UNICODE_STRING* RootDeviceName;
    /* 0x01a8 */ struct _NDIS_OPEN_BLOCK* FilterNextOpen;
    /* 0x01b0 */ unsigned int PacketFilters;
    /* 0x01b4 */ unsigned int OldPacketFilters;
    union
    {
        struct
        {
            /* 0x01b8 */ unsigned int MaxMulticastAddresses;
            /* 0x01bc */ long Padding_279;
            /* 0x01c0 */ struct _ETH_MULTICAST_WRAPPER* MCastAddressBuf;
            /* 0x01c8 */ unsigned int NumAddresses;
            /* 0x01cc */ long Padding_280;
            /* 0x01d0 */ struct _ETH_MULTICAST_WRAPPER* OldMCastAddressBuf;
            /* 0x01d8 */ unsigned int OldNumAddresses;
        }; /* size: 0x001c */
        struct
        {
            /* 0x01b8 */ unsigned long FunctionalAddress;
            /* 0x01bc */ unsigned long OldFunctionalAddress;
            /* 0x01c0 */ unsigned char UsingGroupAddress;
            /* 0x01c1 */ unsigned char OldUsingGroupAddress;
            /* 0x01c2 */ char Padding_281[2];
            /* 0x01c4 */ unsigned long FARefCount[32];
            /* 0x0244 */ unsigned long OldFARefCount[32];
            /* 0x02c4 */ long Padding_282[3];
            /* 0x02d0 */ unsigned char RSSParametersBuf[656];
            /* 0x0560 */ struct _NDIS_RECEIVE_SCALE_PARAMETERS* NdisRSSParameters;
            /* 0x0568 */ SINGLE_LIST_ENTRY PatternList;
            /* 0x0570 */ SINGLE_LIST_ENTRY WOLPatternList;
            /* 0x0578 */ SINGLE_LIST_ENTRY PMProtocolOffloadList;
            /* 0x0580 */ PVOID ProtSendNetBufferListsComplete;
            /* 0x0588 */ PVOID SendCompleteNdisPacketContext;
            /* 0x0590 */ PVOID SendCompleteNetBufferListsContext;
            /* 0x0598 */ PVOID ReceiveNetBufferLists;
            /* 0x05a0 */ PVOID ReceiveNetBufferListsContext;
            /* 0x05a8 */ PVOID SavedSendNBLHandler;
            /* 0x05b0 */ PVOID SavedSendPacketsHandler;
            /* 0x05b8 */ PVOID SavedCancelSendPacketsHandler;
            union
            {
                /* 0x05c0 */ PVOID SavedSendHandler;
                /* 0x05c0 */ PVOID SavedWanSendHandler;
            }; /* size: 0x0008 */
            /* 0x05c8 */ PVOID InitiateOffloadCompleteHandler;
            /* 0x05d0 */ PVOID TerminateOffloadCompleteHandler;
            /* 0x05d8 */ PVOID UpdateOffloadCompleteHandler;
            /* 0x05e0 */ PVOID InvalidateOffloadCompleteHandler;
            /* 0x05e8 */ PVOID QueryOffloadCompleteHandler;
            /* 0x05f0 */ PVOID IndicateOffloadEventHandler;
            /* 0x05f8 */ PVOID TcpOffloadSendCompleteHandler;
            /* 0x0600 */ PVOID TcpOffloadReceiveCompleteHandler;
            /* 0x0608 */ PVOID TcpOffloadDisconnectCompleteHandler;
            /* 0x0610 */ PVOID TcpOffloadForwardCompleteHandler;
            /* 0x0618 */ PVOID TcpOffloadEventHandler;
            /* 0x0620 */ PVOID TcpOffloadReceiveIndicateHandler;
            /* 0x0628 */ unsigned long ProtocolMajorVersion;
            /* 0x062c */ long Padding_283;
            /* 0x0630 */ void** IfBlock;
            /* 0x0638 */ NDIS_SPIN_LOCK PnPStateLock;
            /* 0x0648 */ NDIS_NDIS5_DRIVER_STATE PnPState;
            /* 0x064c */ NDIS_OPEN_TRANSLATION_STATE TranslationState;
            /* 0x0650 */ int OutstandingSends;
            /* 0x0654 */ long Padding_284;
            /* 0x0658 */ NDIS_EVENT PauseEvent;
            /* 0x0670 */ PVOID Ndis5WanSendHandler;
            /* 0x0678 */ PVOID ProtSendCompleteHandler;
            /* 0x0680 */ PVOID OidRequestCompleteHandler;
            /* 0x0688 */ PVOID OidRequestCompleteContext;
            /* 0x0690 */ long NumOfPauseRestartRequests;
            /* 0x0694 */ NDIS_OPEN_STATE State;
            /* 0x0698 */ struct _NDIS_OPEN_OFFLOAD* Offload;
            /* 0x06a0 */ struct _NDIS_STATUS_UNBIND_WORKITEM* StatusUnbindWorkItem;
            /* 0x06a8 */ unsigned __int64 DpcStartCycle;
            /* 0x06b0 */ unsigned long NumberOfNetBufferLists;
            /* 0x06b4 */ long Padding_285;
            /* 0x06b8 */ unsigned char* ReceivedAPacket;
            /* 0x06c0 */ PVOID DirectOidRequestCompleteHandler;
            /* 0x06c8 */ PVOID DirectOidRequestHandler;
            /* 0x06d0 */ PVOID DirectOidRequestCompleteContext;
            /* 0x06d8 */ LIST_ENTRY ReceiveQueueList;
            /* 0x06e8 */ unsigned long NumReceiveQueues;
            /* 0x06ec */ long Padding_286;
            /* 0x06f0 */ LIST_ENTRY SharedMemoryBlockList;
            /* 0x0700 */ PVOID AllocateSharedMemoryHandler;
            /* 0x0708 */ PVOID FreeSharedMemoryHandler;
            /* 0x0710 */ PVOID AllocateSharedMemoryContext;
            /* 0x0718 */ long Padding_287[2];
            /* 0x0720 */ struct _NDIS_CO_AF_BLOCK* NextAf;
            /* 0x0728 */ PVOID MiniportCoCreateVcHandler;
            /* 0x0730 */ PVOID MiniportCoRequestHandler;
            /* 0x0738 */ PVOID CoCreateVcHandler;
            /* 0x0740 */ PVOID CoDeleteVcHandler;
            /* 0x0748 */ PVOID CmActivateVcCompleteHandler;
            /* 0x0750 */ PVOID CmDeactivateVcCompleteHandler;
            /* 0x0758 */ PVOID CoRequestCompleteHandler;
            /* 0x0760 */ PVOID CoRequestHandler;
            /* 0x0768 */ LIST_ENTRY ActiveVcHead;
            /* 0x0778 */ LIST_ENTRY InactiveVcHead;
            /* 0x0788 */ long PendingAfNotifications;
            /* 0x078c */ long Padding_288;
            /* 0x0790 */ struct _KEVENT* AfNotifyCompleteEvent;
            /* 0x0798 */ PVOID MiniportCoOidRequestHandler;
            /* 0x07a0 */ PVOID CoOidRequestCompleteHandler;
            /* 0x07a8 */ PVOID CoOidRequestHandler;
        }; /* size: 0x05ce */
    }; /* size: 0x05ce */
} NDIS_OPEN_BLOCK_7601, *PNDIS_OPEN_BLOCK_7601; /* size: 0x07b0 */

typedef struct _NDIS_OPEN_BLOCK_9200
{
    union
    {
        /* 0x0000 */ PVOID MacHandle;
        /* 0x0000 */ NDIS_OBJECT_HEADER Header;
    }; /* size: 0x0008 */
    /* 0x0008 */ PVOID BindingHandle;
    /* 0x0010 */ struct _NDIS_MINIPORT_BLOCK* MiniportHandle;
    /* 0x0018 */ struct _NDIS_PROTOCOL_BLOCK* ProtocolHandle;
    /* 0x0020 */ PVOID ProtocolBindingContext;
    /* 0x0028 */ PVOID NextSendHandler;
    /* 0x0030 */ PVOID NextSendContext;
    /* 0x0038 */ PVOID MiniportAdapterContext;
    /* 0x0040 */ UCHAR Reserved1;
    /* 0x0041 */ UCHAR CallingFromNdis6Protocol;
    /* 0x0042 */ UCHAR Reserved3;
    /* 0x0043 */ UCHAR Reserved4;
    /* 0x0044 */ long Padding_47;
    /* 0x0048 */ PVOID NextReturnNetBufferListsHandler;
    /* 0x0050 */ unsigned __int64 Reserved5;
    /* 0x0058 */ PVOID NextReturnNetBufferListsContext;
    union
    {
        /* 0x0060 */ PVOID SendHandler;
        /* 0x0060 */ PVOID WanSendHandler;
    }; /* size: 0x0008 */
    /* 0x0068 */ PVOID TransferDataHandler;
    /* 0x0070 */ PVOID SendCompleteHandler;
    /* 0x0078 */ PVOID TransferDataCompleteHandler;
    /* 0x0080 */ PVOID ReceiveHandler;
    /* 0x0088 */ PVOID ReceiveCompleteHandler;
    /* 0x0090 */ PVOID WanReceiveHandler;
    /* 0x0098 */ PVOID RequestCompleteHandler;
    /* 0x00a0 */ PVOID ReceivePacketHandler;
    /* 0x00a8 */ PVOID SendPacketsHandler;
    /* 0x00b0 */ PVOID ResetHandler;
    /* 0x00b8 */ PVOID RequestHandler;
    /* 0x00c0 */ PVOID OidRequestHandler;
    /* 0x00c8 */ PVOID ResetCompleteHandler;
    union
    {
        /* 0x00d0 */ PVOID StatusHandler;
        /* 0x00d0 */ PVOID StatusHandlerEx;
    }; /* size: 0x0008 */
    /* 0x00d8 */ PVOID StatusCompleteHandler;
    /* 0x00e0 */ volatile ULONG OpenFlags;
    /* 0x00e4 */ long References;
    /* 0x00e8 */ unsigned __int64 SpinLock;
    /* 0x00f0 */ PVOID FilterHandle;
    /* 0x00f8 */ unsigned int FrameTypeArraySize;
    /* 0x00fc */ unsigned short FrameTypeArray[4];
    /* 0x0104 */ ULONG ProtocolOptions;
    /* 0x0108 */ ULONG CurrentLookahead;
    /* 0x010c */ long Padding_48;
    /* 0x0110 */ PVOID WSendHandler;
    /* 0x0118 */ PVOID WTransferDataHandler;
    /* 0x0120 */ PVOID WSendPacketsHandler;
    /* 0x0128 */ PVOID CancelSendPacketsHandler;
    /* 0x0130 */ ULONG WakeUpEnable;
    /* 0x0134 */ NDIS_PM_PARAMETERS PMCurrentParameters;
    /* 0x0148 */ KEVENT* CloseCompleteEvent;
    /* 0x0150 */ QUEUED_CLOSE QC;
    /* 0x0178 */ long AfReferences;
    /* 0x017c */ long Padding_49;
    /* 0x0180 */ struct _NDIS_OPEN_BLOCK* NextGlobalOpen;
    /* 0x0188 */ struct _NDIS_OPEN_BLOCK* MiniportNextOpen;
    /* 0x0190 */ struct _NDIS_OPEN_BLOCK* ProtocolNextOpen;
    /* 0x0198 */ struct _UNICODE_STRING* BindDeviceName;
    /* 0x01a0 */ struct _UNICODE_STRING* RootDeviceName;
    /* 0x01a8 */ struct _NDIS_OPEN_BLOCK* FilterNextOpen;
    /* 0x01b0 */ unsigned int PacketFilters;
    /* 0x01b4 */ unsigned int OldPacketFilters;
    /* 0x01b8 */ unsigned int MaxMulticastAddresses;
    /* 0x01bc */ long Padding_50;
    /* 0x01c0 */ struct _ETH_MULTICAST_WRAPPER* MCastAddressBuf;
    /* 0x01c8 */ unsigned int NumAddresses;
    /* 0x01cc */ long Padding_51;
    /* 0x01d0 */ struct _ETH_MULTICAST_WRAPPER* OldMCastAddressBuf;
    /* 0x01d8 */ unsigned int OldNumAddresses;
    /* 0x01dc */ long Padding_52;
    /* 0x01e0 */ UCHAR* RssParametersBuffer;
    /* 0x01e8 */ struct _NDIS_RECEIVE_SCALE_PARAMETERS* NdisRSSParameters;
    /* 0x01f0 */ SINGLE_LIST_ENTRY PatternList;
    /* 0x01f8 */ SINGLE_LIST_ENTRY WOLPatternList;
    /* 0x0200 */ SINGLE_LIST_ENTRY PMProtocolOffloadList;
    /* 0x0208 */ PVOID ProtSendNetBufferListsComplete;
    /* 0x0210 */ PVOID SendCompleteNdisPacketContext;
    /* 0x0218 */ PVOID SendCompleteNetBufferListsContext;
    /* 0x0220 */ PVOID ReceiveNetBufferLists;
    /* 0x0228 */ PVOID ReceiveNetBufferListsContext;
    /* 0x0230 */ PVOID SavedSendPacketsHandler;
    /* 0x0238 */ PVOID SavedCancelSendPacketsHandler;
    /* 0x0240 */ PVOID SavedSendHandler;
    /* 0x0248 */ PVOID InitiateOffloadCompleteHandler;
    /* 0x0250 */ PVOID TerminateOffloadCompleteHandler;
    /* 0x0258 */ PVOID UpdateOffloadCompleteHandler;
    /* 0x0260 */ PVOID InvalidateOffloadCompleteHandler;
    /* 0x0268 */ PVOID QueryOffloadCompleteHandler;
    /* 0x0270 */ PVOID IndicateOffloadEventHandler;
    /* 0x0278 */ PVOID TcpOffloadSendCompleteHandler;
    /* 0x0280 */ PVOID TcpOffloadReceiveCompleteHandler;
    /* 0x0288 */ PVOID TcpOffloadDisconnectCompleteHandler;
    /* 0x0290 */ PVOID TcpOffloadForwardCompleteHandler;
    /* 0x0298 */ PVOID TcpOffloadEventHandler;
    /* 0x02a0 */ PVOID TcpOffloadReceiveIndicateHandler;
    /* 0x02a8 */ struct NDIS_NBL_TRACKER_HANDLE__* NblTracker;
    /* 0x02b0 */ struct NDIS_REFCOUNT_HANDLE__* RefCountTracker;
    /* 0x02b8 */ unsigned __int64 RefCountLock;
    /* 0x02c0 */ ULONG ProtocolMajorVersion;
    /* 0x02c4 */ long Padding_53;
    /* 0x02c8 */ PVOID *IfBlock;
    /* 0x02d0 */ NDIS_SPIN_LOCK PnPStateLock;
    /* 0x02e0 */ NDIS_NDIS5_DRIVER_STATE PnPState;
    /* 0x02e4 */ int OutstandingSends;
    /* 0x02e8 */ NDIS_EVENT PauseEvent;
    /* 0x0300 */ PVOID Ndis5WanSendHandler;
    /* 0x0308 */ PVOID ProtSendCompleteHandler;
    /* 0x0310 */ PVOID OidRequestCompleteHandler;
    /* 0x0318 */ long NumOfPauseRestartRequests;
    /* 0x031c */ NDIS_OPEN_STATE State;
    /* 0x0320 */ struct _NDIS_OPEN_OFFLOAD* Offload;
    /* 0x0328 */ struct _NDIS_STATUS_UNBIND_WORKITEM* StatusUnbindWorkItem;
    /* 0x0330 */ unsigned __int64 DpcStartCycle;
    /* 0x0338 */ struct PNDIS_PER_PROCESSOR_SLOT__* ReceivedAPacketSlot;
    /* 0x0340 */ PVOID DirectOidRequestHandler;
    /* 0x0348 */ LIST_ENTRY ReceiveQueueList;
    /* 0x0358 */ ULONG NumReceiveQueues;
    /* 0x035c */ long Padding_54;
    /* 0x0360 */ LIST_ENTRY SharedMemoryBlockList;
    /* 0x0370 */ PVOID AllocateSharedMemoryHandler;
    /* 0x0378 */ PVOID FreeSharedMemoryHandler;
    /* 0x0380 */ PVOID AllocateSharedMemoryContext;
    /* 0x0388 */ struct _NDIS_COMPOSITE_BUS_INFORMATION* CompositeBus;
    /* 0x0390 */ ULONG NumAllocatedVFs;
    /* 0x0394 */ long Padding_55;
    /* 0x0398 */ LIST_ENTRY VFList;
    /* 0x03a8 */ ULONG NumActiveVPorts;
    /* 0x03ac */ long Padding_56;
    /* 0x03b0 */ LIST_ENTRY VPortList;
    /* 0x03c0 */ NDIS_OPEN_UNBIND_REASON UnbindReason;
    /* 0x03c4 */ ULONG AoAcReferences;
    /* 0x03c8 */ struct _NDIS_CO_AF_BLOCK* NextAf;
    /* 0x03d0 */ PVOID MiniportCoCreateVcHandler;
    /* 0x03d8 */ PVOID MiniportCoRequestHandler;
    /* 0x03e0 */ PVOID CoCreateVcHandler;
    /* 0x03e8 */ PVOID CoDeleteVcHandler;
    /* 0x03f0 */ PVOID CmActivateVcCompleteHandler;
    /* 0x03f8 */ PVOID CmDeactivateVcCompleteHandler;
    /* 0x0400 */ PVOID CoRequestCompleteHandler;
    /* 0x0408 */ PVOID CoRequestHandler;
    /* 0x0410 */ LIST_ENTRY ActiveVcHead;
    /* 0x0420 */ LIST_ENTRY InactiveVcHead;
    /* 0x0430 */ long PendingAfNotifications;
    /* 0x0434 */ long Padding_57;
    /* 0x0438 */ KEVENT* AfNotifyCompleteEvent;
    /* 0x0440 */ PVOID MiniportCoOidRequestHandler;
    /* 0x0448 */ PVOID CoOidRequestCompleteHandler;
    /* 0x0450 */ PVOID CoOidRequestHandler;
} NDIS_OPEN_BLOCK_9200, *PNDIS_OPEN_BLOCK_9200; /* size: 0x0458 */

typedef struct _NDIS_OPEN_BLOCK_9600_10586
{
    /* 0x0000 */ long Padding_302[252]; //NDIS_COMMON_OPEN_BLOCK
    /* 0x03f0 */ struct _NDIS_CO_AF_BLOCK* NextAf;
    /* 0x03f8 */ PVOID MiniportCoCreateVcHandler;
    /* 0x0400 */ PVOID MiniportCoRequestHandler;
    /* 0x0408 */ PVOID CoCreateVcHandler;
    /* 0x0410 */ PVOID CoDeleteVcHandler;
    /* 0x0418 */ PVOID CmActivateVcCompleteHandler;
    /* 0x0420 */ PVOID CmDeactivateVcCompleteHandler;
    /* 0x0428 */ PVOID CoRequestCompleteHandler;
    /* 0x0430 */ PVOID CoRequestHandler;
    /* 0x0438 */ LIST_ENTRY ActiveVcHead;
    /* 0x0448 */ LIST_ENTRY InactiveVcHead;
    /* 0x0458 */ long PendingAfNotifications;
    /* 0x045c */ long Padding_303;
    /* 0x0460 */ KEVENT* AfNotifyCompleteEvent;
    /* 0x0468 */ PVOID MiniportCoOidRequestHandler;
    /* 0x0470 */ PVOID CoOidRequestCompleteHandler;
    /* 0x0478 */ PVOID CoOidRequestHandler;
} NDIS_OPEN_BLOCK_9600_10586, *PNDIS_OPEN_BLOCK_9600_10586; /* size: 0x0480 */

typedef struct _NDIS_OPEN_BLOCK_14393_17134
{
    /* 0x0000 */ long Padding_7[254];
    /* 0x03f8 */ struct _NDIS_CO_AF_BLOCK* NextAf;
    /* 0x0400 */ PVOID MiniportCoCreateVcHandler;
    /* 0x0408 */ PVOID MiniportCoRequestHandler;
    /* 0x0410 */ PVOID CoCreateVcHandler;
    /* 0x0418 */ PVOID CoDeleteVcHandler;
    /* 0x0420 */ PVOID CmActivateVcCompleteHandler;
    /* 0x0428 */ PVOID CmDeactivateVcCompleteHandler;
    /* 0x0430 */ PVOID CoRequestCompleteHandler;
    /* 0x0438 */ PVOID CoRequestHandler;
    /* 0x0440 */ LIST_ENTRY ActiveVcHead;
    /* 0x0450 */ LIST_ENTRY InactiveVcHead;
    /* 0x0460 */ long PendingAfNotifications;
    /* 0x0464 */ long Padding_8;
    /* 0x0468 */ KEVENT* AfNotifyCompleteEvent;
    /* 0x0470 */ PVOID MiniportCoOidRequestHandler;
    /* 0x0478 */ PVOID CoOidRequestCompleteHandler;
    /* 0x0480 */ PVOID CoOidRequestHandler;
} NDIS_OPEN_BLOCK_14393_17134, *PNDIS_OPEN_BLOCK_14393_17134; /* size: 0x0488 */

typedef struct _NDIS_OPEN_BLOCK_17763_18362
{
    /* 0x0000 */ long Padding_297[240];
    /* 0x03c0 */ struct _NDIS_CO_AF_BLOCK* NextAf;
    /* 0x03c8 */ PVOID MiniportCoCreateVcHandler;
    /* 0x03d0 */ PVOID MiniportCoRequestHandler;
    /* 0x03d8 */ PVOID CoCreateVcHandler;
    /* 0x03e0 */ PVOID CoDeleteVcHandler;
    /* 0x03e8 */ PVOID CmActivateVcCompleteHandler;
    /* 0x03f0 */ PVOID CmDeactivateVcCompleteHandler;
    /* 0x03f8 */ PVOID CoRequestCompleteHandler;
    /* 0x0400 */ PVOID CoRequestHandler;
    /* 0x0408 */ LIST_ENTRY ActiveVcHead;
    /* 0x0418 */ LIST_ENTRY InactiveVcHead;
    /* 0x0428 */ long PendingAfNotifications;
    /* 0x042c */ long Padding_298;
    /* 0x0430 */ struct _KEVENT* AfNotifyCompleteEvent;
    /* 0x0438 */ PVOID MiniportCoOidRequestHandler;
    /* 0x0440 */ PVOID CoOidRequestCompleteHandler;
    /* 0x0448 */ PVOID CoOidRequestHandler;
} NDIS_OPEN_BLOCK_17763_18362, *PNDIS_OPEN_BLOCK_17763_18362; /* size: 0x0450 */

typedef struct _NDIS_COMMON_OPEN_BLOCK_9600_10586
{
    union
    {
        /* 0x0000 */ PVOID MacHandle;
        /* 0x0000 */ NDIS_OBJECT_HEADER Header;
    }; /* size: 0x0008 */
    /* 0x0008 */ PVOID BindingHandle;
    /* 0x0010 */ struct _NDIS_MINIPORT_BLOCK* MiniportHandle;
    /* 0x0018 */ struct _NDIS_PROTOCOL_BLOCK* ProtocolHandle;
    /* 0x0020 */ PVOID ProtocolBindingContext;
    /* 0x0028 */ PVOID NextSendHandler;
    /* 0x0030 */ PVOID NextSendContext;
    /* 0x0038 */ PVOID MiniportAdapterContext;
    /* 0x0040 */ UCHAR Reserved1;
    /* 0x0041 */ UCHAR CallingFromNdis6Protocol;
    /* 0x0042 */ UCHAR Reserved3;
    /* 0x0043 */ UCHAR Reserved4;
    /* 0x0044 */ long Padding_439;
    /* 0x0048 */ PVOID NextReturnNetBufferListsHandler;
    /* 0x0050 */ unsigned __int64 Reserved5;
    /* 0x0058 */ PVOID NextReturnNetBufferListsContext;
    union
    {
        /* 0x0060 */ PVOID SendHandler;
        /* 0x0060 */ PVOID WanSendHandler;
    }; /* size: 0x0008 */
    /* 0x0068 */ PVOID TransferDataHandler;
    /* 0x0070 */ PVOID SendCompleteHandler;
    /* 0x0078 */ PVOID TransferDataCompleteHandler;
    /* 0x0080 */ PVOID ReceiveHandler;
    /* 0x0088 */ PVOID ReceiveCompleteHandler;
    /* 0x0090 */ PVOID WanReceiveHandler;
    /* 0x0098 */ PVOID RequestCompleteHandler;
    /* 0x00a0 */ PVOID ReceivePacketHandler;
    /* 0x00a8 */ PVOID SendPacketsHandler;
    /* 0x00b0 */ PVOID ResetHandler;
    /* 0x00b8 */ PVOID RequestHandler;
    /* 0x00c0 */ PVOID OidRequestHandler;
    /* 0x00c8 */ PVOID ResetCompleteHandler;
    union
    {
        /* 0x00d0 */ PVOID StatusHandler;
        /* 0x00d0 */ PVOID StatusHandlerEx;
    }; /* size: 0x0008 */
    /* 0x00d8 */ PVOID StatusCompleteHandler;
    /* 0x00e0 */ volatile ULONG OpenFlags;
    /* 0x00e4 */ long References;
    /* 0x00e8 */ unsigned __int64 SpinLock;
    /* 0x00f0 */ PVOID FilterHandle;
    /* 0x00f8 */ unsigned int FrameTypeArraySize;
    /* 0x00fc */ unsigned short FrameTypeArray[4];
    /* 0x0104 */ ULONG ProtocolOptions;
    /* 0x0108 */ ULONG CurrentLookahead;
    /* 0x010c */ long Padding_440;
    /* 0x0110 */ PVOID WSendHandler;
    /* 0x0118 */ PVOID WTransferDataHandler;
    /* 0x0120 */ PVOID WSendPacketsHandler;
    /* 0x0128 */ PVOID CancelSendPacketsHandler;
    /* 0x0130 */ ULONG WakeUpEnable;
    /* 0x0134 */ NDIS_PM_PARAMETERS PMCurrentParameters;
    /* 0x0148 */ struct _KEVENT* CloseCompleteEvent;
    /* 0x0150 */ QUEUED_CLOSE QC;
    /* 0x0178 */ long AfReferences;
    /* 0x017c */ long Padding_441;
    /* 0x0180 */ struct _NDIS_OPEN_BLOCK* NextGlobalOpen;
    /* 0x0188 */ struct _NDIS_OPEN_BLOCK* MiniportNextOpen;
    /* 0x0190 */ struct _NDIS_OPEN_BLOCK* ProtocolNextOpen;
    /* 0x0198 */ struct _UNICODE_STRING* BindDeviceName;
    /* 0x01a0 */ struct _UNICODE_STRING* RootDeviceName;
    /* 0x01a8 */ struct _NDIS_OPEN_BLOCK* FilterNextOpen;
    /* 0x01b0 */ unsigned int PacketFilters;
    /* 0x01b4 */ unsigned int OldPacketFilters;
    /* 0x01b8 */ unsigned int MaxMulticastAddresses;
    /* 0x01bc */ long Padding_442;
    /* 0x01c0 */ struct _ETH_MULTICAST_WRAPPER* MCastAddressBuf;
    /* 0x01c8 */ unsigned int NumAddresses;
    /* 0x01cc */ long Padding_443;
    /* 0x01d0 */ struct _ETH_MULTICAST_WRAPPER* OldMCastAddressBuf;
    /* 0x01d8 */ unsigned int OldNumAddresses;
    /* 0x01dc */ long Padding_444;
    /* 0x01e0 */ UCHAR* RssParametersBuffer;
    /* 0x01e8 */ struct _NDIS_RECEIVE_SCALE_PARAMETERS* NdisRSSParameters;
    /* 0x01f0 */ SINGLE_LIST_ENTRY PatternList;
    /* 0x01f8 */ SINGLE_LIST_ENTRY WOLPatternList;
    /* 0x0200 */ SINGLE_LIST_ENTRY PMProtocolOffloadList;
    /* 0x0208 */ PVOID ProtSendNetBufferListsComplete;
    /* 0x0210 */ PVOID SendCompleteNdisPacketContext;
    /* 0x0218 */ PVOID SendCompleteNetBufferListsContext;
    /* 0x0220 */ PVOID ReceiveNetBufferLists;
    /* 0x0228 */ PVOID ReceiveNetBufferListsContext;
    /* 0x0230 */ PVOID SavedSendPacketsHandler;
    /* 0x0238 */ PVOID SavedCancelSendPacketsHandler;
    /* 0x0240 */ PVOID SavedSendHandler;
    /* 0x0248 */ PVOID InitiateOffloadCompleteHandler;
    /* 0x0250 */ PVOID TerminateOffloadCompleteHandler;
    /* 0x0258 */ PVOID UpdateOffloadCompleteHandler;
    /* 0x0260 */ PVOID InvalidateOffloadCompleteHandler;
    /* 0x0268 */ PVOID QueryOffloadCompleteHandler;
    /* 0x0270 */ PVOID IndicateOffloadEventHandler;
    /* 0x0278 */ PVOID TcpOffloadSendCompleteHandler;
    /* 0x0280 */ PVOID TcpOffloadReceiveCompleteHandler;
    /* 0x0288 */ PVOID TcpOffloadDisconnectCompleteHandler;
    /* 0x0290 */ PVOID TcpOffloadForwardCompleteHandler;
    /* 0x0298 */ PVOID TcpOffloadEventHandler;
    /* 0x02a0 */ PVOID TcpOffloadReceiveIndicateHandler;
    /* 0x02a8 */ struct NDIS_NBL_TRACKER_HANDLE__* NblTracker;
    /* 0x02b0 */ struct NDIS_REFCOUNT_HANDLE__* RefCountTracker;
    /* 0x02b8 */ unsigned __int64 RefCountLock;
    /* 0x02c0 */ ULONG ProtocolMajorVersion;
    /* 0x02c4 */ long Padding_445;
    /* 0x02c8 */ PVOID *IfBlock;
    /* 0x02d0 */ NDIS_SPIN_LOCK PnPStateLock;
    /* 0x02e0 */ NDIS_NDIS5_DRIVER_STATE PnPState;
    /* 0x02e4 */ int OutstandingSends;
    /* 0x02e8 */ NDIS_EVENT PauseEvent;
    /* 0x0300 */ PVOID Ndis5WanSendHandler;
    /* 0x0308 */ PVOID ProtSendCompleteHandler;
    /* 0x0310 */ PVOID OidRequestCompleteHandler;
    /* 0x0318 */ struct _NDIS_OPEN_OFFLOAD* Offload;
    /* 0x0320 */ struct _NDIS_STATUS_UNBIND_WORKITEM* StatusUnbindWorkItem;
    /* 0x0328 */ unsigned __int64 DpcStartCycle;
    /* 0x0330 */ struct PNDIS_PER_PROCESSOR_SLOT__* ReceivedAPacketSlot;
    /* 0x0338 */ PVOID DirectOidRequestHandler;
    /* 0x0340 */ LIST_ENTRY ReceiveQueueList;
    /* 0x0350 */ ULONG NumReceiveQueues;
    /* 0x0354 */ long Padding_446;
    /* 0x0358 */ LIST_ENTRY SharedMemoryBlockList;
    /* 0x0368 */ PVOID AllocateSharedMemoryHandler;
    /* 0x0370 */ PVOID FreeSharedMemoryHandler;
    /* 0x0378 */ PVOID AllocateSharedMemoryContext;
    /* 0x0380 */ ULONG NumAllocatedVFs;
    /* 0x0384 */ long Padding_447;
    /* 0x0388 */ LIST_ENTRY VFList;
    /* 0x0398 */ ULONG NumActiveVPorts;
    /* 0x039c */ long Padding_448;
    /* 0x03a0 */ LIST_ENTRY VPortList;
    /* 0x03b0 */ ULONG AoAcReferences;
    /* 0x03b4 */ long Padding_449;
    /* 0x03b8 */ struct NDIS_BIND_PROTOCOL_LINK* Bind;
    /* 0x03c0 */ WORK_QUEUE_ITEM UnsolicitedUnbindComplete;
    /* 0x03e0 */ KEVENT* UnsolicitedUnbindEvent;
    /* 0x03e8 */ BOOL PendingLegacyUnbind;
    /* 0x03e9 */ char __PADDING__[7];
} NDIS_COMMON_OPEN_BLOCK_9600_10586, *PNDIS_COMMON_OPEN_BLOCK_9600_10586; /* size: 0x03f0 */

typedef struct _NDIS_COMMON_OPEN_BLOCK_14393_17134
{
    union
    {
        /* 0x0000 */ PVOID MacHandle;
        /* 0x0000 */ NDIS_OBJECT_HEADER Header;
    }; /* size: 0x0008 */
    /* 0x0008 */ PVOID BindingHandle;
    /* 0x0010 */ struct _NDIS_MINIPORT_BLOCK* MiniportHandle;
    /* 0x0018 */ struct _NDIS_PROTOCOL_BLOCK* ProtocolHandle;
    /* 0x0020 */ PVOID ProtocolBindingContext;
    /* 0x0028 */ PVOID NextSendHandler;
    /* 0x0030 */ PVOID NextSendContext;
    /* 0x0038 */ PVOID MiniportAdapterContext;
    /* 0x0040 */ UCHAR Reserved1;
    /* 0x0041 */ UCHAR CallingFromNdis6Protocol;
    /* 0x0042 */ UCHAR Reserved3;
    /* 0x0043 */ UCHAR Reserved4;
    /* 0x0044 */ long Padding_374;
    /* 0x0048 */ PVOID NextReturnNetBufferListsHandler;
    /* 0x0050 */ unsigned __int64 Reserved5;
    /* 0x0058 */ PVOID NextReturnNetBufferListsContext;
    union
    {
        /* 0x0060 */ PVOID SendHandler;
        /* 0x0060 */ PVOID WanSendHandler;
    }; /* size: 0x0008 */
    /* 0x0068 */ PVOID TransferDataHandler;
    /* 0x0070 */ PVOID SendCompleteHandler;
    /* 0x0078 */ PVOID TransferDataCompleteHandler;
    /* 0x0080 */ PVOID ReceiveHandler;
    /* 0x0088 */ PVOID ReceiveCompleteHandler;
    /* 0x0090 */ PVOID WanReceiveHandler;
    /* 0x0098 */ PVOID RequestCompleteHandler;
    /* 0x00a0 */ PVOID ReceivePacketHandler;
    /* 0x00a8 */ PVOID SendPacketsHandler;
    /* 0x00b0 */ PVOID ResetHandler;
    /* 0x00b8 */ PVOID RequestHandler;
    /* 0x00c0 */ PVOID OidRequestHandler;
    /* 0x00c8 */ PVOID ResetCompleteHandler;
    union
    {
        /* 0x00d0 */ PVOID StatusHandler;
        /* 0x00d0 */ PVOID StatusHandlerEx;
    }; /* size: 0x0008 */
    /* 0x00d8 */ PVOID StatusCompleteHandler;
    /* 0x00e0 */ volatile ULONG OpenFlags;
    /* 0x00e4 */ long References;
    /* 0x00e8 */ unsigned __int64 SpinLock;
    /* 0x00f0 */ PVOID FilterHandle;
    /* 0x00f8 */ unsigned int FrameTypeArraySize;
    /* 0x00fc */ unsigned short FrameTypeArray[4];
    /* 0x0104 */ ULONG ProtocolOptions;
    /* 0x0108 */ ULONG CurrentLookahead;
    /* 0x010c */ long Padding_375;
    /* 0x0110 */ PVOID WSendHandler;
    /* 0x0118 */ PVOID WTransferDataHandler;
    /* 0x0120 */ PVOID WSendPacketsHandler;
    /* 0x0128 */ PVOID CancelSendPacketsHandler;
    /* 0x0130 */ ULONG WakeUpEnable;
    /* 0x0134 */ NDIS_PM_PARAMETERS PMCurrentParameters;
    /* 0x0148 */ KEVENT* CloseCompleteEvent;
    /* 0x0150 */ QUEUED_CLOSE QC;
    /* 0x0178 */ long AfReferences;
    /* 0x017c */ long Padding_376;
    /* 0x0180 */ struct _NDIS_OPEN_BLOCK* NextGlobalOpen;
    /* 0x0188 */ struct _NDIS_OPEN_BLOCK* MiniportNextOpen;
    /* 0x0190 */ struct _NDIS_OPEN_BLOCK* ProtocolNextOpen;
    /* 0x0198 */ struct _UNICODE_STRING* BindDeviceName;
    /* 0x01a0 */ struct _UNICODE_STRING* RootDeviceName;
    /* 0x01a8 */ struct _NDIS_OPEN_BLOCK* FilterNextOpen;
    /* 0x01b0 */ unsigned int PacketFilters;
    /* 0x01b4 */ unsigned int OldPacketFilters;
    /* 0x01b8 */ unsigned int MaxMulticastAddresses;
    /* 0x01bc */ long Padding_377;
    /* 0x01c0 */ struct _ETH_MULTICAST_WRAPPER* MCastAddressBuf;
    /* 0x01c8 */ unsigned int NumAddresses;
    /* 0x01cc */ long Padding_378;
    /* 0x01d0 */ struct _ETH_MULTICAST_WRAPPER* OldMCastAddressBuf;
    /* 0x01d8 */ unsigned int OldNumAddresses;
    /* 0x01dc */ long Padding_379;
    /* 0x01e0 */ UCHAR* RssParametersBuffer;
    /* 0x01e8 */ struct _NDIS_RECEIVE_SCALE_PARAMETERS* NdisRSSParameters;
    /* 0x01f0 */ SINGLE_LIST_ENTRY PatternList;
    /* 0x01f8 */ SINGLE_LIST_ENTRY WOLPatternList;
    /* 0x0200 */ SINGLE_LIST_ENTRY PMProtocolOffloadList;
    /* 0x0208 */ PVOID ProtSendNetBufferListsComplete;
    /* 0x0210 */ PVOID SendCompleteNdisPacketContext;
    /* 0x0218 */ PVOID SendCompleteNetBufferListsContext;
    /* 0x0220 */ PVOID ReceiveNetBufferLists;
    /* 0x0228 */ PVOID ReceiveNetBufferListsContext;
    /* 0x0230 */ PVOID SavedSendPacketsHandler;
    /* 0x0238 */ PVOID SavedCancelSendPacketsHandler;
    /* 0x0240 */ PVOID SavedSendHandler;
    /* 0x0248 */ PVOID InitiateOffloadCompleteHandler;
    /* 0x0250 */ PVOID TerminateOffloadCompleteHandler;
    /* 0x0258 */ PVOID UpdateOffloadCompleteHandler;
    /* 0x0260 */ PVOID InvalidateOffloadCompleteHandler;
    /* 0x0268 */ PVOID QueryOffloadCompleteHandler;
    /* 0x0270 */ PVOID IndicateOffloadEventHandler;
    /* 0x0278 */ PVOID TcpOffloadSendCompleteHandler;
    /* 0x0280 */ PVOID TcpOffloadReceiveCompleteHandler;
    /* 0x0288 */ PVOID TcpOffloadDisconnectCompleteHandler;
    /* 0x0290 */ PVOID TcpOffloadForwardCompleteHandler;
    /* 0x0298 */ PVOID TcpOffloadEventHandler;
    /* 0x02a0 */ PVOID TcpOffloadReceiveIndicateHandler;
    /* 0x02a8 */ struct NDIS_NBL_TRACKER_HANDLE__* NblTracker;
    /* 0x02b0 */ struct NDIS_REFCOUNT_HANDLE__* RefCountTracker;
    /* 0x02b8 */ unsigned __int64 RefCountLock;
    /* 0x02c0 */ ULONG ProtocolMajorVersion;
    /* 0x02c4 */ long Padding_380;
    /* 0x02c8 */ PVOID * IfBlock;
    /* 0x02d0 */ NDIS_SPIN_LOCK PnPStateLock;
    /* 0x02e0 */ NDIS_NDIS5_DRIVER_STATE PnPState;
    /* 0x02e4 */ int OutstandingSends;
    /* 0x02e8 */ NDIS_EVENT PauseEvent;
    /* 0x0300 */ PVOID Ndis5WanSendHandler;
    /* 0x0308 */ PVOID ProtSendCompleteHandler;
    /* 0x0310 */ PVOID OidRequestCompleteHandler;
    /* 0x0318 */ struct _NDIS_OPEN_OFFLOAD* Offload;
    /* 0x0320 */ struct _NDIS_STATUS_UNBIND_WORKITEM* StatusUnbindWorkItem;
    /* 0x0328 */ unsigned __int64 DpcStartCycle;
    /* 0x0330 */ struct PNDIS_PER_PROCESSOR_SLOT__* ReceivedAPacketSlot;
    /* 0x0338 */ PVOID DirectOidRequestHandler;
    /* 0x0340 */ LIST_ENTRY ReceiveQueueList;
    /* 0x0350 */ ULONG NumReceiveQueues;
    /* 0x0354 */ long Padding_381;
    /* 0x0358 */ LIST_ENTRY SharedMemoryBlockList;
    /* 0x0368 */ PVOID AllocateSharedMemoryHandler;
    /* 0x0370 */ PVOID FreeSharedMemoryHandler;
    /* 0x0378 */ PVOID AllocateSharedMemoryContext;
    /* 0x0380 */ ULONG NumAllocatedVFs;
    /* 0x0384 */ long Padding_382;
    /* 0x0388 */ LIST_ENTRY VFList;
    /* 0x0398 */ ULONG NumActiveVPorts;
    /* 0x039c */ long Padding_383;
    /* 0x03a0 */ LIST_ENTRY VPortList;
    /* 0x03b0 */ ULONG AoAcReferences;
    /* 0x03b4 */ long Padding_384;
    /* 0x03b8 */ struct NDIS_BIND_PROTOCOL_LINK* Bind;
    /* 0x03c0 */ WORK_QUEUE_ITEM UnsolicitedUnbindComplete;
    /* 0x03e0 */ KEVENT* UnsolicitedUnbindEvent;
    /* 0x03e8 */ BOOL PendingLegacyUnbind;
    /* 0x03e9 */ char Padding_385[7];
    /* 0x03f0 */ KEVENT* WaitNetPnpEvent;
} NDIS_COMMON_OPEN_BLOCK_14393_17134, *PNDIS_COMMON_OPEN_BLOCK_14393_17134; /* size: 0x03f8 */

typedef struct _NDIS_COMMON_OPEN_BLOCK_17763_18362
{
    union
    {
        /* 0x0000 */ PVOID MacHandle;
        /* 0x0000 */ NDIS_OBJECT_HEADER Header;
    }; /* size: 0x0008 */
    /* 0x0008 */ PVOID BindingHandle;
    /* 0x0010 */ struct _NDIS_MINIPORT_BLOCK* MiniportHandle;
    /* 0x0018 */ struct _NDIS_PROTOCOL_BLOCK* ProtocolHandle;
    /* 0x0020 */ PVOID ProtocolBindingContext;
    /* 0x0028 */ PVOID NextSendHandler;
    /* 0x0030 */ PVOID NextSendContext;
    /* 0x0038 */ PVOID MiniportAdapterContext;
    /* 0x0040 */ UCHAR Reserved1;
    /* 0x0041 */ UCHAR CallingFromNdis6Protocol;
    /* 0x0042 */ UCHAR Reserved3;
    /* 0x0043 */ UCHAR Reserved4;
    /* 0x0044 */ long Padding_367;
    /* 0x0048 */ PVOID NextReturnNetBufferListsHandler;
    /* 0x0050 */ unsigned __int64 Reserved5;
    /* 0x0058 */ PVOID NextReturnNetBufferListsContext;
    union
    {
        /* 0x0060 */ PVOID SendHandler;
        /* 0x0060 */ PVOID WanSendHandler;
    }; /* size: 0x0008 */
    /* 0x0068 */ PVOID TransferDataHandler;
    /* 0x0070 */ PVOID SendCompleteHandler;
    /* 0x0078 */ PVOID TransferDataCompleteHandler;
    /* 0x0080 */ PVOID ReceiveHandler;
    /* 0x0088 */ PVOID ReceiveCompleteHandler;
    /* 0x0090 */ PVOID WanReceiveHandler;
    /* 0x0098 */ PVOID RequestCompleteHandler;
    /* 0x00a0 */ PVOID ReceivePacketHandler;
    /* 0x00a8 */ PVOID SendPacketsHandler;
    /* 0x00b0 */ PVOID ResetHandler;
    /* 0x00b8 */ PVOID RequestHandler;
    /* 0x00c0 */ PVOID OidRequestHandler;
    /* 0x00c8 */ PVOID ResetCompleteHandler;
    union
    {
        /* 0x00d0 */ PVOID StatusHandler;
        /* 0x00d0 */ PVOID StatusHandlerEx;
    }; /* size: 0x0008 */
    /* 0x00d8 */ PVOID StatusCompleteHandler;
    /* 0x00e0 */ volatile ULONG OpenFlags;
    /* 0x00e4 */ long References;
    /* 0x00e8 */ unsigned __int64 SpinLock;
    /* 0x00f0 */ PVOID FilterHandle;
    /* 0x00f8 */ unsigned int FrameTypeArraySize;
    /* 0x00fc */ unsigned short FrameTypeArray[4];
    /* 0x0104 */ ULONG ProtocolOptions;
    /* 0x0108 */ ULONG CurrentLookahead;
    /* 0x010c */ long Padding_368;
    /* 0x0110 */ PVOID WSendHandler;
    /* 0x0118 */ PVOID WTransferDataHandler;
    /* 0x0120 */ PVOID WSendPacketsHandler;
    /* 0x0128 */ PVOID CancelSendPacketsHandler;
    /* 0x0130 */ ULONG WakeUpEnable;
    /* 0x0134 */ NDIS_PM_PARAMETERS PMCurrentParameters;
    /* 0x0148 */ KEVENT* CloseCompleteEvent;
    /* 0x0150 */ QUEUED_CLOSE QC;
    /* 0x0178 */ long AfReferences;
    /* 0x017c */ long Padding_369;
    /* 0x0180 */ struct _NDIS_OPEN_BLOCK* NextGlobalOpen;
    /* 0x0188 */ struct _NDIS_OPEN_BLOCK* MiniportNextOpen;
    /* 0x0190 */ struct _NDIS_OPEN_BLOCK* ProtocolNextOpen;
    /* 0x0198 */ struct _UNICODE_STRING* BindDeviceName;
    /* 0x01a0 */ struct _UNICODE_STRING* RootDeviceName;
    /* 0x01a8 */ struct _NDIS_OPEN_BLOCK* FilterNextOpen;
    /* 0x01b0 */ unsigned int PacketFilters;
    /* 0x01b4 */ unsigned int OldPacketFilters;
    /* 0x01b8 */ unsigned int MaxMulticastAddresses;
    /* 0x01bc */ long Padding_370;
    /* 0x01c0 */ struct _ETH_MULTICAST_WRAPPER* MCastAddressBuf;
    /* 0x01c8 */ unsigned int NumAddresses;
    /* 0x01cc */ long Padding_371;
    /* 0x01d0 */ struct _ETH_MULTICAST_WRAPPER* OldMCastAddressBuf;
    /* 0x01d8 */ unsigned int OldNumAddresses;
    /* 0x01dc */ long Padding_372;
    /* 0x01e0 */ UCHAR* RssParametersBuffer;
    /* 0x01e8 */ struct _NDIS_RECEIVE_SCALE_PARAMETERS* NdisRSSParameters;
    /* 0x01f0 */ SINGLE_LIST_ENTRY PatternList;
    /* 0x01f8 */ SINGLE_LIST_ENTRY WOLPatternList;
    /* 0x0200 */ SINGLE_LIST_ENTRY PMProtocolOffloadList;
    /* 0x0208 */ PVOID ProtSendNetBufferListsComplete;
    /* 0x0210 */ PVOID SendCompleteNdisPacketContext;
    /* 0x0218 */ PVOID SendCompleteNetBufferListsContext;
    /* 0x0220 */ PVOID ReceiveNetBufferLists;
    /* 0x0228 */ PVOID ReceiveNetBufferListsContext;
    /* 0x0230 */ PVOID SavedSendPacketsHandler;
    /* 0x0238 */ PVOID SavedCancelSendPacketsHandler;
    /* 0x0240 */ PVOID SavedSendHandler;
    /* 0x0248 */ struct NDIS_NBL_TRACKER_HANDLE__* NblTracker;
    /* 0x0250 */ struct NDIS_REFCOUNT_HANDLE__* RefCountTracker;
    /* 0x0258 */ unsigned __int64 RefCountLock;
    /* 0x0260 */ ULONG ProtocolMajorVersion;
    /* 0x0264 */ long Padding_373;
    /* 0x0268 */ PVOID* IfBlock;
    /* 0x0270 */ NDIS_SPIN_LOCK PnPStateLock;
    /* 0x0280 */ NDIS_NDIS5_DRIVER_STATE PnPState;
    /* 0x0284 */ int OutstandingSends;
    /* 0x0288 */ NDIS_EVENT PauseEvent;
    /* 0x02a0 */ PVOID Ndis5WanSendHandler;
    /* 0x02a8 */ PVOID ProtSendCompleteHandler;
    /* 0x02b0 */ PVOID OidRequestCompleteHandler;
    /* 0x02b8 */ struct _NDIS_OPEN_OFFLOAD* Offload;
    /* 0x02c0 */ struct _NDIS_STATUS_UNBIND_WORKITEM* StatusUnbindWorkItem;
    /* 0x02c8 */ unsigned __int64 DpcStartCycle;
    /* 0x02d0 */ struct PNDIS_PER_PROCESSOR_SLOT__* ReceivedAPacketSlot;
    /* 0x02d8 */ PVOID DirectOidRequestHandler;
    /* 0x02e0 */ LIST_ENTRY ReceiveQueueList;
    /* 0x02f0 */ ULONG NumReceiveQueues;
    /* 0x02f4 */ long Padding_374;
    /* 0x02f8 */ LIST_ENTRY SharedMemoryBlockList;
    /* 0x0308 */ PVOID AllocateSharedMemoryHandler;
    /* 0x0310 */ PVOID FreeSharedMemoryHandler;
    /* 0x0318 */ PVOID AllocateSharedMemoryContext;
    /* 0x0320 */ ULONG NumAllocatedVFs;
    /* 0x0324 */ long Padding_375;
    /* 0x0328 */ struct _LIST_ENTRY VFList;
    /* 0x0338 */ ULONG NumActiveVPorts;
    /* 0x033c */ long Padding_376;
    /* 0x0340 */ struct _LIST_ENTRY VPortList;
    /* 0x0350 */ ULONG AoAcReferences;
    /* 0x0354 */ long Padding_377;
    /* 0x0358 */ struct NDIS_BIND_PROTOCOL_LINK* Bind;
    /* 0x0360 */ WORK_QUEUE_ITEM UnsolicitedUnbindComplete;
    /* 0x0380 */ KEVENT* UnsolicitedUnbindEvent;
    /* 0x0388 */ BOOL PendingLegacyUnbind;
    /* 0x0389 */ char Padding_378[7];
    /* 0x0390 */ KEVENT* WaitNetPnpEvent;
    /* 0x0398 */ PKTMON_COMPONENT_CONTEXT PktMonComp;
    /* 0x03a8 */ PKTMON_EDGE_CONTEXT PktMonEdge;
} NDIS_COMMON_OPEN_BLOCK_17763_18362, *PNDIS_COMMON_OPEN_BLOCK_17763_18362; /* size: 0x03c0 */

typedef struct _NDIS_PROTOCOL_BLOCK_7601 {
    NDIS_OBJECT_HEADER Header;
    LONG Padding_289;
    PVOID ProtocolDriverContext;
    struct _NDIS_PROTOCOL_BLOCK_7601* NextProtocol;
    NDIS_OPEN_BLOCK_7601* OpenQueue;
    REFERENCE Ref;
    UCHAR MajorNdisVersion;
    UCHAR MinorNdisVersion;
    UCHAR MajorDriverVersion;
    UCHAR MinorDriverVersion;
    UINT Reserved;
    UINT Flags;
    LONG Padding_290;
    UNICODE_STRING Name;
    UCHAR IsIPv4;
    UCHAR IsIPv6;
    UCHAR IsNdisTest6;
    CHAR Padding_291[5];
    PVOID BindAdapterHandlerEx;
    PVOID UnbindAdapterHandlerEx;
    PVOID OpenAdapterCompleteHandlerEx;
    PVOID CloseAdapterCompleteHandlerEx;
    union
    {
        PVOID PnPEventHandler;
        PVOID NetPnPEventHandler;
    } u1;
    PVOID UnloadHandler;
    PVOID UninstallHandler;
    PVOID RequestCompleteHandler;
    union
    {
        PVOID StatusHandlerEx;
        PVOID StatusHandler;
    } u2;
    PVOID StatusCompleteHandler;
    PVOID ReceiveNetBufferListsHandler;
    PVOID SendNetBufferListsCompleteHandler;
    union
    {
        PVOID CoStatusHandlerEx;
        PVOID CoStatusHandler;
    } u3;
    PVOID CoAfRegisterNotifyHandler;
    PVOID CoReceiveNetBufferListsHandler;
    PVOID CoSendNetBufferListsCompleteHandler;
    PVOID OpenAdapterCompleteHandler;
    PVOID CloseAdapterCompleteHandler;
    union
    {
        PVOID SendCompleteHandler;
        PVOID WanSendCompleteHandler;
    } u4;
    union
    {
        PVOID TransferDataCompleteHandler;
        PVOID WanTransferDataCompleteHandler;
    } u5;
    PVOID ResetCompleteHandler;
    union
    {
        PVOID ReceiveHandler;
        PVOID WanReceiveHandler;
    } u6;
    PVOID ReceiveCompleteHandler;
    PVOID ReceivePacketHandler;
    PVOID BindAdapterHandler;
    PVOID UnbindAdapterHandler;
    PVOID CoSendCompleteHandler;
    PVOID CoReceivePacketHandler;
    PVOID OidRequestCompleteHandler;
    WORK_QUEUE_ITEM WorkItem;
    KMUTANT Mutex;
    PVOID MutexOwnerThread;
    ULONG MutexOwnerCount;
    ULONG MutexOwner;
    UNICODE_STRING* BindDeviceName;
    UNICODE_STRING* RootDeviceName;
    struct _NDIS_M_DRIVER_BLOCK* AssociatedMiniDriver;
    struct _NDIS_MINIPORT_BLOCK* BindingAdapter;
    KEVENT* DeregEvent;
    union
    {
        NDIS_CO_CLIENT_OPTIONAL_HANDLERS ClientChars;
        NDIS_CO_CALL_MANAGER_OPTIONAL_HANDLERS CallMgrChars;
    } u7;
    PVOID InitiateOffloadCompleteHandler;
    PVOID TerminateOffloadCompleteHandler;
    PVOID UpdateOffloadCompleteHandler;
    PVOID InvalidateOffloadCompleteHandler;
    PVOID QueryOffloadCompleteHandler;
    PVOID IndicateOffloadEventHandler;
    PVOID TcpOffloadSendCompleteHandler;
    PVOID TcpOffloadReceiveCompleteHandler;
    PVOID TcpOffloadDisconnectCompleteHandler;
    PVOID TcpOffloadForwardCompleteHandler;
    PVOID TcpOffloadEventHandler;
    PVOID TcpOffloadReceiveIndicateHandler;
    PVOID DirectOidRequestCompleteHandler;
    PVOID AllocateSharedMemoryHandler;
    PVOID FreeSharedMemoryHandler;
    PVOID AllocateSharedMemoryContext;
    UNICODE_STRING ImageName;
} NDIS_PROTOCOL_BLOCK_7601, *PNDIS_PROTOCOL_BLOCK_7601;  /* size: 0x0300 */

typedef struct _NDIS_PROTOCOL_BLOCK_9200
{
    /* 0x0000 */ NDIS_OBJECT_HEADER Header;
    /* 0x0004 */ long Padding_81;
    /* 0x0008 */ PVOID ProtocolDriverContext;
    /* 0x0010 */ struct _NDIS_PROTOCOL_BLOCK* NextProtocol;
    /* 0x0018 */ struct _NDIS_OPEN_BLOCK* OpenQueue;
    /* 0x0020 */ REFERENCE_EX Ref;
    /* 0x0038 */ UCHAR MajorNdisVersion;
    /* 0x0039 */ UCHAR MinorNdisVersion;
    /* 0x003a */ UCHAR MajorDriverVersion;
    /* 0x003b */ UCHAR MinorDriverVersion;
    /* 0x003c */ unsigned int Reserved;
    /* 0x0040 */ unsigned int Flags;
    /* 0x0044 */ long Padding_82;
    /* 0x0048 */ UNICODE_STRING Name;
    /* 0x0058 */ UCHAR IsIPv4;
    /* 0x0059 */ UCHAR IsIPv6;
    /* 0x005a */ UCHAR IsNdisTest6;
    /* 0x005b */ char Padding_83[5];
    /* 0x0060 */ PVOID BindAdapterHandlerEx;
    /* 0x0068 */ PVOID UnbindAdapterHandlerEx;
    /* 0x0070 */ PVOID OpenAdapterCompleteHandlerEx;
    /* 0x0078 */ PVOID CloseAdapterCompleteHandlerEx;
    union
    {
        /* 0x0080 */ PVOID PnPEventHandler;
        /* 0x0080 */ PVOID NetPnPEventHandler;
    } u1; /* size: 0x0008 */
    /* 0x0088 */ PVOID UnloadHandler;
    /* 0x0090 */ PVOID UninstallHandler;
    /* 0x0098 */ PVOID RequestCompleteHandler;
    union
    {
        /* 0x00a0 */ PVOID StatusHandlerEx;
        /* 0x00a0 */ PVOID StatusHandler;
    } u2; /* size: 0x0008 */
    /* 0x00a8 */ PVOID StatusCompleteHandler;
    /* 0x00b0 */ PVOID ReceiveNetBufferListsHandler;
    /* 0x00b8 */ PVOID SendNetBufferListsCompleteHandler;
    union
    {
        /* 0x00c0 */ PVOID CoStatusHandlerEx;
        /* 0x00c0 */ PVOID CoStatusHandler;
    } u3; /* size: 0x0008 */
    /* 0x00c8 */ PVOID CoAfRegisterNotifyHandler;
    /* 0x00d0 */ PVOID CoReceiveNetBufferListsHandler;
    /* 0x00d8 */ PVOID CoSendNetBufferListsCompleteHandler;
    /* 0x00e0 */ PVOID OpenAdapterCompleteHandler;
    /* 0x00e8 */ PVOID CloseAdapterCompleteHandler;
    union
    {
        /* 0x00f0 */ PVOID SendCompleteHandler;
        /* 0x00f0 */ PVOID WanSendCompleteHandler;
    } u4; /* size: 0x0008 */
    union
    {
        /* 0x00f8 */ PVOID TransferDataCompleteHandler;
        /* 0x00f8 */ PVOID WanTransferDataCompleteHandler;
    } u5; /* size: 0x0008 */
    /* 0x0100 */ PVOID ResetCompleteHandler;
    union
    {
        /* 0x0108 */ PVOID ReceiveHandler;
        /* 0x0108 */ PVOID WanReceiveHandler;
    } u6; /* size: 0x0008 */
    /* 0x0110 */ PVOID ReceiveCompleteHandler;
    /* 0x0118 */ PVOID ReceivePacketHandler;
    /* 0x0120 */ PVOID BindAdapterHandler;
    /* 0x0128 */ PVOID UnbindAdapterHandler;
    /* 0x0130 */ PVOID CoSendCompleteHandler;
    /* 0x0138 */ PVOID CoReceivePacketHandler;
    /* 0x0140 */ PVOID OidRequestCompleteHandler;
    /* 0x0148 */ WORK_QUEUE_ITEM WorkItem;
    /* 0x0168 */ KMUTANT Mutex;
    /* 0x01a0 */ PVOID MutexOwnerThread;
    /* 0x01a8 */ ULONG MutexOwnerCount;
    /* 0x01ac */ ULONG MutexOwner;
    /* 0x01b0 */ struct _UNICODE_STRING* BindDeviceName;
    /* 0x01b8 */ struct _UNICODE_STRING* RootDeviceName;
    /* 0x01c0 */ struct _NDIS_M_DRIVER_BLOCK* AssociatedMiniDriver;
    /* 0x01c8 */ struct _NDIS_MINIPORT_BLOCK* BindingAdapter;
    /* 0x01d0 */ KEVENT* DeregEvent;
    /* 0x01d8 */ NDIS_CO_CLIENT_OPTIONAL_HANDLERS ClientChars;
    /* 0x0278 */ NDIS_CO_CALL_MANAGER_OPTIONAL_HANDLERS CallMgrChars;
    /* 0x0308 */ PVOID InitiateOffloadCompleteHandler;
    /* 0x0310 */ PVOID TerminateOffloadCompleteHandler;
    /* 0x0318 */ PVOID UpdateOffloadCompleteHandler;
    /* 0x0320 */ PVOID InvalidateOffloadCompleteHandler;
    /* 0x0328 */ PVOID QueryOffloadCompleteHandler;
    /* 0x0330 */ PVOID IndicateOffloadEventHandler;
    /* 0x0338 */ PVOID TcpOffloadSendCompleteHandler;
    /* 0x0340 */ PVOID TcpOffloadReceiveCompleteHandler;
    /* 0x0348 */ PVOID TcpOffloadDisconnectCompleteHandler;
    /* 0x0350 */ PVOID TcpOffloadForwardCompleteHandler;
    /* 0x0358 */ PVOID TcpOffloadEventHandler;
    /* 0x0360 */ PVOID TcpOffloadReceiveIndicateHandler;
    /* 0x0368 */ PVOID DirectOidRequestCompleteHandler;
    /* 0x0370 */ PVOID AllocateSharedMemoryHandler;
    /* 0x0378 */ PVOID FreeSharedMemoryHandler;
    /* 0x0380 */ PVOID AllocateSharedMemoryContext;
    /* 0x0388 */ UNICODE_STRING ImageName;
} NDIS_PROTOCOL_BLOCK_9200, *PNDIS_PROTOCOL_BLOCK_9200; /* size: 0x0398 */

typedef struct _NDIS_PROTOCOL_BLOCK_9600_17134
{
    /* 0x0000 */ NDIS_OBJECT_HEADER Header;
    /* 0x0004 */ long Padding_265;
    /* 0x0008 */ PVOID ProtocolDriverContext;
    /* 0x0010 */ struct _NDIS_PROTOCOL_BLOCK* NextProtocol;
    /* 0x0018 */ struct _NDIS_OPEN_BLOCK* OpenQueue;
    /* 0x0020 */ REFERENCE_EX Ref;
    /* 0x0038 */ UCHAR MajorNdisVersion;
    /* 0x0039 */ UCHAR MinorNdisVersion;
    /* 0x003a */ UCHAR MajorDriverVersion;
    /* 0x003b */ UCHAR MinorDriverVersion;
    /* 0x003c */ unsigned int Reserved;
    /* 0x0040 */ unsigned int Flags;
    /* 0x0044 */ long Padding_266;
    /* 0x0048 */ UNICODE_STRING Name;
    /* 0x0058 */ UCHAR IsIPv4;
    /* 0x0059 */ UCHAR IsIPv6;
    /* 0x005a */ UCHAR IsNdisTest6;
    /* 0x005b */ char Padding_267[5];
    /* 0x0060 */ PVOID BindAdapterHandlerEx;
    /* 0x0068 */ PVOID UnbindAdapterHandlerEx;
    /* 0x0070 */ PVOID OpenAdapterCompleteHandlerEx;
    /* 0x0078 */ PVOID CloseAdapterCompleteHandlerEx;
    union
    {
        /* 0x0080 */ PVOID PnPEventHandler;
        /* 0x0080 */ PVOID NetPnPEventHandler;
    } u1; /* size: 0x0008 */
    /* 0x0088 */ PVOID UnloadHandler;
    /* 0x0090 */ PVOID UninstallHandler;
    /* 0x0098 */ PVOID RequestCompleteHandler;
    union
    {
        /* 0x00a0 */ PVOID StatusHandlerEx;
        /* 0x00a0 */ PVOID StatusHandler;
    } u2; /* size: 0x0008 */
    /* 0x00a8 */ PVOID StatusCompleteHandler;
    /* 0x00b0 */ PVOID ReceiveNetBufferListsHandler;
    /* 0x00b8 */ PVOID SendNetBufferListsCompleteHandler;
    union
    {
        /* 0x00c0 */ PVOID CoStatusHandlerEx;
        /* 0x00c0 */ PVOID CoStatusHandler;
    } u3; /* size: 0x0008 */
    /* 0x00c8 */ PVOID CoAfRegisterNotifyHandler;
    /* 0x00d0 */ PVOID CoReceiveNetBufferListsHandler;
    /* 0x00d8 */ PVOID CoSendNetBufferListsCompleteHandler;
    /* 0x00e0 */ PVOID OpenAdapterCompleteHandler;
    /* 0x00e8 */ PVOID CloseAdapterCompleteHandler;
    union
    {
        /* 0x00f0 */ PVOID SendCompleteHandler;
        /* 0x00f0 */ PVOID WanSendCompleteHandler;
    } u4; /* size: 0x0008 */
    union
    {
        /* 0x00f8 */ PVOID TransferDataCompleteHandler;
        /* 0x00f8 */ PVOID WanTransferDataCompleteHandler;
    } u5; /* size: 0x0008 */
    /* 0x0100 */ PVOID ResetCompleteHandler;
    union
    {
        /* 0x0108 */ PVOID ReceiveHandler;
        /* 0x0108 */ PVOID WanReceiveHandler;
    } u6; /* size: 0x0008 */
    /* 0x0110 */ PVOID ReceiveCompleteHandler;
    /* 0x0118 */ PVOID ReceivePacketHandler;
    /* 0x0120 */ PVOID BindAdapterHandler;
    /* 0x0128 */ PVOID UnbindAdapterHandler;
    /* 0x0130 */ PVOID CoSendCompleteHandler;
    /* 0x0138 */ PVOID CoReceivePacketHandler;
    /* 0x0140 */ PVOID OidRequestCompleteHandler;
    /* 0x0148 */ WORK_QUEUE_ITEM WorkItem;
    /* 0x0168 */ KMUTANT Mutex;
    /* 0x01a0 */ PVOID MutexOwnerThread;
    /* 0x01a8 */ ULONG MutexOwnerCount;
    /* 0x01ac */ ULONG MutexOwner;
    /* 0x01b0 */ struct _UNICODE_STRING* BindDeviceName;
    /* 0x01b8 */ struct _UNICODE_STRING* RootDeviceName;
    /* 0x01c0 */ struct _NDIS_M_DRIVER_BLOCK* AssociatedMiniDriver;
    /* 0x01c8 */ struct _NDIS_MINIPORT_BLOCK* BindingAdapter;
    /* 0x01d0 */ KEVENT* DeregEvent;
    /* 0x01d8 */ NDIS_CO_CLIENT_OPTIONAL_HANDLERS ClientChars;
    /* 0x0278 */ NDIS_CO_CALL_MANAGER_OPTIONAL_HANDLERS CallMgrChars;
    /* 0x0308 */ PVOID InitiateOffloadCompleteHandler;
    /* 0x0310 */ PVOID TerminateOffloadCompleteHandler;
    /* 0x0318 */ PVOID UpdateOffloadCompleteHandler;
    /* 0x0320 */ PVOID InvalidateOffloadCompleteHandler;
    /* 0x0328 */ PVOID QueryOffloadCompleteHandler;
    /* 0x0330 */ PVOID IndicateOffloadEventHandler;
    /* 0x0338 */ PVOID TcpOffloadSendCompleteHandler;
    /* 0x0340 */ PVOID TcpOffloadReceiveCompleteHandler;
    /* 0x0348 */ PVOID TcpOffloadDisconnectCompleteHandler;
    /* 0x0350 */ PVOID TcpOffloadForwardCompleteHandler;
    /* 0x0358 */ PVOID TcpOffloadEventHandler;
    /* 0x0360 */ PVOID TcpOffloadReceiveIndicateHandler;
    /* 0x0368 */ PVOID DirectOidRequestCompleteHandler;
    /* 0x0370 */ PVOID AllocateSharedMemoryHandler;
    /* 0x0378 */ PVOID FreeSharedMemoryHandler;
    /* 0x0380 */ PVOID AllocateSharedMemoryContext;
    /* 0x0388 */ UNICODE_STRING ImageName;
    /* 0x0398 */ PVOID Bind; //class pointer
    /* 0x03a0 */ PVOID NotifyBindCompleteWorkItem; //class pointer
} NDIS_PROTOCOL_BLOCK_9600_17134, *PNDIS_PROTOCOL_BLOCK_9600_17134; /* size: 0x03d8 */

typedef struct _NDIS_PROTOCOL_BLOCK_17763
{
    /* 0x0000 */ NDIS_OBJECT_HEADER Header;
    /* 0x0004 */ long Padding_126;
    /* 0x0008 */ PVOID ProtocolDriverContext;
    /* 0x0010 */ struct _NDIS_PROTOCOL_BLOCK* NextProtocol;
    /* 0x0018 */ struct _NDIS_OPEN_BLOCK* OpenQueue;
    /* 0x0020 */ REFERENCE_EX Ref;
    /* 0x0038 */ UCHAR MajorNdisVersion;
    /* 0x0039 */ UCHAR MinorNdisVersion;
    /* 0x003a */ UCHAR MajorDriverVersion;
    /* 0x003b */ UCHAR MinorDriverVersion;
    /* 0x003c */ unsigned int Reserved;
    /* 0x0040 */ unsigned int Flags;
    /* 0x0044 */ long Padding_127;
    /* 0x0048 */ UNICODE_STRING Name;
    /* 0x0058 */ UCHAR IsIPv4;
    /* 0x0059 */ UCHAR IsIPv6;
    /* 0x005a */ UCHAR IsNdisTest6;
    /* 0x005b */ char Padding_128[5];
    /* 0x0060 */ PVOID BindAdapterHandlerEx;
    /* 0x0068 */ PVOID UnbindAdapterHandlerEx;
    /* 0x0070 */ PVOID OpenAdapterCompleteHandlerEx;
    /* 0x0078 */ PVOID CloseAdapterCompleteHandlerEx;
    union
    {
        /* 0x0080 */ PVOID PnPEventHandler;
        /* 0x0080 */ PVOID NetPnPEventHandler;
    } u1; /* size: 0x0008 */
    /* 0x0088 */ PVOID UnloadHandler;
    /* 0x0090 */ PVOID UninstallHandler;
    /* 0x0098 */ PVOID RequestCompleteHandler;
    union
    {
        /* 0x00a0 */ PVOID StatusHandlerEx;
        /* 0x00a0 */ PVOID StatusHandler;
    } u2; /* size: 0x0008 */
    /* 0x00a8 */ PVOID StatusCompleteHandler;
    /* 0x00b0 */ PVOID ReceiveNetBufferListsHandler;
    /* 0x00b8 */ PVOID SendNetBufferListsCompleteHandler;
    union
    {
        /* 0x00c0 */ PVOID CoStatusHandlerEx;
        /* 0x00c0 */ PVOID CoStatusHandler;
    } u3; /* size: 0x0008 */
    /* 0x00c8 */ PVOID CoAfRegisterNotifyHandler;
    /* 0x00d0 */ PVOID CoReceiveNetBufferListsHandler;
    /* 0x00d8 */ PVOID CoSendNetBufferListsCompleteHandler;
    /* 0x00e0 */ PVOID OpenAdapterCompleteHandler;
    /* 0x00e8 */ PVOID CloseAdapterCompleteHandler;
    union
    {
        /* 0x00f0 */ PVOID SendCompleteHandler;
        /* 0x00f0 */ PVOID WanSendCompleteHandler;
    } u4; /* size: 0x0008 */
    union
    {
        /* 0x00f8 */ PVOID TransferDataCompleteHandler;
        /* 0x00f8 */ PVOID WanTransferDataCompleteHandler;
    } u5; /* size: 0x0008 */
    /* 0x0100 */ PVOID ResetCompleteHandler;
    union
    {
        /* 0x0108 */ PVOID ReceiveHandler;
        /* 0x0108 */ PVOID WanReceiveHandler;
    } u6; /* size: 0x0008 */
    /* 0x0110 */ PVOID ReceiveCompleteHandler;
    /* 0x0118 */ PVOID ReceivePacketHandler;
    /* 0x0120 */ PVOID BindAdapterHandler;
    /* 0x0128 */ PVOID UnbindAdapterHandler;
    /* 0x0130 */ PVOID CoSendCompleteHandler;
    /* 0x0138 */ PVOID CoReceivePacketHandler;
    /* 0x0140 */ PVOID OidRequestCompleteHandler;
    /* 0x0148 */ WORK_QUEUE_ITEM WorkItem;
    /* 0x0168 */ KMUTANT Mutex;
    /* 0x01a0 */ PVOID MutexOwnerThread;
    /* 0x01a8 */ ULONG MutexOwnerCount;
    /* 0x01ac */ ULONG MutexOwner;
    /* 0x01b0 */ struct _UNICODE_STRING* BindDeviceName;
    /* 0x01b8 */ struct _UNICODE_STRING* RootDeviceName;
    /* 0x01c0 */ struct _NDIS_M_DRIVER_BLOCK* AssociatedMiniDriver;
    /* 0x01c8 */ struct _NDIS_MINIPORT_BLOCK* BindingAdapter;
    /* 0x01d0 */ KEVENT* DeregEvent;
    /* 0x01d8 */ NDIS_CO_CLIENT_OPTIONAL_HANDLERS ClientChars;
    /* 0x0278 */ NDIS_CO_CALL_MANAGER_OPTIONAL_HANDLERS CallMgrChars;
    /* 0x0308 */ PVOID DirectOidRequestCompleteHandler;
    /* 0x0310 */ PVOID AllocateSharedMemoryHandler;
    /* 0x0318 */ PVOID FreeSharedMemoryHandler;
    /* 0x0320 */ PVOID AllocateSharedMemoryContext;
    /* 0x0328 */ UNICODE_STRING ImageName;
    /* 0x0338 */ PVOID Bind; //class pointer
    /* 0x0340 */ PVOID NotifyBindCompleteWorkItem; //class pointer
} NDIS_PROTOCOL_BLOCK_17763, *PNDIS_PROTOCOL_BLOCK_17763; /* size: 0x0378 */

typedef struct _NDIS_PROTOCOL_BLOCK_18362
{
    /* 0x0000 */ NDIS_OBJECT_HEADER Header;
    /* 0x0004 */ long Padding_126;
    /* 0x0008 */ PVOID ProtocolDriverContext;
    /* 0x0010 */ struct _NDIS_PROTOCOL_BLOCK* NextProtocol;
    /* 0x0018 */ struct _NDIS_OPEN_BLOCK* OpenQueue;
    /* 0x0020 */ REFERENCE_EX Ref;
    /* 0x0038 */ UCHAR MajorNdisVersion;
    /* 0x0039 */ UCHAR MinorNdisVersion;
    /* 0x003a */ UCHAR MajorDriverVersion;
    /* 0x003b */ UCHAR MinorDriverVersion;
    /* 0x003c */ unsigned int Reserved;
    /* 0x0040 */ unsigned int Flags;
    /* 0x0044 */ long Padding_127;
    /* 0x0048 */ UNICODE_STRING Name;
    /* 0x0058 */ UCHAR IsIPv4;
    /* 0x0059 */ UCHAR IsIPv6;
    /* 0x005a */ UCHAR IsNdisTest6;
    /* 0x005b */ char Padding_128[5];
    /* 0x0060 */ PVOID BindAdapterHandlerEx;
    /* 0x0068 */ PVOID UnbindAdapterHandlerEx;
    /* 0x0070 */ PVOID OpenAdapterCompleteHandlerEx;
    /* 0x0078 */ PVOID CloseAdapterCompleteHandlerEx;
    union
    {
        /* 0x0080 */ PVOID PnPEventHandler;
        /* 0x0080 */ PVOID NetPnPEventHandler;
    } u1; /* size: 0x0008 */
    /* 0x0088 */ PVOID UnloadHandler;
    /* 0x0090 */ PVOID UninstallHandler;
    /* 0x0098 */ PVOID RequestCompleteHandler;
    union
    {
        /* 0x00a0 */ PVOID StatusHandlerEx;
        /* 0x00a0 */ PVOID StatusHandler;
    } u2; /* size: 0x0008 */
    /* 0x00a8 */ PVOID StatusCompleteHandler;
    /* 0x00b0 */ PVOID ReceiveNetBufferListsHandler;
    /* 0x00b8 */ PVOID SendNetBufferListsCompleteHandler;
    union
    {
        /* 0x00c0 */ PVOID CoStatusHandlerEx;
        /* 0x00c0 */ PVOID CoStatusHandler;
    } u3; /* size: 0x0008 */
    /* 0x00c8 */ PVOID CoAfRegisterNotifyHandler;
    /* 0x00d0 */ PVOID CoReceiveNetBufferListsHandler;
    /* 0x00d8 */ PVOID CoSendNetBufferListsCompleteHandler;
    /* 0x00e0 */ PVOID OpenAdapterCompleteHandler;
    /* 0x00e8 */ PVOID CloseAdapterCompleteHandler;
    union
    {
        /* 0x00f0 */ PVOID SendCompleteHandler;
        /* 0x00f0 */ PVOID WanSendCompleteHandler;
    } u4; /* size: 0x0008 */
    union
    {
        /* 0x00f8 */ PVOID TransferDataCompleteHandler;
        /* 0x00f8 */ PVOID WanTransferDataCompleteHandler;
    } u5; /* size: 0x0008 */
    /* 0x0100 */ PVOID ResetCompleteHandler;
    union
    {
        /* 0x0108 */ PVOID ReceiveHandler;
        /* 0x0108 */ PVOID WanReceiveHandler;
    } u6; /* size: 0x0008 */
    /* 0x0110 */ PVOID ReceiveCompleteHandler;
    /* 0x0118 */ PVOID ReceivePacketHandler;
    /* 0x0120 */ PVOID BindAdapterHandler;
    /* 0x0128 */ PVOID UnbindAdapterHandler;
    /* 0x0130 */ PVOID CoSendCompleteHandler;
    /* 0x0138 */ PVOID CoReceivePacketHandler;
    /* 0x0140 */ PVOID OidRequestCompleteHandler;
    /* 0x0148 */ WORK_QUEUE_ITEM WorkItem;
    /* 0x0168 */ KMUTANT Mutex;
    /* 0x01a0 */ PVOID MutexOwnerThread;
    /* 0x01a8 */ ULONG MutexOwnerCount;
    /* 0x01ac */ ULONG Padding_220;
    /* 0x01b0 */ struct _UNICODE_STRING* BindDeviceName;
    /* 0x01b8 */ struct _UNICODE_STRING* RootDeviceName;
    /* 0x01c0 */ struct _NDIS_M_DRIVER_BLOCK* AssociatedMiniDriver;
    /* 0x01c8 */ struct _NDIS_MINIPORT_BLOCK* BindingAdapter;
    /* 0x01d0 */ KEVENT* DeregEvent;
    /* 0x01d8 */ NDIS_CO_CLIENT_OPTIONAL_HANDLERS ClientChars;
    /* 0x0278 */ NDIS_CO_CALL_MANAGER_OPTIONAL_HANDLERS CallMgrChars;
    /* 0x0308 */ PVOID DirectOidRequestCompleteHandler;
    /* 0x0310 */ PVOID AllocateSharedMemoryHandler;
    /* 0x0318 */ PVOID FreeSharedMemoryHandler;
    /* 0x0320 */ PVOID AllocateSharedMemoryContext;
    /* 0x0328 */ UNICODE_STRING ImageName;
    /* 0x0338 */ PVOID Bind; //class pointer
    /* 0x0340 */ PVOID NotifyBindCompleteWorkItem; //class pointer
} NDIS_PROTOCOL_BLOCK_18362, *PNDIS_PROTOCOL_BLOCK_18362; /* size: 0x0378 */


//
// NDIS_RTL HEADER END
//

#pragma warning(pop)


#ifdef __cplusplus
}
#endif

#endif NDIS_RTL
