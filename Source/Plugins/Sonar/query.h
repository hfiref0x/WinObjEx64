/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2025
*
*  TITLE:       QUERY.H
*
*  VERSION:     1.05
*
*  DATE:        14 May 2025
*
*  Sonar plugin query information definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define NDIS_OPEN_BLOCK_VERSION_WIN7            1
#define NDIS_OPEN_BLOCK_VERSION_WIN8            2
#define NDIS_OPEN_BLOCK_VERSION_WIN81_WIN10TH1  3
#define NDIS_OPEN_BLOCK_VERSION_WIN10_RS1_4     4
#define NDIS_OPEN_BLOCK_VERSION_WIN10_RS5_WIN11 5
#define NDIS_OPEN_BLOCK_VERSION_WIN11_22_25H2   6

typedef struct _PROTOCOL_BLOCK_VERSIONS {
    union {
        union {
            NDIS_PROTOCOL_BLOCK_7601* v1;
            NDIS_PROTOCOL_BLOCK_9200* v2;
            NDIS_PROTOCOL_BLOCK_9600_17134* v3;
            NDIS_PROTOCOL_BLOCK_17763* v4;
            NDIS_PROTOCOL_BLOCK_18362_25905* v5;
        } Versions;
        PVOID Ref;
    } u1;
} PROTOCOL_BLOCK_VERSIONS, * PPROTOCOL_BLOCK_VERSIONS;

typedef struct _OPEN_BLOCK_VERSIONS {
    union {
        union {
            NDIS_OPEN_BLOCK_7601* v1;
            NDIS_OPEN_BLOCK_9200* v2;
            union {
                NDIS_COMMON_OPEN_BLOCK_9600_10586* v3c;
                NDIS_OPEN_BLOCK_9600_10586* v3;
            } u_v3;
            union {
                NDIS_COMMON_OPEN_BLOCK_14393_17134* v4c;
                NDIS_OPEN_BLOCK_14393_17134* v4;
            } u_v4;
            union {
                NDIS_COMMON_OPEN_BLOCK_17763_22000* v5c;
                NDIS_OPEN_BLOCK_17763_22000* v5;
            } u_v5;
            union {
                NDIS_COMMON_OPEN_BLOCK_22621_25905* v6c;
                NDIS_OPEN_BLOCK_22621_25905* v6;
            } u_v6;
        } Versions;
        PVOID Ref;
    } u1;
} OPEN_BLOCK_VERSIONS, * POPEN_BLOCK_VERSIONS;

typedef enum _NDIS_OBJECT_TYPE {
    NdisObjectTypeProtocolBlock = 1,
    NdisObjectTypeOpenBlock,
    NdisObjectTypeMDriverBlock,
    NdisObjectTypeMiniportBlock,
    NdisObjectTypeInvalid
} NDIS_OBJECT_TYPE;

//
// Structure for dump convertion, only handlers, flags, unicode strings.
//
typedef struct _NDIS_OPEN_BLOCK_HANDLERS {
    PVOID NextSendHandler;
    PVOID NextReturnNetBufferListsHandler;
    PVOID SendHandler;
    PVOID TransferDataHandler;
    PVOID SendCompleteHandler;
    PVOID TransferDataCompleteHandler;
    PVOID ReceiveHandler;
    PVOID ReceiveCompleteHandler;
    PVOID WanReceiveHandler;
    PVOID RequestCompleteHandler;
    PVOID ReceivePacketHandler;
    PVOID SendPacketsHandler;
    PVOID ResetHandler;
    PVOID RequestHandler;
    PVOID OidRequestHandler;
    PVOID ResetCompleteHandler;

    PVOID StatusHandler;
    PVOID StatusCompleteHandler;

    PVOID WSendHandler;
    PVOID WTransferDataHandler;
    PVOID WSendPacketsHandler;
    PVOID CancelSendPacketsHandler;

    PVOID ProtSendNetBufferListsComplete;
    PVOID ReceiveNetBufferLists;
    PVOID SavedSendNBLHandler;
    PVOID SavedSendPacketsHandler;
    PVOID SavedCancelSendPacketsHandler;

    PVOID SavedSendHandler;

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

    PVOID Ndis5WanSendHandler;
    PVOID ProtSendCompleteHandler;
    PVOID OidRequestCompleteHandler;

    PVOID DirectOidRequestCompleteHandler;
    PVOID DirectOidRequestHandler;

    PVOID AllocateSharedMemoryHandler;
    PVOID FreeSharedMemoryHandler;

    PVOID MiniportCoCreateVcHandler;
    PVOID MiniportCoRequestHandler;
    PVOID CoCreateVcHandler;
    PVOID CoDeleteVcHandler;
    PVOID CmActivateVcCompleteHandler;
    PVOID CmDeactivateVcCompleteHandler;
    PVOID CoRequestCompleteHandler;
    PVOID CoRequestHandler;

    PVOID MiniportCoOidRequestHandler;
    PVOID CoOidRequestCompleteHandler;
    PVOID CoOidRequestHandler;
} NDIS_OPEN_BLOCK_HANDLERS, * PNDIS_OPEN_BLOCK_HANDLERS;

typedef struct _NDIS_OPEN_BLOCK_COMPATIBLE {
    PVOID ProtocolNextOpen;

    UNICODE_STRING* BindDeviceName;
    UNICODE_STRING* RootDeviceName;

    NDIS_OPEN_BLOCK_HANDLERS Handlers;

} NDIS_OPEN_BLOCK_COMPATIBLE, * PNDIS_OPEN_BLOCK_COMPATIBLE;

typedef struct _NDIS_PROTOCOL_BLOCK_HANDLERS {
    PVOID BindAdapterHandlerEx;
    PVOID UnbindAdapterHandlerEx;
    PVOID OpenAdapterCompleteHandlerEx;
    PVOID CloseAdapterCompleteHandlerEx;
    PVOID PnPEventHandler;

    PVOID UnloadHandler;
    PVOID UninstallHandler;
    PVOID RequestCompleteHandler;

    PVOID StatusHandler;

    PVOID StatusCompleteHandler;
    PVOID ReceiveNetBufferListsHandler;
    PVOID SendNetBufferListsCompleteHandler;

    PVOID CoStatusHandler;

    PVOID CoAfRegisterNotifyHandler;
    PVOID CoReceiveNetBufferListsHandler;
    PVOID CoSendNetBufferListsCompleteHandler;
    PVOID OpenAdapterCompleteHandler;
    PVOID CloseAdapterCompleteHandler;

    PVOID SendCompleteHandler;

    PVOID TransferDataCompleteHandler;

    PVOID ResetCompleteHandler;

    PVOID ReceiveHandler;

    PVOID ReceiveCompleteHandler;
    PVOID ReceivePacketHandler;
    PVOID BindAdapterHandler;
    PVOID UnbindAdapterHandler;
    PVOID CoSendCompleteHandler;
    PVOID CoReceivePacketHandler;
    PVOID OidRequestCompleteHandler;

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
} NDIS_PROTOCOL_BLOCK_HANDLERS, * PNDIS_PROTOCOL_BLOCK_HANDLERS;

typedef struct _NDIS_PROTOCOL_BLOCK_COMPATIBLE {
    UNICODE_STRING Name;
    UNICODE_STRING ImageName;
    UNICODE_STRING* BindDeviceName;
    UNICODE_STRING* RootDeviceName;

    PVOID NextProtocol;
    PVOID OpenQueue;
    PVOID AssociatedMiniDriver;

    UCHAR MajorNdisVersion;
    UCHAR MinorNdisVersion;
    UCHAR MajorDriverVersion;
    UCHAR MinorDriverVersion;

    NDIS_PROTOCOL_BLOCK_HANDLERS Handlers;

} NDIS_PROTOCOL_BLOCK_COMPATIBLE, * PNDIS_PROTOCOL_BLOCK_COMPATIBLE;

static LPCWSTR g_lpszOpenBlockHandlers[] = {
    TEXT("NextSendHandler"),
    TEXT("NextReturnNetBufferListsHandler"),
    TEXT("SendHandler"),
    TEXT("TransferDataHandler"),
    TEXT("SendCompleteHandler"),
    TEXT("TransferDataCompleteHandler"),
    TEXT("ReceiveHandler"),
    TEXT("ReceiveCompleteHandler"),
    TEXT("WanReceiveHandler"),
    TEXT("RequestCompleteHandler"),
    TEXT("ReceivePacketHandler"),
    TEXT("SendPacketsHandler"),
    TEXT("ResetHandler"),
    TEXT("RequestHandler"),
    TEXT("OidRequestHandler"),
    TEXT("ResetCompleteHandler"),

    TEXT("StatusHandler"),
    TEXT("StatusCompleteHandler"),

    TEXT("WSendHandler"),
    TEXT("WTransferDataHandler"),
    TEXT("WSendPacketsHandler"),
    TEXT("CancelSendPacketsHandler"),

    TEXT("ProtSendNetBufferListsComplete"),
    TEXT("ReceiveNetBufferLists"),
    TEXT("SavedSendNBLHandler"),
    TEXT("SavedSendPacketsHandler"),
    TEXT("SavedCancelSendPacketsHandler"),

    TEXT("SavedSendHandler"),

    TEXT("InitiateOffloadCompleteHandler"),
    TEXT("TerminateOffloadCompleteHandler"),
    TEXT("UpdateOffloadCompleteHandler"),
    TEXT("InvalidateOffloadCompleteHandler"),
    TEXT("QueryOffloadCompleteHandler"),
    TEXT("IndicateOffloadEventHandler"),
    TEXT("TcpOffloadSendCompleteHandler"),
    TEXT("TcpOffloadReceiveCompleteHandler"),
    TEXT("TcpOffloadDisconnectCompleteHandler"),
    TEXT("TcpOffloadForwardCompleteHandler"),
    TEXT("TcpOffloadEventHandler"),
    TEXT("TcpOffloadReceiveIndicateHandler"),

    TEXT("Ndis5WanSendHandler"),
    TEXT("ProtSendCompleteHandler"),
    TEXT("OidRequestCompleteHandler"),

    TEXT("DirectOidRequestCompleteHandler"),
    TEXT("DirectOidRequestHandler"),

    TEXT("AllocateSharedMemoryHandler"),
    TEXT("FreeSharedMemoryHandler"),

    TEXT("MiniportCoCreateVcHandler"),
    TEXT("MiniportCoRequestHandler"),
    TEXT("CoCreateVcHandler"),
    TEXT("CoDeleteVcHandler"),
    TEXT("CmActivateVcCompleteHandler"),
    TEXT("CmDeactivateVcCompleteHandler"),
    TEXT("CoRequestCompleteHandler"),
    TEXT("CoRequestHandler"),

    TEXT("MiniportCoOidRequestHandler"),
    TEXT("CoOidRequestCompleteHandler"),
    TEXT("CoOidRequestHandler")
};

static LPCWSTR g_lpszProtocolBlockHandlers[] = {
    TEXT("BindAdapterHandlerEx"),
    TEXT("UnbindAdapterHandlerEx"),
    TEXT("OpenAdapterCompleteHandlerEx"),
    TEXT("CloseAdapterCompleteHandlerEx"),
    TEXT("PnPEventHandler"),
    TEXT("UnloadHandler"),
    TEXT("UninstallHandler"),
    TEXT("RequestCompleteHandler"),
    TEXT("StatusHandler"),
    TEXT("StatusCompleteHandler"),
    TEXT("ReceiveNetBufferListsHandler"),
    TEXT("SendNetBufferListsCompleteHandler"),
    TEXT("CoStatusHandler"),
    TEXT("CoAfRegisterNotifyHandler"),
    TEXT("CoReceiveNetBufferListsHandler"),
    TEXT("CoSendNetBufferListsCompleteHandler"),
    TEXT("OpenAdapterCompleteHandler"),
    TEXT("CloseAdapterCompleteHandler"),
    TEXT("SendCompleteHandler"),
    TEXT("TransferDataCompleteHandler"),
    TEXT("ResetCompleteHandler"),
    TEXT("ReceiveHandler"),
    TEXT("ReceiveCompleteHandler"),
    TEXT("ReceivePacketHandler"),
    TEXT("BindAdapterHandler"),
    TEXT("UnbindAdapterHandler"),
    TEXT("CoSendCompleteHandler"),
    TEXT("CoReceivePacketHandler"),
    TEXT("OidRequestCompleteHandler"),
    TEXT("InitiateOffloadCompleteHandler"),
    TEXT("TerminateOffloadCompleteHandler"),
    TEXT("UpdateOffloadCompleteHandler"),
    TEXT("InvalidateOffloadCompleteHandler"),
    TEXT("QueryOffloadCompleteHandler"),
    TEXT("IndicateOffloadEventHandler"),
    TEXT("TcpOffloadSendCompleteHandler"),
    TEXT("TcpOffloadReceiveCompleteHandler"),
    TEXT("TcpOffloadDisconnectCompleteHandler"),
    TEXT("TcpOffloadForwardCompleteHandler"),
    TEXT("TcpOffloadEventHandler"),
    TEXT("TcpOffloadReceiveIndicateHandler"),
    TEXT("DirectOidRequestCompleteHandler"),
    TEXT("AllocateSharedMemoryHandler"),
    TEXT("FreeSharedMemoryHandler")
};

ULONG_PTR QueryProtocolList(VOID);

PVOID DumpUnicodeString(
    _In_ ULONG_PTR Address,
    _In_ WORD Length,
    _In_ WORD MaximumLength,
    _In_ BOOLEAN IsPtr);

ULONG GetNextProtocolOffset(
    _In_ ULONG WindowsVersion);

_Success_(return == TRUE)
BOOL ReadAndConvertProtocolBlock(
    _In_ ULONG_PTR ObjectAddress,
    _Inout_ NDIS_PROTOCOL_BLOCK_COMPATIBLE * ProtoBlock,
    _Out_opt_ PULONG ObjectVersion);

_Success_(return == TRUE)
BOOL ReadAndConvertOpenBlock(
    _In_ ULONG_PTR ObjectAddress,
    _Inout_ NDIS_OPEN_BLOCK_COMPATIBLE * OpenBlock,
    _Out_opt_ PULONG ObjectVersion);

