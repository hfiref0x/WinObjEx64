/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2020
*
*  TITLE:       QUERY.H
*
*  VERSION:     1.03
*
*  DATE:        17 July 2020
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

//
// Defines for Major Windows NT release builds
//

// Windows 7 RTM
#define NT_WIN7_RTM             7600

// Windows 7 SP1
#define NT_WIN7_SP1             7601

// Windows 8 RTM
#define NT_WIN8_RTM             9200

// Windows 8.1
#define NT_WIN8_BLUE            9600

// Windows 10 TH1
#define NT_WIN10_THRESHOLD1     10240

// Windows 10 TH2
#define NT_WIN10_THRESHOLD2     10586

// Windows 10 RS1
#define NT_WIN10_REDSTONE1      14393

// Windows 10 RS2
#define NT_WIN10_REDSTONE2      15063

// Windows 10 RS3
#define NT_WIN10_REDSTONE3      16299

// Windows 10 RS4
#define NT_WIN10_REDSTONE4      17134

// Windows 10 RS5
#define NT_WIN10_REDSTONE5      17763

// Windows 10 19H1
#define NT_WIN10_19H1           18362

// Windows 10 19H2
#define NT_WIN10_19H2           18363

// Windows 10 20H1
#define NT_WIN10_20H1           19041

// Windows 10 20H2
#define NT_WIN10_20H2           19042

// Windows 10 Active Develepment Branch (21H1)
#define NTX_WIN10_ADB           20161

typedef struct _PROTOCOL_BLOCK_VERSIONS {
    union {
        union {
            NDIS_PROTOCOL_BLOCK_7601 *v1;
            NDIS_PROTOCOL_BLOCK_9200 *v2;
            NDIS_PROTOCOL_BLOCK_9600_17134 *v3;
            NDIS_PROTOCOL_BLOCK_17763 *v4;
            NDIS_PROTOCOL_BLOCK_18362_20150 *v5;
        } Versions;
        PVOID Ref;
    } u1;
} PROTOCOL_BLOCK_VERSIONS, *PPROTOCOL_BLOCK_VERSIONS;

typedef struct _OPEN_BLOCK_VERSIONS {
    union {
        union {
            NDIS_OPEN_BLOCK_7601 *v1;
            NDIS_OPEN_BLOCK_9200 *v2;
            union {
                NDIS_COMMON_OPEN_BLOCK_9600_10586 *v3c;
                NDIS_OPEN_BLOCK_9600_10586 *v3;
            } u_v3;
            union {
                NDIS_COMMON_OPEN_BLOCK_14393_17134 *v4c;
                NDIS_OPEN_BLOCK_14393_17134 *v4;
            } u_v4;
            union {
                NDIS_COMMON_OPEN_BLOCK_17763_20150 *v5c;
                NDIS_OPEN_BLOCK_17763_20150 *v5;
            } u_v5;
        } Versions;
        PVOID Ref;
    } u1;
} OPEN_BLOCK_VERSIONS, *POPEN_BLOCK_VERSIONS;

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
} NDIS_OPEN_BLOCK_HANDLERS, *PNDIS_OPEN_BLOCK_HANDLERS;

typedef struct _NDIS_OPEN_BLOCK_COMPATIBLE{
    PVOID ProtocolNextOpen;

    UNICODE_STRING* BindDeviceName;
    UNICODE_STRING* RootDeviceName;

    NDIS_OPEN_BLOCK_HANDLERS Handlers;

} NDIS_OPEN_BLOCK_COMPATIBLE, *PNDIS_OPEN_BLOCK_COMPATIBLE;

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
} NDIS_PROTOCOL_BLOCK_HANDLERS, *PNDIS_PROTOCOL_BLOCK_HANDLERS;

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

} NDIS_PROTOCOL_BLOCK_COMPATIBLE, *PNDIS_PROTOCOL_BLOCK_COMPATIBLE;

static LPWSTR g_lpszOpenBlockHandlers[] = {
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

static LPWSTR g_lpszProtocolBlockHandlers[] = {
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
    _Inout_ NDIS_PROTOCOL_BLOCK_COMPATIBLE *ProtoBlock,
    _Out_opt_ PULONG ObjectVersion);

_Success_(return == TRUE)
BOOL ReadAndConvertOpenBlock(
    _In_ ULONG_PTR ObjectAddress,
    _Inout_ NDIS_OPEN_BLOCK_COMPATIBLE *OpenBlock,
    _Out_opt_ PULONG ObjectVersion);

PVOID HeapMemoryAlloc(
    _In_ SIZE_T Size);

BOOL HeapMemoryFree(
    _In_ PVOID Memory);

BOOL GetWin32FileName(
    _In_ LPWSTR FileName,
    _Inout_ LPWSTR Win32FileName,
    _In_ SIZE_T ccWin32FileName);

VOID CopyTreeListSubItemValue(
    _In_ HWND TreeList,
    _In_ UINT ValueIndex);

VOID CopyListViewSubItemValue(
    _In_ HWND ListView,
    _In_ UINT ValueIndex);

INT GetMaxCompareTwoFixedStrings(
    _In_ HWND ListView,
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort,
    _In_ BOOL Inverse);

INT GetMaxOfTwoU64FromHex(
    _In_ HWND ListView,
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lParamSort,
    _In_ BOOL Inverse);
