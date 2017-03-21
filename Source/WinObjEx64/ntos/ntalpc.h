/************************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017, translated from Microsoft sources/debugger
*
*  TITLE:       NTALPC.H
*
*  VERSION:     1.62
*
*  DATE:        21 Mar 2017
*
*  Common header file for the ntos ALPC/CSR related functions and definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
************************************************************************************/
#pragma once

#define CSR_API_PORT_NAME               L"ApiPort"

#define WINSS_OBJECT_DIRECTORY_NAME     L"\\Windows"

#define CSRSRV_SERVERDLL_INDEX          0
#define CSRSRV_FIRST_API_NUMBER         0

#define BASESRV_SERVERDLL_INDEX         1
#define BASESRV_FIRST_API_NUMBER        0

#define CONSRV_SERVERDLL_INDEX          2
#define CONSRV_FIRST_API_NUMBER         512

#define USERSRV_SERVERDLL_INDEX         3
#define USERSRV_FIRST_API_NUMBER        1024

#define CSR_CSRSS_SECTION_SIZE          64 * 1024

typedef enum _ALPC_PORT_INFORMATION_CLASS
{
    AlpcBasicInformation,
    AlpcPortInformation,
    AlpcAssociateCompletionPortInformation,
    AlpcConnectedSIDInformation,
    AlpcServerInformation,
    AlpcMessageZoneInformation,
    AlpcRegisterCompletionListInformation,
    AlpcUnregisterCompletionListInformation,
    AlpcAdjustCompletionListConcurrencyCountInformation,
    AlpcRegisterCallbackInformation,
    AlpcCompletionListRundownInformation
} ALPC_PORT_INFORMATION_CLASS;

typedef struct _ALPC_SERVER_INFORMATION
{
    union
    {
        struct
        {
            HANDLE ThreadHandle;
        } In;
        struct
        {
            BOOLEAN ThreadBlocked;
            HANDLE ConnectedProcessId;
            UNICODE_STRING ConnectionPortName;
        } Out;
    };
} ALPC_SERVER_INFORMATION, *PALPC_SERVER_INFORMATION;

typedef struct _ALPC_PORT_ATTRIBUTES
{
    ULONG Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    SIZE_T MaxMessageLength;
    SIZE_T MemoryBandwidth;
    SIZE_T MaxPoolUsage;
    SIZE_T MaxSectionSize;
    SIZE_T MaxViewSize;
    SIZE_T MaxTotalSectionSize;
    ULONG DupObjectTypes;
#ifdef X64
    ULONG Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;

typedef struct _ALPC_BASIC_INFORMATION
{
    ULONG Flags;
    ULONG SequenceNo;
    PVOID PortContext;
} ALPC_BASIC_INFORMATION, *PALPC_BASIC_INFORMATION;

NTSTATUS NTAPI NtAlpcQueryInformation(
    __in HANDLE                      PortHandle,
    __in ALPC_PORT_INFORMATION_CLASS PortInformationClass,
    __out_bcount(Length) PVOID       PortInformation,
    __in ULONG                       Length,
    __out_opt PULONG                 ReturnLength
);