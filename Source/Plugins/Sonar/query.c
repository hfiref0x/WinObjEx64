/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2025
*
*  TITLE:       QUERY.C
*
*  VERSION:     1.16
*
*  DATE:        14 Jun 2025
*
*  Query NDIS specific data.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*

Generic search pattern

NdisDeregisterProtocol

7601
48 8B 3D 46 B9 FA FF                                            mov     rdi, cs:ndisProtocolList
9200
48 8B 3D 9A 1F FB FF                                            mov     rdi, cs:ndisProtocolList
9600
48 8B 3D 7A EF F9 FF                                            mov     rdi, cs:ndisProtocolList
10240
48 8B 3D FA 1D F9 FF                                            mov     rdi, cs:ndisProtocolList
10586
48 8B 3D 1A 62 F9 FF                                            mov     rdi, cs:ndisProtocolList
14393
48 8B 3D 4A 44 F9 FF                                            mov     rdi, cs:ndisProtocolList
15063
48 8B 3D 32 F4 F8 FF                                            mov     rdi, cs:ndisProtocolList
16299
48 8B 3D 6A BC F8 FF                                            mov     rdi, cs:ndisProtocolList
17134
48 8B 3D 9A AF F8 FF                                            mov     rdi, cs:ndisProtocolList
17763
48 8B 3D C4 7F F8 FF                                            mov     rdi, cs:ndisProtocolList
18362/18363
48 8B 3D A2 CE FA FF                                            mov     rdi, cs:ndisProtocolList
19041/19042
48 8B 3D BA 92 FA FF                                            mov     rdi, cs:ndisProtocolList
21376
48 8B 3D XX XX XX XX                                            mov     rdi, cs:ndisProtocolList
25905
48 8B 3D 7C FB F9 FF                                            mov     rdi, cs:ndisProtocolList
27842
48 8B 3D 44 A6 FA FF                                            mov     rdi, cs:ndisProtocolList
*/

#define HDE_F_ERROR 0x00001000


/*
* AddressInImage
*
* Purpose:
*
* Test if given address in range of image.
*
*/
BOOL AddressInImage(
    _In_ PVOID Address,
    _In_ PVOID ImageBase,
    _In_ ULONG ImageSize
)
{
    return IN_REGION(Address,
        ImageBase,
        ImageSize);
}

/*
* QueryProtocolList
*
* Purpose:
*
* Return kernel address of ndis!ndisProtocolList global variable.
*
*/
ULONG_PTR QueryProtocolList(
    VOID
)
{
    UCHAR       Length;
    LONG        Rel = 0;
    ULONG       Index, DisasmFlags;
    ULONG_PTR   Address = 0, Result = 0;
    HMODULE     hModule = NULL;
    PBYTE       ptrCode;

    PRTL_PROCESS_MODULES            miSpace = NULL;
    PRTL_PROCESS_MODULE_INFORMATION NdisModule;
    WCHAR                           szBuffer[MAX_PATH * 2];

    do {
        if (g_ctx.ParamBlock.GetInstructionLength == NULL)
            break;

        //
        // Query NDIS.sys base
        //
        miSpace = ntsupGetSystemInfoEx(
            SystemModuleInformation,
            NULL,
            (PNTSUPMEMALLOC)HeapMemoryAlloc,
            (PNTSUPMEMFREE)HeapMemoryFree);

        if (miSpace == NULL)
            break;

        if (miSpace->NumberOfModules == 0)
            break;

        NdisModule = ntsupFindModuleEntryByName((PVOID)miSpace, "ndis.sys");
        if (NdisModule == NULL)
            break;

        //
        // Preload NDIS.sys
        //
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

        StringCchPrintf(
            szBuffer,
            _countof(szBuffer),
            TEXT("%s\\system32\\drivers\\ndis.sys"),
            USER_SHARED_DATA->NtSystemRoot);

        hModule = LoadLibraryEx(szBuffer, NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (hModule == NULL)
            break;

        //
        // Match pattern scan from NdisDeregisterProtocol.
        //
        ptrCode = (PBYTE)GetProcAddress(hModule, "NdisDeregisterProtocol");
        if (ptrCode == NULL)
            break;

        Index = 0;
        do {
            DisasmFlags = 0;
            Length = g_ctx.ParamBlock.GetInstructionLength((void*)(ptrCode + Index), &DisasmFlags);
            if (DisasmFlags & HDE_F_ERROR)
                break;

            if (Length == 7) {

                if ((ptrCode[Index] == 0x48) &&
                    (ptrCode[Index + 1] == 0x8B) &&
                    (ptrCode[Index + 2] == 0x3D))
                {
                    Rel = *(PLONG)(ptrCode + Index + 3);
                    break;
                }
            }
            Index += Length;

        } while (Index < 256);

        if (Rel == 0)
            break;

        Address = (ULONG_PTR)ptrCode + Index + Length + Rel;
        Address = (ULONG_PTR)NdisModule->ImageBase + Address - (ULONG_PTR)hModule;

        if (!AddressInImage((PVOID)Address, NdisModule->ImageBase, NdisModule->ImageSize))
            break;

        Result = Address;

    } while (FALSE);

    if (hModule) FreeLibrary(hModule);
    if (miSpace) HeapMemoryFree(miSpace);

    return Result;
}

/*
* DumpObjectWithSpecifiedSize
*
* Purpose:
*
* Return dumped object version aware.
*
* Use HeapMemoryFree to free returned buffer.
*
*/
PVOID DumpObjectWithSpecifiedSize(
    _In_ ULONG_PTR ObjectAddress,
    _In_ ULONG ObjectSize,
    _In_ ULONG ObjectVersion,
    _Out_ PULONG ReadSize,
    _Out_ PULONG ReadVersion
)
{
    PVOID ObjectBuffer = NULL;
    ULONG BufferSize = ALIGN_UP_BY(ObjectSize, PAGE_SIZE);

    if (ReadSize) *ReadSize = 0;
    if (ReadVersion) *ReadVersion = 0;

    ObjectBuffer = HeapMemoryAlloc(BufferSize);
    if (ObjectBuffer == NULL) {
        return NULL;
    }

    if (!g_ctx.ParamBlock.ReadSystemMemoryEx(
        ObjectAddress,
        ObjectBuffer,
        (ULONG)ObjectSize,
        NULL))
    {
        HeapMemoryFree(ObjectBuffer);
        return NULL;
    }

    if (ReadSize)
        *ReadSize = ObjectSize;
    if (ReadVersion)
        *ReadVersion = ObjectVersion;

    return ObjectBuffer;
}

/*
* DumpProtocolBlockVersionAware
*
* Purpose:
*
* Return dumped NDIS_PROTOCOL_BLOCK version aware.
*
* Use HeapMemoryFree to free returned buffer.
*
*/
PVOID DumpProtocolBlockVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version)
{
    ULONG ObjectSize = 0;
    ULONG ObjectVersion = 0;

    //assume failure
    if (Size) *Size = 0;
    if (Version) *Version = 0;

    switch (g_ctx.ParamBlock.Version.dwBuildNumber) {
    case NT_WIN7_RTM:
    case NT_WIN7_SP1:
        ObjectSize = sizeof(NDIS_PROTOCOL_BLOCK_7601);
        ObjectVersion = 1;
        break;

    case NT_WIN8_RTM:
        ObjectSize = sizeof(NDIS_PROTOCOL_BLOCK_9200);
        ObjectVersion = 2;
        break;

    case NT_WIN8_BLUE:
    case NT_WIN10_THRESHOLD1:
    case NT_WIN10_THRESHOLD2:
    case NT_WIN10_REDSTONE1:
    case NT_WIN10_REDSTONE2:
    case NT_WIN10_REDSTONE3:
    case NT_WIN10_REDSTONE4:
        ObjectSize = sizeof(NDIS_PROTOCOL_BLOCK_9600_17134);
        ObjectVersion = 3;
        break;
    case NT_WIN10_REDSTONE5:
        ObjectSize = sizeof(NDIS_PROTOCOL_BLOCK_17763);
        ObjectVersion = 4;
        break;
    case NT_WIN10_19H1:
    case NT_WIN10_19H2:
    case NT_WIN10_20H1:
    case NT_WIN10_20H2:
    case NT_WIN10_21H1:
    case NT_WIN10_21H2:
    case NT_WIN11_21H2:
    case NT_WIN11_22H2:
    case NT_WIN11_23H2:
    case NT_WIN11_24H2:
    default:
        ObjectSize = sizeof(NDIS_PROTOCOL_BLOCK_18362_25905);
        ObjectVersion = 5;
        break;

    }

    return DumpObjectWithSpecifiedSize(ObjectAddress,
        ObjectSize,
        ObjectVersion,
        Size,
        Version);
}

/*
* DumpOpenBlockVersionAware
*
* Purpose:
*
* Return dumped NDIS_OPEN_BLOCK version aware.
*
* Use HeapMemoryFree to free returned buffer.
*
*/
PVOID DumpOpenBlockVersionAware(
    _In_ ULONG_PTR ObjectAddress,
    _Out_ PULONG Size,
    _Out_ PULONG Version)
{
    ULONG ObjectSize = 0;
    ULONG ObjectVersion = 0;

    //assume failure
    if (Size) *Size = 0;
    if (Version) *Version = 0;

    switch (g_ctx.ParamBlock.Version.dwBuildNumber) {
    case NT_WIN7_RTM:
    case NT_WIN7_SP1:
        ObjectSize = sizeof(NDIS_OPEN_BLOCK_7601);
        ObjectVersion = NDIS_OPEN_BLOCK_VERSION_WIN7;
        break;
    case NT_WIN8_RTM:
        ObjectSize = sizeof(NDIS_OPEN_BLOCK_9200);
        ObjectVersion = NDIS_OPEN_BLOCK_VERSION_WIN8;
        break;
    case NT_WIN8_BLUE:
    case NT_WIN10_THRESHOLD1:
    case NT_WIN10_THRESHOLD2:
        ObjectSize = sizeof(NDIS_OPEN_BLOCK_9600_10586);
        ObjectVersion = NDIS_OPEN_BLOCK_VERSION_WIN81_WIN10TH1;
        break;
    case NT_WIN10_REDSTONE1:
    case NT_WIN10_REDSTONE2:
    case NT_WIN10_REDSTONE3:
    case NT_WIN10_REDSTONE4:
        ObjectSize = sizeof(NDIS_OPEN_BLOCK_14393_17134);
        ObjectVersion = NDIS_OPEN_BLOCK_VERSION_WIN10_RS1_4;
        break;
    case NT_WIN10_REDSTONE5:
    case NT_WIN10_19H1:
    case NT_WIN10_19H2:
    case NT_WIN10_20H1:
    case NT_WIN10_20H2:
    case NT_WIN10_21H1:
    case NT_WIN10_21H2:
    case NT_WIN11_21H2:
        ObjectSize = sizeof(NDIS_OPEN_BLOCK_17763_22000);
        ObjectVersion = NDIS_OPEN_BLOCK_VERSION_WIN10_RS5_WIN11;
        break;
    case NT_WIN11_22H2:
    case NT_WIN11_23H2:
    case NT_WIN11_24H2:
    default:
        ObjectSize = sizeof(NDIS_OPEN_BLOCK_22621_25905);
        ObjectVersion = NDIS_OPEN_BLOCK_VERSION_WIN11_22_25H2;
        break;
    }

    return DumpObjectWithSpecifiedSize(ObjectAddress,
        ObjectSize,
        ObjectVersion,
        Size,
        Version);
}

/*
* DumpUnicodeString
*
* Purpose:
*
* Read UNICODE_STRING buffer from kernel.
*
* Use HeapMemoryFree to free returned buffer.
*
*/
PVOID DumpUnicodeString(
    _In_ ULONG_PTR Address,
    _In_ WORD Length,
    _In_ WORD MaximumLength,
    _In_ BOOLEAN IsPtr)
{
    ULONG readBytes;
    PVOID DumpedString = NULL;
    SIZE_T Size;
    UNICODE_STRING tempString;

    if (Address <= g_ctx.ParamBlock.SystemRangeStart)
        return NULL;

    RtlSecureZeroMemory(&tempString, sizeof(tempString));

    if (IsPtr) { //given address is pointer to the string

        if (g_ctx.ParamBlock.ReadSystemMemoryEx(Address,
            &tempString,
            sizeof(UNICODE_STRING),
            &readBytes))
        {
            if (readBytes != sizeof(UNICODE_STRING)) {
                return NULL;
            }
        }

    }
    else {
        tempString.Buffer = (PWCHAR)Address;
        tempString.Length = Length;
        tempString.MaximumLength = MaximumLength;
    }

    if (tempString.Length == 0 && tempString.MaximumLength == 0)
        return NULL;

    Size = (SIZE_T)tempString.Length + MAX_PATH;
    DumpedString = (PVOID)HeapMemoryAlloc(Size);
    if (DumpedString) {
        if (!g_ctx.ParamBlock.ReadSystemMemoryEx((ULONG_PTR)tempString.Buffer,
            DumpedString,
            tempString.Length,
            &readBytes))
        {
            HeapMemoryFree(DumpedString);
            return NULL;
        }

        if (readBytes != tempString.Length) {
            HeapMemoryFree(DumpedString);
            return NULL;
        }
    }

    return DumpedString;
}

/*
* GetNextProtocolOffset
*
* Purpose:
*
* Return offset of NextProtocol structure field (structure version specific).
*
*/
ULONG GetNextProtocolOffset(
    _In_ ULONG WindowsVersion
)
{
    ULONG Offset = 0;

    switch (WindowsVersion) {

    case NT_WIN7_RTM:
    case NT_WIN7_SP1:
        Offset = FIELD_OFFSET(NDIS_PROTOCOL_BLOCK_7601, NextProtocol);
        break;
    case NT_WIN8_RTM:
        Offset = FIELD_OFFSET(NDIS_PROTOCOL_BLOCK_9200, NextProtocol);
        break;
    case NT_WIN8_BLUE:
    case NT_WIN10_THRESHOLD1:
    case NT_WIN10_THRESHOLD2:
    case NT_WIN10_REDSTONE1:
    case NT_WIN10_REDSTONE2:
    case NT_WIN10_REDSTONE3:
    case NT_WIN10_REDSTONE4:
        Offset = FIELD_OFFSET(NDIS_PROTOCOL_BLOCK_9600_17134, NextProtocol);
        break;
    case NT_WIN10_REDSTONE5:
        Offset = FIELD_OFFSET(NDIS_PROTOCOL_BLOCK_17763, NextProtocol);
        break;
    case NT_WIN10_19H1:
    case NT_WIN10_19H2:
    case NT_WIN10_20H1:
    case NT_WIN10_20H2:
    case NT_WIN10_21H1:
    case NT_WIN10_21H2:
    case NT_WIN11_21H2:
    case NT_WIN11_22H2:
    case NT_WIN11_23H2:
    case NT_WIN11_24H2:
    default:
        Offset = FIELD_OFFSET(NDIS_PROTOCOL_BLOCK_18362_25905, NextProtocol);
        break;

    }

    return Offset;
}

/*
* CreateCompatibleProtocolBlock
*
* Purpose:
*
* Build compatible protocol block for easy work with it.
*
*/
_Success_(return == TRUE)
BOOL CreateCompatibleProtocolBlock(
    _In_ ULONG ObjectVersion,
    _In_ PROTOCOL_BLOCK_VERSIONS * ProtocolRef,
    _Out_ NDIS_PROTOCOL_BLOCK_COMPATIBLE * ProtoBlock)
{
    switch (ObjectVersion) {

    case 1:
        RtlCopyMemory(&ProtoBlock->Name, &ProtocolRef->u1.Versions.v1->Name, sizeof(UNICODE_STRING));
        RtlCopyMemory(&ProtoBlock->ImageName, &ProtocolRef->u1.Versions.v1->ImageName, sizeof(UNICODE_STRING));
        ProtoBlock->OpenQueue = ProtocolRef->u1.Versions.v1->OpenQueue;
        ProtoBlock->NextProtocol = ProtocolRef->u1.Versions.v1->NextProtocol;
        ProtoBlock->AssociatedMiniDriver = ProtocolRef->u1.Versions.v1->AssociatedMiniDriver;

        ProtoBlock->MajorDriverVersion = ProtocolRef->u1.Versions.v1->MajorDriverVersion;
        ProtoBlock->MajorNdisVersion = ProtocolRef->u1.Versions.v1->MajorNdisVersion;
        ProtoBlock->MinorDriverVersion = ProtocolRef->u1.Versions.v1->MinorDriverVersion;
        ProtoBlock->MinorNdisVersion = ProtocolRef->u1.Versions.v1->MinorNdisVersion;

        ProtoBlock->Handlers.AllocateSharedMemoryHandler = ProtocolRef->u1.Versions.v1->AllocateSharedMemoryHandler;
        ProtoBlock->Handlers.BindAdapterHandler = ProtocolRef->u1.Versions.v1->BindAdapterHandler;
        ProtoBlock->Handlers.BindAdapterHandlerEx = ProtocolRef->u1.Versions.v1->BindAdapterHandlerEx;
        ProtoBlock->BindDeviceName = ProtocolRef->u1.Versions.v1->BindDeviceName;
        ProtoBlock->Handlers.CloseAdapterCompleteHandler = ProtocolRef->u1.Versions.v1->CloseAdapterCompleteHandler;
        ProtoBlock->Handlers.CloseAdapterCompleteHandlerEx = ProtocolRef->u1.Versions.v1->CloseAdapterCompleteHandlerEx;
        ProtoBlock->Handlers.CoAfRegisterNotifyHandler = ProtocolRef->u1.Versions.v1->CoAfRegisterNotifyHandler;
        ProtoBlock->Handlers.CoReceiveNetBufferListsHandler = ProtocolRef->u1.Versions.v1->CoReceiveNetBufferListsHandler;
        ProtoBlock->Handlers.CoReceivePacketHandler = ProtocolRef->u1.Versions.v1->CoReceivePacketHandler;
        ProtoBlock->Handlers.CoSendCompleteHandler = ProtocolRef->u1.Versions.v1->CoSendCompleteHandler;
        ProtoBlock->Handlers.CoSendNetBufferListsCompleteHandler = ProtocolRef->u1.Versions.v1->CoSendNetBufferListsCompleteHandler;
        ProtoBlock->Handlers.CoStatusHandler = ProtocolRef->u1.Versions.v1->u3.CoStatusHandler;
        ProtoBlock->Handlers.DirectOidRequestCompleteHandler = ProtocolRef->u1.Versions.v1->DirectOidRequestCompleteHandler;
        ProtoBlock->Handlers.FreeSharedMemoryHandler = ProtocolRef->u1.Versions.v1->FreeSharedMemoryHandler;
        ProtoBlock->Handlers.IndicateOffloadEventHandler = ProtocolRef->u1.Versions.v1->IndicateOffloadEventHandler;
        ProtoBlock->Handlers.InitiateOffloadCompleteHandler = ProtocolRef->u1.Versions.v1->InitiateOffloadCompleteHandler;
        ProtoBlock->Handlers.InvalidateOffloadCompleteHandler = ProtocolRef->u1.Versions.v1->InvalidateOffloadCompleteHandler;
        ProtoBlock->Handlers.OidRequestCompleteHandler = ProtocolRef->u1.Versions.v1->OidRequestCompleteHandler;
        ProtoBlock->Handlers.OpenAdapterCompleteHandler = ProtocolRef->u1.Versions.v1->OpenAdapterCompleteHandler;
        ProtoBlock->Handlers.OpenAdapterCompleteHandlerEx = ProtocolRef->u1.Versions.v1->OpenAdapterCompleteHandlerEx;
        ProtoBlock->Handlers.PnPEventHandler = ProtocolRef->u1.Versions.v1->u1.PnPEventHandler;
        ProtoBlock->Handlers.QueryOffloadCompleteHandler = ProtocolRef->u1.Versions.v1->QueryOffloadCompleteHandler;
        ProtoBlock->Handlers.ReceiveCompleteHandler = ProtocolRef->u1.Versions.v1->ReceiveCompleteHandler;
        ProtoBlock->Handlers.ReceiveHandler = ProtocolRef->u1.Versions.v1->u6.ReceiveHandler;
        ProtoBlock->Handlers.ReceiveNetBufferListsHandler = ProtocolRef->u1.Versions.v1->ReceiveNetBufferListsHandler;
        ProtoBlock->Handlers.ReceivePacketHandler = ProtocolRef->u1.Versions.v1->ReceivePacketHandler;
        ProtoBlock->Handlers.RequestCompleteHandler = ProtocolRef->u1.Versions.v1->RequestCompleteHandler;
        ProtoBlock->Handlers.ResetCompleteHandler = ProtocolRef->u1.Versions.v1->ResetCompleteHandler;
        ProtoBlock->RootDeviceName = ProtocolRef->u1.Versions.v1->RootDeviceName;
        ProtoBlock->Handlers.SendCompleteHandler = ProtocolRef->u1.Versions.v1->u4.SendCompleteHandler;
        ProtoBlock->Handlers.SendNetBufferListsCompleteHandler = ProtocolRef->u1.Versions.v1->SendNetBufferListsCompleteHandler;
        ProtoBlock->Handlers.StatusCompleteHandler = ProtocolRef->u1.Versions.v1->StatusCompleteHandler;
        ProtoBlock->Handlers.StatusHandler = ProtocolRef->u1.Versions.v1->u2.StatusHandler;
        ProtoBlock->Handlers.TcpOffloadDisconnectCompleteHandler = ProtocolRef->u1.Versions.v1->TcpOffloadDisconnectCompleteHandler;
        ProtoBlock->Handlers.TcpOffloadEventHandler = ProtocolRef->u1.Versions.v1->TcpOffloadEventHandler;
        ProtoBlock->Handlers.TcpOffloadForwardCompleteHandler = ProtocolRef->u1.Versions.v1->TcpOffloadForwardCompleteHandler;
        ProtoBlock->Handlers.TcpOffloadReceiveCompleteHandler = ProtocolRef->u1.Versions.v1->TcpOffloadReceiveCompleteHandler;
        ProtoBlock->Handlers.TcpOffloadReceiveIndicateHandler = ProtocolRef->u1.Versions.v1->TcpOffloadReceiveIndicateHandler;
        ProtoBlock->Handlers.TcpOffloadSendCompleteHandler = ProtocolRef->u1.Versions.v1->TcpOffloadSendCompleteHandler;
        ProtoBlock->Handlers.TerminateOffloadCompleteHandler = ProtocolRef->u1.Versions.v1->TerminateOffloadCompleteHandler;
        ProtoBlock->Handlers.TransferDataCompleteHandler = ProtocolRef->u1.Versions.v1->u5.TransferDataCompleteHandler;
        ProtoBlock->Handlers.UnbindAdapterHandler = ProtocolRef->u1.Versions.v1->UnbindAdapterHandler;
        ProtoBlock->Handlers.UnbindAdapterHandlerEx = ProtocolRef->u1.Versions.v1->UnbindAdapterHandlerEx;
        ProtoBlock->Handlers.UninstallHandler = ProtocolRef->u1.Versions.v1->UninstallHandler;
        ProtoBlock->Handlers.UnloadHandler = ProtocolRef->u1.Versions.v1->UnloadHandler;
        ProtoBlock->Handlers.UpdateOffloadCompleteHandler = ProtocolRef->u1.Versions.v1->UpdateOffloadCompleteHandler;
        break;

    case 2:
        RtlCopyMemory(&ProtoBlock->Name, &ProtocolRef->u1.Versions.v2->Name, sizeof(UNICODE_STRING));
        RtlCopyMemory(&ProtoBlock->ImageName, &ProtocolRef->u1.Versions.v2->ImageName, sizeof(UNICODE_STRING));
        ProtoBlock->OpenQueue = ProtocolRef->u1.Versions.v2->OpenQueue;
        ProtoBlock->NextProtocol = ProtocolRef->u1.Versions.v2->NextProtocol;
        ProtoBlock->AssociatedMiniDriver = ProtocolRef->u1.Versions.v2->AssociatedMiniDriver;

        ProtoBlock->MajorDriverVersion = ProtocolRef->u1.Versions.v2->MajorDriverVersion;
        ProtoBlock->MajorNdisVersion = ProtocolRef->u1.Versions.v2->MajorNdisVersion;
        ProtoBlock->MinorDriverVersion = ProtocolRef->u1.Versions.v2->MinorDriverVersion;
        ProtoBlock->MinorNdisVersion = ProtocolRef->u1.Versions.v2->MinorNdisVersion;

        ProtoBlock->Handlers.AllocateSharedMemoryHandler = ProtocolRef->u1.Versions.v2->AllocateSharedMemoryHandler;
        ProtoBlock->Handlers.BindAdapterHandler = ProtocolRef->u1.Versions.v2->BindAdapterHandler;
        ProtoBlock->Handlers.BindAdapterHandlerEx = ProtocolRef->u1.Versions.v2->BindAdapterHandlerEx;
        ProtoBlock->BindDeviceName = ProtocolRef->u1.Versions.v2->BindDeviceName;
        ProtoBlock->Handlers.CloseAdapterCompleteHandler = ProtocolRef->u1.Versions.v2->CloseAdapterCompleteHandler;
        ProtoBlock->Handlers.CloseAdapterCompleteHandlerEx = ProtocolRef->u1.Versions.v2->CloseAdapterCompleteHandlerEx;
        ProtoBlock->Handlers.CoAfRegisterNotifyHandler = ProtocolRef->u1.Versions.v2->CoAfRegisterNotifyHandler;
        ProtoBlock->Handlers.CoReceiveNetBufferListsHandler = ProtocolRef->u1.Versions.v2->CoReceiveNetBufferListsHandler;
        ProtoBlock->Handlers.CoReceivePacketHandler = ProtocolRef->u1.Versions.v2->CoReceivePacketHandler;
        ProtoBlock->Handlers.CoSendCompleteHandler = ProtocolRef->u1.Versions.v2->CoSendCompleteHandler;
        ProtoBlock->Handlers.CoSendNetBufferListsCompleteHandler = ProtocolRef->u1.Versions.v2->CoSendNetBufferListsCompleteHandler;
        ProtoBlock->Handlers.CoStatusHandler = ProtocolRef->u1.Versions.v2->u3.CoStatusHandler;
        ProtoBlock->Handlers.DirectOidRequestCompleteHandler = ProtocolRef->u1.Versions.v2->DirectOidRequestCompleteHandler;
        ProtoBlock->Handlers.FreeSharedMemoryHandler = ProtocolRef->u1.Versions.v2->FreeSharedMemoryHandler;
        ProtoBlock->Handlers.IndicateOffloadEventHandler = ProtocolRef->u1.Versions.v2->IndicateOffloadEventHandler;
        ProtoBlock->Handlers.InitiateOffloadCompleteHandler = ProtocolRef->u1.Versions.v2->InitiateOffloadCompleteHandler;
        ProtoBlock->Handlers.InvalidateOffloadCompleteHandler = ProtocolRef->u1.Versions.v2->InvalidateOffloadCompleteHandler;
        ProtoBlock->Handlers.OidRequestCompleteHandler = ProtocolRef->u1.Versions.v2->OidRequestCompleteHandler;
        ProtoBlock->Handlers.OpenAdapterCompleteHandler = ProtocolRef->u1.Versions.v2->OpenAdapterCompleteHandler;
        ProtoBlock->Handlers.OpenAdapterCompleteHandlerEx = ProtocolRef->u1.Versions.v2->OpenAdapterCompleteHandlerEx;
        ProtoBlock->Handlers.PnPEventHandler = ProtocolRef->u1.Versions.v2->u1.PnPEventHandler;
        ProtoBlock->Handlers.QueryOffloadCompleteHandler = ProtocolRef->u1.Versions.v2->QueryOffloadCompleteHandler;
        ProtoBlock->Handlers.ReceiveCompleteHandler = ProtocolRef->u1.Versions.v2->ReceiveCompleteHandler;
        ProtoBlock->Handlers.ReceiveHandler = ProtocolRef->u1.Versions.v2->u6.ReceiveHandler;
        ProtoBlock->Handlers.ReceiveNetBufferListsHandler = ProtocolRef->u1.Versions.v2->ReceiveNetBufferListsHandler;
        ProtoBlock->Handlers.ReceivePacketHandler = ProtocolRef->u1.Versions.v2->ReceivePacketHandler;
        ProtoBlock->Handlers.RequestCompleteHandler = ProtocolRef->u1.Versions.v2->RequestCompleteHandler;
        ProtoBlock->Handlers.ResetCompleteHandler = ProtocolRef->u1.Versions.v2->ResetCompleteHandler;
        ProtoBlock->RootDeviceName = ProtocolRef->u1.Versions.v2->RootDeviceName;
        ProtoBlock->Handlers.SendCompleteHandler = ProtocolRef->u1.Versions.v2->u4.SendCompleteHandler;
        ProtoBlock->Handlers.SendNetBufferListsCompleteHandler = ProtocolRef->u1.Versions.v2->SendNetBufferListsCompleteHandler;
        ProtoBlock->Handlers.StatusCompleteHandler = ProtocolRef->u1.Versions.v2->StatusCompleteHandler;
        ProtoBlock->Handlers.StatusHandler = ProtocolRef->u1.Versions.v2->u2.StatusHandler;
        ProtoBlock->Handlers.TcpOffloadDisconnectCompleteHandler = ProtocolRef->u1.Versions.v2->TcpOffloadDisconnectCompleteHandler;
        ProtoBlock->Handlers.TcpOffloadEventHandler = ProtocolRef->u1.Versions.v2->TcpOffloadEventHandler;
        ProtoBlock->Handlers.TcpOffloadForwardCompleteHandler = ProtocolRef->u1.Versions.v2->TcpOffloadForwardCompleteHandler;
        ProtoBlock->Handlers.TcpOffloadReceiveCompleteHandler = ProtocolRef->u1.Versions.v2->TcpOffloadReceiveCompleteHandler;
        ProtoBlock->Handlers.TcpOffloadReceiveIndicateHandler = ProtocolRef->u1.Versions.v2->TcpOffloadReceiveIndicateHandler;
        ProtoBlock->Handlers.TcpOffloadSendCompleteHandler = ProtocolRef->u1.Versions.v2->TcpOffloadSendCompleteHandler;
        ProtoBlock->Handlers.TerminateOffloadCompleteHandler = ProtocolRef->u1.Versions.v2->TerminateOffloadCompleteHandler;
        ProtoBlock->Handlers.TransferDataCompleteHandler = ProtocolRef->u1.Versions.v2->u5.TransferDataCompleteHandler;
        ProtoBlock->Handlers.UnbindAdapterHandler = ProtocolRef->u1.Versions.v2->UnbindAdapterHandler;
        ProtoBlock->Handlers.UnbindAdapterHandlerEx = ProtocolRef->u1.Versions.v2->UnbindAdapterHandlerEx;
        ProtoBlock->Handlers.UninstallHandler = ProtocolRef->u1.Versions.v2->UninstallHandler;
        ProtoBlock->Handlers.UnloadHandler = ProtocolRef->u1.Versions.v2->UnloadHandler;
        ProtoBlock->Handlers.UpdateOffloadCompleteHandler = ProtocolRef->u1.Versions.v2->UpdateOffloadCompleteHandler;
        break;

    case 3:
        RtlCopyMemory(&ProtoBlock->Name, &ProtocolRef->u1.Versions.v3->Name, sizeof(UNICODE_STRING));
        RtlCopyMemory(&ProtoBlock->ImageName, &ProtocolRef->u1.Versions.v3->ImageName, sizeof(UNICODE_STRING));
        ProtoBlock->OpenQueue = ProtocolRef->u1.Versions.v3->OpenQueue;
        ProtoBlock->NextProtocol = ProtocolRef->u1.Versions.v3->NextProtocol;
        ProtoBlock->AssociatedMiniDriver = ProtocolRef->u1.Versions.v3->AssociatedMiniDriver;

        ProtoBlock->MajorDriverVersion = ProtocolRef->u1.Versions.v3->MajorDriverVersion;
        ProtoBlock->MajorNdisVersion = ProtocolRef->u1.Versions.v3->MajorNdisVersion;
        ProtoBlock->MinorDriverVersion = ProtocolRef->u1.Versions.v3->MinorDriverVersion;
        ProtoBlock->MinorNdisVersion = ProtocolRef->u1.Versions.v3->MinorNdisVersion;

        ProtoBlock->Handlers.AllocateSharedMemoryHandler = ProtocolRef->u1.Versions.v3->AllocateSharedMemoryHandler;
        ProtoBlock->Handlers.BindAdapterHandler = ProtocolRef->u1.Versions.v3->BindAdapterHandler;
        ProtoBlock->Handlers.BindAdapterHandlerEx = ProtocolRef->u1.Versions.v3->BindAdapterHandlerEx;
        ProtoBlock->BindDeviceName = ProtocolRef->u1.Versions.v3->BindDeviceName;
        ProtoBlock->Handlers.CloseAdapterCompleteHandler = ProtocolRef->u1.Versions.v3->CloseAdapterCompleteHandler;
        ProtoBlock->Handlers.CloseAdapterCompleteHandlerEx = ProtocolRef->u1.Versions.v3->CloseAdapterCompleteHandlerEx;
        ProtoBlock->Handlers.CoAfRegisterNotifyHandler = ProtocolRef->u1.Versions.v3->CoAfRegisterNotifyHandler;
        ProtoBlock->Handlers.CoReceiveNetBufferListsHandler = ProtocolRef->u1.Versions.v3->CoReceiveNetBufferListsHandler;
        ProtoBlock->Handlers.CoReceivePacketHandler = ProtocolRef->u1.Versions.v3->CoReceivePacketHandler;
        ProtoBlock->Handlers.CoSendCompleteHandler = ProtocolRef->u1.Versions.v3->CoSendCompleteHandler;
        ProtoBlock->Handlers.CoSendNetBufferListsCompleteHandler = ProtocolRef->u1.Versions.v3->CoSendNetBufferListsCompleteHandler;
        ProtoBlock->Handlers.CoStatusHandler = ProtocolRef->u1.Versions.v3->u3.CoStatusHandler;
        ProtoBlock->Handlers.DirectOidRequestCompleteHandler = ProtocolRef->u1.Versions.v3->DirectOidRequestCompleteHandler;
        ProtoBlock->Handlers.FreeSharedMemoryHandler = ProtocolRef->u1.Versions.v3->FreeSharedMemoryHandler;
        ProtoBlock->Handlers.IndicateOffloadEventHandler = ProtocolRef->u1.Versions.v3->IndicateOffloadEventHandler;
        ProtoBlock->Handlers.InitiateOffloadCompleteHandler = ProtocolRef->u1.Versions.v3->InitiateOffloadCompleteHandler;
        ProtoBlock->Handlers.InvalidateOffloadCompleteHandler = ProtocolRef->u1.Versions.v3->InvalidateOffloadCompleteHandler;
        ProtoBlock->Handlers.OidRequestCompleteHandler = ProtocolRef->u1.Versions.v3->OidRequestCompleteHandler;
        ProtoBlock->Handlers.OpenAdapterCompleteHandler = ProtocolRef->u1.Versions.v3->OpenAdapterCompleteHandler;
        ProtoBlock->Handlers.OpenAdapterCompleteHandlerEx = ProtocolRef->u1.Versions.v3->OpenAdapterCompleteHandlerEx;
        ProtoBlock->Handlers.PnPEventHandler = ProtocolRef->u1.Versions.v3->u1.PnPEventHandler;
        ProtoBlock->Handlers.QueryOffloadCompleteHandler = ProtocolRef->u1.Versions.v3->QueryOffloadCompleteHandler;
        ProtoBlock->Handlers.ReceiveCompleteHandler = ProtocolRef->u1.Versions.v3->ReceiveCompleteHandler;
        ProtoBlock->Handlers.ReceiveHandler = ProtocolRef->u1.Versions.v3->u6.ReceiveHandler;
        ProtoBlock->Handlers.ReceiveNetBufferListsHandler = ProtocolRef->u1.Versions.v3->ReceiveNetBufferListsHandler;
        ProtoBlock->Handlers.ReceivePacketHandler = ProtocolRef->u1.Versions.v3->ReceivePacketHandler;
        ProtoBlock->Handlers.RequestCompleteHandler = ProtocolRef->u1.Versions.v3->RequestCompleteHandler;
        ProtoBlock->Handlers.ResetCompleteHandler = ProtocolRef->u1.Versions.v3->ResetCompleteHandler;
        ProtoBlock->RootDeviceName = ProtocolRef->u1.Versions.v3->RootDeviceName;
        ProtoBlock->Handlers.SendCompleteHandler = ProtocolRef->u1.Versions.v3->u4.SendCompleteHandler;
        ProtoBlock->Handlers.SendNetBufferListsCompleteHandler = ProtocolRef->u1.Versions.v3->SendNetBufferListsCompleteHandler;
        ProtoBlock->Handlers.StatusCompleteHandler = ProtocolRef->u1.Versions.v3->StatusCompleteHandler;
        ProtoBlock->Handlers.StatusHandler = ProtocolRef->u1.Versions.v3->u2.StatusHandler;
        ProtoBlock->Handlers.TcpOffloadDisconnectCompleteHandler = ProtocolRef->u1.Versions.v3->TcpOffloadDisconnectCompleteHandler;
        ProtoBlock->Handlers.TcpOffloadEventHandler = ProtocolRef->u1.Versions.v3->TcpOffloadEventHandler;
        ProtoBlock->Handlers.TcpOffloadForwardCompleteHandler = ProtocolRef->u1.Versions.v3->TcpOffloadForwardCompleteHandler;
        ProtoBlock->Handlers.TcpOffloadReceiveCompleteHandler = ProtocolRef->u1.Versions.v3->TcpOffloadReceiveCompleteHandler;
        ProtoBlock->Handlers.TcpOffloadReceiveIndicateHandler = ProtocolRef->u1.Versions.v3->TcpOffloadReceiveIndicateHandler;
        ProtoBlock->Handlers.TcpOffloadSendCompleteHandler = ProtocolRef->u1.Versions.v3->TcpOffloadSendCompleteHandler;
        ProtoBlock->Handlers.TerminateOffloadCompleteHandler = ProtocolRef->u1.Versions.v3->TerminateOffloadCompleteHandler;
        ProtoBlock->Handlers.TransferDataCompleteHandler = ProtocolRef->u1.Versions.v3->u5.TransferDataCompleteHandler;
        ProtoBlock->Handlers.UnbindAdapterHandler = ProtocolRef->u1.Versions.v3->UnbindAdapterHandler;
        ProtoBlock->Handlers.UnbindAdapterHandlerEx = ProtocolRef->u1.Versions.v3->UnbindAdapterHandlerEx;
        ProtoBlock->Handlers.UninstallHandler = ProtocolRef->u1.Versions.v3->UninstallHandler;
        ProtoBlock->Handlers.UnloadHandler = ProtocolRef->u1.Versions.v3->UnloadHandler;
        ProtoBlock->Handlers.UpdateOffloadCompleteHandler = ProtocolRef->u1.Versions.v3->UpdateOffloadCompleteHandler;
        break;

    case 4:
        RtlCopyMemory(&ProtoBlock->Name, &ProtocolRef->u1.Versions.v4->Name, sizeof(UNICODE_STRING));
        RtlCopyMemory(&ProtoBlock->ImageName, &ProtocolRef->u1.Versions.v4->ImageName, sizeof(UNICODE_STRING));
        ProtoBlock->OpenQueue = ProtocolRef->u1.Versions.v4->OpenQueue;
        ProtoBlock->NextProtocol = ProtocolRef->u1.Versions.v4->NextProtocol;
        ProtoBlock->AssociatedMiniDriver = ProtocolRef->u1.Versions.v4->AssociatedMiniDriver;

        ProtoBlock->MajorDriverVersion = ProtocolRef->u1.Versions.v4->MajorDriverVersion;
        ProtoBlock->MajorNdisVersion = ProtocolRef->u1.Versions.v4->MajorNdisVersion;
        ProtoBlock->MinorDriverVersion = ProtocolRef->u1.Versions.v4->MinorDriverVersion;
        ProtoBlock->MinorNdisVersion = ProtocolRef->u1.Versions.v4->MinorNdisVersion;

        ProtoBlock->Handlers.AllocateSharedMemoryHandler = ProtocolRef->u1.Versions.v4->AllocateSharedMemoryHandler;
        ProtoBlock->Handlers.BindAdapterHandler = ProtocolRef->u1.Versions.v4->BindAdapterHandler;
        ProtoBlock->Handlers.BindAdapterHandlerEx = ProtocolRef->u1.Versions.v4->BindAdapterHandlerEx;
        ProtoBlock->BindDeviceName = ProtocolRef->u1.Versions.v4->BindDeviceName;
        ProtoBlock->Handlers.CloseAdapterCompleteHandler = ProtocolRef->u1.Versions.v4->CloseAdapterCompleteHandler;
        ProtoBlock->Handlers.CloseAdapterCompleteHandlerEx = ProtocolRef->u1.Versions.v4->CloseAdapterCompleteHandlerEx;
        ProtoBlock->Handlers.CoAfRegisterNotifyHandler = ProtocolRef->u1.Versions.v4->CoAfRegisterNotifyHandler;
        ProtoBlock->Handlers.CoReceiveNetBufferListsHandler = ProtocolRef->u1.Versions.v4->CoReceiveNetBufferListsHandler;
        ProtoBlock->Handlers.CoReceivePacketHandler = ProtocolRef->u1.Versions.v4->CoReceivePacketHandler;
        ProtoBlock->Handlers.CoSendCompleteHandler = ProtocolRef->u1.Versions.v4->CoSendCompleteHandler;
        ProtoBlock->Handlers.CoSendNetBufferListsCompleteHandler = ProtocolRef->u1.Versions.v4->CoSendNetBufferListsCompleteHandler;
        ProtoBlock->Handlers.CoStatusHandler = ProtocolRef->u1.Versions.v4->u3.CoStatusHandler;
        ProtoBlock->Handlers.DirectOidRequestCompleteHandler = ProtocolRef->u1.Versions.v4->DirectOidRequestCompleteHandler;
        ProtoBlock->Handlers.FreeSharedMemoryHandler = ProtocolRef->u1.Versions.v4->FreeSharedMemoryHandler;
        ProtoBlock->Handlers.OidRequestCompleteHandler = ProtocolRef->u1.Versions.v4->OidRequestCompleteHandler;
        ProtoBlock->Handlers.OpenAdapterCompleteHandler = ProtocolRef->u1.Versions.v4->OpenAdapterCompleteHandler;
        ProtoBlock->Handlers.OpenAdapterCompleteHandlerEx = ProtocolRef->u1.Versions.v4->OpenAdapterCompleteHandlerEx;
        ProtoBlock->Handlers.PnPEventHandler = ProtocolRef->u1.Versions.v4->u1.PnPEventHandler;
        ProtoBlock->Handlers.ReceiveCompleteHandler = ProtocolRef->u1.Versions.v4->ReceiveCompleteHandler;
        ProtoBlock->Handlers.ReceiveHandler = ProtocolRef->u1.Versions.v4->u6.ReceiveHandler;
        ProtoBlock->Handlers.ReceiveNetBufferListsHandler = ProtocolRef->u1.Versions.v4->ReceiveNetBufferListsHandler;
        ProtoBlock->Handlers.ReceivePacketHandler = ProtocolRef->u1.Versions.v4->ReceivePacketHandler;
        ProtoBlock->Handlers.RequestCompleteHandler = ProtocolRef->u1.Versions.v4->RequestCompleteHandler;
        ProtoBlock->Handlers.ResetCompleteHandler = ProtocolRef->u1.Versions.v4->ResetCompleteHandler;
        ProtoBlock->RootDeviceName = ProtocolRef->u1.Versions.v4->RootDeviceName;
        ProtoBlock->Handlers.SendCompleteHandler = ProtocolRef->u1.Versions.v4->u4.SendCompleteHandler;
        ProtoBlock->Handlers.SendNetBufferListsCompleteHandler = ProtocolRef->u1.Versions.v4->SendNetBufferListsCompleteHandler;
        ProtoBlock->Handlers.StatusCompleteHandler = ProtocolRef->u1.Versions.v4->StatusCompleteHandler;
        ProtoBlock->Handlers.StatusHandler = ProtocolRef->u1.Versions.v4->u2.StatusHandler;
        ProtoBlock->Handlers.TransferDataCompleteHandler = ProtocolRef->u1.Versions.v4->u5.TransferDataCompleteHandler;
        ProtoBlock->Handlers.UnbindAdapterHandler = ProtocolRef->u1.Versions.v4->UnbindAdapterHandler;
        ProtoBlock->Handlers.UnbindAdapterHandlerEx = ProtocolRef->u1.Versions.v4->UnbindAdapterHandlerEx;
        ProtoBlock->Handlers.UninstallHandler = ProtocolRef->u1.Versions.v4->UninstallHandler;
        ProtoBlock->Handlers.UnloadHandler = ProtocolRef->u1.Versions.v4->UnloadHandler;
        break;

    case 5:
        RtlCopyMemory(&ProtoBlock->Name, &ProtocolRef->u1.Versions.v5->Name, sizeof(UNICODE_STRING));
        RtlCopyMemory(&ProtoBlock->ImageName, &ProtocolRef->u1.Versions.v5->ImageName, sizeof(UNICODE_STRING));
        ProtoBlock->OpenQueue = ProtocolRef->u1.Versions.v5->OpenQueue;
        ProtoBlock->NextProtocol = ProtocolRef->u1.Versions.v5->NextProtocol;
        ProtoBlock->AssociatedMiniDriver = ProtocolRef->u1.Versions.v5->AssociatedMiniDriver;

        ProtoBlock->MajorDriverVersion = ProtocolRef->u1.Versions.v5->MajorDriverVersion;
        ProtoBlock->MajorNdisVersion = ProtocolRef->u1.Versions.v5->MajorNdisVersion;
        ProtoBlock->MinorDriverVersion = ProtocolRef->u1.Versions.v5->MinorDriverVersion;
        ProtoBlock->MinorNdisVersion = ProtocolRef->u1.Versions.v5->MinorNdisVersion;

        ProtoBlock->Handlers.AllocateSharedMemoryHandler = ProtocolRef->u1.Versions.v5->AllocateSharedMemoryHandler;
        ProtoBlock->Handlers.BindAdapterHandler = ProtocolRef->u1.Versions.v5->BindAdapterHandler;
        ProtoBlock->Handlers.BindAdapterHandlerEx = ProtocolRef->u1.Versions.v5->BindAdapterHandlerEx;
        ProtoBlock->BindDeviceName = ProtocolRef->u1.Versions.v5->BindDeviceName;
        ProtoBlock->Handlers.CloseAdapterCompleteHandler = ProtocolRef->u1.Versions.v5->CloseAdapterCompleteHandler;
        ProtoBlock->Handlers.CloseAdapterCompleteHandlerEx = ProtocolRef->u1.Versions.v5->CloseAdapterCompleteHandlerEx;
        ProtoBlock->Handlers.CoAfRegisterNotifyHandler = ProtocolRef->u1.Versions.v5->CoAfRegisterNotifyHandler;
        ProtoBlock->Handlers.CoReceiveNetBufferListsHandler = ProtocolRef->u1.Versions.v5->CoReceiveNetBufferListsHandler;
        ProtoBlock->Handlers.CoReceivePacketHandler = ProtocolRef->u1.Versions.v5->CoReceivePacketHandler;
        ProtoBlock->Handlers.CoSendCompleteHandler = ProtocolRef->u1.Versions.v5->CoSendCompleteHandler;
        ProtoBlock->Handlers.CoSendNetBufferListsCompleteHandler = ProtocolRef->u1.Versions.v5->CoSendNetBufferListsCompleteHandler;
        ProtoBlock->Handlers.CoStatusHandler = ProtocolRef->u1.Versions.v5->u3.CoStatusHandler;
        ProtoBlock->Handlers.DirectOidRequestCompleteHandler = ProtocolRef->u1.Versions.v5->DirectOidRequestCompleteHandler;
        ProtoBlock->Handlers.FreeSharedMemoryHandler = ProtocolRef->u1.Versions.v5->FreeSharedMemoryHandler;
        ProtoBlock->Handlers.OidRequestCompleteHandler = ProtocolRef->u1.Versions.v5->OidRequestCompleteHandler;
        ProtoBlock->Handlers.OpenAdapterCompleteHandler = ProtocolRef->u1.Versions.v5->OpenAdapterCompleteHandler;
        ProtoBlock->Handlers.OpenAdapterCompleteHandlerEx = ProtocolRef->u1.Versions.v5->OpenAdapterCompleteHandlerEx;
        ProtoBlock->Handlers.PnPEventHandler = ProtocolRef->u1.Versions.v5->u1.PnPEventHandler;
        ProtoBlock->Handlers.ReceiveCompleteHandler = ProtocolRef->u1.Versions.v5->ReceiveCompleteHandler;
        ProtoBlock->Handlers.ReceiveHandler = ProtocolRef->u1.Versions.v5->u6.ReceiveHandler;
        ProtoBlock->Handlers.ReceiveNetBufferListsHandler = ProtocolRef->u1.Versions.v5->ReceiveNetBufferListsHandler;
        ProtoBlock->Handlers.ReceivePacketHandler = ProtocolRef->u1.Versions.v5->ReceivePacketHandler;
        ProtoBlock->Handlers.RequestCompleteHandler = ProtocolRef->u1.Versions.v5->RequestCompleteHandler;
        ProtoBlock->Handlers.ResetCompleteHandler = ProtocolRef->u1.Versions.v5->ResetCompleteHandler;
        ProtoBlock->RootDeviceName = ProtocolRef->u1.Versions.v5->RootDeviceName;
        ProtoBlock->Handlers.SendCompleteHandler = ProtocolRef->u1.Versions.v5->u4.SendCompleteHandler;
        ProtoBlock->Handlers.SendNetBufferListsCompleteHandler = ProtocolRef->u1.Versions.v5->SendNetBufferListsCompleteHandler;
        ProtoBlock->Handlers.StatusCompleteHandler = ProtocolRef->u1.Versions.v5->StatusCompleteHandler;
        ProtoBlock->Handlers.StatusHandler = ProtocolRef->u1.Versions.v5->u2.StatusHandler;
        ProtoBlock->Handlers.TransferDataCompleteHandler = ProtocolRef->u1.Versions.v5->u5.TransferDataCompleteHandler;
        ProtoBlock->Handlers.UnbindAdapterHandler = ProtocolRef->u1.Versions.v5->UnbindAdapterHandler;
        ProtoBlock->Handlers.UnbindAdapterHandlerEx = ProtocolRef->u1.Versions.v5->UnbindAdapterHandlerEx;
        ProtoBlock->Handlers.UninstallHandler = ProtocolRef->u1.Versions.v5->UninstallHandler;
        ProtoBlock->Handlers.UnloadHandler = ProtocolRef->u1.Versions.v5->UnloadHandler;
        break;

    default:
        return FALSE;
    }
    return TRUE;
}

/*
* CreateCompatibleOpenBlock
*
* Purpose:
*
* Build compatible open block for easy work with it.
*
*/
_Success_(return == TRUE)
BOOL CreateCompatibleOpenBlock(
    _In_ ULONG ObjectVersion,
    _In_ OPEN_BLOCK_VERSIONS * BlockRef,
    _Out_ NDIS_OPEN_BLOCK_COMPATIBLE * OpenBlock)
{
    switch (ObjectVersion) {

    case NDIS_OPEN_BLOCK_VERSION_WIN7: //7600..7601
        OpenBlock->ProtocolNextOpen = BlockRef->u1.Versions.v1->ProtocolNextOpen;
        OpenBlock->BindDeviceName = BlockRef->u1.Versions.v1->BindDeviceName;
        OpenBlock->RootDeviceName = BlockRef->u1.Versions.v1->RootDeviceName;

        OpenBlock->Handlers.AllocateSharedMemoryHandler = BlockRef->u1.Versions.v1->AllocateSharedMemoryHandler;
        OpenBlock->Handlers.CancelSendPacketsHandler = BlockRef->u1.Versions.v1->CancelSendPacketsHandler;
        OpenBlock->Handlers.CmActivateVcCompleteHandler = BlockRef->u1.Versions.v1->CmActivateVcCompleteHandler;
        OpenBlock->Handlers.CmDeactivateVcCompleteHandler = BlockRef->u1.Versions.v1->CmDeactivateVcCompleteHandler;
        OpenBlock->Handlers.CoCreateVcHandler = BlockRef->u1.Versions.v1->CoCreateVcHandler;
        OpenBlock->Handlers.CoDeleteVcHandler = BlockRef->u1.Versions.v1->CoDeleteVcHandler;
        OpenBlock->Handlers.CoOidRequestCompleteHandler = BlockRef->u1.Versions.v1->CoOidRequestCompleteHandler;
        OpenBlock->Handlers.CoOidRequestHandler = BlockRef->u1.Versions.v1->CoOidRequestHandler;
        OpenBlock->Handlers.CoRequestCompleteHandler = BlockRef->u1.Versions.v1->CoRequestCompleteHandler;
        OpenBlock->Handlers.CoRequestHandler = BlockRef->u1.Versions.v1->CoRequestHandler;
        OpenBlock->Handlers.DirectOidRequestCompleteHandler = BlockRef->u1.Versions.v1->DirectOidRequestCompleteHandler;
        OpenBlock->Handlers.DirectOidRequestHandler = BlockRef->u1.Versions.v1->DirectOidRequestHandler;
        OpenBlock->Handlers.FreeSharedMemoryHandler = BlockRef->u1.Versions.v1->FreeSharedMemoryHandler;
        OpenBlock->Handlers.IndicateOffloadEventHandler = BlockRef->u1.Versions.v1->IndicateOffloadEventHandler;
        OpenBlock->Handlers.InitiateOffloadCompleteHandler = BlockRef->u1.Versions.v1->InitiateOffloadCompleteHandler;
        OpenBlock->Handlers.InvalidateOffloadCompleteHandler = BlockRef->u1.Versions.v1->InvalidateOffloadCompleteHandler;
        OpenBlock->Handlers.MiniportCoCreateVcHandler = BlockRef->u1.Versions.v1->MiniportCoCreateVcHandler;
        OpenBlock->Handlers.MiniportCoOidRequestHandler = BlockRef->u1.Versions.v1->MiniportCoOidRequestHandler;
        OpenBlock->Handlers.MiniportCoRequestHandler = BlockRef->u1.Versions.v1->MiniportCoRequestHandler;
        OpenBlock->Handlers.Ndis5WanSendHandler = BlockRef->u1.Versions.v1->Ndis5WanSendHandler;
        OpenBlock->Handlers.NextReturnNetBufferListsHandler = BlockRef->u1.Versions.v1->NextReturnNetBufferListsHandler;
        OpenBlock->Handlers.NextSendHandler = BlockRef->u1.Versions.v1->NextSendHandler;
        OpenBlock->Handlers.OidRequestCompleteHandler = BlockRef->u1.Versions.v1->OidRequestCompleteHandler;
        OpenBlock->Handlers.OidRequestHandler = BlockRef->u1.Versions.v1->OidRequestHandler;
        OpenBlock->Handlers.ProtSendCompleteHandler = BlockRef->u1.Versions.v1->ProtSendCompleteHandler;
        OpenBlock->Handlers.ProtSendNetBufferListsComplete = BlockRef->u1.Versions.v1->ProtSendNetBufferListsComplete;
        OpenBlock->Handlers.QueryOffloadCompleteHandler = BlockRef->u1.Versions.v1->QueryOffloadCompleteHandler;
        OpenBlock->Handlers.ReceiveCompleteHandler = BlockRef->u1.Versions.v1->ReceiveCompleteHandler;
        OpenBlock->Handlers.ReceiveHandler = BlockRef->u1.Versions.v1->ReceiveHandler;
        OpenBlock->Handlers.ReceiveNetBufferLists = BlockRef->u1.Versions.v1->ReceiveNetBufferLists;
        OpenBlock->Handlers.ReceivePacketHandler = BlockRef->u1.Versions.v1->ReceivePacketHandler;
        OpenBlock->Handlers.RequestCompleteHandler = BlockRef->u1.Versions.v1->RequestCompleteHandler;
        OpenBlock->Handlers.RequestHandler = BlockRef->u1.Versions.v1->RequestHandler;
        OpenBlock->Handlers.ResetCompleteHandler = BlockRef->u1.Versions.v1->ResetCompleteHandler;
        OpenBlock->Handlers.ResetHandler = BlockRef->u1.Versions.v1->ResetHandler;
        OpenBlock->Handlers.SavedCancelSendPacketsHandler = BlockRef->u1.Versions.v1->SavedCancelSendPacketsHandler;
        OpenBlock->Handlers.SavedSendHandler = BlockRef->u1.Versions.v1->SavedSendHandler;
        OpenBlock->Handlers.SavedSendNBLHandler = BlockRef->u1.Versions.v1->SavedSendNBLHandler;
        OpenBlock->Handlers.SavedSendPacketsHandler = BlockRef->u1.Versions.v1->SavedSendPacketsHandler;
        OpenBlock->Handlers.SendCompleteHandler = BlockRef->u1.Versions.v1->SendCompleteHandler;
        OpenBlock->Handlers.SendHandler = BlockRef->u1.Versions.v1->SendHandler;
        OpenBlock->Handlers.SendPacketsHandler = BlockRef->u1.Versions.v1->SendPacketsHandler;
        OpenBlock->Handlers.StatusCompleteHandler = BlockRef->u1.Versions.v1->StatusCompleteHandler;
        OpenBlock->Handlers.StatusHandler = BlockRef->u1.Versions.v1->StatusHandler;
        OpenBlock->Handlers.TcpOffloadDisconnectCompleteHandler = BlockRef->u1.Versions.v1->TcpOffloadDisconnectCompleteHandler;
        OpenBlock->Handlers.TcpOffloadEventHandler = BlockRef->u1.Versions.v1->TcpOffloadEventHandler;
        OpenBlock->Handlers.TcpOffloadForwardCompleteHandler = BlockRef->u1.Versions.v1->TcpOffloadForwardCompleteHandler;
        OpenBlock->Handlers.TcpOffloadReceiveCompleteHandler = BlockRef->u1.Versions.v1->TcpOffloadReceiveCompleteHandler;
        OpenBlock->Handlers.TcpOffloadReceiveIndicateHandler = BlockRef->u1.Versions.v1->TcpOffloadReceiveIndicateHandler;
        OpenBlock->Handlers.TcpOffloadSendCompleteHandler = BlockRef->u1.Versions.v1->TcpOffloadSendCompleteHandler;
        OpenBlock->Handlers.TerminateOffloadCompleteHandler = BlockRef->u1.Versions.v1->TerminateOffloadCompleteHandler;
        OpenBlock->Handlers.TransferDataCompleteHandler = BlockRef->u1.Versions.v1->TransferDataCompleteHandler;
        OpenBlock->Handlers.TransferDataHandler = BlockRef->u1.Versions.v1->TransferDataHandler;
        OpenBlock->Handlers.UpdateOffloadCompleteHandler = BlockRef->u1.Versions.v1->UpdateOffloadCompleteHandler;
        OpenBlock->Handlers.WanReceiveHandler = BlockRef->u1.Versions.v1->WanReceiveHandler;
        OpenBlock->Handlers.WSendHandler = BlockRef->u1.Versions.v1->WSendHandler;
        OpenBlock->Handlers.WSendPacketsHandler = BlockRef->u1.Versions.v1->WSendPacketsHandler;
        OpenBlock->Handlers.WTransferDataHandler = BlockRef->u1.Versions.v1->WTransferDataHandler;
        break;

    case NDIS_OPEN_BLOCK_VERSION_WIN8: //9200
        OpenBlock->ProtocolNextOpen = BlockRef->u1.Versions.v2->ProtocolNextOpen;
        OpenBlock->BindDeviceName = BlockRef->u1.Versions.v2->BindDeviceName;
        OpenBlock->RootDeviceName = BlockRef->u1.Versions.v2->RootDeviceName;

        OpenBlock->Handlers.AllocateSharedMemoryHandler = BlockRef->u1.Versions.v2->AllocateSharedMemoryHandler;
        OpenBlock->Handlers.CancelSendPacketsHandler = BlockRef->u1.Versions.v2->CancelSendPacketsHandler;
        OpenBlock->Handlers.CmActivateVcCompleteHandler = BlockRef->u1.Versions.v2->CmActivateVcCompleteHandler;
        OpenBlock->Handlers.CmDeactivateVcCompleteHandler = BlockRef->u1.Versions.v2->CmDeactivateVcCompleteHandler;
        OpenBlock->Handlers.CoCreateVcHandler = BlockRef->u1.Versions.v2->CoCreateVcHandler;
        OpenBlock->Handlers.CoDeleteVcHandler = BlockRef->u1.Versions.v2->CoDeleteVcHandler;
        OpenBlock->Handlers.CoOidRequestCompleteHandler = BlockRef->u1.Versions.v2->CoOidRequestCompleteHandler;
        OpenBlock->Handlers.CoOidRequestHandler = BlockRef->u1.Versions.v2->CoOidRequestHandler;
        OpenBlock->Handlers.CoRequestCompleteHandler = BlockRef->u1.Versions.v2->CoRequestCompleteHandler;
        OpenBlock->Handlers.CoRequestHandler = BlockRef->u1.Versions.v2->CoRequestHandler;
        OpenBlock->Handlers.DirectOidRequestHandler = BlockRef->u1.Versions.v2->DirectOidRequestHandler;
        OpenBlock->Handlers.FreeSharedMemoryHandler = BlockRef->u1.Versions.v2->FreeSharedMemoryHandler;
        OpenBlock->Handlers.IndicateOffloadEventHandler = BlockRef->u1.Versions.v2->IndicateOffloadEventHandler;
        OpenBlock->Handlers.InitiateOffloadCompleteHandler = BlockRef->u1.Versions.v2->InitiateOffloadCompleteHandler;
        OpenBlock->Handlers.InvalidateOffloadCompleteHandler = BlockRef->u1.Versions.v2->InvalidateOffloadCompleteHandler;
        OpenBlock->Handlers.MiniportCoCreateVcHandler = BlockRef->u1.Versions.v2->MiniportCoCreateVcHandler;
        OpenBlock->Handlers.MiniportCoOidRequestHandler = BlockRef->u1.Versions.v2->MiniportCoOidRequestHandler;
        OpenBlock->Handlers.MiniportCoRequestHandler = BlockRef->u1.Versions.v2->MiniportCoRequestHandler;
        OpenBlock->Handlers.Ndis5WanSendHandler = BlockRef->u1.Versions.v2->Ndis5WanSendHandler;
        OpenBlock->Handlers.NextReturnNetBufferListsHandler = BlockRef->u1.Versions.v2->NextReturnNetBufferListsHandler;
        OpenBlock->Handlers.NextSendHandler = BlockRef->u1.Versions.v2->NextSendHandler;
        OpenBlock->Handlers.OidRequestCompleteHandler = BlockRef->u1.Versions.v2->OidRequestCompleteHandler;
        OpenBlock->Handlers.OidRequestHandler = BlockRef->u1.Versions.v2->OidRequestHandler;
        OpenBlock->Handlers.ProtSendCompleteHandler = BlockRef->u1.Versions.v2->ProtSendCompleteHandler;
        OpenBlock->Handlers.ProtSendNetBufferListsComplete = BlockRef->u1.Versions.v2->ProtSendNetBufferListsComplete;
        OpenBlock->Handlers.QueryOffloadCompleteHandler = BlockRef->u1.Versions.v2->QueryOffloadCompleteHandler;
        OpenBlock->Handlers.ReceiveCompleteHandler = BlockRef->u1.Versions.v2->ReceiveCompleteHandler;
        OpenBlock->Handlers.ReceiveHandler = BlockRef->u1.Versions.v2->ReceiveHandler;
        OpenBlock->Handlers.ReceiveNetBufferLists = BlockRef->u1.Versions.v2->ReceiveNetBufferLists;
        OpenBlock->Handlers.ReceivePacketHandler = BlockRef->u1.Versions.v2->ReceivePacketHandler;
        OpenBlock->Handlers.RequestCompleteHandler = BlockRef->u1.Versions.v2->RequestCompleteHandler;
        OpenBlock->Handlers.RequestHandler = BlockRef->u1.Versions.v2->RequestHandler;
        OpenBlock->Handlers.ResetCompleteHandler = BlockRef->u1.Versions.v2->ResetCompleteHandler;
        OpenBlock->Handlers.ResetHandler = BlockRef->u1.Versions.v2->ResetHandler;
        OpenBlock->Handlers.SavedCancelSendPacketsHandler = BlockRef->u1.Versions.v2->SavedCancelSendPacketsHandler;
        OpenBlock->Handlers.SavedSendHandler = BlockRef->u1.Versions.v2->SavedSendHandler;
        OpenBlock->Handlers.SavedSendPacketsHandler = BlockRef->u1.Versions.v2->SavedSendPacketsHandler;
        OpenBlock->Handlers.SendCompleteHandler = BlockRef->u1.Versions.v2->SendCompleteHandler;
        OpenBlock->Handlers.SendHandler = BlockRef->u1.Versions.v2->SendHandler;
        OpenBlock->Handlers.SendPacketsHandler = BlockRef->u1.Versions.v2->SendPacketsHandler;
        OpenBlock->Handlers.StatusCompleteHandler = BlockRef->u1.Versions.v2->StatusCompleteHandler;
        OpenBlock->Handlers.StatusHandler = BlockRef->u1.Versions.v2->StatusHandler;
        OpenBlock->Handlers.TcpOffloadDisconnectCompleteHandler = BlockRef->u1.Versions.v2->TcpOffloadDisconnectCompleteHandler;
        OpenBlock->Handlers.TcpOffloadEventHandler = BlockRef->u1.Versions.v2->TcpOffloadEventHandler;
        OpenBlock->Handlers.TcpOffloadForwardCompleteHandler = BlockRef->u1.Versions.v2->TcpOffloadForwardCompleteHandler;
        OpenBlock->Handlers.TcpOffloadReceiveCompleteHandler = BlockRef->u1.Versions.v2->TcpOffloadReceiveCompleteHandler;
        OpenBlock->Handlers.TcpOffloadReceiveIndicateHandler = BlockRef->u1.Versions.v2->TcpOffloadReceiveIndicateHandler;
        OpenBlock->Handlers.TcpOffloadSendCompleteHandler = BlockRef->u1.Versions.v2->TcpOffloadSendCompleteHandler;
        OpenBlock->Handlers.TerminateOffloadCompleteHandler = BlockRef->u1.Versions.v2->TerminateOffloadCompleteHandler;
        OpenBlock->Handlers.TransferDataCompleteHandler = BlockRef->u1.Versions.v2->TransferDataCompleteHandler;
        OpenBlock->Handlers.TransferDataHandler = BlockRef->u1.Versions.v2->TransferDataHandler;
        OpenBlock->Handlers.UpdateOffloadCompleteHandler = BlockRef->u1.Versions.v2->UpdateOffloadCompleteHandler;
        OpenBlock->Handlers.WanReceiveHandler = BlockRef->u1.Versions.v2->WanReceiveHandler;
        OpenBlock->Handlers.WSendHandler = BlockRef->u1.Versions.v2->WSendHandler;
        OpenBlock->Handlers.WSendPacketsHandler = BlockRef->u1.Versions.v2->WSendPacketsHandler;
        OpenBlock->Handlers.WTransferDataHandler = BlockRef->u1.Versions.v2->WTransferDataHandler;
        break;

    case NDIS_OPEN_BLOCK_VERSION_WIN81_WIN10TH1: //9600..10586      
        OpenBlock->ProtocolNextOpen = BlockRef->u1.Versions.u_v3.v3c->ProtocolNextOpen;
        OpenBlock->BindDeviceName = BlockRef->u1.Versions.u_v3.v3c->BindDeviceName;
        OpenBlock->RootDeviceName = BlockRef->u1.Versions.u_v3.v3c->RootDeviceName;

        OpenBlock->Handlers.AllocateSharedMemoryHandler = BlockRef->u1.Versions.u_v3.v3c->AllocateSharedMemoryHandler;
        OpenBlock->Handlers.CancelSendPacketsHandler = BlockRef->u1.Versions.u_v3.v3c->CancelSendPacketsHandler;
        OpenBlock->Handlers.CmActivateVcCompleteHandler = BlockRef->u1.Versions.u_v3.v3->CmActivateVcCompleteHandler;
        OpenBlock->Handlers.CmDeactivateVcCompleteHandler = BlockRef->u1.Versions.u_v3.v3->CmDeactivateVcCompleteHandler;
        OpenBlock->Handlers.CoCreateVcHandler = BlockRef->u1.Versions.u_v3.v3->CoCreateVcHandler;
        OpenBlock->Handlers.CoDeleteVcHandler = BlockRef->u1.Versions.u_v3.v3->CoDeleteVcHandler;
        OpenBlock->Handlers.CoOidRequestCompleteHandler = BlockRef->u1.Versions.u_v3.v3->CoOidRequestCompleteHandler;
        OpenBlock->Handlers.CoOidRequestHandler = BlockRef->u1.Versions.u_v3.v3->CoOidRequestHandler;
        OpenBlock->Handlers.CoRequestCompleteHandler = BlockRef->u1.Versions.u_v3.v3->CoRequestCompleteHandler;
        OpenBlock->Handlers.CoRequestHandler = BlockRef->u1.Versions.u_v3.v3->CoRequestHandler;
        OpenBlock->Handlers.DirectOidRequestHandler = BlockRef->u1.Versions.u_v3.v3c->DirectOidRequestHandler;
        OpenBlock->Handlers.FreeSharedMemoryHandler = BlockRef->u1.Versions.u_v3.v3c->FreeSharedMemoryHandler;
        OpenBlock->Handlers.IndicateOffloadEventHandler = BlockRef->u1.Versions.u_v3.v3c->IndicateOffloadEventHandler;
        OpenBlock->Handlers.InitiateOffloadCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->InitiateOffloadCompleteHandler;
        OpenBlock->Handlers.InvalidateOffloadCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->InvalidateOffloadCompleteHandler;
        OpenBlock->Handlers.MiniportCoCreateVcHandler = BlockRef->u1.Versions.u_v3.v3->MiniportCoCreateVcHandler;
        OpenBlock->Handlers.MiniportCoOidRequestHandler = BlockRef->u1.Versions.u_v3.v3->MiniportCoOidRequestHandler;
        OpenBlock->Handlers.MiniportCoRequestHandler = BlockRef->u1.Versions.u_v3.v3->MiniportCoRequestHandler;
        OpenBlock->Handlers.Ndis5WanSendHandler = BlockRef->u1.Versions.u_v3.v3c->Ndis5WanSendHandler;
        OpenBlock->Handlers.NextReturnNetBufferListsHandler = BlockRef->u1.Versions.u_v3.v3c->NextReturnNetBufferListsHandler;
        OpenBlock->Handlers.NextSendHandler = BlockRef->u1.Versions.u_v3.v3c->NextSendHandler;
        OpenBlock->Handlers.OidRequestCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->OidRequestCompleteHandler;
        OpenBlock->Handlers.OidRequestHandler = BlockRef->u1.Versions.u_v3.v3c->OidRequestHandler;
        OpenBlock->Handlers.ProtSendCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->ProtSendCompleteHandler;
        OpenBlock->Handlers.ProtSendNetBufferListsComplete = BlockRef->u1.Versions.u_v3.v3c->ProtSendNetBufferListsComplete;
        OpenBlock->Handlers.QueryOffloadCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->QueryOffloadCompleteHandler;
        OpenBlock->Handlers.ReceiveCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->ReceiveCompleteHandler;
        OpenBlock->Handlers.ReceiveHandler = BlockRef->u1.Versions.u_v3.v3c->ReceiveHandler;
        OpenBlock->Handlers.ReceiveNetBufferLists = BlockRef->u1.Versions.u_v3.v3c->ReceiveNetBufferLists;
        OpenBlock->Handlers.ReceivePacketHandler = BlockRef->u1.Versions.u_v3.v3c->ReceivePacketHandler;
        OpenBlock->Handlers.RequestCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->RequestCompleteHandler;
        OpenBlock->Handlers.RequestHandler = BlockRef->u1.Versions.u_v3.v3c->RequestHandler;
        OpenBlock->Handlers.ResetCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->ResetCompleteHandler;
        OpenBlock->Handlers.ResetHandler = BlockRef->u1.Versions.u_v3.v3c->ResetHandler;
        OpenBlock->Handlers.SavedCancelSendPacketsHandler = BlockRef->u1.Versions.u_v3.v3c->SavedCancelSendPacketsHandler;
        OpenBlock->Handlers.SavedSendHandler = BlockRef->u1.Versions.u_v3.v3c->SavedSendHandler;
        OpenBlock->Handlers.SavedSendPacketsHandler = BlockRef->u1.Versions.u_v3.v3c->SavedSendPacketsHandler;
        OpenBlock->Handlers.SendCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->SendCompleteHandler;
        OpenBlock->Handlers.SendHandler = BlockRef->u1.Versions.u_v3.v3c->SendHandler;
        OpenBlock->Handlers.SendPacketsHandler = BlockRef->u1.Versions.u_v3.v3c->SendPacketsHandler;
        OpenBlock->Handlers.StatusCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->StatusCompleteHandler;
        OpenBlock->Handlers.StatusHandler = BlockRef->u1.Versions.u_v3.v3c->StatusHandler;
        OpenBlock->Handlers.TcpOffloadDisconnectCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->TcpOffloadDisconnectCompleteHandler;
        OpenBlock->Handlers.TcpOffloadEventHandler = BlockRef->u1.Versions.u_v3.v3c->TcpOffloadEventHandler;
        OpenBlock->Handlers.TcpOffloadForwardCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->TcpOffloadForwardCompleteHandler;
        OpenBlock->Handlers.TcpOffloadReceiveCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->TcpOffloadReceiveCompleteHandler;
        OpenBlock->Handlers.TcpOffloadReceiveIndicateHandler = BlockRef->u1.Versions.u_v3.v3c->TcpOffloadReceiveIndicateHandler;
        OpenBlock->Handlers.TcpOffloadSendCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->TcpOffloadSendCompleteHandler;
        OpenBlock->Handlers.TerminateOffloadCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->TerminateOffloadCompleteHandler;
        OpenBlock->Handlers.TransferDataCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->TransferDataCompleteHandler;
        OpenBlock->Handlers.TransferDataHandler = BlockRef->u1.Versions.u_v3.v3c->TransferDataHandler;
        OpenBlock->Handlers.UpdateOffloadCompleteHandler = BlockRef->u1.Versions.u_v3.v3c->UpdateOffloadCompleteHandler;
        OpenBlock->Handlers.WanReceiveHandler = BlockRef->u1.Versions.u_v3.v3c->WanReceiveHandler;
        OpenBlock->Handlers.WSendHandler = BlockRef->u1.Versions.u_v3.v3c->WSendHandler;
        OpenBlock->Handlers.WSendPacketsHandler = BlockRef->u1.Versions.u_v3.v3c->WSendPacketsHandler;
        OpenBlock->Handlers.WTransferDataHandler = BlockRef->u1.Versions.u_v3.v3c->WTransferDataHandler;
        break;

    case NDIS_OPEN_BLOCK_VERSION_WIN10_RS1_4: //14393..17134
        OpenBlock->ProtocolNextOpen = BlockRef->u1.Versions.u_v4.v4c->ProtocolNextOpen;
        OpenBlock->BindDeviceName = BlockRef->u1.Versions.u_v4.v4c->BindDeviceName;
        OpenBlock->RootDeviceName = BlockRef->u1.Versions.u_v4.v4c->RootDeviceName;

        OpenBlock->Handlers.AllocateSharedMemoryHandler = BlockRef->u1.Versions.u_v4.v4c->AllocateSharedMemoryHandler;
        OpenBlock->Handlers.CancelSendPacketsHandler = BlockRef->u1.Versions.u_v4.v4c->CancelSendPacketsHandler;
        OpenBlock->Handlers.CmActivateVcCompleteHandler = BlockRef->u1.Versions.u_v4.v4->CmActivateVcCompleteHandler;
        OpenBlock->Handlers.CmDeactivateVcCompleteHandler = BlockRef->u1.Versions.u_v4.v4->CmDeactivateVcCompleteHandler;
        OpenBlock->Handlers.CoCreateVcHandler = BlockRef->u1.Versions.u_v4.v4->CoCreateVcHandler;
        OpenBlock->Handlers.CoDeleteVcHandler = BlockRef->u1.Versions.u_v4.v4->CoDeleteVcHandler;
        OpenBlock->Handlers.CoOidRequestCompleteHandler = BlockRef->u1.Versions.u_v4.v4->CoOidRequestCompleteHandler;
        OpenBlock->Handlers.CoOidRequestHandler = BlockRef->u1.Versions.u_v4.v4->CoOidRequestHandler;
        OpenBlock->Handlers.CoRequestCompleteHandler = BlockRef->u1.Versions.u_v4.v4->CoRequestCompleteHandler;
        OpenBlock->Handlers.CoRequestHandler = BlockRef->u1.Versions.u_v4.v4->CoRequestHandler;
        OpenBlock->Handlers.DirectOidRequestHandler = BlockRef->u1.Versions.u_v4.v4c->DirectOidRequestHandler;
        OpenBlock->Handlers.FreeSharedMemoryHandler = BlockRef->u1.Versions.u_v4.v4c->FreeSharedMemoryHandler;
        OpenBlock->Handlers.IndicateOffloadEventHandler = BlockRef->u1.Versions.u_v4.v4c->IndicateOffloadEventHandler;
        OpenBlock->Handlers.InitiateOffloadCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->InitiateOffloadCompleteHandler;
        OpenBlock->Handlers.InvalidateOffloadCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->InvalidateOffloadCompleteHandler;
        OpenBlock->Handlers.MiniportCoCreateVcHandler = BlockRef->u1.Versions.u_v4.v4->MiniportCoCreateVcHandler;
        OpenBlock->Handlers.MiniportCoOidRequestHandler = BlockRef->u1.Versions.u_v4.v4->MiniportCoOidRequestHandler;
        OpenBlock->Handlers.MiniportCoRequestHandler = BlockRef->u1.Versions.u_v4.v4->MiniportCoRequestHandler;
        OpenBlock->Handlers.Ndis5WanSendHandler = BlockRef->u1.Versions.u_v4.v4c->Ndis5WanSendHandler;
        OpenBlock->Handlers.NextReturnNetBufferListsHandler = BlockRef->u1.Versions.u_v4.v4c->NextReturnNetBufferListsHandler;
        OpenBlock->Handlers.NextSendHandler = BlockRef->u1.Versions.u_v4.v4c->NextSendHandler;
        OpenBlock->Handlers.OidRequestCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->OidRequestCompleteHandler;
        OpenBlock->Handlers.OidRequestHandler = BlockRef->u1.Versions.u_v4.v4c->OidRequestHandler;
        OpenBlock->Handlers.ProtSendCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->ProtSendCompleteHandler;
        OpenBlock->Handlers.ProtSendNetBufferListsComplete = BlockRef->u1.Versions.u_v4.v4c->ProtSendNetBufferListsComplete;
        OpenBlock->Handlers.QueryOffloadCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->QueryOffloadCompleteHandler;
        OpenBlock->Handlers.ReceiveCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->ReceiveCompleteHandler;
        OpenBlock->Handlers.ReceiveHandler = BlockRef->u1.Versions.u_v4.v4c->ReceiveHandler;
        OpenBlock->Handlers.ReceiveNetBufferLists = BlockRef->u1.Versions.u_v4.v4c->ReceiveNetBufferLists;
        OpenBlock->Handlers.ReceivePacketHandler = BlockRef->u1.Versions.u_v4.v4c->ReceivePacketHandler;
        OpenBlock->Handlers.RequestCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->RequestCompleteHandler;
        OpenBlock->Handlers.RequestHandler = BlockRef->u1.Versions.u_v4.v4c->RequestHandler;
        OpenBlock->Handlers.ResetCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->ResetCompleteHandler;
        OpenBlock->Handlers.ResetHandler = BlockRef->u1.Versions.u_v4.v4c->ResetHandler;
        OpenBlock->Handlers.SavedCancelSendPacketsHandler = BlockRef->u1.Versions.u_v4.v4c->SavedCancelSendPacketsHandler;
        OpenBlock->Handlers.SavedSendHandler = BlockRef->u1.Versions.u_v4.v4c->SavedSendHandler;
        OpenBlock->Handlers.SavedSendPacketsHandler = BlockRef->u1.Versions.u_v4.v4c->SavedSendPacketsHandler;
        OpenBlock->Handlers.SendCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->SendCompleteHandler;
        OpenBlock->Handlers.SendHandler = BlockRef->u1.Versions.u_v4.v4c->SendHandler;
        OpenBlock->Handlers.SendPacketsHandler = BlockRef->u1.Versions.u_v4.v4c->SendPacketsHandler;
        OpenBlock->Handlers.StatusCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->StatusCompleteHandler;
        OpenBlock->Handlers.StatusHandler = BlockRef->u1.Versions.u_v4.v4c->StatusHandler;
        OpenBlock->Handlers.TcpOffloadDisconnectCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->TcpOffloadDisconnectCompleteHandler;
        OpenBlock->Handlers.TcpOffloadEventHandler = BlockRef->u1.Versions.u_v4.v4c->TcpOffloadEventHandler;
        OpenBlock->Handlers.TcpOffloadForwardCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->TcpOffloadForwardCompleteHandler;
        OpenBlock->Handlers.TcpOffloadReceiveCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->TcpOffloadReceiveCompleteHandler;
        OpenBlock->Handlers.TcpOffloadReceiveIndicateHandler = BlockRef->u1.Versions.u_v4.v4c->TcpOffloadReceiveIndicateHandler;
        OpenBlock->Handlers.TcpOffloadSendCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->TcpOffloadSendCompleteHandler;
        OpenBlock->Handlers.TerminateOffloadCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->TerminateOffloadCompleteHandler;
        OpenBlock->Handlers.TransferDataCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->TransferDataCompleteHandler;
        OpenBlock->Handlers.TransferDataHandler = BlockRef->u1.Versions.u_v4.v4c->TransferDataHandler;
        OpenBlock->Handlers.UpdateOffloadCompleteHandler = BlockRef->u1.Versions.u_v4.v4c->UpdateOffloadCompleteHandler;
        OpenBlock->Handlers.WanReceiveHandler = BlockRef->u1.Versions.u_v4.v4c->WanReceiveHandler;
        OpenBlock->Handlers.WSendHandler = BlockRef->u1.Versions.u_v4.v4c->WSendHandler;
        OpenBlock->Handlers.WSendPacketsHandler = BlockRef->u1.Versions.u_v4.v4c->WSendPacketsHandler;
        OpenBlock->Handlers.WTransferDataHandler = BlockRef->u1.Versions.u_v4.v4c->WTransferDataHandler;
        break;

    case NDIS_OPEN_BLOCK_VERSION_WIN10_RS5_WIN11: //17763..22000
        OpenBlock->ProtocolNextOpen = BlockRef->u1.Versions.u_v5.v5c->ProtocolNextOpen;
        OpenBlock->BindDeviceName = BlockRef->u1.Versions.u_v5.v5c->BindDeviceName;
        OpenBlock->RootDeviceName = BlockRef->u1.Versions.u_v5.v5c->RootDeviceName;

        OpenBlock->Handlers.AllocateSharedMemoryHandler = BlockRef->u1.Versions.u_v5.v5c->AllocateSharedMemoryHandler;
        OpenBlock->Handlers.CancelSendPacketsHandler = BlockRef->u1.Versions.u_v5.v5c->CancelSendPacketsHandler;
        OpenBlock->Handlers.CmActivateVcCompleteHandler = BlockRef->u1.Versions.u_v5.v5->CmActivateVcCompleteHandler;
        OpenBlock->Handlers.CmDeactivateVcCompleteHandler = BlockRef->u1.Versions.u_v5.v5->CmDeactivateVcCompleteHandler;
        OpenBlock->Handlers.CoCreateVcHandler = BlockRef->u1.Versions.u_v5.v5->CoCreateVcHandler;
        OpenBlock->Handlers.CoDeleteVcHandler = BlockRef->u1.Versions.u_v5.v5->CoDeleteVcHandler;
        OpenBlock->Handlers.CoOidRequestCompleteHandler = BlockRef->u1.Versions.u_v5.v5->CoOidRequestCompleteHandler;
        OpenBlock->Handlers.CoOidRequestHandler = BlockRef->u1.Versions.u_v5.v5->CoOidRequestHandler;
        OpenBlock->Handlers.CoRequestCompleteHandler = BlockRef->u1.Versions.u_v5.v5->CoRequestCompleteHandler;
        OpenBlock->Handlers.CoRequestHandler = BlockRef->u1.Versions.u_v5.v5->CoRequestHandler;
        OpenBlock->Handlers.DirectOidRequestHandler = BlockRef->u1.Versions.u_v5.v5c->DirectOidRequestHandler;
        OpenBlock->Handlers.FreeSharedMemoryHandler = BlockRef->u1.Versions.u_v5.v5c->FreeSharedMemoryHandler;
        OpenBlock->Handlers.MiniportCoCreateVcHandler = BlockRef->u1.Versions.u_v5.v5->MiniportCoCreateVcHandler;
        OpenBlock->Handlers.MiniportCoOidRequestHandler = BlockRef->u1.Versions.u_v5.v5->MiniportCoOidRequestHandler;
        OpenBlock->Handlers.MiniportCoRequestHandler = BlockRef->u1.Versions.u_v5.v5->MiniportCoRequestHandler;
        OpenBlock->Handlers.Ndis5WanSendHandler = BlockRef->u1.Versions.u_v5.v5c->Ndis5WanSendHandler;
        OpenBlock->Handlers.NextReturnNetBufferListsHandler = BlockRef->u1.Versions.u_v5.v5c->NextReturnNetBufferListsHandler;
        OpenBlock->Handlers.NextSendHandler = BlockRef->u1.Versions.u_v5.v5c->NextSendHandler;
        OpenBlock->Handlers.OidRequestCompleteHandler = BlockRef->u1.Versions.u_v5.v5c->OidRequestCompleteHandler;
        OpenBlock->Handlers.OidRequestHandler = BlockRef->u1.Versions.u_v5.v5c->OidRequestHandler;
        OpenBlock->Handlers.ProtSendCompleteHandler = BlockRef->u1.Versions.u_v5.v5c->ProtSendCompleteHandler;
        OpenBlock->Handlers.ProtSendNetBufferListsComplete = BlockRef->u1.Versions.u_v5.v5c->ProtSendNetBufferListsComplete;
        OpenBlock->Handlers.ReceiveCompleteHandler = BlockRef->u1.Versions.u_v5.v5c->ReceiveCompleteHandler;
        OpenBlock->Handlers.ReceiveHandler = BlockRef->u1.Versions.u_v5.v5c->ReceiveHandler;
        OpenBlock->Handlers.ReceiveNetBufferLists = BlockRef->u1.Versions.u_v5.v5c->ReceiveNetBufferLists;
        OpenBlock->Handlers.ReceivePacketHandler = BlockRef->u1.Versions.u_v5.v5c->ReceivePacketHandler;
        OpenBlock->Handlers.RequestCompleteHandler = BlockRef->u1.Versions.u_v5.v5c->RequestCompleteHandler;
        OpenBlock->Handlers.RequestHandler = BlockRef->u1.Versions.u_v5.v5c->RequestHandler;
        OpenBlock->Handlers.ResetCompleteHandler = BlockRef->u1.Versions.u_v5.v5c->ResetCompleteHandler;
        OpenBlock->Handlers.ResetHandler = BlockRef->u1.Versions.u_v5.v5c->ResetHandler;
        OpenBlock->Handlers.SavedCancelSendPacketsHandler = BlockRef->u1.Versions.u_v5.v5c->SavedCancelSendPacketsHandler;
        OpenBlock->Handlers.SavedSendHandler = BlockRef->u1.Versions.u_v5.v5c->SavedSendHandler;
        OpenBlock->Handlers.SavedSendPacketsHandler = BlockRef->u1.Versions.u_v5.v5c->SavedSendPacketsHandler;
        OpenBlock->Handlers.SendCompleteHandler = BlockRef->u1.Versions.u_v5.v5c->SendCompleteHandler;
        OpenBlock->Handlers.SendHandler = BlockRef->u1.Versions.u_v5.v5c->SendHandler;
        OpenBlock->Handlers.SendPacketsHandler = BlockRef->u1.Versions.u_v5.v5c->SendPacketsHandler;
        OpenBlock->Handlers.StatusCompleteHandler = BlockRef->u1.Versions.u_v5.v5c->StatusCompleteHandler;
        OpenBlock->Handlers.StatusHandler = BlockRef->u1.Versions.u_v5.v5c->StatusHandler;
        OpenBlock->Handlers.TransferDataCompleteHandler = BlockRef->u1.Versions.u_v5.v5c->TransferDataCompleteHandler;
        OpenBlock->Handlers.TransferDataHandler = BlockRef->u1.Versions.u_v5.v5c->TransferDataHandler;
        OpenBlock->Handlers.WanReceiveHandler = BlockRef->u1.Versions.u_v5.v5c->WanReceiveHandler;
        OpenBlock->Handlers.WSendHandler = BlockRef->u1.Versions.u_v5.v5c->WSendHandler;
        OpenBlock->Handlers.WSendPacketsHandler = BlockRef->u1.Versions.u_v5.v5c->WSendPacketsHandler;
        OpenBlock->Handlers.WTransferDataHandler = BlockRef->u1.Versions.u_v5.v5c->WTransferDataHandler;
        break;

    case NDIS_OPEN_BLOCK_VERSION_WIN11_22_25H2: //22621..25905
        OpenBlock->ProtocolNextOpen = BlockRef->u1.Versions.u_v6.v6c->ProtocolNextOpen;
        OpenBlock->BindDeviceName = BlockRef->u1.Versions.u_v6.v6c->BindDeviceName;
        OpenBlock->RootDeviceName = BlockRef->u1.Versions.u_v6.v6c->RootDeviceName;

        OpenBlock->Handlers.AllocateSharedMemoryHandler = BlockRef->u1.Versions.u_v6.v6c->AllocateSharedMemoryHandler;
        OpenBlock->Handlers.CancelSendPacketsHandler = BlockRef->u1.Versions.u_v6.v6c->CancelSendPacketsHandler;
        OpenBlock->Handlers.CmActivateVcCompleteHandler = BlockRef->u1.Versions.u_v6.v6->CmActivateVcCompleteHandler;
        OpenBlock->Handlers.CmDeactivateVcCompleteHandler = BlockRef->u1.Versions.u_v6.v6->CmDeactivateVcCompleteHandler;
        OpenBlock->Handlers.CoCreateVcHandler = BlockRef->u1.Versions.u_v6.v6->CoCreateVcHandler;
        OpenBlock->Handlers.CoDeleteVcHandler = BlockRef->u1.Versions.u_v6.v6->CoDeleteVcHandler;
        OpenBlock->Handlers.CoOidRequestCompleteHandler = BlockRef->u1.Versions.u_v6.v6->CoOidRequestCompleteHandler;
        OpenBlock->Handlers.CoOidRequestHandler = BlockRef->u1.Versions.u_v6.v6->CoOidRequestHandler;
        OpenBlock->Handlers.CoRequestCompleteHandler = BlockRef->u1.Versions.u_v6.v6->CoRequestCompleteHandler;
        OpenBlock->Handlers.CoRequestHandler = BlockRef->u1.Versions.u_v6.v6->CoRequestHandler;
        OpenBlock->Handlers.DirectOidRequestHandler = BlockRef->u1.Versions.u_v6.v6c->DirectOidRequestHandler;
        OpenBlock->Handlers.FreeSharedMemoryHandler = BlockRef->u1.Versions.u_v6.v6c->FreeSharedMemoryHandler;
        OpenBlock->Handlers.MiniportCoCreateVcHandler = BlockRef->u1.Versions.u_v6.v6->MiniportCoCreateVcHandler;
        OpenBlock->Handlers.MiniportCoOidRequestHandler = BlockRef->u1.Versions.u_v6.v6->MiniportCoOidRequestHandler;
        OpenBlock->Handlers.MiniportCoRequestHandler = BlockRef->u1.Versions.u_v6.v6->MiniportCoRequestHandler;
        OpenBlock->Handlers.Ndis5WanSendHandler = BlockRef->u1.Versions.u_v6.v6c->Ndis5WanSendHandler;
        OpenBlock->Handlers.NextReturnNetBufferListsHandler = BlockRef->u1.Versions.u_v6.v6c->NextReturnNetBufferListsHandler;
        OpenBlock->Handlers.NextSendHandler = BlockRef->u1.Versions.u_v6.v6c->NextSendHandler;
        OpenBlock->Handlers.OidRequestCompleteHandler = BlockRef->u1.Versions.u_v6.v6c->OidRequestCompleteHandler;
        OpenBlock->Handlers.OidRequestHandler = BlockRef->u1.Versions.u_v6.v6c->OidRequestHandler;
        OpenBlock->Handlers.ProtSendCompleteHandler = BlockRef->u1.Versions.u_v6.v6c->ProtSendCompleteHandler;
        OpenBlock->Handlers.ProtSendNetBufferListsComplete = BlockRef->u1.Versions.u_v6.v6c->ProtSendNetBufferListsComplete;
        OpenBlock->Handlers.ReceiveCompleteHandler = BlockRef->u1.Versions.u_v6.v6c->ReceiveCompleteHandler;
        OpenBlock->Handlers.ReceiveHandler = BlockRef->u1.Versions.u_v6.v6c->ReceiveHandler;
        OpenBlock->Handlers.ReceiveNetBufferLists = BlockRef->u1.Versions.u_v6.v6c->ReceiveNetBufferLists;
        OpenBlock->Handlers.ReceivePacketHandler = BlockRef->u1.Versions.u_v6.v6c->ReceivePacketHandler;
        OpenBlock->Handlers.RequestCompleteHandler = BlockRef->u1.Versions.u_v6.v6c->RequestCompleteHandler;
        OpenBlock->Handlers.RequestHandler = BlockRef->u1.Versions.u_v6.v6c->RequestHandler;
        OpenBlock->Handlers.ResetCompleteHandler = BlockRef->u1.Versions.u_v6.v6c->ResetCompleteHandler;
        OpenBlock->Handlers.ResetHandler = BlockRef->u1.Versions.u_v6.v6c->ResetHandler;
        OpenBlock->Handlers.SavedCancelSendPacketsHandler = BlockRef->u1.Versions.u_v6.v6c->SavedCancelSendPacketsHandler;
        OpenBlock->Handlers.SavedSendHandler = BlockRef->u1.Versions.u_v6.v6c->SavedSendHandler;
        OpenBlock->Handlers.SavedSendPacketsHandler = BlockRef->u1.Versions.u_v6.v6c->SavedSendPacketsHandler;
        OpenBlock->Handlers.SendCompleteHandler = BlockRef->u1.Versions.u_v6.v6c->SendCompleteHandler;
        OpenBlock->Handlers.SendHandler = BlockRef->u1.Versions.u_v6.v6c->SendHandler;
        OpenBlock->Handlers.SendPacketsHandler = BlockRef->u1.Versions.u_v6.v6c->SendPacketsHandler;
        OpenBlock->Handlers.StatusCompleteHandler = BlockRef->u1.Versions.u_v6.v6c->StatusCompleteHandler;
        OpenBlock->Handlers.StatusHandler = BlockRef->u1.Versions.u_v6.v6c->StatusHandler;
        OpenBlock->Handlers.TransferDataCompleteHandler = BlockRef->u1.Versions.u_v6.v6c->TransferDataCompleteHandler;
        OpenBlock->Handlers.TransferDataHandler = BlockRef->u1.Versions.u_v6.v6c->TransferDataHandler;
        OpenBlock->Handlers.WanReceiveHandler = BlockRef->u1.Versions.u_v6.v6c->WanReceiveHandler;
        OpenBlock->Handlers.WSendHandler = BlockRef->u1.Versions.u_v6.v6c->WSendHandler;
        OpenBlock->Handlers.WSendPacketsHandler = BlockRef->u1.Versions.u_v6.v6c->WSendPacketsHandler;
        OpenBlock->Handlers.WTransferDataHandler = BlockRef->u1.Versions.u_v6.v6c->WTransferDataHandler;
        break;
    default:
        return FALSE;
    }

    return TRUE;
}

/*
* ReadAndConvertProtocolBlock
*
* Purpose:
*
* Read protocol block from kernel and convert it to the compatible form.
*
*/
_Success_(return == TRUE)
BOOL ReadAndConvertProtocolBlock(
    _In_ ULONG_PTR ObjectAddress,
    _Inout_ NDIS_PROTOCOL_BLOCK_COMPATIBLE * ProtoBlock,
    _Out_opt_ PULONG ObjectVersion
)
{
    BOOL Result = FALSE;
    ULONG objectVersion;
    ULONG objectSize;
    PVOID objectPtr;

    PROTOCOL_BLOCK_VERSIONS ProtocolRef;

    objectPtr = DumpProtocolBlockVersionAware(ObjectAddress, &objectSize, &objectVersion);
    if (objectPtr == NULL)
        return FALSE;

    ProtocolRef.u1.Ref = objectPtr;
    Result = CreateCompatibleProtocolBlock(objectVersion, &ProtocolRef, ProtoBlock);

    if (ObjectVersion) {
        *ObjectVersion = objectVersion;
    }

    HeapMemoryFree(objectPtr);

    return Result;
}

/*
* ReadAndConvertOpenBlock
*
* Purpose:
*
* Read open block from kernel and convert it to compatible form.
*
*/
_Success_(return == TRUE)
BOOL ReadAndConvertOpenBlock(
    _In_ ULONG_PTR ObjectAddress,
    _Inout_ NDIS_OPEN_BLOCK_COMPATIBLE * OpenBlock,
    _Out_opt_ PULONG ObjectVersion)
{
    BOOL Result = FALSE;
    ULONG objectVersion;
    ULONG objectSize;
    PVOID objectPtr;

    OPEN_BLOCK_VERSIONS BlockRef;

    objectPtr = DumpOpenBlockVersionAware(ObjectAddress, &objectSize, &objectVersion);
    if (objectPtr == NULL) {
        return FALSE;
    }
    BlockRef.u1.Ref = objectPtr;

    Result = CreateCompatibleOpenBlock(objectVersion, &BlockRef, OpenBlock);

    if (ObjectVersion) {
        *ObjectVersion = objectVersion;
    }

    HeapMemoryFree(objectPtr);

    return Result;
}
