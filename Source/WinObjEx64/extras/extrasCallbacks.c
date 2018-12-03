/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       EXTRASCALLBACKS.C
*
*  VERSION:     1.70
*
*  DATE:        30 Nov 2018
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "extras.h"
#include "extrasCallbacks.h"
#include "treelist\treelist.h"
#include "hde/hde64.h"

ATOM g_CbTreeListAtom;

/*
* FindIopFileSystemQueueHeads
*
* Purpose:
*
* Return addresses of list heads for callbacks registered with:
*
*   IoRegisterFileSystem
*
*/
_Success_(return == TRUE)
BOOL FindIopFileSystemQueueHeads(
    _Out_ ULONG_PTR *IopCdRomFileSystemQueueHead,
    _Out_ ULONG_PTR *IopDiskFileSystemQueueHead,
    _Out_ ULONG_PTR *IopTapeFileSystemQueueHead,
    _Out_ ULONG_PTR *IopNetworkFileSystemQueueHead
)
{
    ULONG Index, Count;
    LONG Rel = 0;
    ULONG_PTR Address = 0;
    PBYTE ptrCode;
    hde64s hs;

    ULONG_PTR NtOsBase = (ULONG_PTR)g_kdctx.NtOsBase;
    HMODULE hNtOs = (HINSTANCE)g_kdctx.NtOsImageMap;

    ptrCode = (PBYTE)GetProcAddress(hNtOs, "IoRegisterFileSystem");

    if (ptrCode == NULL)
        return 0;

    Index = 0;
    Rel = 0;
    Count = 0;

    if (g_NtBuildNumber < 9200) {

        do {
            hde64_disasm(ptrCode + Index, &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == 7) {
                //
                // lea  rdx, xxx                
                //
                if ((ptrCode[Index] == 0x48) &&
                    (ptrCode[Index + 1] == 0x8D) &&
                    (ptrCode[Index + 2] == 0x15))
                {
                    Rel = *(PLONG)(ptrCode + Index + 3);
                    if (Rel) {
                        Address = (ULONG_PTR)ptrCode + Index + hs.len + Rel;
                        Address = NtOsBase + Address - (ULONG_PTR)hNtOs;
                        if (kdAddressInNtOsImage((PVOID)Address)) {

                            switch (Count) {
                            case 0:
                                *IopNetworkFileSystemQueueHead = Address;
                                break;

                            case 1:
                                *IopCdRomFileSystemQueueHead = Address;
                                break;

                            case 2:
                                *IopDiskFileSystemQueueHead = Address;
                                break;

                            case 3:
                                *IopTapeFileSystemQueueHead = Address;
                                break;

                            default:
                                break;
                            }
                            Count += 1;
                            if (Count == 4)
                                break;
                        }
                    }
                }

            }

            Index += hs.len;

        } while (Index < 512);

    }
    else {

        do {
            hde64_disasm(ptrCode + Index, &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == 7) {
                //
                // lea  rdx, xxx                
                //
                if ((ptrCode[Index] == 0x48) &&
                    (ptrCode[Index + 1] == 0x8D) &&
                    (ptrCode[Index + 2] == 0x0D) &&
                    ((ptrCode[Index + hs.len] == 0x48) || (ptrCode[Index + hs.len] == 0xE9)))
                {
                    Rel = *(PLONG)(ptrCode + Index + 3);
                    if (Rel) {
                        Address = (ULONG_PTR)ptrCode + Index + hs.len + Rel;
                        Address = NtOsBase + Address - (ULONG_PTR)hNtOs;
                        if (kdAddressInNtOsImage((PVOID)Address)) {

                            switch (Count) {

                            case 0:
                                *IopDiskFileSystemQueueHead = Address;
                                break;

                            case 1:
                                *IopCdRomFileSystemQueueHead = Address;
                                break;

                            case 2:
                                *IopNetworkFileSystemQueueHead = Address;
                                break;

                            case 3:
                                *IopTapeFileSystemQueueHead = Address;
                                break;

                            default:
                                break;
                            }
                            Count += 1;
                            if (Count == 4)
                                break;
                        }
                    }
                }

            }

            Index += hs.len;

        } while (Index < 512);

    }

    return (Count == 4);
}

/*
* FindIopFsNotifyChangeQueueHead
*
* Purpose:
*
* Return address of list head for callbacks registered with:
*
*   IoRegisterFsRegistrationChange
*
*/
ULONG_PTR FindIopFsNotifyChangeQueueHead(
    VOID
)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR Address = 0;
    PBYTE ptrCode;
    hde64s hs;

    ULONG_PTR NtOsBase = (ULONG_PTR)g_kdctx.NtOsBase;
    HMODULE hNtOs = (HINSTANCE)g_kdctx.NtOsImageMap;

    ptrCode = (PBYTE)GetProcAddress(hNtOs, "IoUnregisterFsRegistrationChange");

    if (ptrCode == NULL)
        return 0;

    Index = 0;
    Rel = 0;

    do {
        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 7) {
            //
            // lea  rax, IopFsNotifyChangeQueueHead
            // jmp  short
            //
            if ((ptrCode[Index] == 0x48) &&
                (ptrCode[Index + 1] == 0x8D) &&
                (ptrCode[Index + 2] == 0x05) &&
                (ptrCode[Index + 7] == 0xEB))
            {
                Rel = *(PLONG)(ptrCode + Index + 3);
                break;
            }

        }

        Index += hs.len;

    } while (Index < 256);

    if (Rel == 0)
        return 0;

    Address = (ULONG_PTR)ptrCode + Index + hs.len + Rel;
    Address = NtOsBase + Address - (ULONG_PTR)hNtOs;

    if (!kdAddressInNtOsImage((PVOID)Address))
        return 0;

    return Address;
}

/*
* FindRtlpDebugPrintCallbackList
*
* Purpose:
*
* Return address of list head for callbacks registered with:
*
*   DbgSetDebugPrintCallback
*
*/
ULONG_PTR FindRtlpDebugPrintCallbackList(
    VOID
)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR Address = 0;
    PBYTE ptrCode;
    hde64s hs;

    ULONG_PTR NtOsBase = (ULONG_PTR)g_kdctx.NtOsBase;
    HMODULE hNtOs = (HMODULE)g_kdctx.NtOsImageMap;

    ptrCode = (PBYTE)GetProcAddress(hNtOs, "DbgSetDebugPrintCallback");
    if (ptrCode == NULL)
        return 0;

    //
    // Find DbgpInsertDebugPrintCallback pointer.
    //
    Index = 0;
    do {

        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        //jmp/call DbgpInsertDebugPrintCallback
        if (hs.len == 5) {

            if ((ptrCode[Index] == 0xE9) ||
                (ptrCode[Index] == 0xE8))
            {
                Rel = *(PLONG)(ptrCode + Index + 1);
                break;
            }
        }
        //jz
        if (hs.len == 6) {

            if (ptrCode[Index] == 0x0F) {
                Rel = *(PLONG)(ptrCode + Index + 2);
                break;
            }
        }
        Index += hs.len;

    } while (Index < 64);

    if (Rel == 0)
        return 0;

    ptrCode = ptrCode + Index + (hs.len) + Rel;
    Index = 0;
    Rel = 0;

    //
    // Complicated search. Not unique search patterns.
    //

    do {
        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        //
        // lea  reg, RtlpDebugPrintCallbackList
        //
        if (hs.len == 7) {
            if ((ptrCode[Index] == 0x48) &&
                (ptrCode[Index + 1] == 0x8D) &&
                ((ptrCode[Index + 2] == 0x15) || (ptrCode[Index + 2] == 0x0D)) &&
                (ptrCode[Index + hs.len] == 0x48))
            {
                Rel = *(PLONG)(ptrCode + Index + 3);
                break;
            }
        }

        Index += hs.len;

    } while (Index < 512);

    if (Rel == 0)
        return 0;

    Address = (ULONG_PTR)ptrCode + Index + hs.len + Rel;
    Address = NtOsBase + Address - (ULONG_PTR)hNtOs;

    if (!kdAddressInNtOsImage((PVOID)Address))
        return 0;

    return Address;
}

/*
* FindPopRegisteredPowerSettingCallbacks
*
* Purpose:
*
* Return address of list head for callbacks registered with:
*
*   PoRegisterPowerSettingCallback
*
*/
ULONG_PTR FindPopRegisteredPowerSettingCallbacks(
    VOID
)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR Address = 0;
    PBYTE ptrCode;
    hde64s hs;

    ULONG_PTR NtOsBase = (ULONG_PTR)g_kdctx.NtOsBase;
    HMODULE hNtOs = (HINSTANCE)g_kdctx.NtOsImageMap;

    ptrCode = (PBYTE)GetProcAddress(hNtOs, "PoRegisterPowerSettingCallback");

    if (ptrCode == NULL)
        return 0;

    Index = 0;
    Rel = 0;

    do {
        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 7) {
            //
            // lea      rcx, PopRegisteredPowerSettingCallbacks
            // mov      [rbx + 8], rax
            //
            if ((ptrCode[Index] == 0x48) &&
                (ptrCode[Index + 1] == 0x8D) &&
                (ptrCode[Index + 2] == 0x0D) &&
                (ptrCode[Index + 7] == 0x48))
            {
                Rel = *(PLONG)(ptrCode + Index + 3);
                break;
            }

        }

        Index += hs.len;

    } while (Index < 512);

    if (Rel == 0)
        return 0;

    Address = (ULONG_PTR)ptrCode + Index + hs.len + Rel;
    Address = NtOsBase + Address - (ULONG_PTR)hNtOs;

    if (!kdAddressInNtOsImage((PVOID)Address))
        return 0;

    return Address;
}

/*
* FindSeFileSystemNotifyRoutinesHead
*
* Purpose:
*
* Return address of list head for callbacks registered with:
*
*   SeRegisterLogonSessionTerminatedRoutine
*   SeRegisterLogonSessionTerminatedRoutineEx
*
*/
ULONG_PTR FindSeFileSystemNotifyRoutinesHead(
    _In_ BOOL Extended)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR Address = 0;
    PBYTE ptrCode;
    hde64s hs;

    ULONG_PTR NtOsBase = (ULONG_PTR)g_kdctx.NtOsBase;
    HMODULE hNtOs = (HINSTANCE)g_kdctx.NtOsImageMap;

    //
    // Routines have similar design.
    //
    if (Extended) {
        ptrCode = (PBYTE)GetProcAddress(hNtOs, "SeRegisterLogonSessionTerminatedRoutineEx");
    }
    else {
        ptrCode = (PBYTE)GetProcAddress(hNtOs, "SeRegisterLogonSessionTerminatedRoutine");
    }

    if (ptrCode == NULL)
        return 0;

    Index = 0;
    Rel = 0;

    do {
        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 7) {

            //
            // mov     rax, cs:SeFileSystemNotifyRoutines(Ex)Head
            //

            if ((ptrCode[Index] == 0x48) &&
                (ptrCode[Index + 1] == 0x8B) &&
                (ptrCode[Index + 2] == 0x05))
            {
                Rel = *(PLONG)(ptrCode + Index + 3);
                break;
            }

        }

        Index += hs.len;

    } while (Index < 128);

    if (Rel == 0)
        return 0;

    Address = (ULONG_PTR)ptrCode + Index + hs.len + Rel;
    Address = NtOsBase + Address - (ULONG_PTR)hNtOs;

    if (!kdAddressInNtOsImage((PVOID)Address))
        return 0;

    return Address;
}

/*
* GetObjectTypeCallbackListHeadByType
*
* Purpose:
*
* Return address of list head for callbacks registered with:
*
*   ObRegisterCallbacks
*
*/
ULONG_PTR GetObjectTypeCallbackListHeadByType(
    _In_ ULONG Type
)
{
    ULONG_PTR ListHead = 0;
    ULONG ObjectSize, ObjectVersion = 0, CallbackListOffset = 0;
    LPWSTR lpType = NULL;
    POBJINFO CurrentObject = NULL;
    PVOID ObjectTypeInformation = NULL;

    union {
        union {
            OBJECT_TYPE_7 *ObjectType_7;
            OBJECT_TYPE_8 *ObjectType_8;
            OBJECT_TYPE_RS1 *ObjectType_RS1;
            OBJECT_TYPE_RS2 *ObjectType_RS2;
        } Versions;
        PVOID Ref;
    } ObjectType;

    switch (Type) {
    case 0: //PsProcessType
        lpType = TEXT("Process");
        break;
    case 1: //PsThreadType
        lpType = TEXT("Thread");
        break;
    default:
        //ExDesktopObjectType
        lpType = TEXT("Desktop");
        break;
    }

    //
    // Get the reference to the object.
    //
    CurrentObject = ObQueryObject(T_OBJECTTYPES, lpType);
    if (CurrentObject == NULL)
        return 0;

    //
    // Dump object information version aware.
    //
    ObjectTypeInformation = ObDumpObjectTypeVersionAware(
        CurrentObject->ObjectAddress,
        &ObjectSize,
        &ObjectVersion);

    if (ObjectTypeInformation == NULL) {
        supHeapFree(CurrentObject);
        return 0;
    }

    ObjectType.Ref = ObjectTypeInformation;

    //
    // Flags in structure offset compatible fields.
    //
    if (ObjectType.Versions.ObjectType_7->TypeInfo.SupportsObjectCallbacks) {

        //
        // Calculate offset to structure field.
        //
        switch (ObjectVersion) {
        case 1:
            CallbackListOffset = FIELD_OFFSET(OBJECT_TYPE_7, CallbackList);
            break;

        case 2:
            CallbackListOffset = FIELD_OFFSET(OBJECT_TYPE_8, CallbackList);
            break;

        case 3:
            CallbackListOffset = FIELD_OFFSET(OBJECT_TYPE_RS1, CallbackList);
            break;

        default:
            CallbackListOffset = FIELD_OFFSET(OBJECT_TYPE_RS2, CallbackList);
            break;
        }

        ListHead = CurrentObject->ObjectAddress + CallbackListOffset;
    }

    supHeapFree(CurrentObject);
    supVirtualFree(ObjectTypeInformation);
    return ListHead;
}

/*
* FindIopNotifyShutdownQueueHeadHead
*
* Purpose:
*
* Return address of list head for callbacks registered with:
*
*   IoRegisterShutdownNotification
*   IoRegisterLastChanceShutdownNotification
*
*/
ULONG_PTR FindIopNotifyShutdownQueueHeadHead(
    _In_ BOOL bLastChance)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR Address = 0;
    PBYTE ptrCode;
    hde64s hs;

    ULONG_PTR NtOsBase = (ULONG_PTR)g_kdctx.NtOsBase;
    HMODULE hNtOs = (HINSTANCE)g_kdctx.NtOsImageMap;

    //
    // Routines have similar design.
    //
    if (bLastChance) {
        ptrCode = (PBYTE)GetProcAddress(hNtOs, "IoRegisterLastChanceShutdownNotification");
    }
    else {
        ptrCode = (PBYTE)GetProcAddress(hNtOs, "IoRegisterShutdownNotification");
    }

    if (ptrCode == NULL)
        return 0;

    Index = 0;
    Rel = 0;

    do {
        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 7) { //check if lea

            if (((ptrCode[Index] == 0x48) || (ptrCode[Index] == 0x4C)) &&
                (ptrCode[Index + 1] == 0x8D))
            {
                Rel = *(PLONG)(ptrCode + Index + 3);
                break;
            }

        }

        Index += hs.len;

    } while (Index < 128);

    if (Rel == 0)
        return 0;

    Address = (ULONG_PTR)ptrCode + Index + hs.len + Rel;
    Address = NtOsBase + Address - (ULONG_PTR)hNtOs;

    if (!kdAddressInNtOsImage((PVOID)Address))
        return 0;

    return Address;
}

/*
* FindCmCallbackHead
*
* Purpose:
*
* Return address of list head for callbacks registered with:
*
*   CmRegisterCallback
*   CmRegisterCallbackEx
*
*/
ULONG_PTR FindCmCallbackHead(
    VOID)
{
    ULONG Index, resultOffset;
    LONG Rel = 0, FirstInstructionLength;
    ULONG_PTR Address = 0;
    PBYTE ptrCode;
    hde64s hs, hs_next;

    ULONG_PTR NtOsBase = (ULONG_PTR)g_kdctx.NtOsBase;
    HMODULE hNtOs = (HMODULE)g_kdctx.NtOsImageMap;

    ptrCode = (PBYTE)GetProcAddress(hNtOs, "CmUnRegisterCallback");
    if (ptrCode == NULL)
        return 0;

    Index = 0;
    Rel = 0;
    resultOffset = 0;

    do {
        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 5) {
            /*
            ** lea     rdx, [rsp+20h] <-
            ** lea     rcx, CallbackListHead
            */
            if ((ptrCode[Index] == 0x48) &&
                (ptrCode[Index + 1] == 0x8D) &&
                (ptrCode[Index + 2] == 0x54))
            {
                hde64_disasm(ptrCode + Index + hs.len, &hs_next);
                if (hs_next.flags & F_ERROR)
                    break;
                if (hs_next.len == 7) {

                    /*
                    ** lea     rdx, [rsp+20h]
                    ** lea     rcx, CallbackListHead <-
                    */
                    FirstInstructionLength = hs.len;

                    if ((ptrCode[Index + FirstInstructionLength] == 0x48) &&
                        (ptrCode[Index + FirstInstructionLength + 1] == 0x8D) &&
                        (ptrCode[Index + FirstInstructionLength + 2] == 0x0D))
                    {
                        resultOffset = Index + FirstInstructionLength + hs_next.len;
                        Rel = *(PLONG)(ptrCode + Index + FirstInstructionLength + 3);
                        break;
                    }
                }
            }
        }

        Index += hs.len;

    } while (Index < 256);

    if (Rel == 0)
        return 0;

    Address = (ULONG_PTR)ptrCode + resultOffset + Rel;
    Address = NtOsBase + Address - (ULONG_PTR)hNtOs;

    if (!kdAddressInNtOsImage((PVOID)Address))
        return 0;

    return Address;
}

/*
* FindKeBugCheckReasonCallbackHead
*
* Purpose:
*
* Return address of list head for callbacks registered with:
*
*   KeRegisterBugCheckReasonCallback
*
*/
ULONG_PTR FindKeBugCheckReasonCallbackHead(
    VOID)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR Address = 0;
    PBYTE ptrCode;
    hde64s hs;

    ULONG_PTR NtOsBase = (ULONG_PTR)g_kdctx.NtOsBase;
    HMODULE hNtOs = (HMODULE)g_kdctx.NtOsImageMap;

    ptrCode = (PBYTE)GetProcAddress(hNtOs, "KeRegisterBugCheckReasonCallback");
    if (ptrCode == NULL)
        return 0;

    Index = 0;
    Rel = 0;

    do {
        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 7) { //check if lea

            if (((ptrCode[Index] == 0x48) || (ptrCode[Index] == 0x4C)) &&
                (ptrCode[Index + 1] == 0x8D) &&
                ((ptrCode[Index + hs.len] == 0x48) || (ptrCode[Index + hs.len] == 0x83)))
            {
                Rel = *(PLONG)(ptrCode + Index + 3);
                break;
            }

        }

        Index += hs.len;

    } while (Index < 512);

    if (Rel == 0)
        return 0;

    Address = (ULONG_PTR)ptrCode + Index + hs.len + Rel;
    Address = NtOsBase + Address - (ULONG_PTR)hNtOs;

    if (!kdAddressInNtOsImage((PVOID)Address))
        return 0;

    return Address;
}

/*
* FindKeBugCheckCallbackHead
*
* Purpose:
*
* Return address of list head for callbacks registered with:
*
*   KeRegisterBugCheckCallback
*
*/
ULONG_PTR FindKeBugCheckCallbackHead(
    VOID)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR Address = 0;
    PBYTE ptrCode;
    hde64s hs;

    ULONG_PTR NtOsBase = (ULONG_PTR)g_kdctx.NtOsBase;
    HMODULE hNtOs = (HMODULE)g_kdctx.NtOsImageMap;

    ptrCode = (PBYTE)GetProcAddress(hNtOs, "KeRegisterBugCheckCallback");
    if (ptrCode == NULL)
        return 0;

    Index = 0;
    Rel = 0;

    do {
        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 7) { //check if lea + mov

            if (((ptrCode[Index] == 0x48) || (ptrCode[Index] == 0x4C)) &&
                (ptrCode[Index + 1] == 0x8D) &&
                (ptrCode[Index + hs.len] == 0x48))
            {
                Rel = *(PLONG)(ptrCode + Index + 3);
                break;
            }

        }

        Index += hs.len;

    } while (Index < 512);

    if (Rel == 0)
        return 0;

    Address = (ULONG_PTR)ptrCode + Index + hs.len + Rel;
    Address = NtOsBase + Address - (ULONG_PTR)hNtOs;

    if (!kdAddressInNtOsImage((PVOID)Address))
        return 0;

    return Address;
}

/*
* FindPspLoadImageNotifyRoutine
*
* Purpose:
*
* Return array address of callbacks registered with:
*
*   PsSetLoadImageNotifyRoutine
*   PsSetLoadImageNotifyRoutineEx
*
*/
ULONG_PTR FindPspLoadImageNotifyRoutine(
    VOID)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR Address = 0;
    PBYTE ptrCode;
    hde64s hs;

    ULONG_PTR NtOsBase = (ULONG_PTR)g_kdctx.NtOsBase;
    HMODULE hNtOs = (HMODULE)g_kdctx.NtOsImageMap;

    ptrCode = (PBYTE)GetProcAddress(hNtOs, "PsRemoveLoadImageNotifyRoutine");
    if (ptrCode == NULL)
        return 0;

    Index = 0;
    Rel = 0;

    do {
        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 7) { //check if lea

            if (((ptrCode[Index] == 0x48) || (ptrCode[Index] == 0x4C)) &&
                (ptrCode[Index + 1] == 0x8D))
            {
                Rel = *(PLONG)(ptrCode + Index + 3);
                break;
            }

        }

        Index += hs.len;

    } while (Index < 128);

    if (Rel == 0)
        return 0;

    Address = (ULONG_PTR)ptrCode + Index + hs.len + Rel;
    Address = NtOsBase + Address - (ULONG_PTR)hNtOs;

    if (!kdAddressInNtOsImage((PVOID)Address))
        return 0;

    return Address;
}

/*
* FindPspCreateThreadNotifyRoutine
*
* Purpose:
*
* Return array address of callbacks registered with:
*
*   PsSetCreateThreadNotifyRoutine
*   PsSetCreateThreadNotifyRoutineEx
*
*/
ULONG_PTR FindPspCreateThreadNotifyRoutine(
    VOID)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR Address = 0;
    PBYTE ptrCode;
    hde64s hs;

    ULONG_PTR NtOsBase = (ULONG_PTR)g_kdctx.NtOsBase;
    HMODULE hNtOs = (HMODULE)g_kdctx.NtOsImageMap;

    ptrCode = (PBYTE)GetProcAddress(hNtOs, "PsRemoveCreateThreadNotifyRoutine");
    if (ptrCode == NULL)
        return 0;

    Index = 0;
    Rel = 0;

    do {
        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 7) { //check if lea

            if (((ptrCode[Index] == 0x48) || (ptrCode[Index] == 0x4C)) &&
                (ptrCode[Index + 1] == 0x8D))
            {
                Rel = *(PLONG)(ptrCode + Index + 3);
                break;
            }

        }

        Index += hs.len;

    } while (Index < 128);

    if (Rel == 0)
        return 0;

    Address = (ULONG_PTR)ptrCode + Index + hs.len + Rel;
    Address = NtOsBase + Address - (ULONG_PTR)hNtOs;

    if (!kdAddressInNtOsImage((PVOID)Address))
        return 0;

    return Address;
}

/*
* FindPspCreateProcessNotifyRoutine
*
* Purpose:
*
* Return array address of callbacks registered with:
*
*   PsSetCreateProcessNotifyRoutine
*   PsSetCreateProcessNotifyRoutineEx
*   PsSetCreateProcessNotifyRoutineEx2
*
*/
ULONG_PTR FindPspCreateProcessNotifyRoutine(
    VOID)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR Address = 0;
    PBYTE ptrCode;
    hde64s hs;

    ULONG_PTR NtOsBase = (ULONG_PTR)g_kdctx.NtOsBase;
    HMODULE hNtOs = (HMODULE)g_kdctx.NtOsImageMap;

    ptrCode = (PBYTE)GetProcAddress(hNtOs, "PsSetCreateProcessNotifyRoutine");
    if (ptrCode == NULL)
        return 0;

    //
    // Find PspSetCreateProcessNotifyRoutine pointer.
    //
    Index = 0;
    do {

        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        //jmp/call PspSetCreateProcessNotifyRoutine
        if ((ptrCode[Index] == 0xE9) ||
            (ptrCode[Index] == 0xE8) ||
            (ptrCode[Index] == 0xEB))
        {
            Rel = *(PLONG)(ptrCode + Index + 1);
            break;
        }

        Index += hs.len;

    } while (Index < 64);

    if (Rel == 0)
        return 0;

    ptrCode = ptrCode + Index + (hs.len) + Rel;
    Index = 0;
    Rel = 0;

    do {
        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 7) { //check if lea

            if ((ptrCode[Index] == 0x4C) &&
                (ptrCode[Index + 1] == 0x8D))
            {
                Rel = *(PLONG)(ptrCode + Index + 3);
                break;
            }

        }

        Index += hs.len;

    } while (Index < 128);

    if (Rel == 0)
        return 0;

    Address = (ULONG_PTR)ptrCode + Index + hs.len + Rel;
    Address = NtOsBase + Address - (ULONG_PTR)hNtOs;

    if (!kdAddressInNtOsImage((PVOID)Address))
        return 0;

    return Address;
}

/*
* AddRootEntryToList
*
* Purpose:
*
* Adds callback root entry to the treelist.
*
*/
HTREEITEM AddRootEntryToList(
    _In_ HWND TreeList,
    _In_ LPWSTR lpCallbackType
)
{
    return TreeListAddItem(
        TreeList,
        NULL,
        TVIF_TEXT | TVIF_STATE,
        (UINT)0,
        (UINT)0,
        lpCallbackType,
        NULL);
}

/*
* AddEntryToList
*
* Purpose:
*
* Adds callback entry to the treelist.
*
*/
VOID AddEntryToList(
    _In_ HWND TreeList,
    _In_ HTREEITEM RootItem,
    _In_ ULONG_PTR Function,
    _In_opt_ LPWSTR lpAdditionalInfo,
    _In_ PRTL_PROCESS_MODULES Modules
)
{
    INT ModuleIndex;
    TL_SUBITEMS_FIXED TreeListSubItems;
    WCHAR szAddress[32];
    WCHAR szBuffer[MAX_PATH + 1];

    RtlSecureZeroMemory(&TreeListSubItems, sizeof(TreeListSubItems));
    TreeListSubItems.Count = 2;

    szAddress[0] = L'0';
    szAddress[1] = L'x';
    szAddress[2] = 0;
    u64tohex(Function, &szAddress[2]);
    TreeListSubItems.Text[0] = szAddress;

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

    ModuleIndex = supFindModuleEntryByAddress(Modules, (PVOID)Function);
    if (ModuleIndex == (ULONG)-1) {
        _strcpy(szBuffer, TEXT("Unknown Module"));
    }
    else {

        MultiByteToWideChar(
            CP_ACP,
            0,
            (LPCSTR)&Modules->Modules[ModuleIndex].FullPathName,
            (INT)_strlen_a((char*)Modules->Modules[ModuleIndex].FullPathName),
            szBuffer,
            MAX_PATH);
    }

    TreeListSubItems.Text[0] = szBuffer;
    TreeListSubItems.Text[1] = lpAdditionalInfo;

    TreeListAddItem(
        TreeList,
        RootItem,
        TVIF_TEXT | TVIF_STATE,
        (UINT)0,
        (UINT)0,
        szAddress,
        &TreeListSubItems);
}

/*
* DumpPsCallbacks
*
* Purpose:
*
* Read Psp* callback data from kernel and send it to output window.
*
*/
VOID DumpPsCallbacks(
    _In_ HWND TreeList,
    _In_ LPWSTR lpCallbackType,
    _In_ ULONG_PTR RoutinesArrayAddress,
    _In_ PRTL_PROCESS_MODULES Modules
)
{
    ULONG c;
    ULONG_PTR Address, Function;
    EX_FAST_REF Callbacks[PspNotifyRoutinesLimit];

    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, lpCallbackType);
    if (RootItem == 0)
        return;

    RtlSecureZeroMemory(Callbacks, sizeof(Callbacks));
    if (kdReadSystemMemory(RoutinesArrayAddress,
        &Callbacks, sizeof(Callbacks)))
    {

        for (c = 0; c < PspNotifyRoutinesLimit; c++) {

            if (Callbacks[c].Value) {

                Address = (ULONG_PTR)ObGetObjectFastReference(Callbacks[c]);
                Function = (ULONG_PTR)ObGetCallbackBlockRoutine((PVOID)Address);
                if (Function < g_kdctx.SystemRangeStart)
                    continue;

                AddEntryToList(TreeList,
                    RootItem,
                    Function,
                    NULL,
                    Modules);
            }
        }
    }

}

/*
* DumpKeBugCheckCallbacks
*
* Purpose:
*
* Read KeBugCheck callback data from kernel and send it to output window.
*
*/
VOID DumpKeBugCheckCallbacks(
    _In_ HWND TreeList,
    _In_ LPWSTR lpCallbackType,
    _In_ ULONG_PTR ListHead,
    _In_ PRTL_PROCESS_MODULES Modules
)
{
    LIST_ENTRY ListEntry;

    KBUGCHECK_CALLBACK_RECORD CallbackRecord;

    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, lpCallbackType);
    if (RootItem == 0)
        return;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemoryEx(
        ListHead,
        &ListEntry,
        sizeof(LIST_ENTRY),
        NULL))
    {
        return;
    }

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {

        RtlSecureZeroMemory(&CallbackRecord, sizeof(CallbackRecord));

        if (!kdReadSystemMemoryEx((ULONG_PTR)ListEntry.Flink,
            &CallbackRecord,
            sizeof(CallbackRecord),
            NULL))
        {
            break;
        }

        AddEntryToList(TreeList,
            RootItem,
            (ULONG_PTR)CallbackRecord.CallbackRoutine,
            NULL,
            Modules);

        ListEntry.Flink = CallbackRecord.Entry.Flink;
    }

}

/*
* KeBugCheckReasonToString
*
* Purpose:
*
* Return Reason as text constant.
*
*/
LPWSTR KeBugCheckReasonToString(
    _In_ KBUGCHECK_CALLBACK_REASON Reason)
{
    switch (Reason) {
    case KbCallbackInvalid:
        return TEXT("KbCallbackInvalid");

    case KbCallbackReserved1:
        return TEXT("KbCallbackReserved1");

    case KbCallbackSecondaryDumpData:
        return TEXT("KbCallbackSecondaryDumpData");

    case KbCallbackDumpIo:
        return TEXT("KbCallbackDumpIo");

    case KbCallbackAddPages:
        return TEXT("KbCallbackAddPages");

    case KbCallbackSecondaryMultiPartDumpData:
        return TEXT("KbCallbackSecondaryMultiPartDumpData");

    case KbCallbackRemovePages:
        return TEXT("KbCallbackRemovePages");
    case KbCallbackTriageDumpData:
        return TEXT("KbCallbackTriageDumpData");

    }
    return NULL;
}

/*
* DumpKeBugCheckReasonCallbacks
*
* Purpose:
*
* Read KeBugCheckReason callback data from kernel and send it to output window.
*
*/
VOID DumpKeBugCheckReasonCallbacks(
    _In_ HWND TreeList,
    _In_ LPWSTR lpCallbackType,
    _In_ ULONG_PTR ListHead,
    _In_ PRTL_PROCESS_MODULES Modules
)
{
    LIST_ENTRY ListEntry;

    KBUGCHECK_REASON_CALLBACK_RECORD CallbackRecord;

    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, lpCallbackType);
    if (RootItem == 0)
        return;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemoryEx(
        ListHead,
        &ListEntry,
        sizeof(LIST_ENTRY),
        NULL))
    {
        return;
    }

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {

        RtlSecureZeroMemory(&CallbackRecord, sizeof(CallbackRecord));

        if (!kdReadSystemMemoryEx((ULONG_PTR)ListEntry.Flink,
            &CallbackRecord,
            sizeof(CallbackRecord),
            NULL))
        {
            break;
        }

        AddEntryToList(TreeList,
            RootItem,
            (ULONG_PTR)CallbackRecord.CallbackRoutine,
            KeBugCheckReasonToString(CallbackRecord.Reason),
            Modules);

        ListEntry.Flink = CallbackRecord.Entry.Flink;
    }

}

/*
* DumpCmCallbacks
*
* Purpose:
*
* Read Cm Registry callback data from kernel and send it to output window.
*
*/
VOID DumpCmCallbacks(
    _In_ HWND TreeList,
    _In_ LPWSTR lpCallbackType,
    _In_ ULONG_PTR ListHead,
    _In_ PRTL_PROCESS_MODULES Modules
)
{
    LIST_ENTRY ListEntry;

    CM_CALLBACK_CONTEXT_BLOCK CallbackRecord;

    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, lpCallbackType);
    if (RootItem == 0)
        return;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemoryEx(
        ListHead,
        &ListEntry,
        sizeof(LIST_ENTRY),
        NULL))
    {
        return;
    }

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {

        RtlSecureZeroMemory(&CallbackRecord, sizeof(CallbackRecord));

        if (!kdReadSystemMemoryEx((ULONG_PTR)ListEntry.Flink,
            &CallbackRecord,
            sizeof(CallbackRecord),
            NULL))
        {
            break;
        }

        AddEntryToList(TreeList,
            RootItem,
            (ULONG_PTR)CallbackRecord.Function,
            NULL,
            Modules);

        ListEntry.Flink = CallbackRecord.CallbackListEntry.Flink;
    }

}

/*
* DumpIoCallbacks
*
* Purpose:
*
* Read Io related callback data from kernel and send it to output window.
*
*/
VOID DumpIoCallbacks(
    _In_ HWND TreeList,
    _In_ LPWSTR lpCallbackType,
    _In_ ULONG_PTR ListHead,
    _In_ PRTL_PROCESS_MODULES Modules
)
{
    LIST_ENTRY ListEntry;

    SHUTDOWN_PACKET EntryPacket;

    DEVICE_OBJECT DeviceObject;

    DRIVER_OBJECT DriverObject;

    PVOID Routine;
    LPWSTR lpDescription;

    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, lpCallbackType);
    if (RootItem == 0)
        return;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemoryEx(
        ListHead,
        &ListEntry,
        sizeof(LIST_ENTRY),
        NULL))
    {
        return;
    }

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {

        RtlSecureZeroMemory(&EntryPacket, sizeof(EntryPacket));

        if (!kdReadSystemMemoryEx((ULONG_PTR)ListEntry.Flink,
            &EntryPacket,
            sizeof(EntryPacket),
            NULL))
        {
            break;
        }

        Routine = EntryPacket.DeviceObject;
        lpDescription = TEXT("PDEVICE_OBJECT");

        //
        // Attempt to query owner of the device object.
        //
        if ((ULONG_PTR)EntryPacket.DeviceObject > g_kdctx.SystemRangeStart) {

            //
            // Read DEVICE_OBJECT.
            //
            RtlSecureZeroMemory(&DeviceObject, sizeof(DeviceObject));

            if (kdReadSystemMemoryEx((ULONG_PTR)EntryPacket.DeviceObject,
                (PVOID)&DeviceObject,
                sizeof(DeviceObject),
                NULL))
            {
                //
                // Read DRIVER_OBJECT.
                //
                RtlSecureZeroMemory(&DriverObject, sizeof(DriverObject));
                if (kdReadSystemMemoryEx((ULONG_PTR)DeviceObject.DriverObject,
                    (PVOID)&DriverObject,
                    sizeof(DriverObject),
                    NULL))
                {
                    Routine = DriverObject.MajorFunction[IRP_MJ_SHUTDOWN];
                    lpDescription = TEXT("IRP_MJ_SHUTDOWN");
                }
            }

        }

        AddEntryToList(TreeList,
            RootItem,
            (ULONG_PTR)Routine,
            lpDescription,
            Modules);

        ListEntry.Flink = EntryPacket.ListEntry.Flink;
    }

}

/*
* DumpObCallbacks
*
* Purpose:
*
* Read Ob callback data from kernel and send it to output window.
*
*/
VOID DumpObCallbacks(
    _In_ HWND TreeList,
    _In_ LPWSTR lpCallbackType,
    _In_ ULONG_PTR ListHead,
    _In_ PRTL_PROCESS_MODULES Modules
)
{
    BOOL bAltitudeRead, bNeedFree;

    LPWSTR lpInfoBuffer = NULL, lpType;

    SIZE_T Size, AltitudeSize = 0;

    LIST_ENTRY ListEntry;

    OB_CALLBACK_CONTEXT_BLOCK CallbackRecord;

    OB_CALLBACK_REGISTRATION Registration;

    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, lpCallbackType);
    if (RootItem == 0)
        return;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemoryEx(
        ListHead,
        &ListEntry,
        sizeof(LIST_ENTRY),
        NULL))
    {
        return;
    }

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {

        RtlSecureZeroMemory(&CallbackRecord, sizeof(CallbackRecord));

        if (!kdReadSystemMemoryEx((ULONG_PTR)ListEntry.Flink,
            &CallbackRecord,
            sizeof(CallbackRecord),
            NULL))
        {
            break;
        }

        //
        // Read Altitude.
        //
        bAltitudeRead = FALSE;

        RtlSecureZeroMemory(&Registration, sizeof(Registration));
        if (kdReadSystemMemoryEx((ULONG_PTR)CallbackRecord.Registration,
            (PVOID)&Registration,
            sizeof(Registration),
            NULL))
        {
            AltitudeSize = 8 + Registration.Altitude.Length;
            lpInfoBuffer = (LPWSTR)supHeapAlloc(AltitudeSize);
            if (lpInfoBuffer) {

                bAltitudeRead = kdReadSystemMemoryEx((ULONG_PTR)Registration.Altitude.Buffer,
                    (PVOID)lpInfoBuffer,
                    Registration.Altitude.Length,
                    NULL);
            }
        }

        //
        // Output PreCallback.
        //
        if ((ULONG_PTR)CallbackRecord.PreCallback > g_kdctx.SystemRangeStart) {

            bNeedFree = FALSE;

            if (bAltitudeRead) {
                Size = AltitudeSize + MAX_PATH;
                lpType = (LPWSTR)supHeapAlloc(Size);
                if (lpType) {
                    _strcpy(lpType, TEXT("PreCallback, Altitude: "));
                    _strcat(lpType, lpInfoBuffer);
                    bNeedFree = TRUE;
                }
            }
            else
                lpType = TEXT("PreCallback");

            AddEntryToList(TreeList,
                RootItem,
                (ULONG_PTR)CallbackRecord.PreCallback,
                lpType,
                Modules);

            if (bNeedFree) supHeapFree(lpType);
        }

        //
        // Output PostCallback.
        //
        if ((ULONG_PTR)CallbackRecord.PostCallback > g_kdctx.SystemRangeStart) {

            bNeedFree = FALSE;

            if (bAltitudeRead) {
                Size = AltitudeSize + MAX_PATH;
                lpType = (LPWSTR)supHeapAlloc(Size);
                if (lpType) {
                    _strcpy(lpType, TEXT("PostCallback, Altitude: "));
                    _strcat(lpType, lpInfoBuffer);
                    bNeedFree = TRUE;
                }
            }
            else
                lpType = TEXT("PostCallback");

            AddEntryToList(TreeList,
                RootItem,
                (ULONG_PTR)CallbackRecord.PostCallback,
                lpType,
                Modules);

            if (bNeedFree) supHeapFree(lpType);
        }
        ListEntry.Flink = CallbackRecord.CallbackListEntry.Flink;

        if (lpInfoBuffer) supHeapFree(lpInfoBuffer);
    }

}

/*
* DumpSeCallbacks
*
* Purpose:
*
* Read Se related callback data from kernel and send it to output window.
*
*/
VOID DumpSeCallbacks(
    _In_ HWND TreeList,
    _In_ LPWSTR lpCallbackType,
    _In_ ULONG_PTR EntryHead,
    _In_ PRTL_PROCESS_MODULES Modules
)
{
    ULONG_PTR Next;

    SEP_LOGON_SESSION_TERMINATED_NOTIFICATION SeEntry; // This structure is different for Ex variant but 
                                                       // key callback function field is on the same offset.

    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, lpCallbackType);
    if (RootItem == 0)
        return;

    //
    // Read head.
    //
    RtlSecureZeroMemory(&SeEntry, sizeof(SeEntry));

    if (!kdReadSystemMemoryEx(EntryHead,
        (PVOID)&SeEntry,
        sizeof(SeEntry),
        NULL))
    {
        return;
    }

    //
    // Walk each entry in single linked list.
    //
    Next = (ULONG_PTR)SeEntry.Next;
    while (Next) {

        RtlSecureZeroMemory(&SeEntry, sizeof(SeEntry));

        if (!kdReadSystemMemoryEx(Next,
            (PVOID)&SeEntry,
            sizeof(SeEntry),
            NULL))
        {
            break;
        }

        AddEntryToList(TreeList,
            RootItem,
            (ULONG_PTR)SeEntry.CallbackRoutine,
            NULL,
            Modules);

        Next = (ULONG_PTR)SeEntry.Next;

    }

}

/*
* DumpPoCallbacks
*
* Purpose:
*
* Read Po callback data from kernel and send it to output window.
*
*/
VOID DumpPoCallbacks(
    _In_ HWND TreeList,
    _In_ LPWSTR lpCallbackType,
    _In_ ULONG_PTR ListHead,
    _In_ PRTL_PROCESS_MODULES Modules
)
{
    LIST_ENTRY ListEntry;

    union {
        union {
            POP_POWER_SETTING_REGISTRATION_V1 *v1;
            POP_POWER_SETTING_REGISTRATION_V2 *v2;
        } Versions;
        PBYTE Ref;
    } CallbackData;

    ULONG ReadSize;
    SIZE_T BufferSize;
    LPWSTR GuidString;
    PVOID Buffer = NULL;
    PVOID CallbackRoutine = NULL;

    GUID EntryGuid;
    UNICODE_STRING ConvertedGuid;

    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, lpCallbackType);
    if (RootItem == 0)
        return;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Determinate size of structure to read.
    //
    ReadSize = sizeof(POP_POWER_SETTING_REGISTRATION_V1);
    if (g_NtBuildNumber >= 14393)
        ReadSize = sizeof(POP_POWER_SETTING_REGISTRATION_V2);

    __try {

        //
        // Allocate read buffer with enough size.
        // 

        BufferSize = sizeof(POP_POWER_SETTING_REGISTRATION_V1) + sizeof(POP_POWER_SETTING_REGISTRATION_V2);
        Buffer = supHeapAlloc(BufferSize);
        if (Buffer == NULL)
            __leave;

        CallbackData.Ref = (PBYTE)Buffer;

        //
        // Read head.
        //
        if (!kdReadSystemMemoryEx(
            ListHead,
            &ListEntry,
            sizeof(LIST_ENTRY),
            NULL))
        {
            __leave;
        }

        //
        // Walk list entries.
        //
        while ((ULONG_PTR)ListEntry.Flink != ListHead) {

            RtlSecureZeroMemory(Buffer, BufferSize);

            if (!kdReadSystemMemoryEx((ULONG_PTR)ListEntry.Flink,
                Buffer,
                ReadSize,
                NULL))
            {
                break;
            }

            //
            // Is valid registration entry?
            //
            if (CallbackData.Versions.v1->Tag != PO_POWER_SETTINGS_REGISTRATION_TAG)
                break;

            if (ReadSize == sizeof(POP_POWER_SETTING_REGISTRATION_V2)) {
                CallbackRoutine = CallbackData.Versions.v2->Callback;
                EntryGuid = CallbackData.Versions.v2->Guid;
            }
            else {
                CallbackRoutine = CallbackData.Versions.v1->Callback;
                EntryGuid = CallbackData.Versions.v1->Guid;
            }

            if (CallbackRoutine) {

                if (NT_SUCCESS(RtlStringFromGUID(&EntryGuid, &ConvertedGuid)))
                    GuidString = ConvertedGuid.Buffer;
                else
                    GuidString = NULL;

                AddEntryToList(TreeList,
                    RootItem,
                    (ULONG_PTR)CallbackRoutine,
                    GuidString,
                    Modules);

                if (GuidString)
                    RtlFreeUnicodeString(&ConvertedGuid);

            }

            //
            // Next item address, ListEntry offset version independent.
            //
            ListEntry.Flink = CallbackData.Versions.v1->Link.Flink;
        }

    }
    __finally {
        if (Buffer) supHeapFree(Buffer);
    }
}

/*
* DumpDbgPrintCallbacks
*
* Purpose:
*
* Read Dbg callback data from kernel and send it to output window.
*
*/
VOID DumpDbgPrintCallbacks(
    _In_ HWND TreeList,
    _In_ LPWSTR lpCallbackType,
    _In_ ULONG_PTR ListHead,
    _In_ PRTL_PROCESS_MODULES Modules
)
{
    ULONG_PTR RecordAddress;

    LIST_ENTRY ListEntry;

    RTL_CALLBACK_REGISTER CallbackRecord;

    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, lpCallbackType);
    if (RootItem == 0)
        return;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemoryEx(
        ListHead,
        &ListEntry,
        sizeof(ListEntry),
        NULL))
    {
        return;
    }

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {

        RtlSecureZeroMemory(&CallbackRecord, sizeof(CallbackRecord));

        RecordAddress = (ULONG_PTR)ListEntry.Flink - FIELD_OFFSET(RTL_CALLBACK_REGISTER, ListEntry);

        if (!kdReadSystemMemoryEx((ULONG_PTR)RecordAddress,
            &CallbackRecord,
            sizeof(CallbackRecord),
            NULL))
        {
            break;
        }

        if (CallbackRecord.DebugPrintCallback) {

            AddEntryToList(TreeList,
                RootItem,
                (ULONG_PTR)CallbackRecord.DebugPrintCallback,
                NULL,
                Modules);

        }
        ListEntry.Flink = CallbackRecord.ListEntry.Flink;
    }

}

/*
* DumpIoFsRegistrationCallbacks
*
* Purpose:
*
* Read Io File System registration related callback data from kernel and send it to output window.
*
*/
VOID DumpIoFsRegistrationCallbacks(
    _In_ HWND TreeList,
    _In_ LPWSTR lpCallbackType,
    _In_ ULONG_PTR ListHead,
    _In_ PRTL_PROCESS_MODULES Modules
)
{
    LIST_ENTRY ListEntry;

    NOTIFICATION_PACKET CallbackRecord;

    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, lpCallbackType);
    if (RootItem == 0)
        return;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemoryEx(
        ListHead,
        &ListEntry,
        sizeof(LIST_ENTRY),
        NULL))
    {
        return;
    }

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {

        RtlSecureZeroMemory(&CallbackRecord, sizeof(CallbackRecord));

        if (!kdReadSystemMemoryEx((ULONG_PTR)ListEntry.Flink,
            &CallbackRecord,
            sizeof(CallbackRecord),
            NULL))
        {
            break;
        }

        if (CallbackRecord.NotificationRoutine) {

            AddEntryToList(TreeList,
                RootItem,
                (ULONG_PTR)CallbackRecord.NotificationRoutine,
                NULL,
                Modules);

        }

        ListEntry.Flink = CallbackRecord.ListEntry.Flink;
    }

}

/*
* DumpIoFileSystemCallbacks
*
* Purpose:
*
* Read Io File System related callback data from kernel and send it to output window.
*
*/
VOID DumpIoFileSystemCallbacks(
    _In_ HWND TreeList,
    _In_ LPWSTR lpCallbackType,
    _In_ ULONG_PTR ListHead,
    _In_ PRTL_PROCESS_MODULES Modules
)
{
    BOOL bNeedFree;

    LIST_ENTRY ListEntry, NextEntry;

    ULONG_PTR DeviceObjectAddress = 0, BaseAddress = 0;

    DEVICE_OBJECT DeviceObject;

    DRIVER_OBJECT DriverObject;

    LPWSTR lpType;

    HTREEITEM RootItem;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, lpCallbackType);
    if (RootItem == 0)
        return;

    ListEntry.Flink = ListEntry.Blink = NULL;

    //
    // Read head.
    //
    if (!kdReadSystemMemoryEx(
        ListHead,
        &ListEntry,
        sizeof(LIST_ENTRY),
        NULL))
    {
        return;
    }

    //
    // Walk list entries.
    //
    while ((ULONG_PTR)ListEntry.Flink != ListHead) {

        RtlSecureZeroMemory(&DeviceObject, sizeof(DeviceObject));

        DeviceObjectAddress = (ULONG_PTR)ListEntry.Flink - FIELD_OFFSET(DEVICE_OBJECT, Queue);

        //
        // Read DEVICE_OBJECT.
        //
        if (!kdReadSystemMemoryEx(DeviceObjectAddress,
            &DeviceObject,
            sizeof(DeviceObject),
            NULL))
        {
            break;
        }

        //
        // Additional info column default text.
        //
        lpType = TEXT("PDEVICE_OBJECT");
        BaseAddress = DeviceObjectAddress;
        bNeedFree = FALSE;

        //
        // Read DRIVER_OBJECT.
        //
        RtlSecureZeroMemory(&DriverObject, sizeof(DriverObject));
        if (kdReadSystemMemoryEx((ULONG_PTR)DeviceObject.DriverObject,
            &DriverObject,
            sizeof(DriverObject),
            NULL))
        {
            //
            // Determinate address to display.
            //
            BaseAddress = (ULONG_PTR)DriverObject.DriverInit;
            if (BaseAddress == 0) {
                BaseAddress = (ULONG_PTR)DriverObject.DriverStart;
            }

            lpType = NULL;

            //
            // Read DRIVER_OBJECT name.
            //
            if (DriverObject.DriverName.Length &&
                DriverObject.DriverName.MaximumLength &&
                DriverObject.DriverName.Buffer)
            {
                lpType = (LPWSTR)supHeapAlloc((SIZE_T)DriverObject.DriverName.Length + sizeof(UNICODE_NULL));
                if (lpType) {
                    bNeedFree = TRUE;
                    if (!kdReadSystemMemoryEx((ULONG_PTR)DriverObject.DriverName.Buffer,
                        lpType,
                        (ULONG)DriverObject.DriverName.Length,
                        NULL))
                    {
                        supHeapFree(lpType);
                        lpType = NULL;
                        bNeedFree = FALSE;
                    }
                }
            }
        }

        AddEntryToList(TreeList,
            RootItem,
            BaseAddress,
            lpType, //PDEVICE_OBJECT or DRIVER_OBJECT.DriverName
            Modules);

        if (bNeedFree)
            supHeapFree(lpType);

        //
        // Next ListEntry.
        //
        NextEntry.Blink = NextEntry.Flink = NULL;

        if (!kdReadSystemMemoryEx(
            (ULONG_PTR)ListEntry.Flink,
            &NextEntry,
            sizeof(LIST_ENTRY),
            NULL))
        {
            break;
        }

        if (NextEntry.Flink == NULL)
            break;

        ListEntry.Flink = NextEntry.Flink;
    }

}

/*
* CallbacksList
*
* Purpose:
*
* Find callbacks pointers and list them to output window.
*
*/
VOID CallbacksList(
    _In_ HWND hwndDlg,
    _In_ HWND TreeList)
{
    PRTL_PROCESS_MODULES Modules;

    __try {
        //
        // Query all addresses.
        //
        if (g_NotifyCallbacks.PspCreateProcessNotifyRoutine == 0)
            g_NotifyCallbacks.PspCreateProcessNotifyRoutine = FindPspCreateProcessNotifyRoutine();

        if (g_NotifyCallbacks.PspCreateThreadNotifyRoutine == 0)
            g_NotifyCallbacks.PspCreateThreadNotifyRoutine = FindPspCreateThreadNotifyRoutine();

        if (g_NotifyCallbacks.PspLoadImageNotifyRoutine == 0)
            g_NotifyCallbacks.PspLoadImageNotifyRoutine = FindPspLoadImageNotifyRoutine();

        if (g_NotifyCallbacks.KeBugCheckCallbackHead == 0)
            g_NotifyCallbacks.KeBugCheckCallbackHead = FindKeBugCheckCallbackHead();

        if (g_NotifyCallbacks.KeBugCheckReasonCallbackHead == 0)
            g_NotifyCallbacks.KeBugCheckReasonCallbackHead = FindKeBugCheckReasonCallbackHead();

        if (g_NotifyCallbacks.IopNotifyShutdownQueueHead == 0)
            g_NotifyCallbacks.IopNotifyShutdownQueueHead = FindIopNotifyShutdownQueueHeadHead(FALSE);

        if (g_NotifyCallbacks.IopNotifyLastChanceShutdownQueueHead == 0)
            g_NotifyCallbacks.IopNotifyLastChanceShutdownQueueHead = FindIopNotifyShutdownQueueHeadHead(TRUE);

        if (g_NotifyCallbacks.CmCallbackListHead == 0)
            g_NotifyCallbacks.CmCallbackListHead = FindCmCallbackHead();

        if (g_NotifyCallbacks.ObProcessCallbackHead == 0)
            g_NotifyCallbacks.ObProcessCallbackHead = GetObjectTypeCallbackListHeadByType(0);

        if (g_NotifyCallbacks.ObThreadCallbackHead == 0)
            g_NotifyCallbacks.ObThreadCallbackHead = GetObjectTypeCallbackListHeadByType(1);

        if (g_NotifyCallbacks.ObDesktopCallbackHead == 0)
            g_NotifyCallbacks.ObDesktopCallbackHead = GetObjectTypeCallbackListHeadByType(2);

        if (g_NotifyCallbacks.SeFileSystemNotifyRoutinesHead == 0)
            g_NotifyCallbacks.SeFileSystemNotifyRoutinesHead = FindSeFileSystemNotifyRoutinesHead(FALSE);

        if (g_NotifyCallbacks.SeFileSystemNotifyRoutinesExHead == 0)
            g_NotifyCallbacks.SeFileSystemNotifyRoutinesExHead = FindSeFileSystemNotifyRoutinesHead(TRUE);

        if (g_NotifyCallbacks.PopRegisteredPowerSettingCallbacks == 0)
            g_NotifyCallbacks.PopRegisteredPowerSettingCallbacks = FindPopRegisteredPowerSettingCallbacks();

        if (g_NotifyCallbacks.RtlpDebugPrintCallbackList == 0)
            g_NotifyCallbacks.RtlpDebugPrintCallbackList = FindRtlpDebugPrintCallbackList();

        if (g_NotifyCallbacks.IopFsNotifyChangeQueueHead == 0)
            g_NotifyCallbacks.IopFsNotifyChangeQueueHead = FindIopFsNotifyChangeQueueHead();

        if ((g_NotifyCallbacks.IopCdRomFileSystemQueueHead == 0) ||
            (g_NotifyCallbacks.IopDiskFileSystemQueueHead == 0) ||
            (g_NotifyCallbacks.IopTapeFileSystemQueueHead == 0) ||
            (g_NotifyCallbacks.IopNetworkFileSystemQueueHead == 0))
        {
            if (!FindIopFileSystemQueueHeads(&g_NotifyCallbacks.IopCdRomFileSystemQueueHead,
                &g_NotifyCallbacks.IopDiskFileSystemQueueHead,
                &g_NotifyCallbacks.IopTapeFileSystemQueueHead,
                &g_NotifyCallbacks.IopNetworkFileSystemQueueHead))
            {
#ifdef _DEBUG
                OutputDebugString(TEXT("Could not locate all Iop listheads\r\n"));
#endif
            }
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        MessageBox(hwndDlg, TEXT("An exception occured during callback query"), NULL, MB_ICONERROR);
    }

    Modules = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation);
    if (Modules == NULL) {
        MessageBox(hwndDlg, TEXT("Could not allocate memory for modules list."), NULL, MB_ICONERROR);
        return;
    }

    __try {

        //
        // List process callbacks.
        //

        if (g_NotifyCallbacks.PspCreateProcessNotifyRoutine) {

            DumpPsCallbacks(TreeList,
                TEXT("CreateProcess"),
                g_NotifyCallbacks.PspCreateProcessNotifyRoutine,
                Modules);

        }

        //
        // List thread callbacks.
        //
        if (g_NotifyCallbacks.PspCreateThreadNotifyRoutine) {

            DumpPsCallbacks(TreeList,
                TEXT("CreateThread"),
                g_NotifyCallbacks.PspCreateThreadNotifyRoutine,
                Modules);

        }

        //
        // List load image callbacks.
        //
        if (g_NotifyCallbacks.PspLoadImageNotifyRoutine) {

            DumpPsCallbacks(TreeList,
                TEXT("LoadImage"),
                g_NotifyCallbacks.PspLoadImageNotifyRoutine,
                Modules);

        }

        //
        // List KeBugCheck callbacks.
        //
        if (g_NotifyCallbacks.KeBugCheckCallbackHead) {

            DumpKeBugCheckCallbacks(TreeList,
                TEXT("BugCheck"),
                g_NotifyCallbacks.KeBugCheckCallbackHead,
                Modules);

        }

        if (g_NotifyCallbacks.KeBugCheckReasonCallbackHead) {

            DumpKeBugCheckReasonCallbacks(TreeList,
                TEXT("BugCheckReason"),
                g_NotifyCallbacks.KeBugCheckReasonCallbackHead,
                Modules);

        }

        //
        // List Cm callbacks
        //
        if (g_NotifyCallbacks.CmCallbackListHead) {

            DumpCmCallbacks(TreeList,
                TEXT("CmRegistry"),
                g_NotifyCallbacks.CmCallbackListHead,
                Modules);

        }

        //
        // List Io Shutdown callbacks.
        //
        if (g_NotifyCallbacks.IopNotifyShutdownQueueHead) {

            DumpIoCallbacks(TreeList,
                TEXT("Shutdown"),
                g_NotifyCallbacks.IopNotifyShutdownQueueHead,
                Modules);

        }
        if (g_NotifyCallbacks.IopNotifyLastChanceShutdownQueueHead) {

            DumpIoCallbacks(TreeList,
                TEXT("LastChanceShutdown"),
                g_NotifyCallbacks.IopNotifyLastChanceShutdownQueueHead,
                Modules);

        }

        //
        // List Ob callbacks.
        //
        if (g_NotifyCallbacks.ObProcessCallbackHead) {

            DumpObCallbacks(TreeList,
                TEXT("ObProcess"),
                g_NotifyCallbacks.ObProcessCallbackHead,
                Modules);

        }
        if (g_NotifyCallbacks.ObThreadCallbackHead) {

            DumpObCallbacks(TreeList,
                TEXT("ObThread"),
                g_NotifyCallbacks.ObThreadCallbackHead,
                Modules);

        }
        if (g_NotifyCallbacks.ObDesktopCallbackHead) {

            DumpObCallbacks(TreeList,
                TEXT("ObDesktop"),
                g_NotifyCallbacks.ObDesktopCallbackHead,
                Modules);

        }

        //
        // List Se callbacks.
        //
        if (g_NotifyCallbacks.SeFileSystemNotifyRoutinesHead) {

            DumpSeCallbacks(TreeList,
                TEXT("SeFileSystem"),
                g_NotifyCallbacks.SeFileSystemNotifyRoutinesHead,
                Modules);

        }
        if (g_NotifyCallbacks.SeFileSystemNotifyRoutinesExHead) {

            DumpSeCallbacks(TreeList,
                TEXT("SeFileSystemEx"),
                g_NotifyCallbacks.SeFileSystemNotifyRoutinesExHead,
                Modules);

        }

        //
        // List Po callbacks.
        //
        if (g_NotifyCallbacks.PopRegisteredPowerSettingCallbacks) {

            DumpPoCallbacks(TreeList,
                TEXT("PowerSettings"),
                g_NotifyCallbacks.PopRegisteredPowerSettingCallbacks,
                Modules);

        }

        //
        // List Dbg callbacks
        //
        if (g_NotifyCallbacks.RtlpDebugPrintCallbackList) {

            DumpDbgPrintCallbacks(TreeList,
                TEXT("DbgPrint"),
                g_NotifyCallbacks.RtlpDebugPrintCallbackList,
                Modules);

        }

        //
        // List IoFsRegistration callbacks
        //
        if (g_NotifyCallbacks.IopFsNotifyChangeQueueHead) {

            DumpIoFsRegistrationCallbacks(TreeList,
                TEXT("IoFsRegistration"),
                g_NotifyCallbacks.IopFsNotifyChangeQueueHead,
                Modules);

        }

        //
        // List Io File System callbacks
        //
        if (g_NotifyCallbacks.IopDiskFileSystemQueueHead) {

            DumpIoFileSystemCallbacks(TreeList,
                TEXT("IoDiskFs"),
                g_NotifyCallbacks.IopDiskFileSystemQueueHead,
                Modules);
        }
        if (g_NotifyCallbacks.IopCdRomFileSystemQueueHead) {

            DumpIoFileSystemCallbacks(TreeList,
                TEXT("IoCdRomFs"),
                g_NotifyCallbacks.IopCdRomFileSystemQueueHead,
                Modules);
        }
        if (g_NotifyCallbacks.IopNetworkFileSystemQueueHead) {

            DumpIoFileSystemCallbacks(TreeList,
                TEXT("IoNetworkFs"),
                g_NotifyCallbacks.IopNetworkFileSystemQueueHead,
                Modules);
        }
        if (g_NotifyCallbacks.IopTapeFileSystemQueueHead) {

            DumpIoFileSystemCallbacks(TreeList,
                TEXT("IoTapeFs"),
                g_NotifyCallbacks.IopTapeFileSystemQueueHead,
                Modules);
        }

    }
    __finally {
        supHeapFree(Modules);
    }
}

/*
* CallbacksDialogHandlePopupMenu
*
* Purpose:
*
* Callback treelist popup construction
*
*/
VOID CallbacksDialogHandlePopupMenu(
    _In_ HWND hwndDlg
)
{
    POINT pt1;
    HMENU hMenu;

    if (GetCursorPos(&pt1) == FALSE)
        return;

    hMenu = CreatePopupMenu();
    if (hMenu) {
        InsertMenu(hMenu, 0, MF_BYCOMMAND, ID_OBJECT_COPY, T_COPYADDRESS);
        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, pt1.x, pt1.y, 0, hwndDlg, NULL);
        DestroyMenu(hMenu);
    }
}

/*
* CallbacksDialogResize
*
* Purpose:
*
* WM_SIZE handler.
*
*/
INT_PTR CallbacksDialogResize(
    _In_ HWND hwndDlg,
    _In_ HWND hwndSizeGrip,
    _In_ HWND hwndTreeList
)
{
    RECT r1;
    INT  cy;

    RtlSecureZeroMemory(&r1, sizeof(r1));

    GetClientRect(hwndDlg, &r1);

    cy = r1.bottom - 24;
    if (hwndSizeGrip)
        cy -= GRIPPER_SIZE;

    SetWindowPos(hwndTreeList, 0, 0, 0,
        r1.right - 24,
        cy,
        SWP_NOMOVE | SWP_NOZORDER);

    if (hwndSizeGrip)
        supSzGripWindowOnResize(hwndDlg, hwndSizeGrip);

    return 1;
}

/*
* CallbacksDialogCopyAddress
*
* Purpose:
*
* Copy selected treelist item first column to clipboard.
*
*/
VOID CallbacksDialogCopyAddress(
    _In_ HWND TreeList
)
{
    TVITEMEX    itemex;
    WCHAR       szText[MAX_PATH + 1];

    szText[0] = 0;
    RtlSecureZeroMemory(&itemex, sizeof(itemex));
    itemex.mask = TVIF_TEXT;
    itemex.hItem = TreeList_GetSelection(TreeList);
    itemex.pszText = szText;
    itemex.cchTextMax = MAX_PATH;

    if (TreeList_GetTreeItem(TreeList, &itemex, NULL)) {
        supClipboardCopy(szText, sizeof(szText));
    }
}

/*
* CallbacksDialogProc
*
* Purpose:
*
* Callbacks Dialog window procedure.
*
*/
INT_PTR CALLBACK CallbacksDialogProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam
)
{
    EXTRASCONTEXT *pDlgContext;

    switch (uMsg) {

    case WM_INITDIALOG:
        SetProp(hwndDlg, T_DLGCONTEXT, (HANDLE)lParam);
        supCenterWindow(hwndDlg);
        break;

    case WM_GETMINMAXINFO:
        if (lParam) {
            ((PMINMAXINFO)lParam)->ptMinTrackSize.x = 640;
            ((PMINMAXINFO)lParam)->ptMinTrackSize.y = 480;
        }
        break;

    case WM_SIZE:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            CallbacksDialogResize(hwndDlg, pDlgContext->SizeGrip, pDlgContext->TreeList);
        }
        break;

    case WM_CLOSE:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            if (pDlgContext->SizeGrip) DestroyWindow(pDlgContext->SizeGrip);

            g_WinObj.AuxDialogs[wobjCallbacksDlgId] = NULL;

            supHeapFree(pDlgContext);
        }
        return DestroyWindow(hwndDlg);

    case WM_COMMAND:

        switch (LOWORD(wParam)) {
        case IDCANCEL:
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            return TRUE;
        case ID_OBJECT_COPY:
            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
            if (pDlgContext) {
                CallbacksDialogCopyAddress(pDlgContext->TreeList);
            }
            break;
        default:
            break;
        }
        break;

    case WM_DESTROY:
        RemoveProp(hwndDlg, T_DLGCONTEXT);
        break;

    case WM_CONTEXTMENU:
        CallbacksDialogHandlePopupMenu(hwndDlg);
        break;

    }

    return FALSE;
}

/*
* extrasCreateCallbacksDialog
*
* Purpose:
*
* Create and initialize Callbacks Dialog.
*
*/
VOID extrasCreateCallbacksDialog(
    _In_ HWND hwndParent
)
{
    HWND        hwndDlg;

    HDITEM      hdritem;
    RECT        rc;

    EXTRASCONTEXT  *pDlgContext;


    //allow only one dialog
    if (g_WinObj.AuxDialogs[wobjCallbacksDlgId]) {
        if (IsIconic(g_WinObj.AuxDialogs[wobjCallbacksDlgId]))
            ShowWindow(g_WinObj.AuxDialogs[wobjCallbacksDlgId], SW_RESTORE);
        else
            SetActiveWindow(g_WinObj.AuxDialogs[wobjCallbacksDlgId]);
        return;
    }

    pDlgContext = (EXTRASCONTEXT*)supHeapAlloc(sizeof(EXTRASCONTEXT));
    if (pDlgContext == NULL)
        return;

    hwndDlg = CreateDialogParam(
        g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_TREELIST_PLACEHOLDER),
        hwndParent,
        &CallbacksDialogProc,
        (LPARAM)pDlgContext);

    if (hwndDlg == NULL) {
        return;
    }

    pDlgContext->hwndDlg = hwndDlg;
    g_WinObj.AuxDialogs[wobjCallbacksDlgId] = hwndDlg;
    pDlgContext->SizeGrip = supCreateSzGripWindow(hwndDlg);

    extrasSetDlgIcon(hwndDlg);
    SetWindowText(hwndDlg, TEXT("Notification Callbacks"));

    GetClientRect(hwndParent, &rc);
    g_CbTreeListAtom = InitializeTreeListControl();
    pDlgContext->TreeList = CreateWindowEx(WS_EX_CLIENTEDGE, WC_TREELIST, NULL,
        WS_VISIBLE | WS_CHILD | WS_TABSTOP | TLSTYLE_COLAUTOEXPAND, 12, 14,
        rc.right - 24, rc.bottom - 24, hwndDlg, NULL, NULL, NULL);

    if (pDlgContext->TreeList) {
        RtlSecureZeroMemory(&hdritem, sizeof(hdritem));
        hdritem.mask = HDI_FORMAT | HDI_TEXT | HDI_WIDTH;
        hdritem.fmt = HDF_LEFT | HDF_BITMAP_ON_RIGHT | HDF_STRING;
        hdritem.cxy = 150;
        hdritem.pszText = TEXT("Routine Address");
        TreeList_InsertHeaderItem(pDlgContext->TreeList, 0, &hdritem);

        hdritem.cxy = 300;
        hdritem.pszText = TEXT("Module");
        TreeList_InsertHeaderItem(pDlgContext->TreeList, 1, &hdritem);

        hdritem.cxy = 200;
        hdritem.pszText = TEXT("Additional Information");
        TreeList_InsertHeaderItem(pDlgContext->TreeList, 2, &hdritem);

        CallbacksList(hwndDlg, pDlgContext->TreeList);
    }

    SendMessage(hwndDlg, WM_SIZE, 0, 0);
}
