/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2019
*
*  TITLE:       EXTRASCALLBACKS.C
*
*  VERSION:     1.80
*
*  DATE:        08 Aug 2019
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

ULONG g_CallbacksCount;

//
// All available names for CiCallbacks. Unknown is expected to be XBOX callback.
//
#define CI_CALLBACK_NAMES_COUNT 27
static const WCHAR *CiCallbackNames[CI_CALLBACK_NAMES_COUNT] = {
    L"CiSetFileCache", //0
    L"CiGetFileCache", //1
    L"CiQueryInformation", //2
    L"CiValidateImageHeader", //3
    L"CiValidateImageData", //4
    L"CiHashMemory", //5
    L"KappxIsPackageFile", //6
    L"CiCompareSigningLevels", //7
    L"CiValidateFileAsImageType", //8
    L"CiRegisterSigningInformation", //9
    L"CiUnregisterSigningInformation",//10
    L"CiInitializePolicy",//11
    L"CiReleaseContext",//12
    L"UnknownCallback",//13 XBOX
    L"CiGetStrongImageReference", //14
    L"CiHvciSetImageBaseAddress", //15
    L"CipQueryPolicyInformation", //16
    L"CiValidateDynamicCodePages", //17
    L"CiQuerySecurityPolicy", //18
    L"CiRevalidateImage", //19
    L"CiSetInformation",//20
    L"CiSetInformationProcess", //21
    L"CiGetBuildExpiryTime", //22
    L"CiCheckProcessDebugAccessPolicy", //23
    L"SIPolicyQueryPolicyInformation",//24
    L"SIPolicyQuerySecurityPolicy",//25
    L"CiSetUnlockInformation"//26
};

#define CI_CALLBACKS_NAMES_W7_COUNT 3
static const BYTE CiCallbackIndexes_Win7[CI_CALLBACKS_NAMES_W7_COUNT] = { //Windows 7
    3,  //CiValidateImageHeader
    4,  //CiValidateImageData
    2   //CiQueryInformation
};

#define CI_CALLBACK_NAMES_W8_COUNT 7
static const BYTE CiCallbackIndexes_Win8[CI_CALLBACK_NAMES_W8_COUNT] = { //Windows 8
    0,  //CiSetFileCache
    1,  //CiGetFileCache
    2,  //CiQueryInformation
    3,  //CiValidateImageHeader
    4,  //CiValidateImageData
    5,  //CiHashMemory
    6,  //KappxIsPackageFile
};

#define CI_CALLBACK_NAMES_W81_COUNT 12
static const BYTE CiCallbackIndexes_Win81[CI_CALLBACK_NAMES_W81_COUNT] = { //Windows 8.1
    0,  //CiSetFileCache
    1,  //CiGetFileCache
    2,  //CiQueryInformation
    3,  //CiValidateImageHeader
    4,  //CiValidateImageData
    5,  //CiHashMemory
    6,  //KappxIsPackageFile
    7,  //CiCompareSigningLevels
    8,  //CiValidateFileAsImageType
    9,  //CiRegisterSigningInformation
    10, //CiUnregisterSigningInformation
    11  //CiInitializePolicy
};

#define CI_CALLBACK_NAMES_W10THRESHOLD_COUNT 18
static const BYTE CiCallbackIndexes_Win10Threshold[CI_CALLBACK_NAMES_W10THRESHOLD_COUNT] = { //Windows 10 TH1/TH2
    0,  //CiSetFileCache
    1,  //CiGetFileCache
    2,  //CiQueryInformation
    3,  //CiValidateImageHeader
    4,  //CiValidateImageData
    5,  //CiHashMemory
    6,  //KappxIsPackageFile
    7,  //CiCompareSigningLevels
    8,  //CiValidateFileAsImageType
    9,  //CiRegisterSigningInformation
    10, //CiUnregisterSigningInformation
    11, //CiInitializePolicy
    12, //CiReleaseContext
    13, //Unknown XBOX
    14, //CiGetStrongImageReference
    15, //CiHvciSetImageBaseAddress
    24, //SIPolicyQueryPolicyInformation
    17  //CiValidateDynamicCodePages
};

#define CI_CALLBACK_NAMES_W10RS1_COUNT 20
static const BYTE CiCallbackIndexes_Win10RS1[CI_CALLBACK_NAMES_W10RS1_COUNT] = { //Windows 10 RS1
    0,  //CiSetFileCache
    1,  //CiGetFileCache
    2,  //CiQueryInformation
    3,  //CiValidateImageHeader
    4,  //CiValidateImageData
    5,  //CiHashMemory
    6,  //KappxIsPackageFile
    7,  //CiCompareSigningLevels
    8,  //CiValidateFileAsImageType
    9,  //CiRegisterSigningInformation
    10, //CiUnregisterSigningInformation
    11, //CiInitializePolicy
    12, //CiReleaseContext
    13, //Unknown XBOX
    14, //CiGetStrongImageReference
    15, //CiHvciSetImageBaseAddress
    24, //SIPolicyQueryPolicyInformation
    17, //CiValidateDynamicCodePages
    25, //SIPolicyQuerySecurityPolicy
    19  //CiRevalidateImage
};

#define CI_CALLBACK_NAMES_W10RS2_COUNT 22
static const BYTE CiCallbackIndexes_Win10RS2[CI_CALLBACK_NAMES_W10RS2_COUNT] = { //Windows 10 RS2
    0,  //CiSetFileCache
    1,  //CiGetFileCache
    2,  //CiQueryInformation
    3,  //CiValidateImageHeader
    4,  //CiValidateImageData
    5,  //CiHashMemory
    6,  //KappxIsPackageFile
    7,  //CiCompareSigningLevels
    8,  //CiValidateFileAsImageType
    9,  //CiRegisterSigningInformation
    10, //CiUnregisterSigningInformation
    11, //CiInitializePolicy
    12, //CiReleaseContext
    13, //Unknown XBOX
    14, //CiGetStrongImageReference
    15, //CiHvciSetImageBaseAddress
    16, //CipQueryPolicyInformation
    17, //CiValidateDynamicCodePages
    25, //SIPolicyQuerySecurityPolicy
    19, //CiRevalidateImage
    26, //CiSetUnlockInformation
    22  //CiGetBuildExpiryTime
};

#define CI_CALLBACK_NAMES_W10RS3_COUNT 22
static const BYTE CiCallbackIndexes_Win10RS3[CI_CALLBACK_NAMES_W10RS3_COUNT] = { //Windows 10 RS3
    0,  //CiSetFileCache
    1,  //CiGetFileCache
    2,  //CiQueryInformation
    3,  //CiValidateImageHeader
    4,  //CiValidateImageData
    5,  //CiHashMemory
    6,  //KappxIsPackageFile
    7,  //CiCompareSigningLevels
    8,  //CiValidateFileAsImageType
    9,  //CiRegisterSigningInformation
    10, //CiUnregisterSigningInformation
    11, //CiInitializePolicy
    12, //CiReleaseContext
    13, //Unknown XBOX
    14, //CiGetStrongImageReference
    15, //CiHvciSetImageBaseAddress
    16, //CipQueryPolicyInformation
    17, //CiValidateDynamicCodePages
    18, //CiQuerySecurityPolicy
    19, //CiRevalidateImage
    20, //CiSetInformation
    22  //CiGetBuildExpiryTime
};

#define CI_CALLBACK_NAMES_W10RS4_19H1_COUNT 24
static const BYTE CiCallbackIndexes_Win10RS4_19H1[CI_CALLBACK_NAMES_W10RS4_19H1_COUNT] = { //Windows 10 RS4/RS5/19H1
    0,  //CiSetFileCache
    1,  //CiGetFileCache
    2,  //CiQueryInformation
    3,  //CiValidateImageHeader
    4,  //CiValidateImageData
    5,  //CiHashMemory
    6,  //KappxIsPackageFile
    7,  //CiCompareSigningLevels
    8,  //CiValidateFileAsImageType
    9,  //CiRegisterSigningInformation
    10, //CiUnregisterSigningInformation
    11, //CiInitializePolicy
    12, //CiReleaseContext
    13, //Unknown XBOX
    14, //CiGetStrongImageReference
    15, //CiHvciSetImageBaseAddress
    16, //CipQueryPolicyInformation
    17, //CiValidateDynamicCodePages
    18, //CiQuerySecurityPolicy
    19, //CiRevalidateImage
    20, //CiSetInformation
    21, //CiSetInformationProcess
    22, //CiGetBuildExpiryTime
    23  //CiCheckProcessDebugAccessPolicy
};

/*
* GetCiRoutineNameFromIndex
*
* Purpose:
*
* Return CiCallback name by index
*
*/
LPWSTR GetCiRoutineNameFromIndex(
    _In_ ULONG Index)
{
    ULONG ArrayCount = 0, index;
    CONST BYTE *Indexes;

    switch (g_NtBuildNumber) {

    case 7600:
    case 7601:
        Indexes = CiCallbackIndexes_Win7;
        ArrayCount = CI_CALLBACKS_NAMES_W7_COUNT;
        break;

    case 9200:
        Indexes = CiCallbackIndexes_Win8;
        ArrayCount = CI_CALLBACK_NAMES_W8_COUNT;
        break;

    case 9600:
        Indexes = CiCallbackIndexes_Win81;
        ArrayCount = CI_CALLBACK_NAMES_W81_COUNT;
        break;

    case 10240:
    case 10586:
        Indexes = CiCallbackIndexes_Win10Threshold;
        ArrayCount = CI_CALLBACK_NAMES_W10THRESHOLD_COUNT;
        break;

    case 14393:
        Indexes = CiCallbackIndexes_Win10RS1;
        ArrayCount = CI_CALLBACK_NAMES_W10RS1_COUNT;
        break;

    case 15063:
        Indexes = CiCallbackIndexes_Win10RS2;
        ArrayCount = CI_CALLBACK_NAMES_W10RS2_COUNT;
        break;

    case 16299:
        Indexes = CiCallbackIndexes_Win10RS3;
        ArrayCount = CI_CALLBACK_NAMES_W10RS3_COUNT;
        break;

    case 17134:
    case 17763:
    case 18362:
    default:
        Indexes = CiCallbackIndexes_Win10RS4_19H1;
        ArrayCount = CI_CALLBACK_NAMES_W10RS4_19H1_COUNT;
        break;
    }

    if (Index >= ArrayCount)
        return T_CannotQuery;

    index = Indexes[Index];
    if (index >= CI_CALLBACK_NAMES_COUNT)
        return T_CannotQuery;

    return (LPWSTR)CiCallbackNames[index];
}

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
            // mov      [rbx + 8], rax |
            // cmp      [rax], rcx
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
* FindDbgkLmdCallbacks
*
* Purpose:
*
* Return array address of callbacks registered with:
*
*   DbgkLkmdRegisterCallback
*
*/
ULONG_PTR FindDbgkLmdCallbacks(
    VOID)
{
    ULONG Index;
    LONG Rel = 0;
    ULONG_PTR Address = 0;
    PBYTE ptrCode;
    hde64s hs;

    ULONG_PTR NtOsBase = (ULONG_PTR)g_kdctx.NtOsBase;
    HMODULE hNtOs = (HMODULE)g_kdctx.NtOsImageMap;

    ptrCode = (PBYTE)GetProcAddress(hNtOs, "DbgkLkmdUnregisterCallback");
    if (ptrCode == NULL)
        return 0;

    Index = 0;
    Rel = 0;

    //
    // Find DbgkLmdCallbacks pointer
    //
    do {
        hde64_disasm(ptrCode + Index, &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == 7) { //check if lea

            //
            // lea     rcx, DbgkLmdCallbacks
            //

            if (((ptrCode[Index] == 0x4C) || (ptrCode[Index] == 0x48)) &&
                (ptrCode[Index + 1] == 0x8D))
            {
                Rel = *(PLONG)(ptrCode + Index + 3);
                break;
            }

        }

        Index += hs.len;

    } while (Index < 64);

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

    g_CallbacksCount += 1;
}

/*
* AddZeroEntryToList
*
* Purpose:
*
* Adds emptry callback entry to the treelist.
*
*/
VOID AddZeroEntryToList(
    _In_ HWND TreeList,
    _In_ HTREEITEM RootItem,
    _In_ ULONG_PTR Function,
    _In_opt_ LPWSTR lpAdditionalInfo
)
{
    TL_SUBITEMS_FIXED TreeListSubItems;
    WCHAR szAddress[32];
    WCHAR szBuffer[MAX_PATH + 1];

    RtlSecureZeroMemory(&TreeListSubItems, sizeof(TreeListSubItems));
    TreeListSubItems.Count = 2;

    szAddress[0] = TEXT('0');
    szAddress[1] = TEXT('x');
    szAddress[2] = 0;
    u64tohex(Function, &szAddress[2]);
    TreeListSubItems.Text[0] = szAddress;

    _strcpy(szBuffer, TEXT("Nothing"));

    TreeListSubItems.Text[0] = szBuffer;

    if (Function == 0) {
        TreeListSubItems.Text[1] = T_CannotQuery;
    }
    else {
        TreeListSubItems.Text[1] = lpAdditionalInfo;
    }

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
* DumpDbgkLCallbacks
*
* Purpose:
*
* Read DbgkL* callback data from kernel and send it to output window.
*
*/
VOID DumpDbgkLCallbacks(
    _In_ HWND TreeList,
    _In_ LPWSTR lpCallbackType,
    _In_ ULONG_PTR RoutinesArrayAddress,
    _In_ PRTL_PROCESS_MODULES Modules
)
{
    ULONG c;
    ULONG_PTR Address, Function;
    EX_FAST_REF Callbacks[DbgkLmdCount];

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

        for (c = 0; c < DbgkLmdCount; c++) {

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
            AltitudeSize = 8 + (SIZE_T)Registration.Altitude.Length;
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
* DumpCiCallbacks
*
* Purpose:
*
* Read SeCiCallbacks/g_CiCallbacks related callback data from kernel and send it to output window.
*
*/
VOID DumpCiCallbacks(
    _In_ HWND TreeList,
    _In_ LPWSTR lpCallbackType,
    _In_ ULONG_PTR CiCallbacks,
    _In_ PRTL_PROCESS_MODULES Modules
)
{
    HTREEITEM RootItem;

    ULONG_PTR *CallbacksData;

    LPWSTR CallbackName;

    ULONG_PTR SizeOfCiCallbacks = 0;

    ULONG BytesRead = 0, i, c;

    BOOL bRevisionMarker;

    //
    // Add callback root entry to the treelist.
    //
    RootItem = AddRootEntryToList(TreeList, lpCallbackType);
    if (RootItem == 0)
        return;

    if (g_NtBuildNumber <= 7601) {
        SizeOfCiCallbacks = 3 * sizeof(ULONG_PTR);

        CallbacksData = (PULONG_PTR)supVirtualAlloc((SIZE_T)SizeOfCiCallbacks);
        if (CallbacksData) {

            if (kdReadSystemMemoryEx(CiCallbacks,
                CallbacksData,
                (ULONG)SizeOfCiCallbacks,
                &BytesRead))
            {
                c = (ULONG)(SizeOfCiCallbacks / sizeof(ULONG_PTR));
                for (i = 0; i < c; i++) {

                    CallbackName = GetCiRoutineNameFromIndex(i);

                    if (CallbacksData[i]) {

                        AddEntryToList(TreeList,
                            RootItem,
                            CallbacksData[i],
                            CallbackName,
                            Modules);

                    }
                    else {

                        AddZeroEntryToList(TreeList,
                            RootItem,
                            CallbacksData[i],
                            CallbackName);

                    }
                }
            }
            supVirtualFree(CallbacksData);
        }
    }
    else {

        //
        // Probe size element.
        //
        if (!kdReadSystemMemoryEx(CiCallbacks,
            &SizeOfCiCallbacks,
            sizeof(ULONG_PTR),
            &BytesRead))
        {
            return;
        }

        //
        // Check size.
        //
        if ((SizeOfCiCallbacks == 0) || (SizeOfCiCallbacks > PAGE_SIZE))
            return;

        CallbacksData = (PULONG_PTR)supVirtualAlloc((SIZE_T)SizeOfCiCallbacks);
        if (CallbacksData) {

            if (kdReadSystemMemoryEx(CiCallbacks,
                CallbacksData,
                (ULONG)SizeOfCiCallbacks,
                &BytesRead))
            {
                SizeOfCiCallbacks -= sizeof(ULONG_PTR); //exclude structure sizeof
                bRevisionMarker = (g_NtBuildNumber >= 14393); //there is a revision marker at the end of this structure.
                if (bRevisionMarker) SizeOfCiCallbacks -= sizeof(ULONG_PTR); //exclude marker (windows 10 + revision)

                c = (ULONG)(SizeOfCiCallbacks / sizeof(ULONG_PTR));

                for (i = 1; i <= c; i++) {

                    CallbackName = GetCiRoutineNameFromIndex(i - 1);

                    if (CallbacksData[i]) {

                        AddEntryToList(TreeList,
                            RootItem,
                            CallbacksData[i],
                            CallbackName,
                            Modules);

                    }
                    else {

                        AddZeroEntryToList(TreeList,
                            RootItem,
                            CallbacksData[i],
                            CallbackName);

                    }

                }
            }

            supVirtualFree(CallbacksData);
        }
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
    PRTL_PROCESS_MODULES Modules = NULL;

    WCHAR szText[100];

    __try {
        //
        // Query all addresses.
        //
        if (g_SystemCallbacks.PspCreateProcessNotifyRoutine == 0)
            g_SystemCallbacks.PspCreateProcessNotifyRoutine = FindPspCreateProcessNotifyRoutine();

        if (g_SystemCallbacks.PspCreateThreadNotifyRoutine == 0)
            g_SystemCallbacks.PspCreateThreadNotifyRoutine = FindPspCreateThreadNotifyRoutine();

        if (g_SystemCallbacks.PspLoadImageNotifyRoutine == 0)
            g_SystemCallbacks.PspLoadImageNotifyRoutine = FindPspLoadImageNotifyRoutine();

        if (g_SystemCallbacks.KeBugCheckCallbackHead == 0)
            g_SystemCallbacks.KeBugCheckCallbackHead = FindKeBugCheckCallbackHead();

        if (g_SystemCallbacks.KeBugCheckReasonCallbackHead == 0)
            g_SystemCallbacks.KeBugCheckReasonCallbackHead = FindKeBugCheckReasonCallbackHead();

        if (g_SystemCallbacks.IopNotifyShutdownQueueHead == 0)
            g_SystemCallbacks.IopNotifyShutdownQueueHead = FindIopNotifyShutdownQueueHeadHead(FALSE);

        if (g_SystemCallbacks.IopNotifyLastChanceShutdownQueueHead == 0)
            g_SystemCallbacks.IopNotifyLastChanceShutdownQueueHead = FindIopNotifyShutdownQueueHeadHead(TRUE);

        if (g_SystemCallbacks.CmCallbackListHead == 0)
            g_SystemCallbacks.CmCallbackListHead = FindCmCallbackHead();

        if (g_SystemCallbacks.ObProcessCallbackHead == 0)
            g_SystemCallbacks.ObProcessCallbackHead = GetObjectTypeCallbackListHeadByType(0);

        if (g_SystemCallbacks.ObThreadCallbackHead == 0)
            g_SystemCallbacks.ObThreadCallbackHead = GetObjectTypeCallbackListHeadByType(1);

        if (g_SystemCallbacks.ObDesktopCallbackHead == 0)
            g_SystemCallbacks.ObDesktopCallbackHead = GetObjectTypeCallbackListHeadByType(2);

        if (g_SystemCallbacks.SeFileSystemNotifyRoutinesHead == 0)
            g_SystemCallbacks.SeFileSystemNotifyRoutinesHead = FindSeFileSystemNotifyRoutinesHead(FALSE);

        if (g_SystemCallbacks.SeFileSystemNotifyRoutinesExHead == 0)
            g_SystemCallbacks.SeFileSystemNotifyRoutinesExHead = FindSeFileSystemNotifyRoutinesHead(TRUE);

        if (g_SystemCallbacks.PopRegisteredPowerSettingCallbacks == 0)
            g_SystemCallbacks.PopRegisteredPowerSettingCallbacks = FindPopRegisteredPowerSettingCallbacks();

        if (g_SystemCallbacks.RtlpDebugPrintCallbackList == 0)
            g_SystemCallbacks.RtlpDebugPrintCallbackList = FindRtlpDebugPrintCallbackList();

        if (g_SystemCallbacks.IopFsNotifyChangeQueueHead == 0)
            g_SystemCallbacks.IopFsNotifyChangeQueueHead = FindIopFsNotifyChangeQueueHead();

        if ((g_SystemCallbacks.IopCdRomFileSystemQueueHead == 0) ||
            (g_SystemCallbacks.IopDiskFileSystemQueueHead == 0) ||
            (g_SystemCallbacks.IopTapeFileSystemQueueHead == 0) ||
            (g_SystemCallbacks.IopNetworkFileSystemQueueHead == 0))
        {
            if (!FindIopFileSystemQueueHeads(&g_SystemCallbacks.IopCdRomFileSystemQueueHead,
                &g_SystemCallbacks.IopDiskFileSystemQueueHead,
                &g_SystemCallbacks.IopTapeFileSystemQueueHead,
                &g_SystemCallbacks.IopNetworkFileSystemQueueHead))
            {
#ifdef _DEBUG
                OutputDebugString(TEXT("Could not locate all Iop listheads\r\n"));
#endif
            }
        }

        if (g_SystemCallbacks.DbgkLmdCallbacks == 0)
            g_SystemCallbacks.DbgkLmdCallbacks = FindDbgkLmdCallbacks();

        if (g_SystemCallbacks.CiCallbacks == 0)
            g_SystemCallbacks.CiCallbacks = (ULONG_PTR)kdFindCiCallbacks(&g_kdctx);

    }
    __except (exceptFilter(GetExceptionCode(), GetExceptionInformation())) {
        return;
    }

    __try {

        Modules = (PRTL_PROCESS_MODULES)supGetSystemInfo(SystemModuleInformation, NULL);
        if (Modules == NULL) {
            MessageBox(hwndDlg, TEXT("Could not allocate memory for modules list."), NULL, MB_ICONERROR);
            __leave;
        }


        //
        // List process callbacks.
        //

        if (g_SystemCallbacks.PspCreateProcessNotifyRoutine) {

            DumpPsCallbacks(TreeList,
                TEXT("CreateProcess"),
                g_SystemCallbacks.PspCreateProcessNotifyRoutine,
                Modules);

        }

        //
        // List thread callbacks.
        //
        if (g_SystemCallbacks.PspCreateThreadNotifyRoutine) {

            DumpPsCallbacks(TreeList,
                TEXT("CreateThread"),
                g_SystemCallbacks.PspCreateThreadNotifyRoutine,
                Modules);

        }

        //
        // List load image callbacks.
        //
        if (g_SystemCallbacks.PspLoadImageNotifyRoutine) {

            DumpPsCallbacks(TreeList,
                TEXT("LoadImage"),
                g_SystemCallbacks.PspLoadImageNotifyRoutine,
                Modules);

        }

        //
        // List KeBugCheck callbacks.
        //
        if (g_SystemCallbacks.KeBugCheckCallbackHead) {

            DumpKeBugCheckCallbacks(TreeList,
                TEXT("BugCheck"),
                g_SystemCallbacks.KeBugCheckCallbackHead,
                Modules);

        }

        if (g_SystemCallbacks.KeBugCheckReasonCallbackHead) {

            DumpKeBugCheckReasonCallbacks(TreeList,
                TEXT("BugCheckReason"),
                g_SystemCallbacks.KeBugCheckReasonCallbackHead,
                Modules);

        }

        //
        // List Cm callbacks
        //
        if (g_SystemCallbacks.CmCallbackListHead) {

            DumpCmCallbacks(TreeList,
                TEXT("CmRegistry"),
                g_SystemCallbacks.CmCallbackListHead,
                Modules);

        }

        //
        // List Io Shutdown callbacks.
        //
        if (g_SystemCallbacks.IopNotifyShutdownQueueHead) {

            DumpIoCallbacks(TreeList,
                TEXT("Shutdown"),
                g_SystemCallbacks.IopNotifyShutdownQueueHead,
                Modules);

        }
        if (g_SystemCallbacks.IopNotifyLastChanceShutdownQueueHead) {

            DumpIoCallbacks(TreeList,
                TEXT("LastChanceShutdown"),
                g_SystemCallbacks.IopNotifyLastChanceShutdownQueueHead,
                Modules);

        }

        //
        // List Ob callbacks.
        //
        if (g_SystemCallbacks.ObProcessCallbackHead) {

            DumpObCallbacks(TreeList,
                TEXT("ObProcess"),
                g_SystemCallbacks.ObProcessCallbackHead,
                Modules);

        }
        if (g_SystemCallbacks.ObThreadCallbackHead) {

            DumpObCallbacks(TreeList,
                TEXT("ObThread"),
                g_SystemCallbacks.ObThreadCallbackHead,
                Modules);

        }
        if (g_SystemCallbacks.ObDesktopCallbackHead) {

            DumpObCallbacks(TreeList,
                TEXT("ObDesktop"),
                g_SystemCallbacks.ObDesktopCallbackHead,
                Modules);

        }

        //
        // List Se callbacks.
        //
        if (g_SystemCallbacks.SeFileSystemNotifyRoutinesHead) {

            DumpSeCallbacks(TreeList,
                TEXT("SeFileSystem"),
                g_SystemCallbacks.SeFileSystemNotifyRoutinesHead,
                Modules);

        }
        if (g_SystemCallbacks.SeFileSystemNotifyRoutinesExHead) {

            DumpSeCallbacks(TreeList,
                TEXT("SeFileSystemEx"),
                g_SystemCallbacks.SeFileSystemNotifyRoutinesExHead,
                Modules);

        }

        //
        // List Po callbacks.
        //
        if (g_SystemCallbacks.PopRegisteredPowerSettingCallbacks) {

            DumpPoCallbacks(TreeList,
                TEXT("PowerSettings"),
                g_SystemCallbacks.PopRegisteredPowerSettingCallbacks,
                Modules);

        }

        //
        // List Dbg callbacks
        //
        if (g_SystemCallbacks.RtlpDebugPrintCallbackList) {

            DumpDbgPrintCallbacks(TreeList,
                TEXT("DbgPrint"),
                g_SystemCallbacks.RtlpDebugPrintCallbackList,
                Modules);

        }

        //
        // List IoFsRegistration callbacks
        //
        if (g_SystemCallbacks.IopFsNotifyChangeQueueHead) {

            DumpIoFsRegistrationCallbacks(TreeList,
                TEXT("IoFsRegistration"),
                g_SystemCallbacks.IopFsNotifyChangeQueueHead,
                Modules);

        }

        //
        // List Io File System callbacks
        //
        if (g_SystemCallbacks.IopDiskFileSystemQueueHead) {

            DumpIoFileSystemCallbacks(TreeList,
                TEXT("IoDiskFs"),
                g_SystemCallbacks.IopDiskFileSystemQueueHead,
                Modules);
        }
        if (g_SystemCallbacks.IopCdRomFileSystemQueueHead) {

            DumpIoFileSystemCallbacks(TreeList,
                TEXT("IoCdRomFs"),
                g_SystemCallbacks.IopCdRomFileSystemQueueHead,
                Modules);
        }
        if (g_SystemCallbacks.IopNetworkFileSystemQueueHead) {

            DumpIoFileSystemCallbacks(TreeList,
                TEXT("IoNetworkFs"),
                g_SystemCallbacks.IopNetworkFileSystemQueueHead,
                Modules);
        }
        if (g_SystemCallbacks.IopTapeFileSystemQueueHead) {

            DumpIoFileSystemCallbacks(TreeList,
                TEXT("IoTapeFs"),
                g_SystemCallbacks.IopTapeFileSystemQueueHead,
                Modules);
        }

        //
        // List DbgkLmdCallbacks
        //
        if (g_SystemCallbacks.DbgkLmdCallbacks) {

            DumpDbgkLCallbacks(TreeList,
                TEXT("DbgkLmdCallback"),
                g_SystemCallbacks.DbgkLmdCallbacks,
                Modules);
        }

        //
        // List CI callbacks
        //
        if (g_SystemCallbacks.CiCallbacks) {

            DumpCiCallbacks(TreeList,
                TEXT("CiCallbacks"),
                g_SystemCallbacks.CiCallbacks,
                Modules);
        }

        //
        // Show total number of callbacks.
        //
        _strcpy(szText, TEXT("Total listed callbacks: "));
        ultostr(g_CallbacksCount, _strend(szText));
        SetWindowText(GetDlgItem(hwndDlg, ID_EXTRASLIST_STATUSBAR), szText);

    }
    __finally {
        if (Modules) supHeapFree(Modules);
    }

    SetFocus(TreeList);
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
        InsertMenu(hMenu, 1, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
        InsertMenu(hMenu, 2, MF_BYCOMMAND, ID_VIEW_REFRESH, T_VIEW_REFRESH);

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
    _In_ HWND hwndStatusBar,
    _In_ HWND hwndTreeList
)
{
    RECT r, szr;

    RtlSecureZeroMemory(&r, sizeof(RECT));
    RtlSecureZeroMemory(&szr, sizeof(RECT));

    GetClientRect(hwndDlg, &r);
    GetClientRect(hwndStatusBar, &szr);

    SendMessage(hwndStatusBar, WM_SIZE, 0, 0);

    SetWindowPos(hwndTreeList, 0, 0, 0,
        r.right,
        r.bottom - szr.bottom,
        SWP_NOZORDER);

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
* CallbackDialogContentRefresh
*
* Purpose:
*
* Refresh callback list handler.
*
*/
VOID CallbackDialogContentRefresh(
    _In_  HWND hwndDlg,
    _In_ EXTRASCONTEXT *pDlgContext,
    _In_ BOOL fResetContent
)
{
#ifndef _DEBUG
    HWND hwndBanner = supDisplayLoadBanner(hwndDlg,
        TEXT("Processing callbacks list, please wait"));
#endif

    __try {

        SetCapture(hwndDlg);

        if (fResetContent) TreeList_ClearTree(pDlgContext->TreeList);

        g_CallbacksCount = 0;

        CallbacksList(hwndDlg, pDlgContext->TreeList);

    }
    __finally {
        ReleaseCapture();
#ifndef _DEBUG
        SendMessage(hwndBanner, WM_CLOSE, 0, 0);
#endif
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
            CallbacksDialogResize(hwndDlg, pDlgContext->StatusBar, pDlgContext->TreeList);
        }
        break;

    case WM_CLOSE:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
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
        case ID_VIEW_REFRESH:
            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
            if (pDlgContext) {
                CallbackDialogContentRefresh(hwndDlg, pDlgContext, TRUE);
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
        MAKEINTRESOURCE(IDD_DIALOG_CALLBACKS),
        hwndParent,
        &CallbacksDialogProc,
        (LPARAM)pDlgContext);

    if (hwndDlg == NULL) {
        return;
    }

    pDlgContext->hwndDlg = hwndDlg;
    g_WinObj.AuxDialogs[wobjCallbacksDlgId] = hwndDlg;
    pDlgContext->StatusBar = GetDlgItem(hwndDlg, ID_EXTRASLIST_STATUSBAR);

    extrasSetDlgIcon(hwndDlg);
    SetWindowText(hwndDlg, TEXT("System Callbacks"));

    GetClientRect(hwndParent, &rc);
    pDlgContext->TreeList = CreateWindowEx(WS_EX_STATICEDGE, WC_TREELIST, NULL,
        WS_VISIBLE | WS_CHILD | WS_TABSTOP | TLSTYLE_COLAUTOEXPAND | TLSTYLE_LINKLINES, 12, 14,
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

        CallbackDialogContentRefresh(hwndDlg, pDlgContext, FALSE);
    }

    SendMessage(hwndDlg, WM_SIZE, 0, 0);
}
