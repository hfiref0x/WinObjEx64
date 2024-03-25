/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2024
*
*  TITLE:       KSYMBOLS.H
*
*  VERSION:     2.05
*
*  DATE:        12 Mar 2024
*
*  Header file for kernel symbol names.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define KVAR_KeServiceDescriptorTableShadow         L"KeServiceDescriptorTableShadow"
#define KVAR_KseEngine                              L"KseEngine"
#define KVAR_ObHeaderCookie                         L"ObHeaderCookie"
#define KVAR_IopInvalidDeviceRequest                L"IopInvalidDeviceRequest"
#define KVAR_MmUnloadedDrivers                      L"MmUnloadedDrivers"
#define KVAR_PspHostSiloGlobals                     L"PspHostSiloGlobals"

#define KVAR_SeCiCallbacks                          L"SeCiCallbacks"
#define KVAR_g_CiCallbacks                          L"g_CiCallbacks"

#define KVAR_gSessionGlobalSlots                    L"gSessionGlobalSlots"

#define KVAR_IopFsNotifyChangeQueueHead             L"IopFsNotifyChangeQueueHead"
#define KVAR_RtlpDebugPrintCallbackList             L"RtlpDebugPrintCallbackList"
#define KVAR_PopRegisteredPowerSettingCallbacks     L"PopRegisteredPowerSettingCallbacks"

#define KVAR_IopCdRomFileSystemQueueHead            L"IopCdRomFileSystemQueueHead"
#define KVAR_IopDiskFileSystemQueueHead             L"IopDiskFileSystemQueueHead"
#define KVAR_IopTapeFileSystemQueueHead             L"IopTapeFileSystemQueueHead"
#define KVAR_IopNetworkFileSystemQueueHead          L"IopNetworkFileSystemQueueHead"

#define KVAR_SeFileSystemNotifyRoutinesHead         L"SeFileSystemNotifyRoutinesHead"
#define KVAR_SeFileSystemNotifyRoutinesExHead       L"SeFileSystemNotifyRoutinesExHead"

#define KVAR_IopNotifyShutdownQueueHead             L"IopNotifyShutdownQueueHead"
#define KVAR_IopNotifyLastChanceShutdownQueueHead   L"IopNotifyLastChanceShutdownQueueHead"

#define KVAR_CallbackListHead                       L"CallbackListHead"

#define KVAR_KeBugCheckCallbackListHead             L"KeBugCheckCallbackListHead"
#define KVAR_KeBugCheckReasonCallbackListHead       L"KeBugCheckReasonCallbackListHead"

#define KVAR_PspLoadImageNotifyRoutine              L"PspLoadImageNotifyRoutine"
#define KVAR_PspCreateThreadNotifyRoutine           L"PspCreateThreadNotifyRoutine"
#define KVAR_PspCreateProcessNotifyRoutine          L"PspCreateProcessNotifyRoutine"

#define KVAR_DbgkLmdCallbacks                       L"DbgkLmdCallbacks"

#define KVAR_PsAltSystemCallHandlers                L"PsAltSystemCallHandlers"

#define KVAR_ExpHostList                            L"ExpHostList"

#define KVAR_PopCoalescingCallbackRoutine           L"PopCoalescingCallbackRoutine"
#define KVAR_PopCoalRegistrationList                L"PopCoalRegistrationList"

#define KVAR_PspPicoProviderRoutines                L"PspPicoProviderRoutines"

#define KVAR_KiNmiCallbackListHead                  L"KiNmiCallbackListHead"

#define KVAR_PspSiloMonitorList                     L"PspSiloMonitorList"

#define KVAR_EmpCallbackListHead                    L"EmpCallbackListHead"

#define KVAR_PnpDeviceClassNotifyList               L"PnpDeviceClassNotifyList"

#define KVAR_Win32kApiSetTable                      L"Win32kApiSetTable"

#define KFLD_UniqueProcessId                        L"UniqueProcessId"
#define KFLD_ImageFileName                          L"ImageFileName"

#define KSYM_EPROCESS                               L"_EPROCESS"
#define KSYM_CONTROL_AREA                           L"_CONTROL_AREA"
