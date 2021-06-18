/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       KSYMBOLS.H
*
*  VERSION:     1.90
*
*  DATE:        31 May 2021
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

#define KVAR_KeServiceDescriptorTableShadow L"KeServiceDescriptorTableShadow"
#define KVAR_KseEngine                      L"KseEngine"
#define KVAR_ObHeaderCookie                 L"ObHeaderCookie"
#define KVAR_IopInvalidDeviceRequest        L"IopInvalidDeviceRequest"
#define KVAR_MmUnloadedDrivers              L"MmUnloadedDrivers"
#define KVAR_PspHostSiloGlobals             L"PspHostSiloGlobals"

#define KFLD_UniqueProcessId                L"UniqueProcessId"
#define KFLD_ImageFileName                  L"ImageFileName"

#define KSYM_EPROCESS                       L"_EPROCESS"
#define KSYM_CONTROL_AREA                   L"_CONTROL_AREA"
