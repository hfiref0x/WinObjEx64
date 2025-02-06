/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2025
*
*  TITLE:       EXTAPI.H
*
*  VERSION:     2.07
*
*  DATE:        04 Feb 2025
*
*  Windows SDK compatibility header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#ifndef PRODUCT_ENTERPRISE_S
#define PRODUCT_ENTERPRISE_S 0x0000007D
#endif

#ifndef PRODUCT_ENTERPRISE_S_N
#define PRODUCT_ENTERPRISE_S_N 0x0000007E
#endif

#ifndef PRODUCT_ENTERPRISE_S_EVALUATION
#define PRODUCT_ENTERPRISE_S_EVALUATION 0x00000081
#endif

#ifndef PRODUCT_ENTERPRISE_S_N_EVALUATION
#define PRODUCT_ENTERPRISE_S_N_EVALUATION 0x00000082
#endif

#ifndef PRODUCT_IOTENTERPRISES
#define PRODUCT_IOTENTERPRISES 0x000000BF
#endif

#define sidTypeUser 1
#define sidTypeGroup 2
#define sidTypeDomain 3
#define sidTypeAlias 4
#define sidTypeWellKnownGroup 5 
#define sidTypeDeletedAccount 6
#define sidTypeInvalid 7
#define sidTypeUnknown 8
#define sidTypeComputer 9
#define sidTypeLabel 10
#define sidTypeLogonSession 11

#ifndef UFIELD_OFFSET
#define UFIELD_OFFSET(type, field)    ((DWORD)(LONG_PTR)&(((type *)0)->field))
#endif

//
// These constants are missing in Windows SDK 8.1
//
#ifndef SYSTEM_ACCESS_FILTER_ACE_TYPE
#define SYSTEM_ACCESS_FILTER_ACE_TYPE           (0x15)
#endif

#ifndef IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG
#define IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG 17
#endif

#ifndef SERVICE_USER_SERVICE
#define SERVICE_USER_SERVICE                        0x00000040
#endif

#ifndef SERVICE_USERSERVICE_INSTANCE
#define SERVICE_USERSERVICE_INSTANCE                0x00000080
#endif

#ifndef SERVICE_PKG_SERVICE
#define SERVICE_PKG_SERVICE                         0x00000200
#endif

#ifndef PF_RDTSCP_INSTRUCTION_AVAILABLE
#define PF_RDTSCP_INSTRUCTION_AVAILABLE             32
#endif

#ifndef PF_RDPID_INSTRUCTION_AVAILABLE
#define PF_RDPID_INSTRUCTION_AVAILABLE              33
#endif

#ifndef PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE
#define PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE    34
#endif

#ifndef PF_MONITORX_INSTRUCTION_AVAILABLE
#define PF_MONITORX_INSTRUCTION_AVAILABLE           35   
#endif

#ifndef PF_SSSE3_INSTRUCTIONS_AVAILABLE
#define PF_SSSE3_INSTRUCTIONS_AVAILABLE             36
#endif

#ifndef PF_SSE4_1_INSTRUCTIONS_AVAILABLE
#define PF_SSE4_1_INSTRUCTIONS_AVAILABLE            37
#endif

#ifndef PF_SSE4_2_INSTRUCTIONS_AVAILABLE
#define PF_SSE4_2_INSTRUCTIONS_AVAILABLE            38
#endif

#ifndef PF_AVX_INSTRUCTIONS_AVAILABLE
#define PF_AVX_INSTRUCTIONS_AVAILABLE               39
#endif

#ifndef PF_AVX2_INSTRUCTIONS_AVAILABLE
#define PF_AVX2_INSTRUCTIONS_AVAILABLE              40
#endif

#ifndef PF_AVX512F_INSTRUCTIONS_AVAILABLE
#define PF_AVX512F_INSTRUCTIONS_AVAILABLE           41
#endif

#ifndef PF_ERMS_AVAILABLE
#define PF_ERMS_AVAILABLE                           42
#endif

#ifndef PF_BMI2_INSTRUCTIONS_AVAILABLE
#define PF_BMI2_INSTRUCTIONS_AVAILABLE              60
#endif

#ifndef VER_SUITE_MULTIUSERTS
#define VER_SUITE_MULTIUSERTS 0x00020000
#endif

#ifndef FILE_SUPPORTS_BLOCK_REFCOUNTING     
#define FILE_SUPPORTS_BLOCK_REFCOUNTING             0
#endif

#ifndef _WIN32_WINNT_WIN10

DECLARE_HANDLE(DPI_AWARENESS_CONTEXT);

typedef enum DPI_AWARENESS {
    DPI_AWARENESS_INVALID = -1,
    DPI_AWARENESS_UNAWARE = 0,
    DPI_AWARENESS_SYSTEM_AWARE = 1,
    DPI_AWARENESS_PER_MONITOR_AWARE = 2
} DPI_AWARENESS;

#define DPI_AWARENESS_CONTEXT_UNAWARE               ((DPI_AWARENESS_CONTEXT)-1)
#define DPI_AWARENESS_CONTEXT_SYSTEM_AWARE          ((DPI_AWARENESS_CONTEXT)-2)
#define DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE     ((DPI_AWARENESS_CONTEXT)-3)
#define DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2  ((DPI_AWARENESS_CONTEXT)-4)
#define DPI_AWARENESS_CONTEXT_UNAWARE_GDISCALED     ((DPI_AWARENESS_CONTEXT)-5)

#endif //_WIN32_WINNT_WIN10

#ifndef NTDDI_WINTHRESHOLD
#define NTDDI_WINTHRESHOLD 0x0A000000   /* ABRACADABRA_THRESHOLD */
#endif

#ifndef NTDDI_WIN10
#define NTDDI_WIN10 0x0A000000          /* ABRACADABRA_THRESHOLD */
#endif 

#ifndef NTDDI_WIN10_TH2
#define NTDDI_WIN10_TH2 0x0A000001      /* ABRACADABRA_WIN10_TH2 */
#endif

#ifndef NTDDI_WIN10_RS1
#define NTDDI_WIN10_RS1 0x0A000002      /* ABRACADABRA_WIN10_RS1 */
#endif

#ifndef NTDDI_WIN10_RS2
#define NTDDI_WIN10_RS2 0x0A000003      /* ABRACADABRA_WIN10_RS2 */
#endif

#ifndef NTDDI_WIN10_RS3
#define NTDDI_WIN10_RS3 0x0A000004      /* ABRACADABRA_WIN10_RS3 */
#endif

#ifndef NTDDI_WIN10_RS4
#define NTDDI_WIN10_RS4 0x0A000005      /* ABRACADABRA_WIN10_RS4 */
#endif

#ifndef NTDDI_WIN10_RS5
#define NTDDI_WIN10_RS5 0x0A000006      /* ABRACADABRA_WIN10_RS5 */
#endif

#ifndef NTDDI_WIN10_19H1
#define NTDDI_WIN10_19H1 0x0A000007     /* ABRACADABRA_WIN10_19H1 */
#endif

#ifndef NTDDI_WIN10_VB
#define NTDDI_WIN10_VB 0x0A000008       /* ABRACADABRA_WIN10_VB */
#endif

#ifndef NTDDI_WIN10_MN
#define NTDDI_WIN10_MN 0x0A000009       /* ABRACADABRA_WIN10_MN */
#endif

#ifndef NTDDI_WIN10_FE
#define NTDDI_WIN10_FE 0x0A00000A       /* ABRACADABRA_WIN10_FE */
#endif

#ifndef NTDDI_WIN10_CO
#define NTDDI_WIN10_CO 0x0A00000B       /* ABRACADABRA_WIN10_C0 */
#endif

#ifndef NTDDI_WIN10_NI
#define NTDDI_WIN10_NI 0x0A00000C       /* ABRACADABRA_WIN10_NI */
#endif

#ifndef NTDDI_WIN10_CU
#define NTDDI_WIN10_CU 0x0A00000D       /* ABRACADABRA_WIN10_CU */
#endif

#ifndef NTDDI_WIN11_ZN
#define NTDDI_WIN11_ZN 0x0A00000E       /* ABRACADABRA_WIN11_ZN */
#endif

#ifndef NTDDI_WIN11_GA
#define NTDDI_WIN11_GA 0x0A00000F       /* ABRACADABRA_WIN11_GA */
#endif

#ifndef NTDDI_WIN11_GE
#define NTDDI_WIN11_GE 0x0A000010       /* ABRACADABRA_WIN11_GE */
#endif

#ifndef NTDDI_WIN11_SE
#define NTDDI_WIN11_SE 0x0A000011       /* ABRACADABRA_WIN11_SE */
#endif

FORCEINLINE LONG_PTR _InterlockedExchangeAddPointer(
    _Inout_ _Interlocked_operand_ LONG_PTR volatile* Addend,
    _In_ LONG_PTR Value
)
{
#ifdef _WIN64
    return (LONG_PTR)_InterlockedExchangeAdd64((PLONG64)Addend, (LONG64)Value);
#else
    return (LONG_PTR)_InterlockedExchangeAdd((PLONG)Addend, (LONG)Value);
#endif
}

FORCEINLINE LONG_PTR _InterlockedIncrementPointer(
    _Inout_ _Interlocked_operand_ LONG_PTR volatile* Addend
)
{
#ifdef _WIN64
    return (LONG_PTR)_InterlockedIncrement64((PLONG64)Addend);
#else
    return (LONG_PTR)_InterlockedIncrement((PLONG)Addend);
#endif
}

FORCEINLINE LONG_PTR _InterlockedDecrementPointer(
    _Inout_ _Interlocked_operand_ LONG_PTR volatile* Addend
)
{
#ifdef _WIN64
    return (LONG_PTR)_InterlockedDecrement64((PLONG64)Addend);
#else
    return (LONG_PTR)_InterlockedDecrement((PLONG)Addend);
#endif
}

FORCEINLINE BOOLEAN _InterlockedBitTestAndResetPointer(
    _Inout_ _Interlocked_operand_ LONG_PTR volatile* Base,
    _In_ LONG_PTR Bit
)
{
#ifdef _WIN64
    return _interlockedbittestandreset64((PLONG64)Base, (LONG64)Bit);
#else
    return _interlockedbittestandreset((PLONG)Base, (LONG)Bit);
#endif
}

FORCEINLINE BOOLEAN _InterlockedBitTestAndSetPointer(
    _Inout_ _Interlocked_operand_ LONG_PTR volatile* Base,
    _In_ LONG_PTR Bit
)
{
#ifdef _WIN64
    return _interlockedbittestandset64((PLONG64)Base, (LONG64)Bit);
#else
    return _interlockedbittestandset((PLONG)Base, (LONG)Bit);
#endif
}
