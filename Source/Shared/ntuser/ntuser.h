/************************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2021
*  Translated from Microsoft sources/debugger or mentioned elsewhere.
*
*  TITLE:       NTUSER.H
*
*  VERSION:     1.03
*
*  DATE:        01 Dec 2021
*
*  Common header file for the ntuser API functions and definitions.
*
*  Only projects required API/definitions.
*
*  Depends on:    Windows.h
*                 NtStatus.h
*                 NtOs.h
*
*  Include:       Windows.h
*                 NtStatus.h
*                 NtOs.h
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
************************************************************************************/

#if defined (_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#pragma warning(push)
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 4214) // nonstandard extension used : bit field types other than int

#ifndef NTUSER_RTL
#define NTUSER_RTL


//
// NTUSER_RTL HEADER END
//

#if defined(__cplusplus)
extern "C" {
#endif

#ifdef _WIN32ULIB_PRESENT
#pragma comment(lib, "win32u.lib")
#endif

//
// Warning: DESKTOP and other shared WIN32K objects moved to separate headers as of 1.02.
//

typedef enum tagPROCESS_UICONTEXT {
    PROCESS_UICONTEXT_DESKTOP = 0,
    PROCESS_UICONTEXT_IMMERSIVE = 1,
    PROCESS_UICONTEXT_IMMERSIVE_BROKER = 2,
    PROCESS_UICONTEXT_IMMERSIVE_BROWSER = 3
} PROCESS_UICONTEXT;

typedef enum tagPROCESS_UI_FLAGS {
    PROCESS_UIF_NONE = 0,
    PROCESS_UIF_AUTHORING_MODE = 1,
    PROCESS_UIF_RESTRICTIONS_DISABLED = 2
} PROCESS_UI_FLAGS;

typedef struct tagPROCESS_UICONTEXT_INFORMATION {
    DWORD processUIContext; //PROCESS_UICONTEXT
    DWORD dwFlags; //PROCESS_UI_FLAGS
} PROCESS_UICONTEXT_INFORMATION, * PPROCESS_UICONTEXT_INFORMATION;


typedef HWINSTA(NTAPI* pfnNtUserOpenWindowStation)(
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ACCESS_MASK DesiredAccess);

#ifdef __cplusplus
}
#endif

#pragma warning(pop)

#endif NTUSER_RTL
