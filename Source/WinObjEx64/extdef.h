/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019
*
*  TITLE:       EXTAPI.H
*
*  VERSION:     1.73
*
*  DATE:        16 Mar 2019
*
*  Windows SDK 8.1 compatibility header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef enum _EXT_SID_NAME_USE {
    ExtSidTypeUser = 1,
    ExtSidTypeGroup,
    ExtSidTypeDomain,
    ExtSidTypeAlias,
    ExtSidTypeWellKnownGroup,
    ExtSidTypeDeletedAccount,
    ExtSidTypeInvalid,
    ExtSidTypeUnknown,
    ExtSidTypeComputer,
    ExtSidTypeLabel,
    ExtSidTypeLogonSession
} EXT_SID_NAME_USE, *PEXT_SID_NAME_USE;

//
// These constants are missing in Windows SDK 8.1
//
#ifndef SERVICE_USER_SERVICE
#define SERVICE_USER_SERVICE           0x00000040
#endif

#ifndef SERVICE_USERSERVICE_INSTANCE
#define SERVICE_USERSERVICE_INSTANCE   0x00000080
#endif
