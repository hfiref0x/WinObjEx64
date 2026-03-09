/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2026
*
*  TITLE:       PLUGINMNGR.H
*
*  VERSION:     2.10
*
*  DATE:        07 Mar 2026
*
*  Common header file for the plugin manager.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#include "../plugins/plugin_def.h"

#define ID_MENU_PLUGINS       60000
#define WINOBJEX_MAX_PLUGINS  20
#define ID_MENU_PLUGINS_MAX   (ID_MENU_PLUGINS + WINOBJEX_MAX_PLUGINS)

VOID PmCreate(_In_ HWND ParentWindow);
VOID PmDestroy();

VOID PmProcessEntry(
    _In_ HWND ParentWindow,
    _In_ UINT Id);

VOID PmBuildPluginPopupMenuByObjectType(
    _In_ HMENU ContextMenu,
    _In_ UCHAR ObjectType);

VOID PmViewPlugins(
    VOID);
