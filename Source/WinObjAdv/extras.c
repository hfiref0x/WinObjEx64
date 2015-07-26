/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       EXTRAS.C
*
*  VERSION:     1.20
*
*  DATE:        23 July 2015
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "propDlg.h"
#include "propSecurity.h"
#include "extrasPipes.h"
#include "extrasUSD.h"

/*
* extrasShowPipeDialog
*
* Purpose:
*
* Display Pipe Properties Dialog.
*
*/
VOID extrasShowPipeDialog(
	_In_ HWND hwndParent
	)
{
	extrasCreatePipeDialog(hwndParent);
}

/*
* extrasShowUserSharedDataDialog
*
* Purpose:
*
* Display KUserSharedData dump dialog.
*
*/
VOID extrasShowUserSharedDataDialog(
	_In_ HWND hwndParent
	)
{
	extrasCreateUsdDialog(hwndParent);
}

