/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2026
*
*  TITLE:       UITEST.C
*
*  VERSION:     2.11
*
*  DATE:        23 May 2026
*
*  UI usability tests used while debug.
*
*  Tests are run after the main window and all child controls are fully
*  initialised, immediately before the message loop is entered.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#define OEMRESOURCE

#include "global.h"

static ULONG g_UIFailCount = 0;
static BOOL  g_UIVerbose = TRUE;

#define UI_TEST_ASSERT(expr) do { \
    if (!(expr)) { \
        ++g_UIFailCount; \
        if (g_UIVerbose) { \
            DbgPrint("UI ASSERT FAILED: %s (%s:%d)\n", #expr, __FUNCTION__, __LINE__); \
        } \
    } \
} while (0)

/*
* Test_DpiScaling
*
* Purpose:
*
* Verify that SCALE_DPI_VALUE produces correct scaled values for common
* DPI settings used on Windows.
*
*/
static VOID Test_DpiScaling(VOID)
{
    // Identity at default (96) DPI.
    UI_TEST_ASSERT(SCALE_DPI_VALUE(16, DefaultSystemDpi) == 16);
    UI_TEST_ASSERT(SCALE_DPI_VALUE(0, DefaultSystemDpi) == 0);
    UI_TEST_ASSERT(SCALE_DPI_VALUE(SplitterSize, DefaultSystemDpi) == SplitterSize);
    UI_TEST_ASSERT(SCALE_DPI_VALUE(SplitterMargin, DefaultSystemDpi) == SplitterMargin);

    // 200% scaling (192 DPI).
    UI_TEST_ASSERT(SCALE_DPI_VALUE(16, 192) == 32);

    // 125% scaling (120 DPI): MulDiv(100, 120, 96) == 125.
    UI_TEST_ASSERT(SCALE_DPI_VALUE(100, 120) == 125);

    // 150% scaling (144 DPI): MulDiv(100, 144, 96) == 150.
    UI_TEST_ASSERT(SCALE_DPI_VALUE(100, 144) == 150);

    // Positive input must never produce a zero or negative result.
    UI_TEST_ASSERT(SCALE_DPI_VALUE(1, DefaultSystemDpi) > 0);
    UI_TEST_ASSERT(SCALE_DPI_VALUE(1, 192) > 0);
}

/*
* Test_UIConstants
*
* Purpose:
*
* Sanity-check compile-time UI layout constants to catch obviously
* broken values early.
*
*/
static VOID Test_UIConstants(VOID)
{
    UI_TEST_ASSERT(DefaultSystemDpi == 96);
    UI_TEST_ASSERT(SplitterSize > 0);
    UI_TEST_ASSERT(SplitterMargin > 0);
    // The usable area on each side of the splitter must be meaningful.
    UI_TEST_ASSERT(SplitterMargin > SplitterSize);
    UI_TEST_ASSERT(MAIN_OBJLIST_COLUMN_COUNT == 3);
}

/*
* Test_MainWindowHandles
*
* Purpose:
*
* Verify that every top-level UI handle created during initialisation
* is non-NULL and refers to a live window.
*
*/
static VOID Test_MainWindowHandles(VOID)
{
    UI_TEST_ASSERT(g_hwndMain != NULL);
    UI_TEST_ASSERT(IsWindow(g_hwndMain));

    UI_TEST_ASSERT(g_hwndObjectTree != NULL);
    UI_TEST_ASSERT(IsWindow(g_hwndObjectTree));

    UI_TEST_ASSERT(g_hwndObjectList != NULL);
    UI_TEST_ASSERT(IsWindow(g_hwndObjectList));

    UI_TEST_ASSERT(g_hwndStatusBar != NULL);
    UI_TEST_ASSERT(IsWindow(g_hwndStatusBar));

    UI_TEST_ASSERT(g_hwndToolBar != NULL);
    UI_TEST_ASSERT(IsWindow(g_hwndToolBar));

    UI_TEST_ASSERT(g_hwndSplitter != NULL);
    UI_TEST_ASSERT(IsWindow(g_hwndSplitter));
}

/*
* Test_MainWindowState
*
* Purpose:
*
* Verify the main window is in the expected visible, enabled state
* and has a menu bar and a registered window class.
*
*/
static VOID Test_MainWindowState(VOID)
{
    UI_TEST_ASSERT(IsWindowVisible(g_hwndMain));
    UI_TEST_ASSERT(IsWindowEnabled(g_hwndMain));
    UI_TEST_ASSERT(GetMenu(g_hwndMain) != NULL);
    UI_TEST_ASSERT(g_WinObj.MainWindowClassAtom != 0);
}

/*
* Test_MainMenuStructure
*
* Purpose:
*
* Verify that the menu bar contains all six expected top-level entries
* (File, View, Object, Find, Extras, Help) and that each has a submenu.
*
*/
static VOID Test_MainMenuStructure(VOID)
{
    HMENU hMainMenu = GetMenu(g_hwndMain);

    if (hMainMenu == NULL)
        return;

    // Six top-level entries: File, View, Object, Find, Extras, Help.
    UI_TEST_ASSERT(GetMenuItemCount(hMainMenu) >= 6);

    UI_TEST_ASSERT(GetSubMenu(hMainMenu, IDMM_FILE)   != NULL);
    UI_TEST_ASSERT(GetSubMenu(hMainMenu, IDMM_VIEW)   != NULL);
    UI_TEST_ASSERT(GetSubMenu(hMainMenu, IDMM_OBJECT) != NULL);
    UI_TEST_ASSERT(GetSubMenu(hMainMenu, IDMM_FIND)   != NULL);
    UI_TEST_ASSERT(GetSubMenu(hMainMenu, IDMM_EXTRAS) != NULL);
    UI_TEST_ASSERT(GetSubMenu(hMainMenu, IDMM_HELP)   != NULL);
}

/*
* Test_ListViewConfiguration
*
* Purpose:
*
* Verify the main object list view has the correct column count and the
* extended styles needed for a usable file-browser-style list.
*
*/
static VOID Test_ListViewConfiguration(VOID)
{
    DWORD lvExStyle;
    HWND  hHeader;

    hHeader = ListView_GetHeader(g_hwndObjectList);
    UI_TEST_ASSERT(hHeader != NULL);

    if (hHeader) {
        UI_TEST_ASSERT(Header_GetItemCount(hHeader) == MAIN_OBJLIST_COLUMN_COUNT);
    }

    lvExStyle = ListView_GetExtendedListViewStyle(g_hwndObjectList);
    UI_TEST_ASSERT((lvExStyle & LVS_EX_FULLROWSELECT) != 0);
    UI_TEST_ASSERT((lvExStyle & LVS_EX_LABELTIP)      != 0);
    UI_TEST_ASSERT((lvExStyle & LVS_EX_DOUBLEBUFFER)  != 0);
}

/*
* Test_TreeViewConfiguration
*
* Purpose:
*
* Verify the object tree view has the expected navigation styles
* (buttons, connector lines) and is populated with at least the root item.
*
*/
static VOID Test_TreeViewConfiguration(VOID)
{
    LONG tvStyle = GetWindowLong(g_hwndObjectTree, GWL_STYLE);

    UI_TEST_ASSERT((tvStyle & TVS_HASBUTTONS)  != 0);
    UI_TEST_ASSERT((tvStyle & TVS_HASLINES)    != 0);
    UI_TEST_ASSERT((tvStyle & TVS_LINESATROOT) != 0);

    UI_TEST_ASSERT(IsWindowVisible(g_hwndObjectTree));

    // At least the root "\" directory must appear after ListObjectDirectoryTree.
    UI_TEST_ASSERT(TreeView_GetRoot(g_hwndObjectTree) != NULL);
}

/*
* Test_ToolbarConfiguration
*
* Purpose:
*
* Verify the main toolbar is visible and has at least one button.
*
*/
static VOID Test_ToolbarConfiguration(VOID)
{
    INT buttonCount;

    UI_TEST_ASSERT(IsWindowVisible(g_hwndToolBar));

    buttonCount = (INT)SendMessage(g_hwndToolBar, TB_BUTTONCOUNT, 0, 0);
    UI_TEST_ASSERT(buttonCount > 0);
}

/*
* Test_KeyboardNavigation
*
* Purpose:
*
* Verify that the primary interactive controls participate in keyboard
* tab-order navigation (WS_TABSTOP).
*
*/
static VOID Test_KeyboardNavigation(VOID)
{
    LONG tvStyle = GetWindowLong(g_hwndObjectTree, GWL_STYLE);
    LONG lvStyle = GetWindowLong(g_hwndObjectList, GWL_STYLE);

    UI_TEST_ASSERT((tvStyle & WS_TABSTOP) != 0);
    UI_TEST_ASSERT((lvStyle & WS_TABSTOP) != 0);
}

/*
* Test_WindowTitle
*
* Purpose:
*
* Verify the main window has a non-empty title string.
*
*/
static VOID Test_WindowTitle(VOID)
{
    WCHAR szTitle[256] = { 0 };
    INT len;

    len = GetWindowText(g_hwndMain, szTitle, RTL_NUMBER_OF(szTitle));
    UI_TEST_ASSERT(len > 0);
    UI_TEST_ASSERT(_strlen(szTitle) > 0);
}

/*
* TestUI
*
* Purpose:
*
* Entry point for all UI usability tests.
* Called in debug builds after the main window and all child controls
* are fully initialised, just before the message loop is entered.
*
*/
VOID TestUI(
    VOID
)
{
    g_UIFailCount = 0;

    DbgPrint("[UI] UI usability tests begin\n");

    Test_DpiScaling();
    Test_UIConstants();
    Test_MainWindowHandles();
    Test_MainWindowState();
    Test_MainMenuStructure();
    Test_ListViewConfiguration();
    Test_TreeViewConfiguration();
    Test_ToolbarConfiguration();
    Test_KeyboardNavigation();
    Test_WindowTitle();

    if (g_UIFailCount == 0) {
        DbgPrint("[UI] UI usability tests PASSED (0 failures)\n");
    }
    else {
        DbgPrint("[UI] UI usability tests FAILED (%lu failure(s))\n", g_UIFailCount);
    }
}
