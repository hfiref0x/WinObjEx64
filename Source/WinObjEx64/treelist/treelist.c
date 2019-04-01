/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       TREELIST.C
*
*  VERSION:     1.27
*
*  DATE:        31 Mar 2018
*
*  TreeList control.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#define OEMRESOURCE
#include <Windows.h>
#include <Windowsx.h>
#include <CommCtrl.h>
#include <Uxtheme.h>
#include <vsstyle.h>
#include <vssym32.h>
#include "treelist.h"
#include "minirtl\minirtl.h"
#pragma comment(lib, "Uxtheme.lib")

HTHEME  tl_theme = NULL;

VOID AddTooltipItemSub(
    HWND TreeControl,
    HWND ToolTips,
    UINT_PTR itemid,
    UINT_PTR lParam,
    LPRECT rect
)
{
    TOOLINFO tool;
    RtlSecureZeroMemory(&tool, sizeof(tool));

#ifdef UNICODE
    tool.cbSize = TTTOOLINFOW_V2_SIZE;
#else
    tool.cbSize = TTTOOLINFOA_V2_SIZE;
#endif // UNICODE

    tool.uFlags = TTF_SUBCLASS | TTF_TRANSPARENT;
    tool.uId = itemid;
    tool.hwnd = TreeControl;
    tool.lParam = lParam;
    tool.rect = *rect;
    tool.lpszText = LPSTR_TEXTCALLBACK;
    SendMessage(ToolTips, TTM_ADDTOOL, 0, (LPARAM)&tool);
}

VOID TreeListUpdateTooltips(
    HWND hwndTreeList
)
{
    PTL_SUBITEMS    subitems;
    RECT            rc, subrc, treerc;
    TOOLINFO        tool;
    ULONG           ToolCount, newToolId;
    SIZE_T          i;
    LONG            cx;
    TVITEMEX        itemex;
    HWND            TreeControl = (HWND)GetWindowLongPtr(hwndTreeList, TL_TREECONTROL_SLOT),
        ToolTips = (HWND)GetWindowLongPtr(hwndTreeList, TL_TOOLTIPS_SLOT),
        Header = (HWND)GetWindowLongPtr(hwndTreeList, TL_HEADERCONTROL_SLOT);
    HTREEITEM       item = TreeView_GetRoot(TreeControl);

    ToolCount = (ULONG)SendMessage(ToolTips, TTM_GETTOOLCOUNT, 0, 0);
    RtlSecureZeroMemory(&tool, sizeof(tool));
    tool.cbSize = sizeof(tool);

    for (i = 0; i < ToolCount; i++)
    {
        if (SendMessage(ToolTips, TTM_ENUMTOOLS, 0, (LPARAM)&tool))
            SendMessage(ToolTips, TTM_DELTOOL, 0, (LPARAM)&tool);
    }

    GetClientRect(TreeControl, &treerc);
    Header_GetItemRect(Header, 0, &rc);
    cx = rc.right;
    ToolCount = 0;

    while (item) {
        while (TreeView_GetItemRect(TreeControl, item, &rc, TRUE))
        {
            RtlSecureZeroMemory(&itemex, sizeof(itemex));
            itemex.hItem = item;
            itemex.mask = TVIF_HANDLE | TVIF_PARAM;
            TreeView_GetItem(TreeControl, &itemex);

            if (rc.right > cx)
                rc.right = cx;

            if ((rc.bottom < 0) || (rc.top >= treerc.bottom))
                break;

            newToolId = ToolCount++;
            AddTooltipItemSub(TreeControl, ToolTips, newToolId, (UINT_PTR)item, &rc);

            if (!itemex.lParam)
                break;

            subitems = (PTL_SUBITEMS)itemex.lParam;
            for (i = 0; i < subitems->Count; i++) {

                if (!Header_GetItemRect(Header, i + 1, &subrc))
                    break;

                subrc.top = rc.top;
                subrc.bottom = rc.bottom;
                AddTooltipItemSub(TreeControl, ToolTips, (0x1000 * (i + 1)) + newToolId, (UINT_PTR)item, &subrc);
            }

            break;
        }
        item = TreeView_GetNextVisible(TreeControl, item);
    }
}

LRESULT TreeListCustomDraw(
    HWND hwndHeader,
    LPNMTVCUSTOMDRAW pdraw
)
{
    TCHAR           textbuf[MAX_PATH];
    TVITEMEX        item;
    HDITEM          hdritem;
    HBRUSH          brush;
    HPEN            pen;
    RECT            hr, ir, subr;
    SIZE            tsz;
    LONG            i, ColumnCount, cx;
    PTL_SUBITEMS    subitem;
    HGDIOBJ         prev;
    BOOL            ItemSelected, first_iter = TRUE;
    HIMAGELIST      ImgList;
    HTREEITEM       iparent;

    if ((pdraw->nmcd.dwDrawStage & CDDS_ITEM) == 0)
        return CDRF_NOTIFYITEMDRAW;

    ItemSelected = pdraw->nmcd.uItemState & CDIS_FOCUS;

    RtlSecureZeroMemory(&item, sizeof(item));
    RtlSecureZeroMemory(&textbuf, sizeof(textbuf));
    item.mask = TVIF_TEXT | TVIF_HANDLE | TVIF_PARAM | TVIF_CHILDREN | TVIF_STATE | TVIF_IMAGE;
    item.hItem = (HTREEITEM)pdraw->nmcd.dwItemSpec;
    item.cchTextMax = (sizeof(textbuf) / sizeof(TCHAR)) - 1;
    item.pszText = textbuf;
    TreeView_GetItem(pdraw->nmcd.hdr.hwndFrom, &item);
    subitem = (PTL_SUBITEMS)item.lParam;

    TreeView_GetItemRect(pdraw->nmcd.hdr.hwndFrom, (HTREEITEM)pdraw->nmcd.dwItemSpec, &ir, TRUE);
    ImgList = TreeView_GetImageList(pdraw->nmcd.hdr.hwndFrom, TVSIL_NORMAL);

    if ((GetWindowLongPtr(GetParent(hwndHeader), GWL_STYLE) & TLSTYLE_LINKLINES))
    {
        iparent = (HTREEITEM)pdraw->nmcd.dwItemSpec;
        cx = ir.left - 11;

        while (iparent != NULL) {

            if (TreeView_GetNextSibling(pdraw->nmcd.hdr.hwndFrom, iparent) == NULL)
            {
                if (first_iter)
                {
                    for (i = 0; i < (ir.bottom - ir.top) / 2; i += 2)
                        SetPixel(pdraw->nmcd.hdc, cx, ir.top + i, 0xe0b0b0);
                }
            }
            else
            {
                for (i = ir.top; i < ir.bottom; i += 2)
                    SetPixel(pdraw->nmcd.hdc, cx, i, 0xe0b0b0);
            }

            first_iter = FALSE;
            cx -= 19;
            iparent = TreeView_GetParent(pdraw->nmcd.hdr.hwndFrom, iparent);
        }

        if (textbuf[0] != 0)
        {
            cx = 1 + ir.top + (ir.bottom - ir.top) / 2;
            for (i = ir.left - 11; i < ir.left; i += 2)
                SetPixel(pdraw->nmcd.hdc, i, cx, 0xe0b0b0);
        }
    }

    if (ImgList != NULL)
        ImageList_Draw(ImgList, item.iImage, pdraw->nmcd.hdc, ir.left - 18, ir.top, ILD_NORMAL);

    if (item.cChildren == 1) // msdn: The item has one or more child items.
    {
        RtlSecureZeroMemory(&tsz, sizeof(tsz));
        if (GetThemePartSize(tl_theme, pdraw->nmcd.hdc, TVP_GLYPH, GLPS_CLOSED, NULL, TS_TRUE, &tsz) != S_OK) {
            tsz.cx = 8;
            tsz.cy = 8;
        }

        subr.top = ir.top + (((ir.bottom - ir.top) - tsz.cy) / 2);
        subr.bottom = subr.top + tsz.cy;
        subr.left = ir.left - tsz.cx - 3;

        if (ImgList != NULL)
            subr.left -= 38;

        subr.right = ir.left - 3;

        if ((item.state & TVIS_EXPANDED) == 0)
            i = GLPS_CLOSED;
        else
            i = GLPS_OPENED;

        FillRect(pdraw->nmcd.hdc, &subr, WHITE_BRUSH);
        DrawThemeBackground(tl_theme, pdraw->nmcd.hdc, TVP_GLYPH, i, &subr, NULL);
    }

    cx = 0;
    ColumnCount = Header_GetItemCount(hwndHeader);
    for (i = 0; i < ColumnCount; i++) {
        RtlSecureZeroMemory(&hr, sizeof(hr));
        Header_GetItemRect(hwndHeader, i, &hr);
        if (hr.right > cx)
            cx = hr.right;
    }

    if (subitem && ItemSelected == 0) {
        if (subitem->ColorFlags & TLF_BGCOLOR_SET) {
            pdraw->clrTextBk = subitem->BgColor;
            SetBkColor(pdraw->nmcd.hdc, subitem->BgColor);
        }

        if (subitem->ColorFlags & TLF_FONTCOLOR_SET) {
            pdraw->clrText = subitem->FontColor;
            SetTextColor(pdraw->nmcd.hdc, subitem->FontColor);
        }
    }

    brush = CreateSolidBrush(pdraw->clrTextBk);
    subr.top = ir.top;
    subr.bottom = ir.bottom - 1;
    subr.left = ir.left;
    subr.right = cx;
    FillRect(pdraw->nmcd.hdc, &subr, brush);
    DeleteObject(brush);

    if (!ItemSelected) {
        for (i = 1; i < ColumnCount; i++) {
            RtlSecureZeroMemory(&hr, sizeof(hr));
            Header_GetItemRect(hwndHeader, i, &hr);

            RtlSecureZeroMemory(&hdritem, sizeof(hdritem));
            hdritem.mask = HDI_LPARAM;
            Header_GetItem(hwndHeader, i, &hdritem);

            if (hdritem.lParam != 0)
            {
                brush = CreateSolidBrush((COLORREF)hdritem.lParam);
                subr.top = ir.top;
                subr.bottom = ir.bottom - 1;
                subr.left = hr.left;
                subr.right = hr.right;
                FillRect(pdraw->nmcd.hdc, &subr, brush);
                DeleteObject(brush);
            }
        }
    }

    Header_GetItemRect(hwndHeader, 0, &hr);
    subr.right = hr.right - 3;
    subr.left = ir.left + 3;
    DrawText(pdraw->nmcd.hdc, textbuf, -1, &subr, DT_END_ELLIPSIS | DT_VCENTER | DT_SINGLELINE);

    ir.right = cx;

    pen = CreatePen(PS_SOLID, 1, 0xfbf3e5);// GetSysColor(COLOR_MENUBAR));
    prev = SelectObject(pdraw->nmcd.hdc, pen);

    for (i = 0; i < ColumnCount; i++) {
        RtlSecureZeroMemory(&hr, sizeof(hr));
        Header_GetItemRect(hwndHeader, i, &hr);

        RtlSecureZeroMemory(&hdritem, sizeof(hdritem));
        hdritem.mask = HDI_LPARAM;
        Header_GetItem(hwndHeader, i, &hdritem);

        if ((i > 0) && subitem)
            if (i <= (LONG)subitem->Count)
                if (subitem->Text[i - 1]) {
                    subr.top = ir.top;
                    subr.bottom = ir.bottom;
                    subr.left = hr.left + 3;
                    subr.right = hr.right - 3;

                    if (!ItemSelected)
                    {
                        if (subitem->ColorFlags & TLF_BGCOLOR_SET) {
                            pdraw->clrTextBk = subitem->BgColor;
                            SetBkColor(pdraw->nmcd.hdc, subitem->BgColor);
                        }

                        if (hdritem.lParam != 0)
                            SetBkColor(pdraw->nmcd.hdc, (COLORREF)hdritem.lParam);
                    }

                    DrawText(pdraw->nmcd.hdc, subitem->Text[i - 1], -1, &subr, DT_END_ELLIPSIS | DT_VCENTER | DT_SINGLELINE);
                }

        MoveToEx(pdraw->nmcd.hdc, hr.left, ir.bottom - 1, NULL);
        LineTo(pdraw->nmcd.hdc, hr.right - 1, ir.bottom - 1);
        LineTo(pdraw->nmcd.hdc, hr.right - 1, ir.top - 1);
    }

    SelectObject(pdraw->nmcd.hdc, prev);
    DeleteObject(pen);

    if ((pdraw->nmcd.uItemState & CDIS_FOCUS) != 0)
        DrawFocusRect(pdraw->nmcd.hdc, &ir);

    return CDRF_SKIPDEFAULT;
}

VOID TreeListHandleHeaderNotify(
    HWND hwndBox,
    HWND hwndTree,
    HWND hwndHeader
)
{
    SCROLLINFO  scroll;
    LONG        cx, i, c, headerheight;
    RECT        hr, ir;

    RtlSecureZeroMemory(&hr, sizeof(hr));
    GetWindowRect(hwndHeader, &hr);
    headerheight = hr.bottom - hr.top;

    cx = 0;
    c = Header_GetItemCount(hwndHeader);
    for (i = 0; i < c; i++) {
        Header_GetItemRect(hwndHeader, i, &hr);
        if (hr.right > cx)
            cx = hr.right;
    }

    GetClientRect(hwndBox, &hr);
    if (cx > hr.right) {
        RtlSecureZeroMemory(&scroll, sizeof(scroll));
        scroll.cbSize = sizeof(scroll);
        scroll.fMask = SIF_ALL;
        GetScrollInfo(hwndBox, SB_HORZ, &scroll);

        GetClientRect(hwndHeader, &ir);
        if ((ir.right > cx) && (scroll.nPos + (int)scroll.nPage == scroll.nMax)) {
            SetWindowPos(hwndHeader, 0, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
            SetWindowPos(hwndTree, 0, 0, headerheight, hr.right, hr.bottom - headerheight, SWP_NOZORDER);
            scroll.nPos = 0;
        }

        scroll.nMax = cx;
        scroll.nPage = hr.right;
        SetScrollInfo(hwndBox, SB_HORZ, &scroll, TRUE);
        GetClientRect(hwndBox, &hr);
        GetWindowRect(hwndTree, &ir);
        ir.right -= ir.left;
        SetWindowPos(hwndTree, 0, 0, 0, ir.right, hr.bottom - headerheight, SWP_NOMOVE | SWP_NOZORDER);
        SetWindowPos(hwndHeader, 0, 0, 0, cx, headerheight, SWP_NOMOVE | SWP_NOZORDER);
    }
    else {
        ShowScrollBar(hwndBox, SB_HORZ, FALSE);
        GetClientRect(hwndBox, &hr);
        SetWindowPos(hwndHeader, 0, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
        SetWindowPos(hwndTree, 0, 0, headerheight, hr.right, hr.bottom - headerheight, SWP_NOZORDER);
    }
    RedrawWindow(hwndTree, NULL, NULL, RDW_INVALIDATE | RDW_NOERASE);
}

VOID TreeListAutoExpand(
    HWND hwndHeader,
    LPNMTREEVIEW nhdr
)
{
    RECT        irc;
    LONG        cx = 0, xleft = 0;
    HDITEM      hdi;
    HTREEITEM   citem = TreeView_GetChild(nhdr->hdr.hwndFrom, nhdr->itemNew.hItem);

    RtlSecureZeroMemory(&irc, sizeof(irc));
    TreeView_GetItemRect(nhdr->hdr.hwndFrom, citem, &irc, TRUE);
    xleft = irc.left;

    while (citem) {
        RtlSecureZeroMemory(&irc, sizeof(irc));
        TreeView_GetItemRect(nhdr->hdr.hwndFrom, citem, &irc, TRUE);

        if (irc.left < xleft)
            break;

        if (irc.right > cx)
            cx = irc.right;

        citem = TreeView_GetNextVisible(nhdr->hdr.hwndFrom, citem);
    }

    RtlSecureZeroMemory(&hdi, sizeof(hdi));
    hdi.mask = HDI_WIDTH;
    Header_GetItem(hwndHeader, 0, &hdi);

    if (hdi.cxy < cx + 8)
        hdi.cxy = cx + 8;

    Header_SetItem(hwndHeader, 0, &hdi);
}

LRESULT CALLBACK HeaderHookProc(
    HWND hwnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam
)
{
    HWND        BaseWindow = GetParent(hwnd);
    WNDPROC     OriginalTreeProc = (WNDPROC)GetWindowLongPtr(BaseWindow, TL_HEADERWNDPROC_SLOT);
    HDC         dc;
    LRESULT     retv;
    RECT        rc;
    HPEN        pen, prev;

    retv = OriginalTreeProc(hwnd, uMsg, wParam, lParam);
    if (uMsg != WM_PAINT)
        return retv;

    GetClientRect(hwnd, &rc);
    --rc.bottom;

    dc = GetDC(hwnd);
    pen = CreatePen(PS_SOLID, 1, 0xfbf3e5);
    prev = (HPEN)SelectObject(dc, (HGDIOBJ)pen);

    MoveToEx(dc, 0, rc.bottom, NULL);
    LineTo(dc, rc.right, rc.bottom);

    SelectObject(dc, prev);
    ReleaseDC(hwnd, dc);
    DeleteObject(pen);

    return retv;
}

LRESULT CALLBACK TreeListHookProc(
    HWND hwnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam
)
{
    HWND            BaseWindow = GetParent(hwnd);
    WNDPROC         OriginalTreeProc = (WNDPROC)GetWindowLongPtr(BaseWindow, TL_TREEWNDPROC_SLOT);
    LPNMTTDISPINFO  hdr;
    LPTSTR          privateBuffer;
    TVITEMEX        itemex;
    RECT            rc, hr;
    PTL_SUBITEMS    subitems;
    TOOLINFO        tool;
    HDC             dc;
    ULONG_PTR       subid;

    switch (uMsg) {
    case WM_NOTIFY:
        hdr = (LPNMTTDISPINFO)lParam;
        if (hdr->hdr.hwndFrom == (HWND)GetWindowLongPtr(BaseWindow, TL_TOOLTIPS_SLOT)) {
            switch (hdr->hdr.code) {
            case TTN_SHOW:

                RtlSecureZeroMemory(&tool, sizeof(tool));
                tool.cbSize = sizeof(tool);
                tool.uId = hdr->hdr.idFrom;
                tool.hwnd = hwnd;
                SendMessage(hdr->hdr.hwndFrom, TTM_GETTOOLINFO, 0, (LPARAM)&tool);

                if (TreeView_GetItemRect(hwnd, (HTREEITEM)tool.lParam, &rc, TRUE)) {

                    subid = (tool.uId & ((ULONG_PTR)~0xfff)) >> 12;
                    if (subid > 0) {
                        Header_GetItemRect((HWND)GetWindowLongPtr(BaseWindow, TL_HEADERCONTROL_SLOT), subid, &hr);
                        rc.left = hr.left;
                        rc.right = hr.right;
                    }

                    rc.left += 3;
                    rc.top += 1;

                    ClientToScreen(hwnd, (LPPOINT)&rc);
                    SendMessage(hdr->hdr.hwndFrom, TTM_ADJUSTRECT, TRUE, (LPARAM)&rc);
                    SetWindowPos(hdr->hdr.hwndFrom, 0, rc.left, rc.top, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOREDRAW);
                    return TRUE;
                }
                break;

            case TTN_GETDISPINFO:

                subid = (hdr->hdr.idFrom & ((ULONG_PTR)~0xfff)) >> 12;
                if (!Header_GetItemRect((HWND)GetWindowLongPtr(BaseWindow, TL_HEADERCONTROL_SLOT), subid, &hr))
                    break;

                if (!TreeView_GetItemRect(hwnd, (HTREEITEM)hdr->lParam, &rc, TRUE))
                    break;

                if ((subid == 0) && (rc.right < hr.right - 1)) // is tooltip from the first column?
                    break;

                privateBuffer = (LPTSTR)GetWindowLongPtr(BaseWindow, TL_TOOLTIPSBUFFER_SLOT);
                privateBuffer[0] = 0;

                RtlSecureZeroMemory(&itemex, sizeof(itemex));
                itemex.mask = TVIF_TEXT | TVIF_HANDLE | TVIF_PARAM;
                itemex.cchTextMax = MAX_PATH;
                itemex.pszText = privateBuffer;
                itemex.hItem = (HTREEITEM)hdr->lParam;
                TreeView_GetItem(hwnd, &itemex);

                if ((subid > 0) && (itemex.lParam != 0)) {
                    subitems = (PTL_SUBITEMS)itemex.lParam;

                    rc.left = hr.left + 3;
                    rc.right = hr.right - 3;

                    dc = GetDC(hwnd);
                    SelectObject(dc, (HGDIOBJ)SendMessage(hwnd, WM_GETFONT, 0, 0));

                    /*fake DrawText for calculating bounding rectangle*/
                    DrawText(dc, subitems->Text[subid - 1], -1, &rc, DT_VCENTER | DT_SINGLELINE | DT_CALCRECT);

                    ReleaseDC(hwnd, dc);

                    if (rc.right < hr.right - 2)
                        break;

                    _strncpy(privateBuffer, MAX_PATH, subitems->Text[subid - 1], MAX_PATH);
                }

                hdr->lpszText = privateBuffer;

                break;
            }
        }
        break;

    case WM_PAINT:

        TreeListUpdateTooltips(BaseWindow);
        break;
    }

    return OriginalTreeProc(hwnd, uMsg, wParam, lParam);
}

PTL_SUBITEMS PackSubitems(HANDLE hHeap, IN PTL_SUBITEMS Subitems)
{
    PTL_SUBITEMS    newsubitems;
    size_t          strings_size, header_size;
    ULONG           i;
    LPTSTR          strings;

    /*
    size of header + variable length array .Text[1] part
    */
    header_size = sizeof(TL_SUBITEMS) + (Subitems->Count * sizeof(LPTSTR));

    /*
    total size of all strings including terminating zeros
    */

    strings_size = 0;
    for (i = 0; i < Subitems->Count; i++)
        strings_size += (_strlen(Subitems->Text[i]) + 1) * sizeof(TCHAR);

    newsubitems = (PTL_SUBITEMS)HeapAlloc(hHeap, 0, header_size + strings_size);
    if (!newsubitems)
        return NULL;

    strings = (LPTSTR)((PBYTE)newsubitems + header_size);

    newsubitems->UserParam = Subitems->UserParam;
    newsubitems->ColorFlags = Subitems->ColorFlags;
    newsubitems->BgColor = Subitems->BgColor;
    newsubitems->FontColor = Subitems->FontColor;
    newsubitems->Count = Subitems->Count;

    for (i = 0; i < Subitems->Count; i++) {
        newsubitems->Text[i] = strings;
        _strcpy(newsubitems->Text[i], Subitems->Text[i]);
        strings += _strlen(Subitems->Text[i]) + 1;
    }

    return newsubitems;
}

LRESULT CALLBACK TreeListWindowProc(
    HWND hwnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam
)
{
    HWND            TreeControl, HeaderControl, ToolTip;
    PTL_SUBITEMS    subitems, *ppsubitems;
    TVHITTESTINFO   lhti;
    LONG            cx, headerheight;
    HANDLE          hheap;
    RECT            hr;
    HFONT           font;
    LPNMHEADER      hdr;
    SCROLLINFO      scroll;
    TVITEMEX        item;
    LRESULT         result;

    NONCLIENTMETRICS    ncm;
    TV_INSERTSTRUCT     ins;

    switch (uMsg) {

    case TVM_ENSUREVISIBLE:

        TreeControl = (HWND)GetWindowLongPtr(hwnd, TL_TREECONTROL_SLOT);
        SendMessage(TreeControl, TVM_ENSUREVISIBLE, 0, lParam);
        return SendMessage(TreeControl, TVM_SELECTITEM, TVGN_CARET, lParam);

        break;

    case TVM_GETITEM:

        if (wParam == 0)
            return 0;

        item = *((LPTVITEMEX)wParam);
        ppsubitems = (PTL_SUBITEMS *)lParam;

        if (ppsubitems)
            item.mask |= TVIF_PARAM;

        result = SendMessage((HWND)GetWindowLongPtr(hwnd, TL_TREECONTROL_SLOT), TVM_GETITEM, 0, (LPARAM)&item);

        if (ppsubitems) {
            *ppsubitems = (PTL_SUBITEMS)item.lParam;
            item.lParam = 0;
            item.mask &= ~TVIF_PARAM;
        }

        *((LPTVITEMEX)wParam) = item;

        return result;

    case TVM_SETITEM:

        item = *((LPTVITEMEX)wParam);
        ppsubitems = (PTL_SUBITEMS *)lParam;

        hheap = (HANDLE)GetWindowLongPtr(hwnd, TL_HEAP_SLOT);
        if (!hheap)
            return 0;

        subitems = NULL;
        if (ppsubitems)
        {
            item.mask |= TVIF_PARAM;
            result = SendMessage((HWND)GetWindowLongPtr(hwnd, TL_TREECONTROL_SLOT), TVM_GETITEM, 0, (LPARAM)&item);
            if (!result)
                return FALSE;

            item.mask |= TVIF_PARAM;
            subitems = (PTL_SUBITEMS)item.lParam;
            item.lParam = (LPARAM)PackSubitems(hheap, (PTL_SUBITEMS)lParam);
        }

        result = SendMessage((HWND)GetWindowLongPtr(hwnd, TL_TREECONTROL_SLOT), TVM_SETITEM, 0, (LPARAM)&item);
        HeapFree(hheap, 0, subitems);
        return result;

    case TVM_INSERTITEM:

        if (wParam == 0)
            return 0;

        hheap = (HANDLE)GetWindowLongPtr(hwnd, TL_HEAP_SLOT);
        if (!hheap)
            return 0;

        ins = *((LPTV_INSERTSTRUCT)wParam);

        if (lParam) {
            ins.item.mask |= TVIF_PARAM;
            ins.item.lParam = (LPARAM)PackSubitems(hheap, (PTL_SUBITEMS)lParam);
        }
        else
            ins.item.lParam = 0;

        return SendMessage((HWND)GetWindowLongPtr(hwnd, TL_TREECONTROL_SLOT), TVM_INSERTITEM, 0, (LPARAM)&ins);

    case HDM_INSERTITEM:

        return SendMessage((HWND)GetWindowLongPtr(hwnd, TL_HEADERCONTROL_SLOT), HDM_INSERTITEM, wParam, lParam);

    case TVM_GETNEXTITEM:

        return SendMessage((HWND)GetWindowLongPtr(hwnd, TL_TREECONTROL_SLOT), TVM_GETNEXTITEM, wParam, lParam);

    case TVM_EXPAND:

        return SendMessage((HWND)GetWindowLongPtr(hwnd, TL_TREECONTROL_SLOT), TVM_EXPAND, wParam, lParam);

    case TVM_SETIMAGELIST:

        return SendMessage((HWND)GetWindowLongPtr(hwnd, TL_TREECONTROL_SLOT), TVM_SETIMAGELIST, wParam, lParam);

    case TVM_DELETEITEM:

        if (lParam == (LPARAM)TVI_ROOT) {
            SendMessage((HWND)GetWindowLongPtr(hwnd, TL_TREECONTROL_SLOT), TVM_DELETEITEM, 0, (LPARAM)TVI_ROOT);

            hheap = (HANDLE)GetWindowLongPtr(hwnd, TL_HEAP_SLOT);
            SetWindowLongPtr(hwnd, TL_HEAP_SLOT, 0);
            HeapDestroy(hheap);

            hheap = HeapCreate(0, 0, 0);
            if (hheap == NULL)
                return FALSE;

            SetWindowLongPtr(hwnd, TL_HEAP_SLOT, (LONG_PTR)hheap);
            SetWindowLongPtr(hwnd, TL_TOOLTIPSBUFFER_SLOT, (LONG_PTR)HeapAlloc(hheap, 0, TL_SIZEOF_PRIVATEBUFFER));

            return TRUE;
        }
        break;

    case WM_CONTEXTMENU:

        TreeControl = (HWND)GetWindowLongPtr(hwnd, TL_TREECONTROL_SLOT);
        lhti.flags = 0;
        lhti.hItem = NULL;
        lhti.pt.x = GET_X_LPARAM(lParam);
        lhti.pt.y = GET_Y_LPARAM(lParam);
        ScreenToClient(TreeControl, &lhti.pt);
        TreeView_HitTest(TreeControl, &lhti);
        if (lhti.hItem)
            TreeView_SelectItem(TreeControl, lhti.hItem);

        return SendMessage(GetParent(hwnd), WM_CONTEXTMENU, wParam, lParam);

    case WM_NOTIFY:

        hdr = (LPNMHEADER)lParam;
        HeaderControl = (HWND)GetWindowLongPtr(hwnd, TL_HEADERCONTROL_SLOT);
        TreeControl = (HWND)GetWindowLongPtr(hwnd, TL_TREECONTROL_SLOT);

        if (hdr->hdr.hwndFrom == TreeControl) {
            switch (hdr->hdr.code) {
            case NM_CUSTOMDRAW:
                return TreeListCustomDraw(HeaderControl, (LPNMTVCUSTOMDRAW)lParam);

            case TVN_ITEMEXPANDED:
                if ((((LPNMTREEVIEW)lParam)->action == TVE_EXPAND) && (GetWindowLongPtr(hwnd, GWL_STYLE) & TLSTYLE_COLAUTOEXPAND))
                    TreeListAutoExpand(HeaderControl, (LPNMTREEVIEW)lParam);
                TreeListUpdateTooltips(hwnd);
                break;

            default:
                return SendMessage(GetParent(hwnd), uMsg, wParam, lParam);
            }
            /* break to DefWindowProc */
            break;
        }

        if (hdr->hdr.hwndFrom == HeaderControl) {
            switch (hdr->hdr.code) {
            case HDN_ITEMCHANGED:
                TreeListHandleHeaderNotify(hwnd, TreeControl, HeaderControl);
                break;
            case HDN_ITEMCHANGING:
                if (((hdr->pitem->mask & HDI_WIDTH) != 0) && (hdr->iItem == 0) && (hdr->pitem->cxy < 120))
                    return TRUE;
                break;
            }
        }
        break;

    case WM_HSCROLL:

        TreeControl = (HWND)GetWindowLongPtr(hwnd, TL_TREECONTROL_SLOT);
        HeaderControl = (HWND)GetWindowLongPtr(hwnd, TL_HEADERCONTROL_SLOT);

        GetWindowRect(HeaderControl, &hr);
        headerheight = hr.bottom - hr.top;

        RtlSecureZeroMemory(&scroll, sizeof(scroll));
        scroll.cbSize = sizeof(scroll);
        scroll.fMask = SIF_ALL;
        GetScrollInfo(hwnd, SB_HORZ, &scroll);

        scroll.fMask = SIF_ALL;
        cx = scroll.nMax - scroll.nPage;

        switch (LOWORD(wParam)) {
        case SB_LINELEFT:
            scroll.nPos -= 16;
            break;
        case SB_LINERIGHT:
            scroll.nPos += 16;
            break;
        case SB_THUMBTRACK:
            scroll.nPos = scroll.nTrackPos;
            break;
        case SB_PAGELEFT:
            scroll.nPos -= cx;
            break;
        case SB_PAGERIGHT:
            scroll.nPos += cx;
            break;
        }

        if (scroll.nPos < 0)
            scroll.nPos = 0;
        if (scroll.nPos > cx)
            scroll.nPos = cx;

        SetScrollInfo(hwnd, SB_HORZ, &scroll, TRUE);
        SetWindowPos(HeaderControl, 0, -scroll.nPos, 0, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
        GetClientRect(hwnd, &hr);
        MoveWindow(TreeControl, -scroll.nPos, headerheight, hr.right + scroll.nPos, hr.bottom - headerheight, TRUE);
        break;

    case WM_SETFOCUS:
        SetFocus((HWND)GetWindowLongPtr(hwnd, TL_TREECONTROL_SLOT));
        break;

    case WM_SIZE:
        HeaderControl = (HWND)GetWindowLongPtr(hwnd, TL_HEADERCONTROL_SLOT);
        TreeControl = (HWND)GetWindowLongPtr(hwnd, TL_TREECONTROL_SLOT);

        GetWindowRect(HeaderControl, &hr);
        headerheight = hr.bottom - hr.top;

        RtlSecureZeroMemory(&scroll, sizeof(scroll));
        scroll.cbSize = sizeof(scroll);
        scroll.fMask = SIF_ALL;
        GetScrollInfo(hwnd, SB_HORZ, &scroll);

        GetClientRect(hwnd, &hr);
        MoveWindow(HeaderControl, -scroll.nPos, 0, hr.right + scroll.nPos, headerheight, TRUE);
        MoveWindow(TreeControl, -scroll.nPos, headerheight, hr.right + scroll.nPos, hr.bottom - headerheight, TRUE);
        return 0;

    case WM_CREATE:
        hheap = HeapCreate(0, 0, 0);
        if (hheap == NULL)
            return -1;

        RtlSecureZeroMemory(&hr, sizeof(hr));
        GetClientRect(hwnd, &hr);

        RtlSecureZeroMemory(&ncm, sizeof(ncm));
        ncm.cbSize = sizeof(ncm) - sizeof(int);
        if (SystemParametersInfo(SPI_GETNONCLIENTMETRICS, sizeof(ncm) - sizeof(int), &ncm, 0)) {
            font = CreateFontIndirect(&ncm.lfMenuFont);
            cx = ncm.iCaptionHeight;
        }
        else {
            font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
            cx = 20;
        }

        HeaderControl = CreateWindowEx(0, WC_HEADER, NULL,
            WS_VISIBLE | WS_CHILD | HDS_FULLDRAG, 0, 0, hr.right, cx, hwnd, NULL, NULL, NULL);
        TreeControl = CreateWindowEx(0, WC_TREEVIEW, NULL,
            WS_VISIBLE | WS_CHILD | TVS_NOHSCROLL | TVS_HASBUTTONS | TVS_LINESATROOT | TVS_FULLROWSELECT | TVS_NOTOOLTIPS | TVS_SHOWSELALWAYS,
            0, cx, hr.right, hr.bottom - cx, hwnd, NULL, NULL, NULL);

        ToolTip = CreateWindowEx(WS_EX_TRANSPARENT | WS_EX_TOPMOST, TOOLTIPS_CLASS, NULL, TTS_NOPREFIX, 0, 0, 0, 0, hwnd, NULL, NULL, NULL);
        SendMessage(ToolTip, TTM_SETDELAYTIME, TTDT_INITIAL, 0);
        SendMessage(ToolTip, TTM_SETDELAYTIME, TTDT_RESHOW, 0);

        /*hooks*/
        SetWindowLongPtr(hwnd, TL_TREEWNDPROC_SLOT,
            /*old wndproc here*/
            SetWindowLongPtr(TreeControl, GWLP_WNDPROC, (LONG_PTR)&TreeListHookProc));

        SetWindowLongPtr(hwnd, TL_HEADERWNDPROC_SLOT,
            /*old wndproc here*/
            SetWindowLongPtr(HeaderControl, GWLP_WNDPROC, (LONG_PTR)&HeaderHookProc));

        SendMessage(TreeControl, TVM_SETEXTENDEDSTYLE, TVS_EX_DOUBLEBUFFER, TVS_EX_DOUBLEBUFFER);
        SendMessage(HeaderControl, WM_SETFONT, (WPARAM)font, TRUE);
        SetWindowLongPtr(hwnd, TL_TREECONTROL_SLOT, (LONG_PTR)TreeControl);
        SetWindowLongPtr(hwnd, TL_HEADERCONTROL_SLOT, (LONG_PTR)HeaderControl);
        SetWindowLongPtr(hwnd, TL_HEAP_SLOT, (LONG_PTR)hheap);
        SetWindowLongPtr(hwnd, TL_TOOLTIPS_SLOT, (LONG_PTR)ToolTip);
        SetWindowLongPtr(hwnd, TL_TOOLTIPSBUFFER_SLOT, (LONG_PTR)HeapAlloc(hheap, 0, TL_SIZEOF_PRIVATEBUFFER));

        SetWindowTheme(TreeControl, TEXT("Explorer"), NULL);
        SetWindowTheme(HeaderControl, TEXT("Explorer"), NULL);

        if (tl_theme == NULL)
            tl_theme = OpenThemeData(TreeControl, VSCLASS_TREEVIEW);

        break;

    case WM_DESTROY:
        DestroyWindow((HWND)GetWindowLongPtr(hwnd, TL_TOOLTIPS_SLOT));
        HeapDestroy((HANDLE)GetWindowLongPtr(hwnd, TL_HEAP_SLOT));
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

ATOM InitializeTreeListControl()
{
    WNDCLASSEX  wincls;
    HINSTANCE   hinst = GetModuleHandle(NULL);

    wincls.cbSize = sizeof(WNDCLASSEX);
    wincls.style = 0;
    wincls.lpfnWndProc = &TreeListWindowProc;
    wincls.cbClsExtra = 0;
    wincls.cbWndExtra = sizeof(HANDLE) * 16;
    wincls.hInstance = hinst;
    wincls.hIcon = NULL;
    wincls.hCursor = (HCURSOR)LoadImage(NULL, MAKEINTRESOURCE(OCR_NORMAL), IMAGE_CURSOR, 0, 0, LR_SHARED);
    wincls.hbrBackground = NULL;
    wincls.lpszMenuName = NULL;
    wincls.lpszClassName = WC_TREELIST;
    wincls.hIconSm = 0;

    return RegisterClassEx(&wincls);
}
