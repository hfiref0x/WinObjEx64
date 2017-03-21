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
    LPARAM lParam,
    LPRECT rect
)
{
    TOOLINFO    tool;
    BOOL        result;

    RtlSecureZeroMemory(&tool, sizeof(tool));
    tool.cbSize = sizeof(tool);
    tool.uId = itemid;
    tool.hwnd = TreeControl;
    tool.lParam = lParam;

    result = (BOOL)SendMessage(ToolTips, TTM_GETTOOLINFO, 0, (LPARAM)&tool);

    tool.uFlags |= TTF_SUBCLASS | TTF_TRANSPARENT;
    tool.rect = *rect;
    tool.lpszText = LPSTR_TEXTCALLBACK;

    if (result)
        SendMessage(ToolTips, TTM_SETTOOLINFO, 0, (LPARAM)&tool);
    else
        SendMessage(ToolTips, TTM_ADDTOOL, 0, (LPARAM)&tool);
}

VOID TreeListUpdateTooltips(
    HWND hwndTreeList
)
{
    HWND TreeControl = (HWND)GetWindowLongPtr(hwndTreeList, TL_TREECONTROL_SLOT),
        ToolTips = (HWND)GetWindowLongPtr(hwndTreeList, TL_TOOLTIPS_SLOT),
        Header = (HWND)GetWindowLongPtr(hwndTreeList, TL_HEADERCONTROL_SLOT);

    PTL_SUBITEMS subitems;

    HTREEITEM   item = TreeView_GetRoot(TreeControl);
    RECT        rc, subrc;
    TOOLINFO    tool;
    ULONG       i = 0, c;
    LONG        cx;
    TVITEMEX    itemex;

    RtlSecureZeroMemory(&rc, sizeof(rc));
    Header_GetItemRect(Header, 0, &rc);
    cx = rc.right;

    c = (ULONG)SendMessage(ToolTips, TTM_GETTOOLCOUNT, 0, 0);
    RtlSecureZeroMemory(&tool, sizeof(tool));
    tool.cbSize = sizeof(tool);

    while (SendMessage(ToolTips, TTM_ENUMTOOLS, i, (LPARAM)&tool) && (i < c)) {
        if (!TreeView_GetItemRect(TreeControl, (HTREEITEM)(tool.uId - tool.lParam), &rc, FALSE)) {
            SendMessage(ToolTips, TTM_DELTOOL, 0, (LPARAM)&tool);
            continue;
        }
        i++;
    }

    while (item) {
        if (TreeView_GetItemRect(TreeControl, item, &rc, TRUE)) {
            RtlSecureZeroMemory(&itemex, sizeof(itemex));
            itemex.hItem = item;
            itemex.mask = TVIF_HANDLE | TVIF_PARAM;
            TreeView_GetItem(TreeControl, &itemex);

            if (rc.right > cx)
                rc.right = cx;
            AddTooltipItemSub(TreeControl, ToolTips, (UINT_PTR)item, 0, &rc);

            if (itemex.lParam) {
                subitems = (PTL_SUBITEMS)itemex.lParam;
                for (i = 0; i < subitems->Count; i++) {
                    if (!Header_GetItemRect(Header, i + 1, &subrc))
                        break;
                    subrc.top = rc.top;
                    subrc.bottom = rc.bottom;
                    AddTooltipItemSub(TreeControl, ToolTips, i + 1 + (UINT_PTR)item, i + 1, &subrc);
                }
            }

        }
        item = TreeView_GetNextVisible(TreeControl, item);
    }
}

LRESULT TreeListCustomDraw(
    HWND hwndHeader,
    LPNMTVCUSTOMDRAW pdraw
)
{
    TCHAR               textbuf[MAX_PATH];
    TVITEMEX            item;
    HBRUSH              brush;
    HPEN                pen;
    RECT                hr, ir, subr;
    SIZE                tsz;
    LONG                i, c, cx;
    PTL_SUBITEMS        subitem;
    HGDIOBJ             prev;

    if ((pdraw->nmcd.dwDrawStage & CDDS_ITEM) == 0)
        return CDRF_NOTIFYITEMDRAW;

    RtlSecureZeroMemory(&item, sizeof(item));
    RtlSecureZeroMemory(&textbuf, sizeof(textbuf));
    item.mask = TVIF_TEXT | TVIF_HANDLE | TVIF_PARAM | TVIF_CHILDREN | TVIF_STATE;
    item.hItem = (HTREEITEM)pdraw->nmcd.dwItemSpec;
    item.cchTextMax = (sizeof(textbuf) / sizeof(TCHAR)) - 1;
    item.pszText = textbuf;
    TreeView_GetItem(pdraw->nmcd.hdr.hwndFrom, &item);
    subitem = (PTL_SUBITEMS)item.lParam;

    RtlSecureZeroMemory(&hr, sizeof(hr));
    TreeView_GetItemRect(pdraw->nmcd.hdr.hwndFrom, (HTREEITEM)pdraw->nmcd.dwItemSpec, &ir, TRUE);
    //FillRect(pdraw->nmcd.hdc, &pdraw->nmcd.rc, GetSysColorBrush(COLOR_WINDOW));

    if (item.cChildren == 1) {
        RtlSecureZeroMemory(&tsz, sizeof(tsz));
        if (GetThemePartSize(tl_theme, pdraw->nmcd.hdc, TVP_GLYPH, GLPS_CLOSED, NULL, TS_TRUE, &tsz) != S_OK) {
            tsz.cx = 8;
            tsz.cy = 8;
        }

        subr.top = ir.top + (((ir.bottom - ir.top) - tsz.cy) / 2);
        subr.bottom = subr.top + tsz.cy;
        subr.left = ir.left - tsz.cx - 3;
        subr.right = ir.left - 3;

        if ((item.state & TVIS_EXPANDED) == 0)
            i = GLPS_CLOSED;
        else
            i = GLPS_OPENED;

        DrawThemeBackground(tl_theme, pdraw->nmcd.hdc, TVP_GLYPH, i, &subr, NULL);
    }

    cx = 0;
    c = Header_GetItemCount(hwndHeader);
    for (i = 0; i < c; i++) {
        RtlSecureZeroMemory(&hr, sizeof(hr));
        Header_GetItemRect(hwndHeader, i, &hr);
        if (hr.right > cx)
            cx = hr.right;
    }

    if ((subitem) && ((pdraw->nmcd.uItemState & CDIS_FOCUS)) == 0) {
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

    Header_GetItemRect(hwndHeader, 0, &hr);
    subr.right = hr.right - 3;
    subr.left += 3;
    DrawText(pdraw->nmcd.hdc, textbuf, -1, &subr, DT_END_ELLIPSIS | DT_VCENTER | DT_SINGLELINE);

    ir.right = cx;

    pen = CreatePen(PS_SOLID, 1, GetSysColor(COLOR_MENUBAR));
    prev = SelectObject(pdraw->nmcd.hdc, pen);

    for (i = 0; i < c; i++) {
        RtlSecureZeroMemory(&hr, sizeof(hr));
        Header_GetItemRect(hwndHeader, i, &hr);

        if ((i > 0) && subitem)
            if (i <= (LONG)subitem->Count)
                if (subitem->Text[i - 1]) {
                    subr.top = ir.top;
                    subr.bottom = ir.bottom;
                    subr.left = hr.left + 3;
                    subr.right = hr.right - 3;
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
    LONG        cx, i, c, headerheight;
    RECT        hr, ir;
    SCROLLINFO  scroll;

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

                if (TreeView_GetItemRect(hwnd, (HTREEITEM)(hdr->hdr.idFrom - tool.lParam), &rc, TRUE)) {

                    if (tool.lParam > 0) {
                        Header_GetItemRect((HWND)GetWindowLongPtr(BaseWindow, TL_HEADERCONTROL_SLOT), tool.lParam, &hr);
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
                if (!Header_GetItemRect((HWND)GetWindowLongPtr(BaseWindow, TL_HEADERCONTROL_SLOT), hdr->lParam, &hr))
                    break;

                if (!TreeView_GetItemRect(hwnd, (HTREEITEM)(hdr->hdr.idFrom - hdr->lParam), &rc, TRUE))
                    break;

                if ((hdr->lParam == 0) && (rc.right < hr.right - 1)) // is tooltip from the first column?
                    break;

                privateBuffer = (LPTSTR)GetWindowLongPtr(BaseWindow, TL_TOOLTIPSBUFFER_SLOT);
                RtlSecureZeroMemory(&itemex, sizeof(itemex));
                RtlSecureZeroMemory(privateBuffer, TL_SIZEOF_PRIVATEBUFFER);
                itemex.mask = TVIF_TEXT | TVIF_HANDLE | TVIF_PARAM;
                itemex.cchTextMax = MAX_PATH;
                itemex.pszText = privateBuffer;
                itemex.hItem = (HTREEITEM)(hdr->hdr.idFrom - hdr->lParam);
                TreeView_GetItem(hwnd, &itemex);

                if ((hdr->lParam > 0) && (itemex.lParam != 0)) {
                    subitems = (PTL_SUBITEMS)itemex.lParam;

                    rc.left = hr.left + 3;
                    rc.right = hr.right - 3;

                    dc = GetDC(hwnd);
                    SelectObject(dc, (HGDIOBJ)SendMessage(hwnd, WM_GETFONT, 0, 0));
                    DrawText(dc, subitems->Text[hdr->lParam - 1], -1, &rc, DT_VCENTER | DT_SINGLELINE | DT_CALCRECT);
                    ReleaseDC(hwnd, dc);

                    if (rc.right < hr.right - 2)
                        break;

                    _strncpy(privateBuffer, MAX_PATH, subitems->Text[hdr->lParam - 1], MAX_PATH);
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

LRESULT CALLBACK TreeListWindowProc(
    HWND hwnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam
)
{
    HWND                TreeControl, HeaderControl, ToolTip;
    PTL_SUBITEMS        newsubitems, subitems, *ppsubitems;
    TVHITTESTINFO       lhti;
    LONG                cx, headerheight;
    HANDLE              hheap;
    ULONG               i;
    RECT                hr;
    LPTSTR              s;
    NONCLIENTMETRICS    ncm;
    HFONT               font;
    LPNMHEADER          hdr;
    SCROLLINFO          scroll;
    TV_INSERTSTRUCT     ins;
    size_t              size;
    TVITEMEX            item;
    LRESULT             result;

    switch (uMsg) {
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

    case TVM_INSERTITEM:
        if (wParam == 0)
            return 0;

        hheap = (HANDLE)GetWindowLongPtr(hwnd, TL_HEAP_SLOT);

        if (!hheap)
            return 0;

        ins = *((LPTV_INSERTSTRUCT)wParam);

        if (lParam) {
            size = 0;
            subitems = (PTL_SUBITEMS)lParam;
            ins.item.mask |= TVIF_PARAM;

            for (i = 0; i < subitems->Count; i++)
                size += (_strlen(subitems->Text[i]) + 1) * sizeof(TCHAR);

            size += sizeof(TL_SUBITEMS) + (subitems->Count * sizeof(LPTSTR));
            newsubitems = HeapAlloc(hheap, 0, size);
            if (!newsubitems)
                return 0;

            RtlSecureZeroMemory(newsubitems, size);

            newsubitems->ColorFlags = subitems->ColorFlags;
            newsubitems->BgColor = subitems->BgColor;
            newsubitems->FontColor = subitems->FontColor;
            newsubitems->Count = subitems->Count;
            s = (LPTSTR)((PBYTE)newsubitems + sizeof(TL_SUBITEMS) + (subitems->Count * sizeof(LPTSTR)));
            for (i = 0; i < subitems->Count; i++) {
                newsubitems->Text[i] = s;
                _strcpy(newsubitems->Text[i], subitems->Text[i]);
                s += _strlen(subitems->Text[i]) + 1;
            }

            ins.item.lParam = (LPARAM)newsubitems;
        }
        else
            ins.item.lParam = 0;


        result = SendMessage((HWND)GetWindowLongPtr(hwnd, TL_TREECONTROL_SLOT), TVM_INSERTITEM, 0, (LPARAM)&ins);
        TreeListUpdateTooltips(hwnd);
        return result;

    case HDM_INSERTITEM:
        return SendMessage((HWND)GetWindowLongPtr(hwnd, TL_HEADERCONTROL_SLOT), HDM_INSERTITEM, wParam, lParam);

    case TVM_GETNEXTITEM:
        return SendMessage((HWND)GetWindowLongPtr(hwnd, TL_TREECONTROL_SLOT), TVM_GETNEXTITEM, wParam, lParam);

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

        RtlSecureZeroMemory(&hr, sizeof(hr));
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
        SetWindowPos(HeaderControl, 0, -scroll.nPos, 0, 0, headerheight, SWP_NOSIZE | SWP_NOZORDER);
        GetClientRect(hwnd, &hr);
        MoveWindow(TreeControl, -scroll.nPos, headerheight, hr.right + scroll.nPos, hr.bottom - headerheight, TRUE);
        break;

    case WM_SETFOCUS:
        SetFocus((HWND)GetWindowLongPtr(hwnd, TL_TREECONTROL_SLOT));
        break;

    case WM_SIZE:
        result = DefWindowProc(hwnd, uMsg, wParam, lParam);
        RtlSecureZeroMemory(&hr, sizeof(hr));
        GetClientRect(hwnd, &hr);

        RtlSecureZeroMemory(&ncm, sizeof(ncm));
        ncm.cbSize = sizeof(ncm) - sizeof(int);
        if (SystemParametersInfo(SPI_GETNONCLIENTMETRICS, sizeof(ncm) - sizeof(int), &ncm, 0)) {
            cx = ncm.iCaptionHeight;
        }
        else {
            cx = 20;
        }
        HeaderControl = (HWND)GetWindowLongPtr(hwnd, TL_HEADERCONTROL_SLOT);
        TreeControl = (HWND)GetWindowLongPtr(hwnd, TL_TREECONTROL_SLOT);

        SetWindowPos(HeaderControl, NULL, 0, 0, hr.right, cx, SWP_NOMOVE);
        SetWindowPos(TreeControl, NULL, 0, 0, hr.right, hr.bottom - cx, SWP_NOMOVE);

        UpdateWindow(HeaderControl);
        UpdateWindow(TreeControl);
        return result;

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
            font = GetStockObject(DEFAULT_GUI_FONT);
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

        /*hook*/
        SetWindowLongPtr(hwnd, TL_TREEWNDPROC_SLOT, /*old wndproc here*/SetWindowLongPtr(TreeControl, GWLP_WNDPROC, (LONG_PTR)&TreeListHookProc));

        SendMessage(TreeControl, TVM_SETEXTENDEDSTYLE, TVS_EX_DOUBLEBUFFER, TVS_EX_DOUBLEBUFFER);
        SendMessage(HeaderControl, WM_SETFONT, (WPARAM)font, TRUE);
        SetWindowLongPtr(hwnd, TL_TREECONTROL_SLOT, (LONG_PTR)TreeControl);
        SetWindowLongPtr(hwnd, TL_HEADERCONTROL_SLOT, (LONG_PTR)HeaderControl);
        SetWindowLongPtr(hwnd, TL_HEAP_SLOT, (LONG_PTR)hheap);
        SetWindowLongPtr(hwnd, TL_TOOLTIPS_SLOT, (LONG_PTR)ToolTip);
        SetWindowLongPtr(hwnd, TL_TOOLTIPSBUFFER_SLOT, (LONG_PTR)HeapAlloc(hheap, 0, TL_SIZEOF_PRIVATEBUFFER));

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
    wincls.cbWndExtra = sizeof(HWND) * 8;
    wincls.hInstance = hinst;
    wincls.hIcon = NULL;
    wincls.hCursor = (HCURSOR)LoadImage(NULL, MAKEINTRESOURCE(OCR_NORMAL), IMAGE_CURSOR, 0, 0, LR_SHARED);
    wincls.hbrBackground = NULL;
    wincls.lpszMenuName = NULL;
    wincls.lpszClassName = WC_TREELIST;
    wincls.hIconSm = 0;

    return RegisterClassEx(&wincls);
}
