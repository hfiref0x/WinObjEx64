/*

Tree-List custom control header file

Version 1.1

Feb/22/2016

*/

#define WC_TREELISTA            "CustomTreeList"
#define WC_TREELISTW            L"CustomTreeList"

#ifdef UNICODE
#define WC_TREELIST             WC_TREELISTW
#else
#define WC_TREELIST             WC_TREELISTA
#endif

#define TL_TREECONTROL_SLOT		0
#define TL_HEADERCONTROL_SLOT	sizeof(HANDLE)
#define TL_TREEWNDPROC_SLOT		sizeof(HANDLE)*2
#define TL_HEAP_SLOT			sizeof(HANDLE)*3
#define TL_TOOLTIPS_SLOT		sizeof(HANDLE)*4
#define TL_TOOLTIPSBUFFER_SLOT	sizeof(HANDLE)*5

#define TL_SIZEOF_PRIVATEBUFFER	(sizeof(TCHAR) * (MAX_PATH + 1))

#define TLF_BGCOLOR_SET			0x01
#define TLF_FONTCOLOR_SET		0x02

#define TLSTYLE_COLAUTOEXPAND	0x01

typedef struct _TL_SUBITEMS {
    ULONG		ColorFlags;
    COLORREF	BgColor;
    COLORREF	FontColor;
    ULONG		Count;
    LPTSTR		Text[1];
} TL_SUBITEMS, *PTL_SUBITEMS;

ATOM InitializeTreeListControl();

#define TreeList_GetTreeItem(hwnd, lpitem, subitems) \
    (BOOL)SNDMSG((hwnd), TVM_GETITEM, (WPARAM)(LPTVITEMEX)(lpitem), (LPARAM)(PTL_SUBITEMS *)(subitems))

#define TreeList_InsertTreeItem(hwnd, lpis, subitems) \
    (HTREEITEM)SNDMSG((hwnd), TVM_INSERTITEM, (WPARAM)(LPTV_INSERTSTRUCT)(lpis), (LPARAM)(PTL_SUBITEMS)(subitems))

#define TreeList_InsertHeaderItem(hwndHD, i, phdi) \
    (int)SNDMSG((hwndHD), HDM_INSERTITEM, (WPARAM)(int)(i), (LPARAM)(const HD_ITEM *)(phdi))

#define TreeList_ClearTree(hwnd) \
    (BOOL)SNDMSG((hwnd), TVM_DELETEITEM, 0, (LPARAM)TVI_ROOT)

#define TreeList_GetSelection(hwnd) \
    (HTREEITEM)SNDMSG((hwnd), TVM_GETNEXTITEM, TVGN_CARET, 0)
