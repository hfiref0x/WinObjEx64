#include "rtltypes.h"

char *_strcpyn_a(char* dest, const char* src, size_t n)
{
    size_t i = 0;
    char *p;

    if ((dest == 0) || (src == 0))
        return dest;

    p = dest;

    while (i++ != n && (*p++ = *src++));

    *p = 0;

    return dest;
}

wchar_t *_strcpyn_w(wchar_t* dest, const wchar_t* src, size_t n)
{
    size_t i = 0;
    wchar_t *p;

    if ((dest == 0) || (src == 0))
        return dest;

    p = dest;

    while (i++ != n && (*p++ = *src++));

    *p = 0;

    return dest;
}
