#include "rtltypes.h"

char *_strchr_a(const char *s, const char ch)
{
    char *p = (char *)s;

    if (s == 0)
        return 0;

    while (*p != 0) {
        if (*p == ch)
            return p;
        p++;
    }

    return 0;
}

wchar_t *_strchr_w(const wchar_t *s, const wchar_t ch)
{
    wchar_t *p = (wchar_t *)s;

    if (s == 0)
        return 0;

    while (*p != 0) {
        if (*p == ch)
            return p;
        p++;
    }

    return 0;

}
