#include "rtltypes.h"

unsigned long hextoul_a(char *s)
{
	unsigned long	r = 0;
	char			c;

	if (s == 0)
		return 0;

	while (*s != 0) {
		c = locase_a(*s);
		s++;
		if (_isdigit_a(c))
			r = 16 * r + (c - '0');
		else
			if ((c >= 'a') && (c <= 'f'))
				r = 16 * r + (c - 'a' + 10);
			else
				break;
	}
	return r;
}

unsigned long hextoul_w(wchar_t *s)
{
	unsigned long	r = 0;
	wchar_t			c;

	if ( s==0 )
		return 0;

	while ( *s!=0 ) {
		c = locase_w(*s);
		s++;
		if (_isdigit_w(c))
			r = 16*r + (c-L'0');
		else
			if ((c >= L'a') && (c <= L'f'))
				r = 16*r + (c-L'a'+10);
			else
				break;
	}
	return r;
}
