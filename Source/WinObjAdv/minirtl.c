/*
Module name:
	minirtl.c

Description:
	Conversion routines

Date:
	18 Feb 2015
*/

#include <windows.h>
#include "minirtl.h"

// dummy memset
void _mini_memzero(void *p, size_t size)
{
	while ( size > 0 ) {
		*((unsigned char *)p) = 0;
		p = ((unsigned char *)p) + 1;
		size--;
	}
}

// conversion unsigned long to string, returning string length

unsigned long itostrA(int x, char *s)
{
	unsigned long	t, r = 1;
	int				i, x0 = x;

	if ( x < 0 ) {
		if ( s != 0 ) {
			*s = '-';
			s++;
		}
		x = -x;
	}

	t = x;
	while ( t >= 10 ) {
		t /= 10;
		r++;
	}

	if ( s == 0 ) {
		if ( x0 < 0 )
			return r+1;
		else
			return r;
	}
	
	t = x;
	for (i = r-1; i >= 0; i--) {
		s[i] = (char)(t % 10) + '0';
		t /= 10;
	}

	s[r] = (char)0;
	if ( x0 < 0 )
		return r+1;
	else
		return r;
}

unsigned long i64tostrA(signed long long int x, char *s)
{
	signed long long int	x0 = x;
	unsigned long long		t;
	unsigned long			r = 1;
	int						i;

	if ( x < 0 ) {
		if ( s != 0 ) {
			*s = '-';
			s++;
		}
		x = -x;
	}

	t = x;
	while ( t >= 10 ) {
		t /= 10;
		r++;
	}

	if ( s == 0 ) {
		if ( x0 < 0 )
			return r+1;
		else
			return r;
	}
	
	t = x;
	for (i = r-1; i >= 0; i--) {
		s[i] = (char)(t % 10) + '0';
		t /= 10;
	}

	s[r] = (char)0;
	if ( x0 < 0 )
		return r+1;
	else
		return r;
}

unsigned long i64tostrW(signed long long int x, wchar_t *s)
{
	signed long long int	x0 = x;
	unsigned long long		t;
	unsigned long			r = 1;
	int						i;

	if ( x < 0 ) {
		if ( s != 0 ) {
			*s = '-';
			s++;
		}
		x = -x;
	}

	t = x;
	while ( t >= 10 ) {
		t /= 10;
		r++;
	}

	if ( s == 0 ) {
		if ( x0 < 0 )
			return r+1;
		else
			return r;
	}
	
	t = x;
	for (i = r-1; i >= 0; i--) {
		s[i] = (wchar_t)(t % 10) + '0';
		t /= 10;
	}

	s[r] = (wchar_t)0;
	if ( x0 < 0 )
		return r+1;
	else
		return r;
}

unsigned long ultostrA(unsigned long x, char *s)
{
	unsigned long	t = x, r = 1;
	int				i;

	while ( t >= 10 )
	{
		t /= 10;
		r++;
	}

	if (s == 0)
		return r;
	
	for (i = r-1; i >= 0; i--)
	{
		s[i] = (char)(x % 10) + '0';
		x /= 10;
	}

	s[r] = (char)0;
	return r;
}

unsigned long ultostrW(unsigned long x, wchar_t *s)
{
	unsigned long	t = x, r = 1;
	int				i;

	while ( t >= 10 ) {
		t /= 10;
		r++;
	}

	if (s == 0)
		return r;
	
	for (i = r-1; i >= 0; i--) {
		s[i] = (wchar_t)(x % 10) + '0';
		x /= 10;
	}

	s[r] = (wchar_t)0;
	return r;
}

// conversion unsigned long to hex string
void ultohexA(unsigned long x, char *s)
{
	unsigned long	p;
	int				c;

	if ( s == 0 )
		return;

	for (c=0; c<8; c++) {
		p = (x >> ((7 - c) * 4)) & 0xf;
		if (p < 10)
			s[c] = (char)(p + '0');
		else
			s[c] = (char)('A' + p - 10);
	}
	s[8] = 0;
}

void ultohexW(unsigned long x, wchar_t *s)
{
	unsigned long	p;
	int				c;

	if ( s == 0 )
		return;

	for ( c=0; c<8; c++ ) {
		p = (x >> ((7 - c) * 4)) & 0xf;
		if (p < 10)
			s[c] = (wchar_t)(p + '0');
		else
			s[c] = (wchar_t)('A' + p - 10);
	}
	s[8] = 0;
}

// conversion unsigned __int64 to string, returning string length
unsigned long u64tostrA(unsigned __int64 x, char *s)
{
	unsigned __int64	t = x;
	unsigned long		r = 1;
	int					i;

	while ( t >= 10 ) {
		t /= 10;
		r++;
	}

	if (s == 0)
		return r;
	
	for ( i=r-1; i>=0; i--) {
		s[i] = (char)(x % 10) + '0';
		x /= 10;
	}

	s[r] = 0;
	return r;
}

unsigned long u64tostrW(unsigned __int64 x, wchar_t *s)
{
	unsigned __int64	t = x;
	unsigned long		r = 1;
	int					i;

	while ( t >= 10 ) {
		t /= 10;
		r++;
	}

	if (s == 0)
		return r;
	
	for ( i=r-1; i>=0; i--) {
		s[i] = (wchar_t)(x % 10) + '0';
		x /= 10;
	}

	s[r] = (wchar_t)0;
	return r;
}

// conversion unsigned __int64 to hex string
void u64tohexA(unsigned __int64 x, char *s)
{
	unsigned long	p;
	int				c;

	if ( s == 0 )
		return;

	for ( c=0; c<16; c++ ) {
		p = (x >> ((15-c)*4)) & 0xf;
		if ( p<10 )
			s[c] = (char)(p + '0');
		else
			s[c] = (char)('A' + p - 10);
	}
	s[16] = 0;
}

void u64tohexW(unsigned __int64 x, wchar_t *s)
{
	unsigned long	p;
	int				c;

	if ( s == 0 )
		return;

	for ( c=0; c<16; c++ ) {
		p = (x >> ((15-c)*4)) & 0xf;
		if ( p<10 )
			s[c] = (wchar_t)(p + '0');
		else
			s[c] = (wchar_t)('A' + p - 10);
	}
	s[16] = 0;
}

// conversion string to unsigned long
unsigned long strtoulA(char *s)
{
	unsigned long	a = 0;
	char			c;
	
	if ( s==0 )
		return 0;

	while ( *s!=0 ) {
		c = *s;
		if ( (c>='0') && (c<='9') )
			a = (a*10)+(c-'0');
		else
			break;
		s++;
	}
	return a;
}

unsigned long strtoulW(wchar_t *s)
{
	unsigned long	a = 0;
	wchar_t			c;
	
	if ( s==0 )
		return 0;

	while ( *s!=0 ) {
		c = *s;
		if ( (c>=(wchar_t)'0') && (c<=(wchar_t)'9') )
			a = (a*10)+(c-(wchar_t)'0');
		else
			break;
		s++;
	}
	return a;
}

// conversion string to unsigned __int64
unsigned __int64 strtou64A(char *s)
{
	unsigned __int64	a = 0;
	char				c;
	
	if ( s==0 )
		return 0;

	while ( *s!=0 ) {
		c = *s;
		if ( (c>='0') && (c<='9') )
			a = (a*10)+(c-'0');
		else
			break;
		s++;
	}
	return a;
}

unsigned __int64 strtou64W(wchar_t *s)
{
	unsigned __int64	a = 0;
	wchar_t				c;
	
	if ( s==0 )
		return 0;

	while ( *s != 0 ) {
		c = *s;
		if ( (c>='0') && (c<='9') )
			a = (a*10)+(c-'0');
		else
			break;
		s++;
	}
	return a;
}

// conversion hex string to unsigned __int64
unsigned __int64 hextou64A(char *s)
{
	unsigned __int64	r = 0;
	char				c;

	if ( s==0 )
		return 0;

	while ( *s!=0 ) {
		c = *s;
		s++;
		if ( (c>='0') && (c<='9') )
			r = 16*r + (c-'0');
		else
			if ( (c>='a') && (c<='f') )
				r = 16*r + (c-L'a'+10);
			else
				if ( (c>='A') && (c<='F') )
					r = 16*r + (c-'A'+10);
				else
					break;
	}
	return r;
}

unsigned __int64 hextou64W(wchar_t *s)
{
	unsigned __int64	r = 0;
	wchar_t				c;

	if ( s==0 )
		return 0;

	while ( *s!=0 ) {
		c = *s;
		s++;
		if ( (c>='0') && (c<='9') )
			r = 16*r + (c-'0');
		else
			if ( (c>='a') && (c<='f') )
				r = 16*r + (c-L'a'+10);
			else
				if ( (c>='A') && (c<='F') )
					r = 16*r + (c-'A'+10);
				else
					break;
	}
	return r;
}

char *_strncpyA(char *dest, size_t ccdest, const char *src, size_t ccsrc)
{
	char *p;

	if ( (dest==0) || (src==0) || (ccdest==0) )
		return dest;

	ccdest--;
	p = dest;

	while ( (*src!=0) && (ccdest>0) && (ccsrc>0) ) {
		*p = *src;
		p++;
		src++;
		ccdest--;
		ccsrc--;
	}

	*p = 0;
	return dest;
}

wchar_t *_strncpyW(wchar_t *dest, size_t ccdest, const wchar_t *src, size_t ccsrc)
{
	wchar_t *p;

	if ( (dest==0) || (src==0) || (ccdest==0) )
		return dest;

	ccdest--;
	p = dest;

	while ( (*src!=0) && (ccdest>0) && (ccsrc>0) ) {
		*p = *src;
		p++;
		src++;
		ccdest--;
		ccsrc--;
	}

	*p = 0;
	return dest;
}

char *_strcpyA(char *dest, const char *src)
{
	char *p;

	if ( (dest==0) || (src==0) )
		return dest;

	p = dest;
	while ( *src!=0 ) {
		*p = *src;
		p++;
		src++;
	} 

	*p = 0;
	return dest;
}

wchar_t *_strcpyW(wchar_t *dest, const wchar_t *src)
{
	wchar_t *p;

	if ( (dest==0) || (src==0) )
		return dest;

	p = dest;
	while ( *src!=0 ) {
		*p = *src;
		p++;
		src++;
	} 

	*p = 0;
	return dest;
}

char *_strcatA(char *dest, const char *src)
{
	if ( (dest==0) || (src==0) )
		return dest;

	while ( *dest!=0 )
		dest++;

	while ( *src!=0 ) {
		*dest = *src;
		dest++;
		src++;
	} 

	*dest = 0;
	return dest;
}

wchar_t *_strcatW(_Inout_z_ wchar_t *dest, const wchar_t *src)
{
	if ( (dest==0) || (src==0) )
		return dest;

	while ( *dest!=0 )
		dest++;

	while ( *src!=0 ) {
		*dest = *src;
		dest++;
		src++;
	} 

	*dest = 0;
	return dest;
}

char *_filenameA(const char *f)
{
	char *p = (char *)f;

	if ( f == 0 )
		return 0;

	while ( *f != (char)0 ) {
		if ( *f == '\\' )
			p = (char *)f+1;
		f++;
	}
	return p;
}

wchar_t *_filenameW(const wchar_t *f)
{
	wchar_t *p = (wchar_t *)f;

	if ( f==0 )
		return 0;

	while ( *f != (wchar_t)0 ) {
		if ( *f == (wchar_t)'\\' )
			p = (wchar_t *)f+1;
		f++;
	}
	return p;
}

char *_strendA(const char *s)
{
	if ( s==0 )
		return 0;

	while ( *s!=0 )
		s++;

	return (char *)s;
}

wchar_t *_strendW(const wchar_t *s)
{
	if ( s==0 )
		return 0;

	while ( *s!=0 )
		s++;

	return (wchar_t *)s;
}

size_t _strlenA(const char *s)
{
	char *s0 = (char *)s;

	if ( s==0 )
		return 0;

	while ( *s!=0 )
		s++;

	return (s-s0);
}

size_t _strlenW(const wchar_t *s)
{
	wchar_t *s0 = (wchar_t *)s;

	if ( s==0 )
		return 0;

	while ( *s!=0 )
		s++;

	return (s-s0);
}

char *_filename_noextA(char *dest, const char *f)
{
	char *p, *l, *dot;

	if ( (f == 0) || (dest == 0) )
		return 0;

	p = _filenameA(f);
	dot = _strendA(p);
	l = p;

	while ( *l != (char)0 )
	{
		if ( *l == '.' )
			dot = l;
		l++;
	}

	while ( p<dot )
	{
		*dest = *p;
		p++;
		dest++;
	}

	*dest = 0;
	return dest;
}

wchar_t *_filename_noextW(wchar_t *dest, const wchar_t *f)
{
	wchar_t *p, *l, *dot;

	if ( (f == 0) || (dest == 0) )
		return 0;

	p = _filenameW(f);
	dot = _strendW(p);
	l = p;

	while ( *l != (wchar_t)0 )
	{
		if ( *l == (wchar_t)'.' )
			dot = l;
		l++;
	}

	while ( p<dot )
	{
		*dest = *p;
		p++;
		dest++;
	}

	*dest = 0;
	return dest;
}

char *_fileextA(const char *f)
{
	char *p = 0;

	if ( f==0 )
		return 0;

	while ( *f != (char)0 ) {
		if ( *f == '.' )
			p = (char *)f;
		f++;
	}

	if ( p == 0 )
		p = (char *)f;

	return p;
}

wchar_t *_fileextW(const wchar_t *f)
{
	wchar_t *p = 0;

	if ( f==0 )
		return 0;

	while ( *f != (wchar_t)0 ) {
		if ( *f == '.' )
			p = (wchar_t *)f;
		f++;
	}

	if ( p == 0 )
		p = (wchar_t *)f;

	return p;
}

BOOL GetCommandLineParamW (
	IN	LPCWSTR	CmdLine,
	IN	ULONG	ParamIndex,
	OUT	LPWSTR	Buffer,
	IN	ULONG	BufferSize,
	OUT	PULONG	ParamLen
	)
{
	ULONG	c, plen = 0;
	TCHAR	divider;

	if ( ParamLen != NULL )
		*ParamLen = 0;

	if ( CmdLine == NULL ) {
		if ( (Buffer != NULL) && (BufferSize > 0) )
			*Buffer = 0;
		return FALSE;
	}

	for (c=0; c<=ParamIndex; c++) {
		plen = 0;

		while ( *CmdLine == ' ' )
			CmdLine++;

		switch ( *CmdLine ) {
		case 0:
			goto zero_term_exit;

		case '"':
			CmdLine++;
			divider = '"';
			break;

		default:
			divider = ' ';
		}

		while ( (*CmdLine != '"') && (*CmdLine != divider) && (*CmdLine != 0) ) {
			plen++;
			if ( c == ParamIndex )
				if ( (plen < BufferSize) && (Buffer != NULL) ) {
					*Buffer = *CmdLine;
					Buffer++;
				}
			CmdLine++;
		}

		if ( *CmdLine != 0 )
			CmdLine++;
	}

zero_term_exit:

	if ( (Buffer != NULL) && (BufferSize > 0) )
		*Buffer = 0;

	if ( ParamLen != NULL )
		*ParamLen = plen;

	if ( plen < BufferSize )
		return TRUE;
	else
		return FALSE;
}

BOOL GetCommandLineParamA (
	IN	LPCSTR	CmdLine,
	IN	ULONG	ParamIndex,
	OUT	LPSTR	Buffer,
	IN	ULONG	BufferSize,
	OUT	PULONG	ParamLen
	)
{
	ULONG	c, plen = 0;
	TCHAR	divider;

	if ( CmdLine == NULL )
		return FALSE;

	if ( ParamLen != NULL )
		*ParamLen = 0;

	for (c=0; c<=ParamIndex; c++) {
		plen = 0;

		while ( *CmdLine == ' ' )
			CmdLine++;

		switch ( *CmdLine ) {
		case 0:
			goto zero_term_exit;

		case '"':
			CmdLine++;
			divider = '"';
			break;

		default:
			divider = ' ';
		}

		while ( (*CmdLine != '"') && (*CmdLine != divider) && (*CmdLine != 0) ) {
			plen++;
			if ( c == ParamIndex )
				if ( (plen < BufferSize) && (Buffer != NULL) ) {
					*Buffer = *CmdLine;
					Buffer++;
				}
			CmdLine++;
		}

		if ( *CmdLine != 0 )
			CmdLine++;
	}

zero_term_exit:

	if ( (Buffer != NULL) && (BufferSize > 0) )
		*Buffer = 0;

	if ( ParamLen != NULL )
		*ParamLen = plen;

	if ( plen < BufferSize )
		return TRUE;
	else
		return FALSE;
}

char *ExtractFilePathA(const char *FileName, char *FilePath)
{
	char *p = (char *)FileName, *p0 = (char *)FileName;

	if ( (FileName == 0) || (FilePath == 0) )
		return 0;

	while ( *FileName != 0 ) {
		if ( *FileName == '\\' )
			p = (char *)FileName + 1;
		FileName++;
	}
	
	while ( p0 < p ) {
		*FilePath = *p0;
		FilePath++;
		p0++;
	}

	*FilePath = 0;

	return FilePath;
}

wchar_t *ExtractFilePathW(const wchar_t *FileName, wchar_t *FilePath)
{
	wchar_t *p = (wchar_t *)FileName, *p0 = (wchar_t *)FileName;

	if ( (FileName == 0) || (FilePath == 0) )
		return 0;

	while ( *FileName != 0 ) {
		if ( *FileName == '\\' )
			p = (wchar_t *)FileName + 1;
		FileName++;
	}
	
	while ( p0 < p ) {
		*FilePath = *p0;
		FilePath++;
		p0++;
	}

	*FilePath = 0;

	return FilePath;
}

char locaseA(char c)
{
	if ( (c >= 'A') && (c <= 'Z') )
		return c+0x20;
	else
		return c;
}

wchar_t locaseW(wchar_t c)
{
	if ( (c >= 'A') && (c <= 'Z') )
		return c+0x20;
	else
		return c;
}

int _strcmpiW(const wchar_t *s1, const wchar_t *s2)
{
	wchar_t c1, c2;

	if ( s1==s2 )
		return 0;

	if ( s1==0 )
		return -1;

	if ( s2==0 )
		return 1;

	do {
		c1 = locaseW(*s1);
		c2 = locaseW(*s2);
		s1++;
		s2++;
	} while ( (c1 != 0) && (c1 == c2) );
	
	return (int)(c1 - c2);
}

wchar_t *_strstriW(const wchar_t *s, const wchar_t *sub_s)
{
	wchar_t c0, c1, c2, *tmps, *tmpsub;

	if (s == sub_s)
		return (wchar_t *)s;

	if (s == 0)
		return 0;

	if (sub_s == 0)
		return 0;

	c0 = locaseW(*sub_s);
	while (c0 != 0) {

		while (*s != 0) {
			c2 = locaseW(*s);
			if (c2 == c0)
				break;
			s++;
		}

		if (*s == 0)
			return 0;

		tmps = (wchar_t *)s;
		tmpsub = (wchar_t *)sub_s;
		do {
			c1 = locaseW(*tmps);
			c2 = locaseW(*tmpsub);
			tmps++;
			tmpsub++;
		} while ((c1 == c2) && (c2 != 0));

		if (c2 == 0)
			return (wchar_t *)s;

		s++;
	}
	return 0;
}

int _strcmpiA(const char *s1, const char *s2)
{
	char c1, c2;
	
	if ( s1==s2 )
		return 0;

	if ( s1==0 )
		return -1;

	if ( s2==0 )
		return 1;

	do {
		c1 = locaseA(*s1);
		c2 = locaseA(*s2);
		s1++;
		s2++;
	} while ( (c1 != 0) && (c1 == c2) );
	
	return (int)(c1 - c2);
}

int _strcmpA(const char *s1, const char *s2)
{
	char c1, c2;

	if ( s1==s2 )
		return 0;

	if ( s1==0 )
		return -1;

	if ( s2==0 )
		return 1;

	do {
		c1 = *s1;
		c2 = *s2;
		s1++;
		s2++;
	} while ( (c1 != 0) && (c1 == c2) );
	
	return (int)(c1 - c2);
}

int _strcmpW(const wchar_t *s1, const wchar_t *s2)
{
	wchar_t	c1, c2;

	if ( s1==s2 )
		return 0;

	if ( s1==0 )
		return -1;

	if ( s2==0 )
		return 1;

	do {
		c1 = *s1;
		c2 = *s2;
		s1++;
		s2++;
	} while ( (c1 != 0) && (c1 == c2) );
	
	return (int)(c1 - c2);
}

int _strncmpA(const char *s1, const char *s2, size_t cchars)
{
	char c1, c2;

	if ( s1==s2 )
		return 0;

	if ( s1==0 )
		return -1;

	if ( s2==0 )
		return 1;

	if ( cchars==0 )
		return 0;

	do {
		c1 = *s1;
		c2 = *s2;
		s1++;
		s2++;
		cchars--;
	} while ( (c1 != 0) && (c1 == c2) && (cchars>0) );
	
	return (int)(c1 - c2);
}

int _strncmpW(const wchar_t *s1, const wchar_t *s2, size_t cchars)
{
	wchar_t c1, c2;

	if ( s1==s2 )
		return 0;

	if ( s1==0 )
		return -1;

	if ( s2==0 )
		return 1;

	if ( cchars==0 )
		return 0;

	do {
		c1 = *s1;
		c2 = *s2;
		s1++;
		s2++;
		cchars--;
	} while ( (c1 != 0) && (c1 == c2) && (cchars>0) );
	
	return (int)(c1 - c2);
}

int _strncmpiA(const char *s1, const char *s2, size_t cchars)
{
	char c1, c2;

	if ( s1==s2 )
		return 0;

	if ( s1==0 )
		return -1;

	if ( s2==0 )
		return 1;

	if ( cchars==0 )
		return 0;

	do {
		c1 = locaseA(*s1);
		c2 = locaseA(*s2);
		s1++;
		s2++;
		cchars--;
	} while ( (c1 != 0) && (c1 == c2) && (cchars>0) );
	
	return (int)(c1 - c2);
}

int _strncmpiW(const wchar_t *s1, const wchar_t *s2, size_t cchars)
{
	wchar_t c1, c2;

	if ( s1==s2 )
		return 0;

	if ( s1==0 )
		return -1;

	if ( s2==0 )
		return 1;

	if ( cchars==0 )
		return 0;

	do {
		c1 = locaseW(*s1);
		c2 = locaseW(*s2);
		s1++;
		s2++;
		cchars--;
	} while ( (c1 != 0) && (c1 == c2) && (cchars>0) );
	
	return (int)(c1 - c2);
}

DWORD GetCurrentTimeAs1970Time()
{
	SYSTEMTIME			st1;
	FILETIME			ft1, ft2;
	ULARGE_INTEGER		dt, f;

	memset(&st1, 0, sizeof(st1));
	st1.wDay = 1;
	st1.wMonth = 1;
	st1.wYear = 1970;

	f.QuadPart = 0;

	if (SystemTimeToFileTime(&st1, &ft1)) {
		dt.LowPart = ft1.dwLowDateTime;
		dt.HighPart = ft1.dwHighDateTime;

		GetSystemTimeAsFileTime(&ft2);
		f.LowPart = ft2.dwLowDateTime;
		f.HighPart = ft2.dwHighDateTime;

		f.QuadPart -= dt.QuadPart;
		f.QuadPart /= 10000000;
	}

	return f.LowPart;
}
