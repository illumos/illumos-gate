/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2012 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped

/*
 * Glenn Fowler
 * AT&T Research
 *
 * iconv intercept
 * minimally provides { utf*<=>bin ascii<=>ebcdic* }
 */

#include <ast.h>
#include <dirent.h>

#define DEBUG_TRACE		0
#define _ICONV_LIST_PRIVATE_

#include <ccode.h>
#include <ctype.h>
#include <iconv.h>

#include "lclib.h"

#if !_lib_iconv_open

#define _ast_iconv_t		iconv_t
#define _ast_iconv_f		iconv_f
#define _ast_iconv_list_t	iconv_list_t
#define _ast_iconv_open		iconv_open
#define _ast_iconv		iconv
#define _ast_iconv_close	iconv_close
#define _ast_iconv_list		iconv_list
#define _ast_iconv_move		iconv_move
#define _ast_iconv_name		iconv_name
#define _ast_iconv_write	iconv_write

#endif

#ifndef E2BIG
#define E2BIG			ENOMEM
#endif
#ifndef EILSEQ
#define EILSEQ			EIO
#endif

#define RETURN(e,n,fn) \
	if (*fn && !e) e = E2BIG; \
	if (e) { errno = e; return (size_t)(-1); } \
	return n;

typedef struct Map_s
{
	char*			name;
	const unsigned char*	map;
	_ast_iconv_f		fun;
	int			index;
} Map_t;

typedef struct Conv_s
{
	iconv_t			cvt;
	char*			buf;
	size_t			size;
	Map_t			from;
	Map_t			to;
} Conv_t;

static Conv_t*			freelist[4];
static int			freeindex;

static const char		name_local[] = "local";
static const char		name_native[] = "native";

static const _ast_iconv_list_t	codes[] =
{
	{
	"utf",
	"un|unicode|utf",
	"multibyte 8-bit unicode",
	"UTF-%s",
	"8",
	CC_UTF,
	},

	{
	"ume",
	"um|ume|utf?(-)7",
	"multibyte 7-bit unicode",
	"UTF-7",
	0,
	CC_UME,
	},

	{
	"euc",
	"(big|euc)*",
	"euc family",
	0,
	0,
	CC_ICONV,
	},

	{
	"dos",
	"dos?(-)?(855)",
	"dos code page",
	"DOS855",
	0,
	CC_ICONV,
	},

	{
	"ucs",
	"ucs?(-)?(2)?(be)|utf-16?(be)",
	"unicode runes",
	"UCS-%s",
	"2",
	CC_UCS,
	},

	{
	"ucs-le",
	"ucs?(-)?(2)le|utf-16le",
	"little endian unicode runes",
	"UCS-%sLE",
	"2",
	CC_SCU,
	},

	{ 0 },
};

#if _UWIN

#include <ast_windows.h>

#ifndef CP_UCS2
#define CP_UCS2	0x0000
#endif

static char	_win_maps[] = "/reg/local_machine/SOFTWARE/Classes/MIME/Database/Charset";

/*
 * return the codeset index given its name or alias
 * the map is in the what? oh, the registry
 */

static int
_win_codeset(const char* name)
{
	register char*	s;
	char*		e;
	int		n;
	Sfio_t*		sp;
	char		aka[128];
	char		tmp[128];

#if DEBUG_TRACE
error(DEBUG_TRACE, "AHA#%d _win_codeset name=%s", __LINE__, name);
#endif
	if (name == name_native)
		return CP_ACP;
	if (!strcasecmp(name, "utf") || !strcasecmp(name, "utf8") || !strcasecmp(name, "utf-8"))
		return CP_UTF8;
	if (!strcasecmp(name, "ucs") || !strcasecmp(name, "ucs2") || !strcasecmp(name, "ucs-2"))
		return CP_UCS2;
	if (name[0] == '0' && name[1] == 'x' && (n = strtol(name, &e, 0)) > 0 && !*e)
		return n;
	for (;;)
	{
		sfsprintf(tmp, sizeof(tmp), "%s/%s", _win_maps, name);
		if (!(sp = sfopen(0, tmp, "r")))
		{
			s = (char*)name;
			if ((s[0] == 'c' || s[0] == 'C') && (s[1] == 'p' || s[1] == 'P'))
				s += 2;
			if (!isdigit(s[0]))
				break;
			sfsprintf(tmp, sizeof(tmp), "%s/windows-%s", _win_maps, s);
			if (!(sp = sfopen(0, tmp, "r")))
				break;
		}
		for (;;)
		{
			if (!(s = sfgetr(sp, '\n', 0)))
			{
				sfclose(sp);
				return -1;
			}
			if (!strncasecmp(s, "AliasForCharSet=", 16))
			{
				n = sfvalue(sp) - 17;
				s += 16;
				if (n >= sizeof(aka))
					n = sizeof(aka) - 1;
				memcpy(aka, s, n);
				aka[n] = 0;
				sfclose(sp);
				name = (const char*)aka;
				break;
			}
			if (!strncasecmp(s, "CodePage=", 9))
			{
				s += 9;
				n = strtol(s, 0, 0);
				sfclose(sp);
				return n;
			}
		}
	}
	return -1;
}

/*
 * get and check the codeset indices
 */

static _ast_iconv_t
_win_iconv_open(register Conv_t* cc, const char* t, const char* f)
{
#if DEBUG_TRACE
error(DEBUG_TRACE, "AHA#%d _win_iconv_open f=%s t=%s\n", __LINE__, f, t);
#endif
	if ((cc->from.index = _win_codeset(f)) < 0)
		return (_ast_iconv_t)(-1);
	if ((cc->to.index = _win_codeset(t)) < 0)
		return (_ast_iconv_t)(-1);
#if DEBUG_TRACE
error(DEBUG_TRACE, "AHA#%d _win_iconv_open f=0x%04x t=0x%04x\n", __LINE__, cc->from.index, cc->to.index);
#endif
	return (_ast_iconv_t)cc;
}

/*
 * even though the indices already check out
 * they could still be rejected
 */

static size_t
_win_iconv(_ast_iconv_t cd, char** fb, size_t* fn, char** tb, size_t* tn)
{
	Conv_t*	cc = (Conv_t*)cd;
	size_t	un;
	size_t	tz;
	size_t	fz;
	size_t	bz;
	size_t	pz;
	size_t	oz;
	LPWSTR	ub;

#if DEBUG_TRACE
error(DEBUG_TRACE, "AHA#%d _win_iconv from=0x%04x to=0x%04x\n", __LINE__, cc->from.index, cc->to.index);
#endif
	if (cc->from.index == cc->to.index || cc->from.index != CP_UCS2 && cc->to.index == 0)
	{
		/*
		 * easy
		 */

		fz = tz = (*fn < *tn) ? *fn : *tn;
		memcpy(*tb, *fb, fz);
	}
	else
	{
		ub = 0;
		un = *fn;

		/*
		 * from => ucs-2
		 */

		if (cc->to.index == CP_UCS2)
		{
			if ((tz = MultiByteToWideChar(cc->from.index, 0, (LPCSTR)*fb, (int)*fn, (LPWSTR)*tb, *tn)) && tz <= *tn)
			{
				fz = *fn;
				tz *= sizeof(WCHAR);
			}
			else
			{
				/*
				 * target too small
				 * binary search on input size to make it fit
				 */

				oz = 0;
				pz = *fn / 2;
				fz = *fn - pz;
				for (;;)
				{
					while (!(tz = MultiByteToWideChar(cc->from.index, 0, (LPCSTR)*fb, (int)fz, (LPWSTR)*tb, 0)))
						if (++fz >= *fn)
							goto nope;
					tz *= sizeof(WCHAR);
					if (tz == *tn)
						break;
					if (!(pz /= 2))
					{
						if (!(fz = oz))
							goto nope;
						break;
					}
					if (tz > *tn)
						fz -= pz;
					else
					{
						oz = fz;
						fz += pz;
					}
				}
			}
		}
		else
		{
			if (cc->from.index == CP_UCS2)
			{
				un = *fn / sizeof(WCHAR);
				ub = (LPWSTR)*fb;
			}
			else if (!(un = MultiByteToWideChar(cc->from.index, 0, (LPCSTR)*fb, (int)*fn, (LPWSTR)*tb, 0)))
				goto nope;
			else if (!(ub = (LPWSTR)malloc(un * sizeof(WCHAR))))
				goto nope;
			else if (!(un = MultiByteToWideChar(cc->from.index, 0, (LPCSTR)*fb, (int)*fn, (LPWSTR)ub, un)))
				goto nope;

			/*
			 * ucs-2 => to
			 */

			if (tz = WideCharToMultiByte(cc->to.index, 0, (LPCWSTR)ub, un, *tb, *tn, 0, 0))
				fz = *fn;
			else
			{
				/*
				 * target too small
				 * binary search on input size to make it fit
				 */

				oz = 0;
				pz = *fn / 2;
				bz = *fn - pz;
				for (;;)
				{
					while (!(fz = MultiByteToWideChar(cc->from.index, 0, (LPCSTR)*fb, (int)bz, (LPWSTR)ub, un)))
						if (++bz > *fn)
							goto nope;
					if (!(tz = WideCharToMultiByte(cc->to.index, 0, (LPCWSTR)ub, fz, *tb, 0, 0, 0)))
						goto nope;
					if (tz == *tn)
						break;
					if (!(pz /= 2))
					{
						if (!(fz = oz))
							goto nope;
						break;
					}
					if (tz > *tn)
						bz -= pz;
					else
					{
						oz = bz;
						bz += pz;
					}
				}
				if (!(tz = WideCharToMultiByte(cc->to.index, 0, (LPCWSTR)ub, fz, *tb, tz, 0, 0)))
					goto nope;
#if DEBUG_TRACE
error(DEBUG_TRACE, "AHA#%d _win_iconv *fn=%u fz=%u[%u] *tn=%u tz=%u\n", __LINE__, *fn, fz, fz * sizeof(WCHAR), *tn, tz);
#endif
#if 0
				fz *= sizeof(WCHAR);
#endif
			}
			if (ub != (LPWSTR)*fb)
				free(ub);
		}
	}
	*fb += fz;
	*fn -= fz;
	*tb += tz;
	*tn -= tz;
	return fz;
 nope:
	if (ub && ub != (LPWSTR)*fb)
		free(ub);
	errno = EINVAL;
	return (size_t)(-1);
}

#endif

/*
 * return canonical character code set name for m
 * if b!=0 then canonical name placed in b of size n
 * <ccode.h> index returned
 */

int
_ast_iconv_name(register const char* m, register char* b, size_t n)
{
	register const _ast_iconv_list_t*	cp;
	const _ast_iconv_list_t*		bp;
	register int				c;
	register char*				e;
	ssize_t					sub[2];
	char					buf[16];
#if DEBUG_TRACE
	char*					o;
#endif

	if (!b)
	{
		b = buf;
		n = sizeof(buf);
	}
#if DEBUG_TRACE
	o = b;
#endif
	e = b + n - 1;
	bp = 0;
	n = 0;
	cp = ccmaplist(NiL);
#if DEBUG_TRACE
if (error_info.trace < DEBUG_TRACE) sfprintf(sfstderr, "%s: debug-%d: AHA%d _ast_iconv_name m=\"%s\"\n", error_info.id, error_info.trace, __LINE__, m);
#endif
	for (;;)
	{
#if DEBUG_TRACE
if (error_info.trace < DEBUG_TRACE) sfprintf(sfstderr, "%s: debug-%d: AHA%d _ast_iconv_name n=%d bp=%p cp=%p ccode=%d name=\"%s\"\n", error_info.id, error_info.trace, __LINE__, n, bp, cp, cp->ccode, cp->name);
#endif
		if (strgrpmatch(m, cp->match, sub, elementsof(sub) / 2, STR_MAXIMAL|STR_LEFT|STR_ICASE))
		{
			if (!(c = m[sub[1]]))
			{
				bp = cp;
				break;
			}
			if (sub[1] > n && !isalpha(c))
			{
				bp = cp;
				n = sub[1];
			}
		}
		if (cp->ccode < 0)
		{
			if (!(++cp)->name)
				break;
		}
		else if (!(cp = (const _ast_iconv_list_t*)ccmaplist((_ast_iconv_list_t*)cp)))
			cp = codes;
	}
	if (cp = bp)
	{
		if (cp->canon)
		{
			if (cp->index)
			{
				for (m += sub[1]; *m && !isalnum(*m); m++);
				if (!isdigit(*m))
					m = cp->index;
			}
			else
				m = "1";
			b += sfsprintf(b, e - b, cp->canon, m);
		}
		else if (cp->ccode == CC_NATIVE)
		{
			if ((locales[AST_LC_CTYPE]->flags & LC_default) || !locales[AST_LC_CTYPE]->charset || !(m = locales[AST_LC_CTYPE]->charset->code) || streq(m, "iso8859-1"))
				switch (CC_NATIVE)
				{
				case CC_EBCDIC:
					m = (const char*)"EBCDIC";
					break;
				case CC_EBCDIC_I:
					m = (const char*)"EBCDIC-I";
					break;
				case CC_EBCDIC_O:
					m = (const char*)"EBCDIC-O";
					break;
				default:
					m = (const char*)"ISO-8859-1";
					break;
				}
			b += sfsprintf(b, e - b, "%s", m);
		}
		*b = 0;
#if DEBUG_TRACE
if (error_info.trace < DEBUG_TRACE) sfprintf(sfstderr, "%s: debug-%d: AHA%d _ast_iconv_name ccode=%d canon=\"%s\"\n", error_info.id, error_info.trace, __LINE__, cp->ccode, o);
#endif
		return cp->ccode;
	}
	while (b < e && (c = *m++))
	{
		if (islower(c))
			c = toupper(c);
		*b++ = c;
	}
	*b = 0;
#if DEBUG_TRACE
if (error_info.trace < DEBUG_TRACE) sfprintf(sfstderr, "%s: debug-%d: AHA%d _ast_iconv_name ccode=%d canon=\"%s\"\n", error_info.id, error_info.trace, __LINE__, CC_ICONV, o);
#endif
	return CC_ICONV;
}

/*
 * convert utf-8 to bin
 */

static size_t
utf2bin(_ast_iconv_t cd, char** fb, size_t* fn, char** tb, size_t* tn)
{
	register unsigned char*		f;
	register unsigned char*		fe;
	register unsigned char*		t;
	register unsigned char*		te;
	register unsigned char*		p;
	register int			c;
	register int			w;
	size_t				n;
	int				e;

	e = 0;
	f = (unsigned char*)(*fb);
	fe = f + (*fn);
	t = (unsigned char*)(*tb);
	te = t + (*tn);
	while (t < te && f < fe)
	{
		p = f;
		c = *f++;
		if (c & 0x80)
		{
			if (!(c & 0x40))
			{
				f = p;
				e = EILSEQ;
				break;
			}
			if (c & 0x20)
			{
				w = (c & 0x0F) << 12;
				if (f >= fe)
				{
					f = p;
					e = EINVAL;
					break;
				}
				c = *f++;
				if (c & 0x40)
				{
					f = p;
					e = EILSEQ;
					break;
				}
				w |= (c & 0x3F) << 6;
			}
			else
				w = (c & 0x1F) << 6;
			if (f >= fe)
			{
				f = p;
				e = EINVAL;
				break;
			}
			c = *f++;
			w |= (c & 0x3F);
		}
		else
			w = c;
		*t++ = w;
	}
	*fn -= (char*)f - (*fb);
	*fb = (char*)f;
	*tn -= (n = (char*)t - (*tb));
	*tb = (char*)t;
	RETURN(e, n, fn);
}

/*
 * convert bin to utf-8
 */

static size_t
bin2utf(_ast_iconv_t cd, char** fb, size_t* fn, char** tb, size_t* tn)
{
	register unsigned char*		f;
	register unsigned char*		fe;
	register unsigned char*		t;
	register unsigned char*		te;
	register int			c;
	wchar_t				w;
	size_t				n;
	int				e;

	e = 0;
	f = (unsigned char*)(*fb);
	fe = f + (*fn);
	t = (unsigned char*)(*tb);
	te = t + (*tn);
	while (f < fe && t < te)
	{
		if (!mbwide())
		{
			c = 1;
			w = *f;
		}
		else if ((c = (*_ast_info.mb_towc)(&w, (char*)f, fe - f)) < 0)
		{
			e = EINVAL;
			break;
		}
		else if (!c)
			c = 1;
		if (!(w & ~0x7F))
			*t++ = w;
		else
		{
			if (!(w & ~0x7FF))
			{
				if (t >= (te - 2))
				{
					e = E2BIG;
					break;
				}
				*t++ = 0xC0 + (w >> 6);
			}
			else if (!(w & ~0xffff))
			{
				if (t >= (te - 3))
				{
					e = E2BIG;
					break;
				}
				*t++ = 0xE0 + (w >> 12);
				*t++ = 0x80 + ((w >> 6 ) & 0x3F);
			}
			else
			{
				e = EILSEQ;
				break;
			}
			*t++ = 0x80 + (w & 0x3F);
		}
		f += c;
	}
	*fn -= (n = (char*)f - (*fb));
	*fb = (char*)f;
	*tn -= (char*)t - (*tb);
	*tb = (char*)t;
	RETURN(e, n, fn);
}

static const unsigned char	ume_D[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'(),-./:?!\"#$%&*;<=>@[]^_`{|} \t\n";

static const unsigned char	ume_M[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static unsigned char		ume_d[UCHAR_MAX+1];

static unsigned char		ume_m[UCHAR_MAX+1];

#define NOE			0xFF
#define UMEINIT()		(ume_d[ume_D[0]]?0:umeinit())

/*
 * initialize the ume tables
 */

static int
umeinit(void)
{
	register const unsigned char*	s;
	register int			i;
	register int			c;

	if (!ume_d[ume_D[0]])
	{
		s = ume_D; 
		while (c = *s++)
			ume_d[c] = 1;
		memset(ume_m, NOE, sizeof(ume_m));
		for (i = 0; c = ume_M[i]; i++)
			ume_m[c] = i;
	}
	return 0;
}

/*
 * convert utf-7 to bin
 */

static size_t
ume2bin(_ast_iconv_t cd, char** fb, size_t* fn, char** tb, size_t* tn)
{
	register unsigned char*		f;
	register unsigned char*		fe;
	register unsigned char*		t;
	register unsigned char*		te;
	register unsigned char*		p;
	register int			s;
	register int			c;
	register int			w;
	size_t				n;
	int				e;

	e = 0;
	UMEINIT();
	f = (unsigned char*)(*fb);
	fe = f + (*fn);
	t = (unsigned char*)(*tb);
	te = t + (*tn);
	s = 0;
	while (f < fe && t < te)
	{
		p = f;
		c = *f++;
		if (s)
		{
			if (c == '-' && s > 1)
				s = 0;
			else if ((w = ume_m[c]) == NOE)
			{
				s = 0;
				*t++ = c;
			}
			else if (f >= (fe - 2))
			{
				f = p;
				e = EINVAL;
				break;
			}
			else
			{
				s = 2;
				w = (w << 6) | ume_m[*f++];
				w = (w << 6) | ume_m[*f++];
				if (!(w & ~0xFF))
					*t++ = w;
				else if (t >= (te - 1))
				{
					f = p;
					e = E2BIG;
					break;
				}
				else
				{
					*t++ = (w >> 8) & 0xFF;
					*t++ = w & 0xFF;
				}
			}
		}
		else if (c == '+')
			s = 1;
		else
			*t++ = c;
	}
	*fn -= (char*)f - (*fb);
	*fb = (char*)f;
	*tn -= (n = (char*)t - (*tb));
	*tb = (char*)t;
	RETURN(e, n, fn);
}

/*
 * convert bin to utf-7
 */

static size_t
bin2ume(_ast_iconv_t cd, char** fb, size_t* fn, char** tb, size_t* tn)
{
	register unsigned char*		f;
	register unsigned char*		fe;
	register unsigned char*		t;
	register unsigned char*		te;
	register int			c;
	register int			s;
	wchar_t				w;
	size_t				n;
	int				e;

	e = 0;
	UMEINIT();
	f = (unsigned char*)(*fb);
	fe = f + (*fn);
	t = (unsigned char*)(*tb);
	te = t + (*tn);
	s = 0;
	while (f < fe && t < (te - s))
	{
		if (!mbwide())
		{
			c = 1;
			w = *f;
		}
		else if ((c = (*_ast_info.mb_towc)(&w, (char*)f, fe - f)) < 0)
		{
			e = EINVAL;
			break;
		}
		else if (!c)
			c = 1;
		if (!(w & ~0x7F) && ume_d[w])
		{
			if (s)
			{
				s = 0;
				*t++ = '-';
			}
			*t++ = w;
		}
		else if (t >= (te - (4 + s)))
		{
			e = E2BIG;
			break;
		}
		else
		{
			if (!s)
			{
				s = 1;
				*t++ = '+';
			}
			*t++ = ume_M[(w >> 12) & 0x3F];
			*t++ = ume_M[(w >> 6) & 0x3F];
			*t++ = ume_M[w & 0x3F];
		}
		f += c;
	}
	if (s)
		*t++ = '-';
	*fn -= (n = (char*)f - (*fb));
	*fb = (char*)f;
	*tn -= (char*)t - (*tb);
	*tb = (char*)t;
	RETURN(e, n, fn);
}

/*
 * convert ucs-2 to bin with no byte swap
 */

static size_t
ucs2bin(_ast_iconv_t cd, char** fb, size_t* fn, char** tb, size_t* tn)
{
	register unsigned char*		f;
	register unsigned char*		fe;
	register unsigned char*		t;
	register unsigned char*		te;
	register int			w;
	size_t				n;
	int				e;

	e = 0;
	f = (unsigned char*)(*fb);
	fe = f + (*fn);
	t = (unsigned char*)(*tb);
	te = t + (*tn);
	while (f < (fe - 1) && t < te)
	{
		w = *f++;
		w = (w << 8) | *f++;
		if (!(w & ~0xFF))
			*t++ = w;
		else if (t >= (te - 1))
		{
			f -= 2;
			e = E2BIG;
			break;
		}
		else
		{
			*t++ = (w >> 8) & 0xFF;
			*t++ = w & 0xFF;
		}
	}
	*fn -= (char*)f - (*fb);
	*fb = (char*)f;
	*tn -= (n = (char*)t - (*tb));
	*tb = (char*)t;
	RETURN(e, n, fn);
}

/*
 * convert bin to ucs-2 with no byte swap
 */

static size_t
bin2ucs(_ast_iconv_t cd, char** fb, size_t* fn, char** tb, size_t* tn)
{
	register unsigned char*		f;
	register unsigned char*		fe;
	register unsigned char*		t;
	register unsigned char*		te;
	register int			c;
	wchar_t				w;
	size_t				n;
	int				e;

	e = 0;
	f = (unsigned char*)(*fb);
	fe = f + (*fn);
	t = (unsigned char*)(*tb);
	te = t + (*tn);
	while (f < fe && t < (te - 1))
	{
		if (!mbwide())
		{
			c = 1;
			w = *f;
		}
		if ((c = (*_ast_info.mb_towc)(&w, (char*)f, fe - f)) < 0)
		{
			e = EINVAL;
			break;
		}
		else if (!c)
			c = 1;
		*t++ = (w >> 8) & 0xFF;
		*t++ = w & 0xFF;
		f += c;
	}
	*fn -= (n = (char*)f - (*fb));
	*fb = (char*)f;
	*tn -= (char*)t - (*tb);
	*tb = (char*)t;
	RETURN(e, n, fn);
}

/*
 * convert ucs-2 to bin with byte swap
 */

static size_t
scu2bin(_ast_iconv_t cd, char** fb, size_t* fn, char** tb, size_t* tn)
{
	register unsigned char*		f;
	register unsigned char*		fe;
	register unsigned char*		t;
	register unsigned char*		te;
	register int			w;
	size_t				n;
	int				e;

	e = 0;
	f = (unsigned char*)(*fb);
	fe = f + (*fn);
	t = (unsigned char*)(*tb);
	te = t + (*tn);
	while (f < (fe - 1) && t < te)
	{
		w = *f++;
		w = w | (*f++ << 8);
		if (!(w & ~0xFF))
			*t++ = w;
		else if (t >= (te - 1))
		{
			f -= 2;
			e = E2BIG;
			break;
		}
		else
		{
			*t++ = (w >> 8) & 0xFF;
			*t++ = w & 0xFF;
		}
	}
	*fn -= (char*)f - (*fb);
	*fb = (char*)f;
	*tn -= (n = (char*)t - (*tb));
	*tb = (char*)t;
	RETURN(e, n, fn);
}

/*
 * convert bin to ucs-2 with byte swap
 */

static size_t
bin2scu(_ast_iconv_t cd, char** fb, size_t* fn, char** tb, size_t* tn)
{
	register unsigned char*		f;
	register unsigned char*		fe;
	register unsigned char*		t;
	register unsigned char*		te;
	register int			c;
	wchar_t				w;
	size_t				n;
	int				e;

	e = 0;
	f = (unsigned char*)(*fb);
	fe = f + (*fn);
	t = (unsigned char*)(*tb);
	te = t + (*tn);
	while (f < fe && t < (te - 1))
	{
		if (!mbwide())
		{
			c = 1;
			w = *f;
		}
		else if ((c = (*_ast_info.mb_towc)(&w, (char*)f, fe - f)) < 0)
		{
			e = EINVAL;
			break;
		}
		else if (!c)
			c = 1;
		*t++ = w & 0xFF;
		*t++ = (w >> 8) & 0xFF;
		f += c;
	}
	*fn -= (n = (char*)f - (*fb));
	*fb = (char*)f;
	*tn -= (char*)t - (*tb);
	*tb = (char*)t;
	RETURN(e, n, fn);
}

/*
 * open a character code conversion map from f to t
 */

_ast_iconv_t
_ast_iconv_open(const char* t, const char* f)
{
	register Conv_t*	cc;
	int			fc;
	int			tc;
	int			i;

	char			fr[64];
	char			to[64];

#if DEBUG_TRACE
error(DEBUG_TRACE, "AHA#%d _ast_iconv_open f=%s t=%s\n", __LINE__, f, t);
#endif
	if (!t || !*t || *t == '-' && !*(t + 1) || !strcasecmp(t, name_local) || !strcasecmp(t, name_native))
		t = name_native;
	if (!f || !*f || *f == '-' && !*(f + 1) || !strcasecmp(t, name_local) || !strcasecmp(f, name_native))
		f = name_native;

	/*
	 * the ast identify is always (iconv_t)(0)
	 */

	if (t == f)
		return (iconv_t)(0);
	fc = _ast_iconv_name(f, fr, sizeof(fr));
	tc = _ast_iconv_name(t, to, sizeof(to));
#if DEBUG_TRACE
error(DEBUG_TRACE, "AHA#%d _ast_iconv_open f=%s:%s:%d t=%s:%s:%d\n", __LINE__, f, fr, fc, t, to, tc);
#endif
	if (fc != CC_ICONV && fc == tc || streq(fr, to))
		return (iconv_t)(0);

	/*
	 * first check the free list
	 */

	for (i = 0; i < elementsof(freelist); i++)
		if ((cc = freelist[i]) && streq(to, cc->to.name) && streq(fr, cc->from.name))
		{
			freelist[i] = 0;
#if _lib_iconv_open
			/*
			 * reset the shift state if any
			 */

			if (cc->cvt != (iconv_t)(-1))
				iconv(cc->cvt, NiL, NiL, NiL, NiL);
#endif
			return cc;
		}

	/*
	 * allocate a new one
	 */

	if (!(cc = newof(0, Conv_t, 1, strlen(to) + strlen(fr) + 2)))
		return (iconv_t)(-1);
	cc->to.name = (char*)(cc + 1);
	cc->from.name = strcopy(cc->to.name, to) + 1;
	strcpy(cc->from.name, fr);
	cc->cvt = (iconv_t)(-1);

	/*
	 * 8 bit maps are the easiest
	 */

	if (fc >= 0 && tc >= 0)
		cc->from.map = ccmap(fc, tc);
#if _lib_iconv_open
	else if ((cc->cvt = iconv_open(t, f)) != (iconv_t)(-1) || (cc->cvt = iconv_open(to, fr)) != (iconv_t)(-1))
		cc->from.fun = (_ast_iconv_f)iconv;
#endif
#if _UWIN
	else if ((cc->cvt = _win_iconv_open(cc, t, f)) != (_ast_iconv_t)(-1) || (cc->cvt = _win_iconv_open(cc, to, fr)) != (_ast_iconv_t)(-1))
		cc->from.fun = (_ast_iconv_f)_win_iconv;
#endif
	else
	{
		switch (fc)
		{
		case CC_UTF:
			cc->from.fun = utf2bin;
			break;
		case CC_UME:
			cc->from.fun = ume2bin;
			break;
		case CC_UCS:
			cc->from.fun = ucs2bin;
			break;
		case CC_SCU:
			cc->from.fun = scu2bin;
			break;
		case CC_ASCII:
			break;
		default:
			if (fc < 0)
				goto nope;
			cc->from.map = ccmap(fc, CC_ASCII);
			break;
		}
		switch (tc)
		{
		case CC_UTF:
			cc->to.fun = bin2utf;
			break;
		case CC_UME:
			cc->to.fun = bin2ume;
			break;
		case CC_UCS:
			cc->to.fun = bin2ucs;
			break;
		case CC_SCU:
			cc->to.fun = bin2scu;
			break;
		case CC_ASCII:
			break;
		default:
			if (tc < 0)
				goto nope;
			cc->to.map = ccmap(CC_ASCII, tc);
			break;
		}
	}
	return (iconv_t)cc;
 nope:
	return (iconv_t)(-1);
}

/*
 * close a character code conversion map
 */

int
_ast_iconv_close(_ast_iconv_t cd)
{
	Conv_t*	cc;
	Conv_t*	oc;
	int	i;
	int	r = 0;

	if (cd == (_ast_iconv_t)(-1))
		return -1;
	if (!(cc = (Conv_t*)cd))
		return 0;

	/*
	 * add to the free list
	 */

	i = freeindex;
	for (;;)
	{
		if (++ i >= elementsof(freelist))
			i = 0;
		if (!freelist[i])
			break;
		if (i == freeindex)
		{
			if (++ i >= elementsof(freelist))
				i = 0;

			/*
			 * close the oldest
			 */

			if (oc = freelist[i])
			{
#if _lib_iconv_open
				if (oc->cvt != (iconv_t)(-1))
					r = iconv_close(oc->cvt);
#endif
				if (oc->buf)
					free(oc->buf);
				free(oc);
			}
			break;
		}
	}
	freelist[freeindex = i] = cc;
	return r;
}

/*
 * copy *fb size *fn to *tb size *tn
 * fb,fn tb,tn updated on return
 */

size_t
_ast_iconv(_ast_iconv_t cd, char** fb, size_t* fn, char** tb, size_t* tn)
{
	Conv_t*				cc = (Conv_t*)cd;
	register unsigned char*		f;
	register unsigned char*		t;
	register unsigned char*		e;
	register const unsigned char*	m;
	register size_t			n;
	char*				b;
	char*				tfb;
	size_t				tfn;
	size_t				i;

	if (!fb || !*fb)
	{
		/* TODO: reset to the initial state */
		if (!tb || !*tb)
			return 0;
		/* TODO: write the initial state shift sequence */
		return 0;
	}
	n = *tn;
	if (cc)
	{
		if (cc->from.fun)
		{
			if (cc->to.fun)
			{
				if (!cc->buf && !(cc->buf = oldof(0, char, cc->size = SF_BUFSIZE, 0)))
				{
					errno = ENOMEM;
					return -1;
				}
				b = cc->buf;
				i = cc->size;
				tfb = *fb;
				tfn = *fn;
				if ((*cc->from.fun)(cc->cvt, &tfb, &tfn, &b, &i) == (size_t)(-1))
					return -1;
				tfn = b - cc->buf;
				tfb = cc->buf;
				n = (*cc->to.fun)(cc->cvt, &tfb, &tfn, tb, tn);
				i = tfb - cc->buf;
				*fb += i;
				*fn -= i;
				return n;
			}
			if ((*cc->from.fun)(cc->cvt, fb, fn, tb, tn) == (size_t)(-1))
				return -1;
			n -= *tn;
			if (m = cc->to.map)
			{
				e = (unsigned char*)(*tb);
				for (t = e - n; t < e; t++)
					*t = m[*t];
			}
			return n;
		}
		else if (cc->to.fun)
		{
			if (!(m = cc->from.map))
				return (*cc->to.fun)(cc->cvt, fb, fn, tb, tn);
			if (!cc->buf && !(cc->buf = oldof(0, char, cc->size = SF_BUFSIZE, 0)))
			{
				errno = ENOMEM;
				return -1;
			}
			if ((n = *fn) > cc->size)
				n = cc->size;
			f = (unsigned char*)(*fb);
			e = f + n;
			t = (unsigned char*)(b = cc->buf);
			while (f < e)
				*t++ = m[*f++];
			n = (*cc->to.fun)(cc->cvt, &b, fn, tb, tn);
			*fb += b - cc->buf;
			return n;
		}
	}
	if (n > *fn)
		n = *fn;
	if (cc && (m = cc->from.map))
	{
		f = (unsigned char*)(*fb);
		e = f + n;
		t = (unsigned char*)(*tb);
		while (f < e)
			*t++ = m[*f++];
	}
	else
		memcpy(*tb, *fb, n);
	*fb += n;
	*fn -= n;
	*tb += n;
	*tn -= n;
	return n;
}

#define OK		((size_t)-1)

/*
 * write *fb size *fn to op
 * fb,fn updated on return
 * total bytes written to op returned
 */

ssize_t
_ast_iconv_write(_ast_iconv_t cd, Sfio_t* op, char** fb, size_t* fn, Iconv_disc_t* disc)
{
	char*		fo = *fb;
	char*		tb;
	char*		ts;
	size_t*		e;
	size_t		tn;
	size_t		r;
	int		ok;
	Iconv_disc_t	compat;

	/*
	 * the old api had optional size_t* instead of Iconv_disc_t*
	 */

	if (!disc || disc->version < 20110101L || disc->version >= 30000101L)
	{
		e = (size_t*)disc;
		disc = &compat;
		iconv_init(disc, 0);
	}
	else
		e = 0;
	r = 0;
	tn = 0;
	ok = 1;
	while (ok && *fn > 0)
	{
		if (!(tb = (char*)sfreserve(op, -(tn + 1), SF_WRITE|SF_LOCKR)) || !(tn = sfvalue(op)))
		{
			if (!r)
				r = -1;
			break;
		}
		ts = tb;
#if DEBUG_TRACE
error(DEBUG_TRACE, "AHA#%d iconv_write ts=%p tn=%d", __LINE__, ts, tn);
		for (;;)
#else
		while (*fn > 0 && _ast_iconv(cd, fb, fn, &ts, &tn) == (size_t)(-1))
#endif
		{
#if DEBUG_TRACE
			ssize_t	_r;
error(DEBUG_TRACE, "AHA#%d iconv_write %d => %d `%-.*s'", __LINE__, *fn, tn, *fn, *fb);
			_r = _ast_iconv(cd, fb, fn, &ts, &tn);
error(DEBUG_TRACE, "AHA#%d iconv_write %d => %d [%d]", __LINE__, *fn, tn, _r);
			if (_r != (size_t)(-1) || !fn)
				break;
#endif
			switch (errno)
			{
			case E2BIG:
				break;
			case EINVAL:
				if (disc->errorf)
					(*disc->errorf)(NiL, disc, ERROR_SYSTEM|2, "incomplete multibyte sequence at offset %I*u", sizeof(fo), *fb - fo);
				goto bad;
			default:
				if (disc->errorf)
					(*disc->errorf)(NiL, disc, ERROR_SYSTEM|2, "invalid multibyte sequence at offset %I*u", sizeof(fo), *fb - fo);
			bad:
				disc->errors++;
				if (!(disc->flags & ICONV_FATAL))
				{
					if (!(disc->flags & ICONV_OMIT) && tn > 0)
					{
						*ts++ = (disc->fill >= 0) ? disc->fill : **fb;
						tn--;
					}
					(*fb)++;
					(*fn)--;
					continue;
				}
				ok = 0;
				break;
			}
			break;
		}
#if DEBUG_TRACE
error(DEBUG_TRACE, "AHA#%d iconv_write %d", __LINE__, ts - tb);
#endif
		sfwrite(op, tb, ts - tb);
		r += ts - tb;
	}
	if (e)
		*e = disc->errors;
	return r;
}

/*
 * move n bytes from ip to op
 */

ssize_t
_ast_iconv_move(_ast_iconv_t cd, Sfio_t* ip, Sfio_t* op, size_t n, Iconv_disc_t* disc)
{
	char*		fb;
	char*		fs;
	char*		tb;
	char*		ts;
	size_t*		e;
	size_t		fe;
	size_t		fn;
	size_t		fo;
	size_t		ft;
	size_t		tn;
	size_t		i;
	ssize_t		r = 0;
	int		ok = 1;
	int		locked;
	Iconv_disc_t	compat;

	/*
	 * the old api had optional size_t* instead of Iconv_disc_t*
	 */

	if (!disc || disc->version < 20110101L || disc->version >= 30000101L)
	{
		e = (size_t*)disc;
		disc = &compat;
		iconv_init(disc, 0);
	}
	else
		e = 0;
	tb = 0;
	fe = OK;
	ft = 0;
	fn = n;
	do
	{
		if (n != SF_UNBOUND)
			n = -((ssize_t)(n & (((size_t)(~0))>>1)));
		if ((!(fb = (char*)sfreserve(ip, n, locked = SF_LOCKR)) || !(fo = sfvalue(ip))) &&
		    (!(fb = (char*)sfreserve(ip, n, locked = 0)) || !(fo = sfvalue(ip))))
			break;
		fs = fb;
		fn = fo;
		if (!(tb = (char*)sfreserve(op, SF_UNBOUND, SF_WRITE|SF_LOCKR)))
		{
			if (!r)
				r = -1;
			break;
		}
		ts = tb;
		tn = sfvalue(op);
		while (fn > 0 && _ast_iconv(cd, &fs, &fn, &ts, &tn) == (size_t)(-1))
		{
			switch (errno)
			{
			case E2BIG:
				break;
			case EINVAL:
				if (fe == ft + (fo - fn))
				{
					fe = OK;
					if (disc->errorf)
						(*disc->errorf)(NiL, disc, ERROR_SYSTEM|2, "incomplete multibyte sequence at offset %I*u", sizeof(ft), ft + (fo - fn));
					goto bad;
				}
				fe = ft;
				break;
			default:
				if (disc->errorf)
					(*disc->errorf)(NiL, disc, ERROR_SYSTEM|2, "invalid multibyte sequence at offset %I*u", sizeof(ft), ft + (fo - fn));
			bad:
				disc->errors++;
				if (!(disc->flags & ICONV_FATAL))
				{
					if (!(disc->flags & ICONV_OMIT) && tn > 0)
					{
						*ts++ = (disc->fill >= 0) ? disc->fill : *fs;
						tn--;
					}
					fs++;
					fn--;
					continue;
				}
				ok = 0;
				break;
			}
			break;
		}
		sfwrite(op, tb, ts - tb);
		r += ts - tb;
		ts = tb;
		if (locked)
			sfread(ip, fb, fs - fb);
		else
			for (i = fn; --i >= (fs - fb);)
				sfungetc(ip, fb[i]);
		if (n != SF_UNBOUND)
		{
			if (n <= (fs - fb))
				break;
			n -= fs - fb;
		}
		ft += (fs - fb);
		if (fn == fo)
			fn++;
	} while (ok);
	if (fb && locked)
		sfread(ip, fb, 0);
	if (tb)
	{
		sfwrite(op, tb, 0);
		if (ts > tb)
		{
			sfwrite(op, tb, ts - tb);
			r += ts - tb;
		}
	}
	if (e)
		*e = disc->errors;
	return r;
}

/*
 * iconv_list_t iterator
 * call with arg 0 to start
 * prev return value is current arg
 */

_ast_iconv_list_t*
_ast_iconv_list(_ast_iconv_list_t* cp)
{
#if _UWIN
	struct dirent*	ent;

	if (!cp)
	{
		if (!(cp = newof(0, _ast_iconv_list_t, 1, 0)))
			return ccmaplist(NiL);
		if (!(cp->data = opendir(_win_maps)))
		{
			free(cp);
			return ccmaplist(NiL);
		}
	}
	if (cp->data)
	{
		if (ent = readdir((DIR*)cp->data))
		{
			cp->name = cp->match = cp->desc = (const char*)ent->d_name;
			return cp;
		}
		closedir((DIR*)cp->data);
		free(cp);
		return ccmaplist(NiL);
	}
#else
	if (!cp)
		return ccmaplist(NiL);
#endif
	if (cp->ccode >= 0)
		return (cp = ccmaplist(cp)) ? cp : (_ast_iconv_list_t*)codes;
	return (++cp)->name ? cp : (_ast_iconv_list_t*)0;
}
