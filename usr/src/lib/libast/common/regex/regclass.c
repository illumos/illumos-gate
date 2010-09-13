/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2010 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*            http://www.opensource.org/licenses/cpl1.0.txt             *
*         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         *
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
 * RE character class support
 */

#include "reglib.h"

struct Ctype_s; typedef struct Ctype_s Ctype_t;

struct Ctype_s
{
	const char*	name;
	size_t		size;
	regclass_t	ctype;
	Ctype_t*	next;
#if _lib_wctype
	wctype_t	wtype;
#endif
};

static Ctype_t*		ctypes;

#define CTYPES		12
#if _lib_wctype
#define WTYPES		8
#else
#define WTYPES		0
#endif

/*
 * this stuff gets around posix failure to define isblank,
 * and the fact that ctype functions are macros
 * and any local extensions that may not even have functions or macros
 */

#if _need_iswblank

int
_reg_iswblank(wint_t wc)
{
	static int	initialized;
	static wctype_t	wt;

	if (!initialized)
	{
		initialized = 1;
		wt = wctype("blank");
	}
	return iswctype(wc, wt);
}

#endif

static int  Isalnum(int c) { return  iswalnum(c); }
static int  Isalpha(int c) { return  iswalpha(c); }
static int  Isblank(int c) { return  iswblank(c); }
static int  Iscntrl(int c) { return  iswcntrl(c); }
static int  Isdigit(int c) { return  iswdigit(c); }
static int Notdigit(int c) { return !iswdigit(c); }
static int  Isgraph(int c) { return  iswgraph(c); }
static int  Islower(int c) { return  iswlower(c); }
static int  Isprint(int c) { return  iswprint(c); }
static int  Ispunct(int c) { return  iswpunct(c); }
static int  Isspace(int c) { return  iswspace(c); }
static int Notspace(int c) { return !iswspace(c); }
static int  Isupper(int c) { return  iswupper(c); }
static int   Isword(int c) { return  iswalnum(c) || c == '_'; }
static int  Notword(int c) { return !iswalnum(c) && c != '_'; }
static int Isxdigit(int c) { return  iswxdigit(c);}

#if _lib_wctype

static int Is_wc_1(int);
static int Is_wc_2(int);
static int Is_wc_3(int);
static int Is_wc_4(int);
static int Is_wc_5(int);
static int Is_wc_6(int);
static int Is_wc_7(int);
static int Is_wc_8(int);

#endif

#define SZ(s)		s,(sizeof(s)-1)

static Ctype_t ctype[] =
{
	{ SZ("alnum"), Isalnum },
	{ SZ("alpha"), Isalpha },
	{ SZ("blank"), Isblank },
	{ SZ("cntrl"), Iscntrl },
	{ SZ("digit"), Isdigit },
	{ SZ("graph"), Isgraph },
	{ SZ("lower"), Islower },
	{ SZ("print"), Isprint },
	{ SZ("punct"), Ispunct },
	{ SZ("space"), Isspace },
	{ SZ("upper"), Isupper },
	{ SZ("word"),  Isword  },
	{ SZ("xdigit"),Isxdigit},
#if _lib_wctype
	{ 0, 0,        Is_wc_1 },
	{ 0, 0,        Is_wc_2 },
	{ 0, 0,        Is_wc_3 },
	{ 0, 0,        Is_wc_4 },
	{ 0, 0,        Is_wc_5 },
	{ 0, 0,        Is_wc_6 },
	{ 0, 0,        Is_wc_7 },
	{ 0, 0,        Is_wc_8 },
#endif
};

#if _lib_wctype

static int Is_wc_1(int c) { return iswctype(c, ctype[CTYPES+0].wtype); }
static int Is_wc_2(int c) { return iswctype(c, ctype[CTYPES+1].wtype); }
static int Is_wc_3(int c) { return iswctype(c, ctype[CTYPES+2].wtype); }
static int Is_wc_4(int c) { return iswctype(c, ctype[CTYPES+3].wtype); }
static int Is_wc_5(int c) { return iswctype(c, ctype[CTYPES+4].wtype); }
static int Is_wc_6(int c) { return iswctype(c, ctype[CTYPES+5].wtype); }
static int Is_wc_7(int c) { return iswctype(c, ctype[CTYPES+6].wtype); }
static int Is_wc_8(int c) { return iswctype(c, ctype[CTYPES+7].wtype); }

#endif

/*
 * return pointer to ctype function for :class:] in s
 * s points to the first char after the initial [
 * if e!=0 it points to next char in s
 * 0 returned on error
 */

regclass_t
regclass(const char* s, char** e)
{
	register Ctype_t*	cp;
	register int		c;
	register size_t		n;
	register const char*	t;

	if (c = *s++)
	{
		for (t = s; *t && (*t != c || *(t + 1) != ']'); t++);
		if (*t != c)
			return 0;
		n = t - s;
		for (cp = ctypes; cp; cp = cp->next)
			if (n == cp->size && strneq(s, cp->name, n))
				goto found;
		for (cp = ctype; cp < &ctype[elementsof(ctype)]; cp++)
		{
#if _lib_wctype
			if (!cp->size && (cp->name = (const char*)memdup(s, n + 1)))
			{
				*((char*)cp->name + n) = 0;
				/* mvs.390 needs the (char*) cast -- barf */
				if (!(cp->wtype = wctype((char*)cp->name)))
				{
					free((char*)cp->name);
					return 0;
				}
				cp->size = n;
				goto found;
			}
#endif
			if (n == cp->size && strneq(s, cp->name, n))
				goto found;
		}
	}
	return 0;
 found:
	if (e)
		*e = (char*)t + 2;
	return cp->ctype;
}

/*
 * associate the ctype function fun with name
 */

int
regaddclass(const char* name, regclass_t fun)
{
	register Ctype_t*	cp;
	register Ctype_t*	np;
	register size_t		n;

	n = strlen(name);
	for (cp = ctypes; cp; cp = cp->next)
		if (cp->size == n && strneq(name, cp->name, n))
		{
			cp->ctype = fun;
			return 0;
		}
	if (!(np = newof(0, Ctype_t, 1, n + 1)))
		return REG_ESPACE;
	np->size = n;
	np->name = strcpy((char*)(np + 1), name);
	np->ctype = fun;
	np->next = ctypes;
	ctypes = np;
	return 0;
}

/*
 * return pointer to ctype function for token
 */

regclass_t
classfun(int type)
{
	switch (type)
	{
	case T_ALNUM:		return  Isword;
	case T_ALNUM_NOT:	return Notword;
	case T_DIGIT:		return  Isdigit;
	case T_DIGIT_NOT:	return Notdigit;
	case T_SPACE:		return  Isspace;
	case T_SPACE_NOT:	return Notspace;
	}
	return 0;
}
