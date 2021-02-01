/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2011 AT&T Intellectual Property          *
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
 * time conversion translation support
 */

#include <ast.h>
#include <cdt.h>
#include <iconv.h>
#include <mc.h>
#include <tm.h>
#include <ast_nl_types.h>

#include "lclib.h"

static struct
{
	char*		format;
	Lc_info_t*	locale;
	char		null[1];
} state;

/*
 * this is unix dadgummit
 */

static int
standardized(Lc_info_t* li, register char** b)
{
	if ((li->lc->language->flags & (LC_debug|LC_default)) || streq(li->lc->language->code, "en"))
	{
		b[TM_TIME] = "%H:%M:%S";
		b[TM_DATE] = "%m/%d/%y";
		b[TM_DEFAULT] = "%a %b %e %T %Z %Y";
		return 1;
	}
	return 0;
}

/*
 * fix up LC_TIME data after loading
 */

static void
fixup(Lc_info_t* li, register char** b)
{
	register char**		v;
	register char**		e;
	register int		n;

	static int		must[] =
	{
					TM_TIME,
					TM_DATE,
					TM_DEFAULT,
					TM_MERIDIAN,
					TM_UT,
					TM_DT,
					TM_SUFFIXES,
					TM_PARTS,
					TM_HOURS,
					TM_DAYS,
					TM_LAST,
					TM_THIS,
					TM_NEXT,
					TM_EXACT,
					TM_NOISE,
					TM_ORDINAL,
					TM_CTIME,
					TM_DATE_1,
					TM_INTERNATIONAL,
					TM_RECENT,
					TM_DISTANT,
					TM_MERIDIAN_TIME,
					TM_ORDINALS,
					TM_FINAL,
					TM_WORK,
	};

	standardized(li, b);
	for (v = b, e = b + TM_NFORM; v < e; v++)
		if (!*v)
			*v = state.null;
	for (n = 0; n < elementsof(must); n++)
		if (!*b[must[n]])
			b[must[n]] = tm_data.format[must[n]];
	if (li->lc->flags & LC_default)
		for (n = 0; n < TM_NFORM; n++)
			if (!*b[n])
				b[n] = tm_data.format[n];
	if (strchr(b[TM_UT], '%'))
	{
		tm_info.deformat = b[TM_UT];
		for (n = TM_UT; n < TM_DT; n++)
			b[n] = state.null;
	}
	else
		tm_info.deformat = b[TM_DEFAULT];
	tm_info.format = b;
	if (!(tm_info.deformat = state.format))
		tm_info.deformat = tm_info.format[TM_DEFAULT];
	li->data = (void*)b;
}

#if _WINIX

#include <ast_windows.h>

typedef struct Map_s
{
	LCID		native;
	int		local;
} Map_t;

static const Map_t map[] =
{
	LOCALE_S1159,			(TM_MERIDIAN+0),
	LOCALE_S2359,			(TM_MERIDIAN+1),
	LOCALE_SABBREVDAYNAME1,		(TM_DAY_ABBREV+1),
	LOCALE_SABBREVDAYNAME2,		(TM_DAY_ABBREV+2),
	LOCALE_SABBREVDAYNAME3,		(TM_DAY_ABBREV+3),
	LOCALE_SABBREVDAYNAME4,		(TM_DAY_ABBREV+4),
	LOCALE_SABBREVDAYNAME5,		(TM_DAY_ABBREV+5),
	LOCALE_SABBREVDAYNAME6,		(TM_DAY_ABBREV+6),
	LOCALE_SABBREVDAYNAME7,		(TM_DAY_ABBREV+0),
	LOCALE_SABBREVMONTHNAME1,	(TM_MONTH_ABBREV+0),
	LOCALE_SABBREVMONTHNAME2,	(TM_MONTH_ABBREV+1),
	LOCALE_SABBREVMONTHNAME3,	(TM_MONTH_ABBREV+2),
	LOCALE_SABBREVMONTHNAME4,	(TM_MONTH_ABBREV+3),
	LOCALE_SABBREVMONTHNAME5,	(TM_MONTH_ABBREV+4),
	LOCALE_SABBREVMONTHNAME6,	(TM_MONTH_ABBREV+5),
	LOCALE_SABBREVMONTHNAME7,	(TM_MONTH_ABBREV+6),
	LOCALE_SABBREVMONTHNAME8,	(TM_MONTH_ABBREV+7),
	LOCALE_SABBREVMONTHNAME9,	(TM_MONTH_ABBREV+8),
	LOCALE_SABBREVMONTHNAME10,	(TM_MONTH_ABBREV+9),
	LOCALE_SABBREVMONTHNAME11,	(TM_MONTH_ABBREV+10),
	LOCALE_SABBREVMONTHNAME12,	(TM_MONTH_ABBREV+11),
	LOCALE_SDAYNAME1,		(TM_DAY+1),
	LOCALE_SDAYNAME2,		(TM_DAY+2),
	LOCALE_SDAYNAME3,		(TM_DAY+3),
	LOCALE_SDAYNAME4,		(TM_DAY+4),
	LOCALE_SDAYNAME5,		(TM_DAY+5),
	LOCALE_SDAYNAME6,		(TM_DAY+6),
	LOCALE_SDAYNAME7,		(TM_DAY+0),
	LOCALE_SMONTHNAME1,		(TM_MONTH+0),
	LOCALE_SMONTHNAME2,		(TM_MONTH+1),
	LOCALE_SMONTHNAME3,		(TM_MONTH+2),
	LOCALE_SMONTHNAME4,		(TM_MONTH+3),
	LOCALE_SMONTHNAME5,		(TM_MONTH+4),
	LOCALE_SMONTHNAME6,		(TM_MONTH+5),
	LOCALE_SMONTHNAME7,		(TM_MONTH+6),
	LOCALE_SMONTHNAME8,		(TM_MONTH+7),
	LOCALE_SMONTHNAME9,		(TM_MONTH+8),
	LOCALE_SMONTHNAME10,		(TM_MONTH+9),
	LOCALE_SMONTHNAME11,		(TM_MONTH+10),
	LOCALE_SMONTHNAME12,		(TM_MONTH+11),
};

#undef	extern

/*
 * convert ms word date spec w to posix strftime format f
 * next char after f returned
 * the caller already made sure f is big enough
 */

static char*
word2posix(register char* f, register char* w, int alternate)
{
	register char*	r;
	register int	c;
	register int	p;
	register int	n;

	while (*w)
	{
		p = 0;
		r = w;
		while (*++w == *r);
		if ((n = w - r) > 3 && alternate)
			n--;
		switch (*r)
		{
		case 'a':
		case 'A':
			if (!strncasecmp(w, "am/pm", 5))
				w += 5;
			else if (!strncasecmp(w, "a/p", 3))
				w += 3;
			c = 'p';
			break;
		case 'd':
			switch (n)
			{
			case 1:
				p = '-';
				/*FALLTHROUGH*/
			case 2:
				c = 'd';
				break;
			case 3:
				c = 'a';
				break;
			default:
				c = 'A';
				break;
			}
			break;
		case 'h':
			switch (n)
			{
			case 1:
				p = '-';
				/*FALLTHROUGH*/
			default:
				c = 'I';
				break;
			}
			break;
		case 'H':
			switch (n)
			{
			case 1:
				p = '-';
				/*FALLTHROUGH*/
			default:
				c = 'H';
				break;
			}
			break;
		case 'M':
			switch (n)
			{
			case 1:
				p = '-';
				/*FALLTHROUGH*/
			case 2:
				c = 'm';
				break;
			case 3:
				c = 'b';
				break;
			default:
				c = 'B';
				break;
			}
			break;
		case 'm':
			switch (n)
			{
			case 1:
				p = '-';
				/*FALLTHROUGH*/
			default:
				c = 'M';
				break;
			}
			break;
		case 's':
			switch (n)
			{
			case 1:
				p = '-';
				/*FALLTHROUGH*/
			default:
				c = 'S';
				break;
			}
			break;
		case 'y':
			switch (n)
			{
			case 1:
				p = '-';
				/*FALLTHROUGH*/
			case 2:
				c = 'y';
				break;
			default:
				c = 'Y';
				break;
			}
			break;
		case '\'':
			if (n & 1)
				for (w = r + 1; *w; *f++ = *w++)
					if (*w == '\'')
					{
						w++;
						break;
					}
			continue;
		case '%':
			while (r < w)
			{
				*f++ = *r++;
				*f++ = *r++;
			}
			continue;
		default:
			while (r < w)
				*f++ = *r++;
			continue;
		}
		*f++ = '%';
		if (p)
			*f++ = '-';
		*f++ = c;
	}
	*f++ = 0;
	return f;
}

/*
 * load the native LC_TIME data for the current locale
 */

static void
native_lc_time(Lc_info_t* li)
{
	register char*	s;
	register char*	t;
	register char**	b;
	register int	n;
	register int	m;
	register int	i;
	LCID		lcid;
	int		nt;
	int		ns;
	int		nl;
	int		clock_24;
	int		leading_0;
	char		buf[256];

	lcid = li->lc->index;
	nt = 2 * GetLocaleInfo(lcid, LOCALE_STIME, 0, 0) + 7; /* HH:MM:SS */
	ns = 3 * GetLocaleInfo(lcid, LOCALE_SSHORTDATE, 0, 0);
	nl = 3 * GetLocaleInfo(lcid, LOCALE_SLONGDATE, 0, 0);
	n = nt + ns + nl;
	for (i = 0; i < elementsof(map); i++)
		n += GetLocaleInfo(lcid, map[i].native, 0, 0);
	if (!(b = newof(0, char*, TM_NFORM, n)))
		return;
	s = (char*)(b + TM_NFORM);
	for (i = 0; i < elementsof(map); i++)
	{
		if (!(m = GetLocaleInfo(lcid, map[i].native, s, n)))
			goto bad;
		b[map[i].local] = s;
		s += m;
	}
	if (!standardized(li, b))
	{
		/*
		 * synthesize TM_TIME format from the ms word template
		 */

		if (!GetLocaleInfo(lcid, LOCALE_ITIME, buf, sizeof(buf)))
			goto bad;
		clock_24 = atoi(buf);
		if (!GetLocaleInfo(lcid, LOCALE_ITLZERO, buf, sizeof(buf)))
			goto bad;
		leading_0 = atoi(buf);
		if (!GetLocaleInfo(lcid, LOCALE_STIME, buf, sizeof(buf)))
			goto bad;
		b[TM_TIME] = s;
		*s++ = '%';
		if (!leading_0)
			*s++ = '-';
		*s++ = clock_24 ? 'H' : 'I';
		for (t = buf; *s = *t++; s++);
		*s++ = '%';
		if (!leading_0)
			*s++ = '-';
		*s++ = 'M';
		for (t = buf; *s = *t++; s++);
		*s++ = '%';
		if (!leading_0)
			*s++ = '-';
		*s++ = 'S';
		*s++ = 0;

		/*
		 * synthesize TM_DATE format
		 */

		if (!GetLocaleInfo(lcid, LOCALE_SSHORTDATE, buf, sizeof(buf)))
			goto bad;
		b[TM_DATE] = s;
		s = word2posix(s, buf, 1);

		/*
		 * synthesize TM_DEFAULT format
		 */

		if (!GetLocaleInfo(lcid, LOCALE_SLONGDATE, buf, sizeof(buf)))
			goto bad;
		b[TM_DEFAULT] = s;
		s = word2posix(s, buf, 1);
		strcpy(s - 1, " %X");
	}

	/*
	 * done
	 */

	fixup(li, b);
	return;
 bad:
	free(b);
}

#else

#if _lib_nl_langinfo && _hdr_langinfo

#if _hdr_nl_types
#include <nl_types.h>
#endif

#include <langinfo.h>

typedef struct Map_s
{
	int		native;
	int		local;
} Map_t;

static const Map_t map[] =
{
	AM_STR,				(TM_MERIDIAN+0),
	PM_STR,				(TM_MERIDIAN+1),
	ABDAY_1,			(TM_DAY_ABBREV+0),
	ABDAY_2,			(TM_DAY_ABBREV+1),
	ABDAY_3,			(TM_DAY_ABBREV+2),
	ABDAY_4,			(TM_DAY_ABBREV+3),
	ABDAY_5,			(TM_DAY_ABBREV+4),
	ABDAY_6,			(TM_DAY_ABBREV+5),
	ABDAY_7,			(TM_DAY_ABBREV+6),
	ABMON_1,			(TM_MONTH_ABBREV+0),
	ABMON_2,			(TM_MONTH_ABBREV+1),
	ABMON_3,			(TM_MONTH_ABBREV+2),
	ABMON_4,			(TM_MONTH_ABBREV+3),
	ABMON_5,			(TM_MONTH_ABBREV+4),
	ABMON_6,			(TM_MONTH_ABBREV+5),
	ABMON_7,			(TM_MONTH_ABBREV+6),
	ABMON_8,			(TM_MONTH_ABBREV+7),
	ABMON_9,			(TM_MONTH_ABBREV+8),
	ABMON_10,			(TM_MONTH_ABBREV+9),
	ABMON_11,			(TM_MONTH_ABBREV+10),
	ABMON_12,			(TM_MONTH_ABBREV+11),
	DAY_1,				(TM_DAY+0),
	DAY_2,				(TM_DAY+1),
	DAY_3,				(TM_DAY+2),
	DAY_4,				(TM_DAY+3),
	DAY_5,				(TM_DAY+4),
	DAY_6,				(TM_DAY+5),
	DAY_7,				(TM_DAY+6),
	MON_1,				(TM_MONTH+0),
	MON_2,				(TM_MONTH+1),
	MON_3,				(TM_MONTH+2),
	MON_4,				(TM_MONTH+3),
	MON_5,				(TM_MONTH+4),
	MON_6,				(TM_MONTH+5),
	MON_7,				(TM_MONTH+6),
	MON_8,				(TM_MONTH+7),
	MON_9,				(TM_MONTH+8),
	MON_10,				(TM_MONTH+9),
	MON_11,				(TM_MONTH+10),
	MON_12,				(TM_MONTH+11),
#ifdef _DATE_FMT
	_DATE_FMT,			TM_DEFAULT,
#else
	D_T_FMT,			TM_DEFAULT,
#endif
	D_FMT,				TM_DATE,
	T_FMT,				TM_TIME,
#ifdef ERA
	ERA,				TM_ERA,
	ERA_D_T_FMT,			TM_ERA_DEFAULT,
	ERA_D_FMT,			TM_ERA_DATE,
	ERA_T_FMT,			TM_ERA_TIME,
#endif
#ifdef ALT_DIGITS
	ALT_DIGITS,			TM_DIGITS,
#endif
};

static void
native_lc_time(Lc_info_t* li)
{
	register char*	s;
	register char*	t;
	register char**	b;
	register int	n;
	register int	i;

	n = 0;
	for (i = 0; i < elementsof(map); i++)
	{
		if (!(t = nl_langinfo(map[i].native)))
			t = tm_data.format[map[i].local];
		n += strlen(t) + 1;
	}
	if (!(b = newof(0, char*, TM_NFORM, n)))
		return;
	s = (char*)(b + TM_NFORM);
	for (i = 0; i < elementsof(map); i++)
	{
		b[map[i].local] = s;
		if (!(t = nl_langinfo(map[i].native)))
			t = tm_data.format[map[i].local];
		while (*s++ = *t++);
	}
	fixup(li, b);
}

#else

#define native_lc_time(li)	((li->data=(void*)(tm_info.format=tm_data.format)),(tm_info.deformat=tm_info.format[TM_DEFAULT]))

#endif

#endif

/*
 * load the LC_TIME data for the current locale
 */

static void
load(Lc_info_t* li)
{
	register char*		s;
	register char**		b;
	register char**		v;
	register char**		e;
	unsigned char*		u;
	ssize_t			n;
	iconv_t			cvt;
	Sfio_t*			sp;
	Sfio_t*			tp;
	char			path[PATH_MAX];

	if (b = (char**)li->data)
	{
		tm_info.format = b;
		if (!(tm_info.deformat = state.format))
			tm_info.deformat = tm_info.format[TM_DEFAULT];
		return;
	}
	tm_info.format = tm_data.format;
	if (!(tm_info.deformat = state.format))
		tm_info.deformat = tm_info.format[TM_DEFAULT];
	if (mcfind(NiL, NiL, LC_TIME, 0, path, sizeof(path)) && (sp = sfopen(NiL, path, "r")))
	{
		n = sfsize(sp);
		tp = 0;
		if (u = (unsigned char*)sfreserve(sp, 3, 1))
		{
			if (u[0] == 0xef && u[1] == 0xbb && u[2] == 0xbf && (cvt = iconv_open("", "utf")) != (iconv_t)(-1))
			{
				if (tp = sfstropen())
				{
					sfread(sp, u, 3);
					n = iconv_move(cvt, sp, tp, SF_UNBOUND, NiL);
				}
				iconv_close(cvt);
			}
			if (!tp)
				sfread(sp, u, 0);
		}
		if (b = newof(0, char*, TM_NFORM, n + 2))
		{
			v = b;
			e = b + TM_NFORM;
			s = (char*)e;
			if (tp && memcpy(s, sfstrbase(tp), n) || !tp && sfread(sp, s, n) == n)
			{
				s[n] = '\n';
				while (v < e)
				{
					*v++ = s;
					if (!(s = strchr(s, '\n')))
						break;
					*s++ = 0;
				}
				fixup(li, b);
			}
			else
				free(b);
		}
		if (tp)
			sfclose(tp);
		sfclose(sp);
	}
	else
		native_lc_time(li);
}

/*
 * check that tm_info.format matches the current locale
 */

char**
tmlocale(void)
{
	Lc_info_t*	li;

	if (!tm_info.format)
	{
		tm_info.format = tm_data.format;
		if (!tm_info.deformat)
			tm_info.deformat = tm_info.format[TM_DEFAULT];
		else if (tm_info.deformat != tm_info.format[TM_DEFAULT])
			state.format = tm_info.deformat;
	}
	li = LCINFO(AST_LC_TIME);
	if (!li->data)
		load(li);
	return tm_info.format;
}
