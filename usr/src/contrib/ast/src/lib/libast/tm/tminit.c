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
 * time conversion support
 */

#include <tm.h>
#include <ctype.h>
#include <namval.h>

#include "FEATURE/tmlib"

#ifndef tzname
#	if defined(__DYNAMIC__)
#		undef	_dat_tzname
#		define	tzname		__DYNAMIC__(tzname)
#	else
#		if !_dat_tzname
#			if _dat__tzname
#				undef	_dat_tzname
#				define _dat_tzname	1
#				define tzname		_tzname
#			endif
#		endif
#	endif
#	if _dat_tzname && !defined(tzname)
		extern char*		tzname[];
#	endif
#endif

#define TM_type		(-1)

static const Namval_t		options[] =
{
	"adjust",	TM_ADJUST,
	"format",	TM_DEFAULT,
	"leap",		TM_LEAP,
	"subsecond",	TM_SUBSECOND,
	"type",		TM_type,
	"utc",		TM_UTC,
	0,		0
};

/*
 * 2007-03-19 move tm_info from _tm_info_ to (*_tm_infop_)
 *	      to allow future Tm_info_t growth
 *            by 2009 _tm_info_ can be static
 */

#if _BLD_ast && defined(__EXPORT__)
#define extern		extern __EXPORT__
#endif

extern Tm_info_t	_tm_info_;

#undef	extern

Tm_info_t		_tm_info_ = { 0 };

__EXTERN__(Tm_info_t, _tm_info_);

__EXTERN__(Tm_info_t*, _tm_infop_);

Tm_info_t*		_tm_infop_ = &_tm_info_;

#if _tzset_environ

static char	TZ[256];
static char*	TE[2];

struct tm*
_tm_localtime(const time_t* t)
{
	struct tm*	r;
	char*		e;
	char**		v = environ;

	if (TZ[0])
	{
		if (!environ || !*environ)
			environ = TE;
		else
			e = environ[0];
		environ[0] = TZ;
	}
	r = localtime(t);
	if (TZ[0])
	{
		if (environ != v)
			environ = v;
		else
			environ[0] = e;
	}
	return r;
}

#endif

/*
 * return minutes west of GMT for local time clock
 *
 * isdst will point to non-zero if DST is in effect
 * this routine also kicks in the local initialization
 */

static int
tzwest(time_t* clock, int* isdst)
{
	register struct tm*	tp;
	register int		n;
	register int		m;
	int			h;
	time_t			epoch;

	/*
	 * convert to GMT assuming local time
	 */

	if (!(tp = gmtime(clock)))
	{
		/*
		 * some systems return 0 for negative time_t
		 */

		epoch = 0;
		clock = &epoch;
		tp = gmtime(clock);
	}
	n = tp->tm_yday;
	h = tp->tm_hour;
	m = tp->tm_min;

	/*
	 * tmlocaltime() handles DST and GMT offset
	 */

	tp = tmlocaltime(clock);
	if (n = tp->tm_yday - n)
	{
		if (n > 1)
			n = -1;
		else if (n < -1)
			n = 1;
	}
	*isdst = tp->tm_isdst;
	return (h - tp->tm_hour - n * 24) * 60 + m - tp->tm_min;
}

/*
 * stropt() option handler
 */

static int
tmopt(void* a, const void* p, int n, const char* v)
{
	Tm_zone_t*	zp;

	NoP(a);
	if (p)
		switch (((Namval_t*)p)->value)
		{
		case TM_DEFAULT:
			tm_info.deformat = (n && (n = strlen(v)) > 0 && (n < 2 || v[n-2] != '%' || v[n-1] != '?')) ? strdup(v) : tm_info.format[TM_DEFAULT];
			break;
		case TM_type:
			tm_info.local->type = (n && *v) ? ((zp = tmtype(v, NiL)) ? zp->type : strdup(v)) : 0;
			break;
		default:
			if (n)
				tm_info.flags |= ((Namval_t*)p)->value;
			else
				tm_info.flags &= ~((Namval_t*)p)->value;
			break;
		}
	return 0;
}

/*
 * initialize the local timezone
 */

static void
tmlocal(void)
{
	register Tm_zone_t*	zp;
	register int		n;
	register char*		s;
	register char*		e;
	int			i;
	int			m;
	int			isdst;
	char*			t;
	struct tm*		tp;
	time_t			now;
	char			buf[16];

	static Tm_zone_t	local;

#if _tzset_environ
	{
		char**	v = environ;

		if (s = getenv("TZ"))
		{
			sfsprintf(TZ, sizeof(TZ), "TZ=%s", s);
			if (!environ || !*environ)
				environ = TE;
			else
				e = environ[0];
			environ[0] = TZ;
		}
		else
		{
			TZ[0] = 0;
			e = 0;
		}
#endif
#if _lib_tzset
		tzset();
#endif
#if _tzset_environ
		if (environ != v)
			environ = v;
		else if (e)
			environ[0] = e;
	}
#endif
#if _dat_tzname
	local.standard = strdup(tzname[0]);
	local.daylight = strdup(tzname[1]);
#endif
	tmlocale();

	/*
	 * tm_info.local
	 */

	tm_info.zone = tm_info.local = &local;
	time(&now);
	n = tzwest(&now, &isdst);

	/*
	 * compute local DST offset by roaming
	 * through the last 12 months until tzwest() changes
	 */

	for (i = 0; i < 12; i++)
	{
		now -= 31 * 24 * 60 * 60;
		if ((m = tzwest(&now, &isdst)) != n)
		{
			if (!isdst)
			{
				isdst = n;
				n = m;
				m = isdst;
			}
			m -= n;
			break;
		}
	}
	local.west = n;
	local.dst = m;

	/*
	 * now get the time zone names
	 */

#if _dat_tzname
	if (tzname[0])
	{
		/*
		 * POSIX
		 */

		if (!local.standard)
			local.standard = strdup(tzname[0]);
		if (!local.daylight)
			local.daylight = strdup(tzname[1]);
	}
	else
#endif
	if ((s = getenv("TZNAME")) && *s && (s = strdup(s)))
	{
		/*
		 * BSD
		 */

		local.standard = s;
		if (s = strchr(s, ','))
			*s++ = 0;
		else
			s = "";
		local.daylight = s;
	}
	else if ((s = getenv("TZ")) && *s && *s != ':' && (s = strdup(s)))
	{
		/*
		 * POSIX style but skipped by tmlocaltime()
		 */

		local.standard = s;
		if (*++s && *++s && *++s)
		{
			*s++ = 0;
			tmgoff(s, &t, 0);
			for (s = t; isalpha(*t); t++);
			*t = 0;
		}
		else
			s = "";
		local.daylight = s;
	}
	else
	{
		/*
		 * tm_data.zone table lookup
		 */

		t = 0;
		for (zp = tm_data.zone; zp->standard; zp++)
		{
			if (zp->type)
				t = zp->type;
			if (zp->west == n && zp->dst == m)
			{
				local.type = t;
				local.standard = zp->standard;
				if (!(s = zp->daylight))
				{
					e = (s = buf) + sizeof(buf);
					s = tmpoff(s, e - s, zp->standard, 0, 0);
					if (s < e - 1)
					{
						*s++ = ' ';
						tmpoff(s, e - s, tm_info.format[TM_DT], m, TM_DST);
					}
					s = strdup(buf);
				}
				local.daylight = s;
				break;
			}
		}
		if (!zp->standard)
		{
			/*
			 * not in the table
			 */

			e = (s = buf) + sizeof(buf);
			s = tmpoff(s, e - s, tm_info.format[TM_UT], n, 0);
			local.standard = strdup(buf);
			if (s < e - 1)
			{
				*s++ = ' ';
				tmpoff(s, e - s, tm_info.format[TM_UT], m, TM_DST);
				local.daylight = strdup(buf);
			}
		}
	}

	/*
	 * set the options
	 */

	stropt(getenv("TM_OPTIONS"), options, sizeof(*options), tmopt, NiL);

	/*
	 * the time zone type is probably related to the locale
	 */

	if (!local.type)
	{
		s = local.standard;
		t = 0;
		for (zp = tm_data.zone; zp->standard; zp++)
		{
			if (zp->type)
				t = zp->type;
			if (tmword(s, NiL, zp->standard, NiL, 0))
			{
				local.type = t;
				break;
			}
		}
	}

	/*
	 * tm_info.flags
	 */

	if (!(tm_info.flags & TM_ADJUST))
	{
		now = (time_t)78811200;		/* Jun 30 1972 23:59:60 */
		tp = tmlocaltime(&now);
		if (tp->tm_sec != 60)
			tm_info.flags |= TM_ADJUST;
	}
	if (!(tm_info.flags & TM_UTC))
	{
		s = local.standard;
		zp = tm_data.zone;
		if (local.daylight)
			zp++;
		for (; !zp->type && zp->standard; zp++)
			if (tmword(s, NiL, zp->standard, NiL, 0))
			{
				tm_info.flags |= TM_UTC;
				break;
			}
	}
}

/*
 * initialize tm data
 */

void
tminit(register Tm_zone_t* zp)
{
	static uint32_t		serial = ~(uint32_t)0;

	if (serial != ast.env_serial)
	{
		serial = ast.env_serial;
		if (tm_info.local)
		{
			memset(tm_info.local, 0, sizeof(*tm_info.local));
			tm_info.local = 0;
		}
	}
	if (!tm_info.local)
		tmlocal();
	if (!zp)
		zp = tm_info.local;
	tm_info.zone = zp;
}
