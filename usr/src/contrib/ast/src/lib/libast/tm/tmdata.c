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
 * time conversion support readonly data
 */

#include <ast.h>
#include <tm.h>

/*
 * default format strings -- must agree with TM_* indices
 */

static char*		format[] =
{
	"Jan",		"Feb",		"Mar",		"Apr",
	"May",		"Jun",		"Jul",		"Aug",
	"Sep",		"Oct",		"Nov",		"Dec",

	"January",	"February",	"March",	"April",
	"May",		"June",		"July",		"August",
	"September",	"October",	"November",	"December",

	"Sun",		"Mon",		"Tue",		"Wed",
	"Thu",		"Fri",		"Sat",

	"Sunday",	"Monday",	"Tuesday",	"Wednesday",
	"Thursday",	"Friday",	"Saturday",

	"%H:%M:%S",	"%m/%d/%y",	"%a %b %e %T %Z %Y",

	"AM",		"PM",

	"GMT",		"UTC",		"UCT",		"CUT",

	"DST",		"",		"",		"",

	"s",		"es",		"",		"",

	"second",	"minute",	"hour",		"day",
	"week",		"month",	"year",

	"midnight",	"morning",	"noon",		"evening",

	"yesterday",	"today",	"tomorrow",

	"last",		"ago",		"past",
	"this",		"now",		"current",
	"in",		"next",		"hence",
	"exactly",	"",		"",

	"at",		"on",		"",		"",

	"st",		"nd",		"rd",		"th",		"th",
	"th",		"th",		"th",		"th",		"th",

	"",		"",		"",		"",		"",
	"",		"",		"",		"",		"",

	"%a %b %e %T %Y",
	"%a %b %e %T %Z %Y",
	"%a %b %e %T %z %Z %Y",
	"%b %e %H:%M",
	"%b %e  %Y",
	"%I:%M:%S %p",

	"",		"",		"",		"",		"",

	"first",	"",		"third",	"fourth",	"fifth",
	"sixth",	"seventh",	"eighth",	"ninth",	"tenth",

	"final",	"ending",	"nth",

	"work",		"working",	"workday",
};

/*
 * format[] lex type classes
 */

static unsigned char	lex[] =
{
	TM_MONTH_ABBREV,TM_MONTH_ABBREV,TM_MONTH_ABBREV,TM_MONTH_ABBREV,
	TM_MONTH_ABBREV,TM_MONTH_ABBREV,TM_MONTH_ABBREV,TM_MONTH_ABBREV,
	TM_MONTH_ABBREV,TM_MONTH_ABBREV,TM_MONTH_ABBREV,TM_MONTH_ABBREV,

	TM_MONTH,	TM_MONTH,	TM_MONTH,	TM_MONTH,
	TM_MONTH,	TM_MONTH,	TM_MONTH,	TM_MONTH,
	TM_MONTH,	TM_MONTH,	TM_MONTH,	TM_MONTH,

	TM_DAY_ABBREV,	TM_DAY_ABBREV,	TM_DAY_ABBREV,	TM_DAY_ABBREV,
	TM_DAY_ABBREV,	TM_DAY_ABBREV,	TM_DAY_ABBREV,

	TM_DAY,		TM_DAY,		TM_DAY,		TM_DAY,
	TM_DAY,		TM_DAY,		TM_DAY,

	0,		0,		0,

	TM_MERIDIAN,	TM_MERIDIAN,

	TM_UT,		TM_UT,		TM_UT,		TM_UT,
	TM_DT,		TM_DT,		TM_DT,		TM_DT,

	TM_SUFFIXES,	TM_SUFFIXES,	TM_SUFFIXES,	TM_SUFFIXES,

	TM_PARTS,	TM_PARTS,	TM_PARTS,	TM_PARTS,
	TM_PARTS,	TM_PARTS,	TM_PARTS,

	TM_HOURS,	TM_HOURS,	TM_HOURS,	TM_HOURS,

	TM_DAYS,	TM_DAYS,	TM_DAYS,

	TM_LAST,	TM_LAST,	TM_LAST,
	TM_THIS,	TM_THIS,	TM_THIS,
	TM_NEXT,	TM_NEXT,	TM_NEXT,
	TM_EXACT,	TM_EXACT,	TM_EXACT,

	TM_NOISE,	TM_NOISE,	TM_NOISE,	TM_NOISE,

	TM_ORDINAL,	TM_ORDINAL,	TM_ORDINAL,	TM_ORDINAL,	TM_ORDINAL,
	TM_ORDINAL,	TM_ORDINAL,	TM_ORDINAL,	TM_ORDINAL,	TM_ORDINAL,

	0,		0,		0,		0,		0,
	0,		0,		0,		0,		0,

	0,		0,		0,
	0,		0,		0,

	0,		0,		0,		0,		0,

	TM_ORDINALS,	TM_ORDINALS,	TM_ORDINALS,	TM_ORDINALS,	TM_ORDINALS,
	TM_ORDINALS,	TM_ORDINALS,	TM_ORDINALS,	TM_ORDINALS,	TM_ORDINALS,

	TM_FINAL,	TM_FINAL,	TM_FINAL,

	TM_WORK,	TM_WORK,	TM_WORK,
};

/*
 * output format digits
 */

static char	digit[] = "0123456789";

/*
 * number of days in month i
 */

static short	days[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

/*
 * sum of days in months before month i
 */

static short	sum[] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 };

/*
 * leap second time_t and accumulated adjustments
 * (reverse order -- biased for recent dates)
 *
 * tl.time is the seconds since the epoch for the leap event
 *
 *	adding:		the first additional second
 *	subtracting:	the first dissappearing second
 */

static Tm_leap_t	leap[] =
{
	 1230768023,   24,		/* 2008-12-31+23:59:60-0000 */
	 1136073622,   23,		/* 2005-12-31+23:59:60-0000 */
	  915148821,   22,		/* 1998-12-31+23:59:60-0000 */
	  867715220,   21,		/* 1997-06-30+23:59:60-0000 */
	  820454419,   20,		/* 1995-12-31+23:59:60-0000 */
	  773020818,   19,		/* 1994-06-30+23:59:60-0000 */
	  741484817,   18,		/* 1993-06-30+23:59:60-0000 */
	  709948816,   17,		/* 1992-06-30+23:59:60-0000 */
	  662688015,   16,		/* 1990-12-31+23:59:60-0000 */
	  631152014,   15,		/* 1989-12-31+23:59:60-0000 */
	  567993613,   14,		/* 1987-12-31+23:59:60-0000 */
	  489024012,   13,		/* 1985-06-30+23:59:60-0000 */
	  425865611,   12,		/* 1983-06-30+23:59:60-0000 */
	  394329610,   11,		/* 1982-06-30+23:59:60-0000 */
	  362793609,   10,		/* 1981-06-30+23:59:60-0000 */
	  315532808,    9,		/* 1979-12-31+23:59:60-0000 */
	  283996807,    8,		/* 1978-12-31+23:59:60-0000 */
	  252460806,    7,		/* 1977-12-31+23:59:60-0000 */
	  220924805,    6,		/* 1976-12-31+23:59:60-0000 */
	  189302404,    5,		/* 1975-12-31+23:59:60-0000 */
	  157766403,    4,		/* 1974-12-31+23:59:60-0000 */
	  126230402,    3,		/* 1973-12-31+23:59:60-0000 */
	   94694401,    2,		/* 1972-12-31+23:59:60-0000 */
	   78796800,    1,		/* 1972-06-30+23:59:60-0000 */
		  0,    0,		/* can reference (tl+1)     */
		  0,    0
};

/*
 * time zones
 *
 * the UTC entries must be first
 *
 * zones with the same type are contiguous with all but the
 * first entry for the type having a null type
 *
 * tz.standard is the sentinel
 */

static Tm_zone_t	zone[] =
{
 0,	"GMT",	0,	 ( 0 * 60),	     0,	/* UTC			*/
 0,	"UCT",	0,	 ( 0 * 60),	     0,	/* UTC			*/
 0,	"UTC",	0,	 ( 0 * 60),	     0,	/* UTC			*/
 0,	"CUT",	0,	 ( 0 * 60),	     0,	/* UTC			*/
 0,	"Z",	0,	 ( 0 * 60),	     0,	/* UTC			*/
 "USA",	"HST",	0,	 (10 * 60),	     0,	/* Hawaii		*/
 0,	"YST",	"YDT",	 ( 9 * 60),	TM_DST,	/* Yukon		*/
 0,	"PST",	"PDT",	 ( 8 * 60),	TM_DST,	/* Pacific		*/
 0,	"PST",	"PPET",	 ( 8 * 60),	TM_DST,	/* Pacific pres elect	*/
 0,	"MST",	"MDT",	 ( 7 * 60),	TM_DST,	/* Mountain		*/
 0,	"CST",	"CDT",	 ( 6 * 60),	TM_DST,	/* Central		*/
 0,	"EST",	"EDT",	 ( 5 * 60),	TM_DST,	/* Eastern		*/
 "CAN",	"AST",	"ADT",	 ( 4 * 60),	TM_DST,	/* Atlantic		*/
 0,	"NST",	0,	 ( 3 * 60 + 30),     0,	/* Newfoundland		*/
 "GBR",	"",	"BST",	 ( 0 * 60),	TM_DST,	/* British Summer	*/
 "EUR",	"WET",	"WEST",	 ( 0 * 60),	TM_DST,	/* Western Eurpoean	*/
 0,	"CET",	"CEST",	-( 1 * 60),	TM_DST,	/* Central European	*/
 0,	"MET",	"MEST",	-( 1 * 60),	TM_DST,	/* Middle European	*/
 0,	"EET",	"EEST",	-( 2 * 60),	TM_DST,	/* Eastern Eurpoean	*/
 "ISR",	"IST",	"IDT",  -( 3 * 60),	TM_DST,	/* Israel		*/
 "IND",	"IST",	0,  	-( 5 * 60 + 30 ),    0,	/* India		*/
 "CHN",	"HKT",	0,	-( 8 * 60),	     0,	/* Hong Kong		*/
 "KOR",	"KST",	"KDT",	-( 8 * 60),	TM_DST,	/* Korea		*/
 "SNG",	"SST",	0,	-( 8 * 60),	     0,	/* Singapore		*/
 "JPN",	"JST",	0,	-( 9 * 60),	     0,	/* Japan		*/
 "AUS",	"AWST",	0,	-( 8 * 60),	     0,	/* Australia Western	*/
 0,	"WST",	0,	-( 8 * 60),	     0,	/* Australia Western	*/
 0,	"ACST",	0,	-( 9 * 60 + 30),TM_DST,	/* Australia Central	*/
 0,	"CST",	0,	-( 9 * 60 + 30),TM_DST,	/* Australia Central	*/
 0,	"AEST",	0,	-(10 * 60),	TM_DST,	/* Australia Eastern	*/
 0,	"EST",	0,	-(10 * 60),	TM_DST,	/* Australia Eastern	*/
 "NZL",	"NZST",	"NZDT",	-(12 * 60),	TM_DST,	/* New Zealand		*/
 0,	0,	0,	0,		     0
};

/*
 * 2007-03-19 move tm_data from _tm_data_ to (*_tm_datap_)
 *	      to allow future Tm_data_t growth
 *            by 2009 _tm_data_ can be static
 */

#if _BLD_ast && defined(__EXPORT__)
#define extern		extern __EXPORT__
#endif

extern Tm_data_t	_tm_data_;

#undef	extern

Tm_data_t _tm_data_ = { format, lex, digit, days, sum, leap, zone };

__EXTERN__(Tm_data_t, _tm_data_);

__EXTERN__(Tm_data_t*, _tm_datap_);

Tm_data_t*		_tm_datap_ = &_tm_data_;
