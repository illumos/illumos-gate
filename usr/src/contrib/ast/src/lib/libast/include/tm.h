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
 * time conversion support definitions
 */

#ifndef _TM_H
#define _TM_H

#define TM_VERSION	20070319L

#include <ast.h>
#include <times.h>

#undef	daylight

#define tmset(z)	tminit(z)
#define tmisleapyear(y)	(!((y)%4)&&(((y)%100)||!((((y)<1900)?((y)+1900):(y))%400)))

#define TM_ADJUST	(1<<0)		/* local doesn't do leap secs	*/
#define TM_LEAP		(1<<1)		/* do leap seconds		*/
#define TM_UTC		(1<<2)		/* universal coordinated ref	*/

#define TM_PEDANTIC	(1<<3)		/* pedantic date parse		*/
#define TM_DATESTYLE	(1<<4)		/* date(1) style mmddHHMMccyy	*/
#define TM_SUBSECOND	(1<<5)		/* <something>%S => ...%S.%P	*/

#define TM_DST		(-60)		/* default minutes for DST	*/
#define TM_LOCALZONE	(25 * 60)	/* use local time zone offset	*/
#define TM_UTCZONE	(26 * 60)	/* UTC "time zone"		*/
#define TM_MAXLEAP	1		/* max leap secs per leap	*/
#define TM_WINDOW	69		/* century windowing guard year	*/

/*
 * these indices must agree with tm_dform[]
 */

#define TM_MONTH_ABBREV		0
#define TM_MONTH		12
#define TM_DAY_ABBREV		24
#define TM_DAY			31
#define TM_TIME			38
#define TM_DATE			39
#define TM_DEFAULT		40
#define TM_MERIDIAN		41

#define TM_UT			43
#define TM_DT			47
#define TM_SUFFIXES		51
#define TM_PARTS		55
#define TM_HOURS		62
#define TM_DAYS			66
#define TM_LAST			69
#define TM_THIS			72
#define TM_NEXT			75
#define TM_EXACT		78
#define TM_NOISE		81
#define TM_ORDINAL		85
#define TM_DIGITS		95
#define TM_CTIME		105
#define TM_DATE_1		106
#define TM_INTERNATIONAL	107
#define TM_RECENT		108
#define TM_DISTANT		109
#define TM_MERIDIAN_TIME	110
#define TM_ERA			111
#define TM_ERA_DATE		112
#define TM_ERA_TIME		113
#define TM_ERA_DEFAULT		114
#define TM_ERA_YEAR		115
#define TM_ORDINALS		116
#define TM_FINAL		126
#define TM_WORK			129

#define TM_NFORM		132

typedef struct				/* leap second info		*/
{
	time_t		time;		/* the leap second event	*/
	int		total;		/* inclusive total since epoch	*/
} Tm_leap_t;

typedef struct				/* time zone info		*/
{
	char*		type;		/* type name			*/
	char*		standard;	/* standard time name		*/
	char*		daylight;	/* daylight or summertime name	*/
	short		west;		/* minutes west of GMT		*/
	short		dst;		/* add to tz.west for DST	*/
} Tm_zone_t;

typedef struct				/* tm library readonly data	*/
{
	char**		format;		/* default TM_* format strings	*/
	unsigned char*	lex;		/* format lex type classes	*/
	char*		digit;		/* output digits		*/
	short*		days;		/* days in month i		*/
	short*		sum;		/* days in months before i	*/
	Tm_leap_t*	leap;		/* leap second table		*/
	Tm_zone_t*	zone;		/* alternate timezone table	*/
} Tm_data_t;

typedef struct				/* tm library global info	*/
{
	char*		deformat;	/* TM_DEFAULT override		*/
	int		flags;		/* flags			*/
	char**		format;		/* current format strings	*/
	Tm_zone_t*	date;		/* timezone from last tmdate()	*/
	Tm_zone_t*	local;		/* local timezone		*/
	Tm_zone_t*	zone;		/* current timezone		*/
} Tm_info_t;

typedef struct Tm_s
{
	int			tm_sec;
	int			tm_min;
	int			tm_hour;
	int			tm_mday;
	int			tm_mon;
	int			tm_year;
	int			tm_wday;
	int			tm_yday;
	int			tm_isdst;
	uint32_t		tm_nsec;
	Tm_zone_t*		tm_zone;
} Tm_t;

#if _BLD_ast && defined(__EXPORT__)
#define extern		extern __EXPORT__
#endif
#if !_BLD_ast && defined(__IMPORT__)
#define extern		extern __IMPORT__
#endif

extern Tm_data_t*	_tm_datap_;
extern Tm_info_t*	_tm_infop_;

#define tm_data		(*_tm_datap_)
#define tm_info		(*_tm_infop_)

#undef	extern

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

extern time_t		tmdate(const char*, char**, time_t*);
extern int		tmequiv(Tm_t*);
extern Tm_t*		tmfix(Tm_t*);
extern char*		tmfmt(char*, size_t, const char*, time_t*);
extern char*		tmform(char*, const char*, time_t*);
extern int		tmgoff(const char*, char**, int);
extern void		tminit(Tm_zone_t*);
extern time_t		tmleap(time_t*);
extern int		tmlex(const char*, char**, char**, int, char**, int);
extern char**		tmlocale(void);
extern Tm_t*		tmmake(time_t*);
extern char*		tmpoff(char*, size_t, const char*, int, int);
extern time_t		tmscan(const char*, char**, const char*, char**, time_t*, long);
extern int		tmsleep(time_t, time_t);
extern time_t		tmtime(Tm_t*, int);
extern Tm_zone_t*	tmtype(const char*, char**);
extern int		tmweek(Tm_t*, int, int, int);
extern int		tmword(const char*, char**, const char*, char**, int);
extern Tm_zone_t*	tmzone(const char*, char**, const char*, int*);

#undef	extern

#endif
