/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 1995-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
	  /* from Arthur Olson's 6.1 */

/*LINTLIBRARY*/

#include <tzfile.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>	/* for NULL */
#include <fcntl.h>

#include <sys/param.h>	/* for MAXPATHLEN */

#undef	FILENAME_MAX
#define	FILENAME_MAX	MAXPATHLEN

#ifdef __STDC__

#define P(s)		s

#else /* !defined __STDC__ */

/*
** Memory management functions
*/

extern char *	calloc();
extern char *	malloc();

/*
** Communication with the environment
*/

extern char *	getenv();

#define ASTERISK	*
#define P(s)		(/ASTERISK s ASTERISK/)

#define const

#endif /* !defined __STDC__ */

#ifndef TRUE
#define TRUE		1
#define FALSE		0
#endif /* !defined TRUE */

#define ACCESS_MODE	O_RDONLY

#define OPEN_MODE	O_RDONLY

/*
** Someone might make incorrect use of a time zone abbreviation:
**	1.	They might reference tzname[0] before calling tzset (explicitly
**	 	or implicitly).
**	2.	They might reference tzname[1] before calling tzset (explicitly
**	 	or implicitly).
**	3.	They might reference tzname[1] after setting to a time zone
**		in which Daylight Saving Time is never observed.
**	4.	They might reference tzname[0] after setting to a time zone
**		in which Standard Time is never observed.
**	5.	They might reference tm.TM_ZONE after calling offtime.
** What's best to do in the above cases is open to debate;
** for now, we just set things up so that in any of the five cases
** WILDABBR is used.  Another possibility:  initialize tzname[0] to the
** string "tzname[0] used before set", and similarly for the other cases.
** And another:  initialize tzname[0] to "ERA", with an explanation in the
** manual page of what this "time zone abbreviation" means (doing this so
** that tzname[0] has the "normal" length of three characters).
*/
static const char *WILDABBR = "   ";

static const char *GMT = "GMT";

struct ttinfo {				/* time type information */
	long		tt_gmtoff;	/* GMT offset in seconds */
	int		tt_isdst;	/* used to set tm_isdst */
	int		tt_abbrind;	/* abbreviation list index */
	int		tt_ttisstd;	/* TRUE if transition is std time */
};

struct state {
	int		timecnt;
	int		typecnt;
	int		charcnt;
	time_t		*ats;
	unsigned char	*types;
	struct ttinfo	*ttis;
	char		*chars;
	char		*last_tzload;	/* name of file tzload() last opened */
};

struct rule {
	int		r_type;		/* type of rule--see below */
	int		r_day;		/* day number of rule */
	int		r_week;		/* week number of rule */
	int		r_mon;		/* month number of rule */
	long		r_time;		/* transition time of rule */
};

#define	JULIAN_DAY		0	/* Jn - Julian day */
#define	DAY_OF_YEAR		1	/* n - day of year */
#define	MONTH_NTH_DAY_OF_WEEK	2	/* Mm.n.d - month, week, day of week */

/*
** Prototypes for static functions.
*/

static int		allocall P((register struct state * sp));
static long		detzcode P((const char * codep));
static void		freeall P((register struct state * sp));
static const char *	getzname P((const char * strp, const int i));
static const char *	getnum P((const char * strp, int * nump, int min,
				int max));
static const char *	getsecs P((const char * strp, long * secsp));
static const char *	getoffset P((const char * strp, long * offsetp));
static const char *	getrule P((const char * strp, struct rule * rulep));
static void		gmtload P((struct state * sp));
static void		gmtsub P((const time_t * timep, long offset,
				struct tm * tmp));
static void		localsub P((const time_t * timep, long offset,
				struct tm * tmp));
static void		normalize P((int * tensptr, int * unitsptr, int base));
static void		settzname P((void));
static time_t		time1 P((struct tm * tmp, void (* funcp)(),
				long offset));
static time_t		time2 P((struct tm *tmp, void (* funcp)(),
				long offset, int * okayp));
static void		timesub P((const time_t * timep, long offset,
				struct tm * tmp));
static int		tmcomp P((const struct tm * atmp,
				const struct tm * btmp));
static time_t		transtime P((time_t janfirst, int year,
				const struct rule * rulep, long offset));
static int		tzload P((const char * name, struct state * sp));
static int		tzparse P((const char * name, struct state * sp,
				int lastditch));

static struct state *	lclptr;
static struct state *	gmtptr;

static int		lcl_is_set;
static int		gmt_is_set;

#ifdef S5EMUL
char *			tzname[2] = {
	"GMT",
	"   ",
};

time_t			timezone = 0;
time_t			altzone = 0;
int			daylight = 0;
#endif /* defined S5EMUL */

static long
detzcode(codep)
const char * const	codep;
{
	register long	result;
	register int	i;

	result = 0;
	for (i = 0; i < 4; ++i)
		result = (result << 8) | (codep[i] & 0xff);
	return result;
}

/*
** Free up existing items pointed to by the specified "state" structure,
** and allocate new ones of sizes specified by that "state" structure.
** Return 0 on success; return -1 and free all previously-allocated items
** on failure.
*/
static int
allocall(sp)
register struct state * const	sp;
{
	freeall(sp);

	if (sp->timecnt != 0) {
		sp->ats = (time_t *)calloc((unsigned)sp->timecnt,
		   (unsigned)sizeof (time_t));
		if (sp->ats == NULL)
			return -1;
		sp->types =
		   (unsigned char *)calloc((unsigned)sp->timecnt,
		   (unsigned)sizeof (unsigned char));
		if (sp->types == NULL) {
			freeall(sp);
			return -1;
		}
	}
	sp->ttis =
	  (struct ttinfo *)calloc((unsigned)sp->typecnt,
	  (unsigned)sizeof (struct ttinfo));
	if (sp->ttis == NULL) {
		freeall(sp);
		return -1;
	}
	sp->chars = (char *)calloc((unsigned)sp->charcnt + 1,
	  (unsigned)sizeof (char));
	if (sp->chars == NULL) {
		freeall(sp);
		return -1;
	}
	return 0;
}

/*
** Free all the items pointed to by the specified "state" structure (except for
** "chars", which might have other references to it), and zero out all the
** pointers to those items.
*/
static void
freeall(sp)
register struct state * const	sp;
{
	if (sp->ttis) {
		free((char *)sp->ttis);
		sp->ttis = 0;
	}
	if (sp->types) {
		free((char *)sp->types);
		sp->types = 0;
	}
	if (sp->ats) {
		free((char *)sp->ats);
		sp->ats = 0;
	}
}

#ifdef S5EMUL
static void
settzname()
{
	register const struct state * const	sp = lclptr;
	register int				i;

	tzname[0] = (char *)GMT;
	tzname[1] = (char *)WILDABBR;
	daylight = 0;
	timezone = 0;
	altzone = 0;
	if (sp == NULL)
		return;
	for (i = 0; i < sp->typecnt; ++i) {
		register const struct ttinfo * const	ttisp = &sp->ttis[i];

		tzname[ttisp->tt_isdst] =
			(char *) &sp->chars[ttisp->tt_abbrind];
		if (ttisp->tt_isdst)
			daylight = 1;
		if (i == 0 || !ttisp->tt_isdst)
			timezone = -(ttisp->tt_gmtoff);
		if (i == 0 || ttisp->tt_isdst)
			altzone = -(ttisp->tt_gmtoff);
	}
	/*
	** And to get the latest zone names into tzname. . .
	*/
	for (i = 0; i < sp->timecnt; ++i) {
		register const struct ttinfo * const	ttisp =
							&sp->ttis[sp->types[i]];

		tzname[ttisp->tt_isdst] =
			(char *) &sp->chars[ttisp->tt_abbrind];
	}
}
#endif

/*
** Maximum size of a time zone file.
*/
#define	MAX_TZFILESZ	(sizeof (struct tzhead) + \
			TZ_MAX_TIMES * (4 + sizeof (char)) + \
			TZ_MAX_TYPES * (4 + 2 * sizeof (char)) + \
			TZ_MAX_CHARS * sizeof (char) + \
			TZ_MAX_LEAPS * 2 * 4 + \
			TZ_MAX_TYPES * sizeof (char))

static int
tzload(name, sp)
register const char *	name;
register struct state * const	sp;
{
	register const char *	p;
	register int		i;
	register int		fid;

	if (name == NULL && (name = (const char *)TZDEFAULT) == NULL)
		return -1;
	{
		register int 	doaccess;
		char		fullname[FILENAME_MAX + 1];

		if (name[0] == ':')
			++name;
		doaccess = name[0] == '/';
		if (!doaccess) {
			if ((p = TZDIR) == NULL)
				return -1;
			if ((strlen(p) + strlen(name) + 1) >= sizeof fullname)
				return -1;
			(void) strcpy(fullname, p);
			(void) strcat(fullname, "/");
			(void) strcat(fullname, name);
			/*
			** Set doaccess if '.' (as in "../") shows up in name.
			*/
			if (strchr(name, '.') != NULL)
				doaccess = TRUE;
			name = fullname;
		}
		if (sp->last_tzload && strcmp(sp->last_tzload, name) == 0)
			return (0);
		if (doaccess && access(name, ACCESS_MODE) != 0)
			return -1;
		if ((fid = open(name, OPEN_MODE)) == -1)
			return -1;
	}
	{
		register const struct tzhead *	tzhp;
		char				buf[MAX_TZFILESZ];
		int				leapcnt;
		int				ttisstdcnt;

		i = read(fid, buf, sizeof buf);
		if (close(fid) != 0 || i < sizeof *tzhp)
			return -1;
		tzhp = (struct tzhead *) buf;
		ttisstdcnt = (int) detzcode(tzhp->tzh_ttisstdcnt);
		leapcnt = (int) detzcode(tzhp->tzh_leapcnt);
		sp->timecnt = (int) detzcode(tzhp->tzh_timecnt);
		sp->typecnt = (int) detzcode(tzhp->tzh_typecnt);
		sp->charcnt = (int) detzcode(tzhp->tzh_charcnt);
		if (leapcnt < 0 || leapcnt > TZ_MAX_LEAPS ||
			sp->typecnt <= 0 || sp->typecnt > TZ_MAX_TYPES ||
			sp->timecnt < 0 || sp->timecnt > TZ_MAX_TIMES ||
			sp->charcnt < 0 || sp->charcnt > TZ_MAX_CHARS ||
			(ttisstdcnt != sp->typecnt && ttisstdcnt != 0))
				return -1;
		if (i < sizeof *tzhp +
			sp->timecnt * (4 + sizeof (char)) +
			sp->typecnt * (4 + 2 * sizeof (char)) +
			sp->charcnt * sizeof (char) +
			leapcnt * 2 * 4 +
			ttisstdcnt * sizeof (char))
				return -1;
		if (allocall(sp) < 0)
			return -1;
		p = buf + sizeof *tzhp;
		for (i = 0; i < sp->timecnt; ++i) {
			sp->ats[i] = detzcode(p);
			p += 4;
		}
		for (i = 0; i < sp->timecnt; ++i) {
			sp->types[i] = (unsigned char) *p++;
			if (sp->types[i] >= sp->typecnt)
				return -1;
		}
		for (i = 0; i < sp->typecnt; ++i) {
			register struct ttinfo *	ttisp;

			ttisp = &sp->ttis[i];
			ttisp->tt_gmtoff = detzcode(p);
			p += 4;
			ttisp->tt_isdst = (unsigned char) *p++;
			if (ttisp->tt_isdst != 0 && ttisp->tt_isdst != 1)
				return -1;
			ttisp->tt_abbrind = (unsigned char) *p++;
			if (ttisp->tt_abbrind < 0 ||
				ttisp->tt_abbrind > sp->charcnt)
					return -1;
		}
		for (i = 0; i < sp->charcnt-1; ++i)
			sp->chars[i] = *p++;
		sp->chars[i] = '\0';	/* ensure '\0' at end */
		p += (4 + 4) * leapcnt;	/* skip leap seconds list */
		for (i = 0; i < sp->typecnt; ++i) {
			register struct ttinfo *	ttisp;

			ttisp = &sp->ttis[i];
			if (ttisstdcnt == 0)
				ttisp->tt_ttisstd = FALSE;
			else {
				ttisp->tt_ttisstd = *p++;
				if (ttisp->tt_ttisstd != TRUE &&
					ttisp->tt_ttisstd != FALSE)
						return -1;
			}
		}
	}
	if (sp->last_tzload)
		free(sp->last_tzload);
	sp->last_tzload = strdup(name);
	return 0;
}

static const int	mon_lengths[2][MONSPERYEAR] = {
	31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
	31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

static const int	year_lengths[2] = {
	DAYSPERNYEAR, DAYSPERLYEAR
};

/*
** Given a pointer into a time zone string, scan until a character that is not
** a valid character in a zone name is found.  Return a pointer to that
** character.
** Support both quoted and unquoted timezones.
*/

static const char *
getzname(strp, quoted)
const char *	strp;
int quoted;
{
	unsigned char	c;

	if (quoted) {
		while ((c = (unsigned char)*strp) != '\0' &&
			(isalnum(c) || (c == '+') || (c == '-')))
				++strp;
	} else {
		while ((c = (unsigned char)*strp) != '\0' && !isdigit(c)
			&& (c != ',') && (c != '-') && (c != '+'))
				++strp;
	}
	return strp;
}

/*
** Given a pointer into a time zone string, extract a number from that string.
** Check that the number is within a specified range; if it is not, return
** NULL.
** Otherwise, return a pointer to the first character not part of the number.
*/

static const char *
getnum(strp, nump, min, max)
register const char *	strp;
int * const		nump;
const int		min;
const int		max;
{
	register char	c;
	register int	num;

	if (strp == NULL || !isdigit(*strp))
		return NULL;
	num = 0;
	while ((c = *strp) != '\0' && isdigit(c)) {
		num = num * 10 + (c - '0');
		if (num > max)
			return NULL;	/* illegal value */
		++strp;
	}
	if (num < min)
		return NULL;		/* illegal value */
	*nump = num;
	return strp;
}

/*
** Given a pointer into a time zone string, extract a number of seconds,
** in hh[:mm[:ss]] form, from the string.
** If any error occurs, return NULL.
** Otherwise, return a pointer to the first character not part of the number
** of seconds.
*/

static const char *
getsecs(strp, secsp)
register const char *	strp;
long * const		secsp;
{
	int	num;

	strp = getnum(strp, &num, 0, HOURSPERDAY);
	if (strp == NULL)
		return NULL;
	*secsp = num * SECSPERHOUR;
	if (*strp == ':') {
		++strp;
		strp = getnum(strp, &num, 0, MINSPERHOUR - 1);
		if (strp == NULL)
			return NULL;
		*secsp += num * SECSPERMIN;
		if (*strp == ':') {
			++strp;
			strp = getnum(strp, &num, 0, SECSPERMIN - 1);
			if (strp == NULL)
				return NULL;
			*secsp += num;
		}
	}
	return strp;
}

/*
** Given a pointer into a time zone string, extract an offset, in
** [+-]hh[:mm[:ss]] form, from the string.
** If any error occurs, return NULL.
** Otherwise, return a pointer to the first character not part of the time.
*/

static const char *
getoffset(strp, offsetp)
register const char *	strp;
long * const		offsetp;
{
	register int	neg;

	if (*strp == '-') {
		neg = 1;
		++strp;
	} else if (isdigit(*strp) || *strp++ == '+')
		neg = 0;
	else	return NULL;		/* illegal offset */
	strp = getsecs(strp, offsetp);
	if (strp == NULL)
		return NULL;		/* illegal time */
	if (neg)
		*offsetp = -*offsetp;
	return strp;
}

/*
** Given a pointer into a time zone string, extract a rule in the form
** date[/time].  See POSIX section 8 for the format of "date" and "time".
** If a valid rule is not found, return NULL.
** Otherwise, return a pointer to the first character not part of the rule.
*/

static const char *
getrule(strp, rulep)
const char *			strp;
register struct rule * const	rulep;
{
	if (*strp == 'J') {
		/*
		** Julian day.
		*/
		rulep->r_type = JULIAN_DAY;
		++strp;
		strp = getnum(strp, &rulep->r_day, 1, DAYSPERNYEAR);
	} else if (*strp == 'M') {
		/*
		** Month, week, day.
		*/
		rulep->r_type = MONTH_NTH_DAY_OF_WEEK;
		++strp;
		strp = getnum(strp, &rulep->r_mon, 1, MONSPERYEAR);
		if (strp == NULL)
			return NULL;
		if (*strp++ != '.')
			return NULL;
		strp = getnum(strp, &rulep->r_week, 1, 5);
		if (strp == NULL)
			return NULL;
		if (*strp++ != '.')
			return NULL;
		strp = getnum(strp, &rulep->r_day, 0, DAYSPERWEEK - 1);
	} else if (isdigit(*strp)) {
		/*
		** Day of year.
		*/
		rulep->r_type = DAY_OF_YEAR;
		strp = getnum(strp, &rulep->r_day, 0, DAYSPERLYEAR - 1);
	} else	return NULL;		/* invalid format */
	if (strp == NULL)
		return NULL;
	if (*strp == '/') {
		/*
		** Time specified.
		*/
		++strp;
		strp = getsecs(strp, &rulep->r_time);
	} else	rulep->r_time = 2 * SECSPERHOUR;	/* default = 2:00:00 */
	return strp;
}

/*
** Given the Epoch-relative time of January 1, 00:00:00 GMT, in a year, the
** year, a rule, and the offset from GMT at the time that rule takes effect,
** calculate the Epoch-relative time that rule takes effect.
*/

static time_t
transtime(janfirst, year, rulep, offset)
const time_t				janfirst;
const int				year;
register const struct rule * const	rulep;
const long				offset;
{
	register int	leapyear;
	register time_t	value;
	register int	i;
	int		d, m1, yy0, yy1, yy2, dow;

	leapyear = isleap(year);
	switch (rulep->r_type) {

	case JULIAN_DAY:
		/*
		** Jn - Julian day, 1 == January 1, 60 == March 1 even in leap
		** years.
		** In non-leap years, or if the day number is 59 or less, just
		** add SECSPERDAY times the day number-1 to the time of
		** January 1, midnight, to get the day.
		*/
		value = janfirst + (rulep->r_day - 1) * SECSPERDAY;
		if (leapyear && rulep->r_day >= 60)
			value += SECSPERDAY;
		break;

	case DAY_OF_YEAR:
		/*
		** n - day of year.
		** Just add SECSPERDAY times the day number to the time of
		** January 1, midnight, to get the day.
		*/
		value = janfirst + rulep->r_day * SECSPERDAY;
		break;

	case MONTH_NTH_DAY_OF_WEEK:
		/*
		** Mm.n.d - nth "dth day" of month m.
		*/
		value = janfirst;
		for (i = 0; i < rulep->r_mon - 1; ++i)
			value += mon_lengths[leapyear][i] * SECSPERDAY;

		/*
		** Use Zeller's Congruence to get day-of-week of first day of
		** month.
		*/
		m1 = (rulep->r_mon + 9) % 12 + 1;
		yy0 = (rulep->r_mon <= 2) ? (year - 1) : year;
		yy1 = yy0 / 100;
		yy2 = yy0 % 100;
		dow = ((26 * m1 - 2) / 10 +
			1 + yy2 + yy2 / 4 + yy1 / 4 - 2 * yy1) % 7;
		if (dow < 0)
			dow += DAYSPERWEEK;

		/*
		** "dow" is the day-of-week of the first day of the month.  Get
		** the day-of-month (zero-origin) of the first "dow" day of the
		** month.
		*/
		d = rulep->r_day - dow;
		if (d < 0)
			d += DAYSPERWEEK;
		for (i = 1; i < rulep->r_week; ++i) {
			if (d + DAYSPERWEEK >=
				mon_lengths[leapyear][rulep->r_mon - 1])
					break;
			d += DAYSPERWEEK;
		}

		/*
		** "d" is the day-of-month (zero-origin) of the day we want.
		*/
		value += d * SECSPERDAY;
		break;
	}

	/*
	** "value" is the Epoch-relative time of 00:00:00 GMT on the day in
	** question.  To get the Epoch-relative time of the specified local
	** time on that day, add the transition time and the current offset
	** from GMT.
	*/
	return value + rulep->r_time + offset;
}

/*
** Given a POSIX section 8-style TZ string, fill in the rule tables as
** appropriate.
*/

static int
tzparse(name, sp, lastditch)
const char *			name;
struct state * const	sp;
const int			lastditch;
{
	const char *			stdname;
	const char *			dstname;
	int				stdlen;
	int				dstlen;
	long				stdoffset;
	long				dstoffset;
	time_t *			atp;
	unsigned char *			typep;
	char *				cp;

	freeall(sp);			/* */
	stdname = name;
	if (lastditch) {
		stdlen = strlen(name);	/* length of standard zone name */
		name += stdlen;
		if (stdlen >= sizeof sp->chars)
			stdlen = (sizeof sp->chars) - 1;
	} else {
		if (*name == '<') {
			name++;
			stdname++;
			name = getzname(name, 1);
			if (*name != '>') {
				return (-1);
			}
			stdlen = name - stdname;
			name++;
		} else {
			name = getzname(name, 0);
			stdlen = name - stdname;
		}
		if (stdlen < 3)
			return -1;
	}
	if (*name == '\0')
		stdoffset = 0;
	else {
		name = getoffset(name, &stdoffset);
		if (name == NULL)
			return -1;
	}
	if (*name != '\0') {
		dstname = name;
		if (*name == '<') {
			name++;
			dstname++;
			name = getzname(name, 1);
			if (*name != '>') {
				return (-1);
			}
			dstlen = name - dstname;
			name++;
		} else {
			name = getzname(name, 0);
			dstlen = name - dstname;
		}
		if (dstlen < 3)
			return -1;
		if (*name != '\0' && *name != ',' && *name != ';') {
			name = getoffset(name, &dstoffset);
			if (name == NULL)
				return -1;
		} else	dstoffset = stdoffset - SECSPERHOUR;
		if (*name == ',' || *name == ';') {
			struct rule	start;
			struct rule	end;
			register int	year;
			register time_t	janfirst;
			time_t		starttime;
			time_t		endtime;

			++name;
			if ((name = getrule(name, &start)) == NULL)
				return -1;
			if (*name++ != ',')
				return -1;
			if ((name = getrule(name, &end)) == NULL)
				return -1;
			if (*name != '\0')
				return -1;
			sp->typecnt = 2;	/* standard time and DST */
			/*
			** Two transitions per year, from EPOCH_YEAR to 2037.
			*/
			sp->timecnt = 2 * (2037 - EPOCH_YEAR + 1);
			if (sp->timecnt > TZ_MAX_TIMES)
				return -1;
			sp->charcnt = stdlen + 1 + dstlen + 1;
			if (allocall(sp) < 0)
				return -1;
			sp->ttis[0].tt_gmtoff = -dstoffset;
			sp->ttis[0].tt_isdst = 1;
			sp->ttis[0].tt_abbrind = stdlen + 1;
			sp->ttis[1].tt_gmtoff = -stdoffset;
			sp->ttis[1].tt_isdst = 0;
			sp->ttis[1].tt_abbrind = 0;
			atp = sp->ats;
			typep = sp->types;
			janfirst = 0;
			for (year = EPOCH_YEAR; year <= 2037; ++year) {
				starttime = transtime(janfirst, year, &start,
					stdoffset);
				endtime = transtime(janfirst, year, &end,
					dstoffset);
				if (starttime > endtime) {
					*atp++ = endtime;
					*typep++ = 1;	/* DST ends */
					*atp++ = starttime;
					*typep++ = 0;	/* DST begins */
				} else {
					*atp++ = starttime;
					*typep++ = 0;	/* DST begins */
					*atp++ = endtime;
					*typep++ = 1;	/* DST ends */
				}
				janfirst +=
					year_lengths[isleap(year)] * SECSPERDAY;
			}
		} else {
			int		sawstd;
			int		sawdst;
			long		stdfix;
			long		dstfix;
			long		oldfix;
			int		isdst;
			register int	i;

			if (*name != '\0')
				return -1;
			if (tzload(TZDEFRULES, sp) != 0) {
				freeall(sp);
				return -1;
			}
			/*
			** Discard zone abbreviations from file, and allocate
			** space for the ones from TZ.
			*/
			free(sp->chars);
			sp->charcnt = stdlen + 1 + dstlen + 1;
			sp->chars = (char *)calloc((unsigned)sp->charcnt,
			  (unsigned)sizeof (char));
			/*
			** Compute the difference between the real and
			** prototype standard and summer time offsets
			** from GMT, and put the real standard and summer
			** time offsets into the rules in place of the
			** prototype offsets.
			*/
			sawstd = FALSE;
			sawdst = FALSE;
			stdfix = 0;
			dstfix = 0;
			for (i = 0; i < sp->typecnt; ++i) {
				if (sp->ttis[i].tt_isdst) {
					oldfix = dstfix;
					dstfix =
					    sp->ttis[i].tt_gmtoff + dstoffset;
					if (sawdst && (oldfix != dstfix))
						return -1;
					sp->ttis[i].tt_gmtoff = -dstoffset;
					sp->ttis[i].tt_abbrind = stdlen + 1;
					sawdst = TRUE;
				} else {
					oldfix = stdfix;
					stdfix =
					    sp->ttis[i].tt_gmtoff + stdoffset;
					if (sawstd && (oldfix != stdfix))
						return -1;
					sp->ttis[i].tt_gmtoff = -stdoffset;
					sp->ttis[i].tt_abbrind = 0;
					sawstd = TRUE;
				}
			}
			/*
			** Make sure we have both standard and summer time.
			*/
			if (!sawdst || !sawstd)
				return -1;
			/*
			** Now correct the transition times by shifting
			** them by the difference between the real and
			** prototype offsets.  Note that this difference
			** can be different in standard and summer time;
			** the prototype probably has a 1-hour difference
			** between standard and summer time, but a different
			** difference can be specified in TZ.
			*/
			isdst = FALSE;	/* we start in standard time */
			for (i = 0; i < sp->timecnt; ++i) {
				register const struct ttinfo *	ttisp;

				/*
				** If summer time is in effect, and the
				** transition time was not specified as
				** standard time, add the summer time
				** offset to the transition time;
				** otherwise, add the standard time offset
				** to the transition time.
				*/
				ttisp = &sp->ttis[sp->types[i]];
				sp->ats[i] +=
					(isdst && !ttisp->tt_ttisstd) ?
						dstfix : stdfix;
				isdst = ttisp->tt_isdst;
			}
		}
	} else {
		dstlen = 0;
		sp->typecnt = 1;		/* only standard time */
		sp->timecnt = 0;
		sp->charcnt = stdlen + 1;
		if (allocall(sp) < 0)
			return -1;
		sp->ttis[0].tt_gmtoff = -stdoffset;
		sp->ttis[0].tt_isdst = 0;
		sp->ttis[0].tt_abbrind = 0;
	}
	cp = sp->chars;
	(void) strncpy(cp, stdname, stdlen);
	cp += stdlen;
	*cp++ = '\0';
	if (dstlen != 0) {
		(void) strncpy(cp, dstname, dstlen);
		*(cp + dstlen) = '\0';
	}
	return 0;
}

static void
gmtload(sp)
struct state * const	sp;
{
	if (tzload(GMT, sp) != 0)
		(void) tzparse(GMT, sp, TRUE);
}

void
tzsetwall()
{
	lcl_is_set = TRUE;
	if (lclptr == NULL) {
		lclptr = (struct state *) calloc(1, (unsigned)sizeof *lclptr);
		if (lclptr == NULL) {
#ifdef S5EMUL
			settzname();	/* all we can do */
#endif
			return;
		}
	}
	if (tzload((char *) NULL, lclptr) != 0)
		gmtload(lclptr);
#ifdef S5EMUL
	settzname();
#endif
}

void
tzset()
{
	register const char *	name;

	name = (const char *)getenv("TZ");
	if (name == NULL) {
		tzsetwall();
		return;
	}
	lcl_is_set = TRUE;
	if (lclptr == NULL) {
		lclptr = (struct state *) calloc(1, (unsigned)sizeof *lclptr);
		if (lclptr == NULL) {
#ifdef S5EMUL
			settzname();	/* all we can do */
#endif
			return;
		}
	}
	if (*name == '\0') {
		/*
		** User wants it fast rather than right.
		*/
		lclptr->timecnt = 0;
		lclptr->typecnt = 1;
		lclptr->charcnt = sizeof GMT;
		if (allocall(lclptr) < 0)
			return;
		lclptr->ttis[0].tt_gmtoff = 0;
		lclptr->ttis[0].tt_abbrind = 0;
		(void) strcpy(lclptr->chars, GMT);
	} else if (tzload(name, lclptr) != 0)
		if (name[0] == ':' || tzparse(name, lclptr, FALSE) != 0)
			(void) tzparse(name, lclptr, TRUE);
#ifdef S5EMUL
	settzname();
#endif
}

/*
** The easy way to behave "as if no library function calls" localtime
** is to not call it--so we drop its guts into "localsub", which can be
** freely called.  (And no, the PANS doesn't require the above behavior--
** but it *is* desirable.)
**
** The unused offset argument is for the benefit of mktime variants.
*/

static struct tm	tm;

/*ARGSUSED*/
static void
localsub(timep, offset, tmp)
const time_t * const	timep;
const long		offset;
struct tm * const	tmp;
{
	register const struct state *	sp;
	register const struct ttinfo *	ttisp;
	register int			i;
	const time_t			t = *timep;

	if (!lcl_is_set)
		tzset();
	sp = lclptr;
	if (sp == NULL) {
		gmtsub(timep, offset, tmp);
		return;
	}
	if (sp->timecnt == 0 || t < sp->ats[0]) {
		i = 0;
		while (sp->ttis[i].tt_isdst)
			if (++i >= sp->typecnt) {
				i = 0;
				break;
			}
	} else {
		for (i = 1; i < sp->timecnt; ++i)
			if (t < sp->ats[i])
				break;
		i = sp->types[i - 1];
	}
	ttisp = &sp->ttis[i];
	timesub(&t, ttisp->tt_gmtoff, tmp);
	tmp->tm_isdst = ttisp->tt_isdst;
#ifdef S5EMUL
	tzname[tmp->tm_isdst] = (char *) &sp->chars[ttisp->tt_abbrind];
#endif /* S5EMUL */
	tmp->tm_zone = &sp->chars[ttisp->tt_abbrind];
}

struct tm *
localtime(timep)
const time_t * const	timep;
{
	time_t		temp_time = *(const time_t*)timep;

	_ltzset(&temp_time);	/*
				 * base localtime calls this to initialize
				 * some things, so we'll do it here, too.
				 */
	localsub(timep, 0L, &tm);
	return &tm;
}

/*
** gmtsub is to gmtime as localsub is to localtime.
*/

static void
gmtsub(timep, offset, tmp)
const time_t * const	timep;
const long		offset;
struct tm * const	tmp;
{
	if (!gmt_is_set) {
		gmt_is_set = TRUE;
		gmtptr = (struct state *) calloc(1, (unsigned)sizeof *gmtptr);
		if (gmtptr != NULL)
			gmtload(gmtptr);
	}
	timesub(timep, offset, tmp);
	/*
	** Could get fancy here and deliver something such as
	** "GMT+xxxx" or "GMT-xxxx" if offset is non-zero,
	** but this is no time for a treasure hunt.
	*/
	if (offset != 0)
		tmp->tm_zone = (char *)WILDABBR;
	else {
		if (gmtptr == NULL)
			tmp->tm_zone = (char *)GMT;
		else	tmp->tm_zone = gmtptr->chars;
	}
}

struct tm *
gmtime(timep)
const time_t * const	timep;
{
	gmtsub(timep, 0L, &tm);
	return &tm;
}

struct tm *
offtime(timep, offset)
const time_t * const	timep;
const long		offset;
{
	gmtsub(timep, offset, &tm);
	return &tm;
}

static void
timesub(timep, offset, tmp)
const time_t * const			timep;
const long				offset;
register struct tm * const		tmp;
{
	register long			days;
	register long			rem;
	register int			y;
	register int			yleap;
	register const int *		ip;

	days = *timep / SECSPERDAY;
	rem = *timep % SECSPERDAY;
	rem += offset;
	while (rem < 0) {
		rem += SECSPERDAY;
		--days;
	}
	while (rem >= SECSPERDAY) {
		rem -= SECSPERDAY;
		++days;
	}
	tmp->tm_hour = (int) (rem / SECSPERHOUR);
	rem = rem % SECSPERHOUR;
	tmp->tm_min = (int) (rem / SECSPERMIN);
	tmp->tm_sec = (int) (rem % SECSPERMIN);
	tmp->tm_wday = (int) ((EPOCH_WDAY + days) % DAYSPERWEEK);
	if (tmp->tm_wday < 0)
		tmp->tm_wday += DAYSPERWEEK;
	y = EPOCH_YEAR;
	if (days >= 0)
		for ( ; ; ) {
			yleap = isleap(y);
			if (days < (long) year_lengths[yleap])
				break;
			++y;
			days = days - (long) year_lengths[yleap];
		}
	else do {
		--y;
		yleap = isleap(y);
		days = days + (long) year_lengths[yleap];
	} while (days < 0);
	tmp->tm_year = y - TM_YEAR_BASE;
	tmp->tm_yday = (int) days;
	ip = mon_lengths[yleap];
	for (tmp->tm_mon = 0; days >= (long) ip[tmp->tm_mon]; ++(tmp->tm_mon))
		days = days - (long) ip[tmp->tm_mon];
	tmp->tm_mday = (int) (days + 1);
	tmp->tm_isdst = 0;
	tmp->tm_gmtoff = offset;
}

/*
** Adapted from code provided by Robert Elz, who writes:
**	The "best" way to do mktime I think is based on an idea of Bob
**	Kridle's (so its said...) from a long time ago. (mtxinu!kridle now).
**	It does a binary search of the time_t space.  Since time_t's are
**	just 32 bits, its a max of 32 iterations (even at 64 bits it
**	would still be very reasonable).
*/

#ifndef WRONG
#define WRONG	(-1)
#endif /* !defined WRONG */

static void
normalize(tensptr, unitsptr, base)
int * const	tensptr;
int * const	unitsptr;
const int	base;
{
	int tmp;

	if (*unitsptr >= base) {
		*tensptr += *unitsptr / base;
		*unitsptr %= base;
	} else if (*unitsptr < 0) {
		/* tmp has the range 0 to abs(*unitptr) -1 */
		tmp = -1 - (*unitsptr);
		*tensptr -= (tmp/base + 1);
		*unitsptr = (base - 1) - (tmp % base);
	}
}

static int
tmcomp(atmp, btmp)
register const struct tm * const atmp;
register const struct tm * const btmp;
{
	register int	result;

	if ((result = (atmp->tm_year - btmp->tm_year)) == 0 &&
		(result = (atmp->tm_mon - btmp->tm_mon)) == 0 &&
		(result = (atmp->tm_mday - btmp->tm_mday)) == 0 &&
		(result = (atmp->tm_hour - btmp->tm_hour)) == 0 &&
		(result = (atmp->tm_min - btmp->tm_min)) == 0)
			result = atmp->tm_sec - btmp->tm_sec;
	return result;
}

static time_t
time2(tmp, funcp, offset, okayp)
struct tm * const	tmp;
void (* const		funcp)();
const long		offset;
int * const		okayp;
{
	register const struct state *	sp;
	register int			dir;
	register int			bits;
	register int			i, j ;
	register int			saved_seconds;
	time_t				newt;
	time_t				t;
	struct tm			yourtm, mytm;

	*okayp = FALSE;
	yourtm = *tmp;
	if (yourtm.tm_sec >= SECSPERMIN + 2 || yourtm.tm_sec < 0)
		normalize(&yourtm.tm_min, &yourtm.tm_sec, SECSPERMIN);
	normalize(&yourtm.tm_hour, &yourtm.tm_min, MINSPERHOUR);
	normalize(&yourtm.tm_mday, &yourtm.tm_hour, HOURSPERDAY);
	normalize(&yourtm.tm_year, &yourtm.tm_mon, MONSPERYEAR);
	while (yourtm.tm_mday <= 0) {
		if (yourtm.tm_mon == 0) {
			yourtm.tm_mon = 12;
			--yourtm.tm_year;
		}
		yourtm.tm_mday +=
			mon_lengths[isleap(yourtm.tm_year +
			   TM_YEAR_BASE)][--yourtm.tm_mon];
		if (yourtm.tm_mon >= MONSPERYEAR) {
			yourtm.tm_mon = 0;
			--yourtm.tm_year;
		}
	}
	for ( ; ; ) {
		i = mon_lengths[isleap(yourtm.tm_year +
			TM_YEAR_BASE)][yourtm.tm_mon];
		if (yourtm.tm_mday <= i)
			break;
		yourtm.tm_mday -= i;
		if (++yourtm.tm_mon >= MONSPERYEAR) {
			yourtm.tm_mon = 0;
			++yourtm.tm_year;
		}
	}
	saved_seconds = yourtm.tm_sec;
	yourtm.tm_sec = 0;
	/*
	** Calculate the number of magnitude bits in a time_t
	** (this works regardless of whether time_t is
	** signed or unsigned, though lint complains if unsigned).
	*/
	for (bits = 0, t = 1; t > 0; ++bits, t <<= 1)
		;
	/*
	** If time_t is signed, then 0 is the median value,
	** if time_t is unsigned, then 1 << bits is median.
	*/
	t = (t < 0) ? 0 : ((time_t) 1 << bits);
	for ( ; ; ) {
		(*funcp)(&t, offset, &mytm);
		dir = tmcomp(&mytm, &yourtm);
		if (dir != 0) {
			if (bits-- < 0)
				return WRONG;
			if (bits < 0)
				--t;
			else if (dir > 0)
				t -= (time_t) 1 << bits;
			else	t += (time_t) 1 << bits;
			continue;
		}
		if (yourtm.tm_isdst < 0 || mytm.tm_isdst == yourtm.tm_isdst)
			break;
		/*
		** Right time, wrong type.
		** Hunt for right time, right type.
		** It's okay to guess wrong since the guess
		** gets checked.
		*/
		sp = (const struct state *)
			((funcp == localsub) ? lclptr : gmtptr);
		if (sp == NULL)
			return WRONG;
		for (i = 0; i < sp->typecnt; ++i) {
			if (sp->ttis[i].tt_isdst != yourtm.tm_isdst)
				continue;
			for (j = 0; j < sp->typecnt; ++j) {
				if (sp->ttis[j].tt_isdst == yourtm.tm_isdst)
					continue;
				newt = t + sp->ttis[j].tt_gmtoff -
					sp->ttis[i].tt_gmtoff;
				(*funcp)(&newt, offset, &mytm);
				if (tmcomp(&mytm, &yourtm) != 0)
					continue;
				if (mytm.tm_isdst != yourtm.tm_isdst)
					continue;
				/*
				** We have a match.
				*/
				t = newt;
				goto label;
			}
		}
		return WRONG;
	}
label:
	t += saved_seconds;
	(*funcp)(&t, offset, tmp);
	*okayp = TRUE;
	return t;
}

static time_t
time1(tmp, funcp, offset)
struct tm * const	tmp;
void (* const		funcp)();
const long		offset;
{
	register time_t			t;
	register const struct state *	sp;
	register int			samei, otheri;
	int				okay;

	
        if (tmp->tm_isdst > 1)
                tmp->tm_isdst = 1;
	t = time2(tmp, funcp, offset, &okay);
	if (okay || tmp->tm_isdst < 0)
		return t;
	/*
	** We're supposed to assume that somebody took a time of one type
	** and did some math on it that yielded a "struct tm" that's bad.
	** We try to divine the type they started from and adjust to the
	** type they need.
	*/
	sp = (const struct state *) ((funcp == localsub) ? lclptr : gmtptr);
	if (sp == NULL)
		return WRONG;
	for (samei = 0; samei < sp->typecnt; ++samei) {
		if (sp->ttis[samei].tt_isdst != tmp->tm_isdst)
			continue;
		for (otheri = 0; otheri < sp->typecnt; ++otheri) {
			if (sp->ttis[otheri].tt_isdst == tmp->tm_isdst)
				continue;
			tmp->tm_sec += sp->ttis[otheri].tt_gmtoff -
					sp->ttis[samei].tt_gmtoff;
			tmp->tm_isdst = !tmp->tm_isdst;
			t = time2(tmp, funcp, offset, &okay);
			if (okay)
				return t;
			tmp->tm_sec -= sp->ttis[otheri].tt_gmtoff -
					sp->ttis[samei].tt_gmtoff;
			tmp->tm_isdst = !tmp->tm_isdst;
		}
	}
	return WRONG;
}

time_t
mktime(tmp)
struct tm * const	tmp;
{
	return time1(tmp, localsub, 0L);
}

time_t
timelocal(tmp)
struct tm * const	tmp;
{
	tmp->tm_isdst = -1; 
	return mktime(tmp);
}

time_t
timegm(tmp)
struct tm * const	tmp;
{
	return time1(tmp, gmtsub, 0L);
}

time_t
timeoff(tmp, offset)
struct tm * const	tmp;
const long		offset;
{

	return time1(tmp, gmtsub, offset);
}
