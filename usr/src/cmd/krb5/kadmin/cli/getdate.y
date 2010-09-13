/*
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 *	Openvision retains the copyright to derivative works of
 *	this source code.  Do *NOT* create a derivative of this
 *	source code before consulting with your legal department.
 *	Do *NOT* integrate *ANY* of this source code into another
 *	product before consulting with your legal department.
 *
 *	For further information, read the top-level Openvision
 *	copyright which is contained in the top-level MIT Kerberos
 *	copyright.
 *
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 */


%{
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
**  Originally written by Steven M. Bellovin <smb@research.att.com> while
**  at the University of North Carolina at Chapel Hill.  Later tweaked by
**  a couple of people on Usenet.  Completely overhauled by Rich $alz
**  <rsalz@bbn.com> and Jim Berets <jberets@bbn.com> in August, 1990;
**  send any email to Rich.
**
**  This grammar has nine shift/reduce conflicts.
**
**  This code is in the public domain and has no copyright.
*/
/* SUPPRESS 287 on yaccpar_sccsid *//* Unusd static variable */
/* SUPPRESS 288 on yyerrlab *//* Label unused */

#ifdef HAVE_CONFIG_H
#if defined (emacs) || defined (CONFIG_BROKETS)
#include <config.h>
#else
#include "config.h"
#endif
#endif
#include <string.h>

/* Since the code of getdate.y is not included in the Emacs executable
   itself, there is no need to #define static in this file.  Even if
   the code were included in the Emacs executable, it probably
   wouldn't do any harm to #undef it here; this will only cause
   problems if we try to write to a static variable, which I don't
   think this code needs to do.  */
#ifdef emacs
#undef static
#endif

/* The following block of alloca-related preprocessor directives is here
   solely to allow compilation by non GNU-C compilers of the C parser
   produced from this file by old versions of bison.  Newer versions of
   bison include a block similar to this one in bison.simple.  */

#ifdef __GNUC__
#undef alloca
#define alloca __builtin_alloca
#else
#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#else
#ifdef _AIX /* for Bison */
 #pragma alloca
#else
void *alloca ();
#endif
#endif
#endif

#include <stdio.h>
#include <ctype.h>

#if defined(HAVE_STDLIB_H)
#include <stdlib.h>
#endif

/* The code at the top of get_date which figures out the offset of the
   current time zone checks various CPP symbols to see if special
   tricks are need, but defaults to using the gettimeofday system call.
   Include <sys/time.h> if that will be used.  */

#if	defined(vms)

#include <types.h>
#include <time.h>

#else

#include <sys/types.h>

#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif

#ifdef timezone
#undef timezone /* needed for sgi */
#endif

/*
** We use the obsolete `struct my_timeb' as part of our interface!
** Since the system doesn't have it, we define it here;
** our callers must do likewise.
*/
struct my_timeb {
    time_t		time;		/* Seconds since the epoch	*/
    unsigned short	millitm;	/* Field not used		*/
    short		timezone;	/* Minutes west of GMT		*/
    short		dstflag;	/* Field not used		*/
};
#endif	/* defined(vms) */

#if defined (STDC_HEADERS) || defined (USG)
#include <string.h>
#endif

/* Some old versions of bison generate parsers that use bcopy.
   That loses on systems that don't provide the function, so we have
   to redefine it here.  */
#ifndef bcopy
#define bcopy(from, to, len) memcpy ((to), (from), (len))
#endif

/*
 * The following is a hack so that it is easy to internationalize
 * statically declared strings. We define a wrapper function here that
 * will be a replacement for gettext. We the make gettext a macro that
 * just returns its argument, which now can be used with statically defined
 * strings. The conquence of this is that GETTEXT must be used to translate
 * a string at runtime and gettext must be used around string literals so
 * that xgettext command can extract them to a portable object database file.
 *
 * Thus to translate a string literal that is an argument to a function foo
 * the following will have to be performed:
 *
 *              foo(GETTEXT(gettext("This is a test")));
 *
 * The inner gettext call is for xgettext command to extract the string.
 * The C preprossesor will reduce the above to:
 *
 *              foo(GETTEXT(("This ia a test"));
 */

#include <libintl.h>

static char *
GETTEXT(const char *msgid)
{
	return (gettext(msgid));
}

#define	gettext(s) (s)


extern struct tm	*gmtime();
extern struct tm	*localtime();

#define yyparse getdate_yyparse
#define yylex getdate_yylex
#define yyerror getdate_yyerror

static int getdate_yylex (void);
static int getdate_yyerror (char *);


#define EPOCH		1970
#define EPOCH_END	2099  /* Solaris 64 bit can support this at this point */
#define HOUR(x)		((time_t)(x) * 60)
#define SECSPERDAY	(24L * 60L * 60L)


/*
**  An entry in the lexical lookup table.
*/
typedef struct _TABLE {
    char	*name;
    int		type;
    time_t	value;
} TABLE;


/*
**  Daylight-savings mode:  on, off, or not yet known.
*/
typedef enum _DSTMODE {
    DSTon, DSToff, DSTmaybe
} DSTMODE;

/*
**  Meridian:  am, pm, or 24-hour style.
*/
typedef enum _MERIDIAN {
    MERam, MERpm, MER24
} MERIDIAN;


/*
**  Global variables.  We could get rid of most of these by using a good
**  union as the yacc stack.  (This routine was originally written before
**  yacc had the %union construct.)  Maybe someday; right now we only use
**  the %union very rarely.
*/
static char	*yyInput;
static DSTMODE	yyDSTmode;
static time_t	yyDayOrdinal;
static time_t	yyDayNumber;
static int	yyHaveDate;
static int	yyHaveDay;
static int	yyHaveRel;
static int	yyHaveTime;
static int	yyHaveZone;
static time_t	yyTimezone;
static time_t	yyDay;
static time_t	yyHour;
static time_t	yyMinutes;
static time_t	yyMonth;
static time_t	yySeconds;
static time_t	yyYear;
static MERIDIAN	yyMeridian;
static time_t	yyRelMonth;
static time_t	yyRelSeconds;

%}

%union {
    time_t		Number;
    enum _MERIDIAN	Meridian;
}

%token	tAGO tDAY tDAYZONE tID tMERIDIAN tMINUTE_UNIT tMONTH tMONTH_UNIT
%token	tSEC_UNIT tSNUMBER tUNUMBER tZONE tDST tNEVER

%type	<Number>	tDAY tDAYZONE tMINUTE_UNIT tMONTH tMONTH_UNIT
%type	<Number>	tSEC_UNIT tSNUMBER tUNUMBER tZONE
%type	<Meridian>	tMERIDIAN o_merid

%%

spec	: /* NULL */
	| spec item
        | tNEVER {
	    yyYear = 1970;
	    yyMonth = 1;
	    yyDay = 1;
	    yyHour = yyMinutes = yySeconds = 0;
	    yyDSTmode = DSToff;
	    yyTimezone = 0; /* gmt */
	    yyHaveDate++;
        }
	;

item	: time {
	    yyHaveTime++;
	}
	| zone {
	    yyHaveZone++;
	}
	| date {
	    yyHaveDate++;
	}
	| day {
	    yyHaveDay++;
	}
	| rel {
	    yyHaveRel++;
	}
	;

time	: tUNUMBER tMERIDIAN {
	    yyHour = $1;
	    yyMinutes = 0;
	    yySeconds = 0;
	    yyMeridian = $2;
	}
	| tUNUMBER ':' tUNUMBER o_merid {
	    yyHour = $1;
	    yyMinutes = $3;
	    yySeconds = 0;
	    yyMeridian = $4;
	}
	| tUNUMBER ':' tUNUMBER tSNUMBER {
	    yyHour = $1;
	    yyMinutes = $3;
	    yyMeridian = MER24;
	    yyDSTmode = DSToff;
	    yyTimezone = - ($4 % 100 + ($4 / 100) * 60);
	}
	| tUNUMBER ':' tUNUMBER ':' tUNUMBER o_merid {
	    yyHour = $1;
	    yyMinutes = $3;
	    yySeconds = $5;
	    yyMeridian = $6;
	}
	| tUNUMBER ':' tUNUMBER ':' tUNUMBER tSNUMBER {
	    yyHour = $1;
	    yyMinutes = $3;
	    yySeconds = $5;
	    yyMeridian = MER24;
	    yyDSTmode = DSToff;
	    yyTimezone = - ($6 % 100 + ($6 / 100) * 60);
	}
	;

zone	: tZONE {
	    yyTimezone = $1;
	    yyDSTmode = DSToff;
	}
	| tDAYZONE {
	    yyTimezone = $1;
	    yyDSTmode = DSTon;
	}
	|
	  tZONE tDST {
	    yyTimezone = $1;
	    yyDSTmode = DSTon;
	}
	;

day	: tDAY {
	    yyDayOrdinal = 1;
	    yyDayNumber = $1;
	}
	| tDAY ',' {
	    yyDayOrdinal = 1;
	    yyDayNumber = $1;
	}
	| tUNUMBER tDAY {
	    yyDayOrdinal = $1;
	    yyDayNumber = $2;
	}
	;

date	: tUNUMBER '/' tUNUMBER {
	    yyMonth = $1;
	    yyDay = $3;
	}
	| tUNUMBER '/' tUNUMBER '/' tUNUMBER {
	    yyMonth = $1;
	    yyDay = $3;
	    yyYear = $5;
	}
	| tUNUMBER tSNUMBER tSNUMBER {
	    /* ISO 8601 format.  yyyy-mm-dd.  */
	    yyYear = $1;
	    yyMonth = -$2;
	    yyDay = -$3;
	}
	| tUNUMBER tMONTH tSNUMBER {
	    /* e.g. 17-JUN-1992.  */
	    yyDay = $1;
	    yyMonth = $2;
	    yyYear = -$3;
	}
	| tMONTH tUNUMBER {
	    yyMonth = $1;
	    yyDay = $2;
	}
	| tMONTH tUNUMBER ',' tUNUMBER {
	    yyMonth = $1;
	    yyDay = $2;
	    yyYear = $4;
	}
	| tUNUMBER tMONTH {
	    yyMonth = $2;
	    yyDay = $1;
	}
	| tUNUMBER tMONTH tUNUMBER {
	    yyMonth = $2;
	    yyDay = $1;
	    yyYear = $3;
	}
	;

rel	: relunit tAGO {
	    yyRelSeconds = -yyRelSeconds;
	    yyRelMonth = -yyRelMonth;
	}
	| relunit
	;

relunit	: tUNUMBER tMINUTE_UNIT {
	    yyRelSeconds += $1 * $2 * 60L;
	}
	| tSNUMBER tMINUTE_UNIT {
	    yyRelSeconds += $1 * $2 * 60L;
	}
	| tMINUTE_UNIT {
	    yyRelSeconds += $1 * 60L;
	}
	| tSNUMBER tSEC_UNIT {
	    yyRelSeconds += $1;
	}
	| tUNUMBER tSEC_UNIT {
	    yyRelSeconds += $1;
	}
	| tSEC_UNIT {
	    yyRelSeconds++;
	}
	| tSNUMBER tMONTH_UNIT {
	    yyRelMonth += $1 * $2;
	}
	| tUNUMBER tMONTH_UNIT {
	    yyRelMonth += $1 * $2;
	}
	| tMONTH_UNIT {
	    yyRelMonth += $1;
	}
	;

o_merid	: /* NULL */ {
	    $$ = MER24;
	}
	| tMERIDIAN {
	    $$ = $1;
	}
	;

%%

/* Month and day table. */
static TABLE const MonthDayTable[] = {
	{ gettext("january"),	tMONTH,  1 },
	{ gettext("february"),	tMONTH,  2 },
	{ gettext("march"),	tMONTH,  3 },
	{ gettext("april"),	tMONTH,  4 },
	{ gettext("may"),	tMONTH,  5 },
	{ gettext("june"),	tMONTH,  6 },
	{ gettext("july"),	tMONTH,  7 },
	{ gettext("august"),	tMONTH,  8 },
	{ gettext("september"),	tMONTH,  9 },
	{ gettext("sept"),	tMONTH,  9 },
	{ gettext("october"),	tMONTH, 10 },
	{ gettext("november"),	tMONTH, 11 },
	{ gettext("december"),	tMONTH, 12 },
	{ gettext("sunday"),	tDAY, 0 },
	{ gettext("monday"),	tDAY, 1 },
	{ gettext("tuesday"),	tDAY, 2 },
	{ gettext("tues"),	tDAY, 2 },
	{ gettext("wednesday"),	tDAY, 3 },
	{ gettext("wednes"),	tDAY, 3 },
	{ gettext("thursday"),	tDAY, 4 },
	{ gettext("thur"),	tDAY, 4 },
	{ gettext("thurs"),	tDAY, 4 },
	{ gettext("friday"),	tDAY, 5 },
	{ gettext("saturday"),	tDAY, 6 },
	{ NULL }
};

/* Time units table. */
static TABLE const UnitsTable[] = {
	{ gettext("year"),		tMONTH_UNIT,	12 },
	{ gettext("month"),		tMONTH_UNIT,	1 },
	{ gettext("fortnight"),	tMINUTE_UNIT,	14 * 24 * 60 },
	{ gettext("week"),		tMINUTE_UNIT,	7 * 24 * 60 },
	{ gettext("day"),		tMINUTE_UNIT,	1 * 24 * 60 },
	{ gettext("hour"),		tMINUTE_UNIT,	60 },
	{ gettext("minute"),	tMINUTE_UNIT,	1 },
	{ gettext("min"),		tMINUTE_UNIT,	1 },
	{ gettext("second"),	tSEC_UNIT,	1 },
	{ gettext("sec"),		tSEC_UNIT,	1 },
	{ NULL }
};

/* Assorted relative-time words. */
static TABLE const OtherTable[] = {
	{ gettext("tomorrow"),	tMINUTE_UNIT,	1 * 24 * 60 },
	{ gettext("yesterday"),	tMINUTE_UNIT,	-1 * 24 * 60 },
	{ gettext("today"),	tMINUTE_UNIT,	0 },
	{ gettext("now"),	tMINUTE_UNIT,	0 },
	{ gettext("last"),	tUNUMBER,	-1 },
	{ gettext("this"),	tMINUTE_UNIT,	0 },
	{ gettext("next"),	tUNUMBER,	2 },
	{ gettext("first"),	tUNUMBER,	1 },
	/*  { gettext("second"),	tUNUMBER,	2 }, */
	{ gettext("third"),	tUNUMBER,	3 },
	{ gettext("fourth"),	tUNUMBER,	4 },
	{ gettext("fifth"),	tUNUMBER,	5 },
	{ gettext("sixth"),	tUNUMBER,	6 },
	{ gettext("seventh"),	tUNUMBER,	7 },
	{ gettext("eighth"),	tUNUMBER,	8 },
	{ gettext("ninth"),	tUNUMBER,	9 },
	{ gettext("tenth"),	tUNUMBER,	10 },
	{ gettext("eleventh"),	tUNUMBER,	11 },
	{ gettext("twelfth"),	tUNUMBER,	12 },
	{ gettext("ago"),	tAGO,		1 },
	{ gettext("never"),	tNEVER,		0 },
	{ NULL }
};

/* The timezone table. */
/* Some of these are commented out because a time_t can't store a float. */
static TABLE const TimezoneTable[] = {
	{ gettext("gmt"),	tZONE,     HOUR( 0) },	/* Greenwich Mean */
	{ gettext("ut"),	tZONE,     HOUR( 0) },	/* Universal (Coordinated) */
	{ gettext("utc"),	tZONE,     HOUR( 0) },
	{ gettext("wet"),	tZONE,     HOUR( 0) },	/* Western European */
	{ gettext("bst"),	tDAYZONE,  HOUR( 0) },	/* British Summer */
	{ gettext("wat"),	tZONE,     HOUR( 1) },	/* West Africa */
	{ gettext("at"),	tZONE,     HOUR( 2) },	/* Azores */
#if	0
    /* For completeness.  BST is also British Summer, and GST is
     * also Guam Standard. */
    { gettext("bst"),	tZONE,     HOUR( 3) },	/* Brazil Standard */
    { gettext("gst"),	tZONE,     HOUR( 3) },	/* Greenland Standard */
#endif
#if 0
	{ gettext("nft"),	tZONE,     HOUR(3.5) },	/* Newfoundland */
	{ gettext("nst"),	tZONE,     HOUR(3.5) },	/* Newfoundland Standard */
	{ gettext("ndt"),	tDAYZONE,  HOUR(3.5) },	/* Newfoundland Daylight */
#endif
	{ gettext("ast"),	tZONE,     HOUR( 4) },	/* Atlantic Standard */
	{ gettext("adt"),	tDAYZONE,  HOUR( 4) },	/* Atlantic Daylight */
	{ gettext("est"),	tZONE,     HOUR( 5) },	/* Eastern Standard */
	{ gettext("edt"),	tDAYZONE,  HOUR( 5) },	/* Eastern Daylight */
	{ gettext("cst"),	tZONE,     HOUR( 6) },	/* Central Standard */
	{ gettext("cdt"),	tDAYZONE,  HOUR( 6) },	/* Central Daylight */
	{ gettext("mst"),	tZONE,     HOUR( 7) },	/* Mountain Standard */
	{ gettext("mdt"),	tDAYZONE,  HOUR( 7) },	/* Mountain Daylight */
	{ gettext("pst"),	tZONE,     HOUR( 8) },	/* Pacific Standard */
	{ gettext("pdt"),	tDAYZONE,  HOUR( 8) },	/* Pacific Daylight */
	{ gettext("yst"),	tZONE,     HOUR( 9) },	/* Yukon Standard */
	{ gettext("ydt"),	tDAYZONE,  HOUR( 9) },	/* Yukon Daylight */
	{ gettext("hst"),	tZONE,     HOUR(10) },	/* Hawaii Standard */
	{ gettext("hdt"),	tDAYZONE,  HOUR(10) },	/* Hawaii Daylight */
	{ gettext("cat"),	tZONE,     HOUR(10) },	/* Central Alaska */
	{ gettext("ahst"),	tZONE,     HOUR(10) },	/* Alaska-Hawaii Standard */
	{ gettext("nt"),	tZONE,     HOUR(11) },	/* Nome */
	{ gettext("idlw"),	tZONE,     HOUR(12) },	/* International Date Line West */
	{ gettext("cet"),	tZONE,     -HOUR(1) },	/* Central European */
	{ gettext("met"),	tZONE,     -HOUR(1) },	/* Middle European */
	{ gettext("mewt"),	tZONE,     -HOUR(1) },	/* Middle European Winter */
	{ gettext("mest"),	tDAYZONE,  -HOUR(1) },	/* Middle European Summer */
	{ gettext("swt"),	tZONE,     -HOUR(1) },	/* Swedish Winter */
	{ gettext("sst"),	tDAYZONE,  -HOUR(1) },	/* Swedish Summer */
	{ gettext("fwt"),	tZONE,     -HOUR(1) },	/* French Winter */
	{ gettext("fst"),	tDAYZONE,  -HOUR(1) },	/* French Summer */
	{ gettext("eet"),	tZONE,     -HOUR(2) },	/* Eastern Europe, USSR Zone 1 */
	{ gettext("bt"),	tZONE,     -HOUR(3) },	/* Baghdad, USSR Zone 2 */
#if 0
	{ gettext("it"),	tZONE,     -HOUR(3.5) },/* Iran */
#endif
	{ gettext("zp4"),	tZONE,     -HOUR(4) },	/* USSR Zone 3 */
	{ gettext("zp5"),	tZONE,     -HOUR(5) },	/* USSR Zone 4 */
#if 0
	{ gettext("ist"),	tZONE,     -HOUR(5.5) },/* Indian Standard */
#endif
	{ gettext("zp6"),	tZONE,     -HOUR(6) },	/* USSR Zone 5 */
#if	0
    /* For completeness.  NST is also Newfoundland Stanard, and SST is
     * also Swedish Summer. */
    { gettext("nst"),	tZONE,     -HOUR(6.5) },/* North Sumatra */
    { gettext("sst"),	tZONE,     -HOUR(7) },	/* South Sumatra, USSR Zone 6 */
#endif	/* 0 */
	{ gettext("wast"),	tZONE,     -HOUR(7) },	/* West Australian Standard */
	{ gettext("wadt"),	tDAYZONE,  -HOUR(7) },	/* West Australian Daylight */
#if 0
	{ gettext("jt"),	tZONE,     -HOUR(7.5) },/* Java (3pm in Cronusland!) */
#endif
	{ gettext("cct"),	tZONE,     -HOUR(8) },	/* China Coast, USSR Zone 7 */
	{ gettext("jst"),	tZONE,     -HOUR(9) },	/* Japan Standard, USSR Zone 8 */
	{ gettext("kst"),	tZONE,     -HOUR(9) },	/* Korean Standard */
#if 0
	{ gettext("cast"),	tZONE,     -HOUR(9.5) },/* Central Australian Standard */
	{ gettext("cadt"),	tDAYZONE,  -HOUR(9.5) },/* Central Australian Daylight */
#endif
	{ gettext("east"),	tZONE,     -HOUR(10) },	/* Eastern Australian Standard */
	{ gettext("eadt"),	tDAYZONE,  -HOUR(10) },	/* Eastern Australian Daylight */
	{ gettext("gst"),	tZONE,     -HOUR(10) },	/* Guam Standard, USSR Zone 9 */
	{ gettext("kdt"),	tZONE,     -HOUR(10) },	/* Korean Daylight */
	{ gettext("nzt"),	tZONE,     -HOUR(12) },	/* New Zealand */
	{ gettext("nzst"),	tZONE,     -HOUR(12) },	/* New Zealand Standard */
	{ gettext("nzdt"),	tDAYZONE,  -HOUR(12) },	/* New Zealand Daylight */
	{ gettext("idle"),	tZONE,     -HOUR(12) },	/* International Date Line East */
	{  NULL  }
};

/* ARGSUSED */
static int
yyerror(s)
    char	*s;
{
  return 0;
}


static time_t
ToSeconds(Hours, Minutes, Seconds, Meridian)
    time_t	Hours;
    time_t	Minutes;
    time_t	Seconds;
    MERIDIAN	Meridian;
{
    if (Minutes < 0 || Minutes > 59 || Seconds < 0 || Seconds > 59)
	return -1;
    switch (Meridian) {
    case MER24:
	if (Hours < 0 || Hours > 23)
	    return -1;
	return (Hours * 60L + Minutes) * 60L + Seconds;
    case MERam:
	if (Hours < 1 || Hours > 12)
	    return -1;
	return (Hours * 60L + Minutes) * 60L + Seconds;
    case MERpm:
	if (Hours < 1 || Hours > 12)
	    return -1;
	return ((Hours + 12) * 60L + Minutes) * 60L + Seconds;
    default:
	abort ();
    }
    /* NOTREACHED */
}

/*
 * From hh:mm:ss [am|pm] mm/dd/yy [tz], compute and return the number
 * of seconds since 00:00:00 1/1/70 GMT.
 */
static time_t
Convert(Month, Day, Year, Hours, Minutes, Seconds, Meridian, DSTmode)
    time_t	Month;
    time_t	Day;
    time_t	Year;
    time_t	Hours;
    time_t	Minutes;
    time_t	Seconds;
    MERIDIAN	Meridian;
    DSTMODE	DSTmode;
{
    static int DaysInMonth[12] = {
	31, 0, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };
    time_t	tod;
    time_t	Julian;
    int		i;

    if (Year < 0)
	Year = -Year;
    if (Year < 1900)
	Year += 1900;
    DaysInMonth[1] = Year % 4 == 0 && (Year % 100 != 0 || Year % 400 == 0)
		    ? 29 : 28;
    if (Year < EPOCH
	|| Year > EPOCH_END
	|| Month < 1 || Month > 12
	/* Lint fluff:  "conversion from long may lose accuracy" */
	|| Day < 1 || Day > DaysInMonth[(int)--Month])
	 return -1;

    for (Julian = Day - 1, i = 0; i < Month; i++)
	Julian += DaysInMonth[i];
    for (i = EPOCH; i < Year; i++)
	 Julian += 365 + ((i % 4 == 0) && ((Year % 100 != 0) ||
					   (Year % 400 == 0)));
    Julian *= SECSPERDAY;
    Julian += yyTimezone * 60L;
    if ((tod = ToSeconds(Hours, Minutes, Seconds, Meridian)) < 0)
	return -1;
    Julian += tod;
    if (DSTmode == DSTon
     || (DSTmode == DSTmaybe && localtime(&Julian)->tm_isdst))
	Julian -= 60 * 60;
    return Julian;
}


static time_t
DSTcorrect(Start, Future)
    time_t	Start;
    time_t	Future;
{
    time_t	StartDay;
    time_t	FutureDay;

    StartDay = (localtime(&Start)->tm_hour + 1) % 24;
    FutureDay = (localtime(&Future)->tm_hour + 1) % 24;
    return (Future - Start) + (StartDay - FutureDay) * 60L * 60L;
}


static time_t
RelativeDate(Start, DayOrdinal, DayNumber)
    time_t	Start;
    time_t	DayOrdinal;
    time_t	DayNumber;
{
    struct tm	*tm;
    time_t	now;

    now = Start;
    tm = localtime(&now);
    now += SECSPERDAY * ((DayNumber - tm->tm_wday + 7) % 7);
    now += 7 * SECSPERDAY * (DayOrdinal <= 0 ? DayOrdinal : DayOrdinal - 1);
    return DSTcorrect(Start, now);
}


static time_t
RelativeMonth(Start, RelMonth)
    time_t	Start;
    time_t	RelMonth;
{
    struct tm	*tm;
    time_t	Month;
    time_t	Year;
    time_t	ret;

    if (RelMonth == 0)
	return 0;
    tm = localtime(&Start);
    Month = 12 * tm->tm_year + tm->tm_mon + RelMonth;
    Year = Month / 12;
    Month = Month % 12 + 1;
    ret = Convert(Month, (time_t)tm->tm_mday, Year,
		  (time_t)tm->tm_hour, (time_t)tm->tm_min, (time_t)tm->tm_sec,
		  MER24, DSTmaybe);
    if (ret == -1)
      return ret;
    return DSTcorrect(Start, ret);
}


static int
LookupWord(buff)
    char		*buff;
{
    register char	*p;
    register char	*q;
    register const TABLE	*tp;
    int			i;
    int			abbrev;

    /* Make it lowercase. */
    for (p = buff; *p; p++)
	if (isupper((int) *p))
	    *p = tolower((int) *p);

    if (strcmp(buff, gettext("am")) == 0 || strcmp(buff, gettext("a.m.")) == 0) {
	yylval.Meridian = MERam;
	return tMERIDIAN;
    }
    if (strcmp(buff, gettext("pm")) == 0 ||
	    strcmp(buff, gettext("p.m.")) == 0) {
	yylval.Meridian = MERpm;
	return tMERIDIAN;
    }

    /* See if we have an abbreviation for a month. */
    if (strlen(buff) == 3)
	abbrev = 1;
    else if (strlen(buff) == 4 && buff[3] == '.') {
	abbrev = 1;
	buff[3] = '\0';
    }
    else
	abbrev = 0;

    for (tp = MonthDayTable; tp->name; tp++) {
	if (abbrev) {
	    if (strncmp(buff, GETTEXT(tp->name), 3) == 0) {
		yylval.Number = tp->value;
		return tp->type;
	    }
	}
	else if (strcmp(buff, GETTEXT(tp->name)) == 0) {
	    yylval.Number = tp->value;
	    return tp->type;
	}
    }

    for (tp = TimezoneTable; tp->name; tp++)
	if (strcmp(buff, GETTEXT(tp->name)) == 0) {
	    yylval.Number = tp->value;
	    return tp->type;
	}

    if (strcmp(buff, gettext("dst")) == 0)
	return tDST;

    for (tp = UnitsTable; tp->name; tp++)
	if (strcmp(buff, GETTEXT(tp->name)) == 0) {
	    yylval.Number = tp->value;
	    return tp->type;
	}

    /* Strip off any plural and try the units table again. */
    i = strlen(buff) - 1;
    if (buff[i] == 's') {
	buff[i] = '\0';
	for (tp = UnitsTable; tp->name; tp++)
	    if (strcmp(buff, GETTEXT(tp->name)) == 0) {
		yylval.Number = tp->value;
		return tp->type;
	    }
	buff[i] = 's';		/* Put back for "this" in OtherTable. */
    }

    for (tp = OtherTable; tp->name; tp++)
	if (strcmp(buff, GETTEXT(tp->name)) == 0) {
	    yylval.Number = tp->value;
	    return tp->type;
	}

    /* Drop out any periods and try the timezone table again. */
    for (i = 0, p = q = buff; *q; q++)
	if (*q != '.')
	    *p++ = *q;
	else
	    i++;
    *p = '\0';
    if (i)
	for (tp = TimezoneTable; tp->name; tp++)
	    if (strcmp(buff, GETTEXT(tp->name)) == 0) {
		yylval.Number = tp->value;
		return tp->type;
	    }

    return tID;
}


static int
yylex()
{
    register char	c;
    register char	*p;
    char		buff[20];
    int			Count;
    int			sign;

    for ( ; ; ) {
	while (isspace((int) *yyInput))
	    yyInput++;

	c = *yyInput;
	if (isdigit((int) c) || c == '-' || c == '+') {
	    if (c == '-' || c == '+') {
		sign = c == '-' ? -1 : 1;
		if (!isdigit((int) (*++yyInput)))
		    /* skip the '-' sign */
		    continue;
	    }
	    else
		sign = 0;
	    for (yylval.Number = 0; isdigit((int) (c = *yyInput++)); )
		yylval.Number = 10 * yylval.Number + c - '0';
	    yyInput--;
	    if (sign < 0)
		yylval.Number = -yylval.Number;
	    return sign ? tSNUMBER : tUNUMBER;
	}
	if (isalpha((int) c)) {
	    for (p = buff; isalpha((int) (c = *yyInput++)) || c == '.'; )
		if (p < &buff[sizeof buff - 1])
		    *p++ = c;
	    *p = '\0';
	    yyInput--;
	    return LookupWord(buff);
	}
	if (c != '(')
	    return *yyInput++;
	Count = 0;
	do {
	    c = *yyInput++;
	    if (c == '\0')
		return c;
	    if (c == '(')
		Count++;
	    else if (c == ')')
		Count--;
	} while (Count > 0);
    }
}


#define TM_YEAR_ORIGIN 1900

/* Yield A - B, measured in seconds.  */
static time_t
difftm(a, b)
     struct tm *a, *b;
{
  int ay = a->tm_year + (TM_YEAR_ORIGIN - 1);
  int by = b->tm_year + (TM_YEAR_ORIGIN - 1);
  return
    (
     (
      (
       /* difference in day of year */
       a->tm_yday - b->tm_yday
       /* + intervening leap days */
       +  ((ay >> 2) - (by >> 2))
       -  (ay/100 - by/100)
       +  ((ay/100 >> 2) - (by/100 >> 2))
       /* + difference in years * 365 */
       +  (time_t)(ay-by) * 365
       )*24 + (a->tm_hour - b->tm_hour)
      )*60 + (a->tm_min - b->tm_min)
     )*60 + (a->tm_sec - b->tm_sec);
}

/* For get_date extern declaration compatibility check... yuck.  */
#include <krb5.h>
#include "kadmin.h"

time_t
get_date(p)
    char		*p;
{
    struct my_timeb	*now = NULL;
    struct tm		*tm, gmt;
    struct my_timeb	ftz;
    time_t		Start;
    time_t		tod;
    time_t		delta;

    yyInput = p;
    if (now == NULL) {
        now = &ftz;

	ftz.time = time((time_t *) 0);

	if (! (tm = gmtime (&ftz.time)))
	    return -1;
	gmt = *tm;	/* Make a copy, in case localtime modifies *tm.  */
	ftz.timezone = difftm (&gmt, localtime (&ftz.time)) / 60;
    }

    tm = localtime(&now->time);
    yyYear = tm->tm_year;
    yyMonth = tm->tm_mon + 1;
    yyDay = tm->tm_mday;
    yyTimezone = now->timezone;
    yyDSTmode = DSTmaybe;
    yyHour = 0;
    yyMinutes = 0;
    yySeconds = 0;
    yyMeridian = MER24;
    yyRelSeconds = 0;
    yyRelMonth = 0;
    yyHaveDate = 0;
    yyHaveDay = 0;
    yyHaveRel = 0;
    yyHaveTime = 0;
    yyHaveZone = 0;

    /*
     * When yyparse returns, zero or more of yyHave{Time,Zone,Date,Day,Rel} 
     * will have been incremented.  The value is number of items of
     * that type that were found; for all but Rel, more than one is
     * illegal.
     *
     * For each yyHave indicator, the following values are set:
     *
     * yyHaveTime:
     *	yyHour, yyMinutes, yySeconds: hh:mm:ss specified, initialized
     *				      to zeros above
     *	yyMeridian: MERam, MERpm, or MER24
     *	yyTimeZone: time zone specified in minutes
     *  yyDSTmode: DSToff if yyTimeZone is set, otherwise unchanged
     *		   (initialized above to DSTmaybe)
     *
     * yyHaveZone:
     *  yyTimezone: as above
     *  yyDSTmode: DSToff if a non-DST zone is specified, otherwise DSTon
     *	XXX don't understand interaction with yyHaveTime zone info
     *
     * yyHaveDay:
     *	yyDayNumber: 0-6 for Sunday-Saturday
     *  yyDayOrdinal: val specified with day ("second monday",
     *		      Ordinal=2), otherwise 1
     *
     * yyHaveDate:
     *	yyMonth, yyDay, yyYear: mm/dd/yy specified, initialized to
     *				today above
     *
     * yyHaveRel:
     *	yyRelSeconds: seconds specified with MINUTE_UNITs ("3 hours") or
     *		      SEC_UNITs ("30 seconds")
     *  yyRelMonth: months specified with MONTH_UNITs ("3 months", "1
     *		     year")
     *
     * The code following yyparse turns these values into a single
     * date stamp.
     */
    if (yyparse()
     || yyHaveTime > 1 || yyHaveZone > 1 || yyHaveDate > 1 || yyHaveDay > 1)
	return -1;

    /*
     * If an absolute time specified, set Start to the equivalent Unix
     * timestamp.  Otherwise, set Start to now, and if we do not have
     * a relatime time (ie: only yyHaveZone), decrement Start to the
     * beginning of today.
     *
     * By having yyHaveDay in the "absolute" list, "next Monday" means
     * midnight next Monday.  Otherwise, "next Monday" would mean the
     * time right now, next Monday.  It's not clear to me why the
     * current behavior is preferred.
     */
    if (yyHaveDate || yyHaveTime || yyHaveDay) {
	Start = Convert(yyMonth, yyDay, yyYear, yyHour, yyMinutes, yySeconds,
		    yyMeridian, yyDSTmode);
	if (Start < 0)
	    return -1;
    }
    else {
	Start = now->time;
	if (!yyHaveRel)
	    Start -= ((tm->tm_hour * 60L + tm->tm_min) * 60L) + tm->tm_sec;
    }

    /*
     * Add in the relative time specified.  RelativeMonth adds in the
     * months, accounting for the fact that the actual length of "3
     * months" depends on where you start counting.
     *
     * XXX By having this separate from the previous block, we are
     * allowing dates like "10:00am 3 months", which means 3 months
     * from 10:00am today, or even "1/1/99 two days" which means two
     * days after 1/1/99.
     *
     * XXX Shouldn't this only be done if yyHaveRel, just for
     * thoroughness?
     */
    Start += yyRelSeconds;
    delta = RelativeMonth(Start, yyRelMonth);
    if (delta == (time_t) -1)
      return -1;
    Start += delta;

    /*
     * Now, if you specified a day of week and counter, add it in.  By
     * disallowing Date but allowing Time, you can say "5pm next
     * monday".
     *
     * XXX The yyHaveDay && !yyHaveDate restriction should be enforced
     * above and be able to cause failure.
     */
    if (yyHaveDay && !yyHaveDate) {
	tod = RelativeDate(Start, yyDayOrdinal, yyDayNumber);
	Start += tod;
    }

    /* Have to do *something* with a legitimate -1 so it's distinguishable
     * from the error return value.  (Alternately could set errno on error.) */
    return Start == -1 ? 0 : Start;
}


#if	defined(TEST)

/* ARGSUSED */
main(ac, av)
    int		ac;
    char	*av[];
{
    char	buff[128];
    time_t	d;

    (void)printf(gettext("Enter date, or blank line to exit.\n\t> "));
    (void)fflush(stdout);
    while (gets(buff) && buff[0]) {
	d = get_date(buff, (struct my_timeb *)NULL);
	if (d == -1)
	    (void)printf(
				gettext("Bad format - couldn't convert.\n"));
	else
	    (void)printf("%s", ctime(&d));
	(void)printf("\t> ");
	(void)fflush(stdout);
    }
    exit(0);
    /* NOTREACHED */
}
#endif	/* defined(TEST) */
