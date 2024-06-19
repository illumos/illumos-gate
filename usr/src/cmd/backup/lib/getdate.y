%{
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* $OrigRevision: 2.1 $
**
**  Originally written by Steven M. Bellovin <smb@research.att.com> while
**  at the University of North Carolina at Chapel Hill.  Later tweaked by
**  a couple of people on Usenet.  Completely overhauled by Rich $alz
**  <rsalz@bbn.com> and Jim Berets <jberets@bbn.com> in August, 1990;
**  send any email to Rich.
**
**  This grammar has eight shift/reduce conflicts.
**
**  This code is in the public domain and has no copyright.
*/
/* SUPPRESS 287 on yaccpar_sccsid *//* Unusd static variable */
/* SUPPRESS 288 on yyerrlab *//* Label unused */
#include <stdio.h>
#include <ctype.h>

#include <sys/types.h>
#define NEED_TZSET
struct timeb {
    time_t		time;		/* Seconds since the epoch	*/
    unsigned short	millitm;	/* Field not used		*/
    short		timezone;
    short		dstflag;	/* Field not used		*/
};
#include <time.h>

#include <locale.h>
#include <string.h>
#include <stdlib.h>
#include <note.h>
#include <libintl.h>

#if	!defined(lint) && !defined(SABER)
static char RCS[] =
	"$Header: /home/laramie/berliner/ws/backup/usr/src/cmd/backup/lib/getdate.y,v 1.5 1992/06/09 21:46:21 sam Exp $";
#endif	/* !defined(lint) && !defined(SABER) */


#define EPOCH		1970
#define HOURN(x)	(x * 60)
#define SECSPERDAY	(24L * 60L * 60L)

#define CHECK_TM(y) (((y) % 100) < 70 ? (y) + 2000 : (y) + 1900)

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

static char	*domainname = "hsm_libdump";	/* for dgettext() */

#define yylex 1					/* suppress yacc's definition */
%}

%union {
    time_t		Number;
    enum _MERIDIAN	Meridian;
}

%token	tAGO tDAY tDAYZONE tID tMERIDIAN tMINUTE_UNIT tMONTH tMONTH_UNIT
%token	tSEC_UNIT tSNUMBER tUNUMBER tZONE

%type	<Number>	tDAY tDAYZONE tMINUTE_UNIT tMONTH tMONTH_UNIT
%type	<Number>	tSEC_UNIT tSNUMBER tUNUMBER tZONE
%type	<Meridian>	tMERIDIAN o_merid

%%

spec	: /* NULL */
	| spec item
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
	| number
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

number	: tUNUMBER {
	    if (yyHaveTime && yyHaveDate && !yyHaveRel)
		yyYear = $1;
	    else {
		yyHaveTime++;
		if ($1 < 100) {
		    yyHour = $1;
		    yyMinutes = 0;
		}
		else {
		    yyHour = $1 / 100;
		    yyMinutes = $1 % 100;
		}
		yySeconds = 0;
		yyMeridian = MER24;
	    }
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
static TABLE	MonthDayTable[] = {
    { "january",	tMONTH,  1 },
    { "february",	tMONTH,  2 },
    { "march",		tMONTH,  3 },
    { "april",		tMONTH,  4 },
    { "may",		tMONTH,  5 },
    { "june",		tMONTH,  6 },
    { "july",		tMONTH,  7 },
    { "august",		tMONTH,  8 },
    { "september",	tMONTH,  9 },
    { "sept",		tMONTH,  9 },
    { "october",	tMONTH, 10 },
    { "november",	tMONTH, 11 },
    { "december",	tMONTH, 12 },
    { "sunday",		tDAY, 0 },
    { "monday",		tDAY, 1 },
    { "tuesday",	tDAY, 2 },
    { "tues",		tDAY, 2 },
    { "wednesday",	tDAY, 3 },
    { "wednes",		tDAY, 3 },
    { "thursday",	tDAY, 4 },
    { "thur",		tDAY, 4 },
    { "thurs",		tDAY, 4 },
    { "friday",		tDAY, 5 },
    { "saturday",	tDAY, 6 },
    { NULL }
};

/* Time units table. */
static TABLE	UnitsTable[] = {
    { "year",		tMONTH_UNIT,	12 },
    { "month",		tMONTH_UNIT,	1 },
    { "fortnight",	tMINUTE_UNIT,	14 * 24 * 60 },
    { "week",		tMINUTE_UNIT,	7 * 24 * 60 },
    { "day",		tMINUTE_UNIT,	1 * 24 * 60 },
    { "hour",		tMINUTE_UNIT,	60 },
    { "minute",		tMINUTE_UNIT,	1 },
    { "min",		tMINUTE_UNIT,	1 },
    { "second",		tSEC_UNIT,	1 },
    { "sec",		tSEC_UNIT,	1 },
    { NULL }
};

/* Assorted relative-time words. */
static TABLE	OtherTable[] = {
    { "tomorrow",	tMINUTE_UNIT,	1 * 24 * 60 },
    { "yesterday",	tMINUTE_UNIT,	-1 * 24 * 60 },
    { "today",		tMINUTE_UNIT,	0 },
    { "now",		tMINUTE_UNIT,	0 },
    { "last",		tUNUMBER,	-1 },
    { "this",		tMINUTE_UNIT,	0 },
    { "next",		tUNUMBER,	2 },
    { "first",		tUNUMBER,	1 },
/*  { "second",		tUNUMBER,	2 }, */
    { "third",		tUNUMBER,	3 },
    { "fourth",		tUNUMBER,	4 },
    { "fifth",		tUNUMBER,	5 },
    { "sixth",		tUNUMBER,	6 },
    { "seventh",	tUNUMBER,	7 },
    { "eighth",		tUNUMBER,	8 },
    { "ninth",		tUNUMBER,	9 },
    { "tenth",		tUNUMBER,	10 },
    { "eleventh",	tUNUMBER,	11 },
    { "twelfth",	tUNUMBER,	12 },
    { "ago",		tAGO,	1 },
    { NULL }
};

/* The timezone table. */
static TABLE	TimezoneTable[] = {
    { "gmt",	tZONE,     HOURN( 0) },	/* Greenwich Mean */
    { "ut",	tZONE,     HOURN( 0) },	/* Universal (Coordinated) */
    { "utc",	tZONE,     HOURN( 0) },
    { "wet",	tZONE,     HOURN( 0) },	/* Western European */
    { "bst",	tDAYZONE,  HOURN( 0) },	/* British Summer */
    { "wat",	tZONE,     HOURN( 1) },	/* West Africa */
    { "at",	tZONE,     HOURN( 2) },	/* Azores */
#if	0
    /* For completeness.  BST is also British Summer, and GST is
     * also Guam Standard. */
    { "bst",	tZONE,     HOURN( 3) },	/* Brazil Standard */
    { "gst",	tZONE,     HOURN( 3) },	/* Greenland Standard */
#endif
    { "nft",	tZONE,     HOURN(3.5) },	/* Newfoundland */
    { "nst",	tZONE,     HOURN(3.5) },	/* Newfoundland Standard */
    { "ndt",	tDAYZONE,  HOURN(3.5) },	/* Newfoundland Daylight */
    { "ast",	tZONE,     HOURN( 4) },	/* Atlantic Standard */
    { "adt",	tDAYZONE,  HOURN( 4) },	/* Atlantic Daylight */
    { "est",	tZONE,     HOURN( 5) },	/* Eastern Standard */
    { "edt",	tDAYZONE,  HOURN( 5) },	/* Eastern Daylight */
    { "cst",	tZONE,     HOURN( 6) },	/* Central Standard */
    { "cdt",	tDAYZONE,  HOURN( 6) },	/* Central Daylight */
    { "mst",	tZONE,     HOURN( 7) },	/* Mountain Standard */
    { "mdt",	tDAYZONE,  HOURN( 7) },	/* Mountain Daylight */
    { "pst",	tZONE,     HOURN( 8) },	/* Pacific Standard */
    { "pdt",	tDAYZONE,  HOURN( 8) },	/* Pacific Daylight */
    { "yst",	tZONE,     HOURN( 9) },	/* Yukon Standard */
    { "ydt",	tDAYZONE,  HOURN( 9) },	/* Yukon Daylight */
    { "hst",	tZONE,     HOURN(10) },	/* Hawaii Standard */
    { "hdt",	tDAYZONE,  HOURN(10) },	/* Hawaii Daylight */
    { "cat",	tZONE,     HOURN(10) },	/* Central Alaska */
    { "ahst",	tZONE,     HOURN(10) },	/* Alaska-Hawaii Standard */
    { "nt",	tZONE,     HOURN(11) },	/* Nome */
    { "idlw",	tZONE,     HOURN(12) },	/* International Date Line West */
    { "cet",	tZONE,     -HOURN(1) },	/* Central European */
    { "met",	tZONE,     -HOURN(1) },	/* Middle European */
    { "mewt",	tZONE,     -HOURN(1) },	/* Middle European Winter */
    { "mest",	tDAYZONE,  -HOURN(1) },	/* Middle European Summer */
    { "swt",	tZONE,     -HOURN(1) },	/* Swedish Winter */
    { "sst",	tDAYZONE,  -HOURN(1) },	/* Swedish Summer */
    { "fwt",	tZONE,     -HOURN(1) },	/* French Winter */
    { "fst",	tDAYZONE,  -HOURN(1) },	/* French Summer */
    { "eet",	tZONE,     -HOURN(2) },	/* Eastern Europe, USSR Zone 1 */
    { "bt",	tZONE,     -HOURN(3) },	/* Baghdad, USSR Zone 2 */
    { "it",	tZONE,     -HOURN(3.5) },/* Iran */
    { "zp4",	tZONE,     -HOURN(4) },	/* USSR Zone 3 */
    { "zp5",	tZONE,     -HOURN(5) },	/* USSR Zone 4 */
    { "ist",	tZONE,     -HOURN(5.5) },/* Indian Standard */
    { "zp6",	tZONE,     -HOURN(6) },	/* USSR Zone 5 */
#if	0
    /* For completeness.  NST is also Newfoundland Stanard, nad SST is
     * also Swedish Summer. */
    { "nst",	tZONE,     -HOURN(6.5) },/* North Sumatra */
    { "sst",	tZONE,     -HOURN(7) },	/* South Sumatra, USSR Zone 6 */
#endif	/* 0 */
    { "wast",	tZONE,     -HOURN(7) },	/* West Australian Standard */
    { "wadt",	tDAYZONE,  -HOURN(7) },	/* West Australian Daylight */
    { "jt",	tZONE,     -HOURN(7.5) },/* Java (3pm in Cronusland!) */
    { "cct",	tZONE,     -HOURN(8) },	/* China Coast, USSR Zone 7 */
    { "jst",	tZONE,     -HOURN(9) },	/* Japan Standard, USSR Zone 8 */
    { "cast",	tZONE,     -HOURN(9.5) },/* Central Australian Standard */
    { "cadt",	tDAYZONE,  -HOURN(9.5) },/* Central Australian Daylight */
    { "east",	tZONE,     -HOURN(10) },	/* Eastern Australian Standard */
    { "eadt",	tDAYZONE,  -HOURN(10) },	/* Eastern Australian Daylight */
    { "gst",	tZONE,     -HOURN(10) },	/* Guam Standard, USSR Zone 9 */
    { "nzt",	tZONE,     -HOURN(12) },	/* New Zealand */
    { "nzst",	tZONE,     -HOURN(12) },	/* New Zealand Standard */
    { "nzdt",	tDAYZONE,  -HOURN(12) },	/* New Zealand Daylight */
    { "idle",	tZONE,     -HOURN(12) },	/* International Date Line East */
    {  NULL  }
};

/* Military timezone table. */
static TABLE	MilitaryTable[] = {
    { "a",	tZONE,	HOURN(  1) },
    { "b",	tZONE,	HOURN(  2) },
    { "c",	tZONE,	HOURN(  3) },
    { "d",	tZONE,	HOURN(  4) },
    { "e",	tZONE,	HOURN(  5) },
    { "f",	tZONE,	HOURN(  6) },
    { "g",	tZONE,	HOURN(  7) },
    { "h",	tZONE,	HOURN(  8) },
    { "i",	tZONE,	HOURN(  9) },
    { "k",	tZONE,	HOURN( 10) },
    { "l",	tZONE,	HOURN( 11) },
    { "m",	tZONE,	HOURN( 12) },
    { "n",	tZONE,	HOURN(- 1) },
    { "o",	tZONE,	HOURN(- 2) },
    { "p",	tZONE,	HOURN(- 3) },
    { "q",	tZONE,	HOURN(- 4) },
    { "r",	tZONE,	HOURN(- 5) },
    { "s",	tZONE,	HOURN(- 6) },
    { "t",	tZONE,	HOURN(- 7) },
    { "u",	tZONE,	HOURN(- 8) },
    { "v",	tZONE,	HOURN(- 9) },
    { "w",	tZONE,	HOURN(-10) },
    { "x",	tZONE,	HOURN(-11) },
    { "y",	tZONE,	HOURN(-12) },
    { "z",	tZONE,	HOURN(  0) },
    { NULL }
};




static int
yyerror(const char *s __unused)
{
	return (0);
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
	if (Hours != 12)
	    return (Hours * 60L + Minutes) * 60L + Seconds;
	else
	    return Minutes * 60L + Seconds;
    case MERpm:
	if (Hours < 1 || Hours > 12)
	    return -1;
	if (Hours != 12)
	    return ((Hours + 12) * 60L + Minutes) * 60L + Seconds;
	else
	    return (720L + Minutes) * 60L + Seconds;
    }
    /* NOTREACHED */
    return (-1);
}


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
    static int	DaysInMonth[12] = {
	31, 0, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };
    time_t	tod;
    time_t	Julian;
    time_t	i;

    if (Year < 0)
	Year = -Year;
    if (Year < 138)
	Year += 1900;
    DaysInMonth[1] = Year % 4 == 0 && (Year % 100 != 0 || Year % 400 == 0)
		    ? 29 : 28;
    if (Year < EPOCH || Year > 2037
     || Month < 1 || Month > 12
     /* LINTED Month is a time_t so intermediate results aren't truncated */
     || Day < 1 || Day > DaysInMonth[(int)--Month])
	return -1;

    for (Julian = Day - 1, i = 0; i < Month; i++)
	Julian += DaysInMonth[i];
    for (i = EPOCH; i < Year; i++)
	Julian += 365 + (i % 4 == 0);
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

    if (RelMonth == 0)
	return 0;
    tm = localtime(&Start);
    Month = 12 * tm->tm_year + tm->tm_mon + RelMonth;
    Year = Month / 12;
    Month = Month % 12 + 1;
    return DSTcorrect(Start,
	    Convert(Month, (time_t)tm->tm_mday, Year,
		(time_t)tm->tm_hour, (time_t)tm->tm_min, (time_t)tm->tm_sec,
		MER24, DSTmaybe));
}


static int
LookupWord(buff)
    char		*buff;
{
    char	*p;
    char	*q;
    TABLE	*tp;
    uint_t	i;
    int		abbrev;

    /* Make it lowercase. */
    for (p = buff; *p; p++)
	if (isupper((u_char)*p))
	    *p = tolower(*p);

    if (strcmp(buff, "am") == 0 || strcmp(buff, "a.m.") == 0) {
	yylval.Meridian = MERam;
	return tMERIDIAN;
    }
    if (strcmp(buff, "pm") == 0 || strcmp(buff, "p.m.") == 0) {
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
	    if (strncmp(buff, tp->name, 3) == 0) {
		yylval.Number = tp->value;
		return tp->type;
	    }
	}
	else if (strcmp(buff, tp->name) == 0) {
	    yylval.Number = tp->value;
	    return tp->type;
	}
    }

    for (tp = TimezoneTable; tp->name; tp++)
	if (strcmp(buff, tp->name) == 0) {
	    yylval.Number = tp->value;
	    return tp->type;
	}

    for (tp = UnitsTable; tp->name; tp++)
	if (strcmp(buff, tp->name) == 0) {
	    yylval.Number = tp->value;
	    return tp->type;
	}

    /* Strip off any plural and try the units table again. */
    i = strlen(buff) - 1;
    if (buff[i] == 's') {
	buff[i] = '\0';
	for (tp = UnitsTable; tp->name; tp++)
	    if (strcmp(buff, tp->name) == 0) {
		yylval.Number = tp->value;
		return tp->type;
	    }
    }

    for (tp = OtherTable; tp->name; tp++)
	if (strcmp(buff, tp->name) == 0) {
	    yylval.Number = tp->value;
	    return tp->type;
	}

    /* Military timezones. */
    if (buff[1] == '\0' && isalpha((u_char)*buff)) {
	for (tp = MilitaryTable; tp->name; tp++)
	    if (strcmp(buff, tp->name) == 0) {
		yylval.Number = tp->value;
		return tp->type;
	    }
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
	    if (strcmp(buff, tp->name) == 0) {
		yylval.Number = tp->value;
		return tp->type;
	    }

    return tID;
}

void
pdateerr(p)
    char	*p;
{
    char	*name = "DATEMSK";	/* env variable for date format */
    char	*value;
    char	fmt[256], line[256];
    FILE	*fp;
    time_t	now;
    struct tm	*tm;

    value = getenv(name);
    if (value == (char *)0) {
	fprintf(stderr,
	    dgettext(domainname, "%s: Environment variable %s not set\n"),
		p, name);
	return;
    }
    switch (getdate_err) {
	case 0:
	default:
	    fprintf(stderr,
		dgettext(domainname, "%s: Unkown getdate() error\n"), p);
	    break;
	case 1:
	    fprintf(stderr,
		dgettext(domainname, "%s: %s null or undefined\n"), p, name);
	    break;
	case 2:
	    fprintf(stderr, dgettext(domainname,
		"%s: Cannot read template file %s\n"), p, value);
	    break;
	case 3:
	    fprintf(stderr, dgettext(domainname,
		"%s: Failed to get file status information\n"), p);
	    break;
	case 4:
	    fprintf(stderr, dgettext(domainname,
		"%s: Template file %s not a regular file\n"), p, value);
	    break;
	case 5:
	    fprintf(stderr, dgettext(domainname,
		"%s: Error reading template file %s\n"), p, value);
	    break;
	case 6:
	    fprintf(stderr, dgettext(domainname,
		"%s: %s failed\n"), p, "malloc()");
	    break;
	case 7:
	    fprintf(stderr, dgettext(domainname,
		"%s: Bad date/time format\n"), p);
	    fp = fopen(value, "r");
	    if (fp == (FILE *)0)
		break;
	    now = time((time_t *)0);
	    tm = localtime(&now);
	    fprintf(stderr, dgettext(domainname,
		"The following are examples of valid formats:\n"));
	    while (fgets(fmt, sizeof (fmt), fp)) {
		if (strchr(fmt, '%') == (char *)0)
		    continue;
		fprintf(stderr, "    ");
	        (void) strftime(line, sizeof (line), fmt, tm);
		fprintf(stderr, "%s", line);
	    }
	    (void) fclose(fp);
	    break;
	case 8:
	    (void) fprintf(stderr, dgettext(domainname,
		"%s: Invalid date specification\n"), p);
	    break;
    }
}

#undef yylex
static int
yylex()
{
    char	c;
    char	*p;
    char	buff[20];
    int		Count;
    int		sign;

    for ( ; ; ) {
	while (isspace((u_char)*yyInput))
	    yyInput++;

	if (isdigit((u_char)(c = *yyInput)) || c == '-' || c == '+') {
	    if (c == '-' || c == '+') {
		sign = c == '-' ? -1 : 1;
		if (!isdigit((u_char)*++yyInput))
		    /* skip the '-' sign */
		    continue;
	    }
	    else
		sign = 0;
	    yylval.Number = 0;
	    while (isdigit((u_char)(c = *yyInput++))) {
		int n;
		char digit = c;
		(void) sscanf(&digit, "%1d", &n);
		yylval.Number = 10 * yylval.Number + n;
	    }
	    yyInput--;
	    if (sign < 0)
		yylval.Number = -yylval.Number;
	    return sign ? tSNUMBER : tUNUMBER;
	}
	if (isalpha((u_char)c)) {
	    for (p = buff; isalpha((u_char)(c = *yyInput++)) || c == '.'; )
		if (p < &buff[sizeof (buff) - 1])
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


time_t
getreldate(p, now)
    char		*p;
    struct timeb	*now;
{
    struct tm		*tm;
    struct timeb	ftz;
    time_t		Start;
    time_t		tod;

    if (strcmp(setlocale(LC_TIME, NULL), "C")) {
	static char localedate[24];
	struct tm ltm;

	tm = getdate(p);
	if (getdate_err == 1 /* NODATEMASK */) {
	    char buffy[BUFSIZ];
	    time_t current;

	    printf(gettext("environment variable %s not set\n"), "DATEMSK");
	    do {
		time(&current);
		tm = localtime(&current);
		memcpy(&ltm, tm, sizeof(ltm));
		tm = &ltm;

		(void) fputs(gettext("Enter date as mmddhhmm[yy]: "), stdout);
		(void) fflush(stdout);
		if (fgets(buffy, sizeof (buffy), stdin) == NULL) {
			(void) printf(gettext("Encountered EOF on stdin\n"));
			return(-1);
		}
	    } while (sscanf(buffy, "%2d%2d%2d%2d%2d",
		&(tm->tm_mon), &(tm->tm_mday), &(tm->tm_hour),
		&(tm->tm_min), &(tm->tm_year)) < 4);

	    (tm->tm_mon)--;
	} else if (tm == NULL)
	    return(-1);

	(void)sprintf(localedate, "%d:%2.2d %d/%d %d",
	    tm->tm_hour, tm->tm_min, tm->tm_mon + 1,
	    tm->tm_mday, CHECK_TM(tm->tm_year));
	p = localedate;
    }

    yyInput = p;
    if (now == NULL) {
	now = &ftz;
	(void) time(&ftz.time);
	/* Set the timezone global. */
	tzset();
	/* LINTED timezone is time_t so intermediate results aren't truncated */
	ftz.timezone = (int) timezone / 60;
    }

    tm = localtime(&now->time);
    yyYear = tm->tm_year;
    yyMonth = tm->tm_mon + 1;
    yyDay = tm->tm_mday;
    yyTimezone = now->timezone;
    yyDSTmode = DSTmaybe;
    yyHour = tm->tm_hour;
    yyMinutes = tm->tm_min;
    yySeconds = tm->tm_sec;
    yyMeridian = MER24;
    yyRelSeconds = 0;
    yyRelMonth = 0;
    yyHaveDate = 0;
    yyHaveDay = 0;
    yyHaveRel = 0;
    yyHaveTime = 0;
    yyHaveZone = 0;

    if (yyparse()
     || yyHaveTime > 1 || yyHaveZone > 1 || yyHaveDate > 1 || yyHaveDay > 1)
	return -1;

    if (yyHaveDate || yyHaveTime || yyHaveDay) {
	Start = Convert(yyMonth, yyDay, yyYear, yyHour, yyMinutes, yySeconds,
		    yyMeridian, yyDSTmode);
	if (Start < 0)
	    return -1;
    }
    else {
	Start = now->time;
	if (!yyHaveRel)
	    Start -= ((tm->tm_hour * 60L) + tm->tm_min * 60L) + tm->tm_sec;
    }

    Start += yyRelSeconds;
    Start += RelativeMonth(Start, yyRelMonth);

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

    (void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
    (void) textdomain(TEXT_DOMAIN);

    (void) printf(gettext("Enter date, or blank line to exit.\n\t> "));
    (void) fflush(stdout);
    while (gets(buff) && buff[0]) {
	d = getreldate(buff, (struct timeb *)NULL);
	if (d == -1)
	    (void) printf(gettext("Bad format - couldn't convert.\n"));
	else {
	    (void) cftime(buff, "%c\n", &d);
	    (void) printf("%s", buff);
	}
	(void) printf("\t> ");
	(void) fflush(stdout);
    }
    exit(0);
    /* NOTREACHED */
}
#endif	/* defined(TEST) */
