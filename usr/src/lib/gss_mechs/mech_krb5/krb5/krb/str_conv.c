/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * lib/kadm/str_conv.c
 *
 * Copyright 1995, 1999 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

/*
 * str_conv.c - Convert between strings and Kerberos internal data.
 */

/*
 * Table of contents:
 *
 * String decoding:
 * ----------------
 * krb5_string_to_salttype()	- Convert string to salttype (krb5_int32)
 * krb5_string_to_timestamp()	- Convert string to krb5_timestamp.
 * krb5_string_to_deltat()	- Convert string to krb5_deltat.
 *
 * String encoding:
 * ----------------
 * krb5_salttype_to_string()	- Convert salttype (krb5_int32) to string.
 * krb5_timestamp_to_string()	- Convert krb5_timestamp to string.
 * krb5_timestamp_to_sfstring()	- Convert krb5_timestamp to short filled string
 * krb5_deltat_to_string()	- Convert krb5_deltat to string.
 */

#include "k5-int.h"
#include <ctype.h>

/* Salt type conversions */

/*
 * Local data structures.
 */
struct salttype_lookup_entry {
    krb5_int32		stt_enctype;		/* Salt type		*/
    const char *	stt_specifier;		/* How to recognize it	*/
    const char *	stt_output;		/* How to spit it out	*/
};

/*
 * Lookup tables.
 */

#include "kdb.h"
static const struct salttype_lookup_entry salttype_table[] = {
/* salt type			input specifier	output string  */
/*-----------------------------	--------------- ---------------*/
{ KRB5_KDB_SALTTYPE_NORMAL,	"normal",	"Version 5"	  },
{ KRB5_KDB_SALTTYPE_V4,		"v4",		"Version 4"	  },
{ KRB5_KDB_SALTTYPE_NOREALM,	"norealm",	"Version 5 - No Realm" },
{ KRB5_KDB_SALTTYPE_ONLYREALM,	"onlyrealm",	"Version 5 - Realm Only" },
{ KRB5_KDB_SALTTYPE_SPECIAL,	"special",	"Special" },
{ KRB5_KDB_SALTTYPE_AFS3,	"afs3",		"AFS version 3"    }
};
static const int salttype_table_nents = sizeof(salttype_table)/
					sizeof(salttype_table[0]);

krb5_error_code KRB5_CALLCONV
krb5_string_to_salttype(char *string, krb5_int32 *salttypep)
{
    int i;
    int found;

    found = 0;
    for (i=0; i<salttype_table_nents; i++) {
	if (!strcasecmp(string, salttype_table[i].stt_specifier)) {
	    found = 1;
	    *salttypep = salttype_table[i].stt_enctype;
	    break;
	}
    }
    return((found) ? 0 : EINVAL);
}

/*
 * Internal datatype to string routines.
 *
 * These routines return 0 for success, EINVAL for invalid parameter, ENOMEM
 * if the supplied buffer/length will not contain the output.
 */
krb5_error_code KRB5_CALLCONV
krb5_salttype_to_string(krb5_int32 salttype, char *buffer, size_t buflen)
{
    int i;
    const char *out;

    out = (char *) NULL;
    for (i=0; i<salttype_table_nents; i++) {
	if (salttype ==  salttype_table[i].stt_enctype) {
	    out = salttype_table[i].stt_output;
	    break;
	}
    }
    if (out) {
	if (buflen > strlen(out))
	    strcpy(buffer, out);
	else
	    out = (char *) NULL;
	return((out) ? 0 : ENOMEM);
    }
    else
	return(EINVAL);
}

/* (absolute) time conversions */

#ifndef HAVE_STRFTIME
#undef strftime
#define strftime my_strftime
static size_t strftime (char *, size_t, const char *, const struct tm *);
#endif

#ifdef HAVE_STRPTIME
#ifdef NEED_STRPTIME_PROTO
extern char *strptime (const char *, const char *,
			    struct tm *)
#ifdef __cplusplus
    throw()
#endif
    ;
#endif
#else /* HAVE_STRPTIME */
#undef strptime
#define strptime my_strptime
static char *strptime (const char *, const char *, struct tm *);
#endif

krb5_error_code KRB5_CALLCONV
krb5_string_to_timestamp(char *string, krb5_timestamp *timestampp)
{
    int i;
    struct tm timebuf;
    time_t now, ret_time;
    char *s;
    static const char * const atime_format_table[] = {
	"%Y%m%d%H%M%S",		/* yyyymmddhhmmss		*/
	"%Y.%m.%d.%H.%M.%S",	/* yyyy.mm.dd.hh.mm.ss		*/
	"%y%m%d%H%M%S",		/* yymmddhhmmss			*/
	"%y.%m.%d.%H.%M.%S",	/* yy.mm.dd.hh.mm.ss		*/
	"%y%m%d%H%M",		/* yymmddhhmm			*/
	"%H%M%S",		/* hhmmss			*/
	"%H%M",			/* hhmm				*/
	"%T",			/* hh:mm:ss			*/
	"%R",			/* hh:mm			*/
	/* The following not really supported unless native strptime present */
	"%x:%X",		/* locale-dependent short format */
	"%d-%b-%Y:%T",		/* dd-month-yyyy:hh:mm:ss	*/
	"%d-%b-%Y:%R"		/* dd-month-yyyy:hh:mm		*/
    };
    static const int atime_format_table_nents =
	sizeof(atime_format_table)/sizeof(atime_format_table[0]);


    now = time((time_t *) NULL);
    for (i=0; i<atime_format_table_nents; i++) {
        /* We reset every time throughout the loop as the manual page
	 * indicated that no guarantees are made as to preserving timebuf
	 * when parsing fails
	 */
#ifdef HAVE_LOCALTIME_R
	(void) localtime_r(&now, &timebuf);
#else
	memcpy(&timebuf, localtime(&now), sizeof(timebuf));
#endif
	/*LINTED*/
	if ((s = strptime(string, atime_format_table[i], &timebuf))
	    && (s != string)) {
 	    /* See if at end of buffer - otherwise partial processing */
	    while(*s != 0 && isspace((int) *s)) s++;
	    if (*s != 0)
	        continue;
	    if (timebuf.tm_year <= 0)
		continue;	/* clearly confused */
	    ret_time = mktime(&timebuf);
	    if (ret_time == (time_t) -1)
		continue;	/* clearly confused */
	    *timestampp = (krb5_timestamp) ret_time;
	    return 0;
	}
    }
    return(EINVAL);
}

krb5_error_code KRB5_CALLCONV
krb5_timestamp_to_string(krb5_timestamp timestamp, char *buffer, size_t buflen)
{
    int ret;
    time_t timestamp2 = timestamp;
    struct tm tmbuf;
    const char *fmt = "%c"; /* This is to get around gcc -Wall warning that
			       the year returned might be two digits */

#ifdef HAVE_LOCALTIME_R
    (void) localtime_r(&timestamp2, &tmbuf);
#else
    memcpy(&tmbuf, localtime(&timestamp2), sizeof(tmbuf));
#endif
    ret = strftime(buffer, buflen, fmt, &tmbuf);
    if (ret == 0 || ret == buflen)
	return(ENOMEM);
    return(0);
}

krb5_error_code KRB5_CALLCONV
krb5_timestamp_to_sfstring(krb5_timestamp timestamp, char *buffer, size_t buflen, char *pad)
{
    struct tm	*tmp;
    size_t i;
    size_t	ndone;
    time_t timestamp2 = timestamp;
    struct tm tmbuf;

    static const char * const sftime_format_table[] = {
	"%c",			/* Default locale-dependent date and time */
	"%d %b %Y %T",		/* dd mon yyyy hh:mm:ss			*/
	"%x %X",		/* locale-dependent short format	*/
	"%d/%m/%Y %R"		/* dd/mm/yyyy hh:mm			*/
    };
    static const int sftime_format_table_nents =
	sizeof(sftime_format_table)/sizeof(sftime_format_table[0]);

#ifdef HAVE_LOCALTIME_R
    tmp = localtime_r(&timestamp2, &tmbuf);
#else
    memcpy((tmp = &tmbuf), localtime(&timestamp2), sizeof(tmbuf));
#endif
    ndone = 0;
    for (i=0; i<sftime_format_table_nents; i++) {
	if ((ndone = strftime(buffer, buflen, sftime_format_table[i], tmp)))
	    break;
    }
    if (!ndone) {
#define sftime_default_len	2+1+2+1+4+1+2+1+2+1
	if (buflen >= sftime_default_len) {
	    sprintf(buffer, "%02d/%02d/%4d %02d:%02d",
		    tmp->tm_mday, tmp->tm_mon+1, 1900+tmp->tm_year,
		    tmp->tm_hour, tmp->tm_min);
	    ndone = strlen(buffer);
	}
    }
    if (ndone && pad) {
	for (i=ndone; i<buflen-1; i++)
	    buffer[i] = *pad;
	buffer[buflen-1] = '\0';
    }
    return((ndone) ? 0 : ENOMEM);
}

/* Solaris Kerberos */
#ifdef SUNW_INC_DEAD_CODE
/* relative time (delta-t) conversions */

/* string->deltat is in deltat.y */

krb5_error_code KRB5_CALLCONV
krb5_deltat_to_string(krb5_deltat deltat, char *buffer, size_t buflen)
{
    int			days, hours, minutes, seconds;
    krb5_deltat		dt;

    /*
     * We want something like ceil(log10(2**(nbits-1))) + 1.  That log
     * value is log10(2)*(nbits-1) or log10(2**8)*(nbits-1)/8.  So,
     * 2.4... is log10(256), rounded up.  Add one to handle leading
     * minus, and one more to force int cast to round the value up.
     * This doesn't include room for a trailing nul.
     *
     * This will break if bytes are more than 8 bits.
     */
#define MAX_CHARS_FOR_INT_TYPE(TYPE)	((int) (2 + 2.408241 * sizeof (TYPE)))
    char tmpbuf[MAX_CHARS_FOR_INT_TYPE(int) * 4 + 8];

    days = (int) (deltat / (24*3600L));
    dt = deltat % (24*3600L);
    hours = (int) (dt / 3600);
    dt %= 3600;
    minutes = (int) (dt / 60);
    seconds = (int) (dt % 60);

    memset (tmpbuf, 0, sizeof (tmpbuf));
    if (days == 0)
	sprintf(buffer, "%d:%02d:%02d", hours, minutes, seconds);
    else if (hours || minutes || seconds)
	sprintf(buffer, "%d %s %02d:%02d:%02d", days,
		(days > 1) ? "days" : "day",
		hours, minutes, seconds);
    else
	sprintf(buffer, "%d %s", days,
		(days > 1) ? "days" : "day");
    if (tmpbuf[sizeof(tmpbuf)-1] != 0)
	/* Something must be very wrong with my math above, or the
	   assumptions going into it...  */
	abort ();
    if (strlen (tmpbuf) > buflen)
	return ENOMEM;
    else
	strncpy (buffer, tmpbuf, buflen);
    return 0;
}
#endif /* SUNW_INC_DEAD_CODE */

#undef __P
#define __P(X) X

#if !defined (HAVE_STRFTIME) || !defined (HAVE_STRPTIME)
#undef _CurrentTimeLocale
#define _CurrentTimeLocale (&dummy_locale_info)

struct dummy_locale_info_t {
    char d_t_fmt[15];
    char t_fmt_ampm[12];
    char t_fmt[9];
    char d_fmt[9];
    char day[7][10];
    char abday[7][4];
    char mon[12][10];
    char abmon[12][4];
    char am_pm[2][3];
};
static const struct dummy_locale_info_t dummy_locale_info = {
    "%a %b %d %X %Y",		/* %c */
    "%I:%M:%S %p",		/* %r */
    "%H:%M:%S",			/* %X */
    "%m/%d/%y",			/* %x */
    { "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
      "Saturday" },
    { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" },
    { "January", "February", "March", "April", "May", "June",
      "July", "August", "September", "October", "November", "December" },
    { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" },
    { "AM", "PM" },
};
#undef  TM_YEAR_BASE
#define TM_YEAR_BASE 1900
#endif

#ifndef HAVE_STRFTIME
#undef  DAYSPERLYEAR
#define DAYSPERLYEAR 366
#undef  DAYSPERNYEAR
#define DAYSPERNYEAR 365
#undef  DAYSPERWEEK
#define DAYSPERWEEK 7
#undef  isleap
#define isleap(N)	((N % 4) == 0 && (N % 100 != 0 || N % 400 == 0))
#undef  tzname
#define tzname my_tzname
static const char *const tzname[2] = { 0, 0 };
#undef  tzset
#define tzset()

#include "strftime.c"
#endif

#ifndef HAVE_STRPTIME
#include "strptime.c"
#endif
