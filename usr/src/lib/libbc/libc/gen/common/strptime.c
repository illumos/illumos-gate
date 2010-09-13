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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if !defined(lint) && defined(SCCSIDS)
static  char *sccsid = "%Z%%M% %I%	%E% SMI";
#endif

#include <ctype.h>
#include <locale.h>
#include <time.h>

static char	*strmatch(/*char *cp, char *string*/);
static char	*yearmatch(/*char *cp, char *format, struct tm *tm,
    int *hadyearp*/);
static char	*cvtnum(/*char *cp, int *nump*/);
static char	*skipnws(/*char *format*/);

extern char *getlocale_time();
#define NULL	0

char *
strptime(buf, format, tm)
	char *buf;
	char *format;
	struct tm *tm;
{
	register char *cp, *p;
	register int c, ch;
	register int i;
	register struct dtconv *dtcp;
	int hadyear;

	(void) getlocale_time();
	dtcp = localdtconv();	/* get locale's strings */

	cp = buf;
	while ((c = *format++) != '\0') {
		if (c == '%') {
			switch (*format++) {

			case '%':	/* Percent sign */
				if (*cp++ != '%')
					return (NULL);
				break;

			case 'a':	/* Abbreviated weekday name */
			case 'A':	/* Weekday name */
				for (i = 0; i < 7; i++) {
					if ((p = strmatch(cp,
					      dtcp->weekday_names[i],
					      *format)) != NULL
					    || (p = strmatch(cp,
					      dtcp->abbrev_weekday_names[i],
					      *format)) != NULL)
						goto match_wday;
				}
				return (NULL);	/* no match */

			match_wday:
				tm->tm_wday = i;
				cp = p;
				break;

			case 'h':
			case 'b':	/* Abbreviated month name */
			case 'B':	/* Month name */
				for (i = 0; i < 12; i++) {
					if ((p = strmatch(cp,
					      dtcp->month_names[i],
					      *format)) != NULL
					    || (p = strmatch(cp,
					      dtcp->abbrev_month_names[i],
					      *format)) != NULL)
						goto match_month;
				}
				return (NULL);	/* no match */

			match_month:
				tm->tm_mon = i;
				cp = p;
				break;

			case 'c':	/* date and time representation */
				cp = strptime(cp, "%x %X", tm);
				if (cp == NULL)
					return (NULL);
				break;

			case 'C':	/* long date and time representation */
				cp = strptime(cp, dtcp->ldate_format, tm);
				if (cp == NULL)
					return (NULL);
				break;

			case 'd':	/* Day of month, with leading zero */
			case 'e':       /* Day of month without leading zero */
				cp = cvtnum(cp, &tm->tm_mday);
				if (cp == NULL)
					return (NULL);	/* no digits */
				if (tm->tm_mday > 31)
					return (NULL);
				if ((c = *cp) == '\0'
				    || isspace((unsigned char)c))
					format = skipnws(format);
				break;

			case 'D':	/* Shorthand for %m/%d/%y */
				cp = strptime(cp, "%m/%d/%y", tm);
				if (cp == NULL)
					return (NULL);
				break;

			case 'H':	/* Hour (24 hour version) */
			case 'k':	/* Hour (24 hour version) */
				cp = cvtnum(cp, &tm->tm_hour);
				if (cp == NULL)
					return (NULL);	/* no digits */
				if (tm->tm_hour > 23)
					return (NULL);
				if ((c = *cp) == '\0'
				    || isspace((unsigned char)c))
					format = skipnws(format);
				break;

			case 'I':	/* Hour (12 hour version) */
			case 'l':	/* Hour (12 hour version) */
				cp = cvtnum(cp, &tm->tm_hour);
				if (cp == NULL)
					return (NULL);	/* no digits */
				if (tm->tm_hour == 12)
					tm->tm_hour = 0;
				else if (tm->tm_hour > 11)
					return (NULL);
				if ((c = *cp) == '\0'
				    || isspace((unsigned char)c))
					format = skipnws(format);
				break;

			case 'j':	/* Julian date */
				cp = cvtnum(cp, &tm->tm_yday);
				if (cp == NULL)
					return (NULL);	/* no digits */
				if (tm->tm_yday > 365)
					return (NULL);
				break;

			case 'm':	/* Month number */
				cp = cvtnum(cp, &tm->tm_mon);
				if (cp == NULL)
					return (NULL);	/* no digits */
				tm->tm_mon--;
				if (tm->tm_mon < 0 || tm->tm_mon > 11)
					return (NULL);
				if ((c = *cp) == '\0'
				    || isspace((unsigned char)c))
					format = skipnws(format);
				break;

			case 'M':	/* Minute */
				/*
				 * This is optional; if we're at the end of the
				 * string, or the next character is white
				 * space, don't try to match it.
				 */
				if ((c = *cp) != '\0'
				    && !isspace((unsigned char)c)) {
					cp = cvtnum(cp, &tm->tm_min);
					if (cp == NULL)
						return (NULL);	/* no digits */
					if (tm->tm_min > 59)
						return (NULL);
				}
				if ((c = *cp) == '\0'
				    || isspace((unsigned char)c))
					format = skipnws(format);
				break;

			case 'p':	/* AM or PM */
				if ((p = strmatch(cp, dtcp->am_string,
				    *format)) != NULL) {
					/*
					 * AM.
					 */
					if (tm->tm_hour == 12)
						tm->tm_hour = 0;
					cp = p;
				} else if ((p = strmatch(cp, dtcp->pm_string,
				    *format)) != NULL) {
					/*
					 * PM.
					 */
					if (tm->tm_hour > 12)
						return (NULL); /* error */
					else if (tm->tm_hour != 12)
						tm->tm_hour += 12;
					cp = p;
				}
				break;

			case 'r':	/* Shorthand for %I:%M:%S AM or PM */
				cp = strptime(cp, "%I:%M:%S %p", tm);
				if (cp == NULL)
					return (NULL);
				break;

			case 'R':	/* Time as %H:%M */
				cp = strptime(cp, "%H:%M", tm);
				if (cp == NULL)
					return (NULL);
				break;

			case 'S':	/* Seconds */
				/*
				 * This is optional; if we're at the end of the
				 * string, or the next character is white
				 * space, don't try to match it.
				 */
				if ((c = *cp) != '\0'
				    && !isspace((unsigned char)c)) {
					cp = cvtnum(cp, &tm->tm_sec);
					if (cp == NULL)
						return (NULL);	/* no digits */
					if (tm->tm_sec > 59)
						return (NULL);
				}
				if ((c = *cp) == '\0'
				    || isspace((unsigned char)c))
					format = skipnws(format);
				break;

			case 'T':	/* Shorthand for %H:%M:%S */
				cp = strptime(cp, "%H:%M:%S", tm);
				if (cp == NULL)
					return (NULL);
				break;

			case 'x':	/* Localized date format */
				cp = strptime(cp, dtcp->sdate_format, tm);
				if (cp == NULL)
					return (NULL);
				break;

			case 'X':	/* Localized time format */
				cp = strptime(cp, dtcp->time_format, tm);
				if (cp == NULL)
					return (NULL);
				break;

			case 'y':	/* Year in the form yy */
				cp = yearmatch(cp, format, tm, &hadyear);
				if (cp == NULL)
					return (NULL);
				if (hadyear) {
					if (tm->tm_year < 69) 
						tm->tm_year += 100;
				}
				return (cp);	/* match is complete */

			case 'Y':	/* Year in the form ccyy */
				cp = yearmatch(cp, format, tm, &hadyear);
				if (cp == NULL)
					return (NULL);
				if (hadyear) {
					tm->tm_year -= 1900;
					if (tm->tm_year < 0)
						return (NULL);
				}
				return (cp);	/* match is complete */

			default:
				return (NULL);	/* unknown conversion */
			}
		} else {
			if (isspace((unsigned char)c)) {
				while ((ch = *cp++) != '\0'
				    && isspace((unsigned char)ch))
					;
				cp--;
			} else {
				if (*cp++ != c)
					return (NULL);
			}
		}
	}
	return (cp);
}

/*
 * Try to match the beginning of the string pointed to by "cp" with the string
 * pointed to by "string".  The match is independent of the case of either
 * string.
 *
 * "termc" is the next character in the format string following the one for
 * which this match is being done.  If the match succeeds, make sure the next
 * character after the match is either '\0', or that it would match "termc".
 *
 * If both matches succeed, return a pointer to the next character after the
 * first match.  Otherwise, return NULL.
 */
static char *
strmatch(cp, string, termc)
	register char *cp;
	register char *string;
	char termc;
{
	register unsigned char c, strc;

	/*
	 * Match the beginning portion of "cp" with "string".
	 */
	while ((strc = *string++) != '\0') {
		c = *cp++;
		if (isupper(c))
			c = tolower(c);
		if (isupper(strc))
			strc = tolower(strc);
		if (c != strc)
			return (NULL);
	}

	if ((c = *cp) != '\0') {
		if (isspace((unsigned char)termc)) {
			if (!isspace(c))
				return (NULL);
		} else {
			if (c != (unsigned char)termc)
				return (NULL);
		}
	}
	return (cp);
}

/*
 * Try to match a %y or %Y specification.
 * If it matches, try matching the rest of the format.  If it succeeds, just
 * return.  Otherwise, try backing the scan up, ignoring the %y/%Y and any
 * following non-white-space string.  If that succeeds, just return.  (This
 * permits a missing year to be detected if it's at the beginning of a date, as
 * well as if it's at the end of a date, so that formats such as "%Y/%m/%d" can
 * match "3/14" and default the year.)
 *
 * Set "*hadyearp" to indicate whether a year was specified or not.
 */
static char *
yearmatch(cp, format, tm, hadyearp)
	register char *cp;
	char *format;
	struct tm *tm;
	int *hadyearp;
{
	register int c;
	char *savecp;
	int saveyear;

	/*
	 * This is optional; if we're at the end of the
	 * string, or the next character is white
	 * space, don't try to match it.
	 */
	if ((c = *cp) != '\0' && !isspace((unsigned char)c)) {
		savecp = cp;
		saveyear = tm->tm_year;
		cp = cvtnum(cp, &tm->tm_year);
		if (cp == NULL)
			return (NULL);	/* no digits */
		if ((c = *cp) == '\0'
		    || isspace((unsigned char)c))
			format = skipnws(format);

		/*
		 * Year can also be optional if it's at
		 * the *beginning* of a date.  We check
		 * this by trying to parse the rest of
		 * the date here.  If we succeed, OK;
		 * otherwise, we skip over the %y and
		 * try again.
		 */
		cp = strptime(cp, format, tm);
		if (cp != NULL)
			*hadyearp = 1;
		else {
			*hadyearp = 0;
			cp = savecp;
			format = skipnws(format);
			tm->tm_year = saveyear;
			cp = strptime(cp, format, tm);
		}
	} else {
		*hadyearp = 0;
		if ((c = *cp) == '\0'
		    || isspace((unsigned char)c))
			format = skipnws(format);
		cp = strptime(cp, format, tm);
	}

	return (cp);
}

/*
 * Try to match a (decimal) number in the string pointed to by "cp".
 * If the match succeeds, store the result in the "int" pointed to by "nump"
 * and return a pointer to the character following the number in the string.
 * If it fails, return NULL.
 */
static char *
cvtnum(cp, nump)
	register char *cp;
	int *nump;
{
	register int c;
	register int i;

	c = (unsigned char)*cp++;
	if (!isdigit(c))
		return (NULL);	/* no digits */
	i = 0;
	do {
		i = i*10 + c - '0';
		c = (unsigned char)*cp++;
	} while (isdigit(c));
	*nump = i;
	return (cp - 1);
}

/*
 * If a format item (such as %H, hours) is followed by a non-white-space
 * character other than "%", and the part of the string that matched the format
 * item is followed by white space, the string of non-white-space,
 * non-format-item characters following that format item may be omitted.
 */
static char *
skipnws(format)
	register char *format;
{
	register char c;

	/*
	 * Skip over non-white-space, non-digit characters.  "%" is special.
	 */
	while ((c = *format) != '\0' && !isspace((unsigned char)c)) {
		if (c == '%') {
			/*
			 * This is a format item.  If it's %%, skip it as
			 * that's a non-white space, non-digit character.
			 */
			if (*(format + 1) == '%')
				format++;	/* skip % */
			else
				break;
		}
		format++;
	}

	return (format);
}
