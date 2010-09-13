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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if !defined(lint) && defined(SCCSIDS)
static char *sccsid = "%Z%%M% %I% %E% SMI"; /* from S5R3.1 cftime.c 1.9 */
#endif

/*LINTLIBRARY*/

#include <locale.h>
#include <time.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>

static char     *getstr(/*char *p, char **strp*/);
static char	*itoa();
extern int	stat();
extern char	*getenv();
extern char	*malloc();
extern 	int 	openlocale(/*char *category, int cat_id, char *locale, char *newlocale */);
extern void 	init_statics();

extern	struct	dtconv	*_dtconv;
extern	char	_locales[MAXLOCALE + 1][MAXLOCALENAME + 1];
extern	char	_my_time[];

char 	*dtconv_str = NULL;
char    *getlocale_time();

int
strftime(buf, maxsize, format, tm)
char	*buf, *format;
struct tm	*tm;
{
	register char	*cp, *p,  c;
	int		size;
	int		i, temp;
	register struct dtconv *dtcp;

	(void) getlocale_time();
	dtcp = localdtconv();	/* get locale's strings */

	/* Build date string by parsing format string */
	cp = buf;
	size = 0;
	while ((c = *format++) != '\0') {
		if (c == '%') {
			switch (*format++) {

			case '%':	/* Percent sign */
				if (++size >= maxsize)
					return (0);
				*cp++ = '%';
				break;

			case 'a':	/* Abbreviated weekday name */
				for (p = dtcp->abbrev_weekday_names[tm->tm_wday];
				    *p != '\0'; p++) {
					if (++size >= maxsize)
						return (0);
					*cp++ = *p;
				}
				break;

			case 'A':	/* Weekday name */
				for (p = dtcp->weekday_names[tm->tm_wday];
				    *p != '\0'; p++) {
					if (++size >= maxsize)
						return (0);
					*cp++ = *p;
				}
				break;

			case 'h':
			case 'b':	/* Abbreviated month name */
				for (p = dtcp->abbrev_month_names[tm->tm_mon];
				    *p != '\0'; p++) {
					if (++size >= maxsize)
						return (0);
					*cp++ = *p;
				}
				break;

			case 'B':	/* Month name */
				for (p = dtcp->month_names[tm->tm_mon];
				    *p != '\0'; p++) {
					if (++size >= maxsize)
						return (0);
					*cp++ = *p;
				}
				break;

			case 'c':	/* date and time representation */
				i = strftime(cp, maxsize - size, "%x %X", tm);
				if (i == 0)
					return (0);
				cp += i;
				size += i;
				break;

			case 'C':	/* long date and time representation */
				i = strftime(cp, maxsize - size, 
				    dtcp->ldate_format, tm);
				if (i == 0)
					return (0);
				cp += i;
				size += i;
				break;

			case 'd':	/* Day of month, with leading zero */
				if ((size += 2) >= maxsize)
					return (0);
				cp = itoa(tm->tm_mday, cp, 2);
				break;

			case 'D':	/* Shorthand for %m/%d/%y */
				i = strftime(cp, maxsize - size, "%m/%d/%y",
				    tm);
				if (i == 0)
					return (0);
				cp += i;
				size += i;
				break;

			case 'e':       /* Day of month without leading zero */
				if ((size += 2) >= maxsize)
					return (0);
				if (tm->tm_mday < 10) {
					*cp++ = ' ';
                                	cp = itoa(tm->tm_mday, cp, 1);
				} else
					cp = itoa(tm->tm_mday, cp, 2);
                                break;

			case 'H':	/* Hour (24 hour version) */
				if ((size += 2) >= maxsize)
					return (0);
				cp = itoa(tm->tm_hour, cp, 2);
				break;

			case 'I':	/* Hour (12 hour version) */
				if ((size += 2) >= maxsize)
					return (0);
				cp = itoa(tm->tm_hour > 12 ?
				    tm->tm_hour - 12 :
				    (tm->tm_hour == 0 ? 12 : tm->tm_hour),
				    cp, 2);
				break;

			case 'j':	/* Julian date */
				if ((size += 3) >= maxsize)
					return (0);
				cp = itoa(tm->tm_yday + 1, cp, 3);
				break;

			case 'k':	/* Hour (24 hour version) */
				if ((size += 2) >= maxsize)
					return (0);
				if (tm->tm_hour < 10) {
					*cp++ = ' ';
					cp = itoa(tm->tm_hour, cp, 1);
				} else
					cp = itoa(tm->tm_hour, cp, 2);
				break;

			case 'l':	/* Hour (12 hour version) */
				if ((size += 2) >= maxsize)
					return (0);
				temp = tm->tm_hour > 12 ?
				    tm->tm_hour - 12 :
				    (tm->tm_hour == 0 ? 12 : tm->tm_hour);
				if (temp < 10) {
					*cp++ = ' ';
					cp = itoa(temp, cp, 1);
				} else
					cp = itoa(temp, cp, 2);
				break;

			case 'm':	/* Month number */
				if ((size += 2) >= maxsize)
					return (0);
				cp = itoa(tm->tm_mon + 1, cp, 2);
				break;

			case 'M':	/* Minute */
				if ((size += 2) >= maxsize)
					return (0);
				cp = itoa(tm->tm_min, cp, 2);
				break;

			case 'n':	/* Newline */
				if (++size >= maxsize)
					return (0);
				*cp++ = '\n';
				break;

			case 'p':	/* AM or PM */
				if (tm->tm_hour >= 12) 
					p = dtcp->pm_string;
				else
					p = dtcp->am_string;
				for (; *p != '\0'; p++) {
					if (++size >= maxsize)
						return (0);
					*cp++ = *p;
				}
				break;

			case 'r':	/* Shorthand for %I:%M:%S AM or PM */
				i = strftime(cp, maxsize - size, "%I:%M:%S %p",
				    tm);
				if (i == 0)
					return (0);
				cp += i;
				size += i;
				break;

			case 'R':	/* Time as %H:%M */
				i = strftime(cp, maxsize - size, "%H:%M", tm);
				if (i == 0)
					return (0);
				cp += i;
				size += i;
				break;

			case 'S':	/* Seconds */
				if ((size += 2) >= maxsize)
					return (0);
				cp = itoa(tm->tm_sec, cp, 2);
				break;

			case 't':	/* Tab */
				if (++size >= maxsize)
					return (0);
				*cp++ = '\t';
				break;

			case 'T':	/* Shorthand for %H:%M:%S */
				i = strftime(cp, maxsize - size, "%H:%M:%S",
				    tm);
				if (i == 0)
					return (0);
				cp += i;
				size += i;
				break;

			case 'U':	/* Weekday number, taking Sunday as
					 * the first day of the week */
				if ((size += 2) >= maxsize)
					return (0);
				temp = tm->tm_yday - tm->tm_wday;
				if (temp >= -3 ) {
					i = (temp + 1) / 7 + 1;	/* +1 for - tm->tm_wday */
					if (temp % 7 >= 4)
						i++;
				} else
					i = 52;
				cp = itoa(i, cp, 2);
				break;

			case 'w':	/* Weekday number */
				if (++size >= maxsize)
					return (0);
				cp = itoa(tm->tm_wday, cp, 1);
				break;

			case 'W':	/* Week number of year, taking Monday as
					 * first day of week */
				if ((size += 2) >= maxsize)
					return (0);
				if (tm->tm_wday == 0)
					temp = tm->tm_yday - 6;
				else
					temp = tm->tm_yday - tm->tm_wday + 1;
				if (temp >= -3) {
					i = (temp + 1) / 7 + 1;	/* 1 for 
								   -tm->tm_wday */
					if (temp % 7 >= 4)
						i++;
				} else
					i = 52; /* less than 4 days in the first
						   week causes it to belong to
						   the tail of prev year */
				cp = itoa(i, cp, 2);
				break;

			case 'x':	/* Localized date format */
				i = strftime(cp, maxsize - size,
				    dtcp->sdate_format, tm);
				if (i == 0)
					return (0);
				cp += i;
				size += i;
				break;

			case 'X':	/* Localized time format */
				i = strftime(cp, maxsize - size,
				    dtcp->time_format, tm);
				if (i == 0)
					return (0);
				cp += i;
				size += i;
				break;

			case 'y':	/* Year in the form yy */
				if ((size += 2) >= maxsize)
					return (0);
				cp = itoa((tm->tm_year% 100), cp, 2);
				break;

			case 'Y':	/* Year in the form ccyy */
				if ((size += 4) >= maxsize)
					return (0);
				cp = itoa(1900 + tm->tm_year, cp, 4);
				break;

			case 'Z':	/* Timezone */
				for(p = tm->tm_zone; *p != '\0'; p++) {
					if (++size >= maxsize)
						return (0);
					*cp++ = *p;
				}
				break;

			default:
				if ((size += 2) >= maxsize)
					return (0);
				*cp++ = c;
				*cp++ = *(format - 1);
				break;
			}
		} else {
			if (++size >= maxsize)
				return (0);
		 	*cp++ = c;
		}
	}
	*cp = '\0';
	return(size);
}

static char *
itoa(i, ptr, dig)
register int	i;
register char	*ptr;
register int	dig;
{
	switch(dig) {
	case 4:
		*ptr++ = i / 1000 + '0';
		i = i - i / 1000 * 1000;
	case 3:
		*ptr++ = i / 100 + '0';
		i = i - i / 100 * 100;
	case 2:
		*ptr++ = i / 10 + '0';
	case 1:
		*ptr++ = i % 10 + '0';
	}

	return(ptr);
}

char *
getlocale_time()
{
	register int fd;
	struct stat buf;
	char *str;
	register char *p;
	register int i;
	struct dtconv dtconvp;
	char temp[MAXLOCALENAME + 1];
	
	if (_locales[0][0] == '\0') 
		init_statics();

	/* Here we use the string newlocales to set time constants 
	 * which should have been saved 
	 * from a previous call to setlocale. We deferred the read until now
	 */

	if (strcmp(_my_time, _locales[LC_TIME -1]) == 0) {
		if (dtconv_str == NULL) {
                        /*
                         *  Below is executed if getlocale_time()
                         * is called when LC_TIME locale is initial
                         * C locale.
                         */
                        strcpy(temp, "C");
                        /*
                         * Just to make openlocale() to read LC_TIME file.
                         */
                        strcat(_locales[LC_TIME-1], temp);
                        goto initial;
                }
		return dtconv_str;
	}
	strcpy(temp, _locales[LC_TIME - 1]);
	strcpy(_locales[LC_TIME - 1], _my_time);
initial:
	if ((fd = openlocale("LC_TIME", LC_TIME, temp, _locales[LC_TIME - 1])) < 0)
		return (NULL);
	strcpy(_my_time, _locales[LC_TIME - 1]);
	if (fd == 0)
		return dtconv_str;
	if ((fstat(fd, &buf)) != 0)
		return (NULL);
	if ((str = malloc((unsigned)buf.st_size + 2)) == NULL) {
		close(fd);
		return (NULL);
	}

	if ((read(fd, str, (int)buf.st_size)) != buf.st_size) {
		close(fd);
		free(str);
		return (NULL);
	}

	/* Set last character of str to '\0' */
	p = &str[buf.st_size];
	*p++ = '\n';
	*p = '\0';

	/* p will "walk thru" str */
	p = str;  	

	for (i = 0; i < 12; i++) {
		p = getstr(p, &dtconvp.abbrev_month_names[i]);
		if (p == NULL)
			goto fail;
	}
	for (i = 0; i < 12; i++) {
		p = getstr(p, &dtconvp.month_names[i]);
		if (p == NULL)
			goto fail;
	}
	for (i = 0; i < 7; i++) {
		p = getstr(p, &dtconvp.abbrev_weekday_names[i]);
		if (p == NULL)
			goto fail;
	}
	for (i = 0; i < 7; i++) {
		p = getstr(p, &dtconvp.weekday_names[i]);
		if (p == NULL)
			goto fail;
	}
	p = getstr(p, &dtconvp.time_format);
	if (p == NULL)
		goto fail;
	p = getstr(p, &dtconvp.sdate_format);
	if (p == NULL)
		goto fail;
	p = getstr(p, &dtconvp.dtime_format);
	if (p == NULL)
		goto fail;
	p = getstr(p, &dtconvp.am_string);
	if (p == NULL)
		goto fail;
	p = getstr(p, &dtconvp.pm_string);
	if (p == NULL)
		goto fail;
	p = getstr(p, &dtconvp.ldate_format);
	if (p == NULL)
		goto fail;
	(void) close(fd);

	/*
	 * set info.
	 */
	if (dtconv_str != NULL)
		free(dtconv_str);

	dtconv_str = str;

	/* The following is to get space malloc'd for _dtconv */

	if (_dtconv == 0)
		(void) localdtconv();
	memcpy(_dtconv, &dtconvp, sizeof(struct dtconv));
	return (dtconv_str);

fail:
	(void) close(fd);
	free(str);
	return (NULL);
}


static char *
getstr(p, strp)
        register char *p;
        char **strp;
{
        *strp = p;
        p = strchr(p, '\n');
        if (p == NULL)
                return (NULL);  /* no end-of-line */
        *p++ = '\0';
        return (p);
}
