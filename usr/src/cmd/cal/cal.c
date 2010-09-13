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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <langinfo.h>
#include <locale.h>
#include <nl_types.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static int number(char *);
static int jan1(const int);
static void badmonth(void);
static void badyear(void);
static void usage(void);
static void cal(const int, const int, char *, const int);
static void load_months(void);
static void pstr(char *, const int);

#define	DAYW	" S  M Tu  W Th  F  S"
#define	TITLE	"   %s %u\n"
#define	YEAR	"\n\n\n\t\t\t\t%u\n\n"
#define	MONTH	"\t%4.3s\t\t\t%.3s\t\t%10.3s\n"

static char *months[] = {
	"January", "February", "March", "April",
	"May", "June", "July", "August",
	"September", "October", "November", "December",
};

static char *short_months[] = {
	"Jan", "Feb", "Mar", "Apr",
	"May", "Jun", "Jul", "Aug",
	"Sep", "Oct", "Nov", "Dec",
};

static char mon[] = {
	0,
	31, 29, 31, 30,
	31, 30, 31, 31,
	30, 31, 30, 31,
};

static char *myname;
static char string[432];
static struct tm *thetime;
static time_t timbuf;

int
main(int argc, char *argv[])
{
	int y, i, j;
	int m;
	char *time_locale;
	char	*ldayw;

	myname = argv[0];

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);


	while (getopt(argc, argv, "") != EOF)
		usage();

	argc -= optind;
	argv  = &argv[optind];

	time_locale = setlocale(LC_TIME, NULL);
	if ((time_locale[0] != 'C') || (time_locale[1] != '\0'))
		load_months();

	/*
	 * TRANSLATION_NOTE
	 * This message is to be used for displaying
	 * the names of the seven days, from Sunday to Saturday.
	 * The length of the name of each one should be two or less.
	 */
	ldayw = dcgettext(NULL, DAYW, LC_TIME);

	switch (argc) {
	case 0:
		timbuf = time(&timbuf);
		thetime = localtime(&timbuf);
		m = thetime->tm_mon + 1;
		y = thetime->tm_year + 1900;
		break;
	case 1:
		goto xlong;
	case 2:
		m = number(argv[0]);
		y = number(argv[1]);
		break;
	default:
		usage();
	}

/*
 *	print out just month
 */

	if (m < 1 || m > 12)
		badmonth();
	if (y < 1 || y > 9999)
		badyear();
	/*
	 * TRANSLATION_NOTE
	 * This message is to be used for displaying
	 * specified month and year.
	 */
	(void) printf(dcgettext(NULL, TITLE, LC_TIME), months[m-1], y);
	(void) printf("%s\n", ldayw);
	cal(m, y, string, 24);
	for (i = 0; i < 6*24; i += 24)
		pstr(string+i, 24);
	return (0);

/*
 *	print out complete year
 */

xlong:
	y = number(argv[0]);
	if (y < 1 || y > 9999)
		badyear();
	/*
	 * TRANSLATION_NOTE
	 * This message is to be used for displaying
	 * specified year.
	 */
	(void) printf(dcgettext(NULL, YEAR, LC_TIME), y);
	for (i = 0; i < 12; i += 3) {
		for (j = 0; j < 6*72; j++)
			string[j] = '\0';
		/*
		 * TRANSLATION_NOTE
		 * This message is to be used for displaying
		 * names of three months per a line and should be
		 * correctly translated according to the display width
		 * of the names of months.
		 */
		(void) printf(
			dcgettext(NULL, MONTH, LC_TIME),
			short_months[i], short_months[i+1], short_months[i+2]);
		(void) printf("%s   %s   %s\n", ldayw, ldayw, ldayw);
		cal(i+1, y, string, 72);
		cal(i+2, y, string+23, 72);
		cal(i+3, y, string+46, 72);
		for (j = 0; j < 6*72; j += 72)
			pstr(string+j, 72);
	}
	(void) printf("\n\n\n");
	return (0);
}

static int
number(char *str)
{
	int n, c;
	char *s;

	n = 0;
	s = str;
	/*LINTED*/
	while (c = *s++) {
		if (c < '0' || c > '9')
			return (0);
		n = n*10 + c-'0';
	}
	return (n);
}

static void
pstr(char *str, const int n)
{
	int i;
	char *s;

	s = str;
	i = n;
	while (i--)
		if (*s++ == '\0')
			s[-1] = ' ';
	i = n+1;
	while (i--)
		if (*--s != ' ')
			break;
	s[1] = '\0';
	(void) printf("%s\n", str);
}

static void
cal(const int m, const int y, char *p, const int w)
{
	int d, i;
	char *s;

	s = (char *)p;
	d = jan1(y);
	mon[2] = 29;
	mon[9] = 30;

	switch ((jan1(y+1)+7-d)%7) {

	/*
	 *	non-leap year
	 */
	case 1:
		mon[2] = 28;
		break;

	/*
	 *	1752
	 */
	default:
		mon[9] = 19;
		break;

	/*
	 *	leap year
	 */
	case 2:
		;
	}
	for (i = 1; i < m; i++)
		d += mon[i];
	d %= 7;
	s += 3*d;
	for (i = 1; i <= mon[m]; i++) {
		if (i == 3 && mon[m] == 19) {
			i += 11;
			mon[m] += 11;
		}
		if (i > 9)
			*s = i/10+'0';
		s++;
		*s++ = i%10+'0';
		s++;
		if (++d == 7) {
			d = 0;
			s = p+w;
			p = s;
		}
	}
}

/*
 *	return day of the week
 *	of jan 1 of given year
 */

static int
jan1(const int yr)
{
	int y, d;

/*
 *	normal gregorian calendar
 *	one extra day per four years
 */

	y = yr;
	d = 4+y+(y+3)/4;

/*
 *	julian calendar
 *	regular gregorian
 *	less three days per 400
 */

	if (y > 1800) {
		d -= (y-1701)/100;
		d += (y-1601)/400;
	}

/*
 *	great calendar changeover instant
 */

	if (y > 1752)
		d += 3;

	return (d%7);
}

static void
load_months(void)
{
	int month;

	for (month = MON_1; month <= MON_12; month++)
		months[month - MON_1] = nl_langinfo(month);
	for (month = ABMON_1; month <= ABMON_12; month++)
		short_months[month - ABMON_1] = nl_langinfo(month);
}

static void
badmonth()
{
	(void) fprintf(stderr, gettext("%s: bad month\n"), myname);
	usage();
}

static void
badyear()
{
	(void) fprintf(stderr, gettext("%s: bad year\n"), myname);
	usage();
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext("usage: %s [ [month] year ]\n"), myname);
	exit(1);
}
