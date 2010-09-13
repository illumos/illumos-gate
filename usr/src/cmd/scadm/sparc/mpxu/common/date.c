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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * date.c: support for the scadm date option (change/display service
 * processor date)
 */

#include <libintl.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <langinfo.h>
#include <time.h>  /* required by rsc.h */

#include "librsc.h"
#include "adm.h"

static void ADM_Get_Date();
static void ADM_Set_Date(int argc, char *argv[]);
static int ADM_Decode_Date(char *String, dp_set_date_time_t *Date);
static int ADM_twodigits(char *s);
static void usage();

extern int cftime(char *, char *, const time_t *);

void
ADM_Process_date(int argc, char *argv[])
{
	static dp_set_date_time_t	DateTime;
	static char			date[40];
	time_t				currentTime;
	int				largc;
	char				*largv[3];

	if ((argc != 2) && (argc != 3)) {
		usage();
		exit(-1);
	}

	if (argc == 3) {
		if (strcasecmp(argv[2], "-s") != 0) {
			if (ADM_Decode_Date(argv[2], &DateTime) != 0) {
				usage();
				exit(-1);
			}
		}
	}

	ADM_Start();

	if (argc == 2) {
		ADM_Get_Date();
	} else if (argc == 3) {
		if (strcasecmp(argv[2], "-s") == 0) {
			currentTime = time(NULL);
			(void) cftime(date, "%m""%d""%H""%M""%Y", &currentTime);
			largc = 3;
			largv[0] = argv[0];
			largv[1] = argv[1];
			largv[2] = date;
			ADM_Set_Date(largc, largv);
		} else {
			ADM_Set_Date(argc, argv);
		}
	}
}


static void
ADM_Get_Date()
{
	rscp_msg_t		Message;
	struct timespec		Timeout;
	dp_get_date_time_r_t	*dateInfo;
	struct tm		*tp;
	char			buf[64];

	Message.type = DP_GET_DATE_TIME;
	Message.len  = 0;
	Message.data = NULL;

	ADM_Send(&Message);

	Timeout.tv_nsec = 0;
	Timeout.tv_sec  = ADM_TIMEOUT;
	ADM_Recv(&Message, &Timeout,
	    DP_GET_DATE_TIME_R, sizeof (dp_get_date_time_r_t));

	if (*(int *)Message.data != 0) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: could not read date from SC"));
		exit(-1);
	}

	dateInfo = (dp_get_date_time_r_t *)Message.data;

	/* Print the date */
	(void) setlocale(LC_ALL, "");
	tp = gmtime((time_t *)&dateInfo->current_datetime);
	(void) strftime(buf, 64, nl_langinfo(D_T_FMT), tp);
	(void) printf("%s\n", buf);

	ADM_Free(&Message);
}


static void
ADM_Set_Date(int argc, char *argv[])
{
	static dp_set_date_time_t	specTime;
	rscp_msg_t			Message;
	struct timespec			Timeout;

	if (argc < 3) {
		/* should have caught this earlier */
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: arguments error in set date"));
		exit(-1);
	}

	if (ADM_Decode_Date(argv[2], &specTime) != 0) {
		/* should have caught this earlier */
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: INTERNAL ERROR in set date"));
		exit(-1);
	}

	/* Correct month to be 0 - 11.  Why does firmware want this? */
	/* Correct year to be offset from 1900.  Why does firmware want this? */
	if (specTime.month != DP_SET_DATE_TIME_IGNORE_FIELD)
		specTime.month = specTime.month - 1;
	if (specTime.year != DP_SET_DATE_TIME_IGNORE_FIELD)
		specTime.year  = specTime.year  - 1900;

	Message.type = DP_SET_DATE_TIME;
	Message.len  = sizeof (dp_set_date_time_t);
	Message.data = &specTime;
	ADM_Send(&Message);

	Timeout.tv_nsec = 0;
	Timeout.tv_sec  = ADM_TIMEOUT;
	ADM_Recv(&Message, &Timeout,
	    DP_SET_DATE_TIME_R, sizeof (dp_set_date_time_r_t));

	if (*(int *)Message.data != 0) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: could not set date on SC"));
		exit(-1);
	}

	ADM_Free(&Message);
}


static int
ADM_twodigits(char *s)
{
	int n;

	n = ((s[0] - '0') * 10) + (s[1] - '0');
	return (n);
}


static int
ADM_Decode_Date(char *String, dp_set_date_time_t *Date)
{
	int		localDate;


	if (strlen(String) == 4) {

		/* HHMM */
		Date->month	= DP_SET_DATE_TIME_IGNORE_FIELD;
		Date->day	= DP_SET_DATE_TIME_IGNORE_FIELD;
		Date->hour	= ADM_twodigits(&String[0]);
		Date->minute	= ADM_twodigits(&String[2]);
		Date->second	= DP_SET_DATE_TIME_IGNORE_FIELD;
		Date->year	= DP_SET_DATE_TIME_IGNORE_FIELD;
		if (((int)Date->hour < 0) || (Date->hour > 23))
			return (-1);
		if (((int)Date->minute < 0) || (Date->minute > 59))
			return (-1);

	} else if (strlen(String) == 7) {

		/* HHMM.SS */
		Date->month	= DP_SET_DATE_TIME_IGNORE_FIELD;
		Date->day	= DP_SET_DATE_TIME_IGNORE_FIELD;
		Date->hour	= ADM_twodigits(&String[0]);
		Date->minute	= ADM_twodigits(&String[2]);
		Date->second	= ADM_twodigits(&String[5]);
		Date->year	= DP_SET_DATE_TIME_IGNORE_FIELD;
		if (((int)Date->hour < 0) || (Date->hour > 23))
			return (-1);
		if (((int)Date->minute < 0) || (Date->minute > 59))
			return (-1);
		if (((int)Date->second < 0) || (Date->second > 59))
			return (-1);

	} else if (strlen(String) == 8) {

		/* mmddHHMM */
		Date->month	= ADM_twodigits(&String[0]);
		Date->day	= ADM_twodigits(&String[2]);
		Date->hour	= ADM_twodigits(&String[4]);
		Date->minute	= ADM_twodigits(&String[6]);
		Date->second	= DP_SET_DATE_TIME_IGNORE_FIELD;
		Date->year	= DP_SET_DATE_TIME_IGNORE_FIELD;
		if ((Date->month < 1) || (Date->month > 12))
			return (-1);
		if ((Date->day < 1) || (Date->day > 31))
			return (-1);
		if (((int)Date->hour < 0) || (Date->hour > 23))
			return (-1);
		if (((int)Date->minute < 0) || (Date->minute > 59))
			return (-1);

	} else if (strlen(String) == 11) {

		/* mmddHHMM.SS */
		Date->month  = ADM_twodigits(&String[0]);
		Date->day    = ADM_twodigits(&String[2]);
		Date->hour   = ADM_twodigits(&String[4]);
		Date->minute = ADM_twodigits(&String[6]);
		Date->second = ADM_twodigits(&String[9]);
		Date->year   = DP_SET_DATE_TIME_IGNORE_FIELD;
		if ((Date->month < 1) || (Date->month > 12))
			return (-1);
		if ((Date->day < 1) || (Date->day > 31))
			return (-1);
		if (((int)Date->hour < 0) || (Date->hour > 23))
			return (-1);
		if (((int)Date->minute < 0) || (Date->minute > 59))
			return (-1);
		if (((int)Date->second < 0) || (Date->second > 59))
			return (-1);

	} else if (strlen(String) == 10) {

		/* mmddHHMMyy */
		Date->month	= ADM_twodigits(&String[0]);
		Date->day	= ADM_twodigits(&String[2]);
		Date->hour	= ADM_twodigits(&String[4]);
		Date->minute	= ADM_twodigits(&String[6]);
		Date->second	= DP_SET_DATE_TIME_IGNORE_FIELD;
		localDate	= ADM_twodigits(&String[8]);
		if (localDate > 70)
			Date->year = localDate + 1900;
		else
			Date->year = localDate + 2000;

		if ((Date->month < 1) || (Date->month > 12))
			return (-1);
		if ((Date->day < 1) || (Date->day > 31))
			return (-1);
		if (((int)Date->hour < 0) || (Date->hour > 23))
			return (-1);
		if (((int)Date->minute < 0) || (Date->minute > 59))
			return (-1);
		if ((Date->year < 1970) || (Date->year > 2038))
			return (-1);

	} else if (strlen(String) == 13) {

		/* mmddHHMMyy.SS */
		Date->month	= ADM_twodigits(&String[0]);
		Date->day	= ADM_twodigits(&String[2]);
		Date->hour	= ADM_twodigits(&String[4]);
		Date->minute	= ADM_twodigits(&String[6]);
		Date->second	= ADM_twodigits(&String[11]);
		localDate	= ADM_twodigits(&String[8]);
		if (localDate > 70)
			Date->year = localDate + 1900;
		else
			Date->year = localDate + 2000;

		if ((Date->month < 1) || (Date->month > 12))
			return (-1);
		if ((Date->day < 1) || (Date->day > 31))
			return (-1);
		if (((int)Date->hour < 0) || (Date->hour > 23))
			return (-1);
		if (((int)Date->minute < 0) || (Date->minute > 59))
			return (-1);
		if ((Date->year < 1970) || (Date->year > 2038))
			return (-1);
		if (((int)Date->second < 0) || (Date->second > 59))
			return (-1);

	} else if (strlen(String) == 12) {

		/* mmddHHMMccyy */
		Date->month	= ADM_twodigits(&String[0]);
		Date->day	= ADM_twodigits(&String[2]);
		Date->hour	= ADM_twodigits(&String[4]);
		Date->minute	= ADM_twodigits(&String[6]);
		Date->second	= DP_SET_DATE_TIME_IGNORE_FIELD;
		Date->year	= (ADM_twodigits(&String[8]) * 100) +
		    ADM_twodigits(&String[10]);
		if ((Date->month < 1) || (Date->month > 12))
			return (-1);
		if ((Date->day < 1) || (Date->day > 31))
			return (-1);
		if (((int)Date->hour < 0) || (Date->hour > 23))
			return (-1);
		if (((int)Date->minute < 0) || (Date->minute > 59))
			return (-1);
		if ((Date->year < 1970) || (Date->year > 2038))
			return (-1);

	} else if (strlen(String) == 15) {

		/* mmddHHMMccyy.SS */
		Date->month  = ADM_twodigits(&String[0]);
		Date->day    = ADM_twodigits(&String[2]);
		Date->hour   = ADM_twodigits(&String[4]);
		Date->minute = ADM_twodigits(&String[6]);
		Date->second = ADM_twodigits(&String[13]);
		Date->year   = (ADM_twodigits(&String[8]) * 100) +
		    ADM_twodigits(&String[10]);
		if ((Date->month < 1) || (Date->month > 12))
			return (-1);
		if ((Date->day < 1) || (Date->day > 31))
			return (-1);
		if (((int)Date->hour < 0) || (Date->hour > 23))
			return (-1);
		if (((int)Date->minute < 0) || (Date->minute > 59))
			return (-1);
		if ((Date->year < 1970) || (Date->year > 2038))
			return (-1);
		if (((int)Date->second < 0) || (Date->second > 59))
			return (-1);

	} else {
		return (-1);
	}

	return (0);
}


static void
usage()
{
	(void) fprintf(stderr, "\n%s\n\n",
	    gettext("USAGE: scadm date [-s] "
	    "| [[mmdd]HHMM | mmddHHMM[cc]yy][.SS]\n"
	    "       1  <=  mm  <= 12\n"
	    "       1  <=  dd  <= 31\n"
	    "       1  <=  HH  <= 23\n"
	    "       0  <=  MM  <= 59\n"
	    "     1970 <= ccyy <= 2038\n"
	    "       0  <=  SS  <= 59"));
}
