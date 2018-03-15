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
 * Copyright 2018 Gary Mills
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysi86.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <sys/stat.h>

/* RTC modes */
#define	M_UNSET	0 /* Mode never set */
#define	M_VAR	1 /* Tracks local time including DST */
#define	M_UTC	2 /* Clock runs in UTC */
#define	M_STD	3 /* Clock runs in local standard time */

static char *progname;
static char *zonefile = "/etc/rtc_config";
static FILE *zonefptr;
static char zone_info[256];
static char zone_lag[256];
static char tz[256] = "TZ=";
static char *utc_zone = "UTC";
int debug = 0;
int rtc_mode = M_UNSET;
int lag;
int errors_ok = 0; /* allow "rtc no-args" to be quiet when not configured */
static time_t clock_val;
static char zone_comment[] =
	"#\n"
	"#	This file (%s) contains information used to manage the\n"
	"#	x86 real time clock hardware.  The hardware is kept in\n"
	"#	the machine's local time for compatibility with other x86\n"
	"#	operating systems.  This file is read by the kernel at\n"
	"#	boot time.  It is set and updated by the /usr/sbin/rtc\n"
	"#	command.  The 'zone_info' field designates the local\n"
	"#	time zone.  The 'zone_lag' field indicates the number\n"
	"#	of seconds between local time and Greenwich Mean Time.\n"
	"#\n";

/*
 *	Open the configuration file and extract the
 *	zone_info and the zone_lag.  Return 0 if successful.
 */
int
open_zonefile()
{
	char b[256], *s;
	int lag_hrs;

	if ((zonefptr = fopen(zonefile, "r")) == NULL) {
		if (errors_ok == 0)
			(void) fprintf(stderr,
			    "%s: cannot open %s: errno = %d\n",
			    progname, zonefile, errno);
		return (1);
	}

	for (;;) {
		if ((s = fgets(b, sizeof (b), zonefptr)) == NULL)
			break;
		if ((s = strchr(s, 'z')) == NULL)
			continue;
		if (strncmp(s, "zone_info", 9) == 0) {
			s += 9;
			while (*s != 0 && *s != '=')
				s++;
			if (*s == '=') {
				s++;
				while (*s != 0 && (*s == ' ' || *s == '\t'))
					s++;
				(void) strncpy(zone_info, s,
				    sizeof (zone_info));
				s = zone_info;
				while (*s != 0 && *s != '\n')
					s++;
				if (*s == '\n')
					*s = 0;
			}
		} else if (strncmp(s, "zone_lag", 8) == 0) {
			s += 8;
			while (*s != 0 && *s != '=')
				s++;
			if (*s == '=') {
				s++;
				while (*s != 0 && (*s == ' ' || *s == '\t'))
					s++;
				(void) strncpy(zone_lag, s, sizeof (zone_lag));
				s = zone_lag;
				while (*s != 0 && *s != '\n')
					s++;
				if (*s == '\n')
					*s = 0;
			}
		}
	}
	lag = atoi(zone_lag);
	lag_hrs = lag / 3600;
	if (zone_info[0] == 0) {
		(void) fprintf(stderr, "%s: zone_info field is invalid\n",
		    progname);
		zone_info[0] = 0;
		zone_lag[0] = 0;
		return (1);
	}
	if (zone_lag[0] == 0) {
		(void) fprintf(stderr, "%s: zone_lag field is invalid\n",
		    progname);
		zone_lag[0] = 0;
		return (1);
	}
	if ((lag_hrs < -24) || (lag_hrs > 24)) {
		(void) fprintf(stderr, "%s: a GMT lag of %d is out of range\n",
		    progname, lag_hrs);
		zone_info[0] = 0;
		zone_lag[0] = 0;
		return (1);
	}
	if (debug)
		(void) fprintf(stderr, "zone_info = %s,   zone_lag = %s\n",
		    zone_info, zone_lag);
	if (debug)
		(void) fprintf(stderr, "lag (decimal) is %d\n", lag);

	(void) fclose(zonefptr);
	zonefptr = NULL;
	return (0);
}

void
display_zone_string(void)
{
	if (open_zonefile() == 0)
		(void) printf("%s\n", zone_info);
	else
		(void) printf("GMT\n");
}

int
get_local(char *z)
{
	struct tm *tm;

	tz[3] = 0;
	(void) strncat(tz, z, 253);
	if (debug)
		(void) fprintf(stderr, "Time Zone string is '%s'\n", tz);

	(void) putenv(tz);
	if (debug)
		(void) system("env | grep TZ");

	(void) time(&clock_val);

	tm = localtime(&clock_val);
	return (tm->tm_isdst);
}

long
set_zone(char *zone_string)
{
	int isdst;
	long current_lag;

	(void) umask(0022);
	if ((zonefptr = fopen(zonefile, "w")) == NULL) {
		(void) fprintf(stderr, "%s: cannot open %s: errno = %d\n",
		    progname, zonefile, errno);
		return (0);
	}

	switch (rtc_mode) {
	case M_VAR:
		isdst = get_local(zone_string);
		current_lag = isdst ? altzone : timezone;
		break;
	case M_STD:
		isdst = get_local(zone_string);
		current_lag = timezone;
		break;
	default:	/* Includes M_UTC */
		isdst = 0;
		current_lag = 0;
		zone_string = utc_zone;
		break;
	}
	if (debug)
		(void) printf("%s DST.    Lag is %ld.\n", isdst ? "Is" :
		    "Is NOT",  current_lag);

	(void) fprintf(zonefptr, zone_comment, zonefile);
	(void) fprintf(zonefptr, "zone_info=%s\n", zone_string);
	(void) fprintf(zonefptr, "zone_lag=%ld\n", current_lag);
	(void) fclose(zonefptr);
	zonefptr = NULL;
	return (current_lag);
}

void
correct_rtc_and_lag()
{
	int isdst;
	long kernels_lag;
	long current_lag;

	if (open_zonefile())
		return;

	switch (rtc_mode) {
	case M_VAR:
		isdst = get_local(zone_info);
		current_lag = isdst ? altzone : timezone;
		break;
	case M_STD:
		(void) get_local(zone_info);
		current_lag = timezone;
		break;
	default:	/* Includes M_UTC */
		current_lag = 0;
		break;
	}

	if (current_lag != lag) {	/* if file is wrong */
		if (debug)
			(void) fprintf(stderr, "correcting file\n");
		(void) set_zone(zone_info);	/* then rewrite file */
	}

	(void) sysi86(GGMTL, &kernels_lag);
	if (current_lag != kernels_lag) {
		if (debug)
			(void) fprintf(stderr, "correcting kernel's lag\n");
		(void) sysi86(SGMTL, current_lag);	/* correct the lag */
		(void) sysi86(WTODC);			/* set the rtc to */
							/* new local time */
	}
}

void
initialize_zone(char *zone_string)
{
	long current_lag;

	/* write the config file */
	current_lag = set_zone(zone_string);

	/* correct the lag */
	(void) sysi86(SGMTL, current_lag);

	/*
	 * set the unix time from the rtc,
	 * assuming the rtc was the correct
	 * local time.
	 */
	(void) sysi86(RTCSYNC);
}

void
usage()
{
	static char Usage[] = "Usage:\n\
rtc [-w] [-s|-u|-v] [-c] [-z time_zone] [-?]\n";

	(void) fprintf(stderr, Usage);
}

void
verbose_usage()
{
	static char Usage1[] = "\
	Options:\n\
	    -w\t\tDoes nothing.\n\
	    -s\t\tRTC runs in local standard time.\n\
	    -u\t\tRTC runs in UTC time.\n\
	    -v\t\tRTC tracks local time (with cron command).\n\
	    -c\t\tCheck and correct for daylight savings time rollover.\n\
	    -z [zone]\tRecord the zone info in the config file.\n";

	(void) fprintf(stderr, Usage1);
}

void
set_default()
{
	switch (rtc_mode) {
	default:	/* Includes M_UNSET */
		rtc_mode = M_VAR;
		break;
	case M_VAR:
		/*FALLTHROUGH*/
	case M_UTC:
		/*FALLTHROUGH*/
	case M_STD:
		break;
	}
}

void
check_mode(int letter, int mode)
{
	if (rtc_mode == M_UNSET || rtc_mode == mode) {
		rtc_mode = mode;
		return;
	}
	(void) fprintf(stderr, "%s: option -%c conflicts with other options\n",
	    progname, letter);
	exit(1);
}


int
main(int argc, char *argv[])
{
	int c;
	int cflg = 0;
	char *zone_name = NULL;

	progname = argv[0];

	if (argc == 1) {
		errors_ok = 1;
		display_zone_string();
		exit(0);
	}

	while ((c = getopt(argc, argv, "suvwcz:d")) != EOF) {
		switch (c) {
		case 'c':
			cflg++;
			continue;
		case 'z':
			zone_name = optarg;
			continue;
		case 'd':
			debug = 1;
			continue;
		case 's':	/* standard: RTC runs local standard time */
			check_mode(c, M_STD);
			continue;
		case 'u':	/* utc: RTC runs UTC time */
			check_mode(c, M_UTC);
			continue;
		case 'v':	/* varies: RTC tracks local time */
			check_mode(c, M_VAR);
			continue;
		case 'w':	/* Does nothing */
			continue;
		case '?':
			verbose_usage();
			exit(0);
		default:
			usage();
			exit(1);
		}
	}
	set_default();
	if (zone_name != NULL)
		initialize_zone(zone_name);
	if (cflg > 0)
		correct_rtc_and_lag();
	exit(0);
	/*LINTED*/
}
