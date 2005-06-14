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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Display synchronous serial line statistics
 */

#include <sys/types.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <fcntl.h>
#include <sys/ser_sync.h>
#include <libdlpi.h>

#define	MAXWAIT 15

static struct scc_mode sm;
static struct sl_stats st;

static void usage(void);
static void sample(int count, int period);

/*
 * errstr is MAXPATHLEN + 11; 11 = 10 for "syncstat: " + null
 */
static char errstr[11 + MAXPATHLEN] = "syncstat: /dev/";
static char *ifdevice = errstr + 10;
static char *ifname = errstr + 15;
static int fd;

int
main(int argc, char **argv)
{
	int len;
	char *cp;
	int do_clear = 0;
	int period = 0;
	int isize, osize;
	int count;
	struct strioctl sioc;
	ulong_t ppa;

	if (argc == 1) {
		usage();
		exit(1);
	}
	argc--;				/* skip the command name */
	argv++;

	/*
	 * The following loop processes command line arguments.
	 * If the argument begins with a '-', it is trated as an option.
	 * The only option currently implemented is "-c" (clears statistics).
	 * If the argument begins with a numeral, it is treated as an interval.
	 * Intervals must be positive integers greater than zero.
	 * Any argument that survives this is treated as a device name to be
	 * found under /dev.
	 */
	while (argc > 0) {
		if (argv[0][0] == '-') {
			if (argc == 1) {
				usage();
				exit(1);
			}
			if (argv[0][1] != 'c') {
				usage();
				exit(1);
			}
			do_clear = 1;
		} else if ((argv[0][0] >= '0') && (argv[0][0] <= '9')) {
			period = atoi(*argv);
			if (period == 0) {
				(void) fprintf(stderr,
					"syncstat: bad interval: %s\n", *argv);
				exit(1);
			}
		} else {
			len = sizeof (errstr) - strlen(errstr);
			if (snprintf(ifname, len, "%s", *argv) >= len) {
				(void) fprintf(stderr,
				    "syncstat: invalid device name "
				    "(too long) %s\n", *argv);
				    exit(1);
			}
		}
		argc--;
		argv++;
	}

	for (cp = ifname; (*cp) && (!isdigit(*cp)); cp++) {}
	if (*cp == '\0') {	/* hit the end without finding a number */
		(void) fprintf(stderr,
			"syncstat: %s missing minor device number\n", ifname);
		exit(1);
	}
	ppa = strtoul(cp, NULL, 10);
	*cp = '\0';	/* drop number, leaving name of clone device. */
	fd = open(ifdevice, O_RDWR);
	if (fd < 0) {
		perror(errstr);
		exit(1);
	}

	if (dlpi_attach(fd, MAXWAIT, ppa) != 0) {
		perror("syncstat: dlpi_attach");
		exit(1);
	}

	(void) printf("syncstat: control device: %s, ppa=%ld\n", ifdevice, ppa);

	sioc.ic_cmd = S_IOCGETMODE;
	sioc.ic_timout = -1;
	sioc.ic_len = sizeof (struct scc_mode);
	sioc.ic_dp = (char *)&sm;
	if (ioctl(fd, I_STR, &sioc) < 0) {
		perror("S_IOCGETMODE");
		(void) fprintf(stderr,
			"syncstat: can't get sync mode info for %s\n",
			ifname);
		exit(1);
	}
	if (do_clear) {
		sioc.ic_cmd = S_IOCCLRSTATS;
		sioc.ic_timout = -1;
		sioc.ic_len = sizeof (struct sl_stats);
		sioc.ic_dp = (char *)&st;
		if (ioctl(fd, I_STR, &sioc) < 0) {
			perror("S_IOCCLRSTATS");
			(void) fprintf(stderr,
				"syncstat: can't clear stats for %s\n",
				ifname);
			exit(1);
		}
	}

	sioc.ic_cmd = S_IOCGETSTATS;
	sioc.ic_timout = -1;
	sioc.ic_len = sizeof (struct sl_stats);
	sioc.ic_dp = (char *)&st;
	if (ioctl(fd, I_STR, &sioc) < 0) {
		perror("S_IOCGETSTATS");
		(void) fprintf(stderr, "syncstat: can't get stats for %s\n",
			ifname);
		exit(1);
	}
	if (period) {
		if (sm.sm_baudrate == 0) {
			(void) fprintf(stderr, "syncstat: baud rate not set\n");
			exit(1);
		}
		for (count = 0; ; count++) {
			(void) fflush(stdout);
			(void) sleep(period);
			sample(count, period);
		}
	}
	isize = osize = 0;
	if (st.opack)
		osize = st.ochar / st.opack;
	if (st.ipack)
		isize = st.ichar / st.ipack;
	(void) printf(
"    speed   ipkts   opkts  undrun  ovrrun   abort     crc   isize   osize\n");
	(void) printf(" %7d %7d %7d %7d %7d %7d %7d %7d %7d\n",
		sm.sm_baudrate,
		st.ipack,
		st.opack,
		st.underrun,
		st.overrun,
		st.abort,
		st.crc,
		isize, osize);
	return (0);
}

static void
sample(int count, int period)
{
	struct sl_stats nst;
	struct strioctl sioc;
	int iutil, outil;

	sioc.ic_cmd = S_IOCGETSTATS;
	sioc.ic_timout = -1;
	sioc.ic_len = sizeof (struct sl_stats);
	sioc.ic_dp = (char *)&nst;
	if (ioctl(fd, I_STR, &sioc) < 0) {
		perror("S_IOCGETSTATS");
		(void) fprintf(stderr, "syncstat: can't get stats for %s\n",
			ifname);
		exit(1);
	}

	st.ipack = nst.ipack - st.ipack;
	st.opack = nst.opack - st.opack;
	st.ichar = nst.ichar - st.ichar;
	st.ochar = nst.ochar - st.ochar;
	st.crc = nst.crc - st.crc;
	st.overrun = nst.overrun - st.overrun;
	st.underrun = nst.underrun - st.underrun;
	st.abort = nst.abort - st.abort;
	iutil = 8 * st.ichar / period;
	iutil = 100 * iutil / sm.sm_baudrate;
	outil = 8 * st.ochar / period;
	outil = 100 * outil / sm.sm_baudrate;
	if ((count % 20) == 0) (void) printf(
"    ipkts   opkts  undrun  ovrrun   abort     crc   iutil   outil\n");
	(void) printf(" %7d %7d %7d %7d %7d %7d %6d%% %6d%%\n",
		st.ipack,
		st.opack,
		st.underrun,
		st.overrun,
		st.abort,
		st.crc,
		iutil, outil);

	st = nst;
}

static void
usage()
{
	(void) fprintf(stderr, "%s\n",
		"Usage: syncstat [-c] device [period]");
}
