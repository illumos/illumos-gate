/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Initialize and re-initialize synchronous serial clocking and loopback
 * options.  Interfaces through the S_IOCGETMODE and S_IOCSETMODE ioctls.
 */

#include <sys/types.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ser_sync.h>
#include <libdlpi.h>

static void usage(void);
static int prefix(char *arg, char *pref);
static int lookup(char **table, char *arg);

static char *yesno[] = {
	"no",
	"yes",
	"silent",
	0,
};

static char *txnames[] = {
	"txc",
	"rxc",
	"baud",
	"pll",
	"sysclk",
	"-txc",
	0,
};

static char *rxnames[] = {
	"rxc",
	"txc",
	"baud",
	"pll",
	"sysclk",
	"-rxc",
	0,
};

#ifdef notdef
static char *txdnames[] = {
	"txd",
	" ",	/* dummy entry, do not remove */
	"-txd",
	0,
};

static char *rxdnames[] = {
	"rxd",
	"-rxd",
	0,
};

static char *portab[] = {
	"rs422",
	"v35",
	0,
};
#endif

#define	equal(a, b)	(strcmp((a), (b)) == 0)

int
main(int argc, char **argv)
{
	char cnambuf[DLPI_LINKNAME_MAX], device[DLPI_LINKNAME_MAX];
	struct scc_mode sm;
	struct strioctl sioc;
	int fd, speed;
	int retval;
	char *arg, *cp;
	char loopchange = 0;
	char echochange = 0;
	char clockchange = 0;
	uint_t ppa;
	dlpi_handle_t dh;

	if (argc == 1) {
		usage();
		exit(1);
	}
	argc--;
	argv++;

	if (strlcpy(cnambuf, argv[0], sizeof (cnambuf)) >=
	    sizeof (cnambuf)) {
		(void) fprintf(stderr,
		    "syncinit: invalid device name (too long) %s\n", argv[0]);
		exit(1);
	}

	cp = cnambuf;
	while (*cp)			/* find the end of the name */
		cp++;
	cp--;
	if (!isdigit(*cp)) {
		(void) fprintf(stderr,
		    "syncinit: %s missing minor device number\n", cnambuf);
		exit(1);
	}

	retval = dlpi_open(cnambuf, &dh, DLPI_EXCL|DLPI_SERIAL);
	if (retval != DLPI_SUCCESS) {
		(void) fprintf(stderr, "syncinit: dlpi_open %s: %s\n", cnambuf,
		    dlpi_strerror(retval));
		exit(1);
	}

	(void) dlpi_parselink(cnambuf, device, &ppa);
	(void) printf("device: %s  ppa: %u\n", device, ppa);

	fd = dlpi_fd(dh);

	argc--;
	argv++;
	if (argc) {	/* setting things */
		sioc.ic_cmd = S_IOCGETMODE;
		sioc.ic_timout = -1;
		sioc.ic_len = sizeof (struct scc_mode);
		sioc.ic_dp = (char *)&sm;

		if (ioctl(fd, I_STR, &sioc) < 0) {
			perror("S_IOCGETMODE");
			(void) fprintf(stderr,
				"syncinit: can't get sync mode info for %s\n",
				cnambuf);
			exit(1);
		}
		while (argc-- > 0) {
			arg = *argv++;
			if (sscanf(arg, "%d", &speed) == 1)
				sm.sm_baudrate = speed;
			else if (strchr(arg, '=')) {
				if (prefix(arg, "loop")) {
					if (lookup(yesno, arg))
						sm.sm_config |= CONN_LPBK;
					else
						sm.sm_config &= ~CONN_LPBK;
					loopchange++;
				} else if (prefix(arg, "echo")) {
					if (lookup(yesno, arg))
						sm.sm_config |= CONN_ECHO;
					else
						sm.sm_config &= ~CONN_ECHO;
					echochange++;
				} else if (prefix(arg, "nrzi")) {
					if (lookup(yesno, arg))
						sm.sm_config |= CONN_NRZI;
					else
						sm.sm_config &= ~CONN_NRZI;
				} else if (prefix(arg, "txc")) {
					sm.sm_txclock = lookup(txnames, arg);
					clockchange++;
				} else if (prefix(arg, "rxc")) {
					sm.sm_rxclock = lookup(rxnames, arg);
					clockchange++;
				} else if (prefix(arg, "speed")) {
					arg = strchr(arg, '=') + 1;
					if (sscanf(arg, "%d", &speed) == 1) {
						sm.sm_baudrate = speed;
					} else
						(void) fprintf(stderr,
						    "syncinit: %s %s\n",
						    "bad speed:", arg);
				}
			} else if (equal(arg, "external")) {
				sm.sm_txclock = TXC_IS_TXC;
				sm.sm_rxclock = RXC_IS_RXC;
				sm.sm_config &= ~CONN_LPBK;
			} else if (equal(arg, "sender")) {
				sm.sm_txclock = TXC_IS_BAUD;
				sm.sm_rxclock = RXC_IS_RXC;
				sm.sm_config &= ~CONN_LPBK;
			} else if (equal(arg, "internal")) {
				sm.sm_txclock = TXC_IS_PLL;
				sm.sm_rxclock = RXC_IS_PLL;
				sm.sm_config &= ~CONN_LPBK;
			} else if (equal(arg, "stop")) {
				sm.sm_baudrate = 0;
			} else
				(void) fprintf(stderr, "Bad arg: %s\n", arg);
		}

		/*
		 * If we're going to change the state of loopback, and we
		 * don't have our own plans for clock sources, use defaults.
		 */
		if (loopchange && !clockchange) {
			if (sm.sm_config & CONN_LPBK) {
				sm.sm_txclock = TXC_IS_BAUD;
				sm.sm_rxclock = RXC_IS_BAUD;
			} else {
				sm.sm_txclock = TXC_IS_TXC;
				sm.sm_rxclock = RXC_IS_RXC;
			}
		}
		sioc.ic_cmd = S_IOCSETMODE;
		sioc.ic_timout = -1;
		sioc.ic_len = sizeof (struct scc_mode);
		sioc.ic_dp = (char *)&sm;
		if (ioctl(fd, I_STR, &sioc) < 0) {
			perror("S_IOCSETMODE");
			(void) ioctl(fd, S_IOCGETMODE, &sm);
			(void) fprintf(stderr,
				"syncinit: ioctl failure code = %x\n",
				sm.sm_retval);
			exit(1);
		}
	}

	/* Report State */
	sioc.ic_cmd = S_IOCGETMODE;
	sioc.ic_timout = -1;
	sioc.ic_len = sizeof (struct scc_mode);
	sioc.ic_dp = (char *)&sm;
	if (ioctl(fd, I_STR, &sioc) < 0) {
		perror("S_IOCGETMODE");
		(void) fprintf(stderr,
			"syncinit: can't get sync mode info for %s\n",
			cnambuf);
		exit(1);
	}
	(void) printf(
		"speed=%d, loopback=%s, echo=%s, nrzi=%s, txc=%s, rxc=%s\n",
		sm.sm_baudrate,
		yesno[((int)(sm.sm_config & CONN_LPBK) > 0)],
		yesno[((int)(sm.sm_config & CONN_ECHO) > 0)],
		yesno[((int)(sm.sm_config & CONN_NRZI) > 0)],
		txnames[sm.sm_txclock],
		rxnames[sm.sm_rxclock]);
	return (0);
}

static void
usage()
{
	(void) fprintf(stderr, "Usage: syncinit cnambuf \\\n");
	(void) fprintf(stderr, "\t[baudrate] [loopback=[yes|no]] ");
	(void) fprintf(stderr, "[echo=[yes|no]] [nrzi=[yes|no]] \\\n");
	(void) fprintf(stderr, "\t[txc=[txc|rxc|baud|pll]] \\\n");
	(void) fprintf(stderr, "\t[rxc=[rxc|txc|baud|pll]]\n");
	exit(1);
}

static int
prefix(char *arg, char *pref)
{
	return (strncmp(arg, pref, strlen(pref)) == 0);
}

static int
lookup(char **table, char *arg)
{
	char *val = strchr(arg, '=') + 1;
	int ival;

	for (ival = 0; *table != 0; ival++, table++)
		if (equal(*table, val))
			return (ival);
	(void) fprintf(stderr, "syncinit: bad arg: %s\n", arg);
	exit(1);
	/* NOTREACHED */
}
