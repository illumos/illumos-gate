/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <memory.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <values.h>
#include <poll.h>
#include <locale.h>
#include <libndmp.h>

#define	MAX_DEV_STAT	16
#define	REPRINT	19
#define	VAL(v)		(new->ns_##v)
#define	DELTA(v)	(new->ns_##v - (old ? old->ns_##v : 0))
#define	ADJ(n)		((adj <= 0) ? n : (adj >= n) ? 1 : n - adj)
#define	adjprintf(fmt, n, val)	adj -= (n + 1) - printf(fmt, ADJ(n), val)
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

static int adj;		/* number of excess columns */
static long iter = 0;
static int blksize = 1024;
static int poll_interval = 1;
static ndmp_stat_t *nstat;
static int lines = 1;

static void dostats(ndmp_stat_t *, ndmp_stat_t *);
static void printhdr(int);
static void usage(void);

int
main(int argc, char **argv)
{
	ndmp_stat_t *old = NULL;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	argc--, argv++;

	if (argc > 0) {
		long interval;
		char *endptr;

		errno = 0;
		interval = strtol(argv[0], &endptr, 10);

		if (errno > 0 || *endptr != '\0' || interval <= 0 ||
		    interval > MAXLONG) {
			usage();
			return (1);
		}
		poll_interval = 1000 * interval;
		if (poll_interval <= 0) {
			usage();
			return (1);
		}
		iter = MAXLONG;
		if (argc > 1) {
			iter = strtol(argv[1], NULL, 10);
			if (errno > 0 || *endptr != '\0' || iter <= 0) {
				usage();
				return (1);
			}
		}
		if (argc > 2) {
			usage();
			return (1);
		}
	}

	if (ndmp_door_status()) {
		(void) fprintf(stdout,
		    gettext(" Error: ndmpd service not running.\n"));
		return (1);
	}

	(void) sigset(SIGCONT, printhdr);

	printhdr(0);

	if ((nstat = malloc(sizeof (ndmp_stat_t))) == NULL) {
		(void) fprintf(stdout, gettext("Out of memory"));
		return (1);
	}


	if (ndmp_get_stats(nstat) != 0) {
		free(nstat);
		return (1);
	}

	dostats(old, nstat);
	while (--iter > 0) {
		(void) poll(NULL, 0, poll_interval);

		free(old);
		old = nstat;
		if ((nstat = malloc(sizeof (ndmp_stat_t))) == NULL) {
			(void) fprintf(stdout, gettext("Out of memory"));
			free(old);
			return (1);
		}
		if (ndmp_get_stats(nstat) != 0) {
			free(old);
			free(nstat);
			return (1);
		}
		dostats(old, nstat);
	}

	return (0);
}

/* ARGSUSED */
static void
printhdr(int sig)
{
	(void) printf(" wthr  ops    file      disk      tape      ");
	(void) printf("bytes   perf     prcnt\n");

	(void) printf(" r w  bk rs  rd   wr   rd   wr   rd   wr   rd   ");
	(void) printf("wr  bk rs  dsk tpe idl\n");

	lines = REPRINT;
}

static void
dostats(ndmp_stat_t *old, ndmp_stat_t *new)
{
	long long dskop = 0;
	long long tpop = 0;
	long dpcnt, tpcnt;
	long ipcnt;
	int totl;
	long rbytes;
	long wbytes;

	adj = 0;

	if (--lines == 0)
		printhdr(0);

	if (!old) {
		(void) printf(" 0 0  0  0    0    0    0    ");
		(void) printf("0    0    0    0    0   0  0    0   0 100\n");
		return;
	}

	adjprintf(" %*u", 1, VAL(trun));
	adjprintf(" %*u", 1, VAL(twait));
	adjprintf(" %*u", 2, VAL(nbk));
	adjprintf(" %*u", 2, VAL(nrs));
	adjprintf(" %*u", 4, DELTA(rfile));
	adjprintf(" %*u", 4, DELTA(wfile));
	adjprintf(" %*u", 4, (unsigned)(DELTA(rdisk) / blksize));
	adjprintf(" %*u", 4, (unsigned)(DELTA(wdisk) / blksize));
	adjprintf(" %*u", 4, (unsigned)(DELTA(rtape) / blksize));
	adjprintf(" %*u", 4, (unsigned)(DELTA(wtape) / blksize));

	/* Get the average throughput */
	rbytes = (DELTA(wtape) + DELTA(rdisk)) / 2;
	wbytes = (DELTA(rtape) + DELTA(wdisk)) / 2;
	rbytes /= blksize;
	wbytes /= blksize;

	adjprintf(" %*lu", 4, rbytes);
	adjprintf(" %*lu", 4, wbytes);

	adjprintf(" %*lu", 3, rbytes / poll_interval);
	adjprintf(" %*lu", 2, wbytes / poll_interval);

	dskop += DELTA(rdisk);
	dskop += DELTA(wdisk);
	tpop += DELTA(rtape);
	tpop += DELTA(wtape);
	totl = (dskop + tpop) ? (dskop + tpop) : 1;

	dpcnt = (dskop * 100) / totl;
	tpcnt = (tpop * 100) / totl;
	ipcnt = 100 - dpcnt - tpcnt;

	adjprintf(" %*lu", 4, dpcnt);
	adjprintf(" %*lu", 3, tpcnt);
	adjprintf(" %*lu\n", 3, ipcnt);
	(void) fflush(stdout);
}

static void
usage(void)
{
	(void) fprintf(stderr, "Usage: ndmpstat [interval [count]]\n");
}
