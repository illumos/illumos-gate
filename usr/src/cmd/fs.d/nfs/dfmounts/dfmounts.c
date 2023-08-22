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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * nfs dfmounts
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <rpc/rpc.h>
#include <rpc/rpcb_clnt.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <nfs/nfs.h>
#include <rpcsvc/mount.h>
#include <locale.h>
#include <unistd.h>
#include <clnt_subr.h>

static int hflg;

static void pr_mounts(char *);
static void freemntlist(struct mountbody *);
static int sortpath(const void *, const void *);
static void usage(void);

int
main(int argc, char *argv[])
{

	char hostbuf[256];
	extern int optind;
	int i, c;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "h")) != EOF) {
		switch (c) {
		case 'h':
			hflg++;
			break;
		default:
			usage();
			exit(1);
		}
	}

	if (optind < argc) {
		for (i = optind; i < argc; i++)
			pr_mounts(argv[i]);
	} else {
		if (gethostname(hostbuf, sizeof (hostbuf)) < 0) {
			perror("nfs dfmounts: gethostname");
			exit(1);
		}
		pr_mounts(hostbuf);
	}

	return (0);
}

#define	NTABLEENTRIES	2048
static struct mountbody *table[NTABLEENTRIES];
static struct timeval	rpc_totout_new = {15, 0};

/*
 * Print the filesystems on "host" that are currently mounted by a client.
 */

static void
pr_mounts(char *host)
{
	CLIENT *cl;
	struct mountbody *ml = NULL;
	struct mountbody **tb, **endtb;
	enum clnt_stat err;
	char *lastpath;
	char *lastclient;
	int tail = 0;
	struct	timeval	tout, rpc_totout_old;

	(void) __rpc_control(CLCR_GET_RPCB_TIMEOUT, &rpc_totout_old);
	(void) __rpc_control(CLCR_SET_RPCB_TIMEOUT, &rpc_totout_new);

	cl = mountprog_client_create(host, &rpc_totout_old);
	if (cl == NULL) {
		return;
	}

	(void) __rpc_control(CLCR_SET_RPCB_TIMEOUT, &rpc_totout_old);
	tout.tv_sec = 10;
	tout.tv_usec = 0;

	err = clnt_call(cl, MOUNTPROC_DUMP, xdr_void, 0, xdr_mountlist,
	    (caddr_t)&ml, tout);
	if (err != 0) {
		pr_err("%s\n", clnt_sperrno(err));
		clnt_destroy(cl);
		return;
	}

	if (ml == NULL)
		return;	/* no mounts */

	if (!hflg) {
		printf("%-8s %10s %-24s  %s",
		    gettext("RESOURCE"), gettext("SERVER"),
		    gettext("PATHNAME"), gettext("CLIENTS"));
		hflg++;
	}

	/*
	 * Create an array describing the mounts, so that we can sort them.
	 */
	tb = table;
	for (; ml != NULL && tb < &table[NTABLEENTRIES]; ml = ml->ml_next)
		*tb++ = ml;
	if (ml != NULL && tb == &table[NTABLEENTRIES])
		pr_err(gettext("table overflow:  only %d entries shown\n"),
		    NTABLEENTRIES);
	endtb = tb;
	qsort(table, endtb - table, sizeof (struct mountbody *), sortpath);

	/*
	 * Print out the sorted array.  Group entries for the same
	 * filesystem together, and ignore duplicate entries.
	 */
	lastpath = "";
	lastclient = "";
	for (tb = table; tb < endtb; tb++) {
		if (*((*tb)->ml_directory) == '\0' ||
		    *((*tb)->ml_hostname) == '\0')
			continue;
		if (strcmp(lastpath, (*tb)->ml_directory) == 0) {
			if (strcmp(lastclient, (*tb)->ml_hostname) == 0) {
				continue;	/* ignore duplicate */
			}
		} else {
			printf("\n%-8s %10s %-24s ",
			    "  -", host, (*tb)->ml_directory);
			lastpath = (*tb)->ml_directory;
			tail = 0;
		}
		if (tail++)
			printf(",");
		printf("%s", (*tb)->ml_hostname);
		lastclient = (*tb)->ml_hostname;
	}
	printf("\n");

	freemntlist(ml);
	clnt_destroy(cl);
}

static void
freemntlist(struct mountbody *ml)
{
	struct mountbody *old;

	while (ml) {
		if (ml->ml_hostname)
			free(ml->ml_hostname);
		if (ml->ml_directory)
			free(ml->ml_directory);
		old = ml;
		ml = ml->ml_next;
		free(old);
	}
}

/*
 * Compare two structs for mounted filesystems.  The primary sort key is
 * the name of the exported filesystem.  There is also a secondary sort on
 * the name of the client, so that duplicate entries (same path and
 * hostname) will sort together.
 *
 * Returns < 0 if the first entry sorts before the second entry, 0 if they
 * sort the same, and > 0 if the first entry sorts after the second entry.
 */

static int
sortpath(const void *a, const void *b)
{
	const struct mountbody **m1, **m2;
	int result;

	m1 = (const struct mountbody **)a;
	m2 = (const struct mountbody **)b;

	result = strcmp((*m1)->ml_directory, (*m2)->ml_directory);
	if (result == 0) {
		result = strcmp((*m1)->ml_hostname, (*m2)->ml_hostname);
	}

	return (result);
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext("Usage: dfmounts [-h] [host ...]\n"));
}

void
pr_err(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) fprintf(stderr, "nfs dfmounts: ");
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
}
