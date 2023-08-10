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
 * showmount
 */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <rpc/rpc.h>
#include <rpc/rpcb_clnt.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>
#include <nfs/nfs.h>
#include <rpcsvc/mount.h>
#include <locale.h>
#include <unistd.h>
#include <clnt_subr.h>

int sorthost(const void *, const void *);
int sortpath(const void *, const void *);
void printex(CLIENT *, char *);
void usage(void);

/*
 * Dynamically-sized array of pointers to mountlist entries.  Each element
 * points into the linked list returned by the RPC call.  We use an array
 * so that we can conveniently sort the entries.
 */
static struct mountbody **table;

struct	timeval	rpc_totout_new = {15, 0};

int
main(int argc, char *argv[])
{
	int aflg = 0, dflg = 0, eflg = 0;
	int err;
	struct mountbody *result_list = NULL;
	struct mountbody *ml = NULL;
	struct mountbody **tb;		/* pointer into table */
	char *host, hostbuf[256];
	char *last;
	CLIENT *cl;
	int c;
	struct timeval	tout, rpc_totout_old;
	int numentries;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "ade")) != EOF) {
		switch (c) {
		case 'a':
			aflg++;
			break;
		case 'd':
			dflg++;
			break;
		case 'e':
			eflg++;
			break;
		default:
			usage();
			exit(1);
		}
	}

	switch (argc - optind) {
	case 0:		/* no args */
		if (gethostname(hostbuf, sizeof (hostbuf)) < 0) {
			pr_err("gethostname: %s\n", strerror(errno));
			exit(1);
		}
		host = hostbuf;
		break;
	case 1:		/* one arg */
		host = argv[optind];
		break;
	default:	/* too many args */
		usage();
		exit(1);
	}

	(void) __rpc_control(CLCR_GET_RPCB_TIMEOUT, &rpc_totout_old);
	(void) __rpc_control(CLCR_SET_RPCB_TIMEOUT, &rpc_totout_new);

	cl = mountprog_client_create(host, &rpc_totout_old);
	if (cl == NULL) {
		exit(1);
	}

	(void) __rpc_control(CLCR_SET_RPCB_TIMEOUT, &rpc_totout_old);

	if (eflg) {
		printex(cl, host);
		if (aflg + dflg == 0) {
			exit(0);
		}
	}

	tout.tv_sec = 10;
	tout.tv_usec = 0;

	err = clnt_call(cl, MOUNTPROC_DUMP, xdr_void, 0, xdr_mountlist,
	    (caddr_t)&result_list, tout);
	if (err != 0) {
		pr_err("%s\n", clnt_sperrno(err));
		exit(1);
	}

	/*
	 * Count the number of entries in the list.  If the list is empty,
	 * quit now.
	 */
	numentries = 0;
	for (ml = result_list; ml != NULL; ml = ml->ml_next)
		numentries++;
	if (numentries == 0)
		exit(0);

	/*
	 * Allocate memory for the array and initialize the array.
	 */

	table = calloc(numentries, sizeof (struct mountbody *));
	if (table == NULL) {
		pr_err(gettext("not enough memory for %d entries\n"),
		    numentries);
		exit(1);
	}
	for (ml = result_list, tb = &table[0];
	    ml != NULL;
	    ml = ml->ml_next, tb++) {
		*tb = ml;
	}

	/*
	 * Sort the entries and print the results.
	 */

	if (dflg)
		qsort(table, numentries, sizeof (struct mountbody *), sortpath);
	else
		qsort(table, numentries, sizeof (struct mountbody *), sorthost);
	if (aflg) {
		for (tb = table; tb < table + numentries; tb++)
			printf("%s:%s\n", (*tb)->ml_hostname,
			    (*tb)->ml_directory);
	} else if (dflg) {
		last = "";
		for (tb = table; tb < table + numentries; tb++) {
			if (strcmp(last, (*tb)->ml_directory))
				printf("%s\n", (*tb)->ml_directory);
			last = (*tb)->ml_directory;
		}
	} else {
		last = "";
		for (tb = table; tb < table + numentries; tb++) {
			if (strcmp(last, (*tb)->ml_hostname))
				printf("%s\n", (*tb)->ml_hostname);
			last = (*tb)->ml_hostname;
		}
	}
	return (0);
}

int
sorthost(const void *_a, const void *_b)
{
	struct mountbody **a = (struct mountbody **)_a;
	struct mountbody **b = (struct mountbody **)_b;

	return (strcmp((*a)->ml_hostname, (*b)->ml_hostname));
}

int
sortpath(const void *_a, const void *_b)
{
	struct mountbody **a = (struct mountbody **)_a;
	struct mountbody **b = (struct mountbody **)_b;

	return (strcmp((*a)->ml_directory, (*b)->ml_directory));
}

void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("Usage: showmount [-a] [-d] [-e] [host]\n"));
}

void
pr_err(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) fprintf(stderr, "showmount: ");
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
}

void
printex(CLIENT *cl, char *host)
{
	struct exportnode *ex = NULL;
	struct exportnode *e;
	struct groupnode *gr;
	enum clnt_stat err;
	int max;
	struct	timeval	tout;

	tout.tv_sec = 10;
	tout.tv_usec = 0;

	err = clnt_call(cl, MOUNTPROC_EXPORT, xdr_void, 0, xdr_exports,
	    (caddr_t)&ex, tout);
	if (err != 0) {
		pr_err("%s\n", clnt_sperrno(err));
		exit(1);
	}

	if (ex == NULL) {
		printf(gettext("no exported file systems for %s\n"), host);
	} else {
		printf(gettext("export list for %s:\n"), host);
	}
	max = 0;
	for (e = ex; e != NULL; e = e->ex_next) {
		if (strlen(e->ex_dir) > max) {
			max = strlen(e->ex_dir);
		}
	}
	while (ex) {
		printf("%-*s ", max, ex->ex_dir);
		gr = ex->ex_groups;
		if (gr == NULL) {
			printf(gettext("(everyone)"));
		}
		while (gr) {
			printf("%s", gr->gr_name);
			gr = gr->gr_next;
			if (gr) {
				printf(",");
			}
		}
		printf("\n");
		ex = ex->ex_next;
	}
}
