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
 * nfs dfshares
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
#include <unistd.h>
#include <clnt_subr.h>

int hflg;
void pr_exports(char *);
void free_ex(struct exportnode *);
void usage(void);

int
main(int argc, char *argv[])
{
	char hostbuf[256];
	int i, c;

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
			pr_exports(argv[i]);
	} else {
		if (gethostname(hostbuf, sizeof (hostbuf)) < 0) {
			pr_err("gethostname: %s\n", strerror(errno));
			exit(1);
		}
		pr_exports(hostbuf);
	}

	return (0);
}

struct	timeval	rpc_totout_new = {15, 0};

void
pr_exports(char *host)
{
	CLIENT *cl;
	struct exportnode *ex = NULL;
	enum clnt_stat err;
	struct	timeval	tout, rpc_totout_old;

	(void) __rpc_control(CLCR_GET_RPCB_TIMEOUT, &rpc_totout_old);
	(void) __rpc_control(CLCR_SET_RPCB_TIMEOUT, &rpc_totout_new);

	cl = mountprog_client_create(host, &rpc_totout_old);
	if (cl == NULL) {
		exit(1);
	}

	(void) __rpc_control(CLCR_SET_RPCB_TIMEOUT, &rpc_totout_old);
	tout.tv_sec = 10;
	tout.tv_usec = 0;

	err = clnt_call(cl, MOUNTPROC_EXPORT, xdr_void, 0, xdr_exports,
	    (caddr_t)&ex, tout);
	if (err != 0) {
		pr_err("%s\n", clnt_sperrno(err));
		clnt_destroy(cl);
		exit(1);
	}

	if (ex == NULL) {
		clnt_destroy(cl);
		exit(1);
	}

	if (!hflg) {
		printf("%-35s %12s %-8s  %s\n",
		    "RESOURCE", "SERVER", "ACCESS", "TRANSPORT");
		hflg++;
	}

	while (ex) {
		printf("%10s:%-24s %12s %-8s  %s\n",
		    host, ex->ex_dir, host, " -", " -");
		ex = ex->ex_next;
	}
	free_ex(ex);
	clnt_destroy(cl);
}

void
free_ex(struct exportnode *ex)
{
	struct groupnode *gr, *tmpgr;
	struct exportnode *tmpex;

	while (ex) {
		free(ex->ex_dir);
		gr = ex->ex_groups;
		while (gr) {
			tmpgr = gr->gr_next;
			free(gr);
			gr = tmpgr;
		}
		tmpex = ex;
		ex = ex->ex_next;
		free(tmpex);
	}
}

void
usage(void)
{
	(void) fprintf(stderr, "Usage: dfshares [-h] [host ...]\n");
}

void
pr_err(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) fprintf(stderr, "nfs dfshares: ");
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
}
