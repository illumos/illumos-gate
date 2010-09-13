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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>
#include <libintl.h>
#include <locale.h>
#include <rpc/rpc.h>
#include <rpcsvc/nlm_prot.h>

#include <sys/systeminfo.h>
#include <netdb.h>
#include <nss_dbdefs.h>

#include <nfs/nfs.h>
#include <nfs/export.h>
#include <nfs/nfssys.h>

extern char *optarg;
extern int optind;
extern int _nfssys(enum nfssys_op, void *);

static int share_zap(char *, char *);

/*
 * Clear locks and v4 related state held by
 * 'client'.
 */
static int
nfs4_clr_state(char *client)
{
	int   he_error;
	char  he_buf[NSS_BUFLEN_HOSTS];
	struct hostent host_ent, *he;
	char **ap;
	struct nfs4clrst_args arg;

	if ((he = gethostbyname_r(client, &host_ent, he_buf, sizeof (he_buf),
				&he_error)) == NULL) {
		(void) fprintf(stderr,
			gettext("client name '%s' can not be resolved\n"),
			client);
		return (1);
	}

	if (he_error) {
		perror("gethostbyname");
		return (1);
	}

	/*
	 * The NFS4 clear state interface is
	 * versioned in case we need to pass
	 * more information in the future.
	 */
	arg.vers = NFS4_CLRST_VERSION;
	arg.addr_type = he->h_addrtype;

	/*
	 * Iterate over IP Addresses clear
	 * state for each.
	 */
	for (ap = he->h_addr_list; *ap; ap++) {
		arg.ap = *ap;
		_nfssys(NFS4_CLR_STATE, &arg);
	}
	return (0);
}

int
main(int argc, char *argv[])
{
	int i, c, ret;
	int sflag = 0;
	int errflg = 0;
	char myhostname[MAXHOSTNAMELEN];

	if (geteuid() != (uid_t)0) {
		(void) fprintf(stderr, gettext("clear_locks: must be root\n"));
		exit(1);
	}

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Get the official hostname for this host
	 */
	sysinfo(SI_HOSTNAME, myhostname, sizeof (myhostname));

	while ((c = getopt(argc, argv, "s")) != EOF) {
		switch (c) {
		case 's':
			sflag++;
			break;
		case '?':
			errflg++;
		}
	}

	i = argc - optind;
	if (errflg || i != 1) {
		(void) fprintf(stderr,
				gettext("Usage: clear_locks [-s] hostname\n"));
		exit(2);
	}

	if (sflag) {
		(void) fprintf(stdout,
gettext("Clearing locks held for NFS client %s on server %s\n"),
				myhostname, argv[optind]);
		ret = share_zap(myhostname, argv[optind]);
	} else {
		(void) fprintf(stdout,
gettext("Clearing locks held for NFS client %s on server %s\n"),
				argv[optind], myhostname);
		ret = share_zap(argv[optind], myhostname);
		ret += nfs4_clr_state(argv[optind]);
	}

	return (ret);
}


/*
 * Request that host 'server' free all locks held by
 * host 'client'.
 */
static int
share_zap(char *client, char *server)
{
	struct nlm_notify notify;
	enum clnt_stat rslt;

	notify.state = 0;
	notify.name = client;
	rslt = rpc_call(server, NLM_PROG, NLM_VERSX, NLM_FREE_ALL,
		xdr_nlm_notify, (char *)&notify, xdr_void, 0, NULL);
	if (rslt != RPC_SUCCESS) {
		clnt_perrno(rslt);
		return (3);
	}
	(void) fprintf(stderr,
		gettext("clear of locks held for %s on %s returned success\n"),
		client, server);
	return (0);
}
