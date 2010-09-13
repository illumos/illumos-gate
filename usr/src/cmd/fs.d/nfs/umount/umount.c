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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * nfs umount
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>
#include <kstat.h>
#include <rpc/rpc.h>
#include <sys/mnttab.h>
#include <sys/mount.h>
#include <sys/mntent.h>
#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>
#include <rpcsvc/mount.h>
#include <errno.h>
#include <locale.h>
#include <fslib.h>
#include <priv.h>
#include <tsol/label.h>
#include "replica.h"

#define	RET_OK	0
#define	RET_ERR	32

#ifdef __STDC__
static void pr_err(const char *fmt, ...);
#else
static void pr_err(char *fmt, va_dcl);
#endif
static	void	usage();
static	int	nfs_unmount(char *, int);
static	void	inform_server(char *, char *, bool_t);
static	struct extmnttab *mnttab_find();
extern int __clnt_bindresvport(CLIENT *);

static	int is_v4_mount(struct extmnttab *);

static char *myname;
static char typename[64];

int
main(int argc, char *argv[])
{
	extern int optind;
	int c;
	int umnt_flag = 0;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	myname = strrchr(argv[0], '/');
	myname = myname ? myname+1 : argv[0];
	(void) snprintf(typename, sizeof (typename), "nfs %s", myname);
	argv[0] = typename;

	/*
	 * Set options
	 */
	while ((c = getopt(argc, argv, "f")) != EOF) {
		switch (c) {
		case 'f':
			umnt_flag |= MS_FORCE; /* forced unmount is desired */
			break;
		default:
			usage();
			exit(RET_ERR);
		}
	}
	if (argc - optind != 1) {
		usage();
		exit(RET_ERR);
	}

	if (!priv_ineffect(PRIV_SYS_MOUNT) ||
	    !priv_ineffect(PRIV_NET_PRIVADDR)) {
		pr_err(gettext("insufficient privileges\n"));
		exit(RET_ERR);
	}

	/*
	 * On a labeled system, a MAC flag may be needed if the mount is
	 * read-down, so attempt to assert it but ignore errors in any case.
	 */
	if (is_system_labeled())
		(void) setpflags(NET_MAC_AWARE, 1);

	/*
	 * exit, really
	 */
	return (nfs_unmount(argv[optind], umnt_flag));
}

static void
pr_err(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) fprintf(stderr, "%s: ", typename);
	(void) vfprintf(stderr, fmt, ap);
	(void) fflush(stderr);
	va_end(ap);
}

static void
usage()
{
	(void) fprintf(stderr,
	    gettext("Usage: nfs umount [-f] {server:path | dir}\n"));
	exit(RET_ERR);
}

static int
nfs_unmount(char *pathname, int umnt_flag)
{
	struct extmnttab *mntp;
	bool_t quick = FALSE;
	int is_v4 = FALSE;

	mntp = mnttab_find(pathname);
	if (mntp) {
		pathname = mntp->mnt_mountp;
	}

	if (mntp)
		is_v4 = is_v4_mount(mntp);

	/* Forced unmount will almost always be successful */
	if (umount2(pathname, umnt_flag) < 0) {
		if (errno == EBUSY) {
			pr_err(gettext("%s: is busy\n"), pathname);
		} else {
			pr_err(gettext("%s: not mounted\n"), pathname);
		}
		return (RET_ERR);
	}

	/* All done if it's v4 */
	if (is_v4 == TRUE)
		return (RET_OK);

	/* Inform server quickly in case of forced unmount */
	if (umnt_flag & MS_FORCE)
		quick = TRUE;

	if (mntp) {
		inform_server(mntp->mnt_special, mntp->mnt_mntopts, quick);
	}

	return (RET_OK);
}

/*
 *  Find the mnttab entry that corresponds to "name".
 *  We're not sure what the name represents: either
 *  a mountpoint name, or a special name (server:/path).
 *  Return the last entry in the file that matches.
 */
static struct extmnttab *
mnttab_find(dirname)
	char *dirname;
{
	FILE *fp;
	struct extmnttab mnt;
	struct extmnttab *res = NULL;

	fp = fopen(MNTTAB, "r");
	if (fp == NULL) {
		pr_err("%s: %s\n", MNTTAB, strerror(errno));
		return (NULL);
	}
	while (getextmntent(fp, &mnt, sizeof (struct extmnttab)) == 0) {
		if (strcmp(mnt.mnt_mountp, dirname) == 0 ||
		    strcmp(mnt.mnt_special, dirname) == 0) {
			if (res)
				fsfreemnttab(res);
			res = fsdupmnttab(&mnt);
		}
	}

	(void) fclose(fp);
	return (res);
}

/*
 * If quick is TRUE, it will try to inform server quickly
 * as possible.
 */
static void
inform_server(char *string, char *opts, bool_t quick)
{
	struct timeval timeout;
	CLIENT *cl;
	enum clnt_stat rpc_stat;
	struct replica *list;
	int i, n;
	char *p = NULL;
	static struct timeval create_timeout = {5, 0};
	static struct timeval *timep;

	list = parse_replica(string, &n);

	if (list == NULL) {
		if (n < 0)
			pr_err(gettext("%s is not hostname:path format\n"),
			    string);
		else
			pr_err(gettext("no memory\n"));
		return;
	}

	/*
	 * If mounted with -o public, then no need to contact server
	 * because mount protocol was not used.
	 */
	if (opts != NULL)
		p = strstr(opts, MNTOPT_PUBLIC);

	if (p != NULL) {
		i = strlen(MNTOPT_PUBLIC);
		/*
		 * Now make sure the match of "public" isn't a substring
		 * of another option.
		 */
		if (((p == opts) || (*(p-1) == ',')) &&
		    ((p[i] == ',') || (p[i] == '\0')))
			return;
	}

	for (i = 0; i < n; i++) {
		int vers;

		/*
		 * Skip file systems mounted using WebNFS, because mount
		 * protocol was not used.
		 */
		if (strcmp(list[i].host, "nfs") == 0 && strncmp(list[i].path,
		    "//", 2) == 0)
			continue;

		vers =  MOUNTVERS;
retry:
		/*
		 * Use 5 sec. timeout if file system is forced unmounted,
		 * otherwise use default timeout to create a client handle.
		 * This would minimize the time to force unmount a file
		 * system reside on a server that is down.
		 */
		timep = (quick ? &create_timeout : NULL);
		cl = clnt_create_timed(list[i].host, MOUNTPROG, vers,
		    "datagram_n", timep);
		/*
		 * Do not print any error messages in case of forced
		 * unmount.
		 */
		if (cl == NULL) {
			if (!quick)
				pr_err("%s:%s %s\n", list[i].host, list[i].path,
				    clnt_spcreateerror(
				    "server not responding"));
			continue;
		}
		/*
		 * Now it is most likely that the NFS client will be able
		 * to contact the server since rpcbind is running on
		 * the server. There is still a small window in which
		 * server can be unreachable.
		 */

		if (__clnt_bindresvport(cl) < 0) {
			if (!quick)
				pr_err(gettext(
				    "couldn't bind to reserved port\n"));
			clnt_destroy(cl);
			return;
		}
		if ((cl->cl_auth = authsys_create_default()) == NULL) {
			if (!quick)
				pr_err(gettext(
				    "couldn't create authsys structure\n"));
			clnt_destroy(cl);
			return;
		}
		timeout.tv_usec = 0;
		timeout.tv_sec = 5;
		clnt_control(cl, CLSET_RETRY_TIMEOUT, (char *)&timeout);
		timeout.tv_sec = 25;
		rpc_stat = clnt_call(cl, MOUNTPROC_UMNT, xdr_dirpath,
		    (char *)&list[i].path, xdr_void, (char *)NULL,
		    timeout);
		AUTH_DESTROY(cl->cl_auth);
		clnt_destroy(cl);
		if (rpc_stat == RPC_PROGVERSMISMATCH && vers == MOUNTVERS) {
			/*
			 * The rare case of a v3-only server
			 */
			vers = MOUNTVERS3;
			goto retry;
		}
		if (rpc_stat != RPC_SUCCESS)
			pr_err("%s\n", clnt_sperror(cl, "unmount"));
	}

	free_replica(list, n);
}

/*
 * This function's behavior is taken from nfsstat.
 * Trying to determine what NFS version was used for the mount.
 */
int
is_v4_mount(struct extmnttab *mntp)
{
	kstat_ctl_t *kc = NULL;		/* libkstat cookie */
	kstat_t *ksp;
	struct mntinfo_kstat mik;

	if (mntp == NULL)
		return (FALSE);

	if ((kc = kstat_open()) == NULL)
		return (FALSE);

	for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {
		if (ksp->ks_type != KSTAT_TYPE_RAW)
			continue;
		if (strcmp(ksp->ks_module, "nfs") != 0)
			continue;
		if (strcmp(ksp->ks_name, "mntinfo") != 0)
			continue;
		if (mntp->mnt_minor != ksp->ks_instance)
			continue;

		if (kstat_read(kc, ksp, &mik) == -1)
			continue;

		if (mik.mik_vers == 4)
			return (TRUE);
		else
			return (FALSE);
	}
	return (FALSE);
}
