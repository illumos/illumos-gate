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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <netconfig.h>
#include <netdir.h>
#include <rpc/rpc.h>
#include <sys/file.h>
#include <sys/param.h>
#include "ypxfrd.h"
#include <ndbm.h>
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/nis.h>
#include <strings.h>

#include <sys/isa_defs.h>	/* for ENDIAN defines */

#if defined(_LITTLE_ENDIAN)
#define	DOSWAB 1
#endif

static struct timeval TIMEOUT = {25, 0};
static	DBM	*db;

extern bool secure_map;
extern void logprintf(char *, ...);

/* delete the dbm file with name file */
static int
dbm_deletefile(file)
char *file;
{
	char	pag1[MAXPATHLEN];
	char	dir1[MAXPATHLEN];
	int err;
	strcpy(pag1, file);
	strcat(pag1, ".pag");
	strcpy(dir1, file);
	strcat(dir1, ".dir");
	err = 0;
	if (unlink(pag1) < 0) {
		perror("unlinkpag");
		err = -1;
	}

	if (unlink(dir1) < 0) {
		perror("unlinkdir");
		return (-1);
	}
	return (err);
}

/* xdr just the .pag file of a dbm file */
static	bool_t
xdr_pages(xdrs)
	XDR	*xdrs;
{
	static struct pag res;
	struct pag	*PAG;
#ifdef DOSWAB
	short	*s;
	int		i;
#endif
	bool_t	more;
	bool_t	goteof;
	off64_t	where;
	int	true = 1;

	goteof = FALSE;
	if (!xdr_pag(xdrs, &res))
		return (FALSE);
	PAG = &res;
	while (true) {
		if (PAG->status == OK) {
#ifdef DOSWAB
		s = (short *)PAG->pag_u.ok.blkdat;
		s[0] = ntohs(s[0]);
		for (i = 1; i <= s[0]; i++)
			s[i] = ntohs(s[i]);
#endif
			errno = 0;
			where = (((off64_t)PAG->pag_u.ok.blkno) * PBLKSIZ);
			(void) lseek64(db->dbm_pagf, where, L_SET);
			if (errno != 0) {
				perror("seek");
				exit(-1);
			}
			if (write(db->dbm_pagf,
				PAG->pag_u.ok.blkdat, PBLKSIZ) < 0) {
				perror("write");
				exit(-1);
			}
		} else if (PAG->status == GETDBM_ERROR) {
			(void) printf("clnt call getpag GETDBM_ERROR\n");
			exit(-1);
		} else if (PAG->status == GETDBM_EOF)
			goteof = TRUE;
		if (!xdr_bool(xdrs, &more))
			return (FALSE);
		if (more == FALSE)
			return (goteof);
		if (!xdr_pag(xdrs, &res))
			return (FALSE);
	}
	/*NOTREACHED*/
	return (TRUE);
}
/* xdr  just the .dir part of a dbm file */
static	bool_t
xdr_dirs(xdrs)
	XDR	*xdrs;
{
	static	struct dir res;
	struct	dir	*DIR;
	bool_t	more;
	bool_t	goteof;
	off64_t	where;
	int	true = 1;

	goteof = FALSE;
	if (!xdr_dir(xdrs, &res))
		return (FALSE);
	DIR = &res;
	while (true) {
		if (DIR->status == OK) {
			errno = 0;
			where = (((off64_t)DIR->dir_u.ok.blkno) * DBLKSIZ);
			(void) lseek64(db->dbm_dirf, where, L_SET);
			if (errno != 0) {
				perror("seek");
				exit(-1);
			}
			if (write(db->dbm_dirf,
				DIR->dir_u.ok.blkdat, DBLKSIZ) < 0) {
				perror("write");
				exit(-1);
			}
		} else if (DIR->status == GETDBM_ERROR) {
			(void) printf("clnt call getdir GETDBM_ERROR\n");
			exit(-1);
		} else if (DIR->status == GETDBM_EOF)
			goteof = TRUE;
		if (!xdr_bool(xdrs, &more))
			return (FALSE);
		if (more == FALSE)
			return (goteof);
		if (!xdr_dir(xdrs, &res))
			return (FALSE);
	}
	/*NOTREACHED*/
	return (TRUE);
}

/*
 * xdr a dbm file from ypxfrd
 * note that if the client or server do not support ndbm
 * we may not use this optional protocol
 */

int
xdr_myfyl(xdrs, objp)
	XDR *xdrs;
	int *objp;
{
	if (!xdr_answer(xdrs, (answer *)objp))
		return (FALSE);

	if (*objp != OK)
		return (TRUE);

	if (!xdr_pages(xdrs))
		return (FALSE);

	if (!xdr_dirs(xdrs))
		return (FALSE);

	return (TRUE);
}

int
ypxfrd_getdbm(tempmap, master, domain, map)
	char *tempmap;
	char *master;
	char *domain;
	char *map;
{
	hosereq	rmap;
	CLIENT	*clnt;
	int		res;
	int	recvsiz = 24 * 1024;
	struct netconfig *nconf;
	int fd;
	struct netbuf *svcaddr;
	struct t_bind *tbind;
	char *netid[] = { "tcp6", "tcp" };
	int i, lastnetid = (sizeof (netid)/sizeof (netid[0])) - 1;

	for (i = 0; i <= lastnetid; i++) {
		if ((nconf = getnetconfigent(netid[i])) == NULL) {
			if (i != lastnetid)
				continue;
			logprintf("ypxfr: tcp transport not supported\n");
			return (-1);
		}
		if ((fd = t_open(nconf->nc_device, O_RDWR, NULL)) == -1) {
			freenetconfigent(nconf);
			if (i != lastnetid)
				continue;
			logprintf("ypxfr: TLI problems\n");
			return (-1);
		}
		if (secure_map == TRUE) {
			if (netdir_options(nconf, ND_SET_RESERVEDPORT, fd,
					NULL) == -1) {
				(void) close(fd);
				freenetconfigent(nconf);
				if (i != lastnetid)
					continue;
				logprintf(
			"ypxfr: cannot bind to reserved port for %s\n%s\n",
					netid[i], netdir_sperror());
				return (-1);
			}
		}

		/* LINTED pointer alignment */
		if ((tbind = (struct t_bind *)t_alloc(fd, T_BIND, T_ADDR)) ==
			NULL) {
			(void) close(fd);
			freenetconfigent(nconf);
			if (i != lastnetid)
				continue;
			logprintf("ypxfr: TLI problems\n");
			return (-1);
		}
		svcaddr = &(tbind->addr);
		if (rpcb_getaddr(YPXFRD, 1, nconf, svcaddr, master)
			== FALSE) {
			(void) t_free((char *)tbind, T_BIND);
			(void) close(fd);
			freenetconfigent(nconf);
			if (i != lastnetid)
				continue;
			logprintf("ypxfr: couldnot get %s address\n", master);
			return (-1);
		}
		if ((clnt = __nis_clnt_create(fd, nconf, 0, svcaddr, 0,
						YPXFRD, 1, recvsiz, 0)) == 0) {
			(void) t_free((char *)tbind, T_BIND);
			(void) close(fd);
			freenetconfigent(nconf);
			if (i != lastnetid)
				continue;
			clnt_pcreateerror(
				"ypxfr (get_map) - TCP channel create failure");
			return (-1);
		}
		(void) t_free((char *)tbind, T_BIND);
		break;
	}
	(void) CLNT_CONTROL(clnt, CLSET_FD_CLOSE, (char *)NULL);

	rmap.map = map;
	rmap.domain = domain;
	(void) memset((char *)&res, 0, sizeof (res));
	db = dbm_open(tempmap, O_RDWR + O_CREAT + O_TRUNC, 0777);
	if (db == NULL) {
		logprintf("dbm_open failed %s\n", tempmap);
		perror(tempmap);
		return (-2);
	}

	if (clnt_call(clnt, getdbm, xdr_hosereq, (char *)&rmap, xdr_myfyl,
		(char *)&res, TIMEOUT) != RPC_SUCCESS) {
		logprintf("clnt call to ypxfrd getdbm failed.\n");
		clnt_perror(clnt, "getdbm");
		(void) dbm_deletefile(tempmap);
		return (-3);
	}
	if (res != OK) {
		logprintf("clnt call %s ypxfrd getdbm NOTOK %s %s code=%d\n",
			master, domain, map, res);
		(void) dbm_deletefile(tempmap);
		return (-4);
	}
	return (0);

}
