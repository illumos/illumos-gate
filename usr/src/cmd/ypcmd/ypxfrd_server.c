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
/* Portions Copyright 2005 Juergen Keil */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ndbm.h>
#include <rpc/rpc.h>
#include <rpc/svc.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <syslog.h>
#include "ypxfrd.h"
#include "ypsym.h"
#include "ypdefs.h"
/*
 * Because this code hacks into DBM underneath its API it can't use the N2L
 * shim in it's normal way. It thus includes shim.h instead of shim_hooks.h
 * and has knowledge of shim internals. While copying the DBM files it does
 * not lock them. This reflects the behavior of the pre N2L code.
 */
#include "shim.h"
#include "yptol.h"

#if (defined(vax) || defined(i386))
#define	DOSWAB 1
#endif

USE_YP_SECURE

/* per connection stuff */
struct mycon {
	map_ctrl *map;
	int	lblk;
	int	firstd;
	datum	key;
};

bool_t xdr_myfyl(XDR *xdrs, struct mycon *objp);
bool_t xdr_pages(XDR *xdrs, struct mycon *m);
bool_t xdr_dirs(XDR *xdrs, struct mycon *m);

int mygetdir(char *block, int *no, struct mycon *m);
int mygetpage(char *block, int *pageno, struct mycon *m);

datum mydbm_topkey(DBM *db, datum okey);
datum dbm_do_nextkey();
datum shim_dbm_do_nextkey();

extern void get_secure_nets(char *);
extern int check_secure_net_ti(struct netbuf *, char *);
extern int _main(int, char **);

int
main(int argc, char **argv)
{
	int connmaxrec = RPC_MAXDATASIZE;

	/* load up the securenet file */
	get_secure_nets(argv[0]);

	/*
	 * Set non-blocking mode and maximum record size for
	 * connection oriented RPC transports.
	 */
	if (!rpc_control(RPC_SVC_CONNMAXREC_SET, &connmaxrec)) {
		syslog(LOG_INFO|LOG_DAEMON,
			"unable to set maximum RPC record size");
	}

	/* Initialize file locking etc. */
	if (!init_lock_system(TRUE))
		/* An detailed error will already have been logged */
		exit(-1);

	return (_main(argc, argv));
}

/*
 * In yptol mode we may start a cache update thread within a child process.
 * It is thus important that child processes do not exit, killing any such
 * threads, before the thread has completed. They must thus call this version
 * of the exit() function.
 */
void
yptol_exit(int status)
{
	if (yptol_mode) {
		thr_join(0, NULL, NULL);
	}
	exit(status);
}

dbmfyl *
getdbm_1_svc(hosereq *argp, struct svc_req *rqstp)
{
	static dbmfyl  result;
	char path[MAXNAMLEN + 1];
	SVCXPRT *xprt;
	int pid;
	int res;
	struct mycon m;
	char *ypname = "ypxfrd";
	struct netbuf *nbuf;
	sa_family_t af;
	in_port_t port;

	xprt = rqstp->rq_xprt;

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

	/*
	 * Build up path name. If we are working in N2L mode also conv
	 * to the new N2L style mapname.
	 *
	 * Do not allow any path as a domain name or map name.
	 */
	if ((strchr(argp->domain, '/') != NULL) ||
		(strchr(argp->map, '/') != NULL) ||
		(!ypmkfilename(argp->domain, argp->map, (char *)&path))) {
		res = GETDBM_ERROR;
		if (!svc_sendreply(rqstp->rq_xprt, xdr_answer,
					(caddr_t)&res)) {
			svcerr_systemerr(rqstp->rq_xprt);
		}
		return (NULL);
	}

	pid = fork1();
	if (pid < 0) {
		perror("fork");

		res = GETDBM_ERROR;
		if (!svc_sendreply(rqstp->rq_xprt, xdr_answer,
					(caddr_t)&res)) {
			svcerr_systemerr(rqstp->rq_xprt);
		}
		return (NULL);
	}
	if (pid != 0)
		return (NULL);

	m.map = (map_ctrl *)shim_dbm_open(path, 0, 0);
	if (m.map == NULL) {
		perror(path);
		res = GETDBM_ERROR;
		if (!svc_sendreply(rqstp->rq_xprt, xdr_answer,
					(caddr_t)&res)) {
		    svcerr_systemerr(rqstp->rq_xprt);
		}
		yptol_exit(0);
		return (NULL);
	}

	/* Do the security thing */
	if ((nbuf = svc_getrpccaller(xprt)) == 0) {
		res = GETDBM_ERROR;
		if (!svc_sendreply(xprt, xdr_answer, (caddr_t)&res)) {
			svcerr_systemerr(xprt);
		}
		shim_dbm_close((DBM *)m.map);
		yptol_exit(0);
		return (NULL);
	}
	if (!check_secure_net_ti(nbuf, ypname)) {
		res = GETDBM_ERROR;
		if (!svc_sendreply(xprt, xdr_answer, (caddr_t)&res)) {
			svcerr_systemerr(xprt);
		}
		shim_dbm_close((DBM *)m.map);
		yptol_exit(1);
		return (NULL);
	}

	af = ((struct sockaddr_storage *)nbuf->buf)->ss_family;
	port = (af == AF_INET6) ?
		((struct sockaddr_in6 *)nbuf->buf)->sin6_port :
		((struct sockaddr_in  *)nbuf->buf)->sin_port;

	if ((af == AF_INET || af == AF_INET6) &&
		(ntohs(port) > IPPORT_RESERVED)) {
		datum key, val;

		key.dptr = yp_secure;
		key.dsize = yp_secure_sz;
		val = shim_dbm_fetch((DBM *)m.map, key);
		if (val.dptr != NULL) {
			res = GETDBM_ERROR;
			if (!svc_sendreply(xprt, xdr_answer, (caddr_t)&res)) {
				svcerr_systemerr(xprt);
			}
			shim_dbm_close((DBM *)m.map);
			yptol_exit(1);
			return (NULL);
		}
	}

	/* OK, we're through */
	m.key = shim_dbm_firstkey((DBM *)m.map);

	m.lblk = -1;
	m.firstd = 0;

	if (!svc_sendreply(rqstp->rq_xprt, xdr_myfyl, (caddr_t)&m)) {
		svcerr_systemerr(rqstp->rq_xprt);
	}
	shim_dbm_close((DBM *)m.map);
	yptol_exit(0);

	return (&result);
}

bool_t
xdr_myfyl(XDR *xdrs, struct mycon *objp)
{
	int	ans = OK;

	if (!xdr_answer(xdrs, (answer *) &ans))
		return (FALSE);
	if (!xdr_pages(xdrs, objp))
		return (FALSE);
	if (!xdr_dirs(xdrs, objp))
		return (FALSE);

	return (TRUE);
}

bool_t
xdr_pages(XDR *xdrs, struct mycon *m)
{
	static	struct pag res;
	bool_t	false = FALSE;
	bool_t	true = TRUE;
#ifdef DOSWAB
	short	*s;
	int	i;
	int	cnt;
#endif
	res.status = mygetpage(res.pag_u.ok.blkdat, &(res.pag_u.ok.blkno), m);

#ifdef DOSWAB
	if (res.status == OK) {
		s = (short *)res.pag_u.ok.blkdat;
		cnt = s[0];
		for (i = 0; i <= cnt; i++)
			s[i] = ntohs(s[i]);
	}
#endif

	if (!xdr_pag(xdrs, &res))
		return (FALSE);

	while (res.status == OK) {
		if (!xdr_bool(xdrs, &true))
			return (FALSE);
		res.status = mygetpage(res.pag_u.ok.blkdat,
					&(res.pag_u.ok.blkno), m);

#ifdef DOSWAB
		if (res.status == OK) {
			s = (short *)res.pag_u.ok.blkdat;
			cnt = s[0];
			for (i = 0; i <= cnt; i++)
				s[i] = ntohs(s[i]);
		}
#endif

		if (!xdr_pag(xdrs, &res))
			return (FALSE);
	}

	return (xdr_bool(xdrs, &false));
}

int
mygetdir(char *block, int *no, struct mycon *m)
{
	int	status;
	int	len;

	if (m->firstd == 0) {
		lseek(m->map->entries->dbm_dirf, 0, 0);
		m->firstd = 1;
	} else
		m->firstd++;

	len = read(m->map->entries->dbm_dirf, block, DBLKSIZ);
	*no = (m->firstd) - 1;
	status = OK;

	/*
	 * printf("dir block %d\n", (m->firstd) - 1);
	 */

	if (len < 0) {
		perror("read directory");
		status = GETDBM_ERROR;
	} else if (len == 0) {
		status = GETDBM_EOF;
		/*
		 * printf("dir EOF\n");
		 */
	}
	return (status);
}

bool_t
xdr_dirs(XDR *xdrs, struct mycon *m)
{
	static	struct dir res;
	bool_t	false = FALSE;
	bool_t	true = TRUE;

	res.status = mygetdir(res.dir_u.ok.blkdat, &(res.dir_u.ok.blkno), m);

	if (!xdr_dir(xdrs, &res))
		return (FALSE);

	while (res.status == OK) {
		if (!xdr_bool(xdrs, &true))
			return (FALSE);
		res.status = mygetdir(res.dir_u.ok.blkdat,
					&(res.dir_u.ok.blkno), m);
		if (!xdr_dir(xdrs, &res))
			return (FALSE);
	}

	return (xdr_bool(xdrs, &false));
}

int
mygetpage(char *block, int *pageno, struct mycon *m)
{

	for (; m->key.dptr;
			m->key = shim_dbm_do_nextkey((DBM *)m->map, m->key)) {

		if (m->map->entries->dbm_pagbno != m->lblk) {
			/*
			 * printf("block=%d lblk=%d\n",
			 *		m->map->entries->dbm_pagbno,
			 * 		m->lblk);
			 */
			m->lblk = m->map->entries->dbm_pagbno;
			*pageno = m->lblk;
			memmove(block, m->map->entries->dbm_pagbuf, PBLKSIZ);
			/* advance key on first  try	*/
			m->key = mydbm_topkey(m->map->entries, m->key);
			m->key = shim_dbm_do_nextkey((DBM *)m->map, m->key);
			return (OK);
		}
	}
	/*
	 * printf("EOF\n");
	 */
	return (GETDBM_EOF);
}

datum
mydbm_topkey(DBM *db, datum okey)
{
	datum		ans;
	datum		tmp;
	register char	*buf;
	int		n;
	register short	*sp;
	register short 	t;
	datum		item;
#if defined(_XPG4_2)
	register size_t	m;
#else
	register long	m;
#endif
	register char	*p1, *p2;

	buf = db->dbm_pagbuf;
	sp = (short *)buf;
	/* find the maximum key in cmpdatum order */

	if ((unsigned)0 >= sp[0]) {
		return (okey);
	} else {
		ans.dptr = buf + sp[1];
		ans.dsize = PBLKSIZ - sp[1];
	}
	for (n = 2; ; n += 2) {
		if ((unsigned)n >= sp[0]) {
			if (ans.dptr == NULL) {
				return (okey);
			} else {
				return (ans);
			}
		} else {
			t = PBLKSIZ;
			if (n > 0)
				t = sp[n];
			tmp.dptr = buf + sp[n + 1];
			tmp.dsize = t - sp[n + 1];
		}

		m = tmp.dsize;
		if (m != ans.dsize) {
			if ((m - ans.dsize) < 0)
				ans = tmp;
		} else if (m == 0) {
		} else {
			p1 = tmp.dptr;
			p2 = ans.dptr;
			do
				if (*p1++ != *p2++) {
					if ((*--p1 - *--p2) < 0)
						ans = tmp;
				break;
				}
			while (--m);
		}
	}
}
