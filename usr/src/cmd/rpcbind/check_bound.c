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
 *
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
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
 * check_bound.c
 * Checks to see whether the program is still bound to the
 * claimed address and returns the univeral merged address
 *
 */

#include <stdio.h>
#include <rpc/rpc.h>
#include <netconfig.h>
#include <netdir.h>
#include <sys/syslog.h>
#include <stdlib.h>
#include "rpcbind.h"
#include <string.h>
/* the following just to get my address */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <thread.h>
#include <synch.h>
#include <syslog.h>

struct fdlist {
	int fd;
	mutex_t fd_lock;	/* protects fd */
	struct netconfig *nconf;
	struct fdlist *next;
	int check_binding;
};

static struct fdlist *fdhead;	/* Link list of the check fd's */
static struct fdlist *fdtail;
static char *nullstring = "";

/*
 * Returns 1 if the given address is bound for the given addr & transport
 * For all error cases, we assume that the address is bound
 * Returns 0 for success.
 *
 * fdl: My FD list
 * uaddr: the universal address
 */
static bool_t
check_bound(struct fdlist *fdl, char *uaddr)
{
	int fd;
	struct netbuf *na;
	struct t_bind taddr, *baddr;
	int ans;

	if (fdl->check_binding == FALSE)
		return (TRUE);

	na = uaddr2taddr(fdl->nconf, uaddr);
	if (!na)
		return (TRUE); /* punt, should never happen */

	taddr.addr = *na;
	taddr.qlen = 1;
	(void) mutex_lock(&fdl->fd_lock);
	fd = fdl->fd;
	baddr = (struct t_bind *)t_alloc(fd, T_BIND, T_ADDR);
	if (baddr == NULL) {
		(void) mutex_unlock(&fdl->fd_lock);
		netdir_free((char *)na, ND_ADDR);
		return (TRUE);
	}
	if (t_bind(fd, &taddr, baddr) != 0) {
		(void) mutex_unlock(&fdl->fd_lock);
		netdir_free((char *)na, ND_ADDR);
		(void) t_free((char *)baddr, T_BIND);
		return (TRUE);
	}
	if (t_unbind(fd) != 0) {
		/* Bad fd. Purge this fd */
		(void) t_close(fd);
		fdl->fd = t_open(fdl->nconf->nc_device, O_RDWR, NULL);
		if (fdl->fd == -1)
			fdl->check_binding = FALSE;
	}
	(void) mutex_unlock(&fdl->fd_lock);
	ans = memcmp(taddr.addr.buf, baddr->addr.buf, baddr->addr.len);
	netdir_free((char *)na, ND_ADDR);
	(void) t_free((char *)baddr, T_BIND);
	return (ans == 0 ? FALSE : TRUE);
}

/*
 * Keep open one more file descriptor for this transport, which
 * will be used to determine whether the given service is up
 * or not by trying to bind to the registered address.
 * We are ignoring errors here. It trashes taddr and baddr;
 * but that perhaps should not matter.
 *
 * We check for the following conditions:
 *	1. Is it possible for t_bind to fail in the case where
 *		we bind to an already bound address and have any
 *		other error number besides TNOADDR.
 *	2. If an address is specified in bind addr, can I bind to
 *		the same address.
 *	3. If NULL is specified in bind addr, can I bind to the
 *		address to which the fd finally got bound.
 */
int
add_bndlist(struct netconfig *nconf, struct t_bind *taddr, struct t_bind *baddr)
{
	int fd;
	struct fdlist *fdl;
	struct netconfig *newnconf;
	struct t_info tinfo;
	struct t_bind tmpaddr;

	newnconf = getnetconfigent(nconf->nc_netid);
	if (newnconf == NULL)
		return (-1);
	fdl = (struct fdlist *)malloc((uint_t)sizeof (struct fdlist));
	if (fdl == NULL) {
		freenetconfigent(newnconf);
		syslog(LOG_ERR, "no memory!");
		return (-1);
	}
	(void) mutex_init(&fdl->fd_lock, USYNC_THREAD, NULL);
	fdl->nconf = newnconf;
	fdl->next = NULL;
	if (fdhead == NULL) {
		fdhead = fdl;
		fdtail = fdl;
	} else {
		fdtail->next = fdl;
		fdtail = fdl;
	}
	fdl->check_binding = FALSE;
	if ((fdl->fd = t_open(nconf->nc_device, O_RDWR, &tinfo)) < 0) {
		/*
		 * Note that we haven't dequeued this entry nor have we freed
		 * the netconfig structure.
		 */
		if (debugging) {
			fprintf(stderr,
			    "%s: add_bndlist cannot open connection: %s",
			    nconf->nc_netid, t_errlist[t_errno]);
		}
		return (-1);
	}

	/* Set the qlen only for cots transports */
	switch (tinfo.servtype) {
	case T_COTS:
	case T_COTS_ORD:
		taddr->qlen = 1;
		break;
	case T_CLTS:
		taddr->qlen = 0;
		break;
	default:
		goto error;
	}

	if (t_bind(fdl->fd, taddr, baddr) != 0) {
		if (t_errno == TNOADDR) {
			fdl->check_binding = TRUE;
			return (0);	/* All is fine */
		}
		/* Perhaps condition #1 */
		if (debugging) {
			fprintf(stderr, "%s: add_bndlist cannot bind (1): %s",
			    nconf->nc_netid, t_errlist[t_errno]);
		}
		goto not_bound;
	}

	/* Condition #2 */
	if (!memcmp(taddr->addr.buf, baddr->addr.buf,
	    (int)baddr->addr.len)) {
		goto not_bound;
	}

	/* Condition #3 */
	t_unbind(fdl->fd);
	/* Set the qlen only for cots transports */
	switch (tinfo.servtype) {
	case T_COTS:
	case T_COTS_ORD:
		tmpaddr.qlen = 1;
		break;
	case T_CLTS:
		tmpaddr.qlen = 0;
		break;
	default:
		goto error;
	}
	tmpaddr.addr.len = tmpaddr.addr.maxlen = 0;
	tmpaddr.addr.buf = NULL;
	if (t_bind(fdl->fd, &tmpaddr, taddr) != 0) {
		if (debugging) {
			fprintf(stderr, "%s: add_bndlist cannot bind (2): %s",
			    nconf->nc_netid, t_errlist[t_errno]);
		}
		goto error;
	}
	/* Now fdl->fd is bound to a transport chosen address */
	if ((fd = t_open(nconf->nc_device, O_RDWR, &tinfo)) < 0) {
		if (debugging) {
			fprintf(stderr,
			    "%s: add_bndlist cannot open connection: %s",
			    nconf->nc_netid, t_errlist[t_errno]);
		}
		goto error;
	}
	if (t_bind(fd, taddr, baddr) != 0) {
		if (t_errno == TNOADDR) {
			/*
			 * This transport is schizo.  Previously it handled a
			 * request to bind to an already bound transport by
			 * returning a different bind address, and now it's
			 * returning a TNOADDR for essentially the same
			 * request.  The spec may allow this behavior, so
			 * we'll just assume we can't do bind checking with
			 * this transport.
			 */
			t_close(fd);
			goto not_bound;
		}
		if (debugging) {
			fprintf(stderr, "%s: add_bndlist cannot bind (3): %s",
			    nconf->nc_netid, t_errlist[t_errno]);
		}
		t_close(fd);
		goto error;
	}
	t_close(fd);
	if (!memcmp(taddr->addr.buf, baddr->addr.buf,
	    (int)baddr->addr.len)) {
		switch (tinfo.servtype) {
		case T_COTS:
		case T_COTS_ORD:
			if (baddr->qlen == 1) {
				goto not_bound;
			}
			break;
		case T_CLTS:
			goto not_bound;
		default:
			goto error;
		}
	}

	t_unbind(fdl->fd);
	fdl->check_binding = TRUE;
	return (0);

not_bound:
	t_close(fdl->fd);
	fdl->fd = -1;
	return (1);

error:
	t_close(fdl->fd);
	fdl->fd = -1;
	return (-1);
}

bool_t
is_bound(char *netid, char *uaddr)
{
	struct fdlist *fdl;

	for (fdl = fdhead; fdl; fdl = fdl->next)
		if (strcmp(fdl->nconf->nc_netid, netid) == 0)
			break;
	if (fdl == NULL)
		return (TRUE);
	return (check_bound(fdl, uaddr));
}

/* Return pointer to port string in the universal address */
#define	UADDR_PRT_INDX(UADDR, PORT) { \
	PORT = strrchr(UADDR, '.'); \
	while (*--PORT != '.'); }
/*
 * Returns NULL if there was some system error.
 * Returns "" if the address was not bound, i.e the server crashed.
 * Returns the merged address otherwise.
 */
char *
mergeaddr(SVCXPRT *xprt, char *netid, char *uaddr, char *saddr)
{
	struct fdlist *fdl;
	struct nd_mergearg ma;
	int stat;

	for (fdl = fdhead; fdl; fdl = fdl->next)
		if (strcmp(fdl->nconf->nc_netid, netid) == 0)
			break;
	if (fdl == NULL)
		return (NULL);
	if (check_bound(fdl, uaddr) == FALSE)
		/* that server died */
		return (nullstring);
	/*
	 * If saddr is not NULL, the remote client may have included the
	 * address by which it contacted us.  Use that for the "client" uaddr,
	 * otherwise use the info from the SVCXPRT.
	 */
	if (saddr != NULL) {
		ma.c_uaddr = saddr;
	} else {

		/* retrieve the client's address */
		ma.c_uaddr = taddr2uaddr(fdl->nconf, svc_getrpccaller(xprt));
		if (ma.c_uaddr == NULL) {
			syslog(LOG_ERR, "taddr2uaddr failed for %s: %s",
			    fdl->nconf->nc_netid, netdir_sperror());
			return (NULL);
		}

	}

	/* Not an INET address? */
	if ((strcmp(fdl->nconf->nc_protofmly, NC_INET) != 0) &&
	    (strcmp(fdl->nconf->nc_protofmly, NC_INET6) != 0)) {
		ma.s_uaddr = uaddr;
		stat = netdir_options(fdl->nconf, ND_MERGEADDR, 0, (char *)&ma);
	}
	/* Inet address, but no xp_ltaddr */
	else if ((ma.s_uaddr = taddr2uaddr(fdl->nconf,
	    &(xprt)->xp_ltaddr)) == NULL) {
		ma.s_uaddr = uaddr;
		stat = netdir_options(fdl->nconf, ND_MERGEADDR, 0, (char *)&ma);
	} else {
		/*
		 * (xprt)->xp_ltaddr contains portmap's port address.
		 * Overwrite this with actual application's port address
		 * before returning to the caller.
		 */
		char *s_uport, *uport;

		/* Get the INET/INET6 address part from ma.s_uaddr */
		UADDR_PRT_INDX(ma.s_uaddr, s_uport);
		*s_uport = '\0';

		/* Get the port info from uaddr */
		UADDR_PRT_INDX(uaddr, uport);

		ma.m_uaddr = malloc(strlen(ma.s_uaddr) + strlen(uport) + 1);
		if (ma.m_uaddr == NULL) {
			syslog(LOG_ERR, "mergeaddr: no memory!");
			free(ma.s_uaddr);
			if (saddr == NULL)
				free(ma.c_uaddr);
			return (NULL);
		}

		/* Copy IP address into the Universal address holder */
		strcpy(ma.m_uaddr, ma.s_uaddr);
		/* Append port info to the Universal address holder */
		strcat(ma.m_uaddr, uport);
		free(ma.s_uaddr);
		stat = 0;
	}
	if (saddr == NULL) {
		free(ma.c_uaddr);
	}
	if (stat) {
		syslog(LOG_ERR, "netdir_merge failed for %s: %s",
		    fdl->nconf->nc_netid, netdir_sperror());
		return (NULL);
	}

	return (ma.m_uaddr);
}

/*
 * Returns a netconf structure from its internal list.  This
 * structure should not be freed.
 */
struct netconfig *
rpcbind_get_conf(char *netid)
{
	struct fdlist *fdl;

	for (fdl = fdhead; fdl; fdl = fdl->next)
		if (strcmp(fdl->nconf->nc_netid, netid) == 0)
			break;
	if (fdl == NULL)
		return (NULL);
	return (fdl->nconf);
}
