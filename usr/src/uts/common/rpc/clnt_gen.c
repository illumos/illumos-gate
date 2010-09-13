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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/types.h>
#include <rpc/types.h>
#include <netinet/in.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <sys/tiuser.h>
#include <sys/t_kuser.h>
#include <rpc/svc.h>
#include <rpc/xdr.h>
#include <sys/file.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/stream.h>
#include <sys/tihdr.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>

#define	NC_INET		"inet"

#define	MAX_PRIV	(IPPORT_RESERVED-1)
#define	MIN_PRIV	(IPPORT_RESERVED/2)

ushort_t clnt_udp_last_used = MIN_PRIV;
ushort_t clnt_tcp_last_used = MIN_PRIV;

/*
 * PSARC 2003/523 Contract Private Interface
 * clnt_tli_kcreate
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 */
int
clnt_tli_kcreate(
	struct knetconfig	*config,
	struct netbuf		*svcaddr,	/* Servers address */
	rpcprog_t		prog,		/* Program number */
	rpcvers_t		vers,		/* Version number */
	uint_t			max_msgsize,
	int			retries,
	struct cred		*cred,
	CLIENT			**ncl)
{
	CLIENT			*cl;		/* Client handle */
	int			error;
	int			family = AF_UNSPEC;

	error = 0;
	cl = NULL;

	RPCLOG(8, "clnt_tli_kcreate: prog %x", prog);
	RPCLOG(8, ", vers %d", vers);
	RPCLOG(8, ", knc_semantics %d", config->knc_semantics);
	RPCLOG(8, ", knc_protofmly %s", config->knc_protofmly);
	RPCLOG(8, ", knc_proto %s\n", config->knc_proto);

	if (config == NULL || config->knc_protofmly == NULL || ncl == NULL) {
		RPCLOG0(1, "clnt_tli_kcreate: bad config or handle\n");
		return (EINVAL);
	}

	switch (config->knc_semantics) {
	case NC_TPI_CLTS:
		RPCLOG0(8, "clnt_tli_kcreate: CLTS selected\n");
		error = clnt_clts_kcreate(config, svcaddr, prog, vers,
						retries, cred, &cl);
		if (error != 0) {
			RPCLOG(1,
			"clnt_tli_kcreate: clnt_clts_kcreate failed error %d\n",
			    error);
			return (error);
		}
		break;

	case NC_TPI_COTS:
	case NC_TPI_COTS_ORD:
		RPCLOG0(8, "clnt_tli_kcreate: COTS selected\n");
		if (strcmp(config->knc_protofmly, NC_INET) == 0)
			family = AF_INET;
		else if (strcmp(config->knc_protofmly, NC_INET6) == 0)
			family = AF_INET6;
		error = clnt_cots_kcreate(config->knc_rdev, svcaddr, family,
		    prog, vers, max_msgsize, cred, &cl);
		if (error != 0) {
			RPCLOG(1,
			"clnt_tli_kcreate: clnt_cots_kcreate failed error %d\n",
			error);
			return (error);
		}
		break;
	case NC_TPI_RDMA:
		RPCLOG0(8, "clnt_tli_kcreate: RDMA selected\n");
		/*
		 * RDMA doesn't support TSOL. It's better to
		 * disallow it here.
		 */
		if (is_system_labeled()) {
			RPCLOG0(1, "clnt_tli_kcreate: tsol not supported\n");
			return (EPROTONOSUPPORT);
		}

		if (strcmp(config->knc_protofmly, NC_INET) == 0)
			family = AF_INET;
		else if (strcmp(config->knc_protofmly, NC_INET6) == 0)
			family = AF_INET6;
		error = clnt_rdma_kcreate(config->knc_proto,
		    (void *)config->knc_rdev, svcaddr, family, prog, vers, cred,
		    &cl);
		if (error != 0) {
			RPCLOG(1,
			"clnt_tli_kcreate: clnt_rdma_kcreate failed error %d\n",
			error);
			return (error);
		}
		break;
	default:
		error = EINVAL;
		RPCLOG(1, "clnt_tli_kcreate: Bad service type %d\n",
		    config->knc_semantics);
		return (error);
	}
	*ncl = cl;
	return (0);
}

/*
 * "Kinit" a client handle by calling the appropriate cots or clts routine.
 *
 * PSARC 2003/523 Contract Private Interface
 * clnt_tli_kinit
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 */
int
clnt_tli_kinit(
	CLIENT		*h,
	struct knetconfig *config,
	struct netbuf	*addr,
	uint_t		max_msgsize,
	int		retries,
	struct cred	*cred)
{
	int error = 0;
	int family = AF_UNSPEC;

	switch (config->knc_semantics) {
	case NC_TPI_CLTS:
		clnt_clts_kinit(h, addr, retries, cred);
		break;
	case NC_TPI_COTS:
	case NC_TPI_COTS_ORD:
		RPCLOG0(2, "clnt_tli_kinit: COTS selected\n");
		if (strcmp(config->knc_protofmly, NC_INET) == 0)
			family = AF_INET;
		else if (strcmp(config->knc_protofmly, NC_INET6) == 0)
			family = AF_INET6;
		clnt_cots_kinit(h, config->knc_rdev, family,
		    addr, max_msgsize, cred);
		break;
	case NC_TPI_RDMA:
		RPCLOG0(2, "clnt_tli_kinit: RDMA selected\n");
		clnt_rdma_kinit(h, config->knc_proto,
		    (void *)config->knc_rdev, addr, cred);
		break;
	default:
		error = EINVAL;
	}

	return (error);
}


/*
 * try to bind to a reserved port
 */
int
bindresvport(
	TIUSER		*tiptr,
	struct netbuf	*addr,
	struct netbuf	*bound_addr,
	bool_t		tcp)
{
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;
	bool_t 			ipv6_flag = 0;
	int			i;
	struct t_bind		*req;
	struct t_bind		*ret;
	int			error;
	bool_t			loop_twice;
	int			start;
	int			stop;
	ushort_t			*last_used;

	if ((error = t_kalloc(tiptr, T_BIND, T_ADDR, (char **)&req)) != 0) {
		RPCLOG(1, "bindresvport: t_kalloc %d\n", error);
		return (error);
	}

	if ((error = t_kalloc(tiptr, T_BIND, T_ADDR, (char **)&ret)) != 0) {
		RPCLOG(1, "bindresvport: t_kalloc %d\n", error);
		(void) t_kfree(tiptr, (char *)req, T_BIND);
		return (error);
	}

	/* now separate IPv4 and IPv6 by looking at len of tiptr.addr */
	if (tiptr->tp_info.addr == sizeof (struct sockaddr_in6)) {
		/* it's IPv6 */
		ipv6_flag = 1;
		sin6 = (struct sockaddr_in6 *)req->addr.buf;
		sin6->sin6_family = AF_INET6;
		bzero((char *)&sin6->sin6_addr, sizeof (struct in6_addr));
		req->addr.len = sizeof (struct sockaddr_in6);
	} else {
		/* LINTED pointer alignment */
		sin = (struct sockaddr_in *)req->addr.buf;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = INADDR_ANY;
		req->addr.len = sizeof (struct sockaddr_in);
	}

	/*
	 * Caller wants to bind to a specific port, so don't bother with the
	 * loop that binds to the next free one.
	 */
	if (addr) {
		if (ipv6_flag) {
			sin6->sin6_port =
				((struct sockaddr_in6 *)addr->buf)->sin6_port;
		} else {
			sin->sin_port =
				((struct sockaddr_in *)addr->buf)->sin_port;
		}
		RPCLOG(8, "bindresvport: calling t_kbind tiptr = %p\n",
		    (void *)tiptr);
		if ((error = t_kbind(tiptr, req, ret)) != 0) {
			RPCLOG(1, "bindresvport: t_kbind: %d\n", error);
			/*
			 * The unbind is called in case the bind failed
			 * with an EINTR potentially leaving the
			 * transport in bound state.
			 */
			if (error == EINTR)
				(void) t_kunbind(tiptr);
		} else if (bcmp(req->addr.buf, ret->addr.buf,
				ret->addr.len) != 0) {
			RPCLOG0(1, "bindresvport: bcmp error\n");
			(void) t_kunbind(tiptr);
			error = EADDRINUSE;
		}
	} else {
		if (tcp)
			last_used = &clnt_tcp_last_used;
		else
			last_used = &clnt_udp_last_used;
		error = EADDRINUSE;
		stop = MIN_PRIV;

		start = (*last_used == MIN_PRIV ? MAX_PRIV : *last_used - 1);
		loop_twice = (start < MAX_PRIV ? TRUE : FALSE);

bindresvport_again:
		for (i = start;
		    (error == EADDRINUSE || error == EADDRNOTAVAIL) &&
		    i >= stop; i--) {
			if (ipv6_flag)
				sin6->sin6_port = htons(i);
			else
				sin->sin_port = htons(i);
			RPCLOG(8, "bindresvport: calling t_kbind tiptr = 0%p\n",
			    (void *)tiptr);
			if ((error = t_kbind(tiptr, req, ret)) != 0) {
				RPCLOG(1, "bindresvport: t_kbind: %d\n", error);
				/*
				 * The unbind is called in case the bind failed
				 * with an EINTR potentially leaving the
				 * transport in bound state.
				 */
				if (error == EINTR)
					(void) t_kunbind(tiptr);
			} else if (bcmp(req->addr.buf, ret->addr.buf,
			    ret->addr.len) != 0) {
				RPCLOG0(1, "bindresvport: bcmp error\n");
				(void) t_kunbind(tiptr);
				error = EADDRINUSE;
			} else
				error = 0;
		}
		if (!error) {
			if (ipv6_flag) {
				RPCLOG(8, "bindresvport: port assigned %d\n",
					sin6->sin6_port);
				*last_used = ntohs(sin6->sin6_port);
			} else {
				RPCLOG(8, "bindresvport: port assigned %d\n",
					sin->sin_port);
				*last_used = ntohs(sin->sin_port);
			}
		} else if (loop_twice) {
			loop_twice = FALSE;
			start = MAX_PRIV;
			stop = *last_used + 1;
			goto bindresvport_again;
		}
	}

	if (!error && bound_addr) {
		if (bound_addr->maxlen < ret->addr.len) {
			kmem_free(bound_addr->buf, bound_addr->maxlen);
			bound_addr->buf = kmem_zalloc(ret->addr.len, KM_SLEEP);
			bound_addr->maxlen = ret->addr.len;
		}
		bcopy(ret->addr.buf, bound_addr->buf, ret->addr.len);
		bound_addr->len = ret->addr.len;
	}
	(void) t_kfree(tiptr, (char *)req, T_BIND);
	(void) t_kfree(tiptr, (char *)ret, T_BIND);
	return (error);
}

void
clnt_init(void)
{
	clnt_cots_init();
	clnt_clts_init();
}

void
clnt_fini(void)
{
	clnt_clts_fini();
	clnt_cots_fini();
}

call_table_t *
call_table_init(int size)
{
	call_table_t *ctp;
	int i;

	ctp = kmem_alloc(sizeof (call_table_t) * size, KM_SLEEP);

	for (i = 0; i < size; i++) {
		ctp[i].ct_call_next = (calllist_t *)&ctp[i];
		ctp[i].ct_call_prev = (calllist_t *)&ctp[i];
		mutex_init(&ctp[i].ct_lock, NULL, MUTEX_DEFAULT, NULL);
		ctp[i].ct_len = 0;
	}

	return (ctp);
}
