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
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
 * rpcbind.h
 * The common header declarations
 */

#ifndef _RPCBIND_H
#define	_RPCBIND_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef PORTMAP
#include <rpc/pmap_prot.h>
#endif
#include <rpc/rpcb_prot.h>
#include <signal.h>

#include <tcpd.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern int debugging;
extern int doabort;
extern rpcblist_ptr list_rbl;	/* A list of version 3 & 4 rpcbind services */
extern char *loopback_dg;	/* CLTS loopback transport, for set/unset */
extern char *loopback_vc;	/* COTS loopback transport, for set/unset */
extern char *loopback_vc_ord;	/* COTS_ORD loopback transport, for set/unset */
extern volatile sig_atomic_t sigrefresh; /* Did we receive a SIGHUP recently? */

#ifdef PORTMAP
extern pmaplist *list_pml;	/* A list of version 2 rpcbind services */
extern char *udptrans;		/* Name of UDP transport */
extern char *tcptrans;		/* Name of TCP transport */
extern char *udp_uaddr;		/* Universal UDP address */
extern char *tcp_uaddr;		/* Universal TCP address */
#endif

extern char *mergeaddr();
extern int add_bndlist();
extern int create_rmtcall_fd();
extern bool_t is_bound();
extern void my_svc_run();
extern void rpcb_check_init(void);

/* TCP wrapper functions and variables. */
extern boolean_t localxprt(SVCXPRT *, boolean_t);
extern void qsyslog(int pri, const char *fmt, ...);
extern boolean_t rpcb_check(SVCXPRT *, rpcproc_t, boolean_t);
extern void rpcb_log(boolean_t, SVCXPRT *, rpcproc_t, rpcprog_t, boolean_t);
extern boolean_t allow_indirect, wrap_enabled, verboselog, local_only;

#define	svc_getgencaller(transp) \
	((struct sockaddr_gen *)svc_getrpccaller((transp))->buf)

#define	RPCB_CHECK(xprt, proc) \
	if ((wrap_enabled || local_only) && \
	    !rpcb_check((xprt), (proc), B_FALSE)) \
		return

#define	PMAP_CHECK(xprt, proc) \
	if ((wrap_enabled || local_only) && \
	    !rpcb_check((xprt), (proc), B_TRUE)) \
		return

#define	PMAP_CHECK_RET(xprt, proc, ret) \
	if ((wrap_enabled || local_only) && \
	    !rpcb_check((xprt), (proc), B_TRUE)) \
		return (ret)

#define	RPCB_LOG(xprt, proc, prog) \
	if (wrap_enabled) \
	    rpcb_log(B_TRUE, (xprt), (proc), (prog), B_FALSE)

#define	PMAP_LOG(ans, xprt, proc, prog) \
	if (wrap_enabled) \
	    rpcb_log(ans, (xprt), (proc), (prog), B_TRUE)

extern bool_t map_set(), map_unset();

/* Statistics gathering functions */
extern void rpcbs_procinfo();
extern void rpcbs_set();
extern void rpcbs_unset();
extern void rpcbs_getaddr();
extern void rpcbs_rmtcall();
extern rpcb_stat_byvers *rpcbproc_getstat();

extern struct netconfig *rpcbind_get_conf();
extern void rpcbind_abort() __NORETURN;

/* Common functions shared between versions */
extern void rpcbproc_callit_com();
extern bool_t *rpcbproc_set_com();
extern bool_t *rpcbproc_unset_com();
extern ulong_t *rpcbproc_gettime_com();
extern struct netbuf *rpcbproc_uaddr2taddr_com();
extern char **rpcbproc_taddr2uaddr_com();
extern char **rpcbproc_getaddr_com();
extern void delete_prog();

extern uid_t rpcb_caller_uid(SVCXPRT *);

/* For different getaddr semantics */
#define	RPCB_ALLVERS 0
#define	RPCB_ONEVERS 1

#ifdef	__cplusplus
}
#endif

#endif /* _RPCBIND_H */
