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
 * rpcbind.h
 * The common header declarations
 */

#ifndef _RPCBIND_H
#define	_RPCBIND_H

#ifdef PORTMAP
#include <rpc/pmap_prot.h>
#endif
#include <rpc/rpcb_prot.h>
#include <synch.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern int debugging;
extern int doabort;
extern rwlock_t list_rbl_lock;	/* Protects list_rbl */
extern rpcblist_ptr list_rbl;	/* A list of version 3 & 4 rpcbind services */
extern char *loopback_dg;	/* CLTS loopback transport, for set/unset */
extern char *loopback_vc;	/* COTS loopback transport, for set/unset */
extern char *loopback_vc_ord;	/* COTS_ORD loopback transport, for set/unset */

#ifdef PORTMAP
extern rwlock_t list_pml_lock;	/* Protects list_pml */
extern pmaplist *list_pml;	/* A list of version 2 rpcbind services */
extern char *udptrans;		/* Name of UDP transport */
extern char *tcptrans;		/* Name of TCP transport */
extern char *udp_uaddr;		/* Universal UDP address */
extern char *tcp_uaddr;		/* Universal TCP address */
#endif

char *mergeaddr(SVCXPRT *, char *, char *, char *);
int add_bndlist(struct netconfig *, struct t_bind *, struct t_bind *);
int create_rmtcall_fd(struct netconfig *);
bool_t is_bound(char *, char *);
void set_rpcb_rmtcalls_max(int);

/* TCP wrapper functions and variables. */
boolean_t localxprt(SVCXPRT *, boolean_t);
void qsyslog(int pri, const char *fmt, ...);
boolean_t rpcb_check(SVCXPRT *, rpcproc_t, boolean_t);
void rpcb_log(boolean_t, SVCXPRT *, rpcproc_t, rpcprog_t, boolean_t);
extern volatile boolean_t allow_indirect;
extern volatile boolean_t wrap_enabled;
extern volatile boolean_t verboselog;
extern volatile boolean_t local_only;

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

bool_t map_set(RPCB *, char *);
bool_t map_unset(RPCB *, char *);

/* Statistics gathering functions */
void rpcbs_procinfo(int, rpcproc_t);
void rpcbs_set(int, bool_t);
void rpcbs_unset(int, bool_t);
void rpcbs_getaddr(int, rpcprog_t, rpcvers_t, char *, char *);
void rpcbs_rmtcall(int, rpcproc_t, rpcprog_t, rpcvers_t, rpcproc_t, char *,
    rpcblist_ptr);
bool_t rpcbproc_getstat(void *, rpcb_stat_byvers **);
bool_t xdr_rpcb_stat_byvers_ptr(XDR *, rpcb_stat_byvers **);

struct netconfig *rpcbind_get_conf();
void rpcbind_abort() __NORETURN;

#ifdef PORTMAP
void pmap_service(struct svc_req *, SVCXPRT *xprt);
#endif
void rpcb_service_3(struct svc_req *, SVCXPRT *xprt);
void rpcb_service_4(struct svc_req *, SVCXPRT *xprt);
void read_warmstart(void);
void write_warmstart(void);
int Is_ipv6present(void);

extern zoneid_t myzone;

/* Common functions shared between versions */
void rpcbproc_callit_com(struct svc_req *, SVCXPRT *, ulong_t, int);
bool_t rpcbproc_set_com(RPCB *, bool_t *, struct svc_req *, int);
bool_t rpcbproc_unset_com(RPCB *, bool_t *, struct svc_req *, int);
bool_t rpcbproc_gettime_com(void *, ulong_t *);
bool_t rpcbproc_uaddr2taddr_com(char **, struct netbuf *, struct svc_req *);
bool_t rpcbproc_taddr2uaddr_com(struct netbuf *, char **, struct svc_req *);
bool_t rpcbproc_getaddr_com(RPCB *, char **, struct svc_req *, ulong_t);
void delete_prog(rpcprog_t);
bool_t rpcbproc_dump_com(void *, rpcblist_ptr **);
char *getowner(SVCXPRT *, char *);

int del_pmaplist(RPCB *);
void delete_rbl(rpcblist_ptr);

uid_t rpcb_caller_uid(SVCXPRT *);

/* XDR functions */
bool_t xdr_rpcblist_ptr_ptr(XDR *, rpcblist_ptr **);

/* For different getaddr semantics */
#define	RPCB_ALLVERS 0
#define	RPCB_ONEVERS 1

#ifdef	__cplusplus
}
#endif

#endif /* _RPCBIND_H */
