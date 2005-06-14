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
%/*
% * Copyright (c) 1984,1989 by Sun Microsystems, Inc.
% */

%/* from pmap_prot.x */

#ifdef RPC_HDR
%
%#pragma ident	"%Z%%M%	%I%	%E% SMI"
%
%#ifndef _KERNEL
%
#endif

/*
 * Port Mapper Protocol Specification (in RPC Language)
 * derived from RFC 1057
 */

%/*
% * Protocol for the local binder service, or pmap.
% *
% * Copyright (C) 1984, Sun Microsystems, Inc.
% *
% * The following procedures are supported by the protocol:
% *
% * PMAPPROC_NULL() returns ()
% * 	takes nothing, returns nothing
% *
% * PMAPPROC_SET(struct pmap) returns (bool_t)
% * 	TRUE is success, FALSE is failure.  Registers the tuple
% *	[prog, vers, prot, port].
% *
% * PMAPPROC_UNSET(struct pmap) returns (bool_t)
% *	TRUE is success, FALSE is failure.  Un-registers pair
% *	[prog, vers].  prot and port are ignored.
% *
% * PMAPPROC_GETPORT(struct pmap) returns (rpcport_t).
% *	0 is failure.  Otherwise returns the port number where the pair
% *	[prog, vers] is registered.  It may lie!
% *
% * PMAPPROC_DUMP() RETURNS (struct pmaplist_ptr)
% *
% * PMAPPROC_CALLIT(unsigned, unsigned, unsigned, string<>)
% * 	RETURNS (port, string<>);
% * usage: encapsulatedresults = PMAPPROC_CALLIT(prog, vers, proc,
% *						encapsulatedargs);
% * 	Calls the procedure on the local machine.  If it is not registered,
% *	this procedure is quite; ie it does not return error information!!!
% *	This procedure only is supported on rpc/udp and calls via
% *	rpc/udp.  This routine only passes null authentication parameters.
% *	This file has no interface to xdr routines for PMAPPROC_CALLIT.
% *
% * The service supports remote procedure calls on udp/ip or tcp/ip socket 111.
% */
%
const PMAPPORT = 111;	/* portmapper port number */
%
%
%/*
% * A mapping of (program, version, protocol) to port number
% */

struct pmap {
	rpcprog_t pm_prog;
	rpcvers_t pm_vers;
	rpcprot_t pm_prot;
	rpcport_t pm_port;
};
#ifdef RPC_HDR
%
%typedef pmap PMAP;
%
#endif
%
%/*
% * Supported values for the "prot" field
% */
%
const PMAP_IPPROTO_TCP = 6;	/* protocol number for TCP/IP */
const PMAP_IPPROTO_UDP = 17;	/* protocol number for UDP/IP */
%
%
%/*
% * A list of mappings
% *
% * Below are two definitions for the pmaplist structure.  This is done because
% * xdr_pmaplist() is specified to take a struct pmaplist **, rather than a
% * struct pmaplist * that rpcgen would produce.  One version of the pmaplist
% * structure (actually called pm__list) is used with rpcgen, and the other is
% * defined only in the header file for compatibility with the specified
% * interface.
% */

struct pm__list {
	pmap pml_map;
	struct pm__list *pml_next;
};

typedef pm__list *pmaplist_ptr;		/* results of PMAPPROC_DUMP */

#ifdef RPC_HDR
%
%struct pmaplist {
%	PMAP pml_map;
%	struct pmaplist *pml_next;
%};
%
%typedef struct pmaplist pmaplist;
%typedef struct pmaplist PMAPLIST;
%
%#ifdef __cplusplus
%extern "C" {
%#endif
%#ifdef __STDC__
%extern  bool_t xdr_pmaplist(XDR *, pmaplist**);
%#else /* K&R C */
%bool_t xdr_pmaplist();
%#endif
%#ifdef	__cplusplus
%}
%#endif
%
#endif

%
%/*
% * Arguments to callit
% */

struct rmtcallargs {
	rpcprog_t prog;
	rpcvers_t vers;
	rpcproc_t proc;
	opaque args<>;
};
#ifdef RPC_HDR
%
%/*
% * Client-side only representation of rmtcallargs structure.
% *
% * The routine that XDRs the rmtcallargs structure must deal with the
% * opaque arguments in the "args" structure.  xdr_rmtcall_args() needs to be
% * passed the XDR routine that knows the args' structure.  This routine
% * doesn't need to go over-the-wire (and it wouldn't make sense anyway) since
% * the application being called knows the args structure already.  So we use a
% * different "XDR" structure on the client side, p_rmtcallargs, which includes
% * the args' XDR routine.
% */
%struct p_rmtcallargs {
%	rpcprog_t prog;
%	rpcvers_t vers;
%	rpcproc_t proc;
%	struct {
%		u_int args_len;
%		char *args_val;
%	} args;
%	xdrproc_t	xdr_args;	/* encodes args */
%};
%
#endif	/* def RPC_HDR */
%
%
%/*
% * Results of callit
% */

struct rmtcallres {
	rpcport_t port;
	opaque res<>;
};
#ifdef RPC_HDR
%
%/*
% * Client-side only representation of rmtcallres structure.
% */
%struct p_rmtcallres {
%	rpcport_t port;
%	struct {
%		u_int res_len;
%		char *res_val;
%	} res;
%	xdrproc_t	xdr_res;	/* decodes res */
%};
%
#endif	/* def RPC_HDR */

/*
 * Port mapper procedures
 */

program PMAPPROG {
   version PMAPVERS {
	void
	PMAPPROC_NULL(void)	= 0;

	bool
	PMAPPROC_SET(pmap)	= 1;

	bool
	PMAPPROC_UNSET(pmap)	= 2;

	rpcport_t
	PMAPPROC_GETPORT(pmap)	= 3;

	pmaplist_ptr
	PMAPPROC_DUMP(void)	= 4;

	rmtcallres
	PMAPPROC_CALLIT(rmtcallargs)  = 5;
   } = 2;
} = 100000;
%
#ifdef RPC_HDR
%#define	PMAPVERS_PROTO		((rpcvers_t)2)
%#define	PMAPVERS_ORIG		((rpcvers_t)1)
%
%#else		/* ndef _KERNEL */
%
%#include <rpc/pmap_rmt.h>
%
%#ifdef __cplusplus
%extern "C" {
%#endif
%
%#define	PMAPPORT 111
%
%struct pmap {
%	rpcprog_t pm_prog;
%	rpcvers_t pm_vers;
%	rpcprot_t pm_prot;
%	rpcport_t pm_port;
%};
%typedef struct pmap PMAP;
%#ifdef __STDC__
%extern bool_t xdr_pmap (XDR *, struct pmap *);
%#else
%extern bool_t xdr_pmap ();
%#endif
%
%struct pmaplist {
%	struct pmap pml_map;
%	struct pmaplist *pml_next;
%};
%typedef struct pmaplist PMAPLIST;
%typedef struct pmaplist *pmaplist_ptr;
%
%
%#ifdef __cplusplus
%}
%#endif
%
%#endif		/* ndef _KERNEL */
#endif

