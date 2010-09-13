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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * pmap_prot.h
 * Protocol for the local binder service, or pmap.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 *
 * The following procedures are supported by the protocol:
 *
 * PMAPPROC_NULL() returns ()
 * 	takes nothing, returns nothing
 *
 * PMAPPROC_SET(struct pmap) returns (bool_t)
 * 	TRUE is success, FALSE is failure.  Registers the tuple
 *	[prog, vers, prot, port].
 *
 * PMAPPROC_UNSET(struct pmap) returns (bool_t)
 *	TRUE is success, FALSE is failure.  Un-registers pair
 *	[prog, vers].  prot and port are ignored.
 *
 * PMAPPROC_GETPORT(struct pmap) returns (long unsigned).
 *	0 is failure.  Otherwise returns the port number where the pair
 *	[prog, vers] is registered.  It may lie!
 *
 * PMAPPROC_DUMP() RETURNS (struct pmaplist *)
 *
 * PMAPPROC_CALLIT(unsigned, unsigned, unsigned, string<>)
 * 	RETURNS (port, string<>);
 * usage: encapsulatedresults =
 *		PMAPPROC_CALLIT(prog, vers, proc, encapsulatedargs);
 * 	Calls the procedure on the local machine.  If it is not registered,
 *	this procedure is quite; ie it does not return error information!!!
 *	This procedure only is supported on rpc/udp and calls via
 *	rpc/udp.  This routine only passes null authentication parameters.
 *	This file has no interface to xdr routines for PMAPPROC_CALLIT.
 *
 * The service supports remote procedure calls on udp/ip or tcp/ip socket 111.
 */

#ifndef _rpc_pmap_prot_h
#define	_rpc_pmap_prot_h

#define	PMAPPORT		((u_short)111)
#define	PMAPPROG		((u_long)100000)
#define	PMAPVERS		((u_long)2)
#define	PMAPVERS_PROTO		((u_long)2)
#define	PMAPVERS_ORIG		((u_long)1)
#define	PMAPPROC_NULL		((u_long)0)
#define	PMAPPROC_SET		((u_long)1)
#define	PMAPPROC_UNSET		((u_long)2)
#define	PMAPPROC_GETPORT	((u_long)3)
#define	PMAPPROC_DUMP		((u_long)4)
#define	PMAPPROC_CALLIT		((u_long)5)

struct pmap {
	long unsigned pm_prog;
	long unsigned pm_vers;
	long unsigned pm_prot;
	long unsigned pm_port;
};

extern bool_t xdr_pmap();

struct pmaplist {
	struct pmap	pml_map;
	struct pmaplist *pml_next;
};

#ifndef KERNEL
extern bool_t xdr_pmaplist();
#endif /*!KERNEL*/

#endif /*!_rpc_pmap_prot_h*/
