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
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#ifndef _RPC_PMAP_RMT_H
#define	_RPC_PMAP_RMT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _KERNEL

#include <rpc/pmap_prot.h>

#else	/* ndef _KERNEL */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Structures and XDR routines for parameters to and replies from
 * the portmapper remote-call-service.
 */

struct rmtcallargs {
	rpcprog_t prog;
	rpcvers_t vers;
	rpcproc_t proc;
	unsigned int arglen;
	caddr_t	  args_ptr;
	xdrproc_t xdr_args;
};

#ifdef __STDC__
bool_t xdr_rmtcall_args(XDR *, struct rmtcallargs *);
#else
bool_t xdr_rmtcall_args();
#endif

struct rmtcallres {
	rpcport_t *port_ptr;
	uint_t resultslen;
	caddr_t results_ptr;
	xdrproc_t xdr_results;
};
typedef struct rmtcallres rmtcallres;
#ifdef __STDC__
bool_t xdr_rmtcall_args(XDR *, struct rmtcallargs *);
#else
bool_t xdr_rmtcall_args();
#endif

#ifdef __cplusplus
}
#endif

#endif	/* ndef _KERNEL */

#endif	/* _RPC_PMAP_RMT_H */
