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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PMAP_H
#define	_PMAP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	UA_SIZE		(128)	/* max space needed for an universal addr */

extern enum clnt_stat bpmap_rmtcall(rpcprog_t, rpcvers_t, rpcproc_t, xdrproc_t,
    caddr_t, xdrproc_t, caddr_t, int, int, struct sockaddr_in *,
    struct sockaddr_in *, uint_t);
extern rpcport_t bpmap_getport(rpcprog_t, rpcvers_t, enum clnt_stat *,
	struct sockaddr_in *, struct sockaddr_in *);
extern void bpmap_memfree(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _PMAP_H */
