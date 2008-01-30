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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _RESOLV_COMMON_H
#define	_RESOLV_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <rpcsvc/svc_dg_priv.h>

/*
 * Definitions common to rpc.nisd resolv and rpc.resolv code.
 * Stolen from rpcbind and is used to access xprt->xp_p2 fields.
 */

#define	YPDNSPROC4	1L
#define	YPDNSPROC6	2L

#define	MAX_UADDR	52
#define	GETCALLER(xprt)	svc_getrpccaller(xprt)
#define	SETCALLER(xprt, nbufp)	xprt->xp_rtaddr.len = nbufp->len; \
	(void) memcpy(xprt->xp_rtaddr.buf, nbufp->buf, nbufp->len);
#define	RPC_BUF_MAX	32768

struct ypfwdreq_key4 {
	char *map;
	datum keydat;
	unsigned long xid;
	unsigned long ip;
	unsigned short port;
};

struct ypfwdreq_key6 {
	char		*map;
	datum		keydat;
	unsigned long	xid;
	uint32_t	*addr;
	in_port_t	port;
};

extern ulong_t svc_getxid(SVCXPRT *);
extern bool_t xdr_ypfwdreq_key4(XDR *, struct ypfwdreq_key4 *);
extern bool_t xdr_ypfwdreq_key6(XDR *, struct ypfwdreq_key6 *);

#ifdef __cplusplus
}
#endif

#endif	/* _RESOLV_COMMON_H */
