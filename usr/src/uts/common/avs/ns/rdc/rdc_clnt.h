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

#ifndef _RDC_CLNT_H
#define	_RDC_CLNT_H

#ifdef	__cplusplus
extern "C" {
#endif

extern kmutex_t rdc_clnt_lock;

struct chtab {
	uint_t ch_timesused;
	bool_t ch_inuse;
	ulong_t ch_prog;
	rpcvers_t ch_vers;
	dev_t  ch_dev;
	char   *ch_protofmly;
	CLIENT *ch_client;
	struct chtab *ch_next;	/* chain of different prog/vers/dev/proto */
	struct chtab *ch_list;	/* chain of similar clients */
};

#define	MAXCLIENTS	64

extern int rdc_clnt_call(rdc_srv_t *, rpcproc_t, rpcvers_t, xdrproc_t,
			caddr_t, xdrproc_t, caddr_t, struct timeval *);
extern int rdc_clnt_call_any(rdc_srv_t *, rdc_if_t *, rpcproc_t,
			xdrproc_t, caddr_t, xdrproc_t, caddr_t,
			struct timeval *);
extern int rdc_clnt_call_walk(rdc_k_info_t *, rpcproc_t, xdrproc_t, caddr_t,
			xdrproc_t, caddr_t, struct timeval *);

extern int rdc_rpc_tmout;

extern int rdc_aio_coalesce(rdc_aio_t *, rdc_aio_t *);


#ifdef	__cplusplus
}
#endif

#endif	/* _RDC_CLNT_H */
