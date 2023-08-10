/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 RackTop Systems, Inc.
 */

#ifndef	_CLNT_SUBR_H
#define	_CLNT_SUBR_H

#include <sys/types.h>
#include <rpc/rpc.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * nfs client library routines
 */
extern CLIENT *mountprog_client_create(const char *, struct timeval *);
extern void pr_err(char *, ...);

#ifdef __cplusplus
}
#endif

#endif	/* _CLNT_SUBR_H */
