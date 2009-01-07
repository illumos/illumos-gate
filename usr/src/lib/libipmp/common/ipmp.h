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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _IPMP_H
#define	_IPMP_H

/*
 * General IPMP-related definitions and functions.
 *
 * These interfaces may only be used within ON or after signing a contract
 * with ON.  For documentation, refer to PSARC/2002/615.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/sysevent/ipmp.h>

/*
 * IPMP library error codes.
 */
enum {
	IPMP_SUCCESS,		/* operation succeeded */
	IPMP_FAILURE,		/* operation failed (check errno) */
	IPMP_EMINRED,		/* minimum failover redundancy not met */
	IPMP_EFBDISABLED,	/* failback disabled */
	IPMP_EUNKADDR,		/* unknown IPMP data address */
	IPMP_EINVAL,		/* invalid argument */
	IPMP_ENOMEM,		/* out of memory */
	IPMP_ENOMPATHD,		/* cannot contact in.mpathd */
	IPMP_EUNKGROUP,		/* unknown IPMP group */
	IPMP_EUNKIF,		/* interface is not using IPMP */
	IPMP_EPROTO,		/* unable to communicate with in.mpathd */
	IPMP_EHWADDRDUP,	/* interface has duplicate hardware address */
	IPMP_NERR		/* number of error codes */
};

typedef struct ipmp_state *ipmp_handle_t;

extern int ipmp_open(ipmp_handle_t *);
extern void ipmp_close(ipmp_handle_t);
extern const char *ipmp_errmsg(int);

#ifdef __cplusplus
}
#endif

#endif /* _IPMP_H */
