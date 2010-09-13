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

#ifndef	_FMD_ADM_IMPL_H
#define	_FMD_ADM_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpc/rpc.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <fmd_adm.h>

struct fmd_adm {
	CLIENT *adm_clnt;		/* rpc client handle for connection */
	int adm_version;		/* abi version of library client */
	int adm_svcerr;			/* server-side error from last call */
	int adm_errno;			/* client-side error from last call */
	uint32_t adm_prog;		/* server program */
	uint_t adm_maxretries;		/* maximum number of retries */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_ADM_IMPL_H */
