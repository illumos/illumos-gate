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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * HEADER: dapl_name_service.h
 *
 * PURPOSE: Utility defs & routines supporting name services
 *
 */

#ifndef _DAPL_NAME_SERVICE_H_
#define	_DAPL_NAME_SERVICE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "dapl.h"

/*
 * Prototypes for name service routines
 */

DAT_RETURN dapls_ns_init(void);

DAT_RETURN dapls_ns_lookup_address(
	IN  DAPL_IA		*ia_ptr,
	IN  DAT_IA_ADDRESS_PTR	remote_ia_address,
	IN  DAT_TIMEOUT		timeout,
	OUT ib_gid_t		*gid);

char *dapls_inet_ntop(struct sockaddr *addr, char *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _DAPL_NAME_SERVICE_H_ */
