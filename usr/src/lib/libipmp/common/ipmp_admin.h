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
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _IPMP_ADMIN_H
#define	_IPMP_ADMIN_H

#include <ipmp.h>
#include <sys/types.h>

/*
 * IPMP administrative interfaces.
 *
 * These interfaces may only be used within ON or after signing a contract
 * with ON.  For documentation, refer to PSARC/2007/272.
 */

#ifdef __cplusplus
extern "C" {
#endif

extern int ipmp_offline(ipmp_handle_t, const char *, uint_t);
extern int ipmp_undo_offline(ipmp_handle_t, const char *);
extern int ipmp_ping_daemon(ipmp_handle_t);

#ifdef __cplusplus
}
#endif

#endif /* _IPMP_ADMIN_H */
