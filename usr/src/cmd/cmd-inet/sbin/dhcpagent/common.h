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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _COMMON_H
#define	_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

/*
 * Common opaque structure definitions and values used throughout the dhcpagent
 * implementation.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Things (unfortunately) required because we're in an XPG environment.
 */
#define	B_TRUE	_B_TRUE
#define	B_FALSE	_B_FALSE

struct dhcp_smach_s;
typedef struct dhcp_smach_s dhcp_smach_t;
struct dhcp_lease_s;
typedef struct dhcp_lease_s dhcp_lease_t;
struct dhcp_lif_s;
typedef struct dhcp_lif_s dhcp_lif_t;
struct dhcp_pif_s;
typedef struct dhcp_pif_s dhcp_pif_t;
typedef int script_callback_t(dhcp_smach_t *, void *);
struct dhcp_timer_s;
typedef struct dhcp_timer_s dhcp_timer_t;
struct dhcp_ipc_s;
typedef struct dhcp_ipc_s dhcp_ipc_t;

typedef int64_t monosec_t;		/* see README for details */

#ifdef __cplusplus
}
#endif

#endif /* _COMMON_H */
