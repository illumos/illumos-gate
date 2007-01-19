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

#ifndef	_BOOTPROPS_H
#define	_BOOTPROPS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Boot properties related to netboot:
 */
#define	BP_HOST_IP			"host-ip"
#define	BP_SUBNET_MASK			"subnet-mask"
#define	BP_ROUTER_IP			"router-ip"
#define	BP_BOOT_MAC			"boot-mac"
#define	BP_SERVER_IP			"server-ip"
#define	BP_SERVER_NAME			"server-name"
#define	BP_SERVER_PATH			"server-path"
#define	BP_SERVER_ROOTOPTS		"server-rootopts"
#define	BP_BOOTP_RESPONSE		"bootp-response"
#define	BP_NETWORK_INTERFACE		"network-interface"

#ifdef	__cplusplus
}
#endif

#endif	/* _BOOTPROPS_H */
