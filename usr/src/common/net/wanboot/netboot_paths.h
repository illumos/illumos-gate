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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NETBOOT_PATHS_H
#define	_NETBOOT_PATHS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The netboot filesystem is mounted in different places in userland
 * (the default) and the standalone; these are their mount-points:
 */
#if	defined(_BOOT)
#define	NB_NETBOOT_ROOT	"/"
#else
#define	NB_NETBOOT_ROOT	"/etc/netboot/"
#endif	/* defined(_BOOT) */

/*
 * Well-known files within the netboot filesystem:
 */
#define	NB_CA_CERT		"truststore"
#define	NB_CLIENT_CERT		"certstore"
#define	NB_CLIENT_KEY		"keystore"
#define	NB_WANBOOT_CONF		"wanboot.conf"
#define	NB_SYSTEM_CONF		"system.conf"

/*
 * Well-known paths, derived from the above:
 */
#define	NB_CA_CERT_PATH		NB_NETBOOT_ROOT NB_CA_CERT
#define	NB_CLIENT_CERT_PATH	NB_NETBOOT_ROOT NB_CLIENT_CERT
#define	NB_CLIENT_KEY_PATH	NB_NETBOOT_ROOT NB_CLIENT_KEY
#define	NB_WANBOOT_CONF_PATH	NB_NETBOOT_ROOT NB_WANBOOT_CONF
#define	NB_SYSTEM_CONF_PATH	NB_NETBOOT_ROOT NB_SYSTEM_CONF

#ifdef __cplusplus
}
#endif

#endif /* _NETBOOT_PATHS_H */
