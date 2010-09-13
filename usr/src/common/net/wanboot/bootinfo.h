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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_BOOTINFO_H
#define	_BOOTINFO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Names known to bootinfo:
 */
#define	BI_NET_CONFIG_STRATEGY		"net-config-strategy"
#define	BI_HOST_IP			"host-ip"
#define	BI_SUBNET_MASK			"subnet-mask"
#define	BI_ROUTER_IP			"router-ip"
#define	BI_HOSTNAME			"hostname"
#define	BI_HTTP_PROXY			"http-proxy"
#define	BI_CLIENT_ID			"client-id"

#if	defined(_BOOT)
#define	BI_NETWORK_BOOT_FILE		"network-boot-file"
#define	BI_BOOTFILE			"bootfile"
#define	BI_BOOTP_RESPONSE		"bootp-response"
#define	BI_BOOTSERVER			"bootserver"
#define	BI_AES_KEY			"aes"
#define	BI_3DES_KEY			"3des"
#define	BI_SHA1_KEY			"sha1"
#else
#define	BI_SYSIDCFG			"sysidcfg"
#define	BI_JUMPSCFG			"jumpscfg"
#define	BI_ROOTFS_TYPE			"rootfs-type"
#define	BI_INTERFACE_NAME		"interface-name"
#endif	/* defined(_BOOT) */

/*
 * Possible bootinfo repositories:
 */
#define	BI_R_CHOSEN	0x01		/* /chosen property */
#define	BI_R_DHCPOPT	0x02		/* DHCP option */
#define	BI_R_BOOTMISC	0x04		/* 'misc' value */

#define	BI_R_ALL	(BI_R_CHOSEN|BI_R_DHCPOPT|BI_R_BOOTMISC)

/*
 * bootinfo_get() return values:
 */
typedef enum {
	BI_E_SUCCESS,
	BI_E_ERROR,
	BI_E_ILLNAME,
	BI_E_NOVAL,
	BI_E_BUF2SMALL,
	BI_E_RDONLY
} bi_errcode_t;

extern boolean_t bootinfo_init(void);
extern void bootinfo_end(void);
extern bi_errcode_t bootinfo_get(const char *, void *, size_t *, int *);

#if	defined(_BOOT)
extern int bootinfo_put(const char *, const void *, size_t, int);
#endif	/* defined(_BOOT) */

#ifdef	__cplusplus
}
#endif

#endif	/* _BOOTINFO_H */
