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
 * Copyright 1999-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SUNOS_DHCP_CLASS_H
#define	_SUNOS_DHCP_CLASS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	VS_OFFSET		256	/* option number offset for dhcpinfo */

/* SunOS/Solaris vendor class specific Options */
#define	VS_OPTION_START		0
#define	VS_NFSMNT_ROOTOPTS	1	/* ASCII NFS root fs mount options */
#define	VS_NFSMNT_ROOTSRVR_IP	2	/* IPv4 address of root server */
#define	VS_NFSMNT_ROOTSRVR_NAME	3	/* ASCII hostname of root server */
#define	VS_NFSMNT_ROOTPATH	4	/* ASCII UNIX pathname of root */
#define	VS_NFSMNT_SWAPSERVER	5	/* IPv4 address of swap server */
#define	VS_NFSMNT_SWAPFILE	6	/* ASCII path to swapfile */
#define	VS_NFSMNT_BOOTFILE	7	/* ASCII pathname of file to boot */
#define	VS_POSIX_TIMEZONE	8	/* ASCII 1003 posix timezone spec */
#define	VS_BOOT_NFS_READSIZE	9	/* 16bit int for Boot NFS read size */
#define	VS_INSTALL_SRVR_IP	10	/* IPv4 address of Install server */
#define	VS_INSTALL_SRVR_NAME	11	/* ASCII hostname of Install server */
#define	VS_INSTALL_PATH		12	/* ASCII path to Install directory */
#define	VS_SYSID_SRVR_PATH	13	/* ASCII server:/path of sysid */
					/* configuration file. */
#define	VS_JUMPSTART_SRVR_PATH	14	/* ASCII "server:/path" of JumpStart */
					/* configuration file. */
#define	VS_TERM			15	/* ASCII terminal type name */
#define	VS_NETBOOT_STAND_URI	16	/* ASCII URI for standalone boot file */
#define	VS_NETBOOT_HTTP_PROXY	17	/* ASCII proxy URL for WAN boot */

#define	VS_OPTION_END		17	/* Must be same as entry above */

#ifdef	__cplusplus
}
#endif

#endif	/* _SUNOS_DHCP_CLASS_H */
