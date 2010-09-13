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

#ifndef	_DHCP_HOSTCONF_H
#define	_DHCP_HOSTCONF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/dhcp.h>
#include <netinet/dhcp6.h>
#include <dhcp_impl.h>

/*
 * dhcp_hostconf.[ch] provide an API to the /etc/dhcp/<if>.dhc files.
 * see dhcp_hostconf.c for documentation on how to use the exported
 * functions.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	DHCP_HOSTCONF_MAGIC	0x44484301		/* hex "DHC\1" */
#define	DHCP_HOSTCONF_MAGIC6	0x44484302		/* hex "DHC\2" */
#define	DHCP_HOSTCONF_PREFIX	"/etc/dhcp/"
#define	DHCP_HOSTCONF_SUFFIX	".dhc"
#define	DHCP_HOSTCONF_SUFFIX6	".dh6"
#define	DHCP_HOSTCONF_TMPL	DHCP_HOSTCONF_PREFIX DHCP_HOSTCONF_SUFFIX
#define	DHCP_HOSTCONF_TMPL6	DHCP_HOSTCONF_PREFIX DHCP_HOSTCONF_SUFFIX6

extern char	*ifname_to_hostconf(const char *, boolean_t);
extern int	remove_hostconf(const char *, boolean_t);
extern int	read_hostconf(const char *, PKT_LIST **, uint_t, boolean_t);
extern int	write_hostconf(const char *, PKT_LIST **, uint_t, time_t,
    boolean_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _DHCP_HOSTCONF_H */
