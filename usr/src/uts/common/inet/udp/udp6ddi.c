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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <inet/common.h>
#include <inet/ip.h>

#define	INET_NAME	"udp6"
#define	INET_DEVMINOR	IPV6_MINOR
#define	INET_DEVDESC	"UDP6 STREAMS driver %I%"
#define	INET_STRTAB	udpinfo
#define	INET_DEVMTFLAGS	IP_DEVMTFLAGS
/*
 * We define both synchronous STREAMS and sockfs direct-access
 * mode for UDP module instance, because it is autopushed on
 * top of /dev/ip for the sockets case.
 */
#define	INET_MODMTFLAGS	(D_MP|D_SYNCSTR|_D_DIRECT)

#include "../inetddi.c"

int
_init(void)
{
	INET_BECOME_IP();

	/*
	 * device initialization is done in udpddi.c:_init()
	 * i.e. it is assumed it is called first
	 */
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
