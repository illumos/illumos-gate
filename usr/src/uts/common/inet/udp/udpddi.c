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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1990 Mentat Inc. */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <inet/common.h>
#include <inet/ip.h>

#define	INET_NAME	"udp"
#define	INET_MODDESC	"UDP STREAMS module %I%"
#define	INET_DEVDESC	"UDP STREAMS driver %I%"
#define	INET_DEVMINOR	IPV4_MINOR
#define	INET_STRTAB	udpinfo
#define	INET_DEVMTFLAGS	IP_DEVMTFLAGS	/* since as a driver we're ip */
#define	INET_MODMTFLAGS (D_MP | D_MTQPAIR | D_MTPUTSHARED | _D_MTOCSHARED)

#include "../inetddi.c"

extern void udp_ddi_init(void);
extern void udp_ddi_destroy(void);

int
_init(void)
{
	int	error;

	INET_BECOME_IP();

	/*
	 * Note: After mod_install succeeds, another thread can enter
	 * therefore all initialization is done before it and any
	 * de-initialization needed done if it fails.
	 */
	udp_ddi_init();
	error = mod_install(&modlinkage);
	if (error != 0)
		udp_ddi_destroy();

	return (error);
}

int
_fini(void)
{
	int	error;

	error = mod_remove(&modlinkage);
	if (error != 0)
		return (error);

	udp_ddi_destroy();
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
