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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1990 Mentat Inc. */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/ksynch.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/arp_impl.h>

#define	INET_NAME	"arp"
#define	INET_MODDESC	"ARP STREAMS module %I%"
#define	INET_DEVDESC	"ARP STREAMS driver %I%"
#define	INET_DEVMINOR	IPV4_MINOR
#define	INET_STRTAB	arpinfo
#define	INET_DEVMTFLAGS	IP_DEVMTFLAGS	/* since as a driver we're ip */
#define	INET_MODMTFLAGS	(D_MP | D_MTPERMOD)

static void	arp_ddi_destroy();
static void	arp_ddi_init();

#include "../inetddi.c"

int
_init(void)
{
	int error;

	arp_ddi_init();
	INET_BECOME_IP();

	error = mod_install(&modlinkage);
	if (error != 0)
		arp_ddi_destroy();
	return (error);
}

int
_fini(void)
{
	int error;

	error = mod_remove(&modlinkage);
	if (error == 0)
		arp_ddi_destroy();
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


static void
arp_ddi_init()
{
	rw_init(&arl_g_lock, "ARP ARl lock", RW_DRIVER, NULL);
	arp_net_init();
	arp_hook_init();
}


static void
arp_ddi_destroy()
{
	arp_hook_destroy();
	arp_net_destroy();
	rw_destroy(&arl_g_lock);
}
