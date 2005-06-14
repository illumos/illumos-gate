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
 * Copyright (c) 1995-1997, 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/* Automatic tunnel module */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>

#include <sys/socket.h>
#include <sys/isa_defs.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>

#include <inet/common.h>
#include <inet/arp.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <net/if_dl.h>
#include <inet/ip_if.h>
#include <inet/tun.h>

#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/stat.h>

/* streams linkages */
static struct module_info atuninfo = {
	ATUN_MODID, ATUN_NAME, 1, INFPSZ, 65536, 1024
};

static struct qinit atunrinit = {
	(pfi_t)tun_rput,
	(pfi_t)tun_rsrv,
	tun_open,
	tun_close,
	NULL,
	&atuninfo,
	NULL
};

static struct qinit atunwinit = {
	(pfi_t)tun_wput,
	(pfi_t)tun_wsrv,
	NULL,
	NULL,
	NULL,
	&atuninfo,
	NULL
};

static struct streamtab atun_strtab = {
		&atunrinit, &atunwinit, NULL, NULL
};

static struct fmodsw atun_fmodsw = {
	ATUN_NAME,
	&atun_strtab,
	(D_MP | D_MTQPAIR | D_MTPUTSHARED)
	};

static struct modlstrmod modlstrmod = {
	&mod_strmodops, "auto-tunneling module", &atun_fmodsw
	};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlstrmod,
	NULL
	};


int
_init(void)
{
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
