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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/* Copyright (c) 1990 Mentat Inc. */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/rawip_impl.h>
#include <sys/strsubr.h>
#include <sys/socketvar.h>

#define	INET_NAME	"icmp"
#define	INET_MODDESC	"ICMP dummy STREAMS module"
#define	INET_DEVDESC	"ICMP STREAMS driver"
#define	INET_DEVMINOR	0
#define	INET_DEVSTRTAB	icmpinfov4
#define	INET_MODSTRTAB	dummymodinfo
#define	INET_SOCKDESC	"Rawip socket module"
#define	INET_SOCK_PROTO_CREATE_FUNC 	(*rawip_create)
#define	INET_SOCK_PROTO_FB_FUNC 	(*rawip_fallback)
#define	INET_SOCK_FALLBACK_DEV_V4	"/dev/icmp"
#define	INET_SOCK_FALLBACK_DEV_V6	"/dev/icmp6"
#define	INET_DEVMTFLAGS	D_MP
#define	INET_MODMTFLAGS D_MP

#include "../inetddi.c"

int
_init(void)
{
	/*
	 * device initialization happens when the actual code containing
	 * module (/kernel/drv/ip) is loaded, and driven from ip_ddi_init()
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
