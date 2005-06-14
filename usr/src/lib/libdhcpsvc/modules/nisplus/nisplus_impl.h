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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _NISPLUS_IMPL_H
#define	_NISPLUS_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <dhcp_svc_public.h>
#include <rpcsvc/nis.h>
#include "common.h"

/* table prefix */
#define	TMPLT_PFX	"SUNWnisplus1_"

/* dhcptab table */
#define	TYPE_DT		"SUNW_dhcpsvc_tab"
#define	DT_TBL_NAME	TMPLT_PFX DT_DHCPTAB

/* dhcp network table */
#define	TYPE_DN		"SUNW_dhcpsvc_net"
#define	RE_DN 	"[0-9]\\{1,3\\}_[0-9]\\{1,3\\}_[0-9]\\{1,3\\}_[0-9]\\{1,3\\}"
#define	PATTERN_DN	"^" TMPLT_PFX RE_DN "$"
#define	TMPLT_SFX_DN	"YYY_YYY_YYY_YYY"
#define	TMPLT_DN	TMPLT_PFX TMPLT_SFX_DN
#define	COLS_DN		10
#define	CID_DN		0
#define	F_AUTO_DN	1
#define	F_MANUAL_DN	2
#define	F_UNUSABLE_DN	3
#define	F_BOOTP_DN	4
#define	CIP_DN		5
#define	SIP_DN		6
#define	LEASE_DN	7
#define	MACRO_DN	8
#define	COMMENT_DN	9

/* generic nis related functions */
extern int		dn_to_ip(const char *, char *, int);
extern int		ip_to_dn(const char *, char *, int);

#ifdef	__cplusplus
}
#endif

#endif	/* !_NISPLUS_IMPL_H */
