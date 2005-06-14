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

/*
 * Contains nisplus0 module-specific code.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <dhcp_svc_public.h>
#include <rpcsvc/nis.h>
#include "common.h"

/*
 * Utility macros
 */
#define	DN_TO_IP(x)	(dsvcnis_convert_form((x), '_', '.'))
#define	IP_TO_DN(x)	(dsvcnis_convert_form((x), '.', '_'))

/* dhcptab table */
#define	TYPE_DT		"dhcp_tbl"
#define	DT_TBL_NAME	DT_DHCPTAB

/* dhcp network table */
#define	TYPE_DN		"dhcp_ip_tbl"
#define	PATTERN_DN	"^[0-9]*_[0-9]*_[0-9]*_[0-9]*$"
#define	COLS_DN		7
#define	CID_DN		0
#define	FLAGS_DN	1
#define	CIP_DN		2
#define	SIP_DN		3
#define	LEASE_DN	4
#define	MACRO_DN	5
#define	COMMENT_DN	6

/* generic nis related functions */
extern boolean_t	dsvcnis_valid_ip(const char *);
extern char		*dsvcnis_convert_form(char *, char, char);

#ifdef	__cplusplus
}
#endif

#endif	/* !_NISPLUS_IMPL_H */
