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
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

/*
 * These definitions are private to ipd and ipdadm.
 */

#ifndef _SYS_IPD_H
#define	_SYS_IPD_H

#ifdef __cplusplus
extern "C" {
#endif

#define	IPD_DEV_PATH	"/dev/ipd"
#define	IPD_MAX_DELAY	10000		/* 10 ms in us */

typedef struct ipd_ioc_perturb {
	zoneid_t	ipip_zoneid;
	uint32_t	ipip_arg;
} ipd_ioc_perturb_t;

typedef struct ipd_ioc_info {
	zoneid_t	ipii_zoneid;
	uint32_t	ipii_corrupt;
	uint32_t	ipii_drop;
	uint32_t	ipii_delay;
} ipd_ioc_info_t;

#ifdef _KERNEL

typedef struct ipd_ioc_list32 {
	uint_t		ipil_nzones;
	caddr32_t	ipil_info;
} ipd_ioc_list32_t;

#endif /* _KERNEL */

typedef struct ipd_ioc_list {
	uint_t		ipil_nzones;
	ipd_ioc_info_t	*ipil_info;
} ipd_ioc_list_t;

#define	IPD_CORRUPT	0x1
#define	IPD_DELAY	0x2
#define	IPD_DROP	0x4

#define	IPDIOC		(('i' << 24) | ('p' << 16) | ('d' << 8))
#define	IPDIOC_CORRUPT	(IPDIOC | 1)		/* disable ipd */
#define	IPDIOC_DELAY	(IPDIOC | 2)		/* disable ipd */
#define	IPDIOC_DROP	(IPDIOC | 3)		/* disable ipd */
#define	IPDIOC_LIST	(IPDIOC | 4)		/* enable ipd */
#define	IPDIOC_REMOVE	(IPDIOC | 5)		/* disable ipd */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IPD_H */
