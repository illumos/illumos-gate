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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_HXGE_HXGE_VIRTUAL_H
#define	_SYS_HXGE_HXGE_VIRTUAL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* 12 bits are available */
#define	COMMON_CFG_VALID	0x01
#define	COMMON_CFG_BUSY		0x02
#define	COMMON_INIT_START	0x04
#define	COMMON_INIT_DONE	0x08
#define	COMMON_TCAM_BUSY	0x10
#define	COMMON_VLAN_BUSY	0x20

#define	COMMON_TXDMA_CFG	1
#define	COMMON_RXDMA_CFG	2
#define	COMMON_RXDMA_GRP_CFG	4
#define	COMMON_CLASS_CFG	8
#define	COMMON_QUICK_CFG	0x10

hxge_status_t hxge_intr_mask_mgmt(p_hxge_t hxgep);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HXGE_HXGE_VIRTUAL_H */
