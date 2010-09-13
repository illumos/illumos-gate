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

#ifndef	_SYS_NXGE_NXGE_VIRTUAL_H
#define	_SYS_NXGE_NXGE_VIRTUAL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Neptune Virtualization Control Operations
 */
typedef enum {
	NXGE_CTLOPS_NIUTYPE,
	NXGE_CTLOPS_GET_ATTRIBUTES,
	NXGE_CTLOPS_GET_HWPROPERTIES,
	NXGE_CTLOPS_SET_HWPROPERTIES,
	NXGE_CTLOPS_GET_SHARED_REG,
	NXGE_CTLOPS_SET_SHARED_REG,
	NXGE_CTLOPS_UPDATE_SHARED_REG,
	NXGE_CTLOPS_GET_LOCK_BLOCK,
	NXGE_CTLOPS_GET_LOCK_TRY,
	NXGE_CTLOPS_FREE_LOCK,
	NXGE_CTLOPS_SET_SHARED_REG_LOCK,
	NXGE_CTLOPS_CLEAR_BIT_SHARED_REG,
	NXGE_CTLOPS_CLEAR_BIT_SHARED_REG_UL,
	NXGE_CTLOPS_END
} nxge_ctl_enum_t;

/* 12 bits are available */
#define	COMMON_CFG_VALID	0x01
#define	COMMON_CFG_BUSY	0x02
#define	COMMON_INIT_START	0x04
#define	COMMON_INIT_DONE	0x08
#define	COMMON_TCAM_BUSY	0x10
#define	COMMON_VLAN_BUSY	0x20
#define	COMMON_RESET_NIU_PCI	0x40


#define	NXGE_SR_FUNC_BUSY_SHIFT	0x8
#define	NXGE_SR_FUNC_BUSY_MASK	0xf00


#define	COMMON_TXDMA_CFG	1
#define	COMMON_RXDMA_CFG	2
#define	COMMON_RXDMA_GRP_CFG	4
#define	COMMON_CLASS_CFG	8
#define	COMMON_QUICK_CFG	0x10

nxge_status_t nxge_intr_mask_mgmt(p_nxge_t nxgep);
void nxge_virint_regs_dump(p_nxge_t nxgep);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_VIRTUAL_H */
