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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_HOTPLUG_PCI_PCIEHPC_H
#define	_SYS_HOTPLUG_PCI_PCIEHPC_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Interfaces exported by PCI-E nexus Hot Plug Controller extension module
 */
int pciehpc_init(dev_info_t *dip, caddr_t arg);
int pciehpc_uninit(dev_info_t *dip);
int pciehpc_intr(dev_info_t *dip);
int pciehpc_hp_ops(dev_info_t *dip, char *cn_name, ddi_hp_op_t op, void *arg,
    void *result);
void pciehpc_get_slot_state(pcie_hp_slot_t *slot_p);
void pciehpc_set_slot_name(pcie_hp_ctrl_t *ctrl_p);
uint8_t pciehpc_reg_get8(pcie_hp_ctrl_t *ctrl_p, uint_t off);
uint16_t pciehpc_reg_get16(pcie_hp_ctrl_t *ctrl_p, uint_t off);
uint32_t pciehpc_reg_get32(pcie_hp_ctrl_t *ctrl_p, uint_t off);
void pciehpc_reg_put8(pcie_hp_ctrl_t *ctrl_p, uint_t off, uint8_t val);
void pciehpc_reg_put16(pcie_hp_ctrl_t *ctrl_p, uint_t off, uint16_t val);
void pciehpc_reg_put32(pcie_hp_ctrl_t *ctrl_p, uint_t off, uint32_t val);
#if	defined(__i386) || defined(__amd64)
extern void pciehpc_update_ops(pcie_hp_ctrl_t *ctrl_p);
#endif	/* defined(__i386) || defined(__amd64) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HOTPLUG_PCI_PCIEHPC_H */
