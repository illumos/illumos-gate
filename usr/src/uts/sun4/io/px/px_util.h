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

#ifndef	_SYS_PX_UTIL_H
#define	_SYS_PX_UTIL_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	HI32(x) ((uint32_t)(((uint64_t)(x)) >> 32))
#define	LO32(x) ((uint32_t)(x))
#define	NAMEINST(dip)	ddi_driver_name(dip), ddi_get_instance(dip)
#define	NAMEADDR(dip)	ddi_node_name(dip), ddi_get_name_addr(dip)

extern int px_init_child(px_t *px_p, dev_info_t *child);
extern int px_uninit_child(px_t *px_p, dev_info_t *child);
extern int px_report_dev(dev_info_t *dip);
extern int px_get_props(px_t *px_p, dev_info_t *dip);
extern void px_free_props(px_t *px_p);
extern int px_map_regs(px_t *px_p, dev_info_t *dip);
extern void px_unmap_regs(px_t *px_p);
extern int pci_log_cfg_err(dev_info_t *dip, ushort_t status_reg, char *err_msg);

/* bus map routines */
extern int px_reloc_reg(dev_info_t *dip, dev_info_t *rdip, px_t *px_p,
	pci_regspec_t *pci_rp);
extern int px_xlate_reg(px_t *px_p, pci_regspec_t *pci_rp,
	struct regspec *new_rp);
extern int px_search_ranges(px_t *px_p, uint32_t space_type, uint32_t reg_begin,
	uint32_t reg_end, pci_ranges_t **sel_rng_p, uint_t *base_offset_p);

/* bus add intrspec */
extern off_t px_get_reg_set_size(dev_info_t *child, int rnumber);
extern uint_t px_get_nreg_set(dev_info_t *child);
extern uint_t px_get_nintr(dev_info_t *child);
extern uint64_t px_get_cfg_pabase(px_t *px_p);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_UTIL_H */
