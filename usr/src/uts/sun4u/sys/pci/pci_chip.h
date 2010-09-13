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

#ifndef	_SYS_PCI_CHIP_H
#define	_SYS_PCI_CHIP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

extern void pci_post_init_child(pci_t *pci_p, dev_info_t *child);
extern void pci_post_uninit_child(pci_t *pci_p);

extern int pci_obj_setup(pci_t *pci_p);
extern void pci_obj_destroy(pci_t *pci_p);
extern void pci_obj_resume(pci_t *pci_p);
extern void pci_obj_suspend(pci_t *pci_p);

extern void pci_kstat_init(void);
extern void pci_kstat_fini(void);

extern void pci_add_pci_kstat(pci_t *pci_p);
extern void pci_rem_pci_kstat(pci_t *pci_p);

extern void pci_add_upstream_kstat(pci_t *pci_p);

extern void pci_fix_ranges(pci_ranges_t *rng_p, int rng_entries);
extern int map_pci_registers(pci_t *pci_p, dev_info_t *dip);

extern uint_t pbm_disable_pci_errors(pbm_t *pbm_p);
extern uintptr_t get_pbm_reg_base(pci_t *pci_p);

extern uint32_t ib_map_reg_get_cpu(volatile uint64_t reg);
extern uint64_t *ib_intr_map_reg_addr(ib_t *ib_p, ib_ino_t ino);
extern uint64_t *ib_clear_intr_reg_addr(ib_t *ib_p, ib_ino_t ino);
extern void pci_pbm_intr_dist(pbm_t *pbm_p);

extern void pci_cb_setup(pci_t *pci_p);
extern void pci_cb_teardown(pci_t *pci_p);
extern int cb_register_intr(pci_t *pci_p);
extern void cb_enable_intr(pci_t *pci_p);
extern uint64_t cb_ino_to_map_pa(cb_t *cb_p, ib_ino_t ino);
extern uint64_t cb_ino_to_clr_pa(cb_t *cb_p, ib_ino_t ino);
extern int cb_remove_xintr(pci_t *pci_p, dev_info_t *dip, dev_info_t *rdip,
		ib_ino_t ino, ib_mondo_t mondo);
extern uint32_t pci_xlate_intr(dev_info_t *dip, dev_info_t *rdip,
		ib_t *ib_p, uint32_t intr);
extern uint32_t pci_intr_dist_cpuid(ib_t *ib_p, ib_ino_info_t *ino_p);

extern void pci_ecc_setup(ecc_t *ecc_p);
extern ushort_t pci_ecc_get_synd(uint64_t afsr);

extern uintptr_t pci_iommu_setup(iommu_t *iommu_p);
extern void pci_iommu_teardown(iommu_t *iommu_p);
extern void pci_iommu_config(iommu_t *iommu_p, uint64_t iommu_ctl,
		uint64_t cfgpa);

extern dvma_context_t pci_iommu_get_dvma_context(iommu_t *iommu_p,
		dvma_addr_t dvma_pg_index);
extern void pci_iommu_free_dvma_context(iommu_t *iommu_p, dvma_context_t ctx);

extern void pci_pbm_setup(pbm_t *pbm_p);
extern void pci_pbm_teardown(pbm_t *pbm_p);
extern void pci_pbm_dma_sync(pbm_t *pbm_p, ib_ino_t ino);

extern uint64_t pci_sc_configure(pci_t *pci_p);
extern void pci_sc_setup(sc_t *sc_p);
extern int pci_sc_ctx_inv(dev_info_t *dip, sc_t *sc_p, ddi_dma_impl_t *mp);

extern uintptr_t pci_ib_setup(ib_t *ib_p);
extern int pci_get_numproxy(dev_info_t *dip);

extern int pci_ecc_add_intr(pci_t *pci_p, int inum, ecc_intr_info_t *eii_p);
extern void pci_ecc_rem_intr(pci_t *pci_p, int inum, ecc_intr_info_t *eii_p);

extern int pci_pbm_err_handler(dev_info_t *dip, ddi_fm_error_t *derr,
		const void *impl_data, int caller);
extern void pci_ecc_classify(uint64_t err, ecc_errstate_t *ecc_err_p);
extern int pci_pbm_classify(pbm_errstate_t *pbm_err_p);
extern void pci_format_addr(dev_info_t *dip, uint64_t *afar, uint64_t afsr);
extern int pci_check_error(pci_t *pci_p);

extern int pci_pbm_add_intr(pci_t *pci_p);
extern void pci_pbm_rem_intr(pci_t *pci_p);

extern void pci_pbm_suspend(pci_t *pci_p);
extern void pci_pbm_resume(pci_t *pci_p);

extern int pci_bus_quiesce(pci_t *pci_p, dev_info_t *dip, void *arg);
extern int pci_bus_unquiesce(pci_t *pci_p, dev_info_t *dip, void *arg);

extern void pci_vmem_free(iommu_t *iommu_p, ddi_dma_impl_t *mp,
		void *dvma_addr, size_t npages);

extern dma_bypass_addr_t pci_iommu_bypass_end_configure(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_CHIP_H */
