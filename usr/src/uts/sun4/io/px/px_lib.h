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

#ifndef	_SYS_PX_LIB_H
#define	_SYS_PX_LIB_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Include all data structures and definitions in this file that are
 * required between the common and hardware specific code.
 */

#define	DIP_TO_HANDLE(dip)	((px_t *)DIP_TO_STATE(dip))->px_dev_hdl

/*
 * The following macros define	the mmu page size and related operations.
 */
#define	MMU_PAGE_SHIFT		13
#define	MMU_PAGE_SIZE		(1 << MMU_PAGE_SHIFT)
#define	MMU_PAGE_MASK		~(MMU_PAGE_SIZE - 1)
#define	MMU_PAGE_OFFSET		(MMU_PAGE_SIZE - 1)
#define	MMU_PTOB(x)		(((uint64_t)(x)) << MMU_PAGE_SHIFT)
#define	MMU_BTOP(x)		((x) >> MMU_PAGE_SHIFT)
#define	MMU_BTOPR(x)		MMU_BTOP((x) + MMU_PAGE_OFFSET)

/* MMU map flags */
#define	MMU_MAP_PFN		1
#define	MMU_MAP_BUF		2

typedef struct px px_t;
typedef struct px_msiq px_msiq_t;

extern int px_lib_dev_init(dev_info_t *dip, devhandle_t *dev_hdl);
extern int px_lib_dev_fini(dev_info_t *dip);
extern int px_lib_map_vconfig(dev_info_t *dip, ddi_map_req_t *mp,
    pci_config_offset_t off, pci_regspec_t *rp, caddr_t *addrp);
extern void px_lib_map_attr_check(ddi_map_req_t *mp);

extern int px_lib_intr_devino_to_sysino(dev_info_t *dip, devino_t devino,
    sysino_t *sysino);
extern int px_lib_intr_getvalid(dev_info_t *dip, sysino_t sysino,
    intr_valid_state_t *intr_valid_state);
extern int px_lib_intr_setvalid(dev_info_t *dip, sysino_t sysino,
    intr_valid_state_t intr_valid_state);
extern int px_lib_intr_getstate(dev_info_t *dip, sysino_t sysino,
    intr_state_t *intr_state);
extern int px_lib_intr_setstate(dev_info_t *dip, sysino_t sysino,
    intr_state_t intr_state);
extern int px_lib_intr_gettarget(dev_info_t *dip, sysino_t sysino,
    cpuid_t *cpuid);
extern int px_lib_intr_settarget(dev_info_t *dip, sysino_t sysino,
    cpuid_t cpuid);
extern int px_lib_intr_reset(dev_info_t *dip);

#ifdef FMA
extern void px_fill_rc_status(px_fault_t *px_fault_p,
    pciex_rc_error_regs_t *rc_status);
#endif

extern int px_lib_iommu_map(dev_info_t *dip, tsbid_t tsbid, pages_t pages,
    io_attributes_t attr, void *addr, size_t pfn_index, int flags);
extern int px_lib_iommu_demap(dev_info_t *dip, tsbid_t tsbid, pages_t pages);
extern int px_lib_iommu_getmap(dev_info_t *dip, tsbid_t tsbid,
    io_attributes_t *attr_p, r_addr_t *r_addr_p);
extern int px_lib_dma_bypass_rngchk(dev_info_t *dip, ddi_dma_attr_t *attr_p,
    uint64_t *lo_p, uint64_t *hi_p);
extern int px_lib_iommu_getbypass(dev_info_t *dip, r_addr_t ra,
    io_attributes_t attr, io_addr_t *io_addr_p);
extern uint64_t px_lib_ro_bypass(dev_info_t *dip, io_attributes_t attr,
    uint64_t io_addr);
extern int px_lib_dma_sync(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, off_t off, size_t len, uint_t cache_flags);

/*
 * MSIQ Functions:
 */
extern int px_lib_msiq_init(dev_info_t *dip);
extern int px_lib_msiq_fini(dev_info_t *dip);
extern int px_lib_msiq_info(dev_info_t *dip, msiqid_t msiq_id,
    r_addr_t *ra_p, uint_t *msiq_rec_cnt_p);
extern int px_lib_msiq_getvalid(dev_info_t *dip, msiqid_t msiq_id,
    pci_msiq_valid_state_t *msiq_valid_state);
extern int px_lib_msiq_setvalid(dev_info_t *dip, msiqid_t msiq_id,
    pci_msiq_valid_state_t msiq_valid_state);
extern int px_lib_msiq_getstate(dev_info_t *dip, msiqid_t msiq_id,
    pci_msiq_state_t *msiq_state);
extern int px_lib_msiq_setstate(dev_info_t *dip, msiqid_t msiq_id,
    pci_msiq_state_t msiq_state);
extern int px_lib_msiq_gethead(dev_info_t *dip, msiqid_t msiq_id,
    msiqhead_t *msiq_head);
extern int px_lib_msiq_sethead(dev_info_t *dip, msiqid_t msiq_id,
    msiqhead_t msiq_head);
extern int px_lib_msiq_gettail(dev_info_t *dip, msiqid_t msiq_id,
    msiqtail_t *msiq_tail);
extern void px_lib_get_msiq_rec(dev_info_t *dip, msiqhead_t *msiq_head_p,
    msiq_rec_t *msiq_rec_p);
extern void px_lib_clr_msiq_rec(dev_info_t *dip, msiqhead_t *msiq_head_p);

/*
 * MSI Functions:
 */
extern int px_lib_msi_init(dev_info_t *dip);
extern int px_lib_msi_getmsiq(dev_info_t *dip, msinum_t msi_num,
    msiqid_t *msiq_id);
extern int px_lib_msi_setmsiq(dev_info_t *dip, msinum_t msi_num,
    msiqid_t msiq_id, msi_type_t msitype);
extern int px_lib_msi_getvalid(dev_info_t *dip, msinum_t msi_num,
    pci_msi_valid_state_t *msi_valid_state);
extern int px_lib_msi_setvalid(dev_info_t *dip, msinum_t msi_num,
    pci_msi_valid_state_t msi_valid_state);
extern int px_lib_msi_getstate(dev_info_t *dip, msinum_t msi_num,
    pci_msi_state_t *msi_state);
extern int px_lib_msi_setstate(dev_info_t *dip, msinum_t msi_num,
    pci_msi_state_t msi_state);

/*
 * MSG Functions:
 */
extern int px_lib_msg_getmsiq(dev_info_t *dip, pcie_msg_type_t msg_type,
    msiqid_t *msiq_id);
extern int px_lib_msg_setmsiq(dev_info_t *dip, pcie_msg_type_t msg_type,
    msiqid_t msiq_id);
extern int px_lib_msg_getvalid(dev_info_t *dip, pcie_msg_type_t msg_type,
    pcie_msg_valid_state_t *msg_valid_state);
extern int px_lib_msg_setvalid(dev_info_t *dip, pcie_msg_type_t msg_type,
    pcie_msg_valid_state_t msg_valid_state);

/*
 * PM/CPR Functions:
 */
extern int px_lib_suspend(dev_info_t *dip);
extern void px_lib_resume(dev_info_t *dip);
extern void px_cpr_add_callb(px_t *);
extern void px_cpr_rem_callb(px_t *);
extern int px_lib_pmctl(int cmd, px_t *px_p);
extern uint_t px_pmeq_intr(caddr_t arg);

/*
 * Common range property functions and definitions.
 */
#define	PX_RANGE_PROP_MASK	0x7ff
extern uint64_t px_get_rng_parent_hi_mask(px_t *px_p);

/*
 * Peek and poke access ddi_ctlops helper functions
 */
extern int px_lib_ctlops_poke(dev_info_t *dip, dev_info_t *rdip,
    peekpoke_ctlops_t *in_args);
extern int px_lib_ctlops_peek(dev_info_t *dip, dev_info_t *rdip,
    peekpoke_ctlops_t *in_args, void *result);

/*
 * Error handling functions
 */
#define	PX_INTR_PAYLOAD_SIZE	8	/* 64 bit words */
typedef struct px_fault {
	dev_info_t	*px_fh_dip;
	sysino_t	px_fh_sysino;
	uint_t		(*px_err_func)(caddr_t px_fault);
	devino_t	px_intr_ino;
	uint64_t	px_intr_payload[PX_INTR_PAYLOAD_SIZE];
} px_fault_t;

extern int px_err_add_intr(px_fault_t *px_fault_p);
extern void px_err_rem_intr(px_fault_t *px_fault_p);
extern int px_cb_add_intr(px_fault_t *);
extern void px_cb_rem_intr(px_fault_t *);
extern uint32_t px_fab_get(px_t *px_p, pcie_req_id_t bdf,
    uint16_t offset);
extern void px_fab_set(px_t *px_p, pcie_req_id_t bdf, uint16_t offset,
    uint32_t val);

/*
 * CPR callback
 */
extern void px_cpr_add_callb(px_t *);
extern void px_cpr_rem_callb(px_t *);

/*
 * Hotplug functions
 */
extern int px_lib_hotplug_init(dev_info_t *dip, void *regops);
extern void px_lib_hotplug_uninit(dev_info_t *dip);
extern void px_hp_intr_redist(px_t *px_p);

extern boolean_t px_lib_is_in_drain_state(px_t *px_p);
extern pcie_req_id_t px_lib_get_bdf(px_t *px_p);

extern int px_lib_get_root_complex_mps(px_t *px_p, dev_info_t *dip, int *mps);
extern int px_lib_set_root_complex_mps(px_t *px_p,  dev_info_t *dip, int mps);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_LIB_H */
