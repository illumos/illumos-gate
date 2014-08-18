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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Schizo specifics implementation:
 *	interrupt mapping register
 *	PBM configuration
 *	ECC and PBM error handling
 *	Iommu mapping handling
 *	Streaming Cache flushing
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/async.h>
#include <sys/systm.h>
#include <sys/ivintr.h>
#include <sys/machsystm.h>	/* lddphys() */
#include <sys/machsystm.h>	/* lddphys, intr_dist_add */
#include <sys/iommutsb.h>
#include <sys/promif.h>		/* prom_printf */
#include <sys/map.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/spl.h>
#include <sys/fm/util.h>
#include <sys/ddi_impldefs.h>
#include <sys/fm/protocol.h>
#include <sys/fm/io/sun4upci.h>
#include <sys/fm/io/ddi.h>
#include <sys/fm/io/pci.h>
#include <sys/pci/pci_obj.h>
#include <sys/pci/pcisch.h>
#include <sys/pci/pcisch_asm.h>
#include <sys/x_call.h>		/* XCALL_PIL */

/*LINTLIBRARY*/

extern uint8_t ldstub(uint8_t *);

#define	IOMMU_CTX_BITMAP_SIZE	(1 << (12 - 3))
static void iommu_ctx_free(iommu_t *);
static int iommu_tlb_scrub(iommu_t *, int);
static uint32_t pci_identity_init(pci_t *);

static void pci_cb_clear_error(cb_t *, cb_errstate_t *);
static void pci_clear_error(pci_t *, pbm_errstate_t *);
static uint32_t pci_identity_init(pci_t *pci_p);
static int pci_intr_setup(pci_t *pci_p);
static void iommu_ereport_post(dev_info_t *, uint64_t, pbm_errstate_t *);
static void cb_ereport_post(dev_info_t *, uint64_t, cb_errstate_t *);
static void pcix_ereport_post(dev_info_t *, uint64_t, pbm_errstate_t *);
static void pci_format_ecc_addr(dev_info_t *dip, uint64_t *afar,
		ecc_region_t region);
static void pci_pbm_errstate_get(pci_t *pci_p, pbm_errstate_t *pbm_err_p);
static void tm_vmem_free(ddi_dma_impl_t *mp, iommu_t *iommu_p,
		dvma_addr_t dvma_pg, int npages);

static int pcix_ma_behind_bridge(pbm_errstate_t *pbm_err_p);

static pci_ksinfo_t	*pci_name_kstat;
static pci_ksinfo_t	*saf_name_kstat;

extern void pcix_set_cmd_reg(dev_info_t *child, uint16_t value);

/* called by pci_attach() DDI_ATTACH to initialize pci objects */
int
pci_obj_setup(pci_t *pci_p)
{
	pci_common_t *cmn_p;
	uint32_t chip_id = pci_identity_init(pci_p);
	uint32_t cmn_id = PCI_CMN_ID(ID_CHIP_TYPE(chip_id), pci_p->pci_id);
	int ret;

	/* Perform allocations first to avoid delicate unwinding. */
	if (pci_alloc_tsb(pci_p) != DDI_SUCCESS)
		return (DDI_FAILURE);

	mutex_enter(&pci_global_mutex);
	cmn_p = get_pci_common_soft_state(cmn_id);
	if (cmn_p == NULL) {
		if (alloc_pci_common_soft_state(cmn_id) != DDI_SUCCESS) {
			mutex_exit(&pci_global_mutex);
			pci_free_tsb(pci_p);
			return (DDI_FAILURE);
		}
		cmn_p = get_pci_common_soft_state(cmn_id);
		cmn_p->pci_common_id = cmn_id;
		cmn_p->pci_common_tsb_cookie = IOMMU_TSB_COOKIE_NONE;
	}

	ASSERT((pci_p->pci_side == 0) || (pci_p->pci_side == 1));
	if (cmn_p->pci_p[pci_p->pci_side]) {
		/* second side attach */
		pci_p->pci_side = PCI_OTHER_SIDE(pci_p->pci_side);
		ASSERT(cmn_p->pci_p[pci_p->pci_side] == NULL);
	}

	cmn_p->pci_p[pci_p->pci_side] = pci_p;
	pci_p->pci_common_p = cmn_p;

	if (cmn_p->pci_common_refcnt == 0)
		cmn_p->pci_chip_id = chip_id;

	ib_create(pci_p);

	/*
	 * The initialization of cb internal interrupts depends on ib
	 */
	if (cmn_p->pci_common_refcnt == 0) {
		cb_create(pci_p);
		cmn_p->pci_common_cb_p = pci_p->pci_cb_p;
	} else
		pci_p->pci_cb_p = cmn_p->pci_common_cb_p;

	iommu_create(pci_p);

	if (cmn_p->pci_common_refcnt == 0) {
		ecc_create(pci_p);
		cmn_p->pci_common_ecc_p = pci_p->pci_ecc_p;
	} else
		pci_p->pci_ecc_p = cmn_p->pci_common_ecc_p;

	pbm_create(pci_p);
	sc_create(pci_p);

	pci_fm_create(pci_p);

	if ((ret = pci_intr_setup(pci_p)) != DDI_SUCCESS)
		goto done;

	pci_kstat_create(pci_p);

	cmn_p->pci_common_attachcnt++;
	cmn_p->pci_common_refcnt++;
done:
	mutex_exit(&pci_global_mutex);
	if (ret != DDI_SUCCESS)
		cmn_err(CE_WARN, "pci_obj_setup failed %x", ret);
	return (ret);
}

/* called by pci_detach() DDI_DETACH to destroy pci objects */
void
pci_obj_destroy(pci_t *pci_p)
{
	pci_common_t *cmn_p;
	mutex_enter(&pci_global_mutex);

	cmn_p = pci_p->pci_common_p;
	cmn_p->pci_common_refcnt--;
	cmn_p->pci_common_attachcnt--;

	pci_kstat_destroy(pci_p);

	/* schizo non-shared objects */
	pci_fm_destroy(pci_p);

	sc_destroy(pci_p);
	pbm_destroy(pci_p);
	iommu_destroy(pci_p);
	ib_destroy(pci_p);

	if (cmn_p->pci_common_refcnt != 0) {
		pci_intr_teardown(pci_p);
		cmn_p->pci_p[pci_p->pci_side] = NULL;
		mutex_exit(&pci_global_mutex);
		return;
	}

	/* schizo shared objects - uses cmn_p, must be destroyed before cmn */
	ecc_destroy(pci_p);
	cb_destroy(pci_p);

	free_pci_common_soft_state(cmn_p->pci_common_id);
	pci_intr_teardown(pci_p);
	mutex_exit(&pci_global_mutex);
}

/* called by pci_attach() DDI_RESUME to (re)initialize pci objects */
void
pci_obj_resume(pci_t *pci_p)
{
	pci_common_t *cmn_p = pci_p->pci_common_p;

	mutex_enter(&pci_global_mutex);

	ib_configure(pci_p->pci_ib_p);
	iommu_configure(pci_p->pci_iommu_p);

	if (cmn_p->pci_common_attachcnt == 0)
		ecc_configure(pci_p);

	ib_resume(pci_p->pci_ib_p);

	pbm_configure(pci_p->pci_pbm_p);
	sc_configure(pci_p->pci_sc_p);

	if (cmn_p->pci_common_attachcnt == 0)
		cb_resume(pci_p->pci_cb_p);

	pbm_resume(pci_p->pci_pbm_p);

	cmn_p->pci_common_attachcnt++;
	mutex_exit(&pci_global_mutex);
}

/* called by pci_detach() DDI_SUSPEND to suspend pci objects */
void
pci_obj_suspend(pci_t *pci_p)
{
	mutex_enter(&pci_global_mutex);

	pbm_suspend(pci_p->pci_pbm_p);
	ib_suspend(pci_p->pci_ib_p);

	if (!--pci_p->pci_common_p->pci_common_attachcnt)
		cb_suspend(pci_p->pci_cb_p);

	mutex_exit(&pci_global_mutex);
}

/*
 * add an additional 0x35 or 0x36 ino interrupt on platforms don't have them
 * This routine has multiple places that assumes interrupt takes one cell
 * each and cell size is same as integer size.
 */
static int
pci_intr_setup(pci_t *pci_p)
{
	dev_info_t *dip = pci_p->pci_dip;
	pbm_t *pbm_p = pci_p->pci_pbm_p;
	cb_t *cb_p = pci_p->pci_cb_p;
	uint32_t *intr_buf, *new_intr_buf;
	int intr_len, intr_cnt, ret;

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "interrupts", (caddr_t)&intr_buf, &intr_len) != DDI_SUCCESS)
		cmn_err(CE_PANIC, "%s%d: no interrupts property\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));

	intr_cnt = BYTES_TO_1275_CELLS(intr_len);
	if (intr_cnt < CBNINTR_CDMA)	/* CBNINTR_CDMA is 0 based */
		cmn_err(CE_PANIC, "%s%d: <%d interrupts", ddi_driver_name(dip),
		    ddi_get_instance(dip), CBNINTR_CDMA);

	if (intr_cnt == CBNINTR_CDMA)
		intr_cnt++;

	new_intr_buf = kmem_alloc(CELLS_1275_TO_BYTES(intr_cnt), KM_SLEEP);
	bcopy(intr_buf, new_intr_buf, intr_len);
	kmem_free(intr_buf, intr_len);

	new_intr_buf[CBNINTR_CDMA] = PBM_CDMA_INO_BASE + pci_p->pci_side;
	pci_p->pci_inos = new_intr_buf;
	pci_p->pci_inos_len = CELLS_1275_TO_BYTES(intr_cnt);

	if (ndi_prop_update_int_array(DDI_DEV_T_NONE, dip, "interrupts",
	    (int *)new_intr_buf, intr_cnt))
		cmn_err(CE_PANIC, "%s%d: cannot update interrupts property\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));

	if (pci_p->pci_common_p->pci_common_refcnt == 0) {
		cb_p->cb_no_of_inos = intr_cnt;
		if (ret = cb_register_intr(pci_p))
			goto teardown;
		if (ret = ecc_register_intr(pci_p))
			goto teardown;

		intr_dist_add(cb_intr_dist, cb_p);
		cb_enable_intr(pci_p);
		ecc_enable_intr(pci_p);
	}

	if (CHIP_TYPE(pci_p) != PCI_CHIP_SCHIZO)
		pbm_p->pbm_sync_ino = pci_p->pci_inos[CBNINTR_PBM];
	if (ret = pbm_register_intr(pbm_p)) {
		if (pci_p->pci_common_p->pci_common_refcnt == 0)
			intr_dist_rem(cb_intr_dist, cb_p);
		goto teardown;
	}
	intr_dist_add(pbm_intr_dist, pbm_p);
	ib_intr_enable(pci_p, pci_p->pci_inos[CBNINTR_PBM]);
	ib_intr_enable(pci_p, pci_p->pci_inos[CBNINTR_CDMA]);

	intr_dist_add_weighted(ib_intr_dist_all, pci_p->pci_ib_p);
	return (DDI_SUCCESS);
teardown:
	pci_intr_teardown(pci_p);
	return (ret);
}

uint64_t
pci_sc_configure(pci_t *pci_p)
{
	int instance;
	dev_info_t *dip = pci_p->pci_dip;

	instance = ddi_get_instance(dip);
	if ((pci_xmits_sc_max_prf & (1 << instance)) &&
	    (CHIP_TYPE(pci_p) == PCI_CHIP_XMITS))
		return (XMITS_SC_MAX_PRF);
	else
		return (0);
}

static void
pci_schizo_cdma_sync(pbm_t *pbm_p)
{
	pci_t *pci_p = pbm_p->pbm_pci_p;
	hrtime_t start_time;
	volatile uint64_t *clr_p = ib_clear_intr_reg_addr(pci_p->pci_ib_p,
	    pci_p->pci_inos[CBNINTR_CDMA]);
	uint32_t fail_cnt = pci_cdma_intr_count;

	mutex_enter(&pbm_p->pbm_sync_mutex);
#ifdef PBM_CDMA_DEBUG
	pbm_p->pbm_cdma_req_cnt++;
#endif /* PBM_CDMA_DEBUG */
	pbm_p->pbm_cdma_flag = PBM_CDMA_PEND;
	IB_INO_INTR_TRIG(clr_p);
wait:
	start_time = gethrtime();
	while (pbm_p->pbm_cdma_flag != PBM_CDMA_DONE) {
		if (gethrtime() - start_time <= pci_cdma_intr_timeout)
			continue;
		if (--fail_cnt > 0)
			goto wait;
		if (pbm_p->pbm_cdma_flag == PBM_CDMA_DONE)
			break;
		cmn_err(CE_PANIC, "%s (%s): consistent dma sync timeout",
		    pbm_p->pbm_nameinst_str, pbm_p->pbm_nameaddr_str);
	}
#ifdef PBM_CDMA_DEBUG
	if (pbm_p->pbm_cdma_flag != PBM_CDMA_DONE)
		pbm_p->pbm_cdma_to_cnt++;
	else {
		start_time = gethrtime() - start_time;
		pbm_p->pbm_cdma_success_cnt++;
		pbm_p->pbm_cdma_latency_sum += start_time;
		if (start_time > pbm_p->pbm_cdma_latency_max)
			pbm_p->pbm_cdma_latency_max = start_time;
	}
#endif /* PBM_CDMA_DEBUG */
	mutex_exit(&pbm_p->pbm_sync_mutex);
}

#if !defined(lint)
#include <sys/cpuvar.h>
#endif

#define	SYNC_HW_BUSY(pa, mask)	(lddphysio(pa) & (mask))

/*
 * Consistent DMA Sync/Flush
 *
 * XMITS and Tomatillo use multi-threaded sync/flush register.
 * Called from interrupt wrapper: the associated ino is used to index
 *	the distinctive register bit.
 * Called from pci_dma_sync(): the bit belongs to PBM is shared
 *	for all calls from pci_dma_sync(). Xmits requires serialization
 *	while Tomatillo does not.
 */
void
pci_pbm_dma_sync(pbm_t *pbm_p, ib_ino_t ino)
{
	pci_t *pci_p = pbm_p->pbm_pci_p;
	hrtime_t start_time;
	uint64_t ino_mask, sync_reg_pa;
	volatile uint64_t flag_val;
	uint32_t locked, chip_type = CHIP_TYPE(pci_p);
	int	i;

	if (chip_type == PCI_CHIP_SCHIZO) {
		pci_schizo_cdma_sync(pbm_p);
		return;
	}

	sync_reg_pa = pbm_p->pbm_sync_reg_pa;

	locked = 0;
	if (((chip_type == PCI_CHIP_XMITS) && (ino == pbm_p->pbm_sync_ino)) ||
	    pci_sync_lock) {
		locked = 1;
		mutex_enter(&pbm_p->pbm_sync_mutex);
	}
	ino_mask = 1ull << ino;
	stdphysio(sync_reg_pa, ino_mask);

	for (i = 0; i < 5; i++) {
		if ((flag_val = SYNC_HW_BUSY(sync_reg_pa, ino_mask)) == 0)
			goto done;
	}

	start_time = gethrtime();
	for (; (flag_val = SYNC_HW_BUSY(sync_reg_pa, ino_mask)) != 0; i++) {
		if (gethrtime() - start_time > pci_sync_buf_timeout)
			break;
	}

	if (flag_val && SYNC_HW_BUSY(sync_reg_pa, ino_mask) && !panicstr)
		cmn_err(CE_PANIC, "%s: pbm dma sync %lx,%lx timeout!",
		    pbm_p->pbm_nameaddr_str, sync_reg_pa, flag_val);
done:
	/* optional: stdphysio(sync_reg_pa - 8, ino_mask); */
	if (locked)
		mutex_exit(&pbm_p->pbm_sync_mutex);

	if (tomatillo_store_store_wrka) {
#if !defined(lint)
		kpreempt_disable();
#endif
		tomatillo_store_store_order();
#if !defined(lint)
		kpreempt_enable();
#endif
	}

}

/*ARGSUSED*/
void
pci_fix_ranges(pci_ranges_t *rng_p, int rng_entries)
{
}

/*
 * map_pci_registers
 *
 * This function is called from the attach routine to map the registers
 * accessed by this driver.
 *
 * used by: pci_attach()
 *
 * return value: DDI_FAILURE on failure
 */
int
map_pci_registers(pci_t *pci_p, dev_info_t *dip)
{
	ddi_device_acc_attr_t attr;
	int len;

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;

	/*
	 * Register set 0 is PCI CSR Base
	 */
	if (ddi_regs_map_setup(dip, 0, &pci_p->pci_address[0], 0, 0,
	    &attr, &pci_p->pci_ac[0]) != DDI_SUCCESS) {
		len = 0;
		goto fail;
	}
	/*
	 * Register set 1 is Schizo CSR Base
	 */
	if (ddi_regs_map_setup(dip, 1, &pci_p->pci_address[1], 0, 0,
	    &attr, &pci_p->pci_ac[1]) != DDI_SUCCESS) {
		len = 1;
		goto fail;
	}

	/*
	 * The third register set contains the bridge's configuration
	 * header.  This header is at the very beginning of the bridge's
	 * configuration space.  This space has litte-endian byte order.
	 */
	attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	if (ddi_regs_map_setup(dip, 2, &pci_p->pci_address[2], 0,
	    PCI_CONF_HDR_SIZE, &attr, &pci_p->pci_ac[2]) != DDI_SUCCESS) {
		len = 2;
		goto fail;
	}

	if (ddi_getproplen(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", &len) || (len / sizeof (pci_nexus_regspec_t) < 4))
		goto done;

	/*
	 * The optional fourth register bank points to the
	 * interrupt concentrator registers.
	 */
	attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	if (ddi_regs_map_setup(dip, 3, &pci_p->pci_address[3], 0,
	    0, &attr, &pci_p->pci_ac[3]) != DDI_SUCCESS) {
		len = 3;
		goto fail;
	}

done:
	DEBUG4(DBG_ATTACH, dip, "address (%p,%p,%p,%p)\n",
	    pci_p->pci_address[0], pci_p->pci_address[1],
	    pci_p->pci_address[2], pci_p->pci_address[3]);

	return (DDI_SUCCESS);


fail:
	cmn_err(CE_WARN, "%s%d: unable to map reg entry %d\n",
	    ddi_driver_name(dip), ddi_get_instance(dip), len);
	for (; len--; ddi_regs_map_free(&pci_p->pci_ac[len]))
		;
	return (DDI_FAILURE);
}

/*
 * unmap_pci_registers:
 *
 * This routine unmap the registers mapped by map_pci_registers.
 *
 * used by: pci_detach()
 *
 * return value: none
 */
void
unmap_pci_registers(pci_t *pci_p)
{
	int i;

	for (i = 0; i < 4; i++) {
		if (pci_p->pci_ac[i])
			ddi_regs_map_free(&pci_p->pci_ac[i]);
	}
}

uint64_t
ib_get_map_reg(ib_mondo_t mondo, uint32_t cpu_id)
{
	uint32_t agent_id;
	uint32_t node_id;

	/* ensure that cpu_id is only 10 bits. */
	ASSERT((cpu_id & ~0x3ff) == 0);

	agent_id = cpu_id & 0x1f;
	node_id = (cpu_id >> 5) & 0x1f;

	return ((mondo) | (agent_id << COMMON_INTR_MAP_REG_TID_SHIFT) |
	    (node_id << SCHIZO_INTR_MAP_REG_NID_SHIFT) |
	    COMMON_INTR_MAP_REG_VALID);
}

uint32_t
ib_map_reg_get_cpu(volatile uint64_t reg)
{
	return (((reg & COMMON_INTR_MAP_REG_TID) >>
	    COMMON_INTR_MAP_REG_TID_SHIFT) |
	    ((reg & SCHIZO_INTR_MAP_REG_NID) >>
	    (SCHIZO_INTR_MAP_REG_NID_SHIFT-5)));
}

uint64_t *
ib_intr_map_reg_addr(ib_t *ib_p, ib_ino_t ino)
{
	/*
	 * Schizo maps all interrupts in one contiguous area.
	 * (PCI_CSRBase + 0x00.1000 + INO * 8).
	 */
	return ((uint64_t *)(ib_p->ib_intr_map_regs) + (ino & 0x3f));
}

uint64_t *
ib_clear_intr_reg_addr(ib_t *ib_p, ib_ino_t ino)	/* XXX - needs work */
{
	/*
	 * Schizo maps clear intr. registers in contiguous area.
	 * (PCI_CSRBase + 0x00.1400 + INO * 8).
	 */
	return ((uint64_t *)(ib_p->ib_slot_clear_intr_regs) + (ino & 0x3f));
}

/*
 * schizo does not have mapping register per slot, so no sharing
 * is done.
 */
/*ARGSUSED*/
void
ib_ino_map_reg_share(ib_t *ib_p, ib_ino_t ino, ib_ino_info_t *ino_p)
{
}

/*
 * return true if there are interrupts using this mapping register
 */
/*ARGSUSED*/
int
ib_ino_map_reg_unshare(ib_t *ib_p, ib_ino_t ino, ib_ino_info_t *ino_p)
{
	return (ino_p->ino_ipil_size);
}

void
pci_pbm_intr_dist(pbm_t *pbm_p)
{
	pci_t *pci_p = pbm_p->pbm_pci_p;
	ib_t *ib_p = pci_p->pci_ib_p;
	ib_ino_t ino = IB_MONDO_TO_INO(pci_p->pci_inos[CBNINTR_CDMA]);

	mutex_enter(&pbm_p->pbm_sync_mutex);
	ib_intr_dist_nintr(ib_p, ino, ib_intr_map_reg_addr(ib_p, ino));
	mutex_exit(&pbm_p->pbm_sync_mutex);
}

uint32_t
pci_xlate_intr(dev_info_t *dip, dev_info_t *rdip, ib_t *ib_p, uint32_t intr)
{
	return (IB_INO_TO_MONDO(ib_p, intr));
}


/*
 * Return the cpuid to to be used for an ino.  We have no special cpu
 * assignment constraints for this nexus, so just call intr_dist_cpuid().
 */
/* ARGSUSED */
uint32_t
pci_intr_dist_cpuid(ib_t *ib_p, ib_ino_info_t *ino_p)
{
	return (intr_dist_cpuid());
}

void
pci_cb_teardown(pci_t *pci_p)
{
	cb_t 	*cb_p = pci_p->pci_cb_p;
	uint32_t mondo;

	if (!pci_buserr_interrupt)
		return;

	mondo = ((pci_p->pci_cb_p->cb_ign  << PCI_INO_BITS) |
	    pci_p->pci_inos[CBNINTR_BUS_ERROR]);
	mondo = CB_MONDO_TO_XMONDO(pci_p->pci_cb_p, mondo);

	cb_disable_nintr(cb_p, CBNINTR_BUS_ERROR, IB_INTR_WAIT);
	VERIFY(rem_ivintr(mondo, pci_pil[CBNINTR_BUS_ERROR]) == 0);
}

int
cb_register_intr(pci_t *pci_p)
{
	uint32_t mondo;

	if (!pci_buserr_interrupt)
		return (DDI_SUCCESS);

	mondo = ((pci_p->pci_cb_p->cb_ign << PCI_INO_BITS) |
	    pci_p->pci_inos[CBNINTR_BUS_ERROR]);
	mondo = CB_MONDO_TO_XMONDO(pci_p->pci_cb_p, mondo);

	VERIFY(add_ivintr(mondo, pci_pil[CBNINTR_BUS_ERROR],
	    (intrfunc)cb_buserr_intr, (caddr_t)pci_p->pci_cb_p,
	    NULL, NULL) == 0);

	return (PCI_ATTACH_RETCODE(PCI_CB_OBJ, PCI_OBJ_INTR_ADD, DDI_SUCCESS));
}

void
cb_enable_intr(pci_t *pci_p)
{
	if (pci_buserr_interrupt)
		cb_enable_nintr(pci_p, CBNINTR_BUS_ERROR);
}

uint64_t
cb_ino_to_map_pa(cb_t *cb_p, ib_ino_t ino)
{
	return (cb_p->cb_map_pa + (ino << 3));
}

uint64_t
cb_ino_to_clr_pa(cb_t *cb_p, ib_ino_t ino)
{
	return (cb_p->cb_clr_pa + (ino << 3));
}

/*
 * Useful on psycho only.
 */
int
cb_remove_xintr(pci_t *pci_p, dev_info_t *dip, dev_info_t *rdip, ib_ino_t ino,
ib_mondo_t mondo)
{
	return (DDI_FAILURE);
}

void
pbm_configure(pbm_t *pbm_p)
{
	pci_t *pci_p = pbm_p->pbm_pci_p;
	dev_info_t *dip = pbm_p->pbm_pci_p->pci_dip;
	int instance = ddi_get_instance(dip);
	uint64_t l;
	uint64_t mask = 1ll << instance;
	ushort_t s = 0;

	l = *pbm_p->pbm_ctrl_reg;	/* save control register state */
	DEBUG1(DBG_ATTACH, dip, "pbm_configure: ctrl reg=%llx\n", l);

	/*
	 * See if any SERR# signals are asserted.  We'll clear them later.
	 */
	if (l & COMMON_PCI_CTRL_SERR)
		cmn_err(CE_WARN, "%s%d: SERR asserted on pci bus\n",
		    ddi_driver_name(dip), instance);

	/*
	 * Determine if PCI bus is running at 33 or 66 mhz.
	 */
	if (l & COMMON_PCI_CTRL_SPEED)
		pbm_p->pbm_speed = PBM_SPEED_66MHZ;
	else
		pbm_p->pbm_speed = PBM_SPEED_33MHZ;
	DEBUG1(DBG_ATTACH, dip, "pbm_configure: %d mhz\n",
	    pbm_p->pbm_speed  == PBM_SPEED_66MHZ ? 66 : 33);

	if (pci_set_dto_value & mask) {
		l &= ~(3ull << SCHIZO_PCI_CTRL_PTO_SHIFT);
		l |= pci_dto_value << SCHIZO_PCI_CTRL_PTO_SHIFT;
	} else if (PCI_CHIP_ID(pci_p) >= TOMATILLO_VER_21) {
		l |= (3ull << SCHIZO_PCI_CTRL_PTO_SHIFT);
	}

	/*
	 * Enable error interrupts.
	 */
	if (pci_error_intr_enable & mask)
		l |= SCHIZO_PCI_CTRL_ERR_INT_EN;
	else
		l &= ~SCHIZO_PCI_CTRL_ERR_INT_EN;

	/*
	 * Enable pci streaming byte errors and error interrupts.
	 */
	if (pci_sbh_error_intr_enable & mask)
		l |= SCHIZO_PCI_CTRL_SBH_INT_EN;
	else
		l &= ~SCHIZO_PCI_CTRL_SBH_INT_EN;

	/*
	 * Enable pci discard timeout error interrupt.
	 */
	if (pci_mmu_error_intr_enable & mask)
		l |= SCHIZO_PCI_CTRL_MMU_INT_EN;
	else
		l &= ~SCHIZO_PCI_CTRL_MMU_INT_EN;

	/*
	 * Enable PCI-X error interrupts.
	 */
	if (CHIP_TYPE(pci_p) == PCI_CHIP_XMITS) {

		if (xmits_error_intr_enable & mask)
			l |= XMITS_PCI_CTRL_X_ERRINT_EN;
		else
			l &= ~XMITS_PCI_CTRL_X_ERRINT_EN;
		/*
		 * Panic if older XMITS hardware is found.
		 */
		if (*pbm_p->pbm_ctrl_reg & XMITS_PCI_CTRL_X_MODE)
			if (PCI_CHIP_ID(pci_p) <= XMITS_VER_10)
				cmn_err(CE_PANIC, "%s (%s): PCIX mode "
				"unsupported on XMITS version %d\n",
				    pbm_p->pbm_nameinst_str,
				    pbm_p->pbm_nameaddr_str, CHIP_VER(pci_p));

		if (xmits_perr_recov_int_enable) {
			if (PCI_CHIP_ID(pci_p) >= XMITS_VER_30) {
				uint64_t pcix_err;
				/*
				 * Enable interrupt on PERR
				 */
				pcix_err = *pbm_p->pbm_pcix_err_stat_reg;
				pcix_err |= XMITS_PCIX_STAT_PERR_RECOV_INT_EN;
				pcix_err &= ~XMITS_PCIX_STAT_SERR_ON_PERR;
				*pbm_p->pbm_pcix_err_stat_reg = pcix_err;
			}
		}

		/*
		 * Enable parity error detection on internal memories
		 */
		*pbm_p->pbm_pci_ped_ctrl = 0x3fff;
	}

	/*
	 * Enable/disable bus parking.
	 */
	if ((pci_bus_parking_enable & mask) &&
	    !ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "no-bus-parking"))
		l |= SCHIZO_PCI_CTRL_ARB_PARK;
	else
		l &= ~SCHIZO_PCI_CTRL_ARB_PARK;

	/*
	 * Enable arbitration.
	 */
	l |= PCI_CHIP_ID(pci_p) == XMITS_VER_10 ? XMITS10_PCI_CTRL_ARB_EN_MASK :
	    SCHIZO_PCI_CTRL_ARB_EN_MASK;

	/*
	 * Make sure SERR is clear
	 */
	l |= COMMON_PCI_CTRL_SERR;


	/*
	 * Enable DTO interrupt, if desired.
	 */

	if (PCI_CHIP_ID(pci_p) <= TOMATILLO_VER_20 || (pci_dto_intr_enable &
	    mask))
		l |=	 (TOMATILLO_PCI_CTRL_DTO_INT_EN);
	else
		l &=	 ~(TOMATILLO_PCI_CTRL_DTO_INT_EN);

	l |= TOMATILLO_PCI_CTRL_PEN_RD_MLTPL |
	    TOMATILLO_PCI_CTRL_PEN_RD_ONE |
	    TOMATILLO_PCI_CTRL_PEN_RD_LINE;

	/*
	 * Now finally write the control register with the appropriate value.
	 */
	DEBUG1(DBG_ATTACH, dip, "pbm_configure: ctrl reg=%llx\n", l);
	*pbm_p->pbm_ctrl_reg = l;

	/*
	 * Enable IO Prefetch on Tomatillo
	 */
	if (CHIP_TYPE(pci_p) == PCI_CHIP_TOMATILLO) {
		volatile uint64_t *ioc_csr_p = pbm_p->pbm_ctrl_reg +
		    ((TOMATILLO_IOC_CSR_OFF -
		    SCHIZO_PCI_CTRL_REG_OFFSET) >> 3);
		*ioc_csr_p = TOMATILLO_WRT_PEN |
		    (1 << TOMATILLO_POFFSET_SHIFT) |
		    TOMATILLO_C_PEN_RD_MLTPL |
		    TOMATILLO_C_PEN_RD_ONE |
		    TOMATILLO_C_PEN_RD_LINE;
	}

	/*
	 * Allow DMA write parity errors to generate an interrupt.
	 * This is implemented on Schizo 2.5 and greater and XMITS 3.0
	 * and greater.  Setting this on earlier versions of XMITS 3.0
	 * has no affect.
	 */
	if (((CHIP_TYPE(pci_p) == PCI_CHIP_SCHIZO) &&
	    PCI_CHIP_ID(pci_p) >= SCHIZO_VER_25) ||
	    (CHIP_TYPE(pci_p) == PCI_CHIP_XMITS)) {
		volatile uint64_t *pbm_icd = pbm_p->pbm_ctrl_reg +
		    ((SCHIZO_PERF_PCI_ICD_OFFSET -
		    SCHIZO_PCI_CTRL_REG_OFFSET) >> 3);

		*pbm_icd |= SCHIZO_PERF_PCI_ICD_DMAW_PARITY_INT_ENABLE;
	}

	/*
	 * Clear any PBM errors.
	 */
	l = (SCHIZO_PCI_AFSR_E_MASK << SCHIZO_PCI_AFSR_PE_SHIFT) |
	    (SCHIZO_PCI_AFSR_E_MASK << SCHIZO_PCI_AFSR_SE_SHIFT);
	*pbm_p->pbm_async_flt_status_reg = l;

	/*
	 * Allow the diag register to be set based upon variable that
	 * can be configured via /etc/system.
	 */
	l = *pbm_p->pbm_diag_reg;
	DEBUG1(DBG_ATTACH, dip, "pbm_configure: PCI diag reg=%llx\n", l);

	/*
	 * Enable/disable retry limit.
	 */
	if (pci_retry_disable & mask)
		l |= COMMON_PCI_DIAG_DIS_RETRY;
	else
		l &= ~COMMON_PCI_DIAG_DIS_RETRY;

	/*
	 * Enable/disable DMA write/interrupt synchronization.
	 */
	if (pci_intsync_disable & mask)
		l |= COMMON_PCI_DIAG_DIS_INTSYNC;
	else
		l &= ~COMMON_PCI_DIAG_DIS_INTSYNC;

	/*
	 * Enable/disable retry arbitration priority.
	 */
	if (pci_enable_retry_arb & mask)
		l &= ~SCHIZO_PCI_DIAG_DIS_RTRY_ARB;
	else
		l |= SCHIZO_PCI_DIAG_DIS_RTRY_ARB;

	DEBUG1(DBG_ATTACH, dip, "pbm_configure: PCI diag reg=%llx\n", l);
	*pbm_p->pbm_diag_reg = l;

	/*
	 * Enable SERR# and parity reporting via command register.
	 */
	s = pci_perr_enable & mask ? PCI_COMM_PARITY_DETECT : 0;
	s |= pci_serr_enable & mask ? PCI_COMM_SERR_ENABLE : 0;

	DEBUG1(DBG_ATTACH, dip, "pbm_configure: conf command reg=%x\n", s);
	pbm_p->pbm_config_header->ch_command_reg = s;

	/*
	 * Clear error bits in configuration status register.
	 */
	s = PCI_STAT_PERROR | PCI_STAT_S_PERROR |
	    PCI_STAT_R_MAST_AB | PCI_STAT_R_TARG_AB |
	    PCI_STAT_S_TARG_AB | PCI_STAT_S_PERROR;
	DEBUG1(DBG_ATTACH, dip, "pbm_configure: conf status reg=%x\n", s);
	pbm_p->pbm_config_header->ch_status_reg = s;

	/*
	 * The current versions of the obp are suppose to set the latency
	 * timer register but do not.  Bug 1234181 is open against this
	 * problem.  Until this bug is fixed we check to see if the obp
	 * has attempted to set the latency timer register by checking
	 * for the existence of a "latency-timer" property.
	 */
	if (pci_set_latency_timer_register) {
		DEBUG1(DBG_ATTACH, dip,
		    "pbm_configure: set schizo latency timer to %x\n",
		    pci_latency_timer);
		pbm_p->pbm_config_header->ch_latency_timer_reg =
		    pci_latency_timer;
	}

	(void) ndi_prop_update_int(DDI_DEV_T_ANY, dip, "latency-timer",
	    (int)pbm_p->pbm_config_header->ch_latency_timer_reg);

	/*
	 * Adjust xmits_upper_retry_counter if set in /etc/system
	 *
	 * NOTE: current implementation resets UPPR_RTRY counter for
	 * _all_ XMITS' PBMs and does not support tuning per PBM.
	 */
	if (CHIP_TYPE(pci_p) == PCI_CHIP_XMITS) {
		uint_t xurc = xmits_upper_retry_counter &
		    XMITS_UPPER_RETRY_MASK;

		if (xurc) {
			*pbm_p->pbm_upper_retry_counter_reg = (uint64_t)xurc;
			DEBUG1(DBG_ATTACH, dip, "pbm_configure: Setting XMITS"
			    " uppr_rtry counter = 0x%lx\n",
			    *pbm_p->pbm_upper_retry_counter_reg);
		}
	}
}

uint_t
pbm_disable_pci_errors(pbm_t *pbm_p)
{
	pci_t *pci_p = pbm_p->pbm_pci_p;
	ib_t *ib_p = pci_p->pci_ib_p;

	/*
	 * Disable error and streaming byte hole interrupts via the
	 * PBM control register.
	 */
	*pbm_p->pbm_ctrl_reg &=
	    ~(SCHIZO_PCI_CTRL_ERR_INT_EN | SCHIZO_PCI_CTRL_SBH_INT_EN |
	    SCHIZO_PCI_CTRL_MMU_INT_EN);

	/*
	 * Disable error interrupts via the interrupt mapping register.
	 */
	ib_intr_disable(ib_p, pci_p->pci_inos[CBNINTR_PBM], IB_INTR_NOWAIT);
	return (BF_NONE);
}

/*
 * Layout of the dvma context bucket bitmap entry:
 *
 *	63 - 56		55 - 0
 *	8-bit lock	56-bit, each represent one context
 *	DCB_LOCK_BITS	DCB_BMAP_BITS
 */
#define	DCB_LOCK_BITS	8
#define	DCB_BMAP_BITS	(64 - DCB_LOCK_BITS)

dvma_context_t
pci_iommu_get_dvma_context(iommu_t *iommu_p, dvma_addr_t dvma_pg_index)
{
	dvma_context_t ctx;
	int i = (dvma_pg_index >> 6) & 0x1f;	/* 5 bit index within bucket */
	uint64_t ctx_mask, test = 1ull << i;
	uint32_t bucket_no = dvma_pg_index & 0x3f;
	uint64_t *bucket_ptr = iommu_p->iommu_ctx_bitmap + bucket_no;

	uint32_t spl = ddi_enter_critical();	/* block interrupts */
	if (ldstub((uint8_t *)bucket_ptr)) {	/* try lock */
		ddi_exit_critical(spl);		/* unblock interrupt */
		pci_iommu_ctx_lock_failure++;
		return (0);
	}

	/* clear lock bits */
	ctx_mask = (*bucket_ptr << DCB_LOCK_BITS) >> DCB_LOCK_BITS;
	ASSERT(*bucket_ptr >> DCB_BMAP_BITS == 0xff);
	ASSERT(ctx_mask >> DCB_BMAP_BITS == 0);

	if (ctx_mask & test)			/* quick check i bit */
		for (i = 0, test = 1ull; test & ctx_mask; test <<= 1, i++)
			;
	if (i < DCB_BMAP_BITS)
		ctx_mask |= test;
	*bucket_ptr = ctx_mask;			/* unlock */
	ddi_exit_critical(spl);			/* unblock interrupts */

	ctx = i < DCB_BMAP_BITS ? (bucket_no << 6) | i : 0;
	DEBUG3(DBG_DMA_MAP, iommu_p->iommu_pci_p->pci_dip,
	    "get_dvma_context: ctx_mask=0x%x.%x ctx=0x%x\n",
	    (uint32_t)(ctx_mask >> 32), (uint32_t)ctx_mask, ctx);
	return (ctx);
}

void
pci_iommu_free_dvma_context(iommu_t *iommu_p, dvma_context_t ctx)
{
	uint64_t ctx_mask;
	uint32_t spl, bucket_no = ctx >> 6;
	int bit_no = ctx & 0x3f;
	uint64_t *bucket_ptr = iommu_p->iommu_ctx_bitmap + bucket_no;

	DEBUG1(DBG_DMA_MAP, iommu_p->iommu_pci_p->pci_dip,
	    "free_dvma_context: ctx=0x%x\n", ctx);

	spl = ddi_enter_critical();			/* block interrupts */
	while (ldstub((uint8_t *)bucket_ptr))		/* spin lock */
		;
	ctx_mask = (*bucket_ptr << DCB_LOCK_BITS) >> DCB_LOCK_BITS;
							/* clear lock bits */
	ASSERT(ctx_mask & (1ull << bit_no));
	*bucket_ptr = ctx_mask ^ (1ull << bit_no);	/* clear & unlock */
	ddi_exit_critical(spl);				/* unblock interrupt */
}

int
pci_sc_ctx_inv(dev_info_t *dip, sc_t *sc_p, ddi_dma_impl_t *mp)
{
	dvma_context_t ctx = MP2CTX(mp);
	volatile uint64_t *reg_addr = sc_p->sc_ctx_match_reg + ctx;
	uint64_t matchreg;

	if (!*reg_addr) {
		DEBUG1(DBG_SC, dip, "ctx=%x no match\n", ctx);
		return (DDI_SUCCESS);
	}

	*sc_p->sc_ctx_invl_reg = ctx;	/* 1st flush write */
	matchreg = *reg_addr;		/* re-fetch after 1st flush */
	if (!matchreg)
		return (DDI_SUCCESS);

	matchreg = (matchreg << SC_ENT_SHIFT) >> SC_ENT_SHIFT;	/* low 16-bit */
	do {
		if (matchreg & 1)
			*sc_p->sc_ctx_invl_reg = ctx;
		matchreg >>= 1;
	} while (matchreg);

	if (pci_ctx_no_compat || !*reg_addr)	/* compat: active ctx flush */
		return (DDI_SUCCESS);

	pci_ctx_unsuccess_count++;
	if (pci_ctx_flush_warn)
		cmn_err(pci_ctx_flush_warn, "%s%d: ctx flush unsuccessful\n",
		    NAMEINST(dip));
	return (DDI_FAILURE);
}

void
pci_cb_setup(pci_t *pci_p)
{
	dev_info_t *dip = pci_p->pci_dip;
	cb_t *cb_p = pci_p->pci_cb_p;
	uint64_t pa;
	uint32_t chip_id = PCI_CHIP_ID(pci_p);
	DEBUG1(DBG_ATTACH, dip, "cb_create: chip id %d\n", chip_id);

	if (CHIP_TYPE(pci_p) == PCI_CHIP_TOMATILLO) {
		if ((!tm_mtlb_gc_manual) &&
		    (PCI_CHIP_ID(pci_p) <= TOMATILLO_VER_24))
			tm_mtlb_gc = 1;

		if (PCI_CHIP_ID(pci_p) <= TOMATILLO_VER_23) {
			/* Workaround for the Tomatillo ASIC Erratum #72 */
			ignore_invalid_vecintr = 1;
			tomatillo_store_store_wrka = 1;
			tomatillo_disallow_bypass = 1;
			if (pci_spurintr_msgs == PCI_SPURINTR_MSG_DEFAULT)
				pci_spurintr_msgs = 0;
		}
	}

	if (chip_id == TOMATILLO_VER_20 || chip_id == TOMATILLO_VER_21)
		cmn_err(CE_WARN, "Unsupported Tomatillo rev (%x)", chip_id);

	if (chip_id < SCHIZO_VER_23)
		pci_ctx_no_active_flush = 1;

	cb_p->cb_node_id = PCI_ID_TO_NODEID(pci_p->pci_id);
	cb_p->cb_ign	 = PCI_ID_TO_IGN(pci_p->pci_id);

	/*
	 * schizo control status reg bank is on the 2nd "reg" property entry
	 * interrupt mapping/clear/state regs are on the 1st "reg" entry.
	 *
	 * ALL internal interrupts except pbm interrupts are shared by both
	 * sides, 1st-side-attached is used as *the* owner.
	 */
	pa = (uint64_t)hat_getpfnum(kas.a_hat, pci_p->pci_address[1]);
	cb_p->cb_base_pa = pa << MMU_PAGESHIFT;

	pa = pci_p->pci_address[3] ?
	    (uint64_t)hat_getpfnum(kas.a_hat, pci_p->pci_address[3]) : 0;
	cb_p->cb_icbase_pa = (pa == PFN_INVALID) ? 0 : pa << MMU_PAGESHIFT;

	pa = (uint64_t)hat_getpfnum(kas.a_hat, pci_p->pci_address[0])
	    << MMU_PAGESHIFT;
	cb_p->cb_map_pa = pa + SCHIZO_IB_INTR_MAP_REG_OFFSET;
	cb_p->cb_clr_pa = pa + SCHIZO_IB_CLEAR_INTR_REG_OFFSET;
	cb_p->cb_obsta_pa = pa + COMMON_IB_OBIO_INTR_STATE_DIAG_REG;
}

void
pci_ecc_setup(ecc_t *ecc_p)
{
	ecc_p->ecc_ue.ecc_errpndg_mask = SCHIZO_ECC_UE_AFSR_ERRPNDG;
	ecc_p->ecc_ue.ecc_offset_mask = SCHIZO_ECC_UE_AFSR_QW_OFFSET;
	ecc_p->ecc_ue.ecc_offset_shift = SCHIZO_ECC_UE_AFSR_QW_OFFSET_SHIFT;
	ecc_p->ecc_ue.ecc_size_log2 = 4;

	ecc_p->ecc_ce.ecc_errpndg_mask = SCHIZO_ECC_CE_AFSR_ERRPNDG;
	ecc_p->ecc_ce.ecc_offset_mask = SCHIZO_ECC_CE_AFSR_QW_OFFSET;
	ecc_p->ecc_ce.ecc_offset_shift = SCHIZO_ECC_CE_AFSR_QW_OFFSET_SHIFT;
	ecc_p->ecc_ce.ecc_size_log2 = 4;
}

ushort_t
pci_ecc_get_synd(uint64_t afsr)
{
	return ((ushort_t)((afsr & SCHIZO_ECC_CE_AFSR_SYND) >>
	    SCHIZO_ECC_CE_AFSR_SYND_SHIFT));
}

/*
 * overwrite dvma end address (only on virtual-dma systems)
 * initialize tsb size
 * reset context bits
 * return: IOMMU CSR bank base address (VA)
 */

uintptr_t
pci_iommu_setup(iommu_t *iommu_p)
{
	pci_dvma_range_prop_t *dvma_prop;
	int dvma_prop_len;

	uintptr_t a;
	pci_t *pci_p = iommu_p->iommu_pci_p;
	dev_info_t *dip = pci_p->pci_dip;
	uint_t tsb_size = iommu_tsb_cookie_to_size(pci_p->pci_tsb_cookie);
	uint_t tsb_size_prop;

	/*
	 * Initializations for Tomatillo's micro TLB bug. errata #82
	 */
	if (tm_mtlb_gc) {
		iommu_p->iommu_mtlb_nreq = 0;
		iommu_p->iommu_mtlb_npgs = 0;
		iommu_p->iommu_mtlb_maxpgs = tm_mtlb_maxpgs;
		iommu_p->iommu_mtlb_req_p = (dvma_unbind_req_t *)
		    kmem_zalloc(sizeof (dvma_unbind_req_t) *
		    (tm_mtlb_maxpgs + 1), KM_SLEEP);
		mutex_init(&iommu_p->iommu_mtlb_lock, NULL, MUTEX_DRIVER, NULL);
	}

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "virtual-dma", (caddr_t)&dvma_prop, &dvma_prop_len) !=
	    DDI_PROP_SUCCESS)
		goto tsb_done;

	if (dvma_prop_len != sizeof (pci_dvma_range_prop_t)) {
		cmn_err(CE_WARN, "%s%d: invalid virtual-dma property",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		goto tsb_end;
	}
	iommu_p->iommu_dvma_end = dvma_prop->dvma_base +
	    (dvma_prop->dvma_len - 1);
	tsb_size_prop = IOMMU_BTOP(dvma_prop->dvma_len) * sizeof (uint64_t);
	tsb_size = MIN(tsb_size_prop, tsb_size);
tsb_end:
	kmem_free(dvma_prop, dvma_prop_len);
tsb_done:
	iommu_p->iommu_tsb_size = iommu_tsb_size_encode(tsb_size);
	iommu_p->iommu_ctx_bitmap =
	    kmem_zalloc(IOMMU_CTX_BITMAP_SIZE, KM_SLEEP);
	*iommu_p->iommu_ctx_bitmap = 1ull;	/* reserve context 0 */

	/*
	 * Determine the virtual address of the register block
	 * containing the iommu control registers and determine
	 * the virtual address of schizo specific iommu registers.
	 */
	a = (uintptr_t)pci_p->pci_address[0];
	iommu_p->iommu_flush_ctx_reg =
	    (uint64_t *)(a + SCHIZO_IOMMU_FLUSH_CTX_REG_OFFSET);
	if (CHIP_TYPE(pci_p) == PCI_CHIP_TOMATILLO)
		iommu_p->iommu_tfar_reg =
		    (uint64_t *)(a + TOMATILLO_IOMMU_ERR_TFAR_OFFSET);
	return (a);	/* PCICSRBase */
}

void
pci_iommu_teardown(iommu_t *iommu_p)
{
	if (pci_use_contexts)
		iommu_ctx_free(iommu_p);
	if (iommu_p->iommu_mtlb_req_p) {
		kmem_free(iommu_p->iommu_mtlb_req_p,
		    sizeof (dvma_unbind_req_t) * (tm_mtlb_maxpgs + 1));
		mutex_destroy(&iommu_p->iommu_mtlb_lock);
		iommu_p->iommu_mtlb_req_p = NULL;
		iommu_p->iommu_mtlb_nreq = 0;
		iommu_p->iommu_mtlb_npgs = iommu_p->iommu_mtlb_maxpgs = 0;
	}
}

uintptr_t
get_pbm_reg_base(pci_t *pci_p)
{
	return ((uintptr_t)
	    (pci_p->pci_address[0] + SCHIZO_PCI_CTRL_REG_OFFSET));
}

/* ARGSUSED */
static boolean_t
pci_pbm_panic_callb(void *arg, int code)
{
	pbm_t *pbm_p = (pbm_t *)arg;
	volatile uint64_t *ctrl_reg_p;

	if (pbm_p->pbm_quiesce_count > 0) {
		ctrl_reg_p = pbm_p->pbm_ctrl_reg;
		*ctrl_reg_p = pbm_p->pbm_saved_ctrl_reg;
	}

	return (B_TRUE);
}

static boolean_t
pci_pbm_debug_callb(void *arg, int code)
{
	pbm_t *pbm_p = (pbm_t *)arg;
	volatile uint64_t *ctrl_reg_p;
	uint64_t ctrl_reg;

	if (pbm_p->pbm_quiesce_count > 0) {
		ctrl_reg_p = pbm_p->pbm_ctrl_reg;
		if (code == 0) {
			*ctrl_reg_p = pbm_p->pbm_saved_ctrl_reg;
		} else {
			ctrl_reg = pbm_p->pbm_saved_ctrl_reg;
			ctrl_reg &= ~(SCHIZO_PCI_CTRL_ARB_EN_MASK |
			    SCHIZO_PCI_CTRL_ARB_PARK);
			*ctrl_reg_p = ctrl_reg;
		}
	}

	return (B_TRUE);
}

void
pci_pbm_setup(pbm_t *pbm_p)
{
	pci_t *pci_p = pbm_p->pbm_pci_p;
	caddr_t a = pci_p->pci_address[0]; /* PBM block base VA */
	uint64_t pa = va_to_pa(a);
	extern int segkmem_reloc;

	mutex_init(&pbm_p->pbm_sync_mutex, NULL, MUTEX_DRIVER,
	    (void *)ipltospl(XCALL_PIL));

	pbm_p->pbm_config_header = (config_header_t *)pci_p->pci_address[2];
	pbm_p->pbm_ctrl_reg = (uint64_t *)(a + SCHIZO_PCI_CTRL_REG_OFFSET);
	pbm_p->pbm_diag_reg = (uint64_t *)(a + SCHIZO_PCI_DIAG_REG_OFFSET);
	pbm_p->pbm_async_flt_status_reg =
	    (uint64_t *)(a + SCHIZO_PCI_ASYNC_FLT_STATUS_REG_OFFSET);
	pbm_p->pbm_async_flt_addr_reg =
	    (uint64_t *)(a + SCHIZO_PCI_ASYNC_FLT_ADDR_REG_OFFSET);
	pbm_p->pbm_estar_reg = (uint64_t *)(a + SCHIZO_PCI_ESTAR_REG_OFFSET);
	pbm_p->pbm_pcix_err_stat_reg = (uint64_t *)(a +
	    XMITS_PCI_X_ERROR_STATUS_REG_OFFSET);
	pbm_p->pbm_pci_ped_ctrl = (uint64_t *)(a +
	    XMITS_PARITY_DETECT_REG_OFFSET);

	/*
	 * Create a property to indicate that this node supports DVMA
	 * page relocation.
	 */
	if (CHIP_TYPE(pci_p) != PCI_CHIP_TOMATILLO && segkmem_reloc != 0) {
		pci_dvma_remap_enabled = 1;
		(void) ndi_prop_create_boolean(DDI_DEV_T_NONE,
		    pci_p->pci_dip, "dvma-remap-supported");
	}

	/*
	 * Register a panic callback so we can unquiesce this bus
	 * if it has been placed in the quiesced state.
	 */
	pbm_p->pbm_panic_cb_id = callb_add(pci_pbm_panic_callb,
	    (void *)pbm_p, CB_CL_PANIC, "pci_panic");
	pbm_p->pbm_debug_cb_id = callb_add(pci_pbm_panic_callb,
	    (void *)pbm_p, CB_CL_ENTER_DEBUGGER, "pci_debug_enter");

	if (CHIP_TYPE(pci_p) != PCI_CHIP_SCHIZO)
		goto non_schizo;

	if (PCI_CHIP_ID(pci_p) >= SCHIZO_VER_23) {

		pbm_p->pbm_sync_reg_pa = pa + SCHIZO_PBM_DMA_SYNC_REG_OFFSET;

		/*
		 * This is a software workaround to fix schizo hardware bug.
		 * Create a boolean property and its existence means consistent
		 * dma sync should not be done while in prom. The usb polled
		 * code (OHCI,EHCI) will check for this property and will not
		 * do dma sync if this property exist.
		 */
		(void) ndi_prop_create_boolean(DDI_DEV_T_NONE,
		    pci_p->pci_dip, "no-prom-cdma-sync");
	}
	return;
non_schizo:
	if (CHIP_TYPE(pci_p) == PCI_CHIP_TOMATILLO) {
		pci_dvma_sync_before_unmap = 1;
		pa = pci_p->pci_cb_p->cb_icbase_pa;
	}
	if (CHIP_TYPE(pci_p) == PCI_CHIP_XMITS)
		pbm_p->pbm_upper_retry_counter_reg =
		    (uint64_t *)(a + XMITS_UPPER_RETRY_COUNTER_REG_OFFSET);

	pbm_p->pbm_sync_reg_pa = pa + PBM_DMA_SYNC_PEND_REG_OFFSET;
}

void
pci_pbm_teardown(pbm_t *pbm_p)
{
	(void) callb_delete(pbm_p->pbm_panic_cb_id);
	(void) callb_delete(pbm_p->pbm_debug_cb_id);
}

uintptr_t
pci_ib_setup(ib_t *ib_p)
{
	/*
	 * Determine virtual addresses of bridge specific registers,
	 */
	pci_t *pci_p = ib_p->ib_pci_p;
	uintptr_t a = (uintptr_t)pci_p->pci_address[0];

	ib_p->ib_ign = PCI_ID_TO_IGN(pci_p->pci_id);
	ib_p->ib_max_ino = SCHIZO_MAX_INO;
	ib_p->ib_slot_intr_map_regs = a + SCHIZO_IB_SLOT_INTR_MAP_REG_OFFSET;
	ib_p->ib_intr_map_regs = a + SCHIZO_IB_INTR_MAP_REG_OFFSET;
	ib_p->ib_slot_clear_intr_regs = a + SCHIZO_IB_CLEAR_INTR_REG_OFFSET;
	return (a);
}

void
pci_sc_setup(sc_t *sc_p)
{
	pci_t *pci_p = sc_p->sc_pci_p;
	uintptr_t a;

	/*
	 * Determine the virtual addresses of the stream cache
	 * control/status and flush registers.
	 */
	a = (uintptr_t)pci_p->pci_address[0];	/* PCICSRBase */
	sc_p->sc_ctrl_reg = (uint64_t *)(a + SCHIZO_SC_CTRL_REG_OFFSET);
	sc_p->sc_invl_reg = (uint64_t *)(a + SCHIZO_SC_INVL_REG_OFFSET);
	sc_p->sc_sync_reg = (uint64_t *)(a + SCHIZO_SC_SYNC_REG_OFFSET);
	sc_p->sc_ctx_invl_reg = (uint64_t *)(a + SCHIZO_SC_CTX_INVL_REG_OFFSET);
	sc_p->sc_ctx_match_reg =
	    (uint64_t *)(a + SCHIZO_SC_CTX_MATCH_REG_OFFSET);

	/*
	 * Determine the virtual addresses of the streaming cache
	 * diagnostic access registers.
	 */
	sc_p->sc_data_diag_acc = (uint64_t *)(a + SCHIZO_SC_DATA_DIAG_OFFSET);
	sc_p->sc_tag_diag_acc = (uint64_t *)(a + SCHIZO_SC_TAG_DIAG_OFFSET);
	sc_p->sc_ltag_diag_acc = (uint64_t *)(a + SCHIZO_SC_LTAG_DIAG_OFFSET);
}

/*ARGSUSED*/
int
pci_get_numproxy(dev_info_t *dip)
{
	/*
	 * Schizo does not support interrupt proxies.
	 */
	return (0);
}

/*
 * pcisch error handling 101:
 *
 * The various functions below are responsible for error handling. Given
 * a particular error, they must gather the appropriate state, report all
 * errors with correct payload, and attempt recovery where ever possible.
 *
 * Recovery in the context of this driver is being able notify a leaf device
 * of the failed transaction. This leaf device may either be the master or
 * target for this transaction and may have already received an error
 * notification via a PCI interrupt. Notification is done via DMA and access
 * handles. If we capture an address for the transaction then we can map it
 * to a handle(if the leaf device is fma-compliant) and fault the handle as
 * well as call the device driver registered callback.
 *
 * The hardware can either interrupt or trap upon detection of an error, in
 * some rare cases it also causes a fatal reset.
 *
 * cb_buserr_intr() is responsible for handling control block
 * errors(errors which stem from the host bus side of the bridge). Since
 * we support multiple chips and host bus standards, cb_buserr_intr will
 * call a bus specific error handler to report and handle the detected
 * error. Since this error can either affect or orginate from either of the
 * two PCI busses which are connected to the bridge, we need to call
 * pci_pbm_err_handler() for each bus as well to report their errors. We
 * also need to gather possible errors which have been detected by their
 * compliant children(via ndi_fm_handler_dispatch()).
 *
 * pbm_error_intr() and ecc_intr() are responsible for PCI Block Module
 * errors(generic PCI + bridge specific) and ECC errors, respectively. They
 * are common between pcisch and pcipsy and therefore exist in pci_pbm.c and
 * pci_ecc.c. To support error handling certain chip specific handlers
 * must exist and they are defined below.
 *
 * cpu_deferred_error() and cpu_async_error(), handle the traps that may
 * have originated from IO space. They call into the registered IO callbacks
 * to report and handle errors that may have caused the trap.
 *
 * pci_pbm_err_handler() is called by pbm_error_intr() or pci_err_callback()
 * (generic fma callback for pcipsy/pcisch, pci_fm.c). pci_err_callback() is
 * called when the CPU has trapped because of a possible IO error(TO/BERR/UE).
 * It will call pci_pbm_err_handler() to report and handle all PCI/PBM/IOMMU
 * related errors which are detected by the chip.
 *
 * pci_pbm_err_handler() calls a generic interface pbm_afsr_report()(pci_pbm.c)
 * to report the pbm specific errors and attempt to map the failed address
 * (if captured) to a device instance. pbm_afsr_report() calls a chip specific
 * interface to interpret the afsr bits pci_pbm_classify()(pcisch.c/pcipsy.c).
 * pci_pbm_err_handler() also calls iommu_err_handler() to handle IOMMU related
 * errors.
 *
 * iommu_err_handler() can recover from most errors, as long as the requesting
 * device is notified and the iommu can be flushed. If an IOMMU error occurs
 * due to a UE then it will be passed on to the ecc_err_handler() for
 * subsequent handling.
 *
 * ecc_err_handler()(pci_ecc.c) also calls a chip specific interface to
 * interpret the afsr, pci_ecc_classify(). ecc_err_handler() also calls
 * pci_pbm_err_handler() to report any pbm errors detected.
 *
 * To make sure that the trap code and the interrupt code are not going
 * to step on each others toes we have a per chip pci_fm_mutex. This also
 * makes it necessary for us to be caution while we are at a high PIL, so
 * that we do not cause a subsequent trap that causes us to hang.
 *
 * The attempt to commonize code was meant to keep in line with the current
 * pci driver implementation and it was not meant to confuse. If you are
 * confused then don't worry, I was too.
 *
 */
static void
pci_cb_errstate_get(cb_t *cb_p, cb_errstate_t *cb_err_p)
{
	uint64_t pa = cb_p->cb_base_pa;
	int	i;

	bzero(cb_err_p, sizeof (cb_errstate_t));

	ASSERT(MUTEX_HELD(&cb_p->cb_pci_cmn_p->pci_fm_mutex));

	cb_err_p->cb_bridge_type = PCI_BRIDGE_TYPE(cb_p->cb_pci_cmn_p);

	cb_err_p->cb_csr = lddphysio(pa + SCHIZO_CB_CSR_OFFSET);
	cb_err_p->cb_err = lddphysio(pa + SCHIZO_CB_ERRCTRL_OFFSET);
	cb_err_p->cb_intr = lddphysio(pa + SCHIZO_CB_INTCTRL_OFFSET);
	cb_err_p->cb_elog = lddphysio(pa + SCHIZO_CB_ERRLOG_OFFSET);
	cb_err_p->cb_ecc = lddphysio(pa + SCHIZO_CB_ECCCTRL_OFFSET);
	cb_err_p->cb_ue_afsr = lddphysio(pa + SCHIZO_CB_UEAFSR_OFFSET);
	cb_err_p->cb_ue_afar = lddphysio(pa + SCHIZO_CB_UEAFAR_OFFSET);
	cb_err_p->cb_ce_afsr = lddphysio(pa + SCHIZO_CB_CEAFSR_OFFSET);
	cb_err_p->cb_ce_afar = lddphysio(pa + SCHIZO_CB_CEAFAR_OFFSET);

	if ((CB_CHIP_TYPE((cb_t *)cb_p)) == PCI_CHIP_XMITS) {
		cb_err_p->cb_first_elog = lddphysio(pa +
		    XMITS_CB_FIRST_ERROR_LOG);
		cb_err_p->cb_first_eaddr = lddphysio(pa +
		    XMITS_CB_FIRST_ERROR_ADDR);
		cb_err_p->cb_leaf_status = lddphysio(pa +
		    XMITS_CB_FIRST_ERROR_ADDR);
	}

	/* Gather PBM state information for both sides of this chip */
	for (i = 0; i < 2; i++) {
		if (cb_p->cb_pci_cmn_p->pci_p[i] == NULL)
			continue;
		pci_pbm_errstate_get(((cb_t *)cb_p)->cb_pci_cmn_p->
		    pci_p[i], &cb_err_p->cb_pbm[i]);
	}
}

static void
pci_cb_clear_error(cb_t *cb_p, cb_errstate_t *cb_err_p)
{
	uint64_t pa = ((cb_t *)cb_p)->cb_base_pa;

	stdphysio(pa + SCHIZO_CB_ERRLOG_OFFSET, cb_err_p->cb_elog);
}

static cb_fm_err_t safari_err_tbl[] = {
	SAFARI_BAD_CMD,		SCHIZO_CB_ELOG_BAD_CMD,		CB_FATAL,
	SAFARI_SSM_DIS,		SCHIZO_CB_ELOG_SSM_DIS,		CB_FATAL,
	SAFARI_BAD_CMD_PCIA, 	SCHIZO_CB_ELOG_BAD_CMD_PCIA,	CB_FATAL,
	SAFARI_BAD_CMD_PCIB, 	SCHIZO_CB_ELOG_BAD_CMD_PCIB,	CB_FATAL,
	SAFARI_PAR_ERR_INT_PCIB, XMITS_CB_ELOG_PAR_ERR_INT_PCIB, CB_FATAL,
	SAFARI_PAR_ERR_INT_PCIA, XMITS_CB_ELOG_PAR_ERR_INT_PCIA, CB_FATAL,
	SAFARI_PAR_ERR_INT_SAF,	XMITS_CB_ELOG_PAR_ERR_INT_SAF,	CB_FATAL,
	SAFARI_PLL_ERR_PCIB,	XMITS_CB_ELOG_PLL_ERR_PCIB,	CB_FATAL,
	SAFARI_PLL_ERR_PCIA,	XMITS_CB_ELOG_PLL_ERR_PCIA,	CB_FATAL,
	SAFARI_PLL_ERR_SAF,	XMITS_CB_ELOG_PLL_ERR_SAF,	CB_FATAL,
	SAFARI_SAF_CIQ_TO,	SCHIZO_CB_ELOG_SAF_CIQ_TO,	CB_FATAL,
	SAFARI_SAF_LPQ_TO,	SCHIZO_CB_ELOG_SAF_LPQ_TO,	CB_FATAL,
	SAFARI_SAF_SFPQ_TO,	SCHIZO_CB_ELOG_SAF_SFPQ_TO,	CB_FATAL,
	SAFARI_APERR,		SCHIZO_CB_ELOG_ADDR_PAR_ERR,	CB_FATAL,
	SAFARI_UNMAP_ERR,	SCHIZO_CB_ELOG_UNMAP_ERR,	CB_FATAL,
	SAFARI_BUS_ERR,		SCHIZO_CB_ELOG_BUS_ERR,		CB_FATAL,
	SAFARI_TO_ERR,		SCHIZO_CB_ELOG_TO_ERR,		CB_FATAL,
	SAFARI_DSTAT_ERR,	SCHIZO_CB_ELOG_DSTAT_ERR,	CB_FATAL,
	SAFARI_SAF_UFPQ_TO,	SCHIZO_CB_ELOG_SAF_UFPQ_TO,	CB_FATAL,
	SAFARI_CPU0_PAR_SINGLE,	SCHIZO_CB_ELOG_CPU0_PAR_SINGLE,	CB_FATAL,
	SAFARI_CPU0_PAR_BIDI,	SCHIZO_CB_ELOG_CPU0_PAR_BIDI,	CB_FATAL,
	SAFARI_CPU1_PAR_SINGLE,	SCHIZO_CB_ELOG_CPU1_PAR_SINGLE,	CB_FATAL,
	SAFARI_CPU1_PAR_BIDI,	SCHIZO_CB_ELOG_CPU1_PAR_BIDI,	CB_FATAL,
	NULL,			NULL,				NULL,
};

/*
 * Function used to handle and log Safari bus errors.
 */
static int
safari_err_handler(dev_info_t *dip, uint64_t fme_ena,
		cb_errstate_t *cb_err_p)
{
	int	i;
	int	fatal = 0;
	pci_t *pci_p = get_pci_soft_state(ddi_get_instance(dip));
	pci_common_t *cmn_p = pci_p->pci_common_p;

	ASSERT(MUTEX_HELD(&cmn_p->pci_fm_mutex));

	for (i = 0; safari_err_tbl[i].cb_err_class != NULL; i++) {
		if (cb_err_p->cb_elog & safari_err_tbl[i].cb_reg_bit) {
			cb_err_p->cb_err_class = safari_err_tbl[i].cb_err_class;
			cb_ereport_post(dip, fme_ena, cb_err_p);
			fatal += safari_err_tbl[i].cb_fatal;
		}
	}

	if (fatal)
		return (DDI_FM_FATAL);
	return (DDI_FM_OK);

}

/*
 * Check pbm va log register for captured errant address, and fail handle
 * if in per device cache.
 * Called from jbus_err_handler.
 */
static int
jbus_check_va_log(cb_t *cb_p, uint64_t fme_ena,
    cb_errstate_t *cb_err_p)
{
	int i;
	int ret = DDI_FM_FATAL;
	pci_common_t *cmn_p = cb_p->cb_pci_cmn_p;

	ASSERT(MUTEX_HELD(&cmn_p->pci_fm_mutex));
	/*
	 * Check VA log register for address associated with error,
	 * if no address is registered then return failure
	 */
	for (i = 0; i < 2; i++) {

		if (cb_p->cb_pci_cmn_p->pci_p[i] == NULL)
			continue;
		/*
		 * Look up and fault handle associated with
		 * logged DMA address
		 */
		if (cb_err_p->cb_pbm[i].pbm_va_log) {
			void *addr = (void *)&cb_err_p->cb_pbm[i].pbm_va_log;
			ret = ndi_fmc_error(cb_p->cb_pci_cmn_p->pci_p[i]->
			    pci_dip, NULL, DMA_HANDLE, fme_ena,
			    (void *)addr);
			if (ret == DDI_FM_NONFATAL)
				break;
		}
	}
	return (ret);
}

static cb_fm_err_t jbus_err_tbl[] = {
	JBUS_APERR,		SCHIZO_CB_ELOG_ADDR_PAR_ERR,	CB_FATAL,
	JBUS_PWR_DATA_PERR,	TOMATILLO_CB_ELOG_WR_DATA_PAR_ERR, CB_FATAL,
	JBUS_DRD_DATA_PERR,	TOMATILLO_CB_ELOG_RD_DATA_PAR_ERR, CB_NONFATAL,
	JBUS_CTL_PERR,		TOMATILLO_CB_ELOG_CTL_PAR_ERR,	CB_FATAL,
	JBUS_ILL_BYTE_EN,	TOMATILLO_CB_ELOG_ILL_BYTE_EN,	CB_FATAL,
	JBUS_ILL_COH_IN,	TOMATILLO_CB_ELOG_ILL_COH_IN,	CB_FATAL,
	JBUS_SNOOP_ERR_RD,	TOMATILLO_CB_ELOG_SNOOP_ERR_RD,	CB_FATAL,
	JBUS_SNOOP_ERR_RDS,	TOMATILLO_CB_ELOG_SNOOP_ERR_RDS, CB_FATAL,
	JBUS_SNOOP_ERR_RDSA,	TOMATILLO_CB_ELOG_SNOOP_ERR_RDSA, CB_FATAL,
	JBUS_SNOOP_ERR_OWN,	TOMATILLO_CB_ELOG_SNOOP_ERR_OWN, CB_FATAL,
	JBUS_SNOOP_ERR_RDO,	TOMATILLO_CB_ELOG_SNOOP_ERR_RDO, CB_FATAL,
	JBUS_SNOOP_ERR_PCI,	TOMATILLO_CB_ELOG_SNOOP_ERR_PCI, CB_FATAL,
	JBUS_SNOOP_ERR_GR,	TOMATILLO_CB_ELOG_SNOOP_ERR_GR,	CB_FATAL,
	JBUS_SNOOP_ERR,		TOMATILLO_CB_ELOG_SNOOP_ERR,	CB_FATAL,
	JBUS_BAD_CMD,		SCHIZO_CB_ELOG_BAD_CMD,		CB_FATAL,
	JBUS_UNMAP_ERR,		SCHIZO_CB_ELOG_UNMAP_ERR,	CB_NONFATAL,
	JBUS_TO_EXP_ERR,	TOMATILLO_CB_ELOG_TO_EXP_ERR,	CB_NONFATAL,
	JBUS_TO_ERR,		SCHIZO_CB_ELOG_TO_ERR,		CB_NONFATAL,
	JBUS_BUS_ERR,		SCHIZO_CB_ELOG_BUS_ERR,		CB_NONFATAL,
	NULL,			NULL,				NULL,
};

/*
 * Function used to handle and log Jbus errors.
 */
static int
jbus_err_handler(dev_info_t *dip, uint64_t fme_ena,
    cb_errstate_t *cb_err_p)
{
	int	fatal = 0;
	int	nonfatal = 0;
	int	i;
	pci_t	*pci_p = get_pci_soft_state(ddi_get_instance(dip));
	cb_t	*cb_p = pci_p->pci_cb_p;

	ASSERT(MUTEX_HELD(&pci_p->pci_common_p->pci_fm_mutex));

	for (i = 0; jbus_err_tbl[i].cb_err_class != NULL; i++) {
		if (!(cb_err_p->cb_elog & jbus_err_tbl[i].cb_reg_bit))
			continue;
		cb_err_p->cb_err_class = jbus_err_tbl[i].cb_err_class;
		if (jbus_err_tbl[i].cb_fatal) {
			fatal += jbus_err_tbl[i].cb_fatal;
			continue;
		}
		if (jbus_check_va_log(cb_p, fme_ena, cb_err_p)
		    != DDI_FM_NONFATAL) {
			fatal++;
		}
		cb_ereport_post(dip, fme_ena, cb_err_p);
	}

	return (fatal ? DDI_FM_FATAL : (nonfatal ? DDI_FM_NONFATAL :
	    DDI_FM_OK));
}

/*
 * Control Block error interrupt handler.
 */
uint_t
cb_buserr_intr(caddr_t a)
{
	cb_t *cb_p = (cb_t *)a;
	pci_common_t *cmn_p = cb_p->cb_pci_cmn_p;
	pci_t *pci_p = cmn_p->pci_p[0];
	cb_errstate_t cb_err;
	ddi_fm_error_t derr;
	int ret = DDI_FM_FATAL;
	int i;

	if (pci_p == NULL)
		pci_p = cmn_p->pci_p[1];

	bzero(&derr, sizeof (ddi_fm_error_t));
	derr.fme_version = DDI_FME_VERSION;
	derr.fme_ena = fm_ena_generate(0, FM_ENA_FMT1);

	mutex_enter(&cmn_p->pci_fm_mutex);

	pci_cb_errstate_get(cb_p, &cb_err);

	if (CB_CHIP_TYPE(cb_p) == PCI_CHIP_TOMATILLO)
		ret = jbus_err_handler(pci_p->pci_dip, derr.fme_ena, &cb_err);
	else if ((CB_CHIP_TYPE(cb_p) == PCI_CHIP_SCHIZO) ||
	    (CB_CHIP_TYPE(cb_p) == PCI_CHIP_XMITS))
		ret = safari_err_handler(pci_p->pci_dip, derr.fme_ena, &cb_err);

	/*
	 * Check for related errors in PBM and IOMMU. The IOMMU could cause
	 * a timeout on the jbus due to an IOMMU miss, so we need to check and
	 * log the IOMMU error registers.
	 */
	for (i = 0; i < 2; i++) {
		if (cmn_p->pci_p[i] == NULL)
			continue;
		if (pci_pbm_err_handler(cmn_p->pci_p[i]->pci_dip, &derr,
		    (void *)cmn_p->pci_p[i], PCI_CB_CALL) == DDI_FM_FATAL)
			ret = DDI_FM_FATAL;
	}

	/* Cleanup and reset error bits */
	(void) pci_cb_clear_error(cb_p, &cb_err);
	mutex_exit(&cmn_p->pci_fm_mutex);

	if (ret == DDI_FM_FATAL) {
		fm_panic("Fatal System Bus Error has occurred\n");
	}

	return (DDI_INTR_CLAIMED);
}

static ecc_fm_err_t ecc_err_tbl[] = {
	PCI_ECC_PIO_UE, COMMON_ECC_AFSR_E_PIO, CBNINTR_UE,
	PBM_PRIMARY, SCHIZO_ECC_AFAR_PIOW_UPA64S, SCH_REG_UPA,
	ACC_HANDLE,

	PCI_ECC_PIO_UE, COMMON_ECC_AFSR_E_PIO, CBNINTR_UE,
	PBM_PRIMARY, SCHIZO_ECC_AFAR_PIOW_PCIA_REG, SCH_REG_PCIA_REG,
	ACC_HANDLE,

	PCI_ECC_PIO_UE, COMMON_ECC_AFSR_E_PIO, CBNINTR_UE,
	PBM_PRIMARY, SCHIZO_ECC_AFAR_PIOW_PCIA_MEM, SCH_REG_PCIA_MEM,
	ACC_HANDLE,

	PCI_ECC_PIO_UE, COMMON_ECC_AFSR_E_PIO, CBNINTR_UE,
	PBM_PRIMARY, SCHIZO_ECC_AFAR_PIOW_PCIA_CFGIO, SCH_REG_PCIA_CFGIO,
	ACC_HANDLE,

	PCI_ECC_PIO_UE, COMMON_ECC_AFSR_E_PIO, CBNINTR_UE,
	PBM_PRIMARY, SCHIZO_ECC_AFAR_PIOW_PCIB_REG, SCH_REG_PCIB_REG,
	ACC_HANDLE,

	PCI_ECC_PIO_UE, COMMON_ECC_AFSR_E_PIO, CBNINTR_UE,
	PBM_PRIMARY, SCHIZO_ECC_AFAR_PIOW_PCIB_MEM, SCH_REG_PCIB_MEM,
	ACC_HANDLE,

	PCI_ECC_PIO_UE, COMMON_ECC_AFSR_E_PIO, CBNINTR_UE,
	PBM_PRIMARY, SCHIZO_ECC_AFAR_PIOW_PCIB_CFGIO, SCH_REG_PCIB_CFGIO,
	ACC_HANDLE,

	PCI_ECC_PIO_UE, COMMON_ECC_AFSR_E_PIO, CBNINTR_UE,
	PBM_PRIMARY, SCHIZO_ECC_AFAR_PIOW_SAFARI_REGS, SCH_REG_SAFARI_REGS,
	ACC_HANDLE,

	PCI_ECC_SEC_PIO_UE, COMMON_ECC_AFSR_E_PIO,  CBNINTR_UE,
	PBM_SECONDARY, NULL, NULL, ACC_HANDLE,

	PCI_ECC_PIO_CE, COMMON_ECC_AFSR_E_PIO,  CBNINTR_CE,
	PBM_PRIMARY, NULL, NULL, ACC_HANDLE,

	PCI_ECC_SEC_PIO_CE, COMMON_ECC_AFSR_E_PIO,  CBNINTR_CE,
	PBM_SECONDARY, NULL, NULL, ACC_HANDLE,

	PCI_ECC_DRD_UE, COMMON_ECC_AFSR_E_DRD, CBNINTR_UE,
	PBM_PRIMARY, NULL, NULL, DMA_HANDLE,

	PCI_ECC_SEC_DRD_UE, COMMON_ECC_AFSR_E_DRD, CBNINTR_UE,
	PBM_SECONDARY, NULL, NULL, DMA_HANDLE,

	PCI_ECC_DRD_CE, COMMON_ECC_AFSR_E_DRD, CBNINTR_CE,
	PBM_PRIMARY, NULL, NULL, DMA_HANDLE,

	PCI_ECC_SEC_DRD_CE, COMMON_ECC_AFSR_E_DRD, CBNINTR_CE,
	PBM_SECONDARY, NULL, NULL, DMA_HANDLE,

	PCI_ECC_DWR_UE, COMMON_ECC_AFSR_E_DWR, CBNINTR_UE,
	PBM_PRIMARY, NULL, NULL, DMA_HANDLE,

	PCI_ECC_SEC_DWR_UE, COMMON_ECC_AFSR_E_DWR, CBNINTR_UE,
	PBM_SECONDARY, NULL, NULL, DMA_HANDLE,

	PCI_ECC_DWR_CE, COMMON_ECC_AFSR_E_DWR, CBNINTR_CE,
	PBM_PRIMARY, NULL, NULL, DMA_HANDLE,

	PCI_ECC_SEC_DWR_CE, COMMON_ECC_AFSR_E_DWR, CBNINTR_CE,
	PBM_SECONDARY, NULL, NULL, DMA_HANDLE,

	NULL, NULL, NULL, NULL, NULL, NULL,
};

/*
 * pci_ecc_classify, called by ecc_handler to classify ecc errors
 * and determine if we should panic or not.
 */
void
pci_ecc_classify(uint64_t err, ecc_errstate_t *ecc_err_p)
{
	struct async_flt *ecc_p = &ecc_err_p->ecc_aflt;
	uint64_t region, afar = ecc_p->flt_addr;
	int i, j, ret = 0;
	int flag, fatal = 0;
	pci_common_t *cmn_p = ecc_err_p->ecc_ii_p.ecc_p->ecc_pci_cmn_p;
	pci_t *pci_p = cmn_p->pci_p[0];

	ASSERT(MUTEX_HELD(&cmn_p->pci_fm_mutex));

	ecc_err_p->ecc_bridge_type = PCI_BRIDGE_TYPE(cmn_p);

	if (pci_p == NULL)
		pci_p = cmn_p->pci_p[1];

	ecc_err_p->ecc_ctrl = lddphysio(ecc_err_p->ecc_ii_p.ecc_p->ecc_csr_pa);
	ecc_err_p->ecc_err_addr = afar;
	region = afar & SCHIZO_ECC_AFAR_PIOW_MASK;

	for (i = 0; ecc_err_tbl[i].ecc_err_class != NULL; i++) {
		if (!(err & ecc_err_tbl[i].ecc_reg_bit) ||
		    (ecc_err_p->ecc_ii_p.ecc_type !=
		    ecc_err_tbl[i].ecc_type) ||
		    (ecc_err_p->ecc_pri != ecc_err_tbl[i].ecc_pri))
			continue;

		ecc_p->flt_erpt_class = ecc_err_tbl[i].ecc_err_class;
		flag = ecc_err_tbl[i].ecc_flag;

		if (!ecc_err_tbl[i].ecc_pri ||
		    (ecc_err_tbl[i].ecc_type == CBNINTR_CE)) {
			fatal += (ecc_err_tbl[i].ecc_type == CBNINTR_UE) ?
			    1 : 0;
			break;
		}

		if (flag == ACC_HANDLE &&
		    (region & ecc_err_tbl[i].ecc_region_bits)) {
			ecc_err_p->ecc_region = ecc_err_tbl[i].ecc_region;
			pci_format_ecc_addr(pci_p->pci_dip,
			    &ecc_err_p->ecc_err_addr,
			    ecc_err_p->ecc_region);
		}

		/*
		 * Lookup and fault errant handle
		 */
		for (j = 0; j < 2; ++j) {
			ret = DDI_FM_UNKNOWN;
			if (cmn_p->pci_p[j] == NULL)
				continue;
			ret = ndi_fmc_error(cmn_p->pci_p[j]->pci_dip, NULL,
			    flag, ecc_err_p->ecc_ena,
			    (void *)&ecc_err_p->ecc_err_addr);
			if (ret == DDI_FM_NONFATAL) {
				fatal = 0;
				break;
			} else
				fatal++;
		}
		break;
	}

	if (fatal)
		ecc_p->flt_panic = 1;
	else if (flag != ACC_HANDLE)
		ecc_err_p->ecc_pg_ret = 1;
}

/*
 * Tables to define PCI-X Split Completion errors
 */

pcix_err_msg_rec_t pcix_completer_errs[] = {
	{PCIX_CPLT_OUT_OF_RANGE,	"pcix", "oor"	},
};

pcix_err_tbl_t pcix_split_errs_tbl[] = {
	{PCIX_CLASS_CPLT,
		sizeof (pcix_completer_errs)/sizeof (pcix_err_msg_rec_t),
		pcix_completer_errs		},
};

/*
 * Tables for the PCI-X error status messages
 */
pcix_err_msg_rec_t pcix_stat_errs[] = {
	{XMITS_PCIX_STAT_SC_DSCRD,	"pcix", "discard"  	},
	{XMITS_PCIX_STAT_SC_TTO,	"xmits.pbmx", "tato" 	},
	{XMITS_PCIX_STAT_SMMU,		"xmits.pbmx", "stmmu"	},
	{XMITS_PCIX_STAT_SDSTAT,	"xmits.pbmx", "stdst"	},
	{XMITS_PCIX_STAT_CMMU,		"xmits.pbmx", "cnmmu"	},
	{XMITS_PCIX_STAT_CDSTAT,	"xmits.pbmx", "cndst"	}
};

pcix_err_tbl_t pcix_stat_errs_tbl =
	{PCIX_NO_CLASS,
		sizeof (pcix_stat_errs)/sizeof (pcix_err_msg_rec_t),
		pcix_stat_errs		};


/*
 * walk thru a table of error messages, printing as appropriate
 *
 * t - the table of messages to parse
 * err - the error to match against
 * multi - flag, sometimes multiple error bits may be set/desired
 */
static int
pcix_lookup_err_msgs(dev_info_t *dip, uint64_t ena, pcix_err_tbl_t t,
		pbm_errstate_t *pbm_err_p)
{
	uint32_t err_bits  = pbm_err_p->pbm_err & XMITS_PCIX_MSG_INDEX_MASK;
	int nerr = 0;
	int j;
	char buf[FM_MAX_CLASS];

	for (j = 0; j < t.err_rec_num; j++)  {
		uint32_t msg_key = t.err_msg_tbl[j].msg_key;
		if (pbm_err_p->pbm_multi ? !(err_bits & msg_key) : err_bits
		    != msg_key)
			continue;

		(void) snprintf(buf, FM_MAX_CLASS, "%s.%s%s",
		    t.err_msg_tbl[j].msg_class,
		    pbm_err_p->pbm_pri ? "" : PCIX_SECONDARY,
		    t.err_msg_tbl[j].msg_str);

		pbm_err_p->pbm_err_class = buf;
		pcix_ereport_post(dip, ena, pbm_err_p);
		nerr++;
	}
	return (nerr ? DDI_FM_FATAL : DDI_FM_OK);
}

/*
 * Decodes primary(bit 27-24) or secondary(bit 15-12) PCI-X split
 * completion error message class and index in PBM AFSR.
 */
static void
pcix_log_split_err(dev_info_t *dip, uint64_t ena, pbm_errstate_t *pbm_err_p)
{
	uint32_t class  = pbm_err_p->pbm_err & XMITS_PCIX_MSG_CLASS_MASK;
	uint32_t num_classes = sizeof (pcix_split_errs_tbl) /
	    sizeof (struct pcix_err_tbl);
	int i;

	for (i = 0; i < num_classes; i++) {
		if (class == pcix_split_errs_tbl[i].err_class) {
			pbm_err_p->pbm_multi = PCIX_SINGLE_ERR;
			(void) pcix_lookup_err_msgs(dip, ena,
			    pcix_split_errs_tbl[i], pbm_err_p);
			break;
		}
	}
}

/*
 * Report PBM PCI-X Error Status Register if in PCI-X mode
 *
 * Once a PCI-X fault tree is constructed, the code below may need to
 * change.
 */
static int
pcix_log_pbm(pci_t *pci_p, uint64_t ena, pbm_errstate_t *pbm_err_p)
{
	int fatal = 0;
	int nonfatal = 0;
	uint32_t e;

	ASSERT(MUTEX_HELD(&pci_p->pci_common_p->pci_fm_mutex));

	DEBUG3(DBG_ERR_INTR, pci_p->pci_dip, "pcix_log_pbm: chip_type=%d "
	    "ctr_stat=%lx afsr = 0x%lx", CHIP_TYPE(pci_p),
	    pbm_err_p->pbm_ctl_stat, pbm_err_p->pbm_afsr);

	if (!(CHIP_TYPE(pci_p) == PCI_CHIP_XMITS) ||
	    !(pbm_err_p->pbm_ctl_stat & XMITS_PCI_CTRL_X_MODE))
		return (DDI_FM_OK);

	if (pbm_err_p->pbm_afsr & XMITS_PCI_X_AFSR_P_SC_ERR) {
		pbm_err_p->pbm_err = PBM_AFSR_TO_PRISPLIT(pbm_err_p->pbm_afsr);
		pbm_err_p->pbm_pri = PBM_PRIMARY;
		pcix_log_split_err(pci_p->pci_dip, ena, pbm_err_p);
		nonfatal++;
	}
	if (pbm_err_p->pbm_afsr & XMITS_PCI_X_AFSR_S_SC_ERR) {
		pbm_err_p->pbm_err = PBM_AFSR_TO_PRISPLIT(pbm_err_p->pbm_afsr);
		pbm_err_p->pbm_pri = PBM_PRIMARY;
		pcix_log_split_err(pci_p->pci_dip, ena, pbm_err_p);
		nonfatal++;
	}

	e = PBM_PCIX_TO_PRIERR(pbm_err_p->pbm_pcix_stat);
	if (e) {
		pbm_err_p->pbm_pri = PBM_PRIMARY;
		pbm_err_p->pbm_err = e;
		pbm_err_p->pbm_multi = PCIX_MULTI_ERR;
		if (pcix_lookup_err_msgs(pci_p->pci_dip, ena,
		    pcix_stat_errs_tbl, pbm_err_p) == DDI_FM_FATAL)
			fatal++;
		else
			nonfatal++;
	}

	e = PBM_PCIX_TO_SECERR(pbm_err_p->pbm_pcix_stat);
	if (e) {
		pbm_err_p->pbm_pri = PBM_SECONDARY;
		pbm_err_p->pbm_err = e;
		pbm_err_p->pbm_multi = PCIX_MULTI_ERR;
		if (pcix_lookup_err_msgs(pci_p->pci_dip, ena,
		    pcix_stat_errs_tbl, pbm_err_p) == DDI_FM_FATAL)
			fatal++;
		else
			nonfatal++;
	}

	if (!fatal && !nonfatal)
		return (DDI_FM_OK);
	else if (fatal)
		return (DDI_FM_FATAL);
	return (DDI_FM_NONFATAL);
}

static pbm_fm_err_t pbm_err_tbl[] = {
	PCI_MA,			SCHIZO_PCI_AFSR_E_MA,	PBM_PRIMARY,
	FM_LOG_PCI,	PCI_TARG_MA,

	PCI_SEC_MA,		SCHIZO_PCI_AFSR_E_MA,	PBM_SECONDARY,
	FM_LOG_PBM,	NULL,

	PCI_REC_TA,		SCHIZO_PCI_AFSR_E_TA,	PBM_PRIMARY,
	FM_LOG_PCI,	PCI_TARG_REC_TA,

	PCI_SEC_REC_TA,		SCHIZO_PCI_AFSR_E_TA,	PBM_SECONDARY,
	FM_LOG_PBM,	NULL,

	PCI_PBM_RETRY,		SCHIZO_PCI_AFSR_E_RTRY,	PBM_PRIMARY,
	FM_LOG_PBM,	PCI_PBM_TARG_RETRY,

	PCI_SEC_PBM_RETRY,	SCHIZO_PCI_AFSR_E_RTRY,	PBM_SECONDARY,
	FM_LOG_PBM,	NULL,

	PCI_MDPE,		SCHIZO_PCI_AFSR_E_PERR,	PBM_PRIMARY,
	FM_LOG_PCI,	PCI_TARG_MDPE,

	PCI_SEC_MDPE,		SCHIZO_PCI_AFSR_E_PERR,	PBM_SECONDARY,
	FM_LOG_PBM,	NULL,

	PCI_PBM_TTO,		SCHIZO_PCI_AFSR_E_TTO,	PBM_PRIMARY,
	FM_LOG_PBM,	PCI_PBM_TARG_TTO,

	PCI_SEC_PBM_TTO,	SCHIZO_PCI_AFSR_E_TTO,	PBM_SECONDARY,
	FM_LOG_PBM,	NULL,

	PCI_SCH_BUS_UNUSABLE_ERR, SCHIZO_PCI_AFSR_E_UNUSABLE, PBM_PRIMARY,
	FM_LOG_PBM,	NULL,

	PCI_SEC_SCH_BUS_UNUSABLE_ERR, SCHIZO_PCI_AFSR_E_UNUSABLE, PBM_SECONDARY,
	FM_LOG_PBM,	NULL,

	NULL,			NULL,			NULL,
	NULL,		NULL,
};


/*
 * pci_pbm_classify, called by pbm_afsr_report to classify piow afsr.
 */
int
pci_pbm_classify(pbm_errstate_t *pbm_err_p)
{
	uint32_t err;
	int nerr = 0;
	int i;

	err = pbm_err_p->pbm_pri ? PBM_AFSR_TO_PRIERR(pbm_err_p->pbm_afsr):
	    PBM_AFSR_TO_SECERR(pbm_err_p->pbm_afsr);

	for (i = 0; pbm_err_tbl[i].pbm_err_class != NULL; i++) {
		if ((err & pbm_err_tbl[i].pbm_reg_bit) &&
		    (pbm_err_p->pbm_pri == pbm_err_tbl[i].pbm_pri)) {
			if (pbm_err_tbl[i].pbm_flag == FM_LOG_PCI)
				pbm_err_p->pbm_pci.pci_err_class =
				    pbm_err_tbl[i].pbm_err_class;
			else
				pbm_err_p->pbm_err_class =
				    pbm_err_tbl[i].pbm_err_class;

			pbm_err_p->pbm_terr_class =
			    pbm_err_tbl[i].pbm_terr_class;
			pbm_err_p->pbm_log = pbm_err_tbl[i].pbm_flag;
			nerr++;
			break;
		}
	}

	return (nerr);
}

/*
 * Function used to handle and log IOMMU errors. Called by pci_pbm_err_handler,
 * with pci_fm_mutex held.
 */
static int
iommu_err_handler(dev_info_t *dip, uint64_t ena, pbm_errstate_t *pbm_err_p)
{
	pci_t *pci_p = get_pci_soft_state(ddi_get_instance(dip));
	iommu_t *iommu_p = pci_p->pci_iommu_p;
	ecc_t *ecc_p = pci_p->pci_ecc_p;
	uint64_t stat;
	ushort_t ta_signalled;
	int err = 0;
	int fatal = 0;
	int nonfatal = 0;
	int ret;

	ASSERT(MUTEX_HELD(&ecc_p->ecc_pci_cmn_p->pci_fm_mutex));
	if (!((stat = *iommu_p->iommu_ctrl_reg) & TOMATILLO_IOMMU_ERR)) {
		pbm_err_p->pbm_err_class = PCI_SCH_MMU_ERR;
		iommu_ereport_post(dip, ena, pbm_err_p);
		return (DDI_FM_NONFATAL);
	}

	/*
	 * Need to make sure a Target Abort was signalled to the device if
	 * we have any hope of recovering. Tomatillo does not send a TA for
	 * DMA Writes that result in a Translation Error, thus fooling the
	 * device into believing everything is as it expects. Ignorance
	 * is bliss, but knowledge is power.
	 */
	ta_signalled = pbm_err_p->pbm_pci.pci_cfg_stat &
	    PCI_STAT_S_TARG_AB;

	if (stat & TOMATILLO_IOMMU_ERR_ILLTSBTBW) {
		pbm_err_p->pbm_err_class = PCI_TOM_MMU_BAD_TSBTBW;
		err = 1;
		iommu_ereport_post(dip, ena, pbm_err_p);
		if (!ta_signalled)
			fatal++;
		else
			nonfatal++;
	}

	if (stat & TOMATILLO_IOMMU_ERR_BAD_VA) {
		pbm_err_p->pbm_err_class = PCI_TOM_MMU_BAD_VA;
		err = 1;
		iommu_ereport_post(dip, ena, pbm_err_p);
		if (!ta_signalled)
			fatal++;
		else
			nonfatal++;
	}

	if (!err) {
		stat = ((stat & TOMATILLO_IOMMU_ERRSTS) >>
		    TOMATILLO_IOMMU_ERRSTS_SHIFT);
		switch (stat) {
		case TOMATILLO_IOMMU_PROTECTION_ERR:
			pbm_err_p->pbm_err_class = PCI_TOM_MMU_PROT_ERR;
			iommu_ereport_post(dip, ena, pbm_err_p);
			fatal++;
			break;
		case TOMATILLO_IOMMU_INVALID_ERR:
			pbm_err_p->pbm_err_class = PCI_TOM_MMU_INVAL_ERR;
			/*
			 * Fault the address in iommu_tfar
			 * register to inform target driver of error
			 */
			ret = ndi_fmc_error(pci_p->pci_dip, NULL, DMA_HANDLE,
			    ena, (void *)&pbm_err_p->pbm_iommu.iommu_tfar);

			if (ret != DDI_FM_NONFATAL)
				if (ta_signalled)
					nonfatal++;
				else
					fatal++;
			else
				nonfatal++;

			iommu_ereport_post(dip, ena, pbm_err_p);
			break;
		case TOMATILLO_IOMMU_TIMEOUT_ERR:
			pbm_err_p->pbm_err_class = PCI_TOM_MMU_TO_ERR;
			fatal++;
			iommu_ereport_post(dip, ena, pbm_err_p);
			break;
		case TOMATILLO_IOMMU_ECC_ERR:
			pbm_err_p->pbm_err_class = PCI_TOM_MMU_UE;
			iommu_ereport_post(dip, ena, pbm_err_p);
			break;
		}
	}

	if (fatal)
		return (DDI_FM_FATAL);
	else if (nonfatal)
		return (DDI_FM_NONFATAL);

	return (DDI_FM_OK);
}

int
pci_check_error(pci_t *pci_p)
{
	pbm_t *pbm_p = pci_p->pci_pbm_p;
	uint16_t pci_cfg_stat;
	uint64_t pbm_ctl_stat, pbm_afsr, pbm_pcix_stat;
	caddr_t a = pci_p->pci_address[0];
	uint64_t *pbm_pcix_stat_reg;

	ASSERT(MUTEX_HELD(&pci_p->pci_common_p->pci_fm_mutex));

	pci_cfg_stat = pbm_p->pbm_config_header->ch_status_reg;
	pbm_ctl_stat = *pbm_p->pbm_ctrl_reg;
	pbm_afsr = *pbm_p->pbm_async_flt_status_reg;

	if ((pci_cfg_stat & (PCI_STAT_S_PERROR | PCI_STAT_S_TARG_AB |
	    PCI_STAT_R_TARG_AB | PCI_STAT_R_MAST_AB |
	    PCI_STAT_S_SYSERR | PCI_STAT_PERROR)) ||
	    (pbm_ctl_stat & (SCHIZO_PCI_CTRL_BUS_UNUSABLE |
	    TOMATILLO_PCI_CTRL_PCI_DTO_ERR |
	    SCHIZO_PCI_CTRL_PCI_TTO_ERR |
	    SCHIZO_PCI_CTRL_PCI_RTRY_ERR |
	    SCHIZO_PCI_CTRL_PCI_MMU_ERR |
	    COMMON_PCI_CTRL_SBH_ERR |
	    COMMON_PCI_CTRL_SERR)) ||
	    (PBM_AFSR_TO_PRIERR(pbm_afsr)))
		return (1);

	if ((CHIP_TYPE(pci_p) == PCI_CHIP_XMITS) &&
	    (pbm_ctl_stat & XMITS_PCI_CTRL_X_MODE)) {

		pbm_pcix_stat_reg = (uint64_t *)(a +
		    XMITS_PCI_X_ERROR_STATUS_REG_OFFSET);

		pbm_pcix_stat = *pbm_pcix_stat_reg;

		if (PBM_PCIX_TO_PRIERR(pbm_pcix_stat))
			return (1);

		if (pbm_pcix_stat & XMITS_PCIX_STAT_PERR_RECOV_INT)
			return (1);
	}

	return (0);

}

static pbm_fm_err_t pci_pbm_err_tbl[] = {
	PCI_PBM_RETRY,			SCHIZO_PCI_CTRL_PCI_RTRY_ERR,
	NULL,	PBM_NONFATAL,	PCI_PBM_TARG_RETRY,

	PCI_PBM_TTO,			SCHIZO_PCI_CTRL_PCI_TTO_ERR,
	NULL,	PBM_NONFATAL,	PCI_PBM_TARG_TTO,

	PCI_SCH_BUS_UNUSABLE_ERR,	SCHIZO_PCI_CTRL_BUS_UNUSABLE,
	NULL,	PBM_NONFATAL,	NULL,

	NULL,				NULL,
	NULL,	NULL,		NULL
};

/*
 * Function used to log all PCI/PBM/IOMMU errors found in the system.
 * It is called by the pbm_error_intr as well as the pci_err_callback(trap
 * callback). To protect access we hold the pci_fm_mutex when calling
 * this function.
 */
int
pci_pbm_err_handler(dev_info_t *dip, ddi_fm_error_t *derr,
		const void *impl_data, int caller)
{
	int fatal = 0;
	int nonfatal = 0;
	int unknown = 0;
	uint32_t prierr, secerr;
	pbm_errstate_t pbm_err;
	char buf[FM_MAX_CLASS];
	pci_t *pci_p = (pci_t *)impl_data;
	pbm_t *pbm_p = pci_p->pci_pbm_p;
	int i, ret = 0;

	ASSERT(MUTEX_HELD(&pci_p->pci_common_p->pci_fm_mutex));
	pci_pbm_errstate_get(pci_p, &pbm_err);

	derr->fme_ena = derr->fme_ena ? derr->fme_ena :
	    fm_ena_generate(0, FM_ENA_FMT1);

	prierr = PBM_AFSR_TO_PRIERR(pbm_err.pbm_afsr);
	secerr = PBM_AFSR_TO_SECERR(pbm_err.pbm_afsr);

	if (derr->fme_flag == DDI_FM_ERR_EXPECTED) {
		if (caller == PCI_TRAP_CALL) {
			/*
			 * For ddi_caut_get treat all events as nonfatal.
			 * The trampoline will set err_ena = 0, err_status =
			 * NONFATAL. We only really call this function so that
			 * pci_clear_error() and ndi_fm_handler_dispatch() will
			 * get called.
			 */
			derr->fme_status = DDI_FM_NONFATAL;
			nonfatal++;
			goto done;
		} else {
			/*
			 * For ddi_caut_put treat all events as nonfatal. Here
			 * we have the handle and can call ndi_fm_acc_err_set().
			 */
			derr->fme_status = DDI_FM_NONFATAL;
			ndi_fm_acc_err_set(pbm_p->pbm_excl_handle, derr);
			nonfatal++;
			goto done;
		}
	} else if (derr->fme_flag == DDI_FM_ERR_PEEK) {
		/*
		 * For ddi_peek treat all events as nonfatal. We only
		 * really call this function so that pci_clear_error()
		 * and ndi_fm_handler_dispatch() will get called.
		 */
		nonfatal++;
		goto done;
	} else if (derr->fme_flag == DDI_FM_ERR_POKE) {
		/*
		 * For ddi_poke we can treat as nonfatal if the
		 * following conditions are met :
		 * 1. Make sure only primary error is MA/TA
		 * 2. Make sure no secondary error bits set
		 * 3. check pci config header stat reg to see MA/TA is
		 *    logged. We cannot verify only MA/TA is recorded
		 *    since it gets much more complicated when a
		 *    PCI-to-PCI bridge is present.
		 */
		if ((prierr == SCHIZO_PCI_AFSR_E_MA) && !secerr &&
		    (pbm_err.pbm_pci.pci_cfg_stat & PCI_STAT_R_MAST_AB)) {
			nonfatal++;
			goto done;
		} else if ((*pbm_p->pbm_ctrl_reg & XMITS_PCI_CTRL_X_MODE) &&
		    pcix_ma_behind_bridge(&pbm_err)) {
			/*
			 * MAs behind a PCI-X bridge get sent back to
			 * the host as a Split Completion Error Message.
			 * We handle this the same as the above check.
			 */
			nonfatal++;
			goto done;
		}
		if ((prierr == SCHIZO_PCI_AFSR_E_TA) && !secerr &&
		    (pbm_err.pbm_pci.pci_cfg_stat & PCI_STAT_R_TARG_AB)) {
			nonfatal++;
			goto done;
		}
	}

	DEBUG2(DBG_ERR_INTR, dip, "pci_pbm_err_handler: prierr=0x%x "
	    "secerr=0x%x", prierr, secerr);

	if (prierr || secerr) {
		ret = pbm_afsr_report(dip, derr->fme_ena, &pbm_err);
		if (ret == DDI_FM_FATAL)
			fatal++;
		else
			nonfatal++;
	}
	if ((ret = pcix_log_pbm(pci_p, derr->fme_ena, &pbm_err))
	    == DDI_FM_FATAL)
		fatal++;
	else if (ret == DDI_FM_NONFATAL)
		nonfatal++;

	if ((ret = pci_cfg_report(dip, derr, &pbm_err.pbm_pci, caller, prierr))
	    == DDI_FM_FATAL)
		fatal++;
	else if (ret == DDI_FM_NONFATAL)
		nonfatal++;

	for (i = 0; pci_pbm_err_tbl[i].pbm_err_class != NULL; i++) {
		if ((pbm_err.pbm_ctl_stat & pci_pbm_err_tbl[i].pbm_reg_bit) &&
		    !prierr) {
			pbm_err.pbm_err_class =
			    pci_pbm_err_tbl[i].pbm_err_class;
			pbm_ereport_post(dip, derr->fme_ena, &pbm_err);
			if (pci_pbm_err_tbl[i].pbm_flag)
				fatal++;
			else
				nonfatal++;
			if (caller == PCI_TRAP_CALL &&
			    pci_pbm_err_tbl[i].pbm_terr_class)
				pci_target_enqueue(derr->fme_ena,
				    pci_pbm_err_tbl[i].pbm_terr_class,
				    pbm_err.pbm_bridge_type,
				    (uint64_t)derr->fme_bus_specific);
		}
	}

	if ((pbm_err.pbm_ctl_stat & COMMON_PCI_CTRL_SBH_ERR) &&
	    (CHIP_TYPE(pci_p) != PCI_CHIP_TOMATILLO)) {
		pbm_err.pbm_err_class = PCI_SCH_SBH;
		pbm_ereport_post(dip, derr->fme_ena, &pbm_err);
		if (pci_panic_on_sbh_errors)
			fatal++;
		else
			nonfatal++;
	}

	/*
	 * PBM Received System Error - During any transaction, or
	 * at any point on the bus, some device may detect a critical
	 * error and signal a system error to the system.
	 */
	if (pbm_err.pbm_ctl_stat & COMMON_PCI_CTRL_SERR) {
		/*
		 * may be expected (master abort from pci-pci bridge during
		 * poke will generate SERR)
		 */
		if (derr->fme_flag != DDI_FM_ERR_POKE) {
			DEBUG1(DBG_ERR_INTR, dip, "pci_pbm_err_handler: "
			    "ereport_post: %s", buf);
			(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
			    PCI_ERROR_SUBCLASS, PCI_REC_SERR);
			ddi_fm_ereport_post(dip, buf, derr->fme_ena,
			    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
			    PCI_CONFIG_STATUS, DATA_TYPE_UINT16,
			    pbm_err.pbm_pci.pci_cfg_stat, PCI_CONFIG_COMMAND,
			    DATA_TYPE_UINT16, pbm_err.pbm_pci.pci_cfg_comm,
			    PCI_PA, DATA_TYPE_UINT64, (uint64_t)0, NULL);
		}
		unknown++;
	}

	/*
	 * PCI Retry Timeout - Device fails to retry deferred
	 * transaction within timeout. Only Tomatillo
	 */
	if (pbm_err.pbm_ctl_stat & TOMATILLO_PCI_CTRL_PCI_DTO_ERR) {
		if (pci_dto_fault_warn == CE_PANIC)
			fatal++;
		else
			nonfatal++;

		(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
		    PCI_ERROR_SUBCLASS, PCI_DTO);
		ddi_fm_ereport_post(dip, buf, derr->fme_ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, 0,
		    PCI_CONFIG_STATUS, DATA_TYPE_UINT16,
		    pbm_err.pbm_pci.pci_cfg_stat,
		    PCI_CONFIG_COMMAND, DATA_TYPE_UINT16,
		    pbm_err.pbm_pci.pci_cfg_comm,
		    PCI_PA, DATA_TYPE_UINT64, (uint64_t)0, NULL);
	}

	/*
	 * PBM Detected Data Parity Error - DPE detected during a DMA Write
	 * or PIO Read. Later case is taken care of by cpu_deferred_error
	 * and sent here to be logged.
	 */
	if ((pbm_err.pbm_pci.pci_cfg_stat & PCI_STAT_PERROR) &&
	    !(pbm_err.pbm_pci.pci_cfg_stat & PCI_STAT_S_SYSERR)) {
		/*
		 * If we have an address then fault
		 * it, if not probe for errant device
		 */
		ret = DDI_FM_FATAL;
		if (caller != PCI_TRAP_CALL) {
			if (pbm_err.pbm_va_log) {
				ret = ndi_fmc_error(dip, NULL, DMA_HANDLE,
				    derr->fme_ena, (void *)&pbm_err.pbm_va_log);
			}
			if (ret == DDI_FM_NONFATAL)
				nonfatal++;
			else
				fatal++;
		} else
			nonfatal++;

	}

	/* PBM Detected IOMMU Error */
	if (pbm_err.pbm_ctl_stat & SCHIZO_PCI_CTRL_PCI_MMU_ERR) {
		if (iommu_err_handler(dip, derr->fme_ena, &pbm_err)
		    == DDI_FM_FATAL)
			fatal++;
		else
			nonfatal++;
	}

done:
	ret = ndi_fm_handler_dispatch(dip, NULL, derr);
	if (ret == DDI_FM_FATAL) {
		fatal++;
	} else if (ret == DDI_FM_NONFATAL) {
		nonfatal++;
	} else if (ret == DDI_FM_UNKNOWN) {
		unknown++;
	}

	/*
	 * RSERR not claimed as nonfatal by a child is considered fatal
	 */
	if (unknown && !fatal && !nonfatal)
		fatal++;

	/* Cleanup and reset error bits */
	pci_clear_error(pci_p, &pbm_err);

	return (fatal ? DDI_FM_FATAL : (nonfatal ? DDI_FM_NONFATAL :
	    (unknown ? DDI_FM_UNKNOWN : DDI_FM_OK)));
}

/*
 * Function returns TRUE if a Primary error is Split Completion Error
 * that indicates a Master Abort occured behind a PCI-X bridge.
 * This function should only be called for busses running in PCI-X mode.
 */
static int
pcix_ma_behind_bridge(pbm_errstate_t *pbm_err_p)
{
	uint64_t msg;

	if (pbm_err_p->pbm_afsr & XMITS_PCI_X_AFSR_S_SC_ERR)
		return (0);

	if (pbm_err_p->pbm_afsr & XMITS_PCI_X_AFSR_P_SC_ERR) {
		msg = (pbm_err_p->pbm_afsr >> XMITS_PCI_X_P_MSG_SHIFT) &
		    XMITS_PCIX_MSG_MASK;
		if (msg & PCIX_CLASS_BRIDGE)
			if (msg & PCIX_BRIDGE_MASTER_ABORT) {
				return (1);
			}
	}

	return (0);
}

/*
 * Function used to gather PBM/PCI/IOMMU error state for the
 * pci_pbm_err_handler and the cb_buserr_intr. This function must be
 * called while pci_fm_mutex is held.
 */
static void
pci_pbm_errstate_get(pci_t *pci_p, pbm_errstate_t *pbm_err_p)
{
	pbm_t *pbm_p = pci_p->pci_pbm_p;
	iommu_t *iommu_p = pci_p->pci_iommu_p;
	caddr_t a = pci_p->pci_address[0];
	uint64_t *pbm_pcix_stat_reg;

	ASSERT(MUTEX_HELD(&pci_p->pci_common_p->pci_fm_mutex));
	bzero(pbm_err_p, sizeof (pbm_errstate_t));

	/*
	 * Capture all pbm error state for later logging
	 */
	pbm_err_p->pbm_bridge_type = PCI_BRIDGE_TYPE(pci_p->pci_common_p);

	pbm_err_p->pbm_pci.pci_cfg_stat =
	    pbm_p->pbm_config_header->ch_status_reg;
	pbm_err_p->pbm_ctl_stat = *pbm_p->pbm_ctrl_reg;
	pbm_err_p->pbm_afsr = *pbm_p->pbm_async_flt_status_reg;
	pbm_err_p->pbm_afar = *pbm_p->pbm_async_flt_addr_reg;
	pbm_err_p->pbm_iommu.iommu_stat = *iommu_p->iommu_ctrl_reg;
	pbm_err_p->pbm_pci.pci_cfg_comm =
	    pbm_p->pbm_config_header->ch_command_reg;
	pbm_err_p->pbm_pci.pci_pa = *pbm_p->pbm_async_flt_addr_reg;

	/*
	 * Record errant slot for Xmits and Schizo
	 * Not stored in Tomatillo
	 */
	if (CHIP_TYPE(pci_p) == PCI_CHIP_XMITS ||
	    CHIP_TYPE(pci_p) == PCI_CHIP_SCHIZO) {
		pbm_err_p->pbm_err_sl = (pbm_err_p->pbm_ctl_stat &
		    SCHIZO_PCI_CTRL_ERR_SLOT) >>
		    SCHIZO_PCI_CTRL_ERR_SLOT_SHIFT;

		/*
		 * The bit 51 on XMITS rev1.0 is same as
		 * SCHIZO_PCI_CTRL_ERR_SLOT_LOCK on schizo2.3. But
		 * this bit needs to be cleared to be able to latch
		 * the slot info on next fault.
		 * But in XMITS Rev2.0, this bit indicates a DMA Write
		 * Parity error.
		 */
		if (pbm_err_p->pbm_ctl_stat & XMITS_PCI_CTRL_DMA_WR_PERR) {
			if ((PCI_CHIP_ID(pci_p) == XMITS_VER_10) ||
			    (PCI_CHIP_ID(pci_p) <= SCHIZO_VER_23)) {
				/*
				 * top 32 bits are W1C and we just want to
				 * clear SLOT_LOCK. Leave bottom 32 bits
				 * unchanged
				 */
				*pbm_p->pbm_ctrl_reg =
				    pbm_err_p->pbm_ctl_stat &
				    (SCHIZO_PCI_CTRL_ERR_SLOT_LOCK |
				    0xffffffff);
				pbm_err_p->pbm_ctl_stat = *pbm_p->pbm_ctrl_reg;
			}
		}
	}

	/*
	 * Tomatillo specific registers
	 */
	if (CHIP_TYPE(pci_p) == PCI_CHIP_TOMATILLO) {
		pbm_err_p->pbm_va_log = (uint64_t)va_to_pa(
		    (void *)(uintptr_t)*(a + TOMATILLO_TGT_ERR_VALOG_OFFSET));
		pbm_err_p->pbm_iommu.iommu_tfar = *iommu_p->iommu_tfar_reg;
	}

	/*
	 * Xmits PCI-X register
	 */
	if ((CHIP_TYPE(pci_p) == PCI_CHIP_XMITS) &&
	    (pbm_err_p->pbm_ctl_stat & XMITS_PCI_CTRL_X_MODE)) {

		pbm_pcix_stat_reg = (uint64_t *)(a +
		    XMITS_PCI_X_ERROR_STATUS_REG_OFFSET);

		pbm_err_p->pbm_pcix_stat = *pbm_pcix_stat_reg;
		pbm_err_p->pbm_pcix_pfar = pbm_err_p->pbm_pcix_stat &
		    XMITS_PCI_X_STATUS_PFAR_MASK;
	}
}

/*
 * Function used to clear PBM/PCI/IOMMU error state after error handling
 * is complete. Only clearing error bits which have been logged. Called by
 * pci_pbm_err_handler and pci_bus_exit.
 */
static void
pci_clear_error(pci_t *pci_p, pbm_errstate_t *pbm_err_p)
{
	pbm_t *pbm_p = pci_p->pci_pbm_p;
	iommu_t *iommu_p = pci_p->pci_iommu_p;

	ASSERT(MUTEX_HELD(&pbm_p->pbm_pci_p->pci_common_p->pci_fm_mutex));

	if (*pbm_p->pbm_ctrl_reg & SCHIZO_PCI_CTRL_PCI_MMU_ERR) {
		iommu_tlb_scrub(pci_p->pci_iommu_p, 1);
	}
	pbm_p->pbm_config_header->ch_status_reg =
	    pbm_err_p->pbm_pci.pci_cfg_stat;
	*pbm_p->pbm_ctrl_reg = pbm_err_p->pbm_ctl_stat;
	*pbm_p->pbm_async_flt_status_reg = pbm_err_p->pbm_afsr;
	*iommu_p->iommu_ctrl_reg = pbm_err_p->pbm_iommu.iommu_stat;
}

void
pbm_clear_error(pbm_t *pbm_p)
{
	uint64_t pbm_afsr, pbm_ctl_stat;

	/*
	 * for poke() support - called from POKE_FLUSH. Spin waiting
	 * for MA, TA or SERR to be cleared by a pbm_error_intr().
	 * We have to wait for SERR too in case the device is beyond
	 * a pci-pci bridge.
	 */
	pbm_ctl_stat = *pbm_p->pbm_ctrl_reg;
	pbm_afsr = *pbm_p->pbm_async_flt_status_reg;
	while (((pbm_afsr >> SCHIZO_PCI_AFSR_PE_SHIFT) &
	    (SCHIZO_PCI_AFSR_E_MA | SCHIZO_PCI_AFSR_E_TA)) ||
	    (pbm_ctl_stat & COMMON_PCI_CTRL_SERR)) {
		pbm_ctl_stat = *pbm_p->pbm_ctrl_reg;
		pbm_afsr = *pbm_p->pbm_async_flt_status_reg;
	}
}

/*
 * Function used to convert the 32 bit captured PCI error address
 * to the full Safari or Jbus address. This is so we can look this address
 * up in our handle caches.
 */
void
pci_format_addr(dev_info_t *dip, uint64_t *afar, uint64_t afsr)
{
	pci_t *pci_p = get_pci_soft_state(ddi_get_instance(dip));
	pci_ranges_t *io_range, *mem_range;
	uint64_t err_pa = 0;

	if (afsr & SCHIZO_PCI_AFSR_CONF_SPACE) {
		err_pa |= pci_p->pci_ranges->parent_high;
		err_pa = err_pa << 32;
		err_pa |= pci_p->pci_ranges->parent_low;
	} else if (afsr & SCHIZO_PCI_AFSR_IO_SPACE) {
		io_range = pci_p->pci_ranges + 1;
		err_pa |= io_range->parent_high;
		err_pa = err_pa << 32;
		err_pa |= io_range->parent_low;
	} else if (afsr & SCHIZO_PCI_AFSR_MEM_SPACE) {
		mem_range = pci_p->pci_ranges + 2;
		err_pa |= mem_range->parent_high;
		err_pa = err_pa << 32;
		err_pa |= mem_range->parent_low;
	}
	*afar |= err_pa;
}

static ecc_format_t ecc_format_tbl[] = {
	SCH_REG_UPA,		NULL,				NULL,
	SCH_REG_PCIA_REG,	SCHIZO_PCI_AFSR_CONF_SPACE,	PCI_SIDEA,
	SCH_REG_PCIA_MEM,	SCHIZO_PCI_AFSR_MEM_SPACE,	PCI_SIDEA,
	SCH_REG_PCIA_CFGIO,	SCHIZO_PCI_AFSR_IO_SPACE,	PCI_SIDEA,
	SCH_REG_PCIB_REG,	SCHIZO_PCI_AFSR_CONF_SPACE,	PCI_SIDEB,
	SCH_REG_PCIB_MEM,	SCHIZO_PCI_AFSR_MEM_SPACE,	PCI_SIDEB,
	SCH_REG_PCIB_CFGIO,	SCHIZO_PCI_AFSR_IO_SPACE,	PCI_SIDEB,
	SCH_REG_SAFARI_REGS,	NULL,				NULL,
	NULL,			NULL,				NULL,
};

/*
 * Function used to convert the 32 bit PIO address captured for a
 * Safari Bus UE(during PIO Rd/Wr) to a full Safari Bus Address.
 */
static void
pci_format_ecc_addr(dev_info_t *dip, uint64_t *afar, ecc_region_t region)
{
	pci_t *pci_p = get_pci_soft_state(ddi_get_instance(dip));
	pci_common_t *cmn_p = pci_p->pci_common_p;
	cb_t *cb_p = pci_p->pci_cb_p;
	int i, pci_side = 0;
	int swap = 0;
	uint64_t pa = cb_p->cb_base_pa;
	uint64_t flag, schizo_base, pci_csr_base;

	if (pci_p == NULL)
		return;

	pci_csr_base = va_to_pa(pci_p->pci_address[0]);

	/*
	 * Using the csr_base address to determine which side
	 * we are on.
	 */
	if (pci_csr_base & PCI_SIDE_ADDR_MASK)
		pci_side = 1;
	else
		pci_side = 0;

	schizo_base = pa - PBM_CTRL_OFFSET;

	for (i = 0; ecc_format_tbl[i].ecc_region != NULL; i++) {
		if (region == ecc_format_tbl[i].ecc_region) {
			flag = ecc_format_tbl[i].ecc_space;
			if (ecc_format_tbl[i].ecc_side != pci_side)
				swap = 1;
			if (region == SCH_REG_SAFARI_REGS)
				*afar |= schizo_base;
			break;
		}
	}

	if (swap) {
		pci_p = cmn_p->pci_p[PCI_OTHER_SIDE(pci_p->pci_side)];

		if (pci_p == NULL)
			return;
	}
	pci_format_addr(pci_p->pci_dip, afar, flag);
}

/*
 * Function used to post control block specific ereports.
 */
static void
cb_ereport_post(dev_info_t *dip, uint64_t ena, cb_errstate_t *cb_err)
{
	pci_t *pci_p = get_pci_soft_state(ddi_get_instance(dip));
	char buf[FM_MAX_CLASS], dev_path[MAXPATHLEN], *ptr;
	struct i_ddi_fmhdl *fmhdl = DEVI(dip)->devi_fmhdl;
	nvlist_t *ereport, *detector;
	errorq_elem_t *eqep;
	nv_alloc_t *nva;

	DEBUG1(DBG_ATTACH, dip, "cb_ereport_post: elog 0x%lx",
	    cb_err->cb_elog);

	/*
	 * We do not use ddi_fm_ereport_post because we need to set a
	 * special detector here. Since we do not have a device path for
	 * the bridge chip we use what we think it should be to aid in
	 * diagnosis.
	 */
	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s.%s", DDI_IO_CLASS,
	    cb_err->cb_bridge_type, cb_err->cb_err_class);

	ena = ena ? ena : fm_ena_generate(0, FM_ENA_FMT1);

	eqep = errorq_reserve(fmhdl->fh_errorq);
	if (eqep == NULL)
		return;

	ereport = errorq_elem_nvl(fmhdl->fh_errorq, eqep);
	nva = errorq_elem_nva(fmhdl->fh_errorq, eqep);
	detector = fm_nvlist_create(nva);

	ASSERT(ereport);
	ASSERT(nva);
	ASSERT(detector);

	ddi_pathname(dip, dev_path);
	ptr = strrchr(dev_path, (int)',');

	if (ptr)
		*ptr = '\0';

	fm_fmri_dev_set(detector, FM_DEV_SCHEME_VERSION, NULL, dev_path,
	    NULL, NULL);

	DEBUG1(DBG_ERR_INTR, dip, "cb_ereport_post: ereport_set: %s", buf);

	if (CHIP_TYPE(pci_p) == PCI_CHIP_SCHIZO ||
	    CHIP_TYPE(pci_p) == PCI_CHIP_XMITS) {
		fm_ereport_set(ereport, FM_EREPORT_VERSION, buf, ena, detector,
		    SAFARI_CSR, DATA_TYPE_UINT64, cb_err->cb_csr,
		    SAFARI_ERR, DATA_TYPE_UINT64, cb_err->cb_err,
		    SAFARI_INTR, DATA_TYPE_UINT64, cb_err->cb_intr,
		    SAFARI_ELOG, DATA_TYPE_UINT64, cb_err->cb_elog,
		    SAFARI_PCR, DATA_TYPE_UINT64, cb_err->cb_pcr,
		    NULL);
	} else if (CHIP_TYPE(pci_p) == PCI_CHIP_TOMATILLO) {
		fm_ereport_set(ereport, FM_EREPORT_VERSION, buf, ena, detector,
		    JBUS_CSR, DATA_TYPE_UINT64, cb_err->cb_csr,
		    JBUS_ERR, DATA_TYPE_UINT64, cb_err->cb_err,
		    JBUS_INTR, DATA_TYPE_UINT64, cb_err->cb_intr,
		    JBUS_ELOG, DATA_TYPE_UINT64, cb_err->cb_elog,
		    JBUS_PCR, DATA_TYPE_UINT64, cb_err->cb_pcr,
		    NULL);
	}
	errorq_commit(fmhdl->fh_errorq, eqep, ERRORQ_ASYNC);
}

/*
 * Function used to post IOMMU specific ereports.
 */
static void
iommu_ereport_post(dev_info_t *dip, uint64_t ena, pbm_errstate_t *pbm_err)
{
	char buf[FM_MAX_CLASS];

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
	    pbm_err->pbm_bridge_type, pbm_err->pbm_err_class);

	ena = ena ? ena : fm_ena_generate(0, FM_ENA_FMT1);

	DEBUG1(DBG_ERR_INTR, dip, "iommu_ereport_post: ereport_set: %s", buf);

	ddi_fm_ereport_post(dip, buf, ena, DDI_NOSLEEP,
	    FM_VERSION, DATA_TYPE_UINT8, 0,
	    PCI_CONFIG_STATUS, DATA_TYPE_UINT16, pbm_err->pbm_pci.pci_cfg_stat,
	    PCI_CONFIG_COMMAND, DATA_TYPE_UINT16, pbm_err->pbm_pci.pci_cfg_comm,
	    PCI_PBM_CSR, DATA_TYPE_UINT64, pbm_err->pbm_ctl_stat,
	    PCI_PBM_IOMMU_CTRL, DATA_TYPE_UINT64, pbm_err->pbm_iommu.iommu_stat,
	    PCI_PBM_IOMMU_TFAR, DATA_TYPE_UINT64, pbm_err->pbm_iommu.iommu_tfar,
	    PCI_PBM_SLOT, DATA_TYPE_UINT64, pbm_err->pbm_err_sl,
	    PCI_PBM_VALOG, DATA_TYPE_UINT64, pbm_err->pbm_va_log,
	    NULL);
}

/*
 * Function used to post PCI-X generic ereports.
 * This function needs to be fixed once the Fault Boundary Analysis
 * for PCI-X is conducted. The payload should be made more generic.
 */
static void
pcix_ereport_post(dev_info_t *dip, uint64_t ena, pbm_errstate_t *pbm_err)
{
	char buf[FM_MAX_CLASS];

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
	    pbm_err->pbm_bridge_type, pbm_err->pbm_err_class);

	ena = ena ? ena : fm_ena_generate(0, FM_ENA_FMT1);

	DEBUG1(DBG_ERR_INTR, dip, "pcix_ereport_post: ereport_post: %s", buf);

	ddi_fm_ereport_post(dip, buf, ena, DDI_NOSLEEP,
	    FM_VERSION, DATA_TYPE_UINT8, 0,
	    PCI_CONFIG_STATUS, DATA_TYPE_UINT16, pbm_err->pbm_pci.pci_cfg_stat,
	    PCI_CONFIG_COMMAND, DATA_TYPE_UINT16, pbm_err->pbm_pci.pci_cfg_comm,
	    PCI_PBM_CSR, DATA_TYPE_UINT64, pbm_err->pbm_ctl_stat,
	    PCI_PBM_AFSR, DATA_TYPE_UINT64, pbm_err->pbm_afsr,
	    PCI_PBM_AFAR, DATA_TYPE_UINT64, pbm_err->pbm_afar,
	    PCI_PBM_SLOT, DATA_TYPE_UINT64, pbm_err->pbm_err_sl,
	    PCIX_STAT, DATA_TYPE_UINT64, pbm_err->pbm_pcix_stat,
	    PCIX_PFAR, DATA_TYPE_UINT32, pbm_err->pbm_pcix_pfar,
	    NULL);
}

static void
iommu_ctx_free(iommu_t *iommu_p)
{
	kmem_free(iommu_p->iommu_ctx_bitmap, IOMMU_CTX_BITMAP_SIZE);
}

/*
 * iommu_tlb_scrub():
 *	Exam TLB entries through TLB diagnostic registers and look for errors.
 *	scrub = 1 : cleanup all error bits in tlb, called in FAULT_RESET case
 *	scrub = 0 : log all error conditions to console, FAULT_LOG case
 *	In both cases, it returns number of errors found in tlb entries.
 */
static int
iommu_tlb_scrub(iommu_t *iommu_p, int scrub)
{
	int i, nerr = 0;
	dev_info_t *dip = iommu_p->iommu_pci_p->pci_dip;
	char *neg = "not ";

	uint64_t base = (uint64_t)iommu_p->iommu_ctrl_reg -
	    COMMON_IOMMU_CTRL_REG_OFFSET;

	volatile uint64_t *tlb_tag = (volatile uint64_t *)
	    (base + COMMON_IOMMU_TLB_TAG_DIAG_ACC_OFFSET);
	volatile uint64_t *tlb_data = (volatile uint64_t *)
	    (base + COMMON_IOMMU_TLB_DATA_DIAG_ACC_OFFSET);
	for (i = 0; i < IOMMU_TLB_ENTRIES; i++) {
		uint64_t tag = tlb_tag[i];
		uint64_t data = tlb_data[i];
		uint32_t errstat;
		iopfn_t pfn;

		if (!(tag & TLBTAG_ERR_BIT))
			continue;

		pfn = (iopfn_t)(data & TLBDATA_MEMPA_BITS);
		errstat = (uint32_t)
		    ((tag & TLBTAG_ERRSTAT_BITS) >> TLBTAG_ERRSTAT_SHIFT);
		if (errstat == TLBTAG_ERRSTAT_INVALID) {
			if (scrub)
				tlb_tag[i] = tlb_data[i] = 0ull;
		} else
			nerr++;

		if (scrub)
			continue;

		cmn_err(CE_CONT, "%s%d: Error %x on IOMMU TLB entry %x:\n"
		"\tContext=%lx %sWritable %sStreamable\n"
		"\tPCI Page Size=%sk Address in page %lx\n",
		    ddi_driver_name(dip), ddi_get_instance(dip), errstat, i,
		    (uint64_t)(tag & TLBTAG_CONTEXT_BITS) >>
		    TLBTAG_CONTEXT_SHIFT,
		    (tag & TLBTAG_WRITABLE_BIT) ? "" : neg,
		    (tag & TLBTAG_STREAM_BIT) ? "" : neg,
		    (tag & TLBTAG_PGSIZE_BIT) ? "64" : "8",
		    (uint64_t)(tag & TLBTAG_PCIVPN_BITS) << 13);
		cmn_err(CE_CONT, "Memory: %sValid %sCacheable Page Frame=%lx\n",
		    (data & TLBDATA_VALID_BIT) ? "" : neg,
		    (data & TLBDATA_CACHE_BIT) ? "" : neg, pfn);
	}
	return (nerr);
}

/*
 * pci_iommu_disp: calculates the displacement needed in tomatillo's
 *	iommu control register and modifies the control value template
 *	from caller. It also clears any error status bit that are new
 *	in tomatillo.
 * return value: an 8-bit mask to enable corresponding 512 MB segments
 *	suitable for tomatillo's target address register.
 *	0x00: no programming is needed, use existing value from prom
 *	0x60: use segment 5 and 6 to form a 1GB dvma range
 */
static uint64_t
pci_iommu_disp(iommu_t *iommu_p, uint64_t *ctl_p)
{
	uint64_t ctl_old;
	if (CHIP_TYPE(iommu_p->iommu_pci_p) != PCI_CHIP_TOMATILLO)
		return (0);

	ctl_old = *iommu_p->iommu_ctrl_reg;
	/* iommu ctrl reg error bits are W1C */
	if (ctl_old >> TOMATIILO_IOMMU_ERR_REG_SHIFT) {
		cmn_err(CE_WARN, "Tomatillo iommu err: %lx", ctl_old);
		*ctl_p |= (ctl_old >> TOMATIILO_IOMMU_ERR_REG_SHIFT)
		    << TOMATIILO_IOMMU_ERR_REG_SHIFT;
	}

	if (iommu_p->iommu_tsb_size != TOMATILLO_IOMMU_TSB_MAX)
		return (0);

	/* Tomatillo 2.0 and later, and 1GB DVMA range */
	*ctl_p |= 1 << TOMATILLO_IOMMU_SEG_DISP_SHIFT;
	return (3 << (iommu_p->iommu_dvma_base >> (32 - 3)));
}

void
pci_iommu_config(iommu_t *iommu_p, uint64_t iommu_ctl, uint64_t cfgpa)
{
	uintptr_t pbm_regbase = get_pbm_reg_base(iommu_p->iommu_pci_p);
	volatile uint64_t *pbm_csr_p = (volatile uint64_t *)pbm_regbase;
	volatile uint64_t *tgt_space_p = (volatile uint64_t *)(pbm_regbase |
	    (TOMATILLO_TGT_ADDR_SPACE_OFFSET - SCHIZO_PCI_CTRL_REG_OFFSET));
	volatile uint64_t pbm_ctl = *pbm_csr_p;

	volatile uint64_t *iommu_ctl_p = iommu_p->iommu_ctrl_reg;
	volatile uint64_t tsb_bar_val = iommu_p->iommu_tsb_paddr;
	volatile uint64_t *tsb_bar_p = iommu_p->iommu_tsb_base_addr_reg;
	uint64_t mask = pci_iommu_disp(iommu_p, &iommu_ctl);

	DEBUG2(DBG_ATTACH, iommu_p->iommu_pci_p->pci_dip,
	    "\npci_iommu_config: pbm_csr_p=%llx pbm_ctl=%llx",
	    pbm_csr_p, pbm_ctl);
	DEBUG2(DBG_ATTACH|DBG_CONT, iommu_p->iommu_pci_p->pci_dip,
	    "\n\tiommu_ctl_p=%llx iommu_ctl=%llx",
	    iommu_ctl_p, iommu_ctl);
	DEBUG4(DBG_ATTACH|DBG_CONT, iommu_p->iommu_pci_p->pci_dip,
	    "\n\tcfgpa=%llx tgt_space_p=%llx mask=%x tsb=%llx\n",
	    cfgpa, tgt_space_p, mask, tsb_bar_val);

	if (!cfgpa)
		goto reprog;

	/* disable PBM arbiters - turn off bits 0-7 */
	*pbm_csr_p = (pbm_ctl >> 8) << 8;

	/*
	 * For non-XMITS, flush any previous writes. This is only
	 * necessary for host bridges that may have a USB keywboard
	 * attached.  XMITS does not.
	 */
	if (!(CHIP_TYPE(iommu_p->iommu_pci_p) == PCI_CHIP_XMITS))
		(void) ldphysio(cfgpa);

reprog:
	if (mask)
		*tgt_space_p = mask;

	*tsb_bar_p = tsb_bar_val;
	*iommu_ctl_p = iommu_ctl;

	*pbm_csr_p = pbm_ctl;	/* re-enable bus arbitration */
	pbm_ctl = *pbm_csr_p;	/* flush all prev writes */
}


int
pci_get_portid(dev_info_t *dip)
{
	return (ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "portid", -1));
}

/*
 * Schizo Safari Performance Events.
 */
pci_kev_mask_t
schizo_saf_events[] = {
	{"saf_bus_cycles", 0x1},	{"saf_pause_asserted_cycles", 0x2},
	{"saf_frn_coherent_cmds", 0x3},	{"saf_frn_coherent_hits", 0x4},
	{"saf_my_coherent_cmds", 0x5},	{"saf_my_coherent_hits", 0x6},
	{"saf_frn_io_cmds", 0x7}, 	{"saf_frn_io_hits", 0x8},
	{"merge_buffer", 0x9}, 		{"interrupts", 0xa},
	{"csr_pios", 0xc}, 		{"upa_pios", 0xd},
	{"pcia_pios", 0xe}, 		{"pcib_pios", 0xf},
	{"saf_pause_seen_cycles", 0x11}, 	{"dvma_reads", 0x12},
	{"dvma_writes", 0x13},		{"saf_orq_full_cycles", 0x14},
	{"saf_data_in_cycles", 0x15},	{"saf_data_out_cycles", 0x16},
	{"clear_pic", 0x1f}
};


/*
 * Schizo PCI Performance Events.
 */
pci_kev_mask_t
schizo_pci_events[] = {
	{"dvma_stream_rd", 0x0}, 	{"dvma_stream_wr", 0x1},
	{"dvma_const_rd", 0x2},		{"dvma_const_wr", 0x3},
	{"dvma_stream_buf_mis", 0x4},	{"dvma_cycles", 0x5},
	{"dvma_wd_xfr", 0x6},		{"pio_cycles", 0x7},
	{"dvma_tlb_misses", 0x10},	{"interrupts", 0x11},
	{"saf_inter_nack", 0x12},	{"pio_reads", 0x13},
	{"pio_writes", 0x14},		{"dvma_rd_buf_timeout", 0x15},
	{"dvma_rd_rtry_stc", 0x16},	{"dvma_wr_rtry_stc", 0x17},
	{"dvma_rd_rtry_nonstc", 0x18},	{"dvma_wr_rtry_nonstc", 0x19},
	{"E*_slow_transitions", 0x1a},	{"E*_slow_cycles_per_64", 0x1b},
	{"clear_pic", 0x1f}
};


/*
 * Create the picN kstats for the pci
 * and safari events.
 */
void
pci_kstat_init()
{
	pci_name_kstat = (pci_ksinfo_t *)kmem_alloc(sizeof (pci_ksinfo_t),
	    KM_NOSLEEP);

	if (pci_name_kstat == NULL) {
		cmn_err(CE_WARN, "pcisch : no space for kstat\n");
	} else {
		pci_name_kstat->pic_no_evs =
		    sizeof (schizo_pci_events) / sizeof (pci_kev_mask_t);
		pci_name_kstat->pic_shift[0] = SCHIZO_SHIFT_PIC0;
		pci_name_kstat->pic_shift[1] = SCHIZO_SHIFT_PIC1;
		pci_create_name_kstat("pcis",
		    pci_name_kstat, schizo_pci_events);
	}

	saf_name_kstat = (pci_ksinfo_t *)kmem_alloc(sizeof (pci_ksinfo_t),
	    KM_NOSLEEP);
	if (saf_name_kstat == NULL) {
		cmn_err(CE_WARN, "pcisch : no space for kstat\n");
	} else {
		saf_name_kstat->pic_no_evs =
		    sizeof (schizo_saf_events) / sizeof (pci_kev_mask_t);
		saf_name_kstat->pic_shift[0] = SCHIZO_SHIFT_PIC0;
		saf_name_kstat->pic_shift[1] = SCHIZO_SHIFT_PIC1;
		pci_create_name_kstat("saf", saf_name_kstat, schizo_saf_events);
	}
}

void
pci_kstat_fini()
{
	if (pci_name_kstat != NULL) {
		pci_delete_name_kstat(pci_name_kstat);
		kmem_free(pci_name_kstat, sizeof (pci_ksinfo_t));
		pci_name_kstat = NULL;
	}

	if (saf_name_kstat != NULL) {
		pci_delete_name_kstat(saf_name_kstat);
		kmem_free(saf_name_kstat, sizeof (pci_ksinfo_t));
		saf_name_kstat = NULL;
	}
}

/*
 * Create 'counters' kstat for pci events.
 */
void
pci_add_pci_kstat(pci_t *pci_p)
{
	pci_cntr_addr_t *cntr_addr_p = &pci_p->pci_ks_addr;
	uintptr_t regbase = (uintptr_t)pci_p->pci_address[0];

	cntr_addr_p->pcr_addr = (uint64_t *)
	    (regbase + SCHIZO_PERF_PCI_PCR_OFFSET);
	cntr_addr_p->pic_addr = (uint64_t *)
	    (regbase + SCHIZO_PERF_PCI_PIC_OFFSET);

	pci_p->pci_ksp = pci_create_cntr_kstat(pci_p, "pcis",
	    NUM_OF_PICS, pci_cntr_kstat_update, cntr_addr_p);

	if (pci_p->pci_ksp == NULL) {
		cmn_err(CE_WARN, "pcisch : cannot create counter kstat");
	}
}

void
pci_rem_pci_kstat(pci_t *pci_p)
{
	if (pci_p->pci_ksp != NULL)
		kstat_delete(pci_p->pci_ksp);
	pci_p->pci_ksp = NULL;
}

void
pci_add_upstream_kstat(pci_t *pci_p)
{
	pci_common_t	*cmn_p = pci_p->pci_common_p;
	pci_cntr_pa_t	*cntr_pa_p = &cmn_p->pci_cmn_uks_pa;
	uint64_t regbase = va_to_pa(pci_p->pci_address[1]);

	cntr_pa_p->pcr_pa =
	    regbase + SCHIZO_PERF_SAF_PCR_OFFSET;
	cntr_pa_p->pic_pa =
	    regbase + SCHIZO_PERF_SAF_PIC_OFFSET;

	cmn_p->pci_common_uksp = pci_create_cntr_kstat(pci_p, "saf",
	    NUM_OF_PICS, pci_cntr_kstat_pa_update, cntr_pa_p);
}

/*
 * Extract the drivers binding name to identify which chip
 * we're binding to.  Whenever a new bus bridge is created, the driver alias
 * entry should be added here to identify the device if needed.  If a device
 * isn't added, the identity defaults to PCI_CHIP_UNIDENTIFIED.
 */
static uint32_t
pci_identity_init(pci_t *pci_p)
{
	dev_info_t *dip = pci_p->pci_dip;
	char *name = ddi_binding_name(dip);
	uint32_t ver = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "version#", 0);

	if (strcmp(name, "pci108e,a801") == 0)
		return (CHIP_ID(PCI_CHIP_TOMATILLO, ver, 0x00));

	if (strcmp(name, "pci108e,8001") == 0)
		return (CHIP_ID(PCI_CHIP_SCHIZO, ver, 0x00));

	if (strcmp(name, "pci108e,8002") == 0) {
		uint32_t mod_rev = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "module-revision#", 0);
		return (CHIP_ID(PCI_CHIP_XMITS, ver, mod_rev));
	}

	cmn_err(CE_WARN, "%s%d: Unknown PCI Host bridge %s %x\n",
	    ddi_driver_name(dip), ddi_get_instance(dip), name, ver);

	return (PCI_CHIP_UNIDENTIFIED);
}

/*
 * Setup a physical pointer to one leaf config space area. This
 * is used in several places in order to do a dummy read which
 * guarantees the nexus (and not a bus master) has gained control
 * of the bus.
 */
static void
pci_setup_cfgpa(pci_t *pci_p)
{
	dev_info_t *dip = pci_p->pci_dip;
	dev_info_t *cdip;
	pbm_t *pbm_p = pci_p->pci_pbm_p;
	uint64_t cfgpa = pci_get_cfg_pabase(pci_p);
	uint32_t *reg_p;
	int reg_len;

	for (cdip = ddi_get_child(dip); cdip != NULL;
	    cdip = ddi_get_next_sibling(cdip)) {
		if (ddi_getlongprop(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
		    "reg", (caddr_t)&reg_p, &reg_len) != DDI_PROP_SUCCESS)
			continue;
		cfgpa += (*reg_p) & (PCI_CONF_ADDR_MASK ^ PCI_REG_REG_M);
		kmem_free(reg_p, reg_len);
		break;
	}
	pbm_p->pbm_anychild_cfgpa = cfgpa;
}

void
pci_post_init_child(pci_t *pci_p, dev_info_t *child)
{
	volatile uint64_t *ctrl_reg_p;
	pbm_t *pbm_p = pci_p->pci_pbm_p;

	pci_setup_cfgpa(pci_p);

	/*
	 * This is a hack for skyhawk/casinni combination to address
	 * hardware problems between the request and grant signals which
	 * causes a bus hang.  One workaround, which is applied here,
	 * is to disable bus parking if the child contains the property
	 * pci-req-removal.  Note that if the bus is quiesced we must mask
	 * off the parking bit in the saved control registers, since the
	 * quiesce operation temporarily turns off PCI bus parking.
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "pci-req-removal") == 1) {

		if (pbm_p->pbm_quiesce_count > 0) {
			pbm_p->pbm_saved_ctrl_reg &= ~SCHIZO_PCI_CTRL_ARB_PARK;
		} else {
			ctrl_reg_p = pbm_p->pbm_ctrl_reg;
			*ctrl_reg_p &= ~SCHIZO_PCI_CTRL_ARB_PARK;
		}
	}

	if (CHIP_TYPE(pci_p) == PCI_CHIP_XMITS) {
		if (*pbm_p->pbm_ctrl_reg & XMITS_PCI_CTRL_X_MODE) {
			int value;

			/*
			 * Due to a XMITS bug, we need to set the outstanding
			 * split transactions to 1 for all PCI-X functions
			 * behind the leaf.
			 */
			value = (xmits_max_transactions << 4) |
			    (xmits_max_read_bytes << 2);

			DEBUG1(DBG_INIT_CLD, child, "Turning on XMITS NCPQ "
			    "Workaround: value = %x\n", value);

			pcix_set_cmd_reg(child, value);

			(void) ndi_prop_update_int(DDI_DEV_T_NONE,
			    child, "pcix-update-cmd-reg", value);
		}

		if (PCI_CHIP_ID(pci_p) >= XMITS_VER_30) {
			uint64_t *pbm_pcix_diag_reg =
			    (uint64_t *)(pci_p->pci_address[0] +
			    XMITS_PCI_X_DIAG_REG_OFFSET);
			uint64_t bugcntl = (*pbm_pcix_diag_reg >>
			    XMITS_PCI_X_DIAG_BUGCNTL_SHIFT) &
			    XMITS_PCI_X_DIAG_BUGCNTL_MASK;
			uint64_t tunable = (*pbm_p->pbm_ctrl_reg &
			    XMITS_PCI_CTRL_X_MODE ?
			    xmits_pcix_diag_bugcntl_pcix :
			    xmits_pcix_diag_bugcntl_pci)
			    & XMITS_PCI_X_DIAG_BUGCNTL_MASK;

			DEBUG4(DBG_INIT_CLD, pci_p->pci_dip, "%s: XMITS "
			    "pcix diag bugcntl=0x%lx, tunable=0x%lx, mode=%s\n",
			    ddi_driver_name(child), bugcntl, tunable,
			    ((*pbm_p->pbm_ctrl_reg & XMITS_PCI_CTRL_X_MODE)?
			    "PCI-X":"PCI"));

			DEBUG2(DBG_INIT_CLD, pci_p->pci_dip, "%s: XMITS "
			    "pcix diag reg=0x%lx (CUR)\n",
			    ddi_driver_name(child), *pbm_pcix_diag_reg);

			/*
			 * Due to a XMITS 3.x hw bug, we need to
			 * read PBM's xmits pci ctrl status register to
			 * determine mode (PCI or PCI-X) and then update
			 * PBM's pcix diag register with new BUG_FIX_CNTL
			 * bits (47:32) _if_ different from tunable's mode
			 * based value. This update is performed only once
			 * during the PBM's first child init.
			 *
			 * Per instructions from xmits hw engineering,
			 * non-BUG_FIX_CNTL bits should not be preserved
			 * when updating the pcix diag register. Such bits
			 * should be written as 0s.
			 */

			if (bugcntl != tunable) {
				*pbm_pcix_diag_reg = tunable <<
				    XMITS_PCI_X_DIAG_BUGCNTL_SHIFT;

				DEBUG2(DBG_INIT_CLD, pci_p->pci_dip, "%s: XMITS"
				    " pcix diag reg=0x%lx (NEW)\n",
				    ddi_driver_name(child), *pbm_pcix_diag_reg);
			}
		}
	}
}

void
pci_post_uninit_child(pci_t *pci_p)
{
	pci_setup_cfgpa(pci_p);
}

static int
pci_tom_nbintr_op(pci_t *pci_p, uint32_t inum, intrfunc f, caddr_t arg,
    int flag)
{
	uint32_t ino = pci_p->pci_inos[inum];
	uint32_t mondo = IB_INO_TO_NBMONDO(pci_p->pci_ib_p, ino);
	int ret = DDI_SUCCESS;

	mondo = CB_MONDO_TO_XMONDO(pci_p->pci_cb_p, mondo); /* no op on tom */

	switch (flag) {
	case PCI_OBJ_INTR_ADD:
		VERIFY(add_ivintr(mondo, pci_pil[inum], f,
		    arg, NULL, NULL) == 0);
		break;
	case PCI_OBJ_INTR_REMOVE:
		VERIFY(rem_ivintr(mondo, pci_pil[inum]) == 0);
		break;
	default:
		ret = DDI_FAILURE;
		break;
	}

	return (ret);
}

int
pci_ecc_add_intr(pci_t *pci_p, int inum, ecc_intr_info_t *eii_p)
{
	uint32_t mondo;
	int	r;

	mondo = ((pci_p->pci_cb_p->cb_ign << PCI_INO_BITS) |
	    pci_p->pci_inos[inum]);
	mondo = CB_MONDO_TO_XMONDO(pci_p->pci_cb_p, mondo);

	VERIFY(add_ivintr(mondo, pci_pil[inum], (intrfunc)ecc_intr,
	    (caddr_t)eii_p, NULL, NULL) == 0);

	if (CHIP_TYPE(pci_p) != PCI_CHIP_TOMATILLO)
		return (PCI_ATTACH_RETCODE(PCI_ECC_OBJ, PCI_OBJ_INTR_ADD,
		    DDI_SUCCESS));

	r = pci_tom_nbintr_op(pci_p, inum, (intrfunc)ecc_intr,
	    (caddr_t)eii_p, PCI_OBJ_INTR_ADD);
	return (PCI_ATTACH_RETCODE(PCI_ECC_OBJ, PCI_OBJ_INTR_ADD, r));
}

void
pci_ecc_rem_intr(pci_t *pci_p, int inum, ecc_intr_info_t *eii_p)
{
	uint32_t mondo;

	mondo = ((pci_p->pci_cb_p->cb_ign << PCI_INO_BITS) |
	    pci_p->pci_inos[inum]);
	mondo = CB_MONDO_TO_XMONDO(pci_p->pci_cb_p, mondo);

	VERIFY(rem_ivintr(mondo, pci_pil[inum]) == 0);

	if (CHIP_TYPE(pci_p) == PCI_CHIP_TOMATILLO)
		pci_tom_nbintr_op(pci_p, inum, (intrfunc)ecc_intr,
		    (caddr_t)eii_p, PCI_OBJ_INTR_REMOVE);
}

static uint_t
pci_pbm_cdma_intr(caddr_t a)
{
	pbm_t *pbm_p = (pbm_t *)a;
	pbm_p->pbm_cdma_flag = PBM_CDMA_DONE;
#ifdef PBM_CDMA_DEBUG
	pbm_p->pbm_cdma_intr_cnt++;
#endif /* PBM_CDMA_DEBUG */
	return (DDI_INTR_CLAIMED);
}

int
pci_pbm_add_intr(pci_t *pci_p)
{
	uint32_t mondo;

	mondo = IB_INO_TO_MONDO(pci_p->pci_ib_p, pci_p->pci_inos[CBNINTR_CDMA]);
	mondo = CB_MONDO_TO_XMONDO(pci_p->pci_cb_p, mondo);

	VERIFY(add_ivintr(mondo, pci_pil[CBNINTR_CDMA],
	    (intrfunc)pci_pbm_cdma_intr, (caddr_t)pci_p->pci_pbm_p,
	    NULL, NULL) == 0);

	return (DDI_SUCCESS);
}

void
pci_pbm_rem_intr(pci_t *pci_p)
{
	ib_t		*ib_p = pci_p->pci_ib_p;
	uint32_t	mondo;

	mondo = IB_INO_TO_MONDO(pci_p->pci_ib_p, pci_p->pci_inos[CBNINTR_CDMA]);
	mondo = CB_MONDO_TO_XMONDO(pci_p->pci_cb_p, mondo);

	ib_intr_disable(ib_p, pci_p->pci_inos[CBNINTR_CDMA], IB_INTR_NOWAIT);
	VERIFY(rem_ivintr(mondo, pci_pil[CBNINTR_CDMA]) == 0);
}

void
pci_pbm_suspend(pci_t *pci_p)
{
	pbm_t		*pbm_p = pci_p->pci_pbm_p;
	ib_ino_t	ino = pci_p->pci_inos[CBNINTR_CDMA];

	/* Save CDMA interrupt state */
	pbm_p->pbm_cdma_imr_save = *ib_intr_map_reg_addr(pci_p->pci_ib_p, ino);
}

void
pci_pbm_resume(pci_t *pci_p)
{
	pbm_t		*pbm_p = pci_p->pci_pbm_p;
	ib_ino_t	ino = pci_p->pci_inos[CBNINTR_CDMA];

	/* Restore CDMA interrupt state */
	*ib_intr_map_reg_addr(pci_p->pci_ib_p, ino) = pbm_p->pbm_cdma_imr_save;
}

/*
 * pci_bus_quiesce
 *
 * This function is called as the corresponding control ops routine
 * to a DDI_CTLOPS_QUIESCE command.  Its mission is to halt all DMA
 * activity on the bus by disabling arbitration/parking.
 */
int
pci_bus_quiesce(pci_t *pci_p, dev_info_t *dip, void *result)
{
	volatile uint64_t *ctrl_reg_p;
	volatile uint64_t ctrl_reg;
	pbm_t *pbm_p;

	pbm_p = pci_p->pci_pbm_p;
	ctrl_reg_p = pbm_p->pbm_ctrl_reg;

	if (pbm_p->pbm_quiesce_count++ == 0) {

		DEBUG0(DBG_PWR, dip, "quiescing bus\n");

		ctrl_reg = *ctrl_reg_p;
		pbm_p->pbm_saved_ctrl_reg = ctrl_reg;
		ctrl_reg &= ~(SCHIZO_PCI_CTRL_ARB_EN_MASK |
		    SCHIZO_PCI_CTRL_ARB_PARK);
		*ctrl_reg_p = ctrl_reg;
#ifdef	DEBUG
		ctrl_reg = *ctrl_reg_p;
		if ((ctrl_reg & (SCHIZO_PCI_CTRL_ARB_EN_MASK |
		    SCHIZO_PCI_CTRL_ARB_PARK)) != 0)
			panic("ctrl_reg didn't quiesce: 0x%lx\n", ctrl_reg);
#endif
		if (pbm_p->pbm_anychild_cfgpa)
			(void) ldphysio(pbm_p->pbm_anychild_cfgpa);
	}

	return (DDI_SUCCESS);
}

/*
 * pci_bus_unquiesce
 *
 * This function is called as the corresponding control ops routine
 * to a DDI_CTLOPS_UNQUIESCE command.  Its mission is to resume paused
 * DMA activity on the bus by re-enabling arbitration (and maybe parking).
 */
int
pci_bus_unquiesce(pci_t *pci_p, dev_info_t *dip, void *result)
{
	volatile uint64_t *ctrl_reg_p;
	pbm_t *pbm_p;
#ifdef	DEBUG
	volatile uint64_t ctrl_reg;
#endif

	pbm_p = pci_p->pci_pbm_p;
	ctrl_reg_p = pbm_p->pbm_ctrl_reg;

	ASSERT(pbm_p->pbm_quiesce_count > 0);
	if (--pbm_p->pbm_quiesce_count == 0) {
		*ctrl_reg_p = pbm_p->pbm_saved_ctrl_reg;
#ifdef	DEBUG
		ctrl_reg = *ctrl_reg_p;
		if ((ctrl_reg & (SCHIZO_PCI_CTRL_ARB_EN_MASK |
		    SCHIZO_PCI_CTRL_ARB_PARK)) == 0)
			panic("ctrl_reg didn't unquiesce: 0x%lx\n", ctrl_reg);
#endif
	}

	return (DDI_SUCCESS);
}

int
pci_reloc_getkey(void)
{
	return (0x200);
}

static void
tm_vmem_free(ddi_dma_impl_t *mp, iommu_t *iommu_p, dvma_addr_t dvma_pg,
	int npages)
{
	uint32_t dur_max, dur_base;
	dvma_unbind_req_t *req_p, *req_max_p;
	dvma_unbind_req_t *req_base_p = iommu_p->iommu_mtlb_req_p;
	uint32_t tlb_vpn[IOMMU_TLB_ENTRIES];
	caddr_t reg_base;
	volatile uint64_t *tag_p;
	int i, preserv_count = 0;

	mutex_enter(&iommu_p->iommu_mtlb_lock);

	iommu_p->iommu_mtlb_npgs += npages;
	req_max_p = req_base_p + iommu_p->iommu_mtlb_nreq++;
	req_max_p->dur_npg = npages;
	req_max_p->dur_base = dvma_pg;
	req_max_p->dur_flags = mp->dmai_flags & DMAI_FLAGS_VMEMCACHE;


	if (iommu_p->iommu_mtlb_npgs <= iommu_p->iommu_mtlb_maxpgs)
		goto done;

	/* read TLB */
	reg_base = iommu_p->iommu_pci_p->pci_address[0];
	tag_p = (volatile uint64_t *)
	    (reg_base + COMMON_IOMMU_TLB_TAG_DIAG_ACC_OFFSET);

	for (i = 0; i < IOMMU_TLB_ENTRIES; i++)
		tlb_vpn[i] = tag_p[i] & SCHIZO_VPN_MASK;

	/* for each request search the TLB for a matching address */
	for (req_p = req_base_p; req_p <= req_max_p; req_p++) {
		dur_base = req_p->dur_base;
		dur_max = req_p->dur_base + req_p->dur_npg;

		for (i = 0; i < IOMMU_TLB_ENTRIES; i++) {
			uint_t vpn = tlb_vpn[i];
			if (vpn >= dur_base && vpn < dur_max)
				break;
		}
		if (i >= IOMMU_TLB_ENTRIES) {
			pci_vmem_do_free(iommu_p,
			    (void *)IOMMU_PTOB(req_p->dur_base),
			    req_p->dur_npg, req_p->dur_flags);
			iommu_p->iommu_mtlb_npgs -= req_p->dur_npg;
			continue;
		}
		/* if an empty slot exists */
		if ((req_p - req_base_p) != preserv_count)
			*(req_base_p + preserv_count) = *req_p;
		preserv_count++;
	}

	iommu_p->iommu_mtlb_nreq = preserv_count;
done:
	mutex_exit(&iommu_p->iommu_mtlb_lock);
}

void
pci_vmem_free(iommu_t *iommu_p, ddi_dma_impl_t *mp, void *dvma_addr,
    size_t npages)
{
	if (tm_mtlb_gc)
		tm_vmem_free(mp, iommu_p,
		    (dvma_addr_t)IOMMU_BTOP((dvma_addr_t)dvma_addr), npages);
	else
		pci_vmem_do_free(iommu_p, dvma_addr, npages,
		    (mp->dmai_flags & DMAI_FLAGS_VMEMCACHE));
}

/*
 * pci_iommu_bypass_end_configure
 *
 * Support for 42-bit bus width to SAFARI and JBUS in DVMA and
 * iommu bypass transfers:
 */

dma_bypass_addr_t
pci_iommu_bypass_end_configure(void)
{

	return ((dma_bypass_addr_t)SAFARI_JBUS_IOMMU_BYPASS_END);
}
