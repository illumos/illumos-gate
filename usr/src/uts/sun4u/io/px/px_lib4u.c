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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/modctl.h>
#include <sys/disp.h>
#include <sys/stat.h>
#include <sys/ddi_impldefs.h>
#include <sys/vmem.h>
#include <sys/iommutsb.h>
#include <sys/cpuvar.h>
#include <sys/ivintr.h>
#include <sys/byteorder.h>
#include <sys/hotplug/pci/pciehpc.h>
#include <sys/spl.h>
#include <px_obj.h>
#include <pcie_pwr.h>
#include "px_tools_var.h"
#include <px_regs.h>
#include <px_csr.h>
#include <sys/machsystm.h>
#include "px_lib4u.h"
#include "px_err.h"
#include "oberon_regs.h"

#pragma weak jbus_stst_order

extern void jbus_stst_order();

ulong_t px_mmu_dvma_end = 0xfffffffful;
uint_t px_ranges_phi_mask = 0xfffffffful;
uint64_t *px_oberon_ubc_scratch_regs;
uint64_t px_paddr_mask;

static int px_goto_l23ready(px_t *px_p);
static int px_goto_l0(px_t *px_p);
static int px_pre_pwron_check(px_t *px_p);
static uint32_t px_identity_init(px_t *px_p);
static boolean_t px_cpr_callb(void *arg, int code);
static uint_t px_cb_intr(caddr_t arg);

/*
 * px_lib_map_registers
 *
 * This function is called from the attach routine to map the registers
 * accessed by this driver.
 *
 * used by: px_attach()
 *
 * return value: DDI_FAILURE on failure
 */
int
px_lib_map_regs(pxu_t *pxu_p, dev_info_t *dip)
{
	ddi_device_acc_attr_t	attr;
	px_reg_bank_t		reg_bank = PX_REG_CSR;

	DBG(DBG_ATTACH, dip, "px_lib_map_regs: pxu_p:0x%p, dip 0x%p\n",
	    pxu_p, dip);

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;

	/*
	 * PCI CSR Base
	 */
	if (ddi_regs_map_setup(dip, reg_bank, &pxu_p->px_address[reg_bank],
	    0, 0, &attr, &pxu_p->px_ac[reg_bank]) != DDI_SUCCESS) {
		goto fail;
	}

	reg_bank++;

	/*
	 * XBUS CSR Base
	 */
	if (ddi_regs_map_setup(dip, reg_bank, &pxu_p->px_address[reg_bank],
	    0, 0, &attr, &pxu_p->px_ac[reg_bank]) != DDI_SUCCESS) {
		goto fail;
	}

	pxu_p->px_address[reg_bank] -= FIRE_CONTROL_STATUS;

done:
	for (; reg_bank >= PX_REG_CSR; reg_bank--) {
		DBG(DBG_ATTACH, dip, "reg_bank 0x%x address 0x%p\n",
		    reg_bank, pxu_p->px_address[reg_bank]);
	}

	return (DDI_SUCCESS);

fail:
	cmn_err(CE_WARN, "%s%d: unable to map reg entry %d\n",
	    ddi_driver_name(dip), ddi_get_instance(dip), reg_bank);

	for (reg_bank--; reg_bank >= PX_REG_CSR; reg_bank--) {
		pxu_p->px_address[reg_bank] = NULL;
		ddi_regs_map_free(&pxu_p->px_ac[reg_bank]);
	}

	return (DDI_FAILURE);
}

/*
 * px_lib_unmap_regs:
 *
 * This routine unmaps the registers mapped by map_px_registers.
 *
 * used by: px_detach(), and error conditions in px_attach()
 *
 * return value: none
 */
void
px_lib_unmap_regs(pxu_t *pxu_p)
{
	int i;

	for (i = 0; i < PX_REG_MAX; i++) {
		if (pxu_p->px_ac[i])
			ddi_regs_map_free(&pxu_p->px_ac[i]);
	}
}

int
px_lib_dev_init(dev_info_t *dip, devhandle_t *dev_hdl)
{

	caddr_t			xbc_csr_base, csr_base;
	px_dvma_range_prop_t	px_dvma_range;
	pxu_t			*pxu_p;
	uint8_t			chip_mask;
	px_t			*px_p = DIP_TO_STATE(dip);
	px_chip_type_t		chip_type = px_identity_init(px_p);

	DBG(DBG_ATTACH, dip, "px_lib_dev_init: dip 0x%p", dip);

	if (chip_type == PX_CHIP_UNIDENTIFIED) {
		cmn_err(CE_WARN, "%s%d: Unrecognized Hardware Version\n",
		    NAMEINST(dip));
		return (DDI_FAILURE);
	}

	chip_mask = BITMASK(chip_type);
	px_paddr_mask = (chip_type == PX_CHIP_FIRE) ? MMU_FIRE_PADDR_MASK :
	    MMU_OBERON_PADDR_MASK;

	/*
	 * Allocate platform specific structure and link it to
	 * the px state structure.
	 */
	pxu_p = kmem_zalloc(sizeof (pxu_t), KM_SLEEP);
	pxu_p->chip_type = chip_type;
	pxu_p->portid  = ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "portid", -1);

	/* Map in the registers */
	if (px_lib_map_regs(pxu_p, dip) == DDI_FAILURE) {
		kmem_free(pxu_p, sizeof (pxu_t));

		return (DDI_FAILURE);
	}

	xbc_csr_base = (caddr_t)pxu_p->px_address[PX_REG_XBC];
	csr_base = (caddr_t)pxu_p->px_address[PX_REG_CSR];

	pxu_p->tsb_cookie = iommu_tsb_alloc(pxu_p->portid);
	pxu_p->tsb_size = iommu_tsb_cookie_to_size(pxu_p->tsb_cookie);
	pxu_p->tsb_vaddr = iommu_tsb_cookie_to_va(pxu_p->tsb_cookie);

	pxu_p->tsb_paddr = va_to_pa(pxu_p->tsb_vaddr);

	/*
	 * Create "virtual-dma" property to support child devices
	 * needing to know DVMA range.
	 */
	px_dvma_range.dvma_base = (uint32_t)px_mmu_dvma_end + 1
	    - ((pxu_p->tsb_size >> 3) << MMU_PAGE_SHIFT);
	px_dvma_range.dvma_len = (uint32_t)
	    px_mmu_dvma_end - px_dvma_range.dvma_base + 1;

	(void) ddi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "virtual-dma", (int *)&px_dvma_range,
	    sizeof (px_dvma_range_prop_t) / sizeof (int));
	/*
	 * Initilize all fire hardware specific blocks.
	 */
	hvio_cb_init(xbc_csr_base, pxu_p);
	hvio_ib_init(csr_base, pxu_p);
	hvio_pec_init(csr_base, pxu_p);
	hvio_mmu_init(csr_base, pxu_p);

	px_p->px_plat_p = (void *)pxu_p;

	/*
	 * Initialize all the interrupt handlers
	 */
	switch (PX_CHIP_TYPE(pxu_p)) {
	case PX_CHIP_OBERON:
		/*
		 * Oberon hotplug uses SPARE3 field in ILU Error Log Enable
		 * register to indicate the status of leaf reset,
		 * we need to preserve the value of this bit, and keep it in
		 * px_ilu_log_mask to reflect the state of the bit
		 */
		if (CSR_BR(csr_base, ILU_ERROR_LOG_ENABLE, SPARE3))
			px_ilu_log_mask |= (1ull <<
			    ILU_ERROR_LOG_ENABLE_SPARE3);
		else
			px_ilu_log_mask &= ~(1ull <<
			    ILU_ERROR_LOG_ENABLE_SPARE3);

		px_err_reg_setup_pcie(chip_mask, csr_base, PX_ERR_ENABLE);
		break;

	case PX_CHIP_FIRE:
		px_err_reg_setup_pcie(chip_mask, csr_base, PX_ERR_ENABLE);
		break;

	default:
		cmn_err(CE_WARN, "%s%d: PX primary bus Unknown\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	/* Initilize device handle */
	*dev_hdl = (devhandle_t)csr_base;

	DBG(DBG_ATTACH, dip, "px_lib_dev_init: dev_hdl 0x%llx\n", *dev_hdl);

	return (DDI_SUCCESS);
}

int
px_lib_dev_fini(dev_info_t *dip)
{
	caddr_t			csr_base;
	uint8_t			chip_mask;
	px_t			*px_p = DIP_TO_STATE(dip);
	pxu_t			*pxu_p = (pxu_t *)px_p->px_plat_p;

	DBG(DBG_DETACH, dip, "px_lib_dev_fini: dip 0x%p\n", dip);

	/*
	 * Deinitialize all the interrupt handlers
	 */
	switch (PX_CHIP_TYPE(pxu_p)) {
	case PX_CHIP_OBERON:
	case PX_CHIP_FIRE:
		chip_mask = BITMASK(PX_CHIP_TYPE(pxu_p));
		csr_base = (caddr_t)pxu_p->px_address[PX_REG_CSR];
		px_err_reg_setup_pcie(chip_mask, csr_base, PX_ERR_DISABLE);
		break;

	default:
		cmn_err(CE_WARN, "%s%d: PX primary bus Unknown\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	iommu_tsb_free(pxu_p->tsb_cookie);

	px_lib_unmap_regs((pxu_t *)px_p->px_plat_p);
	kmem_free(px_p->px_plat_p, sizeof (pxu_t));
	px_p->px_plat_p = NULL;
	(void) ddi_prop_remove(DDI_DEV_T_NONE, dip, "virtual-dma");

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_intr_devino_to_sysino(dev_info_t *dip, devino_t devino,
    sysino_t *sysino)
{
	px_t	*px_p = DIP_TO_STATE(dip);
	pxu_t	*pxu_p = (pxu_t *)px_p->px_plat_p;
	uint64_t	ret;

	DBG(DBG_LIB_INT, dip, "px_lib_intr_devino_to_sysino: dip 0x%p "
	    "devino 0x%x\n", dip, devino);

	if ((ret = hvio_intr_devino_to_sysino(DIP_TO_HANDLE(dip),
	    pxu_p, devino, sysino)) != H_EOK) {
		DBG(DBG_LIB_INT, dip,
		    "hvio_intr_devino_to_sysino failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_INT, dip, "px_lib_intr_devino_to_sysino: sysino 0x%llx\n",
	    *sysino);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_intr_getvalid(dev_info_t *dip, sysino_t sysino,
    intr_valid_state_t *intr_valid_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_INT, dip, "px_lib_intr_getvalid: dip 0x%p sysino 0x%llx\n",
	    dip, sysino);

	if ((ret = hvio_intr_getvalid(DIP_TO_HANDLE(dip),
	    sysino, intr_valid_state)) != H_EOK) {
		DBG(DBG_LIB_INT, dip, "hvio_intr_getvalid failed, ret 0x%lx\n",
		    ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_INT, dip, "px_lib_intr_getvalid: intr_valid_state 0x%x\n",
	    *intr_valid_state);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_intr_setvalid(dev_info_t *dip, sysino_t sysino,
    intr_valid_state_t intr_valid_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_INT, dip, "px_lib_intr_setvalid: dip 0x%p sysino 0x%llx "
	    "intr_valid_state 0x%x\n", dip, sysino, intr_valid_state);

	if ((ret = hvio_intr_setvalid(DIP_TO_HANDLE(dip),
	    sysino, intr_valid_state)) != H_EOK) {
		DBG(DBG_LIB_INT, dip, "hvio_intr_setvalid failed, ret 0x%lx\n",
		    ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_intr_getstate(dev_info_t *dip, sysino_t sysino,
    intr_state_t *intr_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_INT, dip, "px_lib_intr_getstate: dip 0x%p sysino 0x%llx\n",
	    dip, sysino);

	if ((ret = hvio_intr_getstate(DIP_TO_HANDLE(dip),
	    sysino, intr_state)) != H_EOK) {
		DBG(DBG_LIB_INT, dip, "hvio_intr_getstate failed, ret 0x%lx\n",
		    ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_INT, dip, "px_lib_intr_getstate: intr_state 0x%x\n",
	    *intr_state);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_intr_setstate(dev_info_t *dip, sysino_t sysino,
    intr_state_t intr_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_INT, dip, "px_lib_intr_setstate: dip 0x%p sysino 0x%llx "
	    "intr_state 0x%x\n", dip, sysino, intr_state);

	if ((ret = hvio_intr_setstate(DIP_TO_HANDLE(dip),
	    sysino, intr_state)) != H_EOK) {
		DBG(DBG_LIB_INT, dip, "hvio_intr_setstate failed, ret 0x%lx\n",
		    ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_intr_gettarget(dev_info_t *dip, sysino_t sysino, cpuid_t *cpuid)
{
	px_t		*px_p = DIP_TO_STATE(dip);
	pxu_t		*pxu_p = (pxu_t *)px_p->px_plat_p;
	uint64_t	ret;

	DBG(DBG_LIB_INT, dip, "px_lib_intr_gettarget: dip 0x%p sysino 0x%llx\n",
	    dip, sysino);

	if ((ret = hvio_intr_gettarget(DIP_TO_HANDLE(dip), pxu_p,
	    sysino, cpuid)) != H_EOK) {
		DBG(DBG_LIB_INT, dip, "hvio_intr_gettarget failed, ret 0x%lx\n",
		    ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_INT, dip, "px_lib_intr_gettarget: cpuid 0x%x\n", cpuid);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_intr_settarget(dev_info_t *dip, sysino_t sysino, cpuid_t cpuid)
{
	px_t		*px_p = DIP_TO_STATE(dip);
	pxu_t		*pxu_p = (pxu_t *)px_p->px_plat_p;
	uint64_t	ret;

	DBG(DBG_LIB_INT, dip, "px_lib_intr_settarget: dip 0x%p sysino 0x%llx "
	    "cpuid 0x%x\n", dip, sysino, cpuid);

	if ((ret = hvio_intr_settarget(DIP_TO_HANDLE(dip), pxu_p,
	    sysino, cpuid)) != H_EOK) {
		DBG(DBG_LIB_INT, dip, "hvio_intr_settarget failed, ret 0x%lx\n",
		    ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_intr_reset(dev_info_t *dip)
{
	devino_t	ino;
	sysino_t	sysino;

	DBG(DBG_LIB_INT, dip, "px_lib_intr_reset: dip 0x%p\n", dip);

	/* Reset all Interrupts */
	for (ino = 0; ino < INTERRUPT_MAPPING_ENTRIES; ino++) {
		if (px_lib_intr_devino_to_sysino(dip, ino,
		    &sysino) != DDI_SUCCESS)
			return (BF_FATAL);

		if (px_lib_intr_setstate(dip, sysino,
		    INTR_IDLE_STATE) != DDI_SUCCESS)
			return (BF_FATAL);
	}

	return (BF_NONE);
}

/*ARGSUSED*/
int
px_lib_iommu_map(dev_info_t *dip, tsbid_t tsbid, pages_t pages,
    io_attributes_t attr, void *addr, size_t pfn_index, int flags)
{
	px_t		*px_p = DIP_TO_STATE(dip);
	pxu_t		*pxu_p = (pxu_t *)px_p->px_plat_p;
	uint64_t	ret;

	DBG(DBG_LIB_DMA, dip, "px_lib_iommu_map: dip 0x%p tsbid 0x%llx "
	    "pages 0x%x attr 0x%x addr 0x%p pfn_index 0x%llx flags 0x%x\n",
	    dip, tsbid, pages, attr, addr, pfn_index, flags);

	if ((ret = hvio_iommu_map(px_p->px_dev_hdl, pxu_p, tsbid, pages,
	    attr, addr, pfn_index, flags)) != H_EOK) {
		DBG(DBG_LIB_DMA, dip,
		    "px_lib_iommu_map failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_iommu_demap(dev_info_t *dip, tsbid_t tsbid, pages_t pages)
{
	px_t		*px_p = DIP_TO_STATE(dip);
	pxu_t		*pxu_p = (pxu_t *)px_p->px_plat_p;
	uint64_t	ret;

	DBG(DBG_LIB_DMA, dip, "px_lib_iommu_demap: dip 0x%p tsbid 0x%llx "
	    "pages 0x%x\n", dip, tsbid, pages);

	if ((ret = hvio_iommu_demap(px_p->px_dev_hdl, pxu_p, tsbid, pages))
	    != H_EOK) {
		DBG(DBG_LIB_DMA, dip,
		    "px_lib_iommu_demap failed, ret 0x%lx\n", ret);

		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_iommu_getmap(dev_info_t *dip, tsbid_t tsbid, io_attributes_t *attr_p,
    r_addr_t *r_addr_p)
{
	px_t	*px_p = DIP_TO_STATE(dip);
	pxu_t	*pxu_p = (pxu_t *)px_p->px_plat_p;
	uint64_t	ret;

	DBG(DBG_LIB_DMA, dip, "px_lib_iommu_getmap: dip 0x%p tsbid 0x%llx\n",
	    dip, tsbid);

	if ((ret = hvio_iommu_getmap(DIP_TO_HANDLE(dip), pxu_p, tsbid,
	    attr_p, r_addr_p)) != H_EOK) {
		DBG(DBG_LIB_DMA, dip,
		    "hvio_iommu_getmap failed, ret 0x%lx\n", ret);

		return ((ret == H_ENOMAP) ? DDI_DMA_NOMAPPING:DDI_FAILURE);
	}

	DBG(DBG_LIB_DMA, dip, "px_lib_iommu_getmap: attr 0x%x r_addr 0x%llx\n",
	    *attr_p, *r_addr_p);

	return (DDI_SUCCESS);
}


/*
 * Checks dma attributes against system bypass ranges
 * The bypass range is determined by the hardware. Return them so the
 * common code can do generic checking against them.
 */
/*ARGSUSED*/
int
px_lib_dma_bypass_rngchk(dev_info_t *dip, ddi_dma_attr_t *attr_p,
    uint64_t *lo_p, uint64_t *hi_p)
{
	px_t	*px_p = DIP_TO_STATE(dip);
	pxu_t	*pxu_p = (pxu_t *)px_p->px_plat_p;

	*lo_p = hvio_get_bypass_base(pxu_p);
	*hi_p = hvio_get_bypass_end(pxu_p);

	return (DDI_SUCCESS);
}


/*ARGSUSED*/
int
px_lib_iommu_getbypass(dev_info_t *dip, r_addr_t ra, io_attributes_t attr,
    io_addr_t *io_addr_p)
{
	uint64_t	ret;
	px_t	*px_p = DIP_TO_STATE(dip);
	pxu_t	*pxu_p = (pxu_t *)px_p->px_plat_p;

	DBG(DBG_LIB_DMA, dip, "px_lib_iommu_getbypass: dip 0x%p ra 0x%llx "
	    "attr 0x%x\n", dip, ra, attr);

	if ((ret = hvio_iommu_getbypass(DIP_TO_HANDLE(dip), pxu_p, ra,
	    attr, io_addr_p)) != H_EOK) {
		DBG(DBG_LIB_DMA, dip,
		    "hvio_iommu_getbypass failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_DMA, dip, "px_lib_iommu_getbypass: io_addr 0x%llx\n",
	    *io_addr_p);

	return (DDI_SUCCESS);
}

/*
 * bus dma sync entry point.
 */
/*ARGSUSED*/
int
px_lib_dma_sync(dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t handle,
    off_t off, size_t len, uint_t cache_flags)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)handle;
	px_t	*px_p = DIP_TO_STATE(dip);
	pxu_t	*pxu_p = (pxu_t *)px_p->px_plat_p;

	DBG(DBG_LIB_DMA, dip, "px_lib_dma_sync: dip 0x%p rdip 0x%p "
	    "handle 0x%llx off 0x%x len 0x%x flags 0x%x\n",
	    dip, rdip, handle, off, len, cache_flags);

	/*
	 * No flush needed for Oberon
	 */
	if (PX_CHIP_TYPE(pxu_p) == PX_CHIP_OBERON)
		return (DDI_SUCCESS);

	/*
	 * jbus_stst_order is found only in certain cpu modules.
	 * Just return success if not present.
	 */
	if (&jbus_stst_order == NULL)
		return (DDI_SUCCESS);

	if (!(mp->dmai_flags & PX_DMAI_FLAGS_INUSE)) {
		cmn_err(CE_WARN, "%s%d: Unbound dma handle %p.",
		    ddi_driver_name(rdip), ddi_get_instance(rdip), (void *)mp);

		return (DDI_FAILURE);
	}

	if (mp->dmai_flags & PX_DMAI_FLAGS_NOSYNC)
		return (DDI_SUCCESS);

	/*
	 * No flush needed when sending data from memory to device.
	 * Nothing to do to "sync" memory to what device would already see.
	 */
	if (!(mp->dmai_rflags & DDI_DMA_READ) ||
	    ((cache_flags & PX_DMA_SYNC_DDI_FLAGS) == DDI_DMA_SYNC_FORDEV))
		return (DDI_SUCCESS);

	/*
	 * Perform necessary cpu workaround to ensure jbus ordering.
	 * CPU's internal "invalidate FIFOs" are flushed.
	 */

#if !defined(lint)
	kpreempt_disable();
#endif
	jbus_stst_order();
#if !defined(lint)
	kpreempt_enable();
#endif
	return (DDI_SUCCESS);
}

/*
 * MSIQ Functions:
 */
/*ARGSUSED*/
int
px_lib_msiq_init(dev_info_t *dip)
{
	px_t		*px_p = DIP_TO_STATE(dip);
	pxu_t		*pxu_p = (pxu_t *)px_p->px_plat_p;
	px_msiq_state_t	*msiq_state_p = &px_p->px_ib_p->ib_msiq_state;
	px_dvma_addr_t	pg_index;
	size_t		size;
	int		ret;

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_init: dip 0x%p\n", dip);

	/*
	 * Map the EQ memory into the Fire MMU (has to be 512KB aligned)
	 * and then initialize the base address register.
	 *
	 * Allocate entries from Fire IOMMU so that the resulting address
	 * is properly aligned.  Calculate the index of the first allocated
	 * entry.  Note: The size of the mapping is assumed to be a multiple
	 * of the page size.
	 */
	size = msiq_state_p->msiq_cnt *
	    msiq_state_p->msiq_rec_cnt * sizeof (msiq_rec_t);

	pxu_p->msiq_mapped_p = vmem_xalloc(px_p->px_mmu_p->mmu_dvma_map,
	    size, (512 * 1024), 0, 0, NULL, NULL, VM_NOSLEEP | VM_BESTFIT);

	if (pxu_p->msiq_mapped_p == NULL)
		return (DDI_FAILURE);

	pg_index = MMU_PAGE_INDEX(px_p->px_mmu_p,
	    MMU_BTOP((ulong_t)pxu_p->msiq_mapped_p));

	if ((ret = px_lib_iommu_map(px_p->px_dip, PCI_TSBID(0, pg_index),
	    MMU_BTOP(size), PCI_MAP_ATTR_WRITE, msiq_state_p->msiq_buf_p,
	    0, MMU_MAP_BUF)) != DDI_SUCCESS) {
		DBG(DBG_LIB_MSIQ, dip,
		    "hvio_msiq_init failed, ret 0x%lx\n", ret);

		(void) px_lib_msiq_fini(dip);
		return (DDI_FAILURE);
	}

	(void) hvio_msiq_init(DIP_TO_HANDLE(dip), pxu_p);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msiq_fini(dev_info_t *dip)
{
	px_t		*px_p = DIP_TO_STATE(dip);
	pxu_t		*pxu_p = (pxu_t *)px_p->px_plat_p;
	px_msiq_state_t	*msiq_state_p = &px_p->px_ib_p->ib_msiq_state;
	px_dvma_addr_t	pg_index;
	size_t		size;

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_fini: dip 0x%p\n", dip);

	/*
	 * Unmap and free the EQ memory that had been mapped
	 * into the Fire IOMMU.
	 */
	size = msiq_state_p->msiq_cnt *
	    msiq_state_p->msiq_rec_cnt * sizeof (msiq_rec_t);

	pg_index = MMU_PAGE_INDEX(px_p->px_mmu_p,
	    MMU_BTOP((ulong_t)pxu_p->msiq_mapped_p));

	(void) px_lib_iommu_demap(px_p->px_dip,
	    PCI_TSBID(0, pg_index), MMU_BTOP(size));

	/* Free the entries from the Fire MMU */
	vmem_xfree(px_p->px_mmu_p->mmu_dvma_map,
	    (void *)pxu_p->msiq_mapped_p, size);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msiq_info(dev_info_t *dip, msiqid_t msiq_id, r_addr_t *ra_p,
    uint_t *msiq_rec_cnt_p)
{
	px_t		*px_p = DIP_TO_STATE(dip);
	px_msiq_state_t	*msiq_state_p = &px_p->px_ib_p->ib_msiq_state;
	size_t		msiq_size;

	DBG(DBG_LIB_MSIQ, dip, "px_msiq_info: dip 0x%p msiq_id 0x%x\n",
	    dip, msiq_id);

	msiq_size = msiq_state_p->msiq_rec_cnt * sizeof (msiq_rec_t);
	ra_p = (r_addr_t *)((caddr_t)msiq_state_p->msiq_buf_p +
	    (msiq_id * msiq_size));

	*msiq_rec_cnt_p = msiq_state_p->msiq_rec_cnt;

	DBG(DBG_LIB_MSIQ, dip, "px_msiq_info: ra_p 0x%p msiq_rec_cnt 0x%x\n",
	    ra_p, *msiq_rec_cnt_p);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msiq_getvalid(dev_info_t *dip, msiqid_t msiq_id,
    pci_msiq_valid_state_t *msiq_valid_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_getvalid: dip 0x%p msiq_id 0x%x\n",
	    dip, msiq_id);

	if ((ret = hvio_msiq_getvalid(DIP_TO_HANDLE(dip),
	    msiq_id, msiq_valid_state)) != H_EOK) {
		DBG(DBG_LIB_MSIQ, dip,
		    "hvio_msiq_getvalid failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_getvalid: msiq_valid_state 0x%x\n",
	    *msiq_valid_state);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msiq_setvalid(dev_info_t *dip, msiqid_t msiq_id,
    pci_msiq_valid_state_t msiq_valid_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_setvalid: dip 0x%p msiq_id 0x%x "
	    "msiq_valid_state 0x%x\n", dip, msiq_id, msiq_valid_state);

	if ((ret = hvio_msiq_setvalid(DIP_TO_HANDLE(dip),
	    msiq_id, msiq_valid_state)) != H_EOK) {
		DBG(DBG_LIB_MSIQ, dip,
		    "hvio_msiq_setvalid failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msiq_getstate(dev_info_t *dip, msiqid_t msiq_id,
    pci_msiq_state_t *msiq_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_getstate: dip 0x%p msiq_id 0x%x\n",
	    dip, msiq_id);

	if ((ret = hvio_msiq_getstate(DIP_TO_HANDLE(dip),
	    msiq_id, msiq_state)) != H_EOK) {
		DBG(DBG_LIB_MSIQ, dip,
		    "hvio_msiq_getstate failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_getstate: msiq_state 0x%x\n",
	    *msiq_state);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msiq_setstate(dev_info_t *dip, msiqid_t msiq_id,
    pci_msiq_state_t msiq_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_setstate: dip 0x%p msiq_id 0x%x "
	    "msiq_state 0x%x\n", dip, msiq_id, msiq_state);

	if ((ret = hvio_msiq_setstate(DIP_TO_HANDLE(dip),
	    msiq_id, msiq_state)) != H_EOK) {
		DBG(DBG_LIB_MSIQ, dip,
		    "hvio_msiq_setstate failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msiq_gethead(dev_info_t *dip, msiqid_t msiq_id,
    msiqhead_t *msiq_head)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_gethead: dip 0x%p msiq_id 0x%x\n",
	    dip, msiq_id);

	if ((ret = hvio_msiq_gethead(DIP_TO_HANDLE(dip),
	    msiq_id, msiq_head)) != H_EOK) {
		DBG(DBG_LIB_MSIQ, dip,
		    "hvio_msiq_gethead failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_gethead: msiq_head 0x%x\n",
	    *msiq_head);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msiq_sethead(dev_info_t *dip, msiqid_t msiq_id,
    msiqhead_t msiq_head)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_sethead: dip 0x%p msiq_id 0x%x "
	    "msiq_head 0x%x\n", dip, msiq_id, msiq_head);

	if ((ret = hvio_msiq_sethead(DIP_TO_HANDLE(dip),
	    msiq_id, msiq_head)) != H_EOK) {
		DBG(DBG_LIB_MSIQ, dip,
		    "hvio_msiq_sethead failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msiq_gettail(dev_info_t *dip, msiqid_t msiq_id,
    msiqtail_t *msiq_tail)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_gettail: dip 0x%p msiq_id 0x%x\n",
	    dip, msiq_id);

	if ((ret = hvio_msiq_gettail(DIP_TO_HANDLE(dip),
	    msiq_id, msiq_tail)) != H_EOK) {
		DBG(DBG_LIB_MSIQ, dip,
		    "hvio_msiq_gettail failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_MSIQ, dip, "px_lib_msiq_gettail: msiq_tail 0x%x\n",
	    *msiq_tail);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
void
px_lib_get_msiq_rec(dev_info_t *dip, msiqhead_t *msiq_head_p,
    msiq_rec_t *msiq_rec_p)
{
	eq_rec_t	*eq_rec_p = (eq_rec_t *)msiq_head_p;

	DBG(DBG_LIB_MSIQ, dip, "px_lib_get_msiq_rec: dip 0x%p eq_rec_p 0x%p\n",
	    dip, eq_rec_p);

	if (!eq_rec_p->eq_rec_fmt_type) {
		/* Set msiq_rec_type to zero */
		msiq_rec_p->msiq_rec_type = 0;

		return;
	}

	DBG(DBG_LIB_MSIQ, dip, "px_lib_get_msiq_rec: EQ RECORD, "
	    "eq_rec_rid 0x%llx eq_rec_fmt_type 0x%llx "
	    "eq_rec_len 0x%llx eq_rec_addr0 0x%llx "
	    "eq_rec_addr1 0x%llx eq_rec_data0 0x%llx "
	    "eq_rec_data1 0x%llx\n", eq_rec_p->eq_rec_rid,
	    eq_rec_p->eq_rec_fmt_type, eq_rec_p->eq_rec_len,
	    eq_rec_p->eq_rec_addr0, eq_rec_p->eq_rec_addr1,
	    eq_rec_p->eq_rec_data0, eq_rec_p->eq_rec_data1);

	/*
	 * Only upper 4 bits of eq_rec_fmt_type is used
	 * to identify the EQ record type.
	 */
	switch (eq_rec_p->eq_rec_fmt_type >> 3) {
	case EQ_REC_MSI32:
		msiq_rec_p->msiq_rec_type = MSI32_REC;

		msiq_rec_p->msiq_rec_data.msi.msi_data =
		    eq_rec_p->eq_rec_data0;
		break;
	case EQ_REC_MSI64:
		msiq_rec_p->msiq_rec_type = MSI64_REC;

		msiq_rec_p->msiq_rec_data.msi.msi_data =
		    eq_rec_p->eq_rec_data0;
		break;
	case EQ_REC_MSG:
		msiq_rec_p->msiq_rec_type = MSG_REC;

		msiq_rec_p->msiq_rec_data.msg.msg_route =
		    eq_rec_p->eq_rec_fmt_type & 7;
		msiq_rec_p->msiq_rec_data.msg.msg_targ = eq_rec_p->eq_rec_rid;
		msiq_rec_p->msiq_rec_data.msg.msg_code = eq_rec_p->eq_rec_data0;
		break;
	default:
		cmn_err(CE_WARN, "%s%d: px_lib_get_msiq_rec: "
		    "0x%x is an unknown EQ record type",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    (int)eq_rec_p->eq_rec_fmt_type);
		break;
	}

	msiq_rec_p->msiq_rec_rid = eq_rec_p->eq_rec_rid;
	msiq_rec_p->msiq_rec_msi_addr = ((eq_rec_p->eq_rec_addr1 << 16) |
	    (eq_rec_p->eq_rec_addr0 << 2));
}

/*ARGSUSED*/
void
px_lib_clr_msiq_rec(dev_info_t *dip, msiqhead_t *msiq_head_p)
{
	eq_rec_t	*eq_rec_p = (eq_rec_t *)msiq_head_p;

	DBG(DBG_LIB_MSIQ, dip, "px_lib_clr_msiq_rec: dip 0x%p eq_rec_p 0x%p\n",
	    dip, eq_rec_p);

	if (eq_rec_p->eq_rec_fmt_type) {
		/* Zero out eq_rec_fmt_type field */
		eq_rec_p->eq_rec_fmt_type = 0;
	}
}

/*
 * MSI Functions:
 */
/*ARGSUSED*/
int
px_lib_msi_init(dev_info_t *dip)
{
	px_t		*px_p = DIP_TO_STATE(dip);
	px_msi_state_t	*msi_state_p = &px_p->px_ib_p->ib_msi_state;
	uint64_t	ret;

	DBG(DBG_LIB_MSI, dip, "px_lib_msi_init: dip 0x%p\n", dip);

	if ((ret = hvio_msi_init(DIP_TO_HANDLE(dip),
	    msi_state_p->msi_addr32, msi_state_p->msi_addr64)) != H_EOK) {
		DBG(DBG_LIB_MSIQ, dip, "px_lib_msi_init failed, ret 0x%lx\n",
		    ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msi_getmsiq(dev_info_t *dip, msinum_t msi_num,
    msiqid_t *msiq_id)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSI, dip, "px_lib_msi_getmsiq: dip 0x%p msi_num 0x%x\n",
	    dip, msi_num);

	if ((ret = hvio_msi_getmsiq(DIP_TO_HANDLE(dip),
	    msi_num, msiq_id)) != H_EOK) {
		DBG(DBG_LIB_MSI, dip,
		    "hvio_msi_getmsiq failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_MSI, dip, "px_lib_msi_getmsiq: msiq_id 0x%x\n",
	    *msiq_id);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msi_setmsiq(dev_info_t *dip, msinum_t msi_num,
    msiqid_t msiq_id, msi_type_t msitype)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSI, dip, "px_lib_msi_setmsiq: dip 0x%p msi_num 0x%x "
	    "msq_id 0x%x\n", dip, msi_num, msiq_id);

	if ((ret = hvio_msi_setmsiq(DIP_TO_HANDLE(dip),
	    msi_num, msiq_id)) != H_EOK) {
		DBG(DBG_LIB_MSI, dip,
		    "hvio_msi_setmsiq failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msi_getvalid(dev_info_t *dip, msinum_t msi_num,
    pci_msi_valid_state_t *msi_valid_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSI, dip, "px_lib_msi_getvalid: dip 0x%p msi_num 0x%x\n",
	    dip, msi_num);

	if ((ret = hvio_msi_getvalid(DIP_TO_HANDLE(dip),
	    msi_num, msi_valid_state)) != H_EOK) {
		DBG(DBG_LIB_MSI, dip,
		    "hvio_msi_getvalid failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_MSI, dip, "px_lib_msi_getvalid: msiq_id 0x%x\n",
	    *msi_valid_state);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msi_setvalid(dev_info_t *dip, msinum_t msi_num,
    pci_msi_valid_state_t msi_valid_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSI, dip, "px_lib_msi_setvalid: dip 0x%p msi_num 0x%x "
	    "msi_valid_state 0x%x\n", dip, msi_num, msi_valid_state);

	if ((ret = hvio_msi_setvalid(DIP_TO_HANDLE(dip),
	    msi_num, msi_valid_state)) != H_EOK) {
		DBG(DBG_LIB_MSI, dip,
		    "hvio_msi_setvalid failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msi_getstate(dev_info_t *dip, msinum_t msi_num,
    pci_msi_state_t *msi_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSI, dip, "px_lib_msi_getstate: dip 0x%p msi_num 0x%x\n",
	    dip, msi_num);

	if ((ret = hvio_msi_getstate(DIP_TO_HANDLE(dip),
	    msi_num, msi_state)) != H_EOK) {
		DBG(DBG_LIB_MSI, dip,
		    "hvio_msi_getstate failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_MSI, dip, "px_lib_msi_getstate: msi_state 0x%x\n",
	    *msi_state);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msi_setstate(dev_info_t *dip, msinum_t msi_num,
    pci_msi_state_t msi_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSI, dip, "px_lib_msi_setstate: dip 0x%p msi_num 0x%x "
	    "msi_state 0x%x\n", dip, msi_num, msi_state);

	if ((ret = hvio_msi_setstate(DIP_TO_HANDLE(dip),
	    msi_num, msi_state)) != H_EOK) {
		DBG(DBG_LIB_MSI, dip,
		    "hvio_msi_setstate failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * MSG Functions:
 */
/*ARGSUSED*/
int
px_lib_msg_getmsiq(dev_info_t *dip, pcie_msg_type_t msg_type,
    msiqid_t *msiq_id)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSG, dip, "px_lib_msg_getmsiq: dip 0x%p msg_type 0x%x\n",
	    dip, msg_type);

	if ((ret = hvio_msg_getmsiq(DIP_TO_HANDLE(dip),
	    msg_type, msiq_id)) != H_EOK) {
		DBG(DBG_LIB_MSG, dip,
		    "hvio_msg_getmsiq failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_MSI, dip, "px_lib_msg_getmsiq: msiq_id 0x%x\n",
	    *msiq_id);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msg_setmsiq(dev_info_t *dip, pcie_msg_type_t msg_type,
    msiqid_t msiq_id)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSG, dip, "px_lib_msi_setstate: dip 0x%p msg_type 0x%x "
	    "msiq_id 0x%x\n", dip, msg_type, msiq_id);

	if ((ret = hvio_msg_setmsiq(DIP_TO_HANDLE(dip),
	    msg_type, msiq_id)) != H_EOK) {
		DBG(DBG_LIB_MSG, dip,
		    "hvio_msg_setmsiq failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msg_getvalid(dev_info_t *dip, pcie_msg_type_t msg_type,
    pcie_msg_valid_state_t *msg_valid_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSG, dip, "px_lib_msg_getvalid: dip 0x%p msg_type 0x%x\n",
	    dip, msg_type);

	if ((ret = hvio_msg_getvalid(DIP_TO_HANDLE(dip), msg_type,
	    msg_valid_state)) != H_EOK) {
		DBG(DBG_LIB_MSG, dip,
		    "hvio_msg_getvalid failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	DBG(DBG_LIB_MSI, dip, "px_lib_msg_getvalid: msg_valid_state 0x%x\n",
	    *msg_valid_state);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
px_lib_msg_setvalid(dev_info_t *dip, pcie_msg_type_t msg_type,
    pcie_msg_valid_state_t msg_valid_state)
{
	uint64_t	ret;

	DBG(DBG_LIB_MSG, dip, "px_lib_msg_setvalid: dip 0x%p msg_type 0x%x "
	    "msg_valid_state 0x%x\n", dip, msg_type, msg_valid_state);

	if ((ret = hvio_msg_setvalid(DIP_TO_HANDLE(dip), msg_type,
	    msg_valid_state)) != H_EOK) {
		DBG(DBG_LIB_MSG, dip,
		    "hvio_msg_setvalid failed, ret 0x%lx\n", ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Suspend/Resume Functions:
 * Currently unsupported by hypervisor
 */
int
px_lib_suspend(dev_info_t *dip)
{
	px_t		*px_p = DIP_TO_STATE(dip);
	pxu_t		*pxu_p = (pxu_t *)px_p->px_plat_p;
	px_cb_t		*cb_p = PX2CB(px_p);
	devhandle_t	dev_hdl, xbus_dev_hdl;
	uint64_t	ret = H_EOK;

	DBG(DBG_DETACH, dip, "px_lib_suspend: dip 0x%p\n", dip);

	dev_hdl = (devhandle_t)pxu_p->px_address[PX_REG_CSR];
	xbus_dev_hdl = (devhandle_t)pxu_p->px_address[PX_REG_XBC];

	if ((ret = hvio_suspend(dev_hdl, pxu_p)) != H_EOK)
		goto fail;

	if (--cb_p->attachcnt == 0) {
		ret = hvio_cb_suspend(xbus_dev_hdl, pxu_p);
		if (ret != H_EOK)
			cb_p->attachcnt++;
	}
	pxu_p->cpr_flag = PX_ENTERED_CPR;

fail:
	return ((ret != H_EOK) ? DDI_FAILURE: DDI_SUCCESS);
}

void
px_lib_resume(dev_info_t *dip)
{
	px_t		*px_p = DIP_TO_STATE(dip);
	pxu_t		*pxu_p = (pxu_t *)px_p->px_plat_p;
	px_cb_t		*cb_p = PX2CB(px_p);
	devhandle_t	dev_hdl, xbus_dev_hdl;
	devino_t	pec_ino = px_p->px_inos[PX_INTR_PEC];
	devino_t	xbc_ino = px_p->px_inos[PX_INTR_XBC];

	DBG(DBG_ATTACH, dip, "px_lib_resume: dip 0x%p\n", dip);

	dev_hdl = (devhandle_t)pxu_p->px_address[PX_REG_CSR];
	xbus_dev_hdl = (devhandle_t)pxu_p->px_address[PX_REG_XBC];

	if (++cb_p->attachcnt == 1)
		hvio_cb_resume(dev_hdl, xbus_dev_hdl, xbc_ino, pxu_p);

	hvio_resume(dev_hdl, pec_ino, pxu_p);
}

/*
 * Generate a unique Oberon UBC ID based on the Logicial System Board and
 * the IO Channel from the portid property field.
 */
static uint64_t
oberon_get_ubc_id(dev_info_t *dip)
{
	px_t	*px_p = DIP_TO_STATE(dip);
	pxu_t	*pxu_p = (pxu_t *)px_p->px_plat_p;
	uint64_t	ubc_id;

	/*
	 * Generate a unique 6 bit UBC ID using the 2 IO_Channel#[1:0] bits and
	 * the 4 LSB_ID[3:0] bits from the Oberon's portid property.
	 */
	ubc_id = (((pxu_p->portid >> OBERON_PORT_ID_IOC) &
	    OBERON_PORT_ID_IOC_MASK) | (((pxu_p->portid >>
	    OBERON_PORT_ID_LSB) & OBERON_PORT_ID_LSB_MASK)
	    << OBERON_UBC_ID_LSB));

	return (ubc_id);
}

/*
 * Oberon does not have a UBC scratch register, so alloc an array of scratch
 * registers when needed and use a unique UBC ID as an index. This code
 * can be simplified if we use a pre-allocated array. They are currently
 * being dynamically allocated because it's only needed by the Oberon.
 */
static void
oberon_set_cb(dev_info_t *dip, uint64_t val)
{
	uint64_t	ubc_id;

	if (px_oberon_ubc_scratch_regs == NULL)
		px_oberon_ubc_scratch_regs =
		    (uint64_t *)kmem_zalloc(sizeof (uint64_t)*
		    OBERON_UBC_ID_MAX, KM_SLEEP);

	ubc_id = oberon_get_ubc_id(dip);

	px_oberon_ubc_scratch_regs[ubc_id] = val;

	/*
	 * Check if any scratch registers are still in use. If all scratch
	 * registers are currently set to zero, then deallocate the scratch
	 * register array.
	 */
	for (ubc_id = 0; ubc_id < OBERON_UBC_ID_MAX; ubc_id++) {
		if (px_oberon_ubc_scratch_regs[ubc_id] != NULL)
			return;
	}

	/*
	 * All scratch registers are set to zero so deallocate the scratch
	 * register array and set the pointer to NULL.
	 */
	kmem_free(px_oberon_ubc_scratch_regs,
	    (sizeof (uint64_t)*OBERON_UBC_ID_MAX));

	px_oberon_ubc_scratch_regs = NULL;
}

/*
 * Oberon does not have a UBC scratch register, so use an allocated array of
 * scratch registers and use the unique UBC ID as an index into that array.
 */
static uint64_t
oberon_get_cb(dev_info_t *dip)
{
	uint64_t	ubc_id;

	if (px_oberon_ubc_scratch_regs == NULL)
		return (0);

	ubc_id = oberon_get_ubc_id(dip);

	return (px_oberon_ubc_scratch_regs[ubc_id]);
}

/*
 * Misc Functions:
 * Currently unsupported by hypervisor
 */
static uint64_t
px_get_cb(dev_info_t *dip)
{
	px_t	*px_p = DIP_TO_STATE(dip);
	pxu_t	*pxu_p = (pxu_t *)px_p->px_plat_p;

	/*
	 * Oberon does not currently have Scratchpad registers.
	 */
	if (PX_CHIP_TYPE(pxu_p) == PX_CHIP_OBERON)
		return (oberon_get_cb(dip));

	return (CSR_XR((caddr_t)pxu_p->px_address[PX_REG_XBC], JBUS_SCRATCH_1));
}

static void
px_set_cb(dev_info_t *dip, uint64_t val)
{
	px_t	*px_p = DIP_TO_STATE(dip);
	pxu_t	*pxu_p = (pxu_t *)px_p->px_plat_p;

	/*
	 * Oberon does not currently have Scratchpad registers.
	 */
	if (PX_CHIP_TYPE(pxu_p) == PX_CHIP_OBERON) {
		oberon_set_cb(dip, val);
		return;
	}

	CSR_XS((caddr_t)pxu_p->px_address[PX_REG_XBC], JBUS_SCRATCH_1, val);
}

/*ARGSUSED*/
int
px_lib_map_vconfig(dev_info_t *dip,
	ddi_map_req_t *mp, pci_config_offset_t off,
		pci_regspec_t *rp, caddr_t *addrp)
{
	/*
	 * No special config space access services in this layer.
	 */
	return (DDI_FAILURE);
}

void
px_lib_map_attr_check(ddi_map_req_t *mp)
{
	ddi_acc_hdl_t *hp = mp->map_handlep;

	/* fire does not accept byte masks from PIO store merge */
	if (hp->ah_acc.devacc_attr_dataorder == DDI_STORECACHING_OK_ACC)
		hp->ah_acc.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
}

/* This function is called only by poke, caut put and pxtool poke. */
void
px_lib_clr_errs(px_t *px_p, dev_info_t *rdip, uint64_t addr)
{
	px_pec_t	*pec_p = px_p->px_pec_p;
	dev_info_t	*rpdip = px_p->px_dip;
	int		rc_err, fab_err, i;
	int		acctype = pec_p->pec_safeacc_type;
	ddi_fm_error_t	derr;
	px_ranges_t	*ranges_p;
	int		range_len;
	uint32_t	addr_high, addr_low;
	pcie_req_id_t	bdf = 0;

	/* Create the derr */
	bzero(&derr, sizeof (ddi_fm_error_t));
	derr.fme_version = DDI_FME_VERSION;
	derr.fme_ena = fm_ena_generate(0, FM_ENA_FMT1);
	derr.fme_flag = acctype;

	if (acctype == DDI_FM_ERR_EXPECTED) {
		derr.fme_status = DDI_FM_NONFATAL;
		ndi_fm_acc_err_set(pec_p->pec_acc_hdl, &derr);
	}

	if (px_fm_enter(px_p) != DDI_SUCCESS)
		return;

	/* send ereport/handle/clear fire registers */
	rc_err = px_err_cmn_intr(px_p, &derr, PX_LIB_CALL, PX_FM_BLOCK_ALL);

	/* Figure out if this is a cfg or mem32 access */
	addr_high = (uint32_t)(addr >> 32);
	addr_low = (uint32_t)addr;
	range_len = px_p->px_ranges_length / sizeof (px_ranges_t);
	i = 0;
	for (ranges_p = px_p->px_ranges_p; i < range_len; i++, ranges_p++) {
		if (ranges_p->parent_high == addr_high) {
			switch (ranges_p->child_high & PCI_ADDR_MASK) {
			case PCI_ADDR_CONFIG:
				bdf = (pcie_req_id_t)(addr_low >> 12);
				addr_low = 0;
				break;
			case PCI_ADDR_MEM32:
				if (rdip)
					bdf = PCI_GET_BDF(rdip);
				else
					bdf = NULL;
				break;
			}
			break;
		}
	}

	px_rp_en_q(px_p, bdf, addr_low, NULL);

	/*
	 * XXX - Current code scans the fabric for all px_tool accesses.
	 * In future, do not scan fabric for px_tool access to IO Root Nexus
	 */
	fab_err = px_scan_fabric(px_p, rpdip, &derr);

	px_err_panic(rc_err, PX_RC, fab_err, B_TRUE);
	px_fm_exit(px_p);
	px_err_panic(rc_err, PX_RC, fab_err, B_FALSE);
}

#ifdef  DEBUG
int	px_peekfault_cnt = 0;
int	px_pokefault_cnt = 0;
#endif  /* DEBUG */

/*ARGSUSED*/
static int
px_lib_do_poke(dev_info_t *dip, dev_info_t *rdip,
    peekpoke_ctlops_t *in_args)
{
	px_t *px_p = DIP_TO_STATE(dip);
	px_pec_t *pec_p = px_p->px_pec_p;
	int err = DDI_SUCCESS;
	on_trap_data_t otd;

	mutex_enter(&pec_p->pec_pokefault_mutex);
	pec_p->pec_ontrap_data = &otd;
	pec_p->pec_safeacc_type = DDI_FM_ERR_POKE;

	/* Set up protected environment. */
	if (!on_trap(&otd, OT_DATA_ACCESS)) {
		uintptr_t tramp = otd.ot_trampoline;

		otd.ot_trampoline = (uintptr_t)&poke_fault;
		err = do_poke(in_args->size, (void *)in_args->dev_addr,
		    (void *)in_args->host_addr);
		otd.ot_trampoline = tramp;
	} else
		err = DDI_FAILURE;

	px_lib_clr_errs(px_p, rdip, in_args->dev_addr);

	if (otd.ot_trap & OT_DATA_ACCESS)
		err = DDI_FAILURE;

	/* Take down protected environment. */
	no_trap();

	pec_p->pec_ontrap_data = NULL;
	pec_p->pec_safeacc_type = DDI_FM_ERR_UNEXPECTED;
	mutex_exit(&pec_p->pec_pokefault_mutex);

#ifdef  DEBUG
	if (err == DDI_FAILURE)
		px_pokefault_cnt++;
#endif
	return (err);
}

/*ARGSUSED*/
static int
px_lib_do_caut_put(dev_info_t *dip, dev_info_t *rdip,
    peekpoke_ctlops_t *cautacc_ctlops_arg)
{
	size_t size = cautacc_ctlops_arg->size;
	uintptr_t dev_addr = cautacc_ctlops_arg->dev_addr;
	uintptr_t host_addr = cautacc_ctlops_arg->host_addr;
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)cautacc_ctlops_arg->handle;
	size_t repcount = cautacc_ctlops_arg->repcount;
	uint_t flags = cautacc_ctlops_arg->flags;

	px_t *px_p = DIP_TO_STATE(dip);
	px_pec_t *pec_p = px_p->px_pec_p;
	int err = DDI_SUCCESS;

	/*
	 * Note that i_ndi_busop_access_enter ends up grabbing the pokefault
	 * mutex.
	 */
	i_ndi_busop_access_enter(hp->ahi_common.ah_dip, (ddi_acc_handle_t)hp);

	pec_p->pec_ontrap_data = (on_trap_data_t *)hp->ahi_err->err_ontrap;
	pec_p->pec_safeacc_type = DDI_FM_ERR_EXPECTED;
	hp->ahi_err->err_expected = DDI_FM_ERR_EXPECTED;

	if (!i_ddi_ontrap((ddi_acc_handle_t)hp)) {
		for (; repcount; repcount--) {
			switch (size) {

			case sizeof (uint8_t):
				i_ddi_put8(hp, (uint8_t *)dev_addr,
				    *(uint8_t *)host_addr);
				break;

			case sizeof (uint16_t):
				i_ddi_put16(hp, (uint16_t *)dev_addr,
				    *(uint16_t *)host_addr);
				break;

			case sizeof (uint32_t):
				i_ddi_put32(hp, (uint32_t *)dev_addr,
				    *(uint32_t *)host_addr);
				break;

			case sizeof (uint64_t):
				i_ddi_put64(hp, (uint64_t *)dev_addr,
				    *(uint64_t *)host_addr);
				break;
			}

			host_addr += size;

			if (flags == DDI_DEV_AUTOINCR)
				dev_addr += size;

			px_lib_clr_errs(px_p, rdip, dev_addr);

			if (pec_p->pec_ontrap_data->ot_trap & OT_DATA_ACCESS) {
				err = DDI_FAILURE;
#ifdef  DEBUG
				px_pokefault_cnt++;
#endif
				break;
			}
		}
	}

	i_ddi_notrap((ddi_acc_handle_t)hp);
	pec_p->pec_ontrap_data = NULL;
	pec_p->pec_safeacc_type = DDI_FM_ERR_UNEXPECTED;
	i_ndi_busop_access_exit(hp->ahi_common.ah_dip, (ddi_acc_handle_t)hp);
	hp->ahi_err->err_expected = DDI_FM_ERR_UNEXPECTED;

	return (err);
}


int
px_lib_ctlops_poke(dev_info_t *dip, dev_info_t *rdip,
    peekpoke_ctlops_t *in_args)
{
	return (in_args->handle ? px_lib_do_caut_put(dip, rdip, in_args) :
	    px_lib_do_poke(dip, rdip, in_args));
}


/*ARGSUSED*/
static int
px_lib_do_peek(dev_info_t *dip, peekpoke_ctlops_t *in_args)
{
	px_t *px_p = DIP_TO_STATE(dip);
	px_pec_t *pec_p = px_p->px_pec_p;
	int err = DDI_SUCCESS;
	on_trap_data_t otd;

	mutex_enter(&pec_p->pec_pokefault_mutex);
	if (px_fm_enter(px_p) != DDI_SUCCESS)
		return (DDI_FAILURE);
	pec_p->pec_safeacc_type = DDI_FM_ERR_PEEK;
	px_fm_exit(px_p);

	if (!on_trap(&otd, OT_DATA_ACCESS)) {
		uintptr_t tramp = otd.ot_trampoline;

		otd.ot_trampoline = (uintptr_t)&peek_fault;
		err = do_peek(in_args->size, (void *)in_args->dev_addr,
		    (void *)in_args->host_addr);
		otd.ot_trampoline = tramp;
	} else
		err = DDI_FAILURE;

	no_trap();
	pec_p->pec_safeacc_type = DDI_FM_ERR_UNEXPECTED;
	mutex_exit(&pec_p->pec_pokefault_mutex);

#ifdef  DEBUG
	if (err == DDI_FAILURE)
		px_peekfault_cnt++;
#endif
	return (err);
}


static int
px_lib_do_caut_get(dev_info_t *dip, peekpoke_ctlops_t *cautacc_ctlops_arg)
{
	size_t size = cautacc_ctlops_arg->size;
	uintptr_t dev_addr = cautacc_ctlops_arg->dev_addr;
	uintptr_t host_addr = cautacc_ctlops_arg->host_addr;
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)cautacc_ctlops_arg->handle;
	size_t repcount = cautacc_ctlops_arg->repcount;
	uint_t flags = cautacc_ctlops_arg->flags;

	px_t *px_p = DIP_TO_STATE(dip);
	px_pec_t *pec_p = px_p->px_pec_p;
	int err = DDI_SUCCESS;

	/*
	 * Note that i_ndi_busop_access_enter ends up grabbing the pokefault
	 * mutex.
	 */
	i_ndi_busop_access_enter(hp->ahi_common.ah_dip, (ddi_acc_handle_t)hp);

	pec_p->pec_ontrap_data = (on_trap_data_t *)hp->ahi_err->err_ontrap;
	pec_p->pec_safeacc_type = DDI_FM_ERR_EXPECTED;
	hp->ahi_err->err_expected = DDI_FM_ERR_EXPECTED;

	if (repcount == 1) {
		if (!i_ddi_ontrap((ddi_acc_handle_t)hp)) {
			i_ddi_caut_get(size, (void *)dev_addr,
			    (void *)host_addr);
		} else {
			int i;
			uint8_t *ff_addr = (uint8_t *)host_addr;
			for (i = 0; i < size; i++)
				*ff_addr++ = 0xff;

			err = DDI_FAILURE;
#ifdef  DEBUG
			px_peekfault_cnt++;
#endif
		}
	} else {
		if (!i_ddi_ontrap((ddi_acc_handle_t)hp)) {
			for (; repcount; repcount--) {
				i_ddi_caut_get(size, (void *)dev_addr,
				    (void *)host_addr);

				host_addr += size;

				if (flags == DDI_DEV_AUTOINCR)
					dev_addr += size;
			}
		} else {
			err = DDI_FAILURE;
#ifdef  DEBUG
			px_peekfault_cnt++;
#endif
		}
	}

	i_ddi_notrap((ddi_acc_handle_t)hp);
	pec_p->pec_ontrap_data = NULL;
	pec_p->pec_safeacc_type = DDI_FM_ERR_UNEXPECTED;
	i_ndi_busop_access_exit(hp->ahi_common.ah_dip, (ddi_acc_handle_t)hp);
	hp->ahi_err->err_expected = DDI_FM_ERR_UNEXPECTED;

	return (err);
}

/*ARGSUSED*/
int
px_lib_ctlops_peek(dev_info_t *dip, dev_info_t *rdip,
    peekpoke_ctlops_t *in_args, void *result)
{
	result = (void *)in_args->host_addr;
	return (in_args->handle ? px_lib_do_caut_get(dip, in_args) :
	    px_lib_do_peek(dip, in_args));
}

/*
 * implements PPM interface
 */
int
px_lib_pmctl(int cmd, px_t *px_p)
{
	ASSERT((cmd & ~PPMREQ_MASK) == PPMREQ);
	switch (cmd) {
	case PPMREQ_PRE_PWR_OFF:
		/*
		 * Currently there is no device power management for
		 * the root complex (fire). When there is we need to make
		 * sure that it is at full power before trying to send the
		 * PME_Turn_Off message.
		 */
		DBG(DBG_PWR, px_p->px_dip,
		    "ioctl: request to send PME_Turn_Off\n");
		return (px_goto_l23ready(px_p));

	case PPMREQ_PRE_PWR_ON:
		DBG(DBG_PWR, px_p->px_dip, "ioctl: PRE_PWR_ON request\n");
		return (px_pre_pwron_check(px_p));

	case PPMREQ_POST_PWR_ON:
		DBG(DBG_PWR, px_p->px_dip, "ioctl: POST_PWR_ON request\n");
		return (px_goto_l0(px_p));

	default:
		return (DDI_FAILURE);
	}
}

/*
 * sends PME_Turn_Off message to put the link in L2/L3 ready state.
 * called by px_ioctl.
 * returns DDI_SUCCESS or DDI_FAILURE
 * 1. Wait for link to be in L1 state (link status reg)
 * 2. write to PME_Turn_off reg to boradcast
 * 3. set timeout
 * 4. If timeout, return failure.
 * 5. If PM_TO_Ack, wait till link is in L2/L3 ready
 */
static int
px_goto_l23ready(px_t *px_p)
{
	pcie_pwr_t	*pwr_p;
	pxu_t		*pxu_p = (pxu_t *)px_p->px_plat_p;
	caddr_t	csr_base = (caddr_t)pxu_p->px_address[PX_REG_CSR];
	int		ret = DDI_SUCCESS;
	clock_t		end, timeleft;
	int		mutex_held = 1;

	/* If no PM info, return failure */
	if (!PCIE_PMINFO(px_p->px_dip) ||
	    !(pwr_p = PCIE_NEXUS_PMINFO(px_p->px_dip)))
		return (DDI_FAILURE);

	mutex_enter(&pwr_p->pwr_lock);
	mutex_enter(&px_p->px_l23ready_lock);
	/* Clear the PME_To_ACK receieved flag */
	px_p->px_pm_flags &= ~PX_PMETOACK_RECVD;
	/*
	 * When P25 is the downstream device, after receiving
	 * PME_To_ACK, fire will go to Detect state, which causes
	 * the link down event. Inform FMA that this is expected.
	 * In case of all other cards complaint with the pci express
	 * spec, this will happen when the power is re-applied. FMA
	 * code will clear this flag after one instance of LDN. Since
	 * there will not be a LDN event for the spec compliant cards,
	 * we need to clear the flag after receiving PME_To_ACK.
	 */
	px_p->px_pm_flags |= PX_LDN_EXPECTED;
	if (px_send_pme_turnoff(csr_base) != DDI_SUCCESS) {
		ret = DDI_FAILURE;
		goto l23ready_done;
	}
	px_p->px_pm_flags |= PX_PME_TURNOFF_PENDING;

	end = ddi_get_lbolt() + drv_usectohz(px_pme_to_ack_timeout);
	while (!(px_p->px_pm_flags & PX_PMETOACK_RECVD)) {
		timeleft = cv_timedwait(&px_p->px_l23ready_cv,
		    &px_p->px_l23ready_lock, end);
		/*
		 * if cv_timedwait returns -1, it is either
		 * 1) timed out or
		 * 2) there was a pre-mature wakeup but by the time
		 * cv_timedwait is called again end < lbolt i.e.
		 * end is in the past.
		 * 3) By the time we make first cv_timedwait call,
		 * end < lbolt is true.
		 */
		if (timeleft == -1)
			break;
	}
	if (!(px_p->px_pm_flags & PX_PMETOACK_RECVD)) {
		/*
		 * Either timedout or interrupt didn't get a
		 * chance to grab the mutex and set the flag.
		 * release the mutex and delay for sometime.
		 * This will 1) give a chance for interrupt to
		 * set the flag 2) creates a delay between two
		 * consequetive requests.
		 */
		mutex_exit(&px_p->px_l23ready_lock);
		delay(drv_usectohz(50 * PX_MSEC_TO_USEC));
		mutex_held = 0;
		if (!(px_p->px_pm_flags & PX_PMETOACK_RECVD)) {
			ret = DDI_FAILURE;
			DBG(DBG_PWR, px_p->px_dip, " Timed out while waiting"
			    " for PME_TO_ACK\n");
		}
	}
	px_p->px_pm_flags &=
	    ~(PX_PME_TURNOFF_PENDING | PX_PMETOACK_RECVD | PX_LDN_EXPECTED);

l23ready_done:
	if (mutex_held)
		mutex_exit(&px_p->px_l23ready_lock);
	/*
	 * Wait till link is in L1 idle, if sending PME_Turn_Off
	 * was succesful.
	 */
	if (ret == DDI_SUCCESS) {
		if (px_link_wait4l1idle(csr_base) != DDI_SUCCESS) {
			DBG(DBG_PWR, px_p->px_dip, " Link is not at L1"
			    " even though we received PME_To_ACK.\n");
			/*
			 * Workaround for hardware bug with P25.
			 * Due to a hardware bug with P25, link state
			 * will be Detect state rather than L1 after
			 * link is transitioned to L23Ready state. Since
			 * we don't know whether link is L23ready state
			 * without Fire's state being L1_idle, we delay
			 * here just to make sure that we wait till link
			 * is transitioned to L23Ready state.
			 */
			delay(drv_usectohz(100 * PX_MSEC_TO_USEC));
		}
		pwr_p->pwr_link_lvl = PM_LEVEL_L3;

	}
	mutex_exit(&pwr_p->pwr_lock);
	return (ret);
}

/*
 * Message interrupt handler intended to be shared for both
 * PME and PME_TO_ACK msg handling, currently only handles
 * PME_To_ACK message.
 */
uint_t
px_pmeq_intr(caddr_t arg)
{
	px_t	*px_p = (px_t *)arg;

	DBG(DBG_PWR, px_p->px_dip, " PME_To_ACK received \n");
	mutex_enter(&px_p->px_l23ready_lock);
	cv_broadcast(&px_p->px_l23ready_cv);
	if (px_p->px_pm_flags & PX_PME_TURNOFF_PENDING) {
		px_p->px_pm_flags |= PX_PMETOACK_RECVD;
	} else {
		/*
		 * This maybe the second ack received. If so then,
		 * we should be receiving it during wait4L1 stage.
		 */
		px_p->px_pmetoack_ignored++;
	}
	mutex_exit(&px_p->px_l23ready_lock);
	return (DDI_INTR_CLAIMED);
}

static int
px_pre_pwron_check(px_t *px_p)
{
	pcie_pwr_t	*pwr_p;

	/* If no PM info, return failure */
	if (!PCIE_PMINFO(px_p->px_dip) ||
	    !(pwr_p = PCIE_NEXUS_PMINFO(px_p->px_dip)))
		return (DDI_FAILURE);

	/*
	 * For the spec compliant downstream cards link down
	 * is expected when the device is powered on.
	 */
	px_p->px_pm_flags |= PX_LDN_EXPECTED;
	return (pwr_p->pwr_link_lvl == PM_LEVEL_L3 ? DDI_SUCCESS : DDI_FAILURE);
}

static int
px_goto_l0(px_t *px_p)
{
	pcie_pwr_t	*pwr_p;
	pxu_t		*pxu_p = (pxu_t *)px_p->px_plat_p;
	caddr_t csr_base = (caddr_t)pxu_p->px_address[PX_REG_CSR];
	int		ret = DDI_SUCCESS;
	uint64_t	time_spent = 0;

	/* If no PM info, return failure */
	if (!PCIE_PMINFO(px_p->px_dip) ||
	    !(pwr_p = PCIE_NEXUS_PMINFO(px_p->px_dip)))
		return (DDI_FAILURE);

	mutex_enter(&pwr_p->pwr_lock);
	/*
	 * The following link retrain activity will cause LDN and LUP event.
	 * Receiving LDN prior to receiving LUP is expected, not an error in
	 * this case.  Receiving LUP indicates link is fully up to support
	 * powering up down stream device, and of course any further LDN and
	 * LUP outside this context will be error.
	 */
	px_p->px_lup_pending = 1;
	if (px_link_retrain(csr_base) != DDI_SUCCESS) {
		ret = DDI_FAILURE;
		goto l0_done;
	}

	/* LUP event takes the order of 15ms amount of time to occur */
	for (; px_p->px_lup_pending && (time_spent < px_lup_poll_to);
	    time_spent += px_lup_poll_interval)
		drv_usecwait(px_lup_poll_interval);
	if (px_p->px_lup_pending)
		ret = DDI_FAILURE;
l0_done:
	px_enable_detect_quiet(csr_base);
	if (ret == DDI_SUCCESS)
		pwr_p->pwr_link_lvl = PM_LEVEL_L0;
	mutex_exit(&pwr_p->pwr_lock);
	return (ret);
}

/*
 * Extract the drivers binding name to identify which chip we're binding to.
 * Whenever a new bus bridge is created, the driver alias entry should be
 * added here to identify the device if needed.  If a device isn't added,
 * the identity defaults to PX_CHIP_UNIDENTIFIED.
 */
static uint32_t
px_identity_init(px_t *px_p)
{
	dev_info_t	*dip = px_p->px_dip;
	char		*name = ddi_binding_name(dip);
	uint32_t	revision = 0;

	revision = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "module-revision#", 0);

	/* Check for Fire driver binding name */
	if (strcmp(name, "pciex108e,80f0") == 0) {
		DBG(DBG_ATTACH, dip, "px_identity_init: %s%d: "
		    "(FIRE), module-revision %d\n", NAMEINST(dip),
		    revision);

		return ((revision >= FIRE_MOD_REV_20) ?
		    PX_CHIP_FIRE : PX_CHIP_UNIDENTIFIED);
	}

	/* Check for Oberon driver binding name */
	if (strcmp(name, "pciex108e,80f8") == 0) {
		DBG(DBG_ATTACH, dip, "px_identity_init: %s%d: "
		    "(OBERON), module-revision %d\n", NAMEINST(dip),
		    revision);

		return (PX_CHIP_OBERON);
	}

	DBG(DBG_ATTACH, dip, "%s%d: Unknown PCI Express Host bridge %s %x\n",
	    ddi_driver_name(dip), ddi_get_instance(dip), name, revision);

	return (PX_CHIP_UNIDENTIFIED);
}

int
px_err_add_intr(px_fault_t *px_fault_p)
{
	dev_info_t	*dip = px_fault_p->px_fh_dip;
	px_t		*px_p = DIP_TO_STATE(dip);

	VERIFY(add_ivintr(px_fault_p->px_fh_sysino, PX_ERR_PIL,
	    (intrfunc)px_fault_p->px_err_func, (caddr_t)px_fault_p,
	    NULL, NULL) == 0);

	px_ib_intr_enable(px_p, intr_dist_cpuid(), px_fault_p->px_intr_ino);

	return (DDI_SUCCESS);
}

void
px_err_rem_intr(px_fault_t *px_fault_p)
{
	dev_info_t	*dip = px_fault_p->px_fh_dip;
	px_t		*px_p = DIP_TO_STATE(dip);

	px_ib_intr_disable(px_p->px_ib_p, px_fault_p->px_intr_ino,
	    IB_INTR_WAIT);

	VERIFY(rem_ivintr(px_fault_p->px_fh_sysino, PX_ERR_PIL) == 0);
}

/*
 * px_cb_intr_redist() - sun4u only, CB interrupt redistribution
 */
void
px_cb_intr_redist(void *arg)
{
	px_cb_t		*cb_p = (px_cb_t *)arg;
	px_cb_list_t	*pxl;
	px_t		*pxp = NULL;
	px_fault_t	*f_p = NULL;
	uint32_t	new_cpuid;
	intr_valid_state_t	enabled = 0;

	mutex_enter(&cb_p->cb_mutex);

	pxl = cb_p->pxl;
	if (!pxl)
		goto cb_done;

	pxp = pxl->pxp;
	f_p = &pxp->px_cb_fault;
	for (; pxl && (f_p->px_fh_sysino != cb_p->sysino); ) {
		pxl = pxl->next;
		pxp = pxl->pxp;
		f_p = &pxp->px_cb_fault;
	}
	if (pxl == NULL)
		goto cb_done;

	new_cpuid =  intr_dist_cpuid();
	if (new_cpuid == cb_p->cpuid)
		goto cb_done;

	if ((px_lib_intr_getvalid(pxp->px_dip, f_p->px_fh_sysino, &enabled)
	    != DDI_SUCCESS) || !enabled) {
		DBG(DBG_IB, pxp->px_dip, "px_cb_intr_redist: CB not enabled, "
		    "sysino(0x%x)\n", f_p->px_fh_sysino);
		goto cb_done;
	}

	PX_INTR_DISABLE(pxp->px_dip, f_p->px_fh_sysino);

	cb_p->cpuid = new_cpuid;
	cb_p->sysino = f_p->px_fh_sysino;
	PX_INTR_ENABLE(pxp->px_dip, cb_p->sysino, cb_p->cpuid);

cb_done:
	mutex_exit(&cb_p->cb_mutex);
}

/*
 * px_cb_add_intr() - Called from attach(9E) to create CB if not yet
 * created, to add CB interrupt vector always, but enable only once.
 */
int
px_cb_add_intr(px_fault_t *fault_p)
{
	px_t		*px_p = DIP_TO_STATE(fault_p->px_fh_dip);
	pxu_t		*pxu_p = (pxu_t *)px_p->px_plat_p;
	px_cb_t		*cb_p = (px_cb_t *)px_get_cb(fault_p->px_fh_dip);
	px_cb_list_t	*pxl, *pxl_new;
	boolean_t	is_proxy = B_FALSE;

	/* create cb */
	if (cb_p == NULL) {
		cb_p = kmem_zalloc(sizeof (px_cb_t), KM_SLEEP);

		mutex_init(&cb_p->cb_mutex, NULL, MUTEX_DRIVER,
		    (void *) ipltospl(FM_ERR_PIL));

		cb_p->px_cb_func = px_cb_intr;
		pxu_p->px_cb_p = cb_p;
		px_set_cb(fault_p->px_fh_dip, (uint64_t)cb_p);

		/* px_lib_dev_init allows only FIRE and OBERON */
		px_err_reg_enable(
		    (pxu_p->chip_type == PX_CHIP_FIRE) ?
		    PX_ERR_JBC : PX_ERR_UBC,
		    pxu_p->px_address[PX_REG_XBC]);
	} else
		pxu_p->px_cb_p = cb_p;

	/* register cb interrupt */
	VERIFY(add_ivintr(fault_p->px_fh_sysino, PX_ERR_PIL,
	    (intrfunc)cb_p->px_cb_func, (caddr_t)cb_p, NULL, NULL) == 0);


	/* update cb list */
	mutex_enter(&cb_p->cb_mutex);
	if (cb_p->pxl == NULL) {
		is_proxy = B_TRUE;
		pxl = kmem_zalloc(sizeof (px_cb_list_t), KM_SLEEP);
		pxl->pxp = px_p;
		cb_p->pxl = pxl;
		cb_p->sysino = fault_p->px_fh_sysino;
		cb_p->cpuid = intr_dist_cpuid();
	} else {
		/*
		 * Find the last pxl or
		 * stop short at encountering a redundent entry, or
		 * both.
		 */
		pxl = cb_p->pxl;
		for (; !(pxl->pxp == px_p) && pxl->next; pxl = pxl->next) {};
		ASSERT(pxl->pxp != px_p);

		/* add to linked list */
		pxl_new = kmem_zalloc(sizeof (px_cb_list_t), KM_SLEEP);
		pxl_new->pxp = px_p;
		pxl->next = pxl_new;
	}
	cb_p->attachcnt++;
	mutex_exit(&cb_p->cb_mutex);

	if (is_proxy) {
		/* add to interrupt redistribution list */
		intr_dist_add(px_cb_intr_redist, cb_p);

		/* enable cb hw interrupt */
		px_ib_intr_enable(px_p, cb_p->cpuid, fault_p->px_intr_ino);
	}

	return (DDI_SUCCESS);
}

/*
 * px_cb_rem_intr() - Called from detach(9E) to remove its CB
 * interrupt vector, to shift proxy to the next available px,
 * or disable CB interrupt when itself is the last.
 */
void
px_cb_rem_intr(px_fault_t *fault_p)
{
	px_t		*px_p = DIP_TO_STATE(fault_p->px_fh_dip), *pxp;
	pxu_t		*pxu_p = (pxu_t *)px_p->px_plat_p;
	px_cb_t		*cb_p = PX2CB(px_p);
	px_cb_list_t	*pxl, *prev;
	px_fault_t	*f_p;

	ASSERT(cb_p->pxl);

	/* find and remove this px, and update cb list */
	mutex_enter(&cb_p->cb_mutex);

	pxl = cb_p->pxl;
	if (pxl->pxp == px_p) {
		cb_p->pxl = pxl->next;
	} else {
		prev = pxl;
		pxl = pxl->next;
		for (; pxl && (pxl->pxp != px_p); prev = pxl, pxl = pxl->next) {
		};
		if (!pxl) {
			cmn_err(CE_WARN, "px_cb_rem_intr: can't find px_p 0x%p "
			    "in registered CB list.", (void *)px_p);
			mutex_exit(&cb_p->cb_mutex);
			return;
		}
		prev->next = pxl->next;
	}
	pxu_p->px_cb_p = NULL;
	cb_p->attachcnt--;
	kmem_free(pxl, sizeof (px_cb_list_t));
	mutex_exit(&cb_p->cb_mutex);

	/* disable cb hw interrupt */
	if (fault_p->px_fh_sysino == cb_p->sysino)
		px_ib_intr_disable(px_p->px_ib_p, fault_p->px_intr_ino,
		    IB_INTR_WAIT);

	/* if last px, remove from interrupt redistribution list */
	if (cb_p->pxl == NULL)
		intr_dist_rem(px_cb_intr_redist, cb_p);

	/* de-register interrupt */
	VERIFY(rem_ivintr(fault_p->px_fh_sysino, PX_ERR_PIL) == 0);

	/* if not last px, assign next px to manage cb */
	mutex_enter(&cb_p->cb_mutex);
	if (cb_p->pxl) {
		if (fault_p->px_fh_sysino == cb_p->sysino) {
			pxp = cb_p->pxl->pxp;
			f_p = &pxp->px_cb_fault;
			cb_p->sysino = f_p->px_fh_sysino;

			PX_INTR_ENABLE(pxp->px_dip, cb_p->sysino, cb_p->cpuid);
			(void) px_lib_intr_setstate(pxp->px_dip, cb_p->sysino,
			    INTR_IDLE_STATE);
		}
		mutex_exit(&cb_p->cb_mutex);
		return;
	}

	/* clean up after the last px */
	mutex_exit(&cb_p->cb_mutex);

	/* px_lib_dev_init allows only FIRE and OBERON */
	px_err_reg_disable(
	    (pxu_p->chip_type == PX_CHIP_FIRE) ? PX_ERR_JBC : PX_ERR_UBC,
	    pxu_p->px_address[PX_REG_XBC]);

	mutex_destroy(&cb_p->cb_mutex);
	px_set_cb(fault_p->px_fh_dip, 0ull);
	kmem_free(cb_p, sizeof (px_cb_t));
}

/*
 * px_cb_intr() - sun4u only,  CB interrupt dispatcher
 */
uint_t
px_cb_intr(caddr_t arg)
{
	px_cb_t		*cb_p = (px_cb_t *)arg;
	px_t		*pxp;
	px_fault_t	*f_p;
	int		ret;

	mutex_enter(&cb_p->cb_mutex);

	if (!cb_p->pxl) {
		mutex_exit(&cb_p->cb_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	pxp = cb_p->pxl->pxp;
	f_p = &pxp->px_cb_fault;

	ret = f_p->px_err_func((caddr_t)f_p);

	mutex_exit(&cb_p->cb_mutex);
	return (ret);
}

#ifdef	FMA
void
px_fill_rc_status(px_fault_t *px_fault_p, pciex_rc_error_regs_t *rc_status)
{
	/* populate the rc_status by reading the registers - TBD */
}
#endif /* FMA */

/*
 * Unprotected raw reads/writes of fabric device's config space.
 * Only used for temporary PCI-E Fabric Error Handling.
 */
uint32_t
px_fab_get(px_t *px_p, pcie_req_id_t bdf, uint16_t offset)
{
	px_ranges_t	*rp = px_p->px_ranges_p;
	uint64_t	range_prop, base_addr;
	int		bank = PCI_REG_ADDR_G(PCI_ADDR_CONFIG);
	uint32_t	val;

	/* Get Fire's Physical Base Address */
	range_prop = px_get_range_prop(px_p, rp, bank);

	/* Get config space first. */
	base_addr = range_prop + PX_BDF_TO_CFGADDR(bdf, offset);

	val = ldphysio(base_addr);

	return (LE_32(val));
}

void
px_fab_set(px_t *px_p, pcie_req_id_t bdf, uint16_t offset,
    uint32_t val) {
	px_ranges_t	*rp = px_p->px_ranges_p;
	uint64_t	range_prop, base_addr;
	int		bank = PCI_REG_ADDR_G(PCI_ADDR_CONFIG);

	/* Get Fire's Physical Base Address */
	range_prop = px_get_range_prop(px_p, rp, bank);

	/* Get config space first. */
	base_addr = range_prop + PX_BDF_TO_CFGADDR(bdf, offset);

	stphysio(base_addr, LE_32(val));
}

/*
 * cpr callback
 *
 * disable fabric error msg interrupt prior to suspending
 * all device drivers; re-enable fabric error msg interrupt
 * after all devices are resumed.
 */
static boolean_t
px_cpr_callb(void *arg, int code)
{
	px_t		*px_p = (px_t *)arg;
	px_ib_t		*ib_p = px_p->px_ib_p;
	px_pec_t	*pec_p = px_p->px_pec_p;
	pxu_t		*pxu_p = (pxu_t *)px_p->px_plat_p;
	caddr_t		csr_base;
	devino_t	ce_ino, nf_ino, f_ino;
	px_ino_t	*ce_ino_p, *nf_ino_p, *f_ino_p;
	uint64_t	imu_log_enable, imu_intr_enable;
	uint64_t	imu_log_mask, imu_intr_mask;

	ce_ino = px_msiqid_to_devino(px_p, pec_p->pec_corr_msg_msiq_id);
	nf_ino = px_msiqid_to_devino(px_p, pec_p->pec_non_fatal_msg_msiq_id);
	f_ino = px_msiqid_to_devino(px_p, pec_p->pec_fatal_msg_msiq_id);
	csr_base = (caddr_t)pxu_p->px_address[PX_REG_CSR];

	imu_log_enable = CSR_XR(csr_base, IMU_ERROR_LOG_ENABLE);
	imu_intr_enable = CSR_XR(csr_base, IMU_INTERRUPT_ENABLE);

	imu_log_mask = BITMASK(IMU_ERROR_LOG_ENABLE_FATAL_MES_NOT_EN_LOG_EN) |
	    BITMASK(IMU_ERROR_LOG_ENABLE_NONFATAL_MES_NOT_EN_LOG_EN) |
	    BITMASK(IMU_ERROR_LOG_ENABLE_COR_MES_NOT_EN_LOG_EN);

	imu_intr_mask =
	    BITMASK(IMU_INTERRUPT_ENABLE_FATAL_MES_NOT_EN_S_INT_EN) |
	    BITMASK(IMU_INTERRUPT_ENABLE_NONFATAL_MES_NOT_EN_S_INT_EN) |
	    BITMASK(IMU_INTERRUPT_ENABLE_COR_MES_NOT_EN_S_INT_EN) |
	    BITMASK(IMU_INTERRUPT_ENABLE_FATAL_MES_NOT_EN_P_INT_EN) |
	    BITMASK(IMU_INTERRUPT_ENABLE_NONFATAL_MES_NOT_EN_P_INT_EN) |
	    BITMASK(IMU_INTERRUPT_ENABLE_COR_MES_NOT_EN_P_INT_EN);

	switch (code) {
	case CB_CODE_CPR_CHKPT:
		/* disable imu rbne on corr/nonfatal/fatal errors */
		CSR_XS(csr_base, IMU_ERROR_LOG_ENABLE,
		    imu_log_enable & (~imu_log_mask));

		CSR_XS(csr_base, IMU_INTERRUPT_ENABLE,
		    imu_intr_enable & (~imu_intr_mask));

		/* disable CORR intr mapping */
		px_ib_intr_disable(ib_p, ce_ino, IB_INTR_NOWAIT);

		/* disable NON FATAL intr mapping */
		px_ib_intr_disable(ib_p, nf_ino, IB_INTR_NOWAIT);

		/* disable FATAL intr mapping */
		px_ib_intr_disable(ib_p, f_ino, IB_INTR_NOWAIT);

		break;

	case CB_CODE_CPR_RESUME:
		pxu_p->cpr_flag = PX_NOT_CPR;
		mutex_enter(&ib_p->ib_ino_lst_mutex);

		ce_ino_p = px_ib_locate_ino(ib_p, ce_ino);
		nf_ino_p = px_ib_locate_ino(ib_p, nf_ino);
		f_ino_p = px_ib_locate_ino(ib_p, f_ino);

		/* enable CORR intr mapping */
		if (ce_ino_p)
			px_ib_intr_enable(px_p, ce_ino_p->ino_cpuid, ce_ino);
		else
			cmn_err(CE_WARN, "px_cpr_callb: RESUME unable to "
			    "reenable PCIe Correctable msg intr.\n");

		/* enable NON FATAL intr mapping */
		if (nf_ino_p)
			px_ib_intr_enable(px_p, nf_ino_p->ino_cpuid, nf_ino);
		else
			cmn_err(CE_WARN, "px_cpr_callb: RESUME unable to "
			    "reenable PCIe Non Fatal msg intr.\n");

		/* enable FATAL intr mapping */
		if (f_ino_p)
			px_ib_intr_enable(px_p, f_ino_p->ino_cpuid, f_ino);
		else
			cmn_err(CE_WARN, "px_cpr_callb: RESUME unable to "
			    "reenable PCIe Fatal msg intr.\n");

		mutex_exit(&ib_p->ib_ino_lst_mutex);

		/* enable corr/nonfatal/fatal not enable error */
		CSR_XS(csr_base, IMU_ERROR_LOG_ENABLE, (imu_log_enable |
		    (imu_log_mask & px_imu_log_mask)));
		CSR_XS(csr_base, IMU_INTERRUPT_ENABLE, (imu_intr_enable |
		    (imu_intr_mask & px_imu_intr_mask)));

		break;
	}

	return (B_TRUE);
}

uint64_t
px_get_rng_parent_hi_mask(px_t *px_p)
{
	pxu_t *pxu_p = (pxu_t *)px_p->px_plat_p;
	uint64_t mask;

	switch (PX_CHIP_TYPE(pxu_p)) {
	case PX_CHIP_OBERON:
		mask = OBERON_RANGE_PROP_MASK;
		break;
	case PX_CHIP_FIRE:
		mask = PX_RANGE_PROP_MASK;
		break;
	default:
		mask = PX_RANGE_PROP_MASK;
	}

	return (mask);
}

/*
 * fetch chip's range propery's value
 */
uint64_t
px_get_range_prop(px_t *px_p, px_ranges_t *rp, int bank)
{
	uint64_t mask, range_prop;

	mask = px_get_rng_parent_hi_mask(px_p);
	range_prop = (((uint64_t)(rp[bank].parent_high & mask)) << 32) |
	    rp[bank].parent_low;

	return (range_prop);
}

/*
 * add cpr callback
 */
void
px_cpr_add_callb(px_t *px_p)
{
	px_p->px_cprcb_id = callb_add(px_cpr_callb, (void *)px_p,
	    CB_CL_CPR_POST_USER, "px_cpr");
}

/*
 * remove cpr callback
 */
void
px_cpr_rem_callb(px_t *px_p)
{
	(void) callb_delete(px_p->px_cprcb_id);
}

/*ARGSUSED*/
static uint_t
px_hp_intr(caddr_t arg1, caddr_t arg2)
{
	px_t	*px_p = (px_t *)arg1;
	pxu_t 	*pxu_p = (pxu_t *)px_p->px_plat_p;
	int	rval;

	rval = pciehpc_intr(px_p->px_dip);

#ifdef  DEBUG
	if (rval == DDI_INTR_UNCLAIMED)
		cmn_err(CE_WARN, "%s%d: UNCLAIMED intr\n",
		    ddi_driver_name(px_p->px_dip),
		    ddi_get_instance(px_p->px_dip));
#endif

	/* Set the interrupt state to idle */
	if (px_lib_intr_setstate(px_p->px_dip,
	    pxu_p->hp_sysino, INTR_IDLE_STATE) != DDI_SUCCESS)
		return (DDI_INTR_UNCLAIMED);

	return (rval);
}

int
px_lib_hotplug_init(dev_info_t *dip, void *arg)
{
	px_t	*px_p = DIP_TO_STATE(dip);
	pxu_t 	*pxu_p = (pxu_t *)px_p->px_plat_p;
	uint64_t ret;

	if ((ret = hvio_hotplug_init(dip, arg)) == DDI_SUCCESS) {
		if (px_lib_intr_devino_to_sysino(px_p->px_dip,
		    px_p->px_inos[PX_INTR_HOTPLUG], &pxu_p->hp_sysino) !=
		    DDI_SUCCESS) {
#ifdef	DEBUG
			cmn_err(CE_WARN, "%s%d: devino_to_sysino fails\n",
			    ddi_driver_name(px_p->px_dip),
			    ddi_get_instance(px_p->px_dip));
#endif
			return (DDI_FAILURE);
		}

		VERIFY(add_ivintr(pxu_p->hp_sysino, PX_PCIEHP_PIL,
		    (intrfunc)px_hp_intr, (caddr_t)px_p, NULL, NULL) == 0);

		px_ib_intr_enable(px_p, intr_dist_cpuid(),
		    px_p->px_inos[PX_INTR_HOTPLUG]);
	}

	return (ret);
}

void
px_lib_hotplug_uninit(dev_info_t *dip)
{
	if (hvio_hotplug_uninit(dip) == DDI_SUCCESS) {
		px_t	*px_p = DIP_TO_STATE(dip);
		pxu_t 	*pxu_p = (pxu_t *)px_p->px_plat_p;

		px_ib_intr_disable(px_p->px_ib_p,
		    px_p->px_inos[PX_INTR_HOTPLUG], IB_INTR_WAIT);

		VERIFY(rem_ivintr(pxu_p->hp_sysino, PX_PCIEHP_PIL) == 0);
	}
}

/*
 * px_hp_intr_redist() - sun4u only, HP interrupt redistribution
 */
void
px_hp_intr_redist(px_t *px_p)
{
	if (px_p && (px_p->px_dev_caps & PX_HOTPLUG_CAPABLE)) {
		px_ib_intr_dist_en(px_p->px_dip, intr_dist_cpuid(),
		    px_p->px_inos[PX_INTR_HOTPLUG], B_FALSE);
	}
}

boolean_t
px_lib_is_in_drain_state(px_t *px_p)
{
	pxu_t 	*pxu_p = (pxu_t *)px_p->px_plat_p;
	caddr_t csr_base = (caddr_t)pxu_p->px_address[PX_REG_CSR];
	uint64_t drain_status;

	if (PX_CHIP_TYPE(pxu_p) == PX_CHIP_OBERON) {
		drain_status = CSR_BR(csr_base, DRAIN_CONTROL_STATUS, DRAIN);
	} else {
		drain_status = CSR_BR(csr_base, TLU_STATUS, DRAIN);
	}

	return (drain_status);
}

pcie_req_id_t
px_lib_get_bdf(px_t *px_p)
{
	pxu_t 	*pxu_p = (pxu_t *)px_p->px_plat_p;
	caddr_t csr_base = (caddr_t)pxu_p->px_address[PX_REG_CSR];
	pcie_req_id_t bdf;

	bdf = CSR_BR(csr_base, DMC_PCI_EXPRESS_CONFIGURATION, REQ_ID);

	return (bdf);
}
