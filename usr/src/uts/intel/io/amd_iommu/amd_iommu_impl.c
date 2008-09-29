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

#include <sys/sunddi.h>
#include <sys/iommulib.h>
#include <sys/amd_iommu.h>
#include <sys/pci_cap.h>

#include "amd_iommu_impl.h"

extern vmem_t *heap_arena;

static int amd_iommu_fini(amd_iommu_t *iommu);
static void amd_iommu_teardown_interrupts(amd_iommu_t *iommu);
static void amd_iommu_stop(amd_iommu_t *iommu);

static int amd_iommu_probe(dev_info_t *rdip);
static int amd_iommu_allochdl(iommulib_handle_t handle,
    dev_info_t *dip, dev_info_t *rdip, ddi_dma_attr_t *attr,
    int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *dma_handlep);
static int amd_iommu_freehdl(iommulib_handle_t handle,
    dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t dma_handle);
static int amd_iommu_bindhdl(iommulib_handle_t handle, dev_info_t *dip,
    dev_info_t *rdip, ddi_dma_handle_t dma_handle,
    struct ddi_dma_req *dmareq, ddi_dma_cookie_t *cookiep,
    uint_t *ccountp);
static int amd_iommu_unbindhdl(iommulib_handle_t handle,
    dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t dma_handle);
static int amd_iommu_sync(iommulib_handle_t handle, dev_info_t *dip,
    dev_info_t *rdip, ddi_dma_handle_t dma_handle, off_t off,
    size_t len, uint_t cache_flags);
static int amd_iommu_win(iommulib_handle_t handle, dev_info_t *dip,
    dev_info_t *rdip, ddi_dma_handle_t dma_handle, uint_t win,
    off_t *offp, size_t *lenp, ddi_dma_cookie_t *cookiep,
    uint_t *ccountp);
static int amd_iommu_map(iommulib_handle_t handle, dev_info_t *dip,
    dev_info_t *rdip, struct ddi_dma_req *dmareq,
    ddi_dma_handle_t *dma_handle);
static int amd_iommu_mctl(iommulib_handle_t handle, dev_info_t *dip,
    dev_info_t *rdip, ddi_dma_handle_t dma_handle,
    enum ddi_dma_ctlops request, off_t *offp, size_t *lenp,
    caddr_t *objpp, uint_t cache_flags);

static int unmap_current_window(iommulib_handle_t handle, dev_info_t *rdip,
    ddi_dma_handle_t dma_handle, int ncookies);

ddi_dma_attr_t amd_iommu_dma_attr = {
	DMA_ATTR_V0,
	0U,				/* dma_attr_addr_lo */
	0xffffffffffffffffULL,		/* dma_attr_addr_hi */
	0xffffffffU,			/* dma_attr_count_max */
	(uint64_t)4096,			/* dma_attr_align */
	1,				/* dma_attr_burstsizes */
	64,				/* dma_attr_minxfer */
	0xffffffffU,			/* dma_attr_maxxfer */
	0xffffffffU,			/* dma_attr_seg */
	1,				/* dma_attr_sgllen, variable */
	64,				/* dma_attr_granular */
	0				/* dma_attr_flags */
};

ddi_device_acc_attr_t amd_iommu_devacc = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

struct iommulib_ops amd_iommulib_ops = {
	IOMMU_OPS_VERSION,
	AMD_IOMMU,
	"AMD IOMMU Vers. 1",
	NULL,
	amd_iommu_probe,
	amd_iommu_allochdl,
	amd_iommu_freehdl,
	amd_iommu_bindhdl,
	amd_iommu_unbindhdl,
	amd_iommu_sync,
	amd_iommu_win,
	amd_iommu_map,
	amd_iommu_mctl
};

uint8_t amd_iommu_htatsresv;
uint8_t amd_iommu_vasize;
uint8_t amd_iommu_pasize;

amd_iommu_debug_t amd_iommu_debug;

static int
amd_iommu_register(amd_iommu_t *iommu)
{
	dev_info_t *dip = iommu->aiomt_dip;
	const char *driver = ddi_driver_name(dip);
	int instance = ddi_get_instance(dip);
	iommulib_ops_t *iommulib_ops;
	iommulib_handle_t handle;
	const char *f = "amd_iommu_register";

	iommulib_ops = kmem_zalloc(sizeof (iommulib_ops_t), KM_SLEEP);

	*iommulib_ops = amd_iommulib_ops;

	iommulib_ops->ilops_data = (void *)iommu;
	iommu->aiomt_iommulib_ops = iommulib_ops;

	if (iommulib_iommu_register(dip, iommulib_ops, &handle)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: Register with iommulib "
		    "failed idx=%d", f, driver, instance, iommu->aiomt_idx);
		kmem_free(iommulib_ops, sizeof (iommulib_ops_t));
		return (DDI_FAILURE);
	}

	iommu->aiomt_iommulib_handle = handle;

	return (DDI_SUCCESS);
}

static int
amd_iommu_unregister(amd_iommu_t *iommu)
{
	if (iommu->aiomt_iommulib_handle == NULL) {
		/* we never registered */
		return (DDI_SUCCESS);
	}

	if (iommulib_iommu_unregister(iommu->aiomt_iommulib_handle)
	    != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	kmem_free(iommu->aiomt_iommulib_ops, sizeof (iommulib_ops_t));
	iommu->aiomt_iommulib_ops = NULL;
	iommu->aiomt_iommulib_handle = NULL;

	return (DDI_SUCCESS);
}

static int
amd_iommu_start(amd_iommu_t *iommu)
{
	dev_info_t *dip = iommu->aiomt_dip;
	int instance = ddi_get_instance(dip);
	const char *driver = ddi_driver_name(dip);
	const char *f = "amd_iommu_start";

	/* Must be set prior to enabling command buffer */
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_ctrl_va),
	    AMD_IOMMU_COMWAITINT_ENABLE, 1);
	/* Must be set prior to enabling event logging */
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_ctrl_va),
	    AMD_IOMMU_EVENTINT_ENABLE, 1);

	/*
	 * If IOMMU contains a HT tunnel that supports address translation
	 * enable translation on the HT tunnel traffic
	 */
	if (AMD_IOMMU_REG_GET(iommu->aiomt_cap_hdr, AMD_IOMMU_CAP_HTTUN)) {
		AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_ctrl_va),
		    AMD_IOMMU_HT_TUN_ENABLE, 1);
	} else {
		AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_ctrl_va),
		    AMD_IOMMU_HT_TUN_ENABLE, 0);
	}

	/*
	 * The Device table entry bit 0 (V) controls whether the device
	 * table entry is valid for address translation and Device table
	 * entry bit 128 (IV) controls whether interrupt remapping is valid.
	 * By setting both to zero we are essentially doing pass-thru. Since
	 * this table is zeroed on allocation, essentially we will have
	 * pass-thru when IOMMU is enabled.
	 */

	/* Finally enable the IOMMU ... */
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_ctrl_va),
	    AMD_IOMMU_ENABLE, 0);

	/* The following must be enabled after the IOMMU is enabled */
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_ctrl_va),
	    AMD_IOMMU_CMDBUF_ENABLE, 1);
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_ctrl_va),
	    AMD_IOMMU_EVENTLOG_ENABLE, 1);

	cmn_err(CE_NOTE, "%s: %s%d: AMD IOMMU idx=%d. "
	    "Successfully started AMD IOMMU", f, driver, instance,
	    iommu->aiomt_idx);

	return (DDI_SUCCESS);
}

static void
amd_iommu_stop(amd_iommu_t *iommu)
{
	dev_info_t *dip = iommu->aiomt_dip;
	int instance = ddi_get_instance(dip);
	const char *driver = ddi_driver_name(dip);
	const char *f = "amd_iommu_stop";

	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_ctrl_va),
	    AMD_IOMMU_ENABLE, 0);
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_ctrl_va),
	    AMD_IOMMU_EVENTINT_ENABLE, 0);
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_ctrl_va),
	    AMD_IOMMU_COMWAITINT_ENABLE, 0);
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_ctrl_va),
	    AMD_IOMMU_EVENTLOG_ENABLE, 0);

	/*
	 * Disable translation on HT tunnel traffic
	 */
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_ctrl_va),
	    AMD_IOMMU_HT_TUN_ENABLE, 0);
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_ctrl_va),
	    AMD_IOMMU_CMDBUF_ENABLE, 0);

	cmn_err(CE_NOTE, "%s: %s%d: AMD IOMMYU idx=%d. "
	    "Successfully stopped AMD IOMMU", f, driver, instance,
	    iommu->aiomt_idx);
}

static int
amd_iommu_setup_tables_and_buffers(amd_iommu_t *iommu)
{
	dev_info_t *dip = iommu->aiomt_dip;
	int instance = ddi_get_instance(dip);
	const char *driver = ddi_driver_name(dip);
	uint32_t dma_bufsz;
	caddr_t addr;
	uint32_t sz;
	uint32_t p2sz;
	int err;
	const char *f = "amd_iommu_setup_tables_and_buffers";

	/*
	 * We will put the Device Table, Command Buffer and
	 * Event Log in contiguous memory. Allocate the maximum
	 * size allowed for such structures
	 * Device Table:  256b * 64K = 32B * 64K
	 * Command Buffer: 128b * 32K = 16B * 32K
	 * Event Log:  128b * 32K = 16B * 32K
	 */
	iommu->aiomt_devtbl_sz = (1<<AMD_IOMMU_DEVTBL_SZ) * AMD_IOMMU_DEVENT_SZ;
	iommu->aiomt_cmdbuf_sz = (1<<AMD_IOMMU_CMDBUF_SZ) * AMD_IOMMU_CMD_SZ;
	iommu->aiomt_eventlog_sz =
	    (1<<AMD_IOMMU_EVENTLOG_SZ) * AMD_IOMMU_EVENT_SZ;

	dma_bufsz = iommu->aiomt_devtbl_sz + iommu->aiomt_cmdbuf_sz
	    + iommu->aiomt_eventlog_sz;

	/*
	 * Alloc a DMA handle.
	 */
	err = ddi_dma_alloc_handle(dip, &amd_iommu_dma_attr,
	    DDI_DMA_SLEEP, NULL, &iommu->aiomt_dmahdl);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: Cannot alloc DMA handle for "
		    "AMD IOMMU tables and buffers", f, driver, instance);
		return (DDI_FAILURE);
	}

	/*
	 * Alloc memory for tables and buffers
	 */
	err = ddi_dma_mem_alloc(iommu->aiomt_dmahdl, dma_bufsz,
	    &amd_iommu_devacc, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
	    NULL, (caddr_t *)&iommu->aiomt_dma_bufva,
	    (size_t *)&iommu->aiomt_dma_mem_realsz, &iommu->aiomt_dma_mem_hdl);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: Cannot alloc memory for DMA "
		    "to AMD IOMMU tables and buffers", f, driver, instance);
		iommu->aiomt_dma_bufva = NULL;
		iommu->aiomt_dma_mem_realsz = 0;
		ddi_dma_free_handle(&iommu->aiomt_dmahdl);
		iommu->aiomt_dmahdl = NULL;
		return (DDI_FAILURE);
	}

	/*
	 * The VA must be 4K aligned and >= table size
	 */
	ASSERT(((uintptr_t)iommu->aiomt_dma_bufva &
	    AMD_IOMMU_TABLE_ALIGN) == 0);
	ASSERT(iommu->aiomt_dma_mem_realsz >= dma_bufsz);

	/*
	 * Now bind the handle
	 */
	err = ddi_dma_addr_bind_handle(iommu->aiomt_dmahdl, NULL,
	    iommu->aiomt_dma_bufva, iommu->aiomt_dma_mem_realsz,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
	    NULL, &iommu->aiomt_buf_dma_cookie, &iommu->aiomt_buf_dma_ncookie);
	if (err != DDI_DMA_MAPPED) {
		cmn_err(CE_WARN, "%s: %s%d: Cannot bind memory for DMA "
		    "to AMD IOMMU tables and buffers. bufrealsz=%p",
		    f, driver, instance,
		    (void *)(uintptr_t)iommu->aiomt_dma_mem_realsz);
		iommu->aiomt_buf_dma_cookie.dmac_laddress = 0;
		iommu->aiomt_buf_dma_cookie.dmac_size = 0;
		iommu->aiomt_buf_dma_cookie.dmac_type = 0;
		iommu->aiomt_buf_dma_ncookie = 0;
		ddi_dma_mem_free(&iommu->aiomt_dma_mem_hdl);
		iommu->aiomt_dma_mem_hdl = NULL;
		iommu->aiomt_dma_bufva = NULL;
		iommu->aiomt_dma_mem_realsz = 0;
		ddi_dma_free_handle(&iommu->aiomt_dmahdl);
		iommu->aiomt_dmahdl = NULL;
		return (DDI_FAILURE);
	}

	/*
	 * We assume the DMA engine on the IOMMU is capable of handling the
	 * whole table buffer in a single cookie. If not and multiple cookies
	 * are needed we fail.
	 */
	if (iommu->aiomt_buf_dma_ncookie != 1) {
		cmn_err(CE_WARN, "%s: %s%d: Cannot handle multiple "
		    "cookies for DMA to AMD IOMMU tables and buffers. "
		    "#cookies=%u", f, driver, instance,
		    iommu->aiomt_buf_dma_ncookie);
		(void) ddi_dma_unbind_handle(iommu->aiomt_dmahdl);
		iommu->aiomt_buf_dma_cookie.dmac_laddress = 0;
		iommu->aiomt_buf_dma_cookie.dmac_size = 0;
		iommu->aiomt_buf_dma_cookie.dmac_type = 0;
		iommu->aiomt_buf_dma_ncookie = 0;
		ddi_dma_mem_free(&iommu->aiomt_dma_mem_hdl);
		iommu->aiomt_dma_mem_hdl = NULL;
		iommu->aiomt_dma_bufva = NULL;
		iommu->aiomt_dma_mem_realsz = 0;
		ddi_dma_free_handle(&iommu->aiomt_dmahdl);
		iommu->aiomt_dmahdl = NULL;
		return (DDI_FAILURE);
	}

	/*
	 * The address in the cookie must be 4K aligned and >= table size
	 */
	ASSERT((iommu->aiomt_buf_dma_cookie.dmac_cookie_addr
	    & AMD_IOMMU_TABLE_ALIGN) == 0);
	ASSERT(iommu->aiomt_buf_dma_cookie.dmac_size
	    <= iommu->aiomt_dma_mem_realsz);
	ASSERT(iommu->aiomt_buf_dma_cookie.dmac_size >= dma_bufsz);

	/*
	 * Setup the device table pointers in the iommu struct as
	 * well as the IOMMU device table register
	 */
	iommu->aiomt_devtbl = iommu->aiomt_dma_bufva;
	bzero(iommu->aiomt_devtbl, iommu->aiomt_devtbl_sz);
	addr = (caddr_t)iommu->aiomt_buf_dma_cookie.dmac_cookie_addr;
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_devtbl_va),
	    AMD_IOMMU_DEVTABBASE, ((uint64_t)(uintptr_t)addr) >> 12);
	sz = (iommu->aiomt_devtbl_sz >> 12) - 1;
	ASSERT(sz <= ((1 << 9) - 1));
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_devtbl_va),
	    AMD_IOMMU_DEVTABSIZE, sz);

	/*
	 * Setup the command buffer pointers
	 */
	iommu->aiomt_cmdbuf = iommu->aiomt_devtbl +
	    iommu->aiomt_devtbl_sz;
	bzero(iommu->aiomt_cmdbuf, iommu->aiomt_cmdbuf_sz);
	addr += iommu->aiomt_devtbl_sz;
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_cmdbuf_va),
	    AMD_IOMMU_COMBASE, ((uint64_t)(uintptr_t)addr) >> 12);

	p2sz = AMD_IOMMU_CMDBUF_SZ;
	ASSERT(p2sz >= AMD_IOMMU_CMDBUF_MINSZ &&
	    p2sz <= AMD_IOMMU_CMDBUF_MAXSZ);
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_cmdbuf_va),
	    AMD_IOMMU_COMLEN, p2sz);
	/*LINTED*/
	iommu->aiomt_cmd_tail = (uint32_t *)iommu->aiomt_cmdbuf;
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_cmdbuf_head_va),
	    AMD_IOMMU_CMDHEADPTR, 0);
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_cmdbuf_tail_va),
	    AMD_IOMMU_CMDTAILPTR, 0);

	/*
	 * Setup the event log pointers
	 */
	iommu->aiomt_eventlog = iommu->aiomt_cmdbuf +
	    iommu->aiomt_eventlog_sz;
	bzero(iommu->aiomt_eventlog, iommu->aiomt_eventlog_sz);
	addr += iommu->aiomt_cmdbuf_sz;
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_eventlog_va),
	    AMD_IOMMU_EVENTBASE, ((uint64_t)(uintptr_t)addr) >> 12);
	p2sz = AMD_IOMMU_EVENTLOG_SZ;
	ASSERT(p2sz >= AMD_IOMMU_EVENTLOG_MINSZ &&
	    p2sz <= AMD_IOMMU_EVENTLOG_MAXSZ);
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_eventlog_va),
	    AMD_IOMMU_EVENTLEN, sz);
	/*LINTED*/
	iommu->aiomt_event_head = (uint32_t *)iommu->aiomt_eventlog;
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_eventlog_head_va),
	    AMD_IOMMU_EVENTHEADPTR, 0);
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_eventlog_tail_va),
	    AMD_IOMMU_EVENTTAILPTR, 0);

	/* dma sync so device sees this init */
	SYNC_FORDEV(iommu->aiomt_dmahdl);

	cmn_err(CE_NOTE, "%s: %s%d: successfully setup AMD IOMMU tables, "
	    "idx=%d", f, driver, instance, iommu->aiomt_idx);

	return (DDI_SUCCESS);
}

static void
amd_iommu_teardown_tables_and_buffers(amd_iommu_t *iommu)
{
	dev_info_t *dip = iommu->aiomt_dip;
	int instance = ddi_get_instance(dip);
	const char *driver = ddi_driver_name(dip);
	const char *f = "amd_iommu_teardown_tables_and_buffers";

	iommu->aiomt_eventlog = NULL;
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_eventlog_va),
	    AMD_IOMMU_EVENTBASE, 0);
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_eventlog_va),
	    AMD_IOMMU_EVENTLEN, 0);

	iommu->aiomt_cmdbuf = NULL;
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_cmdbuf_va),
	    AMD_IOMMU_COMBASE, 0);
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_cmdbuf_va),
	    AMD_IOMMU_COMLEN, 0);

	iommu->aiomt_devtbl = NULL;
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_devtbl_va),
	    AMD_IOMMU_DEVTABBASE, 0);
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_devtbl_va),
	    AMD_IOMMU_DEVTABSIZE, 0);

	if (iommu->aiomt_dmahdl == NULL)
		return;

	/* Unbind the handle */
	if (ddi_dma_unbind_handle(iommu->aiomt_dmahdl) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: failed to unbind handle: "
		    "%p for IOMMU idx=%d", f, driver, instance,
		    (void *)iommu->aiomt_dmahdl, iommu->aiomt_idx);
	}
	iommu->aiomt_buf_dma_cookie.dmac_laddress = 0;
	iommu->aiomt_buf_dma_cookie.dmac_size = 0;
	iommu->aiomt_buf_dma_cookie.dmac_type = 0;
	iommu->aiomt_buf_dma_ncookie = 0;

	/* Free the table memory allocated for DMA */
	ddi_dma_mem_free(&iommu->aiomt_dma_mem_hdl);
	iommu->aiomt_dma_mem_hdl = NULL;
	iommu->aiomt_dma_bufva = NULL;
	iommu->aiomt_dma_mem_realsz = 0;

	/* Free the DMA handle */
	ddi_dma_free_handle(&iommu->aiomt_dmahdl);
	iommu->aiomt_dmahdl = NULL;
}

static int
amd_iommu_setup_exclusion(amd_iommu_t *iommu)
{
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_excl_base_va),
	    AMD_IOMMU_EXCL_BASE_ADDR, 0);
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_excl_base_va),
	    AMD_IOMMU_EXCL_BASE_ALLOW, 1);
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_excl_base_va),
	    AMD_IOMMU_EXCL_BASE_EXEN, 0);
	AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_excl_lim_va),
	    AMD_IOMMU_EXCL_LIM, 0);

	return (DDI_SUCCESS);
}

static void
amd_iommu_teardown_exclusion(amd_iommu_t *iommu)
{
	(void) amd_iommu_setup_exclusion(iommu);
}

static uint_t
amd_iommu_intr_handler(caddr_t arg1, caddr_t arg2)
{
	/*LINTED*/
	amd_iommu_t *iommu = (amd_iommu_t *)arg1;
	dev_info_t *dip = iommu->aiomt_dip;
	int instance = ddi_get_instance(dip);
	const char *driver = ddi_driver_name(dip);
	const char *f = "amd_iommu_intr_handler";

	ASSERT(arg1);
	ASSERT(arg2 == NULL);

	cmn_err(CE_NOTE, "%s: %s%d: IOMMU unit idx=%d. In INTR handler",
	    f, driver, instance, iommu->aiomt_idx);

	if (AMD_IOMMU_REG_GET(REGVAL64(iommu->aiomt_reg_status_va),
	    AMD_IOMMU_COMWAIT_INT) == 1) {
		cmn_err(CE_NOTE, "%s: %s%d: IOMMU unit idx=%d "
		    "Completion Wait Interrupt", f, driver, instance,
		    iommu->aiomt_idx);
		AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_status_va),
		    AMD_IOMMU_COMWAIT_INT, 1);
		sema_v(&iommu->aiomt_compl_wait_sema);
		return (DDI_INTR_CLAIMED);
	}

	if (AMD_IOMMU_REG_GET(REGVAL64(iommu->aiomt_reg_status_va),
	    AMD_IOMMU_EVENT_LOG_INT) == 1) {
		cmn_err(CE_NOTE, "%s: %s%d: IOMMU unit idx=%d "
		    "Event Log Interrupt", f, driver, instance,
		    iommu->aiomt_idx);
		(void) amd_iommu_read_log(iommu);
		WAIT_SEC(1);
		AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_status_va),
		    AMD_IOMMU_EVENT_LOG_INT, 1);
		return (DDI_INTR_CLAIMED);
	}

	if (AMD_IOMMU_REG_GET(REGVAL64(iommu->aiomt_reg_status_va),
	    AMD_IOMMU_EVENT_OVERFLOW_INT) == 1) {
		cmn_err(CE_NOTE, "%s: %s%d: IOMMU unit idx=%d "
		    "Event Overflow Interrupt", f, driver, instance,
		    iommu->aiomt_idx);
		AMD_IOMMU_REG_SET(REGVAL64(iommu->aiomt_reg_status_va),
		    AMD_IOMMU_EVENT_OVERFLOW_INT, 1);
		return (DDI_INTR_CLAIMED);
	}

	return (DDI_INTR_UNCLAIMED);
}

static int
amd_iommu_setup_interrupts(amd_iommu_t *iommu)
{
	dev_info_t *dip = iommu->aiomt_dip;
	int instance = ddi_get_instance(dip);
	const char *driver = ddi_driver_name(dip);
	int intrcap0;
	int intrcapN;
	int type;
	int err;
	int req;
	int avail;
	int p2req;
	int actual;
	int i;
	int j;
	const char *f = "amd_iommu_setup_interrupts";

	if (ddi_intr_get_supported_types(dip, &type) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: ddi_intr_get_supported_types "
		    "failed: idx=%d", f, driver, instance, iommu->aiomt_idx);
		return (DDI_FAILURE);
	}

	cmn_err(CE_NOTE, "%s: %s%d: AMD IOMMU idx=%d. "
	    "Interrupt types supported = 0x%x", f, driver, instance,
	    iommu->aiomt_idx, type);

	/*
	 * for now we only support MSI
	 */
	if ((type & DDI_INTR_TYPE_MSI) == 0) {
		cmn_err(CE_WARN, "%s: %s%d: AMD IOMMU idx=%d. "
		    "MSI interrupts not supported. Failing init.",
		    f, driver, instance, iommu->aiomt_idx);
		return (DDI_FAILURE);
	}

	cmn_err(CE_NOTE, "%s: %s%d: AMD IOMMU idx=%d. MSI supported",
	    f, driver, instance, iommu->aiomt_idx);

	err = ddi_intr_get_nintrs(dip, DDI_INTR_TYPE_MSI, &req);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: AMD IOMMU idx=%d. "
		    "ddi_intr_get_nintrs failed err = %d",
		    f, driver, instance, iommu->aiomt_idx, err);
		return (DDI_FAILURE);
	}

	cmn_err(CE_NOTE, "%s: %s%d: AMD IOMMU idx=%d. "
	    "MSI number of interrupts requested: %d",
	    f, driver, instance, iommu->aiomt_idx, req);

	if (req == 0) {
		cmn_err(CE_WARN, "%s: %s%d: AMD IOMMU idx=%d: 0 MSI "
		    "interrupts requested. Failing init", f,
		    driver, instance, iommu->aiomt_idx);
		return (DDI_FAILURE);
	}

	err = ddi_intr_get_navail(dip, DDI_INTR_TYPE_MSI, &avail);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: AMD IOMMU idx=%d "
		    "ddi_intr_get_navail failed err = %d", f,
		    driver, instance, iommu->aiomt_idx, err);
		return (DDI_FAILURE);
	}

	cmn_err(CE_NOTE, "%s: %s%d: AMD IOMMU idx=%d. "
	    "MSI number of interrupts available: %d",
	    f, driver, instance, iommu->aiomt_idx, avail);

	if (avail == 0) {
		cmn_err(CE_WARN, "%s: %s%d: AMD IOMMU idx=%d: 0 MSI "
		    "interrupts available. Failing init", f,
		    driver, instance, iommu->aiomt_idx);
		return (DDI_FAILURE);
	}

	if (avail < req) {
		cmn_err(CE_WARN, "%s: %s%d: AMD IOMMU idx=%d: MSI "
		    "interrupts: requested (%d) > available (%d). "
		    "Failing init", f, driver, instance, iommu->aiomt_idx,
		    req, avail);
		return (DDI_FAILURE);
	}

	/* Allocate memory for DDI interrupt handles */
	iommu->aiomt_intr_htable_sz = req * sizeof (ddi_intr_handle_t);
	iommu->aiomt_intr_htable = kmem_zalloc(iommu->aiomt_intr_htable_sz,
	    KM_SLEEP);

	iommu->aiomt_intr_state = AMD_IOMMU_INTR_TABLE;

	/* Convert req to a power of two as required by ddi_intr_alloc */
	p2req = 0;
	while (1<<p2req <= req)
		p2req++;
	p2req--;
	req = 1<<p2req;

	cmn_err(CE_NOTE, "%s: %s%d: AMD IOMMU idx=%d. "
	    "MSI power of 2 number of interrupts: %d,%d",
	    f, driver, instance, iommu->aiomt_idx, p2req, req);

	err = ddi_intr_alloc(iommu->aiomt_dip, iommu->aiomt_intr_htable,
	    DDI_INTR_TYPE_MSI, 0, req, &actual, DDI_INTR_ALLOC_STRICT);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: AMD IOMMU idx=%d: "
		    "ddi_intr_alloc failed: err = %d",
		    f, driver, instance, iommu->aiomt_idx, err);
		amd_iommu_teardown_interrupts(iommu);
		return (DDI_FAILURE);
	}

	iommu->aiomt_actual_intrs = actual;
	iommu->aiomt_intr_state = AMD_IOMMU_INTR_ALLOCED;

	cmn_err(CE_NOTE, "%s: %s%d: AMD IOMMU idx=%d. "
	    "number of interrupts actually allocated %d",
	    f, driver, instance, iommu->aiomt_idx, actual);

	if (iommu->aiomt_actual_intrs < req) {
		cmn_err(CE_WARN, "%s: %s%d: AMD IOMMU idx=%d: "
		    "ddi_intr_alloc failed: actual (%d) < req (%d)",
		    f, driver, instance, iommu->aiomt_idx,
		    iommu->aiomt_actual_intrs, req);
		amd_iommu_teardown_interrupts(iommu);
		return (DDI_FAILURE);
	}

	for (i = 0; i < iommu->aiomt_actual_intrs; i++) {
		if (ddi_intr_add_handler(iommu->aiomt_intr_htable[i],
		    amd_iommu_intr_handler, (void *)iommu, NULL)
		    != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s: %s%d: AMD IOMMU idx=%d: "
			    "ddi_intr_add_handler failed: intr = %d, err = %d",
			    f, driver, instance, iommu->aiomt_idx, i, err);
			for (j = 0; j < i; j++) {
				(void) ddi_intr_remove_handler(
				    iommu->aiomt_intr_htable[j]);
			}
			amd_iommu_teardown_interrupts(iommu);
			return (DDI_FAILURE);
		}
	}
	iommu->aiomt_intr_state = AMD_IOMMU_INTR_HANDLER;

	intrcap0 = intrcapN = -1;
	if (ddi_intr_get_cap(iommu->aiomt_intr_htable[0], &intrcap0)
	    != DDI_SUCCESS ||
	    ddi_intr_get_cap(
	    iommu->aiomt_intr_htable[iommu->aiomt_actual_intrs - 1], &intrcapN)
	    != DDI_SUCCESS || intrcap0 != intrcapN) {
		cmn_err(CE_WARN, "%s: %s%d: AMD IOMMU idx=%d: "
		    "ddi_intr_get_cap failed or inconsistent cap among "
		    "interrupts: intrcap0 (%d) < intrcapN (%d)",
		    f, driver, instance, iommu->aiomt_idx, intrcap0, intrcapN);
		amd_iommu_teardown_interrupts(iommu);
		return (DDI_FAILURE);
	}
	iommu->aiomt_intr_cap = intrcap0;

	if (intrcap0 & DDI_INTR_FLAG_BLOCK) {
		/* Need to call block enable */
		cmn_err(CE_NOTE, "%s: %s%d: AMD IOMMU idx=%d: "
		    "Need to call block enable",
		    f, driver, instance, iommu->aiomt_idx);
		if (ddi_intr_block_enable(iommu->aiomt_intr_htable,
		    iommu->aiomt_actual_intrs) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s: %s%d: AMD IOMMU idx=%d: "
			    "ddi_intr_block enable failed ", f, driver,
			    instance, iommu->aiomt_idx);
			(void) ddi_intr_block_disable(iommu->aiomt_intr_htable,
			    iommu->aiomt_actual_intrs);
			amd_iommu_teardown_interrupts(iommu);
			return (DDI_FAILURE);
		}
	} else {
		cmn_err(CE_NOTE, "%s: %s%d: AMD IOMMU idx=%d: "
		    "Need to call individual enable",
		    f, driver, instance, iommu->aiomt_idx);
		for (i = 0; i < iommu->aiomt_actual_intrs; i++) {
			if (ddi_intr_enable(iommu->aiomt_intr_htable[i])
			    != DDI_SUCCESS) {
				cmn_err(CE_WARN, "%s: %s%d: AMD IOMMU idx=%d: "
				    "ddi_intr_enable failed: intr = %d", f,
				    driver, instance, iommu->aiomt_idx, i);
				for (j = 0; j < i; j++) {
					(void) ddi_intr_disable(
					    iommu->aiomt_intr_htable[j]);
				}
				amd_iommu_teardown_interrupts(iommu);
				return (DDI_FAILURE);
			}
		}
	}
	iommu->aiomt_intr_state = AMD_IOMMU_INTR_ENABLED;

	cmn_err(CE_NOTE, "%s: %s%d: AMD IOMMU idx=%d: "
	    "Interrupts successfully %s enabled. # of interrupts = %d",
	    f, driver, instance, iommu->aiomt_idx,
	    (intrcap0 & DDI_INTR_FLAG_BLOCK) ? "(block)" : "(individually)",
	    iommu->aiomt_actual_intrs);

	return (DDI_SUCCESS);
}

static void
amd_iommu_teardown_interrupts(amd_iommu_t *iommu)
{
	int i;

	if (iommu->aiomt_intr_state & AMD_IOMMU_INTR_ENABLED) {
		if (iommu->aiomt_intr_cap & DDI_INTR_FLAG_BLOCK) {
			(void) ddi_intr_block_disable(iommu->aiomt_intr_htable,
			    iommu->aiomt_actual_intrs);
		} else {
			for (i = 0; i < iommu->aiomt_actual_intrs; i++) {
				(void) ddi_intr_disable(
				    iommu->aiomt_intr_htable[i]);
			}
		}
	}

	if (iommu->aiomt_intr_state & AMD_IOMMU_INTR_HANDLER) {
		for (i = 0; i < iommu->aiomt_actual_intrs; i++) {
			(void) ddi_intr_remove_handler(
			    iommu->aiomt_intr_htable[i]);
		}
	}

	if (iommu->aiomt_intr_state & AMD_IOMMU_INTR_ALLOCED) {
		for (i = 0; i < iommu->aiomt_actual_intrs; i++) {
			(void) ddi_intr_free(iommu->aiomt_intr_htable[i]);
		}
	}
	if (iommu->aiomt_intr_state & AMD_IOMMU_INTR_TABLE) {
		kmem_free(iommu->aiomt_intr_htable,
		    iommu->aiomt_intr_htable_sz);
	}
	iommu->aiomt_intr_htable = NULL;
	iommu->aiomt_intr_htable_sz = 0;
	iommu->aiomt_intr_state = AMD_IOMMU_INTR_INVALID;
}

static amd_iommu_t *
amd_iommu_init(dev_info_t *dip, ddi_acc_handle_t handle, int idx,
    uint16_t cap_base)
{
	amd_iommu_t *iommu;
	int instance = ddi_get_instance(dip);
	const char *driver = ddi_driver_name(dip);
	uint32_t caphdr;
	uint32_t low_addr32;
	uint32_t hi_addr32;
	uint32_t range;
	uint32_t misc;
	const char *f = "amd_iommu_init";

	low_addr32 = PCI_CAP_GET32(handle, 0, cap_base,
	    AMD_IOMMU_CAP_ADDR_LOW_OFF);
	if (!(low_addr32 & AMD_IOMMU_REG_ADDR_LOCKED)) {
		cmn_err(CE_WARN, "%s: %s%d: capability registers not locked. "
		    "Unable to use IOMMU unit idx=%d - skipping ...", f, driver,
		    instance, idx);
		return (NULL);
	}

	iommu = kmem_zalloc(sizeof (amd_iommu_t), KM_SLEEP);
	mutex_init(&iommu->aiomt_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_enter(&iommu->aiomt_mutex);

	mutex_init(&iommu->aiomt_cmdlock, NULL, MUTEX_DRIVER, NULL);
	sema_init(&iommu->aiomt_compl_wait_sema, 1, NULL, SEMA_DRIVER, NULL);
	mutex_init(&iommu->aiomt_eventlock, NULL, MUTEX_DRIVER, NULL);

	iommu->aiomt_dip = dip;
	iommu->aiomt_idx = idx;

	/*
	 * Since everything in the capability block is locked and RO at this
	 * point, copy everything into the IOMMU struct
	 */

	/* Get cap header */
	caphdr = PCI_CAP_GET32(handle, 0, cap_base, AMD_IOMMU_CAP_HDR_OFF);
	iommu->aiomt_cap_hdr = caphdr;
	iommu->aiomt_npcache = AMD_IOMMU_REG_GET(caphdr, AMD_IOMMU_CAP_NPCACHE);
	iommu->aiomt_httun = AMD_IOMMU_REG_GET(caphdr, AMD_IOMMU_CAP_HTTUN);
	iommu->aiomt_iotlb = AMD_IOMMU_REG_GET(caphdr, AMD_IOMMU_CAP_IOTLB);
	iommu->aiomt_captype = AMD_IOMMU_REG_GET(caphdr, AMD_IOMMU_CAP_TYPE);
	iommu->aiomt_capid = AMD_IOMMU_REG_GET(caphdr, AMD_IOMMU_CAP_ID);

	/*
	 * Get address of IOMMU control registers
	 */
	hi_addr32 = PCI_CAP_GET32(handle, 0, cap_base,
	    AMD_IOMMU_CAP_ADDR_HI_OFF);
	iommu->aiomt_low_addr32 = low_addr32;
	iommu->aiomt_hi_addr32 = hi_addr32;
	low_addr32 &= ~AMD_IOMMU_REG_ADDR_LOCKED;
	iommu->aiomt_reg_pa =  ((uint64_t)hi_addr32 << 32 | low_addr32);

	/*
	 * Get cap range reg
	 */
	range = PCI_CAP_GET32(handle, 0, cap_base, AMD_IOMMU_CAP_RANGE_OFF);
	iommu->aiomt_range = range;
	iommu->aiomt_rng_valid = AMD_IOMMU_REG_GET(range, AMD_IOMMU_RNG_VALID);
	if (iommu->aiomt_rng_valid) {
		iommu->aiomt_rng_bus = AMD_IOMMU_REG_GET(range,
		    AMD_IOMMU_RNG_BUS);
		iommu->aiomt_first_devfn = AMD_IOMMU_REG_GET(range,
		    AMD_IOMMU_FIRST_DEVFN);
		iommu->aiomt_last_devfn = AMD_IOMMU_REG_GET(range,
		    AMD_IOMMU_LAST_DEVFN);
	} else {
		iommu->aiomt_rng_bus = 0;
		iommu->aiomt_first_devfn = 0;
		iommu->aiomt_last_devfn = 0;
	}
	iommu->aiomt_ht_unitid = AMD_IOMMU_REG_GET(range, AMD_IOMMU_HT_UNITID);

	/*
	 * Get cap misc reg
	 */
	misc = PCI_CAP_GET32(handle, 0, cap_base, AMD_IOMMU_CAP_MISC_OFF);
	iommu->aiomt_misc = misc;
	iommu->aiomt_htatsresv = AMD_IOMMU_REG_GET(misc, AMD_IOMMU_HT_ATSRSV);
	iommu->aiomt_vasize = AMD_IOMMU_REG_GET(misc, AMD_IOMMU_VA_SIZE);
	iommu->aiomt_pasize = AMD_IOMMU_REG_GET(misc, AMD_IOMMU_PA_SIZE);
	iommu->aiomt_msinum = AMD_IOMMU_REG_GET(misc, AMD_IOMMU_MSINUM);

	/*
	 * Set up mapping between control registers PA and VA
	 */
	iommu->aiomt_reg_pages = btopr(AMD_IOMMU_REG_SIZE);
	iommu->aiomt_reg_size = ptob(iommu->aiomt_reg_pages);
	iommu->aiomt_mmu_reg_pages = mmu_btopr(AMD_IOMMU_REG_SIZE);
	iommu->aiomt_mmu_reg_size = mmu_ptob(iommu->aiomt_mmu_reg_pages);
	iommu->aiomt_reg_va =
	    (uint64_t)(uintptr_t)vmem_alloc(heap_arena, iommu->aiomt_reg_size,
	    VM_SLEEP);

	if ((void *)(uintptr_t)iommu->aiomt_reg_va == NULL) {
		cmn_err(CE_WARN, "%s: %s%d: Failed to alloc VA for IOMMU "
		    "control regs. Skipping IOMMU idx=%d", f, driver,
		    instance, idx);
		mutex_exit(&iommu->aiomt_mutex);
		(void) amd_iommu_fini(iommu);
		return (NULL);
	}

	hat_devload(kas.a_hat, (void *)(uintptr_t)iommu->aiomt_reg_va,
	    iommu->aiomt_mmu_reg_size,
	    mmu_btop(iommu->aiomt_reg_pa), PROT_READ | PROT_WRITE,
	    HAT_LOAD_LOCK);

	/*
	 * Setup the various control register's VA
	 */
	iommu->aiomt_reg_devtbl_va = iommu->aiomt_reg_va +
	    AMD_IOMMU_DEVTBL_REG_OFF;
	iommu->aiomt_reg_cmdbuf_va = iommu->aiomt_reg_va +
	    AMD_IOMMU_CMDBUF_REG_OFF;
	iommu->aiomt_reg_eventlog_va = iommu->aiomt_reg_va +
	    AMD_IOMMU_EVENTLOG_REG_OFF;
	iommu->aiomt_reg_ctrl_va = iommu->aiomt_reg_va +
	    AMD_IOMMU_CTRL_REG_OFF;
	iommu->aiomt_reg_excl_base_va = iommu->aiomt_reg_va +
	    AMD_IOMMU_EXCL_BASE_REG_OFF;
	iommu->aiomt_reg_excl_lim_va = iommu->aiomt_reg_va +
	    AMD_IOMMU_EXCL_LIM_REG_OFF;
	iommu->aiomt_reg_cmdbuf_head_va = iommu->aiomt_reg_va +
	    AMD_IOMMU_CMDBUF_HEAD_REG_OFF;
	iommu->aiomt_reg_cmdbuf_tail_va = iommu->aiomt_reg_va +
	    AMD_IOMMU_CMDBUF_TAIL_REG_OFF;
	iommu->aiomt_reg_eventlog_head_va = iommu->aiomt_reg_va +
	    AMD_IOMMU_EVENTLOG_HEAD_REG_OFF;
	iommu->aiomt_reg_eventlog_tail_va = iommu->aiomt_reg_va +
	    AMD_IOMMU_EVENTLOG_TAIL_REG_OFF;
	iommu->aiomt_reg_status_va = iommu->aiomt_reg_va +
	    AMD_IOMMU_STATUS_REG_OFF;


	/*
	 * Setup the DEVICE table, CMD buffer, and LOG buffer in
	 * memory and setup DMA access to this memory location
	 */
	if (amd_iommu_setup_tables_and_buffers(iommu) != DDI_SUCCESS) {
		mutex_exit(&iommu->aiomt_mutex);
		(void) amd_iommu_fini(iommu);
		return (NULL);
	}
	if (amd_iommu_setup_exclusion(iommu) != DDI_SUCCESS) {
		mutex_exit(&iommu->aiomt_mutex);
		(void) amd_iommu_fini(iommu);
		return (NULL);
	}

	if (amd_iommu_setup_interrupts(iommu) != DDI_SUCCESS) {
		mutex_exit(&iommu->aiomt_mutex);
		(void) amd_iommu_fini(iommu);
		return (NULL);
	}

	if (amd_iommu_start(iommu) != DDI_SUCCESS) {
		mutex_exit(&iommu->aiomt_mutex);
		(void) amd_iommu_fini(iommu);
		return (NULL);
	}

	if (amd_iommu_register(iommu) != DDI_SUCCESS) {
		mutex_exit(&iommu->aiomt_mutex);
		(void) amd_iommu_fini(iommu);
		return (NULL);
	}

	cmn_err(CE_NOTE, "%s: %s%d: IOMMU idx=%d inited.", f, driver,
	    instance, idx);

	return (iommu);
}

static int
amd_iommu_fini(amd_iommu_t *iommu)
{
	int idx = iommu->aiomt_idx;
	dev_info_t *dip = iommu->aiomt_dip;
	int instance = ddi_get_instance(dip);
	const char *driver = ddi_driver_name(dip);
	const char *f = "amd_iommu_fini";

	mutex_enter(&iommu->aiomt_mutex);
	if (amd_iommu_unregister(iommu) != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "%s: %s%d: Fini of IOMMU unit failed. "
		    "idx = %d", f, driver, instance, idx);
		return (DDI_FAILURE);
	}
	amd_iommu_stop(iommu);
	amd_iommu_teardown_interrupts(iommu);
	amd_iommu_teardown_exclusion(iommu);
	amd_iommu_teardown_tables_and_buffers(iommu);
	if (iommu->aiomt_reg_va != NULL) {
		hat_unload(kas.a_hat, (void *)(uintptr_t)iommu->aiomt_reg_va,
		    iommu->aiomt_mmu_reg_size, HAT_UNLOAD_UNLOCK);
		vmem_free(heap_arena, (void *)(uintptr_t)iommu->aiomt_reg_va,
		    iommu->aiomt_reg_size);
		iommu->aiomt_reg_va = NULL;
	}
	mutex_destroy(&iommu->aiomt_eventlock);
	sema_destroy(&iommu->aiomt_compl_wait_sema);
	mutex_destroy(&iommu->aiomt_cmdlock);
	mutex_exit(&iommu->aiomt_mutex);
	mutex_destroy(&iommu->aiomt_mutex);
	kmem_free(iommu, sizeof (amd_iommu_t));

	cmn_err(CE_NOTE, "%s: %s%d: Fini of IOMMU unit complete. idx = %d",
	    f, driver, instance, idx);

	return (DDI_SUCCESS);
}

int
amd_iommu_setup(dev_info_t *dip, amd_iommu_state_t *statep)
{
	int instance = ddi_get_instance(dip);
	const char *driver = ddi_driver_name(dip);
	ddi_acc_handle_t handle;
	uint8_t base_class;
	uint8_t sub_class;
	uint8_t prog_class;
	int idx;
	uint32_t id;
	uint16_t cap_base;
	uint32_t caphdr;
	uint8_t cap_type;
	uint8_t cap_id;
	amd_iommu_t *iommu;
	const char *f = "amd_iommu_setup";

	ASSERT(instance >= 0);
	ASSERT(driver);

	/* First setup PCI access to config space */

	if (pci_config_setup(dip, &handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: PCI config setup failed: %s%d",
		    f, driver, instance);
		return (DDI_FAILURE);
	}

	/*
	 * The AMD IOMMU is part of an independent PCI function. There may be
	 * more than one IOMMU in that PCI function
	 */
	base_class = pci_config_get8(handle, PCI_CONF_BASCLASS);
	sub_class = pci_config_get8(handle, PCI_CONF_SUBCLASS);
	prog_class = pci_config_get8(handle, PCI_CONF_PROGCLASS);

	if (base_class != PCI_CLASS_PERIPH || sub_class != PCI_PERIPH_IOMMU ||
	    prog_class != AMD_IOMMU_PCI_PROG_IF) {
		cmn_err(CE_WARN, "%s: %s%d: invalid PCI class(0x%x)/"
		    "subclass(0x%x)/programming interface(0x%x)", f, driver,
		    instance, base_class, sub_class, prog_class);
		pci_config_teardown(&handle);
		return (DDI_FAILURE);
	}

	/*
	 * Find and initialize all IOMMU units in this function
	 */
	for (idx = 0; ; idx++) {
		if (pci_cap_probe(handle, idx, &id, &cap_base) != DDI_SUCCESS)
			break;

		/* check if cap ID is secure device cap id */
		if (id != PCI_CAP_ID_SECURE_DEV) {
			cmn_err(CE_WARN, "%s: %s%d: skipping IOMMU: idx(0x%x) "
			    "cap ID (0x%x) != secure dev capid (0x%x)", f,
			    driver, instance, idx, id, PCI_CAP_ID_SECURE_DEV);
			continue;
		}

		/* check if cap type is IOMMU cap type */
		caphdr = PCI_CAP_GET32(handle, 0, cap_base,
		    AMD_IOMMU_CAP_HDR_OFF);
		cap_type = AMD_IOMMU_REG_GET(caphdr, AMD_IOMMU_CAP_TYPE);
		cap_id = AMD_IOMMU_REG_GET(caphdr, AMD_IOMMU_CAP_ID);

		if (cap_type != AMD_IOMMU_CAP) {
			cmn_err(CE_WARN, "%s: %s%d: skipping IOMMU: idx(0x%x) "
			    "cap type (0x%x) != AMD IOMMU CAP (0x%x)", f,
			    driver, instance, idx, cap_type, AMD_IOMMU_CAP);
			continue;
		}
		ASSERT(cap_id == PCI_CAP_ID_SECURE_DEV);
		ASSERT(cap_id == id);

		iommu = amd_iommu_init(dip, handle, idx, cap_base);
		if (iommu == NULL) {
			cmn_err(CE_WARN, "%s: %s%d: skipping IOMMU: idx(0x%x) "
			    "failed to init IOMMU", f,
			    driver, instance, idx);
			continue;
		}

		if (statep->aioms_iommu_start == NULL) {
			statep->aioms_iommu_start = iommu;
		} else {
			statep->aioms_iommu_end->aiomt_next = iommu;
		}
		statep->aioms_iommu_end = iommu;

		statep->aioms_nunits++;
	}

	pci_config_teardown(&handle);

	cmn_err(CE_NOTE, "%s: %s%d: state=%p: setup %d IOMMU units",
	    f, driver, instance, (void *)statep, statep->aioms_nunits);

	return (DDI_SUCCESS);
}

int
amd_iommu_teardown(dev_info_t *dip, amd_iommu_state_t *statep)
{
	int instance = ddi_get_instance(dip);
	const char *driver = ddi_driver_name(dip);
	amd_iommu_t *iommu;
	int teardown;
	int error = DDI_SUCCESS;
	const char *f = "amd_iommu_teardown";

	teardown = 0;
	for (iommu = statep->aioms_iommu_start; iommu;
	    iommu = iommu->aiomt_next) {
		ASSERT(statep->aioms_nunits > 0);
		if (amd_iommu_fini(iommu) != DDI_SUCCESS) {
			error = DDI_FAILURE;
			continue;
		}
		statep->aioms_nunits--;
		teardown++;
	}

	cmn_err(CE_NOTE, "%s: %s%d: state=%p: toredown %d units. "
	    "%d units left", f, driver, instance, (void *)statep,
	    teardown, statep->aioms_nunits);

	return (error);
}

/* Interface with IOMMULIB */
/*ARGSUSED*/
static int
amd_iommu_probe(dev_info_t *rdip)
{
	/* for now unconditionally return probe success */
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
amd_iommu_allochdl(iommulib_handle_t handle,
    dev_info_t *dip, dev_info_t *rdip, ddi_dma_attr_t *attr,
    int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *dma_handlep)
{
	return (iommulib_iommu_dma_allochdl(dip, rdip, attr, waitfp,
	    arg, dma_handlep));
}

/*ARGSUSED*/
static int
amd_iommu_freehdl(iommulib_handle_t handle,
    dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t dma_handle)
{
	return (iommulib_iommu_dma_freehdl(dip, rdip, dma_handle));
}

/*ARGSUSED*/
static int
map_current_window(iommulib_handle_t handle, dev_info_t *rdip,
    ddi_dma_handle_t dma_handle)
{
	amd_iommu_t *iommu = (amd_iommu_t *)iommulib_iommu_getdata(handle);
	const char *driver = ddi_driver_name(iommu->aiomt_dip);
	int instance = ddi_get_instance(iommu->aiomt_dip);
	int idx = iommu->aiomt_idx;
	ddi_dma_cookie_t cookie;
	uint_t ccount;
	int i;
	dev_info_t *dip = ddi_root_node();
	char path[MAXPATHLEN];
	const char *f = "map_current_window";

	(void) ddi_pathname(rdip, path);

	if (amd_iommu_debug & AMD_IOMMU_DEBUG_PAGE_TABLES) {
		cmn_err(CE_NOTE, "%s: entered for device %s, rdip = %p",
		    f, path, (void *)rdip);
	}

	if (amd_iommu_debug == AMD_IOMMU_DEBUG_PAGE_TABLES) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d Attempting to get cookies "
		    "from handle for device %s",
		    f, driver, instance, idx, path);
	}

	if (iommulib_iommu_dma_get_cookies(dip, dma_handle, &cookie, &ccount) !=
	    DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d Cannot get cookies "
		    "for device %s", f, driver, instance, idx, path);
		return (DDI_FAILURE);
	}

	if (amd_iommu_debug == AMD_IOMMU_DEBUG_PAGE_TABLES) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d GOT %d cookies from handle "
		    "for device %s",
		    f, driver, instance, idx, ccount, path);
	}

	for (i = 0; i < ccount; i++, ddi_dma_nextcookie(dma_handle, &cookie)) {
		if (amd_iommu_map_pa2va(iommu, 1, rdip,
		    cookie.dmac_cookie_addr,
		    cookie.dmac_size) != DDI_SUCCESS) {
			break;
		}
	}

	if (i != ccount) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d Cannot map cookie# %d "
		    "for device %s", f, driver, instance, idx, i, path);
		(void) unmap_current_window(handle, rdip, dma_handle, i);
		return (DDI_FAILURE);
	}
	iommulib_iommu_dma_reset_cookies(dip, dma_handle);

	if (amd_iommu_debug & AMD_IOMMU_DEBUG_PAGE_TABLES) {
		cmn_err(CE_NOTE, "%s: return SUCCESS", f);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
unmap_current_window(iommulib_handle_t handle, dev_info_t *rdip,
    ddi_dma_handle_t dma_handle, int ncookies)
{
	amd_iommu_t *iommu = (amd_iommu_t *)iommulib_iommu_getdata(handle);
	const char *driver = ddi_driver_name(iommu->aiomt_dip);
	int instance = ddi_get_instance(iommu->aiomt_dip);
	int idx = iommu->aiomt_idx;
	ddi_dma_cookie_t cookie;
	uint_t ccount;
	int i;
	dev_info_t *dip = ddi_root_node();
	char path[MAXPATHLEN];
	const char *f = "unmap_current_window";

	(void) ddi_pathname(rdip, path);

	if (iommulib_iommu_dma_get_cookies(dip, dma_handle, &cookie, &ccount) !=
	    DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d Cannot get cookies "
		    "for device %s", f, driver, instance, idx, path);
		return (DDI_FAILURE);
	}

	if (ncookies == -1)
		ncookies = ccount;

	for (i = 0; i < ncookies; i++) {
		if (amd_iommu_unmap_va(iommu, 1, rdip, cookie.dmac_cookie_addr,
		    cookie.dmac_size) != DDI_SUCCESS) {
			break;
		}
		ddi_dma_nextcookie(dma_handle, &cookie);
	}

	if (i != ncookies) {
		cmn_err(CE_WARN, "%s: %s%d: idx=%d Cannot unmap cookie# %d "
		    "for device %s", f, driver, instance, idx, i, path);
		return (DDI_FAILURE);
	}
	iommulib_iommu_dma_reset_cookies(dip, dma_handle);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
amd_iommu_bindhdl(iommulib_handle_t handle, dev_info_t *dip,
    dev_info_t *rdip, ddi_dma_handle_t dma_handle,
    struct ddi_dma_req *dmareq, ddi_dma_cookie_t *cookiep,
    uint_t *ccountp)
{
	int error;
	const char *f = "amd_iommu_bindhdl";

	error = iommulib_iommu_dma_bindhdl(dip, rdip, dma_handle,
	    dmareq, cookiep, ccountp);

	if (error != DDI_DMA_MAPPED && error != DDI_DMA_PARTIAL_MAP)
		return (error);

	if (amd_iommu_debug & AMD_IOMMU_DEBUG_BIND) {
		char buf[MAXPATHLEN];
		(void) ddi_pathname(rdip, buf);
		cmn_err(CE_NOTE, "%s: %s got cookie (%p), #cookies: %d",
		    f, buf, (void *)cookiep->dmac_cookie_addr, *ccountp);
	}

	if (map_current_window(handle, rdip, dma_handle) != DDI_SUCCESS)
		return (DDI_DMA_NOMAPPING);

	if (amd_iommu_debug & AMD_IOMMU_DEBUG_BIND) {
		char buf[MAXPATHLEN];
		(void) ddi_pathname(rdip, buf);
		cmn_err(CE_NOTE, "%s: %s remapped cookie (%p), #cookies: %d",
		    f, buf, (void *)cookiep->dmac_cookie_addr, *ccountp);
	}

	return (error);
}

/*ARGSUSED*/
static int
amd_iommu_unbindhdl(iommulib_handle_t handle,
    dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t dma_handle)
{
	if (unmap_current_window(handle, rdip, dma_handle, -1) != DDI_SUCCESS)
		return (DDI_FAILURE);

	return (iommulib_iommu_dma_unbindhdl(dip, rdip, dma_handle));
}

/*ARGSUSED*/
static int
amd_iommu_sync(iommulib_handle_t handle, dev_info_t *dip,
    dev_info_t *rdip, ddi_dma_handle_t dma_handle, off_t off,
    size_t len, uint_t cache_flags)
{
	return (iommulib_iommu_dma_sync(dip, rdip, dma_handle, off,
	    len, cache_flags));
}

/*ARGSUSED*/
static int
amd_iommu_win(iommulib_handle_t handle, dev_info_t *dip,
    dev_info_t *rdip, ddi_dma_handle_t dma_handle, uint_t win,
    off_t *offp, size_t *lenp, ddi_dma_cookie_t *cookiep,
    uint_t *ccountp)
{
	int error;

	if (unmap_current_window(handle, rdip, dma_handle, -1) != DDI_SUCCESS)
		return (DDI_FAILURE);

	error = iommulib_iommu_dma_win(dip, rdip, dma_handle, win,
	    offp, lenp, cookiep, ccountp);
	if (error != DDI_SUCCESS)
		return (DDI_FAILURE);

	return (map_current_window(handle, rdip, dma_handle));
}

/* Obsoleted DMA routines */

/*ARGSUSED*/
static int
amd_iommu_map(iommulib_handle_t handle, dev_info_t *dip,
    dev_info_t *rdip, struct ddi_dma_req *dmareq,
    ddi_dma_handle_t *dma_handle)
{
	return (iommulib_iommu_dma_map(dip, rdip, dmareq, dma_handle));
}

/*ARGSUSED*/
static int
amd_iommu_mctl(iommulib_handle_t handle, dev_info_t *dip,
    dev_info_t *rdip, ddi_dma_handle_t dma_handle,
    enum ddi_dma_ctlops request, off_t *offp, size_t *lenp,
    caddr_t *objpp, uint_t cache_flags)
{
	return (iommulib_iommu_dma_mctl(dip, rdip, dma_handle,
	    request, offp, lenp, objpp, cache_flags));
}
