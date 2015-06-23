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
 * Copyright 2008 NetXen, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strlog.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/kstat.h>
#include <sys/vtrace.h>
#include <sys/dlpi.h>
#include <sys/strsun.h>
#include <sys/ethernet.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/pci.h>
#include <sys/ddi_intr.h>

#include "unm_nic.h"
#include "unm_nic_hw.h"
#include "unm_brdcfg.h"
#include "nic_cmn.h"
#include "nic_phan_reg.h"
#include "unm_nic_ioctl.h"
#include "nx_hw_pci_regs.h"

char ident[] = "Netxen nic driver v" UNM_NIC_VERSIONID;
char unm_nic_driver_name[] = "ntxn";
int verbmsg = 0;

static char txbcopythreshold_propname[] = "tx_bcopy_threshold";
static char rxbcopythreshold_propname[] = "rx_bcopy_threshold";
static char rxringsize_propname[] = "rx_ring_size";
static char jumborxringsize_propname[] = "jumbo_rx_ring_size";
static char txringsize_propname[] = "tx_ring_size";
static char defaultmtu_propname[] = "default_mtu";
static char dmesg_propname[] = "verbose_driver";

#define	STRUCT_COPY(a, b)	bcopy(&(b), &(a), sizeof (a))

extern int unm_register_mac(unm_adapter *adapter);
extern void unm_fini_kstats(unm_adapter* adapter);
extern void unm_nic_remove(unm_adapter *adapter);
extern int unm_nic_suspend(unm_adapter *);
extern uint_t unm_intr(caddr_t, caddr_t);

/* Data access requirements. */
static struct ddi_device_acc_attr unm_dev_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

static struct ddi_device_acc_attr unm_buf_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

static ddi_dma_attr_t unm_dma_attr_desc = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0xffffffffull,		/* dma_attr_addr_hi */
	0x000fffffull,		/* dma_attr_count_max */
	4096,			/* dma_attr_align */
	0x000fffffull,		/* dma_attr_burstsizes */
	4,			/* dma_attr_minxfer */
	0x003fffffull,		/* dma_attr_maxxfer */
	0xffffffffull,		/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

static ddi_dma_attr_t unm_dma_attr_rxbuf = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0x7ffffffffULL,		/* dma_attr_addr_hi */
	0xffffull,		/* dma_attr_count_max */
	4096,			/* dma_attr_align */
	0xfff8ull,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0xffffffffull,		/* dma_attr_maxxfer */
	0xffffull,		/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

static ddi_dma_attr_t unm_dma_attr_cmddesc = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0x7ffffffffULL,		/* dma_attr_addr_hi */
	0xffffull,		/* dma_attr_count_max */
	1,			/* dma_attr_align */
	0xfff8ull,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0xffff0ull,		/* dma_attr_maxxfer */
	0xffffull,		/* dma_attr_seg */
	16,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

static struct nx_legacy_intr_set legacy_intr[] = NX_LEGACY_INTR_CONFIG;

static int
check_hw_init(struct unm_adapter_s *adapter)
{
	u32	val;
	int	ret = 0;

	adapter->unm_nic_hw_read_wx(adapter, UNM_CAM_RAM(0x1fc), &val, 4);
	if (val == 0x55555555) {
		/* This is the first boot after power up */
		adapter->unm_nic_hw_read_wx(adapter, UNM_ROMUSB_GLB_SW_RESET,
		    &val, 4);
		if (val != 0x80000f)
			ret = -1;

		if (NX_IS_REVISION_P2(adapter->ahw.revision_id)) {
			/* Start P2 boot loader */
			adapter->unm_nic_pci_write_normalize(adapter,
			    UNM_CAM_RAM(0x1fc), UNM_BDINFO_MAGIC);
			adapter->unm_nic_pci_write_normalize(adapter,
			    UNM_ROMUSB_GLB_PEGTUNE_DONE, 1);
		}
	}
	return (ret);
}


static int
unm_get_flash_block(unm_adapter *adapter, int base, int size, uint32_t *buf)
{
	int i, addr;
	uint32_t *ptr32;

	addr  = base;
	ptr32 = buf;
	for (i = 0; i < size / sizeof (uint32_t); i++) {
		if (rom_fast_read(adapter, addr, (int *)ptr32) == -1)
			return (-1);
		ptr32++;
		addr += sizeof (uint32_t);
	}
	if ((char *)buf + size > (char *)ptr32) {
		int local;

		if (rom_fast_read(adapter, addr, &local) == -1)
			return (-1);
		(void) memcpy(ptr32, &local,
		    (uintptr_t)((char *)buf + size) - (uintptr_t)(char *)ptr32);
	}

	return (0);
}


static int
get_flash_mac_addr(struct unm_adapter_s *adapter, u64 mac[])
{
	uint32_t *pmac = (uint32_t *)&mac[0];

	if (NX_IS_REVISION_P3(adapter->ahw.revision_id)) {
		uint32_t temp, crbaddr;
		uint16_t *pmac16 = (uint16_t *)pmac;

		// FOR P3, read from CAM RAM

		int pci_func = adapter->ahw.pci_func;
		pmac16 += (4 * pci_func);
		crbaddr = CRB_MAC_BLOCK_START + (4 * ((pci_func/2) * 3)) +
		    (4 * (pci_func & 1));

		adapter->unm_nic_hw_read_wx(adapter, crbaddr, &temp, 4);
		if (pci_func & 1) {
			*pmac16++ = (temp >> 16);
			adapter->unm_nic_hw_read_wx(adapter, crbaddr+4,
			    &temp, 4);
			*pmac16++ = (temp & 0xffff);
			*pmac16++ = (temp >> 16);
			*pmac16 = 0;
		} else {
			*pmac16++ = (temp & 0xffff);
			*pmac16++ = (temp >> 16);
			adapter->unm_nic_hw_read_wx(adapter, crbaddr+4,
			    &temp, 4);
			*pmac16++ = (temp & 0xffff);
			*pmac16 = 0;
		}
		return (0);
	}


	if (unm_get_flash_block(adapter, USER_START +
	    offsetof(unm_user_info_t, mac_addr), FLASH_NUM_PORTS * sizeof (U64),
	    pmac) == -1)
		return (-1);

	if (*mac == ~0ULL) {
		if (unm_get_flash_block(adapter, USER_START_OLD +
		    offsetof(unm_old_user_info_t, mac_addr),
		    FLASH_NUM_PORTS * sizeof (U64), pmac) == -1)
			return (-1);

		if (*mac == ~0ULL)
			return (-1);
	}

	return (0);
}

static int
unm_initialize_dummy_dma(unm_adapter *adapter)
{
	uint32_t		hi, lo, temp;
	ddi_dma_cookie_t	cookie;

	if (unm_pci_alloc_consistent(adapter, UNM_HOST_DUMMY_DMA_SIZE,
	    (caddr_t *)&adapter->dummy_dma.addr, &cookie,
	    &adapter->dummy_dma.dma_handle,
	    &adapter->dummy_dma.acc_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: Unable to alloc dummy dma buf\n",
		    adapter->name, adapter->instance);
		return (DDI_ENOMEM);
	}

	adapter->dummy_dma.phys_addr = cookie.dmac_laddress;

	hi = (adapter->dummy_dma.phys_addr >> 32) & 0xffffffff;
	lo = adapter->dummy_dma.phys_addr & 0xffffffff;

	UNM_READ_LOCK(&adapter->adapter_lock);
	adapter->unm_nic_hw_write_wx(adapter, CRB_HOST_DUMMY_BUF_ADDR_HI,
	    &hi, 4);
	adapter->unm_nic_hw_write_wx(adapter, CRB_HOST_DUMMY_BUF_ADDR_LO,
	    &lo, 4);
	if (NX_IS_REVISION_P3(adapter->ahw.revision_id)) {
		temp = DUMMY_BUF_INIT;
		adapter->unm_nic_hw_write_wx(adapter, CRB_HOST_DUMMY_BUF,
		    &temp, 4);
	}
	UNM_READ_UNLOCK(&adapter->adapter_lock);

	return (DDI_SUCCESS);
}

void
unm_free_dummy_dma(unm_adapter *adapter)
{
	if (adapter->dummy_dma.addr) {
		unm_pci_free_consistent(&adapter->dummy_dma.dma_handle,
		    &adapter->dummy_dma.acc_handle);
		adapter->dummy_dma.addr = NULL;
	}
}

static int
unm_pci_cfg_init(unm_adapter *adapter)
{
	hardware_context *hwcontext;
	ddi_acc_handle_t pci_cfg_hdl;
	int *reg_options;
	dev_info_t *dip;
	uint_t noptions;
	int ret;
	uint16_t vendor_id, pci_cmd_word;
	uint8_t	base_class, sub_class, prog_class;
	uint32_t pexsizes;
	struct nx_legacy_intr_set *legacy_intrp;

	hwcontext = &adapter->ahw;
	pci_cfg_hdl = adapter->pci_cfg_handle;
	dip = adapter->dip;

	vendor_id = pci_config_get16(pci_cfg_hdl, PCI_CONF_VENID);

	if (vendor_id != 0x4040) {
		cmn_err(CE_WARN, "%s%d: vendor id %x not 0x4040\n",
		    adapter->name, adapter->instance, vendor_id);
		return (DDI_FAILURE);
	}

	ret = ddi_prop_lookup_int_array(DDI_DEV_T_ANY,
	    dip, 0, "reg", &reg_options, &noptions);
	if (ret != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: Could not determine reg property\n",
		    adapter->name, adapter->instance);
		return (DDI_FAILURE);
	}

	hwcontext->pci_func = (reg_options[0] >> 8) & 0x7;
	ddi_prop_free(reg_options);

	base_class = pci_config_get8(pci_cfg_hdl, PCI_CONF_BASCLASS);
	sub_class = pci_config_get8(pci_cfg_hdl, PCI_CONF_SUBCLASS);
	prog_class = pci_config_get8(pci_cfg_hdl, PCI_CONF_PROGCLASS);

	/*
	 * Need this check so that MEZZ card mgmt interface ntxn0 could fail
	 * attach & return and proceed to next interfaces ntxn1 and ntxn2
	 */
	if ((base_class != 0x02) || (sub_class != 0) || (prog_class != 0)) {
		cmn_err(CE_WARN, "%s%d: Base/sub/prog class problem %d/%d/%d\n",
		    adapter->name, adapter->instance, base_class, sub_class,
		    prog_class);
		return (DDI_FAILURE);
	}

	hwcontext->revision_id = pci_config_get8(pci_cfg_hdl, PCI_CONF_REVID);

	/*
	 * Refuse to work with dubious P3 cards.
	 */
	if ((hwcontext->revision_id >= NX_P3_A0) &&
	    (hwcontext->revision_id < NX_P3_B1)) {
		cmn_err(CE_WARN, "%s%d: NetXen chip revs between 0x%x-0x%x "
		    "is unsupported\n", adapter->name, adapter->instance,
		    NX_P3_A0, NX_P3_B0);
		return (DDI_FAILURE);
	}

	/*
	 * Save error reporting settings; clear [19:16] error status bits.
	 * Set max read request [14:12] to 0 for 128 bytes. Set max payload
	 * size[7:5] to 0 for for 128 bytes.
	 */
	if (NX_IS_REVISION_P2(hwcontext->revision_id)) {
		pexsizes = pci_config_get32(pci_cfg_hdl, 0xd8);
		pexsizes &= 7;
		pexsizes |= 0xF0000;
		pci_config_put32(pci_cfg_hdl, 0xd8, pexsizes);
	}

	pci_cmd_word = pci_config_get16(pci_cfg_hdl, PCI_CONF_COMM);
	pci_cmd_word |= (PCI_COMM_INTX_DISABLE | PCI_COMM_SERR_ENABLE);
	pci_config_put16(pci_cfg_hdl, PCI_CONF_COMM, pci_cmd_word);

	if (hwcontext->revision_id >= NX_P3_B0)
		legacy_intrp = &legacy_intr[hwcontext->pci_func];
	else
		legacy_intrp = &legacy_intr[0];

	adapter->legacy_intr.int_vec_bit = legacy_intrp->int_vec_bit;
	adapter->legacy_intr.tgt_status_reg = legacy_intrp->tgt_status_reg;
	adapter->legacy_intr.tgt_mask_reg = legacy_intrp->tgt_mask_reg;
	adapter->legacy_intr.pci_int_reg = legacy_intrp->pci_int_reg;

	return (DDI_SUCCESS);
}

static void
unm_free_tx_dmahdl(unm_adapter *adapter)
{
	int i;
	unm_dmah_node_t	 *nodep;

	mutex_enter(&adapter->tx_lock);
	nodep = &adapter->tx_dma_hdls[0];

	for (i = 0; i < adapter->MaxTxDescCount + EXTRA_HANDLES; i++) {
		if (nodep->dmahdl != NULL) {
			ddi_dma_free_handle(&nodep->dmahdl);
			nodep->dmahdl = NULL;
		}
		nodep->next = NULL;
		nodep++;
	}

	adapter->dmahdl_pool = NULL;
	adapter->freehdls = 0;
	mutex_exit(&adapter->tx_lock);
}

static int
unm_alloc_tx_dmahdl(unm_adapter *adapter)
{
	int		i;
	unm_dmah_node_t	*nodep = &adapter->tx_dma_hdls[0];

	mutex_enter(&adapter->tx_lock);
	for (i = 0; i < adapter->MaxTxDescCount + EXTRA_HANDLES; i++) {
		if (ddi_dma_alloc_handle(adapter->dip, &unm_dma_attr_cmddesc,
		    DDI_DMA_DONTWAIT, NULL, &nodep->dmahdl) != DDI_SUCCESS) {
			mutex_exit(&adapter->tx_lock);
			goto alloc_hdl_fail;
		}

		if (i > 0)
			nodep->next = nodep - 1;
		nodep++;
	}

	adapter->dmahdl_pool = nodep - 1;
	adapter->freehdls = i;
	mutex_exit(&adapter->tx_lock);

	return (DDI_SUCCESS);

alloc_hdl_fail:
	unm_free_tx_dmahdl(adapter);
	cmn_err(CE_WARN, "%s%d: Failed transmit ring dma handle allocation\n",
	    adapter->name, adapter->instance);
	return (DDI_FAILURE);
}

static void
unm_free_dma_mem(dma_area_t *dma_p)
{
	if (dma_p->dma_hdl != NULL) {
		if (dma_p->ncookies) {
			(void) ddi_dma_unbind_handle(dma_p->dma_hdl);
			dma_p->ncookies = 0;
		}
	}
	if (dma_p->acc_hdl != NULL) {
		ddi_dma_mem_free(&dma_p->acc_hdl);
		dma_p->acc_hdl = NULL;
	}
	if (dma_p->dma_hdl != NULL) {
		ddi_dma_free_handle(&dma_p->dma_hdl);
		dma_p->dma_hdl = NULL;
	}
}

static int
unm_alloc_dma_mem(unm_adapter *adapter, int size, uint_t dma_flag,
	ddi_dma_attr_t *dma_attr_p, dma_area_t *dma_p)
{
	int ret;
	caddr_t vaddr;
	size_t actual_size;
	ddi_dma_cookie_t	cookie;

	ret = ddi_dma_alloc_handle(adapter->dip,
	    dma_attr_p, DDI_DMA_DONTWAIT,
	    NULL, &dma_p->dma_hdl);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: Failed ddi_dma_alloc_handle\n",
		    adapter->name, adapter->instance);
		goto dma_mem_fail;
	}

	ret = ddi_dma_mem_alloc(dma_p->dma_hdl,
	    size, &adapter->gc_attr_desc,
	    dma_flag & (DDI_DMA_STREAMING | DDI_DMA_CONSISTENT),
	    DDI_DMA_DONTWAIT, NULL, &vaddr, &actual_size,
	    &dma_p->acc_hdl);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: ddi_dma_mem_alloc() failed\n",
		    adapter->name, adapter->instance);
		goto dma_mem_fail;
	}

	if (actual_size < size) {
		cmn_err(CE_WARN, "%s%d: ddi_dma_mem_alloc() allocated small\n",
		    adapter->name, adapter->instance);
		goto dma_mem_fail;
	}

	ret = ddi_dma_addr_bind_handle(dma_p->dma_hdl,
	    NULL, vaddr, size, dma_flag, DDI_DMA_DONTWAIT,
	    NULL, &cookie, &dma_p->ncookies);
	if (ret != DDI_DMA_MAPPED || dma_p->ncookies != 1) {
		cmn_err(CE_WARN, "%s%d: ddi_dma_addr_bind_handle() failed, "
		    "%d, %d\n", adapter->name, adapter->instance, ret,
		    dma_p->ncookies);
		goto dma_mem_fail;
	}

	dma_p->dma_addr = cookie.dmac_laddress;
	dma_p->vaddr = vaddr;
	(void) memset(vaddr, 0, size);

	return (DDI_SUCCESS);

dma_mem_fail:
	unm_free_dma_mem(dma_p);
	return (DDI_FAILURE);
}

static void
unm_free_tx_buffers(unm_adapter *adapter)
{
	int i;
	dma_area_t *dma_p;
	struct unm_cmd_buffer *cmd_buf;
	unm_dmah_node_t	 *nodep;

	cmd_buf = &adapter->cmd_buf_arr[0];

	for (i = 0; i < adapter->MaxTxDescCount; i++) {
		dma_p = &cmd_buf->dma_area;
		unm_free_dma_mem(dma_p);
		nodep = cmd_buf->head;
		while (nodep != NULL) {
			(void) ddi_dma_unbind_handle(nodep->dmahdl);
			nodep = nodep->next;
		}
		if (cmd_buf->msg != NULL)
			freemsg(cmd_buf->msg);
		cmd_buf++;
	}
	adapter->freecmds = 0;
}

static int
unm_alloc_tx_buffers(unm_adapter *adapter)
{
	int i, ret, size, allocated = 0;
	dma_area_t *dma_p;
	struct unm_cmd_buffer *cmd_buf;

	cmd_buf = &adapter->cmd_buf_arr[0];
	size = adapter->maxmtu;

	for (i = 0; i < adapter->MaxTxDescCount; i++) {
		dma_p = &cmd_buf->dma_area;
		ret = unm_alloc_dma_mem(adapter, size,
		    DDI_DMA_WRITE | DDI_DMA_STREAMING,
		    &unm_dma_attr_rxbuf, dma_p);
		if (ret != DDI_SUCCESS)
			goto alloc_tx_buffer_fail;

		allocated++;
		cmd_buf++;
	}
	adapter->freecmds = adapter->MaxTxDescCount;
	return (DDI_SUCCESS);

alloc_tx_buffer_fail:

	cmd_buf = &adapter->cmd_buf_arr[0];
	for (i = 0; i < allocated; i++) {
		dma_p = &cmd_buf->dma_area;
		unm_free_dma_mem(dma_p);
		cmd_buf++;
	}
	cmn_err(CE_WARN, "%s%d: Failed transmit ring memory allocation\n",
	    adapter->name, adapter->instance);
	return (DDI_FAILURE);
}

/*
 * Called by freemsg() to "free" the resource.
 */
static void
unm_rx_buffer_recycle(char *arg)
{
	unm_rx_buffer_t *rx_buffer = (unm_rx_buffer_t *)(uintptr_t)arg;
	unm_adapter *adapter = rx_buffer->adapter;
	unm_rcv_desc_ctx_t *rcv_desc = rx_buffer->rcv_desc;

	rx_buffer->mp = desballoc(rx_buffer->dma_info.vaddr,
	    rcv_desc->dma_size, 0, &rx_buffer->rx_recycle);

	if (rx_buffer->mp == NULL)
		adapter->stats.desballocfailed++;

	mutex_enter(rcv_desc->recycle_lock);
	rx_buffer->next = rcv_desc->recycle_list;
	rcv_desc->recycle_list = rx_buffer;
	rcv_desc->rx_buf_recycle++;
	mutex_exit(rcv_desc->recycle_lock);
}

static void
unm_destroy_rx_ring(unm_rcv_desc_ctx_t *rcv_desc)
{
	uint32_t i, total_buf;
	unm_rx_buffer_t *buf_pool;

	total_buf = rcv_desc->rx_buf_total;
	buf_pool = rcv_desc->rx_buf_pool;
	for (i = 0; i < total_buf; i++) {
		if (buf_pool->mp != NULL)
			freemsg(buf_pool->mp);
		unm_free_dma_mem(&buf_pool->dma_info);
		buf_pool++;
	}

	kmem_free(rcv_desc->rx_buf_pool, sizeof (unm_rx_buffer_t) * total_buf);
	rcv_desc->rx_buf_pool = NULL;
	rcv_desc->pool_list = NULL;
	rcv_desc->recycle_list = NULL;
	rcv_desc->rx_buf_free = 0;

	mutex_destroy(rcv_desc->pool_lock);
	mutex_destroy(rcv_desc->recycle_lock);
}

static int
unm_create_rx_ring(unm_adapter *adapter, unm_rcv_desc_ctx_t *rcv_desc)
{
	int		i, ret, allocate = 0, sreoff;
	uint32_t	total_buf;
	dma_area_t	*dma_info;
	unm_rx_buffer_t	*rx_buffer;

	sreoff = adapter->ahw.cut_through ? 0 : IP_ALIGNMENT_BYTES;

	/* temporarily set the total rx buffers two times of MaxRxDescCount */
	total_buf = rcv_desc->rx_buf_total = rcv_desc->MaxRxDescCount * 2;

	rcv_desc->rx_buf_pool = kmem_zalloc(sizeof (unm_rx_buffer_t) *
	    total_buf, KM_SLEEP);
	rx_buffer = rcv_desc->rx_buf_pool;
	for (i = 0; i < total_buf; i++) {
		dma_info = &rx_buffer->dma_info;
		ret = unm_alloc_dma_mem(adapter, rcv_desc->buf_size,
		    DDI_DMA_READ | DDI_DMA_STREAMING,
		    &unm_dma_attr_rxbuf, dma_info);
		if (ret != DDI_SUCCESS)
			goto alloc_mem_failed;
		else {
			allocate++;
			dma_info->vaddr = (void *) ((char *)dma_info->vaddr +
			    sreoff);
			dma_info->dma_addr += sreoff;
			rx_buffer->rx_recycle.free_func =
			    unm_rx_buffer_recycle;
			rx_buffer->rx_recycle.free_arg = (caddr_t)rx_buffer;
			rx_buffer->next = NULL;
			rx_buffer->mp = desballoc(dma_info->vaddr,
			    rcv_desc->dma_size, 0, &rx_buffer->rx_recycle);
			if (rx_buffer->mp == NULL)
				adapter->stats.desballocfailed++;
			rx_buffer->rcv_desc = rcv_desc;
			rx_buffer->adapter = adapter;
			rx_buffer++;
		}
	}

	for (i = 0; i < (total_buf - 1); i++) {
		rcv_desc->rx_buf_pool[i].next = &rcv_desc->rx_buf_pool[i + 1];
	}

	rcv_desc->pool_list = rcv_desc->rx_buf_pool;
	rcv_desc->recycle_list = NULL;
	rcv_desc->rx_buf_free = total_buf;

	mutex_init(rcv_desc->pool_lock, NULL,
	    MUTEX_DRIVER, (DDI_INTR_PRI(adapter->intr_pri)));
	mutex_init(rcv_desc->recycle_lock, NULL,
	    MUTEX_DRIVER, (DDI_INTR_PRI(adapter->intr_pri)));

	return (DDI_SUCCESS);

alloc_mem_failed:
	rx_buffer = rcv_desc->rx_buf_pool;
	for (i = 0; i < allocate; i++, rx_buffer++) {
		dma_info = &rx_buffer->dma_info;
		if (rx_buffer->mp != NULL)
			freemsg(rx_buffer->mp);
		unm_free_dma_mem(dma_info);
	}

	kmem_free(rcv_desc->rx_buf_pool, sizeof (unm_rx_buffer_t) * total_buf);
	rcv_desc->rx_buf_pool = NULL;

	cmn_err(CE_WARN, "%s%d: Failed receive ring resource allocation\n",
	    adapter->name, adapter->instance);
	return (DDI_FAILURE);
}

static void
unm_check_options(unm_adapter *adapter)
{
	int			i, ring, tx_desc, rx_desc, rx_jdesc, maxrx;
	unm_recv_context_t	*recv_ctx;
	unm_rcv_desc_ctx_t	*rcv_desc;
	uint8_t			revid = adapter->ahw.revision_id;
	dev_info_t		*dip = adapter->dip;

	/*
	 * Reduce number of regular rcv desc to half on x86.
	 */
	maxrx = MAX_RCV_DESCRIPTORS;
#if !defined(_LP64)
	maxrx /= 2;
#endif /* !_LP64 */

	verbmsg = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    dmesg_propname, 0);

	adapter->tx_bcopy_threshold = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dip, DDI_PROP_DONTPASS, txbcopythreshold_propname,
	    UNM_TX_BCOPY_THRESHOLD);
	adapter->rx_bcopy_threshold = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dip, DDI_PROP_DONTPASS, rxbcopythreshold_propname,
	    UNM_RX_BCOPY_THRESHOLD);

	tx_desc = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    txringsize_propname, MAX_CMD_DESCRIPTORS_HOST);
	if (tx_desc >= 256 && tx_desc <= MAX_CMD_DESCRIPTORS && ISP2(tx_desc)) {
		adapter->MaxTxDescCount = tx_desc;
	} else {
		cmn_err(CE_WARN, "%s%d: TxRingSize defaulting to %d, since "
		    ".conf value is not 2 power aligned in range 256 - %d\n",
		    adapter->name, adapter->instance, MAX_CMD_DESCRIPTORS_HOST,
		    MAX_CMD_DESCRIPTORS);
		adapter->MaxTxDescCount = MAX_CMD_DESCRIPTORS_HOST;
	}

	rx_desc = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    rxringsize_propname, maxrx);
	if (rx_desc >= NX_MIN_DRIVER_RDS_SIZE &&
	    rx_desc <= NX_MAX_SUPPORTED_RDS_SIZE && ISP2(rx_desc)) {
		adapter->MaxRxDescCount = rx_desc;
	} else {
		cmn_err(CE_WARN, "%s%d: RxRingSize defaulting to %d, since "
		    ".conf value is not 2 power aligned in range %d - %d\n",
		    adapter->name, adapter->instance, MAX_RCV_DESCRIPTORS,
		    NX_MIN_DRIVER_RDS_SIZE, NX_MAX_SUPPORTED_RDS_SIZE);
		adapter->MaxRxDescCount = MAX_RCV_DESCRIPTORS;
	}

	rx_jdesc = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    jumborxringsize_propname, MAX_JUMBO_RCV_DESCRIPTORS);
	if (rx_jdesc >= NX_MIN_DRIVER_RDS_SIZE &&
	    rx_jdesc <= NX_MAX_SUPPORTED_JUMBO_RDS_SIZE && ISP2(rx_jdesc)) {
		adapter->MaxJumboRxDescCount = rx_jdesc;
	} else {
		cmn_err(CE_WARN, "%s%d: JumboRingSize defaulting to %d, since "
		    ".conf value is not 2 power aligned in range %d - %d\n",
		    adapter->name, adapter->instance, MAX_JUMBO_RCV_DESCRIPTORS,
		    NX_MIN_DRIVER_RDS_SIZE, NX_MAX_SUPPORTED_JUMBO_RDS_SIZE);
		adapter->MaxJumboRxDescCount = MAX_JUMBO_RCV_DESCRIPTORS;
	}

	/*
	 * Solaris does not use LRO, but older firmware needs to have a
	 * couple of descriptors for initialization.
	 */
	adapter->MaxLroRxDescCount = (adapter->fw_major < 4) ? 2 : 0;

	adapter->mtu = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, defaultmtu_propname, MTU_SIZE);

	if (adapter->mtu < MTU_SIZE) {
		cmn_err(CE_WARN, "Raising mtu to %d\n", MTU_SIZE);
		adapter->mtu = MTU_SIZE;
	}
	adapter->maxmtu = NX_IS_REVISION_P2(revid) ? P2_MAX_MTU : P3_MAX_MTU;
	if (adapter->mtu > adapter->maxmtu) {
		cmn_err(CE_WARN, "Lowering mtu to %d\n", adapter->maxmtu);
		adapter->mtu = adapter->maxmtu;
	}

	adapter->maxmtu = adapter->mtu + NX_MAX_ETHERHDR;

	/*
	 * If we are not expecting to receive jumbo frames, save memory and
	 * do not allocate.
	 */
	if (adapter->mtu <= MTU_SIZE)
		adapter->MaxJumboRxDescCount = NX_MIN_DRIVER_RDS_SIZE;

	for (i = 0; i < MAX_RCV_CTX; ++i) {
		recv_ctx = &adapter->recv_ctx[i];

		for (ring = 0; ring < adapter->max_rds_rings; ring++) {
			rcv_desc = &recv_ctx->rcv_desc[ring];

			switch (RCV_DESC_TYPE(ring)) {
			case RCV_DESC_NORMAL:
				rcv_desc->MaxRxDescCount =
				    adapter->MaxRxDescCount;
				if (adapter->ahw.cut_through) {
					rcv_desc->dma_size =
					    NX_CT_DEFAULT_RX_BUF_LEN;
					rcv_desc->buf_size = rcv_desc->dma_size;
				} else {
					rcv_desc->dma_size =
					    NX_RX_NORMAL_BUF_MAX_LEN;
					rcv_desc->buf_size =
					    rcv_desc->dma_size +
					    IP_ALIGNMENT_BYTES;
				}
				break;

			case RCV_DESC_JUMBO:
				rcv_desc->MaxRxDescCount =
				    adapter->MaxJumboRxDescCount;
				if (adapter->ahw.cut_through) {
					rcv_desc->dma_size =
					    rcv_desc->buf_size =
					    NX_P3_RX_JUMBO_BUF_MAX_LEN;
				} else {
					if (NX_IS_REVISION_P2(revid))
						rcv_desc->dma_size =
						    NX_P2_RX_JUMBO_BUF_MAX_LEN;
					else
						rcv_desc->dma_size =
						    NX_P3_RX_JUMBO_BUF_MAX_LEN;
					rcv_desc->buf_size =
					    rcv_desc->dma_size +
					    IP_ALIGNMENT_BYTES;
				}
				break;

			case RCV_RING_LRO:
				rcv_desc->MaxRxDescCount =
				    adapter->MaxLroRxDescCount;
				rcv_desc->buf_size = MAX_RX_LRO_BUFFER_LENGTH;
				rcv_desc->dma_size = RX_LRO_DMA_MAP_LEN;
				break;
			default:
				break;
			}
		}
	}
}

static void
vector128M(unm_adapter *aptr)
{
	aptr->unm_nic_pci_change_crbwindow = &unm_nic_pci_change_crbwindow_128M;
	aptr->unm_crb_writelit_adapter = &unm_crb_writelit_adapter_128M;
	aptr->unm_nic_hw_write_wx = &unm_nic_hw_write_wx_128M;
	aptr->unm_nic_hw_read_wx = &unm_nic_hw_read_wx_128M;
	aptr->unm_nic_hw_write_ioctl = &unm_nic_hw_write_ioctl_128M;
	aptr->unm_nic_hw_read_ioctl = &unm_nic_hw_read_ioctl_128M;
	aptr->unm_nic_pci_mem_write = &unm_nic_pci_mem_write_128M;
	aptr->unm_nic_pci_mem_read = &unm_nic_pci_mem_read_128M;
	aptr->unm_nic_pci_write_immediate = &unm_nic_pci_write_immediate_128M;
	aptr->unm_nic_pci_read_immediate = &unm_nic_pci_read_immediate_128M;
	aptr->unm_nic_pci_write_normalize = &unm_nic_pci_write_normalize_128M;
	aptr->unm_nic_pci_read_normalize = &unm_nic_pci_read_normalize_128M;
	aptr->unm_nic_pci_set_window = &unm_nic_pci_set_window_128M;
	aptr->unm_nic_clear_statistics = &unm_nic_clear_statistics_128M;
	aptr->unm_nic_fill_statistics = &unm_nic_fill_statistics_128M;
}

static void
vector2M(unm_adapter *aptr)
{
	aptr->unm_nic_pci_change_crbwindow = &unm_nic_pci_change_crbwindow_2M;
	aptr->unm_crb_writelit_adapter = &unm_crb_writelit_adapter_2M;
	aptr->unm_nic_hw_write_wx = &unm_nic_hw_write_wx_2M;
	aptr->unm_nic_hw_read_wx = &unm_nic_hw_read_wx_2M;
	aptr->unm_nic_hw_write_ioctl = &unm_nic_hw_write_wx_2M;
	aptr->unm_nic_hw_read_ioctl = &unm_nic_hw_read_wx_2M;
	aptr->unm_nic_pci_mem_write = &unm_nic_pci_mem_write_2M;
	aptr->unm_nic_pci_mem_read = &unm_nic_pci_mem_read_2M;
	aptr->unm_nic_pci_write_immediate = &unm_nic_pci_write_immediate_2M;
	aptr->unm_nic_pci_read_immediate = &unm_nic_pci_read_immediate_2M;
	aptr->unm_nic_pci_write_normalize = &unm_nic_pci_write_normalize_2M;
	aptr->unm_nic_pci_read_normalize = &unm_nic_pci_read_normalize_2M;
	aptr->unm_nic_pci_set_window = &unm_nic_pci_set_window_2M;
	aptr->unm_nic_clear_statistics = &unm_nic_clear_statistics_2M;
	aptr->unm_nic_fill_statistics = &unm_nic_fill_statistics_2M;
}

static int
unm_pci_map_setup(unm_adapter *adapter)
{
	int ret;
	caddr_t reg_base, db_base;
	caddr_t mem_ptr0, mem_ptr1 = NULL, mem_ptr2 = NULL;
	unsigned long pci_len0;
	unsigned long first_page_group_start, first_page_group_end;

	off_t regsize, dbsize = UNM_DB_MAPSIZE_BYTES;
	dev_info_t *dip = adapter->dip;

	adapter->ahw.qdr_sn_window = adapter->ahw.ddr_mn_window = -1;

	/* map register space */

	ret = ddi_dev_regsize(dip, 1, &regsize);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: failed to read reg size for bar0\n",
		    adapter->name, adapter->instance);
		return (DDI_FAILURE);
	}

	ret = ddi_regs_map_setup(dip, 1, &reg_base, 0,
	    regsize, &unm_dev_attr, &adapter->regs_handle);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: failed to map registers\n",
		    adapter->name, adapter->instance);
		return (DDI_FAILURE);
	}

	mem_ptr0 = reg_base;

	if (regsize == UNM_PCI_128MB_SIZE) {
		pci_len0 = FIRST_PAGE_GROUP_SIZE;
		mem_ptr1 = mem_ptr0 + SECOND_PAGE_GROUP_START;
		mem_ptr2 = mem_ptr0 + THIRD_PAGE_GROUP_START;
		first_page_group_start = FIRST_PAGE_GROUP_START;
		first_page_group_end   = FIRST_PAGE_GROUP_END;
		vector128M(adapter);
	} else if (regsize == UNM_PCI_32MB_SIZE) {
		pci_len0 = 0;
		mem_ptr1 = mem_ptr0;
		mem_ptr2 = mem_ptr0 +
		    (THIRD_PAGE_GROUP_START - SECOND_PAGE_GROUP_START);
		first_page_group_start = 0;
		first_page_group_end   = 0;
		vector128M(adapter);
	} else if (regsize == UNM_PCI_2MB_SIZE) {
		pci_len0 = UNM_PCI_2MB_SIZE;
		first_page_group_start = 0;
		first_page_group_end = 0;
		adapter->ahw.ddr_mn_window = adapter->ahw.qdr_sn_window = 0;
		adapter->ahw.mn_win_crb = 0x100000 + PCIX_MN_WINDOW +
		    (adapter->ahw.pci_func * 0x20);
		if (adapter->ahw.pci_func < 4)
			adapter->ahw.ms_win_crb = 0x100000 + PCIX_SN_WINDOW +
			    (adapter->ahw.pci_func * 0x20);
		else
			adapter->ahw.ms_win_crb = 0x100000 + PCIX_SN_WINDOW +
			    0xA0 + ((adapter->ahw.pci_func - 4) * 0x10);
		vector2M(adapter);
	} else {
		cmn_err(CE_WARN, "%s%d: invalid pci regs map size %ld\n",
		    adapter->name, adapter->instance, regsize);
		ddi_regs_map_free(&adapter->regs_handle);
		return (DDI_FAILURE);
	}

	adapter->ahw.pci_base0  = (unsigned long)mem_ptr0;
	adapter->ahw.pci_len0   = pci_len0;
	adapter->ahw.pci_base1  = (unsigned long)mem_ptr1;
	adapter->ahw.pci_len1   = SECOND_PAGE_GROUP_SIZE;
	adapter->ahw.pci_base2  = (unsigned long)mem_ptr2;
	adapter->ahw.pci_len2   = THIRD_PAGE_GROUP_SIZE;
	adapter->ahw.crb_base   =
	    PCI_OFFSET_SECOND_RANGE(adapter, UNM_PCI_CRBSPACE);

	adapter->ahw.first_page_group_start = first_page_group_start;
	adapter->ahw.first_page_group_end   = first_page_group_end;

	/* map doorbell */

	ret = ddi_regs_map_setup(dip, 2, &db_base, 0,
	    dbsize, &unm_dev_attr, &adapter->db_handle);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: failed to map doorbell\n",
		    adapter->name, adapter->instance);
		ddi_regs_map_free(&adapter->regs_handle);
		return (DDI_FAILURE);
	}

	adapter->ahw.db_base   = (unsigned long)db_base;
	adapter->ahw.db_len    = dbsize;

	return (DDI_SUCCESS);
}

static int
unm_initialize_intr(unm_adapter *adapter)
{

	int		ret;
	int		type, count, avail, actual;

	ret = ddi_intr_get_supported_types(adapter->dip, &type);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: ddi_intr_get_supported_types() "
		    "failed\n", adapter->name, adapter->instance);
		return (DDI_FAILURE);
	}

	type = DDI_INTR_TYPE_MSI;
	ret = ddi_intr_get_nintrs(adapter->dip, type, &count);
	if ((ret == DDI_SUCCESS) && (count > 0))
		goto found_msi;

	type = DDI_INTR_TYPE_FIXED;
	ret = ddi_intr_get_nintrs(adapter->dip, type, &count);
	if ((ret != DDI_SUCCESS) || (count == 0)) {
		cmn_err(CE_WARN,
		    "ddi_intr_get_nintrs() failure ret=%d\n", ret);
		return (DDI_FAILURE);
	}

found_msi:
	adapter->intr_type = type;
	adapter->flags &= ~(UNM_NIC_MSI_ENABLED | UNM_NIC_MSIX_ENABLED);
	if (type == DDI_INTR_TYPE_MSI)
		adapter->flags |= UNM_NIC_MSI_ENABLED;

	/* Get number of available interrupts */
	ret = ddi_intr_get_navail(adapter->dip, type, &avail);
	if ((ret != DDI_SUCCESS) || (avail == 0)) {
		cmn_err(CE_WARN, "ddi_intr_get_navail() failure, ret=%d\n",
		    ret);
		return (DDI_FAILURE);
	}

	ret = ddi_intr_alloc(adapter->dip, &adapter->intr_handle,
	    type, 0, 1, &actual, DDI_INTR_ALLOC_NORMAL);
	if ((ret != DDI_SUCCESS) || (actual == 0)) {
		cmn_err(CE_WARN, "ddi_intr_alloc() failure: %d\n", ret);
		return (DDI_FAILURE);
	}

	ret = ddi_intr_get_pri(adapter->intr_handle, &adapter->intr_pri);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "ddi_intr_get_pri() failure: %d\n", ret);
	}

	/* Call ddi_intr_add_handler() */
	ret = ddi_intr_add_handler(adapter->intr_handle, unm_intr,
	    (caddr_t)adapter, NULL);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: ddi_intr_add_handler() failure\n",
		    adapter->name, adapter->instance);
		(void) ddi_intr_free(adapter->intr_handle);
		return (DDI_FAILURE);
	}

	/* Add softintr if required */

	return (DDI_SUCCESS);

}

void
unm_destroy_intr(unm_adapter *adapter)
{
	/* disable interrupt */
	if (adapter->intr_type == DDI_INTR_TYPE_MSI)
		(void) ddi_intr_block_disable(&adapter->intr_handle, 1);
	else
		(void) ddi_intr_disable(adapter->intr_handle);

	(void) ddi_intr_remove_handler(adapter->intr_handle);
	(void) ddi_intr_free(adapter->intr_handle);

	/* Remove the software intr handler */
}

static void
netxen_set_port_mode(unm_adapter *adapter)
{
	static int	wol_port_mode = UNM_PORT_MODE_AUTO_NEG_1G;
	static int	port_mode = UNM_PORT_MODE_AUTO_NEG;
	int		btype = adapter->ahw.boardcfg.board_type, data = 0;

	if (btype == UNM_BRDTYPE_P3_HMEZ || btype == UNM_BRDTYPE_P3_XG_LOM) {
		data = port_mode;	/* set to port_mode normally */
		if ((port_mode != UNM_PORT_MODE_802_3_AP) &&
		    (port_mode != UNM_PORT_MODE_XG) &&
		    (port_mode != UNM_PORT_MODE_AUTO_NEG_1G) &&
		    (port_mode != UNM_PORT_MODE_AUTO_NEG_XG))
			data = UNM_PORT_MODE_AUTO_NEG;

		adapter->unm_nic_hw_write_wx(adapter, UNM_PORT_MODE_ADDR,
		    &data, 4);

		if ((wol_port_mode != UNM_PORT_MODE_802_3_AP) &&
		    (wol_port_mode != UNM_PORT_MODE_XG) &&
		    (wol_port_mode != UNM_PORT_MODE_AUTO_NEG_1G) &&
		    (wol_port_mode != UNM_PORT_MODE_AUTO_NEG_XG))
			wol_port_mode = UNM_PORT_MODE_AUTO_NEG;

		adapter->unm_nic_hw_write_wx(adapter, UNM_WOL_PORT_MODE,
		    &wol_port_mode, 4);
	}
}

static void
netxen_pcie_strap_init(unm_adapter *adapter)
{
	ddi_acc_handle_t	pcihdl = adapter->pci_cfg_handle;
	u32			chicken, control, c8c9value = 0xF1000;

	adapter->unm_nic_hw_read_wx(adapter, UNM_PCIE_REG(PCIE_CHICKEN3),
	    &chicken, 4);

	chicken &= 0xFCFFFFFF;		/* clear chicken3 25:24 */
	control = pci_config_get32(pcihdl, 0xD0);
	if ((control & 0x000F0000) != 0x00020000)	/* is it gen1? */
		chicken |= 0x01000000;
	adapter->unm_nic_hw_write_wx(adapter, UNM_PCIE_REG(PCIE_CHICKEN3),
	    &chicken, 4);
	control = pci_config_get32(pcihdl, 0xC8);
	control = pci_config_get32(pcihdl, 0xC8);
	pci_config_put32(pcihdl, 0xC8, c8c9value);
}

static int
netxen_read_mac_addr(unm_adapter *adapter)
{
	u64		mac_addr[8 + 1];
	unsigned char	*p;
	int		i;

	if (get_flash_mac_addr(adapter, mac_addr) != 0)
		return (-1);

	if (NX_IS_REVISION_P3(adapter->ahw.revision_id))
		p = (unsigned char *)&mac_addr[adapter->ahw.pci_func];
	else
		p = (unsigned char *)&mac_addr[adapter->portnum];

	for (i = 0; i < 6; i++)
		adapter->mac_addr[i] = p[5 - i];

	if (unm_nic_macaddr_set(adapter, adapter->mac_addr) != 0)
		return (-1);

	return (0);
}

static int
unmattach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	unm_adapter			*adapter;
	int				i, first_driver = 0;
	int				ret, temp;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
	case DDI_PM_RESUME:
	default:
		return (DDI_FAILURE);
	}

	adapter = kmem_zalloc(sizeof (unm_adapter), KM_SLEEP);
	adapter->dip = dip;
	ddi_set_driver_private(dip, adapter);
	adapter->instance = ddi_get_instance(dip);

	adapter->name = ddi_driver_name(dip);

	ret = pci_config_setup(dip, &adapter->pci_cfg_handle);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: pci_config_setup failed\n",
		    adapter->name, adapter->instance);
		goto attach_setup_err;
	}

	ret = unm_pci_cfg_init(adapter);
	if (ret != DDI_SUCCESS)
		goto attach_err;

	ret = unm_pci_map_setup(adapter);
	if (ret != DDI_SUCCESS)
		goto attach_err;

	if (unm_initialize_intr(adapter) != DDI_SUCCESS)
		goto attach_unmap_regs;

	rw_init(&adapter->adapter_lock, NULL,
	    RW_DRIVER, DDI_INTR_PRI(adapter->intr_pri));
	mutex_init(&adapter->tx_lock, NULL,
	    MUTEX_DRIVER, (DDI_INTR_PRI(adapter->intr_pri)));
	mutex_init(&adapter->lock, NULL,
	    MUTEX_DRIVER, (DDI_INTR_PRI(adapter->intr_pri)));

	adapter->portnum = (int8_t)adapter->ahw.pci_func;

	/*
	 * Set the CRB window to invalid. If any register in window 0 is
	 * accessed it should set window to 0 and then reset it to 1.
	 */
	adapter->curr_window = 255;

	adapter->fw_major = adapter->unm_nic_pci_read_normalize(adapter,
	    UNM_FW_VERSION_MAJOR);

	if (adapter->fw_major < 4)
		adapter->max_rds_rings = 3;
	else
		adapter->max_rds_rings = 2;

	STRUCT_COPY(adapter->gc_dma_attr_desc, unm_dma_attr_desc);
	STRUCT_COPY(adapter->gc_attr_desc, unm_buf_attr);

	ret = unm_nic_get_board_info(adapter);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: error reading board config\n",
		    adapter->name, adapter->instance);
		goto attach_destroy_intr;
	}

	/* Mezz cards have PCI function 0, 2, 3 enabled */
	switch (adapter->ahw.boardcfg.board_type) {
	case UNM_BRDTYPE_P2_SB31_10G_IMEZ:
	case UNM_BRDTYPE_P2_SB31_10G_HMEZ:
		if (adapter->ahw.pci_func >= 2) {
			adapter->portnum = adapter->ahw.pci_func - 2;
		}
	default:
		break;
	}

	if (NX_IS_REVISION_P3(adapter->ahw.revision_id)) {
		temp = UNM_CRB_READ_VAL_ADAPTER(UNM_MIU_MN_CONTROL, adapter);
		adapter->ahw.cut_through = NX_IS_SYSTEM_CUT_THROUGH(temp);
		if (adapter->ahw.pci_func == 0)
			first_driver = 1;
	} else {
		if (adapter->portnum == 0)
			first_driver = 1;
	}

	unm_check_options(adapter);

	if (first_driver) {
		int first_boot = adapter->unm_nic_pci_read_normalize(adapter,
		    UNM_CAM_RAM(0x1fc));

		if (check_hw_init(adapter) != 0) {
			cmn_err(CE_WARN, "%s%d: Error in HW init sequence\n",
			    adapter->name, adapter->instance);
			goto attach_destroy_intr;
		}

		if (NX_IS_REVISION_P3(adapter->ahw.revision_id))
			netxen_set_port_mode(adapter);

		if (first_boot != 0x55555555) {
			temp = 0;
			adapter->unm_nic_hw_write_wx(adapter, CRB_CMDPEG_STATE,
			    &temp, 4);
			if (pinit_from_rom(adapter, 0) != 0)
				goto attach_destroy_intr;

			drv_usecwait(500);

			ret = load_from_flash(adapter);
			if (ret != DDI_SUCCESS)
				goto attach_destroy_intr;
		}

		if (ret = unm_initialize_dummy_dma(adapter))
			goto attach_destroy_intr;

		/*
		 * Tell the hardware our version number.
		 */
		i = (_UNM_NIC_MAJOR << 16) |
		    ((_UNM_NIC_MINOR << 8)) | (_UNM_NIC_SUBVERSION);
		adapter->unm_nic_hw_write_wx(adapter, CRB_DRIVER_VERSION,
		    &i, 4);

		/* Unlock the HW, prompting the boot sequence */
		if ((first_boot == 0x55555555) &&
		    (NX_IS_REVISION_P2(adapter->ahw.revision_id)))
			adapter->unm_nic_pci_write_normalize(adapter,
			    UNM_ROMUSB_GLB_PEGTUNE_DONE, 1);

		/* Handshake with the card before we register the devices. */
		if (phantom_init(adapter, 0) != DDI_SUCCESS)
			goto attach_destroy_intr;
	}

	if (NX_IS_REVISION_P3(adapter->ahw.revision_id))
		netxen_pcie_strap_init(adapter);

	/*
	 * See if the firmware gave us a virtual-physical port mapping.
	 */
	adapter->physical_port = adapter->portnum;
	i = adapter->unm_nic_pci_read_normalize(adapter,
	    CRB_V2P(adapter->portnum));
	if (i != 0x55555555)
		adapter->physical_port = (uint16_t)i;

	adapter->ahw.linkup = 0;

	if (receive_peg_ready(adapter)) {
		ret = -EIO;
		goto free_dummy_dma;
	}

	if (netxen_read_mac_addr(adapter))
		cmn_err(CE_WARN, "%s%d: Failed to read MAC addr\n",
		    adapter->name, adapter->instance);

	unm_nic_flash_print(adapter);

	if (verbmsg != 0) {
		switch (adapter->ahw.board_type) {
		case UNM_NIC_GBE:
			cmn_err(CE_NOTE, "%s: QUAD GbE port %d initialized\n",
			    unm_nic_driver_name, adapter->portnum);
			break;

		case UNM_NIC_XGBE:
			cmn_err(CE_NOTE, "%s: XGbE port %d initialized\n",
			    unm_nic_driver_name, adapter->portnum);
			break;
		}
	}

	ret = unm_register_mac(adapter);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "%s%d: Mac registration error\n",
		    adapter->name, adapter->instance);
		goto free_dummy_dma;
	}

	return (DDI_SUCCESS);

free_dummy_dma:
	if (first_driver)
		unm_free_dummy_dma(adapter);
attach_destroy_intr:
	unm_destroy_intr(adapter);
attach_unmap_regs:
	ddi_regs_map_free(&(adapter->regs_handle));
	ddi_regs_map_free(&(adapter->db_handle));
attach_err:
	pci_config_teardown(&adapter->pci_cfg_handle);
attach_setup_err:
	kmem_free(adapter, sizeof (unm_adapter));
	return (ret);
}

static int
unmdetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	unm_adapter  *adapter = (unm_adapter *)ddi_get_driver_private(dip);

	if (adapter == NULL)
	return (DDI_FAILURE);

	switch (cmd) {
	case DDI_DETACH:
		unm_fini_kstats(adapter);
		adapter->kstats[0] = NULL;

		if (adapter->pci_cfg_handle != NULL)
			pci_config_teardown(&adapter->pci_cfg_handle);

		unm_nd_cleanup(adapter);
		unm_nic_remove(adapter);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (unm_nic_suspend(adapter));

	default:
		break;
	}

	return (DDI_FAILURE);
}

int
create_rxtx_rings(unm_adapter *adapter)
{
	unm_recv_context_t	*recv_ctx;
	unm_rcv_desc_ctx_t	*rcv_desc;
	int			i, ring;

	adapter->cmd_buf_arr = (struct unm_cmd_buffer *)kmem_zalloc(
	    sizeof (struct unm_cmd_buffer) * adapter->MaxTxDescCount,
	    KM_SLEEP);

	for (i = 0; i < MAX_RCV_CTX; ++i) {
		recv_ctx = &adapter->recv_ctx[i];

		for (ring = 0; ring < adapter->max_rds_rings; ring++) {
			rcv_desc = &recv_ctx->rcv_desc[ring];
			if (unm_create_rx_ring(adapter, rcv_desc) !=
			    DDI_SUCCESS)
				goto attach_free_cmdbufs;
		}
	}

	if (unm_alloc_tx_dmahdl(adapter) != DDI_SUCCESS)
		goto attach_free_cmdbufs;

	if (unm_alloc_tx_buffers(adapter) != DDI_SUCCESS)
		goto attach_free_tx_dmahdl;

	return (DDI_SUCCESS);

attach_free_tx_buffers:
	unm_free_tx_buffers(adapter);
attach_free_tx_dmahdl:
	unm_free_tx_dmahdl(adapter);
attach_free_cmdbufs:
	kmem_free(adapter->cmd_buf_arr, sizeof (struct unm_cmd_buffer) *
	    adapter->MaxTxDescCount);
	for (i = 0; i < MAX_RCV_CTX; ++i) {
		recv_ctx = &adapter->recv_ctx[i];

		for (ring = 0; ring < adapter->max_rds_rings; ring++) {
			rcv_desc = &recv_ctx->rcv_desc[ring];
			if (rcv_desc->rx_buf_pool != NULL)
				unm_destroy_rx_ring(rcv_desc);
		}
	}
	return (DDI_FAILURE);
}

void
destroy_rxtx_rings(unm_adapter *adapter)
{
	unm_recv_context_t	*recv_ctx;
	unm_rcv_desc_ctx_t	*rcv_desc;
	int			ctx, ring;

	unm_free_tx_buffers(adapter);
	unm_free_tx_dmahdl(adapter);

	for (ctx = 0; ctx < MAX_RCV_CTX; ++ctx) {
		recv_ctx = &adapter->recv_ctx[ctx];
		for (ring = 0; ring < adapter->max_rds_rings; ring++) {
			rcv_desc = &recv_ctx->rcv_desc[ring];
			if (rcv_desc->rx_buf_pool != NULL)
				unm_destroy_rx_ring(rcv_desc);
		}
	}

	if (adapter->cmd_buf_arr != NULL)
		kmem_free(adapter->cmd_buf_arr,
		    sizeof (struct unm_cmd_buffer) * adapter->MaxTxDescCount);
}

#ifdef SOLARIS11
DDI_DEFINE_STREAM_OPS(unm_ops, nulldev, nulldev, unmattach, unmdetach,
	nodev, NULL, D_MP, NULL, NULL);
#else
DDI_DEFINE_STREAM_OPS(unm_ops, nulldev, nulldev, unmattach, unmdetach,
	nodev, NULL, D_MP, NULL);
#endif

static struct modldrv modldrv = {
	&mod_driverops,	/* Type of module.  This one is a driver */
	ident,
	&unm_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(&modldrv),
	NULL
};


int
_init(void)
{
	int ret;

	unm_ops.devo_cb_ops->cb_str = NULL;
	mac_init_ops(&unm_ops, "ntxn");

	ret = mod_install(&modlinkage);
	if (ret != DDI_SUCCESS) {
		mac_fini_ops(&unm_ops);
		cmn_err(CE_WARN, "ntxn: mod_install failed\n");
	}

	return (ret);
}


int
_fini(void)
{
	int ret;

	ret = mod_remove(&modlinkage);
	if (ret == DDI_SUCCESS)
		mac_fini_ops(&unm_ops);
	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
