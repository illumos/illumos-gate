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
 * Copyright 2010 QLogic Corporation. All rights reserved.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <qlge.h>
#include <sys/atomic.h>
#include <sys/strsubr.h>
#include <sys/pattr.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <inet/ip.h>



/*
 * Local variables
 */
static struct ether_addr ql_ether_broadcast_addr =
	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static char version[] = "GLDv3 QLogic 81XX " VERSIONSTR;

/*
 * Local function prototypes
 */
static void ql_free_resources(qlge_t *);
static void ql_fini_kstats(qlge_t *);
static uint32_t ql_get_link_state(qlge_t *);
static void ql_read_conf(qlge_t *);
static int ql_alloc_phys(dev_info_t *, ddi_dma_handle_t *,
    ddi_device_acc_attr_t *, uint_t, ddi_acc_handle_t *,
    size_t, size_t, caddr_t *, ddi_dma_cookie_t *);
static int ql_alloc_phys_rbuf(dev_info_t *, ddi_dma_handle_t *,
    ddi_device_acc_attr_t *, uint_t, ddi_acc_handle_t *,
    size_t, size_t, caddr_t *, ddi_dma_cookie_t *);
static void ql_free_phys(ddi_dma_handle_t *, ddi_acc_handle_t *);
static int ql_set_routing_reg(qlge_t *, uint32_t, uint32_t, int);
static int ql_attach(dev_info_t *, ddi_attach_cmd_t);
static int ql_detach(dev_info_t *, ddi_detach_cmd_t);
static int ql_bringdown_adapter(qlge_t *);
static int ql_bringup_adapter(qlge_t *);
static int ql_asic_reset(qlge_t *);
static void ql_wake_mpi_reset_soft_intr(qlge_t *);
static void ql_stop_timer(qlge_t *qlge);
static void ql_fm_fini(qlge_t *qlge);
int ql_clean_outbound_rx_ring(struct rx_ring *rx_ring);

/*
 * TX dma maping handlers allow multiple sscatter-gather lists
 */
ddi_dma_attr_t  tx_mapping_dma_attr = {
	DMA_ATTR_V0,			/* dma_attr_version */
	QL_DMA_LOW_ADDRESS,		/* low DMA address range */
	QL_DMA_HIGH_64BIT_ADDRESS,	/* high DMA address range */
	QL_DMA_XFER_COUNTER,		/* DMA counter register */
	QL_DMA_ADDRESS_ALIGNMENT,	/* DMA address alignment, default - 8 */
	QL_DMA_BURSTSIZES,		/* DMA burstsizes */
	QL_DMA_MIN_XFER_SIZE,		/* min effective DMA size */
	QL_DMA_MAX_XFER_SIZE,		/* max DMA xfer size */
	QL_DMA_SEGMENT_BOUNDARY,	/* segment boundary */
	QL_MAX_TX_DMA_HANDLES,		/* s/g list length */
	QL_DMA_GRANULARITY,		/* granularity of device */
	DDI_DMA_RELAXED_ORDERING	/* DMA transfer flags */
};

/*
 * Receive buffers and Request/Response queues do not allow scatter-gather lists
 */
ddi_dma_attr_t  dma_attr = {
	DMA_ATTR_V0,			/* dma_attr_version */
	QL_DMA_LOW_ADDRESS,		/* low DMA address range */
	QL_DMA_HIGH_64BIT_ADDRESS,	/* high DMA address range */
	QL_DMA_XFER_COUNTER,		/* DMA counter register */
	QL_DMA_ADDRESS_ALIGNMENT,	/* DMA address alignment, default - 8 */
	QL_DMA_BURSTSIZES,		/* DMA burstsizes */
	QL_DMA_MIN_XFER_SIZE,		/* min effective DMA size */
	QL_DMA_MAX_XFER_SIZE,		/* max DMA xfer size */
	QL_DMA_SEGMENT_BOUNDARY,	/* segment boundary */
	1,				/* s/g list length, i.e no sg list */
	QL_DMA_GRANULARITY,		/* granularity of device */
	QL_DMA_XFER_FLAGS		/* DMA transfer flags */
};
/*
 * Receive buffers do not allow scatter-gather lists
 */
ddi_dma_attr_t  dma_attr_rbuf = {
	DMA_ATTR_V0,			/* dma_attr_version */
	QL_DMA_LOW_ADDRESS,		/* low DMA address range */
	QL_DMA_HIGH_64BIT_ADDRESS,	/* high DMA address range */
	QL_DMA_XFER_COUNTER,		/* DMA counter register */
	0x1,				/* DMA address alignment, default - 8 */
	QL_DMA_BURSTSIZES,		/* DMA burstsizes */
	QL_DMA_MIN_XFER_SIZE,		/* min effective DMA size */
	QL_DMA_MAX_XFER_SIZE,		/* max DMA xfer size */
	QL_DMA_SEGMENT_BOUNDARY,	/* segment boundary */
	1,				/* s/g list length, i.e no sg list */
	QL_DMA_GRANULARITY,		/* granularity of device */
	DDI_DMA_RELAXED_ORDERING	/* DMA transfer flags */
};
/*
 * DMA access attribute structure.
 */
/* device register access from host */
ddi_device_acc_attr_t ql_dev_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/* host ring descriptors */
ddi_device_acc_attr_t ql_desc_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

/* host ring buffer */
ddi_device_acc_attr_t ql_buf_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * Hash key table for Receive Side Scaling (RSS) support
 */
const uint8_t key_data[] = {
	0x23, 0x64, 0xa1, 0xaa, 0x37, 0xc0, 0xed, 0x05, 0x2b, 0x36,
	0x50, 0x5c, 0x45, 0x1e, 0x7e, 0xc8, 0x5d, 0x2a, 0x54, 0x2f,
	0xe4, 0x3d, 0x0f, 0xbb, 0x91, 0xd9, 0x25, 0x60, 0xd4, 0xf8,
	0x12, 0xa0, 0x59, 0x4b, 0x9e, 0x8a, 0x51, 0xda, 0xcd, 0x49};

/*
 * Shadow Registers:
 * Outbound queues have a consumer index that is maintained by the chip.
 * Inbound queues have a producer index that is maintained by the chip.
 * For lower overhead, these registers are "shadowed" to host memory
 * which allows the device driver to track the queue progress without
 * PCI reads. When an entry is placed on an inbound queue, the chip will
 * update the relevant index register and then copy the value to the
 * shadow register in host memory.
 * Currently, ql_read_sh_reg only read Inbound queues'producer index.
 */

static inline unsigned int
ql_read_sh_reg(qlge_t *qlge, struct rx_ring *rx_ring)
{
	uint32_t rtn;

	/* re-synchronize shadow prod index dma buffer before reading */
	(void) ddi_dma_sync(qlge->host_copy_shadow_dma_attr.dma_handle,
	    rx_ring->prod_idx_sh_reg_offset,
	    sizeof (uint32_t), DDI_DMA_SYNC_FORKERNEL);

	rtn = ddi_get32(qlge->host_copy_shadow_dma_attr.acc_handle,
	    (uint32_t *)rx_ring->prod_idx_sh_reg);

	return (rtn);
}

/*
 * Read 32 bit atomically
 */
uint32_t
ql_atomic_read_32(volatile uint32_t *target)
{
	/*
	 * atomic_add_32_nv returns the new value after the add,
	 * we are adding 0 so we should get the original value
	 */
	return (atomic_add_32_nv(target, 0));
}

/*
 * Set 32 bit atomically
 */
void
ql_atomic_set_32(volatile uint32_t *target, uint32_t newval)
{
	(void) atomic_swap_32(target, newval);
}


/*
 * Setup device PCI configuration registers.
 * Kernel context.
 */
static void
ql_pci_config(qlge_t *qlge)
{
	uint16_t w;

	qlge->vendor_id = (uint16_t)pci_config_get16(qlge->pci_handle,
	    PCI_CONF_VENID);
	qlge->device_id = (uint16_t)pci_config_get16(qlge->pci_handle,
	    PCI_CONF_DEVID);

	/*
	 * we want to respect framework's setting of PCI
	 * configuration space command register and also
	 * want to make sure that all bits of interest to us
	 * are properly set in PCI Command register(0x04).
	 * PCI_COMM_IO		0x1	 I/O access enable
	 * PCI_COMM_MAE		0x2	 Memory access enable
	 * PCI_COMM_ME		0x4	 bus master enable
	 * PCI_COMM_MEMWR_INVAL	0x10	 memory write and invalidate enable.
	 */
	w = (uint16_t)pci_config_get16(qlge->pci_handle, PCI_CONF_COMM);
	w = (uint16_t)(w & (~PCI_COMM_IO));
	w = (uint16_t)(w | PCI_COMM_MAE | PCI_COMM_ME |
	    /* PCI_COMM_MEMWR_INVAL | */
	    PCI_COMM_PARITY_DETECT | PCI_COMM_SERR_ENABLE);

	pci_config_put16(qlge->pci_handle, PCI_CONF_COMM, w);

	w = pci_config_get16(qlge->pci_handle, 0x54);
	w = (uint16_t)(w & (~0x7000));
	w = (uint16_t)(w | 0x5000);
	pci_config_put16(qlge->pci_handle, 0x54, w);

	ql_dump_pci_config(qlge);
}

/*
 * This routine parforms the neccessary steps to set GLD mac information
 * such as Function number, xgmac mask and shift bits
 */
static int
ql_set_mac_info(qlge_t *qlge)
{
	uint32_t value;
	int rval = DDI_FAILURE;
	uint32_t fn0_net, fn1_net;

	/* set default value */
	qlge->fn0_net = FN0_NET;
	qlge->fn1_net = FN1_NET;

	if (ql_read_processor_data(qlge, MPI_REG, &value) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s(%d) read MPI register failed",
		    __func__, qlge->instance);
		goto exit;
	} else {
		fn0_net = (value >> 1) & 0x07;
		fn1_net = (value >> 5) & 0x07;
		if ((fn0_net > 4) || (fn1_net > 4) || (fn0_net == fn1_net)) {
			cmn_err(CE_WARN, "%s(%d) bad mpi register value %x, \n"
			    "nic0 function number %d,"
			    "nic1 function number %d "
			    "use default\n",
			    __func__, qlge->instance, value, fn0_net, fn1_net);
			goto exit;
		} else {
			qlge->fn0_net = fn0_net;
			qlge->fn1_net = fn1_net;
		}
	}

	/* Get the function number that the driver is associated with */
	value = ql_read_reg(qlge, REG_STATUS);
	qlge->func_number = (uint8_t)((value >> 6) & 0x03);
	QL_PRINT(DBG_INIT, ("status register is:%x, func_number: %d\n",
	    value, qlge->func_number));

	/* The driver is loaded on a non-NIC function? */
	if ((qlge->func_number != qlge->fn0_net) &&
	    (qlge->func_number != qlge->fn1_net)) {
		cmn_err(CE_WARN,
		    "Invalid function number = 0x%x\n", qlge->func_number);
		goto exit;
	}
	/* network port 0? */
	if (qlge->func_number == qlge->fn0_net) {
		qlge->xgmac_sem_mask = QL_PORT0_XGMAC_SEM_MASK;
		qlge->xgmac_sem_bits = QL_PORT0_XGMAC_SEM_BITS;
	} else {
		qlge->xgmac_sem_mask = QL_PORT1_XGMAC_SEM_MASK;
		qlge->xgmac_sem_bits = QL_PORT1_XGMAC_SEM_BITS;
	}
	rval = DDI_SUCCESS;
exit:
	return (rval);

}

/*
 * write to doorbell register
 */
void
ql_write_doorbell_reg(qlge_t *qlge, uint32_t *addr, uint32_t data)
{
	ddi_put32(qlge->dev_doorbell_reg_handle, addr, data);
}

/*
 * read from doorbell register
 */
uint32_t
ql_read_doorbell_reg(qlge_t *qlge, uint32_t *addr)
{
	uint32_t ret;

	ret = ddi_get32(qlge->dev_doorbell_reg_handle, addr);

	return	(ret);
}

/*
 * This function waits for a specific bit to come ready
 * in a given register.  It is used mostly by the initialize
 * process, but is also used in kernel thread API such as
 * netdev->set_multi, netdev->set_mac_address, netdev->vlan_rx_add_vid.
 */
static int
ql_wait_reg_rdy(qlge_t *qlge, uint32_t reg, uint32_t bit, uint32_t err_bit)
{
	uint32_t temp;
	int count = UDELAY_COUNT;

	while (count) {
		temp = ql_read_reg(qlge, reg);

		/* check for errors */
		if ((temp & err_bit) != 0) {
			break;
		} else if ((temp & bit) != 0)
			return (DDI_SUCCESS);
		qlge_delay(UDELAY_DELAY);
		count--;
	}
	cmn_err(CE_WARN,
	    "Waiting for reg %x to come ready failed.", reg);
	if (qlge->fm_enable) {
		ql_fm_ereport(qlge, DDI_FM_DEVICE_NO_RESPONSE);
		atomic_or_32(&qlge->flags, ADAPTER_ERROR);
	}
	return (DDI_FAILURE);
}

/*
 * The CFG register is used to download TX and RX control blocks
 * to the chip. This function waits for an operation to complete.
 */
static int
ql_wait_cfg(qlge_t *qlge, uint32_t bit)
{
	return (ql_wait_reg_bit(qlge, REG_CONFIGURATION, bit, BIT_RESET, 0));
}


/*
 * Used to issue init control blocks to hw. Maps control block,
 * sets address, triggers download, waits for completion.
 */
static int
ql_write_cfg(qlge_t *qlge, uint32_t bit, uint64_t phy_addr, uint16_t q_id)
{
	int status = DDI_SUCCESS;
	uint32_t mask;
	uint32_t value;

	status = ql_sem_spinlock(qlge, SEM_ICB_MASK);
	if (status != DDI_SUCCESS) {
		goto exit;
	}
	status = ql_wait_cfg(qlge, bit);
	if (status != DDI_SUCCESS) {
		goto exit;
	}

	ql_write_reg(qlge, REG_ICB_ACCESS_ADDRESS_LOWER, LS_64BITS(phy_addr));
	ql_write_reg(qlge, REG_ICB_ACCESS_ADDRESS_UPPER, MS_64BITS(phy_addr));

	mask = CFG_Q_MASK | (bit << 16);
	value = bit | (q_id << CFG_Q_SHIFT);
	ql_write_reg(qlge, REG_CONFIGURATION, (mask | value));

	/*
	 * Wait for the bit to clear after signaling hw.
	 */
	status = ql_wait_cfg(qlge, bit);
	ql_sem_unlock(qlge, SEM_ICB_MASK); /* does flush too */

exit:
	return (status);
}

/*
 * Initialize adapter instance
 */
static int
ql_init_instance(qlge_t *qlge)
{
	int i;

	/* Default value */
	qlge->mac_flags = QL_MAC_INIT;
	qlge->mtu = ETHERMTU;		/* set normal size as default */
	qlge->page_size = VM_PAGE_SIZE;	/* default page size */

	for (i = 0; i < MAX_RX_RINGS; i++) {
		qlge->rx_polls[i] = 0;
		qlge->rx_interrupts[i] = 0;
	}

	/*
	 * Set up the operating parameters.
	 */
	qlge->multicast_list_count = 0;

	/*
	 * Set up the max number of unicast list
	 */
	qlge->unicst_total = MAX_UNICAST_LIST_SIZE;
	qlge->unicst_avail = MAX_UNICAST_LIST_SIZE;

	/*
	 * read user defined properties in .conf file
	 */
	ql_read_conf(qlge); /* mtu, pause, LSO etc */
	qlge->rx_ring_count = qlge->tx_ring_count + qlge->rss_ring_count;

	QL_PRINT(DBG_INIT, ("mtu is %d \n", qlge->mtu));

	/* choose Memory Space mapping and get Vendor Id, Device ID etc */
	ql_pci_config(qlge);
	qlge->ip_hdr_offset = 0;

	if (qlge->device_id == 0x8000) {
		/* Schultz card */
		qlge->cfg_flags |= CFG_CHIP_8100;
		/* enable just ipv4 chksum offload for Schultz */
		qlge->cfg_flags |= CFG_CKSUM_FULL_IPv4;
		/*
		 * Schultz firmware does not do pseduo IP header checksum
		 * calculation, needed to be done by driver
		 */
		qlge->cfg_flags |= CFG_HW_UNABLE_PSEUDO_HDR_CKSUM;
		if (qlge->lso_enable)
			qlge->cfg_flags |= CFG_LSO;
		qlge->cfg_flags |= CFG_SUPPORT_SCATTER_GATHER;
		/* Schultz must split packet header */
		qlge->cfg_flags |= CFG_ENABLE_SPLIT_HEADER;
		qlge->max_read_mbx = 5;
		qlge->ip_hdr_offset = 2;
	}

	/* Set Function Number and some of the iocb mac information */
	if (ql_set_mac_info(qlge) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/* Read network settings from NVRAM */
	/* After nvram is read successfully, update dev_addr */
	if (ql_get_flash_params(qlge) == DDI_SUCCESS) {
		QL_PRINT(DBG_INIT, ("mac%d address is \n", qlge->func_number));
		for (i = 0; i < ETHERADDRL; i++) {
			qlge->dev_addr.ether_addr_octet[i] =
			    qlge->nic_config.factory_MAC[i];
		}
	} else {
		cmn_err(CE_WARN, "%s(%d): Failed to read flash memory",
		    __func__, qlge->instance);
		return (DDI_FAILURE);
	}

	bcopy(qlge->dev_addr.ether_addr_octet,
	    qlge->unicst_addr[0].addr.ether_addr_octet,
	    ETHERADDRL);
	QL_DUMP(DBG_INIT, "\t flash mac address dump:\n",
	    &qlge->dev_addr.ether_addr_octet[0], 8, ETHERADDRL);

	qlge->port_link_state = LS_DOWN;

	return (DDI_SUCCESS);
}


/*
 * This hardware semaphore provides the mechanism for exclusive access to
 * resources shared between the NIC driver, MPI firmware,
 * FCOE firmware and the FC driver.
 */
static int
ql_sem_trylock(qlge_t *qlge, uint32_t sem_mask)
{
	uint32_t sem_bits = 0;

	switch (sem_mask) {
	case SEM_XGMAC0_MASK:
		sem_bits = SEM_SET << SEM_XGMAC0_SHIFT;
		break;
	case SEM_XGMAC1_MASK:
		sem_bits = SEM_SET << SEM_XGMAC1_SHIFT;
		break;
	case SEM_ICB_MASK:
		sem_bits = SEM_SET << SEM_ICB_SHIFT;
		break;
	case SEM_MAC_ADDR_MASK:
		sem_bits = SEM_SET << SEM_MAC_ADDR_SHIFT;
		break;
	case SEM_FLASH_MASK:
		sem_bits = SEM_SET << SEM_FLASH_SHIFT;
		break;
	case SEM_PROBE_MASK:
		sem_bits = SEM_SET << SEM_PROBE_SHIFT;
		break;
	case SEM_RT_IDX_MASK:
		sem_bits = SEM_SET << SEM_RT_IDX_SHIFT;
		break;
	case SEM_PROC_REG_MASK:
		sem_bits = SEM_SET << SEM_PROC_REG_SHIFT;
		break;
	default:
		cmn_err(CE_WARN, "Bad Semaphore mask!.");
		return (DDI_FAILURE);
	}

	ql_write_reg(qlge, REG_SEMAPHORE, sem_bits | sem_mask);
	return (!(ql_read_reg(qlge, REG_SEMAPHORE) & sem_bits));
}

/*
 * Lock a specific bit of Semaphore register to gain
 * access to a particular shared register
 */
int
ql_sem_spinlock(qlge_t *qlge, uint32_t sem_mask)
{
	unsigned int wait_count = 30;

	while (wait_count) {
		if (!ql_sem_trylock(qlge, sem_mask))
			return (DDI_SUCCESS);
		qlge_delay(100);
		wait_count--;
	}
	cmn_err(CE_WARN, "%s(%d) sem_mask 0x%x lock timeout ",
	    __func__, qlge->instance, sem_mask);
	return (DDI_FAILURE);
}

/*
 * Unock a specific bit of Semaphore register to release
 * access to a particular shared register
 */
void
ql_sem_unlock(qlge_t *qlge, uint32_t sem_mask)
{
	ql_write_reg(qlge, REG_SEMAPHORE, sem_mask);
	(void) ql_read_reg(qlge, REG_SEMAPHORE);	/* flush */
}

/*
 * Get property value from configuration file.
 *
 * string = property string pointer.
 *
 * Returns:
 * 0xFFFFFFFF = no property else property value.
 */
static uint32_t
ql_get_prop(qlge_t *qlge, char *string)
{
	char buf[256];
	uint32_t data;

	/* Get adapter instance parameter. */
	(void) sprintf(buf, "hba%d-%s", qlge->instance, string);
	data = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY, qlge->dip, 0, buf,
	    (int)0xffffffff);

	/* Adapter instance parameter found? */
	if (data == 0xffffffff) {
		/* No, get default parameter. */
		data = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY, qlge->dip, 0,
		    string, (int)0xffffffff);
	}

	return (data);
}

/*
 * Read user setting from configuration file.
 */
static void
ql_read_conf(qlge_t *qlge)
{
	uint32_t data;

	/* clear configuration flags */
	qlge->cfg_flags = 0;

	/* Set up the default ring sizes. */
	qlge->tx_ring_size = NUM_TX_RING_ENTRIES;
	data = ql_get_prop(qlge, "tx_ring_size");
	/* if data is valid */
	if ((data != 0xffffffff) && data) {
		if (qlge->tx_ring_size != data) {
			qlge->tx_ring_size = (uint16_t)data;
		}
	}

	qlge->rx_ring_size = NUM_RX_RING_ENTRIES;
	data = ql_get_prop(qlge, "rx_ring_size");
	/* if data is valid */
	if ((data != 0xffffffff) && data) {
		if (qlge->rx_ring_size != data) {
			qlge->rx_ring_size = (uint16_t)data;
		}
	}

	qlge->tx_ring_count = 8;
	data = ql_get_prop(qlge, "tx_ring_count");
	/* if data is valid */
	if ((data != 0xffffffff) && data) {
		if (qlge->tx_ring_count != data) {
			qlge->tx_ring_count = (uint16_t)data;
		}
	}

	qlge->rss_ring_count = 8;
	data = ql_get_prop(qlge, "rss_ring_count");
	/* if data is valid */
	if ((data != 0xffffffff) && data) {
		if (qlge->rss_ring_count != data) {
			qlge->rss_ring_count = (uint16_t)data;
		}
	}

	/* Get default rx_copy enable/disable. */
	if ((data = ql_get_prop(qlge, "force-rx-copy")) == 0xffffffff ||
	    data == 0) {
		qlge->rx_copy = B_FALSE;
		QL_PRINT(DBG_INIT, ("rx copy mode disabled\n"));
	} else if (data == 1) {
		qlge->rx_copy = B_TRUE;
		QL_PRINT(DBG_INIT, ("rx copy mode enabled\n"));
	}

	qlge->rx_copy_threshold = qlge->rx_ring_size / 4;
	data = ql_get_prop(qlge, "rx_copy_threshold");
	if ((data != 0xffffffff) && (data != 0)) {
		qlge->rx_copy_threshold = data;
		cmn_err(CE_NOTE, "!new rx_copy_threshold %d \n",
		    qlge->rx_copy_threshold);
	}

	/* Get mtu packet size. */
	data = ql_get_prop(qlge, "mtu");
	if ((data == ETHERMTU) || (data == JUMBO_MTU)) {
		if (qlge->mtu != data) {
			qlge->mtu = data;
			cmn_err(CE_NOTE, "new mtu is %d\n", qlge->mtu);
		}
	}

	if (qlge->mtu == JUMBO_MTU) {
		qlge->rx_coalesce_usecs = DFLT_RX_COALESCE_WAIT_JUMBO;
		qlge->tx_coalesce_usecs = DFLT_TX_COALESCE_WAIT_JUMBO;
		qlge->rx_max_coalesced_frames = DFLT_RX_INTER_FRAME_WAIT_JUMBO;
		qlge->tx_max_coalesced_frames = DFLT_TX_INTER_FRAME_WAIT_JUMBO;
	}


	/* Get pause mode, default is Per Priority mode. */
	qlge->pause = PAUSE_MODE_PER_PRIORITY;
	data = ql_get_prop(qlge, "pause");
	if (data <= PAUSE_MODE_PER_PRIORITY) {
		if (qlge->pause != data) {
			qlge->pause = data;
			cmn_err(CE_NOTE, "new pause mode %d\n", qlge->pause);
		}
	}
	/* Receive interrupt delay */
	qlge->rx_coalesce_usecs = DFLT_RX_COALESCE_WAIT;
	data = ql_get_prop(qlge, "rx_intr_delay");
	/* if data is valid */
	if ((data != 0xffffffff) && data) {
		if (qlge->rx_coalesce_usecs != data) {
			qlge->rx_coalesce_usecs = (uint16_t)data;
		}
	}
	/* Rx inter-packet delay. */
	qlge->rx_max_coalesced_frames = DFLT_RX_INTER_FRAME_WAIT;
	data = ql_get_prop(qlge, "rx_ipkt_delay");
	/* if data is valid */
	if ((data != 0xffffffff) && data) {
		if (qlge->rx_max_coalesced_frames != data) {
			qlge->rx_max_coalesced_frames = (uint16_t)data;
		}
	}
	/* Transmit interrupt delay */
	qlge->tx_coalesce_usecs = DFLT_TX_COALESCE_WAIT;
	data = ql_get_prop(qlge, "tx_intr_delay");
	/* if data is valid */
	if ((data != 0xffffffff) && data) {
		if (qlge->tx_coalesce_usecs != data) {
			qlge->tx_coalesce_usecs = (uint16_t)data;
		}
	}
	/* Tx inter-packet delay. */
	qlge->tx_max_coalesced_frames = DFLT_TX_INTER_FRAME_WAIT;
	data = ql_get_prop(qlge, "tx_ipkt_delay");
	/* if data is valid */
	if ((data != 0xffffffff) && data) {
		if (qlge->tx_max_coalesced_frames != data) {
			qlge->tx_max_coalesced_frames = (uint16_t)data;
		}
	}

	/* Get split header payload_copy_thresh. */
	qlge->payload_copy_thresh = DFLT_PAYLOAD_COPY_THRESH;
	data = ql_get_prop(qlge, "payload_copy_thresh");
	/* if data is valid */
	if ((data != 0xffffffff) && (data != 0)) {
		if (qlge->payload_copy_thresh != data) {
			qlge->payload_copy_thresh = data;
		}
	}

	/* large send offload (LSO) capability. */
	qlge->lso_enable = 1;
	data = ql_get_prop(qlge, "lso_enable");
	/* if data is valid */
	if ((data == 0) || (data == 1)) {
		if (qlge->lso_enable != data) {
			qlge->lso_enable = (uint16_t)data;
		}
	}

	/* dcbx capability. */
	qlge->dcbx_enable = 1;
	data = ql_get_prop(qlge, "dcbx_enable");
	/* if data is valid */
	if ((data == 0) || (data == 1)) {
		if (qlge->dcbx_enable != data) {
			qlge->dcbx_enable = (uint16_t)data;
		}
	}
	/* fault management enable */
	qlge->fm_enable = B_TRUE;
	data = ql_get_prop(qlge, "fm-enable");
	if ((data == 0x1) || (data == 0)) {
		qlge->fm_enable = (boolean_t)data;
	}

}

/*
 * Enable global interrupt
 */
static void
ql_enable_global_interrupt(qlge_t *qlge)
{
	ql_write_reg(qlge, REG_INTERRUPT_ENABLE,
	    (INTR_EN_EI << 16) | INTR_EN_EI);
	qlge->flags |= INTERRUPTS_ENABLED;
}

/*
 * Disable global interrupt
 */
static void
ql_disable_global_interrupt(qlge_t *qlge)
{
	ql_write_reg(qlge, REG_INTERRUPT_ENABLE, (INTR_EN_EI << 16));
	qlge->flags &= ~INTERRUPTS_ENABLED;
}

/*
 * Enable one ring interrupt
 */
void
ql_enable_completion_interrupt(qlge_t *qlge, uint32_t intr)
{
	struct intr_ctx *ctx = qlge->intr_ctx + intr;

	QL_PRINT(DBG_INTR, ("%s(%d): To enable intr %d, irq_cnt %d \n",
	    __func__, qlge->instance, intr, ctx->irq_cnt));

	if ((qlge->intr_type == DDI_INTR_TYPE_MSIX) && intr) {
		/*
		 * Always enable if we're MSIX multi interrupts and
		 * it's not the default (zeroeth) interrupt.
		 */
		ql_write_reg(qlge, REG_INTERRUPT_ENABLE, ctx->intr_en_mask);
		return;
	}

	if (!atomic_dec_32_nv(&ctx->irq_cnt)) {
		mutex_enter(&qlge->hw_mutex);
		ql_write_reg(qlge, REG_INTERRUPT_ENABLE, ctx->intr_en_mask);
		mutex_exit(&qlge->hw_mutex);
		QL_PRINT(DBG_INTR,
		    ("%s(%d): write %x to intr enable register \n",
		    __func__, qlge->instance, ctx->intr_en_mask));
	}
}

/*
 * ql_forced_disable_completion_interrupt
 * Used by call from OS, may be called without
 * a pending interrupt so force the disable
 */
uint32_t
ql_forced_disable_completion_interrupt(qlge_t *qlge, uint32_t intr)
{
	uint32_t var = 0;
	struct intr_ctx *ctx = qlge->intr_ctx + intr;

	QL_PRINT(DBG_INTR, ("%s(%d): To disable intr %d, irq_cnt %d \n",
	    __func__, qlge->instance, intr, ctx->irq_cnt));

	if ((qlge->intr_type == DDI_INTR_TYPE_MSIX) && intr) {
		ql_write_reg(qlge, REG_INTERRUPT_ENABLE, ctx->intr_dis_mask);
		var = ql_read_reg(qlge, REG_STATUS);
		return (var);
	}

	mutex_enter(&qlge->hw_mutex);
	ql_write_reg(qlge, REG_INTERRUPT_ENABLE, ctx->intr_dis_mask);
	var = ql_read_reg(qlge, REG_STATUS);
	mutex_exit(&qlge->hw_mutex);

	return (var);
}

/*
 * Disable a completion interrupt
 */
void
ql_disable_completion_interrupt(qlge_t *qlge, uint32_t intr)
{
	struct intr_ctx *ctx;

	ctx = qlge->intr_ctx + intr;
	QL_PRINT(DBG_INTR, ("%s(%d): To disable intr %d, irq_cnt %d \n",
	    __func__, qlge->instance, intr, ctx->irq_cnt));
	/*
	 * HW disables for us if we're MSIX multi interrupts and
	 * it's not the default (zeroeth) interrupt.
	 */
	if ((qlge->intr_type == DDI_INTR_TYPE_MSIX) && (intr != 0))
		return;

	if (ql_atomic_read_32(&ctx->irq_cnt) == 0) {
		mutex_enter(&qlge->hw_mutex);
		ql_write_reg(qlge, REG_INTERRUPT_ENABLE, ctx->intr_dis_mask);
		mutex_exit(&qlge->hw_mutex);
	}
	atomic_inc_32(&ctx->irq_cnt);
}

/*
 * Enable all completion interrupts
 */
static void
ql_enable_all_completion_interrupts(qlge_t *qlge)
{
	int i;
	uint32_t value = 1;

	for (i = 0; i < qlge->intr_cnt; i++) {
		/*
		 * Set the count to 1 for Legacy / MSI interrupts or for the
		 * default interrupt (0)
		 */
		if ((qlge->intr_type != DDI_INTR_TYPE_MSIX) || i == 0) {
			ql_atomic_set_32(&qlge->intr_ctx[i].irq_cnt, value);
		}
		ql_enable_completion_interrupt(qlge, i);
	}
}

/*
 * Disable all completion interrupts
 */
static void
ql_disable_all_completion_interrupts(qlge_t *qlge)
{
	int i;
	uint32_t value = 0;

	for (i = 0; i < qlge->intr_cnt; i++) {

		/*
		 * Set the count to 0 for Legacy / MSI interrupts or for the
		 * default interrupt (0)
		 */
		if ((qlge->intr_type != DDI_INTR_TYPE_MSIX) || i == 0)
			ql_atomic_set_32(&qlge->intr_ctx[i].irq_cnt, value);

		ql_disable_completion_interrupt(qlge, i);
	}
}

/*
 * Update small buffer queue producer index
 */
static void
ql_update_sbq_prod_idx(qlge_t *qlge, struct rx_ring *rx_ring)
{
	/* Update the buffer producer index */
	QL_PRINT(DBG_RX, ("sbq: updating prod idx = %d.\n",
	    rx_ring->sbq_prod_idx));
	ql_write_doorbell_reg(qlge, rx_ring->sbq_prod_idx_db_reg,
	    rx_ring->sbq_prod_idx);
}

/*
 * Update large buffer queue producer index
 */
static void
ql_update_lbq_prod_idx(qlge_t *qlge, struct rx_ring *rx_ring)
{
	/* Update the buffer producer index */
	QL_PRINT(DBG_RX, ("lbq: updating prod idx = %d.\n",
	    rx_ring->lbq_prod_idx));
	ql_write_doorbell_reg(qlge, rx_ring->lbq_prod_idx_db_reg,
	    rx_ring->lbq_prod_idx);
}

/*
 * Adds a small buffer descriptor to end of its in use list,
 * assumes sbq_lock is already taken
 */
static void
ql_add_sbuf_to_in_use_list(struct rx_ring *rx_ring,
    struct bq_desc *sbq_desc)
{
	uint32_t inuse_idx = rx_ring->sbq_use_tail;

	rx_ring->sbuf_in_use[inuse_idx] = sbq_desc;
	inuse_idx++;
	if (inuse_idx >= rx_ring->sbq_len)
		inuse_idx = 0;
	rx_ring->sbq_use_tail = inuse_idx;
	atomic_inc_32(&rx_ring->sbuf_in_use_count);
	ASSERT(rx_ring->sbuf_in_use_count <= rx_ring->sbq_len);
}

/*
 * Get a small buffer descriptor from its in use list
 */
static struct bq_desc *
ql_get_sbuf_from_in_use_list(struct rx_ring *rx_ring)
{
	struct bq_desc *sbq_desc = NULL;
	uint32_t inuse_idx;

	/* Pick from head of in use list */
	inuse_idx = rx_ring->sbq_use_head;
	sbq_desc = rx_ring->sbuf_in_use[inuse_idx];
	rx_ring->sbuf_in_use[inuse_idx] = NULL;

	if (sbq_desc != NULL) {
		inuse_idx++;
		if (inuse_idx >= rx_ring->sbq_len)
			inuse_idx = 0;
		rx_ring->sbq_use_head = inuse_idx;
		atomic_dec_32(&rx_ring->sbuf_in_use_count);
		atomic_inc_32(&rx_ring->rx_indicate);
		sbq_desc->upl_inuse = 1;
		/* if mp is NULL */
		if (sbq_desc->mp == NULL) {
			/* try to remap mp again */
			sbq_desc->mp =
			    desballoc((unsigned char *)(sbq_desc->bd_dma.vaddr),
			    rx_ring->sbq_buf_size, 0, &sbq_desc->rx_recycle);
		}
	}

	return (sbq_desc);
}

/*
 * Add a small buffer descriptor to its free list
 */
static void
ql_add_sbuf_to_free_list(struct rx_ring *rx_ring,
    struct bq_desc *sbq_desc)
{
	uint32_t free_idx;

	/* Add to the end of free list */
	free_idx = rx_ring->sbq_free_tail;
	rx_ring->sbuf_free[free_idx] = sbq_desc;
	ASSERT(rx_ring->sbuf_free_count <= rx_ring->sbq_len);
	free_idx++;
	if (free_idx >= rx_ring->sbq_len)
		free_idx = 0;
	rx_ring->sbq_free_tail = free_idx;
	atomic_inc_32(&rx_ring->sbuf_free_count);
}

/*
 * Get a small buffer descriptor from its free list
 */
static struct bq_desc *
ql_get_sbuf_from_free_list(struct rx_ring *rx_ring)
{
	struct bq_desc *sbq_desc;
	uint32_t free_idx;

	free_idx = rx_ring->sbq_free_head;
	/* Pick from top of free list */
	sbq_desc = rx_ring->sbuf_free[free_idx];
	rx_ring->sbuf_free[free_idx] = NULL;
	if (sbq_desc != NULL) {
		free_idx++;
		if (free_idx >= rx_ring->sbq_len)
			free_idx = 0;
		rx_ring->sbq_free_head = free_idx;
		atomic_dec_32(&rx_ring->sbuf_free_count);
	}
	return (sbq_desc);
}

/*
 * Add a large buffer descriptor to its in use list
 */
static void
ql_add_lbuf_to_in_use_list(struct rx_ring *rx_ring,
    struct bq_desc *lbq_desc)
{
	uint32_t inuse_idx;

	inuse_idx = rx_ring->lbq_use_tail;

	rx_ring->lbuf_in_use[inuse_idx] = lbq_desc;
	inuse_idx++;
	if (inuse_idx >= rx_ring->lbq_len)
		inuse_idx = 0;
	rx_ring->lbq_use_tail = inuse_idx;
	atomic_inc_32(&rx_ring->lbuf_in_use_count);
}

/*
 * Get a large buffer descriptor from in use list
 */
static struct bq_desc *
ql_get_lbuf_from_in_use_list(struct rx_ring *rx_ring)
{
	struct bq_desc *lbq_desc;
	uint32_t inuse_idx;

	/* Pick from head of in use list */
	inuse_idx = rx_ring->lbq_use_head;
	lbq_desc = rx_ring->lbuf_in_use[inuse_idx];
	rx_ring->lbuf_in_use[inuse_idx] = NULL;

	if (lbq_desc != NULL) {
		inuse_idx++;
		if (inuse_idx >= rx_ring->lbq_len)
			inuse_idx = 0;
		rx_ring->lbq_use_head = inuse_idx;
		atomic_dec_32(&rx_ring->lbuf_in_use_count);
		atomic_inc_32(&rx_ring->rx_indicate);
		lbq_desc->upl_inuse = 1;

		/* if mp is NULL */
		if (lbq_desc->mp == NULL) {
			/* try to remap mp again */
			lbq_desc->mp =
			    desballoc((unsigned char *)(lbq_desc->bd_dma.vaddr),
			    rx_ring->lbq_buf_size, 0, &lbq_desc->rx_recycle);
		}
	}
	return (lbq_desc);
}

/*
 * Add a large buffer descriptor to free list
 */
static void
ql_add_lbuf_to_free_list(struct rx_ring *rx_ring,
    struct bq_desc *lbq_desc)
{
	uint32_t free_idx;

	/* Add to the end of free list */
	free_idx = rx_ring->lbq_free_tail;
	rx_ring->lbuf_free[free_idx] = lbq_desc;
	free_idx++;
	if (free_idx >= rx_ring->lbq_len)
		free_idx = 0;
	rx_ring->lbq_free_tail = free_idx;
	atomic_inc_32(&rx_ring->lbuf_free_count);
	ASSERT(rx_ring->lbuf_free_count <= rx_ring->lbq_len);
}

/*
 * Get a large buffer descriptor from its free list
 */
static struct bq_desc *
ql_get_lbuf_from_free_list(struct rx_ring *rx_ring)
{
	struct bq_desc *lbq_desc;
	uint32_t free_idx;

	free_idx = rx_ring->lbq_free_head;
	/* Pick from head of free list */
	lbq_desc = rx_ring->lbuf_free[free_idx];
	rx_ring->lbuf_free[free_idx] = NULL;

	if (lbq_desc != NULL) {
		free_idx++;
		if (free_idx >= rx_ring->lbq_len)
			free_idx = 0;
		rx_ring->lbq_free_head = free_idx;
		atomic_dec_32(&rx_ring->lbuf_free_count);
	}
	return (lbq_desc);
}

/*
 * Add a small buffer descriptor to free list
 */
static void
ql_refill_sbuf_free_list(struct bq_desc *sbq_desc, boolean_t alloc_memory)
{
	struct rx_ring *rx_ring = sbq_desc->rx_ring;
	uint64_t *sbq_entry;
	qlge_t *qlge = (qlge_t *)rx_ring->qlge;
	/*
	 * Sync access
	 */
	mutex_enter(&rx_ring->sbq_lock);

	sbq_desc->upl_inuse = 0;

	/*
	 * If we are freeing the buffers as a result of adapter unload, get out
	 */
	if ((sbq_desc->free_buf != NULL) ||
	    (qlge->mac_flags == QL_MAC_DETACH)) {
		if (sbq_desc->free_buf == NULL)
			atomic_dec_32(&rx_ring->rx_indicate);
		mutex_exit(&rx_ring->sbq_lock);
		return;
	}
#ifdef QLGE_LOAD_UNLOAD
	if (rx_ring->rx_indicate == 0)
		cmn_err(CE_WARN, "sbq: indicate wrong");
#endif
#ifdef QLGE_TRACK_BUFFER_USAGE
	uint32_t sb_consumer_idx;
	uint32_t sb_producer_idx;
	uint32_t num_free_buffers;
	uint32_t temp;

	temp = ql_read_doorbell_reg(qlge, rx_ring->sbq_prod_idx_db_reg);
	sb_producer_idx = temp & 0x0000ffff;
	sb_consumer_idx = (temp >> 16);

	if (sb_consumer_idx > sb_producer_idx)
		num_free_buffers = NUM_SMALL_BUFFERS -
		    (sb_consumer_idx - sb_producer_idx);
	else
		num_free_buffers = sb_producer_idx - sb_consumer_idx;

	if (num_free_buffers < qlge->rx_sb_low_count[rx_ring->cq_id])
		qlge->rx_sb_low_count[rx_ring->cq_id] = num_free_buffers;

#endif

#ifdef QLGE_LOAD_UNLOAD
	if (rx_ring->rx_indicate > 0xFF000000)
		cmn_err(CE_WARN, "sbq: indicate(%d) wrong: %d mac_flags %d,"
		    " sbq_desc index %d.",
		    rx_ring->cq_id, rx_ring->rx_indicate, rx_ring->mac_flags,
		    sbq_desc->index);
#endif
	if (alloc_memory) {
		sbq_desc->mp =
		    desballoc((unsigned char *)(sbq_desc->bd_dma.vaddr),
		    rx_ring->sbq_buf_size, 0, &sbq_desc->rx_recycle);
		if (sbq_desc->mp == NULL) {
			rx_ring->rx_failed_sbq_allocs++;
		}
	}

	/* Got the packet from the stack decrement rx_indicate count */
	atomic_dec_32(&rx_ring->rx_indicate);

	ql_add_sbuf_to_free_list(rx_ring, sbq_desc);

	/* Rearm if possible */
	if ((rx_ring->sbuf_free_count >= MIN_BUFFERS_FREE_COUNT) &&
	    (qlge->mac_flags == QL_MAC_STARTED)) {
		sbq_entry = rx_ring->sbq_dma.vaddr;
		sbq_entry += rx_ring->sbq_prod_idx;

		while (rx_ring->sbuf_free_count > MIN_BUFFERS_ARM_COUNT) {
			/* Get first one from free list */
			sbq_desc = ql_get_sbuf_from_free_list(rx_ring);

			*sbq_entry = cpu_to_le64(sbq_desc->bd_dma.dma_addr);
			sbq_entry++;
			rx_ring->sbq_prod_idx++;
			if (rx_ring->sbq_prod_idx >= rx_ring->sbq_len) {
				rx_ring->sbq_prod_idx = 0;
				sbq_entry = rx_ring->sbq_dma.vaddr;
			}
			/* Add to end of in use list */
			ql_add_sbuf_to_in_use_list(rx_ring, sbq_desc);
		}

		/* Update small buffer queue producer index */
		ql_update_sbq_prod_idx(qlge, rx_ring);
	}

	mutex_exit(&rx_ring->sbq_lock);
	QL_PRINT(DBG_RX_RING, ("%s(%d) exited, sbuf_free_count %d\n",
	    __func__, qlge->instance, rx_ring->sbuf_free_count));
}

/*
 * rx recycle call back function
 */
static void
ql_release_to_sbuf_free_list(caddr_t p)
{
	struct bq_desc *sbq_desc = (struct bq_desc *)(void *)p;

	if (sbq_desc == NULL)
		return;
	ql_refill_sbuf_free_list(sbq_desc, B_TRUE);
}

/*
 * Add a large buffer descriptor to free list
 */
static void
ql_refill_lbuf_free_list(struct bq_desc *lbq_desc, boolean_t alloc_memory)
{
	struct rx_ring *rx_ring = lbq_desc->rx_ring;
	uint64_t *lbq_entry;
	qlge_t *qlge = rx_ring->qlge;

	/* Sync access */
	mutex_enter(&rx_ring->lbq_lock);

	lbq_desc->upl_inuse = 0;
	/*
	 * If we are freeing the buffers as a result of adapter unload, get out
	 */
	if ((lbq_desc->free_buf != NULL) ||
	    (qlge->mac_flags == QL_MAC_DETACH)) {
		if (lbq_desc->free_buf == NULL)
			atomic_dec_32(&rx_ring->rx_indicate);
		mutex_exit(&rx_ring->lbq_lock);
		return;
	}
#ifdef QLGE_LOAD_UNLOAD
	if (rx_ring->rx_indicate == 0)
		cmn_err(CE_WARN, "lbq: indicate wrong");
#endif
#ifdef QLGE_TRACK_BUFFER_USAGE
	uint32_t lb_consumer_idx;
	uint32_t lb_producer_idx;
	uint32_t num_free_buffers;
	uint32_t temp;

	temp = ql_read_doorbell_reg(qlge, rx_ring->lbq_prod_idx_db_reg);

	lb_producer_idx = temp & 0x0000ffff;
	lb_consumer_idx = (temp >> 16);

	if (lb_consumer_idx > lb_producer_idx)
		num_free_buffers = NUM_LARGE_BUFFERS -
		    (lb_consumer_idx - lb_producer_idx);
	else
		num_free_buffers = lb_producer_idx - lb_consumer_idx;

	if (num_free_buffers < qlge->rx_lb_low_count[rx_ring->cq_id]) {
		qlge->rx_lb_low_count[rx_ring->cq_id] = num_free_buffers;
	}
#endif

#ifdef QLGE_LOAD_UNLOAD
	if (rx_ring->rx_indicate > 0xFF000000)
		cmn_err(CE_WARN, "lbq: indicate(%d) wrong: %d mac_flags %d,"
		    "lbq_desc index %d",
		    rx_ring->cq_id, rx_ring->rx_indicate, rx_ring->mac_flags,
		    lbq_desc->index);
#endif
	if (alloc_memory) {
		lbq_desc->mp =
		    desballoc((unsigned char *)(lbq_desc->bd_dma.vaddr),
		    rx_ring->lbq_buf_size, 0, &lbq_desc->rx_recycle);
		if (lbq_desc->mp == NULL) {
			rx_ring->rx_failed_lbq_allocs++;
		}
	}

	/* Got the packet from the stack decrement rx_indicate count */
	atomic_dec_32(&rx_ring->rx_indicate);

	ql_add_lbuf_to_free_list(rx_ring, lbq_desc);

	/* Rearm if possible */
	if ((rx_ring->lbuf_free_count >= MIN_BUFFERS_FREE_COUNT) &&
	    (qlge->mac_flags == QL_MAC_STARTED)) {
		lbq_entry = rx_ring->lbq_dma.vaddr;
		lbq_entry += rx_ring->lbq_prod_idx;
		while (rx_ring->lbuf_free_count > MIN_BUFFERS_ARM_COUNT) {
			/* Get first one from free list */
			lbq_desc = ql_get_lbuf_from_free_list(rx_ring);

			*lbq_entry = cpu_to_le64(lbq_desc->bd_dma.dma_addr);
			lbq_entry++;
			rx_ring->lbq_prod_idx++;
			if (rx_ring->lbq_prod_idx >= rx_ring->lbq_len) {
				rx_ring->lbq_prod_idx = 0;
				lbq_entry = rx_ring->lbq_dma.vaddr;
			}

			/* Add to end of in use list */
			ql_add_lbuf_to_in_use_list(rx_ring, lbq_desc);
		}

		/* Update large buffer queue producer index */
		ql_update_lbq_prod_idx(rx_ring->qlge, rx_ring);
	}

	mutex_exit(&rx_ring->lbq_lock);
	QL_PRINT(DBG_RX_RING, ("%s exitd, lbuf_free_count %d\n",
	    __func__, rx_ring->lbuf_free_count));
}
/*
 * rx recycle call back function
 */
static void
ql_release_to_lbuf_free_list(caddr_t p)
{
	struct bq_desc *lbq_desc = (struct bq_desc *)(void *)p;

	if (lbq_desc == NULL)
		return;
	ql_refill_lbuf_free_list(lbq_desc, B_TRUE);
}

/*
 * free small buffer queue buffers
 */
static void
ql_free_sbq_buffers(struct rx_ring *rx_ring)
{
	struct bq_desc *sbq_desc;
	uint32_t i;
	uint32_t j = rx_ring->sbq_free_head;
	int  force_cnt = 0;

	for (i = 0; i < rx_ring->sbuf_free_count; i++) {
		sbq_desc = rx_ring->sbuf_free[j];
		sbq_desc->free_buf = 1;
		j++;
		if (j >= rx_ring->sbq_len) {
			j = 0;
		}
		if (sbq_desc->mp != NULL) {
			freemsg(sbq_desc->mp);
			sbq_desc->mp = NULL;
		}
	}
	rx_ring->sbuf_free_count = 0;

	j = rx_ring->sbq_use_head;
	for (i = 0; i < rx_ring->sbuf_in_use_count; i++) {
		sbq_desc = rx_ring->sbuf_in_use[j];
		sbq_desc->free_buf = 1;
		j++;
		if (j >= rx_ring->sbq_len) {
			j = 0;
		}
		if (sbq_desc->mp != NULL) {
			freemsg(sbq_desc->mp);
			sbq_desc->mp = NULL;
		}
	}
	rx_ring->sbuf_in_use_count = 0;

	sbq_desc = &rx_ring->sbq_desc[0];
	for (i = 0; i < rx_ring->sbq_len; i++, sbq_desc++) {
		/*
		 * Set flag so that the callback does not allocate a new buffer
		 */
		sbq_desc->free_buf = 1;
		if (sbq_desc->upl_inuse != 0) {
			force_cnt++;
		}
		if (sbq_desc->bd_dma.dma_handle != NULL) {
			ql_free_phys(&sbq_desc->bd_dma.dma_handle,
			    &sbq_desc->bd_dma.acc_handle);
			sbq_desc->bd_dma.dma_handle = NULL;
			sbq_desc->bd_dma.acc_handle = NULL;
		}
	}
#ifdef QLGE_LOAD_UNLOAD
	cmn_err(CE_NOTE, "sbq: free %d inuse %d force %d\n",
	    rx_ring->sbuf_free_count, rx_ring->sbuf_in_use_count, force_cnt);
#endif
	if (rx_ring->sbuf_in_use != NULL) {
		kmem_free(rx_ring->sbuf_in_use, (rx_ring->sbq_len *
		    sizeof (struct bq_desc *)));
		rx_ring->sbuf_in_use = NULL;
	}

	if (rx_ring->sbuf_free != NULL) {
		kmem_free(rx_ring->sbuf_free, (rx_ring->sbq_len *
		    sizeof (struct bq_desc *)));
		rx_ring->sbuf_free = NULL;
	}
}

/* Allocate small buffers */
static int
ql_alloc_sbufs(qlge_t *qlge, struct rx_ring *rx_ring)
{
	struct bq_desc *sbq_desc;
	int i;
	ddi_dma_cookie_t dma_cookie;

	rx_ring->sbq_use_head = 0;
	rx_ring->sbq_use_tail = 0;
	rx_ring->sbuf_in_use_count = 0;
	rx_ring->sbq_free_head = 0;
	rx_ring->sbq_free_tail = 0;
	rx_ring->sbuf_free_count = 0;
	rx_ring->sbuf_free = kmem_zalloc(rx_ring->sbq_len *
	    sizeof (struct bq_desc *), KM_NOSLEEP);
	if (rx_ring->sbuf_free == NULL) {
		cmn_err(CE_WARN,
		    "!%s: sbuf_free_list alloc: failed",
		    __func__);
		goto alloc_sbuf_err;
	}

	rx_ring->sbuf_in_use = kmem_zalloc(rx_ring->sbq_len *
	    sizeof (struct bq_desc *), KM_NOSLEEP);
	if (rx_ring->sbuf_in_use == NULL) {
		cmn_err(CE_WARN,
		    "!%s: sbuf_inuse_list alloc: failed",
		    __func__);
		goto alloc_sbuf_err;
	}

	sbq_desc = &rx_ring->sbq_desc[0];

	for (i = 0; i < rx_ring->sbq_len; i++, sbq_desc++) {
		/* Allocate buffer */
		if (ql_alloc_phys_rbuf(qlge->dip, &sbq_desc->bd_dma.dma_handle,
		    &ql_buf_acc_attr,
		    DDI_DMA_READ | DDI_DMA_STREAMING,
		    &sbq_desc->bd_dma.acc_handle,
		    (size_t)rx_ring->sbq_buf_size,	/* mem size */
		    (size_t)0,				/* default alignment */
		    (caddr_t *)&sbq_desc->bd_dma.vaddr,
		    &dma_cookie) != 0) {
			cmn_err(CE_WARN,
			    "!%s: ddi_dma_alloc_handle: failed",
			    __func__);
			goto alloc_sbuf_err;
		}

		/* Set context for Return buffer callback */
		sbq_desc->bd_dma.dma_addr = dma_cookie.dmac_laddress;
		sbq_desc->rx_recycle.free_func = ql_release_to_sbuf_free_list;
		sbq_desc->rx_recycle.free_arg  = (caddr_t)sbq_desc;
		sbq_desc->rx_ring = rx_ring;
		sbq_desc->upl_inuse = 0;
		sbq_desc->free_buf = 0;

		sbq_desc->mp =
		    desballoc((unsigned char *)(sbq_desc->bd_dma.vaddr),
		    rx_ring->sbq_buf_size, 0, &sbq_desc->rx_recycle);
		if (sbq_desc->mp == NULL) {
			cmn_err(CE_WARN, "%s: desballoc() failed", __func__);
			goto alloc_sbuf_err;
		}
		ql_add_sbuf_to_free_list(rx_ring, sbq_desc);
	}

	return (DDI_SUCCESS);

alloc_sbuf_err:
	ql_free_sbq_buffers(rx_ring);
	return (DDI_FAILURE);
}

static void
ql_free_lbq_buffers(struct rx_ring *rx_ring)
{
	struct bq_desc *lbq_desc;
	uint32_t i, j;
	int force_cnt = 0;

	j = rx_ring->lbq_free_head;
	for (i = 0; i < rx_ring->lbuf_free_count; i++) {
		lbq_desc = rx_ring->lbuf_free[j];
		lbq_desc->free_buf = 1;
		j++;
		if (j >= rx_ring->lbq_len)
			j = 0;
		if (lbq_desc->mp != NULL) {
			freemsg(lbq_desc->mp);
			lbq_desc->mp = NULL;
		}
	}
	rx_ring->lbuf_free_count = 0;

	j = rx_ring->lbq_use_head;
	for (i = 0; i < rx_ring->lbuf_in_use_count; i++) {
		lbq_desc = rx_ring->lbuf_in_use[j];
		lbq_desc->free_buf = 1;
		j++;
		if (j >= rx_ring->lbq_len) {
			j = 0;
		}
		if (lbq_desc->mp != NULL) {
			freemsg(lbq_desc->mp);
			lbq_desc->mp = NULL;
		}
	}
	rx_ring->lbuf_in_use_count = 0;

	lbq_desc = &rx_ring->lbq_desc[0];
	for (i = 0; i < rx_ring->lbq_len; i++, lbq_desc++) {
		/* Set flag so that callback will not allocate a new buffer */
		lbq_desc->free_buf = 1;
		if (lbq_desc->upl_inuse != 0) {
			force_cnt++;
		}
		if (lbq_desc->bd_dma.dma_handle != NULL) {
			ql_free_phys(&lbq_desc->bd_dma.dma_handle,
			    &lbq_desc->bd_dma.acc_handle);
			lbq_desc->bd_dma.dma_handle = NULL;
			lbq_desc->bd_dma.acc_handle = NULL;
		}
	}
#ifdef QLGE_LOAD_UNLOAD
	if (force_cnt) {
		cmn_err(CE_WARN, "lbq: free %d inuse %d force %d",
		    rx_ring->lbuf_free_count, rx_ring->lbuf_in_use_count,
		    force_cnt);
	}
#endif
	if (rx_ring->lbuf_in_use != NULL) {
		kmem_free(rx_ring->lbuf_in_use, (rx_ring->lbq_len *
		    sizeof (struct bq_desc *)));
		rx_ring->lbuf_in_use = NULL;
	}

	if (rx_ring->lbuf_free != NULL) {
		kmem_free(rx_ring->lbuf_free, (rx_ring->lbq_len *
		    sizeof (struct bq_desc *)));
		rx_ring->lbuf_free = NULL;
	}
}

/* Allocate large buffers */
static int
ql_alloc_lbufs(qlge_t *qlge, struct rx_ring *rx_ring)
{
	struct bq_desc *lbq_desc;
	ddi_dma_cookie_t dma_cookie;
	int i;
	uint32_t lbq_buf_size;

	rx_ring->lbq_use_head = 0;
	rx_ring->lbq_use_tail = 0;
	rx_ring->lbuf_in_use_count = 0;
	rx_ring->lbq_free_head = 0;
	rx_ring->lbq_free_tail = 0;
	rx_ring->lbuf_free_count = 0;
	rx_ring->lbuf_free = kmem_zalloc(rx_ring->lbq_len *
	    sizeof (struct bq_desc *), KM_NOSLEEP);
	if (rx_ring->lbuf_free == NULL) {
		cmn_err(CE_WARN,
		    "!%s: lbuf_free_list alloc: failed",
		    __func__);
		goto alloc_lbuf_err;
	}

	rx_ring->lbuf_in_use = kmem_zalloc(rx_ring->lbq_len *
	    sizeof (struct bq_desc *), KM_NOSLEEP);

	if (rx_ring->lbuf_in_use == NULL) {
		cmn_err(CE_WARN,
		    "!%s: lbuf_inuse_list alloc: failed",
		    __func__);
		goto alloc_lbuf_err;
	}

	lbq_buf_size = (qlge->mtu == ETHERMTU) ?
	    LRG_BUF_NORMAL_SIZE : LRG_BUF_JUMBO_SIZE;

	lbq_desc = &rx_ring->lbq_desc[0];
	for (i = 0; i < rx_ring->lbq_len; i++, lbq_desc++) {
		rx_ring->lbq_buf_size = lbq_buf_size;
		/* Allocate buffer */
		if (ql_alloc_phys_rbuf(qlge->dip, &lbq_desc->bd_dma.dma_handle,
		    &ql_buf_acc_attr,
		    DDI_DMA_READ | DDI_DMA_STREAMING,
		    &lbq_desc->bd_dma.acc_handle,
		    (size_t)rx_ring->lbq_buf_size,  /* mem size */
		    (size_t)0, /* default alignment */
		    (caddr_t *)&lbq_desc->bd_dma.vaddr,
		    &dma_cookie) != 0) {
			cmn_err(CE_WARN,
			    "!%s: ddi_dma_alloc_handle: failed",
			    __func__);
			goto alloc_lbuf_err;
		}

		/* Set context for Return buffer callback */
		lbq_desc->bd_dma.dma_addr = dma_cookie.dmac_laddress;
		lbq_desc->rx_recycle.free_func = ql_release_to_lbuf_free_list;
		lbq_desc->rx_recycle.free_arg  = (caddr_t)lbq_desc;
		lbq_desc->rx_ring = rx_ring;
		lbq_desc->upl_inuse = 0;
		lbq_desc->free_buf = 0;

		lbq_desc->mp =
		    desballoc((unsigned char *)(lbq_desc->bd_dma.vaddr),
		    rx_ring->lbq_buf_size, 0, &lbq_desc->rx_recycle);
		if (lbq_desc->mp == NULL) {
			cmn_err(CE_WARN, "%s: desballoc() failed", __func__);
			goto alloc_lbuf_err;
		}
		ql_add_lbuf_to_free_list(rx_ring, lbq_desc);
	} /* For all large buffers */

	return (DDI_SUCCESS);

alloc_lbuf_err:
	ql_free_lbq_buffers(rx_ring);
	return (DDI_FAILURE);
}

/*
 * Free rx buffers
 */
static void
ql_free_rx_buffers(qlge_t *qlge)
{
	int i;
	struct rx_ring *rx_ring;

	for (i = 0; i < qlge->rx_ring_count; i++) {
		rx_ring = &qlge->rx_ring[i];
		if (rx_ring->type != TX_Q) {
			ql_free_lbq_buffers(rx_ring);
			ql_free_sbq_buffers(rx_ring);
		}
	}
}

/*
 * Allocate rx buffers
 */
static int
ql_alloc_rx_buffers(qlge_t *qlge)
{
	struct rx_ring *rx_ring;
	int i;

	for (i = 0; i < qlge->rx_ring_count; i++) {
		rx_ring = &qlge->rx_ring[i];
		if (rx_ring->type != TX_Q) {
			if (ql_alloc_sbufs(qlge, rx_ring) != DDI_SUCCESS)
				goto alloc_err;
			if (ql_alloc_lbufs(qlge, rx_ring) != DDI_SUCCESS)
				goto alloc_err;
		}
	}
#ifdef QLGE_TRACK_BUFFER_USAGE
	for (i = 0; i < qlge->rx_ring_count; i++) {
		if (qlge->rx_ring[i].type == RX_Q) {
			qlge->rx_sb_low_count[i] = NUM_SMALL_BUFFERS;
			qlge->rx_lb_low_count[i] = NUM_LARGE_BUFFERS;
		}
		qlge->cq_low_count[i] = NUM_RX_RING_ENTRIES;
	}
#endif
	return (DDI_SUCCESS);

alloc_err:
	ql_free_rx_buffers(qlge);
	return (DDI_FAILURE);
}

/*
 * Initialize large buffer queue ring
 */
static void
ql_init_lbq_ring(struct rx_ring *rx_ring)
{
	uint16_t i;
	struct bq_desc *lbq_desc;

	bzero(rx_ring->lbq_desc, rx_ring->lbq_len * sizeof (struct bq_desc));
	for (i = 0; i < rx_ring->lbq_len; i++) {
		lbq_desc = &rx_ring->lbq_desc[i];
		lbq_desc->index = i;
	}
}

/*
 * Initialize small buffer queue ring
 */
static void
ql_init_sbq_ring(struct rx_ring *rx_ring)
{
	uint16_t i;
	struct bq_desc *sbq_desc;

	bzero(rx_ring->sbq_desc, rx_ring->sbq_len * sizeof (struct bq_desc));
	for (i = 0; i < rx_ring->sbq_len; i++) {
		sbq_desc = &rx_ring->sbq_desc[i];
		sbq_desc->index = i;
	}
}

/*
 * Calculate the pseudo-header checksum if hardware can not do
 */
static void
ql_pseudo_cksum(uint8_t *buf)
{
	uint32_t cksum;
	uint16_t iphl;
	uint16_t proto;

	iphl = (uint16_t)(4 * (buf[0] & 0xF));
	cksum = (((uint16_t)buf[2])<<8) + buf[3] - iphl;
	cksum += proto = buf[9];
	cksum += (((uint16_t)buf[12])<<8) + buf[13];
	cksum += (((uint16_t)buf[14])<<8) + buf[15];
	cksum += (((uint16_t)buf[16])<<8) + buf[17];
	cksum += (((uint16_t)buf[18])<<8) + buf[19];
	cksum = (cksum>>16) + (cksum & 0xFFFF);
	cksum = (cksum>>16) + (cksum & 0xFFFF);

	/*
	 * Point it to the TCP/UDP header, and
	 * update the checksum field.
	 */
	buf += iphl + ((proto == IPPROTO_TCP) ?
	    TCP_CKSUM_OFFSET : UDP_CKSUM_OFFSET);

	*(uint16_t *)(void *)buf = (uint16_t)htons((uint16_t)cksum);

}

/*
 * Transmit an incoming packet.
 */
mblk_t *
ql_ring_tx(void *arg, mblk_t *mp)
{
	struct tx_ring *tx_ring = (struct tx_ring *)arg;
	qlge_t *qlge = tx_ring->qlge;
	mblk_t *next;
	int rval;
	uint32_t tx_count = 0;

	if (qlge->port_link_state == LS_DOWN) {
		/* can not send message while link is down */
		mblk_t *tp;

		while (mp != NULL) {
			tp = mp->b_next;
			mp->b_next = NULL;
			freemsg(mp);
			mp = tp;
		}
		goto exit;
	}

	mutex_enter(&tx_ring->tx_lock);
	/* if mac is not started, driver is not ready, can not send */
	if (tx_ring->mac_flags != QL_MAC_STARTED) {
		cmn_err(CE_WARN, "%s(%d)ring not started, mode %d "
		    " return packets",
		    __func__, qlge->instance, tx_ring->mac_flags);
		mutex_exit(&tx_ring->tx_lock);
		goto exit;
	}

	/* we must try to send all */
	while (mp != NULL) {
		/*
		 * if number of available slots is less than a threshold,
		 * then quit
		 */
		if (tx_ring->tx_free_count <= TX_STOP_THRESHOLD) {
			tx_ring->queue_stopped = 1;
			rval = DDI_FAILURE;
#ifdef QLGE_LOAD_UNLOAD
			cmn_err(CE_WARN, "%s(%d) no resources",
			    __func__, qlge->instance);
#endif
			tx_ring->defer++;
			/*
			 * If we return the buffer back we are expected to call
			 * mac_tx_ring_update() when resources are available
			 */
			break;
		}

		next = mp->b_next;
		mp->b_next = NULL;

		rval = ql_send_common(tx_ring, mp);

		if (rval != DDI_SUCCESS) {
			mp->b_next = next;
			break;
		}
		tx_count++;
		mp = next;
	}

	/*
	 * After all msg blocks are mapped or copied to tx buffer,
	 * trigger the hardware to send!
	 */
	if (tx_count > 0) {
		ql_write_doorbell_reg(tx_ring->qlge, tx_ring->prod_idx_db_reg,
		    tx_ring->prod_idx);
	}

	mutex_exit(&tx_ring->tx_lock);
exit:
	return (mp);
}


/*
 * This function builds an mblk list for the given inbound
 * completion.
 */

static mblk_t *
ql_build_rx_mp(qlge_t *qlge, struct rx_ring *rx_ring,
    struct ib_mac_iocb_rsp *ib_mac_rsp)
{
	mblk_t *mp = NULL;
	mblk_t *mp1 = NULL;	/* packet header */
	mblk_t *mp2 = NULL;	/* packet content */
	struct bq_desc *lbq_desc;
	struct bq_desc *sbq_desc;
	uint32_t err_flag = (ib_mac_rsp->flags2 & IB_MAC_IOCB_RSP_ERR_MASK);
	uint32_t payload_len = le32_to_cpu(ib_mac_rsp->data_len);
	uint32_t header_len = le32_to_cpu(ib_mac_rsp->hdr_len);
	uint32_t pkt_len = payload_len + header_len;
	uint32_t done;
	uint64_t *curr_ial_ptr;
	uint32_t ial_data_addr_low;
	uint32_t actual_data_addr_low;
	mblk_t *mp_ial = NULL;	/* ial chained packets */
	uint32_t size;
	uint32_t cp_offset;
	boolean_t rx_copy = B_FALSE;
	mblk_t *tp = NULL;

	/*
	 * Check if error flags are set
	 */
	if (err_flag != 0) {
		if ((err_flag & IB_MAC_IOCB_RSP_ERR_OVERSIZE) != 0)
			rx_ring->frame_too_long++;
		if ((err_flag & IB_MAC_IOCB_RSP_ERR_UNDERSIZE) != 0)
			rx_ring->frame_too_short++;
		if ((err_flag & IB_MAC_IOCB_RSP_ERR_CRC) != 0)
			rx_ring->fcs_err++;
#ifdef QLGE_LOAD_UNLOAD
		cmn_err(CE_WARN, "bad packet, type 0x%x", err_flag);
#endif
		QL_DUMP(DBG_RX, "qlge_ring_rx: bad response iocb dump\n",
		    (uint8_t *)ib_mac_rsp, 8,
		    (size_t)sizeof (struct ib_mac_iocb_rsp));
	}

	/* header should not be in large buffer */
	if (ib_mac_rsp->flags4 & IB_MAC_IOCB_RSP_HL) {
		cmn_err(CE_WARN, "header in large buffer or invalid!");
		err_flag |= 1;
	}
	/* if whole packet is too big than rx buffer size */
	if (pkt_len > qlge->max_frame_size) {
		cmn_err(CE_WARN, "ql_build_rx_mpframe too long(%d)!", pkt_len);
		err_flag |= 1;
	}
	if (qlge->rx_copy ||
	    (rx_ring->sbuf_in_use_count <= qlge->rx_copy_threshold) ||
	    (rx_ring->lbuf_in_use_count <= qlge->rx_copy_threshold)) {
		rx_copy = B_TRUE;
	}

	/* if using rx copy mode, we need to allocate a big enough buffer */
	if (rx_copy) {
		qlge->stats.norcvbuf++;
		tp = allocb(payload_len + header_len + qlge->ip_hdr_offset,
		    BPRI_MED);
		if (tp == NULL) {
			cmn_err(CE_WARN, "rx copy failed to allocate memory");
		} else {
			tp->b_rptr += qlge->ip_hdr_offset;
		}
	}
	/*
	 * Handle the header buffer if present.
	 * packet header must be valid and saved in one small buffer
	 * broadcast/multicast packets' headers not splitted
	 */
	if ((ib_mac_rsp->flags4 & IB_MAC_IOCB_RSP_HV) &&
	    (ib_mac_rsp->flags4 & IB_MAC_IOCB_RSP_HS)) {
		QL_PRINT(DBG_RX, ("Header of %d bytes in small buffer.\n",
		    header_len));
		/* Sync access */
		sbq_desc = ql_get_sbuf_from_in_use_list(rx_ring);

		ASSERT(sbq_desc != NULL);

		/*
		 * Validate addresses from the ASIC with the
		 * expected sbuf address
		 */
		if (cpu_to_le64(sbq_desc->bd_dma.dma_addr)
		    != ib_mac_rsp->hdr_addr) {
			/* Small buffer address mismatch */
			cmn_err(CE_WARN, "%s(%d) ring%d packet saved"
			    " in wrong small buffer",
			    __func__, qlge->instance, rx_ring->cq_id);
			goto fatal_error;
		}
		/* get this packet */
		mp1 = sbq_desc->mp;
		/* Flush DMA'd data */
		(void) ddi_dma_sync(sbq_desc->bd_dma.dma_handle,
		    0, header_len, DDI_DMA_SYNC_FORKERNEL);

		if ((err_flag != 0)|| (mp1 == NULL)) {
			/* failed on this packet, put it back for re-arming */
#ifdef QLGE_LOAD_UNLOAD
			cmn_err(CE_WARN, "get header from small buffer fail");
#endif
			ql_refill_sbuf_free_list(sbq_desc, B_FALSE);
			mp1 = NULL;
		} else if (rx_copy) {
			if (tp != NULL) {
				bcopy(sbq_desc->bd_dma.vaddr, tp->b_rptr,
				    header_len);
			}
			ql_refill_sbuf_free_list(sbq_desc, B_FALSE);
			mp1 = NULL;
		} else {
			if ((qlge->ip_hdr_offset != 0)&&
			    (header_len < SMALL_BUFFER_SIZE)) {
				/*
				 * copy entire header to a 2 bytes boundary
				 * address for 8100 adapters so that the IP
				 * header can be on a 4 byte boundary address
				 */
				bcopy(mp1->b_rptr,
				    (mp1->b_rptr + SMALL_BUFFER_SIZE +
				    qlge->ip_hdr_offset),
				    header_len);
				mp1->b_rptr += SMALL_BUFFER_SIZE +
				    qlge->ip_hdr_offset;
			}

			/*
			 * Adjust the mp payload_len to match
			 * the packet header payload_len
			 */
			mp1->b_wptr = mp1->b_rptr + header_len;
			mp1->b_next = mp1->b_cont = NULL;
			QL_DUMP(DBG_RX, "\t RX packet header dump:\n",
			    (uint8_t *)mp1->b_rptr, 8, header_len);
		}
	}

	/*
	 * packet data or whole packet can be in small or one or
	 * several large buffer(s)
	 */
	if (ib_mac_rsp->flags3 & IB_MAC_IOCB_RSP_DS) {
		/*
		 * The data is in a single small buffer.
		 */
		sbq_desc = ql_get_sbuf_from_in_use_list(rx_ring);

		ASSERT(sbq_desc != NULL);

		QL_PRINT(DBG_RX,
		    ("%d bytes in a single small buffer, sbq_desc = %p, "
		    "sbq_desc->bd_dma.dma_addr = %x,"
		    " ib_mac_rsp->data_addr = %x, mp = %p\n",
		    payload_len, sbq_desc, sbq_desc->bd_dma.dma_addr,
		    ib_mac_rsp->data_addr, sbq_desc->mp));

		/*
		 * Validate  addresses from the ASIC with the
		 * expected sbuf address
		 */
		if (cpu_to_le64(sbq_desc->bd_dma.dma_addr)
		    != ib_mac_rsp->data_addr) {
			/* Small buffer address mismatch */
			cmn_err(CE_WARN, "%s(%d) ring%d packet saved"
			    " in wrong small buffer",
			    __func__, qlge->instance, rx_ring->cq_id);
			goto fatal_error;
		}
		/* get this packet */
		mp2 = sbq_desc->mp;
		(void) ddi_dma_sync(sbq_desc->bd_dma.dma_handle,
		    0, payload_len, DDI_DMA_SYNC_FORKERNEL);
		if ((err_flag != 0) || (mp2 == NULL)) {
#ifdef QLGE_LOAD_UNLOAD
			/* failed on this packet, put it back for re-arming */
			cmn_err(CE_WARN, "ignore bad data from small buffer");
#endif
			ql_refill_sbuf_free_list(sbq_desc, B_FALSE);
			mp2 = NULL;
		} else if (rx_copy) {
			if (tp != NULL) {
				bcopy(sbq_desc->bd_dma.vaddr,
				    tp->b_rptr + header_len, payload_len);
				tp->b_wptr =
				    tp->b_rptr + header_len + payload_len;
			}
			ql_refill_sbuf_free_list(sbq_desc, B_FALSE);
			mp2 = NULL;
		} else {
			/* Adjust the buffer length to match the payload_len */
			mp2->b_wptr = mp2->b_rptr + payload_len;
			mp2->b_next = mp2->b_cont = NULL;
			/* Flush DMA'd data */
			QL_DUMP(DBG_RX, "\t RX packet payload dump:\n",
			    (uint8_t *)mp2->b_rptr, 8, payload_len);
			/*
			 * if payload is too small , copy to
			 * the end of packet header
			 */
			if ((mp1 != NULL) &&
			    (payload_len <= qlge->payload_copy_thresh) &&
			    (pkt_len <
			    (SMALL_BUFFER_SIZE - qlge->ip_hdr_offset))) {
				bcopy(mp2->b_rptr, mp1->b_wptr, payload_len);
				mp1->b_wptr += payload_len;
				freemsg(mp2);
				mp2 = NULL;
			}
		}
	} else if (ib_mac_rsp->flags3 & IB_MAC_IOCB_RSP_DL) {
		/*
		 * The data is in a single large buffer.
		 */
		lbq_desc = ql_get_lbuf_from_in_use_list(rx_ring);

		QL_PRINT(DBG_RX,
		    ("%d bytes in a single large buffer, lbq_desc = %p, "
		    "lbq_desc->bd_dma.dma_addr = %x,"
		    " ib_mac_rsp->data_addr = %x, mp = %p\n",
		    payload_len, lbq_desc, lbq_desc->bd_dma.dma_addr,
		    ib_mac_rsp->data_addr, lbq_desc->mp));

		ASSERT(lbq_desc != NULL);

		/*
		 * Validate  addresses from the ASIC with
		 * the expected lbuf address
		 */
		if (cpu_to_le64(lbq_desc->bd_dma.dma_addr)
		    != ib_mac_rsp->data_addr) {
			/* Large buffer address mismatch */
			cmn_err(CE_WARN, "%s(%d) ring%d packet saved"
			    " in wrong large buffer",
			    __func__, qlge->instance, rx_ring->cq_id);
			goto fatal_error;
		}
		mp2 = lbq_desc->mp;
		/* Flush DMA'd data */
		(void) ddi_dma_sync(lbq_desc->bd_dma.dma_handle,
		    0, payload_len, DDI_DMA_SYNC_FORKERNEL);
		if ((err_flag != 0) || (mp2 == NULL)) {
#ifdef QLGE_LOAD_UNLOAD
			cmn_err(CE_WARN, "ignore bad data from large buffer");
#endif
			/* failed on this packet, put it back for re-arming */
			ql_refill_lbuf_free_list(lbq_desc, B_FALSE);
			mp2 = NULL;
		} else if (rx_copy) {
			if (tp != NULL) {
				bcopy(lbq_desc->bd_dma.vaddr,
				    tp->b_rptr + header_len, payload_len);
				tp->b_wptr =
				    tp->b_rptr + header_len + payload_len;
			}
			ql_refill_lbuf_free_list(lbq_desc, B_FALSE);
			mp2 = NULL;
		} else {
			/*
			 * Adjust the buffer length to match
			 * the packet payload_len
			 */
			mp2->b_wptr = mp2->b_rptr + payload_len;
			mp2->b_next = mp2->b_cont = NULL;
			QL_DUMP(DBG_RX, "\t RX packet payload dump:\n",
			    (uint8_t *)mp2->b_rptr, 8, payload_len);
			/*
			 * if payload is too small , copy to
			 * the end of packet header
			 */
			if ((mp1 != NULL) &&
			    (payload_len <= qlge->payload_copy_thresh) &&
			    (pkt_len<
			    (SMALL_BUFFER_SIZE - qlge->ip_hdr_offset))) {
				bcopy(mp2->b_rptr, mp1->b_wptr, payload_len);
				mp1->b_wptr += payload_len;
				freemsg(mp2);
				mp2 = NULL;
			}
		}
	} else if (payload_len) { /* ial case */
		/*
		 * payload available but not in sml nor lrg buffer,
		 * so, it is saved in IAL
		 */
#ifdef QLGE_LOAD_UNLOAD
		cmn_err(CE_NOTE, "packet chained in IAL \n");
#endif
		/* lrg buf addresses are saved in one small buffer */
		sbq_desc = ql_get_sbuf_from_in_use_list(rx_ring);
		curr_ial_ptr = (uint64_t *)sbq_desc->bd_dma.vaddr;
		done = 0;
		cp_offset = 0;

		while (!done) {
			ial_data_addr_low =
			    (uint32_t)(le64_to_cpu(*curr_ial_ptr) &
			    0xFFFFFFFE);
			/* check if this is the last packet fragment */
			done = (uint32_t)(le64_to_cpu(*curr_ial_ptr) & 1);
			curr_ial_ptr++;
			/*
			 * The data is in one or several large buffer(s).
			 */
			lbq_desc = ql_get_lbuf_from_in_use_list(rx_ring);
			actual_data_addr_low =
			    (uint32_t)(lbq_desc->bd_dma.dma_addr &
			    0xFFFFFFFE);
			if (ial_data_addr_low != actual_data_addr_low) {
				cmn_err(CE_WARN,
				    "packet saved in wrong ial lrg buffer"
				    " expected %x, actual %lx",
				    ial_data_addr_low,
				    (uintptr_t)lbq_desc->bd_dma.dma_addr);
				goto fatal_error;
			}

			size = (payload_len < rx_ring->lbq_buf_size)?
			    payload_len : rx_ring->lbq_buf_size;
			payload_len -= size;
			mp2 = lbq_desc->mp;
			if ((err_flag != 0) || (mp2 == NULL)) {
#ifdef QLGE_LOAD_UNLOAD
				cmn_err(CE_WARN,
				    "ignore bad data from large buffer");
#endif
				ql_refill_lbuf_free_list(lbq_desc, B_FALSE);
				mp2 = NULL;
			} else if (rx_copy) {
				if (tp != NULL) {
					(void) ddi_dma_sync(
					    lbq_desc->bd_dma.dma_handle,
					    0, size, DDI_DMA_SYNC_FORKERNEL);
					bcopy(lbq_desc->bd_dma.vaddr,
					    tp->b_rptr + header_len + cp_offset,
					    size);
					tp->b_wptr =
					    tp->b_rptr + size + cp_offset +
					    header_len;
					cp_offset += size;
				}
				ql_refill_lbuf_free_list(lbq_desc, B_FALSE);
				mp2 = NULL;
			} else {
				if (mp_ial == NULL) {
					mp_ial = mp2;
				} else {
					linkb(mp_ial, mp2);
				}

				mp2->b_next = NULL;
				mp2->b_cont = NULL;
				mp2->b_wptr = mp2->b_rptr + size;
				/* Flush DMA'd data */
				(void) ddi_dma_sync(lbq_desc->bd_dma.dma_handle,
				    0, size, DDI_DMA_SYNC_FORKERNEL);
				QL_PRINT(DBG_RX, ("ial %d payload received \n",
				    size));
				QL_DUMP(DBG_RX, "\t Mac data dump:\n",
				    (uint8_t *)mp2->b_rptr, 8, size);
			}
		}
		if (err_flag != 0) {
#ifdef QLGE_LOAD_UNLOAD
			/* failed on this packet, put it back for re-arming */
			cmn_err(CE_WARN, "ignore bad data from small buffer");
#endif
			ql_refill_sbuf_free_list(sbq_desc, B_FALSE);
		} else {
			mp2 = mp_ial;
			freemsg(sbq_desc->mp);
		}
	}
	/*
	 * some packets' hdr not split, then send mp2 upstream, otherwise,
	 * concatenate message block mp2 to the tail of message header, mp1
	 */
	if (!err_flag) {
		if (rx_copy) {
			if (tp != NULL) {
				tp->b_next = NULL;
				tp->b_cont = NULL;
				tp->b_wptr = tp->b_rptr +
				    header_len + payload_len;
			}
			mp = tp;
		} else {
			if (mp1) {
				if (mp2) {
					QL_PRINT(DBG_RX,
					    ("packet in mp1 and mp2\n"));
					/* mp1->b_cont = mp2; */
					linkb(mp1, mp2);
					mp = mp1;
				} else {
					QL_PRINT(DBG_RX,
					    ("packet in mp1 only\n"));
					mp = mp1;
				}
			} else if (mp2) {
				QL_PRINT(DBG_RX, ("packet in mp2 only\n"));
				mp = mp2;
			}
		}
	}
	return (mp);

fatal_error:
	/* fatal Error! */
	if (qlge->fm_enable) {
		ddi_fm_service_impact(qlge->dip, DDI_SERVICE_DEGRADED);
		ql_fm_ereport(qlge, DDI_FM_DEVICE_INVAL_STATE);
		atomic_or_32(&qlge->flags, ADAPTER_ERROR);
	}
	if (tp) {
		freemsg(tp);
	}

	/* *mp->b_wptr = 0; */
	ql_wake_asic_reset_soft_intr(qlge);
	return (NULL);

}

/*
 * Bump completion queue consumer index.
 */
static void
ql_update_cq(struct rx_ring *rx_ring)
{
	rx_ring->cnsmr_idx++;
	rx_ring->curr_entry++;
	if (rx_ring->cnsmr_idx >= rx_ring->cq_len) {
		rx_ring->cnsmr_idx = 0;
		rx_ring->curr_entry = rx_ring->cq_dma.vaddr;
	}
}

/*
 * Update completion queue consumer index.
 */
static void
ql_write_cq_idx(struct rx_ring *rx_ring)
{
	qlge_t *qlge = rx_ring->qlge;

	ql_write_doorbell_reg(qlge, rx_ring->cnsmr_idx_db_reg,
	    rx_ring->cnsmr_idx);
}

/*
 * Processes a SYS-Chip Event Notification Completion Event.
 * The incoming notification event that describes a link up/down
 * or some sorts of error happens.
 */
static void
ql_process_chip_ae_intr(qlge_t *qlge,
    struct ib_sys_event_iocb_rsp *ib_sys_event_rsp_ptr)
{
	uint8_t eventType = ib_sys_event_rsp_ptr->event_type;
	uint32_t soft_req = 0;

	switch (eventType) {
		case SYS_EVENT_PORT_LINK_UP:	/* 0x0h */
			QL_PRINT(DBG_MBX, ("Port Link Up\n"));
			break;

		case SYS_EVENT_PORT_LINK_DOWN:	/* 0x1h */
			QL_PRINT(DBG_MBX, ("Port Link Down\n"));
			break;

		case SYS_EVENT_MULTIPLE_CAM_HITS : /* 0x6h */
			cmn_err(CE_WARN, "A multiple CAM hits look up error "
			    "occurred");
			soft_req |= NEED_HW_RESET;
			break;

		case SYS_EVENT_SOFT_ECC_ERR:	/* 0x7h */
			cmn_err(CE_WARN, "Soft ECC error detected");
			soft_req |= NEED_HW_RESET;
			break;

		case SYS_EVENT_MGMT_FATAL_ERR:	/* 0x8h */
			cmn_err(CE_WARN, "Management (MPI) Processor fatal"
			    " error occured");
			soft_req |= NEED_MPI_RESET;
			break;

		case SYS_EVENT_MAC_INTERRUPT:	/* 0x9h */
			QL_PRINT(DBG_MBX, ("MAC Interrupt"));
			break;

		case SYS_EVENT_PCI_ERR_READING_SML_LRG_BUF:	/* 0x40h */
			cmn_err(CE_WARN, "PCI Error reading small/large "
			    "buffers occured");
			soft_req |= NEED_HW_RESET;
			break;

		default:
			QL_PRINT(DBG_RX, ("%s(%d) unknown Sys Event: "
			    "type 0x%x occured",
			    __func__, qlge->instance, eventType));
			break;
	}

	if ((soft_req & NEED_MPI_RESET) != 0) {
		ql_wake_mpi_reset_soft_intr(qlge);
		if (qlge->fm_enable) {
			ql_fm_ereport(qlge, DDI_FM_DEVICE_INVAL_STATE);
			ddi_fm_service_impact(qlge->dip, DDI_SERVICE_DEGRADED);
		}
	} else if ((soft_req & NEED_HW_RESET) != 0) {
		ql_wake_asic_reset_soft_intr(qlge);
		if (qlge->fm_enable) {
			ql_fm_ereport(qlge, DDI_FM_DEVICE_INVAL_STATE);
			ddi_fm_service_impact(qlge->dip, DDI_SERVICE_DEGRADED);
		}
	}
}

/*
 * set received packet checksum flag
 */
void
ql_set_rx_cksum(mblk_t *mp, struct ib_mac_iocb_rsp *net_rsp)
{
	uint32_t flags;

	/* Not TCP or UDP packet? nothing more to do */
	if (((net_rsp->flags2 & IB_MAC_IOCB_RSP_T) == 0) &&
	    ((net_rsp->flags2 & IB_MAC_IOCB_RSP_U) == 0))
		return;

	/* No CKO support for IPv6 */
	if ((net_rsp->flags3 & IB_MAC_IOCB_RSP_V6) != 0)
		return;

	/*
	 * If checksum error, don't set flags; stack will calculate
	 * checksum, detect the error and update statistics
	 */
	if (((net_rsp->flags1 & IB_MAC_IOCB_RSP_TE) != 0) ||
	    ((net_rsp->flags1 & IB_MAC_IOCB_RSP_IE) != 0))
		return;

	/* TCP or UDP packet and checksum valid */
	if (((net_rsp->flags2 & IB_MAC_IOCB_RSP_T) != 0) &&
	    ((net_rsp->flags1 & IB_MAC_IOCB_RSP_NU) == 0)) {
		flags = HCK_FULLCKSUM_OK;
		mac_hcksum_set(mp, 0, 0, 0, 0, flags);
	}
	if (((net_rsp->flags2 & IB_MAC_IOCB_RSP_U) != 0) &&
	    ((net_rsp->flags1 & IB_MAC_IOCB_RSP_NU) == 0)) {
		flags = HCK_FULLCKSUM_OK;
		mac_hcksum_set(mp, 0, 0, 0, 0, flags);
	}
}

/*
 * This function goes through h/w descriptor in one specified rx ring,
 * receives the data if the descriptor status shows the data is ready.
 * It returns a chain of mblks containing the received data, to be
 * passed up to mac_rx_ring().
 */
mblk_t *
ql_ring_rx(struct rx_ring *rx_ring, int poll_bytes)
{
	qlge_t *qlge = rx_ring->qlge;
	uint32_t prod = ql_read_sh_reg(qlge, rx_ring);
	struct ib_mac_iocb_rsp *net_rsp;
	mblk_t *mp;
	mblk_t *mblk_head;
	mblk_t **mblk_tail;
	uint32_t received_bytes = 0;
	uint32_t length;
#ifdef QLGE_PERFORMANCE
	uint32_t pkt_ct = 0;
#endif

#ifdef QLGE_TRACK_BUFFER_USAGE
	uint32_t consumer_idx;
	uint32_t producer_idx;
	uint32_t num_free_entries;
	uint32_t temp;

	temp = ql_read_doorbell_reg(qlge, rx_ring->cnsmr_idx_db_reg);
	consumer_idx = temp & 0x0000ffff;
	producer_idx = (temp >> 16);

	if (consumer_idx > producer_idx)
		num_free_entries = (consumer_idx - producer_idx);
	else
		num_free_entries = NUM_RX_RING_ENTRIES - (
		    producer_idx - consumer_idx);

	if (num_free_entries < qlge->cq_low_count[rx_ring->cq_id])
		qlge->cq_low_count[rx_ring->cq_id] = num_free_entries;

#endif
	mblk_head = NULL;
	mblk_tail = &mblk_head;

	while ((prod != rx_ring->cnsmr_idx)) {
		QL_PRINT(DBG_RX,
		    ("%s cq_id = %d, prod = %d, cnsmr = %d.\n",
		    __func__, rx_ring->cq_id, prod, rx_ring->cnsmr_idx));

		net_rsp = (struct ib_mac_iocb_rsp *)rx_ring->curr_entry;
		(void) ddi_dma_sync(rx_ring->cq_dma.dma_handle,
		    (off_t)((uintptr_t)net_rsp -
		    (uintptr_t)rx_ring->cq_dma.vaddr),
		    (size_t)sizeof (*net_rsp), DDI_DMA_SYNC_FORKERNEL);
		QL_DUMP(DBG_RX, "qlge_ring_rx: rx completion iocb\n",
		    rx_ring->curr_entry, 8, (size_t)sizeof (*net_rsp));

		switch (net_rsp->opcode) {

		case OPCODE_IB_MAC_IOCB:
			/* Adding length of pkt header and payload */
			length = le32_to_cpu(net_rsp->data_len) +
			    le32_to_cpu(net_rsp->hdr_len);
			if ((poll_bytes != QLGE_POLL_ALL) &&
			    ((received_bytes + length) > poll_bytes)) {
				continue;
			}
			received_bytes += length;

#ifdef QLGE_PERFORMANCE
			pkt_ct++;
#endif
			mp = ql_build_rx_mp(qlge, rx_ring, net_rsp);
			if (mp != NULL) {
				if (rx_ring->mac_flags != QL_MAC_STARTED) {
					/*
					 * Increment number of packets we have
					 * indicated to the stack, should be
					 * decremented when we get it back
					 * or when freemsg is called
					 */
					ASSERT(rx_ring->rx_indicate
					    <= rx_ring->cq_len);
#ifdef QLGE_LOAD_UNLOAD
					cmn_err(CE_WARN, "%s do not send to OS,"
					    " mac_flags %d, indicate %d",
					    __func__, rx_ring->mac_flags,
					    rx_ring->rx_indicate);
#endif
					QL_PRINT(DBG_RX,
					    ("cq_id = %d, packet "
					    "dropped, mac not "
					    "enabled.\n",
					    rx_ring->cq_id));
					rx_ring->rx_pkt_dropped_mac_unenabled++;

					/* rx_lock is expected to be held */
					mutex_exit(&rx_ring->rx_lock);
					freemsg(mp);
					mutex_enter(&rx_ring->rx_lock);
					mp = NULL;
				}

				if (mp != NULL) {
					/*
					 * IP full packet has been
					 * successfully verified by
					 * H/W and is correct
					 */
					ql_set_rx_cksum(mp, net_rsp);

					rx_ring->rx_packets++;
					rx_ring->rx_bytes += length;
					*mblk_tail = mp;
					mblk_tail = &mp->b_next;
				}
			} else {
				QL_PRINT(DBG_RX,
				    ("cq_id = %d, packet dropped\n",
				    rx_ring->cq_id));
				rx_ring->rx_packets_dropped_no_buffer++;
			}
			break;

		case OPCODE_IB_SYS_EVENT_IOCB:
			ql_process_chip_ae_intr(qlge,
			    (struct ib_sys_event_iocb_rsp *)
			    net_rsp);
			break;

		default:
			cmn_err(CE_WARN,
			    "%s Ring(%d)Hit default case, not handled!"
			    " dropping the packet, "
			    "opcode = %x.", __func__, rx_ring->cq_id,
			    net_rsp->opcode);
			break;
		}
		/* increment cnsmr_idx and curr_entry */
		ql_update_cq(rx_ring);
		prod = ql_read_sh_reg(qlge, rx_ring);

	}

#ifdef QLGE_PERFORMANCE
	if (pkt_ct >= 7)
		rx_ring->hist[7]++;
	else if (pkt_ct == 6)
		rx_ring->hist[6]++;
	else if (pkt_ct == 5)
		rx_ring->hist[5]++;
	else if (pkt_ct == 4)
		rx_ring->hist[4]++;
	else if (pkt_ct == 3)
		rx_ring->hist[3]++;
	else if (pkt_ct == 2)
		rx_ring->hist[2]++;
	else if (pkt_ct == 1)
		rx_ring->hist[1]++;
	else if (pkt_ct == 0)
		rx_ring->hist[0]++;
#endif

	/* update cnsmr_idx */
	ql_write_cq_idx(rx_ring);
	/* do not enable interrupt for polling mode */
	if (poll_bytes == QLGE_POLL_ALL)
		ql_enable_completion_interrupt(rx_ring->qlge, rx_ring->irq);
	return (mblk_head);
}

/* Process an outbound completion from an rx ring. */
static void
ql_process_mac_tx_intr(qlge_t *qlge, struct ob_mac_iocb_rsp *mac_rsp)
{
	struct tx_ring *tx_ring;
	struct tx_ring_desc *tx_ring_desc;
	int j;

	tx_ring = &qlge->tx_ring[mac_rsp->txq_idx];
	tx_ring_desc = tx_ring->wq_desc;
	tx_ring_desc += mac_rsp->tid;

	if (tx_ring_desc->tx_type == USE_DMA) {
		QL_PRINT(DBG_TX, ("%s(%d): tx type USE_DMA\n",
		    __func__, qlge->instance));

		/*
		 * Release the DMA resource that is used for
		 * DMA binding.
		 */
		for (j = 0; j < tx_ring_desc->tx_dma_handle_used; j++) {
			(void) ddi_dma_unbind_handle(
			    tx_ring_desc->tx_dma_handle[j]);
		}

		tx_ring_desc->tx_dma_handle_used = 0;
		/*
		 * Free the mblk after sending completed
		 */
		if (tx_ring_desc->mp != NULL) {
			freemsg(tx_ring_desc->mp);
			tx_ring_desc->mp = NULL;
		}
	}

	tx_ring->obytes += tx_ring_desc->tx_bytes;
	tx_ring->opackets++;

	if (mac_rsp->flags1 & (OB_MAC_IOCB_RSP_E | OB_MAC_IOCB_RSP_S |
	    OB_MAC_IOCB_RSP_L | OB_MAC_IOCB_RSP_B)) {
		tx_ring->errxmt++;
		if (mac_rsp->flags1 & OB_MAC_IOCB_RSP_E) {
			/* EMPTY */
			QL_PRINT(DBG_TX,
			    ("Total descriptor length did not match "
			    "transfer length.\n"));
		}
		if (mac_rsp->flags1 & OB_MAC_IOCB_RSP_S) {
			/* EMPTY */
			QL_PRINT(DBG_TX,
			    ("Frame too short to be legal, not sent.\n"));
		}
		if (mac_rsp->flags1 & OB_MAC_IOCB_RSP_L) {
			/* EMPTY */
			QL_PRINT(DBG_TX,
			    ("Frame too long, but sent anyway.\n"));
		}
		if (mac_rsp->flags3 & OB_MAC_IOCB_RSP_B) {
			/* EMPTY */
			QL_PRINT(DBG_TX,
			    ("PCI backplane error. Frame not sent.\n"));
		}
	}
	atomic_inc_32(&tx_ring->tx_free_count);
}

/*
 * clean up tx completion iocbs
 */
int
ql_clean_outbound_rx_ring(struct rx_ring *rx_ring)
{
	qlge_t *qlge = rx_ring->qlge;
	uint32_t prod = ql_read_sh_reg(qlge, rx_ring);
	struct ob_mac_iocb_rsp *net_rsp = NULL;
	int count = 0;
	struct tx_ring *tx_ring;
	boolean_t resume_tx = B_FALSE;

	mutex_enter(&rx_ring->rx_lock);
#ifdef QLGE_TRACK_BUFFER_USAGE
	{
	uint32_t consumer_idx;
	uint32_t producer_idx;
	uint32_t num_free_entries;
	uint32_t temp;

	temp = ql_read_doorbell_reg(qlge, rx_ring->cnsmr_idx_db_reg);
	consumer_idx = temp & 0x0000ffff;
	producer_idx = (temp >> 16);

	if (consumer_idx > producer_idx)
		num_free_entries = (consumer_idx - producer_idx);
	else
		num_free_entries = NUM_RX_RING_ENTRIES -
		    (producer_idx - consumer_idx);

	if (num_free_entries < qlge->cq_low_count[rx_ring->cq_id])
		qlge->cq_low_count[rx_ring->cq_id] = num_free_entries;

	}
#endif
	/* While there are entries in the completion queue. */
	while (prod != rx_ring->cnsmr_idx) {

		QL_PRINT(DBG_RX,
		    ("%s cq_id = %d, prod = %d, cnsmr = %d.\n", __func__,
		    rx_ring->cq_id, prod, rx_ring->cnsmr_idx));

		net_rsp = (struct ob_mac_iocb_rsp *)rx_ring->curr_entry;
		(void) ddi_dma_sync(rx_ring->cq_dma.dma_handle,
		    (off_t)((uintptr_t)net_rsp -
		    (uintptr_t)rx_ring->cq_dma.vaddr),
		    (size_t)sizeof (*net_rsp), DDI_DMA_SYNC_FORKERNEL);

		QL_DUMP(DBG_RX, "ql_clean_outbound_rx_ring: "
		    "response packet data\n",
		    rx_ring->curr_entry, 8,
		    (size_t)sizeof (*net_rsp));

		switch (net_rsp->opcode) {

		case OPCODE_OB_MAC_OFFLOAD_IOCB:
		case OPCODE_OB_MAC_IOCB:
			ql_process_mac_tx_intr(qlge, net_rsp);
			break;

		default:
			cmn_err(CE_WARN,
			    "%s Hit default case, not handled! "
			    "dropping the packet,"
			    " opcode = %x.",
			    __func__, net_rsp->opcode);
			break;
		}
		count++;
		ql_update_cq(rx_ring);
		prod = ql_read_sh_reg(qlge, rx_ring);
	}
	ql_write_cq_idx(rx_ring);

	mutex_exit(&rx_ring->rx_lock);

	net_rsp = (struct ob_mac_iocb_rsp *)rx_ring->curr_entry;
	tx_ring = &qlge->tx_ring[net_rsp->txq_idx];

	mutex_enter(&tx_ring->tx_lock);

	if (tx_ring->queue_stopped &&
	    (tx_ring->tx_free_count > TX_RESUME_THRESHOLD)) {
		/*
		 * The queue got stopped because the tx_ring was full.
		 * Wake it up, because it's now at least 25% empty.
		 */
		tx_ring->queue_stopped = 0;
		resume_tx = B_TRUE;
	}

	mutex_exit(&tx_ring->tx_lock);
	/* Don't hold the lock during OS callback */
	if (resume_tx)
		RESUME_TX(tx_ring);
	return (count);
}

/*
 * reset asic when error happens
 */
/* ARGSUSED */
static uint_t
ql_asic_reset_work(caddr_t arg1, caddr_t arg2)
{
	qlge_t *qlge = (qlge_t *)((void *)arg1);
	int status;

	mutex_enter(&qlge->gen_mutex);
	(void) ql_do_stop(qlge);
	/*
	 * Write default ethernet address to chip register Mac
	 * Address slot 0 and Enable Primary Mac Function.
	 */
	mutex_enter(&qlge->hw_mutex);
	(void) ql_unicst_set(qlge,
	    (uint8_t *)qlge->unicst_addr[0].addr.ether_addr_octet, 0);
	mutex_exit(&qlge->hw_mutex);
	qlge->mac_flags = QL_MAC_INIT;
	status = ql_do_start(qlge);
	if (status != DDI_SUCCESS)
		goto error;
	qlge->mac_flags = QL_MAC_STARTED;
	mutex_exit(&qlge->gen_mutex);
	ddi_fm_service_impact(qlge->dip, DDI_SERVICE_RESTORED);

	return (DDI_INTR_CLAIMED);

error:
	mutex_exit(&qlge->gen_mutex);
	cmn_err(CE_WARN,
	    "qlge up/down cycle failed, closing device");
	if (qlge->fm_enable) {
		ql_fm_ereport(qlge, DDI_FM_DEVICE_INVAL_STATE);
		ddi_fm_service_impact(qlge->dip, DDI_SERVICE_LOST);
		atomic_or_32(&qlge->flags, ADAPTER_ERROR);
	}
	return (DDI_INTR_CLAIMED);
}

/*
 * Reset MPI
 */
/* ARGSUSED */
static uint_t
ql_mpi_reset_work(caddr_t arg1, caddr_t arg2)
{
	qlge_t *qlge = (qlge_t *)((void *)arg1);

	(void) ql_reset_mpi_risc(qlge);
	return (DDI_INTR_CLAIMED);
}

/*
 * Process MPI mailbox messages
 */
/* ARGSUSED */
static uint_t
ql_mpi_event_work(caddr_t arg1, caddr_t arg2)
{
	qlge_t *qlge = (qlge_t *)((void *)arg1);

	ql_do_mpi_intr(qlge);
	return (DDI_INTR_CLAIMED);
}

/* Fire up a handler to reset the MPI processor. */
void
ql_wake_asic_reset_soft_intr(qlge_t *qlge)
{
	(void) ddi_intr_trigger_softint(qlge->asic_reset_intr_hdl, NULL);
}

static void
ql_wake_mpi_reset_soft_intr(qlge_t *qlge)
{
	(void) ddi_intr_trigger_softint(qlge->mpi_reset_intr_hdl, NULL);
}

static void
ql_wake_mpi_event_soft_intr(qlge_t *qlge)
{
	(void) ddi_intr_trigger_softint(qlge->mpi_event_intr_hdl, NULL);
}

/*
 * This handles a fatal error, MPI activity, and the default
 * rx_ring in an MSI-X multiple interrupt vector environment.
 * In MSI/Legacy environment it also process the rest of
 * the rx_rings.
 */
/* ARGSUSED */
static uint_t
ql_isr(caddr_t arg1, caddr_t arg2)
{
	struct rx_ring *rx_ring = (struct rx_ring *)((void *)arg1);
	struct rx_ring *ob_ring;
	qlge_t *qlge = rx_ring->qlge;
	struct intr_ctx *intr_ctx = &qlge->intr_ctx[0];
	uint32_t var, prod;
	int i;
	int work_done = 0;

	mblk_t *mp;

	_NOTE(ARGUNUSED(arg2));

	++qlge->rx_interrupts[rx_ring->cq_id];

	if (ql_atomic_read_32(&qlge->intr_ctx[0].irq_cnt)) {
		ql_write_reg(qlge, REG_RSVD7, 0xfeed0002);
		var = ql_read_reg(qlge, REG_ERROR_STATUS);
		var = ql_read_reg(qlge, REG_STATUS);
		var = ql_read_reg(qlge, REG_INTERRUPT_STATUS_1);
		return (DDI_INTR_CLAIMED);
	}

	ql_disable_completion_interrupt(qlge, intr_ctx->intr);

	/*
	 * process send completes on first stride tx ring if available
	 */
	if (qlge->isr_stride) {
		ob_ring = &qlge->rx_ring[qlge->isr_stride];
		if (ql_read_sh_reg(qlge, ob_ring) !=
		    ob_ring->cnsmr_idx) {
			(void) ql_clean_outbound_rx_ring(ob_ring);
		}
	}
	/*
	 * Check the default queue and wake handler if active.
	 */
	rx_ring = &qlge->rx_ring[0];
	prod = ql_read_sh_reg(qlge, rx_ring);
	QL_PRINT(DBG_INTR, ("rx-ring[0] prod index 0x%x, consumer 0x%x ",
	    prod, rx_ring->cnsmr_idx));
	/* check if interrupt is due to incoming packet */
	if (prod != rx_ring->cnsmr_idx) {
		QL_PRINT(DBG_INTR, ("Waking handler for rx_ring[0].\n"));
		ql_disable_completion_interrupt(qlge, intr_ctx->intr);
		mutex_enter(&rx_ring->rx_lock);
		mp = ql_ring_rx(rx_ring, QLGE_POLL_ALL);
		mutex_exit(&rx_ring->rx_lock);

		if (mp != NULL)
			RX_UPSTREAM(rx_ring, mp);
		work_done++;
	} else {
		/*
		 * If interrupt is not due to incoming packet, read status
		 * register to see if error happens or mailbox interrupt.
		 */
		var = ql_read_reg(qlge, REG_STATUS);
		if ((var & STATUS_FE) != 0) {
			ql_write_reg(qlge, REG_RSVD7, 0xfeed0003);
			if (qlge->fm_enable) {
				atomic_or_32(&qlge->flags, ADAPTER_ERROR);
				ql_fm_ereport(qlge, DDI_FM_DEVICE_INVAL_STATE);
				ddi_fm_service_impact(qlge->dip,
				    DDI_SERVICE_LOST);
			}
			cmn_err(CE_WARN, "Got fatal error, STS = %x.", var);
			var = ql_read_reg(qlge, REG_ERROR_STATUS);
			cmn_err(CE_WARN,
			    "Resetting chip. Error Status Register = 0x%x",
			    var);
			ql_wake_asic_reset_soft_intr(qlge);
			return (DDI_INTR_CLAIMED);
		}

		/*
		 * Check MPI processor activity.
		 */
		if ((var & STATUS_PI) != 0) {
			/*
			 * We've got an async event or mailbox completion.
			 * Handle it and clear the source of the interrupt.
			 */
			ql_write_reg(qlge, REG_RSVD7, 0xfeed0004);

			QL_PRINT(DBG_INTR, ("Got MPI processor interrupt.\n"));
			ql_disable_completion_interrupt(qlge, intr_ctx->intr);
			ql_wake_mpi_event_soft_intr(qlge);
			work_done++;
		}
	}


	if (qlge->intr_type != DDI_INTR_TYPE_MSIX) {
		/*
		 * Start the DPC for each active queue.
		 */
		for (i = 1; i < qlge->rx_ring_count; i++) {
			rx_ring = &qlge->rx_ring[i];

			if (ql_read_sh_reg(qlge, rx_ring) !=
			    rx_ring->cnsmr_idx) {
				QL_PRINT(DBG_INTR,
				    ("Waking handler for rx_ring[%d].\n", i));

				ql_disable_completion_interrupt(qlge,
				    rx_ring->irq);
				if (rx_ring->type == TX_Q) {
					(void) ql_clean_outbound_rx_ring(
					    rx_ring);
					ql_enable_completion_interrupt(
					    rx_ring->qlge, rx_ring->irq);
				} else {
					mutex_enter(&rx_ring->rx_lock);
					mp = ql_ring_rx(rx_ring, QLGE_POLL_ALL);
					mutex_exit(&rx_ring->rx_lock);
					if (mp != NULL)
						RX_UPSTREAM(rx_ring, mp);
#ifdef QLGE_LOAD_UNLOAD
					if (rx_ring->mac_flags ==
					    QL_MAC_STOPPED)
						cmn_err(CE_NOTE,
						    "%s rx_indicate(%d) %d\n",
						    __func__, i,
						    rx_ring->rx_indicate);
#endif
				}
				work_done++;
			}
		}
	}

	ql_enable_completion_interrupt(qlge, intr_ctx->intr);

	return (work_done ? DDI_INTR_CLAIMED : DDI_INTR_UNCLAIMED);
}

/*
 * MSI-X Multiple Vector Interrupt Handler for outbound (TX) completions.
 */
/* ARGSUSED */
static uint_t
ql_msix_tx_isr(caddr_t arg1, caddr_t arg2)
{
	struct rx_ring *rx_ring = (struct rx_ring *)((void *)arg1);
	qlge_t *qlge = rx_ring->qlge;
	_NOTE(ARGUNUSED(arg2));

	++qlge->rx_interrupts[rx_ring->cq_id];
	(void) ql_clean_outbound_rx_ring(rx_ring);
	ql_enable_completion_interrupt(rx_ring->qlge, rx_ring->irq);

	return (DDI_INTR_CLAIMED);
}

/*
 * MSI-X Multiple Vector Interrupt Handler
 */
/* ARGSUSED */
static uint_t
ql_msix_isr(caddr_t arg1, caddr_t arg2)
{
	struct rx_ring *rx_ring = (struct rx_ring *)((void *)arg1);
	struct rx_ring *ob_ring;
	qlge_t *qlge = rx_ring->qlge;
	mblk_t *mp;
	_NOTE(ARGUNUSED(arg2));

	QL_PRINT(DBG_INTR, ("%s for ring %d\n", __func__, rx_ring->cq_id));

	ql_disable_completion_interrupt(qlge, rx_ring->irq);

	/*
	 * process send completes on stride tx ring if available
	 */
	if (qlge->isr_stride) {
		ob_ring = rx_ring + qlge->isr_stride;
		if (ql_read_sh_reg(qlge, ob_ring) !=
		    ob_ring->cnsmr_idx) {
			++qlge->rx_interrupts[ob_ring->cq_id];
			(void) ql_clean_outbound_rx_ring(ob_ring);
		}
	}

	++qlge->rx_interrupts[rx_ring->cq_id];

	mutex_enter(&rx_ring->rx_lock);
	mp = ql_ring_rx(rx_ring, QLGE_POLL_ALL);
	mutex_exit(&rx_ring->rx_lock);

	if (mp != NULL)
		RX_UPSTREAM(rx_ring, mp);

	return (DDI_INTR_CLAIMED);
}

/*
 * Poll n_bytes of chained incoming packets
 */
mblk_t *
ql_ring_rx_poll(void *arg, int n_bytes)
{
	struct rx_ring *rx_ring = (struct rx_ring *)arg;
	qlge_t *qlge = rx_ring->qlge;
	mblk_t *mp = NULL;
	uint32_t var;

	ASSERT(n_bytes >= 0);
	QL_PRINT(DBG_GLD, ("%s for ring(%d) to read max %d bytes\n",
	    __func__, rx_ring->cq_id, n_bytes));

	++qlge->rx_polls[rx_ring->cq_id];

	if (n_bytes == 0)
		return (mp);
	mutex_enter(&rx_ring->rx_lock);
	mp = ql_ring_rx(rx_ring, n_bytes);
	mutex_exit(&rx_ring->rx_lock);

	if ((rx_ring->cq_id == 0) && (mp == NULL)) {
		var = ql_read_reg(qlge, REG_STATUS);
		/*
		 * Check for fatal error.
		 */
		if ((var & STATUS_FE) != 0) {
			ql_write_reg(qlge, REG_RSVD7, 0xfeed0003);
			var = ql_read_reg(qlge, REG_ERROR_STATUS);
			cmn_err(CE_WARN, "Got fatal error %x.", var);
			ql_wake_asic_reset_soft_intr(qlge);
			if (qlge->fm_enable) {
				atomic_or_32(&qlge->flags, ADAPTER_ERROR);
				ql_fm_ereport(qlge, DDI_FM_DEVICE_INVAL_STATE);
				ddi_fm_service_impact(qlge->dip,
				    DDI_SERVICE_LOST);
			}
		}
		/*
		 * Check MPI processor activity.
		 */
		if ((var & STATUS_PI) != 0) {
			/*
			 * We've got an async event or mailbox completion.
			 * Handle it and clear the source of the interrupt.
			 */
			ql_write_reg(qlge, REG_RSVD7, 0xfeed0004);
			ql_do_mpi_intr(qlge);
		}
	}

	return (mp);
}

/*
 * MSI-X Multiple Vector Interrupt Handler for inbound (RX) completions.
 */
/* ARGSUSED */
static uint_t
ql_msix_rx_isr(caddr_t arg1, caddr_t arg2)
{
	struct rx_ring *rx_ring = (struct rx_ring *)((void *)arg1);
	qlge_t *qlge = rx_ring->qlge;
	mblk_t *mp;
	_NOTE(ARGUNUSED(arg2));

	QL_PRINT(DBG_INTR, ("%s for ring %d\n", __func__, rx_ring->cq_id));

	++qlge->rx_interrupts[rx_ring->cq_id];

	mutex_enter(&rx_ring->rx_lock);
	mp = ql_ring_rx(rx_ring, QLGE_POLL_ALL);
	mutex_exit(&rx_ring->rx_lock);

	if (mp != NULL)
		RX_UPSTREAM(rx_ring, mp);

	return (DDI_INTR_CLAIMED);
}


/*
 *
 * Allocate DMA Buffer for ioctl service
 *
 */
static int
ql_alloc_ioctl_dma_buf(qlge_t *qlge)
{
	uint64_t phy_addr;
	uint64_t alloc_size;
	ddi_dma_cookie_t dma_cookie;

	alloc_size = qlge->ioctl_buf_dma_attr.mem_len =
	    max(WCS_MPI_CODE_RAM_LENGTH, MEMC_MPI_RAM_LENGTH);
	if (ql_alloc_phys(qlge->dip, &qlge->ioctl_buf_dma_attr.dma_handle,
	    &ql_buf_acc_attr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &qlge->ioctl_buf_dma_attr.acc_handle,
	    (size_t)alloc_size,  /* mem size */
	    (size_t)0,  /* alignment */
	    (caddr_t *)&qlge->ioctl_buf_dma_attr.vaddr,
	    &dma_cookie) != 0) {
		cmn_err(CE_WARN, "%s(%d): ioctl DMA allocation failed.",
		    __func__, qlge->instance);
		return (DDI_FAILURE);
	}

	phy_addr = dma_cookie.dmac_laddress;

	if (qlge->ioctl_buf_dma_attr.vaddr == NULL) {
		cmn_err(CE_WARN, "%s(%d): failed.", __func__, qlge->instance);
		return (DDI_FAILURE);
	}

	qlge->ioctl_buf_dma_attr.dma_addr = phy_addr;

	QL_PRINT(DBG_MBX, ("%s: ioctl_dma_buf_virt_addr = 0x%lx, "
	    "phy_addr = 0x%lx\n",
	    __func__, qlge->ioctl_buf_dma_attr.vaddr, phy_addr));

	return (DDI_SUCCESS);
}


/*
 * Function to free physical memory.
 */
static void
ql_free_phys(ddi_dma_handle_t *dma_handle, ddi_acc_handle_t *acc_handle)
{
	if (*dma_handle != NULL) {
		(void) ddi_dma_unbind_handle(*dma_handle);
		if (*acc_handle != NULL)
			ddi_dma_mem_free(acc_handle);
		ddi_dma_free_handle(dma_handle);
		*acc_handle = NULL;
		*dma_handle = NULL;
	}
}

/*
 * Function to free ioctl dma buffer.
 */
static void
ql_free_ioctl_dma_buf(qlge_t *qlge)
{
	if (qlge->ioctl_buf_dma_attr.dma_handle != NULL) {
		ql_free_phys(&qlge->ioctl_buf_dma_attr.dma_handle,
		    &qlge->ioctl_buf_dma_attr.acc_handle);

		qlge->ioctl_buf_dma_attr.vaddr = NULL;
		qlge->ioctl_buf_dma_attr.dma_handle = NULL;
	}
}

/*
 * Free shadow register space used for request and completion queues
 */
static void
ql_free_shadow_space(qlge_t *qlge)
{
	if (qlge->host_copy_shadow_dma_attr.dma_handle != NULL) {
		ql_free_phys(&qlge->host_copy_shadow_dma_attr.dma_handle,
		    &qlge->host_copy_shadow_dma_attr.acc_handle);
		bzero(&qlge->host_copy_shadow_dma_attr,
		    sizeof (qlge->host_copy_shadow_dma_attr));
	}

	if (qlge->buf_q_ptr_base_addr_dma_attr.dma_handle != NULL) {
		ql_free_phys(&qlge->buf_q_ptr_base_addr_dma_attr.dma_handle,
		    &qlge->buf_q_ptr_base_addr_dma_attr.acc_handle);
		bzero(&qlge->buf_q_ptr_base_addr_dma_attr,
		    sizeof (qlge->buf_q_ptr_base_addr_dma_attr));
	}
}

/*
 * Allocate shadow register space for request and completion queues
 */
static int
ql_alloc_shadow_space(qlge_t *qlge)
{
	ddi_dma_cookie_t dma_cookie;

	if (ql_alloc_phys(qlge->dip,
	    &qlge->host_copy_shadow_dma_attr.dma_handle,
	    &ql_dev_acc_attr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &qlge->host_copy_shadow_dma_attr.acc_handle,
	    (size_t)VM_PAGE_SIZE,  /* mem size */
	    (size_t)4, /* 4 bytes alignment */
	    (caddr_t *)&qlge->host_copy_shadow_dma_attr.vaddr,
	    &dma_cookie) != 0) {
		bzero(&qlge->host_copy_shadow_dma_attr,
		    sizeof (qlge->host_copy_shadow_dma_attr));

		cmn_err(CE_WARN, "%s(%d): Unable to allocate DMA memory for "
		    "response shadow registers", __func__, qlge->instance);
		return (DDI_FAILURE);
	}

	qlge->host_copy_shadow_dma_attr.dma_addr = dma_cookie.dmac_laddress;

	if (ql_alloc_phys(qlge->dip,
	    &qlge->buf_q_ptr_base_addr_dma_attr.dma_handle,
	    &ql_desc_acc_attr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &qlge->buf_q_ptr_base_addr_dma_attr.acc_handle,
	    (size_t)VM_PAGE_SIZE,  /* mem size */
	    (size_t)4, /* 4 bytes alignment */
	    (caddr_t *)&qlge->buf_q_ptr_base_addr_dma_attr.vaddr,
	    &dma_cookie) != 0) {
		bzero(&qlge->buf_q_ptr_base_addr_dma_attr,
		    sizeof (qlge->buf_q_ptr_base_addr_dma_attr));

		cmn_err(CE_WARN, "%s(%d): Unable to allocate DMA memory "
		    "for request shadow registers",
		    __func__, qlge->instance);
		goto err_wqp_sh_area;
	}
	qlge->buf_q_ptr_base_addr_dma_attr.dma_addr = dma_cookie.dmac_laddress;

	return (DDI_SUCCESS);

err_wqp_sh_area:
	ql_free_phys(&qlge->host_copy_shadow_dma_attr.dma_handle,
	    &qlge->host_copy_shadow_dma_attr.acc_handle);
	bzero(&qlge->host_copy_shadow_dma_attr,
	    sizeof (qlge->host_copy_shadow_dma_attr));

	return (DDI_FAILURE);
}

/*
 * Initialize a tx ring
 */
static void
ql_init_tx_ring(struct tx_ring *tx_ring)
{
	int i;
	struct ob_mac_iocb_req *mac_iocb_ptr = tx_ring->wq_dma.vaddr;
	struct tx_ring_desc *tx_ring_desc = tx_ring->wq_desc;

	for (i = 0; i < tx_ring->wq_len; i++) {
		tx_ring_desc->index = i;
		tx_ring_desc->queue_entry = mac_iocb_ptr;
		mac_iocb_ptr++;
		tx_ring_desc++;
	}
	tx_ring->tx_free_count = tx_ring->wq_len;
	tx_ring->queue_stopped = 0;
}

/*
 * Free one tx ring resources
 */
static void
ql_free_tx_resources(struct tx_ring *tx_ring)
{
	struct tx_ring_desc *tx_ring_desc;
	int i, j;

	if (tx_ring->wq_dma.dma_handle != NULL) {
		ql_free_phys(&tx_ring->wq_dma.dma_handle,
		    &tx_ring->wq_dma.acc_handle);
		bzero(&tx_ring->wq_dma, sizeof (tx_ring->wq_dma));
	}
	if (tx_ring->wq_desc != NULL) {
		tx_ring_desc = tx_ring->wq_desc;
		for (i = 0; i < tx_ring->wq_len; i++, tx_ring_desc++) {
			for (j = 0; j < QL_MAX_TX_DMA_HANDLES; j++) {
				if (tx_ring_desc->tx_dma_handle[j]) {
					/*
					 * The unbinding will happen in tx
					 * completion, here we just free the
					 * handles
					 */
					ddi_dma_free_handle(
					    &(tx_ring_desc->tx_dma_handle[j]));
					tx_ring_desc->tx_dma_handle[j] = NULL;
				}
			}
			if (tx_ring_desc->oal != NULL) {
				tx_ring_desc->oal_dma_addr = 0;
				tx_ring_desc->oal = NULL;
				tx_ring_desc->copy_buffer = NULL;
				tx_ring_desc->copy_buffer_dma_addr = 0;

				ql_free_phys(&tx_ring_desc->oal_dma.dma_handle,
				    &tx_ring_desc->oal_dma.acc_handle);
			}
		}
		kmem_free(tx_ring->wq_desc,
		    tx_ring->wq_len * sizeof (struct tx_ring_desc));
		tx_ring->wq_desc = NULL;
	}
	/* free the wqicb struct */
	if (tx_ring->wqicb_dma.dma_handle) {
		ql_free_phys(&tx_ring->wqicb_dma.dma_handle,
		    &tx_ring->wqicb_dma.acc_handle);
		bzero(&tx_ring->wqicb_dma, sizeof (tx_ring->wqicb_dma));
	}
}

/*
 * Allocate work (request) queue memory and transmit
 * descriptors for this transmit ring
 */
static int
ql_alloc_tx_resources(qlge_t *qlge, struct tx_ring *tx_ring)
{
	ddi_dma_cookie_t dma_cookie;
	struct tx_ring_desc *tx_ring_desc;
	int i, j;
	uint32_t length;

	/* allocate dma buffers for obiocbs */
	if (ql_alloc_phys(qlge->dip, &tx_ring->wq_dma.dma_handle,
	    &ql_desc_acc_attr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &tx_ring->wq_dma.acc_handle,
	    (size_t)tx_ring->wq_size,	/* mem size */
	    (size_t)128, /* alignment:128 bytes boundary */
	    (caddr_t *)&tx_ring->wq_dma.vaddr,
	    &dma_cookie) != 0) {
		bzero(&tx_ring->wq_dma, sizeof (&tx_ring->wq_dma));
		cmn_err(CE_WARN, "%s(%d): reqQ allocation failed.",
		    __func__, qlge->instance);
		return (DDI_FAILURE);
	}
	tx_ring->wq_dma.dma_addr = dma_cookie.dmac_laddress;

	tx_ring->wq_desc =
	    kmem_zalloc(tx_ring->wq_len * sizeof (struct tx_ring_desc),
	    KM_NOSLEEP);
	if (tx_ring->wq_desc == NULL) {
		goto err;
	} else {
		tx_ring_desc = tx_ring->wq_desc;
		/*
		 * Allocate a large enough structure to hold the following
		 * 1. oal buffer MAX_SGELEMENTS * sizeof (oal_entry) bytes
		 * 2. copy buffer of QL_MAX_COPY_LENGTH bytes
		 */
		length = (sizeof (struct oal_entry) * MAX_SG_ELEMENTS)
		    + QL_MAX_COPY_LENGTH;
		for (i = 0; i < tx_ring->wq_len; i++, tx_ring_desc++) {

			if (ql_alloc_phys(qlge->dip,
			    &tx_ring_desc->oal_dma.dma_handle,
			    &ql_desc_acc_attr,
			    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
			    &tx_ring_desc->oal_dma.acc_handle,
			    (size_t)length,	/* mem size */
			    (size_t)0, /* default alignment:8 bytes boundary */
			    (caddr_t *)&tx_ring_desc->oal_dma.vaddr,
			    &dma_cookie) != 0) {
				bzero(&tx_ring_desc->oal_dma,
				    sizeof (tx_ring_desc->oal_dma));
				cmn_err(CE_WARN, "%s(%d): reqQ tx buf &"
				    "oal alloc failed.",
				    __func__, qlge->instance);
				goto err;
			}

			tx_ring_desc->oal = tx_ring_desc->oal_dma.vaddr;
			tx_ring_desc->oal_dma_addr = dma_cookie.dmac_laddress;
			tx_ring_desc->copy_buffer =
			    (caddr_t)((uint8_t *)tx_ring_desc->oal
			    + (sizeof (struct oal_entry) * MAX_SG_ELEMENTS));
			tx_ring_desc->copy_buffer_dma_addr =
			    (tx_ring_desc->oal_dma_addr
			    + (sizeof (struct oal_entry) * MAX_SG_ELEMENTS));

			/* Allocate dma handles for transmit buffers */
			for (j = 0; j < QL_MAX_TX_DMA_HANDLES; j++) {
				if (ddi_dma_alloc_handle(qlge->dip,
				    &tx_mapping_dma_attr,
				    DDI_DMA_DONTWAIT,
				    0, &tx_ring_desc->tx_dma_handle[j])
				    != DDI_SUCCESS) {
					tx_ring_desc->tx_dma_handle[j] = NULL;
					cmn_err(CE_WARN,
					    "!%s: ddi_dma_alloc_handle: "
					    "tx_dma_handle "
					    "alloc failed", __func__);
					ql_free_phys(
					    &tx_ring_desc->oal_dma.dma_handle,
					    &tx_ring_desc->oal_dma.acc_handle);
					goto err;
				}
			}
		}
	}
	/* alloc a wqicb control block to load this tx ring to hw */
	if (ql_alloc_phys(qlge->dip, &tx_ring->wqicb_dma.dma_handle,
	    &ql_desc_acc_attr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &tx_ring->wqicb_dma.acc_handle,
	    (size_t)sizeof (struct wqicb_t),	/* mem size */
	    (size_t)0, /* alignment:128 bytes boundary */
	    (caddr_t *)&tx_ring->wqicb_dma.vaddr,
	    &dma_cookie) != 0) {
		bzero(&tx_ring->wqicb_dma, sizeof (tx_ring->wqicb_dma));
		cmn_err(CE_WARN, "%s(%d): wqicb allocation failed.",
		    __func__, qlge->instance);
		goto err;
	}
	tx_ring->wqicb_dma.dma_addr = dma_cookie.dmac_laddress;

	return (DDI_SUCCESS);

err:
	ql_free_tx_resources(tx_ring);
	return (DDI_FAILURE);
}

/*
 * Free one rx ring resources
 */
static void
ql_free_rx_resources(struct rx_ring *rx_ring)
{
	/* Free the small buffer queue. */
	if (rx_ring->sbq_dma.dma_handle) {
		ql_free_phys(&rx_ring->sbq_dma.dma_handle,
		    &rx_ring->sbq_dma.acc_handle);
		bzero(&rx_ring->sbq_dma, sizeof (rx_ring->sbq_dma));
	}

	/* Free the small buffer queue control blocks. */
	if (rx_ring->sbq_desc != NULL) {
		kmem_free(rx_ring->sbq_desc, rx_ring->sbq_len *
		    sizeof (struct bq_desc));
		rx_ring->sbq_desc = NULL;
	}

	/* Free the large buffer queue. */
	if (rx_ring->lbq_dma.dma_handle) {
		ql_free_phys(&rx_ring->lbq_dma.dma_handle,
		    &rx_ring->lbq_dma.acc_handle);
		bzero(&rx_ring->lbq_dma, sizeof (rx_ring->lbq_dma));
	}

	/* Free the large buffer queue control blocks. */
	if (rx_ring->lbq_desc != NULL) {
		kmem_free(rx_ring->lbq_desc, rx_ring->lbq_len *
		    sizeof (struct bq_desc));
		rx_ring->lbq_desc = NULL;
	}

	/* Free cqicb struct */
	if (rx_ring->cqicb_dma.dma_handle) {
		ql_free_phys(&rx_ring->cqicb_dma.dma_handle,
		    &rx_ring->cqicb_dma.acc_handle);
		bzero(&rx_ring->cqicb_dma, sizeof (rx_ring->cqicb_dma));
	}
	/* Free the rx queue. */
	if (rx_ring->cq_dma.dma_handle) {
		ql_free_phys(&rx_ring->cq_dma.dma_handle,
		    &rx_ring->cq_dma.acc_handle);
		bzero(&rx_ring->cq_dma, sizeof (rx_ring->cq_dma));
	}
}

/*
 * Allocate queues and buffers for this completions queue based
 * on the values in the parameter structure.
 */
static int
ql_alloc_rx_resources(qlge_t *qlge, struct rx_ring *rx_ring)
{
	ddi_dma_cookie_t dma_cookie;

	if (ql_alloc_phys(qlge->dip, &rx_ring->cq_dma.dma_handle,
	    &ql_desc_acc_attr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &rx_ring->cq_dma.acc_handle,
	    (size_t)rx_ring->cq_size,  /* mem size */
	    (size_t)128, /* alignment:128 bytes boundary */
	    (caddr_t *)&rx_ring->cq_dma.vaddr,
	    &dma_cookie) != 0)	{
		bzero(&rx_ring->cq_dma, sizeof (rx_ring->cq_dma));
		cmn_err(CE_WARN, "%s(%d): rspQ allocation failed.",
		    __func__, qlge->instance);
		return (DDI_FAILURE);
	}
	rx_ring->cq_dma.dma_addr = dma_cookie.dmac_laddress;

	if (rx_ring->sbq_len != 0) {
		/*
		 * Allocate small buffer queue.
		 */
		if (ql_alloc_phys(qlge->dip, &rx_ring->sbq_dma.dma_handle,
		    &ql_desc_acc_attr,
		    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		    &rx_ring->sbq_dma.acc_handle,
		    (size_t)rx_ring->sbq_size,  /* mem size */
		    (size_t)128, /* alignment:128 bytes boundary */
		    (caddr_t *)&rx_ring->sbq_dma.vaddr,
		    &dma_cookie) != 0) {
			bzero(&rx_ring->sbq_dma, sizeof (rx_ring->sbq_dma));
			cmn_err(CE_WARN,
			    "%s(%d): small buffer queue allocation failed.",
			    __func__, qlge->instance);
			goto err_mem;
		}
		rx_ring->sbq_dma.dma_addr = dma_cookie.dmac_laddress;

		/*
		 * Allocate small buffer queue control blocks.
		 */
		rx_ring->sbq_desc =
		    kmem_zalloc(rx_ring->sbq_len * sizeof (struct bq_desc),
		    KM_NOSLEEP);
		if (rx_ring->sbq_desc == NULL) {
			cmn_err(CE_WARN,
			    "sbq control block allocation failed.");
			goto err_mem;
		}

		ql_init_sbq_ring(rx_ring);
	}

	if (rx_ring->lbq_len != 0) {
		/*
		 * Allocate large buffer queue.
		 */
		if (ql_alloc_phys(qlge->dip, &rx_ring->lbq_dma.dma_handle,
		    &ql_desc_acc_attr,
		    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		    &rx_ring->lbq_dma.acc_handle,
		    (size_t)rx_ring->lbq_size,  /* mem size */
		    (size_t)128, /* alignment:128 bytes boundary */
		    (caddr_t *)&rx_ring->lbq_dma.vaddr,
		    &dma_cookie) != 0) {
			bzero(&rx_ring->lbq_dma, sizeof (rx_ring->lbq_dma));
			cmn_err(CE_WARN, "%s(%d): lbq allocation failed.",
			    __func__, qlge->instance);
			goto err_mem;
		}
		rx_ring->lbq_dma.dma_addr = dma_cookie.dmac_laddress;

		/*
		 * Allocate large buffer queue control blocks.
		 */
		rx_ring->lbq_desc =
		    kmem_zalloc(rx_ring->lbq_len * sizeof (struct bq_desc),
		    KM_NOSLEEP);
		if (rx_ring->lbq_desc == NULL) {
			cmn_err(CE_WARN,
			    "Large buffer queue control block allocation "
			    "failed.");
			goto err_mem;
		}
		ql_init_lbq_ring(rx_ring);
	}

	if (ql_alloc_phys(qlge->dip, &rx_ring->cqicb_dma.dma_handle,
	    &ql_desc_acc_attr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &rx_ring->cqicb_dma.acc_handle,
	    (size_t)sizeof (struct cqicb_t),  /* mem size */
	    (size_t)0, /* alignment:128 bytes boundary */
	    (caddr_t *)&rx_ring->cqicb_dma.vaddr,
	    &dma_cookie) != 0) {
		bzero(&rx_ring->cqicb_dma, sizeof (rx_ring->cqicb_dma));
		cmn_err(CE_WARN, "%s(%d): cqicb allocation failed.",
		    __func__, qlge->instance);
		goto err_mem;
	}
	rx_ring->cqicb_dma.dma_addr = dma_cookie.dmac_laddress;

	return (DDI_SUCCESS);

err_mem:
	ql_free_rx_resources(rx_ring);
	return (DDI_FAILURE);
}

/*
 * Frees tx/rx queues memory resources
 */
static void
ql_free_mem_resources(qlge_t *qlge)
{
	int i;

	if (qlge->ricb_dma.dma_handle) {
		/* free the ricb struct */
		ql_free_phys(&qlge->ricb_dma.dma_handle,
		    &qlge->ricb_dma.acc_handle);
		bzero(&qlge->ricb_dma, sizeof (qlge->ricb_dma));
	}

	ql_free_rx_buffers(qlge);

	ql_free_ioctl_dma_buf(qlge);

	for (i = 0; i < qlge->tx_ring_count; i++)
		ql_free_tx_resources(&qlge->tx_ring[i]);

	for (i = 0; i < qlge->rx_ring_count; i++)
		ql_free_rx_resources(&qlge->rx_ring[i]);

	ql_free_shadow_space(qlge);
}

/*
 * Allocate buffer queues, large buffers and small buffers etc
 *
 * This API is called in the gld_attach member function. It is called
 * only once.  Later reset,reboot should not re-allocate all rings and
 * buffers.
 */
static int
ql_alloc_mem_resources(qlge_t *qlge)
{
	int i;
	ddi_dma_cookie_t dma_cookie;

	/* Allocate space for our shadow registers */
	if (ql_alloc_shadow_space(qlge))
		return (DDI_FAILURE);

	for (i = 0; i < qlge->rx_ring_count; i++) {
		if (ql_alloc_rx_resources(qlge, &qlge->rx_ring[i]) != 0) {
			cmn_err(CE_WARN, "RX resource allocation failed.");
			goto err_mem;
		}
	}
	/* Allocate tx queue resources */
	for (i = 0; i < qlge->tx_ring_count; i++) {
		if (ql_alloc_tx_resources(qlge, &qlge->tx_ring[i]) != 0) {
			cmn_err(CE_WARN, "Tx resource allocation failed.");
			goto err_mem;
		}
	}

	if (ql_alloc_ioctl_dma_buf(qlge) != DDI_SUCCESS) {
		goto err_mem;
	}

	if (ql_alloc_rx_buffers(qlge) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "?%s(%d): ql_alloc_rx_buffers failed",
		    __func__, qlge->instance);
		goto err_mem;
	}

	qlge->sequence |= INIT_ALLOC_RX_BUF;

	if (ql_alloc_phys(qlge->dip, &qlge->ricb_dma.dma_handle,
	    &ql_desc_acc_attr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &qlge->ricb_dma.acc_handle,
	    (size_t)sizeof (struct ricb),  /* mem size */
	    (size_t)0, /* alignment:128 bytes boundary */
	    (caddr_t *)&qlge->ricb_dma.vaddr,
	    &dma_cookie) != 0) {
		bzero(&qlge->ricb_dma, sizeof (qlge->ricb_dma));
		cmn_err(CE_WARN, "%s(%d): ricb allocation failed.",
		    __func__, qlge->instance);
		goto err_mem;
	}
	qlge->ricb_dma.dma_addr = dma_cookie.dmac_laddress;

	return (DDI_SUCCESS);

err_mem:
	ql_free_mem_resources(qlge);
	return (DDI_FAILURE);
}


/*
 * Function used to allocate physical memory and zero it.
 */

static int
ql_alloc_phys_rbuf(dev_info_t *dip, ddi_dma_handle_t *dma_handle,
    ddi_device_acc_attr_t *device_acc_attr,
    uint_t dma_flags,
    ddi_acc_handle_t *acc_handle,
    size_t size,
    size_t alignment,
    caddr_t *vaddr,
    ddi_dma_cookie_t *dma_cookie)
{
	size_t rlen;
	uint_t cnt;

	/*
	 * Workaround for SUN XMITS buffer must end and start on 8 byte
	 * boundary. Else, hardware will overrun the buffer. Simple fix is
	 * to make sure buffer has enough room for overrun.
	 */
	if (size & 7) {
		size += 8 - (size & 7);
	}

	/* Adjust the alignment if requested */
	if (alignment) {
		dma_attr.dma_attr_align = alignment;
	}

	/*
	 * Allocate DMA handle
	 */
	if (ddi_dma_alloc_handle(dip, &dma_attr_rbuf, DDI_DMA_DONTWAIT, NULL,
	    dma_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, QL_BANG "%s:  ddi_dma_alloc_handle FAILED",
		    __func__);
		*dma_handle = NULL;
		return (QL_ERROR);
	}
	/*
	 * Allocate DMA memory
	 */
	if (ddi_dma_mem_alloc(*dma_handle, size, device_acc_attr,
	    dma_flags & (DDI_DMA_CONSISTENT|DDI_DMA_STREAMING),
	    DDI_DMA_DONTWAIT,
	    NULL, vaddr, &rlen, acc_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "alloc_phys: DMA Memory alloc Failed");
		ddi_dma_free_handle(dma_handle);
		*acc_handle = NULL;
		*dma_handle = NULL;
		return (QL_ERROR);
	}

	if (ddi_dma_addr_bind_handle(*dma_handle, NULL, *vaddr, rlen,
	    dma_flags, DDI_DMA_DONTWAIT, NULL,
	    dma_cookie, &cnt) != DDI_DMA_MAPPED) {
		ddi_dma_mem_free(acc_handle);

		ddi_dma_free_handle(dma_handle);
		cmn_err(CE_WARN, "%s ddi_dma_addr_bind_handle FAILED",
		    __func__);
		*acc_handle = NULL;
		*dma_handle = NULL;
		return (QL_ERROR);
	}

	if (cnt != 1) {

		ql_free_phys(dma_handle, acc_handle);

		cmn_err(CE_WARN, "%s: cnt != 1; Failed segment count",
		    __func__);
		return (QL_ERROR);
	}

	bzero((caddr_t)*vaddr, rlen);

	return (0);
}

/*
 * Function used to allocate physical memory and zero it.
 */
static int
ql_alloc_phys(dev_info_t *dip, ddi_dma_handle_t *dma_handle,
    ddi_device_acc_attr_t *device_acc_attr,
    uint_t dma_flags,
    ddi_acc_handle_t *acc_handle,
    size_t size,
    size_t alignment,
    caddr_t *vaddr,
    ddi_dma_cookie_t *dma_cookie)
{
	size_t rlen;
	uint_t cnt;

	/*
	 * Workaround for SUN XMITS buffer must end and start on 8 byte
	 * boundary. Else, hardware will overrun the buffer. Simple fix is
	 * to make sure buffer has enough room for overrun.
	 */
	if (size & 7) {
		size += 8 - (size & 7);
	}

	/* Adjust the alignment if requested */
	if (alignment) {
		dma_attr.dma_attr_align = alignment;
	}

	/*
	 * Allocate DMA handle
	 */
	if (ddi_dma_alloc_handle(dip, &dma_attr, DDI_DMA_DONTWAIT, NULL,
	    dma_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, QL_BANG "%s:  ddi_dma_alloc_handle FAILED",
		    __func__);
		*dma_handle = NULL;
		return (QL_ERROR);
	}
	/*
	 * Allocate DMA memory
	 */
	if (ddi_dma_mem_alloc(*dma_handle, size, device_acc_attr,
	    dma_flags & (DDI_DMA_CONSISTENT|DDI_DMA_STREAMING),
	    DDI_DMA_DONTWAIT,
	    NULL, vaddr, &rlen, acc_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "alloc_phys: DMA Memory alloc Failed");
		ddi_dma_free_handle(dma_handle);
		*acc_handle = NULL;
		*dma_handle = NULL;
		return (QL_ERROR);
	}

	if (ddi_dma_addr_bind_handle(*dma_handle, NULL, *vaddr, rlen,
	    dma_flags, DDI_DMA_DONTWAIT, NULL,
	    dma_cookie, &cnt) != DDI_DMA_MAPPED) {
		ddi_dma_mem_free(acc_handle);
		ddi_dma_free_handle(dma_handle);
		cmn_err(CE_WARN, "%s ddi_dma_addr_bind_handle FAILED",
		    __func__);
		*acc_handle = NULL;
		*dma_handle = NULL;
		return (QL_ERROR);
	}

	if (cnt != 1) {

		ql_free_phys(dma_handle, acc_handle);

		cmn_err(CE_WARN, "%s: cnt != 1; Failed segment count",
		    __func__);
		return (QL_ERROR);
	}

	bzero((caddr_t)*vaddr, rlen);

	return (0);
}

/*
 * Add interrupt handlers based on the interrupt type.
 * Before adding the interrupt handlers, the interrupt vectors should
 * have been allocated, and the rx/tx rings have also been allocated.
 */
static int
ql_add_intr_handlers(qlge_t *qlge)
{
	int vector = 0;
	int rc, i;
	uint32_t value;
	struct intr_ctx *intr_ctx = &qlge->intr_ctx[0];

	switch (qlge->intr_type) {
	case DDI_INTR_TYPE_MSIX:
		/*
		 * Add interrupt handler for rx and tx rings: vector[0 -
		 * (qlge->intr_cnt -1)].
		 */
		value = 0;
		for (vector = 0; vector < qlge->intr_cnt; vector++) {
			ql_atomic_set_32(&intr_ctx->irq_cnt, value);

			/*
			 * associate interrupt vector with interrupt handler
			 */
			rc = ddi_intr_add_handler(qlge->htable[vector],
			    (ddi_intr_handler_t *)intr_ctx->handler,
			    (void *)&qlge->rx_ring[vector], NULL);

			QL_PRINT(DBG_INIT, ("rx_ring[%d] 0x%p\n",
			    vector, &qlge->rx_ring[vector]));
			if (rc != DDI_SUCCESS) {
				QL_PRINT(DBG_INIT,
				    ("Add rx interrupt handler failed. "
				    "return: %d, vector: %d", rc, vector));
				for (vector--; vector >= 0; vector--) {
					(void) ddi_intr_remove_handler(
					    qlge->htable[vector]);
				}
				return (DDI_FAILURE);
			}
			intr_ctx++;
		}
		break;

	case DDI_INTR_TYPE_MSI:
		/*
		 * Add interrupt handlers for the only vector
		 */
		ql_atomic_set_32(&intr_ctx->irq_cnt, value);

		rc = ddi_intr_add_handler(qlge->htable[vector],
		    ql_isr,
		    (caddr_t)&qlge->rx_ring[0], NULL);

		if (rc != DDI_SUCCESS) {
			QL_PRINT(DBG_INIT,
			    ("Add MSI interrupt handler failed: %d\n", rc));
			return (DDI_FAILURE);
		}
		break;

	case DDI_INTR_TYPE_FIXED:
		/*
		 * Add interrupt handlers for the only vector
		 */
		ql_atomic_set_32(&intr_ctx->irq_cnt, value);

		rc = ddi_intr_add_handler(qlge->htable[vector],
		    ql_isr,
		    (caddr_t)&qlge->rx_ring[0], NULL);

		if (rc != DDI_SUCCESS) {
			QL_PRINT(DBG_INIT,
			    ("Add legacy interrupt handler failed: %d\n", rc));
			return (DDI_FAILURE);
		}
		break;

	default:
		return (DDI_FAILURE);
	}

	/* Enable interrupts */
	/* Block enable */
	if (qlge->intr_cap & DDI_INTR_FLAG_BLOCK) {
		QL_PRINT(DBG_INIT, ("Block enabling %d interrupt(s)\n",
		    qlge->intr_cnt));
		(void) ddi_intr_block_enable(qlge->htable, qlge->intr_cnt);
	} else { /* Non block enable */
		for (i = 0; i < qlge->intr_cnt; i++) {
			QL_PRINT(DBG_INIT, ("Non Block Enabling interrupt %d "
			    "handle 0x%x\n", i, qlge->htable[i]));
			(void) ddi_intr_enable(qlge->htable[i]);
		}
	}
	qlge->sequence |= INIT_INTR_ENABLED;

	return (DDI_SUCCESS);
}

/*
 * Here we build the intr_ctx structures based on
 * our rx_ring count and intr vector count.
 * The intr_ctx structure is used to hook each vector
 * to possibly different handlers.
 */
static void
ql_resolve_queues_to_irqs(qlge_t *qlge)
{
	int i = 0;
	struct intr_ctx *intr_ctx = &qlge->intr_ctx[0];

	if (qlge->intr_type == DDI_INTR_TYPE_MSIX) {
		/*
		 * Each rx_ring has its own intr_ctx since we
		 * have separate vectors for each queue.
		 * This only true when MSI-X is enabled.
		 */
		for (i = 0; i < qlge->intr_cnt; i++, intr_ctx++) {
			qlge->rx_ring[i].irq = i;
			intr_ctx->intr = i;
			intr_ctx->qlge = qlge;

			/*
			 * We set up each vectors enable/disable/read bits so
			 * there's no bit/mask calculations in critical path.
			 */
			intr_ctx->intr_en_mask =
			    INTR_EN_TYPE_MASK | INTR_EN_INTR_MASK |
			    INTR_EN_TYPE_ENABLE | INTR_EN_IHD_MASK |
			    INTR_EN_IHD | i;
			intr_ctx->intr_dis_mask =
			    INTR_EN_TYPE_MASK | INTR_EN_INTR_MASK |
			    INTR_EN_TYPE_DISABLE | INTR_EN_IHD_MASK |
			    INTR_EN_IHD | i;
			intr_ctx->intr_read_mask =
			    INTR_EN_TYPE_MASK | INTR_EN_INTR_MASK |
			    INTR_EN_TYPE_READ | INTR_EN_IHD_MASK | INTR_EN_IHD
			    | i;

			if (i == 0) {
				/*
				 * Default queue handles bcast/mcast plus
				 * async events.
				 */
				intr_ctx->handler = ql_isr;
			} else if (qlge->rx_ring[i].type == TX_Q) {
				/*
				 * Outbound queue is for outbound completions
				 * only.
				 */
				if (qlge->isr_stride)
					intr_ctx->handler = ql_msix_isr;
				else
					intr_ctx->handler = ql_msix_tx_isr;
			} else {
				/*
				 * Inbound queues handle unicast frames only.
				 */
				if (qlge->isr_stride)
					intr_ctx->handler = ql_msix_isr;
				else
					intr_ctx->handler = ql_msix_rx_isr;
			}
		}
		i = qlge->intr_cnt;
		for (; i < qlge->rx_ring_count; i++, intr_ctx++) {
			int iv = i - qlge->isr_stride;
			qlge->rx_ring[i].irq = iv;
			intr_ctx->intr = iv;
			intr_ctx->qlge = qlge;

			/*
			 * We set up each vectors enable/disable/read bits so
			 * there's no bit/mask calculations in critical path.
			 */
			intr_ctx->intr_en_mask =
			    INTR_EN_TYPE_MASK | INTR_EN_INTR_MASK |
			    INTR_EN_TYPE_ENABLE | INTR_EN_IHD_MASK |
			    INTR_EN_IHD | iv;
			intr_ctx->intr_dis_mask =
			    INTR_EN_TYPE_MASK | INTR_EN_INTR_MASK |
			    INTR_EN_TYPE_DISABLE | INTR_EN_IHD_MASK |
			    INTR_EN_IHD | iv;
			intr_ctx->intr_read_mask =
			    INTR_EN_TYPE_MASK | INTR_EN_INTR_MASK |
			    INTR_EN_TYPE_READ | INTR_EN_IHD_MASK | INTR_EN_IHD
			    | iv;

			if (qlge->rx_ring[i].type == TX_Q) {
				/*
				 * Outbound queue is for outbound completions
				 * only.
				 */
				intr_ctx->handler = ql_msix_isr;
			} else {
				/*
				 * Inbound queues handle unicast frames only.
				 */
				intr_ctx->handler = ql_msix_rx_isr;
			}
		}
	} else {
		/*
		 * All rx_rings use the same intr_ctx since
		 * there is only one vector.
		 */
		intr_ctx->intr = 0;
		intr_ctx->qlge = qlge;
		/*
		 * We set up each vectors enable/disable/read bits so
		 * there's no bit/mask calculations in the critical path.
		 */
		intr_ctx->intr_en_mask =
		    INTR_EN_TYPE_MASK | INTR_EN_INTR_MASK |
		    INTR_EN_TYPE_ENABLE;
		intr_ctx->intr_dis_mask =
		    INTR_EN_TYPE_MASK | INTR_EN_INTR_MASK |
		    INTR_EN_TYPE_DISABLE;
		intr_ctx->intr_read_mask =
		    INTR_EN_TYPE_MASK | INTR_EN_INTR_MASK |
		    INTR_EN_TYPE_READ;
		/*
		 * Single interrupt means one handler for all rings.
		 */
		intr_ctx->handler = ql_isr;
		for (i = 0; i < qlge->rx_ring_count; i++)
			qlge->rx_ring[i].irq = 0;
	}
}


/*
 * Free allocated interrupts.
 */
static void
ql_free_irq_vectors(qlge_t *qlge)
{
	int i;
	int rc;

	if (qlge->sequence & INIT_INTR_ENABLED) {
		/* Disable all interrupts */
		if (qlge->intr_cap & DDI_INTR_FLAG_BLOCK) {
			/* Call ddi_intr_block_disable() */
			(void) ddi_intr_block_disable(qlge->htable,
			    qlge->intr_cnt);
		} else {
			for (i = 0; i < qlge->intr_cnt; i++) {
				(void) ddi_intr_disable(qlge->htable[i]);
			}
		}

		qlge->sequence &= ~INIT_INTR_ENABLED;
	}

	for (i = 0; i < qlge->intr_cnt; i++) {

		if (qlge->sequence & INIT_ADD_INTERRUPT)
			(void) ddi_intr_remove_handler(qlge->htable[i]);

		if (qlge->sequence & INIT_INTR_ALLOC) {
			rc = ddi_intr_free(qlge->htable[i]);
			if (rc != DDI_SUCCESS) {
				/* EMPTY */
				QL_PRINT(DBG_INIT, ("Free intr failed: %d",
				    rc));
			}
		}
	}
	if (qlge->sequence & INIT_INTR_ALLOC)
		qlge->sequence &= ~INIT_INTR_ALLOC;

	if (qlge->sequence & INIT_ADD_INTERRUPT)
		qlge->sequence &= ~INIT_ADD_INTERRUPT;

	if (qlge->htable) {
		kmem_free(qlge->htable, qlge->intr_size);
		qlge->htable = NULL;
	}
}

/*
 * Allocate interrupt vectors
 * For legacy and MSI, only 1 handle is needed.
 * For MSI-X, if fewer than 2 vectors are available, return failure.
 * Upon success, this maps the vectors to rx and tx rings for
 * interrupts.
 */
static int
ql_request_irq_vectors(qlge_t *qlge, int intr_type)
{
	dev_info_t *devinfo;
	uint32_t request, orig;
	int count, avail, actual;
	int minimum;
	int rc;

	devinfo = qlge->dip;

	switch (intr_type) {
	case DDI_INTR_TYPE_FIXED:
		request = 1;	/* Request 1 legacy interrupt handle */
		minimum = 1;
		QL_PRINT(DBG_INIT, ("interrupt type: legacy\n"));
		break;

	case DDI_INTR_TYPE_MSI:
		request = 1;	/* Request 1 MSI interrupt handle */
		minimum = 1;
		QL_PRINT(DBG_INIT, ("interrupt type: MSI\n"));
		break;

	case DDI_INTR_TYPE_MSIX:
		/*
		 * Ideal number of vectors for the adapter is
		 * # rss rings + tx completion rings for default completion
		 * queue.
		 */
		request = qlge->rx_ring_count;

		orig = request;
		if (request > (MAX_RX_RINGS))
			request = MAX_RX_RINGS;
		minimum = 2;
		QL_PRINT(DBG_INIT, ("interrupt type: MSI-X\n"));
		break;

	default:
		QL_PRINT(DBG_INIT, ("Invalid parameter\n"));
		return (DDI_FAILURE);
	}

	QL_PRINT(DBG_INIT, ("interrupt handles requested: %d  minimum: %d\n",
	    request, minimum));

	/*
	 * Get number of supported interrupts
	 */
	rc = ddi_intr_get_nintrs(devinfo, intr_type, &count);
	if ((rc != DDI_SUCCESS) || (count < minimum)) {
		QL_PRINT(DBG_INIT, ("Get interrupt number failed. Return: %d, "
		    "count: %d\n", rc, count));
		return (DDI_FAILURE);
	}
	QL_PRINT(DBG_INIT, ("interrupts supported: %d\n", count));

	/*
	 * Get number of available interrupts
	 */
	rc = ddi_intr_get_navail(devinfo, intr_type, &avail);
	if ((rc != DDI_SUCCESS) || (avail < minimum)) {
		QL_PRINT(DBG_INIT,
		    ("Get interrupt available number failed. Return:"
		    " %d, available: %d\n", rc, avail));
		return (DDI_FAILURE);
	}
	QL_PRINT(DBG_INIT, ("interrupts available: %d\n", avail));

	if (avail < request) {
		QL_PRINT(DBG_INIT, ("Request %d handles, %d available\n",
		    request, avail));
		request = avail;
	}

	actual = 0;
	qlge->intr_cnt = 0;

	/*
	 * Allocate an array of interrupt handles
	 */
	qlge->intr_size = (size_t)(request * sizeof (ddi_intr_handle_t));
	qlge->htable = kmem_alloc(qlge->intr_size, KM_SLEEP);

	rc = ddi_intr_alloc(devinfo, qlge->htable, intr_type, 0,
	    (int)request, &actual, DDI_INTR_ALLOC_NORMAL);
	if (rc != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s(%d) Allocate interrupts failed. return:"
		    " %d, request: %d, actual: %d",
		    __func__, qlge->instance, rc, request, actual);
		goto ql_intr_alloc_fail;
	}
	qlge->intr_cnt = actual;

	qlge->sequence |= INIT_INTR_ALLOC;

	/*
	 * If the actual number of vectors is less than the minumum
	 * then fail.
	 */
	if (actual < minimum) {
		cmn_err(CE_WARN,
		    "Insufficient interrupt handles available: %d", actual);
		goto ql_intr_alloc_fail;
	}

	/*
	 * For MSI-X, actual might force us to reduce number of tx & rx rings
	 */
	if ((intr_type == DDI_INTR_TYPE_MSIX) && (orig > actual)) {
		if (actual >= (orig / 2)) {
			count = orig / 2;
			qlge->rss_ring_count = count;
			qlge->tx_ring_count = count;
			qlge->isr_stride = count;
		} else if (actual >= (orig / 4)) {
			count = orig / 4;
			qlge->rss_ring_count = count;
			qlge->tx_ring_count = count;
			qlge->isr_stride = count;
		} else if (actual >= (orig / 8)) {
			count = orig / 8;
			qlge->rss_ring_count = count;
			qlge->tx_ring_count = count;
			qlge->isr_stride = count;
		} else if (actual < MAX_RX_RINGS) {
			qlge->tx_ring_count = 1;
			qlge->rss_ring_count = actual - 1;
		}
		qlge->intr_cnt = count;
		qlge->rx_ring_count = qlge->tx_ring_count +
		    qlge->rss_ring_count;
	}
	cmn_err(CE_NOTE, "!qlge(%d) tx %d, rss %d, stride %d\n", qlge->instance,
	    qlge->tx_ring_count, qlge->rss_ring_count, qlge->isr_stride);

	/*
	 * Get priority for first vector, assume remaining are all the same
	 */
	rc = ddi_intr_get_pri(qlge->htable[0], &qlge->intr_pri);
	if (rc != DDI_SUCCESS) {
		QL_PRINT(DBG_INIT, ("Get interrupt priority failed: %d\n", rc));
		goto ql_intr_alloc_fail;
	}

	rc = ddi_intr_get_cap(qlge->htable[0], &qlge->intr_cap);
	if (rc != DDI_SUCCESS) {
		QL_PRINT(DBG_INIT, ("Get interrupt cap failed: %d\n", rc));
		goto ql_intr_alloc_fail;
	}

	qlge->intr_type = intr_type;

	return (DDI_SUCCESS);

ql_intr_alloc_fail:
	ql_free_irq_vectors(qlge);

	return (DDI_FAILURE);
}

/*
 * Allocate interrupt vector(s) for one of the following interrupt types, MSI-X,
 * MSI or Legacy. In MSI and Legacy modes we only support a single receive and
 * transmit queue.
 */
int
ql_alloc_irqs(qlge_t *qlge)
{
	int intr_types;
	int rval;

	/*
	 * Get supported interrupt types
	 */
	if (ddi_intr_get_supported_types(qlge->dip, &intr_types)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s(%d):ddi_intr_get_supported_types failed",
		    __func__, qlge->instance);

		return (DDI_FAILURE);
	}

	QL_PRINT(DBG_INIT, ("%s(%d) Interrupt types supported %d\n",
	    __func__, qlge->instance, intr_types));

	/* Install MSI-X interrupts */
	if ((intr_types & DDI_INTR_TYPE_MSIX) != 0) {
		QL_PRINT(DBG_INIT, ("%s(%d) MSI-X interrupt supported %d\n",
		    __func__, qlge->instance, intr_types));
		rval = ql_request_irq_vectors(qlge, DDI_INTR_TYPE_MSIX);
		if (rval == DDI_SUCCESS) {
			return (rval);
		}
		QL_PRINT(DBG_INIT, ("%s(%d) MSI-X interrupt allocation failed,"
		    " trying MSI interrupts ...\n", __func__, qlge->instance));
	}

	/*
	 * We will have 2 completion queues in MSI / Legacy mode,
	 * Queue 0 for default completions
	 * Queue 1 for transmit completions
	 */
	qlge->rss_ring_count = 1; /* Default completion queue (0) for all */
	qlge->tx_ring_count = 1; /* Single tx completion queue */
	qlge->rx_ring_count = qlge->tx_ring_count + qlge->rss_ring_count;

	QL_PRINT(DBG_INIT, ("%s(%d) Falling back to single completion queue \n",
	    __func__, qlge->instance));
	/*
	 * Add the h/w interrupt handler and initialise mutexes
	 */
	rval = DDI_FAILURE;

	/*
	 * If OS supports MSIX interrupt but fails to allocate, then try
	 * MSI interrupt. If MSI interrupt allocation fails also, then roll
	 * back to fixed interrupt.
	 */
	if (intr_types & DDI_INTR_TYPE_MSI) {
		rval = ql_request_irq_vectors(qlge, DDI_INTR_TYPE_MSI);
		if (rval == DDI_SUCCESS) {
			qlge->intr_type = DDI_INTR_TYPE_MSI;
			QL_PRINT(DBG_INIT, ("%s(%d) use MSI Interrupt \n",
			    __func__, qlge->instance));
		}
	}

	/* Try Fixed interrupt Legacy mode */
	if (rval != DDI_SUCCESS) {
		rval = ql_request_irq_vectors(qlge, DDI_INTR_TYPE_FIXED);
		if (rval != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d):Legacy mode interrupt "
			    "allocation failed",
			    __func__, qlge->instance);
		} else {
			qlge->intr_type = DDI_INTR_TYPE_FIXED;
			QL_PRINT(DBG_INIT, ("%s(%d) use Fixed Interrupt \n",
			    __func__, qlge->instance));
		}
	}

	return (rval);
}

static void
ql_free_rx_tx_locks(qlge_t *qlge)
{
	int i;
	struct rx_ring *rx_ring;
	struct tx_ring *tx_ring;

	for (i = 0; i < qlge->tx_ring_count; i++) {
		tx_ring = &qlge->tx_ring[i];
		mutex_destroy(&tx_ring->tx_lock);
	}

	for (i = 0; i < qlge->rx_ring_count; i++) {
		rx_ring = &qlge->rx_ring[i];
		mutex_destroy(&rx_ring->rx_lock);
		mutex_destroy(&rx_ring->sbq_lock);
		mutex_destroy(&rx_ring->lbq_lock);
	}
}

/*
 * Frees all resources allocated during attach.
 *
 * Input:
 * dip = pointer to device information structure.
 * sequence = bits indicating resources to free.
 *
 * Context:
 * Kernel context.
 */
static void
ql_free_resources(qlge_t *qlge)
{

	/* Disable driver timer */
	ql_stop_timer(qlge);

	if (qlge->sequence & INIT_MAC_REGISTERED) {
		(void) mac_unregister(qlge->mh);
		qlge->sequence &= ~INIT_MAC_REGISTERED;
	}

	if (qlge->sequence & INIT_MAC_ALLOC) {
		/* Nothing to do, macp is already freed */
		qlge->sequence &= ~INIT_MAC_ALLOC;
	}

	if (qlge->sequence & INIT_PCI_CONFIG_SETUP) {
		pci_config_teardown(&qlge->pci_handle);
		qlge->sequence &= ~INIT_PCI_CONFIG_SETUP;
	}

	if (qlge->sequence & INIT_INTR_ALLOC) {
		ql_free_irq_vectors(qlge);
		qlge->sequence &= ~INIT_ADD_INTERRUPT;
	}

	if (qlge->sequence & INIT_ADD_SOFT_INTERRUPT) {
		(void) ddi_intr_remove_softint(qlge->mpi_event_intr_hdl);
		(void) ddi_intr_remove_softint(qlge->mpi_reset_intr_hdl);
		(void) ddi_intr_remove_softint(qlge->asic_reset_intr_hdl);
		qlge->sequence &= ~INIT_ADD_SOFT_INTERRUPT;
	}

	if (qlge->sequence & INIT_KSTATS) {
		ql_fini_kstats(qlge);
		qlge->sequence &= ~INIT_KSTATS;
	}

	if (qlge->sequence & INIT_MUTEX) {
		mutex_destroy(&qlge->gen_mutex);
		mutex_destroy(&qlge->hw_mutex);
		mutex_destroy(&qlge->mbx_mutex);
		cv_destroy(&qlge->cv_mbx_intr);
		qlge->sequence &= ~INIT_MUTEX;
	}

	if (qlge->sequence & INIT_LOCKS_CREATED) {
		ql_free_rx_tx_locks(qlge);
		qlge->sequence &= ~INIT_LOCKS_CREATED;
	}

	if (qlge->sequence & INIT_MEMORY_ALLOC) {
		ql_free_mem_resources(qlge);
		qlge->sequence &= ~INIT_MEMORY_ALLOC;
	}

	if (qlge->sequence & INIT_REGS_SETUP) {
		ddi_regs_map_free(&qlge->dev_handle);
		qlge->sequence &= ~INIT_REGS_SETUP;
	}

	if (qlge->sequence & INIT_DOORBELL_REGS_SETUP) {
		ddi_regs_map_free(&qlge->dev_doorbell_reg_handle);
		qlge->sequence &= ~INIT_DOORBELL_REGS_SETUP;
	}

	/*
	 * free flash flt table that allocated in attach stage
	 */
	if ((qlge->flt.ql_flt_entry_ptr != NULL)&&
	    (qlge->flt.header.length != 0)) {
		kmem_free(qlge->flt.ql_flt_entry_ptr, qlge->flt.header.length);
		qlge->flt.ql_flt_entry_ptr = NULL;
	}

	if (qlge->sequence & INIT_FM) {
		ql_fm_fini(qlge);
		qlge->sequence &= ~INIT_FM;
	}

	ddi_prop_remove_all(qlge->dip);
	ddi_set_driver_private(qlge->dip, NULL);

	/* finally, free qlge structure */
	if (qlge->sequence & INIT_SOFTSTATE_ALLOC) {
		kmem_free(qlge, sizeof (qlge_t));
	}
}

/*
 * Set promiscuous mode of the driver
 * Caller must catch HW_LOCK
 */
void
ql_set_promiscuous(qlge_t *qlge, int mode)
{
	if (mode) {
		(void) ql_set_routing_reg(qlge, RT_IDX_PROMISCUOUS_SLOT,
		    RT_IDX_VALID, 1);
	} else {
		(void) ql_set_routing_reg(qlge, RT_IDX_PROMISCUOUS_SLOT,
		    RT_IDX_VALID, 0);
	}
}
/*
 * Write 'data1' to Mac Protocol Address Index Register and
 * 'data2' to Mac Protocol Address Data Register
 *  Assuming that the Mac Protocol semaphore lock has been acquired.
 */
static int
ql_write_mac_proto_regs(qlge_t *qlge, uint32_t data1, uint32_t data2)
{
	int return_value = DDI_SUCCESS;

	if (ql_wait_reg_bit(qlge, REG_MAC_PROTOCOL_ADDRESS_INDEX,
	    MAC_PROTOCOL_ADDRESS_INDEX_MW, BIT_SET, 5) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Wait for MAC_PROTOCOL Address Register "
		    "timeout.");
		return_value = DDI_FAILURE;
		goto out;
	}
	ql_write_reg(qlge, REG_MAC_PROTOCOL_ADDRESS_INDEX /* A8 */, data1);
	ql_write_reg(qlge, REG_MAC_PROTOCOL_DATA /* 0xAC */, data2);
out:
	return (return_value);
}
/*
 * Enable the 'index'ed multicast address in the host memory's multicast_list
 */
int
ql_add_multicast_address(qlge_t *qlge, int index)
{
	int rtn_val = DDI_FAILURE;
	uint32_t offset;
	uint32_t value1, value2;

	/* Acquire the required semaphore */
	if (ql_sem_spinlock(qlge, QL_MAC_PROTOCOL_SEM_MASK) != DDI_SUCCESS) {
		return (rtn_val);
	}

	/* Program Offset0 - lower 32 bits of the MAC address */
	offset = 0;
	value1 = MAC_PROTOCOL_ADDRESS_ENABLE | MAC_PROTOCOL_TYPE_MULTICAST |
	    (index << 4) | offset;
	value2 = ((qlge->multicast_list[index].addr.ether_addr_octet[2] << 24)
	    |(qlge->multicast_list[index].addr.ether_addr_octet[3] << 16)
	    |(qlge->multicast_list[index].addr.ether_addr_octet[4] << 8)
	    |(qlge->multicast_list[index].addr.ether_addr_octet[5]));
	if (ql_write_mac_proto_regs(qlge, value1, value2) != DDI_SUCCESS)
		goto out;

	/* Program offset1: upper 16 bits of the MAC address */
	offset = 1;
	value1 = MAC_PROTOCOL_ADDRESS_ENABLE | MAC_PROTOCOL_TYPE_MULTICAST |
	    (index<<4) | offset;
	value2 = ((qlge->multicast_list[index].addr.ether_addr_octet[0] << 8)
	    |qlge->multicast_list[index].addr.ether_addr_octet[1]);
	if (ql_write_mac_proto_regs(qlge, value1, value2) != DDI_SUCCESS) {
		goto out;
	}
	rtn_val = DDI_SUCCESS;
out:
	ql_sem_unlock(qlge, QL_MAC_PROTOCOL_SEM_MASK);
	return (rtn_val);
}

/*
 * Disable the 'index'ed multicast address in the host memory's multicast_list
 */
int
ql_remove_multicast_address(qlge_t *qlge, int index)
{
	int rtn_val = DDI_FAILURE;
	uint32_t offset;
	uint32_t value1, value2;

	/* Acquire the required semaphore */
	if (ql_sem_spinlock(qlge, QL_MAC_PROTOCOL_SEM_MASK) != DDI_SUCCESS) {
		return (rtn_val);
	}
	/* Program Offset0 - lower 32 bits of the MAC address */
	offset = 0;
	value1 = (MAC_PROTOCOL_TYPE_MULTICAST | offset)|(index<<4);
	value2 =
	    ((qlge->multicast_list[index].addr.ether_addr_octet[2] << 24)
	    |(qlge->multicast_list[index].addr.ether_addr_octet[3] << 16)
	    |(qlge->multicast_list[index].addr.ether_addr_octet[4] << 8)
	    |(qlge->multicast_list[index].addr.ether_addr_octet[5]));
	if (ql_write_mac_proto_regs(qlge, value1, value2) != DDI_SUCCESS) {
		goto out;
	}
	/* Program offset1: upper 16 bits of the MAC address */
	offset = 1;
	value1 = (MAC_PROTOCOL_TYPE_MULTICAST | offset)|(index<<4);
	value2 = 0;
	if (ql_write_mac_proto_regs(qlge, value1, value2) != DDI_SUCCESS) {
		goto out;
	}
	rtn_val = DDI_SUCCESS;
out:
	ql_sem_unlock(qlge, QL_MAC_PROTOCOL_SEM_MASK);
	return (rtn_val);
}

/*
 * Add a new multicast address to the list of supported list
 * This API is called after OS called gld_set_multicast (GLDv2)
 * or m_multicst (GLDv3)
 *
 * Restriction:
 * The number of maximum multicast address is limited by hardware.
 */
int
ql_add_to_multicast_list(qlge_t *qlge, uint8_t *ep)
{
	uint32_t index = qlge->multicast_list_count;
	int rval = DDI_SUCCESS;
	int status;

	if ((ep[0] & 01) == 0) {
		rval = EINVAL;
		goto exit;
	}

	/* if there is an availabe space in multicast_list, then add it */
	if (index < MAX_MULTICAST_LIST_SIZE) {
		bcopy(ep, qlge->multicast_list[index].addr.ether_addr_octet,
		    ETHERADDRL);
		/* increment the total number of addresses in multicast list */
		(void) ql_add_multicast_address(qlge, index);
		qlge->multicast_list_count++;
		QL_PRINT(DBG_GLD,
		    ("%s(%d): added to index of multicast list= 0x%x, "
		    "total %d\n", __func__, qlge->instance, index,
		    qlge->multicast_list_count));

		if (index > MAX_MULTICAST_HW_SIZE) {
			if (!qlge->multicast_promisc) {
				status = ql_set_routing_reg(qlge,
				    RT_IDX_ALLMULTI_SLOT,
				    RT_IDX_MCAST, 1);
				if (status) {
					cmn_err(CE_WARN,
					    "Failed to init routing reg "
					    "for mcast promisc mode.");
					rval = ENOENT;
					goto exit;
				}
				qlge->multicast_promisc = B_TRUE;
			}
		}
	} else {
		rval = ENOENT;
	}
exit:
	return (rval);
}

/*
 * Remove an old multicast address from the list of supported multicast
 * addresses. This API is called after OS called gld_set_multicast (GLDv2)
 * or m_multicst (GLDv3)
 * The number of maximum multicast address is limited by hardware.
 */
int
ql_remove_from_multicast_list(qlge_t *qlge, uint8_t *ep)
{
	uint32_t total = qlge->multicast_list_count;
	int i = 0;
	int rmv_index = 0;
	size_t length = sizeof (ql_multicast_addr);
	int status;

	for (i = 0; i < total; i++) {
		if (bcmp(ep, &qlge->multicast_list[i].addr, ETHERADDRL) != 0) {
			continue;
		}

		rmv_index = i;
		/* block move the reset of other multicast address forward */
		length = ((total -1) -i) * sizeof (ql_multicast_addr);
		if (length > 0) {
			bcopy(&qlge->multicast_list[i+1],
			    &qlge->multicast_list[i], length);
		}
		qlge->multicast_list_count--;
		if (qlge->multicast_list_count <= MAX_MULTICAST_HW_SIZE) {
			/*
			 * there is a deletion in multicast list table,
			 * re-enable them
			 */
			for (i = rmv_index; i < qlge->multicast_list_count;
			    i++) {
				(void) ql_add_multicast_address(qlge, i);
			}
			/* and disable the last one */
			(void) ql_remove_multicast_address(qlge, i);

			/* disable multicast promiscuous mode */
			if (qlge->multicast_promisc) {
				status = ql_set_routing_reg(qlge,
				    RT_IDX_ALLMULTI_SLOT,
				    RT_IDX_MCAST, 0);
				if (status) {
					cmn_err(CE_WARN,
					    "Failed to init routing reg for "
					    "mcast promisc mode.");
					goto exit;
				}
				/* write to config register */
				qlge->multicast_promisc = B_FALSE;
			}
		}
		break;
	}
exit:
	return (DDI_SUCCESS);
}

/*
 * Read a XGMAC register
 */
int
ql_read_xgmac_reg(qlge_t *qlge, uint32_t addr, uint32_t *val)
{
	int rtn_val = DDI_FAILURE;

	/* wait for XGMAC Address register RDY bit set */
	if (ql_wait_reg_bit(qlge, REG_XGMAC_ADDRESS, XGMAC_ADDRESS_RDY,
	    BIT_SET, 10) != DDI_SUCCESS) {
		goto out;
	}
	/* start rx transaction */
	ql_write_reg(qlge, REG_XGMAC_ADDRESS, addr|XGMAC_ADDRESS_READ_TRANSACT);

	/*
	 * wait for XGMAC Address register RDY bit set,
	 * which indicates data is ready
	 */
	if (ql_wait_reg_bit(qlge, REG_XGMAC_ADDRESS, XGMAC_ADDRESS_RDY,
	    BIT_SET, 10) != DDI_SUCCESS) {
		goto out;
	}
	/* read data from XGAMC_DATA register */
	*val = ql_read_reg(qlge, REG_XGMAC_DATA);
	rtn_val = DDI_SUCCESS;
out:
	return (rtn_val);
}

/*
 * Implement checksum offload for IPv4 IP packets
 */
static void
ql_hw_csum_setup(qlge_t *qlge, uint32_t pflags, caddr_t bp,
    struct ob_mac_iocb_req *mac_iocb_ptr)
{
	struct ip *iphdr = NULL;
	struct ether_header *ethhdr;
	struct ether_vlan_header *ethvhdr;
	struct tcphdr *tcp_hdr;
	uint32_t etherType;
	int mac_hdr_len, ip_hdr_len, tcp_udp_hdr_len;
	int ip_hdr_off, tcp_udp_hdr_off, hdr_off;

	ethhdr  = (struct ether_header *)((void *)bp);
	ethvhdr = (struct ether_vlan_header *)((void *)bp);
	/* Is this vlan packet? */
	if (ntohs(ethvhdr->ether_tpid) == ETHERTYPE_VLAN) {
		mac_hdr_len = sizeof (struct ether_vlan_header);
		etherType = ntohs(ethvhdr->ether_type);
	} else {
		mac_hdr_len = sizeof (struct ether_header);
		etherType = ntohs(ethhdr->ether_type);
	}
	/* Is this IPv4 or IPv6 packet? */
	if (IPH_HDR_VERSION((ipha_t *)(void *)(bp+mac_hdr_len)) ==
	    IPV4_VERSION) {
		if (etherType == ETHERTYPE_IP /* 0800 */) {
			iphdr = (struct ip *)(void *)(bp+mac_hdr_len);
		} else {
			/* EMPTY */
			QL_PRINT(DBG_TX,
			    ("%s(%d) : IPv4 None IP packet type 0x%x\n",
			    __func__, qlge->instance, etherType));
		}
	}
	/* ipV4 packets */
	if (iphdr != NULL) {

		ip_hdr_len = IPH_HDR_LENGTH(iphdr);
		QL_PRINT(DBG_TX,
		    ("%s(%d) : IPv4 header length using IPH_HDR_LENGTH:"
		    " %d bytes \n", __func__, qlge->instance, ip_hdr_len));

		ip_hdr_off = mac_hdr_len;
		QL_PRINT(DBG_TX, ("%s(%d) : ip_hdr_len=%d\n",
		    __func__, qlge->instance, ip_hdr_len));

		mac_iocb_ptr->flag0 = (uint8_t)(mac_iocb_ptr->flag0 |
		    OB_MAC_IOCB_REQ_IPv4);

		if (pflags & HCK_IPV4_HDRCKSUM) {
			QL_PRINT(DBG_TX, ("%s(%d) : Do IPv4 header checksum\n",
			    __func__, qlge->instance));
			mac_iocb_ptr->opcode = OPCODE_OB_MAC_OFFLOAD_IOCB;
			mac_iocb_ptr->flag2 = (uint8_t)(mac_iocb_ptr->flag2 |
			    OB_MAC_IOCB_REQ_IC);
			iphdr->ip_sum = 0;
			mac_iocb_ptr->hdr_off = (uint16_t)
			    cpu_to_le16(ip_hdr_off);
		}
		if (pflags & HCK_FULLCKSUM) {
			if (iphdr->ip_p == IPPROTO_TCP) {
				tcp_hdr =
				    (struct tcphdr *)(void *)
				    ((uint8_t *)(void *)iphdr + ip_hdr_len);
				QL_PRINT(DBG_TX, ("%s(%d) : Do TCP checksum\n",
				    __func__, qlge->instance));
				mac_iocb_ptr->opcode =
				    OPCODE_OB_MAC_OFFLOAD_IOCB;
				mac_iocb_ptr->flag1 =
				    (uint8_t)(mac_iocb_ptr->flag1 |
				    OB_MAC_IOCB_REQ_TC);
				mac_iocb_ptr->flag2 =
				    (uint8_t)(mac_iocb_ptr->flag2 |
				    OB_MAC_IOCB_REQ_IC);
				iphdr->ip_sum = 0;
				tcp_udp_hdr_off = mac_hdr_len+ip_hdr_len;
				tcp_udp_hdr_len = tcp_hdr->th_off*4;
				QL_PRINT(DBG_TX, ("%s(%d): tcp header len:%d\n",
				    __func__, qlge->instance, tcp_udp_hdr_len));
				hdr_off = ip_hdr_off;
				tcp_udp_hdr_off <<= 6;
				hdr_off |= tcp_udp_hdr_off;
				mac_iocb_ptr->hdr_off =
				    (uint16_t)cpu_to_le16(hdr_off);
				mac_iocb_ptr->protocol_hdr_len = (uint16_t)
				    cpu_to_le16(mac_hdr_len + ip_hdr_len +
				    tcp_udp_hdr_len);

				/*
				 * if the chip is unable to do pseudo header
				 * cksum calculation, do it in then put the
				 * result to the data passed to the chip
				 */
				if (qlge->cfg_flags &
				    CFG_HW_UNABLE_PSEUDO_HDR_CKSUM) {
					ql_pseudo_cksum((uint8_t *)iphdr);
				}
			} else if (iphdr->ip_p == IPPROTO_UDP) {
				QL_PRINT(DBG_TX, ("%s(%d) : Do UDP checksum\n",
				    __func__, qlge->instance));
				mac_iocb_ptr->opcode =
				    OPCODE_OB_MAC_OFFLOAD_IOCB;
				mac_iocb_ptr->flag1 =
				    (uint8_t)(mac_iocb_ptr->flag1 |
				    OB_MAC_IOCB_REQ_UC);
				mac_iocb_ptr->flag2 =
				    (uint8_t)(mac_iocb_ptr->flag2 |
				    OB_MAC_IOCB_REQ_IC);
				iphdr->ip_sum = 0;
				tcp_udp_hdr_off = mac_hdr_len + ip_hdr_len;
				tcp_udp_hdr_len = sizeof (struct udphdr);
				QL_PRINT(DBG_TX, ("%s(%d):udp header len:%d\n",
				    __func__, qlge->instance, tcp_udp_hdr_len));
				hdr_off = ip_hdr_off;
				tcp_udp_hdr_off <<= 6;
				hdr_off |= tcp_udp_hdr_off;
				mac_iocb_ptr->hdr_off =
				    (uint16_t)cpu_to_le16(hdr_off);
				mac_iocb_ptr->protocol_hdr_len = (uint16_t)
				    cpu_to_le16(mac_hdr_len + ip_hdr_len
				    + tcp_udp_hdr_len);

				/*
				 * if the chip is unable to calculate pseudo
				 * hdr cksum,do it in then put the result to
				 * the data passed to the chip
				 */
				if (qlge->cfg_flags &
				    CFG_HW_UNABLE_PSEUDO_HDR_CKSUM) {
					ql_pseudo_cksum((uint8_t *)iphdr);
				}
			}
		}
	}
}

/*
 * For TSO/LSO:
 * MAC frame transmission with TCP large segment offload is performed in the
 * same way as the MAC frame transmission with checksum offload with the
 * exception that the maximum TCP segment size (MSS) must be specified to
 * allow the chip to segment the data into legal sized frames.
 * The host also needs to calculate a pseudo-header checksum over the
 * following fields:
 * Source IP Address, Destination IP Address, and the Protocol.
 * The TCP length is not included in the pseudo-header calculation.
 * The pseudo-header checksum is place in the TCP checksum field of the
 * prototype header.
 */
static void
ql_lso_pseudo_cksum(uint8_t *buf)
{
	uint32_t cksum;
	uint16_t iphl;
	uint16_t proto;

	/*
	 * Calculate the LSO pseudo-header checksum.
	 */
	iphl = (uint16_t)(4 * (buf[0] & 0xF));
	cksum = proto = buf[9];
	cksum += (((uint16_t)buf[12])<<8) + buf[13];
	cksum += (((uint16_t)buf[14])<<8) + buf[15];
	cksum += (((uint16_t)buf[16])<<8) + buf[17];
	cksum += (((uint16_t)buf[18])<<8) + buf[19];
	cksum = (cksum>>16) + (cksum & 0xFFFF);
	cksum = (cksum>>16) + (cksum & 0xFFFF);

	/*
	 * Point it to the TCP/UDP header, and
	 * update the checksum field.
	 */
	buf += iphl + ((proto == IPPROTO_TCP) ?
	    TCP_CKSUM_OFFSET : UDP_CKSUM_OFFSET);

	*(uint16_t *)(void *)buf = (uint16_t)htons((uint16_t)cksum);
}

/*
 * For IPv4 IP packets, distribute the tx packets evenly among tx rings
 */
typedef	uint32_t	ub4; /* unsigned 4-byte quantities */
typedef	uint8_t		ub1;

#define	hashsize(n)	((ub4)1<<(n))
#define	hashmask(n)	(hashsize(n)-1)

#define	mix(a, b, c) \
{ \
	a -= b; a -= c; a ^= (c>>13); \
	b -= c; b -= a; b ^= (a<<8); \
	c -= a; c -= b; c ^= (b>>13); \
	a -= b; a -= c; a ^= (c>>12);  \
	b -= c; b -= a; b ^= (a<<16); \
	c -= a; c -= b; c ^= (b>>5); \
	a -= b; a -= c; a ^= (c>>3);  \
	b -= c; b -= a; b ^= (a<<10); \
	c -= a; c -= b; c ^= (b>>15); \
}

ub4
hash(k, length, initval)
register ub1 *k;	/* the key */
register ub4 length;	/* the length of the key */
register ub4 initval;	/* the previous hash, or an arbitrary value */
{
	register ub4 a, b, c, len;

	/* Set up the internal state */
	len = length;
	a = b = 0x9e3779b9;	/* the golden ratio; an arbitrary value */
	c = initval;		/* the previous hash value */

	/* handle most of the key */
	while (len >= 12) {
		a += (k[0] +((ub4)k[1]<<8) +((ub4)k[2]<<16) +((ub4)k[3]<<24));
		b += (k[4] +((ub4)k[5]<<8) +((ub4)k[6]<<16) +((ub4)k[7]<<24));
		c += (k[8] +((ub4)k[9]<<8) +((ub4)k[10]<<16)+((ub4)k[11]<<24));
		mix(a, b, c);
		k += 12;
		len -= 12;
	}

	/* handle the last 11 bytes */
	c += length;
	/* all the case statements fall through */
	switch (len) {
		/* FALLTHRU */
	case 11: c += ((ub4)k[10]<<24);
		/* FALLTHRU */
	case 10: c += ((ub4)k[9]<<16);
		/* FALLTHRU */
	case 9 : c += ((ub4)k[8]<<8);
	/* the first byte of c is reserved for the length */
		/* FALLTHRU */
	case 8 : b += ((ub4)k[7]<<24);
		/* FALLTHRU */
	case 7 : b += ((ub4)k[6]<<16);
		/* FALLTHRU */
	case 6 : b += ((ub4)k[5]<<8);
		/* FALLTHRU */
	case 5 : b += k[4];
		/* FALLTHRU */
	case 4 : a += ((ub4)k[3]<<24);
		/* FALLTHRU */
	case 3 : a += ((ub4)k[2]<<16);
		/* FALLTHRU */
	case 2 : a += ((ub4)k[1]<<8);
		/* FALLTHRU */
	case 1 : a += k[0];
	/* case 0: nothing left to add */
	}
	mix(a, b, c);
	/* report the result */
	return (c);
}

uint8_t
ql_tx_hashing(qlge_t *qlge, caddr_t bp)
{
	struct ip *iphdr = NULL;
	struct ether_header *ethhdr;
	struct ether_vlan_header *ethvhdr;
	struct tcphdr *tcp_hdr;
	struct udphdr *udp_hdr;
	uint32_t etherType;
	int mac_hdr_len, ip_hdr_len;
	uint32_t h = 0; /* 0 by default */
	uint8_t tx_ring_id = 0;
	uint32_t ip_src_addr = 0;
	uint32_t ip_desc_addr = 0;
	uint16_t src_port = 0;
	uint16_t dest_port = 0;
	uint8_t key[12];
	QL_PRINT(DBG_TX, ("%s(%d) entered \n", __func__, qlge->instance));

	ethhdr = (struct ether_header *)((void *)bp);
	ethvhdr = (struct ether_vlan_header *)((void *)bp);

	if (qlge->tx_ring_count == 1)
		return (tx_ring_id);

	/* Is this vlan packet? */
	if (ntohs(ethvhdr->ether_tpid) == ETHERTYPE_VLAN) {
		mac_hdr_len = sizeof (struct ether_vlan_header);
		etherType = ntohs(ethvhdr->ether_type);
	} else {
		mac_hdr_len = sizeof (struct ether_header);
		etherType = ntohs(ethhdr->ether_type);
	}
	/* Is this IPv4 or IPv6 packet? */
	if (etherType == ETHERTYPE_IP /* 0800 */) {
		if (IPH_HDR_VERSION((ipha_t *)(void *)(bp+mac_hdr_len))
		    == IPV4_VERSION) {
			iphdr = (struct ip *)(void *)(bp+mac_hdr_len);
		}
		if (((unsigned long)iphdr) & 0x3) {
			/*  IP hdr not 4-byte aligned */
			return (tx_ring_id);
		}
	}
	/* ipV4 packets */
	if (iphdr) {

		ip_hdr_len = IPH_HDR_LENGTH(iphdr);
		ip_src_addr = iphdr->ip_src.s_addr;
		ip_desc_addr = iphdr->ip_dst.s_addr;

		if (iphdr->ip_p == IPPROTO_TCP) {
			tcp_hdr = (struct tcphdr *)(void *)
			    ((uint8_t *)iphdr + ip_hdr_len);
			src_port = tcp_hdr->th_sport;
			dest_port = tcp_hdr->th_dport;
		} else if (iphdr->ip_p == IPPROTO_UDP) {
			udp_hdr = (struct udphdr *)(void *)
			    ((uint8_t *)iphdr + ip_hdr_len);
			src_port = udp_hdr->uh_sport;
			dest_port = udp_hdr->uh_dport;
		}
		key[0] = (uint8_t)((ip_src_addr) &0xFF);
		key[1] = (uint8_t)((ip_src_addr >> 8) &0xFF);
		key[2] = (uint8_t)((ip_src_addr >> 16) &0xFF);
		key[3] = (uint8_t)((ip_src_addr >> 24) &0xFF);
		key[4] = (uint8_t)((ip_desc_addr) &0xFF);
		key[5] = (uint8_t)((ip_desc_addr >> 8) &0xFF);
		key[6] = (uint8_t)((ip_desc_addr >> 16) &0xFF);
		key[7] = (uint8_t)((ip_desc_addr >> 24) &0xFF);
		key[8] = (uint8_t)((src_port) &0xFF);
		key[9] = (uint8_t)((src_port >> 8) &0xFF);
		key[10] = (uint8_t)((dest_port) &0xFF);
		key[11] = (uint8_t)((dest_port >> 8) &0xFF);
		h = hash(key, 12, 0); /* return 32 bit */
		tx_ring_id = (h & (qlge->tx_ring_count - 1));
		if (tx_ring_id >= qlge->tx_ring_count) {
			cmn_err(CE_WARN, "%s bad tx_ring_id %d\n",
			    __func__, tx_ring_id);
			tx_ring_id = 0;
		}
	}
	return (tx_ring_id);
}

/*
 * Tell the hardware to do Large Send Offload (LSO)
 *
 * Some fields in ob_mac_iocb need to be set so hardware can know what is
 * the incoming packet, TCP or UDP, whether a VLAN tag needs to be inserted
 * in the right place of the packet etc, thus, hardware can process the
 * packet correctly.
 */
static void
ql_hw_lso_setup(qlge_t *qlge, uint32_t mss, caddr_t bp,
    struct ob_mac_iocb_req *mac_iocb_ptr)
{
	struct ip *iphdr = NULL;
	struct ether_header *ethhdr;
	struct ether_vlan_header *ethvhdr;
	struct tcphdr *tcp_hdr;
	struct udphdr *udp_hdr;
	uint32_t etherType;
	uint16_t mac_hdr_len, ip_hdr_len, tcp_udp_hdr_len;
	uint16_t ip_hdr_off, tcp_udp_hdr_off, hdr_off;

	ethhdr = (struct ether_header *)(void *)bp;
	ethvhdr = (struct ether_vlan_header *)(void *)bp;

	/* Is this vlan packet? */
	if (ntohs(ethvhdr->ether_tpid) == ETHERTYPE_VLAN) {
		mac_hdr_len = sizeof (struct ether_vlan_header);
		etherType = ntohs(ethvhdr->ether_type);
	} else {
		mac_hdr_len = sizeof (struct ether_header);
		etherType = ntohs(ethhdr->ether_type);
	}
	/* Is this IPv4 or IPv6 packet? */
	if (IPH_HDR_VERSION((ipha_t *)(void *)(bp + mac_hdr_len)) ==
	    IPV4_VERSION) {
		if (etherType == ETHERTYPE_IP /* 0800 */) {
			iphdr 	= (struct ip *)(void *)(bp+mac_hdr_len);
		} else {
			/* EMPTY */
			QL_PRINT(DBG_TX, ("%s(%d) : IPv4 None IP packet"
			    " type 0x%x\n",
			    __func__, qlge->instance, etherType));
		}
	}

	if (iphdr != NULL) { /* ipV4 packets */
		ip_hdr_len = (uint16_t)IPH_HDR_LENGTH(iphdr);
		QL_PRINT(DBG_TX,
		    ("%s(%d) : IPv4 header length using IPH_HDR_LENGTH: %d"
		    " bytes \n", __func__, qlge->instance, ip_hdr_len));

		ip_hdr_off = mac_hdr_len;
		QL_PRINT(DBG_TX, ("%s(%d) : ip_hdr_len=%d\n",
		    __func__, qlge->instance, ip_hdr_len));

		mac_iocb_ptr->flag0 = (uint8_t)(mac_iocb_ptr->flag0 |
		    OB_MAC_IOCB_REQ_IPv4);
		if (qlge->cfg_flags & CFG_CKSUM_FULL_IPv4) {
			if (iphdr->ip_p == IPPROTO_TCP) {
				tcp_hdr = (struct tcphdr *)(void *)
				    ((uint8_t *)(void *)iphdr +
				    ip_hdr_len);
				QL_PRINT(DBG_TX, ("%s(%d) : Do TSO on TCP "
				    "packet\n",
				    __func__, qlge->instance));
				mac_iocb_ptr->opcode =
				    OPCODE_OB_MAC_OFFLOAD_IOCB;
				mac_iocb_ptr->flag1 =
				    (uint8_t)(mac_iocb_ptr->flag1 |
				    OB_MAC_IOCB_REQ_LSO);
				iphdr->ip_sum = 0;
				tcp_udp_hdr_off =
				    (uint16_t)(mac_hdr_len+ip_hdr_len);
				tcp_udp_hdr_len =
				    (uint16_t)(tcp_hdr->th_off*4);
				QL_PRINT(DBG_TX, ("%s(%d): tcp header len:%d\n",
				    __func__, qlge->instance, tcp_udp_hdr_len));
				hdr_off = ip_hdr_off;
				tcp_udp_hdr_off <<= 6;
				hdr_off |= tcp_udp_hdr_off;
				mac_iocb_ptr->hdr_off =
				    (uint16_t)cpu_to_le16(hdr_off);
				mac_iocb_ptr->protocol_hdr_len = (uint16_t)
				    cpu_to_le16(mac_hdr_len + ip_hdr_len +
				    tcp_udp_hdr_len);
				mac_iocb_ptr->mss = (uint16_t)cpu_to_le16(mss);

				/*
				 * if the chip is unable to calculate pseudo
				 * header checksum, do it in then put the result
				 * to the data passed to the chip
				 */
				if (qlge->cfg_flags &
				    CFG_HW_UNABLE_PSEUDO_HDR_CKSUM)
					ql_lso_pseudo_cksum((uint8_t *)iphdr);
			} else if (iphdr->ip_p == IPPROTO_UDP) {
				udp_hdr = (struct udphdr *)(void *)
				    ((uint8_t *)(void *)iphdr
				    + ip_hdr_len);
				QL_PRINT(DBG_TX, ("%s(%d) : Do TSO on UDP "
				    "packet\n",
				    __func__, qlge->instance));
				mac_iocb_ptr->opcode =
				    OPCODE_OB_MAC_OFFLOAD_IOCB;
				mac_iocb_ptr->flag1 =
				    (uint8_t)(mac_iocb_ptr->flag1 |
				    OB_MAC_IOCB_REQ_LSO);
				iphdr->ip_sum = 0;
				tcp_udp_hdr_off =
				    (uint16_t)(mac_hdr_len+ip_hdr_len);
				tcp_udp_hdr_len =
				    (uint16_t)(udp_hdr->uh_ulen*4);
				QL_PRINT(DBG_TX, ("%s(%d):udp header len:%d\n",
				    __func__, qlge->instance, tcp_udp_hdr_len));
				hdr_off = ip_hdr_off;
				tcp_udp_hdr_off <<= 6;
				hdr_off |= tcp_udp_hdr_off;
				mac_iocb_ptr->hdr_off =
				    (uint16_t)cpu_to_le16(hdr_off);
				mac_iocb_ptr->protocol_hdr_len = (uint16_t)
				    cpu_to_le16(mac_hdr_len + ip_hdr_len +
				    tcp_udp_hdr_len);
				mac_iocb_ptr->mss = (uint16_t)cpu_to_le16(mss);

				/*
				 * if the chip is unable to do pseudo header
				 * checksum calculation, do it here then put the
				 * result to the data passed to the chip
				 */
				if (qlge->cfg_flags &
				    CFG_HW_UNABLE_PSEUDO_HDR_CKSUM)
					ql_lso_pseudo_cksum((uint8_t *)iphdr);
			}
		}
	}
}

/*
 * Generic packet sending function which is used to send one packet.
 */
int
ql_send_common(struct tx_ring *tx_ring, mblk_t *mp)
{
	struct tx_ring_desc *tx_cb;
	struct ob_mac_iocb_req *mac_iocb_ptr;
	mblk_t *tp;
	size_t msg_len = 0;
	size_t off;
	caddr_t bp;
	size_t nbyte, total_len;
	uint_t i = 0;
	int j = 0, frags = 0;
	uint32_t phy_addr_low, phy_addr_high;
	uint64_t phys_addr;
	clock_t now;
	uint32_t pflags = 0;
	uint32_t mss = 0;
	enum tx_mode_t tx_mode;
	struct oal_entry *oal_entry;
	int status;
	uint_t ncookies, oal_entries, max_oal_entries;
	size_t max_seg_len = 0;
	boolean_t use_lso = B_FALSE;
	struct oal_entry *tx_entry = NULL;
	struct oal_entry *last_oal_entry;
	qlge_t *qlge = tx_ring->qlge;
	ddi_dma_cookie_t dma_cookie;
	size_t tx_buf_len = QL_MAX_COPY_LENGTH;
	int force_pullup = 0;

	tp = mp;
	total_len = msg_len = 0;
	max_oal_entries = TX_DESC_PER_IOCB + MAX_SG_ELEMENTS-1;

	/* Calculate number of data and segments in the incoming message */
	for (tp = mp; tp != NULL; tp = tp->b_cont) {
		nbyte = MBLKL(tp);
		total_len += nbyte;
		max_seg_len = max(nbyte, max_seg_len);
		QL_PRINT(DBG_TX, ("Requested sending data in %d segments, "
		    "total length: %d\n", frags, nbyte));
		frags++;
	}

	if (total_len >= QL_LSO_MAX) {
		freemsg(mp);
#ifdef QLGE_LOAD_UNLOAD
		cmn_err(CE_NOTE, "%s: quit, packet oversize %d\n",
		    __func__, (int)total_len);
#endif
		return (NULL);
	}

	bp = (caddr_t)mp->b_rptr;
	if (bp[0] & 1) {
		if (bcmp(bp, ql_ether_broadcast_addr.ether_addr_octet,
		    ETHERADDRL) == 0) {
			QL_PRINT(DBG_TX, ("Broadcast packet\n"));
			tx_ring->brdcstxmt++;
		} else {
			QL_PRINT(DBG_TX, ("multicast packet\n"));
			tx_ring->multixmt++;
		}
	}

	tx_ring->obytes += total_len;
	tx_ring->opackets ++;

	QL_PRINT(DBG_TX, ("total requested sending data length: %d, in %d segs,"
	    " max seg len: %d\n", total_len, frags, max_seg_len));

	/* claim a free slot in tx ring */
	tx_cb = &tx_ring->wq_desc[tx_ring->prod_idx];

	/* get the tx descriptor */
	mac_iocb_ptr = tx_cb->queue_entry;

	bzero((void *)mac_iocb_ptr, 20);

	ASSERT(tx_cb->mp == NULL);

	/*
	 * Decide to use DMA map or copy mode.
	 * DMA map mode must be used when the total msg length is more than the
	 * tx buffer length.
	 */

	if (total_len > tx_buf_len)
		tx_mode = USE_DMA;
	else if	(max_seg_len > QL_MAX_COPY_LENGTH)
		tx_mode = USE_DMA;
	else
		tx_mode = USE_COPY;

	if (qlge->chksum_cap) {
		mac_hcksum_get(mp, NULL, NULL, NULL, NULL, &pflags);
		QL_PRINT(DBG_TX, ("checksum flag is :0x%x, card capability "
		    "is 0x%x \n", pflags, qlge->chksum_cap));
		if (qlge->lso_enable) {
			uint32_t lso_flags = 0;
			mac_lso_get(mp, &mss, &lso_flags);
			use_lso = (lso_flags == HW_LSO);
		}
		QL_PRINT(DBG_TX, ("mss :%d, use_lso %x \n",
		    mss, use_lso));
	}

do_pullup:

	/* concatenate all frags into one large packet if too fragmented */
	if (((tx_mode == USE_DMA)&&(frags > QL_MAX_TX_DMA_HANDLES)) ||
	    force_pullup) {
		mblk_t *mp1;
		if ((mp1 = msgpullup(mp, -1)) != NULL) {
			freemsg(mp);
			mp = mp1;
			frags = 1;
		} else {
			tx_ring->tx_fail_dma_bind++;
			goto bad;
		}
	}

	tx_cb->tx_bytes = (uint32_t)total_len;
	tx_cb->mp = mp;
	tx_cb->tx_dma_handle_used = 0;

	if (tx_mode == USE_DMA) {
		msg_len = total_len;

		mac_iocb_ptr->opcode = OPCODE_OB_MAC_IOCB;
		mac_iocb_ptr->tid = tx_ring->prod_idx;
		mac_iocb_ptr->frame_len = (uint32_t)cpu_to_le32(msg_len);
		mac_iocb_ptr->txq_idx = tx_ring->wq_id;

		tx_entry = &mac_iocb_ptr->oal_entry[0];
		oal_entry = NULL;

		for (tp = mp, oal_entries = j = 0; tp != NULL;
		    tp = tp->b_cont) {
			/* if too many tx dma handles needed */
			if (j >= QL_MAX_TX_DMA_HANDLES) {
				tx_ring->tx_no_dma_handle++;
				if (!force_pullup) {
					force_pullup = 1;
					goto do_pullup;
				} else {
					goto bad;
				}
			}
			nbyte = (uint16_t)MBLKL(tp);
			if (nbyte == 0)
				continue;

			status = ddi_dma_addr_bind_handle(
			    tx_cb->tx_dma_handle[j], NULL,
			    (caddr_t)tp->b_rptr, nbyte,
			    DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_DONTWAIT,
			    0, &dma_cookie, &ncookies);

			QL_PRINT(DBG_TX, ("map sending data segment: %d, "
			    "length: %d, spans in %d cookies\n",
			    j, nbyte, ncookies));

			if (status != DDI_DMA_MAPPED) {
				goto bad;
			}
			/*
			 * Each fragment can span several cookies. One cookie
			 * will use one tx descriptor to transmit.
			 */
			for (i = ncookies; i > 0; i--, tx_entry++,
			    oal_entries++) {
				/*
				 * The number of TX descriptors that can be
				 *  saved in tx iocb and oal list is limited
				 */
				if (oal_entries > max_oal_entries) {
					tx_ring->tx_no_dma_cookie++;
					if (!force_pullup) {
						force_pullup = 1;
						goto do_pullup;
					} else {
						goto bad;
					}
				}

				if ((oal_entries == TX_DESC_PER_IOCB) &&
				    !oal_entry) {
					/*
					 * Time to switch to an oal list
					 * The last entry should be copied
					 * to first entry in the oal list
					 */
					oal_entry = tx_cb->oal;
					tx_entry =
					    &mac_iocb_ptr->oal_entry[
					    TX_DESC_PER_IOCB-1];
					bcopy(tx_entry, oal_entry,
					    sizeof (*oal_entry));

					/*
					 * last entry should be updated to
					 * point to the extended oal list itself
					 */
					tx_entry->buf_addr_low =
					    cpu_to_le32(
					    LS_64BITS(tx_cb->oal_dma_addr));
					tx_entry->buf_addr_high =
					    cpu_to_le32(
					    MS_64BITS(tx_cb->oal_dma_addr));
					/*
					 * Point tx_entry to the oal list
					 * second entry
					 */
					tx_entry = &oal_entry[1];
				}

				tx_entry->buf_len =
				    (uint32_t)cpu_to_le32(dma_cookie.dmac_size);
				phys_addr = dma_cookie.dmac_laddress;
				tx_entry->buf_addr_low =
				    cpu_to_le32(LS_64BITS(phys_addr));
				tx_entry->buf_addr_high =
				    cpu_to_le32(MS_64BITS(phys_addr));

				last_oal_entry = tx_entry;

				if (i > 1)
					ddi_dma_nextcookie(
					    tx_cb->tx_dma_handle[j],
					    &dma_cookie);
			}
			j++;
		}
		/*
		 * if OAL is used, the last oal entry in tx iocb indicates
		 * number of additional address/len pairs in OAL
		 */
		if (oal_entries > TX_DESC_PER_IOCB) {
			tx_entry = &mac_iocb_ptr->oal_entry[TX_DESC_PER_IOCB-1];
			tx_entry->buf_len = (uint32_t)
			    (cpu_to_le32((sizeof (struct oal_entry) *
			    (oal_entries -TX_DESC_PER_IOCB+1))|OAL_CONT_ENTRY));
		}
		last_oal_entry->buf_len = cpu_to_le32(
		    le32_to_cpu(last_oal_entry->buf_len)|OAL_LAST_ENTRY);

		tx_cb->tx_dma_handle_used = j;
		QL_PRINT(DBG_TX, ("total tx_dma_handle_used %d cookies %d \n",
		    j, oal_entries));

		bp = (caddr_t)mp->b_rptr;
	}
	if (tx_mode == USE_COPY) {
		bp = tx_cb->copy_buffer;
		off = 0;
		nbyte = 0;
		frags = 0;
		/*
		 * Copy up to tx_buf_len of the transmit data
		 * from mp to tx buffer
		 */
		for (tp = mp; tp != NULL; tp = tp->b_cont) {
			nbyte = MBLKL(tp);
			if ((off + nbyte) <= tx_buf_len) {
				bcopy(tp->b_rptr, &bp[off], nbyte);
				off += nbyte;
				frags ++;
			}
		}

		msg_len = off;

		mac_iocb_ptr->opcode = OPCODE_OB_MAC_IOCB;
		mac_iocb_ptr->tid = tx_ring->prod_idx;
		mac_iocb_ptr->frame_len = (uint32_t)cpu_to_le32(msg_len);
		mac_iocb_ptr->txq_idx = tx_ring->wq_id;

		QL_PRINT(DBG_TX, ("Copy Mode:actual sent data length is: %d, "
		    "from %d segaments\n", msg_len, frags));

		phys_addr = tx_cb->copy_buffer_dma_addr;
		phy_addr_low = cpu_to_le32(LS_64BITS(phys_addr));
		phy_addr_high = cpu_to_le32(MS_64BITS(phys_addr));

		QL_DUMP(DBG_TX, "\t requested sending data:\n",
		    (uint8_t *)tx_cb->copy_buffer, 8, total_len);

		mac_iocb_ptr->oal_entry[0].buf_len = (uint32_t)
		    cpu_to_le32(msg_len | OAL_LAST_ENTRY);
		mac_iocb_ptr->oal_entry[0].buf_addr_low  = phy_addr_low;
		mac_iocb_ptr->oal_entry[0].buf_addr_high = phy_addr_high;

		freemsg(mp); /* no need, we have copied */
		tx_cb->mp = NULL;
	} /* End of Copy Mode */

	/* Do TSO/LSO on TCP packet? */
	if (use_lso && mss) {
		ql_hw_lso_setup(qlge, mss, bp, mac_iocb_ptr);
	} else if (pflags & qlge->chksum_cap) {
		/* Do checksum offloading */
		ql_hw_csum_setup(qlge, pflags, bp, mac_iocb_ptr);
	}

	/* let device know the latest outbound IOCB */
	(void) ddi_dma_sync(tx_ring->wq_dma.dma_handle,
	    (off_t)((uintptr_t)mac_iocb_ptr - (uintptr_t)tx_ring->wq_dma.vaddr),
	    (size_t)sizeof (*mac_iocb_ptr), DDI_DMA_SYNC_FORDEV);

	if (tx_mode == USE_DMA) {
		/* let device know the latest outbound OAL if necessary */
		if (oal_entries > TX_DESC_PER_IOCB) {
			(void) ddi_dma_sync(tx_cb->oal_dma.dma_handle,
			    (off_t)0,
			    (sizeof (struct oal_entry) *
			    (oal_entries -TX_DESC_PER_IOCB+1)),
			    DDI_DMA_SYNC_FORDEV);
		}
	} else { /* for USE_COPY mode, tx buffer has changed */
		/* let device know the latest change */
		(void) ddi_dma_sync(tx_cb->oal_dma.dma_handle,
		/* copy buf offset */
		    (off_t)(sizeof (oal_entry) * MAX_SG_ELEMENTS),
		    msg_len, DDI_DMA_SYNC_FORDEV);
	}

	/* save how the packet was sent */
	tx_cb->tx_type = tx_mode;

	QL_DUMP_REQ_PKT(qlge, mac_iocb_ptr, tx_cb->oal, oal_entries);
	/* reduce the number of available tx slot */
	atomic_dec_32(&tx_ring->tx_free_count);

	tx_ring->prod_idx++;
	if (tx_ring->prod_idx >= tx_ring->wq_len)
		tx_ring->prod_idx = 0;

	now = ddi_get_lbolt();
	qlge->last_tx_time = now;

	return (DDI_SUCCESS);

bad:
	/*
	 * if for any reason driver can not send, delete
	 * the message pointer, mp
	 */
	now = ddi_get_lbolt();
	freemsg(mp);
	mp = NULL;
	tx_cb->mp = NULL;
	for (i = 0; i < j; i++)
		(void) ddi_dma_unbind_handle(tx_cb->tx_dma_handle[i]);

	QL_PRINT(DBG_TX, ("%s(%d) failed at 0x%x",
	    __func__, qlge->instance, (int)now));

	return (DDI_SUCCESS);
}


/*
 * Initializes hardware and driver software flags before the driver
 * is finally ready to work.
 */
int
ql_do_start(qlge_t *qlge)
{
	int i;
	struct rx_ring *rx_ring;
	uint16_t lbq_buf_size;
	int rings_done;

	ASSERT(qlge != NULL);

	mutex_enter(&qlge->hw_mutex);

	/* Reset adapter */
	(void) ql_asic_reset(qlge);

	lbq_buf_size = (uint16_t)
	    ((qlge->mtu == ETHERMTU)? LRG_BUF_NORMAL_SIZE : LRG_BUF_JUMBO_SIZE);
	if (qlge->rx_ring[0].lbq_buf_size != lbq_buf_size) {
#ifdef QLGE_LOAD_UNLOAD
		cmn_err(CE_NOTE, "realloc buffers old: %d new: %d\n",
		    qlge->rx_ring[0].lbq_buf_size, lbq_buf_size);
#endif
		/*
		 * Check if any ring has buffers still with upper layers
		 * If buffers are pending with upper layers, we use the
		 * existing buffers and don't reallocate new ones
		 * Unfortunately there is no way to evict buffers from
		 * upper layers. Using buffers with the current size may
		 * cause slightly sub-optimal performance, but that seems
		 * to be the easiest way to handle this situation.
		 */
		rings_done = 0;
		for (i = 0; i < qlge->rx_ring_count; i++) {
			rx_ring = &qlge->rx_ring[i];
			if (rx_ring->rx_indicate == 0)
				rings_done++;
			else
				break;
		}
		/*
		 * No buffers pending with upper layers;
		 * reallocte them for new MTU size
		 */
		if (rings_done >= qlge->rx_ring_count) {
			/* free large buffer pool */
			for (i = 0; i < qlge->rx_ring_count; i++) {
				rx_ring = &qlge->rx_ring[i];
				if (rx_ring->type != TX_Q) {
					ql_free_sbq_buffers(rx_ring);
					ql_free_lbq_buffers(rx_ring);
				}
			}
			/* reallocate large buffer pool */
			for (i = 0; i < qlge->rx_ring_count; i++) {
				rx_ring = &qlge->rx_ring[i];
				if (rx_ring->type != TX_Q) {
					(void) ql_alloc_sbufs(qlge, rx_ring);
					(void) ql_alloc_lbufs(qlge, rx_ring);
				}
			}
		}
	}

	if (ql_bringup_adapter(qlge) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "qlge bringup adapter failed");
		mutex_exit(&qlge->hw_mutex);
		if (qlge->fm_enable) {
			atomic_or_32(&qlge->flags, ADAPTER_ERROR);
			ddi_fm_service_impact(qlge->dip, DDI_SERVICE_LOST);
		}
		return (DDI_FAILURE);
	}

	mutex_exit(&qlge->hw_mutex);
	/* if adapter is up successfully but was bad before */
	if (qlge->flags & ADAPTER_ERROR) {
		atomic_and_32(&qlge->flags, ~ADAPTER_ERROR);
		if (qlge->fm_enable) {
			ddi_fm_service_impact(qlge->dip, DDI_SERVICE_RESTORED);
		}
	}

	/* Get current link state */
	qlge->port_link_state = ql_get_link_state(qlge);

	if (qlge->port_link_state == LS_UP) {
		QL_PRINT(DBG_GLD, ("%s(%d) Link UP !!\n",
		    __func__, qlge->instance));
		/* If driver detects a carrier on */
		CARRIER_ON(qlge);
	} else {
		QL_PRINT(DBG_GLD, ("%s(%d) Link down\n",
		    __func__, qlge->instance));
		/* If driver detects a lack of carrier */
		CARRIER_OFF(qlge);
	}
	qlge->mac_flags = QL_MAC_STARTED;
	return (DDI_SUCCESS);
}

/*
 * Stop currently running driver
 * Driver needs to stop routing new packets to driver and wait until
 * all pending tx/rx buffers to be free-ed.
 */
int
ql_do_stop(qlge_t *qlge)
{
	int rc = DDI_FAILURE;
	uint32_t i, j, k;
	struct bq_desc *sbq_desc, *lbq_desc;
	struct rx_ring *rx_ring;

	ASSERT(qlge != NULL);

	CARRIER_OFF(qlge);

	rc = ql_bringdown_adapter(qlge);
	if (rc != DDI_SUCCESS) {
		cmn_err(CE_WARN, "qlge bringdown adapter failed.");
	} else
		rc = DDI_SUCCESS;

	for (k = 0; k < qlge->rx_ring_count; k++) {
		rx_ring = &qlge->rx_ring[k];
		if (rx_ring->type != TX_Q) {
			j = rx_ring->lbq_use_head;
#ifdef QLGE_LOAD_UNLOAD
			cmn_err(CE_NOTE, "ring %d: move %d lbufs in use list"
			    " to free list %d\n total %d\n",
			    k, rx_ring->lbuf_in_use_count,
			    rx_ring->lbuf_free_count,
			    rx_ring->lbuf_in_use_count +
			    rx_ring->lbuf_free_count);
#endif
			for (i = 0; i < rx_ring->lbuf_in_use_count; i++) {
				lbq_desc = rx_ring->lbuf_in_use[j];
				j++;
				if (j >= rx_ring->lbq_len) {
					j = 0;
				}
				if (lbq_desc->mp) {
					atomic_inc_32(&rx_ring->rx_indicate);
					freemsg(lbq_desc->mp);
				}
			}
			rx_ring->lbq_use_head = j;
			rx_ring->lbq_use_tail = j;
			rx_ring->lbuf_in_use_count = 0;
			j = rx_ring->sbq_use_head;
#ifdef QLGE_LOAD_UNLOAD
			cmn_err(CE_NOTE, "ring %d: move %d sbufs in use list,"
			    " to free list %d\n total %d \n",
			    k, rx_ring->sbuf_in_use_count,
			    rx_ring->sbuf_free_count,
			    rx_ring->sbuf_in_use_count +
			    rx_ring->sbuf_free_count);
#endif
			for (i = 0; i < rx_ring->sbuf_in_use_count; i++) {
				sbq_desc = rx_ring->sbuf_in_use[j];
				j++;
				if (j >= rx_ring->sbq_len) {
					j = 0;
				}
				if (sbq_desc->mp) {
					atomic_inc_32(&rx_ring->rx_indicate);
					freemsg(sbq_desc->mp);
				}
			}
			rx_ring->sbq_use_head = j;
			rx_ring->sbq_use_tail = j;
			rx_ring->sbuf_in_use_count = 0;
		}
	}

	qlge->mac_flags = QL_MAC_STOPPED;

	return (rc);
}

/*
 * Support
 */

void
ql_disable_isr(qlge_t *qlge)
{
	/*
	 * disable the hardware interrupt
	 */
	ISP_DISABLE_GLOBAL_INTRS(qlge);

	qlge->flags &= ~INTERRUPTS_ENABLED;
}



/*
 * busy wait for 'usecs' microseconds.
 */
void
qlge_delay(clock_t usecs)
{
	drv_usecwait(usecs);
}

/*
 * retrieve firmware details.
 */

pci_cfg_t *
ql_get_pci_config(qlge_t *qlge)
{
	return (&(qlge->pci_cfg));
}

/*
 * Get current Link status
 */
static uint32_t
ql_get_link_state(qlge_t *qlge)
{
	uint32_t bitToCheck = 0;
	uint32_t temp, linkState;

	if (qlge->func_number == qlge->fn0_net) {
		bitToCheck = STS_PL0;
	} else {
		bitToCheck = STS_PL1;
	}
	temp = ql_read_reg(qlge, REG_STATUS);
	QL_PRINT(DBG_GLD, ("%s(%d) chip status reg: 0x%x\n",
	    __func__, qlge->instance, temp));

	if (temp & bitToCheck) {
		linkState = LS_UP;
	} else {
		linkState = LS_DOWN;
	}
	if (CFG_IST(qlge, CFG_CHIP_8100)) {
		/* for Schultz, link Speed is fixed to 10G, full duplex */
		qlge->speed  = SPEED_10G;
		qlge->duplex = 1;
	}
	return (linkState);
}
/*
 * Get current link status and report to OS
 */
static void
ql_get_and_report_link_state(qlge_t *qlge)
{
	uint32_t cur_link_state;

	/* Get current link state */
	cur_link_state = ql_get_link_state(qlge);
	/* if link state has changed */
	if (cur_link_state != qlge->port_link_state) {

		qlge->port_link_state = cur_link_state;

		if (qlge->port_link_state == LS_UP) {
			QL_PRINT(DBG_GLD, ("%s(%d) Link UP !!\n",
			    __func__, qlge->instance));
			/* If driver detects a carrier on */
			CARRIER_ON(qlge);
		} else {
			QL_PRINT(DBG_GLD, ("%s(%d) Link down\n",
			    __func__, qlge->instance));
			/* If driver detects a lack of carrier */
			CARRIER_OFF(qlge);
		}
	}
}

/*
 * timer callback function executed after timer expires
 */
static void
ql_timer(void* arg)
{
	ql_get_and_report_link_state((qlge_t *)arg);
}

/*
 * stop the running timer if activated
 */
static void
ql_stop_timer(qlge_t *qlge)
{
	timeout_id_t timer_id;
	/* Disable driver timer */
	if (qlge->ql_timer_timeout_id != NULL) {
		timer_id = qlge->ql_timer_timeout_id;
		qlge->ql_timer_timeout_id = NULL;
		(void) untimeout(timer_id);
	}
}

/*
 * stop then restart timer
 */
void
ql_restart_timer(qlge_t *qlge)
{
	ql_stop_timer(qlge);
	qlge->ql_timer_ticks = TICKS_PER_SEC / 4;
	qlge->ql_timer_timeout_id = timeout(ql_timer,
	    (void *)qlge, qlge->ql_timer_ticks);
}

/* ************************************************************************* */
/*
 *		Hardware K-Stats Data Structures and Subroutines
 */
/* ************************************************************************* */
static const ql_ksindex_t ql_kstats_hw[] = {
	/* PCI related hardware information */
	{ 0, "Vendor Id"			},
	{ 1, "Device Id"			},
	{ 2, "Command"				},
	{ 3, "Status"				},
	{ 4, "Revision Id"			},
	{ 5, "Cache Line Size"			},
	{ 6, "Latency Timer"			},
	{ 7, "Header Type"			},
	{ 9, "I/O base addr"			},
	{ 10, "Control Reg Base addr low"	},
	{ 11, "Control Reg Base addr high"	},
	{ 12, "Doorbell Reg Base addr low"	},
	{ 13, "Doorbell Reg Base addr high"	},
	{ 14, "Subsystem Vendor Id"		},
	{ 15, "Subsystem Device ID"		},
	{ 16, "PCIe Device Control"		},
	{ 17, "PCIe Link Status"		},

	{ -1,	NULL				},
};

/*
 * kstat update function for PCI registers
 */
static int
ql_kstats_get_pci_regs(kstat_t *ksp, int flag)
{
	qlge_t *qlge;
	kstat_named_t *knp;

	if (flag != KSTAT_READ)
		return (EACCES);

	qlge = ksp->ks_private;
	knp = ksp->ks_data;
	(knp++)->value.ui32 = qlge->pci_cfg.vendor_id;
	(knp++)->value.ui32 = qlge->pci_cfg.device_id;
	(knp++)->value.ui32 = qlge->pci_cfg.command;
	(knp++)->value.ui32 = qlge->pci_cfg.status;
	(knp++)->value.ui32 = qlge->pci_cfg.revision;
	(knp++)->value.ui32 = qlge->pci_cfg.cache_line_size;
	(knp++)->value.ui32 = qlge->pci_cfg.latency_timer;
	(knp++)->value.ui32 = qlge->pci_cfg.header_type;
	(knp++)->value.ui32 = qlge->pci_cfg.io_base_address;
	(knp++)->value.ui32 =
	    qlge->pci_cfg.pci_cntl_reg_set_mem_base_address_lower;
	(knp++)->value.ui32 =
	    qlge->pci_cfg.pci_cntl_reg_set_mem_base_address_upper;
	(knp++)->value.ui32 =
	    qlge->pci_cfg.pci_doorbell_mem_base_address_lower;
	(knp++)->value.ui32 =
	    qlge->pci_cfg.pci_doorbell_mem_base_address_upper;
	(knp++)->value.ui32 = qlge->pci_cfg.sub_vendor_id;
	(knp++)->value.ui32 = qlge->pci_cfg.sub_device_id;
	(knp++)->value.ui32 = qlge->pci_cfg.pcie_device_control;
	(knp++)->value.ui32 = qlge->pci_cfg.link_status;

	return (0);
}

static const ql_ksindex_t ql_kstats_mii[] = {
	/* MAC/MII related hardware information */
	{ 0, "mtu"},

	{ -1, NULL},
};


/*
 * kstat update function for MII related information.
 */
static int
ql_kstats_mii_update(kstat_t *ksp, int flag)
{
	qlge_t *qlge;
	kstat_named_t *knp;

	if (flag != KSTAT_READ)
		return (EACCES);

	qlge = ksp->ks_private;
	knp = ksp->ks_data;

	(knp++)->value.ui32 = qlge->mtu;

	return (0);
}

static const ql_ksindex_t ql_kstats_reg[] = {
	/* Register information */
	{ 0, "System (0x08)"			},
	{ 1, "Reset/Fail Over(0x0Ch"		},
	{ 2, "Function Specific Control(0x10)"	},
	{ 3, "Status (0x30)"			},
	{ 4, "Intr Enable (0x34)"		},
	{ 5, "Intr Status1 (0x3C)"		},
	{ 6, "Error Status (0x54)"		},
	{ 7, "XGMAC Flow Control(0x11C)"	},
	{ 8, "XGMAC Tx Pause Frames(0x230)"	},
	{ 9, "XGMAC Rx Pause Frames(0x388)"	},
	{ 10, "XGMAC Rx FIFO Drop Count(0x5B8)"	},
	{ 11, "interrupts actually allocated"	},
	{ 12, "interrupts on rx ring 0"		},
	{ 13, "interrupts on rx ring 1"		},
	{ 14, "interrupts on rx ring 2"		},
	{ 15, "interrupts on rx ring 3"		},
	{ 16, "interrupts on rx ring 4"		},
	{ 17, "interrupts on rx ring 5"		},
	{ 18, "interrupts on rx ring 6"		},
	{ 19, "interrupts on rx ring 7"		},
	{ 20, "polls on rx ring 0"		},
	{ 21, "polls on rx ring 1"		},
	{ 22, "polls on rx ring 2"		},
	{ 23, "polls on rx ring 3"		},
	{ 24, "polls on rx ring 4"		},
	{ 25, "polls on rx ring 5"		},
	{ 26, "polls on rx ring 6"		},
	{ 27, "polls on rx ring 7"		},
	{ 28, "tx no resource on ring 0"	},
	{ 29, "tx dma bind fail on ring 0"	},
	{ 30, "tx dma no handle on ring 0"	},
	{ 31, "tx dma no cookie on ring 0"	},
	{ 32, "MPI firmware major version"	},
	{ 33, "MPI firmware minor version"	},
	{ 34, "MPI firmware sub version"	},
	{ 35, "rx no resource"			},

	{ -1, NULL},
};


/*
 * kstat update function for device register set
 */
static int
ql_kstats_get_reg_and_dev_stats(kstat_t *ksp, int flag)
{
	qlge_t *qlge;
	kstat_named_t *knp;
	uint32_t val32;
	int i = 0;
	struct tx_ring *tx_ring;
	struct rx_ring *rx_ring;

	if (flag != KSTAT_READ)
		return (EACCES);

	qlge = ksp->ks_private;
	knp = ksp->ks_data;

	(knp++)->value.ui32 = ql_read_reg(qlge, REG_SYSTEM);
	(knp++)->value.ui32 = ql_read_reg(qlge, REG_RESET_FAILOVER);
	(knp++)->value.ui32 = ql_read_reg(qlge, REG_FUNCTION_SPECIFIC_CONTROL);
	(knp++)->value.ui32 = ql_read_reg(qlge, REG_STATUS);
	(knp++)->value.ui32 = ql_read_reg(qlge, REG_INTERRUPT_ENABLE);
	(knp++)->value.ui32 = ql_read_reg(qlge, REG_INTERRUPT_STATUS_1);
	(knp++)->value.ui32 = ql_read_reg(qlge, REG_ERROR_STATUS);

	if (ql_sem_spinlock(qlge, qlge->xgmac_sem_mask)) {
		return (0);
	}
	(void) ql_read_xgmac_reg(qlge, REG_XGMAC_FLOW_CONTROL, &val32);
	(knp++)->value.ui32 = val32;

	(void) ql_read_xgmac_reg(qlge, REG_XGMAC_MAC_TX_PAUSE_PKTS, &val32);
	(knp++)->value.ui32 = val32;

	(void) ql_read_xgmac_reg(qlge, REG_XGMAC_MAC_RX_PAUSE_PKTS, &val32);
	(knp++)->value.ui32 = val32;

	(void) ql_read_xgmac_reg(qlge, REG_XGMAC_MAC_RX_FIFO_DROPS, &val32);
	(knp++)->value.ui32 = val32;

	ql_sem_unlock(qlge, qlge->xgmac_sem_mask);

	(knp++)->value.ui32 = qlge->intr_cnt;

	for (i = 0; i < 8; i++) {
		(knp++)->value.ui32 = qlge->rx_interrupts[i];
	}

	for (i = 0; i < 8; i++) {
		(knp++)->value.ui32 = qlge->rx_polls[i];
	}

	tx_ring = &qlge->tx_ring[0];
	(knp++)->value.ui32 = tx_ring->defer;
	(knp++)->value.ui32 = tx_ring->tx_fail_dma_bind;
	(knp++)->value.ui32 = tx_ring->tx_no_dma_handle;
	(knp++)->value.ui32 = tx_ring->tx_no_dma_cookie;

	(knp++)->value.ui32 = qlge->fw_version_info.major_version;
	(knp++)->value.ui32 = qlge->fw_version_info.minor_version;
	(knp++)->value.ui32 = qlge->fw_version_info.sub_minor_version;

	for (i = 0; i < qlge->rx_ring_count; i++) {
		rx_ring = &qlge->rx_ring[i];
		val32 += rx_ring->rx_packets_dropped_no_buffer;
	}
	(knp++)->value.ui32 = val32;

	return (0);
}


static kstat_t *
ql_setup_named_kstat(qlge_t *qlge, int instance, char *name,
    const ql_ksindex_t *ksip, size_t size, int (*update)(kstat_t *, int))
{
	kstat_t *ksp;
	kstat_named_t *knp;
	char *np;
	int type;

	size /= sizeof (ql_ksindex_t);
	ksp = kstat_create(ADAPTER_NAME, instance, name, "net",
	    KSTAT_TYPE_NAMED, ((uint32_t)size) - 1, KSTAT_FLAG_PERSISTENT);
	if (ksp == NULL)
		return (NULL);

	ksp->ks_private = qlge;
	ksp->ks_update = update;
	for (knp = ksp->ks_data; (np = ksip->name) != NULL; ++knp, ++ksip) {
		switch (*np) {
		default:
			type = KSTAT_DATA_UINT32;
			break;
		case '&':
			np += 1;
			type = KSTAT_DATA_CHAR;
			break;
		}
		kstat_named_init(knp, np, (uint8_t)type);
	}
	kstat_install(ksp);

	return (ksp);
}

/*
 * Setup various kstat
 */
int
ql_init_kstats(qlge_t *qlge)
{
	/* Hardware KStats */
	qlge->ql_kstats[QL_KSTAT_CHIP] = ql_setup_named_kstat(qlge,
	    qlge->instance, "chip", ql_kstats_hw,
	    sizeof (ql_kstats_hw), ql_kstats_get_pci_regs);
	if (qlge->ql_kstats[QL_KSTAT_CHIP] == NULL) {
		return (DDI_FAILURE);
	}

	/* MII KStats */
	qlge->ql_kstats[QL_KSTAT_LINK] = ql_setup_named_kstat(qlge,
	    qlge->instance, "mii", ql_kstats_mii,
	    sizeof (ql_kstats_mii), ql_kstats_mii_update);
	if (qlge->ql_kstats[QL_KSTAT_LINK] == NULL) {
		return (DDI_FAILURE);
	}

	/* REG KStats */
	qlge->ql_kstats[QL_KSTAT_REG] = ql_setup_named_kstat(qlge,
	    qlge->instance, "reg", ql_kstats_reg,
	    sizeof (ql_kstats_reg), ql_kstats_get_reg_and_dev_stats);
	if (qlge->ql_kstats[QL_KSTAT_REG] == NULL) {
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * delete all kstat
 */
void
ql_fini_kstats(qlge_t *qlge)
{
	int i;

	for (i = 0; i < QL_KSTAT_COUNT; i++) {
		if (qlge->ql_kstats[i] != NULL)
			kstat_delete(qlge->ql_kstats[i]);
	}
}

/* ************************************************************************* */
/*
 *                                 kstat end
 */
/* ************************************************************************* */

/*
 * Setup the parameters for receive and transmit rings including buffer sizes
 * and completion queue sizes
 */
static int
ql_setup_rings(qlge_t *qlge)
{
	uint8_t i;
	struct rx_ring *rx_ring;
	struct tx_ring *tx_ring;
	uint16_t lbq_buf_size;

	lbq_buf_size = (uint16_t)
	    ((qlge->mtu == ETHERMTU)? LRG_BUF_NORMAL_SIZE : LRG_BUF_JUMBO_SIZE);

	/*
	 * rx_ring[0] is always the default queue.
	 */
	/*
	 * qlge->rx_ring_count:
	 * Total number of rx_rings. This includes a number
	 * of outbound completion handler rx_rings, and a
	 * number of inbound completion handler rx_rings.
	 * rss is only enabled if we have more than 1 rx completion
	 * queue. If we have a single rx completion queue
	 * then all rx completions go to this queue and
	 * the last completion queue
	 */

	qlge->tx_ring_first_cq_id = qlge->rss_ring_count;

	for (i = 0; i < qlge->tx_ring_count; i++) {
		tx_ring = &qlge->tx_ring[i];
		bzero((void *)tx_ring, sizeof (*tx_ring));
		tx_ring->qlge = qlge;
		tx_ring->wq_id = i;
		tx_ring->wq_len = qlge->tx_ring_size;
		tx_ring->wq_size = (uint32_t)(
		    tx_ring->wq_len * sizeof (struct ob_mac_iocb_req));

		/*
		 * The completion queue ID for the tx rings start
		 * immediately after the last rss completion queue.
		 */
		tx_ring->cq_id = (uint16_t)(i + qlge->tx_ring_first_cq_id);
	}

	for (i = 0; i < qlge->rx_ring_count; i++) {
		rx_ring = &qlge->rx_ring[i];
		bzero((void *)rx_ring, sizeof (*rx_ring));
		rx_ring->qlge = qlge;
		rx_ring->cq_id = i;
		if (i != 0)
			rx_ring->cpu = (i) % qlge->rx_ring_count;
		else
			rx_ring->cpu = 0;

		if (i < qlge->rss_ring_count) {
			/*
			 * Inbound completions (RSS) queues
			 * Default queue is queue 0 which handles
			 * unicast plus bcast/mcast and async events.
			 * Other inbound queues handle unicast frames only.
			 */
			rx_ring->cq_len = qlge->rx_ring_size;
			rx_ring->cq_size = (uint32_t)
			    (rx_ring->cq_len * sizeof (struct net_rsp_iocb));
			rx_ring->lbq_len = NUM_LARGE_BUFFERS;
			rx_ring->lbq_size = (uint32_t)
			    (rx_ring->lbq_len * sizeof (uint64_t));
			rx_ring->lbq_buf_size = lbq_buf_size;
			rx_ring->sbq_len = NUM_SMALL_BUFFERS;
			rx_ring->sbq_size = (uint32_t)
			    (rx_ring->sbq_len * sizeof (uint64_t));
			rx_ring->sbq_buf_size = SMALL_BUFFER_SIZE * 2;
			rx_ring->type = RX_Q;

			QL_PRINT(DBG_GLD,
			    ("%s(%d)Allocating rss completion queue %d "
			    "on cpu %d\n", __func__, qlge->instance,
			    rx_ring->cq_id, rx_ring->cpu));
		} else {
			/*
			 * Outbound queue handles outbound completions only
			 */
			/* outbound cq is same size as tx_ring it services. */
			QL_PRINT(DBG_INIT, ("rx_ring 0x%p i %d\n", rx_ring, i));
			rx_ring->cq_len = qlge->tx_ring_size;
			rx_ring->cq_size = (uint32_t)
			    (rx_ring->cq_len * sizeof (struct net_rsp_iocb));
			rx_ring->lbq_len = 0;
			rx_ring->lbq_size = 0;
			rx_ring->lbq_buf_size = 0;
			rx_ring->sbq_len = 0;
			rx_ring->sbq_size = 0;
			rx_ring->sbq_buf_size = 0;
			rx_ring->type = TX_Q;

			QL_PRINT(DBG_GLD,
			    ("%s(%d)Allocating TX completion queue %d on"
			    " cpu %d\n", __func__, qlge->instance,
			    rx_ring->cq_id, rx_ring->cpu));
		}
	}

	return (DDI_SUCCESS);
}

static int
ql_start_rx_ring(qlge_t *qlge, struct rx_ring *rx_ring)
{
	struct cqicb_t *cqicb = (struct cqicb_t *)rx_ring->cqicb_dma.vaddr;
	void *shadow_reg = (uint8_t *)qlge->host_copy_shadow_dma_attr.vaddr +
	    (rx_ring->cq_id * sizeof (uint64_t) * RX_TX_RING_SHADOW_SPACE)
	/* first shadow area is used by wqicb's host copy of consumer index */
	    + sizeof (uint64_t);
	uint64_t shadow_reg_dma = qlge->host_copy_shadow_dma_attr.dma_addr +
	    (rx_ring->cq_id * sizeof (uint64_t) * RX_TX_RING_SHADOW_SPACE)
	    + sizeof (uint64_t);
	/* lrg/sml bufq pointers */
	uint8_t *buf_q_base_reg =
	    (uint8_t *)qlge->buf_q_ptr_base_addr_dma_attr.vaddr +
	    (rx_ring->cq_id * sizeof (uint64_t) * BUF_Q_PTR_SPACE);
	uint64_t buf_q_base_reg_dma =
	    qlge->buf_q_ptr_base_addr_dma_attr.dma_addr +
	    (rx_ring->cq_id * sizeof (uint64_t) * BUF_Q_PTR_SPACE);
	caddr_t doorbell_area =
	    qlge->doorbell_reg_iobase + (VM_PAGE_SIZE * (128 + rx_ring->cq_id));
	int err = 0;
	uint16_t bq_len;
	uint64_t tmp;
	uint64_t *base_indirect_ptr;
	int page_entries;

	/* Set up the shadow registers for this ring. */
	rx_ring->prod_idx_sh_reg = shadow_reg;
	rx_ring->prod_idx_sh_reg_dma = shadow_reg_dma;
	rx_ring->prod_idx_sh_reg_offset = (off_t)(((rx_ring->cq_id *
	    sizeof (uint64_t) * RX_TX_RING_SHADOW_SPACE) + sizeof (uint64_t)));

	rx_ring->lbq_base_indirect = (uint64_t *)(void *)buf_q_base_reg;
	rx_ring->lbq_base_indirect_dma = buf_q_base_reg_dma;

	QL_PRINT(DBG_INIT, ("%s rx ring(%d): prod_idx virtual addr = 0x%lx,"
	    " phys_addr 0x%lx\n", __func__, rx_ring->cq_id,
	    rx_ring->prod_idx_sh_reg, rx_ring->prod_idx_sh_reg_dma));

	buf_q_base_reg += ((BUF_Q_PTR_SPACE / 2) * sizeof (uint64_t));
	buf_q_base_reg_dma += ((BUF_Q_PTR_SPACE / 2) * sizeof (uint64_t));
	rx_ring->sbq_base_indirect = (uint64_t *)(void *)buf_q_base_reg;
	rx_ring->sbq_base_indirect_dma = buf_q_base_reg_dma;

	/* PCI doorbell mem area + 0x00 for consumer index register */
	rx_ring->cnsmr_idx_db_reg = (uint32_t *)(void *)doorbell_area;
	rx_ring->cnsmr_idx = 0;
	*rx_ring->prod_idx_sh_reg = 0;
	rx_ring->curr_entry = rx_ring->cq_dma.vaddr;

	/* PCI doorbell mem area + 0x04 for valid register */
	rx_ring->valid_db_reg = (uint32_t *)(void *)
	    ((uint8_t *)(void *)doorbell_area + 0x04);

	/* PCI doorbell mem area + 0x18 for large buffer consumer */
	rx_ring->lbq_prod_idx_db_reg = (uint32_t *)(void *)
	    ((uint8_t *)(void *)doorbell_area + 0x18);

	/* PCI doorbell mem area + 0x1c */
	rx_ring->sbq_prod_idx_db_reg = (uint32_t *)(void *)
	    ((uint8_t *)(void *)doorbell_area + 0x1c);

	bzero((void *)cqicb, sizeof (*cqicb));

	cqicb->msix_vect = (uint8_t)rx_ring->irq;

	bq_len = (uint16_t)((rx_ring->cq_len == 65536) ?
	    (uint16_t)0 : (uint16_t)rx_ring->cq_len);
	cqicb->len = (uint16_t)cpu_to_le16(bq_len | LEN_V | LEN_CPP_CONT);

	cqicb->cq_base_addr_lo =
	    cpu_to_le32(LS_64BITS(rx_ring->cq_dma.dma_addr));
	cqicb->cq_base_addr_hi =
	    cpu_to_le32(MS_64BITS(rx_ring->cq_dma.dma_addr));

	cqicb->prod_idx_addr_lo =
	    cpu_to_le32(LS_64BITS(rx_ring->prod_idx_sh_reg_dma));
	cqicb->prod_idx_addr_hi =
	    cpu_to_le32(MS_64BITS(rx_ring->prod_idx_sh_reg_dma));

	/*
	 * Set up the control block load flags.
	 */
	cqicb->flags = FLAGS_LC | /* Load queue base address */
	    FLAGS_LV | /* Load MSI-X vector */
	    FLAGS_LI;  /* Load irq delay values */
	if (rx_ring->lbq_len) {
		/* Load lbq values */
		cqicb->flags = (uint8_t)(cqicb->flags | FLAGS_LL);
		tmp = (uint64_t)rx_ring->lbq_dma.dma_addr;
		base_indirect_ptr = (uint64_t *)rx_ring->lbq_base_indirect;
		page_entries = 0;
		do {
			*base_indirect_ptr = cpu_to_le64(tmp);
			tmp += VM_PAGE_SIZE;
			base_indirect_ptr++;
			page_entries++;
		} while (page_entries < (int)(
		    ((rx_ring->lbq_len * sizeof (uint64_t)) / VM_PAGE_SIZE)));

		cqicb->lbq_addr_lo =
		    cpu_to_le32(LS_64BITS(rx_ring->lbq_base_indirect_dma));
		cqicb->lbq_addr_hi =
		    cpu_to_le32(MS_64BITS(rx_ring->lbq_base_indirect_dma));
		bq_len = (uint16_t)((rx_ring->lbq_buf_size == 65536) ?
		    (uint16_t)0 : (uint16_t)rx_ring->lbq_buf_size);
		cqicb->lbq_buf_size = (uint16_t)cpu_to_le16(bq_len);
		bq_len = (uint16_t)((rx_ring->lbq_len == 65536) ? (uint16_t)0 :
		    (uint16_t)rx_ring->lbq_len);
		cqicb->lbq_len = (uint16_t)cpu_to_le16(bq_len);
		rx_ring->lbq_prod_idx = 0;
		rx_ring->lbq_curr_idx = 0;
	}
	if (rx_ring->sbq_len) {
		/* Load sbq values */
		cqicb->flags = (uint8_t)(cqicb->flags | FLAGS_LS);
		tmp = (uint64_t)rx_ring->sbq_dma.dma_addr;
		base_indirect_ptr = (uint64_t *)rx_ring->sbq_base_indirect;
		page_entries = 0;

		do {
			*base_indirect_ptr = cpu_to_le64(tmp);
			tmp += VM_PAGE_SIZE;
			base_indirect_ptr++;
			page_entries++;
		} while (page_entries < (uint32_t)
		    (((rx_ring->sbq_len * sizeof (uint64_t)) / VM_PAGE_SIZE)));

		cqicb->sbq_addr_lo =
		    cpu_to_le32(LS_64BITS(rx_ring->sbq_base_indirect_dma));
		cqicb->sbq_addr_hi =
		    cpu_to_le32(MS_64BITS(rx_ring->sbq_base_indirect_dma));
		cqicb->sbq_buf_size = (uint16_t)
		    cpu_to_le16((uint16_t)(rx_ring->sbq_buf_size/2));
		bq_len = (uint16_t)((rx_ring->sbq_len == 65536) ?
		    (uint16_t)0 : (uint16_t)rx_ring->sbq_len);
		cqicb->sbq_len = (uint16_t)cpu_to_le16(bq_len);
		rx_ring->sbq_prod_idx = 0;
		rx_ring->sbq_curr_idx = 0;
	}
	switch (rx_ring->type) {
	case TX_Q:
		cqicb->irq_delay = (uint16_t)
		    cpu_to_le16(qlge->tx_coalesce_usecs);
		cqicb->pkt_delay = (uint16_t)
		    cpu_to_le16(qlge->tx_max_coalesced_frames);
		break;

	case DEFAULT_Q:
		cqicb->irq_delay = (uint16_t)
		    cpu_to_le16(qlge->rx_coalesce_usecs);
		cqicb->pkt_delay = (uint16_t)
		    cpu_to_le16(qlge->rx_max_coalesced_frames);
		break;

	case RX_Q:
		/*
		 * Inbound completion handling rx_rings run in
		 * separate NAPI contexts.
		 */
		cqicb->irq_delay = (uint16_t)
		    cpu_to_le16(qlge->rx_coalesce_usecs);
		cqicb->pkt_delay = (uint16_t)
		    cpu_to_le16(qlge->rx_max_coalesced_frames);
		break;
	default:
		cmn_err(CE_WARN, "Invalid rx_ring->type = %d.",
		    rx_ring->type);
	}
	QL_PRINT(DBG_INIT, ("Initializing rx completion queue %d.\n",
	    rx_ring->cq_id));
	/* QL_DUMP_CQICB(qlge, cqicb); */
	err = ql_write_cfg(qlge, CFG_LCQ, rx_ring->cqicb_dma.dma_addr,
	    rx_ring->cq_id);
	if (err) {
		cmn_err(CE_WARN, "Failed to load CQICB.");
		return (err);
	}

	rx_ring->rx_packets_dropped_no_buffer = 0;
	rx_ring->rx_pkt_dropped_mac_unenabled = 0;
	rx_ring->rx_failed_sbq_allocs = 0;
	rx_ring->rx_failed_lbq_allocs = 0;
	rx_ring->rx_packets = 0;
	rx_ring->rx_bytes = 0;
	rx_ring->frame_too_long = 0;
	rx_ring->frame_too_short = 0;
	rx_ring->fcs_err = 0;

	return (err);
}

/*
 * start RSS
 */
static int
ql_start_rss(qlge_t *qlge)
{
	struct ricb *ricb = (struct ricb *)qlge->ricb_dma.vaddr;
	int status = 0;
	int i;
	uint8_t *hash_id = (uint8_t *)ricb->hash_cq_id;

	bzero((void *)ricb, sizeof (*ricb));

	ricb->base_cq = RSS_L4K;
	ricb->flags =
	    (RSS_L6K | RSS_LI | RSS_LB | RSS_LM | RSS_RI4 | RSS_RI6 | RSS_RT4 |
	    RSS_RT6);
	ricb->mask = (uint16_t)cpu_to_le16(RSS_HASH_CQ_ID_MAX - 1);

	/*
	 * Fill out the Indirection Table.
	 */
	for (i = 0; i < RSS_HASH_CQ_ID_MAX; i++)
		hash_id[i] = (uint8_t)(i & (qlge->rss_ring_count - 1));

	(void) memcpy(&ricb->ipv6_hash_key[0], key_data, 40);
	(void) memcpy(&ricb->ipv4_hash_key[0], key_data, 16);

	QL_PRINT(DBG_INIT, ("Initializing RSS.\n"));

	status = ql_write_cfg(qlge, CFG_LR, qlge->ricb_dma.dma_addr, 0);
	if (status) {
		cmn_err(CE_WARN, "Failed to load RICB.");
		return (status);
	}

	return (status);
}

/*
 * load a tx ring control block to hw and start this ring
 */
static int
ql_start_tx_ring(qlge_t *qlge, struct tx_ring *tx_ring)
{
	struct wqicb_t *wqicb = (struct wqicb_t *)tx_ring->wqicb_dma.vaddr;
	caddr_t doorbell_area =
	    qlge->doorbell_reg_iobase + (VM_PAGE_SIZE * tx_ring->wq_id);
	void *shadow_reg = (uint8_t *)qlge->host_copy_shadow_dma_attr.vaddr +
	    (tx_ring->wq_id * sizeof (uint64_t)) * RX_TX_RING_SHADOW_SPACE;
	uint64_t shadow_reg_dma = qlge->host_copy_shadow_dma_attr.dma_addr +
	    (tx_ring->wq_id * sizeof (uint64_t)) * RX_TX_RING_SHADOW_SPACE;
	int err = 0;

	/*
	 * Assign doorbell registers for this tx_ring.
	 */

	/* TX PCI doorbell mem area for tx producer index */
	tx_ring->prod_idx_db_reg = (uint32_t *)(void *)doorbell_area;
	tx_ring->prod_idx = 0;
	/* TX PCI doorbell mem area + 0x04 */
	tx_ring->valid_db_reg = (uint32_t *)(void *)
	    ((uint8_t *)(void *)doorbell_area + 0x04);

	/*
	 * Assign shadow registers for this tx_ring.
	 */
	tx_ring->cnsmr_idx_sh_reg = shadow_reg;
	tx_ring->cnsmr_idx_sh_reg_dma = shadow_reg_dma;
	*tx_ring->cnsmr_idx_sh_reg = 0;

	QL_PRINT(DBG_INIT, ("%s tx ring(%d): cnsmr_idx virtual addr = 0x%lx,"
	    " phys_addr 0x%lx\n",
	    __func__, tx_ring->wq_id, tx_ring->cnsmr_idx_sh_reg,
	    tx_ring->cnsmr_idx_sh_reg_dma));

	wqicb->len =
	    (uint16_t)cpu_to_le16(tx_ring->wq_len | Q_LEN_V | Q_LEN_CPP_CONT);
	wqicb->flags = cpu_to_le16(Q_FLAGS_LC |
	    Q_FLAGS_LB | Q_FLAGS_LI | Q_FLAGS_LO);
	wqicb->cq_id_rss = (uint16_t)cpu_to_le16(tx_ring->cq_id);
	wqicb->rid = 0;
	wqicb->wq_addr_lo = cpu_to_le32(LS_64BITS(tx_ring->wq_dma.dma_addr));
	wqicb->wq_addr_hi = cpu_to_le32(MS_64BITS(tx_ring->wq_dma.dma_addr));
	wqicb->cnsmr_idx_addr_lo =
	    cpu_to_le32(LS_64BITS(tx_ring->cnsmr_idx_sh_reg_dma));
	wqicb->cnsmr_idx_addr_hi =
	    cpu_to_le32(MS_64BITS(tx_ring->cnsmr_idx_sh_reg_dma));

	ql_init_tx_ring(tx_ring);
	/* QL_DUMP_WQICB(qlge, wqicb); */
	err = ql_write_cfg(qlge, CFG_LRQ, tx_ring->wqicb_dma.dma_addr,
	    tx_ring->wq_id);

	if (err) {
		cmn_err(CE_WARN, "Failed to load WQICB.");
		return (err);
	}
	return (err);
}

/*
 * Set up a MAC, multicast or VLAN address for the
 * inbound frame matching.
 */
int
ql_set_mac_addr_reg(qlge_t *qlge, uint8_t *addr, uint32_t type,
    uint16_t index)
{
	uint32_t offset = 0;
	int status = DDI_SUCCESS;

	switch (type) {
	case MAC_ADDR_TYPE_MULTI_MAC:
	case MAC_ADDR_TYPE_CAM_MAC: {
		uint32_t cam_output;
		uint32_t upper = (addr[0] << 8) | addr[1];
		uint32_t lower =
		    (addr[2] << 24) | (addr[3] << 16) | (addr[4] << 8) |
		    (addr[5]);

		QL_PRINT(DBG_INIT, ("Adding %s ", (type ==
		    MAC_ADDR_TYPE_MULTI_MAC) ?
		    "MULTICAST" : "UNICAST"));
		QL_PRINT(DBG_INIT,
		    ("addr %02x %02x %02x %02x %02x %02x at index %d in "
		    "the CAM.\n",
		    addr[0], addr[1], addr[2], addr[3], addr[4],
		    addr[5], index));

		status = ql_wait_reg_rdy(qlge,
		    REG_MAC_PROTOCOL_ADDRESS_INDEX, MAC_ADDR_MW, 0);
		if (status)
			goto exit;
		/* offset 0 - lower 32 bits of the MAC address */
		ql_write_reg(qlge, REG_MAC_PROTOCOL_ADDRESS_INDEX,
		    (offset++) |
		    (index << MAC_ADDR_IDX_SHIFT) | /* index */
		    type);	/* type */
		ql_write_reg(qlge, REG_MAC_PROTOCOL_DATA, lower);
		status = ql_wait_reg_rdy(qlge,
		    REG_MAC_PROTOCOL_ADDRESS_INDEX, MAC_ADDR_MW, 0);
		if (status)
			goto exit;
		/* offset 1 - upper 16 bits of the MAC address */
		ql_write_reg(qlge, REG_MAC_PROTOCOL_ADDRESS_INDEX,
		    (offset++) |
		    (index << MAC_ADDR_IDX_SHIFT) | /* index */
		    type);	/* type */
		ql_write_reg(qlge, REG_MAC_PROTOCOL_DATA, upper);
		status = ql_wait_reg_rdy(qlge,
		    REG_MAC_PROTOCOL_ADDRESS_INDEX, MAC_ADDR_MW, 0);
		if (status)
			goto exit;
		/* offset 2 - CQ ID associated with this MAC address */
		ql_write_reg(qlge, REG_MAC_PROTOCOL_ADDRESS_INDEX,
		    (offset) | (index << MAC_ADDR_IDX_SHIFT) |	/* index */
		    type);	/* type */
		/*
		 * This field should also include the queue id
		 * and possibly the function id.  Right now we hardcode
		 * the route field to NIC core.
		 */
		if (type == MAC_ADDR_TYPE_CAM_MAC) {
			cam_output = (CAM_OUT_ROUTE_NIC |
			    (qlge->func_number << CAM_OUT_FUNC_SHIFT) |
			    (0 <<
			    CAM_OUT_CQ_ID_SHIFT));

			/* route to NIC core */
			ql_write_reg(qlge, REG_MAC_PROTOCOL_DATA,
			    cam_output);
			}
		break;
		}
	default:
		cmn_err(CE_WARN,
		    "Address type %d not yet supported.", type);
		status = DDI_FAILURE;
	}
exit:
	return (status);
}

/*
 * The NIC function for this chip has 16 routing indexes.  Each one can be used
 * to route different frame types to various inbound queues.  We send broadcast
 * multicast/error frames to the default queue for slow handling,
 * and CAM hit/RSS frames to the fast handling queues.
 */
static int
ql_set_routing_reg(qlge_t *qlge, uint32_t index, uint32_t mask, int enable)
{
	int status;
	uint32_t value = 0;

	QL_PRINT(DBG_INIT,
	    ("%s %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s mask %s the routing reg.\n",
	    (enable ? "Adding" : "Removing"),
	    ((index == RT_IDX_ALL_ERR_SLOT) ? "MAC ERROR/ALL ERROR" : ""),
	    ((index == RT_IDX_IP_CSUM_ERR_SLOT) ? "IP CSUM ERROR" : ""),
	    ((index ==
	    RT_IDX_TCP_UDP_CSUM_ERR_SLOT) ? "TCP/UDP CSUM ERROR" : ""),
	    ((index == RT_IDX_BCAST_SLOT) ? "BROADCAST" : ""),
	    ((index == RT_IDX_MCAST_MATCH_SLOT) ? "MULTICAST MATCH" : ""),
	    ((index == RT_IDX_ALLMULTI_SLOT) ? "ALL MULTICAST MATCH" : ""),
	    ((index == RT_IDX_UNUSED6_SLOT) ? "UNUSED6" : ""),
	    ((index == RT_IDX_UNUSED7_SLOT) ? "UNUSED7" : ""),
	    ((index == RT_IDX_RSS_MATCH_SLOT) ? "RSS ALL/IPV4 MATCH" : ""),
	    ((index == RT_IDX_RSS_IPV6_SLOT) ? "RSS IPV6" : ""),
	    ((index == RT_IDX_RSS_TCP4_SLOT) ? "RSS TCP4" : ""),
	    ((index == RT_IDX_RSS_TCP6_SLOT) ? "RSS TCP6" : ""),
	    ((index == RT_IDX_CAM_HIT_SLOT) ? "CAM HIT" : ""),
	    ((index == RT_IDX_UNUSED013) ? "UNUSED13" : ""),
	    ((index == RT_IDX_UNUSED014) ? "UNUSED14" : ""),
	    ((index == RT_IDX_PROMISCUOUS_SLOT) ? "PROMISCUOUS" : ""),
	    (enable ? "to" : "from")));

	switch (mask) {
	case RT_IDX_CAM_HIT:
		value = RT_IDX_DST_CAM_Q | /* dest */
		    RT_IDX_TYPE_NICQ | /* type */
		    (RT_IDX_CAM_HIT_SLOT << RT_IDX_IDX_SHIFT); /* index */
		break;

	case RT_IDX_VALID: /* Promiscuous Mode frames. */
		value = RT_IDX_DST_DFLT_Q |	/* dest */
		    RT_IDX_TYPE_NICQ |	/* type */
		    (RT_IDX_PROMISCUOUS_SLOT << RT_IDX_IDX_SHIFT); /* index */
		break;

	case RT_IDX_ERR:	/* Pass up MAC,IP,TCP/UDP error frames. */
		value = RT_IDX_DST_DFLT_Q |	/* dest */
		    RT_IDX_TYPE_NICQ |	/* type */
		    (RT_IDX_ALL_ERR_SLOT << RT_IDX_IDX_SHIFT); /* index */
		break;

	case RT_IDX_BCAST:	/* Pass up Broadcast frames to default Q. */
		value = RT_IDX_DST_DFLT_Q |	/* dest */
		    RT_IDX_TYPE_NICQ |	/* type */
		    (RT_IDX_BCAST_SLOT << RT_IDX_IDX_SHIFT); /* index */
		break;

	case RT_IDX_MCAST:	/* Pass up All Multicast frames. */
		value = RT_IDX_DST_CAM_Q |	/* dest */
		    RT_IDX_TYPE_NICQ |	/* type */
		    (RT_IDX_ALLMULTI_SLOT << RT_IDX_IDX_SHIFT); /* index */
		break;

	case RT_IDX_MCAST_MATCH:	/* Pass up matched Multicast frames. */
		value = RT_IDX_DST_CAM_Q |	/* dest */
		    RT_IDX_TYPE_NICQ |	/* type */
		    (RT_IDX_MCAST_MATCH_SLOT << RT_IDX_IDX_SHIFT); /* index */
		break;

	case RT_IDX_RSS_MATCH:	/* Pass up matched RSS frames. */
		value = RT_IDX_DST_RSS |	/* dest */
		    RT_IDX_TYPE_NICQ |	/* type */
		    (RT_IDX_RSS_MATCH_SLOT << RT_IDX_IDX_SHIFT); /* index */
		break;

	case 0:	/* Clear the E-bit on an entry. */
		value = RT_IDX_DST_DFLT_Q |	/* dest */
		    RT_IDX_TYPE_NICQ |	/* type */
		    (index << RT_IDX_IDX_SHIFT); /* index */
		break;

	default:
		cmn_err(CE_WARN, "Mask type %d not yet supported.",
		    mask);
		status = -EPERM;
		goto exit;
	}

	if (value != 0) {
		status = ql_wait_reg_rdy(qlge, REG_ROUTING_INDEX, RT_IDX_MW, 0);
		if (status)
			goto exit;
		value |= (enable ? RT_IDX_E : 0);
		ql_write_reg(qlge, REG_ROUTING_INDEX, value);
		ql_write_reg(qlge, REG_ROUTING_DATA, enable ? mask : 0);
	}

exit:
	return (status);
}

/*
 * Clear all the entries in the routing table.
 * Caller must get semaphore in advance.
 */

static int
ql_stop_routing(qlge_t *qlge)
{
	int status = 0;
	int i;
	/* Clear all the entries in the routing table. */
	for (i = 0; i < 16; i++) {
		status = ql_set_routing_reg(qlge, i, 0, 0);
		if (status) {
			cmn_err(CE_WARN, "Stop routing failed. ");
		}
	}
	return (status);
}

/* Initialize the frame-to-queue routing. */
int
ql_route_initialize(qlge_t *qlge)
{
	int status = 0;

	status = ql_sem_spinlock(qlge, SEM_RT_IDX_MASK);
	if (status != DDI_SUCCESS)
		return (status);

	/* Clear all the entries in the routing table. */
	status = ql_stop_routing(qlge);
	if (status) {
		goto exit;
	}
	status = ql_set_routing_reg(qlge, RT_IDX_BCAST_SLOT, RT_IDX_BCAST, 1);
	if (status) {
		cmn_err(CE_WARN,
		    "Failed to init routing register for broadcast packets.");
		goto exit;
	}
	/*
	 * If we have more than one inbound queue, then turn on RSS in the
	 * routing block.
	 */
	if (qlge->rss_ring_count > 1) {
		status = ql_set_routing_reg(qlge, RT_IDX_RSS_MATCH_SLOT,
		    RT_IDX_RSS_MATCH, 1);
		if (status) {
			cmn_err(CE_WARN,
			    "Failed to init routing register for MATCH RSS "
			    "packets.");
			goto exit;
		}
	}

	status = ql_set_routing_reg(qlge, RT_IDX_CAM_HIT_SLOT,
	    RT_IDX_CAM_HIT, 1);
	if (status) {
		cmn_err(CE_WARN,
		    "Failed to init routing register for CAM packets.");
		goto exit;
	}

	status = ql_set_routing_reg(qlge, RT_IDX_MCAST_MATCH_SLOT,
	    RT_IDX_MCAST_MATCH, 1);
	if (status) {
		cmn_err(CE_WARN,
		    "Failed to init routing register for Multicast "
		    "packets.");
	}

exit:
	ql_sem_unlock(qlge, SEM_RT_IDX_MASK);
	return (status);
}

/*
 * Initialize hardware
 */
static int
ql_device_initialize(qlge_t *qlge)
{
	uint32_t value, mask;
	int i;
	int status = 0;
	uint16_t pause = PAUSE_MODE_DISABLED;
	boolean_t update_port_config = B_FALSE;
	uint32_t pause_bit_mask;
	boolean_t dcbx_enable = B_FALSE;
	uint32_t dcbx_bit_mask = 0x10;
	/*
	 * Set up the System register to halt on errors.
	 */
	value = SYS_EFE | SYS_FAE;
	mask = value << 16;
	ql_write_reg(qlge, REG_SYSTEM, mask | value);

	/* Set the default queue. */
	value = NIC_RCV_CFG_DFQ;
	mask = NIC_RCV_CFG_DFQ_MASK;

	ql_write_reg(qlge, REG_NIC_RECEIVE_CONFIGURATION, mask | value);

	/* Enable the MPI interrupt. */
	ql_write_reg(qlge, REG_INTERRUPT_MASK, (INTR_MASK_PI << 16)
	    | INTR_MASK_PI);
	/* Enable the function, set pagesize, enable error checking. */
	value = FSC_FE | FSC_EPC_INBOUND | FSC_EPC_OUTBOUND |
	    FSC_EC | FSC_VM_PAGE_4K | FSC_DBRST_1024;
	/* Set/clear header splitting. */
	if (CFG_IST(qlge, CFG_ENABLE_SPLIT_HEADER)) {
		value |= FSC_SH;
		ql_write_reg(qlge, REG_SPLIT_HEADER, SMALL_BUFFER_SIZE);
	}
	mask = FSC_VM_PAGESIZE_MASK |
	    FSC_DBL_MASK | FSC_DBRST_MASK | (value << 16);
	ql_write_reg(qlge, REG_FUNCTION_SPECIFIC_CONTROL, mask | value);
	/*
	 * check current port max frame size, if different from OS setting,
	 * then we need to change
	 */
	qlge->max_frame_size =
	    (qlge->mtu == ETHERMTU)? NORMAL_FRAME_SIZE : JUMBO_FRAME_SIZE;

	mutex_enter(&qlge->mbx_mutex);
	status = ql_get_port_cfg(qlge);
	mutex_exit(&qlge->mbx_mutex);

	if (status == DDI_SUCCESS) {
		/* if current frame size is smaller than required size */
		if (qlge->port_cfg_info.max_frame_size <
		    qlge->max_frame_size) {
			QL_PRINT(DBG_MBX,
			    ("update frame size, current %d, new %d\n",
			    qlge->port_cfg_info.max_frame_size,
			    qlge->max_frame_size));
			qlge->port_cfg_info.max_frame_size =
			    qlge->max_frame_size;
			qlge->port_cfg_info.link_cfg |= ENABLE_JUMBO;
			update_port_config = B_TRUE;
		}

		if (qlge->port_cfg_info.link_cfg & STD_PAUSE)
			pause = PAUSE_MODE_STANDARD;
		else if (qlge->port_cfg_info.link_cfg & PP_PAUSE)
			pause = PAUSE_MODE_PER_PRIORITY;

		if (pause != qlge->pause) {
			pause_bit_mask = 0x60;	/* bit 5-6 */
			/* clear pause bits */
			qlge->port_cfg_info.link_cfg &= ~pause_bit_mask;
			if (qlge->pause == PAUSE_MODE_STANDARD)
				qlge->port_cfg_info.link_cfg |= STD_PAUSE;
			else if (qlge->pause == PAUSE_MODE_PER_PRIORITY)
				qlge->port_cfg_info.link_cfg |= PP_PAUSE;
			update_port_config = B_TRUE;
		}

		if (qlge->port_cfg_info.link_cfg & DCBX_ENABLE)
			dcbx_enable = B_TRUE;
		if (dcbx_enable != qlge->dcbx_enable) {
			qlge->port_cfg_info.link_cfg &= ~dcbx_bit_mask;
			if (qlge->dcbx_enable)
				qlge->port_cfg_info.link_cfg |= DCBX_ENABLE;
		}

		update_port_config = B_TRUE;

		/* if need to update port configuration */
		if (update_port_config) {
			mutex_enter(&qlge->mbx_mutex);
			(void) ql_set_mpi_port_config(qlge,
			    qlge->port_cfg_info);
			mutex_exit(&qlge->mbx_mutex);
		}
	} else
		cmn_err(CE_WARN, "ql_get_port_cfg failed");

	/* Start up the rx queues. */
	for (i = 0; i < qlge->rx_ring_count; i++) {
		status = ql_start_rx_ring(qlge, &qlge->rx_ring[i]);
		if (status) {
			cmn_err(CE_WARN,
			    "Failed to start rx ring[%d]", i);
			return (status);
		}
	}

	/*
	 * If there is more than one inbound completion queue
	 * then download a RICB to configure RSS.
	 */
	if (qlge->rss_ring_count > 1) {
		status = ql_start_rss(qlge);
		if (status) {
			cmn_err(CE_WARN, "Failed to start RSS.");
			return (status);
		}
	}

	/* Start up the tx queues. */
	for (i = 0; i < qlge->tx_ring_count; i++) {
		status = ql_start_tx_ring(qlge, &qlge->tx_ring[i]);
		if (status) {
			cmn_err(CE_WARN,
			    "Failed to start tx ring[%d]", i);
			return (status);
		}
	}
	qlge->selected_tx_ring = 0;
	/* Set the frame routing filter. */
	status = ql_route_initialize(qlge);
	if (status) {
		cmn_err(CE_WARN,
		    "Failed to init CAM/Routing tables.");
		return (status);
	}

	return (status);
}
/*
 * Issue soft reset to chip.
 */
static int
ql_asic_reset(qlge_t *qlge)
{
	int status = DDI_SUCCESS;

	ql_write_reg(qlge, REG_RESET_FAILOVER, FUNCTION_RESET_MASK
	    |FUNCTION_RESET);

	if (ql_wait_reg_bit(qlge, REG_RESET_FAILOVER, FUNCTION_RESET,
	    BIT_RESET, 0) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "TIMEOUT!!! errored out of resetting the chip!");
		status = DDI_FAILURE;
	}

	return (status);
}

/*
 * If there are more than MIN_BUFFERS_ARM_COUNT small buffer descriptors in
 * its free list, move xMIN_BUFFERS_ARM_COUNT descriptors to its in use list
 * to be used by hardware.
 */
static void
ql_arm_sbuf(qlge_t *qlge, struct rx_ring *rx_ring)
{
	struct bq_desc *sbq_desc;
	int i;
	uint64_t *sbq_entry = rx_ring->sbq_dma.vaddr;
	uint32_t arm_count;

	if (rx_ring->sbuf_free_count > rx_ring->sbq_len-MIN_BUFFERS_ARM_COUNT)
		arm_count = (rx_ring->sbq_len-MIN_BUFFERS_ARM_COUNT);
	else {
		/* Adjust to a multiple of 16 */
		arm_count = (rx_ring->sbuf_free_count / 16) * 16;
#ifdef QLGE_LOAD_UNLOAD
		cmn_err(CE_NOTE, "adjust sbuf arm_count %d\n", arm_count);
#endif
	}
	for (i = 0; i < arm_count; i++) {
		sbq_desc = ql_get_sbuf_from_free_list(rx_ring);
		if (sbq_desc == NULL)
			break;
		/* Arm asic */
		*sbq_entry = cpu_to_le64(sbq_desc->bd_dma.dma_addr);
		sbq_entry++;

		/* link the descriptors to in_use_list */
		ql_add_sbuf_to_in_use_list(rx_ring, sbq_desc);
		rx_ring->sbq_prod_idx++;
	}
	ql_update_sbq_prod_idx(qlge, rx_ring);
}

/*
 * If there are more than MIN_BUFFERS_ARM_COUNT large buffer descriptors in
 * its free list, move xMIN_BUFFERS_ARM_COUNT descriptors to its in use list
 * to be used by hardware.
 */
static void
ql_arm_lbuf(qlge_t *qlge, struct rx_ring *rx_ring)
{
	struct bq_desc *lbq_desc;
	int i;
	uint64_t *lbq_entry = rx_ring->lbq_dma.vaddr;
	uint32_t arm_count;

	if (rx_ring->lbuf_free_count > rx_ring->lbq_len-MIN_BUFFERS_ARM_COUNT)
		arm_count = (rx_ring->lbq_len-MIN_BUFFERS_ARM_COUNT);
	else {
		/* Adjust to a multiple of 16 */
		arm_count = (rx_ring->lbuf_free_count / 16) * 16;
#ifdef QLGE_LOAD_UNLOAD
		cmn_err(CE_NOTE, "adjust lbuf arm_count %d\n", arm_count);
#endif
	}
	for (i = 0; i < arm_count; i++) {
		lbq_desc = ql_get_lbuf_from_free_list(rx_ring);
		if (lbq_desc == NULL)
			break;
		/* Arm asic */
		*lbq_entry = cpu_to_le64(lbq_desc->bd_dma.dma_addr);
		lbq_entry++;

		/* link the descriptors to in_use_list */
		ql_add_lbuf_to_in_use_list(rx_ring, lbq_desc);
		rx_ring->lbq_prod_idx++;
	}
	ql_update_lbq_prod_idx(qlge, rx_ring);
}


/*
 * Initializes the adapter by configuring request and response queues,
 * allocates and ARMs small and large receive buffers to the
 * hardware
 */
static int
ql_bringup_adapter(qlge_t *qlge)
{
	int i;

	if (ql_device_initialize(qlge) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "?%s(%d): ql_device_initialize failed",
		    __func__, qlge->instance);
		goto err_bringup;
	}
	qlge->sequence |= INIT_ADAPTER_UP;

#ifdef QLGE_TRACK_BUFFER_USAGE
	for (i = 0; i < qlge->rx_ring_count; i++) {
		if (qlge->rx_ring[i].type != TX_Q) {
			qlge->rx_sb_low_count[i] = NUM_SMALL_BUFFERS;
			qlge->rx_lb_low_count[i] = NUM_LARGE_BUFFERS;
		}
		qlge->cq_low_count[i] = NUM_RX_RING_ENTRIES;
	}
#endif
	/* Arm buffers */
	for (i = 0; i < qlge->rx_ring_count; i++) {
		if (qlge->rx_ring[i].type != TX_Q) {
			ql_arm_sbuf(qlge, &qlge->rx_ring[i]);
			ql_arm_lbuf(qlge, &qlge->rx_ring[i]);
		}
	}

	/* Enable work/request queues */
	for (i = 0; i < qlge->tx_ring_count; i++) {
		if (qlge->tx_ring[i].valid_db_reg)
			ql_write_doorbell_reg(qlge,
			    qlge->tx_ring[i].valid_db_reg,
			    REQ_Q_VALID);
	}

	/* Enable completion queues */
	for (i = 0; i < qlge->rx_ring_count; i++) {
		if (qlge->rx_ring[i].valid_db_reg)
			ql_write_doorbell_reg(qlge,
			    qlge->rx_ring[i].valid_db_reg,
			    RSP_Q_VALID);
	}

	for (i = 0; i < qlge->tx_ring_count; i++) {
		mutex_enter(&qlge->tx_ring[i].tx_lock);
		qlge->tx_ring[i].mac_flags = QL_MAC_STARTED;
		mutex_exit(&qlge->tx_ring[i].tx_lock);
	}

	for (i = 0; i < qlge->rx_ring_count; i++) {
		mutex_enter(&qlge->rx_ring[i].rx_lock);
		qlge->rx_ring[i].mac_flags = QL_MAC_STARTED;
		mutex_exit(&qlge->rx_ring[i].rx_lock);
	}

	/* This mutex will get re-acquired in enable_completion interrupt */
	mutex_exit(&qlge->hw_mutex);
	/* Traffic can start flowing now */
	ql_enable_all_completion_interrupts(qlge);
	mutex_enter(&qlge->hw_mutex);

	ql_enable_global_interrupt(qlge);

	qlge->sequence |= ADAPTER_INIT;
	return (DDI_SUCCESS);

err_bringup:
	(void) ql_asic_reset(qlge);
	return (DDI_FAILURE);
}

/*
 * Initialize mutexes of each rx/tx rings
 */
static int
ql_init_rx_tx_locks(qlge_t *qlge)
{
	struct tx_ring *tx_ring;
	struct rx_ring *rx_ring;
	int i;

	for (i = 0; i < qlge->tx_ring_count; i++) {
		tx_ring = &qlge->tx_ring[i];
		mutex_init(&tx_ring->tx_lock, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(qlge->intr_pri));
	}

	for (i = 0; i < qlge->rx_ring_count; i++) {
		rx_ring = &qlge->rx_ring[i];
		mutex_init(&rx_ring->rx_lock, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(qlge->intr_pri));
		mutex_init(&rx_ring->sbq_lock, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(qlge->intr_pri));
		mutex_init(&rx_ring->lbq_lock, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(qlge->intr_pri));
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
/*
 * Simply call pci_ereport_post which generates ereports for errors
 * that occur in the PCI local bus configuration status registers.
 */
static int
ql_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err, const void *impl_data)
{
	pci_ereport_post(dip, err, NULL);
	return (err->fme_status);
}

static void
ql_fm_init(qlge_t *qlge)
{
	ddi_iblock_cookie_t iblk;

	QL_PRINT(DBG_INIT, ("ql_fm_init(%d) entered, FMA capability %x\n",
	    qlge->instance, qlge->fm_capabilities));
	/*
	 * Register capabilities with IO Fault Services. The capabilities
	 * set above may not be supported by the parent nexus, in that case
	 * some capability bits may be cleared.
	 */
	if (qlge->fm_capabilities)
		ddi_fm_init(qlge->dip, &qlge->fm_capabilities, &iblk);

	/*
	 * Initialize pci ereport capabilities if ereport capable
	 */
	if (DDI_FM_EREPORT_CAP(qlge->fm_capabilities) ||
	    DDI_FM_ERRCB_CAP(qlge->fm_capabilities)) {
		pci_ereport_setup(qlge->dip);
	}

	/* Register error callback if error callback capable */
	if (DDI_FM_ERRCB_CAP(qlge->fm_capabilities)) {
		ddi_fm_handler_register(qlge->dip,
		    ql_fm_error_cb, (void*) qlge);
	}

	/*
	 * DDI_FLGERR_ACC indicates:
	 *  Driver will check its access handle(s) for faults on
	 *   a regular basis by calling ddi_fm_acc_err_get
	 *  Driver is able to cope with incorrect results of I/O
	 *   operations resulted from an I/O fault
	 */
	if (DDI_FM_ACC_ERR_CAP(qlge->fm_capabilities)) {
		ql_dev_acc_attr.devacc_attr_access = DDI_FLAGERR_ACC;
	}

	/*
	 * DDI_DMA_FLAGERR indicates:
	 *  Driver will check its DMA handle(s) for faults on a
	 *   regular basis using ddi_fm_dma_err_get
	 *  Driver is able to cope with incorrect results of DMA
	 *   operations resulted from an I/O fault
	 */
	if (DDI_FM_DMA_ERR_CAP(qlge->fm_capabilities)) {
		tx_mapping_dma_attr.dma_attr_flags = DDI_DMA_FLAGERR;
		dma_attr.dma_attr_flags = DDI_DMA_FLAGERR;
	}
	QL_PRINT(DBG_INIT, ("ql_fm_init(%d) done\n",
	    qlge->instance));
}

static void
ql_fm_fini(qlge_t *qlge)
{
	QL_PRINT(DBG_INIT, ("ql_fm_fini(%d) entered\n",
	    qlge->instance));
	/* Only unregister FMA capabilities if we registered some */
	if (qlge->fm_capabilities) {

		/*
		 * Release any resources allocated by pci_ereport_setup()
		 */
		if (DDI_FM_EREPORT_CAP(qlge->fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(qlge->fm_capabilities))
			pci_ereport_teardown(qlge->dip);

		/*
		 * Un-register error callback if error callback capable
		 */
		if (DDI_FM_ERRCB_CAP(qlge->fm_capabilities))
			ddi_fm_handler_unregister(qlge->dip);

		/* Unregister from IO Fault Services */
		ddi_fm_fini(qlge->dip);
	}
	QL_PRINT(DBG_INIT, ("ql_fm_fini(%d) done\n",
	    qlge->instance));
}
/*
 * ql_attach - Driver attach.
 */
static int
ql_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance;
	qlge_t *qlge = NULL;
	int rval;
	uint16_t w;
	mac_register_t *macp = NULL;
	uint32_t data;

	rval = DDI_FAILURE;

	/* first get the instance */
	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_ATTACH:
		/*
		 * Allocate our per-device-instance structure
		 */
		qlge = (qlge_t *)kmem_zalloc(sizeof (*qlge), KM_SLEEP);
		ASSERT(qlge != NULL);
		qlge->sequence |= INIT_SOFTSTATE_ALLOC;

		qlge->dip = dip;
		qlge->instance = instance;
		/* Set up the coalescing parameters. */
		qlge->ql_dbgprnt = 0;
#if QL_DEBUG
		qlge->ql_dbgprnt = QL_DEBUG;
#endif /* QL_DEBUG */

		/*
		 * Initialize for fma support
		 */
		/* fault management (fm) capabilities. */
		qlge->fm_capabilities =
		    DDI_FM_EREPORT_CAPABLE | DDI_FM_ERRCB_CAPABLE;
		data = ql_get_prop(qlge, "fm-capable");
		if (data <= 0xf) {
			qlge->fm_capabilities = data;
		}
		ql_fm_init(qlge);
		qlge->sequence |= INIT_FM;
		QL_PRINT(DBG_INIT, ("ql_attach(%d): fma init done\n",
		    qlge->instance));

		/*
		 * Setup the ISP8x00 registers address mapping to be
		 * accessed by this particular driver.
		 * 0x0   Configuration Space
		 * 0x1   I/O Space
		 * 0x2   1st Memory Space address - Control Register Set
		 * 0x3   2nd Memory Space address - Doorbell Memory Space
		 */
		w = 2;
		if (ddi_regs_map_setup(dip, w, (caddr_t *)&qlge->iobase, 0,
		    sizeof (dev_reg_t), &ql_dev_acc_attr,
		    &qlge->dev_handle) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d): Unable to map device "
			    "registers", ADAPTER_NAME, instance);
			break;
		}
		QL_PRINT(DBG_GLD, ("ql_attach: I/O base = 0x%x\n",
		    qlge->iobase));
		qlge->sequence |= INIT_REGS_SETUP;

		/* map Doorbell memory space */
		w = 3;
		if (ddi_regs_map_setup(dip, w,
		    (caddr_t *)&qlge->doorbell_reg_iobase, 0,
		    0x100000 /* sizeof (dev_doorbell_reg_t) */,
		    &ql_dev_acc_attr,
		    &qlge->dev_doorbell_reg_handle) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d): Unable to map Doorbell "
			    "registers",
			    ADAPTER_NAME, instance);
			break;
		}
		QL_PRINT(DBG_GLD, ("ql_attach: Doorbell I/O base = 0x%x\n",
		    qlge->doorbell_reg_iobase));
		qlge->sequence |= INIT_DOORBELL_REGS_SETUP;

		/*
		 * Allocate a macinfo structure for this instance
		 */
		if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
			cmn_err(CE_WARN, "%s(%d): mac_alloc failed",
			    __func__, instance);
			break;
		}
		/* save adapter status to dip private data */
		ddi_set_driver_private(dip, qlge);
		QL_PRINT(DBG_INIT, ("%s(%d): Allocate macinfo structure done\n",
		    ADAPTER_NAME, instance));
		qlge->sequence |= INIT_MAC_ALLOC;

		/*
		 * Attach this instance of the device
		 */
		/* Setup PCI Local Bus Configuration resource. */
		if (pci_config_setup(dip, &qlge->pci_handle) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d):Unable to get PCI resources",
			    ADAPTER_NAME, instance);
			if (qlge->fm_enable) {
				ql_fm_ereport(qlge, DDI_FM_DEVICE_INVAL_STATE);
				ddi_fm_service_impact(qlge->dip,
				    DDI_SERVICE_LOST);
			}
			break;
		}
		qlge->sequence |= INIT_PCI_CONFIG_SETUP;
		QL_PRINT(DBG_GLD, ("ql_attach(%d): pci_config_setup done\n",
		    instance));

		if (ql_init_instance(qlge) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d): Unable to initialize device "
			    "instance", ADAPTER_NAME, instance);
			if (qlge->fm_enable) {
				ql_fm_ereport(qlge, DDI_FM_DEVICE_INVAL_STATE);
				ddi_fm_service_impact(qlge->dip,
				    DDI_SERVICE_LOST);
			}
			break;
		}
		QL_PRINT(DBG_GLD, ("ql_attach(%d): ql_init_instance done\n",
		    instance));

		/* Setup interrupt vectors */
		if (ql_alloc_irqs(qlge) != DDI_SUCCESS) {
			break;
		}
		qlge->sequence |= INIT_INTR_ALLOC;
		QL_PRINT(DBG_GLD, ("ql_attach(%d): ql_alloc_irqs done\n",
		    instance));

		/* Configure queues */
		if (ql_setup_rings(qlge) != DDI_SUCCESS) {
			break;
		}
		qlge->sequence |= INIT_SETUP_RINGS;
		QL_PRINT(DBG_GLD, ("ql_attach(%d): setup rings done\n",
		    instance));

		/*
		 * Allocate memory resources
		 */
		if (ql_alloc_mem_resources(qlge) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d): memory allocation failed",
			    __func__, qlge->instance);
			break;
		}
		qlge->sequence |= INIT_MEMORY_ALLOC;
		QL_PRINT(DBG_GLD, ("ql_alloc_mem_resources(%d) done\n",
		    instance));

		/*
		 * Map queues to interrupt vectors
		 */
		ql_resolve_queues_to_irqs(qlge);

		/* Initialize mutex, need the interrupt priority */
		(void) ql_init_rx_tx_locks(qlge);
		qlge->sequence |= INIT_LOCKS_CREATED;
		QL_PRINT(DBG_INIT, ("%s(%d): ql_init_rx_tx_locks done\n",
		    ADAPTER_NAME, instance));

		/*
		 * Use a soft interrupt to do something that we do not want
		 * to do in regular network functions or with mutexs being held
		 */
		if (ddi_intr_add_softint(qlge->dip, &qlge->mpi_event_intr_hdl,
		    DDI_INTR_SOFTPRI_MIN, ql_mpi_event_work, (caddr_t)qlge)
		    != DDI_SUCCESS) {
			break;
		}

		if (ddi_intr_add_softint(qlge->dip, &qlge->asic_reset_intr_hdl,
		    DDI_INTR_SOFTPRI_MIN, ql_asic_reset_work, (caddr_t)qlge)
		    != DDI_SUCCESS) {
			break;
		}

		if (ddi_intr_add_softint(qlge->dip, &qlge->mpi_reset_intr_hdl,
		    DDI_INTR_SOFTPRI_MIN, ql_mpi_reset_work, (caddr_t)qlge)
		    != DDI_SUCCESS) {
			break;
		}
		qlge->sequence |= INIT_ADD_SOFT_INTERRUPT;
		QL_PRINT(DBG_INIT, ("%s(%d): ddi_intr_add_softint done\n",
		    ADAPTER_NAME, instance));

		/*
		 * mutex to protect the adapter state structure.
		 * initialize mutexes according to the interrupt priority
		 */
		mutex_init(&qlge->gen_mutex, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(qlge->intr_pri));
		mutex_init(&qlge->hw_mutex, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(qlge->intr_pri));
		mutex_init(&qlge->mbx_mutex, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(qlge->intr_pri));

		/* Mailbox wait and interrupt conditional variable. */
		cv_init(&qlge->cv_mbx_intr, NULL, CV_DRIVER, NULL);
		qlge->sequence |= INIT_MUTEX;
		QL_PRINT(DBG_INIT, ("%s(%d): mutex_init done\n",
		    ADAPTER_NAME, instance));

		/*
		 * KStats
		 */
		if (ql_init_kstats(qlge) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d): KState initialization failed",
			    ADAPTER_NAME, instance);
			break;
		}
		qlge->sequence |= INIT_KSTATS;
		QL_PRINT(DBG_INIT, ("%s(%d): ql_init_kstats done\n",
		    ADAPTER_NAME, instance));

		/*
		 * Initialize gld macinfo structure
		 */
		ql_gld3_init(qlge, macp);
		/*
		 * Add interrupt handlers
		 */
		if (ql_add_intr_handlers(qlge) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Failed to add interrupt "
			    "handlers");
			break;
		}
		qlge->sequence |= INIT_ADD_INTERRUPT;
		QL_PRINT(DBG_INIT, ("%s(%d): Add interrupt handler done\n",
		    ADAPTER_NAME, instance));

		/*
		 * MAC Register
		 */
		if (mac_register(macp, &qlge->mh) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d): mac_register failed",
			    __func__, instance);
			break;
		}
		qlge->sequence |= INIT_MAC_REGISTERED;
		QL_PRINT(DBG_GLD, ("%s(%d): mac_register done\n",
		    ADAPTER_NAME, instance));

		mac_free(macp);
		macp = NULL;

		qlge->mac_flags = QL_MAC_ATTACHED;

		ddi_report_dev(dip);

		rval = DDI_SUCCESS;

	break;
/*
 * DDI_RESUME
 * When called  with  cmd  set  to  DDI_RESUME,  attach()  must
 * restore  the hardware state of a device (power may have been
 * removed from the device), allow  pending  requests  to  con-
 * tinue,  and  service  new requests. In this case, the driver
 * must not  make  any  assumptions  about  the  state  of  the
 * hardware,  but  must  restore the state of the device except
 * for the power level of components.
 *
 */
	case DDI_RESUME:

		if ((qlge = (qlge_t *)QL_GET_DEV(dip)) == NULL)
			return (DDI_FAILURE);

		QL_PRINT(DBG_GLD, ("%s(%d)-DDI_RESUME\n",
		    __func__, qlge->instance));

		mutex_enter(&qlge->gen_mutex);
		rval = ql_do_start(qlge);
		mutex_exit(&qlge->gen_mutex);
		break;

	default:
		break;
	}

	/* if failed to attach */
	if ((cmd == DDI_ATTACH) && (rval != DDI_SUCCESS) && (qlge != NULL)) {
		cmn_err(CE_WARN, "qlge driver attach failed, sequence %x",
		    qlge->sequence);
		ql_free_resources(qlge);
	}

	return (rval);
}

/*
 * Unbind all pending tx dma handles during driver bring down
 */
static void
ql_unbind_pending_tx_dma_handle(struct tx_ring *tx_ring)
{
	struct tx_ring_desc *tx_ring_desc;
	int i, j;

	if (tx_ring->wq_desc) {
		tx_ring_desc = tx_ring->wq_desc;
		for (i = 0; i < tx_ring->wq_len; i++, tx_ring_desc++) {
			for (j = 0; j < tx_ring_desc->tx_dma_handle_used; j++) {
				if (tx_ring_desc->tx_dma_handle[j]) {
					(void) ddi_dma_unbind_handle(
					    tx_ring_desc->tx_dma_handle[j]);
				}
			}
			tx_ring_desc->tx_dma_handle_used = 0;
		} /* end of for loop */
	}
}
/*
 * Wait for all the packets sent to the chip to finish transmission
 * to prevent buffers to be unmapped before or during a transmit operation
 */
static int
ql_wait_tx_quiesce(qlge_t *qlge)
{
	int count = MAX_TX_WAIT_COUNT, i;
	int rings_done;
	volatile struct tx_ring *tx_ring;
	uint32_t consumer_idx;
	uint32_t producer_idx;
	uint32_t temp;
	int done = 0;
	int rval = DDI_FAILURE;

	while (!done) {
		rings_done = 0;

		for (i = 0; i < qlge->tx_ring_count; i++) {
			tx_ring = &qlge->tx_ring[i];
			temp = ql_read_doorbell_reg(qlge,
			    tx_ring->prod_idx_db_reg);
			producer_idx = temp & 0x0000ffff;
			consumer_idx = (temp >> 16);

			if (qlge->isr_stride) {
				struct rx_ring *ob_ring;
				ob_ring = &qlge->rx_ring[tx_ring->cq_id];
				if (producer_idx != ob_ring->cnsmr_idx) {
					cmn_err(CE_NOTE, " force clean \n");
					(void) ql_clean_outbound_rx_ring(
					    ob_ring);
				}
			}
			/*
			 * Get the pending iocb count, ones which have not been
			 * pulled down by the chip
			 */
			if (producer_idx >= consumer_idx)
				temp = (producer_idx - consumer_idx);
			else
				temp = (tx_ring->wq_len - consumer_idx) +
				    producer_idx;

			if ((tx_ring->tx_free_count + temp) >= tx_ring->wq_len)
				rings_done++;
			else {
				done = 1;
				break;
			}
		}

		/* If all the rings are done */
		if (rings_done >= qlge->tx_ring_count) {
#ifdef QLGE_LOAD_UNLOAD
			cmn_err(CE_NOTE, "%s(%d) done successfully \n",
			    __func__, qlge->instance);
#endif
			rval = DDI_SUCCESS;
			break;
		}

		qlge_delay(100);

		count--;
		if (!count) {

			count = MAX_TX_WAIT_COUNT;
#ifdef QLGE_LOAD_UNLOAD
			volatile struct rx_ring *rx_ring;
			cmn_err(CE_NOTE, "%s(%d): Waiting for %d pending"
			    " Transmits on queue %d to complete .\n",
			    __func__, qlge->instance,
			    (qlge->tx_ring[i].wq_len -
			    qlge->tx_ring[i].tx_free_count),
			    i);

			rx_ring = &qlge->rx_ring[i+1];
			temp = ql_read_doorbell_reg(qlge,
			    rx_ring->cnsmr_idx_db_reg);
			consumer_idx = temp & 0x0000ffff;
			producer_idx = (temp >> 16);
			cmn_err(CE_NOTE, "%s(%d): Transmit completion queue %d,"
			    " Producer %d, Consumer %d\n",
			    __func__, qlge->instance,
			    i+1,
			    producer_idx, consumer_idx);

			temp = ql_read_doorbell_reg(qlge,
			    tx_ring->prod_idx_db_reg);
			producer_idx = temp & 0x0000ffff;
			consumer_idx = (temp >> 16);
			cmn_err(CE_NOTE, "%s(%d): Transmit request queue %d,"
			    " Producer %d, Consumer %d\n",
			    __func__, qlge->instance, i,
			    producer_idx, consumer_idx);
#endif

			/* For now move on */
			break;
		}
	}
	/* Stop the request queue */
	mutex_enter(&qlge->hw_mutex);
	for (i = 0; i < qlge->tx_ring_count; i++) {
		if (qlge->tx_ring[i].valid_db_reg) {
			ql_write_doorbell_reg(qlge,
			    qlge->tx_ring[i].valid_db_reg, 0);
		}
	}
	mutex_exit(&qlge->hw_mutex);
	return (rval);
}

/*
 * Wait for all the receives indicated to the stack to come back
 */
static int
ql_wait_rx_complete(qlge_t *qlge)
{
	int i;
	/* Disable all the completion queues */
	mutex_enter(&qlge->hw_mutex);
	for (i = 0; i < qlge->rx_ring_count; i++) {
		if (qlge->rx_ring[i].valid_db_reg) {
			ql_write_doorbell_reg(qlge,
			    qlge->rx_ring[i].valid_db_reg, 0);
		}
	}
	mutex_exit(&qlge->hw_mutex);

	/* Wait for OS to return all rx buffers */
	qlge_delay(QL_ONE_SEC_DELAY);
	return (DDI_SUCCESS);
}

/*
 * stop the driver
 */
static int
ql_bringdown_adapter(qlge_t *qlge)
{
	int i;
	int status = DDI_SUCCESS;

	qlge->mac_flags = QL_MAC_BRINGDOWN;
	if (qlge->sequence & ADAPTER_INIT) {
		/* stop forwarding external packets to driver */
		status = ql_sem_spinlock(qlge, SEM_RT_IDX_MASK);
		if (status)
			return (status);
		(void) ql_stop_routing(qlge);
		ql_sem_unlock(qlge, SEM_RT_IDX_MASK);
		/*
		 * Set the flag for receive and transmit
		 * operations to cease
		 */
		for (i = 0; i < qlge->tx_ring_count; i++) {
			mutex_enter(&qlge->tx_ring[i].tx_lock);
			qlge->tx_ring[i].mac_flags = QL_MAC_STOPPED;
			mutex_exit(&qlge->tx_ring[i].tx_lock);
		}

		for (i = 0; i < qlge->rx_ring_count; i++) {
			mutex_enter(&qlge->rx_ring[i].rx_lock);
			qlge->rx_ring[i].mac_flags = QL_MAC_STOPPED;
			mutex_exit(&qlge->rx_ring[i].rx_lock);
		}

		/*
		 * Need interrupts to be running while the transmit
		 * completions are cleared. Wait for the packets
		 * queued to the chip to be sent out
		 */
		(void) ql_wait_tx_quiesce(qlge);
		/* Interrupts not needed from now */
		ql_disable_all_completion_interrupts(qlge);

		mutex_enter(&qlge->hw_mutex);
		/* Disable Global interrupt */
		ql_disable_global_interrupt(qlge);
		mutex_exit(&qlge->hw_mutex);

		/* Wait for all the indicated packets to come back */
		status = ql_wait_rx_complete(qlge);

		mutex_enter(&qlge->hw_mutex);
		/* Reset adapter */
		(void) ql_asic_reset(qlge);
		/*
		 * Unbind all tx dma handles to prevent pending tx descriptors'
		 * dma handles from being re-used.
		 */
		for (i = 0; i < qlge->tx_ring_count; i++) {
			ql_unbind_pending_tx_dma_handle(&qlge->tx_ring[i]);
		}

		qlge->sequence &= ~ADAPTER_INIT;

		mutex_exit(&qlge->hw_mutex);
	}
	return (status);
}

/*
 * ql_detach
 * Used to remove all the states associated with a given
 * instances of a device node prior to the removal of that
 * instance from the system.
 */
static int
ql_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	qlge_t *qlge;
	int rval;

	rval = DDI_SUCCESS;

	switch (cmd) {
	case DDI_DETACH:

		if ((qlge = QL_GET_DEV(dip)) == NULL)
			return (DDI_FAILURE);
		rval = ql_bringdown_adapter(qlge);
		if (rval != DDI_SUCCESS)
			break;

		qlge->mac_flags = QL_MAC_DETACH;

		/* free memory resources */
		if (qlge->sequence & INIT_MEMORY_ALLOC) {
			ql_free_mem_resources(qlge);
			qlge->sequence &= ~INIT_MEMORY_ALLOC;
		}
		ql_free_resources(qlge);

		break;

	case DDI_SUSPEND:
		if ((qlge = QL_GET_DEV(dip)) == NULL)
			return (DDI_FAILURE);

		mutex_enter(&qlge->gen_mutex);
		if ((qlge->mac_flags == QL_MAC_ATTACHED) ||
		    (qlge->mac_flags == QL_MAC_STARTED)) {
			(void) ql_do_stop(qlge);
		}
		qlge->mac_flags = QL_MAC_SUSPENDED;
		mutex_exit(&qlge->gen_mutex);

		break;
	default:
		rval = DDI_FAILURE;
		break;
	}

	return (rval);
}

/*
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 */
int
ql_quiesce(dev_info_t *dip)
{
	qlge_t *qlge;
	int i;

	if ((qlge = QL_GET_DEV(dip)) == NULL)
		return (DDI_FAILURE);

	if (CFG_IST(qlge, CFG_CHIP_8100)) {
		/* stop forwarding external packets to driver */
		(void) ql_sem_spinlock(qlge, SEM_RT_IDX_MASK);
		(void) ql_stop_routing(qlge);
		ql_sem_unlock(qlge, SEM_RT_IDX_MASK);
		/* Stop all the request queues */
		for (i = 0; i < qlge->tx_ring_count; i++) {
			if (qlge->tx_ring[i].valid_db_reg) {
				ql_write_doorbell_reg(qlge,
				    qlge->tx_ring[i].valid_db_reg, 0);
			}
		}
		qlge_delay(QL_ONE_SEC_DELAY/4);
		/* Interrupts not needed from now */
		/* Disable MPI interrupt */
		ql_write_reg(qlge, REG_INTERRUPT_MASK,
		    (INTR_MASK_PI << 16));
		ql_disable_global_interrupt(qlge);

		/* Disable all the rx completion queues */
		for (i = 0; i < qlge->rx_ring_count; i++) {
			if (qlge->rx_ring[i].valid_db_reg) {
				ql_write_doorbell_reg(qlge,
				    qlge->rx_ring[i].valid_db_reg, 0);
			}
		}
		qlge_delay(QL_ONE_SEC_DELAY/4);
		qlge->mac_flags = QL_MAC_STOPPED;
		/* Reset adapter */
		(void) ql_asic_reset(qlge);
		qlge_delay(100);
	}

	return (DDI_SUCCESS);
}

QL_STREAM_OPS(ql_ops, ql_attach, ql_detach);

/*
 * Loadable Driver Interface Structures.
 * Declare and initialize the module configuration section...
 */
static struct modldrv modldrv = {
	&mod_driverops,		/* type of module: driver */
	version,		/* name of module */
	&ql_ops			/* driver dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, 	&modldrv,	NULL
};

/*
 * Loadable Module Routines
 */

/*
 * _init
 * Initializes a loadable module. It is called before any other
 * routine in a loadable module.
 */
int
_init(void)
{
	int rval;

	mac_init_ops(&ql_ops, ADAPTER_NAME);
	rval = mod_install(&modlinkage);
	if (rval != DDI_SUCCESS) {
		mac_fini_ops(&ql_ops);
		cmn_err(CE_WARN, "?Unable to install/attach driver '%s'",
		    ADAPTER_NAME);
	}

	return (rval);
}

/*
 * _fini
 * Prepares a module for unloading. It is called when the system
 * wants to unload a module. If the module determines that it can
 * be unloaded, then _fini() returns the value returned by
 * mod_remove(). Upon successful return from _fini() no other
 * routine in the module will be called before _init() is called.
 */
int
_fini(void)
{
	int rval;

	rval = mod_remove(&modlinkage);
	if (rval == DDI_SUCCESS) {
		mac_fini_ops(&ql_ops);
	}

	return (rval);
}

/*
 * _info
 * Returns information about loadable module.
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
