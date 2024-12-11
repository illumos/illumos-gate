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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * rtls -- REALTEK 8139-serials PCI Fast Ethernet Driver, Depends on the
 * Generic LAN Driver utility functions in /kernel/misc/mac
 *
 * This product is covered by one or more of the following patents:
 * US5,307,459, US5,434,872, US5,732,094, US6,570,884, US6,115,776, and
 * US6,327,625.
 *
 * Currently supports:
 *	RTL8139
 */

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/errno.h>

#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/devops.h>
#include <sys/ksynch.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <sys/vlan.h>
#include <sys/strsun.h>
#include <sys/pci.h>
#include <sys/sunddi.h>
#include <sys/mii.h>
#include <sys/miiregs.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>

#include "rtls.h"

/*
 * Declarations and Module Linkage
 */

/*
 * This is the string displayed by modinfo, etc.
 */
static char rtls_ident[] = "RealTek 8139 Ethernet driver";

#ifdef RTLS_DEBUG
int rtls_debug = 0;
#endif

/*
 * Required system entry points
 */
static int rtls_attach(dev_info_t *, ddi_attach_cmd_t);
static int rtls_detach(dev_info_t *, ddi_detach_cmd_t);
static int rtls_quiesce(dev_info_t *);

/*
 * Required driver entry points for MAC
 */
static int rtls_m_start(void *);
static void rtls_m_stop(void *);
static int rtls_m_unicst(void *, const uint8_t *);
static int rtls_m_multicst(void *, boolean_t, const uint8_t *);
static int rtls_m_promisc(void *, boolean_t);
static mblk_t *rtls_m_tx(void *, mblk_t *);
static int rtls_m_getprop(void *, const char *, mac_prop_id_t, uint_t,
    void *);
static int rtls_m_setprop(void *, const char *, mac_prop_id_t, uint_t,
    const void *);
static void rtls_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);
static int rtls_m_stat(void *, uint_t, uint64_t *);

static uint_t rtls_intr(caddr_t);

/*
 * MII entry points
 */
static uint16_t rtls_mii_read(void *, uint8_t, uint8_t);
static void rtls_mii_write(void *, uint8_t, uint8_t, uint16_t);
static void rtls_mii_notify(void *, link_state_t);

/*
 * Internal functions used by the above entry points
 */
static int rtls_chip_reset(rtls_t *, boolean_t);
static void rtls_chip_init(rtls_t *);
static void rtls_chip_stop(rtls_t *rtlsp);
static void rtls_chip_start(rtls_t *rtlsp);
static void rtls_chip_restart(rtls_t *rtlsp);
static void rtls_get_mac_addr(rtls_t *, uint8_t *);
static void rtls_set_mac_addr(rtls_t *, const uint8_t *);
static uint_t rtls_hash_index(const uint8_t *);
static boolean_t rtls_send(rtls_t *, mblk_t *);
static void rtls_receive(rtls_t *);

/*
 * Buffer Management Routines
 */
static int rtls_alloc_bufs(rtls_t *);
static void rtls_free_bufs(rtls_t *);
static int rtls_alloc_dma_mem(rtls_t *, size_t,	ddi_device_acc_attr_t *,
	uint_t, dma_area_t *);
static void rtls_free_dma_mem(dma_area_t *);

#ifdef RTLS_DEBUG
static void rtls_reg_print(rtls_t *);	/* debug routine */
#endif

#define	RTLS_DRIVER_NAME	"rtls"

/*
 * Used for buffers allocated by ddi_dma_mem_alloc()
 */
static ddi_dma_attr_t dma_attr = {
	DMA_ATTR_V0,		/* dma_attr version */
	0,			/* dma_attr_addr_lo */
	(uint_t)0xFFFFFFFF,	/* dma_attr_addr_hi */
	0x7FFFFFFF,		/* dma_attr_count_max */
	4,			/* dma_attr_align */
	0x3F,			/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	(uint_t)0xFFFFFFFF,	/* dma_attr_maxxfer */
	(uint_t)0xFFFFFFFF,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0,			/* dma_attr_flags */
};

/*
 * PIO access attributes for registers
 */
static ddi_device_acc_attr_t rtls_reg_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * DMA access attributes for data
 */
static ddi_device_acc_attr_t rtls_buf_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

uchar_t rtls_broadcastaddr[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static mac_callbacks_t rtls_m_callbacks = {
	MC_PROPERTIES,
	rtls_m_stat,
	rtls_m_start,
	rtls_m_stop,
	rtls_m_promisc,
	rtls_m_multicst,
	rtls_m_unicst,
	rtls_m_tx,
	NULL,
	NULL,  /* mc_ioctl */
	NULL,  /* mc_getcapab */
	NULL,  /* mc_open */
	NULL,  /* mc_close */
	rtls_m_setprop,
	rtls_m_getprop,
	rtls_m_propinfo
};

static mii_ops_t rtls_mii_ops = {
	MII_OPS_VERSION,
	rtls_mii_read,
	rtls_mii_write,
	rtls_mii_notify,	/* notify */
	NULL,			/* reset */
};

DDI_DEFINE_STREAM_OPS(rtls_dev_ops, nulldev, nulldev, rtls_attach, rtls_detach,
    nodev, NULL, D_MP, NULL, rtls_quiesce);

/*
 * Standard module linkage initialization for a MAC driver
 */
static struct modldrv rtls_modldrv = {
	&mod_driverops,	/* type of module. This one is a driver */
	rtls_ident,	/* short description */
	&rtls_dev_ops	/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, { (void *)&rtls_modldrv, NULL }
};

/*
 *    ========== RealTek chip register access Routines ==========
 */
static uint8_t
rtls_reg_get8(rtls_t *rtlsp, uint32_t reg)
{
	uint8_t *addr;

	addr = REG8(rtlsp->io_reg, reg);
	return (ddi_get8(rtlsp->io_handle, addr));
}

static uint16_t
rtls_reg_get16(rtls_t *rtlsp, uint32_t reg)
{
	uint16_t *addr;

	addr = REG16(rtlsp->io_reg, reg);
	return (ddi_get16(rtlsp->io_handle, addr));
}

static uint32_t
rtls_reg_get32(rtls_t *rtlsp, uint32_t reg)
{
	uint32_t *addr;

	addr = REG32(rtlsp->io_reg, reg);
	return (ddi_get32(rtlsp->io_handle, addr));
}

static void
rtls_reg_set8(rtls_t *rtlsp, uint32_t reg, uint8_t value)
{
	uint8_t *addr;

	addr = REG8(rtlsp->io_reg, reg);
	ddi_put8(rtlsp->io_handle, addr, value);
}

static void
rtls_reg_set16(rtls_t *rtlsp, uint32_t reg, uint16_t value)
{
	uint16_t *addr;

	addr = REG16(rtlsp->io_reg, reg);
	ddi_put16(rtlsp->io_handle, addr, value);
}

static void
rtls_reg_set32(rtls_t *rtlsp, uint32_t reg, uint32_t value)
{
	uint32_t *addr;

	addr = REG32(rtlsp->io_reg, reg);
	ddi_put32(rtlsp->io_handle, addr, value);
}

/*
 *    ========== Module Loading Entry Points ==========
 */
int
_init(void)
{
	int	rv;

	mac_init_ops(&rtls_dev_ops, RTLS_DRIVER_NAME);
	if ((rv = mod_install(&modlinkage)) != DDI_SUCCESS) {
		mac_fini_ops(&rtls_dev_ops);
	}
	return (rv);
}

int
_fini(void)
{
	int	rv;

	if ((rv = mod_remove(&modlinkage)) == DDI_SUCCESS) {
		mac_fini_ops(&rtls_dev_ops);
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 *    ========== DDI Entry Points ==========
 */

/*
 * attach(9E) -- Attach a device to the system
 *
 * Called once for each board successfully probed.
 */
static int
rtls_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	rtls_t *rtlsp;			/* Our private device info */
	ddi_acc_handle_t pci_handle;
	uint16_t pci_commond;
	uint16_t vendorid;
	uint16_t deviceid;
	uint32_t device;
	mac_register_t *macp;
	int err;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		if ((rtlsp = ddi_get_driver_private(devinfo)) == NULL) {
			return (DDI_FAILURE);
		}
		mutex_enter(&rtlsp->rtls_io_lock);
		mutex_enter(&rtlsp->rtls_rx_lock);
		mutex_enter(&rtlsp->rtls_tx_lock);
		/*
		 * Turn on Master Enable (DMA) and IO Enable bits.
		 * Enable PCI Memory Space accesses
		 * Disable Memory Write/Invalidate
		 */
		if (pci_config_setup(devinfo, &pci_handle) != DDI_SUCCESS) {
			mutex_exit(&rtlsp->rtls_tx_lock);
			mutex_exit(&rtlsp->rtls_rx_lock);
			mutex_exit(&rtlsp->rtls_io_lock);
			return (DDI_FAILURE);
		}
		pci_commond = pci_config_get16(pci_handle, PCI_CONF_COMM);
		pci_commond &= ~PCI_COMM_MEMWR_INVAL;
		pci_commond |= PCI_COMM_ME | PCI_COMM_MAE | PCI_COMM_IO;
		pci_config_put32(pci_handle, PCI_CONF_COMM, pci_commond);
		pci_config_teardown(&pci_handle);

		rtls_chip_restart(rtlsp);
		rtlsp->chip_error = B_FALSE;
		rtlsp->tx_retry = 0;
		rtlsp->rtls_suspended = B_FALSE;
		mutex_exit(&rtlsp->rtls_tx_lock);
		mutex_exit(&rtlsp->rtls_rx_lock);
		mutex_exit(&rtlsp->rtls_io_lock);

		mii_resume(rtlsp->mii);

		mac_tx_update(rtlsp->mh);
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	/*
	 * we don't support high level interrupts in the driver
	 */
	if (ddi_intr_hilevel(devinfo, 0) != 0) {
		cmn_err(CE_WARN, "unsupported high level interrupt");
		return (DDI_FAILURE);
	}

	/*
	 * Get handle to access pci configuration space
	 */
	if (pci_config_setup(devinfo, &pci_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "pci_config_setup fail.");
		return (DDI_FAILURE);
	}

	/*
	 * Make sure we support this particular vendor/device
	 */
	vendorid = pci_config_get16(pci_handle, PCI_CONF_VENID);
	deviceid = pci_config_get16(pci_handle, PCI_CONF_DEVID);
	device = vendorid;
	device = (device << 16) | deviceid;	/* combine two id together */

	/*
	 * See if we support this device
	 * We do not return for wrong device id. It's user risk.
	 */
	switch (device) {
	default:
		cmn_err(CE_WARN,
		    "RTLS doesn't support this device: "
		    "vendorID = 0x%x, deviceID = 0x%x",
		    vendorid, deviceid);
		break;
	case RTLS_SUPPORT_DEVICE_1:
	case RTLS_SUPPORT_DEVICE_2:
	case RTLS_SUPPORT_DEVICE_3:
	case RTLS_SUPPORT_DEVICE_4:
		break;
	}

	/*
	 * Turn on Master Enable (DMA) and IO Enable bits.
	 * Enable PCI Memory Space accesses
	 * Disable Memory Write/Invalidate
	 */
	pci_commond = pci_config_get16(pci_handle, PCI_CONF_COMM);
	pci_commond &= ~PCI_COMM_MEMWR_INVAL;
	pci_commond |= PCI_COMM_ME | PCI_COMM_MAE | PCI_COMM_IO;
	pci_config_put32(pci_handle, PCI_CONF_COMM, pci_commond);

	/*
	 * Free handle to access pci configuration space
	 */
	pci_config_teardown(&pci_handle);

	rtlsp = kmem_zalloc(sizeof (rtls_t), KM_SLEEP);

	ddi_set_driver_private(devinfo, rtlsp);
	rtlsp->devinfo			= devinfo;
	rtlsp->instance			= ddi_get_instance(devinfo);

	/*
	 * Map operating register
	 */
	err = ddi_regs_map_setup(devinfo, 1, &rtlsp->io_reg,
	    (offset_t)0, 0, &rtls_reg_accattr, &rtlsp->io_handle);
	if (err != DDI_SUCCESS) {
		kmem_free((caddr_t)rtlsp, sizeof (rtls_t));
		cmn_err(CE_WARN, "ddi_regs_map_setup fail.");
		return (DDI_FAILURE);
	}

	/*
	 * Allocate the TX and RX descriptors/buffers
	 */
	if (rtls_alloc_bufs(rtlsp) == DDI_FAILURE) {
		cmn_err(CE_WARN, "DMA buffer allocation fail.");
		goto fail;
	}

	/*
	 * Reset the chip
	 */
	err = rtls_chip_reset(rtlsp, B_FALSE);
	if (err != DDI_SUCCESS)
		goto fail;

	/*
	 * Init rtls_t structure
	 */
	rtls_get_mac_addr(rtlsp, rtlsp->netaddr);

	/*
	 * Add the interrupt handler
	 *
	 * This will prevent receiving interrupts before device is ready, as
	 * we are initializing device after setting the interrupts. So we
	 * will not get our interrupt handler invoked by OS while our device
	 * is still coming up or timer routines will not start till we are
	 * all set to process...
	 */

	if (ddi_add_intr(devinfo, 0, &rtlsp->iblk, NULL, rtls_intr,
	    (caddr_t)rtlsp) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "ddi_add_intr fail.");
		goto late_fail;
	}

	if ((rtlsp->mii = mii_alloc(rtlsp, devinfo, &rtls_mii_ops)) == NULL) {
		ddi_remove_intr(devinfo, 0, rtlsp->iblk);
		goto late_fail;
	}
	/*
	 * Note: Some models of 8139 can support pause, but we have
	 * not implemented support for it at this time.  This might be
	 * an interesting feature to add later.
	 */
	mii_set_pauseable(rtlsp->mii, B_FALSE, B_FALSE);

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		cmn_err(CE_WARN, "mac_alloc fail.");
		ddi_remove_intr(devinfo, 0, rtlsp->iblk);
		goto late_fail;
	}

	/*
	 * Init mutex
	 */
	mutex_init(&rtlsp->rtls_io_lock, NULL, MUTEX_DRIVER, rtlsp->iblk);
	mutex_init(&rtlsp->rtls_tx_lock, NULL, MUTEX_DRIVER, rtlsp->iblk);
	mutex_init(&rtlsp->rtls_rx_lock, NULL, MUTEX_DRIVER, rtlsp->iblk);

	/*
	 * Initialize pointers to device specific functions which will be
	 * used by the generic layer.
	 */
	macp->m_type_ident		= MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver			= rtlsp;
	macp->m_dip			= devinfo;
	macp->m_src_addr		= rtlsp->netaddr;
	macp->m_callbacks		= &rtls_m_callbacks;
	macp->m_min_sdu			= 0;
	macp->m_max_sdu			= ETHERMTU;
	macp->m_margin			= VLAN_TAGSZ;

	if (mac_register(macp, &rtlsp->mh) != 0) {
		ddi_remove_intr(devinfo, 0, rtlsp->iblk);
		mutex_destroy(&rtlsp->rtls_io_lock);
		mutex_destroy(&rtlsp->rtls_tx_lock);
		mutex_destroy(&rtlsp->rtls_rx_lock);
		goto late_fail;
	}

	mac_free(macp);

	return (DDI_SUCCESS);

late_fail:
	if (macp)
		mac_free(macp);
	if (rtlsp->mii)
		mii_free(rtlsp->mii);

fail:
	ddi_regs_map_free(&rtlsp->io_handle);
	rtls_free_bufs(rtlsp);
	kmem_free(rtlsp, sizeof (rtls_t));

	return (DDI_FAILURE);
}

/*
 * detach(9E) -- Detach a device from the system
 */
static int
rtls_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	rtls_t *rtlsp;			/* our private device info */

	/*
	 * Get the driver private structure
	 */
	if ((rtlsp = ddi_get_driver_private(devinfo)) == NULL) {
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		mii_suspend(rtlsp->mii);

		mutex_enter(&rtlsp->rtls_io_lock);
		mutex_enter(&rtlsp->rtls_rx_lock);
		mutex_enter(&rtlsp->rtls_tx_lock);

		rtlsp->rtls_suspended = B_TRUE;
		rtls_chip_stop(rtlsp);

		mutex_exit(&rtlsp->rtls_tx_lock);
		mutex_exit(&rtlsp->rtls_rx_lock);
		mutex_exit(&rtlsp->rtls_io_lock);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	if (mac_unregister(rtlsp->mh) != 0) {
		/* device busy */
		return (DDI_FAILURE);
	}

	ddi_remove_intr(devinfo, 0, rtlsp->iblk);

	mii_free(rtlsp->mii);

	mutex_destroy(&rtlsp->rtls_io_lock);
	mutex_destroy(&rtlsp->rtls_tx_lock);
	mutex_destroy(&rtlsp->rtls_rx_lock);

	ddi_regs_map_free(&rtlsp->io_handle);
	rtls_free_bufs(rtlsp);
	kmem_free(rtlsp, sizeof (rtls_t));

	return (DDI_SUCCESS);
}

/*
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
static int
rtls_quiesce(dev_info_t *devinfo)
{
	rtls_t *rtlsp;			/* our private device info */

	/*
	 * Get the driver private structure
	 */
	if ((rtlsp = ddi_get_driver_private(devinfo)) == NULL) {
		return (DDI_FAILURE);
	}
	return (rtls_chip_reset(rtlsp, B_TRUE));
}

/*
 *    ========== MAC Entry Points ==========
 */

/*
 * rtls_m_start() -- start the board receiving and allow transmits
 */
static int
rtls_m_start(void *arg)
{
	rtls_t *rtlsp = (rtls_t *)arg;

	mutex_enter(&rtlsp->rtls_io_lock);
	mutex_enter(&rtlsp->rtls_rx_lock);
	mutex_enter(&rtlsp->rtls_tx_lock);

	if (!rtlsp->rtls_suspended)
		rtls_chip_restart(rtlsp);

	rtlsp->rtls_running = B_TRUE;

	mutex_exit(&rtlsp->rtls_tx_lock);
	mutex_exit(&rtlsp->rtls_rx_lock);
	mutex_exit(&rtlsp->rtls_io_lock);

	drv_usecwait(100);

	mii_start(rtlsp->mii);

	return (0);
}

/*
 * rtls_m_stop() -- stop board receiving and transmits
 */
static void
rtls_m_stop(void *arg)
{
	rtls_t *rtlsp = (rtls_t *)arg;

	mii_stop(rtlsp->mii);

	mutex_enter(&rtlsp->rtls_io_lock);

	if (!rtlsp->rtls_suspended)
		rtls_chip_stop(rtlsp);
	rtlsp->rtls_running = B_FALSE;

	mutex_exit(&rtlsp->rtls_io_lock);
}

/*
 * rtls_m_unicst() -- set the physical network address
 * on the board
 */
static int
rtls_m_unicst(void *arg, const uint8_t *macaddr)
{
	rtls_t *rtlsp = arg;

	mutex_enter(&rtlsp->rtls_io_lock);
	bcopy(macaddr, rtlsp->netaddr, ETHERADDRL);
	if (!rtlsp->rtls_suspended)
		rtls_set_mac_addr(rtlsp, rtlsp->netaddr);
	mutex_exit(&rtlsp->rtls_io_lock);
	return (0);
}

/*
 * rtls_m_multicst() -- set(enable) or disable a multicast address
 *
 * Program the hardware to enable/disable the multicast address in "mcast".
 */
static int
rtls_m_multicst(void *arg, boolean_t enable, const uint8_t *mcast)
{
	rtls_t *rtlsp = (rtls_t *)arg;
	uint_t index;
	uint32_t *hashp;

	mutex_enter(&rtlsp->rtls_io_lock);
	hashp = rtlsp->multi_hash;
	index = rtls_hash_index(mcast);
			/* index value is between 0 and 63 */

	if (enable) {
		if (rtlsp->multicast_cnt[index]++) {
			mutex_exit(&rtlsp->rtls_io_lock);
			return (0);
		}
		hashp[index/32] |= 1<< (index % 32);
	} else {
		if (--rtlsp->multicast_cnt[index]) {
			mutex_exit(&rtlsp->rtls_io_lock);
			return (0);
		}
		hashp[index/32] &= ~(1<< (index % 32));
	}

	/*
	 * Set multicast register
	 */
	if (!rtlsp->rtls_suspended) {
		rtls_reg_set32(rtlsp, MULTICAST_0_REG, hashp[0]);
		rtls_reg_set32(rtlsp, MULTICAST_4_REG, hashp[1]);
	}

	mutex_exit(&rtlsp->rtls_io_lock);

	return (0);
}

/*
 * rtls_hash_index() -- a hashing function used for setting the
 * node address or a multicast address
 */
static uint_t
rtls_hash_index(const uint8_t *address)
{
	uint32_t crc = (ulong_t)RTLS_HASH_CRC;
	uint32_t const POLY = RTLS_HASH_POLY;
	uint32_t msb;
	int bytes;
	uchar_t currentbyte;
	uint_t index;
	int bit;

	for (bytes = 0; bytes < ETHERADDRL; bytes++) {
		currentbyte = address[bytes];
		for (bit = 0; bit < 8; bit++) {
			msb = crc >> 31;
			crc <<= 1;
			if (msb ^ (currentbyte & 1)) {
				crc ^= POLY;
				crc |= 0x00000001;
			}
			currentbyte >>= 1;
		}
	}

	index = crc >> 26;

	return (index);
}

/*
 * rtls_m_promisc() -- set or reset promiscuous mode on the board
 */
static int
rtls_m_promisc(void *arg, boolean_t on)
{
	rtls_t *rtlsp = arg;

	mutex_enter(&rtlsp->rtls_io_lock);

	rtlsp->promisc = on;
	if (!rtlsp->rtls_suspended) {
		uint32_t val32 = rtls_reg_get32(rtlsp, RX_CONFIG_REG);
		if (on) {
			val32 |= RX_ACCEPT_ALL_PACKET;
		} else {
			val32 &= ~RX_ACCEPT_ALL_PACKET;
		}
		rtls_reg_set32(rtlsp, RX_CONFIG_REG, val32);
	}
	mutex_exit(&rtlsp->rtls_io_lock);

	return (0);
}

/*
 * rtls_m_stat() -- retrieve statistic
 *
 * MAC calls this routine just before it reads the driver's statistics
 * structure.  If your board maintains statistics, this is the time to
 * read them in and update the values in the structure. If the driver
 * maintains statistics continuously, this routine need do nothing.
 */
static int
rtls_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	rtls_t *rtlsp = arg;

	if (mii_m_getstat(rtlsp->mii, stat, val) == 0) {
		return (0);
	}

	switch (stat) {
	case MAC_STAT_IPACKETS:
		*val = rtlsp->stats.ipackets;
		break;
	case MAC_STAT_RBYTES:
		*val = rtlsp->stats.rbytes;
		break;
	case MAC_STAT_OPACKETS:
		*val = rtlsp->stats.opackets;
		break;
	case MAC_STAT_OBYTES:
		*val = rtlsp->stats.obytes;
		break;
	case MAC_STAT_IERRORS:
		*val = rtlsp->stats.rcv_err;
		break;
	case MAC_STAT_OERRORS:
		*val = rtlsp->stats.xmt_err;
		break;
	case MAC_STAT_MULTIRCV:
		*val = rtlsp->stats.multi_rcv;
		break;
	case MAC_STAT_BRDCSTRCV:
		*val = rtlsp->stats.brdcst_rcv;
		break;
	case MAC_STAT_MULTIXMT:
		*val = rtlsp->stats.multi_xmt;
		break;
	case MAC_STAT_BRDCSTXMT:
		*val = rtlsp->stats.brdcst_xmt;
		break;
	case MAC_STAT_UNDERFLOWS:
		*val = rtlsp->stats.underflow;
		break;
	case MAC_STAT_OVERFLOWS:
		*val = rtlsp->stats.overflow;
		break;
	case MAC_STAT_NORCVBUF:
		*val = rtlsp->stats.no_rcvbuf;
		break;
	case MAC_STAT_COLLISIONS:
		*val = rtlsp->stats.collisions;
		break;
	case ETHER_STAT_FCS_ERRORS:
		*val = rtlsp->stats.crc_err;
		break;
	case ETHER_STAT_ALIGN_ERRORS:
		*val = rtlsp->stats.frame_err;
		break;
	case ETHER_STAT_DEFER_XMTS:
		*val = rtlsp->stats.defer;
		break;
	case ETHER_STAT_TX_LATE_COLLISIONS:
		*val = rtlsp->stats.xmt_latecoll;
		break;
	case ETHER_STAT_TOOLONG_ERRORS:
		*val = rtlsp->stats.too_long;
		break;
	case ETHER_STAT_TOOSHORT_ERRORS:
		*val = rtlsp->stats.in_short;
		break;
	case ETHER_STAT_CARRIER_ERRORS:
		*val = rtlsp->stats.no_carrier;
		break;
	case ETHER_STAT_FIRST_COLLISIONS:
		*val = rtlsp->stats.firstcol;
		break;
	case ETHER_STAT_MULTI_COLLISIONS:
		*val = rtlsp->stats.multicol;
		break;
	default:
		return (ENOTSUP);
	}

	/*
	 * RTL8139 don't support MII statistics,
	 * these values are maintained by the driver software.
	 */

#ifdef RTLS_DEBUG
	if (rtls_debug & RTLS_TRACE)
		rtls_reg_print(rtlsp);
#endif

	return (0);
}

int
rtls_m_getprop(void *arg, const char *name, mac_prop_id_t num, uint_t sz,
    void *val)
{
	rtls_t *rtlsp = arg;

	return (mii_m_getprop(rtlsp->mii, name, num, sz, val));
}

int
rtls_m_setprop(void *arg, const char *name, mac_prop_id_t num, uint_t sz,
    const void *val)
{
	rtls_t *rtlsp = arg;

	return (mii_m_setprop(rtlsp->mii, name, num, sz, val));
}

static void
rtls_m_propinfo(void *arg, const char *name, mac_prop_id_t num,
    mac_prop_info_handle_t prh)
{
	rtls_t *rtlsp = arg;

	mii_m_propinfo(rtlsp->mii, name, num, prh);
}

/*
 * rtls_send() -- send a packet
 *
 * Called when a packet is ready to be transmitted. A pointer to an
 * M_DATA message that contains the packet is passed to this routine.
 * The complete LLC header is contained in the message's first message
 * block, and the remainder of the packet is contained within
 * additional M_DATA message blocks linked to the first message block.
 *
 * Returns B_TRUE if the packet was properly disposed of, or B_FALSE if
 * if the packet is being deferred and should be tried again later.
 */

static boolean_t
rtls_send(rtls_t *rtlsp, mblk_t *mp)
{
	int totlen;
	int ncc;
	uint16_t cur_desc;
	uint32_t tx_status;

	ASSERT(mp != NULL);
	ASSERT(rtlsp->rtls_running);

	mutex_enter(&rtlsp->rtls_tx_lock);

	if (rtlsp->rtls_suspended) {
		mutex_exit(&rtlsp->rtls_tx_lock);
		return (B_FALSE);
	}

	/*
	 * If chip error ...
	 */
	if (rtlsp->chip_error) {
#ifdef RTLS_DEBUG
		cmn_err(CE_WARN,
		    "%s: send fail--CHIP ERROR!",
		    mac_name(rtlsp->mh));
#endif
		mutex_exit(&rtlsp->rtls_tx_lock);
		freemsg(mp);
		return (B_TRUE);
	}

	/*
	 * If chip link down ...  Note that experimentation shows that
	 * the device seems not to care about whether or not we have
	 * this check, but if we don't add the check here, it might
	 * not be properly reported as a carrier error.
	 */
	if (rtls_reg_get8(rtlsp, MEDIA_STATUS_REG) & MEDIA_STATUS_LINK) {
#ifdef RTLS_DEBUG
		cmn_err(CE_WARN,
		    "%s: send fail--LINK DOWN!",
		    mac_name(rtlsp->mh));
#endif
		rtlsp->stats.no_carrier++;
		mutex_exit(&rtlsp->rtls_tx_lock);
		freemsg(mp);
		return (B_TRUE);
	}

	/*
	 * Current transmit descriptor
	 */
	cur_desc = rtlsp->tx_current_desc;
	ASSERT(cur_desc < RTLS_MAX_TX_DESC);

	/*
	 * RealTek 8139 has 4 tx descriptor for transmit. In the first tx loop
	 * of transmit,we needn't judge transmit status.
	 */
	if (rtlsp->tx_first_loop < RTLS_MAX_TX_DESC) {
		rtlsp->tx_first_loop++;
		goto tx_ready;
	}

	/*
	 * If it's not the first tx loop, we need judge whether the chip is
	 * busy or not. Otherwise, we have to reschedule send and wait...
	 */
	tx_status = rtls_reg_get32(rtlsp, TX_STATUS_DESC0_REG + 4 * cur_desc);

	/*
	 * H/W doesn't complete packet transmit
	 */
	if (!(tx_status & TX_COMPLETE_FLAG)) {
#ifdef RTLS_DEBUG
		if (rtls_debug & RTLS_SEND) {
			cmn_err(CE_NOTE,
			    "%s: rtls_send: need_sched", mac_name(rtlsp->mh));
		}
#endif
		/*
		 * Through test, we find RTL8139 tx status might be
		 * not-completing all along. We have to reset chip
		 * to make RTL8139 tansmit re-work.
		 */
		if (rtlsp->tx_retry++ > RTLS_TX_RETRY_NUM) {

			/*
			 * Wait transmit h/w more time...
			 */
			RTLS_TX_WAIT_TIMEOUT;	/* 100 ms */

			/*
			 * Judge tx status again, if it remains not-completing,
			 * we can confirm RTL8139 is in chip error state
			 * and must reset it.
			 */
			tx_status = rtls_reg_get32(rtlsp,
			    TX_STATUS_DESC0_REG + 4 * cur_desc);
			if (!(tx_status & TX_COMPLETE_FLAG)) {
#ifdef RTLS_DEBUG
				cmn_err(CE_NOTE, "%s: tx chip_error = 0x%x",
				    mac_name(rtlsp->mh), tx_status);
#endif
				rtlsp->tx_retry = 0;
				rtlsp->chip_error = B_TRUE;
				rtlsp->stats.xmt_err++;
				rtlsp->stats.mac_xmt_err++;
				mutex_exit(&rtlsp->rtls_tx_lock);
				freemsg(mp);
				return (B_TRUE);
			}
		} else {
			rtlsp->stats.defer++;
			rtlsp->need_sched = B_TRUE;
			mutex_exit(&rtlsp->rtls_tx_lock);
			return (B_FALSE);
		}
	}

	/*
	 * Transmit error?
	 */
	if (tx_status & TX_ERR_FLAG) {
#ifdef RTLS_DEBUG
		if (rtls_debug & RTLS_SEND) {
			cmn_err(CE_NOTE, "%s: transmit error, status = 0x%x",
			    mac_name(rtlsp->mh), tx_status);
		}
#endif
		rtlsp->stats.xmt_err++;
		if (tx_status & TX_STATUS_TX_UNDERRUN)
			rtlsp->stats.underflow++;
		if (tx_status & TX_STATUS_CS_LOST)
			rtlsp->stats.no_carrier++;
		if (tx_status & TX_STATUS_OWC)
			rtlsp->stats.xmt_latecoll++;
	}
	ncc = ((tx_status & TX_STATUS_NCC) >> TX_STATUS_NCC_SHIFT);
	if (ncc != 0) {
		rtlsp->stats.collisions += ncc;
		rtlsp->stats.firstcol++;
		rtlsp->stats.multicol += ncc - 1;
	}

tx_ready:
	/*
	 * Initialize variable
	 */
	rtlsp->tx_retry = 0;
	totlen = 0;

	/*
	 * Copy packet to tx descriptor buffer
	 */
	totlen = msgsize(mp);
	if (totlen > (ETHERMAX + 4)) {	/* 4 bytes for VLAN header */
		cmn_err(CE_NOTE,
		    "%s: rtls_send: try to send large %d packet",
		    mac_name(rtlsp->mh), totlen);
		rtlsp->stats.mac_xmt_err++;
		rtlsp->stats.xmt_err++;
		freemsg(mp);
		mutex_exit(&rtlsp->rtls_tx_lock);
		return (B_TRUE);
	}

	/* this will free the mblk */
	mcopymsg(mp, rtlsp->tx_buf[cur_desc]);

	/* update stats */
	if (*rtlsp->tx_buf[cur_desc] & 0x1)  {
		uint16_t	*ptr = (void *)rtlsp->tx_buf[cur_desc];
		if ((ptr[0] == 0xffff) &&
		    (ptr[1] == 0xffff) &&
		    (ptr[2] == 0xffff)) {
			rtlsp->stats.brdcst_xmt++;
		} else {
			rtlsp->stats.multi_xmt++;
		}
	}
	rtlsp->stats.opackets++;
	rtlsp->stats.obytes += totlen;

	if (totlen < ETHERMIN) {
		bzero(rtlsp->tx_buf[cur_desc] + totlen, ETHERMIN - totlen);
		totlen = ETHERMIN;
	}

	/* make sure caches are flushed */
	(void) ddi_dma_sync(rtlsp->dma_area_tx[cur_desc].dma_hdl, 0, totlen,
	    DDI_DMA_SYNC_FORDEV);

	/*
	 * Start transmit
	 * set transmit FIFO threshhold to 0x30*32 = 1536 bytes
	 * to avoid tx underrun.
	 */
	rtls_reg_set32(rtlsp, TX_STATUS_DESC0_REG + 4 * cur_desc,
	    totlen | (0x30 << TX_STATUS_TX_THRESHOLD_SHIFT));

	/*
	 * Update the value of current tx descriptor
	 */
	cur_desc++;
	cur_desc %= RTLS_MAX_TX_DESC;
	rtlsp->tx_current_desc = cur_desc;

	mutex_exit(&rtlsp->rtls_tx_lock);

	return (B_TRUE);
}

/*
 * rtls_m_tx() -- send a chain of packets, linked by mp->b_next.
 */
static mblk_t *
rtls_m_tx(void *arg, mblk_t *mp)
{
	rtls_t *rtlsp = arg;
	mblk_t *next;

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		if (!rtls_send(rtlsp, mp)) {
			mp->b_next = next;
			break;
		}
		mp = next;
	}
	return (mp);
}

/*
 * rtls_receive() -- receive packets
 *
 * Called when receive interrupts detected
 */
static void
rtls_receive(rtls_t *rtlsp)
{
	mblk_t *head = NULL;
	mblk_t **mpp;
	mblk_t *mp;
	uint16_t rx_status;
	uint16_t packet_len;
	int wrap_size;
	uint32_t cur_rx;
	uint8_t *rx_ptr;

	mpp = &head;

	mutex_enter(&rtlsp->rtls_rx_lock);

	if (rtlsp->rtls_suspended) {
		mutex_exit(&rtlsp->rtls_rx_lock);
		return;
	}

	while ((rtls_reg_get8(rtlsp, RT_COMMAND_REG)
	    & RT_COMMAND_BUFF_EMPTY) == 0) {

		/*
		 * Chip error state
		 */
		if (rtlsp->chip_error) {
#ifdef RTLS_DEBUG
		cmn_err(CE_WARN,
		    "%s: receive fail--CHIP ERROR!",
		    mac_name(rtlsp->mh));
#endif
			break;
		}

		cur_rx = rtlsp->cur_rx;
		rx_ptr = rtlsp->rx_ring + cur_rx;
		packet_len = (rx_ptr[3] << 8) | (rx_ptr[2]);
		rx_status = rx_ptr[0];

		/*
		 * DMA still in progress
		 */
		if (packet_len == RX_STATUS_DMA_BUSY) {
			cmn_err(CE_NOTE, "%s: Rx DMA still in progress",
			    mac_name(rtlsp->mh));
			break;
		}

		/*
		 * Check receive status
		 */
		if ((rx_status & RX_ERR_FLAGS) ||
		    (!(rx_status & RX_HEADER_STATUS_ROK)) ||
		    (packet_len < (ETHERMIN + ETHERFCSL)) ||
		    (packet_len > (ETHERMAX + ETHERFCSL + 4))) {
#ifdef RTLS_DEBUG
			cmn_err(CE_NOTE,
			    "%s: receive error, status = 0x%x, length = %d",
			    mac_name(rtlsp->mh), rx_status, packet_len);
#endif
			/*
			 * Rx error statistics
			 */
			if ((rx_status & RX_HEADER_STATUS_RUNT) ||
			    (packet_len < (ETHERMIN + ETHERFCSL)))
				rtlsp->stats.in_short++;
			else if (packet_len > (ETHERMAX + ETHERFCSL + 4))
				rtlsp->stats.too_long++;
			else if (rx_status & RX_HEADER_STATUS_CRC)
				rtlsp->stats.crc_err++;
			else if (rx_status & RX_HEADER_STATUS_FAE)
				rtlsp->stats.frame_err++;

			/*
			 * Set chip_error flag to reset chip:
			 * (suggested in RealTek programming guide.)
			 */
			rtlsp->chip_error = B_TRUE;
			mutex_exit(&rtlsp->rtls_rx_lock);
			return;
		}

		/*
		 * We need not up-send ETHERFCSL bytes of receive packet
		 */
		packet_len -= ETHERFCSL;

		/*
		 * Allocate buffer to receive this good packet
		 */
		mp = allocb(packet_len, 0);

		/*
		 * Copy the data found into the new cluster, we have (+4)
		 * to get us past the packet head data that the rtl chip
		 * places at the start of the message
		 */
		if ((cur_rx + packet_len + RX_HEADER_SIZE)
		    > RTLS_RX_BUF_RING) {
			wrap_size = cur_rx + packet_len + RX_HEADER_SIZE
			    - RTLS_RX_BUF_RING;
#ifdef RTLS_DEBUG
			if (rtls_debug & RTLS_RECV) {
				cmn_err(CE_NOTE,
				    "%s: Rx: packet_len = %d, wrap_size = %d",
				    mac_name(rtlsp->mh), packet_len, wrap_size);
			}
#endif

			if (mp != NULL) {
				/* Flush caches */
				(void) ddi_dma_sync(rtlsp->dma_area_rx.dma_hdl,
				    cur_rx + RX_HEADER_SIZE,
				    packet_len - wrap_size,
				    DDI_DMA_SYNC_FORKERNEL);
				(void) ddi_dma_sync(rtlsp->dma_area_rx.dma_hdl,
				    0, wrap_size,
				    DDI_DMA_SYNC_FORKERNEL);

				/*
				 * Copy in first section of message as stored
				 * at the end of the ring buffer
				 */
				bcopy(rx_ptr + RX_HEADER_SIZE,
				    mp->b_wptr, packet_len - wrap_size);
				mp->b_wptr += packet_len - wrap_size;
				bcopy(rtlsp->rx_ring, mp->b_wptr, wrap_size);
				mp->b_wptr += wrap_size;
				*mpp = mp;
				mpp = &mp->b_next;

				rtlsp->stats.ipackets++;
				if (rx_status & RX_HEADER_STATUS_BCAST)
					rtlsp->stats.brdcst_rcv++;
				if (rx_status & RX_HEADER_STATUS_MULTI)
					rtlsp->stats.multi_rcv++;
				rtlsp->stats.rbytes += packet_len;
			} else  {
				rtlsp->stats.no_rcvbuf++;
			}

			cur_rx = RTLS_RX_ADDR_ALIGNED(wrap_size + ETHERFCSL);
							/* 4-byte aligned */
		} else {

			if (mp != NULL) {
				/* Flush caches */
				(void) ddi_dma_sync(rtlsp->dma_area_rx.dma_hdl,
				    cur_rx + RX_HEADER_SIZE, packet_len,
				    DDI_DMA_SYNC_FORKERNEL);
				bcopy(rx_ptr + RX_HEADER_SIZE, mp->b_wptr,
				    packet_len);
				mp->b_wptr += packet_len;
				*mpp = mp;
				mpp = &mp->b_next;

				rtlsp->stats.ipackets++;
				if (rx_status & RX_HEADER_STATUS_BCAST)
					rtlsp->stats.brdcst_rcv++;
				if (rx_status & RX_HEADER_STATUS_MULTI)
					rtlsp->stats.multi_rcv++;
				rtlsp->stats.rbytes += packet_len;
			} else {
				rtlsp->stats.no_rcvbuf++;
			}
			cur_rx += packet_len + RX_HEADER_SIZE + ETHERFCSL;

			cur_rx = RTLS_RX_ADDR_ALIGNED(cur_rx);
							/* 4-byte aligned */
		}

		/*
		 * Update rx buffer ring read pointer:
		 * give us a little leeway to ensure no overflow
		 */
		rtlsp->cur_rx = cur_rx;
		rtls_reg_set16(rtlsp, RX_CURRENT_READ_ADDR_REG,
		    cur_rx - READ_ADDR_GAP);
	}
	mutex_exit(&rtlsp->rtls_rx_lock);

	/*
	 * Upsend packet
	 */
	if (head) {
		mac_rx(rtlsp->mh, NULL, head);
	}
}

/*
 * rtls_intr() -- interrupt from board to inform us that a receive or
 * link change.
 */
static uint_t
rtls_intr(caddr_t arg)
{
	rtls_t *rtlsp = (void *)arg;
	uint32_t int_status;
	uint32_t val32;
	boolean_t	resched = B_FALSE;

	mutex_enter(&rtlsp->rtls_io_lock);
	if (rtlsp->rtls_suspended) {
		mutex_exit(&rtlsp->rtls_io_lock);
		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * Was this interrupt caused by our device...
	 */
	int_status = rtls_reg_get16(rtlsp, RT_INT_STATUS_REG);
	if (!(int_status & rtlsp->int_mask)) {
		mutex_exit(&rtlsp->rtls_io_lock);
		return (DDI_INTR_UNCLAIMED);
				/* indicate it wasn't our interrupt */
	}

	/*
	 * Clear interrupt
	 */
	rtls_reg_set16(rtlsp, RT_INT_STATUS_REG, int_status);

	/*
	 * If chip error, restart chip...
	 */
	if (rtlsp->chip_error) {
		mutex_enter(&rtlsp->rtls_rx_lock);
		mutex_enter(&rtlsp->rtls_tx_lock);
		rtls_chip_restart(rtlsp);
		rtlsp->chip_error = B_FALSE;
		rtlsp->tx_retry = 0;
		mutex_exit(&rtlsp->rtls_tx_lock);
		mutex_exit(&rtlsp->rtls_rx_lock);
		mutex_exit(&rtlsp->rtls_io_lock);
		return (DDI_INTR_CLAIMED);
			/* no need to hand other interrupts */
	}

	/*
	 * Transmit error interrupt
	 */
	if (int_status & TX_ERR_INT) {
		val32 = rtls_reg_get32(rtlsp, TX_CONFIG_REG);
		val32 |= TX_CLEAR_ABORT;
		rtls_reg_set32(rtlsp, TX_CONFIG_REG, val32);
		cmn_err(CE_WARN, "%s: transmit abort!!!", mac_name(rtlsp->mh));
	}

	/*
	 * Trigger mac_tx_update
	 */
	if (rtlsp->need_sched) {
		rtlsp->need_sched = B_FALSE;
		resched = B_TRUE;
	}

	mutex_exit(&rtlsp->rtls_io_lock);

	/*
	 * Receive interrupt
	 */
	if (int_status & RTLS_RX_INT) {
		if (int_status & RX_OVERFLOW_INT) {
			rtlsp->stats.overflow++;
			rtlsp->stats.rcv_err++;
		}
		rtls_receive(rtlsp);
	}

	/*
	 * Link change interrupt.
	 */
	if (int_status & LINK_CHANGE_INT) {
		mii_check(rtlsp->mii);
	}

	if (resched) {
		mac_tx_update(rtlsp->mh);
	}

	return (DDI_INTR_CLAIMED);	/* indicate it was our interrupt */
}

/*
 *    ========== Buffer Management Routines ==========
 */

/*
 * rtls_alloc_dma_mem() -- allocate an area of memory and a DMA handle
 * for accessing it
 */
static int
rtls_alloc_dma_mem(rtls_t *rtlsp, size_t memsize,
    ddi_device_acc_attr_t *attr_p, uint_t dma_flags, dma_area_t *dma_p)
{
	caddr_t vaddr;
	int err;

	/*
	 * Allocate handle
	 */
	err = ddi_dma_alloc_handle(rtlsp->devinfo, &dma_attr,
	    DDI_DMA_SLEEP, NULL, &dma_p->dma_hdl);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s: rtls_alloc_dma_mem: ddi_dma_alloc_handle failed: %d",
		    mac_name(rtlsp->mh), err);
		dma_p->dma_hdl = NULL;
		return (DDI_FAILURE);
	}

	/*
	 * Allocate memory
	 */
	err = ddi_dma_mem_alloc(dma_p->dma_hdl, memsize, attr_p,
	    dma_flags & (DDI_DMA_CONSISTENT | DDI_DMA_STREAMING),
	    DDI_DMA_SLEEP, NULL, &vaddr, &dma_p->alength, &dma_p->acc_hdl);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s: rtls_alloc_dma_mem: ddi_dma_mem_alloc failed: %d",
		    mac_name(rtlsp->mh), err);
		ddi_dma_free_handle(&dma_p->dma_hdl);
		dma_p->dma_hdl = NULL;
		dma_p->acc_hdl = NULL;
		return (DDI_FAILURE);
	}

	/*
	 * Bind the two together
	 */
	dma_p->mem_va = vaddr;
	err = ddi_dma_addr_bind_handle(dma_p->dma_hdl, NULL,
	    vaddr, dma_p->alength, dma_flags, DDI_DMA_SLEEP, NULL,
	    &dma_p->cookie, &dma_p->ncookies);
	if (err != DDI_DMA_MAPPED || dma_p->ncookies != 1) {
		cmn_err(CE_WARN,
		    "%s: rtls_alloc_dma_mem: "
		    "ddi_dma_addr_bind_handle failed: %d",
		    mac_name(rtlsp->mh), err);
		ddi_dma_mem_free(&dma_p->acc_hdl);
		ddi_dma_free_handle(&dma_p->dma_hdl);
		dma_p->acc_hdl = NULL;
		dma_p->dma_hdl = NULL;
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * rtls_free_dma_mem() -- free one allocated area of DMAable memory
 */
static void
rtls_free_dma_mem(dma_area_t *dma_p)
{
	if (dma_p->dma_hdl != NULL) {
		if (dma_p->ncookies) {
			(void) ddi_dma_unbind_handle(dma_p->dma_hdl);
			dma_p->ncookies = 0;
		}
		ddi_dma_free_handle(&dma_p->dma_hdl);
		dma_p->dma_hdl = NULL;
	}

	if (dma_p->acc_hdl != NULL) {
		ddi_dma_mem_free(&dma_p->acc_hdl);
		dma_p->acc_hdl = NULL;
	}
}

/*
 * rtls_alloc_bufs() -- allocate descriptors/buffers for this device instance
 */
static int
rtls_alloc_bufs(rtls_t *rtlsp)
{
	int i;
	int err;

	/*
	 * Allocate memory & handle for Tx buffers
	 */
	for (i = 0; i < RTLS_MAX_TX_DESC; i++) {
		err = rtls_alloc_dma_mem(rtlsp,
		    RTLS_TX_BUF_SIZE,
		    &rtls_buf_accattr,
		    DDI_DMA_WRITE | DDI_DMA_STREAMING,
		    &rtlsp->dma_area_tx[i]);

		if (err != DDI_SUCCESS)
			return (DDI_FAILURE);

		rtlsp->tx_buf[i] = (uint8_t *)rtlsp->dma_area_tx[i].mem_va;
	}

	/*
	 * Allocate memory & handle for Rx buffers
	 */
	err = rtls_alloc_dma_mem(rtlsp,
	    RTLS_RX_BUF_SIZE,
	    &rtls_buf_accattr,
	    DDI_DMA_READ | DDI_DMA_STREAMING,
	    &rtlsp->dma_area_rx);

	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);

	rtlsp->rx_ring = (uint8_t *)rtlsp->dma_area_rx.mem_va;

	return (DDI_SUCCESS);
}

/*
 * rtls_free_bufs() -- free descriptors/buffers allocated for this
 * device instance.
 */
static void
rtls_free_bufs(rtls_t *rtlsp)
{
	int i;

	for (i = 0; i < RTLS_MAX_TX_DESC; i++) {
		rtls_free_dma_mem(&rtlsp->dma_area_tx[i]);
		rtlsp->tx_buf[i] = NULL;
	}

	rtls_free_dma_mem(&rtlsp->dma_area_rx);
	rtlsp->rx_ring = NULL;
}

/*
 *    ========== Chip H/W Operation Routines ==========
 */

/*
 * rtls_chip_reset() -- reset chip
 */
static int
rtls_chip_reset(rtls_t *rtlsp, boolean_t quiesce)
{
	int i;
	uint16_t val16;
	uint8_t val8;

	/*
	 * Chip should be in STOP state
	 */
	val8 = rtls_reg_get8(rtlsp, RT_COMMAND_REG);
	val8 &= ~(RT_COMMAND_RX_ENABLE | RT_COMMAND_TX_ENABLE);
	rtls_reg_set8(rtlsp, RT_COMMAND_REG, val8);

	/*
	 * Disable interrupt
	 */
	val16 = rtls_reg_get16(rtlsp, RT_INT_MASK_REG);
	rtls_reg_set16(rtlsp, RT_INT_MASK_REG, val16 & (~RTLS_INT_MASK_ALL));
	rtlsp->int_mask = RTLS_INT_MASK_NONE;

	/*
	 * Clear pended interrupt
	 */
	val16 = rtls_reg_get16(rtlsp, RT_INT_STATUS_REG);
	rtls_reg_set16(rtlsp, RT_INT_STATUS_REG, val16);

	/*
	 * Reset chip
	 */
	val8 = rtls_reg_get8(rtlsp, RT_COMMAND_REG);
	rtls_reg_set8(rtlsp, RT_COMMAND_REG, val8 | RT_COMMAND_RESET);

	/*
	 * Wait for reset success
	 */
	i = 0;
	while (rtls_reg_get8(rtlsp, RT_COMMAND_REG) & RT_COMMAND_RESET) {
		if (++i > RTLS_RESET_WAIT_NUM) {
			/*
			 * At quiesce path we can't call cmn_err(), as
			 * it might block
			 */
			if (!quiesce)
				cmn_err(CE_WARN,
				    "%s: chip reset fail.",
				    mac_name(rtlsp->mh));
			return (DDI_FAILURE);
		}
		RTLS_RESET_WAIT_INTERVAL;
	}

	return (DDI_SUCCESS);
}

/*
 * rtls_chip_init() -- initialize the specified network board short of
 * actually starting the board.  Call after rtls_chip_reset().
 */
static void
rtls_chip_init(rtls_t *rtlsp)
{
	uint32_t val32;
	uint16_t val16;
	uint8_t val8;

	/*
	 * Initialize internal data structures
	 */
	rtlsp->cur_rx = 0;
	rtlsp->tx_current_desc = 0;
	rtlsp->tx_first_loop = 0;

	/*
	 * Set DMA physical rx/tx buffer address to register
	 */
	rtls_reg_set32(rtlsp, RX_BUFF_ADDR_REG,
	    (ulong_t)rtlsp->dma_area_rx.cookie.dmac_address);
	rtls_reg_set32(rtlsp, TX_ADDR_DESC0_REG,
	    (ulong_t)rtlsp->dma_area_tx[0].cookie.dmac_address);
	rtls_reg_set32(rtlsp, TX_ADDR_DESC1_REG,
	    (ulong_t)rtlsp->dma_area_tx[1].cookie.dmac_address);
	rtls_reg_set32(rtlsp, TX_ADDR_DESC2_REG,
	    (ulong_t)rtlsp->dma_area_tx[2].cookie.dmac_address);
	rtls_reg_set32(rtlsp, TX_ADDR_DESC3_REG,
	    (ulong_t)rtlsp->dma_area_tx[3].cookie.dmac_address);

	/*
	 * Start transmit/receive before set tx/rx configuration register
	 */
	val8 = rtls_reg_get8(rtlsp, RT_COMMAND_REG);
	rtls_reg_set8(rtlsp, RT_COMMAND_REG,
	    val8 | RT_COMMAND_RX_ENABLE | RT_COMMAND_TX_ENABLE);

	/*
	 * Set transmit configuration register
	 */
	val32 = rtls_reg_get32(rtlsp, TX_CONFIG_REG);
	val32 &= TX_CONSIG_REG_RESERVE;
	rtls_reg_set32(rtlsp, TX_CONFIG_REG, val32 | TX_CONFIG_DEFAULT);

	/*
	 * Set receive configuration register
	 */
	val32 = rtls_reg_get32(rtlsp, RX_CONFIG_REG);
	val32 &= RX_CONSIG_REG_RESERVE;
	if (rtlsp->promisc)
		val32 |= RX_ACCEPT_ALL_PACKET;
	rtls_reg_set32(rtlsp, RX_CONFIG_REG, val32 | RX_CONFIG_DEFAULT);

	/*
	 * Set multicast register
	 */
	rtls_reg_set32(rtlsp, MULTICAST_0_REG, rtlsp->multi_hash[0]);
	rtls_reg_set32(rtlsp, MULTICAST_4_REG, rtlsp->multi_hash[1]);

	/*
	 * Set unicast address
	 */
	rtls_set_mac_addr(rtlsp, rtlsp->netaddr);

	/*
	 * Set current address of packet read
	 */
	rtls_reg_set16(rtlsp, RX_CURRENT_READ_ADDR_REG, RX_READ_RESET_VAL);

	/*
	 * No early-rx interrupts
	 */
	val16 = rtls_reg_get16(rtlsp, RT_MUL_INTSEL_REG);
	val16 &= ~RT_MUL_INTSEL_BITS;
	rtls_reg_set16(rtlsp, RT_MUL_INTSEL_REG, val16);
}

/*
 * rtls_chip_start() -- start chip
 */
static void
rtls_chip_start(rtls_t *rtlsp)
{
	uint16_t val16;
	uint8_t val8;

	/*
	 * Start transmit/receive
	 */
	val8 = rtls_reg_get8(rtlsp, RT_COMMAND_REG);
	rtls_reg_set8(rtlsp, RT_COMMAND_REG,
	    val8 | RT_COMMAND_RX_ENABLE | RT_COMMAND_TX_ENABLE);

	/*
	 * Enable interrupt
	 */
	val16 = rtls_reg_get16(rtlsp, RT_INT_MASK_REG);
	rtls_reg_set16(rtlsp, RT_INT_MASK_REG, val16 | RTLS_INT_MASK);
	rtlsp->int_mask = RTLS_INT_MASK;
}

/*
 * rtls_chip_restart() -- restart chip
 */
static void
rtls_chip_restart(rtls_t *rtlsp)
{
	(void) rtls_chip_reset(rtlsp, B_FALSE);
	rtls_chip_init(rtlsp);
	rtls_chip_start(rtlsp);
}

/*
 * rtls_chip_stop() -- stop board receiving
 */
static void
rtls_chip_stop(rtls_t *rtlsp)
{
	uint16_t val16;
	uint8_t val8;

	/*
	 * Disable interrupt
	 */
	val16 = rtls_reg_get16(rtlsp, RT_INT_MASK_REG);
	rtls_reg_set16(rtlsp, RT_INT_MASK_REG, val16 & (~RTLS_INT_MASK_ALL));
	rtlsp->int_mask = RTLS_INT_MASK_NONE;

	/*
	 * Clear pended interrupt
	 */
	val16 = rtls_reg_get16(rtlsp, RT_INT_STATUS_REG);
	rtls_reg_set16(rtlsp, RT_INT_STATUS_REG, val16);

	/*
	 * Stop the board and disable transmit/receive
	 */
	val8 = rtls_reg_get8(rtlsp, RT_COMMAND_REG);
	val8 &= ~(RT_COMMAND_RX_ENABLE | RT_COMMAND_TX_ENABLE);
	rtls_reg_set8(rtlsp, RT_COMMAND_REG, val8);
}

/*
 * rtls_get_mac_addr() -- get the physical network address on the board
 */
static void
rtls_get_mac_addr(rtls_t *rtlsp, uint8_t *macaddr)
{
	uint32_t val32;

	/*
	 * Read first 4-byte of mac address
	 */
	val32 = rtls_reg_get32(rtlsp, ID_0_REG);
	macaddr[0] = val32 & 0xff;
	val32 = val32 >> 8;
	macaddr[1] = val32 & 0xff;
	val32 = val32 >> 8;
	macaddr[2] = val32 & 0xff;
	val32 = val32 >> 8;
	macaddr[3] = val32 & 0xff;

	/*
	 * Read last 2-byte of mac address
	 */
	val32 = rtls_reg_get32(rtlsp, ID_4_REG);
	macaddr[4] = val32 & 0xff;
	val32 = val32 >> 8;
	macaddr[5] = val32 & 0xff;
}

static void
rtls_set_mac_addr(rtls_t *rtlsp, const uint8_t *macaddr)
{
	uint32_t val32;
	uint8_t val8;

	/*
	 * Change to config register write enable mode
	 */
	val8 = rtls_reg_get8(rtlsp, RT_93c46_COMMAND_REG);
	val8 |= RT_93c46_MODE_CONFIG;
	rtls_reg_set8(rtlsp, RT_93c46_COMMAND_REG, val8);

	/*
	 * Get first 4 bytes of mac address
	 */
	val32 = macaddr[3];
	val32 = val32 << 8;
	val32 |= macaddr[2];
	val32 = val32 << 8;
	val32 |= macaddr[1];
	val32 = val32 << 8;
	val32 |= macaddr[0];

	/*
	 * Set first 4 bytes of mac address
	 */
	rtls_reg_set32(rtlsp, ID_0_REG, val32);

	/*
	 * Get last 2 bytes of mac address
	 */
	val32 = macaddr[5];
	val32 = val32 << 8;
	val32 |= macaddr[4];

	/*
	 * Set last 2 bytes of mac address
	 */
	val32 |= rtls_reg_get32(rtlsp, ID_4_REG) & ~0xffff;
	rtls_reg_set32(rtlsp, ID_4_REG, val32);

	/*
	 * Return to normal network/host communication mode
	 */
	val8 &= ~RT_93c46_MODE_CONFIG;
	rtls_reg_set8(rtlsp, RT_93c46_COMMAND_REG, val8);
}

static uint16_t
rtls_mii_read(void *arg, uint8_t phy, uint8_t reg)
{
	rtls_t		*rtlsp = arg;
	uint16_t	val;

	if (phy != 1) {
		return (0xffff);
	}
	switch (reg) {
	case MII_CONTROL:
		val = rtls_reg_get16(rtlsp, BASIC_MODE_CONTROL_REG);
		break;
	case MII_STATUS:
		val = rtls_reg_get16(rtlsp, BASIC_MODE_STATUS_REG);
		break;
	case MII_AN_ADVERT:
		val = rtls_reg_get16(rtlsp, AUTO_NEGO_AD_REG);
		break;
	case MII_AN_LPABLE:
		val = rtls_reg_get16(rtlsp, AUTO_NEGO_LP_REG);
		break;
	case MII_AN_EXPANSION:
		val = rtls_reg_get16(rtlsp, AUTO_NEGO_EXP_REG);
		break;
	case MII_VENDOR(0):
		/*
		 * We "simulate" a vendor private register so that the
		 * PHY layer can access it to determine detected link
		 * speed/duplex.
		 */
		val = rtls_reg_get8(rtlsp, MEDIA_STATUS_REG);
		break;
	case MII_PHYIDH:
	case MII_PHYIDL:
	default:
		val = 0;
		break;
	}
	return (val);
}

void
rtls_mii_write(void *arg, uint8_t phy, uint8_t reg, uint16_t val)
{
	rtls_t		*rtlsp = arg;
	uint8_t		val8;

	if (phy != 1) {
		return;
	}
	switch (reg) {
	case MII_CONTROL:
		/* Enable writes to all bits of BMCR */
		val8 = rtls_reg_get8(rtlsp, RT_93c46_COMMAND_REG);
		val8 |= RT_93c46_MODE_CONFIG;
		rtls_reg_set8(rtlsp, RT_93c46_COMMAND_REG, val8);
		/* write out the value */
		rtls_reg_set16(rtlsp, BASIC_MODE_CONTROL_REG, val);

		/* Return to normal network/host communication mode */
		val8 &= ~RT_93c46_MODE_CONFIG;
		rtls_reg_set8(rtlsp, RT_93c46_COMMAND_REG, val8);
		return;

	case MII_STATUS:
		rtls_reg_set16(rtlsp, BASIC_MODE_STATUS_REG, val);
		break;
	case MII_AN_ADVERT:
		rtls_reg_set16(rtlsp, AUTO_NEGO_AD_REG, val);
		break;
	case MII_AN_LPABLE:
		rtls_reg_set16(rtlsp, AUTO_NEGO_LP_REG, val);
		break;
	case MII_AN_EXPANSION:
		rtls_reg_set16(rtlsp, AUTO_NEGO_EXP_REG, val);
		break;
	case MII_PHYIDH:
	case MII_PHYIDL:
	default:
		/* these are not writable */
		break;
	}
}

void
rtls_mii_notify(void *arg, link_state_t link)
{
	rtls_t	*rtlsp = arg;

	mac_link_update(rtlsp->mh, link);
}

#ifdef RTLS_DEBUG
/*
 * rtls_reg_print() -- print out reg value(for debug use only)
 */
static void
rtls_reg_print(rtls_t *rtlsp)
{
	uint8_t val8;
	uint16_t val16;
	uint32_t val32;

	val8 = rtls_reg_get8(rtlsp, RT_COMMAND_REG);
	cmn_err(CE_NOTE, "%s: RT_COMMAND_REG = 0x%x",
	    mac_name(rtlsp->mh), val8);
	delay(drv_usectohz(1000));

	val16 = rtls_reg_get16(rtlsp, RT_INT_STATUS_REG);
	cmn_err(CE_NOTE, "%s: RT_INT_STATUS_REG = 0x%x",
	    mac_name(rtlsp->mh), val16);
	delay(drv_usectohz(1000));

	val16 = rtls_reg_get16(rtlsp, RT_INT_MASK_REG);
	cmn_err(CE_NOTE, "%s: RT_INT_MASK_REG = 0x%x",
	    mac_name(rtlsp->mh), val16);
	delay(drv_usectohz(1000));

	val32 = rtls_reg_get32(rtlsp, RX_CONFIG_REG);
	cmn_err(CE_NOTE, "%s: RX_CONFIG_REG = 0x%x",
	    mac_name(rtlsp->mh), val32);
	delay(drv_usectohz(1000));

	val16 = rtls_reg_get16(rtlsp, TX_DESC_STAUS_REG);
	cmn_err(CE_NOTE, "%s: TX_DESC_STAUS_REG = 0x%x, cur_desc = %d",
	    mac_name(rtlsp->mh), val16, rtlsp->tx_current_desc);
	delay(drv_usectohz(1000));

	val32 = rtls_reg_get32(rtlsp, TX_STATUS_DESC0_REG);
	cmn_err(CE_NOTE, "%s: TX_STATUS_DESC0_REG = 0x%x",
	    mac_name(rtlsp->mh), val32);
	delay(drv_usectohz(1000));

	val32 = rtls_reg_get32(rtlsp, TX_STATUS_DESC1_REG);
	cmn_err(CE_NOTE, "%s: TX_STATUS_DESC1_REG = 0x%x",
	    mac_name(rtlsp->mh), val32);
	delay(drv_usectohz(1000));

	val32 = rtls_reg_get32(rtlsp, TX_STATUS_DESC2_REG);
	cmn_err(CE_NOTE, "%s: TX_STATUS_DESC2_REG = 0x%x",
	    mac_name(rtlsp->mh), val32);
	delay(drv_usectohz(1000));

	val32 = rtls_reg_get32(rtlsp, TX_STATUS_DESC3_REG);
	cmn_err(CE_NOTE, "%s: TX_STATUS_DESC3_REG = 0x%x",
	    mac_name(rtlsp->mh), val32);
	delay(drv_usectohz(1000));

	cmn_err(CE_NOTE, "%s: in  = %llu, multicast = %llu, broadcast = %llu",
	    mac_name(rtlsp->mh),
	    (unsigned long long)rtlsp->stats.ipackets,
	    (unsigned long long)rtlsp->stats.multi_rcv,
	    (unsigned long long)rtlsp->stats.brdcst_rcv);
	delay(drv_usectohz(1000));
}
#endif
