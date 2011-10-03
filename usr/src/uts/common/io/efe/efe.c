/*
 * Copyright (c) 2010 Steven Stallion.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     1. Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *     2. Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials provided
 *        with the distribution.
 *     3. Neither the name of the copyright owner nor the names of any
 *        contributors may be used to endorse or promote products derived
 *        from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/byteorder.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/varargs.h>
#include <sys/cmn_err.h>
#include <sys/note.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/modctl.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/ddi_intr.h>
#include <sys/sunddi.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/pci.h>
#include <sys/ethernet.h>
#include <sys/vlan.h>
#include <sys/crc32.h>
#include <sys/mii.h>
#include <sys/mac.h>
#include <sys/mac_ether.h>
#include <sys/mac_provider.h>

#include "efe.h"

/* Autoconfiguration entry points */
static int	efe_attach(dev_info_t *, ddi_attach_cmd_t);
static int	efe_detach(dev_info_t *, ddi_detach_cmd_t);
static int	efe_quiesce(dev_info_t *);

/* MII entry points */
static uint16_t	efe_mii_read(void *, uint8_t, uint8_t);
static void	efe_mii_write(void *, uint8_t, uint8_t, uint16_t);
static void	efe_mii_notify(void *, link_state_t);

/* MAC entry points */
static int	efe_m_getstat(void *, uint_t, uint64_t *);
static int	efe_m_start(void *);
static void	efe_m_stop(void *);
static int	efe_m_setpromisc(void *, boolean_t);
static int	efe_m_multicst(void *, boolean_t, const uint8_t *);
static int	efe_m_unicst(void *, const uint8_t *);
static mblk_t	*efe_m_tx(void *, mblk_t *);
static int	efe_m_setprop(void *, const char *, mac_prop_id_t, uint_t,
    const void *);
static int	efe_m_getprop(void *, const char *, mac_prop_id_t, uint_t,
    void *);
static void	efe_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);

/* ISR/periodic callbacks */
static uint_t	efe_intr(caddr_t, caddr_t);

/* Support functions */
static void		efe_init(efe_t *);
static void		efe_init_rx_ring(efe_t *);
static void		efe_init_tx_ring(efe_t *);
static void		efe_reset(efe_t *);
static void		efe_start(efe_t *);
static void		efe_stop(efe_t *);
static void		efe_stop_dma(efe_t *);
static inline void	efe_restart(efe_t *);
static int		efe_suspend(efe_t *);
static int		efe_resume(efe_t *);

static efe_ring_t	*efe_ring_alloc(dev_info_t *, size_t);
static void		efe_ring_free(efe_ring_t **);
static efe_buf_t	*efe_buf_alloc(dev_info_t *, size_t);
static void		efe_buf_free(efe_buf_t **);

static void		efe_intr_enable(efe_t *);
static void		efe_intr_disable(efe_t *);

static mblk_t		*efe_recv(efe_t *);
static mblk_t		*efe_recv_pkt(efe_t *, efe_desc_t *);

static int		efe_send(efe_t *, mblk_t *);
static void		efe_send_done(efe_t *);

static void		efe_getaddr(efe_t *, uint8_t *);
static void		efe_setaddr(efe_t *, uint8_t *);
static void		efe_setmchash(efe_t *, uint16_t *);

static void		efe_eeprom_read(efe_t *, uint8_t *, size_t, uint8_t);
static uint16_t		efe_eeprom_readw(efe_t *, int, uint8_t);
static inline int	efe_eeprom_readbit(efe_t *);
static inline void	efe_eeprom_writebit(efe_t *, int);

static void		efe_dprintf(dev_info_t *, int, const char *, ...);

#ifdef DEBUG
#define	efe_debug(dip, ...) \
	efe_dprintf((dip), CE_CONT, __VA_ARGS__)
#else
#define	efe_debug(dip, ...)	/*EMPTY*/
#endif

#define	efe_error(dip, ...) \
	efe_dprintf((dip), CE_WARN, __VA_ARGS__)

extern struct mod_ops mod_driverops;

DDI_DEFINE_STREAM_OPS(efe_dev_ops, nulldev, nulldev, efe_attach, efe_detach,
    nodev, NULL, D_MP, NULL, efe_quiesce);

static struct modldrv modldrv = {
	&mod_driverops,			/* drv_modops */
	"EPIC/100 Fast Ethernet",	/* drv_linkinfo */
	&efe_dev_ops			/* drv_dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,		/* ml_rev */
	{ &modldrv, NULL }	/* ml_linkage */
};

static ddi_device_acc_attr_t efe_regs_acc_attr = {
	DDI_DEVICE_ATTR_V0,	/* devacc_attr_version */
	DDI_STRUCTURE_LE_ACC,	/* devacc_attr_endian_flags */
	DDI_STRICTORDER_ACC	/* devacc_attr_dataorder */
};

static ddi_device_acc_attr_t efe_buf_acc_attr = {
	DDI_DEVICE_ATTR_V0,	/* devacc_attr_version */
	DDI_NEVERSWAP_ACC,	/* devacc_attr_endian_flags */
	DDI_STRICTORDER_ACC	/* devacc_attr_dataorder */
};

static ddi_dma_attr_t efe_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0xFFFFFFFFUL,		/* dma_attr_addr_hi */
	0x7FFFFFFFUL,		/* dma_attr_count_max */
	4,			/* dma_attr_align */
	0x7F,			/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0xFFFFFFFFUL,		/* dma_attr_maxxfer */
	0xFFFFFFFFUL,		/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

static mii_ops_t efe_mii_ops = {
	MII_OPS_VERSION,	/* mii_version */
	efe_mii_read,		/* mii_read */
	efe_mii_write,		/* mii_write */
	efe_mii_notify		/* mii_notify */
};

static mac_callbacks_t efe_m_callbacks = {
	MC_SETPROP | MC_GETPROP,	/* mc_callbacks */
	efe_m_getstat,			/* mc_getstat */
	efe_m_start,			/* mc_start */
	efe_m_stop,			/* mc_stop */
	efe_m_setpromisc,		/* mc_setpromisc */
	efe_m_multicst,			/* mc_multicst */
	efe_m_unicst,			/* mc_unicst */
	efe_m_tx,			/* mc_tx */
	NULL,				/* mc_reserved */
	NULL,				/* mc_ioctl */
	NULL,				/* mc_getcapab */
	NULL,				/* mc_open */
	NULL,				/* mc_close */
	efe_m_setprop,			/* mc_setprop */
	efe_m_getprop,			/* mc_getprop */
	efe_m_propinfo			/* mc_propinfo */
};

static uint8_t efe_broadcast[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static uint16_t efe_mchash_promisc[] = {
	0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF
};

/*
 * Loadable module entry points.
 */
int
_init(void)
{
	int error;

	mac_init_ops(&efe_dev_ops, "efe");
	if ((error = mod_install(&modlinkage)) != DDI_SUCCESS) {
		mac_fini_ops(&efe_dev_ops);
	}

	return (error);
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) == DDI_SUCCESS) {
		mac_fini_ops(&efe_dev_ops);
	}

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Autoconfiguration entry points.
 */
int
efe_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	ddi_acc_handle_t pci;
	int types;
	int count;
	int actual;
	uint_t pri;
	efe_t *efep;
	mac_register_t *macp;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		efep = ddi_get_driver_private(dip);
		return (efe_resume(efep));

	default:
		return (DDI_FAILURE);
	}

	/*
	 * PCI configuration.
	 */
	if (pci_config_setup(dip, &pci) != DDI_SUCCESS) {
		efe_error(dip, "unable to setup PCI configuration!");
		return (DDI_FAILURE);
	}

	pci_config_put16(pci, PCI_CONF_COMM,
	    pci_config_get16(pci, PCI_CONF_COMM) | PCI_COMM_MAE | PCI_COMM_ME);

	pci_config_teardown(&pci);

	if (ddi_intr_get_supported_types(dip, &types)
	    != DDI_SUCCESS || !(types & DDI_INTR_TYPE_FIXED)) {
		efe_error(dip, "fixed interrupts not supported!");
		return (DDI_FAILURE);
	}

	if (ddi_intr_get_nintrs(dip, DDI_INTR_TYPE_FIXED, &count)
	    != DDI_SUCCESS || count != 1) {
		efe_error(dip, "no fixed interrupts available!");
		return (DDI_FAILURE);
	}

	/*
	 * Initialize soft state.
	 */
	efep = kmem_zalloc(sizeof (efe_t), KM_SLEEP);
	ddi_set_driver_private(dip, efep);

	efep->efe_dip = dip;

	if (ddi_regs_map_setup(dip, 1, (caddr_t *)&efep->efe_regs, 0, 0,
	    &efe_regs_acc_attr, &efep->efe_regs_acch) != DDI_SUCCESS) {
		efe_error(dip, "unable to setup register mapping!");
		goto failure;
	}

	efep->efe_rx_ring = efe_ring_alloc(efep->efe_dip, RXDESCL);
	if (efep->efe_rx_ring == NULL) {
		efe_error(efep->efe_dip, "unable to allocate rx ring!");
		goto failure;
	}

	efep->efe_tx_ring = efe_ring_alloc(efep->efe_dip, TXDESCL);
	if (efep->efe_tx_ring == NULL) {
		efe_error(efep->efe_dip, "unable to allocate tx ring!");
		goto failure;
	}

	if (ddi_intr_alloc(dip, &efep->efe_intrh, DDI_INTR_TYPE_FIXED, 0,
	    count, &actual, DDI_INTR_ALLOC_STRICT) != DDI_SUCCESS ||
	    actual != count) {
		efe_error(dip, "unable to allocate fixed interrupt!");
		goto failure;
	}

	if (ddi_intr_get_pri(efep->efe_intrh, &pri) != DDI_SUCCESS ||
	    pri >= ddi_intr_get_hilevel_pri()) {
		efe_error(dip, "unable to get valid interrupt priority!");
		goto failure;
	}

	mutex_init(&efep->efe_intrlock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(pri));

	mutex_init(&efep->efe_txlock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(pri));

	/*
	 * Initialize device.
	 */
	mutex_enter(&efep->efe_intrlock);
	mutex_enter(&efep->efe_txlock);

	efe_reset(efep);

	mutex_exit(&efep->efe_txlock);
	mutex_exit(&efep->efe_intrlock);

	/* Use factory address as default */
	efe_getaddr(efep, efep->efe_macaddr);

	/*
	 * Enable the ISR.
	 */
	if (ddi_intr_add_handler(efep->efe_intrh, efe_intr, efep, NULL)
	    != DDI_SUCCESS) {
		efe_error(dip, "unable to add interrupt handler!");
		goto failure;
	}

	if (ddi_intr_enable(efep->efe_intrh) != DDI_SUCCESS) {
		efe_error(dip, "unable to enable interrupt!");
		goto failure;
	}

	/*
	 * Allocate MII resources.
	 */
	if ((efep->efe_miih = mii_alloc(efep, dip, &efe_mii_ops)) == NULL) {
		efe_error(dip, "unable to allocate mii resources!");
		goto failure;
	}

	/*
	 * Allocate MAC resources.
	 */
	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		efe_error(dip, "unable to allocate mac resources!");
		goto failure;
	}

	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = efep;
	macp->m_dip = dip;
	macp->m_src_addr = efep->efe_macaddr;
	macp->m_callbacks = &efe_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = ETHERMTU;
	macp->m_margin = VLAN_TAGSZ;

	if (mac_register(macp, &efep->efe_mh) != 0) {
		efe_error(dip, "unable to register with mac!");
		goto failure;
	}
	mac_free(macp);

	ddi_report_dev(dip);

	return (DDI_SUCCESS);

failure:
	if (macp != NULL) {
		mac_free(macp);
	}

	if (efep->efe_miih != NULL) {
		mii_free(efep->efe_miih);
	}

	if (efep->efe_intrh != NULL) {
		(void) ddi_intr_disable(efep->efe_intrh);
		(void) ddi_intr_remove_handler(efep->efe_intrh);
		(void) ddi_intr_free(efep->efe_intrh);
	}

	mutex_destroy(&efep->efe_txlock);
	mutex_destroy(&efep->efe_intrlock);

	if (efep->efe_tx_ring != NULL) {
		efe_ring_free(&efep->efe_tx_ring);
	}
	if (efep->efe_rx_ring != NULL) {
		efe_ring_free(&efep->efe_rx_ring);
	}

	if (efep->efe_regs_acch != NULL) {
		ddi_regs_map_free(&efep->efe_regs_acch);
	}

	kmem_free(efep, sizeof (efe_t));

	return (DDI_FAILURE);
}

int
efe_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	efe_t *efep = ddi_get_driver_private(dip);

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		return (efe_suspend(efep));

	default:
		return (DDI_FAILURE);
	}

	if (mac_unregister(efep->efe_mh) != 0) {
		efe_error(dip, "unable to unregister from mac!");
		return (DDI_FAILURE);
	}

	mii_free(efep->efe_miih);

	(void) ddi_intr_disable(efep->efe_intrh);
	(void) ddi_intr_remove_handler(efep->efe_intrh);
	(void) ddi_intr_free(efep->efe_intrh);

	mutex_destroy(&efep->efe_txlock);
	mutex_destroy(&efep->efe_intrlock);

	if (efep->efe_tx_ring != NULL) {
		efe_ring_free(&efep->efe_tx_ring);
	}
	if (efep->efe_rx_ring != NULL) {
		efe_ring_free(&efep->efe_rx_ring);
	}

	ddi_regs_map_free(&efep->efe_regs_acch);

	kmem_free(efep, sizeof (efe_t));

	return (DDI_SUCCESS);
}

int
efe_quiesce(dev_info_t *dip)
{
	efe_t *efep = ddi_get_driver_private(dip);

	PUTCSR(efep, CSR_GENCTL, GENCTL_RESET);
	drv_usecwait(RESET_DELAY);

	PUTCSR(efep, CSR_GENCTL, GENCTL_PWRDWN);

	return (DDI_SUCCESS);
}

/*
 * MII entry points.
 */
uint16_t
efe_mii_read(void *arg, uint8_t phy, uint8_t reg)
{
	efe_t *efep = arg;

	PUTCSR(efep, CSR_MMCTL, MMCTL_READ |
	    reg << MMCTL_PHYREG | phy << MMCTL_PHYADDR);

	for (int i = 0; i < MII_DELAY_CYCLES; ++i) {
		if (!(GETCSR(efep, CSR_MMCTL) & MMCTL_READ)) {
			return ((uint16_t)GETCSR(efep, CSR_MMDATA));
		}
		drv_usecwait(MII_DELAY);
	}
	efe_error(efep->efe_dip, "timed out reading from MII!");

	return (0);
}

void
efe_mii_write(void *arg, uint8_t phy, uint8_t reg, uint16_t data)
{
	efe_t *efep = arg;

	PUTCSR(efep, CSR_MMDATA, data);

	PUTCSR(efep, CSR_MMCTL, MMCTL_WRITE |
	    reg << MMCTL_PHYREG | phy << MMCTL_PHYADDR);

	for (int i = 0; i < MII_DELAY_CYCLES; ++i) {
		if (!(GETCSR(efep, CSR_MMCTL) & MMCTL_WRITE)) {
			return;
		}
		drv_usecwait(MII_DELAY);
	}
	efe_error(efep->efe_dip, "timed out writing to MII!");
}

void
efe_mii_notify(void *arg, link_state_t link)
{
	efe_t *efep = arg;

	mac_link_update(efep->efe_mh, link);
}

/*
 * MAC entry points.
 */
int
efe_m_getstat(void *arg, uint_t stat, uint64_t *val)
{
	efe_t *efep = arg;

	if (mii_m_getstat(efep->efe_miih, stat, val) == 0) {
		return (0);
	}

	switch (stat) {
	case MAC_STAT_MULTIRCV:
		*val = efep->efe_multircv;
		break;

	case MAC_STAT_BRDCSTRCV:
		*val = efep->efe_brdcstrcv;
		break;

	case MAC_STAT_MULTIXMT:
		*val = efep->efe_multixmt;
		break;

	case MAC_STAT_BRDCSTXMT:
		*val = efep->efe_brdcstxmt;
		break;

	case MAC_STAT_NORCVBUF:
		*val = efep->efe_norcvbuf;
		break;

	case MAC_STAT_IERRORS:
		*val = efep->efe_ierrors;
		break;

	case MAC_STAT_NOXMTBUF:
		*val = efep->efe_noxmtbuf;
		break;

	case MAC_STAT_OERRORS:
		*val = efep->efe_oerrors;
		break;

	case MAC_STAT_COLLISIONS:
		*val = efep->efe_collisions;
		break;

	case MAC_STAT_RBYTES:
		*val = efep->efe_rbytes;
		break;

	case MAC_STAT_IPACKETS:
		*val = efep->efe_ipackets;
		break;

	case MAC_STAT_OBYTES:
		*val = efep->efe_obytes;
		break;

	case MAC_STAT_OPACKETS:
		*val = efep->efe_opackets;
		break;

	case MAC_STAT_UNDERFLOWS:
		*val = efep->efe_uflo;
		break;

	case MAC_STAT_OVERFLOWS:
		*val = efep->efe_oflo;
		break;

	case ETHER_STAT_ALIGN_ERRORS:
		*val = efep->efe_align_errors;
		break;

	case ETHER_STAT_FCS_ERRORS:
		*val = efep->efe_fcs_errors;
		break;

	case ETHER_STAT_FIRST_COLLISIONS:
		*val = efep->efe_first_collisions;
		break;

	case ETHER_STAT_TX_LATE_COLLISIONS:
		*val = efep->efe_tx_late_collisions;
		break;

	case ETHER_STAT_DEFER_XMTS:
		*val = efep->efe_defer_xmts;
		break;

	case ETHER_STAT_EX_COLLISIONS:
		*val = efep->efe_ex_collisions;
		break;

	case ETHER_STAT_MACXMT_ERRORS:
		*val = efep->efe_macxmt_errors;
		break;

	case ETHER_STAT_CARRIER_ERRORS:
		*val = efep->efe_carrier_errors;
		break;

	case ETHER_STAT_TOOLONG_ERRORS:
		*val = efep->efe_toolong_errors;
		break;

	case ETHER_STAT_MACRCV_ERRORS:
		*val = efep->efe_macrcv_errors;
		break;

	case ETHER_STAT_TOOSHORT_ERRORS:
		*val = efep->efe_runt_errors;
		break;

	case ETHER_STAT_JABBER_ERRORS:
		*val = efep->efe_jabber_errors;
		break;

	default:
		return (ENOTSUP);
	}

	return (0);
}

int
efe_m_start(void *arg)
{
	efe_t *efep = arg;

	mutex_enter(&efep->efe_intrlock);
	mutex_enter(&efep->efe_txlock);

	efe_start(efep);
	efep->efe_flags |= FLAG_RUNNING;

	mutex_exit(&efep->efe_txlock);
	mutex_exit(&efep->efe_intrlock);

	mii_start(efep->efe_miih);

	return (0);
}

void
efe_m_stop(void *arg)
{
	efe_t *efep = arg;

	mutex_enter(&efep->efe_intrlock);
	mutex_enter(&efep->efe_txlock);

	efe_stop(efep);
	efep->efe_flags &= ~FLAG_RUNNING;

	mutex_exit(&efep->efe_txlock);
	mutex_exit(&efep->efe_intrlock);

	mii_stop(efep->efe_miih);
}

int
efe_m_setpromisc(void *arg, boolean_t on)
{
	efe_t *efep = arg;

	mutex_enter(&efep->efe_intrlock);
	mutex_enter(&efep->efe_txlock);

	if (efep->efe_flags & FLAG_SUSPENDED) {
		mutex_exit(&efep->efe_txlock);
		mutex_exit(&efep->efe_intrlock);
		return (0);
	}

	efep->efe_promisc = on;

	if (efep->efe_flags & FLAG_RUNNING) {
		efe_restart(efep);
	}

	mutex_exit(&efep->efe_txlock);
	mutex_exit(&efep->efe_intrlock);

	return (0);
}

int
efe_m_multicst(void *arg, boolean_t add, const uint8_t *macaddr)
{
	efe_t *efep = arg;
	uint32_t val;
	int index;
	int bit;
	boolean_t restart = B_FALSE;

	mutex_enter(&efep->efe_intrlock);
	mutex_enter(&efep->efe_txlock);

	if (efep->efe_flags & FLAG_SUSPENDED) {
		mutex_exit(&efep->efe_txlock);
		mutex_exit(&efep->efe_intrlock);
		return (0);
	}

	CRC32(val, macaddr, ETHERADDRL, -1U, crc32_table);
	val %= MCHASHL;

	index = val / MCHASHSZ;
	bit = 1U << (val % MCHASHSZ);

	if (add) {
		efep->efe_mccount[val]++;
		if (efep->efe_mccount[val] == 1) {
			efep->efe_mchash[index] |= bit;
			restart = B_TRUE;
		}

	} else {
		efep->efe_mccount[val]--;
		if (efep->efe_mccount[val] == 0) {
			efep->efe_mchash[index] &= ~bit;
			restart = B_TRUE;
		}
	}

	if (restart && efep->efe_flags & FLAG_RUNNING) {
		efe_restart(efep);
	}

	mutex_exit(&efep->efe_txlock);
	mutex_exit(&efep->efe_intrlock);

	return (0);
}

int
efe_m_unicst(void *arg, const uint8_t *macaddr)
{
	efe_t *efep = arg;

	mutex_enter(&efep->efe_intrlock);
	mutex_enter(&efep->efe_txlock);

	if (efep->efe_flags & FLAG_SUSPENDED) {
		mutex_exit(&efep->efe_txlock);
		mutex_exit(&efep->efe_intrlock);
		return (0);
	}

	bcopy(macaddr, efep->efe_macaddr, ETHERADDRL);

	if (efep->efe_flags & FLAG_RUNNING) {
		efe_restart(efep);
	}

	mutex_exit(&efep->efe_txlock);
	mutex_exit(&efep->efe_intrlock);

	return (0);
}

mblk_t *
efe_m_tx(void *arg, mblk_t *mp)
{
	efe_t *efep = arg;

	mutex_enter(&efep->efe_txlock);

	if (efep->efe_flags & FLAG_SUSPENDED) {
		mutex_exit(&efep->efe_txlock);
		return (mp);
	}

	while (mp != NULL) {
		mblk_t *tmp = mp->b_next;
		mp->b_next = NULL;

		if (efe_send(efep, mp) != DDI_SUCCESS) {
			mp->b_next = tmp;
			break;
		}
		mp = tmp;
	}

	/* Kick the transmitter */
	PUTCSR(efep, CSR_COMMAND, COMMAND_TXQUEUED);

	mutex_exit(&efep->efe_txlock);

	return (mp);
}

int
efe_m_setprop(void *arg, const char *name, mac_prop_id_t id,
    uint_t valsize, const void *val)
{
	efe_t *efep = arg;

	return (mii_m_setprop(efep->efe_miih, name, id, valsize, val));
}

int
efe_m_getprop(void *arg, const char *name, mac_prop_id_t id,
    uint_t valsize, void *val)
{
	efe_t *efep = arg;

	return (mii_m_getprop(efep->efe_miih, name, id, valsize, val));
}

void
efe_m_propinfo(void *arg, const char *name, mac_prop_id_t id,
    mac_prop_info_handle_t state)
{
	efe_t *efep = arg;

	mii_m_propinfo(efep->efe_miih, name, id, state);
}

/*
 * ISR/periodic callbacks.
 */
uint_t
efe_intr(caddr_t arg1, caddr_t arg2)
{
	efe_t *efep = (void *)arg1;
	uint32_t status;
	mblk_t *mp = NULL;

	_NOTE(ARGUNUSED(arg2));

	mutex_enter(&efep->efe_intrlock);

	if (efep->efe_flags & FLAG_SUSPENDED) {
		mutex_exit(&efep->efe_intrlock);
		return (DDI_INTR_UNCLAIMED);
	}

	status = GETCSR(efep, CSR_INTSTAT);
	if (!(status & INTSTAT_ACTV)) {
		mutex_exit(&efep->efe_intrlock);
		return (DDI_INTR_UNCLAIMED);
	}
	PUTCSR(efep, CSR_INTSTAT, status);

	if (status & INTSTAT_RCC) {
		mp = efe_recv(efep);
	}

	if (status & INTSTAT_RQE) {
		efep->efe_ierrors++;
		efep->efe_macrcv_errors++;

		/* Kick the receiver */
		PUTCSR(efep, CSR_COMMAND, COMMAND_RXQUEUED);
	}

	if (status & INTSTAT_TXC) {
		mutex_enter(&efep->efe_txlock);

		efe_send_done(efep);

		mutex_exit(&efep->efe_txlock);
	}

	if (status & INTSTAT_FATAL) {
		mutex_enter(&efep->efe_txlock);

		efe_error(efep->efe_dip, "bus error; resetting!");
		efe_restart(efep);

		mutex_exit(&efep->efe_txlock);
	}

	mutex_exit(&efep->efe_intrlock);

	if (mp != NULL) {
		mac_rx(efep->efe_mh, NULL, mp);
	}

	if (status & INTSTAT_TXC) {
		mac_tx_update(efep->efe_mh);
	}

	if (status & INTSTAT_FATAL) {
		mii_reset(efep->efe_miih);
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * Support functions.
 */
void
efe_init(efe_t *efep)
{
	uint32_t val;

	ASSERT(mutex_owned(&efep->efe_intrlock));
	ASSERT(mutex_owned(&efep->efe_txlock));

	efe_reset(efep);

	val = GENCTL_ONECOPY | GENCTL_RFT_128 | GENCTL_MRM;
#ifdef _BIG_ENDIAN
	val |= GENCTL_BE;
#endif	/* _BIG_ENDIAN */

	PUTCSR(efep, CSR_GENCTL, val);
	PUTCSR(efep, CSR_PBLCNT, BURSTLEN);

	efe_init_rx_ring(efep);
	efe_init_tx_ring(efep);

	efe_setaddr(efep, efep->efe_macaddr);

	if (efep->efe_promisc) {
		efe_setmchash(efep, efe_mchash_promisc);
	} else {
		efe_setmchash(efep, efep->efe_mchash);
	}
}

void
efe_init_rx_ring(efe_t *efep)
{
	efe_ring_t *rp;

	ASSERT(mutex_owned(&efep->efe_intrlock));

	rp = efep->efe_rx_ring;

	for (int i = 0; i < DESCLEN(rp); ++i) {
		efe_desc_t *dp = GETDESC(rp, i);
		efe_buf_t *bp = GETBUF(rp, i);

		PUTDESC16(rp, &dp->d_status, RXSTAT_OWNER);
		PUTDESC16(rp, &dp->d_len, 0);
		PUTDESC32(rp, &dp->d_bufaddr, BUFADDR(bp));
		PUTDESC16(rp, &dp->d_buflen, BUFLEN(bp));
		PUTDESC16(rp, &dp->d_control, 0);
		PUTDESC32(rp, &dp->d_next, NEXTDESCADDR(rp, i));

		SYNCDESC(rp, i, DDI_DMA_SYNC_FORDEV);
	}

	efep->efe_rx_desc = 0;

	PUTCSR(efep, CSR_PRCDAR, DESCADDR(rp, 0));
}

void
efe_init_tx_ring(efe_t *efep)
{
	efe_ring_t *rp;

	ASSERT(mutex_owned(&efep->efe_txlock));

	rp = efep->efe_tx_ring;

	for (int i = 0; i < DESCLEN(rp); ++i) {
		efe_desc_t *dp = GETDESC(rp, i);
		efe_buf_t *bp = GETBUF(rp, i);

		PUTDESC16(rp, &dp->d_status, 0);
		PUTDESC16(rp, &dp->d_len, 0);
		PUTDESC32(rp, &dp->d_bufaddr, BUFADDR(bp));
		PUTDESC16(rp, &dp->d_buflen, BUFLEN(bp));
		PUTDESC16(rp, &dp->d_control, 0);
		PUTDESC32(rp, &dp->d_next, NEXTDESCADDR(rp, i));

		SYNCDESC(rp, i, DDI_DMA_SYNC_FORDEV);
	}

	efep->efe_tx_desc = 0;
	efep->efe_tx_sent = 0;

	PUTCSR(efep, CSR_PTCDAR, DESCADDR(rp, 0));
}

void
efe_reset(efe_t *efep)
{
	ASSERT(mutex_owned(&efep->efe_intrlock));
	ASSERT(mutex_owned(&efep->efe_txlock));

	PUTCSR(efep, CSR_GENCTL, GENCTL_RESET);
	drv_usecwait(RESET_DELAY);

	/* Assert internal clock source (AN 7.15) */
	for (int i = 0; i < RESET_TEST_CYCLES; ++i) {
		PUTCSR(efep, CSR_TEST, TEST_CLOCK);
	}
}

void
efe_start(efe_t *efep)
{
	ASSERT(mutex_owned(&efep->efe_intrlock));
	ASSERT(mutex_owned(&efep->efe_txlock));

	efe_init(efep);

	PUTCSR(efep, CSR_RXCON,
	    RXCON_SEP | RXCON_RRF | RXCON_RBF | RXCON_RMF |
	    (efep->efe_promisc ? RXCON_PROMISC : 0));

	PUTCSR(efep, CSR_TXCON, TXCON_LB_3);

	efe_intr_enable(efep);

	SETBIT(efep, CSR_COMMAND,
	    COMMAND_START_RX | COMMAND_RXQUEUED);
}

void
efe_stop(efe_t *efep)
{
	ASSERT(mutex_owned(&efep->efe_intrlock));
	ASSERT(mutex_owned(&efep->efe_txlock));

	efe_intr_disable(efep);

	PUTCSR(efep, CSR_COMMAND, COMMAND_STOP_RX);

	efe_stop_dma(efep);

	PUTCSR(efep, CSR_GENCTL, GENCTL_RESET);
	drv_usecwait(RESET_DELAY);

	PUTCSR(efep, CSR_GENCTL, GENCTL_PWRDWN);
}

void
efe_stop_dma(efe_t *efep)
{
	ASSERT(mutex_owned(&efep->efe_intrlock));
	ASSERT(mutex_owned(&efep->efe_txlock));

	PUTCSR(efep, CSR_COMMAND,
	    COMMAND_STOP_RDMA | COMMAND_STOP_TDMA);

	for (int i = 0; i < STOP_DELAY_CYCLES; ++i) {
		uint32_t status = GETCSR(efep, CSR_INTSTAT);
		if (status & INTSTAT_RXIDLE &&
		    status & INTSTAT_TXIDLE) {
			return;
		}
		drv_usecwait(STOP_DELAY);
	}
	efe_error(efep->efe_dip, "timed out stopping DMA engine!");
}

static inline void
efe_restart(efe_t *efep)
{
	efe_stop(efep);
	efe_start(efep);
}

int
efe_suspend(efe_t *efep)
{
	mutex_enter(&efep->efe_intrlock);
	mutex_enter(&efep->efe_txlock);

	if (efep->efe_flags & FLAG_RUNNING) {
		efe_stop(efep);
	}
	efep->efe_flags |= FLAG_SUSPENDED;

	mutex_exit(&efep->efe_txlock);
	mutex_exit(&efep->efe_intrlock);

	mii_suspend(efep->efe_miih);

	return (DDI_SUCCESS);
}

int
efe_resume(efe_t *efep)
{
	mutex_enter(&efep->efe_intrlock);
	mutex_enter(&efep->efe_txlock);

	if (efep->efe_flags & FLAG_RUNNING) {
		efe_start(efep);
	}
	efep->efe_flags &= ~FLAG_SUSPENDED;

	mutex_exit(&efep->efe_txlock);
	mutex_exit(&efep->efe_intrlock);

	mii_resume(efep->efe_miih);

	return (DDI_SUCCESS);
}

efe_ring_t *
efe_ring_alloc(dev_info_t *dip, size_t len)
{
	efe_ring_t *rp;
	size_t rlen;
	uint_t ccount;

	ASSERT(len > 1);

	rp = kmem_zalloc(sizeof (efe_ring_t), KM_SLEEP);
	rp->r_len = len;

	if (ddi_dma_alloc_handle(dip, &efe_dma_attr, DDI_DMA_SLEEP, NULL,
	    &rp->r_dmah) != DDI_SUCCESS) {
		efe_error(dip, "unable to allocate DMA handle!");
		goto failure;
	}

	if (ddi_dma_mem_alloc(rp->r_dmah, DESCSZ(len), &efe_buf_acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, (caddr_t *)&rp->r_descp,
	    &rlen, &rp->r_acch) != DDI_SUCCESS) {
		efe_error(dip, "unable to allocate descriptors!");
		goto failure;
	}

	if (ddi_dma_addr_bind_handle(rp->r_dmah, NULL, (caddr_t)rp->r_descp,
	    DESCSZ(len), DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
	    NULL, &rp->r_dmac, &ccount) != DDI_DMA_MAPPED) {
		efe_error(dip, "unable to bind DMA handle to descriptors!");
		goto failure;
	}

	rp->r_bufpp = kmem_zalloc(BUFPSZ(len), KM_SLEEP);

	for (int i = 0; i < len; ++i) {
		efe_buf_t *bp = efe_buf_alloc(dip, BUFSZ);
		if (bp == NULL) {
			goto failure;
		}
		rp->r_bufpp[i] = bp;
	}

	return (rp);

failure:
	efe_ring_free(&rp);

	return (NULL);
}

void
efe_ring_free(efe_ring_t **rpp)
{
	efe_ring_t *rp = *rpp;

	ASSERT(rp != NULL);

	for (int i = 0; i < DESCLEN(rp); ++i) {
		efe_buf_t *bp = GETBUF(rp, i);
		if (bp != NULL) {
			efe_buf_free(&bp);
		}
	}
	kmem_free(rp->r_bufpp, BUFPSZ(DESCLEN(rp)));

	if (rp->r_descp != NULL) {
		(void) ddi_dma_unbind_handle(rp->r_dmah);
	}
	if (rp->r_acch != NULL) {
		ddi_dma_mem_free(&rp->r_acch);
	}
	if (rp->r_dmah != NULL) {
		ddi_dma_free_handle(&rp->r_dmah);
	}
	kmem_free(rp, sizeof (efe_ring_t));

	*rpp = NULL;
}

efe_buf_t *
efe_buf_alloc(dev_info_t *dip, size_t len)
{
	efe_buf_t *bp;
	size_t rlen;
	uint_t ccount;

	bp = kmem_zalloc(sizeof (efe_buf_t), KM_SLEEP);
	bp->b_len = len;

	if (ddi_dma_alloc_handle(dip, &efe_dma_attr, DDI_DMA_SLEEP, NULL,
	    &bp->b_dmah) != DDI_SUCCESS) {
		efe_error(dip, "unable to allocate DMA handle!");
		goto failure;
	}

	if (ddi_dma_mem_alloc(bp->b_dmah, len, &efe_buf_acc_attr,
	    DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL, &bp->b_kaddr, &rlen,
	    &bp->b_acch) != DDI_SUCCESS) {
		efe_error(dip, "unable to allocate buffer!");
		goto failure;
	}

	if (ddi_dma_addr_bind_handle(bp->b_dmah, NULL, bp->b_kaddr,
	    len, DDI_DMA_RDWR | DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL,
	    &bp->b_dmac, &ccount) != DDI_DMA_MAPPED) {
		efe_error(dip, "unable to bind DMA handle to buffer!");
		goto failure;
	}

	return (bp);

failure:
	efe_buf_free(&bp);

	return (NULL);
}

void
efe_buf_free(efe_buf_t **bpp)
{
	efe_buf_t *bp = *bpp;

	ASSERT(bp != NULL);

	if (bp->b_kaddr != NULL) {
		(void) ddi_dma_unbind_handle(bp->b_dmah);
	}
	if (bp->b_acch != NULL) {
		ddi_dma_mem_free(&bp->b_acch);
	}
	if (bp->b_dmah != NULL) {
		ddi_dma_free_handle(&bp->b_dmah);
	}
	kmem_free(bp, sizeof (efe_buf_t));

	*bpp = NULL;
}

void
efe_intr_enable(efe_t *efep)
{
	PUTCSR(efep, CSR_INTMASK,
	    INTMASK_RCC | INTMASK_RQE | INTMASK_TXC | INTMASK_FATAL);

	SETBIT(efep, CSR_GENCTL, GENCTL_INT);
}

void
efe_intr_disable(efe_t *efep)
{
	PUTCSR(efep, CSR_INTMASK, 0);

	CLRBIT(efep, CSR_GENCTL, GENCTL_INT);
}

mblk_t *
efe_recv(efe_t *efep)
{
	efe_ring_t *rp;
	mblk_t *mp = NULL;
	mblk_t **mpp = &mp;

	ASSERT(mutex_owned(&efep->efe_intrlock));

	rp = efep->efe_rx_ring;

	for (;;) {
		efe_desc_t *dp;
		uint16_t status;

		dp = GETDESC(rp, efep->efe_rx_desc);
		SYNCDESC(rp, efep->efe_rx_desc, DDI_DMA_SYNC_FORKERNEL);

		status = GETDESC16(rp, &dp->d_status);

		/* Stop if device owns descriptor */
		if (status & RXSTAT_OWNER) {
			break;
		}

		if (status & RXSTAT_PRI) {
			mblk_t *tmp = efe_recv_pkt(efep, dp);
			if (tmp != NULL) {
				*mpp = tmp;
				mpp = &tmp->b_next;
			}

		} else {
			efep->efe_ierrors++;

			if (status & RXSTAT_FAE) {
				efep->efe_align_errors++;
			}
			if (status & RXSTAT_CRC) {
				efep->efe_fcs_errors++;
			}
			if (status & RXSTAT_MP) {
				efep->efe_oflo++;
			}
		}

		/* Release ownership to device */
		PUTDESC16(rp, &dp->d_status, RXSTAT_OWNER);

		SYNCDESC(rp, efep->efe_rx_desc, DDI_DMA_SYNC_FORDEV);

		efep->efe_rx_desc = NEXTDESC(rp, efep->efe_rx_desc);
	}

	return (mp);
}

mblk_t *
efe_recv_pkt(efe_t *efep, efe_desc_t *dp)
{
	efe_ring_t *rp;
	efe_buf_t *bp;
	uint16_t len;
	mblk_t *mp;
	uint16_t status;

	ASSERT(mutex_owned(&efep->efe_intrlock));

	rp = efep->efe_rx_ring;

	len = GETDESC16(rp, &dp->d_len) - ETHERFCSL;

	if (len < ETHERMIN) {
		efep->efe_ierrors++;
		efep->efe_runt_errors++;
		return (NULL);
	}

	if (len > ETHERMAX + VLAN_TAGSZ) {
		efep->efe_ierrors++;
		efep->efe_toolong_errors++;
		return (NULL);
	}

	mp = allocb(len, 0);
	if (mp == NULL) {
		efep->efe_ierrors++;
		efep->efe_norcvbuf++;
		return (NULL);
	}
	mp->b_wptr = mp->b_rptr + len;

	bp = GETBUF(rp, efep->efe_rx_desc);
	SYNCBUF(bp, DDI_DMA_SYNC_FORKERNEL);

	bcopy(bp->b_kaddr, mp->b_rptr, len);

	efep->efe_ipackets++;
	efep->efe_rbytes += len;

	status = GETDESC16(rp, &dp->d_status);

	if (status & RXSTAT_BAR) {
		efep->efe_brdcstrcv++;

	} else if (status & RXSTAT_MAR) {
		efep->efe_multircv++;
	}

	return (mp);
}

int
efe_send(efe_t *efep, mblk_t *mp)
{
	efe_ring_t *rp;
	uint16_t len;
	efe_desc_t *dp;
	uint16_t status;
	efe_buf_t *bp;

	ASSERT(mutex_owned(&efep->efe_txlock));

	rp = efep->efe_tx_ring;

	len = msgsize(mp);

	if (len > ETHERMAX + VLAN_TAGSZ) {
		efep->efe_oerrors++;
		efep->efe_macxmt_errors++;
		freemsg(mp);
		return (DDI_SUCCESS);
	}

	dp = GETDESC(rp, efep->efe_tx_desc);
	SYNCDESC(rp, efep->efe_tx_desc, DDI_DMA_SYNC_FORKERNEL);

	status = GETDESC16(efep->efe_tx_ring, &dp->d_status);

	/* Stop if device owns descriptor */
	if (status & TXSTAT_OWNER) {
		return (DDI_FAILURE);
	}

	bp = GETBUF(rp, efep->efe_tx_desc);

	mcopymsg(mp, bp->b_kaddr);

	/*
	 * Packets must contain at least ETHERMIN octets.
	 * Padded octets are zeroed out prior to sending.
	 */
	if (len < ETHERMIN) {
		bzero(bp->b_kaddr + len, ETHERMIN - len);
		len = ETHERMIN;
	}

	SYNCBUF(bp, DDI_DMA_SYNC_FORDEV);

	PUTDESC16(rp, &dp->d_status, TXSTAT_OWNER);
	PUTDESC16(rp, &dp->d_len, len);
	PUTDESC16(rp, &dp->d_control, TXCTL_LASTDESCR);

	SYNCDESC(rp, efep->efe_tx_desc, DDI_DMA_SYNC_FORDEV);

	efep->efe_opackets++;
	efep->efe_obytes += len;

	if (*bp->b_kaddr & 0x01) {
		if (bcmp(bp->b_kaddr, efe_broadcast, ETHERADDRL) == 0) {
			efep->efe_brdcstxmt++;
		} else {
			efep->efe_multixmt++;
		}
	}

	efep->efe_tx_desc = NEXTDESC(rp, efep->efe_tx_desc);

	return (DDI_SUCCESS);
}

void
efe_send_done(efe_t *efep)
{
	efe_ring_t *rp;

	ASSERT(mutex_owned(&efep->efe_txlock));

	rp = efep->efe_tx_ring;

	for (;;) {
		efe_desc_t *dp;
		uint16_t status;

		dp = GETDESC(rp, efep->efe_tx_sent);
		SYNCDESC(rp, efep->efe_tx_sent, DDI_DMA_SYNC_FORKERNEL);

		status = GETDESC16(rp, &dp->d_status);

		/* Stop if device owns descriptor */
		if (status & TXSTAT_OWNER) {
			break;
		}

		if (status & TXSTAT_PTX) {
			if (!(status & TXSTAT_ND)) {
				efep->efe_defer_xmts++;
			}
			if (status & TXSTAT_COLL) {
				efep->efe_first_collisions++;
			}

		} else {
			efep->efe_oerrors++;

			if (status & TXSTAT_CSL) {
				efep->efe_carrier_errors++;
			}
			if (status & TXSTAT_UFLO) {
				efep->efe_uflo++;
			}
			if (status & TXSTAT_OWC) {
				efep->efe_tx_late_collisions++;
			}
			if (status & TXSTAT_DEFER) {
				efep->efe_jabber_errors++;
			}
			if (status & TXSTAT_EXCOLL) {
				efep->efe_ex_collisions++;
			}
		}

		efep->efe_collisions +=
		    (status >> TXSTAT_CCNT) & TXSTAT_CCNTMASK;

		efep->efe_tx_sent = NEXTDESC(rp, efep->efe_tx_sent);
	}
}

void
efe_getaddr(efe_t *efep, uint8_t *macaddr)
{
	efe_eeprom_read(efep, macaddr, ETHERADDRL, 0x0);

	efe_debug(efep->efe_dip,
	    "factory address is %02x:%02x:%02x:%02x:%02x:%02x\n",
	    macaddr[0], macaddr[1], macaddr[2], macaddr[3],
	    macaddr[4], macaddr[5]);
}

void
efe_setaddr(efe_t *efep, uint8_t *macaddr)
{
	uint16_t val;

	bcopy(macaddr, &val, sizeof (uint16_t));
	PUTCSR(efep, CSR_LAN0, val);
	macaddr += sizeof (uint16_t);

	bcopy(macaddr, &val, sizeof (uint16_t));
	PUTCSR(efep, CSR_LAN1, val);
	macaddr += sizeof (uint16_t);

	bcopy(macaddr, &val, sizeof (uint16_t));
	PUTCSR(efep, CSR_LAN2, val);
}

void
efe_setmchash(efe_t *efep, uint16_t *mchash)
{
	PUTCSR(efep, CSR_MC0, mchash[0]);
	PUTCSR(efep, CSR_MC1, mchash[1]);
	PUTCSR(efep, CSR_MC2, mchash[2]);
	PUTCSR(efep, CSR_MC3, mchash[3]);
}

void
efe_eeprom_read(efe_t *efep, uint8_t *buf, size_t len, uint8_t addr)
{
	int addrlen;

	ASSERT(len & ~0x1);	/* non-zero; word-aligned */

	PUTCSR(efep, CSR_EECTL, EECTL_ENABLE | EECTL_EECS);
	drv_usecwait(EEPROM_DELAY);

	addrlen = (GETCSR(efep, CSR_EECTL) & EECTL_SIZE ?
	    AT93C46_ADDRLEN : AT93C56_ADDRLEN);

	for (int i = 0; i < len / sizeof (uint16_t); ++i) {
		uint16_t val = efe_eeprom_readw(efep, addrlen, addr + i);
		bcopy(&val, buf, sizeof (uint16_t));
		buf += sizeof (uint16_t);
	}
}

uint16_t
efe_eeprom_readw(efe_t *efep, int addrlen, uint8_t addr)
{
	uint16_t val = 0;

	ASSERT(addrlen > 0);

	/* Write Start Bit (SB) */
	efe_eeprom_writebit(efep, 1);

	/* Write READ instruction */
	efe_eeprom_writebit(efep, 1);
	efe_eeprom_writebit(efep, 0);

	/* Write EEPROM address */
	for (int i = addrlen - 1; i >= 0; --i) {
		efe_eeprom_writebit(efep, addr & 1U << i);
	}

	/* Read EEPROM word */
	for (int i = EEPROM_WORDSZ - 1; i >= 0; --i) {
		val |= efe_eeprom_readbit(efep) << i;
	}

	PUTCSR(efep, CSR_EECTL, EECTL_ENABLE);
	drv_usecwait(EEPROM_DELAY);

	return (val);
}

inline int
efe_eeprom_readbit(efe_t *efep)
{
	PUTCSR(efep, CSR_EECTL, EECTL_ENABLE | EECTL_EECS);
	drv_usecwait(EEPROM_DELAY);

	PUTCSR(efep, CSR_EECTL, EECTL_ENABLE | EECTL_EECS |
	    EECTL_EESK);
	drv_usecwait(EEPROM_DELAY);

	PUTCSR(efep, CSR_EECTL, EECTL_ENABLE | EECTL_EECS);
	drv_usecwait(EEPROM_DELAY);

	return (!!(GETCSR(efep, CSR_EECTL) & EECTL_EEDO));
}

inline void
efe_eeprom_writebit(efe_t *efep, int bit)
{
	PUTCSR(efep, CSR_EECTL, EECTL_ENABLE | EECTL_EECS);
	drv_usecwait(EEPROM_DELAY);

	PUTCSR(efep, CSR_EECTL, EECTL_ENABLE | EECTL_EECS |
	    EECTL_EESK | (bit ? EECTL_EEDI : 0));
	drv_usecwait(EEPROM_DELAY);

	PUTCSR(efep, CSR_EECTL, EECTL_ENABLE | EECTL_EECS);
	drv_usecwait(EEPROM_DELAY);
}

void
efe_dprintf(dev_info_t *dip, int level, const char *format, ...)
{
	va_list ap;
	char buf[255];

	va_start(ap, format);

	(void) vsnprintf(buf, sizeof (buf), format, ap);

	cmn_err(level, "?%s%d %s", ddi_driver_name(dip),
	    ddi_get_instance(dip), buf);

	va_end(ap);
}
