/*
 * Copyright (c) 2011 Jason King.
 * Copyright (c) 2000 Berkeley Software Design, Inc.
 * Copyright (c) 1997, 1998, 1999, 2000
 *      Bill Paul <wpaul@osd.bsdi.com>.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Bill Paul.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Bill Paul AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Bill Paul OR THE VOICES IN HIS HEAD
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/varargs.h>
#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/devops.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/cmn_err.h>
#include <sys/ethernet.h>
#include <sys/kmem.h>
#include <sys/crc32.h>
#include <sys/mii.h>
#include <sys/miiregs.h>
#include <sys/mac.h>
#include <sys/mac_ether.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/vlan.h>
#include <sys/pci.h>
#include <sys/conf.h>

#include "pcn.h"
#include "pcnimpl.h"

#define	ETHERVLANMTU	(ETHERMAX + 4)

#define	CSR_WRITE_4(pcnp, reg, val) \
	ddi_put32(pcnp->pcn_regshandle, (uint32_t *)(pcnp->pcn_regs + reg), val)

#define	CSR_WRITE_2(pcnp, reg, val) \
	ddi_put16(pcnp->pcn_regshandle, (uint16_t *)(pcnp->pcn_regs + reg), val)

#define	CSR_READ_4(pcnp, reg) \
	ddi_get32(pcnp->pcn_regshandle, (uint32_t *)(pcnp->pcn_regs + reg))

#define	CSR_READ_2(pcnp, reg) \
	ddi_get16(pcnp->pcn_regshandle, (uint16_t *)(pcnp->pcn_regs + reg))

#define	PCN_CSR_SETBIT(pcnp, reg, x) \
	pcn_csr_write(pcnp, reg, pcn_csr_read(pcnp, reg) | (x))

#define	PCN_CSR_CLRBIT(pcnp, reg, x) \
	pcn_csr_write(pcnp, reg, pcn_csr_read(pcnp, reg) & ~(x))

#define	PCN_BCR_SETBIT(pncp, reg, x) \
	pcn_bcr_write(pcnp, reg, pcn_bcr_read(pcnp, reg) | (x))

#define	PCN_BCR_CLRBIT(pcnp, reg, x) \
	pcn_bcr_write(pcnp, reg, pcn_bcr_read(pcnp, reg) & ~(x))

static int	pcn_attach(dev_info_t *, ddi_attach_cmd_t);
static int	pcn_detach(dev_info_t *, ddi_detach_cmd_t);
static int	pcn_ddi_resume(dev_info_t *);
static int	pcn_quiesce(dev_info_t *);

static void	pcn_teardown(pcn_t *);

static int	pcn_m_unicast(void *, const uint8_t *);
static int	pcn_m_multicast(void *, boolean_t, const uint8_t *);
static int	pcn_m_promisc(void *, boolean_t);
static mblk_t	*pcn_m_tx(void *, mblk_t *);
static void	pcn_m_ioctl(void *, queue_t *, mblk_t *);
static int	pcn_m_stat(void *, uint_t, uint64_t *);
static int	pcn_m_start(void *);
static void	pcn_m_stop(void *);
static int	pcn_m_getprop(void *, const char *, mac_prop_id_t, uint_t,
    void *);
static int	pcn_m_setprop(void *, const char *, mac_prop_id_t, uint_t,
    const void *);
static void	pcn_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);
static int	pcn_watchdog(pcn_t *);

static unsigned pcn_intr(caddr_t);

static uint16_t	pcn_mii_read(void *, uint8_t, uint8_t);
static void	pcn_mii_write(void *, uint8_t, uint8_t, uint16_t);
static void	pcn_mii_notify(void *, link_state_t);

static uint32_t	pcn_csr_read(pcn_t *, uint32_t);
static uint16_t	pcn_csr_read16(pcn_t *, uint32_t);
static void	pcn_csr_write(pcn_t *, uint32_t, uint32_t);

static uint32_t	pcn_bcr_read(pcn_t *, uint32_t);
static uint16_t pcn_bcr_read16(pcn_t *, uint32_t);
static void	pcn_bcr_write(pcn_t *, uint32_t, uint32_t);

static boolean_t	pcn_send(pcn_t *, mblk_t *);

static pcn_buf_t	*pcn_allocbuf(pcn_t *);
static void		pcn_destroybuf(pcn_buf_t *);
static int		pcn_allocrxring(pcn_t *);
static int		pcn_alloctxring(pcn_t *);
static void		pcn_freetxring(pcn_t *);
static void		pcn_freerxring(pcn_t *);
static void		pcn_resetrings(pcn_t *);
static int		pcn_initialize(pcn_t *, boolean_t);
static mblk_t 		*pcn_receive(pcn_t *);
static void		pcn_resetall(pcn_t *);
static void		pcn_startall(pcn_t *);
static void		pcn_stopall(pcn_t *);
static void		pcn_reclaim(pcn_t *);
static void		pcn_getfactaddr(pcn_t *);
static int		pcn_set_chipid(pcn_t *, uint32_t);
static const pcn_type_t *pcn_match(uint16_t, uint16_t);
static void		pcn_start_timer(pcn_t *);
static void		pcn_stop_timer(pcn_t *);

static void		pcn_error(dev_info_t *, char *, ...);

void *pcn_ssp = NULL;

static uchar_t pcn_broadcast[ETHERADDRL] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static const pcn_type_t pcn_devs[] = {
	{ PCN_VENDORID, PCN_DEVICEID_PCNET, "AMD PCnet/PCI 10/100BaseTX" },
	{ PCN_VENDORID, PCN_DEVICEID_HOME, "AMD PCnet/Home HomePNA" },
	{ 0, 0, NULL }
};

static mii_ops_t pcn_mii_ops = {
	MII_OPS_VERSION,
	pcn_mii_read,
	pcn_mii_write,
	pcn_mii_notify,
	NULL
};

static mac_callbacks_t pcn_m_callbacks = {
	MC_IOCTL | MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	pcn_m_stat,
	pcn_m_start,
	pcn_m_stop,
	pcn_m_promisc,
	pcn_m_multicast,
	pcn_m_unicast,
	pcn_m_tx,
	NULL,
	pcn_m_ioctl,
	NULL,		/* mc_getcapab */
	NULL,		/* mc_open */
	NULL,		/* mc_close */
	pcn_m_setprop,
	pcn_m_getprop,
	pcn_m_propinfo
};

DDI_DEFINE_STREAM_OPS(pcn_devops, nulldev, nulldev, pcn_attach, pcn_detach,
    nodev, NULL, D_MP, NULL, pcn_quiesce);

static struct modldrv pcn_modldrv = {
	&mod_driverops,
	"AMD PCnet",
	&pcn_devops
};

static struct modlinkage pcn_modlinkage = {
	MODREV_1,
	{ &pcn_modldrv, NULL }
};

static ddi_device_acc_attr_t pcn_devattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

static ddi_device_acc_attr_t pcn_bufattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

static ddi_dma_attr_t pcn_dma_attr = {
	DMA_ATTR_V0,		/* dm_attr_version */
	0,			/* dma_attr_addr_lo */
	0xFFFFFFFFU,		/* dma_attr_addr_hi */
	0x7FFFFFFFU,		/* dma_attr_count_max */
	4,			/* dma_attr_align */
	0x3F,			/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0xFFFFFFFFU,		/* dma_attr_maxxfer */
	0xFFFFFFFFU,		/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

static ddi_dma_attr_t pcn_dmadesc_attr = {
	DMA_ATTR_V0,		/* dm_attr_version */
	0,			/* dma_attr_addr_lo */
	0xFFFFFFFFU,		/* dma_attr_addr_hi */
	0x7FFFFFFFU,		/* dma_attr_count_max */
	16,			/* dma_attr_align */
	0x3F,			/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0xFFFFFFFFU,		/* dma_attr_maxxfer */
	0xFFFFFFFFU,		/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

/*
 * DDI entry points
 */
int
_init(void)
{
	int	rc;

	if ((rc = ddi_soft_state_init(&pcn_ssp, sizeof (pcn_t), 1)) != 0)
		return (rc);

	mac_init_ops(&pcn_devops, "pcn");
	if ((rc = mod_install(&pcn_modlinkage)) != DDI_SUCCESS) {
		mac_fini_ops(&pcn_devops);
		ddi_soft_state_fini(&pcn_ssp);
	}
	return (rc);
}

int
_fini(void)
{
	int	rc;

	if ((rc = mod_remove(&pcn_modlinkage)) == DDI_SUCCESS) {
		mac_fini_ops(&pcn_devops);
		ddi_soft_state_fini(&pcn_ssp);
	}
	return (rc);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&pcn_modlinkage, modinfop));
}

int
pcn_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	pcn_t			*pcnp;
	mac_register_t		*macp;
	const pcn_type_t	*pcn_type;
	int			instance = ddi_get_instance(dip);
	int			rc;
	ddi_acc_handle_t	pci;
	uint16_t		venid;
	uint16_t		devid;
	uint16_t		svid;
	uint16_t		ssid;

	switch (cmd) {
	case DDI_RESUME:
		return (pcn_ddi_resume(dip));

	case DDI_ATTACH:
		break;

	default:
		return (DDI_FAILURE);
	}

	if (ddi_slaveonly(dip) == DDI_SUCCESS) {
		pcn_error(dip, "slot does not support PCI bus-master");
		return (DDI_FAILURE);
	}

	if (ddi_intr_hilevel(dip, 0) != 0) {
		pcn_error(dip, "hilevel interrupts not supported");
		return (DDI_FAILURE);
	}

	if (pci_config_setup(dip, &pci) != DDI_SUCCESS) {
		pcn_error(dip, "unable to setup PCI config handle");
		return (DDI_FAILURE);
	}

	venid = pci_config_get16(pci, PCI_CONF_VENID);
	devid = pci_config_get16(pci, PCI_CONF_DEVID);
	svid = pci_config_get16(pci, PCI_CONF_SUBVENID);
	ssid = pci_config_get16(pci, PCI_CONF_SUBSYSID);

	if ((pcn_type = pcn_match(venid, devid)) == NULL) {
		pci_config_teardown(&pci);
		pcn_error(dip, "Unable to identify PCI card");
		return (DDI_FAILURE);
	}

	if (ddi_prop_update_string(DDI_DEV_T_NONE, dip, "model",
	    pcn_type->pcn_name) != DDI_PROP_SUCCESS) {
		pci_config_teardown(&pci);
		pcn_error(dip, "Unable to create model property");
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(pcn_ssp, instance) != DDI_SUCCESS) {
		pcn_error(dip, "Unable to allocate soft state");
		pci_config_teardown(&pci);
		return (DDI_FAILURE);
	}

	pcnp = ddi_get_soft_state(pcn_ssp, instance);
	pcnp->pcn_dip = dip;
	pcnp->pcn_instance = instance;
	pcnp->pcn_extphyaddr = -1;

	if (ddi_get_iblock_cookie(dip, 0, &pcnp->pcn_icookie) != DDI_SUCCESS) {
		pcn_error(pcnp->pcn_dip, "ddi_get_iblock_cookie failed");
		ddi_soft_state_free(pcn_ssp, instance);
		pci_config_teardown(&pci);
		return (DDI_FAILURE);
	}


	mutex_init(&pcnp->pcn_xmtlock, NULL, MUTEX_DRIVER, pcnp->pcn_icookie);
	mutex_init(&pcnp->pcn_intrlock, NULL, MUTEX_DRIVER, pcnp->pcn_icookie);
	mutex_init(&pcnp->pcn_reglock, NULL, MUTEX_DRIVER, pcnp->pcn_icookie);

	/*
	 * Enable bus master, IO space, and memory space accesses
	 */
	pci_config_put16(pci, PCI_CONF_COMM,
	    pci_config_get16(pci, PCI_CONF_COMM) | PCI_COMM_ME | PCI_COMM_MAE);

	pci_config_teardown(&pci);

	if (ddi_regs_map_setup(dip, 1, (caddr_t *)&pcnp->pcn_regs, 0, 0,
	    &pcn_devattr, &pcnp->pcn_regshandle)) {
		pcn_error(dip, "ddi_regs_map_setup failed");
		goto fail;
	}

	if (pcn_set_chipid(pcnp, (uint32_t)ssid << 16 | (uint32_t)svid) !=
	    DDI_SUCCESS) {
		goto fail;
	}

	if ((pcnp->pcn_mii = mii_alloc(pcnp, dip, &pcn_mii_ops)) == NULL)
		goto fail;

	/* XXX: need to set based on device */
	mii_set_pauseable(pcnp->pcn_mii, B_FALSE, B_FALSE);

	if ((pcn_allocrxring(pcnp) != DDI_SUCCESS) ||
	    (pcn_alloctxring(pcnp) != DDI_SUCCESS)) {
		pcn_error(dip, "unable to allocate DMA resources");
		goto fail;
	}

	pcnp->pcn_promisc = B_FALSE;

	mutex_enter(&pcnp->pcn_intrlock);
	mutex_enter(&pcnp->pcn_xmtlock);
	rc = pcn_initialize(pcnp, B_TRUE);
	mutex_exit(&pcnp->pcn_xmtlock);
	mutex_exit(&pcnp->pcn_intrlock);
	if (rc != DDI_SUCCESS)
		goto fail;

	if (ddi_add_intr(dip, 0, NULL, NULL, pcn_intr, (caddr_t)pcnp) !=
	    DDI_SUCCESS) {
		pcn_error(dip, "unable to add interrupt");
		goto fail;
	}

	pcnp->pcn_flags |= PCN_INTR_ENABLED;

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		pcn_error(pcnp->pcn_dip, "mac_alloc failed");
		goto fail;
	}

	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = pcnp;
	macp->m_dip = dip;
	macp->m_src_addr = pcnp->pcn_addr;
	macp->m_callbacks = &pcn_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = ETHERMTU;
	macp->m_margin = VLAN_TAGSZ;

	if (mac_register(macp, &pcnp->pcn_mh) == DDI_SUCCESS) {
		mac_free(macp);
		return (DDI_SUCCESS);
	}

	mac_free(macp);

	return (DDI_SUCCESS);

fail:
	pcn_teardown(pcnp);
	return (DDI_FAILURE);
}

int
pcn_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	pcn_t	*pcnp;

	pcnp = ddi_get_soft_state(pcn_ssp, ddi_get_instance(dip));

	if (pcnp == NULL) {
		pcn_error(dip, "no soft state in detach!");
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		if (mac_unregister(pcnp->pcn_mh) != 0)
			return (DDI_FAILURE);

		mutex_enter(&pcnp->pcn_intrlock);
		mutex_enter(&pcnp->pcn_xmtlock);
		pcnp->pcn_flags &= ~PCN_RUNNING;
		pcn_stopall(pcnp);
		mutex_exit(&pcnp->pcn_xmtlock);
		mutex_exit(&pcnp->pcn_intrlock);

		pcn_teardown(pcnp);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		mii_suspend(pcnp->pcn_mii);

		mutex_enter(&pcnp->pcn_intrlock);
		mutex_enter(&pcnp->pcn_xmtlock);
		pcnp->pcn_flags |= PCN_SUSPENDED;
		pcn_stopall(pcnp);
		mutex_exit(&pcnp->pcn_xmtlock);
		mutex_exit(&pcnp->pcn_intrlock);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

int
pcn_ddi_resume(dev_info_t *dip)
{
	pcn_t	*pcnp;

	if ((pcnp = ddi_get_soft_state(pcn_ssp, ddi_get_instance(dip))) == NULL)
		return (DDI_FAILURE);

	mutex_enter(&pcnp->pcn_intrlock);
	mutex_enter(&pcnp->pcn_xmtlock);

	pcnp->pcn_flags &= ~PCN_SUSPENDED;

	if (!pcn_initialize(pcnp, B_FALSE)) {
		pcn_error(pcnp->pcn_dip, "unable to resume chip");
		pcnp->pcn_flags |= PCN_SUSPENDED;
		mutex_exit(&pcnp->pcn_intrlock);
		mutex_exit(&pcnp->pcn_xmtlock);
		return (DDI_SUCCESS);
	}

	if (IS_RUNNING(pcnp))
		pcn_startall(pcnp);

	mutex_exit(&pcnp->pcn_xmtlock);
	mutex_exit(&pcnp->pcn_intrlock);

	mii_resume(pcnp->pcn_mii);

	return (DDI_SUCCESS);
}

int
pcn_quiesce(dev_info_t *dip)
{
	pcn_t	*pcnp;

	if ((pcnp = ddi_get_soft_state(pcn_ssp, ddi_get_instance(dip))) == NULL)
		return (DDI_FAILURE);

	/* don't want to take the chance of blocking */
	CSR_WRITE_4(pcnp, PCN_IO32_RAP, PCN_CSR_EXTCTL1);
	CSR_WRITE_4(pcnp, PCN_IO32_RDP, CSR_READ_4(pcnp, PCN_IO32_RDP) &
	    ~(PCN_EXTCTL1_SINTEN));

	CSR_WRITE_4(pcnp, PCN_IO32_RAP, PCN_CSR_CSR);
	CSR_WRITE_4(pcnp, PCN_IO32_RDP,
	    (CSR_READ_4(pcnp, PCN_IO32_RDP) & ~(PCN_CSR_INTEN)) |
	    PCN_CSR_STOP);

	return (DDI_SUCCESS);
}

static void
pcn_teardown(pcn_t *pcnp)
{
	ASSERT(!(pcnp->pcn_flags & PCN_RUNNING));

	if (pcnp->pcn_mii != NULL) {
		mii_free(pcnp->pcn_mii);
		pcnp->pcn_mii = NULL;
	}

	if (pcnp->pcn_flags & PCN_INTR_ENABLED)
		ddi_remove_intr(pcnp->pcn_dip, 0, pcnp->pcn_icookie);

	/* These will exit gracefully if not yet allocated */
	pcn_freerxring(pcnp);
	pcn_freetxring(pcnp);

	if (pcnp->pcn_regshandle != NULL)
		ddi_regs_map_free(&pcnp->pcn_regshandle);


	mutex_destroy(&pcnp->pcn_xmtlock);
	mutex_destroy(&pcnp->pcn_intrlock);
	mutex_destroy(&pcnp->pcn_reglock);

	ddi_soft_state_free(pcn_ssp, ddi_get_instance(pcnp->pcn_dip));
}

/*
 * Drains any FIFOs in the card, then pauses it
 */
static void
pcn_suspend(pcn_t *pcnp)
{
	uint32_t val;
	int i;

	PCN_CSR_SETBIT(pcnp, PCN_CSR_EXTCTL1, PCN_EXTCTL1_SPND);
	for (i = 0; i < 5000; i++) {
		if ((val = pcn_csr_read(pcnp, PCN_CSR_EXTCTL1)) &
		    PCN_EXTCTL1_SPND)
			return;
		drv_usecwait(1000);
	}

	pcn_error(pcnp->pcn_dip, "Unable to suspend, EXTCTL1 was 0x%b", val,
	    PCN_EXTCTL1_STR);
}

static void
pcn_resume(pcn_t *pcnp)
{
	PCN_CSR_CLRBIT(pcnp, PCN_CSR_EXTCTL1, PCN_EXTCTL1_SPND);
}

static int
pcn_m_multicast(void *arg, boolean_t add, const uint8_t *macaddr)
{
	pcn_t		*pcnp = (pcn_t *)arg;
	int		index;
	uint32_t	crc;
	uint16_t	bit;
	uint16_t	newval, oldval;

	/*
	 * PCNet uses the upper 6 bits of the CRC of the macaddr
	 * to index into a 64bit mask
	 */
	CRC32(crc, macaddr, ETHERADDRL, -1U, crc32_table);
	crc >>= 26;
	index = crc / 16;
	bit = (1U << (crc % 16));

	mutex_enter(&pcnp->pcn_intrlock);
	mutex_enter(&pcnp->pcn_xmtlock);
	newval = oldval = pcnp->pcn_mctab[index];

	if (add) {
		pcnp->pcn_mccount[crc]++;
		if (pcnp->pcn_mccount[crc] == 1)
			newval |= bit;
	} else {
		pcnp->pcn_mccount[crc]--;
		if (pcnp->pcn_mccount[crc] == 0)
			newval &= ~bit;
	}
	if (newval != oldval) {
		pcnp->pcn_mctab[index] = newval;
		pcn_suspend(pcnp);
		pcn_csr_write(pcnp, PCN_CSR_MAR0 + index, newval);
		pcn_resume(pcnp);
	}

	mutex_exit(&pcnp->pcn_xmtlock);
	mutex_exit(&pcnp->pcn_intrlock);

	return (0);
}

static int
pcn_m_promisc(void *arg, boolean_t on)
{
	pcn_t		*pcnp = (pcn_t *)arg;

	mutex_enter(&pcnp->pcn_intrlock);
	mutex_enter(&pcnp->pcn_xmtlock);

	pcnp->pcn_promisc = on;

	if (IS_RUNNING(pcnp))
		pcn_suspend(pcnp);

	/* set promiscuous mode */
	if (pcnp->pcn_promisc)
		PCN_CSR_SETBIT(pcnp, PCN_CSR_MODE, PCN_MODE_PROMISC);
	else
		PCN_CSR_CLRBIT(pcnp, PCN_CSR_MODE, PCN_MODE_PROMISC);

	if (IS_RUNNING(pcnp))
		pcn_resume(pcnp);

	mutex_exit(&pcnp->pcn_xmtlock);
	mutex_exit(&pcnp->pcn_intrlock);

	return (0);
}

static int
pcn_m_unicast(void *arg, const uint8_t *macaddr)
{
	pcn_t	*pcnp = (pcn_t *)arg;
	int i;
	uint16_t addr[3];

	bcopy(macaddr, addr, sizeof (addr));

	mutex_enter(&pcnp->pcn_intrlock);
	mutex_enter(&pcnp->pcn_xmtlock);

	if (IS_RUNNING(pcnp))
		pcn_suspend(pcnp);

	for (i = 0; i < 3; i++)
		pcn_csr_write(pcnp, PCN_CSR_PAR0 + i, addr[i]);

	bcopy(macaddr, pcnp->pcn_addr, ETHERADDRL);

	if (IS_RUNNING(pcnp))
		pcn_resume(pcnp);

	mutex_exit(&pcnp->pcn_xmtlock);
	mutex_exit(&pcnp->pcn_intrlock);

	return (0);
}

static mblk_t *
pcn_m_tx(void *arg, mblk_t *mp)
{
	pcn_t	*pcnp = (pcn_t *)arg;
	mblk_t	*nmp;

	mutex_enter(&pcnp->pcn_xmtlock);

	if (pcnp->pcn_flags & PCN_SUSPENDED) {
		while ((nmp = mp) != NULL) {
			pcnp->pcn_carrier_errors++;
			mp = mp->b_next;
			freemsg(nmp);
		}
		mutex_exit(&pcnp->pcn_xmtlock);
		return (NULL);
	}

	while (mp != NULL) {
		nmp = mp->b_next;
		mp->b_next = NULL;

		if (!pcn_send(pcnp, mp)) {
			mp->b_next = nmp;
			break;
		}
		mp = nmp;
	}
	mutex_exit(&pcnp->pcn_xmtlock);

	return (mp);
}

static boolean_t
pcn_send(pcn_t *pcnp, mblk_t *mp)
{
	size_t		len;
	pcn_buf_t	*txb;
	pcn_tx_desc_t	*tmd;
	int		txsend;

	ASSERT(mutex_owned(&pcnp->pcn_xmtlock));
	ASSERT(mp != NULL);

	len = msgsize(mp);
	if (len > ETHERVLANMTU) {
		pcnp->pcn_macxmt_errors++;
		freemsg(mp);
		return (B_TRUE);
	}

	if (pcnp->pcn_txavail < PCN_TXRECLAIM)
		pcn_reclaim(pcnp);

	if (pcnp->pcn_txavail == 0) {
		pcnp->pcn_wantw = B_TRUE;

		/* enable tx interrupt */
		PCN_CSR_SETBIT(pcnp, PCN_CSR_EXTCTL1, PCN_EXTCTL1_LTINTEN);
		return (B_FALSE);
	}

	txsend = pcnp->pcn_txsend;

	/*
	 * We copy the packet to a single buffer.  NetBSD sources suggest
	 * that if multiple segements are ever used, VMware has a bug that will
	 * only allow 8 segments to be used, while the physical chips allow 16
	 */
	txb = pcnp->pcn_txbufs[txsend];
	mcopymsg(mp, txb->pb_buf);	/* frees mp! */

	pcnp->pcn_opackets++;
	pcnp->pcn_obytes += len;
	if (txb->pb_buf[0] & 0x1) {
		if (bcmp(txb->pb_buf, pcn_broadcast, ETHERADDRL) != 0)
			pcnp->pcn_multixmt++;
		else
			pcnp->pcn_brdcstxmt++;
	}

	tmd = &pcnp->pcn_txdescp[txsend];

	SYNCBUF(txb, len, DDI_DMA_SYNC_FORDEV);
	tmd->pcn_txstat = 0;
	tmd->pcn_tbaddr = txb->pb_paddr;

	/* PCNet wants the 2's complement of the length of the buffer */
	tmd->pcn_txctl = (~(len) + 1) & PCN_TXCTL_BUFSZ;
	tmd->pcn_txctl |= PCN_TXCTL_MBO;
	tmd->pcn_txctl |= PCN_TXCTL_STP | PCN_TXCTL_ENP | PCN_TXCTL_ADD_FCS |
	    PCN_TXCTL_OWN | PCN_TXCTL_MORE_LTINT;

	SYNCTXDESC(pcnp, txsend, DDI_DMA_SYNC_FORDEV);

	pcnp->pcn_txavail--;
	pcnp->pcn_txsend = (txsend + 1) % PCN_TXRING;
	pcnp->pcn_txstall_time = gethrtime() + (5 * 1000000000ULL);

	pcn_csr_write(pcnp, PCN_CSR_CSR, PCN_CSR_TX|PCN_CSR_INTEN);

	return (B_TRUE);
}

static void
pcn_reclaim(pcn_t *pcnp)
{
	pcn_tx_desc_t	*tmdp;

	while (pcnp->pcn_txavail != PCN_TXRING) {
		int index = pcnp->pcn_txreclaim;

		tmdp = &pcnp->pcn_txdescp[index];

		/* sync before reading */
		SYNCTXDESC(pcnp, index, DDI_DMA_SYNC_FORKERNEL);

		/* check if chip is still working on it */
		if (tmdp->pcn_txctl & PCN_TXCTL_OWN)
			break;

		pcnp->pcn_txavail++;
		pcnp->pcn_txreclaim = (index + 1) % PCN_TXRING;
	}

	if (pcnp->pcn_txavail >= PCN_TXRESCHED) {
		if (pcnp->pcn_wantw) {
			pcnp->pcn_wantw = B_FALSE;

			/* Disable TX interrupt */
			PCN_CSR_CLRBIT(pcnp, PCN_CSR_EXTCTL1,
			    PCN_EXTCTL1_LTINTEN);

			mac_tx_update(pcnp->pcn_mh);
		}
	}
}

static unsigned
pcn_intr(caddr_t arg1)
{
	pcn_t		*pcnp = (void *)arg1;
	mblk_t		*mp = NULL;
	uint32_t	status, status2;
	boolean_t	do_reset = B_FALSE;

	mutex_enter(&pcnp->pcn_intrlock);

	if (IS_SUSPENDED(pcnp)) {
		mutex_exit(&pcnp->pcn_intrlock);
		return (DDI_INTR_UNCLAIMED);
	}

	while ((status = pcn_csr_read(pcnp, PCN_CSR_CSR)) & PCN_CSR_INTR) {
		pcn_csr_write(pcnp, PCN_CSR_CSR, status);

		status2 = pcn_csr_read(pcnp, PCN_CSR_EXTCTL2);

		if (status & PCN_CSR_TINT) {
			mutex_enter(&pcnp->pcn_xmtlock);
			pcn_reclaim(pcnp);
			mutex_exit(&pcnp->pcn_xmtlock);
		}

		if (status & PCN_CSR_RINT)
			mp = pcn_receive(pcnp);

		if (status & PCN_CSR_ERR) {
			do_reset = B_TRUE;
			break;
		}

		/* timer interrupt */
		if (status2 & PCN_EXTCTL2_STINT) {
			/* ack it */
			PCN_CSR_SETBIT(pcnp, PCN_CSR_EXTCTL2,
			    PCN_EXTCTL2_STINT);

			if (pcn_watchdog(pcnp) != DDI_SUCCESS) {
				do_reset = B_TRUE;
				break;
			}
		}
	}

	if (do_reset) {
		mutex_enter(&pcnp->pcn_xmtlock);
		pcn_resetall(pcnp);
		mutex_exit(&pcnp->pcn_xmtlock);
		mutex_exit(&pcnp->pcn_intrlock);

		mii_reset(pcnp->pcn_mii);
	} else {
		mutex_exit(&pcnp->pcn_intrlock);
	}

	if (mp)
		mac_rx(pcnp->pcn_mh, NULL, mp);

	return (DDI_INTR_CLAIMED);
}

static mblk_t *
pcn_receive(pcn_t *pcnp)
{
	uint32_t	len;
	pcn_buf_t	*rxb;
	pcn_rx_desc_t	*rmd;
	mblk_t		*mpchain, **mpp, *mp;
	int		head, cnt;

	mpchain = NULL;
	mpp = &mpchain;
	head = pcnp->pcn_rxhead;

	for (cnt = 0; cnt < PCN_RXRING; cnt++) {
		rmd = &pcnp->pcn_rxdescp[head];
		rxb = pcnp->pcn_rxbufs[head];

		SYNCRXDESC(pcnp, head, DDI_DMA_SYNC_FORKERNEL);
		if (rmd->pcn_rxstat & PCN_RXSTAT_OWN)
			break;

		len = rmd->pcn_rxlen - ETHERFCSL;

		if (rmd->pcn_rxstat & PCN_RXSTAT_ERR) {
			pcnp->pcn_errrcv++;

			if (rmd->pcn_rxstat & PCN_RXSTAT_FRAM)
				pcnp->pcn_align_errors++;
			if (rmd->pcn_rxstat & PCN_RXSTAT_OFLOW)
				pcnp->pcn_overflow++;
			if (rmd->pcn_rxstat & PCN_RXSTAT_CRC)
				pcnp->pcn_fcs_errors++;
		} else if (len > ETHERVLANMTU) {
			pcnp->pcn_errrcv++;
			pcnp->pcn_toolong_errors++;
		} else {
			mp = allocb(len + PCN_HEADROOM, 0);
			if (mp == NULL) {
				pcnp->pcn_errrcv++;
				pcnp->pcn_norcvbuf++;
				goto skip;
			}

			SYNCBUF(rxb, len, DDI_DMA_SYNC_FORKERNEL);
			mp->b_rptr += PCN_HEADROOM;
			mp->b_wptr = mp->b_rptr + len;
			bcopy((char *)rxb->pb_buf, mp->b_rptr, len);

			pcnp->pcn_ipackets++;
			pcnp->pcn_rbytes++;

			if (rmd->pcn_rxstat & PCN_RXSTAT_LAFM|PCN_RXSTAT_BAM) {
				if (rmd->pcn_rxstat & PCN_RXSTAT_BAM)
					pcnp->pcn_brdcstrcv++;
				else
					pcnp->pcn_multircv++;
			}
			*mpp = mp;
			mpp = &mp->b_next;
		}

skip:
		rmd->pcn_rxstat = PCN_RXSTAT_OWN;
		SYNCRXDESC(pcnp, head, DDI_DMA_SYNC_FORDEV);

		head = (head + 1) % PCN_RXRING;
	}

	pcnp->pcn_rxhead = head;
	return (mpchain);
}

static void
pcn_m_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	pcn_t *pcnp = (pcn_t *)arg;

	if (mii_m_loop_ioctl(pcnp->pcn_mii, wq, mp))
		return;

	miocnak(wq, mp, 0, EINVAL);
}

static int
pcn_m_start(void *arg)
{
	pcn_t	*pcnp = (pcn_t *)arg;

	mutex_enter(&pcnp->pcn_intrlock);
	mutex_enter(&pcnp->pcn_xmtlock);

	pcn_startall(pcnp);
	pcnp->pcn_flags |= PCN_RUNNING;

	mutex_exit(&pcnp->pcn_xmtlock);
	mutex_exit(&pcnp->pcn_intrlock);

	mii_start(pcnp->pcn_mii);

	return (0);
}

static void
pcn_m_stop(void *arg)
{
	pcn_t	*pcnp = (pcn_t *)arg;

	mii_stop(pcnp->pcn_mii);

	mutex_enter(&pcnp->pcn_intrlock);
	mutex_enter(&pcnp->pcn_xmtlock);

	pcn_stopall(pcnp);
	pcnp->pcn_flags &= ~PCN_RUNNING;

	mutex_exit(&pcnp->pcn_xmtlock);
	mutex_exit(&pcnp->pcn_intrlock);
}

static int
pcn_initialize(pcn_t *pcnp, boolean_t getfact)
{
	int i;
	uint16_t addr[3];

	bcopy(pcnp->pcn_addr, addr, sizeof (addr));

	/*
	 * Issue a reset by reading from the RESET register.
	 * Note that we don't know if the chip is operating in
	 * 16-bit or 32-bit mode at this point, so we attempt
	 * to reset the chip both ways.  If one fails, the other
	 * will succeed.
	 */
	(void) CSR_READ_2(pcnp, PCN_IO16_RESET);
	(void) CSR_READ_4(pcnp, PCN_IO32_RESET);

	drv_usecwait(1000);

	/* Select 32-bit (DWIO) mode */
	CSR_WRITE_4(pcnp, PCN_IO32_RDP, 0);

	/* The timer is not affected by a reset, so explicitly disable */
	pcn_stop_timer(pcnp);

	/* Enable fast suspend */
	pcn_csr_write(pcnp, PCN_CSR_EXTCTL2, PCN_EXTCTL2_FASTSPNDE);

	/* Select Style 3 descriptors */
	pcn_bcr_write(pcnp, PCN_BCR_SSTYLE, PCN_SWSTYLE_PCNETPCI);

	/* Set MAC address */
	if (getfact)
		pcn_getfactaddr(pcnp);

	pcn_csr_write(pcnp, PCN_CSR_PAR0, addr[0]);
	pcn_csr_write(pcnp, PCN_CSR_PAR1, addr[1]);
	pcn_csr_write(pcnp, PCN_CSR_PAR2, addr[2]);

	/* Clear PCN_MISC_ASEL so we can set the port via PCN_CSR_MODE. */
	PCN_BCR_CLRBIT(pcnp, PCN_BCR_MISCCFG, PCN_MISC_ASEL);

	/*
	 * XXX: need to find a way to determine when 10bt media is
	 * selected for non Am79C978, and set to PCN_PORT_10BASET
	 * instead of PCN_PORT_MII
	 */
	pcn_csr_write(pcnp, PCN_CSR_MODE, PCN_PORT_MII);

	/* Reenable auto negotiation for external phy */
	PCN_BCR_SETBIT(pcnp, PCN_BCR_MIICTL, PCN_MIICTL_XPHYANE);

	if (pcnp->pcn_promisc)
		PCN_CSR_SETBIT(pcnp, PCN_CSR_MODE, PCN_MODE_PROMISC);

	/* Initalize mcast addr filter */
	for (i = 0; i < 4; i++)
		pcn_csr_write(pcnp, PCN_CSR_MAR0 + i, pcnp->pcn_mctab[i]);

	pcn_resetrings(pcnp);

	/* We're not using the initialization block. */
	pcn_csr_write(pcnp, PCN_CSR_IAB1, 0);

	/*
	 * Enable burst read and write.  Also set the no underflow
	 * bit.  This will avoid transmit underruns in ceratin
	 * conditions while still providing decent performance.
	 */
	PCN_BCR_SETBIT(pcnp, PCN_BCR_BUSCTL, PCN_BUSCTL_NOUFLOW |
	    PCN_BUSCTL_BREAD | PCN_BUSCTL_BWRITE);

	/* Enable graceful recovery from underflow. */
	PCN_CSR_SETBIT(pcnp, PCN_CSR_IMR, PCN_IMR_DXSUFLO);

	/* Enable auto-padding of short TX frames. */
	PCN_CSR_SETBIT(pcnp, PCN_CSR_TFEAT, PCN_TFEAT_PAD_TX);

	if (pcnp->pcn_type == Am79C978)
		pcn_bcr_write(pcnp, PCN_BCR_PHYSEL,
		    PCN_PHYSEL_PCNET|PCN_PHY_HOMEPNA);

	return (DDI_SUCCESS);
}

static void
pcn_resetall(pcn_t *pcnp)
{
	pcn_stopall(pcnp);
	pcn_startall(pcnp);
}

static void
pcn_startall(pcn_t *pcnp)
{
	ASSERT(mutex_owned(&pcnp->pcn_intrlock));
	ASSERT(mutex_owned(&pcnp->pcn_xmtlock));

	(void) pcn_initialize(pcnp, B_FALSE);

	/* Start chip and enable interrupts */
	PCN_CSR_SETBIT(pcnp, PCN_CSR_CSR, PCN_CSR_START|PCN_CSR_INTEN);

	pcn_start_timer(pcnp);

	if (IS_RUNNING(pcnp))
		mac_tx_update(pcnp->pcn_mh);
}

static void
pcn_stopall(pcn_t *pcnp)
{
	ASSERT(mutex_owned(&pcnp->pcn_intrlock));
	ASSERT(mutex_owned(&pcnp->pcn_xmtlock));

	pcn_stop_timer(pcnp);
	PCN_CSR_SETBIT(pcnp, PCN_CSR_CSR, PCN_CSR_STOP);
}

/*
 * The soft timer is not affected by a soft reset (according to the datasheet)
 * so it must always be explicitly enabled and disabled
 */
static void
pcn_start_timer(pcn_t *pcnp)
{
	PCN_CSR_SETBIT(pcnp, PCN_CSR_EXTCTL1, PCN_EXTCTL1_SINTEN);

	/*
	 * The frequency this fires varies based on the particular
	 * model, this value is largely arbitrary. It just needs to
	 * fire often enough to detect a stall
	 */
	pcn_bcr_write(pcnp, PCN_BCR_TIMER, 0xa000);
}


static void
pcn_stop_timer(pcn_t *pcnp)
{
	PCN_CSR_CLRBIT(pcnp, PCN_CSR_EXTCTL1, PCN_EXTCTL1_SINTEN);
}

static int
pcn_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	pcn_t	*pcnp = (pcn_t *)arg;

	if (mii_m_getstat(pcnp->pcn_mii, stat, val) == 0)
		return (0);

	switch (stat) {
	case MAC_STAT_MULTIRCV:
		*val = pcnp->pcn_multircv;
		break;

	case MAC_STAT_BRDCSTRCV:
		*val = pcnp->pcn_brdcstrcv;
		break;

	case MAC_STAT_MULTIXMT:
		*val = pcnp->pcn_multixmt;
		break;

	case MAC_STAT_BRDCSTXMT:
		*val = pcnp->pcn_brdcstxmt;
		break;

	case MAC_STAT_IPACKETS:
		*val = pcnp->pcn_ipackets;
		break;

	case MAC_STAT_RBYTES:
		*val = pcnp->pcn_rbytes;
		break;

	case MAC_STAT_OPACKETS:
		*val = pcnp->pcn_opackets;
		break;

	case MAC_STAT_OBYTES:
		*val = pcnp->pcn_obytes;
		break;

	case MAC_STAT_NORCVBUF:
		*val = pcnp->pcn_norcvbuf;
		break;

	case MAC_STAT_NOXMTBUF:
		*val = 0;
		break;

	case MAC_STAT_COLLISIONS:
		*val = pcnp->pcn_collisions;
		break;

	case MAC_STAT_IERRORS:
		*val = pcnp->pcn_errrcv;
		break;

	case MAC_STAT_OERRORS:
		*val = pcnp->pcn_errxmt;
		break;

	case ETHER_STAT_ALIGN_ERRORS:
		*val = pcnp->pcn_align_errors;
		break;

	case ETHER_STAT_FCS_ERRORS:
		*val = pcnp->pcn_fcs_errors;
		break;

	case ETHER_STAT_SQE_ERRORS:
		*val = pcnp->pcn_sqe_errors;
		break;

	case ETHER_STAT_DEFER_XMTS:
		*val = pcnp->pcn_defer_xmts;
		break;

	case ETHER_STAT_FIRST_COLLISIONS:
		*val = pcnp->pcn_first_collisions;
		break;

	case ETHER_STAT_MULTI_COLLISIONS:
		*val = pcnp->pcn_multi_collisions;
		break;

	case ETHER_STAT_TX_LATE_COLLISIONS:
		*val = pcnp->pcn_tx_late_collisions;
		break;

	case ETHER_STAT_EX_COLLISIONS:
		*val = pcnp->pcn_ex_collisions;
		break;

	case ETHER_STAT_MACXMT_ERRORS:
		*val = pcnp->pcn_macxmt_errors;
		break;

	case ETHER_STAT_CARRIER_ERRORS:
		*val = pcnp->pcn_carrier_errors;
		break;

	case ETHER_STAT_TOOLONG_ERRORS:
		*val = pcnp->pcn_toolong_errors;
		break;

	case ETHER_STAT_MACRCV_ERRORS:
		*val = pcnp->pcn_macrcv_errors;
		break;

	case MAC_STAT_OVERFLOWS:
		*val = pcnp->pcn_overflow;
		break;

	case MAC_STAT_UNDERFLOWS:
		*val = pcnp->pcn_underflow;
		break;

	case ETHER_STAT_TOOSHORT_ERRORS:
		*val = pcnp->pcn_runt;
		break;

	case ETHER_STAT_JABBER_ERRORS:
		*val = pcnp->pcn_jabber;
		break;

	default:
		return (ENOTSUP);
	}
	return (0);
}

static int
pcn_m_getprop(void *arg, const char *name, mac_prop_id_t num, uint_t sz,
    void *val)
{
	pcn_t	*pcnp = (pcn_t *)arg;

	return (mii_m_getprop(pcnp->pcn_mii, name, num, sz, val));
}

static int
pcn_m_setprop(void *arg, const char *name, mac_prop_id_t num, uint_t sz,
    const void *val)
{
	pcn_t	*pcnp = (pcn_t *)arg;

	return (mii_m_setprop(pcnp->pcn_mii, name, num, sz, val));
}

static void
pcn_m_propinfo(void *arg, const char *name, mac_prop_id_t num,
    mac_prop_info_handle_t prh)
{
	pcn_t	*pcnp = arg;

	mii_m_propinfo(pcnp->pcn_mii, name, num, prh);
}

static int
pcn_watchdog(pcn_t *pcnp)
{
	if ((pcnp->pcn_txstall_time != 0) &&
	    (gethrtime() > pcnp->pcn_txstall_time) &&
	    (pcnp->pcn_txavail != PCN_TXRING)) {
		pcnp->pcn_txstall_time = 0;
		pcn_error(pcnp->pcn_dip, "TX stall detected!");
		return (DDI_FAILURE);
	} else {
		return (DDI_SUCCESS);
	}
}

static uint16_t
pcn_mii_read(void *arg, uint8_t phy, uint8_t reg)
{
	pcn_t		*pcnp = (pcn_t *)arg;
	uint16_t	val;

	/*
	 * At least Am79C971 with DP83840A wedge when isolating the
	 * external PHY so we can't allow multiple external PHYs.
	 * There are cards that use Am79C971 with both the internal
	 * and an external PHY though.
	 * For internal PHYs it doesn't really matter whether we can
	 * isolate the remaining internal and the external ones in
	 * the PHY drivers as the internal PHYs have to be enabled
	 * individually in PCN_BCR_PHYSEL, PCN_CSR_MODE, etc.
	 * With Am79C97{3,5,8} we don't support switching beetween
	 * the internal and external PHYs, yet, so we can't allow
	 * multiple PHYs with these either.
	 * Am79C97{2,6} actually only support external PHYs (not
	 * connectable internal ones respond at the usual addresses,
	 * which don't hurt if we let them show up on the bus) and
	 * isolating them works.
	 */
	if (((pcnp->pcn_type == Am79C971 && phy != PCN_PHYAD_10BT) ||
	    pcnp->pcn_type == Am79C973 || pcnp->pcn_type == Am79C975 ||
	    pcnp->pcn_type == Am79C978) && pcnp->pcn_extphyaddr != -1 &&
	    phy != pcnp->pcn_extphyaddr) {
		return (0);
	}

	val = ((uint16_t)phy << 5) | reg;
	pcn_bcr_write(pcnp, PCN_BCR_MIIADDR, phy << 5 | reg);
	val = pcn_bcr_read(pcnp, PCN_BCR_MIIDATA) & 0xFFFF;
	if (val == 0xFFFF) {
		return (0);
	}

	if (((pcnp->pcn_type == Am79C971 && phy != PCN_PHYAD_10BT) ||
	    pcnp->pcn_type == Am79C973 || pcnp->pcn_type == Am79C975 ||
	    pcnp->pcn_type == Am79C978) && pcnp->pcn_extphyaddr == -1)
		pcnp->pcn_extphyaddr = phy;

	return (val);
}

static void
pcn_mii_write(void *arg, uint8_t phy, uint8_t reg, uint16_t val)
{
	pcn_t		*pcnp = (pcn_t *)arg;

	pcn_bcr_write(pcnp, PCN_BCR_MIIADDR, reg | (phy << 5));
	pcn_bcr_write(pcnp, PCN_BCR_MIIDATA, val);
}

static void
pcn_mii_notify(void *arg, link_state_t link)
{
	pcn_t		*pcnp = (pcn_t *)arg;

	mac_link_update(pcnp->pcn_mh, link);
}

static const pcn_type_t *
pcn_match(uint16_t vid, uint16_t did)
{
	const pcn_type_t	*t;

	t = pcn_devs;
	while (t->pcn_name != NULL) {
		if ((vid == t->pcn_vid) && (did == t->pcn_did))
			return (t);
		t++;
	}
	return (NULL);
}

static void
pcn_getfactaddr(pcn_t *pcnp)
{
	uint32_t addr[2];

	addr[0] = CSR_READ_4(pcnp, PCN_IO32_APROM00);
	addr[1] = CSR_READ_4(pcnp, PCN_IO32_APROM01);

	bcopy(&addr[0], &pcnp->pcn_addr[0], sizeof (pcnp->pcn_addr));
}

static uint32_t
pcn_csr_read(pcn_t *pcnp, uint32_t reg)
{
	uint32_t val;

	mutex_enter(&pcnp->pcn_reglock);
	CSR_WRITE_4(pcnp, PCN_IO32_RAP, reg);
	val = CSR_READ_4(pcnp, PCN_IO32_RDP);
	mutex_exit(&pcnp->pcn_reglock);
	return (val);
}

static uint16_t
pcn_csr_read16(pcn_t *pcnp, uint32_t reg)
{
	uint16_t val;

	mutex_enter(&pcnp->pcn_reglock);
	CSR_WRITE_2(pcnp, PCN_IO16_RAP, reg);
	val = CSR_READ_2(pcnp, PCN_IO16_RDP);
	mutex_exit(&pcnp->pcn_reglock);
	return (val);
}

static void
pcn_csr_write(pcn_t *pcnp, uint32_t reg, uint32_t val)
{
	mutex_enter(&pcnp->pcn_reglock);
	CSR_WRITE_4(pcnp, PCN_IO32_RAP, reg);
	CSR_WRITE_4(pcnp, PCN_IO32_RDP, val);
	mutex_exit(&pcnp->pcn_reglock);
}

static uint32_t
pcn_bcr_read(pcn_t *pcnp, uint32_t reg)
{
	uint32_t val;

	mutex_enter(&pcnp->pcn_reglock);
	CSR_WRITE_4(pcnp, PCN_IO32_RAP, reg);
	val = CSR_READ_4(pcnp, PCN_IO32_BDP);
	mutex_exit(&pcnp->pcn_reglock);
	return (val);
}

static uint16_t
pcn_bcr_read16(pcn_t *pcnp, uint32_t reg)
{
	uint16_t val;

	mutex_enter(&pcnp->pcn_reglock);
	CSR_WRITE_2(pcnp, PCN_IO16_RAP, reg);
	val = CSR_READ_2(pcnp, PCN_IO16_BDP);
	mutex_exit(&pcnp->pcn_reglock);
	return (val);
}

static void
pcn_bcr_write(pcn_t *pcnp, uint32_t reg, uint32_t val)
{
	mutex_enter(&pcnp->pcn_reglock);
	CSR_WRITE_4(pcnp, PCN_IO32_RAP, reg);
	CSR_WRITE_4(pcnp, PCN_IO32_BDP, val);
	mutex_exit(&pcnp->pcn_reglock);
}

static void
pcn_resetrings(pcn_t *pcnp)
{
	int i;
	uint16_t bufsz = ((~(PCN_BUFSZ) + 1) & PCN_RXLEN_BUFSZ) | PCN_RXLEN_MBO;

	pcnp->pcn_rxhead = 0;
	pcnp->pcn_txreclaim = 0;
	pcnp->pcn_txsend = 0;
	pcnp->pcn_txavail = PCN_TXRING;

	/* reset rx descriptor values */
	for (i = 0; i < PCN_RXRING; i++) {
		pcn_rx_desc_t	*rmd = &pcnp->pcn_rxdescp[i];
		pcn_buf_t	*rxb = pcnp->pcn_rxbufs[i];

		rmd->pcn_rxlen = rmd->pcn_rsvd0 = 0;
		rmd->pcn_rbaddr = rxb->pb_paddr;
		rmd->pcn_bufsz = bufsz;
		rmd->pcn_rxstat = PCN_RXSTAT_OWN;
	}
	(void) ddi_dma_sync(pcnp->pcn_rxdesc_dmah, 0,
	    PCN_RXRING * sizeof (pcn_rx_desc_t), DDI_DMA_SYNC_FORDEV);

	/* reset tx descriptor values */
	for (i = 0; i < PCN_TXRING; i++) {
		pcn_tx_desc_t	*txd = &pcnp->pcn_txdescp[i];
		pcn_buf_t	*txb = pcnp->pcn_txbufs[i];

		txd->pcn_txstat = txd->pcn_txctl = txd->pcn_uspace = 0;
		txd->pcn_tbaddr = txb->pb_paddr;
	}
	(void) ddi_dma_sync(pcnp->pcn_txdesc_dmah, 0,
	    PCN_TXRING * sizeof (pcn_tx_desc_t), DDI_DMA_SYNC_FORDEV);

	/* set addresses of decriptors */
	pcn_csr_write(pcnp, PCN_CSR_RXADDR0, pcnp->pcn_rxdesc_paddr & 0xFFFF);
	pcn_csr_write(pcnp, PCN_CSR_RXADDR1,
	    (pcnp->pcn_rxdesc_paddr >> 16) & 0xFFFF);

	pcn_csr_write(pcnp, PCN_CSR_TXADDR0, pcnp->pcn_txdesc_paddr & 0xFFFF);
	pcn_csr_write(pcnp, PCN_CSR_TXADDR1,
	    (pcnp->pcn_txdesc_paddr >> 16) & 0xFFFF);

	/* set the ring sizes */
	pcn_csr_write(pcnp, PCN_CSR_RXRINGLEN, (~PCN_RXRING) + 1);
	pcn_csr_write(pcnp, PCN_CSR_TXRINGLEN, (~PCN_TXRING) + 1);
}

static void
pcn_destroybuf(pcn_buf_t *buf)
{
	if (buf == NULL)
		return;

	if (buf->pb_paddr)
		(void) ddi_dma_unbind_handle(buf->pb_dmah);
	if (buf->pb_acch)
		ddi_dma_mem_free(&buf->pb_acch);
	if (buf->pb_dmah)
		ddi_dma_free_handle(&buf->pb_dmah);
	kmem_free(buf, sizeof (*buf));
}

static pcn_buf_t *
pcn_allocbuf(pcn_t *pcnp)
{
	pcn_buf_t		*buf;
	size_t			len;
	unsigned		ccnt;
	ddi_dma_cookie_t	dmac;

	buf = kmem_zalloc(sizeof (*buf), KM_SLEEP);

	if (ddi_dma_alloc_handle(pcnp->pcn_dip, &pcn_dma_attr, DDI_DMA_SLEEP,
	    NULL, &buf->pb_dmah) != DDI_SUCCESS) {
		kmem_free(buf, sizeof (*buf));
		return (NULL);
	}

	if (ddi_dma_mem_alloc(buf->pb_dmah, PCN_BUFSZ, &pcn_bufattr,
	    DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL, &buf->pb_buf, &len,
	    &buf->pb_acch) != DDI_SUCCESS) {
		pcn_destroybuf(buf);
		return (NULL);
	}

	if (ddi_dma_addr_bind_handle(buf->pb_dmah, NULL, buf->pb_buf, len,
	    DDI_DMA_READ | DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL, &dmac,
	    &ccnt) != DDI_DMA_MAPPED) {
		pcn_destroybuf(buf);
		return (NULL);
	}
	buf->pb_paddr = dmac.dmac_address;

	return (buf);
}

static int
pcn_alloctxring(pcn_t *pcnp)
{
	int			rval;
	int			i;
	size_t			size;
	size_t			len;
	ddi_dma_cookie_t	dmac;
	unsigned		ncookies;
	caddr_t			kaddr;

	size = PCN_TXRING * sizeof (pcn_tx_desc_t);

	rval = ddi_dma_alloc_handle(pcnp->pcn_dip, &pcn_dma_attr, DDI_DMA_SLEEP,
	    NULL, &pcnp->pcn_txdesc_dmah);
	if (rval != DDI_SUCCESS) {
		pcn_error(pcnp->pcn_dip, "unable to allocate DMA handle for tx "
		    "descriptors");
		return (DDI_FAILURE);
	}

	rval = ddi_dma_mem_alloc(pcnp->pcn_txdesc_dmah, size, &pcn_devattr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &kaddr, &len,
	    &pcnp->pcn_txdesc_acch);
	if (rval != DDI_SUCCESS) {
		pcn_error(pcnp->pcn_dip, "unable to allocate DMA memory for tx "
		    "descriptors");
		return (DDI_FAILURE);
	}

	rval = ddi_dma_addr_bind_handle(pcnp->pcn_txdesc_dmah, NULL, kaddr,
	    size, DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &dmac,
	    &ncookies);
	if (rval != DDI_DMA_MAPPED) {
		pcn_error(pcnp->pcn_dip, "unable to bind DMA for tx "
		    "descriptors");
		return (DDI_FAILURE);
	}

	ASSERT(ncookies == 1);

	pcnp->pcn_txdesc_paddr = dmac.dmac_address;
	pcnp->pcn_txdescp = (void *)kaddr;

	pcnp->pcn_txbufs = kmem_zalloc(PCN_TXRING * sizeof (pcn_buf_t *),
	    KM_SLEEP);

	for (i = 0; i < PCN_TXRING; i++) {
		pcn_buf_t *txb = pcn_allocbuf(pcnp);
		if (txb == NULL)
			return (DDI_FAILURE);
		pcnp->pcn_txbufs[i] = txb;
	}

	return (DDI_SUCCESS);
}

static int
pcn_allocrxring(pcn_t *pcnp)
{
	int			rval;
	int			i;
	size_t			len;
	size_t			size;
	ddi_dma_cookie_t	dmac;
	unsigned		ncookies;
	caddr_t			kaddr;

	size = PCN_RXRING * sizeof (pcn_rx_desc_t);

	rval = ddi_dma_alloc_handle(pcnp->pcn_dip, &pcn_dmadesc_attr,
	    DDI_DMA_SLEEP, NULL, &pcnp->pcn_rxdesc_dmah);
	if (rval != DDI_SUCCESS) {
		pcn_error(pcnp->pcn_dip, "unable to allocate DMA handle for rx "
		    "descriptors");
		return (DDI_FAILURE);
	}

	rval = ddi_dma_mem_alloc(pcnp->pcn_rxdesc_dmah, size, &pcn_devattr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &kaddr, &len,
	    &pcnp->pcn_rxdesc_acch);
	if (rval != DDI_SUCCESS) {
		pcn_error(pcnp->pcn_dip, "unable to allocate DMA memory for rx "
		    "descriptors");
		return (DDI_FAILURE);
	}

	rval = ddi_dma_addr_bind_handle(pcnp->pcn_rxdesc_dmah, NULL, kaddr,
	    size, DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &dmac,
	    &ncookies);
	if (rval != DDI_DMA_MAPPED) {
		pcn_error(pcnp->pcn_dip, "unable to bind DMA for rx "
		    "descriptors");
		return (DDI_FAILURE);
	}

	ASSERT(ncookies == 1);

	pcnp->pcn_rxdesc_paddr = dmac.dmac_address;
	pcnp->pcn_rxdescp = (void *)kaddr;

	pcnp->pcn_rxbufs = kmem_zalloc(PCN_RXRING * sizeof (pcn_buf_t *),
	    KM_SLEEP);

	for (i = 0; i < PCN_RXRING; i++) {
		pcn_buf_t *rxb = pcn_allocbuf(pcnp);
		if (rxb == NULL)
			return (DDI_FAILURE);
		pcnp->pcn_rxbufs[i] = rxb;
	}

	return (DDI_SUCCESS);
}

static void
pcn_freetxring(pcn_t *pcnp)
{
	int	i;

	if (pcnp->pcn_txbufs) {
		for (i = 0; i < PCN_TXRING; i++)
			pcn_destroybuf(pcnp->pcn_txbufs[i]);

		kmem_free(pcnp->pcn_txbufs, PCN_TXRING * sizeof (pcn_buf_t *));
	}

	if (pcnp->pcn_txdesc_paddr)
		(void) ddi_dma_unbind_handle(pcnp->pcn_txdesc_dmah);
	if (pcnp->pcn_txdesc_acch)
		ddi_dma_mem_free(&pcnp->pcn_txdesc_acch);
	if (pcnp->pcn_txdesc_dmah)
		ddi_dma_free_handle(&pcnp->pcn_txdesc_dmah);
}

static void
pcn_freerxring(pcn_t *pcnp)
{
	int	i;

	if (pcnp->pcn_rxbufs) {
		for (i = 0; i < PCN_RXRING; i++)
			pcn_destroybuf(pcnp->pcn_rxbufs[i]);

		kmem_free(pcnp->pcn_rxbufs, PCN_RXRING * sizeof (pcn_buf_t *));
	}

	if (pcnp->pcn_rxdesc_paddr)
		(void) ddi_dma_unbind_handle(pcnp->pcn_rxdesc_dmah);
	if (pcnp->pcn_rxdesc_acch)
		ddi_dma_mem_free(&pcnp->pcn_rxdesc_acch);
	if (pcnp->pcn_rxdesc_dmah)
		ddi_dma_free_handle(&pcnp->pcn_rxdesc_dmah);
}

static int
pcn_set_chipid(pcn_t *pcnp, uint32_t conf_id)
{
	char *name = NULL;
	uint32_t chipid;

	/*
	 * Note: we can *NOT* put the chip into 32-bit mode yet. If a
	 * lance ethernet device is present and pcn tries to attach, it can
	 * hang the device (requiring a hardware reset), since they only work
	 * in 16-bit mode.
	 *
	 * The solution is check using 16-bit operations first, and determine
	 * if 32-bit mode operations are supported.
	 *
	 * The safest way to do this is to read the PCI subsystem ID from
	 * BCR23/24 and compare that with the value read from PCI config
	 * space.
	 */
	chipid = pcn_bcr_read16(pcnp, PCN_BCR_PCISUBSYSID);
	chipid <<= 16;
	chipid |= pcn_bcr_read16(pcnp, PCN_BCR_PCISUBVENID);

	/*
	 * The test for 0x10001000 is a hack to pacify VMware, who's
	 * pseudo-PCnet interface is broken. Reading the subsystem register
	 * from PCI config space yields 0x00000000 while reading the same value
	 * from I/O space yields 0x10001000. It's not supposed to be that way.
	 */
	if (chipid == conf_id || chipid == 0x10001000) {
		/* We're in 16-bit mode. */
		chipid = pcn_csr_read16(pcnp, PCN_CSR_CHIPID1);
		chipid <<= 16;
		chipid |= pcn_csr_read16(pcnp, PCN_CSR_CHIPID0);
	} else {
		chipid = pcn_csr_read(pcnp, PCN_CSR_CHIPID1);
		chipid <<= 16;
		chipid |= pcn_csr_read(pcnp, PCN_CSR_CHIPID0);
	}

	chipid = CHIPID_PARTID(chipid);

	/* Set default value and override as needed */
	switch (chipid) {
	case Am79C970:
		name = "Am79C970 PCnet-PCI";
		pcn_error(pcnp->pcn_dip, "Unsupported chip: %s", name);
		return (DDI_FAILURE);
	case Am79C970A:
		name = "Am79C970A PCnet-PCI II";
		pcn_error(pcnp->pcn_dip, "Unsupported chip: %s", name);
		return (DDI_FAILURE);
	case Am79C971:
		name = "Am79C971 PCnet-FAST";
		break;
	case Am79C972:
		name = "Am79C972 PCnet-FAST+";
		break;
	case Am79C973:
		name = "Am79C973 PCnet-FAST III";
		break;
	case Am79C975:
		name = "Am79C975 PCnet-FAST III";
		break;
	case Am79C976:
		name = "Am79C976";
		break;
	case Am79C978:
		name = "Am79C978";
		break;
	default:
		name = "Unknown";
		pcn_error(pcnp->pcn_dip, "Unknown chip id 0x%x", chipid);
	}

	if (ddi_prop_update_string(DDI_DEV_T_NONE, pcnp->pcn_dip, "chipid",
	    name) != DDI_SUCCESS) {
		pcn_error(pcnp->pcn_dip, "Unable to set chipid property");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
pcn_error(dev_info_t *dip, char *fmt, ...)
{
	va_list	ap;
	char	buf[256];

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	if (dip)
		cmn_err(CE_WARN, "%s%d: %s", ddi_driver_name(dip),
		    ddi_get_instance(dip), buf);
	else
		cmn_err(CE_WARN, "pcn: %s", buf);
}
