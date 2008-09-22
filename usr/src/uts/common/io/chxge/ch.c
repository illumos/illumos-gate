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

/*
 * This file is part of the Chelsio T1 Ethernet driver.
 *
 * Copyright (C) 2003-2005 Chelsio Communications.  All rights reserved.
 */

/*
 * Solaris Multithreaded STREAMS DLPI Chelsio PCI Ethernet Driver
 */

/* #define CH_DEBUG 1 */
#ifdef CH_DEBUG
#define	DEBUG_ENTER(a) debug_enter(a)
#define	PRINT(a) printf a
#else
#define	DEBUG_ENTER(a)
#define	PRINT(a)
#endif

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strlog.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/kstat.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <inet/common.h>
#include <inet/nd.h>
#include <inet/ip.h>
#include <inet/tcp.h>
#include <sys/pattr.h>
#include <sys/gld.h>
#include "ostypes.h"
#include "common.h"
#include "oschtoe.h"
#include "sge.h"
#include "regs.h"
#include "ch.h"			/* Chelsio Driver specific parameters */
#include "version.h"

/*
 * Function prototypes.
 */
static int ch_attach(dev_info_t *, ddi_attach_cmd_t);
static int ch_detach(dev_info_t *, ddi_detach_cmd_t);
static int ch_quiesce(dev_info_t *);
static void ch_free_dma_handles(ch_t *chp);
static void ch_set_name(ch_t *chp, int unit);
static void ch_free_name(ch_t *chp);
static void ch_get_prop(ch_t *chp);

#if defined(__sparc)
static void ch_free_dvma_handles(ch_t *chp);
#endif

/* GLD interfaces */
static int ch_reset(gld_mac_info_t *);
static int ch_start(gld_mac_info_t *);
static int ch_stop(gld_mac_info_t *);
static int ch_set_mac_address(gld_mac_info_t *, uint8_t *);
static int ch_set_multicast(gld_mac_info_t *, uint8_t *, int);
static int ch_ioctl(gld_mac_info_t *, queue_t *, mblk_t *);
static int ch_set_promiscuous(gld_mac_info_t *, int);
static int ch_get_stats(gld_mac_info_t *, struct gld_stats *);
static int ch_send(gld_mac_info_t *, mblk_t *);
static uint_t ch_intr(gld_mac_info_t *);

/*
 * Data access requirements.
 */
static struct ddi_device_acc_attr le_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * No swap mapping device attributes
 */
static struct ddi_device_acc_attr null_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * STREAMS driver identification struture module_info(9s)
 *
 * driver limit values
 */

static	struct module_info ch_minfo = {
	CHIDNUM,	/* mi_idnum */
	CHNAME,		/* mi_idname */
	CHMINPSZ,	/* mi_minpsz */
	CHMAXPSZ,	/* mi_maxpsz */
	CHHIWAT,	/* mi_hiwat */
	CHLOWAT		/* mi_lowat */
};

/*
 * STREAMS queue processiong procedures qinit(9s)
 *
 * read queue procedures
 */

static struct qinit ch_rinit = {
	(int (*)()) NULL, 	/* qi_putp */
	gld_rsrv,		/* qi_srvp */
	gld_open,		/* qi_qopen */
	gld_close,		/* qi_qclose */
	(int (*)()) NULL, 	/* qi_qadmin */
	&ch_minfo,		/* qi_minfo */
	NULL			/* qi_mstat */
};

/*
 * STREAMS queue processiong procedures qinit(9s)
 *
 * write queue procedures
 */

static struct qinit ch_winit = {
	gld_wput,		/* qi_putp */
	gld_wsrv,		/* qi_srvp */
	(int (*)()) NULL, 	/* qi_qopen */
	(int (*)()) NULL, 	/* qi_qclose */
	(int (*)()) NULL, 	/* qi_qadmin */
	&ch_minfo,		/* qi_minfo */
	NULL			/* qi_mstat */
};

/*
 * STREAMS entity declaration structure - streamtab(9s)
 */
static struct streamtab	chinfo = {
	&ch_rinit,	/* read queue information */
	&ch_winit,	/* write queue information */
	NULL,		/* st_muxrinit */
	NULL		/* st_muxwrinit */
};

/*
 * Device driver ops vector - cb_ops(9s)
 *
 * charater/block entry points structure.
 * chinfo identifies driver as a STREAMS driver.
 */

static struct cb_ops cb_ch_ops = {
	nulldev,	/* cb_open */
	nulldev,	/* cb_close */
	nodev,		/* cb_strategy */
	nodev,		/* cb_print */
	nodev,		/* cb_dump */
	nodev,		/* cb_read */
	nodev,		/* cb_write */
	nodev,		/* cb_ioctl */
	nodev,		/* cb_devmap */
	nodev,		/* cb_mmap */
	nodev,		/* cb_segmap */
	nochpoll,	/* cb_chpoll */
	ddi_prop_op,	/* report driver property information - prop_op(9e) */
	&chinfo,	/* cb_stream */
#if defined(__sparc)
	D_MP | D_64BIT,
#else
	D_MP,		/* cb_flag (supports multi-threading) */
#endif
	CB_REV,		/* cb_rev */
	nodev,		/* cb_aread */
	nodev		/* cb_awrite */
};

/*
 * dev_ops(9S) structure
 *
 * Device Operations table, for autoconfiguration
 */

static	struct dev_ops ch_ops = {
	DEVO_REV,	/* Driver build version */
	0,		/* Initial driver reference count */
	gld_getinfo,	/* funcp: get driver information - getinfo(9e) */
	nulldev,	/* funcp: entry point obsolute - identify(9e) */
	nulldev,	/* funp: probe for device - probe(9e) */
	ch_attach,	/* funp: attach driver to dev_info - attach(9e) */
	ch_detach,	/* funp: detach driver to unload - detach(9e) */
	nodev,		/* funp: reset device (not supported) - dev_ops(9s) */
	&cb_ch_ops,	/* ptr to cb_ops structure */
	NULL,		/* ptr to nexus bus operations structure (leaf) */
	NULL,		/* funp: change device power level - power(9e) */
	ch_quiesce,	/* devo_quiesce */
};

/*
 * modldrv(9s) structure
 *
 * Definition for module specific device driver linkage structures (modctl.h)
 */

static struct modldrv modldrv = {
	&mod_driverops,		/* driver module */
	VERSION,
	&ch_ops,		/* driver ops */
};

/*
 * modlinkage(9s) structure
 *
 * module linkage base structure (modctl.h)
 */

static struct modlinkage modlinkage = {
	MODREV_1,		/* revision # of system */
	&modldrv,		/* NULL terminated list of linkage strucures */
	NULL
};

/* ===================== start of STREAMS driver code ================== */

#ifdef CONFIG_CHELSIO_T1_OFFLOAD
/*
 * global pointer to toe per-driver control structure.
 */
#define	MAX_CARDS	4
ch_t *gchp[MAX_CARDS];
#endif

kmutex_t in_use_l;
uint32_t buffers_in_use[SZ_INUSE];
uint32_t in_use_index;

/*
 * Ethernet broadcast address definition.
 */
static struct ether_addr etherbroadcastaddr = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

/*
 * Module initialization functions.
 *
 *      Routine         Called by
 *      _init(9E)       modload(9F)
 *      _info(9E)       modinfo(9F)
 *      _fini(9E)       modunload(9F)
 */

/*
 * _init(9E):
 *
 * Initial, one-time, resource allocation and data initialization.
 */

int
_init(void)
{
	int status;

	status = mod_install(&modlinkage);

	mutex_init(&in_use_l, NULL, MUTEX_DRIVER, NULL);

	return (status);
}

/*
 * _fini(9E): It is here that any device information that was allocated
 * during the _init(9E) routine should be released and the module removed
 * from the system.  In the case of per-instance information, that information
 * should be released in the _detach(9E) routine.
 */

int
_fini(void)
{
	int status;
	int i;
	uint32_t t = 0;

	for (i = 0; i < SZ_INUSE; i++)
		t += buffers_in_use[i];

	if (t != NULL)
		return (DDI_FAILURE);

	status = mod_remove(&modlinkage);

	if (status == DDI_SUCCESS)
		mutex_destroy(&in_use_l);

	return (status);
}

int
_info(struct modinfo *modinfop)
{
	int status;


	status = mod_info(&modlinkage, modinfop);

	return (status);
}

/*
 * Attach(9E) - This is called on the open to the device.  It creates
 * an instance of the driver.  In this routine we create the minor
 * device node.  The routine also initializes all per-unit
 * mutex's and conditional variables.
 *
 * If we were resuming a suspended instance of a device due to power
 * management, then that would be handled here as well.  For more on
 * that subject see the man page for pm(9E)
 *
 * Interface exists: make available by filling in network interface
 * record.  System will initialize the interface when it is ready
 * to accept packets.
 */
int chdebug = 0;
int ch_abort_debug = 0;

static int
ch_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	ch_t *chp;
	int rv;
	int unit;
#ifdef CH_DEBUG
	int Version;
	int VendorID;
	int DeviceID;
	int SubDeviceID;
	int Command;
#endif
	gld_mac_info_t *macinfo;		/* GLD stuff follows */
	char *driver;

	if (ch_abort_debug)
		debug_enter("ch_attach");

	if (chdebug)
		return (DDI_FAILURE);


	if (cmd == DDI_ATTACH) {

		unit = ddi_get_instance(dip);

		driver = (char *)ddi_driver_name(dip);

		PRINT(("driver %s unit: %d\n", driver, unit));

		macinfo = gld_mac_alloc(dip);
		if (macinfo == NULL) {
			PRINT(("macinfo allocation failed\n"));
			DEBUG_ENTER("ch_attach");
			return (DDI_FAILURE);
		}

		chp = (ch_t *)kmem_zalloc(sizeof (ch_t), KM_SLEEP);

		if (chp == NULL) {
			PRINT(("zalloc of chp failed\n"));
			DEBUG_ENTER("ch_attach");

			gld_mac_free(macinfo);

			return (DDI_FAILURE);
		}

#ifdef CONFIG_CHELSIO_T1_OFFLOAD
		/* Solaris TOE support */
		gchp[unit] = chp;
#endif

		PRINT(("attach macinfo: %p chp: %p\n", macinfo, chp));

		chp->ch_dip  = dip;
		chp->ch_macp = macinfo;
		chp->ch_unit = unit;
		ch_set_name(chp, unit);

		/*
		 * map in PCI register spaces
		 *
		 * PCI register set 0 - PCI configuration space
		 * PCI register set 1 - T101 card register space #1
		 */

		/* map in T101 PCI configuration space */
		rv = pci_config_setup(
		    dip,		/* ptr to dev's dev_info struct */
		    &chp->ch_hpci);	/* ptr to data access handle */

		if (rv != DDI_SUCCESS) {
			PRINT(("PCI config setup failed\n"));
			DEBUG_ENTER("ch_attach");
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
			gchp[unit] = NULL;
#endif
			cmn_err(CE_WARN, "%s: ddi_config_setup PCI error %d\n",
			    chp->ch_name, rv);

			ch_free_name(chp);
			kmem_free(chp, sizeof (ch_t));
			gld_mac_free(macinfo);

			return (DDI_FAILURE);
		}

		ch_get_prop(chp);

		macinfo->gldm_devinfo = dip;
		macinfo->gldm_private = (caddr_t)chp;
		macinfo->gldm_reset = ch_reset;
		macinfo->gldm_start = ch_start;
		macinfo->gldm_stop = ch_stop;
		macinfo->gldm_set_mac_addr = ch_set_mac_address;
		macinfo->gldm_send = ch_send;
		macinfo->gldm_set_promiscuous = ch_set_promiscuous;
		macinfo->gldm_get_stats = ch_get_stats;
		macinfo->gldm_ioctl = ch_ioctl;
		macinfo->gldm_set_multicast = ch_set_multicast;
		macinfo->gldm_intr = ch_intr;
		macinfo->gldm_mctl = NULL;

		macinfo->gldm_ident = driver;
		macinfo->gldm_type = DL_ETHER;
		macinfo->gldm_minpkt = 0;
		macinfo->gldm_maxpkt = chp->ch_mtu;
		macinfo->gldm_addrlen = ETHERADDRL;
		macinfo->gldm_saplen = -2;
		macinfo->gldm_ppa = unit;
		macinfo->gldm_broadcast_addr =
		    etherbroadcastaddr.ether_addr_octet;


		/*
		 * do a power reset of card
		 *
		 * 1. set PwrState to D3hot (3)
		 * 2. clear PwrState flags
		 */
		pci_config_put32(chp->ch_hpci, 0x44, 3);
		pci_config_put32(chp->ch_hpci, 0x44, 0);

		/* delay .5 sec */
		DELAY(500000);

#ifdef CH_DEBUG
		VendorID    = pci_config_get16(chp->ch_hpci, 0);
		DeviceID    = pci_config_get16(chp->ch_hpci, 2);
		SubDeviceID = pci_config_get16(chp->ch_hpci, 0x2e);
		Command = pci_config_get16(chp->ch_hpci, 4);

		PRINT(("IDs: %x,%x,%x\n", VendorID, DeviceID, SubDeviceID));
		PRINT(("Command: %x\n", Command));
#endif
		/* map in T101 register space (BAR0) */
		rv = ddi_regs_map_setup(
		    dip,		/* ptr to dev's dev_info struct */
		    BAR0,		/* register address space */
		    &chp->ch_bar0,	/* address of offset */
		    0,		/* offset into register address space */
		    0,		/* length mapped (everything) */
		    &le_attr,	/* ptr to device attr structure */
		    &chp->ch_hbar0);	/* ptr to data access handle */

		if (rv != DDI_SUCCESS) {
			PRINT(("map registers failed\n"));
			DEBUG_ENTER("ch_attach");
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
			gchp[unit] = NULL;
#endif
			cmn_err(CE_WARN,
			    "%s: ddi_regs_map_setup BAR0 error %d\n",
			    chp->ch_name, rv);

			pci_config_teardown(&chp->ch_hpci);
			ch_free_name(chp);
			kmem_free(chp, sizeof (ch_t));
			gld_mac_free(macinfo);

			return (DDI_FAILURE);
		}

#ifdef CH_DEBUG
		Version  = ddi_get32(chp->ch_hbar0,
		    (uint32_t *)(chp->ch_bar0+0x6c));
#endif

		(void) ddi_dev_regsize(dip, 1, &chp->ch_bar0sz);

		PRINT(("PCI BAR0 space addr: %p\n", chp->ch_bar0));
		PRINT(("PCI BAR0 space size: %x\n", chp->ch_bar0sz));
		PRINT(("PE Version: %x\n", Version));

		/*
		 * Add interrupt to system.
		 */
		rv = ddi_get_iblock_cookie(
		    dip,		   /* ptr to dev's dev_info struct */
		    0,		   /* interrupt # (0) */
		    &chp->ch_icookp); /* ptr to interrupt block cookie */

		if (rv != DDI_SUCCESS) {
			PRINT(("iblock cookie failed\n"));
			DEBUG_ENTER("ch_attach");
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
			gchp[unit] = NULL;
#endif
			cmn_err(CE_WARN,
			    "%s: ddi_get_iblock_cookie error %d\n",
			    chp->ch_name, rv);

			ddi_regs_map_free(&chp->ch_hbar0);
			pci_config_teardown(&chp->ch_hpci);
			ch_free_name(chp);
			kmem_free(chp, sizeof (ch_t));
			gld_mac_free(macinfo);

			return (DDI_FAILURE);
		}

		/*
		 * add interrupt handler before card setup.
		 */
		rv = ddi_add_intr(
		    dip,		/* ptr to dev's dev_info struct */
		    0,		/* interrupt # (0) */
		    0,		/* iblock cookie ptr (NULL) */
		    0,		/* idevice cookie ptr (NULL) */
		    gld_intr,	/* function ptr to interrupt handler */
		    (caddr_t)macinfo);	/* handler argument */

		if (rv != DDI_SUCCESS) {
			PRINT(("add_intr failed\n"));
			DEBUG_ENTER("ch_attach");
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
			gchp[unit] = NULL;
#endif
			cmn_err(CE_WARN, "%s: ddi_add_intr error %d\n",
			    chp->ch_name, rv);

			ddi_regs_map_free(&chp->ch_hbar0);
			pci_config_teardown(&chp->ch_hpci);
			ch_free_name(chp);
			kmem_free(chp, sizeof (ch_t));
			gld_mac_free(macinfo);

			return (DDI_FAILURE);
		}

		/* initalize all the remaining per-card locks */
		mutex_init(&chp->ch_lock, NULL, MUTEX_DRIVER,
		    (void *)chp->ch_icookp);
		mutex_init(&chp->ch_intr, NULL, MUTEX_DRIVER,
		    (void *)chp->ch_icookp);
		mutex_init(&chp->ch_mc_lck, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&chp->ch_dh_lck, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&chp->mac_lock, NULL, MUTEX_DRIVER, NULL);

		/* ------- initialize Chelsio card ------- */

		if (pe_attach(chp)) {
			PRINT(("card initialization failed\n"));
			DEBUG_ENTER("ch_attach");
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
			gchp[unit] = NULL;
#endif
			cmn_err(CE_WARN, "%s: pe_attach failed\n",
			    chp->ch_name);

			mutex_destroy(&chp->ch_lock);
			mutex_destroy(&chp->ch_intr);
			mutex_destroy(&chp->ch_mc_lck);
			mutex_destroy(&chp->ch_dh_lck);
			mutex_destroy(&chp->mac_lock);
			ddi_remove_intr(dip, 0, chp->ch_icookp);
			ddi_regs_map_free(&chp->ch_hbar0);
			pci_config_teardown(&chp->ch_hpci);
			ch_free_name(chp);
			kmem_free(chp, sizeof (ch_t));
			gld_mac_free(macinfo);

			return (DDI_FAILURE);
		}

		/* ------- done with Chelsio card ------- */

		/* now can  set mac address */
		macinfo->gldm_vendor_addr = pe_get_mac(chp);

		macinfo->gldm_cookie = chp->ch_icookp;

		/*
		 * We only active checksum offload for T2 architectures.
		 */
		if (is_T2(chp)) {
			if (chp->ch_config.cksum_enabled)
				macinfo->gldm_capabilities |=
				    GLD_CAP_CKSUM_FULL_V4;
		} else
			chp->ch_config.cksum_enabled = 0;

		rv = gld_register(
		    dip,		/* ptr to dev's dev_info struct */
		    (char *)ddi_driver_name(dip),	/* driver name */
		    macinfo);	/* ptr to gld macinfo buffer */

		/*
		 * The Jumbo frames capability is not yet available
		 * in Solaris 10 so registration will fail. MTU > 1500 is
		 * supported in Update 1.
		 */
		if (rv != DDI_SUCCESS) {
			cmn_err(CE_NOTE, "MTU > 1500 not supported by GLD.\n");
			cmn_err(CE_NOTE, "Setting MTU to 1500. \n");
			macinfo->gldm_maxpkt = chp->ch_mtu = 1500;
			rv = gld_register(
			    dip,	/* ptr to dev's dev_info struct */
			    (char *)ddi_driver_name(dip), /* driver name */
			    macinfo); /* ptr to gld macinfo buffer */
		}


		if (rv != DDI_SUCCESS) {
			PRINT(("gld_register failed\n"));
			DEBUG_ENTER("ch_attach");

			cmn_err(CE_WARN, "%s: gld_register error %d\n",
			    chp->ch_name, rv);

			pe_detach(chp);

			mutex_destroy(&chp->ch_lock);
			mutex_destroy(&chp->ch_intr);
			mutex_destroy(&chp->ch_mc_lck);
			mutex_destroy(&chp->ch_dh_lck);
			mutex_destroy(&chp->mac_lock);
			ddi_remove_intr(dip, 0, chp->ch_icookp);
			ddi_regs_map_free(&chp->ch_hbar0);
			pci_config_teardown(&chp->ch_hpci);
			ch_free_name(chp);
			kmem_free(chp, sizeof (ch_t));
			gld_mac_free(macinfo);

			return (DDI_FAILURE);
		}

		/*
		 * print a banner at boot time (verbose mode), announcing
		 * the device pointed to by dip
		 */
		ddi_report_dev(dip);

		if (ch_abort_debug)
			debug_enter("ch_attach");

		return (DDI_SUCCESS);

	} else if (cmd == DDI_RESUME) {
		PRINT(("attach resume\n"));
		DEBUG_ENTER("ch_attach");
		if ((chp = (ch_t *)ddi_get_driver_private(dip)) == NULL)
			return (DDI_FAILURE);

		mutex_enter(&chp->ch_lock);
		chp->ch_flags &= ~PESUSPENDED;
		mutex_exit(&chp->ch_lock);
		return (DDI_SUCCESS);
	} else {
		PRINT(("attach: bad command\n"));
		DEBUG_ENTER("ch_attach");

		return (DDI_FAILURE);
	}
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
ch_quiesce(dev_info_t *dip)
{
	ch_t *chp;
	gld_mac_info_t *macinfo =
	    (gld_mac_info_t *)ddi_get_driver_private(dip);

	chp = (ch_t *)macinfo->gldm_private;
	chdebug = 0;
	ch_abort_debug = 0;

#ifdef CONFIG_CHELSIO_T1_OFFLOAD
	gchp[chp->ch_unit] = NULL;
#endif

	/* Set driver state for this card to IDLE */
	chp->ch_state = PEIDLE;

	/*
	 * Do a power reset of card
	 * 1. set PwrState to D3hot (3)
	 * 2. clear PwrState flags
	 */
	pci_config_put32(chp->ch_hpci, 0x44, 3);
	pci_config_put32(chp->ch_hpci, 0x44, 0);

	/* Wait 0.5 sec */
	drv_usecwait(500000);

	/*
	 * Now stop the chip
	 */
	chp->ch_refcnt = 0;
	chp->ch_state = PESTOP;

	/* Disables all interrupts */
	t1_interrupts_disable(chp);

	/* Disables SGE queues */
	t1_write_reg_4(chp->sge->obj, A_SG_CONTROL, 0x0);
	t1_write_reg_4(chp->sge->obj, A_SG_INT_CAUSE, 0x0);

	return (DDI_SUCCESS);
}

static int
ch_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	gld_mac_info_t *macinfo;
	ch_t *chp;

	if (cmd == DDI_DETACH) {
		macinfo = (gld_mac_info_t *)ddi_get_driver_private(dip);
		chp = (ch_t *)macinfo->gldm_private;

		/*
		 * fail detach if there are outstanding mblks still
		 * in use somewhere.
		 */
		DEBUG_ENTER("ch_detach");
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
		mutex_enter(&chp->ch_lock);
		if (chp->ch_refcnt > 0) {
			mutex_exit(&chp->ch_lock);
			return (DDI_FAILURE);
		}
		mutex_exit(&chp->ch_lock);
		gchp[chp->ch_unit] = NULL;
#endif
		/*
		 * set driver state for this card to IDLE. We're
		 * shutting down.
		 */
		mutex_enter(&chp->ch_lock);
		chp->ch_state = PEIDLE;
		mutex_exit(&chp->ch_lock);

		/*
		 * do a power reset of card
		 *
		 * 1. set PwrState to D3hot (3)
		 * 2. clear PwrState flags
		 */
		pci_config_put32(chp->ch_hpci, 0x44, 3);
		pci_config_put32(chp->ch_hpci, 0x44, 0);

		/* delay .5 sec */
		DELAY(500000);

		/* free register resources */
		(void) gld_unregister(macinfo);

		/* make sure no interrupts while shutting down card */
		ddi_remove_intr(dip, 0, chp->ch_icookp);

		/*
		 * reset device and recover resources
		 */
		pe_detach(chp);

		ddi_regs_map_free(&chp->ch_hbar0);
		pci_config_teardown(&chp->ch_hpci);
		mutex_destroy(&chp->ch_lock);
		mutex_destroy(&chp->ch_intr);
		mutex_destroy(&chp->ch_mc_lck);
		mutex_destroy(&chp->ch_dh_lck);
		mutex_destroy(&chp->mac_lock);
		ch_free_dma_handles(chp);
#if defined(__sparc)
		ch_free_dvma_handles(chp);
#endif
		ch_free_name(chp);
		kmem_free(chp, sizeof (ch_t));
		gld_mac_free(macinfo);

		DEBUG_ENTER("ch_detach end");

		return (DDI_SUCCESS);

	} else if ((cmd == DDI_SUSPEND) || (cmd == DDI_PM_SUSPEND)) {
		DEBUG_ENTER("suspend");
		if ((chp = (ch_t *)ddi_get_driver_private(dip)) == NULL)
			return (DDI_FAILURE);
		mutex_enter(&chp->ch_lock);
		chp->ch_flags |= PESUSPENDED;
		mutex_exit(&chp->ch_lock);
#ifdef TODO
		/* Un-initialize (STOP) T101 */
#endif
		return (DDI_SUCCESS);
	} else
		return (DDI_FAILURE);
}

/*
 * ch_alloc_dma_mem
 *
 * allocates DMA handle
 * allocates kernel memory
 * allocates DMA access handle
 *
 * chp - per-board descriptor
 * type - byteswap mapping?
 * flags - type of mapping
 * size - # bytes mapped
 * paddr - physical address
 * dh - ddi dma handle
 * ah - ddi access handle
 */

void *
ch_alloc_dma_mem(ch_t *chp, int type, int flags, int size, uint64_t *paddr,
	ulong_t *dh, ulong_t *ah)
{
	ddi_dma_attr_t ch_dma_attr;
	ddi_dma_cookie_t cookie;
	ddi_dma_handle_t ch_dh;
	ddi_acc_handle_t ch_ah;
	ddi_device_acc_attr_t *dev_attrp;
	caddr_t ch_vaddr;
	size_t rlen;
	uint_t count;
	uint_t mapping;
	uint_t align;
	uint_t rv;
	uint_t direction;

	mapping = (flags&DMA_STREAM)?DDI_DMA_STREAMING:DDI_DMA_CONSISTENT;
	if (flags & DMA_4KALN)
		align = 0x4000;
	else if (flags & DMA_SMALN)
		align = chp->ch_sm_buf_aln;
	else if (flags & DMA_BGALN)
		align = chp->ch_bg_buf_aln;
	else {
		cmn_err(CE_WARN, "ch_alloc_dma_mem(%s): bad alignment flag\n",
		    chp->ch_name);
		return (0);
	}
	direction = (flags&DMA_OUT)?DDI_DMA_WRITE:DDI_DMA_READ;

	/*
	 * dynamically create a dma attribute structure
	 */
	ch_dma_attr.dma_attr_version = DMA_ATTR_V0;
	ch_dma_attr.dma_attr_addr_lo = 0;
	ch_dma_attr.dma_attr_addr_hi = 0xffffffffffffffff;
	ch_dma_attr.dma_attr_count_max = 0x00ffffff;
	ch_dma_attr.dma_attr_align = align;
	ch_dma_attr.dma_attr_burstsizes = 0xfff;
	ch_dma_attr.dma_attr_minxfer = 1;
	ch_dma_attr.dma_attr_maxxfer = 0x00ffffff;
	ch_dma_attr.dma_attr_seg = 0xffffffff;
	ch_dma_attr.dma_attr_sgllen = 1;
	ch_dma_attr.dma_attr_granular = 1;
	ch_dma_attr.dma_attr_flags = 0;

	rv = ddi_dma_alloc_handle(
	    chp->ch_dip,		/* device dev_info structure */
	    &ch_dma_attr,		/* DMA attributes */
	    DDI_DMA_SLEEP,		/* Wait if no memory */
	    NULL,			/* no argument to callback */
	    &ch_dh);			/* DMA handle */
	if (rv != DDI_SUCCESS) {

		cmn_err(CE_WARN,
		    "%s: ch_alloc_dma_mem: ddi_dma_alloc_handle error %d\n",
		    chp->ch_name, rv);

		return (0);
	}

	/* set byte order for data xfer */
	if (type)
		dev_attrp = &null_attr;
	else
		dev_attrp = &le_attr;

	rv = ddi_dma_mem_alloc(
	    ch_dh,		/* dma handle */
	    size,		/* size desired allocate */
	    dev_attrp,		/* access attributes */
	    mapping,
	    DDI_DMA_SLEEP,	/* wait for resources */
	    NULL,		/* no argument */
	    &ch_vaddr,		/* allocated memory */
	    &rlen,		/* real size allocated */
	    &ch_ah);		/* data access handle */
	if (rv != DDI_SUCCESS) {
		ddi_dma_free_handle(&ch_dh);

		cmn_err(CE_WARN,
		    "%s: ch_alloc_dma_mem: ddi_dma_mem_alloc error %d\n",
		    chp->ch_name, rv);

		return (0);
	}

	rv = ddi_dma_addr_bind_handle(
	    ch_dh,				/* dma handle */
	    (struct as *)0,			/* kernel address space */
	    ch_vaddr,				/* virtual address */
	    rlen,				/* length of object */
	    direction|mapping,
	    DDI_DMA_SLEEP,			/* Wait for resources */
	    NULL,				/* no argument */
	    &cookie,				/* dma cookie */
	    &count);
	if (rv != DDI_DMA_MAPPED) {
		ddi_dma_mem_free(&ch_ah);
		ddi_dma_free_handle(&ch_dh);

		cmn_err(CE_WARN,
		    "%s: ch_alloc_dma_mem: ddi_dma_addr_bind_handle error %d\n",
		    chp->ch_name, rv);

		return (0);
	}

	if (count != 1) {
		cmn_err(CE_WARN,
		    "%s: ch_alloc_dma_mem: ch_alloc_dma_mem cookie count %d\n",
		    chp->ch_name, count);
		PRINT(("ch_alloc_dma_mem cookie count %d\n", count));

		ddi_dma_mem_free(&ch_ah);
		ddi_dma_free_handle(&ch_dh);

		return (0);
	}

	*paddr = cookie.dmac_laddress;

	*(ddi_dma_handle_t *)dh = ch_dh;
	*(ddi_acc_handle_t *)ah = ch_ah;

	return ((void *)ch_vaddr);
}

/*
 * ch_free_dma_mem
 *
 * frees resources allocated by ch_alloc_dma_mem()
 *
 * frees DMA handle
 * frees kernel memory
 * frees DMA access handle
 */

void
ch_free_dma_mem(ulong_t dh, ulong_t ah)
{
	ddi_dma_handle_t ch_dh = (ddi_dma_handle_t)dh;
	ddi_acc_handle_t ch_ah = (ddi_acc_handle_t)ah;

	(void) ddi_dma_unbind_handle(ch_dh);
	ddi_dma_mem_free(&ch_ah);
	ddi_dma_free_handle(&ch_dh);
}

/*
 * create a dma handle and return a dma handle entry.
 */
free_dh_t *
ch_get_dma_handle(ch_t *chp)
{
	ddi_dma_handle_t ch_dh;
	ddi_dma_attr_t ch_dma_attr;
	free_dh_t *dhe;
	int rv;

	dhe = (free_dh_t *)kmem_zalloc(sizeof (*dhe), KM_SLEEP);

	ch_dma_attr.dma_attr_version = DMA_ATTR_V0;
	ch_dma_attr.dma_attr_addr_lo = 0;
	ch_dma_attr.dma_attr_addr_hi = 0xffffffffffffffff;
	ch_dma_attr.dma_attr_count_max = 0x00ffffff;
	ch_dma_attr.dma_attr_align = 1;
	ch_dma_attr.dma_attr_burstsizes = 0xfff;
	ch_dma_attr.dma_attr_minxfer = 1;
	ch_dma_attr.dma_attr_maxxfer = 0x00ffffff;
	ch_dma_attr.dma_attr_seg = 0xffffffff;
	ch_dma_attr.dma_attr_sgllen = 5;
	ch_dma_attr.dma_attr_granular = 1;
	ch_dma_attr.dma_attr_flags = 0;

	rv = ddi_dma_alloc_handle(
	    chp->ch_dip,		/* device dev_info */
	    &ch_dma_attr,		/* DMA attributes */
	    DDI_DMA_SLEEP,		/* Wait if no memory */
	    NULL,			/* no argument */
	    &ch_dh);			/* DMA handle */
	if (rv != DDI_SUCCESS) {

		cmn_err(CE_WARN,
		    "%s: ch_get_dma_handle: ddi_dma_alloc_handle error %d\n",
		    chp->ch_name, rv);

		kmem_free(dhe, sizeof (*dhe));

		return ((free_dh_t *)0);
	}

	dhe->dhe_dh = (ulong_t)ch_dh;

	return (dhe);
}

/*
 * free the linked list of dma descriptor entries.
 */
static void
ch_free_dma_handles(ch_t *chp)
{
	free_dh_t *dhe, *the;

	dhe = chp->ch_dh;
	while (dhe) {
		ddi_dma_free_handle((ddi_dma_handle_t *)&dhe->dhe_dh);
		the = dhe;
		dhe = dhe->dhe_next;
		kmem_free(the, sizeof (*the));
	}
	chp->ch_dh = NULL;
}

/*
 * ch_bind_dma_handle()
 *
 * returns # of entries used off of cmdQ_ce_t array to hold physical addrs.
 *
 * chp - per-board descriptor
 * size - # bytes mapped
 * vaddr - virtual address
 * cmp - array of cmdQ_ce_t entries
 * cnt - # free entries in cmp array
 */

uint32_t
ch_bind_dma_handle(ch_t *chp, int size, caddr_t vaddr, cmdQ_ce_t *cmp,
	uint32_t cnt)
{
	ddi_dma_cookie_t cookie;
	ddi_dma_handle_t ch_dh;
	uint_t count;
	uint32_t n = 1;
	free_dh_t *dhe;
	uint_t rv;

	mutex_enter(&chp->ch_dh_lck);
	if ((dhe = chp->ch_dh) != NULL) {
		chp->ch_dh = dhe->dhe_next;
	}
	mutex_exit(&chp->ch_dh_lck);

	if (dhe == NULL) {
		return (0);
	}

	ch_dh = (ddi_dma_handle_t)dhe->dhe_dh;

	rv = ddi_dma_addr_bind_handle(
	    ch_dh,		/* dma handle */
	    (struct as *)0,	/* kernel address space */
	    vaddr,		/* virtual address */
	    size,		/* length of object */
	    DDI_DMA_WRITE|DDI_DMA_STREAMING,
	    DDI_DMA_SLEEP,	/* Wait for resources */
	    NULL,		/* no argument */
	    &cookie,	/* dma cookie */
	    &count);
	if (rv != DDI_DMA_MAPPED) {

		/* return dma header descriptor back to free list */
		mutex_enter(&chp->ch_dh_lck);
		dhe->dhe_next = chp->ch_dh;
		chp->ch_dh = dhe;
		mutex_exit(&chp->ch_dh_lck);

		cmn_err(CE_WARN,
		    "%s: ch_bind_dma_handle: ddi_dma_addr_bind_handle err %d\n",
		    chp->ch_name, rv);

		return (0);
	}

	/*
	 * abort if we've run out of space
	 */
	if (count > cnt) {
		/* return dma header descriptor back to free list */
		mutex_enter(&chp->ch_dh_lck);
		dhe->dhe_next = chp->ch_dh;
		chp->ch_dh = dhe;
		mutex_exit(&chp->ch_dh_lck);

		return (0);
	}

	cmp->ce_pa = cookie.dmac_laddress;
	cmp->ce_dh = NULL;
	cmp->ce_len = cookie.dmac_size;
	cmp->ce_mp = NULL;
	cmp->ce_flg = DH_DMA;

	while (--count) {
		cmp++;
		n++;
		ddi_dma_nextcookie(ch_dh, &cookie);
		cmp->ce_pa = cookie.dmac_laddress;
		cmp->ce_dh = NULL;
		cmp->ce_len = cookie.dmac_size;
		cmp->ce_mp = NULL;
		cmp->ce_flg = DH_DMA;
	}

	cmp->ce_dh = dhe;

	return (n);
}

/*
 * ch_unbind_dma_handle()
 *
 * frees resources alloacted by ch_bind_dma_handle().
 *
 * frees DMA handle
 */

void
ch_unbind_dma_handle(ch_t *chp, free_dh_t *dhe)
{
	ddi_dma_handle_t ch_dh = (ddi_dma_handle_t)dhe->dhe_dh;

	if (ddi_dma_unbind_handle(ch_dh))
		cmn_err(CE_WARN, "%s: ddi_dma_unbind_handle failed",
		    chp->ch_name);

	mutex_enter(&chp->ch_dh_lck);
	dhe->dhe_next = chp->ch_dh;
	chp->ch_dh = dhe;
	mutex_exit(&chp->ch_dh_lck);
}

#if defined(__sparc)
/*
 * DVMA stuff. Solaris only.
 */

/*
 * create a dvma handle and return a dma handle entry.
 * DVMA is on sparc only!
 */

free_dh_t *
ch_get_dvma_handle(ch_t *chp)
{
	ddi_dma_handle_t ch_dh;
	ddi_dma_lim_t ch_dvma_attr;
	free_dh_t *dhe;
	int rv;

	dhe = (free_dh_t *)kmem_zalloc(sizeof (*dhe), KM_SLEEP);

	ch_dvma_attr.dlim_addr_lo = 0;
	ch_dvma_attr.dlim_addr_hi = 0xffffffff;
	ch_dvma_attr.dlim_cntr_max = 0xffffffff;
	ch_dvma_attr.dlim_burstsizes = 0xfff;
	ch_dvma_attr.dlim_minxfer = 1;
	ch_dvma_attr.dlim_dmaspeed = 0;

	rv = dvma_reserve(
	    chp->ch_dip,		/* device dev_info */
	    &ch_dvma_attr,		/* DVMA attributes */
	    3,			/* number of pages */
	    &ch_dh);		/* DVMA handle */

	if (rv != DDI_SUCCESS) {

		cmn_err(CE_WARN,
		    "%s: ch_get_dvma_handle: dvma_reserve() error %d\n",
		    chp->ch_name, rv);

		kmem_free(dhe, sizeof (*dhe));

		return ((free_dh_t *)0);
	}

	dhe->dhe_dh = (ulong_t)ch_dh;

	return (dhe);
}

/*
 * free the linked list of dvma descriptor entries.
 * DVMA is only on sparc!
 */

static void
ch_free_dvma_handles(ch_t *chp)
{
	free_dh_t *dhe, *the;

	dhe = chp->ch_vdh;
	while (dhe) {
		dvma_release((ddi_dma_handle_t)dhe->dhe_dh);
		the = dhe;
		dhe = dhe->dhe_next;
		kmem_free(the, sizeof (*the));
	}
	chp->ch_vdh = NULL;
}

/*
 * ch_bind_dvma_handle()
 *
 * returns # of entries used off of cmdQ_ce_t array to hold physical addrs.
 * DVMA in sparc only
 *
 * chp - per-board descriptor
 * size - # bytes mapped
 * vaddr - virtual address
 * cmp - array of cmdQ_ce_t entries
 * cnt - # free entries in cmp array
 */

uint32_t
ch_bind_dvma_handle(ch_t *chp, int size, caddr_t vaddr, cmdQ_ce_t *cmp,
	uint32_t cnt)
{
	ddi_dma_cookie_t cookie;
	ddi_dma_handle_t ch_dh;
	uint32_t n = 1;
	free_dh_t *dhe;

	mutex_enter(&chp->ch_dh_lck);
	if ((dhe = chp->ch_vdh) != NULL) {
		chp->ch_vdh = dhe->dhe_next;
	}
	mutex_exit(&chp->ch_dh_lck);

	if (dhe == NULL) {
		return (0);
	}

	ch_dh = (ddi_dma_handle_t)dhe->dhe_dh;
	n = cnt;

	dvma_kaddr_load(
	    ch_dh,		/* dvma handle */
	    vaddr,		/* virtual address */
	    size,		/* length of object */
	    0,		/* start at index 0 */
	    &cookie);

	dvma_sync(ch_dh, 0, DDI_DMA_SYNC_FORDEV);

	cookie.dmac_notused = 0;
	n = 1;

	cmp->ce_pa = cookie.dmac_laddress;
	cmp->ce_dh = dhe;
	cmp->ce_len = cookie.dmac_size;
	cmp->ce_mp = NULL;
	cmp->ce_flg = DH_DVMA;	/* indicate a dvma descriptor */

	return (n);
}

/*
 * ch_unbind_dvma_handle()
 *
 * frees resources alloacted by ch_bind_dvma_handle().
 *
 * frees DMA handle
 */

void
ch_unbind_dvma_handle(ch_t *chp, free_dh_t *dhe)
{
	ddi_dma_handle_t ch_dh = (ddi_dma_handle_t)dhe->dhe_dh;

	dvma_unload(ch_dh, 0, -1);

	mutex_enter(&chp->ch_dh_lck);
	dhe->dhe_next = chp->ch_vdh;
	chp->ch_vdh = dhe;
	mutex_exit(&chp->ch_dh_lck);
}

#endif	/* defined(__sparc) */

/*
 * send received packet up stream.
 *
 * if driver has been stopped, then we drop the message.
 */
void
ch_send_up(ch_t *chp, mblk_t *mp, uint32_t cksum, int flg)
{
	/*
	 * probably do not need a lock here. When we set PESTOP in
	 * ch_stop() a packet could have just passed here and gone
	 * upstream. The next one will be dropped.
	 */
	if (chp->ch_state == PERUNNING) {
		/*
		 * note that flg will not be set unless enable_checksum_offload
		 * set in /etc/system (see sge.c).
		 */
		if (flg)
			(void) hcksum_assoc(mp, NULL, NULL, 0, 0, 0, cksum,
			    HCK_FULLCKSUM, 0);
		gld_recv(chp->ch_macp, mp);
	} else {
		freemsg(mp);
	}
}

/*
 * unblock gld driver.
 */
void
ch_gld_ok(ch_t *chp)
{
	gld_sched(chp->ch_macp);
}


/*
 * reset the card.
 *
 * Note: we only do this after the card has been initialized.
 */
static int
ch_reset(gld_mac_info_t *mp)
{
	ch_t *chp;

	if (mp == NULL) {
		return (GLD_FAILURE);
	}

	chp = (ch_t *)mp->gldm_private;

	if (chp == NULL) {
		return (GLD_FAILURE);
	}

#ifdef NOTYET
	/*
	 * do a reset of card
	 *
	 * 1. set PwrState to D3hot (3)
	 * 2. clear PwrState flags
	 */
	/*
	 * When we did this, the card didn't start. First guess is that
	 * the initialization is not quite correct. For now, we don't
	 * reset things.
	 */
	if (chp->ch_hpci) {
		pci_config_put32(chp->ch_hpci, 0x44, 3);
		pci_config_put32(chp->ch_hpci, 0x44, 0);

		/* delay .5 sec */
		DELAY(500000);
	}
#endif

	return (GLD_SUCCESS);
}

static int
ch_start(gld_mac_info_t *macinfo)
{
	ch_t *chp = (ch_t *)macinfo->gldm_private;
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
	/* only initialize card on first attempt */
	mutex_enter(&chp->ch_lock);
	chp->ch_refcnt++;
	if (chp->ch_refcnt == 1) {
		chp->ch_state = PERUNNING;
		mutex_exit(&chp->ch_lock);
		pe_init((void *)chp);
	} else
		mutex_exit(&chp->ch_lock);
#else
	pe_init((void *)chp);

	/* go to running state, we're being started */
	mutex_enter(&chp->ch_lock);
	chp->ch_state = PERUNNING;
	mutex_exit(&chp->ch_lock);
#endif

	return (GLD_SUCCESS);
}

static int
ch_stop(gld_mac_info_t *mp)
{
	ch_t *chp = (ch_t *)mp->gldm_private;

	/*
	 * can only stop the chip if it's been initialized
	 */
	mutex_enter(&chp->ch_lock);
	if (chp->ch_state == PEIDLE) {
		mutex_exit(&chp->ch_lock);
		return (GLD_FAILURE);
	}
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
	chp->ch_refcnt--;
	if (chp->ch_refcnt == 0) {
		chp->ch_state = PESTOP;
		mutex_exit(&chp->ch_lock);
		pe_stop(chp);
	} else
		mutex_exit(&chp->ch_lock);
#else
	chp->ch_state = PESTOP;
	mutex_exit(&chp->ch_lock);
	pe_stop(chp);
#endif
	return (GLD_SUCCESS);
}

static int
ch_set_mac_address(gld_mac_info_t *mp, uint8_t *mac)
{
	ch_t *chp;

	if (mp) {
		chp = (ch_t *)mp->gldm_private;
	} else {
		return (GLD_FAILURE);
	}

	pe_set_mac(chp, mac);

	return (GLD_SUCCESS);
}

static int
ch_set_multicast(gld_mac_info_t *mp, uint8_t *ep, int flg)
{
	ch_t *chp = (ch_t *)mp->gldm_private;

	return (pe_set_mc(chp, ep, flg));
}

static int
ch_ioctl(gld_mac_info_t *macinfo, queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp;

	switch (mp->b_datap->db_type) {
	case M_IOCTL:
		/* pe_ioctl() does qreply() */
		pe_ioctl((ch_t *)(macinfo->gldm_private), q, mp);
		break;

	default:
/*
 *		cmn_err(CE_NOTE, "ch_ioctl not M_IOCTL\n");
 *		debug_enter("bad ch_ioctl");
 */

		iocp = (struct iocblk *)mp->b_rptr;

		if (mp->b_cont)
			freemsg(mp->b_cont);
		mp->b_cont = NULL;

		mp->b_datap->db_type = M_IOCNAK;
		iocp->ioc_error = EINVAL;
		qreply(q, mp);
		break;
	}

	return (GLD_SUCCESS);
}

static int
ch_set_promiscuous(gld_mac_info_t *mp, int flag)
{
	ch_t *chp = (ch_t *)mp->gldm_private;

	switch (flag) {
	case GLD_MAC_PROMISC_MULTI:
		pe_set_promiscuous(chp, 2);
		break;

	case GLD_MAC_PROMISC_NONE:
		pe_set_promiscuous(chp, 0);
		break;

	case GLD_MAC_PROMISC_PHYS:
	default:
		pe_set_promiscuous(chp, 1);
		break;
	}

	return (GLD_SUCCESS);
}

static int
ch_get_stats(gld_mac_info_t *mp, struct gld_stats *gs)
{
	ch_t *chp = (ch_t *)mp->gldm_private;
	uint64_t speed;
	uint32_t intrcnt;
	uint32_t norcvbuf;
	uint32_t oerrors;
	uint32_t ierrors;
	uint32_t underrun;
	uint32_t overrun;
	uint32_t framing;
	uint32_t crc;
	uint32_t carrier;
	uint32_t collisions;
	uint32_t xcollisions;
	uint32_t late;
	uint32_t defer;
	uint32_t xerrs;
	uint32_t rerrs;
	uint32_t toolong;
	uint32_t runt;
	ulong_t multixmt;
	ulong_t multircv;
	ulong_t brdcstxmt;
	ulong_t brdcstrcv;

	/*
	 * race looks benign here.
	 */
	if (chp->ch_state != PERUNNING) {
		return (GLD_FAILURE);
	}

	(void) pe_get_stats(chp,
	    &speed,
	    &intrcnt,
	    &norcvbuf,
	    &oerrors,
	    &ierrors,
	    &underrun,
	    &overrun,
	    &framing,
	    &crc,
	    &carrier,
	    &collisions,
	    &xcollisions,
	    &late,
	    &defer,
	    &xerrs,
	    &rerrs,
	    &toolong,
	    &runt,
	    &multixmt,
	    &multircv,
	    &brdcstxmt,
	    &brdcstrcv);

	gs->glds_speed = speed;
	gs->glds_media = GLDM_UNKNOWN;
	gs->glds_intr  = intrcnt;
	gs->glds_norcvbuf = norcvbuf;
	gs->glds_errxmt = oerrors;
	gs->glds_errrcv = ierrors;
	gs->glds_missed = ierrors;	/* ??? */
	gs->glds_underflow = underrun;
	gs->glds_overflow = overrun;
	gs->glds_frame = framing;
	gs->glds_crc = crc;
	gs->glds_duplex = GLD_DUPLEX_FULL;
	gs->glds_nocarrier = carrier;
	gs->glds_collisions = collisions;
	gs->glds_excoll = xcollisions;
	gs->glds_xmtlatecoll = late;
	gs->glds_defer = defer;
	gs->glds_dot3_first_coll = 0;	/* Not available */
	gs->glds_dot3_multi_coll = 0;	/* Not available */
	gs->glds_dot3_sqe_error = 0;	/* Not available */
	gs->glds_dot3_mac_xmt_error = xerrs;
	gs->glds_dot3_mac_rcv_error = rerrs;
	gs->glds_dot3_frame_too_long = toolong;
	gs->glds_short = runt;

	gs->glds_noxmtbuf = 0;		/* not documented */
	gs->glds_xmtretry = 0;		/* not documented */
	gs->glds_multixmt = multixmt;	/* not documented */
	gs->glds_multircv = multircv;	/* not documented */
	gs->glds_brdcstxmt = brdcstxmt;	/* not documented */
	gs->glds_brdcstrcv = brdcstrcv;	/* not documented */

	return (GLD_SUCCESS);
}


static int
ch_send(gld_mac_info_t *macinfo, mblk_t *mp)
{
	ch_t *chp = (ch_t *)macinfo->gldm_private;
	uint32_t flg;
	uint32_t msg_flg;

#ifdef TX_CKSUM_FIX
	mblk_t *nmp;
	int frags;
	size_t msg_len;
	struct ether_header *ehdr;
	ipha_t *ihdr;
	int tflg = 0;
#endif	/* TX_CKSUM_FIX */

	/*
	 * race looks benign here.
	 */
	if (chp->ch_state != PERUNNING) {
		return (GLD_FAILURE);
	}

	msg_flg = 0;
	if (chp->ch_config.cksum_enabled) {
		if (is_T2(chp)) {
			hcksum_retrieve(mp, NULL, NULL, NULL, NULL, NULL,
			    NULL, &msg_flg);
			flg = (msg_flg & HCK_FULLCKSUM)?
			    CH_NO_CPL: CH_NO_HWCKSUM|CH_NO_CPL;
		} else
			flg = CH_NO_CPL;
	} else
	flg = CH_NO_HWCKSUM | CH_NO_CPL;

#ifdef TX_CKSUM_FIX
	/*
	 * Check if the message spans more than one mblk or
	 * if it does and the ip header is not in the first
	 * fragment then pull up the message. This case is
	 * expected to be rare.
	 */
	frags = 0;
	msg_len = 0;
	nmp = mp;
	do {
		frags++;
		msg_len += MBLKL(nmp);
		nmp = nmp->b_cont;
	} while (nmp);
#define	MAX_ALL_HDRLEN SZ_CPL_TX_PKT + sizeof (struct ether_header) + \
				TCP_MAX_COMBINED_HEADER_LENGTH
	/*
	 * If the first mblk has enough space at the beginning of
	 * the data buffer to hold a CPL header, then, we'll expancd
	 * the front of the buffer so a pullup will leave space for
	 * pe_start() to add the CPL header in line. We need to remember
	 * that we've done this so we can undo it after the pullup.
	 *
	 * Note that if we decide to do an allocb to hold the CPL header,
	 * we need to catch the case where we've added an empty mblk for
	 * the header but never did a pullup. This would result in the
	 * tests for etherheader, etc. being done on the initial, empty,
	 * mblk instead of the one with data. See PR3646 for further
	 * details. (note this PR is closed since it is no longer relevant).
	 *
	 * Another point is that if we do add an allocb to add space for
	 * a CPL header, after a pullup, the initial pointer, mp, in GLD will
	 * no longer point to a valid mblk. When we get the mblk (by allocb),
	 * we need to switch the mblk structure values between it and the
	 * mp structure values referenced by GLD. This handles the case where
	 * we've run out of cmdQ entries and report GLD_NORESOURCES back to
	 * GLD. The pointer to the mblk data will have been modified to hold
	 * an empty 8 bytes for the CPL header, For now, we let the pe_start()
	 * routine prepend an 8 byte mblk.
	 */
	if (MBLKHEAD(mp) >= SZ_CPL_TX_PKT) {
		mp->b_rptr -= SZ_CPL_TX_PKT;
		tflg = 1;
	}
	if (frags > 3) {
		chp->sge->intr_cnt.tx_msg_pullups++;
		if (pullupmsg(mp, -1) == 0) {
			freemsg(mp);
			return (GLD_SUCCESS);
		}
	} else if ((msg_len > MAX_ALL_HDRLEN) &&
	    (MBLKL(mp) < MAX_ALL_HDRLEN)) {
		chp->sge->intr_cnt.tx_hdr_pullups++;
		if (pullupmsg(mp, MAX_ALL_HDRLEN) == 0) {
			freemsg(mp);
			return (GLD_SUCCESS);
		}
	}
	if (tflg)
		mp->b_rptr += SZ_CPL_TX_PKT;

	ehdr = (struct ether_header *)mp->b_rptr;
	if (ehdr->ether_type == htons(ETHERTYPE_IP)) {
		ihdr = (ipha_t *)&mp->b_rptr[sizeof (struct ether_header)];
		if ((ihdr->ipha_fragment_offset_and_flags & IPH_MF)) {
			if (ihdr->ipha_protocol == IPPROTO_UDP) {
				flg |= CH_UDP_MF;
				chp->sge->intr_cnt.tx_udp_ip_frag++;
			} else if (ihdr->ipha_protocol == IPPROTO_TCP) {
				flg |= CH_TCP_MF;
				chp->sge->intr_cnt.tx_tcp_ip_frag++;
			}
		} else if (ihdr->ipha_protocol == IPPROTO_UDP)
			flg |= CH_UDP;
	}
#endif	/* TX_CKSUM_FIX */

	/*
	 * return 0 - data send successfully
	 * return 1 - no resources, reschedule
	 */
	if (pe_start(chp, mp, flg))
		return (GLD_NORESOURCES);
	else
		return (GLD_SUCCESS);
}

static uint_t
ch_intr(gld_mac_info_t *mp)
{
	return (pe_intr((ch_t *)mp->gldm_private));
}

/*
 * generate name of driver with unit# postpended.
 */
void
ch_set_name(ch_t *chp, int unit)
{
	chp->ch_name = (char *)kmem_alloc(sizeof ("chxge00"), KM_SLEEP);
	if (unit > 9) {
		bcopy("chxge00", (void *)chp->ch_name, sizeof ("chxge00"));
		chp->ch_name[5] += unit/10;
		chp->ch_name[6] += unit%10;
	} else {
		bcopy("chxge0", (void *)chp->ch_name, sizeof ("chxge0"));
		chp->ch_name[5] += unit;
	}
}

void
ch_free_name(ch_t *chp)
{
	if (chp->ch_name)
		kmem_free(chp->ch_name, sizeof ("chxge00"));
	chp->ch_name = NULL;
}

#ifdef CONFIG_CHELSIO_T1_OFFLOAD
/*
 * register toe offload.
 */
void *
ch_register(void *instp, void *toe_rcv, void *toe_free, void *toe_tunnel,
    kmutex_t *toe_tx_mx, kcondvar_t *toe_of_cv, int unit)
{
	ch_t *chp = gchp[unit];
	if (chp != NULL) {
		mutex_enter(&chp->ch_lock);

		chp->toe_rcv = (void (*)(void *, mblk_t *))toe_rcv;
		chp->ch_toeinst = instp;
		chp->toe_free = (void (*)(void *, tbuf_t *))toe_free;
		chp->toe_tunnel = (int (*)(void *, mblk_t *))toe_tunnel;
		chp->ch_tx_overflow_mutex = toe_tx_mx;
		chp->ch_tx_overflow_cv = toe_of_cv;
		chp->open_device_map |= TOEDEV_DEVMAP_BIT;

		/* start up adapter if first user */
		chp->ch_refcnt++;
		if (chp->ch_refcnt == 1) {
			chp->ch_state = PERUNNING;
			mutex_exit(&chp->ch_lock);
			pe_init((void *)chp);
		} else
			mutex_exit(&chp->ch_lock);
	}
	return ((void *)gchp[unit]);
}

/*
 * unregister toe offload.
 * XXX Need to fix races here.
 *     1. turn off SGE interrupts.
 *     2. do update
 *     3. re-enable SGE interrupts
 *     4. SGE doorbell to make sure things get restarted.
 */
void
ch_unregister(void)
{
	int i;
	ch_t *chp;

	for (i = 0; i < MAX_CARDS; i++) {
		chp = gchp[i];
		if (chp == NULL)
			continue;

		mutex_enter(&chp->ch_lock);

		chp->ch_refcnt--;
		if (chp->ch_refcnt == 0) {
			chp->ch_state = PESTOP;
			mutex_exit(&chp->ch_lock);
			pe_stop(chp);
		} else
			mutex_exit(&chp->ch_lock);

		chp->open_device_map &= ~TOEDEV_DEVMAP_BIT;
		chp->toe_rcv = NULL;
		chp->ch_toeinst =  NULL;
		chp->toe_free = NULL;
		chp->toe_tunnel = NULL;
		chp->ch_tx_overflow_mutex = NULL;
		chp->ch_tx_overflow_cv = NULL;
	}
}
#endif	/* CONFIG_CHELSIO_T1_OFFLOAD */

/*
 * get properties from chxge.conf
 */
static void
ch_get_prop(ch_t *chp)
{
	int val;
	int tval = 0;
	extern int enable_latency_timer;
	extern uint32_t sge_cmdq0_cnt;
	extern uint32_t sge_cmdq1_cnt;
	extern uint32_t sge_flq0_cnt;
	extern uint32_t sge_flq1_cnt;
	extern uint32_t sge_respq_cnt;
	extern uint32_t sge_cmdq0_cnt_orig;
	extern uint32_t sge_cmdq1_cnt_orig;
	extern uint32_t sge_flq0_cnt_orig;
	extern uint32_t sge_flq1_cnt_orig;
	extern uint32_t sge_respq_cnt_orig;
	dev_info_t *pdip;
	uint32_t vendor_id, device_id, revision_id;
	uint32_t *prop_val = NULL;
	uint32_t prop_len = NULL;

	val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
	    "enable_dvma", -1);
	if (val == -1)
		val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
		    "enable-dvma", -1);
	if (val != -1) {
		if (val != 0)
			chp->ch_config.enable_dvma = 1;
	}

	val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
	    "amd_bug_workaround", -1);
	if (val == -1)
		val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
		    "amd-bug-workaround", -1);

	if (val != -1) {
		if (val == 0) {
			chp->ch_config.burstsize_set = 0;
			chp->ch_config.transaction_cnt_set = 0;
			goto fail_exit;
		}
	}
	/*
	 * Step up to the parent node,  That's the node above us
	 * in the device tree. And will typically be the PCI host
	 * Controller.
	 */
	pdip = ddi_get_parent(chp->ch_dip);

	/*
	 * Now get the 'Vendor id' properties
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, pdip, 0, "vendor-id",
	    (int **)&prop_val, &prop_len) != DDI_PROP_SUCCESS) {
		chp->ch_config.burstsize_set = 0;
		chp->ch_config.transaction_cnt_set = 0;
		goto fail_exit;
	}
	vendor_id = *(uint32_t *)prop_val;
	ddi_prop_free(prop_val);

	/*
	 * Now get the 'Device id' properties
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, pdip, 0, "device-id",
	    (int **)&prop_val, &prop_len) != DDI_PROP_SUCCESS) {
		chp->ch_config.burstsize_set = 0;
		chp->ch_config.transaction_cnt_set = 0;
		goto fail_exit;
	}
	device_id = *(uint32_t *)prop_val;
	ddi_prop_free(prop_val);

	/*
	 * Now get the 'Revision id' properties
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, pdip, 0, "revision-id",
	    (int **)&prop_val, &prop_len) != DDI_PROP_SUCCESS) {
		chp->ch_config.burstsize_set = 0;
		chp->ch_config.transaction_cnt_set = 0;
		goto fail_exit;
	}
	revision_id = *(uint32_t *)prop_val;
	ddi_prop_free(prop_val);

	/*
	 * set default values based on node above us.
	 */
	if ((vendor_id == AMD_VENDOR_ID) && (device_id == AMD_BRIDGE) &&
	    (revision_id <= AMD_BRIDGE_REV)) {
		uint32_t v;
		uint32_t burst;
		uint32_t cnt;

		/* if 133 Mhz not enabled, then do nothing - we're not PCIx */
		v = pci_config_get32(chp->ch_hpci, 0x64);
		if ((v & 0x20000) == NULL) {
			chp->ch_config.burstsize_set = 0;
			chp->ch_config.transaction_cnt_set = 0;
			goto fail_exit;
		}

		/* check burst size and transaction count */
		v = pci_config_get32(chp->ch_hpci, 0x60);
		burst = (v >> 18) & 3;
		cnt = (v >> 20) & 7;

		switch (burst) {
		case 0:	/* 512 */
			/* 512 burst size legal with split cnts 1,2,3 */
			if (cnt <= 2) {
				chp->ch_config.burstsize_set = 0;
				chp->ch_config.transaction_cnt_set = 0;
				goto fail_exit;
			}
			break;
		case 1:	/* 1024 */
			/* 1024 burst size legal with split cnts 1,2 */
			if (cnt <= 1) {
				chp->ch_config.burstsize_set = 0;
				chp->ch_config.transaction_cnt_set = 0;
				goto fail_exit;
			}
			break;
		case 2:	/* 2048 */
			/* 2048 burst size legal with split cnts 1 */
			if (cnt == 0) {
				chp->ch_config.burstsize_set = 0;
				chp->ch_config.transaction_cnt_set = 0;
				goto fail_exit;
			}
			break;
		case 3:	/* 4096 */
			break;
		}
	} else {
		goto fail_exit;
	}

	/*
	 * if illegal burst size seen, then default to 1024 burst size
	 */
	chp->ch_config.burstsize = 1;
	chp->ch_config.burstsize_set = 1;
	/*
	 * if illegal transaction cnt seen, then default to 2
	 */
	chp->ch_config.transaction_cnt = 1;
	chp->ch_config.transaction_cnt_set = 1;


fail_exit:

	/*
	 * alter the burstsize parameter via an entry
	 * in chxge.conf
	 */

	val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
	    "pci_burstsize", -1);
	if (val == -1)
		val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
		    "pci-burstsize", -1);

	if (val != -1) {

		switch (val) {
		case 0:	/* use default */
			chp->ch_config.burstsize_set = 0;
			break;

		case 1024:
			chp->ch_config.burstsize_set = 1;
			chp->ch_config.burstsize = 1;
			break;

		case 2048:
			chp->ch_config.burstsize_set = 1;
			chp->ch_config.burstsize = 2;
			break;

		case 4096:
			cmn_err(CE_WARN, "%s not supported %d\n",
			    chp->ch_name, val);
			break;

		default:
			cmn_err(CE_WARN, "%s illegal burst size %d\n",
			    chp->ch_name, val);
			break;
		}
	}

	/*
	 * set transaction count
	 */
	val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
	    "pci_split_transaction_cnt", -1);
	if (val == -1)
		val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
		    "pci-split-transaction-cnt", -1);

	if (val != -1) {
		switch (val) {
		case 0:	/* use default */
			chp->ch_config.transaction_cnt_set = 0;
			break;

		case 1:
			chp->ch_config.transaction_cnt_set = 1;
			chp->ch_config.transaction_cnt = 0;
			break;

		case 2:
			chp->ch_config.transaction_cnt_set = 1;
			chp->ch_config.transaction_cnt = 1;
			break;

		case 3:
			chp->ch_config.transaction_cnt_set = 1;
			chp->ch_config.transaction_cnt = 2;
			break;

		case 4:
			chp->ch_config.transaction_cnt_set = 1;
			chp->ch_config.transaction_cnt = 3;
			break;

		case 8:
			chp->ch_config.transaction_cnt_set = 1;
			chp->ch_config.transaction_cnt = 4;
			break;

		case 12:
			chp->ch_config.transaction_cnt_set = 1;
			chp->ch_config.transaction_cnt = 5;
			break;

		case 16:
			chp->ch_config.transaction_cnt_set = 1;
			chp->ch_config.transaction_cnt = 6;
			break;

		case 32:
			chp->ch_config.transaction_cnt_set = 1;
			chp->ch_config.transaction_cnt = 7;
			break;

		default:
			cmn_err(CE_WARN, "%s illegal transaction cnt %d\n",
			    chp->ch_name, val);
			break;
		}
	}

	/*
	 * set relaxed ordering bit?
	 */
	val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
	    "pci_relaxed_ordering_on", -1);
	if (val == -1)
		val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
		    "pci-relaxed-ordering-on", -1);

	/*
	 * default is to use system default value.
	 */
	chp->ch_config.relaxed_ordering = 0;

	if (val != -1) {
		if (val)
			chp->ch_config.relaxed_ordering = 1;
	}

	val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
	    "enable_latency_timer", -1);
	if (val == -1)
		val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
		    "enable-latency-timer", -1);
	if (val != -1)
		enable_latency_timer = (val == 0)? 0: 1;

	/*
	 * default maximum Jumbo Frame size.
	 */
	chp->ch_maximum_mtu = 9198;	/* tunable via chxge.conf */
	val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
	    "maximum_mtu", -1);
	if (val == -1) {
		val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
		    "maximum-mtu", -1);
	}
	if (val != -1) {
		if (val > 9582) {
			cmn_err(CE_WARN,
			    "maximum_mtu value %d > 9582. Value set to 9582",
			    val);
			val = 9582;
		} else if (val < 1500) {
			cmn_err(CE_WARN,
			    "maximum_mtu value %d < 1500. Value set to 1500",
			    val);
			val = 1500;
		}

		if (val)
			chp->ch_maximum_mtu = val;
	}

	/*
	 * default value for this instance mtu
	 */
	chp->ch_mtu = ETHERMTU;

	val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
	    "accept_jumbo", -1);
	if (val == -1) {
		val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
		    "accept-jumbo", -1);
	}
	if (val != -1) {
		if (val)
			chp->ch_mtu = chp->ch_maximum_mtu;
	}
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
	chp->ch_sm_buf_sz = 0x800;
	chp->ch_sm_buf_aln = 0x800;
	chp->ch_bg_buf_sz = 0x4000;
	chp->ch_bg_buf_aln = 0x4000;
#else
	chp->ch_sm_buf_sz = 0x200;
	chp->ch_sm_buf_aln = 0x200;
	chp->ch_bg_buf_sz = 0x800;
	chp->ch_bg_buf_aln = 0x800;
	if ((chp->ch_mtu > 0x800) && (chp->ch_mtu <= 0x1000)) {
		chp->ch_sm_buf_sz = 0x400;
		chp->ch_sm_buf_aln = 0x400;
		chp->ch_bg_buf_sz = 0x1000;
		chp->ch_bg_buf_aln = 0x1000;
	} else if ((chp->ch_mtu > 0x1000) && (chp->ch_mtu <= 0x2000)) {
		chp->ch_sm_buf_sz = 0x400;
		chp->ch_sm_buf_aln = 0x400;
		chp->ch_bg_buf_sz = 0x2000;
		chp->ch_bg_buf_aln = 0x2000;
	} else if (chp->ch_mtu > 0x2000) {
		chp->ch_sm_buf_sz = 0x400;
		chp->ch_sm_buf_aln = 0x400;
		chp->ch_bg_buf_sz = 0x3000;
		chp->ch_bg_buf_aln = 0x4000;
	}
#endif
	chp->ch_config.cksum_enabled = 1;

	val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
	    "enable_checksum_offload", -1);
	if (val == -1)
		val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
		    "enable-checksum-offload", -1);
	if (val != -1) {
		if (val == NULL)
			chp->ch_config.cksum_enabled = 0;
	}

	/*
	 * Provides a tuning capability for the command queue 0 size.
	 */
	val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
	    "sge_cmdq0_cnt", -1);
	if (val == -1)
		val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
		    "sge-cmdq0-cnt", -1);
	if (val != -1) {
		if (val > 10)
			sge_cmdq0_cnt = val;
	}

	if (sge_cmdq0_cnt > 65535) {
		cmn_err(CE_WARN,
		    "%s: sge-cmdQ0-cnt > 65535 - resetting value to default",
		    chp->ch_name);
		sge_cmdq0_cnt = sge_cmdq0_cnt_orig;
	}
	tval += sge_cmdq0_cnt;

	/*
	 * Provides a tuning capability for the command queue 1 size.
	 */
	val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
	    "sge_cmdq1_cnt", -1);
	if (val == -1)
		val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
		    "sge-cmdq1-cnt", -1);
	if (val != -1) {
		if (val > 10)
			sge_cmdq1_cnt = val;
	}

	if (sge_cmdq1_cnt > 65535) {
		cmn_err(CE_WARN,
		    "%s: sge-cmdQ0-cnt > 65535 - resetting value to default",
		    chp->ch_name);
		sge_cmdq1_cnt = sge_cmdq1_cnt_orig;
	}

	/*
	 * Provides a tuning capability for the free list 0 size.
	 */
	val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
	    "sge_flq0_cnt", -1);
	if (val == -1)
		val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
		    "sge-flq0-cnt", -1);
	if (val != -1) {
		if (val > 512)
			sge_flq0_cnt = val;
	}

	if (sge_flq0_cnt > 65535) {
		cmn_err(CE_WARN,
		    "%s: sge-flq0-cnt > 65535 - resetting value to default",
		    chp->ch_name);
		sge_flq0_cnt = sge_flq0_cnt_orig;
	}

	tval += sge_flq0_cnt;

	/*
	 * Provides a tuning capability for the free list 1 size.
	 */
	val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
	    "sge_flq1_cnt", -1);
	if (val == -1)
		val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
		    "sge-flq1-cnt", -1);
	if (val != -1) {
		if (val > 512)
			sge_flq1_cnt = val;
	}

	if (sge_flq1_cnt > 65535) {
		cmn_err(CE_WARN,
		    "%s: sge-flq1-cnt > 65535 - resetting value to default",
		    chp->ch_name);
		sge_flq1_cnt = sge_flq1_cnt_orig;
	}

	tval += sge_flq1_cnt;

	/*
	 * Provides a tuning capability for the responce queue size.
	 */
	val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
	    "sge_respq_cnt", -1);
	if (val == -1)
		val = ddi_getprop(DDI_DEV_T_ANY, chp->ch_dip, DDI_PROP_DONTPASS,
		    "sge-respq-cnt", -1);
	if (val != -1) {
		if (val > 30)
			sge_respq_cnt = val;
	}

	if (sge_respq_cnt > 65535) {
		cmn_err(CE_WARN,
		    "%s: sge-respq-cnt > 65535 - resetting value to default",
		    chp->ch_name);
		sge_respq_cnt = sge_respq_cnt_orig;
	}

	if (tval > sge_respq_cnt) {
		if (tval <= 65535) {
			cmn_err(CE_WARN,
	    "%s: sge-respq-cnt < %d - setting value to %d (cmdQ+flq0+flq1)",
			    chp->ch_name, tval, tval);

			sge_respq_cnt = tval;
		} else {
			cmn_err(CE_WARN,
			    "%s: Q sizes invalid - resetting to default values",
			    chp->ch_name);

			sge_cmdq0_cnt = sge_cmdq0_cnt_orig;
			sge_cmdq1_cnt = sge_cmdq1_cnt_orig;
			sge_flq0_cnt = sge_flq0_cnt_orig;
			sge_flq1_cnt = sge_flq1_cnt_orig;
			sge_respq_cnt = sge_respq_cnt_orig;
		}
	}
}
