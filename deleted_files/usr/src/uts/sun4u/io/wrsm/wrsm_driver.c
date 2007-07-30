/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file implements the standard DDI interface functions for
 * the Wildcat RSM driver.
 */

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/param.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/obpdefs.h>
#include <sys/cmn_err.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/machsystm.h>
#include <sys/policy.h>

/* Driver specific headers */
#include <sys/wci_common.h>
#include <sys/wci_regs.h>
#include <sys/wrsm_driver.h>
#include <sys/wrsm_lc.h>
#include <sys/wrsm.h>
#include <sys/wrsm_plugin.h>
#include <sys/wrsm_cf.h>
#include <sys/wrsm_memseg.h>
#include <sys/wrsm_nc.h>
#include <sys/wrsm_memseg_impl.h>
#include <sys/wrsm_rsmpi.h>
#include <sys/rsm/rsmpi_driver.h>

/* Headers for modules that wrsm depends on */

#include <sys/wrsm_plat.h>
#include <sys/rsm/rsmpi.h>

/*
 * Exported data structures;
 */
dev_info_t *wrsm_ncslice_dip;		/* devinfo for ncslice mappings */
static kmutex_t wrsm_attach_mutex;
static int wrsm_attachcnt = 0;		/* # of instances attached */
wrsm_softstate_t *wrsm_admin_softsp = NULL;

/*
 * Internal Function prototypes
 */
static int wrsm_attach(dev_info_t *, ddi_attach_cmd_t);
static int wrsm_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int wrsm_detach(dev_info_t *, ddi_detach_cmd_t);

static int wrsm_open(dev_t *, int, int, cred_t *);
static int wrsm_close(dev_t, int, int, cred_t *);
static int wrsm_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static int wrsm_segmap(dev_t, off_t, struct as *, caddr_t *, off_t,
    unsigned int, unsigned int, unsigned int, cred_t *);
static int wrsm_devmap(dev_t, devmap_cookie_t, offset_t, size_t,
    size_t *, uint_t);
static int wrsm_device_ioctl(wrsm_softstate_t *softsp, int cmd,
    intptr_t arg, int flag, cred_t *cred_p, int *rval_p);
static int wrsm_map_regs(wrsm_softstate_t *softsp);

static void wrsm_unmap_regs(wrsm_softstate_t *softsp);

static void wrsm_add_status_kstat(wrsm_softstate_t *softsp);
static void wrsm_del_status_kstat(wrsm_softstate_t *softsp);
static int wrsm_status_kstat_update(kstat_t *ksp, int rw);

/*
 * Configuration data structures
 */

static struct cb_ops wrsm_cb_ops = {
	wrsm_open,		/* open */
	wrsm_close,		/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
	nodev,			/* dump */
	nulldev,		/* read */
	nulldev,		/* write */
	wrsm_ioctl,		/* ioctl */
	wrsm_devmap,		/* devmap */
	nodev,			/* mmap */
	wrsm_segmap,		/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab */
	D_MP | D_NEW		/* Driver compatibility flag */
};

static rsmops_registry_t wrsm_rsmops = {
	RSM_VERSION,
	"wrsm",
	wrsmrsm_get_controller_handler,
	wrsmrsm_release_controller_handler,
	NULL /* rsm_thread_entry_pt */
};

static struct dev_ops wrsm_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt */
	wrsm_info,		/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	wrsm_attach,		/* attach */
	wrsm_detach,		/* detach */
	nulldev,		/* reset */
	&wrsm_cb_ops,		/* cb_ops */
	(struct bus_ops *)0,	/* bus_ops */
	nulldev			/* power */
};

static wrsm_plat_ops_t wrsm_plat_ops = {
	wrsm_lc_phys_link_up,		/* discovery success-msg from SC */
	wrsm_lc_phys_link_down,		/* link down - msg from SC */
	wrsm_cf_sc_failed,		/* report that the SC has reset */
	wrsm_cf_lookup_wci,		/* give lcwci_handle for wci id  */
	get_remote_config_data		/* lookup remote config info */
};

/*
 * Driver globals
 */

extern void wrsm_redist(void *);

static void *wrsm_softstates;		/* wrsm soft state hook */
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"WRSM v%I%"		/* name of module */
#ifdef DEBUG
	" (Debug)"
#endif
,
	&wrsm_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,		/* rev */
	(void *)&modldrv,
	NULL
};


/*
 * Controllers must be assigned a minor number that matches their
 * controller id.  This means that the device instance number can't be used
 * for the minor number.  The minor_to_instance table is used to translate
 * between the 2.  To ensure that lower numbered minor numbers are
 * available (controllers ids are assigned starting with 0), the admin
 * device is assigned a minor number of (MAX_INSTANCE - 1), and wci devices
 * are assigned a minor number of (MAX_INSTANCE - 2 - instance#)
 */
#define	MAX_INSTANCES 1024
static int minor_to_instance[MAX_INSTANCES];

#ifdef DEBUG


#define	WRSM_DEBUG	0x0001
#define	WRSM_WARN	0x0002
static uint32_t wrsm_debug = WRSM_WARN;

#define	DPRINTF(a, b) { if (wrsm_debug & a) wrsmdprintf b; }
#else
#define	DPRINTF(a, b) { }
#endif


/*
 * *************************************************************************
 *
 * These are the module initialization routines.
 */

int
_init(void)
{
	int error;
	int i;

#if defined(DEBUG) && defined(DEBUG_LOG)
	bzero(wrsmdbgbuf, wrsmdbgsize);
	wrsmdbgnext = 0;
	wrsmdbginit = 1;
	mutex_init(&wrsmdbglock, NULL, MUTEX_DRIVER, NULL);
#endif
	DPRINTF(WRSM_DEBUG, (CE_CONT, "wrsm_init\n"));

	for (i = 0; i < MAX_INSTANCES; i++) {
		minor_to_instance[i] = -1;
	}

	/* Initialize soft state pointer. */
	if ((error = ddi_soft_state_init(&wrsm_softstates,
	    sizeof (wrsm_softstate_t), 1)) != 0) {
		DPRINTF(WRSM_WARN, (CE_WARN, "ddi_soft_state_init failed"));
#if defined(DEBUG) && defined(DEBUG_LOG)
		mutex_destroy(&wrsmdbglock);
#endif
		return (error);
	}

	mutex_init(&wrsm_attach_mutex, NULL, MUTEX_DRIVER, NULL);
	/* Install the module. */
	if ((error = mod_install(&modlinkage)) != 0) {
		DPRINTF(WRSM_WARN, (CE_WARN, "mod_install failed"));
		goto err_cleanup;
	}

	/*
	 * initialize the various RSM driver sub-modules
	 */
	wrsm_nc_init();
	wrsm_cf_init();
	wrsm_memseg_init();

	/* register call backs with platform specific mailbox layer */
	if ((error = wrsmplat_reg_callbacks(&wrsm_plat_ops)) != 0) {
		wrsm_memseg_fini();
		wrsm_cf_fini();
		(void) wrsm_nc_fini();
		goto err_cleanup;
	}

	/*
	 * register with RSM
	 */
	if ((error = rsm_register_driver(&wrsm_rsmops)) != RSM_SUCCESS) {
		cmn_err(CE_WARN, "wrsm_init: rsm_register_driver failed");
		(void) wrsmplat_unreg_callbacks();
		wrsm_memseg_fini();
		wrsm_cf_fini();
		(void) wrsm_nc_fini();
		goto err_cleanup;
	}

	return (WRSM_SUCCESS);

err_cleanup:
	ddi_soft_state_fini(&wrsm_softstates);
	mutex_destroy(&wrsm_attach_mutex);

#if defined(DEBUG) && defined(DEBUG_LOG)
	mutex_destroy(&wrsmdbglock);
#endif
	return (error);

}

int
_fini(void)
{
	int error;

	/*
	 * Make sure there are no RSMPI users before allowing driver to
	 * be removed.
	 */
	if (rsm_unregister_driver(&wrsm_rsmops) != RSM_SUCCESS) {
		return (EBUSY);
	}

	/*
	 * Make sure there are no configurations installed before allowing
	 * driver to be removed.
	 */
	if (wrsm_nc_check() != WRSM_SUCCESS) {
		(void) rsm_register_driver(&wrsm_rsmops);
		return (EBUSY);
	}

	/* Prepare the module to be removed. */
	if ((error = mod_remove(&modlinkage)) != 0) {
		(void) rsm_register_driver(&wrsm_rsmops);
		return (error);
	}

	/*
	 * mod_remove() succeeded. We can do cleanup now.
	 */
	wrsm_nc_cleanup();

	wrsm_cf_fini();

	/* unregister call backs with platform specific module */
	(void) wrsmplat_unreg_callbacks();

	wrsm_memseg_fini();

	/* Free the soft state info. */
	ddi_soft_state_fini(&wrsm_softstates);
	mutex_destroy(&wrsm_attach_mutex);

#if defined(DEBUG) && defined(DEBUG_LOG)
	mutex_destroy(&wrsmdbglock);
#endif
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* device driver entry points */


/*
 * Translate "dev_t" to a pointer to the associated "dev_info_t".
 */
/* ARGSUSED */
static int
wrsm_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t dev;
	int instance;
	int minor;
	wrsm_softstate_t *softsp;

	DPRINTF(WRSM_DEBUG, (CE_CONT, "wrsm_info\n"));

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		dev = (dev_t)arg;
		minor = getminor(dev);
		if (minor >= MAX_INSTANCES)
			return (DDI_FAILURE);
		instance = minor_to_instance[minor];
		if (instance == -1)
			return (DDI_FAILURE);
		if ((softsp = ddi_get_soft_state(wrsm_softstates, instance))
		    == NULL) {
			DPRINTF(WRSM_WARN, (CE_WARN, "wrsm_info: "
			    "ddi_get_soft_state failed for wrsm%d",
			    instance));
			*result = NULL;
			return (DDI_FAILURE);
		}
		*result = softsp->dip;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		minor = getminor(dev);
		if (minor >= MAX_INSTANCES)
			return (DDI_FAILURE);
		instance = minor_to_instance[minor];
		if (instance == -1)
			return (DDI_FAILURE);
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}



static int
wrsm_do_resume(wrsm_softstate_t *softsp)
{
	int ret;

	switch (softsp->type) {

	case wrsm_admin:
		/* do nothing */
		return (DDI_SUCCESS);

	case wrsm_rsm_controller:
		ret = wrsm_nc_resume(softsp->minor);
		if (ret == WRSM_SUCCESS) {
			return (DDI_SUCCESS);
		} else {
			return (DDI_FAILURE);
		}

	default:
		ASSERT(softsp->type == wrsm_device);
		wrsm_lc_resume(softsp);
		return (DDI_SUCCESS);
	}
}



static int
wrsm_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int instance, link_no;
	wrsm_softstate_t *softsp;
	wci_sw_link_status_u wci_sw_link_status_tmp;
	char *special_name;
	int minor;
	char *ddi_type;

	DPRINTF(WRSM_DEBUG, (CE_CONT, "wrsm_attach\n"));

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		instance = ddi_get_instance(devi);
		if ((softsp = ddi_get_soft_state(wrsm_softstates, instance))
		    == NULL) {
			DPRINTF(WRSM_DEBUG, (CE_CONT,
			    "DDI_RESUME - no device\n"));
			return (DDI_FAILURE);
		}
		ASSERT(softsp->instance == instance);
		return (wrsm_do_resume(softsp));
	default:
		return (DDI_FAILURE);
	}

	/* Allocate soft data structure */
	instance = ddi_get_instance(devi);

	if (ddi_soft_state_zalloc(wrsm_softstates, instance) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "wrsm_attach: ddi_soft_state_zalloc failed "
		    "for wrsm%d", instance);
		return (DDI_FAILURE);
	}

	if ((softsp = ddi_get_soft_state(wrsm_softstates, instance)) == NULL) {
		DPRINTF(WRSM_WARN, (CE_WARN, "wrsm_attach: "
		    "ddi_get_soft_state failed for wrsm%d", instance));
		ddi_soft_state_free(wrsm_softstates, instance);
		return (DDI_FAILURE);
	}

	/* Set the devi in the soft state */
	softsp->dip = devi;
	softsp->instance = instance;
	softsp->wci_common_softst.instance = instance;


	DPRINTF(WRSM_DEBUG, (CE_CONT, "wrsm%d: devi= 0x%p, softsp=0x%p\n",
		instance, (void *)devi, (void *)softsp));

	if (((minor = ddi_getprop(DDI_DEV_T_ANY, devi,
	    DDI_PROP_DONTPASS, WRSM_RSM_CTR, -1))) != -1) {
		/*
		 * controller device
		 */
		DPRINTF(WRSM_DEBUG, (CE_CONT, "wrsm%d is rsm_controller %d",
		    instance, minor));
		if (minor >= MAX_INSTANCES) {
			cmn_err(CE_WARN, "wrsm_attach: (wrsm%d) - "
			    "can't support controller id %d "
			    "(instance >= %d)",
			    instance, minor, MAX_INSTANCES);
			ddi_soft_state_free(wrsm_softstates, instance);
			return (DDI_FAILURE);
		}
		if (minor_to_instance[minor] != -1) {
			cmn_err(CE_WARN, "wrsm_attach: (wrsm%d) - "
			    "controller can't use minor dev %d "
			    "(in use by wrsm instance %d)",
			    instance, minor,
			    minor_to_instance[minor]);
			ddi_soft_state_free(wrsm_softstates, instance);
			return (DDI_FAILURE);
		}
		softsp->type = wrsm_rsm_controller;
		ddi_type = DDI_PSEUDO;
		special_name = "ctrl";

		(void) ddi_prop_create(DDI_DEV_T_NONE, devi, DDI_PROP_CANSLEEP,
		    "pm-hardware-state", (caddr_t)"needs-suspend-resume",
		    strlen("needs-suspend-resume") + 1);

	} else if ((ddi_getprop(DDI_DEV_T_ANY, devi,
	    DDI_PROP_DONTPASS, WRSM_ADMIN, -1)) != -1) {
		DPRINTF(WRSM_DEBUG, (CE_CONT, "wrsm%d is the admin dev\n",
		    instance));
		/*
		 * admin device
		 */
		mutex_enter(&wrsm_attach_mutex);
		if (wrsm_admin_softsp) {
			cmn_err(CE_WARN, "wrsm_attach: an admin dev "
			    "is already attached (wrsm%d) - not "
			    "attaching wrsm%d",
			    wrsm_admin_softsp->instance, instance);
			mutex_exit(&wrsm_attach_mutex);
			ddi_soft_state_free(wrsm_softstates, instance);
			return (DDI_FAILURE);
		}
		wrsm_admin_softsp = softsp;
		mutex_exit(&wrsm_attach_mutex);

		softsp->type = wrsm_admin;
		ddi_type = NULL;
		special_name = "admin";

		/*
		 * record this devi in wrsm_ncslice_dip.
		 */

		wrsm_ncslice_dip = devi;
		minor = MAX_INSTANCES - 1;
	} else {
		/*
		 * wci device
		 */
		/* request safari port id (extended agent id from OBP */
		if ((softsp->portid =
		    (safari_port_t)ddi_getprop(DDI_DEV_T_ANY, devi,
		    DDI_PROP_DONTPASS, OBP_WRSM_PORTID, -1)) == -1) {
			cmn_err(CE_WARN, "wrsm%d: unable to retrieve %s "
			    "property", instance, OBP_WRSM_PORTID);
			ddi_soft_state_free(wrsm_softstates, instance);
			return (DDI_FAILURE);
		}
		DPRINTF(WRSM_DEBUG, (CE_CONT, "wrsm%d is the wci at port %d\n",
		    instance, softsp->portid));
		minor = (MAX_INSTANCES - 2) - instance;
		if (minor < 0) {
			cmn_err(CE_WARN, "wrsm_attach: (wrsm%d) - "
			    "instance out of range (>= %d) for wci %d",
			    instance, MAX_INSTANCES - 1, softsp->portid);
			ddi_soft_state_free(wrsm_softstates, instance);
			return (DDI_FAILURE);
		}
		if (minor_to_instance[minor] != -1) {
			cmn_err(CE_WARN, "wrsm_attach: (wrsm%d) - "
			    "wci can't use minor dev %d "
			    "(in use by wrsm instance %d)",

			    instance, minor,
			    minor_to_instance[minor]);
			ddi_soft_state_free(wrsm_softstates, instance);
			return (DDI_FAILURE);
		}

		softsp->type = wrsm_device;
		ddi_type = DDI_NT_NEXUS;
		special_name = ddi_get_name(devi);

		if (wrsm_map_regs(softsp) != DDI_SUCCESS) {
			ddi_soft_state_free(wrsm_softstates, instance);
			return (DDI_FAILURE);
		}

		/* copy the regs base address into wci common soft state */
		softsp->wci_common_softst.wci_regs = softsp->wrsm_regs;

		/* pre-calc virtual addr's for ecc registers */
		softsp->wci_dco_ce_cnt_vaddr = (volatile uint64_t *)
		    (softsp->wrsm_regs + ADDR_WCI_DCO_CE_COUNT);
		softsp->wci_dc_esr_vaddr = (volatile uint64_t *)
		    (softsp->wrsm_regs + ADDR_WCI_DC_ESR);
		softsp->wci_dco_state_vaddr = (volatile uint64_t *)
		    (softsp->wrsm_regs + ADDR_WCI_DCO_STATE);

		softsp->wci_ca_esr_0_vaddr = (volatile uint64_t *)
		    (softsp->wrsm_regs + ADDR_WCI_CA_ESR_0);
		softsp->wci_ra_esr_1_vaddr = (volatile uint64_t *)
		    (softsp->wrsm_regs + ADDR_WCI_RA_ESR_1);

		softsp->wci_ca_ecc_addr_vaddr = (volatile uint64_t *)
		    (softsp->wrsm_regs + ADDR_WCI_CA_ECC_ADDRESS);
		softsp->wci_ra_ecc_addr_vaddr = (volatile uint64_t *)
		    (softsp->wrsm_regs + ADDR_WCI_RA_ECC_ADDRESS);

		softsp->wci_cci_esr_vaddr = (volatile uint64_t *)
		    (softsp->wrsm_regs + ADDR_WCI_CCI_ESR);


		for (link_no = 0; link_no < WRSM_LINKS_PER_WCI; link_no++) {

			/* pre-calculate virtual address of link error reg */
			softsp->links[link_no].wrsm_link_err_cnt_addr =
			    ((volatile uint64_t *)(softsp->wrsm_regs +
				ADDR_WCI_SW_LINK_ERROR_COUNT + (link_no
				*  STRIDE_WCI_SW_LINK_ERROR_COUNT)));
			/* check if paroli present */
			wci_sw_link_status_tmp.val = *((volatile uint64_t *)
			    (softsp->wrsm_regs + ADDR_WCI_SW_LINK_STATUS +
				(link_no * STRIDE_WCI_SW_LINK_STATUS)));
			if (wci_sw_link_status_tmp.bit.paroli_present !=
			    WCI_PAROLI_PRESENT) {
				/* no paroli module attached for this link */
				softsp->links[link_no].link_req_state =
				    lc_not_there;
			} else {
				softsp->links[link_no].link_req_state =
				    lc_down;
			}
			if (ddi_getprop(DDI_DEV_T_ANY, softsp->dip,
			    DDI_PROP_DONTPASS, "simwci", -1) > 0) {
				softsp->links[link_no].link_req_state =
				    lc_down;
			}
		}

		/* pre-calc virtual addrs for Performance Counters registers */
		softsp->wci_common_softst.wci_misc_ctr_vaddr =
		    (volatile uint64_t *)(softsp->wrsm_regs +
			ADDR_WCI_MISC_CTR);
		softsp->wci_common_softst.wci_misc_ctr_ctl_vaddr =
		    (volatile uint64_t *)(softsp->wrsm_regs +
			ADDR_WCI_MISC_CTR_CTL);
		softsp->wci_common_softst.wci_cluster_ctr_ctl_vaddr =
		    (volatile uint64_t *)(softsp->wrsm_regs +
			ADDR_WCI_CLUSTER_CTR_CTL);
		softsp->wci_common_softst.wci_lpbk_ctr_vaddr =
		    (volatile uint64_t *)(softsp->wrsm_regs +
			ADDR_WCI_LPBK_CTR);
		softsp->wci_common_softst.wci_lpbk_ctr_ctl_vaddr =
		    (volatile uint64_t *)(softsp->wrsm_regs +
			ADDR_WCI_LPBK_CTR_CTL);
		for (link_no = 0; link_no < WCI_NUM_LINKS; link_no++) {
			softsp->wci_common_softst.wci_link_ctr_vaddr[link_no] =
			    (volatile uint64_t *)(softsp->wrsm_regs +
				ADDR_WCI_LINK_CTR +
				(link_no * STRIDE_WCI_LINK_CTR));
			softsp->wci_common_softst.
				wci_link_ctr_ctl_vaddr[link_no] =
			    (volatile uint64_t *)(softsp->wrsm_regs +
				ADDR_WCI_LINK_CTR_CTL +
				(link_no * STRIDE_WCI_LINK_CTR_CTL));
		}

		softsp->wci_common_softst.wci_sfi_sw_ctr_ctl = 0;
		/* map the sfari histogrammming counter registers */
		softsp->wci_common_softst.wci_sfi_ctr0_mask_vaddr =
			(volatile uint64_t *)(softsp->wrsm_regs +
			    ADDR_WCI_SFI_CTR0_MASK);
		softsp->wci_common_softst.wci_sfi_ctr0_match_vaddr =
			(volatile uint64_t *)(softsp->wrsm_regs +
			    ADDR_WCI_SFI_CTR0_MATCH);
		softsp->wci_common_softst.wci_sfi_ctr0_match_transaction_vaddr =
			(volatile uint64_t *)(softsp->wrsm_regs +
			    ADDR_WCI_SFI_CTR0_MATCH_TRANSACTION);
		softsp->wci_common_softst.wci_sfi_ctr1_mask_vaddr =
			(volatile uint64_t *)(softsp->wrsm_regs +
			    ADDR_WCI_SFI_CTR1_MASK);
		softsp->wci_common_softst.wci_sfi_ctr1_match_vaddr =
			(volatile uint64_t *)(softsp->wrsm_regs +
			    ADDR_WCI_SFI_CTR1_MATCH);
		softsp->wci_common_softst.wci_sfi_ctr1_match_transaction_vaddr =
			(volatile uint64_t *)(softsp->wrsm_regs +
			    ADDR_WCI_SFI_CTR1_MATCH_TRANSACTION);

		/*
		 * Create the picN kstats if we are the first instance
		 * to attach. We use wrsm_attachcnt as a count of how
		 * many instances have attached. This is protected by
		 * a lock.
		 */
		mutex_enter(&wrsm_attach_mutex);
		if (wrsm_attachcnt++ == 0) {
			/* add misc, lpbk, link picN kstats */
			wci_add_picN_kstats("wrsm");
			wrsm_avg_weight = ddi_getprop(DDI_DEV_T_ANY,
			    softsp->dip, 0, "wrsm-avg-weight",
			    WRSM_AVG_WEIGHT);
			wrsm_shortterm_interval =
			    ddi_getprop(DDI_DEV_T_ANY, softsp->dip, 0,
			    "wrsm-shortterm-interval",
			    WRSM_SHORTTERM_INTERVAL);
			wrsm_shorts_per_longterm =
			    ddi_getprop(DDI_DEV_T_ANY, softsp->dip, 0,
			    "wrsm-shorts-per-longterm",
			    WRSM_SHORTS_PER_LONGTERM);
			wrsm_lc_setup_timeout_speeds();
		}
		mutex_exit(&wrsm_attach_mutex);

		/* Create the counters kstats for this device */
		wci_add_counters_kstats(&softsp->wci_common_softst, "wrsm");

		/* Create the wci-links kstat for this device */
		wrsm_add_status_kstat(softsp);
	}

	/* This creates the device node */
	softsp->minor = minor;
	minor_to_instance[minor] = instance;
	if (ddi_create_minor_node(devi, special_name, S_IFCHR,
	    minor, ddi_type, NULL) == DDI_FAILURE) {
		DPRINTF(WRSM_WARN, (CE_WARN, "ddi_create_minor_"
		    "node failed on wrsm%d", instance));
		minor_to_instance[minor] = -1;
		if (softsp->type == wrsm_device) {
			wrsm_del_status_kstat(softsp);
			wci_del_counters_kstats(&softsp->wci_common_softst);
			wrsm_unmap_regs(softsp);
		} else if (softsp->type == wrsm_admin) {
			wrsm_admin_softsp = NULL;
		}
		ddi_soft_state_free(wrsm_softstates, instance);
		return (DDI_FAILURE);
	}

	/* wrsm_mutex used with driver open and close */
	mutex_init(&softsp->wrsm_mutex, NULL, MUTEX_DRIVER, NULL);
	/*
	 * cmmu_mutex used during cmmu_update for CMMU_UPDATE_FLUSH flag
	 * as only one thread at a time may request  a FLUSH (sync cmmu's)
	 */
	mutex_init(&softsp->cmmu_mutex, NULL, MUTEX_DRIVER, NULL);

	/* init to NOT opened - just to be paranoid */
	softsp->open = 0;
	if (softsp->type == wrsm_device) {
		/*
		 * create lock to protect the links, the link counters:
		 * link_req_cntdown, and link_req_cntup
		 * and to prevent changes made to the config in softsp->config
		 * while in process of executing config request
		 */
		mutex_init(&softsp->lc_mutex, NULL, MUTEX_DRIVER, NULL);

		/*
		 * Create condition var to allow installconfig to go once there
		 * are no outstanding link_takedown request pending.
		 * lc_cleanconfig will increment oldlink_waitdown_cnt for each
		 * takedown request there is in lc_cleanconfig.
		 * lc_installconfig will cv_wait until oldlink_waitdown_cnt =
		 * 0. lc_phys_link_down is responsible for signalling
		 * lc_installconfig if there are takedown request.
		 */
		cv_init(&softsp->goinstallconfig, NULL, CV_DRIVER, NULL);

		if (wrsm_cf_newwci(softsp, softsp->portid) != WRSM_SUCCESS) {
			cmn_err(CE_WARN, "wrsm_attach:cf_newwci failed "
			    "for wrsm%d", instance);
			mutex_destroy(&softsp->wrsm_mutex);
			mutex_destroy(&softsp->cmmu_mutex);
			cv_destroy(&softsp->goinstallconfig);
			mutex_destroy(&softsp->lc_mutex);
			ddi_remove_minor_node(devi, NULL);
			minor_to_instance[minor] = -1;
			wrsm_del_status_kstat(softsp);
			wci_del_counters_kstats(&softsp->wci_common_softst);
			wrsm_unmap_regs(softsp);
			ddi_soft_state_free(wrsm_softstates, instance);
			return (DDI_FAILURE);
		}
	} else if (softsp->type == wrsm_rsm_controller) {
		/*
		 * Notify config layer that this RSM controller
		 * pseudo device is available
		 */
		if (wrsm_cf_new_controller(softsp->minor, devi) !=
		    WRSM_SUCCESS) {
			cmn_err(CE_WARN, "wrsm_attach:cf_new_controller"
			    " failed for wrsm%d", instance);
			mutex_destroy(&softsp->wrsm_mutex);
			mutex_destroy(&softsp->cmmu_mutex);
			ddi_remove_minor_node(devi, NULL);
			minor_to_instance[minor] = -1;
			ddi_soft_state_free(wrsm_softstates, instance);
			return (DDI_FAILURE);
		}

		intr_dist_add(wrsm_redist, devi);
	}

	ddi_report_dev(devi);
	return (DDI_SUCCESS);
}


static int
wrsm_do_suspend(wrsm_softstate_t *softsp)
{
	int ret;

	switch (softsp->type) {
	case wrsm_admin:
		/* do nothing */
		return (DDI_SUCCESS);

	case wrsm_rsm_controller:
		ret = wrsm_nc_suspend(softsp->minor);
		if (ret == WRSM_SUCCESS) {
			return (DDI_SUCCESS);
		} else {
			return (DDI_FAILURE);
		}

	default:
		ASSERT(softsp->type == wrsm_device);
		wrsm_lc_suspend(softsp);
		return (DDI_SUCCESS);
	}
}


static int
wrsm_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance, i;
	wrsm_softstate_t *softsp;
	uint32_t wci_owner;

	switch (cmd) {
	case DDI_SUSPEND:
		break;
	case DDI_DETACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(devi);
	DPRINTF(WRSM_DEBUG, (CE_CONT, " wrsm_detach %d cmd %d\n",  instance,
	    cmd));
	if ((softsp = ddi_get_soft_state(wrsm_softstates, instance)) == NULL)
		return (DDI_FAILURE);
	ASSERT(softsp->instance == instance);

	if (cmd == DDI_SUSPEND) {
		return (wrsm_do_suspend(softsp));
	}

	switch (softsp->type) {

	case wrsm_rsm_controller:
		if (wrsm_cf_remove_controller(softsp->minor) != WRSM_SUCCESS) {
			cmn_err(CE_WARN, "wrsm_detach:cf_remove_controller "
			    "failed for wrsm%d", instance);
			return (DDI_FAILURE);
		}
		intr_dist_rem(wrsm_redist, devi);
		break;

	case wrsm_admin:
		DPRINTF(WRSM_DEBUG, (CE_CONT, "wrsm_detach: admin"));
		mutex_enter(&wrsm_attach_mutex);
		wrsm_admin_softsp = NULL;
		mutex_exit(&wrsm_attach_mutex);
		break;

	default:
		ASSERT(softsp->type == wrsm_device);

		/* find out which controller (if any) this WCI belongs to */
		wci_owner = wrsm_cf_wci_owner(softsp->portid);

		/*
		 * If this wci has been claimed for external loopback
		 * testing then the owner will be WRSM_LOOPBACK_ID.
		 * If this is the case, then just shut down all the
		 * links.
		 */
		if (wci_owner == WRSM_LOOPBACK_ID) {
			for (i = 0; i < WRSM_LINKS_PER_WCI; i++)
				(void) wrsm_lc_loopback_disable(softsp, i);
			wrsm_cf_release_wci(softsp->portid);
		}

		if (wrsm_cf_remove_wci(softsp) != WRSM_SUCCESS) {
			DPRINTF(WRSM_WARN, (CE_WARN, "wsm_detach:cf_remove_wci"
			    " failed for wrsm%d", instance));
			return (DDI_FAILURE);
		}

		/* check if links are all lc_down/lc_not_there */
		for (i = 0; i < WRSM_LINKS_PER_WCI; i++) {
			if (softsp->links[i].link_req_state != lc_down)
				if (softsp->links[i].link_req_state !=
				    lc_not_there) {
					DPRINTF(WRSM_DEBUG, (CE_CONT,
					    "link in invalid state"));
					(void) wrsm_cf_newwci(softsp,
					    softsp->portid);
					return (DDI_FAILURE);
				}
		}

		/* LINTED: E_NOP_IF_STMT */
		if (untimeout(softsp->err_timeout_id) == -1) {
			DPRINTF(WRSM_DEBUG, (CE_CONT, "wrsm_detach:"
			    " err_timeout_id not valid\n"));
		}
		wrsm_del_status_kstat(softsp);
		wci_del_counters_kstats(&softsp->wci_common_softst);

		/*
		 * See if we are the last instance to detach.
		 * If so, we need to remove the picN kstats
		 */
		mutex_enter(&wrsm_attach_mutex);
		if (--wrsm_attachcnt == 0) {
			/* delete misc, lpbk, link picN kstats driver */
			wci_del_picN_kstats();
		}
		mutex_exit(&wrsm_attach_mutex);


		/* LINTED: E_NOP_IF_STMT */
		if (untimeout(softsp->restart_timeout_id) == -1) {
			DPRINTF(WRSM_DEBUG, (CE_CONT, "wrsm_detach:"
			    " restart_timeout_id not valid\n"));
		}
		cv_destroy(&softsp->goinstallconfig);
		mutex_destroy(&softsp->lc_mutex);
		wrsm_unmap_regs(softsp);
		break;
	}

	minor_to_instance[softsp->minor] = -1;

	/* release minor node */
	ddi_remove_minor_node(softsp->dip, NULL);
	/* destroy per instance mutex's */
	mutex_destroy(&softsp->wrsm_mutex);
	mutex_destroy(&softsp->cmmu_mutex);
	/* release soft state */
	ddi_soft_state_free(wrsm_softstates, instance);
	/*
	 * create lock for a per link basis - needed to
	 * secure state change of softsp->links[i].link_req_state
	 */

	return (DDI_SUCCESS);
}


/* ARGSUSED */
static int
wrsm_open(dev_t *devp, int flags, int otyp, cred_t *cred_p)
{
	int instance;
	int minor;
	int retval = 0;
	wrsm_softstate_t *softsp;

	/* Verify we are being opened as a character device */
	if (otyp != OTYP_CHR)
		return (EINVAL);

	minor = getminor(*devp);
	if (minor >= MAX_INSTANCES)
		return (ENXIO);
	instance = minor_to_instance[minor];
	if (instance == -1)
		return (ENXIO);

	softsp = ddi_get_soft_state(wrsm_softstates, instance);

	DPRINTF(WRSM_DEBUG, (CE_CONT, "wrsm_open:wrsm%d: dev=0x%lx, "
	    "minor=%d softsp=0x%p\n", instance, *devp, minor, (void *)softsp));

	/* Verify instance structure */
	if (softsp == NULL)
		return (ENXIO);

	switch (softsp->type) {

	case wrsm_device:
		mutex_enter(&softsp->wrsm_mutex); /* exclusive open check */
		if (softsp->open == WRSM_OPEN_EXCLUSIVE) {
			DPRINTF(WRSM_WARN, (CE_CONT, "wrsm_open: "
			    "can't open, already opened exclusively"));
			retval = EBUSY;
		} else if ((flags & FEXCL) && (softsp->open > 0)) {
			DPRINTF(WRSM_WARN, (CE_CONT, "wrsm_open: "
			    "can't open exclusively, already open"));
			retval = EBUSY;
		} else {
			DPRINTF(WRSM_DEBUG, (CE_CONT, " successful open "));
			retval = WRSM_SUCCESS;
			if (flags & FEXCL) {
				softsp->open = WRSM_OPEN_EXCLUSIVE;
			} else {
				softsp->open++;
			}
		}
		mutex_exit(&softsp->wrsm_mutex);
		break;

	case wrsm_rsm_controller:
		/*
		 * controllers are opened by the wrsm plugin library
		 * librsmwrsm.so
		 */
		retval = wrsm_nc_open_controller(minor);
		break;

	default:
		ASSERT(softsp->type == wrsm_admin);
		/*
		 * admin devices can also be opened, but there is no need
		 * for an exclusive check.
		 */
		retval =  WRSM_SUCCESS;
		break;
	}
	return (retval);

}
/* ARGSUSED */
static int
wrsm_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	int instance;
	int minor;
	wrsm_softstate_t *softsp;

	/* Verify we are being closed as a character device */
	if (otyp != OTYP_CHR)
		return (EINVAL);

	minor = getminor(dev);
	if (minor >= MAX_INSTANCES)
		return (ENXIO);
	instance = minor_to_instance[minor];
	if (instance == -1)
		return (ENXIO);

	softsp = ddi_get_soft_state(wrsm_softstates, instance);

	DPRINTF(WRSM_DEBUG, (CE_CONT, "wrsm_close:wrsm%d: dev=0x%lx, "
	    "minor=%d softsp=0x%p", instance, dev, minor, (void *)softsp));

	if (softsp == NULL) {
		cmn_err(CE_WARN, "wrsm: could not get state structure "
		    "for instance %d", instance);
		return (ENXIO);
	}

	if (softsp->type == wrsm_rsm_controller) {
		wrsm_nc_close_controller(minor);
		DPRINTF(WRSM_DEBUG, (CE_CONT, "wrsm_close:wrsm%d: "
		    " minor=%d", instance, minor));
	}
	mutex_enter(&softsp->wrsm_mutex);
	softsp->open = 0;
	mutex_exit(&softsp->wrsm_mutex);

	return (WRSM_SUCCESS);
}


/* ARGSUSED */
static int
wrsm_ioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *cred_p,
	int *rval_p)
{
	struct wrsm_soft_state *softsp;
	int minor;
	int instance;
	int retval;

	minor = getminor(dev);
	if (minor >= MAX_INSTANCES)
		return (ENXIO);
	instance = minor_to_instance[minor];
	if (instance == -1)
		return (ENXIO);

	softsp = ddi_get_soft_state(wrsm_softstates, instance);
	/* Verify instance structure */
	if (softsp == NULL)
		return (ENXIO);
	DPRINTF(WRSM_DEBUG, (CE_CONT, "wrsm_ioctl:wrsm%d: dev=0x%lx, "
	    "softsp=0x%p\n", instance, dev, (void *)softsp));

	/*
	 * The 3 types of WCI devices support different ioctls. Use a
	 * different ioctl handling function for each type, so it's easier
	 * to fail on an unsupported ioctl.
	 */

	switch (softsp->type) {

	case wrsm_admin:
		retval = wrsm_cf_admin_ioctl(softsp, cmd, arg, flag, cred_p,
		    rval_p);
		DPRINTF(WRSM_DEBUG, (CE_CONT, "wrsm_ioctl:ret %d rval %d",
		    retval, *rval_p));
		return (retval);

	case wrsm_rsm_controller:
		switch (cmd) {
		case WRSM_CTLR_PLUGIN_SMALLPUT:
			/*
			 * the wrsm_smallput_plugin_ioctl is required
			 * functionality the so that the plugin library can
			 * perform smallputs.
			 */
			return (wrsm_smallput_plugin_ioctl(softsp->minor, cmd,
			    arg, flag, cred_p, rval_p));
		case WRSM_CTLR_PLUGIN_GETLOCALNODE:
			/*
			 * the plugin library needs to know if the export cnode
			 * is a local node
			 */
			return (wrsm_nc_getlocalnode_ioctl(softsp->minor, cmd,
			    arg, flag, cred_p, rval_p));
		default:
			/* provided solely for debuging and testing */
			return (wrsm_cf_ctlr_ioctl(softsp->minor, cmd, arg,
			    flag, cred_p, rval_p));
		}

	default:
		ASSERT(softsp->type == wrsm_device);
		DPRINTF(WRSM_DEBUG, (CE_CONT, "wrsm_ioctl - wrsm_device"));
		retval = wrsm_device_ioctl(softsp, cmd,  arg, flag, cred_p,
		    rval_p);
		return (retval);
	}
}


/* ARGSUSED */
static int
wrsm_segmap(dev_t dev, off_t off, struct as *asp, caddr_t *addrp,
    off_t len, unsigned int prot, unsigned int maxprot,
    unsigned int flags, cred_t *cred)
{

	/*
	 * wrsm_segmap is currently handling only controller related segmaps.
	 * In the event other wrsm type devices (wci or admin( require the
	 * use of segmap, appropriate ddi calls to fetch the softstate
	 * structure will be needed. We know the call into the
	 * wrsm_memseg_segmap will fail for wci or admin devices because the
	 * minor dev won't map to a valid controller id.
	 */
	return (wrsm_memseg_segmap(dev, off, asp, addrp, len, prot, maxprot,
	    flags, cred));

}

/* ARGSUSED */
static int
wrsm_devmap(dev_t dev, devmap_cookie_t handle, offset_t off,
    size_t len, size_t *maplen, uint_t model)
{

	/*
	 * wrsm_devmap is currently handling only controller related segmaps.
	 * In the event other wrsm type devices (wci or admin( require the
	 * use of segmap, appropriate ddi calls to fetch the softstate
	 * structure will be needed. We know the call into the
	 * wrsm_memseg_devmap will fail for wci or admin devices because the
	 * minor dev won't map to a valid controller id.
	 */
	return (wrsm_memseg_devmap(dev, handle, off, len, maplen, model));
}



/*ARGSUSED*/
static int
wrsm_device_ioctl(wrsm_softstate_t *softsp, int cmd, intptr_t arg,
    int flag, cred_t *cred_p, int *rval_p)
{
	int retval = 0;
	uint32_t wci_owner;
	wrsm_linktest_arg_t linktest;
	int linkno;

	DPRINTF(WRSM_DEBUG, (CE_CONT, "	in wrsm_device_ioctl\n"));

	/* Only allow privileged users to do this */
	if ((retval = secpolicy_sys_config(cred_p, B_FALSE)) != 0)
		return (retval);

	switch (cmd) {

	case WRSM_WCI_LOOPBACK_ON:
		retval = wrsm_lc_loopback_enable(softsp, (uint32_t)arg);
		break;

	case WRSM_WCI_LOOPBACK_OFF:
		retval = wrsm_lc_loopback_disable(softsp, (uint32_t)arg);
		break;

	case WRSM_WCI_LINKTEST:
		if (ddi_copyin((void *)arg, &linktest,
		    sizeof (wrsm_linktest_arg_t), flag) != 0) {
			retval = EFAULT;
			break;
		}
		if ((retval = wrsm_lc_linktest(softsp, &linktest)) != 0)
			break;
		if (ddi_copyout(&linktest, (void *)arg,
		    sizeof (wrsm_linktest_arg_t), flag) != 0)
			retval = EFAULT;
		break;

	case WRSM_WCI_CLAIM:
		retval = wrsm_cf_claim_wci(WRSM_LOOPBACK_ID, softsp->portid);
		break;

	case WRSM_WCI_RELEASE:
		/* find out which controller (if any) this WCI belongs to */
		wci_owner = wrsm_cf_wci_owner(softsp->portid);
		if (wci_owner != WRSM_LOOPBACK_ID) {
			retval = EACCES;
			break;
		}
		wrsm_cf_release_wci(softsp->portid);
		return (0);

	case WRSM_WCI_LINKUP:
		if (ddi_copyin((void *)arg, &linkno,
		    sizeof (linkno), flag) != 0) {
			retval = EFAULT;
			break;
		}
		retval = wrsm_lc_user_linkup(softsp, linkno);
		break;

	case WRSM_WCI_LINKDOWN:
		if (ddi_copyin((void *)arg, &linkno,
		    sizeof (linkno), flag) != 0) {
			retval = EFAULT;
			break;
		}
		retval = wrsm_lc_user_linkdown(softsp, linkno);
		break;

	default:
		retval = wrsm_lc_register_ioctl(softsp, cmd, arg, flag,
		    cred_p, rval_p);
		break;
	}

	return (retval);
}

static int
wrsm_map_regs(wrsm_softstate_t *softsp)
{
	volatile unsigned char *sram_vaddr;

	DPRINTF(WRSM_DEBUG, (CE_CONT, "in wrsm_map_regs \n"));

	/* Map in the device registers */
	ASSERT(softsp->type == wrsm_device);
	if (ddi_map_regs(softsp->dip, WRSM_REGS,
	    (caddr_t *)&softsp->wrsm_regs, 0, 0)) {
		cmn_err(CE_WARN, "wrsm%d: unable to map register set %d",
		    softsp->instance, WRSM_REGS);
		return (DDI_FAILURE);
	}
	/*
	 * since OBP provides SRAM as a register set
	 * we use ddi_map_regs to get the vaddr
	 * for the SRAM and then we use va_to_pa to get
	 * the physical addr.
	 */
	if (ddi_map_regs(softsp->dip, WRSM_SRAM,
	    (caddr_t *)&sram_vaddr, 0, 1)) {
		cmn_err(CE_WARN, "wrsm%d: unable to map register set %d",
		    softsp->instance, WRSM_SRAM);
		wrsm_unmap_regs(softsp);
		return (DDI_FAILURE);
	}
	if (ddi_dev_regsize(softsp->dip, WRSM_SRAM,
	    &softsp->sramsize) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "wrsm%d: sramsize not"
		    " available %d", softsp->instance,
		    WRSM_SRAM);
		ddi_unmap_regs(softsp->dip, WRSM_SRAM, (caddr_t *)&sram_vaddr,
		    0, 1);
		wrsm_unmap_regs(softsp);
		return (DDI_FAILURE);
	}
	/* physical addr for sram */
	softsp->wrsm_sram = (unsigned char *)va_to_pa((void *)sram_vaddr);
	DPRINTF(WRSM_DEBUG, (CE_CONT, "wrsm%d sram physical addr %p",
	    softsp->instance, softsp->wrsm_sram));

	ddi_unmap_regs(softsp->dip, WRSM_SRAM, (caddr_t *)&sram_vaddr, 0, 1);
	return (DDI_SUCCESS);
}

static void
wrsm_unmap_regs(wrsm_softstate_t *softsp)
{
	DPRINTF(WRSM_DEBUG, (CE_CONT, " unmapped wrsm regs"));

	if (softsp->wrsm_regs)
		ddi_unmap_regs(softsp->dip, WRSM_REGS,
		    (caddr_t *)&softsp->wrsm_regs, 0, 0);
}

static void
wrsm_add_status_kstat(wrsm_softstate_t *softsp)
{
	struct kstat *status_ksp;
	wrsm_status_kstat_t *status_named_ksp;
	int instance;
	int i;
	char tmp_str[100];

	/* Get the instance */
	instance = softsp->instance;

	if ((status_ksp = kstat_create(WRSM_KSTAT_WRSM, instance,
	    WRSM_KSTAT_STATUS,
	    "bus", KSTAT_TYPE_NAMED,
	    sizeof (wrsm_status_kstat_t) / sizeof (kstat_named_t),
	    0)) == NULL) {
		cmn_err(CE_WARN, "wci%d: kstat_create failed", instance);
		return;
	}

	status_named_ksp = (wrsm_status_kstat_t *)(status_ksp->ks_data);

	/* initialize the named kstats */
	kstat_named_init(&status_named_ksp->ks_version,
	    WRSMKS_WCI_VERSION_NAMED, KSTAT_DATA_UINT64);

	kstat_named_init(&status_named_ksp->controller_id,
	    WRSMKS_CONTROLLER_ID_NAMED, KSTAT_DATA_UINT32);

	kstat_named_init(&status_named_ksp->portid,
	    WRSMKS_PORTID, KSTAT_DATA_UINT32);

	kstat_named_init(&status_named_ksp->error_limit,
	    WRSMKS_ERROR_LIMIT, KSTAT_DATA_UINT32);

	kstat_named_init(&status_named_ksp->errstat_interval,
	    WRSMKS_ERRSTAT_INTERVAL, KSTAT_DATA_UINT32);

	kstat_named_init(&status_named_ksp->intervals_per_lt,
	    WRSMKS_INTERVALS_PER_LT, KSTAT_DATA_UINT32);

	kstat_named_init(&status_named_ksp->avg_weight,
	    WRSMKS_AVG_WEIGHT, KSTAT_DATA_UINT32);

	for (i = 0; i < WCI_NUM_LINKS; i++) {

	    (void) sprintf(tmp_str, WRSMKS_VALID_LINK, i);
	    kstat_named_init(&status_named_ksp->valid_link[i],
		    tmp_str, KSTAT_DATA_UINT32);
	    (void) sprintf(tmp_str, WRSMKS_REMOTE_CNODE_ID, i);
	    kstat_named_init(&status_named_ksp->remote_cnode_id[i],
		    tmp_str, KSTAT_DATA_UINT32);
	    (void) sprintf(tmp_str, WRSMKS_REMOTE_WNODE, i);
	    kstat_named_init(&status_named_ksp->remote_wnode_id[i],
		    tmp_str, KSTAT_DATA_UINT32);
	    (void) sprintf(tmp_str, WRSMKS_REMOTE_WCI_PORTID, i);
	    kstat_named_init(&status_named_ksp->remote_wci_portid[i],
		    tmp_str, KSTAT_DATA_UINT32);
	    (void) sprintf(tmp_str, WRSMKS_REMOTE_LINKNUM, i);
	    kstat_named_init(&status_named_ksp->remote_linknum[i],
		    tmp_str, KSTAT_DATA_UINT32);
	    (void) sprintf(tmp_str, WRSMKS_LC_LINK_STATE, i);
	    kstat_named_init(&status_named_ksp->state[i],
		    tmp_str, KSTAT_DATA_UINT32);
	    (void) sprintf(tmp_str, WRSMKS_PHYS_LINK_STATE, i);
	    kstat_named_init(&status_named_ksp->link_state[i],
		    tmp_str, KSTAT_DATA_UINT32);
	    (void) sprintf(tmp_str, WRSMKS_PHYS_LASER_ENABLE, i);
	    kstat_named_init(&status_named_ksp->laser[i],
		    tmp_str, KSTAT_DATA_UINT32);
	    (void) sprintf(tmp_str, WRSMKS_PHYS_XMIT_ENABLE, i);
	    kstat_named_init(&status_named_ksp->xmit_enable[i],
		    tmp_str, KSTAT_DATA_UINT32);

	    (void) sprintf(tmp_str, WRSMKS_LINK_ERR_TAKEDOWNS, i);
	    kstat_named_init(&status_named_ksp->link_err_takedowns[i],
		    tmp_str, KSTAT_DATA_UINT32);
	    (void) sprintf(tmp_str, WRSMKS_LAST_LINK_ERR_TAKEDOWNS, i);
	    kstat_named_init(&status_named_ksp->last_link_err_takedowns[i],
		    tmp_str, KSTAT_DATA_UINT32);
	    (void) sprintf(tmp_str, WRSMKS_MAX_LINK_ERR_TAKEDOWNS, i);
	    kstat_named_init(&status_named_ksp->max_link_err_takedowns[i],
		    tmp_str, KSTAT_DATA_UINT32);
	    (void) sprintf(tmp_str, WRSMKS_AVG_LINK_ERR_TAKEDOWNS, i);
	    kstat_named_init(&status_named_ksp->avg_link_err_takedowns[i],
		    tmp_str, KSTAT_DATA_UINT32);

	    (void) sprintf(tmp_str, WRSMKS_LINK_DISCON_TAKEDOWNS, i);
	    kstat_named_init(&status_named_ksp->
		link_disconnected_takedowns[i], tmp_str, KSTAT_DATA_UINT32);
	    (void) sprintf(tmp_str, WRSMKS_LINK_CFG_TAKEDOWNS, i);
	    kstat_named_init(&status_named_ksp->link_cfg_takedowns[i],
		    tmp_str, KSTAT_DATA_UINT32);
	    (void) sprintf(tmp_str, WRSMKS_LINK_FAILED_BRINGUPS, i);
	    kstat_named_init(&status_named_ksp->link_failed_bringups[i],
		    tmp_str, KSTAT_DATA_UINT32);

	    (void) sprintf(tmp_str, WRSMKS_LINK_ENABLED, i);
	    kstat_named_init(&status_named_ksp->link_enabled[i],
		    tmp_str, KSTAT_DATA_UINT32);
	    (void) sprintf(tmp_str, WRSMKS_LINK_INTERVAL_COUNT, i);
	    kstat_named_init(&status_named_ksp->link_interval_count[i],
		    tmp_str, KSTAT_DATA_UINT32);

	    (void) sprintf(tmp_str, WRSMKS_LINK_ERRORS, i);
	    kstat_named_init(&status_named_ksp->link_errors[i],
		    tmp_str, KSTAT_DATA_UINT32);
	    (void) sprintf(tmp_str, WRSMKS_LAST_LINK_ERRORS, i);
	    kstat_named_init(&status_named_ksp->last_link_errors[i],
		    tmp_str, KSTAT_DATA_UINT32);
	    (void) sprintf(tmp_str, WRSMKS_MAX_LINK_ERRORS, i);
	    kstat_named_init(&status_named_ksp->max_link_errors[i],
		    tmp_str, KSTAT_DATA_UINT32);
	    (void) sprintf(tmp_str, WRSMKS_AVG_LINK_ERRORS, i);
	    kstat_named_init(&status_named_ksp->avg_link_errors[i],
		    tmp_str, KSTAT_DATA_UINT32);
	    (void) sprintf(tmp_str, WRSMKS_LAST_LT_LINK_ERRORS, i);
	    kstat_named_init(&status_named_ksp->last_lt_link_errors[i],
		    tmp_str, KSTAT_DATA_UINT32);
	    (void) sprintf(tmp_str, WRSMKS_MAX_LT_LINK_ERRORS, i);
	    kstat_named_init(&status_named_ksp->max_lt_link_errors[i],
		    tmp_str, KSTAT_DATA_UINT32);
	    (void) sprintf(tmp_str, WRSMKS_AVG_LT_LINK_ERRORS, i);
	    kstat_named_init(&status_named_ksp->avg_lt_link_errors[i],
		    tmp_str, KSTAT_DATA_UINT32);


	    (void) sprintf(tmp_str, WRSMKS_AUTO_SHUTDOWN_EN, i);
	    kstat_named_init(&status_named_ksp->auto_shutdown_en[i],
		    tmp_str, KSTAT_DATA_UINT32);

	}

	kstat_named_init(&status_named_ksp->cluster_error_count,
	    WRSMKS_CLUSTER_ERROR_COUNT, KSTAT_DATA_UINT64);

	kstat_named_init(&status_named_ksp->uc_sram_ecc_error,
	    WRSMKS_UC_SRAM_ECC_ERROR, KSTAT_DATA_UINT32);

	kstat_named_init(&status_named_ksp->sram_ecc_errors,
	    WRSMKS_LAST_SRAM_ECC_ERRORS, KSTAT_DATA_UINT32);

	kstat_named_init(&status_named_ksp->last_sram_ecc_errors,
	    WRSMKS_LAST_SRAM_ECC_ERRORS, KSTAT_DATA_UINT32);

	kstat_named_init(&status_named_ksp->max_sram_ecc_errors,
	    WRSMKS_MAX_SRAM_ECC_ERRORS, KSTAT_DATA_UINT32);

	kstat_named_init(&status_named_ksp->avg_sram_ecc_errors,
	    WRSMKS_AVG_SRAM_ECC_ERRORS, KSTAT_DATA_UINT32);

	/* Save the kstat pointer in the softstate */
	softsp->wrsm_wci_ksp = status_ksp;

	status_ksp->ks_update = wrsm_status_kstat_update;
	status_ksp->ks_private = (void *)softsp;
	kstat_install(status_ksp);

}

static int
wrsm_status_kstat_update(kstat_t *ksp, int rw)
{
	wrsm_status_kstat_t *link_ksp;
	wrsm_softstate_t *softsp;
	uint32_t controller_id;

	wrsm_wci_data_t *config;
	wnodeid_t remote_wnode;
	gnid_t remote_gnid;
	int num_failed_bringups;
	int i;
	wci_sw_link_control_u reg;
	wci_cluster_error_count_u errors;

	link_ksp  = (wrsm_status_kstat_t *)ksp->ks_data;
	softsp = (wrsm_softstate_t *)ksp->ks_private;

	mutex_enter(&softsp->lc_mutex);
	link_ksp->portid.value.ui32 = softsp->portid;
	link_ksp->error_limit.value.ui32 = MAXERRORS;
	link_ksp->errstat_interval.value.ui32 = wrsm_shortterm_interval;
	link_ksp->intervals_per_lt.value.ui32 = wrsm_shorts_per_longterm;
	link_ksp->avg_weight.value.ui32 = wrsm_avg_weight;

	if (softsp->config == NULL) {
		/* Device is not part of a controller */
		link_ksp->controller_id.value.ui32 =
		    (uint32_t)WRSM_KSTAT_NO_CTRLR;
		link_ksp->ks_version.value.ui64 = 0;
		/* Set all links to be invalid status */
		for (i = 0; i < WCI_NUM_LINKS; i++) {
			link_ksp->valid_link[i].value.ui32 =
				(uint32_t)WRSMKS_LINK_NOT_PRESENT;
			/*
			 * The rest of these fields should be ignored since
			 * link is marked "not present", but set to 0 just
			 * to be sure.
			 */
			link_ksp->remote_cnode_id[i].value.ui32 = 0;
			link_ksp->remote_wnode_id[i].value.ui32 = 0;
			link_ksp->remote_wci_portid[i].value.ui32 = 0;
			link_ksp->remote_linknum[i].value.ui32 = 0;
			link_ksp->state[i].value.ui32 = 0;
			link_ksp->laser[i].value.ui32 = 0;
			link_ksp->xmit_enable[i].value.ui32 = 0;
			link_ksp->link_state[i].value.ui32 = 0;
			link_ksp->link_err_takedowns[i].value.ui32 = 0;
			link_ksp->last_link_err_takedowns[i].value.ui32 = 0;
			link_ksp->max_link_err_takedowns[i].value.ui32 = 0;
			link_ksp->avg_link_err_takedowns[i].value.ui32 = 0;
			link_ksp->link_disconnected_takedowns[i].value.ui32 =
				0;
			link_ksp->link_cfg_takedowns[i].value.ui32 = 0;
			link_ksp->link_failed_bringups[i].value.ui32 = 0;
			link_ksp->link_interval_count[i].value.ui32 = 0;
			link_ksp->link_enabled[i].value.ui32 = 0;
			link_ksp->link_errors[i].value.ui32 = 0;
			link_ksp->last_link_errors[i].value.ui32 = 0;
			link_ksp->max_link_errors[i].value.ui32 = 0;
			link_ksp->avg_link_errors[i].value.ui32 = 0;
			link_ksp->last_lt_link_errors[i].value.ui32 = 0;
			link_ksp->max_lt_link_errors[i].value.ui32 = 0;
			link_ksp->avg_lt_link_errors[i].value.ui32 = 0;
			link_ksp->auto_shutdown_en[i].value.ui32 = 0;
		}
		/* Set error kstats to 0 -- not applicable if not in ctrl */
		link_ksp->cluster_error_count.value.ui64 = 0;
		link_ksp->uc_sram_ecc_error.value.ui32 = 0;
		link_ksp->sram_ecc_errors.value.ui32 = 0;
		link_ksp->max_sram_ecc_errors.value.ui32 = 0;
		link_ksp->last_sram_ecc_errors.value.ui32 = 0;
		link_ksp->avg_sram_ecc_errors.value.ui32 = 0;

		mutex_exit(&softsp->lc_mutex);
		return (WRSM_SUCCESS);
	}

	if (rw == KSTAT_WRITE) {
		mutex_exit(&softsp->lc_mutex);
		return (EACCES);
	}

	config = softsp->config;
	controller_id = wrsm_cf_wci_owner(softsp->portid);
	link_ksp->ks_version.value.ui64 =
		softsp->ctlr_config->version_stamp;
	link_ksp->controller_id.value.ui32 = (uint32_t)controller_id;

	for (i = 0; i < WCI_NUM_LINKS; i++) {

		if (config->links[i].present == 1) {
			/* read the wci_sw_controll register */
			wrsm_lc_csr_read(softsp,
			ADDR_WCI_SW_LINK_CONTROL +
			    (i * STRIDE_WCI_SW_LINK_CONTROL),
			    &reg.val);

			link_ksp->valid_link[i].value.ui32 =
				(uint32_t)WRSMKS_LINK_PRESENT;

			remote_gnid = config->links[i].remote_gnid;
			remote_wnode = config->gnid_to_wnode[remote_gnid];

			link_ksp->remote_cnode_id[i].value.ui32 =
				(uint32_t)config->reachable[remote_wnode];

			link_ksp->remote_wnode_id[i].value.ui32 =
				(uint32_t)remote_wnode;

			link_ksp->remote_wci_portid[i].value.ui32 =
			    (uint32_t)config->links[i].remote_port;

			link_ksp->remote_linknum[i].value.ui32 =
				(uint32_t)config->links[i].remote_link_num;

			link_ksp->state[i].value.ui32 =
				(uint32_t)softsp->links[i].link_req_state;

			link_ksp->link_state[i].value.ui32 =
				reg.bit.link_state;

			link_ksp->laser[i].value.ui32 =
				reg.bit.laser_enable;

			link_ksp->xmit_enable[i].value.ui32 =
				reg.bit.xmit_enable;

			num_failed_bringups =
				softsp->links[i].num_requested_bringups -
				softsp->links[i].num_completed_bringups;

			link_ksp->link_failed_bringups[i].value.ui32 =
				num_failed_bringups;

			/* link takedown stats */
			link_ksp->link_err_takedowns[i].value.ui32 =
				softsp->links[i].num_err_takedown;

			link_ksp->last_link_err_takedowns[i].value.ui32 =
				softsp->links[i].last_err_takedown;

			link_ksp->max_link_err_takedowns[i].value.ui32 =
				softsp->links[i].max_err_takedown;

			/* note that avg_err is average * weight */
			link_ksp->avg_link_err_takedowns[i].value.ui32 =
				(softsp->links[i].avg_err_takedown /
				wrsm_avg_weight);

			link_ksp->link_disconnected_takedowns[i].
				value.ui32 =
				softsp->links[i].num_disconnected_takedown;

			link_ksp->link_cfg_takedowns[i].value.ui32 =
				softsp->links[i].num_cfg_takedown;

			link_ksp->link_enabled[i].value.ui32 =
				softsp->links[i].user_down_requested ?
				0 : 1;

			/* shortterm interval count */
			link_ksp->link_interval_count[i].value.ui32 =
				softsp->links[i].interval_count;

			/* shortterm link error stats */
			link_ksp->link_errors[i].value.ui32 =
				softsp->links[i].num_errors;

			link_ksp->last_link_errors[i].value.ui32 =
				softsp->links[i].shortterm_last_errors;

			link_ksp->max_link_errors[i].value.ui32 =
				softsp->links[i].shortterm_max_errors;

			/* note that avg_errors is average * weight */
			link_ksp->avg_link_errors[i].value.ui32 =
				(softsp->links[i].shortterm_avg_errors /
				wrsm_avg_weight);

			/* longterm link error stats */
			link_ksp->last_lt_link_errors[i].value.ui32 =
				softsp->links[i].longterm_last_errors;

			link_ksp->max_lt_link_errors[i].value.ui32 =
				softsp->links[i].longterm_max_errors;

			/* note that avg_errors is average * weight */
			link_ksp->avg_lt_link_errors[i].value.ui32 =
				(softsp->links[i].longterm_avg_errors
				/ wrsm_avg_weight);


			/* set the auto_shutdown_en[i] field */
			link_ksp->auto_shutdown_en[i].value.ui32 =
				reg.bit.auto_shut_en;

		} else {
			/* This link does not exist */
			link_ksp->valid_link[i].value.ui32 =
				(uint32_t)WRSMKS_LINK_NOT_PRESENT;
			/*
			 * The rest of these fields should be ignored since
			 * link is marked "not present", but set to 0 just
			 * to be sure.
			 */
			link_ksp->remote_cnode_id[i].value.ui32 = 0;
			link_ksp->remote_wnode_id[i].value.ui32 = 0;
			link_ksp->remote_wci_portid[i].value.ui32 = 0;
			link_ksp->remote_linknum[i].value.ui32 = 0;
			link_ksp->state[i].value.ui32 = 0;
			link_ksp->laser[i].value.ui32 = 0;
			link_ksp->xmit_enable[i].value.ui32 = 0;
			link_ksp->link_state[i].value.ui32 = 0;
			link_ksp->link_err_takedowns[i].value.ui32 = 0;
			link_ksp->last_link_err_takedowns[i].value.ui32 = 0;
			link_ksp->max_link_err_takedowns[i].value.ui32 = 0;
			link_ksp->avg_link_err_takedowns[i].value.ui32 = 0;
			link_ksp->link_disconnected_takedowns[i].value.ui32 =
				0;
			link_ksp->link_cfg_takedowns[i].value.ui32 = 0;
			link_ksp->link_failed_bringups[i].value.ui32 = 0;
			link_ksp->link_interval_count[i].value.ui32 = 0;
			link_ksp->link_enabled[i].value.ui32 = 0;
			link_ksp->link_errors[i].value.ui32 = 0;
			link_ksp->last_link_errors[i].value.ui32 = 0;
			link_ksp->max_link_errors[i].value.ui32 = 0;
			link_ksp->avg_link_errors[i].value.ui32 = 0;
			link_ksp->last_lt_link_errors[i].value.ui32 = 0;
			link_ksp->max_lt_link_errors[i].value.ui32 = 0;
			link_ksp->avg_lt_link_errors[i].value.ui32 = 0;
			link_ksp->auto_shutdown_en[i].value.ui32 = 0;
		}
	}
	wrsm_lc_csr_read(softsp, ADDR_WCI_CLUSTER_ERROR_COUNT, &errors.val);

	link_ksp->cluster_error_count.value.ui64 = errors.val;
	link_ksp->uc_sram_ecc_error.value.ui32 = softsp->uc_sram_ecc_error;
	link_ksp->sram_ecc_errors.value.ui32 = softsp->num_sram_ecc_errors;
	link_ksp->max_sram_ecc_errors.value.ui32 =
	    softsp->max_sram_ecc_errors;
	link_ksp->last_sram_ecc_errors.value.ui32 =
	    softsp->last_sram_ecc_errors;
	/* note that the avg_sram_ecc_errors is the average * weight */
	link_ksp->avg_sram_ecc_errors.value.ui32 =
	    (softsp->avg_sram_ecc_errors / wrsm_avg_weight);

	mutex_exit(&softsp->lc_mutex);

	return (WRSM_SUCCESS);
}


static void
wrsm_del_status_kstat(wrsm_softstate_t *softsp)
{
	kstat_delete(softsp->wrsm_wci_ksp);
}


/*
 * translate from dip to network pointer
 */
wrsm_network_t *
wrsm_dip_to_network(dev_info_t *dip)
{
	int instance;
	wrsm_softstate_t *softsp;

	instance = ddi_get_instance(dip);
	if ((softsp = ddi_get_soft_state(wrsm_softstates, instance)) == NULL) {
		return (NULL);
	}
	if (softsp->type != wrsm_rsm_controller) {
		return (NULL);
	}
	return (wrsm_nc_ctlr_to_network(softsp->minor));
}
