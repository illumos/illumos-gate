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
 * hci1394_attach.c
 *    HBA attach() routine with associated funtions.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/pci.h>

#include <sys/1394/h1394.h>
#include <sys/1394/adapters/hci1394.h>
#include <sys/1394/adapters/hci1394_extern.h>


/*
 * Attach State Information. These states are used to track the status of the
 * attach.  They are bit offsets.
 */
#define	STATE_ZALLOC		0
#define	STATE_ISR_INIT		1
#define	STATE_MINOR_NODE	2
#define	STATE_HW_INIT		3
#define	STATE_PHASE2		4
#define	STATE_POWER_INIT	5
#define	STATE_H1394_ATTACH	6
#define	STATE_ISR_HANDLER	7
#define	STATE_STARTUP		8

static void hci1394_statebit_set(uint64_t *state, uint_t statebit);
static boolean_t hci1394_statebit_tst(uint64_t state, uint_t statebit);

static void hci1394_cleanup(hci1394_state_t *soft_state, uint64_t attach_state);

static int hci1394_hardware_init(hci1394_state_t *soft_state);
static int hci1394_hardware_resume(hci1394_state_t *soft_state);

static int hci1394_pci_init(hci1394_state_t *soft_state);
static void hci1394_pci_resume(hci1394_state_t *soft_state);

static void hci1394_soft_state_phase1_init(hci1394_state_t *soft_state,
    dev_info_t *dip, int instance);
static void hci1394_soft_state_phase2_init(hci1394_state_t *soft_state);

static int hci1394_resmap_get(hci1394_state_t *soft_state);
static void hci1394_resmap_free(hci1394_state_t *soft_state);



int
hci1394_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	hci1394_state_t *soft_state;
	uint64_t attach_state = 0;
	int instance;
	int status;


	TNF_PROBE_0_DEBUG(hci1394_attach_enter, HCI1394_TNF_HAL_STACK, "");

	switch (cmd) {
	case DDI_ATTACH:
		instance = ddi_get_instance(dip);
		status = ddi_soft_state_zalloc(hci1394_statep, instance);
		if (status != DDI_SUCCESS) {
			TNF_PROBE_1(hci1394_attach_ssz_fail,
			    HCI1394_TNF_HAL_ERROR, "", tnf_string, errmsg,
			    "ddi_soft_state_zalloc() failed");
			TNF_PROBE_0_DEBUG(hci1394_attach_exit,
			    HCI1394_TNF_HAL_STACK, "");
			return (DDI_FAILURE);
		}
		soft_state = ddi_get_soft_state(hci1394_statep, instance);
		if (soft_state == NULL) {
			ddi_soft_state_free(hci1394_statep, instance);
			TNF_PROBE_1(hci1394_attach_gss_fail,
			    HCI1394_TNF_HAL_ERROR, "", tnf_string, errmsg,
			    "ddi_get_soft_state() failed");
			TNF_PROBE_0_DEBUG(hci1394_attach_exit,
			    HCI1394_TNF_HAL_STACK, "");
			return (DDI_FAILURE);
		}
		hci1394_statebit_set(&attach_state, STATE_ZALLOC);

		hci1394_soft_state_phase1_init(soft_state, dip, instance);

		/* get iblock cookie, other interrupt init stuff */
		status = hci1394_isr_init(soft_state);
		if (status != DDI_SUCCESS) {
			hci1394_cleanup(soft_state, attach_state);
			TNF_PROBE_0(hci1394_attach_isr_fail,
			    HCI1394_TNF_HAL_ERROR, "");
			TNF_PROBE_0_DEBUG(hci1394_attach_exit,
			    HCI1394_TNF_HAL_STACK, "");
			return (DDI_FAILURE);
		}
		hci1394_statebit_set(&attach_state, STATE_ISR_INIT);

		status = ddi_create_minor_node(dip, "devctl", S_IFCHR,
		    instance, DDI_NT_NEXUS, 0);
		if (status != DDI_SUCCESS) {
			hci1394_cleanup(soft_state, attach_state);
			TNF_PROBE_0(hci1394_attach_cmn_fail,
			    HCI1394_TNF_HAL_ERROR, "");
			TNF_PROBE_0_DEBUG(hci1394_attach_exit,
			    HCI1394_TNF_HAL_STACK, "");
			return (DDI_FAILURE);
		}
		hci1394_statebit_set(&attach_state, STATE_MINOR_NODE);

		status = hci1394_hardware_init(soft_state);
		if (status != DDI_SUCCESS) {
			hci1394_cleanup(soft_state, attach_state);
			TNF_PROBE_0(hci1394_attach_hwi_fail,
			    HCI1394_TNF_HAL_ERROR, "");
			TNF_PROBE_0_DEBUG(hci1394_attach_exit,
			    HCI1394_TNF_HAL_STACK, "");
			return (DDI_FAILURE);
		}
		hci1394_statebit_set(&attach_state, STATE_HW_INIT);

		hci1394_soft_state_phase2_init(soft_state);
		hci1394_statebit_set(&attach_state, STATE_PHASE2);

		/* build up the reserved addresses map */
		status = hci1394_resmap_get(soft_state);
		if (status != DDI_SUCCESS) {
			hci1394_cleanup(soft_state, attach_state);
			TNF_PROBE_0(hci1394_attach_rmg_fail,
			    HCI1394_TNF_HAL_ERROR, "");
			TNF_PROBE_0_DEBUG(hci1394_attach_exit,
			    HCI1394_TNF_HAL_STACK, "");
			return (DDI_FAILURE);
		}

		/* "attach" to the Services Layer */
		status = h1394_attach(&soft_state->halinfo, DDI_ATTACH,
		    &soft_state->drvinfo.di_sl_private);
		if (status != DDI_SUCCESS) {
			hci1394_resmap_free(soft_state);
			hci1394_cleanup(soft_state, attach_state);
			TNF_PROBE_0(hci1394_attach_ha_fail,
			    HCI1394_TNF_HAL_ERROR, "");
			TNF_PROBE_0_DEBUG(hci1394_attach_exit,
			    HCI1394_TNF_HAL_STACK, "");
			return (DDI_FAILURE);
		}
		/* free the reserved addresses map */
		hci1394_resmap_free(soft_state);

		hci1394_statebit_set(&attach_state, STATE_H1394_ATTACH);
		status = hci1394_isr_handler_init(soft_state);
		if (status != DDI_SUCCESS) {
			hci1394_cleanup(soft_state, attach_state);
			TNF_PROBE_0(hci1394_attach_ih_fail,
			    HCI1394_TNF_HAL_ERROR, "");
			TNF_PROBE_0_DEBUG(hci1394_attach_exit,
			    HCI1394_TNF_HAL_STACK, "");
			return (DDI_FAILURE);
		}
		hci1394_statebit_set(&attach_state, STATE_ISR_HANDLER);

		/* Report that driver was loaded */
		ddi_report_dev(dip);

		/*
		 * Turn on link, Reset Bus, enable interrupts.  Should be the
		 * last routine called in attach. The statebit for starup must
		 * be set before startup is called since startup enables
		 * interrupts.
		 */
		hci1394_statebit_set(&attach_state, STATE_STARTUP);
		status = hci1394_ohci_startup(soft_state->ohci);
		if (status != DDI_SUCCESS) {
			hci1394_cleanup(soft_state, attach_state);
			TNF_PROBE_0(hci1394_attach_str_fail,
			    HCI1394_TNF_HAL_ERROR, "");
			TNF_PROBE_0_DEBUG(hci1394_attach_exit,
			    HCI1394_TNF_HAL_STACK, "");
			return (DDI_FAILURE);
		}
		TNF_PROBE_0_DEBUG(hci1394_attach_exit, HCI1394_TNF_HAL_STACK,
		    "");

		return (DDI_SUCCESS);

	case DDI_RESUME:
		instance = ddi_get_instance(dip);
		soft_state = ddi_get_soft_state(hci1394_statep, instance);
		if (soft_state == NULL) {
			TNF_PROBE_1(hci1394_attach_resgss_fail,
			    HCI1394_TNF_HAL_ERROR, "", tnf_string, errmsg,
			    "ddi_get_soft_state() failed");
			TNF_PROBE_0_DEBUG(hci1394_attach_exit,
			    HCI1394_TNF_HAL_STACK, "");
			return (DDI_FAILURE);
		}

		status = hci1394_hardware_resume(soft_state);
		if (status != DDI_SUCCESS) {
			TNF_PROBE_1(hci1394_attach_res_hwr_fail,
			    HCI1394_TNF_HAL_ERROR, "", tnf_string, errmsg,
			    "hardware failed to resume");
			TNF_PROBE_0_DEBUG(hci1394_attach_exit,
			    HCI1394_TNF_HAL_STACK, "");
			return (DDI_FAILURE);
		}

		/*
		 * set our state back to initial.  The next bus reset were
		 * about to generate will set us in motion.
		 */
		soft_state->drvinfo.di_drvstate.ds_state = HCI1394_INITIAL;

		/* turn on the link, enable interrupts, reset the bus */
		status = hci1394_ohci_startup(soft_state->ohci);
		if (status != DDI_SUCCESS) {
			TNF_PROBE_1(hci1394_attach_res_str_fail,
			    HCI1394_TNF_HAL_ERROR, "", tnf_string, errmsg,
			    "hci1394_ohci_startup() failed");
			TNF_PROBE_0_DEBUG(hci1394_attach_exit,
			    HCI1394_TNF_HAL_STACK, "");
			return (DDI_FAILURE);
		}

		/* tell the Services Layer that we are resuming */
		status = h1394_attach(&soft_state->halinfo, DDI_RESUME,
		    &soft_state->drvinfo.di_sl_private);
		if (status != DDI_SUCCESS) {
			TNF_PROBE_0(hci1394_attach_res_ha_fail,
			    HCI1394_TNF_HAL_ERROR, "");
			TNF_PROBE_0_DEBUG(hci1394_attach_exit,
			    HCI1394_TNF_HAL_STACK, "");
			return (DDI_FAILURE);
		}

		TNF_PROBE_0_DEBUG(hci1394_attach_exit, HCI1394_TNF_HAL_STACK,
		    "");
		return (DDI_SUCCESS);

	default:
		TNF_PROBE_0(h1394_attach_default_fail, HCI1394_TNF_HAL_ERROR,
		    "");
		break;
	}

	TNF_PROBE_0_DEBUG(hci1394_attach_exit, HCI1394_TNF_HAL_STACK, "");

	return (DDI_FAILURE);
}


/*
 * hci1394_soft_state_phase1_init()
 *    First part soft_state initialization.  This should be called before any
 *    other initialization routines are called.  Anything that requires cleanup
 *    on detach or after an attach failure should be setup in phase2 init (i.e.
 *    mutex's, cv's, etc.)
 */
static void
hci1394_soft_state_phase1_init(hci1394_state_t *soft_state, dev_info_t *dip,
    int instance)
{
	ASSERT(soft_state != NULL);
	TNF_PROBE_0_DEBUG(hci1394_soft_state_phase1_init_enter,
	    HCI1394_TNF_HAL_STACK, "");

	soft_state->drvinfo.di_dip = dip;
	soft_state->drvinfo.di_instance = instance;

	/* current bus generation */
	soft_state->drvinfo.di_gencnt = 0;

	soft_state->drvinfo.di_sl_private = NULL;

	/* initialize statistics */
	soft_state->drvinfo.di_stats.st_bus_reset_count = 0;
	soft_state->drvinfo.di_stats.st_selfid_count = 0;
	soft_state->drvinfo.di_stats.st_phy_isr = 0;
	soft_state->drvinfo.di_stats.st_phy_loop_err = 0;
	soft_state->drvinfo.di_stats.st_phy_pwrfail_err = 0;
	soft_state->drvinfo.di_stats.st_phy_timeout_err = 0;
	soft_state->drvinfo.di_stats.st_phy_portevt_err = 0;

	soft_state->swap_data = B_FALSE;
	soft_state->sl_selfid_buf = NULL;

	/* halinfo is what is passed up to the Services Layer */
	soft_state->halinfo.hal_private = soft_state;
	soft_state->halinfo.dip = soft_state->drvinfo.di_dip;
	soft_state->halinfo.hal_events = hci1394_evts;
	soft_state->halinfo.max_generation = OHCI_BUSGEN_MAX;
	soft_state->halinfo.addr_map_num_entries = HCI1394_ADDR_MAP_SIZE;
	soft_state->halinfo.addr_map = hci1394_addr_map;
	hci1394_buf_attr_get(&soft_state->halinfo.dma_attr);

	TNF_PROBE_0_DEBUG(hci1394_soft_state_phase1_init_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_soft_state_phase2_init()
 *    Second part of soft_state initialization.  This should be called after a
 *    successful hardware_init() and before the call to h1394_attach().
 */
static void
hci1394_soft_state_phase2_init(hci1394_state_t *soft_state)
{
	ASSERT(soft_state != NULL);
	TNF_PROBE_0_DEBUG(hci1394_soft_state_phase2_init_enter,
	    HCI1394_TNF_HAL_STACK, "");

	/*
	 * Setup our initial driver state.  This requires the HW iblock
	 * cookie so this must be setup in phase2_init()
	 */
	soft_state->drvinfo.di_drvstate.ds_state = HCI1394_INITIAL;
	mutex_init(&soft_state->drvinfo.di_drvstate.ds_mutex, NULL,
	    MUTEX_DRIVER, soft_state->drvinfo.di_iblock_cookie);

	/*
	 * halinfo.acc_attr tells the services layer what our buffer access
	 * attributes are.  drvinfo.di_buf_attr it initialized in pci_init so
	 * this must be setup in phase2_init()
	 */
	soft_state->halinfo.acc_attr = soft_state->drvinfo.di_buf_attr;

	/*
	 * halinfo.hw_interrupt tells the services layer what our
	 * iblock_cookie is. drvinfo.di_iblock_cookie is setup in isr_init so
	 * this must be setup in phase2_init()
	 */
	soft_state->halinfo.hw_interrupt = soft_state->drvinfo.di_iblock_cookie;

	/*
	 * Read in our node capabilities.  Since we are calling into csr
	 * we must have first called hardware_init().  Therefore, this must
	 * be in phase2_init().
	 */
	hci1394_csr_node_capabilities(soft_state->csr,
	    &soft_state->halinfo.node_capabilities);

	/*
	 * Read in our bus capabilities.  Since we are calling into ohci
	 * we must have first called hardware_init().  Therefore, this must
	 * be in phase2_init().
	 */
	hci1394_ohci_bus_capabilities(soft_state->ohci,
	    &soft_state->halinfo.bus_capabilities);

	/*
	 * Setup our async command overhead. When a target driver or the ARREQ
	 * engine allocates a command, the services layer will tack on space
	 * for itself and the HAL so we do not have to manage memory for every
	 * command.  hal_overhead is how much memory the hal requires to track
	 * an async command. Since we are calling into async we must have first
	 * called hardware_init().  Therefore, this must be in phase2_init().
	 */
	soft_state->halinfo.hal_overhead = hci1394_async_cmd_overhead();

	TNF_PROBE_0_DEBUG(hci1394_soft_state_phase2_init_exit,
	    HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_hardware_init()
 *    Initialize the adapter hardware.  This should be called during
 *    the initial attach().
 */
static int
hci1394_hardware_init(hci1394_state_t *soft_state)
{
	int status;


	ASSERT(soft_state != NULL);
	TNF_PROBE_0_DEBUG(hci1394_hardware_init_enter, HCI1394_TNF_HAL_STACK,
	    "");

	/* Initialize PCI config registers */
	status = hci1394_pci_init(soft_state);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(hci1394_hardware_init_pci_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_hardware_init_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Initialize the OpenHCI Hardware */
	status = hci1394_ohci_init(soft_state, &soft_state->drvinfo,
	    &soft_state->ohci);
	if (status != DDI_SUCCESS) {
		hci1394_pci_fini(soft_state);
		TNF_PROBE_0(hci1394_hardware_init_ohci_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_hardware_init_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Initialize SW based CSR registers */
	hci1394_csr_init(&soft_state->drvinfo, soft_state->ohci,
	    &soft_state->csr);

	/* Initialize the Asynchronous Q's */
	status = hci1394_async_init(&soft_state->drvinfo, soft_state->ohci,
	    soft_state->csr, &soft_state->async);
	if (status != DDI_SUCCESS) {
		hci1394_csr_fini(&soft_state->csr);
		hci1394_ohci_fini(&soft_state->ohci);
		hci1394_pci_fini(soft_state);
		TNF_PROBE_0(hci1394_hardware_init_asyn_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_hardware_init_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Initialize the Isochronous logic */
	hci1394_isoch_init(&soft_state->drvinfo, soft_state->ohci,
	    &soft_state->isoch);

	/* Initialize any Vendor Specific Registers */
	status = hci1394_vendor_init(&soft_state->drvinfo, soft_state->ohci,
	    &soft_state->vendor_info, &soft_state->vendor);
	if (status != DDI_SUCCESS) {
		hci1394_isoch_fini(&soft_state->isoch);
		hci1394_async_fini(&soft_state->async);
		hci1394_csr_fini(&soft_state->csr);
		hci1394_ohci_fini(&soft_state->ohci);
		hci1394_pci_fini(soft_state);
		TNF_PROBE_0(hci1394_hardware_init_vend_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_hardware_init_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	TNF_PROBE_0_DEBUG(hci1394_hardware_init_exit,
	    HCI1394_TNF_HAL_STACK, "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_hardware_resume()
 *    Resume the adapter HW.  This routine will be called during resume after
 *    a successful system suspend.  All memory should be in the state it was
 *    before the suspend.  All we have to do is re-setup the HW.
 */
static int
hci1394_hardware_resume(hci1394_state_t *soft_state)
{
	int status;


	ASSERT(soft_state != NULL);
	TNF_PROBE_0_DEBUG(hci1394_hardware_resume_enter, HCI1394_TNF_HAL_STACK,
	    "");

	/* re-enable global byte swap (if we using it) */
	hci1394_pci_resume(soft_state);

	/* Re-init the OpenHCI HW */
	status = hci1394_ohci_resume(soft_state->ohci);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(hci1394_hardware_resume_ohci_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_hardware_resume_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* re-setup our SW based CSR registers */
	hci1394_csr_resume(soft_state->csr);

	/* Re-setup the Async Q's */
	status = hci1394_async_resume(soft_state->async);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(hci1394_hardware_resume_asyn_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_hardware_resume_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	/* Re-setup any Vendor Specific Registers */
	status = hci1394_vendor_resume(soft_state->vendor);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(hci1394_hardware_resume_vend_fail,
		    HCI1394_TNF_HAL_ERROR, "");
		TNF_PROBE_0_DEBUG(hci1394_hardware_resume_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_FAILURE);
	}

	TNF_PROBE_0_DEBUG(hci1394_hardware_resume_exit,
	    HCI1394_TNF_HAL_STACK, "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_pci_init()
 *    Map in PCI config space and initialize PCI config space registers.
 */
static int
hci1394_pci_init(hci1394_state_t *soft_state)
{
	int status;
#ifndef _LITTLE_ENDIAN
	uint32_t global_swap;
#endif


	ASSERT(soft_state != NULL);
	TNF_PROBE_0_DEBUG(hci1394_pci_init_enter, HCI1394_TNF_HAL_STACK, "");

	/* Setup PCI configuration space */
	status = pci_config_setup(soft_state->drvinfo.di_dip,
	    &soft_state->pci_config);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(hci1394_pci_init_cfg_fail, HCI1394_TNF_HAL_ERROR,
		    "");
		TNF_PROBE_0_DEBUG(hci1394_pci_init_exit, HCI1394_TNF_HAL_STACK,
		    "");
		return (DDI_FAILURE);
	}


#ifdef _LITTLE_ENDIAN
	/* Start of little endian specific code */
	soft_state->drvinfo.di_reg_attr.devacc_attr_version =
	    DDI_DEVICE_ATTR_V0;
	soft_state->drvinfo.di_reg_attr.devacc_attr_endian_flags =
	    DDI_STRUCTURE_LE_ACC;
	soft_state->drvinfo.di_reg_attr.devacc_attr_dataorder =
	    DDI_STRICTORDER_ACC;
	soft_state->drvinfo.di_buf_attr.devacc_attr_version =
	    DDI_DEVICE_ATTR_V0;
	soft_state->drvinfo.di_buf_attr.devacc_attr_endian_flags =
	    DDI_STRUCTURE_LE_ACC;
	soft_state->drvinfo.di_buf_attr.devacc_attr_dataorder =
	    DDI_STRICTORDER_ACC;
	soft_state->swap_data = B_TRUE;
	/* End of little endian specific code */
#else
	/* Start of big endian specific code */
	/* If PCI_Global_Swap bit is not set, try to set it */
	global_swap = pci_config_get32(soft_state->pci_config,
	    OHCI_PCI_HCI_CONTROL_REG);

	/* Lets see if the global byte swap feature is supported */
	if ((global_swap & OHCI_PCI_GLOBAL_SWAP) == 0) {
		global_swap = global_swap | OHCI_PCI_GLOBAL_SWAP;
		pci_config_put32(soft_state->pci_config,
		    OHCI_PCI_HCI_CONTROL_REG, global_swap);
	}

	global_swap = pci_config_get32(soft_state->pci_config,
	    OHCI_PCI_HCI_CONTROL_REG);

	/* If PCI_Global_Swap bit is not set, it is unsupported */
	if ((global_swap & OHCI_PCI_GLOBAL_SWAP) == 0) {
		TNF_PROBE_0_DEBUG(hci1394_pci_gbs_npresent,
		    HCI1394_TNF_HAL_INFO, "global swap not present");
		soft_state->drvinfo.di_reg_attr.devacc_attr_version =
		    DDI_DEVICE_ATTR_V0;
		soft_state->drvinfo.di_reg_attr.devacc_attr_endian_flags =
		    DDI_STRUCTURE_LE_ACC;
		soft_state->drvinfo.di_reg_attr.devacc_attr_dataorder =
		    DDI_STRICTORDER_ACC;
		soft_state->drvinfo.di_buf_attr.devacc_attr_version =
		    DDI_DEVICE_ATTR_V0;
		soft_state->drvinfo.di_buf_attr.devacc_attr_endian_flags =
		    DDI_STRUCTURE_LE_ACC;
		soft_state->drvinfo.di_buf_attr.devacc_attr_dataorder =
		    DDI_STRICTORDER_ACC;
		soft_state->swap_data = B_TRUE;
	/*
	 * global byte swap is supported.  This should be the case
	 * for almost all of the adapters.
	 */
	} else {
		TNF_PROBE_0_DEBUG(hci1394_pci_gbs_present,
		    HCI1394_TNF_HAL_INFO, "global swap present");
		soft_state->drvinfo.di_reg_attr.devacc_attr_version =
		    DDI_DEVICE_ATTR_V0;
		soft_state->drvinfo.di_reg_attr.devacc_attr_endian_flags =
		    DDI_STRUCTURE_BE_ACC;
		soft_state->drvinfo.di_reg_attr.devacc_attr_dataorder =
		    DDI_STRICTORDER_ACC;
		soft_state->drvinfo.di_buf_attr.devacc_attr_version =
		    DDI_DEVICE_ATTR_V0;
		soft_state->drvinfo.di_buf_attr.devacc_attr_endian_flags =
		    DDI_STRUCTURE_BE_ACC;
		soft_state->drvinfo.di_buf_attr.devacc_attr_dataorder =
		    DDI_STRICTORDER_ACC;
		soft_state->swap_data = B_FALSE;
	}
	/* End of big endian specific code */
#endif

	/* read in vendor Information */
	soft_state->vendor_info.vendor_id =
	    (uint_t)pci_config_get16(soft_state->pci_config, PCI_CONF_VENID);
	soft_state->vendor_info.device_id =
	    (uint_t)pci_config_get16(soft_state->pci_config, PCI_CONF_DEVID);
	soft_state->vendor_info.revision_id =
	    (uint_t)pci_config_get8(soft_state->pci_config, PCI_CONF_REVID);

	TNF_PROBE_0_DEBUG(hci1394_pci_init_exit, HCI1394_TNF_HAL_STACK, "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_pci_resume()
 *    Re-Initialize PCI config space registers during a resume.
 */
/* ARGSUSED */
static void
hci1394_pci_resume(hci1394_state_t *soft_state)
{
#ifndef _LITTLE_ENDIAN
	uint32_t global_swap;
#endif


	ASSERT(soft_state != NULL);
	TNF_PROBE_0_DEBUG(hci1394_pci_resume_enter, HCI1394_TNF_HAL_STACK, "");

#ifdef _LITTLE_ENDIAN
	/* Start of little endian specific code */
	/* nothing to do here yet.  Maybe later?? */
	/* End of little endian specific code */
#else
	/* Start of big endian specific code */
	/* If PCI_Global_Swap bit is not set, try to set it */
	global_swap = pci_config_get32(soft_state->pci_config,
	    OHCI_PCI_HCI_CONTROL_REG);
	/* Try and set GlobalByteSwap */
	if ((global_swap & OHCI_PCI_GLOBAL_SWAP) == 0) {
		global_swap = global_swap | OHCI_PCI_GLOBAL_SWAP;
		pci_config_put32(soft_state->pci_config,
		    OHCI_PCI_HCI_CONTROL_REG, global_swap);
	}
	/* End of big endian specific code */
#endif
	TNF_PROBE_0_DEBUG(hci1394_pci_resume_exit, HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_resmap_get()
 *    Look for adapter property "reserved-addresses".  This property is used to
 *    reserve 1394 address space so that it will not randomly be given to a
 *    target driver during a 1394 address space alloc.  Some protocols hard
 *    code addresses which make us do this.  The target driver must specifically
 *    ask for these addresses.  This routine should be called before the
 *    call to h1394_attach().
 */
static int
hci1394_resmap_get(hci1394_state_t *soft_state)
{
	h1394_addr_map_t *resv_map;
	int resv_num;
	int status;
	int reslen;
	uint32_t *resptr;
	int rescnt;
	int mapcnt;


	ASSERT(soft_state != NULL);
	TNF_PROBE_0_DEBUG(hci1394_resmap_get_enter, HCI1394_TNF_HAL_STACK, "");

	/*
	 * See if the "reserved-addresses" property is defined.  The format
	 * should be:
	 *
	 * reserved-addresses=	0x0000ffff,0xf0000B00,0x200,
	 * 			0x0000ffff,0xf0000D00,0x200,
	 * 			0x0000ffff,0xf0000234,0x4;
	 * You can have multiple reserved addresses.  Each reserved address
	 * takes up 3 integers.
	 *    MSWofAddr,LSWofAddr,ByteCount
	 */
	status = ddi_prop_lookup_int_array(DDI_DEV_T_ANY,
	    soft_state->drvinfo.di_dip, DDI_PROP_DONTPASS, "reserved-addresses",
	    (int **)&resptr, (uint_t *)&reslen);
	if (status != DDI_PROP_SUCCESS) {
		/* the property is not defined,  0 reserved addresses */
		soft_state->halinfo.resv_map_num_entries = 0;
		soft_state->halinfo.resv_map = NULL;
		TNF_PROBE_0_DEBUG(hci1394_resmap_get_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return (DDI_SUCCESS);
	} else if ((reslen < 3) || ((reslen % 3) != 0)) {
		/*
		 * the property is defined but the correct number of integers
		 * is not present.
		 */
		resv_num = 0;
		resv_map = NULL;
		cmn_err(CE_NOTE, "!%s(%d): Invalid reserved-addresses property."
		    " Property ignored", ddi_node_name(
		    soft_state->drvinfo.di_dip), ddi_get_instance(
		    soft_state->drvinfo.di_dip));
	} else {
		/* the property is defined. Alloc space to copy data into */
		resv_num = reslen / 3;
		resv_map = kmem_alloc((sizeof (h1394_addr_map_t) * (resv_num)),
		    KM_SLEEP);

		/* read in the address, length, and set the type to reserved */
		rescnt = 0;
		mapcnt = 0;
		while (rescnt < reslen) {
			resv_map[mapcnt].address =
			    (uint64_t)resptr[rescnt] << 32;
			rescnt++;
			resv_map[mapcnt].address |= (uint64_t)resptr[rescnt];
			rescnt++;
			resv_map[mapcnt].length = (uint64_t)resptr[rescnt];
			rescnt++;
			resv_map[mapcnt].addr_type = H1394_ADDR_RESERVED;
			mapcnt++;
		}
	}

	ddi_prop_free(resptr);

	/*
	 * copy the number of reserved address ranges and a pointer to the map
	 * into halinfo so we can tell the services layer about them in
	 * h1394_attach()
	 */
	soft_state->halinfo.resv_map_num_entries = resv_num;
	soft_state->halinfo.resv_map = resv_map;

	TNF_PROBE_0_DEBUG(hci1394_resmap_get_exit, HCI1394_TNF_HAL_STACK, "");

	return (DDI_SUCCESS);
}


/*
 * hci1394_resmap_free()
 *    Free up the space alloced in hci1394_resmap_get().  This routine should
 *    be called after h1394_attach().  The HAL does not need this information
 *    and the services layer only uses it for a calculation during attach and
 *    should not refer to the pointer after it returns from h1394_attach().
 */
static void
hci1394_resmap_free(hci1394_state_t *soft_state)
{
	ASSERT(soft_state != NULL);
	TNF_PROBE_0_DEBUG(hci1394_resmap_free_enter, HCI1394_TNF_HAL_STACK, "");

	/*
	 * if we have one or more reserved map entries, free up the space that
	 * was allocated to store them
	 */
	if (soft_state->halinfo.resv_map_num_entries > 0) {
		ASSERT(soft_state->halinfo.resv_map != NULL);
		kmem_free(soft_state->halinfo.resv_map,
		    (sizeof (h1394_addr_map_t) *
		    soft_state->halinfo.resv_map_num_entries));
	}

	TNF_PROBE_0_DEBUG(hci1394_resmap_free_exit, HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_statebit_set()
 *     Set bit "statebit" in "state"
 */
static void
hci1394_statebit_set(uint64_t *state, uint_t statebit)
{
	ASSERT(state != NULL);
	ASSERT(statebit < 64);
	*state |= (uint64_t)0x1 << statebit;
}


/*
 * hci1394_statebit_tst()
 *    Return status of bit "statebit".  Is it set or not?
 */
static boolean_t
hci1394_statebit_tst(uint64_t state, uint_t statebit)
{
	uint64_t bitset;
	int status;


	ASSERT(statebit < 64);
	bitset = state & ((uint64_t)0x1 << statebit);
	if (bitset == 0) {
		status = B_FALSE;
	} else {
		status = B_TRUE;
	}
	return (status);
}


/*
 * hci1394_cleanup()
 *    Cleanup after a failed attach
 */
static void
hci1394_cleanup(hci1394_state_t *soft_state, uint64_t attach_state)
{
	int status;


	ASSERT(soft_state != NULL);
	TNF_PROBE_0_DEBUG(hci1394_cleanup_enter, HCI1394_TNF_HAL_STACK, "");


	status = hci1394_statebit_tst(attach_state, STATE_STARTUP);
	if (status == B_TRUE) {
		/* Don't allow the HW to generate any more interrupts */
		hci1394_ohci_intr_master_disable(soft_state->ohci);

		/* don't accept anymore commands from services layer */
		(void) hci1394_state_set(&soft_state->drvinfo,
		    HCI1394_SHUTDOWN);

		/* Reset the chip */
		(void) hci1394_ohci_soft_reset(soft_state->ohci);

		/* Flush out async DMA Q's (cancels pendingQ timeouts too) */
		hci1394_async_flush(soft_state->async);
	}

	status = hci1394_statebit_tst(attach_state, STATE_ISR_HANDLER);
	if (status == B_TRUE) {
		hci1394_isr_handler_fini(soft_state);
	}

	status = hci1394_statebit_tst(attach_state, STATE_H1394_ATTACH);
	if (status == B_TRUE) {
		(void) h1394_detach(&soft_state->drvinfo.di_sl_private,
		    DDI_DETACH);
	}

	status = hci1394_statebit_tst(attach_state, STATE_HW_INIT);
	if (status == B_TRUE) {
		hci1394_detach_hardware(soft_state);
	}

	status = hci1394_statebit_tst(attach_state, STATE_MINOR_NODE);
	if (status == B_TRUE) {
		ddi_remove_minor_node(soft_state->drvinfo.di_dip, "devctl");
	}

	status = hci1394_statebit_tst(attach_state, STATE_ISR_INIT);
	if (status == B_TRUE) {
		hci1394_isr_fini(soft_state);
	}

	status = hci1394_statebit_tst(attach_state, STATE_PHASE2);
	if (status == B_TRUE) {
		hci1394_soft_state_fini(soft_state);
	}

	status = hci1394_statebit_tst(attach_state, STATE_ZALLOC);
	if (status == B_TRUE) {
		ddi_soft_state_free(hci1394_statep,
		    soft_state->drvinfo.di_instance);
	}

	TNF_PROBE_0_DEBUG(hci1394_cleanup_exit, HCI1394_TNF_HAL_STACK, "");
}
