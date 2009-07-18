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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * hermon_fm.c
 *    Hermon (InfiniBand) HCA Driver Fault Management Routines
 *
 * [Hermon FM Implementation]
 *
 * Hermon FM recovers the system from a HW error situation and/or isolates a
 * HW error by calling the FMA acc handle check functions. (calling
 * ddi_fm_acc_err_get()) If a HW error is detected when either
 * ddi_fm_acc_err_get() is called, to determine whether or not the error is
 * transient, the I/O operation causing the error will retry up to three times.
 *
 * (Basic HW error recovery)
 *
 *        |
 *  .---->*
 *  |     |
 *  |   issue an I/O request via PIO
 *  |     |
 *  |     |
 *  |   check acc handle
 *  |     |
 *  |     |
 *  `--< a HW error detected && retry count < 3 >
 *        |
 *        v
 *
 * When a HW error is detected, to provide the error information for users to
 * isolate the faulted HW, Hermon FM issues Solaris FMA ereports as follows.
 *
 *  * PIO transient error
 *         invalid_state => unaffected
 *
 *  * PIO persistent error
 *         invalid_state => lost
 *
 *  * PIO fatal error
 *         invalid_state => lost => panic
 *
 *  * Hermon HCA firmware error
 *         invalid_state => degraded
 *
 *  * Other Hermon HCA specific errors
 *	   uncorrect => unaffected
 *		or
 *	   correct => unaffected
 *
 * (Restrictions)
 *
 * The current implementation has the following restrictions.
 *  * No runtime check/protection
 *  * No detach time check/protection
 *  * No DMA check/protection
 *
 * See the Hermon FMA portfolio in detail.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/list.h>
#include <sys/modhash.h>

#include <sys/ib/adapters/hermon/hermon.h>

/*
 * Hermon driver has to disable its FM functionality
 * if this "fm_capable" variable is defined or has a value
 * in /kernel/drv/hermon.conf.
 */
static char *fm_cap = "fm-capable";	/* FM capability */

static hermon_hca_fm_t hca_fm;		/* Hermon HCA FM Structure */

static void i_hca_fm_ereport(dev_info_t *, int, char *);
static void i_hca_fm_init(struct i_hca_fm *);
static void i_hca_fm_fini(struct i_hca_fm *);
static int i_hca_regs_map_setup(struct i_hca_fm *, dev_info_t *, uint_t,
    caddr_t *, offset_t, offset_t, ddi_device_acc_attr_t *, ddi_acc_handle_t *);
static void i_hca_regs_map_free(struct i_hca_fm *, ddi_acc_handle_t *);
static int i_hca_pci_config_setup(struct i_hca_fm *, dev_info_t *,
    ddi_acc_handle_t *);
static void i_hca_pci_config_teardown(struct i_hca_fm *, ddi_acc_handle_t *);
static int i_hca_pio_start(dev_info_t *, struct i_hca_acc_handle *,
    hermon_test_t *);
static int i_hca_pio_end(dev_info_t *, struct i_hca_acc_handle *, int *,
    hermon_test_t *);
static struct i_hca_acc_handle *i_hca_get_acc_handle(struct i_hca_fm *,
    ddi_acc_handle_t);

/* forward declaration for hermon_fm_{init, fini}() */
#ifdef FMA_TEST
static void i_hca_test_init(mod_hash_t **, mod_hash_t **);
static void i_hca_test_fini(mod_hash_t **, mod_hash_t **);
#endif /* FMA_TEST */

/*
 * Hermon FM Functions
 *
 * These functions are based on the HCA FM common interface
 * defined below, but specific to the Hermon HCA FM capabilities.
 */

/*
 *  void
 *  hermon_hca_fm_init(hermon_state_t *state, hermon_hca_fm_t *hca)
 *
 *  Overview
 *      hermon_hca_fm_init() initializes the Hermon FM resources.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *      hca: pointer to Hermon FM structure
 *
 *  Return value
 *      Nothing
 *
 *  Caller's context
 *      hermon_hca_fm_init() can be called in user or kernel context only.
 */
static void
hermon_hca_fm_init(hermon_state_t *state, hermon_hca_fm_t *hca_fm)
{
	state->hs_fm_hca_fm = hca_fm;
	i_hca_fm_init((struct i_hca_fm *)hca_fm);
}


/*
 *  void
 *  hermon_hca_fm_fini(hermon_state_t *state)
 *
 *  Overview
 *      hermon_hca_fm_fini() releases the Hermon FM resources.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *
 *  Return value
 *      Nothing
 *
 *  Caller's context
 *      hermon_hca_fm_fini() can be called in user or kernel context only.
 */
static void
hermon_hca_fm_fini(hermon_state_t *state)
{
	i_hca_fm_fini((struct i_hca_fm *)state->hs_fm_hca_fm);
	state->hs_fm_hca_fm = NULL;
}

/*
 *  void
 *  hermon_clr_state_nolock(hermon_state_t *state, int fm_state)
 *
 *  Overview
 *      hermon_clr_state() drops the specified state from Hermon FM state
 *      without the mutex locks.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *      fm_state: Hermon FM state, which is composed of:
 *		HCA_NO_FM	Hermom FM is not supported
 *		HCA_PIO_FM	PIO is fma-protected
 *		HCA_DMA_FM	DMA is fma-protected
 *		HCA_EREPORT_FM	FMA ereport is available
 *		HCA_ERRCB_FM	FMA error callback is supported
 *		HCA_ATTCH_FM	HCA FM attach mode
 *		HCA_RUNTM_FM	HCA FM runtime mode
 *
 *  Return value
 *  	Nothing
 *
 *  Caller's context
 *      hermon_clr_state() can be called in user, kernel, interrupt context
 *      or high interrupt context.
 */
void
hermon_clr_state_nolock(hermon_state_t *state, int fm_state)
{
	extern void membar_sync(void);

	state->hs_fm_state &= ~fm_state;
	membar_sync();
}


/*
 *  void
 *  hermon_clr_state(hermon_state_t *state, int fm_state)
 *
 *  Overview
 *      hermon_clr_state() drops the specified state from Hermon FM state.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *      fm_state: Hermon FM state, which is composed of:
 *		HCA_NO_FM	Hermom FM is not supported
 *		HCA_PIO_FM	PIO is fma-protected
 *		HCA_DMA_FM	DMA is fma-protected
 *		HCA_EREPORT_FM	FMA ereport is available
 *		HCA_ERRCB_FM	FMA error callback is supported
 *		HCA_ATTCH_FM	HCA FM attach mode
 *		HCA_RUNTM_FM	HCA FM runtime mode
 *
 *  Return value
 *  	Nothing
 *
 *  Caller's context
 *      hermon_clr_state() can be called in user, kernel or interrupt context.
 */
static void
hermon_clr_state(hermon_state_t *state, int fm_state)
{
	ASSERT(fm_state != HCA_NO_FM);

	mutex_enter(&state->hs_fm_lock);
	hermon_clr_state_nolock(state, fm_state);
	mutex_exit(&state->hs_fm_lock);
}


/*
 *  void
 *  hermon_set_state(hermon_state_t *state, int fm_state)
 *
 *  Overview
 *      hermon_set_state() sets Hermon FM state.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *      fm_state: Hermon FM state, which is composed of:
 *		HCA_NO_FM	Hermom FM is not supported
 *		HCA_PIO_FM	PIO is fma-protected
 *		HCA_DMA_FM	DMA is fma-protected
 *		HCA_EREPORT_FM	FMA ereport is available
 *		HCA_ERRCB_FM	FMA error callback is supported
 *		HCA_ATTCH_FM	HCA FM attach mode
 *		HCA_RUNTM_FM	HCA FM runtime mode
 *
 *  Return value
 *  	Nothing
 *
 *  Caller's context
 *      hermon_set_state() can be called in user, kernel or interrupt context.
 */
static void
hermon_set_state(hermon_state_t *state, int fm_state)
{
	extern void membar_sync(void);

	mutex_enter(&state->hs_fm_lock);
	if (fm_state == HCA_NO_FM) {
		state->hs_fm_state = HCA_NO_FM;
	} else {
		state->hs_fm_state |= fm_state;
	}
	membar_sync();
	mutex_exit(&state->hs_fm_lock);
}


/*
 *  int
 *  hermon_get_state(hermon_state_t *state)
 *
 *  Overview
 *      hermon_get_state() returns the current Hermon FM state.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *
 *  Return value
 *      fm_state: Hermon FM state, which is composed of:
 *		HCA_NO_FM	Hermom FM is not supported
 *		HCA_PIO_FM	PIO is fma-protected
 *		HCA_DMA_FM	DMA is fma-protected
 *		HCA_EREPORT_FM	FMA ereport is available
 *		HCA_ERRCB_FM	FMA error callback is supported
 *		HCA_ATTCH_FM	HCA FM attach mode
 *		HCA_RUNTM_FM	HCA FM runtime mode
 *
 *  Caller's context
 *      hermon_get_state() can be called in user, kernel or interrupt context.
 */
int
hermon_get_state(hermon_state_t *state)
{
	return (state->hs_fm_state);
}


/*
 *  void
 *  hermon_fm_init(hermon_state_t *state)
 *
 *  Overview
 *      hermon_fm_init() is a Hermon FM initialization function which registers
 *      some FMA functions such as the ereport and the acc check capabilities
 *      for Hermon. If the "fm_disable" property in /kernel/drv/hermon.conf is
 *      defined (and/or its value is set), then the Hermon FM capabilities will
 *      drop, and only the default capabilities (the ereport and error callback
 *      capabilities) are available (and the action against HW errors is
 *      issuing an ereport then panicking the system).
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *
 *  Return value
 *      Nothing
 *
 *  Caller's context
 *      hermon_fm_init() can be called in user or kernel context only.
 */
void
hermon_fm_init(hermon_state_t *state)
{
	ddi_iblock_cookie_t iblk;

	/*
	 * Check the "fm_disable" property. If it's defined,
	 * use the Solaris FMA default action for Hermon.
	 */
	if (ddi_getprop(DDI_DEV_T_NONE, state->hs_dip, DDI_PROP_DONTPASS,
	    "fm_disable", 0) != 0) {
		state->hs_fm_disable = 1;
	}

	/* If hs_fm_diable is set, then skip the rest */
	if (state->hs_fm_disable) {
		hermon_set_state(state, HCA_NO_FM);
		return;
	}

	/* Set the Hermon FM attach mode */
	hermon_set_state(state, HCA_ATTCH_FM);

	/* Initialize the Solaris FMA capabilities for the Hermon FM support */
	state->hs_fm_capabilities = ddi_prop_get_int(DDI_DEV_T_ANY,
	    state->hs_dip, DDI_PROP_DONTPASS, fm_cap,
	    DDI_FM_EREPORT_CAPABLE | DDI_FM_ACCCHK_CAPABLE);

	/*
	 * The Hermon FM uses the ereport and acc check capabilites only,
	 * but both of them should be available. If either is not, turn
	 * hs_fm_disable on and behave in the same way as the "fm_diable"
	 * property is set.
	 */
	if (state->hs_fm_capabilities !=
	    (DDI_FM_EREPORT_CAPABLE | DDI_FM_ACCCHK_CAPABLE)) {
		state->hs_fm_disable = 1;
		hermon_set_state(state, HCA_NO_FM);
		HERMON_ATTACH_MSG(state->hs_attach_buf,
		    "Hermon FM capability fails");
		return;
	}

	/* Initialize the HCA FM resources */
	hermon_hca_fm_init(state, &hca_fm);

	/* Initialize the fm state lock */
	mutex_init(&state->hs_fm_lock, NULL, MUTEX_DRIVER, NULL);

	/* Register the capabilities with the IO fault services */
	ddi_fm_init(state->hs_dip, &state->hs_fm_capabilities, &iblk);

	/* Set up the pci ereport capabilities if the ereport is capable */
	if (DDI_FM_EREPORT_CAP(state->hs_fm_capabilities)) {
		pci_ereport_setup(state->hs_dip);
	}

	/* Set the Hermon FM state */
	hermon_set_state(state, HCA_PIO_FM | HCA_EREPORT_FM);

#ifdef FMA_TEST
	i_hca_test_init(&state->hs_fm_test_hash, &state->hs_fm_id_hash);
#endif /* FMA_TEST */
}


/*
 *  void
 *  hermon_fm_fini(hermon_state_t *state)
 *
 *  Overview
 *      hermon_fm_fini() is a Hermon FM finalization function which de-registers
 *      Solaris FMA functions set to Hermon.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *
 *  Return value
 *      Nothing
 *
 *  Caller's context
 *      hermon_fm_fini() can be called in user or kernel context only.
 */
void
hermon_fm_fini(hermon_state_t *state)
{
	/*
	 * If hermon_fm_diable is set or there is no FM service provided,
	 * then skip the rest.
	 */
	if (state->hs_fm_disable || hermon_get_state(state) == HCA_NO_FM) {
		return;
	}

	ASSERT(!(hermon_get_state(state) & HCA_ERRCB_FM));

#ifdef FMA_TEST
	i_hca_test_fini(&state->hs_fm_test_hash, &state->hs_fm_id_hash);
#endif /* FMA_TEST */

	/* Set the Hermon FM state to no support */
	hermon_set_state(state, HCA_NO_FM);

	/* Release HCA FM resources */
	hermon_hca_fm_fini(state);

	/*
	 * Release any resources allocated by pci_ereport_setup()
	 */
	if (DDI_FM_EREPORT_CAP(state->hs_fm_capabilities)) {
		pci_ereport_teardown(state->hs_dip);
	}

	/* De-register the Hermon FM from the IO fault services */
	ddi_fm_fini(state->hs_dip);
}


/*
 *  int
 *  hermon_fm_ereport_init(hermon_state_t *state)
 *
 *  Overview
 *      hermon_fm_ereport_init() changes the Hermon FM state to the ereport
 *      only mode during the driver attach.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *
 *  Return value
 *      DDI_SUCCESS
 *      DDI_FAILURE
 *
 *  Caller's context
 *      hermon_fm_ereport_init() can be called in user or kernel context only.
 */
int
hermon_fm_ereport_init(hermon_state_t *state)
{
	ddi_iblock_cookie_t iblk;
	hermon_cfg_profile_t *cfgprof;
	hermon_hw_querydevlim_t	*devlim;
	hermon_rsrc_hw_entry_info_t entry_info;
	hermon_rsrc_pool_info_t	*rsrc_pool;
	uint64_t offset, num, max, num_prealloc;
	ddi_device_acc_attr_t dev_attr = {
		DDI_DEVICE_ATTR_V0,
		DDI_STRUCTURE_LE_ACC,
		DDI_STRICTORDER_ACC,
		DDI_DEFAULT_ACC
	};
	char *rsrc_name;
	extern void membar_sync(void);

	/* Stop the poll thread while the FM state is being changed */
	state->hs_fm_poll_suspend = B_TRUE;
	membar_sync();

	/*
	 * Disable the Hermon interrupt after the interrupt capability flag
	 * is checked.
	 */
	if (state->hs_intrmsi_cap & DDI_INTR_FLAG_BLOCK) {
		if (ddi_intr_block_disable
		    (&state->hs_intrmsi_hdl[0], 1) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
	} else {
		if (ddi_intr_disable
		    (state->hs_intrmsi_hdl[0]) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
	}

	/*
	 * Release any resources allocated by pci_ereport_setup()
	 */
	if (DDI_FM_EREPORT_CAP(state->hs_fm_capabilities)) {
		pci_ereport_teardown(state->hs_dip);
	}

	/* De-register the Hermon FM from the IO fault services */
	ddi_fm_fini(state->hs_dip);

	/* Re-initialize fm ereport with the ereport only */
	state->hs_fm_capabilities = ddi_prop_get_int(DDI_DEV_T_ANY,
	    state->hs_dip, DDI_PROP_DONTPASS, fm_cap,
	    DDI_FM_EREPORT_CAPABLE);

	/*
	 * Now that the Hermon FM uses the ereport capability only,
	 * If it's not set, turn hs_fm_disable on and behave in the
	 * same way as the "fm_diable" property is set.
	 */
	if (state->hs_fm_capabilities != DDI_FM_EREPORT_CAPABLE) {
		HERMON_ATTACH_MSG(state->hs_attach_buf,
		    "Hermon FM ereport fails (ereport mode)");
		goto error;
	}

	/* Re-register the ereport capability with the IO fault services */
	ddi_fm_init(state->hs_dip, &state->hs_fm_capabilities, &iblk);

	/* Initialize the pci ereport capabilities if the ereport is capable */
	if (DDI_FM_EREPORT_CAP(state->hs_fm_capabilities)) {
		pci_ereport_setup(state->hs_dip);
	}

	/* Setup for PCI config read/write of HCA device */
	if (pci_config_setup(state->hs_dip, &state->hs_reg_pcihdl) !=
	    DDI_SUCCESS) {
		HERMON_ATTACH_MSG(state->hs_attach_buf,
		    "PCI config mapping fails (ereport mode)");
		goto error;
	}

	/* Allocate the regular access handle for MSI-X tables */
	if (ddi_regs_map_setup(state->hs_dip, state->hs_msix_tbl_rnumber,
	    (caddr_t *)&state->hs_msix_tbl_addr, state->hs_msix_tbl_offset,
	    state->hs_msix_tbl_size, &dev_attr,
	    &state->hs_reg_msix_tblhdl) != DDI_SUCCESS) {
		HERMON_ATTACH_MSG(state->hs_attach_buf,
		    "MSI-X Table mapping fails (ereport mode)");
		goto error;
	}

	/* Allocate the regular access handle for MSI-X PBA */
	if (ddi_regs_map_setup(state->hs_dip, state->hs_msix_pba_rnumber,
	    (caddr_t *)&state->hs_msix_pba_addr, state->hs_msix_pba_offset,
	    state->hs_msix_pba_size, &dev_attr,
	    &state->hs_reg_msix_pbahdl) != DDI_SUCCESS) {
		HERMON_ATTACH_MSG(state->hs_attach_buf,
		    "MSI-X PBA mapping fails (ereport mode)");
		goto error;
	}

	/* Allocate the regular access handle for Hermon CMD I/O space */
	if (ddi_regs_map_setup(state->hs_dip, HERMON_CMD_BAR,
	    &state->hs_reg_cmd_baseaddr, 0, 0, &state->hs_reg_accattr,
	    &state->hs_reg_cmdhdl) != DDI_SUCCESS) {
		HERMON_ATTACH_MSG(state->hs_attach_buf,
		    "CMD_BAR mapping fails (ereport mode)");
		goto error;
	}

	/* Reset the host command register */
	state->hs_cmd_regs.hcr = (hermon_hw_hcr_t *)
	    ((uintptr_t)state->hs_reg_cmd_baseaddr + HERMON_CMD_HCR_OFFSET);

	/* Reset the software reset register */
	state->hs_cmd_regs.sw_reset = (uint32_t *)
	    ((uintptr_t)state->hs_reg_cmd_baseaddr +
	    HERMON_CMD_SW_RESET_OFFSET);

	/* Reset the software reset register semaphore */
	state->hs_cmd_regs.sw_semaphore = (uint32_t *)
	    ((uintptr_t)state->hs_reg_cmd_baseaddr +
	    HERMON_CMD_SW_SEMAPHORE_OFFSET);

	/* Calculate the clear interrupt register offset */
	offset = state->hs_fw.clr_intr_offs & HERMON_CMD_OFFSET_MASK;

	/* Reset the clear interrupt address */
	state->hs_cmd_regs.clr_intr = (uint64_t *)
	    (uintptr_t)(state->hs_reg_cmd_baseaddr + offset);

	/* Reset the internal error buffer address */
	state->hs_cmd_regs.fw_err_buf = (uint32_t *)(uintptr_t)
	    (state->hs_reg_cmd_baseaddr + state->hs_fw.error_buf_addr);

	/* Check if the blue flame is enabled, and set the offset value */
	if (state->hs_devlim.blu_flm) {
		offset = (uint64_t)1 <<
		    (state->hs_devlim.log_max_uar_sz + 20);
	} else {
		offset = 0;
	}

	/* Allocate the regular access handle for Hermon UAR I/O space */
	if (ddi_regs_map_setup(state->hs_dip, HERMON_UAR_BAR,
	    &state->hs_reg_uar_baseaddr, 0, offset,
	    &state->hs_reg_accattr, &state->hs_reg_uarhdl) != DDI_SUCCESS) {
		HERMON_ATTACH_MSG(state->hs_attach_buf,
		    "UAR BAR mapping fails (ereport mode)");
		goto error;
	}

	/* Drop the Hermon FM Attach Mode */
	hermon_clr_state(state, HCA_ATTCH_FM);

	/* Set the Hermon FM Runtime Mode */
	hermon_set_state(state, HCA_RUNTM_FM);

	/* Free up Hermon UAR page #1 */
	hermon_rsrc_free(state, &state->hs_uarkpg_rsrc);

	/* Free up the UAR pool */
	entry_info.hwi_rsrcpool = &state->hs_rsrc_hdl[HERMON_UARPG];
	hermon_rsrc_hw_entries_fini(state, &entry_info);

	/* Re-allocate the UAR pool */
	cfgprof = state->hs_cfg_profile;
	devlim	= &state->hs_devlim;
	num			  = ((uint64_t)1 << cfgprof->cp_log_num_uar);
	max			  = num;
	num_prealloc		  = max(devlim->num_rsvd_uar, 128);
	rsrc_pool		  = &state->hs_rsrc_hdl[HERMON_UARPG];
	rsrc_pool->rsrc_type	  = HERMON_UARPG;
	rsrc_pool->rsrc_loc	  = HERMON_IN_UAR;
	rsrc_pool->rsrc_pool_size = (num << PAGESHIFT);
	rsrc_pool->rsrc_shift	  = PAGESHIFT;
	rsrc_pool->rsrc_quantum	  = (uint_t)PAGESIZE;
	rsrc_pool->rsrc_align	  = PAGESIZE;
	rsrc_pool->rsrc_state	  = state;
	rsrc_pool->rsrc_start	  = (void *)state->hs_reg_uar_baseaddr;
	rsrc_name = (char *)kmem_zalloc(HERMON_RSRC_NAME_MAXLEN, KM_SLEEP);
	HERMON_RSRC_NAME(rsrc_name, HERMON_UAR_PAGE_VMEM_RUNTM);
	entry_info.hwi_num	  = num;
	entry_info.hwi_max	  = max;
	entry_info.hwi_prealloc	  = num_prealloc;
	entry_info.hwi_rsrcpool	  = rsrc_pool;
	entry_info.hwi_rsrcname	  = rsrc_name;
	if (hermon_rsrc_hw_entries_init(state, &entry_info) != DDI_SUCCESS) {
		kmem_free(rsrc_name, HERMON_RSRC_NAME_MAXLEN);
		goto error;
	}
	kmem_free(rsrc_name, HERMON_RSRC_NAME_MAXLEN);

	/* Re-allocate the kernel UAR page */
	if (hermon_rsrc_alloc(state, HERMON_UARPG, 1, HERMON_SLEEP,
	    &state->hs_uarkpg_rsrc) != DDI_SUCCESS) {
		goto error;
	}

	/* Setup pointer to kernel UAR page */
	state->hs_uar = (hermon_hw_uar_t *)state->hs_uarkpg_rsrc->hr_addr;

	/* Now drop the the Hermon PIO FM */
	hermon_clr_state(state, HCA_PIO_FM);

	/* Release the MSI-X Table access handle */
	if (state->hs_fm_msix_tblhdl) {
		hermon_regs_map_free(state, &state->hs_fm_msix_tblhdl);
		state->hs_fm_msix_tblhdl = NULL;
	}

	/* Release the MSI-X PBA access handle */
	if (state->hs_fm_msix_pbahdl) {
		hermon_regs_map_free(state, &state->hs_fm_msix_pbahdl);
		state->hs_fm_msix_pbahdl = NULL;
	}

	/* Release the pci config space access handle */
	if (state->hs_fm_pcihdl) {
		hermon_regs_map_free(state, &state->hs_fm_pcihdl);
		state->hs_fm_pcihdl = NULL;
	}

	/* Release the cmd protected access handle */
	if (state->hs_fm_cmdhdl) {
		hermon_regs_map_free(state, &state->hs_fm_cmdhdl);
		state->hs_fm_cmdhdl = NULL;
	}

	/* Release the uar fma-protected access handle */
	if (state->hs_fm_uarhdl) {
		hermon_regs_map_free(state, &state->hs_fm_uarhdl);
		state->hs_fm_uarhdl = NULL;
	}

	/* Enable the Hermon interrupt again */
	if (state->hs_intrmsi_cap & DDI_INTR_FLAG_BLOCK) {
		if (ddi_intr_block_enable
		    (&state->hs_intrmsi_hdl[0], 1) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
	} else {
		if (ddi_intr_enable
		    (state->hs_intrmsi_hdl[0]) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
	}

	/* Restart the poll thread */
	state->hs_fm_poll_suspend = B_FALSE;

	return (DDI_SUCCESS);

error:
	/* Enable the Hermon interrupt again */
	if (state->hs_intrmsi_cap & DDI_INTR_FLAG_BLOCK) {
		(void) ddi_intr_block_enable(&state->hs_intrmsi_hdl[0], 1);
	} else {
		(void) ddi_intr_enable(state->hs_intrmsi_hdl[0]);
	}
	return (DDI_FAILURE);
}


/*
 *  int
 *  hermon_regs_map_setup(hermon_state_t *state, uint_t rnumber, caddr_t *addrp,
 *	offset_t offset, offset_t len, ddi_device_acc_attr_t *accattrp,
 *	ddi_acc_handle_t *handle)
 *
 *  Overview
 *      This is a wrapper function of i_hca_regs_map_setup() for Hermon FM so
 *      that it calls i_hca_regs_map_setup() inside after it checks the
 *      "fm_disable" configuration property. If the "fm_disable" is described
 *      in /kernel/drv/hermon.conf, the function calls ddi_regs_map_setup()
 *      directly instead.
 *      See i_hca_regs_map_setup() in detail.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *      rnumber: index number to the register address space set
 *      addrp: platform-dependent value (same as ddi_regs_map_setup())
 *      offset: offset into the register address space
 *      len: address space length to be mapped
 *      accattrp: pointer to device access attribute structure
 *	handle: pointer to ddi_acc_handle_t used for HCA FM
 *
 *  Return value
 *      ddi function status value which are:
 *      	DDI_SUCCESS
 *      	DDI_FAILURE
 *      	DDI_ME_RNUMBER_RNGE
 *      	DDI_REGS_ACC_CONFLICT
 *
 *  Caller's context
 *      hermon_regs_map_setup() can be called in user or kernel context only.
 */
int
hermon_regs_map_setup(hermon_state_t *state, uint_t rnumber, caddr_t *addrp,
	offset_t offset, offset_t len, ddi_device_acc_attr_t *accattrp,
	ddi_acc_handle_t *handle)
{
	if (state->hs_fm_disable) {
		return (ddi_regs_map_setup(state->hs_dip, rnumber, addrp,
		    offset, len, accattrp, handle));
	} else {
		return (i_hca_regs_map_setup(state->hs_fm_hca_fm, state->hs_dip,
		    rnumber, addrp, offset, len, accattrp, handle));
	}
}


/*
 *  void
 *  hermon_regs_map_free(hermon_state_t *state, ddi_acc_handle_t *handlep)
 *
 *  Overview
 *      This is a wrapper function of i_hca_regs_map_free() for Hermon FM so
 *      that it calls i_hca_regs_map_free() inside after it checks the
 *      "fm_disable" configuration property. If the "fm_disable" is described
 *      in /kernel/drv/hermon.conf, the function calls ddi_regs_map_fre()
 *      directly instead.  See i_hca_regs_map_free() in detail.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *	handle: pointer to ddi_acc_handle_t used for HCA FM
 *
 *  Return value
 *      Nothing
 *
 *  Caller's context
 *      hermon_regs_map_free() can be called in user or kernel context only.
 *
 *  Note that the handle passed to hermon_regs_map_free() is NULL-cleared
 *  after this function is called.
 */
void
hermon_regs_map_free(hermon_state_t *state, ddi_acc_handle_t *handle)
{
	if (state->hs_fm_disable) {
		ddi_regs_map_free(handle);
		*handle = NULL;
	} else {
		i_hca_regs_map_free(state->hs_fm_hca_fm, handle);
	}
}


/*
 *  int
 *  hermon_pci_config_setup(hermon_state_t *state, ddi_acc_handle_t *handle)
 *
 *  Overview
 *      This is a wrapper function of i_hca_pci_config_setup() for Hermon FM so
 *      that it calls i_hca_pci_config_setup() inside after it checks the
 *      "fm-disable" configuration property. If the "fm_disable" is described
 *      in /kernel/drv/hermon.conf, the function calls pci_config_setup()
 *      directly instead. See i_hca_pci_config_setup() in detail.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *	handle: pointer to ddi_acc_handle_t used for HCA FM
 *
 *  Return value
 *      ddi function status value which are:
 *      	DDI_SUCCESS
 *      	DDI_FAILURE
 *
 *  Caller's context
 *      hermon_pci_config_setup() can be called in user or kernel context only.
 */
int
hermon_pci_config_setup(hermon_state_t *state, ddi_acc_handle_t *handle)
{
	if (state->hs_fm_disable) {
		return (pci_config_setup(state->hs_dip, handle));
	} else {
		/* Check Hermon FM and Solaris FMA capability flags */
		ASSERT((hermon_get_state(state) & HCA_PIO_FM &&
		    DDI_FM_ACC_ERR_CAP(ddi_fm_capable(state->hs_dip))) ||
		    (!(hermon_get_state(state) & HCA_PIO_FM) &&
		    !DDI_FM_ACC_ERR_CAP(ddi_fm_capable(state->hs_dip))));
		return (i_hca_pci_config_setup(state->hs_fm_hca_fm,
		    state->hs_dip, handle));
	}
}


/*
 *  void
 *  hermon_pci_config_teardown(hermon_state_t *state, ddi_acc_handle_t *handle)
 *
 *  Overview
 *      This is a wrapper function of i_hca_pci_config_teardown() for Hermon
 *      FM so that it calls i_hca_pci_config_teardown() inside after it checks
 *      the "fm-disable" configuration property. If the "fm_disable" is
 *      described in /kernel/drv/hermon.conf, the function calls
 *      pci_config_teardown() directly instead.
 *      See i_hca_pci_config_teardown() in detail.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *	handle: pointer to ddi_acc_handle_t used for HCA FM
 *
 *  Return value
 *      Nothing
 *
 *  Caller's context
 *      hermon_pci_config_teardown() can be called in user or kernel context
 *      only.
 */
void
hermon_pci_config_teardown(hermon_state_t *state, ddi_acc_handle_t *handle)
{
	if (state->hs_fm_disable) {
		pci_config_teardown(handle);
		*handle = NULL;
	} else {
		i_hca_pci_config_teardown(state->hs_fm_hca_fm, handle);
	}
}


/*
 *  boolean_t
 *  hermon_init_failure(hermon_state_t *state)
 *
 *  Overview
 *      hermon_init_failure() tells if HW errors are detected in
 *      the Hermon driver attach.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *
 *  Return value
 *  	B_TRUE		HW errors detected during attach
 *  	B_FALSE		No HW errors during attach
 *
 *  Caller's context
 *      hermon_init_failure() can be called in user, kernel, interrupt
 *      context or high interrupt context.
 */
boolean_t
hermon_init_failure(hermon_state_t *state)
{
	ddi_acc_handle_t hdl;
	ddi_fm_error_t derr;

	if (!(hermon_get_state(state) & HCA_PIO_FM))
		return (B_FALSE);

	/* check if fatal errors occur during attach */
	if (state->hs_fm_async_fatal)
		return (B_TRUE);

	hdl = hermon_get_uarhdl(state);
	/* Get the PIO error against UAR I/O space */
	ddi_fm_acc_err_get(hdl, &derr, DDI_FME_VERSION);
	if (derr.fme_status != DDI_FM_OK) {
		return (B_TRUE);
	}

	hdl = hermon_get_cmdhdl(state);
	/* Get the PIO error againsts CMD I/O space */
	ddi_fm_acc_err_get(hdl, &derr, DDI_FME_VERSION);
	if (derr.fme_status != DDI_FM_OK) {
		return (B_TRUE);
	}

	return (B_FALSE);
}


/*
 *  void
 *  hermon_fm_ereport(hermon_state_t *state, int type, int detail)
 *
 *  Overview
 *      hermon_fm_ereport() is a Hermon FM ereport function used
 *      to issue a Solaris FMA ereport. See Hermon FM comments at the
 *      beginning of this file in detail.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *      type: error type
 *		HCA_SYS_ERR	FMA reporting HW error
 *		HCA_IBA_ERR	HCA specific HW error
 *      detail: HW error hint implying which ereport is issued
 * 		HCA_ERR_TRANSIENT	HW transienet error
 * 		HCA_ERR_NON_FATAL	HW persistent error
 * 		HCA_ERR_FATAL		HW fatal error
 * 		HCA_ERR_SRV_LOST	IB service lost due to HW error
 * 		HCA_ERR_DEGRADED	Hermon driver and/or uDAPL degraded
 * 					due to HW error
 * 		HCA_ERR_IOCTL		HW error detected in user conetxt
 * 					(especially in ioctl())
 *
 *  Return value
 *      Nothing
 *
 *  Caller's context
 *      hermon_fm_ereport() can be called in user, kernel, interrupt context
 *      or high interrupt context.
 */
void
hermon_fm_ereport(hermon_state_t *state, int type, int detail)
{
	/*
	 * If hermon_fm_diable is set or there is no FM ereport service
	 * provided, then skip the rest.
	 */
	if (state->hs_fm_disable ||
	    !(hermon_get_state(state) & HCA_EREPORT_FM)) {
		return;
	}

	switch (type) {

	case HCA_SYS_ERR:
		switch (detail) {
		case HCA_ERR_TRANSIENT:
		case HCA_ERR_IOCTL:
			ddi_fm_service_impact(state->hs_dip,
			    DDI_SERVICE_UNAFFECTED);
			break;
		case HCA_ERR_NON_FATAL:
			/* Nothing */
			break;
		case HCA_ERR_SRV_LOST:
			ddi_fm_service_impact(state->hs_dip,
			    DDI_SERVICE_LOST);
			break;
		case HCA_ERR_DEGRADED:
			switch (state->hs_fm_degraded_reason) {
			case HCA_FW_CORRUPT:
				i_hca_fm_ereport(state->hs_dip, type,
				    DDI_FM_DEVICE_FW_CORRUPT);
				break;
			case HCA_FW_MISMATCH:
				i_hca_fm_ereport(state->hs_dip, type,
				    DDI_FM_DEVICE_FW_MISMATCH);
				break;
			case HCA_FW_MISC:
			default:
				i_hca_fm_ereport(state->hs_dip, type,
				    DDI_FM_DEVICE_INTERN_UNCORR);
				break;
			}
			ddi_fm_service_impact(state->hs_dip,
			    DDI_SERVICE_DEGRADED);
			break;
		case HCA_ERR_FATAL:
			ddi_fm_service_impact(state->hs_dip,
			    DDI_SERVICE_LOST);
			state->hs_fm_async_fatal = B_TRUE;
			break;
		default:
			cmn_err(CE_WARN, "hermon_fm_ereport: Unknown error. "
			    "type = %d, detail = %d\n.", type, detail);
		}
		break;

	case HCA_IBA_ERR:
		switch (detail) {
		case HCA_ERR_TRANSIENT:
			i_hca_fm_ereport(state->hs_dip, type,
			    DDI_FM_DEVICE_INTERN_UNCORR);
			ddi_fm_service_impact(state->hs_dip,
			    DDI_SERVICE_UNAFFECTED);
			break;
		case HCA_ERR_SRV_LOST:
			cmn_err(CE_WARN, "hermon_fm_ereport: not supported "
			    "error. type = %d, detail = %d\n.", type, detail);
			break;
		case HCA_ERR_DEGRADED:
			switch (state->hs_fm_degraded_reason) {
			case HCA_FW_CORRUPT:
				i_hca_fm_ereport(state->hs_dip, type,
				    DDI_FM_DEVICE_FW_CORRUPT);
				break;
			case HCA_FW_MISMATCH:
				i_hca_fm_ereport(state->hs_dip, type,
				    DDI_FM_DEVICE_FW_MISMATCH);
				break;
			case HCA_FW_MISC:
			default:
				i_hca_fm_ereport(state->hs_dip, type,
				    DDI_FM_DEVICE_INTERN_UNCORR);
				break;
			}
			ddi_fm_service_impact(state->hs_dip,
			    DDI_SERVICE_DEGRADED);
			break;
		case HCA_ERR_IOCTL:
		case HCA_ERR_NON_FATAL:
			i_hca_fm_ereport(state->hs_dip, type,
			    DDI_FM_DEVICE_INTERN_UNCORR);
			ddi_fm_service_impact(state->hs_dip,
			    DDI_SERVICE_UNAFFECTED);
			break;
		case HCA_ERR_FATAL:
			if (hermon_get_state(state) & HCA_PIO_FM) {
				if (servicing_interrupt()) {
					atomic_inc_32(&state->
					    hs_fm_async_errcnt);
				} else {
					i_hca_fm_ereport(state->hs_dip, type,
					    DDI_FM_DEVICE_INTERN_UNCORR);
					ddi_fm_service_impact(state->hs_dip,
					    DDI_SERVICE_LOST);
				}
				state->hs_fm_async_fatal = B_TRUE;
			} else {
				i_hca_fm_ereport(state->hs_dip, type,
				    DDI_FM_DEVICE_INTERN_UNCORR);
				ddi_fm_service_impact(state->hs_dip,
				    DDI_SERVICE_LOST);
				cmn_err(CE_PANIC,
				    "Hermon Fatal Internal Error. "
				    "Hermon state=0x%p", (void *)state);
			}
			break;
		default:
			cmn_err(CE_WARN, "hermon_fm_ereport: Unknown error. "
			    "type = %d, detail = %d\n.", type, detail);
		}
		break;

	default:
		cmn_err(CE_WARN, "hermon_fm_ereport: Unknown type "
		    "type = %d, detail = %d\n.", type, detail);
		break;
	}
}


/*
 *  uchar_t
 *  hermon_devacc_attr_version(hermon_state_t *)
 *
 *  Overview
 *      hermon_devacc_attr_version() returns the ddi device attribute
 *      version.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *
 *  Return value
 *      dev_acc_attr_version value
 *      	DDI_DEVICE_ATTR_V0	Hermon FM disabled
 *      	DDI_DEVICE_ATTR_V1	Hermon FM enabled
 *
 *  Caller's context
 *      hermon_devacc_attr_version() can be called in user, kernel, interrupt
 *      context or high interrupt context.
 */
ushort_t
hermon_devacc_attr_version(hermon_state_t *state)
{
	if (state->hs_fm_disable) {
		return (DDI_DEVICE_ATTR_V0);
	} else {
		return (DDI_DEVICE_ATTR_V1);
	}
}


/*
 *  uchar_t
 *  hermon_devacc_attr_access(hermon_state_t *)
 *
 *  Overview
 *      hermon_devacc_attr_access() returns devacc_attr_access error
 *      protection types.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *
 *  Return value
 *      dev_acc_attr_access error protection type
 *      	DDI_DEFAULT_ACC		Hermon FM disabled for PIO
 *      	DDI_FLAGERR_ACC		Hermon FM enabled for PIO
 *
 *  Caller's context
 *      hermon_devacc_attr_access() can be called in user, kernel, interrupt
 *      context or high interrupt context.
 */
uchar_t
hermon_devacc_attr_access(hermon_state_t *state)
{
	if (state->hs_fm_disable) {
		return (DDI_DEFAULT_ACC);
	} else {
		return (DDI_FLAGERR_ACC);
	}
}


/*
 *  int
 *  hermon_PIO_start(hermon_state_t *state, ddi_acc_handle_t handle,
 *      hermon_test_t *tst)
 *
 *  Overview
 *      hermon_PIO_start() should be called before Hermon driver issues PIOs
 *      against I/O space. If Hermon FM is disabled, this function returns
 *      HCA_PIO_OK always. See i_hca_pio_start() in detail.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *	handle: pointer to ddi_acc_handle_t used for HCA FM
 *      tst: pointer to HCA FM function test structure. If the structure
 *           is not used, the NULL value must be passed instead.
 *
 *  Return value
 *  	error status showing whether or not this error can retry
 *	HCA_PIO_OK		No HW errors
 *	HCA_PIO_TRANSIENT	This error could be transient
 *	HCA_PIO_PERSISTENT	This error is persistent
 *
 *  Caller's context
 *      hermon_PIO_start() can be called in user, kernel or interrupt context.
 */
int
hermon_PIO_start(hermon_state_t *state, ddi_acc_handle_t handle,
    hermon_test_t *tst)
{
	if (state->hs_fm_disable) {
		return (HCA_PIO_OK);
	} else {
		struct i_hca_acc_handle *handlep =
		    i_hca_get_acc_handle(state->hs_fm_hca_fm, handle);
		ASSERT(handlep != NULL);
		return (i_hca_pio_start(state->hs_dip, handlep, tst));
	}
}


/*
 *  int
 *  hermon_PIO_end(hermon_state_t *state, ddi_acc_handle_t handle, int *cnt,
 *      hermon_test_t *tst)
 *
 *  Overview
 *      hermon_PIO_end() should be called after Hermon driver issues PIOs
 *      against I/O space. If Hermon FM is disabled, this function returns
 *      HCA_PIO_OK always. See i_hca_pio_end() in detail.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *	handle: pointer to ddi_acc_handle_t used for HCA FM
 *	cnt: pointer to the counter variable which holds the nubmer of retry
 *	     (HCA_PIO_RETRY_CNT) when a HW error is detected.
 *      tst: pointer to HCA FM function test structure. If the structure
 *           is not used, the NULL value must be passed instead.
 *
 *  Return value
 *  	error status showing whether or not this error can retry
 *	HCA_PIO_OK		No HW errors
 *	HCA_PIO_TRANSIENT	This error could be transient
 *	HCA_PIO_PERSISTENT	This error is persistent
 *
 *  Caller's context
 *      hermon_PIO_end() can be called in user, kernel or interrupt context.
 */
int
hermon_PIO_end(hermon_state_t *state, ddi_acc_handle_t handle, int *cnt,
    hermon_test_t *tst)
{
	if (state->hs_fm_disable) {
		return (HCA_PIO_OK);
	} else {
		struct i_hca_acc_handle *handlep =
		    i_hca_get_acc_handle(state->hs_fm_hca_fm, handle);
		ASSERT(handlep != NULL);
		return (i_hca_pio_end(state->hs_dip, handlep, cnt, tst));
	}
}


/*
 *  ddi_acc_handle_t
 *  hermon_get_cmdhdl(hermon_state_t *state)
 *
 *  Overview
 *      hermon_get_cmdhdl() returns either the fma-protected access handle or
 *      the regular ddi-access handle depending on the Hermon FM state for
 *      Hermon command I/O space.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *
 *  Return value
 *  	the access handle for pio requests
 *
 *  Caller's context
 *      hermon_get_cmdhdl() can be called in user, kernel, interrupt context
 *      or high interrupt context.
 */
ddi_acc_handle_t
hermon_get_cmdhdl(hermon_state_t *state)
{
	return (state->hs_fm_disable || hermon_get_state(state) & HCA_PIO_FM ?
	    state->hs_fm_cmdhdl : state->hs_reg_cmdhdl);
}


/*
 *  ddi_acc_handle_t
 *  hermon_get_uarhdl(hermon_state_t *state)
 *
 *  Overview
 *      hermon_get_uarhdl() returns either the fma-protected access handle or
 *      the regular ddi-access handle depending on the Hermon FM state for
 *      Hermon UAR I/O space.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *
 *  Return value
 *  	the access handle for pio requests
 *
 *  Caller's context
 *      hermon_get_uarhdl() can be called in user, kernel, interrupt context
 *      or high interrupt context.
 */
ddi_acc_handle_t
hermon_get_uarhdl(hermon_state_t *state)
{
	return (state->hs_fm_disable || hermon_get_state(state) & HCA_PIO_FM ?
	    state->hs_fm_uarhdl : state->hs_reg_uarhdl);
}


/*
 *  ddi_acc_handle_t
 *  hermon_rsrc_alloc_uarhdl(hermon_state_t *state)
 *
 *  Overview
 *      hermon_rsrc_alloc_uarhdl() returns either the fma-protected access
 *      handle or the regular ddi-access handle depending on the Hermon FM
 *      state for Hermon UAR I/O space as well as hermon_get_uarhdl(), but
 *      this function is dedicated to the UAR resource allocator.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *
 *  Return value
 *  	the access handle for pio requests
 *
 *  Caller's context
 *      hermon_rsrc_alloc_uarhdl() can be called in user, kernel, interrupt
 *      or high interrupt context.
 */
ddi_acc_handle_t
hermon_rsrc_alloc_uarhdl(hermon_state_t *state)
{
	return (state->hs_fm_disable || hermon_get_state(state) & HCA_ATTCH_FM ?
	    state->hs_fm_uarhdl : state->hs_reg_uarhdl);
}

/*
 *  ddi_acc_handle_t
 *  hermon_get_pcihdl(hermon_state_t *state)
 *
 *  Overview
 *      hermon_get_pcihdl() returns either the fma-protected access
 *      handle or the regular ddi-access handle to access the PCI config
 *      space. Whether or not which handle is returned at the moment depends
 *      on the Hermon FM state.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *
 *  Return value
 *  	the access handle to PCI config space
 *
 *  Caller's context
 *      hermon_get_pcihdl() can be called in user, kernel, interrupt
 *      or high interrupt context.
 */
ddi_acc_handle_t
hermon_get_pcihdl(hermon_state_t *state)
{
	return (state->hs_fm_disable || hermon_get_state(state) & HCA_ATTCH_FM ?
	    state->hs_fm_pcihdl : state->hs_reg_pcihdl);
}


/*
 *  ddi_acc_handle_t
 *  hermon_get_msix_tblhdl(hermon_state_t *state)
 *
 *  Overview
 *      hermon_get_msix_tblhdl() returns either the fma-protected access
 *      handle or the regular ddi-access handle to access the MSI-X tables.
 *      Whether or not which handle is returned at the moment depends on
 *      the Hermon FM state.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *
 *  Return value
 *  	the access handle to MSI-X tables
 *
 *  Caller's context
 *      hermon_get_msix_tblhdl() can be called in user, kernel, interrupt
 *      context or high interrupt context.
 */
ddi_acc_handle_t
hermon_get_msix_tblhdl(hermon_state_t *state)
{
	return (state->hs_fm_disable || hermon_get_state(state) & HCA_ATTCH_FM ?
	    state->hs_fm_msix_tblhdl : state->hs_reg_msix_tblhdl);
}


/*
 *  ddi_acc_handle_t
 *  hermon_get_msix_pbahdl(hermon_state_t *state)
 *
 *  Overview
 *      hermon_get_msix_pbahdl() returns either the fma-protected access
 *      handle or the regular ddi-access handle to access the MSI-X PBA.
 *      Whether or not which handle is returned at the moment depends on
 *      the Hermon FM state.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *
 *  Return value
 *  	the access handle to MSI-X PBA
 *
 *  Caller's context
 *      hermon_get_msix_pbahdl() can be called in user, kernel, interrupt
 *      context or high interrupt context.
 */
ddi_acc_handle_t
hermon_get_msix_pbahdl(hermon_state_t *state)
{
	return (state->hs_fm_disable || hermon_get_state(state) & HCA_ATTCH_FM ?
	    state->hs_fm_msix_pbahdl : state->hs_reg_msix_pbahdl);
}


/*
 *  void
 *  hermon_inter_err_chk(void *arg)
 *
 *  Overview
 *      hermon_inter_err_chk() periodically checks the internal error buffer
 *      to pick up a Hermon asynchronous internal error.
 *
 *      Note that this internal error can be notified if the interrupt is
 *      registered, but even so there are some cases that an interrupt against
 *      it cannot be raised so that Hermon RPM recommeds to poll this internal
 *      error buffer periodically instead. This function is invoked at
 *      10ms interval in kernel context though the function itself can be
 *      called in interrupt context.
 *
 *  Argument
 *      arg: pointer to Hermon state structure
 *
 *  Return value
 *  	Nothing
 *
 *  Caller's context
 *      hermon_inter_err_chk() can be called in user, kernel, interrupt
 *      context or high interrupt context.
 *
 */
void
hermon_inter_err_chk(void *arg)
{
	uint32_t	word;
	ddi_acc_handle_t cmdhdl;
	hermon_state_t *state = (hermon_state_t *)arg;

	/* initialize the FMA retry loop */
	hermon_pio_init(fm_loop_cnt, fm_status, fm_test);

#ifdef FMA_TEST
	if (hermon_test_num != 0) {
		return;
	}
#endif
	if (state->hs_fm_poll_suspend) {
		return;
	}

	/* Get the access handle for Hermon CMD I/O space */
	cmdhdl = hermon_get_cmdhdl(state);

	/* the FMA retry loop starts. */
	hermon_pio_start(state, cmdhdl, pio_error, fm_loop_cnt, fm_status,
	    fm_test);

	word = ddi_get32(cmdhdl, state->hs_cmd_regs.fw_err_buf);

	/* the FMA retry loop ends. */
	hermon_pio_end(state, cmdhdl, pio_error, fm_loop_cnt, fm_status,
	    fm_test);

	if (word != 0) {
		HERMON_FMANOTE(state, HERMON_FMA_INTERNAL);
		/* if fm_disable is on, Hermon FM functions don't work */
		if (state->hs_fm_disable) {
			cmn_err(CE_PANIC,
			    "Hermon Fatal Internal Error. "
			    "Hermon state=0x%p", (void *)state);
		} else {
			hermon_fm_ereport(state, HCA_IBA_ERR, HCA_ERR_FATAL);
		}
	}

	/* issue the ereport pended in the interrupt context */
	if (state->hs_fm_async_errcnt > 0) {
		hermon_fm_ereport(state, HCA_IBA_ERR, HCA_ERR_FATAL);
		atomic_dec_32(&state->hs_fm_async_errcnt);
	}

	return;

pio_error:
	hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_FATAL);
}


/*
 *  boolean_t
 *  hermon_cmd_retry_ok(hermon_cmd_post_t *cmd, int status)
 *
 *  Overview
 *  	In the case that a HW error is detected, if it can be isolated
 *  	enough, Hermon FM retries the operation which caused the error.
 *  	However, this retry can induce another error; since the retry is
 *  	achieved as a block basis, not a statement basis, once the state
 *  	was set inside the Hermon HW already in the previous operation, the
 *  	retry can cause for example, a CMD_BAD_SYS_STATE error, as a result.
 *  	In this case, CMD_BAD_SYS_STATE should be taken as a side effect
 *  	but a harmless result. hermon_cmd_retry_ok() checks this kind of
 *  	situation then returns if the state Hermon CMD returns is OK or not.
 *
 *  Argument
 *      cmd: pointer to hermon_cmd_post_t structure
 *      status: Hermon CMD status
 *
 *  Return value
 *  	B_TRUE		this state is no problem
 *  	B_FALSE		this state should be taken as an error
 *
 *  Caller's context
 *      hermon_cmd_retry_ok() can be called in user, kernel, interrupt
 *      context or high interrupt context.
 *
 *  Note that status except for HERMON_CMD_SUCCESS shouldn't be accepted
 *  in the debug module to catch a hidden software bug, so that ASSERT()
 *  is enabled in the case.
 */
boolean_t
hermon_cmd_retry_ok(hermon_cmd_post_t *cmd, int status)
{
	if (status == HERMON_CMD_SUCCESS)
		return (B_TRUE);

	/*
	 * The wrong status such as HERMON_CMD_BAD_SYS_STATE or
	 * HERMON_CMD_BAD_RES_STATE can return as a side effect
	 * because of the Hermon FM operation retry when a PIO
	 * error is detected during the I/O transaction. In the
	 * case, the driver may set the same value in Hermon
	 * though it was set already, then Hermon returns HERMON_
	 * CMD_BAD_{RES,SYS}_STATE as a result, which should be
	 * taken as OK.
	 */
	switch (cmd->cp_opcode) {
	case INIT_HCA:
		/*
		 * HERMON_CMD_BAD_SYS_STATE can be gotten in case of
		 * ICM not mapped or HCA already initialized.
		 */
		if (status == HERMON_CMD_BAD_SYS_STATE)
			return (B_TRUE);
		return (B_FALSE);

	case CLOSE_HCA:
		/*
		 * HERMON_CMD_BAD_SYS_STATE can be gotten in case of Firmware
		 * area is not mapped or HCA already closed.
		 */
		if (status == HERMON_CMD_BAD_SYS_STATE)
			return (B_TRUE);
		return (B_FALSE);

	case CLOSE_PORT:
		/*
		 * HERMON_CMD_BAD_SYS_STATE can be gotten in case of HCA not
		 * initialized or in case that IB ports are already down.
		 */
		if (status == HERMON_CMD_BAD_SYS_STATE)
			return (B_TRUE);
		return (B_FALSE);

	case SW2HW_MPT:
		/*
		 * HERMON_CMD_BAD_RES_STATE can be gotten in case of MPT
		 * entry already in hardware ownership.
		 */
		if (status == HERMON_CMD_BAD_RES_STATE)
			return (B_TRUE);
		return (B_FALSE);

	case HW2SW_MPT:
		/*
		 * HERMON_CMD_BAD_RES_STATE can be gotten in case of MPT
		 * entry already in software ownership.
		 */
		if (status == HERMON_CMD_BAD_RES_STATE)
			return (B_TRUE);
		return (B_FALSE);

	case SW2HW_EQ:
		/*
		 * HERMON_CMD_BAD_RES_STATE can be gotten in case of EQ
		 * entry already in hardware ownership.
		 */
		if (status == HERMON_CMD_BAD_RES_STATE)
			return (B_TRUE);
		return (B_FALSE);

	case HW2SW_EQ:
		/*
		 * HERMON_CMD_BAD_RES_STATE can be gotten in case of EQ
		 * entry already in software ownership.
		 */
		if (status == HERMON_CMD_BAD_RES_STATE)
			return (B_TRUE);
		return (B_FALSE);

	case SW2HW_CQ:
		/*
		 * HERMON_CMD_BAD_RES_STATE can be gotten in case of CQ
		 * entry already in hardware ownership.
		 */
		if (status == HERMON_CMD_BAD_RES_STATE)
			return (B_TRUE);
		return (B_FALSE);

	case HW2SW_CQ:
		/*
		 * HERMON_CMD_BAD_RES_STATE can be gotten in case of CQ
		 * entry already in software ownership.
		 */
		if (status == HERMON_CMD_BAD_RES_STATE)
			return (B_TRUE);
		return (B_FALSE);

	case SW2HW_SRQ:
		/*
		 * HERMON_CMD_BAD_RES_STATE can be gotten in case of SRQ
		 * entry already in hardware ownership.
		 */
		if (status == HERMON_CMD_BAD_RES_STATE)
			return (B_TRUE);
		return (B_FALSE);

	case HW2SW_SRQ:
		/*
		 * HERMON_CMD_BAD_RES_STATE can be gotten in case of SRQ
		 * entry already in software ownership.
		 */
		if (status == HERMON_CMD_BAD_RES_STATE)
			return (B_TRUE);
		return (B_FALSE);
	default:
		break;
	}

	/* other cases */
	return (B_FALSE);
}


#ifdef FMA_TEST

/*
 * Hermon FMA test variables
 */
#define	FMA_TEST_HASHSZ	64
int hermon_test_num;			/* predefined testset */

static struct i_hca_fm_test *i_hca_test_register(char *, int, int,
    void (*)(struct i_hca_fm_test *, ddi_fm_error_t *),
    void *, mod_hash_t *, mod_hash_t *, int);
static void i_hca_test_free_item(mod_hash_val_t);
static void i_hca_test_set_item(int, struct i_hca_fm_test *);
static void hermon_trigger_pio_error(hermon_test_t *, ddi_fm_error_t *);

/*
 * Hermon FMA Function Test Interface
 */

/* Attach Errors */

#define	ATTACH_TS	(HCA_TEST_TRANSIENT | HCA_TEST_ATTACH | HCA_TEST_START)
#define	ATTACH_TE	(HCA_TEST_TRANSIENT | HCA_TEST_ATTACH | HCA_TEST_END)

#define	ATTACH_PS	(HCA_TEST_PERSISTENT | HCA_TEST_ATTACH | HCA_TEST_START)
#define	ATTACH_PE	(HCA_TEST_PERSISTENT | HCA_TEST_ATTACH | HCA_TEST_END)

static hermon_test_t testset[] = {
/* Initial Value */
{0, 0, 0, NULL, 0, 0, NULL, NULL, NULL},	/* 0 */

/* PIO Transient Errors */
{0, HCA_TEST_PIO, ATTACH_TS, NULL, /* attach/transient/start/propagate */
    HCA_PIO_RETRY_CNT, 0, NULL, NULL, NULL},	/* 1 */
{0, HCA_TEST_PIO, ATTACH_TE, NULL, /* attach/transient/end/propagate */
    HCA_PIO_RETRY_CNT, 0, NULL, NULL, NULL},	/* 2 */

/* PIO Persistent Errors */
{0, HCA_TEST_PIO, ATTACH_PS, NULL, /* attach/persistent/start/propagate */
    0, 0, NULL, NULL, NULL},			/* 3 */
{0, HCA_TEST_PIO, ATTACH_PE, NULL, /* attach/persistent/end/propagate */
    0, 0, NULL, NULL, NULL},			/* 4 */

};


/*
 *  void
 *  hermon_trigger_pio_error(hermon_test_t *tst, ddi_fm_error_t *derr)
 *
 *  Overview
 *      hermon_trigger_pio_error() is a PIO error injection function
 *      to cause a pseduo PIO error.
 *
 *  Argument
 *      tst: pointer to HCA FM function test structure. If the structure
 *           is not used, the NULL value must be passed instead.
 *      derr: pointer to ddi_fm_error_t structure
 *
 *  Return value
 *      Nothing
 *
 *  Caller's context
 *      hermon_trigger_pio_error() can be called in user, kernel, interrupt
 *      context or high interrupt context.
 */
static void
hermon_trigger_pio_error(hermon_test_t *tst, ddi_fm_error_t *derr)
{
	hermon_state_t *state = (hermon_state_t *)tst->private;
	derr->fme_status = DDI_FM_OK;

	if (tst->type != HCA_TEST_PIO) {
		return;
	}

	if ((tst->trigger & HCA_TEST_ATTACH &&
	    i_ddi_node_state(state->hs_dip) < DS_ATTACHED &&
	    hermon_get_state(state) & HCA_PIO_FM)) {
		if (tst->trigger & HCA_TEST_PERSISTENT) {
			i_hca_fm_ereport(state->hs_dip, HCA_IBA_ERR,
			    DDI_FM_DEVICE_INVAL_STATE);
			derr->fme_status = DDI_FM_NONFATAL;
			return;
		} else if (tst->trigger & HCA_TEST_TRANSIENT &&
		    tst->errcnt) {
			i_hca_fm_ereport(state->hs_dip, HCA_IBA_ERR,
			    DDI_FM_DEVICE_INVAL_STATE);
			derr->fme_status = DDI_FM_NONFATAL;
			tst->errcnt--;
			return;
		}
	}
}


/*
 *  struct hermon_fm_test *
 *  hermon_test_register(hermon_state_t *state, char *filename, int linenum,
 *      int type)
 *
 *  Overview
 *      hermon_test_register() registers a Hermon FM test item for the
 *      function test.
 *
 *  Argument
 *      state: pointer to Hermon state structure
 *  	filename: source file name where the function call is implemented
 *		  This value is usually a __FILE__  pre-defined macro.
 *  	linenum: line number where the function call is described in the
 *		 file specified above.
 *		 This value is usually a __LINE__ pre-defined macro.
 *	type: HW error type
 *			HCA_TEST_PIO	pio error
 *			HCA_TEST_IBA	ib specific error
 *
 *  Return value
 *      pointer to Hermon FM function test structure registered.
 *
 *  Caller's context
 *      hermon_test_register() can be called in user, kernel or interrupt
 *      context.
 *
 *  Note that no test item is registered if Hermon FM is disabled.
 */
hermon_test_t *
hermon_test_register(hermon_state_t *state, char *filename, int linenum,
    int type)
{
	void (*pio_injection)(struct i_hca_fm_test *, ddi_fm_error_t *) =
	    (void (*)(struct i_hca_fm_test *, ddi_fm_error_t *))
	    hermon_trigger_pio_error;

	if (state->hs_fm_disable)
		return (NULL);

	return ((hermon_test_t *)i_hca_test_register(filename, linenum, type,
	    pio_injection, (void *)state, state->hs_fm_test_hash,
	    state->hs_fm_id_hash, hermon_test_num));
}
#endif /* FMA_TEST */


/*
 * HCA FM Common Interface
 *
 * These functions should be used for any HCA drivers, but probably
 * customized for their own HW design and/or FM implementation.
 * Customized functins should have the driver name prefix such as
 * hermon_xxxx() and be defined separately but whose functions should
 * call the common interface inside.
 */

/*
 *  void
 *  i_hca_fm_init(struct i_hca_fm *hca_fm)
 *
 *  Overview
 *      i_hca_fm_init() is an initialization function which sets up the acc
 *      handle kmem_cache if this function is called the first time.
 *
 *  Argument
 *      hca_fm: pointer to HCA FM structure
 *
 *  Return value
 *      Nothing
 *
 *  Caller's context
 *      i_hca_fm_init() can be called in user or kernel context, but cannot
 *      be called in interrupt context.
 */
static void
i_hca_fm_init(struct i_hca_fm *hca_fm)
{

	mutex_enter(&hca_fm->lock);

	++hca_fm->ref_cnt;
	if (hca_fm->fm_acc_cache == NULL) {
		hca_fm->fm_acc_cache = kmem_cache_create("hca_fm_acc_handle",
		    sizeof (struct i_hca_acc_handle), 0, NULL,
		    NULL, NULL, NULL, NULL, 0);
	}

	mutex_exit(&hca_fm->lock);
}


/*
 *  void
 *  i_hca_fm_fini(struct i_hca_fm *hca_fm)
 *
 *  Overview
 *      i_hca_fm_fini() is a finalization function which frees up the acc
 *      handle kmem_cache if this function is called the last time.
 *
 *  Argument
 *      hca_fm: pointer to HCA FM structure
 *
 *  Return value
 *      Nothing
 *
 *  Caller's context
 *      i_hca_fm_fini() can be called in user or kernel context, but cannot
 *      be called in interrupt context.
 */
static void
i_hca_fm_fini(struct i_hca_fm *hca_fm)
{
	mutex_enter(&hca_fm->lock);

	if (--hca_fm->ref_cnt == 0) {

		if (hca_fm->fm_acc_cache) {
			kmem_cache_destroy(hca_fm->fm_acc_cache);
			hca_fm->fm_acc_cache = NULL;
		}
	}

	mutex_exit(&hca_fm->lock);
}


/*
 *  void
 *  i_hca_fm_ereport(dev_info_t *dip, int type, char *detail)
 *
 *  Overview
 *      i_hca_fm_ereport() is a wrapper function of ddi_fm_ereport_post() but
 *      generates an ena before it calls ddi_fm_ereport_post() for HCA
 *      specific HW errors.
 *
 *  Argument
 *      dip: pointer to this device dev_info structure
 *      type: error type
 *		HCA_SYS_ERR	FMA reporting HW error
 *		HCA_IBA_ERR	HCA specific HW error
 *      detail: definition of leaf driver detected ereports which is one of:
 *      	DDI_FM_DEVICE_INVAL_STATE
 *		DDI_FM_DEVICE_NO_RESPONSE
 *		DDI_FM_DEVICE_STALL
 *		DDI_FM_DEVICE_BADINT_LIMIT
 *		DDI_FM_DEVICE_INTERN_CORR
 *		DDI_FM_DEVICE_INTERN_UNCORR
 *
 *  Return value
 *      Nothing
 *
 *  Caller's context
 *      i_hca_fm_ereport() can be called in user, kernel or interrupt context.
 */
static void
i_hca_fm_ereport(dev_info_t *dip, int type, char *detail)
{
	uint64_t ena;
	char buf[FM_MAX_CLASS];

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s", DDI_FM_DEVICE, detail);

	ena = fm_ena_generate(0, FM_ENA_FMT1);
	if (type == HCA_IBA_ERR) {
		/* this is an error of its own */
		ena = fm_ena_increment(ena);
	}

	ddi_fm_ereport_post(dip, buf, ena, DDI_NOSLEEP,
	    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0, NULL);
}


/*
 * struct i_hca_acc_handle *
 * i_hca_get_acc_handle(struct i_hca_fm *hca_fm, ddi_acc_handle_t handle)
 *
 *  Overview
 *      i_hca_get_acc_handle() returns ddi_acc_handle_t used for HCA FM.
 *
 *  Argument
 *      hca_fm: pointer to HCA FM structure
 *      handle: ddi_acc_handle_t
 *
 *  Return value
 *	handle: pointer to ddi_acc_handle_t used for HCA FM
 *
 *  Caller's context
 *      i_hca_get_acc_handle() can be called in user, kernel or interrupt
 *      context.
 */
static struct i_hca_acc_handle *
i_hca_get_acc_handle(struct i_hca_fm *hca_fm, ddi_acc_handle_t handle)
{
	struct i_hca_acc_handle *hdlp;

	/* Retrieve the HCA FM access handle */
	mutex_enter(&hca_fm->lock);

	for (hdlp = hca_fm->hdl; hdlp != NULL; hdlp = hdlp->next) {
		if (hdlp->save_hdl == handle) {
			mutex_exit(&hca_fm->lock);
			return (hdlp);
		}
	}

	mutex_exit(&hca_fm->lock);
	return (hdlp);
}


/*
 *  int
 *  i_hca_regs_map_setup(struct i_hca_fm *hca_fm, dev_info_t *dip,
 *      uint_t rnumber, caddr_t *addrp, offset_t offset, offset_t len,
 *      ddi_device_acc_attr_t *accattrp, ddi_acc_handle_t *handle)
 *
 *  Overview
 *      i_hca_regs_map_setup() is a wrapper function of ddi_regs_map_setup(),
 *      but allocates the HCA FM acc handle structure and initializes it.
 *
 *  Argument
 *      hca_fm: pointer to HCA FM structure
 *      dip: pointer to this device dev_info structure
 *      rnumber: index number to the register address space set
 *      addrp: platform-dependent value (same as ddi_regs_map_setup())
 *      offset: offset into the register address space
 *      len: address space length to be mapped
 *      accattrp: pointer to device access attribute structure
 *	handle: pointer to ddi_acc_handle_t used for HCA FM
 *
 *  Return value
 *      ddi function status value which are:
 *      	DDI_SUCCESS
 *      	DDI_FAILURE
 *      	DDI_ME_RNUMBER_RNGE
 *      	DDI_REGS_ACC_CONFLICT
 *
 *  Caller's context
 *      i_hca_regs_map_setup() can be called in user or kernel context only.
 */
static int
i_hca_regs_map_setup(struct i_hca_fm *hca_fm, dev_info_t *dip, uint_t rnumber,
    caddr_t *addrp, offset_t offset, offset_t len,
    ddi_device_acc_attr_t *accattrp, ddi_acc_handle_t *handle)
{
	int status;
	struct i_hca_acc_handle *handlep, *hdlp, *last;

	/* Allocate an access handle */
	if ((status = ddi_regs_map_setup(dip, rnumber, addrp, offset,
	    len, accattrp, handle)) != DDI_SUCCESS) {
		return (status);
	}

	/* Allocate HCA FM acc handle structure */
	handlep = kmem_cache_alloc(hca_fm->fm_acc_cache, KM_SLEEP);

	/* Initialize fields */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*handlep))
	handlep->next = NULL;
	handlep->save_hdl = (*handle);
	handlep->thread_cnt = 0;
	mutex_init(&handlep->lock, NULL, MUTEX_DRIVER, NULL);

	/* Register this handle */
	mutex_enter(&hca_fm->lock);
	for (last = hdlp = hca_fm->hdl; hdlp != NULL; hdlp = hdlp->next) {
		last = hdlp;
	}
	if (last == NULL) {
		hca_fm->hdl = handlep;
	} else {
		last->next = handlep;
	}
	mutex_exit(&hca_fm->lock);

	return (status);
}


/*
 *  void
 *  i_hca_regs_map_free(struct i_hca_fm *hca_fm, ddi_acc_handle_t *handlep)
 *
 *  Overview
 *      i_hca_regs_map_setup() is a wrapper function of ddi_regs_map_free(),
 *      and frees the HCA FM acc handle structure allocated by
 *      i_hca_regs_map_setup().
 *
 *  Argument
 *      hca_fm: pointer to HCA FM structure
 *	handle: pointer to ddi_acc_handle_t used for HCA FM
 *
 *  Return value
 *      Nothing
 *
 *  Caller's context
 *      i_hca_regs_map_free() can be called in user or kernel context only.
 *
 *  Note that the handle passed to i_hca_regs_map_free() is NULL-cleared
 *  after this function is called.
 */
static void
i_hca_regs_map_free(struct i_hca_fm *hca_fm, ddi_acc_handle_t *handle)
{
	struct i_hca_acc_handle *handlep, *hdlp, *prev;

	/* De-register this handle */
	mutex_enter(&hca_fm->lock);
	for (prev = hdlp = hca_fm->hdl; hdlp != NULL; hdlp = hdlp->next) {
		if (hdlp->save_hdl == *handle)
			break;
		prev = hdlp;
	}
	ASSERT(prev != NULL && hdlp != NULL);
	if (hdlp != prev) {
		prev->next = hdlp->next;
	} else {
		hca_fm->hdl = hdlp->next;
	}
	handlep = hdlp;
	mutex_exit(&hca_fm->lock);

	mutex_destroy(&handlep->lock);
	handlep->save_hdl = NULL;
	kmem_cache_free(hca_fm->fm_acc_cache, handlep);

	/* Release this handle */
	ddi_regs_map_free(handle);
	*handle = NULL;
}


/*
 *  int
 *  i_hca_pci_config_setup(struct i_hca_fm *hca_fm, dev_info_t *dip,
 *      ddi_acc_handle_t *handle, boolean_t fm_protect)
 *
 *  Overview
 *      i_hca_pci_config_setup() is a wrapper function of pci_config_setup(),
 *      but allocates the HCA FM acc handle structure and initializes it.
 *
 *  Argument
 *      hca_fm: pointer to HCA FM structure
 *      dip: pointer to this device dev_info structure
 *	handle: pointer to ddi_acc_handle_t used for HCA PCI config space
 *		with FMA
 *	fm_protect: flag to tell if an fma-protected access handle should
 *		be used
 *
 *  Return value
 *      ddi function status value which are:
 *      	DDI_SUCCESS
 *      	DDI_FAILURE
 *
 *  Caller's context
 *      i_hca_pci_config_setup() can be called in user or kernel context only.
 */
static int
i_hca_pci_config_setup(struct i_hca_fm *hca_fm, dev_info_t *dip,
    ddi_acc_handle_t *handle)
{
	int status;
	struct i_hca_acc_handle *handlep, *hdlp, *last;

	/* Allocate an access handle */
	if ((status = pci_config_setup(dip, handle)) != DDI_SUCCESS) {
		return (status);
	}

	/* Allocate HCA FM acc handle structure */
	handlep = kmem_cache_alloc(hca_fm->fm_acc_cache, KM_SLEEP);

	/* Initialize fields */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*handlep))
	handlep->next = NULL;
	handlep->save_hdl = (*handle);
	handlep->thread_cnt = 0;
	mutex_init(&handlep->lock, NULL, MUTEX_DRIVER, NULL);

	/* Register this handle */
	mutex_enter(&hca_fm->lock);
	for (last = hdlp = hca_fm->hdl; hdlp != NULL; hdlp = hdlp->next) {
		last = hdlp;
	}
	if (last == NULL) {
		hca_fm->hdl = handlep;
	} else {
		last->next = handlep;
	}
	mutex_exit(&hca_fm->lock);

	return (status);
}


/*
 *  void
 *  i_hca_pci_config_teardown(struct i_hca_fm *hca_fm,
 *      ddi_acc_handle_t *handlep)
 *
 *  Overview
 *      i_hca_pci_config_teardown() is a wrapper function of
 *      pci_config_teardown(), and frees the HCA FM acc handle structure
 *      allocated by i_hca_pci_config_setup().
 *
 *  Argument
 *      hca_fm: pointer to HCA FM structure
 *	handle: pointer to ddi_acc_handle_t used for HCA FM
 *
 *  Return value
 *      Nothing
 *
 *  Caller's context
 *      i_hca_pci_config_teardown() can be called in user or kernel context
 *      only.
 *
 *  Note that the handle passed to i_hca_pci_config_teardown() is NULL-cleared
 *  after this function is called.
 */
static void
i_hca_pci_config_teardown(struct i_hca_fm *hca_fm, ddi_acc_handle_t *handle)
{
	struct i_hca_acc_handle *handlep, *hdlp, *prev;

	/* De-register this handle */
	mutex_enter(&hca_fm->lock);
	for (prev = hdlp = hca_fm->hdl; hdlp != NULL; hdlp = hdlp->next) {
		if (hdlp->save_hdl == *handle)
			break;
		prev = hdlp;
	}
	ASSERT(prev != NULL && hdlp != NULL);
	if (hdlp != prev) {
		prev->next = hdlp->next;
	} else {
		hca_fm->hdl = hdlp->next;
	}
	handlep = hdlp;
	mutex_exit(&hca_fm->lock);

	mutex_destroy(&handlep->lock);
	handlep->save_hdl = NULL;
	kmem_cache_free(hca_fm->fm_acc_cache, handlep);

	/* Release this handle */
	pci_config_teardown(handle);
	*handle = NULL;
}


/*
 *  int
 *  i_hca_pio_start(dev_info_t *dip, struct i_acc_handle *handle,
 *      struct i_hca_fm_test *tst)
 *
 *  Overview
 *      i_hca_pio_start() is one of a pair of HCA FM fuctions for PIO, which
 *      should be called before HCA drivers issue PIOs against I/O space.
 *      See HCA FM comments at the beginning of this file in detail.
 *
 *  Argument
 *      dip: pointer to this device dev_info structure
 *	handle: pointer to ddi_acc_handle_t used for HCA FM
 *      tst: pointer to HCA FM function test structure. If the structure
 *           is not used, the NULL value must be passed instead.
 *
 *  Return value
 *  	error status showing whether or not this error can retry
 *	HCA_PIO_OK		No HW errors
 *	HCA_PIO_TRANSIENT	This error could be transient
 *	HCA_PIO_PERSISTENT	This error is persistent
 *
 *  Caller's context
 *      i_hca_pio_start() can be called in user, kernel or interrupt context.
 */
/* ARGSUSED */
static int
i_hca_pio_start(dev_info_t *dip, struct i_hca_acc_handle *hdlp,
    struct i_hca_fm_test *tst)
{
	ddi_fm_error_t derr;

	/* Count up the number of threads issuing this PIO */
	mutex_enter(&hdlp->lock);
	hdlp->thread_cnt++;
	mutex_exit(&hdlp->lock);

	/* Get the PIO error via FMA */
	ddi_fm_acc_err_get(fm_acc_hdl(hdlp), &derr, DDI_FME_VERSION);

#ifdef FMA_TEST
	/* Trigger PIO errors */
	if (tst != NULL && tst->trigger & HCA_TEST_START) {
		(*tst->pio_injection)(tst, &derr);
	}
#endif /* FMA_TEST */

	switch (derr.fme_status) {
	case DDI_FM_OK:
		/* Not have to clear the fma error log */
		return (HCA_PIO_OK);

	case DDI_FM_NONFATAL:
		/* Now clear this error */
		ddi_fm_acc_err_clear(fm_acc_hdl(hdlp), DDI_FME_VERSION);

		/* Log this error and notify it as a persistent error */
		ddi_fm_service_impact(dip, DDI_SERVICE_LOST);
		return (HCA_PIO_PERSISTENT);

	/* In theory, this shouldn't happen */
	case DDI_FM_FATAL:
	case DDI_FM_UNKNOWN:
	default:
		cmn_err(CE_WARN, "Unknown HCA HW error status (%d)",
		    derr.fme_status);
		/* Return this as a persistent error */
		return (HCA_PIO_PERSISTENT);
	}
}


/*
 *  int
 *  i_hca_pio_end(dev_info_t *dip, ddi_acc_handle_t handle, int *cnt,
 *      struct i_hca_fm_test *tst)
 *
 *  Overview
 *      i_hca_pio_end() is the other of a pair of HCA FM fuctions for PIO,
 *      which should be called after HCA drivers issue PIOs against I/O space.
 *      See HCA FM comments at the beginning of this file in detail.
 *
 *  Argument
 *      dip: pointer to this device dev_info structure
 *	handle: pointer to ddi_acc_handle_t used for HCA FM
 *	cnt: pointer to the counter variable which holds the nubmer of retry
 *	     when a HW error is detected.
 *      tst: pointer to HCA FM function test structure. If the structure
 *           is not used, the NULL value must be passed instead.
 *
 *  Return value
 *  	error status showing whether or not this error can retry
 *	HCA_PIO_OK		No HW errors
 *	HCA_PIO_TRANSIENT	This error could be transient
 *	HCA_PIO_PERSISTENT	This error is persistent
 *
 *  Caller's context
 *      i_hca_pio_end() can be called in user, kernel or interrupt context.
 */
/* ARGSUSED */
static int
i_hca_pio_end(dev_info_t *dip, struct i_hca_acc_handle *hdlp, int *cnt,
    struct i_hca_fm_test *tst)
{
	ddi_fm_error_t derr;

	/* Get the PIO error via FMA */
	ddi_fm_acc_err_get(fm_acc_hdl(hdlp), &derr, DDI_FME_VERSION);

#ifdef FMA_TEST
	/* Trigger PIO errors */
	if (tst != NULL && tst->trigger & HCA_TEST_END) {
		(*tst->pio_injection)(tst, &derr);
	}
#endif /* FMA_TEST */

	/* Evaluate the PIO error */
	switch (derr.fme_status) {
	case DDI_FM_OK:
		/* Count down the number of threads issuing this PIO */
		mutex_enter(&hdlp->lock);
		hdlp->thread_cnt--;
		mutex_exit(&hdlp->lock);

		/* Not have to clear the fma error log */
		return (HCA_PIO_OK);

	case DDI_FM_NONFATAL:
		/* Now clear this error */
		ddi_fm_acc_err_clear(fm_acc_hdl(hdlp), DDI_FME_VERSION);

		/*
		 * Check if this error comes from another thread running
		 * with the same handle almost at the same time.
		 */
		mutex_enter(&hdlp->lock);
		if (hdlp->thread_cnt > 1) {
			/* Count down the number of threads */
			hdlp->thread_cnt--;
			mutex_exit(&hdlp->lock);

			/* Return this as a persistent error */
			return (HCA_PIO_PERSISTENT);
		}
		mutex_exit(&hdlp->lock);

		/* Now determine if this error is persistent or not */
		if (--(*cnt) >= 0)  {
			return (HCA_PIO_TRANSIENT);
		} else {
			/* Count down the number of threads */
			mutex_enter(&hdlp->lock);
			hdlp->thread_cnt--;
			mutex_exit(&hdlp->lock);
			return (HCA_PIO_PERSISTENT);
		}

	/* In theory, this shouldn't happen */
	case DDI_FM_FATAL:
	case DDI_FM_UNKNOWN:
	default:
		cmn_err(CE_WARN, "Unknown HCA HW error status (%d)",
		    derr.fme_status);
		/* Return this as a persistent error */
		return (HCA_PIO_PERSISTENT);
	}
}


/*
 * HCA FM Test Interface
 *
 * These functions should be used for any HCA drivers, but probably
 * customized for their own HW design and/or FM implementation.
 * Customized functins should have the driver name prefix such as
 * hermon_xxxx() and be defined separately but whose function should
 * call the common interface inside.
 */

#ifdef FMA_TEST
static int test_num;		/* serial number */
static kmutex_t i_hca_test_lock; 	/* lock for serial numer */

/*
 *  void
 *  i_hca_test_init(mod_hash_t **strHashp, mod_hash_t **idHashp)
 *
 *  Overview
 *      i_hca_test_init() creates two hash tables, one of which is for string,
 *      and the other of which is for ID, then saves pointers to arguments
 *      passed. This function uses the mod_hash utilities to manage the
 *      hash tables. About the mod_hash, see common/os/modhash.c.
 *
 *  Argument
 *      strHashp: pointer to String hash table pointer
 *      idHashp: pointer to ID hash table pointer
 *
 *  Return value
 *      Nothing
 *
 *  Caller's context
 *      i_hca_test_init() can be called in user or kernel context only.
 */
static void
i_hca_test_init(mod_hash_t **strHashp, mod_hash_t **idHashp)
{
	*idHashp = mod_hash_create_idhash("HCA_FMA_id_hash",
	    FMA_TEST_HASHSZ, mod_hash_null_valdtor);

	*strHashp = mod_hash_create_strhash("HCA_FMA_test_hash",
	    FMA_TEST_HASHSZ, i_hca_test_free_item);
}


/*
 *  void
 *  i_hca_test_fini(mod_hash_t **strHashp, mod_hash_t **idHashp)
 *
 *  Overview
 *      i_hca_test_fini() releases two hash tables used for HCA FM test.
 *
 *  Argument
 *      strHashp: pointer to String hash table pointer
 *      idHashp: pointer to ID hash table pointer
 *
 *  Return value
 *      Nothing
 *
 *  Caller's context
 *      i_hca_test_fini() can be called in user, kernel or interrupt context.
 *
 */
static void
i_hca_test_fini(mod_hash_t **strHashp, mod_hash_t **idHashp)
{
	mod_hash_destroy_hash(*strHashp);
	*strHashp = NULL;

	mod_hash_destroy_hash(*idHashp);
	*idHashp = NULL;
}


/*
 *  struct i_hca_fm_test *
 *  i_hca_test_register(char *filename, int linenum, int type,
 *      void (*pio_injection)(struct i_hca_fm_test *, ddi_fm_error_t *),
 *      void *private, mod_hash_t *strHash, mod_hash_t *idHash, int preTestNum)
 *
 *  Overview
 *      i_hca_test_register() registers an HCA FM test item against HCA FM
 *      function callings specified with the file name and the line number
 *      (passed as the arguments).
 *
 *  Argument
 *  	filename: source file name where the function call is implemented
 *		  This value is usually a __FILE__  pre-defined macro.
 *  	linenum: line number where the function call is described in the
 *		 file specified above.
 *		 This value is usually a __LINE__ pre-defined macro.
 *	type: HW error type
 *			HCA_TEST_PIO	pio error
 *			HCA_TEST_IBA	ib specific error
 *	pio_injection: pio error injection callback function invoked when the
 *		       function specified above (with the file name and the
 *		       line number) is executed. If the function is not a PIO,
 *		       request, this parameter should be NULL.
 *	private: the argument passed to either of injection functions when
 *		 they're invoked.
 *      strHashp: pointer to String hash table
 *      idHashp: pointer to ID hash table
 *      preTestNum: the index of the pre-defined testset for this test item.
 *
 *  Return value
 *      pointer to HCA FM function test structure registered.
 *
 *  Caller's context
 *      i_hca_test_register() can be called in user, kernel or interrupt
 *      context.
 *
 */
static struct i_hca_fm_test *
i_hca_test_register(char *filename, int linenum, int type,
    void (*pio_injection)(struct i_hca_fm_test *, ddi_fm_error_t *),
    void *private, mod_hash_t *strHash, mod_hash_t *idHash, int preTestNum)
{
	struct i_hca_fm_test *t_item;
	char key_buf[255], *hash_key;
	int status;

	(void) sprintf(key_buf, "%s:%d", filename, linenum);
	hash_key = kmem_zalloc(strlen(key_buf) + 1, KM_NOSLEEP);

	if (hash_key == NULL)
		cmn_err(CE_PANIC, "No memory for HCA FMA Test.");

	bcopy(key_buf, hash_key, strlen(key_buf));

	status = mod_hash_find(strHash, (mod_hash_key_t)hash_key,
	    (mod_hash_val_t *)&t_item);

	switch (status) {
	case MH_ERR_NOTFOUND:
		t_item = (struct i_hca_fm_test *)
		    kmem_alloc(sizeof (struct i_hca_fm_test), KM_NOSLEEP);
		if (t_item == NULL)
			cmn_err(CE_PANIC, "No memory for HCA FMA Test.");

		/* Set the error number */
		mutex_enter(&i_hca_test_lock);
		t_item->num = test_num++;
		mutex_exit(&i_hca_test_lock);

		/* Set type and other static information */
		t_item->type = type;
		t_item->line_num = linenum;
		t_item->file_name = filename;
		t_item->hash_key = hash_key;
		t_item->private = private;
		t_item->pio_injection = pio_injection;

		/* Set the pre-defined hermon test item */
		i_hca_test_set_item(preTestNum, (struct i_hca_fm_test *)t_item);

		status = mod_hash_insert(strHash, (mod_hash_key_t)
		    hash_key, (mod_hash_val_t)t_item);
		ASSERT(status == 0);

		status = mod_hash_insert(idHash, (mod_hash_key_t)
		    (uintptr_t)t_item->num, (mod_hash_val_t)t_item);
		ASSERT(status == 0);
		break;

	case MH_ERR_NOMEM:
		cmn_err(CE_PANIC, "No memory for HCA FMA Test.");
		break;

	case MH_ERR_DUPLICATE:
		cmn_err(CE_PANIC, "HCA FMA Test Internal Error.");
		break;
	default:
		/* OK, this is already registered. */
		kmem_free(hash_key, strlen(key_buf) + 1);
		break;
	}
	return (t_item);
}


/*
 *  void
 *  i_hca_test_set_item(int num, struct i_hca_fm_test *t_item)
 *
 *  Overview
 *      i_hca_test_set_item() is a private function used in
 *      i_hca_test_register() above. This function sets the testset specified
 *      (with the index number) to HCA FM function test structure.
 *
 *  Argument
 *      num: index to test set (testset structure array)
 *      t_item: pointer to HCA fM function test structure
 *
 *  Return value
 *      Nothing
 *
 *  Caller's context
 *      i_hca_test_set_item() can be called in user, kernel, interrupt
 *      context or hight interrupt context.
 *
 */
static void
i_hca_test_set_item(int num, struct i_hca_fm_test *t_item)
{
	if (num < 0 || num >= sizeof (testset) / sizeof (hermon_test_t) ||
	    testset[num].type != t_item->type) {
		t_item->trigger = testset[0].trigger;
		t_item->errcnt = testset[0].errcnt;
		return;
	}

	/* Set the testsuite */
	t_item->trigger = testset[num].trigger;
	t_item->errcnt = testset[num].errcnt;
}


/*
 *  void
 *  i_hca_test_free_item(mod_hash_val_t val)
 *
 *  Overview
 *      i_hca_test_free_item() is a private function used to free HCA FM
 *      function test structure when i_hca_test_fini() is called. This function
 *      is registered as a destructor when the hash table is created in
 *      i_hca_test_init().
 *
 *  Argument
 *      val: pointer to the value stored in hash table (pointer to HCA FM
 *           function test structure)
 *
 *  Return value
 *      Nothing
 *
 *  Caller's context
 *      i_hca_test_free_item() can be called in user, kernel or interrupt
 *      context.
 *
 */
static void
i_hca_test_free_item(mod_hash_val_t val)
{
	struct i_hca_fm_test *t_item = (struct i_hca_fm_test *)val;
	kmem_free(t_item, sizeof (struct i_hca_fm_test));
}
#endif /* FMA_TEST */
