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
 * Universal Host Controller Driver (UHCI)
 *
 * The UHCI driver is a driver which interfaces to the Universal
 * Serial Bus Architecture (USBA) and the Host Controller (HC). The interface to
 * the Host Controller is defined by the Universal Host Controller Interface.
 * This file contains code for auto-configuration entry points and interrupt
 * handling.
 */
#include <sys/usb/hcd/uhci/uhcid.h>
#include <sys/usb/hcd/uhci/uhcihub.h>
#include <sys/usb/hcd/uhci/uhciutil.h>

/*
 * Prototype Declarations for cb_ops and dev_ops
 */
static	int uhci_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static	int uhci_add_intrs(uhci_state_t *uhcip, int	intr_type);
static	int uhci_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static void uhci_rem_intrs(uhci_state_t	*uhcip);
static	int uhci_open(dev_t *devp, int flags, int otyp, cred_t *credp);
static	int uhci_close(dev_t dev, int flag, int otyp, cred_t *credp);
static	int uhci_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
		cred_t *credp, int *rvalp);
static	int uhci_reset(dev_info_t *dip, ddi_reset_cmd_t cmd);
static	int uhci_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);

/* extern */
int usba_hubdi_root_hub_power(dev_info_t *dip, int comp, int level);

static struct cb_ops uhci_cb_ops = {
	uhci_open,			/* Open */
	uhci_close,			/* Close */
	nodev,				/* Strategy */
	nodev,				/* Print */
	nodev,				/* Dump */
	nodev,				/* Read */
	nodev,				/* Write */
	uhci_ioctl,			/* Ioctl */
	nodev,				/* Devmap */
	nodev,				/* Mmap */
	nodev,				/* Segmap */
	nochpoll,			/* Poll */
	ddi_prop_op,			/* cb_prop_op */
	NULL,				/* Streamtab */
	D_MP				/* Driver compatibility flag */
};

static struct dev_ops uhci_ops = {
	DEVO_REV,			/* Devo_rev */
	0,				/* Refcnt */
	uhci_info,			/* Info */
	nulldev,			/* Identify */
	nulldev,			/* Probe */
	uhci_attach,			/* Attach */
	uhci_detach,			/* Detach */
	uhci_reset,			/* Reset */
	&uhci_cb_ops,			/* Driver operations */
	&usba_hubdi_busops,		/* Bus operations */
	usba_hubdi_root_hub_power	/* Power */
};

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module. This one is a driver */
	"USB UHCI Controller Driver",	/* Name of the module. */
	&uhci_ops,		/* Driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

/*
 *  Globals
 */
void		*uhci_statep;
uint_t		uhci_errlevel = USB_LOG_L2;
uint_t		uhci_errmask = PRINT_MASK_ALL;
uint_t		uhci_instance_debug = (uint_t)-1;

uint_t		uhci_td_pool_size = 256;			/* Num TDs */
uint_t		uhci_qh_pool_size = 130;			/* Num QHs */
ushort_t	uhci_tree_bottom_nodes[NUM_FRAME_LST_ENTRIES];


/*
 * UHCI MSI tunable:
 *
 * By default MSI is enabled on all supported platforms.
 */
boolean_t uhci_enable_msi = B_TRUE;

/*
 * tunable, delay during attach in seconds
 */
int		uhci_attach_wait = 0;

/* function prototypes */
static void	uhci_handle_intr_td_errors(uhci_state_t *uhcip, uhci_td_t *td,
			uhci_trans_wrapper_t *tw, uhci_pipe_private_t *pp);
static void	uhci_handle_one_xfer_completion(uhci_state_t *uhcip,
			usb_cr_t usb_err, uhci_td_t *td);
static uint_t	uhci_intr(caddr_t arg1, caddr_t arg2);
static int	uhci_cleanup(uhci_state_t *uhcip);
static int	uhci_cpr_suspend(uhci_state_t *uhcip);
static int	uhci_cpr_resume(uhci_state_t *uhcip);


int
_init(void)
{
	int error;
	ushort_t i, j, k, *temp, num_of_nodes;

	/* Initialize the soft state structures */
	if ((error = ddi_soft_state_init(&uhci_statep, sizeof (uhci_state_t),
	    UHCI_MAX_INSTS)) != 0) {

		return (error);
	}

	/* Install the loadable module */
	if ((error = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&uhci_statep);

		return (error);
	}

	/*
	 *  Build the tree bottom shared by all instances
	 */
	temp = kmem_zalloc(NUM_FRAME_LST_ENTRIES * 2, KM_SLEEP);

	num_of_nodes = 1;
	for (i = 0; i < log_2(NUM_FRAME_LST_ENTRIES); i++) {
		for (j = 0, k = 0; k < num_of_nodes; k++, j++) {
			uhci_tree_bottom_nodes[j++] = temp[k];
			uhci_tree_bottom_nodes[j]   = temp[k] + pow_2(i);
		}

		num_of_nodes *= 2;
		for (k = 0; k < num_of_nodes; k++)
			temp[k] = uhci_tree_bottom_nodes[k];

	}
	kmem_free(temp, (NUM_FRAME_LST_ENTRIES*2));


	return (error);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


int
_fini(void)
{
	int error;

	error = mod_remove(&modlinkage);

	if (error == 0) {
		/* Release per module resources */
		ddi_soft_state_fini(&uhci_statep);
	}

	return (error);
}

/*
 * The following simulated polling is for debugging purposes only.
 * It is activated on x86 by setting usb-polling=true in GRUB or uhci.conf.
 */
static int
uhci_is_polled(dev_info_t *dip)
{
	int ret;
	char *propval;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, 0,
	    "usb-polling", &propval) != DDI_SUCCESS)

		return (0);

	ret = (strcmp(propval, "true") == 0);
	ddi_prop_free(propval);

	return (ret);
}

static void
uhci_poll_intr(void *arg)
{
	/* poll every msec */
	for (;;) {
		(void) uhci_intr(arg, NULL);
		delay(drv_usectohz(1000));
	}
}

/*
 * Host Controller Driver (HCD) Auto configuration entry points
 */

/*
 * Function Name  :  uhci_attach:
 * Description	  :  Attach entry point - called by the Kernel.
 *		     Allocates of per controller data structure.
 *		     Initializes the controller.
 * Output	  :  DDI_SUCCESS / DDI_FAILURE
 */
static int
uhci_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int				instance, polled;
	int				i, intr_types;
	uhci_state_t			*uhcip = NULL;
	usba_hcdi_register_args_t	hcdi_args;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, NULL, "uhci_attach:");

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		uhcip = uhci_obtain_state(dip);

		return (uhci_cpr_resume(uhcip));
	default:

		return (DDI_FAILURE);
	}

	/* Get the instance and create soft state */
	instance = ddi_get_instance(dip);

	/* Allocate the soft state structure for this instance of the driver */
	if (ddi_soft_state_zalloc(uhci_statep, instance) != 0) {

		return (DDI_FAILURE);
	}

	if ((uhcip = ddi_get_soft_state(uhci_statep, instance)) == NULL) {

		return (DDI_FAILURE);
	}

	uhcip->uhci_log_hdl = usb_alloc_log_hdl(dip, "uhci", &uhci_errlevel,
	    &uhci_errmask, &uhci_instance_debug, 0);

	/* Set host controller soft state to initialization */
	uhcip->uhci_hc_soft_state = UHCI_CTLR_INIT_STATE;

	/* Save the dip and instance */
	uhcip->uhci_dip		= dip;
	uhcip->uhci_instance	= instance;

	polled = uhci_is_polled(dip);
	if (polled)

		goto skip_intr;

	/* Get supported interrupt types */
	if (ddi_intr_get_supported_types(uhcip->uhci_dip,
	    &intr_types) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "uhci_attach: ddi_intr_get_supported_types failed");

		usb_free_log_hdl(uhcip->uhci_log_hdl);
		ddi_soft_state_free(uhci_statep, instance);

		return (DDI_FAILURE);
	}

	USB_DPRINTF_L3(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
	    "uhci_attach: supported interrupt types 0x%x", intr_types);

	if ((intr_types & DDI_INTR_TYPE_MSI) && uhci_enable_msi) {
		if (uhci_add_intrs(uhcip, DDI_INTR_TYPE_MSI)
		    != DDI_SUCCESS) {
			USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
			    "uhci_attach: MSI registration failed, "
			    "trying FIXED interrupt \n");
		} else {
			USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
			    "uhci_attach: Using MSI interrupt type\n");

			uhcip->uhci_intr_type = DDI_INTR_TYPE_MSI;
		}
	}

	if (!(uhcip->uhci_htable) && (intr_types & DDI_INTR_TYPE_FIXED)) {
		if (uhci_add_intrs(uhcip, DDI_INTR_TYPE_FIXED)
		    != DDI_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
			    "uhci_attach: FIXED interrupt registration "
			    "failed\n");

			usb_free_log_hdl(uhcip->uhci_log_hdl);
			ddi_soft_state_free(uhci_statep, instance);

			return (DDI_FAILURE);
		}

		USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "uhci_attach: Using FIXED interrupt type\n");

		uhcip->uhci_intr_type = DDI_INTR_TYPE_FIXED;
	}

skip_intr:
	/* Semaphore to serialize opens and closes */
	sema_init(&uhcip->uhci_ocsem, 1, NULL, SEMA_DRIVER, NULL);

	/* Create prototype condition variable */
	cv_init(&uhcip->uhci_cv_SOF, NULL, CV_DRIVER, NULL);

	/* Initialize the DMA attributes */
	uhci_set_dma_attributes(uhcip);

	/* Initialize the kstat structures */
	uhci_create_stats(uhcip);

	/* Create the td and ed pools */
	if (uhci_allocate_pools(uhcip) != USB_SUCCESS) {

		goto fail;
	}

	/* Map the registers */
	if (uhci_map_regs(uhcip) != USB_SUCCESS) {

		goto fail;
	}

	/* Enable all interrupts */
	if (polled) {
		extern pri_t maxclsyspri;

		USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "uhci_attach: running in simulated polled mode.");

		/* create thread to poll */
		(void) thread_create(NULL, 0, uhci_poll_intr, uhcip, 0, &p0,
		    TS_RUN, maxclsyspri);
	} else if (uhcip->uhci_intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_enable() for MSI interrupts */
		(void) ddi_intr_block_enable(uhcip->uhci_htable,
		    uhcip->uhci_intr_cnt);
	} else {
		/* Call ddi_intr_enable for MSI or FIXED interrupts */
		for (i = 0; i < uhcip->uhci_intr_cnt; i++)
			(void) ddi_intr_enable(uhcip->uhci_htable[i]);
	}


	/* Initialize the controller */
	if (uhci_init_ctlr(uhcip) != USB_SUCCESS) {

		goto fail;
	}

	/*
	 * At this point, the hardware will be okay.
	 * Initialize the usba_hcdi structure
	 */
	uhcip->uhci_hcdi_ops = uhci_alloc_hcdi_ops(uhcip);

	/*
	 * Make this HCD instance known to USBA
	 * (dma_attr must be passed for USBA busctl's)
	 */
	hcdi_args.usba_hcdi_register_version = HCDI_REGISTER_VERSION;
	hcdi_args.usba_hcdi_register_dip = dip;
	hcdi_args.usba_hcdi_register_ops = uhcip->uhci_hcdi_ops;
	hcdi_args.usba_hcdi_register_dma_attr = &uhcip->uhci_dma_attr;
	hcdi_args.usba_hcdi_register_iblock_cookie =
	    (ddi_iblock_cookie_t)(uintptr_t)uhcip->uhci_intr_pri;

	if (usba_hcdi_register(&hcdi_args, 0) != USB_SUCCESS) {

		goto fail;
	}

#ifndef __sparc
	/*
	 * On NCR system,  the driver seen  failure of some commands
	 * while booting. This delay mysteriously solved the problem.
	 */
	delay(drv_usectohz(uhci_attach_wait*1000000));
#endif

	/*
	 * Create another timeout handler to check whether any
	 * control/bulk/interrupt commands failed.
	 * This gets called every second.
	 */
	uhcip->uhci_cmd_timeout_id = timeout(uhci_cmd_timeout_hdlr,
	    (void *)uhcip, UHCI_ONE_SECOND);

	mutex_enter(&uhcip->uhci_int_mutex);

	/*
	 * Set HcInterruptEnable to enable all interrupts except Root
	 * Hub Status change and SOF interrupts.
	 */
	Set_OpReg16(USBINTR, ENABLE_ALL_INTRS);

	/* Test the SOF interrupt */
	if (uhci_wait_for_sof(uhcip) != USB_SUCCESS) {
		USB_DPRINTF_L0(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "No SOF interrupts have been received, this USB UHCI host"
		    " controller is unusable");
		mutex_exit(&uhcip->uhci_int_mutex);

		goto fail;
	}

	mutex_exit(&uhcip->uhci_int_mutex);

	/* This should be the last step which might fail during attaching */
	if (uhci_init_root_hub(uhcip) != USB_SUCCESS) {

		goto fail;
	}

	/* Display information in the banner */
	ddi_report_dev(dip);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
	    "uhci_attach successful");

	return (DDI_SUCCESS);

fail:
	USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
	    "failed to attach");

	(void) uhci_cleanup(uhcip);

	return (DDI_FAILURE);
}


/*
 * uhci_add_intrs:
 *
 * Register FIXED or MSI interrupts.
 */
static int
uhci_add_intrs(uhci_state_t	*uhcip,
		int		intr_type)
{
	int	actual, avail, intr_size, count = 0;
	int	i, flag, ret;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
	    "uhci_add_intrs: interrupt type 0x%x", intr_type);

	/* Get number of interrupts */
	ret = ddi_intr_get_nintrs(uhcip->uhci_dip, intr_type, &count);
	if ((ret != DDI_SUCCESS) || (count == 0)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "uhci_add_intrs: ddi_intr_get_nintrs() failure, "
		    "ret: %d, count: %d", ret, count);

		return (DDI_FAILURE);
	}

	/* Get number of available interrupts */
	ret = ddi_intr_get_navail(uhcip->uhci_dip, intr_type, &avail);
	if ((ret != DDI_SUCCESS) || (avail == 0)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "uhci_add_intrs: ddi_intr_get_navail() failure, "
		    "ret: %d, count: %d", ret, count);

		return (DDI_FAILURE);
	}

	if (avail < count) {
		USB_DPRINTF_L3(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "uhci_add_intrs: uhci_add_intrs: nintrs () "
		    "returned %d, navail returned %d\n", count, avail);
	}

	/* Allocate an array of interrupt handles */
	intr_size = count * sizeof (ddi_intr_handle_t);
	uhcip->uhci_htable = kmem_zalloc(intr_size, KM_SLEEP);

	flag = (intr_type == DDI_INTR_TYPE_MSI) ?
	    DDI_INTR_ALLOC_STRICT:DDI_INTR_ALLOC_NORMAL;

	/* call ddi_intr_alloc() */
	ret = ddi_intr_alloc(uhcip->uhci_dip, uhcip->uhci_htable,
	    intr_type, 0, count, &actual, flag);

	if ((ret != DDI_SUCCESS) || (actual == 0)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "uhci_add_intrs: ddi_intr_alloc() failed %d", ret);

		kmem_free(uhcip->uhci_htable, intr_size);

		return (DDI_FAILURE);
	}

	if (actual < count) {
		USB_DPRINTF_L3(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "uhci_add_intrs: Requested: %d, Received: %d\n",
		    count, actual);

		for (i = 0; i < actual; i++)
			(void) ddi_intr_free(uhcip->uhci_htable[i]);

		kmem_free(uhcip->uhci_htable, intr_size);

		return (DDI_FAILURE);
	}

	uhcip->uhci_intr_cnt = actual;

	if ((ret = ddi_intr_get_pri(uhcip->uhci_htable[0],
	    &uhcip->uhci_intr_pri)) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "uhci_add_intrs: ddi_intr_get_pri() failed %d", ret);

		for (i = 0; i < actual; i++)
			(void) ddi_intr_free(uhcip->uhci_htable[i]);

		kmem_free(uhcip->uhci_htable, intr_size);

		return (DDI_FAILURE);
	}

	USB_DPRINTF_L3(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
	    "uhci_add_intrs: Supported Interrupt priority 0x%x",
	    uhcip->uhci_intr_pri);

	/* Test for high level mutex */
	if (uhcip->uhci_intr_pri >= ddi_intr_get_hilevel_pri()) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "uhci_add_intrs: Hi level interrupt not supported");

		for (i = 0; i < actual; i++)
			(void) ddi_intr_free(uhcip->uhci_htable[i]);

		kmem_free(uhcip->uhci_htable, intr_size);

		return (DDI_FAILURE);
	}

	/* Initialize the mutex */
	mutex_init(&uhcip->uhci_int_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(uhcip->uhci_intr_pri));

	/* Call ddi_intr_add_handler() */
	for (i = 0; i < actual; i++) {
		if ((ret = ddi_intr_add_handler(uhcip->uhci_htable[i],
		    uhci_intr, (caddr_t)uhcip,
		    (caddr_t)(uintptr_t)i)) != DDI_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
			    "uhci_add_intrs: ddi_intr_add_handler() "
			    "failed %d", ret);

			for (i = 0; i < actual; i++)
				(void) ddi_intr_free(uhcip->uhci_htable[i]);

			mutex_destroy(&uhcip->uhci_int_mutex);
			kmem_free(uhcip->uhci_htable, intr_size);

			return (DDI_FAILURE);
		}
	}

	if ((ret = ddi_intr_get_cap(uhcip->uhci_htable[0],
	    &uhcip->uhci_intr_cap)) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "uhci_add_intrs: ddi_intr_get_cap() failed %d", ret);

		for (i = 0; i < actual; i++) {
			(void) ddi_intr_remove_handler(uhcip->uhci_htable[i]);
			(void) ddi_intr_free(uhcip->uhci_htable[i]);
		}

		mutex_destroy(&uhcip->uhci_int_mutex);
		kmem_free(uhcip->uhci_htable, intr_size);

		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * Function Name:	uhci_detach
 * Description:		Detach entry point - called by the Kernel.
 *			Deallocates all the memory
 *			Unregisters the interrupt handle and other resources.
 * Output:		DDI_SUCCESS / DDI_FAILURE
 */
static int
uhci_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	uhci_state_t	*uhcip = uhci_obtain_state(dip);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
	    "uhci_detach:");

	switch (cmd) {
	case DDI_DETACH:

		return (uhci_cleanup(uhcip) == USB_SUCCESS ?
		    DDI_SUCCESS : DDI_FAILURE);
	case DDI_SUSPEND:

		return (uhci_cpr_suspend(uhcip));
	default:

		return (DDI_FAILURE);
	}
}


/*
 * uhci_rem_intrs:
 *
 * Unregister FIXED or MSI interrupts
 */
static void
uhci_rem_intrs(uhci_state_t	*uhcip)
{
	int	i;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
	    "uhci_rem_intrs: interrupt type 0x%x", uhcip->uhci_intr_type);

	/* Disable all interrupts */
	if (uhcip->uhci_intr_cap & DDI_INTR_FLAG_BLOCK) {
		(void) ddi_intr_block_disable(uhcip->uhci_htable,
		    uhcip->uhci_intr_cnt);
	} else {
		for (i = 0; i < uhcip->uhci_intr_cnt; i++) {
			(void) ddi_intr_disable(uhcip->uhci_htable[i]);
		}
	}

	/* Call ddi_intr_remove_handler() */
	for (i = 0; i < uhcip->uhci_intr_cnt; i++) {
		(void) ddi_intr_remove_handler(uhcip->uhci_htable[i]);
		(void) ddi_intr_free(uhcip->uhci_htable[i]);
	}

	kmem_free(uhcip->uhci_htable,
	    uhcip->uhci_intr_cnt * sizeof (ddi_intr_handle_t));
}


/*
 * Function Name:	uhci_reset
 * Description:		Reset entry point - called by the Kernel
 *			on the way down.
 *			The Toshiba laptop has been observed to	hang
 *			on reboot when BIOS is set to suspend/resume.
 *			The resetting uhci on the way down solves the
 *			problem.
 * Output:		DDI_SUCCESS / DDI_FAILURE
 */
/* ARGSUSED */
static int
uhci_reset(dev_info_t *dip, ddi_reset_cmd_t cmd)
{
	uhci_state_t	*uhcip = uhci_obtain_state(dip);

	/* Disable all HC ED list processing */
	Set_OpReg16(USBINTR, DISABLE_ALL_INTRS);
	Set_OpReg16(USBCMD, 0);

	return (DDI_SUCCESS);
}


/*
 * uhci_info:
 */
/* ARGSUSED */
static int
uhci_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t		dev;
	int		instance;
	int		error = DDI_FAILURE;
	uhci_state_t	*uhcip;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		dev = (dev_t)arg;
		instance = UHCI_UNIT(dev);
		uhcip = ddi_get_soft_state(uhci_statep, instance);
		if (uhcip != NULL) {
			*result = (void *)uhcip->uhci_dip;
			if (*result != NULL) {
				error = DDI_SUCCESS;
			}
		} else {
			*result = NULL;
		}

		break;
	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		instance = UHCI_UNIT(dev);
		*result = (void *)(uintptr_t)instance;
		error = DDI_SUCCESS;

		break;
	default:
		break;
	}

	return (error);
}


/*
 * uhci_cleanup:
 *	Cleanup on attach failure or detach
 */
static int
uhci_cleanup(uhci_state_t *uhcip)
{
	USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl, "uhci_cleanup:");

	if (usba_hubdi_unbind_root_hub(uhcip->uhci_dip) != USB_SUCCESS) {

		return (USB_FAILURE);
	}

	mutex_enter(&uhcip->uhci_int_mutex);

	if (uhcip->uhci_cmd_timeout_id) {
		timeout_id_t timeout_id = uhcip->uhci_cmd_timeout_id;
		uhcip->uhci_cmd_timeout_id = 0;
		mutex_exit(&uhcip->uhci_int_mutex);
		(void) untimeout(timeout_id);
		mutex_enter(&uhcip->uhci_int_mutex);
	}

	uhci_uninit_ctlr(uhcip);

	mutex_exit(&uhcip->uhci_int_mutex);

	/* do interrupt cleanup */
	if (uhcip->uhci_htable) {
		uhci_rem_intrs(uhcip);
	}

	mutex_enter(&uhcip->uhci_int_mutex);

	usba_hcdi_unregister(uhcip->uhci_dip);

	uhci_unmap_regs(uhcip);

	uhci_free_pools(uhcip);

	mutex_exit(&uhcip->uhci_int_mutex);

	mutex_destroy(&uhcip->uhci_int_mutex);
	cv_destroy(&uhcip->uhci_cv_SOF);
	sema_destroy(&uhcip->uhci_ocsem);

	/* cleanup kstat structures */
	uhci_destroy_stats(uhcip);

	usba_free_hcdi_ops(uhcip->uhci_hcdi_ops);
	usb_free_log_hdl(uhcip->uhci_log_hdl);
	ddi_prop_remove_all(uhcip->uhci_dip);
	ddi_soft_state_free(uhci_statep, uhcip->uhci_instance);

	return (USB_SUCCESS);
}


/*
 * uhci_cpr_suspend
 */
static int
uhci_cpr_suspend(uhci_state_t	*uhcip)
{
	USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
	    "uhci_cpr_suspend:");

	/* Call into the root hub and suspend it */
	if (usba_hubdi_detach(uhcip->uhci_dip, DDI_SUSPEND) != DDI_SUCCESS) {

		return (DDI_FAILURE);
	}

	mutex_enter(&uhcip->uhci_int_mutex);

	/* Disable interrupts */
	Set_OpReg16(USBINTR, DISABLE_ALL_INTRS);

	mutex_exit(&uhcip->uhci_int_mutex);

	/* Wait for SOF time to handle the scheduled interrupt */
	delay(drv_usectohz(UHCI_TIMEWAIT));

	mutex_enter(&uhcip->uhci_int_mutex);
	/* Stop the Host Controller */
	Set_OpReg16(USBCMD, 0);

	/* Set Global Suspend bit */
	Set_OpReg16(USBCMD, USBCMD_REG_ENER_GBL_SUSPEND);

	/* Set host controller soft state to suspend */
	uhcip->uhci_hc_soft_state = UHCI_CTLR_SUSPEND_STATE;

	mutex_exit(&uhcip->uhci_int_mutex);

	return (USB_SUCCESS);
}


/*
 * uhci_cpr_cleanup:
 *
 * Cleanup uhci specific information across resuming.
 */
static void
uhci_cpr_cleanup(uhci_state_t	*uhcip)
{
	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	/* Reset software part of usb frame number */
	uhcip->uhci_sw_frnum = 0;
}


/*
 * uhci_cpr_resume
 */
static int
uhci_cpr_resume(uhci_state_t	*uhcip)
{
	USB_DPRINTF_L4(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
	    "uhci_cpr_resume: Restart the controller");

	mutex_enter(&uhcip->uhci_int_mutex);

	/* Cleanup uhci specific information across cpr */
	uhci_cpr_cleanup(uhcip);

	mutex_exit(&uhcip->uhci_int_mutex);

	/* Restart the controller */
	if (uhci_init_ctlr(uhcip) != DDI_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ATTA, uhcip->uhci_log_hdl,
		    "uhci_cpr_resume: uhci host controller resume failed ");

		return (DDI_FAILURE);
	}

	mutex_enter(&uhcip->uhci_int_mutex);

	/*
	 * Set HcInterruptEnable to enable all interrupts except Root
	 * Hub Status change and SOF interrupts.
	 */
	Set_OpReg16(USBINTR, ENABLE_ALL_INTRS);

	mutex_exit(&uhcip->uhci_int_mutex);

	/* Now resume the root hub */
	if (usba_hubdi_attach(uhcip->uhci_dip, DDI_RESUME) != DDI_SUCCESS) {

		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * uhci_intr:
 *	uhci interrupt handling routine.
 */
static uint_t
uhci_intr(caddr_t arg1, caddr_t arg2)
{
	ushort_t	intr_status, cmd_reg, intr_reg;
	uhci_state_t	*uhcip = (uhci_state_t *)arg1;

	USB_DPRINTF_L4(PRINT_MASK_INTR, uhcip->uhci_log_hdl,
	    "uhci_intr: Interrupt occurred, arg1 0x%p arg2 0x%p",
	    (void *)arg1, (void *)arg2);

	mutex_enter(&uhcip->uhci_int_mutex);

	/* Any interrupt is not handled for the suspended device. */
	if (uhcip->uhci_hc_soft_state == UHCI_CTLR_SUSPEND_STATE) {
		mutex_exit(&uhcip->uhci_int_mutex);

		return (DDI_INTR_UNCLAIMED);
	}

	/* Get the status of the interrupts */
	intr_status = Get_OpReg16(USBSTS);
	intr_reg = Get_OpReg16(USBINTR);

	USB_DPRINTF_L3(PRINT_MASK_INTR, uhcip->uhci_log_hdl,
	    "uhci_intr: intr_status = %x, intr_reg = %x",
	    intr_status, intr_reg);

	/*
	 * If uhci interrupts are all disabled, the driver should return
	 * unclaimed.
	 * HC Process Error and Host System Error interrupts cannot be
	 * disabled by intr register, and need to be judged separately.
	 */
	if (((intr_reg & ENABLE_ALL_INTRS) == 0) &&
	    ((intr_status & USBSTS_REG_HC_PROCESS_ERR) == 0) &&
	    ((intr_status & USBSTS_REG_HOST_SYS_ERR) == 0)) {

		USB_DPRINTF_L3(PRINT_MASK_INTR, uhcip->uhci_log_hdl,
		    "uhci_intr: interrupts disabled, unclaim");
		mutex_exit(&uhcip->uhci_int_mutex);

		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * If the intr is not from our controller, just return unclaimed.
	 * HCHalted status bit cannot generate interrupts and should be
	 * ignored.
	 */
	if (!(intr_status & UHCI_INTR_MASK)) {

		USB_DPRINTF_L3(PRINT_MASK_INTR, uhcip->uhci_log_hdl,
		    "uhci_intr: no interrupt status set, unclaim");
		mutex_exit(&uhcip->uhci_int_mutex);

		return (DDI_INTR_UNCLAIMED);
	}

	/* Update kstat values */
	uhci_do_intrs_stats(uhcip, intr_status);

	/* Acknowledge the interrupt */
	Set_OpReg16(USBSTS, intr_status);

	/*
	 * If uhci controller has not been initialized, just clear the
	 * interrupter status and return claimed.
	 */
	if (uhcip->uhci_hc_soft_state != UHCI_CTLR_OPERATIONAL_STATE) {

		USB_DPRINTF_L2(PRINT_MASK_INTR, uhcip->uhci_log_hdl,
		    "uhci_intr: uhci controller is not in the operational "
		    "state");
		mutex_exit(&uhcip->uhci_int_mutex);

		return (DDI_INTR_CLAIMED);
	}

	/*
	 * We configured the hw incorrectly, disable future interrupts.
	 */
	if ((intr_status & USBSTS_REG_HOST_SYS_ERR)) {
		USB_DPRINTF_L2(PRINT_MASK_INTR, uhcip->uhci_log_hdl,
		    "uhci_intr: Sys Err Disabling Interrupt");
		Set_OpReg16(USBINTR, DISABLE_ALL_INTRS);
		uhcip->uhci_hc_soft_state = UHCI_CTLR_ERROR_STATE;

		mutex_exit(&uhcip->uhci_int_mutex);

		return (DDI_INTR_CLAIMED);
	}

	/*
	 * Check whether a frame number overflow occurred.
	 * if so, update the sw frame number.
	 */
	uhci_isoc_update_sw_frame_number(uhcip);

	/*
	 * Check whether any commands got completed. If so, process them.
	 */
	uhci_process_submitted_td_queue(uhcip);

	/*
	 * This should not occur. It occurs only if a HC controller
	 * experiences internal problem.
	 */
	if (intr_status & USBSTS_REG_HC_HALTED) {
		USB_DPRINTF_L2(PRINT_MASK_INTR, uhcip->uhci_log_hdl,
		    "uhci_intr: Controller halted");
		cmd_reg = Get_OpReg16(USBCMD);
		Set_OpReg16(USBCMD, (cmd_reg | USBCMD_REG_HC_RUN));
	}

	/*
	 * Wake up all the threads which are waiting for the Start of Frame
	 */
	if (uhcip->uhci_cv_signal == B_TRUE) {
		cv_broadcast(&uhcip->uhci_cv_SOF);
		uhcip->uhci_cv_signal = B_FALSE;
	}

	mutex_exit(&uhcip->uhci_int_mutex);

	return (DDI_INTR_CLAIMED);
}


/*
 * uhci_process_submitted_td_queue:
 *    Traverse thru the submitted queue and process the completed ones.
 */
void
uhci_process_submitted_td_queue(uhci_state_t *uhcip)
{
	uhci_td_t		*head = uhcip->uhci_outst_tds_head;
	uhci_trans_wrapper_t	*tw;

	while (head != NULL) {
		if ((!(GetTD_status(uhcip, head) & UHCI_TD_ACTIVE)) &&
		    (head->tw->tw_claim == UHCI_NOT_CLAIMED)) {
			tw = head->tw;

			/*
			 * Call the corresponding handle_td routine
			 */
			(*tw->tw_handle_td)(uhcip, head);

			/* restart at the beginning again */
			head = uhcip->uhci_outst_tds_head;
		} else {
			head = head->outst_td_next;
		}
	}
}


/*
 * uhci_handle_intr_td:
 *     handles the completed interrupt transfer TD's.
 */
void
uhci_handle_intr_td(uhci_state_t *uhcip, uhci_td_t *td)
{
	usb_req_attrs_t		attrs;
	uint_t			bytes_xfered;
	usb_cr_t		usb_err;
	uhci_trans_wrapper_t	*tw = td->tw;
	uhci_pipe_private_t	*pp = tw->tw_pipe_private;
	usb_intr_req_t		*intr_reqp =
	    (usb_intr_req_t *)tw->tw_curr_xfer_reqp;
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_handle_intr_td: intr_reqp = 0x%p", (void *)intr_reqp);

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	/* set tw->tw_claim flag, so that nobody else works on this td. */
	tw->tw_claim = UHCI_INTR_HDLR_CLAIMED;

	/* Interrupt OUT */
	if (UHCI_XFER_DIR(&ph->p_ep) == USB_EP_DIR_OUT) {

		/* process errors first */
		usb_err = uhci_parse_td_error(uhcip, pp, td);

		/* get the actual xfered data size */
		bytes_xfered = GetTD_alen(uhcip, td);

		/* check data underrun error */
		if ((usb_err == USB_CR_OK) && (bytes_xfered !=
		    GetTD_mlen(uhcip, td))) {

			USB_DPRINTF_L2(PRINT_MASK_LISTS,
			    uhcip->uhci_log_hdl, "uhci_handle_intr_td:"
			    " Intr out pipe, data underrun occurred");

			usb_err = USB_CR_DATA_UNDERRUN;

		}

		bytes_xfered = (bytes_xfered == ZERO_LENGTH) ?
		    0 : bytes_xfered+1;
		tw->tw_bytes_xfered += bytes_xfered;
		uhci_do_byte_stats(uhcip, tw->tw_bytes_xfered,
		    ph->p_ep.bmAttributes, ph->p_ep.bEndpointAddress);


		/*
		 * If error occurred or all data xfered, delete the current td,
		 * free tw, do the callback. Otherwise wait for the next td.
		 */
		if (usb_err != USB_CR_OK) {

			USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
			    "uhci_handle_intr_td: Intr out pipe error");

			/* update the element pointer */
			SetQH32(uhcip, pp->pp_qh->element_ptr, GetTD32(
			    uhcip, tw->tw_hctd_tail->link_ptr));


		} else if (tw->tw_bytes_xfered == tw->tw_length) {

			/* all data xfered */
			USB_DPRINTF_L3(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
			    "uhci_handle_intr_td: Intr out pipe,"
			    " all data xfered");

		} else {

			/* remove the current td and wait for the next one. */
			uhci_delete_td(uhcip, td);
			tw->tw_claim = UHCI_NOT_CLAIMED;

			return;
		}

		uhci_delete_td(uhcip, td);
		uhci_hcdi_callback(uhcip, pp, ph, tw, usb_err);
		uhci_deallocate_tw(uhcip, tw->tw_pipe_private, tw);

		return;
	}

	/* Interrupt IN */

	/* Get the actual received data size */
	tw->tw_bytes_xfered = GetTD_alen(uhcip, td);
	if (tw->tw_bytes_xfered == ZERO_LENGTH) {
		tw->tw_bytes_xfered = 0;
	} else {
		tw->tw_bytes_xfered++;
	}

	/* process errors first */
	if (GetTD_status(uhcip, td) & TD_STATUS_MASK) {
		SetQH32(uhcip, pp->pp_qh->element_ptr,
		    GetTD32(uhcip, td->link_ptr));

		uhci_handle_intr_td_errors(uhcip, td, tw, pp);

		return;
	}

	/*
	 * Check for data underruns.
	 * For data underrun case, the host controller does not update
	 * element pointer. So, we update here.
	 */
	if (GetTD_alen(uhcip, td) != GetTD_mlen(uhcip, td)) {
		SetQH32(uhcip, pp->pp_qh->element_ptr,
		    GetTD32(uhcip, td->link_ptr));
	}

	/*
	 * Call uhci_sendup_td_message to send message upstream.
	 * The function uhci_sendup_td_message returns USB_NO_RESOURCES
	 * if allocb fails and also sends error message to upstream by
	 * calling USBA callback function. Under error conditions just
	 * drop the current message.
	 */

	/* Get the interrupt xfer attributes */
	attrs = intr_reqp->intr_attributes;

	/*
	 * Check usb flag whether USB_FLAGS_ONE_XFER flag is set
	 * and if so, free duplicate request.
	 */
	if (attrs & USB_ATTRS_ONE_XFER) {
		uhci_handle_one_xfer_completion(uhcip, USB_CR_OK, td);

		return;
	}

	/* save it temporarily */
	if (tw->tw_bytes_xfered != 0) {
		uhci_sendup_td_message(uhcip, USB_CR_OK, tw);
	}

	/* Clear the tw->tw_claim flag */
	tw->tw_claim = UHCI_NOT_CLAIMED;

	uhci_delete_td(uhcip, td);

	/* allocate another interrupt periodic resource */
	if (pp->pp_state == UHCI_PIPE_STATE_ACTIVE) {
		if (uhci_allocate_periodic_in_resource(uhcip, pp, tw, 0) !=
		    USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
			    "uhci_insert_intr_req: Interrupt request structure"
			    "allocation failed");

			uhci_hcdi_callback(uhcip, pp, ph,
			    tw, USB_CR_NO_RESOURCES);

			return;
		}

		/* Insert another interrupt TD */
		if (uhci_insert_hc_td(uhcip, 0,
		    tw->tw_length, pp, tw, PID_IN, attrs) != USB_SUCCESS) {

			uhci_deallocate_periodic_in_resource(uhcip, pp, tw);

			USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
			    "uhci_handle_intr_td: TD exhausted");

			uhci_hcdi_callback(uhcip, pp, ph,
			    tw, USB_CR_NO_RESOURCES);
		}
	}
}


/*
 * uhci_sendup_td_message:
 *
 * Get a message block and send the received message upstream.
 */
void
uhci_sendup_td_message(
	uhci_state_t		*uhcip,
	usb_cr_t		usb_err,
	uhci_trans_wrapper_t	*tw)
{
	mblk_t			*mp = NULL;
	size_t			length = 0;
	size_t			skip_len = 0;
	uchar_t			*buf;
	usb_opaque_t		curr_xfer_reqp = tw->tw_curr_xfer_reqp;
	uhci_pipe_private_t	*pp = tw->tw_pipe_private;
	usb_ep_descr_t		*ept = &pp->pp_pipe_handle->p_ep;

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_sendup_td_message: bytes transferred=0x%x, "
	    "bytes pending=0x%x",
	    tw->tw_bytes_xfered, tw->tw_bytes_pending);

	length = tw->tw_bytes_xfered;

	switch (UHCI_XFER_TYPE(ept)) {
	case USB_EP_ATTR_CONTROL:
		skip_len = UHCI_CTRL_EPT_MAX_SIZE; /* length to skip */
		mp = ((usb_ctrl_req_t *)curr_xfer_reqp)->ctrl_data;
		break;
	case USB_EP_ATTR_INTR:
		mp = ((usb_intr_req_t *)curr_xfer_reqp)->intr_data;
		break;
	case USB_EP_ATTR_BULK:
		mp = ((usb_bulk_req_t *)curr_xfer_reqp)->bulk_data;
		break;
	case USB_EP_ATTR_ISOCH:
		length = tw->tw_length;
		mp = ((usb_isoc_req_t *)curr_xfer_reqp)->isoc_data;
		break;
	default:
		break;
	}

	/* Copy the data into the mblk_t */
	buf = (uchar_t *)tw->tw_buf + skip_len;

	ASSERT(mp != NULL);

	/*
	 * Update kstat byte counts
	 * The control endpoints don't have direction bits so in
	 * order for control stats to be counted correctly an IN
	 * bit must be faked on a control read.
	 */
	uhci_do_byte_stats(uhcip, length, ept->bmAttributes,
	    (UHCI_XFER_TYPE(ept) == USB_EP_ATTR_CONTROL) ?
	    USB_EP_DIR_IN : ept->bEndpointAddress);

	if (length) {
		int rval, i;
		uchar_t *p = mp->b_rptr;

		if (UHCI_XFER_TYPE(ept) == USB_EP_ATTR_ISOCH) {
			/* Deal with isoc data by packets */
			for (i = 0; i < tw->tw_ncookies; i++) {
				rval = ddi_dma_sync(
				    tw->tw_isoc_bufs[i].dma_handle, 0,
				    tw->tw_isoc_bufs[i].length,
				    DDI_DMA_SYNC_FORCPU);
				ASSERT(rval == DDI_SUCCESS);

				ddi_rep_get8(tw->tw_isoc_bufs[i].mem_handle,
				    p, (uint8_t *)tw->tw_isoc_bufs[i].buf_addr,
				    tw->tw_isoc_bufs[i].length,
				    DDI_DEV_AUTOINCR);
				p += tw->tw_isoc_bufs[i].length;
			}
		} else {
			/* Sync the streaming buffer */
			rval = ddi_dma_sync(tw->tw_dmahandle, 0,
			    (skip_len + length), DDI_DMA_SYNC_FORCPU);
			ASSERT(rval == DDI_SUCCESS);

			/* Copy the data into the message */
			ddi_rep_get8(tw->tw_accesshandle,
			    mp->b_rptr, buf, length, DDI_DEV_AUTOINCR);
		}

		/* Increment the write pointer */
		mp->b_wptr += length;
	} else {
		USB_DPRINTF_L3(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "uhci_sendup_td_message: Zero length packet");
	}

	/* Do the callback */
	uhci_hcdi_callback(uhcip, pp, pp->pp_pipe_handle, tw, usb_err);
}


/*
 * uhci_handle_ctrl_td:
 *	Handle a control Transfer Descriptor (TD).
 */
void
uhci_handle_ctrl_td(uhci_state_t *uhcip, uhci_td_t *td)
{
	ushort_t		direction;
	ushort_t		bytes_for_xfer;
	ushort_t		bytes_xfered;
	ushort_t		MaxPacketSize;
	usb_cr_t		error;
	uhci_trans_wrapper_t	*tw = td->tw;
	uhci_pipe_private_t	*pp = tw->tw_pipe_private;
	usba_pipe_handle_data_t	*usb_pp = pp->pp_pipe_handle;
	usb_ep_descr_t		*eptd = &usb_pp->p_ep;
	usb_ctrl_req_t		*reqp = (usb_ctrl_req_t *)tw->tw_curr_xfer_reqp;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_handle_ctrl_td: pp = 0x%p tw = 0x%p td = 0x%p "
	    "state = 0x%x len = 0x%lx", (void *)pp, (void *)tw,
	    (void *)td, tw->tw_ctrl_state, tw->tw_length);

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	error = uhci_parse_td_error(uhcip, pp, td);

	/*
	 * In case of control transfers, the device can send NAK when it
	 * is busy. If a NAK is received, then send the status TD again.
	 */
	if (error != USB_CR_OK) {
		USB_DPRINTF_L3(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "uhci_handle_ctrl_td: Ctrl cmd failed, error = %x", error);

		SetQH32(uhcip, pp->pp_qh->element_ptr,
		    GetTD32(uhcip, td->link_ptr));
		uhci_delete_td(uhcip, td);

		/* Return number of bytes xfered */
		if (GetTD_alen(uhcip, td) != ZERO_LENGTH) {
			tw->tw_bytes_xfered = GetTD_alen(uhcip, td) + 1;
		}

		USB_DPRINTF_L3(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "uhci_handle_ctrl_td: Bytes transferred = %x",
		    tw->tw_bytes_xfered);

		if ((tw->tw_ctrl_state == DATA) &&
		    (tw->tw_direction == PID_IN)) {
			uhci_sendup_td_message(uhcip, error, tw);
		} else {
			uhci_hcdi_callback(uhcip, pp, usb_pp, tw, error);

			uhci_deallocate_tw(uhcip, pp, tw);
		}

		return;
	}

	/*
	 * A control transfer consists of three phases:
	 *	- Setup
	 *	- Data (optional)
	 *	- Status
	 *
	 * There is a TD per phase. A TD for a given phase isn't
	 * enqueued until the previous phase is finished.
	 */
	switch (tw->tw_ctrl_state) {
	case SETUP:
		/*
		 * Enqueue either the data or the status
		 * phase depending on the length.
		 */
		pp->pp_data_toggle = 1;
		uhci_delete_td(uhcip, td);

		/*
		 * If the length is 0, move to the status.
		 * If length is not 0, then we have some data
		 * to move on the bus to device either IN or OUT.
		 */
		if ((tw->tw_length - SETUP_SIZE) == 0) {
			/*
			 * There is no data stage,  then
			 * initiate status phase from the host.
			 */
			if ((uhci_insert_hc_td(uhcip, 0, 0, pp, tw, PID_IN,
			    reqp->ctrl_attributes)) != USB_SUCCESS) {
				USB_DPRINTF_L2(PRINT_MASK_LISTS,
				    uhcip->uhci_log_hdl,
				    "uhci_handle_ctrl_td: No resources");

				uhci_hcdi_callback(uhcip, pp, usb_pp, tw,
				    USB_CR_NO_RESOURCES);

				return;
			}

			tw->tw_ctrl_state = STATUS;
		} else {
			uint_t xx;

			/*
			 * Each USB device can send/receive 8/16/32/64
			 * depending on wMaxPacketSize's implementation.
			 * We need to insert 'N = Number of byte/
			 * MaxpktSize" TD's in the lattice to send/
			 * receive the data. Though the USB protocol
			 * allows to insert more than one TD in the same
			 * frame, we are inserting only one TD in one
			 * frame. This is bcos OHCI has seen some problem
			 * when multiple TD's are inserted at the same time.
			 */
			tw->tw_length -= UHCI_CTRL_EPT_MAX_SIZE;
			MaxPacketSize = eptd->wMaxPacketSize;

			/*
			 * We dont know the maximum packet size that
			 * the device can handle(MaxPAcketSize=0).
			 * In that case insert a data phase with
			 * eight bytes or less.
			 */
			if (MaxPacketSize == 0) {
				xx = (tw->tw_length > 8) ? 8 : tw->tw_length;
			} else {
				xx = (tw->tw_length > MaxPacketSize) ?
				    MaxPacketSize : tw->tw_length;
			}

			tw->tw_tmp = xx;

			/*
			 * Create the TD.  If this is an OUT
			 * transaction,  the data is already
			 * in the buffer of the TW.
			 * Get first 8 bytes of the command only.
			 */
			if ((uhci_insert_hc_td(uhcip,
			    UHCI_CTRL_EPT_MAX_SIZE, xx,
			    pp, tw, tw->tw_direction,
			    reqp->ctrl_attributes)) != USB_SUCCESS) {

				USB_DPRINTF_L2(PRINT_MASK_LISTS,
				    uhcip->uhci_log_hdl,
				    "uhci_handle_ctrl_td: No resources");

				uhci_hcdi_callback(uhcip, pp, usb_pp, tw,
				    USB_CR_NO_RESOURCES);

				return;
			}

			tw->tw_ctrl_state = DATA;
		}

		USB_DPRINTF_L3(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "Setup complete: pp 0x%p td 0x%p", (void *)pp, (void *)td);

		break;
	case DATA:
		uhci_delete_td(uhcip, td);

		MaxPacketSize = eptd->wMaxPacketSize;

		/*
		 * Decrement pending bytes and increment the total
		 * number bytes transferred by the actual number of bytes
		 * transferred in this TD. If the number of bytes transferred
		 * is less than requested, that means an underrun has
		 * occurred. Set the tw_tmp varible to indicate UNDER run.
		 */
		bytes_xfered = GetTD_alen(uhcip, td);
		if (bytes_xfered == ZERO_LENGTH) {
			bytes_xfered = 0;
		} else {
			bytes_xfered++;
		}

		tw->tw_bytes_pending -= bytes_xfered;
		tw->tw_bytes_xfered += bytes_xfered;

		if (bytes_xfered < tw->tw_tmp) {
			tw->tw_bytes_pending = 0;
			tw->tw_tmp = UHCI_UNDERRUN_OCCURRED;

			/*
			 * Controller does not update the queue head
			 * element pointer when a data underrun occurs.
			 */
			SetQH32(uhcip, pp->pp_qh->element_ptr,
			    GetTD32(uhcip, td->link_ptr));
		}

		if (bytes_xfered > tw->tw_tmp) {
			tw->tw_bytes_pending = 0;
			tw->tw_tmp = UHCI_OVERRUN_OCCURRED;
		}

		/*
		 * If no more bytes are pending, insert status
		 * phase. Otherwise insert data phase.
		 */
		if (tw->tw_bytes_pending) {
			bytes_for_xfer = (tw->tw_bytes_pending >
			    MaxPacketSize) ? MaxPacketSize :
			    tw->tw_bytes_pending;

			tw->tw_tmp = bytes_for_xfer;

			if ((uhci_insert_hc_td(uhcip,
			    UHCI_CTRL_EPT_MAX_SIZE + tw->tw_bytes_xfered,
			    bytes_for_xfer, pp, tw,
			    tw->tw_direction,
			    reqp->ctrl_attributes)) != USB_SUCCESS) {
				USB_DPRINTF_L2(PRINT_MASK_LISTS,
				    uhcip->uhci_log_hdl,
				    "uhci_handle_ctrl_td: No TD");

				uhci_hcdi_callback(uhcip, pp, usb_pp,
				    tw, USB_NO_RESOURCES);

				return;
			}

			tw->tw_ctrl_state = DATA;

			break;
		}

		pp->pp_data_toggle = 1;
		direction = (tw->tw_direction == PID_IN) ? PID_OUT : PID_IN;

		if ((uhci_insert_hc_td(uhcip, 0, 0, pp, tw, direction,
		    reqp->ctrl_attributes)) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
			    "uhci_handle_ctrl_td: TD exhausted");

			uhci_hcdi_callback(uhcip, pp, usb_pp, tw,
			    USB_NO_RESOURCES);

			return;
		}

		tw->tw_ctrl_state = STATUS;
		USB_DPRINTF_L3(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "Data complete: pp 0x%p td 0x%p", (void *)pp, (void *)td);

		break;
	case STATUS:
		/*
		 * Send the data to the client if it is a DATA IN,
		 * else send just return status for DATA OUT commnads.
		 * And set the tw_claim flag.
		 */
		tw->tw_claim = UHCI_INTR_HDLR_CLAIMED;

		if ((tw->tw_length != 0) && (tw->tw_direction == PID_IN)) {
			usb_req_attrs_t	attrs = ((usb_ctrl_req_t *)
			    tw->tw_curr_xfer_reqp)->ctrl_attributes;
			/*
			 * Call uhci_sendup_td_message to send message
			 * upstream. The function uhci_sendup_td_message
			 * returns USB_NO_RESOURCES if allocb fails and
			 * also sends error message to upstream by calling
			 * USBA callback function.
			 *
			 * Under error conditions just drop the current msg.
			 */
			if ((tw->tw_tmp == UHCI_UNDERRUN_OCCURRED) &&
			    (!(attrs & USB_ATTRS_SHORT_XFER_OK))) {
				error = USB_CR_DATA_UNDERRUN;
			} else if (tw->tw_tmp == UHCI_OVERRUN_OCCURRED) {
				error = USB_CR_DATA_OVERRUN;
			}
			uhci_sendup_td_message(uhcip, error, tw);

		} else {
			uhci_do_byte_stats(uhcip, tw->tw_length,
			    eptd->bmAttributes, eptd->bEndpointAddress);

			uhci_hcdi_callback(uhcip, pp, usb_pp, tw, USB_CR_OK);
		}

		USB_DPRINTF_L3(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "Status complete: pp 0x%p td 0x%p", (void *)pp, (void *)td);

		uhci_delete_td(uhcip, td);
		uhci_deallocate_tw(uhcip, pp, tw);

		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_INTR, uhcip->uhci_log_hdl,
		    "uhci_handle_ctrl_td: Bad control state");

		uhci_hcdi_callback(uhcip, pp, usb_pp, tw,
		    USB_CR_UNSPECIFIED_ERR);
	}
}


/*
 * uhci_handle_intr_td_errors:
 *	Handles the errors encountered for the interrupt transfers.
 */
static void
uhci_handle_intr_td_errors(uhci_state_t *uhcip, uhci_td_t *td,
    uhci_trans_wrapper_t *tw, uhci_pipe_private_t *pp)
{
	usb_cr_t		usb_err;
	usb_intr_req_t		*intr_reqp =
	    (usb_intr_req_t *)tw->tw_curr_xfer_reqp;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_handle_intr_td_errors: td = 0x%p tw = 0x%p",
	    (void *)td, (void *)tw);

	usb_err = uhci_parse_td_error(uhcip, pp, td);

	if (intr_reqp->intr_attributes & USB_ATTRS_ONE_XFER) {
		uhci_handle_one_xfer_completion(uhcip, usb_err, td);

		return;
	}

	uhci_delete_td(uhcip, td);
	uhci_sendup_td_message(uhcip, usb_err, tw);
	uhci_deallocate_tw(uhcip, tw->tw_pipe_private, tw);
}


/*
 * uhci_handle_one_xfer_completion:
 */
static void
uhci_handle_one_xfer_completion(
	uhci_state_t		*uhcip,
	usb_cr_t		usb_err,
	uhci_td_t		*td)
{
	uhci_trans_wrapper_t	*tw = td->tw;
	uhci_pipe_private_t	*pp = tw->tw_pipe_private;
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	usb_intr_req_t		*intr_reqp =
	    (usb_intr_req_t *)tw->tw_curr_xfer_reqp;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_handle_one_xfer_completion: td = 0x%p", (void *)td);

	ASSERT(intr_reqp->intr_attributes & USB_ATTRS_ONE_XFER);

	/* set state to idle */
	pp->pp_state = UHCI_PIPE_STATE_IDLE;

	((usb_intr_req_t *)(pp->pp_client_periodic_in_reqp))->
	    intr_data = ((usb_intr_req_t *)(tw->tw_curr_xfer_reqp))->intr_data;

	((usb_intr_req_t *)tw->tw_curr_xfer_reqp)->intr_data = NULL;

	/* now free duplicate current request */
	usb_free_intr_req((usb_intr_req_t *)tw->tw_curr_xfer_reqp);
	mutex_enter(&ph->p_mutex);
	ph->p_req_count--;
	mutex_exit(&ph->p_mutex);

	/* make client's request the current request */
	tw->tw_curr_xfer_reqp = pp->pp_client_periodic_in_reqp;
	pp->pp_client_periodic_in_reqp = NULL;

	uhci_sendup_td_message(uhcip, usb_err, tw);
	/* Clear the tw->tw_claim flag */
	tw->tw_claim = UHCI_NOT_CLAIMED;

	uhci_delete_td(uhcip, td);
	uhci_deallocate_tw(uhcip, pp, tw);
}


/*
 * uhci_parse_td_error
 *	Parses the Transfer Descriptors error
 */
usb_cr_t
uhci_parse_td_error(uhci_state_t *uhcip, uhci_pipe_private_t *pp, uhci_td_t *td)
{
	uint_t	status;

	status = GetTD_status(uhcip, td) & TD_STATUS_MASK;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_parse_td_error: status_bits=0x%x", status);

	if (UHCI_XFER_TYPE(&pp->pp_pipe_handle->p_ep) == USB_EP_ATTR_ISOCH) {

		return (USB_CR_OK);
	}

	if (!status) {

		return (USB_CR_OK);
	}

	USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
	    "uhci_parse_td_error: status_bits=0x%x", status);


	if (status & UHCI_TD_BITSTUFF_ERR) {

		return (USB_CR_BITSTUFFING);
	}

	if (status & UHCI_TD_CRC_TIMEOUT) {
		pp->pp_data_toggle = GetTD_dtogg(uhcip, td);

		USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "uhci_parse_td_error: timeout & data toggle reset; "
		    "data toggle: %x", pp->pp_data_toggle);

		return ((GetTD_PID(uhcip, td) == PID_IN) ? USB_CR_DEV_NOT_RESP :
		    USB_CR_TIMEOUT);
	}

	if (status & UHCI_TD_BABBLE_ERR) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "babble error");

		return (USB_CR_UNSPECIFIED_ERR);
	}

	if (status & UHCI_TD_DATA_BUFFER_ERR) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "buffer error");

		return ((GetTD_PID(uhcip, td) == PID_IN) ?
		    USB_CR_BUFFER_OVERRUN : USB_CR_BUFFER_UNDERRUN);
	}

	if (status & UHCI_TD_STALLED) {
		pp->pp_data_toggle = 0;
		USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "uhci_parse_td_error: stall; data toggle reset; "
		    "data toggle: %x", pp->pp_data_toggle);

		return (USB_CR_STALL);
	}

	if (status) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, uhcip->uhci_log_hdl,
		    "unspecified error=0x%x", status);
	}

	return (USB_CR_OK);
}


static dev_info_t *
uhci_get_dip(dev_t dev)
{
	int instance = UHCI_UNIT(dev);
	uhci_state_t *uhcip = ddi_get_soft_state(uhci_statep, instance);

	return (uhcip ? uhcip->uhci_dip : NULL);
}


/*
 * cb_ops entry points
 */
static int
uhci_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	dev_info_t *dip = uhci_get_dip(*devp);

	return (usba_hubdi_open(dip, devp, flags, otyp, credp));
}


static int
uhci_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	dev_info_t *dip = uhci_get_dip(dev);

	return (usba_hubdi_close(dip, dev, flag, otyp, credp));
}


static int
uhci_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp)
{
	dev_info_t *dip = uhci_get_dip(dev);

	return (usba_hubdi_ioctl(dip, dev, cmd, arg, mode, credp, rvalp));
}
