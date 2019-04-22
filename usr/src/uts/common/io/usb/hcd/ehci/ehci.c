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
 * EHCI Host Controller Driver (EHCI)
 *
 * The EHCI driver is a software driver which interfaces to the Universal
 * Serial Bus layer (USBA) and the Host Controller (HC). The interface to
 * the Host Controller is defined by the EHCI Host Controller Interface.
 *
 * This file contains code for Auto-configuration and HCDI entry points.
 *
 * NOTE:
 *
 * Currently EHCI driver does not support the following features
 *
 * - Alternate QTD for short xfer condition is only used in Bulk xfers.
 * - Frame Span Traversal Nodes (FSTN).
 * - Bandwidth allocation scheme needs to be updated for FSTN and USB2.0
 *   or High speed hub with multiple TT implementation. Currently bandwidth
 *   allocation scheme assumes one TT per USB2.0 or High speed hub.
 * - 64 bit addressing capability.
 * - Programmable periodic frame list size like 256, 512, 1024.
 *   It supports only 1024 periodic frame list size.
 */

#include <sys/usb/hcd/ehci/ehcid.h>
#include <sys/usb/hcd/ehci/ehci_xfer.h>
#include <sys/usb/hcd/ehci/ehci_intr.h>
#include <sys/usb/hcd/ehci/ehci_util.h>
#include <sys/usb/hcd/ehci/ehci_isoch.h>

/* Pointer to the state structure */
void *ehci_statep;

/* Number of instances */
#define	EHCI_INSTS	1

/* Debugging information */
uint_t ehci_errmask	= (uint_t)PRINT_MASK_ALL;
uint_t ehci_errlevel	= USB_LOG_L2;
uint_t ehci_instance_debug = (uint_t)-1;

/*
 * Tunable to ensure host controller goes off even if a keyboard is attached.
 */
int force_ehci_off = 1;

/* Enable all workarounds for VIA VT62x2 */
uint_t ehci_vt62x2_workaround = EHCI_VIA_WORKAROUNDS;

/*
 * EHCI Auto-configuration entry points.
 *
 * Device operations (dev_ops) entries function prototypes.
 *
 * We use the hub cbops since all nexus ioctl operations defined so far will
 * be executed by the root hub. The following are the Host Controller Driver
 * (HCD) entry points.
 *
 * the open/close/ioctl functions call the corresponding usba_hubdi_*
 * calls after looking up the dip thru the dev_t.
 */
static int	ehci_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int	ehci_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int	ehci_reset(dev_info_t *dip, ddi_reset_cmd_t cmd);
static int	ehci_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
    void *arg, void **result);

static int	ehci_open(dev_t	*devp, int flags, int otyp, cred_t *credp);
static int	ehci_close(dev_t dev, int flag, int otyp, cred_t *credp);
static int	ehci_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp);

int		usba_hubdi_root_hub_power(dev_info_t *dip, int comp, int level);
static int	ehci_quiesce(dev_info_t *dip);

static struct cb_ops ehci_cb_ops = {
	ehci_open,			/* EHCI */
	ehci_close,			/* Close */
	nodev,				/* Strategy */
	nodev,				/* Print */
	nodev,				/* Dump */
	nodev,				/* Read */
	nodev,				/* Write */
	ehci_ioctl,			/* Ioctl */
	nodev,				/* Devmap */
	nodev,				/* Mmap */
	nodev,				/* Segmap */
	nochpoll,			/* Poll */
	ddi_prop_op,			/* cb_prop_op */
	NULL,				/* Streamtab */
	D_NEW | D_MP | D_HOTPLUG	/* Driver compatibility flag */
};

static struct dev_ops ehci_ops = {
	DEVO_REV,			/* Devo_rev */
	0,				/* Refcnt */
	ehci_info,			/* Info */
	nulldev,			/* Identify */
	nulldev,			/* Probe */
	ehci_attach,			/* Attach */
	ehci_detach,			/* Detach */
	ehci_reset,			/* Reset */
	&ehci_cb_ops,			/* Driver operations */
	&usba_hubdi_busops,		/* Bus operations */
	usba_hubdi_root_hub_power,	/* Power */
	ehci_quiesce			/* Quiesce */
};

/*
 * The USBA library must be loaded for this driver.
 */
static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module. This one is a driver */
	"USB EHCI Driver",	/* Name of the module. */
	&ehci_ops,		/* Driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};


int
_init(void)
{
	int error;

	/* Initialize the soft state structures */
	if ((error = ddi_soft_state_init(&ehci_statep, sizeof (ehci_state_t),
	    EHCI_INSTS)) != 0) {
		return (error);
	}

	/* Install the loadable module */
	if ((error = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&ehci_statep);
	}

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

	if ((error = mod_remove(&modlinkage)) == 0) {

		/* Release per module resources */
		ddi_soft_state_fini(&ehci_statep);
	}

	return (error);
}


/*
 * EHCI Auto configuration entry points.
 */

/*
 * ehci_attach:
 *
 * Description: Attach entry point is called by the Kernel.
 *		Allocates resources for each EHCI host controller instance.
 *		Initializes the EHCI Host Controller.
 *
 * Return     : DDI_SUCCESS / DDI_FAILURE.
 */
static int
ehci_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance;
	ehci_state_t		*ehcip = NULL;
	usba_hcdi_register_args_t hcdi_args;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		ehcip = ehci_obtain_state(dip);

		return (ehci_cpr_resume(ehcip));
	default:
		return (DDI_FAILURE);
	}

	/* Get the instance and create soft state */
	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(ehci_statep, instance) != 0) {

		return (DDI_FAILURE);
	}

	ehcip = ddi_get_soft_state(ehci_statep, instance);
	if (ehcip == NULL) {

		return (DDI_FAILURE);
	}

	ehcip->ehci_flags = EHCI_ATTACH;

	ehcip->ehci_log_hdl = usb_alloc_log_hdl(dip, "ehci", &ehci_errlevel,
	    &ehci_errmask, &ehci_instance_debug, 0);

	ehcip->ehci_flags |= EHCI_ZALLOC;

	/* Set host controller soft state to initialization */
	ehcip->ehci_hc_soft_state = EHCI_CTLR_INIT_STATE;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehcip = 0x%p", (void *)ehcip);

	/* Save the dip and instance */
	ehcip->ehci_dip = dip;
	ehcip->ehci_instance = instance;

	/* Map the registers */
	if (ehci_map_regs(ehcip) != DDI_SUCCESS) {
		(void) ehci_cleanup(ehcip);

		return (DDI_FAILURE);
	}

	/* Get the ehci chip vendor and device id */
	ehcip->ehci_vendor_id = pci_config_get16(
	    ehcip->ehci_config_handle, PCI_CONF_VENID);
	ehcip->ehci_device_id = pci_config_get16(
	    ehcip->ehci_config_handle, PCI_CONF_DEVID);
	ehcip->ehci_rev_id = pci_config_get8(
	    ehcip->ehci_config_handle, PCI_CONF_REVID);

	/* Initialize the DMA attributes */
	ehci_set_dma_attributes(ehcip);

	/* Initialize kstat structures */
	ehci_create_stats(ehcip);

	/* Create the qtd and qh pools */
	if (ehci_allocate_pools(ehcip) != DDI_SUCCESS) {
		(void) ehci_cleanup(ehcip);

		return (DDI_FAILURE);
	}

	/* Initialize the isochronous resources */
	if (ehci_isoc_init(ehcip) != DDI_SUCCESS) {
		(void) ehci_cleanup(ehcip);

		return (DDI_FAILURE);
	}

	/* Register interrupts */
	if (ehci_register_intrs_and_init_mutex(ehcip) != DDI_SUCCESS) {
		(void) ehci_cleanup(ehcip);

		return (DDI_FAILURE);
	}

	mutex_enter(&ehcip->ehci_int_mutex);

	/* Initialize the controller */
	if (ehci_init_ctlr(ehcip, EHCI_NORMAL_INITIALIZATION) != DDI_SUCCESS) {
		mutex_exit(&ehcip->ehci_int_mutex);
		(void) ehci_cleanup(ehcip);

		return (DDI_FAILURE);
	}

	/*
	 * At this point, the hardware will be okay.
	 * Initialize the usba_hcdi structure
	 */
	ehcip->ehci_hcdi_ops = ehci_alloc_hcdi_ops(ehcip);

	mutex_exit(&ehcip->ehci_int_mutex);

	/*
	 * Make this HCD instance known to USBA
	 * (dma_attr must be passed for USBA busctl's)
	 */
	hcdi_args.usba_hcdi_register_version = HCDI_REGISTER_VERSION;
	hcdi_args.usba_hcdi_register_dip = dip;
	hcdi_args.usba_hcdi_register_ops = ehcip->ehci_hcdi_ops;
	hcdi_args.usba_hcdi_register_dma_attr = &ehcip->ehci_dma_attr;

	/*
	 * Priority and iblock_cookie are one and the same
	 * (However, retaining hcdi_soft_iblock_cookie for now
	 * assigning it w/ priority. In future all iblock_cookie
	 * could just go)
	 */
	hcdi_args.usba_hcdi_register_iblock_cookie =
	    (ddi_iblock_cookie_t)(uintptr_t)ehcip->ehci_intr_pri;

	if (usba_hcdi_register(&hcdi_args, 0) != DDI_SUCCESS) {
		(void) ehci_cleanup(ehcip);

		return (DDI_FAILURE);
	}

	ehcip->ehci_flags |= EHCI_USBAREG;

	mutex_enter(&ehcip->ehci_int_mutex);

	if ((ehci_init_root_hub(ehcip)) != USB_SUCCESS) {
		mutex_exit(&ehcip->ehci_int_mutex);
		(void) ehci_cleanup(ehcip);

		return (DDI_FAILURE);
	}

	mutex_exit(&ehcip->ehci_int_mutex);

	/* Finally load the root hub driver */
	if (ehci_load_root_hub_driver(ehcip) != USB_SUCCESS) {
		(void) ehci_cleanup(ehcip);

		return (DDI_FAILURE);
	}
	ehcip->ehci_flags |= EHCI_RHREG;

	/* Display information in the banner */
	ddi_report_dev(dip);

	mutex_enter(&ehcip->ehci_int_mutex);

	/* Reset the ehci initialization flag */
	ehcip->ehci_flags &= ~EHCI_ATTACH;

	/* Print the Host Control's Operational registers */
	ehci_print_caps(ehcip);
	ehci_print_regs(ehcip);

	(void) pci_report_pmcap(dip, PCI_PM_IDLESPEED, (void *)4000);

	mutex_exit(&ehcip->ehci_int_mutex);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_attach: dip = 0x%p done", (void *)dip);

	return (DDI_SUCCESS);
}


/*
 * ehci_detach:
 *
 * Description: Detach entry point is called by the Kernel.
 *		Deallocates all resource allocated.
 *		Unregisters the interrupt handler.
 *
 * Return     : DDI_SUCCESS / DDI_FAILURE
 */
int
ehci_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	ehci_state_t		*ehcip = ehci_obtain_state(dip);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl, "ehci_detach:");

	switch (cmd) {
	case DDI_DETACH:

		return (ehci_cleanup(ehcip));
	case DDI_SUSPEND:

		return (ehci_cpr_suspend(ehcip));
	default:

		return (DDI_FAILURE);
	}
}

/*
 * ehci_reset:
 *
 * Description:	Reset entry point - called by the Kernel
 *		on the way down.
 *		Toshiba Tecra laptop has been observed to hang
 *		on soft reboot. The resetting ehci on the way
 *		down solves the problem.
 *
 * Return	: DDI_SUCCESS / DDI_FAILURE
 */
/* ARGSUSED */
static int
ehci_reset(dev_info_t *dip, ddi_reset_cmd_t cmd)
{
#if defined(__sparc)
	/*
	 * Don't reset the host controller on SPARC, for OBP needs Solaris
	 * to continue to provide keyboard support after shutdown of SPARC,
	 * or the keyboard connected to a USB 2.0 port will not work after
	 * that. The incomplete reset problem on Toshiba Tecra laptop is
	 * specific to Tecra laptop or BIOS, not present on SPARC. The SPARC
	 * OBP guarantees good reset behavior during startup.
	 */
	return (DDI_SUCCESS);
#else
	ehci_state_t		*ehcip = ehci_obtain_state(dip);

	mutex_enter(&ehcip->ehci_int_mutex);

	/*
	 * To reset the host controller, the HCRESET bit should be set to one.
	 * Software should not set this bit to a one when the HCHalted bit in
	 * the USBSTS register is a zero. Attempting to reset an actively
	 * running host controller will result in undefined behavior.
	 * see EHCI SPEC. for more information.
	 */
	if (!(Get_OpReg(ehci_status) & EHCI_STS_HOST_CTRL_HALTED)) {

		/* Stop the EHCI host controller */
		Set_OpReg(ehci_command,
		    Get_OpReg(ehci_command) & ~EHCI_CMD_HOST_CTRL_RUN);
		/*
		 * When this bit is set to 0, the Host Controller completes the
		 * current and any actively pipelined transactions on the USB
		 * and then halts. The Host Controller must halt within 16
		 * micro-frames after software clears the Run bit.
		 * The HC Halted bit in the status register indicates when the
		 * Host Controller has finished its pending pipelined
		 * transactions and has entered the stopped state.
		 */
		drv_usecwait(EHCI_RESET_TIMEWAIT);
	}

	/* Reset the EHCI host controller */
	Set_OpReg(ehci_command,
	    Get_OpReg(ehci_command) | EHCI_CMD_HOST_CTRL_RESET);

	mutex_exit(&ehcip->ehci_int_mutex);

	return (DDI_SUCCESS);
#endif
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
ehci_quiesce(dev_info_t *dip)
{
	ehci_state_t		*ehcip = ehci_obtain_state(dip);

	if (ehcip == NULL)
		return (DDI_FAILURE);

#ifndef lint
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif
	/*
	 * To reset the host controller, the HCRESET bit should be set to one.
	 * Software should not set this bit to a one when the HCHalted bit in
	 * the USBSTS register is a zero. Attempting to reset an actively
	 * running host controller will result in undefined behavior.
	 * see EHCI SPEC. for more information.
	 */
	if (!(Get_OpReg(ehci_status) & EHCI_STS_HOST_CTRL_HALTED)) {

		/* Stop the EHCI host controller */
		Set_OpReg(ehci_command,
		    Get_OpReg(ehci_command) & ~EHCI_CMD_HOST_CTRL_RUN);
		/*
		 * When this bit is set to 0, the Host Controller completes the
		 * current and any actively pipelined transactions on the USB
		 * and then halts. The Host Controller must halt within 16
		 * micro-frames after software clears the Run bit.
		 * The HC Halted bit in the status register indicates when the
		 * Host Controller has finished its pending pipelined
		 * transactions and has entered the stopped state.
		 */
		drv_usecwait(EHCI_RESET_TIMEWAIT);
	}

	/* Reset the EHCI host controller */
	Set_OpReg(ehci_command,
	    Get_OpReg(ehci_command) | EHCI_CMD_HOST_CTRL_RESET);

#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif
	return (DDI_SUCCESS);
}


/*
 * ehci_info:
 */
/* ARGSUSED */
static int
ehci_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t			dev;
	ehci_state_t		*ehcip;
	int			instance;
	int			error = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		dev = (dev_t)arg;
		instance = EHCI_UNIT(dev);
		ehcip = ddi_get_soft_state(ehci_statep, instance);
		if (ehcip != NULL) {
			*result = (void *)ehcip->ehci_dip;
			if (*result != NULL) {
				error = DDI_SUCCESS;
			}
		} else {
			*result = NULL;
		}

		break;
	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		instance = EHCI_UNIT(dev);
		*result = (void *)(uintptr_t)instance;
		error = DDI_SUCCESS;
		break;
	default:
		break;
	}

	return (error);
}


/*
 * EHCI CB_OPS entry points.
 */
static dev_info_t *
ehci_get_dip(dev_t dev)
{
	int		instance = EHCI_UNIT(dev);
	ehci_state_t	*ehcip = ddi_get_soft_state(ehci_statep, instance);

	if (ehcip) {

		return (ehcip->ehci_dip);
	} else {

		return (NULL);
	}
}


static int
ehci_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	dev_info_t	*dip = ehci_get_dip(*devp);

	return (usba_hubdi_open(dip, devp, flags, otyp, credp));
}


static int
ehci_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	dev_info_t	*dip = ehci_get_dip(dev);

	return (usba_hubdi_close(dip, dev, flag, otyp, credp));
}


static int
ehci_ioctl(dev_t dev, int cmd, intptr_t	arg, int mode, cred_t *credp,
    int *rvalp)
{
	dev_info_t	*dip = ehci_get_dip(dev);

	return (usba_hubdi_ioctl(dip,
	    dev, cmd, arg, mode, credp, rvalp));
}

/*
 * EHCI Interrupt Handler entry point.
 */

/*
 * ehci_intr:
 *
 * EHCI (EHCI) interrupt handling routine.
 */
uint_t
ehci_intr(caddr_t arg1, caddr_t arg2)
{
	uint_t			intr;
	ehci_state_t		*ehcip = (void *)arg1;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_intr: Interrupt occurred, arg1 0x%p arg2 0x%p",
	    (void *)arg1, (void *)arg2);

	/* Get the ehci global mutex */
	mutex_enter(&ehcip->ehci_int_mutex);

	/* Any interrupt is not handled for the suspended device. */
	if (ehcip->ehci_hc_soft_state == EHCI_CTLR_SUSPEND_STATE) {
		mutex_exit(&ehcip->ehci_int_mutex);

		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * Now process the actual ehci interrupt events  that caused
	 * invocation of this ehci interrupt handler.
	 */
	intr = (Get_OpReg(ehci_status) & Get_OpReg(ehci_interrupt));

	/* Update kstat values */
	ehci_do_intrs_stats(ehcip, intr);

	/*
	 * We could have gotten a spurious interrupts. If so, do not
	 * claim it.  This is quite  possible on some  architectures
	 * where more than one PCI slots share the IRQs.  If so, the
	 * associated driver's interrupt routine may get called even
	 * if the interrupt is not meant for them.
	 *
	 * By unclaiming the interrupt, the other driver gets chance
	 * to service its interrupt.
	 */
	if (!intr) {
		mutex_exit(&ehcip->ehci_int_mutex);

		return (DDI_INTR_UNCLAIMED);
	}

	/* Acknowledge the interrupt */
	Set_OpReg(ehci_status, intr);

	if (ehcip->ehci_hc_soft_state == EHCI_CTLR_ERROR_STATE) {
		mutex_exit(&ehcip->ehci_int_mutex);

		return (DDI_INTR_CLAIMED);
	}

	USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "Interrupt status 0x%x", intr);

	/*
	 * If necessary broadcast that an interrupt has occured.  This
	 * is only necessary during controller init.
	 */
	if (ehcip->ehci_flags & EHCI_CV_INTR) {
		ehcip->ehci_flags &= ~EHCI_CV_INTR;
		cv_broadcast(&ehcip->ehci_async_schedule_advance_cv);
	}

	/* Check for Frame List Rollover */
	if (intr & EHCI_INTR_FRAME_LIST_ROLLOVER) {
		USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_intr: Frame List Rollover");

		ehci_handle_frame_list_rollover(ehcip);

		/* VIA VT6202 looses EHCI_INTR_USB interrupts, workaround. */
		if ((ehcip->ehci_vendor_id == PCI_VENDOR_VIA) &&
		    (ehci_vt62x2_workaround & EHCI_VIA_LOST_INTERRUPTS)) {
			ehcip->ehci_missed_intr_sts |= EHCI_INTR_USB;
		}
	}

	/* Check for Advance on Asynchronous Schedule */
	if (intr & EHCI_INTR_ASYNC_ADVANCE) {
		USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_intr: Asynchronous Schedule Advance Notification");

		/* Disable async list advance interrupt */
		Set_OpReg(ehci_interrupt,
		    (Get_OpReg(ehci_interrupt) & ~EHCI_INTR_ASYNC_ADVANCE));

		/*
		 * Call cv_broadcast on every this interrupt to wakeup
		 * all the threads that are waiting the async list advance
		 * event.
		 */
		cv_broadcast(&ehcip->ehci_async_schedule_advance_cv);
	}

	/* Always process completed itds */
	ehci_traverse_active_isoc_list(ehcip);

	/*
	 * Check for any USB transaction completion notification. Also
	 * process any missed USB transaction completion interrupts.
	 */
	if ((intr & EHCI_INTR_USB) || (intr & EHCI_INTR_USB_ERROR) ||
	    (ehcip->ehci_missed_intr_sts & EHCI_INTR_USB) ||
	    (ehcip->ehci_missed_intr_sts & EHCI_INTR_USB_ERROR)) {

		USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_intr: USB Transaction Completion Notification");

		/* Clear missed interrupts */
		if (ehcip->ehci_missed_intr_sts) {
			ehcip->ehci_missed_intr_sts = 0;
		}

		/* Process completed qtds */
		ehci_traverse_active_qtd_list(ehcip);
	}

	/* Process endpoint reclamation list */
	if (ehcip->ehci_reclaim_list) {
		ehci_handle_endpoint_reclaimation(ehcip);
	}

	/* Check for Host System Error */
	if (intr & EHCI_INTR_HOST_SYSTEM_ERROR) {
		USB_DPRINTF_L2(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_intr: Unrecoverable error");

		ehci_handle_ue(ehcip);
	}

	/*
	 * Read interrupt status register to make sure that any PIO
	 * store to clear the ISR has made it on the PCI bus before
	 * returning from its interrupt handler.
	 */
	(void) Get_OpReg(ehci_status);

	/* Release the ehci global mutex */
	mutex_exit(&ehcip->ehci_int_mutex);

	USB_DPRINTF_L4(PRINT_MASK_INTR,  ehcip->ehci_log_hdl,
	    "Interrupt handling completed");

	return (DDI_INTR_CLAIMED);
}


/*
 * EHCI HCDI entry points
 *
 * The Host Controller Driver Interfaces (HCDI) are the software interfaces
 * between the Universal Serial Bus Layer (USBA) and the Host Controller
 * Driver (HCD). The HCDI interfaces or entry points are subject to change.
 */

/*
 * ehci_hcdi_pipe_open:
 *
 * Member of HCD Ops structure and called during client specific pipe open
 * Add the pipe to the data structure representing the device and allocate
 * bandwidth for the pipe if it is a interrupt or isochronous endpoint.
 */
int
ehci_hcdi_pipe_open(
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags)
{
	ehci_state_t		*ehcip = ehci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	usb_ep_descr_t		*epdt = &ph->p_ep;
	int			rval, error = USB_SUCCESS;
	int			kmflag = (flags & USB_FLAGS_SLEEP) ?
	    KM_SLEEP : KM_NOSLEEP;
	uchar_t			smask = 0;
	uchar_t			cmask = 0;
	uint_t			pnode = 0;
	ehci_pipe_private_t	*pp;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
	    "ehci_hcdi_pipe_open: addr = 0x%x, ep%d",
	    ph->p_usba_device->usb_addr,
	    epdt->bEndpointAddress & USB_EP_NUM_MASK);

	mutex_enter(&ehcip->ehci_int_mutex);
	rval = ehci_state_is_operational(ehcip);
	mutex_exit(&ehcip->ehci_int_mutex);

	if (rval != USB_SUCCESS) {

		return (rval);
	}

	/*
	 * Check and handle root hub pipe open.
	 */
	if (ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) {

		mutex_enter(&ehcip->ehci_int_mutex);
		error = ehci_handle_root_hub_pipe_open(ph, flags);
		mutex_exit(&ehcip->ehci_int_mutex);

		return (error);
	}

	/*
	 * Opening of other pipes excluding root hub pipe are
	 * handled below. Check whether pipe is already opened.
	 */
	if (ph->p_hcd_private) {
		USB_DPRINTF_L2(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
		    "ehci_hcdi_pipe_open: Pipe is already opened");

		return (USB_FAILURE);
	}

	/*
	 * A portion of the bandwidth is reserved for the non-periodic
	 * transfers, i.e control and bulk transfers in each of one
	 * millisecond frame period & usually it will be 20% of frame
	 * period. Hence there is no need to check for the available
	 * bandwidth before adding the control or bulk endpoints.
	 *
	 * There is a need to check for the available bandwidth before
	 * adding the periodic transfers, i.e interrupt & isochronous,
	 * since all these periodic transfers are guaranteed transfers.
	 * Usually 80% of the total frame time is reserved for periodic
	 * transfers.
	 */
	if (EHCI_PERIODIC_ENDPOINT(epdt)) {

		mutex_enter(&ehcip->ehci_int_mutex);
		mutex_enter(&ph->p_mutex);

		error = ehci_allocate_bandwidth(ehcip,
		    ph, &pnode, &smask, &cmask);

		if (error != USB_SUCCESS) {

			USB_DPRINTF_L2(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
			    "ehci_hcdi_pipe_open: Bandwidth allocation failed");

			mutex_exit(&ph->p_mutex);
			mutex_exit(&ehcip->ehci_int_mutex);

			return (error);
		}

		mutex_exit(&ph->p_mutex);
		mutex_exit(&ehcip->ehci_int_mutex);
	}

	/* Create the HCD pipe private structure */
	pp = kmem_zalloc(sizeof (ehci_pipe_private_t), kmflag);

	/*
	 * Return failure if ehci pipe private
	 * structure allocation fails.
	 */
	if (pp == NULL) {

		mutex_enter(&ehcip->ehci_int_mutex);

		/* Deallocate bandwidth */
		if (EHCI_PERIODIC_ENDPOINT(epdt)) {

			mutex_enter(&ph->p_mutex);
			ehci_deallocate_bandwidth(ehcip,
			    ph, pnode, smask, cmask);
			mutex_exit(&ph->p_mutex);
		}

		mutex_exit(&ehcip->ehci_int_mutex);

		return (USB_NO_RESOURCES);
	}

	mutex_enter(&ehcip->ehci_int_mutex);

	/* Save periodic nodes */
	pp->pp_pnode = pnode;

	/* Save start and complete split mask values */
	pp->pp_smask = smask;
	pp->pp_cmask = cmask;

	/* Create prototype for xfer completion condition variable */
	cv_init(&pp->pp_xfer_cmpl_cv, NULL, CV_DRIVER, NULL);

	/* Set the state of pipe as idle */
	pp->pp_state = EHCI_PIPE_STATE_IDLE;

	/* Store a pointer to the pipe handle */
	pp->pp_pipe_handle = ph;

	mutex_enter(&ph->p_mutex);

	/* Store the pointer in the pipe handle */
	ph->p_hcd_private = (usb_opaque_t)pp;

	/* Store a copy of the pipe policy */
	bcopy(&ph->p_policy, &pp->pp_policy, sizeof (usb_pipe_policy_t));

	mutex_exit(&ph->p_mutex);

	/* Allocate the host controller endpoint descriptor */
	pp->pp_qh = ehci_alloc_qh(ehcip, ph, EHCI_INTERRUPT_MODE_FLAG);

	/* Initialize the halting flag */
	pp->pp_halt_state = EHCI_HALT_STATE_FREE;

	/* Create prototype for halt completion condition variable */
	cv_init(&pp->pp_halt_cmpl_cv, NULL, CV_DRIVER, NULL);

	/* Isoch does not use QH, so ignore this */
	if ((pp->pp_qh == NULL) && !(EHCI_ISOC_ENDPOINT(epdt))) {
		ASSERT(pp->pp_qh == NULL);

		USB_DPRINTF_L2(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
		    "ehci_hcdi_pipe_open: QH allocation failed");

		mutex_enter(&ph->p_mutex);

		/* Deallocate bandwidth */
		if (EHCI_PERIODIC_ENDPOINT(epdt)) {

			ehci_deallocate_bandwidth(ehcip,
			    ph, pnode, smask, cmask);
		}

		/* Destroy the xfer completion condition variable */
		cv_destroy(&pp->pp_xfer_cmpl_cv);

		/*
		 * Deallocate the hcd private portion
		 * of the pipe handle.
		 */
		kmem_free(ph->p_hcd_private, sizeof (ehci_pipe_private_t));

		/*
		 * Set the private structure in the
		 * pipe handle equal to NULL.
		 */
		ph->p_hcd_private = NULL;

		mutex_exit(&ph->p_mutex);
		mutex_exit(&ehcip->ehci_int_mutex);

		return (USB_NO_RESOURCES);
	}

	/*
	 * Isoch does not use QH so no need to
	 * restore data toggle or insert QH
	 */
	if (!(EHCI_ISOC_ENDPOINT(epdt))) {
		/* Restore the data toggle information */
		ehci_restore_data_toggle(ehcip, ph);
	}

	/*
	 * Insert the endpoint onto the host controller's
	 * appropriate endpoint list. The host controller
	 * will not schedule this endpoint and will not have
	 * any QTD's to process.  It will also update the pipe count.
	 */
	ehci_insert_qh(ehcip, ph);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
	    "ehci_hcdi_pipe_open: ph = 0x%p", (void *)ph);

	ehcip->ehci_open_pipe_count++;

	mutex_exit(&ehcip->ehci_int_mutex);

	return (USB_SUCCESS);
}


/*
 * ehci_hcdi_pipe_close:
 *
 * Member of HCD Ops structure and called during the client  specific pipe
 * close. Remove the pipe and the data structure representing the device.
 * Deallocate  bandwidth for the pipe if it is a interrupt or isochronous
 * endpoint.
 */
/* ARGSUSED */
int
ehci_hcdi_pipe_close(
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags)
{
	ehci_state_t		*ehcip = ehci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	usb_ep_descr_t		*eptd = &ph->p_ep;
	int			error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
	    "ehci_hcdi_pipe_close: addr = 0x%x, ep%d",
	    ph->p_usba_device->usb_addr,
	    eptd->bEndpointAddress & USB_EP_NUM_MASK);

	/* Check and handle root hub pipe close */
	if (ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) {

		mutex_enter(&ehcip->ehci_int_mutex);
		error = ehci_handle_root_hub_pipe_close(ph);
		mutex_exit(&ehcip->ehci_int_mutex);

		return (error);
	}

	ASSERT(ph->p_hcd_private != NULL);

	mutex_enter(&ehcip->ehci_int_mutex);

	/* Set pipe state to pipe close */
	pp->pp_state = EHCI_PIPE_STATE_CLOSE;

	ehci_pipe_cleanup(ehcip, ph);

	/*
	 * Remove the endpoint descriptor from Host
	 * Controller's appropriate endpoint list.
	 */
	ehci_remove_qh(ehcip, pp, B_TRUE);

	/* Deallocate bandwidth */
	if (EHCI_PERIODIC_ENDPOINT(eptd)) {

		mutex_enter(&ph->p_mutex);
		ehci_deallocate_bandwidth(ehcip, ph, pp->pp_pnode,
		    pp->pp_smask, pp->pp_cmask);
		mutex_exit(&ph->p_mutex);
	}

	mutex_enter(&ph->p_mutex);

	/* Destroy the xfer completion condition variable */
	cv_destroy(&pp->pp_xfer_cmpl_cv);


	/* Destory halt completion condition variable */
	cv_destroy(&pp->pp_halt_cmpl_cv);

	/*
	 * Deallocate the hcd private portion
	 * of the pipe handle.
	 */
	kmem_free(ph->p_hcd_private, sizeof (ehci_pipe_private_t));
	ph->p_hcd_private = NULL;

	mutex_exit(&ph->p_mutex);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
	    "ehci_hcdi_pipe_close: ph = 0x%p", (void *)ph);

	ehcip->ehci_open_pipe_count--;

	mutex_exit(&ehcip->ehci_int_mutex);

	return (error);
}


/*
 * ehci_hcdi_pipe_reset:
 */
/* ARGSUSED */
int
ehci_hcdi_pipe_reset(
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		usb_flags)
{
	ehci_state_t		*ehcip = ehci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	int			error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
	    "ehci_hcdi_pipe_reset:");

	/*
	 * Check and handle root hub pipe reset.
	 */
	if (ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) {

		error = ehci_handle_root_hub_pipe_reset(ph, usb_flags);
		return (error);
	}

	mutex_enter(&ehcip->ehci_int_mutex);

	/* Set pipe state to pipe reset */
	pp->pp_state = EHCI_PIPE_STATE_RESET;

	ehci_pipe_cleanup(ehcip, ph);

	mutex_exit(&ehcip->ehci_int_mutex);

	return (error);
}

/*
 * ehci_hcdi_pipe_reset_data_toggle:
 */
void
ehci_hcdi_pipe_reset_data_toggle(
	usba_pipe_handle_data_t	*ph)
{
	ehci_state_t		*ehcip = ehci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
	    "ehci_hcdi_pipe_reset_data_toggle:");

	mutex_enter(&ehcip->ehci_int_mutex);

	mutex_enter(&ph->p_mutex);
	usba_hcdi_set_data_toggle(ph->p_usba_device, ph->p_ep.bEndpointAddress,
	    DATA0);
	mutex_exit(&ph->p_mutex);

	Set_QH(pp->pp_qh->qh_status,
	    Get_QH(pp->pp_qh->qh_status) & (~EHCI_QH_STS_DATA_TOGGLE));
	mutex_exit(&ehcip->ehci_int_mutex);

}

/*
 * ehci_hcdi_pipe_ctrl_xfer:
 */
int
ehci_hcdi_pipe_ctrl_xfer(
	usba_pipe_handle_data_t	*ph,
	usb_ctrl_req_t		*ctrl_reqp,
	usb_flags_t		usb_flags)
{
	ehci_state_t		*ehcip = ehci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	int			rval;
	int			error = USB_SUCCESS;
	ehci_trans_wrapper_t	*tw;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
	    "ehci_hcdi_pipe_ctrl_xfer: ph = 0x%p reqp = 0x%p flags = %x",
	    (void *)ph, (void *)ctrl_reqp, usb_flags);

	mutex_enter(&ehcip->ehci_int_mutex);
	rval = ehci_state_is_operational(ehcip);
	mutex_exit(&ehcip->ehci_int_mutex);

	if (rval != USB_SUCCESS) {

		return (rval);
	}

	/*
	 * Check and handle root hub control request.
	 */
	if (ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) {

		error = ehci_handle_root_hub_request(ehcip, ph, ctrl_reqp);

		return (error);
	}

	mutex_enter(&ehcip->ehci_int_mutex);

	/*
	 *  Check whether pipe is in halted state.
	 */
	if (pp->pp_state == EHCI_PIPE_STATE_ERROR) {

		USB_DPRINTF_L2(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
		    "ehci_hcdi_pipe_ctrl_xfer: "
		    "Pipe is in error state, need pipe reset to continue");

		mutex_exit(&ehcip->ehci_int_mutex);

		return (USB_FAILURE);
	}

	/* Allocate a transfer wrapper */
	if ((tw = ehci_allocate_ctrl_resources(ehcip, pp, ctrl_reqp,
	    usb_flags)) == NULL) {

		error = USB_NO_RESOURCES;
	} else {
		/* Insert the qtd's on the endpoint */
		ehci_insert_ctrl_req(ehcip, ph, ctrl_reqp, tw, usb_flags);
	}

	mutex_exit(&ehcip->ehci_int_mutex);

	return (error);
}


/*
 * ehci_hcdi_bulk_transfer_size:
 *
 * Return maximum bulk transfer size
 */

/* ARGSUSED */
int
ehci_hcdi_bulk_transfer_size(
	usba_device_t	*usba_device,
	size_t		*size)
{
	ehci_state_t	*ehcip = ehci_obtain_state(
	    usba_device->usb_root_hub_dip);
	int		rval;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
	    "ehci_hcdi_bulk_transfer_size:");

	mutex_enter(&ehcip->ehci_int_mutex);
	rval = ehci_state_is_operational(ehcip);
	mutex_exit(&ehcip->ehci_int_mutex);

	if (rval != USB_SUCCESS) {

		return (rval);
	}

	/* VIA VT6202 may not handle bigger xfers well, workaround. */
	if ((ehcip->ehci_vendor_id == PCI_VENDOR_VIA) &&
	    (ehci_vt62x2_workaround & EHCI_VIA_REDUCED_MAX_BULK_XFER_SIZE)) {
		*size = EHCI_VIA_MAX_BULK_XFER_SIZE;
	} else {
		*size = EHCI_MAX_BULK_XFER_SIZE;
	}

	return (USB_SUCCESS);
}


/*
 * ehci_hcdi_pipe_bulk_xfer:
 */
int
ehci_hcdi_pipe_bulk_xfer(
	usba_pipe_handle_data_t	*ph,
	usb_bulk_req_t		*bulk_reqp,
	usb_flags_t		usb_flags)
{
	ehci_state_t		*ehcip = ehci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	int			rval, error = USB_SUCCESS;
	ehci_trans_wrapper_t	*tw;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
	    "ehci_hcdi_pipe_bulk_xfer: ph = 0x%p reqp = 0x%p flags = %x",
	    (void *)ph, (void *)bulk_reqp, usb_flags);

	mutex_enter(&ehcip->ehci_int_mutex);
	rval = ehci_state_is_operational(ehcip);

	if (rval != USB_SUCCESS) {
		mutex_exit(&ehcip->ehci_int_mutex);

		return (rval);
	}

	/*
	 *  Check whether pipe is in halted state.
	 */
	if (pp->pp_state == EHCI_PIPE_STATE_ERROR) {

		USB_DPRINTF_L2(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
		    "ehci_hcdi_pipe_bulk_xfer:"
		    "Pipe is in error state, need pipe reset to continue");

		mutex_exit(&ehcip->ehci_int_mutex);

		return (USB_FAILURE);
	}

	/* Allocate a transfer wrapper */
	if ((tw = ehci_allocate_bulk_resources(ehcip, pp, bulk_reqp,
	    usb_flags)) == NULL) {

		error = USB_NO_RESOURCES;
	} else {
		/* Add the QTD into the Host Controller's bulk list */
		ehci_insert_bulk_req(ehcip, ph, bulk_reqp, tw, usb_flags);
	}

	mutex_exit(&ehcip->ehci_int_mutex);

	return (error);
}


/*
 * ehci_hcdi_pipe_intr_xfer:
 */
int
ehci_hcdi_pipe_intr_xfer(
	usba_pipe_handle_data_t	*ph,
	usb_intr_req_t		*intr_reqp,
	usb_flags_t		usb_flags)
{
	ehci_state_t		*ehcip = ehci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	int			pipe_dir, rval, error = USB_SUCCESS;
	ehci_trans_wrapper_t	*tw;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
	    "ehci_hcdi_pipe_intr_xfer: ph = 0x%p reqp = 0x%p flags = %x",
	    (void *)ph, (void *)intr_reqp, usb_flags);

	mutex_enter(&ehcip->ehci_int_mutex);
	rval = ehci_state_is_operational(ehcip);

	if (rval != USB_SUCCESS) {
		mutex_exit(&ehcip->ehci_int_mutex);

		return (rval);
	}

	/* Get the pipe direction */
	pipe_dir = ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK;

	if (pipe_dir == USB_EP_DIR_IN) {
		error = ehci_start_periodic_pipe_polling(ehcip, ph,
		    (usb_opaque_t)intr_reqp, usb_flags);
	} else {
		/* Allocate transaction resources */
		if ((tw = ehci_allocate_intr_resources(ehcip, ph,
		    intr_reqp, usb_flags)) == NULL) {

			error = USB_NO_RESOURCES;
		} else {
			ehci_insert_intr_req(ehcip,
			    (ehci_pipe_private_t *)ph->p_hcd_private,
			    tw, usb_flags);
		}
	}

	mutex_exit(&ehcip->ehci_int_mutex);

	return (error);
}

/*
 * ehci_hcdi_pipe_stop_intr_polling()
 */
int
ehci_hcdi_pipe_stop_intr_polling(
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags)
{
	ehci_state_t		*ehcip = ehci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	int			error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
	    "ehci_hcdi_pipe_stop_intr_polling: ph = 0x%p fl = 0x%x",
	    (void *)ph, flags);

	mutex_enter(&ehcip->ehci_int_mutex);

	error = ehci_stop_periodic_pipe_polling(ehcip, ph, flags);

	mutex_exit(&ehcip->ehci_int_mutex);

	return (error);
}


/*
 * ehci_hcdi_get_current_frame_number:
 *
 * Get the current usb frame number.
 * Return whether the request is handled successfully.
 */
int
ehci_hcdi_get_current_frame_number(
	usba_device_t		*usba_device,
	usb_frame_number_t	*frame_number)
{
	ehci_state_t		*ehcip = ehci_obtain_state(
	    usba_device->usb_root_hub_dip);
	int			rval;

	ehcip = ehci_obtain_state(usba_device->usb_root_hub_dip);

	mutex_enter(&ehcip->ehci_int_mutex);
	rval = ehci_state_is_operational(ehcip);

	if (rval != USB_SUCCESS) {
		mutex_exit(&ehcip->ehci_int_mutex);

		return (rval);
	}

	*frame_number = ehci_get_current_frame_number(ehcip);

	mutex_exit(&ehcip->ehci_int_mutex);

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
	    "ehci_hcdi_get_current_frame_number: "
	    "Current frame number 0x%llx", (unsigned long long)(*frame_number));

	return (rval);
}


/*
 * ehci_hcdi_get_max_isoc_pkts:
 *
 * Get maximum isochronous packets per usb isochronous request.
 * Return whether the request is handled successfully.
 */
int
ehci_hcdi_get_max_isoc_pkts(
	usba_device_t	*usba_device,
	uint_t		*max_isoc_pkts_per_request)
{
	ehci_state_t		*ehcip = ehci_obtain_state(
	    usba_device->usb_root_hub_dip);
	int			rval;

	mutex_enter(&ehcip->ehci_int_mutex);
	rval = ehci_state_is_operational(ehcip);
	mutex_exit(&ehcip->ehci_int_mutex);

	if (rval != USB_SUCCESS) {

		return (rval);
	}

	*max_isoc_pkts_per_request = EHCI_MAX_ISOC_PKTS_PER_XFER;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
	    "ehci_hcdi_get_max_isoc_pkts: maximum isochronous"
	    "packets per usb isochronous request = 0x%x",
	    *max_isoc_pkts_per_request);

	return (rval);
}


/*
 * ehci_hcdi_pipe_isoc_xfer:
 */
int
ehci_hcdi_pipe_isoc_xfer(
	usba_pipe_handle_data_t	*ph,
	usb_isoc_req_t		*isoc_reqp,
	usb_flags_t		usb_flags)
{
	ehci_state_t		*ehcip = ehci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);

	int			pipe_dir, rval;
	ehci_isoc_xwrapper_t	*itw;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
	    "ehci_hcdi_pipe_isoc_xfer: ph = 0x%p reqp = 0x%p flags = 0x%x",
	    (void *)ph, (void *)isoc_reqp, usb_flags);

	mutex_enter(&ehcip->ehci_int_mutex);
	rval = ehci_state_is_operational(ehcip);

	if (rval != USB_SUCCESS) {
		mutex_exit(&ehcip->ehci_int_mutex);

		return (rval);
	}

	/* Get the isochronous pipe direction */
	pipe_dir = ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK;

	if (pipe_dir == USB_EP_DIR_IN) {
		rval = ehci_start_periodic_pipe_polling(ehcip, ph,
		    (usb_opaque_t)isoc_reqp, usb_flags);
	} else {
		/* Allocate transaction resources */
		if ((itw = ehci_allocate_isoc_resources(ehcip, ph,
		    isoc_reqp, usb_flags)) == NULL) {
			rval = USB_NO_RESOURCES;
		} else {
			rval = ehci_insert_isoc_req(ehcip,
			    (ehci_pipe_private_t *)ph->p_hcd_private,
			    itw, usb_flags);
		}
	}

	mutex_exit(&ehcip->ehci_int_mutex);

	return (rval);
}


/*
 * ehci_hcdi_pipe_stop_isoc_polling()
 */
/*ARGSUSED*/
int
ehci_hcdi_pipe_stop_isoc_polling(
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags)
{
	ehci_state_t		*ehcip = ehci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	int			rval;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
	    "ehci_hcdi_pipe_stop_isoc_polling: ph = 0x%p fl = 0x%x",
	    (void *)ph, flags);

	mutex_enter(&ehcip->ehci_int_mutex);
	rval = ehci_state_is_operational(ehcip);

	if (rval != USB_SUCCESS) {
		mutex_exit(&ehcip->ehci_int_mutex);

		return (rval);
	}

	rval = ehci_stop_periodic_pipe_polling(ehcip, ph, flags);

	mutex_exit(&ehcip->ehci_int_mutex);

	return (rval);
}
