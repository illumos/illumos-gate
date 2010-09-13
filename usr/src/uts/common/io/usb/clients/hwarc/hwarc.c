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
 * UWB HWA Radio Controller driver.
 *
 *
 * The device has four states (refer to usbai.h):
 *	USB_DEV_ONLINE: In action or ready for action.
 *	USB_DEV_DISCONNECTED: Hotplug removed, or device not present/correct on
 *		resume (CPR).
 *	USB_DEV_SUSPENDED: Device has been suspended along with the system.
 *	USB_DEV_PWRED_DOWN: Device has been powered down.  (Note that this
 *		driver supports only two power states, powered down and
 *		full power.)
 *
 * In order to avoid race conditions between driver entry points,
 * access to the device is serialized.	Race conditions are an issue in
 * particular between disconnect event callbacks, detach, power, open
 * and data transfer callbacks.  The functions hwarc_serialize/release_access
 * are implemented for this purpose.
 *
 * Mutexes should never be held when making calls into USBA or when
 * sleeping.
 *
 * pm_busy_component and pm_idle_component mark the device as busy or idle to
 * the system.	These functions are paired, and are called only from code
 * bracketed by hwarc_serialize_access and hwarc_release_access.
 *
 */

#define	USBDRV_MAJOR_VER	2
#define	USBDRV_MINOR_VER	0

#include <sys/strsun.h>
#include <sys/usb/usba.h>
#include <sys/usb/clients/hwarc/hwarc.h>



uint_t		hwarc_errlevel		= 4;
static uint_t	hwarc_errmask		= (uint_t)PRINT_MASK_ALL;
static uint_t	hwarc_instance_debug 	= (uint_t)-1;

static char	*name		= "hwarc";	/* Driver name, used all over */


/* Function Prototypes */
static int	hwarc_attach(dev_info_t *, ddi_attach_cmd_t);
static int	hwarc_detach(dev_info_t *, ddi_detach_cmd_t);
static int	hwarc_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	hwarc_cleanup(dev_info_t *, hwarc_state_t *);
static int	hwarc_open(dev_t *, int, int, cred_t *);
static int	hwarc_close(dev_t, int, int, cred_t *);
static int 	hwarc_send_cmd(uwb_dev_handle_t, mblk_t *, uint16_t);
static int	hwarc_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int	hwarc_disconnect_callback(dev_info_t *);
static int	hwarc_reconnect_callback(dev_info_t *);
static void	hwarc_restore_device_state(dev_info_t *, hwarc_state_t *);
static int	hwarc_cpr_suspend(dev_info_t *);
static void	hwarc_cpr_resume(dev_info_t *);
static int	hwarc_open_intr_pipe(hwarc_state_t *);
static void	hwarc_close_intr_pipe(hwarc_state_t *);
static void	hwarc_pm_busy_component(hwarc_state_t *);
static void	hwarc_pm_idle_component(hwarc_state_t *);
static int	hwarc_power(dev_info_t *, int, int);
static int	hwarc_serialize_access(hwarc_state_t *, boolean_t);
static void	hwarc_release_access(hwarc_state_t *);
static int	hwarc_reset_device(hwarc_state_t *);
static int	hwarc_init_phy(hwarc_state_t *);


static int	hwarc_start_polling(hwarc_state_t *, usb_pipe_handle_t);


_NOTE(SCHEME_PROTECTS_DATA("unique per call", usb_ctrl_req))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", usb_intr_req))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", buf))

/* module loading stuff */
struct cb_ops hwarc_cb_ops = {
	hwarc_open,		/* open  */
	hwarc_close,		/* close */
	nodev,			/* strategy */
	nulldev,		/* print */
	nulldev,		/* dump */
	nodev,			/* read */
	nodev,			/* write */
	hwarc_ioctl,		/* ioctl */
	nulldev,		/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* streamtab  */
	D_MP
};

static struct dev_ops hwarc_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	hwarc_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	hwarc_attach,		/* attach */
	hwarc_detach,		/* detach */
	nodev,			/* reset */
	&hwarc_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	hwarc_power,		/* power */
	ddi_quiesce_not_needed, /* devo_quiesce */
};

static struct modldrv hwarc_modldrv =	{
	&mod_driverops,
	"USB HWA Radio Controller driver",
	&hwarc_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&hwarc_modldrv,
	NULL
};

/* Soft state structures */
#define	HWARC_INITIAL_SOFT_SPACE	1
static void *hwarc_statep;


/* Module-wide initialization routine */
int
_init(void)
{
	int rval;

	if ((rval = ddi_soft_state_init(&hwarc_statep,
	    sizeof (hwarc_state_t), HWARC_INITIAL_SOFT_SPACE)) != 0) {

		return (rval);
	}

	if ((rval = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&hwarc_statep);
	}

	return (rval);
}


/* Module-wide tear-down routine */
int
_fini(void)
{
	int rval;

	if ((rval = mod_remove(&modlinkage)) != 0) {

		return (rval);
	}

	ddi_soft_state_fini(&hwarc_statep);

	return (rval);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * hwarc_info:
 *	Get minor number, soft state structure, etc.
 */
/*ARGSUSED*/
static int
hwarc_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
			void *arg, void **result)
{
	hwarc_state_t	*hrcp;
	int error = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = NULL;
		if ((hrcp = ddi_get_soft_state(hwarc_statep,
		    getminor((dev_t)arg))) != NULL) {
			*result = hrcp->hrc_dip;
		}
		error = (*result)? DDI_SUCCESS:DDI_FAILURE;

		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)getminor((dev_t)arg);
		error = DDI_SUCCESS;
		break;
	default:
		break;
	}

	return (error);
}



/*
 * hwarc_init_power_mgmt:
 *	Initialize power management and remote wakeup functionality.
 *	No mutex is necessary in this function as it's called only by attach.
 */
static void
hwarc_init_power_mgmt(hwarc_state_t *hrcp)
{
	hwarc_power_t	*hrcpm = NULL;
	uint_t		pwr_states;

	USB_DPRINTF_L4(PRINT_MASK_PM, hrcp->hrc_log_hdl,
	    "init_power_mgmt enter");

	/* Put online before PM init as can get power managed afterward. */
	hrcp->hrc_dev_state = USB_DEV_ONLINE;

	/* Allocate the state structure */
	hrcpm = kmem_zalloc(sizeof (hwarc_power_t), KM_SLEEP);

	hrcpm->hrc_state 		= hrcp;
	hrcpm->hrc_pm_capabilities 	= 0;
	hrcpm->hrc_current_power 	= USB_DEV_OS_FULL_PWR;


	if (usb_create_pm_components(hrcp->hrc_dip, &pwr_states) ==
	    USB_SUCCESS) {
		hrcpm->hrc_pwr_states 	= (uint8_t)pwr_states;

		if (usb_handle_remote_wakeup(hrcp->hrc_dip,
		    USB_REMOTE_WAKEUP_ENABLE) == USB_SUCCESS) {
			hrcpm->hrc_wakeup_enabled = 1;
		} else {
			USB_DPRINTF_L2(PRINT_MASK_PM,
			    hrcp->hrc_log_hdl, "hwarc_init_power_mgmt:"
			    " remote wakeup not supported");
		}

	} else {
		USB_DPRINTF_L2(PRINT_MASK_PM, hrcp->hrc_log_hdl,
		    "hwarc_init_power_mgmt:created PM components failed");
	}
	mutex_enter(&hrcp->hrc_mutex);
	hrcp->hrc_pm = hrcpm;
	hwarc_pm_busy_component(hrcp);
	mutex_exit(&hrcp->hrc_mutex);

	(void) pm_raise_power(
	    hrcp->hrc_dip, 0, USB_DEV_OS_FULL_PWR);

	USB_DPRINTF_L4(PRINT_MASK_PM, hrcp->hrc_log_hdl,
	    "hwarc_init_power_mgmt: end");
}


/*
 * hwarc_destroy_power_mgmt:
 *	Shut down and destroy power management and remote wakeup functionality.
 */
static void
hwarc_destroy_power_mgmt(hwarc_state_t *hrcp)
{
	hwarc_power_t	*pm;

	USB_DPRINTF_L4(PRINT_MASK_PM, hrcp->hrc_log_hdl,
	    "destroy_power_mgmt enter");

	mutex_enter(&hrcp->hrc_mutex);

	if ((pm = hrcp->hrc_pm) == NULL) {
		USB_DPRINTF_L3(PRINT_MASK_PM, hrcp->hrc_log_hdl,
		    "hwarc_destroy_power_mgmt:pm not supported");
		goto done;
	}

	if (hrcp->hrc_dev_state == USB_DEV_DISCONNECTED) {
		USB_DPRINTF_L3(PRINT_MASK_PM, hrcp->hrc_log_hdl,
		    "hwarc_destroy_power_mgmt:device disconnected");
		goto done;
	}

	hwarc_pm_busy_component(hrcp);

	mutex_exit(&hrcp->hrc_mutex);

	if (pm->hrc_wakeup_enabled) {

		/* First bring the device to full power */
		(void) pm_raise_power(hrcp->hrc_dip, 0, USB_DEV_OS_FULL_PWR);
		if (usb_handle_remote_wakeup(hrcp->hrc_dip,
		    USB_REMOTE_WAKEUP_DISABLE) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_PM,
			    hrcp->hrc_log_hdl, "hwarc_destroy_power_mgmt: "
			    "Error disabling rmt wakeup");
		}

	}

	/*
	 * Since remote wakeup is disabled now,
	 * no one can raise power
	 * and get to device once power is lowered here.
	 */
	(void) pm_lower_power(hrcp->hrc_dip, 0, USB_DEV_OS_PWR_OFF);

	mutex_enter(&hrcp->hrc_mutex);

	hwarc_pm_idle_component(hrcp);

done:
	if (pm) {
		kmem_free(pm, sizeof (hwarc_power_t));

		hrcp->hrc_pm = NULL;
	}
	mutex_exit(&hrcp->hrc_mutex);
}


static void
hwarc_pm_busy_component(hwarc_state_t *hrcp)
{
	ASSERT(mutex_owned(&hrcp->hrc_mutex));

	USB_DPRINTF_L4(PRINT_MASK_PM, hrcp->hrc_log_hdl,
	    "hwarc_pm_busy_component: enter");
	if (hrcp->hrc_pm == NULL) {
		USB_DPRINTF_L4(PRINT_MASK_PM, hrcp->hrc_log_hdl,
		    "hwarc_pm_busy_component: pm not supported, return");

		return;
	}

	hrcp->hrc_pm->hrc_pm_busy++;

	mutex_exit(&hrcp->hrc_mutex);
	if (pm_busy_component(hrcp->hrc_dip, 0) !=
	    DDI_SUCCESS) {
		mutex_enter(&hrcp->hrc_mutex);
		USB_DPRINTF_L3(PRINT_MASK_PM, hrcp->hrc_log_hdl,
		    "hwarc_pm_busy_component: pm busy fail, hrc_pm_busy=%d",
		    hrcp->hrc_pm->hrc_pm_busy);

		hrcp->hrc_pm->hrc_pm_busy--;
		mutex_exit(&hrcp->hrc_mutex);
	}
	mutex_enter(&hrcp->hrc_mutex);

	USB_DPRINTF_L4(PRINT_MASK_PM, hrcp->hrc_log_hdl,
	    "hwarc_pm_busy_component: exit");
}


static void
hwarc_pm_idle_component(hwarc_state_t *hrcp)
{
	ASSERT(mutex_owned(&hrcp->hrc_mutex));
	USB_DPRINTF_L4(PRINT_MASK_PM, hrcp->hrc_log_hdl,
	    "hwarc_pm_idle_component: enter");

	if (hrcp->hrc_pm == NULL) {
		USB_DPRINTF_L4(PRINT_MASK_PM, hrcp->hrc_log_hdl,
		    "hwarc_pm_idle_component: pm not supported");

		return;
	}

	mutex_exit(&hrcp->hrc_mutex);
	if (pm_idle_component(hrcp->hrc_dip, 0) == DDI_SUCCESS) {
		mutex_enter(&hrcp->hrc_mutex);
		ASSERT(hrcp->hrc_pm->hrc_pm_busy > 0);
		hrcp->hrc_pm->hrc_pm_busy--;
		mutex_exit(&hrcp->hrc_mutex);
	}
	mutex_enter(&hrcp->hrc_mutex);

	USB_DPRINTF_L3(PRINT_MASK_PM, hrcp->hrc_log_hdl,
	    "hwarc_pm_idle_component: %d", hrcp->hrc_pm->hrc_pm_busy);

}


/*
 * hwarc_pwrlvl0:
 * Functions to handle power transition for OS levels 0 -> 3
 */
static int
hwarc_pwrlvl0(hwarc_state_t *hrcp)
{
	int rval;

	USB_DPRINTF_L3(PRINT_MASK_PM, hrcp->hrc_log_hdl,
	    "hwarc_pwrlvl0, dev_state: %x", hrcp->hrc_dev_state);

	switch (hrcp->hrc_dev_state) {
		case USB_DEV_ONLINE:
			/* Deny the powerdown request if the device is busy */
			if (hrcp->hrc_pm->hrc_pm_busy != 0) {
				USB_DPRINTF_L2(PRINT_MASK_PM, hrcp->hrc_log_hdl,
				    "hwarc_pwrlvl0: hrc_pm_busy");

				return (USB_FAILURE);
			}

			/* Close the interrupt pipe */
			mutex_exit(&hrcp->hrc_mutex);
			hwarc_close_intr_pipe(hrcp);
			mutex_enter(&hrcp->hrc_mutex);

			/* Issue USB D3 command to the device here */
			rval = usb_set_device_pwrlvl3(hrcp->hrc_dip);
			ASSERT(rval == USB_SUCCESS);

			hrcp->hrc_dev_state = USB_DEV_PWRED_DOWN;
			hrcp->hrc_pm->hrc_current_power = USB_DEV_OS_PWR_OFF;

		/* FALLTHRU */
		case USB_DEV_DISCONNECTED:
		case USB_DEV_SUSPENDED:

			return (USB_SUCCESS);

		case USB_DEV_PWRED_DOWN:
		default:
			USB_DPRINTF_L2(PRINT_MASK_PM, hrcp->hrc_log_hdl,
			    "hwarc_pwrlvl0: illegal dev state");

			return (USB_FAILURE);
	}
}


/*
 * hwarc_pwrlvl1:
 *	Functions to handle power transition to OS levels -> 2
 */
static int
hwarc_pwrlvl1(hwarc_state_t *hrcp)
{
	int	rval;

	USB_DPRINTF_L4(PRINT_MASK_PM, hrcp->hrc_log_hdl, "hwarc_pwrlvl1");

	/* Issue USB D2 command to the device here */
	rval = usb_set_device_pwrlvl2(hrcp->hrc_dip);
	ASSERT(rval == USB_SUCCESS);

	return (USB_FAILURE);
}


/*
 * hwarc_pwrlvl2:
 *	Functions to handle power transition to OS levels -> 1
 */
static int
hwarc_pwrlvl2(hwarc_state_t *hrcp)
{
	int	rval;

	USB_DPRINTF_L3(PRINT_MASK_PM, hrcp->hrc_log_hdl,
	    "hwarc_pwrlvl2, dev_stat=%d", hrcp->hrc_dev_state);

	/* Issue USB D1 command to the device here */
	rval = usb_set_device_pwrlvl1(hrcp->hrc_dip);
	ASSERT(rval == USB_SUCCESS);

	return (USB_FAILURE);
}


/*
 * hwarc_pwrlvl3:
 *	Functions to handle power transition to OS level -> 0
 */
static int
hwarc_pwrlvl3(hwarc_state_t *hrcp)
{

	USB_DPRINTF_L3(PRINT_MASK_PM, hrcp->hrc_log_hdl,
	    "hwarc_pwrlvl3, dev_stat=%d", hrcp->hrc_dev_state);

	switch (hrcp->hrc_dev_state) {
		case USB_DEV_PWRED_DOWN:
			/* Issue USB D0 command to the device here */
			(void) usb_set_device_pwrlvl0(hrcp->hrc_dip);

			mutex_exit(&hrcp->hrc_mutex);
			if (hwarc_open_intr_pipe(hrcp) != USB_SUCCESS) {
				mutex_enter(&hrcp->hrc_mutex);

				return (USB_FAILURE);
			}
			mutex_enter(&hrcp->hrc_mutex);

			/* Todo: Reset device or not */
			hrcp->hrc_dev_state 		= USB_DEV_ONLINE;
			hrcp->hrc_pm->hrc_current_power = USB_DEV_OS_FULL_PWR;

			/* FALLTHRU */
		case USB_DEV_ONLINE:
			/* we are already in full power */
			/* FALLTHRU */
		case USB_DEV_DISCONNECTED:
		case USB_DEV_SUSPENDED:
			/*
			 * PM framework tries to put us in full power
			 * during system shutdown. If we are disconnected/cpr'ed
			 * return success anyways
			 */

			return (USB_SUCCESS);

		default:
			USB_DPRINTF_L2(PRINT_MASK_PM, hrcp->hrc_log_hdl,
			    "hwarc_pwrlvl3: illegal dev state");

			return (USB_FAILURE);
	}
}

/* Init dev inst */
static void
hwarc_init_devinst(dev_info_t *dip, hwarc_state_t *hrcp)
{
	char	*devinst;
	int	devinstlen;

	hrcp->hrc_dip	  = dip;
	hrcp->hrc_log_hdl = usb_alloc_log_hdl(dip,
	    "hwarc", &hwarc_errlevel,
	    &hwarc_errmask, &hwarc_instance_debug, 0);

	devinst = kmem_zalloc(USB_MAXSTRINGLEN, KM_SLEEP);
	devinstlen = snprintf(devinst, USB_MAXSTRINGLEN, "%s%d: ",
	    ddi_driver_name(dip), ddi_get_instance(dip));

	hrcp->hrc_devinst = kmem_zalloc(devinstlen + 1, KM_SLEEP);
	(void) strncpy(hrcp->hrc_devinst, devinst, devinstlen);

	kmem_free(devinst, USB_MAXSTRINGLEN);
}

/* init endpoints */
static int
hwarc_init_ep(dev_info_t *dip, hwarc_state_t *hrcp)
{
	int status = USB_SUCCESS;
	usb_ep_data_t	*ep_datap;
	if ((status = usb_client_attach(dip, USBDRV_VERSION, 0)) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hrcp->hrc_log_hdl,
		    "hwarc_init_ep: usb_client_attach failed"
		    " error code = %d", status);
		goto done;
	}

	if ((status = usb_get_dev_data(dip, &hrcp->hrc_reg, USB_PARSE_LVL_ALL,
	    0)) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hrcp->hrc_log_hdl,
		    "hwarc_init_ep: usb_get_dev_data failed"
		    "error code = %d", status);
		goto done;
	}
	hrcp->hrc_if_descr =
	    &hrcp->hrc_reg->dev_curr_cfg->cfg_if[hrcp->hrc_reg->dev_curr_if];
	hrcp->hrc_default_ph = hrcp->hrc_reg->dev_default_ph;

	/*
	 * Get the descriptor for an intr pipe at alt 0 of current interface.
	 * This will be used later to open the pipe.
	 */
	if ((ep_datap = usb_lookup_ep_data(dip, hrcp->hrc_reg,
	    hrcp->hrc_reg->dev_curr_if, 0, 0,
	    USB_EP_ATTR_INTR, USB_EP_DIR_IN)) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hrcp->hrc_log_hdl,
		    "hwarc_init_ep: Error getting intr endpoint descriptor");
		status = USB_FAILURE;
		goto done;
	}
	hrcp->hrc_intr_ep_descr = ep_datap->ep_descr;

done:

	return (status);
}
/* init mutex */
static void
hwarc_init_mutex(hwarc_state_t *hrcp) {
	mutex_init(&hrcp->hrc_mutex, NULL, MUTEX_DRIVER,
	    hrcp->hrc_reg->dev_iblock_cookie);

	cv_init(&hrcp->hrc_serial_cv, NULL, CV_DRIVER, NULL);
	hrcp->hrc_serial_inuse = B_FALSE;

	hrcp->hrc_locks_initialized = B_TRUE;
}
/*
 * hwarc_attach:
 *	Attach or resume.
 *
 *	For attach, initialize state and device, including:
 *		state variables, locks, device node
 *		device registration with system
 *		power management, hotplugging
 *	For resume, restore device and state
 */
static int
hwarc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance = ddi_get_instance(dip);
	hwarc_state_t		*hrcp = NULL;

	switch (cmd) {
		case DDI_ATTACH:
			break;

		case DDI_RESUME:
			hwarc_cpr_resume(dip);
			/*
			 * Always return success to work around enumeration
			 * failures.This works around an issue where devices
			 * which are present before a suspend and absent upon
			 * resume could cause a system panic on resume.
			 */

			return (DDI_SUCCESS);
		default:
			return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(hwarc_statep, instance) == DDI_SUCCESS) {
		hrcp = ddi_get_soft_state(hwarc_statep, instance);
	}
	if (hrcp == NULL)  {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, NULL,
		    "hwarc_attach: get soft state failed for instance %d",
		    instance);

		return (DDI_FAILURE);
	}

	(void) hwarc_init_devinst(dip, hrcp);

	if (hwarc_init_ep(dip, hrcp) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hrcp->hrc_log_hdl,
		    "attach: Error init usb data");
		goto fail;
	}
	hwarc_init_mutex(hrcp);

	/* create minor node */
	if (ddi_create_minor_node(dip, name, S_IFCHR, instance,
	    NULL, 0) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hrcp->hrc_log_hdl,
		    "attach: Error creating minor node");
		goto fail;
	}

	/* initialize power management */
	hwarc_init_power_mgmt(hrcp);

	if (usb_register_hotplug_cbs(dip, hwarc_disconnect_callback,
	    hwarc_reconnect_callback) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hrcp->hrc_log_hdl,
		    "attach: Error register hotplug cbs");

		goto fail;
	}

	/* register this device to uwba */
	uwb_dev_attach(dip, &hrcp->hrc_dev_hdl, 0, hwarc_send_cmd);

	if (hwarc_open_intr_pipe(hrcp) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hrcp->hrc_log_hdl,
		    "attach: Error open intr pipe");

		goto fail;
	}

	/* reset device */
	if (hwarc_reset_device(hrcp) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hrcp->hrc_log_hdl,
		    "attach: Error reset deivce");
		goto fail;
	}
	/* init phy capabilities */
	if (hwarc_init_phy(hrcp) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hrcp->hrc_log_hdl,
		    "attach: Error get phy ie");

		goto fail;
	}
	/* Report device */
	ddi_report_dev(dip);

	mutex_enter(&hrcp->hrc_mutex);
	hwarc_pm_idle_component(hrcp);
	mutex_exit(&hrcp->hrc_mutex);

	return (DDI_SUCCESS);

fail:
	(void) hwarc_cleanup(dip, hrcp);

	return (DDI_FAILURE);
}


/*
 * hwarc_detach:
 *	detach or suspend driver instance
 *
 * Note: in detach, only contention threads is from pm and disconnnect.
 */
static int
hwarc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		rval	= USB_SUCCESS;
	hwarc_state_t	*hrcp	=
	    ddi_get_soft_state(hwarc_statep, ddi_get_instance(dip));

	USB_DPRINTF_L3(PRINT_MASK_ATTA, hrcp->hrc_log_hdl,
	    "hwarc_detach: enter for detach, cmd = %d", cmd);


	switch (cmd) {
		case DDI_DETACH:

			rval = hwarc_cleanup(dip, hrcp);

			break;
		case DDI_SUSPEND:

			rval = hwarc_cpr_suspend(dip);
		default:

			break;
	}

	return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}


/*
 * hwarc_cleanup:
 *	clean up the driver state for detach
 */
static int
hwarc_cleanup(dev_info_t *dip, hwarc_state_t *hrcp)
{
	USB_DPRINTF_L2(PRINT_MASK_ATTA, hrcp->hrc_log_hdl, "Cleanup: enter");

	if (hrcp->hrc_locks_initialized) {

		(void) uwb_stop_beacon(dip);
		/* This must be done 1st to prevent more events from coming. */
		usb_unregister_hotplug_cbs(dip);

		hwarc_close_intr_pipe(hrcp);

		/*
		 * At this point, no new activity can be initiated. The driver
		 * has disabled hotplug callbacks. The Solaris framework has
		 * disabled new opens on a device being detached, and does not
		 * allow detaching an open device.
		 *
		 * The following ensures that all driver activity has drained.
		 */
		mutex_enter(&hrcp->hrc_mutex);
		(void) hwarc_serialize_access(hrcp, HWARC_SER_NOSIG);
		hwarc_release_access(hrcp);
		mutex_exit(&hrcp->hrc_mutex);

		/* All device activity has died down. */
		hwarc_destroy_power_mgmt(hrcp);

		/* start dismantling */
		ddi_remove_minor_node(dip, NULL);
		cv_destroy(&hrcp->hrc_serial_cv);
		mutex_destroy(&hrcp->hrc_mutex);
	}

	usb_client_detach(dip, hrcp->hrc_reg);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, hrcp->hrc_log_hdl, "Cleanup: end");

	usb_free_log_hdl(hrcp->hrc_log_hdl);

	uwb_dev_detach(hrcp->hrc_dev_hdl);

	kmem_free(hrcp->hrc_devinst, strlen(hrcp->hrc_devinst) + 1);

	ddi_soft_state_free(hwarc_statep, ddi_get_instance(dip));
	ddi_prop_remove_all(dip);

	return (USB_SUCCESS);
}



/*ARGSUSED*/
static int
hwarc_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	hwarc_state_t	*hrcp = NULL;
	int rval = 0;

	hrcp = ddi_get_soft_state(hwarc_statep, getminor(*devp));

	ASSERT(hrcp != NULL);

	USB_DPRINTF_L4(PRINT_MASK_OPEN, hrcp->hrc_log_hdl, "hwarc_open: enter");

	/*
	 * Keep it simple: one client at a time.
	 * Exclusive open only
	 */
	mutex_enter(&hrcp->hrc_mutex);
	/* exclusive open */
	if ((flag & FEXCL) && (hrcp->hrc_open_count > 0)) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, hrcp->hrc_log_hdl,
		    "hwarc_open failed, open count=%d", hrcp->hrc_open_count);
		mutex_exit(&hrcp->hrc_mutex);

		return (EBUSY);
	}

	if ((hrcp->hrc_dev_state == USB_DEV_DISCONNECTED) ||
	    (hrcp->hrc_dev_state == USB_DEV_SUSPENDED)) {

		USB_DPRINTF_L2(PRINT_MASK_OPEN, hrcp->hrc_log_hdl,
		    "hwarc_open failed, dev_stat=%d", hrcp->hrc_dev_state);
		mutex_exit(&hrcp->hrc_mutex);

		return (EIO);
	}

	hrcp->hrc_open_count++;

	USB_DPRINTF_L3(PRINT_MASK_OPEN, hrcp->hrc_log_hdl,
	    "hwarc_open, open count=%d", hrcp->hrc_open_count);
	if (hwarc_serialize_access(hrcp, HWARC_SER_SIG) == 0) {
		hrcp->hrc_open_count--;
		hwarc_release_access(hrcp);
		mutex_exit(&hrcp->hrc_mutex);

		return (EINTR);
	}

	hwarc_pm_busy_component(hrcp);

	mutex_exit(&hrcp->hrc_mutex);
	(void) pm_raise_power(hrcp->hrc_dip, 0, USB_DEV_OS_FULL_PWR);

	mutex_enter(&hrcp->hrc_mutex);
	/* Fail if device is no longer ready. */
	if (hrcp->hrc_dev_state != USB_DEV_ONLINE) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, hrcp->hrc_log_hdl,
		    "hwarc_open failed, dev_stat=%d", hrcp->hrc_dev_state);
		rval = EIO;
	}
	hwarc_release_access(hrcp);
	/* Device specific initialization goes here. */
	if (rval != 0) {
		hrcp->hrc_open_count--;
		hwarc_pm_idle_component(hrcp);
	}
	mutex_exit(&hrcp->hrc_mutex);

	USB_DPRINTF_L4(PRINT_MASK_OPEN, hrcp->hrc_log_hdl, "hwarc_open: leave");

	return (0);
}


/*ARGSUSED*/
static int
hwarc_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	hwarc_state_t	*hrcp =
	    ddi_get_soft_state(hwarc_statep, getminor(dev));

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, hrcp->hrc_log_hdl,
	    "hwarc_close: enter");

	mutex_enter(&hrcp->hrc_mutex);
	(void) hwarc_serialize_access(hrcp, HWARC_SER_NOSIG);

	hrcp->hrc_open_count--;
	USB_DPRINTF_L3(PRINT_MASK_CLOSE, hrcp->hrc_log_hdl,
	    "hwarc_close: open count=%d", hrcp->hrc_open_count);

	hwarc_release_access(hrcp);
	hwarc_pm_idle_component(hrcp);

	mutex_exit(&hrcp->hrc_mutex);

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, hrcp->hrc_log_hdl,
	    "hwarc_close: leave");

	return (0);
}

/* Send cmd to hwarc device */
int
hwarc_send_cmd(uwb_dev_handle_t uwb_dev_hdl, mblk_t *data, uint16_t data_len)
{
	usb_cb_flags_t		cb_flags;
	usb_cr_t		cr;
	usb_ctrl_setup_t 	setup;
	int 			rval;
	hwarc_state_t		*hrcp = NULL;
	dev_info_t 		*dip = uwb_get_dip(uwb_dev_hdl);

	hrcp = ddi_get_soft_state(hwarc_statep, ddi_get_instance(dip));

	ASSERT((hrcp != NULL) && (data != NULL));

	setup.bmRequestType	= HWARC_SET_IF;
	setup.bRequest 		= HWA_EXEC_RC_CMD;

	setup.wValue		= 0;
	setup.wIndex = hrcp->hrc_if_descr->if_alt->altif_descr.bInterfaceNumber;

	setup.wLength		= data_len;
	setup.attrs		= 0;

	USB_DPRINTF_L3(PRINT_MASK_DEVCTRL, hrcp->hrc_log_hdl,
	    "hwarc_send_cmd: wLength=%d, data[0], [1], [2], [3]=%d, %d, %d, %d",
	    setup.wLength, data->b_rptr[0], data->b_rptr[1], data->b_rptr[2],
	    data->b_rptr[3]);

	if ((rval = usb_pipe_ctrl_xfer_wait(hrcp->hrc_default_ph, &setup,
	    &data, &cr, &cb_flags, 0)) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_DEVCTRL, hrcp->hrc_log_hdl,
		    "hwarc_send_cmd: fail, rval=%d, cr=%d, "
		    "cb_flags=%x", rval, cr, cb_flags);

	}

	freemsg(data);

	return (rval);
}

/* ioctl, call uwb ioctl  */
/*ARGSUSED*/
static int
hwarc_ioctl(dev_t dev, int cmd, intptr_t arg,
		int mode, cred_t *cred_p, int *rval_p)
{
	int		rv = 0;

	hwarc_state_t	*hrcp =
	    ddi_get_soft_state(hwarc_statep, getminor(dev));
	if (hrcp == NULL) {

		return (ENXIO);
	}

	if (drv_priv(cred_p) != 0) {
		USB_DPRINTF_L3(PRINT_MASK_ALL, hrcp->hrc_log_hdl,
		    "hwahc_wusb_ioctl: user must have SYS_DEVICE privilege,"
		    "cmd=%x", cmd);

		return (EPERM);
	}



	USB_DPRINTF_L4(PRINT_MASK_ALL, hrcp->hrc_log_hdl, "hwarc_ioctl: enter");

	mutex_enter(&hrcp->hrc_mutex);
	if (hrcp->hrc_dev_state != USB_DEV_ONLINE) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, hrcp->hrc_log_hdl,
		    "ioctl: Device is not online,"
		    " dev_stat=%d", hrcp->hrc_dev_state);
		mutex_exit(&hrcp->hrc_mutex);

		return (EFAULT);
	}
	mutex_exit(&hrcp->hrc_mutex);

	rv = uwb_do_ioctl(hrcp->hrc_dev_hdl, cmd, arg, mode);

	return (rv);
}


/*
 * hwarc_disconnect_callback:
 *	Called when device hotplug-removed.
 *		Close pipes. (This does not attempt to contact device.)
 *		Set state to DISCONNECTED
 */
static int
hwarc_disconnect_callback(dev_info_t *dip)
{
	hwarc_state_t	*hrcp =
	    ddi_get_soft_state(hwarc_statep, ddi_get_instance(dip));

	USB_DPRINTF_L4(PRINT_MASK_CB, hrcp->hrc_log_hdl, "disconnect: enter");

	/* Disconnect the uwb device will stop beacon and save state */
	(void) uwb_dev_disconnect(dip);
	hwarc_close_intr_pipe(hrcp);

	mutex_enter(&hrcp->hrc_mutex);
	(void) hwarc_serialize_access(hrcp, HWARC_SER_NOSIG);

	/*
	 * Save any state of device or IO in progress required by
	 * hwarc_restore_device_state for proper device "thawing" later.
	 */
	hrcp->hrc_dev_state = USB_DEV_DISCONNECTED;

	hwarc_release_access(hrcp);
	mutex_exit(&hrcp->hrc_mutex);

	return (USB_SUCCESS);
}


/*
 * hwarc_reconnect_callback:
 *	Called with device hotplug-inserted
 *		Restore state
 */
static int
hwarc_reconnect_callback(dev_info_t *dip)
{
	int instance = ddi_get_instance(dip);
	hwarc_state_t	*hrcp =
	    ddi_get_soft_state(hwarc_statep, instance);

	USB_DPRINTF_L4(PRINT_MASK_CB, hrcp->hrc_log_hdl, "reconnect: enter");

	mutex_enter(&hrcp->hrc_mutex);
	(void) hwarc_serialize_access(hrcp, HWARC_SER_NOSIG);
	hwarc_restore_device_state(dip, hrcp);
	hwarc_release_access(hrcp);
	mutex_exit(&hrcp->hrc_mutex);

	/* Reconnect the uwb device will restore uwb device state */
	(void) uwb_dev_reconnect(dip);
	return (USB_SUCCESS);
}


/*
 * hwarc_restore_device_state:
 *	Called during hotplug-reconnect and resume.
 *		reenable power management
 *		Verify the device is the same as before the disconnect/suspend.
 *		Restore device state
 *		Thaw any IO which was frozen.
 *		Quiesce device.  (Other routines will activate if thawed IO.)
 *		Set device online.
 *		Leave device disconnected if there are problems.
 */
static void
hwarc_restore_device_state(dev_info_t *dip, hwarc_state_t *hrcp)
{

	USB_DPRINTF_L4(PRINT_MASK_ATTA, hrcp->hrc_log_hdl,
	    "hwarc_restore_device_state: enter");

	ASSERT(mutex_owned(&hrcp->hrc_mutex));

	ASSERT((hrcp->hrc_dev_state == USB_DEV_DISCONNECTED) ||
	    (hrcp->hrc_dev_state == USB_DEV_SUSPENDED));

	hwarc_pm_busy_component(hrcp);

	mutex_exit(&hrcp->hrc_mutex);

	(void) pm_raise_power(hrcp->hrc_dip, 0, USB_DEV_OS_FULL_PWR);

	if (usb_check_same_device(dip, hrcp->hrc_log_hdl, USB_LOG_L2,
	    PRINT_MASK_ALL, USB_CHK_BASIC|USB_CHK_CFG, NULL) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hrcp->hrc_log_hdl,
		    "hwarc_restore_device_state: check same device failed");

		goto fail;

	}
	if (hwarc_open_intr_pipe(hrcp) != USB_SUCCESS) {

		goto fail;
	}
	mutex_enter(&hrcp->hrc_mutex);

	hrcp->hrc_dev_state = USB_DEV_ONLINE;

	if (hrcp->hrc_pm && hrcp->hrc_pm->hrc_wakeup_enabled) {

		mutex_exit(&hrcp->hrc_mutex);
		if (usb_handle_remote_wakeup(dip, USB_REMOTE_WAKEUP_ENABLE) !=
		    USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, hrcp->hrc_log_hdl,
			    "hwarc_restore_device_state: "
			    "fail to enable device remote wakeup");
		}
		mutex_enter(&hrcp->hrc_mutex);

	}

	hwarc_pm_idle_component(hrcp);

	USB_DPRINTF_L3(PRINT_MASK_ATTA, hrcp->hrc_log_hdl,
	    "hwarc_restore_device_state: end");

	return;

fail:
	/* change the device state from suspended to disconnected */
	mutex_enter(&hrcp->hrc_mutex);
	hrcp->hrc_dev_state = USB_DEV_DISCONNECTED;
	hwarc_pm_idle_component(hrcp);
}


/*
 * hwarc_cpr_suspend:
 *	Clean up device.
 *	Wait for any IO to finish, then close pipes.
 *	Quiesce device.
 */
static int
hwarc_cpr_suspend(dev_info_t *dip)
{
	hwarc_state_t	*hrcp = ddi_get_soft_state(hwarc_statep,
	    ddi_get_instance(dip));

	USB_DPRINTF_L3(PRINT_MASK_PM, hrcp->hrc_log_hdl,
	    "hwarc_cpr_suspend, dev_stat=%d", hrcp->hrc_dev_state);

	/* Disconnect the uwb device will stop beacon and save state */
	(void) uwb_dev_disconnect(dip);

	/* Serialize to prevent races with detach, open, device access. */
	mutex_enter(&hrcp->hrc_mutex);
	(void) hwarc_serialize_access(hrcp, HWARC_SER_NOSIG);

	hwarc_pm_busy_component(hrcp);

	/*
	 * Set dev_state to suspended so other driver threads don't start any
	 * new I/O.  In a real driver, there may be draining of requests done
	 * afterwards, and we don't want the draining to compete with new
	 * requests being queued.
	 */

	/* Don't suspend if the device is open. */
	if (hrcp->hrc_open_count != 0) {
		USB_DPRINTF_L3(PRINT_MASK_PM, hrcp->hrc_log_hdl,
		    "suspend: Device is open.  Can't suspend");

		hwarc_release_access(hrcp);
		hwarc_pm_idle_component(hrcp);
		mutex_exit(&hrcp->hrc_mutex);

		return (USB_FAILURE);
	}

	/* Access device here to clean it up. */
	mutex_exit(&hrcp->hrc_mutex);
	hwarc_close_intr_pipe(hrcp);
	mutex_enter(&hrcp->hrc_mutex);

	hrcp->hrc_dev_state = USB_DEV_SUSPENDED;

	/*
	 * Save any state of device required by hwarc_restore_device_state
	 * for proper device "thawing" later.
	 */
	hwarc_release_access(hrcp);
	hwarc_pm_idle_component(hrcp);
	mutex_exit(&hrcp->hrc_mutex);

	USB_DPRINTF_L3(PRINT_MASK_PM, hrcp->hrc_log_hdl, "suspend: success");

	return (USB_SUCCESS);
}


/*
 * hwarc_cpr_resume:
 *
 *	hwarc_restore_device_state marks success by putting device back online
 */
static void
hwarc_cpr_resume(dev_info_t *dip)
{
	int		instance = ddi_get_instance(dip);
	hwarc_state_t	*hrcp = ddi_get_soft_state(hwarc_statep,
	    instance);

	USB_DPRINTF_L3(PRINT_MASK_PM, hrcp->hrc_log_hdl,
	    "hwarc_cpr_resume, dev_stat=%d", hrcp->hrc_dev_state);

	/*
	 * NOTE: A pm_raise_power in hwarc_restore_device_state will bring
	 * the power-up state of device into synch with the system.
	 */
	mutex_enter(&hrcp->hrc_mutex);
	hwarc_restore_device_state(dip, hrcp);
	mutex_exit(&hrcp->hrc_mutex);

	/* Reconnect the uwb device will restore uwb device state */
	(void) uwb_dev_reconnect(dip);
}

/*
 * pipe callbacks
 * --------------
 *
 * intr in callback for event receiving for hwarc device
 */
/*ARGSUSED*/
void
hwarc_intr_cb(usb_pipe_handle_t pipe, usb_intr_req_t *req)
{
	hwarc_state_t *hrcp = (hwarc_state_t *)req->intr_client_private;
	uwb_dev_handle_t uwb_dev_hd;
	mblk_t	*data = req->intr_data;
	int		data_len, parse_err;

	uwb_dev_hd = hrcp->hrc_dev_hdl;
	data_len = (data) ? MBLKL(data) : 0;

	if (data_len == 0) {

		return;
	}

	/*
	 * Parse the event/notifications from the device, and cv_signal the
	 * waiting cmd
	 */
	parse_err = uwb_parse_evt_notif((uint8_t *)data->b_rptr,
	    data_len, uwb_dev_hd);
	if (parse_err != UWB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_CB, hrcp->hrc_log_hdl,
		    "hwarc_intr_cb: parse failed, no cmd result or "
		    "notifs delivered. parse_err= %d", parse_err);
		if (data_len >= 5) {
			USB_DPRINTF_L2(PRINT_MASK_CB, hrcp->hrc_log_hdl,
			    "hwarc_intr_cb: erro evt len=%d"
			    " evtcode=%d %d,evt_context=%d, result-code=%d",
			    data_len, data->b_rptr[1], data->b_rptr[2],
			    data->b_rptr[3], data->b_rptr[4]);
		}
	}

	usb_free_intr_req(req);
}

/*
 * pipe callbacks
 * --------------
 *
 * intr in exception callback
 */
void
hwarc_intr_ex_cb(usb_pipe_handle_t pipe, usb_intr_req_t *req)
{
	hwarc_state_t *hrcp = (hwarc_state_t *)req->intr_client_private;
	usb_cr_t	cr = req->intr_completion_reason;

	USB_DPRINTF_L4(PRINT_MASK_CB, hrcp->hrc_log_hdl,
	    "hwarc_intr_ex_cb: ph = 0x%p req = 0x%p  cr=%d flags=%x",
	    (void *)pipe, (void *)req, cr, req->intr_cb_flags);

	usb_free_intr_req(req);

	/* restart polling */
	if ((cr != USB_CR_PIPE_CLOSING) && (cr != USB_CR_STOPPED_POLLING) &&
	    (cr != USB_CR_FLUSHED) && (cr != USB_CR_DEV_NOT_RESP) &&
	    (cr != USB_CR_PIPE_RESET) &&
	    (hrcp->hrc_dev_state == USB_DEV_ONLINE)) {
		if (hwarc_start_polling(hrcp, hrcp->hrc_intr_ph) !=
		    USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_CB, hrcp->hrc_log_hdl,
			    "hwarc_intr_ex_cb:"
			    "Restart pollling failed.");
		}
	} else {
		USB_DPRINTF_L2(PRINT_MASK_CB, hrcp->hrc_log_hdl,
		    "hwarc_intr_ex_cb:"
		    "get events failed: cr=%d", cr);
	}
}

/*
 * start polling on the interrupt pipe for events
 */
int
hwarc_start_polling(hwarc_state_t *hrcp, usb_pipe_handle_t intr_ph)
{
	usb_intr_req_t	*br;
	int		rval = USB_SUCCESS;

	USB_DPRINTF_L3(PRINT_MASK_OPEN, hrcp->hrc_log_hdl,
	    "hwarc_start_polling");

	br = usb_alloc_intr_req(hrcp->hrc_dip, 0, USB_FLAGS_SLEEP);

	if (!br) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, hrcp->hrc_log_hdl,
		    "hwarc_start_polling: alloc req failed.");

		return (USB_FAILURE);
	}
	br->intr_attributes = USB_ATTRS_SHORT_XFER_OK | USB_ATTRS_AUTOCLEARING;
	br->intr_len = hrcp->hrc_intr_ep_descr.wMaxPacketSize;
	br->intr_client_private = (void *)hrcp;

	br->intr_cb = hwarc_intr_cb;
	br->intr_exc_cb = hwarc_intr_ex_cb;

	rval = usb_pipe_intr_xfer(intr_ph, br, USB_FLAGS_SLEEP);

	if (rval != USB_SUCCESS) {
		usb_free_intr_req(br);

		USB_DPRINTF_L2(PRINT_MASK_OPEN, hrcp->hrc_log_hdl,
		    "hwarc_start_polling: failed (%d)", rval);
	}

	return (rval);
}

/*
 * hwarc_open_intr_pipe:
 *	Open any pipes other than default pipe.
 *	Mutex is assumed to be held.
 */
static int
hwarc_open_intr_pipe(hwarc_state_t *hrcp)
{

	int			rval = USB_SUCCESS;
	usb_pipe_policy_t	pipe_policy;
	usb_pipe_handle_t	pipe_handle;

	USB_DPRINTF_L3(PRINT_MASK_ATTA, hrcp->hrc_log_hdl, "open_pipes enter");

	bzero(&pipe_policy, sizeof (pipe_policy));

	/*
	 * Allow that pipes can support at least two asynchronous operations
	 * going on simultaneously.  Operations include asynchronous callbacks,
	 * resets, closures.
	 */
	pipe_policy.pp_max_async_reqs = 2;

	if ((rval = usb_pipe_open(hrcp->hrc_dip,
	    &hrcp->hrc_intr_ep_descr, &pipe_policy,
	    USB_FLAGS_SLEEP, &pipe_handle)) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hrcp->hrc_log_hdl,
		    "hwarc_open_intr_pipe:Error opening intr pipe: status = %d",
		    rval);
		goto done;
	}

	mutex_enter(&hrcp->hrc_mutex);
	hrcp->hrc_intr_ph = pipe_handle;
	mutex_exit(&hrcp->hrc_mutex);

	/*
	 * At this point, polling could be started on the pipe by making an
	 * asynchronous input request on the pipe.  Allocate a request by
	 * calling usb_alloc_intr_req(9F) with a zero length, initialize
	 * attributes with USB_ATTRS_SHORT_XFER_OK | USB_ATTRS_AUTOCLEARING,
	 * initialize length to be packetsize of the endpoint, specify the
	 * callbacks.  Pass this request to usb_pipe_intr_xfer to start polling.
	 * Call usb_pipe_stop_intr_poling(9F) to stop polling.
	 */
	rval = hwarc_start_polling(hrcp, hrcp->hrc_intr_ph);
	if (rval != USB_SUCCESS) {
		hwarc_close_intr_pipe(hrcp);

		USB_DPRINTF_L3(PRINT_MASK_ATTA, hrcp->hrc_log_hdl,
		    "hwarc_open_intr_pipe: Error start "
		    "polling intr pipe: rval = %d", rval);
	}

done:

	return (rval);
}


/*
 * hwarc_close_intr_pipe:
 *	Close pipes. Mutex is assumed to be held.
 */
static void
hwarc_close_intr_pipe(hwarc_state_t *hrcp)
{
	usb_pipe_handle_t	pipe_handle = NULL;
	USB_DPRINTF_L3(PRINT_MASK_ATTA, hrcp->hrc_log_hdl, "close_pipes enter");

	mutex_enter(&hrcp->hrc_mutex);
	if (!hrcp->hrc_intr_ph) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hrcp->hrc_log_hdl,
		    "hwarc intr pipe not exist");
		mutex_exit(&hrcp->hrc_mutex);
		return;
	}

	pipe_handle = hrcp->hrc_intr_ph;
	hrcp->hrc_intr_ph = NULL;
	mutex_exit(&hrcp->hrc_mutex);

	/* Stop polling */
	usb_pipe_stop_intr_polling(pipe_handle, USB_FLAGS_SLEEP);

	/* Close Pipe */
	usb_pipe_close(hrcp->hrc_dip, pipe_handle, USB_FLAGS_SLEEP, NULL, 0);
}

/*
 * hwarc_power :
 *	Power entry point, the workhorse behind pm_raise_power, pm_lower_power,
 *	usb_req_raise_power and usb_req_lower_power.
 */
/*ARGSUSED*/
static int
hwarc_power(dev_info_t *dip, int comp, int level)
{
	hwarc_state_t	*hrcp;
	int	rval = USB_FAILURE;

	hrcp = ddi_get_soft_state(hwarc_statep, ddi_get_instance(dip));

	USB_DPRINTF_L3(PRINT_MASK_PM, hrcp->hrc_log_hdl,
	    "hwarc_power: level = %d", level);

	mutex_enter(&hrcp->hrc_mutex);

	ASSERT(hrcp->hrc_pm != NULL);

	(void) hwarc_serialize_access(hrcp, HWARC_SER_NOSIG);

	/*
	 * If we are disconnected/suspended, return success. Note that if we
	 * return failure, bringing down the system will hang when
	 * PM tries to power up all devices
	 */
	if ((hrcp->hrc_dev_state == USB_DEV_DISCONNECTED) ||
	    (hrcp->hrc_dev_state == USB_DEV_SUSPENDED)) {

		USB_DPRINTF_L3(PRINT_MASK_PM, hrcp->hrc_log_hdl,
		    "hwarc_power: disconnected/suspended "
		    "dev_state=%d", hrcp->hrc_dev_state);
		rval = USB_SUCCESS;

		goto done;
	}


	/* Check if we are transitioning to a legal power level */
	if (USB_DEV_PWRSTATE_OK(hrcp->hrc_pm->hrc_pwr_states, level)) {
		USB_DPRINTF_L2(PRINT_MASK_PM, hrcp->hrc_log_hdl,
		    "hwarc_power: illegal power level = %d "
		    "pwr_states: %x", level, hrcp->hrc_pm->hrc_pwr_states);

		goto done;
	}

	switch (level) {
	case USB_DEV_OS_PWR_OFF :
		rval = hwarc_pwrlvl0(hrcp);

		break;
	case USB_DEV_OS_PWR_1:
		rval = hwarc_pwrlvl1(hrcp);

		break;
	case USB_DEV_OS_PWR_2:
		rval = hwarc_pwrlvl2(hrcp);

		break;
	case USB_DEV_OS_FULL_PWR :
		rval = hwarc_pwrlvl3(hrcp);

		break;
	}

done:
	hwarc_release_access(hrcp);
	mutex_exit(&hrcp->hrc_mutex);

	return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}


/*
 * hwarc_serialize_access:
 *    Get the serial synchronization object before returning.
 *
 * Arguments:
 *    hrcp - Pointer to hwarc state structure
 *    waitsig - Set to:
 *	HWARC_SER_SIG - to wait such that a signal can interrupt
 *	HWARC_SER_NOSIG - to wait such that a signal cannot interrupt
 */
static int
hwarc_serialize_access(hwarc_state_t *hrcp, boolean_t waitsig)
{
	int rval = 1;

	ASSERT(mutex_owned(&hrcp->hrc_mutex));

	while (hrcp->hrc_serial_inuse) {
		if (waitsig == HWARC_SER_SIG) {
			rval = cv_wait_sig(&hrcp->hrc_serial_cv,
			    &hrcp->hrc_mutex);
		} else {
			cv_wait(&hrcp->hrc_serial_cv,
			    &hrcp->hrc_mutex);
		}
	}
	hrcp->hrc_serial_inuse = B_TRUE;

	return (rval);
}


/*
 * hwarc_release_access:
 *    Release the serial synchronization object.
 */
static void
hwarc_release_access(hwarc_state_t *hrcp)
{
	ASSERT(mutex_owned(&hrcp->hrc_mutex));
	hrcp->hrc_serial_inuse = B_FALSE;
	cv_broadcast(&hrcp->hrc_serial_cv);
}


/*
 * hwarc_reset_device:
 *	Reset the readio controller with uwb interfaces.
 *	if the device is different.  Can block.
 */
static int
hwarc_reset_device(hwarc_state_t *hrcp)
{
	if (uwb_reset_dev(hrcp->hrc_dip) != UWB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hrcp->hrc_log_hdl,
		    "hwarc_reset_device: uwb_reset_dev failed");

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}

/*
 * hwarc_init_phy
 *	init the physical capabilities of the radio controller.
 *	the band groups and phy rates will be initialized in the
 *	uwb devices.
 */
static int
hwarc_init_phy(hwarc_state_t *hrcp)
{
	if (uwb_init_phy(hrcp->hrc_dip) != UWB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, hrcp->hrc_log_hdl,
		    "hwarc_init_phy: uwb_init_phy failed");

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}
