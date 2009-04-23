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
 * This driver is to be used for download firmware for devices.
 */

#if defined(lint) && !defined(DEBUG)
#define	DEBUG
#endif

#define	USBDRV_MAJOR_VER	2
#define	USBDRV_MINOR_VER	0

#include <sys/kobj.h>
#include <sys/usb/usba.h>
#include <sys/usb/usba/usbai_private.h>
#include <sys/usb/clients/wusb_df/wusb_df.h>

#define	WUSB_DF_INITIAL_SOFT_SPACE	1
#define	MAX_DAT_FILE_SIZE	(512 * 1024)

uint_t	wusb_df_errlevel = USB_LOG_L4;
uint_t  wusb_df_errmask   = (uint_t)PRINT_MASK_ALL;
uint_t  wusb_df_instance_debug = (uint_t)-1;
static char	*name = "wusb_df";	/* Driver name, used all over. */
static char wusb_fwmod[] = "hwa1480_fw";
static char wusb_fwsym1[] = "hwa1480_fw";

/* Soft state structures */
static void *wusb_df_statep;

/*
 * Function Prototypes
 */
static int	wusb_df_attach(dev_info_t *, ddi_attach_cmd_t);
static int	wusb_df_detach(dev_info_t *, ddi_detach_cmd_t);
static int	wusb_df_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	wusb_df_cleanup(dev_info_t *, wusb_df_state_t *);
static int	wusb_df_disconnect_callback(dev_info_t *);
static int	wusb_df_reconnect_callback(dev_info_t *);
static void	wusb_df_restore_device_state(dev_info_t *, wusb_df_state_t *);
static int	wusb_df_cpr_suspend(dev_info_t *);
static void	wusb_df_cpr_resume(dev_info_t *);
static void	wusb_df_pm_busy_component(wusb_df_state_t *);
static void	wusb_df_pm_idle_component(wusb_df_state_t *);
static int	wusb_df_power(dev_info_t *, int, int);
static void	wusb_df_init_power_mgmt(wusb_df_state_t *);
static void	wusb_df_destroy_power_mgmt(wusb_df_state_t *);
static int	wusb_df_serialize_access(wusb_df_state_t *, boolean_t);
static void	wusb_df_release_access(wusb_df_state_t *);
static int	wusb_df_firmware_download(wusb_df_state_t *wusbp);


/* _NOTE is an advice for locklint.  Locklint checks lock use for deadlocks. */
_NOTE(SCHEME_PROTECTS_DATA("unique per call", usb_ctrl_req))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", buf))

/* module loading stuff */
struct cb_ops wusb_df_cb_ops = {
	nodev,			/* open  */
	nodev,  		/* close */
	nodev,			/* strategy */
	nulldev,		/* print */
	nulldev,		/* dump */
	nodev,			/* read */
	nodev,			/* write */
	nodev,			/* ioctl */
	nulldev,		/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* streamtab  */
	D_MP
};

static struct dev_ops wusb_df_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	wusb_df_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	wusb_df_attach,		/* attach */
	wusb_df_detach,		/* detach */
	nodev,			/* reset */
	&wusb_df_cb_ops,	/* driver operations */
	NULL,			/* bus operations */
	wusb_df_power		/* power */
};

static struct modldrv wusb_df_modldrv =	{
	&mod_driverops,
	"WUSB firmware download",
	&wusb_df_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&wusb_df_modldrv,
	NULL
};

/*
 * Descriptor for a record of firmware
 */
typedef struct fw_dsc {
	uint32_t		addr;
	size_t			size;
	uint8_t			*data;
	struct fw_dsc		*next;
} fw_dsc_t;


/*
 * Module-wide initialization routine.
 */
int
_init(void)
{
	int rval;


	if ((rval = ddi_soft_state_init(&wusb_df_statep,
	    sizeof (wusb_df_state_t), WUSB_DF_INITIAL_SOFT_SPACE)) != 0) {

		return (rval);
	}

	if ((rval = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&wusb_df_statep);
	}


	return (rval);
}


/*
 * Module-wide tear-down routine.
 */
int
_fini(void)
{
	int rval;

	if ((rval = mod_remove(&modlinkage)) != 0) {

		return (rval);
	}

	ddi_soft_state_fini(&wusb_df_statep);

	return (rval);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * wusb_df_attach:
 *	Attach or resume.
 *
 *	For attach, initialize state and device, including:
 *		state variables, locks, device node
 *		device registration with system
 *		power management, hotplugging
 *	For resume, restore device and state
 */
static int
wusb_df_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance = ddi_get_instance(dip);
	char			*devinst;
	int			devinstlen;
	wusb_df_state_t		*wusb_dfp = NULL;
	usb_ep_data_t		*ep_datap;
	int			status;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		wusb_df_cpr_resume(dip);

		/*
		 * Always return success to work around enumeration failures.
		 * This works around an issue where devices which are present
		 * before a suspend and absent upon resume could cause a system
		 * panic on resume.
		 */
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(wusb_df_statep, instance) == DDI_SUCCESS) {
		wusb_dfp = ddi_get_soft_state(wusb_df_statep, instance);
	}
	if (wusb_dfp == NULL)  {

		return (DDI_FAILURE);
	}

	wusb_dfp->wusb_df_dip = dip;

	devinst = kmem_zalloc(USB_MAXSTRINGLEN, KM_SLEEP);
	devinstlen = snprintf(devinst, USB_MAXSTRINGLEN, "%s%d: ",
	    ddi_driver_name(dip), instance);

	wusb_dfp->wusb_df_devinst = kmem_zalloc(devinstlen + 1, KM_SLEEP);
	(void) strncpy(wusb_dfp->wusb_df_devinst, devinst, devinstlen);
	kmem_free(devinst, USB_MAXSTRINGLEN);

	wusb_dfp->wusb_df_log_hdl = usb_alloc_log_hdl(dip, "wusb_df",
	    &wusb_df_errlevel, &wusb_df_errmask, &wusb_df_instance_debug, 0);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, wusb_dfp->wusb_df_log_hdl,
	    "Attach: enter for attach");

	if ((status = usb_client_attach(dip, USBDRV_VERSION, 0)) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, wusb_dfp->wusb_df_log_hdl,
		    "attach: usb_client_attach failed, error code:%d", status);
		goto fail;
	}

	if ((status = usb_get_dev_data(dip, &wusb_dfp->wusb_df_reg,
	    USB_PARSE_LVL_ALL, 0)) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, wusb_dfp->wusb_df_log_hdl,
		    "attach: usb_get_dev_data failed, error code:%d", status);
		goto fail;
	}


	/*
	 * Get the descriptor for an intr pipe at alt 0 of current interface.
	 * This will be used later to open the pipe.
	 */
	if ((ep_datap = usb_lookup_ep_data(dip, wusb_dfp->wusb_df_reg,
	    wusb_dfp->wusb_df_reg->dev_curr_if, 0, 0,
	    USB_EP_ATTR_INTR, USB_EP_DIR_IN)) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, wusb_dfp->wusb_df_log_hdl,
		    "attach: Error getting intr endpoint descriptor");
		goto fail;
	}
	wusb_dfp->wusb_df_intr_ep_descr = ep_datap->ep_descr;

	usb_free_descr_tree(dip, wusb_dfp->wusb_df_reg);

	mutex_init(&wusb_dfp->wusb_df_mutex, NULL, MUTEX_DRIVER,
	    wusb_dfp->wusb_df_reg->dev_iblock_cookie);

	cv_init(&wusb_dfp->wusb_df_serial_cv, NULL, CV_DRIVER, NULL);
	wusb_dfp->wusb_df_serial_inuse = B_FALSE;

	wusb_dfp->wusb_df_locks_initialized = B_TRUE;

	/* create minor node */
	if (ddi_create_minor_node(dip, name, S_IFCHR, instance,
	    "wusb_df", 0) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, wusb_dfp->wusb_df_log_hdl,
		    "attach: Error creating minor node");
		goto fail;
	}

	/* Put online before PM init as can get power managed afterward. */
	wusb_dfp->wusb_df_dev_state = USB_DEV_ONLINE;

	/* initialize power management */
	wusb_df_init_power_mgmt(wusb_dfp);

	if (usb_register_hotplug_cbs(dip, wusb_df_disconnect_callback,
	    wusb_df_reconnect_callback) != USB_SUCCESS) {

		goto fail;
	}

	/* Report device */
	ddi_report_dev(dip);

	(void) wusb_df_firmware_download(wusb_dfp);

	if (usb_reset_device(dip, USB_RESET_LVL_REATTACH) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_PM, wusb_dfp->wusb_df_log_hdl,
		    "reset device failed");

		return (USB_FAILURE);
	}

	return (DDI_SUCCESS);

fail:
	if (wusb_dfp) {
		(void) wusb_df_cleanup(dip, wusb_dfp);
	}

	return (DDI_FAILURE);
}


/*
 * wusb_df_detach:
 *	detach or suspend driver instance
 *
 * Note: in detach, only contention threads is from pm and disconnnect.
 */
static int
wusb_df_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance = ddi_get_instance(dip);
	wusb_df_state_t	*wusb_dfp =
	    ddi_get_soft_state(wusb_df_statep, instance);
	int		rval = DDI_FAILURE;

	switch (cmd) {
	case DDI_DETACH:

		USB_DPRINTF_L4(PRINT_MASK_ATTA, wusb_dfp->wusb_df_log_hdl,
		    "Detach: enter for detach");

		rval = wusb_df_cleanup(dip, wusb_dfp);

		break;
	case DDI_SUSPEND:
		USB_DPRINTF_L4(PRINT_MASK_ATTA, wusb_dfp->wusb_df_log_hdl,
		    "Detach: enter for suspend");

		rval = wusb_df_cpr_suspend(dip);
	default:

		break;
	}

	return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}


/*
 * wusb_df_cleanup:
 *	clean up the driver state for detach
 */
static int
wusb_df_cleanup(dev_info_t *dip, wusb_df_state_t *wusb_dfp)
{

	USB_DPRINTF_L3(PRINT_MASK_ATTA, wusb_dfp->wusb_df_log_hdl,
	    "Cleanup: enter");

	if (wusb_dfp->wusb_df_locks_initialized) {

		/* This must be done 1st to prevent more events from coming. */
		usb_unregister_hotplug_cbs(dip);

		/*
		 * At this point, no new activity can be initiated. The driver
		 * has disabled hotplug callbacks. The Solaris framework has
		 * disabled new opens on a device being detached, and does not
		 * allow detaching an open device.
		 *
		 * The following ensures that all driver activity has drained.
		 */
		mutex_enter(&wusb_dfp->wusb_df_mutex);
		(void) wusb_df_serialize_access(wusb_dfp, WUSB_DF_SER_NOSIG);
		wusb_df_release_access(wusb_dfp);
		mutex_exit(&wusb_dfp->wusb_df_mutex);

		/* All device activity has died down. */
		wusb_df_destroy_power_mgmt(wusb_dfp);

		/* start dismantling */
		ddi_remove_minor_node(dip, NULL);

		cv_destroy(&wusb_dfp->wusb_df_serial_cv);
		mutex_destroy(&wusb_dfp->wusb_df_mutex);
	}

	usb_client_detach(dip, wusb_dfp->wusb_df_reg);

	usb_free_log_hdl(wusb_dfp->wusb_df_log_hdl);

	if (wusb_dfp->wusb_df_devinst != NULL) {
		kmem_free(wusb_dfp->wusb_df_devinst,
		    strlen(wusb_dfp->wusb_df_devinst) + 1);
	}

	ddi_soft_state_free(wusb_df_statep, ddi_get_instance(dip));
	ddi_prop_remove_all(dip);

	return (USB_SUCCESS);
}


/*
 * wusb_df_disconnect_callback:
 *	Called when device hotplug-removed.
 *		Close pipes. (This does not attempt to contact device.)
 *		Set state to DISCONNECTED
 */
static int
wusb_df_disconnect_callback(dev_info_t *dip)
{
	int instance = ddi_get_instance(dip);
	wusb_df_state_t	*wusb_dfp =
	    ddi_get_soft_state(wusb_df_statep, instance);


	USB_DPRINTF_L4(PRINT_MASK_CB, wusb_dfp->wusb_df_log_hdl,
	    "disconnect: enter");

	mutex_enter(&wusb_dfp->wusb_df_mutex);
	(void) wusb_df_serialize_access(wusb_dfp, WUSB_DF_SER_NOSIG);

	/*
	 * Save any state of device or IO in progress required by
	 * wusb_df_restore_device_state for proper device "thawing" later.
	 */
	wusb_dfp->wusb_df_dev_state = USB_DEV_DISCONNECTED;

	wusb_df_release_access(wusb_dfp);
	mutex_exit(&wusb_dfp->wusb_df_mutex);

	return (USB_SUCCESS);
}


/*
 * wusb_df_reconnect_callback:
 *	Called with device hotplug-inserted
 *		Restore state
 */
static int
wusb_df_reconnect_callback(dev_info_t *dip)
{
	int instance = ddi_get_instance(dip);
	wusb_df_state_t	*wusb_dfp =
	    ddi_get_soft_state(wusb_df_statep, instance);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, wusb_dfp->wusb_df_log_hdl,
	    "reconnect: enter");

	wusb_df_pm_busy_component(wusb_dfp);
	(void) pm_raise_power(wusb_dfp->wusb_df_dip, 0, USB_DEV_OS_FULL_PWR);

	mutex_enter(&wusb_dfp->wusb_df_mutex);
	(void) wusb_df_serialize_access(wusb_dfp, WUSB_DF_SER_NOSIG);
	wusb_df_restore_device_state(dip, wusb_dfp);
	wusb_df_release_access(wusb_dfp);
	mutex_exit(&wusb_dfp->wusb_df_mutex);

	wusb_df_pm_idle_component(wusb_dfp);

	return (USB_SUCCESS);
}


/*
 * wusb_df_restore_device_state:
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
wusb_df_restore_device_state(dev_info_t *dip, wusb_df_state_t *wusb_dfp)
{
	USB_DPRINTF_L2(PRINT_MASK_PM, wusb_dfp->wusb_df_log_hdl,
	    "wusb_df_restore_device_state: enter");

	ASSERT(mutex_owned(&wusb_dfp->wusb_df_mutex));

	ASSERT((wusb_dfp->wusb_df_dev_state == USB_DEV_DISCONNECTED) ||
	    (wusb_dfp->wusb_df_dev_state == USB_DEV_SUSPENDED));

	mutex_exit(&wusb_dfp->wusb_df_mutex);


	/* Check if we are talking to the same device */
	if (usb_check_same_device(dip, wusb_dfp->wusb_df_log_hdl,
	    USB_LOG_L0, PRINT_MASK_ALL,
	    USB_CHK_ALL, NULL) != USB_SUCCESS) {

		/* change the device state from suspended to disconnected */
		mutex_enter(&wusb_dfp->wusb_df_mutex);
		wusb_dfp->wusb_df_dev_state = USB_DEV_SUSPENDED;
		USB_DPRINTF_L2(PRINT_MASK_PM, wusb_dfp->wusb_df_log_hdl,
		    "wusb_df_restore_device_state: check same device failed");
		return;
	}

	mutex_enter(&wusb_dfp->wusb_df_mutex);
	wusb_dfp->wusb_df_dev_state = USB_DEV_ONLINE;

	if (wusb_dfp->wusb_df_pm &&
	    wusb_dfp->wusb_df_pm->wusb_df_wakeup_enabled) {

		/* Failure here means device disappeared again. */
		mutex_exit(&wusb_dfp->wusb_df_mutex);
		if (usb_handle_remote_wakeup(dip, USB_REMOTE_WAKEUP_ENABLE) !=
		    USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_PM, wusb_dfp->wusb_df_log_hdl,
			    "device may or may not be accessible. "
			    "Please verify reconnection");
		}
		mutex_enter(&wusb_dfp->wusb_df_mutex);
	}


	USB_DPRINTF_L4(PRINT_MASK_PM, wusb_dfp->wusb_df_log_hdl,
	    "wusb_df_restore_device_state: end");

}


/*
 * wusb_df_cpr_suspend:
 *	Clean up device.
 *	Wait for any IO to finish, then close pipes.
 *	Quiesce device.
 */
static int
wusb_df_cpr_suspend(dev_info_t *dip)
{
	int		instance = ddi_get_instance(dip);
	wusb_df_state_t	*wusb_dfp =
	    ddi_get_soft_state(wusb_df_statep, instance);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, wusb_dfp->wusb_df_log_hdl,
	    "suspend enter");

	/* Serialize to prevent races with detach, open, device access. */
	mutex_enter(&wusb_dfp->wusb_df_mutex);
	(void) wusb_df_serialize_access(wusb_dfp, WUSB_DF_SER_NOSIG);
	mutex_exit(&wusb_dfp->wusb_df_mutex);

	wusb_df_pm_busy_component(wusb_dfp);

	mutex_enter(&wusb_dfp->wusb_df_mutex);

	/* Access device here to clean it up. */

	wusb_dfp->wusb_df_dev_state = USB_DEV_SUSPENDED;

	/*
	 * Save any state of device required by wusb_df_restore_device_state
	 * for proper device "thawing" later.
	 */

	wusb_df_release_access(wusb_dfp);
	mutex_exit(&wusb_dfp->wusb_df_mutex);

	wusb_df_pm_idle_component(wusb_dfp);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, wusb_dfp->wusb_df_log_hdl,
	    "suspend: success");

	return (USB_SUCCESS);
}


/*
 * wusb_df_cpr_resume:
 *
 *	wusb_df_restore_device_state marks success by putting device back online
 */
static void
wusb_df_cpr_resume(dev_info_t *dip)
{
	int		instance = ddi_get_instance(dip);
	wusb_df_state_t	*wusb_dfp =
	    ddi_get_soft_state(wusb_df_statep, instance);

	USB_DPRINTF_L4(PRINT_MASK_CPR, wusb_dfp->wusb_df_log_hdl,
	    "resume: enter");

	/*
	 * NOTE: A pm_raise_power in wusb_df_restore_device_state will bring
	 * the power-up state of device into synch with the system.
	 */
	wusb_df_pm_busy_component(wusb_dfp);
	(void) pm_raise_power(wusb_dfp->wusb_df_dip, 0, USB_DEV_OS_FULL_PWR);
	mutex_enter(&wusb_dfp->wusb_df_mutex);
	wusb_df_restore_device_state(dip, wusb_dfp);
	mutex_exit(&wusb_dfp->wusb_df_mutex);
	wusb_df_pm_idle_component(wusb_dfp);
}

static void
wusb_df_pm_busy_component(wusb_df_state_t *wusb_dfp)
{
	ASSERT(!mutex_owned(&wusb_dfp->wusb_df_mutex));

	mutex_enter(&wusb_dfp->wusb_df_mutex);
	if (wusb_dfp->wusb_df_pm == NULL) {
		USB_DPRINTF_L4(PRINT_MASK_PM, wusb_dfp->wusb_df_log_hdl,
		    "wusb_df_pm_busy_component: pm = NULL");
		goto done;
	}

	wusb_dfp->wusb_df_pm->wusb_df_pm_busy++;
	USB_DPRINTF_L4(PRINT_MASK_PM, wusb_dfp->wusb_df_log_hdl,
	    "wusb_df_pm_busy_component: %d",
	    wusb_dfp->wusb_df_pm->wusb_df_pm_busy);

	mutex_exit(&wusb_dfp->wusb_df_mutex);

	if (pm_busy_component(wusb_dfp->wusb_df_dip, 0) != DDI_SUCCESS) {
		mutex_enter(&wusb_dfp->wusb_df_mutex);
		wusb_dfp->wusb_df_pm->wusb_df_pm_busy--;

		USB_DPRINTF_L4(PRINT_MASK_PM, wusb_dfp->wusb_df_log_hdl,
		    "wusb_df_pm_busy_component: %d",
		    wusb_dfp->wusb_df_pm->wusb_df_pm_busy);
		mutex_exit(&wusb_dfp->wusb_df_mutex);


	}
	return;
done:
		mutex_exit(&wusb_dfp->wusb_df_mutex);

}

static void
wusb_df_pm_idle_component(wusb_df_state_t *wusb_dfp)
{
	ASSERT(!mutex_owned(&wusb_dfp->wusb_df_mutex));
	mutex_enter(&wusb_dfp->wusb_df_mutex);
	if (wusb_dfp->wusb_df_pm == NULL) {
		mutex_exit(&wusb_dfp->wusb_df_mutex);
		return;
	}
	mutex_exit(&wusb_dfp->wusb_df_mutex);


	if (pm_idle_component(wusb_dfp->wusb_df_dip, 0) == DDI_SUCCESS) {
		mutex_enter(&wusb_dfp->wusb_df_mutex);
		ASSERT(wusb_dfp->wusb_df_pm->wusb_df_pm_busy > 0);
		wusb_dfp->wusb_df_pm->wusb_df_pm_busy--;

		USB_DPRINTF_L4(PRINT_MASK_PM, wusb_dfp->wusb_df_log_hdl,
		    "wusb_df_pm_idle_component: %d",
		    wusb_dfp->wusb_df_pm->wusb_df_pm_busy);

		mutex_exit(&wusb_dfp->wusb_df_mutex);
	}
}

/*
 * wusb_df_power :
 *	Power entry point, the workhorse behind pm_raise_power, pm_lower_power,
 *	usb_req_raise_power and usb_req_lower_power.
 */
/* ARGSUSED */
static int
wusb_df_power(dev_info_t *dip, int comp, int level)
{
	wusb_df_state_t	*wusb_dfp;
	wusb_df_power_t	*pm;
	int	rval = USB_SUCCESS;

	wusb_dfp = ddi_get_soft_state(wusb_df_statep, ddi_get_instance(dip));

	USB_DPRINTF_L3(PRINT_MASK_PM, wusb_dfp->wusb_df_log_hdl,
	    "wusb_df_power: enter: level = %d", level);

	mutex_enter(&wusb_dfp->wusb_df_mutex);
	(void) wusb_df_serialize_access(wusb_dfp, WUSB_DF_SER_NOSIG);


	/*
	 * If we are disconnected/suspended, return success. Note that if we
	 * return failure, bringing down the system will hang when
	 * PM tries to power up all devices
	 */
	if ((wusb_dfp->wusb_df_dev_state == USB_DEV_DISCONNECTED) ||
	    (wusb_dfp->wusb_df_dev_state == USB_DEV_SUSPENDED)) {

		USB_DPRINTF_L3(PRINT_MASK_PM, wusb_dfp->wusb_df_log_hdl,
		    "wusb_df_power: disconnected/suspended "
		    "dev_state=%d", wusb_dfp->wusb_df_dev_state);
		rval = USB_SUCCESS;

		goto done;
	}

	if (wusb_dfp->wusb_df_pm == NULL) {

		goto done;
	}

	pm = wusb_dfp->wusb_df_pm;

	/* Check if we are transitioning to a legal power level */
	if (USB_DEV_PWRSTATE_OK(pm->wusb_df_pwr_states, level)) {
		USB_DPRINTF_L3(PRINT_MASK_PM, wusb_dfp->wusb_df_log_hdl,
		    "wusb_df_power: illegal power level = %d "
		    "pwr_states: %x", level, pm->wusb_df_pwr_states);

		goto done;
	}

	switch (level) {
	case USB_DEV_OS_PWR_OFF :
		/* fail attempt to go to low power if busy */
		if (pm->wusb_df_pm_busy) {

			goto done;
		}
		if (wusb_dfp->wusb_df_dev_state == USB_DEV_ONLINE) {
			wusb_dfp->wusb_df_dev_state = USB_DEV_PWRED_DOWN;
			wusb_dfp->wusb_df_pm->wusb_df_current_power =
			    USB_DEV_OS_PWR_OFF;
		} else {
			rval = USB_SUCCESS;
		}
		break;

	case USB_DEV_OS_FULL_PWR :
		/*
		 * PM framework tries to put us in full power during system
		 * shutdown.
		 */
		wusb_dfp->wusb_df_dev_state = USB_DEV_ONLINE;
		wusb_dfp->wusb_df_pm->wusb_df_current_power =
		    USB_DEV_OS_FULL_PWR;
		break;

	/* Levels 1 and 2 are not supported by this driver to keep it simple. */
	default:
		USB_DPRINTF_L3(PRINT_MASK_PM, wusb_dfp->wusb_df_log_hdl,
		    "wusb_df_power: power level %d not supported", level);
		break;
	}
done:
	wusb_df_release_access(wusb_dfp);
	mutex_exit(&wusb_dfp->wusb_df_mutex);

	return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}


/*
 * wusb_df_init_power_mgmt:
 *	Initialize power management and remote wakeup functionality.
 *	No mutex is necessary in this function as it's called only by attach.
 */
static void
wusb_df_init_power_mgmt(wusb_df_state_t *wusb_dfp)
{
	wusb_df_power_t *wusb_dfpm;
	uint_t		pwr_states;

	USB_DPRINTF_L4(PRINT_MASK_PM, wusb_dfp->wusb_df_log_hdl,
	    "init_power_mgmt enter");

	/*
	 * If remote wakeup is not available you may not want to do
	 * power management.
	 */
	/* Allocate the state structure */
	wusb_dfpm = kmem_zalloc(sizeof (wusb_df_power_t), KM_SLEEP);
	wusb_dfp->wusb_df_pm = wusb_dfpm;
	wusb_dfpm->wusb_df_state = wusb_dfp;
	wusb_dfpm->wusb_df_pm_capabilities = 0;
	wusb_dfpm->wusb_df_current_power = USB_DEV_OS_FULL_PWR;

	if (usb_create_pm_components(wusb_dfp->wusb_df_dip, &pwr_states) ==
	    USB_SUCCESS) {

		USB_DPRINTF_L4(PRINT_MASK_PM, wusb_dfp->wusb_df_log_hdl,
		    "wusb_df_init_power_mgmt: created PM components");

		wusb_dfpm->wusb_df_pwr_states = (uint8_t)pwr_states;
		(void) pm_raise_power(wusb_dfp->wusb_df_dip, 0,
		    USB_DEV_OS_FULL_PWR);

		if (usb_handle_remote_wakeup(wusb_dfp->wusb_df_dip,
		    USB_REMOTE_WAKEUP_ENABLE) == USB_SUCCESS) {
			wusb_dfpm->wusb_df_wakeup_enabled = 1;
		} else {
			USB_DPRINTF_L2(PRINT_MASK_PM, wusb_dfp->wusb_df_log_hdl,
			    "wusb_df_init_power_mgmt:"
			    "fail to enable remote wakeup");
		}

	} else {
		USB_DPRINTF_L2(PRINT_MASK_PM, wusb_dfp->wusb_df_log_hdl,
		    "wusb_df_init_power_mgmt: create_pm_compts failed");
	}
	USB_DPRINTF_L4(PRINT_MASK_PM, wusb_dfp->wusb_df_log_hdl,
	    "wusb_df_init_power_mgmt: end");

}


/*
 * wusb_df_destroy_power_mgmt:
 *	Shut down and destroy power management and remote wakeup functionality.
 */
static void
wusb_df_destroy_power_mgmt(wusb_df_state_t *wusb_dfp)
{
	USB_DPRINTF_L4(PRINT_MASK_PM, wusb_dfp->wusb_df_log_hdl,
	    "destroy_power_mgmt enter");

	ASSERT(!mutex_owned(&wusb_dfp->wusb_df_mutex));

	mutex_enter(&wusb_dfp->wusb_df_mutex);
	if (!wusb_dfp->wusb_df_pm) {
		mutex_exit(&wusb_dfp->wusb_df_mutex);
		return;
	}
	mutex_exit(&wusb_dfp->wusb_df_mutex);

	(void) wusb_df_pm_busy_component(wusb_dfp);

	mutex_enter(&wusb_dfp->wusb_df_mutex);
	if (wusb_dfp->wusb_df_dev_state != USB_DEV_DISCONNECTED) {

		if (wusb_dfp->wusb_df_pm->wusb_df_wakeup_enabled) {
			mutex_exit(&wusb_dfp->wusb_df_mutex);

			(void) pm_raise_power(wusb_dfp->wusb_df_dip, 0,
			    USB_DEV_OS_FULL_PWR);
			if (usb_handle_remote_wakeup(wusb_dfp->wusb_df_dip,
			    USB_REMOTE_WAKEUP_DISABLE) != USB_SUCCESS) {
				USB_DPRINTF_L2(PRINT_MASK_PM,
				    wusb_dfp->wusb_df_log_hdl,
				    "wusb_df_destroy_power_mgmt: "
				    "Error disabling rmt wakeup");
			}
			mutex_enter(&wusb_dfp->wusb_df_mutex);

		}
	}
	mutex_exit(&wusb_dfp->wusb_df_mutex);

	/*
	 * Since remote wakeup is disabled now,
	 * no one can raise power
	 * and get to device once power is lowered here.
	 */
	(void) pm_lower_power(wusb_dfp->wusb_df_dip, 0, USB_DEV_OS_PWR_OFF);
	wusb_df_pm_idle_component(wusb_dfp);

	mutex_enter(&wusb_dfp->wusb_df_mutex);
	kmem_free(wusb_dfp->wusb_df_pm, sizeof (wusb_df_power_t));
	wusb_dfp->wusb_df_pm = NULL;
	mutex_exit(&wusb_dfp->wusb_df_mutex);
}


/*
 * wusb_df_serialize_access:
 *    Get the serial synchronization object before returning.
 *
 * Arguments:
 *    wusb_dfp - Pointer to wusb_df state structure
 *    waitsig - Set to:
 *	WUSB_DF_SER_SIG - to wait such that a signal can interrupt
 *	WUSB_DF_SER_NOSIG - to wait such that a signal cannot interrupt
 */
static int
wusb_df_serialize_access(wusb_df_state_t *wusb_dfp, boolean_t waitsig)
{
	int rval = 1;

	ASSERT(mutex_owned(&wusb_dfp->wusb_df_mutex));

	while (wusb_dfp->wusb_df_serial_inuse) {
		if (waitsig == WUSB_DF_SER_SIG) {
			rval = cv_wait_sig(&wusb_dfp->wusb_df_serial_cv,
			    &wusb_dfp->wusb_df_mutex);
		} else {
			cv_wait(&wusb_dfp->wusb_df_serial_cv,
			    &wusb_dfp->wusb_df_mutex);
		}
	}
	wusb_dfp->wusb_df_serial_inuse = B_TRUE;

	return (rval);
}


/*
 * wusb_df_release_access:
 *    Release the serial synchronization object.
 */
static void
wusb_df_release_access(wusb_df_state_t *wusb_dfp)
{
	ASSERT(mutex_owned(&wusb_dfp->wusb_df_mutex));
	wusb_dfp->wusb_df_serial_inuse = B_FALSE;
	cv_broadcast(&wusb_dfp->wusb_df_serial_cv);
}

/*
 * wusb_df_info:
 *	Get minor number, soft state structure, etc.
 */
/*ARGSUSED*/
static int
wusb_df_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
			void *arg, void **result)
{
	wusb_df_state_t	*wusb_dfp;
	int error = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((wusb_dfp = ddi_get_soft_state(wusb_df_statep,
		    getminor((dev_t)arg))) != NULL) {
			*result = wusb_dfp->wusb_df_dip;
			if (*result != NULL) {
				error = DDI_SUCCESS;
			}
		} else {
			*result = NULL;
		}
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

/* Free a chain of firmware headers */
static void
free_fw_dscs(struct fw_dsc *head)
{
	struct fw_dsc *next;

	while (head) {
		next = head->next;
		kmem_free(head, sizeof (fw_dsc_t));
		head = next;
	}
}

static unsigned int
char2int32(unsigned char *input)
{
	return ((*input) |
	    (*(input + 1) <<  8) |
	    (*(input + 2) << 16) |
	    (*(input + 3) << 24));
}

/*
 * download firmware or command by control pipe
 */
static int
wusb_df_send_data(wusb_df_state_t *wusbp,
		unsigned int address,
		const unsigned char *buffer,
		unsigned int size)
{
	int			error = DDI_FAILURE;
	usb_ctrl_setup_t	setup;
	usb_cb_flags_t		cb_flags;
	usb_cr_t		cr;
	mblk_t			*data = NULL;	/* data for USBA */
	uint16_t		data_len;	/* # of bytes want to write */
	uint_t			cnt;		/* # of xfered bytes */

	setup.bmRequestType	= USB_DEV_REQ_TYPE_VENDOR |
	    USB_DEV_REQ_HOST_TO_DEV | USB_DEV_REQ_RCPT_DEV;
	setup.bRequest		= 0xf0;
	setup.attrs		= 0;

	for (cnt = 0; cnt < size; cnt += data_len) {
		data_len = min(size - cnt, 512);

		/* reuse previous mblk if possible */
		if ((data = reallocb(data, data_len, 0)) == NULL) {

			return (USB_FAILURE);
		}
		bcopy(buffer + cnt, data->b_rptr, data_len);
		data->b_wptr += data_len;

		setup.wValue		= (address + cnt) & 0xffff;
		setup.wIndex		= ((address + cnt) >> 16) & 0xffff;
		setup.wLength		= data_len;
		error = usb_pipe_ctrl_xfer_wait(
		    wusbp->wusb_df_reg->dev_default_ph, &setup, &data,
		    &cr, &cb_flags, 0);
		if (error != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, wusbp->wusb_df_log_hdl,
			    "wusb_df_send_data: "
			    "send failed rval=%d, cr=%d, cb=0x%x\n",
			    error, cr, cb_flags);

			break;
		}
	}

	if (data) {
		freemsg(data);
	}

	return (error);
}

/*
 * find the firmware module's "_start", "_end" symbols
 * and get the size of firmware.
 */
static int
wusbdf_mod_loadsym(wusb_df_state_t *dfp, ddi_modhandle_t modp, char *mod,
	char *sym, char **start, size_t *len)
{
	char start_sym[256];
	char end_sym[256];
	char *p, *end;
	int rv;
	size_t n;

	(void) snprintf(start_sym, sizeof (start_sym), "%s_start", sym);
	(void) snprintf(end_sym, sizeof (end_sym), "%s_end", sym);

	p = (char *)ddi_modsym(modp, start_sym, &rv);
	if (p == NULL || rv != 0) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, dfp->wusb_df_log_hdl,
		    "mod %s: symbol %s not found\n", mod, start_sym);
		return (-1);
	}
	end = (char *)ddi_modsym(modp, end_sym, &rv);
	if (end == NULL || rv != 0) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, dfp->wusb_df_log_hdl,
		    "mod %s: symbol %s not found\n", mod, end_sym);
		return (-1);
	}
	n = end - p;

	*start = p;
	*len = n;

	return (0);
}

/* write firmware segments into device through control endpoint */
static int
wusb_df_fw_download(wusb_df_state_t *wusb_dfp)
{
	int		error = USB_SUCCESS;
	size_t		size  = 0, record_cnt = 0;
	unsigned char	*pdata, *data_end;
	unsigned char	*firmware_image;
	fw_dsc_t	*pdsc = NULL, *rcd_head = NULL, *tmpr = NULL;
	unsigned int	remaining_size;
	int		rv = 0;
	ddi_modhandle_t modp;
	char *firm_start;

	USB_DPRINTF_L3(PRINT_MASK_ATTA, wusb_dfp->wusb_df_log_hdl,
	    "Download firmware: %s", wusb_fwmod);

	/* allow user specify firmware in .conf? */

	/* see elfwrap(1) for how to turn firmware into loadable module */
	modp = ddi_modopen(wusb_fwmod, KRTLD_MODE_FIRST, &rv);
	if (modp == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, wusb_dfp->wusb_df_log_hdl,
		    "module %s not found", wusb_fwmod);

		error = USB_FAILURE;
		goto checkstatus;
	}

	rv = wusbdf_mod_loadsym(wusb_dfp, modp, wusb_fwmod, wusb_fwsym1,
	    &firm_start, &size);
	if (rv != 0) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, wusb_dfp->wusb_df_log_hdl,
		    "module(%s) loadsym error", wusb_fwmod);

		error = USB_FAILURE;
		goto checkstatus;
	}

	if (size >= MAX_DAT_FILE_SIZE) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, wusb_dfp->wusb_df_log_hdl,
		    "file size too big");

		error = USB_FAILURE;
		goto checkstatus;
	} else {
		firmware_image = (unsigned char *)kmem_alloc(size, KM_SLEEP);

		if (!firmware_image) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    wusb_dfp->wusb_df_log_hdl, "malloc failed");

			error = USB_FAILURE;
			goto checkstatus;
		}

		(void) memcpy(firmware_image, firm_start, size);
	}

	USB_DPRINTF_L3(PRINT_MASK_ATTA, wusb_dfp->wusb_df_log_hdl,
	    "file size = %d", (int)size);

	/*
	 * close the module, return if 1) fail to close or 2) encounter error
	 * when getting above symbol
	 */
checkstatus:
	if (modp != NULL)
		rv = ddi_modclose(modp);

	if ((rv != 0) || (error != USB_SUCCESS)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, wusb_dfp->wusb_df_log_hdl,
		    "modclose(%s) error", wusb_fwmod);

		return (USB_FAILURE);
	}

	/*
	 * BIN firmware has this format:
	 * address(4B) + length(4B) + data(Length Bytes) ... repeat
	 */
	pdata = firmware_image;
	data_end = firmware_image + size;
	while (pdata < data_end) {
		error = USB_FAILURE;
		pdsc = (fw_dsc_t *)kmem_zalloc(sizeof (fw_dsc_t), KM_SLEEP);

		/* hdr_offset = pdata - firmware_image; */
		remaining_size = data_end - pdata;

		if ((pdata + 8) > data_end) {
			kmem_free(pdsc, sizeof (fw_dsc_t));
			free_fw_dscs(rcd_head);
			break;
		}

		pdsc->next = NULL;
		pdsc->addr = char2int32(pdata);
		pdsc->size = 4 * char2int32(pdata + 4);
		pdsc->data = pdata + 8;
		if (pdsc->size > remaining_size) {
			kmem_free(pdsc, sizeof (fw_dsc_t));
			free_fw_dscs(rcd_head);
			break;
		}
		USB_DPRINTF_L3(PRINT_MASK_ATTA, wusb_dfp->wusb_df_log_hdl,
		    "address = 0x%x, length = 0x%x, "
		    "first 4 byte is : 0x%02x 0x%02x 0x%02x 0x%02x",
		    pdsc->addr, (int)pdsc->size, pdsc->data[0], pdsc->data[1],
		    pdsc->data[2], pdsc->data[3]);

		pdata += 8 + pdsc->size;
		if (rcd_head == NULL) {
			rcd_head = pdsc;
		} else {
			tmpr->next = pdsc;
		}

		tmpr = pdsc; /* tmp record */
		record_cnt ++;
		error = USB_SUCCESS;
	}

	USB_DPRINTF_L3(PRINT_MASK_ATTA, wusb_dfp->wusb_df_log_hdl,
	    "Start download firmware ...");
	for (pdsc = rcd_head; pdsc != NULL; pdsc = pdsc->next) {
		error = wusb_df_send_data(wusb_dfp, pdsc->addr,
		    pdsc->data, pdsc->size);
		if (error != USB_SUCCESS) {

			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    wusb_dfp->wusb_df_log_hdl, "Download failure!");
			break;
		}

		delay(drv_usectohz(1000));
	}

	USB_DPRINTF_L2(PRINT_MASK_ATTA, wusb_dfp->wusb_df_log_hdl,
	    "Download firmware end.");

	free_fw_dscs(rcd_head);
	kmem_free(firmware_image, size);

	return (error);
}


/*
 * Firmware download. Program device special registers and then call
 * wusb_df_fw_download() to download the true data.
 */
static int
wusb_df_firmware_download(wusb_df_state_t *wusbp)
{
	int error = USB_FAILURE;
	unsigned char buf[4];

	(void) memset(buf, 0, 4);
	/* program the device register to make it ready to accept fw */
	error = wusb_df_send_data(wusbp, 0x800000c0, buf, 4);
	if (error != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, wusbp->wusb_df_log_hdl,
		    "Fail init");
		return (error);
	}

	error = wusb_df_fw_download(wusbp);
	if (error != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, wusbp->wusb_df_log_hdl,
		    "Fail to download firmware");
		return (error);
	}

	buf[0] = 0x48;
	buf[1] = 0x56;
	buf[2] = 0x2c;
	buf[3] = 0x00;
	error = wusb_df_send_data(wusbp, 0x80008060, buf, 4);
	if (error != USB_SUCCESS) {
		return (error);
	}

	(void) memset(buf, 0, 4);
	buf[0] = 0x18;
	/* firmware download finished, program the device to lock fw */
	error = wusb_df_send_data(wusbp, 0x800000c0, buf, 4);

	return (error);
}
