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
 * WUSB cable association driver
 *
 * This driver implements the cable association mechanism defined in
 * "Association Models Supplement to the Certified Wireless Universal
 * Serial Bus Specification 1.0". Cable association compliant devices,
 * i.e. with bInterfaceClass=0xEF, bInterfaceSubClass=0x03 and
 * bInterfaceProtocol=0x01(compatible names: "usbif,classef.3.1") will
 * be supported by this driver.
 *
 * The Cable Association Model uses the USB Cable-Based Association
 * Framework (CBAF). The basic operation under this framework is:
 *
 * - The user connects the device to the host using a USB cable.
 *
 * - The host detects that the device supports the CBAF and it is capable
 *   of configuring WUSB CC(Connection Context).
 *
 * - The host sends its CHID to the device, along with other information
 *
 * - If the device has a valid CC with a matching CHID, the device will
 *   respond to the host with the CDID from the CC.
 *
 * - As of this driver implementation, no matter if the CDID returned
 *   from the device matches the CDID in the host's copy of CC, we choose
 *   to skip further explicit user conditioning, generate a new CC and send
 *   it to the device.
 *
 * - Upon receiving the CC, the device must store the CC in non-volatile
 *   memory, replacing any existing CC with a matching CHID if it exists.
 *
 * - First time association is complete: Host has securely transferred the CC
 *   to the device
 *
 * CBAF requires device to use the default control endpoint to exchange
 * requests and data with host. Three control requests are defined by spec
 * and supported by this driver:
 *	- GET_ASSOCIATION_INFORMATION
 *	- GET_ASSOCIATION_REQUEST
 *	- SET_ASSOCIATION_RESPONSE
 *
 */

#if defined(lint) && !defined(DEBUG)
#define	DEBUG
#endif

#define	USBDRV_MAJOR_VER	2
#define	USBDRV_MINOR_VER	0

#include <sys/usb/usba.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/usb/clients/wusb_ca/wusb_ca_priv.h>
#include <sys/usb/clients/wusb_ca/wusb_ca.h>


uint_t	wusb_ca_errlevel = USB_LOG_L4;
uint_t  wusb_ca_errmask   = (uint_t)PRINT_MASK_ALL;
uint_t  wusb_ca_instance_debug = (uint_t)-1;

/*
 * Function Prototypes
 */
static int	wusb_ca_attach(dev_info_t *, ddi_attach_cmd_t);
static int	wusb_ca_detach(dev_info_t *, ddi_detach_cmd_t);
static int	wusb_ca_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	wusb_ca_cleanup(dev_info_t *, wusb_ca_state_t *);
static int	wusb_ca_open(dev_t *, int, int, cred_t *);
static int	wusb_ca_close(dev_t, int, int, cred_t *);
static int	wusb_ca_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int	wusb_ca_disconnect_callback(dev_info_t *);
static int	wusb_ca_reconnect_callback(dev_info_t *);
static void	wusb_ca_restore_device_state(dev_info_t *, wusb_ca_state_t *);

static int	wusb_ca_cpr_suspend(dev_info_t *);
static void	wusb_ca_cpr_resume(dev_info_t *);
static int	wusb_ca_pm_busy_component(wusb_ca_state_t *);
static void	wusb_ca_pm_idle_component(wusb_ca_state_t *);
static int	wusb_ca_power(dev_info_t *, int, int);
static void	wusb_ca_init_power_mgmt(wusb_ca_state_t *);
static void	wusb_ca_destroy_power_mgmt(wusb_ca_state_t *);

static int	wusb_ca_serialize_access(wusb_ca_state_t *, boolean_t);
static void	wusb_ca_release_access(wusb_ca_state_t *);
static int	wusb_ca_check_same_device(wusb_ca_state_t *);

static mblk_t	*trans_from_host_info(wusb_cbaf_host_info_t *);
static mblk_t	*trans_from_cc_data(wusb_cbaf_cc_data_t *);
static mblk_t	*trans_from_cc_fail(wusb_cbaf_cc_fail_t *);
static int	trans_to_device_info(wusb_ca_state_t *, mblk_t *,
		wusb_cbaf_device_info_t *);

/* _NOTE is an advice for locklint.  Locklint checks lock use for deadlocks. */
_NOTE(SCHEME_PROTECTS_DATA("unique per call", usb_ctrl_req))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", buf))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", msgb))
/* module loading stuff */
struct cb_ops wusb_ca_cb_ops = {
	wusb_ca_open,		/* open  */
	wusb_ca_close,		/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
	nulldev,		/* dump */
	nodev,			/* read */
	nodev,			/* write */
	wusb_ca_ioctl,		/* ioctl */
	nulldev,		/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* streamtab  */
	D_MP
};

static struct dev_ops wusb_ca_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	wusb_ca_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	wusb_ca_attach,		/* attach */
	wusb_ca_detach,		/* detach */
	nodev,			/* reset */
	&wusb_ca_cb_ops,	/* driver operations */
	NULL,			/* bus operations */
	wusb_ca_power,		/* power */
	ddi_quiesce_not_needed, /* quiesce */
};

static struct modldrv wusb_ca_modldrv =	{
	&mod_driverops,
	"WUSB Cable Association driver",
	&wusb_ca_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&wusb_ca_modldrv,
	NULL
};

/* local variables */

/* Soft state structures */
#define	WUSB_CA_INITIAL_SOFT_SPACE	1
static void *wusb_ca_statep;


/*
 * Module-wide initialization routine.
 */
int
_init(void)
{
	int rval;

	if ((rval = ddi_soft_state_init(&wusb_ca_statep,
	    sizeof (wusb_ca_state_t), WUSB_CA_INITIAL_SOFT_SPACE)) != 0) {

		return (rval);
	}

	if ((rval = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&wusb_ca_statep);
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

	ddi_soft_state_fini(&wusb_ca_statep);

	return (rval);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * wusb_ca_info:
 *	Get minor number, soft state structure, etc.
 */
/*ARGSUSED*/
static int
wusb_ca_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
			void *arg, void **result)
{
	wusb_ca_state_t	*wusb_cap;
	int error = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((wusb_cap = ddi_get_soft_state(wusb_ca_statep,
		    getminor((dev_t)arg))) != NULL) {
			*result = wusb_cap->wusb_ca_dip;
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


/*
 * wusb_ca_attach:
 *	Attach or resume.
 *
 *	For attach, initialize state and device, including:
 *		state variables, locks, device node
 *		device registration with system
 *		power management, hotplugging
 *	For resume, restore device and state
 */
static int
wusb_ca_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance = ddi_get_instance(dip);
	char			*devinst;
	int			devinstlen;
	wusb_ca_state_t		*wusb_cap = NULL;
	int			status;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		wusb_ca_cpr_resume(dip);

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

	if (ddi_soft_state_zalloc(wusb_ca_statep, instance) == DDI_SUCCESS) {
		wusb_cap = ddi_get_soft_state(wusb_ca_statep, instance);
	}
	if (wusb_cap == NULL)  {

		return (DDI_FAILURE);
	}

	wusb_cap->wusb_ca_dip = dip;

	devinst = kmem_zalloc(USB_MAXSTRINGLEN, KM_SLEEP);
	devinstlen = snprintf(devinst, USB_MAXSTRINGLEN, "%s%d: ",
	    ddi_driver_name(dip), instance);

	wusb_cap->wusb_ca_devinst = kmem_zalloc(devinstlen + 1, KM_SLEEP);
	(void) strncpy(wusb_cap->wusb_ca_devinst, devinst, devinstlen);
	kmem_free(devinst, USB_MAXSTRINGLEN);

	wusb_cap->wusb_ca_log_hdl = usb_alloc_log_hdl(dip, "wusb_ca",
	    &wusb_ca_errlevel, &wusb_ca_errmask, &wusb_ca_instance_debug, 0);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, wusb_cap->wusb_ca_log_hdl,
	    "Attach: enter for attach");



	if ((status = usb_client_attach(dip, USBDRV_VERSION, 0)) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, wusb_cap->wusb_ca_log_hdl,
		    "attach: usb_client_attach failed, error code:%d", status);
		goto fail;
	}

	if ((status = usb_get_dev_data(dip, &wusb_cap->wusb_ca_reg,
	    USB_PARSE_LVL_ALL, 0)) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, wusb_cap->wusb_ca_log_hdl,
		    "attach: usb_get_dev_data failed, error code:%d", status);
		goto fail;
	}

	usb_free_descr_tree(dip, wusb_cap->wusb_ca_reg);

	mutex_init(&wusb_cap->wusb_ca_mutex, NULL, MUTEX_DRIVER,
	    wusb_cap->wusb_ca_reg->dev_iblock_cookie);

	cv_init(&wusb_cap->wusb_ca_serial_cv, NULL, CV_DRIVER, NULL);
	wusb_cap->wusb_ca_serial_inuse = B_FALSE;

	wusb_cap->wusb_ca_locks_initialized = B_TRUE;

	/* create minor node */
	if (ddi_create_minor_node(dip, "wusb_ca", S_IFCHR, instance,
	    "wusb_ca", 0) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, wusb_cap->wusb_ca_log_hdl,
		    "attach: Error creating minor node");

		goto fail;
	}

	/* Put online before PM init as can get power managed afterward. */
	wusb_cap->wusb_ca_dev_state = USB_DEV_ONLINE;

	/* initialize power management */
	wusb_ca_init_power_mgmt(wusb_cap);

	if (usb_register_hotplug_cbs(dip, wusb_ca_disconnect_callback,
	    wusb_ca_reconnect_callback) != USB_SUCCESS) {

		goto fail;
	}

	/* Report device */
	ddi_report_dev(dip);

	return (DDI_SUCCESS);

fail:
	if (wusb_cap) {
		(void) wusb_ca_cleanup(dip, wusb_cap);
	}

	return (DDI_FAILURE);
}


/*
 * wusb_ca_detach:
 *	detach or suspend driver instance
 *
 * Note: in detach, only contention threads is from pm and disconnnect.
 */
static int
wusb_ca_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance = ddi_get_instance(dip);
	int		rval = DDI_FAILURE;
	wusb_ca_state_t	*wusb_cap;

	wusb_cap = ddi_get_soft_state(wusb_ca_statep, instance);
	switch (cmd) {
	case DDI_DETACH:
		mutex_enter(&wusb_cap->wusb_ca_mutex);
		ASSERT((wusb_cap->wusb_ca_drv_state & WUSB_CA_OPEN) == 0);
		mutex_exit(&wusb_cap->wusb_ca_mutex);

		USB_DPRINTF_L4(PRINT_MASK_ATTA, wusb_cap->wusb_ca_log_hdl,
		    "Detach: enter for detach");

		rval = wusb_ca_cleanup(dip, wusb_cap);

		break;
	case DDI_SUSPEND:
		USB_DPRINTF_L4(PRINT_MASK_ATTA, wusb_cap->wusb_ca_log_hdl,
		    "Detach: enter for suspend");

		rval = wusb_ca_cpr_suspend(dip);
	default:

		break;
	}

	return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}


/*
 * wusb_ca_cleanup:
 *	clean up the driver state for detach
 */
static int
wusb_ca_cleanup(dev_info_t *dip, wusb_ca_state_t *wusb_cap)
{
	USB_DPRINTF_L4(PRINT_MASK_ATTA, wusb_cap->wusb_ca_log_hdl,
	    "Cleanup: enter");

	if (wusb_cap->wusb_ca_locks_initialized) {

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
		mutex_enter(&wusb_cap->wusb_ca_mutex);
		(void) wusb_ca_serialize_access(wusb_cap, WUSB_CA_SER_NOSIG);
		wusb_ca_release_access(wusb_cap);
		mutex_exit(&wusb_cap->wusb_ca_mutex);

		/* All device activity has died down. */
		wusb_ca_destroy_power_mgmt(wusb_cap);

		/* start dismantling */
		ddi_remove_minor_node(dip, NULL);

		cv_destroy(&wusb_cap->wusb_ca_serial_cv);
		mutex_destroy(&wusb_cap->wusb_ca_mutex);
	}

	usb_client_detach(dip, wusb_cap->wusb_ca_reg);

	usb_free_log_hdl(wusb_cap->wusb_ca_log_hdl);

	if (wusb_cap->wusb_ca_devinst != NULL) {
		kmem_free(wusb_cap->wusb_ca_devinst,
		    strlen(wusb_cap->wusb_ca_devinst) + 1);
	}

	ddi_soft_state_free(wusb_ca_statep, ddi_get_instance(dip));
	ddi_prop_remove_all(dip);

	return (USB_SUCCESS);
}


/*ARGSUSED*/
static int
wusb_ca_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	wusb_ca_state_t	*wusb_cap =
	    ddi_get_soft_state(wusb_ca_statep, getminor(*devp));
	int rval = 0;

	if (wusb_cap == NULL) {

		return (ENXIO);
	}

	USB_DPRINTF_L4(PRINT_MASK_OPEN, wusb_cap->wusb_ca_log_hdl,
	    "open: enter");

	/*
	 * Keep it simple: one client at a time.
	 * Exclusive open only
	 */
	mutex_enter(&wusb_cap->wusb_ca_mutex);
	if ((wusb_cap->wusb_ca_drv_state & WUSB_CA_OPEN) != 0) {
		mutex_exit(&wusb_cap->wusb_ca_mutex);

		return (EBUSY);
	}
	wusb_cap->wusb_ca_drv_state |= WUSB_CA_OPEN;

	/*
	 * This is in place so that a disconnect or CPR doesn't interfere with
	 * pipe opens.
	 */
	if (wusb_ca_serialize_access(wusb_cap, WUSB_CA_SER_SIG) == 0) {
		wusb_cap->wusb_ca_drv_state &= ~WUSB_CA_OPEN;
		mutex_exit(&wusb_cap->wusb_ca_mutex);

		return (EINTR);
	}

	mutex_exit(&wusb_cap->wusb_ca_mutex);
	if (wusb_ca_pm_busy_component(wusb_cap) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, wusb_cap->wusb_ca_log_hdl,
		    "open: Error raising power");
		rval = EIO;
		goto done;
	}
	mutex_enter(&wusb_cap->wusb_ca_mutex);

	/* Fail if device is no longer ready. */
	if (wusb_cap->wusb_ca_dev_state != USB_DEV_ONLINE) {
		mutex_exit(&wusb_cap->wusb_ca_mutex);
		rval = EIO;
		goto done;
	}

	mutex_exit(&wusb_cap->wusb_ca_mutex);

done:
	if (rval != 0) {
		mutex_enter(&wusb_cap->wusb_ca_mutex);
		wusb_cap->wusb_ca_drv_state &= ~WUSB_CA_OPEN;

		wusb_ca_release_access(wusb_cap);
		mutex_exit(&wusb_cap->wusb_ca_mutex);

		wusb_ca_pm_idle_component(wusb_cap);
	} else {

		/* Device is idle until it is used. */
		mutex_enter(&wusb_cap->wusb_ca_mutex);
		wusb_ca_release_access(wusb_cap);
		mutex_exit(&wusb_cap->wusb_ca_mutex);
	}

	return (rval);
}


/*ARGSUSED*/
static int
wusb_ca_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	wusb_ca_state_t	*wusb_cap =
	    ddi_get_soft_state(wusb_ca_statep, getminor(dev));

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, wusb_cap->wusb_ca_log_hdl,
	    "close: enter");

	mutex_enter(&wusb_cap->wusb_ca_mutex);
	(void) wusb_ca_serialize_access(wusb_cap, WUSB_CA_SER_NOSIG);
	mutex_exit(&wusb_cap->wusb_ca_mutex);

	/* Perform device session cleanup here. */

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, wusb_cap->wusb_ca_log_hdl,
	    "close: cleaning up...");

	/*
	 * USBA automatically flushes/resets active non-default pipes
	 * when they are closed.  We can't reset default pipe, but we
	 * can wait for all requests on it from this dip to drain.
	 */
	(void) usb_pipe_drain_reqs(wusb_cap->wusb_ca_dip,
	    wusb_cap->wusb_ca_reg->dev_default_ph, 0,
	    USB_FLAGS_SLEEP, NULL, 0);

	mutex_enter(&wusb_cap->wusb_ca_mutex);

	wusb_cap->wusb_ca_drv_state &= ~WUSB_CA_OPEN;

	wusb_ca_release_access(wusb_cap);
	mutex_exit(&wusb_cap->wusb_ca_mutex);

	wusb_ca_pm_idle_component(wusb_cap);

	return (0);
}


/*
 * ioctl for cable association operations.
 */
/*ARGSUSED*/
static int
wusb_ca_ioctl(dev_t dev, int cmd, intptr_t arg,
		int mode, cred_t *cred_p, int *rval_p)
{
	wusb_ca_state_t	*wusb_cap =
	    ddi_get_soft_state(wusb_ca_statep, getminor(dev));

	USB_DPRINTF_L4(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
	    "ioctl enter");

	mutex_enter(&wusb_cap->wusb_ca_mutex);

	switch (cmd) {
	case CBAF_IOCTL_GET_ASSO_INFO:
		*rval_p = wusb_cbaf_get_asso_info(wusb_cap, arg, mode);

		break;
	case CBAF_IOCTL_GET_ASSO_REQS:
		*rval_p = wusb_cbaf_get_asso_reqs(wusb_cap, arg, mode);

		break;
	case CBAF_IOCTL_SET_HOST_INFO:
		*rval_p = wusb_cbaf_set_host_info(wusb_cap, arg, mode);

		break;
	case CBAF_IOCTL_GET_DEVICE_INFO:
		*rval_p = wusb_cbaf_get_device_info(wusb_cap, arg, mode);

		break;
	case CBAF_IOCTL_SET_CONNECTION:
		*rval_p = wusb_cbaf_set_connection(wusb_cap, arg, mode);

		break;
	case CBAF_IOCTL_SET_FAILURE:
		*rval_p = wusb_cbaf_set_failure(wusb_cap, arg, mode);

		break;
	default:

		*rval_p = EINVAL;
	}

	mutex_exit(&wusb_cap->wusb_ca_mutex);

	return (*rval_p);
}


/*
 * wusb_ca_disconnect_callback:
 *	Called when device hotplug-removed.
 *		Close pipes. (This does not attempt to contact device.)
 *		Set state to DISCONNECTED
 */
static int
wusb_ca_disconnect_callback(dev_info_t *dip)
{
	int instance = ddi_get_instance(dip);
	wusb_ca_state_t	*wusb_cap;

	wusb_cap = ddi_get_soft_state(wusb_ca_statep, instance);

	USB_DPRINTF_L4(PRINT_MASK_CB, wusb_cap->wusb_ca_log_hdl,
	    "disconnect: enter");

	mutex_enter(&wusb_cap->wusb_ca_mutex);
	(void) wusb_ca_serialize_access(wusb_cap, WUSB_CA_SER_NOSIG);

	/*
	 * Save any state of device or IO in progress required by
	 * wusb_ca_restore_device_state for proper device "thawing" later.
	 */
	wusb_cap->wusb_ca_dev_state = USB_DEV_DISCONNECTED;

	wusb_ca_release_access(wusb_cap);
	mutex_exit(&wusb_cap->wusb_ca_mutex);

	return (USB_SUCCESS);
}


/*
 * wusb_ca_reconnect_callback:
 *	Called with device hotplug-inserted
 *		Restore state
 */
static int
wusb_ca_reconnect_callback(dev_info_t *dip)
{
	int instance = ddi_get_instance(dip);
	wusb_ca_state_t	*wusb_cap;

	wusb_cap = ddi_get_soft_state(wusb_ca_statep, instance);

	USB_DPRINTF_L4(PRINT_MASK_CB, wusb_cap->wusb_ca_log_hdl,
	    "reconnect: enter");

	mutex_enter(&wusb_cap->wusb_ca_mutex);
	(void) wusb_ca_serialize_access(wusb_cap, WUSB_CA_SER_NOSIG);
	wusb_ca_restore_device_state(dip, wusb_cap);
	wusb_ca_release_access(wusb_cap);
	mutex_exit(&wusb_cap->wusb_ca_mutex);

	return (USB_SUCCESS);
}


/*
 * wusb_ca_restore_device_state:
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
wusb_ca_restore_device_state(dev_info_t *dip, wusb_ca_state_t *wusb_cap)
{
	USB_DPRINTF_L4(PRINT_MASK_CPR, wusb_cap->wusb_ca_log_hdl,
	    "wusb_ca_restore_device_state: enter");

	ASSERT(mutex_owned(&wusb_cap->wusb_ca_mutex));

	ASSERT((wusb_cap->wusb_ca_dev_state == USB_DEV_DISCONNECTED) ||
	    (wusb_cap->wusb_ca_dev_state == USB_DEV_SUSPENDED));

	mutex_exit(&wusb_cap->wusb_ca_mutex);

	if (wusb_ca_pm_busy_component(wusb_cap) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_CPR, wusb_cap->wusb_ca_log_hdl,
		    "wusb_ca_restore_device_state: Error raising power");

		goto fail;
	}

	/* Check if we are talking to the same device */
	if (wusb_ca_check_same_device(wusb_cap) != USB_SUCCESS) {
		wusb_ca_pm_idle_component(wusb_cap);

		goto fail;
	}

	mutex_enter(&wusb_cap->wusb_ca_mutex);
	wusb_cap->wusb_ca_dev_state = USB_DEV_ONLINE;

	if ((wusb_cap->wusb_ca_pm) &&
	    (wusb_cap->wusb_ca_pm->wusb_ca_remote_wakeup)) {
		mutex_exit(&wusb_cap->wusb_ca_mutex);

		/* Failure here means device disappeared again. */
		if (usb_handle_remote_wakeup(dip, USB_REMOTE_WAKEUP_ENABLE) !=
		    USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_CPR,
			    wusb_cap->wusb_ca_log_hdl,
			    "device may or may not be accessible. "
			    "Please verify reconnection");
		}

		mutex_enter(&wusb_cap->wusb_ca_mutex);
	}

	mutex_exit(&wusb_cap->wusb_ca_mutex);
	wusb_ca_pm_idle_component(wusb_cap);
	mutex_enter(&wusb_cap->wusb_ca_mutex);

	USB_DPRINTF_L4(PRINT_MASK_CPR, wusb_cap->wusb_ca_log_hdl,
	    "wusb_ca_restore_device_state: end");

	return;

fail:
	/* change the device state from suspended to disconnected */
	mutex_enter(&wusb_cap->wusb_ca_mutex);
	wusb_cap->wusb_ca_dev_state = USB_DEV_DISCONNECTED;
}


/*
 * wusb_ca_cpr_suspend:
 *	Clean up device.
 *	Wait for any IO to finish, then close pipes.
 *	Quiesce device.
 */
static int
wusb_ca_cpr_suspend(dev_info_t *dip)
{
	int		instance = ddi_get_instance(dip);
	wusb_ca_state_t	*wusb_cap;

	wusb_cap = ddi_get_soft_state(wusb_ca_statep, instance);

	USB_DPRINTF_L4(PRINT_MASK_CPR, wusb_cap->wusb_ca_log_hdl,
	    "suspend enter");

	/* Serialize to prevent races with detach, open, device access. */
	mutex_enter(&wusb_cap->wusb_ca_mutex);
	(void) wusb_ca_serialize_access(wusb_cap, WUSB_CA_SER_NOSIG);
	mutex_exit(&wusb_cap->wusb_ca_mutex);

	if (wusb_ca_pm_busy_component(wusb_cap) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_CPR, wusb_cap->wusb_ca_log_hdl,
		    "suspend: Error raising power");
		wusb_ca_pm_idle_component(wusb_cap);

		return (USB_FAILURE);
	}

	mutex_enter(&wusb_cap->wusb_ca_mutex);

	/*
	 * Set dev_state to suspended so other driver threads don't start any
	 * new I/O.
	 */

	/* Don't suspend if the device is open. */
	if ((wusb_cap->wusb_ca_drv_state & WUSB_CA_OPEN) != 0) {
		USB_DPRINTF_L2(PRINT_MASK_CPR, wusb_cap->wusb_ca_log_hdl,
		    "suspend: Device is open.  Can't suspend");

		wusb_ca_release_access(wusb_cap);
		mutex_exit(&wusb_cap->wusb_ca_mutex);

		wusb_ca_pm_idle_component(wusb_cap);

		return (USB_FAILURE);
	}

	wusb_cap->wusb_ca_dev_state = USB_DEV_SUSPENDED;

	wusb_ca_release_access(wusb_cap);
	mutex_exit(&wusb_cap->wusb_ca_mutex);

	wusb_ca_pm_idle_component(wusb_cap);

	USB_DPRINTF_L4(PRINT_MASK_CPR, wusb_cap->wusb_ca_log_hdl,
	    "suspend: success");

	return (USB_SUCCESS);
}


/*
 * wusb_ca_cpr_resume:
 *
 *	wusb_ca_restore_device_state marks success by putting device back online
 */
static void
wusb_ca_cpr_resume(dev_info_t *dip)
{
	int		instance = ddi_get_instance(dip);
	wusb_ca_state_t	*wusb_cap;

	wusb_cap = ddi_get_soft_state(wusb_ca_statep, instance);

	USB_DPRINTF_L4(PRINT_MASK_CPR, wusb_cap->wusb_ca_log_hdl,
	    "resume: enter");

	/*
	 * A pm_raise_power in wusb_ca_restore_device_state will bring
	 * the power-up state of device into synch with the system.
	 */
	mutex_enter(&wusb_cap->wusb_ca_mutex);
	wusb_ca_restore_device_state(dip, wusb_cap);
	mutex_exit(&wusb_cap->wusb_ca_mutex);
}


static int
wusb_ca_pm_busy_component(wusb_ca_state_t *wusb_cap)
{
	int rval = DDI_SUCCESS;

	mutex_enter(&wusb_cap->wusb_ca_mutex);
	if (wusb_cap->wusb_ca_pm != NULL) {
		wusb_cap->wusb_ca_pm->wusb_ca_pm_busy++;
		mutex_exit(&wusb_cap->wusb_ca_mutex);
		if (pm_busy_component(wusb_cap->wusb_ca_dip, 0) ==
		    DDI_SUCCESS) {
			(void) pm_raise_power(
			    wusb_cap->wusb_ca_dip, 0, USB_DEV_OS_FULL_PWR);
			mutex_enter(&wusb_cap->wusb_ca_mutex);
		} else {
			mutex_enter(&wusb_cap->wusb_ca_mutex);
			wusb_cap->wusb_ca_pm->wusb_ca_pm_busy--;
		}
	}
	mutex_exit(&wusb_cap->wusb_ca_mutex);

	return (rval);
}

static void
wusb_ca_pm_idle_component(wusb_ca_state_t *wusb_cap)
{
	mutex_enter(&wusb_cap->wusb_ca_mutex);
	if (wusb_cap->wusb_ca_pm != NULL) {
		mutex_exit(&wusb_cap->wusb_ca_mutex);
		if (pm_idle_component(wusb_cap->wusb_ca_dip, 0) ==
		    DDI_SUCCESS) {
			mutex_enter(&wusb_cap->wusb_ca_mutex);
			ASSERT(wusb_cap->wusb_ca_pm->wusb_ca_pm_busy > 0);
			wusb_cap->wusb_ca_pm->wusb_ca_pm_busy--;
			mutex_exit(&wusb_cap->wusb_ca_mutex);
		}
		mutex_enter(&wusb_cap->wusb_ca_mutex);
		USB_DPRINTF_L3(PRINT_MASK_PM, wusb_cap->wusb_ca_log_hdl,
		    "wusb_ca_pm_idle_component: %d",
		    wusb_cap->wusb_ca_pm->wusb_ca_pm_busy);
	}
	mutex_exit(&wusb_cap->wusb_ca_mutex);
}

/*
 * wusb_ca_power :
 *	Power entry point, the workhorse behind pm_raise_power, pm_lower_power,
 *	usb_req_raise_power and usb_req_lower_power.
 */
/* ARGSUSED */
static int
wusb_ca_power(dev_info_t *dip, int comp, int level)
{
	wusb_ca_state_t	*wusb_cap;
	wusb_ca_power_t	*pm;
	int	rval = USB_SUCCESS;

	wusb_cap = ddi_get_soft_state(wusb_ca_statep, ddi_get_instance(dip));

	USB_DPRINTF_L4(PRINT_MASK_PM, wusb_cap->wusb_ca_log_hdl,
	    "wusb_ca_power: enter: level = %d", level);

	mutex_enter(&wusb_cap->wusb_ca_mutex);
	(void) wusb_ca_serialize_access(wusb_cap, WUSB_CA_SER_NOSIG);

	/*
	 * If we are disconnected/suspended, return success. Note that if we
	 * return failure, bringing down the system will hang when PM tries
	 * to power up all devices
	 */
	if ((wusb_cap->wusb_ca_dev_state == USB_DEV_DISCONNECTED) ||
	    (wusb_cap->wusb_ca_dev_state == USB_DEV_SUSPENDED)) {

		USB_DPRINTF_L3(PRINT_MASK_PM, wusb_cap->wusb_ca_log_hdl,
		    "wusb_ca_power: disconnected/suspended "
		    "dev_state=%d", wusb_cap->wusb_ca_dev_state);
		rval = USB_SUCCESS;

		goto done;
	}

	if (wusb_cap->wusb_ca_pm == NULL) {

		goto done;
	}

	pm = wusb_cap->wusb_ca_pm;

	/* Check if we are transitioning to a legal power level */
	if (USB_DEV_PWRSTATE_OK(pm->wusb_ca_pwr_states, level)) {
		USB_DPRINTF_L3(PRINT_MASK_PM, wusb_cap->wusb_ca_log_hdl,
		    "wusb_ca_power: illegal power level = %d "
		    "pwr_states: %x", level, pm->wusb_ca_pwr_states);

		goto done;
	}

	switch (level) {
	case USB_DEV_OS_PWR_OFF :
		/* fail attempt to go to low power if busy */
		if (pm->wusb_ca_pm_busy) {

			goto done;
		}
		if (wusb_cap->wusb_ca_dev_state == USB_DEV_ONLINE) {
			(void) usb_set_device_pwrlvl3(wusb_cap->wusb_ca_dip);

			wusb_cap->wusb_ca_dev_state = USB_DEV_PWRED_DOWN;
			wusb_cap->wusb_ca_pm->wusb_ca_current_power =
			    USB_DEV_OS_PWR_OFF;
		}

		break;

	case USB_DEV_OS_FULL_PWR :
		/*
		 * PM framework tries to put us in full power during system
		 * shutdown. Handle USB_DEV_PWRED_DOWN only.
		 */
		if (wusb_cap->wusb_ca_dev_state == USB_DEV_PWRED_DOWN) {
			(void) usb_set_device_pwrlvl0(wusb_cap->wusb_ca_dip);
			wusb_cap->wusb_ca_dev_state = USB_DEV_ONLINE;
			wusb_cap->wusb_ca_pm->wusb_ca_current_power =
			    USB_DEV_OS_FULL_PWR;
		}

		break;

	/* Levels 1 and 2 are not supported by this driver to keep it simple. */
	default:
		USB_DPRINTF_L3(PRINT_MASK_PM, wusb_cap->wusb_ca_log_hdl,
		    "wusb_ca_power: power level %d not supported", level);
		break;
	}
done:
	wusb_ca_release_access(wusb_cap);
	mutex_exit(&wusb_cap->wusb_ca_mutex);

	/* Generally return success to make PM succeed */
	return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}


/*
 * wusb_ca_init_power_mgmt:
 *	Initialize power management and remote wakeup functionality.
 *	No mutex is necessary in this function as it's called only by attach.
 */
static void
wusb_ca_init_power_mgmt(wusb_ca_state_t *wusb_cap)
{
	wusb_ca_power_t *wusb_capm;
	uint_t		pwr_states;

	USB_DPRINTF_L4(PRINT_MASK_PM, wusb_cap->wusb_ca_log_hdl,
	    "init_power_mgmt enter");

	/* Allocate the state structure */
	wusb_capm = kmem_zalloc(sizeof (wusb_ca_power_t), KM_SLEEP);
	wusb_cap->wusb_ca_pm = wusb_capm;
	wusb_capm->wusb_ca_state = wusb_cap;
	wusb_capm->wusb_ca_pm_capabilities = 0;
	wusb_capm->wusb_ca_current_power = USB_DEV_OS_FULL_PWR;

	if (usb_create_pm_components(wusb_cap->wusb_ca_dip,
	    &pwr_states) == USB_SUCCESS) {
		USB_DPRINTF_L3(PRINT_MASK_PM, wusb_cap->wusb_ca_log_hdl,
		    "wusb_ca_init_power_mgmt: created PM components");

		wusb_capm->wusb_ca_pwr_states = (uint8_t)pwr_states;
		(void) pm_raise_power(wusb_cap->wusb_ca_dip, 0,
		    USB_DEV_OS_FULL_PWR);
	} else {
		USB_DPRINTF_L3(PRINT_MASK_PM, wusb_cap->wusb_ca_log_hdl,
		    "wusb_ca_init_power_mgmt: create_pm_compts failed");
	}

	/*
	 * If remote wakeup is not available you may not want to do
	 * power management.
	 */
	if (usb_handle_remote_wakeup(wusb_cap->wusb_ca_dip,
	    USB_REMOTE_WAKEUP_ENABLE) == USB_SUCCESS) {
		wusb_capm->wusb_ca_remote_wakeup = 1;
	} else {
		USB_DPRINTF_L3(PRINT_MASK_PM, wusb_cap->wusb_ca_log_hdl,
		    "wusb_ca_init_power_mgmt: failure enabling remote wakeup");
	}

	USB_DPRINTF_L4(PRINT_MASK_PM, wusb_cap->wusb_ca_log_hdl,
	    "wusb_ca_init_power_mgmt: end");
}


/*
 * wusb_ca_destroy_power_mgmt:
 *	Shut down and destroy power management and remote wakeup functionality.
 */
static void
wusb_ca_destroy_power_mgmt(wusb_ca_state_t *wusb_cap)
{
	wusb_ca_power_t *wusb_capm;

	USB_DPRINTF_L4(PRINT_MASK_PM, wusb_cap->wusb_ca_log_hdl,
	    "destroy_power_mgmt enter");

	ASSERT(!mutex_owned(&wusb_cap->wusb_ca_mutex));

	mutex_enter(&wusb_cap->wusb_ca_mutex);

	wusb_capm = wusb_cap->wusb_ca_pm;
	if (!wusb_capm) {
		mutex_exit(&wusb_cap->wusb_ca_mutex);

		return;
	}

	mutex_exit(&wusb_cap->wusb_ca_mutex);

	(void) wusb_ca_pm_busy_component(wusb_cap);

	mutex_enter(&wusb_cap->wusb_ca_mutex);
	if (wusb_cap->wusb_ca_dev_state != USB_DEV_DISCONNECTED) {
		int rval;

		if (wusb_capm->wusb_ca_remote_wakeup) {
			mutex_exit(&wusb_cap->wusb_ca_mutex);

			(void) pm_raise_power(wusb_cap->wusb_ca_dip, 0,
			    USB_DEV_OS_FULL_PWR);

			rval = usb_handle_remote_wakeup(
			    wusb_cap->wusb_ca_dip,
			    USB_REMOTE_WAKEUP_DISABLE);

			USB_DPRINTF_L2(PRINT_MASK_PM,
			    wusb_cap->wusb_ca_log_hdl,
			    "wusb_ca_destroy_power_mgmt: "
			    "Error disabling rmt wakeup: rval = %d",
			    rval);

			mutex_enter(&wusb_cap->wusb_ca_mutex);
		}
	}

	mutex_exit(&wusb_cap->wusb_ca_mutex);

	/*
	 * Since remote wakeup is disabled now,
	 * no one can raise power
	 * and get to device once power is lowered here.
	 */
	(void) pm_lower_power(wusb_cap->wusb_ca_dip, 0, USB_DEV_OS_PWR_OFF);
	wusb_ca_pm_idle_component(wusb_cap);

	mutex_enter(&wusb_cap->wusb_ca_mutex);
	kmem_free(wusb_cap->wusb_ca_pm, sizeof (wusb_ca_power_t));
	wusb_cap->wusb_ca_pm = NULL;
	mutex_exit(&wusb_cap->wusb_ca_mutex);
}


/*
 * wusb_ca_serialize_access:
 *    Get the serial synchronization object before returning.
 *
 * Arguments:
 *    wusb_cap - Pointer to wusb_ca state structure
 *    waitsig - Set to:
 *	WUSB_CA_SER_SIG - to wait such that a signal can interrupt
 *	WUSB_CA_SER_NOSIG - to wait such that a signal cannot interrupt
 */
static int
wusb_ca_serialize_access(wusb_ca_state_t *wusb_cap, boolean_t waitsig)
{
	int rval = 1;

	ASSERT(mutex_owned(&wusb_cap->wusb_ca_mutex));

	while (wusb_cap->wusb_ca_serial_inuse) {
		if (waitsig == WUSB_CA_SER_SIG) {
			rval = cv_wait_sig(&wusb_cap->wusb_ca_serial_cv,
			    &wusb_cap->wusb_ca_mutex);
		} else {
			cv_wait(&wusb_cap->wusb_ca_serial_cv,
			    &wusb_cap->wusb_ca_mutex);
		}
	}
	wusb_cap->wusb_ca_serial_inuse = B_TRUE;

	return (rval);
}


/*
 * wusb_ca_release_access:
 *    Release the serial synchronization object.
 */
static void
wusb_ca_release_access(wusb_ca_state_t *wusb_cap)
{
	ASSERT(mutex_owned(&wusb_cap->wusb_ca_mutex));
	wusb_cap->wusb_ca_serial_inuse = B_FALSE;
	cv_broadcast(&wusb_cap->wusb_ca_serial_cv);
}


/*
 * wusb_ca_check_same_device:
 *	Check if the device connected to the port is the same as
 *	the previous device that was in the port.  The previous device is
 *	represented by the dip on record for the port.	Print a message
 *	if the device is different.  Can block.
 *
 * return values:
 *	USB_SUCCESS:		same device
 *	USB_INVALID_VERSION	not same device
 *	USB_FAILURE:		Failure processing request
 */
static int
wusb_ca_check_same_device(wusb_ca_state_t *wusb_cap)
{
	usb_dev_descr_t		*orig_usb_dev_descr;
	usb_dev_descr_t		usb_dev_descr;
	mblk_t			*pdata = NULL;
	int			rval;
	char			*buf;
	usb_cr_t		completion_reason;
	usb_cb_flags_t		cb_flags;
	boolean_t		match = B_TRUE;

	usb_ctrl_setup_t	setup = {
	    USB_DEV_REQ_DEV_TO_HOST | USB_DEV_REQ_TYPE_STANDARD |
		USB_DEV_REQ_RCPT_DEV,
	    USB_REQ_GET_DESCR,		/* bRequest */
	    USB_DESCR_TYPE_SETUP_DEV,	/* wValue */
	    0,				/* wIndex */
	    USB_DEV_DESCR_SIZE,		/* wLength */
	    0				/* request attributes */
	};

	ASSERT(!mutex_owned(&wusb_cap->wusb_ca_mutex));

	orig_usb_dev_descr = wusb_cap->wusb_ca_reg->dev_descr;

	/* get the "new" device descriptor */
	rval = usb_pipe_ctrl_xfer_wait(wusb_cap->wusb_ca_reg->dev_default_ph,
	    &setup, &pdata, &completion_reason, &cb_flags, USB_FLAGS_SLEEP);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		    "wusb_ca_check_same_device: "
		    "getting device descriptor failed "
		    "rval=%d, cr=%d, cb=0x%x\n",
		    rval, completion_reason, cb_flags);
		freemsg(pdata);

		return (USB_FAILURE);
	}

	ASSERT(pdata != NULL);

	(void) usb_parse_data("2cs4c3s4c", pdata->b_rptr,
	    (intptr_t)pdata->b_wptr - (intptr_t)pdata->b_rptr, &usb_dev_descr,
	    sizeof (usb_dev_descr_t));

	freemsg(pdata);
	pdata = NULL;

	/* Always check the device descriptor length. */
	if (usb_dev_descr.bLength != USB_DEV_DESCR_SIZE) {
		match = B_FALSE;

	/* Always check the device descriptor. */
	} else if (bcmp(orig_usb_dev_descr,
	    (char *)&usb_dev_descr, USB_DEV_DESCR_SIZE) != 0) {
		match = B_FALSE;
	}

	/* if requested & this device has a serial number check and compare */
	if ((match == B_TRUE) &&
	    (wusb_cap->wusb_ca_reg->dev_serial != NULL)) {
		buf = kmem_alloc(USB_MAXSTRINGLEN, KM_SLEEP);
		if (usb_get_string_descr(wusb_cap->wusb_ca_dip, USB_LANG_ID,
		    usb_dev_descr.iSerialNumber, buf,
		    USB_MAXSTRINGLEN) == USB_SUCCESS) {
			match =
			    (strcmp(buf,
			    wusb_cap->wusb_ca_reg->dev_serial) == 0);
		}
		kmem_free(buf, USB_MAXSTRINGLEN);
	}

	if (match == B_FALSE) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		    "Device is not identical to the "
		    "previous one this port.\n"
		    "Please disconnect and reconnect");

		return (USB_INVALID_VERSION);
	}

	return (USB_SUCCESS);
}


/* get association info */
int
wusb_cbaf_get_asso_info(wusb_ca_state_t *wusb_cap, intptr_t arg, int flag)
{
	usb_pipe_handle_t	pipe = wusb_cap->wusb_ca_reg->dev_default_ph;
	usb_ctrl_setup_t	setup;
	usb_cr_t		completion_reason;
	usb_cb_flags_t		cb_flags;
	wusb_cbaf_asso_info_t	ca_info;
	mblk_t			*pdata = NULL;
	int rval;

	setup.bmRequestType = USB_DEV_REQ_DEV_TO_HOST |
	    USB_DEV_REQ_TYPE_CLASS | USB_DEV_REQ_RCPT_IF;
	setup.bRequest =  WUSB_CBAF_GET_ASSOCIATION_INFORMATION;
	setup.wValue = 0;
	setup.wIndex = 0;
	setup.wLength = WUSB_ASSO_INFO_SIZE;
	setup.attrs = USB_ATTRS_NONE;

	rval = usb_pipe_ctrl_xfer_wait(pipe, &setup, &pdata,
	    &completion_reason, &cb_flags, USB_FLAGS_SLEEP);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		"cr = %d cb_flags = %d", completion_reason, cb_flags);

		return (EIO);
	}
	if (pdata == NULL || msgsize(pdata) == 0) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		    "empty pdata");

		return (EIO);
	}

	rval = usb_parse_data("scs", pdata->b_rptr, WUSB_ASSO_INFO_SIZE,
	    &ca_info, sizeof (ca_info));
	if (rval <= 0) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		    "parse data");

		return (EIO);
	}

	rval = ddi_copyout(&ca_info, (void *)arg, sizeof (ca_info), flag);
	if (rval != 0) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		    "ddi_copyout");

		return (EIO);
	}

	freemsg(pdata);

	return (0);
}

/* get request array */
int
wusb_cbaf_get_asso_reqs(wusb_ca_state_t *wusb_cap, intptr_t arg, int flag)
{
	usb_pipe_handle_t	pipe = wusb_cap->wusb_ca_reg->dev_default_ph;
	usb_ctrl_setup_t	setup;
	usb_cr_t		completion_reason;
	usb_cb_flags_t		cb_flags;
	wusb_cbaf_asso_info_t	ca_info;
	wusb_cbaf_asso_req_t	*ca_reqs;
	mblk_t			*pdata = NULL;
	uchar_t			*data;
	int rval, reqs_size, i;

	rval = ddi_copyin((void *)arg, &ca_info, sizeof (ca_info), flag);
	if (rval != 0) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		    "ddi_copyin");

		return (EIO);
	}

	setup.bmRequestType = USB_DEV_REQ_DEV_TO_HOST |
	    USB_DEV_REQ_TYPE_CLASS | USB_DEV_REQ_RCPT_IF;
	setup.bRequest =  WUSB_CBAF_GET_ASSOCIATION_INFORMATION;
	setup.wValue = 0;
	setup.wIndex = 0;
	setup.wLength = ca_info.Length;
	setup.attrs = USB_ATTRS_NONE;

	rval = usb_pipe_ctrl_xfer_wait(pipe, &setup, &pdata,
	    &completion_reason, &cb_flags, USB_FLAGS_SLEEP);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		"cr = %d cb_flags = %d", completion_reason, cb_flags);

		return (EIO);
	}
	if (pdata == NULL || msgsize(pdata) == 0) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		    "empty pdata");

		return (EIO);
	}

	reqs_size = sizeof (wusb_cbaf_asso_req_t) *
	    ca_info.NumAssociationRequests;
	ca_reqs = (wusb_cbaf_asso_req_t	*)kmem_zalloc(reqs_size, KM_SLEEP);

	data = pdata->b_rptr + WUSB_ASSO_INFO_SIZE;
	for (i = 0; i < ca_info.NumAssociationRequests; i++) {
		rval = usb_parse_data("ccssl", data, WUSB_ASSO_REQUEST_SIZE,
		    &(ca_reqs[i]), sizeof (wusb_cbaf_asso_req_t));
		if (rval <= 0) {
			USB_DPRINTF_L2(PRINT_MASK_ALL,
			    wusb_cap->wusb_ca_log_hdl,
			    "parse data");

			return (EIO);
		}
		data += WUSB_ASSO_REQUEST_SIZE;
	}

	rval = ddi_copyout(ca_reqs, (void *)(arg + sizeof (ca_info)),
	    reqs_size, flag);
	if (rval != 0) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		    "ddi_copyout");

		return (EIO);
	}

	freemsg(pdata);
	kmem_free(ca_reqs, reqs_size);

	return (0);
}

/* set host info */
int
wusb_cbaf_set_host_info(wusb_ca_state_t *wusb_cap, intptr_t arg, int flag)
{
	usb_pipe_handle_t	pipe = wusb_cap->wusb_ca_reg->dev_default_ph;
	usb_ctrl_setup_t	setup;
	usb_cr_t		completion_reason;
	usb_cb_flags_t		cb_flags;
	wusb_cbaf_host_info_t	host_info;
	mblk_t			*pdata;
	int rval;

	rval = ddi_copyin((void *)arg, &host_info, sizeof (host_info), flag);
	if (rval != 0) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		    "ddi_copyin");

		return (EIO);
	}

	if ((pdata = trans_from_host_info(&host_info)) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		    "trans host info");

		return (EIO);
	}

	setup.bmRequestType = USB_DEV_REQ_TYPE_CLASS | USB_DEV_REQ_RCPT_IF;
	setup.bRequest =  WUSB_CBAF_SET_ASSOCIATION_RESPONSE;
	setup.wValue = 0x101;
	setup.wIndex = 0;
	setup.wLength = WUSB_HOST_INFO_SIZE;
	setup.attrs = USB_ATTRS_NONE;

	rval = usb_pipe_ctrl_xfer_wait(pipe, &setup, &pdata,
	    &completion_reason, &cb_flags, USB_FLAGS_SLEEP);

	freemsg(pdata);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		"cr = %d cb_flags = 0x%03x", completion_reason, cb_flags);

		return (EIO);
	}

	return (0);
}

/* get device info */
int
wusb_cbaf_get_device_info(wusb_ca_state_t *wusb_cap, intptr_t arg, int flag)
{
	usb_pipe_handle_t	pipe = wusb_cap->wusb_ca_reg->dev_default_ph;
	usb_ctrl_setup_t	setup;
	usb_cr_t		completion_reason;
	usb_cb_flags_t		cb_flags;
	wusb_cbaf_device_info_t	device_info;
	mblk_t			*pdata = NULL;
	int rval;

	setup.bmRequestType = USB_DEV_REQ_DEV_TO_HOST |
	    USB_DEV_REQ_TYPE_CLASS | USB_DEV_REQ_RCPT_IF;
	setup.bRequest =  WUSB_CBAF_GET_ASSOCIATION_REQUEST;
	setup.wValue = 0x200;
	setup.wIndex = 0;
	setup.wLength = WUSB_DEVICE_INFO_SIZE;
	setup.attrs = USB_ATTRS_NONE;

	rval = usb_pipe_ctrl_xfer_wait(pipe, &setup, &pdata,
	    &completion_reason, &cb_flags, USB_FLAGS_SLEEP);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		    "cr = %d cb_flags = %d", completion_reason, cb_flags);

		return (EIO);
	}
	if (pdata == NULL || msgsize(pdata) == 0) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		    "empty pdata");

		return (EIO);
	}

	if (trans_to_device_info(wusb_cap, pdata, &device_info) != 0) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		    "trans to device_info");

		return (EIO);
	}

	rval = ddi_copyout(&device_info, (void *)arg,
	    sizeof (device_info), flag);
	if (rval != 0) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		    "ddi_copyout");

		return (EIO);
	}

	freemsg(pdata);

	return (0);
}

/* set connection to device */
int
wusb_cbaf_set_connection(wusb_ca_state_t *wusb_cap, intptr_t arg, int flag)
{
	usb_pipe_handle_t	pipe = wusb_cap->wusb_ca_reg->dev_default_ph;
	usb_ctrl_setup_t	setup;
	usb_cr_t		completion_reason;
	usb_cb_flags_t		cb_flags;
	wusb_cbaf_cc_data_t	cc_data;
	mblk_t			*pdata = NULL;
	int rval;

	rval = ddi_copyin((void *)arg, &cc_data, sizeof (cc_data), flag);
	if (rval != 0) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		    "ddi_copyin");

		return (EIO);
	}

	if ((pdata = trans_from_cc_data(&cc_data)) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		    "trans cc data");

		return (EIO);
	}

	setup.bmRequestType = USB_DEV_REQ_TYPE_CLASS | USB_DEV_REQ_RCPT_IF;
	setup.bRequest =  WUSB_CBAF_SET_ASSOCIATION_RESPONSE;
	setup.wValue = 0x201;
	setup.wIndex = 0;
	setup.wLength = WUSB_CC_DATA_SIZE;
	setup.attrs = USB_ATTRS_NONE;

	rval = usb_pipe_ctrl_xfer_wait(pipe, &setup, &pdata,
	    &completion_reason, &cb_flags, USB_FLAGS_SLEEP);

	freemsg(pdata);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		"cr = %d cb_flags = %d", completion_reason, cb_flags);

		return (EIO);
	}

	return (0);
}

/* set failure */
int
wusb_cbaf_set_failure(wusb_ca_state_t *wusb_cap, intptr_t arg, int flag)
{
	usb_pipe_handle_t	pipe = wusb_cap->wusb_ca_reg->dev_default_ph;
	usb_ctrl_setup_t	setup;
	usb_cr_t		completion_reason;
	usb_cb_flags_t		cb_flags;
	wusb_cbaf_cc_fail_t	cc_fail;
	mblk_t			*pdata = NULL;
	int rval;

	rval = ddi_copyin((void *)arg, &cc_fail, sizeof (cc_fail), flag);
	if (rval != 0) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		    "ddi_copyin");

		return (EIO);
	}

	if ((pdata = trans_from_cc_fail(&cc_fail)) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		    "trans cc fail");

		return (EIO);
	}

	setup.bmRequestType = USB_DEV_REQ_TYPE_CLASS | USB_DEV_REQ_RCPT_IF;
	setup.bRequest =  WUSB_CBAF_SET_ASSOCIATION_RESPONSE;
	setup.wValue = 0x201;
	setup.wIndex = 0;
	setup.wLength = WUSB_CC_DATA_SIZE;
	setup.attrs = USB_ATTRS_NONE;

	rval = usb_pipe_ctrl_xfer_wait(pipe, &setup, &pdata,
	    &completion_reason, &cb_flags, USB_FLAGS_SLEEP);

	freemsg(pdata);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, wusb_cap->wusb_ca_log_hdl,
		    "cr = %d cb_flags = %d", completion_reason, cb_flags);

		return (EIO);
	}

	return (0);
}

#define	DRAW_BYTE(x, sh)	(((x) >> (sh * 8)) & 0xff)

static mblk_t *
trans_from_host_info(wusb_cbaf_host_info_t *host_info)
{
	mblk_t *pdata;

	if ((pdata = allocb(WUSB_HOST_INFO_SIZE, BPRI_HI)) == NULL) {

		return (NULL);
	}

	bcopy(fieldAssociationTypeId, pdata->b_wptr, 4);
	pdata->b_wptr += 4;
	*pdata->b_wptr++ = DRAW_BYTE(host_info->AssociationTypeId, 0);
	*pdata->b_wptr++ = DRAW_BYTE(host_info->AssociationTypeId, 1);

	bcopy(fieldAssociationSubTypeId, pdata->b_wptr, 4);
	pdata->b_wptr += 4;
	*pdata->b_wptr++ = DRAW_BYTE(host_info->AssociationSubTypeId, 0);
	*pdata->b_wptr++ = DRAW_BYTE(host_info->AssociationSubTypeId, 1);

	bcopy(fieldCHID, pdata->b_wptr, 4);
	pdata->b_wptr += 4;
	bcopy(host_info->CHID, pdata->b_wptr, 16);
	pdata->b_wptr += 16;

	bcopy(fieldLangID, pdata->b_wptr, 4);
	pdata->b_wptr += 4;
	*pdata->b_wptr++ = DRAW_BYTE(host_info->LangID, 0);
	*pdata->b_wptr++ = DRAW_BYTE(host_info->LangID, 1);

	bcopy(fieldHostFriendlyName, pdata->b_wptr, 4);
	pdata->b_wptr += 4;
	bcopy(host_info->HostFriendlyName, pdata->b_wptr, 64);
	pdata->b_wptr += 64;

	return (pdata);
}

static mblk_t *
trans_from_cc_data(wusb_cbaf_cc_data_t *cc_data)
{
	mblk_t *pdata;

	if ((pdata = allocb(WUSB_CC_DATA_SIZE, BPRI_HI)) == NULL) {

		return (NULL);
	}

	bcopy(fieldAssociationTypeId, pdata->b_wptr, 4);
	pdata->b_wptr += 4;
	*pdata->b_wptr++ = DRAW_BYTE(cc_data->AssociationTypeId, 0);
	*pdata->b_wptr++ = DRAW_BYTE(cc_data->AssociationTypeId, 1);

	bcopy(fieldAssociationSubTypeId, pdata->b_wptr, 4);
	pdata->b_wptr += 4;
	*pdata->b_wptr++ = DRAW_BYTE(cc_data->AssociationSubTypeId, 0);
	*pdata->b_wptr++ = DRAW_BYTE(cc_data->AssociationSubTypeId, 1);

	bcopy(fieldLength, pdata->b_wptr, 4);
	pdata->b_wptr += 4;
	*pdata->b_wptr++ = DRAW_BYTE(cc_data->Length, 0);
	*pdata->b_wptr++ = DRAW_BYTE(cc_data->Length, 1);
	*pdata->b_wptr++ = DRAW_BYTE(cc_data->Length, 2);
	*pdata->b_wptr++ = DRAW_BYTE(cc_data->Length, 3);

	bcopy(fieldConnectionContext, pdata->b_wptr, 4);
	pdata->b_wptr += 4;
	bcopy(&(cc_data->CC), pdata->b_wptr, 48);
	pdata->b_wptr += 48;

	bcopy(fieldBandGroups, pdata->b_wptr, 4);
	pdata->b_wptr += 4;
	*pdata->b_wptr++ = DRAW_BYTE(cc_data->BandGroups, 0);
	*pdata->b_wptr++ = DRAW_BYTE(cc_data->BandGroups, 1);

	return (pdata);
}

static mblk_t *
trans_from_cc_fail(wusb_cbaf_cc_fail_t *cc_fail)
{
	mblk_t *pdata;

	if ((pdata = allocb(WUSB_CC_FAILURE_SIZE, BPRI_HI)) == NULL) {

		return (NULL);
	}

	bcopy(fieldAssociationTypeId, pdata->b_wptr, 4);
	pdata->b_wptr += 4;
	*pdata->b_wptr++ = DRAW_BYTE(cc_fail->AssociationTypeId, 0);
	*pdata->b_wptr++ = DRAW_BYTE(cc_fail->AssociationTypeId, 1);

	bcopy(fieldAssociationSubTypeId, pdata->b_wptr, 4);
	pdata->b_wptr += 4;
	*pdata->b_wptr++ = DRAW_BYTE(cc_fail->AssociationSubTypeId, 0);
	*pdata->b_wptr++ = DRAW_BYTE(cc_fail->AssociationSubTypeId, 1);

	bcopy(fieldLength, pdata->b_wptr, 4);
	pdata->b_wptr += 4;
	*pdata->b_wptr++ = DRAW_BYTE(cc_fail->Length, 0);
	*pdata->b_wptr++ = DRAW_BYTE(cc_fail->Length, 1);
	*pdata->b_wptr++ = DRAW_BYTE(cc_fail->Length, 2);
	*pdata->b_wptr++ = DRAW_BYTE(cc_fail->Length, 3);

	bcopy(fieldAssociationStatus, pdata->b_wptr, 4);
	pdata->b_wptr += 4;
	*pdata->b_wptr++ = DRAW_BYTE(cc_fail->AssociationStatus, 0);
	*pdata->b_wptr++ = DRAW_BYTE(cc_fail->AssociationStatus, 1);
	*pdata->b_wptr++ = DRAW_BYTE(cc_fail->AssociationStatus, 2);
	*pdata->b_wptr++ = DRAW_BYTE(cc_fail->AssociationStatus, 3);

	return (pdata);
}

static int
trans_to_device_info(wusb_ca_state_t *wusb_cap,
    mblk_t *pdata, wusb_cbaf_device_info_t *device_info)
{
	int i, plen;
	void *paddr;
	char *mode;
	uchar_t *ptr = (uchar_t *)pdata->b_rptr;
	wusb_cbaf_info_item_t item;

	for (i = 0; i < 5; i++) {
		if (((int)usb_parse_data("ss", ptr, 4, &item,
		    sizeof (item))) <= 0) {
			USB_DPRINTF_L2(PRINT_MASK_ALL,
			    wusb_cap->wusb_ca_log_hdl,
			    "parse item[%d] failed", i);

			return (-1);
		}
		ptr += 4;

		switch (item.typeID) {
		case attrLength:
			mode = "l";
			paddr = &(device_info->Length);
			plen = sizeof (uint32_t);

			break;
		case attrCDID:
			mode = "16c";
			paddr = &(device_info->CDID);
			plen = 16 * sizeof (uint8_t);

			break;
		case attrBandGroups:
			mode = "s";
			paddr = &(device_info->BandGroups);
			plen = sizeof (uint16_t);

			break;
		case attrLangID:
			mode = "s";
			paddr = &(device_info->LangID);
			plen = sizeof (uint16_t);

			break;
		case attrDeviceFriendlyName:
			mode = "l";
			paddr = &(device_info->DeviceFriendlyName);
			plen = 64 * sizeof (char);

			break;
		default:
			USB_DPRINTF_L2(PRINT_MASK_ALL,
			    wusb_cap->wusb_ca_log_hdl,
			    "item[%d]: 0x%04x", i, item.typeID);

			return (-1);
		}

		if (((int)usb_parse_data(mode, ptr, item.length,
		    paddr, plen)) <= 0) {
			USB_DPRINTF_L2(PRINT_MASK_ALL,
			    wusb_cap->wusb_ca_log_hdl,
			    "item[%d]: 0x%04x", i, item.typeID);

			return (-1);
		}
		ptr += item.length;
	}

	return (0);
}
