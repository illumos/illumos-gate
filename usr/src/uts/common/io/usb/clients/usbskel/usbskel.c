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
 * Sample skeleton USB driver.
 * This driver provides a framework for developing USB client drivers.
 *
 * As a simplistic example, usbskel implements a data transfer by reading
 * raw configuration data, which every USB device has. It is expected that
 * the caller will issue an initial 4-byte read to get the total length of the
 * first configuration, and follow up with a second read, passing the total
 * length to read the entire configuration cloud.
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
 * access to the device is serialized.  Race conditions are an issue in
 * particular between disconnect event callbacks, detach, power, open
 * and data transfer callbacks.  The functions usbskel_serialize/release_access
 * are implemented for this purpose.
 *
 * Mutexes should never be held when making calls into USBA or when
 * sleeping.
 *
 * pm_busy_component and pm_idle_component mark the device as busy or idle to
 * the system.  These functions are paired, and are called only from code
 * bracketed by usbskel_serialize_access and usbskel_release_access.
 *
 * NOTE: PM and CPR will be enabled at a later release of S10.
 */

#if defined(lint) && !defined(DEBUG)
#define	DEBUG
#endif

#define	USBDRV_MAJOR_VER	2
#define	USBDRV_MINOR_VER	0

/* Uncomment to enable Power Management, when the OS PM framework is ready. */
/*
 * #ifndef USBSKEL_PM
 * #define	USBSKEL_PM
 * #endif
 */

/*
 * Uncomment to enable Check Point Resume (system suspend and resume) when the
 * OS CPR framework is ready.
 */
/*
 * #ifndef USBSKEL_CPR
 * #define	USBSKEL_CPR
 * #endif
 */

#include <sys/usb/usba.h>
#include <sys/strsun.h>
#include <sys/usb/clients/usbskel/usbskel.h>

int		usbskel_errlevel = USBSKEL_LOG_LOG;
static char	*name = "usbskl";	/* Driver name, used all over. */

/*
 * Boolean set to whether or not to dump the device's descriptor tree.
 * Can be changed with the usblog_dumptree property in a usbskel.conf file.
 */
static boolean_t	usbskel_dumptree;

/*
 * Function Prototypes
 */
static int	usbskel_attach(dev_info_t *, ddi_attach_cmd_t);
static int	usbskel_detach(dev_info_t *, ddi_detach_cmd_t);
static int	usbskel_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	usbskel_cleanup(dev_info_t *, usbskel_state_t *);
static int	usbskel_open(dev_t *, int, int, cred_t *);
static int	usbskel_close(dev_t, int, int, cred_t *);
static int	usbskel_read(dev_t, struct uio *uip_p, cred_t *);
static int	usbskel_strategy(struct buf *);
static void	usbskel_minphys(struct buf *);
static void	usbskel_normal_callback(usb_pipe_handle_t, usb_ctrl_req_t *);
static void	usbskel_exception_callback(usb_pipe_handle_t, usb_ctrl_req_t *);
static int	usbskel_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int	usbskel_disconnect_callback(dev_info_t *);
static int	usbskel_reconnect_callback(dev_info_t *);
static void	usbskel_restore_device_state(dev_info_t *, usbskel_state_t *);
static int	usbskel_cpr_suspend(dev_info_t *);
static void	usbskel_cpr_resume(dev_info_t *);
static int	usbskel_test_and_adjust_device_state(usbskel_state_t *);
static int	usbskel_open_pipes(usbskel_state_t *);
static void	usbskel_close_pipes(usbskel_state_t *);
static int	usbskel_pm_busy_component(usbskel_state_t *);
static void	usbskel_pm_idle_component(usbskel_state_t *);
static int	usbskel_power(dev_info_t *, int, int);
#ifdef USBSKEL_PM
static int	usbskel_init_power_mgmt(usbskel_state_t *);
static void	usbskel_destroy_power_mgmt(usbskel_state_t *);
#endif
static int	usbskel_serialize_access(usbskel_state_t *, boolean_t);
static void	usbskel_release_access(usbskel_state_t *);
static int	usbskel_check_same_device(usbskel_state_t *);

/*PRINTFLIKE3*/
static void	usbskel_log(usbskel_state_t *, int, char *, ...);

/* _NOTE is an advice for locklint.  Locklint checks lock use for deadlocks. */
_NOTE(SCHEME_PROTECTS_DATA("unique per call", usb_ctrl_req))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", buf))

/* module loading stuff */
struct cb_ops usbskel_cb_ops = {
	usbskel_open,		/* open  */
	usbskel_close,		/* close */
	usbskel_strategy,	/* strategy */
	nulldev,		/* print */
	nulldev,		/* dump */
	usbskel_read,		/* read */
	nodev,			/* write */
	usbskel_ioctl,		/* ioctl */
	nulldev,		/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* streamtab  */
	D_MP
};

static struct dev_ops usbskel_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	usbskel_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	usbskel_attach,		/* attach */
	usbskel_detach,		/* detach */
	nodev,			/* reset */
	&usbskel_cb_ops,	/* driver operations */
	NULL,			/* bus operations */
	usbskel_power,		/* power */
	ddi_quiesce_not_needed,	/* devo_quiesce */
};

static struct modldrv usbskel_modldrv =	{
	&mod_driverops,
	"USB skeleton driver",
	&usbskel_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&usbskel_modldrv,
	NULL
};

/* local variables */

/* Soft state structures */
#define	USBSKEL_INITIAL_SOFT_SPACE	1
static void *usbskel_statep;


/*
 * Module-wide initialization routine.
 */
int
_init(void)
{
	int rval;

	usbskel_log(NULL, USBSKEL_LOG_LOG, "usbskel _init");

	if ((rval = ddi_soft_state_init(&usbskel_statep,
	    sizeof (usbskel_state_t), USBSKEL_INITIAL_SOFT_SPACE)) != 0) {

		return (rval);
	}

	if ((rval = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&usbskel_statep);
	}

	usbskel_log(NULL, USBSKEL_LOG_LOG, "usbskel _init done");

	return (rval);
}


/*
 * Module-wide tear-down routine.
 */
int
_fini(void)
{
	int rval;

	usbskel_log(NULL, USBSKEL_LOG_LOG, "usbskel _fini");
	if ((rval = mod_remove(&modlinkage)) != 0) {

		return (rval);
	}

	ddi_soft_state_fini(&usbskel_statep);
	usbskel_log(NULL, USBSKEL_LOG_LOG, "usbskel _fini done");

	return (rval);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * usbskel_info:
 *	Get minor number, soft state structure, etc.
 */
/*ARGSUSED*/
static int
usbskel_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
			void *arg, void **result)
{
	usbskel_state_t	*usbskelp;
	int error = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((usbskelp = ddi_get_soft_state(usbskel_statep,
		    getminor((dev_t)arg))) != NULL) {
			*result = usbskelp->usbskel_dip;
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
 * usbskel_attach:
 *	Attach or resume.
 *
 *	For attach, initialize state and device, including:
 *		state variables, locks, device node
 *		device registration with system
 *		power management, hotplugging
 *	For resume, restore device and state
 */
static int
usbskel_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance = ddi_get_instance(dip);
	char			*devinst;
	int			devinstlen;
	usbskel_state_t		*usbskelp = NULL;
	usb_reg_parse_lvl_t	parse_level;
	usb_ep_data_t		*ep_datap;
	int			status;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		usbskel_cpr_resume(dip);

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

	if (ddi_soft_state_zalloc(usbskel_statep, instance) == DDI_SUCCESS) {
		usbskelp = ddi_get_soft_state(usbskel_statep, instance);
	}
	if (usbskelp == NULL)  {

		return (DDI_FAILURE);
	}

	usbskelp->usbskel_dip = dip;

	devinst = kmem_zalloc(USB_MAXSTRINGLEN, KM_SLEEP);
	devinstlen = snprintf(devinst, USB_MAXSTRINGLEN, "%s%d: ",
	    ddi_driver_name(dip), instance);

	usbskelp->usbskel_devinst = kmem_zalloc(devinstlen + 1, KM_SLEEP);
	(void) strncpy(usbskelp->usbskel_devinst, devinst, devinstlen);
	kmem_free(devinst, USB_MAXSTRINGLEN);

	usbskel_log(usbskelp, USBSKEL_LOG_LOG, "Attach: enter for attach");

	usbskel_dumptree = (ddi_prop_exists(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "usbskel_dumptree") == 1);

	usbskel_log(usbskelp, USBSKEL_LOG_LOG, "Tree will %sbe dumped",
	    ((usbskel_dumptree) ? "" : "not "));

	parse_level = (usb_reg_parse_lvl_t)ddi_prop_get_int(
	    DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "usbskel_parse_level", USB_PARSE_LVL_ALL);

	switch (parse_level) {
	case USB_PARSE_LVL_NONE:
		/* This driver needs a tree. */
		usbskel_log(usbskelp, USBSKEL_LOG_LOG,
		    "parse_level requested to NOT DUMP");
		parse_level = USB_PARSE_LVL_IF;
		/*FALLTHROUGH*/
	case USB_PARSE_LVL_IF:
		usbskel_log(usbskelp, USBSKEL_LOG_LOG,
		    "parse_level set to dump specific interface");
		break;
	case USB_PARSE_LVL_CFG:
		usbskel_log(usbskelp, USBSKEL_LOG_LOG,
		    "parse_level set to dump specific config");
		break;
	case USB_PARSE_LVL_ALL:
		usbskel_log(usbskelp, USBSKEL_LOG_LOG,
		    "parse_level set to dump everything");
		break;
	default:
		usbskel_log(usbskelp, USBSKEL_LOG_LOG,
		    "attach: parse_level will default to dump everything");
		parse_level = USB_PARSE_LVL_ALL;
	}

	if ((status = usb_client_attach(dip, USBDRV_VERSION, 0)) !=
	    USB_SUCCESS) {
		usbskel_log(usbskelp, USBSKEL_LOG_CONSOLE,
		    "attach: usb_client_attach failed, error code:%d", status);
		goto fail;
	}

	if ((status = usb_get_dev_data(dip, &usbskelp->usbskel_reg, parse_level,
	    0)) != USB_SUCCESS) {
		usbskel_log(usbskelp, USBSKEL_LOG_CONSOLE,
		    "attach: usb_get_dev_data failed, error code:%d", status);
		goto fail;
	}

	if (usbskel_dumptree) {
		(void) usb_print_descr_tree(
		    usbskelp->usbskel_dip, usbskelp->usbskel_reg);
	}

	/*
	 * Get the descriptor for an intr pipe at alt 0 of current interface.
	 * This will be used later to open the pipe.
	 */
	if ((ep_datap = usb_lookup_ep_data(dip, usbskelp->usbskel_reg,
	    usbskelp->usbskel_reg->dev_curr_if, 0, 0,
	    USB_EP_ATTR_INTR, USB_EP_DIR_IN)) == NULL) {
		usbskel_log(usbskelp, USBSKEL_LOG_CONSOLE,
		    "attach: Error getting intr endpoint descriptor");
		goto fail;
	}
	usbskelp->usbskel_intr_ep_descr = ep_datap->ep_descr;

	usb_free_descr_tree(dip, usbskelp->usbskel_reg);

	mutex_init(&usbskelp->usbskel_mutex, NULL, MUTEX_DRIVER,
	    usbskelp->usbskel_reg->dev_iblock_cookie);

	cv_init(&usbskelp->usbskel_serial_cv, NULL, CV_DRIVER, NULL);
	usbskelp->usbskel_serial_inuse = B_FALSE;

	usbskelp->usbskel_locks_initialized = B_TRUE;

	/* create minor node */
	if (ddi_create_minor_node(dip, name, S_IFCHR, instance,
	    "usb_skeleton", 0) != DDI_SUCCESS) {
		usbskel_log(usbskelp, USBSKEL_LOG_CONSOLE,
		    "attach: Error creating minor node");
		goto fail;
	}

	/* Put online before PM init as can get power managed afterward. */
	usbskelp->usbskel_dev_state = USB_DEV_ONLINE;

#ifdef USBSKEL_PM
	/* initialize power management */
	if (usbskel_init_power_mgmt(usbskelp) != USB_SUCCESS) {
		usbskel_log(usbskelp, USBSKEL_LOG_CONSOLE,
		    "attach: Could not initialize power mgmt");
	}
#endif

	if (usb_register_hotplug_cbs(dip, usbskel_disconnect_callback,
	    usbskel_reconnect_callback) != USB_SUCCESS) {

		goto fail;
	}

	/* Report device */
	ddi_report_dev(dip);

	return (DDI_SUCCESS);

fail:
	if (usbskelp) {
		(void) usbskel_cleanup(dip, usbskelp);
	}

	return (DDI_FAILURE);
}


/*
 * usbskel_detach:
 *	detach or suspend driver instance
 *
 * Note: in detach, only contention threads is from pm and disconnnect.
 */
static int
usbskel_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance = ddi_get_instance(dip);
	usbskel_state_t	*usbskelp =
	    ddi_get_soft_state(usbskel_statep, instance);
	int		rval = DDI_FAILURE;

	switch (cmd) {
	case DDI_DETACH:
		mutex_enter(&usbskelp->usbskel_mutex);
		ASSERT((usbskelp->usbskel_drv_state & USBSKEL_OPEN) == 0);
		mutex_exit(&usbskelp->usbskel_mutex);

		usbskel_log(usbskelp, USBSKEL_LOG_LOG,
		    "Detach: enter for detach");

		rval = usbskel_cleanup(dip, usbskelp);

		break;
	case DDI_SUSPEND:
		usbskel_log(usbskelp, USBSKEL_LOG_LOG,
		    "Detach: enter for suspend");

		rval = usbskel_cpr_suspend(dip);
	default:

		break;
	}

	return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}


/*
 * usbskel_cleanup:
 *	clean up the driver state for detach
 */
static int
usbskel_cleanup(dev_info_t *dip, usbskel_state_t *usbskelp)
{
	usbskel_log(usbskelp, USBSKEL_LOG_LOG, "Cleanup: enter");

	if (usbskelp->usbskel_locks_initialized) {

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
		mutex_enter(&usbskelp->usbskel_mutex);
		(void) usbskel_serialize_access(usbskelp, USBSKEL_SER_NOSIG);
		usbskel_release_access(usbskelp);
		mutex_exit(&usbskelp->usbskel_mutex);

#ifdef USBSKEL_PM
		/* All device activity has died down. */
		usbskel_destroy_power_mgmt(usbskelp);
#endif

		/* start dismantling */
		ddi_remove_minor_node(dip, NULL);

		cv_destroy(&usbskelp->usbskel_serial_cv);
		mutex_destroy(&usbskelp->usbskel_mutex);
	}

	usb_client_detach(dip, usbskelp->usbskel_reg);

	if (usbskelp->usbskel_devinst != NULL) {
		kmem_free(usbskelp->usbskel_devinst,
		    strlen(usbskelp->usbskel_devinst) + 1);
	}

	ddi_soft_state_free(usbskel_statep, ddi_get_instance(dip));
	ddi_prop_remove_all(dip);

	return (USB_SUCCESS);
}


/*ARGSUSED*/
static int
usbskel_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	usbskel_state_t	*usbskelp =
	    ddi_get_soft_state(usbskel_statep, getminor(*devp));
	int rval = 0;

	if (usbskelp == NULL) {

		return (ENXIO);
	}

	usbskel_log(usbskelp, USBSKEL_LOG_LOG, "open: enter");

	/*
	 * Keep it simple: one client at a time.
	 * Exclusive open only
	 */
	mutex_enter(&usbskelp->usbskel_mutex);
	if ((usbskelp->usbskel_drv_state & USBSKEL_OPEN) != 0) {
		mutex_exit(&usbskelp->usbskel_mutex);

		return (EBUSY);
	}
	usbskelp->usbskel_drv_state |= USBSKEL_OPEN;

	/*
	 * This is in place so that a disconnect or CPR doesn't interfere with
	 * pipe opens.
	 */
	if (usbskel_serialize_access(usbskelp, USBSKEL_SER_SIG) == 0) {
		usbskelp->usbskel_drv_state &= ~USBSKEL_OPEN;
		mutex_exit(&usbskelp->usbskel_mutex);

		return (EINTR);
	}

	mutex_exit(&usbskelp->usbskel_mutex);
	if (usbskel_pm_busy_component(usbskelp) != DDI_SUCCESS) {
		usbskel_log(usbskelp, USBSKEL_LOG_CONSOLE,
		    "open: Error raising power");
		rval = EIO;
		goto done;
	}
	mutex_enter(&usbskelp->usbskel_mutex);

	/* Fail if device is no longer ready. */
	if (usbskelp->usbskel_dev_state != USB_DEV_ONLINE) {
		mutex_exit(&usbskelp->usbskel_mutex);
		rval = EIO;
		goto done;
	}

	mutex_exit(&usbskelp->usbskel_mutex);
	if (usbskel_open_pipes(usbskelp) != USB_SUCCESS) {
		rval = EIO;
		goto done;
	}

	/* Device specific initialization goes here. */

done:
	if (rval != 0) {
		mutex_enter(&usbskelp->usbskel_mutex);
		usbskelp->usbskel_drv_state &= ~USBSKEL_OPEN;

		usbskel_release_access(usbskelp);
		mutex_exit(&usbskelp->usbskel_mutex);

		usbskel_pm_idle_component(usbskelp);
	} else {

		/* Device is idle until it is used. */
		mutex_enter(&usbskelp->usbskel_mutex);
		usbskel_release_access(usbskelp);
		mutex_exit(&usbskelp->usbskel_mutex);
	}

	return (rval);
}


/*ARGSUSED*/
static int
usbskel_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	usbskel_state_t	*usbskelp =
	    ddi_get_soft_state(usbskel_statep, getminor(dev));

	usbskel_log(usbskelp, USBSKEL_LOG_LOG, "close: enter");

	mutex_enter(&usbskelp->usbskel_mutex);
	(void) usbskel_serialize_access(usbskelp, USBSKEL_SER_NOSIG);
	mutex_exit(&usbskelp->usbskel_mutex);

	/* Perform device session cleanup here. */

	usbskel_log(usbskelp, USBSKEL_LOG_LOG, "close: cleaning up...");

	/*
	 * USBA automatically flushes/resets active non-default pipes
	 * when they are closed.  We can't reset default pipe, but we
	 * can wait for all requests on it from this dip to drain.
	 */
	(void) usb_pipe_drain_reqs(usbskelp->usbskel_dip,
	    usbskelp->usbskel_reg->dev_default_ph, 0,
	    USB_FLAGS_SLEEP, NULL, 0);

	mutex_enter(&usbskelp->usbskel_mutex);
	usbskel_close_pipes(usbskelp);

	usbskelp->usbskel_drv_state &= ~USBSKEL_OPEN;

	usbskel_release_access(usbskelp);
	mutex_exit(&usbskelp->usbskel_mutex);

	usbskel_pm_idle_component(usbskelp);

	return (0);
}


/*ARGSUSED*/
static int
usbskel_read(dev_t dev, struct uio *uio_p, cred_t *cred_p)
{
	usbskel_state_t	*usbskelp =
	    ddi_get_soft_state(usbskel_statep, getminor(dev));

	usbskel_log(usbskelp, USBSKEL_LOG_LOG, "read enter");

	return (physio(usbskel_strategy, NULL, dev, B_READ,
	    usbskel_minphys, uio_p));
}


/*
 * strategy:
 *	Called through physio to setup and start the transfer.
 */
static int
usbskel_strategy(struct buf *bp)
{
	usbskel_state_t *usbskelp = ddi_get_soft_state(usbskel_statep,
	    getminor(bp->b_edev));
	usb_pipe_handle_t pipe = usbskelp->usbskel_reg->dev_default_ph;
	usb_ctrl_req_t 	*request;
	int status;

	usbskel_log(usbskelp, USBSKEL_LOG_LOG, "strategy enter");

	/*
	 * Initialize residual count here in case transfer doesn't even get
	 * started.
	 */
	bp->b_resid = bp->b_bcount;

	/* Needed as this is a character driver. */
	if (bp->b_flags & (B_PHYS | B_PAGEIO)) {
		bp_mapin(bp);
	}

	mutex_enter(&usbskelp->usbskel_mutex);
	(void) usbskel_serialize_access(usbskelp, USBSKEL_SER_NOSIG);

	/* Make sure device has not been disconnected. */
	if (usbskelp->usbskel_dev_state != USB_DEV_ONLINE) {
		usbskel_log(usbskelp, USBSKEL_LOG_CONSOLE,
		    "usbskel_strategy: device can't be accessed");
		mutex_exit(&usbskelp->usbskel_mutex);
		goto fail;
	}
	mutex_exit(&usbskelp->usbskel_mutex);

	/*
	 * Since every device has raw configuration data, set up a control
	 * transfer to read the raw configuration data. In a production driver
	 * a read would probably be done on a pipe other than the default pipe,
	 * and would be reading data streamed by the device.
	 */

	/* Allocate and initialize the request. */
	if ((bp->b_private = request = usb_alloc_ctrl_req(
	    usbskelp->usbskel_dip, bp->b_bcount, USB_FLAGS_SLEEP)) ==
	    NULL) {
		usbskel_log(usbskelp, USBSKEL_LOG_CONSOLE,
		    "usbskel_read: Error allocating request");
		goto fail;
	}

	request->ctrl_bmRequestType =
	    USB_DEV_REQ_DEV_TO_HOST | USB_DEV_REQ_TYPE_STANDARD |
	    USB_DEV_REQ_RCPT_DEV;
	request->ctrl_bRequest = USB_REQ_GET_DESCR;

	/* For now, return only the first configuration. */
	request->ctrl_wValue = USB_DESCR_TYPE_SETUP_CFG | 0;
	request->ctrl_wIndex = 0;
	request->ctrl_wLength = bp->b_bcount;
	request->ctrl_timeout = 3;

	/* Autoclearing automatically set on default pipe. */
	request->ctrl_attributes = USB_ATTRS_SHORT_XFER_OK;

	request->ctrl_cb = usbskel_normal_callback;
	request->ctrl_exc_cb = usbskel_exception_callback;

	/* Hook the req to the bp, so callback knows where to put the data. */
	/* Now both bp and request know about each other. */
	request->ctrl_client_private = (usb_opaque_t)bp;

	/*
	 * Issue the request asynchronously.  Physio will block waiting for an
	 * "interrupt" which comes as a callback.  The callback calls biodone
	 * to release physio from its wait.
	 */
	if ((status = usb_pipe_ctrl_xfer(pipe, request, USB_FLAGS_NOSLEEP)) !=
	    USB_SUCCESS) {
		usbskel_log(usbskelp, USBSKEL_LOG_CONSOLE,
		    "usbskel_strategy: can't start transfer: status: %d",
		    status);
		goto fail;
	}

	/*
	 * Normally, usbskel_release_access() and usbskel_pm_idle_component
	 * is called in callback handler.
	 */

	return (0);

fail:
	mutex_enter(&usbskelp->usbskel_mutex);
	usbskel_release_access(usbskelp);
	mutex_exit(&usbskelp->usbskel_mutex);

	bioerror(bp, EIO);
	biodone(bp);

	return (0);
}


static void
usbskel_minphys(struct buf *bp)
{
	/* the config cloud is limited to 64k */
	if (bp->b_bcount > USBSKEL_REQUEST_SIZE) {
		bp->b_bcount = USBSKEL_REQUEST_SIZE;
	}
	minphys(bp);
}


/*
 * usbskel_normal_callback:
 *	Completion handler for successful transfer.
 *		Copy data from mblk returned by USBA, into
 *		buffer passed by physio, to get it back to user.
 *		Idle device
 *		update counts, etc.
 *		release request.
 *		signal completion via biodone
 */
/*ARGSUSED*/
static void
usbskel_normal_callback(usb_pipe_handle_t pipe, usb_ctrl_req_t *request)
{
	struct buf *bp 		= (struct buf *)request->ctrl_client_private;
	usbskel_state_t *usbskelp = ddi_get_soft_state(usbskel_statep,
	    getminor(bp->b_edev));
	mblk_t *data 		= request->ctrl_data;
	int amt_transferred 	= MBLKL(data);

	usbskel_log(usbskelp, USBSKEL_LOG_LOG, "normal callback enter");

	ASSERT((request->ctrl_cb_flags & USB_CB_INTR_CONTEXT) == 0);

	usbskel_log(usbskelp, USBSKEL_LOG_LOG,
	    "at entry, b_bcount = %lu, b_resid = %lu, trans = %d", bp->b_bcount,
	    bp->b_resid, amt_transferred);

	mutex_enter(&usbskelp->usbskel_mutex);
	usbskel_release_access(usbskelp);
	mutex_exit(&usbskelp->usbskel_mutex);

	/* Copy data out of mblk, into buffer. */
	if (amt_transferred) {
		bcopy(data->b_rptr, bp->b_un.b_addr, amt_transferred);
	}

	usbskel_log(usbskelp, USBSKEL_LOG_LOG,
	    "normal callback: transferring %d bytes from 0x%p to 0x%p",
	    amt_transferred, (void *)data, (void *)(bp->b_un.b_addr));

	/* Unhook. */
	bp->b_private = NULL;
	request->ctrl_client_private = NULL;

	/* Free request. */
	usb_free_ctrl_req(request);

	/* Finish up. */
	bp->b_resid = bp->b_bcount - amt_transferred;

	usbskel_log(usbskelp, USBSKEL_LOG_LOG,
	    "at exit, b_bcount = %lu, b_resid = %lu, trans = %d", bp->b_bcount,
	    bp->b_resid, amt_transferred);

	biodone(bp);
}


/*
 * usbskel_exception_callback:
 *	Completion handler for an erred transfer.
 *		Copy data from mblk returned by USBA, if any, into
 *		buffer passed by physio, to get it back to user.
 *		Idle device
 *		update counts, etc.
 *		release request.
 *		signal completion via biodone
 */
/*ARGSUSED*/
static void
usbskel_exception_callback(usb_pipe_handle_t pipe, usb_ctrl_req_t *request)
{
	struct buf *bp = (struct buf *)request->ctrl_client_private;
	usbskel_state_t *usbskelp = ddi_get_soft_state(usbskel_statep,
	    getminor(bp->b_edev));
	mblk_t 	*data = request->ctrl_data;
	int 	amt_transferred = (data ? MBLKL(data) : 0);

	usbskel_log(usbskelp, USBSKEL_LOG_LOG,
	    "at except cb entry, b_bcount = %lu, b_resid = %lu, trans = %d",
	    bp->b_bcount, bp->b_resid, amt_transferred);

	ASSERT((request->ctrl_cb_flags & USB_CB_INTR_CONTEXT) == 0);

	mutex_enter(&usbskelp->usbskel_mutex);
	usbskel_release_access(usbskelp);
	mutex_exit(&usbskelp->usbskel_mutex);

	/* Copy data, if any,  out of mblk, into buffer. */
	if (amt_transferred) {
		bcopy(data, bp->b_un.b_addr, amt_transferred);
	}
	bp->b_resid = bp->b_bcount - amt_transferred;

	usbskel_log(usbskelp, USBSKEL_LOG_LOG,
	    "exception cb: req = 0x%p, cr = %d\n\t cb_flags = 0x%x "
	    "data = 0x%p, amt xfered = %d", (void *)request,
	    request->ctrl_completion_reason, request->ctrl_cb_flags,
	    (void *)(request->ctrl_data), amt_transferred);

	/* Unhook */
	bp->b_private = NULL;
	request->ctrl_client_private = NULL;

	/* Free request. */
	usb_free_ctrl_req(request);

	usbskel_log(usbskelp, USBSKEL_LOG_LOG,
	    "at except cb exit, b_bcount = %lu, b_resid = %lu, trans = %d",
	    bp->b_bcount, bp->b_resid, amt_transferred);

	bioerror(bp, EIO);
	biodone(bp);
}


/*
 * XXX Empty ioctl for now.
 */
/*ARGSUSED*/
static int
usbskel_ioctl(dev_t dev, int cmd, intptr_t arg,
		int mode, cred_t *cred_p, int *rval_p)
{
	usbskel_state_t	*usbskelp =
	    ddi_get_soft_state(usbskel_statep, getminor(dev));

	usbskel_log(usbskelp, USBSKEL_LOG_LOG, "ioctl enter");

	return (ENOTTY);
}


/*
 * usbskel_disconnect_callback:
 *	Called when device hotplug-removed.
 *		Close pipes. (This does not attempt to contact device.)
 *		Set state to DISCONNECTED
 */
static int
usbskel_disconnect_callback(dev_info_t *dip)
{
	int instance = ddi_get_instance(dip);
	usbskel_state_t	*usbskelp =
	    ddi_get_soft_state(usbskel_statep, instance);

	usbskel_log(usbskelp, USBSKEL_LOG_LOG, "disconnect: enter");

	mutex_enter(&usbskelp->usbskel_mutex);
	(void) usbskel_serialize_access(usbskelp, USBSKEL_SER_NOSIG);

	/*
	 * Save any state of device or IO in progress required by
	 * usbskel_restore_device_state for proper device "thawing" later.
	 */
	usbskelp->usbskel_dev_state = USB_DEV_DISCONNECTED;

	usbskel_release_access(usbskelp);
	mutex_exit(&usbskelp->usbskel_mutex);

	return (USB_SUCCESS);
}


/*
 * usbskel_reconnect_callback:
 *	Called with device hotplug-inserted
 *		Restore state
 */
static int
usbskel_reconnect_callback(dev_info_t *dip)
{
	int instance = ddi_get_instance(dip);
	usbskel_state_t	*usbskelp =
	    ddi_get_soft_state(usbskel_statep, instance);

	usbskel_log(usbskelp, USBSKEL_LOG_LOG, "reconnect: enter");

	mutex_enter(&usbskelp->usbskel_mutex);
	(void) usbskel_serialize_access(usbskelp, USBSKEL_SER_NOSIG);
	usbskel_restore_device_state(dip, usbskelp);
	usbskel_release_access(usbskelp);
	mutex_exit(&usbskelp->usbskel_mutex);

	return (USB_SUCCESS);
}


/*
 * usbskel_restore_device_state:
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
usbskel_restore_device_state(dev_info_t *dip, usbskel_state_t *usbskelp)
{
	int rval;

	usbskel_log(usbskelp, USBSKEL_LOG_LOG,
	    "usbskel_restore_device_state: enter");

	ASSERT(mutex_owned(&usbskelp->usbskel_mutex));

	ASSERT((usbskelp->usbskel_dev_state == USB_DEV_DISCONNECTED) ||
	    (usbskelp->usbskel_dev_state == USB_DEV_SUSPENDED));

	mutex_exit(&usbskelp->usbskel_mutex);

	if (usbskel_pm_busy_component(usbskelp) != DDI_SUCCESS) {
		usbskel_log(usbskelp, USBSKEL_LOG_CONSOLE,
		    "usbskel_restore_device_state: Error raising power");

		goto fail;
	}

	/* Check if we are talking to the same device */
	if (usbskel_check_same_device(usbskelp) != USB_SUCCESS) {

		goto fail;
	}

	mutex_enter(&usbskelp->usbskel_mutex);
	if ((rval = usbskel_test_and_adjust_device_state(usbskelp)) !=
	    USB_SUCCESS) {
		mutex_exit(&usbskelp->usbskel_mutex);
		usbskel_log(usbskelp, USBSKEL_LOG_CONSOLE,
		    "usbskel_restore_device_state: "
		    "Error adjusting device: rval = %d", rval);

		goto fail;
	}
	usbskelp->usbskel_dev_state = USB_DEV_ONLINE;
	mutex_exit(&usbskelp->usbskel_mutex);

	if (usbskelp->usbskel_pm) {

		/* Failure here means device disappeared again. */
		if (usb_handle_remote_wakeup(dip, USB_REMOTE_WAKEUP_ENABLE) !=
		    USB_SUCCESS) {
			usbskel_log(usbskelp, USBSKEL_LOG_CONSOLE,
			    "device may or may not be accessible. "
			    "Please verify reconnection");
		}
		usbskel_pm_idle_component(usbskelp);
	}


	mutex_enter(&usbskelp->usbskel_mutex);

	usbskel_log(usbskelp, USBSKEL_LOG_LOG,
	    "usbskel_restore_device_state: end");

	return;

fail:
	/* change the device state from suspended to disconnected */
	mutex_enter(&usbskelp->usbskel_mutex);
	usbskelp->usbskel_dev_state = USB_DEV_DISCONNECTED;
	mutex_exit(&usbskelp->usbskel_mutex);

	usbskel_pm_idle_component(usbskelp);
	mutex_enter(&usbskelp->usbskel_mutex);
}


/*
 * usbskel_cpr_suspend:
 *	Clean up device.
 *	Wait for any IO to finish, then close pipes.
 *	Quiesce device.
 */
static int
usbskel_cpr_suspend(dev_info_t *dip)
{
	int		instance = ddi_get_instance(dip);
	usbskel_state_t	*usbskelp = ddi_get_soft_state(usbskel_statep,
	    instance);

	usbskel_log(usbskelp, USBSKEL_LOG_LOG, "suspend enter");

	/* Serialize to prevent races with detach, open, device access. */
	mutex_enter(&usbskelp->usbskel_mutex);
	(void) usbskel_serialize_access(usbskelp, USBSKEL_SER_NOSIG);
	mutex_exit(&usbskelp->usbskel_mutex);

	if (usbskel_pm_busy_component(usbskelp) != DDI_SUCCESS) {
		usbskel_log(usbskelp, USBSKEL_LOG_CONSOLE,
		    "suspend: Error raising power");
		usbskel_pm_idle_component(usbskelp);

		return (USB_FAILURE);
	}

	mutex_enter(&usbskelp->usbskel_mutex);

	/*
	 * Set dev_state to suspended so other driver threads don't start any
	 * new I/O.  In a real driver, there may be draining of requests done
	 * afterwards, and we don't want the draining to compete with new
	 * requests being queued.
	 */

	/* Don't suspend if the device is open. */
	if ((usbskelp->usbskel_drv_state & USBSKEL_OPEN) != 0) {
		usbskel_log(usbskelp, USBSKEL_LOG_LOG,
		    "suspend: Device is open.  Can't suspend");

		usbskel_release_access(usbskelp);
		mutex_exit(&usbskelp->usbskel_mutex);

		usbskel_pm_idle_component(usbskelp);

		return (USB_FAILURE);
	}

	/* Access device here to clean it up. */

	usbskelp->usbskel_dev_state = USB_DEV_SUSPENDED;

	/*
	 * Save any state of device required by usbskel_restore_device_state
	 * for proper device "thawing" later.
	 */

	usbskel_release_access(usbskelp);
	mutex_exit(&usbskelp->usbskel_mutex);

	usbskel_pm_idle_component(usbskelp);

	usbskel_log(usbskelp, USBSKEL_LOG_LOG, "suspend: success");

	return (USB_SUCCESS);
}


/*
 * usbskel_cpr_resume:
 *
 *	usbskel_restore_device_state marks success by putting device back online
 */
static void
usbskel_cpr_resume(dev_info_t *dip)
{
	int		instance = ddi_get_instance(dip);
	usbskel_state_t	*usbskelp = ddi_get_soft_state(usbskel_statep,
	    instance);

	usbskel_log(usbskelp, USBSKEL_LOG_LOG, "resume: enter");

	/*
	 * NOTE: A pm_raise_power in usbskel_restore_device_state will bring
	 * the power-up state of device into synch with the system.
	 */
	mutex_enter(&usbskelp->usbskel_mutex);
	usbskel_restore_device_state(dip, usbskelp);
	mutex_exit(&usbskelp->usbskel_mutex);
}


/*
 * usbskel_test_and_adjust_device_state:
 *	Place any device-specific initialization or sanity verification here.
 */
static int
usbskel_test_and_adjust_device_state(usbskel_state_t *usbskelp)
{
	usbskel_log(usbskelp, USBSKEL_LOG_LOG, "test and adjust enter");

	return (USB_SUCCESS);
}


/*
 * usbskel_open_pipes:
 *	Open any pipes other than default pipe.
 *	Mutex is assumed to be held.
 */
static int
usbskel_open_pipes(usbskel_state_t *usbskelp)
{

	int			rval = USB_SUCCESS;
	usb_pipe_policy_t	pipe_policy;
	usb_pipe_handle_t	pipe_handle;

	usbskel_log(usbskelp, USBSKEL_LOG_LOG, "open_pipes enter");

	bzero(&pipe_policy, sizeof (pipe_policy));

	/*
	 * Allow that pipes can support at least two asynchronous operations
	 * going on simultaneously.  Operations include asynchronous callbacks,
	 * resets, closures.
	 */
	pipe_policy.pp_max_async_reqs = 2;

	if ((rval = usb_pipe_open(usbskelp->usbskel_dip,
	    &usbskelp->usbskel_intr_ep_descr, &pipe_policy,
	    USB_FLAGS_SLEEP, &pipe_handle)) != USB_SUCCESS) {
		usbskel_log(usbskelp, USBSKEL_LOG_CONSOLE,
		    "usbskel_open_pipes: Error opening intr pipe: status = %d",
		    rval);
		rval = USB_FAILURE;
	}
	mutex_enter(&usbskelp->usbskel_mutex);
	usbskelp->usbskel_intr_ph = pipe_handle;
	mutex_exit(&usbskelp->usbskel_mutex);

	/*
	 * At this point, polling could be started on the pipe by making an
	 * asynchronous input request on the pipe.  Allocate a request by
	 * calling usb_alloc_intr_req(9F) with a zero length, initialize
	 * attributes with USB_ATTRS_SHORT_XFER_OK | USB_ATTRS_AUTOCLEARING,
	 * initialize length to be packetsize of the endpoint, specify the
	 * callbacks.  Pass this request to usb_pipe_intr_xfer to start polling.
	 * Call usb_pipe_stop_intr_polling(9F) to stop polling.
	 */

	return (rval);
}


/*
 * usbskel_close_pipes:
 *	Close pipes. Mutex is assumed to be held.
 */
/*ARGSUSED*/
static void
usbskel_close_pipes(usbskel_state_t *usbskelp)
{
	usbskel_log(usbskelp, USBSKEL_LOG_LOG, "close_pipes enter");

	if (usbskelp->usbskel_intr_ph) {
		usb_pipe_handle_t	pipe_handle = usbskelp->usbskel_intr_ph;
		usbskelp->usbskel_intr_ph = NULL;
		mutex_exit(&usbskelp->usbskel_mutex);

		usb_pipe_close(usbskelp->usbskel_dip, pipe_handle,
		    USB_FLAGS_SLEEP, NULL, 0);

		mutex_enter(&usbskelp->usbskel_mutex);
	}
}

static int
usbskel_pm_busy_component(usbskel_state_t *usbskelp)
{
	int rval = DDI_SUCCESS;

	mutex_enter(&usbskelp->usbskel_mutex);
	if (usbskelp->usbskel_pm != NULL) {
		usbskelp->usbskel_pm->usbskel_pm_busy++;
		mutex_exit(&usbskelp->usbskel_mutex);
		if (pm_busy_component(usbskelp->usbskel_dip, 0) ==
		    DDI_SUCCESS) {
			(void) pm_raise_power(
			    usbskelp->usbskel_dip, 0, USB_DEV_OS_FULL_PWR);
			mutex_enter(&usbskelp->usbskel_mutex);
		} else {
			mutex_enter(&usbskelp->usbskel_mutex);
			usbskelp->usbskel_pm->usbskel_pm_busy--;
			rval = DDI_FAILURE;
		}
	}
	mutex_exit(&usbskelp->usbskel_mutex);

	return (rval);
}

static void
usbskel_pm_idle_component(usbskel_state_t *usbskelp)
{
	mutex_enter(&usbskelp->usbskel_mutex);
	if (usbskelp->usbskel_pm != NULL) {
		mutex_exit(&usbskelp->usbskel_mutex);
		if (pm_idle_component(usbskelp->usbskel_dip, 0) ==
		    DDI_SUCCESS) {
			mutex_enter(&usbskelp->usbskel_mutex);
			ASSERT(usbskelp->usbskel_pm->usbskel_pm_busy > 0);
			usbskelp->usbskel_pm->usbskel_pm_busy--;
			mutex_exit(&usbskelp->usbskel_mutex);
		}
		mutex_enter(&usbskelp->usbskel_mutex);
		usbskel_log(usbskelp, USBSKEL_LOG_LOG,
		    "usbskel_pm_idle_component: %d",
		    usbskelp->usbskel_pm->usbskel_pm_busy);
	}
	mutex_exit(&usbskelp->usbskel_mutex);
}

/*
 * usbskel_power :
 *	Power entry point, the workhorse behind pm_raise_power, pm_lower_power,
 *	usb_req_raise_power and usb_req_lower_power.
 */
/* ARGSUSED */
static int
usbskel_power(dev_info_t *dip, int comp, int level)
{
	usbskel_state_t	*usbskelp;
	usbskel_power_t	*pm;
	int	rval = USB_FAILURE;

	usbskelp = ddi_get_soft_state(usbskel_statep, ddi_get_instance(dip));

	usbskel_log(usbskelp, USBSKEL_LOG_LOG,
	    "usbskel_power: enter: level = %d", level);

	mutex_enter(&usbskelp->usbskel_mutex);
	(void) usbskel_serialize_access(usbskelp, USBSKEL_SER_NOSIG);


	/*
	 * If we are disconnected/suspended, return success. Note that if we
	 * return failure, bringing down the system will hang when
	 * PM tries to power up all devices
	 */
	if ((usbskelp->usbskel_dev_state == USB_DEV_DISCONNECTED) ||
	    (usbskelp->usbskel_dev_state == USB_DEV_SUSPENDED)) {

		usbskel_log(usbskelp, USBSKEL_LOG_LOG,
		    "usbskel_power: disconnected/suspended "
		    "dev_state=%d", usbskelp->usbskel_dev_state);
		rval = USB_SUCCESS;

		goto done;
	}

	if (usbskelp->usbskel_pm == NULL) {

		goto done;
	}

	pm = usbskelp->usbskel_pm;

	/* Check if we are transitioning to a legal power level */
	if (USB_DEV_PWRSTATE_OK(pm->usbskel_pwr_states, level)) {
		usbskel_log(usbskelp, USBSKEL_LOG_CONSOLE,
		    "usbskel_power: illegal power level = %d "
		    "pwr_states: %x", level, pm->usbskel_pwr_states);

		goto done;
	}

	switch (level) {
	case USB_DEV_OS_PWR_OFF :
		/* fail attempt to go to low power if busy */
		if (pm->usbskel_pm_busy) {

			goto done;
		}
		if (usbskelp->usbskel_dev_state == USB_DEV_ONLINE) {
			usbskelp->usbskel_dev_state = USB_DEV_PWRED_DOWN;
			usbskelp->usbskel_pm->usbskel_current_power =
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
		usbskelp->usbskel_dev_state = USB_DEV_ONLINE;
		usbskelp->usbskel_pm->usbskel_current_power =
		    USB_DEV_OS_FULL_PWR;
		break;

	/* Levels 1 and 2 are not supported by this driver to keep it simple. */
	default:
		usbskel_log(usbskelp, USBSKEL_LOG_LOG,
		    "usbskel_power: power level %d not supported", level);
		break;
	}
done:
	usbskel_release_access(usbskelp);
	mutex_exit(&usbskelp->usbskel_mutex);

	return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}


#ifdef USBSKEL_PM
/*
 * usbskel_init_power_mgmt:
 *	Initialize power management and remote wakeup functionality.
 *	No mutex is necessary in this function as it's called only by attach.
 */
static int
usbskel_init_power_mgmt(usbskel_state_t *usbskelp)
{
	int 		rval = USB_FAILURE;

	usbskel_log(usbskelp, USBSKEL_LOG_LOG, "init_power_mgmt enter");

	/*
	 * If remote wakeup is not available you may not want to do
	 * power management.
	 */
	if (usb_handle_remote_wakeup(usbskelp->usbskel_dip,
	    USB_REMOTE_WAKEUP_ENABLE) == USB_SUCCESS) {
		usbskel_power_t *usbskelpm;
		uint_t		pwr_states;

		/* Allocate the state structure */
		usbskelpm = kmem_zalloc(sizeof (usbskel_power_t), KM_SLEEP);
		usbskelp->usbskel_pm = usbskelpm;
		usbskelpm->usbskel_state = usbskelp;
		usbskelpm->usbskel_pm_capabilities = 0;
		usbskelpm->usbskel_current_power = USB_DEV_OS_FULL_PWR;

		if ((rval = usb_create_pm_components(
		    usbskelp->usbskel_dip, &pwr_states)) == USB_SUCCESS) {

			usbskel_log(usbskelp, USBSKEL_LOG_LOG,
			    "usbskel_init_power_mgmt: created PM components");

			usbskelpm->usbskel_pwr_states =
			    (uint8_t)pwr_states;
			(void) pm_raise_power(
			    usbskelp->usbskel_dip, 0, USB_DEV_OS_FULL_PWR);
		} else {
			usbskel_log(usbskelp, USBSKEL_LOG_CONSOLE,
			    "usbskel_init_power_mgmt: create_pm_compts failed");
		}
	} else {
		usbskel_log(usbskelp, USBSKEL_LOG_CONSOLE,
		    "usbskel_init_power_mgmt: failure enabling remote wakeup");
	}
	usbskel_log(usbskelp, USBSKEL_LOG_LOG, "usbskel_init_power_mgmt: end");

	return (rval);
}


/*
 * usbskel_destroy_power_mgmt:
 *	Shut down and destroy power management and remote wakeup functionality.
 */
static void
usbskel_destroy_power_mgmt(usbskel_state_t *usbskelp)
{
	usbskel_log(usbskelp, USBSKEL_LOG_LOG, "destroy_power_mgmt enter");

	ASSERT(!mutex_owned(&usbskelp->usbskel_mutex));

	if (usbskelp->usbskel_pm) {
		(void) usbskel_pm_busy_component(usbskelp);

		mutex_enter(&usbskelp->usbskel_mutex);
		if (usbskelp->usbskel_dev_state != USB_DEV_DISCONNECTED) {
			int rval;

			mutex_exit(&usbskelp->usbskel_mutex);

			if ((rval = usb_handle_remote_wakeup(
			    usbskelp->usbskel_dip,
			    USB_REMOTE_WAKEUP_DISABLE)) !=
			    USB_SUCCESS) {
				usbskel_log(usbskelp, USBSKEL_LOG_CONSOLE,
				    "usbskel_destroy_power_mgmt: "
				    "Error disabling rmt wakeup: rval = %d",
				    rval);
			}
		} else {
			mutex_exit(&usbskelp->usbskel_mutex);
		}

		/*
		 * Since remote wakeup is disabled now,
		 * no one can raise power
		 * and get to device once power is lowered here.
		 */
		pm_lower_power(usbskelp->usbskel_dip, 0, USB_DEV_OS_PWR_OFF);
		usbskel_pm_idle_component(usbskelp);
		kmem_free(usbskelp->usbskel_pm, sizeof (usbskel_power_t));
		usbskelp->usbskel_pm = NULL;
	}
}
#endif


/*
 * usbskel_serialize_access:
 *    Get the serial synchronization object before returning.
 *
 * Arguments:
 *    usbskelp - Pointer to usbskel state structure
 *    waitsig - Set to:
 *	USBSKEL_SER_SIG - to wait such that a signal can interrupt
 *	USBSKEL_SER_NOSIG - to wait such that a signal cannot interrupt
 */
static int
usbskel_serialize_access(usbskel_state_t *usbskelp, boolean_t waitsig)
{
	int rval = 1;

	ASSERT(mutex_owned(&usbskelp->usbskel_mutex));

	while (usbskelp->usbskel_serial_inuse) {
		if (waitsig == USBSKEL_SER_SIG) {
			rval = cv_wait_sig(&usbskelp->usbskel_serial_cv,
			    &usbskelp->usbskel_mutex);
		} else {
			cv_wait(&usbskelp->usbskel_serial_cv,
			    &usbskelp->usbskel_mutex);
		}
	}
	usbskelp->usbskel_serial_inuse = B_TRUE;

	return (rval);
}


/*
 * usbskel_release_access:
 *    Release the serial synchronization object.
 */
static void
usbskel_release_access(usbskel_state_t *usbskelp)
{
	ASSERT(mutex_owned(&usbskelp->usbskel_mutex));
	usbskelp->usbskel_serial_inuse = B_FALSE;
	cv_broadcast(&usbskelp->usbskel_serial_cv);
}


/*
 * usbskel_check_same_device:
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
usbskel_check_same_device(usbskel_state_t *usbskelp)
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

	ASSERT(!mutex_owned(&usbskelp->usbskel_mutex));

	orig_usb_dev_descr = usbskelp->usbskel_reg->dev_descr;

	/* get the "new" device descriptor */
	rval = usb_pipe_ctrl_xfer_wait(usbskelp->usbskel_reg->dev_default_ph,
	    &setup, &pdata, &completion_reason, &cb_flags, USB_FLAGS_SLEEP);

	if (rval != USB_SUCCESS) {
		usbskel_log(usbskelp, USBSKEL_LOG_CONSOLE,
		    "usbskel_check_same_device: "
		    "getting device descriptor failed "
		    "rval=%d, cr=%d, cb=0x%x\n",
		    rval, completion_reason, cb_flags);
		freemsg(pdata);

		return (USB_FAILURE);
	}

	ASSERT(pdata != NULL);

	(void) usb_parse_data("2cs4c3s4c", pdata->b_rptr,
	    MBLKL(pdata), &usb_dev_descr,
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
	    (usbskelp->usbskel_reg->dev_serial != NULL)) {
		buf = kmem_alloc(USB_MAXSTRINGLEN, KM_SLEEP);
		if (usb_get_string_descr(usbskelp->usbskel_dip, USB_LANG_ID,
		    usb_dev_descr.iSerialNumber, buf,
		    USB_MAXSTRINGLEN) == USB_SUCCESS) {
			match =
			    (strcmp(buf,
			    usbskelp->usbskel_reg->dev_serial) == 0);
		}
		kmem_free(buf, USB_MAXSTRINGLEN);
	}

	if (match == B_FALSE) {
		usbskel_log(usbskelp, USBSKEL_LOG_CONSOLE,
		    "Device is not identical to the "
		    "previous one this port.\n"
		    "Please disconnect and reconnect");

		return (USB_INVALID_VERSION);
	}

	return (USB_SUCCESS);
}

/*
 * usbskel_log:
 *     Switchable logging to logfile and screen.
 *
 * Arguments:
 *     usbskelp: usbskel state pointer.
 *	   if NULL, driver name and instance won't print with the message
 *     msglevel:
 *         if USBSKEL_LOG_LOG, goes only to logfile.
 *		(usbskel_errlevel must be set to USBSKEL_LOG_LOG too.)
 *         if USBSKEL_LOG_CONSOLE, goes to both logfile and screen
 *		(usbskel_errlevel can be either value for this to work.)
 *     cmn_err_level: error level passed to cmn_err(9F)
 *     format and args: as you would call cmn_err, except without special
 *         first routing character.
 *
 * Do not call this in an interrupt context, since kmem_alloc can sleep.
 */
static void
usbskel_log(usbskel_state_t *usbskelp, int msglevel, char *formatarg, ...)
{
	va_list	ap;

	if (msglevel <= usbskel_errlevel) {
		char *format;
		int formatlen = strlen(formatarg) + 2;	/* '!' and NULL char */
		int devinst_start = 0;

		/* Allocate extra room if driver name and instance is present */
		if (usbskelp != NULL) {
			formatlen += strlen(usbskelp->usbskel_devinst);
		}

		format = kmem_zalloc(formatlen, KM_SLEEP);

		if (msglevel == USBSKEL_LOG_LOG) {
			format[0] = '!';
			devinst_start = 1;
		}

		if (usbskelp != NULL) {
			(void) strcpy(&format[devinst_start],
			    usbskelp->usbskel_devinst);
		}

		va_start(ap, formatarg);
		(void) strcat(format, formatarg);
		vcmn_err(CE_CONT, format, ap);
		va_end(ap);

		kmem_free(format, formatlen);
	}
}
