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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Printer Class Driver for USB
 *
 * This driver supports devices that adhere to the USB Printer Class
 * specification 1.0.
 *
 * NOTE: This driver is not DDI compliant in that it uses undocumented
 * functions for logging (USB_DPRINTF_L*, usb_alloc_log_hdl, usb_free_log_hdl),
 * and serialization (usb_serialize_access, usb_release_access,
 * usb_init_serialization, usb_fini_serialization)
 *
 * Undocumented functions may go away in a future Solaris OS release.
 *
 * Please see the DDK for sample code of these functions, and for the usbskel
 * skeleton template driver which contains scaled-down versions of these
 * functions written in a DDI-compliant way.
 */

#if defined(lint) && !defined(DEBUG)
#define	DEBUG
#endif
#ifdef __lock_lint
#define	_MULTI_DATAMODEL
#endif

#define	USBDRV_MAJOR_VER	2
#define	USBDRV_MINOR_VER	0

#include <sys/usb/usba.h>
#include <sys/usb/usba/usba_ugen.h>
#include <sys/bpp_io.h>
#include <sys/ecppsys.h>
#include <sys/prnio.h>
#include <sys/errno.h>
#include <sys/usb/clients/printer/usb_printer.h>
#include <sys/usb/clients/printer/usbprn.h>
#include <sys/strsun.h>

/* Debugging support */
uint_t	usbprn_errmask		= (uint_t)PRINT_MASK_ALL;
uint_t	usbprn_errlevel 	= USB_LOG_L4;
uint_t	usbprn_instance_debug	= (uint_t)-1;

/* local variables */
static uint_t usbprn_ifcap =
	PRN_HOTPLUG | PRN_1284_DEVID | PRN_1284_STATUS | PRN_TIMEOUTS;

/*
 * Function Prototypes
 */
static int	usbprn_attach(dev_info_t *, ddi_attach_cmd_t);
static int	usbprn_detach(dev_info_t *, ddi_detach_cmd_t);
static int	usbprn_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static void	usbprn_cleanup(dev_info_t *, usbprn_state_t *);

static int	usbprn_get_descriptors(usbprn_state_t *);
static int	usbprn_get_device_id(usbprn_state_t *);
static int	usbprn_get_port_status(usbprn_state_t *);

static int	usbprn_open(dev_t *, int, int, cred_t *);
static int	usbprn_close(dev_t, int, int, cred_t *);
static int	usbprn_open_usb_pipes(usbprn_state_t *);
static void	usbprn_close_usb_pipes(usbprn_state_t *);
static int	usbprn_write(dev_t, struct uio *, cred_t *);
static int	usbprn_read(dev_t, struct uio *, cred_t *);
static int	usbprn_poll(dev_t, short, int, short *, struct pollhead **);

static int	usbprn_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static void	usbprn_minphys(struct buf *);
static int	usbprn_strategy(struct buf *);
static int	usbprn_setparms(usbprn_state_t *, intptr_t arg, int);
static int	usbprn_getparms(usbprn_state_t *, intptr_t, int);
static void	usbprn_geterr(usbprn_state_t *, intptr_t, int);
static int	usbprn_testio(usbprn_state_t  *, int);
static int	usbprn_ioctl_get_status(usbprn_state_t *);
static int	usbprn_prnio_get_status(usbprn_state_t *, intptr_t, int);
static int	usbprn_prnio_get_1284_status(usbprn_state_t *, intptr_t, int);
static int	usbprn_prnio_get_ifcap(usbprn_state_t *, intptr_t, int);
static int	usbprn_prnio_set_ifcap(usbprn_state_t *, intptr_t, int);
static int	usbprn_prnio_get_ifinfo(usbprn_state_t *, intptr_t, int);
static int	usbprn_prnio_get_1284_devid(usbprn_state_t *, intptr_t, int);
static int	usbprn_prnio_get_timeouts(usbprn_state_t *, intptr_t, int);
static int	usbprn_prnio_set_timeouts(usbprn_state_t *, intptr_t, int);

static void	usbprn_send_async_bulk_data(usbprn_state_t *);

static void	usbprn_bulk_xfer_cb(usb_pipe_handle_t, usb_bulk_req_t *);
static void	usbprn_bulk_xfer_exc_cb(usb_pipe_handle_t,
		    usb_bulk_req_t *);

static void	usbprn_biodone(usbprn_state_t *, int, int);
static char	usbprn_error_state(uchar_t);
static void	usbprn_print_long(usbprn_state_t *, char *, int);

/* event handling */
static	void	usbprn_restore_device_state(dev_info_t *, usbprn_state_t *);
static	int	usbprn_disconnect_event_cb(dev_info_t *);
static	int	usbprn_reconnect_event_cb(dev_info_t *);
static	int	usbprn_cpr_suspend(dev_info_t *);
static	void	usbprn_cpr_resume(dev_info_t *);

static usb_event_t usbprn_events = {
	usbprn_disconnect_event_cb,
	usbprn_reconnect_event_cb,
	NULL, NULL
};

/* PM handling */
static	void	usbprn_create_pm_components(dev_info_t *, usbprn_state_t *);
static	int	usbprn_power(dev_info_t *, int comp, int level);
static	int	usbprn_pwrlvl0(usbprn_state_t *);
static	int	usbprn_pwrlvl1(usbprn_state_t *);
static	int	usbprn_pwrlvl2(usbprn_state_t *);
static	int	usbprn_pwrlvl3(usbprn_state_t *);
static	void	usbprn_pm_busy_component(usbprn_state_t *);
static	void	usbprn_pm_idle_component(usbprn_state_t *);

/* module loading stuff */
struct cb_ops usbprn_cb_ops = {
	usbprn_open,		/* open  */
	usbprn_close,		/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
	nulldev,		/* dump */
	usbprn_read,		/* read */
	usbprn_write,		/* write */
	usbprn_ioctl,		/* ioctl */
	nulldev,		/* devmap */
	nulldev,		/* mmap */
	nulldev,		/* segmap */
	usbprn_poll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* streamtab  */
	D_64BIT | D_MP
};

static struct dev_ops usbprn_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	usbprn_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	usbprn_attach,		/* attach */
	usbprn_detach,		/* detach */
	nodev,			/* reset */
	&usbprn_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	usbprn_power		/* power */
};

static struct modldrv usbprnmodldrv =	{
	&mod_driverops,
	"USB printer client driver",
	&usbprn_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&usbprnmodldrv,
	NULL,
};

/* local variables */

/* soft state structures */
#define	USBPRN_INITIAL_SOFT_SPACE	1
static void *usbprn_statep;

static int usbprn_max_xfer_size = USBPRN_MAX_XFER_SIZE;

/* prnio support */
static const char usbprn_prnio_ifinfo[] = PRN_USB;


int
_init(void)
{
	int rval;

	if ((rval = ddi_soft_state_init(&usbprn_statep,
	    sizeof (usbprn_state_t), USBPRN_INITIAL_SOFT_SPACE)) != 0) {

		return (rval);
	}

	if ((rval = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&usbprn_statep);
	}

	return (rval);
}


int
_fini(void)
{
	int rval;

	if ((rval = mod_remove(&modlinkage)) != 0) {

		return (rval);
	}

	ddi_soft_state_fini(&usbprn_statep);

	return (rval);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * usbprn_info:
 *	Get minor number, soft state structure, etc.
 */
/*ARGSUSED*/
static int
usbprn_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
			void *arg, void **result)
{
	usbprn_state_t	*usbprnp;
	int		error = DDI_FAILURE;
	minor_t		minor = getminor((dev_t)arg);
	int		instance = USBPRN_MINOR_TO_INSTANCE(minor);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((usbprnp = ddi_get_soft_state(usbprn_statep,
		    instance)) != NULL) {
			*result = usbprnp->usbprn_dip;
			if (*result != NULL) {
				error = DDI_SUCCESS;
			}
		} else {
			*result = NULL;
		}

		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		error = DDI_SUCCESS;

		break;
	default:

		break;
	}

	return (error);
}


/*
 * usbprn_attach:
 *	Attach driver
 *	Get the descriptor information
 *	Get the device id
 *	Reset the device
 *	Get the port status
 */
static int
usbprn_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance = ddi_get_instance(dip);
	usbprn_state_t		*usbprnp = NULL;
	size_t			sz;
	usb_ugen_info_t 	usb_ugen_info;

	switch (cmd) {
	case DDI_ATTACH:

		break;
	case DDI_RESUME:
		usbprn_cpr_resume(dip);

		return (DDI_SUCCESS);
	default:

		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(usbprn_statep, instance) == DDI_SUCCESS) {
		usbprnp = ddi_get_soft_state(usbprn_statep, instance);
	}
	if (usbprnp == NULL)  {

		return (DDI_FAILURE);
	}

	usbprnp->usbprn_instance = instance;
	usbprnp->usbprn_dip	= dip;
	usbprnp->usbprn_log_handle = usb_alloc_log_hdl(dip,
	    "prn", &usbprn_errlevel,
	    &usbprn_errmask, &usbprn_instance_debug, 0);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, usbprnp->usbprn_log_handle,
	    "usbprn_attach: cmd=%x", cmd);

	if (usb_client_attach(dip, USBDRV_VERSION, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbprnp->usbprn_log_handle,
		    "usb_client_attach failed");

		goto fail;
	}
	if (usb_get_dev_data(dip, &usbprnp->usbprn_dev_data,
	    USB_PARSE_LVL_IF, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbprnp->usbprn_log_handle,
		    "usb_get_dev_data failed");

		goto fail;
	}

	/* Initialize locks and conditional variables */
	mutex_init(&usbprnp->usbprn_mutex, NULL, MUTEX_DRIVER,
	    usbprnp->usbprn_dev_data->dev_iblock_cookie);
	usbprnp->usbprn_write_acc = usb_init_serialization(dip,
	    USB_INIT_SER_CHECK_SAME_THREAD);
	usbprnp->usbprn_ser_acc = usb_init_serialization(dip,
	    USB_INIT_SER_CHECK_SAME_THREAD);
	usbprnp->usbprn_dev_acc = usb_init_serialization(dip, 0);

	usbprnp->usbprn_flags |= USBPRN_LOCKS_INIT_DONE;

	/* Obtain all the relevant descriptors */
	if (usbprn_get_descriptors(usbprnp) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbprnp->usbprn_log_handle,
		    "usb get descriptors failed");

		goto fail;
	}

	usbprnp->usbprn_def_ph = usbprnp->usbprn_dev_data->dev_default_ph;

	/* Obtain the device id */
	(void) usbprn_get_device_id(usbprnp);

	/* Get the port status */
	if (usbprn_get_port_status(usbprnp) != USB_SUCCESS) {
		/* some printers fail on the first */
		if (usbprn_get_port_status(usbprnp) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    usbprnp->usbprn_log_handle,
			    "usb get port status failed");

			goto fail;
		}
	}

	USB_DPRINTF_L3(PRINT_MASK_ATTA, usbprnp->usbprn_log_handle,
	    "usbprn_attach: printer status=0x%x", usbprnp->usbprn_last_status);

	if ((usbprnp->usbprn_last_status & USB_PRINTER_PORT_NO_ERROR) == 0) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbprnp->usbprn_log_handle,
		    "usbprn_attach: error occurred with the printer");
	}

	/*
	 * Create minor node based on information from the
	 * descriptors
	 */
	if ((ddi_create_minor_node(dip, "printer", S_IFCHR,
	    instance << USBPRN_MINOR_INSTANCE_SHIFT,
	    DDI_NT_PRINTER, 0)) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbprnp->usbprn_log_handle,
		    "usbprn_attach: cannot create minor node");

		goto fail;
	}

	usbprnp->usbprn_setparms.write_timeout = USBPRN_XFER_TIMEOUT;
	usbprnp->usbprn_setparms.mode =  ECPP_CENTRONICS;
	usbprnp->usbprn_dev_state = USB_DEV_ONLINE;

	if (usb_pipe_get_max_bulk_transfer_size(usbprnp->usbprn_dip, &sz)) {

		goto fail;
	}

	usbprnp->usbprn_max_bulk_xfer_size = sz;

	USB_DPRINTF_L4(PRINT_MASK_OPEN, usbprnp->usbprn_log_handle,
	    "usbprn_attach: xfer_size=0x%lx", sz);

	/* enable PM */
	usbprn_create_pm_components(dip, usbprnp);

	/* Register for events */
	if (usb_register_event_cbs(dip, &usbprn_events, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbprnp->usbprn_log_handle,
		    "usbprn_attach: usb_register_event_cbs failed");

		goto fail;
	}

	usb_free_dev_data(dip, usbprnp->usbprn_dev_data);
	usbprnp->usbprn_dev_data = NULL;

	if (usb_owns_device(dip)) {
		/* get a ugen handle */
		bzero(&usb_ugen_info, sizeof (usb_ugen_info));

		usb_ugen_info.usb_ugen_flags = 0;
		usb_ugen_info.usb_ugen_minor_node_ugen_bits_mask =
		    (dev_t)USBPRN_MINOR_UGEN_BITS_MASK;
		usb_ugen_info.usb_ugen_minor_node_instance_mask =
		    (dev_t)~USBPRN_MINOR_UGEN_BITS_MASK;
		usbprnp->usbprn_ugen_hdl =
		    usb_ugen_get_hdl(dip, &usb_ugen_info);

		if (usb_ugen_attach(usbprnp->usbprn_ugen_hdl, cmd) !=
		    USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    usbprnp->usbprn_log_handle,
			    "usb_ugen_attach failed");

			usb_ugen_release_hdl(usbprnp->usbprn_ugen_hdl);
			usbprnp->usbprn_ugen_hdl = NULL;
		}
	}

	/* Report device */
	ddi_report_dev(dip);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, usbprnp->usbprn_log_handle,
	    "usbprn_attach: done");

	return (DDI_SUCCESS);

fail:
	if (usbprnp) {
		usbprn_cleanup(dip, usbprnp);
	}

	return (DDI_FAILURE);
}


/*
 * usbprn_detach:
 *	detach or suspend driver instance
 */
static int
usbprn_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance = ddi_get_instance(dip);
	usbprn_state_t	*usbprnp;
	int		rval = DDI_FAILURE;

	usbprnp = ddi_get_soft_state(usbprn_statep, instance);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, usbprnp->usbprn_log_handle,
	    "usbprn_detach: cmd=%x", cmd);

	switch (cmd) {
	case DDI_DETACH:
		ASSERT((usbprnp->usbprn_flags & USBPRN_OPEN) == 0);
		usbprn_cleanup(dip, usbprnp);

		return (DDI_SUCCESS);
	case DDI_SUSPEND:
		rval = usbprn_cpr_suspend(dip);

		return ((rval == USB_SUCCESS) ? DDI_SUCCESS :
		    DDI_FAILURE);
	default:

		return (rval);
	}
}


/*
 * usbprn_cleanup:
 *	clean up the driver state
 */
static void
usbprn_cleanup(dev_info_t *dip, usbprn_state_t *usbprnp)
{
	usbprn_power_t	*usbprnpm = usbprnp->usbprn_pm;
	int		rval = 0;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, usbprnp->usbprn_log_handle,
	    "usbprn_cleanup: Start");

	ASSERT(usbprnp != NULL);

	if (usbprnp->usbprn_flags & USBPRN_LOCKS_INIT_DONE) {
		/*
		 * Disable the event callbacks first, after this point, event
		 * callbacks will never get called. Note we shouldn't hold
		 * mutex while unregistering events because there may be a
		 * competing event callback thread. Event callbacks are done
		 * with ndi mutex held and this can cause a potential deadlock.
		 */
		usb_unregister_event_cbs(dip, &usbprn_events);

		mutex_enter(&usbprnp->usbprn_mutex);
		if ((usbprnpm) &&
		    (usbprnp->usbprn_dev_state != USB_DEV_DISCONNECTED)) {

			mutex_exit(&usbprnp->usbprn_mutex);
			usbprn_pm_busy_component(usbprnp);
			mutex_enter(&usbprnp->usbprn_mutex);

			if (usbprnpm->usbprn_wakeup_enabled) {

				mutex_exit(&usbprnp->usbprn_mutex);

				(void) pm_raise_power(dip, 0,
				    USB_DEV_OS_FULL_PWR);

				if ((rval = usb_handle_remote_wakeup(dip,
				    USB_REMOTE_WAKEUP_DISABLE)) !=
				    USB_SUCCESS) {
					USB_DPRINTF_L2(PRINT_MASK_ALL,
					    usbprnp->usbprn_log_handle,
					    "usbprn_cleanup: "
					    "disable remote wakeup "
					    "failed, rval=%d", rval);
				}
			} else {
				mutex_exit(&usbprnp->usbprn_mutex);
			}

			(void) pm_lower_power(dip, 0, USB_DEV_OS_PWR_OFF);
			usbprn_pm_idle_component(usbprnp);

			mutex_enter(&usbprnp->usbprn_mutex);
		}

		ddi_remove_minor_node(dip, NULL);

		mutex_exit(&usbprnp->usbprn_mutex);

		if (usbprnp->usbprn_device_id) {
			kmem_free(usbprnp->usbprn_device_id,
			    usbprnp->usbprn_device_id_len + 1);
		}

		mutex_destroy(&usbprnp->usbprn_mutex);
		usb_fini_serialization(usbprnp->usbprn_dev_acc);
		usb_fini_serialization(usbprnp->usbprn_ser_acc);
		usb_fini_serialization(usbprnp->usbprn_write_acc);
	}

	if (usbprnpm) {
		kmem_free(usbprnpm, sizeof (usbprn_power_t));
	}

	USB_DPRINTF_L4(PRINT_MASK_ATTA, usbprnp->usbprn_log_handle,
	    "usbprn_cleanup: End");

	if (usbprnp->usbprn_ugen_hdl) {
		(void) usb_ugen_detach(usbprnp->usbprn_ugen_hdl, DDI_DETACH);
		usb_ugen_release_hdl(usbprnp->usbprn_ugen_hdl);
	}

	/* unregister with USBA */
	usb_client_detach(dip, usbprnp->usbprn_dev_data);

	usb_free_log_hdl(usbprnp->usbprn_log_handle);
	ddi_prop_remove_all(dip);
	ddi_soft_state_free(usbprn_statep, usbprnp->usbprn_instance);
}


/*
 * usbprn_cpr_suspend:
 *	prepare to be suspended
 */
static int
usbprn_cpr_suspend(dev_info_t *dip)
{
	usbprn_state_t	*usbprnp;
	int		instance = ddi_get_instance(dip);
	int		rval = USB_FAILURE;

	usbprnp = ddi_get_soft_state(usbprn_statep, instance);

	USB_DPRINTF_L4(PRINT_MASK_CPR, usbprnp->usbprn_log_handle,
	    "usbprn_cpr_suspend");

	(void) usb_serialize_access(usbprnp->usbprn_ser_acc, USB_WAIT, 0);

	mutex_enter(&usbprnp->usbprn_mutex);

	if ((usbprnp->usbprn_flags & USBPRN_OPEN) != 0) {
		mutex_exit(&usbprnp->usbprn_mutex);

		USB_DPRINTF_L2(PRINT_MASK_CPR,
		    usbprnp->usbprn_log_handle,
		    "usbprn_cpr_suspend: "
		    "Device is open.  Can't suspend");

	} else {
		usbprnp->usbprn_dev_state = USB_DEV_SUSPENDED;
		mutex_exit(&usbprnp->usbprn_mutex);

		USB_DPRINTF_L4(PRINT_MASK_CPR, usbprnp->usbprn_log_handle,
		    "usbprn_cpr_suspend: SUCCESS");
		rval = USB_SUCCESS;
	}
	usb_release_access(usbprnp->usbprn_ser_acc);

	if ((rval == USB_SUCCESS) && usbprnp->usbprn_ugen_hdl) {
		rval = usb_ugen_detach(usbprnp->usbprn_ugen_hdl,
		    DDI_SUSPEND);
	}

	return (rval);
}


static void
usbprn_cpr_resume(dev_info_t *dip)
{
	int		instance = ddi_get_instance(dip);
	usbprn_state_t	*usbprnp = ddi_get_soft_state(usbprn_statep, instance);

	USB_DPRINTF_L4(PRINT_MASK_CPR, usbprnp->usbprn_log_handle,
	    "usbprn_cpr_resume");

	/* Needed as power up state of dev is "unknown" to system */
	usbprn_pm_busy_component(usbprnp);
	(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

	usbprn_restore_device_state(dip, usbprnp);

	usbprn_pm_idle_component(usbprnp);

	if (usbprnp->usbprn_ugen_hdl) {
		(void) usb_ugen_attach(usbprnp->usbprn_ugen_hdl,
		    DDI_RESUME);
	}
}


/*
 * usbprn_get_descriptors:
 *	Obtain all the descriptors for the device
 */
static int
usbprn_get_descriptors(usbprn_state_t *usbprnp)
{
	int			interface;
	usb_client_dev_data_t	*dev_data =
	    usbprnp->usbprn_dev_data;
	usb_alt_if_data_t	*altif_data;
	usb_cfg_data_t		*cfg_data;
	usb_ep_data_t		*ep_data;
	dev_info_t		*dip = usbprnp->usbprn_dip;
	int			alt, rval;

	ASSERT(!mutex_owned(&usbprnp->usbprn_mutex));

	/*
	 * Section 4.2.1 of the spec says the printer could have
	 * multiple configurations.  This driver is just for one
	 * configuration interface and one interface.
	 */
	interface = dev_data->dev_curr_if;
	cfg_data = dev_data->dev_curr_cfg;

	/* find alternate that supports BI/UNI protocol */
	for (alt = 0; alt < cfg_data->cfg_if[interface].if_n_alt; alt++) {
		altif_data = &cfg_data->cfg_if[interface].if_alt[alt];

		if ((altif_data->altif_descr.bInterfaceProtocol ==
		    USB_PROTO_PRINTER_UNI) ||
		    (altif_data->altif_descr.bInterfaceProtocol ==
		    USB_PROTO_PRINTER_BI)) {

			break;
		} else {
			USB_DPRINTF_L3(PRINT_MASK_ATTA,
			    usbprnp->usbprn_log_handle,
			    "alternate %d not supported", alt);
		}
	}

	if (alt == cfg_data->cfg_if[interface].if_n_alt) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbprnp->usbprn_log_handle,
		    "usbprn_get_descriptors: no alternate");

		return (USB_FAILURE);
	}


	if ((rval = usb_set_alt_if(dip, interface, alt, USB_FLAGS_SLEEP,
	    NULL, NULL)) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbprnp->usbprn_log_handle,
		    "usbprn_get_descriptors: set alternate failed (%d)",
		    rval);

		return (rval);
	}

	usbprnp->usbprn_config_descr = cfg_data->cfg_descr;
	usbprnp->usbprn_if_descr = altif_data->altif_descr;

	/*
	 * find the endpoint descriptors. There will be a bulk-out endpoint
	 * and an optional bulk-in endpoint.
	 */
	if ((ep_data = usb_lookup_ep_data(dip, dev_data, interface, alt, 0,
	    USB_EP_ATTR_BULK, USB_EP_DIR_OUT)) != NULL) {
		usbprnp->usbprn_bulk_out.ps_ept_descr = ep_data->ep_descr;
	}
	if ((ep_data = usb_lookup_ep_data(dip, dev_data, interface, alt, 0,
	    USB_EP_ATTR_BULK, USB_EP_DIR_IN)) != NULL) {
		usbprnp->usbprn_bulk_in.ps_ept_descr = ep_data->ep_descr;
	}

	return (USB_SUCCESS);
}


/*
 * usbprn_get_device_id:
 *	Get the device id as described in 4.2.1 of the specification
 *	Lexmark printer returns 2 bytes when asked for 8 bytes
 *	We are ignoring data over and underrun.
 *	This is a synchronous function
 */
static int
usbprn_get_device_id(usbprn_state_t *usbprnp)
{
	int			len, n;
	mblk_t			*data = NULL;
	usb_cr_t		completion_reason;
	usb_cb_flags_t		cb_flags;
	int			rval = USB_FAILURE;
	usb_ctrl_setup_t setup = {
	    USB_DEV_REQ_DEV_TO_HOST |	/* bmRequestType */
	    USB_DEV_REQ_TYPE_CLASS |
	    USB_DEV_REQ_RCPT_IF,
	    USB_PRINTER_GET_DEVICE_ID,	/* bRequest */
	    0,				/* wValue: fill in later */
	    0,				/* wIndex: fill in later  */
	    0,				/* wLength: fill in later */
	    0				/* attributes */
	    };
	void			*ptr;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, usbprnp->usbprn_log_handle,
	    "usbprn_get_device_id: Begin");

	ASSERT(!mutex_owned(&usbprnp->usbprn_mutex));

	setup.wIndex = (usbprnp->usbprn_if_descr.bInterfaceNumber << 0x8) |
	    (usbprnp->usbprn_if_descr.bAlternateSetting);
	setup.wLength = USBPRN_MAX_DEVICE_ID_LENGTH;
	setup.wValue = usbprnp->usbprn_config_descr.iConfiguration;

	/*
	 * This is always a sync request as this will never
	 * be called in interrupt context.
	 * First get the first two bytes that gives the length
	 * of the device id string; then get the whole string
	 */
	if (usb_pipe_ctrl_xfer_wait(usbprnp->usbprn_def_ph, &setup,
	    &data, &completion_reason, &cb_flags, 0) != USB_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbprnp->usbprn_log_handle,
		    "usbprn_get_device_id: First sync command failed, cr=%d ",
		    completion_reason);

		/*
		 * some devices return more than requested. as long as
		 * we get the first two bytes, we can continue
		 */
		if (((completion_reason != USB_CR_DATA_OVERRUN) &&
		    (completion_reason != USB_CR_DATA_UNDERRUN)) ||
		    (data == NULL)) {

			goto done;
		}
	}

	ASSERT(data);
	n = MBLKL(data);

	if (n < 2) {

		goto done;
	}

	len = (((*data->b_rptr) << 0x8) | (*(data->b_rptr+1)));

	/*
	 * Std 1284-1994, chapter 7.6:
	 *	Length values of x'0000', x'0001' and x'0002' are reserved
	 */
	if (len < 3) {

		goto done;
	}

	USB_DPRINTF_L3(PRINT_MASK_ATTA, usbprnp->usbprn_log_handle,
	    "usbprn_get_device_id: device id length=%d", len);

	/* did we get enough data */
	if (len > n) {
		freemsg(data);
		data = NULL;

		setup.wLength = (uint16_t)len;
		if ((rval = usb_pipe_ctrl_xfer_wait(usbprnp->usbprn_def_ph,
		    &setup, &data, &completion_reason, &cb_flags, 0)) !=
		    USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    usbprnp->usbprn_log_handle,
			    "usbprn_get_device_id: 2nd command failed "
			    "cr=%d cb_flags=0x%x",
			    completion_reason, cb_flags);

			goto done;
		}

		ASSERT(len == MBLKL(data));
	}

	USB_DPRINTF_L3(PRINT_MASK_ATTA, usbprnp->usbprn_log_handle,
	    "usbprn_get_device_id: returned data length=%ld",
	    (long)(MBLKL(data)));

	ptr = kmem_zalloc(len + 1, KM_SLEEP);

	mutex_enter(&usbprnp->usbprn_mutex);
	usbprnp->usbprn_device_id_len = len;
	usbprnp->usbprn_device_id = ptr;

	bcopy(data->b_rptr, usbprnp->usbprn_device_id,
	    usbprnp->usbprn_device_id_len);
	usbprnp->usbprn_device_id[usbprnp->usbprn_device_id_len] = '\0';

	/* Length is in the first two bytes, dump string in logbuf */
	usbprn_print_long(usbprnp, usbprnp->usbprn_device_id + 2,
	    usbprnp->usbprn_device_id_len - 2);
	mutex_exit(&usbprnp->usbprn_mutex);

	rval = USB_SUCCESS;
done:
	freemsg(data);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, usbprnp->usbprn_log_handle,
	    "usbprn_get_device_id: rval=%d", rval);

	return (rval);
}


/*
 * usbprn_get_port_status:
 *	Get the port status.
 *	This is a synchronous function
 */
static int
usbprn_get_port_status(usbprn_state_t  *usbprnp)
{
	mblk_t			*data = NULL;
	usb_cr_t		completion_reason;
	usb_cb_flags_t		cb_flags;
	usb_ctrl_setup_t setup = {
	    USB_DEV_REQ_DEV_TO_HOST |	/* bmRequestType */
	    USB_DEV_REQ_TYPE_CLASS |
	    USB_DEV_REQ_RCPT_IF,
	    USB_PRINTER_GET_PORT_STATUS, /* bRequest */
	    0,				/* wValue */
	    0,				/* wIndex: fill in later  */
	    1,				/* wLength */
	    0				/* attributes */
	    };
	ASSERT(!mutex_owned(&usbprnp->usbprn_mutex));

	USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
	    "usbprn_get_port_status: Begin");

	setup.wIndex = usbprnp->usbprn_if_descr.bInterfaceNumber;
	if (usb_pipe_ctrl_xfer_wait(usbprnp->usbprn_def_ph,
	    &setup, &data, &completion_reason, &cb_flags, 0) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_get_port_status: Sync command failed "
		    "cr=%d cb_flags=0x%x", completion_reason, cb_flags);

		freemsg(data);

		return (USB_FAILURE);
	} else {
		mutex_enter(&usbprnp->usbprn_mutex);

		ASSERT(data);
		ASSERT(MBLKL(data) == 1);

		usbprnp->usbprn_last_status = *data->b_rptr;

		USB_DPRINTF_L3(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_get_port_status(sync): status=0x%x",
		    usbprnp->usbprn_last_status);

		mutex_exit(&usbprnp->usbprn_mutex);
		freemsg(data);

		return (USB_SUCCESS);
	}
}


/*
 * usbprn_open:
 *	Open the pipes
 */
/*ARGSUSED*/
static int
usbprn_open(dev_t *devp, int flag, int sflag, cred_t *credp)
{
	usbprn_state_t *usbprnp = ddi_get_soft_state(usbprn_statep,
	    USBPRN_MINOR_TO_INSTANCE(getminor(*devp)));
	int rval = 0;

	if (usbprnp == NULL) {

		return (ENXIO);
	}

	USB_DPRINTF_L4(PRINT_MASK_OPEN, usbprnp->usbprn_log_handle,
	    "usbprn_open:");

	(void) usb_serialize_access(usbprnp->usbprn_ser_acc, USB_WAIT, 0);

	/* Fail open on a disconnected device */
	mutex_enter(&usbprnp->usbprn_mutex);
	if (usbprnp->usbprn_dev_state == USB_DEV_DISCONNECTED) {
		mutex_exit(&usbprnp->usbprn_mutex);
		usb_release_access(usbprnp->usbprn_ser_acc);

		return (ENODEV);
	}

	/* cannot happen? but just in case */
	if (usbprnp->usbprn_dev_state == USB_DEV_SUSPENDED) {
		mutex_exit(&usbprnp->usbprn_mutex);
		usb_release_access(usbprnp->usbprn_ser_acc);

		return (EIO);
	}

	if (getminor(*devp) & USBPRN_MINOR_UGEN_BITS_MASK) {
		mutex_exit(&usbprnp->usbprn_mutex);

		rval = usb_ugen_open(usbprnp->usbprn_ugen_hdl,
		    devp, flag, sflag, credp);

		usb_release_access(usbprnp->usbprn_ser_acc);

		return (rval);
	}

	/* Exit if this instance is already open */
	if (usbprnp->usbprn_flags & USBPRN_OPEN) {
		mutex_exit(&usbprnp->usbprn_mutex);
		usb_release_access(usbprnp->usbprn_ser_acc);

		return (EBUSY);
	}
	mutex_exit(&usbprnp->usbprn_mutex);

	/* raise power */
	usbprn_pm_busy_component(usbprnp);
	(void) pm_raise_power(usbprnp->usbprn_dip,
	    0, USB_DEV_OS_FULL_PWR);
	/* initialize some softstate data */
	mutex_enter(&usbprnp->usbprn_mutex);
	usbprnp->usbprn_prn_timeouts.tmo_forward =
	    usbprnp->usbprn_setparms.write_timeout;
	usbprnp->usbprn_prn_timeouts.tmo_reverse = 0;
	mutex_exit(&usbprnp->usbprn_mutex);

	if (usbprn_open_usb_pipes(usbprnp) != USB_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbprnp->usbprn_log_handle,
		    "usbprn_open: pipe open failed");

		usb_release_access(usbprnp->usbprn_ser_acc);
		usbprn_pm_idle_component(usbprnp);

		return (EIO);
	}

	mutex_enter(&usbprnp->usbprn_mutex);
	usbprnp->usbprn_flags |= USBPRN_OPEN;

	/* set last status to online */
	usbprnp->usbprn_last_status &= ~USB_PRINTER_PORT_NO_SELECT;
	mutex_exit(&usbprnp->usbprn_mutex);

	usb_release_access(usbprnp->usbprn_ser_acc);

	USB_DPRINTF_L4(PRINT_MASK_OPEN, usbprnp->usbprn_log_handle,
	    "usbprn_open: End");

	return (rval);
}


/*
 * usbprn_close:
 *	Close the pipes
 */
/*ARGSUSED*/
static int
usbprn_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	usbprn_state_t	*usbprnp = ddi_get_soft_state(usbprn_statep,
	    USBPRN_MINOR_TO_INSTANCE(getminor(dev)));
	int		rval = 0;

	if (usbprnp == NULL) {

		return (ENXIO);
	}

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, usbprnp->usbprn_log_handle,
	    "usbprn_close:");

	if (getminor(dev) & USBPRN_MINOR_UGEN_BITS_MASK) {
		rval = usb_ugen_close(usbprnp->usbprn_ugen_hdl,
		    dev, flag, otyp, credp);

		return (rval);
	}

	/* avoid races with connect/disconnect */
	(void) usb_serialize_access(usbprnp->usbprn_ser_acc, USB_WAIT, 0);
	(void) usb_serialize_access(usbprnp->usbprn_dev_acc, USB_WAIT, 0);

	/* Close all usb pipes */
	usbprn_close_usb_pipes(usbprnp);

	/* prevent any accesses by setting flags to closed */
	mutex_enter(&usbprnp->usbprn_mutex);
	usbprnp->usbprn_flags &= ~USBPRN_OPEN;
	mutex_exit(&usbprnp->usbprn_mutex);

	usb_release_access(usbprnp->usbprn_dev_acc);
	usb_release_access(usbprnp->usbprn_ser_acc);

	usbprn_pm_idle_component(usbprnp);

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, usbprnp->usbprn_log_handle,
	    "usbprn_close: End");

	return (rval);
}


/*
 * usbprn_read:
 *	Read entry point (TBD)
 */
/* ARGSUSED */
static int
usbprn_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	usbprn_state_t *usbprnp = ddi_get_soft_state(usbprn_statep,
	    USBPRN_MINOR_TO_INSTANCE(getminor(dev)));

	if (usbprnp == NULL) {

		return (ENXIO);
	}

	if (getminor(dev) & USBPRN_MINOR_UGEN_BITS_MASK) {
		int rval;

		/* raise power */
		usbprn_pm_busy_component(usbprnp);
		(void) pm_raise_power(usbprnp->usbprn_dip,
		    0, USB_DEV_OS_FULL_PWR);

		if (usb_serialize_access(usbprnp->usbprn_write_acc,
		    USB_WAIT_SIG, 0) == 0) {
			usbprn_pm_idle_component(usbprnp);

			return (EINTR);
		}

		rval = usb_ugen_read(usbprnp->usbprn_ugen_hdl, dev,
		    uiop, credp);

		usb_release_access(usbprnp->usbprn_write_acc);

		usbprn_pm_idle_component(usbprnp);

		return (rval);
	}

	/* Do a bulk-in from the printer */

	return (EIO);
}


/*
 * usbprn_write:
 *	Write to the printer
 */
/* ARGSUSED2 */
static int
usbprn_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	usbprn_state_t *usbprnp = ddi_get_soft_state(usbprn_statep,
	    USBPRN_MINOR_TO_INSTANCE(getminor(dev)));
	usbprn_ps_t	*bulk_in = &usbprnp->usbprn_bulk_in;
	usbprn_ps_t	*bulk_out = &usbprnp->usbprn_bulk_out;
	int		rval;

	if (usbprnp == NULL) {

		return (ENXIO);
	}

	USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
	    "usbprn_write: Begin usbprnp=0x%p ", (void *)usbprnp);

	if (getminor(dev) & USBPRN_MINOR_UGEN_BITS_MASK) {
		/* raise power */
		usbprn_pm_busy_component(usbprnp);
		(void) pm_raise_power(usbprnp->usbprn_dip,
		    0, USB_DEV_OS_FULL_PWR);

		if (usb_serialize_access(usbprnp->usbprn_write_acc,
		    USB_WAIT_SIG, 0) == 0) {
			usbprn_pm_idle_component(usbprnp);

			return (EINTR);
		}

		rval = usb_ugen_write(usbprnp->usbprn_ugen_hdl, dev,
		    uiop, credp);

		usb_release_access(usbprnp->usbprn_write_acc);

		usbprn_pm_idle_component(usbprnp);

		return (rval);
	}

	/*
	 * serialize writes
	 * we cannot use usbprn_ser_acc sync object at this point because
	 * that would block out the ioctls for the full duration of the write.
	 */
	if (usb_serialize_access(usbprnp->usbprn_write_acc,
	    USB_WAIT_SIG, 0) == 0) {

		return (EINTR);
	}

	/*
	 * Check the status of the pipe.  If it's not idle,
	 * then wait.
	 */
	mutex_enter(&usbprnp->usbprn_mutex);

	/* if device is disconnected or pipes closed, fail immediately */
	if (!(USBPRN_DEVICE_ACCESS_OK(usbprnp))) {
		mutex_exit(&usbprnp->usbprn_mutex);

		USB_DPRINTF_L2(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_write: device can't be accessed");

		usb_release_access(usbprnp->usbprn_write_acc);

		return (EIO);
	}

	/* all pipes must be idle */
	ASSERT(bulk_out->ps_flags == USBPRN_PS_IDLE);
	ASSERT(bulk_in->ps_flags == USBPRN_PS_IDLE);

	mutex_exit(&usbprnp->usbprn_mutex);

	/*
	 * Call physio to do the transfer.  physio will
	 * call the strategy routine, and then call
	 * biowait() to block until the transfer completes.
	 */
	rval = physio(usbprn_strategy, (struct buf *)0, dev,
	    B_WRITE, usbprn_minphys, uiop);

	usb_release_access(usbprnp->usbprn_write_acc);

	USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
	    "usbprn_write: End");

	return (rval);
}


/*
 * usbprn_poll
 */
static int
usbprn_poll(dev_t dev, short events,
    int anyyet,  short *reventsp, struct pollhead **phpp)
{
	usbprn_state_t *usbprnp = ddi_get_soft_state(usbprn_statep,
	    USBPRN_MINOR_TO_INSTANCE(getminor(dev)));

	if (usbprnp == NULL) {

		return (ENXIO);
	}

	if (getminor(dev) & USBPRN_MINOR_UGEN_BITS_MASK) {
		return (usb_ugen_poll(usbprnp->usbprn_ugen_hdl, dev, events,
		    anyyet, reventsp, phpp));
	}

	return (ENXIO);
}


/*
 * usbprn_strategy:
 *	service a request to the device.
 */
static int
usbprn_strategy(struct buf *bp)
{
	usbprn_state_t *usbprnp = ddi_get_soft_state(usbprn_statep,
	    USBPRN_MINOR_TO_INSTANCE(getminor(bp->b_edev)));
	usbprn_ps_t	*bulk_out = &usbprnp->usbprn_bulk_out;

	bp_mapin(bp);

	/*
	 * serialize to avoid races
	 * access is released in usbprn_biodone()
	 */
	(void) usb_serialize_access(usbprnp->usbprn_dev_acc, USB_WAIT, 0);

	mutex_enter(&usbprnp->usbprn_mutex);
	if (!(USBPRN_DEVICE_ACCESS_OK(usbprnp))) {
		usbprn_biodone(usbprnp, EIO, 0);
		mutex_exit(&usbprnp->usbprn_mutex);

		USB_DPRINTF_L2(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_strategy: device can't be accessed");

		return (0);
	}

	bulk_out->ps_flags = USBPRN_PS_NEED_TO_XFER;

	ASSERT(usbprnp->usbprn_bp == NULL);
	usbprnp->usbprn_bp = bp;

	USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
	    "usbprn_strategy: usbprnp=0x%p bp=0x%p count=%lu",
	    (void *)usbprnp, (void *)bp, bp->b_bcount);

	ASSERT(usbprnp->usbprn_bulk_mp == NULL);

	usbprnp->usbprn_bulk_mp = allocb(bp->b_bcount, BPRI_HI);

	if (usbprnp->usbprn_bulk_mp == NULL) {
		bulk_out->ps_flags = USBPRN_PS_IDLE;
		usbprn_biodone(usbprnp, EIO, 0);
		mutex_exit(&usbprnp->usbprn_mutex);

		USB_DPRINTF_L2(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_strategy: allocb failed");

		return (0);
	}

	bcopy((caddr_t)bp->b_un.b_addr,
	    usbprnp->usbprn_bulk_mp->b_datap->db_base, bp->b_bcount);
	usbprnp->usbprn_bulk_mp->b_wptr += bp->b_bcount;
	mutex_exit(&usbprnp->usbprn_mutex);

	usbprn_send_async_bulk_data(usbprnp);

	return (0);
}


/*
 * usbprn_ioctl:
 *	handle the ioctl
 */
/*ARGSUSED4*/
static int
usbprn_ioctl(dev_t dev, int cmd, intptr_t arg, int flag,
		cred_t *credp, int *rvalp)
{
	int		err = 0;
	usbprn_state_t	*usbprnp = ddi_get_soft_state(usbprn_statep,
	    USBPRN_MINOR_TO_INSTANCE(getminor(dev)));
	struct ecpp_device_id	usbprn_devid;
	int		len;

	USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
	    "usbprn_ioctl: Begin ");

	(void) usb_serialize_access(usbprnp->usbprn_ser_acc, USB_WAIT, 0);
	mutex_enter(&usbprnp->usbprn_mutex);

	/*
	 * only for PRNIOC_GET_STATUS cmd:
	 * if device is disconnected or pipes closed, fail immediately
	 */
	if ((cmd == PRNIOC_GET_STATUS) &&
	    !(USBPRN_DEVICE_ACCESS_OK(usbprnp))) {
		mutex_exit(&usbprnp->usbprn_mutex);

		USB_DPRINTF_L2(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_write: device can't be accessed");

		usb_release_access(usbprnp->usbprn_ser_acc);

		return (EIO);
	}
	mutex_exit(&usbprnp->usbprn_mutex);

	switch (cmd) {
	case ECPPIOC_GETDEVID:
		/*
		 * With genericized ioctls this interface should change.
		 * We ignore the mode in USB printer driver because
		 * it need not be in nibble mode in usb driver unlike
		 * ecpp to retrieve the device id string. Also we do
		 * not expect the application to call this twice since
		 * it doesn't change since attach time and we take care
		 * of calling it twice: once for getting the length and
		 * once for getting the actual device id string. So we
		 * set both the lengths to actual device id string length.
		 * Ref: PSARC/2000/018
		 */
		USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_ioctl: ECPPIOC_GETDEVID(0x%x)", cmd);

		bzero(&usbprn_devid, sizeof (usbprn_devid));

		ASSERT(!(mutex_owned(&usbprnp->usbprn_mutex)));
#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32: {
			struct ecpp_device_id32	usbprn_devid32;

			if (ddi_copyin((caddr_t)arg, &usbprn_devid32,
			    sizeof (struct ecpp_device_id32), flag)) {
				err = EFAULT;

				break;
			}

			if (usbprnp->usbprn_device_id == NULL) {
				err = EIO;

				break;
			}
			ASSERT(usbprnp->usbprn_device_id_len > 2);

			usbprn_devid32.rlen = usbprnp->usbprn_device_id_len - 2;
			len = min(usbprn_devid32.len, usbprn_devid32.rlen);

			if (ddi_copyout(usbprnp->usbprn_device_id + 2,
			    (caddr_t)(uintptr_t)usbprn_devid32.addr,
			    len, flag)) {
				err = EFAULT;

				break;
			}

			if (ddi_copyout(&usbprn_devid32, (caddr_t)arg,
			    sizeof (struct ecpp_device_id32), flag)) {
				err = EFAULT;

				break;
			}

			break;
		}
		case DDI_MODEL_NONE:
			if (ddi_copyin((caddr_t)arg, &usbprn_devid,
			    sizeof (struct ecpp_device_id), flag)) {
				err = EFAULT;

				break;
			}

			if (usbprnp->usbprn_device_id == NULL) {
				err = EIO;

				break;
			}
			ASSERT(usbprnp->usbprn_device_id_len > 2);

			usbprn_devid.rlen = usbprnp->usbprn_device_id_len - 2;
			len = min(usbprn_devid.len, usbprn_devid.rlen);

			if (ddi_copyout(usbprnp->usbprn_device_id + 2,
			    usbprn_devid.addr, len, flag)) {
				err = EFAULT;

				break;
			}

			if (ddi_copyout(&usbprn_devid, (caddr_t)arg,
			    sizeof (struct ecpp_device_id), flag)) {
				err = EFAULT;

				break;
			}

			break;
		}

		break;
#else
		if (ddi_copyin((caddr_t)arg, &usbprn_devid,
		    sizeof (struct ecpp_device_id), flag)) {
			err = EFAULT;

			break;
		}


		if (usbprnp->usbprn_device_id == NULL) {
			err = EIO;

			break;
		}
		ASSERT(usbprnp->usbprn_device_id_len > 2);

		usbprn_devid.rlen = usbprnp->usbprn_device_id_len - 2;
		len = min(usbprn_devid.len, usbprn_devid.rlen);

		if (ddi_copyout(usbprnp->usbprn_device_id + 2,
		    usbprn_devid.addr, len, flag)) {
			err = EFAULT;

			break;
		}

		if (ddi_copyout(&usbprn_devid, (caddr_t)arg,
		    sizeof (struct ecpp_device_id), flag)) {
			err = EFAULT;

			break;
		}

		break;
#endif
	case ECPPIOC_SETPARMS:
		err = usbprn_setparms(usbprnp, arg, flag);

		break;
	case ECPPIOC_GETPARMS:
		USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_ioctl: ECPPIOC_GETPARMS(0x%x)", cmd);

		/* Get the parameters */
		err = usbprn_getparms(usbprnp, arg, flag);

		break;
	case BPPIOC_GETERR:
		USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_ioctl: ECPPIOC_GETERR(0x%x)", cmd);

		/* Get the error state */
		usbprn_geterr(usbprnp, arg, flag);

		break;
	case BPPIOC_TESTIO:
		USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_ioctl: BPPIOC_TESTIO(0x%x)",  cmd);

		/* Get the port status */
		err = usbprn_testio(usbprnp, flag);

		break;
	case PRNIOC_GET_IFCAP:
		USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_ioctl : PRNIOC_GET_IFCAP(0x%x)",  cmd);

		/* get interface capabilities */
		err = usbprn_prnio_get_ifcap(usbprnp, arg, flag);

		break;
	case PRNIOC_SET_IFCAP:
		USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_ioctl : PRNIOC_SET_IFCAP(0x%x)",  cmd);

		/* get interface capabilities */
		err = usbprn_prnio_set_ifcap(usbprnp, arg, flag);

		break;
	case PRNIOC_GET_IFINFO:
		USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_ioctl : PRNIOC_GET_IFINFO(0x%x)",  cmd);

		/* get interface information */
		err = usbprn_prnio_get_ifinfo(usbprnp, arg, flag);

		break;
	case PRNIOC_GET_STATUS:
		USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_ioctl : PRNIOC_GET_STATUS(0x%x)",  cmd);

		/* get prnio status */
		err = usbprn_prnio_get_status(usbprnp, arg, flag);

		break;
	case PRNIOC_GET_1284_DEVID:
		USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_ioctl : PRNIOC_GET_1284_DEVID(0x%x)",  cmd);

		/* get device ID */
		err = usbprn_prnio_get_1284_devid(usbprnp, arg, flag);

		break;
	case PRNIOC_GET_1284_STATUS:
		USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_ioctl : PRNIOC_GET_1284_STATUS(0x%x)",  cmd);

		/* get prnio status */
		err = usbprn_prnio_get_1284_status(usbprnp, arg, flag);

		break;
	case PRNIOC_GET_TIMEOUTS:
		USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_ioctl : PRNIOC_GET_TIMEOUTS(0x%x)", cmd);

		/* Get the parameters */
		err = usbprn_prnio_get_timeouts(usbprnp, arg, flag);

		break;
	case PRNIOC_SET_TIMEOUTS:
		USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_ioctl : PRNIOC_SET_TIMEOUTS(0x%x)", cmd);

		/* Get the parameters */
		err = usbprn_prnio_set_timeouts(usbprnp, arg, flag);

		break;
	case PRNIOC_RESET:
		USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_ioctl : PRNIOC_RESET(0x%x)",  cmd);

		/* nothing */
		err = 0;

		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_ioctl: unknown(0x%x)", cmd);
		err = EINVAL;
	}

	usb_release_access(usbprnp->usbprn_ser_acc);

	USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
	    "usbprn_ioctl: End ");

	return (err);
}


/*
 * breakup by physio
 */
static void
usbprn_minphys(struct buf *bp)
{
	usbprn_state_t *usbprnp = ddi_get_soft_state(usbprn_statep,
	    USBPRN_MINOR_TO_INSTANCE(getminor(bp->b_edev)));

	mutex_enter(&usbprnp->usbprn_mutex);
	USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
	    "usbprn_minphys: bcount=%lu", bp->b_bcount);

	if (bp->b_bcount > usbprnp->usbprn_max_bulk_xfer_size) {
		bp->b_bcount = min(usbprn_max_xfer_size,
		    usbprnp->usbprn_max_bulk_xfer_size);
	} else {
		bp->b_bcount = min(usbprn_max_xfer_size, bp->b_bcount);
	}
	mutex_exit(&usbprnp->usbprn_mutex);
}


/*
 * usbprn_open_usb_pipes:
 *	Open all pipes on the device
 */
static int
usbprn_open_usb_pipes(usbprn_state_t *usbprnp)
{
	usb_pipe_policy_t *policy;
	usbprn_ps_t	*bulk_in = &usbprnp->usbprn_bulk_in;
	usbprn_ps_t	*bulk_out = &usbprnp->usbprn_bulk_out;

	USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
	    "usbprn_open_usb_pipes:");

	/*
	 * Intitialize the pipe policy for the bulk out pipe
	 */
	mutex_enter(&usbprnp->usbprn_mutex);
	policy = &(bulk_out->ps_policy);
	policy->pp_max_async_reqs = 1;
	mutex_exit(&usbprnp->usbprn_mutex);

	/* Open bulk_out pipe */
	if (usb_pipe_open(usbprnp->usbprn_dip, &bulk_out->ps_ept_descr,
	    policy, USB_FLAGS_SLEEP, &bulk_out->ps_handle) != USB_SUCCESS) {

		return (USB_FAILURE);
	}

#ifdef LATER
	mutex_enter(&usbprnp->usbprn_mutex);
	/* Open the bulk in pipe if one exists */
	if (bulk_in->ps_ept_descr->bLength) {
		/*
		 * Initialize the pipe policy for the Bulk In pipe
		 */
		policy = &bulk_in->ps_policy;
		bulk_in->ps_flags = USBPRN_PS_IDLE;
		policy->pp_max_async_reqs = 1;
		mutex_exit(&usbprnp->usbprn_mutex);

		/* Open bulk_in pipe */
		if (usb_pipe_open(usbprnp->usbprn_dip, bulk_in->ps_ept_descr,
		    policy, USB_FLAGS_SLEEP, &bulk_in->ps_handle) !=
		    USB_SUCCESS) {

			return (USB_FAILURE);
		}
	} else {
		mutex_exit(&usbprnp->usbprn_mutex);
	}
#else
	mutex_enter(&usbprnp->usbprn_mutex);
	bulk_in->ps_flags = USBPRN_PS_IDLE;
	mutex_exit(&usbprnp->usbprn_mutex);
#endif

	USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
	    "usbprn_open_usb_pipes: success");

	return (USB_SUCCESS);
}


/*
 * usbprn_close_usb_pipes:
 *	Close the default/bulk in/out pipes synchronously
 */
static void
usbprn_close_usb_pipes(usbprn_state_t *usbprnp)
{
	usbprn_ps_t	*bulk_in = &usbprnp->usbprn_bulk_in;
	usbprn_ps_t	*bulk_out = &usbprnp->usbprn_bulk_out;

	USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
	    "usbprn_close_usb_pipes:");
#ifdef DEBUG
	mutex_enter(&usbprnp->usbprn_mutex);
	ASSERT(bulk_out->ps_flags == USBPRN_PS_IDLE);
	ASSERT(bulk_in->ps_flags == USBPRN_PS_IDLE);
	mutex_exit(&usbprnp->usbprn_mutex);
#endif

	/*
	 * close the pipe, if another thread is already closing the
	 * pipe, we get USB_INVALID_PIPE
	 */
	if (bulk_out->ps_handle) {

		USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_close_usb_pipes: Closing bulk out pipe");

		usb_pipe_close(usbprnp->usbprn_dip, bulk_out->ps_handle,
		    USB_FLAGS_SLEEP, NULL, NULL);
		bulk_out->ps_handle = NULL;
	}
	if (bulk_in->ps_handle) {

		USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_close_usb_pipes: Closing bulk in pipe");

		usb_pipe_close(usbprnp->usbprn_dip, bulk_in->ps_handle,
		    USB_FLAGS_SLEEP, NULL, NULL);
		bulk_in->ps_handle = NULL;
	}
}


/*
 * usbprn_getparms:
 *	Get the parameters for the device
 */
static int
usbprn_getparms(usbprn_state_t *usbprnp, intptr_t arg, int flag)
{
	ASSERT(!(mutex_owned(&usbprnp->usbprn_mutex)));

	if (ddi_copyout(&usbprnp->usbprn_setparms,
	    (caddr_t)arg, sizeof (struct ecpp_transfer_parms), flag)) {

		return (EFAULT);
	}

	return (0);
}


/*
 * usbprn_setparms:
 *	Set the parameters for the device
 */
static int
usbprn_setparms(usbprn_state_t *usbprnp, intptr_t arg, int flag)
{
	struct ecpp_transfer_parms xfer;

	ASSERT(!(mutex_owned(&usbprnp->usbprn_mutex)));

	if (ddi_copyin((caddr_t)arg, &xfer,
	    sizeof (struct ecpp_transfer_parms), flag)) {

		return (EFAULT);
	}
	if ((xfer.write_timeout < USBPRN_XFER_TIMEOUT_MIN) ||
	    (xfer.write_timeout > USBPRN_XFER_TIMEOUT_MAX)) {

		return (EINVAL);
	}
	if (!((xfer.mode == ECPP_CENTRONICS) ||
	    (xfer.mode == ECPP_COMPAT_MODE) ||
	    (xfer.mode == ECPP_NIBBLE_MODE) ||
	    (xfer.mode == ECPP_ECP_MODE) ||
	    (xfer.mode == ECPP_DIAG_MODE))) {

		return (EINVAL);

	}
	if (xfer.mode != ECPP_CENTRONICS) {

		return (EPROTONOSUPPORT);
	}

	mutex_enter(&usbprnp->usbprn_mutex);
	usbprnp->usbprn_setparms = xfer;
	usbprnp->usbprn_prn_timeouts.tmo_forward = xfer.write_timeout;
	mutex_exit(&usbprnp->usbprn_mutex);

	return (0);
}


/*
 * usbprn_geterr:
 *	Return the any device error state
 */
static void
usbprn_geterr(usbprn_state_t *usbprnp, intptr_t arg, int flag)
{
	struct bpp_error_status bpp_status;

	bzero(&bpp_status, sizeof (bpp_status));

	mutex_enter(&usbprnp->usbprn_mutex);
	bpp_status.bus_error = 0;
	bpp_status.timeout_occurred = 0;
	bpp_status.pin_status = usbprn_error_state(usbprnp->usbprn_last_status);

	USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
	    "usbprn_geterr: status=0x%x", usbprnp->usbprn_last_status);

	mutex_exit(&usbprnp->usbprn_mutex);

	(void) ddi_copyout(&bpp_status,
	    (caddr_t)arg, sizeof (struct bpp_error_status), flag);
}


/*
 * usbprn_error_state:
 *	Map the driver error state to that of the application
 */
static char
usbprn_error_state(uchar_t status)
{
	uchar_t app_err_status = 0;

	if (!(status & USB_PRINTER_PORT_NO_ERROR)) {
		app_err_status |= USB_PRINTER_ERR_ERR;
	}
	if (status & USB_PRINTER_PORT_EMPTY) {
		app_err_status |= USB_PRINTER_PE_ERR;
	}
	if (!(status & USB_PRINTER_PORT_NO_SELECT)) {
		app_err_status |= USB_PRINTER_SLCT_ERR;
	}

	return (app_err_status);
}


static int
usbprn_ioctl_get_status(usbprn_state_t *usbprnp)
{
	/* Check the transfer mode */
	mutex_enter(&usbprnp->usbprn_mutex);

	/* if device is disconnected or pipes closed, fail immediately */
	if (!(USBPRN_DEVICE_ACCESS_OK(usbprnp))) {
		mutex_exit(&usbprnp->usbprn_mutex);

		USB_DPRINTF_L2(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_ioctl_get_status: device can't be accessed");

		return (EIO);
	}
	mutex_exit(&usbprnp->usbprn_mutex);

	if (usbprn_get_port_status(usbprnp) != USB_SUCCESS) {

		return (EIO);
	}

	return (0);
}


/*
 * usbprn_testio:
 *	Execute the ECPP_TESTIO ioctl
 */
/* ARGSUSED1 */
static int
usbprn_testio(usbprn_state_t *usbprnp, int flag)
{
	int	err;

	USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
	    "usbprn_testio: begin");

	if ((err = usbprn_ioctl_get_status(usbprnp)) != 0) {

		return (err);
	}

	/* There is an error.  Return it to the user */
	mutex_enter(&usbprnp->usbprn_mutex);

	if (usbprn_error_state(usbprnp->usbprn_last_status) != 0) {
		mutex_exit(&usbprnp->usbprn_mutex);

		return (EIO);

	} else {
		mutex_exit(&usbprnp->usbprn_mutex);

		return (0);
	}
}


/*
 * usbprn_prnio_get_status:
 *	Execute the PRNIOC_GET_STATUS ioctl
 */
static int
usbprn_prnio_get_status(usbprn_state_t *usbprnp, intptr_t arg, int flag)
{
	uint_t	prnio_status = 0;
	int	err;

	USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
	    "usbprn_prnio_get_status: begin");

	/* capture printer status */
	err = usbprn_ioctl_get_status(usbprnp);

	mutex_enter(&usbprnp->usbprn_mutex);

	if (usbprnp->usbprn_dev_state == USB_DEV_ONLINE) {
		prnio_status |= PRN_ONLINE;
	}
	if ((err == 0) &&
	    (usbprnp->usbprn_last_status & USB_PRINTER_PORT_NO_ERROR)) {
		prnio_status |= PRN_READY;
	}

	mutex_exit(&usbprnp->usbprn_mutex);

	if (ddi_copyout(&prnio_status,
	    (caddr_t)arg, sizeof (prnio_status), flag)) {

		return (EFAULT);
	}

	return (0);
}


/*
 * usbprn_prnio_get_1284_status:
 *	Execute the PRNIOC_GET_1284_STATUS ioctl
 */
static int
usbprn_prnio_get_1284_status(usbprn_state_t *usbprnp, intptr_t arg, int flag)
{
	uchar_t		status;
	int		err;

	USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
	    "usbprn_prnio_get_1284_status: begin");

	if ((err = usbprn_ioctl_get_status(usbprnp)) != 0) {

		return (err);
	}

	/* status was captured successfully */
	mutex_enter(&usbprnp->usbprn_mutex);

	status = usbprnp->usbprn_last_status & (USB_PRINTER_PORT_NO_ERROR |
	    USB_PRINTER_PORT_NO_SELECT | USB_PRINTER_PORT_EMPTY);

	mutex_exit(&usbprnp->usbprn_mutex);

	if (ddi_copyout(&status, (caddr_t)arg, sizeof (status), flag)) {

		return (EFAULT);
	}

	return (0);
}


/*
 * usbprn_prnio_get_ifcap:
 *	Execute the PRNIOC_GET_IFCAP ioctl
 */
/* ARGSUSED */
static int
usbprn_prnio_get_ifcap(usbprn_state_t *usbprnp, intptr_t arg, int flag)
{
	ASSERT(!(mutex_owned(&usbprnp->usbprn_mutex)));

	if (ddi_copyout(&usbprn_ifcap, (caddr_t)arg, sizeof (usbprn_ifcap),
	    flag)) {

		return (EFAULT);
	}

	return (0);
}


/*
 * usbprn_prnio_get_ifcap:
 *	Execute the PRNIOC_SET_IFCAP ioctl
 */
/* ARGSUSED */
static int
usbprn_prnio_set_ifcap(usbprn_state_t *usbprnp, intptr_t arg, int flag)
{
	uint_t	new_ifcap;

	ASSERT(!(mutex_owned(&usbprnp->usbprn_mutex)));

	if (ddi_copyin((caddr_t)arg, &new_ifcap, sizeof (new_ifcap), flag)) {

		return (EFAULT);
	}

	/* no settable capabilities */
	if (usbprn_ifcap != new_ifcap) {

		return (EINVAL);
	}

	return (0);
}


/*
 * usbprn_prnio_get_ifinfo:
 *	Execute the PRNIOC_GET_IFINFO ioctl
 */
/* ARGSUSED */
static int
usbprn_prnio_get_ifinfo(usbprn_state_t *usbprnp, intptr_t arg, int flag)
{
	struct prn_interface_info	prn_info;
	int	rlen, len;

	rlen = strlen(usbprn_prnio_ifinfo);

#ifdef _MULTI_DATAMODEL
	ASSERT(!(mutex_owned(&usbprnp->usbprn_mutex)));

	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32: {
		struct prn_interface_info32	prn_info32;

		if (ddi_copyin((caddr_t)arg, &prn_info32,
		    sizeof (struct prn_interface_info32), flag)) {

			return (EFAULT);
		}

		prn_info32.if_rlen = rlen;
		len = min(rlen, prn_info32.if_len);

		if (ddi_copyout(&usbprn_prnio_ifinfo[0],
		    (caddr_t)(uintptr_t)prn_info32.if_data, len, flag)) {

			return (EFAULT);
		}

		if (ddi_copyout(&prn_info32, (caddr_t)arg,
		    sizeof (struct prn_interface_info32), flag)) {

			return (EFAULT);
		}

		break;
	}
	case DDI_MODEL_NONE:
#endif /* _MULTI_DATAMODEL */
		ASSERT(!(mutex_owned(&usbprnp->usbprn_mutex)));

		if (ddi_copyin((caddr_t)arg, &prn_info,
		    sizeof (struct prn_interface_info), flag)) {

			return (EFAULT);
		}

		prn_info.if_rlen = rlen;
		len = min(rlen, prn_info.if_len);

		if (ddi_copyout(&usbprn_prnio_ifinfo[0],
		    prn_info.if_data, len, flag)) {

			return (EFAULT);
		}

		if (ddi_copyout(&prn_info, (caddr_t)arg,
		    sizeof (struct prn_interface_info), flag)) {

			return (EFAULT);
		}
#ifdef _MULTI_DATAMODEL

		break;
	}
#endif /* _MULTI_DATAMODEL */

	return (0);
}


/*
 * usbprn_prnio_getdevid:
 *	Execute the PRNIOC_GET_1284_DEVID ioctl
 */
static int
usbprn_prnio_get_1284_devid(usbprn_state_t *usbprnp, intptr_t arg, int flag)
{
	struct prn_1284_device_id prn_devid;
	int	len;

	ASSERT(!(mutex_owned(&usbprnp->usbprn_mutex)));

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32: {
		struct prn_1284_device_id32	prn_devid32;

		if (ddi_copyin((caddr_t)arg, &prn_devid32,
		    sizeof (struct prn_1284_device_id32), flag)) {

			return (EFAULT);
		}

		prn_devid32.id_rlen = usbprnp->usbprn_device_id_len - 2;
		len = min(prn_devid32.id_rlen, prn_devid32.id_len);

		if (ddi_copyout(usbprnp->usbprn_device_id + 2,
		    (caddr_t)(uintptr_t)prn_devid32.id_data, len, flag)) {

			return (EFAULT);
		}

		if (ddi_copyout(&prn_devid32, (caddr_t)arg,
		    sizeof (struct prn_1284_device_id32), flag)) {

			return (EFAULT);
		}

		break;
	}
	case DDI_MODEL_NONE:
#endif /* _MULTI_DATAMODEL */
		if (ddi_copyin((caddr_t)arg, &prn_devid,
		    sizeof (struct prn_1284_device_id), flag)) {

			return (EFAULT);
		}

		prn_devid.id_rlen = usbprnp->usbprn_device_id_len - 2;
		len = min(prn_devid.id_rlen, prn_devid.id_len);

		if (ddi_copyout(usbprnp->usbprn_device_id + 2,
		    prn_devid.id_data, len, flag)) {

			return (EFAULT);
		}

		if (ddi_copyout(&prn_devid, (caddr_t)arg,
		    sizeof (struct prn_1284_device_id), flag)) {

			return (EFAULT);
		}
#ifdef _MULTI_DATAMODEL

		break;
	}
#endif /* _MULTI_DATAMODEL */

	return (0);
}


/*
 * usbprn_prnio_get_timeouts:
 *	Return timeout
 */
static int
usbprn_prnio_get_timeouts(usbprn_state_t *usbprnp, intptr_t arg, int flag)
{
	ASSERT(!(mutex_owned(&usbprnp->usbprn_mutex)));

	if (ddi_copyout(&usbprnp->usbprn_prn_timeouts,
	    (caddr_t)arg, sizeof (struct prn_timeouts), flag)) {

		return (EFAULT);
	}

	return (0);
}


/*
 * usbprn_prnio_set_timeouts:
 *	Set write timeout and prn timeout
 */
static int
usbprn_prnio_set_timeouts(usbprn_state_t *usbprnp, intptr_t arg, int flag)
{
	struct prn_timeouts prn_timeouts;

	ASSERT(!(mutex_owned(&usbprnp->usbprn_mutex)));

	if (ddi_copyin((caddr_t)arg, &prn_timeouts,
	    sizeof (struct prn_timeouts), flag)) {

		return (EFAULT);
	}

	if ((prn_timeouts.tmo_forward < USBPRN_XFER_TIMEOUT_MIN) ||
	    (prn_timeouts.tmo_forward > USBPRN_XFER_TIMEOUT_MAX)) {

		return (EINVAL);
	}

	mutex_enter(&usbprnp->usbprn_mutex);

	usbprnp->usbprn_prn_timeouts = prn_timeouts;
	usbprnp->usbprn_setparms.write_timeout = prn_timeouts.tmo_forward;

	mutex_exit(&usbprnp->usbprn_mutex);

	return (0);
}


/*
 * usbprn_biodone:
 *	If there is a bp, complete it
 */
static void
usbprn_biodone(usbprn_state_t *usbprnp, int err, int bytes_remaining)
{
	struct buf *bp = usbprnp->usbprn_bp;
	usbprn_ps_t	*bulk_out = &usbprnp->usbprn_bulk_out;
	usbprn_ps_t	*bulk_in = &usbprnp->usbprn_bulk_in;

	ASSERT(mutex_owned(&usbprnp->usbprn_mutex));

	/* all pipes must be idle now */
	ASSERT(bulk_out->ps_flags == USBPRN_PS_IDLE);
	ASSERT(bulk_in->ps_flags == USBPRN_PS_IDLE);

	if (bp) {
		bp->b_resid = bytes_remaining;

		USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_biodone: "
		    "bp=0x%p bcount=0x%lx resid=0x%lx remaining=0x%x err=%d",
		    (void *)bp, bp->b_bcount, bp->b_resid, bytes_remaining,
		    err);

		if (err) {
			bioerror(bp, err);
		}

		usbprnp->usbprn_bp = NULL;
		biodone(bp);
	}

	/* release access */
	usb_release_access(usbprnp->usbprn_dev_acc);
}


/*
 * usbprn_send_async_bulk_data:
 *	Send bulk data down to the device through the bulk out pipe
 */
static void
usbprn_send_async_bulk_data(usbprn_state_t *usbprnp)
{
	int		rval;
	int		timeout;
	mblk_t		*mp;
	size_t		max_xfer_count, xfer_count;
	usbprn_ps_t	*bulk_out = &usbprnp->usbprn_bulk_out;
	usb_bulk_req_t *req;

	mutex_enter(&usbprnp->usbprn_mutex);
	ASSERT(bulk_out->ps_flags == USBPRN_PS_NEED_TO_XFER);

	timeout = usbprnp->usbprn_setparms.write_timeout;
	max_xfer_count = usbprnp->usbprn_bp->b_bcount;
	mp = usbprnp->usbprn_bulk_mp;
	ASSERT(mp != NULL);
	xfer_count = MBLKL(mp);
	mutex_exit(&usbprnp->usbprn_mutex);

	req = usb_alloc_bulk_req(usbprnp->usbprn_dip, 0, USB_FLAGS_SLEEP);
	req->bulk_len		= (uint_t)xfer_count;
	req->bulk_data		= mp;
	req->bulk_timeout	= timeout;
	req->bulk_cb		= usbprn_bulk_xfer_cb;
	req->bulk_exc_cb	= usbprn_bulk_xfer_exc_cb;
	req->bulk_client_private = (usb_opaque_t)usbprnp;
	req->bulk_attributes	= USB_ATTRS_AUTOCLEARING;

	USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
	    "usbprn_send_async_bulk_data: req = 0x%p "
	    "max_bulk_xfer_size=%lu mp=0x%p xfer_cnt=%lu timeout=%x",
	    (void *)req, max_xfer_count, (void *)mp, xfer_count, timeout);

	ASSERT(xfer_count <= max_xfer_count);


	if ((rval = usb_pipe_bulk_xfer(bulk_out->ps_handle, req, 0)) !=
	    USB_SUCCESS) {

		USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_send_async_bulk_data: Bulk mp=0x%p "
		    "rval=%d", (void *)mp, rval);

		mutex_enter(&usbprnp->usbprn_mutex);
		bulk_out->ps_flags = USBPRN_PS_IDLE;
		usbprnp->usbprn_bulk_mp = NULL;
		usbprn_biodone(usbprnp, EIO, 0);
		mutex_exit(&usbprnp->usbprn_mutex);

		usb_free_bulk_req(req);
	} else {
		mutex_enter(&usbprnp->usbprn_mutex);
		usbprnp->usbprn_bulk_mp = NULL;
		mutex_exit(&usbprnp->usbprn_mutex);
	}
}


/*
 * usbprn_bulk_xfer_cb
 *	Callback for a normal transfer for both bulk pipes.
 */
/*ARGSUSED*/
static void
usbprn_bulk_xfer_cb(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	usbprn_state_t	*usbprnp = (usbprn_state_t *)req->bulk_client_private;
	usbprn_ps_t	*bulk_out = &usbprnp->usbprn_bulk_out;

	ASSERT(usbprnp != NULL);
	ASSERT(!mutex_owned(&usbprnp->usbprn_mutex));

	mutex_enter(&usbprnp->usbprn_mutex);

	USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
	    "usbprn_bulk_xfer_cb: mp=0x%p ", (void *)usbprnp->usbprn_bulk_mp);

	ASSERT(bulk_out->ps_flags == USBPRN_PS_NEED_TO_XFER);
	ASSERT(usbprnp->usbprn_bp != NULL);
	ASSERT((req->bulk_cb_flags & USB_CB_INTR_CONTEXT) == 0);

	/*
	 * if device is disconnected or driver close called, return
	 * The pipe could be closed, or a timeout could have
	 * come in and the pipe is being reset.  If the
	 * state isn't transferring, then return
	 */
	if (!(USBPRN_DEVICE_ACCESS_OK(usbprnp)) ||
	    (bulk_out->ps_flags != USBPRN_PS_NEED_TO_XFER)) {
		USB_DPRINTF_L3(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_bulk_xfer_cb: no access or pipe closed");

		bulk_out->ps_flags = USBPRN_PS_IDLE;
		usbprn_biodone(usbprnp, EIO, 0);
	} else {

		/*
		 * data has been xferred, complete the bp.
		 */
		USB_DPRINTF_L3(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_bulk_xfer_cb: transaction over");

		bulk_out->ps_flags = USBPRN_PS_IDLE;
		usbprn_biodone(usbprnp, 0, 0);
	}

	mutex_exit(&usbprnp->usbprn_mutex);

	usb_free_bulk_req(req);
}


/*
 * usbprn_bulk_xfer_exc_cb:
 *	Exception callback for the bulk pipes
 */
static void
usbprn_bulk_xfer_exc_cb(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	usbprn_state_t	*usbprnp = (usbprn_state_t *)req->bulk_client_private;
	usbprn_ps_t	*bulk_out = &usbprnp->usbprn_bulk_out;
	int		bytes_remaining = 0;
	mblk_t		*data = req->bulk_data;
	usb_cr_t	completion_reason = req->bulk_completion_reason;
	usb_cb_flags_t	cb_flags = req->bulk_cb_flags;

	USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
	    "usbprn_bulk_xfer_exc_cb: "
	    "pipe=0x%p req=0x%p cr=%d cb_flags=0x%x data=0x%p",
	    (void *)pipe, (void *)req, completion_reason, cb_flags,
	    (void *)data);

	ASSERT((req->bulk_cb_flags & USB_CB_INTR_CONTEXT) == 0);
	ASSERT(data != NULL);
	mutex_enter(&usbprnp->usbprn_mutex);

	ASSERT(bulk_out->ps_flags == USBPRN_PS_NEED_TO_XFER);
	bulk_out->ps_flags = USBPRN_PS_IDLE;
	bulk_out->ps_cr = completion_reason;

	if (data) {
		bytes_remaining = MBLKL(data);
	}

	/*
	 * If the pipe is closed or device not responding or not in
	 * need of transfer, just give up on this bp.
	 */
	if (!(USBPRN_DEVICE_ACCESS_OK(usbprnp)) ||
	    (req->bulk_completion_reason == USB_CR_DEV_NOT_RESP)) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_bulk_xfer_exc_cb: "
		    "device not accesible or wrong state");
		usbprn_biodone(usbprnp, EIO, 0);
	} else {
		if (completion_reason == USB_CR_TIMEOUT) {
			USB_DPRINTF_L2(PRINT_MASK_ALL,
			    usbprnp->usbprn_log_handle,
			    "usbprn_bulk_xfer_exc_cb: timeout error, "
			    "xferred %lu bytes",
			    ((usbprnp->usbprn_bp->b_bcount) -
			    bytes_remaining));
			usbprn_biodone(usbprnp, 0, bytes_remaining);
		} else {
			usbprn_biodone(usbprnp, EIO, 0);
		}

	}

	mutex_exit(&usbprnp->usbprn_mutex);

	usb_free_bulk_req(req);
}


/*
 * usbprn_reconnect_event_cb:
 *	Called upon when the device is hotplugged back; event handling
 */
/*ARGSUSED*/
static int
usbprn_reconnect_event_cb(dev_info_t *dip)
{
	usbprn_state_t	*usbprnp =
	    (usbprn_state_t *)ddi_get_soft_state(usbprn_statep,
	    ddi_get_instance(dip));

	ASSERT(usbprnp != NULL);

	USB_DPRINTF_L3(PRINT_MASK_EVENTS, usbprnp->usbprn_log_handle,
	    "usbprn_reconnect_event_cb:");

	(void) usb_serialize_access(usbprnp->usbprn_ser_acc, USB_WAIT, 0);

	mutex_enter(&usbprnp->usbprn_mutex);
	ASSERT(usbprnp->usbprn_dev_state == USB_DEV_DISCONNECTED);

	mutex_exit(&usbprnp->usbprn_mutex);

	usbprn_restore_device_state(dip, usbprnp);

	if (usbprnp->usbprn_ugen_hdl) {
		(void) usb_ugen_reconnect_ev_cb(usbprnp->usbprn_ugen_hdl);
	}

	usb_release_access(usbprnp->usbprn_ser_acc);

	return (USB_SUCCESS);
}


/*
 * usbprn_disconnect_event_cb:
 *	callback for disconnect events
 */
/*ARGSUSED*/
static int
usbprn_disconnect_event_cb(dev_info_t *dip)
{
	usbprn_state_t	*usbprnp = (usbprn_state_t *)ddi_get_soft_state(
	    usbprn_statep, ddi_get_instance(dip));

	USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
	    "usbprn_disconnect_event_cb: Begin");

	(void) usb_serialize_access(usbprnp->usbprn_ser_acc, USB_WAIT, 0);

	mutex_enter(&usbprnp->usbprn_mutex);
	usbprnp->usbprn_dev_state = USB_DEV_DISCONNECTED;

	if (usbprnp->usbprn_flags & USBPRN_OPEN) {
		USB_DPRINTF_L0(PRINT_MASK_EVENTS, usbprnp->usbprn_log_handle,
		    "device was disconnected while open. "
		    "Data may have been lost");
	}

	/* For now, we set the offline bit in usbprn_last_status */
	usbprnp->usbprn_last_status |= USB_PRINTER_PORT_NO_SELECT;

	mutex_exit(&usbprnp->usbprn_mutex);

	if (usbprnp->usbprn_ugen_hdl) {
		(void) usb_ugen_disconnect_ev_cb(usbprnp->usbprn_ugen_hdl);
	}

	usb_release_access(usbprnp->usbprn_ser_acc);

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, usbprnp->usbprn_log_handle,
	    "usbprn_disconnect_event_cb: End");

	return (USB_SUCCESS);
}


/*
 * usbprn_restore_device_state:
 *	set original configuration of the device
 *	Restores data xfer
 */
static void
usbprn_restore_device_state(dev_info_t *dip, usbprn_state_t *usbprnp)
{
	int alt, rval, iface;

	USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
	    "usbprn_restore_device_state:");

	mutex_enter(&usbprnp->usbprn_mutex);
	ASSERT((usbprnp->usbprn_dev_state == USB_DEV_DISCONNECTED) ||
	    (usbprnp->usbprn_dev_state == USB_DEV_SUSPENDED));

	mutex_exit(&usbprnp->usbprn_mutex);

	/* Check if we are talking to the same device */
	if (usb_check_same_device(dip, usbprnp->usbprn_log_handle,
	    USB_LOG_L0, PRINT_MASK_ALL,
	    USB_CHK_ALL, NULL) != USB_SUCCESS) {

		/* change the device state from suspended to disconnected */
		mutex_enter(&usbprnp->usbprn_mutex);
		usbprnp->usbprn_dev_state = USB_DEV_DISCONNECTED;
		mutex_exit(&usbprnp->usbprn_mutex);

		return;
	}

	USB_DPRINTF_L0(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
	    "Printer has been reconnected but data may have been lost");

	mutex_enter(&usbprnp->usbprn_mutex);

	/* set last status to online */
	usbprnp->usbprn_last_status &= ~USB_PRINTER_PORT_NO_SELECT;
	mutex_exit(&usbprnp->usbprn_mutex);

	/* Get the port status */
	if (usbprn_get_port_status(usbprnp) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbprnp->usbprn_log_handle,
		    "usbprn_restore_device_state: port status failed");

		return;
	}

	mutex_enter(&usbprnp->usbprn_mutex);

	if ((usbprnp->usbprn_last_status & USB_PRINTER_PORT_NO_ERROR) == 0) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
		    "usbprn_restore_device_state: An error with the printer");
	}

	if (usbprnp->usbprn_flags & USBPRN_OPEN) {
		mutex_exit(&usbprnp->usbprn_mutex);
		usbprn_close_usb_pipes(usbprnp);
		mutex_enter(&usbprnp->usbprn_mutex);
	}

	/* restore alternate */
	alt = usbprnp->usbprn_if_descr.bAlternateSetting,
	    mutex_exit(&usbprnp->usbprn_mutex);

	iface = usb_owns_device(dip) ? 0 :  usb_get_if_number(dip);
	if ((rval = usb_set_alt_if(dip, iface, alt,
	    USB_FLAGS_SLEEP, NULL, NULL)) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbprnp->usbprn_log_handle,
		    "usbprn_restore_device_state: set alternate failed (%d)",
		    rval);

		return;
	}

	mutex_enter(&usbprnp->usbprn_mutex);

	if (usbprnp->usbprn_flags & USBPRN_OPEN) {

		mutex_exit(&usbprnp->usbprn_mutex);
		(void) usbprn_open_usb_pipes(usbprnp);
		mutex_enter(&usbprnp->usbprn_mutex);
	}

	if (usbprnp->usbprn_pm && usbprnp->usbprn_pm->usbprn_wakeup_enabled) {
		mutex_exit(&usbprnp->usbprn_mutex);
		(void) usb_handle_remote_wakeup(usbprnp->usbprn_dip,
		    USB_REMOTE_WAKEUP_ENABLE);
		mutex_enter(&usbprnp->usbprn_mutex);
	}

	usbprnp->usbprn_dev_state = USB_DEV_ONLINE;
	mutex_exit(&usbprnp->usbprn_mutex);

	USB_DPRINTF_L4(PRINT_MASK_ALL, usbprnp->usbprn_log_handle,
	    "usbprn_restore_device_state: End");
}


/*
 *	Create power managements components
 */
static void
usbprn_create_pm_components(dev_info_t *dip, usbprn_state_t *usbprnp)
{
	usbprn_power_t	*usbprnpm;
	uint_t		pwr_states;

	USB_DPRINTF_L4(PRINT_MASK_PM, usbprnp->usbprn_log_handle,
	    "usbprn_create_pm_components: Begin");

	/* Allocate the state structure */
	usbprnpm = kmem_zalloc(sizeof (usbprn_power_t),
	    KM_SLEEP);
	usbprnp->usbprn_pm = usbprnpm;
	usbprnpm->usbprn_pm_capabilities = 0;
	usbprnpm->usbprn_current_power = USB_DEV_OS_FULL_PWR;

	if (usb_create_pm_components(dip, &pwr_states) ==
	    USB_SUCCESS) {
		USB_DPRINTF_L4(PRINT_MASK_PM,
		    usbprnp->usbprn_log_handle,
		    "usbprn_create_pm_components: "
		    "created PM components");

		if (usb_handle_remote_wakeup(dip,
		    USB_REMOTE_WAKEUP_ENABLE) == USB_SUCCESS) {
			usbprnpm->usbprn_wakeup_enabled = 1;
		}
		usbprnpm->usbprn_pwr_states = (uint8_t)pwr_states;
		(void) pm_raise_power(usbprnp->usbprn_dip, 0,
		    USB_DEV_OS_FULL_PWR);
	} else {
		USB_DPRINTF_L2(PRINT_MASK_PM,
		    usbprnp->usbprn_log_handle,
		    "usbprn_create_pm_components: Failed");
	}

	USB_DPRINTF_L4(PRINT_MASK_PM, usbprnp->usbprn_log_handle,
	    "usbprn_create_pm_components: END");
}


/*
 * usbprn_pwrlvl0:
 * Functions to handle power transition for OS levels 0 -> 3
 */
static int
usbprn_pwrlvl0(usbprn_state_t *usbprnp)
{
	int	rval;

	USB_DPRINTF_L4(PRINT_MASK_PM, usbprnp->usbprn_log_handle,
	    "usbprn_pwrlvl0:");

	switch (usbprnp->usbprn_dev_state) {
	case USB_DEV_ONLINE:
		/* Deny the powerdown request if the device is busy */
		if (usbprnp->usbprn_pm->usbprn_pm_busy != 0) {

			return (USB_FAILURE);
		}

		/* Issue USB D3 command to the device here */
		rval = usb_set_device_pwrlvl3(usbprnp->usbprn_dip);
		ASSERT(rval == USB_SUCCESS);

		usbprnp->usbprn_dev_state = USB_DEV_PWRED_DOWN;
		usbprnp->usbprn_pm->usbprn_current_power =
		    USB_DEV_OS_PWR_OFF;
		/* FALLTHRU */
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:
		/* allow a disconnect/cpr'ed device to go to lower power */

		return (USB_SUCCESS);
	case USB_DEV_PWRED_DOWN:
	default:
		USB_DPRINTF_L2(PRINT_MASK_PM, usbprnp->usbprn_log_handle,
		    "usbprn_pwrlvl0: illegal dev state");

		return (USB_FAILURE);
	}
}


/*
 * usbprn_pwrlvl1:
 *	Functions to handle power transition to OS levels -> 2
 */
static int
usbprn_pwrlvl1(usbprn_state_t *usbprnp)
{
	int	rval;

	USB_DPRINTF_L4(PRINT_MASK_PM, usbprnp->usbprn_log_handle,
	    "usbprn_pwrlvl1:");

	/* Issue USB D2 command to the device here */
	rval = usb_set_device_pwrlvl2(usbprnp->usbprn_dip);
	ASSERT(rval == USB_SUCCESS);

	return (USB_FAILURE);
}


/*
 * usbprn_pwrlvl2:
 *	Functions to handle power transition to OS levels -> 1
 */
static int
usbprn_pwrlvl2(usbprn_state_t *usbprnp)
{
	int	rval;

	USB_DPRINTF_L4(PRINT_MASK_PM, usbprnp->usbprn_log_handle,
	    "usbprn_pwrlvl2:");

	/* Issue USB D1 command to the device here */
	rval = usb_set_device_pwrlvl1(usbprnp->usbprn_dip);
	ASSERT(rval == USB_SUCCESS);

	return (USB_FAILURE);
}


/*
 * usbprn_pwrlvl3:
 *	Functions to handle power transition to OS level -> 0
 */
static int
usbprn_pwrlvl3(usbprn_state_t *usbprnp)
{
	USB_DPRINTF_L4(PRINT_MASK_PM, usbprnp->usbprn_log_handle,
	    "usbprn_pwrlvl3:");

	switch (usbprnp->usbprn_dev_state) {
	case USB_DEV_PWRED_DOWN:
		/* Issue USB D0 command to the device here */
		(void) usb_set_device_pwrlvl0(usbprnp->usbprn_dip);

		usbprnp->usbprn_dev_state = USB_DEV_ONLINE;
		usbprnp->usbprn_pm->usbprn_current_power =
		    USB_DEV_OS_FULL_PWR;

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
		USB_DPRINTF_L4(PRINT_MASK_PM, usbprnp->usbprn_log_handle,
		    "usbprn_pwrlvl3:");


		return (USB_FAILURE);
	}
}


/*
 * usbprn_power :
 *	Power entry point
 */
/* ARGSUSED */
static int
usbprn_power(dev_info_t *dip, int comp, int level)
{
	usbprn_state_t	*usbprnp;
	usbprn_power_t	*pm;
	int		rval = USB_FAILURE;

	usbprnp = (usbprn_state_t *)ddi_get_soft_state(usbprn_statep,
	    ddi_get_instance(dip));

	USB_DPRINTF_L3(PRINT_MASK_PM, usbprnp->usbprn_log_handle,
	    "usbprn_power: Begin: level=%d", level);

	(void) usb_serialize_access(usbprnp->usbprn_ser_acc, USB_WAIT, 0);

	mutex_enter(&usbprnp->usbprn_mutex);
	pm = usbprnp->usbprn_pm;
	ASSERT(pm != NULL);

	/* Check if we are transitioning to a legal power level */
	if (USB_DEV_PWRSTATE_OK(pm->usbprn_pwr_states, level)) {
		USB_DPRINTF_L2(PRINT_MASK_PM, usbprnp->usbprn_log_handle,
		    "usbprn_power: illegal power level=%d "
		    "pwr_states=0x%x", level, pm->usbprn_pwr_states);

		goto done;
	}

	switch (level) {
	case USB_DEV_OS_PWR_OFF :
		rval = usbprn_pwrlvl0(usbprnp);

		break;
	case USB_DEV_OS_PWR_1 :
		rval = usbprn_pwrlvl1(usbprnp);

		break;
	case USB_DEV_OS_PWR_2 :
		rval = usbprn_pwrlvl2(usbprnp);

		break;
	case USB_DEV_OS_FULL_PWR :
		rval = usbprn_pwrlvl3(usbprnp);

		break;
	}

done:
	mutex_exit(&usbprnp->usbprn_mutex);

	usb_release_access(usbprnp->usbprn_ser_acc);

	return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}


/*
 * usbprn_print_long:
 *	Breakup a string which is > USBPRN_PRINT_MAXLINE and print it
 */
static void
usbprn_print_long(usbprn_state_t *usbprnp, char *str, int len)
{
	char *tmp = str;
	char pbuf[USBPRN_PRINT_MAXLINE];

	for (;;) {
		if (len <= USBPRN_PRINT_MAXLINE) {
			USB_DPRINTF_L4(PRINT_MASK_ATTA,
			    usbprnp->usbprn_log_handle, "%s", tmp);

			break;
		} else {
			bcopy(tmp, pbuf, USBPRN_PRINT_MAXLINE);
			USB_DPRINTF_L4(PRINT_MASK_ATTA,
			    usbprnp->usbprn_log_handle, "%s", pbuf);
			tmp += USBPRN_PRINT_MAXLINE;
			len -= USBPRN_PRINT_MAXLINE;
		}
	}
}


static void
usbprn_pm_busy_component(usbprn_state_t *usbprn_statep)
{
	ASSERT(!mutex_owned(&usbprn_statep->usbprn_mutex));
	if (usbprn_statep->usbprn_pm != NULL) {
		mutex_enter(&usbprn_statep->usbprn_mutex);
		usbprn_statep->usbprn_pm->usbprn_pm_busy++;

		USB_DPRINTF_L4(PRINT_MASK_PM, usbprn_statep->usbprn_log_handle,
		    "usbprn_pm_busy_component: %d",
		    usbprn_statep->usbprn_pm->usbprn_pm_busy);

		mutex_exit(&usbprn_statep->usbprn_mutex);

		if (pm_busy_component(usbprn_statep->usbprn_dip, 0) !=
		    DDI_SUCCESS) {
			mutex_enter(&usbprn_statep->usbprn_mutex);
			usbprn_statep->usbprn_pm->usbprn_pm_busy--;

			USB_DPRINTF_L2(PRINT_MASK_PM,
			    usbprn_statep->usbprn_log_handle,
			    "usbprn_pm_busy_component: %d",
			    usbprn_statep->usbprn_pm->usbprn_pm_busy);

			mutex_exit(&usbprn_statep->usbprn_mutex);
		}

	}
}


static void
usbprn_pm_idle_component(usbprn_state_t *usbprn_statep)
{
	ASSERT(!mutex_owned(&usbprn_statep->usbprn_mutex));
	if (usbprn_statep->usbprn_pm != NULL) {
		if (pm_idle_component(usbprn_statep->usbprn_dip, 0) ==
		    DDI_SUCCESS) {
			mutex_enter(&usbprn_statep->usbprn_mutex);
			ASSERT(usbprn_statep->usbprn_pm->usbprn_pm_busy > 0);
			usbprn_statep->usbprn_pm->usbprn_pm_busy--;

			USB_DPRINTF_L4(PRINT_MASK_PM,
			    usbprn_statep->usbprn_log_handle,
			    "usbprn_pm_idle_component: %d",
			    usbprn_statep->usbprn_pm->usbprn_pm_busy);

			mutex_exit(&usbprn_statep->usbprn_mutex);
		}

	}
}
