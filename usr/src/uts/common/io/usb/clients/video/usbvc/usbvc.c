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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * USB video class driver (usbvc(7D))
 *
 * 1. Overview
 * ------------
 *
 * This driver supports USB video class devices that used to capture video,
 * e.g., some webcams. It is developed according to "USB Device Class
 * Definition for Video Devices" spec. This spec defines detail info needed by
 * designing a USB video device. It is available at:
 * http://www.usb.org/developers/devclass_docs
 *
 * This driver implements:
 *
 *   - V4L2 interfaces for applications to communicate with video devices.
 *     V4L2 is an API that is widely used by video applications, like Ekiga,
 *     luvcview, etc. The API spec is at:
 *     http://www.thedirks.org/v4l2/
 *     This driver is according to V4L2 spec version 0.20
 *
 *   - Video capture function. (Video output is not supported by now.)
 *
 *   - Isochronous transfer for video data. (Bulk transfer is not supported.)
 *
 *   - read & mmap I/O methods for userland video applications to get video
 *     data. Userland video applications can use read() system call directly,
 *     it is the simplest way but not the most efficient way. Applications can
 *     also use mmap() system call to map several bufs (they are linked as a
 *     buf list), and then use some specific ioctls to start/stop isoc polling,
 *     to queue/dequeue bufs.
 *
 * 2. Source and header files
 * ---------------------------
 *
 * There are two source files and three header files for this driver:
 *
 *   - usbvc.c		Main source file, implements usb video class spec.
 *
 *   - usbvc_v4l2.c	V4L2 interface specific code.
 *
 *   - usbvc_var.h	Main header file, includes soft state structure.
 *
 *   - usbvc.h		The descriptors in usb video class spec.
 *
 *   - videodev2.h	This header file is included in V4L2 spec. It defines
 *     ioctls and data structures that used as an interface between video
 *     applications and video drivers. This is the only header file that
 *     usbvc driver should export to userland application.
 *
 * 3. USB video class devices overview
 * -----------------------------------
 * According to UVC spec, there must be one control interface in a UVC device.
 * Control interface is used to receive control commands from user, all the
 * commands are sent through default ctrl pipe. usbvc driver implements V4L2
 * API, so ioctls are implemented to relay user commands to UVC device.
 *
 * There can be no or multiple stream interfaces in a UVC device. Stream
 * interfaces are used to do video data I/O. In practice, if no stream
 * interface, the video device can do nothing since it has no data I/O.
 *
 * usbvc driver parses descriptors of control interface and stream interfaces.
 * The descriptors tell the function layout and the capability of the device.
 * During attach, usbvc driver set up some key data structures according to
 * the descriptors.
 *
 * 4. I/O methods
 * ---------------
 *
 * Userland applications use ioctls to set/get video formats of the device,
 * and control brightness, contrast, image size, etc.
 *
 * Besides implementing standard read I/O method to get video data from
 * the device, usbvc driver also implements some specific ioctls to implement
 * mmap I/O method.
 *
 * A view from userland application: ioctl and mmap flow chart:
 *
 * REQBUFS -> QUERYBUF -> mmap() ->
 *
 *    -> QBUF -> STREAMON -> DQBUF -> process image -> QBUF
 *			       ^			|
 *			       |			|
 *			       |			v
 *			       |---<--------------------
 *
 * The above queue and dequeue buf operations can be stopped by issuing a
 * STREAMOFF ioctl.
 *
 * 5. Device states
 * ----------------
 *
 * The device has four states (refer to usbai.h):
 *
 *	- USB_DEV_ONLINE: In action or ready for action.
 *
 *	- USB_DEV_DISCONNECTED: Hotplug removed, or device not present/correct
 *				on resume (CPR).
 *
 *	- USB_DEV_SUSPENDED: Device has been suspended along with the system.
 *
 *	- USB_DEV_PWRED_DOWN: Device has been powered down.  (Note that this
 *		driver supports only two power states, powered down and
 *		full power.)
 *
 * 6. Serialize
 * -------------
 * In order to avoid race conditions between driver entry points, access to
 * the device is serialized. All the ioctls, and read, open/close are
 * serialized. The functions usbvc_serialize/release_access are implemented
 * for this purpose.
 *
 * 7. PM & CPR
 * ------------
 * PM & CPR are supported. pm_busy_component and pm_idle_component mark
 * the device as busy or idle to the system.
 */

#if defined(lint) && !defined(DEBUG)
#define	DEBUG
#endif

#define	USBDRV_MAJOR_VER	2
#define	USBDRV_MINOR_VER	0

#include <sys/usb/usba.h>
#include <sys/fcntl.h>
#include <sys/cmn_err.h>
#include <sys/usb/clients/video/usbvc/usbvc_var.h>
#include <sys/videodev2.h> /* V4L2 API header file */

/* Descriptors according to USB video class spec */
#include <sys/usb/clients/video/usbvc/usbvc.h>

static uint_t	usbvc_errmask		= (uint_t)PRINT_MASK_ALL;
static uint_t	usbvc_errlevel = 4;
static uint_t	usbvc_instance_debug = (uint_t)-1;

static char	*name = "usbvc";	/* Driver name, used all over. */

/*
 * Function Prototypes
 */

/* Entries */
static int	usbvc_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	usbvc_attach(dev_info_t *, ddi_attach_cmd_t);
static int	usbvc_detach(dev_info_t *, ddi_detach_cmd_t);
static void	usbvc_cleanup(dev_info_t *, usbvc_state_t *);
static int	usbvc_open(dev_t *, int, int, cred_t *);
static int	usbvc_close(dev_t, int, int, cred_t *);
static int	usbvc_read(dev_t, struct uio *uip_p, cred_t *);
static int	usbvc_strategy(struct buf *);
static void	usbvc_minphys(struct buf *);
static int	usbvc_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int	usbvc_devmap(dev_t, devmap_cookie_t, offset_t,
		    size_t, size_t *, uint_t);

/* pm and cpr */
static int	usbvc_power(dev_info_t *, int, int);
static void	usbvc_init_power_mgmt(usbvc_state_t *);
static void	usbvc_destroy_power_mgmt(usbvc_state_t *);
static void	usbvc_pm_busy_component(usbvc_state_t *);
static void	usbvc_pm_idle_component(usbvc_state_t *);
static int	usbvc_pwrlvl0(usbvc_state_t *);
static int	usbvc_pwrlvl1(usbvc_state_t *);
static int	usbvc_pwrlvl2(usbvc_state_t *);
static int	usbvc_pwrlvl3(usbvc_state_t *);
static void	usbvc_cpr_suspend(dev_info_t *);
static void	usbvc_cpr_resume(dev_info_t *);
static void	usbvc_restore_device_state(dev_info_t *, usbvc_state_t *);

/* Events */
static int	usbvc_disconnect_event_cb(dev_info_t *);
static int	usbvc_reconnect_event_cb(dev_info_t *);

/* Sync objs and lists */
static void	usbvc_init_sync_objs(usbvc_state_t *);
static void	usbvc_fini_sync_objs(usbvc_state_t *);
static void	usbvc_init_lists(usbvc_state_t *);
static void	usbvc_fini_lists(usbvc_state_t *);
static void	usbvc_free_ctrl_descr(usbvc_state_t *);
static void	usbvc_free_stream_descr(usbvc_state_t *);

/* Parse descriptors */
static int	usbvc_chk_descr_len(uint8_t, uint8_t, uint8_t,
		    usb_cvs_data_t *);
static usbvc_stream_if_t *usbvc_parse_stream_if(usbvc_state_t *, int);
static int	usbvc_parse_ctrl_if(usbvc_state_t *);
static int	usbvc_parse_stream_ifs(usbvc_state_t *);
static void	usbvc_parse_color_still(usbvc_state_t *,
		    usbvc_format_group_t *, usb_cvs_data_t *, uint_t, uint_t);
static void	usbvc_parse_frames(usbvc_state_t *, usbvc_format_group_t *,
		    usb_cvs_data_t *, uint_t, uint_t);
static int	usbvc_parse_format_group(usbvc_state_t *,
		    usbvc_format_group_t *, usb_cvs_data_t *, uint_t, uint_t);
static int	usbvc_parse_format_groups(usbvc_state_t *, usbvc_stream_if_t *);
static int	usbvc_parse_stream_header(usbvc_state_t *, usbvc_stream_if_t *);

/* read I/O functions */
static int	usbvc_alloc_read_bufs(usbvc_state_t *, usbvc_stream_if_t *);
static int	usbvc_read_buf(usbvc_state_t *, struct buf *);
static void	usbvc_free_read_buf(usbvc_buf_t *);
static void	usbvc_free_read_bufs(usbvc_state_t *, usbvc_stream_if_t *);
static void	usbvc_close_isoc_pipe(usbvc_state_t *, usbvc_stream_if_t *);

/* callbacks */
static void	usbvc_isoc_cb(usb_pipe_handle_t, usb_isoc_req_t *);
static void	usbvc_isoc_exc_cb(usb_pipe_handle_t, usb_isoc_req_t *);

/* Others */
static int	usbvc_set_alt(usbvc_state_t *, usbvc_stream_if_t *);
static int	usbvc_decode_stream_header(usbvc_state_t *, usbvc_buf_grp_t *,
		    mblk_t *, int);
static int	usbvc_serialize_access(usbvc_state_t *, boolean_t);
static void	usbvc_release_access(usbvc_state_t *);
static int		usbvc_set_default_stream_fmt(usbvc_state_t *);

static usb_event_t usbvc_events = {
	usbvc_disconnect_event_cb,
	usbvc_reconnect_event_cb,
	NULL, NULL
};

/* module loading stuff */
struct cb_ops usbvc_cb_ops = {
	usbvc_open,		/* open  */
	usbvc_close,		/* close */
	usbvc_strategy,	/* strategy */
	nulldev,		/* print */
	nulldev,		/* dump */
	usbvc_read,		/* read */
	nodev,			/* write */
	usbvc_ioctl,		/* ioctl */
	usbvc_devmap,		/* devmap */
	nodev,			/* mmap */
	ddi_devmap_segmap,	/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* streamtab  */
	D_MP | D_DEVMAP
};

static struct dev_ops usbvc_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	usbvc_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	usbvc_attach,		/* attach */
	usbvc_detach,		/* detach */
	nodev,			/* reset */
	&usbvc_cb_ops,	/* driver operations */
	NULL,			/* bus operations */
	usbvc_power,		/* power */
	ddi_quiesce_not_needed,	/* quiesce */
};

static struct modldrv usbvc_modldrv =	{
	&mod_driverops,
	"USB video class driver",
	&usbvc_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&usbvc_modldrv,
	NULL
};

/* Soft state structures */
#define	USBVC_INITIAL_SOFT_SPACE	1
static void *usbvc_statep;


/*
 * Module-wide initialization routine.
 */
int
_init(void)
{
	int rval;

	if ((rval = ddi_soft_state_init(&usbvc_statep,
	    sizeof (usbvc_state_t), USBVC_INITIAL_SOFT_SPACE)) != 0) {

		return (rval);
	}

	if ((rval = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&usbvc_statep);
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

	ddi_soft_state_fini(&usbvc_statep);

	return (rval);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * usbvc_info:
 *	Get minor number, soft state structure, etc.
 */
/*ARGSUSED*/
static int
usbvc_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
    void *arg, void **result)
{
	usbvc_state_t	*usbvcp;
	int error = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((usbvcp = ddi_get_soft_state(usbvc_statep,
		    getminor((dev_t)arg))) != NULL) {
			*result = usbvcp->usbvc_dip;
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
 * Entry functions.
 */

/*
 * usbvc_attach:
 *	Attach or resume.
 *
 *	For attach, initialize state and device, including:
 *		state variables, locks, device node
 *		device registration with system
 *		power management, hotplugging
 *	For resume, restore device and state
 */
static int
usbvc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance = ddi_get_instance(dip);
	usbvc_state_t		*usbvcp = NULL;
	int			status;

	switch (cmd) {
	case DDI_ATTACH:

		break;
	case DDI_RESUME:
		usbvc_cpr_resume(dip);

		return (DDI_SUCCESS);
	default:

		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(usbvc_statep, instance) == DDI_SUCCESS) {
		usbvcp = ddi_get_soft_state(usbvc_statep, instance);
	}
	if (usbvcp == NULL)  {

		return (DDI_FAILURE);
	}

	usbvcp->usbvc_dip = dip;

	usbvcp->usbvc_log_handle = usb_alloc_log_hdl(dip,
	    "usbvc", &usbvc_errlevel,
	    &usbvc_errmask, &usbvc_instance_debug, 0);

	USB_DPRINTF_L3(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
	    "usbvc_attach: enter");

	if ((status = usb_client_attach(dip, USBDRV_VERSION, 0)) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
		    "usbvc_attach: usb_client_attach failed, error code:%d",
		    status);

		goto fail;
	}

	if ((status = usb_get_dev_data(dip, &usbvcp->usbvc_reg,
	    USB_PARSE_LVL_ALL, 0)) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
		    "usbvc_attach: usb_get_dev_data failed, error code:%d",
		    status);

		goto fail;
	}
	usbvc_init_sync_objs(usbvcp);

	/* create minor node */
	if ((status = ddi_create_minor_node(dip, name, S_IFCHR, instance,
	    "usb_video", 0)) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
		    "usbvc_attach: Error creating minor node, error code:%d",
		    status);

		goto fail;
	}

	mutex_enter(&usbvcp->usbvc_mutex);
	usbvc_init_lists(usbvcp);

	usbvcp->usbvc_default_ph = usbvcp->usbvc_reg->dev_default_ph;

	/* Put online before PM init as can get power managed afterward. */
	usbvcp->usbvc_dev_state = USB_DEV_ONLINE;
	mutex_exit(&usbvcp->usbvc_mutex);

	/* initialize power management */
	usbvc_init_power_mgmt(usbvcp);

	if ((status = usbvc_parse_ctrl_if(usbvcp)) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
		    "usbvc_attach: parse ctrl interface fail, error code:%d",
		    status);

		goto fail;
	}
	if ((status = usbvc_parse_stream_ifs(usbvcp)) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
		    "usbvc_attach: parse stream interfaces fail, error code:%d",
		    status);

		goto fail;
	}
	(void) usbvc_set_default_stream_fmt(usbvcp);

	/* Register for events */
	if ((status = usb_register_event_cbs(dip, &usbvc_events, 0)) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
		    "usbvc_attach: register_event_cbs failed, error code:%d",
		    status);

		goto fail;
	}

	/* Report device */
	ddi_report_dev(dip);

	return (DDI_SUCCESS);

fail:
	if (usbvcp) {
		usbvc_cleanup(dip, usbvcp);
	}

	return (DDI_FAILURE);
}


/*
 * usbvc_detach:
 *	detach or suspend driver instance
 *
 * Note: in detach, only contention threads is from pm and disconnnect.
 */
static int
usbvc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance = ddi_get_instance(dip);
	usbvc_state_t	*usbvcp = ddi_get_soft_state(usbvc_statep, instance);
	int		rval = USB_FAILURE;

	switch (cmd) {
	case DDI_DETACH:
		mutex_enter(&usbvcp->usbvc_mutex);
		ASSERT((usbvcp->usbvc_drv_state & USBVC_OPEN) == 0);
		mutex_exit(&usbvcp->usbvc_mutex);

		USB_DPRINTF_L3(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
		    "usbvc_detach: enter for detach");

		usbvc_cleanup(dip, usbvcp);
		rval = USB_SUCCESS;

		break;
	case DDI_SUSPEND:
		USB_DPRINTF_L3(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
		    "usbvc_detach: enter for suspend");

		usbvc_cpr_suspend(dip);
		rval = USB_SUCCESS;

		break;
	default:

		break;
	}

	return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}


/*
 * usbvc_cleanup:
 *	clean up the driver state for detach
 */
static void
usbvc_cleanup(dev_info_t *dip, usbvc_state_t *usbvcp)
{
	USB_DPRINTF_L4(PRINT_MASK_OPEN, usbvcp->usbvc_log_handle,
	    "Cleanup: enter");

	if (usbvcp->usbvc_locks_initialized) {

		/* This must be done 1st to prevent more events from coming. */
		usb_unregister_event_cbs(dip, &usbvc_events);

		/*
		 * At this point, no new activity can be initiated. The driver
		 * has disabled hotplug callbacks. The Solaris framework has
		 * disabled new opens on a device being detached, and does not
		 * allow detaching an open device.
		 *
		 * The following ensures that all driver activity has drained.
		 */
		mutex_enter(&usbvcp->usbvc_mutex);
		(void) usbvc_serialize_access(usbvcp, USBVC_SER_NOSIG);
		usbvc_release_access(usbvcp);
		mutex_exit(&usbvcp->usbvc_mutex);

		/* All device activity has died down. */
		usbvc_destroy_power_mgmt(usbvcp);
		mutex_enter(&usbvcp->usbvc_mutex);
		usbvc_fini_lists(usbvcp);
		mutex_exit(&usbvcp->usbvc_mutex);

		ddi_remove_minor_node(dip, NULL);
		usbvc_fini_sync_objs(usbvcp);
	}

	usb_client_detach(dip, usbvcp->usbvc_reg);
	usb_free_log_hdl(usbvcp->usbvc_log_handle);
	ddi_soft_state_free(usbvc_statep, ddi_get_instance(dip));
	ddi_prop_remove_all(dip);
}


/*ARGSUSED*/
static int
usbvc_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	usbvc_state_t	*usbvcp =
	    ddi_get_soft_state(usbvc_statep, getminor(*devp));

	if (usbvcp == NULL) {

		return (ENXIO);
	}

	/*
	 * Keep it simple: one client at a time.
	 * Exclusive open only
	 */
	mutex_enter(&usbvcp->usbvc_mutex);
	USB_DPRINTF_L4(PRINT_MASK_OPEN, usbvcp->usbvc_log_handle,
	    "usbvc_open: enter, dev_stat=%d", usbvcp->usbvc_dev_state);

	if (usbvcp->usbvc_dev_state == USB_DEV_DISCONNECTED) {
		mutex_exit(&usbvcp->usbvc_mutex);

		return (ENODEV);
	}
	if (usbvcp->usbvc_dev_state == USB_DEV_SUSPENDED) {
		mutex_exit(&usbvcp->usbvc_mutex);

		return (EIO);
	}
	if ((usbvcp->usbvc_drv_state & USBVC_OPEN) != 0) {
		mutex_exit(&usbvcp->usbvc_mutex);

		return (EBUSY);
	}
	usbvcp->usbvc_drv_state |= USBVC_OPEN;

	if (usbvc_serialize_access(usbvcp, USBVC_SER_SIG) == 0) {
		usbvcp->usbvc_drv_state &= ~USBVC_OPEN;
		usbvcp->usbvc_serial_inuse = B_FALSE;
		mutex_exit(&usbvcp->usbvc_mutex);

		return (EINTR);
	}

	/* raise power */
	usbvc_pm_busy_component(usbvcp);
	if (usbvcp->usbvc_pm->usbvc_current_power != USB_DEV_OS_FULL_PWR) {
		usbvcp->usbvc_pm->usbvc_raise_power = B_TRUE;
		mutex_exit(&usbvcp->usbvc_mutex);
		(void) pm_raise_power(usbvcp->usbvc_dip,
		    0, USB_DEV_OS_FULL_PWR);
		mutex_enter(&usbvcp->usbvc_mutex);
		usbvcp->usbvc_pm->usbvc_raise_power = B_FALSE;
	}

	/* Device is idle until it is used. */
	usbvc_release_access(usbvcp);
	mutex_exit(&usbvcp->usbvc_mutex);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
	    "usbvc_open: end.");

	return (0);
}


/*ARGSUSED*/
static int
usbvc_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	usbvc_stream_if_t *strm_if;
	int		if_num;
	usbvc_state_t	*usbvcp =
	    ddi_get_soft_state(usbvc_statep, getminor(dev));

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, usbvcp->usbvc_log_handle,
	    "close: enter");

	mutex_enter(&usbvcp->usbvc_mutex);
	(void) usbvc_serialize_access(usbvcp, USBVC_SER_NOSIG);
	mutex_exit(&usbvcp->usbvc_mutex);

	/* Perform device session cleanup here. */

	USB_DPRINTF_L3(PRINT_MASK_CLOSE, usbvcp->usbvc_log_handle,
	    "close: cleaning up...");

	/*
	 * USBA automatically flushes/resets active non-default pipes
	 * when they are closed.  We can't reset default pipe, but we
	 * can wait for all requests on it from this dip to drain.
	 */
	(void) usb_pipe_drain_reqs(usbvcp->usbvc_dip,
	    usbvcp->usbvc_reg->dev_default_ph, 0,
	    USB_FLAGS_SLEEP, NULL, 0);

	mutex_enter(&usbvcp->usbvc_mutex);
	strm_if = usbvcp->usbvc_curr_strm;
	if (strm_if->start_polling == 1) {
		mutex_exit(&usbvcp->usbvc_mutex);
		usb_pipe_stop_isoc_polling(strm_if->datain_ph, USB_FLAGS_SLEEP);
		mutex_enter(&usbvcp->usbvc_mutex);
		strm_if->start_polling = 0;
	}
	strm_if->stream_on = 0;

	usbvc_close_isoc_pipe(usbvcp, strm_if);
	if_num = strm_if->if_descr->if_alt->altif_descr.bInterfaceNumber;
	mutex_exit(&usbvcp->usbvc_mutex);

	/* reset alternate to the default one. */
	(void) usb_set_alt_if(usbvcp->usbvc_dip, if_num, 0,
	    USB_FLAGS_SLEEP, NULL, NULL);
	mutex_enter(&usbvcp->usbvc_mutex);

	usbvc_free_read_bufs(usbvcp, strm_if);

	/* reset the desired read buf number to the default value on close */
	strm_if->buf_read_num = USBVC_DEFAULT_READ_BUF_NUM;

	usbvc_free_map_bufs(usbvcp, strm_if);
	usbvcp->usbvc_drv_state &= ~USBVC_OPEN;

	usbvc_release_access(usbvcp);
	usbvc_pm_idle_component(usbvcp);
	mutex_exit(&usbvcp->usbvc_mutex);

	return (0);
}


/*ARGSUSED*/
/* Read isoc data from usb video devices */
static int
usbvc_read(dev_t dev, struct uio *uio_p, cred_t *cred_p)
{
	int			rval;
	usbvc_stream_if_t	*strm_if;
	usbvc_state_t	*usbvcp =
	    ddi_get_soft_state(usbvc_statep, getminor(dev));

	USB_DPRINTF_L4(PRINT_MASK_READ, usbvcp->usbvc_log_handle,
	    "usbvc_read: enter");
	mutex_enter(&usbvcp->usbvc_mutex);
	if (usbvcp->usbvc_dev_state != USB_DEV_ONLINE) {
		USB_DPRINTF_L2(PRINT_MASK_READ, usbvcp->usbvc_log_handle,
		    "usbvc_read: Device is not available,"
		    " dev_stat=%d", usbvcp->usbvc_dev_state);
		mutex_exit(&usbvcp->usbvc_mutex);

		return (EFAULT);
	}
	if ((uio_p->uio_fmode & (FNDELAY|FNONBLOCK)) &&
	    (usbvcp->usbvc_serial_inuse != B_FALSE)) {
		USB_DPRINTF_L2(PRINT_MASK_READ, usbvcp->usbvc_log_handle,
		    "usbvc_read: non-blocking read, return fail.");
		mutex_exit(&usbvcp->usbvc_mutex);

		return (EAGAIN);
	}
	if (usbvc_serialize_access(usbvcp, USBVC_SER_SIG) <= 0) {
		USB_DPRINTF_L2(PRINT_MASK_READ, usbvcp->usbvc_log_handle,
		    "usbvc_read: serialize_access failed.");
		rval = EFAULT;

		goto fail;
	}

	/* Get the first stream interface */
	strm_if = usbvcp->usbvc_curr_strm;
	if (!strm_if) {
		USB_DPRINTF_L2(PRINT_MASK_READ, usbvcp->usbvc_log_handle,
		    "usbvc_read: no stream interfaces");
		rval = EFAULT;

		goto fail;
	}

	/*
	 * If it is the first read, open isoc pipe and allocate bufs for
	 * read I/O method.
	 */
	if (strm_if->datain_ph == NULL) {
		if (usbvc_open_isoc_pipe(usbvcp, strm_if) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_READ,
			    usbvcp->usbvc_log_handle,
			    "usbvc_read: first read, open pipe fail");
			rval = EFAULT;

			goto fail;
		}
		if (usbvc_alloc_read_bufs(usbvcp, strm_if) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_READ,
			    usbvcp->usbvc_log_handle,
			    "usbvc_read: allocate rw bufs fail");
			rval = EFAULT;

			goto fail;
		}
	}

	/* start polling if it is not started yet */
	if (strm_if->start_polling != 1) {
		if (usbvc_start_isoc_polling(usbvcp, strm_if, 0) !=
		    USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_READ,
			    usbvcp->usbvc_log_handle,
			    "usbvc_read: usbvc_start_isoc_polling fail");
			rval = EFAULT;

			goto fail;
		}
		strm_if->start_polling = 1;
	}

	if (list_is_empty(&strm_if->buf_read.uv_buf_done)) {
		USB_DPRINTF_L3(PRINT_MASK_READ, usbvcp->usbvc_log_handle,
		    "usbvc_read: full buf list is empty.");

		if (uio_p->uio_fmode & (FNDELAY | FNONBLOCK)) {
			USB_DPRINTF_L2(PRINT_MASK_READ,
			    usbvcp->usbvc_log_handle, "usbvc_read: fail, "
			    "non-blocking read, done buf is empty.");
			rval = EAGAIN;

			goto fail;
		}

		/* no available buffers, block here */
		while (list_is_empty(&strm_if->buf_read.uv_buf_done)) {
			USB_DPRINTF_L3(PRINT_MASK_READ,
			    usbvcp->usbvc_log_handle,
			    "usbvc_read: wait for done buf");
			if (cv_wait_sig(&usbvcp->usbvc_read_cv,
			    &usbvcp->usbvc_mutex) <= 0) {
				/* no done buf and cv is signaled */
				rval = EINTR;

				goto fail;
			}
			if (usbvcp->usbvc_dev_state != USB_DEV_ONLINE) {

				/* Device is disconnected. */
				rval = EINTR;

				goto fail;
			}
		}

	}

	mutex_exit(&usbvcp->usbvc_mutex);
	rval = physio(usbvc_strategy, NULL, dev, B_READ,
	    usbvc_minphys, uio_p);

	mutex_enter(&usbvcp->usbvc_mutex);
	usbvc_release_access(usbvcp);
	mutex_exit(&usbvcp->usbvc_mutex);

	return (rval);

fail:
	usbvc_release_access(usbvcp);
	mutex_exit(&usbvcp->usbvc_mutex);

	return (rval);
}


/*
 * strategy:
 *	Called through physio to setup and start the transfer.
 */
static int
usbvc_strategy(struct buf *bp)
{
	usbvc_state_t *usbvcp = ddi_get_soft_state(usbvc_statep,
	    getminor(bp->b_edev));

	USB_DPRINTF_L4(PRINT_MASK_READ, usbvcp->usbvc_log_handle,
	    "usbvc_strategy: enter");

	/*
	 * Initialize residual count here in case transfer doesn't even get
	 * started.
	 */
	bp->b_resid = bp->b_bcount;

	/* Needed as this is a character driver. */
	if (bp->b_flags & (B_PHYS | B_PAGEIO)) {
		bp_mapin(bp);
	}

	mutex_enter(&usbvcp->usbvc_mutex);

	/* Make sure device has not been disconnected. */
	if (usbvcp->usbvc_dev_state != USB_DEV_ONLINE) {
		USB_DPRINTF_L2(PRINT_MASK_READ, usbvcp->usbvc_log_handle,
		    "usbvc_strategy: device can't be accessed");
		mutex_exit(&usbvcp->usbvc_mutex);

		goto fail;
	}

	/* read data from uv_buf_done list */
	if (usbvc_read_buf(usbvcp, bp) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_READ, usbvcp->usbvc_log_handle,
		    "usbvc_strategy: read full buf list fail");
		mutex_exit(&usbvcp->usbvc_mutex);

		goto fail;
	}

	mutex_exit(&usbvcp->usbvc_mutex);

	biodone(bp);

	return (0);

fail:
	USB_DPRINTF_L2(PRINT_MASK_READ, usbvcp->usbvc_log_handle,
	    "usbvc_strategy: strategy fail");
	bp->b_private = NULL;

	bioerror(bp, EIO);
	biodone(bp);

	return (0);
}


static void
usbvc_minphys(struct buf *bp)
{
	dev_t			dev = bp->b_edev;
	usbvc_stream_if_t	*strm_if;
	uint32_t		maxsize;
	usbvc_state_t		*usbvcp =
	    ddi_get_soft_state(usbvc_statep, getminor(dev));

	mutex_enter(&usbvcp->usbvc_mutex);
	strm_if = usbvcp->usbvc_curr_strm;
	LE_TO_UINT32(strm_if->ctrl_pc.dwMaxVideoFrameSize, 0, maxsize);
	USB_DPRINTF_L3(PRINT_MASK_READ, usbvcp->usbvc_log_handle,
	    "usbvc_minphys: max read size=%d", maxsize);

	if (bp->b_bcount > maxsize) {
		bp->b_bcount = maxsize;
	}
	mutex_exit(&usbvcp->usbvc_mutex);
}


/*
 * ioctl entry.
 */
/*ARGSUSED*/
static int
usbvc_ioctl(dev_t dev, int cmd, intptr_t arg,
    int mode, cred_t *cred_p, int *rval_p)
{
	int		rv = 0;
	usbvc_state_t	*usbvcp =
	    ddi_get_soft_state(usbvc_statep, getminor(dev));

	if (usbvcp == NULL) {

		return (ENXIO);
	}
	USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
	    "ioctl enter, cmd=%x", cmd);
	mutex_enter(&usbvcp->usbvc_mutex);
	if (usbvcp->usbvc_dev_state != USB_DEV_ONLINE) {
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "ioctl: Device is not online,"
		    " dev_stat=%d", usbvcp->usbvc_dev_state);
		mutex_exit(&usbvcp->usbvc_mutex);

		return (EFAULT);
	}
	if (usbvc_serialize_access(usbvcp, USBVC_SER_SIG) <= 0) {
		usbvcp->usbvc_serial_inuse = B_FALSE;
		mutex_exit(&usbvcp->usbvc_mutex);
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "serialize_access failed.");

		return (EFAULT);
	}
	mutex_exit(&usbvcp->usbvc_mutex);

	rv = usbvc_v4l2_ioctl(usbvcp, cmd, arg, mode);

	mutex_enter(&usbvcp->usbvc_mutex);
	usbvc_release_access(usbvcp);
	mutex_exit(&usbvcp->usbvc_mutex);

	USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
	    "usbvc_ioctl exit");

	return (rv);
}


/* Entry for mmap system call */
static int
usbvc_devmap(dev_t dev, devmap_cookie_t handle, offset_t off,
    size_t len, size_t *maplen, uint_t model)
{
	usbvc_state_t		*usbvcp;
	int			error, i;
	usbvc_buf_t		*buf = NULL;
	usbvc_stream_if_t	*strm_if;
	usbvc_buf_grp_t		*bufgrp;

	usbvcp = ddi_get_soft_state(usbvc_statep, getminor(dev));
	if (usbvcp == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_DEVMAP, usbvcp->usbvc_log_handle,
		    "usbvc_devmap: usbvcp == NULL");

		return (ENXIO);
	}

	USB_DPRINTF_L3(PRINT_MASK_DEVMAP, usbvcp->usbvc_log_handle,
	    "devmap: memory map for instance(%d), off=%llx,"
	    "len=%ld, maplen=%ld, model=%d", getminor(dev), off,
	    len, *maplen, model);

	mutex_enter(&usbvcp->usbvc_mutex);
	(void) usbvc_serialize_access(usbvcp, USBVC_SER_NOSIG);
	strm_if = usbvcp->usbvc_curr_strm;
	if (!strm_if) {
		USB_DPRINTF_L2(PRINT_MASK_DEVMAP, usbvcp->usbvc_log_handle,
		    "usbvc_devmap: No current strm if");
		mutex_exit(&usbvcp->usbvc_mutex);

		return (ENXIO);
	}
	bufgrp = &strm_if->buf_map;
	for (i = 0; i < bufgrp->buf_cnt; i++) {
		if (bufgrp->buf_head[i].v4l2_buf.m.offset == off) {
			buf = &bufgrp->buf_head[i];

			break;
		}
	}
	USB_DPRINTF_L3(PRINT_MASK_DEVMAP, usbvcp->usbvc_log_handle,
	    "usbvc_devmap: idx=%d", i);
	if (buf == NULL) {
		mutex_exit(&usbvcp->usbvc_mutex);

		return (ENXIO);
	}
	/*
	 * round up len to a multiple of a page size, according to chapter
	 * 10 of "writing device drivers"
	 */
	len = ptob(btopr(len));
	if (len > ptob(btopr(buf->len))) {
		USB_DPRINTF_L2(PRINT_MASK_DEVMAP, usbvcp->usbvc_log_handle,
		    "usbvc_devmap: len=0x%lx", len);
		mutex_exit(&usbvcp->usbvc_mutex);

		return (ENXIO);
	}
	mutex_exit(&usbvcp->usbvc_mutex);

	error = devmap_umem_setup(handle, usbvcp->usbvc_dip, NULL,
	    buf->umem_cookie, off, len, PROT_ALL, DEVMAP_DEFAULTS, NULL);
	mutex_enter(&usbvcp->usbvc_mutex);
	*maplen = len;
	if (error == 0 && buf->status == USBVC_BUF_INIT) {
		buf->status = USBVC_BUF_MAPPED;
	} else {
		USB_DPRINTF_L3(PRINT_MASK_DEVMAP, usbvcp->usbvc_log_handle,
		    "usbvc_devmap: devmap_umem_setup, err=%d", error);
	}

	(void) usbvc_release_access(usbvcp);
	mutex_exit(&usbvcp->usbvc_mutex);

	return (error);
}

/*
 * pm and cpr
 */

/*
 *  usbvc_power :
 *	Power entry point, the workhorse behind pm_raise_power, pm_lower_power,
 *	usb_req_raise_power and usb_req_lower_power.
 */
/* ARGSUSED */
static int
usbvc_power(dev_info_t *dip, int comp, int level)
{
	usbvc_state_t	*usbvcp;
	usbvc_power_t	*pm;
	int		rval = USB_FAILURE;

	usbvcp = ddi_get_soft_state(usbvc_statep, ddi_get_instance(dip));
	mutex_enter(&usbvcp->usbvc_mutex);
	USB_DPRINTF_L4(PRINT_MASK_PM, usbvcp->usbvc_log_handle,
	    "usbvc_power: enter: level = %d, dev_state: %x",
	    level, usbvcp->usbvc_dev_state);

	if (usbvcp->usbvc_pm == NULL) {

		goto done;
	}

	pm = usbvcp->usbvc_pm;

	/* Check if we are transitioning to a legal power level */
	if (USB_DEV_PWRSTATE_OK(pm->usbvc_pwr_states, level)) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
		    "usbvc_power: illegal power level = %d "
		    "pwr_states: %x", level, pm->usbvc_pwr_states);

		goto done;
	}
	/*
	 * if we are about to raise power and asked to lower power, fail
	 */
	if (pm->usbvc_raise_power && (level < (int)pm->usbvc_current_power)) {

		goto done;
	}
	switch (level) {
	case USB_DEV_OS_PWR_OFF :
		rval = usbvc_pwrlvl0(usbvcp);

		break;
	case USB_DEV_OS_PWR_1 :
		rval = usbvc_pwrlvl1(usbvcp);

		break;
	case USB_DEV_OS_PWR_2 :
		rval = usbvc_pwrlvl2(usbvcp);

		break;
	case USB_DEV_OS_FULL_PWR :
		rval = usbvc_pwrlvl3(usbvcp);

		break;
	}

done:
	mutex_exit(&usbvcp->usbvc_mutex);

	return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}


/*
 * usbvc_init_power_mgmt:
 *	Initialize power management and remote wakeup functionality.
 *	No mutex is necessary in this function as it's called only by attach.
 */
static void
usbvc_init_power_mgmt(usbvc_state_t *usbvcp)
{
	usbvc_power_t	*usbvcpm;
	uint_t		pwr_states;

	USB_DPRINTF_L4(PRINT_MASK_PM, usbvcp->usbvc_log_handle,
	    "init_power_mgmt enter");

	/* Allocate the state structure */
	usbvcpm = kmem_zalloc(sizeof (usbvc_power_t), KM_SLEEP);
	mutex_enter(&usbvcp->usbvc_mutex);
	usbvcp->usbvc_pm = usbvcpm;
	usbvcpm->usbvc_state = usbvcp;
	usbvcpm->usbvc_pm_capabilities = 0;
	usbvcpm->usbvc_current_power = USB_DEV_OS_FULL_PWR;
	mutex_exit(&usbvcp->usbvc_mutex);

	if (usb_create_pm_components(usbvcp->usbvc_dip, &pwr_states) ==
	    USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_PM, usbvcp->usbvc_log_handle,
		    "usbvc_init_power_mgmt: created PM components");

		if (usb_handle_remote_wakeup(usbvcp->usbvc_dip,
		    USB_REMOTE_WAKEUP_ENABLE) == USB_SUCCESS) {
			usbvcpm->usbvc_wakeup_enabled = 1;
		} else {
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    usbvcp->usbvc_log_handle, "usbvc_init_power_mgmt:"
			    " remote wakeup not supported");
		}

		mutex_enter(&usbvcp->usbvc_mutex);
		usbvcpm->usbvc_pwr_states = (uint8_t)pwr_states;
		usbvc_pm_busy_component(usbvcp);
		usbvcpm->usbvc_raise_power = B_TRUE;
		mutex_exit(&usbvcp->usbvc_mutex);

		(void) pm_raise_power(
		    usbvcp->usbvc_dip, 0, USB_DEV_OS_FULL_PWR);

		mutex_enter(&usbvcp->usbvc_mutex);
		usbvcpm->usbvc_raise_power = B_FALSE;
		usbvc_pm_idle_component(usbvcp);
		mutex_exit(&usbvcp->usbvc_mutex);

	}
	USB_DPRINTF_L4(PRINT_MASK_PM, usbvcp->usbvc_log_handle,
	    "usbvc_init_power_mgmt: end");
}


/*
 *  usbvc_destroy_power_mgmt:
 *	Shut down and destroy power management and remote wakeup functionality.
 */
static void
usbvc_destroy_power_mgmt(usbvc_state_t *usbvcp)
{
	usbvc_power_t	*pm;
	int		rval;

	USB_DPRINTF_L4(PRINT_MASK_PM, usbvcp->usbvc_log_handle,
	    "destroy_power_mgmt enter");
	mutex_enter(&usbvcp->usbvc_mutex);
	pm = usbvcp->usbvc_pm;
	if (pm && (usbvcp->usbvc_dev_state != USB_DEV_DISCONNECTED)) {

		usbvc_pm_busy_component(usbvcp);
		if (pm->usbvc_wakeup_enabled) {
			pm->usbvc_raise_power = B_TRUE;
			mutex_exit(&usbvcp->usbvc_mutex);

			/* First bring the device to full power */
			(void) pm_raise_power(usbvcp->usbvc_dip, 0,
			    USB_DEV_OS_FULL_PWR);
			if ((rval = usb_handle_remote_wakeup(
			    usbvcp->usbvc_dip,
			    USB_REMOTE_WAKEUP_DISABLE)) !=
			    USB_SUCCESS) {
				USB_DPRINTF_L2(PRINT_MASK_ATTA,
				    usbvcp->usbvc_log_handle,
				    "usbvc_destroy_power_mgmt: "
				    "Error disabling rmt wakeup: rval = %d",
				    rval);
			}
			mutex_enter(&usbvcp->usbvc_mutex);
			pm->usbvc_raise_power = B_FALSE;

		}
		mutex_exit(&usbvcp->usbvc_mutex);

		/*
		 * Since remote wakeup is disabled now,
		 * no one can raise power
		 * and get to device once power is lowered here.
		 */
		(void) pm_lower_power(usbvcp->usbvc_dip, 0, USB_DEV_OS_PWR_OFF);
		mutex_enter(&usbvcp->usbvc_mutex);
		usbvc_pm_idle_component(usbvcp);
	}

	if (pm) {
		kmem_free(pm, sizeof (usbvc_power_t));
		usbvcp->usbvc_pm = NULL;
	}
	mutex_exit(&usbvcp->usbvc_mutex);
}


static void
usbvc_pm_busy_component(usbvc_state_t *usbvcp)
{
	ASSERT(mutex_owned(&usbvcp->usbvc_mutex));
	USB_DPRINTF_L4(PRINT_MASK_PM, usbvcp->usbvc_log_handle,
	    "usbvc_pm_busy_component: enter");

	usbvcp->usbvc_pm->usbvc_pm_busy++;
	mutex_exit(&usbvcp->usbvc_mutex);

	if (pm_busy_component(usbvcp->usbvc_dip, 0) !=
	    DDI_SUCCESS) {
		mutex_enter(&usbvcp->usbvc_mutex);
		USB_DPRINTF_L2(PRINT_MASK_PM, usbvcp->usbvc_log_handle,
		    "usbvc_pm_busy_component: pm busy fail, usbvc_pm_busy=%d",
		    usbvcp->usbvc_pm->usbvc_pm_busy);

		usbvcp->usbvc_pm->usbvc_pm_busy--;
		mutex_exit(&usbvcp->usbvc_mutex);
	}
	mutex_enter(&usbvcp->usbvc_mutex);
	USB_DPRINTF_L4(PRINT_MASK_PM, usbvcp->usbvc_log_handle,
	    "usbvc_pm_busy_component: exit");
}


static void
usbvc_pm_idle_component(usbvc_state_t *usbvcp)
{
	ASSERT(mutex_owned(&usbvcp->usbvc_mutex));
	USB_DPRINTF_L4(PRINT_MASK_PM, usbvcp->usbvc_log_handle,
	    "usbvc_pm_idle_component: enter");

	if (usbvcp->usbvc_pm != NULL) {
		mutex_exit(&usbvcp->usbvc_mutex);
		if (pm_idle_component(usbvcp->usbvc_dip, 0) ==
		    DDI_SUCCESS) {
			mutex_enter(&usbvcp->usbvc_mutex);
			ASSERT(usbvcp->usbvc_pm->usbvc_pm_busy > 0);
			usbvcp->usbvc_pm->usbvc_pm_busy--;
			mutex_exit(&usbvcp->usbvc_mutex);
		}
		mutex_enter(&usbvcp->usbvc_mutex);
		USB_DPRINTF_L2(PRINT_MASK_PM, usbvcp->usbvc_log_handle,
		    "usbvc_pm_idle_component: %d",
		    usbvcp->usbvc_pm->usbvc_pm_busy);
	}
}


/*
 * usbvc_pwrlvl0:
 * Functions to handle power transition for OS levels 0 -> 3
 */
static int
usbvc_pwrlvl0(usbvc_state_t *usbvcp)
{
	int rval;

	USB_DPRINTF_L4(PRINT_MASK_PM, usbvcp->usbvc_log_handle,
	    "usbvc_pwrlvl0, dev_state: %x", usbvcp->usbvc_dev_state);

	switch (usbvcp->usbvc_dev_state) {
	case USB_DEV_ONLINE:
		/* Deny the powerdown request if the device is busy */
		if (usbvcp->usbvc_pm->usbvc_pm_busy != 0) {
			USB_DPRINTF_L2(PRINT_MASK_PM, usbvcp->usbvc_log_handle,
			    "usbvc_pwrlvl0: usbvc_pm_busy");

			return (USB_FAILURE);
		}

		/* Issue USB D3 command to the device here */
		rval = usb_set_device_pwrlvl3(usbvcp->usbvc_dip);
		ASSERT(rval == USB_SUCCESS);

		usbvcp->usbvc_dev_state = USB_DEV_PWRED_DOWN;
		usbvcp->usbvc_pm->usbvc_current_power = USB_DEV_OS_PWR_OFF;

		/* FALLTHRU */
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:
		/* allow a disconnect/cpr'ed device to go to lower power */

		return (USB_SUCCESS);
	case USB_DEV_PWRED_DOWN:
	default:
		USB_DPRINTF_L2(PRINT_MASK_PM, usbvcp->usbvc_log_handle,
		    "usbvc_pwrlvl0: illegal dev state");

		return (USB_FAILURE);
	}
}


/*
 * usbvc_pwrlvl1:
 *	Functions to handle power transition to OS levels -> 2
 */
static int
usbvc_pwrlvl1(usbvc_state_t *usbvcp)
{
	int	rval;

	USB_DPRINTF_L4(PRINT_MASK_PM, usbvcp->usbvc_log_handle,
	    "usbvc_pwrlvl1");

	/* Issue USB D2 command to the device here */
	rval = usb_set_device_pwrlvl2(usbvcp->usbvc_dip);
	ASSERT(rval == USB_SUCCESS);

	return (USB_FAILURE);
}


/*
 * usbvc_pwrlvl2:
 *	Functions to handle power transition to OS levels -> 1
 */
static int
usbvc_pwrlvl2(usbvc_state_t *usbvcp)
{
	int	rval;

	USB_DPRINTF_L4(PRINT_MASK_PM, usbvcp->usbvc_log_handle,
	    "usbvc_pwrlvl2");

	/* Issue USB D1 command to the device here */
	rval = usb_set_device_pwrlvl1(usbvcp->usbvc_dip);
	ASSERT(rval == USB_SUCCESS);

	return (USB_FAILURE);
}


/*
 * usbvc_pwrlvl3:
 *	Functions to handle power transition to OS level -> 0
 */
static int
usbvc_pwrlvl3(usbvc_state_t *usbvcp)
{
	USB_DPRINTF_L4(PRINT_MASK_PM, usbvcp->usbvc_log_handle,
	    "usbvc_pwrlvl3, dev_stat=%d", usbvcp->usbvc_dev_state);

	switch (usbvcp->usbvc_dev_state) {
	case USB_DEV_PWRED_DOWN:
		/* Issue USB D0 command to the device here */
		(void) usb_set_device_pwrlvl0(usbvcp->usbvc_dip);

		usbvcp->usbvc_dev_state = USB_DEV_ONLINE;
		usbvcp->usbvc_pm->usbvc_current_power =
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
		USB_DPRINTF_L2(PRINT_MASK_PM, usbvcp->usbvc_log_handle,
		    "usbvc_pwrlvl3: illegal dev state");

		return (USB_FAILURE);
	}
}


/*
 * usbvc_cpr_suspend:
 *	Clean up device.
 *	Wait for any IO to finish, then close pipes.
 *	Quiesce device.
 */
static void
usbvc_cpr_suspend(dev_info_t *dip)
{
	int		instance = ddi_get_instance(dip);
	usbvc_state_t	*usbvcp = ddi_get_soft_state(usbvc_statep, instance);

	USB_DPRINTF_L4(PRINT_MASK_PM, usbvcp->usbvc_log_handle,
	    "usbvc_cpr_suspend enter");

	mutex_enter(&usbvcp->usbvc_mutex);

	/*
	 * Set dev_state to suspended so other driver threads don't start any
	 * new I/O.
	 */
	usbvcp->usbvc_dev_state = USB_DEV_SUSPENDED;

	mutex_exit(&usbvcp->usbvc_mutex);

	USB_DPRINTF_L4(PRINT_MASK_OPEN, usbvcp->usbvc_log_handle,
	    "usbvc_cpr_suspend: return");
}


/*
 * If the polling has been stopped due to some exceptional errors,
 * we reconfigure the device and start polling again. Only for S/R
 * resume or hotplug reconnect operations.
 */
static int
usbvc_resume_operation(usbvc_state_t *usbvcp)
{
	usbvc_stream_if_t	*strm_if;
	int rv = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
	    "usbvc_resume_operation: enter");

	mutex_enter(&usbvcp->usbvc_mutex);
	strm_if = usbvcp->usbvc_curr_strm;
	if (!strm_if) {
		mutex_exit(&usbvcp->usbvc_mutex);
		rv = USB_FAILURE;

		return (rv);
	}

	/*
	 * 1) if application has not started STREAMON ioctl yet,
	 *    just return
	 * 2) if application use READ mode, return immediately
	 */
	if (strm_if->stream_on == 0) {
		mutex_exit(&usbvcp->usbvc_mutex);

		return (rv);
	}

	/* isoc pipe is expected to be opened already if (stream_on==1) */
	if (!strm_if->datain_ph) {
		mutex_exit(&usbvcp->usbvc_mutex);
		rv = USB_FAILURE;

		return (rv);
	}

	mutex_exit(&usbvcp->usbvc_mutex);

	/* first commit the parameters negotiated and saved during S_FMT */
	if ((rv = usbvc_vs_set_probe_commit(usbvcp, strm_if,
	    &strm_if->ctrl_pc, VS_COMMIT_CONTROL)) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_IOCTL,
		    usbvcp->usbvc_log_handle,
		    "usbvc_resume_operation: set probe failed, rv=%d", rv);

		return (rv);
	}

	mutex_enter(&usbvcp->usbvc_mutex);

	/* Set alt interfaces, must be after probe_commit according to spec */
	if ((rv = usbvc_set_alt(usbvcp, strm_if)) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_IOCTL,
		    usbvcp->usbvc_log_handle,
		    "usbvc_resume_operation: set alt failed");
		mutex_exit(&usbvcp->usbvc_mutex);

		return (rv);
	}

	/*
	 * The isoc polling could be stopped by isoc_exc_cb
	 * during suspend or hotplug. Restart it.
	 */
	if (usbvc_start_isoc_polling(usbvcp, strm_if, V4L2_MEMORY_MMAP)
	    != USB_SUCCESS) {
		rv = USB_FAILURE;
		mutex_exit(&usbvcp->usbvc_mutex);

		return (rv);
	}

	strm_if->start_polling = 1;

	mutex_exit(&usbvcp->usbvc_mutex);

	return (rv);
}

/*
 * usbvc_cpr_resume:
 *
 *	usbvc_restore_device_state marks success by putting device back online
 */
static void
usbvc_cpr_resume(dev_info_t *dip)
{
	int		instance = ddi_get_instance(dip);
	usbvc_state_t	*usbvcp = ddi_get_soft_state(usbvc_statep, instance);

	USB_DPRINTF_L4(PRINT_MASK_OPEN, usbvcp->usbvc_log_handle,
	    "resume: enter");

	/*
	 * NOTE: A pm_raise_power in usbvc_restore_device_state will bring
	 * the power-up state of device into synch with the system.
	 */
	mutex_enter(&usbvcp->usbvc_mutex);
	usbvc_restore_device_state(dip, usbvcp);
	mutex_exit(&usbvcp->usbvc_mutex);
}


/*
 *  usbvc_restore_device_state:
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
usbvc_restore_device_state(dev_info_t *dip, usbvc_state_t *usbvcp)
{
	USB_DPRINTF_L4(PRINT_MASK_PM, usbvcp->usbvc_log_handle,
	    "usbvc_restore_device_state: enter");

	ASSERT(mutex_owned(&usbvcp->usbvc_mutex));

	ASSERT((usbvcp->usbvc_dev_state == USB_DEV_DISCONNECTED) ||
	    (usbvcp->usbvc_dev_state == USB_DEV_SUSPENDED));

	usbvc_pm_busy_component(usbvcp);
	usbvcp->usbvc_pm->usbvc_raise_power = B_TRUE;
	mutex_exit(&usbvcp->usbvc_mutex);
	(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

	/* Check if we are talking to the same device */
	if (usb_check_same_device(dip, usbvcp->usbvc_log_handle,
	    USB_LOG_L0, PRINT_MASK_ALL,
	    USB_CHK_BASIC|USB_CHK_CFG, NULL) != USB_SUCCESS) {

		goto fail;
	}

	mutex_enter(&usbvcp->usbvc_mutex);
	usbvcp->usbvc_pm->usbvc_raise_power = B_FALSE;
	usbvcp->usbvc_dev_state = USB_DEV_ONLINE;
	mutex_exit(&usbvcp->usbvc_mutex);

	if (usbvcp->usbvc_pm->usbvc_wakeup_enabled) {

		/* Failure here means device disappeared again. */
		if (usb_handle_remote_wakeup(dip, USB_REMOTE_WAKEUP_ENABLE) !=
		    USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    usbvcp->usbvc_log_handle,
			    "device may or may not be accessible. "
			    "Please verify reconnection");
		}
	}

	if (usbvc_resume_operation(usbvcp) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_PM, usbvcp->usbvc_log_handle,
		    "usbvc_restore_device_state: can't resume operation");

		goto fail;
	}

	mutex_enter(&usbvcp->usbvc_mutex);

	usbvc_pm_idle_component(usbvcp);

	USB_DPRINTF_L4(PRINT_MASK_PM, usbvcp->usbvc_log_handle,
	    "usbvc_restore_device_state: end");

	return;

fail:
	/* change the device state from suspended to disconnected */
	mutex_enter(&usbvcp->usbvc_mutex);
	usbvcp->usbvc_dev_state = USB_DEV_DISCONNECTED;
	usbvc_pm_idle_component(usbvcp);
}


/* Events */

/*
 * usbvc_disconnect_event_cb:
 *	Called when device hotplug-removed.
 *		Close pipes. (This does not attempt to contact device.)
 *		Set state to DISCONNECTED
 */
static int
usbvc_disconnect_event_cb(dev_info_t *dip)
{
	int		instance = ddi_get_instance(dip);
	usbvc_state_t	*usbvcp = ddi_get_soft_state(usbvc_statep, instance);

	USB_DPRINTF_L4(PRINT_MASK_HOTPLUG, usbvcp->usbvc_log_handle,
	    "disconnect: enter");

	mutex_enter(&usbvcp->usbvc_mutex);
	/*
	 * Save any state of device or IO in progress required by
	 * usbvc_restore_device_state for proper device "thawing" later.
	 */
	usbvcp->usbvc_dev_state = USB_DEV_DISCONNECTED;

	/*
	 * wake up the read threads in case there are any threads are blocking,
	 * after being waked up, those threads will quit fail immediately since
	 * we have changed the dev_stat.
	 */
	if (usbvcp->usbvc_io_type == V4L2_MEMORY_MMAP) {
		cv_broadcast(&usbvcp->usbvc_mapio_cv);
	} else {
		cv_broadcast(&usbvcp->usbvc_read_cv);
	}
	/* Wait for the other threads to quit */
	(void) usbvc_serialize_access(usbvcp, USBVC_SER_SIG);
	usbvc_release_access(usbvcp);
	mutex_exit(&usbvcp->usbvc_mutex);

	return (USB_SUCCESS);
}


/*
 * usbvc_reconnect_event_cb:
 *	Called with device hotplug-inserted
 *		Restore state
 */
static int
usbvc_reconnect_event_cb(dev_info_t *dip)
{
	int		instance = ddi_get_instance(dip);
	usbvc_state_t	*usbvcp = ddi_get_soft_state(usbvc_statep, instance);

	USB_DPRINTF_L4(PRINT_MASK_HOTPLUG, usbvcp->usbvc_log_handle,
	    "reconnect: enter");

	mutex_enter(&usbvcp->usbvc_mutex);
	(void) usbvc_serialize_access(usbvcp, USBVC_SER_SIG);
	usbvc_restore_device_state(dip, usbvcp);
	usbvc_release_access(usbvcp);
	mutex_exit(&usbvcp->usbvc_mutex);

	return (USB_SUCCESS);
}

/* Sync objs and lists */

/*
 * init/fini sync objects during attach
 */
static void
usbvc_init_sync_objs(usbvc_state_t *usbvcp)
{
	mutex_init(&usbvcp->usbvc_mutex, NULL, MUTEX_DRIVER,
	    usbvcp->usbvc_reg->dev_iblock_cookie);

	cv_init(&usbvcp->usbvc_serial_cv, NULL, CV_DRIVER, NULL);
	cv_init(&usbvcp->usbvc_read_cv, NULL, CV_DRIVER, NULL);
	cv_init(&usbvcp->usbvc_mapio_cv, NULL, CV_DRIVER, NULL);

	usbvcp->usbvc_serial_inuse = B_FALSE;

	usbvcp->usbvc_locks_initialized = B_TRUE;
}


static void
usbvc_fini_sync_objs(usbvc_state_t *usbvcp)
{
	cv_destroy(&usbvcp->usbvc_serial_cv);
	cv_destroy(&usbvcp->usbvc_read_cv);
	cv_destroy(&usbvcp->usbvc_mapio_cv);

	mutex_destroy(&usbvcp->usbvc_mutex);
}


static void
usbvc_init_lists(usbvc_state_t *usbvcp)
{
	/* video terminals */
	list_create(&(usbvcp->usbvc_term_list), sizeof (usbvc_terms_t),
	    offsetof(usbvc_terms_t, term_node));

	/* video units */
	list_create(&(usbvcp->usbvc_unit_list), sizeof (usbvc_units_t),
	    offsetof(usbvc_units_t, unit_node));

	/* stream interfaces */
	list_create(&(usbvcp->usbvc_stream_list), sizeof (usbvc_stream_if_t),
	    offsetof(usbvc_stream_if_t, stream_if_node));
}


/*
 * Free all the data structures allocated when parsing descriptors of ctrl
 * and stream interfaces. It is safe to call this function because it always
 * checks the pointer before free mem.
 */
static void
usbvc_fini_lists(usbvc_state_t *usbvcp)
{
	USB_DPRINTF_L4(PRINT_MASK_CLOSE, usbvcp->usbvc_log_handle,
	    "usbvc_fini_lists: enter");

	usbvc_free_ctrl_descr(usbvcp);

	/* Free all video stream structure and the sub-structures */
	usbvc_free_stream_descr(usbvcp);

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, usbvcp->usbvc_log_handle,
	    "usbvc_fini_lists: end");
}


/*
 * Free all the data structures allocated when parsing descriptors of ctrl
 * interface.
 */
static void
usbvc_free_ctrl_descr(usbvc_state_t *usbvcp)
{
	usbvc_terms_t	*term;
	usbvc_units_t	*unit;

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, usbvcp->usbvc_log_handle,
	    "usbvc_free_ctrl_descr: enter");

	if (usbvcp->usbvc_vc_header) {
		kmem_free(usbvcp->usbvc_vc_header, sizeof (usbvc_vc_header_t));
	}

	/* Free all video terminal structure */
	while (!list_is_empty(&usbvcp->usbvc_term_list)) {
			term = list_head(&usbvcp->usbvc_term_list);
			if (term != NULL) {
				list_remove(&(usbvcp->usbvc_term_list), term);
				kmem_free(term, sizeof (usbvc_terms_t));
			}
	}

	/* Free all video unit structure */
	while (!list_is_empty(&usbvcp->usbvc_unit_list)) {
			unit = list_head(&usbvcp->usbvc_unit_list);
			if (unit != NULL) {
				list_remove(&(usbvcp->usbvc_unit_list), unit);
				kmem_free(unit, sizeof (usbvc_units_t));
			}
	}
}


/*
 * Free all the data structures allocated when parsing descriptors of stream
 * interfaces.
 */
static void
usbvc_free_stream_descr(usbvc_state_t *usbvcp)
{
	usbvc_stream_if_t	*strm;
	usbvc_input_header_t	*in_hdr;
	usbvc_output_header_t	*out_hdr;
	uint8_t			fmt_cnt, frm_cnt;

	while (!list_is_empty(&usbvcp->usbvc_stream_list)) {
		USB_DPRINTF_L3(PRINT_MASK_CLOSE, usbvcp->usbvc_log_handle,
		    "usbvc_fini_lists: stream list not empty.");

		strm = list_head(&usbvcp->usbvc_stream_list);
		if (strm != NULL) {

			/* unlink this stream's data structure from the list */
			list_remove(&(usbvcp->usbvc_stream_list), strm);
		} else {

			/* No real stream data structure in the list */
			return;
		}

		in_hdr = strm->input_header;
		out_hdr = strm->output_header;

		if (in_hdr) {
			fmt_cnt = in_hdr->descr->bNumFormats;
		} else if (out_hdr) {
			fmt_cnt = out_hdr->descr->bNumFormats;
		}

		USB_DPRINTF_L3(PRINT_MASK_CLOSE,
		    usbvcp->usbvc_log_handle, "usbvc_fini_lists:"
		    " fmtgrp cnt=%d", fmt_cnt);

		/* Free headers */
		if (in_hdr) {
			kmem_free(in_hdr, sizeof (usbvc_input_header_t));
		}
		if (out_hdr) {
			kmem_free(out_hdr, sizeof (usbvc_output_header_t));
		}

		/* Free format descriptors */
		if (strm->format_group) {
			int i;
			usbvc_format_group_t *fmtgrp;

			for (i = 0; i < fmt_cnt; i++) {
				fmtgrp = &strm->format_group[i];
				if (fmtgrp->format == NULL) {

					break;
				}
				if (fmtgrp->still) {
					kmem_free(fmtgrp->still,
					    sizeof (usbvc_still_image_frame_t));
				}
				frm_cnt = fmtgrp->format->bNumFrameDescriptors;

				USB_DPRINTF_L3(PRINT_MASK_CLOSE,
				    usbvcp->usbvc_log_handle,
				    "usbvc_fini_lists:"
				    " frame cnt=%d", frm_cnt);

				if (fmtgrp->frames) {
					kmem_free(fmtgrp->frames,
					    sizeof (usbvc_frames_t) * frm_cnt);
				}
			}
			kmem_free(strm->format_group,
			    sizeof (usbvc_format_group_t) * fmt_cnt);
		}
		USB_DPRINTF_L3(PRINT_MASK_CLOSE,
		    usbvcp->usbvc_log_handle, "usbvc_fini_lists:"
		    " free stream_if_t");

		kmem_free(strm, sizeof (usbvc_stream_if_t));
	}
}

/*
 * Parse class specific descriptors of the video device
 */

/*
 * Check the length of a class specific descriptor. Make sure cvs_buf_len is
 * not less than the length expected according to uvc spec.
 *
 * Args:
 * - off_num: the cvs_buf offset of the descriptor element that
 *   indicates the number of variable descriptor elements;
 * - size: the size of each variable descriptor element, if zero, then the
 *   size value is offered by off_size;
 * - off_size: the cvs_buf offset of the descriptor element that indicates
 *   the size of each variable descriptor element;
 */
static int
usbvc_chk_descr_len(uint8_t off_num, uint8_t size, uint8_t off_size,
    usb_cvs_data_t *cvs_data)
{
	uchar_t			*cvs_buf;
	uint_t			cvs_buf_len;

	cvs_buf = cvs_data->cvs_buf;
	cvs_buf_len = cvs_data->cvs_buf_len;

	if (size == 0) {
		if (cvs_buf_len > off_size) {
			size = cvs_buf[off_size];
		} else {

			return (USB_FAILURE);
		}
	}
	if (cvs_buf_len < (off_num + 1)) {

		return (USB_FAILURE);
	}

	if (cvs_buf_len < (cvs_buf[off_num] * size + off_num +1)) {

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/* Parse the descriptors of control interface */
static int
usbvc_parse_ctrl_if(usbvc_state_t *usbvcp)
{
	int			if_num;
	int			cvs_num;
	usb_alt_if_data_t	*if_alt_data;
	usb_cvs_data_t		*cvs_data;
	uchar_t			*cvs_buf;
	uint_t			cvs_buf_len;
	uint16_t		version;

	if_num = usbvcp->usbvc_reg->dev_curr_if;
	if_alt_data = usbvcp->usbvc_reg->dev_curr_cfg->cfg_if[if_num].if_alt;
	cvs_data = if_alt_data->altif_cvs;

	for (cvs_num = 0; cvs_num < if_alt_data->altif_n_cvs; cvs_num++) {
		cvs_buf = cvs_data[cvs_num].cvs_buf;
		cvs_buf_len = cvs_data[cvs_num].cvs_buf_len;
		USB_DPRINTF_L3(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
		    "usbvc_parse_ctrl_if: cvs_num= %d, cvs_buf_len=%d",
		    cvs_num, cvs_buf_len);

		/*
		 * parse interface cvs descriptors here; by checking
		 * bDescriptorType (cvs_buf[1])
		 */
		if (cvs_buf[1] != CS_INTERFACE) {

			continue;
		}

		/*
		 * Different descriptors in VC interface; according to
		 * bDescriptorSubType (cvs_buf[2])
		 */
		switch (cvs_buf[2]) {
		case VC_HEADER:

			/*
			 * According to uvc spec, there must be one and only
			 * be one header. If more than one, return failure.
			 */
			if (usbvcp->usbvc_vc_header) {

				return (USB_FAILURE);
			}
			/*
			 * Check if it is a valid HEADER descriptor in case of
			 * a device not compliant to uvc spec. This descriptor
			 * is critical, return failure if not a valid one.
			 */
			if (usbvc_chk_descr_len(11, 1, 0, cvs_data) !=
			    USB_SUCCESS) {

				return (USB_FAILURE);
			}
			usbvcp->usbvc_vc_header =
			    (usbvc_vc_header_t *)kmem_zalloc(
			    sizeof (usbvc_vc_header_t), KM_SLEEP);
			usbvcp->usbvc_vc_header->descr =
			    (usbvc_vc_header_descr_t *)&cvs_buf[0];

			LE_TO_UINT16(usbvcp->usbvc_vc_header->descr->bcdUVC,
			    0, version);
			USB_DPRINTF_L3(PRINT_MASK_ATTA,
			    usbvcp->usbvc_log_handle, "usbvc_parse_ctrl_if:"
			    " VC header, bcdUVC=%x", version);
			if (usbvcp->usbvc_vc_header->descr->bInCollection ==
			    0) {
				USB_DPRINTF_L3(PRINT_MASK_ATTA,
				    usbvcp->usbvc_log_handle,
				    "usbvc_parse_ctrl_if: no strm interfaces");

				break;
			}

			/* stream interface numbers */
			usbvcp->usbvc_vc_header->baInterfaceNr = &cvs_buf[12];

			break;
		case VC_INPUT_TERMINAL:
		{
			usbvc_terms_t *term;

			/*
			 * Check if it is a valid descriptor in case of a
			 * device not compliant to uvc spec
			 */
			if (cvs_buf_len < USBVC_I_TERM_LEN_MIN) {

				break;
			}
			term = (usbvc_terms_t *)
			    kmem_zalloc(sizeof (usbvc_terms_t), KM_SLEEP);
			term->descr = (usbvc_term_descr_t *)cvs_buf;

			USB_DPRINTF_L3(PRINT_MASK_ATTA,
			    usbvcp->usbvc_log_handle, "usbvc_parse_ctrl_if: "
			    "input term type=%x", term->descr->wTerminalType);
			if (term->descr->wTerminalType == ITT_CAMERA) {
				if (usbvc_chk_descr_len(14, 1, 0, cvs_data) !=
				    USB_SUCCESS) {
					kmem_free(term, sizeof (usbvc_terms_t));

					break;
				}
				term->bmControls = &cvs_buf[15];
			} else if (cvs_buf_len > 8) { /* other input terms */
				term->bSpecific = &cvs_buf[8];
			}
			list_insert_tail(&(usbvcp->usbvc_term_list), term);

			break;
		}
		case VC_OUTPUT_TERMINAL:
		{
			usbvc_terms_t *term;

			if (cvs_buf_len < USBVC_O_TERM_LEN_MIN) {

				break;
			}
			term = (usbvc_terms_t *)
			    kmem_zalloc(sizeof (usbvc_terms_t), KM_SLEEP);
			term->descr = (usbvc_term_descr_t *)cvs_buf;

			USB_DPRINTF_L3(PRINT_MASK_ATTA,
			    usbvcp->usbvc_log_handle, "usbvc_parse_ctrl_if:"
			    " output term id= %x", term->descr->bTerminalID);
			if (cvs_buf_len > 9) {
				term->bSpecific = &cvs_buf[9];
			}
			list_insert_tail(&(usbvcp->usbvc_term_list), term);

			break;
		}
		case VC_PROCESSING_UNIT:
		{
			uint8_t sz;
			usbvc_units_t *unit;

			if (usbvc_chk_descr_len(7, 1, 0, cvs_data) !=
			    USB_SUCCESS) {

				break;
			}

			/* bControlSize */
			sz = cvs_buf[7];

			if ((sz + 8) >= cvs_buf_len) {

				break;
			}
			unit = (usbvc_units_t *)
			    kmem_zalloc(sizeof (usbvc_units_t), KM_SLEEP);

			unit->descr = (usbvc_unit_descr_t *)cvs_buf;

			USB_DPRINTF_L3(PRINT_MASK_ATTA,
			    usbvcp->usbvc_log_handle, "usbvc_parse_ctrl_if: "
			    "unit type=%x", unit->descr->bDescriptorSubType);

			if (sz != 0) {
				unit->bmControls = &cvs_buf[8];
			}
			unit->iProcessing = cvs_buf[8 + sz];

			/*
			 * video class 1.1 version add one element
			 * (bmVideoStandards) to processing unit descriptor
			 */
			if (cvs_buf_len > (9 + sz)) {
				unit->bmVideoStandards = cvs_buf[9 + sz];
			}
			list_insert_tail(&(usbvcp->usbvc_unit_list), unit);

			break;
		}
		case VC_SELECTOR_UNIT:
		{
			uint8_t  pins;
			usbvc_units_t *unit;

			if (usbvc_chk_descr_len(4, 1, 0, cvs_data) !=
			    USB_SUCCESS) {

				break;
			}
			pins = cvs_buf[4];
			if ((pins + 5) >= cvs_buf_len) {

				break;
			}
			unit = (usbvc_units_t *)
			    kmem_zalloc(sizeof (usbvc_units_t), KM_SLEEP);

			unit->descr = (usbvc_unit_descr_t *)cvs_buf;

			USB_DPRINTF_L3(PRINT_MASK_ATTA,
			    usbvcp->usbvc_log_handle, "usbvc_parse_ctrl_if: "
			    "unit type=%x", unit->descr->bDescriptorSubType);
			if (pins > 0) {
				unit->baSourceID = &cvs_buf[5];
			}
			unit->iSelector = cvs_buf[5 + pins];

			list_insert_tail(&(usbvcp->usbvc_unit_list), unit);

			break;
		}
		case VC_EXTENSION_UNIT:
		{
			uint8_t  pins, n;
			usbvc_units_t *unit;

			if (usbvc_chk_descr_len(21, 1, 0, cvs_data) !=
			    USB_SUCCESS) {

				break;
			}
			pins = cvs_buf[21];
			if ((pins + 22) >= cvs_buf_len) {

				break;
			}

			/* Size of bmControls */
			n = cvs_buf[pins + 22];

			if (usbvc_chk_descr_len(pins + 22, 1, 0, cvs_data) !=
			    USB_SUCCESS) {

				break;
			}
			if ((23 + pins + n) >= cvs_buf_len) {

				break;
			}
			unit = (usbvc_units_t *)
			    kmem_zalloc(sizeof (usbvc_units_t), KM_SLEEP);

			unit->descr = (usbvc_unit_descr_t *)cvs_buf;

			USB_DPRINTF_L3(PRINT_MASK_ATTA,
			    usbvcp->usbvc_log_handle, "usbvc_parse_ctrl_if: "
			    "unit type=%x", unit->descr->bDescriptorSubType);
			if (pins != 0) {
				unit->baSourceID = &cvs_buf[22];
			}
			unit->bControlSize = cvs_buf[22 + pins];

			if (unit->bControlSize != 0) {
				unit->bmControls = &cvs_buf[23 + pins];
			}
			unit->iExtension = cvs_buf[23 + pins + n];

			list_insert_tail(&(usbvcp->usbvc_unit_list), unit);

			break;
		}
		default:

			break;
		}
	}

	/*
	 * For webcam which is not compliant to video class specification
	 * and no header descriptor in VC interface, return USB_FAILURE.
	 */
	if (!usbvcp->usbvc_vc_header) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
		    "usbvc_parse_ctrl_if: no header descriptor");

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/* Parse all the cvs descriptors in one stream interface. */
usbvc_stream_if_t *
usbvc_parse_stream_if(usbvc_state_t *usbvcp, int if_num)
{
	usb_alt_if_data_t	*if_alt_data;
	uint_t			i, j;
	usbvc_stream_if_t	*strm_if;
	uint16_t		pktsize;
	uint8_t			ep_adr;

	strm_if = (usbvc_stream_if_t *)kmem_zalloc(sizeof (usbvc_stream_if_t),
	    KM_SLEEP);
	strm_if->if_descr = &usbvcp->usbvc_reg->dev_curr_cfg->cfg_if[if_num];
	if_alt_data = strm_if->if_descr->if_alt;
	if (usbvc_parse_stream_header(usbvcp, strm_if) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
		    "usbvc_parse_stream_if: parse header fail");
		kmem_free(strm_if, sizeof (usbvc_stream_if_t));

		return (NULL);
	}
	if (usbvc_parse_format_groups(usbvcp, strm_if) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
		    "usbvc_parse_stream_if: parse groups fail");
		kmem_free(strm_if, sizeof (usbvc_stream_if_t));

		return (NULL);
	}

	/* Parse the alternate settings to find the maximum bandwidth. */
	for (i = 0; i < strm_if->if_descr->if_n_alt; i++) {
		if_alt_data = &strm_if->if_descr->if_alt[i];
		for (j = 0; j < if_alt_data->altif_n_ep; j++) {
			ep_adr =
			    if_alt_data->altif_ep[j].ep_descr.bEndpointAddress;
			if (strm_if->input_header != NULL &&
			    ep_adr !=
			    strm_if->input_header->descr->bEndpointAddress) {

				continue;
			}
			if (strm_if->output_header != NULL &&
			    ep_adr !=
			    strm_if->output_header->descr->bEndpointAddress) {

				continue;
			}
			pktsize =
			    if_alt_data->altif_ep[j].ep_descr.wMaxPacketSize;
			pktsize = HS_PKT_SIZE(pktsize);
			if (pktsize > strm_if->max_isoc_payload) {
				strm_if->max_isoc_payload = pktsize;
			}
		}
	}

	/* initialize MJPEC FID toggle */
	strm_if->fid = 0xff;

	/*
	 * initialize desired number of buffers used internally in read() mode
	 */
	strm_if->buf_read_num = USBVC_DEFAULT_READ_BUF_NUM;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
	    "usbvc_parse_stream_if: return. max_isoc_payload=%x",
	    strm_if->max_isoc_payload);

	return (strm_if);
}


/*
 * Parse all the stream interfaces asociated with the video control interface.
 * This driver will attach to a video control interface on the device,
 * there might be multiple video stream interfaces associated with one video
 * control interface.
 */
static int
usbvc_parse_stream_ifs(usbvc_state_t *usbvcp)
{
	int			i, if_cnt, if_num;
	usbvc_stream_if_t	*strm_if;

	if_cnt = usbvcp->usbvc_vc_header->descr->bInCollection;
	if (if_cnt == 0) {
		ASSERT(list_is_empty(&usbvcp->usbvc_stream_list));
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
		    "usbvc_parse_stream_ifs: no stream interfaces");

		return (USB_SUCCESS);
	}
	for (i = 0; i < if_cnt; i++) {
		if_num = usbvcp->usbvc_vc_header->baInterfaceNr[i];
		strm_if = usbvc_parse_stream_if(usbvcp, if_num);
		if (strm_if == NULL) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    usbvcp->usbvc_log_handle, "usbvc_parse_stream_ifs:"
			    " parse stream interface %d failed.", if_num);

			return (USB_FAILURE);
		}
		/* video data buffers */
		list_create(&(strm_if->buf_map.uv_buf_free),
		    sizeof (usbvc_buf_t), offsetof(usbvc_buf_t, buf_node));
		list_create(&(strm_if->buf_map.uv_buf_done),
		    sizeof (usbvc_buf_t), offsetof(usbvc_buf_t, buf_node));
		list_create(&(strm_if->buf_read.uv_buf_free),
		    sizeof (usbvc_buf_t), offsetof(usbvc_buf_t, buf_node));
		list_create(&(strm_if->buf_read.uv_buf_done),
		    sizeof (usbvc_buf_t), offsetof(usbvc_buf_t, buf_node));

		list_insert_tail(&(usbvcp->usbvc_stream_list), strm_if);
	}

	/* Make the first stream interface as the default one. */
	usbvcp->usbvc_curr_strm =
	    (usbvc_stream_if_t *)list_head(&usbvcp->usbvc_stream_list);

	return (USB_SUCCESS);
}


/*
 * Parse colorspace descriptor and still image descriptor of a format group.
 * There is only one colorspace or still image descriptor in one format group.
 */
static void
usbvc_parse_color_still(usbvc_state_t *usbvcp, usbvc_format_group_t *fmtgrp,
    usb_cvs_data_t *cvs_data, uint_t cvs_num, uint_t altif_n_cvs)
{
	uint8_t		frame_cnt;
	uint_t		last_frame, i;
	uchar_t		*cvs_buf;
	uint_t			cvs_buf_len;

	frame_cnt = fmtgrp->format->bNumFrameDescriptors;
	last_frame = frame_cnt + cvs_num;

	/*
	 * Find the still image descr and color format descr if there are any.
	 * UVC Spec: only one still image and one color descr is allowed in
	 * one format group.
	 */
	for (i = 1; i <= 2; i++) {
		if ((last_frame + i) >= altif_n_cvs) {

			break;
		}
		cvs_buf = cvs_data[last_frame + i].cvs_buf;
		cvs_buf_len = cvs_data[last_frame + i].cvs_buf_len;

		if (cvs_buf[2] == VS_STILL_IMAGE_FRAME) {
			uint8_t m, n, off;
			usbvc_still_image_frame_t *st;

			if (usbvc_chk_descr_len(4, 4, 0, cvs_data) !=
			    USB_SUCCESS) {

				continue;
			}

			/* Number of Image Size patterns of this format */
			n = cvs_buf[4];

			/* offset of bNumCompressionPattern */
			off = 9 + 4 * n -4;

			if (off >= cvs_buf_len) {

				continue;
			}

			/* Number of compression pattern of this format */
			m = cvs_buf[off];

			if (usbvc_chk_descr_len(m, 1, 0, cvs_data) !=
			    USB_SUCCESS) {

				continue;
			}
			fmtgrp->still = (usbvc_still_image_frame_t *)
			    kmem_zalloc(sizeof (usbvc_still_image_frame_t),
			    KM_SLEEP);
			st = fmtgrp->still;
			st->descr = (usbvc_still_image_frame_descr_t *)cvs_buf;
			n = st->descr->bNumImageSizePatterns;
			if (n > 0) {
				st->width_height =
				    (width_height_t *)&cvs_buf[5];
			}
			st->bNumCompressionPattern = cvs_buf[off];
			if (cvs_buf[off] > 0) {
				st->bCompression = &cvs_buf[off + 1];
			}
		}
		if (cvs_buf[2] == VS_COLORFORMAT) {
			fmtgrp->color = (usbvc_color_matching_descr_t *)cvs_buf;
			fmtgrp->v4l2_color = usbvc_v4l2_colorspace(
			    fmtgrp->color->bColorPrimaries);
		}
	}
	USB_DPRINTF_L4(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
	    "usbvc_parse_color_still: still=%p, color=%p",
	    (void *)fmtgrp->still, (void *)fmtgrp->color);
}


/*
 * Parse frame descriptors of a format group. There might be multi frame
 * descriptors in one format group.
 */
static void
usbvc_parse_frames(usbvc_state_t *usbvcp, usbvc_format_group_t *fmtgrp,
    usb_cvs_data_t *cvs_data, uint_t cvs_num, uint_t altif_n_cvs)
{
	uint_t		last_frame;
	usbvc_frames_t	*frm;
	usb_cvs_data_t		*cvs;
	uchar_t		*cvs_buf;
	uint_t			cvs_buf_len;
	uint8_t		i;
	uint8_t		frame_cnt = fmtgrp->format->bNumFrameDescriptors;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
	    "usbvc_parse_format_group: frame_cnt=%d", frame_cnt);

	if (frame_cnt == 0) {
		fmtgrp->frames = NULL;

		return;
	}

	/* All these mem allocated will be freed in cleanup() */
	fmtgrp->frames = (usbvc_frames_t *)
	    kmem_zalloc(sizeof (usbvc_frames_t) * frame_cnt, KM_SLEEP);

	last_frame = frame_cnt + cvs_num;
	cvs_num++;
	i = 0;

	/*
	 * Traverse from the format decr's first frame decr to the the last
	 * frame descr.
	 */
	for (; cvs_num <= last_frame; cvs_num++) {
		USB_DPRINTF_L3(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
		    "usbvc_parse_frames: cvs_num=%d, i=%d", cvs_num, i);
		if (cvs_num >= altif_n_cvs) {
			USB_DPRINTF_L3(PRINT_MASK_ATTA,
			    usbvcp->usbvc_log_handle,
			    "usbvc_parse_frames: less frames than "
			    "expected, cvs_num=%d, i=%d", cvs_num, i);

			break;
		}
		cvs = &cvs_data[cvs_num];
		cvs_buf = cvs->cvs_buf;
		cvs_buf_len = cvs->cvs_buf_len;
		if (cvs_buf_len < USBVC_FRAME_LEN_MIN) {
			i++;

			continue;
		}
		frm = &fmtgrp->frames[i];
		frm->descr = (usbvc_frame_descr_t *)cvs->cvs_buf;

		/* Descriptor for discrete frame interval */
		if (frm->descr->bFrameIntervalType > 0) {
			if (usbvc_chk_descr_len(25, 4, 0, cvs) != USB_SUCCESS) {
				frm->descr = NULL;
				i++;

				continue;
			}

			frm->dwFrameInterval = (uint8_t *)&cvs_buf[26];
		} else {	/* Continuous interval */
			if (cvs_buf_len < USBVC_FRAME_LEN_CON) {
				frm->descr = NULL;
				i++;

				continue;
			}

			/* Continuous frame intervals */
			LE_TO_UINT32(cvs_buf, 26, frm->dwMinFrameInterval);
			LE_TO_UINT32(cvs_buf, 30, frm->dwMaxFrameInterval);
			LE_TO_UINT32(cvs_buf, 34, frm->dwFrameIntervalStep);
		}

		i++;
	}
	fmtgrp->frame_cnt = i;
	USB_DPRINTF_L4(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
	    "usbvc_parse_frames: %d frames are actually parsed",
	    fmtgrp->frame_cnt);
}


/* Parse one of the format groups in a stream interface */
static int
usbvc_parse_format_group(usbvc_state_t *usbvcp, usbvc_format_group_t *fmtgrp,
    usb_cvs_data_t *cvs_data, uint_t cvs_num, uint_t altif_n_cvs)
{
	usbvc_format_descr_t *fmt;

	fmt = fmtgrp->format;
	USB_DPRINTF_L4(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
	    "usbvc_parse_format_group: frame_cnt=%d, cvs_num=%d",
	    fmt->bNumFrameDescriptors, cvs_num);

	switch (fmt->bDescriptorSubType) {
	case VS_FORMAT_UNCOMPRESSED:
		usbvc_parse_color_still(usbvcp, fmtgrp, cvs_data, cvs_num,
		    altif_n_cvs);
		usbvc_parse_frames(usbvcp, fmtgrp, cvs_data, cvs_num,
		    altif_n_cvs);
		fmtgrp->v4l2_bpp = fmt->fmt.uncompressed.bBitsPerPixel / 8;
		fmtgrp->v4l2_pixelformat = usbvc_v4l2_guid2fcc(
		    (uint8_t *)&fmt->fmt.uncompressed.guidFormat);

		break;
	case VS_FORMAT_MJPEG:
		usbvc_parse_color_still(usbvcp, fmtgrp, cvs_data, cvs_num,
		    altif_n_cvs);
		usbvc_parse_frames(usbvcp, fmtgrp, cvs_data, cvs_num,
		    altif_n_cvs);
		fmtgrp->v4l2_bpp = 0;
		fmtgrp->v4l2_pixelformat = V4L2_PIX_FMT_MJPEG;

		break;
	case VS_FORMAT_MPEG2TS:
	case VS_FORMAT_DV:
	case VS_FORMAT_FRAME_BASED:
	case VS_FORMAT_STREAM_BASED:
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
		    "usbvc_parse_format_group: format not supported yet.");

		return (USB_FAILURE);
	default:
		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
		    "usbvc_parse_format_group: unknown format.");

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/* Parse the descriptors belong to one format */
static int
usbvc_parse_format_groups(usbvc_state_t *usbvcp, usbvc_stream_if_t *strm_if)
{
	usb_alt_if_data_t	*if_alt_data;
	usb_cvs_data_t		*cvs_data;
	uint8_t			fmtgrp_num, fmtgrp_cnt;
	uchar_t			*cvs_buf;
	uint_t			cvs_num = 0;
	usbvc_format_group_t	*fmtgrp;

	fmtgrp_cnt = 0;
	/*
	 * bNumFormats indicates the number of formats in this stream
	 * interface. On some devices, we see this number is larger than
	 * the truth.
	 */
	if (strm_if->input_header) {
		fmtgrp_cnt = strm_if->input_header->descr->bNumFormats;
	} else if (strm_if->output_header) {
		fmtgrp_cnt = strm_if->output_header->descr->bNumFormats;
	}
	if (!fmtgrp_cnt) {

		return (USB_FAILURE);
	}
	USB_DPRINTF_L3(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
	    "usbvc_parse_format_groups: fmtgrp_cnt=%d", fmtgrp_cnt);

	fmtgrp = (usbvc_format_group_t *)
	    kmem_zalloc(sizeof (usbvc_format_group_t) * fmtgrp_cnt, KM_SLEEP);

	if_alt_data = strm_if->if_descr->if_alt;
	cvs_data = if_alt_data->altif_cvs;

	for (fmtgrp_num = 0; fmtgrp_num < fmtgrp_cnt &&
	    cvs_num < if_alt_data->altif_n_cvs; cvs_num++) {
		cvs_buf = cvs_data[cvs_num].cvs_buf;
		switch (cvs_buf[2]) {
		case VS_FORMAT_UNCOMPRESSED:
		case VS_FORMAT_MJPEG:
		case VS_FORMAT_MPEG2TS:
		case VS_FORMAT_DV:
		case VS_FORMAT_FRAME_BASED:
		case VS_FORMAT_STREAM_BASED:
			fmtgrp[fmtgrp_num].format =
			    (usbvc_format_descr_t *)cvs_buf;

			/*
			 * Now cvs_data[cvs_num].cvs_buf is format descriptor,
			 * usbvc_parse_format_group will then parse the frame
			 * descriptors following this format descriptor.
			 */
			(void) usbvc_parse_format_group(usbvcp,
			    &fmtgrp[fmtgrp_num], cvs_data, cvs_num,
			    if_alt_data->altif_n_cvs);

			fmtgrp_num++;

			break;
		default:
			break;
		}
	}

	/* Save the number of parsed format groups. */
	strm_if->fmtgrp_cnt = fmtgrp_num;
	USB_DPRINTF_L3(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
	    "usbvc_parse_format_groups: acctually %d formats parsed",
	    fmtgrp_num);

	/*
	 * If can't find any formats, then free all allocated
	 * usbvc_format_group_t, return failure.
	 */
	if (!(fmtgrp[0].format)) {
		kmem_free(fmtgrp, sizeof (usbvc_format_group_t) * fmtgrp_cnt);
		strm_if->format_group = NULL;

		USB_DPRINTF_L2(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
		    "usbvc_parse_format_groups: can't find any formats");

		return (USB_FAILURE);
	}
	strm_if->format_group = fmtgrp;
	USB_DPRINTF_L3(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
	    "usbvc_parse_format_groups: %d format groups parsed", fmtgrp_num);

	return (USB_SUCCESS);
}


/*
 * Parse the input/output header in one stream interface.
 * UVC Spec: there must be one and only one header in one stream interface.
 */
int
usbvc_parse_stream_header(usbvc_state_t *usbvcp, usbvc_stream_if_t *strm_if)
{
	usb_alt_if_data_t	*if_alt_data;
	usb_cvs_data_t		*cvs_data;
	int			cvs_num;
	uchar_t			*cvs_buf;
	usbvc_input_header_t	*in_hdr;
	usbvc_output_header_t	*out_hdr;

	if_alt_data = strm_if->if_descr->if_alt;
	cvs_data = if_alt_data->altif_cvs;
	for (cvs_num = 0; cvs_num < if_alt_data->altif_n_cvs; cvs_num++) {
		cvs_buf = cvs_data[cvs_num].cvs_buf;
		USB_DPRINTF_L3(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
		    "usbvc_parse_stream_header: cvs_num= %d", cvs_num);

		/*
		 * parse interface cvs descriptors here; by checking
		 * bDescriptorType (cvs_buf[1])
		 */
		if (cvs_buf[1] != CS_INTERFACE) {

			continue;
		}

		if (cvs_buf[2] == VS_INPUT_HEADER) {
			if (usbvc_chk_descr_len(3, 0, 12, cvs_data) !=
			    USB_SUCCESS) {

				continue;
			}

			strm_if->input_header =
			    (usbvc_input_header_t *)
			    kmem_zalloc(sizeof (usbvc_input_header_t),
			    KM_SLEEP);
			in_hdr = strm_if->input_header;
			in_hdr->descr = (usbvc_input_header_descr_t *)cvs_buf;
			if (in_hdr->descr->bNumFormats > 0) {
				in_hdr->bmaControls = &cvs_buf[13];
			}

			return (USB_SUCCESS);
		} else if (cvs_buf[2] == VS_OUTPUT_HEADER) {
			if (usbvc_chk_descr_len(3, 0, 8, cvs_data) !=
			    USB_SUCCESS) {

				continue;
			}
			strm_if->output_header =
			    (usbvc_output_header_t *)
			    kmem_zalloc(sizeof (usbvc_output_header_t),
			    KM_SLEEP);
			out_hdr = strm_if->output_header;
			out_hdr->descr =
			    (usbvc_output_header_descr_t *)cvs_buf;
			if (out_hdr->descr->bNumFormats > 0) {
				out_hdr->bmaControls = &cvs_buf[13];
			}

			return (USB_SUCCESS);
		} else {

			continue;
		}
	}
	/* Didn't find one header descriptor. */
	USB_DPRINTF_L2(PRINT_MASK_ATTA, usbvcp->usbvc_log_handle,
	    "usbvc_parse_stream_header: FAIL");

	return (USB_FAILURE);
}

/* read I/O functions */

/* Allocate bufs for read I/O method */
static int
usbvc_alloc_read_bufs(usbvc_state_t *usbvcp, usbvc_stream_if_t *strm_if)
{
	usbvc_buf_t	*buf;
	uchar_t		*data;
	int		i;
	uint32_t	len;

	ASSERT(mutex_owned(&usbvcp->usbvc_mutex));

	LE_TO_UINT32(strm_if->ctrl_pc.dwMaxVideoFrameSize, 0, len);
	if (!len) {

		return (USB_FAILURE);
	}
	for (i = 0; i < strm_if->buf_read_num; i++) {
		mutex_exit(&usbvcp->usbvc_mutex);
		buf = (usbvc_buf_t *)kmem_zalloc(sizeof (usbvc_buf_t),
		    KM_SLEEP);
		data = (uchar_t *)kmem_zalloc(len, KM_SLEEP);
		mutex_enter(&usbvcp->usbvc_mutex);
		buf->data = data;
		buf->len = len;
		list_insert_tail(&(strm_if->buf_read.uv_buf_free), buf);
	}
	strm_if->buf_read.buf_cnt = strm_if->buf_read_num;
	USB_DPRINTF_L4(PRINT_MASK_READ, usbvcp->usbvc_log_handle,
	    "read_bufs: %d bufs allocated", strm_if->buf_read.buf_cnt);

	return (USB_SUCCESS);
}


/* Read a done buf, copy data to bp. This function is for read I/O method */
static int
usbvc_read_buf(usbvc_state_t *usbvcp, struct buf *bp)
{
	usbvc_buf_t	*buf;
	int		buf_residue;
	int		len_to_copy;

	ASSERT(mutex_owned(&usbvcp->usbvc_mutex));

	if (list_is_empty(&usbvcp->usbvc_curr_strm->buf_read.uv_buf_done)) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, usbvcp->usbvc_log_handle,
		    "usbvc_read_buf: empty list(uv_buf_done)!");

		return (USB_FAILURE);
	}

	/* read a buf from full list and then put it to free list */
	buf = list_head(&usbvcp->usbvc_curr_strm->buf_read.uv_buf_done);

	USB_DPRINTF_L2(PRINT_MASK_OPEN, usbvcp->usbvc_log_handle,
	    "usbvc_read_buf: buf=%p, buf->filled=%d, buf->len=%d,"
	    " buf->len_read=%d bp->b_bcount=%ld, bp->b_resid=%lu",
	    (void *)buf, buf->filled, buf->len, buf->len_read,
	    bp->b_bcount, bp->b_resid);

	ASSERT(buf->len_read <= buf->filled);

	buf_residue = buf->filled - buf->len_read;
	len_to_copy = min(bp->b_bcount, buf_residue);

	bcopy(buf->data + buf->len_read, bp->b_un.b_addr, len_to_copy);
	bp->b_private = NULL;
	buf->len_read += len_to_copy;
	bp->b_resid = bp->b_bcount - len_to_copy;

	if (len_to_copy == buf_residue) {
		/*
		 * the bp can accommodate all the remaining bytes of
		 * the buf. Then we can reuse this buf.
		 */
		buf->len_read = 0;
		list_remove(&usbvcp->usbvc_curr_strm->buf_read.uv_buf_done,
		    buf);
		list_insert_tail(&usbvcp->usbvc_curr_strm->buf_read.uv_buf_free,
		    buf);
	}

	return (USB_SUCCESS);
}


/* Free one buf which is for read/write IO style */
static void
usbvc_free_read_buf(usbvc_buf_t *buf)
{
	if (buf != NULL) {
		if (buf->data) {
			kmem_free(buf->data, buf->len);
		}
		kmem_free(buf, sizeof (usbvc_buf_t));
	}
}


/* Free all bufs which are for read/write IO style */
static void
usbvc_free_read_bufs(usbvc_state_t *usbvcp, usbvc_stream_if_t *strm_if)
{
	usbvc_buf_t	*buf;

	ASSERT(mutex_owned(&usbvcp->usbvc_mutex));

	if (!strm_if) {

		return;
	}
	buf = strm_if->buf_read.buf_filling;
	usbvc_free_read_buf(buf);
	strm_if->buf_read.buf_filling = NULL;

	while (!list_is_empty(&strm_if->buf_read.uv_buf_free)) {
		buf = list_head(&strm_if->buf_read.uv_buf_free);
		if (buf != NULL) {
			list_remove(&(strm_if->buf_read.uv_buf_free), buf);
			usbvc_free_read_buf(buf);
		}
	}
	while (!list_is_empty(&strm_if->buf_read.uv_buf_done)) {
		buf = list_head(&strm_if->buf_read.uv_buf_done);
		if (buf != NULL) {
			list_remove(&(strm_if->buf_read.uv_buf_done), buf);
			usbvc_free_read_buf(buf);
		}
	}
	strm_if->buf_read.buf_cnt = 0;
	USB_DPRINTF_L4(PRINT_MASK_CLOSE, usbvcp->usbvc_log_handle,
	    "usbvc_free_read_bufs: return");
}


/*
 * Allocate bufs for mapped I/O , return the number of allocated bufs
 * if success, return 0 if fail.
 */
int
usbvc_alloc_map_bufs(usbvc_state_t *usbvcp, usbvc_stream_if_t *strm_if,
    int buf_cnt, int buf_len)
{
	int		i = 0;
	usbvc_buf_t	*bufs;

	ASSERT(mutex_owned(&usbvcp->usbvc_mutex));
	USB_DPRINTF_L4(PRINT_MASK_OPEN, usbvcp->usbvc_log_handle,
	    "usbvc_alloc_map_bufs: bufcnt=%d, buflen=%d", buf_cnt, buf_len);
	if (buf_len <= 0 || buf_cnt <= 0) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, usbvcp->usbvc_log_handle,
		    "usbvc_alloc_map_bufs: len<=0, cnt<=0");

		return (0);
	}
	mutex_exit(&usbvcp->usbvc_mutex);

	bufs = (usbvc_buf_t *) kmem_zalloc(sizeof (usbvc_buf_t) * buf_cnt,
	    KM_SLEEP);

	mutex_enter(&usbvcp->usbvc_mutex);
	strm_if->buf_map.buf_head = bufs;
	buf_len = ptob(btopr(buf_len));

	mutex_exit(&usbvcp->usbvc_mutex);
	bufs[0].data = ddi_umem_alloc(buf_len * buf_cnt, DDI_UMEM_SLEEP,
	    &bufs[0].umem_cookie);
	mutex_enter(&usbvcp->usbvc_mutex);

	for (i = 0; i < buf_cnt; i++) {
		bufs[i].len = buf_len;
		bufs[i].data = bufs[0].data + (buf_len * i);
		bufs[i].umem_cookie = bufs[0].umem_cookie;
		bufs[i].status = USBVC_BUF_INIT;

		bufs[i].v4l2_buf.index = i;
		bufs[i].v4l2_buf.m.offset = i * bufs[i].len;
		bufs[i].v4l2_buf.length = bufs[i].len;
		bufs[i].v4l2_buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		bufs[i].v4l2_buf.sequence = 0;
		bufs[i].v4l2_buf.field = V4L2_FIELD_NONE;
		bufs[i].v4l2_buf.memory = V4L2_MEMORY_MMAP;
		bufs[i].v4l2_buf.flags = V4L2_MEMORY_MMAP;

		list_insert_tail(&strm_if->buf_map.uv_buf_free, &bufs[i]);
		USB_DPRINTF_L4(PRINT_MASK_OPEN, usbvcp->usbvc_log_handle,
		    "usbvc_alloc_map_bufs: prepare %d buffers of %d bytes",
		    buf_cnt, bufs[i].len);
	}
	strm_if->buf_map.buf_cnt = buf_cnt;
	strm_if->buf_map.buf_filling = NULL;

	return (buf_cnt);
}


/* Free all bufs which are for memory map IO style */
void
usbvc_free_map_bufs(usbvc_state_t *usbvcp, usbvc_stream_if_t *strm_if)
{
	usbvc_buf_t	*buf;

	ASSERT(mutex_owned(&usbvcp->usbvc_mutex));
	if (!strm_if) {

		return;
	}
	strm_if->buf_map.buf_filling = NULL;
	while (!list_is_empty(&strm_if->buf_map.uv_buf_free)) {
		buf = (usbvc_buf_t *)list_head(&strm_if->buf_map.uv_buf_free);
		list_remove(&(strm_if->buf_map.uv_buf_free), buf);
	}
	while (!list_is_empty(&strm_if->buf_map.uv_buf_done)) {
		buf = (usbvc_buf_t *)list_head(&strm_if->buf_map.uv_buf_done);
		list_remove(&(strm_if->buf_map.uv_buf_done), buf);
	}
	buf = strm_if->buf_map.buf_head;
	if (!buf) {
		USB_DPRINTF_L2(PRINT_MASK_CLOSE, usbvcp->usbvc_log_handle,
		    "usbvc_free_map_bufs: no data buf need be freed, return");

		return;
	}
	if (buf->umem_cookie) {
		ddi_umem_free(buf->umem_cookie);
	}
	kmem_free(buf, sizeof (usbvc_buf_t) * strm_if->buf_map.buf_cnt);
	strm_if->buf_map.buf_cnt = 0;
	strm_if->buf_map.buf_head = NULL;

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, usbvcp->usbvc_log_handle,
	    "usbvc_free_map_bufs: return");
}


/*
 * Open the isoc pipe, this pipe is for video data transfer
 */
int
usbvc_open_isoc_pipe(usbvc_state_t *usbvcp, usbvc_stream_if_t *strm_if)
{
	usb_pipe_policy_t policy;
	int	rval = USB_SUCCESS;

	ASSERT(mutex_owned(&usbvcp->usbvc_mutex));

	if ((rval = usbvc_set_alt(usbvcp, strm_if)) != USB_SUCCESS) {

		return (rval);
	}
	bzero(&policy, sizeof (usb_pipe_policy_t));
	policy.pp_max_async_reqs = 2;
	mutex_exit(&usbvcp->usbvc_mutex);
	if ((rval = usb_pipe_open(usbvcp->usbvc_dip, strm_if->curr_ep, &policy,
	    USB_FLAGS_SLEEP, &strm_if->datain_ph)) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, usbvcp->usbvc_log_handle,
		    "usbvc_open_isoc_pipe: open pipe fail");
		mutex_enter(&usbvcp->usbvc_mutex);

		return (rval);
	}
	mutex_enter(&usbvcp->usbvc_mutex);
	strm_if->start_polling = 0;

	strm_if->stream_on = 0;

	USB_DPRINTF_L4(PRINT_MASK_OPEN, usbvcp->usbvc_log_handle,
	    "usbvc_open_isoc_pipe: success, datain_ph=%p",
	    (void *)strm_if->datain_ph);

	return (rval);
}


/*
 * Open the isoc pipe
 */
static void
usbvc_close_isoc_pipe(usbvc_state_t *usbvcp, usbvc_stream_if_t *strm_if)
{
	ASSERT(mutex_owned(&usbvcp->usbvc_mutex));
	if (!strm_if) {
		USB_DPRINTF_L2(PRINT_MASK_CLOSE, usbvcp->usbvc_log_handle,
		    "usbvc_close_isoc_pipe: stream interface is NULL");

		return;
	}
	if (strm_if->datain_ph) {
		mutex_exit(&usbvcp->usbvc_mutex);
		usb_pipe_close(usbvcp->usbvc_dip, strm_if->datain_ph,
		    USB_FLAGS_SLEEP, NULL, NULL);
		mutex_enter(&usbvcp->usbvc_mutex);
	}
	strm_if->datain_ph = NULL;
}


/*
 * Start to get video data from isoc pipe in the stream interface,
 * issue isoc req.
 */
int
usbvc_start_isoc_polling(usbvc_state_t *usbvcp, usbvc_stream_if_t *strm_if,
    uchar_t io_type)
{
	int		rval = USB_SUCCESS;
	uint_t		if_num;
	usb_isoc_req_t	*req;
	ushort_t	pkt_size;
	ushort_t	n_pkt, pkt;
	uint32_t	frame_size;

	ASSERT(mutex_owned(&usbvcp->usbvc_mutex));
	pkt_size = HS_PKT_SIZE(strm_if->curr_ep->wMaxPacketSize);
	if_num = strm_if->if_descr->if_alt->altif_descr.bInterfaceNumber;
	LE_TO_UINT32(strm_if->ctrl_pc.dwMaxVideoFrameSize, 0, frame_size);
	n_pkt = (frame_size + (pkt_size) - 1) / (pkt_size);

	USB_DPRINTF_L3(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
	    "usbvc_start_isoc_polling: if_num=%d, alt=%d, n_pkt=%d,"
	    " pkt_size=0x%x, MaxPacketSize=0x%x(Tsac#=%d), frame_size=0x%x",
	    if_num, strm_if->curr_alt, n_pkt, pkt_size,
	    strm_if->curr_ep->wMaxPacketSize,
	    (1 + ((strm_if->curr_ep->wMaxPacketSize>> 11) & 3)),
	    frame_size);

	if (n_pkt > USBVC_MAX_PKTS) {
		n_pkt = USBVC_MAX_PKTS;
	}
	USB_DPRINTF_L3(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
	    "usbvc_start_isoc_polling: n_pkt=%d", n_pkt);

	mutex_exit(&usbvcp->usbvc_mutex);
	if ((req = usb_alloc_isoc_req(usbvcp->usbvc_dip, n_pkt,
	    n_pkt * pkt_size, USB_FLAGS_SLEEP)) != NULL) {
		mutex_enter(&usbvcp->usbvc_mutex);

		/* Initialize the packet descriptor */
		for (pkt = 0; pkt < n_pkt; pkt++) {
			req->isoc_pkt_descr[pkt].isoc_pkt_length = pkt_size;
		}

		req->isoc_pkts_count = n_pkt;

		/*
		 * zero here indicates that HCDs will use
		 * isoc_pkt_descr->isoc_pkt_length to calculate
		 * isoc_pkts_length.
		 */
		req->isoc_pkts_length = 0;
		req->isoc_attributes = USB_ATTRS_ISOC_XFER_ASAP |
		    USB_ATTRS_SHORT_XFER_OK | USB_ATTRS_AUTOCLEARING;
		req->isoc_cb = usbvc_isoc_cb;
		req->isoc_exc_cb = usbvc_isoc_exc_cb;
		usbvcp->usbvc_io_type = io_type;
		req->isoc_client_private = (usb_opaque_t)usbvcp;
		mutex_exit(&usbvcp->usbvc_mutex);
		rval = usb_pipe_isoc_xfer(strm_if->datain_ph, req, 0);
		mutex_enter(&usbvcp->usbvc_mutex);
	} else {
		mutex_enter(&usbvcp->usbvc_mutex);
		USB_DPRINTF_L2(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
		    "usbvc_start_isoc_polling: alloc_isoc_req fail");

		return (USB_FAILURE);
	}

	if (rval != USB_SUCCESS) {
		if (req) {
			usb_free_isoc_req(req);
			req = NULL;
		}
	}
	USB_DPRINTF_L4(PRINT_MASK_IOCTL, usbvcp->usbvc_log_handle,
	    "usbvc_start_isoc_polling: return, rval=%d", rval);

	return (rval);
}

/* callbacks for receiving video data (isco in transfer) */

/*ARGSUSED*/
/* Isoc transfer callback, get video data */
static void
usbvc_isoc_cb(usb_pipe_handle_t ph, usb_isoc_req_t *isoc_req)
{
	usbvc_state_t	*usbvcp =
	    (usbvc_state_t *)isoc_req->isoc_client_private;
	int		i;
	mblk_t		*data = isoc_req->isoc_data;
	usbvc_buf_grp_t	*bufgrp;

	mutex_enter(&usbvcp->usbvc_mutex);

	USB_DPRINTF_L3(PRINT_MASK_CB, usbvcp->usbvc_log_handle,
	    "usbvc_isoc_cb: rq=0x%p, fno=%" PRId64 ", n_pkts=%u, flag=0x%x,"
	    " data=0x%p, cnt=%d",
	    (void *)isoc_req, isoc_req->isoc_frame_no,
	    isoc_req->isoc_pkts_count, isoc_req->isoc_attributes,
	    (void *)isoc_req->isoc_data, isoc_req->isoc_error_count);

	ASSERT((isoc_req->isoc_cb_flags & USB_CB_INTR_CONTEXT) != 0);
	for (i = 0; i < isoc_req->isoc_pkts_count; i++) {

		USB_DPRINTF_L3(PRINT_MASK_CB, usbvcp->usbvc_log_handle,
		    "\tpkt%d: "
		    "pktsize=%d status=%d resid=%d",
		    i,
		    isoc_req->isoc_pkt_descr[i].isoc_pkt_length,
		    isoc_req->isoc_pkt_descr[i].isoc_pkt_status,
		    isoc_req->isoc_pkt_descr[i].isoc_pkt_actual_length);

		if (isoc_req->isoc_pkt_descr[i].isoc_pkt_status !=
		    USB_CR_OK) {
			USB_DPRINTF_L3(PRINT_MASK_CB,
			    usbvcp->usbvc_log_handle,
			    "record: pkt=%d status=%s", i, usb_str_cr(
			    isoc_req->isoc_pkt_descr[i].isoc_pkt_status));
		}

		if (usbvcp->usbvc_io_type == V4L2_MEMORY_MMAP) {
			bufgrp = &usbvcp->usbvc_curr_strm->buf_map;
		} else {
			bufgrp = &usbvcp->usbvc_curr_strm->buf_read;
		}

		if (isoc_req->isoc_pkt_descr[i].isoc_pkt_actual_length) {
			if (usbvc_decode_stream_header(usbvcp, bufgrp, data,
			    isoc_req->isoc_pkt_descr[i].isoc_pkt_actual_length)
			    != USB_SUCCESS) {
				USB_DPRINTF_L3(PRINT_MASK_CB,
				    usbvcp->usbvc_log_handle, "decode error");
			}
			if (bufgrp->buf_filling &&
			    (bufgrp->buf_filling->status == USBVC_BUF_ERR ||
			    bufgrp->buf_filling->status == USBVC_BUF_DONE)) {

				/* Move the buf to the full list */
				list_insert_tail(&bufgrp->uv_buf_done,
				    bufgrp->buf_filling);

				bufgrp->buf_filling = NULL;

				if (usbvcp->usbvc_io_type == V4L2_MEMORY_MMAP) {
					cv_broadcast(&usbvcp->usbvc_mapio_cv);
				} else {
					cv_broadcast(&usbvcp->usbvc_read_cv);
				}
			}
		}

		data->b_rptr += isoc_req->isoc_pkt_descr[i].isoc_pkt_length;
	}
	mutex_exit(&usbvcp->usbvc_mutex);
	usb_free_isoc_req(isoc_req);
}


/*ARGSUSED*/
static void
usbvc_isoc_exc_cb(usb_pipe_handle_t ph, usb_isoc_req_t *isoc_req)
{
	usbvc_state_t	*usbvcp =
	    (usbvc_state_t *)isoc_req->isoc_client_private;
	usb_cr_t	completion_reason;
	int		rval;
	usbvc_stream_if_t	*strm_if;

	ASSERT(!list_is_empty(&usbvcp->usbvc_stream_list));

	mutex_enter(&usbvcp->usbvc_mutex);

	/* get the first stream interface */
	strm_if = usbvcp->usbvc_curr_strm;

	completion_reason = isoc_req->isoc_completion_reason;

	USB_DPRINTF_L3(PRINT_MASK_CB, usbvcp->usbvc_log_handle,
	    "usbvc_isoc_exc_cb: ph=0x%p, isoc_req=0x%p, cr=%d",
	    (void *)ph, (void *)isoc_req, completion_reason);

	ASSERT((isoc_req->isoc_cb_flags & USB_CB_INTR_CONTEXT) == 0);

	switch (completion_reason) {
	case USB_CR_STOPPED_POLLING:
	case USB_CR_PIPE_CLOSING:
	case USB_CR_PIPE_RESET:

		break;
	case USB_CR_NO_RESOURCES:
		/*
		 * keep the show going: Since we have the original
		 * request, we just resubmit it
		 */
		rval = usb_pipe_isoc_xfer(strm_if->datain_ph, isoc_req,
		    USB_FLAGS_NOSLEEP);
		USB_DPRINTF_L2(PRINT_MASK_CB, usbvcp->usbvc_log_handle,
		    "usbvc_isoc_exc_cb: restart capture rval=%d", rval);
		mutex_exit(&usbvcp->usbvc_mutex);

		return;
	default:
		mutex_exit(&usbvcp->usbvc_mutex);
		usb_pipe_stop_isoc_polling(ph, USB_FLAGS_NOSLEEP);
		USB_DPRINTF_L2(PRINT_MASK_CB, usbvcp->usbvc_log_handle,
		    "usbvc_isoc_exc_cb: stop polling");
		mutex_enter(&usbvcp->usbvc_mutex);
	}
	usb_free_isoc_req(isoc_req);
	strm_if->start_polling = 0;
	USB_DPRINTF_L3(PRINT_MASK_CB, usbvcp->usbvc_log_handle,
	    "usbvc_isoc_exc_cb: start_polling=%d cr=%d",
	    strm_if->start_polling, completion_reason);
	mutex_exit(&usbvcp->usbvc_mutex);
}

/*
 * Other utility functions
 */

/*
 * Find a proper alternate according to the bandwidth that the current video
 * format need;
 * Set alternate by calling usb_set_alt_if;
 * Called before open pipes in stream interface.
 */
static int
usbvc_set_alt(usbvc_state_t *usbvcp, usbvc_stream_if_t *strm_if)
{
	usb_alt_if_data_t	*alt;
	uint_t			i, j, if_num;
	uint16_t		pktsize, curr_pktsize;
	uint32_t		bandwidth;
	int			rval = USB_SUCCESS;
	usbvc_input_header_t	*ihd;
	usbvc_output_header_t	*ohd;

	ASSERT(mutex_owned(&usbvcp->usbvc_mutex));

	LE_TO_UINT32(strm_if->ctrl_pc.dwMaxPayloadTransferSize, 0, bandwidth);
	if (!bandwidth) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, usbvcp->usbvc_log_handle,
		    "usbvc_set_alt: bandwidth is not set yet");

		return (USB_FAILURE);
	}
	USB_DPRINTF_L3(PRINT_MASK_OPEN, usbvcp->usbvc_log_handle,
	    "usbvc_set_alt: bandwidth=%x", bandwidth);

	strm_if->curr_ep = NULL;
	curr_pktsize = 0xffff;
	ohd = strm_if->output_header;
	ihd = strm_if->input_header;
	/*
	 * Find one alternate setting whose isoc ep's max pktsize is just
	 * enough for the bandwidth.
	 */
	for (i = 0; i < strm_if->if_descr->if_n_alt; i++) {
		alt = &strm_if->if_descr->if_alt[i];

		for (j = 0; j < alt->altif_n_ep; j++) {

			/* if this stream interface is for input */
			if (ihd != NULL &&
			    alt->altif_ep[j].ep_descr.bEndpointAddress !=
			    ihd->descr->bEndpointAddress) {

				continue;
			}
			/*  if this stream interface is for output */
			if (ohd != NULL &&
			    alt->altif_ep[j].ep_descr.bEndpointAddress !=
			    ohd->descr->bEndpointAddress) {

				continue;
			}
			pktsize =
			    alt->altif_ep[j].ep_descr.wMaxPacketSize;
			pktsize = HS_PKT_SIZE(pktsize);
			if (pktsize >= bandwidth && pktsize < curr_pktsize) {
				curr_pktsize = pktsize;
				strm_if->curr_alt = i;
				strm_if->curr_ep = &alt->altif_ep[j].ep_descr;
			}
		}
	}
	if (!strm_if->curr_ep) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, usbvcp->usbvc_log_handle,
		    "usbvc_set_alt: can't find a proper ep to satisfy"
		    " the given bandwidth");

		return (USB_FAILURE);
	}
	USB_DPRINTF_L3(PRINT_MASK_OPEN, usbvcp->usbvc_log_handle,
	    "usbvc_set_alt: strm_if->curr_alt=%d", strm_if->curr_alt);
	if_num = strm_if->if_descr->if_alt->altif_descr.bInterfaceNumber;
	mutex_exit(&usbvcp->usbvc_mutex);
	if ((rval = usb_set_alt_if(usbvcp->usbvc_dip, if_num, strm_if->curr_alt,
	    USB_FLAGS_SLEEP, NULL, NULL)) != USB_SUCCESS) {
		mutex_enter(&usbvcp->usbvc_mutex);
		USB_DPRINTF_L2(PRINT_MASK_OPEN, usbvcp->usbvc_log_handle,
		    "usbvc_set_alt: usb_set_alt_if fail, if.alt=%d.%d, rval=%d",
		    if_num, strm_if->curr_alt, rval);

		return (rval);
	}
	mutex_enter(&usbvcp->usbvc_mutex);

	USB_DPRINTF_L4(PRINT_MASK_OPEN, usbvcp->usbvc_log_handle,
	    "usbvc_set_alt: return, if_num=%d, alt=%d",
	    if_num, strm_if->curr_alt);

	return (rval);
}


/*
 * Decode stream header for mjpeg and uncompressed format video data.
 * mjpeg and uncompressed format have the same stream header. See their
 * payload spec, 2.2 and 2.4
 */
static int
usbvc_decode_stream_header(usbvc_state_t *usbvcp, usbvc_buf_grp_t *bufgrp,
    mblk_t *data, int actual_len)
{
	uint32_t len, buf_left, data_len;
	usbvc_stream_if_t *strm_if;
	uchar_t head_flag, head_len;
	usbvc_buf_t *buf_filling;

	ASSERT(mutex_owned(&usbvcp->usbvc_mutex));
	USB_DPRINTF_L4(PRINT_MASK_CB, usbvcp->usbvc_log_handle,
	    "usbvc_decode_stream_header: enter. actual_len=%x", actual_len);

	/* header length check. */
	if (actual_len < 2) {
		USB_DPRINTF_L2(PRINT_MASK_CB, usbvcp->usbvc_log_handle,
		    "usbvc_decode_stream_header: header is not completed");

		return (USB_FAILURE);
	}
	head_len = data->b_rptr[0];
	head_flag = data->b_rptr[1];

	USB_DPRINTF_L3(PRINT_MASK_CB, usbvcp->usbvc_log_handle,
	    "usbvc_decode_stream_header: headlen=%x", head_len);

	/* header length check. */
	if (actual_len < head_len) {
		USB_DPRINTF_L2(PRINT_MASK_CB, usbvcp->usbvc_log_handle,
		    "usbvc_decode_stream_header: actual_len < head_len");

		return (USB_FAILURE);
	}

	/*
	 * If there is no stream data in this packet and this packet is not
	 * used to indicate the end of a frame, then just skip it.
	 */
	if ((actual_len == head_len) && !(head_flag & USBVC_STREAM_EOF)) {
		USB_DPRINTF_L2(PRINT_MASK_CB, usbvcp->usbvc_log_handle,
		    "usbvc_decode_stream_header: only header, no data");

		return (USB_FAILURE);
	}

	/* Get the first stream interface */
	strm_if = usbvcp->usbvc_curr_strm;

	LE_TO_UINT32(strm_if->ctrl_pc.dwMaxVideoFrameSize, 0, len);
	USB_DPRINTF_L3(PRINT_MASK_CB, usbvcp->usbvc_log_handle,
	    "usbvc_decode_stream_header: dwMaxVideoFrameSize=%x, head_flag=%x",
	    len, head_flag);

	/*
	 * if no buf is filling, pick one buf from free list and alloc data
	 * mem for the buf.
	 */
	if (!bufgrp->buf_filling) {
		if (list_is_empty(&bufgrp->uv_buf_free)) {
			strm_if->fid = head_flag & USBVC_STREAM_FID;
			USB_DPRINTF_L2(PRINT_MASK_CB, usbvcp->usbvc_log_handle,
			    "usbvc_decode_stream_header: free list are empty");

			return (USB_FAILURE);

		} else {
			bufgrp->buf_filling =
			    (usbvc_buf_t *)list_head(&bufgrp->uv_buf_free);

			/* unlink from buf free list */
			list_remove(&bufgrp->uv_buf_free, bufgrp->buf_filling);
		}
		bufgrp->buf_filling->filled = 0;
		USB_DPRINTF_L3(PRINT_MASK_CB, usbvcp->usbvc_log_handle,
		    "usbvc_decode_stream_header: status=%d",
		    bufgrp->buf_filling->status);
		bufgrp->buf_filling->status = USBVC_BUF_EMPTY;
	}
	buf_filling = bufgrp->buf_filling;
	ASSERT(buf_filling->len >= buf_filling->filled);
	buf_left = buf_filling->len - buf_filling->filled;

	/* if no buf room left, then return with a err status */
	if (buf_left == 0) {
		/* buffer full, got an EOF packet(head only, no payload) */
		if ((head_flag & USBVC_STREAM_EOF) &&
		    (actual_len == head_len)) {
			buf_filling->status = USBVC_BUF_DONE;
			USB_DPRINTF_L3(PRINT_MASK_CB, usbvcp->usbvc_log_handle,
			    "usbvc_decode_stream_header: got a EOF packet");

			return (USB_SUCCESS);
		}

		/* Otherwise, mark the buf error and return failure */
		buf_filling->status = USBVC_BUF_ERR;
		USB_DPRINTF_L3(PRINT_MASK_CB, usbvcp->usbvc_log_handle,
		    "usbvc_decode_stream_header: frame buf full");

		return (USB_FAILURE);
	}

	/* get this sample's data length except header */
	data_len = actual_len - head_len;
	USB_DPRINTF_L3(PRINT_MASK_CB, usbvcp->usbvc_log_handle,
	    "usbvc_decode_stream_header: fid=%x, len=%x, filled=%x",
	    strm_if->fid, buf_filling->len, buf_filling->filled);

	/* if the first sample for a frame */
	if (buf_filling->filled == 0) {
		/*
		 * Only if it is the frist packet of a frame,
		 * we will begin filling a frame.
		 */
		if (strm_if->fid != 0xff && strm_if->fid ==
		    (head_flag & USBVC_STREAM_FID)) {
			USB_DPRINTF_L2(PRINT_MASK_CB, usbvcp->usbvc_log_handle,
			    "usbvc_decode_stream_header: 1st sample of a frame,"
			    " fid is incorrect.");

			return (USB_FAILURE);
		}
		strm_if->fid = head_flag & USBVC_STREAM_FID;

	/* If in the middle of a frame, fid should be consistent. */
	} else if (strm_if->fid != (head_flag & USBVC_STREAM_FID)) {
		USB_DPRINTF_L2(PRINT_MASK_CB, usbvcp->usbvc_log_handle,
		    "usbvc_decode_stream_header: fid is incorrect.");
		strm_if->fid = head_flag & USBVC_STREAM_FID;
		buf_filling->status = USBVC_BUF_ERR;

		return (USB_FAILURE);
	}
	if (data_len) {
		bcopy((void *)(data->b_rptr + head_len),
		    (void *)(buf_filling->data + buf_filling->filled),
		    min(data_len, buf_left));

		buf_filling->filled += min(data_len, buf_left);
	}

	/* If the last packet for this frame */
	if (head_flag & USBVC_STREAM_EOF) {
		buf_filling->status = USBVC_BUF_DONE;
	}
	if (data_len > buf_left) {
		buf_filling->status = USBVC_BUF_ERR;
	}
	USB_DPRINTF_L4(PRINT_MASK_CB, usbvcp->usbvc_log_handle,
	    "usbvc_decode_stream_header: buf_status=%d", buf_filling->status);

	return (USB_SUCCESS);
}


/*
 * usbvc_serialize_access:
 *    Get the serial synchronization object before returning.
 *
 * Arguments:
 *    usbvcp - Pointer to usbvc state structure
 *    waitsig - Set to:
 *	USBVC_SER_SIG - to wait such that a signal can interrupt
 *	USBVC_SER_NOSIG - to wait such that a signal cannot interrupt
 */
static int
usbvc_serialize_access(usbvc_state_t *usbvcp, boolean_t waitsig)
{
	int rval = 1;

	ASSERT(mutex_owned(&usbvcp->usbvc_mutex));

	while (usbvcp->usbvc_serial_inuse) {
		if (waitsig == USBVC_SER_SIG) {
			rval = cv_wait_sig(&usbvcp->usbvc_serial_cv,
			    &usbvcp->usbvc_mutex);
		} else {
			cv_wait(&usbvcp->usbvc_serial_cv,
			    &usbvcp->usbvc_mutex);
		}
	}
	usbvcp->usbvc_serial_inuse = B_TRUE;

	return (rval);
}


/*
 * usbvc_release_access:
 *    Release the serial synchronization object.
 */
static void
usbvc_release_access(usbvc_state_t *usbvcp)
{
	ASSERT(mutex_owned(&usbvcp->usbvc_mutex));
	usbvcp->usbvc_serial_inuse = B_FALSE;
	cv_broadcast(&usbvcp->usbvc_serial_cv);
}


/* Send req to video control interface to get ctrl */
int
usbvc_vc_get_ctrl(usbvc_state_t *usbvcp, uint8_t req_code, uint8_t entity_id,
    uint16_t cs, uint16_t wlength, mblk_t *data)
{
	usb_cb_flags_t	cb_flags;
	usb_cr_t	cr;
	usb_ctrl_setup_t setup;

	setup.bmRequestType = USBVC_GET_IF;	/* bmRequestType */
	setup.bRequest = req_code;		/* bRequest */
	setup.wValue = cs<<8;
	setup.wIndex = entity_id<<8;
	setup.wLength = wlength;
	setup.attrs = 0;

	if (usb_pipe_ctrl_xfer_wait(usbvcp->usbvc_default_ph, &setup, &data,
	    &cr, &cb_flags, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_DEVCTRL, usbvcp->usbvc_log_handle,
		    "usbvc_vc_get_ctrl: cmd failed, cr=%d, cb_flags=%x",
		    cr, cb_flags);

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/* Send req to video control interface to get ctrl */
int
usbvc_vc_set_ctrl(usbvc_state_t *usbvcp, uint8_t req_code,  uint8_t entity_id,
    uint16_t cs, uint16_t wlength, mblk_t *data)
{
	usb_cb_flags_t	cb_flags;
	usb_cr_t	cr;
	usb_ctrl_setup_t setup;

	setup.bmRequestType = USBVC_SET_IF;	/* bmRequestType */
	setup.bRequest = req_code;		/* bRequest */
	setup.wValue = cs<<8;
	setup.wIndex = entity_id<<8;
	setup.wLength = wlength;
	setup.attrs = 0;

	if (usb_pipe_ctrl_xfer_wait(usbvcp->usbvc_default_ph, &setup, &data,
	    &cr, &cb_flags, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_DEVCTRL, usbvcp->usbvc_log_handle,
		    "usbvc_vc_set_ctrl: cmd failed, cr=%d, cb_flags=%x",
		    cr, cb_flags);

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/* Set probe or commit ctrl for video stream interface */
int
usbvc_vs_set_probe_commit(usbvc_state_t *usbvcp, usbvc_stream_if_t *strm_if,
    usbvc_vs_probe_commit_t *ctrl_pc, uchar_t cs)
{
	mblk_t *data;
	usb_cb_flags_t	cb_flags;
	usb_cr_t	cr;
	usb_ctrl_setup_t setup;
	int rval;

	setup.bmRequestType = USBVC_SET_IF;	/* bmRequestType */
	setup.bRequest = SET_CUR;		/* bRequest */

	/* wValue, VS_PROBE_CONTROL or VS_COMMIT_CONTROL */
	setup.wValue = cs;

	/* UVC Spec: this value must be put to the high byte */
	setup.wValue = setup.wValue << 8;

	setup.wIndex = strm_if->if_descr->if_alt->altif_descr.bInterfaceNumber;
	setup.wLength = usbvcp->usbvc_vc_header->descr->bcdUVC[0] ? 34 : 26;
	setup.attrs = 0;

	USB_DPRINTF_L3(PRINT_MASK_DEVCTRL, usbvcp->usbvc_log_handle,
	    "usbvc_vs_set_probe_commit: wLength=%d", setup.wLength);

	/* Data block */
	if ((data = allocb(setup.wLength, BPRI_HI)) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_DEVCTRL, usbvcp->usbvc_log_handle,
		    "usbvc_vs_set_probe_commit: allocb failed");

		return (USB_FAILURE);
	}

	bcopy(ctrl_pc, data->b_rptr, setup.wLength);
	data->b_wptr += setup.wLength;

	if ((rval = usb_pipe_ctrl_xfer_wait(usbvcp->usbvc_default_ph, &setup,
	    &data, &cr, &cb_flags, 0)) != USB_SUCCESS) {
		if (data) {
			freemsg(data);
		}
		USB_DPRINTF_L2(PRINT_MASK_DEVCTRL, usbvcp->usbvc_log_handle,
		    "usbvc_vs_set_probe_commit: fail, rval=%d, cr=%d, "
		    "cb_flags=%x", rval, cr, cb_flags);

		return (rval);
	}
	if (data) {
		freemsg(data);
	}

	return (USB_SUCCESS);
}


/* Get probe ctrl for vodeo stream interface */
int
usbvc_vs_get_probe(usbvc_state_t *usbvcp, usbvc_stream_if_t *strm_if,
    usbvc_vs_probe_commit_t *ctrl_pc, uchar_t bRequest)
{
	mblk_t *data = NULL;
	usb_cb_flags_t	cb_flags;
	usb_cr_t	cr;
	usb_ctrl_setup_t setup;

	setup.bmRequestType = USBVC_GET_IF;	/* bmRequestType */
	setup.bRequest = bRequest;		/* bRequest */
	setup.wValue = VS_PROBE_CONTROL;	/* wValue, PROBE or COMMIT */
	setup.wValue = setup.wValue << 8;
	setup.wIndex =
	    (uint16_t)strm_if->if_descr->if_alt->altif_descr.bInterfaceNumber;
	setup.wLength = usbvcp->usbvc_vc_header->descr->bcdUVC[0] ? 34 : 26;

	setup.attrs = 0;

	if (usb_pipe_ctrl_xfer_wait(usbvcp->usbvc_default_ph, &setup, &data,
	    &cr, &cb_flags, 0) != USB_SUCCESS) {
		if (data) {
			freemsg(data);
		}
		USB_DPRINTF_L2(PRINT_MASK_DEVCTRL, usbvcp->usbvc_log_handle,
		    "usbvc_vs_get_probe: cmd failed, cr=%d, cb_flags=%x",
		    cr, cb_flags);

		return (USB_FAILURE);
	}
	bcopy(data->b_rptr, ctrl_pc, setup.wLength);
	if (data) {
		freemsg(data);
	}

	return (USB_SUCCESS);
}


/* Set a default format when open the device */
static int
usbvc_set_default_stream_fmt(usbvc_state_t *usbvcp)
{
	usbvc_vs_probe_commit_t ctrl, ctrl_get;
	usbvc_stream_if_t *strm_if;
	usbvc_format_group_t *curr_fmtgrp;
	uint32_t bandwidth;
	uint8_t  index, i;

	USB_DPRINTF_L4(PRINT_MASK_DEVCTRL, usbvcp->usbvc_log_handle,
	    "usbvc_set_default_stream_fmt: enter");

	mutex_enter(&usbvcp->usbvc_mutex);
	if (list_is_empty(&usbvcp->usbvc_stream_list)) {
		USB_DPRINTF_L2(PRINT_MASK_DEVCTRL, usbvcp->usbvc_log_handle,
		    "usbvc_set_default_stream_fmt: no stream interface, fail");
		mutex_exit(&usbvcp->usbvc_mutex);

		return (USB_FAILURE);
	}
	bzero((void *)&ctrl, sizeof (usbvc_vs_probe_commit_t));

	/* Get the current stream interface */
	strm_if = usbvcp->usbvc_curr_strm;

	/* Fill the probe commit req data */
	ctrl.bmHint[0] = 0;

	for (i = 0; i < strm_if->fmtgrp_cnt; i++) {
		curr_fmtgrp = &strm_if->format_group[i];

		/*
		 * If v4l2_pixelformat is NULL, then that means there is not
		 * a parsed format in format_group[i].
		 */
		if (!curr_fmtgrp || !curr_fmtgrp->v4l2_pixelformat ||
		    curr_fmtgrp->frame_cnt == 0) {
			USB_DPRINTF_L2(PRINT_MASK_DEVCTRL,
			    usbvcp->usbvc_log_handle,
			    "usbvc_set_default_stream_fmt: no frame, fail");

			continue;
		} else {

			break;
		}
	}
	if (!curr_fmtgrp || curr_fmtgrp->frame_cnt == 0) {
		USB_DPRINTF_L2(PRINT_MASK_DEVCTRL, usbvcp->usbvc_log_handle,
		    "usbvc_set_default_stream_fmt: can't find a fmtgrp"
		    "which has a frame, fail");
		mutex_exit(&usbvcp->usbvc_mutex);

		return (USB_FAILURE);
	}

	ctrl.bFormatIndex = curr_fmtgrp->format->bFormatIndex;

	/* use the first frame descr as default */
	ctrl.bFrameIndex = curr_fmtgrp->frames[0].descr->bFrameIndex;

	/* use bcopy to keep the byte sequence as 32 bit little endian */
	bcopy(&(curr_fmtgrp->frames[0].descr->dwDefaultFrameInterval[0]),
	    &(ctrl.dwFrameInterval[0]), 4);

	mutex_exit(&usbvcp->usbvc_mutex);
	if (usbvc_vs_set_probe_commit(usbvcp, strm_if, &ctrl, VS_PROBE_CONTROL)
	    != USB_SUCCESS) {

		return (USB_FAILURE);
	}
	if (usbvc_vs_get_probe(usbvcp, strm_if, &ctrl_get, GET_CUR)
	    != USB_SUCCESS) {

		return (USB_FAILURE);
	}

	mutex_enter(&usbvcp->usbvc_mutex);
	LE_TO_UINT32(strm_if->ctrl_pc.dwMaxPayloadTransferSize, 0, bandwidth);
	USB_DPRINTF_L3(PRINT_MASK_DEVCTRL, usbvcp->usbvc_log_handle,
	    "usbvc_set_default_stream_fmt: get bandwidth=%x", bandwidth);

	mutex_exit(&usbvcp->usbvc_mutex);
	if (usbvc_vs_set_probe_commit(usbvcp, strm_if, &ctrl_get,
	    VS_COMMIT_CONTROL) != USB_SUCCESS) {

		return (USB_FAILURE);
	}

	mutex_enter(&usbvcp->usbvc_mutex);

	/*  it's good to check index here before use it */
	index = ctrl_get.bFormatIndex - curr_fmtgrp->format->bFormatIndex;
	if (index < strm_if->fmtgrp_cnt) {
		strm_if->cur_format_group = &strm_if->format_group[index];
	} else {
		USB_DPRINTF_L2(PRINT_MASK_DEVCTRL, usbvcp->usbvc_log_handle,
		    "usbvc_set_default_stream_fmt: format index out of range");
		mutex_exit(&usbvcp->usbvc_mutex);

		return (USB_FAILURE);
	}

	index = ctrl_get.bFrameIndex -
	    strm_if->cur_format_group->frames[0].descr->bFrameIndex;
	if (index < strm_if->cur_format_group->frame_cnt) {
		strm_if->cur_format_group->cur_frame =
		    &strm_if->cur_format_group->frames[index];
	} else {
		USB_DPRINTF_L2(PRINT_MASK_DEVCTRL, usbvcp->usbvc_log_handle,
		    "usbvc_set_default_stream: frame index out of range");
		mutex_exit(&usbvcp->usbvc_mutex);

		return (USB_FAILURE);
	}

	/*
	 * by now, the video format is set successfully. record the current
	 * setting to strm_if->ctrl_pc
	 */
	bcopy(&ctrl_get, &strm_if->ctrl_pc, sizeof (usbvc_vs_probe_commit_t));

	mutex_exit(&usbvcp->usbvc_mutex);

	return (USB_SUCCESS);
}
