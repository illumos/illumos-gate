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
 * Audio Streams Driver: This driver is responsible for
 * (1) Processing audio data messages during play and record and
 * management of isoc pipe, (2) Selecting correct alternate that matches
 * a set of parameters and management of control pipe. This streams driver
 * is pushed under usb_ac and interacts with usb_ac using streams messages.
 * When a streams message has been received from usb_ac, it is immediately
 * put on WQ. The write side service routine loops thru all the queued
 * messages, processes them and sends up a reply. If the processing involves
 * an async USBA command, the reqly is sent up after completion of the
 * command.
 *
 * Note: (1) All streams messages from usb_ac are M_CTL messages.
 * (2) When there is a play/record, usb_as calls mixer routines directly for
 * data (play) or sends data to mixer (record).
 *
 * Serialization: usb_as being a streams driver and having the requirement
 * making non-blockings calls (USBA or streams or mixer) needs to drop
 * mutexes over such calls.  But at the same time, a competing thread
 * can't be allowed to interfere with (1) pipe, (2) streams state.
 * So we need some kind of serialization among the asynchronous
 * threads that can run in the driver. The serialization is mostly
 * needed to avoid races among open/close/events/power entry points
 * etc. Once a routine grabs access, if checks if the resource (pipe or
 * stream or dev state) is still accessible. If so, it proceeds with
 * its job and until it completes, no other thread requiring the same
 * resource can run.
 *
 * PM Model in usb_as: Raise power during attach and lower power in detach.
 * If device is not fully powered, synchronous raise power in wsrv entry points.
 *
 * locking: Warlock is not aware of the automatic locking mechanisms for
 * streams drivers. This driver is single threaded per queue instance.
 *
 * TODO:
 *	- mdb dcmds
 *	- dump
 *	- kstat
 */
#include <sys/usb/usba/usbai_version.h>
#include <sys/usb/usba.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>

#include <sys/audio.h>
#include <sys/audiovar.h>
#include <sys/audio/audio_support.h>
#include <sys/audio/audio_src.h>
#include <sys/mixer.h>
#include <sys/audio/audio_mixer.h>
#include <sys/audio/am_src2.h>

#include <sys/usb/clients/audio/usb_audio.h>
#include <sys/usb/clients/audio/usb_mixer.h>
#include <sys/usb/clients/audio/usb_as/usb_as.h>

/* debug support */
uint_t	usb_as_errlevel	= USB_LOG_L4;
uint_t	usb_as_errmask	= (uint_t)-1;
uint_t	usb_as_instance_debug = (uint_t)-1;

/*
 * Module linkage routines for the kernel
 */
static int	usb_as_attach(dev_info_t *, ddi_attach_cmd_t);
static int	usb_as_detach(dev_info_t *, ddi_detach_cmd_t);
static int	usb_as_power(dev_info_t *, int, int);
static int	usb_as_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);

/*
 * STREAMS module entry points
 */
static int usb_as_open();
static int usb_as_close();
static int usb_as_wsrv();

/* support functions */
static void	usb_as_cleanup(dev_info_t *, usb_as_state_t *);

static int	usb_as_handle_descriptors(usb_as_state_t *);
static void	usb_as_prepare_registration_data(usb_as_state_t *);
static int	usb_as_valid_format(usb_as_state_t *, uint_t,
				uint_t *, uint_t);
static void	usb_as_free_alts(usb_as_state_t *);
static int	usb_audio_fmt_convert(int);

static void	usb_as_create_pm_components(dev_info_t *, usb_as_state_t *);
static int	usb_as_disconnect_event_cb(dev_info_t *);
static int	usb_as_reconnect_event_cb(dev_info_t *);
static int	usb_as_cpr_suspend(dev_info_t *);
static void	usb_as_cpr_resume(dev_info_t *);

static int	usb_as_ioctl(queue_t *, mblk_t *);
static int	usb_as_mctl_rcv(queue_t *, mblk_t *);

static void	usb_as_default_xfer_cb(usb_pipe_handle_t, usb_ctrl_req_t *);
static void	usb_as_default_xfer_exc_cb(usb_pipe_handle_t, usb_ctrl_req_t *);

static int	usb_as_pwrlvl0(usb_as_state_t *);
static int	usb_as_pwrlvl1(usb_as_state_t *);
static int	usb_as_pwrlvl2(usb_as_state_t *);
static int	usb_as_pwrlvl3(usb_as_state_t *);
static void	usb_as_pm_busy_component(usb_as_state_t *);
static void	usb_as_pm_idle_component(usb_as_state_t *);

static void	usb_as_restore_device_state(dev_info_t *, usb_as_state_t *);
static int	usb_as_setup(usb_as_state_t *, mblk_t *);
static void	usb_as_teardown(usb_as_state_t *, mblk_t *);
static int	usb_as_start_play(usb_as_state_t *, mblk_t *);
static void	usb_as_continue_play(usb_as_state_t *);
static void	usb_as_pause_play(usb_as_state_t *, mblk_t *);

static void	usb_as_qreply_error(usb_as_state_t *, queue_t *, mblk_t *);
static void	usb_as_send_merr_up(usb_as_state_t *, mblk_t *);
static void	usb_as_send_mctl_up(usb_as_state_t *, mblk_t *);
static int	usb_as_set_format(usb_as_state_t *, mblk_t *);
static int	usb_as_set_sample_freq(usb_as_state_t *, mblk_t *);
static int	usb_as_send_ctrl_cmd(usb_as_state_t *, uchar_t, uchar_t,
			ushort_t, ushort_t, ushort_t, mblk_t *, boolean_t);

static void	usb_as_isoc_close_cb(usb_pipe_handle_t ph,
				usb_opaque_t arg, int, usb_cb_flags_t);
static int	usb_as_start_record(usb_as_state_t *, mblk_t *);
static int	usb_as_stop_record(usb_as_state_t *, mblk_t *);
static void	usb_as_play_cb(usb_pipe_handle_t, usb_isoc_req_t *);
static void	usb_as_record_cb(usb_pipe_handle_t, usb_isoc_req_t *);
static void	usb_as_play_exc_cb(usb_pipe_handle_t, usb_isoc_req_t  *);
static void	usb_as_record_exc_cb(usb_pipe_handle_t, usb_isoc_req_t	*);
static int	usb_as_get_pktsize(usb_as_state_t *, usb_audio_formats_t *,
				usb_frame_number_t);
static void	usb_as_handle_shutdown(usb_as_state_t *, mblk_t *);
static int	usb_as_play_isoc_data(usb_as_state_t *, mblk_t *);

/* anchor for soft state structures */
static void	*usb_as_statep;

/*
 * STREAMS Structures
 */

/* STREAMS driver id and limit value structure */
static struct module_info usb_as_modinfo = {
	0xffff,				/* module ID number */
	"usb_as",			/* module name */
	USB_AUDIO_MIN_PKTSZ,		/* minimum packet size */
	USB_AUDIO_MAX_PKTSZ,		/* maximum packet size */
	USB_AS_HIWATER,			/* high water mark */
	USB_AS_LOWATER			/* low water mark */
};

/* STREAMS queue processing procedures structures */
/* read queue */
static struct qinit usb_as_rqueue = {
	NULL,			/* put procedure */
	NULL,			/* service procedure */
	usb_as_open,		/* open procedure */
	usb_as_close,		/* close procedure */
	NULL,			/* unused */
	&usb_as_modinfo,	/* module parameters */
	NULL			/* module statistics */
};

/* write queue */
static struct qinit usb_as_wqueue = {
	putq,		/* put procedure */
	usb_as_wsrv,		/* service procedure */
	NULL,			/* open procedure */
	NULL,			/* close procedure */
	NULL,			/* unused */
	&usb_as_modinfo,	/* module parameters */
	NULL			/* module statistics */
};

/* STREAMS entity declaration structure */
static struct streamtab usb_as_str_info = {
	&usb_as_rqueue,	/* read queue */
	&usb_as_wqueue,	/* write queue */
	NULL,		/* mux lower read queue */
	NULL,		/* mux lower write queue */
};

/*
 * DDI Structures
 */

/* Entry points structure */
static struct cb_ops usb_as_cb_ops = {
	nulldev,		/* cb_open */
	nulldev,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	&usb_as_str_info,	/* cb_str */
	D_MP | D_MTPERQ,	/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev,			/* cb_arwite */
};

/* Device operations structure */
static struct dev_ops usb_as_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	usb_as_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify - obsolete */
	nulldev,		/* devo_probe - not needed */
	usb_as_attach,		/* devo_attach */
	usb_as_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&usb_as_cb_ops,		/* devi_cb_ops */
	NULL,			/* devo_busb_as_ops */
	usb_as_power,		/* devo_power */
	ddi_quiesce_not_needed,	/* devo_quiesce */
};

/* Linkage structure for loadable drivers */
static struct modldrv usb_as_modldrv = {
	&mod_driverops,			/* drv_modops */
	"USB Audio Streaming Driver",	/* drv_linkinfo */
	&usb_as_dev_ops			/* drv_dev_ops */
};

/* Module linkage structure */
static struct modlinkage usb_as_modlinkage = {
	MODREV_1,			/* ml_rev */
	(void *)&usb_as_modldrv,	/* ml_linkage */
	NULL				/* NULL terminates the list */
};

/* warlock directives */
_NOTE(SCHEME_PROTECTS_DATA("unshared", iocblk))
_NOTE(SCHEME_PROTECTS_DATA("unshared", datab))
_NOTE(SCHEME_PROTECTS_DATA("unshared", msgb))
_NOTE(SCHEME_PROTECTS_DATA("unshared", queue))
_NOTE(SCHEME_PROTECTS_DATA("unshared", usb_pipe_policy_t))
_NOTE(SCHEME_PROTECTS_DATA("unshared", usb_isoc_pkt_descr))
_NOTE(SCHEME_PROTECTS_DATA("unshared", usb_isoc_req))

static usb_event_t usb_as_events = {
	usb_as_disconnect_event_cb,
	usb_as_reconnect_event_cb,
	NULL, NULL
};

/*
 * Mixer registration Management
 *	use defaults as much as possible
 */

/* default sample rates that must be supported */
static uint_t usb_as_default_srs[] = {
	8000,	9600, 11025, 16000, 18900, 22050,
	32000,	33075, 37800, 44100, 48000, 0
};

static uint_t usb_as_mixer_srs[] = {
	8000,	48000,	0
};


int
_init(void)
{
	int rval;

	/* initialize the soft state */
	if ((rval = ddi_soft_state_init(&usb_as_statep,
	    sizeof (usb_as_state_t), 1)) != DDI_SUCCESS) {

		return (rval);
	}

	if ((rval = mod_install(&usb_as_modlinkage)) != 0) {
		ddi_soft_state_fini(&usb_as_statep);
	}

	return (rval);
}


int
_fini(void)
{
	int rval;

	if ((rval = mod_remove(&usb_as_modlinkage)) == 0) {
		/* Free the soft state internal structures */
		ddi_soft_state_fini(&usb_as_statep);
	}

	return (rval);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&usb_as_modlinkage, modinfop));
}


/*ARGSUSED*/
static int
usb_as_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd,
			void *arg, void **result)
{
	usb_as_state_t	*uasp = NULL;
	int		error = DDI_FAILURE;
	int		instance = USB_AS_MINOR_TO_INSTANCE(
	    getminor((dev_t)arg));

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:

		if ((uasp = ddi_get_soft_state(usb_as_statep,
		    instance)) != NULL) {
			*result = uasp->usb_as_dip;
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


static int
usb_as_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance = ddi_get_instance(dip);
	usb_as_state_t		*uasp;

	switch (cmd) {
		case DDI_ATTACH:

			break;
		case DDI_RESUME:
			usb_as_cpr_resume(dip);

			return (DDI_SUCCESS);
		default:

			return (DDI_FAILURE);
	}

	/*
	 * Allocate soft state information.
	 */
	if (ddi_soft_state_zalloc(usb_as_statep, instance) != DDI_SUCCESS) {

		return (DDI_FAILURE);
	}

	/*
	 * get soft state space and initialize
	 */
	uasp = (usb_as_state_t *)ddi_get_soft_state(usb_as_statep, instance);
	if (uasp == NULL) {

		return (DDI_FAILURE);
	}

	uasp->usb_as_log_handle = usb_alloc_log_hdl(dip, "as",
	    &usb_as_errlevel,
	    &usb_as_errmask, &usb_as_instance_debug, 0);

	uasp->usb_as_instance = instance;
	uasp->usb_as_dip = dip;

	if (usb_client_attach(dip, USBDRV_VERSION, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
		    "usb_client_attach failed");

		usb_free_log_hdl(uasp->usb_as_log_handle);
		ddi_soft_state_free(usb_as_statep, uasp->usb_as_instance);

		return (DDI_FAILURE);
	}

	if (usb_get_dev_data(dip, &uasp->usb_as_dev_data,
	    USB_PARSE_LVL_IF, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
		    "usb_get_dev_data failed");
		usb_client_detach(dip, NULL);
		usb_free_log_hdl(uasp->usb_as_log_handle);
		ddi_soft_state_free(usb_as_statep, uasp->usb_as_instance);

		return (DDI_FAILURE);
	}

	/* initialize mutex */
	mutex_init(&uasp->usb_as_mutex, NULL, MUTEX_DRIVER,
	    uasp->usb_as_dev_data->dev_iblock_cookie);
	uasp->usb_as_ser_acc = usb_init_serialization(dip,
	    USB_INIT_SER_CHECK_SAME_THREAD);

	uasp->usb_as_default_ph = uasp->usb_as_dev_data->dev_default_ph;
	uasp->usb_as_isoc_pp.pp_max_async_reqs = 1;

	/* parse all descriptors */
	if (usb_as_handle_descriptors(uasp) != USB_SUCCESS) {

		goto fail;
	}

	usb_free_descr_tree(dip, uasp->usb_as_dev_data);

	if ((ddi_create_minor_node(dip, "usb_as", S_IFCHR,
	    USB_AS_CONSTRUCT_MINOR(instance),
	    NULL, 0)) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
		    "usb_as_attach: couldn't create minor node");

		goto fail;
	}

	/* we are online */
	uasp->usb_as_dev_state = USB_DEV_ONLINE;

	/* create components to power manage this device */
	usb_as_create_pm_components(dip, uasp);

	/* Register for events */
	if (usb_register_event_cbs(dip, &usb_as_events, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
		    "usb_as_attach: couldn't register for events");

		goto fail;
	}

	/* report device */
	ddi_report_dev(dip);

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
	    "usb_as_attach: End");

	return (DDI_SUCCESS);

fail:
	if (uasp) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
		    "attach failed");
		usb_as_cleanup(dip, uasp);
	}

	return (DDI_FAILURE);
}


/*ARGSUSED*/
static int
usb_as_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	usb_as_state_t	*uasp;
	int rval;

	uasp = ddi_get_soft_state(usb_as_statep, instance);

	switch (cmd) {
	case DDI_DETACH:
		usb_as_cleanup(dip, uasp);

		return (DDI_SUCCESS);
	case DDI_SUSPEND:
		rval = usb_as_cpr_suspend(dip);

		return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
	default:

		return (DDI_FAILURE);
	}
}


static void
usb_as_cleanup(dev_info_t *dip, usb_as_state_t *uasp)
{
	usb_as_power_t	*uaspm;

	if (uasp == NULL) {

		return;
	}

	uaspm = uasp->usb_as_pm;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_cleanup: uaspm=0x%p", (void *)uaspm);

	if (uasp->usb_as_isoc_ph) {
		usb_pipe_close(dip, uasp->usb_as_isoc_ph,
		    USB_FLAGS_SLEEP, NULL, NULL);
	}
	/*
	 * Disable the event callbacks first, after this point, event
	 * callbacks will never get called. Note we shouldn't hold
	 * mutex while unregistering events because there may be a
	 * competing event callback thread. Event callbacks are done
	 * with ndi mutex held and this can cause a potential deadlock.
	 */
	usb_unregister_event_cbs(dip, &usb_as_events);

	mutex_enter(&uasp->usb_as_mutex);

	if (uaspm && (uasp->usb_as_dev_state != USB_DEV_DISCONNECTED)) {
		if (uaspm->aspm_wakeup_enabled) {
			mutex_exit(&uasp->usb_as_mutex);

			/*
			 * We need to raise power first because
			 * we need to send down a command to disable
			 * remote wakeup
			 */
			usb_as_pm_busy_component(uasp);
			(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

			if (usb_handle_remote_wakeup(dip,
			    USB_REMOTE_WAKEUP_DISABLE)) {
				USB_DPRINTF_L2(PRINT_MASK_ALL,
				    uasp->usb_as_log_handle,
				    "disable remote wake up failed");
			}
			usb_as_pm_idle_component(uasp);
		} else {
			mutex_exit(&uasp->usb_as_mutex);
		}

		(void) pm_lower_power(dip, 0, USB_DEV_OS_PWR_OFF);

		mutex_enter(&uasp->usb_as_mutex);
	}

	if (uaspm) {
		kmem_free(uaspm, sizeof (usb_as_power_t));
		uasp->usb_as_pm = NULL;
	}

	usb_client_detach(dip, uasp->usb_as_dev_data);

	usb_as_free_alts(uasp);

	mutex_exit(&uasp->usb_as_mutex);
	mutex_destroy(&uasp->usb_as_mutex);

	usb_fini_serialization(uasp->usb_as_ser_acc);

	ddi_remove_minor_node(dip, NULL);
	usb_free_log_hdl(uasp->usb_as_log_handle);
	ddi_soft_state_free(usb_as_statep, uasp->usb_as_instance);

	ddi_prop_remove_all(dip);
}


/*
 * usb_as_open:
 *	Open entry point for plumbing only
 */
/*ARGSUSED*/
static int
usb_as_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	usb_as_state_t	*uasp =
	    ddi_get_soft_state(usb_as_statep,
	    USB_AS_MINOR_TO_INSTANCE(getminor(*devp)));
	if (uasp == NULL) {

		return (ENXIO);
	}

	/* Do mux plumbing stuff */
	USB_DPRINTF_L4(PRINT_MASK_OPEN, uasp->usb_as_log_handle,
	    "usb_as_open: Begin q=0x%p", (void *)q);

	if (sflag) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, uasp->usb_as_log_handle,
		    "usb_as_open: clone open not supported");

		return (ENXIO);
	}

	mutex_enter(&uasp->usb_as_mutex);

	/* fail open on a disconnected device */
	if (uasp->usb_as_dev_state == USB_DEV_DISCONNECTED) {
		mutex_exit(&uasp->usb_as_mutex);

		return (ENODEV);
	}

	/* Initialize the queue pointers */
	q->q_ptr = uasp;
	WR(q)->q_ptr = uasp;
	uasp->usb_as_rq = q;
	uasp->usb_as_wq = WR(q);
	uasp->usb_as_streams_flag = USB_AS_STREAMS_OPEN;
	mutex_exit(&uasp->usb_as_mutex);

	/*
	 * go to full power, and remain pm_busy till close
	 */
	usb_as_pm_busy_component(uasp);
	(void) pm_raise_power(uasp->usb_as_dip, 0, USB_DEV_OS_FULL_PWR);

	qprocson(q);

	USB_DPRINTF_L4(PRINT_MASK_OPEN, uasp->usb_as_log_handle,
	    "usb_as_open: End q=0x%p", (void *)q);

	return (0);
}


/*
 * usb_as_close:
 *	Close entry point for plumbing
 */
/*ARGSUSED*/
static int
usb_as_close(queue_t *q, int flag, cred_t *credp)
{
	usb_as_state_t	*uasp = (usb_as_state_t *)q->q_ptr;

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, uasp->usb_as_log_handle,
	    "usb_as_close: q=0x%p", (void *)q);

	mutex_enter(&uasp->usb_as_mutex);
	uasp->usb_as_streams_flag = USB_AS_STREAMS_DISMANTLING;
	mutex_exit(&uasp->usb_as_mutex);

	/*
	 * Avoid races with other routines.
	 * For example, if a control transfer is going on, wait
	 * for that to be completed
	 * At this point default pipe cannot be open.
	 */
	(void) usb_serialize_access(uasp->usb_as_ser_acc, USB_WAIT, 0);

	usb_release_access(uasp->usb_as_ser_acc);

	qprocsoff(q);

	/* we can now power down */
	usb_as_pm_idle_component(uasp);

	return (0);
}


static void
usb_as_qreply_error(usb_as_state_t *uasp, queue_t *q, mblk_t *mp)
{
	mutex_enter(&uasp->usb_as_mutex);
	uasp->usb_as_def_mblk = NULL;
	mutex_exit(&uasp->usb_as_mutex);

	if (!canputnext(RD(q))) {
		freemsg(mp);
	} else {
		/*
		 * Pass an error message up.
		 */
		mp->b_datap->db_type = M_ERROR;
		if (mp->b_cont) {
			freemsg(mp->b_cont);
			mp->b_cont = NULL;
		}
		mp->b_rptr = mp->b_datap->db_base;
		mp->b_wptr = mp->b_rptr + sizeof (char);
		*mp->b_rptr = EINVAL;
		qreply(q, mp);
	}
	USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_qreply_error: sending M_ERROR up q=0x%p,mp=0x%p",
	    (void *)q, (void *)mp);
}


/*
 * usb_as_wsrv
 *	write service routine, processes all the queued mblks.
 *	returns DDI_SUCCESS or DDI_FAILURE
 */
static int
usb_as_wsrv(queue_t *q)
{
	int		error;
	usb_as_state_t	*uasp = q->q_ptr;
	mblk_t		*mp = NULL;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_wsrv: Begin q=0x%p", (void *)q);

	/* process all message blocks on the queue */
	while ((mp = getq(q)) != NULL) {
		ASSERT(mp->b_datap != NULL);

		switch (mp->b_datap->db_type) {
		case M_FLUSH:
			/*
			 * Canonical flush handling :
			 *	mp will be freed by usb_ac since it passes
			 *	the same mp
			 */
			if (*mp->b_rptr & FLUSHW) {
				flushq(q, FLUSHDATA);
			}
			/* read queue not used so just send up */
			if (*mp->b_rptr & FLUSHR) {
				*mp->b_rptr &= ~FLUSHW;
				qreply(q, mp);
			} else {
				freemsg(mp);
			}

			break;
		case M_IOCTL:
			/* only ioctl is mixer registration data */
			error = usb_as_ioctl(q, mp);

			break;
		case M_CTL:
			/* process the message */
			mutex_enter(&uasp->usb_as_mutex);
			ASSERT(uasp->usb_as_def_mblk == NULL);
			uasp->usb_as_def_mblk = mp;
			mutex_exit(&uasp->usb_as_mutex);

			error = usb_as_mctl_rcv(q, mp);
			if (error != USB_SUCCESS) {
				usb_as_qreply_error(uasp, q, mp);
			}

			break;
		default:
			usb_as_qreply_error(uasp, q, mp);

			break;
		}
	}

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_wsrv: End q=0x%p", (void *)q);

	return (DDI_SUCCESS);
}


/*
 * usb_as_ioctl:
 *	usb_as handles only USB_AUDIO_MIXER_REGISTRATION ioctl
 *	NACK all other ioctl requests
 *	Returns USB_SUCCESS or USB_FAILURE
 */
static int
usb_as_ioctl(queue_t *q, mblk_t *mp)
{
	int		error = USB_FAILURE;
	usb_as_state_t	*uasp = q->q_ptr;
	register struct iocblk *iocp;

	iocp = (struct iocblk *)mp->b_rptr;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_ioctl: Begin q=0x%p, mp=0x%p", (void *)q, (void *)mp);

	if (mp->b_cont == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_ioctl: no data block, q=0x%p, mp=0x%p",
		    (void *)q, (void *)mp);
	} else {
		switch (iocp->ioc_cmd) {
		case USB_AUDIO_MIXER_REGISTRATION:
			USB_DPRINTF_L4(PRINT_MASK_ALL,
			    uasp->usb_as_log_handle,
			    "usb_as_ioctl(mixer reg): q=0x%p, "
			    "mp=0x%p, b_cont_rptr=0x%p, b_cont_wptr=0x%p",
			    (void *)q, (void *)mp, (void *)mp->b_cont->b_rptr,
			    (void *)mp->b_cont->b_wptr);

			mutex_enter(&uasp->usb_as_mutex);

			/*
			 * Copy the usb_as_reg structure to the structure
			 * that usb_ac passed. Note that this is a structure
			 * assignment and not a pointer assignment!
			 */
			*((usb_as_registration_t *)(*((
			    usb_as_registration_t **)mp->
			    b_cont->b_rptr))) = uasp->usb_as_reg;

			mp->b_cont->b_wptr = mp->b_cont->b_rptr +
			    sizeof (usb_as_registration_t *);

			mutex_exit(&uasp->usb_as_mutex);
			error = USB_SUCCESS;
			break;
		default:
			USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
			    "usb_as_ioctl: unknown IOCTL, cmd=%d",
			    iocp->ioc_cmd);
			break;
		}
	}

	iocp->ioc_rval = 0;
	if (error == USB_FAILURE) {
		iocp->ioc_error = ENOTTY;
		mp->b_datap->db_type = M_IOCNAK;
	} else {
		iocp->ioc_error = 0;
		mp->b_datap->db_type = M_IOCACK;
	}

	/*
	 * Send the response up
	 */
	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_ioctl: error=%d, q=0x%p, mp=0x%p", error,
	    (void *)q, (void *)mp);

	qreply(q, mp);

	return (error);
}


/*
 * usb_as_mctl_rcv:
 *	Handle M_CTL requests from usb_ac.
 *	Returns USB_SUCCESS/FAILURE
 */
static int
usb_as_mctl_rcv(queue_t *q, mblk_t *mp)
{
	int		error = USB_FAILURE;
	usb_as_state_t	*uasp = q->q_ptr;
	struct iocblk	*iocp;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_mctl_rcv: Begin q=0x%p mp=0x%p",
	    (void *)q, (void *)mp);

	ASSERT(mp != NULL);

	/*
	 * Uopn success, each function sends up a reply either immediately,
	 * or on callback. On failure, reply is send up in the wsrv.
	 */
	iocp = (struct iocblk *)mp->b_rptr;
	mutex_enter(&uasp->usb_as_mutex);
	switch (iocp->ioc_cmd) {
		case USB_AUDIO_SET_FORMAT:
			error = usb_as_set_format(uasp, mp);
			break;
		case USB_AUDIO_SET_SAMPLE_FREQ:
			error = usb_as_set_sample_freq(uasp, mp);
			break;
		case USB_AUDIO_SETUP:
			error = usb_as_setup(uasp, mp);
			break;
		case USB_AUDIO_TEARDOWN:
			usb_as_teardown(uasp, mp);
			error = USB_SUCCESS;
			break;
		case USB_AUDIO_START_PLAY:
			error = usb_as_start_play(uasp, mp);
			break;
		case USB_AUDIO_STOP_PLAY:
		case USB_AUDIO_PAUSE_PLAY:
			usb_as_pause_play(uasp, mp);
			error = USB_SUCCESS;
			break;
		case USB_AUDIO_START_RECORD:
			error = usb_as_start_record(uasp, mp);
			break;
		case USB_AUDIO_STOP_RECORD:
			error = usb_as_stop_record(uasp, mp);
			break;
		default:
			break;
	}

	mutex_exit(&uasp->usb_as_mutex);

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_mctl_rcv: End q=0x%p mp=0x%p error=%d",
	    (void *)q, (void *)mp, error);

	return (error);
}


/*
 * usb_as_set_sample_freq:
 *	Sets the sample freq by sending a control command to interface
 *	Although not required for continuous sample rate devices, some
 *	devices such as plantronics devices do need this.
 *	On the other hand, the TI chip which does not support continuous
 *	sample rate stalls on this request
 *	Therefore, we ignore errors and carry on regardless
 */
static int
usb_as_set_sample_freq(usb_as_state_t *uasp, mblk_t *mp)
{
	int	freq, alt, ep;
	mblk_t	*data;
	int	rval = USB_FAILURE;
	boolean_t ignore_errors;

	ASSERT(mp != NULL);
	ASSERT(mp->b_cont != NULL);
	ASSERT(mutex_owned(&uasp->usb_as_mutex));

	alt = uasp->usb_as_alternate;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_set_sample_freq: mp=0x%p cont_sr=%d", (void *)mp,
	    uasp->usb_as_alts[alt].alt_continuous_sr);

	ignore_errors = B_TRUE;

	ep = uasp->usb_as_alts[alt].alt_ep->bEndpointAddress;
	freq = *((int *)mp->b_cont->b_rptr);

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_set_sample_freq: freq = %d", freq);

	if (mp->b_cont) {
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
	}

	data = allocb(4, BPRI_HI);
	if (data) {
		*(data->b_wptr++) = (char)freq;
		*(data->b_wptr++) = (char)(freq >> 8);
		*(data->b_wptr++) = (char)(freq >> 16);

		mutex_exit(&uasp->usb_as_mutex);

		if ((rval = usb_as_send_ctrl_cmd(uasp,
		    USB_DEV_REQ_HOST_TO_DEV |
		    USB_DEV_REQ_TYPE_CLASS |
		    USB_DEV_REQ_RCPT_EP,		/* bmRequestType */
		    USB_AUDIO_SET_CUR,			/* bRequest */
		    USB_AUDIO_SAMPLING_FREQ_CONTROL << 8, /* wValue */
		    ep,					/* wIndex */
		    3,					/* wLength */
		    data,
		    ignore_errors)) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
			    "usb_as_set_sample_freq: set sample freq failed");

			freemsg(data);
		}
		mutex_enter(&uasp->usb_as_mutex);
	}

	return (rval);
}


/*
 * usb_as_set_format:
 *	Matches channel, encoding and precision and find out
 *	the right alternate. Sets alternate interface.
 */
static int
usb_as_set_format(usb_as_state_t *uasp, mblk_t *mp)
{
	int		n;
	usb_as_registration_t *reg;
	usb_audio_formats_t *format;
	int		alt, rval;
	uint_t		interface;

	ASSERT(mp != NULL);
	ASSERT(mp->b_cont != NULL);
	ASSERT(mutex_owned(&uasp->usb_as_mutex));

	if (uasp->usb_as_request_count) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_set_format: failing mp=0x%p, rq_cnt=%d",
		    (void *)mp, uasp->usb_as_request_count);

		return (USB_FAILURE);
	}

	ASSERT(uasp->usb_as_isoc_ph == NULL);

	reg = &uasp->usb_as_reg;
	interface = uasp->usb_as_ifno;
	format = (usb_audio_formats_t *)mp->b_cont->b_rptr;

	bcopy(format, &uasp->usb_as_curr_format, sizeof (usb_audio_formats_t));

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_set_format: mp=0x%p, reg=0x%p, format=0x%p",
	    (void *)mp, (void *)reg, (void *)format);

	for (n = 0; n < reg->reg_n_formats; n++) {
		if ((format->fmt_chns == reg->reg_formats[n].fmt_chns) &&
		    (format->fmt_precision == reg->reg_formats[n].
		    fmt_precision) && (format->fmt_encoding ==
		    reg->reg_formats[n].fmt_encoding)) {
			/*
			 * Found the alternate
			 */
			uasp->usb_as_alternate = alt =
			    reg->reg_formats[n].fmt_alt;
			break;
		}
	}

	if (n > reg->reg_n_formats) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_set_format: Didn't find a matching alt");

		return (USB_FAILURE);
	}

	ASSERT(uasp->usb_as_isoc_ph == NULL);

	USB_DPRINTF_L3(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_set_format: interface=%d alternate=%d",
	    interface, alt);

	mutex_exit(&uasp->usb_as_mutex);

	if ((rval = usb_as_send_ctrl_cmd(uasp,
					/* bmRequestType */
	    USB_DEV_REQ_HOST_TO_DEV | USB_DEV_REQ_RCPT_IF,
	    USB_REQ_SET_IF,		/* bRequest */
	    alt,			/* wValue */
	    interface,			/* wIndex */
	    0,				/* wLength */
	    NULL, B_FALSE)) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_set_format: set_alternate failed");

	}
	mutex_enter(&uasp->usb_as_mutex);

	return (rval);
}


/*
 * usb_as_setup:
 *	Open isoc pipe. Will hang around till bandwidth
 *	is available.
 */
static int
usb_as_setup(usb_as_state_t *uasp, mblk_t *mp)
{
	int alt = uasp->usb_as_alternate;
	usb_ep_descr_t *ep = (usb_ep_descr_t *)uasp->usb_as_alts[alt].alt_ep;
	int rval;

	ASSERT(mp != NULL);
	ASSERT(mutex_owned(&uasp->usb_as_mutex));

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_setup: Begin usb_as_setup, mp=0x%p", (void *)mp);

	ASSERT(uasp->usb_as_request_count == 0);

	/* Set record packet size to max packet size */
	if (uasp->usb_as_alts[alt].alt_mode == AUDIO_RECORD) {
		uasp->usb_as_record_pkt_size = ep->wMaxPacketSize;
	} else {
		uasp->usb_as_record_pkt_size = 0;
	}

	mutex_exit(&uasp->usb_as_mutex);

	/* open isoc pipe, may fail if there is no bandwidth  */
	rval = usb_pipe_open(uasp->usb_as_dip, ep, &uasp->usb_as_isoc_pp,
	    0, &uasp->usb_as_isoc_ph);

	if (rval != USB_SUCCESS) {
		switch (rval) {
		case USB_NO_BANDWIDTH:
			USB_DPRINTF_L0(PRINT_MASK_ALL, uasp->usb_as_log_handle,
			    "no bandwidth available");
			break;
		case USB_NOT_SUPPORTED:
			USB_DPRINTF_L0(PRINT_MASK_ALL, uasp->usb_as_log_handle,
			    "Operating a full/high speed audio device on a "
			    "high speed port is not supported");
			break;
		default:
			USB_DPRINTF_L2(PRINT_MASK_ALL,
			    uasp->usb_as_log_handle,
			    "usb_as_setup: isoc pipe open failed (%d)",
			    rval);
		}

		mutex_enter(&uasp->usb_as_mutex);

		return (USB_FAILURE);
	}

	(void) usb_pipe_set_private(uasp->usb_as_isoc_ph, (usb_opaque_t)uasp);

	/* return reply up */
	mutex_enter(&uasp->usb_as_mutex);
	uasp->usb_as_audio_state = USB_AS_IDLE;
	uasp->usb_as_setup_cnt++;
	usb_as_send_mctl_up(uasp, NULL);

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_setup: End");

	return (USB_SUCCESS);
}


/*
 * usb_as_teardown
 *
 */
static void
usb_as_teardown(usb_as_state_t *uasp, mblk_t *mp)
{
	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_teardown: Begin mp=0x%p", (void *)mp);
	ASSERT(mutex_owned(&uasp->usb_as_mutex));

	uasp->usb_as_audio_state = USB_AS_IDLE;

	if (uasp->usb_as_isoc_ph) {
		USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_teardown: closing isoc pipe, ph=0x%p",
		    (void *)uasp->usb_as_isoc_ph);

		mutex_exit(&uasp->usb_as_mutex);

		/* reply mp will be sent up in isoc close callback */
		usb_pipe_close(uasp->usb_as_dip, uasp->usb_as_isoc_ph, 0,
		    usb_as_isoc_close_cb, (usb_opaque_t)uasp);

		/* wait for callback to send up a reply */
		mutex_enter(&uasp->usb_as_mutex);
		uasp->usb_as_isoc_ph = NULL;

		/* reset setup flag */
		uasp->usb_as_setup_cnt--;

	} else {
		USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_teardown: Pipe already closed");

		usb_as_send_mctl_up(uasp, NULL);
	}

	ASSERT(uasp->usb_as_setup_cnt == 0);

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_teardown: End");
}


/*
 * usb_as_start_play:
 *	this function is called from usb_as_mctl_rcv
 */
static int
usb_as_start_play(usb_as_state_t *uasp, mblk_t *mp)
{
	usb_audio_play_req_t *play_req;
	int		samples;
	int		n_requests;
	int		rval = USB_FAILURE;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_start_play: Begin mp=0x%p, req_cnt=%d",
	    (void *)mp, uasp->usb_as_request_count);

	ASSERT(mutex_owned(&uasp->usb_as_mutex));

	ASSERT(mp && mp->b_cont);

	play_req = (usb_audio_play_req_t *)mp->b_cont->b_rptr;
	uasp->usb_as_request_samples = play_req->up_samples;
	uasp->usb_as_ahdl = play_req->up_handle;
	uasp->usb_as_audio_state = USB_AS_ACTIVE;

	samples = uasp->usb_as_request_samples;

	if ((uasp->usb_as_request_count >= USB_AS_MAX_REQUEST_COUNT) ||
	    (uasp->usb_as_audio_state == USB_AS_IDLE) ||
	    (uasp->usb_as_audio_state == USB_AS_PLAY_PAUSED)) {
		USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "nothing to do or paused or idle (%d)",
		    uasp->usb_as_audio_state);
		rval = USB_SUCCESS;
	} else {
		USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_start_play: samples=%d requestcount=%d ",
		    samples, uasp->usb_as_request_count);

		/* queue up as many requests as allowed */
		for (n_requests = uasp->usb_as_request_count;
		    n_requests < USB_AS_MAX_REQUEST_COUNT; n_requests++) {
			if ((rval = usb_as_play_isoc_data(uasp, mp)) !=
			    USB_SUCCESS) {
				break;
			}
		}
	}

	/*
	 * send mctl up for success. For failure, usb_as_wsrv
	 * will send an merr up.
	 */
	if (rval == USB_SUCCESS) {
		usb_as_send_mctl_up(uasp, NULL);
	}


	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_start_play: End");

	return (rval);
}


/*
 * usb_as_continue_play:
 *	this function is called from the play callbacks
 */
static void
usb_as_continue_play(usb_as_state_t *uasp)
{
	int		samples;
	int		n_requests;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_contine_play: Begin req_cnt=%d",
	    uasp->usb_as_request_count);

	ASSERT(mutex_owned(&uasp->usb_as_mutex));

	if (uasp->usb_as_dev_state == USB_DEV_DISCONNECTED) {
		usb_as_handle_shutdown(uasp, NULL);

		return;
	}

	samples = uasp->usb_as_request_samples;

	if ((uasp->usb_as_request_count >= USB_AS_MAX_REQUEST_COUNT) ||
	    (uasp->usb_as_audio_state == USB_AS_IDLE) ||
	    (uasp->usb_as_audio_state == USB_AS_PLAY_PAUSED)) {
		USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_continue_play: nothing to do (audio_state=%d)",
		    uasp->usb_as_audio_state);
	} else {
		USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_continue_play: samples=%d requestcount=%d ",
		    samples, uasp->usb_as_request_count);

		/* queue up as many requests as allowed */
		for (n_requests = uasp->usb_as_request_count;
		    n_requests < USB_AS_MAX_REQUEST_COUNT; n_requests++) {
			if (usb_as_play_isoc_data(uasp, NULL) !=
			    USB_SUCCESS) {

				break;
			}
		}
	}

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_continue_play: End");
}


static void
usb_as_handle_shutdown(usb_as_state_t *uasp, mblk_t *mp)
{
	audiohdl_t	ahdl;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_handl_shutdown, mp=0x%p", (void *)mp);

	if (mp != NULL) {
		usb_as_send_mctl_up(uasp, NULL);
	}

	USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_handle_shutdown: am_play_shutdown");

	uasp->usb_as_audio_state = USB_AS_IDLE;
	uasp->usb_as_pkt_count = 0;
	ahdl = uasp->usb_as_ahdl;

	mutex_exit(&uasp->usb_as_mutex);
	am_play_shutdown(ahdl, AUDIO_NO_CHANNEL);
	mutex_enter(&uasp->usb_as_mutex);
}


static int
usb_as_play_isoc_data(usb_as_state_t *uasp, mblk_t *mp)
{
	int		rval = USB_FAILURE;

	usb_isoc_req_t *isoc_req = NULL;
	usb_audio_formats_t *format = &uasp->usb_as_curr_format;
	mblk_t		*data = NULL;
	audiohdl_t	ahdl = uasp->usb_as_ahdl;
	int		precision;
	int		pkt, frame, n, n_pkts, count;
	size_t		bufsize;
	int		pkt_len[USB_AS_N_FRAMES];

	ASSERT(mutex_owned(&uasp->usb_as_mutex));

	/* we only support two precisions */
	if ((format->fmt_precision != AUDIO_PRECISION_8) &&
	    (format->fmt_precision != AUDIO_PRECISION_16)) {

		rval = USB_FAILURE;

		goto done;
	}

	precision = (format->fmt_precision == AUDIO_PRECISION_8) ? 1 : 2;

	frame = uasp->usb_as_pkt_count;

	/*
	 * calculate total bufsize by determining the pkt size for
	 * each frame
	 */
	for (bufsize = pkt = 0; pkt < USB_AS_N_FRAMES; pkt++) {
		pkt_len[pkt] = usb_as_get_pktsize(uasp, format, frame++);
		bufsize += pkt_len[pkt];
	}

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_play_isoc_data: Begin bufsize=0x%lx, mp=0x%p", bufsize,
	    (void *)mp);

	mutex_exit(&uasp->usb_as_mutex);

	if ((data = allocb(bufsize, BPRI_HI)) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_play_isoc_data: allocb failed");
		mutex_enter(&uasp->usb_as_mutex);

		goto done;
	}

	if ((count = am_get_audio(ahdl, (void *)data->b_wptr,
	    AUDIO_NO_CHANNEL, bufsize / precision)) == 0) {
		mutex_enter(&uasp->usb_as_mutex);
		if (uasp->usb_as_request_count == 0) {
			usb_as_handle_shutdown(uasp, NULL);

			/* Don't return failure for 0 bytes of data sent */
			if (mp) {
				/*
				 * Since we set rval to SUCCESS
				 * we treat it as a special case
				 * and free data here
				 */
				rval = USB_SUCCESS;
				freemsg(data);
				data = NULL;

				goto done;
			}
		} else {
			USB_DPRINTF_L2(PRINT_MASK_ALL,
			    uasp->usb_as_log_handle,
			    "usb_as_play_isoc_data: no audio bytes, "
			    "rcnt=0x%x ", uasp->usb_as_request_count);
		}
		rval = USB_FAILURE;

		goto done;
	}

	bufsize = n = count * precision;
	data->b_wptr += n;

	/* calculate how many frames we can actually fill */
	for (n_pkts = 0; (n_pkts < USB_AS_N_FRAMES) && (n > 0); n_pkts++) {
		if (n < pkt_len[n_pkts]) {
			pkt_len[n_pkts] = n;
		}
		n -= pkt_len[n_pkts];
	}

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_play_isoc_data: n_pkts=%d, bufsize=%ld, n=%d",
	    n_pkts, bufsize, count * precision);

	/* allocate an isoc request packet */
	if ((isoc_req = usb_alloc_isoc_req(uasp->usb_as_dip,
	    n_pkts, 0, 0)) == NULL) {
		mutex_enter(&uasp->usb_as_mutex);

		goto done;
	}


#if defined(_BIG_ENDIAN)
	/* byte swap if necessary */
	if (format->fmt_precision == AUDIO_PRECISION_16) {
		int i;
		uchar_t tmp;
		uchar_t *p = data->b_rptr;

		for (i = 0; i < bufsize; i += 2, p += 2) {
			tmp = *p;
			*p = *(p + 1);
			*(p + 1) = tmp;
		}
	}
#endif

	/* initialize the packet descriptor */
	for (pkt = 0; pkt < n_pkts; pkt++) {
		isoc_req->isoc_pkt_descr[pkt].isoc_pkt_length =
		    pkt_len[pkt];
	}

	isoc_req->isoc_data		= data;
	isoc_req->isoc_pkts_count	= (ushort_t)n_pkts;
	isoc_req->isoc_attributes	= USB_ATTRS_ISOC_XFER_ASAP |
	    USB_ATTRS_AUTOCLEARING;
	isoc_req->isoc_cb		= usb_as_play_cb;
	isoc_req->isoc_exc_cb		= usb_as_play_exc_cb;
	isoc_req->isoc_client_private	= (usb_opaque_t)uasp;

	mutex_enter(&uasp->usb_as_mutex);

	USB_DPRINTF_L3(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_play_isoc_data: rq=0x%p data=0x%p cnt=0x%x "
	    "pkt=0x%p rqcnt=%d ", (void *)isoc_req, (void *)data, count,
	    (void *)isoc_req->isoc_pkt_descr, uasp->usb_as_request_count);

	ASSERT(isoc_req->isoc_data != NULL);

	uasp->usb_as_send_debug_count++;
	uasp->usb_as_request_count++;
	uasp->usb_as_pkt_count += n_pkts;
	mutex_exit(&uasp->usb_as_mutex);

	if ((rval = usb_pipe_isoc_xfer(uasp->usb_as_isoc_ph,
	    isoc_req, 0)) != USB_SUCCESS) {

		mutex_enter(&uasp->usb_as_mutex);
		uasp->usb_as_request_count--;
		uasp->usb_as_send_debug_count--;
		uasp->usb_as_pkt_count -= n_pkts;

		USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_play_isoc_data: rval=%d", rval);

		rval = USB_FAILURE;

	} else {
		mutex_enter(&uasp->usb_as_mutex);

		data = NULL;
		isoc_req = NULL;
	}

done:
	if (rval != USB_SUCCESS) {
		freemsg(data);
		if (isoc_req) {
			isoc_req->isoc_data = NULL;
			usb_free_isoc_req(isoc_req);
		}
	}

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_play_isoc_data: SEND CNT=%d, RCV COUNT=%d",
	    uasp->usb_as_send_debug_count, uasp->usb_as_rcv_debug_count);

	return (rval);
}


/*ARGSUSED*/
static void
usb_as_pause_play(usb_as_state_t *uasp, mblk_t *mp)
{
	ASSERT(mutex_owned(&uasp->usb_as_mutex));
	uasp->usb_as_audio_state = USB_AS_PLAY_PAUSED;
	usb_as_send_mctl_up(uasp, NULL);
}


/*ARGSUSED*/
static void
usb_as_play_cb(usb_pipe_handle_t ph, usb_isoc_req_t *isoc_req)
{
	usb_as_state_t *uasp = (usb_as_state_t *)
	    (isoc_req->isoc_client_private);
	int i;

	USB_DPRINTF_L4(PRINT_MASK_CB, uasp->usb_as_log_handle,
	    "usb_as_play_cb: Begin ph=0x%p, isoc_req=0x%p",
	    (void *)ph, (void *)isoc_req);

	ASSERT((isoc_req->isoc_cb_flags & USB_CB_INTR_CONTEXT) != 0);

	for (i = 0; i < isoc_req->isoc_pkts_count; i++) {
		if (isoc_req->isoc_pkt_descr[i].isoc_pkt_status !=
		    USB_CR_OK) {
			USB_DPRINTF_L2(PRINT_MASK_CB, uasp->usb_as_log_handle,
			    "usb_as_play_cb: \tpkt%d: len=%d status=%s", i,
			    isoc_req->isoc_pkt_descr[i].isoc_pkt_length,
			    usb_str_cr(isoc_req->
			    isoc_pkt_descr[i].isoc_pkt_status));
		}
	}

	mutex_enter(&uasp->usb_as_mutex);
	if (isoc_req->isoc_error_count) {
		USB_DPRINTF_L2(PRINT_MASK_CB, uasp->usb_as_log_handle,
		    "usb_as_play_cb: error_count = %d",
		    isoc_req->isoc_error_count);
	}

	usb_free_isoc_req(isoc_req);
	uasp->usb_as_request_count--;
	uasp->usb_as_rcv_debug_count++;
	usb_as_continue_play(uasp);

	USB_DPRINTF_L4(PRINT_MASK_CB, uasp->usb_as_log_handle,
	    "usb_as_play_cb: SEND CNT=%d, RCV COUNT=%d",
	    uasp->usb_as_send_debug_count, uasp->usb_as_rcv_debug_count);

	USB_DPRINTF_L4(PRINT_MASK_CB, uasp->usb_as_log_handle,
	    "usb_as_play_cb: End, req_cnt=%d", uasp->usb_as_request_count);

	mutex_exit(&uasp->usb_as_mutex);
}


static void
usb_as_play_exc_cb(usb_pipe_handle_t ph, usb_isoc_req_t *isoc_req)
{
	int i;
	usb_as_state_t	*uasp = (usb_as_state_t *)
	    (isoc_req->isoc_client_private);
	usb_cr_t	cr = isoc_req->isoc_completion_reason;
	usb_cb_flags_t	cb_flags = isoc_req->isoc_cb_flags;

	USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_play_exc_cb: ph=0x%p, rq=0x%p data=0x%p pkts=0x%x "
	    "cr=%d, cb_flag=0x%x", (void *)ph, (void *)isoc_req,
	    (void *)isoc_req->isoc_data, isoc_req->isoc_pkts_count,
	    cr, cb_flags);

	ASSERT((isoc_req->isoc_cb_flags & USB_CB_INTR_CONTEXT) == 0);

	for (i = 0; i < isoc_req->isoc_pkts_count; i++) {
		if (isoc_req->isoc_pkt_descr[i].isoc_pkt_status ==
		    USB_CR_OK) {
			USB_DPRINTF_L2(PRINT_MASK_ALL,
			    uasp->usb_as_log_handle,
			    "usb_as_play_exc_cb: \tpkt%d: len=%d status=%d",
			    i,
			    isoc_req->isoc_pkt_descr[i].isoc_pkt_length,
			    isoc_req->isoc_pkt_descr[i].isoc_pkt_status);
		}
	}

	usb_free_isoc_req(isoc_req);

	mutex_enter(&uasp->usb_as_mutex);
	uasp->usb_as_rcv_debug_count++;
	uasp->usb_as_request_count--;
	usb_as_handle_shutdown(uasp, NULL);

	USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_play_exc_cb: SEND CNT=%d, RCV COUNT=%d",
	    uasp->usb_as_send_debug_count, uasp->usb_as_rcv_debug_count);

	USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_play_exc_cb: End request_count=%d",
	    uasp->usb_as_request_count);

	mutex_exit(&uasp->usb_as_mutex);
}


/*
 * usb_as_start_record
 */
static int
usb_as_start_record(usb_as_state_t *uasp, mblk_t *mp)
{
	int		rval = USB_FAILURE;
	usb_isoc_req_t *isoc_req;
	ushort_t	record_pkt_size = uasp->usb_as_record_pkt_size;
	ushort_t	n_pkt = 1, pkt;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_start_record: mp=0x%p", (void *)mp);

	ASSERT(mp != NULL);
	ASSERT(mp->b_cont != NULL);
	ASSERT(mutex_owned(&uasp->usb_as_mutex));

	/*
	 * A start_record should not happen when stop polling is
	 * happening
	 */
	ASSERT(uasp->usb_as_audio_state != USB_AS_STOP_POLLING_STARTED);

	if (uasp->usb_as_audio_state == USB_AS_IDLE) {

		uasp->usb_as_ahdl = *((audiohdl_t *)mp->b_cont->b_rptr);
		uasp->usb_as_audio_state = USB_AS_ACTIVE;
		mutex_exit(&uasp->usb_as_mutex);

		if ((isoc_req = usb_alloc_isoc_req(uasp->usb_as_dip, n_pkt,
		    n_pkt * record_pkt_size, 0)) != NULL) {
			/* Initialize the packet descriptor */
			for (pkt = 0; pkt < n_pkt; pkt++) {
				isoc_req->isoc_pkt_descr[pkt].
				    isoc_pkt_length = record_pkt_size;
			}

			isoc_req->isoc_pkts_count = n_pkt;
			isoc_req->isoc_pkts_length = record_pkt_size;
			isoc_req->isoc_attributes = USB_ATTRS_ISOC_XFER_ASAP |
			    USB_ATTRS_SHORT_XFER_OK | USB_ATTRS_AUTOCLEARING;
			isoc_req->isoc_cb = usb_as_record_cb;
			isoc_req->isoc_exc_cb = usb_as_record_exc_cb;
			isoc_req->isoc_client_private = (usb_opaque_t)uasp;

			rval = usb_pipe_isoc_xfer(uasp->usb_as_isoc_ph,
			    isoc_req, 0);

		} else {
			USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
			    "usb_as_start_record: Isoc req allocation failed");
		}

		mutex_enter(&uasp->usb_as_mutex);

	} else {

		USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_start_record: Record in progress");

		rval = USB_SUCCESS;
	}

	if (rval != USB_SUCCESS) {
		uasp->usb_as_audio_state = USB_AS_IDLE;
		if (isoc_req) {
			usb_free_isoc_req(isoc_req);
			isoc_req = NULL;
		}
	} else {
		usb_as_send_mctl_up(uasp, NULL);
	}

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_start_record: rval=%d", rval);

	return (rval);
}


/*ARGSUSED*/
static int
usb_as_stop_record(usb_as_state_t *uasp, mblk_t *mp)
{
	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_stop_record: ");
	ASSERT(mutex_owned(&uasp->usb_as_mutex));

	/* if we are disconnected, the pipe will be closed anyways */
	if (uasp->usb_as_dev_state == USB_DEV_DISCONNECTED) {
		usb_as_send_mctl_up(uasp, NULL);

		return (USB_SUCCESS);
	}

	switch (uasp->usb_as_audio_state) {
	case USB_AS_ACTIVE:
		mutex_exit(&uasp->usb_as_mutex);

		/*
		 * Stop polling. When the completion reason indicate that
		 * polling is over, return response message up.
		 */
		usb_pipe_stop_isoc_polling(uasp->usb_as_isoc_ph,
		    USB_FLAGS_SLEEP);
		mutex_enter(&uasp->usb_as_mutex);

		usb_as_send_mctl_up(uasp, NULL);

		break;
	case USB_AS_STOP_POLLING_STARTED:
		/* A stop polling in progress, wait for completion and reply */
		break;
	default:
		usb_as_send_mctl_up(uasp, NULL);
	}


	return (USB_SUCCESS);
}


static void
usb_as_record_exc_cb(usb_pipe_handle_t ph, usb_isoc_req_t *isoc_req)
{
	usb_as_state_t	*uasp = (usb_as_state_t *)
	    (isoc_req->isoc_client_private);
	usb_cr_t	completion_reason;
	int		rval;

	completion_reason = isoc_req->isoc_completion_reason;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_record_exc_cb: ph=0x%p, isoc_req=0x%p, cr=%d",
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
		rval = usb_pipe_isoc_xfer(uasp->usb_as_isoc_ph, isoc_req, 0);

		USB_DPRINTF_L3(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_record_exc_cb: restart record rval=%d", rval);

		return;
	default:

		mutex_enter(&uasp->usb_as_mutex);

		/* Do not start if one is already in progress */
		if (uasp->usb_as_audio_state != USB_AS_STOP_POLLING_STARTED) {
			uasp->usb_as_audio_state = USB_AS_STOP_POLLING_STARTED;

			mutex_exit(&uasp->usb_as_mutex);
			(void) usb_pipe_stop_isoc_polling(ph,
			    USB_FLAGS_NOSLEEP);

			return;
		} else {
			mutex_exit(&uasp->usb_as_mutex);
		}

		break;
	}
	usb_free_isoc_req(isoc_req);

	mutex_enter(&uasp->usb_as_mutex);
	USB_DPRINTF_L3(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_record_exc_cb: state=%d cr=0x%x",
	    uasp->usb_as_audio_state, completion_reason);

	uasp->usb_as_audio_state = USB_AS_IDLE;
	mutex_exit(&uasp->usb_as_mutex);
}


/*ARGSUSED*/
static void
usb_as_record_cb(usb_pipe_handle_t ph, usb_isoc_req_t *isoc_req)
{
	usb_as_state_t *uasp = (usb_as_state_t *)isoc_req->isoc_client_private;
	int		i, offset, sz;
	audiohdl_t	ahdl;
	usb_audio_formats_t *format = &uasp->usb_as_curr_format;
	int		precision;

	USB_DPRINTF_L4(PRINT_MASK_CB, uasp->usb_as_log_handle,
	    "usb_as_record_cb: rq=0x%p data=0x%p pkts=0x%x",
	    (void *)isoc_req, (void *)isoc_req->isoc_data,
	    isoc_req->isoc_pkts_count);

	USB_DPRINTF_L4(PRINT_MASK_CB, uasp->usb_as_log_handle,
	    "\tfno=%" PRId64 ", n_pkts=%u, flag=0x%x, data=0x%p, cnt=%d",
	    isoc_req->isoc_frame_no, isoc_req->isoc_pkts_count,
	    isoc_req->isoc_attributes, (void *)isoc_req->isoc_data,
	    isoc_req->isoc_error_count);

	ASSERT((isoc_req->isoc_cb_flags & USB_CB_INTR_CONTEXT) != 0);

	mutex_enter(&uasp->usb_as_mutex);
	ahdl = uasp->usb_as_ahdl;
	sz = uasp->usb_as_record_pkt_size;
	precision = (format->fmt_precision == AUDIO_PRECISION_8) ? 1 : 2;

	if (uasp->usb_as_audio_state != USB_AS_IDLE) {
#if defined(_BIG_ENDIAN)
		unsigned char	*ptr = isoc_req->isoc_data->b_rptr;
#endif
		for (offset = i = 0; i < isoc_req->isoc_pkts_count; i++) {
#if defined(_BIG_ENDIAN)
			int len = isoc_req->isoc_pkt_descr[i].
			    isoc_pkt_actual_length;
			/* do byte swap for precision 16 */
			if (format->fmt_precision == AUDIO_PRECISION_16) {
				int  j;
				for (j = 0; j < len; j += 2, ptr += 2) {
					char t = *ptr;
					*ptr = *(ptr + 1);
					*(ptr + 1) = t;
				}
			}
#endif
			USB_DPRINTF_L3(PRINT_MASK_CB, uasp->usb_as_log_handle,
			    "\tpkt%d: "
			    "offset=%d pktsize=%d len=%d status=%d resid=%d",
			    i, offset, sz,
			    isoc_req->isoc_pkt_descr[i].isoc_pkt_length,
			    isoc_req->isoc_pkt_descr[i].isoc_pkt_status,
			    isoc_req->isoc_pkt_descr[i].isoc_pkt_actual_length);

			if (isoc_req->isoc_pkt_descr[i].isoc_pkt_status !=
			    USB_CR_OK) {
				USB_DPRINTF_L2(PRINT_MASK_CB,
				    uasp->usb_as_log_handle,
				    "record: pkt=%d offset=0x%x status=%s",
				    i, offset, usb_str_cr(isoc_req->
				    isoc_pkt_descr[i].isoc_pkt_status));
			}
			mutex_exit(&uasp->usb_as_mutex);

			am_send_audio(ahdl,
			    isoc_req->isoc_data->b_rptr + offset,
			    AUDIO_NO_CHANNEL, isoc_req->
			    isoc_pkt_descr[i].isoc_pkt_actual_length /
			    precision);

			mutex_enter(&uasp->usb_as_mutex);
			offset += isoc_req->isoc_pkt_descr[i].isoc_pkt_length;
		}
	}

	mutex_exit(&uasp->usb_as_mutex);

	usb_free_isoc_req(isoc_req);
}


/*
 * Support for sample rates that are not multiple of 1K. We have 3 such
 * sample rates: 11025, 22050 and 44100.
 */
typedef struct usb_as_pktsize_table {
	uint_t		sr;
	ushort_t	pkt;
	ushort_t	cycle;
	int		extra;
} usb_as_pktsize_table_t;

/*
 * usb_as_pktsize_info is the table that calculates the pktsize
 * corresponding to the current frame and the current format.
 * Since the int_rate is 1000, we have to do special arithmetic for
 * sample rates not multiple of 1K. For example,
 * if the sample rate is 48000(i.e multiple of 1K), we can send 48000/1000
 * = 48 samples every packet per channel. Since we have to support sample
 * rate like 11025, 22050 and 44100, we will have some extra samples
 * at the end that we need to spread among the 1000 cycles. So if we make
 * the pktsize as below for these sample rates, at the end of 1000 cycles,
 * we will be able to send all the data in the correct rate:
 *
 * 11025: 39 samples of 11, 1 of 12
 * 22050: 19 samples of 22, 1 of 23
 * 44100: 9 samples of 44, 1 of 45
 *
 * frameno is a simple counter maintained in the soft state structure.
 * So the pkt size is:
 * pkt_size =  ((frameno %  cycle) ?  pkt : (pkt + extra));
 *
 */
static usb_as_pktsize_table_t usb_as_pktsize_info[] = {
	{8000,	8,	1000,	0},
	{9600,	10,	5,	-2},
	{11025,	11,	40,	1},
	{16000,	16,	1000,	0},
	{18900, 19,	10,	-1},
	{22050,	22,	20,	1},
	{32000,	32,	1000,	0},
	{33075, 33,	12,	1},
	{37800, 38,	5,	-1},
	{44100,	44,	10,	1},
	{48000, 48,	1000,	0},
	{ 0 }
};


static int
usb_as_get_pktsize(usb_as_state_t *uasp, usb_audio_formats_t *format,
	usb_frame_number_t frameno)
{
	int	n;
	int	pkt_size = 0;
	ushort_t pkt, cycle;
	int	extra;
	int	n_srs =
	    sizeof (usb_as_pktsize_info) / sizeof (usb_as_pktsize_table_t);

	for (n = 0; n < n_srs; n++) {
		if (usb_as_pktsize_info[n].sr == format->fmt_sr) {
			cycle	= usb_as_pktsize_info[n].cycle;
			pkt	= usb_as_pktsize_info[n].pkt;
			extra	= usb_as_pktsize_info[n].extra;
			pkt_size = (((frameno + 1) % cycle) ?
			    pkt : (pkt + extra));
			pkt_size *= ((format->fmt_precision ==
			    AUDIO_PRECISION_16) ? 2 : 1)
			    * format->fmt_chns;
			break;
		}
	}

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_get_pktsize: %d", pkt_size);

	return (pkt_size);
}


/*
 * usb_as_send_ctrl_cmd:
 *	Opens the pipe; sends a control command down
 */
static int
usb_as_send_ctrl_cmd(usb_as_state_t *uasp,
	uchar_t	bmRequestType, uchar_t bRequest,
	ushort_t wValue, ushort_t wIndex, ushort_t wLength,
	mblk_t	*data, boolean_t ignore_errors)
{
	usb_ctrl_req_t *reqp;


	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_send_ctrl_cmd: Begin bmRequestType=%d,\n\t"
	    "bRequest=%d, wValue=%d, wIndex=%d, wLength=%d, data=0x%p",
	    bmRequestType, bRequest, wValue, wIndex, wLength, (void *)data);

	if ((reqp = usb_alloc_ctrl_req(uasp->usb_as_dip, 0, 0)) == NULL) {

		mutex_enter(&uasp->usb_as_mutex);
		uasp->usb_as_xfer_cr = USB_AS_SEND_MERR;
		mutex_exit(&uasp->usb_as_mutex);

		return (USB_FAILURE);
	}

	reqp->ctrl_bmRequestType	= bmRequestType;
	reqp->ctrl_bRequest		= bRequest;
	reqp->ctrl_wValue		= wValue;
	reqp->ctrl_wIndex		= wIndex;
	reqp->ctrl_wLength		= wLength;
	reqp->ctrl_data			= data;
	reqp->ctrl_attributes		= 0;
	reqp->ctrl_client_private	= (usb_opaque_t)uasp;
	reqp->ctrl_cb			= usb_as_default_xfer_cb;
	reqp->ctrl_exc_cb		= ignore_errors ?
	    usb_as_default_xfer_cb : usb_as_default_xfer_exc_cb;

	/* Send async command down */
	if (usb_pipe_ctrl_xfer(uasp->usb_as_default_ph, reqp, 0) !=
	    USB_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_send_ctrl_cmd: usba xfer failed (req=%d)",
		    bRequest);

		mutex_enter(&uasp->usb_as_mutex);
		uasp->usb_as_xfer_cr = USB_AS_SEND_MERR;
		mutex_exit(&uasp->usb_as_mutex);
		usb_free_ctrl_req(reqp);

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


static void
usb_as_send_merr_up(usb_as_state_t *uasp, mblk_t *mp)
{
	queue_t *q;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_send_merr_up: data=0x%p", (void *)mp);

	ASSERT(mutex_owned(&uasp->usb_as_mutex));
	q = uasp->usb_as_rq;

	mp->b_datap->db_type = M_ERROR;

	if (mp->b_cont) {
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
	}

	mp->b_rptr = mp->b_datap->db_base;
	mp->b_wptr = mp->b_rptr + sizeof (char);
	*mp->b_rptr = EINVAL;

	mutex_exit(&uasp->usb_as_mutex);
	if (!canputnext(RD(q))) {
		freemsg(mp);
		mp = NULL;
	} else {
		putnext(RD(q), mp);
	}
	mutex_enter(&uasp->usb_as_mutex);
}


static void
usb_as_send_mctl_up(usb_as_state_t *uasp, mblk_t *data)
{
	mblk_t		*tmp, *mp;
	queue_t		*q;
	struct iocblk	*iocp;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_send_mctl_up: data=0x%p", (void *)data);
	ASSERT(mutex_owned(&uasp->usb_as_mutex));

	q = uasp->usb_as_rq;
	mp = uasp->usb_as_def_mblk;
	ASSERT(mp != NULL);

	/* Free the b_cont of the original mblk_t, if any */
	if (mp->b_cont) {
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
	}

	/*
	 * If we have response to send up, attach it at the b_cont
	 * of the mctl message. Otherwise just send the mctl message
	 * up and the module above will decode the command
	 */
	iocp = (struct iocblk *)mp->b_rptr;
	iocp->ioc_error = 0;

	switch (iocp->ioc_cmd) {
	case USB_AUDIO_SET_FORMAT:
		freemsg(data);

		/*
		 * we cannot easily recover if we can't get an mblk
		 * so we have to sleep here
		 */
		tmp = allocb_wait(sizeof (int), BPRI_HI,
		    STR_NOSIG, NULL);
		iocp->ioc_count = sizeof (int);
		*(int *)tmp->b_wptr = uasp->usb_as_alternate;
		tmp->b_wptr += sizeof (int);
		mp->b_cont = tmp;

		USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_send_mctl_up: set_format returning,alt=%d",
		    uasp->usb_as_alternate);

		break;
	default:
		if (data != NULL) {
			/*
			 * Use the original mp to send the message up
			 * This should already have the right ioc_cmd in.
			 */
			iocp->ioc_count = MBLKL(data);
			mp->b_cont = data;
		} else {
			iocp->ioc_count = 0;
		}
		break;
	}
	uasp->usb_as_def_mblk = NULL;
	mutex_exit(&uasp->usb_as_mutex);
	if (!canputnext(q)) {
		freemsg(mp);
		mp = NULL;
	} else {
		putnext(q, mp);
	}
	mutex_enter(&uasp->usb_as_mutex);
}


/*
 * usb_as_default_xfer_cb:
 *	Callback routine for the async control xfer. Reply mctl here.
 */
/*ARGSUSED*/
static void
usb_as_default_xfer_cb(usb_pipe_handle_t def, usb_ctrl_req_t *reqp)
{
	usb_as_state_t	*uasp = (usb_as_state_t *)reqp->ctrl_client_private;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_default_xfer_cb: ph=0x%p, reqp=0x%p",
	    (void *)def, (void *)reqp);

	ASSERT((reqp->ctrl_cb_flags & USB_CB_INTR_CONTEXT) == 0);

	mutex_enter(&uasp->usb_as_mutex);
	uasp->usb_as_xfer_cr = USB_AS_SEND_MCTL;
	usb_as_send_mctl_up(uasp, NULL);
	mutex_exit(&uasp->usb_as_mutex);

	usb_free_ctrl_req(reqp);

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_default_xfer_cb: End");
}


/*
 * usb_as_isoc_close_cb()
 *	called from teardown usb_pipe_close
 */
static void
usb_as_isoc_close_cb(usb_pipe_handle_t ph, usb_opaque_t arg,
	int rval, usb_cb_flags_t cb_flags)
{
	usb_as_state_t	*uasp = (usb_as_state_t  *)arg;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_isoc_close_cb: ph=0x%p arg=0x%p cb_flags=0x%x",
	    (void *)ph, (void *)arg, cb_flags);

	/* pipe close cannot fail */
	ASSERT(rval == USB_SUCCESS);

	mutex_enter(&uasp->usb_as_mutex);
	usb_as_send_mctl_up(uasp, NULL);
	mutex_exit(&uasp->usb_as_mutex);

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_isoc_close_cb: End");
}


/*
 * usb_as_default_exc_cb:
 *	Exception callback for the default pipe. Autoclearing took care
 *	of the recovery
 */
/*ARGSUSED*/
static void
usb_as_default_xfer_exc_cb(usb_pipe_handle_t def, usb_ctrl_req_t *reqp)
{
	usb_as_state_t	*uasp = (usb_as_state_t *)reqp->ctrl_client_private;
	mblk_t		*mp;

	USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_default_xfer_exc_cb: ph=0x%p, reqp=0x%p",
	    (void *)def, (void *)reqp);

	ASSERT((reqp->ctrl_cb_flags & USB_CB_INTR_CONTEXT) == 0);

	mutex_enter(&uasp->usb_as_mutex);
	uasp->usb_as_xfer_cr = USB_AS_SEND_MERR;
	mp = uasp->usb_as_def_mblk;
	uasp->usb_as_def_mblk = NULL;

	usb_as_send_merr_up(uasp, mp);

	mutex_exit(&uasp->usb_as_mutex);

	usb_free_ctrl_req(reqp);

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_default_xfer_exc_cb: End");
}


/*
 * Power management
 */

/*ARGSUSED*/
static void
usb_as_create_pm_components(dev_info_t *dip, usb_as_state_t *uasp)
{
	usb_as_power_t	*uaspm;
	uint_t		pwr_states;

	USB_DPRINTF_L4(PRINT_MASK_PM, uasp->usb_as_log_handle,
	    "usb_as_create_pm_components: begin");

	/* Allocate the state structure */
	uaspm = kmem_zalloc(sizeof (usb_as_power_t), KM_SLEEP);
	uasp->usb_as_pm = uaspm;
	uaspm->aspm_state = uasp;
	uaspm->aspm_capabilities = 0;
	uaspm->aspm_current_power = USB_DEV_OS_FULL_PWR;

	USB_DPRINTF_L3(PRINT_MASK_PM, uasp->usb_as_log_handle,
	    "usb_as_pm_components: remote Wakeup enabled");
	if (usb_create_pm_components(dip, &pwr_states) ==
	    USB_SUCCESS) {
		if (usb_handle_remote_wakeup(dip,
		    USB_REMOTE_WAKEUP_ENABLE) != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_PM,
			    uasp->usb_as_log_handle,
			    "enable remote wakeup failed");
		} else {
			uaspm->aspm_wakeup_enabled = 1;
		}
		uaspm->aspm_pwr_states = (uint8_t)pwr_states;
		(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);
	}

	USB_DPRINTF_L4(PRINT_MASK_PM, uasp->usb_as_log_handle,
	    "usb_as_create_pm_components: end");
}


/*
 * usb_as_power:
 *	power entry point
 */
static int
usb_as_power(dev_info_t *dip, int comp, int level)
{
	int		instance = ddi_get_instance(dip);
	usb_as_state_t	*uasp;
	usb_as_power_t	*uaspm;
	int		retval = USB_FAILURE;

	uasp = ddi_get_soft_state(usb_as_statep, instance);

	USB_DPRINTF_L4(PRINT_MASK_PM, uasp->usb_as_log_handle,
	    "usb_as_power: comp=%d level=%d", comp, level);

	(void) usb_serialize_access(uasp->usb_as_ser_acc, USB_WAIT, 0);

	mutex_enter(&uasp->usb_as_mutex);
	uaspm = uasp->usb_as_pm;

	if (USB_DEV_PWRSTATE_OK(uaspm->aspm_pwr_states, level)) {
		USB_DPRINTF_L2(PRINT_MASK_PM, uasp->usb_as_log_handle,
		    "usb_as_power: illegal level=%d pwr_states=%d",
		    level, uaspm->aspm_pwr_states);

		goto done;
	}

	switch (level) {
	case USB_DEV_OS_PWR_OFF:
		retval = usb_as_pwrlvl0(uasp);
		break;
	case USB_DEV_OS_PWR_1:
		retval = usb_as_pwrlvl1(uasp);
		break;
	case USB_DEV_OS_PWR_2:
		retval = usb_as_pwrlvl2(uasp);
		break;
	case USB_DEV_OS_FULL_PWR:
		retval = usb_as_pwrlvl3(uasp);
		break;
	default:
		retval = USB_FAILURE;
		break;
	}

done:

	usb_release_access(uasp->usb_as_ser_acc);
	mutex_exit(&uasp->usb_as_mutex);

	return ((retval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}


/*
 * functions to handle power transition for various levels
 * These functions act as place holders to issue USB commands
 * to the devices to change their power levels
 * Level 0 = Device is powered off
 * Level 3 = Device if full powered
 * Level 1,2 = Intermediate power level of the device as implemented
 *	by the hardware.
 * Note that Level 0 is OS power-off and Level 3 is OS full-power.
 */
static int
usb_as_pwrlvl0(usb_as_state_t *uasp)
{
	usb_as_power_t	*uaspm;
	int		rval;

	uaspm = uasp->usb_as_pm;

	switch (uasp->usb_as_dev_state) {
	case USB_DEV_ONLINE:
		/* Deny the powerdown request if the device is busy */
		if (uaspm->aspm_pm_busy != 0) {

			return (USB_FAILURE);
		}

		if (uasp->usb_as_audio_state != USB_AS_IDLE) {

			return (USB_FAILURE);
		}

		/* Issue USB D3 command to the device here */
		rval = usb_set_device_pwrlvl3(uasp->usb_as_dip);
		ASSERT(rval == USB_SUCCESS);

		uasp->usb_as_dev_state = USB_DEV_PWRED_DOWN;
		uaspm->aspm_current_power = USB_DEV_OS_PWR_OFF;

		/* FALLTHRU */
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:
		/* allow a disconnected/cpr'ed device to go to low power */

		return (USB_SUCCESS);
	case USB_DEV_PWRED_DOWN:
	default:
		USB_DPRINTF_L2(PRINT_MASK_PM, uasp->usb_as_log_handle,
		    "usb_as_pwrlvl0: Illegal dev_state");

		return (USB_FAILURE);
	}
}


/* ARGSUSED */
static int
usb_as_pwrlvl1(usb_as_state_t *uasp)
{
	int		rval;

	/* Issue USB D2 command to the device here */
	rval = usb_set_device_pwrlvl2(uasp->usb_as_dip);
	ASSERT(rval == USB_SUCCESS);

	return (USB_FAILURE);
}


/* ARGSUSED */
static int
usb_as_pwrlvl2(usb_as_state_t *uasp)
{
	int		rval;

	rval = usb_set_device_pwrlvl1(uasp->usb_as_dip);
	ASSERT(rval == USB_SUCCESS);

	return (USB_FAILURE);
}


static int
usb_as_pwrlvl3(usb_as_state_t *uasp)
{
	usb_as_power_t	*uaspm;
	int		rval;

	uaspm = uasp->usb_as_pm;

	switch (uasp->usb_as_dev_state) {
	case USB_DEV_PWRED_DOWN:

		/* Issue USB D0 command to the device here */
		rval = usb_set_device_pwrlvl0(uasp->usb_as_dip);
		ASSERT(rval == USB_SUCCESS);

		uasp->usb_as_dev_state = USB_DEV_ONLINE;
		uaspm->aspm_current_power = USB_DEV_OS_FULL_PWR;

		/* FALLTHRU */
	case USB_DEV_ONLINE:
		/* we are already in full power */

		/* fall thru */
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:
		/* allow power change on a disconnected/cpr'ed device */

		return (USB_SUCCESS);
	default:
		USB_DPRINTF_L2(PRINT_MASK_PM, uasp->usb_as_log_handle,
		    "usb_as_pwrlvl3: Illegal dev_state");

		return (DDI_FAILURE);
	}
}


/*
 * Descriptor Management
 *
 * usb_as_handle_descriptors:
 *	read and parse all descriptors and build up usb_as_alts list
 *
 *	the order is as follows:
 *	    interface, general, format, endpoint, CV endpoint
 */
static int
usb_as_handle_descriptors(usb_as_state_t *uasp)
{
	usb_client_dev_data_t		*dev_data = uasp->usb_as_dev_data;
	int				interface = dev_data->dev_curr_if;
	uint_t				alternate;
	uint_t				n_alternates;
	int				len, i, n, n_srs, sr, index;
	int				rval = USB_SUCCESS;
	usb_if_descr_t			*if_descr;
	usb_audio_as_if_descr_t 	*general;
	usb_audio_type1_format_descr_t	*format;
	usb_ep_descr_t			*ep;
	usb_audio_as_isoc_ep_descr_t	*cs_ep;
	usb_if_data_t			*if_data;
	usb_alt_if_data_t		*altif_data;
	usb_ep_data_t			*ep_data;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
	    "usb_as_handle_descriptors: cfg=%ld interface=%d",
	    (long)(dev_data->dev_curr_cfg - &dev_data->dev_cfg[0]),
	    dev_data->dev_curr_if);

	if_data = &dev_data->dev_curr_cfg->cfg_if[dev_data->dev_curr_if];
	uasp->usb_as_ifno = interface;

	/*
	 * find the number of alternates for this interface
	 * and allocate an array to store the descriptors for
	 * each alternate
	 */
	uasp->usb_as_n_alternates = n_alternates = if_data->if_n_alt;
	uasp->usb_as_alts = kmem_zalloc((n_alternates) *
	    sizeof (usb_as_alt_descr_t), KM_SLEEP);

	/*
	 * for each alternate read descriptors
	 */
	for (alternate = 0; alternate < n_alternates; alternate++) {
		altif_data = &if_data->if_alt[alternate];

		uasp->usb_as_alts[alternate].alt_if =
		    kmem_zalloc(sizeof (usb_if_descr_t), KM_SLEEP);
		if_descr = &altif_data->altif_descr;

		USB_DPRINTF_L3(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
		    "interface (%d.%d):\n\t"
		    "l = 0x%x type = 0x%x n = 0x%x alt = 0x%x #ep = 0x%x\n\t"
		    "iclass = 0x%x subclass = 0x%x proto = 0x%x string = 0x%x",
		    interface, alternate,
		    if_descr->bLength, if_descr->bDescriptorType,
		    if_descr->bInterfaceNumber, if_descr->bAlternateSetting,
		    if_descr->bNumEndpoints, if_descr->bInterfaceClass,
		    if_descr->bInterfaceSubClass,
		    if_descr->bInterfaceProtocol, if_descr->iInterface);

		*(uasp->usb_as_alts[alternate].alt_if) = *if_descr;

		/* read the general descriptor */
		index = 0;

		if (altif_data->altif_cvs == NULL) {

			continue;
		}

		general = kmem_zalloc(sizeof (*general), KM_SLEEP);

		len = usb_parse_data(AS_IF_DESCR_FORMAT,
		    altif_data->altif_cvs[index].cvs_buf,
		    altif_data->altif_cvs[index].cvs_buf_len,
		    (void *)general, sizeof (*general));

		/* is this a sane header descriptor */
		if (!((len >= AS_IF_DESCR_SIZE) &&
		    (general->bDescriptorType == USB_AUDIO_CS_INTERFACE) &&
		    (general->bDescriptorSubType == USB_AUDIO_AS_GENERAL))) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    uasp->usb_as_log_handle,
			    "invalid general cs interface descr");

			kmem_free(general, sizeof (*general));

			continue;
		}

		USB_DPRINTF_L3(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
		    "general (%d.%d): type=0x%x subtype=0x%x termlink=0x%x\n\t"
		    "delay=0x%x format=0x%x",
		    interface, alternate,
		    general->bDescriptorType, general->bDescriptorSubType,
		    general->bTerminalLink, general->bDelay,
		    general->wFormatTag);

		uasp->usb_as_alts[alternate].alt_general = general;

		/*
		 * there should be one format descriptor of unknown size.
		 * the format descriptor contains just bytes, no need to
		 * parse
		 */
		index++;
		len = altif_data->altif_cvs[index].cvs_buf_len;
		format = kmem_zalloc(len, KM_SLEEP);
		bcopy(altif_data->altif_cvs[index].cvs_buf, format, len);

		uasp->usb_as_alts[alternate].alt_format_len = (uchar_t)len;

		/* is this a sane format descriptor */
		if (!((format->blength >= AUDIO_TYPE1_FORMAT_SIZE) &&
		    format->bDescriptorSubType == USB_AUDIO_AS_FORMAT_TYPE)) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    uasp->usb_as_log_handle,
			    "invalid format cs interface descr");

			kmem_free(format, len);

			continue;
		}

		uasp->usb_as_alts[alternate].alt_format = format;

		USB_DPRINTF_L3(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
		    "format (%d.%d): len = %d "
		    "type = 0x%x subtype = 0x%x format = 0x%x\n\t"
		    "#channels = 0x%x subframe = 0x%x resolution = 0x%x\n\t"
		    "sample freq type = 0x%x",
		    interface, alternate, len,
		    format->bDescriptorType,
		    format->bDescriptorSubType,
		    format->bFormatType,
		    format->bNrChannels,
		    format->bSubFrameSize,
		    format->bBitResolution,
		    format->bSamFreqType);

		if (format->bSamFreqType == 0) {
			/* continuous sample rate limits */
			n_srs = 2;
			uasp->usb_as_alts[alternate].alt_continuous_sr++;
		} else {
			n_srs = format->bSamFreqType;
		}

		uasp->usb_as_alts[alternate].alt_n_sample_rates =
		    (uchar_t)n_srs;

		uasp->usb_as_alts[alternate].alt_sample_rates =
		    kmem_zalloc(n_srs * (sizeof (uint_t)), KM_SLEEP);

		/* go thru all sample rates (3 bytes) each */
		for (i = 0, n = 0; n < n_srs; i += 3, n++) {
			sr = ((format->bSamFreqs[i+2] << 16) & 0xff0000) |
			    ((format->bSamFreqs[i+1] << 8) & 0xff00) |
			    (format->bSamFreqs[i] & 0xff);

			USB_DPRINTF_L3(PRINT_MASK_ATTA,
			    uasp->usb_as_log_handle,
			    "sr = %d", sr);

			uasp->usb_as_alts[alternate].
			    alt_sample_rates[n] = sr;
		}

		if ((ep_data = usb_lookup_ep_data(uasp->usb_as_dip,
		    dev_data, interface, alternate, 0,
		    USB_EP_ATTR_ISOCH, USB_EP_DIR_IN)) == NULL) {
			if ((ep_data = usb_lookup_ep_data(uasp->usb_as_dip,
			    dev_data, interface, alternate, 0,
			    USB_EP_ATTR_ISOCH, USB_EP_DIR_OUT)) == NULL) {

				USB_DPRINTF_L2(PRINT_MASK_ATTA,
				    uasp->usb_as_log_handle,
				    "no endpoint descriptor found");

				continue;
			}
		}
		ep = &ep_data->ep_descr;

		uasp->usb_as_alts[alternate].alt_ep =
		    kmem_zalloc(sizeof (usb_ep_descr_t), KM_SLEEP);
		*(uasp->usb_as_alts[alternate].alt_ep) = *ep;

		USB_DPRINTF_L4(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
		    "endpoint (%d.%d):\n\t"
		    "len = 0x%x type = 0x%x add = 0x%x "
		    "attr = 0x%x mps = 0x%x\n\t"
		    "int = 0x%x",
		    interface, alternate,
		    ep->bLength, ep->bDescriptorType, ep->bEndpointAddress,
		    ep->bmAttributes, ep->wMaxPacketSize, ep->bInterval);

		uasp->usb_as_alts[alternate].alt_mode  =
		    (ep->bEndpointAddress & USB_EP_DIR_IN) ?
		    AUDIO_RECORD : AUDIO_PLAY;

		if (ep_data->ep_n_cvs == 0) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    uasp->usb_as_log_handle,
			    "no cv ep descriptor");

			continue;
		}

		cs_ep = kmem_zalloc(sizeof (*cs_ep), KM_SLEEP);
		len = usb_parse_data(AS_ISOC_EP_DESCR_FORMAT,
		    ep_data->ep_cvs[0].cvs_buf,
		    ep_data->ep_cvs[0].cvs_buf_len,
		    (void *)cs_ep, sizeof (*cs_ep));

		if ((len < AS_ISOC_EP_DESCR_SIZE) ||
		    (cs_ep->bDescriptorType != USB_AUDIO_CS_ENDPOINT)) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    uasp->usb_as_log_handle,
			    "cs endpoint descriptor invalid (%d)", len);
			kmem_free(cs_ep, sizeof (*cs_ep));

			continue;
		}

		USB_DPRINTF_L4(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
		    "cs isoc endpoint (%d.%d):\n\t"
		    "type=0x%x sub=0x%x attr=0x%x units=0x%x delay=%x",
		    interface, alternate,
		    cs_ep->bDescriptorType,
		    cs_ep->bDescriptorSubType,
		    cs_ep->bmAttributes,
		    cs_ep->bLockDelayUnits,
		    cs_ep->wLockDelay);

		uasp->usb_as_alts[alternate].alt_cs_ep = cs_ep;

		/* we are done */
		uasp->usb_as_alts[alternate].alt_valid++;
	}

done:
	usb_as_prepare_registration_data(uasp);

	return (rval);
}


/*
 * usb_as_free_alts:
 *	cleanup alternate list and deallocate all descriptors
 */
static void
usb_as_free_alts(usb_as_state_t *uasp)
{
	int	alt;
	usb_as_alt_descr_t *altp;

	if (uasp->usb_as_alts) {
		for (alt = 0; alt < uasp->usb_as_n_alternates; alt++) {
			altp = &uasp->usb_as_alts[alt];
			if (altp) {
				if (altp->alt_sample_rates) {
					kmem_free(altp->alt_sample_rates,
					    altp->alt_n_sample_rates *
					    sizeof (uint_t));
				}
				if (altp->alt_if) {
					kmem_free(altp->alt_if,
					    sizeof (usb_if_descr_t));
				}
				if (altp->alt_general) {
					kmem_free(altp->alt_general,
					    sizeof (usb_audio_as_if_descr_t));
				}
				if (altp->alt_format) {
					kmem_free(altp->alt_format,
					    altp->alt_format_len);
				}
				if (altp->alt_ep) {
					kmem_free(altp->alt_ep,
					    sizeof (usb_ep_descr_t));
				}
				if (altp->alt_cs_ep) {
					kmem_free(altp->alt_cs_ep,
					    sizeof (*altp->alt_cs_ep));
				}
			}
		}
		kmem_free(uasp->usb_as_alts, (uasp->usb_as_n_alternates) *
		    sizeof (usb_as_alt_descr_t));
	}
}


/*
 * usb_as_prepare_registration_data
 */
static void
usb_as_prepare_registration_data(usb_as_state_t   *uasp)
{
	usb_as_registration_t *reg = &uasp->usb_as_reg;
	usb_audio_type1_format_descr_t	*format;
	uchar_t n_alternates = uasp->usb_as_n_alternates;
	uchar_t channels[3];
	int alt, n, i, t;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
	    "usb_as_prepare_registration_data:");

	/* there has to be at least two alternates, ie 0 and 1	*/
	if (n_alternates < 2) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
		    "not enough alternates %d", n_alternates);

		return;
	}

	reg->reg_ifno = uasp->usb_as_ifno;
	reg->reg_mode = uasp->usb_as_alts[1].alt_mode;

	/* all endpoints need to have the same direction */
	for (alt = 2; alt < n_alternates; alt++) {
		if (!uasp->usb_as_alts[alt].alt_valid) {
			continue;
		}
		if (uasp->usb_as_alts[alt].alt_mode !=
		    reg->reg_mode) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
			    "alternates have different direction");

			return;
		}
	}

	/*
	 * we prefer that a valid format supports all our
	 * default sample rates. If not we delete sample rates
	 * to get a set that is supported by all formats.
	 *
	 * Continuous sample rate will be checked in set_format
	 * command for a particular alternate. This is interface
	 * specific registration data and not per alternate.
	 */
	reg->reg_mixer_srs.ad_srs = reg->reg_mixer_srs_list;
	reg->reg_mixer_srs.ad_limits = MIXER_SRS_FLAG_SR_LIMITS;

	/* copy over sample rate table	but zero it first */
	bzero(reg->reg_mixer_srs_list, sizeof (reg->reg_mixer_srs_list));
	bcopy(usb_as_mixer_srs, reg->reg_mixer_srs_list,
	    sizeof (usb_as_mixer_srs));

	reg->reg_compat_srs.ad_srs = reg->reg_compat_srs_list;
	reg->reg_compat_srs.ad_limits = MIXER_SRS_FLAG_SR_NOT_LIMITS;

	/* copy over sample rate table	but zero it first */
	bzero(reg->reg_compat_srs_list, sizeof (reg->reg_compat_srs_list));
	bcopy(usb_as_default_srs, reg->reg_compat_srs_list,
	    sizeof (usb_as_default_srs));

	channels[1] = channels[2] = 0;

	/*
	 * we assume that alternate 0 is not interesting (no bandwidth),
	 * we check all formats and use the formats that we can support
	 */
	for (alt = 1, n = 0; alt < n_alternates; alt++) {
		if (!uasp->usb_as_alts[alt].alt_valid) {
			continue;
		}

		format = uasp->usb_as_alts[alt].alt_format;
		if (uasp->usb_as_alts[alt].alt_valid &&
		    (n < USB_AS_N_FORMATS) &&
		    (usb_as_valid_format(uasp, alt,
		    reg->reg_compat_srs_list,
		    (sizeof (reg->reg_compat_srs_list)/
		    sizeof (uint_t)) - 1)) == USB_SUCCESS) {
			reg->reg_formats[n].fmt_termlink =
			    uasp->usb_as_alts[alt].alt_general->
			    bTerminalLink;
			reg->reg_formats[n].fmt_alt = (uchar_t)alt;
			reg->reg_formats[n].fmt_chns =
			    format->bNrChannels;
			reg->reg_formats[n].fmt_precision =
			    format->bBitResolution;
			reg->reg_formats[n++].fmt_encoding =
			    usb_audio_fmt_convert(format->bFormatType);
			/* count how many mono and stereo we have */
			channels[format->bNrChannels]++;
		}
	}

	reg->reg_n_formats = (uchar_t)n;

	if (n == 0) {
		/* no valid formats */
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
		    "zero valid formats");

		return;
	}

	/* dump what we have so far */
	for (n = 0; n < reg->reg_n_formats; n++) {
		USB_DPRINTF_L3(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
		    "format%d: alt=%d chns=%d prec=%d enc=%d", n,
		    reg->reg_formats[n].fmt_alt,
		    reg->reg_formats[n].fmt_chns,
		    reg->reg_formats[n].fmt_precision,
		    reg->reg_formats[n].fmt_encoding);
	}

	/*
	 * Fill out channels
	 * Note that we assumed all alternates have the same number
	 * of channels.
	 */
	n = 0;
	if (channels[1]) {
		reg->reg_channels[n++] = AUDIO_CHANNELS_MONO;
	}
	if (channels[2]) {
		reg->reg_channels[n] = AUDIO_CHANNELS_STEREO;
	}

	USB_DPRINTF_L3(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
	    "channels %d %d", reg->reg_channels[0], reg->reg_channels[1]);


	/* fill out combinations */
	for (i = n = 0; n < reg->reg_n_formats; n++) {
		uchar_t prec = reg->reg_formats[n].fmt_precision;
		uchar_t enc = reg->reg_formats[n].fmt_encoding;

		/* check if already there */
		for (t = 0; t < n; t++) {
			uchar_t ad_prec = reg->reg_combinations[t].ad_prec;
			uchar_t ad_enc = reg->reg_combinations[t].ad_enc;
			if ((prec == ad_prec) && (enc == ad_enc)) {
				break;
			}
		}

		/* if not, add this combination */
		if (t == n) {
			reg->reg_combinations[i].ad_prec = prec;
			reg->reg_combinations[i++].ad_enc = enc;
		}
	}


	USB_DPRINTF_L3(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
	    "combinations: %d %d %d %d %d %d %d %d",
	    reg->reg_combinations[0].ad_prec, reg->reg_combinations[0].ad_enc,
	    reg->reg_combinations[1].ad_prec, reg->reg_combinations[1].ad_enc,
	    reg->reg_combinations[2].ad_prec, reg->reg_combinations[2].ad_enc,
	    reg->reg_combinations[3].ad_prec, reg->reg_combinations[3].ad_enc);

	reg->reg_valid++;
}


/*
 * usb_as_valid_format:
 *	check if this format can be supported
 */
static int
usb_as_valid_format(usb_as_state_t *uasp, uint_t alternate,
	uint_t *srs, uint_t n_srs)
{
	int n, i, j;
	usb_as_alt_descr_t *alt_descr = &uasp->usb_as_alts[alternate];
	usb_audio_type1_format_descr_t	*format = alt_descr->alt_format;

	USB_DPRINTF_L4(PRINT_MASK_PM, uasp->usb_as_log_handle,
	    "usb_as_valid_format: %d %d %d %d %d",
	    format->bNrChannels, format->bSubFrameSize,
	    format->bBitResolution, format->bSamFreqType,
	    format->bFormatType);
	USB_DPRINTF_L4(PRINT_MASK_PM, uasp->usb_as_log_handle,
	    "alt=%d n_srs=%d", alternate, n_srs);

	switch (format->bNrChannels) {
	case 1:
	case 2:
		break;
	default:

		return (USB_FAILURE);
	}

	switch (format->bSubFrameSize) {
	case 1:
	case 2:
		break;
	default:

		return (USB_FAILURE);
	}

	switch (format->bBitResolution) {
	case 8:
	case 16:
		break;
	default:

		return (USB_FAILURE);
	}

	switch (format->bFormatType) {
	case USB_AUDIO_FORMAT_TYPE1_PCM:
		break;
	default:

		return (USB_FAILURE);
	}

	switch (format->bSamFreqType) {
	case 0:
		/* continuous */

		break;
	default:
		/* count the number of sample rates we still have */
		for (j = n = 0; j < n_srs; n++) {
			if (srs[n] == 0) {

				break;
			} else {
				j++;
			}
		}

		/* check if our preferred sample rates are supported */
		for (n = 0; n < n_srs; n++) {
			uint_t sr = srs[n];

			if (sr == 0) {
				break;
			}

			USB_DPRINTF_L4(PRINT_MASK_PM, uasp->usb_as_log_handle,
			    "checking sr=%d", sr);
			for (i = 0; i < alt_descr->alt_n_sample_rates; i++) {
				if (sr == alt_descr->alt_sample_rates[i]) {
					break;
				}
			}

			if (i == alt_descr->alt_n_sample_rates) {
				/*
				 * remove this sample rate except if it is
				 * the last one
				 */
				if (j > 1) {
					srs[n] = 0;
				} else {

					return (USB_FAILURE);
				}
			}
		}

		USB_DPRINTF_L3(PRINT_MASK_PM, uasp->usb_as_log_handle,
		    "before srs (%d): %d %d %d %d %d %d %d %d %d %d %d %d",
		    n_srs,
		    srs[0], srs[1], srs[2], srs[3], srs[4], srs[5], srs[6],
		    srs[7], srs[8], srs[9], srs[10], srs[11]);


		/* now compact srs table, eliminating zero entries */
		for (i = n = 0; n < n_srs; n++) {
			if (srs[n]) {
				/* move up & remove from the list */
				srs[i] = srs[n];
				if (i++ != n) {
					srs[n] = 0;
				}
			}
		}

		/* last entry must always be zero */
		srs[i] = 0;

		USB_DPRINTF_L3(PRINT_MASK_PM, uasp->usb_as_log_handle,
		    "before srs (%d): %d %d %d %d %d %d %d %d %d %d %d %d",
		    n_srs,
		    srs[0], srs[1], srs[2], srs[3], srs[4], srs[5], srs[6],
		    srs[7], srs[8], srs[9], srs[10], srs[11]);

		break;
	}
	return (USB_SUCCESS);
}


/*
 * convert  usb audio format type to SADA type
 */
static int
usb_audio_fmt_convert(int type)
{
	switch (type) {
	case USB_AUDIO_FORMAT_TYPE1_PCM:
		return (AUDIO_ENCODING_LINEAR);

	case USB_AUDIO_FORMAT_TYPE1_PCM8:
		return (AUDIO_ENCODING_LINEAR8);

	case USB_AUDIO_FORMAT_TYPE1_ALAW:
		return (AUDIO_ENCODING_ALAW);

	case USB_AUDIO_FORMAT_TYPE1_MULAW:
		return (AUDIO_ENCODING_ULAW);

	case USB_AUDIO_FORMAT_TYPE1_IEEE_FLOAT:
	default:
		return (0);
	}
}


/*
 * Event Management
 *
 * usb_as_disconnect_event_cb:
 *	The device has been disconnected.
 */
static int
usb_as_disconnect_event_cb(dev_info_t *dip)
{
	usb_as_state_t *uasp = (usb_as_state_t *)ddi_get_soft_state(
	    usb_as_statep, ddi_get_instance(dip));

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, uasp->usb_as_log_handle,
	    "usb_as_disconnect_event_cb: dip=0x%p", (void *)dip);

	(void) usb_serialize_access(uasp->usb_as_ser_acc, USB_WAIT, 0);

	mutex_enter(&uasp->usb_as_mutex);
	uasp->usb_as_dev_state = USB_DEV_DISCONNECTED;
	mutex_exit(&uasp->usb_as_mutex);

	usb_release_access(uasp->usb_as_ser_acc);

	return (USB_SUCCESS);
}


/*
 * usb_as_cpr_suspend:
 */
static int
usb_as_cpr_suspend(dev_info_t *dip)
{
	usb_as_state_t *uasp = (usb_as_state_t *)ddi_get_soft_state(
	    usb_as_statep, ddi_get_instance(dip));

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, uasp->usb_as_log_handle,
	    "usb_as_cpr_suspend: Begin");

	(void) usb_serialize_access(uasp->usb_as_ser_acc, USB_WAIT, 0);

	mutex_enter(&uasp->usb_as_mutex);
	uasp->usb_as_dev_state = USB_DEV_SUSPENDED;
	mutex_exit(&uasp->usb_as_mutex);

	usb_release_access(uasp->usb_as_ser_acc);

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_cpr_suspend: End");

	return (USB_SUCCESS);
}


/*
 * usb_as_reconnect_event_cb:
 *	The device was disconnected but this instance not detached, probably
 *	because the device was busy.
 *	if the same device, continue with restoring state
 */
static int
usb_as_reconnect_event_cb(dev_info_t *dip)
{
	usb_as_state_t *uasp = (usb_as_state_t *)ddi_get_soft_state(
	    usb_as_statep, ddi_get_instance(dip));

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, uasp->usb_as_log_handle,
	    "usb_as_reconnect_event_cb: dip=0x%p", (void *)dip);

	(void) usb_serialize_access(uasp->usb_as_ser_acc, USB_WAIT, 0);

	mutex_enter(&uasp->usb_as_mutex);
	usb_as_restore_device_state(dip, uasp);
	mutex_exit(&uasp->usb_as_mutex);

	usb_release_access(uasp->usb_as_ser_acc);

	return (USB_SUCCESS);
}


/*
 * usb_as_cpr_resume:
 *	recover this device from suspended state
 */
static void
usb_as_cpr_resume(dev_info_t *dip)
{
	usb_as_state_t *uasp = (usb_as_state_t *)ddi_get_soft_state(
	    usb_as_statep, ddi_get_instance(dip));

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, uasp->usb_as_log_handle,
	    "usb_as_cpr_resume: dip=0x%p", (void *)dip);

	(void) usb_serialize_access(uasp->usb_as_ser_acc, USB_WAIT, 0);

	mutex_enter(&uasp->usb_as_mutex);
	usb_as_restore_device_state(dip, uasp);
	mutex_exit(&uasp->usb_as_mutex);

	usb_release_access(uasp->usb_as_ser_acc);
}


/*
 * usb_as_restore_device_state:
 *	Set original configuration of the device
 *	enable wrq - this starts new transactions on the control pipe
 */
static void
usb_as_restore_device_state(dev_info_t *dip, usb_as_state_t *uasp)
{
	usb_as_power_t	*uaspm;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
	    "usb_as_restore_device_state:");

	ASSERT(mutex_owned(&uasp->usb_as_mutex));

	uaspm = uasp->usb_as_pm;

	/* Check if we are talking to the same device */
	mutex_exit(&uasp->usb_as_mutex);
	usb_as_pm_busy_component(uasp);
	(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

	if (usb_check_same_device(dip, uasp->usb_as_log_handle, USB_LOG_L0,
	    PRINT_MASK_ALL, USB_CHK_BASIC|USB_CHK_CFG, NULL) != USB_SUCCESS) {
		usb_as_pm_idle_component(uasp);

		/* change the device state from suspended to disconnected */
		mutex_enter(&uasp->usb_as_mutex);
		uasp->usb_as_dev_state = USB_DEV_DISCONNECTED;

		return;
	}
	mutex_enter(&uasp->usb_as_mutex);

	if (uaspm) {
		if (uaspm->aspm_wakeup_enabled) {
			mutex_exit(&uasp->usb_as_mutex);
			if (usb_handle_remote_wakeup(uasp->usb_as_dip,
			    USB_REMOTE_WAKEUP_ENABLE)) {
				USB_DPRINTF_L2(PRINT_MASK_ALL,
				    uasp->usb_as_log_handle,
				    "enable remote wake up failed");
			}
			mutex_enter(&uasp->usb_as_mutex);
		}
	}
	uasp->usb_as_dev_state = USB_DEV_ONLINE;

	mutex_exit(&uasp->usb_as_mutex);
	usb_as_pm_idle_component(uasp);
	mutex_enter(&uasp->usb_as_mutex);
}


static void
usb_as_pm_busy_component(usb_as_state_t *usb_as_statep)
{
	ASSERT(!mutex_owned(&usb_as_statep->usb_as_mutex));

	if (usb_as_statep->usb_as_pm != NULL) {
		mutex_enter(&usb_as_statep->usb_as_mutex);
		usb_as_statep->usb_as_pm->aspm_pm_busy++;

		USB_DPRINTF_L4(PRINT_MASK_PM, usb_as_statep->usb_as_log_handle,
		    "usb_as_pm_busy_component: %d",
		    usb_as_statep->usb_as_pm->aspm_pm_busy);

		mutex_exit(&usb_as_statep->usb_as_mutex);

		if (pm_busy_component(usb_as_statep->usb_as_dip, 0) !=
		    DDI_SUCCESS) {
			mutex_enter(&usb_as_statep->usb_as_mutex);
			usb_as_statep->usb_as_pm->aspm_pm_busy--;

			USB_DPRINTF_L2(PRINT_MASK_PM,
			    usb_as_statep->usb_as_log_handle,
			    "usb_as_pm_busy_component failed: %d",
			    usb_as_statep->usb_as_pm->aspm_pm_busy);

			mutex_exit(&usb_as_statep->usb_as_mutex);
		}
	}
}


static void
usb_as_pm_idle_component(usb_as_state_t *usb_as_statep)
{
	ASSERT(!mutex_owned(&usb_as_statep->usb_as_mutex));

	if (usb_as_statep->usb_as_pm != NULL) {
		if (pm_idle_component(usb_as_statep->usb_as_dip, 0) ==
		    DDI_SUCCESS) {
			mutex_enter(&usb_as_statep->usb_as_mutex);
			ASSERT(usb_as_statep->usb_as_pm->aspm_pm_busy > 0);
			usb_as_statep->usb_as_pm->aspm_pm_busy--;

			USB_DPRINTF_L4(PRINT_MASK_PM,
			    usb_as_statep->usb_as_log_handle,
			    "usb_as_pm_idle_component: %d",
			    usb_as_statep->usb_as_pm->aspm_pm_busy);

			mutex_exit(&usb_as_statep->usb_as_mutex);
		}
	}
}
