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
 * Audio Streams Interface Driver:
 *
 * usb_as is responsible for (1) Processing audio data messages during
 * play and record and management of isoc pipe, (2) Selecting correct
 * alternate that matches a set of parameters and management of control pipe.
 * This driver is opened by usb_ac and interacts with usb_ac synchronously
 * using ioctls. If the processing involves an async USBA command, the ioctl
 * returns after completion of the command.
 *
 * Note: When there is a play/record, usb_as calls framework routines
 * directly for data (play) or sends data to mixer (record).
 *
 * Serialization: A competing thread can't be allowed to interfere with
 * (1) pipe, (2) streams state.
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
 */
#include <sys/usb/usba/usbai_version.h>
#include <sys/usb/usba.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/audio/audio_driver.h>

#include <sys/usb/clients/audio/usb_audio.h>
#include <sys/usb/clients/audio/usb_mixer.h>
#include <sys/usb/clients/audio/usb_as/usb_as.h>
#include <sys/usb/clients/audio/usb_ac/usb_ac.h>


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

static int usb_as_open(dev_t *, int, int, cred_t *);
static int usb_as_close(dev_t, int, int, cred_t *);


/* support functions */
static void	usb_as_cleanup(dev_info_t *, usb_as_state_t *);

static int	usb_as_handle_descriptors(usb_as_state_t *);
static void	usb_as_prepare_registration_data(usb_as_state_t *);
static int	usb_as_valid_format(usb_as_state_t *, uint_t);
static void	usb_as_free_alts(usb_as_state_t *);

static void	usb_as_create_pm_components(dev_info_t *, usb_as_state_t *);
static int	usb_as_disconnect_event_cb(dev_info_t *);
static int	usb_as_reconnect_event_cb(dev_info_t *);
static int	usb_as_cpr_suspend(dev_info_t *);
static void	usb_as_cpr_resume(dev_info_t *);

static int	usb_as_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static int	usb_as_pwrlvl0(usb_as_state_t *);
static int	usb_as_pwrlvl1(usb_as_state_t *);
static int	usb_as_pwrlvl2(usb_as_state_t *);
static int	usb_as_pwrlvl3(usb_as_state_t *);
static void	usb_as_pm_busy_component(usb_as_state_t *);
static void	usb_as_pm_idle_component(usb_as_state_t *);

static void	usb_as_restore_device_state(dev_info_t *, usb_as_state_t *);
static int	usb_as_setup(usb_as_state_t *);
static void	usb_as_teardown(usb_as_state_t *);
static int	usb_as_start_play(usb_as_state_t *, usb_audio_play_req_t *);
static void	usb_as_continue_play(usb_as_state_t *);
static void	usb_as_pause_play(usb_as_state_t *);

static int	usb_as_set_format(usb_as_state_t *, usb_audio_formats_t *);
static int	usb_as_set_sample_freq(usb_as_state_t *, int);
static int	usb_as_send_ctrl_cmd(usb_as_state_t *, uchar_t, uchar_t,
			ushort_t, ushort_t, ushort_t, mblk_t *, boolean_t);

static int	usb_as_start_record(usb_as_state_t *, void *);
static int	usb_as_stop_record(usb_as_state_t *);
static void	usb_as_play_cb(usb_pipe_handle_t, usb_isoc_req_t *);
static void	usb_as_record_cb(usb_pipe_handle_t, usb_isoc_req_t *);
static void	usb_as_play_exc_cb(usb_pipe_handle_t, usb_isoc_req_t  *);
static void	usb_as_record_exc_cb(usb_pipe_handle_t, usb_isoc_req_t	*);
static int	usb_as_get_pktsize(usb_as_state_t *, usb_frame_number_t);
static void	usb_as_handle_shutdown(usb_as_state_t *);
static int	usb_as_play_isoc_data(usb_as_state_t *,
			usb_audio_play_req_t *);

/* anchor for soft state structures */
static void	*usb_as_statep;


/*
 * DDI Structures
 */

/* Entry points structure */
static struct cb_ops usb_as_cb_ops = {
	usb_as_open,		/* cb_open */
	usb_as_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	usb_as_ioctl,		/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_str */
	D_MP | D_64BIT,		/* cb_flag */
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


static usb_event_t usb_as_events = {
	usb_as_disconnect_event_cb,
	usb_as_reconnect_event_cb,
	NULL, NULL
};

/*
 * Mixer registration Management
 *	use defaults as much as possible
 */

_NOTE(SCHEME_PROTECTS_DATA("unique per call", mblk_t))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", usb_isoc_req_t))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", usb_isoc_pkt_descr))

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

	(void) snprintf(uasp->dstr, sizeof (uasp->dstr), "%s#%d",
	    ddi_driver_name(dip), instance);

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

	cv_init(&uasp->usb_as_pipe_cv, NULL, CV_DRIVER, NULL);

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
usb_as_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int		inst = USB_AS_MINOR_TO_INSTANCE(getminor(*devp));
	usb_as_state_t	*uasp = ddi_get_soft_state(usb_as_statep, inst);

	if (uasp == NULL) {

		return (ENXIO);
	}

	/* Do mux plumbing stuff */
	USB_DPRINTF_L4(PRINT_MASK_OPEN, uasp->usb_as_log_handle,
	    "usb_as_open: start");

	mutex_enter(&uasp->usb_as_mutex);

	if (uasp->usb_as_flag == USB_AS_OPEN || credp != kcred) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, uasp->usb_as_log_handle,
		    "usb_as_open:multiple opens or opens from userspace"
		    " not supported");

		mutex_exit(&uasp->usb_as_mutex);

		return (ENXIO);
	}

	/* fail open on a disconnected device */
	if (uasp->usb_as_dev_state == USB_DEV_DISCONNECTED) {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, uasp->usb_as_log_handle,
		    "usb_as_open: disconnected");
		mutex_exit(&uasp->usb_as_mutex);

		return (ENODEV);
	}

	/* Initialize state */
	uasp->usb_as_flag = USB_AS_OPEN;
	mutex_exit(&uasp->usb_as_mutex);

	/*
	 * go to full power, and remain pm_busy till close
	 */
	usb_as_pm_busy_component(uasp);
	(void) pm_raise_power(uasp->usb_as_dip, 0, USB_DEV_OS_FULL_PWR);

	USB_DPRINTF_L4(PRINT_MASK_OPEN, uasp->usb_as_log_handle,
	    "usb_as_open:done");

	return (0);
}


/*
 * usb_as_close:
 *	Close entry point for plumbing
 */
/*ARGSUSED*/
static int
usb_as_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int		inst = USB_AS_MINOR_TO_INSTANCE(getminor(dev));
	usb_as_state_t	*uasp = ddi_get_soft_state(usb_as_statep, inst);

	USB_DPRINTF_L4(PRINT_MASK_CLOSE, uasp->usb_as_log_handle,
	    "usb_as_close: inst=%d", inst);

	mutex_enter(&uasp->usb_as_mutex);
	uasp->usb_as_flag = USB_AS_DISMANTLING;
	mutex_exit(&uasp->usb_as_mutex);

	/*
	 * Avoid races with other routines.
	 * For example, if a control transfer is going on, wait
	 * for that to be completed
	 * At this point default pipe cannot be open.
	 */
	(void) usb_serialize_access(uasp->usb_as_ser_acc, USB_WAIT, 0);

	usb_release_access(uasp->usb_as_ser_acc);

	/* we can now power down */
	usb_as_pm_idle_component(uasp);

	mutex_enter(&uasp->usb_as_mutex);
	uasp->usb_as_flag = 0;
	mutex_exit(&uasp->usb_as_mutex);

	return (0);
}


/*
 *
 */
/*ARGSUSED*/
static int
usb_as_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int		inst = USB_AS_MINOR_TO_INSTANCE(getminor(dev));
	usb_as_state_t	*uasp = ddi_get_soft_state(usb_as_statep, inst);
	int		rv = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_ioctl: Begin inst=%d, cmd=0x%x, arg=0x%p",
	    inst, cmd, (void *)arg);

	if (!(mode & FKIOCTL)) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_ioctl: inst=%d, user space not supported", inst);
		return (ENXIO);
	}

	mutex_enter(&uasp->usb_as_mutex);

	switch (cmd) {
	case USB_AUDIO_MIXER_REGISTRATION:
		USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_ioctl(mixer reg): inst=%d", inst);

		/*
		 * Copy the usb_as_reg structure to the structure
		 * that usb_ac passed. Note that this is a structure
		 * assignment and not a pointer assignment!
		 */
		*(usb_as_registration_t *)arg = uasp->usb_as_reg;

		break;
	case USB_AUDIO_SET_FORMAT:
		rv = usb_as_set_format(uasp, (usb_audio_formats_t *)arg);
		break;
	case USB_AUDIO_SET_SAMPLE_FREQ:
		rv = usb_as_set_sample_freq(uasp, *(int *)arg);
		break;
	case USB_AUDIO_SETUP:
		rv = usb_as_setup(uasp);
		break;
	case USB_AUDIO_TEARDOWN:
		usb_as_teardown(uasp);
		break;
	case USB_AUDIO_START_PLAY:
		rv = usb_as_start_play(uasp, (usb_audio_play_req_t *)arg);
		break;
	case USB_AUDIO_STOP_PLAY:
	case USB_AUDIO_PAUSE_PLAY:
		usb_as_pause_play(uasp);
		break;
	case USB_AUDIO_START_RECORD:
		rv = usb_as_start_record(uasp, (void *)arg);
		break;
	case USB_AUDIO_STOP_RECORD:
		rv = usb_as_stop_record(uasp);
		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_ioctl: unknown IOCTL, cmd=%d", cmd);
		break;
	}

	mutex_exit(&uasp->usb_as_mutex);

	return (rv == USB_SUCCESS ? 0 : ENXIO);
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
usb_as_set_sample_freq(usb_as_state_t *uasp, int freq)
{
	int	alt, ep;
	mblk_t	*data;
	int	rval = USB_FAILURE;
	boolean_t ignore_errors;

	ASSERT(mutex_owned(&uasp->usb_as_mutex));

	alt = uasp->usb_as_alternate;

	uasp->usb_as_curr_sr = freq;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_set_sample_freq: inst=%d cont_sr=%d freq=%d",
	    ddi_get_instance(uasp->usb_as_dip),
	    uasp->usb_as_alts[alt].alt_continuous_sr, freq);

	ignore_errors = B_TRUE;

	ep = uasp->usb_as_alts[alt].alt_ep->bEndpointAddress;

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
		}
		mutex_enter(&uasp->usb_as_mutex);
	}
	freemsg(data);

	return (rval);
}


/*
 * usb_as_set_format:
 *	Matches channel, encoding and precision and find out
 *	the right alternate. Sets alternate interface and returns it.
 */
static int
usb_as_set_format(usb_as_state_t *uasp, usb_audio_formats_t *format)
{
	int		n;
	usb_as_registration_t *reg;
	int		alt, rval;
	uint_t		interface;

	ASSERT(mutex_owned(&uasp->usb_as_mutex));

	if (uasp->usb_as_request_count) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_set_format: failing inst=%d, rq_cnt=%d",
		    ddi_get_instance(uasp->usb_as_dip),
		    uasp->usb_as_request_count);

		return (USB_FAILURE);
	}

	reg = &uasp->usb_as_reg;
	interface = uasp->usb_as_ifno;

	uasp->usb_as_curr_format = *format;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_set_format: inst=%d, reg=0x%p, format=0x%p",
	    ddi_get_instance(uasp->usb_as_dip), (void *)reg, (void *)format);

	for (n = 0; n < reg->reg_n_formats; n++) {
		if ((format->fmt_chns == reg->reg_formats[n].fmt_chns) &&
		    (format->fmt_precision == reg->reg_formats[n].
		    fmt_precision) && (format->fmt_encoding ==
		    reg->reg_formats[n].fmt_encoding)) {
			int i;
			int n_srs = reg->reg_formats[n].fmt_n_srs;
			uint_t *srs = reg->reg_formats[n].fmt_srs;

			/* match sample rate */
			for (i = 0; i < n_srs; i++) {
				if (format->fmt_srs[0] == srs[i]) {

					break;
				}
			}

			if (i == n_srs) {

				continue;
			}

			/*
			 * Found the alternate
			 */
			uasp->usb_as_alternate = alt =
			    reg->reg_formats[n].fmt_alt;
			break;
		}
	}

	if (n >= reg->reg_n_formats) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_set_format: Didn't find a matching alt");

		return (USB_FAILURE);
	}


	USB_DPRINTF_L3(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_set_format: interface=%d alternate=%d",
	    interface, alt);

	mutex_exit(&uasp->usb_as_mutex);

	rval = usb_as_send_ctrl_cmd(uasp,
					/* bmRequestType */
	    USB_DEV_REQ_HOST_TO_DEV | USB_DEV_REQ_RCPT_IF,
	    USB_REQ_SET_IF,		/* bRequest */
	    alt,			/* wValue */
	    interface,			/* wIndex */
	    0,				/* wLength */
	    NULL, B_FALSE);

	mutex_enter(&uasp->usb_as_mutex);

	if (rval != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_set_format: set_alternate failed");
	} else {
		format->fmt_alt = (uchar_t)alt;
	}

	return (rval);
}


/*
 * usb_as_setup:
 *	Open isoc pipe. Will hang around till bandwidth
 *	is available.
 */
static int
usb_as_setup(usb_as_state_t *uasp)
{
	int alt = uasp->usb_as_alternate;
	usb_ep_descr_t *ep = (usb_ep_descr_t *)uasp->usb_as_alts[alt].alt_ep;
	int rval;


	ASSERT(mutex_owned(&uasp->usb_as_mutex));

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_setup: Begin usb_as_setup, inst=%d",
	    ddi_get_instance(uasp->usb_as_dip));


	/* Set record packet size to max packet size */
	if (uasp->usb_as_alts[alt].alt_mode == USB_AUDIO_RECORD) {
		uasp->usb_as_record_pkt_size = ep->wMaxPacketSize;
	} else {
		uasp->usb_as_record_pkt_size = 0;
	}

	if (uasp->usb_as_isoc_ph != NULL) {
		while (uasp->usb_as_request_count) {
			cv_wait(&uasp->usb_as_pipe_cv,
			    &uasp->usb_as_mutex);
		}

		/* close the isoc pipe which is opened before */
		mutex_exit(&uasp->usb_as_mutex);
		usb_pipe_close(uasp->usb_as_dip, uasp->usb_as_isoc_ph,
		    USB_FLAGS_SLEEP, NULL, (usb_opaque_t)NULL);

		mutex_enter(&uasp->usb_as_mutex);
		uasp->usb_as_isoc_ph = NULL;
	}

	ASSERT(uasp->usb_as_request_count == 0);
	mutex_exit(&uasp->usb_as_mutex);

	/* open isoc pipe, may fail if there is no bandwidth  */
	rval = usb_pipe_open(uasp->usb_as_dip, ep, &uasp->usb_as_isoc_pp,
	    USB_FLAGS_SLEEP, &uasp->usb_as_isoc_ph);

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

	mutex_enter(&uasp->usb_as_mutex);
	uasp->usb_as_audio_state = USB_AS_IDLE;
	uasp->usb_as_setup_cnt++;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_setup: End");

	return (USB_SUCCESS);
}


/*
 * usb_as_teardown
 *
 */
static void
usb_as_teardown(usb_as_state_t *uasp)
{
	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_teardown: Begin inst=%d",
	    ddi_get_instance(uasp->usb_as_dip));

	ASSERT(mutex_owned(&uasp->usb_as_mutex));

	uasp->usb_as_audio_state = USB_AS_IDLE;

	ASSERT(uasp->usb_as_isoc_ph);
	/* reset setup flag */
	uasp->usb_as_setup_cnt--;


	ASSERT(uasp->usb_as_setup_cnt == 0);

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_teardown: End");
}


/*
 * usb_as_start_play
 */
static int
usb_as_start_play(usb_as_state_t *uasp, usb_audio_play_req_t *play_req)
{
	int		n_requests;
	int		rval = USB_FAILURE;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_start_play: Begin inst=%d, req_cnt=%d",
	    ddi_get_instance(uasp->usb_as_dip), uasp->usb_as_request_count);

	ASSERT(mutex_owned(&uasp->usb_as_mutex));

	uasp->usb_as_request_samples = play_req->up_samples;
	uasp->usb_as_ahdl = play_req->up_handle;
	uasp->usb_as_audio_state = USB_AS_ACTIVE;

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
		    uasp->usb_as_request_samples, uasp->usb_as_request_count);

		/* queue up as many requests as allowed */
		for (n_requests = uasp->usb_as_request_count;
		    n_requests < USB_AS_MAX_REQUEST_COUNT; n_requests++) {
			if ((rval = usb_as_play_isoc_data(uasp, play_req)) !=
			    USB_SUCCESS) {
				break;
			}
		}
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
	int		n_requests;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_contine_play: Begin req_cnt=%d",
	    uasp->usb_as_request_count);

	ASSERT(mutex_owned(&uasp->usb_as_mutex));

	if (uasp->usb_as_dev_state == USB_DEV_DISCONNECTED) {
		usb_as_handle_shutdown(uasp);

		return;
	}

	if ((uasp->usb_as_request_count >= USB_AS_MAX_REQUEST_COUNT) ||
	    (uasp->usb_as_audio_state == USB_AS_IDLE) ||
	    (uasp->usb_as_audio_state == USB_AS_PLAY_PAUSED)) {
		USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_continue_play: nothing to do (audio_state=%d)",
		    uasp->usb_as_audio_state);
	} else {
		USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_continue_play: samples=%d requestcount=%d ",
		    uasp->usb_as_request_samples, uasp->usb_as_request_count);

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
usb_as_handle_shutdown(usb_as_state_t *uasp)
{
	void	*ahdl;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_handle_shutdown, inst=%d",
	    ddi_get_instance(uasp->usb_as_dip));

	USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_handle_shutdown: am_play_shutdown");

	uasp->usb_as_audio_state = USB_AS_IDLE;
	uasp->usb_as_pkt_count = 0;
	ahdl = uasp->usb_as_ahdl;

	mutex_exit(&uasp->usb_as_mutex);
	usb_ac_stop_play(ahdl, NULL);
	mutex_enter(&uasp->usb_as_mutex);
}


static int
usb_as_play_isoc_data(usb_as_state_t *uasp, usb_audio_play_req_t *play_req)
{
	int		rval = USB_FAILURE;

	usb_isoc_req_t *isoc_req = NULL;
	usb_audio_formats_t *format = &uasp->usb_as_curr_format;
	mblk_t		*data = NULL;
	void *	ahdl = uasp->usb_as_ahdl;
	int		precision;
	int		pkt, frame, n, n_pkts, count;
	size_t		bufsize;
	int		pkt_len[USB_AS_N_FRAMES];

	ASSERT(mutex_owned(&uasp->usb_as_mutex));

	precision = format->fmt_precision >> 3;

	frame = uasp->usb_as_pkt_count;

	/*
	 * calculate total bufsize by determining the pkt size for
	 * each frame
	 */
	for (bufsize = pkt = 0; pkt < USB_AS_N_FRAMES; pkt++) {
		pkt_len[pkt] = usb_as_get_pktsize(uasp, frame++);
		bufsize += pkt_len[pkt];
	}

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_play_isoc_data: Begin bufsize=0x%lx, inst=%d", bufsize,
	    ddi_get_instance(uasp->usb_as_dip));

	mutex_exit(&uasp->usb_as_mutex);

	if ((data = allocb(bufsize, BPRI_HI)) == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_play_isoc_data: allocb failed");
		mutex_enter(&uasp->usb_as_mutex);

		goto done;
	}

	/*
	 * restriction of Boomer: cannot call usb_ac_get_audio() in the context
	 * of start so we play a fragment of silence at first
	 */
	if (play_req != NULL) {
		bzero(data->b_wptr, bufsize);
		count = bufsize / precision;

	} else if ((count = usb_ac_get_audio(ahdl, (void *)data->b_wptr,
	    bufsize / precision)) == 0) {
		mutex_enter(&uasp->usb_as_mutex);
		if (uasp->usb_as_request_count == 0) {
			usb_as_handle_shutdown(uasp);

			/* Don't return failure for 0 bytes of data sent */
			if (play_req) {
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
		cv_signal(&uasp->usb_as_pipe_cv);
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


static void
usb_as_pause_play(usb_as_state_t *uasp)
{
	ASSERT(mutex_owned(&uasp->usb_as_mutex));

	/* this will stop the isoc request in the play callback */
	uasp->usb_as_audio_state = USB_AS_PLAY_PAUSED;
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
	cv_signal(&uasp->usb_as_pipe_cv);
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
	cv_signal(&uasp->usb_as_pipe_cv);
	usb_as_handle_shutdown(uasp);

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
usb_as_start_record(usb_as_state_t *uasp, void * ahdl)
{
	int		rval = USB_FAILURE;
	usb_isoc_req_t *isoc_req;
	ushort_t	record_pkt_size = uasp->usb_as_record_pkt_size;
	ushort_t	n_pkt = 1, pkt;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_start_record: inst=%d",
	    ddi_get_instance(uasp->usb_as_dip));

	ASSERT(mutex_owned(&uasp->usb_as_mutex));

	/*
	 * A start_record should not happen when stop polling is
	 * happening
	 */
	ASSERT(uasp->usb_as_audio_state != USB_AS_STOP_POLLING_STARTED);

	if (uasp->usb_as_audio_state == USB_AS_IDLE) {

		uasp->usb_as_ahdl = ahdl;
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
	}

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_start_record: rval=%d", rval);

	return (rval);
}


static int
usb_as_stop_record(usb_as_state_t *uasp)
{
	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_stop_record: ");
	ASSERT(mutex_owned(&uasp->usb_as_mutex));

	/* if we are disconnected, the pipe will be closed anyways */
	if (uasp->usb_as_dev_state == USB_DEV_DISCONNECTED)
		return (USB_SUCCESS);

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

		break;
	case USB_AS_STOP_POLLING_STARTED:
		/* A stop polling in progress, wait for completion and reply */
		break;
	default:
		break;
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
	void *	ahdl;
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
	precision = format->fmt_precision >> 3;

	if (uasp->usb_as_audio_state != USB_AS_IDLE) {
		for (offset = i = 0; i < isoc_req->isoc_pkts_count; i++) {
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

			usb_ac_send_audio(ahdl,
			    isoc_req->isoc_data->b_rptr + offset,
			    isoc_req->isoc_pkt_descr[i].isoc_pkt_actual_length /
			    precision);

			mutex_enter(&uasp->usb_as_mutex);
			offset += isoc_req->isoc_pkt_descr[i].isoc_pkt_length;
		}
	}

	mutex_exit(&uasp->usb_as_mutex);

	usb_free_isoc_req(isoc_req);
}

/*
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

static int
usb_as_get_pktsize(usb_as_state_t *uasp, usb_frame_number_t frameno)
{
	static uint_t	sr = 0;
	static ushort_t	pkt, cycle;
	static int	extra;
	int	pkt_size = 0;
	usb_audio_formats_t *format = &uasp->usb_as_curr_format;

	if (sr != uasp->usb_as_curr_sr) {
		/* calculate once */
		sr = uasp->usb_as_curr_sr;
		pkt = (sr + 500) / 1000;
		extra = sr % 1000;

		if (extra == 0) {
			/* sample rate is a multiple of 1000 */
			cycle = 1000;
		} else {
			/* find a common divisor of 1000 and extra */
			int m = 1000;
			int n = extra;

			while (m != n) {
				if (m > n) {
					m = m - n;
				} else {
					n = n - m;
				}
			}
			cycle = (1000 / n);
			extra = ((extra >= 500) ? (extra - 1000) : extra) / n;
		}
	}
	pkt_size = (((frameno + 1) % cycle) ?
	    pkt : (pkt + extra));
	pkt_size *= (format->fmt_precision >> 3)
	    * format->fmt_chns;

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
	usb_ctrl_setup_t setup;
	usb_cr_t cr;
	usb_cb_flags_t cf;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uasp->usb_as_log_handle,
	    "usb_as_send_ctrl_cmd: Begin bmRequestType=%d,\n\t"
	    "bRequest=%d, wValue=%d, wIndex=%d, wLength=%d, data=0x%p",
	    bmRequestType, bRequest, wValue, wIndex, wLength, (void *)data);

	setup.bmRequestType	= bmRequestType & ~USB_DEV_REQ_DEV_TO_HOST;
	setup.bRequest		= bRequest;
	setup.wValue		= wValue;
	setup.wIndex		= wIndex;
	setup.wLength		= wLength;
	setup.attrs		= 0;

	if (usb_pipe_ctrl_xfer_wait(uasp->usb_as_default_ph, &setup, &data,
	    &cr, &cf, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uasp->usb_as_log_handle,
		    "usb_as_send_ctrl_cmd: usba xfer failed (req=%d), "
		    "completion reason: 0x%x, completion flags: 0x%x",
		    bRequest, cr, cf);

		return (ignore_errors ? USB_SUCCESS: USB_FAILURE);
	}

	return (USB_SUCCESS);
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
	int				len, i, j, n, n_srs, sr, index;
	int				rval = USB_SUCCESS;
	usb_if_descr_t			*if_descr;
	usb_audio_as_if_descr_t 	*general;
	usb_audio_type1_format_descr_t	*format;
	uint_t				*sample_rates;
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

		/* is this a sane format descriptor */
		if (!((format->blength >= AUDIO_TYPE1_FORMAT_SIZE) &&
		    format->bDescriptorSubType == USB_AUDIO_AS_FORMAT_TYPE)) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    uasp->usb_as_log_handle,
			    "invalid format cs interface descr");

			kmem_free(format, len);

			continue;
		}

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

		sample_rates =
		    kmem_zalloc(n_srs * (sizeof (uint_t)), KM_SLEEP);

		/* go thru all sample rates (3 bytes) each */
		for (i = 0, j = 0, n = 0; n < n_srs; i += 3, n++) {
			sr = (format->bSamFreqs[i+2] << 16) |
			    (format->bSamFreqs[i+1] << 8) |
			    format->bSamFreqs[i];
			USB_DPRINTF_L3(PRINT_MASK_ATTA,
			    uasp->usb_as_log_handle,
			    "sr = %d", sr);
			sample_rates[n] = sr;
			if (sr != 0) {
				j++;
			}
		}

		if (j == 0) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    uasp->usb_as_log_handle,
			    "format cs interface descr has no valid rates");

			kmem_free(format, len);
			kmem_free(sample_rates, n_srs * (sizeof (uint_t)));

			continue;
		}

		uasp->usb_as_alts[alternate].alt_format_len = (uchar_t)len;

		uasp->usb_as_alts[alternate].alt_format = format;

		uasp->usb_as_alts[alternate].alt_n_sample_rates =
		    (uchar_t)n_srs;

		uasp->usb_as_alts[alternate].alt_sample_rates =
		    sample_rates;

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
		    USB_AUDIO_RECORD : USB_AUDIO_PLAY;

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
	int alt, n;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
	    "usb_as_prepare_registration_data:");

	/* there has to be at least two alternates, ie 0 and 1	*/
	if (n_alternates < 2) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
		    "not enough alternates %d", n_alternates);

		return;
	}

	reg->reg_ifno = uasp->usb_as_ifno;

	/* all endpoints need to have the same direction */
	for (alt = 1; alt < n_alternates; alt++) {
		if (!uasp->usb_as_alts[alt].alt_valid) {
			continue;
		}
		if (reg->reg_mode && uasp->usb_as_alts[alt].alt_mode !=
		    reg->reg_mode) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, uasp->usb_as_log_handle,
			    "alternates have different direction");

			return;
		}
		reg->reg_mode = uasp->usb_as_alts[alt].alt_mode;
	}

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
		    (usb_as_valid_format(uasp, alt) == USB_SUCCESS)) {
			reg->reg_formats[n].fmt_termlink =
			    uasp->usb_as_alts[alt].alt_general->
			    bTerminalLink;
			reg->reg_formats[n].fmt_alt = (uchar_t)alt;
			reg->reg_formats[n].fmt_chns =
			    format->bNrChannels;
			reg->reg_formats[n].fmt_precision =
			    format->bBitResolution;
			reg->reg_formats[n].fmt_encoding =
			    format->bFormatType;
			reg->reg_formats[n].fmt_n_srs =
			    uasp->usb_as_alts[alt].alt_n_sample_rates;
			reg->reg_formats[n++].fmt_srs =
			    uasp->usb_as_alts[alt].alt_sample_rates;
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
		    "regformats[%d]: termlink = %d, alt=%d chns=%d"
		    " prec=%d enc=%d", n,
		    reg->reg_formats[n].fmt_termlink,
		    reg->reg_formats[n].fmt_alt,
		    reg->reg_formats[n].fmt_chns,
		    reg->reg_formats[n].fmt_precision,
		    reg->reg_formats[n].fmt_encoding);
	}

	reg->reg_valid++;
}


/*
 * usb_as_valid_format:
 *	check if this format can be supported
 */
static int
usb_as_valid_format(usb_as_state_t *uasp, uint_t alternate)
{
	usb_as_alt_descr_t *alt_descr = &uasp->usb_as_alts[alternate];
	usb_audio_type1_format_descr_t	*format = alt_descr->alt_format;

	USB_DPRINTF_L4(PRINT_MASK_PM, uasp->usb_as_log_handle,
	    "usb_as_valid_format: %d %d %d %d %d",
	    format->bNrChannels, format->bSubFrameSize,
	    format->bBitResolution, format->bSamFreqType,
	    format->bFormatType);
	USB_DPRINTF_L4(PRINT_MASK_PM, uasp->usb_as_log_handle,
	    "alt=%d", alternate);

	switch (format->bNrChannels) {
	case 0:

		return (USB_FAILURE);
	default:

		break;
	}

	switch (format->bSubFrameSize) {
	case 1:
	case 2:
		break;
	default:

		return (USB_FAILURE);
	}

	switch (format->bBitResolution) {
	case USB_AUDIO_PRECISION_8:
	case USB_AUDIO_PRECISION_16:
	case USB_AUDIO_PRECISION_24:
	case USB_AUDIO_PRECISION_32:
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

	return (USB_SUCCESS);
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
