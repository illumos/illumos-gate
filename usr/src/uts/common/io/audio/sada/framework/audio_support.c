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
 * Audio Support Module
 *
 * This module is use by Audio Drivers that use the new audio driver
 * architecture. It provides common services to get and set data
 * structures used by Audio Drivers and Audio Personality Modules.
 * It provides the home for the audio_state_t structures, one per
 * audio device.
 *
 * Audio Drivers set their qinit structures to the open, close, info, put
 * and service routines in this module. Then this module determines
 * which Audio Personality Module to call to implement the read, write,
 * and ioctl semantics.
 *
 * This module supports persistent data across driver/module unloads
 * and reloads. The space_*() routines are used to save an main anchor
 * which points to a linked list of instance data structures. Each instance
 * data structure points to APM data structures for its instance. These
 * instance and APM persistent data structures are available only via the
 * main anchor.
 */

#include <sys/note.h>
#include <sys/varargs.h>
#include <sys/stream.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsun.h>
#include <sys/taskq.h>
#include <sys/audio.h>
#include <sys/audio/audio_support.h>
#include <sys/audio/audio_apm.h>
#include <sys/audio/audio_trace.h>
#include <sys/audio/impl/audio_support_impl.h>

/*
 * Solaris external defines.
 */
extern pri_t minclsyspri;

/*
 * External functions not declared in header files.
 */
extern uintptr_t space_fetch(char *key);
extern void space_free(char *key);
extern int space_store(char *key, uintptr_t ptr);

/* streams stuff */
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", copyreq))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", copyresp))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", datab))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", iocblk))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", msgb))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", queue))

/* other unshared/stable or no lock needed stuff */
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", audio_channel))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", audio_i_state))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", audio_qptr))

#ifdef DEBUG
/*
 * Global audio tracing variables
 */
audio_trace_buf_t audio_trace_buffer[AUDIO_TRACE_BUFFER_SIZE];
kmutex_t	audio_tb_lock;
size_t		audio_tb_siz = AUDIO_TRACE_BUFFER_SIZE;
int		audio_tb_pos = 0;
uint_t		audio_tb_seq = 0;
#endif

/*
 * Global hidden variables.
 */
/* for persistent memory */
static audio_inst_persist_t **audio_main_anchor = NULL;
static char *audio_key_class = AUDIO_KEY_CLASS;

static audio_inst_info_t *audio_drv_list_head;
					/* list of all registered drivers */

/* locks */
static kmutex_t audio_drv_list_lock;	/* mutex to protect driver list */
static kmutex_t audio_persist_lock;	/* mutex to protect persistent data */
_NOTE(MUTEX_PROTECTS_DATA(audio_drv_list_lock, audio_inst_info))
_NOTE(MUTEX_PROTECTS_DATA(audio_persist_lock, audio_main_anchor))
_NOTE(MUTEX_PROTECTS_DATA(audio_persist_lock, audio_inst_persist))
_NOTE(MUTEX_PROTECTS_DATA(audio_persist_lock, audio_apm_persist))

/* console message logging */
static kmutex_t audio_sup_log_lock;
static char audio_sup_log_buf[256];
_NOTE(MUTEX_PROTECTS_DATA(audio_sup_log_lock, audio_sup_log_buf))

static audio_device_t audio_device_info = {
	AUDIO_NAME,
	AUDIO_VERSION,
	AUDIO_CONFIGURATION
};

/*
 * Local Support Routine Prototypes For Audio Support Module
 */
static audio_inst_info_t *audio_sup_create_drv_entry(dev_info_t *);
static audio_inst_info_t *audio_sup_lookup_drv_entry(dev_info_t *);
static void audio_sup_free_drv_entry(dev_info_t *);
static void audio_sup_free_apm_persist(audio_state_t *, audio_apm_persist_t *);
static void audio_sup_free_inst_persist(audio_state_t *,
	audio_inst_persist_t *);
static int audio_sup_persist(audio_state_t *, char *);

static int audio_sup_wiocdata(queue_t *, mblk_t *, audio_ch_t *);
static int audio_sup_wioctl(queue_t *, mblk_t *, audio_ch_t *);

/*
 * Module Linkage Structures
 */
/* Linkage structure for loadable drivers */
static struct modlmisc audio_modlmisc = {
	&mod_miscops,		/* drv_modops */
	AUDIO_MOD_NAME,		/* drv_linkinfo */
};

static struct modlinkage audio_modlinkage =
{
	MODREV_1,		/* ml_rev */
	(void*)&audio_modlmisc,	/* ml_linkage */
	NULL			/* NULL terminates the list */
};

/*
 *  Standard loadable Module Configuration Entry Points
 */

/*
 * _init()
 *
 * Description:
 *	Driver initialization, called when module is first loaded.
 *	Global module locks are initialized here.
 * Arguments:
 *	None
 *
 * Returns:
 *	mod_install() status, see mod_install(9f)
 */
int
_init(void)
{
	int	error;

#ifdef DEBUG
	/* initialize the trace lock */
	mutex_init(&audio_tb_lock, NULL, MUTEX_DRIVER, NULL);
#endif

	/* standard linkage call */
	if ((error = mod_install(&audio_modlinkage)) != 0) {
		ATRACE_32("audiosup _init() error 1", error);
#ifdef DEBUG
		mutex_destroy(&audio_tb_lock);
#endif
		return (error);

	}

	/* init mutexes after we can't have any failures */

	/* initialize the instance list lock */
	mutex_init(&audio_drv_list_lock, NULL, MUTEX_DRIVER, NULL);
	/* log buffer mutex */
	mutex_init(&audio_sup_log_lock, NULL, MUTEX_DRIVER, NULL);

	/* persistent data mutex */
	mutex_init(&audio_persist_lock, NULL, MUTEX_DRIVER, NULL);

	ATRACE("audiosup _init() successful", 0);

	return (error);

}	/* _init() */

/*
 * _fini()
 *
 * Description
 *	Module de-initialization, called when driver is to be unloaded.
 *	Free resources that were allocated in _init().
 *
 * Arguments:
 *	None
 *
 * Returns:
 *	mod_remove() status, see mod_remove(9f)
 */
int
_fini(void)
{
	int	error;

	ATRACE("in audiosup _fini()", 0);

	/* all drivers must have unregistered */
	ASSERT(audio_drv_list_head == NULL);

	if ((error = mod_remove(&audio_modlinkage)) != 0) {
		ATRACE_32("audiosup _fini() mod_remove failed", error);

		return (error);

	}

	/* free instance list lock */
	mutex_destroy(&audio_drv_list_lock);
	/* free log lock */
	mutex_destroy(&audio_sup_log_lock);
	/* free persistent memory lock */
	mutex_destroy(&audio_persist_lock);

	ATRACE_32("audiosup _fini() successful", error);

#ifdef DEBUG
	mutex_destroy(&audio_tb_lock);
#endif

	return (0);

}	/* _fini() */

/*
 * _info()
 *
 * Description:
 *	Module information, returns information about the driver.
 *
 * Arguments:
 *	modinfo	*modinfop	Pointer to an opaque modinfo structure
 *
 * Returns:
 *	mod_info() status, see mod_info(9f)
 */
int
_info(struct modinfo *modinfop)
{
	int		rc;

	rc = mod_info(&audio_modlinkage, modinfop);

	ATRACE_32("audiosup _info() returning", rc);

	return (rc);

}	/* _info() */

/*
 * Public Audio Device Independent Driver Entry Points
 *
 * Standard Driver Entry Points
 */

/*
 * audio_sup_attach() and audio_sup_detach() are being replaced in the
 * next minor release of Solaris. Audio drivers must be modified to use
 * the new interfaces.
 */
/*ARGSUSED*/
audiohdl_t
audio_sup_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	audio_sup_reg_data_t	data;

	data.asrd_version = AUDIOSUP_VERSION;
	data.asrd_key = NULL;

	return (audio_sup_register(dip, &data));

}       /* audio_sup_attach() */

/*ARGSUSED*/
int
audio_sup_detach(audiohdl_t handle, ddi_detach_cmd_t cmd)
{
	return (audio_sup_unregister(handle));
}

/*
 * audio_sup_register()
 *
 * Description:
 *	This routine initializes structures used for an instance of an
 *	audio driver. Persistent state storage is allocated and used to
 *	store state when drivers are unloaded. This routine always allocates
 *	a very small chunk of memory for each instance which we never free.
 *
 * Arguments:
 *	dev_info_t		*dip	Ptr to the device's dev_info structure
 *	audio_sup_reg_data_t	*data	Registration data
 *
 * Returns:
 *	audiohdl_t			Handle to the audio device is successful
 *	NULL				Attach failed
 */
audiohdl_t
audio_sup_register(dev_info_t *dip, audio_sup_reg_data_t *data)
{
	audio_inst_info_t	*instp;		/* inst info pointer */
	audio_state_t		*statep;	/* instance state pointer */
	audio_ch_t		*chptr;		/* channel pointer */
	int			i;
	int			sup_chs;

	ATRACE("in audio_sup_register() dip", dip);
	ATRACE("audio_sup_register() version", data->asrd_version);

	/* make sure we have a supported version */
	if (data->asrd_version != AUDIOSUP_VERSION) {
		ATRACE("audio_sup_register() bad version", data->asrd_version);
		audio_sup_log(NULL, CE_WARN, "unsupported version: %d",
		    data->asrd_version);
		return (NULL);
	}

	/* minors per inst - reserved audio channels */
	sup_chs = AUDIO_MINOR_PER_INST - AUDIO_NUM_DEVS;
	ATRACE_32("audio_sup_register() supported channels per device",
	    sup_chs);

	/* register and get device instance number */
	if ((instp = audio_sup_create_drv_entry(dip)) == NULL) {
		ATRACE("audio_sup_register() "
		    "audio_sup_create_drv_entry() failed", 0);

		return (NULL);
	}

	statep = &instp->ail_state;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*statep))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*chptr))

	/*
	 * WARNING: From here on all error returns must worry about the
	 *	driver list.
	 *
	 * Initialize the instance mutex and condition variables. Used to
	 * allocate channels.
	 */
	mutex_init(&statep->as_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&statep->as_cv, NULL, CV_DRIVER, NULL);

	/* initialize other state information */
	statep->as_dip = dip;
	statep->as_dev_instance = ddi_get_instance(dip);
	statep->as_major = ddi_driver_major(dip);
	statep->as_max_chs = sup_chs;
	statep->as_minors_per_inst = AUDIO_MINOR_PER_INST;
	statep->as_audio_reserved = AUDIO_NUM_DEVS;

	/* sanity check that we can use the device */
	ASSERT((sup_chs >= AUDIO_MIN_CLONE_CHS) &&
	    (sup_chs <= AUDIO_CLONE_CHANLIM));

	/* setup persistent memory */
	if (audio_sup_persist(statep, data->asrd_key) == AUDIO_FAILURE) {
		ATRACE("audio_sup_register() couldn't set up persist mem", 0);

		goto error;
	}

	/*
	 * WARNING: From here on we cannot fail. Otherwise we would have
	 *	to loop through the channel structures and clear those CVs
	 *	and locks.
	 *
	 * Initialize the channel structures.
	 */
	ATRACE("audio_sup_register() # sup channels", sup_chs);
	for (i = 0, chptr = &statep->as_channels[0];
	    i < sup_chs; i++, chptr++) {
		/* most everything is zero, do it quickly */
		bzero(chptr, sizeof (*chptr));

		/* now do the non-zero members */
		chptr->ch_statep =		statep;
		chptr->ch_dev =			NODEV;
		chptr->ch_info.ch_number =	i;
		chptr->ch_info.dev_type =	UNDEFINED;

		mutex_init(&chptr->ch_lock, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&chptr->ch_adata_lock, NULL, MUTEX_DRIVER, NULL);
		cv_init(&chptr->ch_cv, NULL, CV_DRIVER, NULL);
	}

	ATRACE_32("audio_sup_register() returning", statep->as_dev_instance);

done:
	ATRACE("audio_sup_register() handle", statep);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*statep))
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*chptr))

	return (AUDIO_STATE2HDL(statep));

error:
	ATRACE("audio_sup_register() error", statep);

	mutex_destroy(&statep->as_lock);
	cv_destroy(&statep->as_cv);

	audio_sup_free_drv_entry(statep->as_dip);

	return (NULL);

}	/* audio_sup_register() */

/*
 * audio_sup_unregister()
 *
 * Description:
 *	This routine de-initializes structures used for an instance of the
 *	of an audio driver. It doesn't really do too much.
 *
 * Arguments:
 *	audiohdl_t		handle	Handle to the device
 *
 * Returns:
 *	AUDIO_SUCCESS			Detach successful
 *	AUDIO_FAILURE			Detach failed
 */
int
audio_sup_unregister(audiohdl_t handle)
{
	audio_state_t		*statep = AUDIO_HDL2STATE(handle);
	audio_inst_persist_t	*persistp;

	ATRACE("in audio_sup_unregister()", handle);

	/*
	 * WARNING: From here on all error returns must worry about the
	 *	instance state structures.
	 */

	/* get the state pointer for this instance */
	if ((statep = audio_sup_devinfo_to_state(statep->as_dip)) == NULL) {
		ATRACE("audio_sup_unregister() "
		    "audio_sup_devinfo_to_state() failed", 0);

		return (AUDIO_FAILURE);

	}

	/*
	 * Free the instance persistent data struct if it doesn't point to
	 * any saved data.
	 */
	mutex_enter(&statep->as_lock);
	mutex_enter(&audio_persist_lock);
	ASSERT(audio_main_anchor);

	persistp = (audio_inst_persist_t *)statep->as_persistp;

	if (persistp->amp_apmp == NULL) {
		(void) audio_sup_free_inst_persist(statep, persistp);
		statep->as_persistp = NULL;
	}

	mutex_exit(&audio_persist_lock);
	mutex_exit(&statep->as_lock);

	/* remove the dip from the instance list */
	ATRACE("audio_sup_unregister() freeing instance", statep->as_dip);
	audio_sup_free_drv_entry(statep->as_dip);

	ATRACE("audio_sup_unregister() returning", 0);

	return (AUDIO_SUCCESS);

}	/* audio_sup_unregister() */

/*
 * audio_sup_open()
 *
 * Description:
 *	This routine is called when the kernel wants to open an Audio Driver
 *	channel. It figures out what kind of device it is and calls the
 *	appropriate Audio Personality Module.
 *
 * Arguments:
 *	queue_t		*q	Pointer to the read queue
 *	dev_t		*devp	Pointer to the device
 *	int		flag	Open flags
 *	int		sflag	STREAMS flags
 *	cred_t		*credp	Pointer to the user's credential struct.
 *
 * Returns:
 *	0			Successfully opened the device
 *	errno			Error number for failed open
 */
int
audio_sup_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	audio_state_t		*statep;
	audio_apm_info_t	*apm_infop;
	audio_ch_t		*chptr;
	audio_device_type_e	type;
	int			rc;

	ATRACE("in audio_sup_open()", q);

	/* get the state structure */
	if ((statep = audio_sup_devt_to_state(*devp)) == NULL) {
		ATRACE_32(
		    "audio_sup_open() audio_sup_devt_to_state() failed", 0);

		return (ENXIO);

	}
	ATRACE("audio_sup_open() statep", statep);

	/* get the device type */
	type = audio_sup_devt_to_ch_type(statep, *devp);
	ATRACE_32("audio_sup_open() type", type);

	/* get the APM info structure */
	if ((apm_infop = audio_sup_get_apm_info(statep, type)) == NULL) {
		ATRACE_32("audio_sup_open() audio_sup_get_apm_info() failed",
		    type);

		return (ENXIO);

	}
	ATRACE("audio_sup_open() apm_infop", apm_infop);

	ASSERT(apm_infop->apm_open);

	rc = (*apm_infop->apm_open)(q, devp, flag, sflag, credp);

	if (rc == AUDIO_SUCCESS) {
		/* open was successful, make sure we've got routines */
		chptr = (audio_ch_t *)audio_sup_get_qptr_data(q);
		if (chptr == NULL ||
		    chptr->ch_wput == NULL || chptr->ch_wsvc == NULL ||
		    chptr->ch_rput == NULL || chptr->ch_rsvc == NULL) {
			ATRACE("audio_sup_open() bad open", chptr);
			/* close the device */
			(*apm_infop->apm_close)(q, flag, credp);
			rc = EIO;
		}
	}

	return (rc);

}	/* audio_sup_open() */

/*
 * audio_sup_close()
 *
 * Description:
 *	This routine is called when the kernel wants to close an Audio Driver
 *	channel. It figures out what kind of device it is and calls the
 *	appropriate Audio Personality Module.
 *
 * Arguments:
 *	queue_t		*q	Pointer to the read queue
 *	int		flag	Open flags
 *	cred_t		*credp	Pointer to the user's credential struct.
 *
 * Returns:
 *	0			Successfully closed the device
 *	errno			Error number for failed close
 */
int
audio_sup_close(queue_t *q, int flag, cred_t *credp)
{
	audio_ch_t		*chptr;

	ATRACE("in audio_sup_close()", q);

	if ((chptr = (audio_ch_t *)audio_sup_get_qptr_data(q)) == NULL) {
		ATRACE("audio_sup_close() bad chptr", 0);
		return (EIO);
	}

	ASSERT(chptr->ch_apm_infop);
	ASSERT(chptr->ch_apm_infop->apm_close);
	ATRACE("audio_sup_close() chptr->ch_apm_infop", chptr->ch_apm_infop);

	return ((*chptr->ch_apm_infop->apm_close)(q, flag, credp));

}	/* audio_sup_open() */

/*
 * audio_sup_restore_state()
 *
 * Description:
 *	Restore the state of the hardware that the specified APM controls.
 *	The specified APM is called to do the restore. It is up to that
 *	APM's restore state function to restart the hardware or not. The
 *	APM also deals with the direction. If anything keeps the state from
 *	being restored then AUDIO_FAILURE is returned. If AUDIO_ALL_DEVICES
 *	is sent then if any one APM fails the whole call fails. It is also
 *	a failure to restore an APM that doesn't have an apm_restore_state()
 *	function, which is optional.
 *
 * Arguments:
 *	audiohdl_t		handle		Device handle
 *	audio_device_type_e	device		The device to restore
 *	int			dir		The direction to restore
 *
 * Returns:
 *	AUDIO_SUCCESS				State restored
 *	AUDIO_FAILURE				State not restored
 */
int
audio_sup_restore_state(audiohdl_t handle, audio_device_type_e device, int dir)
{
	audio_state_t		*statep = AUDIO_HDL2STATE(handle);
	audio_apm_info_t	*apm_infop;
	int			found;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*apm_infop))

	ATRACE("in audio_sup_restore_state()", handle);
	ATRACE_32("audio_sup_restore_state() device", device);

	if (statep == NULL) {
		ATRACE("audio_sup_restore_state() no statep", statep);
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*apm_infop))
		return (AUDIO_FAILURE);
	}

	if ((dir & AUDIO_BOTH) == 0) {
		ATRACE_32("audio_sup_restore_state() no direction", dir);
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*apm_infop))
		return (AUDIO_FAILURE);
	}

	mutex_enter(&statep->as_lock);
	if ((apm_infop = statep->as_apm_info_list) == NULL) {
		/* nothing to restore, so this is an error */
		mutex_exit(&statep->as_lock);
		ATRACE("audio_sup_restore_state() no apm list", statep);
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*apm_infop))
		return (AUDIO_FAILURE);
	}
	mutex_exit(&statep->as_lock);

	/* go through the list looking for APMs that match this device */
	for (found = 0; apm_infop != NULL; apm_infop = apm_infop->apm_next) {
		/* does this APM match? */
		if (device != AUDIO_ALL_DEVICES &&
		    device != apm_infop->apm_type) {
			/* nope, it doesn't, so get the next one */
			ATRACE_32("audio_sup_restore_state() not this one",
			    apm_infop->apm_type);
			continue;
		}

		/* does this APM have a restore function? */
		if (apm_infop->apm_restore_state == NULL) {
			/* if AUDIO_ALL_DEVICES then it's okay to be NULL */
			if (device == AUDIO_ALL_DEVICES) {
				ATRACE("audio_sup_restore_state() NULL", 0);
				continue;
			} else {
				ATRACE("audio_sup_restore_state() fail NULL",
				    0);
				_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*apm_infop))
				return (AUDIO_FAILURE);
			}
		}

		/* this is ours, so call it */
		ATRACE("audio_sup_restore_state() calling restore",
		    apm_infop->apm_restore_state);
		if ((*apm_infop->apm_restore_state)(statep, apm_infop, dir) ==
		    AUDIO_FAILURE) {
			ATRACE("audio_sup_restore_state() restore failed",
			    apm_infop->apm_restore_state);
			_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*apm_infop))
			return (AUDIO_FAILURE);
		}
		ATRACE_32("audio_sup_restore_state() restore succeeded",
		    apm_infop->apm_type);

		/* are we done? */
		if (device != AUDIO_ALL_DEVICES) {
			/* yes, just a single device to restore */
			ATRACE_32(
			    "audio_sup_restore_state() single dev success",
			    device);
			_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*apm_infop))
			return (AUDIO_SUCCESS);
		}
	}

	/* if we specify the device then it's possible it wasn't there, so ck */
	if (device != AUDIO_ALL_DEVICES && !found) {
		ATRACE_32("audio_sup_restore_state() single device not found",
		    device);
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*apm_infop))
		return (AUDIO_FAILURE);
	}

	/*
	 * Either we found the single device or we looked at all the devices
	 * and they succeeded. Even if there wasn't a single restore function
	 * to call when AUDIO_ALL_DEVICES was specified we still succeeded.
	 */

	ATRACE_32("audio_sup_restore_state() all devices found", device);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*apm_infop))

	return (AUDIO_SUCCESS);

}	/* audio_sup_restore_state() */

/*
 * audio_sup_save_state()
 *
 * Description:
 *	Save the state of the hardware that the specified APM controls.
 *	The specified APM is called to do the save. It is up to that
 *	APM's save state function to define any interaction with the
 *	hardware. If anything keeps the state from being saved then
 *	AUDIO_FAILURE is returned. If AUDIO_ALL_DEVICES is sent then if
 *	any one APM fails the whole call fails. It is also a failure to
 *	save an APM that doesn't have an apm_save_state() function, which
 *	is optional.
 *
 * Arguments:
 *	audiohdl_t		handle		Device handle
 *	audio_device_type_e	device		The device to save
 *	int			dir		The direction to save
 *
 * Returns:
 *	AUDIO_SUCCESS				State save
 *	AUDIO_FAILURE				State not save
 */
int
audio_sup_save_state(audiohdl_t handle, audio_device_type_e device, int dir)
{
	audio_state_t		*statep = AUDIO_HDL2STATE(handle);
	audio_apm_info_t	*apm_infop;
	int			found;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*apm_infop))

	ATRACE("in audio_sup_save_state()", handle);
	ATRACE_32("audio_sup_save_state() device", device);

	if (statep == NULL) {
		ATRACE("audio_sup_save_state() no statep", statep);
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*apm_infop))
		return (AUDIO_FAILURE);
	}

	if ((dir & AUDIO_BOTH) == 0) {
		ATRACE_32("audio_sup_save_state() no direction", dir);
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*apm_infop))
		return (AUDIO_FAILURE);
	}

	mutex_enter(&statep->as_lock);
	if ((apm_infop = statep->as_apm_info_list) == NULL) {
		/* nothing to save, so this is an error */
		mutex_exit(&statep->as_lock);
		ATRACE("audio_sup_save_state() no apm list", statep);
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*apm_infop))
		return (AUDIO_FAILURE);
	}
	mutex_exit(&statep->as_lock);

	/* go through the list looking for APMs that match this device */
	for (found = 0; apm_infop != NULL; apm_infop = apm_infop->apm_next) {
		/* does this APM match? */
		if (device != AUDIO_ALL_DEVICES &&
		    device != apm_infop->apm_type) {
			/* nope, it doesn't, so get the next one */
			ATRACE_32("audio_sup_save_state() not this one",
			    apm_infop->apm_type);
			continue;
		}

		/* does this APM have a save function? */
		if (apm_infop->apm_save_state == NULL) {
			/* if AUDIO_ALL_DEVICES then it's okay to be NULL */
			if (device == AUDIO_ALL_DEVICES) {
				ATRACE("audio_sup_save_state() NULL", 0);
				continue;
			} else {
				ATRACE("audio_sup_save_state() fail NULL",
				    0);
				_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*apm_infop))
				return (AUDIO_FAILURE);
			}
		}

		/* this is ours, so call it */
		ATRACE("audio_sup_save_state() calling save",
		    apm_infop->apm_save_state);
		if ((*apm_infop->apm_save_state)(statep, apm_infop, dir) ==
		    AUDIO_FAILURE) {
			ATRACE("audio_sup_save_state() save failed",
			    apm_infop->apm_save_state);
			_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*apm_infop))
			return (AUDIO_FAILURE);
		}
		ATRACE_32("audio_sup_save_state() save succeeded",
		    apm_infop->apm_type);

		/* are we done? */
		if (device != AUDIO_ALL_DEVICES) {
			/* yes, just a single device to save */
			ATRACE_32(
			    "audio_sup_save_state() single dev success",
			    device);
			_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*apm_infop))
			return (AUDIO_SUCCESS);
		}
	}

	/* if we specify the device then it's possible it wasn't there, so ck */
	if (device != AUDIO_ALL_DEVICES && !found) {
		ATRACE_32("audio_sup_save_state() single device not found",
		    device);
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*apm_infop))
		return (AUDIO_FAILURE);
	}

	/*
	 * Either we found the single device or we looked at all the devices
	 * and they succeeded. Even if there wasn't a single save function
	 * to call when AUDIO_ALL_DEVICES was specified we still succeeded.
	 */

	ATRACE_32("audio_sup_save_state() all devices found", device);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*apm_infop))

	return (AUDIO_SUCCESS);

}	/* audio_sup_save_state() */

/*
 * audio_sup_getinfo()
 *
 * XXX this function is incorrect and should be obsoleted
 *
 * Description:
 *	Get driver information.
 *
 * Arguments:
 *	def_info_t	*dip	Pointer to the device's dev_info structure
 *				WARNING: Don't use this dev_info structure
 *	ddi_info_cmd_t	infocmd	Getinfo command
 *	void		*arg	Command specific argument
 *	void		**result Pointer to the requested information
 *
 * Returns:
 *	DDI_SUCCESS		The information could be returned
 *	DDI_FAILURE		The information couldn't be returned
 */
/*ARGSUSED*/
int
audio_sup_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	int			error;
	int			instance = 0;
	audio_state_t		*statep;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		statep = audio_sup_devt_to_state((dev_t)arg);
		if ((statep == NULL) || (statep->as_dip == NULL)) {
			error = DDI_FAILURE;
		} else {
			*result = (void *)statep->as_dip;
			error = DDI_SUCCESS;
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		instance = AUDIO_MINOR_TO_INST((dev_t)arg);
		*result = (void *)(uintptr_t)instance;

		if (*result != NULL) {
			error = DDI_SUCCESS;
		} else {
			error = DDI_FAILURE;
		}
		break;

	default:
		error = DDI_FAILURE;
		break;
	}

	return (error);

}	/* audio_sup_getinfo() */

/*
 * audio_sup_rput()
 *
 * Description:
 *	Make sure we have a valid function pointer. If we do we make the call.
 *
 *
 * Arguments:
 *	queue_t		*q	Pointer to a queue
 *	mblk_t		*mp	Ptr to the msg block being passed to the queue
 *
 * Returns:
 *	0			Always returns 0
 */
int
audio_sup_rput(queue_t *q, mblk_t *mp)
{
	audio_ch_t		*chptr;
	int			rc;

	ATRACE("in audio_sup_rput()", q);

	if ((chptr = (audio_ch_t *)audio_sup_get_qptr_data(q)) == NULL) {
		ATRACE("audio_sup_rput() bad chptr", 0);
		return (0);
	}
	ASSERT(chptr->ch_rput);

	ATRACE("audio_sup_rput() calling ch_rput()", chptr);

	rc = chptr->ch_rput(q, mp);

	ATRACE_32("audio_sup_rput() ch_rput() returned", rc);

	return (rc);

}	/* audio_sup_rput() */

/*
 * audio_sup_rsvc()
 *
 * Description:
 *	Make sure we have a valid function pointer. If we do we make the call.
 *
 * Arguments:
 *	queue_t		*q	Pointer to a queue
 *
 * Returns:
 *	0			Always returns 0
 */
int
audio_sup_rsvc(queue_t *q)
{
	audio_ch_t		*chptr;
	int			rc;

	ATRACE("in audio_sup_rsvc()", q);

	if ((chptr = (audio_ch_t *)audio_sup_get_qptr_data(q)) == NULL) {
		ATRACE("audio_sup_rsvc() null chptr", 0);
		return (0);
	}
	ASSERT(chptr->ch_rsvc);

	ATRACE("audio_sup_rsvc() calling ch_rsvc()", chptr);

	rc = chptr->ch_rsvc(q);

	ATRACE_32("audio_sup_rsvc() ch_rsvc() returned", rc);

	return (rc);

}	/* audio_sup_rsvc() */

/*
 * audio_sup_wput()
 *
 * Description:
 *	Make sure we have a valid function pointer. If we do we make the call.
 *
 *
 * Arguments:
 *	queue_t		*q	Pointer to a queue
 *	mblk_t		*mp	Ptr to the msg block being passed to the queue
 *
 * Returns:
 *	0			Always returns 0
 */
int
audio_sup_wput(queue_t *q, mblk_t *mp)
{
	audio_ch_t		*chptr;
	audio_i_state_t		*cmd;
	struct iocblk		*iocbp;
	struct copyresp		*csp;
	int			rc = 0;

	ATRACE("in audio_sup_wput()", q);

	if ((chptr = (audio_ch_t *)audio_sup_get_qptr_data(q)) == NULL) {
		ATRACE("audio_sup_close() bad chptr", 0);
		return (0);
	}
	ASSERT(chptr->ch_wput);

	/* pick off the audio support ioctls, there aren't very many */
	ATRACE_32("audio_sup_wput() type", mp->b_datap->db_type);
	switch (mp->b_datap->db_type) {

	case M_IOCTL:
		ATRACE("audio_sup_wput() IOCTL ", chptr);
		iocbp = (struct iocblk *)mp->b_rptr;	/* ptr to ioctl info */

		switch (iocbp->ioc_cmd) {
		case AUDIO_GET_CH_NUMBER:
		case AUDIO_GET_CH_TYPE:
		case AUDIO_GET_NUM_CHS:
		case AUDIO_GET_AD_DEV:
		case AUDIO_GET_APM_DEV:
		case AUDIO_GET_AS_DEV:
			ATRACE_32("audio_sup_wput() "
			    "IOCTL calling audio_sup_wioctl()", iocbp->ioc_cmd);
			rc = audio_sup_wioctl(q, mp, chptr);
			break;
		default:
			ATRACE("audio_sup_wput() IOCTL calling ch_wput()",
			    chptr);
			rc = chptr->ch_wput(q, mp);
		}
		break;
	case M_IOCDATA:
		ATRACE("audio_sup_wput() IOCDATA ", chptr);
		iocbp = (struct iocblk *)mp->b_rptr;	/* ptr to ioctl info */
		csp = (struct copyresp *)mp->b_rptr;	/* copy response ptr */
		cmd = (audio_i_state_t *)csp->cp_private; /* get state info */

		if (cmd == NULL) {
			ATRACE("audio_sup_wput() M_IOCDATA NULL cmd calling "
			    "ch_wput()", chptr);
			csp->cp_rval = 0;
			rc = chptr->ch_wput(q, mp);
			break;
		}

		switch (cmd->ais_command) {
		case AUDIO_COPY_OUT_CH_NUMBER:
		case AUDIO_COPY_OUT_CH_TYPE:
		case AUDIO_COPY_OUT_NUM_CHS:
		case AUDIO_COPY_OUT_AD_DEV:
		case AUDIO_COPY_OUT_APM_DEV:
		case AUDIO_COPY_OUT_AS_DEV:
			ATRACE_32("audio_sup_wput() "
			    "IOCDATA calling audio_sup_wiocdata()",
			    cmd->ais_command);
			rc = audio_sup_wiocdata(q, mp, chptr);
			break;
		default:
			ATRACE("audio_sup_wput() IOCDATA calling ch_wput()",
			    chptr);
			rc = chptr->ch_wput(q, mp);
		}
		break;
	default:
		ATRACE("audio_sup_wput() calling ch_wput()", chptr);
		rc = chptr->ch_wput(q, mp);
	}

	ATRACE_32("audio_sup_wput() ch_wput() returned", rc);

	return (rc);

}	/* audio_sup_wput() */

/*
 * audio_sup_wsvc()
 *
 * Description:
 *	Make sure we have a valid function pointer. If we do we make the call.
 *
 * Arguments:
 *	queue_t		*q	Pointer to a queue
 *
 * Returns:
 *	0			Always returns 0
 */
int
audio_sup_wsvc(queue_t *q)
{
	audio_ch_t		*chptr;
	int			rc;

	ATRACE("in audio_sup_wsvc()", q);

	if ((chptr = (audio_ch_t *)audio_sup_get_qptr_data(q)) == NULL) {
		ATRACE("audio_sup_wsvc() bad chptr", 0);
		return (EIO);
	}
	ASSERT(chptr->ch_wsvc);

	ATRACE("audio_sup_wsvc() calling ch_wsvc()", chptr);

	rc = chptr->ch_wsvc(q);

	ATRACE_32("audio_sup_wsvc() ch_wsvc() returned", rc);

	return (rc);

}	/* audio_sup_wsvc() */

/*
 * Public Audio Personality Module Support Routines
 *
 * Channel Routines
 */

/*
 * audio_sup_alloc_ch()
 *
 * Description:
 *	Go through the list of channels. Find the first one that isn't
 *	assigned and take it. If there aren't any channels then depending
 *	on the flags either wait for a channel to become free or return
 *	NULL
 *
 *	CAUTION: Make sure *error is always set before returning.
 *
 *	NOTE: This routine expects the Audio Personality Module to fill in
 *		all the members of the audio_ch_t structure.
 *
 * Arguments:
 *	audio_state_t		*statep	The device state structure
 *	int			*error	Error code
 *	audio_device_type_e	type	The device type
 *	int			flags	AUDIO_NO_SLEEP or AUDIO_SLEEP
 *
 * Returns:
 *	valid pointer to ch		Channel allocated
 *	NULL				Channel not allocated
 */
audio_ch_t *
audio_sup_alloc_ch(audio_state_t *statep, int *error, audio_device_type_e type,
    int flags)
{
	audio_ch_t		*chptr;
	audio_apm_info_t	*apm_infop;
	int			i;
	int			max_chs = statep->as_max_chs;
	int			rc;

	ATRACE("in audio_sup_alloc_ch()", statep);

	ASSERT((flags & (AUDIO_NO_SLEEP|AUDIO_SLEEP)) !=
	    (AUDIO_NO_SLEEP|AUDIO_SLEEP));

	/* make sure there's an apm_infop for the type */
	if ((apm_infop = audio_sup_get_apm_info(statep, type)) == NULL) {
		ATRACE("audio_sup_alloc_ch() audio_sup_get_apm_info() failed",
		    statep);
		*error = EIO;

		return (NULL);

	}

	/* find the first unused channel */
	mutex_enter(&statep->as_lock);

	/* cv_broadcast() means we may need to try many times */
	while (statep->as_ch_inuse >= max_chs) {
		/* no channels available right now, do we wait? */
		if (flags & AUDIO_NO_SLEEP) {
			/* don't wait for a channel to become free */
			mutex_exit(&statep->as_lock);
			ATRACE("audio_sup_alloc_ch() no ch return", 0);
			*error = EBUSY;

			return (NULL);

		}

		/* wait for a channel to become free */
		rc = cv_wait_sig(&statep->as_cv, &statep->as_lock);
		if (rc <= 0) {
			ATRACE("audio_sup_alloc_ch() max chs signal wakeup",
			    statep);
			/*
			 * This channel may have had a signal, but that doesn't
			 * mean any of the other channels may proceed. So make
			 * sure every channel gets another go.
			 */
			mutex_exit(&statep->as_lock);
			ATRACE("audio_sup_alloc_ch() no ch sig return", 0);
			*error = EINTR;

			return (NULL);

		}
	}

	/* we've got a channel, so find it */
	for (i = 0, chptr = &statep->as_channels[0];
	    i < max_chs; i++, chptr++) {
		mutex_enter(&chptr->ch_lock);
		if (!(chptr->ch_flags & AUDIO_CHNL_ALLOCATED)) {
			/* found it! */
			mutex_exit(&chptr->ch_lock);
			break;
		}
		mutex_exit(&chptr->ch_lock);
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*chptr))
	ASSERT(i <= max_chs);
	ASSERT(i == chptr->ch_info.ch_number);
	ASSERT(statep == chptr->ch_statep);

	ATRACE("audio_sup_alloc_ch() found channel", chptr);

	chptr->ch_info.dev_type = type;
	chptr->ch_apm_infop = apm_infop;
	chptr->ch_flags |= AUDIO_CHNL_ALLOCATED;
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*chptr))

	/* just to be sure */
	mutex_enter(&chptr->ch_adata_lock);
	chptr->ch_adata = NULL;
	chptr->ch_adata_end = NULL;
	chptr->ch_adata_cnt = 0;
	mutex_exit(&chptr->ch_adata_lock);

	statep->as_ch_inuse++;		/* inc. the number of allocated chs */

	mutex_exit(&statep->as_lock);

	ATRACE("audio_sup_alloc_ch() returning", chptr);

	*error = 0;	/* no errors */

	return (chptr);

}	/* audio_sup_alloc_ch() */

/*
 * audio_sup_free_ch()
 *
 * Description:
 *	This routine returns a channel structure to the device instance's
 *	pool of channel structures. All the various pointers must be freed
 *	and NULLed before this routine is called. It then does a cv_broadcast()
 *	to wake up any cv_wait()/cv_wait_sig() calls which might be waiting
 *	for a channel to be freed.
 *
 * Arguments:
 *	audio_ch_t	*chptr	The channel structure to free
 *
 * Returns:
 *	AUDIO_SUCCESS		No error
 *	AUDIO_FAILURE		One of the pointers is not set to NULL or
 *				chptr is not valid
 */
int
audio_sup_free_ch(audio_ch_t *chptr)
{
	audio_state_t		*statep;
	audio_apm_info_t	*apm_infop;

	ATRACE("in audio_sup_free_ch()", chptr);

	if (chptr == NULL) {
		ATRACE("audio_sup_free_ch() chptr == NULL", chptr);

		return (AUDIO_FAILURE);
	}

	statep = chptr->ch_statep;
	apm_infop = chptr->ch_apm_infop;

	ASSERT(chptr->ch_statep == statep);
	ASSERT(apm_infop != NULL);

	/* finally, clear the channel structure and make available for reuse */
	mutex_enter(&statep->as_lock);
	mutex_enter(&chptr->ch_lock);

#ifdef DEBUG
	mutex_enter(&chptr->ch_adata_lock);
	ASSERT(chptr->ch_adata_cnt == 0);
	mutex_exit(&chptr->ch_adata_lock);
#endif

	ATRACE("audio_sup_free_ch() chptr", chptr);
	ATRACE("audio_sup_free_ch() ch_private", chptr->ch_private);
	ATRACE("audio_sup_free_ch() ch_info.info", chptr->ch_info.info);

	if (chptr->ch_private) {
		ATRACE("audio_sup_free_ch() chptr->ch_private != NULL",
		    chptr->ch_private);
		mutex_exit(&chptr->ch_lock);
		mutex_exit(&statep->as_lock);
		return (AUDIO_FAILURE);

	}
	if (chptr->ch_info.info) {
		ATRACE("audio_sup_free_ch() chptr->ch_info.info != NULL",
		    chptr->ch_info.info);
		mutex_exit(&chptr->ch_lock);
		mutex_exit(&statep->as_lock);
		return (AUDIO_FAILURE);

	}

	/* free the message list */
	ATRACE("audio_sup_free_ch() freeing saved messages", chptr);
	audio_sup_flush_audio_data(chptr);

	chptr->ch_flags =		0;
	chptr->ch_info.pid =		0;

	statep->as_ch_inuse--;

	ATRACE("audio_sup_free_ch() resetting channel info", chptr);

	chptr->ch_qptr =		NULL;
	mutex_enter(&chptr->ch_adata_lock);
	chptr->ch_adata =		NULL;
	chptr->ch_adata_end =		NULL;
	chptr->ch_adata_cnt =		0;
	mutex_exit(&chptr->ch_adata_lock);
	chptr->ch_apm_infop =		NULL;
	chptr->ch_wput =		NULL;
	chptr->ch_wsvc =		NULL;
	chptr->ch_rput =		NULL;
	chptr->ch_rsvc =		NULL;
	chptr->ch_dir =			0;
	chptr->ch_dev =			NODEV;
	chptr->ch_info.dev_type =	UNDEFINED;

	mutex_exit(&chptr->ch_lock);

	/* the channel is freed, so send the broadcast */

	cv_broadcast(&statep->as_cv);

	mutex_exit(&statep->as_lock);

	ATRACE("audio_sup_free_ch() returning success", statep);

	return (AUDIO_SUCCESS);

}	/* audio_sup_free_ch() */

/*
 * Persistent Memory Routines
 */

/*
 * audio_sup_get_persist_state()
 *
 * Description:
 *	Search through the linked list of audio_apm_persist data structures
 *	for this driver instance's persistent data for the specifed audio
 *	personality module.
 *
 * Arguments:
 *	audio_state_t		*statep		Device state structure
 *	audio_device_type_e	dev_type	APM to set data for
 *
 * Returns:
 *	valid pointer			Pointer to the saved data
 *	NULL				Couldn't find the data
 */
void *
audio_sup_get_persist_state(audio_state_t *statep, audio_device_type_e dev_type)
{
	audio_inst_persist_t	*instp;
	audio_apm_persist_t	*tmp;
	void			*ret_ptr;

	ATRACE("in audio_sup_get_persist_state()", statep);
	ATRACE_32("audio_sup_get_persist_state() dev_type", dev_type);

	mutex_enter(&statep->as_lock);
	mutex_enter(&audio_persist_lock);

	ASSERT(statep->as_persistp);
	instp = statep->as_persistp;

	for (tmp = instp->amp_apmp; tmp; tmp = tmp->ap_next) {
		if (tmp->ap_apm_type == dev_type) {
			ret_ptr = tmp->ap_data;	/* make warlock happy */
			mutex_exit(&audio_persist_lock);
			mutex_exit(&statep->as_lock);
			ATRACE("audio_sup_get_persist_state() found state",
			    ret_ptr);
			return (ret_ptr);
		}
	}
	mutex_exit(&audio_persist_lock);
	mutex_exit(&statep->as_lock);

	return (NULL);

}	/* audio_sup_get_persist_state() */

/*
 * audio_sup_free_persist_state()
 *
 * Description:
 *	Search through the linked list of audio_apm_persist data structures
 *	for this driver instance's persistent data for the specifed audio
 *	personality module. When found remove it from the linked list and
 *	free it.
 *
 *	If the dev_type is set to AUDIO_ALL_DEVICES then we free all of
 *	the entries.
 *
 * Arguments:
 *	audio_state_t		*statep		Device state structure
 *	audio_device_type_e	dev_type	APM to free data for
 *
 * Returns:
 *	AUDIO_SUCCESS			Memory freed
 *	AUDIO_FAILURE			Memory not found to free
 */
int
audio_sup_free_persist_state(audio_state_t *statep,
	audio_device_type_e dev_type)
{
	audio_apm_persist_t	**plist;
	audio_apm_persist_t	*list;
	audio_apm_persist_t	*tmp;

	ATRACE("in audio_sup_free_persist_state()", statep);
	ATRACE_32("audio_sup_free_persist_state() dev_type", dev_type);

	mutex_enter(&statep->as_lock);
	mutex_enter(&audio_persist_lock);
	plist = &((audio_inst_persist_t *)statep->as_persistp)->amp_apmp;

	if (*plist == NULL) {
		/* no items on the list */
		mutex_exit(&audio_persist_lock);
		mutex_exit(&statep->as_lock);
		ATRACE("audio_sup_free_persist_state() empty list", plist);
		return (AUDIO_FAILURE);
	}

	list = *plist;

	/* see if we clear all, or just one that matches dev_type */
	if (dev_type == AUDIO_ALL_DEVICES) {
		/* clear all of them */
		ATRACE("audio_sup_free_persist_state() clear all", plist);
		while (list) {
			tmp = list;
			list = list->ap_next;
			kmem_free(tmp->ap_data, tmp->ap_size);
			kmem_free(tmp, sizeof (*tmp));
		}
		((audio_inst_persist_t *)statep->as_persistp)->amp_apmp = NULL;

		mutex_exit(&audio_persist_lock);
		mutex_exit(&statep->as_lock);

		ATRACE("audio_sup_free_persist_state() free all done", statep);

		return (AUDIO_SUCCESS);

	} else {
		/* clear just the match */
		ATRACE("audio_sup_free_persist_state() clear match", dev_type);
		while (list) {
			if (list->ap_apm_type == dev_type) {
				/* remove from the linked list */
				*plist = list->ap_next;

				ATRACE("audio_sup_free_persist_state() "
				    "freeing state", list);

				kmem_free(list->ap_data, list->ap_size);
				kmem_free(list, sizeof (*list));

				mutex_exit(&audio_persist_lock);
				mutex_exit(&statep->as_lock);
				return (AUDIO_SUCCESS);
			}
			plist = &list->ap_next;
			list = list->ap_next;
		}
	}

	mutex_exit(&audio_persist_lock);
	mutex_exit(&statep->as_lock);

	ATRACE("audio_sup_free_persist_state() not found, failed", 0);

	return (AUDIO_FAILURE);

}	/* audio_sup_free_persist_state() */

/*
 * audio_sup_set_persist_state()
 *
 * Description:
 *	Search through the list to see if we already have data for this
 *	APM type. If so then free it, then update with the new data. If
 *	the APM type isn't found then allocate an audio_apm_persist_t
 *	structure and add to the list.
 *
 * Arguments:
 *	audio_state_t		*statep		Device state structure
 *	audio_device_type_e	dev_type	APM to set data for
 *	void			*state_data	The data to save
 *	size_t			state_size	Size of the persistent data
 *
 * Returns:
 *	AUDIO_SUCCESS			Successfully set persistent state info
 *	AUDIO_FAILURE			Couldn't set persistent state info
 */
int
audio_sup_set_persist_state(audio_state_t *statep, audio_device_type_e dev_type,
	void *state_data, size_t state_size)
{
	audio_apm_persist_t	*anchor;
	audio_apm_persist_t	*tmp;

	ATRACE("in audio_sup_set_persist_state() statep", statep);
	ATRACE_32("audio_sup_set_persist_state() dev_type", dev_type);
	ATRACE("audio_sup_set_persist_state() data", state_data);
	ATRACE("audio_sup_set_persist_state() size", state_size);

	mutex_enter(&statep->as_lock);
	mutex_enter(&audio_persist_lock);

	ASSERT(statep->as_persistp);

	/* get the anchor */
	anchor = ((audio_inst_persist_t *)statep->as_persistp)->amp_apmp;

	/* look for a matching device type */
	for (tmp = anchor; tmp; tmp = tmp->ap_next) {
		if (tmp->ap_apm_type == dev_type) {
			ATRACE("audio_sup_set_persist_state() found tmp", tmp);
			break;
		}
	}

	/*
	 * If not found or first on list then allocate a new structure and
	 * place on the list.
	 */
	if (tmp == NULL) {
		/* allocate an audio_apm_persist struct */
		tmp = kmem_alloc(sizeof (*tmp), KM_SLEEP);
		tmp->ap_apm_type = dev_type;

		/* and place at the beginning of the list */
		tmp->ap_next = anchor;
		((audio_inst_persist_t *)statep->as_persistp)->amp_apmp = tmp;
	} else {
		/* we found on the list, so free old data */
		kmem_free(tmp->ap_data, tmp->ap_size);
	}

	/* update the rest of the new data structure */
	tmp->ap_data = state_data;
	tmp->ap_size = state_size;

	mutex_exit(&audio_persist_lock);
	mutex_exit(&statep->as_lock);

	ATRACE("audio_sup_set_persist_state() new return", tmp);

	return (AUDIO_SUCCESS);

}	/* audio_sup_set_persist_state() */

/*
 * Device Independent Driver Registration Routines
 */

/*
 * audio_sup_register_apm()
 *
 * Description:
 *	Register the Audio Personality Module with this instance of the
 *	Audio Driver. This provides a place to store state information
 *	for the APM.
 *
 *	We only allow one instance of an APM present for each instance of
 *	an Audio Driver.
 *
 *	NOTE: Instance and type are mandatory.
 *
 *	NOTE: It is okay for memory allocation to sleep.
 *
 * Arguments:
 *	audio_state_t	*statep		Device state structure
 *	audio_device_type_e type	APM type
 *	audio_apm_reg_t	*reg_info	Ptr to APM registration information
 *
 * Returns:
 *	valid pointer			The audio_apm_info structure registered
 *	NULL				Couldn't register the APM
 */
audio_apm_info_t *
audio_sup_register_apm(audio_state_t *statep, audio_device_type_e type,
	audio_apm_reg_t *reg_info)
{
	audio_apm_info_t	*apm_infop;
	audio_apm_info_t	*tmp_apm_infop;

	ATRACE_32("in audio_sup_register_apm()", type);

	/* make sure the registration information data structure is okay */
	if (reg_info->aar_version != AM_AAR_VERSION) {
		ATRACE("audio_sup_register_apm() bad version",
		    reg_info->aar_version);
		return (NULL);
	}

	/* we must have an open() and close() routine */
	if (reg_info->aar_apm_open == NULL || reg_info->aar_apm_close == NULL) {
		ATRACE("audio_sup_register_apm() aar_apm_open()",
		    reg_info->aar_apm_open);
		ATRACE("audio_sup_register_apm() apm_close()",
		    reg_info->aar_apm_close);

		return (NULL);

	}

	/* allocate the structure now so we won't sleep with as_lock held */
	tmp_apm_infop = kmem_zalloc(sizeof (*tmp_apm_infop), KM_SLEEP);

	/* first make sure we haven't already registered this type before */
	mutex_enter(&statep->as_lock);

	for (apm_infop = statep->as_apm_info_list; apm_infop != NULL;
	    apm_infop = apm_infop->apm_next) {
		if (apm_infop->apm_type == type) {
			mutex_exit(&statep->as_lock);
			kmem_free(tmp_apm_infop, sizeof (*tmp_apm_infop));
			ATRACE("audio_sup_register_apm() "
			    "duplicate diaudio type", 0);

			return (NULL);

		}
	}
	apm_infop = tmp_apm_infop;

	ATRACE("audio_sup_register_apm() not a duplicate, ok to continue", 0);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*apm_infop))

	mutex_init(&apm_infop->apm_lock, NULL, MUTEX_DRIVER, NULL);

	apm_infop->apm_open =		reg_info->aar_apm_open;
	apm_infop->apm_close =		reg_info->aar_apm_close;
	apm_infop->apm_restore_state =	reg_info->aar_apm_restore_state;
	apm_infop->apm_save_state =	reg_info->aar_apm_save_state;
	apm_infop->apm_info =		reg_info->aar_dev_info;
	apm_infop->apm_type =		type;
	apm_infop->apm_private =	reg_info->aar_private;
	apm_infop->apm_ad_infop =	reg_info->aar_info;
	apm_infop->apm_ad_state =	reg_info->aar_state;

	/* put at the head of the list */
	apm_infop->apm_next = statep->as_apm_info_list;
	statep->as_apm_info_list = apm_infop;

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*apm_infop))

	mutex_exit(&statep->as_lock);

	ATRACE("audio_sup_register_apm() returning successful", apm_infop);

	return (apm_infop);

}	/* audio_sup_register_apm() */

/*
 *
 * Description:
 *	Unregister the Audio Personality Module from this instance of the
 *	Audio Driver. If the APM wasn't registered we silently and
 *	successfully fail and return. Otherwise we free the structure which
 *	represents the APM. However, if the private data wasn't freed we
 *	fail.
 *
 * Arguments:
 *	audio_state_t		*statep		device state structure
 *	audio_device_type_e	type		APM type
 *
 * Returns:
 *	AUDIO_SUCCESS			APM unregistered
 *	AUDIO_FAILURE			APM private data not freed
 */
int
audio_sup_unregister_apm(audio_state_t *statep, audio_device_type_e type)
{
	audio_apm_info_t	*apm_infop;
	audio_apm_info_t	**papm_infop;

	ATRACE_32("in audio_sup_unregister_apm()", type);

	/* protect the personality module list */
	mutex_enter(&statep->as_lock);

	papm_infop = &statep->as_apm_info_list;
	apm_infop = *papm_infop;

	while (apm_infop) {
		if (apm_infop->apm_type == type) {
			break;
		}
		papm_infop = &apm_infop->apm_next;
		apm_infop = *papm_infop;
	}
	ATRACE("audio_sup_unregister_apm() while done", apm_infop);

	/* type not found on the list or the list is empty */
	if (apm_infop == NULL) {
		mutex_exit(&statep->as_lock);
		ATRACE_32("audio_sup_unregister_apm() not found on list", type);

		return (AUDIO_SUCCESS);

	}

	/* make sure the private data has been freed */
	if (apm_infop->apm_private) {
		mutex_exit(&statep->as_lock);
		ATRACE("audio_sup_unregister_apm() private data not cleared",
		    apm_infop->apm_private);

		return (AUDIO_FAILURE);

	}
	ATRACE("audio_sup_unregister_apm() ok to unreregister", apm_infop);

	/* remove the item by bypassing it */
	*papm_infop = apm_infop->apm_next;

	/* APM off the list, so okay to release the lock */
	mutex_exit(&statep->as_lock);

	ATRACE("audio_sup_unregister_apm() freeing apm_infop", apm_infop);
	mutex_destroy(&apm_infop->apm_lock);
	kmem_free(apm_infop, sizeof (*apm_infop));

	ATRACE("audio_sup_unregister_apm() done", 0);

	return (AUDIO_SUCCESS);

}	/* audio_sup_unregister_apm() */

/*
 * Audio task queue routines
 */

/*
 * audio_sup_taskq_create()
 *
 * Description:
 *	Wrapper to abstract the creation of a kernel taskq. We pick some
 *	defaults that make sense for audio, such as single threaded.
 *
 * Arguments:
 *	const char	*q_name		Name of the task queue to create
 *
 * Returns:
 *	handle				Queue successfully created
 *	NULL				Couldn't allocate structs, failed
 */
audio_taskq_t
audio_sup_taskq_create(const char *q_name)
{
	taskq_t		*tq;

	ATRACE("in audio_sup_taskq_create()", q_name);

	tq = taskq_create(q_name, AUDIO_SUP_TASKQ_NTHREADS, minclsyspri,
	    AUDIO_SUP_TASKQ_MINALLOC, AUDIO_SUP_TASKQ_MAXALLOC,
	    TASKQ_PREPOPULATE);

	ATRACE("audio_sup_taskq_create() returning", tq);

	return (AUDIO_TQHDL2AUDIOTQHDL(tq));

}	/* audio_sup_taskq_create() */

/*
 * audio_sup_taskq_destroy()
 *
 * Description:
 *	Destroy the taskq.
 *
 *	CAUTION: If the taskq is used after destroying then the system
 *		will probably panic
 *
 * Arguments:
 *	audio_taskq_t	tq_handle	Handle to the taskq to destroy
 *
 * Returns:
 *	void
 */
void
audio_sup_taskq_destroy(audio_taskq_t tq_handle)
{
	ATRACE("in audio_sup_taskq_destroy()", tq_handle);

	taskq_destroy(AUDIO_AUDIOTQHDL2TQHDL(tq_handle));

	ATRACE("audio_sup_taskq_destroy() returning", tq_handle);

}	/* audio_sup_taskq_destroy() */

/*
 * audio_sup_taskq_dispatch()
 *
 * Description:
 *	Dispatch a task. The task_function pointer must not be NULL.
 *
 * Arguments:
 *	audio_taskq_t	tq_handle	Handle to the taskq to destroy
 *	void (*)()	task_function	Ptr to the function to execute
 *	void		*arg		Ptr to argument for task_function
 *	int		sleep		KM_SLEEP or KM_NOSLEEP
 *
 * Returns:
 *	AUDIO_SUCCESS			Task scheduled
 *	AUDIO_FAILURE			Task not scheduled or bad task_function
 *					or bad sleep flags
 */
int
audio_sup_taskq_dispatch(audio_taskq_t tq_handle,
    void (*task_function)(void *arg), void *arg, int sleep)
{
	taskq_t		*tq;
	taskqid_t	tid;

	ATRACE("in audio_sup_taskq_dispatch()", tq_handle);

	if (task_function == NULL) {
		ATRACE("audio_sup_taskq_dispatch() NULL function", tq_handle);
		return (AUDIO_FAILURE);
	}

	if (sleep != KM_SLEEP && sleep != KM_NOSLEEP) {
		ATRACE_32("audio_sup_taskq_dispatch() bad sleep", sleep);
		return (AUDIO_FAILURE);
	}

	tq = AUDIO_AUDIOTQHDL2TQHDL(tq_handle);

	if ((tid = taskq_dispatch(tq, task_function, arg, sleep))) {
		ATRACE("audio_sup_taskq_dispatch() successful", tid);
		return (AUDIO_SUCCESS);
	} else {
		ATRACE("audio_sup_taskq_dispatch() failed", tid);
		return (AUDIO_FAILURE);
	}

}	/* audio_sup_taskq_dispatch() */

/*
 * audio_sup_taskq_resume()
 *
 * Description:
 *	Resume task execution.
 *
 * Arguments:
 *	audio_taskq_t	tq_handle	Handle to the taskq to wait on
 *
 * Returns:
 *	void
 */
void
audio_sup_taskq_resume(audio_taskq_t tq_handle)
{
	ATRACE("in audio_sup_taskq_resume()", tq_handle);

	taskq_resume(AUDIO_AUDIOTQHDL2TQHDL(tq_handle));

	ATRACE("audio_sup_taskq_resume() returning", tq_handle);

}	/* audio_sup_taskq_resume() */

/*
 * audio_sup_taskq_suspended()
 *
 * Description:
 *	Determine if the taskq is running or suspended.
 *
 * Arguments:
 *	audio_taskq_t	tq_handle	Handle to the taskq to wait on
 *
 * Returns:
 *	AUDIO_TASKQ_RUNNING		The taskq is running
 *	AUDIO_TASKQ_SUSPENDED		The taskq is not running (suspended)
 */
int
audio_sup_taskq_suspended(audio_taskq_t tq_handle)
{
	ATRACE("in audio_sup_taskq_suspend()", tq_handle);

	if (taskq_suspended(AUDIO_AUDIOTQHDL2TQHDL(tq_handle))) {
		ATRACE("audio_sup_taskq_suspend() returning suspended",
		    tq_handle);
		return (AUDIO_TASKQ_SUSPENDED);
	} else {
		ATRACE("audio_sup_taskq_suspend() returning running",
		    tq_handle);
		return (AUDIO_TASKQ_RUNNING);
	}

}	/* audio_sup_taskq_suspended() */

/*
 * audio_sup_taskq_suspend()
 *
 * Description:
 *	Tasks on the taskq are suspended when this routine returns.
 *	Running tasks will continue to execute, but all new tasks will
 *	be suspended.
 *
 * Arguments:
 *	audio_taskq_t	tq_handle	Handle to the taskq to wait on
 *
 * Returns:
 *	void
 */
void
audio_sup_taskq_suspend(audio_taskq_t tq_handle)
{
	ATRACE("in audio_sup_taskq_suspend()", tq_handle);

	taskq_suspend(AUDIO_AUDIOTQHDL2TQHDL(tq_handle));

	ATRACE("audio_sup_taskq_suspend() returning", tq_handle);

}	/* audio_sup_taskq_suspend() */

/*
 * audio_sup_taskq_wait()
 *
 * Description:
 *	Wait for all pending tasks to complete
 *
 * Arguments:
 *	audio_taskq_t	tq_handle	Handle to the taskq to wait on
 *
 * Returns:
 *	void
 */
void
audio_sup_taskq_wait(audio_taskq_t tq_handle)
{
	ATRACE("in audio_sup_taskq_wait()", tq_handle);

	taskq_wait(AUDIO_AUDIOTQHDL2TQHDL(tq_handle));

	ATRACE("audio_sup_taskq_wait() returning", tq_handle);

}	/* audio_sup_taskq_wait() */


/*
 * Audio Data Handling Routines
 */

/*
 * audio_sup_flush_audio_data()
 *
 * Description:
 *	Flush all the data queued up for a channel. We remain locked at
 *	all times so no one else can sneak in and grab a data structure.
 *
 * Arguments:
 *	audio_ch_t	*chptr	Pointer to the channel structure
 *
 * Returns:
 *	void
 */
void
audio_sup_flush_audio_data(audio_ch_t *chptr)
{
	audio_data_t	*tmp;

	ATRACE("in audio_sup_flush_audio_data()", chptr);

	ASSERT(mutex_owned(&chptr->ch_lock));

	mutex_enter(&chptr->ch_adata_lock);

	while ((tmp = chptr->ch_adata) != 0) {
		/* set up for next loop */
		chptr->ch_adata = tmp->adata_next;

		ATRACE("audio_sup_flush_audio_data() freeing data", tmp);
		audio_sup_free_audio_data(tmp);

		chptr->ch_adata_cnt--;
	}

	ASSERT(chptr->ch_adata_cnt == 0);

	chptr->ch_adata = NULL;
	chptr->ch_adata_end = NULL;

	mutex_exit(&chptr->ch_adata_lock);

	ATRACE("audio_sup_flush_audio_data() finished", chptr);

}	/* audio_sup_flush_audio_data() */

/*
 * audio_sup_free_audio_data()
 *
 * Description:
 *	Free the audio data.
 *
 *	NOTE: The audio data structure must already be off the list, so there
 *		isn't a need to lock the data list.
 *
 * Arguments:
 *	audio_data_t	*adata		The audio data structure to free
 *
 * Returns:
 *	void
 */
void
audio_sup_free_audio_data(audio_data_t *adata)
{
	ATRACE("in audio_sup_free_audio_data()", adata);

	if (adata == NULL) {
		ATRACE("audio_sup_free_audio_data() nothing to free", adata);

		return;

	}

	ATRACE("audio_sup_free_audio_data() adata differ, orig",
	    adata->adata_orig);
	ATRACE("audio_sup_free_audio_data() adata differ, proc",
	    adata->adata_proc);
	if (adata->adata_orig) {
		ATRACE("audio_sup_free_audio_data() freeing original data",
		    adata->adata_orig);
		kmem_free(adata->adata_orig, adata->adata_osize);
	}
	if (adata->adata_proc) {
		ATRACE("audio_sup_free_audio_data() freeing processed data",
		    adata->adata_proc);
		kmem_free(adata->adata_proc, adata->adata_psize);
	}

	ATRACE("audio_sup_free_audio_data() freeing adata structure", adata);
	kmem_free(adata, sizeof (*adata));

	ATRACE("audio_sup_free_audio_data() done", 0);

}	/* audio_sup_free_audio_data() */

/*
 * audio_sup_get_audio_data()
 *
 * Description:
 *	Get the oldest audio data structure off the channel's data list, which
 *	would be the first message.
 *
 * Arguments:
 *	audio_ch_t	*chptr		Pointer to the channel structure
 *
 * Returns:
 *	Valid audio_data_t pointer	The audio data structure
 *	NULL				No audio data available
 */
audio_data_t *
audio_sup_get_audio_data(audio_ch_t *chptr)
{
	audio_data_t	*tmp;

	ATRACE("in audio_sup_get_audio_data()", chptr);

	mutex_enter(&chptr->ch_adata_lock);

	tmp = chptr->ch_adata;

	if (tmp) {
		/* set up for next time */
		chptr->ch_adata = tmp->adata_next;

		chptr->ch_adata_cnt--;

		ASSERT(chptr->ch_adata_cnt >= 0);

		mutex_exit(&chptr->ch_adata_lock);

		ATRACE("audio_sup_get_audio_data() found data to return", tmp);

		return (tmp);

	}
	ASSERT(chptr->ch_adata_cnt == 0);

	mutex_exit(&chptr->ch_adata_lock);

	ATRACE("audio_sup_get_audio_data() NO data found", chptr);

	return (NULL);

}	/* audio_sup_get_audio_data() */

/*
 * audio_sup_get_audio_data_cnt()
 *
 * Description:
 *	Get the number of data structures currently queued on the data list.
 *
 * Arguments:
 *	audio_ch_t	*chptr		Pointer to the channel structure
 *
 * Returns:
 *	>= 0				The number of queued data structures
 */
int
audio_sup_get_audio_data_cnt(audio_ch_t *chptr)
{
	int		tmp;

	ATRACE("in audio_sup_get_audio_data_cnt()", chptr);

	mutex_enter(&chptr->ch_adata_lock);
	ASSERT(chptr->ch_adata_cnt >= 0);
	tmp = chptr->ch_adata_cnt;
	mutex_exit(&chptr->ch_adata_lock);

	ATRACE("audio_sup_get_audio_data_cnt() returning", tmp);

	return (tmp);

}	/* audio_sup_get_audio_data_cnt() */

/*
 * audio_sup_get_audio_data_size()
 *
 * Description:
 *	Get the number of bytes stored in data structures that are currently
 *	queued on the data list. Look at the proc_size if it's there and
 *	otherwise look at the orig_size.
 *
 * Arguments:
 *	audio_ch_t	*chptr		Pointer to the channel structure
 *
 * Returns:
 *	>= 0				The number of bytes queued
 */
int
audio_sup_get_audio_data_size(audio_ch_t *chptr)
{
	audio_data_t	*adata;
	int		tmp = 0;

	ATRACE("in audio_sup_get_audio_data_size()", chptr);

	/* lock the structure */
	mutex_enter(&chptr->ch_adata_lock);

	ASSERT(chptr->ch_adata_cnt >= 0);

	adata = chptr->ch_adata;
	while (adata != 0) {
		if (adata->adata_proc) {
			tmp += adata->adata_psize;
		} else {
			tmp += adata->adata_osize;
		}
		adata = adata->adata_next;
	}


	mutex_exit(&chptr->ch_adata_lock);

	ATRACE("audio_sup_get_audio_data_size() returning", tmp);

	return (tmp);

}	/* audio_sup_get_audio_data_size() */

/*
 * audio_sup_putback_audio_data()
 *
 * Description:
 *	Put the audio data structure back onto the list. It will be the first
 *	to be removed the next time audio_sup_get_audio_data() is called.
 *
 * Arguments:
 *	audio_ch_t	*chptr		Pointer to the channel structure
 *	audio_data_t	*adata		The message to put back on the list
 *
 * Returns:
 *	void
 */
void
audio_sup_putback_audio_data(audio_ch_t *chptr, audio_data_t *adata)
{
	ATRACE("in audio_sup_putback_audio_data()", chptr);

	if (adata == 0) {
		ATRACE("audio_sup_putback_audio_data() bad message pointer",
		    adata);

		return;

	}

	ATRACE("audio_sup_putback_audio_data() putting data back", adata);

	/* lock the data list */
	mutex_enter(&chptr->ch_adata_lock);

	adata->adata_next = chptr->ch_adata;

	chptr->ch_adata = adata;

	chptr->ch_adata_cnt++;

	ASSERT(chptr->ch_adata_cnt >= 1);

	mutex_exit(&chptr->ch_adata_lock);

	ATRACE("audio_sup_putback_audio_data() done", chptr);

}	/* audio_sup_putback_audio_data() */

/*
 * audio_sup_save_audio_data()
 *
 * Description:
 *	Save audio data on the channel's data list. New data is placed at
 *	the end of the list.
 *
 *	CAUTION: This routine may be called from interrupt context, so memory
 *		allocation cannot sleep.
 *
 * Arguments:
 *	audio_ch_t	*chptr		Pointer to the channel structure
 *	void		*adata_orig	Pointer to the original data to save
 *	size_t		adata_osize	Size of the original data
 *	void		*adata_proc	Pointer to the processed data to save
 *	size_t		adata_psize	Size of the processed data
 *
 * Returns:
 *	AUDIO_SUCCESS		The message was successfully saved
 *	AUDIO_FAILURE		The message was not successfully saved
 */
int
audio_sup_save_audio_data(audio_ch_t *chptr, void *adata_orig,
    size_t adata_osize, void *adata_proc, size_t adata_psize)
{
	audio_data_t	*new;

	ATRACE("in audio_sup_save_audio_data()", chptr);

	/* first we allocate an audio_data_t structure (zeros out next field) */
	if ((new = kmem_zalloc(sizeof (*new), KM_NOSLEEP)) == NULL) {
		ATRACE("audio_sup_save_audio_data() kmem_zalloc() failed", 0);

		return (AUDIO_FAILURE);

	}

	if (adata_orig) {
		new->adata_orig = adata_orig;	/* orig data from app */
		new->adata_optr = adata_orig;
		new->adata_oeptr = (char *)adata_orig + adata_osize;
		new->adata_osize = adata_osize;
	}
	if (adata_proc) {
		new->adata_proc = adata_proc;	/* the processed data */
		new->adata_pptr = adata_proc;
		new->adata_peptr = (char *)adata_proc + adata_psize;
		new->adata_psize = adata_psize;
	}

	/* now we save the message */
	mutex_enter(&chptr->ch_adata_lock);

	/* see if this is the first message */
	if (chptr->ch_adata == NULL) {		/* it is */
		ASSERT(chptr->ch_adata_cnt == 0);
		chptr->ch_adata = new;		/* next is already set to 0 */
		chptr->ch_adata_cnt = 1;
		chptr->ch_adata_end = new;
		mutex_exit(&chptr->ch_adata_lock);
		ATRACE("audio_sup_save_audio_data() first message", new);

		return (AUDIO_SUCCESS);

	}

	ATRACE("audio_sup_save_audio_data() saving message", new);

	/* append new message to list */
	chptr->ch_adata_end->adata_next = new;
	chptr->ch_adata_end = new;

	chptr->ch_adata_cnt++;

	ASSERT(chptr->ch_adata_cnt >= 1);

	mutex_exit(&chptr->ch_adata_lock);

	return (AUDIO_SUCCESS);

}	/* audio_sup_save_audio_data() */

/*
 * Minor <--> Channel Routines:
 *
 * audio_sup_ch_to_minor()
 *
 * Description:
 *	Return the minor number of the channel.
 *
 * Arguments:
 *	audio_state_t	*statep		The device state structure
 *	int		channel		The device channel
 *
 * Returns:
 *	>= 0			The minor number of the channel
 */
int
audio_sup_ch_to_minor(audio_state_t *statep, int channel)
{
	ATRACE("in audio_sup_ch_to_minor(): statep", statep);
	ATRACE_32("audio_sup_ch_to_minor(): channel #", channel);

	ATRACE_32("audio_sup_ch_to_minor() returning",
	    ((statep->as_dev_instance * statep->as_minors_per_inst) +
	    channel + statep->as_audio_reserved));

	return ((statep->as_dev_instance * statep->as_minors_per_inst) +
	    channel + statep->as_audio_reserved);

}	/* audio_sup_ch_to_minor() */

/*
 * audio_sup_get_max_chs()
 *
 * Description:
 *	Get the maximum number of supported channels per instance.
 *
 * Arguments:
 *	audiohdl_t	handle		Handle to the device
 *
 * Returns:
 *	> 0			The number of minor numbers per instance
 */
int
audio_sup_get_max_chs(audiohdl_t handle)
{
	audio_state_t	*statep = AUDIO_HDL2STATE(handle);

	ATRACE_32("in audio_sup_get_max_chs() returning",
	    statep->as_max_chs);

	return (statep->as_max_chs);

}	/* audio_sup_get_max_chs() */

/*
 * audio_sup_get_minors_per_inst()
 *
 * Description:
 *	Get the number of minor numbers allowed per instance.
 *
 * Arguments:
 *	audiohdl_t	handle		Handle to the device
 *
 * Returns:
 *	> 0			The number of minor numbers per instance
 */
int
audio_sup_get_minors_per_inst(audiohdl_t handle)
{
	audio_state_t	*statep = AUDIO_HDL2STATE(handle);

	ATRACE_32("in audio_sup_get_minors_per_inst() returning",
	    statep->as_minors_per_inst);

	return (statep->as_minors_per_inst);

}	/* audio_sup_get_minors_per_inst() */

/*
 * audio_sup_construct_minor()
 *
 * Description:
 *	construct a minor number for this dip and device type
 *
 * Arguments:
 *	audiohdl_t	handle		Handle to the device
 *	device_type_e	device_type	type of audio device the channel is
 *					associated with
 *
 * Returns:
 *	>= 0				minor node number
 */
int
audio_sup_construct_minor(audiohdl_t handle, audio_device_type_e device_type)
{
	audio_state_t	*statep = AUDIO_HDL2STATE(handle);
	dev_info_t	*dip = statep->as_dip;
	int		minors_per_inst = statep->as_minors_per_inst;
	int		minor;

	ATRACE_32("in audio_sup_construct_minor()", device_type);

	minor = (ddi_get_instance(dip) * minors_per_inst) +
	    audio_sup_type_to_minor(device_type);

	ATRACE_32("audio_sup_construct_minor() returning", minor);

	return (minor);

}	/* audio_sup_construct_minor() */

/*
 * audio_sup_minor_to_ch()
 *
 * Description:
 *	Convert a minor number to a channel number.
 *
 * Arguments:
 *	audio_state_t	*statep		The device state structure
 *	minor_t		minor		The minor number to convert
 *
 * Returns:
 *	>= 0			The channel number
 */
int
audio_sup_minor_to_ch(audio_state_t *statep, minor_t minor)
{
	int	minors_per_inst = statep->as_minors_per_inst;
	int	audio_reserved = statep->as_audio_reserved;

	ATRACE_32("in audio_sup_minor_to_ch()", minor);
	ATRACE_32("audio_sup_minor_to_ch() returning",
	    ((minor % minors_per_inst) - audio_reserved));

	return ((minor % minors_per_inst) - audio_reserved);

}	/* audio_sup_minor_to_ch() */

/*
 * audio_sup_type_to_minor()
 *
 * Description:
 *	Normally a macro would be used to figure out the minor number. But
 *	we don't want the Audio Driver using the Audio Support Module's
 *	macros which might change. So we provide a call that will let us
 *	change what we are doing later on if we wish.
 *
 * Arguments:
 *	audio_device_type_e	type	The device type we want the minor # of
 *
 * Returns:
 *	The device type
 *	AUDIO_FAILURE		Unrecognized audio device
 */
int
audio_sup_type_to_minor(audio_device_type_e type)
{
	int		minor;

	ATRACE_32("in audio_sup_type_to_minor()", type);

	switch (type) {
	case AUDIO:
		minor = AUDIO_MINOR_AUDIO;
		break;
	case AUDIOCTL:
		minor = AUDIO_MINOR_AUDIOCTL;
		break;
	case WTABLE:
		minor = AUDIO_MINOR_WAVE_TABLE;
		break;
	case MIDI:
		minor = AUDIO_MINOR_MIDI_PORT;
		break;
	case ATIME:
		minor = AUDIO_MINOR_TIME;
		break;
	case USER1:
		minor = AUDIO_MINOR_USER1;
		break;
	case USER2:
		minor = AUDIO_MINOR_USER2;
		break;
	case USER3:
		minor = AUDIO_MINOR_USER3;
		break;
	case UNDEFINED:
		/*FALLTHROUGH*/
	default:
		minor = AUDIO_FAILURE;
		break;
	}

	ATRACE_32("audio_sup_type_to_minor() returning minor", minor);

	return (minor);

}	/* audio_sup_type_to_minor() */

/*
 * audio_sup_devt_to_instance()
 *
 * Description:
 *	Convert a dev_t to instance
 *
 * Arguments:
 *	dev_t		dev	The device we are getting the instance for
 *
 * Returns:
 *	>= 0			The instance number
 */
int
audio_sup_devt_to_instance(dev_t devt)
{
	return (AUDIO_MINOR_TO_INST(devt));

}	/* audio_sup_devt_to_instance() */

/*
 * Miscellaneous Routines
 */

/*
 * audio_sup_devt_to_ch_type()
 *
 * Description:
 *	Given a channel's minor number figure out what kind of channel
 *	it is. This works for both the reserved minor nodes as well as
 *	the clone channels.
 *
 * Arguments:
 *	audio_state_t	*statep		The device state structure
 *	dev_t		dev		The device we are getting the type of
 *
 * Returns:
 *	The device type
 *	AUDIO_FAILURE		Couldn't get the state structure, so failed
 */
audio_device_type_e
audio_sup_devt_to_ch_type(audio_state_t *statep, dev_t dev)
{
	audio_device_type_e	type;
	minor_t			minor;
	int			minors_per_inst = statep->as_minors_per_inst;
	int			audio_reserved = statep->as_audio_reserved;

	ATRACE("in audio_sup_devt_to_ch_type()", dev);

	/* figure out the minor number given an instance */
	minor = getminor(dev) % minors_per_inst;

	if (minor < audio_reserved) {
		ATRACE_32("audio_sup_devt_to_ch_type() reserved minor",
		    minor);

		switch (minor) {
		case AUDIO_MINOR_AUDIO:
			type = AUDIO;
			break;
		case AUDIO_MINOR_AUDIOCTL:
			type = AUDIOCTL;
			break;
		case AUDIO_MINOR_WAVE_TABLE:
			type = WTABLE;
			break;
		case AUDIO_MINOR_MIDI_PORT:
			type = MIDI;
			break;
		case AUDIO_MINOR_TIME:
			type = TIME;
			break;
		case AUDIO_MINOR_USER1:
			type = USER1;
			break;
		case AUDIO_MINOR_USER2:
			type = USER2;
			break;
		case AUDIO_MINOR_USER3:
			type = USER3;
			break;
		default:
			type = UNDEFINED;
			break;
		}

		ATRACE_32("audio_sup_devt_to_ch_type() reserved, returning",
		    type);

		return (type);

	} else {
		audio_state_t	*statep;
		audio_ch_t	*chptr;

		ATRACE_32("audio_sup_devt_to_ch_type() allocated channel",
		    minor);

		if ((statep = audio_sup_devt_to_state(dev)) == NULL) {
			ATRACE("audio_sup_devt_to_ch_type() "
			    "audio_sup_devt_to_ch_type() failed", 0);

			return ((audio_device_type_e)AUDIO_FAILURE);

		}

		ATRACE("audio_sup_devt_to_ch_type() statep", statep);

		chptr = &statep->as_channels[audio_sup_minor_to_ch(
		    statep, minor)];

		ATRACE("audio_sup_devt_to_ch_type() chptr", chptr);

		ATRACE_32("audio_sup_devt_to_ch_type() returning type",
		    chptr->ch_info.dev_type);

		return (chptr->ch_info.dev_type);

	}

}	/* audio_sup_devt_to_ch_type() */

/*
 * audio_sup_get_channel_number()
 *
 * Description:
 *	Get the channel number for the audio queue.
 *
 * Arguments:
 *	queue_t		*q	Pointer to a queue structure
 *
 * Returns:
 *	channel number		The channel number for the audio queue.
 *	AUDIO_FAILURE		Bad q_ptr
 */
int
audio_sup_get_channel_number(queue_t *q)
{
	audio_ch_t		*chptr;

	ATRACE("in audio_sup_get_channel_number()", q);

	if ((chptr = (audio_ch_t *)audio_sup_get_qptr_data(q)) == NULL) {
		ATRACE("audio_sup_get_channel_number() bad chptr", 0);
		return (AUDIO_FAILURE);
	}

	ATRACE("audio_sup_get_channel_number() returning",
	    chptr->ch_info.ch_number);

	return (chptr->ch_info.ch_number);

}	/* audio_sup_get_channel_number() */

/*
 * audio_sup_get_apm_info()
 *
 * Description:
 *	Get the audio_apm_info structure for the audio instance and
 *	type passed in.
 *
 *	NOTE: Since the apm_info list is created when the driver is
 *		attached it should never change during normal operation
 *		of the audio device. Therefore we don't need to lock
 *		the list while we traverse it.
 *
 * Arguments:
 *	audio_state_t		*statep		device state structure
 *	audio_device_type_e	type		APM type
 *
 * Returns:
 *	valid pointer		Ptr to the returned audio_apm_info struct
 *	NULL			audio_apm_info struct not found
 */
audio_apm_info_t *
audio_sup_get_apm_info(audio_state_t *statep, audio_device_type_e type)
{
	audio_apm_info_t	*apm_infop;

	ATRACE("in audio_sup_get_apm_info()", statep);

	/* sanity check */
	if (type == UNDEFINED) {
		ATRACE("audio_sup_get_apm_info() returning NULL (fail)", 0);

		return (NULL);

	}

	mutex_enter(&statep->as_lock);
	apm_infop = statep->as_apm_info_list;

	while (apm_infop != NULL) {
		if (apm_infop->apm_type == type) {
			ATRACE_32("audio_sup_get_apm_info() found type", type);
			break;
		}
		apm_infop = apm_infop->apm_next;
	}

	mutex_exit(&statep->as_lock);

	/* make sure we got a structure */
	if (apm_infop == NULL) {
		ATRACE_32("audio_sup_get_apm_info() didn't find type", type);

		return (NULL);

	}

	ATRACE("audio_sup_get_apm_info() returning", apm_infop);

	return (apm_infop);

}	/* audio_sup_get_apm_info() */

/*
 * audio_sup_get_dip()
 *
 * Description:
 *	Get the dev_info_t pointer for the audio handle.
 *
 * Arguments:
 *	audiohdl_t	handle		Handle to the device
 *
 * Returns:
 *	dev_info_t *			The dip for the handle, always returned
 */
dev_info_t *
audio_sup_get_dip(audiohdl_t handle)
{

	return (AUDIO_HDL2STATE(handle)->as_dip);

}	/* audio_sup_get_dip() */

/*
 * audio_sup_get_info()
 *
 * Description:
 *	Get the info structure for the audio queue.
 *
 * Arguments:
 *	queue_t		*q	Pointer to a queue structure
 *
 * Returns:
 *	valid pointer		Ptr to the returned audio_apm_info struct
 */
void *
audio_sup_get_info(queue_t *q)
{
	audio_ch_t		*chptr;

	ATRACE("in audio_sup_get_info()", q);

	if ((chptr = (audio_ch_t *)audio_sup_get_qptr_data(q)) == NULL) {
		ATRACE("audio_sup_close() bad chptr", 0);
		return (NULL);
	}

	ATRACE("audio_sup_get_info() returning", chptr->ch_info.info);

	return (chptr->ch_info.info);

}	/* audio_sup_get_info() */


/*
 * audio_sup_mblk_alloc()
 *
 * Description:
 *	Allocate a STREAMS message block if the current block isn't there or
 *	is too small. This is placed into the continuation pointer for the
 *	passed in message block.
 *
 *	When we return the b_wptr is set to b_rptr + size;
 *
 * Arguments:
 *	mblk_t		*mp		STREAMS message block to add to
 *	size_t		size		Size of the message to allocate
 *
 * Returns:
 *	AUDIO_SUCCESS			Message block allocated
 *	AUDIO_FAILURE			Message block not allocated
 */
int
audio_sup_mblk_alloc(mblk_t *mp, size_t size)
{
	/* first the easy case, the buffer is already big enough */
	if (msgdsize(mp->b_cont) >= size) {
		mp->b_cont->b_wptr = mp->b_cont->b_rptr + size;
		return (AUDIO_SUCCESS);
	}

	/* the old message either isn't there or it's too small */
	if (mp->b_cont) {
		/* here, but too small */
		freemsg(mp->b_cont);
	}

	/* no memory leak, time to allocate the new message */
	mp->b_cont = allocb((size), BPRI_HI);
	if (mp->b_cont == NULL) {
		return (AUDIO_FAILURE);
	}

	mp->b_cont->b_wptr = mp->b_cont->b_rptr + size;

	return (AUDIO_SUCCESS);

}	/* audio_sup_mblk_alloc() */

/*
 * audio_sup_get_private()
 *
 * Description:
 *	Return the pointer to the audio driver's private state information.
 *
 * Arguments:
 *	audiohdl_t		handle		Handle to the device
 *
 * Returns:
 *	Pointer to private data, even if it's set to NULL
 */
void *
audio_sup_get_private(audiohdl_t handle)
{

	return (AUDIO_HDL2STATE(handle)->as_private);

}	/* audio_sup_get_private() */

/*
 * audio_sup_set_private()
 *
 * Description:
 *	Set the audio driver's private state in the audio handle. It may
 *	be reset at any time.
 *
 * Arguments:
 *	audiohdl_t		handle		Handle to the device
 *	void			*private	Audio driver's private data
 *
 * Returns:
 *	void
 */
void
audio_sup_set_private(audiohdl_t handle, void *private)
{
	AUDIO_HDL2STATE(handle)->as_private = private;

}	/* audio_sup_set_private() */

/*
 * audio_sup_log()
 *
 * Description:
 *	similar to cmn_err but prefixes the message with
 *	<drivername><instance>:
 *
 * Arguments:
 *	audiohdl_t	handle		May be NULL in which case it behaves as
 *					cmn_err()
 *	uint_t		level		A constant indicating the severity
 *	char		*format		The message to be displayed
 *
 * NOTE: ? ! ^ should work as expected
 */
void
audio_sup_log(audiohdl_t handle, uint_t level, char *fmt, ...)
{
	va_list		ap;
	audio_state_t	*statep = AUDIO_HDL2STATE(handle);
	int		n = 0;
	int		skip = 0;

	mutex_enter(&audio_sup_log_lock);

	if (statep) {
		dev_info_t 	*dip = statep->as_dip;

		switch (fmt[0]) {
		case '?':
		case '!':
		case '^':
			audio_sup_log_buf[0] = fmt[n++];
			skip++;
			break;
		default:
			break;
		}

		(void) sprintf(&audio_sup_log_buf[n], "%s%d: ",
		    ddi_driver_name(dip), ddi_get_instance(dip));

		n = strlen(audio_sup_log_buf);
	}

	va_start(ap, fmt);
	(void) vsprintf(&audio_sup_log_buf[n], &fmt[skip], ap);
	va_end(ap);
	cmn_err(level, audio_sup_log_buf);

	ATRACE(audio_sup_log_buf, 0);

	mutex_exit(&audio_sup_log_lock);

}	/* audio_sup_log() */

/*
 * audio_sup_update_persist_key()
 *
 * Description:
 *	Update the persistent key to a new value. Memory is freed from the old
 *	key and allocated for the new key.
 *
 * Arguments:
 *	dev_info_t	*dip		dev_info_t pointer for the device
 *	char		*key		Pointer to the new key string
 *	int		sleep_okay	Non-zero if okay to sleep on mem. alloc.
 *
 * Returns:
 *	AUDIO_SUCCESS			Key successfully updated to new key
 *	AUDIO_FAILURE			Memory allocation failed, dip not found
 */
int
audio_sup_update_persist_key(dev_info_t *dip, char *key, int sleep_okay)
{
	audio_inst_persist_t	*tptr;
	char			*new_key;
	size_t			key_length;
	major_t			major = ddi_driver_major(dip);
	int			instance = ddi_get_instance(dip);

	ATRACE("in audio_sup_update_persist_key()", key);

	/* see audio_sup_persist() for an explaination on keys */
	if (key == NULL) {
		ATRACE("audio_sup_update_persist_key() NULL key", key);
		return (AUDIO_FAILURE);
	}

	key_length = strlen(audio_key_class);
	key_length += strlen(key);
	key_length++;	/* make room for NULL at end of string */

	if (sleep_okay) {
		new_key = kmem_alloc(key_length, KM_SLEEP);
	} else {
		new_key = kmem_alloc(key_length, KM_NOSLEEP);
		if (new_key == NULL) {
			ATRACE("audio_sup_update_persist_key() no memory", key);
			return (AUDIO_FAILURE);
		}
	}

	(void) sprintf(new_key, "%s%s", audio_key_class, key);
	ATRACE("audio_sup_update_persist_key() key string", new_key);

	/*
	 * Find our dip, we do this after getting the key so we hold the
	 * locks for as short a time as possible.
	 */
	mutex_enter(&audio_persist_lock);
	ASSERT(audio_main_anchor);
	for (tptr = *audio_main_anchor; tptr; tptr = tptr->amp_next) {
		if (tptr->amp_major == major &&
		    tptr->amp_instance == instance) {
			break;
		}
	}
	if (tptr == NULL) {
		kmem_free(new_key, key_length);
		mutex_exit(&audio_persist_lock);
		ATRACE("audio_sup_update_persist_key() dip not found", dip);
		return (AUDIO_FAILURE);
	}

	ATRACE("audio_sup_update_persist_key() dip found", dip);
	kmem_free(tptr->amp_key, strlen(tptr->amp_key)+1);
	tptr->amp_key = new_key;

	mutex_exit(&audio_persist_lock);

	ATRACE("audio_sup_update_persist_key() done", new_key);

	return (AUDIO_SUCCESS);


}	/* audio_sup_update_persist_key() */

/*
 * STREAMS Private Data Routines
 */

/*
 * audio_sup_set_qptr()
 *
 * Description:
 *	Allocate an audio_qptr structure to hold the private STREAM data
 *	structure. Then set the values and point both the RD() and WR()
 *	STREAMS queues to this data structure. That way it'll be available
 *	regardless of which direction the queue may be pointed.
 *
 * NOTE: open() and close() use the read queue, which is why we put it on
 *	both the read and write side.
 *
 * Arguments:
 *	queue_t		*q	Pointer to the STREAMS queue
 *	dev_t		dev	Device name
 *	void		*data	Pointer to the private data
 *
 * Returns:
 *	void
 */
void
audio_sup_set_qptr(queue_t *q, dev_t dev, void *data)
{
	audio_qptr_t		*tmp;

	ATRACE("in audio_sup_set_qptr()", q);

	tmp = (audio_qptr_t *)kmem_alloc(sizeof (audio_qptr_t), KM_SLEEP);

	tmp->aq_dev = dev;
	tmp->aq_data = data;

	RD(q)->q_ptr = (caddr_t)tmp;
	WR(q)->q_ptr = (caddr_t)tmp;

	ATRACE("audio_sup_set_qptr() done", tmp);

}	/* audio_sup_set_qptr() */

/*
 * audio_sup_free_qptr()
 *
 * Description:
 *	Free the private STREAMS data structure.
 *
 * Arguments:
 *	queue_t		*q	Pointer to the STREAMS queue
 *
 * Returns:
 *	void
 */
void
audio_sup_free_qptr(queue_t *q)
{
	ATRACE("in audio_sup_free_qptr()", q);

	kmem_free(q->q_ptr, sizeof (audio_qptr_t));

	RD(q)->q_ptr = NULL;
	WR(q)->q_ptr = NULL;

	ATRACE("audio_sup_free_qptr() done", q);

}	/* audio_sup_free_qptr() */

/*
 * audio_sup_get_qptr_dev()
 *
 * Description:
 *	Get the device info from the private data.
 *
 * Arguments:
 *	queue_t		*q	Pointer to the STREAMS queue
 *
 * Returns:
 *	The dev_t that was saved
 */
dev_t
audio_sup_get_qptr_dev(queue_t *q)
{
	audio_qptr_t		*tmp;

	ATRACE("in audio_sup_get_qptr_dev()", q);

	/* make sure the q_ptr is valid */
	if (q->q_ptr == NULL) {
		ATRACE("audio_sup_get_qptr_dev() null q_ptr", NULL);
		return (NULL);
	}

	tmp = (audio_qptr_t *)q->q_ptr;

	ATRACE("audio_sup_get_qptr_dev() dev_t", tmp->aq_dev);

	return (tmp->aq_dev);

}	/* audio_sup_get_qptr_dev() */

/*
 * audio_sup_get_qptr_data()
 *
 * Description:
 *	Get the data info from the private data.
 *
 * Arguments:
 *	queue_t		*q	Pointer to the STREAMS queue
 *
 * Returns:
 *	Pointer to the private data.
 */
void *
audio_sup_get_qptr_data(queue_t *q)
{
	audio_qptr_t		*tmp;

	ATRACE("in audio_sup_get_qptr_data()", q);

	/* make sure the q_ptr is valid */
	if (q->q_ptr == NULL) {
		ATRACE("audio_sup_get_qptr_data() null q_ptr", NULL);
		return (NULL);
	}

	tmp = (audio_qptr_t *)q->q_ptr;

	ATRACE("audio_sup_get_qptr_data() done, data", tmp->aq_data);

	return (tmp->aq_data);

}	/* audio_sup_get_qptr_data() */

/*
 * audio_sup_get_qptr_instance()
 *
 * Description:
 *	Get the instance number from the private data's dev_t.
 *
 * Arguments:
 *	queue_t		*q	Pointer to the STREAMS queue
 *
 * Returns:
 *	>= 0			The instance number
 */
int
audio_sup_get_qptr_instance(queue_t *q)
{
	dev_t		dev = audio_sup_get_qptr_dev(q);
	audio_state_t	*statep = audio_sup_devt_to_state(dev);
	int		minor = getminor(dev);
	int		instance;

	instance = minor / audio_sup_get_minors_per_inst(
	    AUDIO_STATE2HDL(statep));

	ATRACE("in audio_sup_get_qptr_instance()", q);
	ATRACE_32("in audio_sup_get_qptr_instance() returning", instance);

	return (instance);

}	/* audio_sup_get_qptr_instance() */

/*
 * State structure handling:
 */

/*
 * audio_sup_devt_to_state()
 *
 * Description:
 *	This routine is used to associate the device number with the
 *	dev_info_t pointer. It returns the device's state structure when
 *	it is done.
 *
 * Arguments:
 *	dev_t		dev	Device name
 *
 * Returns:
 *	Valid pointer			Pointer to the state
 *	NULL				State pointer not found
 */
audio_state_t *
audio_sup_devt_to_state(dev_t dev)
{
	audio_inst_info_t	*list;	/* for walking the list */
	audio_inst_info_t	**plist	/* for walking the list */;
	dev_info_t		*my_dip;
	audio_state_t		*statep;
	int			instance;
	major_t			major = getmajor(dev);
	major_t			my_major;

	ATRACE("in audio_sup_devt_to_state()", dev);

	/* protect the driver list */
	mutex_enter(&audio_drv_list_lock);

	plist = &audio_drv_list_head;
	list = *plist;
	while (list) {
		statep = &list->ail_state;
		mutex_enter(&statep->as_lock);
		my_dip = statep->as_dip;
		my_major = statep->as_major;
		instance = getminor(dev) /
		    audio_sup_get_minors_per_inst(AUDIO_STATE2HDL(statep));

		if ((my_major == major) &&
		    (instance == ddi_get_instance(my_dip))) {
			mutex_exit(&statep->as_lock);
			mutex_exit(&audio_drv_list_lock);

			ATRACE("audio_sup_devt_to_state() returning", statep);

			return (statep);

		}
		plist = &list->ail_next;
		list = list->ail_next;
		mutex_exit(&statep->as_lock);
	}
	mutex_exit(&audio_drv_list_lock);

	ATRACE("audio_sup_devt_to_state() returning NULL", 0);

	return (NULL);

}	/* audio_sup_devt_to_state() */

/*
 * audio_sup_devinfo_to_state()
 *
 * Description:
 *	Get the state pointer for the audio device given a devinfo_t *.
 *
 * Arguments:
 *	dev_info_t	*dip	dev_info_t pointer for the device
 *
 * Returns:
 *	Valid pointer			Pointer to the state
 *	NULL				State pointer not found
 */
audio_state_t *
audio_sup_devinfo_to_state(dev_info_t *dip)
{
	audio_inst_info_t	*instp;

	ATRACE("in audio_sup_devinfo_to_state(), dip", dip);

	mutex_enter(&audio_drv_list_lock);
	instp = audio_sup_lookup_drv_entry(dip);

	if (instp && (instp->ail_state.as_dip == dip)) {
		mutex_exit(&audio_drv_list_lock);

		/* verify, if given */
		ATRACE("audio_sup_devinfo_to_state() "
		    "found dip match, returning", &instp->ail_state);

		return (&instp->ail_state);

	} else {
		mutex_exit(&audio_drv_list_lock);
		ATRACE("audio_sup_devinfo_to_state() no dip match", dip);

		return (NULL);

	}

}	/* audio_sup_devinfo_to_state() */

/*
 * audio_sup_create_drv_entry()
 *
 * Description:
 *	Create & add an entry in the instance list (audio_drv_list_head).
 *	The whole linked list is scanned
 *	to make sure we don't ever get a duplicate entry.
 *
 * Arguments:
 *	dev_info_t	*dip	dev_info_t pointer for the device, what we use
 *				to find the instance
 *
 * Returns:
 *	Valid pointer		Valid instance
 *	NULL			Instance already registered
 */
static audio_inst_info_t *
audio_sup_create_drv_entry(dev_info_t *dip)
{
	audio_inst_info_t	*list;		/* for walking the list */
	audio_inst_info_t	**plist;	/* for walking the list */
	audio_inst_info_t	*entry;		/* new entry */

	ATRACE("in audio_sup_create_drv_entry()", dip);

	/* protect the driver list */
	mutex_enter(&audio_drv_list_lock);
	plist = &audio_drv_list_head;
	list = *plist;
	while (list) {
		if (list->ail_state.as_dip == dip) {
			mutex_exit(&audio_drv_list_lock);

			ATRACE("audio_sup_create_drv_entry() "
			    "instance already registered", dip);
			audio_sup_log(NULL, CE_NOTE,
			    "%s%d already registered",
			    ddi_driver_name(dip), ddi_get_instance(dip));

			return (NULL);

		}
		plist = &list->ail_next;
		list = list->ail_next;
	}

	/* "dip" is not registered, create new one and add to list */
	ATRACE("audio_sup_create_drv_entry() dip not registered", dip);

	entry = kmem_zalloc(sizeof (*entry), KM_SLEEP);
	*plist = entry;
	mutex_exit(&audio_drv_list_lock);

	return (entry);

}	/* audio_sup_create_drv_entry() */

/*
 * audio_sup_free_drv_entry()
 *
 * Description:
 *	This routine is used to clear entries in the driver list that
 *	were added in by audio_sup_create_drv_entry().
 *
 * Arguments:
 *	dev_info_t	*dip		dev_info_t pointer for the device.
 *					if NULL, delete all entries
 *
 * Returns:
 *	void
 */
static void
audio_sup_free_drv_entry(dev_info_t *dip)
{
	audio_inst_info_t	*list;	/* for walking the list */
	audio_inst_info_t	**plist	/* for walking the list */;
	audio_ch_t		*chptr;
	audio_state_t		*statep;
	int			i;
	int			num_chs;

	ATRACE("in audio_sup_free_drv_entry()", dip);

	/* protect the driver list */
	mutex_enter(&audio_drv_list_lock);
	plist = &audio_drv_list_head;
	list = *plist;
	while (list) {
		if ((dip == NULL) || (list->ail_state.as_dip == dip)) {
			/* found it */
			*plist = list->ail_next;
			list->ail_next = NULL;

			statep = &list->ail_state;

			/* de-initialize the channel structures */
			num_chs = statep->as_max_chs;
			for (i = 0, chptr = &statep->as_channels[0];
			    i < num_chs; i++, chptr++) {
				/*
				 * All we have to worry about is locks and
				 * condition variables.
				 */
				mutex_destroy(&chptr->ch_lock);
				mutex_destroy(&chptr->ch_adata_lock);
				cv_destroy(&chptr->ch_cv);
			}

			/* destroy mutex, cv */
			mutex_destroy(&statep->as_lock);
			cv_destroy(&statep->as_cv);

			/* free the structure */
			kmem_free(list, sizeof (audio_inst_info_t));

			/* see if we need to go again */
			if (dip) {
				/* nope, done */
				break;
			}
		}
		plist = &list->ail_next;
		list = list->ail_next;
	}
	mutex_exit(&audio_drv_list_lock);

	ATRACE("audio_sup_free_drv_entry() done", 0);

}	/* audio_sup_free_drv_entry() */

/*
 * audio_sup_free_apm_persist()
 *
 * Description:
 *	Free the audio_apm_persist list that is associated with the instance.
 *
 * Arguments:
 *	audio_state_t		*statep		Pointer to device state info
 *	audio_apm_persist_t	*instp		Pointer to instance data
 *
 * Returns:
 *	void					Silently fails if key useless
 */
static void
audio_sup_free_apm_persist(audio_state_t *statep, audio_apm_persist_t *instp)
{
	audio_apm_persist_t	*tmp;

	ATRACE("in audio_sup_free_apm_persist() statep", statep);
	ATRACE("audio_sup_free_apm_persist() instp", instp);

	ASSERT(mutex_owned(&audio_persist_lock));

	tmp = instp;
	while (tmp) {
		tmp = tmp->ap_next;
		kmem_free(instp->ap_data, instp->ap_size);
		kmem_free(instp, sizeof (*instp));
	}

	ATRACE("audio_sup_free_apm_persist() done", statep);

}	/* audio_sup_free_apm_persist() */

/*
 * audio_sup_free_inst_persist()
 *
 * Description:
 *	Free the audio_inst_persist_t structure for this dip.
 *
 * Arguments:
 *	audio_state_t		*statep		Pointer to device state info
 *	audio_inst_persist_t	*persistp	Pointer to the struct to remove
 *
 * Returns:
 *	void
 */
static void
audio_sup_free_inst_persist(audio_state_t *statep,
	audio_inst_persist_t *persistp)
{
	audio_inst_persist_t	**plist;
	audio_inst_persist_t	*list;

	ATRACE("in audio_sup_free_inst_persist() statep", statep);
	ATRACE("audio_sup_free_inst_persist() persistp", persistp);

	ASSERT(mutex_owned(&audio_persist_lock));
	ASSERT(audio_main_anchor);

	plist = audio_main_anchor;
	list = *plist;

	while (list) {
		if (list == persistp) {
			/* found it, free the APM list and key */
			if (list->amp_key) {
				kmem_free(list->amp_key,
				    strlen(list->amp_key)+1);
			}
			if (list->amp_apmp) {
				audio_sup_free_apm_persist(statep,
				    list->amp_apmp);
			}
			/* remove from the list */
			*plist = list->amp_next;
			ATRACE("audio_sup_free_inst_persist() "
			    "freeing dip & return", list);
			kmem_free(list, sizeof (*list));
			return;
		}

		plist = &list->amp_next;
		list = list->amp_next;
	}

	ATRACE("audio_sup_free_inst_persist() returning, not found", persistp);

}	/* audio_sup_free_inst_persist() */

/*
 * audio_sup_lookup_drv_entry()
 *
 * Description:
 *	Lookup audio_inst_info_t pointer corresponding to dip
 *
 * Arguments:
 *	dev_info_t	*dip		dev_info_t pointer for the device
 *
 * Returns:
 *	audio_inst_info_t pointer or NULL
 */
static audio_inst_info_t *
audio_sup_lookup_drv_entry(dev_info_t *dip)
{
	audio_inst_info_t	*list;	/* for walking the list */
	audio_inst_info_t	**plist	/* for walking the list */;

	ATRACE("in audio_sup_lookup_drv_entry()", dip);
	ASSERT(mutex_owned(&audio_drv_list_lock));

	plist = &audio_drv_list_head;
	list = *plist;
	while (list) {
		if (list->ail_state.as_dip == dip) {
			break;
		}
		plist = &list->ail_next;
		list = list->ail_next;
	}

	ATRACE("audio_sup_lookup_drv_entry() done", list);

	return (list);

}	/* audio_sup_lookup_drv_entry() */

/*
 * audio_sup_persist()
 *
 * Description:
 *	Routine to initialize and find persistent state and its unique key.
 *
 *	There are two types of persistent state, per instance and per APM
 *	state. Per instance saves the key and dip. Thus the correct instance
 *	may be found based on the key or the dip. It is also possible to
 *	detect, given a driver provided unique key, when a device moves
 *	from one port to another. Right now a linear search is used to find
 *	the matching dip. If we get to the point of supporting 100s or 1000s
 *	of instances then this will need to be changed to something more
 *	sophisticated.
 *
 *	The second type is used to save the state for each APM for the
 *	instance. It is not a requirement for any APM to save persistent
 *	state, thus we could be allocating the per instance state structure
 *	for nothing. The APM is responsible for allocating the memory and
 *	providing a pointer to that memory and the size.
 *	audio_sup_free_persist_state() will free this memory for the APM.
 *
 *	The per instance state structures are found by retreiving the
 *	main anchor using the AUDIO_SUP_KEY unique key.
 *
 *	If the reset-configuration property is set to non-zero then any
 *	saved state is cleared and the APMs rebuild the persistent data
 *	from scratch. This effectively resets them to their defaults.
 *
 *	NOTE: All allocated memory is owned by the main anchor.
 *
 * Arguments:
 *	audio_state_t		*statep	The device state structure
 *	char			*key	Unique key to for finding memory
 *
 * Returns:
 *	AUDIO_SUCCESS			Persistent state allocated/found
 *	AUDIO_FAILURE			Couldn't allocate/find persistent state
 */
static int
audio_sup_persist(audio_state_t *statep, char *key)
{
	audio_inst_persist_t	*key_persistp = NULL;
	audio_inst_persist_t	*inst_persistp;
	audio_inst_persist_t	*main_anchor;
	audio_inst_persist_t	*tmp_persistp;
	dev_info_t		*dip = statep->as_dip;
	size_t			key_length;
	major_t			major = ddi_driver_major(dip);
	char			*anchor_key = AUDIO_SUP_KEY;
	char			*new_key;
	char			pathbuf[MAXPATHLEN];
	int			do_reset = 0;
	int			instance = statep->as_dev_instance;

	ATRACE("in audio_sup_persist()", statep);

	/*
	 * The 1st step is to make sure we have the anchor. It could have
	 * been allocated on a previous audio framework load, or it could be
	 * unallocated.
	 */
	mutex_enter(&audio_persist_lock);
	ATRACE("audio_sup_persist() audio_main_anchor", audio_main_anchor);
	if (audio_main_anchor == NULL) {
		/* anchor not loaded, so find it */
		main_anchor = (audio_inst_persist_t *)space_fetch(anchor_key);
		ATRACE("audio_sup_persist() space_fetch() main_anchor",
		    main_anchor);
		if (main_anchor == NULL) {
			/* 1st load, need to allocate the anchor memory */
			main_anchor = kmem_zalloc(sizeof (main_anchor),
			    KM_SLEEP);
			if (space_store(anchor_key,
			    (uintptr_t)main_anchor) != 0) {
				mutex_exit(&audio_persist_lock);
				audio_sup_log(AUDIO_STATE2HDL(statep), CE_WARN,
				    "!cannot create persistent anchor");
				kmem_free(main_anchor, sizeof (main_anchor));
				return (AUDIO_FAILURE);
			}
			ATRACE("audio_sup_persist() space_store() main_anchor",
			    main_anchor);
		}
		/* set this after the check above! */
		audio_main_anchor = (audio_inst_persist_t **)main_anchor;
		ATRACE("audio_sup_persist() new audio_main_anchor",
		    audio_main_anchor);
	}
	mutex_exit(&audio_persist_lock);

	/*
	 * Set up the instance key. Following the comments in space.c this
	 * key is in one of two formats:
	 *
	 *	AUDIO:key_string_from_driver
	 *
	 * or
	 *
	 *	AUDIO:pathname
	 *
	 * The former is when the driver passes a string for the key. This
	 * string MUST be unique. The later is when the driver passes a
	 * NULL key string.
	 */
	if (key == NULL) {
		key = ddi_pathname(dip, pathbuf);
		ATRACE("audio_sup_persist() NULL key string", key);
	} else {
		ATRACE("audio_sup_persist() provided key string", key);
	}

	key_length = strlen(audio_key_class);
	key_length += strlen(key);
	key_length++;	/* make room for NULL at end of string */

	new_key = kmem_alloc(key_length, KM_SLEEP);
	(void) sprintf(new_key, "%s%s", audio_key_class, key);
	ATRACE("audio_sup_register() key string", new_key);

	/*
	 * In order to determine if this device has moved to a different port
	 * or if the key has changed we need to search through all of the dev
	 * structures. Once this loop ends we'll know if the current key and
	 * dev are present. This is one of the simple search algorithms that
	 * would need to be changed if we need to support a huge number of
	 * instances.
	 */
	mutex_enter(&audio_persist_lock);
	for (tmp_persistp = *audio_main_anchor; tmp_persistp;
	    tmp_persistp = tmp_persistp->amp_next) {
		if (strcmp(new_key, tmp_persistp->amp_key) == 0) {
			ATRACE("audio_sup_persist() dev: found key",
			    tmp_persistp);
			ASSERT(!key_persistp);
			key_persistp = tmp_persistp;
			break;
		}
	}

	if (key_persistp) {
		key_persistp->amp_major = major;
		key_persistp->amp_instance = instance;

		ATRACE("audio_sup_persist() match", key_persistp);
		inst_persistp = key_persistp;

		/* free new_key so we don't have a memory leak */
		kmem_free(new_key, key_length);
	} else {
		ATRACE("audio_sup_persist() no match", statep);
		mutex_exit(&audio_persist_lock);
		inst_persistp = kmem_zalloc(sizeof (*inst_persistp), KM_SLEEP);
		mutex_enter(&audio_persist_lock);

		/* don't free new_key because we need it */
		inst_persistp->amp_key = new_key;
		inst_persistp->amp_major = major;
		inst_persistp->amp_instance = instance;

		/* put on list */
		inst_persistp->amp_next = *audio_main_anchor;
		*audio_main_anchor = inst_persistp;
	}

	/*
	 * CAUTION: From here new_key must have been freed or placed in an
	 *	audio_inst_persist_t structure. Otherwise we'll have a memory
	 *	leak.
	 *
	 * We are done!
	 */

	ASSERT(inst_persistp);
	mutex_exit(&audio_persist_lock);

	/* have statep point to instance persist info */
	mutex_enter(&statep->as_lock);
	statep->as_persistp = (void *)inst_persistp;
	ATRACE("audio_sup_register() as_persistp", statep->as_persistp);
	mutex_exit(&statep->as_lock);

	/*
	 * The final piece of information we need is whether we need to
	 * do a reset or not.
	 */
	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reset-configuration", 0)) {
		ATRACE("audio_sup_persist() need reset", statep);
		do_reset++;
	}

	/*
	 * Now that we have good persistence data see if we need to reset it.
	 * We don't block the attach() in this case because the driver is still
	 * useful.
	 */
	if (do_reset && audio_sup_free_persist_state(statep,
	    AUDIO_ALL_DEVICES) == AUDIO_FAILURE) {
		audio_sup_log(NULL, CE_NOTE, "!state reset failed");
	}

	ATRACE("audio_sup_persist() returning, tmp_persistp", tmp_persistp);

	return (AUDIO_SUCCESS);

}	/* audio_sup_persist() */

/*
 * audio_sup_wiocdata()
 *
 * Description:
 *	This routine is called by audio_sup_wput() to process the IOCDATA
 *	messages that belong to the Audio Support Module's routines.
 *
 *	We only support transparent ioctls.
 *
 *	WARNING: Don't forget to free the mblk_t struct used to hold private
 *		data. The done: jump point takes care of this.
 *
 *	WARNING: Don't free the private mblk_t structure if the command is
 *		going to call qreply(). This frees the private date that will
 *		be needed for the next M_IOCDATA message.
 *
 * Arguments:
 *	queue_t		*q	Pointer to the STREAMS queue
 *	mblk_t		*mp	Pointer to the message block
 *	audio_ch_t	*chptr	Pointer to this channel's state information
 *
 * Returns:
 *	0			Always returns a 0, becomes on return for
 *				audio_sup_wput()
 */
static int
audio_sup_wiocdata(queue_t *q, mblk_t *mp, audio_ch_t *chptr)
{
	audio_state_t		*statep = chptr->ch_statep;
	struct copyreq		*cqp;
	struct copyresp		*csp;
	audio_i_state_t		*cmd;
	int			error = 0;

	ATRACE("in audio_sup_wiocdata()", chptr);

	ASSERT(statep);
	ASSERT(chptr);

	csp = (struct copyresp *)mp->b_rptr;	/* set up copy response ptr */
	cmd = (audio_i_state_t *)csp->cp_private;	/* get state info */
	cqp =  (struct copyreq *)mp->b_rptr;	/* set up copy request ptr */

	/* make sure we've got a good return value */
	if (csp->cp_rval) {
		ATRACE("audio_sup_wiocdata() bad return value", csp->cp_rval);
		error = EINVAL;
		goto done;
	}

	/* find the command */
	ATRACE_32("audio_sup_wiocdata() command", cmd->ais_command);
	switch (cmd->ais_command) {

	case AUDIO_COPY_OUT_CH_NUMBER:	/* AUDIO_GET_CH_NUMBER */
		ATRACE("audio_sup_wiocdata() AUDIO_COPY_OUT_CH_NUMBER", chptr);
		if (csp->cp_cmd != AUDIO_GET_CH_NUMBER) {
			error = EINVAL;
		}
		break;

	case AUDIO_COPY_OUT_CH_TYPE:		/* AUDIO_GET_CH_TYPE */
		ATRACE("audio_sup_wiocdata() AUDIO_COPY_OUT_CH_TYPE", chptr);
		if (csp->cp_cmd != AUDIO_GET_CH_TYPE) {
			error = EINVAL;
		}
		break;

	case AUDIO_COPY_OUT_NUM_CHS:		/* AUDIO_GET_NUM_CHS */
		ATRACE("audio_sup_wiocdata() AUDIO_COPY_OUT_CHANNELS", chptr);
		if (csp->cp_cmd != AUDIO_GET_NUM_CHS) {
			error = EINVAL;
		}
		break;

	case AUDIO_COPY_OUT_AD_DEV:		/* AUDIO_GET_AD_DEV */
		ATRACE("audio_sup_wiocdata() AUDIO_COPY_OUT_AD_DEV", chptr);
		if (csp->cp_cmd != AUDIO_GET_AD_DEV) {
			error = EINVAL;
		}
		break;

	case AUDIO_COPY_OUT_APM_DEV:		/* AUDIO_GET_APM_DEV */
		ATRACE("audio_sup_wiocdata() AUDIO_COPY_OUT_APM_DEV", chptr);
		if (csp->cp_cmd != AUDIO_GET_APM_DEV) {
			error = EINVAL;
		}
		break;

	case AUDIO_COPY_OUT_AS_DEV:		/* AUDIO_GET_AS_DEV */
		ATRACE("audio_sup_wiocdata() AUDIO_COPY_OUT_AS_DEV", chptr);
		if (csp->cp_cmd != AUDIO_GET_AS_DEV) {
			error = EINVAL;
		}
		break;

	default:
		ATRACE("audio_sup_wiocdata() default", chptr);
		error = EINVAL;
		break;
	}

	/* we always either ack or nack depending on if error is set or not */
	ATRACE_32("audio_sup_wiocdata() switch done", error);

done:
	if (csp->cp_private) {
		ATRACE("audio_sup_wiocdata() freeing csp->cp_private",
		    csp->cp_private);
		kmem_free(csp->cp_private, sizeof (audio_i_state_t));
		csp->cp_private = NULL;
	}
	if (cqp->cq_private) {
		ATRACE("audio_sup_wiocdata() freeing cqp->cq_private",
		    cqp->cq_private);
		kmem_free(cqp->cq_private, sizeof (audio_i_state_t));
		cqp->cq_private = NULL;
	}

	if (error) {
		miocnak(q, mp, 0, error);
	} else {
		miocack(q, mp, 0, 0);
	}

	ATRACE_32("audio_sup_wiocdata() returning", error);

	return (0);

}	/* audio_sup_wiocdata() */

/*
 * audio_sup_wioctl()
 *
 * Description:
 *	This routine is called by audio_sup_wput() to process all M_IOCTL
 *	messages that the Audio Support Module provides.
 *
 *	We only support transparent ioctls. Since this is a driver we
 *	nack unrecognized ioctls.
 *
 *	The following ioctls are supported:
 *		AUDIO_GET_CH_NUMBER
 *		AUDIO_GET_CH_TYPE
 *		AUDIO_GET_NUM_CHS
 *		AUDIO_GET_AD_DEV
 *		AUDIO_GET_APM_DEV
 *		AUDIO_GET_AS_DEV
 *		unknown		nack back up the queue
 *
 *	CAUTION: This routine is called from interrupt context, so memory
 *		allocation cannot sleep.
 *
 *	WARNING: There cannot be any locks owned by calling routines.
 *
 * Arguments:
 *	queue_t		*q	Pointer to the STREAMS queue
 *	mblk_t		*mp	Pointer to the message block
 *	audio_ch_t	*chptr	Pointer to this channel's state information
 *
 * Returns:
 *	0			Always returns a 0, becomes a return for
 *				audio_sup_wput()
 */
static int
audio_sup_wioctl(queue_t *q, mblk_t *mp, audio_ch_t *chptr)
{
	audio_state_t		*statep = chptr->ch_statep;
	audio_device_t		*devp;
	struct iocblk		*iocbp;
	audio_i_state_t		*state = NULL;
	audio_device_type_e	type = chptr->ch_info.dev_type;
	int			error;

	ATRACE("in audio_sup_wioctl()", chptr);

	ASSERT(statep);
	ASSERT(chptr);

	ASSERT(!mutex_owned(&statep->as_lock));

	iocbp = (struct iocblk *)mp->b_rptr;	/* pointer to ioctl info */

	/* make sure this is a transparent ioctl */
	if (iocbp->ioc_count != TRANSPARENT) {
		ATRACE_32("audio_sup_wioctl() not TRANSPARENT",
		    iocbp->ioc_count);
		error = EINVAL;
		goto nack;
	}

	/* get a buffer for private data */
	if ((state = kmem_alloc(sizeof (*state), KM_NOSLEEP)) == NULL) {
		ATRACE("audio_sup_wioctl() state kmem_alloc() failed", 0);
		error = ENOMEM;
		goto nack;
	}

	ATRACE_32("audio_sup_wioctl() command", iocbp->ioc_cmd);
	switch (iocbp->ioc_cmd) {

	case AUDIO_GET_CH_NUMBER:
		ATRACE("audio_sup_wioctl() AUDIO_GET_CH_NUMBER", chptr);

		/* save state for M_IOCDATA processing */
		state->ais_command = AUDIO_COPY_OUT_CH_NUMBER;
			/* user space addr */
		state->ais_address = (caddr_t)(*(caddr_t *)mp->b_cont->b_rptr);

		/* only an int, so reuse the data block without checks */
		*(int *)mp->b_cont->b_rptr = chptr->ch_info.ch_number;
		mp->b_cont->b_wptr = mp->b_cont->b_rptr + sizeof (int);

		/* Setup for copyout */
		mcopyout(mp, (mblk_t *)state, sizeof (int), state->ais_address,
		    NULL);

		/* send the copy out request */
		qreply(q, mp);

		ATRACE("audio_sup_wioctl() AUDIO_GET_CH_NUMBER returning",
		    chptr);

		return (0);

		/* end AUDIO_GET_CH_NUMBER */

	case AUDIO_GET_CH_TYPE:
		ATRACE("audio_sup_wioctl() AUDIO_GET_CH_TYPE", chptr);

		/* save state for M_IOCDATA processing */
		state->ais_command = AUDIO_COPY_OUT_CH_TYPE;
			/* user space addr */
		state->ais_address = (caddr_t)(*(caddr_t *)mp->b_cont->b_rptr);

		/* only an int, so reuse the data block without checks */
		*(int *)mp->b_cont->b_rptr = type;
		mp->b_cont->b_wptr = mp->b_cont->b_rptr + sizeof (AUDIO);

		/* Setup for copyout */
		mcopyout(mp, (mblk_t *)state, sizeof (int), state->ais_address,
		    NULL);

		/* send the copy out request */
		qreply(q, mp);

		ATRACE("audio_sup_wioctl() AUDIO_GET_CH_TYPE returning", chptr);

		return (0);

		/* end AUDIO_GET_CH_TYPE */

	case AUDIO_GET_NUM_CHS:
		ATRACE("audio_sup_wioctl() AUDIO_GET_NUM_CHS", chptr);

		/* save state for M_IOCDATA processing */
		state->ais_command = AUDIO_COPY_OUT_NUM_CHS;
			/* user space addr */
		state->ais_address = (caddr_t)(*(caddr_t *)mp->b_cont->b_rptr);

		/* only an int, so reuse the data block without checks */
		*(int *)mp->b_cont->b_rptr = statep->as_max_chs;
		mp->b_cont->b_wptr = mp->b_cont->b_rptr + sizeof (int);

		/* Setup for copyout */
		mcopyout(mp, (mblk_t *)state, sizeof (int), state->ais_address,
		    NULL);

		/* send the copy out request */
		qreply(q, mp);

		ATRACE("audio_sup_wioctl() AUDIO_GET_NUM_CHS returning",
		    chptr);

		return (0);

		/* end AUDIO_GET_NUM_CHS */

	case AUDIO_GET_AD_DEV:
		ATRACE("audio_sup_wioctl() AUDIO_GET_AD_DEV", chptr);

		/* save state for M_IOCDATA processing */
		state->ais_command = AUDIO_COPY_OUT_AD_DEV;
			/* user space addr */
		state->ais_address = (caddr_t)(*(caddr_t *)mp->b_cont->b_rptr);

		/* Setup for copyout */
		mcopyout(mp, (mblk_t *)state, sizeof (*chptr->ch_dev_info),
		    state->ais_address, NULL);

		/* put the data in the buffer, but try to reuse it first */
		if (MBLKSIZE(mp->b_cont) < sizeof (audio_device_t)) {
			freemsg(mp->b_cont);
			mp->b_cont = allocb(
			    sizeof (*chptr->ch_dev_info), BPRI_MED);
			if (mp->b_cont == NULL) {
				error = EAGAIN;
				goto nack;
			}
		}

		/*
		 * We don't bother to lock the state structure because this
		 * is static data.
		 */

		devp = (audio_device_t *)mp->b_cont->b_rptr;

		bcopy(chptr->ch_dev_info, devp, sizeof (*chptr->ch_dev_info));

		mp->b_cont->b_wptr = mp->b_cont->b_rptr +
		    sizeof (*chptr->ch_dev_info);

		/* send the copy out request */
		qreply(q, mp);

		ATRACE("audio_sup_wioctl() AUDIO_GET_AD_DEV returning", chptr);

		return (0);

	case AUDIO_GET_APM_DEV:
		ATRACE("audio_sup_wioctl() AUDIO_GET_APM_DEV", chptr);

		/* save state for M_IOCDATA processing */
		state->ais_command = AUDIO_COPY_OUT_APM_DEV;
			/* user space addr */
		state->ais_address = (caddr_t)(*(caddr_t *)mp->b_cont->b_rptr);

		/* Setup for copyout */
		mcopyout(mp, (mblk_t *)state, sizeof (*chptr->ch_dev_info),
		    state->ais_address, NULL);

		/* put the data in the buffer, but try to reuse it first */
		if (MBLKSIZE(mp->b_cont) < sizeof (*chptr->ch_dev_info)) {
			freemsg(mp->b_cont);
			mp->b_cont = allocb(
			    sizeof (*chptr->ch_dev_info), BPRI_MED);
			if (mp->b_cont == NULL) {
				error = EAGAIN;
				goto nack;
			}
		}

		/*
		 * We don't bother to lock the state structure because this
		 * is static data.
		 */

		devp = (audio_device_t *)mp->b_cont->b_rptr;

		bcopy(chptr->ch_apm_infop->apm_info, devp,
		    sizeof (*chptr->ch_dev_info));

		mp->b_cont->b_wptr = mp->b_cont->b_rptr +
		    sizeof (*chptr->ch_dev_info);

		/* send the copy out request */
		qreply(q, mp);

		ATRACE("audio_sup_wioctl() AUDIO_GET_APM_DEV returning", chptr);

		return (0);

	case AUDIO_GET_AS_DEV:
		ATRACE("audio_sup_wioctl() AUDIO_GET_AS_DEV", chptr);

		/* save state for M_IOCDATA processing */
		state->ais_command = AUDIO_COPY_OUT_AS_DEV;
			/* user space addr */
		state->ais_address = (caddr_t)(*(caddr_t *)mp->b_cont->b_rptr);

		/* Setup for copyout */
		mcopyout(mp, (mblk_t *)state, sizeof (*chptr->ch_dev_info),
		    state->ais_address, NULL);

		/* put the data in the buffer, but try to reuse it first */
		if (MBLKSIZE(mp->b_cont) < sizeof (*chptr->ch_dev_info)) {
			freemsg(mp->b_cont);
			mp->b_cont = allocb(
			    sizeof (*chptr->ch_dev_info), BPRI_MED);
			if (mp->b_cont == NULL) {
				error = EAGAIN;
				goto nack;
			}
		}

		/*
		 * We don't bother to lock the state structure because this
		 * is static data.
		 */

		devp = (audio_device_t *)mp->b_cont->b_rptr;

		bcopy(&audio_device_info, devp, sizeof (*chptr->ch_dev_info));

		mp->b_cont->b_wptr = mp->b_cont->b_rptr +
		    sizeof (*chptr->ch_dev_info);

		/* send the copy out request */
		qreply(q, mp);

		ATRACE("audio_sup_wioctl() AUDIO_GET_AS_DEV returning", chptr);

		return (0);

	default:	/* this should never happen */
		ATRACE_32("audio_sup_wioctl() default", iocbp->ioc_cmd);
		error = EINVAL;
		break;
	}

	/* we always nack */
	ATRACE_32("audio_sup_wioctl() switch done", error);

nack:
	/* we always nack if we break out of the switch() */
	ATRACE("audio_sup_wioctl() nack", chptr);

	if (state) {		/* free allocated state memory */
		ATRACE("audio_sup_wioctl() nack freeing state", state);
		kmem_free(state, sizeof (audio_i_state_t));
	}

	miocnak(q, mp, 0, error);

	ATRACE("audio_sup_wioctl() returning failure", chptr);

	return (0);

}	/* audio_sup_wioctl() */
