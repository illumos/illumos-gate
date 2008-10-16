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
 * Mixer Audio Personality Module (mixer)
 *
 * This module is used by Audio Drivers that wish to have the audio(7I)
 * and mixer(7I) semantics for /dev/audio and /dev/audioctl. In general,
 * the mixer(7I) semantics are a superset of the audio(7I) semantics. Either
 * semantics may be enforced, depending on the mode of the mixer, AM_MIXER_MODE
 * or AM_COMPAT_MODE, respectively. The initial mode is set by the Audio
 * Driver and may be changed on the fly, even while playing or recording
 * audio. When mixing is enabled multiple play and record streams are allowed,
 * and new ioctls are also available. Some legacy applications may not behave
 * well in this mode, thus the availability of the compatibility mode.
 *
 * In addition to providing two sets of semantics, this module also supports
 * two types of audio Codecs, those that have a single play and record stream
 * (traditional Codecs) and those that allow multiple play and record streams
 * (multi-stream Codecs). Because multi-streaming Codecs must do sample rate
 * conversion in hardware in order to mix, the audio stream is not sample rate
 * converted. However, for traditional Codecs the  audio streams must be sample
 * rate converted.
 *
 * The mixer supports a number of data formats on all hardware devices. To do
 * this all incoming audio is converted to a canonical format, which is 16-bit
 * linear PCM. This audio is held in 32-bit integers, which allows it to be
 * mixed with other streams without losing data due to overflowing as would
 * happen if it was stored as a 16-bit short. It is also converted to mono or
 * stereo to match the hardware. When audio is played it is converted to the
 * format the hardware supports.
 *
 * Once the hardware format is set it is never changed again, except for the
 * sample rate.
 *
 * The following formats are supported:
 *	16-bit linear PCM, mono and stereo
 *	8-bit linear PCM, mono and stereo
 *	8-bit u-law, mono and stereo
 *	8-bit a-law, mono and stereo
 *
 * In order to present a uniform view of audio there are three different
 * views of the hardware.
 * 1.	The true configuration of the audio device. This view is not
 *	visible by applications. However it is used by the mixer to properly
 *	format audio for the device.
 * 2.	The COMPAT mode view. The is the view AUDIOCTL channels get when
 *	there aren't any AUDIO channels open in the application. This is
 *	called the master view. The reason this is not the true hardware view
 *	is because some hardware cannot support all formats. For example,
 *	many devices do not support u-law or a-law. The mixer can do this
 *	translation. However it would be confusing to show apps that the
 *	device was really set to linear PCM.
 * 2.	The MIXER mode view. This is the view AUDIO channels and AUDIOCTL
 *	channels in apps that have an AUDIO channel open see. It is mostly
 *	virtual. It always reflects how the channel was programmed. This
 *	becomes the COMPAT view when put into compatibility mode.
 *
 * Most ioctl()s are executed from a task queue. This gives them their own
 * thread and thus they can block without violating the STREAMS blocking rules.
 * The task queue is limited to just one thread. Thus these ioctl()s are
 * serialized and thus access to the hardware state structures and hardware
 * are protected.
 *
 *	NOTE: statep->as_max_chs is set when the audiosup module loads, so we
 *		don't need to protect it when we access it.
 *
 *	NOTE: All linear PCM is assumed to be signed. Therefore if the device
 *		only supports unsigned linear PCM we need to translate either
 *		before we send it to the device or after we take it from the
 *		device. This way we save each Audio Driver from having to do
 *		this.
 *
 *	NOTE: This module depends on the misc/audiosup module being loaded 1st.
 *
 * The audio mixer source code is broken up into three components:
 *	am_main.c:	module load and STREAMS entry points
 *	am_ad.c:	Audio Driver entry points
 *	am_ioctl.c:	ioctl() code
 *
 * These routines are called by the audio support module:
 *	am_open_audio()
 *	am_open_audioctl()
 *	am_close_audio()
 *	am_close_audioctl()
 *	am_restore_state()
 *	am_save_state()
 *	am_rput() - private
 *	am_rsvc() - private
 *	am_wput() - private
 *	am_wsvc() - private
 *
 * These routines are provided for use by the other mixer source code files:
 *	am_apply_gain_balance()
 *	am_convert_int_mono_stereo()
 *	am_convert_to_int()
 *	am_send_signal()
 *	am_update_conv_buffer()
 *	am_update_src_buffer()
 */

#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/stropts.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/note.h>
#include <sys/audio.h>
#include <sys/audiovar.h>
#include <sys/audio/audio_support.h>
#include <sys/audio/audio_apm.h>
#include <sys/audio/audio_src.h>
#include <sys/audio/audio_trace.h>
#include <sys/mixer.h>
#include <sys/audio/audio_mixer.h>
#include <sys/audio/impl/audio_mixer_impl.h>

/*
 * Private primary routines provided by this file. These are provided to the
 * audio support module via am_open_audio() and am_open_audioctl().
 */
static int am_rput(queue_t *, mblk_t *);
static int am_rsvc(queue_t *);
static int am_wput(queue_t *, mblk_t *);
static int am_wsvc(queue_t *);

/*
 * Local routine prototypes used only by this file.
 */
static void am_flush(queue_t *, mblk_t *);
static int am_p_process(audio_ch_t *, void *, size_t, int **, size_t *, int **,
    size_t *);
static void am_set_waiting(audio_state_t *, pid_t, int, boolean_t, boolean_t);

/*
 * Module Linkage Structures
 */
/* Linkage structure for loadable drivers */
static struct modlmisc mixer_modlmisc = {
	&mod_miscops,		/* drv_modops */
	MIXER_MOD_NAME,		/* drv_linkinfo */
};

static struct modlinkage mixer_modlinkage =
{
	MODREV_1,		/* ml_rev */
	(void*)&mixer_modlmisc,	/* ml_linkage */
	NULL			/* NULL terminates the list */
};

/*
 *  Loadable Module Configuration Entry Points
 *
 *
 * _init()
 *
 * Description:
 *	Driver initialization, called when driver is first loaded.
 *
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

	ATRACE("in mixer _init()", 0);

	/* standard linkage call */
	if ((error = mod_install(&mixer_modlinkage)) != 0) {
		ATRACE_32("mixer _init() error 1", error);
		return (error);
	}

	ATRACE("mixer _init() successful", 0);

	return (error);

}	/* _init() */

/*
 * _fini()
 *
 * Description
 *	Module de-initialization, called when driver is to be unloaded.
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

	ATRACE("in mixer _fini()", 0);

	if ((error = mod_remove(&mixer_modlinkage)) != 0) {
		ATRACE_32("mixer _fini() mod_remove failed", error);
		return (error);
	}

	ATRACE_32("mixer _fini() successful", error);

	return (error);

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

	rc = mod_info(&mixer_modlinkage, modinfop);

	ATRACE_32("mixer _info() returning", rc);

	return (rc);

}	/* _info() */

/*
 * The public main routines for this file.
 */

/*
 * am_open_audio()
 *
 * Description:
 *	AUDIO channel specific open() routine. There are lots of rules here,
 *	depending on audio vs. audioctl and backward compatibility vs. mixer
 *	mode. Thus mode switching must be frozen, which we do by freezing the
 *	taskq.
 *
 *	NOTE: In user context so it is okay for memory allocation to sleep.
 *
 *	NOTE: audio(7I) redefines the O_NONBLOCK/O_NDELAY open() flags to also
 *		mean don't block waiting for a play/record channel to exit.
 *
 * Arguments:
 *	queue_t		*q		Pointer to the read queue
 *	dev_t		*devp		Pointer to the device
 *	int		oflag		Open flags
 *	int		sflag		STREAMS flag
 *	cred_t		*credp		Ptr to the user's credential structure
 *
 * Returns:
 *	AUDIO_SUCCESS			Successfully opened the device
 *	errno				Error number for failed open()
 */
/*ARGSUSED*/
int
am_open_audio(queue_t *q, dev_t *devp, int oflag, int sflag, cred_t *credp)
{
	audio_state_t		*statep;
	audio_apm_info_t	*apm_infop;
	am_ad_info_t		*ad_infop;
	am_apm_private_t	*stpptr;
	am_ch_private_t		*chpptr = NULL;
	audio_ch_t		*chptr;
	audio_ch_t		*tchptr;
	audio_info_t		*default_info;
	audio_info_t		*hw_info;
	audio_info_t		*iptr;
	pid_t			pid;
	boolean_t		wantread = B_FALSE;
	boolean_t		wantwrite = B_FALSE;
	ulong_t			minor;
	int			ch_flags = 0;
	int			error;
	int			i;
	int			max_chs;
	int			multi_open = 0;
	int			mode;
	int			rc;

	ATRACE("in am_open_audio()", devp);

	/* get the state structure */
	if ((statep = audio_sup_devt_to_state(*devp)) == NULL) {
		ATRACE_32(
		    "am_open_audio() audio_sup_devt_to_state() failed", 0);
		return (EIO);
	}

	/* this driver does only a conventional open(), i.e., no clone opens */
	if (sflag) {
		ATRACE("am_open_audio() clone open() failure", sflag);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "only conventional open()s are supported");
		return (EIO);
	}

	/*
	 * Determine if opening to FREAD and/or FWRITE. We also make sure
	 * that at least one of FREAD or FWRITE is set.
	 */
	if (oflag & FREAD) {
		wantread = B_TRUE;
		ch_flags |= AUDIO_RECORD;
		ATRACE_32("am_open_audio() allocate channel with read limits",
		    ch_flags);
	} else {
		wantread = B_FALSE;
	}
	if (oflag & FWRITE) {
		wantwrite = B_TRUE;
		ch_flags |= AUDIO_PLAY;
		ATRACE_32("am_open_audio() allocate channel with write limits",
		    ch_flags);
	} else {
		wantwrite = B_FALSE;
	}
	if (wantread == B_FALSE && wantwrite == B_FALSE) {
		ATRACE_32("am_open_audio(): must be RD, WR or RDWR", oflag);
		return (EINVAL);
	}

	/* figure out if allocates should sleep or not */
	ch_flags |= (oflag & (O_NONBLOCK|O_NDELAY)) ?
	    AUDIO_NO_SLEEP : AUDIO_SLEEP;

	/* get the PID for the process opening the channel */
	pid = ddi_get_pid();

	/* get pointers to various data structures */
	if ((apm_infop = audio_sup_get_apm_info(statep, AUDIO)) == NULL) {
		ATRACE("am_open_audio() audio_sup_get_apm_info() failed", 0);
		return (EIO);
	}

	mutex_enter(&apm_infop->apm_lock);
	stpptr = apm_infop->apm_private;
	hw_info = &stpptr->am_hw_info;
	ad_infop = apm_infop->apm_ad_infop;
	default_info = ad_infop->ad_defaults;
	max_chs = statep->as_max_chs;

	/* see if we've been offlined */
	if (!(stpptr->am_flags & AM_PRIV_ON_LINE)) {
		ATRACE_32("am_open_audio() offline #1", stpptr->am_flags);
		mutex_exit(&apm_infop->apm_lock);
		return (EIO);
	}
	mutex_exit(&apm_infop->apm_lock);

	/*
	 * The hardware may support only play or record and not the other.
	 * If this is the case and the application asked for the direction
	 * that isn't supported there's no way it can ever succeed. So we
	 * fail right away.
	 */
	if ((wantwrite &&
	    !(default_info->hw_features & AUDIO_HWFEATURE_PLAY)) ||
	    (wantread &&
	    !(default_info->hw_features & AUDIO_HWFEATURE_RECORD))) {
		ATRACE("am_open_audio() trying to do illegal direction",
		    default_info);
		return (EINVAL);
	}

	/*
	 * The hardware may be limited to simplex operation, i.e., it may
	 * only play or record at any one time. We make sure we haven't
	 * asked for something the hardware can't do before we continue.
	 */
	if ((default_info->hw_features & AUDIO_HWFEATURE_DUPLEX) == 0) {
		ATRACE_32("am_open_audio() simplex", default_info->hw_features);
		/* make sure we didn't open read/write */
		if (wantread && wantwrite) {
			/* we can never, ever succeed, so fail now */
			ATRACE("am_open_audio() simplex failed, RD_WR", stpptr);
			return (EBUSY);
		}

		/* we have to freeze the channels while we look at them */
		mutex_enter(&statep->as_lock);

		/* make sure we are asking for something we can have */
		while ((stpptr->am_in_chs && wantwrite) ||
		    (stpptr->am_out_chs && wantread)) {

			ATRACE("am_open_audio() simplex blocked", stpptr);

			/* is it okay to block and wait for the hw? */
			if (ch_flags & AUDIO_NO_SLEEP) {
				mutex_exit(&statep->as_lock);
				return (EBUSY);
			}

			/*
			 * Mark all AUDIO ch waiting flags. We may be
			 * re-marking some, but there may be new chs since
			 * the last loop through the channels. We also
			 * mark both directions so that one direction knows
			 * that the other is waiting.
			 */
			am_set_waiting(statep, AM_NO_PID, AM_SET_WAITING,
			    AM_SET_PLAY, AM_SET_RECORD);

			/* send a signal so other procs will wake up */
			mutex_exit(&statep->as_lock);
			am_send_signal(statep, stpptr);
			mutex_enter(&statep->as_lock);

			/* wait for a channel to be freed */
			ATRACE("am_open_audio() simplex blocked", stpptr);
			if (cv_wait_sig(&statep->as_cv,
			    &statep->as_lock) <= 0) {

				ATRACE("am_open_audio() simplex signal wakeup",
				    statep);
				/*
				 * This channel may have had a signal, but
				 * that doesn't mean any of the other channels
				 * may proceed. So make sure every channel
				 * gets another go. We clear the waiting flags
				 * and then any others loop back and reset if
				 * needed. That's why we do the cv_broadcast().
				 */
				am_set_waiting(statep, AM_NO_PID,
				    AM_CLEAR_WAITING, AM_SET_PLAY,
				    AM_SET_RECORD);
				cv_broadcast(&statep->as_cv);
				mutex_exit(&statep->as_lock);
				return (EINTR);
			}
			/*
			 * Normal wakeup, clear the waiting flags. If the
			 * channels need to wait they'll set the flags. That's
			 * why we wake all the channels up, so they'll go
			 * through their loop.
			 */
			am_set_waiting(statep, AM_NO_PID, AM_CLEAR_WAITING,
			    AM_SET_PLAY, AM_SET_RECORD);
			cv_broadcast(&statep->as_cv);

			ATRACE("am_open_audio() simplex normal wakeup", statep);
		}

		mutex_exit(&statep->as_lock);
	}

	ASSERT(!mutex_owned(&statep->as_lock));

	/*
	 * Before we go any further we allocate all the memory we'll need.
	 * We do it now so that we can sleep while not holding any locks
	 * or freezing the taskq, which would be bad if we have to wait
	 * a long time.
	 */
	if ((chptr = audio_sup_alloc_ch(statep, &error, AUDIO, ch_flags)) ==
	    NULL) {
		ATRACE_32("am_open_audio() alloc returning", error);
		return (error);
	}
	ASSERT(chptr->ch_info.pid == 0);

	/*
	 * Before we get the rest of the memory we need we make sure that we
	 * can allocate a channel in the audio driver, if needed. This may
	 * block for a while, which is why we do it now.
	 */
	if (am_ad_setup(statep, stpptr, ad_infop, chptr->ch_info.ch_number,
	    ch_flags) == AUDIO_FAILURE) {
			/*
			 * This should always succeed because we have the
			 * configuration information. So if we don't there's
			 * something wrong and we fail.
			 */
			ATRACE("am_open_audio() ad_setup() failed", 0);
			(void) audio_sup_free_ch(chptr);
			return (EIO);
	}
	ATRACE("am_open_audio() ad_setup() succeeded", 0);

	/*
	 * CAUTION: From here on we have to call ad_teardown() to
	 *	free the stream resources in the Audio Driver if
	 *	there is an error.
	 *
	 * Now allocate the rest of memory.
	 */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*chpptr));
	chpptr = kmem_zalloc(sizeof (*chpptr), KM_SLEEP);
	chpptr->acp_psb_size = ad_infop->ad_play.ad_bsize;
	chpptr->acp_play_samp_buf = kmem_zalloc(chpptr->acp_psb_size, KM_SLEEP);

	/* get an audio structure to use */
	iptr = kmem_alloc(sizeof (*iptr), KM_SLEEP);

	/*
	 * CAUTION: From here on we must free the channel and memory if we
	 *	need to return on an error.
	 *
	 * Getting to here means there aren't any conflicts with the hardware,
	 * so now the semantics of MIXER and COMPAT modes come to play. Because
	 * these semantics depend on the mixer mode we have to block it from
	 * changing. We do this by taking control of the taskq. Once we have
	 * the taskq we know there's no way for the mode to change.
	 */
	ATRACE("am_open_audio() entering again:", chptr);

again:	/* we loop back to here when cv_wait_sig returns due to a wakeup */
	ATRACE("am_open_audio() again: loop", chptr);

	ASSERT(!MUTEX_HELD(&statep->as_lock));

	/* check again to see if we've been offlined */
	mutex_enter(&apm_infop->apm_lock);
	if (!(stpptr->am_flags & AM_PRIV_ON_LINE)) {
		ATRACE_32("am_open_audio() offline #2", stpptr->am_flags);
		mutex_exit(&apm_infop->apm_lock);
		rc = EIO;
		goto error;
	}
	mutex_exit(&apm_infop->apm_lock);

	/*
	 * CAUTION: We must keep the taskq blocked until we have everything
	 *	done. Otherwise a mode switch will make the state inconsistent.
	 *	Every time we jump to again: the taskq has been released so it
	 *	is possible for ioctl()s to make progress. This also means we
	 *	have to do a complete check every time since the hardware state
	 *	could have changed.
	 */
	audio_sup_taskq_suspend(stpptr->am_taskq);

	/* freeze the channels after freezing the taskq */
	mutex_enter(&statep->as_lock);

	mode = stpptr->am_pstate->apm_mode;	/* reget, it may have changed */

	/*
	 * If in MIXER mode then we look for multiple open()s with the same
	 * PID. If no other AUDIO channels for the PID then we always succeed.
	 * If in COMPAT mode we look for any open()s in the same direction.
	 */
	ASSERT(pid != 0);
	if (mode == AM_MIXER_MODE) {
		for (i = 0, multi_open = 0, tchptr = &statep->as_channels[0];
		    i < max_chs; i++, tchptr++) {

			/* skip non-audio channels and those not allocated */
			mutex_enter(&tchptr->ch_lock);
			if (!(tchptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
			    chptr == tchptr ||
			    tchptr->ch_info.dev_type != AUDIO ||
			    tchptr->ch_info.pid != pid) {
				mutex_exit(&tchptr->ch_lock);
				continue;
			}

			/*
			 * The same process can have separate read and write
			 * open()s. But it can't have two reads or writes,
			 * unless multiple open()s per process are allowed.
			 */
			if (((am_ch_private_t *)tchptr->ch_private)->
			    acp_flags & AM_CHNL_MULTI_OPEN) {
				mutex_exit(&tchptr->ch_lock);
				ch_flags |= AM_CHNL_MULTI_OPEN;
				/* don't need to look any further */
				break;
			} else if (
			    (wantread && (tchptr->ch_dir & AUDIO_RECORD)) ||
			    (wantwrite && (tchptr->ch_dir & AUDIO_PLAY))) {
				mutex_exit(&tchptr->ch_lock);
				/*
				 * Multiple open()s not supported. So let the
				 * taskq continue.
				 */
				audio_sup_taskq_resume(stpptr->am_taskq);

				/* if O_NDELAY then we just return */
				if (ch_flags & AUDIO_NO_SLEEP) {
					mutex_exit(&statep->as_lock);
					rc = EBUSY;
					goto error;
				}

				/* set waiting flags and wait */
				am_set_waiting(statep, pid, AM_SET_WAITING,
				    wantwrite, wantread);

				/* send a signal so other procs will wake up */
				mutex_exit(&statep->as_lock);
				am_send_signal(statep, stpptr);
				mutex_enter(&statep->as_lock);

				/*
				 * Wait for channels to be freed so we can
				 * try again.
				 */
				if (cv_wait_sig(&statep->as_cv,
				    &statep->as_lock) <= 0) {
					/*
					 * Signal wakeup, clear waiting flags
					 * for the PID. We wakeup all waiting
					 * channels, thus they go through their
					 * loops and remark waiting.
					 */
					am_set_waiting(statep, pid,
					    AM_CLEAR_WAITING, wantwrite,
					    wantread);
					mutex_exit(&statep->as_lock);
					rc = EINTR;
					goto error;
				}
				/*
				 * Normal wakeup, clear the waiting flags. If
				 * the channels need to wait they'll set the
				 * flags. That's why we wake all the channels
				 * up, so they'll go through their loop.
				 */
				am_set_waiting(statep, pid, AM_CLEAR_WAITING,
				    wantwrite, wantread);
				cv_broadcast(&statep->as_cv);
				mutex_exit(&statep->as_lock);
				goto again;

			}
			mutex_exit(&tchptr->ch_lock);
		}
	} else {
		ASSERT(mode == AM_COMPAT_MODE);

		/* we can't have two reads or writes at one once */
		mutex_enter(&chptr->ch_lock);
		if ((wantread && stpptr->am_in_chs) ||
		    (wantwrite && stpptr->am_out_chs)) {
			mutex_exit(&chptr->ch_lock);
			/*
			 * Multiple open()s not supported. So let the
			 * taskq continue.
			 */
			audio_sup_taskq_resume(stpptr->am_taskq);

			/* if O_NDELAY then we just return */
			if (ch_flags & AUDIO_NO_SLEEP) {
				mutex_exit(&statep->as_lock);
				rc = EBUSY;
				goto error;
			}

			/* set waiting flags and wait */
			am_set_waiting(statep, pid, AM_SET_WAITING, wantwrite,
			    wantread);

			/* send a signal so other procs will wake up */
			mutex_exit(&statep->as_lock);
			am_send_signal(statep, stpptr);
			mutex_enter(&statep->as_lock);

			/* wait for channels to be freed so we can try again */
			if (cv_wait_sig(&statep->as_cv,
			    &statep->as_lock) <= 0) {
				/*
				 * Signal wakeup, clear waiting flags for the
				 * PID. We wakeup all waiting channels, thus
				 * they go through their loops and remark
				 * waiting.
				 */
				am_set_waiting(statep, pid, AM_CLEAR_WAITING,
				    wantwrite, wantread);
				mutex_exit(&statep->as_lock);
				rc = EINTR;
				goto error;
			}
			/*
			 * Normal wakeup, clear the waiting flags. If the
			 * channels need to wait they'll set the flags. That's
			 * why we wake all the channels up, so they'll go
			 * through their loop.
			 */
			am_set_waiting(statep, pid, AM_CLEAR_WAITING,
			    wantwrite, wantread);
			cv_broadcast(&statep->as_cv);
			mutex_exit(&statep->as_lock);
			goto again;

		}
		mutex_exit(&chptr->ch_lock);
	}

	ASSERT(MUTEX_HELD(&statep->as_lock));
	ASSERT(audio_sup_taskq_suspended(stpptr->am_taskq) ==
	    AUDIO_TASKQ_SUSPENDED);

	/*
	 * If we get here there are no conflicting open()s. However, if in
	 * MIXER mode then we may be limited by the max number of channels,
	 * max number of read channels, and the max number of write channels.
	 * It wasn't easy to check above, so we do it now.
	 */
	if (mode == AM_MIXER_MODE &&
	    (stpptr->am_channels >= max_chs ||
	    (wantread && stpptr->am_in_chs >= stpptr->am_max_in_chs) ||
	    (wantwrite && stpptr->am_out_chs >= stpptr->am_max_out_chs))) {
		/* let the taskq continue working */
		audio_sup_taskq_resume(stpptr->am_taskq);

		/* if O_NDELAY then we just return */
		if (ch_flags & AUDIO_NO_SLEEP) {
			mutex_exit(&statep->as_lock);
			rc = EBUSY;
			goto error;
		}

		/* set waiting flags and wait */
		am_set_waiting(statep, pid, AM_SET_WAITING, wantwrite,
		    wantread);

		/* send a signal so other procs will wake up */
		mutex_exit(&statep->as_lock);
		am_send_signal(statep, stpptr);
		mutex_enter(&statep->as_lock);

		if (cv_wait_sig(&statep->as_cv, &statep->as_lock) <= 0) {
			/*
			 * Signal wakeup, clear waiting flags for the PID.
			 * We wakeup all waiting channels, thus they go
			 * through their loops and remark waiting.
			 */
			am_set_waiting(statep, pid, AM_CLEAR_WAITING,
			    wantwrite, wantread);
			mutex_exit(&statep->as_lock);
			rc = EINTR;
			goto error;
		}
		/*
		 * Normal wakeup, clear the waiting flags. If the channels
		 * need to wait they'll set the flags. That's why we wake all
		 * the channels up, so they'll go through their loop.
		 */
		am_set_waiting(statep, pid, AM_CLEAR_WAITING, wantwrite,
		    wantread);
		cv_broadcast(&statep->as_cv);
		mutex_exit(&statep->as_lock);
		goto again;
	}

	ASSERT(MUTEX_HELD(&statep->as_lock));
	ASSERT(audio_sup_taskq_suspended(stpptr->am_taskq) ==
	    AUDIO_TASKQ_SUSPENDED);

	/*
	 * We have a good channel, all open() semantics pass, so init the ch.
	 *
	 * CAUTION: pid isn't filled in until the very end. Otherwise
	 *	other routines that look for AUDIO or AUDIOCTL channels may
	 *	think that the channel is fully allocated and available for
	 *	use.
	 */
	mutex_enter(&chptr->ch_lock);
	ASSERT(chptr->ch_statep == statep);

	chptr->ch_qptr =		q;
	chptr->ch_wput =		am_wput;
	chptr->ch_wsvc =		am_wsvc;
	chptr->ch_rput =		am_rput;
	chptr->ch_rsvc =		am_rsvc;
	chptr->ch_dir =			ch_flags & AUDIO_BOTH;
	chptr->ch_dev =			*devp;
	chptr->ch_private =		chpptr;
	chptr->ch_info.info_size =	sizeof (audio_info_t);
	chptr->ch_dev_info =		ad_infop->ad_dev_info;

	chpptr->acp_flags =		multi_open;
	chpptr->acp_reading =		wantread;
	chpptr->acp_writing =		wantwrite;

	/* get the minor device for the new channel */
	minor = audio_sup_ch_to_minor(statep, chptr->ch_info.ch_number);
	ATRACE_32("am_open_audio() channel number", chptr->ch_info.ch_number);
	ATRACE_32("am_open_audio() new minor number", minor);

	/*
	 * Setup the channel. We use the audio_info structure allocated above.
	 * If we are in MIXER mode then we keep this structure and it becomes
	 * the virtual state. If in COMPAT mode we free it after we set the
	 * state.
	 *
	 * We init both play and record, that way it is always filled in.
	 * Not all members are filled in, that happens in the ioctl() code.
	 * Thus we have to init the structure so am_audio_set_info() will
	 * ignore them.
	 */
	AUDIO_INIT(iptr, sizeof (*iptr));

	iptr->record.sample_rate =	default_info->record.sample_rate;
	iptr->record.channels =		AUDIO_CHANNELS_MONO;
	iptr->record.precision =	AUDIO_PRECISION_8;
	iptr->record.encoding =		AUDIO_ENCODING_ULAW;
	iptr->record.buffer_size =	ad_infop->ad_record.ad_bsize;
	iptr->record.samples =		0;
	iptr->record.eof =		0;
	iptr->record.pause =		0;
	iptr->record.error =		0;
	iptr->record.waiting =		0;
	iptr->record.minordev =		minor;
	iptr->record.open =		0;
	iptr->record.active =		0;

	iptr->play.sample_rate =	default_info->play.sample_rate;
	iptr->play.channels =		AUDIO_CHANNELS_MONO;
	iptr->play.precision =		AUDIO_PRECISION_8;
	iptr->play.encoding =		AUDIO_ENCODING_ULAW;
	iptr->play.buffer_size =	0;
	iptr->play.samples =		0;
	iptr->play.eof =		0;
	iptr->play.pause =		0;
	iptr->play.error =		0;
	iptr->play.waiting =		0;
	iptr->play.minordev =		minor;
	iptr->play.open =		0;
	iptr->play.active =		0;

	if (mode == AM_MIXER_MODE) {	/* virtual channel */
		iptr->record.gain =	stpptr->am_pstate->apm_rgain;
		iptr->record.balance =	stpptr->am_pstate->apm_rbal;
		iptr->play.gain =	stpptr->am_pstate->apm_pgain;
		iptr->play.balance =	stpptr->am_pstate->apm_pbal;
		chptr->ch_info.info = iptr;
		iptr->output_muted = 0;
		iptr->ref_cnt = 1;
	} else {	/* AM_COMPAT_MODE, physical channel */
		iptr->record.gain =	hw_info->record.gain;
		iptr->record.balance =	hw_info->record.balance;
		iptr->play.gain =	hw_info->play.gain;
		iptr->play.balance =	hw_info->play.balance;
		chptr->ch_info.info = hw_info;
		iptr->output_muted = hw_info->output_muted;
		iptr->ref_cnt = 0;		/* delete struct when done */
	}
	iptr->monitor_gain = hw_info->monitor_gain;

	mutex_exit(&chptr->ch_lock);
	ASSERT(MUTEX_HELD(&statep->as_lock));

	/* before we setup the hardware we need to init src */
	if (ad_infop->ad_codec_type == AM_TRAD_CODEC) {
		if (wantread) {
			ATRACE("am_open_audio() REC., calling src init", chptr);
			mutex_enter(&chptr->ch_lock);
			chpptr->acp_ch_rbuf_size =
				ad_infop->ad_record.ad_conv->ad_src_init(
					AM_SRC_CHPTR2HDL(chptr), AUDIO_RECORD);
			mutex_exit(&chptr->ch_lock);
		}
		if (wantwrite) {
			ATRACE("am_open_audio() PLAY, calling src init", chptr);
			mutex_enter(&chptr->ch_lock);
			chpptr->acp_ch_pbuf_size =
				ad_infop->ad_play.ad_conv->ad_src_init(
					AM_SRC_CHPTR2HDL(chptr), AUDIO_PLAY);
			mutex_exit(&chptr->ch_lock);
		}
	}

	/* set the open flags and increment the counts */
	if (wantread) {
		stpptr->am_in_chs++;
	}
	if (wantwrite) {
		stpptr->am_out_chs++;
	}
	stpptr->am_channels++;

	/* setting the hardware can take a long time, so let channels go */
	mutex_exit(&statep->as_lock);

	/* setup the hardware */
	ASSERT(audio_sup_taskq_suspended(stpptr->am_taskq) ==
	    AUDIO_TASKQ_SUSPENDED);
	if (am_audio_set_info(chptr, iptr, NULL) == AUDIO_FAILURE) {
		ATRACE("am_open_audio() hw set failed", chptr);

		mutex_enter(&statep->as_lock);
		if (wantread) {
			stpptr->am_in_chs--;
		}
		if (wantwrite) {
			stpptr->am_out_chs--;
		}
		stpptr->am_channels--;
		mutex_exit(&statep->as_lock);

		/* let the taskq continue */
		audio_sup_taskq_resume(stpptr->am_taskq);

		rc = EINVAL;

		/* free up any sample rate conv. memory we allocated earlier */
		if (wantread) {
			ad_infop->ad_record.ad_conv->ad_src_exit(
			    AM_SRC_CHPTR2HDL(chptr), AUDIO_RECORD);
		}
		if (wantwrite) {
			ad_infop->ad_play.ad_conv->ad_src_exit(
			    AM_SRC_CHPTR2HDL(chptr), AUDIO_PLAY);
		}

		goto error;
	}

	/*
	 * From here on we can't fail. If in COMPAT mode we need to clean up
	 * the hardware reference counts.
	 */
	if (mode == AM_COMPAT_MODE) {
		kmem_free(iptr, sizeof (*iptr));
		iptr = hw_info;
		iptr->ref_cnt++;
	}
	if (wantread) {
		iptr->record.open = 1;
	}
	if (wantwrite) {
		iptr->play.open = 1;
	}

	/*
	 * For mixer mode we see if there are any AUDIOCTL channels with
	 * this process. If there are then we need to re-associate them
	 * to this channel.
	 *
	 * NOTE: We must still have the taskq frozen.
	 */
	mutex_enter(&statep->as_lock);

	if (mode == AM_MIXER_MODE) {
		/* we have to keep the channels stable */
		for (i = 0, tchptr = &statep->as_channels[0];
		    i < max_chs; i++, tchptr++) {

			/* skip myself, unallocated, and closing channels */
			mutex_enter(&tchptr->ch_lock);
			if (!(tchptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
			    chptr == tchptr ||
			    (tchptr->ch_private &&
			    ((am_ch_private_t *)tchptr->ch_private)->
			    acp_flags & AM_CHNL_CLOSING)) {
				mutex_exit(&tchptr->ch_lock);
				continue;
			}

			/*
			 * Skip if different PIDs, including 0. pid is set
			 * to 0 when am_close_audio*() is entered, so we aren't
			 * associated with a closing channel.
			 */
			if (tchptr->ch_info.pid != pid) {
				mutex_exit(&tchptr->ch_lock);
				continue;
			}

			/* same PID, make sure it's AUDIOCTL */
			if (tchptr->ch_info.dev_type != AUDIOCTL) {
				mutex_exit(&tchptr->ch_lock);
				continue;
			}

			/*
			 * Yes! It's possible that the AUDIOCTL ch is
			 * already attached to an AUDIO ch. If so we
			 * don't muck with it. From this point it is
			 * indeterminate as to what happens with
			 * AUDIOCTL channels. If it isn't we associate
			 * it with this AUDIO channel.
			 */
			if (tchptr->ch_info.info == hw_info) {
				hw_info->ref_cnt--;
				ASSERT(hw_info->ref_cnt >= 1);

				((am_ch_private_t *)
				    tchptr->ch_private)->acp_flags |=
				    AM_CHNL_CONTROL;
				tchptr->ch_info.info = iptr;
				iptr->ref_cnt++;
			}

			/*
			 * we don't break because there can be more
			 * than one AUDIOCTL for any one AUDIO channel.
			 */
			mutex_exit(&tchptr->ch_lock);
		}

		/*
		 * Above we set Codec info, but we need to set the
		 * rest of the info in the iptr structure, except for
		 * hardware related members, which we fill in when
		 * needed.
		 */
		iptr->play.avail_ports = hw_info->play.avail_ports;
		iptr->play.mod_ports = hw_info->play.mod_ports;
		iptr->record.avail_ports = hw_info->record.avail_ports;
		iptr->record.mod_ports = hw_info->record.mod_ports;
	}

	ASSERT(iptr != NULL);
	ASSERT(audio_sup_taskq_suspended(stpptr->am_taskq) ==
	    AUDIO_TASKQ_SUSPENDED);

	/* we start out open and empty */
	chpptr->acp_flags |= (AM_CHNL_OPEN | AM_CHNL_EMPTY);

	/* we've made it through all the checks, so it's safe to make the dev */
	*devp = makedevice(getmajor(*devp), minor);
	ATRACE("am_open_audio() made device", devp);

	mutex_enter(&chptr->ch_lock);
	chptr->ch_dev = *devp;
	mutex_exit(&chptr->ch_lock);

	ASSERT(chptr->ch_info.ch_number ==
			audio_sup_minor_to_ch(statep, minor));

	ATRACE("am_open_audio() qprocson()", chptr);

	/*
	 * WARNING: Do this after we can no longer fail or we will have a
	 * potential memory leak. Also, do it before qprocson().
	 */
	audio_sup_set_qptr(q, *devp, chptr);

	/* schedule the queue */
	qprocson(q);

	/*
	 * Now we can set the pid. We don't need to lock the structure because
	 * the worst thing that will happen is the channel will be skipped and
	 * then picked up on the next sweep through the channels. Once this is
	 * set the other mixer routines will see the channel.
	 *
	 * CAUTION: This must be after qprocson(), otherwise other threads will
	 *	try to process STREAMS messages on a partially started stream.
	 *	This will cause a panic. This shows up in am_send_signal().
	 */
	mutex_enter(&chptr->ch_lock);
	chptr->ch_info.pid = pid;
	mutex_exit(&chptr->ch_lock);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*chpptr));

	/* thaw the taskq AFTER setting the pid */
	audio_sup_taskq_resume(stpptr->am_taskq);

	mutex_exit(&statep->as_lock);

	/* MUST be after inc. above - not locked any more, start recording */
	if (wantread) {
		mutex_enter(&chptr->ch_lock);
		if (am_set_record_streams(chptr) == AUDIO_SUCCESS) {
			chpptr->acp_flags |= AM_CHNL_RSTREAMS_SET;
			ATRACE("am_open() record STREAMS water marks adjusted",
			    0);
#ifdef DEBUG
		} else {
			ATRACE("am_open() record STREAMS water marks not "
			    "adjusted", 0);
#endif
		}
		mutex_exit(&chptr->ch_lock);

		/* start recording, regardless of mode or Codec type */
		ATRACE("am_open_audio() starting record DMA engine", statep);
		/* set before start for mode switch */
		hw_info->record.active = 1;
		iptr->record.active = 1;
		iptr->record.pause = 0;
		if (am_ad_start_record(statep, stpptr, ad_infop,
		    chptr->ch_info.ch_number, AM_SERIALIZE) == AUDIO_FAILURE) {
			iptr->record.active = 0;
			hw_info->record.active = 0;
			/* we don't change pause flag if failed to start */
		}
	}

	ATRACE("am_open_audio() successful", statep);

	am_send_signal(statep, stpptr);

	return (AUDIO_SUCCESS);

error:
	kmem_free(chpptr->acp_play_samp_buf, chpptr->acp_psb_size);
	kmem_free(chpptr, sizeof (*chpptr));
	if (iptr && iptr != hw_info) {
		kmem_free(iptr, sizeof (*iptr));
	}
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*chpptr));

	mutex_enter(&chptr->ch_lock);
	chptr->ch_private = NULL;
	chptr->ch_info.info = NULL;
	mutex_exit(&chptr->ch_lock);

	(void) audio_sup_free_ch(chptr);

	/* tell the Audio Driver to free up ch resources */
	am_ad_teardown(statep, stpptr, ad_infop, chptr->ch_info.ch_number,
	    (ch_flags & AUDIO_BOTH));
	ATRACE("am_open_audio() ad_teardown() returned", 0);

	ATRACE_32("am_open_audio() at \"error\"", rc);

	return (rc);

}	/* am_open_audio() */

/*
 * am_open_audioctl()
 *
 * Description:
 *	AUDIOCTL channel specific open() routine. There are lots of rules here,
 *	but not as bad audio am_open_audio(). We don't worry about whether the
 *	channel is opened for read or writing as we don't read() or write()
 *	the device.
 *
 *	How AUDIOCTL channels are allocated:
 *	    COMPAT MODE
 *		always points to the hardware
 *	    MIXER MODE
 *		if no AUDIO channels open() for the process then points to
 *		the hardware
 *		if one AUDIO channel open() for the process then point to that
 *		channel, thus it is virtual
 *		if more than one AUDIO channel open() for the process then
 *		point to the first AUDIO channel, this includes multiple open()s
 *		as well as one for read and one for write, which isn't the same
 *		as a multiple open()
 *
 *	NOTE: In user context so it is okay for memory allocation to sleep.
 *
 * Arguments:
 *	queue_t		*q		Pointer to the read queue
 *	dev_t		*devp		Pointer to the device
 *	int		oflag		Open flags
 *	int		sflag		STREAMS flag
 *	cred_t		*credp		Ptr to the user's credential structure
 *
 * Returns:
 *	AUDIO_SUCCESS			Successfully opened the device
 *	errno				Error number for failed open()
 */
/*ARGSUSED*/
int
am_open_audioctl(queue_t *q, dev_t *devp, int oflag, int sflag, cred_t *credp)
{
	audio_state_t		*statep;
	audio_apm_info_t	*apm_infop;
	audio_ch_t		*chptr;
	audio_ch_t		*tchptr;
	audio_info_t		*hw_info;
	audio_info_t		*iptr;
	am_ch_private_t		*chpptr = 0;
	am_ad_info_t		*ad_infop;
	am_apm_private_t	*stpptr;
	pid_t			pid;
	ulong_t			minor;
	int			ch_flags;
	int			error;
	int			i;
	int			max_chs;
	int			mode;

	ATRACE("in am_open_audioctl()", devp);

	/* get the state structure */
	if ((statep = audio_sup_devt_to_state(*devp)) == NULL) {
		ATRACE_32(
		    "am_open_audioctl() audio_sup_devt_to_state() failed", 0);
		return (EIO);
	}

	/* this driver does only a conventional open(), i.e., no clone opens */
	if (sflag) {
		ATRACE("am_open_audioctl() clone open() failure", sflag);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE, "mixer:"
		    "only conventional open()s are supported");
		return (EIO);
	}

	/* figure out if allocates should sleep or not */
	ch_flags = (oflag & (O_NONBLOCK|O_NDELAY)) ?
	    AUDIO_NO_SLEEP : AUDIO_SLEEP;

	/* get the PID for the process opening the channel */
	pid = ddi_get_pid();

	/* get pointers to various data structures */
	if ((apm_infop = audio_sup_get_apm_info(statep, AUDIOCTL)) == NULL) {
		ATRACE("am_open_audioctl() audio_sup_get_apm_info() failed", 0);
		return (EIO);
	}
	stpptr = apm_infop->apm_private;
	hw_info = &stpptr->am_hw_info;
	ad_infop = apm_infop->apm_ad_infop;
	max_chs = statep->as_max_chs;

	/* see if we've been offlined */
	mutex_enter(&apm_infop->apm_lock);
	if (!(stpptr->am_flags & AM_PRIV_ON_LINE)) {
		ATRACE_32("am_open_audio() offline", stpptr->am_flags);
		mutex_exit(&apm_infop->apm_lock);
		return (EIO);
	}
	mutex_exit(&apm_infop->apm_lock);

	/*
	 * Before we go any further we allocate the channel and all memory
	 * that we'll need. That way we don't sleep holding any locks or
	 * the taskq.
	 */
	if ((chptr = audio_sup_alloc_ch(statep, &error, AUDIOCTL, ch_flags)) ==
	    NULL) {
		ATRACE("am_open_audioctl() alloc returning", statep);
		return (error);
	}

	ASSERT(chptr->ch_info.pid == 0);

	chpptr = kmem_zalloc(sizeof (*chpptr), KM_SLEEP);


	/*
	 * CAUTION: We must keep the taskq blocked until we have everything
	 *	done. Otherwise a mode switch will make the state inconsistent.
	 */
	audio_sup_taskq_suspend(stpptr->am_taskq);

	/* freeze channel allocation */
	mutex_enter(&statep->as_lock);
	mutex_enter(&chptr->ch_lock);

	/* mode may have changed, so re-get */
	mode = stpptr->am_pstate->apm_mode;

	/*
	 * We have a good channel, all open() semantics pass, so init the ch.
	 *
	 * CAUTION: pid isn't filled in until the very end. Otherwise
	 *	other routines that look for AUDIO or AUDIOCTL channels may
	 *	think that the channel is fully allocated and available for
	 *	use.
	 */
	chptr->ch_qptr =		q;
	ASSERT(chptr->ch_statep == statep);
	chptr->ch_wput =		am_wput;
	chptr->ch_wsvc =		am_wsvc;
	chptr->ch_rput =		am_rput;
	chptr->ch_rsvc =		am_rsvc;
	chptr->ch_dir =			0;
	chptr->ch_dev =			*devp;
	chptr->ch_private =		chpptr;
	chptr->ch_info.info_size =	sizeof (audio_info_t);
	chptr->ch_dev_info =		ad_infop->ad_dev_info;

	chpptr->acp_flags =		0;

	/* get the minor device for the new channel */
	minor = audio_sup_ch_to_minor(statep, chptr->ch_info.ch_number);
	ATRACE_32("am_open_audioctl() channel number",
	    chptr->ch_info.ch_number);
	ATRACE_32("am_open_audioctl() new minor number", minor);

	/*
	 * Update the number of AUDIOCTL chs open for the mixer. We
	 * don't bother updating the read or write counts because
	 * they don't make sense for AUDIOCTL channels.
	 */
	stpptr->am_channels++;

	mutex_exit(&chptr->ch_lock);

	/* figure out the audio_info structure, and initialize */
	if (mode == AM_MIXER_MODE) {
		/* is this AUDIOCTL channel related to an AUDIO ch? */
		for (i = 0, tchptr = &statep->as_channels[0];
		    i < max_chs; i++, tchptr++) {
			/* skip myself, unallocated & diff. PID channels */
			mutex_enter(&tchptr->ch_lock);
			if (!(tchptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
			    tchptr == chptr ||
			    tchptr->ch_info.dev_type != AUDIO ||
			    tchptr->ch_info.pid != pid) {
				mutex_exit(&tchptr->ch_lock);
				continue;
			}

			/* yes, so link the info structs */
			ATRACE("am_open_audioctl() AUDIOCTL related", chptr);

			/* we lock the channel, not the state */
			iptr = tchptr->ch_info.info;
			chptr->ch_info.info = iptr;
			iptr->ref_cnt++;
			chpptr->acp_flags |= AM_CHNL_CONTROL;
			mutex_exit(&tchptr->ch_lock);
			break;
		}

		if (i == max_chs) {	/* no, so link to HW */
			ATRACE("am_open_audioctl() AUDIOCTL not related",
			    chptr);

			iptr = hw_info;
			mutex_enter(&chptr->ch_lock);
			chptr->ch_info.info = iptr;
			mutex_exit(&chptr->ch_lock);
			iptr->ref_cnt++;
		}
	} else {
		/* in COMPAT mode there is only one state structure */
		ATRACE("am_open_audioctl() AUDIOCTL: mode == AM_COMPAT_MODE",
		    chptr);

		iptr = hw_info;
		mutex_enter(&chptr->ch_lock);
		chptr->ch_info.info = iptr;
		mutex_exit(&chptr->ch_lock);
		iptr->ref_cnt++;
	}

	/* we have all the state info, so we can let the state go */
	mutex_exit(&statep->as_lock);

	ATRACE("am_open_audioctl() AUDIOCTL iptr", iptr);
	ASSERT(iptr != NULL);

	mutex_enter(&chptr->ch_lock);
	/* we start out open and empty */
	chpptr->acp_flags |= (AM_CHNL_OPEN | AM_CHNL_EMPTY);

	ASSERT(iptr != NULL);

	/* we've made it through all the checks, so it's safe to make the dev */
	*devp = makedevice(getmajor(*devp), minor);
	ATRACE("am_open_audioctl() made device", devp);

	ASSERT(chptr->ch_info.ch_number ==
			audio_sup_minor_to_ch(statep, minor));

	ATRACE("am_open_audioctl() qprocson()", chptr);
	mutex_exit(&chptr->ch_lock);

	/*
	 * WARNING: Do this after we can no longer fail or we will have a
	 * potential memory leak. Also, do it before qprocson().
	 */
	audio_sup_set_qptr(q, *devp, chptr);

	/* schedule the queue */
	qprocson(q);

	/*
	 * Now we can set the pid. We don't need to lock the structure because
	 * the worst thing that will happen is the channel will be skipped and
	 * then picked up on the next sweep through the channels. Once this is
	 * set the other mixer routines will see the channel.
	 *
	 * CAUTION: This must be after qprocson(), otherwise other threads will
	 *	try to process STREAMS messages on a partially started stream.
	 *	This will cause a panic. This shows up in am_send_signal().
	 */
	mutex_enter(&chptr->ch_lock);
	chptr->ch_info.pid = pid;
	mutex_exit(&chptr->ch_lock);

	/* thaw the taskq AFTER setting the pid */
	audio_sup_taskq_resume(stpptr->am_taskq);

	ATRACE("am_open_audioctl() successful", statep);

	am_send_signal(statep, stpptr);

	return (AUDIO_SUCCESS);

}	/* am_open_audioctl() */

/*
 * am_close_audio()
 *
 * Description:
 *	Close a minor device, returning the minor number to the pool so that
 *	open(2) may use it again.
 *
 *	chpptr->acp_flags is used to coordinate draining the write queue.
 *	am_close_audio() sets flags to AM_CHNL_CLOSING. It then waits for the
 *	flags to have AM_CHNL_EMPTY set by am_get_audio() when all available
 *	data has been drained and played. If a signal interrupts the draining
 *	the queue is flushed and the AM_CHNL_OPEN flag is cleared.
 *	am_get_audio() then ignores this channel until it is open()ed again.
 *
 *	There are a number of rules that have to be followed when closing
 *	an audio channel. Some of them depend on the state of the mixer.
 *	Thus we must stop any mode switching. This is done by freezing the
 *	taskq.
 *
 *	NOTE: When ch_info.info is set and ref_cnt is changed statep->as_lock
 *		is used and the taskq MUST be frozen. Otherwise a mode switch
 *		will mess things up.
 *
 *	NOTE: We need to behave differently for a normal close() vs. the user
 *		app calling exit(). Unfortunately there isn't a DDI compliant
 *		method for doing this, so we take a look at the current thread
 *		and see if it's exiting or not. This is how the old diaudio
 *		module did it.
 *
 * Arguments:
 *	queue_t		*q	Pointer to the read queue
 *	int		flag	File status flag
 *	cred_t		*credp	Pointer to the user's credential structure
 *
 * Returns:
 *	AUDIO_SUCCESS		Successfully closed the device
 *	errno			Error number for failed close()
 */
/*ARGSUSED*/
int
am_close_audio(queue_t *q, int flag,  cred_t *credp)
{
	audio_info_t		*info;
	audio_ch_t		*chptr = (audio_ch_t *)
				    audio_sup_get_qptr_data(q);
	audio_ch_t		*tchptr;
	audio_state_t		*statep = chptr->ch_statep;
	audio_apm_info_t	*apm_infop = chptr->ch_apm_infop;
	audio_info_t		*hw_info = apm_infop->apm_ad_state;
	audio_info_t		*alt_info = NULL;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	am_ch_private_t		*chpptr = chptr->ch_private;
	am_ad_info_t		*ad_infop = chptr->ch_apm_infop->apm_ad_infop;
	mblk_t			*rec_mp;
	pid_t			save_pid;
	int			codec_type = ad_infop->ad_codec_type;
	int			dir = 0;
	int			i;
	int			max_chs;
	int			mode;
	int			tmp_stream;
	int			was_reading;
	int			was_writing;

	ATRACE("in am_close_audio()", chptr);
	ATRACE_32("am_close_audio() channel number", chptr->ch_info.ch_number);

	ASSERT(q == chptr->ch_qptr);

	/* mark the channel as in the process of being closed */
	mutex_enter(&chptr->ch_lock);
	was_reading = chpptr->acp_reading;
	was_writing = chpptr->acp_writing;
	chpptr->acp_flags |= AM_CHNL_CLOSING;
	mutex_exit(&chptr->ch_lock);

	/* set the direction for ad_teardown() */
	if (was_reading) {
		dir |= AUDIO_RECORD;
	}
	if (was_writing) {
		dir |= AUDIO_PLAY;
	}

	/*
	 * Wait for queue to drain, unless we were signaled in AUDIO_DRAIN
	 * or the process is exiting (in which case we use the hack).
	 */
	ATRACE("am_close_audio() checking to see if need to wait", chptr);

	if (was_writing) {
		/* we now need the info, so protect it by freezing the taskq */
		audio_sup_taskq_suspend(stpptr->am_taskq);

		mutex_enter(&chptr->ch_lock);

		info = chptr->ch_info.info;

		if (info->play.active && !info->play.pause) {
			/* release the taskq so it can continue */
			audio_sup_taskq_resume(stpptr->am_taskq);
			ATRACE("am_close_audio() need to wait", chptr);
			while (!(chpptr->acp_flags & AM_CHNL_EMPTY) &&
			    !(curthread->t_proc_flag & TP_LWPEXIT)) {
				ATRACE_32("am_close_audio() not empty",
				    chpptr->acp_flags);

				/* wait for drain to complete */
				if (cv_wait_sig(&chptr->ch_cv,
				    &chptr->ch_lock) <= 0) {
					ATRACE("am_close_audio() signal wakeup",
					    chptr);

					break;
				}
				ATRACE_32("am_close_audio() normal wakeup",
				    chpptr->acp_flags);
			}
			ATRACE_32("am_close_audio() empty", chpptr->acp_flags);

			/* clear the writing flag, for mode switching */
			chpptr->acp_writing = 0;

			mutex_exit(&chptr->ch_lock);
		} else {
			mutex_exit(&chptr->ch_lock);
			/* release the taskq so it can continue */
			audio_sup_taskq_resume(stpptr->am_taskq);
		}
	}

	/*
	 * It is possible an old AUDIO_DRAIN, which was interrupted, is
	 * still outstanding. So just in case, we see of there's an mblk_t
	 * hanging around. If so then we send it back. The STREAMS head will
	 * ignore it if appropriate.
	 *
	 * The channel is marked as empty. Thus if the process is killed or
	 * the cv_wait_sig() returns we force the AUDIO_DRAIN ioctl() to
	 * return. This is okay since we will be flushing any queued up audio
	 * and closing the STREAMS q.
	 */
	mutex_enter(&chptr->ch_lock);
	chpptr->acp_flags |= AM_CHNL_EMPTY;
	am_audio_drained(chptr);
	mutex_exit(&chptr->ch_lock);

	/* wait for queued tasks to clear */
	audio_sup_taskq_wait(stpptr->am_taskq);

	/* the mode & info struct mean something ONLY when the mode is frozen */
	audio_sup_taskq_suspend(stpptr->am_taskq);

	mode = stpptr->am_pstate->apm_mode;
	info =	chptr->ch_info.info;

	/*
	 * Shutdown play and record. We shut down play first because it could
	 * take a long time to shut down and we don't want to stop recording
	 * too soon.
	 */
	mutex_enter(&statep->as_lock);
	mutex_enter(&chptr->ch_lock);

	/* mark the channel closed so we can shut down the STREAMS queue */
	chpptr->acp_flags &= ~AM_CHNL_OPEN;

	/*
	 * We shutdown the device if in COMPAT mode or for multi-stream
	 * Codecs, or if this is the last playing/recording stream.
	 */
	if (was_writing) {
		if (mode == AM_COMPAT_MODE || codec_type == AM_MS_CODEC ||
		    stpptr->am_out_chs == 1) {
			ATRACE("am_close_audio() stopping play", statep);
			mutex_exit(&statep->as_lock);
			tmp_stream = chptr->ch_info.ch_number;
			mutex_exit(&chptr->ch_lock);
			am_ad_stop_play(statep, stpptr, ad_infop, tmp_stream);
			mutex_enter(&statep->as_lock);
			mutex_enter(&chptr->ch_lock);
			info->play.active = 0;
			hw_info->play.active = 0;
			info->play.pause = 0;

			/* make sure a mode switch wakes up */
			mutex_enter(&stpptr->am_mode_lock);
			cv_signal(&stpptr->am_mode_cv);
			mutex_exit(&stpptr->am_mode_lock);
		}

		/* clear the writing flag, for mode switching */
		chpptr->acp_writing = 0;
	}
	if (was_reading) {
		if (mode == AM_COMPAT_MODE || codec_type == AM_MS_CODEC ||
		    stpptr->am_in_chs == 1) {
			ATRACE("am_close_audio() stopping record", statep);
			mutex_exit(&statep->as_lock);
			tmp_stream = chptr->ch_info.ch_number;
			mutex_exit(&chptr->ch_lock);
			am_ad_stop_record(statep, stpptr, ad_infop, tmp_stream);
			mutex_enter(&statep->as_lock);
			mutex_enter(&chptr->ch_lock);
			info->record.active = 0;
			hw_info->record.active = 0;
			info->record.pause = 0;
		}

		/* send any recorded data that may still be hanging around */
		if (chpptr->acp_rec_mp) {
			info->record.samples += (chpptr->acp_rec_mp->b_wptr -
			    chpptr->acp_rec_mp->b_rptr) /
			    (info->record.channels *
			    (info->record.precision >> AUDIO_PRECISION_SHIFT));

			rec_mp = chpptr->acp_rec_mp;
			chpptr->acp_rec_mp = NULL;

			mutex_exit(&chptr->ch_lock);
			mutex_exit(&statep->as_lock);
			putnext(RD(q), rec_mp);
			mutex_enter(&statep->as_lock);
			mutex_enter(&chptr->ch_lock);

			chpptr->acp_rec_mp = NULL;
		}

		/* clear the reading flag, for mode switching */
		chpptr->acp_reading = 0;
	}

	/* save the gain and balance for the next open() */
	if (was_writing) {
		stpptr->am_pstate->apm_pgain = info->play.gain;
		stpptr->am_pstate->apm_pbal = info->play.balance;
	}
	if (was_reading) {
		stpptr->am_pstate->apm_rgain = info->record.gain;
		stpptr->am_pstate->apm_rbal = info->record.balance;
	}

	/*
	 * Clear the pid field - keeps this channel from being used while the
	 * contents are being freed. But save the pid because we need it later.
	 *
	 * CAUTION: The taskq must be blocked before the PID is set to 0.
	 *	Otherwise switching modes can happen in the middle of closing,
	 *	which results in a bad reference count.
	 */
	save_pid = chptr->ch_info.pid;
	chptr->ch_info.pid = 0;

	mutex_exit(&chptr->ch_lock);

	/* we are modifying mixer global data, so lock the mixer */
	mutex_enter(&apm_infop->apm_lock);

	ASSERT(stpptr->am_channels > 0);
	ASSERT(stpptr->am_in_chs >= 0);
	ASSERT(stpptr->am_out_chs >= 0);

	stpptr->am_channels--;

	if (was_reading) {
		ASSERT(stpptr->am_in_chs > 0);
		stpptr->am_in_chs--;
		if (stpptr->am_in_chs == 0) {
			/* turn off capture */
			info->record.active = 0;
		}

		info->record.open = 0;
		info->record.waiting = 0;
		info->record.active = 0;
		info->record.pause = 0;
		info->record.samples = 0;
		info->record.error = 0;
	}

	if (was_writing) {
		ASSERT(stpptr->am_out_chs > 0);
		stpptr->am_out_chs--;

		info->play.open = 0;
		info->play.waiting = 0;
		info->play.active = 0;
		info->play.pause = 0;
		info->play.samples = 0;
		info->play.eof = 0;
		info->play.error = 0;
	}

	mutex_exit(&apm_infop->apm_lock);
	mutex_exit(&statep->as_lock);

	/*
	 * If in MIXER mode the next step for closing the AUDIO channel is to
	 * fix any AUDIOCTL channels that were pointing to this channel. Even
	 * if multiple open()s aren't allowed we can still have one channel for
	 * read and one for write. If there are multiple open()s then there
	 * could be many channels. Thus we just look for the first AUDIO
	 * channel with the same PID. If there isn't then we point to the
	 * hardware.
	 *
	 * If in COMPAT mode then we are already pointing to hardware so
	 * we skip this step.
	 */
	max_chs = statep->as_max_chs;
	mutex_enter(&statep->as_lock);		/* freeze the channels */

	if (mode == AM_MIXER_MODE) {
		/* first find the first AUDIO channel */
		ASSERT(alt_info == 0);
		for (i = 0, tchptr = &statep->as_channels[0];
		    i < max_chs; i++, tchptr++) {
			/* skip the same and unallocated channels */
			mutex_enter(&tchptr->ch_lock);
			if (!(tchptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
			    tchptr == chptr ||
			    tchptr->ch_info.pid == 0) {
				mutex_exit(&tchptr->ch_lock);
				continue;
			}

			/* skip if not AUDIOCTL or different PIDs */
			if (tchptr->ch_info.dev_type != AUDIO ||
			    tchptr->ch_info.pid != save_pid) {
				mutex_exit(&tchptr->ch_lock);
				continue;
			}

			alt_info = tchptr->ch_info.info;

			mutex_exit(&tchptr->ch_lock);

			break;
		}
		if (alt_info == NULL) {
			/* no match found, so set to hardware */
			alt_info = &stpptr->am_hw_info;
		}

		/* next update the AUDIOCTL chs to point to the correct ch */
		for (i = 0, tchptr = &statep->as_channels[0];
		    i < max_chs; i++, tchptr++) {
			/* skip the same and unallocated channels */
			mutex_enter(&tchptr->ch_lock);
			if (!(tchptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
			    tchptr == chptr ||
			    tchptr->ch_info.pid == 0) {
				mutex_exit(&tchptr->ch_lock);
				continue;
			}

			/* skip if not AUDIOCTL or different PIDs */
			if (tchptr->ch_info.dev_type != AUDIOCTL ||
			    tchptr->ch_info.pid != save_pid) {
				mutex_exit(&tchptr->ch_lock);
				continue;
			}

			ATRACE("am_close_audio() setting AUDIOCTL info",
			    alt_info);
			ATRACE_32("am_close_audio() setting AUDIOCTL info, ch",
			    i);

			/*
			 * This is the same PID, so fix info pointers. We check
			 * to see if the AUDIOCTL channel is already pointing
			 * to alt_info. If so then we don't have to do a thing.
			 * But if it doesn't then we have to decrement the
			 * count for where it points and then reset and
			 * increment the new reference count.
			 */
			if (tchptr->ch_info.info == alt_info) {
				/* the same, so continue */
				mutex_exit(&tchptr->ch_lock);
				continue;
			}

			/* different, so update counters and pointer */
			((audio_info_t *)tchptr->ch_info.info)->ref_cnt--;
			tchptr->ch_info.info = alt_info;
			alt_info->ref_cnt++;
			mutex_exit(&tchptr->ch_lock);
		}
	}

	mutex_exit(&statep->as_lock);

	/* make sure we aren't closing while someone is busy */
	mutex_enter(&chptr->ch_lock);
	while (chpptr->acp_busy_cnt) {
		ATRACE_32("am_close_audio() in putnext(), calling cv_wait()",
		    chpptr->acp_flags);

		chpptr->acp_flags |= AM_CHNL_SIGNAL_NEEDED;

		/* wait for the count to go to 0 */
		cv_wait(&chptr->ch_cv, &chptr->ch_lock);
		ATRACE("am_close_audio() putnext() cv wakeup", chptr);
	}

	/*
	 * Mark that qprocsoff() has been called, even though technically it
	 * hasn't. However, it will eliminate the race condition between
	 * releasing the lock and the qprocsoff() below.
	 */
	chpptr->acp_flags |= AM_CHNL_QPROCSOFF;

	mutex_exit(&chptr->ch_lock);

	ATRACE("am_close_audio() flushing q", chptr);
	flushq(RD(q), FLUSHALL);

	/* unschedule the queue */
	ATRACE("am_close_audio() qprocsoff()", chptr);
	qprocsoff(q);

	/*
	 * Remove the private data from the q, AFTER turning the q off.
	 * If this is done before qprocsoff() then any STREAMS call
	 * between these two would find bad qptr data and panic.
	 */
	audio_sup_free_qptr(q);

	/* we have to reget this because it could have changed */
	info =	chptr->ch_info.info;

	/* take care of references to the audio state structure */
	mutex_enter(&statep->as_lock);
	if (info->ref_cnt <= 1) {
		/*
		 * Need to free the buffer. We don't need to lock because
		 * only this thread can now be using this channel.
		 */
		ASSERT(info != apm_infop->apm_ad_state);
		kmem_free(info, sizeof (audio_info_t));
	} else {
		info->ref_cnt--;
	}
	mutex_exit(&statep->as_lock);

	/* release the taskq AFTER we don't care about the mode */
	audio_sup_taskq_resume(stpptr->am_taskq);

	/* free the sample rate conversion routine buffers */
	if (codec_type == AM_TRAD_CODEC) {
		if (was_writing) {
			ad_infop->ad_play.ad_conv->ad_src_exit(
			    AM_SRC_CHPTR2HDL(chptr), AUDIO_PLAY);
		}
		if (was_reading) {
			ad_infop->ad_record.ad_conv->ad_src_exit(
			    AM_SRC_CHPTR2HDL(chptr), AUDIO_RECORD);
		}
	}

	/*
	 * Tell the Audio Driver to free up any channel config info.
	 * This may block, which is why we do it without any locks held
	 * or the taskq frozen.
	 */
	am_ad_teardown(statep, stpptr, ad_infop, chptr->ch_info.ch_number, dir);
	ATRACE("am_close_audio() ad_teardown() returned", 0);

	mutex_enter(&chptr->ch_lock);

	/* free all the buffers */
	if (chpptr->acp_play_samp_buf) {
		kmem_free(chpptr->acp_play_samp_buf, chpptr->acp_psb_size);
		chpptr->acp_play_samp_buf = NULL;
		chpptr->acp_psb_size = 0;
	}
	if (chpptr->acp_ch_psrc1) {
		kmem_free(chpptr->acp_ch_psrc1, chpptr->acp_ch_psrc_siz);
		chpptr->acp_ch_psrc1 = NULL;
	}
	if (chpptr->acp_ch_psrc2) {
		kmem_free(chpptr->acp_ch_psrc2, chpptr->acp_ch_psrc_siz);
		chpptr->acp_ch_psrc2 = NULL;
	}
	chpptr->acp_ch_psrc_siz = 0;
	if (chpptr->acp_ch_pconv1) {
		kmem_free(chpptr->acp_ch_pconv1, chpptr->acp_ch_pconv_siz);
		chpptr->acp_ch_pconv1 = NULL;
	}
	if (chpptr->acp_ch_pconv2) {
		kmem_free(chpptr->acp_ch_pconv2, chpptr->acp_ch_pconv_siz);
		chpptr->acp_ch_pconv2 = NULL;
	}
	chpptr->acp_ch_pconv_siz = 0;
	if (chpptr->acp_ch_rsrc1) {
		kmem_free(chpptr->acp_ch_rsrc1, chpptr->acp_ch_rsrc_siz);
		chpptr->acp_ch_rsrc1 = NULL;
	}
	if (chpptr->acp_ch_rsrc2) {
		kmem_free(chpptr->acp_ch_rsrc2, chpptr->acp_ch_rsrc_siz);
		chpptr->acp_ch_rsrc2 = NULL;
	}
	chpptr->acp_ch_rsrc_siz = 0;
	if (chpptr->acp_ch_rconv1) {
		kmem_free(chpptr->acp_ch_rconv1, chpptr->acp_ch_rconv_siz);
		chpptr->acp_ch_rconv1 = NULL;
	}
	if (chpptr->acp_ch_rconv2) {
		kmem_free(chpptr->acp_ch_rconv2, chpptr->acp_ch_rconv_siz);
		chpptr->acp_ch_rconv2 = NULL;
	}
	chpptr->acp_ch_rconv_siz = 0;

	ASSERT(chpptr->acp_rec_mp == NULL);

	/* send the close signal */
	mutex_exit(&chptr->ch_lock);
	am_send_signal(statep, stpptr);
	mutex_enter(&chptr->ch_lock);

	kmem_free(chpptr, sizeof (*chpptr));
	chptr->ch_private = NULL;

	/* wait until the very end to flush */
	ATRACE("am_close_audio() flushing messages", chptr);
	audio_sup_flush_audio_data(chptr);

	/* audio_sup_free_ch() requires the info ptr to be NULLed */
	chptr->ch_info.info = NULL;

	mutex_exit(&chptr->ch_lock);

	ATRACE("am_close_audio() calling audio_free_ch()", chptr);
	if (audio_sup_free_ch(chptr) == AUDIO_FAILURE) {
		/* not much we can do if this fails */
		ATRACE("am_close_audio() audio_sup_free_ch() failed", chptr);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "close_audio() audio_sup_free_ch() error");
	}

	ATRACE("am_close_audio() successful", 0);
	return (AUDIO_SUCCESS);

}	/* am_close_audio() */

/*
 * am_close_audioctl()
 *
 * Description:
 *	Close a minor device, returning the minor number to the pool so that
 *	open(2) may use it again.
 *
 *	NOTE: When ch_info.info is set and ref_cnt is changed statep->as_lock
 *		is used and the taskq MUST be frozen. Otherwise a mode switch
 *		will mess things up.
 *
 * Arguments:
 *	queue_t		*q	Pointer to the read queue
 *	int		flag	File status flag
 *	cred_t		*credp	Pointer to the user's credential structure
 *
 * Returns:
 *	AUDIO_SUCCESS		Successfully closed the device
 *	errno			Error number for failed close()
 */
/*ARGSUSED*/
int
am_close_audioctl(queue_t *q, int flag,  cred_t *credp)
{
	audio_info_t		*info;
	audio_ch_t		*chptr = (audio_ch_t *)
				    audio_sup_get_qptr_data(q);
	audio_state_t		*statep = chptr->ch_statep;
	audio_apm_info_t	*apm_infop = chptr->ch_apm_infop;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	am_ch_private_t		*chpptr = chptr->ch_private;

	ATRACE("in am_close_audioctl()", chptr);
	ATRACE_32("am_close_audioctl() channel number",
	    chptr->ch_info.ch_number);

	ASSERT(q == chptr->ch_qptr);

	/* mark the channel as in the process of being closed */
	mutex_enter(&chptr->ch_lock);
	chpptr->acp_flags |= AM_CHNL_CLOSING;
	mutex_exit(&chptr->ch_lock);

	/* wait for queued tasks to clear */
	audio_sup_taskq_wait(stpptr->am_taskq);

	/* we now need everything stable, so freeze the taskq */
	audio_sup_taskq_suspend(stpptr->am_taskq);

	/* mark the channel as being closed */
	mutex_enter(&chptr->ch_lock);
	chpptr->acp_flags = 0;

	/*
	 * Clear the pid field - keeps this channel from being used while the
	 * contents are being freed.
	 *
	 * CAUTION: The taskq must be blocked before the PID is set to 0.
	 *	Otherwise switching modes can happen in the middle of closing,
	 *	which results in a bad reference count.
	 */
	chptr->ch_info.pid = 0;

	/* make sure we aren't closing while someone is busy */
	while (chpptr->acp_busy_cnt) {
		ATRACE_32("am_close_audioctl() in putnext(), calling cv_wait()",
		    chpptr->acp_flags);

		chpptr->acp_flags |= AM_CHNL_SIGNAL_NEEDED;

		/* wait for the count to go to 0 */
		cv_wait(&chptr->ch_cv, &chptr->ch_lock);
		ATRACE("am_close_audioctl() putnext() cv wakeup", chptr);
	}

	/*
	 * Mark that qprocsoff() has been called, even though technically it
	 * hasn't. However, it will eliminate the race condition between
	 * releasing the lock and the qprocsoff() below.
	 */
	chpptr->acp_flags |= AM_CHNL_QPROCSOFF;

	mutex_exit(&chptr->ch_lock);

	ATRACE("am_close_audioctl() flushing q", chptr);
	flushq(RD(q), FLUSHALL);

	/* unschedule the queue */
	ATRACE("am_close_audioctl() qprocsoff()", chptr);
	qprocsoff(q);

	/*
	 * Remove the private data from the q, AFTER turning the q off.
	 * If this is done before qprocsoff() then any STREAMS call
	 * between these two would find bad qptr data and panic.
	 */
	audio_sup_free_qptr(q);

	/* we are modifying mixer global data, so lock the mixer */
	mutex_enter(&statep->as_lock);
	mutex_enter(&apm_infop->apm_lock);

	ASSERT(stpptr->am_channels > 0);
	ASSERT(stpptr->am_in_chs >= 0);
	ASSERT(stpptr->am_out_chs >= 0);

	stpptr->am_channels--;

	mutex_exit(&apm_infop->apm_lock);
	mutex_exit(&statep->as_lock);

	info = chptr->ch_info.info;

	/*
	 * Unlike AUDIO channels the reference count can never be 1. That's
	 * because AUDIOCTL channels in COMPAT mode always increment the
	 * count, as they do in MIXER mode when the process doesn't have an
	 * AUDIO channel open as well. If in MIXER mode with an AUDIO channel
	 * in the same process then the AUDIO channels reference count is
	 * used, not the hardware.
	 */
	mutex_enter(&statep->as_lock);
	info->ref_cnt--;
	ASSERT(info->ref_cnt);
	mutex_exit(&statep->as_lock);

	/* release the taskq AFTER we don't care about the mode */
	audio_sup_taskq_resume(stpptr->am_taskq);

#ifdef DEBUG
	mutex_enter(&chptr->ch_lock);
	ASSERT(chpptr->acp_play_samp_buf == NULL);
	ASSERT(chpptr->acp_ch_psrc1 == NULL);
	ASSERT(chpptr->acp_ch_psrc2 == NULL);
	ASSERT(chpptr->acp_ch_pconv1 == NULL);
	ASSERT(chpptr->acp_ch_pconv2 == NULL);
	ASSERT(chpptr->acp_ch_rsrc1 == NULL);
	ASSERT(chpptr->acp_ch_rsrc2 == NULL);
	ASSERT(chpptr->acp_ch_rconv1 == NULL);
	ASSERT(chpptr->acp_ch_rconv2 == NULL);
	ASSERT(chpptr->acp_rec_mp == NULL);
	mutex_exit(&chptr->ch_lock);
#endif

	/* send the close signal */
	am_send_signal(statep, stpptr);

	mutex_enter(&chptr->ch_lock);

	kmem_free(chpptr, sizeof (*chpptr));
	chptr->ch_private = NULL;

	/* audio_sup_free_ch() requires the info ptr to be NULLed */
	chptr->ch_info.info = NULL;

	mutex_exit(&chptr->ch_lock);

	ATRACE("am_close_audioctl() calling audio_free_ch()", chptr);
	if (audio_sup_free_ch(chptr) == AUDIO_FAILURE) {
		/* not much we can do if this fails */
		ATRACE("am_close_audioctl() audio_sup_free_ch() failed", chptr);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "close_audioctl() audio_sup_free_ch() error");
	}

	ATRACE("am_close_audioctl() successful", 0);
	return (AUDIO_SUCCESS);

}	/* am_close_audioctl() */

/*
 * am_restore_state()
 *
 * Description:
 *	Restore the device's hardware state and restart playing and recording.
 *	If am_save_state() was called then we have the taskq frozen. Otherwise
 *	it isn't and we have to freeze it. That way hot unplug and hot plug
 *	events won't mess with open(), close(), or ioctl().
 *
 * Arguments:
 *	audio_state_t		*statep		Ptr to the dev instance's state
 *	audio_apm_info_t	*apm_infop	Ptr to the APM's state info
 *	int			dir		Direction to restore
 *
 * Returns:
 *	AUDIO_SUCCESS			State restored and restarted
 *	AUDIO_FAILURE			State not restored or restart failed
 */
int
am_restore_state(audio_state_t *statep, audio_apm_info_t *apm_infop, int dir)
{
	am_ad_info_t		*ad_infop;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	audio_info_t		*hw_info;
	audiohdl_t		handle = AUDIO_STATE2HDL(statep);
	uint_t			pgain;		/* play gain to set h/w */
	uint_t			pbalance;	/* play balance to set h/w */
	uint_t			rgain;		/* record gain to set h/w */
	uint_t			rbalance;	/* record balance to set h/w */
	int			doread;		/* device supports record */
	int			dowrite;	/* device supports play */
	int			psr;
	int			rsr;
	int			rc = AUDIO_FAILURE;

	ATRACE("in am_restore_state()", statep);

	ad_infop = apm_infop->apm_ad_infop;
	stpptr = apm_infop->apm_private;
	hw_info = &stpptr->am_hw_info;

	psr	=  hw_info->play.sample_rate;
	pgain 	= hw_info->play.gain;
	pbalance = hw_info->play.balance;
	rsr 	= hw_info->record.sample_rate;
	rgain 	= hw_info->record.gain;
	rbalance = hw_info->record.balance;

	/* figure out the direction, am_attach() already did the sanity ck */
	dowrite =
	    (ad_infop->ad_defaults->hw_features & AUDIO_HWFEATURE_PLAY) &&
	    (dir & AUDIO_PLAY);
	doread =
	    (ad_infop->ad_defaults->hw_features & AUDIO_HWFEATURE_RECORD) &&
	    (dir & AUDIO_RECORD);
	if (!doread && !dowrite) {
		ATRACE("am_restore_state() nothing to do", dir);
		mutex_enter(&stpptr->am_ad_lock);
		stpptr->am_ad_in &= ~AM_APM_FREEZE;
		mutex_exit(&stpptr->am_ad_lock);

		return (AUDIO_FAILURE);
	}

	/* freeze the taskq */
	audio_sup_taskq_suspend(stpptr->am_taskq);

	mutex_enter(&stpptr->am_ad_lock);

	/*
	 * Set state saved in preparation for restore. We set this because it
	 * is possible that am_save_state() was not called first, so this
	 * simulates this call. Don't both with a check if it is set, this
	 * wastes more time than just setting.
	 */
	stpptr->am_ad_in |= AM_APM_FREEZE;

	mutex_exit(&stpptr->am_ad_lock);

	ASSERT(doread || dowrite);

	ATRACE("am_restore_state() dowrite", dowrite);
	ATRACE("am_restore_state() doread", doread);

	/*
	 * CAUTION: Keep the calls the same as in am_attach(). There may be
	 *	order dependencies and once the audio driver works we don't
	 *	want to break it if we change the order.
	 *
	 *	Set the play format and gain, if present.
	 */
	if (dowrite) {
		if (am_set_format(statep, stpptr, ad_infop, AM_SET_CONFIG_BOARD,
		    AUDIO_PLAY, psr, stpptr->am_hw_pchs, stpptr->am_hw_pprec,
		    stpptr->am_hw_penc, AM_FORCE, AM_NO_SERIALIZE) ==
		    AUDIO_FAILURE) {
			audio_sup_log(handle, CE_WARN, "am_restore_state() "
			    "couldn't set play data format: %d %d %d %d",
			    hw_info->play.sample_rate, stpptr->am_hw_pchs,
			    stpptr->am_hw_pprec, stpptr->am_hw_penc);

			goto error;
		}

		if (am_set_gain(statep, apm_infop, stpptr->am_hw_pchs,
		    pgain, pbalance, AUDIO_PLAY, AM_SET_CONFIG_BOARD,
		    AM_FORCE, AM_NO_SERIALIZE) == AUDIO_FAILURE) {
			audio_sup_log(handle, CE_WARN,
			    "am_restore_state() couldn't set play gain");

			goto error;
		}
	}

	/* set the record format and gain, if present */
	if (doread) {
		if (am_set_format(statep, stpptr, ad_infop, AM_SET_CONFIG_BOARD,
		    AUDIO_RECORD, rsr, stpptr->am_hw_rchs, stpptr->am_hw_rprec,
		    stpptr->am_hw_renc, AM_FORCE, AM_NO_SERIALIZE) ==
		    AUDIO_FAILURE) {
			audio_sup_log(handle, CE_WARN,
			    "am_restore_state() "
			    "couldn't set record data format: %d %d %d %d",
			    hw_info->record.sample_rate, stpptr->am_hw_rchs,
			    stpptr->am_hw_rprec, stpptr->am_hw_renc);

			goto error;
		}

		/* set the gains */
		if (am_set_gain(statep, apm_infop, stpptr->am_hw_rchs,
		    rgain, rbalance, AUDIO_RECORD, AM_SET_CONFIG_BOARD,
		    AM_FORCE, AM_NO_SERIALIZE) == AUDIO_FAILURE) {
			audio_sup_log(handle, CE_WARN,
			    "am_restore_state() couldn't set record gain");

			goto error;
		}
	}

	/* now set the ports, monitor gain, etc. */
	if (dowrite) {
		if (am_ad_set_config(statep, stpptr, ad_infop,
		    AM_SET_CONFIG_BOARD, AM_SET_PORT, AUDIO_PLAY,
		    hw_info->play.port, NULL, AM_NO_SERIALIZE) ==
		    AUDIO_FAILURE) {
			audio_sup_log(handle, CE_WARN,
			    "am_restore_state() couldn't set play port: 0x%x",
			    ad_infop->ad_defaults->play.port);

			goto error;
		}
	}

	if (doread) {
		if (am_ad_set_config(statep, stpptr, ad_infop,
		    AM_SET_CONFIG_BOARD, AM_SET_PORT, AUDIO_RECORD,
		    hw_info->record.port, NULL, AM_NO_SERIALIZE) ==
		    AUDIO_FAILURE) {
			audio_sup_log(handle, CE_WARN,
			    "am_restore_state() couldn't set record port: 0x%x",
			    ad_infop->ad_defaults->record.port);

			goto error;
		}
	}

	if ((ad_infop->ad_defaults->hw_features & AUDIO_HWFEATURE_IN2OUT) &&
	    am_ad_set_config(statep, stpptr, ad_infop, AM_SET_CONFIG_BOARD,
	    AM_SET_MONITOR_GAIN, AUDIO_BOTH, hw_info->monitor_gain, NULL,
	    AM_NO_SERIALIZE) == AUDIO_FAILURE) {
		audio_sup_log(handle, CE_WARN,
		    "am_restore_state() couldn't set monitor gain: 0x%x",
		    ad_infop->ad_defaults->monitor_gain);

		goto error;
	}

	if (dowrite && am_ad_set_config(statep, stpptr, ad_infop,
	    AM_SET_CONFIG_BOARD, AM_OUTPUT_MUTE, AUDIO_PLAY,
	    hw_info->output_muted, NULL, AM_NO_SERIALIZE) == AUDIO_FAILURE) {
		audio_sup_log(handle, CE_WARN,
		    "am_restore_state() couldn't set output muted: 0x%x",
		    ad_infop->ad_defaults->output_muted);

		goto error;
	}

	if (doread && (ad_infop->ad_assist_flags & AM_ASSIST_MIC) &&
	    am_ad_set_config(statep, stpptr, ad_infop, AM_SET_CONFIG_BOARD,
	    AM_MIC_BOOST, AUDIO_RECORD,
	    (ad_infop->ad_add_mode & AM_ADD_MODE_MIC_BOOST), NULL,
	    AM_NO_SERIALIZE) == AUDIO_FAILURE) {
		audio_sup_log(handle, CE_WARN,
		    "am_restore_state() couldn't set mic boost: 0x%x",
		    ad_infop->ad_add_mode);

		goto error;
	}

	/*
	 * Restart play and record, if there are any apps that have the
	 * device open for the direction. If not then we don't waste time
	 * restarting.
	 *
	 * It is legal for a play restart calls to fail. This can happen
	 * when there's no audio to play. If it does fail due to no audio
	 * then we are already stopped and the active flags should be cleared.
	 * If play is restarted then the active flags should be set. We don't
	 * check because there is a race condition and with this routine
	 * and am_wsvc(). The flags will get set correctly very quickly, so
	 * there's no reason to try to work around this race, which would not
	 * be easy.
	 *
	 * The same is not true for record. If we start record for no recording
	 * apps then the mixer will turn off the record later after the 1st
	 * interrupt.
	 */
	if (ad_infop->ad_codec_type == AM_MS_CODEC) {
		audio_ch_t	*chptr;
		am_ch_private_t	*chpptr;
		int		i;
		int		max_chs = statep->as_max_chs;
		int		restore_dir = 0;

		restore_dir = doread | dowrite;
		ATRACE_32("am_restore_state() restore_dir", restore_dir);

		ATRACE("am_restore_state() restarting MS", 0);
		for (i = 0,  chptr = &statep->as_channels[0]; i < max_chs;
		    i++, chptr++, restore_dir = 0) {

			/* lock the channel before we check it out */
			mutex_enter(&chptr->ch_lock);

			/* skip non-AUDIO and unallocated channels */
			if (!(chptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
			    chptr->ch_info.dev_type != AUDIO ||
			    chptr->ch_info.pid == 0) {
				mutex_exit(&chptr->ch_lock);
				continue;
			}

			/* make sure this channel is writing */
			chpptr = chptr->ch_private;

			/*
			 * Figure which to restart for this channel. We do it
			 * this way so we can free the mutex fore calling the
			 * device's start routines.
			 */
			if (dowrite && chpptr->acp_writing) {
				restore_dir |= AUDIO_PLAY;
			}
			if (doread && chpptr->acp_reading) {
				restore_dir |= AUDIO_RECORD;
			}

			mutex_exit(&chptr->ch_lock);

			if (restore_dir & AUDIO_PLAY) {
				ATRACE("am_restore_state() MS restart play",
				    chptr);
				/*
				 * Don't set active flags because they
				 * should already be set.
				 */
				(void) am_ad_start_play(statep, stpptr,
				    ad_infop, i, AM_NO_SERIALIZE);
			}

			if (restore_dir & AUDIO_RECORD) {
				ATRACE("am_restore_state() MS restart record",
				    chptr);
				/*
				 * Don't set active flags because they
				 * should already be set.
				 */
				(void) am_ad_start_record(statep, stpptr,
				    ad_infop, i, AM_NO_SERIALIZE);
			}
		}
	} else {
		mutex_enter(&statep->as_lock);
		if (dowrite) {
			/* do restart */
			mutex_exit(&statep->as_lock);
			ATRACE_32("am_restore_state() restarting play TRAD",
			    stpptr->am_out_chs);

			/*
			 * We don't bother with the individual channel or
			 * hardware active flags because they should already
			 * be set.
			 */
			(void) am_ad_start_play(statep, stpptr, ad_infop,
			    AM_SET_CONFIG_BOARD, AM_NO_SERIALIZE);
			mutex_enter(&statep->as_lock);
		}

		if (doread) {
			/* do restart */
			mutex_exit(&statep->as_lock);
			ATRACE_32("am_restore_state() restarting record TRAD",
			    stpptr->am_in_chs);

			/*
			 * We don't bother with the individual channel or
			 * hardware active flags because they should already
			 * be set.
			 */
			(void) am_ad_start_record(statep, stpptr, ad_infop,
			    AM_SET_CONFIG_BOARD, AM_NO_SERIALIZE);
		} else {
			mutex_exit(&statep->as_lock);
		}
	}

	ATRACE("am_restore_state() done - success", statep);

	rc = AUDIO_SUCCESS;

error:
	/* restore error, thaw that taskq and free flags */
	audio_sup_taskq_resume(stpptr->am_taskq);

	mutex_enter(&stpptr->am_ad_lock);

	stpptr->am_ad_in &= ~AM_APM_FREEZE;

	/* wake up a blocked driver access, just in case */
	cv_signal(&stpptr->am_ad_cv);

	mutex_exit(&stpptr->am_ad_lock);

	ATRACE_32("am_restore_state() returning", rc);

	return (rc);

}	/* am_restore_state() */

/*
 * am_save_state()
 *
 * Description:
 *	Flag that we are frozen. This stops calls into the audio driver,
 *	except for ioctl()s.
 *
 *	We don't care about which direction. Both act the same.
 *
 *	There is a very tiny window of opportunity between taskq_wait()
 *	and the mutex_enter() where in theory we could get another task added
 *	to the queue, would execute, and potentially cause problems.
 *
 * Arguments:
 *	audio_state_t		*statep		Ptr to the dev instance's state
 *	audio_apm_info_t	*apm_infop	Ptr to the APM's state info
 *	int			dir		Direction to save
 *
 * Returns:
 *	AUDIO_SUCCESS			State restored and restarted
 *	AUDIO_FAILURE			State not restored or restart failed
 */
/*ARGSUSED*/
int
am_save_state(audio_state_t *statep, audio_apm_info_t *apm_infop, int dir)
{
	am_apm_private_t	*stpptr = apm_infop->apm_private;

	ATRACE("in am_save_state()", statep);

	audio_sup_taskq_wait(stpptr->am_taskq);

	mutex_enter(&stpptr->am_ad_lock);

	/* flag that we're frozen */
	stpptr->am_ad_in |= AM_APM_FREEZE;

	mutex_exit(&stpptr->am_ad_lock);

	return (AUDIO_SUCCESS);

}	/* am_save_state() */

/*
 * The private main routines for this file.
 */

/*
 * am_rput()
 *
 * Description:
 *	We have this here just for symmetry. There aren't any modules/drivers
 *	below this, so this should never be called. But just in case, we
 *	return.
 *
 * Arguments:
 *	queue_t		*q	Pointer to a queue
 *	mblk_t		*mp	Ptr to the msg block being passed to the queue
 *
 * Returns:
 *	0			Always returns 0
 */
/*ARGSUSED*/
static int
am_rput(queue_t *q, mblk_t *mp)
{
	ATRACE("in am_rput()", q);

	ATRACE("am_rput() returning 0", q);

	freemsg(mp);

	return (0);

}	/* am_rput() */

/*
 * am_rsvc()
 *
 * Description:
 *	We have this here just for symmetry. There aren't any modules/drivers
 *	below this, so this should never be called. But just in case, we
 *	return
 *
 * Arguments:
 *	queue_t		*q	Pointer to a queue
 *
 * Returns:
 *	0			Always returns 0
 */
/*ARGSUSED*/
static int
am_rsvc(queue_t *q)
{
	mblk_t		*mp;

	ATRACE("in am_rsvc()", q);

	/* we always have to drain the queue */
	while ((mp = getq(q)) != NULL) {
		freemsg(mp);
	}

	ATRACE("am_rsvc() returning 0", q);

	return (0);

}	/* am_rsvc() */

/*
 * am_wput()
 *
 * Description:
 *	All messages to the mixer arrive here. We don't support very many
 *	messages.
 *		M_DATA		Passed on to the write svc() routine
 *		M_IOCTL		Calls am_wioctl() for further processing
 *		M_IOCDATA	Calls am_wiocdata() for further processing
 *		M_FLUSH		Flushes the input and/or output queues
 *
 * Arguments:
 *	queue_t		*q	Pointer to a queue
 *	mblk_t		*mp	Ptr to the msg block being passed to the queue
 *
 * Returns:
 *	0			Always returns 0
 */
static int
am_wput(queue_t *q, mblk_t *mp)
{
	audio_ch_t		*chptr = (audio_ch_t *)
				    audio_sup_get_qptr_data(q);
	audio_state_t		*statep = chptr->ch_statep;
	int			error = EIO;

	ATRACE("in am_wput()", q);

	ASSERT(chptr);

	/* figure out what kind of message we've got */
	ATRACE_32("am_wput() type", mp->b_datap->db_type);
	switch (mp->b_datap->db_type) {
	case M_FLUSH:
		ATRACE("am_wput() FLUSH", chptr);

		ASSERT(WR(q) == q);

		am_flush(q, mp);
		return (0);

	case M_IOCTL:
		ATRACE("am_wput() IOCTL", chptr);
		return (am_wioctl(q, mp, chptr));

	case M_IOCDATA:
		ATRACE("am_wput() IOCDATA", chptr);
		return (am_wiocdata(q, mp, chptr));

	case M_DATA:
		ATRACE("am_wput() DATA", chptr);
		/* make sure the write is on an AUDIO channel */
		mutex_enter(&chptr->ch_lock);
		if (chptr->ch_info.dev_type != AUDIO ||
		    !((am_ch_private_t *)chptr->ch_private)->acp_writing) {

			/* NOT an AUDIO channel, we don't allow write */
			ATRACE_32("am_wput() not AUDIO",
			    chptr->ch_info.dev_type);
			mutex_exit(&chptr->ch_lock);
			goto done;
		}
		mutex_exit(&chptr->ch_lock);
		ATRACE("am_wput() putting msg on q", mp);

		/*
		 * First, concatenate the message. If in mixer mode
		 * with a traditional Codec we do sample rate conversion
		 * on the concatenated buffer before we save the data
		 * for later use.
		 */
		if (pullupmsg(mp, -1)) {
			ATRACE("am_wput() pullupmsg() successful", mp);
			(void) putq(q, mp);	/* does qenable() */
		} else {
			ATRACE("am_wput() pullupmsg() failed", mp);
			audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
			    "wput() pullupmsg() failed, sound lost");
			freemsg(mp);
		}
		ATRACE_32("am_wput() putting msg on q done", 0);

		/* don't break because then we free a msg we've already freed */
		ATRACE_32("am_wput() returning", 0);
		return (0);

	default:
		ATRACE("am_wput() default", chptr);
		break;
	}

	/* if we get here there was some kind of error, so send an M_ERROR */
done:
	ATRACE("am_wput() done:", chptr);

	if (error) {
		ATRACE_32("am_wput() error", error);
		mp->b_datap->db_type = M_ERROR;
		mp->b_rptr = mp->b_datap->db_base;
		*(int *)mp->b_rptr = EIO;
		mp->b_wptr = mp->b_rptr + sizeof (int *);
		if (mp->b_cont) {
			freemsg(mp->b_cont);
			mp->b_cont = NULL;
		}
		qreply(q, mp);
	} else {
		if (mp) {
			freemsg(mp);
		}
	}

	ATRACE("am_wput() returning", chptr);

	return (0);

}	/* am_wput() */

/*
 * am_wsvc()
 *
 * Description:
 *	Write service routine. By definition, this service routine grabs
 *	all messages from the queue before it returns.
 *
 *	The only message that we ever get is an M_DATA message, which is
 *	audio data. The audio data is converted to the canonical data format.
 *	If we need to sample rate convert then the data is converted.
 *
 *	We also make sure the play DMA engine is running.
 *
 * Arguments:
 *	queue_t		*q	Pointer to a queue
 *
 * Returns:
 *	0			Always returns 0
 */
static int
am_wsvc(queue_t *q)
{
	audio_ch_t		*chptr = (audio_ch_t *)
				    audio_sup_get_qptr_data(q);
	am_ch_private_t		*chpptr = chptr->ch_private;
	audio_state_t		*statep = chptr->ch_statep;
	am_ad_info_t		*ad_infop = chptr->ch_apm_infop->apm_ad_infop;
	am_apm_private_t	*stpptr = chptr->ch_apm_infop->apm_private;
	audio_apm_info_t	*apm_infop = chptr->ch_apm_infop;
	audio_info_t		*hw_info = &stpptr->am_hw_info;
	audio_info_t		*tinfo;
	mblk_t			*mp;
	int			EOF_count;
	int			*orig_data;
	int			*proc_data;
	size_t			size;
	size_t			orig_size;
	size_t			proc_size;

	ATRACE("in am_wsvc()", q);
	ATRACE("am_wsvc() chptr", chptr);
	ASSERT(RD(q) == chptr->ch_qptr);
	ASSERT(!MUTEX_HELD(&chptr->ch_lock));

	/* we always have to drain the queue */
	while ((mp = getq(q)) != NULL) {
		/* this is an AUDIO channel */
		ATRACE("am_wsvc() processing data", mp);

		/*
		 * If this is an EOF marker, 0 size write(), we place an
		 * empty audio data structure on the data list.
		 */
		size = mp->b_wptr - mp->b_rptr;
		if (size == 0) {
			ATRACE("am_wsvc() EOF message, putting on list", mp);
			if (audio_sup_save_audio_data(chptr, NULL, 0, NULL,
			    0) == AUDIO_FAILURE) {
				audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
				    "am_wsvc() EOF marker lost");
			}
			freemsg(mp);
#ifdef FLOW_CONTROL
			goto flow;
#else
			continue;
#endif
		}

		/* not an EOF message, so process it */
		ATRACE("am_wsvc() calling am_p_process()", size);

		/* don't let mode switch happen while we sample rate convert */
		mutex_enter(&chptr->ch_lock);
		mutex_enter(&stpptr->am_mode_lock);

		/* if we are switching modes then return */
		mutex_enter(&apm_infop->apm_lock);
		if (stpptr->am_flags & AM_PRIV_SW_MODES) {
			ATRACE_32("am_wsvc() switching modes",
			    stpptr->am_flags);

			/* put the message back on the queue */
			(void) putbq(q, mp);

			/* make sure the queue is off */
			noenable(WR(q));

			/* for AUDIO_DRAIN */
			chpptr->acp_flags |= AM_CHNL_MSG_ON_QUEUE;

			mutex_exit(&apm_infop->apm_lock);
			mutex_exit(&stpptr->am_mode_lock);
			mutex_exit(&chptr->ch_lock);

			return (0);
		}
		mutex_exit(&apm_infop->apm_lock);

		if (am_p_process(chptr, mp->b_rptr, size, &orig_data,
		    &orig_size, &proc_data, &proc_size) == AUDIO_FAILURE) {
			mutex_exit(&stpptr->am_mode_lock);
			mutex_exit(&chptr->ch_lock);

			ATRACE("am_wsvc() am_p_process() failed", chptr);

			freemsg(mp);
#ifdef FLOW_CONTROL
			goto flow;
#else
			continue;
#endif
		}
		mutex_exit(&stpptr->am_mode_lock);
		mutex_exit(&chptr->ch_lock);

		freemsg(mp);

		/* save the audio data */
		if (audio_sup_save_audio_data(chptr, orig_data, orig_size,
		    proc_data, proc_size) == AUDIO_FAILURE) {
			audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
			    "am_wsvc() data save failed, audio lost");
#ifdef FLOW_CONTROL
			goto flow;
#else
			continue;
#endif
		}

		/*
		 * Mark the channel as busy and not empty, but only if we
		 * actually processed the message. If that failed then we
		 * give up on this message and try again on the next one.
		 */
		mutex_enter(&chptr->ch_lock);
		chpptr->acp_flags &= ~(AM_CHNL_EMPTY|AM_CHNL_ALMOST_EMPTY1|\
		    AM_CHNL_ALMOST_EMPTY2);
		mutex_exit(&chptr->ch_lock);

#ifdef FLOW_CONTROL
flow:
		/* do we need to do flow control? */
		mutex_enter(&chptr->ch_lock);
		if (!(chpptr->acp_flags & AM_CHNL_PFLOW) &&
		    (audio_sup_get_audio_data_size(chptr) >
		    AM_MAX_QUEUED_MSGS_SIZE ||
		    audio_sup_get_audio_data_cnt(chptr) >
		    AM_MAX_QUEUED_MSGS_CNT)) {
			/* yes, do flow control */
			chpptr->acp_flags |= AM_CHNL_PFLOW;
			mutex_exit(&chptr->ch_lock);

			ATRACE("am_wsvc() flow control enabled, q off", q);

			noenable(q);		/* keep putq() from enabling */

			break;
		}
		mutex_exit(&chptr->ch_lock);
#endif
	}

	/*
	 * If !paused make sure the play engine is on.
	 *
	 * It is possible during a mode switch that the channel info
	 * structure can change on us. So we use the channel lock to
	 * make sure it remains stable.
	 */
	mutex_enter(&chptr->ch_lock);
	tinfo = chptr->ch_info.info;

	/* for AUDIO_DRAIN */
	chpptr->acp_flags &= ~AM_CHNL_MSG_ON_QUEUE;
	ATRACE("am_wsvc() starting play eng", statep);
	if (!tinfo->play.pause) {
		/*
		 * Set the active bits before starting play so a switch mode
		 * will sleep on the CV.
		 */
		tinfo = chptr->ch_info.info;
		tinfo->play.active = 1;
		hw_info->play.active = 1;
		tinfo->play.pause = 0;
		mutex_exit(&chptr->ch_lock);
		if (am_ad_start_play(statep, stpptr, ad_infop,
		    chptr->ch_info.ch_number, AM_SERIALIZE) == AUDIO_FAILURE) {
			/* we don't change pause if failed to start */
			mutex_enter(&chptr->ch_lock);
			tinfo = chptr->ch_info.info;
			tinfo->play.active = 0;
			hw_info->play.active = 0;

			/*
			 * If we turn off the hardware then make sure any
			 * queued up EOF messages go out. This is done in
			 * am_get_samples(). Hopefully most of the EOFs will
			 * be caught there. However, especially when in mixer
			 * mode, it can be difficult to catch them all when
			 * only EOFs are being written. Doing it again here
			 * costs very little and we know nothing is lost.
			 */
			EOF_count = 0;
			if (chpptr->acp_EOF[chpptr->acp_EOF_toggle]) {
				EOF_count +=
				    chpptr->acp_EOF[chpptr->acp_EOF_toggle];
				chpptr->acp_EOF[chpptr->acp_EOF_toggle] = 0;
			}
			AUDIO_TOGGLE(chpptr->acp_EOF_toggle);
			if (chpptr->acp_EOF[chpptr->acp_EOF_toggle]) {
				EOF_count +=
				    chpptr->acp_EOF[chpptr->acp_EOF_toggle];
				chpptr->acp_EOF[chpptr->acp_EOF_toggle] = 0;
			}
			mutex_exit(&chptr->ch_lock);

			for (; EOF_count; EOF_count--) {
				tinfo->play.eof++;
				am_send_signal(chptr->ch_statep, stpptr);
			}

			/*
			 * It is possible that we tried to start playing
			 * while in the middle of the audio driver calling
			 * am_play_shutdown(). Thus the start would reload
			 * the transfer engine but it would be shut down by
			 * the ISR after am_play_shutdown() returns. The
			 * appropriate flags in the audio driver will keep
			 * the transfer engine from being shut back down.
			 * However, if a mode switch happens after
			 * am_play_shutdown() checks the mode switch flag
			 * then when the ISR calls am_get_audio() the switch
			 * mode flag will be set and no audio will ever be
			 * transferred. Thus playing will be deadlocked with
			 * the mode switch.
			 *
			 * The easiest way to expose this is to run showmetv
			 * with 1894.mov and do insane mode switching. The
			 * switch modes CV will never wake up, so we go ahead
			 * and wake it up. The switch mode code will deal
			 * with a bogus cv_signal().
			 */
			mutex_enter(&stpptr->am_mode_lock);
			cv_signal(&stpptr->am_mode_cv);
			mutex_exit(&stpptr->am_mode_lock);
		}
	} else {
		mutex_exit(&chptr->ch_lock);
	}
	ATRACE("am_wsvc() start play eng ret", statep);

	ATRACE("am_wsvc() returning", chptr);

	return (0);

}	/* am_wsvc() */

/*
 * am_apply_gain_balance()
 *
 * Description:
 *	Apply gain and balance to the canonical audio data buffer.
 *
 * Arguments:
 *	int		*buf		Pointer to the canonical audio data
 *	int		samples		Number of samples
 *	int		channels	MONO or STEREO
 *	int		gain		Gain, 0 - 255
 *	int		balance		Balance, 0 - 64
 *
 * Returns:
 *	void
 */
void
am_apply_gain_balance(int *buf, int samples, int channels, int gain,
    int balance)
{
	int		l_gain;
	int		r_gain;

	ATRACE("in am_apply_gain_balance()", buf);
	ATRACE_32("am_apply_gain_balance() samples", samples);
	ATRACE_32("am_apply_gain_balance() channels", channels);
	ATRACE_32("am_apply_gain_balance() gain", gain);
	ATRACE_32("am_apply_gain_balance() balance", balance);

	if (channels == AUDIO_CHANNELS_MONO) {
		l_gain = gain;
		for (; samples; buf++, samples--) {
			*buf = (*buf * l_gain) >> AM_MAX_GAIN_SHIFT;
		}
	} else {
		ASSERT(channels == AUDIO_CHANNELS_STEREO);
		ASSERT((samples % 1) == 0);

		l_gain = r_gain = gain;

		if (balance < AUDIO_MID_BALANCE) {
			/* leave l gain alone and scale down r gain */
			r_gain = (r_gain * balance) >> AM_TIMES_32_SHIFT;
		} else if (balance > AUDIO_MID_BALANCE) {
			/* leave r gain alone and scale down l gain */
			l_gain = (l_gain * (64 - balance)) >> AM_TIMES_32_SHIFT;
		}

		for (; samples; buf += 2, samples -= 2) {
			buf[0] = (buf[0] * l_gain) >> AM_MAX_GAIN_SHIFT;
			buf[1] = (buf[1] * r_gain) >> AM_MAX_GAIN_SHIFT;
		}
	}

	ATRACE("am_apply_gain_balance() done", buf);

}	/* am_apply_gain_balance() */

/*
 * am_convert_int_mono_stereo()
 *
 * Description:
 *	Convert a buffer between mono and stereo. Both the source and
 *	destination buffers are 32-bit integers. The number of samples
 *	is updated to match the new number of samples.
 *
 *	CAUTION: The calling routine must ensure that the dest is large
 *		enough for the data, or we'll panic.
 *
 * Arguments:
 *	int		*src		Input data buffer
 *	int		*dest		Output data buffer
 *	int		*samples	Ptr to he number of samples to convert
 *	int		src_chs		Input channels
 *	int		dest_chs	Output channels
 *
 * Returns:
 *	void
 */
void
am_convert_int_mono_stereo(int *src, int *dest, int *samples, int src_chs,
    int dest_chs)
{
	size_t		size;
	int		i;
	int		val;

	ATRACE("in am_convert_int_mono_stereo()", src);

	if (src_chs == dest_chs) {
		/*
		 * The same size so no translation needed, just copy.
		 * size = samples * sizeof (int)
		 */
		size = *samples << AM_TIMES_4_SHIFT;
		bcopy(src, dest, size);

	} else if (src_chs > dest_chs) {
		/* convert from stereo to mono */
		*samples >>= AM_TIMES_2_SHIFT;
		for (i = *samples; i--; ) {
			/* average the left and right channels */
			val = *src++;
			val += *src++;
			*dest++ = val >> AM_HALF_ENERGY_SHIFT;
		}
	} else {
		ASSERT(src_chs < dest_chs);
		/* convert from mono to stereo */
		for (i = *samples; i--; ) {
			val = *src++;
			*dest++ = val;
			*dest++ = val;
		}
		*samples <<= AM_TIMES_2_SHIFT;
	}

	ATRACE("am_convert_int_mono_stereo() done", dest);

}	/* am_convert_int_mono_stereo() */

/*
 * am_convert_to_int()
 *
 * Description:
 *	Convert a buffer of various precisions and encodings into 16-bit
 *	linear PCM stored in a 32-bit int. If the input is unsigned PCM
 *	we convert it to signed PCM while converting it.
 *
 *	CAUTION: The calling routine must ensure that the outbuf is large
 *		enough for the data, or we'll panic.
 *
 * Arguments:
 *	void		*inbuf		Input data buffer
 *	int		*outbuf		Output data buffer
 *	int		samples		The number of samples to convert
 *	int		precision	The precision of the input buffer.
 *	int		encoding	The encoding of the input buffer.
 *	int		flags		Flags, including AM_PRIV_8/16_TRANS
 *
 * Returns:
 *	void
 */
void
am_convert_to_int(void *inbuf, int *outbuf, int samples, int precision,
    int encoding, int flags)
{
	int		i;

	ATRACE("in am_convert_to_int()", inbuf);

	if (precision == AUDIO_PRECISION_16) {	/* do the easy case first */
		int16_t		*src = (int16_t *)inbuf;

		ASSERT(encoding == AUDIO_ENCODING_LINEAR);

		ATRACE_32("am_convert_to_int() 16-Bit", samples);

		if (flags & AM_PRIV_16_TRANS) {
			for (i = samples; i--; ) {
				*outbuf++ = (int)*src++ + INT16_MIN;
			}
		} else {
			for (i = samples; i--; ) {
				*outbuf++ = (int)*src++;
			}
		}
	} else {		/* now the hard case, 8-bit */
		int16_t		*aptr;
		int8_t		*src = (int8_t *)inbuf;

		ASSERT(precision == AUDIO_PRECISION_8);

		if (encoding == AUDIO_ENCODING_ULAW) {
			aptr = _8ulaw2linear16;
			ATRACE("am_convert_to_int() 8-bit u-law", aptr);

			/*
			 * Copy the data into the buf. acp_ch_pptr1,
			 * char -> int.
			 */
			for (i = samples; i--; ) {
				/* the conv. array does the scaling */
				*outbuf++ = (int)aptr[(unsigned char)*src++];
			}
		} else if (encoding == AUDIO_ENCODING_ALAW) {
			aptr = _8alaw2linear16;
			ATRACE("am_convert_to_int() 8-bit A-law", aptr);

			/*
			 * Copy the data into the buf. acp_ch_pptr1,
			 * char -> int.
			 */
			for (i = samples; i--; ) {
				/* the conv. array does the scaling */
				*outbuf++ = (int)aptr[(unsigned char)*src++];
			}
		} else if (encoding == AUDIO_ENCODING_LINEAR8 ||
		    (flags & AM_PRIV_8_TRANS)) {
			/*
			 * Copy the data into the buffer with a shift to
			 * make signed.
			 */
			for (i = samples; i--; ) {
				*outbuf++ = (((int)*src++ & AM_CHAR2INT_MASK) -
				    INT8_MAX) << AM_256_SHIFT;
			}
		} else {
			ASSERT(encoding == AUDIO_ENCODING_LINEAR);
			/*
			 * Copy the data into the buf. acp_ch_pptr1,
			 * char -> int.
			 */
			for (i = samples; i--; ) {
				*outbuf++ = (int)(*src++) << AM_256_SHIFT;
			}
		}
	}

	ATRACE("am_convert_to_int() done", outbuf);

}	/* am_convert_to_int() */

/*
 * am_reprocess()
 *
 * Description:
 *	Process the original data, which am_p_process() created, into sample
 *	rate converted audio.
 *
 *	Unlike am_p_process() we don't have the opportunity to minimize the
 *	sample rate conversion processing because we can't take advantage of
 *	converting between mono and stereo.
 *
 *	It is possible we need to convert original audio that has been
 *	partially played. So see if we may need to fix the processed
 *	data pointers.
 *
 *	CAUTION: This routine can be called from interrupt context, so memory
 *		allocation cannot sleep.
 *
 *	CAUTION: It is not possible to update the sample rate converter in
 *		this routine because it may be called when switching modes
 *		and thus the configuration information may be in transition
 *		and not accurate. Thus the calling routines must ensure the
 *		the converter is ready.
 *
 * Arguments:
 *	audio_ch_t	*chptr		Pointer to this channel's state info
 *	audio_data_t	*data		Original and new processed data struct
 *
 * Returns:
 *	AUDIO_SUCCESS		Data converted and saved
 *	AUDIO_FAILURE		Data conversion and save failed, audio lost
 */
int
am_reprocess(audio_ch_t *chptr, audio_data_t *data)
{
	audio_state_t		*statep = chptr->ch_statep;
	am_ch_private_t		*chpptr = chptr->ch_private;
	am_apm_private_t	*stpptr = chptr->ch_apm_infop->apm_private;
	am_ad_info_t		*ad_infop = chptr->ch_apm_infop->apm_ad_infop;
	am_ad_src_entry_t	*psrs = ad_infop->ad_play.ad_conv;
	int			*tmp;
	int			tmp_size;
	uint_t			hw_channels = stpptr->am_hw_pchs;
	int			mode = stpptr->am_pstate->apm_mode;
	int			orig_samples;
	int			src_samples;
	int			*data_start;
	int			*conv;
	size_t			orig_size_plus_pb;
	size_t			orig_size;

	ATRACE("in am_reprocess()", data);

	/* don't let mode switch happen while we sample rate convert */
	mutex_enter(&stpptr->am_mode_lock);

	/* make sure we need to process the data */
	if (mode != AM_MIXER_MODE || ad_infop->ad_codec_type != AM_TRAD_CODEC) {
		/* we don't SRC this data */
		mutex_exit(&stpptr->am_mode_lock);
		ATRACE_32("am_reprocess() don't SRC", mode);
		return (AUDIO_FAILURE);
	}

	/* figure out the number of samples */
	orig_samples = data->adata_osize >> AM_TIMES_4_SHIFT;
	orig_size = orig_samples << AM_INT32_SHIFT;
	orig_size_plus_pb = orig_size + chpptr->acp_ch_pbuf_size;
	ATRACE_32("am_reprocess() BUF orig_samples", orig_samples);

	/*
	 * Make sure we've got good sample rate converter buffers. If we fail
	 * the calling routine will throw away the audio. There aren't more
	 * chances to process the audio.
	 */
	if (am_update_src_buffer(chptr, orig_samples, hw_channels,
	    AUDIO_PLAY) == AUDIO_SUCCESS) {
		ATRACE("am_reprocess() update_src_buffer() okay", 0);
		src_samples = orig_samples;
	} else {
		mutex_exit(&stpptr->am_mode_lock);
		ATRACE_32("am_reprocess() calling update_src_buffer() failed",
		    mode);
		return (AUDIO_FAILURE);
	}
	ATRACE_32("am_reprocess() src_samples", src_samples);

	/* Only do extra work if necessary */
	if (chpptr->acp_ch_pbuf_size > 0) {

		/* Make sure we have good conversion buffers */
		if (am_update_conv_buffer(chptr, orig_size_plus_pb,
			AUDIO_PLAY) == AUDIO_FAILURE) {
			mutex_exit(&stpptr->am_mode_lock);
			audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
				"!process(1) couldn't allocate memory, "
				"audio lost");
			return (AUDIO_FAILURE);
		}

		/* Set conv pointing to pconv2 */
		conv = chpptr->acp_ch_pconv2;

		/* Set data_start pointing to where incoming data begins */
		data_start = conv + (chpptr->acp_ch_pbuf_size >>
			AM_TIMES_4_SHIFT);

		/* We have to copy orig data to data_start */
		bcopy(data->adata_orig, data_start, orig_size);
	} else {
		/* Set conv pointing to orig data */
		conv = data->adata_orig;
	}

	tmp = psrs->ad_src_convert(AM_SRC_CHPTR2HDL(chptr), hw_channels,
	    AUDIO_PLAY, conv, chpptr->acp_ch_psrc1,
	    chpptr->acp_ch_psrc2, &src_samples);

	ASSERT(src_samples <= (chpptr->acp_ch_psrc_siz >> AM_TIMES_4_SHIFT));

	/* if successful then copy to proc */
	if (tmp) {
		/* sizeof (int) = 4 */
		tmp_size = src_samples << AM_TIMES_4_SHIFT;
		data->adata_proc = kmem_alloc(tmp_size, KM_NOSLEEP);
		if (data->adata_proc) {
			bcopy(tmp, data->adata_proc, tmp_size);
			data->adata_psize = tmp_size;
		} else {
			mutex_exit(&stpptr->am_mode_lock);
			ATRACE_32("am_reprocess() couldn't allocate new buffer",
			    0);
			return (AUDIO_FAILURE);
		}
		data->adata_psize = tmp_size;
		data->adata_peptr = (char *)data->adata_proc + tmp_size;
	} else {
		mutex_exit(&stpptr->am_mode_lock);
		ATRACE_32("am_reprocess() SRC failed", 0);
		return (AUDIO_FAILURE);
	}

	ATRACE("am_reprocess() orig", data->adata_orig);
	ATRACE("am_reprocess() optr", data->adata_optr);
	ATRACE("am_reprocess() oeptr", data->adata_oeptr);
	ATRACE_32("am_reprocess() osize", data->adata_osize);

	/* see if we need to fix the processed data pointers */
	if (data->adata_optr != data->adata_orig) {
		long		tmp;

		/*
		 * Make a guess as to where to point to. We make sure we are
		 * on a 4 byte boundary. That way we don't have to worry
		 * about being in the middle of a sample.
		 *
		 * The equation:
		 *	(offset of orig data from start)*(length of proc data)
		 *	--------------------------------------------------------
		 *		(length of orig data)
		 */
		tmp = ((char *)data->adata_optr - (char *)data->adata_orig) *
		    data->adata_psize / data->adata_osize;

		/*
		 * tmp is an offset, which must be added to adata_proc to
		 * get adata_pptr. We mask off adata_pptr so that regardless
		 * of the format of the data we always are on a sample frame
		 * boundary.
		 */
		data->adata_pptr = (char *)data->adata_proc +
		    (tmp & ~AM_MISC_MASK);
	} else {
		/* on a boundary, so the pointers are easy */
		data->adata_pptr = data->adata_proc;
	}

	ATRACE("am_reprocess() proc", data->adata_proc);
	ATRACE("am_reprocess() pptr", data->adata_pptr);
	ATRACE("am_reprocess() peptr", data->adata_peptr);
	ATRACE_32("am_reprocess() psize", data->adata_psize);

	/* we don't need to block mode switching now */
	mutex_exit(&stpptr->am_mode_lock);

	return (AUDIO_SUCCESS);

}	/* am_reprocess() */

/*
 * am_send_signal()
 *
 * Description:
 *	This routine is used to send signals back to user land processes.
 *
 *	We always create a prototype signal message, but we use dupb() to
 *	actually send up the queue.
 *
 *	NOTE: We don't lock the tchptr because the state is frozen thus
 *		channels can't be allocated or freed. However they can
 *		have their state updated. The worst that can happen is
 *		we miss a channel to send a signal on, which isn't that
 *		bad. And this is only when open()ing or close()ing. Since
 *		those operations send a signal we're covered.
 *
 *	NOTE: This routine must be called with as_lock held.
 *
 * Arguments:
 *	audio_state_t		*statep	Pointer to the device instance's state
 *	am_apm_private_t	*stpptr	Pointer to APM private data
 *
 * Returns:
 *	void
 */
void
am_send_signal(audio_state_t *statep, am_apm_private_t *stpptr)
{
	audio_ch_t	*tchptr;
	mblk_t		*mp = stpptr->am_sig_mp;
	mblk_t		*dup_mp;
	int		i;
	int		max_chs;

	ATRACE("in am_send_signal()", statep);

	ASSERT(!MUTEX_HELD(&statep->as_lock));

	/* get the number of chs for this instance */
	max_chs = statep->as_max_chs;

	ATRACE("am_send_signal() AM_SIGNAL_ALL_CTL", mp);

	/* look for AUDIOCTL channels */
	for (i = 0, tchptr = &statep->as_channels[0];
	    i < max_chs; i++, tchptr++) {
		/* skip unallocated, non-AUDIOCTL and closing channels */

		mutex_enter(&tchptr->ch_lock);
		if (!(tchptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
		    tchptr->ch_info.dev_type != AUDIOCTL ||
		    tchptr->ch_info.pid == 0 ||
		    (((am_ch_private_t *)tchptr->ch_private)->acp_flags &
		    AM_CHNL_CLOSING)) {
			mutex_exit(&tchptr->ch_lock);
			continue;
		}

		ATRACE("am_send_signal() tchptr", tchptr);
		if ((dup_mp = dupb(mp)) == NULL) {
			ATRACE("am_send_signal() AUDIOCTL "
			    "couldn't allocate duplicate message", tchptr);
			audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
			    "signal() couldn't allocate duplicate "
			    "message to send signal, signal lost");
			mutex_exit(&tchptr->ch_lock);
			continue;
		}

		ATRACE_32("am_send_signal() AM_SIGNAL_ALL_CTL putnext()",
		    tchptr->ch_info.ch_number);
		ASSERT((((am_ch_private_t *)tchptr->ch_private)->acp_flags &
		    AM_CHNL_CLOSING) == 0);

		am_safe_putnext(tchptr, dup_mp);

		ATRACE("am_send_signal() "
		    "AM_SIGNAL_ALL_CTL putnext() done", dup_mp);

		mutex_exit(&tchptr->ch_lock);
	}

	ATRACE("am_send_signal() done", statep);

}	/* am_send_signal() */

/*
 * am_update_conv_buffer()
 *
 * Description:
 *	Make sure the conversion to 32-bit linear PCM buffers are large
 *	enough. If not then the ones are allocated. Both buffers are always
 *	set to the same size.
 *
 *	CAUTION: This routine is called from interrupt context, so memory
 *		allocation cannot sleep.
 *
 * Arguments:
 *	audio_ch_t	*chptr		Pointer to this channel's state info
 *	size_t		size		The size we need
 *	int		dir		AUDIO_PLAY or AUDIO_RECORD, not both
 *
 * Returns:
 *	AUDIO_SUCCESS			Buffers okay
 *	AUDIO_FAILURE			Buffer allocation failed
 */
int
am_update_conv_buffer(audio_ch_t *chptr, size_t size, int dir)
{
	am_ch_private_t		*chpptr = chptr->ch_private;
	void			*tmp1;
	void			*tmp2;

	ATRACE("in am_update_conv_buffer()", chptr);
	ATRACE("am_update_conv_buffer() size", size);

	ASSERT(MUTEX_HELD(&chptr->ch_lock));

	ASSERT(dir != AUDIO_BOTH);

	if (dir == AUDIO_PLAY) {
		if (chpptr->acp_ch_pconv_siz &&
		    size <= chpptr->acp_ch_pconv_siz) {
			/* buffers large enough */
			ASSERT(chpptr->acp_ch_pconv1);
			ASSERT(chpptr->acp_ch_pconv2);
			return (AUDIO_SUCCESS);
		}
	} else {
		ASSERT(dir == AUDIO_RECORD);
		if (chpptr->acp_ch_rconv_siz &&
		    size <= chpptr->acp_ch_rconv_siz) {
			/* buffers large enough */
			ASSERT(chpptr->acp_ch_rconv1);
			ASSERT(chpptr->acp_ch_rconv2);
			return (AUDIO_SUCCESS);
		}
	}

	if ((tmp1 = kmem_zalloc(size, KM_NOSLEEP)) == NULL) {
		ATRACE("am_update_conv_buffer() kmem_zalloc(1) failed", NULL);
		return (AUDIO_FAILURE);
	}
	if ((tmp2 = kmem_zalloc(size, KM_NOSLEEP)) == NULL) {
		ATRACE("am_update_conv_buffer() kmem_zalloc(2) failed", NULL);
		kmem_free(tmp1, size);
		return (AUDIO_FAILURE);
	}
	ATRACE("am_update_conv_buffer() new buffers", size);

	if (dir == AUDIO_PLAY) {
		ASSERT(size >= chpptr->acp_ch_pbuf_size);
		if (chpptr->acp_ch_pconv1) {
			bcopy(chpptr->acp_ch_pconv1, tmp1,
				chpptr->acp_ch_pbuf_size);
			kmem_free(chpptr->acp_ch_pconv1,
			    chpptr->acp_ch_pconv_siz);
		}
		if (chpptr->acp_ch_pconv2) {
			bcopy(chpptr->acp_ch_pconv2, tmp2,
				chpptr->acp_ch_pbuf_size);
			kmem_free(chpptr->acp_ch_pconv2,
			    chpptr->acp_ch_pconv_siz);
		}
		chpptr->acp_ch_pconv1 = tmp1;
		chpptr->acp_ch_pconv2 = tmp2;
		chpptr->acp_ch_pconv_siz = size;
	} else {
		ASSERT(size >= chpptr->acp_ch_rbuf_size);
		if (chpptr->acp_ch_rconv1) {
			bcopy(chpptr->acp_ch_rconv1, tmp1,
				chpptr->acp_ch_rbuf_size);
			kmem_free(chpptr->acp_ch_rconv1,
			    chpptr->acp_ch_rconv_siz);
		}
		if (chpptr->acp_ch_rconv2) {
			bcopy(chpptr->acp_ch_rconv2, tmp2,
				chpptr->acp_ch_rbuf_size);
			kmem_free(chpptr->acp_ch_rconv2,
			    chpptr->acp_ch_rconv_siz);
		}
		chpptr->acp_ch_rconv1 = tmp1;
		chpptr->acp_ch_rconv2 = tmp2;
		chpptr->acp_ch_rconv_siz = size;
	}

	return (AUDIO_SUCCESS);

}	/* am_update_conv_buffer() */

/*
 * am_update_src_buffer()
 *
 * Description:
 *	Make sure the sample rate conversion buffers are large enough. If
 *	not then the ones are allocated. Both buffers are always set to
 *	the same size.
 *
 *	CAUTION: This routine is called from interrupt context, so memory
 *		allocation cannot sleep.
 *
 * Arguments:
 *	audio_ch_t	*chptr		Pointer to this channel's state info
 *	int		samples		The number of samples to convert
 *	uint_t		hw_channels	Number of hardware channels
 *	int		dir		AUDIO_PLAY or AUDIO_RECORD, not both
 *
 * Returns:
 *	AUDIO_SUCCESS			Buffers okay
 *	AUDIO_FAILURE			Buffer allocation failed, buffers 0ed
 */
int
am_update_src_buffer(audio_ch_t *chptr, int samples, uint_t hw_channels,
    int dir)
{
	am_ch_private_t		*chpptr = chptr->ch_private;
	am_apm_private_t	*stpptr = chptr->ch_apm_infop->apm_private;
	am_ad_info_t		*ad_infop = chptr->ch_apm_infop->apm_ad_infop;
	am_ad_src_entry_t	*srs;
	audio_info_t		*info = chptr->ch_info.info;
	size_t			size;
	void			*tmp1;
	void			*tmp2;

	ATRACE("in am_update_src_buffer()", chptr);
	ATRACE_32("am_update_src_buffer() samples", samples);

	ASSERT(MUTEX_HELD(&stpptr->am_mode_lock));
	ASSERT(MUTEX_HELD(&chptr->ch_lock));

	ASSERT(dir != AUDIO_BOTH);

	if (dir == AUDIO_PLAY) {
		srs = ad_infop->ad_play.ad_conv;
		size = srs->ad_src_size(AM_SRC_CHPTR2HDL(chptr),
		    &info->play, AUDIO_PLAY, samples, hw_channels);
		if (chpptr->acp_ch_psrc_siz &&
			size <= chpptr->acp_ch_psrc_siz) {
			/* buffers large enough */
			ASSERT(chpptr->acp_ch_psrc1);
			ASSERT(chpptr->acp_ch_psrc2);
			return (AUDIO_SUCCESS);
		}
	} else {
		ASSERT(dir == AUDIO_RECORD);
		srs = ad_infop->ad_record.ad_conv;
		size = srs->ad_src_size(AM_SRC_CHPTR2HDL(chptr),
		    &info->record, AUDIO_RECORD, samples, hw_channels);
		if (chpptr->acp_ch_rsrc_siz &&
			size <= chpptr->acp_ch_rsrc_siz) {
			/* buffers large enough */
			ASSERT(chpptr->acp_ch_rsrc1);
			ASSERT(chpptr->acp_ch_rsrc2);
			return (AUDIO_SUCCESS);
		}
	}

	if ((tmp1 = kmem_alloc(size, KM_NOSLEEP)) == NULL) {
		ATRACE("am_update_src_buffer() kmem_alloc(1) failed", NULL);
		return (AUDIO_FAILURE);
	}
	if ((tmp2 = kmem_alloc(size, KM_NOSLEEP)) == NULL) {
		ATRACE("am_update_src_buffer() kmem_alloc(2) failed", NULL);
		kmem_free(tmp1, size);
		return (AUDIO_FAILURE);
	}

	if (dir == AUDIO_PLAY) {
		if (chpptr->acp_ch_psrc1) {
			kmem_free(chpptr->acp_ch_psrc1,
			    chpptr->acp_ch_psrc_siz);
		}
		if (chpptr->acp_ch_psrc2) {
			kmem_free(chpptr->acp_ch_psrc2,
			    chpptr->acp_ch_psrc_siz);
		}
		chpptr->acp_ch_psrc1 = tmp1;
		chpptr->acp_ch_psrc2 = tmp2;
		chpptr->acp_ch_psrc_siz = size;
	} else {
		if (chpptr->acp_ch_rsrc1) {
			kmem_free(chpptr->acp_ch_rsrc1,
			    chpptr->acp_ch_rsrc_siz);
		}
		if (chpptr->acp_ch_rsrc2) {
			kmem_free(chpptr->acp_ch_rsrc2,
			    chpptr->acp_ch_rsrc_siz);
		}
		chpptr->acp_ch_rsrc1 = tmp1;
		chpptr->acp_ch_rsrc2 = tmp2;
		chpptr->acp_ch_rsrc_siz = size;
	}

	return (AUDIO_SUCCESS);

}	/* am_update_src_buffer() */

/*
 * Private routines used only by this file.
 */

/*
 * am_flush()
 *
 * Description:
 *	Flush the data stream. We handle both play and record. In order
 *	to flush we have to clear out any play buffers so we have to stop
 *	and then restart. This applies to both play and record.
 *
 * Arguments:
 *	queue_t		*q	Pointer to a queue
 *	mblk_t		*mp	Ptr to the msg block being passed to the queue
 *
 * Returns:
 *	void
 */
static void
am_flush(queue_t *q, mblk_t *mp)
{
	audio_ch_t		*chptr = (audio_ch_t *)
				    audio_sup_get_qptr_data(q);
	audio_state_t		*statep = chptr->ch_statep;
	audio_apm_info_t	*apm_infop = chptr->ch_apm_infop;
	audio_info_t		*hw_info = apm_infop->apm_ad_state;
	am_ad_info_t		*ad_infop = chptr->ch_apm_infop->apm_ad_infop;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	am_ch_private_t		*chpptr = chptr->ch_private;
	audio_info_t		*tinfo;
	mblk_t			*tmp;

	ATRACE("in am_flush()", q);

	ASSERT(chptr);

	/* are we flushing the play side? */
	if (*mp->b_rptr & FLUSHW) {
		ATRACE("am_flush() flushing play side", 0);
		flushq(q, FLUSHDATA);
		*mp->b_rptr &= ~FLUSHW;

		mutex_enter(&chptr->ch_lock);

		/* flush accumulated data */
		audio_sup_flush_audio_data(chptr);

		/*
		 * Flush the DMA engine and Codec, but only if this
		 * channel points to the hardware and is an AUDIO
		 * channel.
		 */
		tinfo = chptr->ch_info.info;
		chpptr->acp_flags |= AM_CHNL_EMPTY;
		if (chptr->ch_info.dev_type == AUDIO &&
		    (chptr->ch_info.info == apm_infop->apm_ad_state ||
		    ad_infop->ad_codec_type == AM_MS_CODEC)) {
			/* before we can flush the DMA engine we must stop it */
			mutex_exit(&chptr->ch_lock);
			am_ad_stop_play(statep, stpptr, ad_infop,
			    chptr->ch_info.ch_number);
			mutex_enter(&chptr->ch_lock);

			tinfo->play.active = 0;
			hw_info->play.active = 0;
			/* we don't change pause flag, it can be set */
		}

		/* update the played sample count */
		if (stpptr->am_pstate->apm_mode == AM_MIXER_MODE &&
		    ad_infop->ad_codec_type == AM_TRAD_CODEC) {
			tinfo->play.samples +=
			    ad_infop->ad_play.ad_conv->ad_src_adjust(
			    AM_SRC_CHPTR2HDL(chptr), AUDIO_PLAY,
			    chpptr->acp_psamples_p);
		} else {
			tinfo->play.samples += chpptr->acp_psamples_p;
		}
		chpptr->acp_psamples_c = 0;
		chpptr->acp_psamples_f = 0;
		chpptr->acp_psamples_p = 0;

		/* by definition we are empty */
		am_audio_drained(chptr);
		mutex_exit(&chptr->ch_lock);

		ATRACE("am_flush() flushing play done", q);
	}

	/* now for the record side */
	if (*mp->b_rptr & FLUSHR) {
		ATRACE("am_flush() flushing record side", 0);

		/*
		 * Flush the DMA engine and Codec, but only if this channel
		 * points to the hardware and is an AUDIO channel.
		 */
		if (chptr->ch_info.dev_type == AUDIO) {
			/*
			 * We only flush AUDIO channels, there's nothing on
			 * AUDIOCTL channels to flush.
			 */
			mutex_enter(&chptr->ch_lock);
			tinfo = chptr->ch_info.info;
			if (tinfo->record.active &&
			    (chptr->ch_info.info == apm_infop->apm_ad_state ||
			    ad_infop->ad_codec_type == AM_MS_CODEC)) {
				/*
				 * Before we can flush the DMA engine we
				 * must stop it.
				 */
				mutex_exit(&chptr->ch_lock);

				am_ad_stop_record(statep, stpptr, ad_infop,
				    chptr->ch_info.ch_number);

				/*
				 * Flush any partially captured data. This
				 * needs to be done before we restart recording.
				 */
				mutex_enter(&chptr->ch_lock);
				if (chpptr->acp_rec_mp) {
					tmp = chpptr->acp_rec_mp;
					chpptr->acp_rec_mp = NULL;
					mutex_exit(&chptr->ch_lock);

					freemsg(tmp);
				} else {
					mutex_exit(&chptr->ch_lock);
				}

				/* restart the record */
				if (am_ad_start_record(statep,
				    apm_infop->apm_private, ad_infop,
				    chptr->ch_info.ch_number,
				    AM_SERIALIZE) == AUDIO_FAILURE) {
					audio_sup_log(AUDIO_STATE2HDL(statep),
					    CE_WARN, "couldn't restart record "
					    "after flush");
					tinfo->record.active = 0;
					hw_info->record.active = 0;
				}
			} else {
				/*
				 * Not currently recording but we still
				 * need to flush any partial buffers.
				 */
				if (chpptr->acp_rec_mp) {
					tmp = chpptr->acp_rec_mp;
					chpptr->acp_rec_mp = NULL;
					mutex_exit(&chptr->ch_lock);

					freemsg(tmp);
				} else {
					mutex_exit(&chptr->ch_lock);
				}
			}
		}

		/* send the flush back up to the STREAMS head */
		*mp->b_rptr &= ~FLUSHW;	/* clear the write */
		qreply(q, mp);
		mp = NULL;		/* stop freemsg() */

		ATRACE("am_flush() flushing read done", q);
	}

	if (mp) {
		freemsg(mp);
	}

	ATRACE("am_flush() returning", q);

}	/* am_flush() */

/*
 * am_p_process()
 *
 * Description:
 *	Process the message block into canonical form. If in MIXER mode
 *	then we also sample rate convert it to match the hardware. When
 *	done the original data and the converted data, if present, are
 *	saved in an audio_data_t structure. If sample rate conversion
 *	fails we don't worry about it. There is a second chance when
 *	the samples are mixed.
 *
 *	CAUTION: This routine is called from interrupt context, so memory
 *		allocation cannot sleep.
 *
 * Arguments:
 *	audio_ch_t	*chptr		Pointer to this channel's state info
 *	void		*buf		Ptr to the original msg block being
 *					processed
 *	size_t		size		The size of the data buffer in bytes
 *	int		**orig_data	Ptr to the original canonical audio ptr
 *	size_t		*orig_size	Ptr to the original audio size
 *	int		**proc_data	Ptr to the processed canonical audio ptr
 *	size_t		*proc_size	Ptr to the processed audio size
 *
 * Returns:
 *	AUDIO_SUCCESS		Data converted and saved
 *	AUDIO_FAILURE		Data conversion and save failed, audio lost
 */
static int
am_p_process(audio_ch_t *chptr, void *buf, size_t size, int **orig_data,
    size_t *orig_size, int **proc_data, size_t *proc_size)
{
	audio_state_t		*statep = chptr->ch_statep;
	audio_info_t		*info;
	am_ch_private_t		*chpptr = chptr->ch_private;
	am_apm_private_t	*stpptr = chptr->ch_apm_infop->apm_private;
	am_ad_info_t		*ad_infop = chptr->ch_apm_infop->apm_ad_infop;
	am_ad_src_entry_t	*psrs = ad_infop->ad_play.ad_conv;
	int			*dest;
	int			*src;
	int			*tmp;
	int			tmp_size;
	uint_t			channels;
	uint_t			encoding;
	uint_t			precision;
	uint_t			hw_channels;
	int			i;
	int			mode;
	int			orig_samples;
	int			src_samples;
	int			val;
	int			*conv;
	int			*data_start;
	size_t			orig_size_plus_pb;

	ATRACE("in am_p_process()", buf);
	ATRACE("am_p_process() size", size);

	ASSERT(MUTEX_HELD(&stpptr->am_mode_lock));

	/* set after we are frozen */
	info = chptr->ch_info.info;
	channels = info->play.channels;
	encoding = info->play.encoding;
	precision = info->play.precision;
	hw_channels = stpptr->am_hw_pchs;
	mode = stpptr->am_pstate->apm_mode;

	/* figure out the number of samples */
	orig_samples = size / (precision >> AUDIO_PRECISION_SHIFT);
	*orig_size = orig_samples << AM_INT32_SHIFT;
	orig_size_plus_pb = *orig_size + chpptr->acp_ch_pbuf_size;
	ATRACE_32("am_p_process() BUF orig_size", *orig_size);
	ATRACE_32("am_p_process() BUF orig_samples", orig_samples);

	/*
	 * It is possible that an odd sample write has happened. This can
	 * happen when the system is very busy and partial STREAMS messages
	 * are created. Or when an application just plain makes a mistake.
	 * We chop off the partial sample and press on. This does mean it is
	 * possible that the next buffer will be out of sync. If it was due to
	 * the STREAMS message being chopped off then hopefully this just
	 * finish off the messed up buffer and all will be back in sync. If it
	 * was because the app is in error, then there's not much hope.
	 *
	 * This applies only for stereo, mono can be odd.
	 */
	if (channels == AUDIO_CHANNELS_STEREO) {
		if ((orig_samples % AUDIO_CHANNELS_STEREO) != 0) {
			ATRACE("am_p_process() stereo samples chopped",
			    orig_samples);

			/* fix */
			orig_samples = orig_samples -
			    (orig_samples % AUDIO_CHANNELS_STEREO);
			*orig_size = orig_samples << AM_INT32_SHIFT;
			orig_size_plus_pb = *orig_size +
			    chpptr->acp_ch_pbuf_size;

			ATRACE_32("am_p_process() new BUF orig_size",
			    *orig_size);
			ATRACE_32("am_p_process() new BUF orig_samples",
			    orig_samples);
		}
		ATRACE("am_p_process() stereo samples okay", orig_samples);
	}

	/*
	 * If we are going to need to do sample rate conversion then make sure
	 * we've got good buffers.
	 */
	if (mode == AM_MIXER_MODE && ad_infop->ad_codec_type == AM_TRAD_CODEC) {
		/*
		 * Make sure we've got good sample rate converter buffers.
		 * However, even if we fail we still proceed. We get a second
		 * chance later on to do the sample rate conversion.
		 */
		if (am_update_src_buffer(chptr, orig_samples, hw_channels,
		    AUDIO_PLAY) == AUDIO_SUCCESS) {
			ATRACE("am_p_process() update_src_buffer() okay", 0);
			src_samples = orig_samples;
		} else {
			/* mark the failure */
			ATRACE_32(
			    "am_p_process() calling update_src_buffer() failed",
			    mode);
			src_samples = 0;
		}
	} else {
		/* setting to 0 also means don't do src */
		src_samples = 0;
	}
	ATRACE_32("am_p_process() src_samples", src_samples);

	/*
	 * We convert to 16-bit linear in a 32-bit integer only if buf != NULL.
	 *
	 * For converting to canonical format or sample rate conversion
	 * we need several buffers. We use acp_ch_pconv* for conversion and
	 * acp_ch_pptr* for sample rate conversion. There are two buffers
	 * for each, which gives us the space to toggle. We need different
	 * buffers because we could be converting to 32-bit linear PCM the
	 * same time we are sample rate converting.
	 */
	if (am_update_conv_buffer(chptr, orig_size_plus_pb,
		AUDIO_PLAY) == AUDIO_FAILURE) {
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
			"!process(1) couldn't allocate memory, audio lost");
		return (AUDIO_FAILURE);
	}

	/* prepare for failure */
	*proc_data = NULL;
	*proc_size = 0;

	/*
	 * Do the conversions. We try to minimize data copies as much as
	 * possible. There are three possible situations, and how we deal
	 * with the conversions. We make sure we do the sample rate conversion
	 * on the minimum amount of audio data
	 *
	 * same (mono --> mono or stereo --> stereo)
	 *	am_convert_to_int(buf)		--> orig data
	 *	SRC(orig data)			--> proc data
	 *
	 * mono --> stereo
	 *	am_convert_to_int(buf)		--> tmp data
	 *	inline mono2stereo(tmp data)	--> orig data
	 *	SRC(tmp data)			--> tmp data
	 *	inline mono2stereo(tmp data)	--> proc data
	 *
	 * stereo --> mono
	 *	am_convert_to_int(buf)		--> tmp data
	 *	inline stereo2mono(tmp data)	--> orig data
	 *	SRC(orig data)			--> proc data
	 */
	if (channels == hw_channels) {
		/* either mono --> mono or stereo --> stereo */
		ATRACE("am_p_process() channels == hw_channels", 0);

		*orig_data = kmem_alloc(*orig_size, KM_NOSLEEP);
		if (*orig_data == NULL) {
			audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
			    "!process(2) couldn't allocate"
			    " memory, audio lost");
			return (AUDIO_FAILURE);
		}

		/* convert to int and place in orig data */
		am_convert_to_int(buf, *orig_data, orig_samples, precision,
		    encoding, 0);

		/* SRC the data if we need to */
		if (src_samples) {

			/* only do extra work if necessary */
			if (chpptr->acp_ch_pbuf_size > 0) {

				/* set conv pointing to pconv1 */
				conv = chpptr->acp_ch_pconv1;

				/* set data_start pointing to incoming data */
				data_start = conv + (chpptr->acp_ch_pbuf_size
					>> AM_TIMES_4_SHIFT);

				/* we have to copy orig data to data_start */
				bcopy(*orig_data, data_start, *orig_size);
			} else {
				/* set conv pointing to orig data */
				conv = *orig_data;
			}

			tmp = psrs->ad_src_convert(AM_SRC_CHPTR2HDL(chptr),
			    channels, AUDIO_PLAY, conv, chpptr->acp_ch_psrc1,
			    chpptr->acp_ch_psrc2, &src_samples);

			ASSERT(src_samples <= (chpptr->acp_ch_psrc_siz >>
				AM_TIMES_4_SHIFT));

			/* if successful then update info */
			if (tmp) {
				/* sizeof (int) = 4 */
				tmp_size = src_samples << AM_TIMES_4_SHIFT;
				*proc_data = kmem_alloc(tmp_size, KM_NOSLEEP);
				if (*proc_data) {
					bcopy(tmp, *proc_data, tmp_size);
					*proc_size = tmp_size;
				}
			}
		}
	} else if (channels < hw_channels) {
		/* mono --> stereo */
		ATRACE_32("am_p_process() to stereo", channels);
		ASSERT(channels == AUDIO_CHANNELS_MONO);
		ASSERT(hw_channels == AUDIO_CHANNELS_STEREO);

		/* set data_start pointing to incoming data */
		data_start = (int *)chpptr->acp_ch_pconv1 +
		    (chpptr->acp_ch_pbuf_size >> AM_TIMES_4_SHIFT);

		/*
		 * Convert to int and save. We need this mono data twice,
		 * as the source for SRC and to be converted to stereo. If
		 * we converted directly to stereo then we would have to
		 * do SRC on stereo instead of mono.
		 */
		am_convert_to_int(buf, data_start, orig_samples, precision,
		    encoding, 0);

		/* double in size and allocate orig data to save */
		*orig_size <<= AM_TIMES_2_SHIFT;
		*orig_data = kmem_alloc(*orig_size, KM_NOSLEEP);
		if (*orig_data == NULL) {
			audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
			    "!process(2) couldn't allocate"
			    " memory, audio lost");
			return (AUDIO_FAILURE);
		}

		/* convert to stereo */
		src = data_start;
		dest = *orig_data;
		for (i = orig_samples; i--; ) {
			/* dup to left and right channels */
			val = *src++;
			*dest++ = val;
			*dest++ = val;
		}

		/* SRC the data and then convert to stereo */
		if (src_samples) {
			/* SRC the old mono data, not the new stereo data */
			tmp = psrs->ad_src_convert(AM_SRC_CHPTR2HDL(chptr),
			    AUDIO_CHANNELS_MONO, AUDIO_PLAY,
			    chpptr->acp_ch_pconv1, chpptr->acp_ch_psrc1,
			    chpptr->acp_ch_psrc2, &src_samples);

			ASSERT(src_samples <= (chpptr->acp_ch_psrc_siz >>
			    AM_TIMES_4_SHIFT));

			/* if successful then convert to stereo and save */
			if (tmp) {
				/* sizeof (int) * 2 = 8 */
				tmp_size = src_samples << AM_TIMES_8_SHIFT;
				*proc_data = kmem_alloc(tmp_size, KM_NOSLEEP);
				if (*proc_data) {
					src = tmp;
					dest = *proc_data;
					for (i = src_samples; i--; ) {
						/* dup to left & right chs */
						val = *src++;
						*dest++ = val;
						*dest++ = val;
					}
					*proc_size = tmp_size;
				}
			}
		}
	} else {
		/* stereo --> mono */
		ATRACE_32("am_p_process() to mono", channels);
		ASSERT(channels == AUDIO_CHANNELS_STEREO);
		ASSERT(hw_channels == AUDIO_CHANNELS_MONO);

		/* set data_start pointing to incoming data */
		data_start = (int *)chpptr->acp_ch_pconv1 +
		    (chpptr->acp_ch_pbuf_size >> AM_TIMES_4_SHIFT);

		/* convert to int and then from stereo --> mono */
		am_convert_to_int(buf, data_start, orig_samples, precision,
		    encoding, 0);

		/* divide in half the size and allocate orig data to save */
		*orig_size >>= AM_TIMES_2_SHIFT;
		*orig_data = kmem_alloc(*orig_size, KM_NOSLEEP);
		if (*orig_data == NULL) {
			audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
			    "!process(3) couldn't allocate"
			    " memory, audio lost");
			return (AUDIO_FAILURE);
		}

		/* convert to mono */
		src = data_start;
		dest = *orig_data;
		for (i = (orig_samples >> AM_TIMES_2_SHIFT); i--; ) {
			/* average the left and right channels */
			val = *src++;
			val += *src++;
			*dest++ = val >> AM_HALF_ENERGY_SHIFT;
		}

		/* SRC the data, which is already mono */
		if (src_samples) {
			tmp = psrs->ad_src_convert(AM_SRC_CHPTR2HDL(chptr),
			    AUDIO_CHANNELS_MONO, AUDIO_PLAY,
			    chpptr->acp_ch_pconv1, chpptr->acp_ch_psrc1,
			    chpptr->acp_ch_psrc2, &src_samples);

			ASSERT(src_samples <= (chpptr->acp_ch_psrc_siz >>
			    AM_TIMES_4_SHIFT));

			/* if successful then update info */
			if (tmp) {
				/* sizeof (int) = 4 */
				tmp_size = src_samples << AM_TIMES_4_SHIFT;
				*proc_data = kmem_alloc(tmp_size, KM_NOSLEEP);
				if (*proc_data) {
					bcopy(tmp, *proc_data, tmp_size);
					*proc_size = tmp_size;
				}
			}
		}
	}

	return (AUDIO_SUCCESS);

}	/* am_p_process() */

/*
 * am_set_waiting()
 *
 * Description:
 *	Go through all of the channels. If PID is set then we set the read
 *	and write waiting flags for that PID only. If PID is 0 then we set
 *	all of the AUDIO channels. We set the flag to the argument value.
 *	This lets this routine to be used to both set and clear the flag.
 *
 * Arguments:
 *	audio_state_t	*statep		Pointer to the device instance's state
 *	pid_t		pid		The PID to match
 *	int		value		Value to set the waiting flag
 *	boolean_t	wantwrite	If not 0 then set play.waiting
 *	boolean_t	wantread	If not 0 then set record.waiting
 *
 * Returns:
 *	void
 */
static void
am_set_waiting(audio_state_t *statep, pid_t pid, int value, boolean_t wantwrite,
    boolean_t wantread)
{
	audio_ch_t		*tchptr;
	audio_info_t		*info;
	int			i;
	int			max_chs = statep->as_max_chs;

	ASSERT(MUTEX_HELD(&statep->as_lock));

	for (i = 0, tchptr = &statep->as_channels[0]; i < max_chs;
	    i++, tchptr++) {

		/* skip non-audio channels */
		mutex_enter(&tchptr->ch_lock);
		if (!(tchptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
		    tchptr->ch_info.dev_type != AUDIO ||
		    tchptr->ch_info.pid == 0) {
			mutex_exit(&tchptr->ch_lock);
			continue;
		}

		/* if pid then look for that PID, otherwise all others */
		if (pid && tchptr->ch_info.pid != pid) {
			mutex_exit(&tchptr->ch_lock);
			continue;
		}

		/* pid == 0 or pid's match, so set flags */
		info = tchptr->ch_info.info;
		if (wantwrite) {
			info->play.waiting = (uchar_t)value;
		}
		if (wantread) {
			info->record.waiting = (uchar_t)value;
		}
		mutex_exit(&tchptr->ch_lock);
	}

	ASSERT(MUTEX_HELD(&statep->as_lock));

}	/* am_set_waiting() */
