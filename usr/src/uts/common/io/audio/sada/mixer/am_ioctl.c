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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains the code for implementing the ioctl()s that the audio.7I
 * and mixer.7I man pages define. This file also contains private routines to
 * support these calls.
 *
 * am_wput() in am_main.c just grabs the M_IOCTL and M_IOCDATA messages and
 * sends them to either am_wioctl() or am_wiocdata(), where all processing
 * takes place. am_svc() doesn't do any ioctl() processing at all.
 *
 * The following ioctl()s are supported:
 *	AUDIO_DIAG_LOOPBACK
 *	AUDIO_DRAIN
 *	AUDIO_GETINFO
 *	AUDIO_SETINFO
 *	AUDIO_GETDEV
 *	AUDIO_MIXER_MULTIPLE_OPEN
 *	AUDIO_MIXER_SINGLE_OPEN
 *	AUDIO_MIXER_GET_SAMPLE_RATES
 *	AUDIO_MIXERCTL_GETINFO
 *	AUDIO_MIXERCTL_SETINFO
 *	AUDIO_MIXERCTL_GET_CHINFO
 *	AUDIO_MIXERCTL_SET_CHINFO
 *	AUDIO_MIXERCTL_GET_MODE
 *	AUDIO_MIXERCTL_SET_MODE
 *
 * Most of the ioctl()s copy in a data structure for use by the ioctl().
 * am_wioctl() or am_wiocdata() will request the data. Based on the ioctl()
 * it then creates a data structure and enqueues a task request to execute
 * that ioctl() in a separate thread. This allows am_wput() and am_wsvc() to
 * continue working while the ioctl() is processed. When the ioctl() in it's
 * own thread is complete it creates the appropriate message and sends it
 * back up the queue. Further processing to copy out and ack/nack is done by
 * am_wiocdata().
 *
 * A task queue is used to serialize all access to the hardware state
 * structures and the hardware. This greatly simplifies the locking model.
 * When closing we wait for all of the tasks to complete. This may introduce
 * a delay in closing, but tests with 40 playing channels shows no noticable
 * delays.
 *
 * Two ioctl()s are not placed on the task queue. They are:
 *
 *	AUDIO_GETINFO - Returns static data and thus the hardware state is
 *		irrelevant.
 *	AUDIO_DRAIN - This ioctl() doesn't change or get the device state.
 *		It is also a very long lived ioctl() and is dependent on how
 *		much audio is queued up. We don't want to block other channels
 *		from being open()ed or their ioctl()s. Because this is a long
 *		lived ioctl() it is handled in am_wsvc() instead of am_wput().
 *		Otherwise it would block am_wput() and this is against the
 *		rules.
 *
 * Signals are generated when the hardware is modified. The signal is sent
 * after the ioctl()'s ack or nack has been sent. That way we don't get an
 * interrupted system call.
 *
 * These routines are provided for use by the other mixer source code files:
 *	am_wiocdata()
 *	am_wioctl()
 *	am_audio_drained()
 *	am_audio_set_info()
 *	am_set_format()
 *	am_set_gain()
 */

#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/stropts.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsun.h>
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
 * Local routine prototypes used only by this file.
 */
static int am_ck_bits_set32(uint_t);
static void am_exit_task(audio_ch_t *);
static void am_fix_info(audio_ch_t *, audio_info_t *);
static void am_fix_play_pause(audio_ch_t *);
static void am_mixer_task_acknack(audio_i_state_t *, audio_ch_t *,
	queue_t *, mblk_t *, am_ioctl_args_t *, int);
static void am_restart(audio_state_t *, audio_info_t *);
static int am_sched_task(queue_t *, mblk_t *, audio_ch_t *,
	void (*func)(void *));
static int am_set_compat_mode(audio_ch_t *, am_ad_info_t *, audio_ch_t *,
	audio_ch_t *);
static int am_set_mixer_mode(audio_ch_t *, am_ad_info_t *, am_apm_private_t *,
	audio_ch_t *, audio_ch_t *);
static int am_wiocdata_mixerctl_chinfo(queue_t *, mblk_t *, audio_i_state_t *);
static int am_wiocdata_mixerctl_get_chinfo(queue_t *, mblk_t *,
	audio_i_state_t *);
static int am_wiocdata_sr(queue_t *, mblk_t *, struct copyreq *,
	audio_i_state_t *);
static int am_wioctl_copyin(queue_t *, mblk_t *, audio_ch_t *,
	audio_i_state_t *, int);
static void am_wioctl_drain(queue_t *, mblk_t *, audio_ch_t *,
	struct copyreq *);
static int am_wioctl_getdev(queue_t *, mblk_t *, audio_ch_t *,
	audio_i_state_t *);

/*
 * Taskq callbacks.
 */
static void am_diag_loopback_task(void *);
static void am_get_chinfo_task(void *);
static void am_get_mode_task(void *);
static void am_getinfo_task(void *);
static void am_mixerctl_getinfo_task(void *);
static void am_mixerctl_setinfo_task(void *);
static void am_multiple_open_task(void *);
static void am_sample_rate_task(void *);
static void am_set_chinfo_task(void *);
static void am_set_mode_task(void *);
static void am_setinfo_task(void *);
static void am_single_open_task(void *);

/* this simulates the rw lock handling by taskq framework */
#ifdef __lock_lint
extern krwlock_t q_lock;

static void
am_enter_rwlock()
{
	_NOTE(READ_LOCK_ACQUIRED_AS_SIDE_EFFECT(&q_lock));
	rw_enter(&q_lock, RW_READER);
}

static void
am_release_rwlock()
{
	_NOTE(LOCK_RELEASED_AS_SIDE_EFFECT(&q_lock));
	rw_exit(&q_lock);
}
#else
#define	am_enter_rwlock()
#define	am_release_rwlock()
#endif

/*
 * The main routines for this file.
 */

/*
 * am_wiocdata()
 *
 * Description:
 *	This routine is called by am_wput() to process all M_IOCDATA
 *	messages.
 *
 *	We only support transparent ioctls.
 *
 *	This routine also is used to return a IOCNAK if the state pointer
 *	or the channel pointer, setup in am_wsvc(), are invalid.
 *
 *	CAUTION: This routine is called from interrupt context, so memory
 *		allocation cannot sleep.
 *
 *	WARNING: Don't forget to free the mblk_t struct used to hold private
 *		data. The ack: and nack: jump points take care of this.
 *
 *	WARNING: Don't free the private mblk_t structure if the command is
 *		going to call qreply(). This frees the private data that will
 *		be needed for the next M_IOCDATA message.
 *
 * Arguments:
 *	queue_t		*q	Pointer to the STREAMS queue
 *	mblk_t		*mp	Pointer to the message block
 *	audio_ch_t	*chptr	Pointer to this channel's state information
 *
 * Returns:
 *	0			Always returns a 0, becomes a return for
 *				am_wsvc()
 */
int
am_wiocdata(queue_t *q, mblk_t *mp, audio_ch_t *chptr)
{
	audio_state_t		*statep = chptr->ch_statep;
	audio_apm_info_t	*apm_infop = chptr->ch_apm_infop;
	am_ad_info_t		*ad_infop = apm_infop->apm_ad_infop;
	am_apm_private_t	*stpptr = chptr->ch_apm_infop->apm_private;
	struct copyreq		*cqp;
	struct copyresp		*csp;
	audio_i_state_t		*cmd;
	int			error = 0;
	int			send_sig = 0;

	ATRACE("in am_wiocdata()", chptr);
	ATRACE_32("am_wiocdata() channel type", chptr->ch_info.dev_type);

	ASSERT(statep);
	ASSERT(!MUTEX_HELD(&apm_infop->apm_lock));

	csp = (struct copyresp *)mp->b_rptr;	/* setup copy response ptr */
	cqp = (struct copyreq *)mp->b_rptr;	/* setup copy request ptr */
	cmd = (audio_i_state_t *)csp->cp_private;	/* get state info */

	/* make sure we've got a good return value */
	if (csp->cp_rval) {
		ATRACE("am_wiocdata() bad return value", csp->cp_rval);
		error = EINVAL;
		goto done;
	}

	/*
	 * Work through the iocdata messages. These are arranged so that
	 * the messages that need to do further work are ordered first and
	 * then the ACKs.
	 */
	if (cmd != NULL) {
		ATRACE_32("am_wiocdata() command", cmd->ais_command);
		switch (cmd->ais_command) {

		case AM_COPY_IN_AUDIOINFO:
			/* AUDIO_SETINFO */
			ATRACE("am_wiocdata() AM_COPY_IN_AUDIOINFO", chptr);
			ASSERT(csp->cp_cmd == AUDIO_SETINFO);

			error = am_sched_task(q, mp, chptr, am_setinfo_task);
			if (error) {
				goto done;
			}
			return (0);

		case AM_COPY_IN_DIAG_LOOPB:
			/* AUDIO_DIAG_LOOPBACK */
			ATRACE("am_wiocdata() AM_COPY_IN_DIAG_LOOPB", chptr);
			ASSERT(csp->cp_cmd == AUDIO_DIAG_LOOPBACK);

			error = am_sched_task(q, mp, chptr,
			    am_diag_loopback_task);
			if (error) {
				goto done;
			}
			return (0);

		case AM_COPY_IN_SAMP_RATES:
			/* AUDIO_MIXER_GET_SAMPLE_RATES */
			ATRACE("am_wiocdata() AM_COPY_IN_SAMP_RATES", chptr);
			ASSERT(csp->cp_cmd == AUDIO_MIXER_GET_SAMPLE_RATES);

			error = am_wiocdata_sr(q, mp, cqp, cmd);
			if (error) {
				goto done;
			}
			return (0);

		case AM_COPY_IN_SAMP_RATES2:
			/* AUDIO_MIXER_GET_SAMPLE_RATES */
			ATRACE("am_wiocdata() AM_COPY_IN_SAMP_RATES2", chptr);
			ASSERT(csp->cp_cmd == AUDIO_MIXER_GET_SAMPLE_RATES);

			error = am_sched_task(q, mp, chptr,
			    am_sample_rate_task);
			if (error) {
				goto done;
			}
			return (0);

		case AM_COPY_IN_MIXCTLINFO:
			/* AUDIO_MIXERCTL_SETINFO */
			ATRACE("am_wiocdata() AM_COPY_IN_MIXCTLINFO", chptr);
			ASSERT(csp->cp_cmd == AUDIO_MIXERCTL_SETINFO);

			error = am_sched_task(q, mp, chptr,
			    am_mixerctl_setinfo_task);
			if (error) {
				goto done;
			}
			return (0);

		case AM_COPY_IN_MIXCTL_GET_CHINFO:
			/* AUDIO_MIXERCTL_GET_CHINFO */
			ATRACE("am_wiocdata() AM_COPY_IN_MIXCTL_CHINFO", chptr);
			ASSERT(csp->cp_cmd == AUDIO_MIXERCTL_GET_CHINFO);

			error = am_sched_task(q, mp, chptr, am_get_chinfo_task);
			if (error) {
				goto done;
			}
			return (0);

		case AM_COPY_OUT_MIXCTL_GET_CHINFO:
			/* AUDIO_MIXERCTL_GET/SET_CHINFO */
			ATRACE("am_wiocdata() AM_COPY_OUT_MIXCTL_GET_CHINFO",
			    chptr);
			ASSERT(csp->cp_cmd == AUDIO_MIXERCTL_GET_CHINFO ||
			    csp->cp_cmd == AUDIO_MIXERCTL_SET_CHINFO);

			error = am_wiocdata_mixerctl_get_chinfo(q, mp, cmd);
			if (error) {
				goto done;
			}
			return (0);

		case AM_COPY_IN_MIXCTL_SET_CHINFO:
			/* AUDIO_MIXERCTL_SET_CHINFO */
			ATRACE("am_wiocdata() AM_COPY_IN_MIXCTL_CHINFO", chptr);
			ASSERT(csp->cp_cmd == AUDIO_MIXERCTL_SET_CHINFO);

			error = am_wiocdata_mixerctl_chinfo(q, mp, cmd);
			if (error) {
				goto done;
			}
			return (0);

		case AM_COPY_IN_MIXCTL_SET_CHINFO2:
			/* AUDIO_MIXERCTL_SET_CHINFO */
			ATRACE("am_wiocdata() AM_COPY_IN_MIXCTL_CHINFO", chptr);
			ASSERT(csp->cp_cmd == AUDIO_MIXERCTL_SET_CHINFO);

			error = am_sched_task(q, mp, chptr, am_set_chinfo_task);
			if (error) {
				goto done;
			}
			return (0);

		case AM_COPY_IN_MIXCTL_MODE:
			/* AUDIO_MIXERCTL_SET_MODE */
			ATRACE("am_wiocdata() AM_COPY_IN_MIXCTL_MODE", chptr);
			ASSERT(csp->cp_cmd == AUDIO_MIXERCTL_SET_MODE);

			error = am_sched_task(q, mp, chptr, am_set_mode_task);
			if (error) {
				goto done;
			}
			return (0);

		case AM_COPY_OUT_AUDIOINFO:
			/* AUDIO_GETINFO */
			ATRACE("am_wiocdata() AM_COPY_OUT_AUDIOINFO", chptr);
			ASSERT(csp->cp_cmd == AUDIO_GETINFO);

			goto done;

		case AM_COPY_OUT_AUDIOINFO2:
			/* AUDIO_SETINFO */
			ATRACE("am_wiocdata() AM_COPY_OUT_AUDIOINFO2", chptr);
			ASSERT(csp->cp_cmd == AUDIO_SETINFO);

			send_sig++;

			goto done;

		case AM_COPY_OUT_GETDEV:
			/* AUDIO_GETDEV */
			ATRACE("am_wiocdata() AM_COPY_OUT_GETDEV", chptr);
			ASSERT(csp->cp_cmd == AUDIO_GETDEV);

			goto done;

		case AM_COPY_OUT_SAMP_RATES:
			/* AUDIO_MIXER_GET_SAMPLE_RATES */
			ATRACE("am_wiocdata() AM_COPY_OUT_SAMP_RATES", chptr);
			ASSERT(csp->cp_cmd == AUDIO_MIXER_GET_SAMPLE_RATES);

			goto done;

		case AM_COPY_OUT_MIXCTLINFO:
			/* AUDIO_MIXERCTL_GET/SETINFO */
			ATRACE("am_wiocdata() AM_COPY_OUT_MIXCTLINFO", chptr);
			ASSERT(csp->cp_cmd == AUDIO_MIXERCTL_GETINFO ||
			    csp->cp_cmd == AUDIO_MIXERCTL_SETINFO);

			/* generate a signal ONLY when we set the info */
			if (csp->cp_cmd == AUDIO_MIXERCTL_SETINFO) {
				send_sig++;
			}

			goto done;

		case AM_COPY_OUT_MIXCTL_GET_CHINFO2:
			/* AUDIO_MIXERCTL_GET/SET_CHINFO */
			ATRACE("am_wiocdata() AM_COPY_OUT_MIXCTL_GET_CHINFO2",
			    chptr);
			ASSERT(csp->cp_cmd == AUDIO_MIXERCTL_GET_CHINFO ||
			    csp->cp_cmd == AUDIO_MIXERCTL_SET_CHINFO);

			/* generate a signal ONLY when we set the info */
			if (csp->cp_cmd == AUDIO_MIXERCTL_SET_CHINFO) {
				send_sig++;
			}

			goto done;

		case AM_COPY_OUT_MIXCTL_MODE:
			/* AUDIO_MIXERCTL_GET_MODE */
			ATRACE("am_wiocdata() AM_COPY_OUT_MIXCTL_MODE", chptr);
			ASSERT(csp->cp_cmd == AUDIO_MIXERCTL_GET_MODE);

			goto done;

		default:
			ATRACE("am_wiocdata() No framework cmds found, "
			    "check driver entry points next", chptr);
			break;
		}
	}

	/* see if we have an entry pt in the Audio Driver */
	if (ad_infop->ad_entry->ad_iocdata) {
		/* we do, so call it */
		ATRACE("am_wiocdata(): "
		    "calling Audio Driver iocdata() routine",
		    ad_infop->ad_entry);

		switch (ad_infop->ad_entry->ad_iocdata(
		    AUDIO_STATE2HDL(statep), chptr->ch_info.ch_number,
		    q, mp, &error)) {
		case AM_WIOCDATA:
			return (0);
		case AM_ACK:
			goto done;
		case AM_NACK:
			goto done;
		default:
			break;
		}
	}

	/* no driver entry, so we nack unrecognized iocdata cmds */
	ATRACE("am_wiocdata() no entry", chptr);
	error = EINVAL;

	/* Done checking */
	ATRACE("am_wiocdata() switch & driver check done", chptr);

done:
	ATRACE("am_wiocdata() done", chptr);

	if (csp->cp_private) {
		kmem_free(csp->cp_private, sizeof (audio_i_state_t));
		csp->cp_private = NULL;
	}
	if (cqp->cq_private) {
		kmem_free(cqp->cq_private, sizeof (audio_i_state_t));
		cqp->cq_private = NULL;
	}

	if (error) {
		miocnak(q, mp, 0, error);
	} else {
		miocack(q, mp, 0, 0);
	}

	if (send_sig) {
		am_send_signal(statep, stpptr);
	}

	ATRACE("am_wiocdata() returning success", chptr);

	return (0);

}	/* am_wiocdata() */

/*
 * am_wioctl()
 *
 * Description:
 *	This routine is called by am_wput() to process all M_IOCTL
 *	messages.
 *
 *	We only support transparent ioctls. Since this is a driver we
 *	nack unrecognized ioctls.
 *
 *	This routine also is used to return a IOCNAK if the state pointer
 *	or the channel pointer, setup in am_wsvc(), are invalid.
 *
 *	The following ioctls are supported:
 *		AUDIO_DIAG_LOOPBACK		special diagnostics mode
 *		AUDIO_DRAIN
 *		AUDIO_GETDEV
 *		AUDIO_GETINFO
 *		AUDIO_SETINFO
 *		AUDIO_MIXER_MULTIPLE_OPEN
 *		AUDIO_MIXER_SINGLE_OPEN
 *		AUDIO_MIXER_GET_SAMPLE_RATES
 *		AUDIO_MIXERCTL_GETINFO
 *		AUDIO_MIXERCTL_SETINFO
 *		AUDIO_MIXERCTL_GET_CHINFO
 *		AUDIO_MIXERCTL_SET_CHINFO
 *		AUDIO_MIXERCTL_GET_MODE
 *		AUDIO_MIXERCTL_SET_MODE
 *		unknown		call Audio Driver ioctl() routine
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
 *				am_wsvc()
 */
int
am_wioctl(queue_t *q, mblk_t *mp, audio_ch_t *chptr)
{
	audio_state_t		*statep = chptr->ch_statep;
	audio_apm_info_t	*apm_infop = chptr->ch_apm_infop;
	am_ad_info_t		*ad_infop = apm_infop->apm_ad_infop;
	struct iocblk		*iocbp;
	struct copyreq		*cqp;
	audio_i_state_t		*state = NULL;
	audio_device_type_e	type = chptr->ch_info.dev_type;
	int			command;
	int			error = 0;

	ATRACE("in am_wioctl()", chptr);
	ATRACE_32("am_wioctl() channel type", chptr->ch_info.dev_type);

	ASSERT(statep);
	ASSERT(type == AUDIO || type == AUDIOCTL);
	ASSERT(!MUTEX_HELD(&apm_infop->apm_lock));

	iocbp = (struct iocblk *)mp->b_rptr;	/* pointer to ioctl info */
	cqp = (struct copyreq *)mp->b_rptr;	/* setup copyreq ptr */

	command = iocbp->ioc_cmd;

	/* make sure this is a transparent ioctl */
	if (iocbp->ioc_count != TRANSPARENT) {
		ATRACE_32("am_wioctl() not TRANSPARENT", iocbp->ioc_count);
		error = EINVAL;
		goto done;
	}

	/* get a buffer for priv. data, but only if this isn't an AUDIO_DRAIN */
	if (command != AUDIO_DRAIN) {
		if ((state = kmem_zalloc(sizeof (*state), KM_NOSLEEP)) ==
		    NULL) {
			ATRACE("am_wioctl() state kmem_zalloc() failed", 0);
			error = ENOMEM;
			goto done;
		}
	}

	ATRACE_32("am_wioctl() command", iocbp->ioc_cmd);
	switch (command) {

	case AUDIO_DIAG_LOOPBACK:
		ATRACE("am_wioctl() AUDIO_DIAG_LOOPBACK", chptr);

		cqp->cq_private = (mblk_t *)state;
		error = am_wioctl_copyin(q, mp, chptr, state,
		    AUDIO_DIAG_LOOPBACK);
		if (error) {
			goto done;
		}
		return (0);

	case AUDIO_DRAIN:
		ATRACE("am_wioctl() AUDIO_DRAIN", chptr);

		cqp->cq_private = NULL;
		am_wioctl_drain(q, mp, chptr, cqp);
		return (0);

	case AUDIO_GETDEV:
		ATRACE("am_wioctl() AUDIO_GETDEV", chptr);

		cqp->cq_private = (mblk_t *)state;
		error = am_wioctl_getdev(q, mp, chptr, state);
		if (error) {
			goto done;
		}
		return (0);

	case AUDIO_GETINFO:
		ATRACE("am_wioctl() AUDIO_GETINFO", chptr);

		cqp->cq_private = (mblk_t *)state;
		error = am_sched_task(q, mp, chptr, am_getinfo_task);
		if (error) {
			goto done;
		}
		return (0);

	case AUDIO_SETINFO:
		ATRACE("am_wioctl() AUDIO_SETINFO", chptr);

		cqp->cq_private = (mblk_t *)state;
		error = am_wioctl_copyin(q, mp, chptr, state,
		    AUDIO_SETINFO);
		if (error) {
			goto done;
		}
		return (0);

	case AUDIO_MIXER_MULTIPLE_OPEN:
		ATRACE("am_wioctl() AUDIO_MIXER_MULTIPLE_OPEN", chptr);

		cqp->cq_private = (mblk_t *)state;

		if (chptr->ch_info.dev_type != AUDIO) {
			error = EINVAL;
			goto done;
		}

		error = am_sched_task(q, mp, chptr, am_multiple_open_task);
		if (error) {
			goto done;
		}
		return (0);

	case AUDIO_MIXER_SINGLE_OPEN:
		ATRACE("am_wioctl() AUDIO_MIXER_SINGLE_OPEN", chptr);

		cqp->cq_private = (mblk_t *)state;

		if (chptr->ch_info.dev_type != AUDIO) {
			error = EINVAL;
			goto done;
		}

		error = am_sched_task(q, mp, chptr, am_single_open_task);
		if (error) {
			goto done;
		}
		return (0);

	case AUDIO_MIXER_GET_SAMPLE_RATES:
		ATRACE("am_wioctl() AUDIO_MIXER_GET_SAMPLE_RATES", chptr);

		cqp->cq_private = (mblk_t *)state;
		error = am_wioctl_copyin(q, mp, chptr, state,
		    AUDIO_MIXER_GET_SAMPLE_RATES);
		if (error) {
			goto done;
		}
		return (0);

	case AUDIO_MIXERCTL_GETINFO:
		ATRACE("am_wioctl() AUDIO_MIXERCTL_GETINFO", chptr);

		cqp->cq_private = (mblk_t *)state;
		error = am_sched_task(q, mp, chptr, am_mixerctl_getinfo_task);
		if (error) {
			goto done;
		}
		return (0);

	case AUDIO_MIXERCTL_SETINFO:
		ATRACE("am_wioctl() AUDIO_MIXERCTL_SETINFO", chptr);

		cqp->cq_private = (mblk_t *)state;
		error = am_wioctl_copyin(q, mp, chptr, state,
		    AUDIO_MIXERCTL_SETINFO);
		if (error) {
			goto done;
		}
		return (0);

	case AUDIO_MIXERCTL_GET_CHINFO:
		ATRACE("am_wioctl() AUDIO_MIXERCTL_GET_CHINFO", chptr);

		cqp->cq_private = (mblk_t *)state;
		error = am_wioctl_copyin(q, mp, chptr, state,
		    AUDIO_MIXERCTL_GET_CHINFO);
		if (error) {
			goto done;
		}
		return (0);

	case AUDIO_MIXERCTL_SET_CHINFO:
		ATRACE("am_wioctl() AUDIO_MIXERCTL_SET_CHINFO", chptr);

		cqp->cq_private = (mblk_t *)state;
		error = am_wioctl_copyin(q, mp, chptr, state,
		    AUDIO_MIXERCTL_SET_CHINFO);
		if (error) {
			goto done;
		}
		return (0);

	case AUDIO_MIXERCTL_GET_MODE:
		ATRACE("am_wioctl() AUDIO_MIXERCTL_GET_MODE", chptr);

		cqp->cq_private = (mblk_t *)state;

		/* allowed only on AUDIOCTL channels */
		if (chptr->ch_info.dev_type != AUDIOCTL) {
			error = EINVAL;
			goto done;
		}

		error = am_sched_task(q, mp, chptr, am_get_mode_task);
		if (error) {
			goto done;
		}
		return (0);

	case AUDIO_MIXERCTL_SET_MODE:
		ATRACE("am_wioctl() AUDIO_MIXERCTL_SET_MODE", chptr);

		cqp->cq_private = (mblk_t *)state;
		error = am_wioctl_copyin(q, mp, chptr, state,
		    AUDIO_MIXERCTL_SET_MODE);
		if (error) {
			goto done;
		}
		return (0);

	default:	/* see if we have an entry pt in the Audio Driver */
		if (ad_infop->ad_entry->ad_ioctl) {
			/* we do, so call it */
			ATRACE("am_wioctl(): "
			    "calling Audio Driver ioctl() routine",
			    ad_infop->ad_entry);
			ASSERT(ad_infop->ad_entry->ad_iocdata);

			switch (ad_infop->ad_entry->ad_ioctl(
			    AUDIO_STATE2HDL(statep), chptr->ch_info.ch_number,
			    q, mp, &error)) {
			case AM_WIOCDATA:
				return (0);
			case AM_ACK:
				goto done;
			case AM_NACK:
				goto done;
			default:
				break;
			}
		}

		/* no - we're a driver, so we nack unrecognized ioctls */
		ATRACE_32("am_wioctl() default", iocbp->ioc_cmd);

		audio_sup_log(AUDIO_STATE2HDL(statep),
		    CE_NOTE, "wioctl() unrecognized ioc_cmd: 0x%x",
		    iocbp->ioc_cmd);
		error = EINVAL;
		break;
	}

	/* we always either ack or nack depending on if error is set or not */
	ATRACE_32("am_wioctl() switch done", error);

done:
	ATRACE("am_wioctl() done", chptr);

	/* free allocated state memory */
	if (state) {
		kmem_free(state, sizeof (*state));
	}

	if (error) {
		miocnak(q, mp, 0, error);
	} else {
		miocack(q, mp, 0, 0);
	}

	ATRACE_32("am_wioctl() returning", error);

	return (0);

}	/* am_wioctl() */

/*
 * Private utilities used by this and other audio mixer files.
 */

/*
 * am_audio_drained()
 *
 * Description:
 *	There's an AUDIO_DRAIN ioctl() that is waiting. When the channel
 *	goes empty this routine is called to send the ack back to the
 *	STREAMS head, which lets the ioctl() return.
 *
 *	We also generate a CV signal so that waiting close()s will wakeup.
 *
 * Arguments:
 *	audio_ch_t	*chptr		Pointer to this channel's state info
 *
 * Returns:
 *	void
 */
void
am_audio_drained(audio_ch_t *chptr)
{
	audio_apm_info_t	*apm_infop = chptr->ch_apm_infop;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	am_ch_private_t		*chpptr = (am_ch_private_t *)chptr->ch_private;
	mblk_t			*mp;

	ATRACE("in am_audio_drained()", chptr);

	ASSERT(MUTEX_HELD(&chptr->ch_lock));

	/* make sure the channel is empty, while locked */
	if (!(chpptr->acp_flags & AM_CHNL_EMPTY)) {
		ATRACE("am_audio_drained() returned, not empty", chptr);
		return;
	}

	chpptr->acp_flags &= ~(AM_CHNL_ALMOST_EMPTY1|AM_CHNL_ALMOST_EMPTY2|\
	    AM_CHNL_DRAIN|AM_CHNL_DRAIN_NEXT_INT);
	mp = chpptr->acp_drain_mp;
	chpptr->acp_drain_mp = NULL;
	cv_signal(&chptr->ch_cv);
	ATRACE("am_audio_drained() MP", mp);

	/*
	 * By definition we don't have any audio to play thus if we need to
	 * switch modes we can go ahead and do it now.
	 */
	mutex_enter(&stpptr->am_mode_lock);
	cv_signal(&stpptr->am_mode_cv);
	mutex_exit(&stpptr->am_mode_lock);

	/* ack only if we have an mblk_t */
	if (mp) {
		miocack(WR(chptr->ch_qptr), mp, 0, 0);
		ATRACE("am_audio_drained() AUDIO_DRAIN acked", mp);
	}

	ATRACE("am_audio_drained() returning", chptr);

}	/* am_audio_drained() */

/*
 * am_audio_set_info()
 *
 * Description:
 *	This routine double checks the passed in audio_info_t structure to
 *	make sure the values are legal. If they are then they are used to
 *	update the audio hardware. In COMPAT mode all the hardware is updated,
 *	as it is for a multi-stream Codec. However traditional Codecs in MIXER
 *	mode don't update the data format or gain. Everything else can be
 *	updated.
 *
 *	After the checks are completed and the hardware has been updated
 *	the reti pointer is checked. If NULL we are done. Otherwise the
 *	structure pointed to by reti is filled in with the new hardware
 *	configuration.
 *
 *	The mixer only supports a few formats, 16-bit linear and 8-bit
 *	u-law, A-law and linear. Any other format will cause the check to
 *	fail.
 *
 *	We don't bother checking the read only members, silently ignoring any
 *	modifications.
 *
 *	XXX Need to set hardware to original state if error, especially
 *	if src_update() fails. Also, maybe move src_update() up higher so it
 *	can fail before we change hardware. Plus, it's easier to undo
 *	src_update().
 *
 *	NOTE: The Codec's lock must NOT be held when calling this routine.
 *
 *	NOTE: reti will be NULL only when this routine is being called by
 *		am_open().
 *
 *	NOTE: The calling routine is responsible for sending the hardware
 *		change signal.
 *
 * Arguments:
 *	audio_ch_t	*chptr		Pointer to this channel's state info
 *	audio_info_t	*newi		Pointer to the struct with new values
 *	audio_info_t	*reti		Pointer to the updated struct that is
 *					returned
 *
 * Returns:
 *	AUDIO_SUCCESS			Successful
 *	AUDIO_FAILURE			Failed
 */
int
am_audio_set_info(audio_ch_t *chptr, audio_info_t *newi, audio_info_t *reti)
{
	audio_info_t		*curi;		/* current state */
	audio_state_t		*statep = chptr->ch_statep;
	am_ch_private_t		*chpptr = chptr->ch_private;
	audio_apm_info_t	*apm_infop = chptr->ch_apm_infop;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	am_ad_info_t		*ad_infop = apm_infop->apm_ad_infop;
	audio_info_t		*hw_info = apm_infop->apm_ad_state;
	audio_info_t		tempi;		/* approved values in here */
	audio_device_type_e	type = chptr->ch_info.dev_type;
	boolean_t		ch_ctl = B_FALSE;
	boolean_t		new_play_samples = B_FALSE;
	boolean_t		new_record_samples = B_FALSE;
	boolean_t		play = B_FALSE;
	boolean_t		record = B_FALSE;
	boolean_t		start_play = B_FALSE;
	boolean_t		start_record = B_FALSE;
	boolean_t		stop_play = B_FALSE;
	boolean_t		stop_record = B_FALSE;
	int			codec_type = ad_infop->ad_codec_type;
	int			doread;
	int			dowrite;
	int			mode = stpptr->am_pstate->apm_mode;
	int			stream;

	ATRACE("in am_audio_set_info()", chptr);
	ATRACE_32("am_audio_set_info() mode", mode);

	ASSERT(!mutex_owned(&statep->as_lock));
	ASSERT(apm_infop);

	/*
	 * Are we playing and/or recording? For AUDIOCTL channels we
	 * force play and record, thus checking to see if it is changing
	 * the format. Since AUDIOCTL channels can't change the format
	 * we fail if the format isn't the same.
	 */
	curi = chptr->ch_info.info;
	if ((chptr->ch_dir & AUDIO_PLAY) || type == AUDIOCTL) {
		play = B_TRUE;
	}
	if ((chptr->ch_dir & AUDIO_RECORD) || type == AUDIOCTL) {
		record = B_TRUE;
	}

	/*
	 * If hardware supports both play and record then we need to do the
	 * play vs. record checks.
	 */
	doread = ad_infop->ad_defaults->hw_features & AUDIO_HWFEATURE_RECORD;
	dowrite = ad_infop->ad_defaults->hw_features & AUDIO_HWFEATURE_PLAY;

	/*
	 * The AUDIO_MIXERCTL_SETINFO ioctl() creates a pseudo channel that
	 * has it's ch_info.info set to hw_info. When in mixer mode this is
	 * the only time this happens. For this ioctl() we set only a small
	 * number of the h/w specific entries. So we fake out compat mode
	 * so that the h/w does get set.
	 */
	if (mode == AM_MIXER_MODE && chptr->ch_info.info == hw_info) {
		ATRACE("am_audio_set_info() AUDIO_MIXERCTL_SETINFO ioctl()",
		    NULL);
		mode = AM_COMPAT_MODE;
	}

	/* we use curi to get info to check against */
	if (mode == AM_COMPAT_MODE) {
		curi = hw_info;
#ifdef DEBUG
	} else {
		/* this was set above, just be a bit paranoid */
		ASSERT(mode == AM_MIXER_MODE);
		ASSERT(curi == chptr->ch_info.info);
#endif
	}

	/* first make sure the new data format is legal */
	if (play && Modify(newi->play.sample_rate) &&
	    newi->play.sample_rate != curi->play.sample_rate) {
		if (type != AUDIO || am_ck_sample_rate(&ad_infop->ad_play,
		    mode, newi->play.sample_rate) == AUDIO_FAILURE) {
			goto error;
		}
		tempi.play.sample_rate = newi->play.sample_rate;
	} else {
		tempi.play.sample_rate = curi->play.sample_rate;
	}
	if (record && Modify(newi->record.sample_rate) &&
	    newi->record.sample_rate != curi->record.sample_rate) {
		if (type != AUDIO || am_ck_sample_rate(&ad_infop->ad_record,
		    mode, newi->record.sample_rate) == AUDIO_FAILURE) {
			goto error;
		}
		tempi.record.sample_rate = newi->record.sample_rate;
	} else {
		tempi.record.sample_rate = curi->record.sample_rate;
	}
	mutex_enter(&statep->as_lock);
	if (doread && dowrite) {
		if (mode == AM_COMPAT_MODE &&
		    !(ad_infop->ad_diff_flags & AM_DIFF_SR) &&
		    tempi.play.sample_rate != tempi.record.sample_rate) {
			/* if only play or record we can fix this */
			if (stpptr->am_in_chs && stpptr->am_out_chs == 0) {
				/* set play to capture sample rate */
				tempi.play.sample_rate =
				    tempi.record.sample_rate;
			} else if (stpptr->am_in_chs == 0 &&
			    stpptr->am_out_chs) {
				/* set capture to play sample rate */
				tempi.record.sample_rate =
				    tempi.play.sample_rate;
			} else {
				mutex_exit(&statep->as_lock);
				goto error;
			}
		} else {
			/*
			 * There's a bug in audiotool which after doing an
			 * AUDIO_SETINFO it updates the state in AudioDevice.cc
			 * SetState() it uses the record side to get the new
			 * sample rate! So work around if write only. Who knows,
			 * perhaps other apps are as stupid!
			 */
			if (stpptr->am_out_chs != 0 && stpptr->am_in_chs == 0) {
				/* set to the same sample rate, gads! */
				tempi.record.sample_rate =
				    tempi.play.sample_rate;
			}
		}
	}

	ATRACE_32("am_audio_set_info() PLAY sample rate set",
	    tempi.play.sample_rate);
	ATRACE_32("am_audio_set_info() RECORD sample rate set",
	    tempi.record.sample_rate);

	if (play && Modify(newi->play.channels) &&
	    newi->play.channels != curi->play.channels) {
		if (type != AUDIO || am_ck_channels(&ad_infop->ad_play,
		    newi->play.channels, B_FALSE) == AUDIO_FAILURE) {
			mutex_exit(&statep->as_lock);
			goto error;
		}
		tempi.play.channels = newi->play.channels;
	} else {
		tempi.play.channels = curi->play.channels;
	}
	if (record && Modify(newi->record.channels) &&
	    newi->record.channels != curi->record.channels) {
		if (type != AUDIO || am_ck_channels(&ad_infop->ad_record,
		    newi->record.channels, B_FALSE) == AUDIO_FAILURE) {
			mutex_exit(&statep->as_lock);
			goto error;
		}
		tempi.record.channels = newi->record.channels;
	} else {
		tempi.record.channels = curi->record.channels;
	}
	if (doread && dowrite) {
		if (mode == AM_COMPAT_MODE &&
		    !(ad_infop->ad_diff_flags & AM_DIFF_CH) &&
		    tempi.play.channels != tempi.record.channels) {
			/* if only play or record we can fix this */
			if (stpptr->am_in_chs && stpptr->am_out_chs == 0) {
				/* set play to capture sample rate */
				tempi.play.channels = tempi.record.channels;
			} else if (stpptr->am_in_chs != 0 &&
			    stpptr->am_out_chs) {
				/* set capture to play sample rate */
				tempi.record.channels = tempi.play.channels;
			} else {
				mutex_exit(&statep->as_lock);
				goto error;
			}
		} else {
			/* see audiotool bug description above */
			if (stpptr->am_out_chs != 0 && stpptr->am_in_chs == 0) {
				/* set to the same channels, gads! */
				tempi.record.channels = tempi.play.channels;
			}
		}
	}
	ATRACE_32("am_audio_set_info() PLAY channels set",
	    tempi.play.channels);
	ATRACE_32("am_audio_set_info() RECORD channels set",
	    tempi.record.channels);

	if (play && Modify(newi->play.precision) &&
	    newi->play.precision != curi->play.precision) {
		if (type != AUDIO) {
			mutex_exit(&statep->as_lock);
			goto error;
		}
		tempi.play.precision = newi->play.precision;
	} else {
		tempi.play.precision = curi->play.precision;
	}
	if (record && Modify(newi->record.precision) &&
	    newi->record.precision != curi->record.precision) {
		if (type != AUDIO) {
			mutex_exit(&statep->as_lock);
			goto error;
		}
		tempi.record.precision = newi->record.precision;
	} else {
		tempi.record.precision = curi->record.precision;
	}
	if (doread && dowrite) {
		if (mode == AM_COMPAT_MODE &&
		    !(ad_infop->ad_diff_flags & AM_DIFF_PREC) &&
		    tempi.play.precision != tempi.record.precision) {
			/* if only play or record we can fix this */
			if (stpptr->am_in_chs && stpptr->am_out_chs == 0) {
				/* set play to capture sample rate */
				tempi.play.precision = tempi.record.precision;
			} else if (stpptr->am_in_chs == 0 &&
			    stpptr->am_out_chs) {
				/* set capture to play sample rate */
				tempi.record.precision = tempi.play.precision;
			} else {
				mutex_exit(&statep->as_lock);
				goto error;
			}
		} else {
			/* see audiotool bug description above */
			if (stpptr->am_out_chs != 0 && stpptr->am_in_chs == 0) {
				/* set to the same precision, gads! */
				tempi.record.precision = tempi.play.precision;
			}
		}
	}
	ATRACE_32("am_audio_set_info() PLAY precision set",
	    tempi.play.precision);
	ATRACE_32("am_audio_set_info() RECORD precision set",
	    tempi.record.precision);

	if (play && Modify(newi->play.encoding) &&
	    newi->play.encoding != curi->play.encoding) {
		if (type != AUDIO) {
			mutex_exit(&statep->as_lock);
			goto error;
		}
		tempi.play.encoding = newi->play.encoding;
	} else {
		tempi.play.encoding = curi->play.encoding;
	}
	if (record && Modify(newi->record.encoding) &&
	    newi->record.encoding != curi->record.encoding) {
		if (type != AUDIO) {
			mutex_exit(&statep->as_lock);
			goto error;
		}
		tempi.record.encoding = newi->record.encoding;
	} else {
		tempi.record.encoding = curi->record.encoding;
	}
	if (doread && dowrite) {
		if (mode == AM_COMPAT_MODE &&
		    !(ad_infop->ad_diff_flags & AM_DIFF_ENC) &&
		    tempi.play.encoding != tempi.record.encoding) {
			/* if only play or record we can fix this */
			if (stpptr->am_in_chs && stpptr->am_out_chs == 0) {
				/* set play to capture sample rate */
				tempi.play.encoding = tempi.record.encoding;
			} else if (stpptr->am_in_chs == 0 &&
			    stpptr->am_out_chs) {
				/* set capture to play sample rate */
				tempi.record.encoding = tempi.play.encoding;
			} else {
				mutex_exit(&statep->as_lock);
				goto error;
			}
		} else {
			/* see audiotool bug description above */
			if (stpptr->am_out_chs != 0 && stpptr->am_in_chs == 0) {
				/* set to the same encoding, gads! */
				tempi.record.encoding = tempi.play.encoding;
			}
		}
	}
	mutex_exit(&statep->as_lock);

	ATRACE_32("am_audio_set_info() PLAY encoding set",
	    tempi.play.encoding);
	ATRACE_32("am_audio_set_info() RECORD encoding set",
	    tempi.record.encoding);

	/*
	 * In COMPAT mode or with multi-channel Codecs we check against
	 * what the hardware allows. Otherwise, we check against what the
	 * mixer can deal with. But only if an AUDIO channel.
	 */
	if (type == AUDIO) {
		if (mode == AM_COMPAT_MODE || codec_type == AM_MS_CODEC) {
			if (dowrite && am_ck_combinations(
			    ad_infop->ad_play_comb, tempi.play.encoding,
			    tempi.play.precision, B_FALSE) == AUDIO_FAILURE) {
				goto error;
			}
			if (doread && am_ck_combinations(ad_infop->ad_rec_comb,
			    tempi.record.encoding, tempi.record.precision,
			    B_FALSE) == AUDIO_FAILURE) {
				goto error;
			}

		} else {	/* AM_MIXER_MODE */
			/* make sure the mixer can deal with the combinations */
			ASSERT(mode == AM_MIXER_MODE);

			switch ((int)tempi.play.channels) {
			case -1:		/* no change to channel */
			case AUDIO_CHANNELS_MONO:
			case AUDIO_CHANNELS_STEREO:
				break;
			default:
				goto error;
			}
			switch ((int)tempi.record.channels) {
			case -1:		/* no change to channel */
			case AUDIO_CHANNELS_MONO:
			case AUDIO_CHANNELS_STEREO:
				break;
			default:
				goto error;
			}

			switch ((int)tempi.play.encoding) {
			case -1:		/* no change to encoding */
			    break;
			case AUDIO_ENCODING_LINEAR:	/* signed */
			    /* we support 8 & 16-bit linear */
			    if (tempi.play.precision != AUDIO_PRECISION_16 &&
				tempi.play.precision != AUDIO_PRECISION_8) {
				    goto error;
			    }
			    break;
			case AUDIO_ENCODING_LINEAR8:	/* unsigned */
			case AUDIO_ENCODING_ULAW:
			case AUDIO_ENCODING_ALAW:
			    /* support 8-bit unsigned linear, u-law & A-law */
			    if (tempi.play.precision != AUDIO_PRECISION_8) {
				    goto error;
			    }
			    break;
			default:
			    goto error;
			}
			switch ((int)tempi.record.encoding) {
			case -1:		/* no change to encoding */
			    break;
			case AUDIO_ENCODING_LINEAR:	/* signed */
			    /* we support 8 & 16-bit linear */
			    if (tempi.record.precision != AUDIO_PRECISION_16 &&
				tempi.record.precision != AUDIO_PRECISION_8) {
				    goto error;
			    }
			    break;
			case AUDIO_ENCODING_LINEAR8:	/* unsigned */
			case AUDIO_ENCODING_ULAW:
			case AUDIO_ENCODING_ALAW:
			    /* support 8-bit unsigned linear, u-law & A-law */
			    if (tempi.record.precision != AUDIO_PRECISION_8) {
				    goto error;
			    }
			    break;
			default:
			    goto error;
			}
		}
	}
	ATRACE("am_audio_set_info() precision/encoding checked OK", &tempi);

	if (Modify(newi->play.gain)) {
		if (newi->play.gain > AUDIO_MAX_GAIN) {
			goto error;
		}
		tempi.play.gain = newi->play.gain;
	} else {
		tempi.play.gain = curi->play.gain;
	}
	if (Modify(newi->record.gain)) {
		if (newi->record.gain > AUDIO_MAX_GAIN) {
			goto error;
		}
		tempi.record.gain = newi->record.gain;
	} else {
		tempi.record.gain = curi->record.gain;
	}
	ATRACE_32("am_audio_set_info() PLAY gain set", tempi.play.gain);
	ATRACE_32("am_audio_set_info() RECORD gain set", tempi.record.gain);

	if (Modify(newi->play.port)) {
		tempi.play.port = newi->play.port;
	} else {
		tempi.play.port = hw_info->play.port;
	}
	if (tempi.play.port & ~hw_info->play.avail_ports) { /* legal port? */
		goto error;
	}
	/* always turn on un-modifiable ports */
	tempi.play.port |= hw_info->play.avail_ports & ~hw_info->play.mod_ports;
	if (ad_infop->ad_misc_flags & AM_MISC_PP_EXCL) { /* check exclusivity */
		if (am_ck_bits_set32(tempi.play.port) > 1) {
			goto error;
		}
	}
	if (Modify(newi->record.port)) {
		tempi.record.port = newi->record.port;
	} else {
		tempi.record.port = hw_info->record.port;
	}
	if (tempi.record.port & ~hw_info->record.avail_ports) {	/* legal ? */
		goto error;
	}
	/* always turn on un-modifiable ports */
	tempi.record.port |=
	    hw_info->record.avail_ports & ~hw_info->record.mod_ports;
	/* check exclusivity */
	if (ad_infop->ad_misc_flags & AM_MISC_RP_EXCL) {
		if (am_ck_bits_set32(tempi.record.port) > 1) {
			goto error;
		}
	}
	ATRACE_32("am_audio_set_info() PLAY ports set", tempi.play.port);
	ATRACE_32("am_audio_set_info() RECORD ports set", tempi.record.port);

	if (Modifyc(newi->play.balance)) {
		if (newi->play.balance > AUDIO_RIGHT_BALANCE) {
			goto error;
		}
		tempi.play.balance = newi->play.balance;
	} else {
		tempi.play.balance = curi->play.balance;
	}
	if (Modifyc(newi->record.balance)) {
		if (newi->record.balance > AUDIO_RIGHT_BALANCE) {
			goto error;
		}
		tempi.record.balance = newi->record.balance;
	} else {
		tempi.record.balance = curi->record.balance;
	}

	ATRACE_32("am_audio_set_info() PLAY balance set", tempi.play.balance);
	ATRACE_32("am_audio_set_info() REC balance set", tempi.record.balance);

	if (Modify(newi->monitor_gain)) {
		if (ad_infop->ad_defaults->hw_features &
		    AUDIO_HWFEATURE_IN2OUT) {
			if (newi->monitor_gain > AUDIO_MAX_GAIN) {
				goto error;
			}
			tempi.monitor_gain = newi->monitor_gain;
		} else {
			if (newi->monitor_gain != hw_info->monitor_gain) {
				ATRACE("am_audio_set_info() "
				    "monitor gain cannot be set", 0);
				goto error;
			}
			tempi.monitor_gain = hw_info->monitor_gain;
		}
	} else {
		tempi.monitor_gain = hw_info->monitor_gain;
	}
	ATRACE_32("am_audio_set_info() monitor gain set", tempi.monitor_gain);

	if (dowrite && Modifyc(newi->output_muted)) {
		tempi.output_muted = newi->output_muted;
	} else {
		tempi.output_muted = curi->output_muted;
	}
	ATRACE_32("am_audio_set_info() output muted set", tempi.output_muted);

	/*
	 * Now that we've got the new values verified we need to update the
	 * hardware. The following is updated:
	 *   COMPAT Mode, All Devices
	 *	play.minordev (H/W)		record.minordev (H/W)
	 *   COMPAT Mode, AUDIO Device
	 *	play.sample_rate (H/W)		record.sample_rate (H/W)
	 *	play.channels (H/W)		record.channels (H/W)
	 *	play.precision (H/W)		record.precision (H/W)
	 *	play.encoding (H/W)		record.encoding (H/W)
	 *	play.gain (H/W)			record.gain (H/W)
	 *	play.balance (H/W)		record.balance (H/W)
	 *	output_muted (H/W)
	 *   COMPAT Mode, AUDIOCTL Device
	 *	play.gain (H/W)			record.gain (H/W)
	 *	play.balance (H/W)		record.balance (H/W)
	 *	output_muted (H/W)
	 *   MIXER Mode, All Devices
	 *	play.minordev (CH)		record.minordev (CH)
	 *   MIXER Mode, AUDIO Device, Traditional Codec
	 *	play.sample_rate (CH)		record.sample_rate (CH)
	 *	play.channels (CH)		record.channels (CH)
	 *	play.precision (CH)		record.precision (CH)
	 *	play.encoding (CH)		record.encoding (CH)
	 *	play.gain (CH)			record.gain (CH)
	 *	play.balance (CH)		record.balance (CH)
	 *	output_muted (CH)
	 *   MIXER Mode, AUDIOCTL Device, Traditional Codec, Same Process As
	 *   An AUDIO Channel, ch_ctl == TRUE
	 *	play.gain (CH)			record.gain (CH)
	 *	play.balance (CH)		record.balance (CH)
	 *	output_muted (CH)
	 *   MIXER Mode, AUDIOCTL Device, Traditional Codec, Different Proc.
	 *   From An AUDIO Channel, ch_ctl == FALSE
	 *	play.gain (H/W)			record.gain (H/W)
	 *	play.balance (H/W)		record.balance (H/W)
	 *	output_muted (H/W)
	 *   MIXER Mode, AUDIO Device, Multi-Channel Codec
	 *	play.sample_rate (CH H/W)	record.sample_rate (CH H/W)
	 *	play.channels (CH H/W)		record.channels (CH H/W)
	 *	play.precision (CH H/W)		record.precision (CH H/W)
	 *	play.encoding (CH H/W)		record.encoding (CH H/W)
	 *	play.gain (CH H/W)		record.gain (CH H/W)
	 *	play.balance (CH H/W)		record.balance (CH H/W)
	 *	output_muted (CH H/W)
	 *   MIXER Mode, AUDIOCTL Device, Multi-Channel Codec, Same Proc. As
	 *   An AUDIO Channel, ch_ctl == TRUE
	 *	play.gain (CH H/W)		record.gain (CH H/W)
	 *	play.balance (CH H/W)		record.balance (CH H/W)
	 *	output_muted (CH H/W)
	 *   MIXER Mode, AUDIOCTL Device, Multi-Channel Codec, Different
	 *   Process From An AUDIO, ch_ctl == FALSE
	 *	play.gain (H/W)			record.gain (H/W)
	 *	play.balance (H/W)		record.balance (H/W)
	 *	output_muted (H/W)
	 *   All May Modify These Fields
	 *	play.port (H/W)			record.port (H/W)
	 *	monitor_gain (H/W)
	 *
	 * If we are in AM_COMPAT_MODE then output_muted controls the hardware,
	 * otherwise it just affects the channel, if it is a ch_ctl.
	 */

	/* only AUDIO channels can affect the data format */
	if (type == AUDIO) {
		/* figure out our "stream number" */
		if (codec_type == AM_MS_CODEC) {
			stream = chptr->ch_info.ch_number;
		} else {
			stream = AM_SET_CONFIG_BOARD;
		}

		if (mode == AM_COMPAT_MODE || codec_type == AM_MS_CODEC) {
			/*
			 * We only set the format if there's been a change.
			 * Otherwise we risk introducing noise, pops, etc.,
			 * for little good reason.
			 */
			if (dowrite && (hw_info->play.sample_rate !=
				tempi.play.sample_rate ||
			    hw_info->play.channels !=
				tempi.play.channels ||
			    hw_info->play.precision !=
				tempi.play.precision ||
			    hw_info->play.encoding !=
				tempi.play.encoding)) {
				if (am_set_format(statep, stpptr, ad_infop,
				    stream, AUDIO_PLAY,
				    tempi.play.sample_rate,
				    stpptr->am_hw_pchs, stpptr->am_hw_pprec,
				    stpptr->am_hw_penc, AM_NO_FORCE,
				    AM_SERIALIZE) == AUDIO_FAILURE) {
					goto error;
				}
			}
			if (doread && (hw_info->record.sample_rate !=
				tempi.record.sample_rate ||
			    hw_info->record.channels !=
				tempi.record.channels ||
			    hw_info->record.precision !=
				tempi.record.precision ||
			    hw_info->record.encoding !=
				tempi.record.encoding)) {
				if (am_set_format(statep, stpptr, ad_infop,
				    stream, AUDIO_RECORD,
				    tempi.record.sample_rate,
				    stpptr->am_hw_rchs, stpptr->am_hw_rprec,
				    stpptr->am_hw_renc, AM_NO_FORCE,
				    AM_SERIALIZE) == AUDIO_FAILURE) {
					goto error;
				}
			}
		}
		/* lock state while updating so ISR calls will be okay */
		mutex_enter(&chptr->ch_lock);
		if (mode == AM_MIXER_MODE) {
			curi->play.sample_rate = tempi.play.sample_rate;
			curi->play.channels = tempi.play.channels;
			curi->play.precision = tempi.play.precision;
			curi->play.encoding = tempi.play.encoding;
			curi->record.sample_rate = tempi.record.sample_rate;
			curi->record.channels = tempi.record.channels;
			curi->record.precision = tempi.record.precision;
			curi->record.encoding = tempi.record.encoding;
		} else {
			hw_info->play.sample_rate = tempi.play.sample_rate;
			hw_info->play.channels = tempi.play.channels;
			hw_info->play.precision = tempi.play.precision;
			hw_info->play.encoding = tempi.play.encoding;
			hw_info->record.sample_rate = tempi.record.sample_rate;
			hw_info->record.channels = tempi.record.channels;
			hw_info->record.precision = tempi.record.precision;
			hw_info->record.encoding = tempi.record.encoding;
		}

		/* see if we need to update the sample rate conv. routines */
		if (mode == AM_MIXER_MODE && codec_type == AM_TRAD_CODEC) {
			audio_apm_info_t *apm_infop = chptr->ch_apm_infop;

			if (chpptr->acp_writing) {
				ATRACE("am_audio_set_info() PLAY, "
				    "calling src update", chpptr);
				if (ad_infop->ad_play.ad_conv->ad_src_update(
				    AM_SRC_CHPTR2HDL(chptr),
				    &((audio_info_t *)chptr->ch_info.info)->
				    play,
				    &((audio_info_t *)apm_infop->apm_ad_state)->
				    play,
				    ((am_ad_info_t *)apm_infop->apm_ad_infop)->
				    ad_play.ad_sr_info,
				    AUDIO_PLAY) == AUDIO_FAILURE) {
					ATRACE("am_audio_set_info() "
					    "play src_update() failed", 0);
					mutex_exit(&chptr->ch_lock);
					goto error;
				}
			}
			if (chpptr->acp_reading) {
				ATRACE("am_audio_set_info() RECORD, "
				    "calling src update", chpptr);
				if (ad_infop->ad_record.ad_conv->ad_src_update(
				    AM_SRC_CHPTR2HDL(chptr),
				    &((audio_info_t *)chptr->ch_info.info)->
				    record,
				    &((audio_info_t *)apm_infop->apm_ad_state)->
				    record,
				    ((am_ad_info_t *)apm_infop->apm_ad_infop)->
				    ad_record.ad_sr_info,
				    AUDIO_RECORD) == AUDIO_FAILURE) {
					ATRACE("am_audio_set_info() "
					    "record src_update() failed", 0);
					mutex_exit(&chptr->ch_lock);
					goto error;
				}
			}
		}
		mutex_exit(&chptr->ch_lock);
	}

	/* is this an AUDIOCTL ch with the PID as another AUDIO ch? */
	mutex_enter(&chptr->ch_lock);
	ch_ctl = (chpptr->acp_flags & AM_CHNL_CONTROL) ? B_TRUE : B_FALSE;
	mutex_exit(&chptr->ch_lock);

	/* re-figure out our "stream number" */
	if (mode == AM_COMPAT_MODE || (mode == AM_MIXER_MODE && !ch_ctl)) {
		stream = AM_SET_CONFIG_BOARD;
	} else {
		stream = chptr->ch_info.ch_number;
	}

	/*
	 * AUDIO and AUDIOCTL can affect gains, ports, etc. If in COMPAT
	 * mode or a MS Codec we affect hardware. Otherwise this is a
	 * virtual ch. and only that channel's parameters are affected,
	 * i.e., no hardware update. Also, if a MS Codec and an AUDIOCTL
	 * channel isn't associated with a particular stream then we don't
	 * muck with hardware either.
	 */
	if (mode == AM_COMPAT_MODE || codec_type == AM_MS_CODEC ||
	    (type == AUDIOCTL && !ch_ctl)) {
		if (dowrite && am_set_gain(statep, apm_infop,
		    stpptr->am_hw_pchs, (tempi.play.gain & 0x0ff),
		    tempi.play.balance, AUDIO_PLAY, stream, AM_NO_FORCE,
		    AM_SERIALIZE) == AUDIO_FAILURE) {
			goto error;
		}
		if (doread && am_set_gain(statep, apm_infop,
		    stpptr->am_hw_rchs, (tempi.record.gain & 0x0ff),
		    tempi.record.balance, AUDIO_RECORD, stream, AM_NO_FORCE,
		    AM_SERIALIZE) == AUDIO_FAILURE) {
			goto error;
		}
		/* only if output_muted actually changed */
		if (hw_info->output_muted != tempi.output_muted) {
			if (am_ad_set_config(statep, stpptr, ad_infop, stream,
			    AM_OUTPUT_MUTE, AUDIO_PLAY, tempi.output_muted,
			    NULL, AM_SERIALIZE) == AUDIO_FAILURE) {
				goto error;
			}
		}
	}
	if (mode == AM_MIXER_MODE) {
		curi->play.gain = tempi.play.gain;
		curi->play.balance = tempi.play.balance;
		curi->record.gain = tempi.record.gain;
		curi->record.balance = tempi.record.balance;
		curi->output_muted = tempi.output_muted;
		tempi.play.minordev = curi->play.minordev;
		tempi.record.minordev = curi->record.minordev;
	} else {
		hw_info->play.gain = tempi.play.gain;
		hw_info->play.balance = tempi.play.balance;
		hw_info->record.gain = tempi.record.gain;
		hw_info->record.balance = tempi.record.balance;
		hw_info->output_muted = tempi.output_muted;
		tempi.play.minordev = hw_info->play.minordev;
		tempi.record.minordev = hw_info->record.minordev;
	}

	/* now we can set the ports and monitor gain, since all can set them */
	if (tempi.play.port != hw_info->play.port) {
		/* only if the play port actually changed */
		if (hw_info->play.port != tempi.play.port) {
			if (am_ad_set_config(statep, stpptr, ad_infop, stream,
			    AM_SET_PORT, AUDIO_PLAY, tempi.play.port, NULL,
			    AM_SERIALIZE) == AUDIO_FAILURE) {
				goto error;
			}
		}
		hw_info->play.port = tempi.play.port;
	}
	if (tempi.record.port != hw_info->record.port) {
		/* only if the record port actually changed */
		if (hw_info->record.port != tempi.record.port) {
			if (am_ad_set_config(statep, stpptr, ad_infop, stream,
			    AM_SET_PORT, AUDIO_RECORD, tempi.record.port,
			    NULL, AM_SERIALIZE) == AUDIO_FAILURE) {
				goto error;
			}
		}
		hw_info->record.port = tempi.record.port;
	}
	if (tempi.monitor_gain != hw_info->monitor_gain) {
		/* only if the monitor gain actually changed */
		if (hw_info->monitor_gain != tempi.monitor_gain) {
			if (am_ad_set_config(statep, stpptr, ad_infop, stream,
			    AM_SET_MONITOR_GAIN, AUDIO_BOTH, tempi.monitor_gain,
			    NULL, AM_SERIALIZE) == AUDIO_FAILURE) {
				goto error;
			}
		}
		hw_info->monitor_gain = tempi.monitor_gain;
	}

	/* we need to update the virtual channel, if we have one */
	if (mode == AM_MIXER_MODE) {
		curi->play.port = tempi.play.port;
		curi->record.port = tempi.record.port;
		curi->monitor_gain = tempi.monitor_gain;
	}

	/* now fix virtual channel parameters */
	if (Modify(newi->play.buffer_size)) {
		tempi.play.buffer_size = newi->play.buffer_size;
	} else {
		tempi.play.buffer_size = curi->play.buffer_size;
	}
	if (Modify(newi->record.buffer_size)) {
		tempi.record.buffer_size = newi->record.buffer_size;
	} else {
		tempi.record.buffer_size = curi->record.buffer_size;
	}
	ATRACE("am_audio_set_info() buffer size set", &tempi);

	if (Modify(newi->play.samples)) {
		tempi.play.samples = newi->play.samples;
		new_play_samples = B_TRUE;
	} else {
		tempi.play.samples = curi->play.samples;
	}
	if (Modify(newi->record.samples)) {
		tempi.record.samples = newi->record.samples;
		new_record_samples = B_TRUE;
	} else {
		tempi.record.samples = curi->record.samples;
	}
	ATRACE("am_audio_set_info() samples updated", &tempi);

	if (Modify(newi->play.eof)) {
		tempi.play.eof = newi->play.eof;
	} else {
		tempi.play.eof = curi->play.eof;
	}
	ATRACE("am_audio_set_info() eof updated", &tempi);

	if (Modifyc(newi->play.pause)) {
		tempi.play.pause = newi->play.pause;
	} else {
		tempi.play.pause = curi->play.pause;
	}
	if (Modifyc(newi->record.pause)) {
		tempi.record.pause = newi->record.pause;
	} else {
		tempi.record.pause = curi->record.pause;
	}
	/* if we unpaused we need to make sure we start up again */
	if (!tempi.play.pause && curi->play.pause) {
		start_play = B_TRUE;
	} else if (tempi.play.pause && !curi->play.pause &&
	    (mode == AM_COMPAT_MODE || codec_type == AM_MS_CODEC)) {
		stop_play = B_TRUE;
	}
	if (!tempi.record.pause && curi->record.pause) {
		start_record = B_TRUE;
	} else if (tempi.record.pause && !curi->record.pause &&
	    (mode == AM_COMPAT_MODE || codec_type == AM_MS_CODEC)) {
		stop_record = B_TRUE;
	}
	ATRACE("am_audio_set_info() pause set", &tempi);

	if (Modifyc(newi->play.error)) {
		tempi.play.error = newi->play.error;
	} else {
		tempi.play.error = curi->play.error;
	}
	if (Modifyc(newi->record.error)) {
		tempi.record.error = newi->record.error;
	} else {
		tempi.record.error = curi->record.error;
	}
	ATRACE("am_audio_set_info() error updated", &tempi);

	if (Modifyc(newi->play.waiting)) {
		tempi.play.waiting = newi->play.waiting;
	} else {
		tempi.play.waiting = curi->play.waiting;
	}
	if (Modifyc(newi->record.waiting)) {
		tempi.record.waiting = newi->record.waiting;
	} else {
		tempi.record.waiting = curi->record.waiting;
	}
	ATRACE("am_audio_set_info() waiting updated", &tempi);

	/*
	 * For MIXER mode we must update virtual channel parameters, because
	 * as soon as we restart the DMA engine(s) it's going to ask for audio.
	 * If the pause is still in effect then no data is going to be
	 * transferred.
	 */
	if (mode == AM_MIXER_MODE) {
		mutex_enter(&chptr->ch_lock);
		curi->play.buffer_size = tempi.play.buffer_size;
		curi->play.pause = tempi.play.pause;
		curi->play.eof = tempi.play.eof;
		curi->play.error = tempi.play.error;
		curi->play.waiting = tempi.play.waiting;
		curi->record.buffer_size = tempi.record.buffer_size;
		curi->record.pause = tempi.record.pause;
		curi->record.error = tempi.record.error;
		curi->record.waiting = tempi.record.waiting;
		mutex_exit(&chptr->ch_lock);
	}

	/* before we leave, we need to restart the DMA engines, or ... */
	if (start_play == B_TRUE) {
		/* make sure the play DMA engine is running */
		ASSERT(stop_play == B_FALSE);
		ATRACE("am_audio_set_info() start play", chptr);
		curi->play.pause = 0;	/* must be before the call */
		curi->play.active = 1;	/* set before start for mode switch */
		hw_info->play.active = 1;
		if (am_ad_start_play(statep, stpptr, ad_infop, stream,
		    AM_SERIALIZE) == AUDIO_FAILURE) {
			/* we don't change pause flag if failed to start */
			curi->play.active = 0;
			hw_info->play.active = 0;
			/*
			 * Since we are serialized we don't worry about the
			 * mode switch CV like am_wsvc() has to.
			 */
		} else {
			am_send_signal(statep, stpptr);
		}
	} else if (stop_play == B_TRUE) {
		/* make sure the play DMA engine is paused */
		ATRACE("am_audio_set_info() pause play", chptr);
		am_ad_pause_play(statep, stpptr, ad_infop, stream);
		curi->play.active = 0;
		hw_info->play.active = 0;
		curi->play.pause = 1;
		am_send_signal(statep, stpptr);
	}
	if (start_record == B_TRUE) {
		/* make sure the record DMA engine is running */
		ASSERT(stop_record == B_FALSE);
		ATRACE("am_audio_set_info() start record", chptr);
		curi->record.pause = 0;	/* must be before the call */
		curi->record.active = 1;  /* set before start for mode switch */
		hw_info->record.active = 1;
		if (am_ad_start_record(statep, stpptr, ad_infop, stream,
		    AM_SERIALIZE) == AUDIO_FAILURE) {
			curi->record.active = 0;
			hw_info->record.active = 0;
			/* we don't change pause flag if failed to start */
		} else {
			am_send_signal(statep, stpptr);
		}
	} else if (stop_record == B_TRUE) {
		/* make sure the record DMA engine is stopped */
		ATRACE("am_audio_set_info() stop record", chptr);
		am_ad_stop_record(statep, stpptr, ad_infop, stream);
		curi->record.pause = 1;
		curi->record.active = 0;
		hw_info->record.active = 0;
		am_send_signal(statep, stpptr);
	}

	/*
	 * For COMPAT mode we are dealing with the hardware, not a virtual
	 * channel. So the true state of the hardware can't be modified before
	 * starting or stopping the DMA engine(s).
	 */
	if (mode == AM_COMPAT_MODE) {
		mutex_enter(&chptr->ch_lock);
		hw_info->play.buffer_size = tempi.play.buffer_size;
		hw_info->play.pause = tempi.play.pause;
		hw_info->play.eof = tempi.play.eof;
		hw_info->play.error = tempi.play.error;
		hw_info->play.waiting = tempi.play.waiting;
		hw_info->record.buffer_size = tempi.record.buffer_size;
		hw_info->record.pause = tempi.record.pause;
		hw_info->record.error = tempi.record.error;
		hw_info->record.waiting = tempi.record.waiting;
		mutex_exit(&chptr->ch_lock);
	}

	/* everything passed so we can update the samples count */
	if (new_play_samples) {
		curi->play.samples = tempi.play.samples;
		mutex_enter(&chptr->ch_lock);
		chpptr->acp_psamples_c = 0;
		chpptr->acp_psamples_f = 0;
		chpptr->acp_psamples_p = 0;
		mutex_exit(&chptr->ch_lock);
	}
	if (new_record_samples) {
		curi->record.samples = tempi.record.samples;
	}

	/*
	 * If we don't have a reti pointer we ignore the R/O members. If we
	 * need them we get them directly from the channel that is active.
	 * So if reti == NULL we are done. Otherwise copy tempi into the
	 * memory pointed to by reti and then copy over the R/O members.
	 *
	 * We pass the reserved members, just in case.
	 *	play._xxx[1]			record._xxx[1]
	 *	_xxx[1]
	 *	_xxx[2]
	 */
	if (reti != NULL) {
		ATRACE("am_audio_set_info() reti succeeded", chptr);

		/* do a quick copy, and then fill in the special fields */
		bcopy(curi, reti, sizeof (*curi));

		mutex_enter(&chptr->ch_lock);
		reti->play.avail_ports =	hw_info->play.avail_ports;
		reti->record.avail_ports =	hw_info->record.avail_ports;
		reti->play.mod_ports =		hw_info->play.mod_ports;
		reti->record.mod_ports =	hw_info->record.mod_ports;
		reti->record.eof =		0;
		reti->monitor_gain =		hw_info->monitor_gain;
		reti->output_muted =		hw_info->output_muted;
		reti->hw_features =		hw_info->hw_features;
		reti->sw_features =		hw_info->sw_features;
		reti->sw_features_enabled =	hw_info->sw_features_enabled;
		mutex_exit(&chptr->ch_lock);
	}

	ATRACE("am_audio_set_info() succeeded", chptr);

	return (AUDIO_SUCCESS);

error:
	ATRACE("am_audio_set_info() failed", chptr);

	return (AUDIO_FAILURE);

}	/* am_audio_set_info() */

/*
 * am_set_format()
 *
 * Description:
 *	Set the hardware to the desired format. If the format is not
 *	supported we set it to the next best thing. Then the audio is
 *	translated to the desired format during playback or record.
 *
 *	NOTE: All setting of the hardware format MUST be done via this
 *		routine. Thus this is the only place the am_hw_* members
 *		are updated.
 *
 *	NOTE: We don't worry about checking the sample rate. This routine
 *		won't be called with a sample rate that isn't legal according
 *		to the audio driver's configuration tables.
 *
 * Arguments:
 *	audio_state_t		*statep		Ptr to the dev instance's state
 *	am_apm_private_t	*stpptr		Ptr to APM private data
 *	am_ad_info_t		*ad_infop	Ptr to the AD's config info
 *	int			stream		Audio stream
 *	int			dir		AUDIO_PLAY or AUDIO_RECORD
 *	int			sample_rate	Sample rate to set
 *	int			channels	The number of channels to set
 *	int			precision	The sample precision
 *	int			encoding	The encoding method
 *	int			force		Force the format to be set
 *	int			serialize	Serialize calls into driver
 *
 * Returns:
 *	AUDIO_SUCCESS		The format was successfully set
 *	AUDIO_FAILURE		The format wasn't set
 */
int
am_set_format(audio_state_t *statep, am_apm_private_t *stpptr,
	am_ad_info_t *ad_infop, int stream, int dir, int sample_rate,
	int channels, int precision, int encoding, int force, int serialize)
{
	uint_t		hw_sr;
	uint_t		hw_chs;
	uint_t		hw_enc;
	uint_t		hw_prec;
	uint_t		new_chs;
	uint_t		new_enc;
	uint_t		new_prec;
	int		flags;

	ATRACE("in am_set_format()", statep);
	ATRACE_32("am_set_format() passed sample rate", sample_rate);

	if (dir == AUDIO_PLAY) {
		flags = stpptr->am_pflags;
		hw_sr = stpptr->am_hw_info.play.sample_rate;
		hw_chs = stpptr->am_hw_pchs;
		hw_enc = stpptr->am_hw_penc;
		hw_prec = stpptr->am_hw_pprec;
	} else if (dir == AUDIO_RECORD) {
		flags = stpptr->am_rflags;
		hw_sr = stpptr->am_hw_info.record.sample_rate;
		hw_chs = stpptr->am_hw_rchs;
		hw_enc = stpptr->am_hw_renc;
		hw_prec = stpptr->am_hw_rprec;
	} else {
		audio_sup_log(AUDIO_STATE2HDL(statep),
		    CE_NOTE, "set_format() bad direction: %d", dir);
		return (AUDIO_FAILURE);
	}

	/* start with channels */
	switch (channels) {
	case AUDIO_CHANNELS_MONO:
		/* try to set the same 1st */
		if (flags & AM_PRIV_CH_MONO) {
			new_chs = AUDIO_CHANNELS_MONO;
		} else {
			/* we have to use stereo, so will need to translate */
			ASSERT(flags & AM_PRIV_CH_STEREO);
			new_chs = AUDIO_CHANNELS_STEREO;
		}
		break;
	case AUDIO_CHANNELS_STEREO:
		/* try to set the same 1st */
		if (flags & AM_PRIV_CH_STEREO) {
			new_chs = AUDIO_CHANNELS_STEREO;
		} else {
			/* we have to use mono, so will need to translate */
			ASSERT(flags & AM_PRIV_CH_MONO);
			new_chs = AUDIO_CHANNELS_MONO;
		}
		break;
	default:
		audio_sup_log(AUDIO_STATE2HDL(statep),
		    CE_NOTE, "set_format() bad channels: %d",
		    channels);
		return (AUDIO_FAILURE);
	}
	ATRACE_32("am_set_format() passed channels", channels);
	ATRACE_32("am_set_format() derived channels", new_chs);

	/* check the precision */
	if (precision == AUDIO_PRECISION_16) {
		/* see if the hardware supports what we want */
		if (flags & AM_PRIV_16_PCM) {
			new_prec = AUDIO_PRECISION_16;
			new_enc = AUDIO_ENCODING_LINEAR;
		} else {
			/* the h/w doesn't, so pick an alternative */
			new_prec = AUDIO_PRECISION_8;
			if (flags & AM_PRIV_8_ULAW) {
				new_enc = AUDIO_ENCODING_ULAW;
			} else if (flags & AM_PRIV_8_ALAW) {
				new_enc = AUDIO_ENCODING_ALAW;
			} else {
				ASSERT(flags & AM_PRIV_8_PCM);
				new_enc = AUDIO_ENCODING_LINEAR;
			}
		}
	} else {
		ASSERT(precision == AUDIO_PRECISION_8);
		/* just like above go through the list to see what we can use */
		new_prec = AUDIO_PRECISION_8;
		if (encoding == AUDIO_ENCODING_LINEAR) {
			if (flags & AM_PRIV_8_PCM) {
				new_enc = AUDIO_ENCODING_LINEAR;
			} else {
				if (flags & AM_PRIV_8_ULAW) {
					new_enc = AUDIO_ENCODING_ULAW;
				} else if (flags & AM_PRIV_8_ALAW) {
					new_enc = AUDIO_ENCODING_ALAW;
				} else {
					ASSERT(flags & AM_PRIV_16_PCM);
					new_prec = AUDIO_PRECISION_16;
					new_enc = AUDIO_ENCODING_LINEAR;
				}
			}
		} else if (encoding == AUDIO_ENCODING_ULAW) {
			if (flags & AM_PRIV_8_ULAW) {
				new_enc = AUDIO_ENCODING_ULAW;
			} else {
				if (flags & AM_PRIV_8_ALAW) {
					new_enc = AUDIO_ENCODING_ALAW;
				} else if (flags & AM_PRIV_8_PCM) {
					new_enc = AUDIO_ENCODING_LINEAR;
				} else {
					ASSERT(flags & AM_PRIV_16_PCM);
					new_prec = AUDIO_PRECISION_16;
					new_enc = AUDIO_ENCODING_LINEAR;
				}
			}
		} else {
			ASSERT(encoding == AUDIO_ENCODING_ALAW);
			if (flags & AM_PRIV_8_ALAW) {
				new_enc = AUDIO_ENCODING_ALAW;
			} else {
				if (flags & AM_PRIV_8_ULAW) {
					new_enc = AUDIO_ENCODING_ULAW;
				} else if (flags & AM_PRIV_8_PCM) {
					new_enc = AUDIO_ENCODING_LINEAR;
				} else {
					ASSERT(flags & AM_PRIV_16_PCM);
					new_prec = AUDIO_PRECISION_16;
					new_enc = AUDIO_ENCODING_LINEAR;
				}
			}
		}
	}
	ATRACE_32("am_set_format() passed precision", precision);
	ATRACE_32("am_set_format() derived precision", new_prec);
	ATRACE_32("am_set_format() passed encoding", encoding);
	ATRACE_32("am_set_format() derived encoding", new_enc);

	/*
	 * We now have the best possible h/w configuration. We see if
	 * it matches what we already have. If so then there's nothing
	 * to do. Otherwise the driver is called to set the hardware.
	 * If we do call the h/w we use the derived format, not the
	 * format passed to this routine.
	 */
	if (hw_sr != sample_rate || hw_chs != new_chs ||
	    hw_enc != new_enc || hw_prec != new_prec || force) {
		ATRACE("am_set_format() calling am_ad_set_format()", 0);
		if (am_ad_set_format(statep, stpptr, ad_infop, stream, dir,
		    sample_rate, new_chs, new_prec, new_enc, serialize) ==
		    AUDIO_FAILURE) {
			ATRACE("am_set_format() am_ad_set_format() failed", 0);
			return (AUDIO_FAILURE);
		}
		/* update the true hardware image */
		/* XXX this is probably not right! */
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*stpptr))
		if (dir == AUDIO_PLAY) {
			stpptr->am_hw_info.play.sample_rate = sample_rate;
			stpptr->am_hw_pchs = new_chs;
			stpptr->am_hw_pprec = new_prec;
			stpptr->am_hw_penc = new_enc;
		} else {
			ASSERT(dir == AUDIO_RECORD);
			stpptr->am_hw_info.record.sample_rate = sample_rate;
			stpptr->am_hw_rchs = new_chs;
			stpptr->am_hw_rprec = new_prec;
			stpptr->am_hw_renc = new_enc;
		}
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*stpptr))
	}

	/* there's no hardware change so just return */
	ATRACE("am_set_format() just returning", 0);
	return (AUDIO_SUCCESS);

}	/* am_set_format() */

/*
 * am_set_gain()
 *
 * Description:
 *	This routine is used to set the gain of all channels in the Codec.
 *	The gain is modified by balance. We try two different methods, the
 *	first with the gain and balance, and the second with gain and balance
 *	mixed down into left and right gain. This lets the Audio Driver accept
 *	whichever format it prefers. If the Audio Driver doesn't like the
 *	first method it returns AUDIO_FAILURE and the second is tried.
 *
 *	Some Codecs, like the Crystal 4231, will copy a mono input signal
 *	over to the 2nd channel. If this is the case then we apply balance
 *	to the left and right channels. Otherwise we adjust the only left
 *	gain.
 *
 *	NOTE: We change the gain only if it actually did change.
 *
 * Arguments:
 *	audio_state_t	*statep		Pointer to the device instance's state
 *	audio_apm_info_t *apm_infop	Ptr to driver's audio_apm_info structure
 *	uint_t		channels	The number of h/w channels
 *	uint_t		gain		The gain to set
 *	uint_t		balance		The balance to set
 *	int		dir		AUDIO_PLAY or AUDIO_RECORD
 *	int		stream		The hardware stream to set gain on
 *	int		force		Force the gain to be set
 *	int		serialize	Serialize access to the audio driver
 *
 * Returns:
 *	AUDIO_SUCCESS			The gain was successfully set
 *	AUDIO_FAILURE			The gain was not successfully set
 */
int
am_set_gain(audio_state_t *statep, audio_apm_info_t *apm_infop, uint_t channels,
	uint_t gain, uint_t balance, int dir, int stream, int force,
	int serialize)
{
	audio_prinfo_t		*hw_pinfo;
	am_ad_info_t		*ad_infop = apm_infop->apm_ad_infop;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	uint_t			g;

	ATRACE("in am_set_gain()", apm_infop);
	ATRACE("am_set_gain() channels", channels);
	ATRACE("am_set_gain() gain", gain);
	ATRACE("am_set_gain() balance", balance);

	if (dir == AUDIO_PLAY) {
		hw_pinfo = &((audio_info_t *)apm_infop->apm_ad_state)->play;
	} else {
		ASSERT(dir == AUDIO_RECORD);
		hw_pinfo = &((audio_info_t *)apm_infop->apm_ad_state)->record;
	}

	/* 1st try the gain and balance method since it's the easiest for us */
	if (am_ad_set_config(statep, stpptr, ad_infop, stream, AM_SET_GAIN_BAL,
	    dir, gain, balance, serialize) == AUDIO_SUCCESS) {
		ATRACE("am_set_gain() AM_SET_GAIN_BAL successful", 0);
		return (AUDIO_SUCCESS);
	}

	if (channels == 1 && !(ad_infop->ad_misc_flags & AM_MISC_MONO_DUP)) {
		/* make sure there was a change */
		if (!force && (hw_pinfo->gain == gain)) {
			ATRACE_32("am_set_gain() mono, the same gain", gain);
			return (AUDIO_SUCCESS);
		}

		/* we always set left gain */
		if (am_ad_set_config(statep, stpptr, ad_infop, stream,
		    AM_SET_GAIN, dir, gain, 0, serialize) == AUDIO_FAILURE) {
			return (AUDIO_FAILURE);
		}
		return (AUDIO_SUCCESS);
	} else {
		/* make sure there was a change */
		if (!force &&
		    (hw_pinfo->gain == gain) &&
		    (hw_pinfo->balance == balance)) {
			ATRACE_32("am_set_gain() stereo, the same gain", gain);
			ATRACE_32("am_set_gain() stereo, the same balance",
			    balance);
			return (AUDIO_SUCCESS);
		}

		/*
		 * Balance adjusts gain. If balance < 32 then left is
		 * enhanced by attenuating right. If balance > 32 then
		 * right is enhanced by attenuating left.
		 */
		if (balance == AUDIO_MID_BALANCE) {	/* no adj. */
			/* left channel */
			ATRACE_32("am_set_gain() L1 gain", gain);
			if (am_ad_set_config(statep, stpptr, ad_infop, stream,
			    AM_SET_GAIN, dir, gain, 0, serialize) ==
			    AUDIO_FAILURE) {
				return (AUDIO_FAILURE);
			}
			/* right channel */
			ATRACE_32("am_set_gain() R1 gain", gain);
			return (am_ad_set_config(statep, stpptr, ad_infop,
			    stream, AM_SET_GAIN, dir, gain, 1, serialize));
		} else if (balance < AUDIO_MID_BALANCE) {
			/*
			 * l = gain
			 * r = (gain * balance) / 32
			 */
			g = (gain * balance) >> AM_BALANCE_SHIFT;
			/* left channel */
			ATRACE_32("am_set_gain() L2 gain", gain);
			if (am_ad_set_config(statep, stpptr, ad_infop, stream,
			    AM_SET_GAIN, dir, gain, 0, serialize) ==
			    AUDIO_FAILURE) {
				return (AUDIO_FAILURE);
			}
			/* right channel */
			ATRACE_32("am_set_gain() R2 gain", g);
			return (am_ad_set_config(statep, stpptr, ad_infop,
			    stream, AM_SET_GAIN, dir, g, 1, serialize));
		} else {
			/*
			 * l = (gain * (64 - balance)) / 32
			 * r = gain
			 */
			g = (gain * (AUDIO_RIGHT_BALANCE - balance)) >>
			    AM_BALANCE_SHIFT;
			/* left channel */
			ATRACE_32("am_set_gain() L3 gain", g);
			if (am_ad_set_config(statep, stpptr, ad_infop, stream,
			    AM_SET_GAIN, dir, g, 0, serialize) ==
			    AUDIO_FAILURE) {
				return (AUDIO_FAILURE);
			}
			/* right channel */
			ATRACE_32("am_set_gain() R3 gain", gain);
			return (am_ad_set_config(statep, stpptr, ad_infop,
			    stream, AM_SET_GAIN, dir, gain, 1, serialize));
		}
	}

}	/* am_set_gain() */

/*
 * Private utilities used only by this file.
 */

/*
 * am_ck_bits_set32()
 *
 * Description:
 *	This routine figures out how many bits are set in the passed in val.
 *
 * Arguments:
 *	uint	val		The argument to test
 *
 * Returns:
 *	0 - 32			The number of bits set
 */
int
am_ck_bits_set32(uint_t val)
{
	uint_t		mask = 0x00000001u;
	int		count;
	int		i;

	ATRACE_32("in am_ck_bits_set32()", val);

	for (i = 0, count = 0; i < 32; i++) {
		if (mask & val) {
			count++;
		}
		mask <<= 1;
	}

	ATRACE_32("am_ck_bits_set32() done", count);

	return (count);

}	/* am_ck_bits_set32() */

/*
 * am_exit_task()
 *
 * Description:
 *	Exit from a task. This means decrementing the task counter so a
 *	blocked close() may continue.
 *
 * Arguments:
 *	audio_ch_t		*chptr		Ptr to the channel's struct
 *
 * Returns:
 *	void
 */
static void
am_exit_task(audio_ch_t *chptr)
{
	am_ch_private_t		*chpptr = chptr->ch_private;

	ATRACE("in am_exit_task()", chptr);

	mutex_enter(&chptr->ch_lock);

	/* clear the taskq flag */
	chpptr->acp_flags &= ~AM_CHNL_IOCTL_TASK;

	ATRACE_32("am_exit_task() flag cleared", chpptr->acp_flags);

	mutex_exit(&chptr->ch_lock);

	ATRACE("am_exit_task() done", chpptr);

}	/* am_exit_task() */

/*
 * am_fix_info()
 *
 * Description:
 *	When in mixer mode we usually play at a different sample rate
 *	than the data stream from the application. Therefore the sample
 *	count from the Codec is meaningless. This routine adjusts for the
 *	difference in sample rates.
 *
 *	We only adjust the play sample count because when recording you send
 *	x samples so you always know how many samples you sent so you don't
 *	have to adjust.
 *
 *	If this is an AUDIOCTL channel and it is associated with the H/W
 *	we don't do anything.
 *
 *	We also fix port and pause info, as well as other H/W related info,
 *	depending on the mixer mode.
 *
 * Arguments:
 *	audio_ch_t		*chptr	Ptr to the channel's state structure
 *	audio_info_t		*info	Ptr to the info structure to update
 *
 * Returns:
 *	void
 */
static void
am_fix_info(audio_ch_t *chptr, audio_info_t *info)
{
	audio_device_type_e	type = chptr->ch_info.dev_type;
	audio_apm_info_t	*apm_infop = chptr->ch_apm_infop;
	am_ad_info_t		*ad_infop = apm_infop->apm_ad_infop;
	am_ch_private_t		*chpptr = chptr->ch_private;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	audio_info_t		*hw_info = apm_infop->apm_ad_state;
	int			mode = stpptr->am_pstate->apm_mode;

	ATRACE("in am_fix_info()", chptr);
	ASSERT(MUTEX_HELD(&chptr->ch_lock));

	/* first, update the features */
	info->hw_features =		hw_info->hw_features;
	info->sw_features =		hw_info->sw_features;
	info->sw_features_enabled =	hw_info->sw_features_enabled;

	/* now fix various other things */
	if (mode == AM_MIXER_MODE) {
		ATRACE("am_fix_info() fixing other things", 0);
		if (info->play.pause) {
			info->play.active = 0;
		}
		info->play.port = hw_info->play.port;
		if (info->record.pause) {
			info->record.active = 0;

		}
		info->record.port = hw_info->record.port;
		info->monitor_gain = hw_info->monitor_gain;
	}

	/*
	 * CAUTION: Don't place anything related to record below this
	 *	point. Otherwise it may not execute.
	 *
	 * Finally, fix play samples, if we need to.
	 */
	if (!chpptr->acp_writing || (type == AUDIOCTL &&
	    hw_info == chptr->ch_info.info)) {

		ATRACE_32("am_fix_info() not writing, returning",
		    chpptr->acp_writing);

		return;
	} else {
		if (mode == AM_MIXER_MODE &&
		    ad_infop->ad_codec_type == AM_TRAD_CODEC) {
			ATRACE("am_fix_info() sample conversion", 0);

			info->play.samples +=
			    ad_infop->ad_play.ad_conv->ad_src_adjust(
			    AM_SRC_CHPTR2HDL(chptr), AUDIO_PLAY,
			    chpptr->acp_psamples_p);
		} else {
			ATRACE("am_fix_info() NO sample conversion",
			    info->play.samples);

			info->play.samples += chpptr->acp_psamples_p;
		}
	}

	ATRACE("am_fix_info() done", info);

}	/* am_fix_info() */

/*
 * am_fix_play_pause()
 *
 * Description:
 *	Convenience routine to clean up the code for switching to
 *	mixer mode while paused.
 *
 * Arguments:
 *	audio_ch_t		*chptr		Ptr to the channel
 *
 * Returns:
 *	void
 */
static void
am_fix_play_pause(audio_ch_t *chptr)
{
	audio_state_t		*statep = chptr->ch_statep;
	audio_info_t		*info = chptr->ch_info.info;
	audio_data_t		*data;

	ATRACE("in am_fix_play_pause()", chptr);

	/*
	 * It is possible that the channel was paused and then the mode
	 * was switched. Thus we are most likely changing modes not on
	 * a message boundary. Thus we need to make a best guess as to
	 * where to start playing.
	 */
	if (info->play.pause &&
	    (data = audio_sup_get_audio_data(chptr)) != NULL) {
		/* it's remotely possible that we happen to be at the end */
		if (data->adata_optr >= data->adata_oeptr) {
			ATRACE("am_fix_play_pause() end of message", statep);

			/* don't let it be played again! */
			audio_sup_free_audio_data(data);
			return;
		} else if (data->adata_orig == data->adata_optr) {
			/* or that we are just about to use a new msg */
			ATRACE("am_fix_play_pause() new message", statep);

			/* put it back to use next */
			audio_sup_putback_audio_data(chptr, data);
			return;
		}

		/* see if we need to process the data */
		mutex_enter(&chptr->ch_lock);
		if (data->adata_proc == NULL && am_reprocess(chptr, data) ==
		    AUDIO_FAILURE) {
			mutex_exit(&chptr->ch_lock);
			/*
			 * For some reason we can't convert the message and
			 * there isn't much we can do, so just blow it away
			 * and live with the gap in audio. We don't fail
			 * changing modes because that went okay.
			 */
			ATRACE("am_fix_play_pause() am_reprocess() failed",
			    statep);
			return;
		}
		mutex_exit(&chptr->ch_lock);
		ATRACE("am_fix_play_pause() process successful", data);

		/* put it back to use next */
		audio_sup_putback_audio_data(chptr, data);
	}

	ATRACE("am_fix_play_pause() successful", statep);

}	/* am_fix_play_pause() */

/*
 * am_mixer_task_acknack()
 *
 * Description:
 *	Sometimes when a taskq thread is done the ioctl() is also done.
 *	To finish off an ioctl() an M_IOCACK or M_IOCNAK message must be sent
 *	up to the STREAMS head. This routine performs that task.
 *
 * Arguments:
 *	audio_i_state_t	*state		Pointer to the ioctl() state structure
 *	audio_ch_t	*chptr		Ptr 2 the channel's state structure
 *	queue_t		*q		Pointer to the STREAMS queue
 *	mblk_t		*mp		Pointer to the STREAMS message to use
 *	am_ioctl_args_t	*arg		Argument structure
 *	int		error		0 if no error, errno otherwise
 *
 * Returns:
 *	void
 */
static void
am_mixer_task_acknack(audio_i_state_t *state, audio_ch_t *chptr,
    queue_t *q, mblk_t *mp, am_ioctl_args_t *arg, int error)
{
	struct copyreq		*cqp = (struct copyreq *)mp->b_rptr;

	ATRACE("in am_mixer_task_acknack()", state);

	/* no memory leaks allowed */
	if (state->ais_address2) {
		freemsg((mblk_t *)state->ais_address2);
	}

	if (cqp->cq_private) {
		kmem_free(cqp->cq_private, sizeof (audio_i_state_t));
		cqp->cq_private = NULL;
	}

	ATRACE_32("am_mixer_task_acknack() error", error);

	if (error) {
		miocnak(q, mp, 0, error);
	} else {
		miocack(q, mp, 0, 0);
	}

	/* let am_close() proceed */
	am_exit_task(chptr);

	kmem_free(arg, sizeof (*arg));

	ATRACE("am_mixer_task_acknack() done", mp);

}	/* am_mixer_task_acknack() */

/*
 * am_restart()
 *
 * Description:
 *	This routine is used to restart playing and recording audio when
 *	they have been stopped to switch mixer modes.
 *
 *	NOTE: This can only be for traditional Codecs, multi-stream Codecs
 *		aren't stopped to changed modes.
 *
 * Arguments:
 *	audio_state_t	*statep		Pointer to the device instance's state
 *	audio_info_t	*hw_info	Pointer to the hardware state
 *
 * Returns:
 *	void
 */
static void
am_restart(audio_state_t *statep, audio_info_t *hw_info)
{
	audio_ch_t		*tchptr;
	am_ch_private_t		*chpptr;
	audio_apm_info_t	*apm_infop;
	am_apm_private_t	*stpptr;
	am_ad_info_t		*ad_infop;
	audio_info_t		*tinfo;
	int			i;
	int			max_chs = statep->as_max_chs;

	ATRACE("in am_restart()", statep);

	if ((apm_infop = audio_sup_get_apm_info(statep, AUDIO)) == NULL) {
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "am_restart() failed");
		return;
	}
	stpptr = apm_infop->apm_private;
	ad_infop = apm_infop->apm_ad_infop;

	for (i = 0, tchptr = &statep->as_channels[0]; i < max_chs;
	    i++, tchptr++) {

		/* skip non-AUDIO and unallocated channels */
		mutex_enter(&tchptr->ch_lock);
		if (!(tchptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
		    tchptr->ch_info.dev_type != AUDIO ||
		    tchptr->ch_info.pid == 0) {
			mutex_exit(&tchptr->ch_lock);
			continue;
		}


		chpptr = tchptr->ch_private;
		tinfo = tchptr->ch_info.info;

		if (chpptr->acp_writing) {
			/* turn the Q back on */
			enableok(WR(tchptr->ch_qptr));
			qenable(WR(tchptr->ch_qptr));

			/* make sure we'll be flow controlled in am_wsvc() */
			chpptr->acp_flags &= ~AM_CHNL_PFLOW;

			/*
			 * It is possible we switched modes right when the last
			 * message was played and there's no way we're going
			 * to get the three calls to am_get_samples() we need
			 * to call cv_signal() for AUDIO_DRAIN. Therefore we
			 * set AM_CHNL_EMPTY, which means the next time
			 * am_get_samples() is called, which will happen when
			 * we start playing below, it does the cv_signal().
			 * We can subvert the number of times am_get_samples()
			 * needs to be called because we know the DMA buffers
			 * have been drained.
			 */
			if (audio_sup_get_audio_data_cnt(tchptr) == 0 &&
			    chpptr->acp_flags & AM_CHNL_DRAIN) {
				chpptr->acp_flags &= ~(AM_CHNL_ALMOST_EMPTY1|\
				    AM_CHNL_ALMOST_EMPTY2|AM_CHNL_DRAIN|\
				    AM_CHNL_DRAIN_NEXT_INT);
				chpptr->acp_flags |= AM_CHNL_EMPTY;
				/* signal any DRAIN situation */
				am_audio_drained(tchptr);
			}
			ATRACE("am_restart() starting playing again", tchptr);

			mutex_exit(&tchptr->ch_lock);
			if (!tinfo->play.pause) {
				/* set before start for mode switch */
				if (tinfo->play.active == 0) {
					am_send_signal(statep, stpptr);
				}
				tinfo->play.active = 1;
				hw_info->play.active = 1;
				if (am_ad_start_play(statep, stpptr, ad_infop,
				    tchptr->ch_info.ch_number, AM_SERIALIZE) ==
				    AUDIO_FAILURE) {
					/*
					 * We don't change pause if failed to
					 * start.
					 */
					tinfo->play.active = 0;
					hw_info->play.active = 0;
					/*
					 * Since we are part of the mode switch
					 * we don't have to worry about the
					 * mode switch CV like am_wsvc() has to.
					 */
				}
			}
			mutex_enter(&tchptr->ch_lock);
		}

		if (chpptr->acp_reading) {
			ATRACE("am_restart() starting recording again", tchptr);
			if (!tinfo->record.pause) {
				/* set before start for mode switch */
				mutex_exit(&tchptr->ch_lock);
				if (tinfo->record.active == 0) {
					am_send_signal(statep, stpptr);
				}
				tinfo->record.active = 1;
				hw_info->record.active = 1;
				if (am_ad_start_record(statep, stpptr, ad_infop,
				    tchptr->ch_info.ch_number, AM_SERIALIZE) ==
				    AUDIO_FAILURE) {
					/*
					 * We don't change pause if failed to
					 * start.
					 */
					tinfo->record.active = 0;
					hw_info->record.active = 0;
				}
			} else {
				mutex_exit(&tchptr->ch_lock);
			}
		} else {
			mutex_exit(&tchptr->ch_lock);
		}
	}

}	/* am_restart() */

/*
 * am_sched_task()
 *
 * Description:
 *	Common routine called to place a task on the taskq.
 *
 * Arguments:
 *	queue_t		*q	Pointer to the STREAMS queue
 *	mblk_t		*mp	Pointer to the message block
 *	audio_ch_t	*chptr	Pointer to this channel's state information
 *	void		(*func)(void *)	Pointer to the task to schedule
 *
 * Returns:
 *	0			No error
 *	errno			Error number for the error
 */
static int
am_sched_task(queue_t *q, mblk_t *mp, audio_ch_t *chptr,
	void (*func)(void *))
{
	audio_apm_info_t	*apm_infop = chptr->ch_apm_infop;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	am_ioctl_args_t		*arg;

	ATRACE("in am_sched_task()", q);

	/* get the arg structure and fill it in */
	if ((arg = kmem_alloc(sizeof (*arg), KM_NOSLEEP)) == NULL) {
		return (ENOMEM);
	}

	arg->aia_q = q;
	arg->aia_mp = mp;

	/* schedule the task */
	if (audio_sup_taskq_dispatch(stpptr->am_taskq, func, arg, KM_NOSLEEP) ==
	    AUDIO_FAILURE) {
		/* let am_close() proceed and free the arg structure */
		kmem_free(arg, sizeof (*arg));
		am_exit_task(chptr);
		return (EIO);
	}

	ATRACE("am_sched_task() returning", chptr);

	return (0);

}	/* am_sched_task() */

/*
 * am_set_compat_mode()
 *
 * Description:
 *	This routine is used to convert the mixer from MIXER mode to COMPAT
 *	mode. Any playing and recording channels should have been stopped
 *	before this routine is called.
 *
 *	When this routine is called there may be one playing and one recording
 *	channel.
 *
 *	We don't have to worry about resetting psamples_f after calling
 *	am_audio_set_info() because am_get_samples() has been called twice
 *	while we wait to shutdown. Thus it has already been added into the
 *	sample count.
 *
 *	NOTE: Only traditional Codecs will use this code.
 *
 * Arguments:
 *	audio_ch_t	*chptr		Ptr to the channel changing the mode
 *	am_ad_info_t	*ad_infop	Ptr to the Audio Driver's config info
 *	audio_ch_t	*pchptr		Ptr to the play channel
 *	audio_ch_t	*pchptr		Ptr to the record channel
 *
 * Returns:
 *	AUDIO_SUCCESS		Mode change completed successfully.
 *	AUDIO_FAILURE		Mode change failed.
 */
static int
am_set_compat_mode(audio_ch_t *chptr, am_ad_info_t *ad_infop,
	audio_ch_t *pchptr, audio_ch_t *rchptr)
{
	audio_state_t		*statep = chptr->ch_statep;
	audio_apm_info_t	*apm_infop;
	audio_data_t		*data;
	audio_info_t		*hw_info;
	am_apm_persist_t	*persistp;
	am_apm_private_t	*stpptr;
	audio_ch_t		nchptr;
	audio_info_t		new_info;
	am_ch_private_t		ch_private;
	long			tmp;
	int			tmp_pgain;
	int			tmp_pbal;
	int			tmp_rgain;
	int			tmp_rbal;
	uchar_t			popen = 0;
	uchar_t			ropen = 0;

	ATRACE("in am_set_compat_mode()", chptr);
	ASSERT(ad_infop->ad_codec_type == AM_TRAD_CODEC);

	if ((apm_infop = audio_sup_get_apm_info(statep, AUDIO)) == NULL) {
		ATRACE("am_set_compat_mode() audio_sup_get_apm_info() failed",
		    statep);
		return (AUDIO_FAILURE);
	}
	stpptr = apm_infop->apm_private;
	hw_info = &stpptr->am_hw_info;
	tmp_pgain = hw_info->play.gain;
	tmp_pbal = hw_info->play.balance;
	tmp_rgain = hw_info->record.gain;
	tmp_rbal = hw_info->record.balance;

	/* copy the original channel structure to the temp, just in case */
	bcopy(chptr, &nchptr, sizeof (nchptr));

	/* we only reset the hardware if we are playing or recording */
	AUDIO_INIT(&new_info, sizeof (new_info));
	bzero(&ch_private, sizeof (ch_private));

	nchptr.ch_dir = 0;

	if (pchptr) {
		audio_info_t *p_info = pchptr->ch_info.info;

		new_info.play.sample_rate = p_info->play.sample_rate;
		new_info.play.channels = p_info->play.channels;
		new_info.play.precision = p_info->play.precision;
		new_info.play.encoding = p_info->play.encoding;
		new_info.play.gain = p_info->play.gain;
		new_info.play.balance = p_info->play.balance;
		new_info.play.samples = p_info->play.samples;
		new_info.play.eof = p_info->play.eof;
		popen = p_info->play.open;
		ch_private.acp_writing = 1;
		nchptr.ch_dir |= AUDIO_PLAY;
	}
	if (rchptr) {
		audio_info_t *r_info = rchptr->ch_info.info;

		new_info.record.sample_rate = r_info->record.sample_rate;
		new_info.record.channels = r_info->record.channels;
		new_info.record.precision = r_info->record.precision;
		new_info.record.encoding = r_info->record.encoding;
		new_info.record.gain = r_info->record.gain;
		new_info.record.balance = r_info->record.balance;
		new_info.record.samples = r_info->record.samples;
		ropen = r_info->record.open;
		ch_private.acp_reading = 1;
		nchptr.ch_dir |= AUDIO_RECORD;
	}

	/* we always save the hardware state, even if no play/rec channels */
	stpptr->am_pstate->apm_mode = AM_COMPAT_MODE;
	hw_info->sw_features_enabled &= ~AUDIO_SWFEATURE_MIXER;

	/* change the hardware, if we had active play/record channels */
	if (pchptr || rchptr) {
		nchptr.ch_qptr = chptr->ch_qptr;
		nchptr.ch_statep = chptr->ch_statep;
		nchptr.ch_info.dev_type = AUDIO;
		nchptr.ch_apm_infop = apm_infop;
		nchptr.ch_private = &ch_private;
		nchptr.ch_info.info = &new_info;
		/*
		 * It's possible that when the bcopy above happens,
		 * the ch_lock is held by someone else. It should be
		 * cleared. Or, later when we try to hold it and find
		 * it's held, deadlock may happen.
		 */
		mutex_init(&nchptr.ch_lock, NULL, MUTEX_DRIVER, NULL);

		if (am_audio_set_info(&nchptr, &new_info, NULL) ==
		    AUDIO_FAILURE) {
			ATRACE("am_set_compat_mode() am_audio_set_info()"
			    "failed", &nchptr);
			audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
			    "set_compat() couldn't reconfigure hardware");
			stpptr->am_pstate->apm_mode = AM_MIXER_MODE;
			hw_info->sw_features_enabled |= AUDIO_SWFEATURE_MIXER;
			mutex_destroy(&nchptr.ch_lock);
			return (AUDIO_FAILURE);
		}
		mutex_destroy(&nchptr.ch_lock);
	}

	/* update the hardware open flags */
	hw_info->play.open = popen;
	hw_info->record.open = ropen;

	/* update persistent memory */
	persistp = stpptr->am_pstate;
	persistp->apm_mpgain = tmp_pgain;
	persistp->apm_mpbal = tmp_pbal;
	persistp->apm_mrgain = tmp_rgain;
	persistp->apm_mrbal = tmp_rbal;

	/*
	 * It is possible that the channel was paused and then the mode
	 * was switched. Thus we are most likely changing modes not on
	 * a message boundary. Thus we need to make a best guess as to
	 * where to start playing.
	 */
	if (pchptr &&
	    ((audio_info_t *)pchptr->ch_info.info)->play.pause &&
	    (data = audio_sup_get_audio_data(pchptr)) != NULL) {
		/* it's remotely possible that we happen to be at the end */
		if (data->adata_pptr >= data->adata_peptr) {
			ATRACE("am_set_compat_mode() end of data", statep);

			/* don't let it be played again! */
			audio_sup_free_audio_data(data);
			return (AUDIO_SUCCESS);
		} else if (data->adata_pptr == data->adata_proc) {
			/* or that we are just about to use new data */
			ATRACE("am_set_compat_mode() new message", statep);

			/* put it back to use next */
			audio_sup_putback_audio_data(pchptr, data);
			return (AUDIO_SUCCESS);
		}

		/*
		 * Make a guess as to where to point to. We make sure we are
		 * on a 4 byte boundary. That way we don't have to worry
		 * about being in the middle of sample.
		 *
		 * The equation:
		 *	(offset of proc data from start)*(length of orig data)
		 *	--------------------------------------------------------
		 *		(length of proc data)
		 */
		ATRACE("am_set_compat_mode() orig", data->adata_orig);
		ATRACE("am_set_compat_mode() optr", data->adata_optr);
		ATRACE("am_set_compat_mode() oeptr", data->adata_oeptr);
		ATRACE_32("am_set_compat_mode(): osize", data->adata_osize);
		ATRACE("am_set_compat_mode() proc", data->adata_proc);
		ATRACE("am_set_compat_mode() pptr", data->adata_pptr);
		ATRACE("am_set_compat_mode() peptr", data->adata_peptr);
		ATRACE_32("am_set_compat_mode(): psize", data->adata_psize);

		tmp = (((char *)data->adata_pptr - (char *)data->adata_proc) *
		    data->adata_osize) / data->adata_psize;

		/*
		 * tmp is an offset, which must be added to adata_orig to
		 * get adata_optr. We mask off adata_optr so that regardless
		 * of the format of the data we always are on a sample frame
		 * boundary.
		 */
		data->adata_optr = (char *)data->adata_orig +
		    (tmp & ~AM_MISC_MASK);
		ATRACE("am_set_compat_mode() new optr", data->adata_optr);

		/* put it back to use next */
		audio_sup_putback_audio_data(pchptr, data);
	}

	ATRACE("am_set_compat_mode() done", 0);

	return (AUDIO_SUCCESS);

}	/* am_set_compat_mode() */

/*
 * am_set_mixer_mode()
 *
 * Description:
 *	This routine is used to convert the mixer from COMPAT mode to MIXER
 *	mode. Any playing and recording channels should have been stopped
 *	before this routine is called.
 *
 *	When this routine is called there may be one playing and one recording
 *	channel.
 *
 *	Just like am_set_compat_mode(), psamples_f has already been added into
 *	the played sample count. So we don't need to do anything with it here.
 *
 *	NOTE: Only traditional Codecs will use this code.
 *
 * Arguments:
 *	audio_ch_t	*chptr		Ptr to the channel changing the mode
 *	am_ad_info_t	*ad_infop	Ptr to the Audio Driver's config info
 *	am_apm_private_t **stpptr	Ptr to the mixer's private state data
 *	audio_apm_info_t *apm_infop	Ptr to the mixer's APM info structure
 *	audio_ch_t	*pchptr		Ptr to the play channel
 *	audio_ch_t	*rchptr		Ptr to the record channel
 *
 * Returns:
 *	AUDIO_SUCCESS		Mode change completed successfully.
 *	AUDIO_FAILURE		Mode change failed.
 */
static int
am_set_mixer_mode(audio_ch_t *chptr, am_ad_info_t *ad_infop,
	am_apm_private_t *stpptr, audio_ch_t *pchptr, audio_ch_t *rchptr)
{
	audio_state_t		*statep = chptr->ch_statep;
	audio_apm_info_t	*apm_infop;
	audio_ch_t		nchptr;
	am_ch_private_t		ch_private;
	audio_info_t		*hw_info;
	audio_info_t		new_info;
	am_apm_persist_t	*persistp;

	ATRACE("in am_set_mixer_mode()", statep);
	ASSERT(ad_infop->ad_codec_type == AM_TRAD_CODEC);

	if ((apm_infop = audio_sup_get_apm_info(statep, AUDIO)) == NULL) {
		ATRACE("am_set_mixer_mode() audio_sup_get_apm_info() failed",
		    statep);
		return (AUDIO_FAILURE);
	}
	persistp = stpptr->am_pstate;
	hw_info = apm_infop->apm_ad_state;

	/*
	 * see if we need to update the sample rate conv. routines. This should
	 * be done before setting the apm_mode to AM_MIXER_MODE. Or, other code
	 * path,e.g. am_flush, may find apm_mode == AM_MIXER_MODE and then find
	 * the src module has not been update correctly and panic the system.
	 * We update the src module before update the hardware so that if it
	 * fails, the hardware state is still correct.
	 */
	if (pchptr) {
		ATRACE("am_set_mixer_mode(), "
		    "calling play src update", pchptr);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "am_set_mixer_mode calling play src update");
		if (ad_infop->ad_play.ad_conv->ad_src_update(
		    AM_SRC_CHPTR2HDL(pchptr),
		    &((audio_info_t *)pchptr->ch_info.info)->
		    play,
		    &((audio_info_t *)apm_infop->apm_ad_state)->
		    play,
		    ((am_ad_info_t *)apm_infop->apm_ad_infop)->
		    ad_play.ad_sr_info,
		    AUDIO_PLAY) == AUDIO_FAILURE) {
			ATRACE("am_set_mixer_mode() "
			    "play src_update() failed", 0);
			return (AUDIO_FAILURE);
		}
	}
	if (rchptr) {
		ATRACE("am_set_mixer_mode(), "
		    "calling record src update", rchptr);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "am_set_mixer_mode calling record src update");
		if (ad_infop->ad_record.ad_conv->ad_src_update(
		    AM_SRC_CHPTR2HDL(rchptr),
		    &((audio_info_t *)rchptr->ch_info.info)->
		    record,
		    &((audio_info_t *)apm_infop->apm_ad_state)->
		    record,
		    ((am_ad_info_t *)apm_infop->apm_ad_infop)->
		    ad_record.ad_sr_info,
		    AUDIO_RECORD) == AUDIO_FAILURE) {
			ATRACE("am_set_mixer_mode() "
			    "record src_update() failed", 0);
			return (AUDIO_FAILURE);
		}
	}

	/* copy the original channel structure to the temp, just in case */
	bcopy(chptr, &nchptr, sizeof (nchptr));

	/* we always reset the hardware, even if no play/rec channels */
	AUDIO_INIT(&new_info, sizeof (new_info));
	bzero(&ch_private, sizeof (ch_private));

	if (pchptr) {
		if (am_ck_sample_rate(&ad_infop->ad_play, AM_MIXER_MODE,
		    hw_info->play.sample_rate) == AUDIO_FAILURE) {
			ATRACE("am_set_mixer_mode() mixer can't play using "
			    "unsupported sample rate",
			    hw_info->play.sample_rate);
			return (AUDIO_FAILURE);
		}
		new_info.play.samples =
		    ((audio_info_t *)pchptr->ch_info.info)->play.samples;
		ch_private.acp_writing = 1;
	}
	if (rchptr) {
		if (am_ck_sample_rate(&ad_infop->ad_record, AM_MIXER_MODE,
		    hw_info->record.sample_rate) == AUDIO_FAILURE) {
			ATRACE("am_set_mixer_mode() mixer can't record using "
			    "unsupported sample rate",
			    hw_info->record.sample_rate);
			return (AUDIO_FAILURE);
		}
		new_info.record.samples =
		    ((audio_info_t *)rchptr->ch_info.info)->record.samples;
		ch_private.acp_reading = 1;
	}

	if (ad_infop->ad_defaults->hw_features & AUDIO_HWFEATURE_PLAY) {
		new_info.play.sample_rate = stpptr->am_save_psr;
		new_info.play.gain = persistp->apm_mpgain;
		new_info.play.balance = persistp->apm_mpbal;
	}

	if (ad_infop->ad_defaults->hw_features & AUDIO_HWFEATURE_RECORD) {
		new_info.record.sample_rate = stpptr->am_save_rsr;
		new_info.record.gain = persistp->apm_mrgain;
		new_info.record.balance = persistp->apm_mrbal;
	}

	nchptr.ch_qptr = chptr->ch_qptr;
	nchptr.ch_statep = chptr->ch_statep;
	nchptr.ch_dir = AUDIO_BOTH;
	nchptr.ch_info.dev_type = AUDIO;
	nchptr.ch_apm_infop = apm_infop;
	nchptr.ch_private = &ch_private;
	nchptr.ch_info.info = &new_info;
	/*
	 * It's possible that when the bcopy above happens,
	 * the ch_lock is held by someone else. It should be
	 * cleared. Or, later when we try to hold it and find
	 * it's held, deadlock may happen.
	 */
	mutex_init(&nchptr.ch_lock, NULL, MUTEX_DRIVER, NULL);

	if (am_audio_set_info(&nchptr, &new_info, &new_info) == AUDIO_FAILURE) {
		ATRACE("am_set_mixer_mode() am_audio_set_info() failed",
		    &nchptr);
		audio_sup_log(AUDIO_STATE2HDL(statep), CE_NOTE,
		    "set_mixer() "
		    "couldn't reconfigure hardware");
		mutex_destroy(&nchptr.ch_lock);
		return (AUDIO_FAILURE);
	}
	mutex_destroy(&nchptr.ch_lock);


	/*
	 * We need to look like we've changed modes AFTER we try to set hw.
	 * Otherwise am_audio_set_info() won't update the hardware. It'll
	 * try to update the virtual channel.
	 */
	stpptr->am_pstate->apm_mode = AM_MIXER_MODE;
	hw_info->sw_features_enabled |= AUDIO_SWFEATURE_MIXER;

	/* clear the open flags in the hardware */
	hw_info->play.open = 0;
	hw_info->record.open = 0;

	/* clear the hardware's waiting flags */
	hw_info->play.waiting = 0;
	hw_info->record.waiting = 0;

	/* clear misc flags */
	hw_info->play.eof = 0;

	/*
	 * Also update the hardware info for the number of channels,
	 * precision, and encoding.
	 */
	hw_info->play.channels = stpptr->am_hw_pchs;
	hw_info->record.channels = stpptr->am_hw_rchs;

	hw_info->play.precision = stpptr->am_hw_pprec;
	hw_info->record.precision = stpptr->am_hw_rprec;

	hw_info->play.encoding = stpptr->am_hw_penc;
	hw_info->record.encoding = stpptr->am_hw_renc;

	ATRACE("am_set_mixer_mode() successful", statep);

	return (AUDIO_SUCCESS);

}	/* am_set_mixer_mode() */

/*
 * am_wiocdata_mixerctl_chinfo()
 *
 * Description:
 *	We have the audio_channel_t data structure so we know how big the info
 *	structure is. We make sure the size of the info structure is correct,
 *	that there is a buffer, and that the channel number is reasonable.
 *
 * Arguments:
 *	queue_t		*q	Pointer to the STREAMS queue
 *	mblk_t		*mp	Pointer to the message block
 *	audio_i_state_t	*state	Pointer to ioctl() state structure
 *
 * Returns:
 *	0			No error
 *	errno			Error number for the error
 */
static int
am_wiocdata_mixerctl_chinfo(queue_t *q, mblk_t *mp, audio_i_state_t *state)
{
	STRUCT_HANDLE(audio_channel, audio_channel);
	audio_ch_t		*chptr = (audio_ch_t *)
				    audio_sup_get_qptr_data(q);
	audio_ch_t		*tchptr;
	audio_state_t		*statep = chptr->ch_statep;
	struct iocblk		*iocbp = (struct iocblk *)mp->b_rptr;
	audio_info_t		*info;
	int			ch_number;

	ATRACE("in am_wiocdata_mixerctl_chinfo()", q);

	/* get ready to do the model conversion */
	STRUCT_SET_HANDLE(audio_channel, iocbp->ioc_flag,
		(audio_channel_t *)mp->b_cont->b_rptr);

	/*
	 * Make sure the size is good, fortunately audio_info_t doesn't have
	 * any pointers in it, so it's the same size, regardless of _ILP32
	 * or _LP64.
	 */
	if (STRUCT_FGET(audio_channel, info_size) != sizeof (audio_info_t)) {
		ATRACE_32("am_wiocdata_mixerctl_chinfo() bad size",
		    STRUCT_FGET(audio_channel, info_size));
		return (EINVAL);
	}

	/* make sure the app has a buffer to place the data into */
	if ((info = STRUCT_FGETP(audio_channel, info)) == NULL) {
		ATRACE("am_wiocdata_mixerctl_chinfo() no buffer",
		    STRUCT_FGETP(audio_channel, info));
		return (EINVAL);
	}

	/* get the channel number and make sure it's good */
	ch_number = STRUCT_FGET(audio_channel, ch_number);
	if (ch_number >= statep->as_max_chs || ch_number < 0) {
		ATRACE_32("am_wiocdata_mixerctl_chinfo() bad ch number",
		    STRUCT_FGET(audio_channel, ch_number));
		return (EINVAL);
	}

	/* make sure this is a valid AUDIO/AUDIOCTL ch */
	tchptr = &statep->as_channels[ch_number];
	mutex_enter(&tchptr->ch_lock);
	if (!(tchptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
	    tchptr->ch_info.pid == 0 ||
	    (tchptr->ch_info.dev_type != AUDIO &&
	    tchptr->ch_info.dev_type != AUDIOCTL)) {
		mutex_exit(&tchptr->ch_lock);
		ATRACE("am_wiocdata_mixerctl_chinfo() bad ch", tchptr);
		return (EINVAL);
	}
	mutex_exit(&tchptr->ch_lock);

	/*
	 * We have a good audio_channel_t structure so we can do the next
	 * step in the process, which is to ask for the audio_info structure.
	 * But first we save the audio_channel structure for later use.
	 * The STREAMS head will give us a new mp->b_cont message block
	 * when it gives us the audio_info structure.
	 */
	state->ais_command = AM_COPY_IN_MIXCTL_SET_CHINFO2;
	state->ais_address = (caddr_t)info;
	state->ais_address2 = (caddr_t)mp->b_cont;

	/* Set mp->b_cont = NULL so mcopyin() does not free the saved message */
	mp->b_cont = NULL;

	/* Setup for copyin */
	ASSERT(state->ais_address != NULL);
	mcopyin(mp, state, sizeof (audio_info_t), (caddr_t)state->ais_address);

	/* send the copy in request */
	qreply(q, mp);

	ATRACE("am_wiocdata_mixerctl_chinfo() returning", q);

	return (0);

}	/* am_wiocdata_mixerctl_chinfo() */

/*
 * am_wiocdata_mixerctl_get_chinfo()
 *
 * Description:
 *	The audio_info_t data structure has been copied out, so now we copy
 *	out the updated audio_channel_t structure.
 *
 * Arguments:
 *	queue_t		*q	Pointer to the STREAMS queue
 *	mblk_t		*mp	Pointer to the message block
 *	audio_i_state_t	*state	Pointer to ioctl() state structure
 *
 * Returns:
 *	0			No error
 *	errno			Error number for the error
 */
static int
am_wiocdata_mixerctl_get_chinfo(queue_t *q, mblk_t *mp, audio_i_state_t *state)
{
	mblk_t		*tmp;

	ATRACE("in am_wiocdata_mixerctl_get_chinfo()", q);

	state->ais_command = AM_COPY_OUT_MIXCTL_GET_CHINFO2;

	tmp = (mblk_t *)state->ais_address2;

	/* Setup for copyout */
	ASSERT(state->ais_address != NULL);
	mcopyout(mp, state, tmp->b_wptr - tmp->b_rptr, state->ais_address, tmp);

	state->ais_address2 = NULL;

	qreply(q, mp);

	ATRACE("am_wiocdata_mixerctl_get_chinfo() done", q);

	return (0);

}	/* am_wiocdata_mixerctl_get_chinfo() */

/*
 * am_wiocdata_sr()
 *
 * Description:
 *	The next step in getting the sample rates. We've got the
 *	am_sample_rates_t structure so we can now get the number of sample
 *	rates to ask for, which we do. Thus we copy in the structure a
 *	second time, but this time it'll be larger.
 *
 * Arguments:
 *	queue_t		*q	Pointer to the STREAMS queue
 *	mblk_t		*mp	Pointer to the message block
 *	struct copyreq	*cqp	Pointer to copy request register
 *	audio_i_state_t	*state	Pointer to ioctl() state structure
 *
 * Returns:
 *	0			No error
 *	errno			Error number for the error
 */
static int
am_wiocdata_sr(queue_t *q, mblk_t *mp, struct copyreq *cqp,
	audio_i_state_t *state)
{
	am_sample_rates_t	*new;
	size_t			size;

	ATRACE("in am_wiocdata_sr()", q);

	/*
	 * We copy in just the am_sample_rates_t structure to get the
	 * number of sample rates the samp_rates array can support.
	 * Once we know this we make another call to get the whole
	 * thing.
	 */

	/* get a pointer to the user supplied structure */
	new = (am_sample_rates_t *)mp->b_cont->b_rptr;

	/* make sure the number of array elements is sane */
	if (new->num_samp_rates <= 0) {
		ATRACE_32("am_wiocdata_sr() AM_COPY_IN_SAMP_RATES "
		    "bad num_samp_rates", new->num_samp_rates);
		return (EINVAL);
	}

	ATRACE("am_wiocdata_sr() new", new);
	ATRACE_32("am_wiocdata_sr() num_samp_rates", new->num_samp_rates);
	size = AUDIO_MIXER_SAMP_RATES_STRUCT_SIZE(new->num_samp_rates);

	/*
	 * Now that we know the number of array elements, we can ask
	 * for the right number of bytes.
	 *
	 * Reuse the cq_private buffer, saving data for M_IOCDATA processing.
	 */
	state->ais_command = AM_COPY_IN_SAMP_RATES2;
	ASSERT(cqp->cq_private == (mblk_t *)state);

	/* Setup for copyin */
	ASSERT(state->ais_address != NULL);
	mcopyin(mp, state, size, (caddr_t)state->ais_address);

	/* send the copy in request */
	qreply(q, mp);

	ATRACE("am_wiocdata_sr() returning success", 0);

	return (0);

}	/* am_wiocdata_sr() */

/*
 * am_wioctl_copyin()
 *
 * Description:
 *	Common routine used to start the copy in process for many ioctl()s.
 *
 * Arguments:
 *	queue_t		*q	Pointer to the STREAMS queue
 *	mblk_t		*mp	Pointer to the message block
 *	audio_ch_t	*chptr	Pointer to this channel's state information
 *	audio_i_state_t	*state	Pointer to ioctl() state structure
 *	int		cmd	IOCTL command
 *
 * Returns:
 *	0			No error
 *	errno			Error number for the error
 */
static int
am_wioctl_copyin(queue_t *q, mblk_t *mp, audio_ch_t *chptr,
	audio_i_state_t *state, int cmd)
{
	size_t		size;
	int		new_cmd;

	ATRACE("in am_wioctl_copyin()", q);

	/* set copyin based on the ioctl() command */
	switch (cmd) {
	case AUDIO_DIAG_LOOPBACK: {
		audio_apm_info_t	*apm_infop = chptr->ch_apm_infop;
		am_ad_info_t		*ad_infop = apm_infop->apm_ad_infop;

		/* not all Audio Drivers and their hardware support loopbacks */
		if (!(ad_infop->ad_diag_flags & AM_DIAG_INTERNAL_LOOP)) {
			ATRACE_32("am_wioctl_diag_loopback() no loopbacks",
			    ad_infop->ad_diag_flags);
			return (ENOTTY);
		}

		new_cmd = AM_COPY_IN_DIAG_LOOPB;
		size = sizeof (int);

		break;
	}

	case AUDIO_SETINFO:
		new_cmd = AM_COPY_IN_AUDIOINFO;
		size = sizeof (audio_info_t);

		break;
	case AUDIO_MIXER_GET_SAMPLE_RATES:
		new_cmd = AM_COPY_IN_SAMP_RATES;
		size = sizeof (am_sample_rates_t);

		break;
	case AUDIO_MIXERCTL_SETINFO:
		/* allowed only on AUDIOCTL channels */
		if (chptr->ch_info.dev_type != AUDIOCTL) {
			return (EINVAL);
		}

		new_cmd = AM_COPY_IN_MIXCTLINFO;
		/*
		 * We only need the dev_info part of am_control_t. Fortunately
		 * this is at the front of the structure. So set the size to
		 * copy in only the dev_info part. Otherwise we'll blow an
		 * assert in am_mixerctl_setinfo_task().
		 */
		size = sizeof (audio_info_t);

		break;
	case AUDIO_MIXERCTL_GET_CHINFO:
		/* allowed only on AUDIOCTL channels */
		if (chptr->ch_info.dev_type != AUDIOCTL) {
			return (EINVAL);
		}

		/* size can be different, depending on _ILP32 and _LP64 */
		new_cmd = AM_COPY_IN_MIXCTL_GET_CHINFO;
		size = SIZEOF_STRUCT(audio_channel,
		    ((struct iocblk *)mp->b_rptr)->ioc_flag);

		break;
	case AUDIO_MIXERCTL_SET_CHINFO:
		/* allowed only on AUDIOCTL channels */
		if (chptr->ch_info.dev_type != AUDIOCTL) {
			return (EINVAL);
		}

		/* size can be different, depending on _ILP32 and _LP64 */
		new_cmd = AM_COPY_IN_MIXCTL_SET_CHINFO;
		size = SIZEOF_STRUCT(audio_channel,
		    ((struct iocblk *)mp->b_rptr)->ioc_flag);

		break;
	case AUDIO_MIXERCTL_SET_MODE:
		/* allowed only on AUDIOCTL channels */
		if (chptr->ch_info.dev_type != AUDIOCTL) {
			return (EINVAL);
		}

		new_cmd = AM_COPY_IN_MIXCTL_MODE;
		size = sizeof (int);

		break;
	default:
		return (EIO);
	}

	/* set up the message */
	state->ais_command = new_cmd;
	state->ais_address = (caddr_t)(*(caddr_t *)mp->b_cont->b_rptr);

	/* Setup for copyin */
	if (state->ais_address == NULL) {
		return (EINVAL);
	}
	mcopyin(mp, state, size, state->ais_address);

	/* send the copy in request */
	qreply(q, mp);

	ATRACE("am_wioctl_copyin() returning", chptr);

	return (0);

}	/* am_wioctl_copyin() */

/*
 * am_wioctl_drain()
 *
 * Description:
 *	First make sure this is an AUDIO channel. Then see if there is
 *	any queued up audio. If there is then just return after setting
 *	a flag. Otherwise we've got an AUDIO_DRAIN before there's any
 *	played audio or after it has all played, thus we ACK.
 *
 *	Once all audio has been played am_audio_drained() is called and
 *	it generates the ACK.
 *
 *	This ioctl() doesn't use the taskq. Thus other channels won't be
 *	blocked by this ioctl().
 *
 *	Like all ioctl()s, AUDIO_DRAIN may be interrupted by a signal.
 *	The STREAMS head will let the ioctl() return to the app. We have
 *	no way of knowing this has happened, unless we use cv_wait_sig().
 *	This would block am_wput() so we aren't going to use it. However
 *	the fact we don't know about the signal is okay. The STREAMS head
 *	keeps a sequence number and as long as we save the original mp it
 *	can tell if this is an old ioctl() or not. If it is it just ignores
 *	the ACK. Further, am_close() will call am_audio_drained() which
 *	will send the ACK, which the STREAMS head will ignore if it wishes.
 *	Or we'll get another AUDIO_DRAIN and we still have the old mp, and
 *	thus we'll know the old AUDIO_DRAIN was interrupted. So we just
 *	free the mp and we're still okay.
 *
 *	XXX - I don't understand what this means if there's a mux pushed
 *	on top of the mixer. If this happens it is possible to have multiple
 *	AUDIO_DRAINs at once, but then you can also have multiple audio
 *	streams on one channel. So audio isn't going to work very well in
 *	that case anyway.
 *
 * Arguments:
 *	queue_t		*q	Pointer to the STREAMS queue
 *	mblk_t		*mp	Pointer to the message block
 *	audio_ch_t	*chptr	Pointer to this channel's state information
 *	struct copyreq	*cqp	Pointer to copy request register
 *
 * Returns:
 *	void
 */
/*ARGSUSED*/
static void
am_wioctl_drain(queue_t *q, mblk_t *mp, audio_ch_t *chptr,
	struct copyreq *cqp)
{
	am_ch_private_t		*chpptr = (am_ch_private_t *)chptr->ch_private;
	int			error = 0;

	ATRACE("in am_wioctl_drain() chptr", chptr);

	/* must be on a play audio channel */
	mutex_enter(&chptr->ch_lock);
	if (!chpptr->acp_writing || chptr->ch_info.dev_type != AUDIO) {
		mutex_exit(&chptr->ch_lock);
		ATRACE("am_wioctl_drain() AUDIO_DRAIN bad type", chptr);
		error = EINVAL;
		goto done;
	}

	/*
	 * See if we've got a new AUDIO_DRAIN, which means the last one
	 * was interrupted.
	 */
	if (chpptr->acp_drain_mp) {
		/* free it, it's lost and the STREAM head knows this */
		freemsg(chpptr->acp_drain_mp);
	}

	/* see if we are empty, the easy case */
	if (!(chpptr->acp_flags & AM_CHNL_MSG_ON_QUEUE) &&
	    audio_sup_get_audio_data_cnt(chptr) == 0) {
		chpptr->acp_drain_mp = NULL;
		mutex_exit(&chptr->ch_lock);
		ATRACE("am_wioctl_drain() no messages", chptr);
		goto done;
	}

	/* we need to wait for empty */
	chpptr->acp_flags |= AM_CHNL_DRAIN;
	chpptr->acp_drain_mp = mp;

	ATRACE_32("am_wioctl_drain() messages, acp_flags", chpptr->acp_flags);
	ATRACE("am_wioctl_drain() MP", mp);

	mutex_exit(&chptr->ch_lock);

	return;

done:
	ASSERT(cqp->cq_private == NULL);

	if (error) {
		miocnak(q, mp, 0, error);
	} else {
		miocack(q, mp, 0, 0);
	}

	ATRACE("am_wioctl_drain() drained", chptr);

}	/* am_wioctl_drain() */

/*
 * am_wioctl_getdev()
 *
 * Description:
 *	The first half of the AUDIO_GETDEV ioctl(). Ask to copy out
 *	the audio driver's device information structure.
 *
 * Arguments:
 *	queue_t		*q	Pointer to the STREAMS queue
 *	mblk_t		*mp	Pointer to the message block
 *	audio_ch_t	*chptr	Pointer to this channel's state information
 *	audio_i_state_t	*state	Pointer to ioctl() state structure
 *
 * Returns:
 *	0			No error
 *	errno			Error number for the error
 */
static int
am_wioctl_getdev(queue_t *q, mblk_t *mp, audio_ch_t *chptr,
	audio_i_state_t *state)
{
	audio_apm_info_t	*apm_infop = chptr->ch_apm_infop;
	am_ad_info_t		*ad_infop = apm_infop->apm_ad_infop;
	audio_device_t		*devp;

	ATRACE("in am_wioctl_getdev()", q);

	/* set STREAMS for copy out of the audio_device structure */
	state->ais_command = AM_COPY_OUT_GETDEV;
	state->ais_address = (caddr_t)(*(caddr_t *)mp->b_cont->b_rptr);

	/* Setup for copyout */
	if (state->ais_address == NULL) {
		return (EINVAL);
	}
	mcopyout(mp, state, sizeof (*ad_infop->ad_dev_info), state->ais_address,
	    NULL);

	/* put the data in the buffer, but try to reuse it first */
	if (audio_sup_mblk_alloc(mp, sizeof (*ad_infop->ad_dev_info)) ==
	    AUDIO_FAILURE) {
		return (ENOMEM);
	}

	/*
	 * We don't bother to lock the state structure because this
	 * is static data.
	 */

	devp = (audio_device_t *)mp->b_cont->b_rptr;

	bcopy(ad_infop->ad_dev_info, devp,
	    sizeof (*ad_infop->ad_dev_info));

	/* send the copy out request */
	qreply(q, mp);

	ATRACE("am_wioctl_getdev() returning", chptr);

	return (0);

}	/* am_wioctl_getdev() */

/*
 * Task queue callbacks.
 */

/*
 * am_diag_loopback_task()
 *
 * Description:
 *	Called by the task queue to set the loopback mode in the audio
 *	driver.
 *
 * Arguments:
 *	void		*arg	Argument structure
 *
 * Returns:
 *	void
 */
static void
am_diag_loopback_task(void *arg)
{
	queue_t			*q = ((am_ioctl_args_t *)arg)->aia_q;
	mblk_t			*mp = ((am_ioctl_args_t *)arg)->aia_mp;
	audio_ch_t		*chptr = (audio_ch_t *)
				    audio_sup_get_qptr_data(q);
	audio_state_t		*statep = chptr->ch_statep;
	audio_apm_info_t	*apm_infop = chptr->ch_apm_infop;
	am_ad_info_t		*ad_infop = apm_infop->apm_ad_infop;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	struct copyreq		*cqp = (struct copyreq *)mp->b_rptr;
	audio_i_state_t		*state = (audio_i_state_t *)cqp->cq_private;
	int			error = 0;

	ATRACE("in am_diag_lookback() arg", arg);

	am_enter_rwlock();

	if (*(int *)mp->b_cont->b_rptr) {
		ATRACE_32("am_diag_loopback_task() enable",
		    *(int *)mp->b_cont->b_rptr);

		if (am_ad_set_config(statep, stpptr, ad_infop,
		    AM_SET_CONFIG_BOARD, AM_SET_DIAG_MODE, NULL, 1, NULL,
		    AM_SERIALIZE) == AUDIO_FAILURE) {
			ATRACE("am_diag_loopback_task() "
			    "AM_COPY_IN_DIAG_LOOPB enable failed", 0);
			error = EIO;
		}
	} else {
		ATRACE_32("am_diag_loopback_task() disable",
		    *(int *)mp->b_cont->b_rptr);

		if (am_ad_set_config(statep, stpptr, ad_infop,
		    AM_SET_CONFIG_BOARD, AM_SET_DIAG_MODE, NULL, 0, NULL,
		    AM_SERIALIZE) == AUDIO_FAILURE) {
			ATRACE("am_diag_loopback_task() "
			    "AM_COPY_IN_DIAG_LOOPB disable failed", 0);
			error = EIO;
		}
	}

	am_mixer_task_acknack(state, chptr, q, mp, arg, error);

	am_release_rwlock();

	ATRACE("am_diag_lookback() done", error);

}	/* am_diag_loopback_task() */

/*
 * am_get_chinfo_task()
 *
 * Description:
 *	Called by the task queue to get the channel's info. If the size of
 *	the info structure doesn't match then we return an EINVAL. This is
 *	better than trying to copy out to much data and cause a core dump
 *	in the application.
 *
 * Arguments:
 *	void		*arg	Argument structure
 *
 * Returns:
 *	void
 */
static void
am_get_chinfo_task(void *arg)
{
	STRUCT_HANDLE(audio_channel, audio_channel);
	queue_t			*q = ((am_ioctl_args_t *)arg)->aia_q;
	mblk_t			*mp = ((am_ioctl_args_t *)arg)->aia_mp;
	audio_ch_t		*chptr = (audio_ch_t *)
				    audio_sup_get_qptr_data(q);
	audio_ch_t		*tchptr;
	audio_state_t		*statep = chptr->ch_statep;
	audio_apm_info_t	*apm_infop = chptr->ch_apm_infop;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	struct copyreq		*cqp = (struct copyreq *)mp->b_rptr;
	audio_i_state_t		*state = (audio_i_state_t *)cqp->cq_private;
	struct iocblk		*iocbp = (struct iocblk *)mp->b_rptr;
	audio_info_t		*info;
	mblk_t			*tmp;
	int			ch_number;
	int			error = 0;

	ATRACE("in am_get_chinfo_task() arg", arg);

	am_enter_rwlock();

	/* we have to check the mode when it's stable */
	if (stpptr->am_pstate->apm_mode != AM_MIXER_MODE) {
		ATRACE_32("am_get_chinfo_task() bad mode",
		    chptr->ch_info.dev_type);
		error = EINVAL;
		goto nack;
	}

	/* get ready to do the model conversion */
	STRUCT_SET_HANDLE(audio_channel, iocbp->ioc_flag,
	    (audio_channel_t *)mp->b_cont->b_rptr);

	/*
	 * Make sure the size is good, fortunately audio_info_t doesn't have
	 * any pointers in it, so it's the same size, regardless of _ILP32
	 * or _LP64.
	 */
	if (STRUCT_FGET(audio_channel, info_size) != sizeof (audio_info_t)) {
		ATRACE_32("am_get_chinfo_task() bad size",
		    STRUCT_FGET(audio_channel, info_size));
		error = EINVAL;
		goto nack;
	}

	/* make sure the app has a buffer to place the data into */
	if ((info = STRUCT_FGETP(audio_channel, info)) == NULL) {
		ATRACE("am_get_chinfo_task() no buffer",
		    STRUCT_FGETP(audio_channel, info));
		error = EINVAL;
		goto nack;
	}

	/* get the channel number and make sure it's good */
	ch_number = STRUCT_FGET(audio_channel, ch_number);
	if (ch_number >= statep->as_max_chs || ch_number < 0) {
		ATRACE_32("am_get_chinfo_task() bad ch number",
		    STRUCT_FGET(audio_channel, ch_number));
		error = EINVAL;
		goto nack;
	}

	/* make sure this is a valid AUDIO/AUDIOCTL ch */
	tchptr = &statep->as_channels[ch_number];
	mutex_enter(&tchptr->ch_lock);
	if (!(tchptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
	    tchptr->ch_info.pid == 0 ||
	    (tchptr->ch_info.dev_type != AUDIO &&
	    tchptr->ch_info.dev_type != AUDIOCTL)) {
		ATRACE("am_get_chinfo_task() bad ch", tchptr);
		error = EINVAL;
		mutex_exit(&tchptr->ch_lock);
		goto nack;
	}
	mutex_exit(&tchptr->ch_lock);

	/* okay to update the channel's info */
	STRUCT_FSET(audio_channel, pid, tchptr->ch_info.pid);
	STRUCT_FSET(audio_channel, dev_type, tchptr->ch_info.dev_type);

	/*
	 * We have consistent data so now we can start the copy out,
	 * beginning with the audio_info_t structure. That's because
	 * we've got the _IPL32/_LP64 environment. Also, we can't use
	 * the macros here because of the special address. So we save
	 * the audio_channel_t data structure for later. And then get
	 * a new mblk to put the audio_info structure into.
	 */
	if ((tmp = allocb(sizeof (audio_info_t), BPRI_HI)) == 0) {
		error = ENOMEM;
		goto nack;
	}
	state->ais_address2 = (caddr_t)mp->b_cont;

	/*
	 * Set mp->b_cont = NULL so the mcopyout() below does not free the
	 * saved message in state->ais_address2 above when it sets
	 * mp->b_cont = tmp
	 */
	mp->b_cont = NULL;

	bcopy(tchptr->ch_info.info, tmp->b_wptr, sizeof (audio_info_t));
	tmp->b_wptr = tmp->b_rptr + sizeof (audio_info_t);

	state->ais_command = AM_COPY_OUT_MIXCTL_GET_CHINFO;

	/* Setup for copyout */
	ASSERT(state->ais_address != NULL);
	mcopyout(mp, state, sizeof (audio_info_t), (caddr_t)info, tmp);

	ASSERT(mp->b_cont == tmp);

	/* send the copy in request */
	qreply(q, mp);

	kmem_free(arg, sizeof (am_ioctl_args_t));

	am_exit_task(chptr);

	am_release_rwlock();

	ATRACE("am_get_chinfo_task() return", chptr);

	return;
nack:
	am_mixer_task_acknack(state, chptr, q, mp, arg, error);

	am_release_rwlock();

	ATRACE("am_get_chinfo_task() returning nack", chptr);

}	/* am_get_chinfo_task() */

/*
 * am_get_mode_task()
 *
 * Description:
 *	This task gets the current mixer mode while the state is stable.
 *
 * Arguments:
 *	void		*arg	Argument structure
 *
 * Returns:
 *	void
 */
static void
am_get_mode_task(void *arg)
{
	queue_t			*q = ((am_ioctl_args_t *)arg)->aia_q;
	mblk_t			*mp = ((am_ioctl_args_t *)arg)->aia_mp;
	audio_ch_t		*chptr = (audio_ch_t *)
				    audio_sup_get_qptr_data(q);
	audio_apm_info_t	*apm_infop = chptr->ch_apm_infop;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	struct copyreq		*cqp = (struct copyreq *)mp->b_rptr;
	audio_i_state_t		*state = (audio_i_state_t *)cqp->cq_private;
	int 			error = 0;

	ATRACE("in am_get_mode_task() arg", arg);

	am_enter_rwlock();

	/* set STREAMS for copy out of the mode */
	state->ais_command = AM_COPY_OUT_MIXCTL_MODE;
	state->ais_address = (caddr_t)(*(caddr_t *)mp->b_cont->b_rptr);

	/* Setup for copyout */
	if (state->ais_address == NULL) {
		error = EINVAL;
		goto done;
	}
	mcopyout(mp, state, sizeof (int), state->ais_address, NULL);

	/* put the data in the buffer, but try to reuse it first */
	if (audio_sup_mblk_alloc(mp, sizeof (int)) == AUDIO_FAILURE) {
		error = ENOMEM;
		goto done;
	} else {
		*((int *)mp->b_cont->b_rptr) = stpptr->am_pstate->apm_mode;
		mp->b_cont->b_wptr = mp->b_cont->b_rptr +
		    sizeof (stpptr->am_pstate->apm_mode);
		qreply(q, mp);
	}

done:
	if (error) {
		if (cqp->cq_private) {
			kmem_free(cqp->cq_private, sizeof (audio_i_state_t));
			cqp->cq_private = NULL;
		}
		miocnak(q, mp, 0, error);
	}
	kmem_free(arg, sizeof (am_ioctl_args_t));

	am_exit_task(chptr);

	am_release_rwlock();

	ATRACE("am_get_mode_task() returning", chptr);

}	/* am_get_mode_task() */

/*
 * am_getinfo_task()
 *
 * Description:
 *	This is the task that gets serial access to the info data structure
 *	and copies out the audio_info data structure.
 *
 * Arguments:
 *	void		*arg	Argument structure
 *
 * Returns:
 *	void
 */
static void
am_getinfo_task(void *arg)
{
	queue_t			*q = ((am_ioctl_args_t *)arg)->aia_q;
	mblk_t			*mp = ((am_ioctl_args_t *)arg)->aia_mp;
	audio_ch_t		*chptr = (audio_ch_t *)
				    audio_sup_get_qptr_data(q);
	audio_info_t		*info = chptr->ch_info.info;
	struct copyreq		*cqp = (struct copyreq *)mp->b_rptr;
	audio_i_state_t		*state = (audio_i_state_t *)cqp->cq_private;
	audio_info_t		*info_out;
	int			error = 0;

	ATRACE("in am_getinfo_task() arg", arg);

	am_enter_rwlock();

	/* set STREAMS for copy out of the audio_info structure */
	state->ais_command = AM_COPY_OUT_AUDIOINFO;
	state->ais_address = (caddr_t)(*(caddr_t *)mp->b_cont->b_rptr);

	/* Setup for copyout */
	if (state->ais_address == NULL) {
		error = EINVAL;
		ATRACE("am_getinfo_task() with invalid address", chptr);
		goto done;
	}
	mcopyout(mp, state, sizeof (*info_out), state->ais_address, NULL);

	/* put the data in the buffer, but try to reuse it first */
	if (audio_sup_mblk_alloc(mp, sizeof (*info_out)) == AUDIO_FAILURE) {
		error = ENOMEM;
		ATRACE("am_getinfo_task() failing to alloc mblk", chptr);
		goto done;
	}

	info_out = (audio_info_t *)mp->b_cont->b_rptr;

	bcopy(info, info_out, sizeof (*info_out));

	/* update the played sample count */
	mutex_enter(&chptr->ch_lock);
	am_fix_info(chptr, info_out);
	mutex_exit(&chptr->ch_lock);

	qreply(q, mp);

	kmem_free(arg, sizeof (am_ioctl_args_t));

	am_exit_task(chptr);

done:
	if (error) {
		am_mixer_task_acknack(state, chptr, q, mp, arg, error);
	}
	am_release_rwlock();

	ATRACE("am_getinfo_task() returning", chptr);

}	/* am_getinfo_task() */

/*
 * am_mixerctl_getinfo_task()
 *
 * Description:
 *	This task gets serial access to the state to copy out the am_control
 *	data structure.
 *
 * Arguments:
 *	void		*arg	Argument structure
 *
 * Returns:
 *	void
 */
static void
am_mixerctl_getinfo_task(void *arg)
{
	queue_t			*q = ((am_ioctl_args_t *)arg)->aia_q;
	mblk_t			*mp = ((am_ioctl_args_t *)arg)->aia_mp;
	audio_ch_t		*chptr = (audio_ch_t *)
				    audio_sup_get_qptr_data(q);
	audio_ch_t		*tchptr;
	audio_state_t		*statep = chptr->ch_statep;
	audio_apm_info_t	*apm_infop = chptr->ch_apm_infop;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	struct copyreq		*cqp = (struct copyreq *)mp->b_rptr;
	audio_i_state_t		*state = (audio_i_state_t *)cqp->cq_private;
	audio_info_t		*info_out;
	am_control_t		*ptr;
	size_t			size;
	int			i;
	int			error = 0;
	int			max_chs = statep->as_max_chs;

	ATRACE("in am_mixerctl_getinfo_task() arg", arg);

	am_enter_rwlock();

	/* we have to check the mode when it's stable, we also check the type */
	if (stpptr->am_pstate->apm_mode != AM_MIXER_MODE ||
	    chptr->ch_info.dev_type != AUDIOCTL) {
		ATRACE_32("am_mixerctl_getinfo_task() bad mode/type",
		    chptr->ch_info.dev_type);
		error = EINVAL;
		goto nack;
	}

	size = AUDIO_MIXER_CTL_STRUCT_SIZE(max_chs);

	/* set STREAMS for copy out of the audio_info structure */
	state->ais_command = AM_COPY_OUT_MIXCTLINFO;
	state->ais_address = (caddr_t)(*(caddr_t *)mp->b_cont->b_rptr);

	/* Setup for copyout */
	if (state->ais_address == NULL) {
		ATRACE("am_mixerctl_getinfo_task() bad address from user",
		    NULL);
		error = EINVAL;
		goto nack;
	}
	mcopyout(mp, state, size, state->ais_address, NULL);

	/* put the data in the buffer, but try to reuse it first */
	if (audio_sup_mblk_alloc(mp, size) == AUDIO_FAILURE) {
		ATRACE("am_mixerctl_getinfo_task() can't get memory", 0);
		error = ENOMEM;
		goto nack;
	}

	ptr = (am_control_t *)mp->b_cont->b_rptr;
	info_out = &ptr->dev_info;

	/*
	 * We have to assemble this one by pieces. First we take
	 * care of the hardware state, then extended hardware state.
	 */

	bcopy(apm_infop->apm_ad_state, info_out, sizeof (audio_info_t));

	/* update the played sample count */
	mutex_enter(&chptr->ch_lock);
	am_fix_info(chptr, info_out);
	mutex_exit(&chptr->ch_lock);

	/* now get the channel information */
	mutex_enter(&statep->as_lock);		/* freeze ch state */

	for (i = 0, tchptr = &statep->as_channels[0]; i < max_chs;
	    i++, tchptr++) {
		mutex_enter(&tchptr->ch_lock);
		if (tchptr->ch_info.pid) {
			ptr->ch_open[i] = 1;
		} else {
			ptr->ch_open[i] = 0;
		}
		mutex_exit(&tchptr->ch_lock);
	}

	mutex_exit(&statep->as_lock);

	/* send the copy out request */
	qreply(q, mp);

	kmem_free(arg, sizeof (am_ioctl_args_t));

	am_exit_task(chptr);

	am_release_rwlock();

	ATRACE("am_mixerctl_getinfo_task() returning", chptr);

	return;

nack:
	am_mixer_task_acknack(state, chptr, q, mp, arg, error);

	am_release_rwlock();

	ATRACE("am_mixerctl_getinfo_task() returning nack", chptr);

}	/* am_mixerctl_getinfo_task() */

/*
 * am_mixerctl_setinfo_task()
 *
 * Description:
 *	This task gets serial access to the state to set it based on the
 *	am_control data structure. Can only set a few global things. The
 *	ch_open argument of the am_control data structure since this is
 *	read only.
 *
 * Arguments:
 *	void		*arg	Argument structure
 *
 * Returns:
 *	void
 */
static void
am_mixerctl_setinfo_task(void *arg)
{
	queue_t			*q = ((am_ioctl_args_t *)arg)->aia_q;
	mblk_t			*mp = ((am_ioctl_args_t *)arg)->aia_mp;
	audio_ch_t		*chptr = (audio_ch_t *)
				    audio_sup_get_qptr_data(q);
	audio_apm_info_t	*apm_infop = chptr->ch_apm_infop;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	audio_info_t		*hw_info = apm_infop->apm_ad_state;
	struct copyreq		*cqp = (struct copyreq *)mp->b_rptr;
	audio_i_state_t		*state = (audio_i_state_t *)cqp->cq_private;
	audio_info_t		ninfo;
	audio_ch_t		ch;
	audio_info_t		*tinfo;
	am_control_t		*new;
	int			error = 0;

	ATRACE("in am_mixerctl_setinfo_task() arg", arg);

	am_enter_rwlock();

	/* we have to check the mode when it's stable */
	if (stpptr->am_pstate->apm_mode != AM_MIXER_MODE) {
		ATRACE_32("am_mixerctl_setinfo_task() bad mode",
		    chptr->ch_info.dev_type);
		error = EINVAL;
		goto nack;
	}

	/* get a pointer to the user supplied structure */
	new = (am_control_t *)mp->b_cont->b_rptr;
	tinfo = &new->dev_info;

	/* we can only modify a few things so make sure that's all we touch */
	AUDIO_INIT(&ninfo, sizeof (ninfo));
	ninfo.play.gain = tinfo->play.gain;
	ninfo.play.balance = tinfo->play.balance;
	ninfo.play.port = tinfo->play.port;
	ninfo.play.pause = tinfo->play.pause;
	ninfo.record.gain = tinfo->record.gain;
	ninfo.record.balance = tinfo->record.balance;
	ninfo.record.port = tinfo->record.port;
	ninfo.record.pause = tinfo->record.pause;
	ninfo.monitor_gain = tinfo->monitor_gain;
	ninfo.output_muted = tinfo->output_muted;

	/* we always create a pseudo channel that points to the h/w */
	bcopy(chptr, &ch, sizeof (*chptr));
	ch.ch_info.info = hw_info;

	/* too ugly to check here, so send to a utility routine */
	ATRACE("am_mixerctl_setinfo_task() calling am_audio_set_info()", chptr);
	if (am_audio_set_info(&ch, &ninfo, &ninfo) == AUDIO_FAILURE) {
		ATRACE("am_mixerctl_setinfo_task() am_audio_set_info() failed",
		    chptr);
		error = EINVAL;
		goto nack;
	}

	/* since there wasn't an error we succeeded, so return struct */
	tinfo->play.gain = ninfo.play.gain;
	tinfo->play.balance = ninfo.play.balance;
	tinfo->play.port = ninfo.play.port;
	tinfo->play.pause = ninfo.play.pause;
	tinfo->record.gain = ninfo.record.gain;
	tinfo->record.balance = ninfo.record.balance;
	tinfo->record.port = ninfo.record.port;
	tinfo->record.pause = ninfo.record.pause;
	tinfo->monitor_gain = ninfo.monitor_gain;
	tinfo->output_muted = ninfo.output_muted;

	/*
	 * Since there wasn't an error we were successful, now return
	 * the updated structure.
	 */
	state->ais_command = AM_COPY_OUT_MIXCTLINFO;

	/* Setup for copyout */
	ASSERT(state->ais_address != NULL);
	mcopyout(mp, state, sizeof (*tinfo), state->ais_address, NULL);
	ASSERT(mp->b_cont->b_wptr == (mp->b_cont->b_rptr + sizeof (*tinfo)));

	qreply(q, mp);

	kmem_free(arg, sizeof (am_ioctl_args_t));

	am_exit_task(chptr);

	am_release_rwlock();

	ATRACE("am_mixerctl_setinfo_task() returning", chptr);

	return;

nack:
	am_mixer_task_acknack(state, chptr, q, mp, arg, error);

	am_release_rwlock();

	ATRACE("am_mixerctl_setinfo_task() returning error", chptr);

}	/* am_mixerctl_setinfo_task() */

/*
 * am_multiple_open_task()
 *
 * Description:
 *	The second part of the AUDIO_MIXER_MULTIPLE_OPEN ioctl(). We check
 *	the state here so we can rely on the state.
 *
 * Arguments:
 *	void		*arg	Argument structure
 *
 * Returns:
 *	void
 */
static void
am_multiple_open_task(void *arg)
{
	queue_t			*q = ((am_ioctl_args_t *)arg)->aia_q;
	mblk_t			*mp = ((am_ioctl_args_t *)arg)->aia_mp;
	audio_ch_t		*chptr = (audio_ch_t *)
				    audio_sup_get_qptr_data(q);
	audio_apm_info_t	*apm_infop = chptr->ch_apm_infop;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	am_ch_private_t		*chpptr = chptr->ch_private;
	struct copyreq		*cqp = (struct copyreq *)mp->b_rptr;
	audio_i_state_t		*state = (audio_i_state_t *)cqp->cq_private;
	int			error = 0;

	ATRACE("in am_multiple_open_task() arg", arg);

	am_enter_rwlock();

	/*
	 * Don't allow this ioctl() if not in MIXER mode. We have to do this
	 * check in the task because that's the only way we can rely on the
	 * state.
	 */
	if (stpptr->am_pstate->apm_mode == AM_COMPAT_MODE) {
		ATRACE_32("am_multiple_open_task() bad mode",
		    stpptr->am_pstate->apm_mode);
		error = EINVAL;
		goto done;
	}

	/* just set the mode without checking what it is */
	mutex_enter(&chptr->ch_lock);
	chpptr->acp_flags |= AM_CHNL_MULTI_OPEN;
	ATRACE_32("am_multiple_open_task() flags", chpptr->acp_flags);
	mutex_exit(&chptr->ch_lock);

	/* wake up any channels waiting on multiple open()s */
	mutex_enter(&chptr->ch_statep->as_lock);
	cv_broadcast(&chptr->ch_statep->as_cv);
	mutex_exit(&chptr->ch_statep->as_lock);

done:
	am_mixer_task_acknack(state, chptr, q, mp, arg, error);

	am_release_rwlock();

	ATRACE_32("am_multiple_open_task() done", error);

}	/* am_multiple_open_task() */

/*
 * am_sample_rate_task()
 *
 * Description:
 *	Now that we will know how many sample rates to return we can get
 *	them. We do this in a task because we need to know the mixer mode.
 *
 * Arguments:
 *	void		*arg	Argument structure
 *
 * Returns:
 *	void
 */
static void
am_sample_rate_task(void *arg)
{
	queue_t			*q = ((am_ioctl_args_t *)arg)->aia_q;
	mblk_t			*mp = ((am_ioctl_args_t *)arg)->aia_mp;
	audio_ch_t		*chptr = (audio_ch_t *)
				    audio_sup_get_qptr_data(q);
	struct copyreq		*cqp = (struct copyreq *)mp->b_rptr;
	audio_i_state_t		*state = (audio_i_state_t *)cqp->cq_private;
	audio_apm_info_t	*apm_infop = chptr->ch_apm_infop;
	am_ad_info_t		*ad_infop = apm_infop->apm_ad_infop;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	am_sample_rates_t	*new;
	am_ad_sample_rates_t	*src;
	size_t			size;
	int			error = 0;
	int			i;
	int			mode = stpptr->am_pstate->apm_mode;
	int			num;

	ATRACE("in am_sample_rate_task() arg", arg);

	am_enter_rwlock();

	/* get a pointer to the user supplied structure */
	new = (am_sample_rates_t *)mp->b_cont->b_rptr;
	/* new->flags is random data, so clear */
	new->flags = 0;

	/* make sure the number of array elements is sane */
	if (new->num_samp_rates <= 0) {
		ATRACE_32("am_sample_rate_task() AM_COPY_IN_SAMP_RATES2 "
		    "bad num_samp_rates", new->num_samp_rates);
		error = EINVAL;
		goto nack;
	}

	size = AUDIO_MIXER_SAMP_RATES_STRUCT_SIZE(new->num_samp_rates);

	ATRACE_32("am_sample_rate_task() AM_COPY_IN_SAMP_RATES2 type",
	    new->type);
	if (new->type == AUDIO_PLAY &&
	    (ad_infop->ad_defaults->hw_features & AUDIO_HWFEATURE_PLAY)) {
		if (mode == AM_MIXER_MODE) {
			src = &ad_infop->ad_play.ad_mixer_srs;
		} else {
			ASSERT(mode == AM_COMPAT_MODE);
			src = &ad_infop->ad_play.ad_compat_srs;
		}
	} else if (new->type == AUDIO_RECORD &&
	    (ad_infop->ad_defaults->hw_features & AUDIO_HWFEATURE_RECORD)) {
		if (mode == AM_MIXER_MODE) {
			src = &ad_infop->ad_record.ad_mixer_srs;
		} else {
			ASSERT(mode == AM_COMPAT_MODE);
			src = &ad_infop->ad_record.ad_compat_srs;
		}
	} else {
		error = EINVAL;
		goto nack;
	}

	/* figure out how many sample rates we have */
	for (num = 0; src->ad_srs[num] != 0; num++);

	/* we don't copy more sample rates than we have */
	if (num < new->num_samp_rates) {
		new->num_samp_rates = num;
	}

	/* we reuse the buffer we got from user space */
	for (i = 0; i < new->num_samp_rates; i++) {
		/* get sample rate for array elements */
		if (src->ad_srs[i] == 0) {
			/* at the end of sample rates */
			break;
		}
		new->samp_rates[i] = src->ad_srs[i];
	}

	/* let the app know there are more */
	if (num > new->num_samp_rates) {
		new->num_samp_rates = num;
	}

	/* type remains the same, but update others */
	if (src->ad_limits & MIXER_SRS_FLAG_SR_LIMITS) {
		new->flags = MIXER_SR_LIMITS;
	}

	/* ready to send the filled in structure back */
	state->ais_command = AM_COPY_OUT_SAMP_RATES;

	/* Setup for copyout */
	ASSERT(state->ais_address != NULL);
	mcopyout(mp, state, size, state->ais_address, NULL);
	ASSERT(mp->b_cont->b_wptr == (mp->b_cont->b_rptr + size));

	qreply(q, mp);

	kmem_free(arg, sizeof (am_ioctl_args_t));

	am_exit_task(chptr);

	am_release_rwlock();

	ATRACE_32("am_sample_rate_task() done", error);

	return;

nack:
	am_mixer_task_acknack(state, chptr, q, mp, arg, error);

	am_release_rwlock();

	ATRACE_32("am_sample_rate_task() returning error", error);

}	/* am_sample_rate_task() */

/*
 * am_set_chinfo_task()
 *
 * Description:
 *	Called by the task queue to set the channel's state. We've already
 *	verified the size and channel are okay, as well as there is a buffer.
 *	We have the audio_info structure, in mp->b_cont,  so new we can set
 *	the state.
 *
 * Arguments:
 *	void		*arg	Argument structure
 *
 * Returns:
 *	void
 */
static void
am_set_chinfo_task(void *arg)
{
	STRUCT_HANDLE(audio_channel, audio_channel);
	queue_t			*q = ((am_ioctl_args_t *)arg)->aia_q;
	mblk_t			*mp = ((am_ioctl_args_t *)arg)->aia_mp;
	audio_ch_t		*chptr = (audio_ch_t *)
				    audio_sup_get_qptr_data(q);
	audio_ch_t		*tchptr;
	audio_state_t		*statep = chptr->ch_statep;
	audio_apm_info_t	*apm_infop = chptr->ch_apm_infop;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	struct copyreq		*cqp = (struct copyreq *)mp->b_rptr;
	audio_i_state_t		*state = (audio_i_state_t *)cqp->cq_private;
	audio_info_t		*tinfo = (audio_info_t *)mp->b_cont->b_rptr;
	audio_channel_t		*ch;
	struct iocblk		*iocbp = (struct iocblk *)mp->b_rptr;
	int			ch_number;
	int			error = 0;

	ATRACE("in am_set_chinfo_task() arg", arg);

	am_enter_rwlock();

	/* we have to check the mode when it's stable */
	if (stpptr->am_pstate->apm_mode != AM_MIXER_MODE) {
		ATRACE_32("am_set_chinfo_task() bad mode",
		    chptr->ch_info.dev_type);
		error = EINVAL;
		goto nack;
	}

	/* get ready to do the model conversion */
	ch = (audio_channel_t *)((mblk_t *)state->ais_address2)->b_rptr;
	STRUCT_SET_HANDLE(audio_channel, iocbp->ioc_flag, ch);

	/*
	 * We check things again because since the last check it could have
	 * changed on us.
	 */
	if (STRUCT_FGET(audio_channel, info_size) != sizeof (audio_info_t)) {
		ATRACE_32("am_set_chinfo_task() bad size",
		    STRUCT_FGET(audio_channel, info_size));
		error = EINVAL;
		goto nack;
	}
	if (STRUCT_FGETP(audio_channel, info) == NULL) {
		ATRACE("am_set_chinfo_task() no buffer",
		    STRUCT_FGETP(audio_channel, info));
		error = EINVAL;
		goto nack;
	}
	ch_number = STRUCT_FGET(audio_channel, ch_number);
	if (ch_number >= statep->as_max_chs || ch_number < 0) {
		ATRACE_32("am_set_chinfo_task() bad ch number",
		    STRUCT_FGET(audio_channel, ch_number));
		error = EINVAL;
		goto nack;
	}

	/* make sure this is a valid AUDIO/AUDIOCTL ch */
	tchptr = &statep->as_channels[ch_number];
	mutex_enter(&tchptr->ch_lock);
	if (!(tchptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
	    tchptr->ch_info.pid == 0 ||
	    (tchptr->ch_info.dev_type != AUDIO &&
	    tchptr->ch_info.dev_type != AUDIOCTL)) {
		mutex_exit(&tchptr->ch_lock);
		ATRACE("am_set_chinfo_task() bad ch", tchptr);
		error = EINVAL;
		goto nack;
	}
	mutex_exit(&tchptr->ch_lock);

	/* because the channels are stable we update the audio_channel struct */
	STRUCT_FSET(audio_channel, pid, tchptr->ch_info.pid);
	STRUCT_FSET(audio_channel, dev_type, tchptr->ch_info.dev_type);

	/* too ugly to check here, so send to a utility routine */
	ATRACE("am_set_chinfo_task() calling am_audio_set_info()", chptr);
	if (am_audio_set_info(tchptr, tinfo, tinfo) == AUDIO_FAILURE) {
		error = EINVAL;
		goto nack;
	}

	/* update the played sample count */
	mutex_enter(&chptr->ch_lock);
	am_fix_info(chptr, tinfo);
	mutex_exit(&chptr->ch_lock);

	/*
	 * Since there wasn't an error we were successful, now return
	 * the updated structure.
	 */
	state->ais_command = AM_COPY_OUT_MIXCTL_GET_CHINFO;

	/* Setup for copyout */
	ASSERT(state->ais_address != NULL);
	mcopyout(mp, state, sizeof (*tinfo), state->ais_address, NULL);
	ASSERT(mp->b_cont->b_wptr == (mp->b_cont->b_rptr + sizeof (*tinfo)));

	qreply(q, mp);

	kmem_free(arg, sizeof (am_ioctl_args_t));

	am_exit_task(chptr);

	am_release_rwlock();

	ATRACE("am_set_chinfo_task() returning", chptr);

	return;

nack:
	am_mixer_task_acknack(state, chptr, q, mp, arg, error);

	am_release_rwlock();

	ATRACE("am_set_chinfo_task() returning error", chptr);

}	/* am_set_chinfo_task() */

/*
 * am_set_mode_task()
 *
 * Description:
 *	Switch modes. We have to shut down play and record first, then change
 *	modes, and finally restart. Since we are a low priority thread we
 *	can sleep!
 *
 * Arguments:
 *	void		*arg	Argument structure
 *
 * Returns:
 *	void
 */
static void
am_set_mode_task(void *arg)
{
	queue_t			*q = ((am_ioctl_args_t *)arg)->aia_q;
	mblk_t			*mp = ((am_ioctl_args_t *)arg)->aia_mp;
	audio_ch_t		*chptr = (audio_ch_t *)
				    audio_sup_get_qptr_data(q);
	audio_state_t		*statep = chptr->ch_statep;
	am_ch_private_t		*chpptr = chptr->ch_private;
	audio_apm_info_t	*apm_infop = chptr->ch_apm_infop;
	am_ad_info_t		*ad_infop = apm_infop->apm_ad_infop;
	struct copyreq		*cqp = (struct copyreq *)mp->b_rptr;
	audio_i_state_t		*state = (audio_i_state_t *)cqp->cq_private;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	audio_ch_t		*pchptr = NULL;
	audio_ch_t		*rchptr = NULL;
	audio_ch_t		*tchptr;
	am_ch_private_t		*tchpptr;
	audio_info_t		*hw_info = apm_infop->apm_ad_state;
	audio_info_t		*new_pinfo = NULL;
	audio_info_t		*new_rinfo = NULL;
	audio_info_t		old_hw_info;
	audio_info_t		*tinfo;
	int			doread;
	int			dowrite;
	int			error = 0;
	int			i;
	int			max_chs = statep->as_max_chs;
	int			mode = stpptr->am_pstate->apm_mode;
	int			new_mode;
	int			ppid = 0;
	int			rpid = 0;
#ifdef DEBUG
	int			pcount = 0;
	int			rcount = 0;
#endif

	ATRACE("in am_set_mode_task() arg", arg);

	am_enter_rwlock();

	/* get the new_mode and make sure it's good */
	new_mode = *((int *)mp->b_cont->b_rptr);
	ATRACE_32("am_set_mode_task() new mode", new_mode);
	if (new_mode != AM_MIXER_MODE && new_mode != AM_COMPAT_MODE) {
		ATRACE_32("am_set_mode_task() bad mode", new_mode);
		error = EINVAL;
		goto done;
	}

	/* make sure we aren't going into the same mode */
	if (mode == new_mode) {
		ATRACE_32("am_set_mode_task() same mode", new_mode);
		goto done;
	}

	/* figure out the direction */
	doread = ad_infop->ad_defaults->hw_features & AUDIO_HWFEATURE_RECORD;
	dowrite = ad_infop->ad_defaults->hw_features & AUDIO_HWFEATURE_PLAY;

	/* we allocate this memory while it's easy to back out */
	if (new_mode == AM_MIXER_MODE &&
	    ad_infop->ad_codec_type == AM_TRAD_CODEC) {
			new_pinfo = kmem_alloc(sizeof (*new_pinfo), KM_SLEEP);
			new_rinfo = kmem_alloc(sizeof (*new_rinfo), KM_SLEEP);
	}

	/* get the AUDIO apm_info pointer, we've got one for AUDIOCTL */
	if ((apm_infop = audio_sup_get_apm_info(statep, AUDIO)) == NULL) {
		if (new_pinfo) {
			kmem_free(new_pinfo, sizeof (*new_pinfo));
		}
		if (new_rinfo) {
			kmem_free(new_rinfo, sizeof (*new_rinfo));
		}
		error = EIO;
		goto done;
	}

	/*
	 * Make sure we can go to COMPAT mode while we're locked. By
	 * definition if we are going to MIXER mode we can't have more
	 * than one in and one out channel allocated.
	 */
	mutex_enter(&statep->as_lock);
	if (new_mode == AM_COMPAT_MODE && (stpptr->am_in_chs > 1 ||
	    stpptr->am_out_chs > 1)) {
		ATRACE("am_set_mode_task() AM_COPY_IN_MIXCTL_MODE busy", chptr);
		ASSERT(new_pinfo == NULL);
		ASSERT(new_rinfo == NULL);

		error = EBUSY;
		mutex_exit(&statep->as_lock);
		goto done;
	} else {
		ASSERT(stpptr->am_in_chs <= 1);
		ASSERT(stpptr->am_out_chs <= 1);
	}
	mutex_exit(&statep->as_lock);

	/* once playing/recording has stopped we can clear this flag */
	mutex_enter(&apm_infop->apm_lock);
	stpptr->am_flags |= AM_PRIV_SW_MODES;
	mutex_exit(&apm_infop->apm_lock);

	/* how we do the switch is different based on the device */
	if (ad_infop->ad_codec_type == AM_MS_CODEC) {
		/* find the reading and writing channels */
		for (i = 0, tchptr = &statep->as_channels[0];
		    i < max_chs; i++, tchptr++) {

			mutex_enter(&tchptr->ch_lock);

			/* skip non-AUDIO and unallocated channels */
			if (!(tchptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
			    tchptr->ch_info.dev_type != AUDIO ||
			    tchptr->ch_info.pid == 0) {
				mutex_exit(&tchptr->ch_lock);
				continue;
			}

			/* is this channel playing?, recording? */
			tchpptr = tchptr->ch_private;
			ATRACE("am_set_mode_task() found ch flags",
			    chpptr->acp_flags);
			if (tchpptr->acp_writing) {
				ATRACE_32("am_set_mode_task() MS found play ch",
				    tchptr->ch_info.ch_number);
				ASSERT(pchptr == NULL);
				ASSERT(dowrite);
				pchptr = tchptr;
#ifdef DEBUG
				pcount++;
#endif
			}
			if (tchpptr->acp_reading) {
				ATRACE_32(
				    "am_set_mode_task() MS found record ch",
				    tchptr->ch_info.ch_number);
				ASSERT(rchptr == 0);
				ASSERT(doread);
				rchptr = tchptr;
#ifdef DEBUG
				rcount++;
#endif
			}
			mutex_exit(&tchptr->ch_lock);

			/* are we done finding active channels? */
			if ((pchptr || !dowrite) && (rchptr || !doread)) {
				break;
			}
		}
		ASSERT(pcount <= 1);
		ASSERT(rcount <= 1);

		/* pause playing & recording, so the ISR isn't called */
		if (dowrite) {
			ATRACE("am_set_mode_task() pause play", chptr);
			tinfo = pchptr->ch_info.info;
			am_ad_pause_play(statep, stpptr, ad_infop,
			    pchptr->ch_info.ch_number);
			tinfo->play.active = 0;
			hw_info->play.active = 0;
			tinfo->play.pause = 1;
		}
		if (doread) {
			ATRACE("am_set_mode_task() stop record", chptr);
			tinfo = rchptr->ch_info.info;
			am_ad_stop_record(statep, stpptr, ad_infop,
			    rchptr->ch_info.ch_number);
			tinfo->record.active = 0;
			hw_info->record.active = 0;
			tinfo->record.pause = 0;
		}

		/*
		 * Multi-stream Codecs already use the virtual channel
		 * configuration to set the hardware, so this is a trivial
		 * change to make. Everything is halted so we don't need
		 * to lock this.
		 */
		if (new_mode == AM_COMPAT_MODE) {
			stpptr->am_pstate->apm_mode = AM_COMPAT_MODE;
		} else {
			ASSERT(new_mode == AM_MIXER_MODE);
			stpptr->am_pstate->apm_mode = AM_MIXER_MODE;
		}

		ATRACE("am_set_mode_task() AM_MS_CODEC switch done", ad_infop);

	} else {
		ASSERT(ad_infop->ad_codec_type == AM_TRAD_CODEC);

		/* wait for playing to end */
		mutex_enter(&stpptr->am_mode_lock);

		while (dowrite && hw_info->play.active) {
			ATRACE_32("am_set_mode_task() wait to stop playing",
			    hw_info->play.active);
			if (cv_wait_sig(&stpptr->am_mode_cv,
			    &stpptr->am_mode_lock) <= 0) {

				ATRACE("am_set_mode_task() signal interrupt",
				    hw_info->play.active);

				mutex_exit(&stpptr->am_mode_lock);

				/* we aren't switching modes any longer */
				mutex_enter(&apm_infop->apm_lock);
				stpptr->am_flags &= ~AM_PRIV_SW_MODES;
				mutex_exit(&apm_infop->apm_lock);

				/* we are bailing, so we need to restart */
				am_restart(statep, hw_info);

				if (new_mode == AM_MIXER_MODE) {
					if (new_pinfo) {
						kmem_free(new_pinfo,
						    sizeof (*new_pinfo));
					}
					if (new_rinfo) {
						kmem_free(new_rinfo,
						    sizeof (*new_rinfo));
					}
				}

				error = EINTR;
				goto done;
			}
			ATRACE(
			    "am_set_mode_task() signal returned normally", 0);
		}
		mutex_exit(&stpptr->am_mode_lock);

		/*
		 * Now we shutdown the record channel, if active.
		 * We have to lock to make this call.
		 */
		if (doread && hw_info->record.active) {
			am_ad_stop_record(statep, stpptr, ad_infop,
			    chptr->ch_info.ch_number);
			hw_info->record.active = 0;
		}

		/* wait as long as possible to save the old state for later */
		bcopy(hw_info, &old_hw_info, sizeof (*hw_info));

		/* find the play and record channels */
		ASSERT(pcount == 0);
		ASSERT(rcount == 0);
		ASSERT(pchptr == 0);
		ASSERT(rchptr == 0);
		for (i = 0, tchptr = &statep->as_channels[0];
			    i < max_chs; i++, tchptr++) {
			/* skip non-AUDIO and unallocated channels */
			mutex_enter(&tchptr->ch_lock);
			if (!(tchptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
			    tchptr->ch_info.dev_type != AUDIO ||
			    tchptr->ch_info.pid == 0) {
				mutex_exit(&tchptr->ch_lock);
				continue;
			}

			/* is this channel playing?, recording? */
			tchpptr = tchptr->ch_private;
			ATRACE("am_set_mode_task() found ch flags",
				    tchpptr->acp_flags);
			if (dowrite && tchpptr->acp_writing) {
				ATRACE_32("am_set_mode_task() T found play ch",
				    tchptr->ch_info.ch_number);
				/*
				 * Disable the queue so that am_wsvc() won't
				 * process any more data messages.
				 */
				noenable(tchptr->ch_qptr);

				pchptr = tchptr;
#ifdef DEBUG
				pcount++;
#endif
			}
			if (doread && tchpptr->acp_reading) {
				ATRACE_32(
				    "am_set_mode_task() T found record ch",
				    tchptr->ch_info.ch_number);
				rchptr = tchptr;
#ifdef DEBUG
				rcount++;
#endif
			}

			mutex_exit(&tchptr->ch_lock);

			/* are we done finding active channels? */
			if ((pchptr || !dowrite) && (rchptr || !doread)) {
				break;
			}
		}
		ASSERT(pcount <= 1);
		ASSERT(rcount <= 1);

		/*
		 * We stop playing because we have to force it to restart from
		 * scratch, which means flushing the DMA engine. Otherwise
		 * there's old data with the wrong format. This a problem only
		 * when we are paused.
		 */
		if (pchptr &&
		    ((audio_info_t *)pchptr->ch_info.info)->play.pause) {
			am_ad_stop_play(statep, stpptr, ad_infop,
			    AM_SET_CONFIG_BOARD);
		}

		if (new_mode == AM_MIXER_MODE) {
			if (am_set_mixer_mode(chptr, ad_infop, stpptr,
			    pchptr, rchptr) == AUDIO_FAILURE) {
				/* we aren't switching modes any longer */
				mutex_enter(&apm_infop->apm_lock);
				stpptr->am_flags &= ~AM_PRIV_SW_MODES;
				mutex_exit(&apm_infop->apm_lock);

				/* we are bailing, so we need to restart */
				am_restart(statep, hw_info);

				if (new_pinfo) {
					kmem_free(new_pinfo,
					    sizeof (*new_pinfo));
				}
				if (new_rinfo) {
					kmem_free(new_rinfo,
					    sizeof (*new_rinfo));
				}

				error = EIO;
				goto done;
			}
		} else {
			if (am_set_compat_mode(chptr, ad_infop,
			    pchptr, rchptr) == AUDIO_FAILURE) {
				/* we aren't switching modes any longer */
				mutex_enter(&apm_infop->apm_lock);
				stpptr->am_flags &= ~AM_PRIV_SW_MODES;
				mutex_exit(&apm_infop->apm_lock);

				/* we are bailing, so we need to restart */
				am_restart(statep, hw_info);

				ASSERT(new_pinfo == NULL);
				ASSERT(new_rinfo == NULL);

				error = EIO;
				goto done;
			}
		}
	}
	/* save the mode in persistent memory */
	stpptr->am_pstate->apm_mode = new_mode;

	/*
	 * CAUTION: From here on out we cannot fail. We've changed modes
	 *	and to fail would require setting it back. It is better
	 *	to have a gap in audio then to go back at this point.
	 */

	/* we're in a new mode now, so fix the play/rec info pointers */
	hw_info = &stpptr->am_hw_info;
	if (new_mode == AM_MIXER_MODE) {
		int	tpid;
		/* rebuild info structures and get pids */
		if (pchptr && pchptr == rchptr) {
			/* this is play/record channel */
			mutex_enter(&pchptr->ch_lock);
			ppid = pchptr->ch_info.pid;
			rpid = ppid;

			tinfo = new_pinfo;
			pchptr->ch_info.info = tinfo;
			mutex_exit(&pchptr->ch_lock);

			if (new_rinfo) {
				kmem_free(new_rinfo, sizeof (*new_rinfo));
			}
			new_rinfo = NULL;

			/* copy in the old play state */
			bcopy(&old_hw_info.play, &tinfo->play,
			    (2 * sizeof (old_hw_info.play)));

			/* copy the current dev state */
			tinfo->monitor_gain = hw_info->monitor_gain;
			tinfo->output_muted = hw_info->output_muted;
			tinfo->hw_features = hw_info->hw_features;
			tinfo->sw_features = hw_info->sw_features;
			tinfo->sw_features_enabled =
			    hw_info->sw_features_enabled;
			tinfo->ref_cnt = 1;
		} else {
			/* play or record channels */
			ASSERT(pchptr != rchptr ||
			    (pchptr == 0 && rchptr == 0));
			if (pchptr) {
				mutex_enter(&pchptr->ch_lock);
				ppid = pchptr->ch_info.pid;

				tinfo = new_pinfo;
				AUDIO_INIT(tinfo, sizeof (*tinfo));
				pchptr->ch_info.info = tinfo;

				/* copy in the old play state */
				bcopy(&old_hw_info.play, &tinfo->play,
				    sizeof (tinfo->play));
				/* copy the current dev state */
				tinfo->monitor_gain = hw_info->monitor_gain;
				tinfo->output_muted = hw_info->output_muted;
				tinfo->hw_features = hw_info->hw_features;
				tinfo->sw_features = hw_info->sw_features;
				tinfo->sw_features_enabled =
					hw_info->sw_features_enabled;
				tinfo->ref_cnt = 1;
				mutex_exit(&pchptr->ch_lock);
			} else {
				if (new_pinfo) {
					kmem_free(new_pinfo,
						sizeof (*new_pinfo));
				}
				new_pinfo = NULL;
			}
			if (rchptr) {
				mutex_enter(&rchptr->ch_lock);
				rpid = rchptr->ch_info.pid;

				tinfo = new_rinfo;
				AUDIO_INIT(tinfo, sizeof (*tinfo));
				rchptr->ch_info.info = tinfo;

				/* copy in the old record state */
				bcopy(&old_hw_info.record, &tinfo->record,
				    sizeof (old_hw_info.record));
				/* copy the current dev state */
				tinfo->monitor_gain = hw_info->monitor_gain;
				tinfo->output_muted = hw_info->output_muted;
				tinfo->hw_features = hw_info->hw_features;
				tinfo->sw_features = hw_info->sw_features;
				tinfo->sw_features_enabled =
					hw_info->sw_features_enabled;
				tinfo->ref_cnt = 1;
				mutex_exit(&rchptr->ch_lock);
			} else {
				if (new_rinfo) {
					kmem_free(new_rinfo,
						sizeof (*new_rinfo));
				}
				new_rinfo = NULL;
			}
		}

		/* start over with the reference count */
		hw_info->ref_cnt = 1;

		/* find AUDIOCTL channels to assoc. with AUDIO chs */
		for (i = 0, tchptr = &statep->as_channels[0];
		    i < max_chs; i++, tchptr++) {

			/* skip if not AUDIOCTL or allocated chs */
			mutex_enter(&tchptr->ch_lock);
			if (!(tchptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
			    tchptr->ch_info.dev_type != AUDIOCTL ||
			    tchptr->ch_info.pid == 0) {
				mutex_exit(&tchptr->ch_lock);
				continue;
			}

			ASSERT(hw_info == tchptr->ch_info.info);

			tpid = tchptr->ch_info.pid;

			if (ppid && tpid == ppid) {
				tchptr->ch_info.info = new_pinfo;
				new_pinfo->ref_cnt++;
			} else if (rpid && tpid == rpid) {
				tchptr->ch_info.info = new_rinfo;
				new_rinfo->ref_cnt++;
			} else {
				tchptr->ch_info.info = hw_info;
				hw_info->ref_cnt++;
			}
			mutex_exit(&tchptr->ch_lock);
		}

		/* now we need to re-initialize the src structures */
		if (pchptr) {
			ATRACE("am_set_mode_task() calling am_fix_play_pause",
				pchptr->ch_private);

			am_fix_play_pause(pchptr);
		}
	} else {
		/* start over with the reference count */
		hw_info->ref_cnt = 1;

		for (i = 0, tchptr = &statep->as_channels[0];
		    i < max_chs; i++, tchptr++) {

			/*
			 * Skip if ! AUDIO, AUDIOCTL or allocated channels.
			 *
			 * It is possible that new audio will arrive in
			 * am_wsvc(), thus we need to make sure we have this
			 * lock and hold it if we have to manipulate the
			 * channel's info structure.
			 */
			mutex_enter(&tchptr->ch_lock);
			if (!(tchptr->ch_flags & AUDIO_CHNL_ALLOCATED) ||
			    (tchptr->ch_info.dev_type != AUDIO &&
			    tchptr->ch_info.dev_type != AUDIOCTL) ||
			    tchptr->ch_info.pid == 0) {
				mutex_exit(&tchptr->ch_lock);
				continue;
			}

			/* see if we need to free the info structure */
			tinfo = tchptr->ch_info.info;
			if (tinfo != hw_info) {
				/* not set to hw */
				if (tinfo->ref_cnt == 1) {
					/* not set to hw, and only ref so clr */
					kmem_free(tinfo, sizeof (*tinfo));
				} else {
					/* someone else has a link to it */
					tinfo->ref_cnt--;
				}
			}
			/* now set to hardware */
			tchptr->ch_info.info = hw_info;
			hw_info->ref_cnt++;
			mutex_exit(&tchptr->ch_lock);
		}
	}

	/* we don't need this flag anymore, re-enabling ioctls */
	mutex_enter(&apm_infop->apm_lock);
	stpptr->am_flags &= ~AM_PRIV_SW_MODES;
	mutex_exit(&apm_infop->apm_lock);

	/* we're in the new mode, so restart I/O */
	am_restart(statep, hw_info);

	mutex_enter(&statep->as_lock);
	/* if we have blocked processes they should unblock */
	if (new_mode == AM_MIXER_MODE) {
		cv_broadcast(&statep->as_cv);
	}
	mutex_exit(&statep->as_lock);

	ATRACE_32("am_set_mode_task() done, new mode", new_mode);

done:
	am_mixer_task_acknack(state, chptr, q, mp, arg, error);

	am_release_rwlock();

	am_send_signal(statep, stpptr);

	ATRACE_32("am_set_mode_task() returning ack", error);

}	/* am_set_mode_task() */

/*
 * am_setinfo_task()
 *
 * Description:
 *	The third part of the AUDIO_SETINFO ioctl(). This is the task that
 *	gets serial access to the info data structure and hardware.
 *
 * Arguments:
 *	void		*arg	Argument structure
 *
 * Returns:
 *	void
 */
static void
am_setinfo_task(void *arg)
{
	queue_t			*q = ((am_ioctl_args_t *)arg)->aia_q;
	mblk_t			*mp = ((am_ioctl_args_t *)arg)->aia_mp;
	audio_ch_t		*chptr = (audio_ch_t *)
				    audio_sup_get_qptr_data(q);
	am_ch_private_t		*chpptr = chptr->ch_private;
	struct copyreq		*cqp = (struct copyreq *)mp->b_rptr;
	audio_i_state_t		*state = (audio_i_state_t *)cqp->cq_private;
	audio_info_t		*tinfo = (audio_info_t *)mp->b_cont->b_rptr;
	int			error = 0;

	ATRACE("in am_setinfo_task() arg", arg);

	am_enter_rwlock();

	if (cqp->cq_cmd != AUDIO_SETINFO) {
		ATRACE_32("am_wioctl() AUDIO_SETINFO bad command", cqp->cq_cmd);
		error = EINVAL;
		goto nack;
	}

	/*
	 * Don't allow this ioctl() when on an audioctl channel when multiple
	 * audio channel open()s are allowed. We have to do this in the task
	 * because that's the only way we can rely on the state.
	 */
	mutex_enter(&chptr->ch_lock);
	if (chptr->ch_info.dev_type == AUDIOCTL &&
	    (chpptr->acp_flags & AM_CHNL_MULTI_OPEN)) {
		ATRACE_32("am_wioctl() AUDIO_SETINFO bad type",
		    chptr->ch_info.dev_type);
		mutex_exit(&chptr->ch_lock);
		error = EINVAL;
		goto nack;
	}
	mutex_exit(&chptr->ch_lock);

	/* too ugly to check here, so send to a utility routine */
	ATRACE("am_setinfo_task() calling am_audio_set_info()", chptr);
	if (am_audio_set_info(chptr, tinfo, tinfo) == AUDIO_FAILURE) {
		ATRACE_32("am_wioctl() AUDIO_SETINFO setinfo failed command",
		    cqp->cq_cmd);
		error = EINVAL;
		goto nack;
	}

	/* update the played sample count */
	mutex_enter(&chptr->ch_lock);
	am_fix_info(chptr, tinfo);
	mutex_exit(&chptr->ch_lock);

	/*
	 * Since there wasn't an error we were successful, now return
	 * the updated structure.
	 */
	state->ais_command = AM_COPY_OUT_AUDIOINFO2;

	/* Setup for copyout */
	ASSERT(state->ais_address != NULL);
	mcopyout(mp, state, sizeof (*tinfo), state->ais_address, NULL);
	ASSERT(mp->b_cont->b_wptr == (mp->b_cont->b_rptr + sizeof (*tinfo)));

	qreply(q, mp);

	kmem_free(arg, sizeof (am_ioctl_args_t));

	am_exit_task(chptr);

	am_release_rwlock();

	ATRACE("am_setinfo_task() returning", chptr);

	return;

nack:
	am_mixer_task_acknack(state, chptr, q, mp, arg, error);

	am_release_rwlock();

	ATRACE_32("am_setinfo_task() returning nack", error);

}	/* am_setinfo_task() */

/*
 * am_single_open_task()
 *
 * Description:
 *	The second part of the AUDIO_MIXER_SINGLE_OPEN ioctl(). We check
 *	the state here so we can rely on the state.
 *
 * Arguments:
 *	void		*arg	Argument structure
 *
 * Returns:
 *	void
 */
static void
am_single_open_task(void *arg)
{
	queue_t			*q = ((am_ioctl_args_t *)arg)->aia_q;
	mblk_t			*mp = ((am_ioctl_args_t *)arg)->aia_mp;
	audio_ch_t		*chptr = (audio_ch_t *)
				    audio_sup_get_qptr_data(q);
	audio_ch_t		*tchptr;
	audio_state_t		*statep = chptr->ch_statep;
	audio_apm_info_t	*apm_infop = chptr->ch_apm_infop;
	am_apm_private_t	*stpptr = apm_infop->apm_private;
	am_ch_private_t		*chpptr = chptr->ch_private;
	struct copyreq		*cqp = (struct copyreq *)mp->b_rptr;
	audio_i_state_t		*state = (audio_i_state_t *)cqp->cq_private;
	am_ch_private_t		*tchpptr;
	pid_t			tpid;
	int			error = 0;
	int			i;
	int			max_chs = statep->as_max_chs;
	int			num_rd = 0;
	int			num_wr = 0;

	ATRACE("in am_single_open_task() arg", arg);

	am_enter_rwlock();

	/*
	 * Don't allow this ioctl() if not in MIXER mode. We have to do this
	 * check in the task because that's the only way we can rely on the
	 * state.
	 */
	if (stpptr->am_pstate->apm_mode == AM_COMPAT_MODE) {
		ATRACE_32("am_single_open_task() bad mode",
		    stpptr->am_pstate->apm_mode);
		error = EINVAL;
		goto done;
	}

	/* see if there are multiple open()s already */
	tpid = chptr->ch_info.pid;

	/* we need to freeze channel allocation */
	mutex_enter(&statep->as_lock);
	for (i = 0, tchptr = &statep->as_channels[0]; i < max_chs;
	    i++, tchptr++) {
		/* ignore different processes */
		mutex_enter(&tchptr->ch_lock);
		if (tchptr->ch_info.pid != tpid) {
			mutex_exit(&tchptr->ch_lock);
			continue;
		}

		tchpptr = tchptr->ch_private;
		if (tchpptr->acp_reading) {
			num_rd++;
		}
		if (tchpptr->acp_writing) {
			num_wr++;
		}
		mutex_exit(&tchptr->ch_lock);
	}
	mutex_exit(&statep->as_lock);

	/* we change back only if at most 1 read or write ch. open */
	if (num_rd > 1 || num_wr > 1) {
		/* too many channels open, so we have to fail */
		error = EIO;
	} else {
		/* if we get here we know there is only 1 ch, ours */
		mutex_enter(&chptr->ch_lock);
		chpptr->acp_flags &= ~AM_CHNL_MULTI_OPEN;
		mutex_exit(&chptr->ch_lock);

		ATRACE("am_single_open_task() flags", chpptr->acp_flags);
	}

done:
	am_mixer_task_acknack(state, chptr, q, mp, arg, error);

	am_release_rwlock();

	ATRACE_32("am_single_open_task() done", error);

}	/* am_single_open_task() */
