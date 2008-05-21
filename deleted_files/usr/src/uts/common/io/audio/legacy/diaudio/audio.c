/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1995, 1997, 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SunOS STREAMS Device-Independent Audio driver
 */

#include <sys/types.h>
#include <sys/machtypes.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/ioccom.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/modctl.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsun.h>

#include <sys/audioio.h>
#include <sys/audiovar.h>
#include <sys/audiodebug.h>

/*
 * Generic AUDIO driver
 *
 * This file contains the generic routines for handling a STREAMS-based
 * audio device.  The SPARCstation 1 audio chips, the SPARCstation 3 DBRI
 * chips, and the Crystal Semiconductor CS4231 are examples of such devices.
 */


/*
 * Local Function Prototypes
 */
static aud_return_t audio_do_setinfo(aud_stream_t *, mblk_t *, int *);


/*
 * Loadable module support
 */

extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops, "Generic Audio"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};


int
_init(void)
{
	return (mod_install(&modlinkage));
}


int
_fini(void)
{
	return (mod_remove(&modlinkage));
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * Start of audio routines...
 */

#define	OPEN_NONBLOCKING	(FNDELAY | FNONBLOCK)


/*
 * define macros to add and remove aud_cmd_t structures from the free list
 */
#define	audio_alloc_cmd(c, d)	{		\
		(d) = (c)->free;		\
		if ((d) != NULL)		\
			(c)->free = (d)->next;	\
	}

#define	audio_free_cmds(v, f, l) {		\
		(l)->next = (v)->free;		\
		(v)->free = (f);		\
	}


/*
 * For debugging, allocate space for the trace buffer
 */
#if defined(AUDIOTRACE) || defined(DBRITRACE)
struct audiotrace audiotrace_buffer[NAUDIOTRACE+1];
struct audiotrace *audiotrace_ptr;
int audiotrace_count;
#endif


/*
 * Append a command block to a list of chained commands
 */
static void
audio_append_cmd(aud_cmdlist_t *list, aud_cmd_t *cmdp)
{
	ATRACE(audio_append_cmd, 'APND', cmdp);

	cmdp->next = NULL;

	if (list->tail != NULL)
		list->tail->next = cmdp;
	else
		list->head = cmdp;
	list->tail = cmdp;

}


/*
 * audio_delete_cmds - Remove one or more cmds from anywhere on a command
 * list.  Deletes the commands from headp to lastp inclusive.
 */
static void
audio_delete_cmds(aud_cmdlist_t *list, aud_cmd_t *headp, aud_cmd_t *lastp)
{
	aud_cmd_t *cmdp;

	if (list->head == NULL)
		return;

	if (list->head == headp) {	/* Delete from head of list */
		list->head = lastp->next;
		if (list->head == NULL)
			list->tail = NULL;
	} else {			/* Delete from middle/end of list */
		/*
		 * Find element directly preceeding headp of list to delete
		 */
		for (cmdp = list->head; cmdp->next != NULL; cmdp = cmdp->next) {
			if (cmdp->next == headp)
				break;
		}

		cmdp->next = lastp->next;
		if (cmdp->next == NULL)
			list->tail = cmdp;
	}
	audio_free_cmds(list, headp, lastp);

} /* audio_delete_cmds */


/*
 * Flush a command list.
 * Audio i/o must be stopped on the list before flushing it.
 */
void
audio_flush_cmdlist(aud_stream_t *as)
{
	aud_cmdlist_t *list;
	aud_cmd_t *cmdp;

	ASSERT_ASLOCKED(as);

	list = &as->cmdlist;
	AUD_FLUSHCMD(as);

	/* Release STREAMS command block */
	for (cmdp = list->head; cmdp != NULL; cmdp = cmdp->next)  {
		if (cmdp->dihandle != NULL) {
			freemsg((mblk_t *)cmdp->dihandle);
			cmdp->dihandle = NULL;
		}
		cmdp->skip = B_FALSE;
		cmdp->done = B_FALSE;
		cmdp->dihandle = NULL;
		cmdp->data = 0;
		cmdp->enddata = 0;
		cmdp->lastfragment = 0;
		cmdp->processed = 0;
		cmdp->iotype = 0;
	}

	/*
	 * Remove entire command list
	 */
	audio_delete_cmds(list, list->head, list->tail);
} /* audio_flush_cmdlist */


/*
 * The ordinary audio device may only have a single reader and single
 * writer.  However, a special minor device is defined for which multiple
 * opens are permitted.  Reads and writes are prohibited for this
 * 'control' device, but certain ioctls, such as AUDIO_SETINFO, are
 * allowed.
 *
 * Note that this is NOT a generic STREAMS open routine.  It must be
 * called from a device-dependent open routine that sets 'as'
 * appropriately.
 *
 * NB: as must point to the correct "as"
 */
/*ARGSUSED*/
int
audio_open(aud_stream_t *as, queue_t *q, dev_t *devp, int flag, int sflag)
{
	int wantwrite;
	int wantread;
	int newminor;

	ATRACEINIT();		/* initialize tracing */
	ATRACE(audio_open, 'flag', flag);
	ASSERT(sflag != MODOPEN);
	ASSERT(as != NULL);

	ASSERT_ASLOCKED(as);

	if ((ISDATASTREAM(as) && ((flag & (FREAD|FWRITE)) == FREAD) &&
	    (as != as->input_as))) {
		cmn_err(CE_PANIC, "audio: open failure!");
		return (EINVAL);
	}

	/*
	 * If this is a data device: allow only one reader and one writer.
	 * If the requested access is busy, return EBUSY or hang until
	 * close().
	 *
	 * Due to a STREAMS bug, exclusive access is tricky to implement.
	 * A CLONE device is used, but, since a clone open cannot specify
	 * the minor number, we have to determine what it should be.
	 */

	/*
	 * If this device does not carry data, then it is not an
	 * exclusive open device.  Open is very simple for such devices.
	 */
	if (!ISDATASTREAM(as)) {
		/* If this is the first open, init the Streams queues */
		if (as->info.open == B_FALSE) {
			as->info.open = B_TRUE;
			as->sequence = 0;
			as->openflag = 0;

			ASSERT(as->readq == NULL);
			ASSERT(as->writeq == NULL);

			as->readq = q;
			as->writeq = WR(q);
			WR(q)->q_ptr = (caddr_t)as;
			q->q_ptr = (caddr_t)as;
			qprocson(q);
		}
		as->openflag |= (flag & (FREAD|FWRITE));

		ATRACE(audio_open, 'Open', as->info.minordev);
		return (0);
	}


	wantwrite = (flag & FWRITE) ? B_TRUE : B_FALSE;
	wantread = (flag & FREAD) ? B_TRUE : B_FALSE;

	if (!wantwrite && !wantread)
		return (EINVAL); /* must read and/or write data */

	while ((wantwrite && as->output_as->info.open) ||
	    (wantread && as->input_as->info.open)) {
		int notify;

		ATRACE(audio_open, 'BUSY', as);

		/*
		 * We can't sleep if this open is not a clone open or
		 * if the user specified a non-blocking open
		 */
		if ((sflag != CLONEOPEN) || (flag & OPEN_NONBLOCKING)) {
			ATRACE(audio_open, '!slp', as);
			return (EBUSY);
		}

		/*
		 * Otherwise, hang until device is closed or a signal
		 * interrupts the sleep.
		 *
		 * If this is the first process to request access, signal
		 * the control device so that it can detect the status
		 * change.  Unfortunately, if the current process has
		 * opened and enabled signals on the control device, this
		 * signal will break the sleep we're about to do.
		 * However, the process should already be prepared for
		 * this by retrying the open() when EINTR is returned.
		 */
		if (wantwrite && !as->output_as->info.waiting) {
			as->output_as->info.waiting = B_TRUE;
			notify = B_TRUE;
		} else {
			notify = B_FALSE;
		}

		if (wantread && !as->input_as->info.waiting) {
			as->input_as->info.waiting = B_TRUE;
			notify = B_TRUE;
		}

		/*
		 * NB: ASLOCK is held across this audio_sendsig
		 */
		if (notify)
			audio_sendsig(as, AUDIO_SENDSIG_ALL);

		if (cv_wait_sig(&as->control_as->cv, as->lock) == 0) {
			as->input_as->info.waiting = B_FALSE;
			return (EINTR);
		}

		ATRACE(audio_open, '!BSY', as);
	}

	if (wantwrite)
		newminor = as->output_as->info.minordev;
	else
		newminor = as->input_as->info.minordev;

	if (newminor == 0)
		return (ENODEV);


	/*
	 * Set up the streams pointers for the requested access modes.
	 * If opened read/write, set the streams q_ptr to &v->play and
	 * mark the stream accordingly.
	 */
	if (wantread) {
		as->input_as->sequence = 0;
		as->input_as->info.open = B_TRUE;
		as->input_as->openflag = flag & (FREAD|FWRITE);
		as->input_as->readq = q;
		as->input_as->writeq = WR(q);
		WR(q)->q_ptr = (caddr_t)as->input_as;
		q->q_ptr = (caddr_t)as->input_as;

		ATRACE(audio_open, 'Oinp', as->input_as);
	}

	if (wantwrite) {
		as->output_as->sequence = 0;
		as->output_as->info.open = B_TRUE;
		as->output_as->openflag = flag & (FREAD|FWRITE);
		as->output_as->readq = q;
		as->output_as->writeq = WR(q);
		WR(q)->q_ptr = (caddr_t)as->output_as;
		q->q_ptr = (caddr_t)as->output_as;

		ATRACE(audio_open, 'Oout', as->output_as);
	}

	/*
	 * Enable queueing on the stream
	 */
	qprocson(q);

	/*
	 * Signal a state change
	 */
	audio_sendsig(as, AUDIO_SENDSIG_ALL);

	/*
	 * NB: It is the caller's responsibility to return a unique
	 * minor number if it was a clone open.  The generic routine
	 * cannot know enough to properly construct the minor number.
	 */

	return (0);
}


/*
 * Close the device.  Be careful to only dismantle the open parts.
 *
 * If the device is open for both play and record, q_ptr will have been
 * set to as->output_as and as->openflag to (FREAD|FWRITE).
 */
/*ARGSUSED*/
int
audio_close(queue_t *q, int flag, cred_t *cred)
{
	aud_stream_t *as;
	aud_stream_t *as_output;
	aud_stream_t *as_input;
	boolean_t writing, reading;

	as = (aud_stream_t *)q->q_ptr;
	ASSERT(as != NULL);

#if 1 /* XXX */
	/* What about draining? */
	qprocsoff(as->readq);
#endif
	LOCK_AS(as);

	as_output = as->output_as;
	ASSERT(as_output != NULL);
	as_input = as->input_as;
	ASSERT(as_input != NULL);

	ATRACE(audio_close, 'CLOS', as);

	reading = ISRECORDSTREAM(as);
	writing = ISPLAYSTREAM(as);

	/*
	 * Stop recording
	 */
	if (reading) {
		ATRACE(audio_close, 'Cinp', as_input);

		AUD_STOP(as_input);
		audio_flush_cmdlist(as_input);

		/* Call the device-dependent close routine */
		AUD_CLOSE(as_input);

		as_input->info.open = B_FALSE;
		as_input->info.pause = B_FALSE;
		as_input->info.error = B_FALSE;
		as_input->info.eof = 0;

		/* Clear the record-side stream info */
		if (reading && writing) {
			as_input->readq = NULL;
			as_input->writeq = NULL;
		}

		as_input->openflag &= ~FREAD;
		if (writing)
			as_output->openflag &= ~FREAD;
		as_input->dioctl.mp = NULL;
	}

	/*
	 * Stop playing
	 */
	if (writing) {
		boolean_t lwpexit;	/* XXX */

		ATRACE(audio_close, 'Cout', as_output);

		/*
		 * If there is any data waiting to be written, then sleep
		 * until it is all gone.  Since any process may
		 * legitimately use the control device to pause output,
		 * this could take a very long time to complete.
		 *
		 * However, if the process was killed we don't want to
		 * continue draining audio output... we want to stop
		 * audio output immediately.  Since we can't distinguish
		 * a normal exit from an abnormal termination, we must
		 * settle for distinguishing exit() from close(),
		 * flushing the output buffer if the process is exiting.
		 *
		 * XXX - Using curthread is promiscuous and
		 * non-DDI-compliant, but it is the only way to implement
		 * this at present.
		 */
#if defined(TP_LWPEXIT) /* XXX - ON493 and beyond */
		lwpexit = (curthread->t_proc_flag & TP_LWPEXIT) ?
		    B_TRUE : B_FALSE;
#else /* XXX - Jupiter and Mars */
		lwpexit = (curthread->t_flag & LWPEXIT) ? B_TRUE : B_FALSE;
#endif
		if (!lwpexit) {
			ATRACE(audio_close, 'Cdrn', as_output);
			as_output->draining = B_TRUE;
			audio_process_output(as_output);
			if (as_output->draining) {
				ATRACE(audio_close, 'drn2', as_output);
				/*
				 * cv_wait_sig releases and re-acquires
				 * the audio_stream lock.
				 *
				 * XXX - There seems to be cases in which
				 * the streamhead caught the signal and
				 * cv_wait_sig does not detect this.
				 *
				 * XXX - The driver should be able to
				 * disable the streamhead 15-sec delay on
				 * slow closes.
				 */
				(void) cv_wait_sig(&as_output->cv,
				    as_output->lock);
			}
			as_output->draining = B_FALSE;
		}

		AUD_STOP(as_output);
		audio_flush_cmdlist(as_output);

		as_output->info.open = B_FALSE;
		as_output->info.pause = B_FALSE;
		as_output->info.error = B_FALSE;
		as_output->info.eof = 0;

		/* Call the device-dependent close routine */
		AUD_CLOSE(as_output);

		as_output->openflag &= ~FWRITE;
		if (reading)
			as_input->openflag &= ~FWRITE;
		as_input->dioctl.mp = NULL;
	}

	/*
	 * This is so control streams can be cleaned up
	 * XXXXXX - check for side effects!
	 */
	if (!reading && !writing) {
		AUD_CLOSE(as);
		as->dioctl.mp = NULL;
	}

	/*
	 * Clear out stream info
	 */
	flushq(as->readq, FLUSHALL);
	flushq(as->writeq, FLUSHALL);
#if 0 /* XXX */
	qprocsoff(as->readq);
#endif
	as->readq->q_ptr = NULL;
	as->writeq->q_ptr = NULL;
	as->readq = NULL;
	as->writeq = NULL;

	/*
	 * If closing play or record, signal the control stream
	 */
	if (reading || writing) {
		/*
		 * if either record or play is now closed
		 * ensure waiting flags get cleared
		 */
		if (!as_input->info.open)
			as_input->info.waiting = B_FALSE;
		if (!as_output->info.open)
			as_output->info.waiting = B_FALSE;
		audio_sendsig(as, AUDIO_SENDSIG_ALL);
		cv_signal(&as->control_as->cv); /* wakeup audio_open */
	}

	/*
	 * If this stream is only a control stream, then cleanup is needed.
	 * Otherwise, the following is redundant.
	 */
	as->info.open = B_FALSE;
	as->openflag = 0;

	UNLOCK_AS(as);

	ATRACE(audio_close, 'Clsd', as);

	return (0);
}


/*
 * Acknowledge an ioctl, given a reusable message block.  If error == 0,
 * ACK; else NAK.  No data can be returned using this interface (use
 * mcopyout()).
 */
void
audio_ack(queue_t *q, mblk_t *mp, int error)
{
	struct iocblk *iocp;
	aud_stream_t *as;

	if (q == NULL) {
		ATRACE(audio_ack, '!q  ', 0);
		return;
	}

	as = (aud_stream_t *)q->q_ptr;
	if (as->dioctl.action == AUDIOCACTION_WAIT) {
		ATRACE(audio_ack, 'wait', as);
		/*
		 * We wanted to delay the ack of this ioctl, but
		 * we haven't entered the final stages of negotiation
		 * yet, so we'll just let the ack happen automatically
		 * at a later time.
		 */
		as->dioctl.action = AUDIOCACTION_INIT;
		as->dioctl.reason = error;
		return;
	}

	if (mp == NULL) {
		ATRACE(audio_ack, '!mp ', as);
		return;
	}

	/* Safety net */
	if (as->dioctl.action == AUDIOCACTION_WAITING && as->dioctl.mp != mp) {
		ATRACE(audio_ack, 'XXX!', as->dioctl.mp);
		ATRACE(audio_ack, 'mp  ', mp);
		cmn_err(CE_WARN, "audio: out-of-order ioctl ack!");
	}

	as->dioctl.mp = NULL;

	iocp = (struct iocblk *)(void *)mp->b_rptr;

	mp->b_wptr = mp->b_rptr + sizeof (struct iocblk);
	if (mp->b_cont != NULL) {
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
	}
	iocp->ioc_count = 0;
	iocp->ioc_error = error;
	iocp->ioc_rval = (error) ? -1 : 0;
	mp->b_datap->db_type = (error) ? M_IOCNAK : M_IOCACK;

	/*
	 * Send it off
	 */
	qreply(q, mp);
	ATRACE(audio_ack, 'ACK ', as);
}

/*
 * This routine is provided only for compatibility with `audioens'; new
 * code should use mcopyout() instead.
 */
void
audio_copyout(queue_t *q, mblk_t *mp, caddr_t addr, uint_t len)
{
	mcopyout(mp, (void *)-1, len, addr, NULL);
	qreply(q, mp);
}

/*
 * In addition to the streamio(4) and filio(4) ioctls, the driver accepts:
 * 	AUDIO_DRAIN	- hang until output is drained
 * 	AUDIO_GETINFO	- get state information
 * 	AUDIO_SETINFO	- set state information
 *
 * Other ioctls may be processed by the device-specific ioctl handler.
 *
 * If the IOCTL is done on the control stream and channel is not
 * specified assume normal play/record stream. If channel is "all" then
 * return status of all streams (need to use streams data xfer
 * messgages?). If channel is specified, then return/affect only that
 * stream.
 *
 * XXX - fix up this definition.
 */
static void
audio_ioctl(aud_stream_t *as, queue_t *q, mblk_t *mp)
{
	aud_state_t *distate;
	struct iocblk *iocp;
	audio_info_t *ip;
	aud_return_t change;
	aud_stream_t *as_input;
	aud_stream_t *as_output;
	long state;
	int cmd;
	int error;

	distate = as->distate;

	iocp = (struct iocblk *)(void *)mp->b_rptr;

	switch (mp->b_datap->db_type) {
	case M_IOCTL:
		/* I_STR ioctls are invalid */
		if (iocp->ioc_count != TRANSPARENT) {
			ATRACE(audio_ioctl, 'xprt', iocp->ioc_cmd);
			as->dioctl.action = AUDIOCACTION_INIT;
			audio_ack(q, mp, EINVAL);
			return;
		}
		cmd = iocp->ioc_cmd;
		state = 0;	/* initial state */
		as->dioctl.action = AUDIOCACTION_INIT;
		as->dioctl.ioctl_id = iocp->ioc_id;
		as->dioctl.credp = iocp->ioc_cr;
		ATRACE(audio_ioctl, 'INIT', cmd);
		break;

	case M_IOCDATA: {
		struct copyresp *csp;

		csp = (struct copyresp *)(void *)mp->b_rptr;

		/*
		 * If copy request failed, quit now
		 */
		if (csp->cp_rval != 0) {
			ATRACE(audio_ioctl, 'rval', csp->cp_rval);
			/*
			 * XXX - This does not appear to "wakeup"
			 * the ioctl.
			 */
			freemsg(mp);
			return;
		}

		cmd = csp->cp_cmd;
		state = (long)csp->cp_private;

		/*
		 * If the state is -1, then all we need is an ACK
		 */
		if (state == -1) {
			switch (as->dioctl.action) {
			case AUDIOCACTION_WAIT:
				as->dioctl.mp = mp;
				as->dioctl.action = AUDIOCACTION_WAITING;
				as->dioctl.reason = 0;
				ATRACE(audio_ioctl, 'wait', cmd);
				return;

			case AUDIOCACTION_WAITING:
				ATRACE(audio_ioctl, 'wtng', cmd);
				cmn_err(CE_WARN,
				    "audio: ioctl out of sequence");
				return;

			default:
				as->dioctl.action = AUDIOCACTION_INIT;
				/* copyout completed */
				audio_ack(q, mp, as->dioctl.reason);
				as->dioctl.mp = NULL;
				ATRACE(audio_ioctl, 'dflt', cmd);
				return;
			}
		}
		ATRACE(audio_ioctl, 'iocd', state);
		break;
	    } /* case M_IOCDATA */

	default:
		cmd = 0;
		state = (long)0;
	} /* switch message type */

	ATRACE(audio_ioctl, 'IOCa', as);
	ATRACE(audio_ioctl, 'IOCc', cmd);

	switch (cmd) {
	case AUDIO_SETINFO: {			/* Set state information */
		uint_t play_eof;
		uchar_t play_err, rec_err;

		switch (state) {
		case 0:		/* initial state */
			mcopyin(mp, *(caddr_t *)mp->b_cont->b_rptr,
			    sizeof (audio_info_t), NULL);
			qreply(q, mp);
			return;

		default:	/* copyin completed state */
			ip = (audio_info_t *)(void *)mp->b_cont->b_rptr;

			as_output = as->output_as;
			as_input = as->input_as;
			error = 0;

			/*
			 * Error indicators and play eof count are updated
			 * atomically so that processes may reset them safely.
			 * Sample counts are also updated like this, but are
			 * handled in the device-specific setinfo routine.
			 */
			LOCK_AS(as);
			play_eof = as_output->info.eof;	/* Save old values */
			play_err = as_output->info.error;
			rec_err = as_input->info.error;
			change = audio_do_setinfo(as, mp, &error);
			ip->play = as_output->info;
			ip->record = as_input->info;
			ip->monitor_gain = distate->monitor_gain;
			ip->output_muted = distate->output_muted;
			if (error == 0 && change == AUDRETURN_DELAYED)
				as->dioctl.action = AUDIOCACTION_WAIT;
			UNLOCK_AS(as);

			if (error != 0) {
				audio_ack(q, mp, error);
				return;
			} else if (change == AUDRETURN_CHANGE) {
				as->dioctl.reason = error;
				audio_sendsig(as, AUDIO_SENDSIG_ALL);
			}

			/*
			 * Restore old values
			 */
			ip->play.eof = play_eof;
			ip->play.error = play_err;
			ip->record.error = rec_err;

			mcopyout(mp, (void *)-1, sizeof (audio_info_t),
			    (void *)state, NULL);
			qreply(q, mp);
			return;

		} /* switch state */
	    } /* case AUDIO_SETINFO */

	case AUDIO_GETINFO: {		/* Get state information */
		caddr_t uaddr;

		switch (state) {
		case 0:		/* initial state */
			/* Get the user buffer address */
			uaddr = *(caddr_t *)(void *)mp->b_cont->b_rptr;

			/* Allocate a buffer for the return info structure */
			freemsg(mp->b_cont);
			mp->b_cont = allocb(sizeof (audio_info_t), BPRI_HI);
			if (mp->b_cont == NULL) {
				audio_ack(q, mp, ENOSR);
				return;
			}

			/* Set pointer to buffer to receive the info struct */
			ip = (audio_info_t *)(void *)mp->b_cont->b_rptr;
			mp->b_cont->b_wptr = mp->b_cont->b_rptr +
			    sizeof (audio_info_t);

			/* Update values not stored in the state struct */
			as_output = as->output_as;
			as_input = as->input_as;

			LOCK_AS(as);
			AUD_GETINFO(as);

			/* Copy current state */
			ip->play = as_output->info;
			ip->record = as_input->info;
			ip->monitor_gain = distate->monitor_gain;
			ip->output_muted = distate->output_muted;
			UNLOCK_AS(as);

			mcopyout(mp, (void *)-1, sizeof (audio_info_t), uaddr,
			    NULL);
			qreply(q, mp);
			return;
		} /* switch state */
	    } /* case AUDIO_GETINFO */
	    break;

	case AUDIO_DRAIN:			/* Drain output */
		/*
		 * AUDIO_DRAIN must be queued to the service procedure,
		 * since there is no user context in which to sleep.  If
		 * the request is not for a play device, return an error.
		 */
		if (!ISPLAYSTREAM(as))
			audio_ack(q, mp, EINVAL);
		else
			(void) putq(q, mp);
		return;			/* don't acknowledge now */

	/* Other ioctls may be handled by the device-specific module */
	default:
		LOCK_AS(as);
		change = AUD_IOCTL(as, q, mp);
		UNLOCK_AS(as);

		if (change == AUDRETURN_CHANGE)
			audio_sendsig(as, AUDIO_SENDSIG_ALL);
	} /* switch on command */
} /* audio_ioctl */


/*
 * Set all modified fields in the AUDIO_SETINFO structure.  Return B_TRUE
 * if no error, with 'as' updated to reflect new values.  Otherwise,
 * returns B_FALSE.
 */
/*ARGSUSED*/
static aud_return_t
audio_do_setinfo(aud_stream_t *as, mblk_t *mp, int *error)
{
	aud_stream_t *as_output;
	aud_stream_t *as_input;
	audio_info_t *ip;
	aud_return_t change;

	as_output = as->output_as;
	as_input = as->input_as;
	ip = (audio_info_t *)(void *)mp->b_cont->b_rptr;

	ATRACE(audio_do_setinfo, 'SETI', as);

	/*
	 * Make sure user structure is reasonable.
	 * Unsigned fields don't need bounds check for < 0
	 */
	if ((Modify(ip->play.gain) && (ip->play.gain > AUDIO_MAX_GAIN)) ||
	    (Modify(ip->record.gain) && (ip->record.gain > AUDIO_MAX_GAIN)) ||
	    (Modify(ip->monitor_gain) && (ip->monitor_gain > AUDIO_MAX_GAIN))) {
		ATRACE(audio_do_setinfo, 'illg', as);
		*error = EINVAL;
		return (AUDRETURN_NOCHANGE); /* if error, return ignored */
	}

	if ((Modifyc(ip->play.balance) &&
	    (ip->play.balance > AUDIO_RIGHT_BALANCE)) ||
	    (Modifyc(ip->record.balance) &&
	    (ip->record.balance > AUDIO_RIGHT_BALANCE))) {
		*error = EINVAL;
		return (AUDRETURN_NOCHANGE);
	}

	if ((Modify(ip->play.channels) &&
	    ((ip->play.channels < AUDIO_MIN_PLAY_CHANNELS) ||
	    (ip->play.channels > AUDIO_MAX_PLAY_CHANNELS))) ||
	    (Modify(ip->record.channels) &&
	    ((ip->record.channels < AUDIO_MIN_REC_CHANNELS) ||
	    (ip->record.channels > AUDIO_MAX_REC_CHANNELS)))) {
		*error = EINVAL;
		return (AUDRETURN_NOCHANGE);
	}

	if ((Modify(ip->play.precision) &&
	    ((ip->play.precision < AUDIO_MIN_PLAY_PRECISION) ||
	    (ip->play.precision > AUDIO_MAX_PLAY_PRECISION))) ||
	    (Modify(ip->record.precision) &&
	    ((ip->record.precision < AUDIO_MIN_REC_PRECISION) ||
	    (ip->record.precision > AUDIO_MAX_REC_PRECISION)))) {
		*error = EINVAL;
		return (AUDRETURN_NOCHANGE);
	}

	/*
	 * Validate and set device-specific values
	 */
	change = AUD_SETINFO(as, mp, error);
	if (*error != 0)
		return (change);

	/*
	 * The following parameters are zeroed on close() of the i/o
	 * device.  Attempts to change them are silently ignored if it is
	 * closed.  Applications should check the info struct returned by
	 * AUDIO_SETINFO to determine whether they succeeded.
	 */
	if (as_output->info.open) {
		if (Modifyc(ip->play.pause)) {
			if (ip->play.pause)
				audio_pause_play(as_output);
			else
				audio_resume_play(as_output);
		}

		if (Modify(ip->play.eof))
			as_output->info.eof = ip->play.eof;

		if (Modifyc(ip->play.error))
			as_output->info.error = (ip->play.error != 0);

		/* The waiting flags may only be set.  close() clears them. */
		if (Modifyc(ip->play.waiting) && ip->play.waiting)
			as_output->info.waiting = B_TRUE;

		/*
		 * Get active flag again, since pause/resume may have
		 * changed them.  If we called the getinfo routine here,
		 * then the sample count would get overwritten as well.
		 */
		as_output->info.active = AUD_GETFLAG(as_output, AUD_ACTIVE);
		ATRACE(audio_do_setinfo, 'outp', as_output->info.active);
	}

	if (as_input->info.open) {
		if (Modifyc(ip->record.pause)) {
			if (ip->record.pause)
				audio_pause_record(as_input);
			else
				audio_resume_record(as_input);
		}

		if (Modifyc(ip->record.error))
			as_input->info.error = (ip->record.error != 0);

		if (Modifyc(ip->record.waiting) && ip->record.waiting)
			as_input->info.waiting = B_TRUE;

		/* Get active flag again */
		as_input->info.active = AUD_GETFLAG(as_input, AUD_ACTIVE);
		ATRACE(audio_do_setinfo, 'inp ', as_input->info.active);
	}

	return (change);
}


/*
 * audio_wput - Stream write queue put procedure.  All messages from
 * above arrive first in this routine.  All control device messages
 * should be handled or dismissed here.
 */
int
audio_wput(queue_t *q, mblk_t *mp)
{
	aud_stream_t *as;
	aud_return_t change;

	ASSERT(q != NULL);
	ASSERT(mp != NULL);

	as = (aud_stream_t *)q->q_ptr;

	ASSERT(as != NULL);
	ATRACE(audio_wput, 'WPUT', as);

	switch (mp->b_datap->db_type) {
	case M_PROTO:		/* inline control messages */
		/*
		 * If the M_PROTO message came down a control stream,
		 * process it now.
		 */
		if (as == as->control_as) {
			change = AUD_MPROTO(as, mp);
			if (change == AUDRETURN_CHANGE)
				audio_sendsig(as, AUDIO_SENDSIG_ALL);
			break;
		}

		if (!ISDATASTREAM(as)) {
			freemsg(mp);
			break;
		}

		/*
		 * An incoming M_PROTO message will only be delivered
		 * on a RW or RO STREAM.
		 */
		/*FALLTHROUGH*/

	case M_DATA:		/* regular data */
		/*
		 * Only queue data on output stream
		 */
		if (ISPLAYSTREAM(as)) {
			/*
			 * If audio_process_output() has previously
			 * executed, as it would have during open(), then
			 * it may have found an empty queue (getq()).  If
			 * the queue was previously found empty, then
			 * getq() will have set QWANTR in the queue_t and
			 * this call to putq() will schedule the write
			 * service procedure, audio_wsrv(). Therefore,
			 * there is no need for this routine to directly
			 * call audio_process_output().
			 *
			 * XXX - Correct?
			 */
			(void) putq(q, mp);
			qenable(q);	/* XXX - Need this? */
			ATRACE(audio_wput, 'PUTQ', mp);
		} else {
			freemsg(mp);	/* No data on ctl or record streams */
			ATRACE(audio_wput, 'FMSG', mp);
		}
		break;

	case M_IOCTL:		/* ioctl */
	case M_IOCDATA:
		/*
		 * Most ioctls take effect immediately.  audio_ioctl()
		 * queues AUDIO_DRAIN to the service procedure.
		 */
		audio_ioctl(as, q, mp);
		break;

	case M_FLUSH:		/* flush queues */
		/*
		 * Any stream can flush its queues.  We must be careful
		 * to flush the device command list only when flushing
		 * the relevant queue.
		 */
		ATRACE(audio_wput, 'FLSH', *mp->b_rptr);
		if (*mp->b_rptr & FLUSHW) {
			*mp->b_rptr &= ~FLUSHW;
			flushq(q, FLUSHDATA);
			if (ISPLAYSTREAM(as)) {
				LOCK_AS(as);
				AUD_STOP(as->output_as);
				audio_flush_cmdlist(as->output_as);
				UNLOCK_AS(as);
				qenable(q); /* schedule audio_wsrv() */
			}
		}
		if (*mp->b_rptr & FLUSHR) {
			/*
			 * Don't bother flushing the record buffers if
			 * this is not the record device or recording is
			 * already paused (buffers are flushed when
			 * pausing record).
			 */
			LOCK_AS(as);
			if (ISRECORDSTREAM(as) && !as->info.pause) {
				AUD_STOP(as->input_as);
				audio_flush_cmdlist(as->input_as);
			}
			UNLOCK_AS(as);
			flushq(RD(q), FLUSHDATA);
			qreply(q, mp);
			qenable(RD(q));	/* schedule audio_rsrv() */
		} else {
			freemsg(mp);
		}
		break;

	default:
		ATRACE(audio_wput, 'UNKN', mp->b_datap->db_type);
		freemsg(mp);
		break;
	}

	return (0);
}


/*
 * Write service procedure can find the following on its queue:
 *	data messages queued for writing
 *	AUDIO_DRAIN ioctl messages
 * Only messages for the audio i/o stream should be found on the queue.
 */
int
audio_wsrv(queue_t *q)
{
	aud_stream_t *as;

	ASSERT(q != NULL);
	ASSERT(q->q_ptr != NULL);

	as = (aud_stream_t *)q->q_ptr;

	ATRACE(audio_wsrv, '  AS', as);

	ASSERT(as != NULL);

	LOCK_AS(as);
	audio_process_output(as->output_as);
	UNLOCK_AS(as);

	return (0);
}


/*
 * audio_gc_output_internal - Garbage collect used output buffers.
 *
 * Returns B_TRUE if application needs to be signaled.
 */
static int
audio_gc_output_internal(aud_stream_t *as)
{
	mblk_t *mp;
	aud_cmd_t *cmdp;
	aud_cmd_t *headp;
	aud_cmd_t *lastp;
	int notify;

	notify = B_FALSE;

	ATRACE(audio_gc_output_internal, '  AS', as);

	/*
	 * Insure that beyond first processed cmd lies a valid done
	 * command.
	 *
	 * NB - Remember error case where entire list is NULLED out
	 * cmdptr == NULL and so is cmdlast. (pas)
	 */
	for (cmdp = as->cmdlist.head; cmdp != NULL; cmdp = as->cmdlist.head) {

		/* Don't look at cmd's still owned by the device */
		if (!cmdp->done)
			break;

		/*
		 * Headp points to the first cmd on the list that can
		 * be deleted.
		 *
		 * It may be that the head of the list has been previously
		 * processed and commands completed since then allow for the
		 * head to be removed (ouch!).
		 *
		 * Everything from headp to lastp will be removed from the
		 * list.
		 */
		headp = cmdp;

		if (cmdp->processed) {
			/*
			 * If the command has been processed here already,
			 * it still cannot be reclaimed if it is the last
			 * done command in the transmit chain.
			 */
			if ((cmdp->next == NULL) || !cmdp->next->done)
				break;

			cmdp = cmdp->next;
			ASSERT(cmdp != NULL);

			/*
			 * Headp is left pointing at the "processed"
			 * command while cmdp has advanced to the next command.
			 */
		}

		ASSERT(cmdp->processed == 0);
		ASSERT(cmdp->lastfragment != NULL);

		lastp = cmdp->lastfragment;

		/*
		 * Check if the last command of the packet is done and do
		 * nothing if it is still uncompleted.
		 */
		if (!lastp->done)
			break;

		mp = (mblk_t *)lastp->dihandle;
		ATRACE(audio_gc_output_internal, '  mp', mp);

		switch (cmdp->iotype) {
		case M_IOCTL:
			/*
			 * ACK the AUDIO_DRAIN ioctl
			 */
			ATRACE(audio_gc_output_internal, 'ictl', cmdp);
			audio_ack(as->writeq, mp, 0);
			lastp->dihandle = NULL;

			/* ignore error after drain */
			(void) AUD_GETFLAG(as, AUD_ERRORRESET);

			/*
			 * Do not delete device's "continuation" command.
			 */
			headp = cmdp;

			/* Delete everything from headp to lastp */
			break;

		case (uchar_t)(0xff): /* XXX - Pseudo IO, Audio Marker */
			ATRACE(audio_gc_output_internal, 'psio', cmdp);

			if (mp != NULL) {
				freemsg(mp);
				mp = NULL;
				lastp->dihandle = NULL;
			}

			headp = cmdp;	/* Device's cmd will remain */

			if (as->mode == AUDMODE_AUDIO) {
				ATRACE(audio_gc_output_internal, 'eof!', as);
				as->info.eof++;
				notify = B_TRUE;

				/* ignore error after eof */
				(void) AUD_GETFLAG(as, AUD_ERRORRESET);
			}
			break;

		case M_PROTO:
			ATRACE(audio_gc_output_internal, 'mpro', cmdp);
			if (AUD_MPROTO(as, mp) == AUDRETURN_CHANGE)
				notify = B_TRUE;
			cmdp->dihandle = NULL;
			break;

		case M_DATA:
			ATRACE(audio_gc_output_internal, 'data', cmdp);
			/*
			 * The current aud_cmd has been completely transmitted
			 * or otherwise processed. Therefore, it is ok to free
			 * the mblk.
			 */
			if (mp != NULL) {
				if (as->traceq != NULL)
					audio_trace(as, lastp);
				freemsg(mp);
				mp = NULL;
				lastp->dihandle = NULL;
			}

			if (cmdp->skip) {
				/*
				 * XXX - We will probably have to
				 * differentiate between "skip" which is
				 * never seen by the device, and some new
				 * flag, "error", which is on the device
				 * IO list.
				 */
				/*
				 * There was a transmission error, and
				 * the packet was marked as "skip" as
				 * part of discarding it. Transmission
				 * errors include trying to transmit on
				 * an inactive channel.
				 *
				 * XXX - check for other types of errors,
				 * does this code still work?
				 */
				headp = cmdp;	/* Device's cmd will remain */

				/* Delete this entire aud_cmd */
				break;
			}

			/*
			 * aud_cmd contained real data.
			 */

			/*
			 * If the packet was owned by the device, then it
			 * may be important for the device specific code
			 * to retain partial "ownership" of the last
			 * command so that it can pick up the forward
			 * pointer if it is told simply to "continue IO".
			 *
			 * If the packet following the current packet is
			 * also marked as "done", then the current packet
			 * can be completely garbage collected,
			 * otherwise, the last fragment of the current
			 * packet must remain on the list.
			 */

			if (lastp->next != NULL &&
			    lastp->next->done &&
			    !lastp->next->skip) {
				/*EMPTY*/
				/*
				 * This packet, and the possible
				 * preceeding "processed" command, can be
				 * completely gc'ed, which is what headp
				 * and lastp currently indicate.
				 *
				 * XXX - Packets marked skip MAY be on
				 * the device IO list!
				 */
				ATRACE(audio_gc_output_internal, ' all', mp);
			} else if (cmdp == lastp) {
				/*
				 * This packet consists of one fragment
				 * and there is no completed packet after
				 * it.  It must remain on the chain.
				 */
				cmdp->processed = B_TRUE;

				/*
				 * If there was a previously "processed"
				 * packet at the head of the list, it can
				 * now be removed.
				 */
				if (headp != cmdp) {
					lastp = headp->lastfragment;
				} else {
					ATRACE(audio_gc_output_internal,
					    'nada', cmdp);
					lastp = headp = NULL;
				}
			} else {
				aud_cmd_t *p;

				/*
				 * This is a multi-fragment packet where
				 * all but the last fragment can be
				 * collected.
				 *
				 * Set lastp to the penultimate fragment.
				 */
				for (p = cmdp; p != p->lastfragment;
				    p = p->next) {
					lastp = p;
				}

				ASSERT(lastp != NULL);
				cmdp->lastfragment->processed = B_TRUE;
				ATRACE(audio_gc_output_internal, 'pcsd',
				    cmdp->lastfragment);
			}

			break;

		default:
			ATRACE(audio_gc_output_internal, 'unkn', cmdp);
			if (mp != NULL) {
				freemsg(mp);
				cmdp->dihandle = NULL;
			}
			break;
		} /* switch on packet type */

		/*
		 * Delete cmd struct from play list and add to free list
		 */
		if (lastp != NULL) {
			aud_cmd_t *p;

			ASSERT(headp != NULL);

			/*
			 * Be tidy...
			 */
			for (p = headp; p != NULL; p = p->next) {
				ASSERT(p->dihandle == NULL);
				p->lastfragment = NULL;
				p->iotype = 0;

				if (p == lastp)
					break;
			}

			audio_delete_cmds(&as->cmdlist, headp, lastp);
		}
	} /* for each packet on the command list */

	return (notify);
}


/*
 * audio_gc_output - perform only the garbage collection phase
 * of output processing
 */
void
audio_gc_output(aud_stream_t *as)
{
	ASSERT(as == as->output_as);

	ASSERT_ASLOCKED(as);

	if (audio_gc_output_internal(as))
		audio_sendsig(as, AUDIO_SENDSIG_ALL);
}


/*
 * audio_process_output - Deliver new play buffers to the interrupt routine
 * and clean up used buffers.
 */
void
audio_process_output(aud_stream_t *as)
{
	mblk_t *mp;
	aud_cmd_t *cmdp;
	aud_cmd_t *head_cmdp;
	int notify;
	uchar_t iotype;

	ASSERT(as == as->output_as);

	ASSERT_ASLOCKED(as);

	/* If no write access, don't even bother trying */
	if (!ISPLAYSTREAM(as))
		return;

	/*
	 * Garbage collect recently emptied output buffers.
	 */
	notify = audio_gc_output_internal(as);

restart:
	/*
	 * Dequeue messages as long as there are command blocks available.
	 */
#if defined(AUDIOTRACE)
	if (as->cmdlist.free == NULL) {
		ATRACE(audio_process_output, 'full', as);
	}
#endif
	mp = NULL;
	while ((as->cmdlist.free != NULL) &&
	    ((mp = getq(as->writeq)) != NULL)) {
		mblk_t	*head_mp;

		head_mp = mp;
		head_cmdp = NULL;
		cmdp = NULL;
		iotype = mp->b_datap->db_type;

		/*
		 * Attach each element of a mblk chain to a command structure.
		 */
		do {
			/*
			 * Allocate and initialize a command block
			 */

			/*
			 * It is assumed that an mblk_t and all of its
			 * continuation blocks are of the same type.
			 * The processing of M_DATA messages depends on
			 * this assumption.
			 */
			ASSERT(iotype == mp->b_datap->db_type);

			/*
			 * Do not allocate command blocks for null fragments
			 * in M_DATA messages.
			 */
			if ((iotype == M_DATA) &&
			    (mp->b_rptr == mp->b_wptr)) {
				ATRACE(audio_process_output, 'Zlen', mp);
				mp = mp->b_cont;
				continue;
			}

			/*
			 * If any data block is larger than what the device
			 * says it can handle, drop it.
			 */
			if ((iotype == M_DATA) &&
			    (mp->b_wptr - mp->b_rptr > as->maxfrag_size)) {
				if (head_cmdp != NULL) {
					audio_delete_cmds(&as->cmdlist,
					    head_cmdp, cmdp);
				}
				freemsg(head_mp);

				ATRACE(audio_process_output, '2BIG', mp);
				goto restart;
			}

			/*
			 * cmdp gets the next free aud_cmd_t from the
			 * free list
			 */
			audio_alloc_cmd(&as->cmdlist, cmdp);

			if (head_cmdp == NULL)
				head_cmdp = cmdp;

			/*
			 * Initialize aud_cmd defaults
			 */
			cmdp->data = NULL;
			cmdp->enddata = NULL;
			cmdp->next = NULL;
			cmdp->lastfragment = NULL;
			cmdp->iotype = iotype;
			cmdp->skip = B_FALSE;
			cmdp->done = B_FALSE;
			cmdp->processed = B_FALSE;
			cmdp->dihandle = NULL;
			cmdp->tracehdr.seq = 0;

			/*
			 * AUDIO_DRAIN M_IOCTL, 0 length M_DATA messages
			 * (EOF), and M_CTL messages go through the
			 * command path for synchronization but do not
			 * get played.
			 */
			if (iotype != M_DATA) {
				cmdp->skip = B_TRUE;
				cmdp->dihandle = (void *)mp;
			} else {
				/*
				 * Non-null M_DATA fragment.
				 *
				 * Empty M_DATA fragments have already
				 * been filtered out.
				 */
				cmdp->skip = B_FALSE;
				cmdp->data = mp->b_rptr;
				cmdp->enddata = mp->b_wptr;
			}

			/*
			 * NB: although the "driver" list is being appended
			 * here, the "device" list is not being affected.
			 * Even if the device is currently running, it is not
			 * allowed to "notice" these new aud_cmd's until
			 * the AUD_QUEUE() primitive is executed.
			 */
			audio_append_cmd(&as->cmdlist, cmdp);

			/*
			 * Since the device routine doesn't
			 * really process non-M_DATA messages,
			 * it is not important to allocate a
			 * separate aud_cmd for each one.
			 */
			if (iotype != M_DATA) {
				/* Exit loop successfully */
				mp = NULL;
			} else {
				/* Advance to next mblk on chain */
				mp = mp->b_cont;
			}

			/*
			 * Stop when there are no more mblk fragments
			 * or when there are no free aud_cmd_t's left.
			 */
		} while ((mp != NULL) && (as->cmdlist.free != NULL));

		/*
		 * If non-zero, head_cmdp points to the start of the first
		 * aud_cmd representing the first M_DATA fragment that has
		 * some data in it, or, if not an M_DATA message, the first
		 * fragment of the mblk.
		 *
		 * If head_cmdp is zero, it is because the message was a zero
		 * length M_DATA message. If we are here, there was at least
		 * one aud_cmd structure on the free list.
		 *
		 * If non-zero, cmdp points to the last aud_cmd used to
		 * represent the mblk.
		 */
		if (head_cmdp == NULL) {
			ATRACE(audio_process_output, 'oEOF', cmdp);

			/*
			 * Zero length M_DATA is used as an "Audio Marker".
			 * It is queued the same as a non-data message.
			 */
			audio_alloc_cmd(&as->cmdlist, cmdp);

			/*
			 * The encompassing while loop condition ensures that
			 * there is at least one aud_cmd structure available.
			 */
			ASSERT(cmdp != NULL);

			cmdp->iotype = (uchar_t)(0xff); /* XXX */;
			cmdp->data = NULL;
			cmdp->enddata = NULL;
			cmdp->next = NULL;
			cmdp->lastfragment = NULL; /* set later */
			cmdp->skip = B_TRUE;
			cmdp->done = B_FALSE;
			cmdp->processed	= B_FALSE;
			cmdp->dihandle = NULL;	/* later set to head_mp */

			head_cmdp = cmdp;
			audio_append_cmd(&as->cmdlist, cmdp);

			/*
			 * XXX - It would be nice to freemsg(mp) now, but
			 * other code uses the db_type field.
			 */
		} else if (mp != NULL) {
			ATRACE(audio_process_output, 'oOUT', mp);

			/*
			 * If mp is not null, it is because we ran out of
			 * aud_cmd structures. Release any aud_cmd's that
			 * may have been used and put the mblk back on
			 * the queue.
			 */

			/*
			 * Release mblk and command chains at the tail of
			 * the list.
			 */
			audio_delete_cmds(&as->cmdlist, head_cmdp, cmdp);

			/*
			 * Unless we do something, this packet will block
			 * the output stream forever.  If there is
			 * nothing else to do, concatenate the parts of
			 * this message.
			 */
			if ((as->cmdlist.head == NULL) ||
			    ((as->cmdlist.head->processed) &&
			    (as->cmdlist.head->done) &&
			    (as->cmdlist.head->next == NULL))) {
				mblk_t *nmp = NULL;

				/*
				 * Ensure that there will not be a single
				 * fragment larger than the max fragment
				 * size.
				 */
#if 1 /* XXX - Broken pullupmsg in Mars */
				/*
				 * For now, assume that we have an MTU of
				 * maxfrag_size and drop anything larger.
				 */
				if (head_mp != NULL &&
				    msgdsize(head_mp) > as->maxfrag_size) {
					freemsg(head_mp);
					head_mp = NULL;
				}
#else
				while ((nmp != NULL) &&
				    (msgdsize(nmp) > as->maxfrag_size)) {
					if (pullupmsg(nmp,
					    as->maxfrag_size) == 1) {
						ATRACE(audio_process_output,
						    'pull', nmp);
						nmp = nmp->b_cont;
					} else {
						ATRACE(audio_process_output,
						    '!pll', nmp);
						freemsg(head_mp);
						head_mp = NULL;
						nmp = NULL;
					}
				}
#endif

#if 1 /* XXX - Broken pullupmsg in Mars */
				/*
				 * The remaining fragments are smaller
				 * than the max fragment size, so pull
				 * them all together.
				 */
				if (head_mp != NULL) {
					nmp = msgpullup(head_mp, -1);
					freemsg(head_mp);
					head_mp = NULL;
					if (nmp != NULL) {
						ATRACE(audio_process_output,
						    'pull', nmp);
						head_mp = nmp;
						(void) putbq(as->writeq,
						    head_mp);
					} else {
						/*EMPTY*/
						ATRACE(audio_process_output,
						    '!pll', nmp);
					}
				}
#else
				/*
				 * The remaining fragments are smaller
				 * than the max fragment size, so pull
				 * them all together.
				 */
				if (nmp != NULL) {
					if (pullupmsg(nmp, -1) == 1) {
						ATRACE(audio_process_output,
						    'pull', nmp);
						(void) putbq(as->writeq,
						    head_mp);
					} else {
						ATRACE(audio_process_output,
						    '!pll', nmp);
						freemsg(head_mp);
						head_mp = NULL;
					}
				}
#endif

				/*
				 * If we were able to massage it, then try
				 * to process it again.
				 */
				if (head_mp != NULL)
					goto restart;

				/*
				 * Looks like we have to drop it.
				 */
				break;

			} else {
				(void) putbq(as->writeq, head_mp);
			}

			/*
			 * We won't get desperate until there is
			 * positively no may to get more resources.  If
			 * we're here, then there are still resources
			 * available that will be freed when more output
			 * is processed.
			 */
			break; /* out of while loop queuing commands */
		}

		/*
		 * Cmdp still points to the last fragment in the chain.
		 * Set the lastfragment pointer in each aud_cmd to point
		 * to the last fragment to simplify future processing.
		 */
		{
			aud_cmd_t *p;

			for (p = head_cmdp; p != NULL; p = p->next)
				p->lastfragment = cmdp;
		}

		ASSERT(head_cmdp->lastfragment != NULL);
		ASSERT(head_cmdp->lastfragment->lastfragment != NULL);

		/*
		 * The last fragment gets the pointer to the mblk.
		 */
		head_cmdp->lastfragment->dihandle = (void *)head_mp;
		head_cmdp->lastfragment->tracehdr.seq = as->sequence++;

		/*
		 * Make the device aware of the new output tasks
		 */
		AUD_QUEUECMD(as, head_cmdp);
	} /* while there are audio commands and more STREAMS messages */
	ATRACE(audio_process_output, 'DONE', cmdp);

	/*
	 * The device-dependent portion of the driver is responsible for
	 * completing pseudo-IO.  It must mark the pseudo-IO as "done"
	 * and then call audio_gc_output_internal().
	 */

	/*
	 * If no messages left, and no data in write buffers, wake up
	 * audio_close() if necessary.  Ignore errors if draining.
	 *
	 * XXX - The test for "empty list" is ugly due to the "processed"
	 * fragment that may be at the end of the list.
	 */
	if (as->draining && (mp == NULL) &&
	    ((as->cmdlist.head == NULL) ||
	    (as->cmdlist.head == as->cmdlist.tail &&
	    as->cmdlist.head->processed))) {
		as->draining = B_FALSE;
		cv_signal(&as->output_as->cv);
	} else if (AUD_GETFLAG(as, AUD_ERRORRESET)) {
		/* Only signal when this flag is set for the first time */
		if (!as->info.error) {
			as->info.error = B_TRUE;
			notify = B_TRUE;
		}
	}

	/*
	 * If a state change occurred, send a signal to the control device
	 */
	if (notify)
		audio_sendsig(as, AUDIO_SENDSIG_ALL);
} /* audio_process_output */


/*
 * audio_rput- Since putnext() is a macro, it is convenient to have this
 * simple read put procedure to keep from having to dequeue packets in
 * the service procedure.
 */
/*ARGSUSED*/
int
audio_rput(queue_t *q, mblk_t *mp)
{
	cmn_err(CE_PANIC, "audio: audio_rput called!");
	return (0); /*NOTREACHED*/
}


/*
 * audio_rsrc - The read service procedure is scheduled when the upstream
 * read queue is flushed, to make sure that further record buffers are
 * processed.
 *
 * It can also be scheduled if the driver is flow controlled by
 * (canput() == 0)
 */
int
audio_rsrv(queue_t *q)
{
	aud_stream_t *as = (aud_stream_t *)q->q_ptr;

	ASSERT(as != NULL);
	ATRACE(audio_rsrv, '  AS', as);

	LOCK_AS(as);
	audio_process_input(as->input_as);
	UNLOCK_AS(as);

	return (0);
}


/*
 * audio_gc_input - Collect completed input buffers. Also garbage collect
 * unused input buffers when IO has been stopped.  Return 1 if read side
 * was flow controlled.
 */
static int
audio_gc_input(aud_stream_t *as)
{
	mblk_t *mp;
	struct {
		aud_cmd_t *head;
		aud_cmd_t *tail;
	} packet;
	aud_cmd_t *cmdp;
	boolean_t flow_control;

	for (cmdp = as->cmdlist.head;
	    cmdp != NULL && cmdp->done;
	    cmdp = as->cmdlist.head) {

		packet.head = NULL;
		do {
			mp = (mblk_t *)cmdp->dihandle;	/* get buffer ptr */
			ASSERT(mp != NULL);

			/*
			 * Empty fragments should not hurt anyone.
			 * Packet.head gets set to 1st non-empty
			 * fragment.
			 */
			if (cmdp->skip) {
				ATRACE(audio_gc_input, 'FREE', mp);
				freemsg(mp);
				/* XXX - TIDY this up */
				cmdp->dihandle = NULL;
				cmdp->data = NULL;
				cmdp->enddata = NULL;
				mp = NULL;

				/*
				 * XXX - If this is going to remain a
				 * subroutine, it should return both
				 * "notify" and "flow_control".
				 */
				audio_sendsig(as, AUDIO_SENDSIG_ALL);
			} else {
				/* Set STREAMS end of data */
				mp->b_wptr = cmdp->data;

				ATRACE(audio_gc_input, 'frag', mp->b_wptr -
				    mp->b_rptr);

				/*
				 * If start of packet not set yet, this
				 * must be it.  Don't chain the 1st
				 * fragment to the "previous".
				 */
				if (packet.head == NULL)  {
					packet.head = cmdp;
				} else {
					mblk_t	*tmp;

					/* Chain up current mblk to list */
					tmp = (mblk_t *)packet.tail->dihandle;
					tmp->b_cont = mp;
				}
			}
			packet.tail = cmdp;

			if (cmdp == cmdp->lastfragment)
				break;
		} while ((cmdp = cmdp->next) != NULL);

		if (packet.head) {
			/*
			 * Collect new received packets on driver's readq
			 * for this aud_stream.
			 */
			packet.head->tracehdr.seq = as->sequence++;
			if (as->traceq != NULL)
				audio_trace(as, packet.head);

			mp = (mblk_t *)packet.head->dihandle;
			(void) putq(as->readq, mp);
			ATRACE(audio_gc_input, 'PUTQ', mp);
		}

		/*
		 * XXX - As soon as we start using DBRI's CDP command for
		 * the receive side, we will need logic similar to that
		 * in audio_gc_output_internal() in order to maintain
		 * an end-of-list command structure for the benefit of
		 * the device.
		 */
		audio_delete_cmds(&as->cmdlist, as->cmdlist.head, packet.tail);
	} /* for each completed audio command */
	ATRACE(audio_gc_input, 'DONE', cmdp);

	flow_control = B_FALSE;

	ASSERT(as->readq->q_flag & QREADR);

	while ((mp = getq(as->readq)) != NULL) {
		if (mp->b_datap->db_type <= QPCTL &&
		    !canput(as->readq->q_next)) {
			ATRACE(audio_gc_input, 'flow', as->readq->q_next);
			(void) putbq(as->readq, mp); /* read side is blocked */
			flow_control = B_TRUE;
			break;
		}

		/*
		 * Flow control is ok. Send received packet to upper
		 * module.  Don't send zero-length messages to the stream
		 * head.
		 */
		if (mp->b_wptr - mp->b_rptr == 0) {
			ATRACE(audio_gc_output, 'free', mp);
			freemsg(mp);
		} else {
			ATRACE(audio_gc_input, 'putn', mp);
			putnext(as->readq, mp);
		}
	}

	return (flow_control);
}


/*
 * audio_process_input - Send record buffers upstream, if ready.  If
 * recording is not paused, make sure record buffers are allocated.
 */
void
audio_process_input(aud_stream_t *as)
{
	mblk_t *mp;
	aud_cmd_t *cmdp;
	aud_cmd_t *headp;
	boolean_t flow_control;

	ASSERT(as != NULL);
	ASSERT(as == as->input_as); /* XXX - ensure strict compliance */

	/* If no read access, don't bother even trying */
	if (!ISRECORDSTREAM(as))
		return;

	ASSERT_ASLOCKED(as);

	/*
	 * Collect finished record buffers and send upstream.  If
	 * recording was paused, all buffers were marked done, even if
	 * they were unused. The same goes for error condition.
	 *
	 * Note: We need to chain up potentially multiple mblks for
	 * datacomm.
	 */

	flow_control = audio_gc_input(as);
#if defined(AUDIOTRACE)
	if (flow_control) {
		ATRACE(audio_process_input, '-fc-', as);
	} else {
		ATRACE(audio_process_input, '-ok-', as);
	}
#endif

	headp = NULL;
	/*
	 * If paused or upstream flow control hit high water, don't
	 * allocate new record buffers.
	 */
	if (!as->info.pause && !flow_control) {
		/*
		 * As long as there are free command blocks, allocate new
		 * buffers for recording.
		 */
		mp = NULL;
		while ((as->cmdlist.free != NULL) &&
		    ((mp = allocb(as->info.buffer_size, BPRI_MED)) != NULL)) {

			/*
			 * Allocate and initialize a command block
			 */
			audio_alloc_cmd(&as->cmdlist, cmdp);
			if (headp == NULL)
				headp = cmdp;
			cmdp->data = mp->b_rptr = mp->b_wptr;
			cmdp->enddata = cmdp->data + as->info.buffer_size;
			cmdp->dihandle = (void *)mp;

			/* iotype not used for receive */
			cmdp->iotype = M_DATA;
			cmdp->lastfragment = cmdp; /* not known yet */
			cmdp->done = B_FALSE;
			cmdp->skip = B_FALSE;
			cmdp->processed = B_FALSE;
			cmdp->tracehdr.seq = 0;

			/*
			 * Add it to the cmd chain
			 */
			audio_append_cmd(&as->cmdlist, cmdp);
			ATRACE(audio_process_input, 'NEWR', mp);
		}

#if defined(AUDIOTRACE)
		/*
		 * We'll want to know if we ran out of STREAMS buffers
		 */
		if ((mp == NULL) && (as->cmdlist.free != NULL)) {
			ATRACE(audio_process_input, 'NOMP', 0);
		}
#endif

		/*
		 * Queue up dbri cmd after available free cmds are
		 * chained up and send to device if we have allocated new
		 * command blocks.
		 */
		if (headp != NULL) {
			AUD_QUEUECMD(as, headp);
		}
	}

	/*
	 * If record overflow occurred, send a signal to the control
	 * device.  Only signal when this flag is set for the first time.
	 */
	if (AUD_GETFLAG(as, AUD_ERRORRESET) && !as->info.error) {
		as->info.error = B_TRUE;
		audio_sendsig(as, AUDIO_SENDSIG_ALL);
	}
} /* audio_process_input */


/*
 * Send a SIGPOLL up the specified stream.
 *
 * NB: as always points to the write-side aud_stream
 * NB: sometimes called with XXX lock help
 */
void
audio_sendsig(aud_stream_t *as, audio_sendsig_t which)
{
	mblk_t *mp;
	aud_stream_t *all[3]; /* DIC */
	int i;

	all[0] = all[1] = all[2] = NULL;

	if (as == NULL)
		return;

	switch (which) {
	case AUDIO_SENDSIG_ALL:
		all[0] = as->control_as;
		if (as->input_as->mode == AUDMODE_AUDIO)
			all[1] = as->input_as;
		if (as->output_as->mode == AUDMODE_AUDIO)
			all[2] = as->output_as;
		break;

	case AUDIO_SENDSIG_EXPLICIT:
		all[0] = as;
		break;

	default:
		return;
	}

	/*
	 * Filter out duplicate queues
	 */
	if (all[2] != NULL && all[1] != NULL && all[2]->readq == all[1]->readq)
		all[2] = NULL;
	if (all[2] != NULL && all[0] != NULL && all[2]->readq == all[0]->readq)
		all[2] = NULL;
	if (all[1] != NULL && all[0] != NULL && all[1]->readq == all[0]->readq)
		all[1] = NULL;

	/*
	 * Initialize a message to send a SIGPOLL upstream
	 * Just allocate one and deallocate it before we
	 * leave this routine.  For each message we send
	 * upstream we simply duplicate our prototype message.
	 */
	if ((mp = allocb(sizeof (char), BPRI_HI)) == NULL) {
		ATRACE(audio_sendsig, '!blk', 0);
		return;
	}

	mp->b_datap->db_type = M_PCSIG;
	*mp->b_wptr++ = SIGPOLL;

	for (i = 0; i < 3; i++) {
		mblk_t *dmp;

		if (all[i] == NULL)
			continue;

		/*
		 * If stream is not open, simply return
		 */
		if (all[i]->readq == NULL)
			continue;

		if (!all[i]->signals_okay)
			continue;

		dmp = dupb(mp);
		if (dmp == NULL) {
			ATRACE(audio_sendsig, '!NTF', all[i]);
			continue;
		}

		/*
		 * Signal the specified stream
		 */
		putnext(all[i]->readq, dmp);
		ATRACE(audio_sendsig, 'NTFY', all[i]);
	}

	freemsg(mp);
} /* audio_sendsig */


/*
 * The next two routines are used to pause reads or writes.  Pause is
 * used to temporarily suspend i/o without losing the contents of the
 * buffer.
 */
void
audio_pause_record(aud_stream_t *as)
{
	aud_cmd_t *cmdp;

	ASSERT(as == as->input_as);

	if (!ISRECORDSTREAM(as) || (as->mode != AUDMODE_AUDIO))
		return;

	ASSERT_ASLOCKED(as);
	ATRACE(audio_pause_record, 'PAUZ', as);

	as->info.pause = B_TRUE;
	AUD_STOP(as);

	/*
	 * When recording is paused, partially filled buffers are sent
	 * upstream and unused buffers are released.  Mark all command
	 * buffers done and let audio_process_input() handle them.
	 *
	 * XXX - There could be a problem here as packets have multiple
	 * cmds.
	 */
	for (cmdp = as->cmdlist.head; cmdp != NULL; cmdp = cmdp->next)
		cmdp->done = B_TRUE;

	/*
	 * Flush the device's chained command list
	 */
	AUD_FLUSHCMD(as);

	/*
	 * Process partially filled buffer and release the rest
	 */
	audio_process_input(as);
}


void
audio_pause_play(aud_stream_t *as)
{
	ASSERT_ASLOCKED(as);
	ATRACE(audio_pause_play, 'PAUZ', as);
	ASSERT(as == as->output_as);

	if (as != as->output_as)
		return;


	if (as->info.open && (as->mode == AUDMODE_AUDIO)) {
		as->info.pause = B_TRUE;
		AUD_STOP(as);
	}
}


/*
 * The next two routines are called from ioctls to resume paused
 * read/write.
 */
void
audio_resume_record(aud_stream_t *as)
{
	ASSERT_ASLOCKED(as);
	ATRACE(audio_resume_record, 'RSUM', as);
	ASSERT(as == as->input_as);

	if (!as->info.pause)
		return;

	/*
	 * Must clear pause flag before calling audio_process_input
	 */
	as->info.pause = B_FALSE;

	/*
	 * audio_process_input() will call the AUD_START routine
	 */
	audio_process_input(as);
}


void
audio_resume_play(aud_stream_t *as)
{
	ASSERT_ASLOCKED(as);
	ATRACE(audio_resume_play, 'RSUM', as);
	ASSERT(as == as->output_as);

	if (!as->info.pause)
		return;

	/*
	 * Must clear pause flag before calling audio_process_output
	 */
	as->info.pause = B_FALSE;

	/*
	 * Queue up output buffers and enable output conversion
	 */
	audio_process_output(as);
	AUD_START(as);
}


/*
 * audio_trace - for a particular STREAM, copy the STREAMS message
 * pointed to by the audio command to the trace queue (if any).  the
 * dihandle of the command will contain a pointer to the data message and
 * the aud_stream will have a pointer to the trace queue.  The audio
 * command also contains a structure of information pertaining to the
 * data message (status, etc).
 */
void
audio_trace(aud_stream_t *as, aud_cmd_t *cmdp)
{
	mblk_t *msghdrp;
	mblk_t *msgp;

	/* If trace stream is not open, simply return */
	if (as->traceq == NULL || !(as->traceq->q_flag & QREADR))
		return;

	/*
	 * If STREAM is full, then we just don't send anything.  No
	 * promises are made that this is reliable...
	 */
	if (!canput(as->traceq->q_next))
		return;

	msgp = dupmsg((mblk_t *)cmdp->dihandle);
	if (msgp == NULL)
		return;

	if ((msghdrp = allocb(sizeof (audtrace_hdr_t), BPRI_HI)) == NULL) {
		freemsg(msgp);
		return;
	}

	msghdrp->b_datap->db_type = M_PROTO;
	uniqtime32(&cmdp->tracehdr.timestamp);
	*((audtrace_hdr_t *)(void *)msghdrp->b_wptr) = cmdp->tracehdr;
	msghdrp->b_wptr += sizeof (audtrace_hdr_t);

	linkb(msghdrp, msgp);

	/*
	 * Send the messages upstream
	 */
	putnext(as->traceq, msghdrp);
}


/*
 * audio_trace_hdr - send only the header part up the trace stream
 */
void
audio_trace_hdr(aud_stream_t *as, audtrace_hdr_t *th)
{
	mblk_t *msghdrp;

	/* If trace stream is not open, simply return */
	if (as->traceq == NULL)
		return;

	ASSERT(as->traceq->q_flag & QREADR);

	/*
	 * If STREAM is full, then we just don't send anything.  No
	 * promises are made that this is reliable...
	 */
	if (!canput(as->traceq->q_next))
		return;

	if ((msghdrp = allocb(sizeof (audtrace_hdr_t), BPRI_HI)) == NULL) {
		return;
	}

	msghdrp->b_datap->db_type = M_PROTO;
	uniqtime32(&th->timestamp);
	*((audtrace_hdr_t *)(void *)msghdrp->b_wptr) = *th;
	msghdrp->b_wptr += sizeof (audtrace_hdr_t);

	/*
	 * Send the messages upstream
	 */
	putnext(as->traceq, msghdrp);
}
