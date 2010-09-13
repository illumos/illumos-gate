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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This is the Beep module for supporting keyboard beep for keyboards
 * that do not have the beeping feature within themselves
 *
 */

#include <sys/types.h>
#include <sys/conf.h>

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/ddi_impldefs.h>
#include <sys/kmem.h>

#include <sys/beep.h>
#include <sys/inttypes.h>

/*
 * Debug stuff
 * BEEP_DEBUG used for errors
 * BEEP_DEBUG1 prints when beep_debug > 1 and used for normal messages
 */
#ifdef DEBUG
int beep_debug = 0;
#define	BEEP_DEBUG(args)	if (beep_debug) cmn_err args
#define	BEEP_DEBUG1(args)	if (beep_debug > 1) cmn_err args
#else
#define	BEEP_DEBUG(args)
#define	BEEP_DEBUG1(args)
#endif

int beep_queue_size = BEEP_QUEUE_SIZE;

/*
 * Note that mutex_init is not called on the mutex in beep_state,
 * But assumes that zeroed memory does not need to call mutex_init,
 * as documented in mutex.c
 */

beep_state_t beep_state;

beep_params_t beep_params[] = {
	{BEEP_CONSOLE,	900,	200},
	{BEEP_TYPE4,	2000,	0},
	{BEEP_DEFAULT,	1000,	200},	/* Must be last */
};


/*
 * beep_init:
 * Allocate the beep_queue structure
 * Initialize beep_state structure
 * Called from beep driver attach routine
 */

int
beep_init(void *arg,
    beep_on_func_t beep_on_func,
    beep_off_func_t beep_off_func,
    beep_freq_func_t beep_freq_func)
{
	beep_entry_t *queue;

	BEEP_DEBUG1((CE_CONT,
	    "beep_init(0x%lx, 0x%lx, 0x%lx, 0x%lx) : start.",
	    (unsigned long) arg,
	    (unsigned long) beep_on_func,
	    (unsigned long) beep_off_func,
	    (unsigned long) beep_freq_func));

	mutex_enter(&beep_state.mutex);

	if (beep_state.mode != BEEP_UNINIT) {
		mutex_exit(&beep_state.mutex);
		BEEP_DEBUG((CE_WARN,
		    "beep_init : beep_state already initialized."));
		return (DDI_SUCCESS);
	}

	queue = kmem_zalloc(sizeof (beep_entry_t) * beep_queue_size,
	    KM_SLEEP);

	BEEP_DEBUG1((CE_CONT,
	    "beep_init : beep_queue kmem_zalloc(%d) = 0x%lx.",
	    (int)sizeof (beep_entry_t) * beep_queue_size,
	    (unsigned long)queue));

	if (queue == NULL) {
		BEEP_DEBUG((CE_WARN,
		    "beep_init : kmem_zalloc of beep_queue failed."));
		return (DDI_FAILURE);
	}

	beep_state.arg = arg;
	beep_state.mode = BEEP_OFF;
	beep_state.beep_freq = beep_freq_func;
	beep_state.beep_on = beep_on_func;
	beep_state.beep_off = beep_off_func;
	beep_state.timeout_id = 0;

	beep_state.queue_head = 0;
	beep_state.queue_tail = 0;
	beep_state.queue_size = beep_queue_size;
	beep_state.queue = queue;

	mutex_exit(&beep_state.mutex);

	BEEP_DEBUG1((CE_CONT, "beep_init : done."));
	return (DDI_SUCCESS);
}


int
beep_fini(void)
{
	BEEP_DEBUG1((CE_CONT, "beep_fini() : start."));

	(void) beeper_off();

	mutex_enter(&beep_state.mutex);

	if (beep_state.mode == BEEP_UNINIT) {
		mutex_exit(&beep_state.mutex);
		BEEP_DEBUG((CE_WARN,
		    "beep_fini : beep_state already uninitialized."));
		return (0);
	}

	if (beep_state.queue != NULL)
		kmem_free(beep_state.queue,
		    sizeof (beep_entry_t) * beep_state.queue_size);

	beep_state.arg = (void *)NULL;
	beep_state.mode = BEEP_UNINIT;
	beep_state.beep_freq = (beep_freq_func_t)NULL;
	beep_state.beep_on = (beep_on_func_t)NULL;
	beep_state.beep_off = (beep_off_func_t)NULL;
	beep_state.timeout_id = 0;

	beep_state.queue_head = 0;
	beep_state.queue_tail = 0;
	beep_state.queue_size = 0;
	beep_state.queue = (beep_entry_t *)NULL;

	mutex_exit(&beep_state.mutex);

	BEEP_DEBUG1((CE_CONT, "beep_fini() : done."));

	return (0);
}


int
beeper_off(void)
{
	BEEP_DEBUG1((CE_CONT, "beeper_off : start."));

	mutex_enter(&beep_state.mutex);

	if (beep_state.mode == BEEP_UNINIT) {
		mutex_exit(&beep_state.mutex);
		return (ENXIO);
	}

	if (beep_state.mode == BEEP_TIMED) {
		(void) untimeout(beep_state.timeout_id);
		beep_state.timeout_id = 0;
	}

	if (beep_state.mode != BEEP_OFF) {
		beep_state.mode = BEEP_OFF;

		if (beep_state.beep_off != NULL)
			(*beep_state.beep_off)(beep_state.arg);
	}

	beep_state.queue_head = 0;
	beep_state.queue_tail = 0;

	mutex_exit(&beep_state.mutex);

	BEEP_DEBUG1((CE_CONT, "beeper_off : done."));

	return (0);
}

int
beeper_freq(enum beep_type type, int freq)
{
	beep_params_t *bp;

	BEEP_DEBUG1((CE_CONT, "beeper_freq(%d, %d) : start", type, freq));

	/*
	 * The frequency value is limited to the range of [0 - 32767]
	 */
	if (freq < 0 || freq > INT16_MAX)
		return (EINVAL);

	for (bp = beep_params; bp->type != BEEP_DEFAULT; bp++) {
		if (bp->type == type)
			break;
	}

	if (bp->type != type) {
		BEEP_DEBUG((CE_WARN, "beeper_freq : invalid type."));

		return (EINVAL);
	}

	bp->frequency = freq;

	BEEP_DEBUG1((CE_CONT, "beeper_freq : done."));
	return (0);
}

/*
 * beep :
 *      Start beeping for period specified by the type value,
 *      from the value in the beep_param structure in milliseconds.
 */
int
beep(enum beep_type type)
{

	beep_params_t *bp;

	BEEP_DEBUG1((CE_CONT, "beep(%d) : start.", type));

	for (bp = beep_params; bp->type != BEEP_DEFAULT; bp++) {
		if (bp->type == type)
			break;
	}

	if (bp->type != type) {

		BEEP_DEBUG((CE_WARN, "beep : invalid type."));

		/* If type doesn't match, return silently without beeping */
		return (EINVAL);
	}

	return (beep_mktone(bp->frequency, bp->duration));
}


/*ARGSUSED*/
int
beep_polled(enum beep_type type)
{
	/*
	 * No-op at this time.
	 *
	 * Don't think we can make this work in general, as tem_safe
	 * has a requirement of no mutexes, but kbd sends messages
	 * through streams.
	 */

	BEEP_DEBUG1((CE_CONT, "beep_polled(%d)", type));

	return (0);
}

/*
 * beeper_on :
 *      Turn the beeper on
 */
int
beeper_on(enum beep_type type)
{
	beep_params_t *bp;
	int status = 0;

	BEEP_DEBUG1((CE_CONT, "beeper_on(%d) : start.", type));

	for (bp = beep_params; bp->type != BEEP_DEFAULT; bp++) {
		if (bp->type == type)
			break;
	}

	if (bp->type != type) {

		BEEP_DEBUG((CE_WARN, "beeper_on : invalid type."));

		/* If type doesn't match, return silently without beeping */
		return (EINVAL);
	}

	mutex_enter(&beep_state.mutex);

	if (beep_state.mode == BEEP_UNINIT) {
		status = ENXIO;

	/* Start another beep only if the previous one is over */
	} else if (beep_state.mode == BEEP_OFF) {
		if (bp->frequency != 0) {
			beep_state.mode = BEEP_ON;

			if (beep_state.beep_freq != NULL)
				(*beep_state.beep_freq)(beep_state.arg,
				    bp->frequency);

			if (beep_state.beep_on != NULL)
				(*beep_state.beep_on)(beep_state.arg);
		}
	} else {
		status = EBUSY;
	}

	mutex_exit(&beep_state.mutex);

	BEEP_DEBUG1((CE_CONT, "beeper_on : done, status %d.", status));

	return (status);
}


int
beep_mktone(int frequency, int duration)
{
	int next;
	int status = 0;

	BEEP_DEBUG1((CE_CONT, "beep_mktone(%d, %d) : start.", frequency,
	    duration));

	/*
	 * The frequency value is limited to the range of [0 - 32767]
	 */
	if (frequency < 0 || frequency > INT16_MAX)
		return (EINVAL);

	mutex_enter(&beep_state.mutex);

	if (beep_state.mode == BEEP_UNINIT) {
		status = ENXIO;

	} else if (beep_state.mode == BEEP_TIMED) {

		/* If already processing a beep, queue this one */

		if (frequency != 0) {
			next = beep_state.queue_tail + 1;
			if (next == beep_state.queue_size)
				next = 0;

			if (next != beep_state.queue_head) {
				/*
				 * If there is room in the queue,
				 * add this entry
				 */

				beep_state.queue[beep_state.queue_tail].
				    frequency = (unsigned short)frequency;

				beep_state.queue[beep_state.queue_tail].
				    duration = (unsigned short)duration;

				beep_state.queue_tail = next;
			} else {
				status = EAGAIN;
			}
		}

	} else if (beep_state.mode == BEEP_OFF) {

		/* Start another beep only if the previous one is over */

		if (frequency != 0) {
			beep_state.mode = BEEP_TIMED;

			if (beep_state.beep_freq != NULL)
				(*beep_state.beep_freq)(beep_state.arg,
				    frequency);

			if (beep_state.beep_on != NULL)
				(*beep_state.beep_on)(beep_state.arg);

			/*
			 * Set timeout for ending the beep after the
			 * specified time
			 */

			beep_state.timeout_id = timeout(beep_timeout, NULL,
			    drv_usectohz(duration * 1000));
		}
	} else {
		status = EBUSY;
	}

	mutex_exit(&beep_state.mutex);

	BEEP_DEBUG1((CE_CONT, "beep_mktone : done, status %d.", status));

	return (status);
}


/*
 * Turn the beeper off which had been turned on from beep()
 * for a specified period of time
 */
/*ARGSUSED*/
void
beep_timeout(void *arg)
{
	int frequency;
	int duration;
	int next;

	BEEP_DEBUG1((CE_CONT, "beeper_timeout : start."));

	mutex_enter(&beep_state.mutex);

	beep_state.timeout_id = 0;

	if (beep_state.mode == BEEP_UNINIT) {
		mutex_exit(&beep_state.mutex);
		BEEP_DEBUG1((CE_CONT, "beep_timeout : uninitialized."));
		return;
	}

	if ((beep_state.mode == BEEP_ON) ||
	    (beep_state.mode == BEEP_TIMED)) {

		beep_state.mode = BEEP_OFF;

		if (beep_state.beep_off != NULL)
			(*beep_state.beep_off)(beep_state.arg);
	}

	if (beep_state.queue_head != beep_state.queue_tail) {

		next = beep_state.queue_head;

		frequency = beep_state.queue[next].frequency;

		duration = beep_state.queue[next].duration;

		next++;
		if (next == beep_state.queue_size)
			next = 0;

		beep_state.queue_head = next;

		beep_state.mode = BEEP_TIMED;

		if (frequency != 0) {
			if (beep_state.beep_freq != NULL)
				(*beep_state.beep_freq)(beep_state.arg,
				    frequency);

			if (beep_state.beep_on != NULL)
				(*beep_state.beep_on)(beep_state.arg);
		}

		/* Set timeout for ending the beep after the specified time */

		beep_state.timeout_id = timeout(beep_timeout, NULL,
		    drv_usectohz(duration * 1000));
	}

	mutex_exit(&beep_state.mutex);

	BEEP_DEBUG1((CE_CONT, "beep_timeout : done."));
}


/*
 * Return true (1) if we are sounding a tone.
 */
int
beep_busy(void)
{
	int status;

	BEEP_DEBUG1((CE_CONT, "beep_busy : start."));

	mutex_enter(&beep_state.mutex);

	status = beep_state.mode != BEEP_UNINIT &&
	    beep_state.mode != BEEP_OFF;

	mutex_exit(&beep_state.mutex);

	BEEP_DEBUG1((CE_CONT, "beep_busy : status %d.", status));

	return (status);
}
