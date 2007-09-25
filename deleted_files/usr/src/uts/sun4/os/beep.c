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

#include <sys/devops.h>

#include <sys/beep.h>
#include <sys/errno.h>
#include <sys/inttypes.h>

/*
 * Debug stuff
 * BEEP_DEBUG used for errors
 * BEEP_DEBUG1 prints when beep_debug > 1 and used for normal messages
 */
#ifdef DEBUG
int beep_debug = 0;
#define	BEEP_DEBUG(args)  if (beep_debug) cmn_err args
#define	BEEP_DEBUG1(args)  if (beep_debug > 1) cmn_err args
#else
#define	BEEP_DEBUG(args)
#define	BEEP_DEBUG1(args)
#endif


/* Prototypes */

static void beep_timeout();


struct beep_params {
	enum beep_type	type;
	int		frequency;	/* Hz */
	int		duration;	/* milliseconds */
};


struct beep_params beep_params[] = {
	BEEP_CONSOLE,	900,	200,
	BEEP_TYPE4,	2000,	0,
	BEEP_DEFAULT,	1000,	200,	/* Must be last */
};


/* beep_state structure */

typedef struct beep_state {

	dev_info_t	*beep_state_beep_dip;	/* device pointer */

	/* Indicates if a beep command is already in progress */
	enum		{BEEP_OFF, BEEP_TIMED, BEEP_ON} beep_state_mode;

	/* Address of the hw-dependent beep_freq function */
	void		(*beep_state_beep_freq) (dev_info_t *, int);

	/* Address of the hw-dependent beep_on function */
	void		(*beep_state_beep_on) (dev_info_t *);

	/* Address of the hw-dependent beep_off function */
	void		(*beep_state_beep_off) (dev_info_t *);

	/* Timeout id for the beep() timeout function */
	timeout_id_t	beep_state_timeout_id;

	/* Mutex */
	kmutex_t	beep_state_mutex;

} beep_state_t;


static beep_state_t	*beep_statep = NULL;


/*
 * beep_init :
 * 	Alloc beep_state structure
 * 	called from the beep driver attach routine
 */
int
beep_init(dev_info_t *dip, void (*hwbeep_beep_on)(dev_info_t *),
		void (*hwbeep_beep_off)(dev_info_t *),
		void (*hwbeep_beep_freq)(dev_info_t *, int))
{
	BEEP_DEBUG1((CE_CONT, "beep_init : start"));

	if (dip == NULL) {
		return (DDI_FAILURE);
	}

	if ((hwbeep_beep_on == NULL) || (hwbeep_beep_off == NULL) ||
		(hwbeep_beep_freq == NULL)) {

		BEEP_DEBUG((CE_WARN,
			"beep_init : Null routines passed for registration."));
		return (DDI_FAILURE);
	}

	beep_statep = kmem_zalloc(sizeof (beep_state_t), KM_SLEEP);
	if (beep_statep  == NULL) {
		BEEP_DEBUG((CE_WARN,
			"beep_init : kmem_zalloc failed."));
		return (DDI_FAILURE);
	}

	beep_statep->beep_state_beep_dip = dip;
	beep_statep->beep_state_beep_on = hwbeep_beep_on;
	beep_statep->beep_state_beep_off = hwbeep_beep_off;
	beep_statep->beep_state_beep_freq = hwbeep_beep_freq;
	beep_statep->beep_state_mode = BEEP_OFF;

	mutex_init(&beep_statep->beep_state_mutex, NULL, MUTEX_DRIVER, NULL);

	BEEP_DEBUG1((CE_CONT, "beep_init : Done."));
	return (DDI_SUCCESS);

}


/*
 * beep :
 *	Start beeping for period specified by 'time' (in microsecond)
 */
void
beep(enum beep_type type)
{

	struct beep_params *bp;

	BEEP_DEBUG1((CE_CONT, "beep : Start"));

	if (beep_statep == NULL) {
		return;
	}

	for (bp = beep_params; bp->type != BEEP_DEFAULT; bp++) {
		if (bp->type == type)
			break;
	}

	if (bp->type != type) {

		/* If type doesn't match, return silently without beeping */
		return;
	}

	mutex_enter(&beep_statep->beep_state_mutex);

	/* Beep only when no previous beep is in progress */
	if (beep_statep->beep_state_mode == BEEP_OFF && bp->frequency != 0) {

		beep_statep->beep_state_mode = BEEP_TIMED;

		(*beep_statep->beep_state_beep_freq)(beep_statep->
			beep_state_beep_dip, bp->frequency);
		(*beep_statep->beep_state_beep_on)(beep_statep->
				beep_state_beep_dip);

		/* Set timeout for ending the beep after the specified time */
		beep_statep->beep_state_timeout_id = timeout(beep_timeout,
					NULL,
					drv_usectohz(bp->duration*1000));
	}

	mutex_exit(&beep_statep->beep_state_mutex);

	BEEP_DEBUG1((CE_CONT, "beep : Done"));

}


/*ARGSUSED*/
void
beep_polled(enum beep_type type)
{
	/* No-op at this time */
}


/*
 * beeper_on :
 *	Turn the beeper on
 */
void
beeper_on(enum beep_type type)
{

	struct beep_params *bp;

	BEEP_DEBUG1((CE_CONT, "beeper_on : Start"));

	if (beep_statep == NULL) {
		return;
	}

	for (bp = beep_params; bp->type != BEEP_DEFAULT; bp++) {
		if (bp->type == type)
			break;
	}

	if (bp->type != type) {

		/* If type doesn't match, return silently */
		return;
	}

	mutex_enter(&beep_statep->beep_state_mutex);

	/* Start another beep only if the previous one is over */
	if (beep_statep->beep_state_mode == BEEP_OFF) {

		beep_statep->beep_state_mode = BEEP_ON;

		if (bp->frequency != 0) {
			(*beep_statep->beep_state_beep_freq)(beep_statep->
					beep_state_beep_dip, bp->frequency);
			(*beep_statep->beep_state_beep_on)(beep_statep->
						beep_state_beep_dip);
		}
	}
	mutex_exit(&beep_statep->beep_state_mutex);

	BEEP_DEBUG1((CE_CONT, "beeper_on : Done"));

}


/*
 * beeper_off :
 *	Turn the beeper off
 */
void
beeper_off()
{

	BEEP_DEBUG1((CE_CONT, "beeper_off : Start"));

	if (beep_statep == NULL) {
		return;
	}

	mutex_enter(&beep_statep->beep_state_mutex);

	if (beep_statep->beep_state_mode == BEEP_ON) {

		beep_statep->beep_state_mode = BEEP_OFF;
		(*beep_statep->beep_state_beep_off)(beep_statep->
						beep_state_beep_dip);
	}
	mutex_exit(&beep_statep->beep_state_mutex);

	BEEP_DEBUG1((CE_CONT, "beeper_off : Done"));

}


/*
 * Turn the beeper off which had been turned on from beep()
 * for a specified period of time
 */
void
beep_timeout()
{
	BEEP_DEBUG1((CE_CONT, "beeper_timeout : Start"));

	beep_statep->beep_state_timeout_id = 0;
	mutex_enter(&beep_statep->beep_state_mutex);

	if ((beep_statep->beep_state_mode == BEEP_ON) ||
	    (beep_statep->beep_state_mode == BEEP_TIMED)) {

		beep_statep->beep_state_mode = BEEP_OFF;
		(*beep_statep->beep_state_beep_off)(beep_statep->
						beep_state_beep_dip);
	}
	mutex_exit(&beep_statep->beep_state_mutex);

	BEEP_DEBUG1((CE_CONT, "beeper_timeout : Done"));

}

/*
 * Beeper_freq:
 *	Set beeper frequency
 */
int
beeper_freq(enum beep_type type, int freq)
{
	struct beep_params *bp;

	BEEP_DEBUG1((CE_CONT, "beeper_freq : Start"));

	/*
	 * The frequency value is limited to the range of [0 - 32767]
	 */
	if ((type != BEEP_CONSOLE && type != BEEP_TYPE4) || freq < 0 ||
	    freq > INT16_MAX)
		return (EINVAL);

	for (bp = beep_params; bp->type != BEEP_DEFAULT; bp++) {
		if (bp->type == type)
			break;
	}

	bp->frequency = freq;

	BEEP_DEBUG1((CE_CONT, "beeper_freq : Done"));

	return (0);
}
