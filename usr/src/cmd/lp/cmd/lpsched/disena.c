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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.9.1.4	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "lpsched.h"
#include <time.h>

/**
 ** disable() - DISABLE PRINTER
 **/

int
disable(PSTATUS *pps, char *reason, int when)
{
	if (pps->status & PS_DISABLED)
		return (-1);

	else {
		pps->status |= PS_DISABLED;
		time (&pps->dis_date);
		load_str (&pps->dis_reason, reason);

		dump_pstatus ();

		if (pps->status & PS_BUSY)
			switch (when) {

			case DISABLE_STOP:
				/*
				 * Stop current job, requeue.
				 */
				if (pps->request)
				    pps->request->request->outcome |= RS_STOPPED;
				terminate (pps->exec);
				break;

			case DISABLE_FINISH:
				/*
				 * Let current job finish.
				 */
				break;

			case DISABLE_CANCEL:
				/*
				 * Cancel current job outright.
				 */
				if (pps->request)
				    cancel (pps->request, 1);
				break;

			}

		/*
		 * Need we check to see if requests assigned to
		 * this printer should be assigned elsewhere?
		 * No, if the "validate()" routine is properly
		 * assigning requests. If another printer is available
		 * for printing requests (that would otherwise be)
		 * assigned to this printer, at least one of those
		 * requests will be assigned to that other printer,
		 * and should be currently printing. Once it is done
		 * printing, the queue will be examined for the next
		 * request, and the one(s) assigned this printer will
		 * be picked up.
		 */
/*		(void)queue_repel (pps, 0, (qchk_fnc_type)0);	*/

		return (0);
	}
}

/**
 ** enable() - ENABLE PRINTER
 **/

int
enable (register PSTATUS *pps)
{
	/*
	 * ``Enabling a printer'' includes clearing a fault and
	 * clearing the do-it-later flag to allow the printer
	 * to start up again.
	 */
	if (!(pps->status & (PS_FAULTED|PS_DISABLED|PS_LATER)))
		return (-1);

	else {
		pps->status &= ~(PS_FAULTED|PS_DISABLED|PS_LATER);
		(void) time (&pps->dis_date);

		dump_pstatus ();

		if (pps->alert->active)
			cancel_alert (A_PRINTER, pps);

		/*
		 * Attract the FIRST request that is waiting to
		 * print to this printer. In this regard we're acting
		 * like the printer just finished printing a request
		 * and is looking for another.
		 */
		queue_attract (pps, qchk_waiting, 1);
		return (0);
	}
}
