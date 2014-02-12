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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "lpsched.h"
#include "validate.h"

/*
 * The routines in this file are used to examine queued requests
 * to see if something must be done about them. We don't bother
 * checking requests that are:
 *
 *	- printing (we could, to allow the administrator to stop
 *	  a request by making a configuration change, but that
 *	  can lead to trouble (yet another way to terminate a child)
 *	  and the administrator can always disable the request to
 *	  force it to stop printing and be reevaluated);
 *
 *	- changing, since once the change is complete the request
 *	  will be reevaluated again anyway;
 *
 *	- notifying, since the request is essentially finished
 *
 *	- being sent or already sent to a remote machine;
 *
 *	- done.
 *
 * Requests that are being held or are filtering ARE to be considered,
 * because things may have changed to make them impossible to print.
 */
#define RS_SKIP	((RS_ACTIVE & ~RS_FILTERING) | RS_DONE)
#define	SKIP_IT(PRS) ((PRS)->request->outcome & RS_SKIP)

/**
 ** queue_attract() - REASSIGN REQUEST(S) TO PRINTER, IF POSSIBLE
 **/

void
queue_attract(PSTATUS *pps, int (*qchk_p)(RSTATUS *), int attract_just_one)
{
	register RSTATUS	*prs;
	register CLSTATUS	*pcs;
	int			called_schedule	= 0;


	/*
	 * Evaluate requests that:
	 *	- meet a criteria set by a function passed.
	 *	- are already queued for the printer
	 *	- are destined for a class containing this printer
	 *	- or are destined for any printer
	 * We stop on the first one that will work on the printer,
	 * and schedule an interface for the printer (which will
	 * find the first request ready, namely the one we stopped on).
	 */

#define	SAMECLASS(PRS,PPS) \
	( \
		((pcs = search_cstatus(PRS->request->destination)) != NULL) \
	     && searchlist(PPS->printer->name, pcs->class->members) \
	)

#define ISANY(PRS)	STREQU(PRS->request->destination, NAME_ANY)

	for (prs = Request_List; prs; prs = prs->next) {
		if (
			!SKIP_IT(prs)
		     && (!qchk_p || (*qchk_p)(prs))
		     && (
				prs->printer == pps
			     || ISANY(prs)
			     || SAMECLASS(prs, pps)
			)
		)
			/*
			 * Don't need to evaluate the request if it
			 * is already queued!
			 */
			if (
				prs->printer == pps
			     || evaluate_request(prs, pps, 0) == MOK
			) {
				/*
				 * This request was attracted to the
				 * printer but maybe it now needs to be
				 * filtered. If so, filter it but see if
				 * there's another request all set to go.
				 */
				if (NEEDS_FILTERING(prs))
					schedule (EV_SLOWF, prs);
				else {
					if (!called_schedule) {
						schedule (EV_INTERF, pps);
						called_schedule = 1;
					}
					if (attract_just_one)
						break;
				}
			}
	}

	return;
}

/**
 ** queue_repel() - REASSIGN REQUESTS TO ANOTHER PRINTER, IF POSSIBLE
 **/

int
queue_repel(PSTATUS *pps, int move_off, int (*qchk_p)(RSTATUS *))
{
	register RSTATUS	*prs;
	register int		all_can		= 1;
	register PSTATUS	*stop_pps	= (move_off? pps : 0);

	/*
	 * Reevaluate all requests that are assigned to this
	 * printer, to see if there's another printer that
	 * can handle them.
	 *
	 * If the "move_off" flag is set, don't consider the current
	 * printer when reevaluating, but also don't cancel the request
	 * if it can't be moved off the printer.
	 * (Currently this is only used when deciding if a printer
	 * can be deleted.)
	 */
	for (prs = Request_List; prs != NULL; prs = prs->next) {
		if (prs->printer != pps)
			continue;

		/*
		 * "all_can" keeps track of whether all of the requests
		 * of interest to the caller (governed by "qchk_p") can
		 * be moved to another printer. Now we don't move certain
		 * requests (active, done, gone remote), and some of those
		 * matter in the ``all can'' consideration.
		 */
		if (qchk_p && !(*qchk_p)(prs))
			continue;
		else if (SKIP_IT(prs)) {
			if ( !(prs->request->outcome & RS_DONE) )
				all_can = 0;
			continue;

		} else

			if (reevaluate_request(prs, stop_pps) == MOK) {

				/*
				 * If this request needs to be filtered,
				 * try to schedule it for filtering,
				 * otherwise schedule it for printing.
				 * We are inefficient here, because we may
				 * try to schedule many requests but the
				 * filtering slot(s) and printers are
				 * busy; but the requests may languish
				 * if we don't check here.
				 */
				if (NEEDS_FILTERING(prs))
					schedule (EV_SLOWF, prs);
				else
					schedule (EV_INTERF, prs->printer);

			} else {
				all_can = 0;
				if (!move_off)
					cancel (prs, 1);
				else
					prs->reason = MOK;
			}
	}

	return (all_can);
}

/**
 ** queue_check() - CHECK ALL REQUESTS AGAIN
 **/

void
queue_check(int (*qchk_p)( RSTATUS * ))
{
	register RSTATUS	*prs;


	for (prs = Request_List; prs; prs = prs->next)
		if (!SKIP_IT(prs) && (!qchk_p || (*qchk_p)(prs)))
			if (reevaluate_request(prs, (PSTATUS *)0) == MOK)
				if (NEEDS_FILTERING(prs))
					schedule (EV_SLOWF, prs);
				else
					schedule (EV_INTERF, prs->printer);
			else
				cancel (prs, 1);

	return;
}

/**
 ** qchk_waiting() - CHECK IF REQUEST IS READY TO PRINT
 ** qchk_filter() - CHECK IF REQUEST NEEDS A FILTER
 ** qchk_form() - CHECK IF REQUEST NEEDS A FORM
 ** qchk_pwheel() - CHECK IF REQUEST NEEDS PRINT A WHEEL
 **/

int
qchk_waiting(RSTATUS *prs)
{
	return (
		!(prs->request->outcome & (RS_HELD|RS_DONE|RS_ACTIVE))
	     && !NEEDS_FILTERING(prs)
	);
}

int
qchk_filter(RSTATUS *prs)
{
	/*
	 * No need to reevaluate this request if it isn't using a filter
	 * or if it is done or is being changed.
	 */
	return (
		!(prs->request->outcome & (RS_DONE|RS_CHANGING|RS_NOTIFY))
	     && (prs->slow || prs->fast)
	);
}

FSTATUS *		form_in_question;

int
qchk_form(RSTATUS *prs)
{
	return (prs->form == form_in_question);
}

char *			pwheel_in_question;

int
qchk_pwheel(RSTATUS *prs)
{
	return (SAME(prs->pwheel_name, pwheel_in_question));
}
