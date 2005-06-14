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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.9.1.5	*/

#include	"dispatch.h"
#include <syslog.h>
#include <time.h>

extern char	*LP_ALL_NEW;

char *showForms(PSTATUS *);

/*
 * untidbit_all() - CALL untidbit() FOR A LIST OF TYPES
 */

static void
untidbit_all (char **printer_types)
{
	char **			pl;

	for (pl = printer_types; *pl; pl++)
		untidbit (*pl);
	return;
}

/*
 * s_load_printer()
 */

void
s_load_printer(char *m, MESG *md)
{
	char			*printer;
	ushort			status;
	PRINTER			op;
	register PRINTER	*pp;
	register PSTATUS	*pps;
	char **paperDenied;

	(void) getmessage(m, S_LOAD_PRINTER, &printer);
	syslog(LOG_DEBUG, "s_load_printer(%s)", (printer ? printer : "NULL"));

	if (!*printer)
		/* no printer */
		status = MNODEST;
	else if (!(pp = Getprinter(printer))) {
		/* Strange or missing printer? */
		switch (errno) {
		case EBADF:
			status = MERRDEST;
			break;
		case ENOENT:
		default:
			status = MNODEST;
			break;
		}
	} else if ((pps = search_ptable(printer))) {
		/* Printer we know about already? */

		op = *(pps->printer);
		*(pps->printer) = *pp;

		/*
		 * Ensure that an old Terminfo type that's no longer
		 * needed gets freed, and that an existing type gets
		 * reloaded (in case it has been changed).
		 */
		untidbit_all (op.printer_types);
		untidbit_all (pp->printer_types);

		/*
		 * Does an alert get affected?
		 *	- Different command?
		 *	- Different wait interval?
		 */
		if (pps->alert->active)
			if (!SAME(pp->fault_alert.shcmd,
				  op.fault_alert.shcmd) ||
			    pp->fault_alert.W != op.fault_alert.W) {
				/*
				 * We can't use "cancel_alert()" here
				 * because it will remove the message.
				 * We'll do half of the cancel, then
				 * check if we need to run the new alert,
				 * and remove the message if not.
				 */
				pps->alert->active = 0;
				terminate (pps->alert->exec);
				if (pp->fault_alert.shcmd)
					alert(A_PRINTER, pps, (RSTATUS *)0,
						(char *)0);
				else
					Unlink (pps->alert->msgfile);
			}
		freeprinter (&op);

		unload_list (&pps->users_allowed);
		unload_list (&pps->users_denied);
		unload_list (&pps->forms_allowed);
		unload_list (&pps->forms_denied);
		load_userprinter_access(pp->name, &pps->users_allowed,
			&pps->users_denied);
		load_formprinter_access(pp->name, &pps->forms_allowed,
			&pps->forms_denied);

		unload_list (&pps->paper_allowed);
		load_paperprinter_access(pp->name, &pps->paper_allowed,
			&paperDenied);
		freelist(paperDenied);

		load_sdn (&pps->cpi, pp->cpi);
		load_sdn (&pps->lpi, pp->lpi);
		load_sdn (&pps->plen, pp->plen);
		load_sdn (&pps->pwid, pp->pwid);

		pps->last_dial_rc = 0;
		pps->nretry = 0;

		/*
		 * Evaluate all requests queued for this printer,
		 * to make sure they are still eligible. They will
		 * get moved to another printer, get (re)filtered,
		 * or get canceled.
		 */
		(void) queue_repel(pps, 0, (qchk_fnc_type)0);

		status = MOK;
        } else if (pp->remote) {
		/* don't really load a remote printer */
		status = MOK;
	} else if ((pps = search_ptable((char *)0))) {
		/* Room for new printer? */
		pps->status = PS_DISABLED | PS_REJECTED;
		pps->request = 0;
		pps->alert->active = 0;

		pps->forms = 0;
		pps->numForms = 0;
		pps->pwheel_name = 0;
		pps->pwheel = 0;

		load_str (&pps->dis_reason, CUZ_NEW_PRINTER);
		load_str (&pps->rej_reason, CUZ_NEW_DEST);
		load_str (&pps->fault_reason, CUZ_PRINTING_OK);
		time (&pps->dis_date);
		time (&pps->rej_date);

		*(pps->printer) = *pp;

		untidbit_all (pp->printer_types);

		unload_list (&pps->users_allowed);
		unload_list (&pps->users_denied);
		unload_list (&pps->forms_allowed);
		unload_list (&pps->forms_denied);
		load_userprinter_access(pp->name, &pps->users_allowed,
			&pps->users_denied);
		load_formprinter_access(pp->name, &pps->forms_allowed,
			&pps->forms_denied);

		unload_list (&pps->paper_allowed);
		load_paperprinter_access(pp->name, &pps->paper_allowed,
			&paperDenied);
		freelist(paperDenied);

		load_sdn (&pps->cpi, pp->cpi);
		load_sdn (&pps->lpi, pp->lpi);
		load_sdn (&pps->plen, pp->plen);
		load_sdn (&pps->pwid, pp->pwid);

		pps->last_dial_rc = 0;
		pps->nretry = 0;

		dump_pstatus ();

		status = MOK;

	} else {
		freeprinter (pp);
		status = MNOSPACE;
	}


	mputm (md, R_LOAD_PRINTER, status);
	return;
}

/*
 * s_unload_printer()
 */

static void
_unload_printer(PSTATUS *pps)
{
	register CSTATUS	*pcs;

	if (pps->alert->active)
		cancel_alert (A_PRINTER, pps);

	/*
	 * Remove this printer from the classes it may be in.
	 * This is likely to be redundant, i.e. upon deleting
	 * a printer the caller is SUPPOSED TO check all the
	 * classes; any that contain the printer will be changed
	 * and we should receive a S_LOAD_CLASS message for each
	 * to reload the class.
	 *
	 * HOWEVER, this leaves a (small) window where someone
	 * can sneak a request in destined for the CLASS. If
	 * we have deleted the printer but still have it in the
	 * class, we may have trouble!
	 */
	for (pcs = walk_ctable(1); pcs; pcs = walk_ctable(0))
		(void) dellist(&(pcs->class->members), pps->printer->name);

	untidbit_all (pps->printer->printer_types);
	freeprinter (pps->printer);
	pps->printer->name = 0;		/* freeprinter() doesn't */
	if (pps->forms) {
		Free(pps->forms);
		}
	pps->forms = NULL;
	pps->numForms = 0;

	return;
}

void
s_unload_printer(char *m, MESG *md)
{
	char			*printer;
	ushort			status;
	register PSTATUS	*pps;

	(void) getmessage(m, S_UNLOAD_PRINTER, &printer);

	syslog(LOG_DEBUG, "s_unload_printer(%s)",
	       (printer ? printer : "NULL"));

	if (!*printer || STREQU(printer, NAME_ALL))
		/* Unload ALL printers */
		if (!Request_List)
			/*  If we have ANY requests queued, we can't do it. */
			status = MBUSY;

		else {
			for (pps = walk_ptable(1); pps; pps = walk_ptable(0))
				_unload_printer (pps);
			status = MOK;
		}

	else if (!(pps = search_ptable(printer)))
		/* Have we seen this printer before */
		status = MNODEST;
	else {
		/*
		 * Note: This routine WILL MOVE requests to another
		 * printer. It will not stop until it has gone through
		 * the entire list of requests, so all requests that
		 * can be moved will be moved. If any couldn't move,
		 * however, we don't unload the printer.
		 */
		if (queue_repel(pps, 1, (qchk_fnc_type)0))
			status = MOK;
		else
			status = MBUSY;

		if (status == MOK)
			_unload_printer (pps);

	}

	if (status == MOK)
		dump_pstatus ();

	mputm (md, R_UNLOAD_PRINTER, status);
	return;
}

/*
 * combineReasons()
 */

static char *
combineReasons(PSTATUS *pps, char *freeReason)
{
	char	*reason = NULL;

	if (pps->status & PS_FAULTED) {
		if ((pps->status & (PS_DISABLED | PS_LATER)) &&
		    (!STREQU(pps->dis_reason, CUZ_STOPPED)) &&
		    (addstring(&reason, "Fault reason: ") == 0) &&
		    (addstring(&reason, pps->fault_reason) == 0) &&
		    (addstring(&reason, "\n\tDisable reason: ") == 0) &&
		    (addstring(&reason, pps->dis_reason) == 0))
			*freeReason = 1;

		else {
			if (reason)
				/* memory allocation failed part way through */
				Free(reason);

			reason = pps->fault_reason;
			*freeReason = 0;
		}
	} else {
		reason = pps->dis_reason;
		*freeReason = 0;
	}
	return (reason);
}

static void
local_printer_status(MESG *md, PSTATUS *pps, short status)
{
	char	*reason = NULL;
	char	freeReason = 0;
	char	*formList = NULL;

	reason = combineReasons(pps, &freeReason);
	formList = showForms(pps);

	send(md, R_INQUIRE_PRINTER_STATUS, status, pps->printer->name,
		(formList ? formList : ""),
		(pps->pwheel_name ? pps->pwheel_name : ""),
		reason, pps->rej_reason, pps->status,
		(pps->request ? pps->request->secure->req_id : ""),
		pps->dis_date, pps->rej_date);

	if (formList)
		Free(formList);

	if (freeReason)
		Free(reason);
}

/*
 * s_inquire_printer_status()
 */

void
s_inquire_printer_status(char *m, MESG *md)
{
	char			*printer;
	register PSTATUS	*pps, *ppsnext;

	(void) getmessage(m, S_INQUIRE_PRINTER_STATUS, &printer);
	syslog(LOG_DEBUG, "s_inquire_printer_status(%s)\n", printer);

	if (!*printer || STREQU(printer, NAME_ALL)) {
		/* inquire about all printers */
		pps = walk_ptable(1);
		while (ppsnext = walk_ptable(0)) {
			local_printer_status(md, pps, MOKMORE);
			pps = ppsnext;
		}
	} else
		/* inquire about a specific printer */
		pps = search_ptable(printer);

	if (pps)
		local_printer_status(md, pps, MOK);
	else {
		mputm(md, R_INQUIRE_PRINTER_STATUS, MNODEST, "", "", "", "",
			"", 0, "", 0L, 0L);
	}
}


/*
 * s_load_class()
 */

void
s_load_class(char *m, MESG *md)
{
	char			*class;
	ushort			status;
	register CLASS		*pc;
	register CSTATUS	*pcs;

	(void) getmessage(m, S_LOAD_CLASS, &class);
	syslog(LOG_DEBUG, "s_load_class(%s)", (class ? class : "NULL"));

	if (!*class)
		/* no class defined */
		status = MNODEST;
	else if (!(pc = Getclass(class))) {
		/* Strange or missing class */
		switch (errno) {
		case EBADF:
			status = MERRDEST;
			break;
		case ENOENT:
		default:
			status = MNODEST;
			break;
		}

	} else if ((pcs = search_ctable(class))) {
		/* Class we already know about */
		register RSTATUS	*prs;

		freeclass (pcs->class);
		*(pcs->class) = *pc;

		/*
		 * Here we go through the list of requests
		 * to see who gets affected.
		 */
		BEGIN_WALK_BY_DEST_LOOP (prs, class)
			/*
			 * If not still eligible for this class...
			 */
			switch (validate_request(prs, (char **)0, 1)) {
			case MOK:
			case MERRDEST:	/* rejecting (shouldn't happen) */
				break;
			case MDENYDEST:
			case MNOMOUNT:
			case MNOMEDIA:
			case MNOFILTER:
			default:
				/*
				 * ...then too bad!
				 */
				cancel (prs, 1);
				break;
			}
		END_WALK_LOOP
		status = MOK;
	} else if ((pcs = search_ctable((char *)0))) {
		/* Room for new class? */
		pcs->status = CS_REJECTED;

		load_str (&pcs->rej_reason, CUZ_NEW_DEST);
		time (&pcs->rej_date);

		*(pcs->class) = *pc;

		dump_cstatus ();

		status = MOK;
	} else {
		freeclass (pc);
		status = MNOSPACE;
	}


	mputm (md, R_LOAD_CLASS, status);
	return;
}

/*
 * s_unload_class()
 */

static void
_unload_class(CSTATUS *pcs)
{
	freeclass (pcs->class);
	pcs->class->name = 0;	/* freeclass() doesn't */

	return;
}

void
s_unload_class(char *m, MESG *md)
{
	char			*class;
	ushort			status;
	RSTATUS			*prs;
	register CSTATUS	*pcs;

	(void) getmessage(m, S_UNLOAD_CLASS, &class);
	syslog(LOG_DEBUG, "s_unload_class(%s)", (class ? class : "NULL"));

	/*
	 * Unload ALL classes?
	 */
	if (!*class || STREQU(class, NAME_ALL)) {

		/*
		 * If we have a request queued for a member of ANY
		 * class, we can't do it.
		 */
		status = MOK;
		for (pcs = walk_ctable(1); pcs && status == MOK;
		    pcs = walk_ctable(0))
			BEGIN_WALK_BY_DEST_LOOP (prs, pcs->class->name)
				status = MBUSY;
				break;
			END_WALK_LOOP

		if (status == MOK)
			for (pcs = walk_ctable(1); pcs; pcs = walk_ctable(0))
				_unload_class (pcs);

	/*
	 * Have we seen this class before?
	 */
	} else if (!(pcs = search_ctable(class)))
		status = MNODEST;

	/*
	 * Is there even one request queued for this class?
	 * If not, we can safely remove it.
	 */
	else {
		status = MOK;
		BEGIN_WALK_BY_DEST_LOOP (prs, class)
			status = MBUSY;
			break;
		END_WALK_LOOP
		if (status == MOK)
			_unload_class (pcs);
	}

	if (status == MOK)
		dump_cstatus ();

	mputm (md, R_UNLOAD_CLASS, status);
	return;
}

/*
 * s_inquire_class()
 */

void
s_inquire_class(char *m, MESG *md)
{
	char			*class;
	register CSTATUS	*pcs,
				*pcsnext;

	(void) getmessage(m, S_INQUIRE_CLASS, &class);
	syslog(LOG_DEBUG, "s_inquire_class(%s)", (class ? class : "NULL"));



	if (!*class || STREQU(class, NAME_ALL)) {
		/* inquire about ALL classes */
		pcs = walk_ctable(1);
		while (pcsnext = walk_ctable(0)) {
			send(md, R_INQUIRE_CLASS, MOKMORE,
			     pcs->class->name, pcs->status,
			     pcs->rej_reason, pcs->rej_date);
			pcs = pcsnext;
		}
	} else
		/* inquire about a single class */
		pcs = search_ctable(class);

	if (pcs)
		send(md, R_INQUIRE_CLASS, MOK, pcs->class->name, pcs->status,
			pcs->rej_reason, pcs->rej_date);
	else
		mputm (md, R_INQUIRE_CLASS, MNODEST, "", 0, "", 0L);

	return;
}

/*
 * s_paper_allowed()
 */

void
s_paper_allowed(char *m, MESG *md)
{
	char			*printer;
	char			*paperList = NULL;
	register PSTATUS	*pps, *ppsnext;

	(void) getmessage(m, S_PAPER_ALLOWED, &printer);
	syslog(LOG_DEBUG, "s_paper_allowed(%s)", (printer ? printer : "NULL"));


	if (!*printer || STREQU(printer, NAME_ALL)) {
		/* inquire about ALL printers */
		pps = walk_ptable(1);
		while (ppsnext = walk_ptable(0)) {
			paperList = sprintlist(pps->paper_allowed);
			send(md, R_PAPER_ALLOWED, MOKMORE, pps->printer->name,
				(paperList ? paperList : ""));
			if (paperList)
				Free(paperList);
			pps = ppsnext;
		}
	} else
		/* inquire about a specific printer */
		pps = search_ptable(printer);

	if (pps) {
		paperList = sprintlist(pps->paper_allowed);
		send(md, R_PAPER_ALLOWED, MOK, pps->printer->name,
			(paperList ? paperList : ""));
		if (paperList)
			Free(paperList);

	} else {
		mputm(md, R_PAPER_ALLOWED, MNODEST, "", "");
	}
}
