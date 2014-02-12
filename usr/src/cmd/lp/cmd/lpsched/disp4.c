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


#include "time.h"
#include "dispatch.h"
#include <syslog.h>


/**
 ** s_accept_dest()
 **/

void
s_accept_dest(char *m, MESG *md)
{
	char			*destination;
	ushort			status;
	register PSTATUS	*pps;
	register CLSTATUS	*pcs;

	getmessage (m, S_ACCEPT_DEST, &destination);
	syslog(LOG_DEBUG, "s_accept_dest(%s)",
	       (destination ? destination : "NULL"));

	/*
	 * Have we seen this destination as a printer?
	 */
	if ((pps = search_pstatus(destination)))
		if ((pps->status & PS_REJECTED) == 0)
			status = MERRDEST;
		else {
			pps->status &= ~PS_REJECTED;
			(void) time (&pps->rej_date);
			dump_pstatus ();
			status = MOK;
		}

	/*
	 * Have we seen this destination as a class?
	 */
	else if ((pcs = search_cstatus(destination)))
		if ((pcs->status & CS_REJECTED) == 0)
			status = MERRDEST;
		else {
			pcs->status &= ~CS_REJECTED;
			(void) time (&pcs->rej_date);
			dump_cstatus ();
			status = MOK;
		}

	else
		status = MNODEST;

	mputm (md, R_ACCEPT_DEST, status);
	return;
}

/**
 ** s_reject_dest()
 **/

void
s_reject_dest(char *m, MESG *md)
{
	char			*destination,
				*reason;
	ushort			status;
	register PSTATUS	*pps;
	register CLSTATUS	*pcs;


	getmessage (m, S_REJECT_DEST, &destination, &reason);
	syslog(LOG_DEBUG, "s_reject_dest(%s, %s)",
	       (destination ? destination : "NULL"),
	       (reason ? reason : "NULL"));

	/*
	 * Have we seen this destination as a printer?
	 */
	if ((pps = search_pstatus(destination)))
		if (pps->status & PS_REJECTED)
			status = MERRDEST;
		else {
			pps->status |= PS_REJECTED;
			(void) time (&pps->rej_date);
			load_str (&pps->rej_reason, reason);
			dump_pstatus ();
			status = MOK;
		}

	/*
	 * Have we seen this destination as a class?
	 */
	else if ((pcs = search_cstatus(destination)))
		if (pcs->status & CS_REJECTED)
			status = MERRDEST;
		else {
			pcs->status |= CS_REJECTED;
			(void) time (&pcs->rej_date);
			load_str (&pcs->rej_reason, reason);
			dump_cstatus ();
			status = MOK;
		}

	else
		status = MNODEST;

	mputm (md, R_REJECT_DEST, status);
	return;
}

/**
 ** s_enable_dest()
 **/

void
s_enable_dest(char *m, MESG *md)
{
	char			*printer;
	ushort			status;
	register PSTATUS	*pps;


	getmessage (m, S_ENABLE_DEST, &printer);
	syslog(LOG_DEBUG, "s_enable_dest(%s)", (printer ? printer : "NULL"));

	/*
	 * Have we seen this printer before?
	 */
	if ((pps = search_pstatus(printer)))
		if (enable(pps) == -1)
			status = MERRDEST;
		else
			status = MOK;
	else
		status = MNODEST;

	mputm (md, R_ENABLE_DEST, status);
	return;
}

/**
 ** s_disable_dest()
 **/

void
s_disable_dest(char *m, MESG *md)
{
	char			*destination,
				*reason,
				*req_id		= 0;
	ushort			when,
				status;
	register PSTATUS	*pps;

	getmessage (m, S_DISABLE_DEST, &destination, &reason, &when);
	syslog(LOG_DEBUG, "s_disable_dest(%s, %s, %d)",
	       (destination ? destination : "NULL"),
	       (reason ? reason : "NULL"), when);


	/*
	 * Have we seen this printer before?
	 */
	if ((pps = search_pstatus(destination))) {

		/*
		 * If we are to cancel a currently printing request,
		 * we will send back the request's ID.
		 * Save a copy of the ID before calling "disable()",
		 * in case the disabling loses it (e.g. the request
		 * might get attached to another printer). (Actually,
		 * the current implementation won't DETACH the request
		 * from this printer until the child process responds,
		 * but a future implementation might.)
		 */
		if (pps->request && when == 2)
			req_id = Strdup(pps->request->secure->req_id);

		if (disable(pps, reason, (int)when) == -1) {
			if (req_id) {
				Free (req_id);
				req_id = 0;
			}
			status = MERRDEST;
		} else
			status = MOK;

	} else
		status = MNODEST;

	mputm (md, R_DISABLE_DEST, status, NB(req_id));
	if (req_id)
		Free (req_id);

	return;
}

/**
 ** s_load_filter_table()
 **/

void
s_load_filter_table(char *m, MESG *md)
{
	ushort			status;

	syslog(LOG_DEBUG, "s_load_filter_table()");

	trash_filters ();
	if (Loadfilters((char *)0) == -1)
		status = MNOOPEN;
	else {
		/*
		 * This is what makes changing filters expensive!
		 */
		queue_check (qchk_filter);

		status = MOK;
	}

	mputm (md, R_LOAD_FILTER_TABLE, status);
	return;
}

/**
 ** s_unload_filter_table()
 **/

void
s_unload_filter_table(char *m, MESG *md)
{
	syslog(LOG_DEBUG, "s_unload_filter_table()");

	trash_filters ();

	/*
	 * This is what makes changing filters expensive!
	 */
	queue_check (qchk_filter);

	mputm (md, R_UNLOAD_FILTER_TABLE, MOK);
	return;
}

/**
 ** s_load_user_file()
 **/

void
s_load_user_file(char *m, MESG *md)
{
	/*
	 * The first call to "getuser()" will load the whole file.
	 */
	syslog(LOG_DEBUG, "s_load_user_file()");

	trashusers ();

	mputm (md, R_LOAD_USER_FILE, MOK);
	return;
}

/**
 ** s_unload_user_file()
 **/

void
s_unload_user_file(char *m, MESG *md)
{
	syslog(LOG_DEBUG, "s_unload_user_file()");

	trashusers ();	/* THIS WON'T DO TRUE UNLOAD, SORRY! */

	mputm (md, R_UNLOAD_USER_FILE, MOK);
	return;
}
/**
 ** s_shutdown()
 **/

void
s_shutdown(char *m, MESG *md)
{
	ushort			immediate;

	(void)getmessage (m, S_SHUTDOWN, &immediate);
	syslog(LOG_DEBUG, "s_shutdown(%d)", immediate);

	switch (md->type) {
	case MD_STREAM:
	case MD_SYS_FIFO:
	case MD_USR_FIFO:
		mputm (md, R_SHUTDOWN, MOK);
		lpshut (immediate);
		/*NOTREACHED*/
	default:
		syslog(LOG_DEBUG,
		       "Received S_SHUTDOWN on a type %d connection\n",
		       md->type);
	}

	return;
}

/**
 ** s_quiet_alert()
 **/

void
s_quiet_alert(char *m, MESG *md)
{
	char			*name;
	ushort			type,
				status;
	register FSTATUS	*pfs;
	register PSTATUS	*pps;
	register PWSTATUS	*ppws;


	/*
	 * We quiet an alert by cancelling it with "cancel_alert()"
	 * and then resetting the active flag. This effectively just
	 * terminates the process running the alert but tricks the
	 * rest of the Spooler into thinking it is still active.
	 * The alert will be reactivated only AFTER "cancel_alert()"
	 * has been called (to clear the active flag) and then "alert()"
	 * is called again. Thus:
	 *
	 * For printer faults the alert will be reactivated when:
	 *	- a fault is found after the current fault has been
	 *	  cleared (i.e. after successful print or after manually
	 *	  enabled).
	 *
	 * For forms/print-wheels the alert will be reactivated when:
	 *	- the form/print-wheel becomes mounted and then unmounted
	 *	  again, with too many requests still pending;
	 *	- the number of requests falls below the threshold and
	 *	  then rises above it again.
	 */

	(void)getmessage (m, S_QUIET_ALERT, &name, &type);
	syslog(LOG_DEBUG, "s_quiet_alert(%s, %d)", (name ? name : "NULL"),
	       type);

	if (!*name)
		status = MNODEST;

	else switch (type) {
	case QA_FORM:
		if (!(pfs = search_fstatus(name)))
			status = MNODEST;

		else if (!pfs->alert->active)
			status = MERRDEST;

		else {
			cancel_alert (A_FORM, pfs);
			pfs->alert->active = 1;
			status = MOK;
		}
		break;
		
	case QA_PRINTER:
		if (!(pps = search_pstatus(name)))
			status = MNODEST;

		else if (!pps->alert->active)
			status = MERRDEST;

		else {
			cancel_alert (A_PRINTER, pps);
			pps->alert->active = 1;
			status = MOK;
		}
		break;
		
	case QA_PRINTWHEEL:
		if (!(ppws = search_pwstatus(name)))
			status = MNODEST;

		else if (!ppws->alert->active)
			status = MERRDEST;

		else {
			cancel_alert (A_PWHEEL, ppws);
			ppws->alert->active = 1;
			status = MOK;
		}
		break;
	}
	
	mputm (md, R_QUIET_ALERT, status);
	return;
}

/**
 ** s_send_fault()
 **/

void
s_send_fault(char *m, MESG *md)
{
	long			key;
	char			*printerOrForm, *alert_text;
	ushort			status;
	register PSTATUS	*pps;

	getmessage (m, S_SEND_FAULT, &printerOrForm, &key, &alert_text);
	syslog(LOG_DEBUG, "s_send_fault(%s, %x, %s)",
	       (printerOrForm ? printerOrForm : "NULL"), key,
	       (alert_text ? alert_text : "NULL"));

	if (!(pps = search_pstatus(printerOrForm)) || (!pps->exec) ||
		pps->exec->key != key || !pps->request) {
		status = MERRDEST;
	} else {
		printer_fault(pps, pps->request, alert_text, 0);
		status = MOK;
	}

	mputm (md, R_SEND_FAULT, status);
}

/*
 * s_clear_fault()
 */
void
s_clear_fault(char *m, MESG *md)
{
	long	key;
	char	*printerOrForm, *alert_text;
	ushort	status;
	register PSTATUS	*pps;

	getmessage(m, S_CLEAR_FAULT, &printerOrForm, &key, &alert_text);
	syslog(LOG_DEBUG, "s_clear_fault(%s, %x, %s)",
	       (printerOrForm ? printerOrForm : "NULL"), key,
	       (alert_text ? alert_text : "NULL"));


	if (! (pps = search_pstatus(printerOrForm)) || ((key > 0) &&
	    ((!pps->exec) || pps->exec->key != key || !pps->request ))) {
		status = MERRDEST;
	} else {
		clear_printer_fault(pps, alert_text);
		status = MOK;
	}

	mputm (md, R_CLEAR_FAULT, status);
}


/*
 * s_paper_changed()
 */
void
s_paper_changed(char *m, MESG *md)
{
	short			trayNum, mode, pagesPrinted;
	char			*printer, *paper;
	ushort			status;
	short			chgd = 0;
	register PSTATUS	*pps;
	register FSTATUS	*pfs,*pfsWas;

	getmessage(m, S_PAPER_CHANGED, &printer, &trayNum, &paper, &mode,
		&pagesPrinted);
	syslog(LOG_DEBUG, "s_paper_changed(%s, %d, %s, %d, %d)",
	       (printer ? printer : "NULL"), trayNum, (paper ? paper : "NULL"),
	       mode, pagesPrinted);

	if (!(pps = search_pstatus(printer)))
		status = MNODEST;
	else if ((trayNum <=0) || (trayNum > pps->numForms))
		status = MNOTRAY;
	else {
		status = MOK;
		if (*paper && (pfsWas = pps->forms[trayNum-1].form) && 
		    (!STREQU(pfsWas->form->paper,paper))) {
			pfs = search_fptable(paper);
			if (pfs) {
				remount_form(pps, pfs, trayNum);
				chgd = 1;
			} else
				status = MNOMEDIA;
		}
		if ( status == MOK ) {
			pps->forms[trayNum].isAvailable = mode;
			if ((chgd || !mode) && (!pagesPrinted) && pps->exec) {
				if (pps->request)
					pps->request->request->outcome |=
						RS_STOPPED;
				terminate(pps->exec);
				schedule(EV_LATER, 1, EV_INTERF, pps);
			}
		}
	}
	mputm(md, R_PAPER_CHANGED, status);
}

