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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#include "dispatch.h"
#include <syslog.h>

/**
 ** remount_form() - MOUNT A FORM WHERE ANOTHER WAS MOUNTED
 **/

void
remount_form(register PSTATUS *pps, FSTATUS *pfs, short trayNum)
{
	trayNum--; /* make zero based */
	if (pps->forms && (pps->forms[trayNum].form == pfs)) {
		pps->forms[trayNum].isAvailable = (pfs ? 1 : 0);
					 /* force it */
		return;	/* nothing to do */
	} else if ((!pps->forms) && (!pfs)) {
		return;	/* nothing to do */
	}

	/*
	 * Unmount the old form.
	 */
	if (pps->forms && pps->forms[trayNum].form) {
		register FSTATUS	*Opfs	= pps->forms[trayNum].form;

		pps->forms[trayNum].form = 0;
		pps->forms[trayNum].isAvailable = 1;
		Opfs->mounted--;

		/*
		 * Unmounting the form may make some print requests
		 * no longer printable, because they were accepted
		 * only because the form was already mounted.
		 * Unmounting the form will also force some requests
		 * to another printer (where the form is mounted)
		 * so they can print.
		 */
		form_in_question = Opfs;
		(void)queue_repel (pps, 0, qchk_form);

		/*
		 * Maybe an alert is due.
		 */
		check_form_alert (Opfs, (_FORM *)0);
	}

	/*
	 * Mount the new form?
	 */
	if (pfs) {
		syslog(LOG_DEBUG, "remount_form add %x(%s) to tray %d\n",
			 pfs, (pfs ? pfs->form->name : "NULL"), trayNum);

		if (pps && !pps->forms) {
                        pps->forms = (PFSTATUS *)calloc((trayNum +1),
							sizeof(PFSTATUS));
			pps->numForms = trayNum + 1;
		}

		if (pps && pps->forms && (pps->numForms > trayNum)) {
			pps->forms[trayNum].form = pfs;
			pps->forms[trayNum].isAvailable = 1;
			pfs->mounted++;
		} else {
			return; /* nothing to do, can't mount form,
				   so no need to pretend we did */
		}


		/*
		 * Attract all the requests needing this newly mounted
		 * form. This may cause some unnecessary shuffling, but
		 * we have to ensure requests aren't assigned to a printer
		 * without the form mounted, so that the alert check is
		 * correct.
		 */
		if (pfs->requests) {
			form_in_question = pfs;
			queue_attract (pps, qchk_form, 0);

			/*
			 * Maybe an alert can be shut off.
			 */
			check_form_alert (pfs, (_FORM *)0);
		}

	} else {
		/*
		 * Attract first request that doesn't need a form mounted.
		 * We only need to get one request printing, because it
		 * completing will cause the next request to be attracted.
		 */
		form_in_question = 0;
		queue_attract (pps, qchk_form, 1);
	}

	dump_pstatus ();

	return;
}

/**
 ** remount_pwheel() - MOUNT A PRINT-WHEEL WHERE ANOTHER WAS MOUNTED
 **/

static void
remount_pwheel(register PSTATUS *pps, char *pwheel_name)
{
	PWSTATUS		*ppws;

	if (SAME(pps->pwheel_name, pwheel_name))
		return;	/* nothing to do */

	/*
	 * Unmount the old print wheel
	 */
	if (pps->pwheel_name) {
		register PWSTATUS	*Oppws	= pps->pwheel;

		pps->pwheel = 0;
		if (Oppws)
			Oppws->mounted--;

		/*
		 * Unmounting the print wheel may make some print
		 * requests no longer printable, because they were
		 * accepted only because the print wheel was already
		 * mounted. Unmounting the print wheel will also force
		 * some requests to another printer (where the print wheel
		 * is mounted) so they can print.
		 */
		pwheel_in_question = pps->pwheel_name;
		(void)queue_repel (pps, 0, qchk_pwheel);

		unload_str (&pps->pwheel_name);

		/*
		 * Maybe an alert is due.
		 */
		if (Oppws)
			check_pwheel_alert (Oppws, (PWHEEL *)0);
	}

	/*
	 * Mount the new print wheel?
	 */
	if (pwheel_name) {
		load_str (&pps->pwheel_name, pwheel_name);
		if (ppws = search_pwstatus(pwheel_name)) {
			pps->pwheel = ppws;
			ppws->mounted++;

			/*
			 * Attract all requests needing this newly
			 * mounted print wheel. This may cause some
			 * unnecessary shuffling, but we have to ensure
			 * requests aren't assigned to a printer without
			 * the print-wheel mounted, so that the alert
			 * check is correct.
			 */
			if (ppws->requests) {
				pwheel_in_question = pwheel_name;
				queue_attract (pps, qchk_pwheel, 0);

				/*
				 * Maybe an alert can be shut off.
				 */
				check_pwheel_alert (ppws, (PWHEEL *)0);
			}

		} else {
			/*
			 * Attract the first request that needs this newly
			 * mounted print wheel. If no alert has been
			 * defined for the print wheel, we don't know how
			 * many requests are queued waiting for it, so we
			 * have to do this unconditionally.
			 */
			pwheel_in_question = pwheel_name;
			queue_attract (pps, qchk_pwheel, 1);
		}

	} else {
		/*
		 * Attract the first request that doesn't need a
		 * print wheel mounted.
		 * We only need to get one request printing, because it
		 * completing will cause the next request to be attracted.
		 */
		pwheel_in_question = 0;
		queue_attract (pps, qchk_pwheel, 1);
	}

	dump_pstatus ();

	return;
}

#define MAX_TRAYS 100

/**
 ** s_max_trays()
 **/

void
s_max_trays(char *m, MESG *md)
{
	char			*printer;
	ushort			status;
	short numTrays;
	register PSTATUS	*pps;
	register PFSTATUS	*ppfs;

	(void) getmessage(m, S_MAX_TRAYS, &printer, &numTrays);
	syslog(LOG_DEBUG, "s_max_trays(%s, %d)", (printer ? printer : "NULL"),
	       numTrays);

	/* Have we seen this printer before? */
	if (!*printer || !(pps = search_pstatus(printer)))
		status = MNODEST;

	/* How about the tray? */
	else if ((numTrays <=0) || (numTrays > MAX_TRAYS))
		status = MNOTRAY;

	/* If the printer is currently printing, we can't disturb it. */
	else if (pps->request)
		    status = MBUSY;

	else if (pps->forms) {
		if (!(ppfs = Realloc(pps->forms,numTrays * sizeof(PFSTATUS))))
			status = MNOMEM;
		else {
			int i;

			for (i = pps->numForms; i < numTrays; i++) {
				ppfs[i].form = NULL;
				ppfs[i].isAvailable = 1;
			}
			pps->forms = ppfs;
			pps->numForms = numTrays;
			status = MOK;
		}
	} else if (!(ppfs = Calloc(numTrays,sizeof(PFSTATUS)))) {
		status = MNOMEM;
	} else  {
		pps->forms = ppfs;
		pps->numForms = numTrays;
		status = MOK;
	}
	dump_pstatus();
	mputm(md, R_MAX_TRAYS, status);
}

/**
 ** s_mount()
 **/

void
s_mount(char *m, MESG *md)
{
	char			*printer, *form, *pwheel_name;
	ushort			status;
	register PSTATUS	*pps;
	register FSTATUS	*pfs;

	(void) getmessage(m, S_MOUNT, &printer, &form, &pwheel_name);
	syslog(LOG_DEBUG, "s_mount(%s, %s, %s)", (printer ? printer : "NULL"),
	       (form ? form : "NULL"), (pwheel_name ? pwheel_name : "NULL"));

	if (!*form && !*pwheel_name)
		status = MNOMEDIA;

	/* Have we seen this printer before? */
	else if (!*printer || !(pps = search_pstatus(printer)))
		status = MNODEST;

	/* How about the form? */
	else if (*form && !(pfs = search_fstatus(form)))
		status = MNOMEDIA;

	/* If the printer is currently printing, we can't disturb it. */
	else if (pps->request)
		    status = MBUSY;

	else {
		/*
		 * Mount them.
		 */
		if (*form)
			remount_form (pps, pfs,1);
		if (*pwheel_name)
			remount_pwheel(pps, pwheel_name);

		status = MOK;
	}

	mputm(md, R_MOUNT, status);
}

/*
 * s_mount_tray()
 */

void
s_mount_tray(char *m, MESG *md)
{
	char			*printer, *form, *pwheel_name;
	ushort			status;
	short			trayNum;
	register PSTATUS	*pps;
	register FSTATUS	*pfs;

	(void) getmessage(m, S_MOUNT_TRAY, &printer, &form, &pwheel_name,
		&trayNum);
	syslog(LOG_DEBUG, "s_mount_tray(%s, %s, %s, %d)",
	       (printer ? printer : "NULL"), (form ? form : "NULL"),
	       (pwheel_name ? pwheel_name : "NULL"), trayNum);

	if (!*form && !*pwheel_name)
		status = MNOMEDIA;

	/* Have we seen this printer before? */
	else if (!*printer || !(pps = search_pstatus(printer)))
		status = MNODEST;

	/* How about the form? */
	else if (*form && !(pfs = search_fstatus(form)))
		status = MNOMEDIA;

	/* How about the tray? */
	else if ((trayNum <=0) || (trayNum > pps->numForms))
		status = MNOTRAY;

	/* If the printer is currently printing, we can't disturb it. */
	else if (pps->request)
		    status = MBUSY;

	else {
		/*
		 * Mount them.
		 */
		if (*form)
			remount_form(pps, pfs,trayNum);
		if (*pwheel_name)
			remount_pwheel(pps, pwheel_name);

		status = MOK;
	}

	mputm (md, R_MOUNT_TRAY, status);
}

/**
 ** s_unmount()
 **/

void
s_unmount(char *m, MESG *md)
{
	char			*printer,
				*form,
				*pwheel_name;
	ushort			status;
	register PSTATUS	*pps;

	(void)getmessage (m, S_UNMOUNT, &printer, &form, &pwheel_name);
	syslog(LOG_DEBUG, "s_unmount(%s, %s, %s)",
	       (printer ? printer : "NULL"), (form ? form : "NULL"),
	       (pwheel_name ? pwheel_name : "NULL"));

	if (!*form && !*pwheel_name)
		status = MNOMEDIA;

	/*
	 * Have we seen this printer before?
	 */
	else if (!*printer || !(pps = search_pstatus(printer)))
		status = MNODEST;


	/*
	 * If the printer is currently printing a request,
	 * we can't unmount the current form/pwheel.
	 */
	else if (pps->request)
		status = MBUSY;

	else {
		/*
		 * Unmount them.
		 */
		if (*form)
			remount_form (pps, (FSTATUS *)0,1);
		if (*pwheel_name)
			remount_pwheel (pps, (char *)0);

		status = MOK;
	}

	mputm (md, R_UNMOUNT, status);
	return;
}
/**
 ** s_unmount_tray()
 **/

void
s_unmount_tray(char *m, MESG *md)
{
	char			*printer,
				*form,
				*pwheel_name;

	ushort			status;
	short			trayNum;

	register PSTATUS	*pps;

	(void)getmessage (m, S_UNMOUNT_TRAY, &printer, &form, &pwheel_name,
		&trayNum);
	syslog(LOG_DEBUG, "s_unmount_tray(%s, %s, %s, %d)",
	       (printer ? printer : "NULL"), (form ? form : "NULL"),
	       (pwheel_name ? pwheel_name : "NULL"), trayNum);


	if (!*form && !*pwheel_name)
		status = MNOMEDIA;

	else if (!*printer || !(pps = search_pstatus(printer)))
		/* haven't seen this printer before */
		status = MNODEST;
	else if ((trayNum <=0) || (trayNum > pps->numForms))
		/* haven't seen the tray before */
		status = MNOTRAY;
	else if (pps->request)
		/* is the printer busy */
		status = MBUSY;
	else {
		/* Unmount them. */
		if (*form)
			remount_form (pps, (FSTATUS *)0,trayNum);
		if (*pwheel_name)
			remount_pwheel (pps, (char *)0);

		status = MOK;
	}

	mputm (md, R_UNMOUNT_TRAY, status);
	return;
}

/**
 ** s_load_form()
 **/

void
s_load_form(char *m, MESG *md)
{
	char			*form;
	ushort			status;
	register _FORM		*pf;
	register FSTATUS	*pfs;

	(void)getmessage (m, S_LOAD_FORM, &form);
	syslog(LOG_DEBUG, "s_load_form(%s)", (form ? form : "NULL"));

	if (!*form)
		/* no form specified */
		status = MNODEST;
	else if (!(pf = Getform(form))) {
		/* strange or missing form */
		switch (errno) {
		case EBADF:
			status = MERRDEST;
			break;
		case ENOENT:
		default:
			status = MNODEST;
			break;
		}

	} else if ((pfs = search_fstatus(form))) {
		/* Have we seen this form before? */
		unload_list (&pfs->users_allowed);
		unload_list (&pfs->users_denied);
		load_userform_access (
			pf->name,
			&pfs->users_allowed,
			&pfs->users_denied
		);

		load_sdn (&pfs->cpi, pf->cpi);
		load_sdn (&pfs->lpi, pf->lpi);
		load_sdn (&pfs->plen, pf->plen);
		load_sdn (&pfs->pwid, pf->pwid);


		/*
		 * These have to be done in the order shown,
		 * and after the assignments above, so that all
		 * the new information is in place for the
		 * checks. An unfortunate side effect is that
		 * it is possible for the alert to shut off
		 * and then come on again, if (1) enough requests
		 * are canceled to drop the level below the old
		 * alert threshold, but (2) the new alert threshold
		 * is even lower. The final alert will be correct,
		 * though.
		 */

		form_in_question = pfs;
		queue_check (qchk_form);

		check_form_alert (pfs, pf);


		status = MOK;

	/*
	 * Room for a new form?
	 */
	} else if ((pfs = new_fstatus(pf))) {
		/*
		 * No alert is possible for a new form, of course,
		 * but this routine does a bit more than just check
		 * the alert.
		 */
		check_form_alert (pfs, pf);
		status = MOK;
	} else {
		free_form (pf);
		status = MNOSPACE;
	}

	mputm (md, R_LOAD_FORM, status);
	return;
}

/**
 ** s_unload_form()
 **/

static void
_unload_form(register FSTATUS *pfs)
{
	int i;
	short numForms;
	PFSTATUS *ppfs;

	/*
	 * Unmount this form everywhere and get rid of it.
	 */
	for (i = 0; PStatus != NULL && PStatus[i] != NULL; i++)
		if (((ppfs = PStatus[i]->forms) != NULL) &&
		    ((numForms = PStatus[i]->numForms) > 0)) {
			int j;
			for ( j = 0 ; j < numForms ; j++ )
				if (ppfs[j].form == pfs) ppfs[j].form= NULL;
		}

	return;
}

void
s_unload_form(char *m, MESG *md)
{
	char			*form;
	ushort			status;
	RSTATUS			*prs;
	register FSTATUS	*pfs;

	(void)getmessage (m, S_UNLOAD_FORM, &form);
	syslog(LOG_DEBUG, "s_unload_form(%s)", (form ? form : "NULL"));

	if (!*form || STREQU(form, NAME_ALL)) {
		int i;
		/* If we have a request queued for ANY form, we can't do it. */
		status = MOK;
		for (i = 0; FStatus != NULL && FStatus[i] != NULL &&
			    status == MOK; i++) {
			for (prs = Request_List; prs != NULL; prs = prs->next)
				if (prs->form == FStatus[i]) {
					status = MBUSY;
					break;
				}
		}

		if (status == MOK) {
			for (i = 0; FStatus != NULL && FStatus[i] != NULL; i++)
				_unload_form (FStatus[i]);
			free(FStatus);
			FStatus = NULL;
		}

	} else if (!*form || !(pfs = search_fstatus(form)))
		/* Have we seen this form before? */
		status = MNODEST;
	else {
		/* Is there even one request waiting for this form? */
		status = MOK;
		for (prs = Request_List; prs != NULL; prs = prs->next)
			if (prs->form == pfs) {
				status = MBUSY;
				break;
			}

		if (status == MOK) {
			_unload_form (pfs);
			list_remove((void ***)&FStatus, (void *)pfs);
		}
	}

	mputm (md, R_UNLOAD_FORM, status);
	return;
}

/**
 ** s_load_printwheel()
 **/

void
s_load_printwheel(char *m, MESG *md)
{
	char			*pwheel_name;
	ushort			status;
	register PWHEEL		*ppw;
	register PWSTATUS	*ppws;

	(void)getmessage (m, S_LOAD_PRINTWHEEL, &pwheel_name);
	syslog(LOG_DEBUG, "s_load_printwheel(%s)",
	       (pwheel_name ? pwheel_name : "NULL"));

	if (!*pwheel_name)
		/* no printwheel specified */
		status = MNODEST;
	else if (!(ppw = Getpwheel(pwheel_name))) {
		/* Strange or missing print wheel? */
		switch (errno) {
		case EBADF:
			status = MERRDEST;
			break;
		case ENOENT:
		default:
			status = MNODEST;
			break;
		}
	} else if ((ppws = search_pwstatus(pwheel_name))) {
		/* Print wheel we already know about? */
		check_pwheel_alert (ppws, ppw);
		status = MOK;
	} else if ((ppws = new_pwstatus(ppw))) {
		/* Room for a new print wheel? */
		register RSTATUS 	*prs;

		/*
		 * Because of the quirky nature of the print wheel
		 * structures, i.e. no structure unless an alert has
		 * been defined, we have to run through the requests
		 * and see which ones are waiting for this print wheel,
		 * so we can assign alerts and count pending requests.
		 */
		for (prs = Request_List; prs != NULL; prs = prs->next)
			if ((prs->pwheel_name == pwheel_name) &&
			    (!one_printer_with_charsets(prs))) {
				prs->pwheel = ppws;
				ppws->requests++;
			}
		check_pwheel_alert (ppws, ppw);

		status = MOK;
	} else {
		freepwheel (ppw);
		status = MNOSPACE;
	}

	mputm (md, R_LOAD_PRINTWHEEL, status);
	return;
}

/**
 ** s_unload_printwheel()
 **/

static void
_unload_pwheel(register PWSTATUS *ppws)
{
	register PSTATUS		*pps;
	register RSTATUS		*prs;
	int i;


	/*
	 * ``Unmount'' the alert part of this print wheel everywhere.
	 * THIS IS NOT A COMPLETE UNMOUNT, JUST THE ALERT STRUCTURE
	 * IS REMOVED.
	 */
	for (i = 0; PStatus != NULL && PStatus[i] != NULL; i++)
		if (PStatus[i]->pwheel == ppws)
			PStatus[i]->pwheel = 0;

	/*
	 * Remove the alert part from all requests.
	 */
	for (prs = Request_List; prs; prs = prs->next)
		if (prs->pwheel == ppws)
			prs->pwheel = 0;

	/*
	 * Cancel any alert pending. Here we're different from the
	 * similar code for unloading a form, because, to be able to
	 * unload a form we first require NO requests pending. If no
	 * requests are pending there should be no alert to cancel.
	 * Print wheels, on the other hand, only exist as names and
	 * alerts. We can always unload a ``print wheel'' because
	 * all we're really unloading is an alert. Thus, there can
	 * be requests queued for the print wheel (the name), and
	 * thus there can be an alert running.
	 */
	if (ppws->alert->active)
		cancel_alert (A_PWHEEL, ppws);

	free_pwstatus(ppws);

	return;
}

void
s_unload_printwheel(char *m, MESG *md)
{
	char			*pwheel_name;

	ushort			status;

	register PWSTATUS	*ppws;


	/*
	 * We don't care if any requests are waiting for the print
	 * wheel(s)--what we're removing here is (are) just the alert(s)!
	 */

	(void)getmessage (m, S_UNLOAD_PRINTWHEEL, &pwheel_name);
	syslog(LOG_DEBUG, "s_unload_printwheel(%s)",
	       (pwheel_name ? pwheel_name : "NULL"));


	/*
	 * Remove all print wheel alerts?
	 */
	if (!*pwheel_name || STREQU(pwheel_name, NAME_ALL)) {
		int i;

		for (i = 0; PWStatus != NULL && PWStatus[i] != NULL; i++)
			_unload_pwheel (PWStatus[i]);
		free(PWStatus);
		PWStatus = NULL;
		status = MOK;

	/*
	 * Have we seen this print wheel before?
	 */
	} else if (!(ppws = search_pwstatus(pwheel_name)))
		status = MNODEST;

	else {
		_unload_pwheel (ppws);
		list_remove((void ***)&PWStatus, (void *)ppws);
		status = MOK;

	}

	mputm (md, R_UNLOAD_PRINTWHEEL, status);
	return;
}
