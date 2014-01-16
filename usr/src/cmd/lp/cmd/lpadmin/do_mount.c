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
 * Copyright 1993 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.9	*/

#include "stdio.h"
#include "string.h"
#include "sys/types.h"

#include "lp.h"
#include "msgs.h"
#include "printers.h"
#include "form.h"
#include "access.h"

#define	WHO_AM_I	I_AM_LPADMIN
#include "oam.h"

#include "lpadmin.h"

extern FORM		formbuf;

void			mount_unmount();

short			printer_status;

static char		*cur_pwheel;
char			*disable_reason,
			*reject_reason;

static void		inquire_printer_status();

/**
 ** do_mount() - MOUNT/UNMOUNT A FORM/PRINT-WHEEL
 **/

void			do_mount (printer, form, pwheel)
	char			*printer,
				*form,
				*pwheel;
{
	/*
	 * Take care of unmounts, first.
	 */

	if (form && STREQU(form, NAME_NONE))
		form = "";
	if (pwheel && (STREQU(pwheel, NAME_ANY) || STREQU(pwheel, NAME_NONE)))
		pwheel = "";

	if (form && !*form && a)
		LP_ERRMSG (WARNING, E_ADM_UNALIGN);

	if (form && !*form && pwheel && !*pwheel) {
		mount_unmount (S_UNMOUNT, printer, NAME_NONE, NAME_ANY);
		form = 0;
		pwheel = 0;
	} else if (form && !*form) {
		mount_unmount (S_UNMOUNT, printer, NAME_NONE, "");
		form = 0;
	} else if (pwheel && !*pwheel) {
		mount_unmount (S_UNMOUNT, printer, "", NAME_ANY);
		pwheel = 0;
	}

	if (!form && !pwheel)
		return;

	/*
	 * See if the form will work on the printer. We do this even if
	 * the form has already been allowed, just in case the form has
	 * changed since then. Also, the check reads the form definition
	 * into a global that we can use for subsequent checks.
	 */
	if (!s) { /* a local printer */
		
	if (form && *form)
		switch (verify_form(form)) {
		case -1:
			LP_ERRMSG (WARNING, E_ADM_BADMOUNT);
			break;
		case -2:
			LP_ERRMSG1 (ERROR, E_ADM_MANDCHSET, formbuf.chset);
			done (1);
		}

	/*
	 * Is the form allowed on the printer?
	 */
	if (form && *form && !is_form_allowed_printer(form, printer))
		LP_ERRMSG2 (WARNING, E_ADM_ICKFORM, form, printer);


	/*
	 * Does the printer take print wheels?
	 * For us to be here, "daisy" must have been set.
	 * (-S requires knowing printer type (T), and knowing
	 * T caused call to "tidbit()" to set "daisy").
	 */
	if (pwheel && *pwheel && !daisy) {
		LP_ERRMSG (ERROR, E_ADM_NOPWHEEL);
		done (1);
	}

	/*
	 * If the form requires a particular print wheel, make sure
	 * it is either mounted already, or is being mounted now.
	 */
	if (form && *form) {
		/*
		 * The printer status is also needed for "do_align()".
		 */
		inquire_printer_status (printer);

		/*
		 * The "!daisy" case was investigated in "verify_form()".
		 */
		if (daisy && formbuf.mandatory && formbuf.chset)
			if (!pwheel || !*pwheel) {
				if (!STREQU(formbuf.chset, cur_pwheel))
					LP_ERRMSG1 (
						WARNING,
						E_ADM_MANDPWHEEL1,
						formbuf.chset
					);
			} else if (!STREQU(formbuf.chset, pwheel)) {
				LP_ERRMSG1 (
					WARNING,
					E_ADM_MANDPWHEEL2,
					formbuf.chset
				);
			}
	}

	/*
	 * Is the print wheel listed for this printer?
	 * The information that will tell us is either in the
	 * original info. we read in ("oldp->char_sets") if this
	 * is an existing printer, or--if this is a new printer--we
	 * don't have it (ambiguous -S options, mate!)
	 */
	if (
		pwheel
	     && *pwheel
	     && !(
			oldp
		     && searchlist(pwheel, oldp->char_sets)
		)
	)
		LP_ERRMSG2 (WARNING, E_ADM_ICKPWHEEL, pwheel, printer);

	}

	/*
	 * Do the mount with the printing of the alignment pattern,
	 * if required and possible. Otherwise, just mount the form
	 * (and print-wheel).
	 */
	if (!a || !do_align(printer, form, pwheel))
		mount_unmount (S_MOUNT, printer, NB(form), NB(pwheel));

	return;
}

void			mount_unmount (type, printer, form, pwheel)
	int			type;
	char			*printer,
				*form,
				*pwheel;
{
	int			rc;

	if (t) {  /* tray specified */
		type = (type == S_MOUNT ? S_MOUNT_TRAY : S_UNMOUNT_TRAY);
		send_message(type, printer, form, pwheel, t);
	} else
		send_message(type, printer, form, pwheel);

	rc = output(type + 1);

	switch(rc) {

	case MOK:
		break;

	case MNOMEDIA:
		LP_ERRMSG (ERROR, E_ADM_NOMEDIA);
		done (1);
		/*NOTREACHED*/

	case MNODEST:
		LP_ERRMSG1 (ERROR, E_ADM_NODEST, printer);
		done (1);
		/*NOTREACHED*/

	case MBUSY:
		LP_ERRMSG (ERROR, E_ADM_MNTLATER);
		done (1);
		/*NOTREACHED*/

	case MNOTRAY:
		LP_ERRMSG (ERROR, E_ADM_BADTRAY);
		done (1);
		/*NOTREACHED*/

	case MNOPERM:	/* taken care of up front */
	default:
		LP_ERRMSG1 (ERROR, E_LP_BADSTATUS, rc);
		done (1);
		/*NOTREACHED*/

	}
	return;
}

void
do_max_trays(char *printer)
{
	int			rc;

	if (t)  /* tray specified */
		send_message(S_MAX_TRAYS, printer, t);

	rc = output(R_MAX_TRAYS);

	switch(rc) {

	case MOK:
		break;

	case MNOMEDIA:
		LP_ERRMSG (ERROR, E_ADM_NOMEDIA);
		done (1);
		/*NOTREACHED*/

	case MNODEST:
		LP_ERRMSG1 (ERROR, E_ADM_NODEST, printer);
		done (1);
		/*NOTREACHED*/

	case MBUSY:
		LP_ERRMSG (ERROR, E_ADM_MNTLATER);
		done (1);
		/*NOTREACHED*/

	case MNOTRAY:
		LP_ERRMSG (ERROR, E_ADM_MAXTRAY);
		done (1);
		/*NOTREACHED*/

	case MNOPERM:	/* taken care of up front */
	default:
		LP_ERRMSG1 (ERROR, E_LP_BADSTATUS, rc);
		done (1);
		/*NOTREACHED*/

	}
	return;
}

/**
 ** inquire_printer_status()
 **/

static void		inquire_printer_status (printer)
	char			*printer;
{
	short			status;

	char			*s_ignore,
				buffer[MSGMAX];

	long			l_ignore;


	send_message (S_INQUIRE_PRINTER_STATUS, printer);
	if (mrecv(buffer, MSGMAX) != R_INQUIRE_PRINTER_STATUS) {
		LP_ERRMSG (ERROR, E_LP_MRECV);
		done (1);
	}
	(void)getmessage (
		buffer,
		R_INQUIRE_PRINTER_STATUS,
		&status,
		&s_ignore,
		&s_ignore,
		&cur_pwheel,
		&disable_reason,
		&reject_reason,
		&printer_status,
		&s_ignore,
		&l_ignore,
		&l_ignore
	);

	switch (status) {
	case MOK:
		disable_reason = strdup(disable_reason);
		reject_reason = strdup(reject_reason);
		cur_pwheel = strdup(cur_pwheel);
		break;

	case MNODEST:
		LP_ERRMSG1 (ERROR, E_LP_PGONE, printer);
		done (1);
	}

	return;
}
