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
 * Copyright 1991 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.11	*/

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <stdlib.h>
#include <libintl.h>

#include "lp.h"
#include "printers.h"
#include "msgs.h"

#define	WHO_AM_I	I_AM_LPADMIN
#include "oam.h"

#include "lpadmin.h"


extern char		*nameit(),
			*label;

static void		configure_pwheel();

/**
 ** do_pwheel() - SET ALERT FOR NEED TO MOUNT PRINT WHEEL
 **/

void			do_pwheel ()
{
	int			rc;


	if (A && STREQU(A, NAME_NONE)) {
		BEGIN_CRITICAL
			if (delpwheel(*S) == -1) {
				LP_ERRMSG1 (WARNING, E_ADM_BADPWHEEL, *S);
				return;
			}
		END_CRITICAL

	} else if (strlen(modifications))
		configure_pwheel (modifications);

	if (A && STREQU(A, NAME_LIST)) {
		if (label)
			(void) printf(gettext("Print wheel %s: "), label);
		printalert (stdout, &(oldS->alert), 0);
		return;
	}

	if (A && STREQU(A, NAME_QUIET)) {

		send_message(S_QUIET_ALERT, *S, (char *)QA_PRINTWHEEL, "");
		rc = output(R_QUIET_ALERT);

		switch(rc) {
		case MOK:
			break;

		case MNODEST:	/* not quite, but not a lie either */
		case MERRDEST:
			LP_ERRMSG1 (WARNING, E_LP_NOQUIET, *S);
			break;

		case MNOPERM:	/* taken care of up front */
		default:
			LP_ERRMSG1 (ERROR, E_LP_BADSTATUS, rc);
			done (1);
			/*NOTREACHED*/
		}

		return;
	}

	if (A && STREQU(A, NAME_NONE)) {
		send_message(S_UNLOAD_PRINTWHEEL, *S);
		rc = output(R_UNLOAD_PRINTWHEEL);
	} else {
		send_message(S_LOAD_PRINTWHEEL, *S);
		rc = output(R_LOAD_PRINTWHEEL);
	}

	switch(rc) {
	case MOK:
		break;

	case MNODEST:
		/*
		 * Should only occur if we're deleting a print wheel
		 * alert that doesn't exist.
		 */
		break;

	case MERRDEST:
		LP_ERRMSG (ERROR, E_ADM_ERRDEST);
		done (1);
		/*NOTREACHED*/

	case MNOSPACE:
		LP_ERRMSG (WARNING, E_ADM_NOPWSPACE);
		break;

	case MNOPERM:	/* taken care of up front */
	default:
		LP_ERRMSG1 (ERROR, E_LP_BADSTATUS, rc);
		done (1);
		/*NOTREACHED*/
	}
	return;
}

/**
 ** configure_pwheel() - SET OR CHANGE CONFIGURATION OF A PRINT WHEEL
 **/

static void		configure_pwheel (list)
	char			*list;
{
	register PWHEEL		*ppw;

	PWHEEL			pwheel_buf;

	char			type;


	if (oldS)
		ppw = oldS;
	else {
		ppw = &pwheel_buf;
		ppw->alert.shcmd = 0;
		ppw->alert.Q = 0;
		ppw->alert.W = 0;
	}

	while ((type = *list++) != '\0')  switch(type) {

	case 'A':
		if (STREQU(A, NAME_MAIL) || STREQU(A, NAME_WRITE))
			ppw->alert.shcmd = nameit(A);
		else
			ppw->alert.shcmd = A;

		break;

	case 'Q':
		ppw->alert.Q = Q;
		break;

	case 'W':
		ppw->alert.W = W;
		break;

	}

	BEGIN_CRITICAL
		if (putpwheel(*S, ppw) == -1) {
			LP_ERRMSG2 (
				ERROR,
				E_ADM_PUTPWHEEL,
				*S,
				PERROR
			);
			done(1);
		}
	END_CRITICAL

	return;
}
