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


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.7	*/

#include "stdio.h"
#include "string.h"
#include "sys/types.h"

#include "lp.h"
#include "printers.h"
#include "msgs.h"
#include "requests.h"

#define	WHO_AM_I	I_AM_LPADMIN
#include "oam.h"

#include "lpadmin.h"


/**
 ** output() - (MISNOMER) HANDLE MESSAGES BACK FROM SPOOLER
 **/

int			output (type)
	int			type;
{
	char			buffer[MSGMAX];

	int			rc;

	short			status;
	char			*dummy;


	if (!scheduler_active)
		switch (type) {

		case R_MOUNT_TRAY:
		case R_UNMOUNT_TRAY:
		case R_MOUNT:
		case R_UNMOUNT:
		case R_MAX_TRAYS:
		case R_QUIET_ALERT:
		case R_INQUIRE_PRINTER_STATUS:
		case R_ALLOC_FILES:
		case R_PRINT_REQUEST:
		case R_REJECT_DEST:
		case R_ACCEPT_DEST:
		case R_DISABLE_DEST:
		case R_ENABLE_DEST:
		case R_CANCEL_REQUEST:
		default:
			LP_ERRMSG (ERROR, E_LP_NEEDSCHED);
			done (1);

		case R_UNLOAD_PRINTER:
		case R_UNLOAD_CLASS:
		case R_UNLOAD_PRINTWHEEL:
			if (anyrequests()) {
				LP_ERRMSG (ERROR, E_LP_HAVEREQS);
				done (1);
			}
			/* fall through */

		case R_LOAD_PRINTER:
		case R_LOAD_CLASS:
		case R_LOAD_PRINTWHEEL:
			return (MOK);

		}

	status = MOKMORE;
	while (status == MOKMORE) {

		if ((rc = mrecv(buffer, MSGMAX)) != type) {
			LP_ERRMSG (ERROR, E_LP_MRECV);
			done (1);
		}
			
		switch(type) {

		case R_MOUNT_TRAY:
		case R_UNMOUNT_TRAY:
		case R_MOUNT:
		case R_UNMOUNT:
		case R_MAX_TRAYS:
		case R_LOAD_PRINTER:
		case R_UNLOAD_PRINTER:
		case R_LOAD_CLASS:
		case R_UNLOAD_CLASS:
		case R_LOAD_PRINTWHEEL:
		case R_UNLOAD_PRINTWHEEL:
		case R_QUIET_ALERT:
		case R_REJECT_DEST:
		case R_ACCEPT_DEST:
		case R_ENABLE_DEST:
		case R_CANCEL_REQUEST:
			rc = getmessage(buffer, type, &status);
			goto CheckRC;

		case R_DISABLE_DEST:
			rc = getmessage(buffer, type, &status, &dummy);
CheckRC:		if (rc != type) {
				LP_ERRMSG1 (ERROR, E_LP_BADREPLY, rc);
				done (1);
			}
			break;

		case R_INQUIRE_PRINTER_STATUS:
		case R_ALLOC_FILES:
		case R_PRINT_REQUEST:
			return (0);	/* handled by caller */
		}

	}

	return (status);
}
