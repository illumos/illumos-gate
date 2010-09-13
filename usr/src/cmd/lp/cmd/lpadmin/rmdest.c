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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "stdio.h"
#include "ctype.h"
#include "errno.h"
#include "sys/types.h"

#include "lp.h"
#include "msgs.h"
#include "access.h"
#include "class.h"
#include "printers.h"

#define	WHO_AM_I	I_AM_LPADMIN
#include "oam.h"

#include "lpadmin.h"

extern void		fromallclasses();

/**
 ** rmdest() - REMOVE DESTINATION
 **/

void			rmdest (aclass, dest)
	int			aclass;
	char			*dest;
{
	int			rc,
				type;


	if (!aclass)
		type = S_UNLOAD_PRINTER;
	else
		type = S_UNLOAD_CLASS;


	send_message(type, dest, "", "");
	rc = output(type + 1);

	switch (rc) {
	case MOK:
	case MNODEST:
		BEGIN_CRITICAL
			if (
				aclass && delclass(dest) == -1
			     || !aclass && delprinter(dest) == -1
			) {
				if (rc == MNODEST && errno == ENOENT)
					LP_ERRMSG1 (
						ERROR,
						E_ADM_NODEST,
						dest
					);

				else
					LP_ERRMSG2 (
						ERROR,
(rc == MNODEST? (aclass? E_LP_DELCLASS : E_LP_DELPRINTER) : E_ADM_DELSTRANGE),
						dest,
						PERROR
					);

				done(1);
			}
		END_CRITICAL

		/*
		 * S_UNLOAD_PRINTER tells the Spooler to remove
		 * the printer from all classes (in its internal
		 * tables, of course). So it's okay for us to do
		 * the same with the disk copies.
		 */
		if (!aclass)
			fromallclasses (dest);

		if (STREQU(getdflt(), dest))
			newdflt (NAME_NONE);

		if (system_labeled) {
			update_dev_dbs(dest, NULL, "REMOVE");
		}
		break;

	case MBUSY:
		LP_ERRMSG1 (ERROR, E_ADM_DESTBUSY, dest);
		done (1);

	case MNOPERM:	/* taken care of up front */
	default:
		LP_ERRMSG1 (ERROR, E_LP_BADSTATUS, rc);
		done (1);
		break;

	}
	return;
}
