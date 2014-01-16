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


#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "sys/types.h"
#include "stdlib.h"

#include "lp.h"
#include "printers.h"
#include <syslog.h>

/**
 **  freeprinter() - FREE MEMORY ALLOCATED FOR PRINTER STRUCTURE
 **/

void			freeprinter (pp)
	PRINTER			*pp;
{
	if (!pp)
		return;

	syslog(LOG_DEBUG, "freeprinter(%s)", pp->name ? pp->name : "");
	if (pp->name)
		Free (pp->name);
	if (pp->char_sets)
		freelist (pp->char_sets);
	if (pp->input_types)
		freelist (pp->input_types);
	if (pp->options)
		freelist (pp->options);
	if (pp->device)
		Free (pp->device);
	if (pp->dial_info)
		Free (pp->dial_info);
	if (pp->fault_rec)
		Free (pp->fault_rec);
	if (pp->interface)
		Free (pp->interface);
	if (pp->printer_type)
		Free (pp->printer_type);
	if (pp->remote)
		Free (pp->remote);
	if (pp->speed)
		Free (pp->speed);
	if (pp->stty)
		Free (pp->stty);
	if (pp->description)
		Free (pp->description);
	if (pp->fault_alert.shcmd)
		Free (pp->fault_alert.shcmd);
#if	defined(CAN_DO_MODULES)
	if (pp->modules)
		freelist (pp->modules);
#endif
	if (pp->printer_types)
		freelist (pp->printer_types);
	Free (pp);

	return;
}
