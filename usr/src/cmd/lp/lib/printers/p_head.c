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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "sys/types.h"

#include "lp.h"
#include "printers.h"

struct {
	char			*v;
	short			len,
				okremote;
}			prtrheadings[PR_MAX] = {

#define	ENTRY(X)	X, sizeof(X)-1

	ENTRY("Banner:"),	   0,	/* PR_BAN */
	ENTRY("CPI:"),		   0,	/* PR_CPI */
	ENTRY("Character sets:"),  1,	/* PR_CS */
	ENTRY("Content types:"),   1,	/* PR_ITYPES */
	ENTRY("Device:"),	   0,	/* PR_DEV */
	ENTRY("Dial:"),		   0,	/* PR_DIAL */
	ENTRY("Fault:"),	   0,	/* PR_RECOV */
	ENTRY("Interface:"),	   0,	/* PR_INTFC */
	ENTRY("LPI:"),		   0,	/* PR_LPI */
	ENTRY("Length:"),	   0,	/* PR_LEN */
	ENTRY("Login:"),	   0,	/* PR_LOGIN */
	ENTRY("Printer type:"),    1,	/* PR_PTYPE */
	ENTRY("Remote:"),	   1,	/* PR_REMOTE */
	ENTRY("Speed:"),	   0,	/* PR_SPEED */
	ENTRY("Stty:"),		   0,	/* PR_STTY */
	ENTRY("Width:"),	   0,	/* PR_WIDTH */
#if	defined(CAN_DO_MODULES)
	ENTRY("Modules:"),	   0,	/* PR_MODULES */
#endif
	ENTRY("Options:"),		1, /* PR_OPTIONS */
	ENTRY("PPD:"),		   0,	/* PR_PPD */

#undef	ENTRY

};
