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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	Set default values in Err global structure.
 */

#include	"errmsg.h"

static	char	deftofix[] = "Refer to help error database or manual.";
static	char	*defsevmsg[] = {	/* default severity messages */
		"INFORM: ",
		"WARNING: ",
		"ERROR: ",
		"HALT: ",
		0
	};

struct Err	Err = {
					/* verbosity flags */
		/* vbell */	ENO,
		/* vprefix */	EYES,
		/* vsource */	EYES,
		/* vsevmsg */	EYES,
		/* vsyserr */	EDEF,
		/* vfix */	EYES,
		/* vtag */	EYES,
		/* vtext */	EYES,
					/* message content */
		/* prefix */	0,
		/* envsource */	0,
		/* source */	0,
		/* severity */	0,
		/* sevmsg */	defsevmsg,
		/* tofix */	deftofix,
		/* tagnum */	0,
		/* tagstr */	0,
		/* exit */	1,
};
