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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/* change state of signal flag */

#pragma weak sigflag = _sigflag

#include "synonyms.h"
#include <sys/types.h>
#include <signal.h>

int
sigflag(int sig, int flag, int on)
{
	struct sigaction sa;
	int v;

	if ((v = sigaction(sig, 0, &sa)) < 0)
		return (v);
	if (on)
		sa.sa_flags |= flag;
	else
		sa.sa_flags &= ~flag;
	return (sigaction(sig, &sa, 0));
}
