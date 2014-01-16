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
#include "requests.h"

/**
 ** freerequest() - FREE STRUCTURE ALLOCATED FOR A REQUEST STRUCTURE
 **/

void
#if	defined(__STDC__)
freerequest (
	REQUEST *		reqbufp
)
#else
freerequest (reqbufp)
	register REQUEST	*reqbufp;
#endif
{
	if (!reqbufp)
		return;
	if (reqbufp->destination)
		Free (reqbufp->destination);
	if (reqbufp->file_list)
		freelist (reqbufp->file_list);
	if (reqbufp->form)
		Free (reqbufp->form);
	if (reqbufp->alert)
		Free (reqbufp->alert);
	if (reqbufp->options)
		Free (reqbufp->options);
	if (reqbufp->pages)
		Free (reqbufp->pages);
	if (reqbufp->charset)
		Free (reqbufp->charset);
	if (reqbufp->modes)
		Free (reqbufp->modes);
	if (reqbufp->title)
		Free (reqbufp->title);
	if (reqbufp->input_type)
		Free (reqbufp->input_type);
	if (reqbufp->user)
		Free (reqbufp->user);
	Free (reqbufp);

	return;
}
