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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma	weak _setlabel = setlabel

#include "lint.h"
#include "mtlib.h"
#include <pfmt.h>
#include <thread.h>
#include <string.h>
#include "pfmt_data.h"

int
setlabel(const char *label)
{
	lrw_wrlock(&_rw_pfmt_label);
	if (!label)
		__pfmt_label[0] = '\0';
	else {
		(void) strncpy(__pfmt_label, label, sizeof (__pfmt_label) - 1);
		__pfmt_label[sizeof (__pfmt_label) - 1] = '\0';
	}
	lrw_unlock(&_rw_pfmt_label);
	return (0);
}
