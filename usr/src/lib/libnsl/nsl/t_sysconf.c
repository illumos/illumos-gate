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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <unistd.h>
#include <errno.h>
#include <stropts.h>
#include <sys/stream.h>
#include <assert.h>
#include <xti.h>
#include "tx.h"

int
_tx_sysconf(int name, int api_semantics)
{
	assert(api_semantics == TX_XTI_XNS5_API);
	if (name != _SC_T_IOV_MAX) {
		t_errno = TBADFLAG;
		return (-1);
	}
	return ((int)_sysconf(_SC_T_IOV_MAX));
}
