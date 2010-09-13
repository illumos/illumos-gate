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

/*
 *	This file contains interface code to the kernel.
 */

/* LINTLIBRARY */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/ksynch.h>
#include <sys/cmn_err.h>
#include <sys/uio.h>
#include <sys/conf.h>
#include <sys/ddi.h>

#include <sys/nsctl/nsctl.h>
#include "nsc_list.h"

/*
 * _nsc_init_start
 *
 * ARGUMENTS:
 *
 * RETURNS:
 *
 * USAGE:
 *
 * CALLED BY:
 */
void
_nsc_init_start(void)
{
}

/*
 * _nsc_init_os -
 *
 * ARGUMENTS:
 *
 * RETURNS:
 *
 * USAGE:
 *
 * CALLED BY:
 */
void
_nsc_init_os(void)
{
}

/*
 * _nsc_deinit_os -
 *
 * ARGUMENTS:
 *
 * RETURNS:
 *
 * USAGE:
 *
 * CALLED BY:
 */
void
_nsc_deinit_os(void)
{
}

/* dummy routine unless RMS/MC is really running */
void
_nsc_self_alive()
{
}

/*
 * Check other nodes: checks for the heart_beat of other nodes and decides
 * if a node that was up went down... or a node that was down is now
 * up. Events NODE_UP and NODE_DOWN are posted to myself (this node)
 * Any processing that happens in these event handlers SHOULD abide by
 * the health monitor rules for the health monitor to work correctly.
 * If excessive computation during these events is required, consider the
 * possibility of forking of a process OR breaking up the computation into
 * smaller parts, and making sure that we call "SELF_ALIVE()" "often".
 * This is not the suggested mechanism, but there are times when we need it.
 */

void
_nsc_check_other_nodes()
{
}

/*
 * Is our partner active ? (Should never block)
 */
int
alternate_health_hbeat()
{
	return (0);
}


static int
mark_rm_pages_to_dump(addr, size, dump)
caddr_t addr;
int size, dump;
{
	return (0);
}


void
_nsc_mark_pages(caddr_t addr, size_t size, int dump)
{
	if (mark_rm_pages_to_dump(addr, (int)size, dump) < 0)
		cmn_err(CE_WARN, "_nsc_mark_pages: %s failed - 0x%p size %d",
			(dump ? "mark" : "unmark"), addr, (int)size);
}
