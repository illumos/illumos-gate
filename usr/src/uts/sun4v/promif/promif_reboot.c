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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif_impl.h>
#include <sys/hypervisor_api.h>

/*
 * By the time we reach this function we are single-threaded and
 * running at a high interrupt level.  It is too late to send
 * the boot args to LDoms Manager.  This is now done earlier --
 * see mdboot(), and thus the arg to this function is ignored.
 */

/*ARGSUSED*/
int
promif_reboot(void *p)
{
	int	rv = 0;

	prom_printf("Resetting...\n");

	rv = hv_mach_sir();

	/* should not return */
	ASSERT(0);

	return (rv);
}
