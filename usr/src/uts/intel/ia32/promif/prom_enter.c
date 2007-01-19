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

#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/archsystm.h>
#include <sys/reboot.h>
#include <sys/kdi.h>

/*
 * The Intel cpu does not have an underlying monitor.
 * So, we emulate the best we can.....
 */

void
prom_enter_mon(void)
{
#if defined(I386BOOT)
	return;
#endif

#if defined(_KMDB)
	prom_exit_to_mon();
#endif

	if (boothowto & RB_DEBUG)
		kmdb_enter();
	else {
		prom_printf("Press any key to continue.");
		(void) prom_getchar();
	}
}
