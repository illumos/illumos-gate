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
#include <sys/consdev.h>
#include <sys/promimpl.h>
#include <sys/archsystm.h>
#include <sys/reboot.h>
#include <sys/kdi.h>

/*
 * The Intel cpu does not have an underlying monitor.
 * So, we do the best we can.....
 */

extern void prom_poll_enter(void);

extern cons_polledio_t *cons_polledio;

void
prom_exit_to_mon(void)
{

#if !defined(_KMDB)
	prom_poll_enter();
#endif
#ifdef I386BOOT
	prom_printf("[spinning forever]\n");
	for (;;)
		continue;
#else
#if !defined(_KMDB)
	if (boothowto & RB_DEBUG)
		kmdb_enter();
#endif	/* !_KMDB */
	prom_reboot_prompt();
	prom_reboot(NULL);
#endif	/* !I386BOOT */
}

#if !defined(_KMDB)
void
prom_poll_enter(void)
{
	if (cons_polledio != NULL) {
		if (cons_polledio->cons_polledio_enter != NULL) {
			cons_polledio->cons_polledio_enter(
			    cons_polledio->cons_polledio_argument);
		}
	}
}
#endif
