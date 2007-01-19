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

void
prom_panic(char *s)
{
	const char fmt[] = "%s: prom_panic: %s\n";

	if (s == NULL)
		s = "unknown panic";

#if defined(I386BOOT)
	prom_printf(fmt, "boot", s);
	for (;;)
		continue;
	/*NOTREACHED*/
#elif defined(_KMDB)
	prom_printf(fmt, "kmdb", s);
#elif defined(_KERNEL)
	prom_printf(fmt, "kernel", s);
	if (boothowto & RB_DEBUG)
		kmdb_enter();
#else
#error	"configuration error"
#endif
	prom_reboot_prompt();
	prom_reboot(NULL);
}
