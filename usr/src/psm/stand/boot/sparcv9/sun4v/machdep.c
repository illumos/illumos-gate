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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/promif.h>
#include <sys/prom_plat.h>
#include <sys/salib.h>

int vac = 0;

/*
 * Check if the CPU is an UltraSPARC-1 or not.
 */
int
cpu_is_ultrasparc_1(void)
{
	return (0);
}

/*
 * Retain a page or reclaim a previously retained page of physical
 * memory for use by the prom upgrade. If successful, leave
 * an indication that a page was retained by creating a boolean
 * property in the root node.
 *
 * XXX: SUNW,retain doesn't work as expected on server systems,
 * so we don't try to retain any memory on those systems.
 *
 * XXX: do a '0 to my-self' as a workaround for 4160914
 */

int dont_retain_memory;

void
retain_nvram_page(void)
{
	unsigned long long phys = 0;
	static char create_prop[] =
	    "0 to my-self dev / 0 0 \" boot-retained-page\" property";
	extern int verbosemode;

	if (dont_retain_memory)
		return;

	if (prom_retain("OBPnvram", PAGESIZE, PAGESIZE, &phys) != 0) {
		printf("prom_retain failed\n");
		return;
	}
	if (verbosemode)
		printf("retained OBPnvram page at 0x%llx\n", phys);

	prom_interpret(create_prop, 0, 0, 0, 0, 0);
}
