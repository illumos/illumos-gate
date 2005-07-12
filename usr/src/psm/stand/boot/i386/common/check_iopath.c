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

#include <sys/promif.h>
#include "multiboot.h"
#include "util.h"
#include "debug.h"

extern multiboot_info_t *mbi;

/* return the number of bits set to 1 */
static uint_t
count_bits(int val)
{
	int nbits = 0;

	while (val = (val ^ (val - 1)))
		nbits++;

	return (nbits);
}

/*
 * GRUB has loaded two identical modules, we compare the content
 * to check for potential problems in the BIOS I/O code path.
 * Andromeda appears to have problems with USB DVD drive, but IDE
 * drive works fine. This is a simple way to check it.
 */
void
check_iopath(void)
{
	mb_module_t *mod;
	char errbits = 0;
	uchar_t *cp1, *cp2;
	uint_t i, size1, size2;

	/* check # modules */
	if (mbi->mods_count != 2) {
		printf("The number of modules is not 2.\n");
		panic("reboot with modified GRUB menu");
	}

	/* check module sizes */
	mod = (mb_module_t *)mbi->mods_addr;
	cp1 = (uchar_t *)mod[0].mod_start;
	cp2 = (uchar_t *)mod[1].mod_start;
	size1 = mod[0].mod_end - mod[0].mod_start;
	size2 = mod[1].mod_end - mod[1].mod_start;
	printf("module 1: start = 0x%p, size = 0x%x (%s)\n",
	    (void *)cp1, size1, (char *)mod[0].string);
	printf("module 2: start = 0x%p, size = 0x%x (%s)\n",
	    (void *)cp2, size2, (char *)mod[1].string);

	if (size1 != size2) {
		printf("Module sizes are different!\n");
		panic("Check FAILED");
	}

	for (i = 0; i < size1; i++) {
		if (cp1[i] != cp2[i]) {
			printf("byte 0x%x differ: %2x, %2x\n",
			    i, cp1[i], cp2[i]);
			errbits += count_bits(cp1[i] ^ cp2[i]);
		}
	}
	if (errbits)
		panic("Check FAILED: err bit rate %d in %d bytes\n",
		    errbits, size1);
	else
		panic("Check PASSED: no bit error\n");
}
