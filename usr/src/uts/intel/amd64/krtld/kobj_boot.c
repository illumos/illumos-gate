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

/*
 * Bootstrap the linker/loader.
 */

#include <sys/types.h>
#include <sys/bootconf.h>
#include <sys/link.h>
#include <sys/auxv.h>
#include <sys/kobj.h>
#include <sys/bootsvcs.h>
#include <vm/kboot_mmu.h>
#include <sys/kobj_impl.h>

/*
 * the kernel's entry point (from locore.s)
 */
extern void _locore_start();

/*
 * fakebop and dboot don't create the boot auxillary vector information.
 * Do that here before calling krtld initialization.
 */
/*ARGSUSED3*/
void
_kobj_boot(
	struct boot_syscalls *syscallp,
	void *dvec,
	struct bootops *bootops,
	Boot *ebp)
{
	val_t bootaux[BA_NUM];
	int i;

	for (i = 0; i < BA_NUM; i++)
		bootaux[i].ba_val = NULL;

	bootaux[BA_ENTRY].ba_ptr = (void *)_locore_start;
	bootaux[BA_PAGESZ].ba_val = PAGESIZE;
	bootaux[BA_LPAGESZ].ba_val = kbm_nucleus_size;

	/*
	 * Off to krtld initialization.
	 */
	kobj_init(syscallp, dvec, bootops, bootaux);
}
