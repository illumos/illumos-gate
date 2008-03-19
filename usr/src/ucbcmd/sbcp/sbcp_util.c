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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/auxv.h>
#include <sys/types.h>

void
sbcp_init(int argc, char *argv[], char *envp[])
{
	auxv_t			*ap;
	uintptr_t		*p;
	int			err;

	/*
	 * Find the aux vector on the stack.
	 */
	p = (uintptr_t *)envp;
	while (*p != NULL)
		p++;

	/*
	 * p is now pointing at the 0 word after the environ pointers.
	 * After that is the aux vectors.
	 *
	 * We need to clear the AF_SUN_NOPLM flag from the AT_SUN_AUXFLAGS
	 * aux vector.  This flag told our linker that we don't have a
	 * primary link map.  Now that our linker is done initializing, we
	 * want to clear this flag before we transfer control to the
	 * applications copy of the linker, since we want that linker to have
	 * a primary link map which will be the link map for the application
	 * we're running.
	 */
	p++;
	for (ap = (auxv_t *)p; ap->a_type != AT_NULL; ap++) {
		switch (ap->a_type) {
			case AT_SUN_AUXFLAGS:
				ap->a_un.a_val &= ~AF_SUN_NOPLM;
				break;
			default:
				break;
		}
	}
}
