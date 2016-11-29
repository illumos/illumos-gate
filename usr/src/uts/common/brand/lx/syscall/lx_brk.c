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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/errno.h>

/* From usr/src/uts/common/os/grow.c */
extern intptr_t brk(caddr_t);

long
lx_brk(caddr_t nva)
{
	if (nva != 0) {
		(void) brk(nva);

		/*
		 * Despite claims to the contrary in the man page, when Linux
		 * brk(2) fails, errno is left unchanged.
		 */
		ttolwp(curthread)->lwp_errno = 0;
	}

	/*
	 * When ASLR was integrated, our internal brk(2) was updated to emit
	 * the current brk when arg0 == 0.  Using the function yields an
	 * equivalent result to manually calculating the brk, but also
	 * serializes with changes to the process AS.
	 */
	return ((long)brk((caddr_t)0));
}
