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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Miscellaneous C routines for copying data around without
 * descending into assembler.  Compilers are pretty good at
 * scheduling instructions, and humans are pretty hopeless at
 * writing correct assembler.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/param.h>

/*
 * copyinstr_noerr and copyoutstr_noerr can be implemented completely
 * in C on machines with shared user and kernel context.
 */
static int
copystr_nofault(const char *src, char *dst, size_t maxlength,
    size_t *lencopied)
{
	int error = 0;
	size_t leftover;

	if ((leftover = maxlength) == 0)
		error = ENAMETOOLONG;
	else
		do {
			leftover--;
			if ((*dst++ = *src++) == '\0')
				break;
			if (leftover == 0) {
				error = ENAMETOOLONG;
				break;
			}
		/*CONSTCOND*/
		} while (1);

	if (lencopied)
		*lencopied = maxlength - leftover;
	return (error);
}


int
copyinstr_noerr(const char *uaddr, char *kaddr, size_t maxlength,
    size_t *lencopied)
{
	char *ua = (char *)uaddr;

	ASSERT((uintptr_t)kaddr > kernelbase);

	if ((uintptr_t)ua > kernelbase) {
		/*
		 * force fault at kernelbase
		 */
		ua = (char *)kernelbase;
	}
	return (copystr_nofault(ua, kaddr, maxlength, lencopied));
}

int
copyoutstr_noerr(const char *kaddr, char *uaddr, size_t maxlength,
    size_t *lencopied)
{
	char *ua = (char *)uaddr;

	ASSERT((uintptr_t)kaddr > kernelbase);

	if ((uintptr_t)ua > kernelbase) {
		/*
		 * force fault at kernelbase
		 */
		ua = (char *)kernelbase;
	}
	return (copystr_nofault(kaddr, ua, maxlength, lencopied));
}
