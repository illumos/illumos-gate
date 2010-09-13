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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * MKS interface extension.
 * Ensure that errno is set if malloc() fails.
 *
 * Copyright 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */
#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/mks/rcs/m_malloc.c 1.4 1993/12/17 15:22:04 rog Exp $";
#endif /*lint*/
#endif /*M_RCSID*/

#include <mks.h>
#include <errno.h>
#include <stdlib.h>

#ifdef __STDC__
#define _VOID	void
#else
#define _VOID	char
#endif

#undef m_malloc	   /* in case <mks.h> included in <errno.h> or <stdlib.h> */

/*f
 * m_malloc: 
 *   Portable replacement for malloc().
 *   If malloc() fails (e.g returns NULL)
 *   then return ENOMEM unless malloc() sets errno for us on this system
 *   and ensure malloc(0) returns a non-NULL pointer.
 *
 */
_VOID*
m_malloc(amount)
size_t amount;
{
	_VOID* ptr;

	/*l
	 * Prob 1:
	 *  ANSI does not insist setting errno when malloc() fails.
	 *  But UNIX existing practice (which MKS relies on) always returns
	 *  an errno when malloc() fails.
	 *  Thus, on systems that implement malloc() where an errno is not
	 *  returned, we set ENOMEM.
	 *
	 *  Note: we don't care about previous value of errno since
	 *        POSIX.1 (Section 2.4) says you can only look at errno
	 *        after a function returns a status indicating an error.
	 *        (and the function explicitly states an errno value can be
	 *         returned - Well, m_malloc() is so stated.)
	 *
	 * Prob 2:
         *  MKS code seems to rely on malloc(0) returning a valid pointer.
	 *  This allows it to realloc() later when actual size is determined.
	 *
	 *  According to ANSI (4.10.3 line 18-19) the result of malloc(0) is
	 *  implementation-defined.
	 */

	errno = 0;
	if ((ptr = malloc(amount)) == NULL) {
		if (amount == 0) {
			/*
			 *  confirm we are really out of memory
			 */
			return (m_malloc(1));
		}
		if (errno==0) {
			/*
			 *  ensure errno is always set
			 */
			errno = ENOMEM;
		}
	}
	return (ptr);
}
