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

#if !defined(__lint)
#include <sys/asm_linkage.h>
#include <sys/privregs.h>
#endif

/*
 * The interface for a client programs that call the 64-bit romvec OBP
 */

#if defined(__lint)
/* ARGSUSED */
int
client_handler(void *cif_handler, void *arg_array)
{
	return (0);
}
#else	/* __lint */

	ENTRY(client_handler)
	save	%sp, -SA64(MINFRAME64), %sp	! 32 bit frame, 64 bit sized
	mov	%i1, %o0
1:
	rdpr	%pstate, %l4			! Get the present pstate value
	andn	%l4, PSTATE_AM, %l6
	wrpr	%l6, 0, %pstate			! Set PSTATE_AM = 0
	jmpl	%i0, %o7			! Call cif handler
	nop
	wrpr	%l4, 0, %pstate			! Just restore 
	ret					! Return result ...
	restore	%o0, %g0, %o0			! delay; result in %o0
	SET_SIZE(client_handler)

#endif	/* __lint */
