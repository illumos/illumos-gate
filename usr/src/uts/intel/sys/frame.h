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

#ifndef _SYS_FRAME_H
#define	_SYS_FRAME_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/regset.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * In the Intel world, a stack frame looks like this:
 *
 * %fp0->|				 |
 *	 |-------------------------------|
 *	 |  Args to next subroutine	 |
 *	 |-------------------------------|-\
 * %sp0->|  One word struct-ret address	 | |
 *	 |-------------------------------|  > minimum stack frame
 * %fp1->|  Previous frame pointer (%fp0)| |
 *	 |-------------------------------|-/
 *	 |  Local variables		 |
 * %sp1->|-------------------------------|
 *
 * For amd64, the minimum stack frame is 16 bytes and the frame pointer must
 * be 16-byte aligned.
 */

struct frame {
	greg_t	fr_savfp;		/* saved frame pointer */
	greg_t	fr_savpc;		/* saved program counter */
};

#ifdef _SYSCALL32

/*
 * Kernel's view of a 32-bit stack frame.
 */
struct frame32 {
	greg32_t fr_savfp;		/* saved frame pointer */
	greg32_t fr_savpc;		/* saved program counter */
};

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FRAME_H */
