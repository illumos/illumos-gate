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
 * Copyright 1987-1997,2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_FRAME_H
#define	_SYS_FRAME_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* sys4-3.2L 1.1 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Definition of the sparc stack frame (when it is pushed on the stack).
 */
struct frame {
	long	fr_local[8];		/* saved locals */
	long	fr_arg[6];		/* saved arguments [0 - 5] */
	struct frame	*fr_savfp;	/* saved frame pointer */
	long	fr_savpc;		/* saved program counter */
#if !defined(__sparcv9)
	char	*fr_stret;		/* struct return addr */
#endif	/* __sparcv9 */
	long	fr_argd[6];		/* arg dump area */
	long	fr_argx[1];		/* array of args past the sixth */
};

#ifdef _SYSCALL32
/*
 * Kernels view of a 32-bit stack frame
 */
struct frame32 {
	int	fr_local[8];		/* saved locals */
	int	fr_arg[6];		/* saved arguments [0 - 5] */
	caddr32_t fr_savfp;		/* saved frame pointer */
	int	fr_savpc;		/* saved program counter */
	caddr32_t fr_stret;		/* struct return addr */
	int	fr_argd[6];		/* arg dump area */
	int	fr_argx[1];		/* array of args past the sixth */
};
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FRAME_H */
