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

#ifndef	_SYS_CORE_H
#define	_SYS_CORE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _KERNEL
#include <sys/reg.h>
#endif /* _KERNEL */

#include <sys/exechdr.h>
#include <sys/pcb.h>
#include <sys/user.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	CORE_MAGIC	0x080456
#define	CORE_NAMELEN	16

#if !defined(_LP64) && !defined(_KERNEL)
/*
 * This structure describes the header of the old 32-bit SunOS 4.x aout exec
 * module's core files.  Following the header, copies of the data and stack
 * segments and a copy of the user struct were recorded in the core file.
 * These core files have not been produced since SunOS 5.5; new debuggers
 * should not make use of this structure.  The structure is not suitable for
 * 64-bit consumers and will be removed altogether in a future Solaris release.
 */
struct core {
	int	c_magic;		/* Corefile magic number */
	int	c_len;			/* Sizeof (struct core) */
	struct	regs c_regs;		/* General purpose registers */
	struct 	exdata c_exdata;	/* Executable header */
	int	c_signo;		/* Killing signal, if any */
	int	c_tsize;		/* Text size (bytes) */
	int	c_dsize;		/* Data size (bytes) */
	int	c_ssize;		/* Stack size (bytes) */
	char	c_cmdname[CORE_NAMELEN + 1]; /* Command name */
	struct	fpu c_fpu;		/* external FPU state */
#if defined(__sparc)
	struct	fq c_fpu_q[MAXFPQ];	/* fpu exception queue */
#endif
	int	c_ucode;		/* Exception no. from u_code */
};
#endif	/* !_LP64 && !_KERNEL */

#ifdef	_KERNEL

extern int core(int, int);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_CORE_H */
