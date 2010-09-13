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

#ifndef	_AMD64_SYS_PRIVMREGS_H
#define	_AMD64_SYS_PRIVMREGS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(__amd64)
#error	"non-amd64 code depends on amd64 privileged header!"
#endif

#ifndef _ASM

#define	PM_GREGS (1 << 0)
#define	PM_CRREGS (1 << 1)
#define	PM_DRREGS (1 << 2)

/*
 * This structure is intended to represent a complete machine state for a CPU,
 * when that information is available.  It is only for use internally between
 * KMDB and the kernel, or within MDB.  Note that this isn't yet finished.
 */
typedef struct privmregs {
	ulong_t pm_flags;
	/* general registers */
	struct regs pm_gregs;
	/* cr0-8 */
	ulong_t pm_cr[8];
	/* dr0-8 */
	ulong_t pm_dr[8];
} privmregs_t;

#endif /* !_ASM */

#ifdef __cplusplus
}
#endif

#endif	/* !_AMD64_SYS_PRIVMREGS_H */
