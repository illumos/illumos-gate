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

#ifndef	_SYS_FPRAS_H
#define	_SYS_FPRAS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The following identify copy operations using the fpras mechanism.
 * They are used in array indexing so keep them sequential.
 */
#define	FPRAS_BCOPY	0
#define	FPRAS_COPYIN	1
#define	FPRAS_COPYOUT	2
#define	FPRAS_PGCOPY	3
#define	FPRAS_NCOPYOPS	(FPRAS_PGCOPY + 1)

/*
 * Identifying where fpras_failure was called from.
 */
#define	FPRAS_FROMCHKFN	0
#define	FPRAS_FROMTRAP	1

/*
 * Return values from a check function.
 */
#define	FPRAS_OK	0
#define	FPRAS_BADCALC	1
#define	FPRAS_BADTRAP	2

#if !defined(_ASM)

/*
 * Set if an architecture/cpu combination implements fpRAS.
 */
extern int fpras_implemented;

/*
 * Set in /etc/system to disable fpRAS mechanism at reboot.
 * Changing this value on a live system may have no effect (eg, if an
 * implementation checks only at startup).
 */
extern int fpras_disable;

/*
 * Set in /etc/system to disable checking of particular copy operations.  Set
 * bit N to disable checking of the corresponding copy operation (eg, bit 2
 * for copyout).  Changing this value on a live system may have no effect.
 */
extern int fpras_disableids;

/*
 * Function called from a check function to indicate an incorrect result
 * was obtained and from trap handlers to determine if the trap was due to
 * an fpRAS failure.  Symbol only appears for architecture/cpu combinations
 * that implement fpRAS.
 */
#pragma	weak fpras_chktrap
struct regs;
extern int fpras_chktrap(struct regs *);
extern int fpras_failure(int, int);

#endif	/* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FPRAS_H */
