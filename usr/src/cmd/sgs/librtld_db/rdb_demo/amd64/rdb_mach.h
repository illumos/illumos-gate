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

#ifndef _RDB_MACH_H
#define	_RDB_MACH_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/regset.h>
#include <sys/psw.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	ERRBIT	PS_C
#define	R_PS	REG_RFL


/*
 * Breakpoint instruction
 */
typedef	unsigned char	bptinstr_t;
#define	BPINSTR		0xcc		/* int	3 */


/*
 * PLT section type
 */
#define	PLTSECTT	SHT_PROGBITS

#ifdef __cplusplus
}
#endif

#endif	/* _RDB_MACH_H */
