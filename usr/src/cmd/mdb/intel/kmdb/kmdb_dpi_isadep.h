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

#ifndef _KMDB_DPI_ISADEP_H
#define	_KMDB_DPI_ISADEP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _ASM
#include <mdb/mdb_isautil.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define	KMDB_MSR_READ		0x1	/* read during entry (unlimited) */
#define	KMDB_MSR_WRITE		0x2	/* write during exit (unlimited) */
#define	KMDB_MSR_WRITEDELAY	0x4	/* write after last branch (<= 1) */
#define	KMDB_MSR_CLEARENTRY	0x3	/* clear before 1st branch (<= 1) */

#ifndef _ASM

typedef struct kmdb_msr {
	uint_t		msr_num;
	uint_t		msr_type;
	union {
		uint64_t *_msr_valp;
		uint64_t _msr_val;
	} _u;
} kmdb_msr_t;

#define	msr_val		_u._msr_val
#define	msr_valp	_u._msr_valp

extern void kmdb_dpi_handle_fault(kreg_t, kreg_t, kreg_t, int);

extern void kmdb_dpi_reboot(void) __NORETURN;

extern void kmdb_dpi_msr_add(const kmdb_msr_t *);
extern uint64_t kmdb_dpi_msr_get(uint_t);
extern uint64_t kmdb_dpi_msr_get_by_cpu(int, uint_t);

#endif /* _ASM */

#ifdef __cplusplus
}
#endif

#endif /* _KMDB_DPI_ISADEP_H */
