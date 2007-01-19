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

#ifndef _MDB_INTR_COMMON_H
#define	_MDB_INTR_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <sys/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <sys/modctl.h>
#include <sys/avintr.h>
#include <sys/psm_common.h>
#include <sys/pic.h>
#include <sys/apic.h>

/*
 * Function prototypes
 */
void interrupt_help(void);
void interrupt_print_isr(uintptr_t, uintptr_t, uintptr_t);
void apic_interrupt_dump(apic_irq_t *, struct av_head *, int i,
	ushort_t *, char);

void soft_interrupt_help(void);
int soft_interrupt_dump(uintptr_t, uint_t, int, const mdb_arg_t *);

/*
 * ::interrupts usage related defines and variables
 * -d and -i options are supported and saved in option_flags
 */
#define	INTR_DISPLAY_DRVR_INST	0x1	/* -d option */
#define	INTR_DISPLAY_INTRSTAT	0x2	/* -i option */

extern int	option_flags;

/*
 * gld_intr_addr is used to save address of gld_intr() ISR
 */
extern uintptr_t	gld_intr_addr;

#ifdef __cplusplus
}
#endif

#endif	/* _MDB_INTR_COMMON_H */
