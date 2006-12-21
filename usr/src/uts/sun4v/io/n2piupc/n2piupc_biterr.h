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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_N2PIUPC_BITERR_H
#define	_N2PIUPC_BITERR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * "Virtual register" definitions for the bit error performance counters.
 *
 * The N2 PIU presents two bit error counters.  Bit 63 on the first counter
 * serves as an enable for all bit error counters.   Bit 62 serves as a clear
 * for all the bit error counters.
 *
 * Busstat doesn't play well with a register that has counters, enable and
 * clear, so this module presents to the rest of the driver and to busstat a
 * new layered set of register interfaces.
 *
 * These are:
 *	SW_N2PIU_BITERR_CNT1_DATA	Biterr counter 1 data (readonly)
 *						Maps directly to HW biterr
 *						counter 1.  Returns data for
 *						bad_dllps, bad_tlps,
 *						phys_rcvr_errs
 *
 *	SW_N2PIU_BITERR_CNT2_DATA	Biterr counter 2 data (readonly)
 *						Maps to HW biterr counter 2, but
 *						offers evt select of individual
 *						lanes 0-7 or all lanes together
 *
 *	SW_N2PIU_BITERR_CLR		Setting bit 62 here clears all biterr
 *						counters (write-only)
 *
 *	SW_N2PIU_BITERR_SEL		Bit 63 is overall biterr enable.
 *					Bits 0-3 are event select for counter 2
 *					(read-write)
 *
 * Note: each is assigned an offset similar to the offset of real performance
 * counter registers.  Offsets for these registers extend beyond the real reg
 * set.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/sunddi.h>

/* SW abstractions for the BITERR counters. */

/* Select register.  Select enable for all biterr ctrs, and PIC3 events. */
#define	SW_N2PIU_BITERR_SEL		HVIO_N2PIU_PERFREG_NUM_REGS

/* Clear register.  This zeros out all biterr ctrs. */
#define	SW_N2PIU_BITERR_CLR		(HVIO_N2PIU_PERFREG_NUM_REGS + 1)

/* Biterr counter 1.  Same as in the PRM. */
#define	SW_N2PIU_BITERR_CNT1_DATA	(HVIO_N2PIU_PERFREG_NUM_REGS + 2)

/*
 * Biterr counter 2.  Reports errors for all lanes, or for any individual lane.
 * Select what to report with the SELect register above.  Enabled only if the
 * enable for all biterr counters is enabled.
 */
#define	SW_N2PIU_BITERR_CNT2_DATA	(HVIO_N2PIU_PERFREG_NUM_REGS + 3)

/* Biterr counter abstraction functions. */
extern int n2piupc_biterr_attach(void **);
extern void n2piupc_biterr_detach(void *);
extern int n2piupc_biterr_write(n2piupc_t *n2piupc_p, int regid, uint64_t data);
extern int n2piupc_biterr_read(n2piupc_t *n2piupc_p, int regid, uint64_t *data);

#ifdef	__cplusplus
}
#endif

#endif	/* _N2PIUPC_BITERR_H */
