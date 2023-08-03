/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

#ifndef _T4_EXTRA_REGS_H
#define	_T4_EXTRA_REGS_H

/*
 * Additional registers not present in the current auto-generated t4_regs.h.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * RS FEC error count registers. These are 16-bit counters. The low register
 * must be read first. These are clear on read registers.
 */
#define	T6_RS_FEC_CCW_LO	0x2208
#define	T6_RS_FEC_CCW_HI	0x220c
#define	T6_RS_FEC_NCCW_LO	0x2210
#define	T6_RS_FEC_NCCW_HI	0x2214

#define	T6_RS_FEC_SYMERR0_LO	0x2228
#define	T6_RS_FEC_SYMERR0_HI	0x222c
#define	T6_RS_FEC_SYMERR1_LO	0x2230
#define	T6_RS_FEC_SYMERR1_HI	0x2234
#define	T6_RS_FEC_SYMERR2_LO	0x2238
#define	T6_RS_FEC_SYMERR2_HI	0x223c
#define	T6_RS_FEC_SYMERR3_LO	0x2240
#define	T6_RS_FEC_SYMERR3_HI	0x2244

/*
 * Firecode / BASE-R FEC registers. These only exist per-lane. There is a pair
 * of registers for both correctable and uncorrectable errors. These are also
 * clear on read registers.
 */
#define	T6_FC_FEC_L0_CERR_LO	0x2624
#define	T6_FC_FEC_L0_CERR_HI	0x2628
#define	T6_FC_FEC_L0_NCERR_LO	0x262c
#define	T6_FC_FEC_L0_NCERR_HI	0x2630

#define	T6_FC_FEC_L1_CERR_LO	0x2668
#define	T6_FC_FEC_L1_CERR_HI	0x266c
#define	T6_FC_FEC_L1_NCERR_LO	0x2670
#define	T6_FC_FEC_L1_NCERR_HI	0x2674

#define	T6_FC_FEC_L2_CERR_LO	0x26ac
#define	T6_FC_FEC_L2_CERR_HI	0x26b0
#define	T6_FC_FEC_L2_NCERR_LO	0x26b4
#define	T6_FC_FEC_L2_NCERR_HI	0x26b8

#define	T6_FC_FEC_L3_CERR_LO	0x26f0
#define	T6_FC_FEC_L3_CERR_HI	0x26f4
#define	T6_FC_FEC_L3_NCERR_LO	0x26f8
#define	T6_FC_FEC_L3_NCERR_HI	0x26fc

#ifdef __cplusplus
}
#endif

#endif /* _T4_EXTRA_REGS_H */
