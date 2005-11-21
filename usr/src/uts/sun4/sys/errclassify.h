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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_ERRCLASSIFY_H
#define	_SYS_ERRCLASSIFY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_ASM

#include <sys/errorq.h>

/*
 * Note that the order in the following must be kept in sync with that
 * in the sun4u DE cmd_memerr.c and with the cetypes array of us3_common.c
 */
typedef enum {
	/*
	 * The first byte (256 values) is for type and can be sequential.
	 */
	CE_DISP_UNKNOWN,
	CE_DISP_INTERMITTENT,
	CE_DISP_POSS_PERS,
	CE_DISP_PERS,
	CE_DISP_LEAKY,
	CE_DISP_POSS_STICKY,
	CE_DISP_STICKY,
	/*
	 * The next byte encodes the next action as a bitmask
	 */
	CE_ACT_DONE = 0x100,
	CE_ACT_LKYCHK = 0x200,
	CE_ACT_PTNRCHK = 0x400,
	/*
	 * Keep this as the last entry.  Not all entries of the type lookup
	 * table are used and this value is the "uninitialized" pattern.
	 */
	CE_DISP_BAD = 0xbadbad1
} ce_dispact_t;

/*
 * Extract disposition or action from a ce_dispact_t
 */
#define	CE_DISP(dispact) \
	(dispact & 0xff)
#define	CE_ACT(dispact) \
	(dispact & 0xff00)

/*
 * Short string names for classification types.
 */
#define	CE_DISP_DESC_U		"U"
#define	CE_DISP_DESC_I		"I"
#define	CE_DISP_DESC_PP		"PP"
#define	CE_DISP_DESC_P		"P"
#define	CE_DISP_DESC_L		"L"
#define	CE_DISP_DESC_PS		"PS"
#define	CE_DISP_DESC_S		"S"

/*
 * Various sun4u CPU types use different Ecache state encodings.
 * For CE classification the following unified scheme is used.
 */
#define	EC_STATE_M		0x4
#define	EC_STATE_O		0x3
#define	EC_STATE_E		0x2
#define	EC_STATE_S		0x1
#define	EC_STATE_I		0x0

/*
 * Macros to generate the initial CE classification table (in both kernel and
 * userland).  An array size CE_INITDISPTBL_SIZE of ce_dispact_t should be
 * defined and passed by name to ECC_INITDISPTBL_POPULATE which will populate
 * the array slots that are use and set the unused ones to CE_DISP_BAD.
 *
 * To perform a lookup use CE_DISPACT passing the name of the same
 * array and the afarmatch, ecstate, ce1 and ce2 information.
 *
 * Other macros defined here should not be used directly.
 *
 * CE_INITDISPTBL_INDEX will generate an index as follows:
 *
 *	<5>	afar match
 *	<4:2>	line state
 *	<1>	ce2 - CE seen on lddphys of scrub algorithm (after writeback)
 *	<0>	ce1 - CE seen on CASXA of scrub algorithm (before writeback)
 *
 * When the afar does not match line state must be zero.
 */
#define	CE_INITDISPTBL_SIZE	(1 << 6)
#define	CE_INITDISPTBL_INDEX(afarmatch, ecstate, ce1, ce2) \
	((afarmatch) << 5 | (ecstate) << 2 | (ce2) << 1 | (ce1))

#define	CE_DISPACT(array, afarmatch, ecstate, ce1, ce2) \
	(array[CE_INITDISPTBL_INDEX(afarmatch, ecstate, ce1, ce2)])

#define	CE_INITDISPTBL_POPULATE(a)					\
{									\
	int i;								\
	for (i = 0; i < CE_INITDISPTBL_SIZE; ++i)			\
		a[i] = CE_DISP_BAD;					\
/*									\
 *	   afar  ec	      ce1  ce2	initial disp and next action	\
 *	  match  state							\
 */									\
CE_DISPACT(a, 0, 0,		0, 0) = CE_DISP_UNKNOWN | CE_ACT_DONE; \
CE_DISPACT(a, 0, 0,		0, 1) = CE_DISP_POSS_STICKY | CE_ACT_PTNRCHK; \
CE_DISPACT(a, 0, 0,		1, 0) = CE_DISP_POSS_PERS | CE_ACT_LKYCHK; \
CE_DISPACT(a, 0, 0,		1, 1) = CE_DISP_POSS_STICKY | CE_ACT_PTNRCHK; \
CE_DISPACT(a, 1, EC_STATE_M,	0, 0) = CE_DISP_UNKNOWN | CE_ACT_DONE; \
CE_DISPACT(a, 1, EC_STATE_M,	0, 1) = CE_DISP_UNKNOWN | CE_ACT_DONE; \
CE_DISPACT(a, 1, EC_STATE_M,	1, 0) = CE_DISP_UNKNOWN | CE_ACT_DONE; \
CE_DISPACT(a, 1, EC_STATE_M,	1, 1) = CE_DISP_POSS_STICKY | CE_ACT_PTNRCHK; \
CE_DISPACT(a, 1, EC_STATE_O,	0, 0) = CE_DISP_UNKNOWN | CE_ACT_DONE; \
CE_DISPACT(a, 1, EC_STATE_O,	0, 1) = CE_DISP_UNKNOWN | CE_ACT_DONE; \
CE_DISPACT(a, 1, EC_STATE_O,	1, 0) = CE_DISP_UNKNOWN | CE_ACT_DONE; \
CE_DISPACT(a, 1, EC_STATE_O,	1, 1) = CE_DISP_POSS_STICKY | CE_ACT_PTNRCHK; \
CE_DISPACT(a, 1, EC_STATE_E,	0, 0) = CE_DISP_INTERMITTENT | CE_ACT_DONE; \
CE_DISPACT(a, 1, EC_STATE_E,	0, 1) = CE_DISP_UNKNOWN | CE_ACT_DONE; \
CE_DISPACT(a, 1, EC_STATE_E,	1, 0) = CE_DISP_POSS_PERS | CE_ACT_LKYCHK; \
CE_DISPACT(a, 1, EC_STATE_E,	1, 1) = CE_DISP_POSS_STICKY | CE_ACT_PTNRCHK; \
CE_DISPACT(a, 1, EC_STATE_S,	0, 0) = CE_DISP_INTERMITTENT | CE_ACT_DONE; \
CE_DISPACT(a, 1, EC_STATE_S,	0, 1) = CE_DISP_POSS_STICKY | CE_ACT_PTNRCHK; \
CE_DISPACT(a, 1, EC_STATE_S,	1, 0) = CE_DISP_POSS_PERS | CE_ACT_LKYCHK; \
CE_DISPACT(a, 1, EC_STATE_S,	1, 1) = CE_DISP_POSS_STICKY | CE_ACT_PTNRCHK; \
CE_DISPACT(a, 1, EC_STATE_I,	0, 0) = CE_DISP_UNKNOWN | CE_ACT_DONE; \
CE_DISPACT(a, 1, EC_STATE_I,	0, 1) = CE_DISP_POSS_STICKY | CE_ACT_PTNRCHK; \
CE_DISPACT(a, 1, EC_STATE_I,	1, 0) = CE_DISP_POSS_PERS | CE_ACT_LKYCHK; \
CE_DISPACT(a, 1, EC_STATE_I,	1, 1) = CE_DISP_POSS_STICKY | CE_ACT_PTNRCHK; \
}

#endif	/* !_ASM */

/*
 * Legacy error type names corresponding to the flt_status bits
 */
#define	ERR_TYPE_DESC_INTERMITTENT	"Intermittent"
#define	ERR_TYPE_DESC_PERSISTENT	"Persistent"
#define	ERR_TYPE_DESC_STICKY		"Sticky"
#define	ERR_TYPE_DESC_UNKNOWN		"Unknown"

/*
 * flt_disp for a CE will record all scrub test data for the extended
 * classification attempt.
 *
 * --------------------------------------------------------------------------
 * |            | partner |   |          | leaky   | partner | detector     |
 * | partner id | type    | - | skipcode | results | results | results      |
 * |63	      32|31     30|   |27      24|23     16|15      8|7            0|
 * --------------------------------------------------------------------------
 */
#define	CE_XDIAG_DTCRMASK		0xffULL
#define	CE_XDIAG_PTNRSHIFT		8
#define	CE_XDIAG_PTNRMASK		(0xffULL << CE_XDIAG_PTNRSHIFT)
#define	CE_XDIAG_LKYSHIFT		16
#define	CE_XDIAG_LKYMASK		(0xffULL << CE_XDIAG_LKYSHIFT)
#define	CE_XDIAG_SKIPCODESHIFT		24
#define	CE_XDIAG_SKIPCODEMASK		(0xfULL << CE_XDIAG_SKIPCODESHIFT)
#define	CE_XDIAG_PTNRTYPESHIFT		30
#define	CE_XDIAG_PTNRTYPEMASK		(0x3ULL << CE_XDIAG_PTNRTYPESHIFT)
#define	CE_XDIAG_PTNRIDSHIFT		32

/*
 * Given a CE flt_disp set the given field
 */
#define	CE_XDIAG_SETPTNRID(disp, id) \
	((disp) |= (uint64_t)(id) << CE_XDIAG_PTNRIDSHIFT)
#define	CE_XDIAG_SETPTNRTYPE(disp, type) \
	((disp) |= (uint64_t)type << CE_XDIAG_PTNRTYPESHIFT)
#define	CE_XDIAG_SETSKIPCODE(disp, code) \
	((disp) |= (uint64_t)code << CE_XDIAG_SKIPCODESHIFT)
#define	CE_XDIAG_SETLKYINFO(disp, result) \
	((disp) |= (uint64_t)result << CE_XDIAG_LKYSHIFT)
#define	CE_XDIAG_SETPTNRINFO(disp, result) \
	((disp) |= (uint64_t)result << CE_XDIAG_PTNRSHIFT)
#define	CE_XDIAG_SETDTCRINFO(disp, result) \
	((disp) |= (uint64_t)result)

/*
 * Given a CE flt_disp extract the requested component
 */
#define	CE_XDIAG_DTCRINFO(disp)	((disp) & CE_XDIAG_DTCRMASK)
#define	CE_XDIAG_PTNRINFO(disp)	(((disp) & CE_XDIAG_PTNRMASK) >> \
    CE_XDIAG_PTNRSHIFT)
#define	CE_XDIAG_LKYINFO(disp)	(((disp) & CE_XDIAG_LKYMASK) >> \
    CE_XDIAG_LKYSHIFT)
#define	CE_XDIAG_SKIPCODE(disp)	(((disp) & CE_XDIAG_SKIPCODEMASK) >> \
    CE_XDIAG_SKIPCODESHIFT)
#define	CE_XDIAG_PTNRTYPE(disp)	(((disp) & CE_XDIAG_PTNRTYPEMASK) >> \
    CE_XDIAG_PTNRTYPESHIFT)
#define	CE_XDIAG_PTNRID(disp)	((disp) >> CE_XDIAG_PTNRIDSHIFT)

/*
 * Format of individual detector/partner/leaky test results.  CE_XDIAG_EXTALG
 * in the detector case indicates that the extended classification algorithm
 * has been applied;  common code uses this to distinguish between old and new.
 * In the partner check and leaky check cases CE_XDIAG_EXTALG is used to
 * indicate that the given test has run and recorded its results in its
 * result field.
 */
#define	CE_XDIAG_STATE_MASK	0x7	/* Low 3 bits are for MOESI state */
#define	CE_XDIAG_AFARMATCH	0x08	/* Line at e$ index matched AFAR */
#define	CE_XDIAG_NOLOGOUT	0x10	/* Logout data unavailable */
#define	CE_XDIAG_CE1		0x20	/* CE logged on casx during scrub */
#define	CE_XDIAG_CE2		0x40	/* CE logged on post-scrub reread */
#define	CE_XDIAG_EXTALG		0x80	/* Extended algorithm applied */

/*
 * Extract classification information for detector/partner.  Expects
 * a value from one of CE_XDIAG_{DTCR,PTNR,LKY}_INFO.
 */
#define	CE_XDIAG_AFARMATCHED(c)		(((c) & CE_XDIAG_AFARMATCH) != 0)
#define	CE_XDIAG_LOGOUTVALID(c)		(((c) & CE_XDIAG_NOLOGOUT) == 0)
#define	CE_XDIAG_CE1SEEN(c)		(((c) & CE_XDIAG_CE1) != 0)
#define	CE_XDIAG_CE2SEEN(c)		(((c) & CE_XDIAG_CE2) != 0)
#define	CE_XDIAG_STATE(c)		(CE_XDIAG_AFARMATCHED(c) ? \
	((c) & CE_XDIAG_STATE_MASK) : 0)
#define	CE_XDIAG_EXT_ALG_APPLIED(c)	(((c) & CE_XDIAG_EXTALG) != 0)

/*
 * A leaky or partner test is considered valid if the line was not present
 * in cache, or was present but Invalid, at the time of the additional scrub.
 */
#define	CE_XDIAG_TESTVALID(c) (CE_XDIAG_EXT_ALG_APPLIED(c) && \
	(!CE_XDIAG_AFARMATCHED(c) || CE_XDIAG_STATE(c) == EC_STATE_I))

/*
 * Skipcodes - reasons for not applying extended diags; 4 bits
 */
#define	CE_XDIAG_SKIP_NOPP		0x1	/* Can't lookup page pointer */
#define	CE_XDIAG_SKIP_PAGEDET		0x2	/* Page deteriorating/retired */
#define	CE_XDIAG_SKIP_NOTMEM		0x3	/* AFAR is not memory */
#define	CE_XDIAG_SKIP_DUPFAIL		0x4	/* errorq recirculate failed */
#define	CE_XDIAG_SKIP_NOPTNR		0x5	/* no suitable partner avail */
#define	CE_XDIAG_SKIP_UNIPROC		0x6	/* test needs 2 or more cpus */
#define	CE_XDIAG_SKIP_ACTBAD		0x7	/* bad action lookup - bug */
#define	CE_XDIAG_SKIP_NOSCRUB		0x8	/* detector did not scrub */

/*
 * Partner type information.
 */
#define	CE_XDIAG_PTNR_REMOTE	0x0	/* partner in different lgroup */
#define	CE_XDIAG_PTNR_LOCAL	0x1	/* partner in same lgroup */
#define	CE_XDIAG_PTNR_SIBLING	0x2	/* partner is a sibling core */
#define	CE_XDIAG_PTNR_SELF	0x3	/* partnered self */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ERRCLASSIFY_H */
