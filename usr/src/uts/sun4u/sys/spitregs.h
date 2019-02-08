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
/*
 * Copyright 2019 Peter Tribble.
 */

#ifndef _SYS_SPITREGS_H
#define	_SYS_SPITREGS_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file is cpu dependent.
 */

/*
 * The mid is the same as the cpu id.
 * We might want to change this later
 */
#define	CPUID_TO_UPAID(cpuid)	(cpuid)

/*
 * LSU Control Register
 *
 * +------+----+----+----+----+----+----+-----+------+----+----+----+---+
 * | Resv | PM | VM | PR | PW | VR | VW | Rsv |  FM  | DM | IM | DC | IC|
 * +------+----+----+----+----+----+----+-----+------+----+----+----+---+
 *  63  41   33   25   24   23	 22   21   20  19   4	3    2	  1   0
 *
 */

#define	LSU_IC		0x00000000001	/* icache enable */
#define	LSU_DC		0x00000000002	/* dcache enable */
#define	LSU_IM		0x00000000004	/* immu enable */
#define	LSU_DM		0x00000000008	/* dmmu enable */
#define	LSU_FM		0x000000FFFF0	/* parity mask */
#define	LSU_VW		0x00000200000	/* virtual watchpoint write enable */
#define	LSU_VR		0x00000400000	/* virtual watchpoint read enable */
#define	LSU_PW		0x00000800000	/* physical watchpoint write enable */
#define	LSU_PR		0x00001000000	/* physical watchpoint read enable */
#define	LSU_VM		0x001fe000000	/* virtual watchpoint byte mask */
#define	LSU_PM		0x1fe00000000	/* physical watch point byte mask */

#define	LSU_VM_SHIFT	25
#define	LSU_PM_SHIFT	33

/*
 * Defines for the different types of dcache_flush
 * it is stored in dflush_type
 */
#define	FLUSHALL_TYPE	0x0		/* blasts all cache lines */
#define	FLUSHMATCH_TYPE	0x1		/* flush entire cache but check each */
					/* each line for a match */
#define	FLUSHPAGE_TYPE	0x2		/* flush only one page and check */
					/* each line for a match */

/*
 * D-Cache Tag Data Register
 *
 * +----------+--------+----------+
 * | Reserved | DC_Tag | DC_Valid |
 * +----------+--------+----------+
 *  63	    30 29    2	1	 0
 *
 */
#define	ICACHE_FLUSHSZ	0x20	/* one line in i$ */
#define	DC_PTAG_SHIFT	34
#define	DC_LINE_SHIFT	30
#define	SF_DC_VBIT_SHIFT 2
#define	SF_DC_VBIT_MASK	0x3
#define	IC_LINE_SHIFT	3
#define	IC_LINE		512
#define	INDEX_BIT_SHIFT	13

/*
 * Definitions of sun4u cpu implementations as specified in version register
 */
#define	SPITFIRE_IMPL	0x10
#define	IS_SPITFIRE(impl)	((impl) == SPITFIRE_IMPL)
#define	SPITFIRE_MAJOR_VERSION(rev)	(((rev) >> 4) & 0xf)
#define	SPITFIRE_MINOR_VERSION(rev)	((rev) & 0xf)

#define	BLACKBIRD_IMPL	0x11
#define	IS_BLACKBIRD(impl)	((impl) == BLACKBIRD_IMPL)
#define	BLACKBIRD_MAJOR_VERSION(rev)	(((rev) >> 4) & 0xf)
#define	BLACKBIRD_MINOR_VERSION(rev)	((rev) & 0xf)

#define	SABRE_IMPL	0x12
#define	HUMMBRD_IMPL	0x13

/*
 * Bits of Spitfire Asynchronous Fault Status Register
 */
#define	P_AFSR_STICKY	0x00000001FFF00000ULL /* mask for all sticky bits */
#define	P_AFSR_ERRS	0x000000001EE00000ULL /* mask for remaining errors */
#define	P_AFSR_ME	0x0000000100000000ULL /* errors > 1, same type!=CE */
#define	P_AFSR_PRIV	0x0000000080000000ULL /* priv/supervisor access */
#define	P_AFSR_ISAP	0x0000000040000000ULL /* incoming system addr. parity */
#define	P_AFSR_ETP	0x0000000020000000ULL /* ecache tag parity */
#define	P_AFSR_IVUE	0x0000000010000000ULL /* interrupt vector with UE */
#define	P_AFSR_TO	0x0000000008000000ULL /* bus timeout */
#define	P_AFSR_BERR	0x0000000004000000ULL /* bus error */
#define	P_AFSR_LDP	0x0000000002000000ULL /* data parity error from SDB */
#define	P_AFSR_CP	0x0000000001000000ULL /* copyout parity error */
#define	P_AFSR_WP	0x0000000000800000ULL /* writeback ecache data parity */
#define	P_AFSR_EDP	0x0000000000400000ULL /* ecache data parity */
#define	P_AFSR_UE	0x0000000000200000ULL /* uncorrectable ECC error */
#define	P_AFSR_CE	0x0000000000100000ULL /* correctable ECC error */
#define	P_AFSR_ETS	0x00000000000F0000ULL /* cache tag parity syndrome */
#define	P_AFSR_P_SYND	0x000000000000FFFFULL /* data parity syndrome */

/*
 * All error types
 */
#define	S_AFSR_ALL_ERRS	(P_AFSR_STICKY & ~P_AFSR_PRIV)

/*
 * Shifts for Spitfire Asynchronous Fault Status Register
 */
#define	P_AFSR_D_SIZE_SHIFT	(57)
#define	P_AFSR_CP_SHIFT		(24)
#define	P_AFSR_ETS_SHIFT	(16)

/*
 * AFSR error bits for AFT Level 1 messages (uncorrected + parity + BERR + TO)
 */
#define	P_AFSR_LEVEL1   (P_AFSR_UE | P_AFSR_EDP | P_AFSR_WP | P_AFSR_CP |\
			P_AFSR_LDP | P_AFSR_BERR | P_AFSR_TO)

/*
 * Bits of Spitfire Asynchronous Fault Status Register
 */
#define	S_AFSR_MASK	0x00000001FFFFFFFFULL /* <33:0>: valid AFSR bits */

/*
 * Bits of Spitfire Asynchronous Fault Address Register
 * The Sabre AFAR includes more bits since it only has a UDBH, no UDBL
 */
#define	S_AFAR_PA	0x000001FFFFFFFFF0ULL /* PA<40:4>: physical address */
#define	SABRE_AFAR_PA	0x000001FFFFFFFFF8ULL /* PA<40:3>: physical address */

/*
 * Bits of Spitfire/Sabre/Hummingbird Error Enable Registers
 */
#define	EER_EPEN	0x00000000000000010ULL /* enable ETP, EDP, WP, CP */
#define	EER_UEEN	0x00000000000000008ULL /* enable UE */
#define	EER_ISAPEN	0x00000000000000004ULL /* enable ISAP */
#define	EER_NCEEN	0x00000000000000002ULL /* enable the other errors */
#define	EER_CEEN	0x00000000000000001ULL /* enable CE */
#define	EER_DISABLE	0x00000000000000000ULL /* no errors enabled */
#define	EER_ECC_DISABLE	(EER_EPEN|EER_UEEN|EER_ISAPEN)
#define	EER_CE_DISABLE	(EER_EPEN|EER_UEEN|EER_ISAPEN|EER_NCEEN)
#define	EER_ENABLE	(EER_EPEN|EER_UEEN|EER_ISAPEN|EER_NCEEN|EER_CEEN)

/*
 * Bits and vaddrs of Spitfire Datapath Error Registers
 */
#define	P_DER_UE	0x00000000000000200ULL	/* UE has occurred */
#define	P_DER_CE	0x00000000000000100ULL	/* CE has occurred */
#define	P_DER_E_SYND	0x000000000000000FFULL	/* SYND<7:0>: ECC syndrome */
#define	P_DER_H		0x0			/* datapath error reg upper */
#define	P_DER_L		0x18			/* datapath error reg upper */

/*
 * Bits of Spitfire Datapath Control Register
 */
#define	P_DCR_VER	0x000001E00		/* datapath version */
#define	P_DCR_F_MODE	0x000000100		/* send FCB<7:0> */
#define	P_DCR_FCB	0x0000000FF		/* ECC check bits to force */
#define	P_DCR_H		0x20			/* datapath control reg upper */
#define	P_DCR_L		0x38			/* datapath control reg lower */

/*
 * Bits and shifts for the Spitfire (S), Sabre (SB) and Hummingbird (HB)
 * Ecache tag data
 */
#define	S_ECTAG_MASK	0x000000000003FFFFFULL	/* spitfire ecache tag mask */
#define	SB_ECTAG_MASK	0x00000000000000FFFULL	/* sabre ecache tag mask */
#define	HB_ECTAG_MASK	0x0000000000000FFFFULL	/* hbird ecache tag mask */
#define	S_ECSTATE_MASK	0x00000000001C00000ULL	/* spitfire tag state mask */
#define	SB_ECSTATE_MASK 0x0000000000000C000ULL	/* sabre tag state mask */
#define	HB_ECSTATE_MASK 0x00000000000030000ULL	/* hbird tag state mask */
#define	S_ECPAR_MASK	0x0000000001E000000ULL	/* spitfire tag parity mask */
#define	SB_ECPAR_MASK	0x00000000000030000ULL	/* sabre tag parity mask */
#define	HB_ECPAR_MASK	0x00000000000300000ULL	/* hbird tag parity mask */
#define	S_ECTAG_SHIFT		19		/* spitfire ecache tag shift */
#define	SB_ECTAG_SHIFT		18		/* sabre ecache tag shift */
#define	HB_ECTAG_SHIFT		16		/* hbird ecache tag shift */
#define	S_ECSTATE_SHIFT		22		/* spitfire tag state shift */
#define	SB_ECSTATE_SHIFT	14		/* sabre tag state shift */
#define	HB_ECSTATE_SHIFT	16		/* hbird tag state shift */
#define	S_ECPAR_SHIFT		25		/* spitfire tag parity shift */
#define	SB_ECPAR_SHIFT		16		/* sabre tag parity shift */
#define	HB_ECPAR_SHIFT		20		/* hbird tag parity shift */
#define	S_ECACHE_MAX_LSIZE	64		/* E$ line size */

/*
 * Constants representing the complete Spitfire (S), Sabre (SB) and Hummingbird
 * (HB) tag state:
 */
#define	S_ECSTATE_SHR		0x1		/* shared */
#define	S_ECSTATE_EXL		0x3		/* exclusive */
#define	S_ECSTATE_OWN		0x5		/* owner */
#define	S_ECSTATE_MOD		0x7		/* modified */
#define	SB_ECSTATE_EXL		0x2		/* exclusive */
#define	SB_ECSTATE_MOD		0x3		/* modified */
#define	HB_ECSTATE_EXL		0x2		/* exclusive */
#define	HB_ECSTATE_MOD		0x3		/* modified */

/*
 * Constants representing the individual Spitfire (S), Sabre (SB) and
 * Hummingbird (HB) state bits:
 */
#define	S_ECSTATE_VALID		0x1		/* line is valid */
#define	S_ECSTATE_DIRTY		0x4		/* line is dirty */
#define	SB_ECSTATE_VALID	0x2		/* line is valid */
#define	SB_ECSTATE_DIRTY	0x1		/* line is dirty */
#define	HB_ECSTATE_VALID	0x2		/* line is valid */
#define	HB_ECSTATE_DIRTY	0x1		/* line is dirty */

/*
 * Constants representing the individual Spitfire (S), Sabre (SB) and
 * Hummingbird (HB) state parity and address parity bits:
 */
#define	S_ECSTATE_PARITY	0x8		/* tag state parity bit */
#define	S_EC_PARITY		0xF		/* all parity bits */
#define	SB_ECSTATE_PARITY	0x2		/* tag state parity bit */
#define	SB_EC_PARITY		0x3		/* all parity bits */
#define	HB_ECSTATE_PARITY	0x2		/* tag state parity bit */
#define	HB_EC_PARITY		0x3		/* all parity bits */

#ifdef HUMMINGBIRD

#define	HB_ESTAR_MODE		INT64_C(0x1FE0000F080)	/* estar mode reg */
#define	HB_MEM_CNTRL0		INT64_C(0x1FE0000F010)	/* mem control0 reg */
#define	HB_REFRESH_COUNT_MASK	0x7F00			/* mc0<14:8>: ref cnt */
#define	HB_REFRESH_COUNT_SHIFT	8			/* bits to shift */
#define	HB_REFRESH_INTERVAL	INT64_C(7800)		/* 7800 nsecs memory */
							/* refresh interval */
							/* works for all DIMM */
							/* same value as OBP */
#define	HB_REFRESH_CLOCKS_PER_COUNT	INT64_C(64)	/* cpu clks per count */
#define	HB_SELF_REFRESH_MASK	0x10000			/* mc0<16>: self ref */
#define	HB_SELF_REFRESH_SHIFT	16			/* bits to shift */
#define	HB_SELF_REFRESH_DISABLE	0			/* disable self ref */
#define	HB_SELF_REFRESH_ENABLE	1			/* enable self ref */

#define	HB_ECLK_1	INT64_C(0x0000000000000000) 	/* 1/1 clock */
#define	HB_ECLK_2	INT64_C(0x0000000000000001) 	/* 1/2 clock */
#define	HB_ECLK_4	INT64_C(0x0000000000000003) 	/* 1/4 clock */
#define	HB_ECLK_6	INT64_C(0x0000000000000002) 	/* 1/6 clock */
#define	HB_ECLK_8	INT64_C(0x0000000000000004) 	/* 1/8 clock */
#define	HB_ECLK_MASK	(HB_ECLK_1|HB_ECLK_2|HB_ECLK_4|HB_ECLK_6|HB_ECLK_8)


/*
 * UPA Configuration Register
 *
 * +--------------+----+------+------+----------+------+-------------+
 * |     Resv     | RR |  DM  | ELIM |   PCON   | MID  |     PCAP    |
 * +--------------+----+------+------+----------+------+-------------+
 *  63          39  38  37..36 35..33 32......22 21..17 16..........0
 *
 */

#define	HB_UPA_DMAP_DATA_BIT	36	/* loads and stores direct mapped */
#define	HB_UPA_DMAP_INSTR_BIT	37	/* instruction misses direct mapped */
#define	HB_UPA_RR_BIT		38	/* reset rand generator */

#endif /* HUMMINGBIRD */

/*
 * The minimum size needed to ensure consistency on a virtually address
 * cache.  Computed by taking the largest virtually indexed cache and dividing
 * by its associativity.
 */
#define	S_VAC_SIZE	0x4000

#ifdef _KERNEL

#ifndef _ASM
#include <sys/kstat.h>

void	get_udb_errors(uint64_t *udbh, uint64_t *udbl);

/*
 * The scrub_misc structure contains miscellaneous bookeepping items for
 * scrubbing the E$.
 *
 * Counter of outstanding E$ scrub requests. The counter for a given CPU id
 * is atomically incremented and decremented _only_  on that CPU,
 * to avoid cacheline ownership bouncing.
 */

typedef struct spitfire_scrub_misc {
	uint32_t	ec_scrub_outstanding;	/* outstanding reqs */
	int		ecache_flush_index;	/* offset into E$ for flush */
	int		ecache_busy;		/* keeps track if cpu busy */
	int		ecache_nlines;		/* no. of E$ lines */
	int		ecache_mirror;		/* E$ is mirrored */
	kstat_t		*ecache_ksp;		/* ptr to the kstat */
} spitfire_scrub_misc_t;

/*
 * Spitfire module private data structure. One of these is allocated for each
 * valid cpu at setup time and is pointed to by the machcpu "cpu_private"
 * pointer.
 */
typedef struct spitfire_private {
	spitfire_scrub_misc_t	sfpr_scrub_misc;
	uint64_t		sfpr_scrub_afsr;
} spitfire_private_t;

#endif /* !_ASM */

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SPITREGS_H */
