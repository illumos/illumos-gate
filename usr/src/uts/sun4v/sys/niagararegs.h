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

#ifndef _SYS_NIAGARAREGS_H
#define	_SYS_NIAGARAREGS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Niagara SPARC Performance Instrumentation Counter
 */
#define	PIC0_MASK (((uint64_t)1 << 32) - 1)	/* pic0 in bits 31:0 */
#define	PIC1_SHIFT 32				/* pic1 in bits 64:32 */

/*
 * Niagara SPARC Performance Control Register
 */

#define	CPC_NIAGARA_PCR_PRIVPIC		0
#define	CPC_NIAGARA_PCR_SYS		1
#define	CPC_NIAGARA_PCR_USR		2

#define	CPC_NIAGARA_PCR_PIC0_SHIFT	4
#define	CPC_NIAGARA_PCR_PIC1_SHIFT	0
#define	CPC_NIAGARA_PCR_PIC0_MASK	UINT64_C(0x7)
#define	CPC_NIAGARA_PCR_PIC1_MASK	UINT64_C(0)

#define	CPC_NIAGARA_PCR_OVF_MASK	UINT64_C(0x300)
#define	CPC_NIAGARA_PCR_OVF_SHIFT	8

/*
 * Niagara DRAM performance counters
 */
#define	NIAGARA_DRAM_BANKS		0x4

#define	NIAGARA_DRAM_PIC0_SEL_SHIFT	0x4
#define	NIAGARA_DRAM_PIC1_SEL_SHIFT	0x0

#define	NIAGARA_DRAM_PIC0_SHIFT		0x20
#define	NIAGARA_DRAM_PIC0_MASK		0x7fffffff
#define	NIAGARA_DRAM_PIC1_SHIFT		0x0
#define	NIAGARA_DRAM_PIC1_MASK		0x7fffffff

/*
 * Niagara JBUS performance counters
 */
#define	NIAGARA_JBUS_PIC0_SEL_SHIFT	0x4
#define	NIAGARA_JBUS_PIC1_SEL_SHIFT	0x0

#define	NIAGARA_JBUS_PIC0_SHIFT		0x20
#define	NIAGARA_JBUS_PIC0_MASK		0x7fffffff
#define	NIAGARA_JBUS_PIC1_SHIFT		0x0
#define	NIAGARA_JBUS_PIC1_MASK		0x7fffffff


/*
 * Hypervisor FAST_TRAP API function numbers to get/set DRAM and
 * JBUS performance counters
 */
#define	HV_NIAGARA_GETPERF	0x100
#define	HV_NIAGARA_SETPERF	0x101

/*
 * Hypervisor FAST_TRAP API function numbers for Niagara MMU statistics
 */
#define	HV_NIAGARA_MMUSTAT_CONF	0x102
#define	HV_NIAGARA_MMUSTAT_INFO	0x103

/*
 * DRAM/JBUS performance counter register numbers for HV_NIAGARA_GETPERF
 * and HV_NIAGARA_SETPERF
 */
#define	HV_NIAGARA_JBUS_CTL		0x0
#define	HV_NIAGARA_JBUS_COUNT		0x1
#define	HV_NIAGARA_DRAM_CTL0		0x2
#define	HV_NIAGARA_DRAM_COUNT0		0x3
#define	HV_NIAGARA_DRAM_CTL1		0x4
#define	HV_NIAGARA_DRAM_COUNT1		0x5
#define	HV_NIAGARA_DRAM_CTL2		0x6
#define	HV_NIAGARA_DRAM_COUNT2		0x7
#define	HV_NIAGARA_DRAM_CTL3		0x8
#define	HV_NIAGARA_DRAM_COUNT3		0x9

#ifndef _ASM

/*
 * Niagara MMU statistics data structure
 */

#define	NIAGARA_MMUSTAT_PGSZS	8

typedef struct niagara_tsbinfo {
	uint64_t	tsbhit_count;
	uint64_t	tsbhit_time;
} niagara_tsbinfo_t;

typedef struct niagara_mmustat {
	niagara_tsbinfo_t	kitsb[NIAGARA_MMUSTAT_PGSZS];
	niagara_tsbinfo_t	uitsb[NIAGARA_MMUSTAT_PGSZS];
	niagara_tsbinfo_t	kdtsb[NIAGARA_MMUSTAT_PGSZS];
	niagara_tsbinfo_t	udtsb[NIAGARA_MMUSTAT_PGSZS];
} niagara_mmustat_t;


/*
 * prototypes for hypervisor interface to get/set DRAM and JBUS
 * performance counters
 */
extern uint64_t hv_niagara_setperf(uint64_t regnum, uint64_t val);
extern uint64_t hv_niagara_getperf(uint64_t regnum, uint64_t *val);
extern uint64_t hv_niagara_mmustat_conf(uint64_t buf, uint64_t *prev_buf);
extern uint64_t hv_niagara_mmustat_info(uint64_t *buf);

#endif /* _ASM */

/*
 * Bits defined in L2 Error Status Register
 *
 *	(Niagara 1)
 * +---+---+---+---+----+----+----+----+----+----+----+----+----+----+
 * |MEU|MEC|RW |RSV|MODA|VCID|LDAC|LDAU|LDWC|LDWU|LDRC|LDRU|LDSC|LDSU|
 * +---+---+---+---+----+----+----+----+----+----+----+----+----+----+
 *  63  62  61  60   59 58-54  53   52   51   50   49   48   47   46
 *
 *	(Niagara 2)
 * +---+---+---+----+--------+----+----+----+----+----+----+----+----+
 * |MEU|MEC|RW |MODA|  VCID  |LDAC|LDAU|LDWC|LDWU|LDRC|LDRU|LDSC|LDSU|
 * +---+---+---+----+--------+----+----+----+----+----+----+----+----+
 *  63  62  61  60     59-54   53   52   51   50   49   48   47   46
 *
 *      (Niagara 1)
 * +---+---+---+---+---+---+---+---+---+---+---+-------+------+
 * |LTC|LRU|LVU|DAC|DAU|DRC|DRU|DSC|DSU|VEC|VEU| RSVD1 | SYND |
 * +---+---+---+---+---+---+---+---+---+---+---+-------+------+
 *  45  44  43  42  41  40  39  38  37  36  35   34-32   31-0
 *
 *      (Niagara 2)
 * +---+---+---+---+---+---+---+---+---+---+---+---+----+-----+
 * |LTC|LRU|LVU|DAC|DAU|DRC|DRU|DSC|DSU|VEC|VEU|LVC|RSVD| SYND|
 * +---+---+---+---+---+---+---+---+---+---+---+---+----+-----+
 *  45  44  43  42  41  40  39  38  37  36  35  34  33-28 27-0
 *
 * Note that relative to error status bits, Niagara-1 is a strict subset of
 * Niagara-2.
 */

#define	NI_L2AFSR_MEU 	0x8000000000000000ULL
#define	NI_L2AFSR_MEC	0x4000000000000000ULL
#define	NI_L2AFSR_RW 	0x2000000000000000ULL
#define	NI2_L2AFSR_MODA	0x1000000000000000ULL
#define	NI1_L2AFSR_MODA	0x0800000000000000ULL
#define	NI_L2AFSR_VCID	0x07C0000000000000ULL
#define	NI_L2AFSR_LDAC	0x0020000000000000ULL
#define	NI_L2AFSR_LDAU	0x0010000000000000ULL
#define	NI_L2AFSR_LDWC	0x0008000000000000ULL
#define	NI_L2AFSR_LDWU	0x0004000000000000ULL
#define	NI_L2AFSR_LDRC	0x0002000000000000ULL
#define	NI_L2AFSR_LDRU	0x0001000000000000ULL
#define	NI_L2AFSR_LDSC	0x0000800000000000ULL
#define	NI_L2AFSR_LDSU	0x0000400000000000ULL
#define	NI_L2AFSR_LTC	0x0000200000000000ULL
#define	NI_L2AFSR_LRU	0x0000100000000000ULL
#define	NI_L2AFSR_LVU	0x0000080000000000ULL
#define	NI_L2AFSR_DAC	0x0000040000000000ULL
#define	NI_L2AFSR_DAU	0x0000020000000000ULL
#define	NI_L2AFSR_DRC	0x0000010000000000ULL
#define	NI_L2AFSR_DRU	0x0000008000000000ULL
#define	NI_L2AFSR_DSC	0x0000004000000000ULL
#define	NI_L2AFSR_DSU	0x0000002000000000ULL
#define	NI_L2AFSR_VEC	0x0000001000000000ULL
#define	NI_L2AFSR_VEU	0x0000000800000000ULL
#define	NI_L2AFSR_LVC	0x0000000400000000ULL
#define	NI1_L2AFSR_SYND	0x00000000FFFFFFFFULL
#define	NI2_L2AFSR_SYND	0x000000000FFFFFFFULL

/*
 * These L2 bit masks are used to determine if another bit of higher priority
 * is set.  This tells us whether the reported syndrome and address are valid
 * for this ereport. If the error in hand is Pn, use Pn-1 to bitwise & with
 * the l2-afsr value.  If result is 0, then this ereport's afsr is valid.
 */
#define	NI_L2AFSR_P01	(NI_L2AFSR_LVU)
#define	NI_L2AFSR_P02	(NI_L2AFSR_P01 | NI_L2AFSR_LRU)
#define	NI_L2AFSR_P03	(NI_L2AFSR_P02 | NI_L2AFSR_LDAU | NI_L2AFSR_LDSU)
#define	NI_L2AFSR_P04	(NI_L2AFSR_P03 | NI_L2AFSR_LDWU)
#define	NI_L2AFSR_P05	(NI_L2AFSR_P04 | NI_L2AFSR_LDRU)
#define	NI_L2AFSR_P06	(NI_L2AFSR_P05 | NI_L2AFSR_DAU | NI_L2AFSR_DRU)
#define	NI_L2AFSR_P07   (NI_L2AFSR_P06 | NI_L2AFSR_LVC)
#define	NI_L2AFSR_P08	(NI_L2AFSR_P07 | NI_L2AFSR_LTC)
#define	NI_L2AFSR_P09	(NI_L2AFSR_P08 | NI_L2AFSR_LDAC | NI_L2AFSR_LDSC)
#define	NI_L2AFSR_P10	(NI_L2AFSR_P09 | NI_L2AFSR_LDWC)
#define	NI_L2AFSR_P11	(NI_L2AFSR_P10 | NI_L2AFSR_LDRC)
#define	NI_L2AFSR_P12	(NI_L2AFSR_P11 | NI_L2AFSR_DAC | NI_L2AFSR_DRC)

/*
 * Bits defined in DRAM Error Status Register (Niagara-2)
 * Niagara-1 is strict subset
 *
 * +---+---+---+---+---+---+---+---+---+---+----------+------+
 * |MEU|MEC|DAC|DAU|DSC|DSU|DBU|MEB|FBU|FBR| RESERVED | SYND |
 * +---+---+---+---+---+---+---+---+---+---+----------+------+
 *  63  62  61  60  59  58  57  56  55  54    53-16     15-0
 *
 */
#define	NI_DMAFSR_MEU 	0x8000000000000000ULL
#define	NI_DMAFSR_MEC	0x4000000000000000ULL
#define	NI_DMAFSR_DAC 	0x2000000000000000ULL
#define	NI_DMAFSR_DAU	0x1000000000000000ULL
#define	NI_DMAFSR_DSC	0x0800000000000000ULL
#define	NI_DMAFSR_DSU	0x0400000000000000ULL
#define	NI_DMAFSR_DBU	0x0200000000000000ULL
#define	NI_DMAFSR_MEB	0x0100000000000000ULL
#define	NI_DMAFSR_FBU	0x0080000000000000ULL
#define	NI_DMAFSR_FBR	0x0040000000000000ULL
#define	NI_DMAFSR_SYND	0x000000000000FFFFULL

/* Bit mask for DRAM priority determination */
#define	NI_DMAFSR_P01	(NI_DMAFSR_DSU | NI_DMAFSR_DAU | NI_DMAFSR_FBU)

/*
 * The following is the syndrome value placed in memory
 * when an uncorrectable error is written back from L2 cache.
 */
#define	NI_DRAM_POISON_SYND_FROM_LDWU		0x1118
#define	N2_DRAM_POISON_SYND_FROM_LDWU		0x8221

/*
 * This L2 poison syndrome is placed on 4 byte checkwords of L2
 * when a UE is loaded or DMA'ed into L2
 */
#define	NI_L2_POISON_SYND_FROM_DAU		0x3
#define	NI_L2_POISON_SYND_MASK			0x7F
#define	NI_L2_POISON_SYND_SIZE			7

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NIAGARAREGS_H */
