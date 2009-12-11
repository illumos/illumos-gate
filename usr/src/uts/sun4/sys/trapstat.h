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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_TRAPSTAT_H
#define	_SYS_TRAPSTAT_H

#ifndef _ASM
#include <sys/processor.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#define	TSTATIOC	(('t' << 16) | ('s' << 8))

#define	TSTATIOC_READ		(TSTATIOC | 1)
#define	TSTATIOC_GO		(TSTATIOC | 2)
#define	TSTATIOC_NOGO		(TSTATIOC | 3)
#define	TSTATIOC_STOP		(TSTATIOC | 4)
#define	TSTATIOC_CPU		(TSTATIOC | 5)
#define	TSTATIOC_NOCPU		(TSTATIOC | 6)
#define	TSTATIOC_ENTRY		(TSTATIOC | 7)
#define	TSTATIOC_NOENTRY	(TSTATIOC | 8)
#define	TSTATIOC_TLBDATA	(TSTATIOC | 9)

#define	TSTAT_NENT		512

#ifndef _ASM

/*
 * tstat_missdata_t must be of size 2^n, for some value of n.  This allows
 * tstat_tlbdata_t to be of size 2^(n+2), and tstat_pgszdata_t to be of
 * size 2^(n+3) -- a constraint which greatly simplifies the TLB return
 * entry.
 */
typedef struct tstat_missdata {
	uint64_t	tmiss_count;
	hrtime_t	tmiss_time;
} tstat_missdata_t;

typedef struct tstat_tlbdata {
	tstat_missdata_t	ttlb_tlb;
	tstat_missdata_t	ttlb_tsb;
} tstat_tlbdata_t;

typedef struct tstat_modedata {
	tstat_tlbdata_t		tmode_itlb;
	tstat_tlbdata_t		tmode_dtlb;
} tstat_modedata_t;

typedef struct tstat_pgszdata {
	tstat_modedata_t	tpgsz_user;
	tstat_modedata_t	tpgsz_kernel;
} tstat_pgszdata_t;

#ifdef sun4v
/*
 * For sun4v, we optimized by using a smaller 4K data area
 * per-cpu. We use separate structures for data collection,
 * one for normal trapstat collection and one for collecting
 * TLB stats. Note that we either collect normal trapstats
 * or TLB stats, never both. For TLB stats, we are only
 * interested in the MMU/TLB miss traps (which are trap #s
 * 0x9, 0x32, 0x64 & 0x68)
 */
#define	TSTAT_TLB_NENT	200 /* max trap entries for tlb stats */

typedef struct tstat_ndata {
	uint64_t	tdata_traps[TSTAT_NENT];
} tstat_ndata_t;

typedef struct tstat_tdata {
	uint64_t	tdata_traps[TSTAT_TLB_NENT];
	hrtime_t	tdata_tmptick;
	tstat_pgszdata_t tdata_pgsz[1];
} tstat_tdata_t;
#endif /* sun4v */

typedef struct tstat_data {
	processorid_t	tdata_cpuid;
	hrtime_t	tdata_snapts;
	hrtime_t	tdata_snaptick;
	hrtime_t	tdata_tmptick;
	hrtime_t	tdata_peffect;
	uint64_t	tdata_traps[TSTAT_NENT];
	tstat_pgszdata_t tdata_pgsz[1];
} tstat_data_t;

#endif

#ifdef _KERNEL

#define	TSTAT_TLGT0_NENT	256
#define	TSTAT_TOTAL_NENT	(TSTAT_NENT + TSTAT_TLGT0_NENT)

#define	TSTAT_ENT_NINSTR	8		/* 8 instructions/entry */
#define	TSTAT_ENT_SHIFT		5		/* 32 bytes/entry */
#define	TSTAT_ENT_ITLBMISS	0x64
#define	TSTAT_ENT_DTLBMISS	0x68

#define	TSTAT_TLBRET_NINSTR	32

#define	TSTAT_PROBE_NPAGES	2048
#define	TSTAT_PROBE_SIZE	(TSTAT_PROBE_NPAGES * MMU_PAGESIZE)
#define	TSTAT_PROBE_NLAPS	10

#ifdef sun4v
#define	TSTAT_TRAPCNT_NINSTR	8
#define	TSTAT_TLBENT_NINSTR	64
#define	TSTAT_ENT_IMMUMISS	0x09
#define	TSTAT_ENT_DMMUMISS	0x31
#endif

#ifndef _ASM

typedef struct tstat_tlbretent {
	uint32_t	ttlbrent_instr[TSTAT_TLBRET_NINSTR];
} tstat_tlbretent_t;

#ifdef sun4v
typedef struct tstat_tlbent {
	uint32_t	ttlbent_instr[TSTAT_TLBENT_NINSTR];
} tstat_tlbent_t;
#endif /* sun4v */


typedef struct tstat_tlbret {
	tstat_tlbretent_t	ttlbr_ktlb;
	tstat_tlbretent_t	ttlbr_ktsb;
	tstat_tlbretent_t	ttlbr_utlb;
	tstat_tlbretent_t	ttlbr_utsb;
} tstat_tlbret_t;

typedef struct tstat_instr {
	uint32_t	tinst_traptab[TSTAT_TOTAL_NENT * TSTAT_ENT_NINSTR];
	tstat_tlbret_t	tinst_itlbret;
	tstat_tlbret_t	tinst_dtlbret;
#ifdef sun4v
	tstat_tlbent_t	tinst_immumiss;
	tstat_tlbent_t	tinst_dmmumiss;
	uint32_t	tinst_trapcnt[TSTAT_TRAPCNT_NINSTR];
#endif
} tstat_instr_t;

typedef struct tstat_tsbmiss_patch_entry {
	uint32_t *tpe_addr;
	uint32_t tpe_instr;
} tstat_tsbmiss_patch_entry_t;

#endif

#ifdef sun4v

#define	TSTAT_TLB_STATS		0x1		/* cpu_tstat_flags */
#define	TSTAT_INSTR_SIZE	\
	((sizeof (tstat_instr_t) + MMU_PAGESIZE - 1) & ~(MMU_PAGESIZE - 1))
#define	TSTAT_DATA_SHIFT	12
#define	TSTAT_DATA_SIZE		(1 << TSTAT_DATA_SHIFT)	/* 4K per CPU */
#define	TSTAT_TBA_MASK		~((1 << 15) - 1)	/* 32K boundary */

#define	TSTAT_CPU0_DATA_OFFS(tcpu, mem)	\
	((uintptr_t)(tcpu)->tcpu_ibase + TSTAT_INSTR_SIZE + \
	    offsetof(tstat_ndata_t, mem))

#define	TSTAT_CPU0_TLBDATA_OFFS(tcpu, mem) \
	((uintptr_t)(tcpu)->tcpu_ibase + TSTAT_INSTR_SIZE + \
	    offsetof(tstat_tdata_t, mem))

/*
 * Sun4v trapstat can use up to 3 4MB pages to support
 * 3064 cpus. Each cpu needs 4K of data page for stats collection.
 * The first 32K (TSTAT_TRAPTBLE_SIZE) in the first 4 MB page is
 * use for the traptable leaving 4MB - 32K = 4064K for cpu data
 * which work out to be 4064/4K = 1016 cpus. Each additional
 * 4MB page (2nd and 3rd ones) can support 4096/4 = 1024 cpus.
 * This works out to be a total of 1016 + 1024 + 1024 = 3064 cpus.
 */
#define	ROUNDUP(a, n)	(((a) + ((n) - 1)) & ~((n) - 1))
#define	TSTAT_MAXNUM4M_MAPPING	3
#define	TSTAT_TRAPTBL_SIZE	(32 * 1024)
#define	TSTAT_NUM4M_LIMIT \
	(ROUNDUP((NCPU * TSTAT_DATA_SIZE) + TSTAT_TRAPTBL_SIZE, \
	    MMU_PAGESIZE4M) >> MMU_PAGESHIFT4M)

#if (TSTAT_NUM4M_LIMIT > TSTAT_MAXNUM4M_MAPPING)
#error "NCPU is too large for trapstat"
#endif

/*
 * Note that the macro below is almost identical to the
 * one for TSTAT_NUM4M_LIMIT with one difference. Instead of
 * using TSTAT_TRAPTBL_SIZE constant, it uses TSTAT_INSTR_SIZE which
 * has a runtime sizeof() expression. The result should be
 * the same. This macro is used at runtime as an extra
 * validation for correctness.
 */
#define	TSTAT_NUM4M_MACRO(ncpu) \
	(ROUNDUP(((ncpu) * TSTAT_DATA_SIZE) + TSTAT_INSTR_SIZE, \
	    MMU_PAGESIZE4M) >> MMU_PAGESHIFT4M)

#else /* sun4v */

#define	TSTAT_INSTR_PAGES	((sizeof (tstat_instr_t) >> MMU_PAGESHIFT) + 1)
#define	TSTAT_INSTR_SIZE	(TSTAT_INSTR_PAGES * MMU_PAGESIZE)
#define	TSTAT_TBA_MASK		~((1 << 16) - 1)	/* 64K per cpu */

#define	TSTAT_DATA_OFFS(tcpu, mem)	\
	((uintptr_t)(tcpu)->tcpu_dbase + offsetof(tstat_data_t, mem))

#endif /* sun4v */

#define	TSTAT_INSTR_OFFS(tcpu, mem)	\
	((uintptr_t)(tcpu)->tcpu_ibase + offsetof(tstat_instr_t, mem))

#define	TSTAT_CPU_SELECTED	0x0001
#define	TSTAT_CPU_ALLOCATED	0x0002
#define	TSTAT_CPU_ENABLED	0x0004

#define	TSTAT_OPT_CPU		0x0001
#define	TSTAT_OPT_NOGO		0x0002
#define	TSTAT_OPT_TLBDATA	0x0004
#define	TSTAT_OPT_ENTRY		0x0008

#define	TSTAT_TSBMISS_INSTR	0x8e01e000	/* add %g7, 0, %g7 */

#ifndef _ASM

typedef struct tstat_percpu {
	uint32_t	tcpu_flags;
	caddr_t		tcpu_tba;
	caddr_t		tcpu_vabase;
	caddr_t		tcpu_ibase;
	caddr_t		tcpu_dbase;
	pfn_t		*tcpu_pfn;
	tstat_instr_t	*tcpu_instr;
	tstat_data_t	*tcpu_data;
#ifdef sun4v
	hrtime_t	tcpu_tdata_peffect;
#endif /* sun4v */
} tstat_percpu_t;

#endif

#endif
#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TRAPSTAT_H */
