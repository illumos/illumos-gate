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

#ifndef _SYS_TRAPSTAT_H
#define	_SYS_TRAPSTAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#if (NCPU > 508)
#error "sun4v trapstat supports up to 508 cpus"
#endif

#define	TSTAT_TLB_STATS		0x1		/* cpu_tstat_flags */
#define	TSTAT_INSTR_SIZE	\
	((sizeof (tstat_instr_t) + MMU_PAGESIZE - 1) & ~(MMU_PAGESIZE - 1))
#define	TSTAT_DATA_SHIFT	13
#define	TSTAT_DATA_SIZE		(1 << TSTAT_DATA_SHIFT)	/* 8K per CPU */
#define	TSTAT_TBA_MASK		~((1 << 15) - 1)	/* 32K boundary */

#define	TSTAT_CPU0_DATA_OFFS(tcpu, mem)	\
	((uintptr_t)(tcpu)->tcpu_ibase + TSTAT_INSTR_SIZE + \
	    offsetof(tstat_data_t, mem))

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
} tstat_percpu_t;

#endif

#endif
#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TRAPSTAT_H */
