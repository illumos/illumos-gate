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

#ifndef	_ZULUMOD_H
#define	_ZULUMOD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/int_const.h>
#include <sys/zuluvm.h>

#ifndef _ASM

#include <sys/zulu_hat.h>
#include <sys/sysmacros.h>

#define	ZULUVM_VERSION_STR(a)	#a
#define	ZULUVM_VERSION(a)	ZULUVM_VERSION_STR(a)
#define	ZULUVM_MOD_VERSION \
	ZULUVM_VERSION(XHAT_PROVIDER_VERSION) "." \
	ZULUVM_VERSION(ZULUVM_INTERFACE_VERSION)

#define	ZULUDCHKFUNC(_p1, _p2, _p3) \
	((_p1) != NULL && (_p1)->_p2 != NULL) ? \
	(_p1)->_p2 _p3 : ZULUVM_NO_SUPPORT
#define	ZULUDCHKPROC(_p1, _p2, _p3) \
	if ((_p1) != NULL && (_p1)->_p2 != NULL) (_p1)->_p2 _p3

#define	zulud_set_itlb_pc(_devp, _a, _b) \
	ZULUDCHKPROC((_devp)->dops, set_itlb_pc, (_a, _b))
#define	zulud_set_dtlb_pc(_devp, _a, _b) \
	ZULUDCHKPROC((_devp)->dops, set_dtlb_pc, (_a, _b))
#define	zulud_write_tte(_devp, _a, _b, _c, _d, _e, _f) \
	ZULUDCHKFUNC((_devp)->dops, write_tte, (_a, _b, _c, _d, _e, _f))
#define	zulud_tlb_done(_devp, _a, _b, _c) \
	ZULUDCHKPROC((_devp)->dops, tlb_done, (_a, _b, _c))
#define	zulud_demap_page(_devp, _a, _b, _c) \
	ZULUDCHKPROC((_devp)->dops, demap_page, (_a, _b, _c))
#define	zulud_demap_ctx(_devp, _a, _b) \
	ZULUDCHKPROC((_devp)->dops, demap_ctx, (_a, _b))

#endif

#define	ZULUVM_DATA0_IDX	0
#define	ZULUVM_DATA1_IDX	1
#define	ZULUVM_DATA2_IDX	2
#define	ZULUVM_DATA3_IDX	3
#define	ZULUVM_DATA4_IDX	4
#define	ZULUVM_DATA5_IDX	5
#define	ZULUVM_DATA6_IDX	6
#define	ZULUVM_DATA7_IDX	7

#define	ZULUVM_IDX2FLAG(i)	(1 << (7 - i))
#define	ZULUVM_DATA0_FLAG	ZULUVM_IDX2FLAG(ZULUVM_DATA0_IDX)
#define	ZULUVM_DATA1_FLAG	ZULUVM_IDX2FLAG(ZULUVM_DATA1_IDX)
#define	ZULUVM_DATA2_FLAG	ZULUVM_IDX2FLAG(ZULUVM_DATA2_IDX)
#define	ZULUVM_DATA3_FLAG	ZULUVM_IDX2FLAG(ZULUVM_DATA3_IDX)
#define	ZULUVM_DATA4_FLAG	ZULUVM_IDX2FLAG(ZULUVM_DATA4_IDX)
#define	ZULUVM_DATA5_FLAG	ZULUVM_IDX2FLAG(ZULUVM_DATA5_IDX)
#define	ZULUVM_DATA6_FLAG	ZULUVM_IDX2FLAG(ZULUVM_DATA6_IDX)
#define	ZULUVM_DATA7_FLAG	ZULUVM_IDX2FLAG(ZULUVM_DATA7_IDX)

#define	ZULUVM_TLB_ADDR_IDX	ZULUVM_DATA0_IDX
#define	ZULUVM_TLB_TYPE_IDX	ZULUVM_DATA1_IDX
#define	ZULUVM_TLB_TTE_IDX	ZULUVM_DATA2_IDX
#define	ZULUVM_TLB_ERRCODE_IDX	ZULUVM_DATA3_IDX

#define	ZULUVM_DATA_FLAGS	(ZULUVM_DATA1_FLAG | \
				ZULUVM_DATA6_FLAG)

#define	ZULUVM_GET_TLB_TTE(devp) \
		(devp)->zvm.idata[ZULUVM_TLB_TTE_IDX]
#define	ZULUVM_GET_TLB_ADDR(devp) \
		(devp)->zvm.idata[ZULUVM_TLB_ADDR_IDX]
#define	ZULUVM_GET_TLB_TYPE(devp) (ZULUVM_DMA_MASK & \
		(devp)->zvm.idata[ZULUVM_TLB_TYPE_IDX])
#define	ZULUVM_GET_TLB_ERRCODE(devp) (int)(0xffffffff & \
		(devp)->zvm.idata[ZULUVM_TLB_ERRCODE_IDX])

#define	ZULUVM_MAX_DEV		2
#define	ZULUVM_PIL		PIL_2
#define	ZULUVM_NUM_PGSZS	4

#define	ZULUVM_STATE_IDLE		0
#define	ZULUVM_STATE_STOPPED		1
#define	ZULUVM_STATE_CANCELED		2
#define	ZULUVM_STATE_TLB_PENDING	3
#define	ZULUVM_STATE_INTR_QUEUED	4
#define	ZULUVM_STATE_INTR_PENDING	5
#define	ZULUVM_STATE_WRITE_TTE		6

#ifndef _ASM

typedef struct {
	uint64_t	idata[4];	/* mondo pkt copy area */
	void		*arg;		/* arg for device calls */
	uint64_t	mmu_pa;		/* phy. addr of MMU regs */
	struct zuluvm_proc *proc1;
	struct zuluvm_proc *proc2;
	volatile uint32_t state;	/* state of tlb miss handling */
	uint64_t	intr_num;	/* our soft intr number */
	short		dmv_intr;	/* dmv interrupt handle */
#ifdef ZULUVM_STATS
	int 		cancel;
	int		tlb_miss[ZULUVM_NUM_PGSZS];
	int		pagefault;
	int		no_mapping;
	int		preload;
	int		migrate;
	int		pagesize;
	int		itlb1miss;
	int		dtlb1miss;
	int		itlb2miss;
	int		dtlb2miss;
	int		demap_page;
	int		demap_ctx;
#endif
	uint64_t	pfnbuf[50];
	int		pfncnt;
} zuluvm_miss_t;

#ifdef ZULUVM_STATS
#define	ZULUVM_STATS_MISS(devp, sz)	(devp)->zvm.tlb_miss[sz]++
#define	ZULUVM_STATS_PAGEFAULT(devp)	(devp)->zvm.pagefault++
#define	ZULUVM_STATS_NOMAP(devp)	(devp)->zvm.no_mapping++
#define	ZULUVM_STATS_PRELOAD(devp)	(devp)->zvm.preload++
#define	ZULUVM_STATS_MIGRATE(devp)	(devp)->zvm.migrate++
#define	ZULUVM_STATS_PAGEZISE(devp)	(devp)->zvm.pagesize++
#define	ZULUVM_STATS_CANCEL(devp)	(devp)->zvm.cancel++
#define	ZULUVM_STATS_DEMAP_PAGE(devp)	(devp)->zvm.demap_page++
#define	ZULUVM_STATS_DEMAP_CTX(devp)	(devp)->zvm.demap_ctx++
#else
#define	ZULUVM_STATS_MISS(devp, sz)
#define	ZULUVM_STATS_PAGEFAULT(devp)
#define	ZULUVM_STATS_NOMAP(devp)
#define	ZULUVM_STATS_PRELOAD(devp)
#define	ZULUVM_STATS_MIGRATE(devp)
#define	ZULUVM_STATS_PAGEZISE(devp)
#define	ZULUVM_STATS_CANCEL(devp)
#define	ZULUVM_STATS_DEMAP_PAGE(devp)
#define	ZULUVM_STATS_DEMAP_CTX(devp)
#endif

#define	ZULUVM_MAX_INTR 32

typedef struct {
	short offset;
	short ino;
} zuluvm_intr_t;

/*
 * This structure contains per device data.
 * It is protected by dev_lck.
 */
typedef struct {
	zuluvm_miss_t		zvm;		/* tlb miss state */
	volatile uint64_t	*imr;		/* intr mapping regs */
	struct zuluvm_proc 	*procs; 	/* protected by proc_lck */
	dev_info_t		*dip;		/* device driver instance */
	zulud_ops_t		*dops;		/* device drv operations */
	kmutex_t		load_lck;	/* protects in_intr */
	kmutex_t		dev_lck;	/* protects this struct */
	kmutex_t 		proc_lck;	/* protects active procs */
	kcondvar_t 		intr_wait;	/* sync for as_free */
	int			intr_flags;
	int			in_intr;
	kmutex_t		park_lck;	/* page fault thread */
	kcondvar_t		park_cv;
	int			parking;
	int			agentid;	/* zulu's agent id */
	zuluvm_intr_t		interrupts[ZULUVM_MAX_INTR];
} zuluvm_state_t;

#define	ZULUVM_INTR_OFFSET	offsetof(zuluvm_state_t, interrupts)
#define	ZULUVM_INTR2INO(addr)	(((zuluvm_intr_t *)(addr))->ino)
#define	ZULUVM_INTR2ZDEV(addr) \
	(zuluvm_state_t *)((caddr_t)addr - (ZULUVM_INTR2INO(addr) * \
	sizeof (zuluvm_intr_t)) - ZULUVM_INTR_OFFSET)

typedef struct zuluvm_proc {
	struct zulu_hat	*zhat;
	zuluvm_state_t  *zdev;  /* back ptr to dev instance */
	unsigned short	refcnt;	/* keep this until ref == 0 */
	short		valid;	/* if valid is 0 then don't use */
	struct zuluvm_proc *next;
	struct zuluvm_proc *prev;
} zuluvm_proc_t;

#define	ZULUVM_DO_INTR1		INT32_C(1)
#define	ZULUVM_WAIT_INTR1	INT32_C(2)
#define	ZULUVM_DO_INTR2		INT32_C(4)
#define	ZULUVM_WAIT_INTR2	INT32_C(8)

int zuluvm_change_state(uint32_t *state_pa, int new, int assume);
void zuluvm_demap_page(void *, struct hat *, short, caddr_t, uint_t);
void zuluvm_demap_ctx(void *, short);
void zuluvm_dmv_tlbmiss_tl1(void);
void zuluvm_load_tte(struct zulu_hat *zhat, caddr_t addr, uint64_t pfn,
		int perm, int size);


#endif

/*
 * The following defines are copied from the ZFB and ZULU
 * workspaces. We re-define them here since we can't have
 * a dependency onto files outside our consolidation
 */
#define	ZULUVM_IMR_V_MASK	UINT64_C(0x0000000080000000)
#define	ZULUVM_IMR_TARGET_SHIFT INT32_C(26)
#define	ZULUVM_IMR_MAX		INT32_C(0x3f)

#define	ZULUVM_ZFB_MMU_TLB_D_V_MASK	  0x8000000000000000
#define	ZULUVM_ZFB_MMU_TLB_D_PA_SHIFT	  0xD	/* 13 bits */
#define	ZULUVM_ZFB_MMU_TLB_D_C_MASK	  0x20
#define	ZULUVM_ZFB_MMU_TLB_D_SZ_SHIFT	  0x3D	/* 61 */
#define	ZULUVM_ZFB_MMU_TLB_D_SZ_MASK	  0x6000000000000000
#define	ZULUVM_ZFB_MMU_TLB_D_W_MASK	  0x2
#define	ZULUVM_ZFB_MMU_TLB_CR_IMISS_MASK  0x2
#define	ZULUVM_ZFB_MMU_TLB_CR_DMISS_MASK  0x1
#define	ZULUVM_ZFB_MMU_DTLB_PAGE_SZ_2_MASK  0xc /* DTLB2 Page size */
#define	ZULUVM_ZFB_MMU_DTLB_PAGE_SZ_2_SHIFT 2
#define	ZULUVM_DTLB_PAGE_SZ	0x8
#define	ZULUVM_ITLB_DATA_IN	0x18
#define	ZULUVM_DTLB_DATA_IN	0x28
#define	ZULUVM_TLB_CONTROL	0
#define	ZULUVM_ITLB_MISS_ICR	0x0
#define	ZULUVM_DTLB_MISS_ICR	0x8
#define	ZULUVM_DMA1_TSB_BASE	0x50
#define	ZULUVM_DMA2_TSB_BASE	0x68

#ifdef	__cplusplus
}
#endif

#endif	/* _ZULUMOD_H */
