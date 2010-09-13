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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__ZULUVM_INCL__
#define	__ZULUVM_INCL__

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* zulud interface */

#ifndef _ASM

#include <sys/dditypes.h>

typedef struct {
	caddr_t	addr;
	size_t  len;
	int	tlbtype;
} zulud_preload_t;

typedef struct {
	int version;
	int (*set_itlb_pc)(void *handle, uint64_t mondo);
	int (*set_dtlb_pc)(void *handle, uint64_t mondo);
	int (*set_suspendAck_pc)(void *handle, uint64_t mondo);
	int (*write_tte)(void *handle, int ttesize, uint64_t tag,
	    pfn_t pfn, int permission, int tlbtype);
	int (*tlb_done)(void *handle, int tlbtype, int status);
	int (*demap_page)(void *handle, caddr_t vaddr, short ctx);
	int (*demap_ctx)(void *handle, short ctx);
	int (*dma_suspend_ack)(void *handle);
	int (*set_tsb)(void *handle, int tlbtype, uint64_t tsbreg);
} zulud_ops_t;

#endif

#define	ZULUVM_SUCCESS		0
#define	ZULUVM_ERROR		1
#define	ZULUVM_NO_TTE		2
#define	ZULUVM_INVALID_MISS	3
#define	ZULUVM_NO_DEV		4
#define	ZULUVM_NO_HAT		5
#define	ZULUVM_NO_MAP		6
#define	ZULUVM_VERSION_MISMATCH	7
#define	ZULUVM_TTE_DELAY	8
#define	ZULUVM_MISS_CANCELED	9
#define	ZULUVM_BAD_IDX		10
#define	ZULUVM_WATCH_POINT	11
#define	ZULUVM_NO_SUPPORT	12
#define	ZULUVM_CTX_LOCKED	13

#define	ZULUVM_ITLB_FLAG	0x1
#define	ZULUVM_DMA_FLAG		0x2
#define	ZULUVM_DMA_MASK		0x3

#define	ZULUVM_DMA1	0
#define	ZULUVM_DMA2	ZULUVM_DMA_FLAG
#define	ZULUVM_ITLB1	ZULUVM_ITLB_FLAG
#define	ZULUVM_ITLB2	(ZULUVM_ITLB_FLAG | ZULUVM_DMA_FLAG)
#define	ZULUVM_INVAL	0x4

#ifndef _ASM

/* zuluvm interface */

#define	ZULUVM_INTERFACE_VERSION	1 /* inc with every intf change */

typedef void * zuluvm_info_t;
int zuluvm_init(zulud_ops_t *ops, int **pagesizes);
int zuluvm_fini(void);
int zuluvm_alloc_device(dev_info_t *devi, void *arg, zuluvm_info_t *devp,
    caddr_t mmu, caddr_t imr);
int zuluvm_free_device(zuluvm_info_t devp);
int zuluvm_dma_add_proc(zuluvm_info_t devp, uint64_t *cookie);
int zuluvm_dma_delete_proc(zuluvm_info_t devp, uint64_t cookie);
int zuluvm_dma_alloc_ctx(zuluvm_info_t devp, int dma, short *ctx,
    uint64_t *tsb);
int zuluvm_dma_preload(zuluvm_info_t devp, int dma, int num,
    zulud_preload_t *list);
int zuluvm_dma_free_ctx(zuluvm_info_t devp, int dma);
int zuluvm_add_intr(zuluvm_info_t devp, int ino, uint_t (*handler)(caddr_t),
    caddr_t arg);
int zuluvm_rem_intr(zuluvm_info_t devp, int ino);
int zuluvm_enable_intr(zuluvm_info_t devp, int num);
int zuluvm_disable_intr(zuluvm_info_t devp, int num);
int zuluvm_park(zuluvm_info_t devp);

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* __ZULUVM_INCL__ */
