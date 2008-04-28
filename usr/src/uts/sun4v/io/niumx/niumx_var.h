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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_NIUMX_VAR_H
#define	_SYS_NIUMX_VAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum {	/* same sequence as niumx_debug_sym[] */
	/*  0 */ DBG_ATTACH,
	/*  1 */ DBG_MAP,
	/*  2 */ DBG_CTLOPS,
	/*  3 */ DBG_INTROPS,
	/*  4 */ DBG_A_INTX,
	/*  5 */ DBG_R_INTX,
	/*  6 */ DBG_INTR,
	/*  7 */ DBG_DMA_ALLOCH,
	/*  8 */ DBG_DMA_BINDH,
	/*  9 */ DBG_DMA_UNBINDH,
	/* 10 */ DBG_CHK_MOD
} niumx_debug_bit_t;

#if defined(DEBUG)
#define	DBG niumx_dbg
extern void niumx_dbg(niumx_debug_bit_t bit, dev_info_t *dip, char *fmt, ...);
#else
#define	DBG 0 &&
#endif	/* DEBUG */

typedef uint64_t devhandle_t;
#define	NIUMX_DEVHDLE_MASK	0xFFFFFFF
typedef uint32_t cpuid_t;
typedef uint32_t devino_t;
typedef	uint64_t sysino_t;

/*
 * The following structure represents an interrupt handler control block for
 * each interrupt added via ddi_intr_add_handler().
 */
typedef struct niumx_ih {
	dev_info_t	*ih_dip;	/* devinfo structure */
	uint32_t	ih_inum;	/* interrupt index, from leaf */
	sysino_t	ih_sysino;	/* System virtual inumber, from HV */
	cpuid_t		ih_cpuid;	/* cpu that ino is targeting */
	uint_t		(*ih_hdlr)();	/* interrupt handler */
	caddr_t		ih_arg1;	/* interrupt handler argument #1 */
	caddr_t		ih_arg2;	/* interrupt handler argument #2 */
	struct niumx_ih	*ih_next;	/* next in the chain */
} niumx_ih_t;

typedef struct niumx_devstate {
	dev_info_t *dip;
	devhandle_t	niumx_dev_hdl;	/* device handle */
	kmutex_t niumx_mutex;
	int niumx_fm_cap;
	ddi_iblock_cookie_t niumx_fm_ibc;
} niumx_devstate_t;

#define	NIUMX_MAX_INTRS	64
#define	NIUMX_RSVD_INTRS	16

/*
 * flags for overloading dmai_inuse field of the dma request structure:
 */
#define	dmai_pfnlst		dmai_iopte
#define	dmai_pfn0		dmai_sbi
#define	dmai_roffset		dmai_pool

#define	NIUMX_PAGE_SHIFT		13
#define	NIUMX_PAGE_SIZE		(1 << NIUMX_PAGE_SHIFT)
#define	NIUMX_PAGE_MASK		~(NIUMX_PAGE_SIZE - 1)
#define	NIUMX_PAGE_OFFSET		(NIUMX_PAGE_SIZE - 1)
#define	NIUMX_PTOB(x)		(((uint64_t)(x)) << NIUMX_PAGE_SHIFT)

/* for "ranges" property */
typedef struct niumx_ranges {
	uint32_t child_hi;
	uint32_t child_lo;
	uint32_t parent_hi;
	uint32_t parent_lo;
	uint32_t size_hi;
	uint32_t size_lo;
} niumx_ranges_t;

/* IPL of 6 for networking devices */
#define	NIUMX_DEFAULT_PIL	6

typedef struct {
	uint32_t addr_high;
	uint32_t addr_low;
	uint32_t size_high;
	uint32_t size_low;
} niu_regspec_t;

/*
 * HV INTR  API versioning.
 *
 * Currently NIU nexus driver supports version 1.0
 */
#define	NIUMX_INTR_MAJOR_VER_1	0x1ull
#define	NIUMX_INTR_MAJOR_VER	NIUMX_INTR_MAJOR_VER_1

#define	NIUMX_INTR_MINOR_VER_0	0x0ull
#define	NIUMX_INTR_MINOR_VER	NIUMX_INTR_MINOR_VER_0

#define	NAMEINST(dip)   ddi_driver_name(dip), ddi_get_instance(dip)
#define	DIP_TO_HANDLE(dip) \
		((niumx_devstate_t *)DIP_TO_STATE(dip))->niumx_dev_hdl
#define	DIP_TO_INST(dip)	ddi_get_instance(dip)
#define	INST_TO_STATE(inst)	ddi_get_soft_state(niumx_state, inst)
#define	DIP_TO_STATE(dip)	INST_TO_STATE(DIP_TO_INST(dip))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NIUMX_VAR_H */
