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

#ifndef	_SYS_PX_DEBUG_H
#define	_SYS_PX_DEBUG_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/varargs.h>	/* va_list */
#include <sys/promif.h>		/* prom_printf */

typedef enum {	/* same sequence as px_debug_sym[] */
	/*  0 */ DBG_ATTACH,
	/*  1 */ DBG_DETACH,
	/*  2 */ DBG_MAP,
	/*  3 */ DBG_CTLOPS,

	/*  4 */ DBG_INTROPS,
	/*  5 */ DBG_A_INTX,
	/*  6 */ DBG_R_INTX,
	/*  7 */ DBG_INTX_INTR,

	/*  8 */ DBG_MSIQ,
	/*  9 */ DBG_MSIQ_INTR,
	/* 10 */ DBG_MSG,
	/* 11 */ DBG_MSG_INTR,

	/* 12 */ DBG_A_MSIX,
	/* 13 */ DBG_R_MSIX,
	/* 14 */ DBG_MSIX_INTR,
	/* 15 */ DBG_ERR_INTR,

	/* 16 */ DBG_DMA_ALLOCH,
	/* 17 */ DBG_DMA_FREEH,
	/* 18 */ DBG_DMA_BINDH,
	/* 19 */ DBG_DMA_UNBINDH,

	/* 20 */ DBG_CHK_MOD,
	/* 21 */ DBG_BYPASS,
	/* 22 */ DBG_FAST_DVMA,
	/* 23 */ DBG_INIT_CLD,

	/* 24 */ DBG_DMA_MAP,
	/* 25 */ DBG_DMA_WIN,
	/* 26 */ DBG_MAP_WIN,
	/* 27 */ DBG_UNMAP_WIN,

	/* 28 */ DBG_DMA_CTL,
	/* 29 */ DBG_DMA_SYNC,
	/* 30 */ DBG_RSV1,
	/* 31 */ DBG_RSV2,

	/* 32 */ DBG_IB,
	/* 33 */ DBG_CB,
	/* 34 */ DBG_DMC,
	/* 35 */ DBG_PEC,

	/* 36 */ DBG_ILU,
	/* 37 */ DBG_TLU,
	/* 38 */ DBG_LPU,
	/* 39 */ DBG_MMU,

	/* 40 */ DBG_OPEN,
	/* 41 */ DBG_CLOSE,
	/* 42 */ DBG_IOCTL,
	/* 43 */ DBG_PWR,

	/* 44 */ DBG_LIB_CFG,
	/* 45 */ DBG_LIB_INT,
	/* 46 */ DBG_LIB_DMA,
	/* 47 */ DBG_LIB_MSIQ,

	/* 48 */ DBG_LIB_MSI,
	/* 49 */ DBG_LIB_MSG,
	/* 50 */ DBG_RSV4,
	/* 51 */ DBG_RSV5,

	/* 52 */ DBG_TOOLS,
	/* 53 */ DBG_PHYS_ACC,
	/* 54 */ DBG_HP,
	/* 55 */ DBG_MPS

} px_debug_bit_t;

#define	DBG_BITS	6
#define	DBG_CONT	(1 << DBG_BITS)
#define	DBG_MASK	(DBG_CONT - 1)
#define	DBG_MSG_SIZE	320

/* Used only during High PIL printing */
typedef struct px_dbg_msg {
	boolean_t	active;
	px_debug_bit_t  bit;
	dev_info_t	*dip;
	char		msg[DBG_MSG_SIZE];
} px_dbg_msg_t;

extern void px_dbg_attach(dev_info_t *dip, ddi_softint_handle_t *px_dbg_hdl);
extern void px_dbg_detach(dev_info_t *dip, ddi_softint_handle_t *px_dbg_hdl);

#if defined(DEBUG)

#define	DBG px_dbg
extern void px_dbg(px_debug_bit_t bit, dev_info_t *dip, char *fmt, ...);

#else	/* DEBUG */

#define	DBG 0 &&

#endif	/* DEBUG */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_DEBUG_H */
