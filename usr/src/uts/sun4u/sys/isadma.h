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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_ISADMA_H
#define	_SYS_ISADMA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * definition of ebus reg spec entry:
 */
typedef struct {
	uint32_t ebus_addr_hi;
	uint32_t ebus_addr_low;
	uint32_t ebus_size;
} ebus_regspec_t;

/*
 * driver soft state structure:
 */
typedef struct {
	dev_info_t *isadma_dip;			/* Our dip */
	ebus_regspec_t *isadma_regp;		/* Our cached registers */
	int32_t isadma_reglen;			/* reg len */
	kmutex_t isadma_access_lock;		/* PIO/DMA lock */
	kcondvar_t isadma_access_cv;		/* cv to prevent PIO's */
	dev_info_t *isadma_ldip;		/* DMA lock dip */
	int isadma_want;			/* Want state flag */
} isadma_devstate_t;

/*
 * Lower bound and upper bound of DMA address space hole. Registers
 * in this hole belong to our childs  devices.
 */
#define	LO_BOUND	DMAC2_ALLMASK
#define	HI_BOUND	DMA_0XCNT
#define	IN_CHILD_SPACE(o)	((o) > LO_BOUND && (o) < HI_BOUND)
#define	IN_16BIT_SPACE(o)	((((o) >= DMA_0ADR) && (o) <= DMA_3WCNT) || \
	(((o) >= DMA_4ADR) && ((o) <= DMA_7WCNT)))
#define	IS_SEQREG(o)		(((o) == DMAC1_CLFF) || ((o) == DMAC2_CLFF))
#define	HDL_TO_SEQREG_ADDR(h, o) \
	((((o) >= DMA_0ADR) && ((o) <= DMA_3WCNT)) ? \
	(h)->ahi_common.ah_addr + DMAC1_CLFF : \
	(h)->ahi_common.ah_addr + DMAC2_CLFF)

#define	BEGIN_ISADMA(o, v)	((o) == DMAC1_ALLMASK && (v))
#define	END_ISADMA(o, v)	((o) == DMAC1_ALLMASK && (v) == 0)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ISADMA_H */
