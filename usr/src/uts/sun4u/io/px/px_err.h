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

#ifndef	_SYS_PX_ERR_H
#define	_SYS_PX_ERR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum {
	PX_ERR_JBC,
	PX_ERR_MMU,
	PX_ERR_IMU,
	PX_ERR_TLU_UE,
	PX_ERR_TLU_CE,
	PX_ERR_TLU_OE,
	PX_ERR_ILU,
	PX_ERR_LPU_LINK,
	PX_ERR_LPU_PHY,
	PX_ERR_LPU_RX,
	PX_ERR_LPU_TX,
	PX_ERR_LPU_LTSSM,
	PX_ERR_LPU_GIGABLZ
} px_err_id_t;

void px_err_reg_enable(px_t *px_p, px_err_id_t id);
void px_err_reg_disable(px_t *px_p, px_err_id_t id);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_ERR_H */
