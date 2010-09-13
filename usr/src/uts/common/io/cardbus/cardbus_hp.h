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
/*
 * Copyright (c)  * Copyright (c) 2001 Tadpole Technology plc
 * All rights reserved.
 */

#ifndef	_SYS_CARDBUS_HP_H
#define	_SYS_CARDBUS_HP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef  __cplusplus
extern "C" {
#endif

struct  cardbus_config_ctrl {
	int	op;	/* operation - PCICFG_OP_ONLINE/PCICFG_OP_OFFLINE */
	int	busno;
	int	rv;	/* return error code */
	uint_t	flags;
	dev_info_t	*dip;	/* first error occurred here */
};

extern void *cardbus_state;

extern int cardbus_init_hotplug(cbus_t *cbp);
extern int cardbus_unconfigure_node(dev_info_t *dip, int prim_bus,
		boolean_t top_bridge);
extern int cbus_configure(dev_info_t *dip, void *hdl);

#ifdef  __cplusplus
}
#endif

#endif	/* _SYS_CARDBUS_HP_H */
