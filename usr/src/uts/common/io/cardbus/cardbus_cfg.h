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

#ifndef	_SYS_CARDBUS_CFG_H
#define	_SYS_CARDBUS_CFG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Cardbus device identifiers
 */
#define	CBUS_ID(vend, dev)	((uint32_t)(((uint32_t)(vend) << 16) | (dev)))

#define	CB_PPD_CODE	0x2441

struct cardbus_parent_private_data {
	struct ddi_parent_private_data	ppd;	/* this format for prtconf */
	uint16_t	code;	/* == CB_PPD_CODE */
	/* pci_regspec_t *regs; */
};

extern kmutex_t cardbus_list_mutex;
extern int cardbus_latency_timer;

extern int cardbus_configure(cbus_t *cbp);
extern int cardbus_unconfigure(cbus_t *cbp);
extern int cardbus_teardown_device(dev_info_t *);
extern int cardbus_primary_busno(dev_info_t *dip);

#ifdef DEBUG
extern void cardbus_dump_children(dev_info_t *dip, int level);
extern void cardbus_dump_family_tree(dev_info_t *dip);
#endif

#ifdef  __cplusplus
}
#endif

#endif	/* _SYS_CARDBUS_CFG_H */
