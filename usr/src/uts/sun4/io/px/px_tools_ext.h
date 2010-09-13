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

#ifndef	_SYS_PX_TOOLS_EXT_H
#define	_SYS_PX_TOOLS_EXT_H

#ifdef	__cplusplus
extern "C" {
#endif

/* Stuff exported by px_tools.c and px_tools_4[u/v].c */
int pxtool_dev_reg_ops(dev_info_t *dip, void *arg, int cmd, int mode);
int pxtool_bus_reg_ops(dev_info_t *dip, void *arg, int cmd, int mode);
int pxtool_intr(dev_info_t *dip, void *arg, int cmd, int mode);
int pxtool_init(dev_info_t *dip);
void pxtool_uninit(dev_info_t *dip);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_TOOLS_EXT_H */
