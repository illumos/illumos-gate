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

#ifndef	_SYS_NXGE_NXGE_STR_CFG_H
#define	_SYS_NXGE_NXGE_STR_CFG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The following definition controls on a per stream basis
 * wether the stream will use the interrupt context to push
 * packets to the next layer, use a streams service routine
 * or will bypass streams completely using caller provided
 * vectors.
 * This M_CTL definition applies only to in kernel modules.
 */
#ifdef _KERNEL
typedef enum {
	use_intr,
	use_rsrv,
	use_str_bypass
} put_cfg;

typedef enum {
	use_start,
	use_start_serial
} start_cfg;

/*
 * The following data structure allows an independent driver/module
 * using the dpli driver to send and M_CTL message to the driver
 * which will alter the datapath mode of operation of the driver.
 */
typedef struct _str_cfg_t {
	uint_t	cmd;		/* M_CTL message magic */
	put_cfg cfg;		/* data path configuration. */
	int	(*canputp)();	/* Caller replacement for canputnext */
	void	(*putp)();	/* Caller replacement for putnext */
} str_cfg_t, *p_str_cfg_t;

#define	STR_CFG_M_CTL	0xCEDEC0DE /* M_CTL command for this feature. */

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_STR_CFG_H */
