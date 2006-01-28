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
 * Copyright (c) 1995,1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_JTAG_H
#define	_SYS_JTAG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

enum board_type jtag_get_board_type(volatile uint_t *, sysc_cfga_stat_t *);
int jtag_powerdown_board(volatile uint_t *, int, enum board_type,
	uint_t *, uint_t *, int);
int jtag_get_board_info(volatile uint_t *, struct sysc_cfga_stat *);
int jtag_init_disk_board(volatile uint_t *, int, uint_t *, uint_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_JTAG_H */
