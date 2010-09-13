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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _MONTECARLO_SYS_HSC_H
#define	_MONTECARLO_SYS_HSC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * These functions serve as the interface between the SCSB and the HSC
 */
int	hsc_slot_occupancy(int, boolean_t, int, int);
int	hsc_board_healthy(int slot_number, boolean_t healthy);
int	hsc_init();
int	hsc_fini();
void	hsc_ac_op();
int	scsb_hsc_attach(dev_info_t *, void *, int);
int	scsb_hsc_detach(dev_info_t *, void *, int);
int	scsb_get_slot_state();
int	scsb_reset_slot();
int	scsb_connect_slot();
int	scsb_disconnect_slot();
int	scsb_hsc_ac_op();
int	scsb_hsc_freeze(dev_info_t *);
int	scsb_hsc_restore(dev_info_t *);
int	scsb_hsc_freeze_check(dev_info_t *);


#ifdef	__cplusplus
}
#endif

#endif	/* _MONTECARLO_SYS_HSC_H */
