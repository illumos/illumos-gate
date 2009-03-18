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
#ifndef	_FCOET_ETH_H
#define	_FCOET_ETH_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

void fcoet_rx_frame(fcoe_frame_t *frame);
void fcoet_port_event(fcoe_port_t *eport, uint32_t event);
void fcoet_release_sol_frame(fcoe_frame_t *frame);
int fcoet_clear_unsol_exchange(fcoet_exchange_t *xch);
void fcoet_clear_sol_exchange(fcoet_exchange_t *xch);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _FCOET_ETH_H */
