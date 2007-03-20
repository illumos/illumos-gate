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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Hypervisor calls called by niu leaf driver.
*/

#include <sys/asm_linkage.h>
#include <sys/hypervisor_api.h>
#include <sys/nxge/nxge_impl.h>

#if defined(lint) || defined(__lint)

/*ARGSUSED*/
uint64_t
hv_niu_rx_logical_page_conf(uint64_t chidx, uint64_t pgidx,
	uint64_t raddr, uint64_t size)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_rx_logical_page_info(uint64_t chidx, uint64_t pgidx,
	uint64_t *raddr, uint64_t *size)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_tx_logical_page_conf(uint64_t chidx, uint64_t pgidx,
	uint64_t raddr, uint64_t size)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_tx_logical_page_info(uint64_t chidx, uint64_t pgidx,
	uint64_t *raddr, uint64_t *size)
{ return (0); }

#else	/* lint || __lint */

	/*
	 * hv_niu_rx_logical_page_conf(uint64_t chidx, uint64_t pgidx,
	 *	uint64_t raddr, uint64_t size)
	 */
	ENTRY(hv_niu_rx_logical_page_conf)
	mov	N2NIU_RX_LP_CONF, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_niu_rx_logical_page_conf)

	/*
	 * hv_niu_rx_logical_page_info(uint64_t chidx, uint64_t pgidx,
	 *	uint64_t *raddr, uint64_t *size)
	 */
	ENTRY(hv_niu_rx_logical_page_info)
	mov	%o2, %g1
	mov	%o3, %g2
	mov	N2NIU_RX_LP_INFO, %o5
	ta	FAST_TRAP
	stx	%o1, [%g1]
	retl
	stx	%o2, [%g2]
	SET_SIZE(hv_niu_rx_logical_page_info)

	/*
	 * hv_niu_tx_logical_page_conf(uint64_t chidx, uint64_t pgidx,
	 *	uint64_t raddr, uint64_t size)
	 */
	ENTRY(hv_niu_tx_logical_page_conf)
	mov	N2NIU_TX_LP_CONF, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_niu_tx_logical_page_conf)

	/*
	 * hv_niu_tx_logical_page_info(uint64_t chidx, uint64_t pgidx,
	 *	uint64_t *raddr, uint64_t *size)
	 */
	ENTRY(hv_niu_tx_logical_page_info)
	mov	%o2, %g1
	mov	%o3, %g2
	mov	N2NIU_TX_LP_INFO, %o5
	ta	FAST_TRAP
	stx	%o1, [%g1]
	retl
	stx	%o2, [%g2]
	SET_SIZE(hv_niu_tx_logical_page_info)

#endif	/* lint || __lint */
