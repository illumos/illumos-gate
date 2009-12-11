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

/*
 * Hypervisor calls called by niu leaf driver.
 */

#include <sys/asm_linkage.h>
#include <sys/hypervisor_api.h>
#include <sys/nxge/nxge_impl.h>

#if defined(sun4v)

/*
 * NIU HV API v1.0 definitions
 */
#define	N2NIU_RX_LP_SET		0x142
#define	N2NIU_RX_LP_GET		0x143
#define	N2NIU_TX_LP_SET		0x144
#define	N2NIU_TX_LP_GET		0x145

/*
 * NIU HV API v1.1 definitions
 */
#define	N2NIU_VR_ASSIGN		0x146
#define	N2NIU_VR_UNASSIGN	0x147
#define	N2NIU_VR_GETINFO	0x148

#define	N2NIU_VR_RX_DMA_ASSIGN		0x149
#define	N2NIU_VR_RX_DMA_UNASSIGN	0x14a
#define	N2NIU_VR_TX_DMA_ASSIGN		0x14b
#define	N2NIU_VR_TX_DMA_UNASSIGN	0x14c

#define	N2NIU_VR_GET_RX_MAP	0x14d
#define	N2NIU_VR_GET_TX_MAP	0x14e

#define	N2NIU_VRRX_SET_INO	0x150
#define	N2NIU_VRTX_SET_INO	0x151

#define	N2NIU_VRRX_GET_INFO	0x152
#define	N2NIU_VRTX_GET_INFO	0x153

#define	N2NIU_VRRX_LP_SET	0x154
#define	N2NIU_VRRX_LP_GET	0x155
#define	N2NIU_VRTX_LP_SET	0x156
#define	N2NIU_VRTX_LP_GET	0x157

#define	N2NIU_VRRX_PARAM_GET	0x158
#define	N2NIU_VRRX_PARAM_SET	0x159

#define	N2NIU_VRTX_PARAM_GET	0x15a
#define	N2NIU_VRTX_PARAM_SET	0x15b

/*
 * The new set of HV APIs to provide the ability
 * of a domain to manage multiple NIU resources at once to
 * support the KT familty chip having up to 4 NIUs
 * per system. The trap # will be the same as those defined
 * before 2.0
 */
#define	N2NIU_CFGH_RX_LP_SET	0x142
#define	N2NIU_CFGH_TX_LP_SET	0x143
#define	N2NIU_CFGH_RX_LP_GET	0x144
#define	N2NIU_CFGH_TX_LP_GET	0x145
#define	N2NIU_CFGH_VR_ASSIGN	0x146

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

/*ARGSUSED*/
uint64_t
hv_niu_vr_assign(uint64_t vridx, uint64_t ldc_id, uint32_t *cookie)
{ return (0); }

/*
 * KT: Interfaces functions which require the configuration handle
 */
/*ARGSUSED*/
uint64_t
hv_niu_cfgh_rx_logical_page_conf(uint64_t cfgh, uint64_t chidx, uint64_t pgidx,
	uint64_t raddr, uint64_t size)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_cfgh_rx_logical_page_info(uint64_t cfgh, uint64_t chidx, uint64_t pgidx,
	uint64_t *raddr, uint64_t *size)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_cfgh_tx_logical_page_conf(uint64_t cfgh, uint64_t chidx, uint64_t pgidx,
	uint64_t raddr, uint64_t size)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_cfgh_tx_logical_page_info(uint64_t cfgh, uint64_t chidx, uint64_t pgidx,
	uint64_t *raddr, uint64_t *size)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_cfgh_vr_assign(uint64_t cfgh, uint64_t vridx, uint64_t ldc_id, uint32_t *cookie)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_vr_unassign(uint32_t cookie)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_vr_getinfo(uint32_t cookie, uint64_t *real_start, uint64_t *size)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_vr_get_rxmap(uint32_t cookie, uint64_t *dma_map)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_vr_get_txmap(uint32_t cookie, uint64_t *dma_map)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_rx_dma_assign(uint32_t cookie, uint64_t chidx, uint64_t *vchidx)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_rx_dma_unassign(uint32_t cookie, uint64_t vchidx)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_tx_dma_assign(uint32_t cookie, uint64_t chidx, uint64_t *vchidx)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_tx_dma_unassign(uint32_t cookie, uint64_t chidx)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_vrrx_logical_page_conf(uint32_t cookie, uint64_t chidx, uint64_t pgidx,
    uint64_t raddr, uint64_t size)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_vrrx_logical_page_info(uint32_t cookie, uint64_t chidx, uint64_t pgidx,
    uint64_t *raddr, uint64_t *size)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_vrtx_logical_page_conf(uint32_t cookie, uint64_t chidx, uint64_t pgidx,
    uint64_t raddr, uint64_t size)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_vrtx_logical_page_info(uint32_t cookie, uint64_t chidx, uint64_t pgidx,
    uint64_t *raddr, uint64_t *size)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_vrrx_param_get(uint32_t cookie, uint64_t vridx, uint64_t param,
	uint64_t *value)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_vrrx_param_set(uint32_t cookie, uint64_t vridx, uint64_t param,
	uint64_t value)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_vrtx_param_get(uint32_t cookie, uint64_t vridx, uint64_t param,
	uint64_t *value)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_vrtx_param_set(uint32_t cookie, uint64_t vridx, uint64_t param,
	uint64_t value)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_vrtx_getinfo(uint32_t cookie, uint64_t vridx,
	uint64_t *group, uint64_t *logdev)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_vrrx_getinfo(uint32_t cookie, uint64_t vridx,
		uint64_t *group, uint64_t *logdev)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_vrtx_set_ino(uint32_t cookie, uint64_t vridx, uint32_t ino)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_niu_vrrx_set_ino(uint32_t cookie, uint64_t vridx, uint32_t ino)
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

	/*
	 * hv_niu_vr_assign(uint64_t vridx, uint64_t ldc_id,
	 *	uint32_t *cookie)
	 */
	ENTRY(hv_niu_vr_assign)
	mov	%o2, %g1
	mov	N2NIU_VR_ASSIGN, %o5
	ta	FAST_TRAP
	retl
	stw	%o1, [%g1]
	SET_SIZE(hv_niu_vr_assign)

	/*
	 * hv_niu_vr_unassign(uint32_t cookie)
	 */
	ENTRY(hv_niu_vr_unassign)
	mov	N2NIU_VR_UNASSIGN, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_niu_vr_unassign)

	/*
	 * hv_niu_vr_getinfo(uint32_t cookie, uint64_t &real_start,
	 *	uint64_t &size)
	 */
	ENTRY(hv_niu_vr_getinfo)
	mov	%o1, %g1
	mov	%o2, %g2
	mov	N2NIU_VR_GETINFO, %o5
	ta	FAST_TRAP
	stx	%o1, [%g1]
	retl
	stx	%o2, [%g2]
	SET_SIZE(hv_niu_vr_getinfo)

	/*
	 * hv_niu_vr_get_rxmap(uint32_t cookie, uint64_t *dma_map)
	 */
	ENTRY(hv_niu_vr_get_rxmap)
	mov	%o1, %g1
	mov	N2NIU_VR_GET_RX_MAP, %o5
	ta	FAST_TRAP
	retl
	stx	%o1, [%g1]
	SET_SIZE(hv_niu_vr_get_rxmap)

	/*
	 * hv_niu_vr_get_txmap(uint32_t cookie, uint64_t *dma_map)
	 */
	ENTRY(hv_niu_vr_get_txmap)
	mov	%o1, %g1
	mov	N2NIU_VR_GET_TX_MAP, %o5
	ta	FAST_TRAP
	retl
	stx	%o1, [%g1]
	SET_SIZE(hv_niu_vr_get_txmap)

	/*
	 * hv_niu_rx_dma_assign(uint32_t cookie, uint64_t chidx,
	 *	uint64_t *vchidx)
	 */
	ENTRY(hv_niu_rx_dma_assign)
	mov	%o2, %g1
	mov	N2NIU_VR_RX_DMA_ASSIGN, %o5
	ta	FAST_TRAP
	retl
	stx	%o1, [%g1]
	SET_SIZE(hv_niu_rx_dma_assign)

	/*
	 * hv_niu_rx_dma_unassign(uint32_t cookie, uint64_t vchidx)
	 */
	ENTRY(hv_niu_rx_dma_unassign)
	mov	N2NIU_VR_RX_DMA_UNASSIGN, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_niu_rx_dma_unassign)

	/*
	 * hv_niu_tx_dma_assign(uint32_t cookie, uint64_t chidx,
	 *	uint64_t *vchidx)
	 */
	ENTRY(hv_niu_tx_dma_assign)
	mov	%o2, %g1
	mov	N2NIU_VR_TX_DMA_ASSIGN, %o5
	ta	FAST_TRAP
	retl
	stx	%o1, [%g1]
	SET_SIZE(hv_niu_tx_dma_assign)

	/*
	 * hv_niu_tx_dma_unassign(uint32_t cookie, uint64_t vchidx)
	 */
	ENTRY(hv_niu_tx_dma_unassign)
	mov	N2NIU_VR_TX_DMA_UNASSIGN, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_niu_tx_dma_unassign)

	/*
	 * hv_niu_vrrx_logical_page_conf(uint32_t cookie, uint64_t chidx,
	 *	uint64_t pgidx, uint64_t raddr, uint64_t size)
	 */
	ENTRY(hv_niu_vrrx_logical_page_conf)
	mov	N2NIU_VRRX_LP_SET, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_niu_vrrx_logical_page_conf)

	/*
	 * hv_niu_vrrx_logical_page_info(uint32_t cookie, uint64_t chidx,
	 *	uint64_t pgidx, uint64_t *raddr, uint64_t *size)
	 */
	ENTRY(hv_niu_vrrx_logical_page_info)
	mov	%o3, %g1
	mov	%o4, %g2
	mov	N2NIU_VRRX_LP_GET, %o5
	ta	FAST_TRAP
	stx	%o1, [%g1]
	retl
	stx	%o2, [%g2]
	SET_SIZE(hv_niu_vrrx_logical_page_info)

	/*
	 * hv_niu_vrtx_logical_page_conf(uint32_t cookie, uint64_t chidx,
	 *	uint64_t pgidx, uint64_t raddr, uint64_t size)
	 */
	ENTRY(hv_niu_vrtx_logical_page_conf)
	mov	N2NIU_VRTX_LP_SET, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_niu_vrtx_logical_page_conf)

	/*
	 * hv_niu_vrtx_logical_page_info(uint32_t cookie, uint64_t chidx,
	 *	uint64_t pgidx, uint64_t *raddr, uint64_t *size)
	 */
	ENTRY(hv_niu_vrtx_logical_page_info)
	mov	%o3, %g1
	mov	%o4, %g2
	mov	N2NIU_VRTX_LP_GET, %o5
	ta	FAST_TRAP
	stx	%o1, [%g1]
	retl
	stx	%o2, [%g2]
	SET_SIZE(hv_niu_vrtx_logical_page_info)

	/*
	 * hv_niu_vrrx_getinfo(uint32_t cookie, uint64_t vridx,
	 *	uint64_t *group, uint64_t *logdev)
	 */
	ENTRY(hv_niu_vrrx_getinfo)
	mov	%o2, %g1
	mov	%o3, %g2
	mov	N2NIU_VRRX_GET_INFO, %o5
	ta	FAST_TRAP
	stx	%o2, [%g2]
	retl
	stx	%o1, [%g1]
	SET_SIZE(hv_niu_vrrx_getinfo)

	/*
	 * hv_niu_vrtx_getinfo(uint32_t cookie, uint64_t vridx,
	 *	uint64_t *group, uint64_t *logdev)
	 */
	ENTRY(hv_niu_vrtx_getinfo)
	mov	%o2, %g1
	mov	%o3, %g2
	mov	N2NIU_VRTX_GET_INFO, %o5
	ta	FAST_TRAP
	stx	%o2, [%g2]
	retl
	stx	%o1, [%g1]
	SET_SIZE(hv_niu_vrtx_getinfo)

	/*
	 * hv_niu_vrrx_set_ino(uint32_t cookie, uint64_t vridx, uint32_t ino)
	 */
	ENTRY(hv_niu_vrrx_set_ino)
	mov	N2NIU_VRRX_SET_INO, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_niu_vrrx_set_ino)

	/*
	 * hv_niu_vrtx_set_ino(uint32_t cookie, uint64_t vridx, uint32_t ino)
	 */
	ENTRY(hv_niu_vrtx_set_ino)
	mov	N2NIU_VRTX_SET_INO, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_niu_vrtx_set_ino)

	/*
	 * hv_niu_vrrx_param_get(uint32_t cookie, uint64_t vridx,
	 *	uint64_t param, uint64_t *value)
	 *
	 */
	ENTRY(hv_niu_vrrx_param_get)
	mov	%o3, %g1
	mov	N2NIU_VRRX_PARAM_GET, %o5
	ta	FAST_TRAP
	retl
	stx	%o1, [%g1]
	SET_SIZE(hv_niu_vrrx_param_get)

	/*
	 * hv_niu_vrrx_param_set(uint32_t cookie, uint64_t vridx,
	 *	uint64_t param, uint64_t value)
	 *
	 */
	ENTRY(hv_niu_vrrx_param_set)
	mov	N2NIU_VRRX_PARAM_SET, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_niu_vrrx_param_set)

	/*
	 * hv_niu_vrtx_param_get(uint32_t cookie, uint64_t vridx,
	 *	uint64_t param, uint64_t *value)
	 *
	 */
	ENTRY(hv_niu_vrtx_param_get)
	mov	%o3, %g1
	mov	N2NIU_VRTX_PARAM_GET, %o5
	ta	FAST_TRAP
	retl
	stx	%o1, [%g1]
	SET_SIZE(hv_niu_vrtx_param_get)

	/*
	 * hv_niu_vrtx_param_set(uint32_t cookie, uint64_t vridx,
	 *	uint64_t param, uint64_t value)
	 *
	 */
	ENTRY(hv_niu_vrtx_param_set)
	mov	N2NIU_VRTX_PARAM_SET, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_niu_vrtx_param_set)

	/*
	 * Interfaces functions which require the configuration handle.
	 */
	/*
	 * hv_niu__cfgh_rx_logical_page_conf(uint64_t cfgh, uint64_t chidx,
	 *    uint64_t pgidx, uint64_t raddr, uint64_t size)
	 */
	ENTRY(hv_niu_cfgh_rx_logical_page_conf)
	mov	N2NIU_RX_LP_CONF, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_niu_cfgh_rx_logical_page_conf)

	/*
	 * hv_niu__cfgh_rx_logical_page_info(uint64_t cfgh, uint64_t chidx,
	 *    uint64_t pgidx, uint64_t *raddr, uint64_t *size)
	 */
	ENTRY(hv_niu_cfgh_rx_logical_page_info)
	mov	%o3, %g1
	mov	%o4, %g2
	mov	N2NIU_RX_LP_INFO, %o5
	ta	FAST_TRAP
	stx	%o1, [%g1]
	retl
	stx	%o2, [%g2]
	SET_SIZE(hv_niu_cfgh_rx_logical_page_info)

	/*
	 * hv_niu_cfgh_tx_logical_page_conf(uint64_t cfgh, uint64_t chidx,
	 *    uint64_t pgidx, uint64_t raddr, uint64_t size)
	 */
	ENTRY(hv_niu_cfgh_tx_logical_page_conf)
	mov	N2NIU_TX_LP_CONF, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_niu_cfgh_tx_logical_page_conf)

	/*
	 * hv_niu_cfgh_tx_logical_page_info(uint64_t cfgh, uint64_t chidx,
	 *    uint64_t pgidx, uint64_t *raddr, uint64_t *size)
	 */
	ENTRY(hv_niu_cfgh_tx_logical_page_info)
	mov	%o3, %g1
	mov	%o4, %g2
	mov	N2NIU_TX_LP_INFO, %o5
	ta	FAST_TRAP
	stx	%o1, [%g1]
	retl
	stx	%o2, [%g2]
	SET_SIZE(hv_niu_cfgh_tx_logical_page_info)

	/*
	 * hv_niu_cfgh_vr_assign(uint64_t cfgh, uint64_t vridx, uint64_t ldc_id,
	 *     uint32_t *cookie)
	 */
	ENTRY(hv_niu_cfgh_vr_assign)
	mov	%o3, %g1
	mov	N2NIU_VR_ASSIGN, %o5
	ta	FAST_TRAP
	retl
	stw	%o1, [%g1]
	SET_SIZE(hv_niu_cfgh_vr_assign)

#endif	/* lint || __lint */

#endif /*defined(sun4v)*/
