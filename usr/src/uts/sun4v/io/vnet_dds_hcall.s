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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Hypervisor calls called by niu leaf driver.
*/

#include <sys/asm_linkage.h>
#include <sys/hypervisor_api.h>

/*
 * NIU HV API v1.1 definitions
 */
#define	N2NIU_VR_GETINFO	0x148
#define	N2NIU_VR_GET_RX_MAP	0x14d
#define	N2NIU_VR_GET_TX_MAP	0x14e
#define N2NIU_VRRX_SET_INO	0x150
#define N2NIU_VRTX_SET_INO	0x151


	/*
	 * vdds_hv_niu_vr_getinfo(uint32_t cookie, uint64_t &real_start,
	 *     uint64_t &size)
	 */
	ENTRY(vdds_hv_niu_vr_getinfo)
	mov	%o1, %g1
	mov	%o2, %g2
	mov	N2NIU_VR_GETINFO, %o5
	ta	FAST_TRAP
	stx	%o1, [%g1]
	retl
	stx	%o2, [%g2]
	SET_SIZE(vdds_hv_niu_vr_getinfo)

	/*
	 * vdds_hv_niu_vr_get_rxmap(uint32_t cookie, uint64_t *dma_map)
	 */
	ENTRY(vdds_hv_niu_vr_get_rxmap)
	mov	%o1, %g1
	mov	N2NIU_VR_GET_RX_MAP, %o5
	ta	FAST_TRAP
	retl
	stx	%o1, [%g1]
	SET_SIZE(vdds_hv_niu_vr_get_rxmap)

	/*
	 * vdds_hv_niu_vr_get_txmap(uint32_t cookie, uint64_t *dma_map)
	 */
	ENTRY(vdds_hv_niu_vr_get_txmap)
	mov	%o1, %g1
	mov	N2NIU_VR_GET_TX_MAP, %o5
	ta	FAST_TRAP
	retl
	stx	%o1, [%g1]
	SET_SIZE(vdds_hv_niu_vr_get_txmap)

	/*
	 * vdds_hv_niu_vrrx_set_ino(uint32_t cookie, uint64_t vch_idx, uint32_t ino)
	 */
	ENTRY(vdds_hv_niu_vrrx_set_ino)
	mov	N2NIU_VRRX_SET_INO, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(vdds_hv_niu_vrrx_set_ino)

	/*
	 * vdds_hv_niu_vrtx_set_ino(uint32_t cookie, uint64_t vch_idx, uint32_t ino)
	 */
	ENTRY(vdds_hv_niu_vrtx_set_ino)
	mov	N2NIU_VRTX_SET_INO, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(vdds_hv_niu_vrtx_set_ino)

