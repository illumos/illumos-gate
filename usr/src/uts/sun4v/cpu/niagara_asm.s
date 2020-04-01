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

#include "assym.h"

/*
 * Niagara processor specific assembly routines
 */

#include <sys/asm_linkage.h>
#include <sys/machasi.h>
#include <sys/machparam.h>
#include <sys/hypervisor_api.h>
#include <sys/niagararegs.h>
#include <sys/machasi.h>
#include <sys/niagaraasi.h>
#include <vm/hat_sfmmu.h>

	/*
	 * hv_niagara_getperf(uint64_t perfreg, uint64_t *datap)
	 */
	ENTRY(hv_niagara_getperf)
	mov	%o1, %o4			! save datap
	mov	HV_NIAGARA_GETPERF, %o5
	ta	FAST_TRAP
	brz,a	%o0, 1f
	stx	%o1, [%o4]
1:
	retl
	nop
	SET_SIZE(hv_niagara_getperf)

	/*
	 * hv_niagara_setperf(uint64_t perfreg, uint64_t data)
	 */
	ENTRY(hv_niagara_setperf)
	mov	HV_NIAGARA_SETPERF, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_niagara_setperf)

/*
 * Invalidate all of the entries within the TSB, by setting the inv bit
 * in the tte_tag field of each tsbe.
 *
 * We take advantage of the fact that the TSBs are page aligned and a
 * multiple of PAGESIZE to use ASI_BLK_INIT_xxx ASI.
 *
 * See TSB_LOCK_ENTRY and the miss handlers for how this works in practice
 * (in short, we set all bits in the upper word of the tag, and we give the
 * invalid bit precedence over other tag bits in both places).
 */
	ENTRY(cpu_inv_tsb)

	/*
	 * The following code assumes that the tsb_base (%o0) is 256 bytes
	 * aligned and the tsb_bytes count is multiple of 256 bytes.
	 */

	wr	%g0, ASI_BLK_INIT_ST_QUAD_LDD_P, %asi
	set	TSBTAG_INVALID, %o2
	sllx	%o2, 32, %o2		! INV bit in upper 32 bits of the tag
1:
	stxa	%o2, [%o0+0x0]%asi
	stxa	%o2, [%o0+0x40]%asi
	stxa	%o2, [%o0+0x80]%asi
	stxa	%o2, [%o0+0xc0]%asi

	stxa	%o2, [%o0+0x10]%asi
	stxa	%o2, [%o0+0x20]%asi
	stxa	%o2, [%o0+0x30]%asi

	stxa	%o2, [%o0+0x50]%asi
	stxa	%o2, [%o0+0x60]%asi
	stxa	%o2, [%o0+0x70]%asi

	stxa	%o2, [%o0+0x90]%asi
	stxa	%o2, [%o0+0xa0]%asi
	stxa	%o2, [%o0+0xb0]%asi

	stxa	%o2, [%o0+0xd0]%asi
	stxa	%o2, [%o0+0xe0]%asi
	stxa	%o2, [%o0+0xf0]%asi

	subcc	%o1, 0x100, %o1
	bgu,pt	%ncc, 1b
	add	%o0, 0x100, %o0

	membar	#Sync
	retl
	nop

	SET_SIZE(cpu_inv_tsb)

	/*
	 * hv_niagara_mmustat_conf(uint64_t buf, uint64_t *prev_buf)
	 */
	ENTRY(hv_niagara_mmustat_conf)
	mov	%o1, %o4			! save prev_buf
	mov	HV_NIAGARA_MMUSTAT_CONF, %o5
	ta	FAST_TRAP
	retl
	stx	%o1, [%o4]
	SET_SIZE(hv_niagara_mmustat_conf)

	/*
	 * hv_niagara_mmustat_info(uint64_t *buf)
	 */
	ENTRY(hv_niagara_mmustat_info)
	mov	%o0, %o4			! save buf
	mov	HV_NIAGARA_MMUSTAT_INFO, %o5
	ta	FAST_TRAP
	retl
	stx	%o1, [%o4]
	SET_SIZE(hv_niagara_mmustat_info)

