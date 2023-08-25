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
 * Hypervisor calls called by glvc driver.
*/

#include <sys/asm_linkage.h>
#include <sys/hypervisor_api.h>
#include <sys/glvc.h>

	/*
	 * hv_service_recv(uint64_t s_id, uint64_t buf_pa,
	 *     uint64_t size, uint64_t *recv_bytes);
	 */
	ENTRY(hv_service_recv)
	save	%sp, -SA(MINFRAME), %sp
	mov	%i0, %o0
	mov	%i1, %o1
	mov	%i2, %o2
	mov	%i3, %o3
	mov	SVC_RECV, %o5
	ta	FAST_TRAP
	brnz	%o0, 1f
	mov	%o0, %i0
	stx	%o1, [%i3]
1:
	ret
	restore
	SET_SIZE(hv_service_recv)

	/*
	 * hv_service_send(uint64_t s_id, uint64_t buf_pa,
	 *     uint64_t size, uint64_t *recv_bytes);
	 */
	ENTRY(hv_service_send)
	save	%sp, -SA(MINFRAME), %sp
	mov	%i0, %o0
	mov	%i1, %o1
	mov	%i2, %o2
	mov	%i3, %o3
	mov	SVC_SEND, %o5
	ta	FAST_TRAP
	brnz	%o0, 1f
	mov	%o0, %i0
	stx	%o1, [%i3]
1:
	ret
	restore
	SET_SIZE(hv_service_send)

	/*
	 * hv_service_getstatus(uint64_t s_id, uint64_t *vreg);
	 */
	ENTRY(hv_service_getstatus)
	mov	%o1, %o4			! save datap
	mov	SVC_GETSTATUS, %o5
	ta	FAST_TRAP
	brz,a	%o0, 1f
	stx	%o1, [%o4]
1:
	retl
	nop
	SET_SIZE(hv_service_getstatus)

	/*
	 * hv_service_setstatus(uint64_t s_id, uint64_t bits);
	 */
	ENTRY(hv_service_setstatus)
	mov	SVC_SETSTATUS, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_service_setstatus)

	/*
	 * hv_service_clrstatus(uint64_t s_id, uint64_t bits);
	 */
	ENTRY(hv_service_clrstatus)
	mov	SVC_CLRSTATUS, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_service_clrstatus)

