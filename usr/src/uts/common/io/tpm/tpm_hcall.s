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
 * Hypervisor calls used by tpm driver
 */

#include <sys/asm_linkage.h>

#if defined(sun4v)
#include <sys/hypervisor_api.h>

/*
 * hcall_tpm_get(uint64_t locality, uint64_t offset, uint64_t size,
 *     uint64_t *value)
 */
	ENTRY(hcall_tpm_get)
	mov	%o3, %g1
	mov	HV_TPM_GET, %o5
	ta	FAST_TRAP
	stx	%o1, [%g1]
	retl
	nop
	SET_SIZE(hcall_tpm_get)

/*
 * uint64_t
 * hcall_tpm_put(uint64_t locality, uint64_t offset, uint64_t size,
 *     uint64_t value)
 */
	ENTRY(hcall_tpm_put)
	mov	HV_TPM_PUT, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hcall_tpm_put)

#endif /* defined(sun4v) */
