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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Hypervisor calls called by ncp driver.
 */

#include <sys/asm_linkage.h>
#include <sys/hypervisor_api.h>
#include <sys/n2rng.h>

#if defined(lint) || defined(__lint)

/*ARGSUSED*/
uint64_t
hv_rng_get_diag_control()
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_rng_ctl_read(uint64_t ctlregsptr_ra, uint64_t *rstate, uint64_t *tdelta)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_rng_ctl_write(uint64_t ctlregsptr_ra, uint64_t nstate, uint64_t wtimeout,
		uint64_t *tdelta)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_rng_data_read_diag(uint64_t buffer_ra, uint64_t sz, uint64_t *tdelta)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_rng_data_read(uint64_t buffer_ra, uint64_t *tdelta)
{ return (0); }

#else	/* lint || __lint */

	/*
	 * hv_rng_get_diag_control()
	 */
	ENTRY(hv_rng_get_diag_control)
	mov	HV_RNG_GET_DIAG_CONTROL, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_rng_get_diag_control)

	/*
	 * hv_rng_ctl_read(uint64_t ctlregsptr_ra, uint64_t *rstate,
	 *		uint64_t *tdelta)
	 */
	ENTRY(hv_rng_ctl_read)
	mov	%o1, %o3
	mov	%o2, %o4
	mov	HV_RNG_CTL_READ, %o5
	ta	FAST_TRAP
	stx	%o1, [%o3]
	retl
	stx	%o2, [%o4]
	SET_SIZE(hv_rng_ctl_read)

	/*
	 * hv_rng_ctl_write(uint64_t ctlregsptr_ra, uint64_t nstate,
	 *		uint64_t wtimeout, uint64_t *tdelta)
	 */
	ENTRY(hv_rng_ctl_write)
	mov	%o3, %o4
	mov	HV_RNG_CTL_WRITE, %o5
	ta	FAST_TRAP
	retl
	stx	%o1, [%o4]
	SET_SIZE(hv_rng_ctl_write)

	/*
	 * hv_rng_data_read_diag(uint64_t buffer_ra, uint64_t sz,
	 *			uint64_t *tdelta)
	 */
	ENTRY(hv_rng_data_read_diag)
	mov	%o2, %o4
	mov	HV_RNG_DATA_READ_DIAG, %o5
	ta	FAST_TRAP
	retl
	stx	%o1, [%o4]
	SET_SIZE(hv_rng_data_read_diag)

	/*
	 * hv_rng_data_read(uint64_t buffer_ra, uint64_t *tdelta)
	 */
	ENTRY(hv_rng_data_read)
	mov	%o1, %o4
	mov	HV_RNG_DATA_READ, %o5
	ta	FAST_TRAP
	retl
	stx	%o1, [%o4]
	SET_SIZE(hv_rng_data_read)

#endif	/* lint || __lint */
