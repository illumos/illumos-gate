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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/systm.h>
#include <sys/param.h>
#include <sys/atomic.h>
#include <sys/kmem.h>
#include <sys/refstr.h>
#include <sys/refstr_impl.h>

refstr_t *
refstr_alloc(const char *str)
{
	refstr_t *rsp;
	size_t size = sizeof (rsp->rs_size) + sizeof (rsp->rs_refcnt) +
		strlen(str) + 1;

	ASSERT(size <= UINT32_MAX);
	rsp = kmem_alloc(size, KM_SLEEP);
	rsp->rs_size = (uint32_t)size;
	rsp->rs_refcnt = 1;
	(void) strcpy(rsp->rs_string, str);
	return (rsp);
}

const char *
refstr_value(refstr_t *rsp)
{
	return (rsp != NULL ? (const char *)rsp->rs_string : NULL);
}

void
refstr_hold(refstr_t *rsp)
{
	atomic_inc_32(&rsp->rs_refcnt);
}

void
refstr_rele(refstr_t *rsp)
{
	if (atomic_dec_32_nv(&rsp->rs_refcnt) == 0)
		kmem_free(rsp, (size_t)rsp->rs_size);
}
