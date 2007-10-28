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

#include <sys/types.h>
#include <sys/systm.h>
#include <vm/page.h>
#include <sys/errno.h>

/*
 * Return supported page sizes.
 */
int
getpagesizes(int legacy, size_t *buf, int nelem)
{
	int i, pagesizes = page_num_user_pagesizes(legacy);
	size_t *pgsza;

	if (nelem < 0) {
		return (set_errno(EINVAL));
	}
	if (nelem == 0 && buf != NULL) {
		return (set_errno(EINVAL));
	}
	if (nelem == 0 && buf == NULL) {
		return (pagesizes);
	}
	if (buf == NULL) {
		return (set_errno(EINVAL));
	}
	if (nelem > pagesizes) {
		nelem = pagesizes;
	}
	pgsza = kmem_alloc(sizeof (*pgsza) * nelem, KM_SLEEP);
	for (i = 0; i < nelem; i++) {
		pgsza[i] = page_get_user_pagesize(i);
	}
	if (copyout(pgsza, buf, nelem * sizeof (*pgsza)) != 0) {
		kmem_free(pgsza, sizeof (*pgsza) * nelem);
		return (set_errno(EFAULT));
	}
	kmem_free(pgsza, sizeof (*pgsza) * nelem);
	return (nelem);
}

#if defined(_SYSCALL32_IMPL)

/*
 * Some future platforms will support page sizes larger than
 * a 32-bit address space.
 */
int
getpagesizes32(int legacy, size32_t *buf, int nelem)
{
	int i, pagesizes = page_num_user_pagesizes(legacy);
	size32_t *pgsza32;
	size_t pgsz;
	int rc;

	if (nelem < 0) {
		return (set_errno(EINVAL));
	}
	if (nelem == 0 && buf != NULL) {
		return (set_errno(EINVAL));
	}

	pgsza32 = kmem_alloc(sizeof (*pgsza32) * pagesizes, KM_SLEEP);
	for (i = 0; i < pagesizes; i++) {
		pgsz = page_get_user_pagesize(i);
		pgsza32[i] = (size32_t)pgsz;
		if (pgsz > (size32_t)-1) {
			pagesizes = i - 1;
			break;
		}
	}
	ASSERT(pagesizes > 0);
	ASSERT(page_get_user_pagesize(pagesizes - 1) <= (size32_t)-1);
	if (nelem > pagesizes) {
		nelem = pagesizes;
	}
	if (nelem == 0 && buf == NULL) {
		rc = pagesizes;
		goto done;
	}
	if (buf == NULL) {
		rc = set_errno(EINVAL);
		goto done;
	}
	if (copyout(pgsza32, buf, nelem * sizeof (*pgsza32)) != 0) {
		rc = set_errno(EFAULT);
		goto done;
	}
	rc = nelem;
done:
	kmem_free(pgsza32, sizeof (*pgsza32) *
	    page_num_user_pagesizes(legacy));
	return (rc);
}
#endif
