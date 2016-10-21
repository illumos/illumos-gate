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

#pragma weak _sbrk = sbrk
#pragma weak _brk = brk

#include "lint.h"
#include <synch.h>
#include <errno.h>
#include <sys/isa_defs.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <inttypes.h>
#include <unistd.h>
#include "mtlib.h"
#include "libc.h"

void *_nd = NULL;
mutex_t __sbrk_lock = DEFAULTMUTEX;

extern intptr_t _brk_unlocked(void *);
void *_sbrk_unlocked(intptr_t);

/*
 * The break must always be at least 8-byte aligned
 */
#if (_MAX_ALIGNMENT < 8)
#define	ALIGNSZ		8
#else
#define	ALIGNSZ		_MAX_ALIGNMENT
#endif

#define	BRKALIGN(x)	(caddr_t)P2ROUNDUP((uintptr_t)(x), ALIGNSZ)

void *
sbrk(intptr_t addend)
{
	void *result;

	if (!primary_link_map) {
		errno = ENOTSUP;
		return ((void *)-1);
	}
	lmutex_lock(&__sbrk_lock);
	result = _sbrk_unlocked(addend);
	lmutex_unlock(&__sbrk_lock);

	return (result);
}

/*
 * _sbrk_unlocked() aligns the old break, adds the addend, aligns
 * the new break, and calls _brk_unlocked() to set the new break.
 * We must align the old break because _nd may begin life misaligned.
 * The addend can be either positive or negative, so there are two
 * overflow/underflow edge conditions to reject:
 *
 *   - the addend is negative and brk + addend < 0.
 *   - the addend is positive and brk + addend > ULONG_MAX
 */
void *
_sbrk_unlocked(intptr_t addend)
{
	char *old_brk;
	char *new_brk;

	if (_nd == NULL) {
		_nd = (void *)_brk_unlocked(0);
	}

	old_brk = BRKALIGN(_nd);
	new_brk = BRKALIGN(old_brk + addend);

	if ((addend > 0 && new_brk < old_brk) ||
	    (addend < 0 && new_brk > old_brk)) {
		errno = ENOMEM;
		return ((void *)-1);
	}
	if (_brk_unlocked(new_brk) != 0)
		return ((void *)-1);
	_nd = new_brk;
	return (old_brk);
}

/*
 * _sbrk_grow_aligned() aligns the old break to a low_align boundry,
 * adds min_size, aligns to a high_align boundry, and calls _brk_unlocked()
 * to set the new break.  The low_aligned-aligned value is returned, and
 * the actual space allocated is returned through actual_size.
 *
 * Unlike sbrk(2), _sbrk_grow_aligned takes an unsigned size, and does
 * not allow shrinking the heap.
 */
void *
_sbrk_grow_aligned(size_t min_size, size_t low_align, size_t high_align,
    size_t *actual_size)
{
	uintptr_t old_brk;
	uintptr_t ret_brk;
	uintptr_t high_brk;
	uintptr_t new_brk;
	intptr_t brk_result;

	if (!primary_link_map) {
		errno = ENOTSUP;
		return ((void *)-1);
	}
	if ((low_align & (low_align - 1)) != 0 ||
	    (high_align & (high_align - 1)) != 0) {
		errno = EINVAL;
		return ((void *)-1);
	}
	low_align = MAX(low_align, ALIGNSZ);
	high_align = MAX(high_align, ALIGNSZ);

	lmutex_lock(&__sbrk_lock);

	if (_nd == NULL)
		_nd = (void *)_brk_unlocked(0);

	old_brk = (uintptr_t)BRKALIGN(_nd);
	ret_brk = P2ROUNDUP(old_brk, low_align);
	high_brk = ret_brk + min_size;
	new_brk = P2ROUNDUP(high_brk, high_align);

	/*
	 * Check for overflow
	 */
	if (ret_brk < old_brk || high_brk < ret_brk || new_brk < high_brk) {
		lmutex_unlock(&__sbrk_lock);
		errno = ENOMEM;
		return ((void *)-1);
	}

	if ((brk_result = _brk_unlocked((void *)new_brk)) == 0)
		_nd = (void *)new_brk;
	lmutex_unlock(&__sbrk_lock);

	if (brk_result != 0)
		return ((void *)-1);

	if (actual_size != NULL)
		*actual_size = (new_brk - ret_brk);
	return ((void *)ret_brk);
}

int
brk(void *new_brk)
{
	intptr_t result;

	/*
	 * brk(2) will return the current brk if given an argument of 0, so we
	 * need to fail it here
	 */
	if (new_brk == 0) {
		errno = ENOMEM;
		return (-1);
	}

	if (!primary_link_map) {
		errno = ENOTSUP;
		return (-1);
	}
	/*
	 * Need to align this here;  _brk_unlocked won't do it for us.
	 */
	new_brk = BRKALIGN(new_brk);

	lmutex_lock(&__sbrk_lock);
	if ((result = _brk_unlocked(new_brk)) == 0)
		_nd = new_brk;
	lmutex_unlock(&__sbrk_lock);

	return (result);
}
