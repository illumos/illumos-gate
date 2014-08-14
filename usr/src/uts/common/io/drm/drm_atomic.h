/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * \file drm_atomic.h
 * Atomic operations used in the DRM which may or may not be provided by the OS.
 *
 * \author Eric Anholt <anholt@FreeBSD.org>
 */

/*
 * Copyright 2004 Eric Anholt
 * Copyright (c) 2009, Intel Corporation.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * VA LINUX SYSTEMS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/* Many of these implementations are rather fake, but good enough. */



#ifndef	_SYS_DRM_ATOMIC_H_
#define	_SYS_DRM_ATOMIC_H_

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/atomic.h>

#ifdef __LINT__
#undef inline
#define	inline
#endif
typedef uint32_t	atomic_t;

#define	atomic_set(p, v)	(*(p) = (v))
#define	atomic_read(p)		(*(p))
#define	atomic_inc(p)		atomic_inc_uint(p)
#define	atomic_dec(p)		atomic_dec_uint(p)
#define	atomic_add(n, p)	atomic_add_int(p, n)
#define	atomic_sub(n, p)	atomic_add_int(p, -n)
#define	atomic_set_int(p, bits)	atomic_or_uint(p, bits)
#define	atomic_clear_int(p, bits)	atomic_and_uint(p, ~(bits))
#define	atomic_cmpset_int(p, c, n) \
	((c == atomic_cas_uint(p, c, n)) ? 1 : 0)

#define	set_bit(b, p) \
	atomic_set_int(((volatile uint_t *)(void *)p) + (b >> 5), \
	1 << (b & 0x1f))

#define	clear_bit(b, p) \
	atomic_clear_int(((volatile uint_t *)(void *)p) + (b >> 5), \
	1 << (b & 0x1f))

#define	test_bit(b, p) \
	(((volatile uint_t *)(void *)p)[b >> 5] & (1 << (b & 0x1f)))

/*
 * Note: this routine doesn't return old value. It return
 * 0 when succeeds, or -1 when fails.
 */
#ifdef _LP64
#define	test_and_set_bit(b, p) \
	atomic_set_long_excl(((ulong_t *)(void *)p) + (b >> 6), (b & 0x3f))
#else
#define	test_and_set_bit(b, p) \
	atomic_set_long_excl(((ulong_t *)(void *)p) + (b >> 5), (b & 0x1f))
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_DRM_ATOMIC_H_ */
