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

#include <mdb/mdb_debug.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_io.h>

#define	UMEM_STANDALONE
#include <umem_impl.h>

/*
 * The standalone umem requires that kmdb provide some error-handling
 * services.  These are them.
 */

/*ARGSUSED*/
int
__umem_assert_failed(const char *assertion, const char *file, int line)
{
#ifdef DEBUG
	(void) mdb_dassert(assertion, file, line);
	/*NOTREACHED*/
#endif
	return (0);
}

void
umem_panic(const char *format, ...)
{
	va_list alist;

	va_start(alist, format);
	vfail(format, alist);
	va_end(alist);
}

void
umem_err_recoverable(const char *format, ...)
{
	va_list alist;

	va_start(alist, format);
	vwarn(format, alist);
	va_end(alist);
}

int
umem_vsnprintf(char *s, size_t n, const char *format, va_list ap)
{
	return (mdb_iob_vsnprintf(s, n, format, ap));
}

int
umem_snprintf(char *s, size_t n, const char *format, ...)
{
	va_list ap;
	int rc;

	va_start(ap, format);
	rc = umem_vsnprintf(s, n, format, ap);
	va_end(ap);

	return (rc);
}

/* These aren't atomic, but we're not MT, so it doesn't matter */
uint32_t
umem_atomic_add_32_nv(uint32_t *target, int32_t delta)
{
	return (*target = *target + delta);
}

void
umem_atomic_add_64(uint64_t *target, int64_t delta)
{
	*target = *target + delta;
}

uint64_t
umem_atomic_swap_64(volatile uint64_t *t, uint64_t v)
{
	uint64_t old = *t;
	*t = v;
	return (old);
}

/*
 * Standalone umem must be manually initialized
 */
void
mdb_umem_startup(caddr_t base, size_t len, size_t pgsize)
{
	umem_startup(base, len, pgsize, base, base + len);
}

/*
 * The kernel will tell us when there's more memory available for us to use.
 * This is most common on amd64, which boots with only 4G of VA available, and
 * later expands to the full 64-bit address space.
 */
int
mdb_umem_add(caddr_t base, size_t len)
{
	return (umem_add(base, len));
}
