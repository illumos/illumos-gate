/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef _COMPAT_FREEBSD_STDATOMIC_H_
#define	_COMPAT_FREEBSD_STDATOMIC_H_

#include <machine/atomic.h>

/*
 * For now, this is just enough to support the usage in usr/src/cmd/bhyve/rfb.c
 * which uses these functions with atomic_bool/bool arguments.
 */

#define	atomic_bool volatile u_int

#define	atomic_compare_exchange_strong(p, ovalp, nval) \
	atomic_cmpset_int((p), *(ovalp), (nval))

#define	atomic_exchange(p, nval)	atomic_swap_int((p), (nval))

#endif	/* _COMPAT_FREEBSD_STDATOMIC_H_ */
