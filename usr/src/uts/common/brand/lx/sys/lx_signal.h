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
 * Copyright 2015 Joyent, Inc.
 */

#ifndef _LX_SIGNAL_H
#define	_LX_SIGNAL_H

#include <lx_signum.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern void lx_ltos_sigset(lx_sigset_t *, k_sigset_t *);
extern void lx_stol_sigset(k_sigset_t *, lx_sigset_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LX_SIGNAL_H */
