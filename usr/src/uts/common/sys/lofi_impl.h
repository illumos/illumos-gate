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
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 */

#ifndef _SYS_LOFI_IMPL_H
#define	_SYS_LOFI_IMPL_H

/*
 * lofi private implementation details.
 */

#include <sys/nvpair.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Structure for custom data, maintained as nvlist. */
typedef struct lofi_nvl {
	kmutex_t	ln_lock;
	kcondvar_t	ln_cv;
	nvlist_t	*ln_data;
} lofi_nvl_t;

extern lofi_nvl_t lofi_devlink_cache;
#ifdef __cplusplus
}
#endif

#endif /* _SYS_LOFI_IMPL_H */
