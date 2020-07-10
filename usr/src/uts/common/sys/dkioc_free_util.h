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
 * Copyright 2017 Nexenta Inc.  All rights reserved.
 * Copyright 2020 Joyent, Inc.
 */

#ifndef _SYS_DKIOC_FREE_UTIL_H
#define	_SYS_DKIOC_FREE_UTIL_H

#include <sys/dkio.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	DFL_COPYIN_MAX_EXTS	(1024 * 1024)

#define	DFL_ISSYNC(dfl) (((dfl)->dfl_flags & DF_WAIT_SYNC) ? B_TRUE : B_FALSE)

/*
 * Since dkioc_free_list_t and in general DKIOCFREE use bytes to express
 * values instead of blocks, dkioc_free_info_t uses bytes as well for
 * consistency.
 */
typedef struct dkioc_free_info {
	/* log2(block size) */
	uint64_t	dfi_bshift;

	/* Maximum number of extents in a single request. 0 == no limit */
	uint64_t	dfi_max_ext;

	/*
	 * Maximum total number of bytes in a single request.  0 == no limit.
	 * Must by a multiple of 1U << dfi_bshift (e.g. dfi_bshift == 9,
	 * dfk_max_bytes must be a multiple of 512).
	 */
	uint64_t	dfi_max_bytes;

	/*
	 * Maximum length of an extent. 0 == same as dfi_max_bytes. If > 0,
	 * must be a multiple of 1U << dfi_shift (the block size) and
	 * <= dfi_max_bytes.
	 */
	uint64_t	dfi_max_ext_bytes;

	/*
	 * Minimum alignment for starting extent offsets in bytes
	 * Must be > 0, and a multiple of 1U << dfi_shift.
	 *
	 * A possible future extention might be to also express a preferred
	 * alignment when splitting extents.
	 */
	uint64_t	dfi_align;
} dkioc_free_info_t;

typedef int (*dfl_iter_fn_t)(dkioc_free_list_t *dfl, void *arg, int kmflag);

int dfl_copyin(void *arg, dkioc_free_list_t **out, int ddi_flags, int kmflags);
void dfl_free(dkioc_free_list_t *dfl);
int dfl_iter(dkioc_free_list_t *dfl, const dkioc_free_info_t *dfi, uint64_t len,
    dfl_iter_fn_t fn, void *arg, int kmflag);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_DKIOC_FREE_UTIL_H */
