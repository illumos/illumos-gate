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
 */

/* needed when building libzpool */
#ifndef	_KERNEL
#include <sys/zfs_context.h>
#endif

#include <sys/sunddi.h>
#include <sys/dkio.h>
#include <sys/dkioc_free_util.h>
#include <sys/sysmacros.h>
#include <sys/file.h>
#include <sys/sdt.h>

/*
 * Copy-in convenience function for variable-length dkioc_free_list_t
 * structures. The pointer to be copied from is in `arg' (may be a pointer
 * to userspace). A new buffer is allocated and a pointer to it is placed
 * in `out'. `ddi_flags' indicates whether the pointer is from user-
 * or kernelspace (FKIOCTL) and `kmflags' are the flags passed to
 * kmem_zalloc when allocating the new structure.
 * Returns 0 on success, or an errno on failure.
 */
int
dfl_copyin(void *arg, dkioc_free_list_t **out, int ddi_flags, int kmflags)
{
	dkioc_free_list_t *dfl;

	if (ddi_flags & FKIOCTL) {
		dkioc_free_list_t *dfl_in = arg;

		if (dfl_in->dfl_num_exts == 0 ||
		    dfl_in->dfl_num_exts > DFL_COPYIN_MAX_EXTS)
			return (SET_ERROR(EINVAL));
		dfl = kmem_alloc(DFL_SZ(dfl_in->dfl_num_exts), kmflags);
		if (dfl == NULL)
			return (SET_ERROR(ENOMEM));
		bcopy(dfl_in, dfl, DFL_SZ(dfl_in->dfl_num_exts));
	} else {
		uint64_t num_exts;

		if (ddi_copyin(((uint8_t *)arg) + offsetof(dkioc_free_list_t,
		    dfl_num_exts), &num_exts, sizeof (num_exts),
		    ddi_flags) != 0)
			return (SET_ERROR(EFAULT));
		if (num_exts == 0 || num_exts > DFL_COPYIN_MAX_EXTS)
			return (SET_ERROR(EINVAL));
		dfl = kmem_alloc(DFL_SZ(num_exts), kmflags);
		if (dfl == NULL)
			return (SET_ERROR(ENOMEM));
		if (ddi_copyin(arg, dfl, DFL_SZ(num_exts), ddi_flags) != 0 ||
		    dfl->dfl_num_exts != num_exts) {
			kmem_free(dfl, DFL_SZ(num_exts));
			return (SET_ERROR(EFAULT));
		}
	}

	*out = dfl;
	return (0);
}

/* Frees a variable-length dkioc_free_list_t structure. */
void
dfl_free(dkioc_free_list_t *dfl)
{
	kmem_free(dfl, DFL_SZ(dfl->dfl_num_exts));
}
