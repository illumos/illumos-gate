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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBZFS_JNI_DISKMGT_H
#define	_LIBZFS_JNI_DISKMGT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libdiskmgt.h>
#include <sys/varargs.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Types
 */

typedef struct dmgt_slice {
	char *name;
	uint64_t start;
	uint64_t size;
	char *used_name;
	char *used_by;
} dmgt_slice_t;

typedef struct dmgt_disk {
	char *name;
	uint64_t size;
	uint32_t blocksize;
	int in_use;

	/* NULL-terminated array */
	char **aliases;

	/* NULL-terminated array */
	dmgt_slice_t **slices;
} dmgt_disk_t;

/* Callback function for available disk iteration */
typedef int (*dmgt_disk_iter_f)(dmgt_disk_t *, void *);

/*
 * Function prototypes
 */

extern int dmgt_avail_disk_iter(dmgt_disk_iter_f func, void *data);
extern void dmgt_free_disk(dmgt_disk_t *);
extern void dmgt_free_slice(dmgt_slice_t *);
extern void dmgt_set_error_handler(void (*)(const char *, va_list));

#ifdef __cplusplus
}
#endif

#endif /* _LIBZFS_JNI_DISKMGT_H */
