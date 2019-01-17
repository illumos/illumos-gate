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

#ifndef _MERGEQ_H
#define	_MERGEQ_H

/*
 * mergeq library routines
 */

#include <sys/types.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mergeq mergeq_t;
typedef int (mergeq_proc_f)(void *, void *, void **, void *);

extern int mergeq_init(mergeq_t **, uint_t);
extern void mergeq_fini(mergeq_t *);

extern int mergeq_add(mergeq_t *, void *);

#define	MERGEQ_ERROR	-1
#define	MERGEQ_UERROR	-2
extern int mergeq_merge(mergeq_t *, mergeq_proc_f *, void *, void **, int *);

/*
 * Routines consumers need to implement
 */
extern void *mergeq_alloc(size_t);
extern void mergeq_free(void *, size_t);

#ifdef __cplusplus
}
#endif

#endif /* _MERGEQ_H */
