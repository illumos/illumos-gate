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

#ifndef _WORKQ_H
#define	_WORKQ_H

/*
 * workq library routines
 */

#include <sys/types.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct workq workq_t;
typedef int (workq_proc_f)(void *, void *);

extern int workq_init(workq_t **, uint_t);
extern void workq_fini(workq_t *);

extern int workq_add(workq_t *, void *);

#define	WORKQ_ERROR	(-1)
#define	WORKQ_UERROR	(-2)
extern int workq_work(workq_t *, workq_proc_f *, void *, int *);

/*
 * Routines consumers need to implement
 */
extern void *workq_alloc(size_t);
extern void workq_free(void *, size_t);

#ifdef __cplusplus
}
#endif

#endif /* _WORKQ_H */
