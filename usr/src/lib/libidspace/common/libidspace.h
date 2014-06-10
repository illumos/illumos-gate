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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

#ifndef _LIBIDSPACE_H
#define	_LIBIDSPACE_H

/*
 * libidspace public header
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

typedef struct id_space id_space_t;

extern id_space_t *id_space_create(const char *, id_t, id_t);
extern void id_space_destroy(id_space_t *);
extern void id_space_extend(id_space_t *, id_t, id_t);
extern id_t id_alloc(id_space_t *);
extern id_t id_alloc_specific(id_space_t *, id_t);
extern void id_free(id_space_t *, id_t);

#ifdef __cplusplus
}
#endif

#endif /* _LIBIDSPACE_H */
