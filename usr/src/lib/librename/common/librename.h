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

#ifndef _LIBRENAME_H
#define	_LIBRENAME_H

/*
 * librename(3RENAME) public interfaces
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct librename_atomic librename_atomic_t;

#define	LIBRENAME_ATOMIC_NOUNLINK	0x01
#define	LIBRENAME_ATOMIC_CLOEXEC	0x02
extern int librename_atomic_init(const char *, const char *, const char *,
    int, int, librename_atomic_t **);
extern int librename_atomic_fdinit(int, const char *, const char *, int, int,
    librename_atomic_t **);
extern int librename_atomic_fd(librename_atomic_t *);
extern int librename_atomic_commit(librename_atomic_t *);
extern void librename_atomic_fini(librename_atomic_t *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBRENAME_H */
