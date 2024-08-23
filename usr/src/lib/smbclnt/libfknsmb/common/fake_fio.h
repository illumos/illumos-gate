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
 * Copyright 2024 RackTop Systems, Inc.
 */

#ifndef _FAKE_FS_H
#define	_FAKE_FS_H

/*
 * Fake file system layer for user-level.
 */

#include <sys/isa_defs.h>
#include <sys/file.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * These are private to this library, used by the "ktli" shim.
 * See fake_fio.c
 */
extern file_t *file_getf(int);
extern void file_releasef(int);
int file_getfd(struct file *fp);

#ifdef __cplusplus
}
#endif

#endif /* _FAKE_FS_H */
