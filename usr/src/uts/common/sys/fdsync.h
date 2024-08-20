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
 * Copyright 2024 Oxide Computer Company
 */

#ifndef _SYS_FDSYNC_H
#define	_SYS_FDSYNC_H

/*
 * This is a private header that shouldn't be shipped which covers specifics of
 * the fdsync system call (which is not a public libc interface).
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	/*
	 * Sync the file system indicated by the file descriptor. This is
	 * syncfs(3C).
	 */
	FDSYNC_FS	= 1,
	/*
	 * Sync all data and metadata that is outstanding on the file
	 * descriptor. This is fsync(3C).
	 */
	FDSYNC_FILE,
	/*
	 * Sync only the data that is outstanding on the file descriptor. This
	 * is fdatasync(3C).
	 */
	FDSYNC_DATA
} fdsync_mode_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_FDSYNC_H */
