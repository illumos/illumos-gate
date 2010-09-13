/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1990-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _MULTIMEDIA_AUDIOUNIXFILE_INLINE_H
#define	_MULTIMEDIA_AUDIOUNIXFILE_INLINE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

// Inline routines for class AudioUnixfile

// Return the file descriptor
inline int AudioUnixfile::
getfd() const {
	return (fd);
}

// Set the file descriptor
inline void AudioUnixfile::
setfd(
	int newfd)				// new file descriptor
{
	fd = newfd;
}


// Return TRUE if fd is valid
inline Boolean AudioUnixfile::
isfdset() const {

	return (fd >= 0);
}

// Return TRUE if file hdr read/written
inline Boolean AudioUnixfile::
isfilehdrset() const {

	return (filehdrset);
}

// Return TRUE if stream is open
inline Boolean AudioUnixfile::
opened() const {

	return (isfdset() && isfilehdrset());
}

// Return the access mode
inline FileAccess AudioUnixfile::
GetAccess() const {
	return (mode);
}

// Return the blocking i/o mode
inline Boolean AudioUnixfile::
GetBlocking() const {
	return (block);
}

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_AUDIOUNIXFILE_INLINE_H */
