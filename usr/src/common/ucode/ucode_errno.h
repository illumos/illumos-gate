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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2023 Oxide Computer Company
 */

#ifndef _UCODE_ERRNO_H
#define	_UCODE_ERRNO_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum ucode_errno {
	EM_OK,		/* No error */
	EM_FILESIZE,	/* File size is invalid */
	EM_OPENFILE,	/* Failed to open file */
	EM_FILEFORMAT,	/* Not a valid microcode file */
	EM_HEADER,	/* File header is invalid */
	EM_CHECKSUM,	/* Checksum is invalid */
	EM_EXTCHECKSUM,	/* Extended signature table checksum is invalid */
	EM_SIGCHECKSUM,	/* Extended signature checksum is invalid */
	EM_INVALIDARG,	/* Invalid argument(s) */
	EM_NOMATCH,	/* No matching microcode found */
	EM_HIGHERREV,	/* File does not contain higher revision microcode */
	EM_NOTSUP,	/* Processor does not support microcode operations */
	EM_UPDATE,	/* Failed to update to the latest revision */
	EM_SYS,		/* System call failed.  See errno */
	EM_NOVENDOR,	/* Could not determine the type of the update file */
	EM_NOMEM	/* Not enough memory */
} ucode_errno_t;

extern const char *ucode_strerror(ucode_errno_t);
extern const char *ucode_errname(ucode_errno_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _UCODE_ERRNO_H */
