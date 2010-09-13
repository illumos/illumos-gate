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
 */

#ifndef	_MESSAGE_H
#define	_MESSAGE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <libintl.h>

#define	OPT_DC_EXCL	gettext("fiocompress: -c and -d are exclusive\n")
#define	INVALID_BLKSZ	gettext("fiocompress: invalid block size\n")
#define	UNKNOWN_OPTION	gettext("fiocompress: unknown option -%c\n")
#define	MISS_FILES	gettext("fiocompress: input and output files\
 must be specified\n")
#define	FIO_COMP_FAIL	gettext("fiocompress: FIO_COMPRESSED on %s failed\
 - %s\n")
#define	CANT_OPEN	gettext("fiocompress: cannot open %s - %s\n")
#define	STAT_FAIL	gettext("fiocompress: stat of %s failed - %s\n")
#define	MMAP_FAIL	gettext("fiocompress: mmapping on %s failed - %s\n")
#define	OPEN_FAIL	gettext("fiocompress: open of %s failed - %s\n")
#define	HDR_ALLOC	gettext("fiocompress: failed to allocate %d bytes\
 for header\n")
#define	BUF_ALLOC	gettext("fiocompress: failed to allocate %d bytes\
 for buffer\n")
#define	SEEK_ERR	gettext("fiocompress: seek to %ld on %s failed - %s\n")
#define	COMP_ERR	gettext("fiocompress: %s - compression error %d\n")
#define	WRITE_ERR	gettext("fiocompress: write of %ld bytes on %s failed\
 - %s\n")
#define	BAD_MAGIC	gettext("fiocompress: %s - bad magic (0x%llx/0x%x)\n")
#define	BAD_VERS	gettext("fiocompress: %s - bad version (0x%llx/0x%x)\n")
#define	BAD_ALG		gettext("fiocompress: %s - bad algorithm\
 (0x%llx/0x%x)\n")
#define	DECOMP_ERR	gettext("fiocompress: %s - decompression error %d\n")
#define	CORRUPT		gettext("fiocompress: %s - corrupt file\n")

#ifdef	__cplusplus
}
#endif

#endif /* _MESSAGE_H */
