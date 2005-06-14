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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_EXACCT_IMPL_H
#define	_EXACCT_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/exacct.h>
#include <stdio.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct _ea_file_depth {
	int	efd_nobjs;		/* number of objects in group */
	int	efd_obj;		/* index of curr object within group */
} ea_file_depth_t;

typedef struct _ea_file_impl {
	char	*ef_filename;		/* file name */
	char	*ef_creator;		/* file creator */
	char	*ef_hostname;		/* file hostname */
	FILE	*ef_fp;			/* file stream pointer */
	ea_file_depth_t *ef_depth;	/* pointer to depth stack */
	char	*ef_buf;		/* pointer for buffer consumption */
	ssize_t	ef_bufsize;		/* remaining bytes in buffer */
	void	*ef_lpad[1];
	offset_t ef_advance;		/* bytes to advance on next op */
	offset_t ef_opad[2];
	mode_t	ef_oflags;		/* flags to open(2) */
	int	ef_fd;			/* file descriptor */
	int	ef_version;		/* exacct file version */
	int	ef_ndeep;		/* current depth in allocated stack */
	int	ef_mxdeep;		/* maximum depth of allocated stack */
	int	ef_ipad[1];
} ea_file_impl_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _EXACCT_IMPL_H */
