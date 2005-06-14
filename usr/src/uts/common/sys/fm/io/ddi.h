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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FM_IO_DDI_H
#define	_SYS_FM_IO_DDI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	DDI_DVR_MAX_CLASS		32

/* IO-specific FMA ereport class defintions */
#define	DDI_IO_CLASS			"io"

/* Driver defect ereport specifications */
#define	DVR_ERPT		"ddi."
#define	DVR_ECONTEXT		"context"	/* Invalid calling context */
#define	DVR_EINVAL		"einval"	/* Invalid calling semantic */
#define	DVR_EFMCAP		"fm-capability"	/* Improper FM capability */
#define	DVR_EVER		"version"	/* Invalid structure version */

/* Required payload member names */
#define	DVR_NAME		"dvr-name"
#define	DVR_STACK		"dvr-stack"
#define	DVR_STACK_DEPTH		"dvr-stack-depth"
#define	DVR_ERR_SPECIFIC	"dvr-error-specific"

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FM_IO_DDI_H */
