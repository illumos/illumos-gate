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
 * Copyright 2001, 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_META_REPARTITION_H
#define	_META_REPARTITION_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <meta.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* meta_repartition_drive() option flags */
#define	MD_REPART_FORCE		0x01
#define	MD_REPART_LEAVE_REP	0x02
#define	MD_REPART_DONT_LABEL	0x04

/* meta_repartition.c */
extern	int meta_repartition_drive(mdsetname_t *sp,
    mddrivename_t *dnp, int options, mdvtoc_t *vtocp, md_error_t *ep);

#ifdef	__cplusplus
}
#endif

#endif	/* _META_REPARTITION_H */
