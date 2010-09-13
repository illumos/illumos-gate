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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<sys/types.h>
#include 	<limits.h>
#include	<stdio.h>
#include	<project.h>
#include	<sys/param.h>
#include	<nss_dbdefs.h>
#include	<users.h>
#include	<userdefs.h>

/*  validate a project id */
int
valid_projid(projid_t projid, struct project *pptr, void *buf, size_t len)
{
	struct project pbuf;
	struct project *t_pptr;

	if (projid < 0)
		return (INVALID);

	if (projid > MAXPROJID)
		return (TOOBIG);

	if (t_pptr = getprojbyid(projid, pptr, buf, len))
		return (NOTUNIQUE);

	return (UNIQUE);
}
