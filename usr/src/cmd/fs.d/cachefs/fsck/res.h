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
/*
 *
 *			res.h
 *
 *   Defines routines to operate on the resource file.
 */

#ifndef	_RES_H
#define	_RES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	cfs_fsck_res_h
#define	cfs_fsck_res_h

typedef struct res res;

res *res_create(char *namep, int entries, int verbose);
void res_destroy(res *resp);
int res_done(res *resp);
void res_addfile(res *resp, long nbytes);
int res_addident(res *resp, int index, rl_entry_t *dp, long nbytes, int file);
void res_clearident(res *resp, int index, int nbytes, int file);

#endif /* cfs_fsck_res_h */

#endif /* _RES_H */
