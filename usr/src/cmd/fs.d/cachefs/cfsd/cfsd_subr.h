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
 *
 *			cfsd_subr.h
 *
 * Include file for the various common routines.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* Copyright (c) 1994 by Sun Microsystems, Inc. */

#ifndef CFSD_SUBR
#define	CFSD_SUBR

void subr_add_mount(cfsd_all_object_t *all_object_p, const char *dirp,
    const char *idp);
void *subr_mount_thread(void *datap);
void subr_cache_setup(cfsd_all_object_t *all_object_p);
int subr_fsck_cache(const char *cachedirp);
void subr_doexec(const char *fstype, char *newargv[], const char *progp);
void pr_err(char *fmt, ...);
char *subr_strdup(const char *strp);

#endif /* CFSD_SUBR */
