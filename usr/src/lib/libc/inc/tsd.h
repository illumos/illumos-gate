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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBC_INC_TSD_H
#define	_LIBC_INC_TSD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	_T_GETDATE = 0,
	_T_WCSTOK,
	_T_FP_GET,
	_T_NL_LANINFO,
	_T_GETPASS,
	_T_PTSNAME,
	_T_L64A,
	_T_GETVFSENT,
	_T_GETMNTENT,
	_T_GETDATE_ERR_ADDR,
	_T_CRYPT,
	_T_NSS_STATUS_VEC,
	_T_REGCMP_ISIZE,
	_T_REGEX_LOC1,
	_T_SETLOCALE,
	_T_STRUCT_TM,
	_T_TTYNAME,
	_T_CTIME,
	_T_LOGIN,
	_T_STRTOK,
	_T_TMPNAM,
	_T_ECVT,
	_T_PWBUF,
	_T_GRBUF,
	_T_SPBUF,
	_T_DOORBUF,
	_T_DEFREAD,
	_T_NUM_ENTRIES		/* this *must* be the last member */
} __tsd_item_t;

/*
 * Internal routine from tsdalloc.c
 */
extern void *tsdalloc(__tsd_item_t, size_t, void (*)(void *));

#ifdef __cplusplus
}
#endif

#endif	/* _LIBC_INC_TSD_H */
