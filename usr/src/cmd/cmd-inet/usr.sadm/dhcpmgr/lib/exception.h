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

#ifndef _EXCEPTION_H
#define	_EXCEPTION_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <jni.h>
#include <dhcp_symbol.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This really doesn't belong here, but rather than create another whole
 * header file just for this macro, we stuck it here.
 */
#define	ARRAY_LENGTH(arr, len)	for (len = 0; arr[len] != NULL; ++len);

#define	ULONG_MAX_CHAR	(sizeof ("4294967295"))
#define	UINT64_MAX_CHAR	(sizeof ("18446744073709551615"))
#define	IPADDR_MAX_CHAR	(sizeof ("255.255.255.255"))

extern void throw_libdhcpsvc_exception(JNIEnv *, int);
extern void throw_remove_dd_exception(JNIEnv *, int, const char *);
extern void throw_open_dd_exception(JNIEnv *, int, const char *);
extern void throw_add_dd_entry_exception(JNIEnv *, int, const char *);
extern void throw_delete_dd_entry_exception(JNIEnv *, int, const char *);
extern void throw_modify_dd_entry_exception(JNIEnv *, int, const char *,
	const char *);
extern void throw_bridge_exception(JNIEnv *, const char *);
extern void throw_memory_exception(JNIEnv *);
extern void throw_no_defaults_exception(JNIEnv *);
extern void throw_noent_exception(JNIEnv *, const char *);
extern void throw_not_running_exception(JNIEnv *);
extern void throw_invalid_resource_exception(JNIEnv *, const char *);
extern void throw_invalid_path_exception(JNIEnv *, const char *);
extern void throw_dsym_parser_exception(JNIEnv *, const char *, char **, int,
    dsym_errcode_t);
extern void throw_dsym_parser_init_exception(JNIEnv *, const char *,
    dsym_errcode_t);
extern void throw_wordexp_exception(JNIEnv *, int);
extern boolean_t is_no_defaults_exception(JNIEnv *, jthrowable);
#ifdef	__cplusplus
}
#endif

#endif	/* !_EXCEPTION_H */
