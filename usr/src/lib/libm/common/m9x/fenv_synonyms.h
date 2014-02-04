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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_M9X_FENV_SYNONYMS_H
#define	_M9X_FENV_SYNONYMS_H

#include <sys/isa_defs.h>

/* feexcept.c */
#define feclearexcept	__feclearexcept
#define feraiseexcept	__feraiseexcept
#define fetestexcept	__fetestexcept
#define fegetexceptflag	__fegetexceptflag
#define fesetexceptflag	__fesetexceptflag

/* fenv.c */
#define feholdexcept	__feholdexcept
#define feholdexcept96	__feholdexcept96
#define feupdateenv		__feupdateenv
#define fegetenv		__fegetenv
#define fesetenv		__fesetenv
#define fex_merge_flags	__fex_merge_flags

#if defined(__x86)
/* feprec.c */
#define fegetprec		__fegetprec
#define fesetprec		__fesetprec
#endif

/* feround.c */
#define fegetround		__fegetround
#define fesetround		__fesetround
#define fesetround96	__fesetround96

/* fex_handler.c */
#define fex_get_handling		__fex_get_handling
#define fex_set_handling		__fex_set_handling
#define fex_getexcepthandler	__fex_getexcepthandler
#define fex_setexcepthandler	__fex_setexcepthandler

/* fex_log.c */
#define fex_get_log			__fex_get_log
#define fex_set_log			__fex_set_log
#define fex_get_log_depth	__fex_get_log_depth
#define fex_set_log_depth	__fex_set_log_depth
#define fex_log_entry		__fex_log_entry

/* libc, libthread */
#define close			_close
#define getcontext		_getcontext
#define getpid			_getpid
#define kill			_kill
#define lseek			_lseek
#define mutex_lock		_mutex_lock
#define mutex_unlock	_mutex_unlock
#define open			_open
#define read			_read
#define sigaction		_sigaction
#define sigemptyset		_sigemptyset
#define sigismember		_sigismember
#define sigprocmask		_sigprocmask
#define stat			_stat
#define thr_getspecific	_thr_getspecific
#define thr_keycreate	_thr_keycreate
#define thr_main		_thr_main
#define thr_setspecific	_thr_setspecific
#define write			_write

/* ??? see V9 /usr/include/stdio.h */
#ifdef __sparcv9
#define fileno			_fileno
#endif

#ifdef __sparc
/* libm, libsunmath */
#define fp_class		__fp_class
#define fp_classf		__fp_classf
#define sqrt			__sqrt
#define sqrtf			__sqrtf
#endif

#endif	/* _M9X_FENV_SYNONYMS_H */
