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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_VA_IMPL_H
#define	_SYS_VA_IMPL_H

/*
 * An application should not include this header directly.  Instead it
 * should be included only through the inclusion of other Sun headers,
 * specifically <stdarg.h> and <varargs.h>.
 *
 * This header serves two purposes.
 *
 * First, it provides a common set of definitions that implementations
 * of the various standards for variable argument lists may use.  These
 * various standards are implemented in <varargs.h>, <stdarg.h>,
 * <iso/stdarg_iso.h>, <iso/stdarg_c99.h>, and <sys/varargs.h>.
 *
 * Second, it provides varying implementations of the common definitions,
 * depending upon the compiler.
 */

/*
 * The common definitions exported by this header or compilers using
 * this header are:
 *
 * the macro __va_start(list, name) starting the list iteration
 * the macro __va_arg(list, type) getting the current arg and iterating
 * the macro __va_copy(to, from) to bookmark the list iteration
 * the macro __va_end(list) to end the iteration
 *
 * In addition, the following are exported via inclusion of <sys/va_list.h>:
 *
 * the identifier __builtin_va_alist for the variable list pseudo parameter
 * the type __va_alist_type for the variable list pseudo parameter
 * the type __va_list defining the type of the variable list iterator
 */

/*
 * This header uses feature macros (e.g. __BUILTIN_VA_ARG_INCR and
 * __BUILTIN_VA_STRUCT), compiler macros (e.g. __GNUC__), and processor
 * macros (e.g. __sparc) to determine the protocol appropriate to the
 * current compilation.  It is intended that the compilation system
 * define the feature, processor, and compiler macros, not the user of
 * the system.
 */

/*
 * Many compilation systems depend upon the use of special functions
 * built into the the compilation system to handle variable argument
 * lists.  These built-in symbols may include one or more of the
 * following:
 *
 *      __builtin_va_alist
 *      __builtin_va_start
 *      __builtin_va_arg_incr
 *      __builtin_stdarg_start
 *      __builtin_va_end
 *      __builtin_va_arg
 *      __builtin_va_copy
 */

/*
 * The following are defined in <sys/va_list.h>:
 *
 *      __va_alist_type
 *      __va_void()
 *      __va_ptr_base
 *      ISA definitions via inclusion of <sys/isa_defs.h>
 *
 * Inclusion of this header also makes visible the symbols in <sys/va_list.h>.
 * This header is included in <varargs.h>, <sys/varargs.h> and in <stdarg.h>
 * via inclusion of <iso/stdarg_iso.h>.
 */

#include <sys/va_list.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(__lint)	/* ---------------------------------------- protocol */

#define	__va_start(list, name)	((list) = (__va_list)&name)
#define	__va_arg(list, type)	((type *)(list))[0]
#define	__va_copy(to, from)	__va_void(((to) = (from)))
/*ARGSUSED*/
static void __va_end(__va_list list) { __va_end(list); }

#elif defined(__BUILTIN_VA_STRUCT)	/* ------------------------ protocol */

/* ISA __va_list structures defined in <sys/va_list.h> */

void __builtin_va_start(__va_list, ...);
void *__builtin_va_arg_incr(__va_list, ...);

#define	__va_start(list, name)	__builtin_va_start(list, 0)
#define	__va_arg(list, type)	\
	((type *)__builtin_va_arg_incr(list, (type *)0))[0]
#define	__va_copy(to, from)	__va_void(((to)[0] = (from)[0]))
#define	__va_end(list)		__va_void(0)

#elif defined(__BUILTIN_VA_ARG_INCR)	/* ------------------------ protocol */

#define	__va_start(list, name)	\
	__va_void(((list) = (__va_list)&__builtin_va_alist))
#define	__va_arg(list, type)	\
	((type *)__builtin_va_arg_incr((type *)(list)))[0]
#define	__va_copy(to, from)	__va_void(((to) = (from)))
#define	__va_end(list)		__va_void(0)

#elif defined(__GNUC__)	&& ((__GNUC__ == 2 && __GNUC_MINOR__ >= 96) || \
	(__GNUC__ >= 3))		/* ------------------------ protocol */
#if (__GNUC__ < 3) || ((__GNUC__ == 3) && (__GNUC_MINOR__ < 3))
#define	__va_start(list, name)	__builtin_stdarg_start(list, name)
#else
#define	__va_start(list, name)	__builtin_va_start(list, name)
#endif

#define	__va_arg(list, type)	__builtin_va_arg(list, type)
#define	__va_end(list)		__builtin_va_end(list)
#define	__va_copy(to, from)	__builtin_va_copy(to, from)

#else					/* ----------------------- protocol */

/*
 * Because we can not predict the compiler protocol for unknown compilers, we
 * force an error in order to avoid unpredictable behavior. For versions of
 * gcc 2.95 and earlier, variable argument lists are handled in gcc specific
 * stdarg.h and varargs.h headers created via the gcc fixincl utility. In
 * those cases, the gcc headers would override this header.
 */

#error("Unrecognized compiler protocol for variable argument lists")

#endif  /* -------------------------------------------------------- protocol */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VA_IMPL_H */
