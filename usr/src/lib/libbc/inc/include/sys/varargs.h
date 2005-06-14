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
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	from UCB 4.1 83/05/03	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _sys_varargs_h
#define _sys_varargs_h

typedef char *va_list;
#if defined(sparc)
# define va_alist __builtin_va_alist
#endif
# define va_dcl int va_alist;
# define va_start(list) list = (char *) &va_alist
# define va_end(list)
# if defined(__BUILTIN_VA_ARG_INCR) && !defined(lint)
#    define va_arg(list,mode) ((mode*)__builtin_va_arg_incr((mode *)list))[0]
# else
#    define va_arg(list,mode) ((mode *)(list += sizeof(mode)))[-1]
# endif

#endif /*!_sys_varargs_h*/
