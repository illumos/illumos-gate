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
 * Copyright 2002 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MKSH_MACRO_H
#define	_MKSH_MACRO_H

#include <mksh/defs.h>

extern void	expand_macro(Source, String, wchar_t *, Boolean);
extern void	expand_value(Name, String, Boolean);
extern Name	getvar(Name);

extern Property	setvar_daemon(Name, Name, Boolean, Daemon, Boolean, short);

#endif /* _MKSH_MACRO_H */
