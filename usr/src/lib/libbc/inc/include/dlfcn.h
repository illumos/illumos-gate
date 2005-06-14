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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	_dlfcn_h
#define	_dlfcn_h

/*
 * Copyright (c) 1989 Sun Microsystems, Inc.
 */

/*
 * Interface description for the contents of libdl -- simple programmer's
 * interfaces to the dynamic linker.
 */

/*
 * Manifest constants
 */
#define	RTLD_LAZY	1		/* deferred binding of procedures */

/*
 * Function declarations
 */
extern	void *dlopen();			/* open and map a shared object */
extern	void *dlsym();			/* obtain address of symbol */
extern	int dlclose();			/* remove a shared object */
extern	char *dlerror();		/* string representing last error */

#endif /* !_dlfcn_h */
