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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	Copyright (c) 1988 AT&T
 *	All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * NOTE: The environment symbol pair may also occur in crt1.o.  The definitions
 * within crt1.o are required for the generation of ABI compliant applications
 * (see bugid 1181124).  No other symbol definitions should be added to this
 * file.
 */

/*
 * The original SVR3 ABI states:
 *
 * Application Constraints
 * As described above, libsys provides symbols for applications. In a few cases,
 * however, an application is obliged to provide symbols for the library.
 *
 * extern char **environ;
 *     Normally, this symbol is synonymous with environ, as
 *     exec(BA_OS) describes.  This isn't always true, though, because
 *     ANSI C does not define environ.  Thus, an ANSI C-conforming
 *     application can define its own environ symbol, unrelated to the pro-
 *     cess environment.  If the application defines environ and intends it
 *     to have the System V Interface Definition, Third Edition semantics, it
 *     must also define _environ so that the two symbols refer to the same
 *     data object.
 *
 * The ABI description implies that the process environment should use
 * _environ and that nothing in libc should make reference to the unadorned
 * "environ" symbol.  This way, an application can define and use a symbol
 * named "environ" for its own purposes without affecting the actual
 * process environment.
 */

#pragma weak environ = _environ
const char **_environ = 0;
