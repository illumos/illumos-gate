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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

/*
 * C++ Demangling
 */
#define	LIBDEMANGLE	"libdemangle.so.1"
#define	DEMANGLEFUNC	"cplus_demangle"

#define	MAXDBUF		1024

char *
sgs_demangle(char *name)
{
	static char *demangled_name;
	static int (*demangle_func)() = NULL;
	static int first_flag = 0;
	static int size = MAXDBUF;
	int ret;

	/*
	 * Determine if libdemangle is available.
	 */
	if (first_flag == 0) {
		void *demangle_hand;

		demangle_hand = dlopen(LIBDEMANGLE, RTLD_LAZY);
		if (demangle_hand != NULL)
			demangle_func = (int (*)(int))dlsym(
				demangle_hand, DEMANGLEFUNC);

		first_flag = 1;
	}

	/*
	 * Pass through name untouched if libdemangle is not available.
	 */
	if (demangle_func == NULL)
		return (name);

	/*
	 * If this is the first call (or malloc() failed previously) allocate a
	 * new buffer for storage.
	 */
	if (demangled_name == NULL) {
		size = MAXDBUF;
		demangled_name = malloc(size);
		if (demangled_name == NULL)
			return (name);
	}

	/*
	 * libdemangle returns -1 when the buffer size is not sufficient.
	 */
	while ((ret = (*demangle_func)(name, demangled_name, size)) == -1) {
		free(demangled_name);
		size = size + MAXDBUF;
		demangled_name = malloc(size);
		if (demangled_name == NULL)
			return (name);
	}

	if (ret != 0)
		return (name);
	return (demangled_name);
}
