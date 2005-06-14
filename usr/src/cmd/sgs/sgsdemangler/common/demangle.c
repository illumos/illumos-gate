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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include "dem.h"

/*
 * C++ Demangling
 */
#define	LIBDEMANGLE	"libdemangle.so.1"
#define	DEMANGLEFUNC	"cplus_demangle"

extern char *cafe_demangle(char *, char *);

/*
 * This is a backup routine which uses routine from CAFE
 * project. The -3 value is returned when the demangling
 * did not succeed.
 * (The -1 value is intentionally not used.)
 */
/*ARGSUSED*/
static int
sgs_cafe_demangle(char *name, char *demangled_name, int limit)
{
	char *cafe_out;
	DEM dem_struct;
	int dem_ret_val;

	cafe_out = cafe_demangle(
			(char *)name,
			(char *)demangled_name);

	if (cafe_out != name) {
		return (0);
	}

	dem_ret_val = dem(name, &dem_struct, demangled_name);

	if (dem_ret_val < 0)
		return (-3);

	return (0);
}

/*
 *
 */
char *
sgs_demangle(char *name)
{
	static char *demangled_name;
	static int (*demangle_func)() = 0;
	static int first_flag = 0;
	static int size = MAXDBUF;
	int ret;

	/*
	 * If this is the first time called,
	 * decide which demangling function to use.
	 */
	if (first_flag == 0) {
		void *demangle_hand;

		demangle_hand = dlopen(LIBDEMANGLE, RTLD_LAZY);
		if (demangle_hand != NULL)
			demangle_func = (int (*)(int))dlsym(
				demangle_hand, DEMANGLEFUNC);

		if (demangle_func == NULL)
			demangle_func = sgs_cafe_demangle;

		/*
		 * Allocate the buffer
		 */
		demangled_name = (char *) malloc(size);
		if (demangled_name == NULL)
			return (name);

		first_flag = 1;
	}

	/*
	 * If malloc() failed in the previous call,
	 * demangle_name is NULL. So the following codes are
	 * here.
	 */
	if (demangled_name == NULL) {
		size = MAXDBUF;
		demangled_name = (char *) malloc(size);
		if (demangled_name == NULL)
			return (name);
	}

	/*
	 * When we use the real one.
	 * The real function returns -1 when the buffer size
	 * is not sufficient.
	 *
	 * When we use the back up function, it never returns -1.
	 */
	while ((ret = (*demangle_func)(name, demangled_name, size)) == -1) {
		free(demangled_name);
		size = size + MAXDBUF;
		demangled_name = (char *) malloc(size);
		if (demangled_name == NULL)
			return (name);
	}

	if (ret != 0)
		return (name);
	return (demangled_name);
}
