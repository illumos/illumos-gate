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
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * misc routines
 */

#include <stdio.h>
#include <sys/types.h>
#include "codeset.h"
#include "mbextern.h"
#include <dlfcn.h>

static void *handle = (void *)NULL;	/* initialize it with NULL */

/*
 * Close current library library
 */
int
_ml_close_library(void)
{
	if (handle == (void *)NULL) {
		_code_set_info.open_flag = NULL;
		return (-1);
	}

	dlclose(handle);  
	_code_set_info.open_flag = NULL;
	handle = (void *)NULL;
	return (0);
}

/*
 * Open the given library
 */
void *
_ml_open_library(void)
{
	char buf[BUFSIZ];

	if (handle != (void *)NULL) /* This library is already opened */
		return (handle);

	/*
	 * Open the given library
	 */
	strcpy(buf, LIBRARY_PATH);
	strcat(buf, _code_set_info.code_name);
	strcat(buf, ".so");
#ifdef DEBUG
	printf ("ml_open_library: buf = '%s'\n", buf);
#endif
	handle = dlopen(buf, 1);
	if (handle != (void *)NULL)
		_code_set_info.open_flag = 1;
#ifdef DEBUG
	else
		printf ("_ml_open_library: dlopen failed\n");
#endif
	return (handle);
}
