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
 *
 */

/* $Id: psm.c 146 2006-03-24 00:26:54Z njacobs $ */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dlfcn.h>
#include <papi_impl.h>

#ifndef	RTLD_GROUP
#define	RTLD_GROUP 0
#endif	/* RTLD_GROUP */

#ifndef	PSM_DIR
#define	PSM_DIR	"/usr/lib/print"
#endif

papi_status_t
psm_open(service_t *svc, char *scheme)
{
	papi_status_t result = PAPI_OK;
	char path[BUFSIZ];

	if ((scheme == NULL) || (strchr(scheme, '/') != NULL))
		return (PAPI_BAD_ARGUMENT);

	snprintf(path, sizeof (path), PSM_DIR "/psm-%s.so", scheme);

	svc->so_handle = dlopen(path, RTLD_LAZY|RTLD_LOCAL|RTLD_GROUP);
	if (svc->so_handle == NULL) {	/* failed, set the result/message */
		if ((access(path, F_OK) < 0) && (errno == ENOENT))
			result = PAPI_URI_SCHEME;
		else
			result = PAPI_NOT_POSSIBLE;
#ifdef DEBUG
		detailed_error(svc, "psm_open(%s): %s: %s", scheme, path,
		    dlerror());
#endif
	}

	return (result);
}

void
psm_close(void *handle)
{
	dlclose(handle);
}

void *
psm_sym(service_t *svc, char *name)
{
#ifdef DEBUG
	char *error = "invalid input";
#endif
	void *func = NULL;

	if ((svc != NULL) && (svc->so_handle != NULL) && (name != NULL)) {
		if ((func = dlsym(svc->so_handle, name)) == NULL) {
#ifdef DEBUG
			error = dlerror();
#else
			return (func);
#endif
		}
	}
#ifdef DEBUG
	if (func == NULL)
		detailed_error(svc, "psm_sym(%s): %s", name, error);
#endif

	return (func);
}
