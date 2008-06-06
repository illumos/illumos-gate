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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Default backend-finder(s) for the name-service-switch routines.
 * At present there is a single finder that uses dlopen() to do its thing.
 *
 * === Could also do a finder that includes db-name in filename
 * === and one that does dlopen(0) to check in the executable
 */

	/* Allow our finder(s) to be overridden by user-supplied ones */

#pragma weak _nss_default_finders = nss_default_finders

#include "lint.h"
#include "mtlib.h"
#include <nss_common.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <alloca.h>

/* === ? move these constants to a public header file ? */
static const int  dlopen_version  = 1;
#ifndef NSS_DLOPEN_FORMAT
#define	NSS_DLOPEN_FORMAT "nss_%s.so.%d"
#endif
#ifndef NSS_DLSYM_FORMAT
#define	NSS_DLSYM_FORMAT "_nss_%s_%s_constr"
#endif
static const char dlopen_format[] = NSS_DLOPEN_FORMAT;
static const char dlsym_format [] = NSS_DLSYM_FORMAT;
static const size_t  format_maxlen   = sizeof (dlsym_format) - 4;

/*ARGSUSED*/
static nss_backend_constr_t
SO_per_src_lookup(void *dummy, const char *db_name, const char *src_name,
	void **delete_privp)
{
	char			*name;
	void			*dlhandle;
	void			*sym;
	size_t			len;
	nss_backend_constr_t	res = 0;

	len = format_maxlen + strlen(db_name) + strlen(src_name);
	name = alloca(len);
	(void) sprintf(name, dlopen_format, src_name, dlopen_version);
	if ((dlhandle = dlopen(name, RTLD_LAZY)) != 0) {
		(void) sprintf(name, dlsym_format, src_name, db_name);
		if ((sym = dlsym(dlhandle, name)) == 0) {
			(void) dlclose(dlhandle);
		} else {
			*delete_privp = dlhandle;
			res = (nss_backend_constr_t)sym;
		}
	}
	return (res);
}

/*ARGSUSED*/
static void
SO_per_src_delete(void *delete_priv, nss_backend_constr_t dummy)
{
	(void) dlclose(delete_priv);
}

static nss_backend_finder_t SO_per_src = {
	SO_per_src_lookup,
	SO_per_src_delete,
	0,
	0
};

nss_backend_finder_t *nss_default_finders = &SO_per_src;
