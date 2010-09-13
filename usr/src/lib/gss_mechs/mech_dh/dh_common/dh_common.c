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

#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

#include "dh_gssapi.h"
#include "dh_common.h"

#define	MECH_LIB_PREFIX1	"/usr/lib/"

/*
 * This #ifdef mess figures out if we are to be compiled into an
 * lp64 binary for the purposes of figuring the absolute location
 * of gss-api mechanism modules.
 */
#ifdef  _LP64

#ifdef __sparc

#define	MECH_LIB_PREFIX2	"sparcv9/"

#elif defined(__amd64)

#define	MECH_LIB_PREFIX2	"amd64/"

#else   /* __sparc */

you need to define where under /usr the LP64 libraries live for this platform

#endif  /* __sparc */

#else   /* _LP64 */

#define	MECH_LIB_PREFIX2	""

#endif  /* _LP64 */

#define	MECH_LIB_DIR		"gss/"

#define	MECH_LIB_PREFIX MECH_LIB_PREFIX1 MECH_LIB_PREFIX2 MECH_LIB_DIR

#define	DH_MECH_BACKEND		"mech_dh.so.1"

#define	DH_MECH_BACKEND_PATH MECH_LIB_PREFIX DH_MECH_BACKEND

static char *DHLIB = DH_MECH_BACKEND_PATH;

#ifndef DH_MECH_SYM
#define	DH_MECH_SYM		"__dh_gss_initialize"
#endif

/*
 * __dh_generic_initialize: This routine is called from the mechanism
 * specific gss_mech_initialize routine, which in turn is called from
 * libgss to initialize a mechanism. This routine takes a pointer to
 * a struct gss_config, the OID for the calling mechanism and that mechanisms
 * keyopts. It returns the same gss_mechanism back, but with all fields
 * correctly initialized. This routine in turn opens the common wire
 * protocol moduel mech_dh.so.1 to fill in the common parts of the
 * gss_mechanism. It then associatates the OID and the keyopts with this
 * gss_mechanism. If there is any failure NULL is return instead.
 */
gss_mechanism
__dh_generic_initialize(gss_mechanism dhmech, /* The mechanism to initialize */
			gss_OID_desc mech_type, /* OID of mechanism */
			dh_keyopts_t keyopts /* Key mechanism entry points  */)
{
	gss_mechanism (*mech_init)(gss_mechanism mech);
	gss_mechanism mech;
	void *dlhandle;
	dh_context_t context;

	/* Open the common backend */
	if ((dlhandle = dlopen(DHLIB, RTLD_NOW)) == NULL) {
		return (NULL);
	}

	/* Fetch the common backend initialization routine */
	mech_init = (gss_mechanism (*)(gss_mechanism))
		dlsym(dlhandle, DH_MECH_SYM);

	/* Oops this should not happen */
	if (mech_init == NULL) {
		return (NULL);

	}

	/* Initialize the common parts of the gss_mechanism */
	if ((mech = mech_init(dhmech)) == NULL) {
		return (NULL);
	}

	/* Set the mechanism OID */
	mech->mech_type = mech_type;

	/* Grab the mechanism context */
	context = (dh_context_t)mech->context;

	/* Set the keyopts */
	context->keyopts = keyopts;

	/* Set a handle to the mechanism OID in the per mechanism context */
	context->mech = &mech->mech_type;

	return (mech);
}
