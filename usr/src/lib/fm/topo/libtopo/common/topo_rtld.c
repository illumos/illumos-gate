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

#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <assert.h>

#include <fm/topo_mod.h>

#include <topo_error.h>
#include <topo_alloc.h>
#include <topo_subr.h>

typedef struct topo_rtld {
	void *rtld_dlp;		/* libdl handle for shared library */
	int (*rtld_init)(topo_mod_t *, topo_version_t); /* .so _topo_init() */
	void (*rtld_fini)(topo_mod_t *); /* .so _topo_fini() */
} topo_rtld_t;

static int
rtld_fini(topo_mod_t *mod)
{
	topo_rtld_t *rp = mod->tm_data;

	assert(mod != NULL);

	if (mod->tm_flags & TOPO_MOD_REG) {
		rp->rtld_fini(mod);
		if (mod->tm_flags & TOPO_MOD_REG) {
			topo_mod_unregister(mod);
		}
	}

	if (getenv("TOPONODLCLOSE") == NULL)
		(void) dlclose(rp->rtld_dlp);
	topo_mod_free(mod, rp, sizeof (topo_rtld_t));

	return (0);
}

static int
rtld_init(topo_mod_t *mod, topo_version_t version)
{
	int err;
	topo_rtld_t *rp;
	void *dlp;

	if ((dlp = dlopen(mod->tm_path, RTLD_LOCAL | RTLD_NOW)) == NULL) {
		topo_dprintf(mod->tm_hdl, TOPO_DBG_ERR,
		    "dlopen() failed: %s\n", dlerror());
		return (topo_mod_seterrno(mod, ETOPO_RTLD_OPEN));
	}

	if ((rp = mod->tm_data = topo_mod_alloc(mod, sizeof (topo_rtld_t)))
	    == NULL)
		return (topo_mod_seterrno(mod, ETOPO_RTLD_OPEN));

	rp->rtld_dlp = dlp;
	rp->rtld_init = (int (*)())dlsym(dlp, "_topo_init");
	rp->rtld_fini = (void (*)())dlsym(dlp, "_topo_fini");

	if (rp->rtld_init == NULL) {
		(void) dlclose(dlp);
		topo_free(rp, sizeof (topo_rtld_t));
		return (topo_mod_seterrno(mod, ETOPO_RTLD_INIT));
	}

	/*
	 * Call _topo_init() in the module.
	 */
	err = rp->rtld_init(mod, version);

	if (err < 0 || !(mod->tm_flags & TOPO_MOD_REG)) {
		(void) rtld_fini(mod);
		return (topo_mod_seterrno(mod, ETOPO_MOD_NOREG));
	}

	return (0);
}

const topo_imodops_t topo_rtld_ops = {
	rtld_init,
	rtld_fini,
};
