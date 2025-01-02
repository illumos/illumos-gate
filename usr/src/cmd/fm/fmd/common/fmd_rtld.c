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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <dlfcn.h>
#include <link.h>

#include <fmd_module.h>
#include <fmd_error.h>
#include <fmd_alloc.h>
#include <fmd_subr.h>
#include <fmd_event.h>
#include <fmd.h>

typedef struct fmd_rtld {
	void *rtld_dlp;		/* libdl handle for shared library */
	void (*rtld_init)(fmd_hdl_t *); /* shared library's _fmd_init() */
	void (*rtld_fini)(fmd_hdl_t *); /* shared library's _fmd_fini() */
} fmd_rtld_t;

static int
rtld_init(fmd_module_t *mp)
{
	fmd_rtld_t *rp;
	void *dlp;

	if ((dlp = dlopen(mp->mod_path, RTLD_LOCAL | RTLD_NOW)) == NULL) {
		fmd_error(EFMD_RTLD_OPEN, "%s\n", dlerror());
		return (fmd_set_errno(EFMD_RTLD_OPEN));
	}

	rp = mp->mod_data = fmd_alloc(sizeof (fmd_rtld_t), FMD_SLEEP);

	rp->rtld_dlp = dlp;
	rp->rtld_init = (void (*)())dlsym(dlp, "_fmd_init");
	rp->rtld_fini = (void (*)())dlsym(dlp, "_fmd_fini");

	if (rp->rtld_init == NULL) {
		(void) dlclose(dlp);
		fmd_free(rp, sizeof (fmd_rtld_t));
		return (fmd_set_errno(EFMD_RTLD_INIT));
	}

	(void) pthread_mutex_unlock(&mp->mod_lock);

	/*
	 * Call _fmd_init() in the module.  If this causes a module abort and
	 * mod_info has been registered, unregister it on behalf of the module.
	 */
	if (fmd_module_enter(mp, rp->rtld_init) != 0 && mp->mod_info != NULL)
		fmd_hdl_unregister((fmd_hdl_t *)mp);

	fmd_module_exit(mp);
	(void) pthread_mutex_lock(&mp->mod_lock);

	if (mp->mod_info == NULL) {
		(void) dlclose(dlp);
		fmd_free(rp, sizeof (fmd_rtld_t));
		return (fmd_set_errno(EFMD_HDL_INIT));
	}

	return (0);
}

static int
rtld_fini(fmd_module_t *mp)
{
	fmd_rtld_t *rp = mp->mod_data;
	int doclose = 1, err = 0;

	if (mp->mod_info != NULL) {
		(void) fmd_module_enter(mp, rp->rtld_fini);

		if (mp->mod_info != NULL) {
			fmd_module_lock(mp);
			fmd_module_unregister(mp);
			fmd_module_unlock(mp);
		}

		fmd_module_exit(mp);
	}

	(void) fmd_conf_getprop(fmd.d_conf, "plugin.close", &doclose);
	if (doclose)
		err = dlclose(rp->rtld_dlp);

	fmd_free(rp, sizeof (fmd_rtld_t));
	return (err);
}

const fmd_modops_t fmd_rtld_ops = {
	rtld_init,
	rtld_fini,
	fmd_module_dispatch,
	fmd_module_transport,
};
