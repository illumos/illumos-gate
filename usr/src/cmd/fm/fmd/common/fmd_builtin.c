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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fmd_module.h>
#include <fmd_subr.h>
#include <fmd_error.h>
#include <fmd_string.h>
#include <fmd_event.h>
#include <fmd_builtin.h>

static const struct fmd_builtin _fmd_builtins[] = {
	{ "fmd-self-diagnosis", self_init, self_fini },
	{ "sysevent-transport", sysev_init, sysev_fini },
	{ NULL, NULL, NULL }
};

static int
bltin_init(fmd_module_t *mp)
{
	const fmd_builtin_t *bp;

	for (bp = _fmd_builtins; bp->bltin_name != NULL; bp++) {
		if (strcmp(mp->mod_name, bp->bltin_name) == 0)
			break;
	}

	if (bp == NULL)
		return (fmd_set_errno(EFMD_BLTIN_NAME));

	if (bp->bltin_init == NULL)
		return (fmd_set_errno(EFMD_BLTIN_INIT));

	mp->mod_data = (void *)bp;
	(void) pthread_mutex_unlock(&mp->mod_lock);

	/*
	 * Call _fmd_init() in the module.  If this causes a module abort and
	 * mod_info has been registered, unregister it on behalf of the module.
	 */
	if (fmd_module_enter(mp, bp->bltin_init) != 0 && mp->mod_info != NULL)
		fmd_hdl_unregister((fmd_hdl_t *)mp);

	fmd_module_exit(mp);
	(void) pthread_mutex_lock(&mp->mod_lock);

	if (mp->mod_info == NULL)
		return (fmd_set_errno(EFMD_HDL_INIT));

	return (0);
}

static int
bltin_fini(fmd_module_t *mp)
{
	fmd_builtin_t *bp = mp->mod_data;

	if (mp->mod_info != NULL) {
		(void) fmd_module_enter(mp, bp->bltin_fini);

		if (mp->mod_info != NULL) {
			fmd_module_lock(mp);
			fmd_module_unregister(mp);
			fmd_module_unlock(mp);
		}

		fmd_module_exit(mp);
	}

	return (0);
}

const fmd_modops_t fmd_bltin_ops = {
	bltin_init,
	bltin_fini,
	fmd_module_dispatch,
	fmd_module_transport,
};

int
fmd_builtin_loadall(fmd_modhash_t *mhp)
{
	const fmd_builtin_t *bp;
	int err = 0;

	for (bp = _fmd_builtins; bp->bltin_name != NULL; bp++) {
		if (fmd_modhash_load(mhp, bp->bltin_name,
		    &fmd_bltin_ops) == NULL)
			err = -1;
	}

	return (err);
}
