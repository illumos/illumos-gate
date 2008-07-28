/*
 *
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <alloca.h>
#include <limits.h>
#include <fm/topo_mod.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <sys/fm/protocol.h>
#include <sys/stat.h>

#include <topo_method.h>
#include <topo_subr.h>
#include <fmd.h>

static int fmd_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *, void *);
static void fmd_release(topo_mod_t *, tnode_t *);
static int fmd_fmri_nvl2str(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

const topo_method_t fmd_methods[] = {
	{ TOPO_METH_NVL2STR, TOPO_METH_NVL2STR_DESC, TOPO_METH_NVL2STR_VERSION,
	    TOPO_STABILITY_INTERNAL, fmd_fmri_nvl2str },
	{ NULL }
};

static const topo_modops_t fmd_ops =
	{ fmd_enum, fmd_release };
static const topo_modinfo_t fmd_info =
	{ FMD, FM_FMRI_SCHEME_FMD, FMD_VERSION, &fmd_ops };

int
fmd_init(topo_mod_t *mod, topo_version_t version)
{
	/*
	 * Turn on module debugging output
	 */
	if (getenv("TOPOFMDDEBUG"))
		topo_mod_setdebug(mod);

	topo_mod_dprintf(mod, "initializing fmd builtin\n");

	if (version != FMD_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (topo_mod_register(mod, &fmd_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "failed to register fmd: "
		    "%s\n", topo_mod_errmsg(mod));
		return (-1); /* mod errno already set */
	}

	return (0);
}

void
fmd_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}


/*ARGSUSED*/
int
fmd_enum(topo_mod_t *mod, tnode_t *pnode, const char *name, topo_instance_t min,
    topo_instance_t max, void *notused1, void *notused2)
{
	(void) topo_method_register(mod, pnode, fmd_methods);
	return (0);
}

/*ARGSUSED*/
static void
fmd_release(topo_mod_t *mp, tnode_t *node)
{
	topo_method_unregister_all(mp, node);
}

static ssize_t
fmri_nvl2str(nvlist_t *nvl, char *buf, size_t buflen)
{
	char *name;

	if (nvlist_lookup_string(nvl, FM_FMRI_FMD_NAME, &name) != 0)
		return (0);

	return (snprintf(buf, buflen,
	    "%s:///module/%s", FM_FMRI_SCHEME_FMD, name));
}

/*ARGSUSED*/
static int
fmd_fmri_nvl2str(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *nvl, nvlist_t **out)
{
	ssize_t len;
	char *name = NULL;
	nvlist_t *fmristr;

	if (version > TOPO_METH_NVL2STR_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if ((len = fmri_nvl2str(nvl, NULL, 0)) == 0 ||
	    (name = topo_mod_alloc(mod, len + 1)) == NULL ||
	    fmri_nvl2str(nvl, name, len + 1) == 0) {
		if (name != NULL)
			topo_mod_free(mod, name, len + 1);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	if (topo_mod_nvalloc(mod, &fmristr, NV_UNIQUE_NAME) != 0) {
		topo_mod_free(mod, name, len + 1);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}
	if (nvlist_add_string(fmristr, "fmri-string", name) != 0) {
		topo_mod_free(mod, name, len + 1);
		nvlist_free(fmristr);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}
	topo_mod_free(mod, name, len + 1);
	*out = fmristr;

	return (0);
}
