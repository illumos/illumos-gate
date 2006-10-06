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

#include <errno.h>
#include <kstat.h>
#include <limits.h>
#include <strings.h>
#include <unistd.h>
#include <fm/topo_mod.h>
#include <sys/fm/protocol.h>

#include <topo_error.h>

static int mem_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *);
static void mem_release(topo_mod_t *, tnode_t *);
static int mem_nvl2str(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int mem_str2nvl(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int mem_present(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int mem_contains(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int mem_unusable(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int mem_expand(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);

#define	MEM_VERSION	TOPO_VERSION

static const topo_method_t mem_methods[] = {
	{ TOPO_METH_NVL2STR, TOPO_METH_NVL2STR_DESC, TOPO_METH_NVL2STR_VERSION,
	    TOPO_STABILITY_INTERNAL, mem_nvl2str },
	{ TOPO_METH_STR2NVL, TOPO_METH_STR2NVL_DESC, TOPO_METH_STR2NVL_VERSION,
	    TOPO_STABILITY_INTERNAL, mem_str2nvl },
	{ TOPO_METH_PRESENT, TOPO_METH_PRESENT_DESC, TOPO_METH_PRESENT_VERSION,
	    TOPO_STABILITY_INTERNAL, mem_present },
	{ TOPO_METH_CONTAINS, TOPO_METH_CONTAINS_DESC,
	    TOPO_METH_CONTAINS_VERSION, TOPO_STABILITY_INTERNAL, mem_contains },
	{ TOPO_METH_UNUSABLE, TOPO_METH_UNUSABLE_DESC,
	    TOPO_METH_UNUSABLE_VERSION, TOPO_STABILITY_INTERNAL, mem_unusable },
	{ TOPO_METH_EXPAND, TOPO_METH_UNUSABLE_DESC,
	    TOPO_METH_EXPAND_VERSION, TOPO_STABILITY_INTERNAL, mem_expand },
	{ NULL }
};

static const topo_modinfo_t mem_info =
	{ "mem", MEM_VERSION, mem_enum, mem_release };

void
mem_init(topo_mod_t *mod)
{

	topo_mod_setdebug(mod, TOPO_DBG_ALL);
	topo_mod_dprintf(mod, "initializing mem builtin\n");

	if (topo_mod_register(mod, &mem_info, NULL) != 0) {
		topo_mod_dprintf(mod, "failed to register mem_info: "
		    "%s\n", topo_mod_errmsg(mod));
		return;
	}
}

void
mem_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}

/*ARGSUSED*/
static int
mem_enum(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *arg)
{
	(void) topo_method_register(mod, pnode, mem_methods);

	return (0);
}

static void
mem_release(topo_mod_t *mod, tnode_t *node)
{
	topo_method_unregister_all(mod, node);
}

/*ARGSUSED*/
static int
mem_nvl2str(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	const char *format;
	nvlist_t *nvl;
	uint64_t val;
	char *buf, *unum;
	size_t len;
	int err;

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	if (nvlist_lookup_string(in, FM_FMRI_MEM_UNUM, &unum) != 0) {
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	/*
	 * If we have a DIMM offset, include it in the string.  If we have a
	 * PA then use that.  Otherwise just format the unum element.
	 */
	if (nvlist_lookup_uint64(nvl, FM_FMRI_MEM_OFFSET, &val) == 0) {
		format = FM_FMRI_SCHEME_MEM ":///%1$s/"
		    FM_FMRI_MEM_OFFSET "=%2$llx";
	} else if (nvlist_lookup_uint64(nvl, FM_FMRI_MEM_PHYSADDR, &val) == 0) {
		format = FM_FMRI_SCHEME_MEM ":///%1$s/"
		    FM_FMRI_MEM_PHYSADDR "=%2$llx";
	} else
		format = FM_FMRI_SCHEME_MEM ":///" "%1$s";

	/*
	 * If we have a well-formed unum we step over the hc:/// prefix
	 */
	if (strncmp(unum, "hc:///", 6) == 0)
		unum += 6;

	len = snprintf(NULL, 0, format, unum, val) + 1;
	buf = topo_mod_zalloc(mod, len);

	if (buf == NULL) {
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	(void) snprintf(buf, len, format, unum, val);
	err = nvlist_add_string(nvl, "fmri-string", buf);
	topo_mod_free(mod, buf, len);

	if (err != 0) {
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	*out = nvl;
	return (0);
}

/*ARGSUSED*/
static int
mem_str2nvl(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	return (-1);
}

/*ARGSUSED*/
static int
mem_present(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	return (-1);
}

/*ARGSUSED*/
static int
mem_contains(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	return (-1);
}

/*ARGSUSED*/
static int
mem_unusable(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	return (-1);
}

/*ARGSUSED*/
static int
mem_expand(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	return (-1);
}
