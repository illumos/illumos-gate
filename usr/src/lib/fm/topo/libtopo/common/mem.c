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

#include <topo_method.h>
#include <mem.h>

static int mem_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *, void *);
static void mem_release(topo_mod_t *, tnode_t *);
static int mem_nvl2str(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int mem_fmri_create(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

static const topo_method_t mem_methods[] = {
	{ TOPO_METH_NVL2STR, TOPO_METH_NVL2STR_DESC, TOPO_METH_NVL2STR_VERSION,
	    TOPO_STABILITY_INTERNAL, mem_nvl2str },
	{ TOPO_METH_FMRI, TOPO_METH_FMRI_DESC, TOPO_METH_FMRI_VERSION,
	    TOPO_STABILITY_INTERNAL, mem_fmri_create },
	{ NULL }
};

static const topo_modops_t mem_ops =
	{ mem_enum, mem_release };
static const topo_modinfo_t mem_info =
	{ "mem", FM_FMRI_SCHEME_MEM, MEM_VERSION, &mem_ops };

int
mem_init(topo_mod_t *mod, topo_version_t version)
{

	topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "initializing mem builtin\n");

	if (version != MEM_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (topo_mod_register(mod, &mem_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "failed to register mem_info: "
		    "%s\n", topo_mod_errmsg(mod));
		return (-1); /* mod errno already set */
	}

	return (0);
}

void
mem_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}

/*ARGSUSED*/
static int
mem_enum(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *notused1, void *notused2)
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
	if (nvlist_lookup_uint64(in, FM_FMRI_MEM_OFFSET, &val) == 0) {
		format = FM_FMRI_SCHEME_MEM ":///%1$s/"
		    FM_FMRI_MEM_OFFSET "=%2$llx";
	} else if (nvlist_lookup_uint64(in, FM_FMRI_MEM_PHYSADDR, &val) == 0) {
		format = FM_FMRI_SCHEME_MEM ":///%1$s/"
		    FM_FMRI_MEM_PHYSADDR "=%2$llx";
	} else
		format = FM_FMRI_SCHEME_MEM ":///" "%1$s";

	/*
	 * If we have a well-formed unum we step over the hc:// and
	 * authority prefix
	 */
	if (strncmp(unum, "hc://", 5) == 0) {
		unum += 5;
		unum = strchr(unum, '/');
		++unum;
	}

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

static nvlist_t *
mem_fmri(topo_mod_t *mod, uint64_t pa, uint64_t offset, char *unum, int flags)
{
	int err;
	nvlist_t *asru;

	if (topo_mod_nvalloc(mod, &asru, NV_UNIQUE_NAME) != 0)
		return (NULL);

	/*
	 * If we have a well-formed unum we step over the hc:/// and
	 * authority prefix
	 */
	if (strncmp(unum, "hc://", 5) == 0) {
		char *tstr;

		tstr = strchr(unum, '/');
		unum = ++tstr;
	}

	err = nvlist_add_uint8(asru, FM_VERSION, FM_MEM_SCHEME_VERSION);
	err |= nvlist_add_string(asru, FM_FMRI_SCHEME, FM_FMRI_SCHEME_MEM);
	err |= nvlist_add_string(asru, FM_FMRI_MEM_UNUM, unum);
	if (flags & TOPO_MEMFMRI_PA)
		err |= nvlist_add_uint64(asru, FM_FMRI_MEM_PHYSADDR, pa);
	if (flags & TOPO_MEMFMRI_OFFSET)
		err |= nvlist_add_uint64(asru, FM_FMRI_MEM_OFFSET, offset);

	if (err != 0) {
		nvlist_free(asru);
		return (NULL);
	}

	return (asru);
}

/*ARGSUSED*/
static int
mem_fmri_create(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	uint64_t pa = 0, offset = 0;
	int flags = 0;
	nvlist_t *asru;
	char *unum;

	if (nvlist_lookup_uint64(in, FM_FMRI_MEM_PHYSADDR, &pa) == 0)
		flags |= TOPO_MEMFMRI_PA;
	if (nvlist_lookup_uint64(in, FM_FMRI_MEM_OFFSET, &offset) == 0)
		flags |= TOPO_MEMFMRI_OFFSET;
	if (nvlist_lookup_string(in, FM_FMRI_MEM_UNUM, &unum) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));

	asru = mem_fmri(mod, pa, offset, unum, flags);

	if (asru == NULL)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	*out = asru;

	return (0);
}
