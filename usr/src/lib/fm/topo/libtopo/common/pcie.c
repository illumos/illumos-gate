/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

/*
 * This provides the basic mechanisms for dealing with the pcie schema. A pcie
 * FMRI has the form:
 *
 *     pcie:///cpu=C[/root-complex=R[function=F[...]]]
 *
 * That is to say that the top level nodes represent physical CPUs in the
 * system and their PCIe root complexes are enumerated directly under that.
 *
 * Each node inherits the FMRI of its parent, and then appends a new
 * '/<type>=<instance>' part, for example:
 *
 *     pcie:///cpu=0
 *     pcie:///cpu=0/root-complex=0
 *     pcie:///cpu=0/root-complex=0/function=0
 *     pcie:///cpu=0/root-complex=0/function=0/port=0
 *
 * Types used in the scheme are:
 *	cpu
 *	root-complex
 *	device
 *	function
 *	port
 *	link
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
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
#include <pthread.h>

#include <pcie.h>

static size_t
fmri_nvl2str(nvlist_t *nvl, char *buf, size_t buflen)
{
	size_t size = 0;
	uint8_t version;
	nvlist_t **plist;
	uint_t nplist;
	int err;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_PCIE_SCHEME_VERSION) {
		return (0);
	}

	if (!topo_fmristr_build(&size, buf, buflen, FM_FMRI_SCHEME_PCIE, NULL,
	    ":///")) {
		return (0);
	}

	err = nvlist_lookup_nvlist_array(nvl, FM_FMRI_PCIE_LIST,
	    &plist, &nplist);
	if (err != 0 || plist == NULL)
		return (0);

	for (uint_t i = 0; i < nplist; i++) {
		char *name = NULL;
		char *id = NULL;

		if (i > 0) {
			if (!topo_fmristr_build(&size, buf, buflen, "/", NULL,
			    NULL)) {
				return (0);
			}
		}
		if (nvlist_lookup_string(plist[i],
		    FM_FMRI_PCIE_NAME, &name) != 0 ||
		    nvlist_lookup_string(plist[i],
		    FM_FMRI_PCIE_ID, &id) != 0) {
			return (0);
		}
		if (name == NULL || id == NULL)
			return (0);
		if (!topo_fmristr_build(&size, buf, buflen, "=", name, id))
			return (0);
	}

	return (size);
}

static int
pcie_fmri_nvl2str(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *nvl, nvlist_t **out)
{
	size_t len;
	char *name = NULL;
	nvlist_t *fmristr;

	if (version > TOPO_METH_NVL2STR_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if ((len = fmri_nvl2str(nvl, NULL, 0)) == 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	if ((name = topo_mod_alloc(mod, len + 1)) == NULL)
		return (topo_mod_seterrno(mod, EMOD_NOMEM));

	if (fmri_nvl2str(nvl, name, len + 1) == 0) {
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

static nvlist_t *
fmri_create_err(topo_mod_t *mod, nvlist_t **list, uint_t elems,
    nvlist_t *fmri, int err)
{
	if (list != NULL) {
		for (uint_t i = 0; i < elems; i++)
			nvlist_free(list[i]);

		topo_mod_free(mod, list, sizeof (nvlist_t *) * elems);
	}

	nvlist_free(fmri);

	(void) topo_mod_seterrno(mod, err);

	topo_mod_dprintf(mod, "unable to create pcie FMRI: %s\n",
	    topo_mod_errmsg(mod));

	return (NULL);
}

static nvlist_t *
fmri_create_component(topo_mod_t *mod, const char *name, topo_instance_t inst)
{
	char str[21]; /* decimal representation of UINT64_MAX + '\0' */
	nvlist_t *comp;

	if (topo_mod_nvalloc(mod, &comp, NV_UNIQUE_NAME) != 0)
		return (NULL);

	(void) snprintf(str, sizeof (str), "%" PRIu64, inst);

	if (nvlist_add_string(comp, FM_FMRI_PCIE_NAME, name) != 0 ||
	    nvlist_add_string(comp, FM_FMRI_PCIE_ID, str) != 0) {
		nvlist_free(comp);
		return (NULL);
	}

	return (comp);
}

static nvlist_t *
fmri_create(topo_mod_t *mod, nvlist_t *pfmri, const char *name,
    topo_instance_t inst, nvlist_t *auth)
{
	nvlist_t **pplist = NULL;
	nvlist_t **plist = NULL;
	nvlist_t *fmri = NULL;
	uint_t pelems = 0, elems;
	uint_t i;

	/*
	 * This FMRI will be constructed from the FMRI of the parent, with a
	 * new path component (name=inst) after it. We copy the parent's
	 * property list to this node, and then add our new property to the
	 * end.
	 */

	/* Retrieve the parent's property list */
	if (pfmri != NULL) {
		if (nvlist_lookup_nvlist_array(pfmri, FM_FMRI_PCIE_LIST,
		    &pplist, &pelems) != 0) {
			return (fmri_create_err(mod, plist, pelems, fmri,
			    EMOD_FMRI_MALFORM));
		}
	}

	/* We want space for an extra entry in the new FMRI's property list */
	elems = pelems + 1;

	plist = topo_mod_zalloc(mod, sizeof (nvlist_t *) * elems);
	if (plist == NULL) {
		return (fmri_create_err(mod, plist, elems, fmri,
		    ETOPO_FMRI_NOMEM));
	}

	/* Copy the parent properties */
	for (i = 0; i < pelems; i++) {
		if (topo_mod_nvdup(mod, pplist[i], &plist[i]) != 0) {
			return (fmri_create_err(mod, plist, elems, fmri,
			    EMOD_FMRI_NVL));
		}
	}

	/* Add the new path component */
	if ((plist[i] = fmri_create_component(mod, name, inst)) == NULL) {
		return (fmri_create_err(mod, plist, elems, fmri,
		    EMOD_FMRI_NVL));
	}

	/* Create the fmri */
	if (topo_mod_nvalloc(mod, &fmri, NV_UNIQUE_NAME) != 0) {
		return (fmri_create_err(mod, plist, elems, fmri,
		    EMOD_FMRI_NVL));
	}

	if (nvlist_add_uint8(fmri, FM_VERSION, FM_PCIE_SCHEME_VERSION) ||
	    nvlist_add_string(fmri, FM_FMRI_SCHEME, FM_FMRI_SCHEME_PCIE)) {
		return (fmri_create_err(mod, plist, elems, fmri,
		    EMOD_FMRI_NVL));
	}

	/* Add the new property list */
	if (nvlist_add_nvlist_array(fmri, FM_FMRI_PCIE_LIST,
	    plist, elems) != 0) {
		return (fmri_create_err(mod, plist, elems, fmri,
		    EMOD_FMRI_NVL));
	}

	if (auth != NULL)
		(void) nvlist_add_nvlist(fmri, FM_FMRI_AUTHORITY, auth);

	if (plist != NULL) {
		for (uint_t i = 0; i < elems; i++)
			nvlist_free(plist[i]);
		topo_mod_free(mod, plist, sizeof (nvlist_t *) * elems);
	}

	return (fmri);
}

static int
pcie_fmri_create_meth(topo_mod_t *mod, tnode_t *tnode, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	char *name;
	topo_instance_t inst;
	nvlist_t *args, *auth = NULL, *pfmri = NULL;
	int ret;

	if (version > TOPO_METH_FMRI_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_string(in, TOPO_METH_FMRI_ARG_NAME, &name) != 0 ||
	    nvlist_lookup_uint64(in, TOPO_METH_FMRI_ARG_INST, &inst) != 0) {
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));
	}

	if ((ret = nvlist_lookup_nvlist(in, TOPO_METH_FMRI_ARG_NVL,
	    &args)) != 0) {
		if (ret != ENOENT)
			return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));
	} else {
		(void) nvlist_lookup_nvlist(args, TOPO_METH_FMRI_ARG_PARENT,
		    &pfmri);
		(void) nvlist_lookup_nvlist(args, TOPO_METH_FMRI_ARG_AUTH,
		    &auth);
	}

	*out = fmri_create(mod, pfmri, name, inst, auth);
	if (*out == NULL)
		return (-1);

	return (0);
}

const topo_method_t pcie_methods[] = {
	{
		.tm_name = TOPO_METH_NVL2STR,
		.tm_desc = TOPO_METH_NVL2STR_DESC,
		.tm_version = TOPO_METH_NVL2STR_VERSION,
		.tm_stability = TOPO_STABILITY_INTERNAL,
		.tm_func = pcie_fmri_nvl2str
	},
	{
		.tm_name = TOPO_METH_FMRI,
		.tm_desc = TOPO_METH_FMRI_DESC,
		.tm_version = TOPO_METH_FMRI_VERSION,
		.tm_stability = TOPO_STABILITY_INTERNAL,
		.tm_func = pcie_fmri_create_meth
	},
	{ NULL }
};

int
pcie_enum(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *u1 __unused,
    void *u2 __unused)
{
	topo_mod_dprintf(mod, "enumerating pcie: %s (%"PRIu64" - %"PRIu64")",
	    name, min, max);

	(void) topo_method_register(mod, pnode, pcie_methods);
	return (0);
}

static void
pcie_rele(topo_mod_t *mp, tnode_t *node)
{
	topo_method_unregister_all(mp, node);
}

static const topo_modops_t pcie_ops = {
	.tmo_enum = pcie_enum,
	.tmo_release = pcie_rele
};

static const topo_modinfo_t pcie_info = {
	.tmi_desc = PCIE,
	.tmi_scheme = FM_FMRI_SCHEME_PCIE,
	.tmi_version = PCIE_VERSION,
	.tmi_ops = &pcie_ops
};

int
pcie_init(topo_mod_t *mod, topo_version_t version)
{
	if (getenv("TOPOPCIEDEBUG"))
		topo_mod_setdebug(mod);

	topo_mod_dprintf(mod, "initializing pcie builtin");

	if (version != PCIE_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (topo_mod_register(mod, &pcie_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "failed to register pcie: %s",
		    topo_mod_errmsg(mod));
		return (-1); /* mod errno already set */
	}

	return (0);
}

void
pcie_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}
