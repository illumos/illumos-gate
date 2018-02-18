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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Topology Plugin Modules
 *
 * Topology plugin modules are shared libraries that are dlopen'd and
 * used to enumerate resources in the system and export per-node method
 * operations.
 *
 * They are loaded by our builtin scheme-specific plugins, other modules or
 * by processing a topo map XML file to enumerate and create nodes for
 * resources that are present in the system.  They may also export a set of
 * topology node specific methods that can be invoked directly via
 * topo_method_invoke() or indirectly via the
 * topo_prop_get* family of functions to access dynamic property data.
 *
 * Module Plugin API
 *
 * Enumerators must provide entry points for initialization and clean-up
 * (_topo_init() and _topo_fini()).  In their _topo_init() function, an
 * enumerator should register (topo_mod_register()) its enumeration callback
 * and allocate resources required for a subsequent call to the callback.
 * Optionally, methods may also be registered with topo_method_register().
 *
 * In its enumeration callback routine, the module should search for resources
 * within its realm of responsibility and create any node ranges,
 * topo_node_range_create() and nodes, topo_node_bind().  The Enumerator
 * module is handed a node to which it may begin attaching additional
 * topology nodes.  The enumerator may only access those nodes within its
 * current scope of operation: the node passed into its enumeration op and
 * any nodes it creates during enumeration.  If the enumerator requires walker-
 * style access to these nodes, it must use
 * topo_mod_walk_init()/topo_walk_step()/topo_walk_fini().
 *
 * If additional helper modules need to be loaded to complete the enumeration
 * the module may do so by calling topo_mod_load().  Enumeration may then
 * continue with the module handing off enumeration to its helper module
 * by calling topo_mod_enumerate().  Similarly, a module may call
 * topo_mod_enummap() to kick-off enumeration according to a given XML
 * topology map file.  A module *may* not cause re-entrance to itself
 * via either of these interfaces.  If re-entry is detected an error
 * will be returned (ETOPO_ENUM_RECURS).
 *
 * If the module registers a release callback, it will be called on a node
 * by node basis during topo_snap_rele().  Any private node data may be
 * deallocated or methods unregistered at that time.  Global module data
 * should be cleaned up before or at the time that the module _topo_fini
 * entry point is called.
 *
 * Module entry points and method invocations are guaranteed to be
 * single-threaded for a given snapshot handle.  Applications may have
 * more than one topology snapshot open at a time.  This means that the
 * module operations and methods may be called for different module handles
 * (topo_mod_t) asynchronously.  The enumerator should not use static or
 * global data structures that may become inconsistent in this situation.
 * Method operations may be re-entrant if the module invokes one of its own
 * methods directly or via dynamic property access.  Caution should be
 * exercised with method operations to insure that data remains consistent
 * within the module and that deadlocks can not occur.
 */

#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <alloca.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <pcidb.h>
#include <sys/param.h>
#include <sys/utsname.h>
#include <sys/smbios.h>
#include <sys/fm/protocol.h>

#include <topo_alloc.h>
#include <topo_error.h>
#include <topo_file.h>
#include <topo_fmri.h>
#include <topo_module.h>
#include <topo_method.h>
#include <topo_string.h>
#include <topo_subr.h>
#include <topo_tree.h>

#define	PLUGIN_PATH	"plugins"
#define	PLUGIN_PATH_LEN	MAXNAMELEN + 5

topo_mod_t *
topo_mod_load(topo_mod_t *pmod, const char *name,
    topo_version_t version)
{
	char *path;
	char file[PLUGIN_PATH_LEN];
	topo_mod_t *mod = NULL;
	topo_hdl_t *thp;

	thp = pmod->tm_hdl;

	/*
	 * Already loaded, topo_mod_lookup will bump the ref count
	 */
	if ((mod = topo_mod_lookup(thp, name, 1)) != NULL) {
		if (mod->tm_info->tmi_version != version) {
			topo_mod_rele(mod);
			(void) topo_mod_seterrno(pmod, ETOPO_MOD_VER);
			return (NULL);
		}
		return (mod);
	}

	(void) snprintf(file, PLUGIN_PATH_LEN, "%s/%s.so",
	    PLUGIN_PATH, name);
	path = topo_search_path(pmod, thp->th_rootdir, (const char *)file);
	if (path == NULL ||
	    (mod = topo_modhash_load(thp, name, path, &topo_rtld_ops, version))
	    == NULL) { /* returned with mod held */
			topo_mod_strfree(pmod, path);
			(void) topo_mod_seterrno(pmod, topo_hdl_errno(thp) ?
			    topo_hdl_errno(thp) : ETOPO_MOD_NOENT);
			return (NULL);
	}

	topo_mod_strfree(pmod, path);

	return (mod);
}

void
topo_mod_unload(topo_mod_t *mod)
{
	topo_mod_rele(mod);
}

static int
set_register_error(topo_mod_t *mod, int err)
{
	if (mod->tm_info != NULL)
		topo_mod_unregister(mod);

	topo_dprintf(mod->tm_hdl, TOPO_DBG_ERR,
	    "module registration failed for %s: %s\n",
	    mod->tm_name, topo_strerror(err));

	return (topo_mod_seterrno(mod, err));
}

int
topo_mod_register(topo_mod_t *mod, const topo_modinfo_t *mip,
    topo_version_t version)
{

	assert(!(mod->tm_flags & TOPO_MOD_FINI ||
	    mod->tm_flags & TOPO_MOD_REG));

	if (version != TOPO_VERSION)
		return (set_register_error(mod, EMOD_VER_ABI));

	if ((mod->tm_info = topo_mod_zalloc(mod, sizeof (topo_imodinfo_t)))
	    == NULL)
		return (set_register_error(mod, EMOD_NOMEM));
	if ((mod->tm_info->tmi_ops = topo_mod_alloc(mod,
	    sizeof (topo_modops_t))) == NULL)
		return (set_register_error(mod, EMOD_NOMEM));

	mod->tm_info->tmi_desc = topo_mod_strdup(mod, mip->tmi_desc);
	if (mod->tm_info->tmi_desc == NULL)
		return (set_register_error(mod, EMOD_NOMEM));

	mod->tm_info->tmi_scheme = topo_mod_strdup(mod, mip->tmi_scheme);
	if (mod->tm_info->tmi_scheme == NULL)
		return (set_register_error(mod, EMOD_NOMEM));


	mod->tm_info->tmi_version = (topo_version_t)mip->tmi_version;
	mod->tm_info->tmi_ops->tmo_enum = mip->tmi_ops->tmo_enum;
	mod->tm_info->tmi_ops->tmo_release = mip->tmi_ops->tmo_release;

	mod->tm_flags |= TOPO_MOD_REG;

	topo_dprintf(mod->tm_hdl, TOPO_DBG_MODSVC,
	    "registration succeeded for %s\n", mod->tm_name);

	return (0);
}

void
topo_mod_unregister(topo_mod_t *mod)
{
	if (mod->tm_info == NULL)
		return;

	assert(!(mod->tm_flags & TOPO_MOD_FINI));

	mod->tm_flags &= ~TOPO_MOD_REG;

	if (mod->tm_info == NULL)
		return;

	if (mod->tm_info->tmi_ops != NULL)
		topo_mod_free(mod, mod->tm_info->tmi_ops,
		    sizeof (topo_modops_t));
	if (mod->tm_info->tmi_desc != NULL)
		topo_mod_strfree(mod, mod->tm_info->tmi_desc);
	if (mod->tm_info->tmi_scheme != NULL)
		topo_mod_strfree(mod, mod->tm_info->tmi_scheme);

	topo_mod_free(mod, mod->tm_info, sizeof (topo_imodinfo_t));

	mod->tm_info = NULL;
}

int
topo_mod_enumerate(topo_mod_t *mod, tnode_t *node, const char *enum_name,
    const char *name, topo_instance_t min, topo_instance_t max, void *data)
{
	int err = 0;
	topo_mod_t *enum_mod;

	assert(mod->tm_flags & TOPO_MOD_REG);

	if ((enum_mod = topo_mod_lookup(mod->tm_hdl, enum_name, 0)) == NULL)
		return (topo_mod_seterrno(mod, EMOD_MOD_NOENT));

	topo_node_hold(node);

	topo_dprintf(mod->tm_hdl, TOPO_DBG_MODSVC, "module %s enumerating "
	    "node %s=%d\n", (char *)mod->tm_name, (char *)node->tn_name,
	    node->tn_instance);

	topo_mod_enter(enum_mod);
	err = enum_mod->tm_info->tmi_ops->tmo_enum(enum_mod, node, name, min,
	    max, enum_mod->tm_priv, data);
	topo_mod_exit(enum_mod);

	if (err != 0) {
		(void) topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);

		topo_dprintf(mod->tm_hdl, TOPO_DBG_ERR,
		    "module %s failed enumeration for "
		    " node %s=%d\n", (char *)mod->tm_name,
		    (char *)node->tn_name, node->tn_instance);

		topo_node_rele(node);
		return (-1);
	}

	topo_node_rele(node);

	return (0);
}

int
topo_mod_enummap(topo_mod_t *mod, tnode_t *node, const char *name,
    const char *scheme)
{
	return (topo_file_load(mod, node, (char *)name, (char *)scheme, 0));
}

static nvlist_t *
set_fmri_err(topo_mod_t *mod, int err)
{
	(void) topo_mod_seterrno(mod, err);
	return (NULL);
}

nvlist_t *
topo_mod_hcfmri(topo_mod_t *mod, tnode_t *pnode, int version, const char *name,
    topo_instance_t inst, nvlist_t *hc_specific, nvlist_t *auth,
    const char *part, const char *rev, const char *serial)
{
	int err;
	nvlist_t *pfmri = NULL, *fmri = NULL, *args = NULL;
	nvlist_t *nfp = NULL;
	char *lpart, *lrev, *lserial;

	if (version != FM_HC_SCHEME_VERSION)
		return (set_fmri_err(mod, EMOD_FMRI_VERSION));

	/*
	 * Do we have any args to pass?
	 */
	if (pnode != NULL || auth != NULL || part != NULL || rev != NULL ||
	    serial != NULL || hc_specific != NULL) {
		if (topo_mod_nvalloc(mod, &args, NV_UNIQUE_NAME) != 0)
			return (set_fmri_err(mod, EMOD_FMRI_NVL));
	}

	if (pnode != NULL) {
		if (topo_node_resource(pnode, &pfmri, &err) < 0) {
			nvlist_free(args);
			return (set_fmri_err(mod, EMOD_NVL_INVAL));
		}

		if (nvlist_add_nvlist(args, TOPO_METH_FMRI_ARG_PARENT,
		    pfmri) != 0) {
			nvlist_free(pfmri);
			nvlist_free(args);
			return (set_fmri_err(mod, EMOD_FMRI_NVL));
		}
		nvlist_free(pfmri);
	}

	/*
	 * Add optional payload
	 */
	if (auth != NULL)
		(void) nvlist_add_nvlist(args, TOPO_METH_FMRI_ARG_AUTH, auth);
	if (part != NULL) {
		lpart = topo_cleanup_auth_str(mod->tm_hdl, part);
		if (lpart != NULL) {
			(void) nvlist_add_string(args, TOPO_METH_FMRI_ARG_PART,
			    lpart);
			topo_hdl_free(mod->tm_hdl, lpart, strlen(lpart) + 1);
		} else {
			(void) nvlist_add_string(args, TOPO_METH_FMRI_ARG_PART,
			    "");
		}
	}
	if (rev != NULL) {
		lrev = topo_cleanup_auth_str(mod->tm_hdl, rev);
		if (lrev != NULL) {
			(void) nvlist_add_string(args, TOPO_METH_FMRI_ARG_REV,
			    lrev);
			topo_hdl_free(mod->tm_hdl, lrev, strlen(lrev) + 1);
		} else {
			(void) nvlist_add_string(args, TOPO_METH_FMRI_ARG_REV,
			    "");
		}
	}
	if (serial != NULL) {
		lserial = topo_cleanup_auth_str(mod->tm_hdl, serial);
		if (lserial != NULL) {
			(void) nvlist_add_string(args, TOPO_METH_FMRI_ARG_SER,
			    lserial);
			topo_hdl_free(mod->tm_hdl, lserial,
			    strlen(lserial) + 1);
		} else {
			(void) nvlist_add_string(args, TOPO_METH_FMRI_ARG_SER,
			    "");
		}
	}
	if (hc_specific != NULL)
		(void) nvlist_add_nvlist(args, TOPO_METH_FMRI_ARG_HCS,
		    hc_specific);

	if ((fmri = topo_fmri_create(mod->tm_hdl, FM_FMRI_SCHEME_HC, name, inst,
	    args, &err)) == NULL) {
		nvlist_free(args);
		return (set_fmri_err(mod, err));
	}

	nvlist_free(args);

	(void) topo_mod_nvdup(mod, fmri, &nfp);
	nvlist_free(fmri);

	return (nfp);
}

nvlist_t *
topo_mod_devfmri(topo_mod_t *mod, int version, const char *dev_path,
    const char *devid)
{
	int err;
	nvlist_t *fmri, *args;
	nvlist_t *nfp = NULL;

	if (version != FM_DEV_SCHEME_VERSION)
		return (set_fmri_err(mod, EMOD_FMRI_VERSION));

	if (topo_mod_nvalloc(mod, &args, NV_UNIQUE_NAME) != 0)
		return (set_fmri_err(mod, EMOD_FMRI_NVL));

	if (nvlist_add_string(args, FM_FMRI_DEV_PATH, dev_path) != 0) {
		nvlist_free(args);
		return (set_fmri_err(mod, EMOD_FMRI_NVL));
	}

	(void) nvlist_add_string(args, FM_FMRI_DEV_ID, devid);

	if ((fmri = topo_fmri_create(mod->tm_hdl, FM_FMRI_SCHEME_DEV,
	    FM_FMRI_SCHEME_DEV, 0, args, &err)) == NULL) {
		nvlist_free(args);
		return (set_fmri_err(mod, err));
	}

	nvlist_free(args);

	(void) topo_mod_nvdup(mod, fmri, &nfp);
	nvlist_free(fmri);

	return (nfp);
}

nvlist_t *
topo_mod_cpufmri(topo_mod_t *mod, int version, uint32_t cpu_id, uint8_t cpumask,
    const char *serial)
{
	int err;
	nvlist_t *fmri = NULL, *args = NULL;
	nvlist_t *nfp = NULL;

	if (version != FM_CPU_SCHEME_VERSION)
		return (set_fmri_err(mod, EMOD_FMRI_VERSION));

	if (topo_mod_nvalloc(mod, &args, NV_UNIQUE_NAME) != 0)
		return (set_fmri_err(mod, EMOD_FMRI_NVL));

	if (nvlist_add_uint32(args, FM_FMRI_CPU_ID, cpu_id) != 0) {
		nvlist_free(args);
		return (set_fmri_err(mod, EMOD_FMRI_NVL));
	}

	/*
	 * Add optional payload
	 */
	(void) nvlist_add_uint8(args, FM_FMRI_CPU_MASK, cpumask);
	(void) nvlist_add_string(args, FM_FMRI_CPU_SERIAL_ID, serial);

	if ((fmri = topo_fmri_create(mod->tm_hdl, FM_FMRI_SCHEME_CPU,
	    FM_FMRI_SCHEME_CPU, 0, args, &err)) == NULL) {
		nvlist_free(args);
		return (set_fmri_err(mod, err));
	}

	nvlist_free(args);

	(void) topo_mod_nvdup(mod, fmri, &nfp);
	nvlist_free(fmri);

	return (nfp);
}

nvlist_t *
topo_mod_memfmri(topo_mod_t *mod, int version, uint64_t pa, uint64_t offset,
    const char *unum, int flags)
{
	int err;
	nvlist_t *args = NULL, *fmri = NULL;
	nvlist_t *nfp = NULL;

	if (version != FM_MEM_SCHEME_VERSION)
		return (set_fmri_err(mod, EMOD_FMRI_VERSION));

	if (topo_mod_nvalloc(mod, &args, NV_UNIQUE_NAME) != 0)
		return (set_fmri_err(mod, EMOD_FMRI_NVL));

	err = nvlist_add_string(args, FM_FMRI_MEM_UNUM, unum);
		nvlist_free(args);
	if (flags & TOPO_MEMFMRI_PA)
		err |= nvlist_add_uint64(args, FM_FMRI_MEM_PHYSADDR, pa);
	if (flags & TOPO_MEMFMRI_OFFSET)
		err |= nvlist_add_uint64(args, FM_FMRI_MEM_OFFSET, offset);

	if (err != 0) {
		nvlist_free(args);
		return (set_fmri_err(mod, EMOD_FMRI_NVL));
	}

	if ((fmri = topo_fmri_create(mod->tm_hdl, FM_FMRI_SCHEME_MEM,
	    FM_FMRI_SCHEME_MEM, 0, args, &err)) == NULL) {
		nvlist_free(args);
		return (set_fmri_err(mod, err));
	}

	nvlist_free(args);

	(void) topo_mod_nvdup(mod, fmri, &nfp);
	nvlist_free(fmri);

	return (nfp);

}

nvlist_t *
topo_mod_pkgfmri(topo_mod_t *mod, int version, const char *path)
{
	int err;
	nvlist_t *fmri = NULL, *args = NULL;
	nvlist_t *nfp = NULL;

	if (version != FM_PKG_SCHEME_VERSION)
		return (set_fmri_err(mod, EMOD_FMRI_VERSION));

	if (topo_mod_nvalloc(mod, &args, NV_UNIQUE_NAME) != 0)
		return (set_fmri_err(mod, EMOD_FMRI_NVL));

	if (nvlist_add_string(args, "path", path) != 0) {
		nvlist_free(args);
		return (set_fmri_err(mod, EMOD_FMRI_NVL));
	}

	if ((fmri = topo_fmri_create(mod->tm_hdl, FM_FMRI_SCHEME_PKG,
	    FM_FMRI_SCHEME_PKG, 0, args, &err)) == NULL) {
		nvlist_free(args);
		return (set_fmri_err(mod, err));
	}

	nvlist_free(args);

	(void) topo_mod_nvdup(mod, fmri, &nfp);
	nvlist_free(fmri);

	return (nfp);
}

nvlist_t *
topo_mod_modfmri(topo_mod_t *mod, int version, const char *driver)
{
	int err;
	nvlist_t *fmri = NULL, *args = NULL;
	nvlist_t *nfp = NULL;

	if (version != FM_MOD_SCHEME_VERSION)
		return (set_fmri_err(mod, EMOD_FMRI_VERSION));

	if (topo_mod_nvalloc(mod, &args, NV_UNIQUE_NAME) != 0)
		return (set_fmri_err(mod, EMOD_FMRI_NVL));

	if (nvlist_add_string(args, "DRIVER", driver) != 0) {
		nvlist_free(args);
		return (set_fmri_err(mod, EMOD_FMRI_NVL));
	}

	if ((fmri = topo_fmri_create(mod->tm_hdl, FM_FMRI_SCHEME_MOD,
	    FM_FMRI_SCHEME_MOD, 0, args, &err)) == NULL) {
		nvlist_free(args);
		return (set_fmri_err(mod, err));
	}

	nvlist_free(args);

	(void) topo_mod_nvdup(mod, fmri, &nfp);
	nvlist_free(fmri);

	return (nfp);
}

#define	_SWFMRI_ADD_STRING(nvl, name, val) \
	((val) ? (nvlist_add_string(nvl, name, val) != 0) : 0)

nvlist_t *
topo_mod_swfmri(topo_mod_t *mod, int version,
    char *obj_path, char *obj_root, nvlist_t *obj_pkg,
    char *site_token, char *site_module, char *site_file, char *site_func,
    int64_t site_line, char *ctxt_origin, char *ctxt_execname,
    int64_t ctxt_pid, char *ctxt_zone, int64_t ctxt_ctid,
    char **ctxt_stack, uint_t ctxt_stackdepth)
{
	nvlist_t *fmri, *args;
	nvlist_t *nfp = NULL;
	int err;

	if (version != FM_SW_SCHEME_VERSION)
		return (set_fmri_err(mod, EMOD_FMRI_VERSION));

	if (topo_mod_nvalloc(mod, &args, NV_UNIQUE_NAME) != 0)
		return (set_fmri_err(mod, EMOD_FMRI_NVL));

	err = 0;
	err |= _SWFMRI_ADD_STRING(args, "obj_path", obj_path);
	err |= _SWFMRI_ADD_STRING(args, "obj_root", obj_root);
	if (obj_pkg)
		err |= nvlist_add_nvlist(args, "obj_pkg", obj_pkg);

	err |= _SWFMRI_ADD_STRING(args, "site_token", site_token);
	err |= _SWFMRI_ADD_STRING(args, "site_module", site_module);
	err |= _SWFMRI_ADD_STRING(args, "site_file", site_file);
	err |= _SWFMRI_ADD_STRING(args, "site_func", site_func);
	if (site_line != -1)
		err |= nvlist_add_int64(args, "site_line", site_line);

	err |= _SWFMRI_ADD_STRING(args, "ctxt_origin", ctxt_origin);
	err |= _SWFMRI_ADD_STRING(args, "ctxt_execname", ctxt_execname);
	if (ctxt_pid != -1)
		err |= nvlist_add_int64(args, "ctxt_pid", ctxt_pid);
	err |= _SWFMRI_ADD_STRING(args, "ctxt_zone", ctxt_zone);
	if (ctxt_ctid != -1)
		err |= nvlist_add_int64(args, "ctxt_ctid", ctxt_ctid);
	if (ctxt_stack != NULL && ctxt_stackdepth != 0)
		err |= nvlist_add_string_array(args, "stack", ctxt_stack,
		    ctxt_stackdepth);

	if (err) {
		nvlist_free(args);
		return (set_fmri_err(mod, EMOD_FMRI_NVL));
	}

	if ((fmri = topo_fmri_create(mod->tm_hdl, FM_FMRI_SCHEME_SW,
	    FM_FMRI_SCHEME_SW, 0, args, &err)) == NULL) {
		nvlist_free(args);
		return (set_fmri_err(mod, err));
	}

	nvlist_free(args);

	(void) topo_mod_nvdup(mod, fmri, &nfp);
	nvlist_free(fmri);

	return (nfp);
}

int
topo_mod_str2nvl(topo_mod_t *mod, const char *fmristr, nvlist_t **fmri)
{
	int err;
	nvlist_t *np = NULL;

	if (topo_fmri_str2nvl(mod->tm_hdl, fmristr, &np, &err) < 0)
		return (topo_mod_seterrno(mod, err));

	if (topo_mod_nvdup(mod, np, fmri) < 0) {
		nvlist_free(np);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	nvlist_free(np);

	return (0);
}

int
topo_mod_nvl2str(topo_mod_t *mod, nvlist_t *fmri, char **fmristr)
{
	int err;
	char *sp;

	if (topo_fmri_nvl2str(mod->tm_hdl, fmri, &sp, &err) < 0)
		return (topo_mod_seterrno(mod, err));

	if ((*fmristr = topo_mod_strdup(mod, sp)) == NULL) {
		topo_hdl_strfree(mod->tm_hdl, sp);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	topo_hdl_strfree(mod->tm_hdl, sp);

	return (0);
}

void *
topo_mod_getspecific(topo_mod_t *mod)
{
	return (mod->tm_priv);
}

void
topo_mod_setspecific(topo_mod_t *mod, void *data)
{
	mod->tm_priv = data;
}

void
topo_mod_setdebug(topo_mod_t *mod)
{
	mod->tm_debug = 1;
}

ipmi_handle_t *
topo_mod_ipmi_hold(topo_mod_t *mod)
{
	topo_hdl_t *thp = mod->tm_hdl;
	int err;
	char *errmsg;

	(void) pthread_mutex_lock(&thp->th_ipmi_lock);
	if (thp->th_ipmi == NULL) {
		if ((thp->th_ipmi = ipmi_open(&err, &errmsg, IPMI_TRANSPORT_BMC,
		    NULL)) == NULL) {
			topo_dprintf(mod->tm_hdl, TOPO_DBG_ERR,
			    "ipmi_open() failed: %s (ipmi errno=%d)", errmsg,
			    err);
			(void) pthread_mutex_unlock(&thp->th_ipmi_lock);
		}
	}


	return (thp->th_ipmi);
}

void
topo_mod_ipmi_rele(topo_mod_t *mod)
{
	topo_hdl_t *thp = mod->tm_hdl;

	(void) pthread_mutex_unlock(&thp->th_ipmi_lock);
}

di_node_t
topo_mod_devinfo(topo_mod_t *mod)
{
	return (topo_hdl_devinfo(mod->tm_hdl));
}

smbios_hdl_t *
topo_mod_smbios(topo_mod_t *mod)
{
	topo_hdl_t *thp = mod->tm_hdl;

	if (thp->th_smbios == NULL)
		thp->th_smbios = smbios_open(NULL, SMB_VERSION, 0, NULL);

	return (thp->th_smbios);
}

di_prom_handle_t
topo_mod_prominfo(topo_mod_t *mod)
{
	return (topo_hdl_prominfo(mod->tm_hdl));
}

pcidb_hdl_t *
topo_mod_pcidb(topo_mod_t *mod)
{
	topo_hdl_t *thp = mod->tm_hdl;

	if (thp->th_pcidb == NULL)
		thp->th_pcidb = pcidb_open(PCIDB_VERSION);

	return (thp->th_pcidb);
}

void
topo_mod_clrdebug(topo_mod_t *mod)
{
	mod->tm_debug = 0;
}

/*PRINTFLIKE2*/
void
topo_mod_dprintf(topo_mod_t *mod, const char *format, ...)
{
	va_list alist;

	if (mod->tm_debug == 0)
		return;

	va_start(alist, format);
	topo_vdprintf(mod->tm_hdl, TOPO_DBG_MOD, (const char *)mod->tm_name,
	    format, alist);
	va_end(alist);
}

static char *
topo_mod_product(topo_mod_t *mod)
{
	return (topo_mod_strdup(mod, mod->tm_hdl->th_product));
}

static char *
topo_mod_server(topo_mod_t *mod)
{
	static struct utsname uts;

	(void) uname(&uts);
	return (topo_mod_strdup(mod, uts.nodename));
}

static char *
topo_mod_psn(topo_mod_t *mod)
{
	smbios_hdl_t *shp;
	const char *psn;

	if ((shp = topo_mod_smbios(mod)) == NULL ||
	    (psn = smbios_psn(shp)) == NULL)
		return (NULL);

	return (topo_cleanup_auth_str(mod->tm_hdl, psn));
}

static char *
topo_mod_csn(topo_mod_t *mod)
{
	char csn[MAXNAMELEN];
	smbios_hdl_t *shp;
	di_prom_handle_t promh = DI_PROM_HANDLE_NIL;
	di_node_t rooth = DI_NODE_NIL;
	const char *bufp;

	if ((shp = topo_mod_smbios(mod)) != NULL) {
		bufp = smbios_csn(shp);
		if (bufp != NULL)
			(void) strlcpy(csn, bufp, MAXNAMELEN);
		else
			return (NULL);
	} else if ((rooth = topo_mod_devinfo(mod)) != DI_NODE_NIL &&
	    (promh = topo_mod_prominfo(mod)) != DI_PROM_HANDLE_NIL) {
		if (di_prom_prop_lookup_bytes(promh, rooth, "chassis-sn",
		    (unsigned char **)&bufp) != -1) {
			(void) strlcpy(csn, bufp, MAXNAMELEN);
		} else {
			return (NULL);
		}
	} else {
		return (NULL);
	}

	return (topo_cleanup_auth_str(mod->tm_hdl, csn));
}

nvlist_t *
topo_mod_auth(topo_mod_t *mod, tnode_t *pnode)
{
	int err;
	char *prod = NULL;
	char *csn = NULL;
	char *psn = NULL;
	char *server = NULL;
	nvlist_t *auth;

	if ((err = topo_mod_nvalloc(mod, &auth, NV_UNIQUE_NAME)) != 0) {
		(void) topo_mod_seterrno(mod, EMOD_FMRI_NVL);
		return (NULL);
	}

	(void) topo_prop_get_string(pnode, FM_FMRI_AUTHORITY,
	    FM_FMRI_AUTH_PRODUCT, &prod, &err);
	(void) topo_prop_get_string(pnode, FM_FMRI_AUTHORITY,
	    FM_FMRI_AUTH_PRODUCT_SN, &psn, &err);
	(void) topo_prop_get_string(pnode, FM_FMRI_AUTHORITY,
	    FM_FMRI_AUTH_CHASSIS, &csn, &err);
	(void) topo_prop_get_string(pnode, FM_FMRI_AUTHORITY,
	    FM_FMRI_AUTH_SERVER, &server, &err);

	/*
	 * Let's do this the hard way
	 */
	if (prod == NULL)
		prod = topo_mod_product(mod);
	if (csn == NULL)
		csn = topo_mod_csn(mod);
	if (psn == NULL)
		psn = topo_mod_psn(mod);
	if (server == NULL) {
		server = topo_mod_server(mod);
	}

	/*
	 * No luck, return NULL
	 */
	if (!prod && !server && !csn && !psn) {
		nvlist_free(auth);
		return (NULL);
	}

	err = 0;
	if (prod != NULL) {
		err |= nvlist_add_string(auth, FM_FMRI_AUTH_PRODUCT, prod);
		topo_mod_strfree(mod, prod);
	}
	if (psn != NULL) {
		err |= nvlist_add_string(auth, FM_FMRI_AUTH_PRODUCT_SN, psn);
		topo_mod_strfree(mod, psn);
	}
	if (server != NULL) {
		err |= nvlist_add_string(auth, FM_FMRI_AUTH_SERVER, server);
		topo_mod_strfree(mod, server);
	}
	if (csn != NULL) {
		err |= nvlist_add_string(auth, FM_FMRI_AUTH_CHASSIS, csn);
		topo_mod_strfree(mod, csn);
	}

	if (err != 0) {
		nvlist_free(auth);
		(void) topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		return (NULL);
	}

	return (auth);
}

topo_walk_t *
topo_mod_walk_init(topo_mod_t *mod, tnode_t *node, topo_mod_walk_cb_t cb_f,
    void *pdata, int *errp)
{
	topo_walk_t *wp;
	topo_hdl_t *thp = mod->tm_hdl;

	if ((wp = topo_node_walk_init(thp, mod, node, (int (*)())cb_f, pdata,
	    errp)) == NULL)
		return (NULL);

	return (wp);
}
