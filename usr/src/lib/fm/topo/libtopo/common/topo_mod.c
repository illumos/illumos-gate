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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Topology Plugin Modules
 *
 * Topology plugin modules are shared libraries that are dlopen'd and
 * used to enumerate resources in the system.
 * They are loaded by our builtin scheme-specific plugins or other modules
 * to enumerate and create nodes for resources that are present in the system.
 * They may also export a set of resource (node) specific methods that can be
 * called on node-by-node basis.
 *
 * Module Plugin API
 *
 * Enumerators must provide entry points for intialization and clean-up
 * (_topo_init() and _topo_fini()).  In their _topo_init() function, an
 * enumerator should register (topo_mod_register()) its enumeration callback
 * and allocate resources required for a subsequent call to the callback.
 * Optionally, methods may also be registered with topo_method_register().
 *
 * In its enumeration callback routine, the module should search for resources
 * within its realm of resposibility and create any node ranges,
 * topo_node_range_create() or nodes, topo_node_bind().  The Enumerator
 * module is handed a node to which it may begin attaching additional
 * topology nodes.
 *
 * If additional helper modules need to be loaded to complete the enumeration
 * the module may do so by calling topo_mod_load().  Enumeration may then
 * continue with the module handing off enumeration to its helper module
 * by calling topo_mod_enumerate().
 *
 * If the module registers a release callback, it will be called on a node
 * by node basis during topo_snap_rele().  Any private node data may be
 * deallocated or methods unregistered at that time.  Global module data
 * should be clean-up before or at the time that the module _topo_fini
 * entry point is called.
 */

#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <alloca.h>
#include <unistd.h>
#include <stdio.h>

#include <topo_module.h>
#include <topo_alloc.h>
#include <topo_string.h>
#include <topo_error.h>
#include <topo_subr.h>

topo_mod_t *
topo_mod_load(topo_mod_t *pmod, const char *path)
{
	int err = 0;
	char *p;
	topo_mod_t *mod = NULL;
	topo_hdl_t *thp;

	thp = pmod->tm_hdl;

	/*
	 * Already loaded, bump the ref count
	 */
	if ((mod = topo_mod_lookup(thp, path)) != NULL) {
		topo_mod_hold(mod);
		return (mod);
	}

	/*
	 * Check for a valid path
	 */
	if (access(path, F_OK) != 0) {
		(void) topo_mod_seterrno(pmod, ETOPO_MOD_NOENT);
		return (NULL);
	}

	if ((p = strrchr(path, '.')) != NULL && strcmp(p, ".so") == 0) {
		if ((mod = topo_modhash_load(thp, path,
		    &topo_rtld_ops)) == NULL) { /* returned with mod held */
			(void) topo_mod_seterrno(pmod, err ? err :
			    ETOPO_MOD_NOENT);
			return (NULL);
		}
	} else {
		(void) topo_mod_seterrno(pmod, err ? err : ETOPO_MOD_NOENT);
		return (NULL);
	}

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

	topo_dprintf(TOPO_DBG_ERR, "module registration failed for %s: %s\n",
	    mod->tm_name, topo_strerror(err));

	return (topo_mod_seterrno(mod, err));
}

int
topo_mod_register(topo_mod_t *mod, const topo_modinfo_t *mip, void *priv)
{

	assert(!(mod->tm_flags & TOPO_MOD_FINI ||
	    mod->tm_flags & TOPO_MOD_REG));

	if (mod->tm_version > mip->tmi_version)
		return (set_register_error(mod, ETOPO_VER_OLD));
	if (mod->tm_version < mip->tmi_version)
		return (set_register_error(mod, ETOPO_VER_NEW));

	if ((mod->tm_info = topo_mod_alloc(mod, sizeof (topo_modinfo_t)))
	    == NULL)
		return (set_register_error(mod, ETOPO_NOMEM));

	mod->tm_info->tmi_desc = topo_mod_strdup(mod, mip->tmi_desc);
	if (mod->tm_info->tmi_desc == NULL)
		return (set_register_error(mod, ETOPO_NOMEM));

	mod->tm_info->tmi_version = (topo_version_t)mip->tmi_version;
	mod->tm_info->tmi_enum = mip->tmi_enum;
	mod->tm_info->tmi_release = mip->tmi_release;

	mod->tm_flags |= TOPO_MOD_REG;
	mod->tm_priv = priv;

	if (mod == NULL) {
		topo_dprintf(TOPO_DBG_MOD, "registration succeeded for %s\n",
		    mod->tm_name);

		return (0);
	}


	topo_dprintf(TOPO_DBG_MOD, "registration succeeded for %s\n",
	    mod->tm_name);

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

	if (mod->tm_info->tmi_desc != NULL)
		topo_mod_strfree(mod, mod->tm_info->tmi_desc);

	topo_mod_free(mod, mod->tm_info, sizeof (topo_modinfo_t));

	mod->tm_info = NULL;
}

int
topo_mod_enumerate(topo_mod_t *mod, tnode_t *node, const char *enum_name,
    const char *name, topo_instance_t min, topo_instance_t max)
{
	int err = 0;
	topo_mod_t *enum_mod;

	assert(mod->tm_flags & TOPO_MOD_REG);

	if ((enum_mod = topo_mod_lookup(mod->tm_hdl, enum_name)) == NULL)
		return (topo_mod_seterrno(mod, ETOPO_MOD_NOENT));

	topo_node_hold(node);

	topo_dprintf(TOPO_DBG_MOD, "module %s enumerating node %s=%d\n",
	    (char *)mod->tm_name, (char *)node->tn_name, node->tn_instance);

	topo_mod_enter(enum_mod);
	err = enum_mod->tm_info->tmi_enum(enum_mod, node, name, min, max,
	    enum_mod->tm_priv);
	topo_mod_exit(enum_mod);

	if (err != 0) {
		(void) topo_mod_seterrno(mod, ETOPO_MODULE);

		topo_dprintf(TOPO_DBG_ERR, "module %s failed enumeration for "
		    " node %s=%d\n", (char *)mod->tm_name,
		    (char *)node->tn_name, node->tn_instance);

		topo_node_rele(node);
		return (-1);
	}

	topo_node_rele(node);

	return (0);
}

char *
topo_mod_rootdir(topo_mod_t *mod)
{
	return (mod->tm_rootdir);
}

topo_hdl_t *
topo_mod_handle(topo_mod_t *mod)
{
	return (mod->tm_hdl);
}

void *
topo_mod_private(topo_mod_t *mod)
{
	return (mod->tm_priv);
}

void
topo_mod_setdebug(topo_mod_t *mod, int mask)
{
	mod->tm_debug |= mask;
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
	if (mod->tm_debug & mod->tm_hdl->th_debug) {
		va_list alist;

		va_start(alist, format);
		(void) fputs("libtopo DEBUG: ", stderr);
		(void) vfprintf(stderr, format, alist);
		va_end(alist);
	}
}
