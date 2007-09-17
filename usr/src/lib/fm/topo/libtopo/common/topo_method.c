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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <alloca.h>
#include <unistd.h>
#include <stdio.h>
#include <strings.h>

#include <topo_mod.h>

#include <topo_error.h>
#include <topo_module.h>
#include <topo_subr.h>
#include <topo_tree.h>

topo_imethod_t *
topo_method_lookup(tnode_t *node, const char *name)
{
	topo_imethod_t *mp;

	for (mp = topo_list_next(&node->tn_methods); mp != NULL;
	    mp = topo_list_next(mp)) {
		if (strcmp(name, mp->tim_name) == 0) {
			topo_node_unlock(node);
			return (mp);
		}
	}

	return (NULL);
}

static void
topo_method_enter(topo_imethod_t *mp)
{
	(void) pthread_mutex_lock(&mp->tim_lock);

	while (mp->tim_busy != 0)
		(void) pthread_cond_wait(&mp->tim_cv, &mp->tim_lock);

	++mp->tim_busy;

	(void) pthread_mutex_unlock(&mp->tim_lock);
}

static void
topo_method_exit(topo_imethod_t *mp)
{
	(void) pthread_mutex_lock(&mp->tim_lock);
	--mp->tim_busy;

	assert(mp->tim_busy == 0);

	(void) pthread_cond_broadcast(&mp->tim_cv);
	(void) pthread_mutex_unlock(&mp->tim_lock);
}

static int
set_methregister_error(topo_mod_t *mod, tnode_t *node, topo_imethod_t *mp,
    int err)
{
	if (mp != NULL) {
		topo_list_delete(&node->tn_methods, mp);
		if (mp->tim_name != NULL)
			topo_mod_strfree(mod, mp->tim_name);
		if (mp->tim_desc != NULL)
			topo_mod_strfree(mod, mp->tim_desc);

		topo_mod_free(mod, mp, sizeof (topo_imethod_t));
	}

	topo_node_unlock(node);

	topo_dprintf(mod->tm_hdl, TOPO_DBG_ERR,
	    "method registration failed for %s: %s\n",
	    mod->tm_name, topo_strerror(err));

	return (topo_mod_seterrno(mod, err));
}

int
topo_method_register(topo_mod_t *mod, tnode_t *node, const topo_method_t *mp)
{
	topo_imethod_t *imp;
	const topo_method_t *meth;

	/*
	 * Initialize module methods
	 */
	for (meth = &mp[0]; meth->tm_name != NULL; meth++) {

		topo_node_lock(node);
		if (topo_method_lookup(node, meth->tm_name) != NULL) {
			topo_node_unlock(node);
			continue;
		}

		if (meth->tm_stability < TOPO_STABILITY_INTERNAL ||
		    meth->tm_stability > TOPO_STABILITY_MAX ||
		    meth->tm_func == NULL)
			return (set_methregister_error(mod, node, NULL,
			    ETOPO_METHOD_INVAL));

		imp = topo_mod_zalloc(mod, sizeof (topo_imethod_t));
		if (imp == NULL)
			return (set_methregister_error(mod, node, imp,
			    ETOPO_METHOD_NOMEM));

		if ((imp->tim_name = topo_mod_strdup(mod, meth->tm_name))
		    == NULL)
			return (set_methregister_error(mod, node, imp,
			    ETOPO_METHOD_NOMEM));

		if ((imp->tim_desc = topo_mod_strdup(mod, meth->tm_desc))
		    == NULL)
			return (set_methregister_error(mod, node, imp,
			    ETOPO_METHOD_NOMEM));


		imp->tim_stability = meth->tm_stability;
		imp->tim_version = meth->tm_version;
		imp->tim_func = meth->tm_func;
		imp->tim_mod = mod;

		topo_list_append(&node->tn_methods, imp);
		topo_node_unlock(node);

		topo_dprintf(mod->tm_hdl, TOPO_DBG_MODSVC,
		    "registered module %s method "
		    "%s for %s=%d\n", mod->tm_name, imp->tim_name,
		    topo_node_name(node), topo_node_instance(node));

	}

	return (0);
}

void
topo_method_unregister(topo_mod_t *mod, tnode_t *node, const char *name)
{
	topo_imethod_t *mp;

	topo_node_lock(node);
	for (mp = topo_list_next(&node->tn_methods); mp != NULL;
	    mp = topo_list_next(mp)) {
		if (strcmp(name, mp->tim_name) == 0)
			break;
	}

	if (mp == NULL) {
		topo_node_unlock(node);
		return;
	}

	topo_list_delete(&node->tn_methods, mp);
	topo_node_unlock(node);

	if (mp->tim_name != NULL)
		topo_mod_strfree(mod, mp->tim_name);
	if (mp->tim_desc != NULL)
		topo_mod_strfree(mod, mp->tim_desc);

	topo_mod_free(mod, mp, sizeof (topo_imethod_t));
}

void
topo_method_unregister_all(topo_mod_t *mod, tnode_t *node)
{
	topo_imethod_t *mp;

	topo_node_lock(node);
	while ((mp = topo_list_next(&node->tn_methods)) != NULL) {
		topo_list_delete(&node->tn_methods, mp);
		if (mp->tim_name != NULL)
			topo_mod_strfree(mod, mp->tim_name);
		if (mp->tim_desc != NULL)
			topo_mod_strfree(mod, mp->tim_desc);
		topo_mod_free(mod, mp, sizeof (topo_imethod_t));
	}
	topo_node_unlock(node);
}


int
topo_method_call(tnode_t *node, const char *method,
    topo_version_t version, nvlist_t *in, nvlist_t **out, int *err)
{
	int rc;
	topo_imethod_t *mp;

	for (mp = topo_list_next(&node->tn_methods); mp != NULL;
	    mp = topo_list_next(mp)) {
		if (strcmp(method, mp->tim_name) != 0)
			continue;

		if (version < mp->tim_version) {
			*err = ETOPO_METHOD_VEROLD;
			return (-1);
		} else if (version > mp->tim_version) {
			*err = ETOPO_METHOD_VERNEW;
			return (-1);
		}

		topo_method_enter(mp);
		if ((rc = mp->tim_func(mp->tim_mod, node, version, in, out))
		    < 0) {
			if (mp->tim_mod->tm_errno == 0)
				*err = ETOPO_METHOD_FAIL;
			else
				*err = mp->tim_mod->tm_errno;
		}
		topo_method_exit(mp);

		return (rc);

	}

	*err = ETOPO_METHOD_NOTSUP;
	return (-1);
}

int
topo_method_invoke(tnode_t *node, const char *method,
    topo_version_t version, nvlist_t *in, nvlist_t **out, int *err)
{
	int rc;

	topo_node_hold(node);
	rc = topo_method_call(node, method, version, in, out, err);
	topo_node_rele(node);

	return (rc);
}
