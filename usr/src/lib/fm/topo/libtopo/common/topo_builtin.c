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

#include <pthread.h>

#include <topo_module.h>
#include <topo_string.h>
#include <topo_builtin.h>
#include <topo_error.h>
#include <topo_subr.h>

static const struct topo_builtin _topo_builtins[] = {
	{ "cpu", cpu_init, cpu_fini },
	{ "dev", dev_init, dev_fini },
	{ "mem", mem_init, mem_fini },
	{ "pkg", pkg_init, pkg_fini },
	{ "mod", mod_init, mod_fini },
	{ "hc", hc_init, hc_fini },
	{ NULL, NULL, NULL }
};

static int
bltin_init(topo_mod_t *mp)
{
	const topo_builtin_t *bp;

	for (bp = _topo_builtins; bp->bltin_name != NULL; bp++) {
		if (strcmp(mp->tm_name, bp->bltin_name) == 0)
			break;
	}

	mp->tm_data = (void *)bp;

	(*bp->bltin_init)(mp);

	if (mp->tm_info == NULL) {
		topo_dprintf(TOPO_DBG_ERR,
		    "unable initialize builtin module: %s\n", bp->bltin_name);
		return (topo_mod_seterrno(mp, ETOPO_MOD_INIT));
	}

	return (0);
}

static int
bltin_fini(topo_mod_t *mp)
{
	topo_builtin_t *bp = mp->tm_data;

	if (mp->tm_info != NULL) {
		(*bp->bltin_fini)(mp);

	}

	return (0);
}

const topo_modops_t topo_bltin_ops = {
	bltin_init,
	bltin_fini,
};

/*ARGSUSED*/
int
topo_builtin_create(topo_hdl_t *thp, const char *rootdir)
{
	const topo_builtin_t *bp;
	topo_mod_t *mod;
	ttree_t *tp;
	tnode_t *rnode;

	/*
	 * Create a scheme-specific topo tree for all builtins
	 */
	for (bp = _topo_builtins; bp->bltin_name != NULL; bp++) {

		/*
		 * Load scheme-specific module
		 */
		if ((mod = topo_modhash_load(thp, bp->bltin_name,
		    &topo_bltin_ops)) == NULL) {
			topo_dprintf(TOPO_DBG_ERR, "unable to create scheme "
			    "tree for %s:%s\n", bp->bltin_name,
			    topo_hdl_errmsg(thp));
			return (-1);
		}
		if ((tp = topo_tree_create(thp, mod, bp->bltin_name))
		    == NULL) {
			topo_dprintf(TOPO_DBG_ERR, "unable to create scheme "
			    "tree for %s:%s\n", bp->bltin_name,
			    topo_hdl_errmsg(thp));
			return (-1);
		}
		topo_list_append(&thp->th_trees, tp);

		/*
		 * Call the enumerator on the root of the tree, with the
		 * scheme name as the name to enumerate.  This will
		 * establish methods on the root node.
		 */
		rnode = tp->tt_root;
		if (topo_mod_enumerate(mod, rnode, mod->tm_name, rnode->tn_name,
		    rnode->tn_instance, rnode->tn_instance) < 0) {
			/*
			 * If we see a failure, note it in the handle and
			 * drive on
			 */
			(void) topo_hdl_seterrno(thp, ETOPO_ENUM_PARTIAL);
		}

	}

	return (0);
}
