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
 * Copyright 2020 Joyent, Inc.
 */

#include <pthread.h>

#include <topo_module.h>
#include <topo_string.h>
#include <topo_builtin.h>
#include <topo_error.h>
#include <topo_subr.h>

#include <cpu.h>
#include <hc.h>
#include <dev.h>
#include <fmd.h>
#include <mem.h>
#include <mod.h>
#include <pkg.h>
#include <svc.h>
#include <sw.h>
#include <zfs.h>

static const struct topo_builtin _topo_builtins[] = {
	{ "cpu", CPU_VERSION, cpu_init, cpu_fini, TOPO_BLTIN_TYPE_TREE },
	{ "dev", DEV_VERSION, dev_init, dev_fini, TOPO_BLTIN_TYPE_TREE },
	{ "fmd", FMD_VERSION, fmd_init, fmd_fini, TOPO_BLTIN_TYPE_TREE },
	{ "mem", MEM_VERSION, mem_init, mem_fini, TOPO_BLTIN_TYPE_TREE },
	{ "pkg", PKG_VERSION, pkg_init, pkg_fini, TOPO_BLTIN_TYPE_TREE },
	{ "svc", SVC_VERSION, svc_init, svc_fini, TOPO_BLTIN_TYPE_TREE },
	{ "sw", SW_VERSION, sw_init, sw_fini, TOPO_BLTIN_TYPE_TREE },
	{ "zfs", ZFS_VERSION, zfs_init, zfs_fini, TOPO_BLTIN_TYPE_TREE },
	{ "mod", MOD_VERSION, mod_init, mod_fini, TOPO_BLTIN_TYPE_TREE },
	/* hc must go last */
	{ "hc", HC_VERSION, hc_init, hc_fini, TOPO_BLTIN_TYPE_TREE },
	{ NULL, 0, NULL, NULL, 0 }
};

static int
bltin_init(topo_mod_t *mp, topo_version_t version)
{
	const topo_builtin_t *bp;

	for (bp = _topo_builtins; bp->bltin_name != NULL; bp++) {
		if (strcmp(mp->tm_name, bp->bltin_name) == 0)
			break;
	}

	mp->tm_data = (void *)bp;

	if ((*bp->bltin_init)(mp, version) != 0 || mp->tm_info == NULL) {
		if (mp->tm_errno == 0)
			(void) topo_mod_seterrno(mp, ETOPO_MOD_INIT);
		topo_dprintf(mp->tm_hdl, TOPO_DBG_ERR,
		    "unable initialize builtin module: %s: %s\n",
		    bp->bltin_name, topo_mod_errmsg(mp));
		return (-1);
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

const topo_imodops_t topo_bltin_ops = {
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
	topo_digraph_t *tdg;

	/*
	 * Create a scheme-specific topo tree for all builtins
	 */
	for (bp = _topo_builtins; bp->bltin_name != NULL; bp++) {

		/*
		 * Load scheme-specific module
		 */
		if ((mod = topo_modhash_load(thp, bp->bltin_name, NULL,
		    &topo_bltin_ops, bp->bltin_version)) == NULL) {
			topo_dprintf(thp, TOPO_DBG_ERR,
			    "unable to create scheme "
			    "topology for %s:%s\n", bp->bltin_name,
			    topo_hdl_errmsg(thp));
			return (-1);
		}
		switch (bp->bltin_type) {
		case TOPO_BLTIN_TYPE_TREE:
			if ((tp = topo_tree_create(thp, mod, bp->bltin_name))
			    == NULL) {
				topo_dprintf(thp, TOPO_DBG_ERR, "unable to "
				    "create scheme tree for %s:%s\n",
				    bp->bltin_name, topo_hdl_errmsg(thp));
				return (-1);
			}
			topo_list_append(&thp->th_trees, tp);

			rnode = tp->tt_root;
			break;
		case TOPO_BLTIN_TYPE_DIGRAPH:
			if ((tdg = topo_digraph_new(thp, mod, bp->bltin_name))
			    == NULL) {
				topo_dprintf(thp, TOPO_DBG_ERR, "unable to "
				    "create scheme digraph for %s:%s\n",
				    bp->bltin_name, topo_hdl_errmsg(thp));
				return (-1);
			}
			topo_list_append(&thp->th_digraphs, tdg);

			rnode = tdg->tdg_rootnode;
			break;
		default:
			topo_dprintf(thp, TOPO_DBG_ERR, "unexpected topology "
			    "type: %u", bp->bltin_type);
			return (-1);
		}
		if (topo_mod_enumerate(mod, rnode, mod->tm_name,
		    rnode->tn_name, rnode->tn_instance, rnode->tn_instance,
		    NULL) < 0) {
			/*
			 * If we see a failure, note it in the handle and drive
			 * on
			 */
			(void) topo_hdl_seterrno(thp, ETOPO_ENUM_PARTIAL);
		}
	}

	return (0);
}
