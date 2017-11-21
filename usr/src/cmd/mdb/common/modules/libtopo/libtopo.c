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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2017, Joyent, Inc.
 */
#include <sys/mdb_modapi.h>
#include <libelf.h>
#include <sys/fm/protocol.h>
#include <topo_mod.h>
#include <topo_tree.h>
#include <topo_module.h>
#include <stddef.h>


/*
 * We use this to keep track of which bucket we're in while walking
 * the modhash and we also cache the length of the hash
 */
static topo_modhash_t tmh;
static uint_t hash_idx;

static uintptr_t curr_pg;
static uint_t is_root;
static uint_t verbose;
static char *pgrp;
static char *tgt_scheme;
static char parent[255];

/*
 * This structure is used by the topo_nodehash walker instances to
 * keep track of where they're at in the node hash
 */
typedef struct tnwalk_state {
	uint_t hash_idx;
	topo_nodehash_t hash;
	topo_nodehash_t *curr_hash;
} tnwalk_state_t;


static char *stab_lvls[] = {"Internal", "", "Private", "Obsolete", "External",
	"Unstable", "Evolving", "Stable", "Standard", "Max"};

/*ARGSUSED*/
static int
topo_handle(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char uuid[36], root[36], plat[36], isa[36], machine[36], product[36];
	topo_hdl_t th;

	/*
	 * Read in the structure and then read in all of the string fields from
	 * the target's addr space
	 */
	if (mdb_vread(&th, sizeof (th), addr) != sizeof (th)) {
		mdb_warn("failed to read topo_hdl_t at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_readstr(uuid, sizeof (uuid), (uintptr_t)th.th_uuid) < 0) {
		(void) mdb_snprintf(uuid, sizeof (uuid), "<%p>", th.th_uuid);
	}
	if (mdb_readstr(root, sizeof (root), (uintptr_t)th.th_rootdir) < 0) {
		(void) mdb_snprintf(root, sizeof (root), "<%p>", th.th_rootdir);
	}
	if (mdb_readstr(plat, sizeof (plat), (uintptr_t)th.th_platform) < 0) {
		(void) mdb_snprintf(plat, sizeof (plat), "<%p>",
		    th.th_platform);
	}
	if (mdb_readstr(isa, sizeof (isa), (uintptr_t)th.th_isa) < 0) {
		(void) mdb_snprintf(isa, sizeof (isa), "<%p>", th.th_isa);
	}
	if (mdb_readstr(machine, sizeof (machine), (uintptr_t)th.th_machine)
	    < 0) {

		(void) mdb_snprintf(machine, sizeof (machine), "<%p>",
		    th.th_machine);
	}
	if (mdb_readstr(product, sizeof (product), (uintptr_t)th.th_product)
	    < 0) {

		(void) mdb_snprintf(product, sizeof (product), "<%p>",
		    th.th_product);
	}

	/*
	 * Dump it all out in a nice pretty format and keep it to 80 chars wide
	 */
	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-12s %-36s %-30s%</u>\n", "FIELD", "VALUE",
		    "DESCR");
	}
	mdb_printf("%-12s 0x%-34p %-30s\n", "th_lock",
	    addr + offsetof(topo_hdl_t, th_lock),
	    "Mutex lock protecting handle");
	mdb_printf("%-12s %-36s %-30s\n", "th_uuid", uuid,
	    "UUID of the topology snapshot");
	mdb_printf("%-12s %-36s %-30s\n", "th_rootdir", root,
	    "Root directory of plugin paths");
	mdb_printf("%-12s %-36s %-30s\n", "th_platform", plat, "Platform name");
	mdb_printf("%-12s %-36s %-30s\n", "th_isa", isa, "ISA name");
	mdb_printf("%-12s %-36s %-30s\n", "th_machine", machine,
	    "Machine name");
	mdb_printf("%-12s %-36s %-30s\n", "th_product", product,
	    "Product name");
	mdb_printf("%-12s 0x%-34p %-30s\n", "th_di", th.th_di,
	    "Handle to the root of the devinfo tree");
	mdb_printf("%-12s 0x%-34p %-30s\n", "th_pi", th.th_pi,
	    "Handle to the root of the PROM tree");
	mdb_printf("%-12s 0x%-34p %-30s\n", "th_modhash", th.th_modhash,
	    "Module hash");
	mdb_printf("%-12s %-36s %-30s\n", "th_trees", "",
	    "Scheme-specific topo tree list");
	mdb_printf("  %-12s 0x%-34p %-30s\n", "l_prev", th.th_trees.l_prev,
	    "");
	mdb_printf("  %-12s 0x%-34p %-30s\n", "l_next", th.th_trees.l_next,
	    "");
	mdb_printf("%-12s 0x%-34p %-30s\n", "th_alloc", th.th_alloc,
	    "Allocators");
	mdb_printf("%-12s %-36d %-30s\n", "tm_ernno", th.th_errno, "errno");
	mdb_printf("%-12s %-36d %-30s\n", "tm_debug", th.th_debug,
	    "Debug mask");
	mdb_printf("%-12s %-36d %-30s\n", "tm_dbout", th.th_dbout,
	    "Debug channel");

	return (DCMD_OK);
}


/*ARGSUSED*/
static int
topo_module(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char name[36], path[36], root[36];
	topo_mod_t tm;

	/*
	 * Read in the structure and then read in all of the string fields from
	 * the target's addr space
	 */
	if (mdb_vread(&tm, sizeof (tm), addr) != sizeof (tm)) {
		mdb_warn("failed to read topo_mod_t at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_readstr(name, sizeof (name), (uintptr_t)tm.tm_name) < 0) {
		(void) mdb_snprintf(name, sizeof (name), "<%p>", tm.tm_name);
	}
	if (mdb_readstr(path, sizeof (path), (uintptr_t)tm.tm_path) < 0) {
		(void) mdb_snprintf(path, sizeof (path), "<%p>", tm.tm_path);
	}
	if (mdb_readstr(root, sizeof (root), (uintptr_t)tm.tm_rootdir) < 0) {
		(void) mdb_snprintf(root, sizeof (root), "<%p>", tm.tm_rootdir);
	}

	/*
	 * Dump it all out in a nice pretty format and keep it to 80 chars wide
	 */
	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-12s %-36s %-30s%</u>\n",
		    "FIELD", "VALUE", "DESCR");
	}
	mdb_printf("%-12s 0x%-34p %-30s\n", "tm_lock",
	    addr + offsetof(topo_mod_t, tm_lock),
	    "Lock for tm_cv/owner/flags/refs");
	mdb_printf("%-12s 0x%-34p %-30s\n", "tm_cv",
	    addr + offsetof(topo_mod_t, tm_cv),
	    "Module condition variable");
	if (tm.tm_busy)
		mdb_printf("%-12s %-36s %-30s\n", "tm_busy", "TRUE",
		    "Busy indicator");
	else
		mdb_printf("%-12s %-36s %-30s\n", "tm_busy", "FALSE",
		    "Busy indicator");

	mdb_printf("%-12s 0x%-34p %-30s\n", "tm_next", tm.tm_next,
	    "Next module in hash chain");
	mdb_printf("%-12s 0x%-34p %-30s\n", "tm_hdl", tm.tm_hdl,
	    "Topo handle for this module");
	mdb_printf("%-12s 0x%-34p %-30s\n", "tm_alloc", tm.tm_alloc,
	    "Allocators");
	mdb_printf("%-12s %-36s %-30s\n", "tm_name", name,
	    "Basename of module");
	mdb_printf("%-12s %-36s %-30s\n", "tm_path", path,
	    "Full pathname of module");
	mdb_printf("%-12s %-36s %-30s\n", "tm_rootdir", root,
	    "Relative root directory of module");
	mdb_printf("%-12s %-36u %-30s\n", "tm_refs", tm.tm_refs,
	    "Module reference count");
	mdb_printf("%-12s %-36u %-30s\n", "tm_flags", tm.tm_flags,
	    "Module flags");
	if (TOPO_MOD_INIT & tm.tm_flags) {
		mdb_printf("%-12s %-36s %-30s\n", "", "TOPO_MOD_INIT",
		    "Module init completed");
	}
	if (TOPO_MOD_FINI & tm.tm_flags) {
		mdb_printf("%-12s %-36s %-30s\n", "", "TOPO_MOD_FINI",
		    "Module fini completed");
	}
	if (TOPO_MOD_REG & tm.tm_flags) {
		mdb_printf("%-12s %-36s %-30s\n", "", "TOPO_MOD_REG",
		    "Module registered");
	}
	if (TOPO_MOD_UNREG & tm.tm_flags) {
		mdb_printf("%-12s %-36s %-30s\n", "", "TOPO_MOD_UNREG",
		    "Module unregistered");
	}

	mdb_printf("%-12s %-36u %-30s\n", "tm_debug", tm.tm_debug,
	    "Debug printf mask");
	mdb_printf("%-12s 0x%-34p %-30s\n", "tm_data", tm.tm_data,
	    "Private rtld/builtin data");
	mdb_printf("%-12s 0x%-34p %-30s\n", "tm_mops", tm.tm_mops,
	    "Module class ops vector");
	mdb_printf("%-12s 0x%-34p %-30s\n", "tm_info", tm.tm_info,
	    "Module info registered with handle");
	mdb_printf("%-12s %-36d %-30s\n", "tm_ernno", tm.tm_errno,
	    "Module errno");

	return (DCMD_OK);
}


/*ARGSUSED*/
static int
topo_node(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char name[36];
	tnode_t tn;

	if (!addr)
		return (DCMD_ERR);

	/*
	 * Read in the structure and then read in all of the string fields from
	 * the target's addr space
	 */
	if (mdb_vread(&tn, sizeof (tn), addr) != sizeof (tn)) {
		mdb_warn("failed to read tnode_t at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_readstr(name, sizeof (name), (uintptr_t)tn.tn_name) < 0) {
		(void) mdb_snprintf(name, sizeof (name), "<%p>", tn.tn_name);
	}

	/*
	 * Dump it all out in a nice pretty format and keep it to 80 chars wide
	 */
	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-12s %-36s %-30s%</u>\n",
		"FIELD", "VALUE", "DESCR");
	}

	mdb_printf("%-12s 0x%-34p %-30s\n", "tn_lock",
	    addr + offsetof(tnode_t, tn_lock),
	    "Lock protecting node members");
	mdb_printf("%-12s %-36s %-30s\n", "tn_name", name,
	    "Node name");
	mdb_printf("%-12s %-36d %-30s\n", "tn_instance", tn.tn_instance,
	    "Node instance");
	mdb_printf("%-12s %-36d %-30s\n", "tn_state", tn.tn_state,
	    "Node state");
	if (TOPO_NODE_INIT & tn.tn_state) {
		mdb_printf("%-12s %-36s %-30s\n", "", "TOPO_NODE_INIT", "");
	}
	if (TOPO_NODE_ROOT & tn.tn_state) {
		mdb_printf("%-12s %-36s %-30s\n", "", "TOPO_NODE_ROOT", "");
	}
	if (TOPO_NODE_BOUND & tn.tn_state) {
		mdb_printf("%-12s %-36s %-30s\n", "", "TOPO_NODE_BOUND", "");
	}
	if (TOPO_NODE_LINKED & tn.tn_state) {
		mdb_printf("%-12s %-36s %-30s\n", "", "TOPO_NODE_LINKED", "");
	}
	mdb_printf("%-12s %-36d %-30s\n", "tn_fflags", tn.tn_fflags,
	    "FMRI flags");
	mdb_printf("%-12s 0x%-34p %-30s\n", "tn_parent", tn.tn_parent,
	    "Node parent");
	mdb_printf("%-12s 0x%-34p %-30s\n", "tn_phash", tn.tn_phash,
	    "Parent hash bucket");
	mdb_printf("%-12s 0x%-34p %-30s\n", "tn_hdl", tn.tn_hdl,
	    "Topo handle");
	mdb_printf("%-12s 0x%-34p %-30s\n", "tn_enum", tn.tn_enum,
	    "Enumerator module");
	mdb_printf("%-12s %-36s %-30s\n", "tn_children", "",
	    "Hash table of child nodes");
	mdb_printf("  %-12s 0x%-34p\n", "l_prev", tn.tn_children.l_prev);
	mdb_printf("  %-12s 0x%-34p\n", "l_next", tn.tn_children.l_next);
	mdb_printf("%-12s 0x%-34p %-30s\n", "tn_pgroups", &(tn.tn_pgroups),
	    "Property group list");
	mdb_printf("%-12s 0x%-34p %-30s\n", "tn_methods", &(tn.tn_methods),
	    "Registered method list");
	mdb_printf("%-12s 0x%-34p %-30s\n", "tn_priv", tn.tn_priv,
	    "Private enumerator data");
	mdb_printf("%-12s %-36d %-30s\n", "tn_refs", tn.tn_refs,
	    "Node reference count");

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
find_tree_root(uintptr_t addr, const void *data, void *arg)
{
	ttree_t *tree = (ttree_t *)data;
	char scheme[36];

	if (mdb_readstr(scheme, sizeof (scheme), (uintptr_t)tree->tt_scheme)
	    < 0) {
		(void) mdb_snprintf(scheme, sizeof (scheme), "<%p>",
		    tree->tt_scheme);
	}

	if (strncmp(tgt_scheme, scheme, 36) == 0) {
		*((tnode_t **)arg) = tree->tt_root;
		return (WALK_DONE);
	}
	return (WALK_NEXT);
}

static void
dump_propmethod(uintptr_t addr)
{
	topo_propmethod_t pm;
	char mname[32];

	if (mdb_vread(&pm, sizeof (pm), addr) != sizeof (pm)) {
		mdb_warn("failed to read topo_propmethod at %p", addr);
		return;
	}
	if (mdb_readstr(mname, sizeof (mname), (uintptr_t)pm.tpm_name) < 0) {
		(void) mdb_snprintf(mname, sizeof (mname), "<%p>", pm.tpm_name);
	}

	mdb_printf("       method: %-32s version: %-16d args: %p\n",
	    mname, pm.tpm_version, pm.tpm_args);
}

/*
 * Dump the given property value. For the actual property values
 * we dump a pointer to the nvlist which can be decoded using the ::nvlist
 * dcmd from the libnvpair MDB module
 */
/*ARGSUSED*/
static int
dump_propval(uintptr_t addr, const void *data, void *arg)
{
	topo_proplist_t *plistp = (topo_proplist_t *)data;
	topo_propval_t pval;
	char name[32], *type;

	if (mdb_vread(&pval, sizeof (pval), (uintptr_t)plistp->tp_pval)
	    != sizeof (pval)) {

		mdb_warn("failed to read topo_propval_t at %p",
		    plistp->tp_pval);
		return (WALK_ERR);
	}
	if (mdb_readstr(name, sizeof (name), (uintptr_t)pval.tp_name) < 0) {
		(void) mdb_snprintf(name, sizeof (name), "<%p>", pval.tp_name);
	}
	switch (pval.tp_type) {
		case TOPO_TYPE_BOOLEAN: type = "boolean"; break;
		case TOPO_TYPE_INT32: type = "int32"; break;
		case TOPO_TYPE_UINT32: type = "uint32"; break;
		case TOPO_TYPE_INT64: type = "int64"; break;
		case TOPO_TYPE_UINT64: type = "uint64"; break;
		case TOPO_TYPE_STRING: type = "string"; break;
		case TOPO_TYPE_FMRI: type = "fmri"; break;
		case TOPO_TYPE_INT32_ARRAY: type = "int32[]"; break;
		case TOPO_TYPE_UINT32_ARRAY: type = "uint32[]"; break;
		case TOPO_TYPE_INT64_ARRAY: type = "int64[]"; break;
		case TOPO_TYPE_UINT64_ARRAY: type = "uint64[]"; break;
		case TOPO_TYPE_STRING_ARRAY: type = "string[]"; break;
		case TOPO_TYPE_FMRI_ARRAY: type = "fmri[]"; break;
		default: type = "unknown type";
	}
	mdb_printf("    %-32s %-16s value: %p\n", name, type, pval.tp_val);

	if (pval.tp_method != NULL)
		dump_propmethod((uintptr_t)pval.tp_method);

	return (WALK_NEXT);
}


/*
 * Dumps the contents of the property group.
 */
/*ARGSUSED*/
static int
dump_pgroup(uintptr_t addr, const void *data, void *arg)
{
	topo_pgroup_t *pgp = (topo_pgroup_t *)data;
	topo_ipgroup_info_t ipg;
	char buf[32];

	if (mdb_vread(&ipg, sizeof (ipg), (uintptr_t)pgp->tpg_info)
	    != sizeof (ipg)) {

		mdb_warn("failed to read topo_ipgroup_info_t at %p",
		    pgp->tpg_info);
		return (WALK_ERR);
	}
	if (mdb_readstr(buf, sizeof (buf), (uintptr_t)ipg.tpi_name) < 0) {
		mdb_warn("failed to read string at %p", ipg.tpi_name);
		return (WALK_ERR);
	}
	/*
	 * If this property group is the one we're interested in or if the user
	 * specified the "all" property group, we'll dump it
	 */
	if ((strncmp(pgrp, buf, sizeof (buf)) == 0) ||
	    (strncmp(pgrp, "all", sizeof (buf)) == 0)) {

		mdb_printf("  group: %-32s version: %d, stability: %s/%s\n",
		    buf, ipg.tpi_version, stab_lvls[ipg.tpi_namestab],
		    stab_lvls[ipg.tpi_datastab]);

		(void) mdb_pwalk("topo_proplist", dump_propval, NULL, curr_pg);
	}
	return (WALK_NEXT);
}


/*
 * Recursive function to dump the specified node and all of it's children
 */
/*ARGSUSED*/
static int
dump_tnode(uintptr_t addr, const void *data, void *arg)
{
	tnode_t node;
	char pname[255], buf[80], old_pname[255];

	if (!addr) {
		return (WALK_NEXT);
	}

	if (mdb_vread(&node, sizeof (node), addr) != sizeof (node)) {
		mdb_warn("failed to read tnode_t at %p", addr);
		return (WALK_ERR);
	}
	if (mdb_readstr(buf, sizeof (buf), (uintptr_t)node.tn_name) < 0) {
		(void) mdb_snprintf(buf, sizeof (buf), "<%p>",
		    node.tn_name);
	}

	if (is_root) {
		mdb_snprintf(pname, sizeof (pname), "%s", parent);
		is_root = 0;
	} else {
		mdb_snprintf(pname, sizeof (pname), "%s/%s=%u",
		    parent, buf, node.tn_instance);

		if (verbose)
			mdb_printf("%s\n  tnode_t: %p\n", pname, addr);
		else
			mdb_printf("%s\n", pname);
	}
	mdb_snprintf(old_pname, sizeof (old_pname), "%s", parent);
	mdb_snprintf(parent, sizeof (parent), "%s", pname);

	if (pgrp)
		(void) mdb_pwalk("topo_pgroup", dump_pgroup, NULL, addr);

	(void) mdb_pwalk("topo_nodehash", dump_tnode, NULL, addr);
	mdb_snprintf(parent, sizeof (parent), "%s", old_pname);

	return (WALK_NEXT);
}


/*
 * Given a topo_hdl_t *, the topo dcmd dumps the topo tree.  The format of the
 * output is modeled after fmtopo.  Like fmtopo, by default, we'll dump the
 * "hc" scheme tree.  The user can optionally specify a different tree via the
 * "-s <scheme>" option.
 *
 * Specifying the "-v" option provides more verbose output.  Currently it
 * outputs the tnode_t * addr for each node, which is useful if you want to
 * dump it with the topo_node dcmd.
 *
 * The functionality of the "-P" option is similar to fmtopo.
 */
/*ARGSUSED*/
static int
fmtopo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char product[36], *opt_s = NULL, *opt_P = NULL;
	topo_hdl_t th;
	tnode_t *tree_root;
	uint_t opt_v = FALSE;
	char *def_scheme = "hc";

	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, TRUE, &opt_v,
	    's', MDB_OPT_STR, &opt_s, 'P', MDB_OPT_STR, &opt_P, NULL)
	    != argc) {
		return (DCMD_USAGE);
	}

	if (opt_s) {
		tgt_scheme = opt_s;
	} else {
		tgt_scheme = def_scheme;
	}

	pgrp = opt_P;
	verbose = opt_v;
	is_root = 1;

	/*
	 * Read in the topo_handle and some of its string fields from
	 * the target's addr space
	 */
	if (mdb_vread(&th, sizeof (th), addr) != sizeof (th)) {
		mdb_warn("failed to read topo_hdl_t at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_readstr(product, sizeof (product), (uintptr_t)th.th_product)
	    < 0) {

		(void) mdb_snprintf(product, sizeof (product), "<%p>",
		    th.th_product);
	}

	mdb_snprintf(parent, sizeof (parent),
	    "%s://:product-id=%s", tgt_scheme, product);

	/*
	 * Walk the list of topo trees, looking for the one that is for the
	 * scheme we're interested in.
	 */
	tree_root = NULL;
	mdb_pwalk("topo_tree", find_tree_root, &tree_root, addr);

	if (! tree_root) {
		mdb_warn("failed to find a topo tree for scheme %s\n",
		    tgt_scheme);
		return (DCMD_ERR);
	}

	return (dump_tnode((uintptr_t)tree_root, NULL, NULL));
}


static int
ttree_walk_init(mdb_walk_state_t *wsp)
{
	topo_hdl_t th;

	if (wsp->walk_addr == NULL) {
		mdb_warn("NULL topo_hdl_t passed in");
		return (WALK_ERR);
	}

	if (mdb_vread(&th, sizeof (th), wsp->walk_addr) != sizeof (th)) {
		mdb_warn("failed to read topo_hdl_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)th.th_trees.l_next;
	wsp->walk_data = mdb_alloc(sizeof (ttree_t), UM_SLEEP);

	return (WALK_NEXT);
}


static int
ttree_walk_step(mdb_walk_state_t *wsp)
{
	int rv;
	ttree_t *tree;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (ttree_t), wsp->walk_addr)
	    != sizeof (ttree_t)) {

		mdb_warn("failed to read ttree_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	rv = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	tree = (ttree_t *)wsp->walk_data;
	wsp->walk_addr = (uintptr_t)tree->tt_list.l_next;

	return (rv);
}


static void
ttree_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (ttree_t));
}


static int
tmod_walk_init(mdb_walk_state_t *wsp)
{
	topo_hdl_t th;

	if (wsp->walk_addr == NULL) {
		mdb_warn("NULL topo_hdl_t passed in");
		return (WALK_ERR);
	}

	if (mdb_vread(&th, sizeof (th), wsp->walk_addr) != sizeof (th)) {
		mdb_warn("failed to read topo_hdl_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	if (mdb_vread(&tmh, sizeof (topo_modhash_t), (uintptr_t)th.th_modhash)
	    == -1) {

		mdb_warn("failed to read topo_modhash_t at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	hash_idx = 0;

	if (mdb_vread(&(wsp->walk_addr), sizeof (uintptr_t *),
	    (uintptr_t)(tmh.mh_hash)) != sizeof (tnode_t *)) {

		mdb_warn("failed to read %u bytes at %p", sizeof (tnode_t *),
		    tmh.mh_hash);
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_alloc(sizeof (topo_mod_t), UM_SLEEP);

	return (WALK_NEXT);
}


static int
tmod_walk_step(mdb_walk_state_t *wsp)
{
	int rv;
	topo_mod_t *tm;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (topo_mod_t), wsp->walk_addr)
	    == -1) {

		mdb_warn("failed to read topo_mod_t at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	rv = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	tm = (topo_mod_t *)wsp->walk_data;

	if (tm->tm_next)
		wsp->walk_addr = (uintptr_t)tm->tm_next;
	else if (++hash_idx < tmh.mh_hashlen)
		if (mdb_vread(&(wsp->walk_addr), sizeof (uintptr_t *),
		    (uintptr_t)(tmh.mh_hash+hash_idx)) != sizeof (tnode_t *)) {

			mdb_warn("failed to read %u bytes at %p",
			    sizeof (tnode_t *), tmh.mh_hash+hash_idx);
			return (DCMD_ERR);
		}
	else
		wsp->walk_addr = NULL;

	return (rv);
}

static void
tmod_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (topo_mod_t));
}


static int
tpg_walk_init(mdb_walk_state_t *wsp)
{
	tnode_t node;

	if (wsp->walk_addr == NULL) {
		mdb_warn("NULL tnode_t passed in");
		return (WALK_ERR);
	}

	if (mdb_vread(&node, sizeof (node), wsp->walk_addr) != sizeof (node)) {
		mdb_warn("failed to read tnode_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)node.tn_pgroups.l_next;
	wsp->walk_data = mdb_alloc(sizeof (topo_pgroup_t), UM_SLEEP);

	return (WALK_NEXT);
}


static int
tpg_walk_step(mdb_walk_state_t *wsp)
{
	int rv;
	topo_pgroup_t *tpgp;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (topo_pgroup_t), wsp->walk_addr)
	    == -1) {

		mdb_warn("failed to read topo_pgroup_t at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	curr_pg = wsp->walk_addr;
	rv = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	tpgp = (topo_pgroup_t *)wsp->walk_data;
	wsp->walk_addr = (uintptr_t)tpgp->tpg_list.l_next;

	return (rv);
}


static void
tpg_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (topo_pgroup_t));
}


static int
tpl_walk_init(mdb_walk_state_t *wsp)
{
	topo_pgroup_t pg;

	if (wsp->walk_addr == NULL) {
		mdb_warn("NULL topo_pgroup_t passed in");
		return (WALK_ERR);
	}

	if (mdb_vread(&pg, sizeof (pg), wsp->walk_addr) != sizeof (pg)) {
		mdb_warn("failed to read topo_pgroup_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)pg.tpg_pvals.l_next;
	wsp->walk_data = mdb_alloc(sizeof (topo_proplist_t), UM_SLEEP);

	return (WALK_NEXT);
}


static int
tpl_walk_step(mdb_walk_state_t *wsp)
{
	int rv;
	topo_proplist_t *plp;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (topo_proplist_t), wsp->walk_addr)
	    == -1) {

		mdb_warn("failed to read topo_proplist_t at %p",
		    wsp->walk_addr);
		return (WALK_DONE);
	}
	plp = (topo_proplist_t *)wsp->walk_data;

	rv = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)plp->tp_list.l_next;

	return (rv);
}


static void
tpl_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (topo_proplist_t));
}


static int
tnh_walk_init(mdb_walk_state_t *wsp)
{
	tnode_t node;
	tnwalk_state_t *state;

	if (wsp->walk_addr == NULL) {
		mdb_warn("NULL tnode_t passed in");
		return (WALK_ERR);
	}

	if (mdb_vread(&node, sizeof (node), wsp->walk_addr) != sizeof (node)) {
		mdb_warn("failed to read tnode_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	state = mdb_zalloc(sizeof (tnwalk_state_t), UM_SLEEP);

	state->curr_hash = (topo_nodehash_t *)node.tn_children.l_next;
	state->hash_idx = 0;
	wsp->walk_data = state;

	return (WALK_NEXT);
}


static int
tnh_walk_step(mdb_walk_state_t *wsp)
{
	tnwalk_state_t *state = wsp->walk_data;
	int rv, i = state->hash_idx++;
	tnode_t *npp;

	if (state->curr_hash == NULL)
		return (WALK_DONE);

	if (mdb_vread(&(state->hash), sizeof (topo_nodehash_t),
	    (uintptr_t)state->curr_hash) != sizeof (topo_nodehash_t)) {

		mdb_warn("failed to read topo_nodehash_t at %p",
		    (uintptr_t)state->curr_hash);
		return (WALK_ERR);
	}

	if (mdb_vread(&npp, sizeof (tnode_t *),
	    (uintptr_t)(state->hash.th_nodearr+i)) != sizeof (tnode_t *)) {

		mdb_warn("failed to read %u bytes at %p", sizeof (tnode_t *),
		    state->hash.th_nodearr+i);
		return (WALK_ERR);
	}
	wsp->walk_addr = (uintptr_t)npp;

	rv = wsp->walk_callback(wsp->walk_addr, state, wsp->walk_cbdata);

	if (state->hash_idx >= state->hash.th_arrlen) {
		/*
		 * move on to the next child hash bucket
		 */
		state->curr_hash =
		    (topo_nodehash_t *)(state->hash.th_list.l_next);
		state->hash_idx = 0;
	}

	return (rv);
}


static void
tnh_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (tnwalk_state_t));
}

static int
tlist_walk_init(mdb_walk_state_t *wsp)
{
	topo_list_t tl;

	if (wsp->walk_addr == NULL) {
		mdb_warn("NULL topo_list_t passed in\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&tl, sizeof (tl), wsp->walk_addr) == -1) {
		mdb_warn("failed to read topo_list_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)tl.l_next;
	wsp->walk_data = mdb_alloc(sizeof (topo_list_t), UM_SLEEP | UM_GC);

	return (WALK_NEXT);
}

static int
tlist_walk_step(mdb_walk_state_t *wsp)
{
	int rv;
	topo_list_t *tl;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (topo_list_t), wsp->walk_addr) ==
	    -1) {
		mdb_warn("failed to read topo_list_t at %p", wsp->walk_addr);
		return (WALK_DONE);
	}
	tl = (topo_list_t *)wsp->walk_data;

	rv = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)tl->l_next;

	return (rv);
}

static const mdb_dcmd_t dcmds[] = {
	{ "topo_handle", "", "print contents of a topo handle", topo_handle,
		NULL },
	{ "topo_module", "", "print contents of a topo module handle",
		topo_module, NULL },
	{ "topo_node", "", "print contents of a topo node", topo_node, NULL },
	{ "fmtopo", "[-P <pgroup>][-s <scheme>][-v]",
	    "print topology of the given handle", fmtopo, NULL },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "topo_tree", "walk the tree list for a given topo handle",
		ttree_walk_init, ttree_walk_step, ttree_walk_fini, NULL },
	{ "topo_module", "walk the module hash for a given topo handle",
		tmod_walk_init, tmod_walk_step, tmod_walk_fini, NULL },
	{ "topo_pgroup", "walk the property groups for a given topo node",
		tpg_walk_init, tpg_walk_step, tpg_walk_fini, NULL },
	{ "topo_proplist", "walk the property list for a given property group",
		tpl_walk_init, tpl_walk_step, tpl_walk_fini, NULL },
	{ "topo_nodehash", "walk the child nodehash for a given topo node",
		tnh_walk_init, tnh_walk_step, tnh_walk_fini, NULL },
	{ "topo_list", "walk a topo_list_t linked list",
		tlist_walk_init, tlist_walk_step, NULL, NULL },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
