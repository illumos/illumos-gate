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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * This plugin creates memory configuration nodes and properties in the
 * PICL tree for Grover/Grover+ platform.
 *
 * Subtree of memory-controller in the physical aspect.
 * memory-controller --- memory-module
 * However, there is no memory controller node on Grover. Thus we need to
 * create it under platform.
 *
 * Subtree of memory in the logical aspect.
 * memory --- memory-segment
 * Add property _memory-module_ at memory-segment referring to the
 * memory-module since memory-segment equals to memory-module on Grover.
 *
 * Undo strategy:
 * Create all nodes and properties, or none if it fails in physical and
 * logical memory tree respectively. It keeps on creating logical
 * memory tree although it falis on physical logical tree, but no link to
 * memory module.
 *
 * NOTE:
 * It depends on PICL devtree plugin.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <alloca.h>
#include <syslog.h>
#include <string.h>
#include <libintl.h>
#include <picl.h>
#include <picltree.h>
#include <sys/types.h>
#include <sys/obpdefs.h>
#include "piclmemcfg.h"
#include "memcfg_impl.h"

static	void	piclmemcfg_register(void);
static	void	piclmemcfg_init(void);
static	void	piclmemcfg_fini(void);

#pragma	init(piclmemcfg_register)

static picld_plugin_reg_t  my_reg_info = {
	PICLD_PLUGIN_VERSION_1,
	PICLD_PLUGIN_NON_CRITICAL,
	"SUNW_piclmemcfg",
	piclmemcfg_init,
	piclmemcfg_fini
};

/*
 * Create logical memory tree
 * memory --- memory-segment
 */
static int
create_logical_tree(picl_nodehdl_t memh, mmodinfo_t *mmodinfo)
{
	picl_nodehdl_t		msegh;
	picl_nodehdl_t		*memsegh;
	ptree_propinfo_t	propinfo;
	uint32_t		ifactor = INTERLEAVEFACTOR;
	int			i;
	int			err = PICL_SUCCESS;

	if ((memsegh = alloca(sizeof (picl_nodehdl_t) * TOTAL_MEM_SLOTS)) ==
	    NULL)
		return (PICL_FAILURE);

	for (i = 0; i < TOTAL_MEM_SLOTS; i++) {
		/*
		 * It means no segment for the slot if size is zero
		 */
		if (mmodinfo[i].size == 0) {
			memsegh[i] = 0;
			continue;
		}

		/*
		 * Create memory-segment node under memory
		 */
		err = ptree_create_and_add_node(memh, PICL_NAME_MEMORY_SEGMENT,
		    PICL_CLASS_MEMORY_SEGMENT, &msegh);
		if (err != PICL_SUCCESS)
			break;

		/*
		 * For undo easily later
		 */
		memsegh[i] = msegh;

		/*
		 * Add property, Size to memory-segment node
		 */
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_UNSIGNED_INT, PICL_READ,
		    sizeof (mmodinfo[i].size), PICL_PROP_SIZE, NULL, NULL);
		if (err != PICL_SUCCESS)
			break;

		err = ptree_create_and_add_prop(msegh, &propinfo,
		    &mmodinfo[i].size, NULL);
		if (err != PICL_SUCCESS)
			break;

		/*
		 * Add property, BaseAddress to memory-segment node
		 */
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_UNSIGNED_INT, PICL_READ,
		    sizeof (mmodinfo[i].base), PICL_PROP_BASEADDRESS, NULL,
		    NULL);
		if (err != PICL_SUCCESS)
			break;

		err = ptree_create_and_add_prop(msegh, &propinfo,
		    &mmodinfo[i].base, NULL);
		if (err != PICL_SUCCESS)
			break;

		/*
		 * Add property, InterleaveFactor to memory-segment node
		 */
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_UNSIGNED_INT, PICL_READ, sizeof (ifactor),
		    PICL_PROP_INTERLEAVE_FACTOR, NULL, NULL);
		if (err != PICL_SUCCESS)
			break;

		err = ptree_create_and_add_prop(msegh, &propinfo, &ifactor,
		    NULL);
		if (err != PICL_SUCCESS)
			break;

		/*
		 * Add reference property to the memory module if memory
		 * module node handle is not NULL.
		 */
		if (mmodinfo[i].memmodh == 0)
			continue;

		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_REFERENCE, PICL_READ, sizeof (picl_nodehdl_t),
		    PICL_REFPROP_MEMORY_MODULE, NULL, NULL);
		if (err != PICL_SUCCESS)
			break;

		err = ptree_create_and_add_prop(msegh, &propinfo,
		    &mmodinfo[i].memmodh, NULL);
		if (err != PICL_SUCCESS)
			break;
	}

	if (err != PICL_SUCCESS) {
		/*
		 * Undo in the logical memory tree
		 */
		for (i = 0; i < TOTAL_MEM_SLOTS; i++) {
			if (memsegh[i] == 0)
				continue;

			(void) ptree_delete_node(memsegh[i]);
			(void) ptree_destroy_node(memsegh[i]);
		}
	}

	return (err);
}

/*
 * Create physical memory tree
 * memory-controller --- memory-module
 */
static int
create_physical_tree(picl_nodehdl_t plfh, mmodinfo_t *mmodinfo)
{
	picl_nodehdl_t		mch, memmodh;
	ptree_propinfo_t	propinfo;
	int			i;
	int			err = PICL_SUCCESS;
	uint32_t		id;

	/*
	 * Create memory-controller node under platform
	 */
	err = ptree_create_and_add_node(plfh, PICL_NAME_MEMORY_CONTROLLER,
	    PICL_CLASS_MEMORY_CONTROLLER, &mch);
	if (err != PICL_SUCCESS)
		return (err);

	/*
	 * Create memory-module nodes and properties
	 * Get all memory modules with dimm
	 */
	for (i = 0; i < TOTAL_MEM_SLOTS; i++) {
		/*
		 * It means no dimm on the slot if size is zero
		 */
		if (mmodinfo[i].size == 0)
			continue;

		/* Create memory-module node under memory-controller */
		err = ptree_create_and_add_node(mch, PICL_NAME_MEMORY_MODULE,
		    PICL_CLASS_MEMORY_MODULE, &memmodh);
		if (err != PICL_SUCCESS)
			break;

		/*
		 * Update memory module node handle at mmodinfo
		 */
		mmodinfo[i].memmodh = memmodh;

		/*
		 * Add property, Size to memory-module node
		 */
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_UNSIGNED_INT, PICL_READ,
		    sizeof (mmodinfo[i].size), PICL_PROP_SIZE, NULL, NULL);
		if (err != PICL_SUCCESS)
			break;

		err = ptree_create_and_add_prop(memmodh, &propinfo,
		    &mmodinfo[i].size, NULL);
		if (err != PICL_SUCCESS)
			break;

		/*
		 * Add property, ID to memory-module node
		 */
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_INT, PICL_READ, sizeof (id), PICL_PROP_ID,
		    NULL, NULL);
		if (err != PICL_SUCCESS)
			break;

		id = i;
		err = ptree_create_and_add_prop(memmodh, &propinfo, &id, NULL);
		if (err != PICL_SUCCESS)
			break;
	}

	if (err != PICL_SUCCESS) {
		/*
		 * Clear out the saved memory module node handle so that
		 * logical memory tree won't link to memory module.
		 */
		for (i = 0; i < TOTAL_MEM_SLOTS; i++)
			mmodinfo[i].memmodh = 0;

		/*
		 * Undo in the physical memory tree
		 */
		(void) ptree_delete_node(mch);
		(void) ptree_destroy_node(mch);
	}

	return (err);
}

/*
 * Get the memory module and memory segment information from
 * property reg of memory node.
 *
 * mmodinfo will be updated. Also, the pointers to mseginfo and
 * the number of segments will be passed to the caller.
 */
static int
get_reg_info(picl_nodehdl_t plfh, picl_nodehdl_t memh,
    mmodinfo_t *mmodinfo)
{
	picl_prophdl_t		proph;
	ptree_propinfo_t	pinfo;
	regspec_t		*memspec;
	int			i, err;
	int			pval;
	int			nregspec;


	/*
	 * Check if the #size-cells of the platform node is 2
	 */
	err = ptree_get_propval_by_name(plfh, OBP_PROP_SIZE_CELLS, &pval,
	    sizeof (pval));

	if (err == PICL_PROPNOTFOUND)
		pval = SUPPORTED_NUM_CELL_SIZE;
	else if (err != PICL_SUCCESS)
		return (err);

	/*
	 * don't know to handle other vals
	 */
	if (pval != SUPPORTED_NUM_CELL_SIZE)
		return (PICL_FAILURE);

	/*
	 * Get property reg of memory node
	 */
	err = ptree_get_prop_by_name(memh, OBP_REG, &proph);
	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_get_propinfo(proph, &pinfo);
	if (err != PICL_SUCCESS)
		return (err);

	if ((memspec = alloca(pinfo.piclinfo.size)) == NULL)
		return (PICL_FAILURE);

	nregspec = pinfo.piclinfo.size / sizeof (*memspec);

	if ((nregspec == 0) || (nregspec > TOTAL_MEM_SLOTS))
		return (PICL_FAILURE);

	err = ptree_get_propval(proph, memspec, pinfo.piclinfo.size);
	if (err != PICL_SUCCESS)
		return (err);


	for (i = 0; i < nregspec; i++) {

		mmodinfo[i].base = memspec[i].physaddr;
		mmodinfo[i].size = memspec[i].size;

	}

	return (PICL_SUCCESS);
}

/*
 * executed as part of .init when the plugin is dlopen()ed
 */
static void
piclmemcfg_register(void)
{
	(void) picld_plugin_register(&my_reg_info);
}

/*
 * Init entry point of the plugin
 * Creates the PICL nodes and properties in the physical and logical aspects.
 */
static void
piclmemcfg_init(void)
{
	picl_nodehdl_t		plfh, memh;
	mmodinfo_t		mmodinfo[TOTAL_MEM_SLOTS];

	/*
	 * Get platform node
	 */
	if ((ptree_get_node_by_path(PLATFORM_PATH, &plfh)) != PICL_SUCCESS) {
		syslog(LOG_ERR, EM_INIT_FAILED);
		return;
	}

	/*
	 * Find the memory node
	 */
	if ((ptree_get_node_by_path(MEMORY_PATH, &memh)) != PICL_SUCCESS) {
		syslog(LOG_ERR, EM_INIT_FAILED);
		return;
	}

	/*
	 * Initialize the mmodinfo and get segment information from reg
	 */
	(void) memset(mmodinfo, 0, sizeof (mmodinfo));

	if ((get_reg_info(plfh, memh, mmodinfo)) != PICL_SUCCESS) {
		syslog(LOG_ERR, EM_INIT_FAILED);
		return;
	}

	/*
	 * Create subtree of memory-controller in the physical aspect.
	 * memory-controller --- memory-module
	 */
	if ((create_physical_tree(plfh, mmodinfo)) != PICL_SUCCESS)
		syslog(LOG_ERR, EM_PHYSIC_MEM_TREE_FAILED);

	/*
	 * Create subtree of memory in the logical aspect.
	 * memory --- memory-segment
	 */
	if ((create_logical_tree(memh, mmodinfo)) != PICL_SUCCESS)
		syslog(LOG_ERR, EM_LOGIC_MEM_TREE_FAILED);
}

/*
 * fini entry point of the plugin
 */
static void
piclmemcfg_fini(void)
{
}
