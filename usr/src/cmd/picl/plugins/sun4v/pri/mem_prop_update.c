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

/*
 * The PRI plug-in picks up memory configuration data from the PRI
 * and injects this into PICL's /platform tree.  It only populates
 * the logical view of memory: memory, memory-segment, memory-bank.
 * It does not populate the /device tree since there are no memory
 * controller devices on sun4v.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "priplugin.h"
#include "../../common/memcfg/piclmemcfg.h"

static void
add_memory_props(picl_nodehdl_t node, mde_cookie_t memorylistp, md_t *mdp,
	uint64_t size);

static void
add_bank_props(picl_nodehdl_t node, mde_cookie_t banklistp,
	md_t *mdp, uint64_t *size, uint64_t *mask, unsigned int id);
static uint64_t countbits(uint64_t v);

static void
add_segment_props(picl_nodehdl_t node, mde_cookie_t segmentlistp,
	md_t *mdp, uint64_t interleave, uint64_t *size, uint64_t base);

/*
 * Callback function for picl_walk_tree_by_class().
 * NOTE: picl_walk_tree_by_class() maps the return codes PICL_WALK_CONTINUE
 * and PICL_WALK_TERMINATE to PICL_SUCCESS.
 */
int
add_mem_prop(picl_nodehdl_t node, void *args)
{
	mde_cookie_t *memorylistp, *segmentlistp, *banklistp;
	picl_prophdl_t memh, segmenth, bankh;
	mde_cookie_t *buf, md_rootnode;
	int j, k, num_nodes, interleave, err;
	int nsegments, nbanks, nmemory;
	uint64_t memsize, segsize, segbase;
	uint64_t size, mask;
	md_t *mdp = (md_t *)args;

	if (mdp == NULL)
		return (PICL_WALK_CONTINUE);

	md_rootnode = md_root_node(mdp);

	/*
	 * An absence of nodes or failure to obtain memory for searches
	 * or absence of the /memory node will cause this to fail.
	 * Return PICL_WALK_SUCCESS to allow the plug-in to continue.
	 */
	num_nodes = md_node_count(mdp);
	if (num_nodes == 0) {
		pri_debug(LOG_NOTICE, "add_mem_prop: no nodes to walk\n");
		return (PICL_SUCCESS);
	}
	buf = (mde_cookie_t *)malloc(sizeof (mde_cookie_t) * num_nodes * 3);
	if (buf == NULL) {
		pri_debug(LOG_NOTICE, "add_mem_prop: can't allocate memory\n");
		return (PICL_SUCCESS);
	}

	memorylistp = &buf[0];
	segmentlistp = &buf[num_nodes];
	banklistp = &buf[num_nodes * 2];

	if ((ptree_get_node_by_path(MEMORY_PATH, &memh)) != PICL_SUCCESS) {
		pri_debug(LOG_NOTICE,
		    "add_mem_prop: can't find /memory node in platform tree\n");
		free(buf);
		return (PICL_SUCCESS);
	}

	/*
	 * There should be only one memory node.
	 * If we can't find what we're looking for in the DAG then
	 * return PICL_PROPNOTFOUND to get the caller to re-try with
	 * a different property name.
	 */
	nmemory = md_scan_dag(mdp, md_rootnode, md_find_name(mdp,
	    "memory-segments"), md_find_name(mdp, "fwd"), memorylistp);
	if (nmemory != 1) {
		pri_debug(LOG_NOTICE,
		    "add_mem_prop: wrong number of memory dags: expected "
		    "1, got %d\n", nmemory);
		free(buf);
		return (PICL_PROPNOTFOUND);
	}

	nsegments = md_scan_dag(mdp, memorylistp[0],
	    md_find_name(mdp, "memory-segment"),
	    md_find_name(mdp, "fwd"),
	    segmentlistp);

	if (nsegments == 0) {
		pri_debug(LOG_NOTICE, "add_mem_prop: wrong number of memory "
		    "segments: expected >0, got %d\n", nsegments);
		free(buf);
		return (PICL_PROPNOTFOUND);
	}

	/*
	 * Add memory segments, keep running total of system memory.
	 */
	for (memsize = 0, segsize = 0, j = 0; j < nsegments;
	    ++j, memsize += segsize) {
		nbanks = 0;
		err = ptree_create_and_add_node(memh,
		    PICL_NAME_MEMORY_SEGMENT,
		    PICL_CLASS_MEMORY_SEGMENT, &segmenth);
		if (err == PICL_SUCCESS) {
			size = 0;
			mask = 0;

			/*
			 * Need to pull this out here since it's used for
			 * the ID.
			 */
			if (md_get_prop_val(mdp, segmentlistp[j], "base",
			    &segbase))
				segbase = 0ULL;

			/*
			 * Add banks under each segment.
			 */
			nbanks = md_scan_dag(mdp, segmentlistp[j],
			    md_find_name(mdp, "memory-bank"),
			    md_find_name(mdp, "fwd"),
			    banklistp);

			if (nbanks <= 0) {
				pri_debug(LOG_NOTICE, "add_mem_prop: no banks "
				    "found for segment %d\n", j);
			} else {
				for (k = 0; k < nbanks; ++k) {
					err =
					    ptree_create_and_add_node(segmenth,
					    PICL_NAME_MEMORY_BANK,
					    PICL_CLASS_MEMORY_BANK, &bankh);
					if (err == PICL_SUCCESS) {
						/*
						 * Add AddressMatch,
						 * AddressMask, Size, and
						 * ID to each bank.
						 */
						add_bank_props(bankh,
						    banklistp[k],
						    mdp,
						    &size, &mask,
						    (segbase >> 32) * j + k);
					}
				}
			}
		}

		/*
		 * Add Interleave, BaseAddress, and Size to each segment.
		 */
		interleave = 2 << (countbits(mask & (size - 1)) - 1);
		add_segment_props(segmenth, segmentlistp[j],
		    mdp, interleave, &segsize, segbase);
	}

	/*
	 * Add TransferSize and Size (total memory) to this node.
	 */
	add_memory_props(memh, memorylistp[0], mdp, memsize);

	free(buf);
	return (PICL_WALK_CONTINUE);
}

static void
add_bank_props(picl_nodehdl_t bankh, mde_cookie_t banklistp,
	md_t *mdp, uint64_t *size, uint64_t *mask, unsigned int id)
{
	uint64_t int_value;
	mde_cookie_t *dimmlistp;
	int node_count, i, type_size, nac_size, status;
	uint8_t *type;
	char *pc, *nac;
	picl_prophdl_t dimmh;

	*size = 0ULL;
	*mask = 0ULL;

	node_count = md_node_count(mdp);
	dimmlistp = (mde_cookie_t *)malloc(node_count * sizeof (mde_cookie_t));

	if (!md_get_prop_val(mdp, banklistp, "size", &int_value)) {
		add_md_prop(bankh, sizeof (int_value), PICL_PROP_SIZE,
		    &int_value, PICL_PTYPE_UNSIGNED_INT);
		*size = int_value;
	}
	if (!md_get_prop_val(mdp, banklistp, "mask",
	    &int_value)) {
		add_md_prop(bankh, sizeof (int_value),
		    PICL_PROP_ADDRESSMASK,
		    &int_value, PICL_PTYPE_UNSIGNED_INT);
		*mask = int_value;
	}
	if (!md_get_prop_val(mdp, banklistp, "match",
	    &int_value)) {
		add_md_prop(bankh, sizeof (int_value),
		    PICL_PROP_ADDRESSMATCH,
		    &int_value, PICL_PTYPE_UNSIGNED_INT);
	}

	add_md_prop(bankh, sizeof (id), PICL_PROP_ID, &id,
	    PICL_PTYPE_INT);

	node_count = md_scan_dag(mdp, banklistp, md_find_name(mdp, "component"),
	    md_find_name(mdp, "fwd"), dimmlistp);

	for (i = 0; i < node_count; ++i) {
		status = md_get_prop_str(mdp, dimmlistp[i], "type",
		    (char **)&type);
		if (status == -1) {
			status = md_get_prop_data(mdp, dimmlistp[i],
			    "type", &type, &type_size);
		}
		if (status == -1) /* can't get node type - just skip */
			continue;
		if (strcmp((const char *)type, "dimm") == 0) {
			if (md_get_prop_str(mdp, dimmlistp[i], "nac",
			    (char **)&nac) == 0) {
				nac_size = strlen(nac) + 1;
				if (ptree_create_and_add_node(bankh,
				    PICL_NAME_MEMORY_MODULE,
				    PICL_CLASS_MEMORY_MODULE, &dimmh) ==
				    PICL_SUCCESS) {
					add_md_prop(dimmh, nac_size,
					    "nac", nac,
					    PICL_PTYPE_CHARSTRING);
					if ((pc = strrchr(nac, '/')) != NULL)
						nac = ++pc;
					nac_size = strlen(nac) + 1;
					add_md_prop(dimmh, nac_size,
					    PICL_PROP_LABEL, nac,
					    PICL_PTYPE_CHARSTRING);
				}
			}
		}
	}
}

static uint64_t
countbits(uint64_t v)
{
	uint64_t c;	/* c accumulates the total bits set in v */

	for (c = 0; v; c++)
		v &= v - 1;	/* clear the least significant bit set */
	return (c);
}

static void
add_segment_props(picl_nodehdl_t node, mde_cookie_t segmentlistp,
    md_t *mdp, uint64_t interleave, uint64_t *size, uint64_t base)
{
	uint64_t int_value;

	*size = 0;
	if (!md_get_prop_val(mdp, segmentlistp, "size", &int_value)) {
		add_md_prop(node, sizeof (int_value),
		    PICL_PROP_SIZE, &int_value,
		    PICL_PTYPE_UNSIGNED_INT);
		*size = int_value;
	}
	add_md_prop(node, sizeof (base), PICL_PROP_BASEADDRESS,
	    &base, PICL_PTYPE_UNSIGNED_INT);

	add_md_prop(node, sizeof (interleave), PICL_PROP_INTERLEAVE_FACTOR,
	    &interleave, PICL_PTYPE_UNSIGNED_INT);
}

static void
add_memory_props(picl_nodehdl_t node, mde_cookie_t memorylistp, md_t *mdp,
	uint64_t size)
{
	uint64_t int_value;

	/*
	 * If the top-level node has a size property then use that,
	 * otherwise use the size that was calculated by the caller
	 * and passed in.
	 */
	if (md_get_prop_val(mdp, memorylistp, "size", &int_value))
		int_value = size;
	add_md_prop(node, sizeof (int_value), PICL_PROP_SIZE, &int_value,
	    PICL_PTYPE_UNSIGNED_INT);
	if (!md_get_prop_val(mdp, memorylistp, "transfer_size",
	    &int_value)) {
		add_md_prop(node, sizeof (int_value),
		    PICL_PROP_TRANSFER_SIZE,
		    &int_value, PICL_PTYPE_UNSIGNED_INT);
	}
}
