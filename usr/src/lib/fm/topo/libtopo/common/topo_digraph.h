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
 * Copyright 2020 Joyent, Inc.
 */

#ifndef _TOPO_DIGRAPH_H
#define	_TOPO_DIGRAPH_H

#include <fm/topo_mod.h>

#include <topo_list.h>
#include <topo_prop.h>
#include <topo_method.h>
#include <topo_alloc.h>
#include <topo_error.h>
#include <topo_file.h>
#include <topo_module.h>
#include <topo_string.h>
#include <topo_subr.h>
#include <topo_tree.h>

#ifdef __cplusplus
extern "C" {
#endif

struct topo_digraph {
	topo_list_t	tdg_list;		/* next/prev pointers */
	const char	*tdg_scheme;		/* FMRI scheme */
	topo_mod_t	*tdg_mod;		/* builtin enumerator mod */
	tnode_t		*tdg_rootnode;		/* see topo_digraph_new() */
	topo_list_t	tdg_vertices;		/* adjacency list */
	uint_t		tdg_nvertices;		/* total num of vertices */
	uint_t		tdg_nedges;		/* total num of edges */
};

struct topo_vertex {
	topo_list_t	tvt_list;		/* next/prev pointers */
	tnode_t		*tvt_node;
	topo_list_t	tvt_incoming;
	topo_list_t	tvt_outgoing;
	uint_t		tvt_nincoming;		/* total num incoming edges */
	uint_t		tvt_noutgoing;		/* total num outgoing edges */
};

struct topo_edge {
	topo_list_t	tve_list;		/* next/prev pointers */
	topo_vertex_t	*tve_vertex;
};

#ifdef __cplusplus
}
#endif

#endif	/* _TOPO_DIGRAPH_H */
