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

/*
 * This file implements a set of APIs for creating, destroying and traversing
 * directed-graph (digraph) topologies.  The API is split into categories:
 * client API and module API.
 *
 * The client API can be used by libtopo consumers for traversing an existing
 * digraph topology.  The module API can be used by topo plugins to create or
 * destroy a digraph topology.
 *
 * client API
 * ----------
 * topo_digraph_get
 * topo_vertex_iter
 * topo_vertex_node
 * topo_edge_iter
 * topo_digraph_paths
 * topo_path_destroy
 *
 * module API
 * ----------
 * topo_digraph_new
 * topo_digraph_destroy
 * topo_vertex_new
 * topo_vertex_destroy
 * topo_edge_new
 *
 * A digraph is represented in-core by a topo_digraph_t structure which
 * maintains an adjacency list of vertices (see topo_digraph.h).  Vertices
 * are represented by topo_vertex_t structures which are essentially thin
 * wrappers around topo node (tnode_t) structures.  In addition to holding
 * a pointer to the underlyng topo node, the topo_vertex_t maintains a list
 * of incoming and outgoing edges and a pointer to the next and previous
 * vertices in digraph's adjecency list.
 *
 * Locking
 * -------
 * The module APIs should only be used during snapshot creation, which is
 * single-threaded, or as the result of a call to topo_snap_release() or
 * topo_close().  While libtopo does prevent concurrent calls to
 * topo_snap_release() and topo_close() via the topo_hdl_t lock, there is no
 * mechanism currently that prevents the situation where one or more threads
 * were to access the snapshot (e.g. they've got a cached tnode_t ptr or are
 * walking the snapshot) while another thread is calling topo_snap_release()
 * or topo_close().  The same is true for tree topologies.  It is up to the
 * library consumer to provide their own synchronization or reference counting
 * mechanism for that case. For example, fmd implements a reference counting
 * mechanism around topo snapshots so that individual fmd modules can safely
 * cache pointers to a given topo snapshot.
 *
 * None of the client APIs modify the state of the graph structure once
 * the snapshot is created.  The exception is the state of the underlyng topo
 * nodes for each vertex, who's properties may change as a result of the
 * following:
 *
 * 1) topo_prop_get operations for properties that are backed by topo methods
 * 2) topo_prop_set operations.
 *
 * For both of the above situations, synchronization is enforced by the per-node
 * locks. Thus there a no locks used for synchronizing access to
 * the topo_digraph_t or topo_vertex_t structures.
 *
 * path scheme FMRIs
 * -----------------
 * For digraph topologies it is useful to be able to treat paths between
 * vertices as resources and thus have a way to represent a unique path
 * between those vertices.  The path FMRI scheme is used for this purpose and
 * has the following form:
 *
 * path://scheme=<scheme>/<nodename>=<instance>/...
 *
 * The path FMRI for a path from one vertex to another vertex is represented by
 * a sequence of nodename/instance pairs where each pair represents a vertex on
 * the path between the two vertices.  The first nodename/instance pair
 * represents the "from" vertex and the last nodename/instance pair represents
 * the "to" vertex.
 *
 * For example, the path FMRI to represent a path from an initiator to a
 * target in a SAS scheme digraph might look like this:
 *
 * path://scheme=sas/initiator=5003048023567a00/port=5003048023567a00/
 *       port=500304801861347f/expander=500304801861347f/port=500304801861347f/
 *       port=5000c500adc881d5/target=5000c500adc881d4
 *
 * This file implements NVL2STR and STR2NVL methods for path-scheme FMRIs.
 */

#include <libtopo.h>
#include <sys/fm/protocol.h>

#include <topo_digraph.h>
#include <topo_method.h>

#define	__STDC_FORMAT_MACROS
#include <inttypes.h>


extern int path_fmri_str2nvl(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
extern int path_fmri_nvl2str(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

static const topo_method_t digraph_root_methods[] = {
	{ TOPO_METH_PATH_STR2NVL, TOPO_METH_STR2NVL_DESC,
	    TOPO_METH_STR2NVL_VERSION, TOPO_STABILITY_INTERNAL,
	    path_fmri_str2nvl },
	{ TOPO_METH_PATH_NVL2STR, TOPO_METH_NVL2STR_DESC,
	    TOPO_METH_NVL2STR_VERSION, TOPO_STABILITY_INTERNAL,
	    path_fmri_nvl2str },
	{ NULL }
};

/*
 * On success, returns a pointer to the digraph for the specified FMRI scheme.
 * On failure, returns NULL.
 */
topo_digraph_t *
topo_digraph_get(topo_hdl_t *thp, const char *scheme)
{
	topo_digraph_t *tdg;

	for (tdg = topo_list_next(&thp->th_digraphs); tdg != NULL;
	    tdg = topo_list_next(tdg)) {
		if (strcmp(scheme, tdg->tdg_scheme) == 0)
			return (tdg);
	}
	return (NULL);
}

static topo_digraph_t *
find_digraph(topo_mod_t *mod)
{
	return (topo_digraph_get(mod->tm_hdl, mod->tm_info->tmi_scheme));
}

/*
 * On successs, allocates a new topo_digraph_t structure for the requested
 * scheme.  The caller is responsible for free all memory allocated for this
 * structure when done via a call to topo_digraph_destroy().
 *
 * On failure, this function returns NULL and sets topo errno.
 */
topo_digraph_t *
topo_digraph_new(topo_hdl_t *thp, topo_mod_t *mod, const char *scheme)
{
	topo_digraph_t *tdg;
	tnode_t *tn = NULL;

	if ((tdg = topo_mod_zalloc(mod, sizeof (topo_digraph_t))) == NULL) {
		(void) topo_hdl_seterrno(thp, ETOPO_NOMEM);
		return (NULL);
	}

	tdg->tdg_mod = mod;

	if ((tdg->tdg_scheme = topo_mod_strdup(mod, scheme)) == NULL) {
		(void) topo_hdl_seterrno(thp, ETOPO_NOMEM);
		goto err;
	}

	/*
	 * For digraph topologies, the "root" node, which gets passed in to
	 * the scheme module's enum method is not part of the actual graph
	 * structure per-se.
	 * Its purpose is simply to provide a place on which to register the
	 * scheme-specific methods.  Client code then invokes these methods via
	 * the topo_fmri_* interfaces.
	 */
	if ((tn = topo_mod_zalloc(mod, sizeof (tnode_t))) == NULL)
		goto err;

	/*
	 * Adding the TOPO_NODE_ROOT state to the node has the effect of
	 * preventing topo_node_destroy() from trying to clean up the parent
	 * node's node hash, which is only necessary in tree topologies.
	 */
	tn->tn_state = TOPO_NODE_ROOT | TOPO_NODE_INIT;
	tn->tn_name = (char *)scheme;
	tn->tn_instance = 0;
	tn->tn_enum = mod;
	tn->tn_hdl = thp;
	topo_node_hold(tn);

	tdg->tdg_rootnode = tn;
	if (topo_method_register(mod, tn, digraph_root_methods) != 0) {
		topo_mod_dprintf(mod, "failed to register digraph root "
		    "methods");
		/* errno set */
		return (NULL);
	}

	/* This is released during topo_digraph_destroy() */
	topo_mod_hold(mod);

	return (tdg);
err:
	topo_mod_free(mod, tdg, sizeof (topo_digraph_t));
	return (NULL);
}

/*
 * Deallocates all memory associated with the specified topo_digraph_t.
 *
 * This only frees the memory allocated during topo_digraph_new().  To free the
 * actual graph vertices one should call topo_snap_destroy() prior to calling
 * topo_digraph_destroy().
 *
 * Calling topo_close() will also result in a call to topo_snap_destroy() and
 * topo_digraph_dstroy() for all digraphs associated with the library handle.
 *
 * This function is a NOP if NULL is passed in.
 */
void
topo_digraph_destroy(topo_digraph_t *tdg)
{
	topo_mod_t *mod;

	if (tdg == NULL)
		return;

	mod = tdg->tdg_mod;
	topo_method_unregister_all(mod, tdg->tdg_rootnode);
	topo_mod_strfree(mod, (char *)tdg->tdg_scheme);
	topo_mod_free(mod, tdg->tdg_rootnode, sizeof (tnode_t));
	topo_mod_free(mod, tdg, sizeof (topo_digraph_t));
	topo_mod_rele(mod);
}

/*
 * This function creates a new vertex and adds it to the digraph associated
 * with the module.
 *
 * name: name of the vertex
 * instance: instance number of the vertex
 *
 * On success, it returns a pointer to the allocated topo_vertex_t associated
 * with the new vertex.  The caller is responsible for free-ing this structure
 * via a call to topo_vertex_destroy().
 *
 * On failures, this function returns NULL and sets topo_mod_errno.
 */
topo_vertex_t *
topo_vertex_new(topo_mod_t *mod, const char *name, topo_instance_t inst)
{
	tnode_t *tn = NULL;
	topo_vertex_t *vtx = NULL;
	topo_digraph_t *tdg;

	topo_mod_dprintf(mod, "Creating vertex %s=%" PRIx64 "", name, inst);
	if ((tdg = find_digraph(mod)) == NULL) {
		topo_mod_dprintf(mod, "%s faild: no existing digraph for FMRI "
		    " scheme %s", __func__, mod->tm_info->tmi_scheme);
		return (NULL);
	}
	if ((vtx = topo_mod_zalloc(mod, sizeof (topo_vertex_t))) == NULL ||
	    (tn = topo_mod_zalloc(mod, sizeof (tnode_t))) == NULL) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}
	if ((tn->tn_name = topo_mod_strdup(mod, name)) == NULL) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}
	tn->tn_enum = mod;
	tn->tn_hdl = mod->tm_hdl;
	tn->tn_vtx = vtx;
	tn->tn_instance = inst;
	/*
	 * Adding the TOPO_NODE_ROOT state to the node has the effect of
	 * preventing topo_node_destroy() from trying to clean up the parent
	 * node's node hash, which is only necessary in tree topologies.
	 */
	tn->tn_state = TOPO_NODE_ROOT | TOPO_NODE_BOUND;
	vtx->tvt_node = tn;
	topo_node_hold(tn);

	/* Bump the refcnt on the module that's creating this vertex. */
	topo_mod_hold(mod);

	if (tdg->tdg_nvertices == UINT32_MAX) {
		topo_mod_dprintf(mod, "Max vertices reached!");
		(void) topo_mod_seterrno(mod, EMOD_DIGRAPH_MAXSZ);
		topo_mod_rele(mod);
		goto err;
	}
	tdg->tdg_nvertices++;
	topo_list_append(&tdg->tdg_vertices, vtx);

	return (vtx);
err:
	topo_mod_dprintf(mod, "failed to add create vertex %s=%" PRIx64 "(%s)",
	    name, inst, topo_strerror(topo_mod_errno(mod)));
	if (tn != NULL) {
		topo_mod_strfree(mod, tn->tn_name);
		topo_mod_free(mod, tn, sizeof (tnode_t));
	}
	if (vtx != NULL)
		topo_mod_free(mod, vtx, sizeof (topo_vertex_t));

	return (NULL);
}

/*
 * Returns the underlying tnode_t structure for the specified vertex.
 */
tnode_t *
topo_vertex_node(topo_vertex_t *vtx)
{
	return (vtx->tvt_node);
}

/*
 * Convenience interface for deallocating a topo_vertex_t
 * This function is a NOP if NULL is passed in.
 */
void
topo_vertex_destroy(topo_mod_t *mod, topo_vertex_t *vtx)
{
	topo_edge_t *edge;

	if (vtx == NULL)
		return;

	topo_node_unbind(vtx->tvt_node);

	edge = topo_list_next(&vtx->tvt_incoming);
	while (edge != NULL) {
		topo_edge_t *tmp = edge;

		edge = topo_list_next(edge);
		topo_mod_free(mod, tmp, sizeof (topo_edge_t));
	}

	edge = topo_list_next(&vtx->tvt_outgoing);
	while (edge != NULL) {
		topo_edge_t *tmp = edge;

		edge = topo_list_next(edge);
		topo_mod_free(mod, tmp, sizeof (topo_edge_t));
	}

	topo_mod_free(mod, vtx, sizeof (topo_vertex_t));
}

/*
 * This function can be used to iterate over all of the vertices in the
 * specified digraph.  The specified callback function is invoked for each
 * vertices.  Callback function should return the standard topo walker
 * (TOPO_WALK_*) return values.
 *
 * On success, this function returns 0.
 *
 * On failure this function returns -1.
 */
int
topo_vertex_iter(topo_hdl_t *thp, topo_digraph_t *tdg,
    int (*func)(topo_hdl_t *, topo_vertex_t *, boolean_t, void *), void *arg)
{
	uint_t n = 0;

	for (topo_vertex_t *vtx = topo_list_next(&tdg->tdg_vertices);
	    vtx != NULL; vtx = topo_list_next(vtx), n++) {
		int ret;
		boolean_t last_vtx = B_FALSE;

		if (n == (tdg->tdg_nvertices - 1))
			last_vtx = B_TRUE;

		ret = func(thp, vtx, last_vtx, arg);

		switch (ret) {
		case TOPO_WALK_NEXT:
			continue;
		case TOPO_WALK_TERMINATE:
			goto out;
		case TOPO_WALK_ERR:
		default:
			return (-1);
		}
	}
out:
	return (0);
}

/*
 * Add a new outgoing edge the vertex "from" to the vertex "to".
 *
 * On success, this functions returns 0.
 *
 * On failure, this function returns -1.
 */
int
topo_edge_new(topo_mod_t *mod, topo_vertex_t *from, topo_vertex_t *to)
{
	topo_digraph_t *tdg;
	topo_edge_t *e_from = NULL, *e_to = NULL;

	topo_mod_dprintf(mod, "Adding edge from vertex %s=%" PRIx64 " to "
	    "%s=%" PRIx64"", topo_node_name(from->tvt_node),
	    topo_node_instance(from->tvt_node),
	    topo_node_name(to->tvt_node), topo_node_instance(to->tvt_node));

	if ((tdg = find_digraph(mod)) == NULL) {
		topo_mod_dprintf(mod, "Digraph lookup failed");
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}
	if (from->tvt_noutgoing == UINT32_MAX ||
	    to->tvt_nincoming == UINT32_MAX ||
	    tdg->tdg_nedges == UINT32_MAX) {
		topo_mod_dprintf(mod, "Max edges reached!");
		return (topo_mod_seterrno(mod, EMOD_DIGRAPH_MAXSZ));

	}
	if ((e_from = topo_mod_zalloc(mod, sizeof (topo_edge_t))) == NULL ||
	    (e_to = topo_mod_zalloc(mod, sizeof (topo_edge_t))) == NULL) {
		topo_mod_free(mod, e_from, sizeof (topo_edge_t));
		topo_mod_free(mod, e_to, sizeof (topo_edge_t));
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}
	e_from->tve_vertex = from;
	e_to->tve_vertex = to;

	topo_list_append(&from->tvt_outgoing, e_to);
	from->tvt_noutgoing++;
	topo_list_append(&to->tvt_incoming, e_from);
	to->tvt_nincoming++;
	tdg->tdg_nedges++;

	return (0);
}

/*
 * This function can be used to iterate over all of the outgoing edges in
 * for specified vertex.  The specified callback function is invoked for each
 * edge.  Callback function should return the standard topo walker
 * (TOPO_WALK_*) return values.
 *
 * On success, this function returns 0.
 *
 * On failure this function returns -1.
 */
int
topo_edge_iter(topo_hdl_t *thp, topo_vertex_t *vtx,
    int (*func)(topo_hdl_t *, topo_edge_t *, boolean_t, void *), void *arg)
{
	uint_t n = 0;

	for (topo_edge_t *edge = topo_list_next(&vtx->tvt_outgoing);
	    edge != NULL; edge = topo_list_next(edge), n++) {
		int ret;
		boolean_t last_edge = B_FALSE;

		if (n == (vtx->tvt_noutgoing - 1))
			last_edge = B_TRUE;

		ret = func(thp, edge, last_edge, arg);

		switch (ret) {
		case TOPO_WALK_NEXT:
			continue;
		case TOPO_WALK_TERMINATE:
			break;
		case TOPO_WALK_ERR:
		default:
			return (-1);
		}
	}
	return (0);
}

/*
 * Convenience interface for deallocating a topo_path_t
 * This function is a NOP if NULL is passed in.
 */
void
topo_path_destroy(topo_hdl_t *thp, topo_path_t *path)
{
	topo_path_component_t *pathcomp;

	if (path == NULL)
		return;

	topo_hdl_strfree(thp, (char *)path->tsp_fmristr);
	nvlist_free(path->tsp_fmri);

	pathcomp = topo_list_next(&path->tsp_components);
	while (pathcomp != NULL) {
		topo_path_component_t *tmp = pathcomp;

		pathcomp = topo_list_next(pathcomp);
		topo_hdl_free(thp, tmp, sizeof (topo_path_component_t));
	}

	topo_hdl_free(thp, path, sizeof (topo_path_t));
}

/*
 * This just wraps topo_path_t so that visit_vertex() can build a linked list
 * of paths.
 */
struct digraph_path {
	topo_list_t	dgp_link;
	topo_path_t	*dgp_path;
};

/*
 * This is a callback function for the vertex iteration that gets initiated by
 * topo_digraph_paths().
 *
 * This is used to implement a depth-first search for all paths that lead to
 * the vertex pointed to by the "to" parameter.  As we walk the graph we
 * maintain a linked list of the components (vertices) in the in-progress path
 * as well as the string form of the current path being walked.  Whenever we
 * eoncounter the "to" vertex, we save the current path to the all_paths list
 * (which keeps track of all the paths we've found to the "to" vertex) and
 * increment npaths (which keeps track of the number of paths we've found to
 * the "to" vertex).
 */
static int
visit_vertex(topo_hdl_t *thp, topo_vertex_t *vtx, topo_vertex_t *to,
    topo_list_t *all_paths, const char *curr_path,
    topo_list_t *curr_path_comps, uint_t *npaths)
{
	struct digraph_path *pathnode = NULL;
	topo_path_t *path = NULL;
	topo_path_component_t *pathcomp = NULL;
	nvlist_t *fmri = NULL;
	char *pathstr;
	int err;

	if (asprintf(&pathstr, "%s/%s=%" PRIx64"",
	    curr_path,
	    topo_node_name(vtx->tvt_node),
	    topo_node_instance(vtx->tvt_node)) < 0) {
		return (topo_hdl_seterrno(thp, ETOPO_NOMEM));
	}

	/*
	 * Check if this vertex is in the list of vertices in the
	 * curr_path_comps list.  If it is, then we've encountered a cycle
	 * and need to turn back.
	 */
	for (topo_path_component_t *pc = topo_list_next(curr_path_comps);
	    pc != NULL; pc = topo_list_next(pc)) {
		if (pc->tspc_vertex == vtx) {
			topo_dprintf(thp, TOPO_DBG_WALK, "Cycle detected: %s",
			    pathstr);
			free(pathstr);
			return (0);
		}
	}

	if ((pathcomp = topo_hdl_zalloc(thp, sizeof (topo_path_component_t)))
	    == NULL) {
		(void) topo_hdl_seterrno(thp, ETOPO_NOMEM);
		goto err;
	}
	pathcomp->tspc_vertex = vtx;
	topo_list_append(curr_path_comps, pathcomp);

	if (vtx == to) {
		(*npaths)++;
		pathnode = topo_hdl_zalloc(thp, sizeof (struct digraph_path));

		if ((path = topo_hdl_zalloc(thp, sizeof (topo_path_t))) ==
		    NULL ||
		    (path->tsp_fmristr = topo_hdl_strdup(thp, pathstr)) ==
		    NULL) {
			(void) topo_hdl_seterrno(thp, ETOPO_NOMEM);
			goto err;
		}

		if (topo_list_deepcopy(thp, &path->tsp_components,
		    curr_path_comps, sizeof (topo_path_component_t)) != 0) {
			(void) topo_hdl_seterrno(thp, ETOPO_NOMEM);
		}
		if (topo_fmri_str2nvl(thp, pathstr, &fmri, &err) != 0) {
			/* errno set */
			goto err;
		}
		path->tsp_fmri = fmri;
		pathnode->dgp_path = path;

		topo_list_append(all_paths, pathnode);
		free(pathstr);
		topo_list_delete(curr_path_comps, pathcomp);
		topo_hdl_free(thp, pathcomp, sizeof (topo_path_component_t));
		return (0);
	}

	for (topo_edge_t *edge = topo_list_next(&vtx->tvt_outgoing);
	    edge != NULL; edge = topo_list_next(edge)) {

		if (visit_vertex(thp, edge->tve_vertex, to, all_paths, pathstr,
		    curr_path_comps, npaths) != 0)
			goto err;
	}

	free(pathstr);
	topo_list_delete(curr_path_comps, pathcomp);
	topo_hdl_free(thp, pathcomp, sizeof (topo_path_component_t));
	return (0);

err:
	free(pathstr);
	topo_hdl_free(thp, pathnode, sizeof (struct digraph_path));
	topo_path_destroy(thp, path);
	return (-1);
}

/*
 * On success, 0 is returns and the "paths" parameter is populated with an
 * array of topo_path_t structs representing all paths from the "from" vertex
 * to the "to" vertex.  The caller is responsible for freeing this array.  The
 * "npaths" parameter will be populated with the number of paths found or 0 if
 * no paths were found.
 *
 * On error, -1 is returned.
 */
int
topo_digraph_paths(topo_hdl_t *thp, topo_digraph_t *tdg, topo_vertex_t *from,
    topo_vertex_t *to, topo_path_t ***paths, uint_t *npaths)
{
	topo_list_t all_paths = { 0 };
	char *curr_path;
	topo_path_component_t *pathcomp = NULL;
	topo_list_t curr_path_comps = { 0 };
	struct digraph_path *path;
	uint_t i;
	int ret;

	if (asprintf(&curr_path, "%s://%s=%s/%s=%" PRIx64"",
	    FM_FMRI_SCHEME_PATH, FM_FMRI_SCHEME, tdg->tdg_scheme,
	    topo_node_name(from->tvt_node),
	    topo_node_instance(from->tvt_node)) < 1) {
		return (topo_hdl_seterrno(thp, ETOPO_NOMEM));
	}

	if ((pathcomp = topo_hdl_zalloc(thp, sizeof (topo_path_component_t)))
	    == NULL) {
		(void) topo_hdl_seterrno(thp, ETOPO_NOMEM);
		goto err;
	}
	pathcomp->tspc_vertex = from;
	topo_list_append(&curr_path_comps, pathcomp);

	*npaths = 0;
	for (topo_edge_t *edge = topo_list_next(&from->tvt_outgoing);
	    edge != NULL; edge = topo_list_next(edge)) {

		ret = visit_vertex(thp, edge->tve_vertex, to, &all_paths,
		    curr_path, &curr_path_comps, npaths);
		if (ret != 0) {
			/* errno set */
			goto err;
		}
	}
	topo_hdl_free(thp, pathcomp, sizeof (topo_path_component_t));

	/*
	 * No paths were found between the "from" and "to" vertices, so
	 * we're done here.
	 */
	if (*npaths == 0) {
		free(curr_path);
		return (0);
	}

	*paths = topo_hdl_zalloc(thp, (*npaths) * sizeof (topo_path_t *));
	if (*paths == NULL) {
		(void) topo_hdl_seterrno(thp, ETOPO_NOMEM);
		goto err;
	}

	for (i = 0, path = topo_list_next(&all_paths); path != NULL;
	    i++, path = topo_list_next(path)) {

		*((*paths) + i) = path->dgp_path;
	}

	path = topo_list_next(&all_paths);
	while (path != NULL) {
		struct digraph_path *tmp = path;

		path = topo_list_next(path);
		topo_hdl_free(thp, tmp, sizeof (struct digraph_path));
	}
	free(curr_path);
	return (0);

err:
	free(curr_path);
	path = topo_list_next(&all_paths);
	while (path != NULL) {
		struct digraph_path *tmp = path;

		path = topo_list_next(path);
		topo_hdl_free(thp, tmp, sizeof (struct digraph_path));
	}

	topo_dprintf(thp, TOPO_DBG_ERR, "%s: failed (%s)", __func__,
	    topo_hdl_errmsg(thp));
	return (-1);
}

/* Helper function for path_fmri_nvl2str() */
static ssize_t
fmri_bufsz(nvlist_t *nvl)
{
	char *dg_scheme = NULL;
	nvlist_t **hops, *auth;
	uint_t nhops;
	ssize_t bufsz = 1;
	int ret;

	if (nvlist_lookup_nvlist(nvl, FM_FMRI_AUTHORITY, &auth) != 0 ||
	    nvlist_lookup_string(auth, FM_FMRI_PATH_DIGRAPH_SCHEME,
	    &dg_scheme) != 0) {
		return (0);
	}

	if ((ret = snprintf(NULL, 0, "%s://%s=%s", FM_FMRI_SCHEME_PATH,
	    FM_FMRI_SCHEME, dg_scheme)) < 0) {
		return (-1);
	}
	bufsz += ret;

	if (nvlist_lookup_nvlist_array(nvl, FM_FMRI_PATH, &hops, &nhops) !=
	    0) {
		return (0);
	}

	for (uint_t i = 0; i < nhops; i++) {
		char *name;
		uint64_t inst;

		if (nvlist_lookup_string(hops[i], FM_FMRI_PATH_NAME, &name) !=
		    0 ||
		    nvlist_lookup_uint64(hops[i], FM_FMRI_PATH_INST, &inst) !=
		    0) {
			return (0);
		}
		if ((ret = snprintf(NULL, 0, "/%s=%" PRIx64 "", name, inst)) <
		    0) {
			return (-1);
		}
		bufsz += ret;
	}
	return (bufsz);
}

int
path_fmri_nvl2str(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	uint8_t scheme_vers;
	nvlist_t *outnvl;
	nvlist_t **paths, *auth;
	uint_t nelem;
	ssize_t bufsz, end = 0;
	char *buf, *dg_scheme;
	int ret;

	if (version > TOPO_METH_NVL2STR_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_uint8(in, FM_FMRI_PATH_VERSION, &scheme_vers) != 0) {
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	if (scheme_vers != FM_PATH_SCHEME_VERSION) {
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	/*
	 * Get size of buffer needed to hold the string representation of the
	 * FMRI.
	 */
	bufsz = fmri_bufsz(in);
	if (bufsz == 0) {
		return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));
	} else if (bufsz < 1) {
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}

	if ((buf = topo_mod_zalloc(mod, bufsz)) == NULL) {
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	/*
	 * We've already successfully done these nvlist lookups in fmri_bufsz()
	 * so we don't worry about checking retvals this time around.
	 */
	(void) nvlist_lookup_nvlist(in, FM_FMRI_AUTHORITY, &auth);
	(void) nvlist_lookup_string(auth, FM_FMRI_PATH_DIGRAPH_SCHEME,
	    &dg_scheme);
	(void) nvlist_lookup_nvlist_array(in, FM_FMRI_PATH, &paths,
	    &nelem);
	if ((ret = snprintf(buf, bufsz, "%s://%s=%s", FM_FMRI_SCHEME_PATH,
	    FM_FMRI_SCHEME, dg_scheme)) < 0) {
		topo_mod_free(mod, buf, bufsz);
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}
	end += ret;

	for (uint_t i = 0; i < nelem; i++) {
		char *pathname;
		uint64_t pathinst;

		(void) nvlist_lookup_string(paths[i], FM_FMRI_PATH_NAME,
		    &pathname);
		(void) nvlist_lookup_uint64(paths[i], FM_FMRI_PATH_INST,
		    &pathinst);

		if ((ret = snprintf(buf + end, (bufsz - end), "/%s=%" PRIx64 "",
		    pathname, pathinst)) < 0) {
			topo_mod_free(mod, buf, bufsz);
			return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
		}
		end += ret;
	}

	if (topo_mod_nvalloc(mod, &outnvl, NV_UNIQUE_NAME) != 0) {
		topo_mod_free(mod, buf, bufsz);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}
	if (nvlist_add_string(outnvl, "fmri-string", buf) != 0) {
		nvlist_free(outnvl);
		topo_mod_free(mod, buf, bufsz);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}
	topo_mod_free(mod, buf, bufsz);
	*out = outnvl;

	return (0);
}

int
path_fmri_str2nvl(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	char *fmristr, *tmp = NULL, *lastpair;
	char *dg_scheme, *dg_scheme_end, *pathname, *path_start;
	nvlist_t *fmri = NULL, *auth = NULL, **path = NULL;
	uint_t npairs = 0, i = 0, fmrilen, path_offset;

	if (version > TOPO_METH_STR2NVL_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_string(in, "fmri-string", &fmristr) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));

	if (strncmp(fmristr, "path://", 7) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));

	if (topo_mod_nvalloc(mod, &fmri, NV_UNIQUE_NAME) != 0) {
		/* errno set */
		return (-1);
	}
	if (nvlist_add_string(fmri, FM_FMRI_SCHEME,
	    FM_FMRI_SCHEME_PATH) != 0 ||
	    nvlist_add_uint8(fmri, FM_FMRI_PATH_VERSION,
	    FM_PATH_SCHEME_VERSION) != 0) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}

	/*
	 * We need to make a copy of the fmri string because strtok will
	 * modify it.  We can't use topo_mod_strdup/strfree because
	 * topo_mod_strfree will end up leaking part of the string because
	 * of the NUL chars that strtok inserts - which will cause
	 * topo_mod_strfree to miscalculate the length of the string.  So we
	 * keep track of the length of the original string and use
	 * topo_mod_alloc/topo_mod_free.
	 */
	fmrilen = strlen(fmristr) + 1;
	if ((tmp = topo_mod_alloc(mod, fmrilen)) == NULL) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}
	bcopy(fmristr, tmp, fmrilen);

	/*
	 * Find the offset of the "/" after the authority portion of the FMRI.
	 */
	if ((path_start = strchr(tmp + 7, '/')) == NULL) {
		(void) topo_mod_seterrno(mod, EMOD_FMRI_MALFORM);
		goto err;
	}

	path_offset = path_start - tmp;
	pathname = fmristr + path_offset + 1;

	/*
	 * Count the number of "=" chars after the "path:///" portion of the
	 * FMRI to determine how big the path array needs to be.
	 */
	(void) strtok_r(tmp + path_offset, "=", &lastpair);
	while (strtok_r(NULL, "=", &lastpair) != NULL)
		npairs++;

	if (npairs == 0) {
		(void) topo_mod_seterrno(mod, EMOD_FMRI_MALFORM);
		goto err;
	}

	if ((path = topo_mod_zalloc(mod, npairs * sizeof (nvlist_t *))) ==
	    NULL) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}

	/*
	 * Build the auth nvlist.  There is only one nvpair in the path FMRI
	 * scheme, which is the scheme of the underlying digraph.
	 */
	if (topo_mod_nvalloc(mod, &auth, NV_UNIQUE_NAME) != 0) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}

	if ((dg_scheme = strchr(tmp + 7, '=')) == NULL ||
	    dg_scheme > path_start) {
		(void) topo_mod_seterrno(mod, EMOD_FMRI_MALFORM);
		goto err;
	}
	dg_scheme_end = tmp + path_offset;
	*dg_scheme_end = '\0';

	if (nvlist_add_string(auth, FM_FMRI_PATH_DIGRAPH_SCHEME, dg_scheme) !=
	    0 ||
	    nvlist_add_nvlist(fmri, FM_FMRI_AUTHORITY, auth) != 0) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}

	while (i < npairs) {
		nvlist_t *pathcomp;
		uint64_t pathinst;
		char *end, *addrstr, *estr;

		if (topo_mod_nvalloc(mod, &pathcomp, NV_UNIQUE_NAME) != 0) {
			(void) topo_mod_seterrno(mod, EMOD_NOMEM);
			goto err;
		}
		if ((end = strchr(pathname, '=')) == NULL) {
			(void) topo_mod_seterrno(mod, EMOD_FMRI_MALFORM);
			goto err;
		}
		*end = '\0';
		addrstr = end + 1;

		/*
		 * If this is the last pair, then addrstr will already be
		 * nul-terminated.
		 */
		if (i < (npairs - 1)) {
			if ((end = strchr(addrstr, '/')) == NULL) {
				(void) topo_mod_seterrno(mod,
				    EMOD_FMRI_MALFORM);
				goto err;
			}
			*end = '\0';
		}

		/*
		 * Convert addrstr to a uint64_t
		 */
		errno = 0;
		pathinst = strtoull(addrstr, &estr, 16);
		if (errno != 0 || *estr != '\0') {
			(void) topo_mod_seterrno(mod, EMOD_FMRI_MALFORM);
			goto err;
		}

		/*
		 * Add both nvpairs to the nvlist and then add the nvlist to
		 * the path nvlist array.
		 */
		if (nvlist_add_string(pathcomp, FM_FMRI_PATH_NAME, pathname) !=
		    0 ||
		    nvlist_add_uint64(pathcomp, FM_FMRI_PATH_INST, pathinst) !=
		    0) {
			(void) topo_mod_seterrno(mod, EMOD_NOMEM);
			goto err;
		}
		path[i++] = pathcomp;
		pathname = end + 1;
	}
	if (nvlist_add_nvlist_array(fmri, FM_FMRI_PATH, path, npairs) != 0) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}
	*out = fmri;

	if (path != NULL) {
		for (i = 0; i < npairs; i++)
			nvlist_free(path[i]);

		topo_mod_free(mod, path, npairs * sizeof (nvlist_t *));
	}
	nvlist_free(auth);
	topo_mod_free(mod, tmp, fmrilen);
	return (0);

err:
	topo_mod_dprintf(mod, "%s failed: %s", __func__,
	    topo_strerror(topo_mod_errno(mod)));
	if (path != NULL) {
		for (i = 0; i < npairs; i++)
			nvlist_free(path[i]);

		topo_mod_free(mod, path, npairs * sizeof (nvlist_t *));
	}
	nvlist_free(auth);
	nvlist_free(fmri);
	if (tmp != NULL)
		topo_mod_free(mod, tmp, fmrilen);
	return (-1);
}
