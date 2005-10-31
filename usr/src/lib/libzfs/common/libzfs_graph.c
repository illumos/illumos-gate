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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Iterate over all children of the current object.  This includes the normal
 * dataset hierarchy, but also arbitrary hierarchies due to clones.  We want to
 * walk all datasets in the pool, and construct a directed graph of the form:
 *
 * 			home
 *                        |
 *                   +----+----+
 *                   |         |
 *                   v         v             ws
 *                  bar       baz             |
 *                             |              |
 *                             v              v
 *                          @yesterday ----> foo
 *
 * In order to construct this graph, we have to walk every dataset in the pool,
 * because the clone parent is stored as a property of the child, not the
 * parent.  The parent only keeps track of the number of clones.
 *
 * In the normal case (without clones) this would be rather expensive.  To avoid
 * unnecessary computation, we first try a walk of the subtree hierarchy
 * starting from the initial node.  At each dataset, we construct a node in the
 * graph and an edge leading from its parent.  If we don't see any snapshots
 * with a non-zero clone count, then we are finished.
 *
 * If we do find a cloned snapshot, then we finish the walk of the current
 * subtree, but indicate that we need to do a complete walk.  We then perform a
 * global walk of all datasets, avoiding the subtree we already processed.
 *
 * At the end of this, we'll end up with a directed graph of all relevant (and
 * possible some irrelevant) datasets in the system.  We need to both find our
 * limiting subgraph and determine a safe ordering in which to destroy the
 * datasets.  We do a topological ordering of our graph starting at our target
 * dataset, and then walk the results in reverse.
 *
 * When removing datasets, we want to destroy the snapshots in chronological
 * order (because this is the most efficient method).  In order to accomplish
 * this, we store the creation transaction group with each vertex and keep each
 * vertex's edges sorted according to this value.  The topological sort will
 * automatically walk the snapshots in the correct order.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <libzfs.h>

#include "libzfs_impl.h"
#include "zfs_namecheck.h"

#define	MIN_EDGECOUNT	4

/*
 * Vertex structure.  Indexed by dataset name, this structure maintains a list
 * of edges to other vertices.
 */
struct zfs_edge;
typedef struct zfs_vertex {
	char			zv_dataset[ZFS_MAXNAMELEN];
	struct zfs_vertex	*zv_next;
	int			zv_visited;
	uint64_t		zv_txg;
	struct zfs_edge		**zv_edges;
	int			zv_edgecount;
	int			zv_edgealloc;
} zfs_vertex_t;

/*
 * Edge structure.  Simply maintains a pointer to the destination vertex.  There
 * is no need to store the source vertex, since we only use edges in the context
 * of the source vertex.
 */
typedef struct zfs_edge {
	zfs_vertex_t		*ze_dest;
	struct zfs_edge		*ze_next;
} zfs_edge_t;

#define	ZFS_GRAPH_SIZE		1027	/* this could be dynamic some day */

/*
 * Graph structure.  Vertices are maintained in a hash indexed by dataset name.
 */
typedef struct zfs_graph {
	zfs_vertex_t		**zg_hash;
	size_t			zg_size;
	size_t			zg_nvertex;
} zfs_graph_t;

/*
 * Allocate a new edge pointing to the target vertex.
 */
static zfs_edge_t *
zfs_edge_create(zfs_vertex_t *dest)
{
	zfs_edge_t *zep = zfs_malloc(sizeof (zfs_edge_t));

	zep->ze_dest = dest;

	return (zep);
}

/*
 * Destroy an edge.
 */
static void
zfs_edge_destroy(zfs_edge_t *zep)
{
	free(zep);
}

/*
 * Allocate a new vertex with the given name.
 */
static zfs_vertex_t *
zfs_vertex_create(const char *dataset)
{
	zfs_vertex_t *zvp = zfs_malloc(sizeof (zfs_vertex_t));

	assert(strlen(dataset) < ZFS_MAXNAMELEN);

	(void) strlcpy(zvp->zv_dataset, dataset, sizeof (zvp->zv_dataset));

	zvp->zv_edges = zfs_malloc(MIN_EDGECOUNT * sizeof (void *));
	zvp->zv_edgealloc = MIN_EDGECOUNT;

	return (zvp);
}

/*
 * Destroy a vertex.  Frees up any associated edges.
 */
static void
zfs_vertex_destroy(zfs_vertex_t *zvp)
{
	int i;

	for (i = 0; i < zvp->zv_edgecount; i++)
		zfs_edge_destroy(zvp->zv_edges[i]);

	free(zvp->zv_edges);
	free(zvp);
}

/*
 * Given a vertex, add an edge to the destination vertex.
 */
static void
zfs_vertex_add_edge(zfs_vertex_t *zvp, zfs_vertex_t *dest)
{
	zfs_edge_t *zep = zfs_edge_create(dest);

	if (zvp->zv_edgecount == zvp->zv_edgealloc) {
		zfs_edge_t **newedges = zfs_malloc(zvp->zv_edgealloc * 2 *
		    sizeof (void *));

		bcopy(zvp->zv_edges, newedges,
		    zvp->zv_edgealloc * sizeof (void *));

		zvp->zv_edgealloc *= 2;
		free(zvp->zv_edges);
		zvp->zv_edges = newedges;
	}

	zvp->zv_edges[zvp->zv_edgecount++] = zep;
}

static int
zfs_edge_compare(const void *a, const void *b)
{
	const zfs_edge_t *ea = *((zfs_edge_t **)a);
	const zfs_edge_t *eb = *((zfs_edge_t **)b);

	if (ea->ze_dest->zv_txg < eb->ze_dest->zv_txg)
		return (-1);
	if (ea->ze_dest->zv_txg > eb->ze_dest->zv_txg)
		return (1);
	return (0);
}

/*
 * Sort the given vertex edges according to the creation txg of each vertex.
 */
static void
zfs_vertex_sort_edges(zfs_vertex_t *zvp)
{
	if (zvp->zv_edgecount == 0)
		return;

	qsort(zvp->zv_edges, zvp->zv_edgecount, sizeof (void *),
	    zfs_edge_compare);
}

/*
 * Construct a new graph object.  We allow the size to be specified as a
 * parameter so in the future we can size the hash according to the number of
 * datasets in the pool.
 */
static zfs_graph_t *
zfs_graph_create(size_t size)
{
	zfs_graph_t *zgp = zfs_malloc(sizeof (zfs_graph_t));

	zgp->zg_size = size;
	zgp->zg_hash = zfs_malloc(size * sizeof (zfs_vertex_t *));

	return (zgp);
}

/*
 * Destroy a graph object.  We have to iterate over all the hash chains,
 * destroying each vertex in the process.
 */
static void
zfs_graph_destroy(zfs_graph_t *zgp)
{
	int i;
	zfs_vertex_t *current, *next;

	for (i = 0; i < zgp->zg_size; i++) {
		current = zgp->zg_hash[i];
		while (current != NULL) {
			next = current->zv_next;
			zfs_vertex_destroy(current);
			current = next;
		}
	}

	free(zgp->zg_hash);
	free(zgp);
}

/*
 * Graph hash function.  Classic bernstein k=33 hash function, taken from
 * usr/src/cmd/sgs/tools/common/strhash.c
 */
static size_t
zfs_graph_hash(zfs_graph_t *zgp, const char *str)
{
	size_t hash = 5381;
	int c;

	while ((c = *str++) != 0)
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

	return (hash % zgp->zg_size);
}

/*
 * Given a dataset name, finds the associated vertex, creating it if necessary.
 */
static zfs_vertex_t *
zfs_graph_lookup(zfs_graph_t *zgp, const char *dataset, uint64_t txg)
{
	size_t idx = zfs_graph_hash(zgp, dataset);
	zfs_vertex_t *zvp;

	for (zvp = zgp->zg_hash[idx]; zvp != NULL; zvp = zvp->zv_next) {
		if (strcmp(zvp->zv_dataset, dataset) == 0) {
			if (zvp->zv_txg == 0)
				zvp->zv_txg = txg;
			return (zvp);
		}
	}

	zvp = zfs_vertex_create(dataset);
	zvp->zv_next = zgp->zg_hash[idx];
	zvp->zv_txg = txg;
	zgp->zg_hash[idx] = zvp;
	zgp->zg_nvertex++;

	return (zvp);
}

/*
 * Given two dataset names, create an edge between them.  For the source vertex,
 * mark 'zv_visited' to indicate that we have seen this vertex, and not simply
 * created it as a destination of another edge.  If 'dest' is NULL, then this
 * is an individual vertex (i.e. the starting vertex), so don't add an edge.
 */
static void
zfs_graph_add(zfs_graph_t *zgp, const char *source, const char *dest,
    uint64_t txg)
{
	zfs_vertex_t *svp, *dvp;

	svp = zfs_graph_lookup(zgp, source, 0);
	svp->zv_visited = 1;
	if (dest != NULL) {
		dvp = zfs_graph_lookup(zgp, dest, txg);
		zfs_vertex_add_edge(svp, dvp);
	}
}

/*
 * Iterate over all children of the given dataset, adding any vertices as
 * necessary.  Returns 0 if no cloned snapshots were seen, 1 otherwise.  This is
 * a simple recursive algorithm - the ZFS namespace typically is very flat.  We
 * manually invoke the necessary ioctl() calls to avoid the overhead and
 * additional semantics of zfs_open().
 */
static int
iterate_children(zfs_graph_t *zgp, const char *dataset)
{
	zfs_cmd_t zc = { 0 };
	int ret = 0;
	zfs_vertex_t *zvp;

	/*
	 * Look up the source vertex, and avoid it if we've seen it before.
	 */
	zvp = zfs_graph_lookup(zgp, dataset, 0);
	if (zvp->zv_visited)
		return (0);

	for ((void) strlcpy(zc.zc_name, dataset, sizeof (zc.zc_name));
	    ioctl(zfs_fd, ZFS_IOC_DATASET_LIST_NEXT, &zc) == 0;
	    (void) strlcpy(zc.zc_name, dataset, sizeof (zc.zc_name))) {

		/*
		 * Ignore private dataset names.
		 */
		if (dataset_name_hidden(zc.zc_name))
			continue;

		/*
		 * Get statistics for this dataset, to determine the type of the
		 * dataset and clone statistics.  If this fails, the dataset has
		 * since been removed, and we're pretty much screwed anyway.
		 */
		if (ioctl(zfs_fd, ZFS_IOC_OBJSET_STATS, &zc) != 0)
			continue;

		/*
		 * Add an edge between the parent and the child.
		 */
		zfs_graph_add(zgp, dataset, zc.zc_name,
		    zc.zc_objset_stats.dds_creation_txg);

		/*
		 * If this dataset has a clone parent, add an appropriate edge.
		 */
		if (zc.zc_objset_stats.dds_clone_of[0] != '\0')
			zfs_graph_add(zgp, zc.zc_objset_stats.dds_clone_of,
			    zc.zc_name, zc.zc_objset_stats.dds_creation_txg);

		/*
		 * Iterate over all children
		 */
		ret |= iterate_children(zgp, zc.zc_name);

		/*
		 * Indicate if we found a dataset with a non-zero clone count.
		 */
		if (zc.zc_objset_stats.dds_num_clones != 0)
			ret |= 1;
	}

	/*
	 * Now iterate over all snapshots.
	 */
	bzero(&zc, sizeof (zc));

	for ((void) strlcpy(zc.zc_name, dataset, sizeof (zc.zc_name));
	    ioctl(zfs_fd, ZFS_IOC_SNAPSHOT_LIST_NEXT, &zc) == 0;
	    (void) strlcpy(zc.zc_name, dataset, sizeof (zc.zc_name))) {

		/*
		 * Get statistics for this dataset, to determine the type of the
		 * dataset and clone statistics.  If this fails, the dataset has
		 * since been removed, and we're pretty much screwed anyway.
		 */
		if (ioctl(zfs_fd, ZFS_IOC_OBJSET_STATS, &zc) != 0)
			continue;

		/*
		 * Add an edge between the parent and the child.
		 */
		zfs_graph_add(zgp, dataset, zc.zc_name,
		    zc.zc_objset_stats.dds_creation_txg);

		/*
		 * Indicate if we found a dataset with a non-zero clone count.
		 */
		if (zc.zc_objset_stats.dds_num_clones != 0)
			ret |= 1;
	}

	zvp->zv_visited = 1;

	return (ret);
}

/*
 * Construct a complete graph of all necessary vertices.  First, we iterate over
 * only our object's children.  If we don't find any cloned snapshots, then we
 * simple return that.  Otherwise, we have to start at the pool root and iterate
 * over all datasets.
 */
static zfs_graph_t *
construct_graph(const char *dataset)
{
	zfs_graph_t *zgp = zfs_graph_create(ZFS_GRAPH_SIZE);
	zfs_cmd_t zc = { 0 };

	/*
	 * We need to explicitly check whether this dataset has clones or not,
	 * since iterate_children() only checks the children.
	 */
	(void) strlcpy(zc.zc_name, dataset, sizeof (zc.zc_name));
	(void) ioctl(zfs_fd, ZFS_IOC_OBJSET_STATS, &zc);

	if (zc.zc_objset_stats.dds_num_clones != 0 ||
	    iterate_children(zgp, dataset) != 0) {
		/*
		 * Determine pool name and try again.
		 */
		char *pool, *slash;

		if ((slash = strchr(dataset, '/')) != NULL ||
		    (slash = strchr(dataset, '@')) != NULL) {
			pool = zfs_malloc(slash - dataset + 1);
			(void) strncpy(pool, dataset, slash - dataset);
			pool[slash - dataset] = '\0';

			(void) iterate_children(zgp, pool);
			zfs_graph_add(zgp, pool, NULL, 0);

			free(pool);
		}
	}
	zfs_graph_add(zgp, dataset, NULL, 0);

	return (zgp);
}

/*
 * Given a graph, do a recursive topological sort into the given array.  This is
 * really just a depth first search, so that the deepest nodes appear first.
 * hijack the 'zv_visited' marker to avoid visiting the same vertex twice.
 */
static void
topo_sort(char **result, size_t *idx, zfs_vertex_t *zgv)
{
	int i;

	/* avoid doing a search if we don't have to */
	if (zgv->zv_visited == 2)
		return;

	zfs_vertex_sort_edges(zgv);
	for (i = 0; i < zgv->zv_edgecount; i++)
		topo_sort(result, idx, zgv->zv_edges[i]->ze_dest);

	/* we may have visited this in the course of the above */
	if (zgv->zv_visited == 2)
		return;

	result[*idx] = zfs_malloc(strlen(zgv->zv_dataset) + 1);
	(void) strcpy(result[*idx], zgv->zv_dataset);
	*idx += 1;
	zgv->zv_visited = 2;
}

/*
 * The only public interface for this file.  Do the dirty work of constructing a
 * child list for the given object.  Construct the graph, do the toplogical
 * sort, and then return the array of strings to the caller.
 */
char **
get_dependents(const char *dataset, size_t *count)
{
	char **result;
	zfs_graph_t *zgp;
	zfs_vertex_t *zvp;

	zgp = construct_graph(dataset);
	result = zfs_malloc(zgp->zg_nvertex * sizeof (char *));

	zvp = zfs_graph_lookup(zgp, dataset, 0);

	*count = 0;
	topo_sort(result, count, zvp);

	/*
	 * Get rid of the last entry, which is our starting vertex and not
	 * strictly a dependent.
	 */
	assert(*count > 0);
	free(result[*count - 1]);
	(*count)--;

	zfs_graph_destroy(zgp);

	return (result);
}
