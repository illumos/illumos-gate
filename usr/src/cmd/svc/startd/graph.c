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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2015, Syneto S.R.L. All rights reserved.
 * Copyright 2016 RackTop Systems.
 */

/*
 * graph.c - master restarter graph engine
 *
 *   The graph engine keeps a dependency graph of all service instances on the
 *   system, as recorded in the repository.  It decides when services should
 *   be brought up or down based on service states and dependencies and sends
 *   commands to restarters to effect any changes.  It also executes
 *   administrator commands sent by svcadm via the repository.
 *
 *   The graph is stored in uu_list_t *dgraph and its vertices are
 *   graph_vertex_t's, each of which has a name and an integer id unique to
 *   its name (see dict.c).  A vertex's type attribute designates the type
 *   of object it represents: GVT_INST for service instances, GVT_SVC for
 *   service objects (since service instances may depend on another service,
 *   rather than service instance), GVT_FILE for files (which services may
 *   depend on), and GVT_GROUP for dependencies on multiple objects.  GVT_GROUP
 *   vertices are necessary because dependency lists may have particular
 *   grouping types (require any, require all, optional, or exclude) and
 *   event-propagation characteristics.
 *
 *   The initial graph is built by libscf_populate_graph() invoking
 *   dgraph_add_instance() for each instance in the repository.  The function
 *   adds a GVT_SVC vertex for the service if one does not already exist, adds
 *   a GVT_INST vertex named by the FMRI of the instance, and sets up the edges.
 *   The resulting web of vertices & edges associated with an instance's vertex
 *   includes
 *
 *     - an edge from the GVT_SVC vertex for the instance's service
 *
 *     - an edge to the GVT_INST vertex of the instance's resarter, if its
 *       restarter is not svc.startd
 *
 *     - edges from other GVT_INST vertices if the instance is a restarter
 *
 *     - for each dependency property group in the instance's "running"
 *       snapshot, an edge to a GVT_GROUP vertex named by the FMRI of the
 *       instance and the name of the property group
 *
 *     - for each value of the "entities" property in each dependency property
 *       group, an edge from the corresponding GVT_GROUP vertex to a
 *       GVT_INST, GVT_SVC, or GVT_FILE vertex
 *
 *     - edges from GVT_GROUP vertices for each dependent instance
 *
 *   After the edges are set up the vertex's GV_CONFIGURED flag is set.  If
 *   there are problems, or if a service is mentioned in a dependency but does
 *   not exist in the repository, the GV_CONFIGURED flag will be clear.
 *
 *   The graph and all of its vertices are protected by the dgraph_lock mutex.
 *   See restarter.c for more information.
 *
 *   The properties of an instance fall into two classes: immediate and
 *   snapshotted.  Immediate properties should have an immediate effect when
 *   changed.  Snapshotted properties should be read from a snapshot, so they
 *   only change when the snapshot changes.  The immediate properties used by
 *   the graph engine are general/enabled, general/restarter, and the properties
 *   in the restarter_actions property group.  Since they are immediate, they
 *   are not read out of a snapshot.  The snapshotted properties used by the
 *   graph engine are those in the property groups with type "dependency" and
 *   are read out of the "running" snapshot.  The "running" snapshot is created
 *   by the the graph engine as soon as possible, and it is updated, along with
 *   in-core copies of the data (dependency information for the graph engine) on
 *   receipt of the refresh command from svcadm.  In addition, the graph engine
 *   updates the "start" snapshot from the "running" snapshot whenever a service
 *   comes online.
 *
 *   When a DISABLE event is requested by the administrator, svc.startd shutdown
 *   the dependents first before shutting down the requested service.
 *   In graph_enable_by_vertex, we create a subtree that contains the dependent
 *   vertices by marking those vertices with the GV_TOOFFLINE flag. And we mark
 *   the vertex to disable with the GV_TODISABLE flag. Once the tree is created,
 *   we send the _ADMIN_DISABLE event to the leaves. The leaves will then
 *   transition from STATE_ONLINE/STATE_DEGRADED to STATE_OFFLINE/STATE_MAINT.
 *   In gt_enter_offline and gt_enter_maint if the vertex was in a subtree then
 *   we clear the GV_TOOFFLINE flag and walk the dependencies to offline the new
 *   exposed leaves. We do the same until we reach the last leaf (the one with
 *   the GV_TODISABLE flag). If the vertex to disable is also part of a larger
 *   subtree (eg. multiple DISABLE events on vertices in the same subtree) then
 *   once the first vertex is disabled (GV_TODISABLE flag is removed), we
 *   continue to propagate the offline event to the vertex's dependencies.
 *
 *
 * SMF state transition notifications
 *
 *   When an instance of a service managed by SMF changes state, svc.startd may
 *   publish a GPEC sysevent. All transitions to or from maintenance, a
 *   transition cause by a hardware error will generate an event.
 *   Other transitions will generate an event if there exist notification
 *   parameter for that transition. Notification parameters are stored in the
 *   SMF repository for the service/instance they refer to. System-wide
 *   notification parameters are stored in the global instance.
 *   svc.startd can be told to send events for all SMF state transitions despite
 *   of notification parameters by setting options/info_events_all to true in
 *   restarter:default
 *
 *   The set of transitions that generate events is cached in the
 *   dgraph_vertex_t gv_stn_tset for service/instance and in the global
 *   stn_global for the system-wide set. They are re-read when instances are
 *   refreshed.
 *
 *   The GPEC events published by svc.startd are consumed by fmd(1M). After
 *   processing these events, fmd(1M) publishes the processed events to
 *   notification agents. The notification agents read the notification
 *   parameters from the SMF repository through libscf(3LIB) interfaces and send
 *   the notification, or not, based on those parameters.
 *
 *   Subscription and publishing to the GPEC channels is done with the
 *   libfmevent(3LIB) wrappers fmev_[r]publish_*() and
 *   fmev_shdl_(un)subscribe().
 *
 */

#include <sys/uadmin.h>
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <fm/libfmevent.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <librestart.h>
#include <libuutil.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/statvfs.h>
#include <sys/uadmin.h>
#include <zone.h>
#if defined(__i386)
#include <libgrubmgmt.h>
#endif	/* __i386 */

#include "startd.h"
#include "protocol.h"


#define	MILESTONE_NONE	((graph_vertex_t *)1)

#define	CONSOLE_LOGIN_FMRI	"svc:/system/console-login:default"
#define	FS_MINIMAL_FMRI		"svc:/system/filesystem/minimal:default"

#define	VERTEX_REMOVED	0	/* vertex has been freed  */
#define	VERTEX_INUSE	1	/* vertex is still in use */

#define	IS_ENABLED(v) ((v)->gv_flags & (GV_ENABLED | GV_ENBLD_NOOVR))

/*
 * stn_global holds the tset for the system wide notification parameters.
 * It is updated on refresh of svc:/system/svc/global:default
 *
 * There are two assumptions that relax the need for a mutex:
 *     1. 32-bit value assignments are atomic
 *     2. Its value is consumed only in one point at
 *     dgraph_state_transition_notify(). There are no test and set races.
 *
 *     If either assumption is broken, we'll need a mutex to synchronize
 *     access to stn_global
 */
int32_t stn_global;
/*
 * info_events_all holds a flag to override notification parameters and send
 * Information events for all state transitions.
 * same about the need of a mutex here.
 */
int info_events_all;

/*
 * Services in these states are not considered 'down' by the
 * milestone/shutdown code.
 */
#define	up_state(state)	((state) == RESTARTER_STATE_ONLINE || \
	(state) == RESTARTER_STATE_DEGRADED || \
	(state) == RESTARTER_STATE_OFFLINE)

#define	is_depgrp_bypassed(v) ((v->gv_type == GVT_GROUP) && \
	((v->gv_depgroup == DEPGRP_EXCLUDE_ALL) || \
	(v->gv_restart < RERR_RESTART)))

static uu_list_pool_t *graph_edge_pool, *graph_vertex_pool;
static uu_list_t *dgraph;
static pthread_mutex_t dgraph_lock;

/*
 * milestone indicates the current subgraph.  When NULL, it is the entire
 * graph.  When MILESTONE_NONE, it is the empty graph.  Otherwise, it is all
 * services on which the target vertex depends.
 */
static graph_vertex_t *milestone = NULL;
static boolean_t initial_milestone_set = B_FALSE;
static pthread_cond_t initial_milestone_cv = PTHREAD_COND_INITIALIZER;

/* protected by dgraph_lock */
static boolean_t sulogin_thread_running = B_FALSE;
static boolean_t sulogin_running = B_FALSE;
static boolean_t console_login_ready = B_FALSE;

/* Number of services to come down to complete milestone transition. */
static uint_t non_subgraph_svcs;

/*
 * These variables indicate what should be done when we reach the milestone
 * target milestone, i.e., when non_subgraph_svcs == 0.  They are acted upon in
 * dgraph_set_instance_state().
 */
static int halting = -1;
static boolean_t go_single_user_mode = B_FALSE;
static boolean_t go_to_level1 = B_FALSE;

/*
 * Tracks when we started halting.
 */
static time_t halting_time = 0;

/*
 * This tracks the legacy runlevel to ensure we signal init and manage
 * utmpx entries correctly.
 */
static char current_runlevel = '\0';

/* Number of single user threads currently running */
static pthread_mutex_t single_user_thread_lock;
static int single_user_thread_count = 0;

/* Statistics for dependency cycle-checking */
static u_longlong_t dep_inserts = 0;
static u_longlong_t dep_cycle_ns = 0;
static u_longlong_t dep_insert_ns = 0;


static const char * const emsg_invalid_restarter =
	"Transitioning %s to maintenance, restarter FMRI %s is invalid "
	"(see 'svcs -xv' for details).\n";
static const char * const console_login_fmri = CONSOLE_LOGIN_FMRI;
static const char * const single_user_fmri = SCF_MILESTONE_SINGLE_USER;
static const char * const multi_user_fmri = SCF_MILESTONE_MULTI_USER;
static const char * const multi_user_svr_fmri = SCF_MILESTONE_MULTI_USER_SERVER;


/*
 * These services define the system being "up".  If none of them can come
 * online, then we will run sulogin on the console.  Note that the install ones
 * are for the miniroot and when installing CDs after the first.  can_come_up()
 * does the decision making, and an sulogin_thread() runs sulogin, which can be
 * started by dgraph_set_instance_state() or single_user_thread().
 *
 * NOTE: can_come_up() relies on SCF_MILESTONE_SINGLE_USER being the first
 * entry, which is only used when booting_to_single_user (boot -s) is set.
 * This is because when doing a "boot -s", sulogin is started from specials.c
 * after milestone/single-user comes online, for backwards compatibility.
 * In this case, SCF_MILESTONE_SINGLE_USER needs to be part of up_svcs
 * to ensure sulogin will be spawned if milestone/single-user cannot be reached.
 */
static const char * const up_svcs[] = {
	SCF_MILESTONE_SINGLE_USER,
	CONSOLE_LOGIN_FMRI,
	"svc:/system/install-setup:default",
	"svc:/system/install:default",
	NULL
};

/* This array must have an element for each non-NULL element of up_svcs[]. */
static graph_vertex_t *up_svcs_p[] = { NULL, NULL, NULL, NULL };

/* These are for seed repository magic.  See can_come_up(). */
static const char * const manifest_import = SCF_INSTANCE_MI;
static graph_vertex_t *manifest_import_p = NULL;


static char target_milestone_as_runlevel(void);
static void graph_runlevel_changed(char rl, int online);
static int dgraph_set_milestone(const char *, scf_handle_t *, boolean_t);
static boolean_t should_be_in_subgraph(graph_vertex_t *v);
static int mark_subtree(graph_edge_t *, void *);
static boolean_t insubtree_dependents_down(graph_vertex_t *);

/*
 * graph_vertex_compare()
 *	This function can compare either int *id or * graph_vertex_t *gv
 *	values, as the vertex id is always the first element of a
 *	graph_vertex structure.
 */
/* ARGSUSED */
static int
graph_vertex_compare(const void *lc_arg, const void *rc_arg, void *private)
{
	int lc_id = ((const graph_vertex_t *)lc_arg)->gv_id;
	int rc_id = *(int *)rc_arg;

	if (lc_id > rc_id)
		return (1);
	if (lc_id < rc_id)
		return (-1);
	return (0);
}

void
graph_init()
{
	graph_edge_pool = startd_list_pool_create("graph_edges",
	    sizeof (graph_edge_t), offsetof(graph_edge_t, ge_link), NULL,
	    UU_LIST_POOL_DEBUG);
	assert(graph_edge_pool != NULL);

	graph_vertex_pool = startd_list_pool_create("graph_vertices",
	    sizeof (graph_vertex_t), offsetof(graph_vertex_t, gv_link),
	    graph_vertex_compare, UU_LIST_POOL_DEBUG);
	assert(graph_vertex_pool != NULL);

	(void) pthread_mutex_init(&dgraph_lock, &mutex_attrs);
	(void) pthread_mutex_init(&single_user_thread_lock, &mutex_attrs);
	dgraph = startd_list_create(graph_vertex_pool, NULL, UU_LIST_SORTED);
	assert(dgraph != NULL);

	if (!st->st_initial)
		current_runlevel = utmpx_get_runlevel();

	log_framework(LOG_DEBUG, "Initialized graph\n");
}

static graph_vertex_t *
vertex_get_by_name(const char *name)
{
	int id;

	assert(MUTEX_HELD(&dgraph_lock));

	id = dict_lookup_byname(name);
	if (id == -1)
		return (NULL);

	return (uu_list_find(dgraph, &id, NULL, NULL));
}

static graph_vertex_t *
vertex_get_by_id(int id)
{
	assert(MUTEX_HELD(&dgraph_lock));

	if (id == -1)
		return (NULL);

	return (uu_list_find(dgraph, &id, NULL, NULL));
}

/*
 * Creates a new vertex with the given name, adds it to the graph, and returns
 * a pointer to it.  The graph lock must be held by this thread on entry.
 */
static graph_vertex_t *
graph_add_vertex(const char *name)
{
	int id;
	graph_vertex_t *v;
	void *p;
	uu_list_index_t idx;

	assert(MUTEX_HELD(&dgraph_lock));

	id = dict_insert(name);

	v = startd_zalloc(sizeof (*v));

	v->gv_id = id;

	v->gv_name = startd_alloc(strlen(name) + 1);
	(void) strcpy(v->gv_name, name);

	v->gv_dependencies = startd_list_create(graph_edge_pool, v, 0);
	v->gv_dependents = startd_list_create(graph_edge_pool, v, 0);

	p = uu_list_find(dgraph, &id, NULL, &idx);
	assert(p == NULL);

	uu_list_node_init(v, &v->gv_link, graph_vertex_pool);
	uu_list_insert(dgraph, v, idx);

	return (v);
}

/*
 * Removes v from the graph and frees it.  The graph should be locked by this
 * thread, and v should have no edges associated with it.
 */
static void
graph_remove_vertex(graph_vertex_t *v)
{
	assert(MUTEX_HELD(&dgraph_lock));

	assert(uu_list_numnodes(v->gv_dependencies) == 0);
	assert(uu_list_numnodes(v->gv_dependents) == 0);
	assert(v->gv_refs == 0);

	startd_free(v->gv_name, strlen(v->gv_name) + 1);
	uu_list_destroy(v->gv_dependencies);
	uu_list_destroy(v->gv_dependents);
	uu_list_remove(dgraph, v);

	startd_free(v, sizeof (graph_vertex_t));
}

static void
graph_add_edge(graph_vertex_t *fv, graph_vertex_t *tv)
{
	graph_edge_t *e, *re;
	int r;

	assert(MUTEX_HELD(&dgraph_lock));

	e = startd_alloc(sizeof (graph_edge_t));
	re = startd_alloc(sizeof (graph_edge_t));

	e->ge_parent = fv;
	e->ge_vertex = tv;

	re->ge_parent = tv;
	re->ge_vertex = fv;

	uu_list_node_init(e, &e->ge_link, graph_edge_pool);
	r = uu_list_insert_before(fv->gv_dependencies, NULL, e);
	assert(r == 0);

	uu_list_node_init(re, &re->ge_link, graph_edge_pool);
	r = uu_list_insert_before(tv->gv_dependents, NULL, re);
	assert(r == 0);
}

static void
graph_remove_edge(graph_vertex_t *v, graph_vertex_t *dv)
{
	graph_edge_t *e;

	for (e = uu_list_first(v->gv_dependencies);
	    e != NULL;
	    e = uu_list_next(v->gv_dependencies, e)) {
		if (e->ge_vertex == dv) {
			uu_list_remove(v->gv_dependencies, e);
			startd_free(e, sizeof (graph_edge_t));
			break;
		}
	}

	for (e = uu_list_first(dv->gv_dependents);
	    e != NULL;
	    e = uu_list_next(dv->gv_dependents, e)) {
		if (e->ge_vertex == v) {
			uu_list_remove(dv->gv_dependents, e);
			startd_free(e, sizeof (graph_edge_t));
			break;
		}
	}
}

static void
remove_inst_vertex(graph_vertex_t *v)
{
	graph_edge_t *e;
	graph_vertex_t *sv;
	int i;

	assert(MUTEX_HELD(&dgraph_lock));
	assert(uu_list_numnodes(v->gv_dependents) == 1);
	assert(uu_list_numnodes(v->gv_dependencies) == 0);
	assert(v->gv_refs == 0);
	assert((v->gv_flags & GV_CONFIGURED) == 0);

	e = uu_list_first(v->gv_dependents);
	sv = e->ge_vertex;
	graph_remove_edge(sv, v);

	for (i = 0; up_svcs[i] != NULL; ++i) {
		if (up_svcs_p[i] == v)
			up_svcs_p[i] = NULL;
	}

	if (manifest_import_p == v)
		manifest_import_p = NULL;

	graph_remove_vertex(v);

	if (uu_list_numnodes(sv->gv_dependencies) == 0 &&
	    uu_list_numnodes(sv->gv_dependents) == 0 &&
	    sv->gv_refs == 0)
		graph_remove_vertex(sv);
}

static void
graph_walk_dependents(graph_vertex_t *v, void (*func)(graph_vertex_t *, void *),
    void *arg)
{
	graph_edge_t *e;

	for (e = uu_list_first(v->gv_dependents);
	    e != NULL;
	    e = uu_list_next(v->gv_dependents, e))
		func(e->ge_vertex, arg);
}

static void
graph_walk_dependencies(graph_vertex_t *v,
    void (*func)(graph_vertex_t *, void *), void *arg)
{
	graph_edge_t *e;

	assert(MUTEX_HELD(&dgraph_lock));

	for (e = uu_list_first(v->gv_dependencies);
	    e != NULL;
	    e = uu_list_next(v->gv_dependencies, e)) {

		func(e->ge_vertex, arg);
	}
}

/*
 * Generic graph walking function.
 *
 * Given a vertex, this function will walk either dependencies
 * (WALK_DEPENDENCIES) or dependents (WALK_DEPENDENTS) of a vertex recursively
 * for the entire graph.  It will avoid cycles and never visit the same vertex
 * twice.
 *
 * We avoid traversing exclusion dependencies, because they are allowed to
 * create cycles in the graph.  When propagating satisfiability, there is no
 * need to walk exclusion dependencies because exclude_all_satisfied() doesn't
 * test for satisfiability.
 *
 * The walker takes two callbacks.  The first is called before examining the
 * dependents of each vertex.  The second is called on each vertex after
 * examining its dependents.  This allows is_path_to() to construct a path only
 * after the target vertex has been found.
 */
typedef enum {
	WALK_DEPENDENTS,
	WALK_DEPENDENCIES
} graph_walk_dir_t;

typedef int (*graph_walk_cb_t)(graph_vertex_t *, void *);

typedef struct graph_walk_info {
	graph_walk_dir_t 	gi_dir;
	uchar_t			*gi_visited;	/* vertex bitmap */
	int			(*gi_pre)(graph_vertex_t *, void *);
	void			(*gi_post)(graph_vertex_t *, void *);
	void			*gi_arg;	/* callback arg */
	int			gi_ret;		/* return value */
} graph_walk_info_t;

static int
graph_walk_recurse(graph_edge_t *e, graph_walk_info_t *gip)
{
	uu_list_t *list;
	int r;
	graph_vertex_t *v = e->ge_vertex;
	int i;
	uint_t b;

	i = v->gv_id / 8;
	b = 1 << (v->gv_id % 8);

	/*
	 * Check to see if we've visited this vertex already.
	 */
	if (gip->gi_visited[i] & b)
		return (UU_WALK_NEXT);

	gip->gi_visited[i] |= b;

	/*
	 * Don't follow exclusions.
	 */
	if (v->gv_type == GVT_GROUP && v->gv_depgroup == DEPGRP_EXCLUDE_ALL)
		return (UU_WALK_NEXT);

	/*
	 * Call pre-visit callback.  If this doesn't terminate the walk,
	 * continue search.
	 */
	if ((gip->gi_ret = gip->gi_pre(v, gip->gi_arg)) == UU_WALK_NEXT) {
		/*
		 * Recurse using appropriate list.
		 */
		if (gip->gi_dir == WALK_DEPENDENTS)
			list = v->gv_dependents;
		else
			list = v->gv_dependencies;

		r = uu_list_walk(list, (uu_walk_fn_t *)graph_walk_recurse,
		    gip, 0);
		assert(r == 0);
	}

	/*
	 * Callbacks must return either UU_WALK_NEXT or UU_WALK_DONE.
	 */
	assert(gip->gi_ret == UU_WALK_NEXT || gip->gi_ret == UU_WALK_DONE);

	/*
	 * If given a post-callback, call the function for every vertex.
	 */
	if (gip->gi_post != NULL)
		(void) gip->gi_post(v, gip->gi_arg);

	/*
	 * Preserve the callback's return value.  If the callback returns
	 * UU_WALK_DONE, then we propagate that to the caller in order to
	 * terminate the walk.
	 */
	return (gip->gi_ret);
}

static void
graph_walk(graph_vertex_t *v, graph_walk_dir_t dir,
    int (*pre)(graph_vertex_t *, void *),
    void (*post)(graph_vertex_t *, void *), void *arg)
{
	graph_walk_info_t gi;
	graph_edge_t fake;
	size_t sz = dictionary->dict_new_id / 8 + 1;

	gi.gi_visited = startd_zalloc(sz);
	gi.gi_pre = pre;
	gi.gi_post = post;
	gi.gi_arg = arg;
	gi.gi_dir = dir;
	gi.gi_ret = 0;

	/*
	 * Fake up an edge for the first iteration
	 */
	fake.ge_vertex = v;
	(void) graph_walk_recurse(&fake, &gi);

	startd_free(gi.gi_visited, sz);
}

typedef struct child_search {
	int	id;		/* id of vertex to look for */
	uint_t	depth;		/* recursion depth */
	/*
	 * While the vertex is not found, path is NULL.  After the search, if
	 * the vertex was found then path should point to a -1-terminated
	 * array of vertex id's which constitute the path to the vertex.
	 */
	int	*path;
} child_search_t;

static int
child_pre(graph_vertex_t *v, void *arg)
{
	child_search_t *cs = arg;

	cs->depth++;

	if (v->gv_id == cs->id) {
		cs->path = startd_alloc((cs->depth + 1) * sizeof (int));
		cs->path[cs->depth] = -1;
		return (UU_WALK_DONE);
	}

	return (UU_WALK_NEXT);
}

static void
child_post(graph_vertex_t *v, void *arg)
{
	child_search_t *cs = arg;

	cs->depth--;

	if (cs->path != NULL)
		cs->path[cs->depth] = v->gv_id;
}

/*
 * Look for a path from from to to.  If one exists, returns a pointer to
 * a NULL-terminated array of pointers to the vertices along the path.  If
 * there is no path, returns NULL.
 */
static int *
is_path_to(graph_vertex_t *from, graph_vertex_t *to)
{
	child_search_t cs;

	cs.id = to->gv_id;
	cs.depth = 0;
	cs.path = NULL;

	graph_walk(from, WALK_DEPENDENCIES, child_pre, child_post, &cs);

	return (cs.path);
}

/*
 * Given an array of int's as returned by is_path_to, allocates a string of
 * their names joined by newlines.  Returns the size of the allocated buffer
 * in *sz and frees path.
 */
static void
path_to_str(int *path, char **cpp, size_t *sz)
{
	int i;
	graph_vertex_t *v;
	size_t allocd, new_allocd;
	char *new, *name;

	assert(MUTEX_HELD(&dgraph_lock));
	assert(path[0] != -1);

	allocd = 1;
	*cpp = startd_alloc(1);
	(*cpp)[0] = '\0';

	for (i = 0; path[i] != -1; ++i) {
		name = NULL;

		v = vertex_get_by_id(path[i]);

		if (v == NULL)
			name = "<deleted>";
		else if (v->gv_type == GVT_INST || v->gv_type == GVT_SVC)
			name = v->gv_name;

		if (name != NULL) {
			new_allocd = allocd + strlen(name) + 1;
			new = startd_alloc(new_allocd);
			(void) strcpy(new, *cpp);
			(void) strcat(new, name);
			(void) strcat(new, "\n");

			startd_free(*cpp, allocd);

			*cpp = new;
			allocd = new_allocd;
		}
	}

	startd_free(path, sizeof (int) * (i + 1));

	*sz = allocd;
}


/*
 * This function along with run_sulogin() implements an exclusion relationship
 * between system/console-login and sulogin.  run_sulogin() will fail if
 * system/console-login is online, and the graph engine should call
 * graph_clogin_start() to bring system/console-login online, which defers the
 * start if sulogin is running.
 */
static void
graph_clogin_start(graph_vertex_t *v)
{
	assert(MUTEX_HELD(&dgraph_lock));

	if (sulogin_running)
		console_login_ready = B_TRUE;
	else
		vertex_send_event(v, RESTARTER_EVENT_TYPE_START);
}

static void
graph_su_start(graph_vertex_t *v)
{
	/*
	 * /etc/inittab used to have the initial /sbin/rcS as a 'sysinit'
	 * entry with a runlevel of 'S', before jumping to the final
	 * target runlevel (as set in initdefault).  We mimic that legacy
	 * behavior here.
	 */
	utmpx_set_runlevel('S', '0', B_FALSE);
	vertex_send_event(v, RESTARTER_EVENT_TYPE_START);
}

static void
graph_post_su_online(void)
{
	graph_runlevel_changed('S', 1);
}

static void
graph_post_su_disable(void)
{
	graph_runlevel_changed('S', 0);
}

static void
graph_post_mu_online(void)
{
	graph_runlevel_changed('2', 1);
}

static void
graph_post_mu_disable(void)
{
	graph_runlevel_changed('2', 0);
}

static void
graph_post_mus_online(void)
{
	graph_runlevel_changed('3', 1);
}

static void
graph_post_mus_disable(void)
{
	graph_runlevel_changed('3', 0);
}

static struct special_vertex_info {
	const char	*name;
	void		(*start_f)(graph_vertex_t *);
	void		(*post_online_f)(void);
	void		(*post_disable_f)(void);
} special_vertices[] = {
	{ CONSOLE_LOGIN_FMRI, graph_clogin_start, NULL, NULL },
	{ SCF_MILESTONE_SINGLE_USER, graph_su_start,
	    graph_post_su_online, graph_post_su_disable },
	{ SCF_MILESTONE_MULTI_USER, NULL,
	    graph_post_mu_online, graph_post_mu_disable },
	{ SCF_MILESTONE_MULTI_USER_SERVER, NULL,
	    graph_post_mus_online, graph_post_mus_disable },
	{ NULL },
};


void
vertex_send_event(graph_vertex_t *v, restarter_event_type_t e)
{
	switch (e) {
	case RESTARTER_EVENT_TYPE_ADD_INSTANCE:
		assert(v->gv_state == RESTARTER_STATE_UNINIT);

		MUTEX_LOCK(&st->st_load_lock);
		st->st_load_instances++;
		MUTEX_UNLOCK(&st->st_load_lock);
		break;

	case RESTARTER_EVENT_TYPE_ENABLE:
		log_framework(LOG_DEBUG, "Enabling %s.\n", v->gv_name);
		assert(v->gv_state == RESTARTER_STATE_UNINIT ||
		    v->gv_state == RESTARTER_STATE_DISABLED ||
		    v->gv_state == RESTARTER_STATE_MAINT);
		break;

	case RESTARTER_EVENT_TYPE_DISABLE:
	case RESTARTER_EVENT_TYPE_ADMIN_DISABLE:
		log_framework(LOG_DEBUG, "Disabling %s.\n", v->gv_name);
		assert(v->gv_state != RESTARTER_STATE_DISABLED);
		break;

	case RESTARTER_EVENT_TYPE_STOP_RESET:
	case RESTARTER_EVENT_TYPE_STOP:
		log_framework(LOG_DEBUG, "Stopping %s.\n", v->gv_name);
		assert(v->gv_state == RESTARTER_STATE_DEGRADED ||
		    v->gv_state == RESTARTER_STATE_ONLINE);
		break;

	case RESTARTER_EVENT_TYPE_START:
		log_framework(LOG_DEBUG, "Starting %s.\n", v->gv_name);
		assert(v->gv_state == RESTARTER_STATE_OFFLINE);
		break;

	case RESTARTER_EVENT_TYPE_REMOVE_INSTANCE:
	case RESTARTER_EVENT_TYPE_ADMIN_DEGRADED:
	case RESTARTER_EVENT_TYPE_ADMIN_REFRESH:
	case RESTARTER_EVENT_TYPE_ADMIN_RESTART:
	case RESTARTER_EVENT_TYPE_ADMIN_MAINT_OFF:
	case RESTARTER_EVENT_TYPE_ADMIN_MAINT_ON:
	case RESTARTER_EVENT_TYPE_ADMIN_MAINT_ON_IMMEDIATE:
	case RESTARTER_EVENT_TYPE_DEPENDENCY_CYCLE:
	case RESTARTER_EVENT_TYPE_INVALID_DEPENDENCY:
		break;

	default:
#ifndef NDEBUG
		uu_warn("%s:%d: Bad event %d.\n", __FILE__, __LINE__, e);
#endif
		abort();
	}

	restarter_protocol_send_event(v->gv_name, v->gv_restarter_channel, e,
	    v->gv_reason);
}

static void
graph_unset_restarter(graph_vertex_t *v)
{
	assert(MUTEX_HELD(&dgraph_lock));
	assert(v->gv_flags & GV_CONFIGURED);

	vertex_send_event(v, RESTARTER_EVENT_TYPE_REMOVE_INSTANCE);

	if (v->gv_restarter_id != -1) {
		graph_vertex_t *rv;

		rv = vertex_get_by_id(v->gv_restarter_id);
		graph_remove_edge(v, rv);
	}

	v->gv_restarter_id = -1;
	v->gv_restarter_channel = NULL;
}

/*
 * Return VERTEX_REMOVED when the vertex passed in argument is deleted from the
 * dgraph otherwise return VERTEX_INUSE.
 */
static int
free_if_unrefed(graph_vertex_t *v)
{
	assert(MUTEX_HELD(&dgraph_lock));

	if (v->gv_refs > 0)
		return (VERTEX_INUSE);

	if (v->gv_type == GVT_SVC &&
	    uu_list_numnodes(v->gv_dependents) == 0 &&
	    uu_list_numnodes(v->gv_dependencies) == 0) {
		graph_remove_vertex(v);
		return (VERTEX_REMOVED);
	} else if (v->gv_type == GVT_INST &&
	    (v->gv_flags & GV_CONFIGURED) == 0 &&
	    uu_list_numnodes(v->gv_dependents) == 1 &&
	    uu_list_numnodes(v->gv_dependencies) == 0) {
		remove_inst_vertex(v);
		return (VERTEX_REMOVED);
	}

	return (VERTEX_INUSE);
}

static void
delete_depgroup(graph_vertex_t *v)
{
	graph_edge_t *e;
	graph_vertex_t *dv;

	assert(MUTEX_HELD(&dgraph_lock));
	assert(v->gv_type == GVT_GROUP);
	assert(uu_list_numnodes(v->gv_dependents) == 0);

	while ((e = uu_list_first(v->gv_dependencies)) != NULL) {
		dv = e->ge_vertex;

		graph_remove_edge(v, dv);

		switch (dv->gv_type) {
		case GVT_INST:		/* instance dependency */
		case GVT_SVC:		/* service dependency */
			(void) free_if_unrefed(dv);
			break;

		case GVT_FILE:		/* file dependency */
			assert(uu_list_numnodes(dv->gv_dependencies) == 0);
			if (uu_list_numnodes(dv->gv_dependents) == 0)
				graph_remove_vertex(dv);
			break;

		default:
#ifndef NDEBUG
			uu_warn("%s:%d: Unexpected node type %d", __FILE__,
			    __LINE__, dv->gv_type);
#endif
			abort();
		}
	}

	graph_remove_vertex(v);
}

static int
delete_instance_deps_cb(graph_edge_t *e, void **ptrs)
{
	graph_vertex_t *v = ptrs[0];
	boolean_t delete_restarter_dep = (boolean_t)ptrs[1];
	graph_vertex_t *dv;

	dv = e->ge_vertex;

	/*
	 * We have four possibilities here:
	 *   - GVT_INST: restarter
	 *   - GVT_GROUP - GVT_INST: instance dependency
	 *   - GVT_GROUP - GVT_SVC - GV_INST: service dependency
	 *   - GVT_GROUP - GVT_FILE: file dependency
	 */
	switch (dv->gv_type) {
	case GVT_INST:	/* restarter */
		assert(dv->gv_id == v->gv_restarter_id);
		if (delete_restarter_dep)
			graph_remove_edge(v, dv);
		break;

	case GVT_GROUP:	/* pg dependency */
		graph_remove_edge(v, dv);
		delete_depgroup(dv);
		break;

	case GVT_FILE:
		/* These are currently not direct dependencies */

	default:
#ifndef NDEBUG
		uu_warn("%s:%d: Bad vertex type %d.\n", __FILE__, __LINE__,
		    dv->gv_type);
#endif
		abort();
	}

	return (UU_WALK_NEXT);
}

static void
delete_instance_dependencies(graph_vertex_t *v, boolean_t delete_restarter_dep)
{
	void *ptrs[2];
	int r;

	assert(MUTEX_HELD(&dgraph_lock));
	assert(v->gv_type == GVT_INST);

	ptrs[0] = v;
	ptrs[1] = (void *)delete_restarter_dep;

	r = uu_list_walk(v->gv_dependencies,
	    (uu_walk_fn_t *)delete_instance_deps_cb, &ptrs, UU_WALK_ROBUST);
	assert(r == 0);
}

/*
 * int graph_insert_vertex_unconfigured()
 *   Insert a vertex without sending any restarter events. If the vertex
 *   already exists or creation is successful, return a pointer to it in *vp.
 *
 *   If type is not GVT_GROUP, dt can remain unset.
 *
 *   Returns 0, EEXIST, or EINVAL if the arguments are invalid (i.e., fmri
 *   doesn't agree with type, or type doesn't agree with dt).
 */
static int
graph_insert_vertex_unconfigured(const char *fmri, gv_type_t type,
    depgroup_type_t dt, restarter_error_t rt, graph_vertex_t **vp)
{
	int r;
	int i;

	assert(MUTEX_HELD(&dgraph_lock));

	switch (type) {
	case GVT_SVC:
	case GVT_INST:
		if (strncmp(fmri, "svc:", sizeof ("svc:") - 1) != 0)
			return (EINVAL);
		break;

	case GVT_FILE:
		if (strncmp(fmri, "file:", sizeof ("file:") - 1) != 0)
			return (EINVAL);
		break;

	case GVT_GROUP:
		if (dt <= 0 || rt < 0)
			return (EINVAL);
		break;

	default:
#ifndef NDEBUG
		uu_warn("%s:%d: Unknown type %d.\n", __FILE__, __LINE__, type);
#endif
		abort();
	}

	*vp = vertex_get_by_name(fmri);
	if (*vp != NULL)
		return (EEXIST);

	*vp = graph_add_vertex(fmri);

	(*vp)->gv_type = type;
	(*vp)->gv_depgroup = dt;
	(*vp)->gv_restart = rt;

	(*vp)->gv_flags = 0;
	(*vp)->gv_state = RESTARTER_STATE_NONE;

	for (i = 0; special_vertices[i].name != NULL; ++i) {
		if (strcmp(fmri, special_vertices[i].name) == 0) {
			(*vp)->gv_start_f = special_vertices[i].start_f;
			(*vp)->gv_post_online_f =
			    special_vertices[i].post_online_f;
			(*vp)->gv_post_disable_f =
			    special_vertices[i].post_disable_f;
			break;
		}
	}

	(*vp)->gv_restarter_id = -1;
	(*vp)->gv_restarter_channel = 0;

	if (type == GVT_INST) {
		char *sfmri;
		graph_vertex_t *sv;

		sfmri = inst_fmri_to_svc_fmri(fmri);
		sv = vertex_get_by_name(sfmri);
		if (sv == NULL) {
			r = graph_insert_vertex_unconfigured(sfmri, GVT_SVC, 0,
			    0, &sv);
			assert(r == 0);
		}
		startd_free(sfmri, max_scf_fmri_size);

		graph_add_edge(sv, *vp);
	}

	/*
	 * If this vertex is in the subgraph, mark it as so, for both
	 * GVT_INST and GVT_SERVICE verteces.
	 * A GVT_SERVICE vertex can only be in the subgraph if another instance
	 * depends on it, in which case it's already been added to the graph
	 * and marked as in the subgraph (by refresh_vertex()).  If a
	 * GVT_SERVICE vertex was freshly added (by the code above), it means
	 * that it has no dependents, and cannot be in the subgraph.
	 * Regardless of this, we still check that gv_flags includes
	 * GV_INSUBGRAPH in the event that future behavior causes the above
	 * code to add a GVT_SERVICE vertex which should be in the subgraph.
	 */

	(*vp)->gv_flags |= (should_be_in_subgraph(*vp)? GV_INSUBGRAPH : 0);

	return (0);
}

/*
 * Returns 0 on success or ELOOP if the dependency would create a cycle.
 */
static int
graph_insert_dependency(graph_vertex_t *fv, graph_vertex_t *tv, int **pathp)
{
	hrtime_t now;

	assert(MUTEX_HELD(&dgraph_lock));

	/* cycle detection */
	now = gethrtime();

	/* Don't follow exclusions. */
	if (!(fv->gv_type == GVT_GROUP &&
	    fv->gv_depgroup == DEPGRP_EXCLUDE_ALL)) {
		*pathp = is_path_to(tv, fv);
		if (*pathp)
			return (ELOOP);
	}

	dep_cycle_ns += gethrtime() - now;
	++dep_inserts;
	now = gethrtime();

	graph_add_edge(fv, tv);

	dep_insert_ns += gethrtime() - now;

	/* Check if the dependency adds the "to" vertex to the subgraph */
	tv->gv_flags |= (should_be_in_subgraph(tv) ? GV_INSUBGRAPH : 0);

	return (0);
}

static int
inst_running(graph_vertex_t *v)
{
	assert(v->gv_type == GVT_INST);

	if (v->gv_state == RESTARTER_STATE_ONLINE ||
	    v->gv_state == RESTARTER_STATE_DEGRADED)
		return (1);

	return (0);
}

/*
 * The dependency evaluation functions return
 *   1 - dependency satisfied
 *   0 - dependency unsatisfied
 *   -1 - dependency unsatisfiable (without administrator intervention)
 *
 * The functions also take a boolean satbility argument.  When true, the
 * functions may recurse in order to determine satisfiability.
 */
static int require_any_satisfied(graph_vertex_t *, boolean_t);
static int dependency_satisfied(graph_vertex_t *, boolean_t);

/*
 * A require_all dependency is unsatisfied if any elements are unsatisfied.  It
 * is unsatisfiable if any elements are unsatisfiable.
 */
static int
require_all_satisfied(graph_vertex_t *groupv, boolean_t satbility)
{
	graph_edge_t *edge;
	int i;
	boolean_t any_unsatisfied;

	if (uu_list_numnodes(groupv->gv_dependencies) == 0)
		return (1);

	any_unsatisfied = B_FALSE;

	for (edge = uu_list_first(groupv->gv_dependencies);
	    edge != NULL;
	    edge = uu_list_next(groupv->gv_dependencies, edge)) {
		i = dependency_satisfied(edge->ge_vertex, satbility);
		if (i == 1)
			continue;

		log_framework2(LOG_DEBUG, DEBUG_DEPENDENCIES,
		    "require_all(%s): %s is unsatisfi%s.\n", groupv->gv_name,
		    edge->ge_vertex->gv_name, i == 0 ? "ed" : "able");

		if (!satbility)
			return (0);

		if (i == -1)
			return (-1);

		any_unsatisfied = B_TRUE;
	}

	return (any_unsatisfied ? 0 : 1);
}

/*
 * A require_any dependency is satisfied if any element is satisfied.  It is
 * satisfiable if any element is satisfiable.
 */
static int
require_any_satisfied(graph_vertex_t *groupv, boolean_t satbility)
{
	graph_edge_t *edge;
	int s;
	boolean_t satisfiable;

	if (uu_list_numnodes(groupv->gv_dependencies) == 0)
		return (1);

	satisfiable = B_FALSE;

	for (edge = uu_list_first(groupv->gv_dependencies);
	    edge != NULL;
	    edge = uu_list_next(groupv->gv_dependencies, edge)) {
		s = dependency_satisfied(edge->ge_vertex, satbility);

		if (s == 1)
			return (1);

		log_framework2(LOG_DEBUG, DEBUG_DEPENDENCIES,
		    "require_any(%s): %s is unsatisfi%s.\n",
		    groupv->gv_name, edge->ge_vertex->gv_name,
		    s == 0 ? "ed" : "able");

		if (satbility && s == 0)
			satisfiable = B_TRUE;
	}

	return (!satbility || satisfiable ? 0 : -1);
}

/*
 * An optional_all dependency only considers elements which are configured,
 * enabled, and not in maintenance.  If any are unsatisfied, then the dependency
 * is unsatisfied.
 *
 * Offline dependencies which are waiting for a dependency to come online are
 * unsatisfied.  Offline dependences which cannot possibly come online
 * (unsatisfiable) are always considered satisfied.
 */
static int
optional_all_satisfied(graph_vertex_t *groupv, boolean_t satbility)
{
	graph_edge_t *edge;
	graph_vertex_t *v;
	boolean_t any_qualified;
	boolean_t any_unsatisfied;
	int i;

	any_qualified = B_FALSE;
	any_unsatisfied = B_FALSE;

	for (edge = uu_list_first(groupv->gv_dependencies);
	    edge != NULL;
	    edge = uu_list_next(groupv->gv_dependencies, edge)) {
		v = edge->ge_vertex;

		switch (v->gv_type) {
		case GVT_INST:
			/* Skip missing instances */
			if ((v->gv_flags & GV_CONFIGURED) == 0)
				continue;

			if (v->gv_state == RESTARTER_STATE_MAINT)
				continue;

			any_qualified = B_TRUE;
			if (v->gv_state == RESTARTER_STATE_OFFLINE) {
				/*
				 * For offline dependencies, treat unsatisfiable
				 * as satisfied.
				 */
				i = dependency_satisfied(v, B_TRUE);
				if (i == -1)
					i = 1;
			} else if (v->gv_state == RESTARTER_STATE_DISABLED) {
				/*
				 * If the instance is transitioning out of
				 * disabled the dependency is temporarily
				 * unsatisfied (not unsatisfiable).
				 */
				i = v->gv_flags & GV_ENABLED ? 0 : 1;
			} else {
				i = dependency_satisfied(v, satbility);
			}
			break;

		case GVT_FILE:
			any_qualified = B_TRUE;
			i = dependency_satisfied(v, satbility);

			break;

		case GVT_SVC: {
			any_qualified = B_TRUE;
			i = optional_all_satisfied(v, satbility);

			break;
		}

		case GVT_GROUP:
		default:
#ifndef NDEBUG
			uu_warn("%s:%d: Unexpected vertex type %d.\n", __FILE__,
			    __LINE__, v->gv_type);
#endif
			abort();
		}

		if (i == 1)
			continue;

		log_framework2(LOG_DEBUG, DEBUG_DEPENDENCIES,
		    "optional_all(%s): %s is unsatisfi%s.\n", groupv->gv_name,
		    v->gv_name, i == 0 ? "ed" : "able");

		if (!satbility)
			return (0);
		if (i == -1)
			return (-1);
		any_unsatisfied = B_TRUE;
	}

	if (!any_qualified)
		return (1);

	return (any_unsatisfied ? 0 : 1);
}

/*
 * An exclude_all dependency is unsatisfied if any non-service element is
 * satisfied or any service instance which is configured, enabled, and not in
 * maintenance is satisfied.  Usually when unsatisfied, it is also
 * unsatisfiable.
 */
#define	LOG_EXCLUDE(u, v)						\
	log_framework2(LOG_DEBUG, DEBUG_DEPENDENCIES,			\
	    "exclude_all(%s): %s is satisfied.\n",			\
	    (u)->gv_name, (v)->gv_name)

/* ARGSUSED */
static int
exclude_all_satisfied(graph_vertex_t *groupv, boolean_t satbility)
{
	graph_edge_t *edge, *e2;
	graph_vertex_t *v, *v2;

	for (edge = uu_list_first(groupv->gv_dependencies);
	    edge != NULL;
	    edge = uu_list_next(groupv->gv_dependencies, edge)) {
		v = edge->ge_vertex;

		switch (v->gv_type) {
		case GVT_INST:
			if ((v->gv_flags & GV_CONFIGURED) == 0)
				continue;

			switch (v->gv_state) {
			case RESTARTER_STATE_ONLINE:
			case RESTARTER_STATE_DEGRADED:
				LOG_EXCLUDE(groupv, v);
				return (v->gv_flags & GV_ENABLED ? -1 : 0);

			case RESTARTER_STATE_OFFLINE:
			case RESTARTER_STATE_UNINIT:
				LOG_EXCLUDE(groupv, v);
				return (0);

			case RESTARTER_STATE_DISABLED:
			case RESTARTER_STATE_MAINT:
				continue;

			default:
#ifndef NDEBUG
				uu_warn("%s:%d: Unexpected vertex state %d.\n",
				    __FILE__, __LINE__, v->gv_state);
#endif
				abort();
			}
			/* NOTREACHED */

		case GVT_SVC:
			break;

		case GVT_FILE:
			if (!file_ready(v))
				continue;
			LOG_EXCLUDE(groupv, v);
			return (-1);

		case GVT_GROUP:
		default:
#ifndef NDEBUG
			uu_warn("%s:%d: Unexpected vertex type %d.\n", __FILE__,
			    __LINE__, v->gv_type);
#endif
			abort();
		}

		/* v represents a service */
		if (uu_list_numnodes(v->gv_dependencies) == 0)
			continue;

		for (e2 = uu_list_first(v->gv_dependencies);
		    e2 != NULL;
		    e2 = uu_list_next(v->gv_dependencies, e2)) {
			v2 = e2->ge_vertex;
			assert(v2->gv_type == GVT_INST);

			if ((v2->gv_flags & GV_CONFIGURED) == 0)
				continue;

			switch (v2->gv_state) {
			case RESTARTER_STATE_ONLINE:
			case RESTARTER_STATE_DEGRADED:
				LOG_EXCLUDE(groupv, v2);
				return (v2->gv_flags & GV_ENABLED ? -1 : 0);

			case RESTARTER_STATE_OFFLINE:
			case RESTARTER_STATE_UNINIT:
				LOG_EXCLUDE(groupv, v2);
				return (0);

			case RESTARTER_STATE_DISABLED:
			case RESTARTER_STATE_MAINT:
				continue;

			default:
#ifndef NDEBUG
				uu_warn("%s:%d: Unexpected vertex type %d.\n",
				    __FILE__, __LINE__, v2->gv_type);
#endif
				abort();
			}
		}
	}

	return (1);
}

/*
 * int instance_satisfied()
 *   Determine if all the dependencies are satisfied for the supplied instance
 *   vertex. Return 1 if they are, 0 if they aren't, and -1 if they won't be
 *   without administrator intervention.
 */
static int
instance_satisfied(graph_vertex_t *v, boolean_t satbility)
{
	assert(v->gv_type == GVT_INST);
	assert(!inst_running(v));

	return (require_all_satisfied(v, satbility));
}

/*
 * Decide whether v can satisfy a dependency.  v can either be a child of
 * a group vertex, or of an instance vertex.
 */
static int
dependency_satisfied(graph_vertex_t *v, boolean_t satbility)
{
	switch (v->gv_type) {
	case GVT_INST:
		if ((v->gv_flags & GV_CONFIGURED) == 0) {
			if (v->gv_flags & GV_DEATHROW) {
				/*
				 * A dependency on an instance with GV_DEATHROW
				 * flag is always considered as satisfied.
				 */
				return (1);
			}
			return (-1);
		}

		/*
		 * Any vertex with the GV_TODISABLE flag set is guaranteed
		 * to have its dependencies unsatisfiable.  Any vertex with
		 * GV_TOOFFLINE may be satisfied after it transitions.
		 */
		if (v->gv_flags & GV_TODISABLE)
			return (-1);
		if (v->gv_flags & GV_TOOFFLINE)
			return (0);

		switch (v->gv_state) {
		case RESTARTER_STATE_ONLINE:
		case RESTARTER_STATE_DEGRADED:
			return (1);

		case RESTARTER_STATE_OFFLINE:
			if (!satbility)
				return (0);
			return (instance_satisfied(v, satbility) != -1 ?
			    0 : -1);

		case RESTARTER_STATE_DISABLED:
		case RESTARTER_STATE_MAINT:
			return (-1);

		case RESTARTER_STATE_UNINIT:
			return (0);

		default:
#ifndef NDEBUG
			uu_warn("%s:%d: Unexpected vertex state %d.\n",
			    __FILE__, __LINE__, v->gv_state);
#endif
			abort();
			/* NOTREACHED */
		}

	case GVT_SVC:
		if (uu_list_numnodes(v->gv_dependencies) == 0)
			return (-1);
		return (require_any_satisfied(v, satbility));

	case GVT_FILE:
		/* i.e., we assume files will not be automatically generated */
		return (file_ready(v) ? 1 : -1);

	case GVT_GROUP:
		break;

	default:
#ifndef NDEBUG
		uu_warn("%s:%d: Unexpected node type %d.\n", __FILE__, __LINE__,
		    v->gv_type);
#endif
		abort();
		/* NOTREACHED */
	}

	switch (v->gv_depgroup) {
	case DEPGRP_REQUIRE_ANY:
		return (require_any_satisfied(v, satbility));

	case DEPGRP_REQUIRE_ALL:
		return (require_all_satisfied(v, satbility));

	case DEPGRP_OPTIONAL_ALL:
		return (optional_all_satisfied(v, satbility));

	case DEPGRP_EXCLUDE_ALL:
		return (exclude_all_satisfied(v, satbility));

	default:
#ifndef NDEBUG
		uu_warn("%s:%d: Unknown dependency grouping %d.\n", __FILE__,
		    __LINE__, v->gv_depgroup);
#endif
		abort();
	}
}

void
graph_start_if_satisfied(graph_vertex_t *v)
{
	if (v->gv_state == RESTARTER_STATE_OFFLINE &&
	    instance_satisfied(v, B_FALSE) == 1) {
		if (v->gv_start_f == NULL)
			vertex_send_event(v, RESTARTER_EVENT_TYPE_START);
		else
			v->gv_start_f(v);
	}
}

/*
 * propagate_satbility()
 *
 * This function is used when the given vertex changes state in such a way that
 * one of its dependents may become unsatisfiable.  This happens when an
 * instance transitions between offline -> online, or from !running ->
 * maintenance, as well as when an instance is removed from the graph.
 *
 * We have to walk all the dependents, since optional_all dependencies several
 * levels up could become (un)satisfied, instead of unsatisfiable.  For example,
 *
 *	+-----+  optional_all  +-----+  require_all  +-----+
 *	|  A  |--------------->|  B  |-------------->|  C  |
 *	+-----+                +-----+               +-----+
 *
 *	                                        offline -> maintenance
 *
 * If C goes into maintenance, it's not enough simply to check B.  Because A has
 * an optional dependency, what was previously an unsatisfiable situation is now
 * satisfied (B will never come online, even though its state hasn't changed).
 *
 * Note that it's not necessary to continue examining dependents after reaching
 * an optional_all dependency.  It's not possible for an optional_all dependency
 * to change satisfiability without also coming online, in which case we get a
 * start event and propagation continues naturally.  However, it does no harm to
 * continue propagating satisfiability (as it is a relatively rare event), and
 * keeps the walker code simple and generic.
 */
/*ARGSUSED*/
static int
satbility_cb(graph_vertex_t *v, void *arg)
{
	if (v->gv_flags & GV_TOOFFLINE)
		return (UU_WALK_NEXT);

	if (v->gv_type == GVT_INST)
		graph_start_if_satisfied(v);

	return (UU_WALK_NEXT);
}

static void
propagate_satbility(graph_vertex_t *v)
{
	graph_walk(v, WALK_DEPENDENTS, satbility_cb, NULL, NULL);
}

static void propagate_stop(graph_vertex_t *, void *);

/*
 * propagate_start()
 *
 * This function is used to propagate a start event to the dependents of the
 * given vertex.  Any dependents that are offline but have their dependencies
 * satisfied are started.  Any dependents that are online and have restart_on
 * set to "restart" or "refresh" are restarted because their dependencies have
 * just changed.  This only happens with optional_all dependencies.
 */
static void
propagate_start(graph_vertex_t *v, void *arg)
{
	restarter_error_t err = (restarter_error_t)arg;

	if (v->gv_flags & GV_TOOFFLINE)
		return;

	switch (v->gv_type) {
	case GVT_INST:
		/* Restarter */
		if (inst_running(v)) {
			if (err == RERR_RESTART || err == RERR_REFRESH) {
				vertex_send_event(v,
				    RESTARTER_EVENT_TYPE_STOP_RESET);
			}
		} else {
			graph_start_if_satisfied(v);
		}
		break;

	case GVT_GROUP:
		if (v->gv_depgroup == DEPGRP_EXCLUDE_ALL) {
			graph_walk_dependents(v, propagate_stop,
			    (void *)RERR_RESTART);
			break;
		}
		err = v->gv_restart;
		/* FALLTHROUGH */

	case GVT_SVC:
		graph_walk_dependents(v, propagate_start, (void *)err);
		break;

	case GVT_FILE:
#ifndef NDEBUG
		uu_warn("%s:%d: propagate_start() encountered GVT_FILE.\n",
		    __FILE__, __LINE__);
#endif
		abort();
		/* NOTREACHED */

	default:
#ifndef NDEBUG
		uu_warn("%s:%d: Unknown vertex type %d.\n", __FILE__, __LINE__,
		    v->gv_type);
#endif
		abort();
	}
}

/*
 * propagate_stop()
 *
 * This function is used to propagate a stop event to the dependents of the
 * given vertex.  Any dependents that are online (or in degraded state) with
 * the restart_on property set to "restart" or "refresh" will be stopped as
 * their dependencies have just changed, propagate_start() will start them
 * again once their dependencies have been re-satisfied.
 */
static void
propagate_stop(graph_vertex_t *v, void *arg)
{
	restarter_error_t err = (restarter_error_t)arg;

	if (v->gv_flags & GV_TOOFFLINE)
		return;

	switch (v->gv_type) {
	case GVT_INST:
		/* Restarter */
		if (err > RERR_NONE && inst_running(v)) {
			if (err == RERR_RESTART || err == RERR_REFRESH) {
				vertex_send_event(v,
				    RESTARTER_EVENT_TYPE_STOP_RESET);
			} else {
				vertex_send_event(v, RESTARTER_EVENT_TYPE_STOP);
			}
		}
		break;

	case GVT_SVC:
		graph_walk_dependents(v, propagate_stop, arg);
		break;

	case GVT_FILE:
#ifndef NDEBUG
		uu_warn("%s:%d: propagate_stop() encountered GVT_FILE.\n",
		    __FILE__, __LINE__);
#endif
		abort();
		/* NOTREACHED */

	case GVT_GROUP:
		if (v->gv_depgroup == DEPGRP_EXCLUDE_ALL) {
			graph_walk_dependents(v, propagate_start, NULL);
			break;
		}

		if (err == RERR_NONE || err > v->gv_restart)
			break;

		graph_walk_dependents(v, propagate_stop, arg);
		break;

	default:
#ifndef NDEBUG
		uu_warn("%s:%d: Unknown vertex type %d.\n", __FILE__, __LINE__,
		    v->gv_type);
#endif
		abort();
	}
}

void
offline_vertex(graph_vertex_t *v)
{
	scf_handle_t *h = libscf_handle_create_bound_loop();
	scf_instance_t *scf_inst = safe_scf_instance_create(h);
	scf_propertygroup_t *pg = safe_scf_pg_create(h);
	restarter_instance_state_t state, next_state;
	int r;

	assert(v->gv_type == GVT_INST);

	if (scf_inst == NULL)
		bad_error("safe_scf_instance_create", scf_error());
	if (pg == NULL)
		bad_error("safe_scf_pg_create", scf_error());

	/* if the vertex is already going offline, return */
rep_retry:
	if (scf_handle_decode_fmri(h, v->gv_name, NULL, NULL, scf_inst, NULL,
	    NULL, SCF_DECODE_FMRI_EXACT) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
			libscf_handle_rebind(h);
			goto rep_retry;

		case SCF_ERROR_NOT_FOUND:
			scf_pg_destroy(pg);
			scf_instance_destroy(scf_inst);
			(void) scf_handle_unbind(h);
			scf_handle_destroy(h);
			return;
		}
		uu_die("Can't decode FMRI %s: %s\n", v->gv_name,
		    scf_strerror(scf_error()));
	}

	r = scf_instance_get_pg(scf_inst, SCF_PG_RESTARTER, pg);
	if (r != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
			libscf_handle_rebind(h);
			goto rep_retry;

		case SCF_ERROR_NOT_SET:
		case SCF_ERROR_NOT_FOUND:
			scf_pg_destroy(pg);
			scf_instance_destroy(scf_inst);
			(void) scf_handle_unbind(h);
			scf_handle_destroy(h);
			return;

		default:
			bad_error("scf_instance_get_pg", scf_error());
		}
	} else {
		r = libscf_read_states(pg, &state, &next_state);
		if (r == 0 && (next_state == RESTARTER_STATE_OFFLINE ||
		    next_state == RESTARTER_STATE_DISABLED)) {
			log_framework(LOG_DEBUG,
			    "%s: instance is already going down.\n",
			    v->gv_name);
			scf_pg_destroy(pg);
			scf_instance_destroy(scf_inst);
			(void) scf_handle_unbind(h);
			scf_handle_destroy(h);
			return;
		}
	}

	scf_pg_destroy(pg);
	scf_instance_destroy(scf_inst);
	(void) scf_handle_unbind(h);
	scf_handle_destroy(h);

	vertex_send_event(v, RESTARTER_EVENT_TYPE_STOP_RESET);
}

/*
 * void graph_enable_by_vertex()
 *   If admin is non-zero, this is an administrative request for change
 *   of the enabled property.  Thus, send the ADMIN_DISABLE rather than
 *   a plain DISABLE restarter event.
 */
void
graph_enable_by_vertex(graph_vertex_t *vertex, int enable, int admin)
{
	graph_vertex_t *v;
	int r;

	assert(MUTEX_HELD(&dgraph_lock));
	assert((vertex->gv_flags & GV_CONFIGURED));

	vertex->gv_flags = (vertex->gv_flags & ~GV_ENABLED) |
	    (enable ? GV_ENABLED : 0);

	if (enable) {
		if (vertex->gv_state != RESTARTER_STATE_OFFLINE &&
		    vertex->gv_state != RESTARTER_STATE_DEGRADED &&
		    vertex->gv_state != RESTARTER_STATE_ONLINE) {
			/*
			 * In case the vertex was notified to go down,
			 * but now can return online, clear the _TOOFFLINE
			 * and _TODISABLE flags.
			 */
			vertex->gv_flags &= ~GV_TOOFFLINE;
			vertex->gv_flags &= ~GV_TODISABLE;

			vertex_send_event(vertex, RESTARTER_EVENT_TYPE_ENABLE);
		}

		/*
		 * Wait for state update from restarter before sending _START or
		 * _STOP.
		 */

		return;
	}

	if (vertex->gv_state == RESTARTER_STATE_DISABLED)
		return;

	if (!admin) {
		vertex_send_event(vertex, RESTARTER_EVENT_TYPE_DISABLE);

		/*
		 * Wait for state update from restarter before sending _START or
		 * _STOP.
		 */

		return;
	}

	/*
	 * If it is a DISABLE event requested by the administrator then we are
	 * offlining the dependents first.
	 */

	/*
	 * Set GV_TOOFFLINE for the services we are offlining. We cannot
	 * clear the GV_TOOFFLINE bits from all the services because
	 * other DISABLE events might be handled at the same time.
	 */
	vertex->gv_flags |= GV_TOOFFLINE;

	/* remember which vertex to disable... */
	vertex->gv_flags |= GV_TODISABLE;

	log_framework(LOG_DEBUG, "Marking in-subtree vertices before "
	    "disabling %s.\n", vertex->gv_name);

	/* set GV_TOOFFLINE for its dependents */
	r = uu_list_walk(vertex->gv_dependents, (uu_walk_fn_t *)mark_subtree,
	    NULL, 0);
	assert(r == 0);

	/* disable the instance now if there is nothing else to offline */
	if (insubtree_dependents_down(vertex) == B_TRUE) {
		vertex_send_event(vertex, RESTARTER_EVENT_TYPE_ADMIN_DISABLE);
		return;
	}

	/*
	 * This loop is similar to the one used for the graph reversal shutdown
	 * and could be improved in term of performance for the subtree reversal
	 * disable case.
	 */
	for (v = uu_list_first(dgraph); v != NULL;
	    v = uu_list_next(dgraph, v)) {
		/* skip the vertex we are disabling for now */
		if (v == vertex)
			continue;

		if (v->gv_type != GVT_INST ||
		    (v->gv_flags & GV_CONFIGURED) == 0 ||
		    (v->gv_flags & GV_ENABLED) == 0 ||
		    (v->gv_flags & GV_TOOFFLINE) == 0)
			continue;

		if ((v->gv_state != RESTARTER_STATE_ONLINE) &&
		    (v->gv_state != RESTARTER_STATE_DEGRADED)) {
			/* continue if there is nothing to offline */
			continue;
		}

		/*
		 * Instances which are up need to come down before we're
		 * done, but we can only offline the leaves here. An
		 * instance is a leaf when all its dependents are down.
		 */
		if (insubtree_dependents_down(v) == B_TRUE) {
			log_framework(LOG_DEBUG, "Offlining in-subtree "
			    "instance %s for %s.\n",
			    v->gv_name, vertex->gv_name);
			offline_vertex(v);
		}
	}
}

static int configure_vertex(graph_vertex_t *, scf_instance_t *);

/*
 * Set the restarter for v to fmri_arg.  That is, make sure a vertex for
 * fmri_arg exists, make v depend on it, and send _ADD_INSTANCE for v.  If
 * v is already configured and fmri_arg indicates the current restarter, do
 * nothing.  If v is configured and fmri_arg is a new restarter, delete v's
 * dependency on the restarter, send _REMOVE_INSTANCE for v, and set the new
 * restarter.  Returns 0 on success, EINVAL if the FMRI is invalid,
 * ECONNABORTED if the repository connection is broken, and ELOOP
 * if the dependency would create a cycle.  In the last case, *pathp will
 * point to a -1-terminated array of ids which compose the path from v to
 * restarter_fmri.
 */
int
graph_change_restarter(graph_vertex_t *v, const char *fmri_arg, scf_handle_t *h,
    int **pathp)
{
	char *restarter_fmri = NULL;
	graph_vertex_t *rv;
	int err;
	int id;

	assert(MUTEX_HELD(&dgraph_lock));

	if (fmri_arg[0] != '\0') {
		err = fmri_canonify(fmri_arg, &restarter_fmri, B_TRUE);
		if (err != 0) {
			assert(err == EINVAL);
			return (err);
		}
	}

	if (restarter_fmri == NULL ||
	    strcmp(restarter_fmri, SCF_SERVICE_STARTD) == 0) {
		if (v->gv_flags & GV_CONFIGURED) {
			if (v->gv_restarter_id == -1) {
				if (restarter_fmri != NULL)
					startd_free(restarter_fmri,
					    max_scf_fmri_size);
				return (0);
			}

			graph_unset_restarter(v);
		}

		/* Master restarter, nothing to do. */
		v->gv_restarter_id = -1;
		v->gv_restarter_channel = NULL;
		vertex_send_event(v, RESTARTER_EVENT_TYPE_ADD_INSTANCE);
		return (0);
	}

	if (v->gv_flags & GV_CONFIGURED) {
		id = dict_lookup_byname(restarter_fmri);
		if (id != -1 && v->gv_restarter_id == id) {
			startd_free(restarter_fmri, max_scf_fmri_size);
			return (0);
		}

		graph_unset_restarter(v);
	}

	err = graph_insert_vertex_unconfigured(restarter_fmri, GVT_INST, 0,
	    RERR_NONE, &rv);
	startd_free(restarter_fmri, max_scf_fmri_size);
	assert(err == 0 || err == EEXIST);

	if (rv->gv_delegate_initialized == 0) {
		if ((rv->gv_delegate_channel = restarter_protocol_init_delegate(
		    rv->gv_name)) == NULL)
			return (EINVAL);
		rv->gv_delegate_initialized = 1;
	}
	v->gv_restarter_id = rv->gv_id;
	v->gv_restarter_channel = rv->gv_delegate_channel;

	err = graph_insert_dependency(v, rv, pathp);
	if (err != 0) {
		assert(err == ELOOP);
		return (ELOOP);
	}

	vertex_send_event(v, RESTARTER_EVENT_TYPE_ADD_INSTANCE);

	if (!(rv->gv_flags & GV_CONFIGURED)) {
		scf_instance_t *inst;

		err = libscf_fmri_get_instance(h, rv->gv_name, &inst);
		switch (err) {
		case 0:
			err = configure_vertex(rv, inst);
			scf_instance_destroy(inst);
			switch (err) {
			case 0:
			case ECANCELED:
				break;

			case ECONNABORTED:
				return (ECONNABORTED);

			default:
				bad_error("configure_vertex", err);
			}
			break;

		case ECONNABORTED:
			return (ECONNABORTED);

		case ENOENT:
			break;

		case ENOTSUP:
			/*
			 * The fmri doesn't specify an instance - translate
			 * to EINVAL.
			 */
			return (EINVAL);

		case EINVAL:
		default:
			bad_error("libscf_fmri_get_instance", err);
		}
	}

	return (0);
}


/*
 * Add all of the instances of the service named by fmri to the graph.
 * Returns
 *   0 - success
 *   ENOENT - service indicated by fmri does not exist
 *
 * In both cases *reboundp will be B_TRUE if the handle was rebound, or B_FALSE
 * otherwise.
 */
static int
add_service(const char *fmri, scf_handle_t *h, boolean_t *reboundp)
{
	scf_service_t *svc;
	scf_instance_t *inst;
	scf_iter_t *iter;
	char *inst_fmri;
	int ret, r;

	*reboundp = B_FALSE;

	svc = safe_scf_service_create(h);
	inst = safe_scf_instance_create(h);
	iter = safe_scf_iter_create(h);
	inst_fmri = startd_alloc(max_scf_fmri_size);

rebound:
	if (scf_handle_decode_fmri(h, fmri, NULL, svc, NULL, NULL, NULL,
	    SCF_DECODE_FMRI_EXACT) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			libscf_handle_rebind(h);
			*reboundp = B_TRUE;
			goto rebound;

		case SCF_ERROR_NOT_FOUND:
			ret = ENOENT;
			goto out;

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_NOT_BOUND:
		case SCF_ERROR_HANDLE_MISMATCH:
			bad_error("scf_handle_decode_fmri", scf_error());
		}
	}

	if (scf_iter_service_instances(iter, svc) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			libscf_handle_rebind(h);
			*reboundp = B_TRUE;
			goto rebound;

		case SCF_ERROR_DELETED:
			ret = ENOENT;
			goto out;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_NOT_BOUND:
		case SCF_ERROR_NOT_SET:
			bad_error("scf_iter_service_instances", scf_error());
		}
	}

	for (;;) {
		r = scf_iter_next_instance(iter, inst);
		if (r == 0)
			break;
		if (r != 1) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				libscf_handle_rebind(h);
				*reboundp = B_TRUE;
				goto rebound;

			case SCF_ERROR_DELETED:
				ret = ENOENT;
				goto out;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_NOT_BOUND:
			case SCF_ERROR_NOT_SET:
			case SCF_ERROR_INVALID_ARGUMENT:
				bad_error("scf_iter_next_instance",
				    scf_error());
			}
		}

		if (scf_instance_to_fmri(inst, inst_fmri, max_scf_fmri_size) <
		    0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
				libscf_handle_rebind(h);
				*reboundp = B_TRUE;
				goto rebound;

			case SCF_ERROR_DELETED:
				continue;

			case SCF_ERROR_NOT_BOUND:
			case SCF_ERROR_NOT_SET:
				bad_error("scf_instance_to_fmri", scf_error());
			}
		}

		r = dgraph_add_instance(inst_fmri, inst, B_FALSE);
		switch (r) {
		case 0:
		case ECANCELED:
			break;

		case EEXIST:
			continue;

		case ECONNABORTED:
			libscf_handle_rebind(h);
			*reboundp = B_TRUE;
			goto rebound;

		case EINVAL:
		default:
			bad_error("dgraph_add_instance", r);
		}
	}

	ret = 0;

out:
	startd_free(inst_fmri, max_scf_fmri_size);
	scf_iter_destroy(iter);
	scf_instance_destroy(inst);
	scf_service_destroy(svc);
	return (ret);
}

struct depfmri_info {
	graph_vertex_t	*v;		/* GVT_GROUP vertex */
	gv_type_t	type;		/* type of dependency */
	const char	*inst_fmri;	/* FMRI of parental GVT_INST vert. */
	const char	*pg_name;	/* Name of dependency pg */
	scf_handle_t	*h;
	int		err;		/* return error code */
	int		**pathp;	/* return circular dependency path */
};

/*
 * Find or create a vertex for fmri and make info->v depend on it.
 * Returns
 *   0 - success
 *   nonzero - failure
 *
 * On failure, sets info->err to
 *   EINVAL - fmri is invalid
 *	      fmri does not match info->type
 *   ELOOP - Adding the dependency creates a circular dependency.  *info->pathp
 *	     will point to an array of the ids of the members of the cycle.
 *   ECONNABORTED - repository connection was broken
 *   ECONNRESET - succeeded, but repository connection was reset
 */
static int
process_dependency_fmri(const char *fmri, struct depfmri_info *info)
{
	int err;
	graph_vertex_t *depgroup_v, *v;
	char *fmri_copy, *cfmri;
	size_t fmri_copy_sz;
	const char *scope, *service, *instance, *pg;
	scf_instance_t *inst;
	boolean_t rebound;

	assert(MUTEX_HELD(&dgraph_lock));

	/* Get or create vertex for FMRI */
	depgroup_v = info->v;

	if (strncmp(fmri, "file:", sizeof ("file:") - 1) == 0) {
		if (info->type != GVT_FILE) {
			log_framework(LOG_NOTICE,
			    "FMRI \"%s\" is not allowed for the \"%s\" "
			    "dependency's type of instance %s.\n", fmri,
			    info->pg_name, info->inst_fmri);
			return (info->err = EINVAL);
		}

		err = graph_insert_vertex_unconfigured(fmri, info->type, 0,
		    RERR_NONE, &v);
		switch (err) {
		case 0:
			break;

		case EEXIST:
			assert(v->gv_type == GVT_FILE);
			break;

		case EINVAL:		/* prevented above */
		default:
			bad_error("graph_insert_vertex_unconfigured", err);
		}
	} else {
		if (info->type != GVT_INST) {
			log_framework(LOG_NOTICE,
			    "FMRI \"%s\" is not allowed for the \"%s\" "
			    "dependency's type of instance %s.\n", fmri,
			    info->pg_name, info->inst_fmri);
			return (info->err = EINVAL);
		}

		/*
		 * We must canonify fmri & add a vertex for it.
		 */
		fmri_copy_sz = strlen(fmri) + 1;
		fmri_copy = startd_alloc(fmri_copy_sz);
		(void) strcpy(fmri_copy, fmri);

		/* Determine if the FMRI is a property group or instance */
		if (scf_parse_svc_fmri(fmri_copy, &scope, &service,
		    &instance, &pg, NULL) != 0) {
			startd_free(fmri_copy, fmri_copy_sz);
			log_framework(LOG_NOTICE,
			    "Dependency \"%s\" of %s has invalid FMRI "
			    "\"%s\".\n", info->pg_name, info->inst_fmri,
			    fmri);
			return (info->err = EINVAL);
		}

		if (service == NULL || pg != NULL) {
			startd_free(fmri_copy, fmri_copy_sz);
			log_framework(LOG_NOTICE,
			    "Dependency \"%s\" of %s does not designate a "
			    "service or instance.\n", info->pg_name,
			    info->inst_fmri);
			return (info->err = EINVAL);
		}

		if (scope == NULL || strcmp(scope, SCF_SCOPE_LOCAL) == 0) {
			cfmri = uu_msprintf("svc:/%s%s%s",
			    service, instance ? ":" : "", instance ? instance :
			    "");
		} else {
			cfmri = uu_msprintf("svc://%s/%s%s%s",
			    scope, service, instance ? ":" : "", instance ?
			    instance : "");
		}

		startd_free(fmri_copy, fmri_copy_sz);

		err = graph_insert_vertex_unconfigured(cfmri, instance ?
		    GVT_INST : GVT_SVC, instance ? 0 : DEPGRP_REQUIRE_ANY,
		    RERR_NONE, &v);
		uu_free(cfmri);
		switch (err) {
		case 0:
			break;

		case EEXIST:
			/* Verify v. */
			if (instance != NULL)
				assert(v->gv_type == GVT_INST);
			else
				assert(v->gv_type == GVT_SVC);
			break;

		default:
			bad_error("graph_insert_vertex_unconfigured", err);
		}
	}

	/* Add dependency from depgroup_v to new vertex */
	info->err = graph_insert_dependency(depgroup_v, v, info->pathp);
	switch (info->err) {
	case 0:
		break;

	case ELOOP:
		return (ELOOP);

	default:
		bad_error("graph_insert_dependency", info->err);
	}

	/* This must be after we insert the dependency, to avoid looping. */
	switch (v->gv_type) {
	case GVT_INST:
		if ((v->gv_flags & GV_CONFIGURED) != 0)
			break;

		inst = safe_scf_instance_create(info->h);

		rebound = B_FALSE;

rebound:
		err = libscf_lookup_instance(v->gv_name, inst);
		switch (err) {
		case 0:
			err = configure_vertex(v, inst);
			switch (err) {
			case 0:
			case ECANCELED:
				break;

			case ECONNABORTED:
				libscf_handle_rebind(info->h);
				rebound = B_TRUE;
				goto rebound;

			default:
				bad_error("configure_vertex", err);
			}
			break;

		case ENOENT:
			break;

		case ECONNABORTED:
			libscf_handle_rebind(info->h);
			rebound = B_TRUE;
			goto rebound;

		case EINVAL:
		case ENOTSUP:
		default:
			bad_error("libscf_fmri_get_instance", err);
		}

		scf_instance_destroy(inst);

		if (rebound)
			return (info->err = ECONNRESET);
		break;

	case GVT_SVC:
		(void) add_service(v->gv_name, info->h, &rebound);
		if (rebound)
			return (info->err = ECONNRESET);
	}

	return (0);
}

struct deppg_info {
	graph_vertex_t	*v;		/* GVT_INST vertex */
	int		err;		/* return error */
	int		**pathp;	/* return circular dependency path */
};

/*
 * Make info->v depend on a new GVT_GROUP node for this property group,
 * and then call process_dependency_fmri() for the values of the entity
 * property.  Return 0 on success, or if something goes wrong return nonzero
 * and set info->err to ECONNABORTED, EINVAL, or the error code returned by
 * process_dependency_fmri().
 */
static int
process_dependency_pg(scf_propertygroup_t *pg, struct deppg_info *info)
{
	scf_handle_t *h;
	depgroup_type_t deptype;
	restarter_error_t rerr;
	struct depfmri_info linfo;
	char *fmri, *pg_name;
	size_t fmri_sz;
	graph_vertex_t *depgrp;
	scf_property_t *prop;
	int err;
	int empty;
	scf_error_t scferr;
	ssize_t len;

	assert(MUTEX_HELD(&dgraph_lock));

	h = scf_pg_handle(pg);

	pg_name = startd_alloc(max_scf_name_size);

	len = scf_pg_get_name(pg, pg_name, max_scf_name_size);
	if (len < 0) {
		startd_free(pg_name, max_scf_name_size);
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			return (info->err = ECONNABORTED);

		case SCF_ERROR_DELETED:
			return (info->err = 0);

		case SCF_ERROR_NOT_SET:
			bad_error("scf_pg_get_name", scf_error());
		}
	}

	/*
	 * Skip over empty dependency groups.  Since dependency property
	 * groups are updated atomically, they are either empty or
	 * fully populated.
	 */
	empty = depgroup_empty(h, pg);
	if (empty < 0) {
		log_error(LOG_INFO,
		    "Error reading dependency group \"%s\" of %s: %s\n",
		    pg_name, info->v->gv_name, scf_strerror(scf_error()));
		startd_free(pg_name, max_scf_name_size);
		return (info->err = EINVAL);

	} else if (empty == 1) {
		log_framework(LOG_DEBUG,
		    "Ignoring empty dependency group \"%s\" of %s\n",
		    pg_name, info->v->gv_name);
		startd_free(pg_name, max_scf_name_size);
		return (info->err = 0);
	}

	fmri_sz = strlen(info->v->gv_name) + 1 + len + 1;
	fmri = startd_alloc(fmri_sz);

	(void) snprintf(fmri, fmri_sz, "%s>%s", info->v->gv_name,
	    pg_name);

	/* Validate the pg before modifying the graph */
	deptype = depgroup_read_grouping(h, pg);
	if (deptype == DEPGRP_UNSUPPORTED) {
		log_error(LOG_INFO,
		    "Dependency \"%s\" of %s has an unknown grouping value.\n",
		    pg_name, info->v->gv_name);
		startd_free(fmri, fmri_sz);
		startd_free(pg_name, max_scf_name_size);
		return (info->err = EINVAL);
	}

	rerr = depgroup_read_restart(h, pg);
	if (rerr == RERR_UNSUPPORTED) {
		log_error(LOG_INFO,
		    "Dependency \"%s\" of %s has an unknown restart_on value."
		    "\n", pg_name, info->v->gv_name);
		startd_free(fmri, fmri_sz);
		startd_free(pg_name, max_scf_name_size);
		return (info->err = EINVAL);
	}

	prop = safe_scf_property_create(h);

	if (scf_pg_get_property(pg, SCF_PROPERTY_ENTITIES, prop) != 0) {
		scferr = scf_error();
		scf_property_destroy(prop);
		if (scferr == SCF_ERROR_DELETED) {
			startd_free(fmri, fmri_sz);
			startd_free(pg_name, max_scf_name_size);
			return (info->err = 0);
		} else if (scferr != SCF_ERROR_NOT_FOUND) {
			startd_free(fmri, fmri_sz);
			startd_free(pg_name, max_scf_name_size);
			return (info->err = ECONNABORTED);
		}

		log_error(LOG_INFO,
		    "Dependency \"%s\" of %s is missing a \"%s\" property.\n",
		    pg_name, info->v->gv_name, SCF_PROPERTY_ENTITIES);

		startd_free(fmri, fmri_sz);
		startd_free(pg_name, max_scf_name_size);

		return (info->err = EINVAL);
	}

	/* Create depgroup vertex for pg */
	err = graph_insert_vertex_unconfigured(fmri, GVT_GROUP, deptype,
	    rerr, &depgrp);
	assert(err == 0);
	startd_free(fmri, fmri_sz);

	/* Add dependency from inst vertex to new vertex */
	err = graph_insert_dependency(info->v, depgrp, info->pathp);
	/* ELOOP can't happen because this should be a new vertex */
	assert(err == 0);

	linfo.v = depgrp;
	linfo.type = depgroup_read_scheme(h, pg);
	linfo.inst_fmri = info->v->gv_name;
	linfo.pg_name = pg_name;
	linfo.h = h;
	linfo.err = 0;
	linfo.pathp = info->pathp;
	err = walk_property_astrings(prop, (callback_t)process_dependency_fmri,
	    &linfo);

	scf_property_destroy(prop);
	startd_free(pg_name, max_scf_name_size);

	switch (err) {
	case 0:
	case EINTR:
		return (info->err = linfo.err);

	case ECONNABORTED:
	case EINVAL:
		return (info->err = err);

	case ECANCELED:
		return (info->err = 0);

	case ECONNRESET:
		return (info->err = ECONNABORTED);

	default:
		bad_error("walk_property_astrings", err);
		/* NOTREACHED */
	}
}

/*
 * Build the dependency info for v from the repository.  Returns 0 on success,
 * ECONNABORTED on repository disconnection, EINVAL if the repository
 * configuration is invalid, and ELOOP if a dependency would cause a cycle.
 * In the last case, *pathp will point to a -1-terminated array of ids which
 * constitute the rest of the dependency cycle.
 */
static int
set_dependencies(graph_vertex_t *v, scf_instance_t *inst, int **pathp)
{
	struct deppg_info info;
	int err;
	uint_t old_configured;

	assert(MUTEX_HELD(&dgraph_lock));

	/*
	 * Mark the vertex as configured during dependency insertion to avoid
	 * dependency cycles (which can appear in the graph if one of the
	 * vertices is an exclusion-group).
	 */
	old_configured = v->gv_flags & GV_CONFIGURED;
	v->gv_flags |= GV_CONFIGURED;

	info.err = 0;
	info.v = v;
	info.pathp = pathp;

	err = walk_dependency_pgs(inst, (callback_t)process_dependency_pg,
	    &info);

	if (!old_configured)
		v->gv_flags &= ~GV_CONFIGURED;

	switch (err) {
	case 0:
	case EINTR:
		return (info.err);

	case ECONNABORTED:
		return (ECONNABORTED);

	case ECANCELED:
		/* Should get delete event, so return 0. */
		return (0);

	default:
		bad_error("walk_dependency_pgs", err);
		/* NOTREACHED */
	}
}


static void
handle_cycle(const char *fmri, int *path)
{
	const char *cp;
	size_t sz;

	assert(MUTEX_HELD(&dgraph_lock));

	path_to_str(path, (char **)&cp, &sz);

	log_error(LOG_ERR, "Transitioning %s to maintenance "
	    "because it completes a dependency cycle (see svcs -xv for "
	    "details):\n%s", fmri ? fmri : "?", cp);

	startd_free((void *)cp, sz);
}

/*
 * Increment the vertex's reference count to prevent the vertex removal
 * from the dgraph.
 */
static void
vertex_ref(graph_vertex_t *v)
{
	assert(MUTEX_HELD(&dgraph_lock));

	v->gv_refs++;
}

/*
 * Decrement the vertex's reference count and remove the vertex from
 * the dgraph when possible.
 *
 * Return VERTEX_REMOVED when the vertex has been removed otherwise
 * return VERTEX_INUSE.
 */
static int
vertex_unref(graph_vertex_t *v)
{
	assert(MUTEX_HELD(&dgraph_lock));
	assert(v->gv_refs > 0);

	v->gv_refs--;

	return (free_if_unrefed(v));
}

/*
 * When run on the dependencies of a vertex, populates list with
 * graph_edge_t's which point to the service vertices or the instance
 * vertices (no GVT_GROUP nodes) on which the vertex depends.
 *
 * Increment the vertex's reference count once the vertex is inserted
 * in the list. The vertex won't be able to be deleted from the dgraph
 * while it is referenced.
 */
static int
append_svcs_or_insts(graph_edge_t *e, uu_list_t *list)
{
	graph_vertex_t *v = e->ge_vertex;
	graph_edge_t *new;
	int r;

	switch (v->gv_type) {
	case GVT_INST:
	case GVT_SVC:
		break;

	case GVT_GROUP:
		r = uu_list_walk(v->gv_dependencies,
		    (uu_walk_fn_t *)append_svcs_or_insts, list, 0);
		assert(r == 0);
		return (UU_WALK_NEXT);

	case GVT_FILE:
		return (UU_WALK_NEXT);

	default:
#ifndef NDEBUG
		uu_warn("%s:%d: Unexpected vertex type %d.\n", __FILE__,
		    __LINE__, v->gv_type);
#endif
		abort();
	}

	new = startd_alloc(sizeof (*new));
	new->ge_vertex = v;
	uu_list_node_init(new, &new->ge_link, graph_edge_pool);
	r = uu_list_insert_before(list, NULL, new);
	assert(r == 0);

	/*
	 * Because we are inserting the vertex in a list, we don't want
	 * the vertex to be freed while the list is in use. In order to
	 * achieve that, increment the vertex's reference count.
	 */
	vertex_ref(v);

	return (UU_WALK_NEXT);
}

static boolean_t
should_be_in_subgraph(graph_vertex_t *v)
{
	graph_edge_t *e;

	if (v == milestone)
		return (B_TRUE);

	/*
	 * v is in the subgraph if any of its dependents are in the subgraph.
	 * Except for EXCLUDE_ALL dependents.  And OPTIONAL dependents only
	 * count if we're enabled.
	 */
	for (e = uu_list_first(v->gv_dependents);
	    e != NULL;
	    e = uu_list_next(v->gv_dependents, e)) {
		graph_vertex_t *dv = e->ge_vertex;

		if (!(dv->gv_flags & GV_INSUBGRAPH))
			continue;

		/*
		 * Don't include instances that are optional and disabled.
		 */
		if (v->gv_type == GVT_INST && dv->gv_type == GVT_SVC) {

			int in = 0;
			graph_edge_t *ee;

			for (ee = uu_list_first(dv->gv_dependents);
			    ee != NULL;
			    ee = uu_list_next(dv->gv_dependents, ee)) {

				graph_vertex_t *ddv = e->ge_vertex;

				if (ddv->gv_type == GVT_GROUP &&
				    ddv->gv_depgroup == DEPGRP_EXCLUDE_ALL)
					continue;

				if (ddv->gv_type == GVT_GROUP &&
				    ddv->gv_depgroup == DEPGRP_OPTIONAL_ALL &&
				    !(v->gv_flags & GV_ENBLD_NOOVR))
					continue;

				in = 1;
			}
			if (!in)
				continue;
		}
		if (v->gv_type == GVT_INST &&
		    dv->gv_type == GVT_GROUP &&
		    dv->gv_depgroup == DEPGRP_OPTIONAL_ALL &&
		    !(v->gv_flags & GV_ENBLD_NOOVR))
			continue;

		/* Don't include excluded services and instances */
		if (dv->gv_type == GVT_GROUP &&
		    dv->gv_depgroup == DEPGRP_EXCLUDE_ALL)
			continue;

		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Ensures that GV_INSUBGRAPH is set properly for v and its descendents.  If
 * any bits change, manipulate the repository appropriately.  Returns 0 or
 * ECONNABORTED.
 */
static int
eval_subgraph(graph_vertex_t *v, scf_handle_t *h)
{
	boolean_t old = (v->gv_flags & GV_INSUBGRAPH) != 0;
	boolean_t new;
	graph_edge_t *e;
	scf_instance_t *inst;
	int ret = 0, r;

	assert(milestone != NULL && milestone != MILESTONE_NONE);

	new = should_be_in_subgraph(v);

	if (new == old)
		return (0);

	log_framework(LOG_DEBUG, new ? "Adding %s to the subgraph.\n" :
	    "Removing %s from the subgraph.\n", v->gv_name);

	v->gv_flags = (v->gv_flags & ~GV_INSUBGRAPH) |
	    (new ? GV_INSUBGRAPH : 0);

	if (v->gv_type == GVT_INST && (v->gv_flags & GV_CONFIGURED)) {
		int err;

get_inst:
		err = libscf_fmri_get_instance(h, v->gv_name, &inst);
		if (err != 0) {
			switch (err) {
			case ECONNABORTED:
				libscf_handle_rebind(h);
				ret = ECONNABORTED;
				goto get_inst;

			case ENOENT:
				break;

			case EINVAL:
			case ENOTSUP:
			default:
				bad_error("libscf_fmri_get_instance", err);
			}
		} else {
			const char *f;

			if (new) {
				err = libscf_delete_enable_ovr(inst);
				f = "libscf_delete_enable_ovr";
			} else {
				err = libscf_set_enable_ovr(inst, 0);
				f = "libscf_set_enable_ovr";
			}
			scf_instance_destroy(inst);
			switch (err) {
			case 0:
			case ECANCELED:
				break;

			case ECONNABORTED:
				libscf_handle_rebind(h);
				/*
				 * We must continue so the graph is updated,
				 * but we must return ECONNABORTED so any
				 * libscf state held by any callers is reset.
				 */
				ret = ECONNABORTED;
				goto get_inst;

			case EROFS:
			case EPERM:
				log_error(LOG_WARNING,
				    "Could not set %s/%s for %s: %s.\n",
				    SCF_PG_GENERAL_OVR, SCF_PROPERTY_ENABLED,
				    v->gv_name, strerror(err));
				break;

			default:
				bad_error(f, err);
			}
		}
	}

	for (e = uu_list_first(v->gv_dependencies);
	    e != NULL;
	    e = uu_list_next(v->gv_dependencies, e)) {
		r = eval_subgraph(e->ge_vertex, h);
		if (r != 0) {
			assert(r == ECONNABORTED);
			ret = ECONNABORTED;
		}
	}

	return (ret);
}

/*
 * Delete the (property group) dependencies of v & create new ones based on
 * inst.  If doing so would create a cycle, log a message and put the instance
 * into maintenance.  Update GV_INSUBGRAPH flags as necessary.  Returns 0 or
 * ECONNABORTED.
 */
int
refresh_vertex(graph_vertex_t *v, scf_instance_t *inst)
{
	int err;
	int *path;
	char *fmri;
	int r;
	scf_handle_t *h = scf_instance_handle(inst);
	uu_list_t *old_deps;
	int ret = 0;
	graph_edge_t *e;
	graph_vertex_t *vv;

	assert(MUTEX_HELD(&dgraph_lock));
	assert(v->gv_type == GVT_INST);

	log_framework(LOG_DEBUG, "Graph engine: Refreshing %s.\n", v->gv_name);

	if (milestone > MILESTONE_NONE) {
		/*
		 * In case some of v's dependencies are being deleted we must
		 * make a list of them now for GV_INSUBGRAPH-flag evaluation
		 * after the new dependencies are in place.
		 */
		old_deps = startd_list_create(graph_edge_pool, NULL, 0);

		err = uu_list_walk(v->gv_dependencies,
		    (uu_walk_fn_t *)append_svcs_or_insts, old_deps, 0);
		assert(err == 0);
	}

	delete_instance_dependencies(v, B_FALSE);

	err = set_dependencies(v, inst, &path);
	switch (err) {
	case 0:
		break;

	case ECONNABORTED:
		ret = err;
		goto out;

	case EINVAL:
	case ELOOP:
		r = libscf_instance_get_fmri(inst, &fmri);
		switch (r) {
		case 0:
			break;

		case ECONNABORTED:
			ret = ECONNABORTED;
			goto out;

		case ECANCELED:
			ret = 0;
			goto out;

		default:
			bad_error("libscf_instance_get_fmri", r);
		}

		if (err == EINVAL) {
			log_error(LOG_ERR, "Transitioning %s "
			    "to maintenance due to misconfiguration.\n",
			    fmri ? fmri : "?");
			vertex_send_event(v,
			    RESTARTER_EVENT_TYPE_INVALID_DEPENDENCY);
		} else {
			handle_cycle(fmri, path);
			vertex_send_event(v,
			    RESTARTER_EVENT_TYPE_DEPENDENCY_CYCLE);
		}
		startd_free(fmri, max_scf_fmri_size);
		ret = 0;
		goto out;

	default:
		bad_error("set_dependencies", err);
	}

	if (milestone > MILESTONE_NONE) {
		boolean_t aborted = B_FALSE;

		for (e = uu_list_first(old_deps);
		    e != NULL;
		    e = uu_list_next(old_deps, e)) {
			vv = e->ge_vertex;

			if (vertex_unref(vv) == VERTEX_INUSE &&
			    eval_subgraph(vv, h) == ECONNABORTED)
				aborted = B_TRUE;
		}

		for (e = uu_list_first(v->gv_dependencies);
		    e != NULL;
		    e = uu_list_next(v->gv_dependencies, e)) {
			if (eval_subgraph(e->ge_vertex, h) ==
			    ECONNABORTED)
				aborted = B_TRUE;
		}

		if (aborted) {
			ret = ECONNABORTED;
			goto out;
		}
	}

	graph_start_if_satisfied(v);

	ret = 0;

out:
	if (milestone > MILESTONE_NONE) {
		void *cookie = NULL;

		while ((e = uu_list_teardown(old_deps, &cookie)) != NULL)
			startd_free(e, sizeof (*e));

		uu_list_destroy(old_deps);
	}

	return (ret);
}

/*
 * Set up v according to inst.  That is, make sure it depends on its
 * restarter and set up its dependencies.  Send the ADD_INSTANCE command to
 * the restarter, and send ENABLE or DISABLE as appropriate.
 *
 * Returns 0 on success, ECONNABORTED on repository disconnection, or
 * ECANCELED if inst is deleted.
 */
static int
configure_vertex(graph_vertex_t *v, scf_instance_t *inst)
{
	scf_handle_t *h;
	scf_propertygroup_t *pg;
	scf_snapshot_t *snap;
	char *restarter_fmri = startd_alloc(max_scf_value_size);
	int enabled, enabled_ovr;
	int err;
	int *path;
	int deathrow;
	int32_t tset;

	restarter_fmri[0] = '\0';

	assert(MUTEX_HELD(&dgraph_lock));
	assert(v->gv_type == GVT_INST);
	assert((v->gv_flags & GV_CONFIGURED) == 0);

	/* GV_INSUBGRAPH should already be set properly. */
	assert(should_be_in_subgraph(v) ==
	    ((v->gv_flags & GV_INSUBGRAPH) != 0));

	/*
	 * If the instance fmri is in the deathrow list then set the
	 * GV_DEATHROW flag on the vertex and create and set to true the
	 * SCF_PROPERTY_DEATHROW boolean property in the non-persistent
	 * repository for this instance fmri.
	 */
	if ((v->gv_flags & GV_DEATHROW) ||
	    (is_fmri_in_deathrow(v->gv_name) == B_TRUE)) {
		if ((v->gv_flags & GV_DEATHROW) == 0) {
			/*
			 * Set flag GV_DEATHROW, create and set to true
			 * the SCF_PROPERTY_DEATHROW property in the
			 * non-persistent repository for this instance fmri.
			 */
			v->gv_flags |= GV_DEATHROW;

			switch (err = libscf_set_deathrow(inst, 1)) {
			case 0:
				break;

			case ECONNABORTED:
			case ECANCELED:
				startd_free(restarter_fmri, max_scf_value_size);
				return (err);

			case EROFS:
				log_error(LOG_WARNING, "Could not set %s/%s "
				    "for deathrow %s: %s.\n",
				    SCF_PG_DEATHROW, SCF_PROPERTY_DEATHROW,
				    v->gv_name, strerror(err));
				break;

			case EPERM:
				uu_die("Permission denied.\n");
				/* NOTREACHED */

			default:
				bad_error("libscf_set_deathrow", err);
			}
			log_framework(LOG_DEBUG, "Deathrow, graph set %s.\n",
			    v->gv_name);
		}
		startd_free(restarter_fmri, max_scf_value_size);
		return (0);
	}

	h = scf_instance_handle(inst);

	/*
	 * Using a temporary deathrow boolean property, set through
	 * libscf_set_deathrow(), only for fmris on deathrow, is necessary
	 * because deathrow_fini() may already have been called, and in case
	 * of a refresh, GV_DEATHROW may need to be set again.
	 * libscf_get_deathrow() sets deathrow to 1 only if this instance
	 * has a temporary boolean property named 'deathrow' valued true
	 * in a property group 'deathrow', -1 or 0 in all other cases.
	 */
	err = libscf_get_deathrow(h, inst, &deathrow);
	switch (err) {
	case 0:
		break;

	case ECONNABORTED:
	case ECANCELED:
		startd_free(restarter_fmri, max_scf_value_size);
		return (err);

	default:
		bad_error("libscf_get_deathrow", err);
	}

	if (deathrow == 1) {
		v->gv_flags |= GV_DEATHROW;
		startd_free(restarter_fmri, max_scf_value_size);
		return (0);
	}

	log_framework(LOG_DEBUG, "Graph adding %s.\n", v->gv_name);

	/*
	 * If the instance does not have a restarter property group,
	 * initialize its state to uninitialized/none, in case the restarter
	 * is not enabled.
	 */
	pg = safe_scf_pg_create(h);

	if (scf_instance_get_pg(inst, SCF_PG_RESTARTER, pg) != 0) {
		instance_data_t idata;
		uint_t count = 0, msecs = ALLOC_DELAY;

		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
			break;

		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			scf_pg_destroy(pg);
			startd_free(restarter_fmri, max_scf_value_size);
			return (ECONNABORTED);

		case SCF_ERROR_DELETED:
			scf_pg_destroy(pg);
			startd_free(restarter_fmri, max_scf_value_size);
			return (ECANCELED);

		case SCF_ERROR_NOT_SET:
			bad_error("scf_instance_get_pg", scf_error());
		}

		switch (err = libscf_instance_get_fmri(inst,
		    (char **)&idata.i_fmri)) {
		case 0:
			break;

		case ECONNABORTED:
		case ECANCELED:
			scf_pg_destroy(pg);
			startd_free(restarter_fmri, max_scf_value_size);
			return (err);

		default:
			bad_error("libscf_instance_get_fmri", err);
		}

		idata.i_state = RESTARTER_STATE_NONE;
		idata.i_next_state = RESTARTER_STATE_NONE;

init_state:
		switch (err = _restarter_commit_states(h, &idata,
		    RESTARTER_STATE_UNINIT, RESTARTER_STATE_NONE,
		    restarter_get_str_short(restarter_str_insert_in_graph))) {
		case 0:
			break;

		case ENOMEM:
			++count;
			if (count < ALLOC_RETRY) {
				(void) poll(NULL, 0, msecs);
				msecs *= ALLOC_DELAY_MULT;
				goto init_state;
			}

			uu_die("Insufficient memory.\n");
			/* NOTREACHED */

		case ECONNABORTED:
			startd_free((void *)idata.i_fmri, max_scf_fmri_size);
			scf_pg_destroy(pg);
			startd_free(restarter_fmri, max_scf_value_size);
			return (ECONNABORTED);

		case ENOENT:
			startd_free((void *)idata.i_fmri, max_scf_fmri_size);
			scf_pg_destroy(pg);
			startd_free(restarter_fmri, max_scf_value_size);
			return (ECANCELED);

		case EPERM:
		case EACCES:
		case EROFS:
			log_error(LOG_NOTICE, "Could not initialize state for "
			    "%s: %s.\n", idata.i_fmri, strerror(err));
			break;

		case EINVAL:
		default:
			bad_error("_restarter_commit_states", err);
		}

		startd_free((void *)idata.i_fmri, max_scf_fmri_size);
	}

	scf_pg_destroy(pg);

	if (milestone != NULL) {
		/*
		 * Make sure the enable-override is set properly before we
		 * read whether we should be enabled.
		 */
		if (milestone == MILESTONE_NONE ||
		    !(v->gv_flags & GV_INSUBGRAPH)) {
			/*
			 * This might seem unjustified after the milestone
			 * transition has completed (non_subgraph_svcs == 0),
			 * but it's important because when we boot to
			 * a milestone, we set the milestone before populating
			 * the graph, and all of the new non-subgraph services
			 * need to be disabled here.
			 */
			switch (err = libscf_set_enable_ovr(inst, 0)) {
			case 0:
				break;

			case ECONNABORTED:
			case ECANCELED:
				startd_free(restarter_fmri, max_scf_value_size);
				return (err);

			case EROFS:
				log_error(LOG_WARNING,
				    "Could not set %s/%s for %s: %s.\n",
				    SCF_PG_GENERAL_OVR, SCF_PROPERTY_ENABLED,
				    v->gv_name, strerror(err));
				break;

			case EPERM:
				uu_die("Permission denied.\n");
				/* NOTREACHED */

			default:
				bad_error("libscf_set_enable_ovr", err);
			}
		} else {
			assert(v->gv_flags & GV_INSUBGRAPH);
			switch (err = libscf_delete_enable_ovr(inst)) {
			case 0:
				break;

			case ECONNABORTED:
			case ECANCELED:
				startd_free(restarter_fmri, max_scf_value_size);
				return (err);

			case EPERM:
				uu_die("Permission denied.\n");
				/* NOTREACHED */

			default:
				bad_error("libscf_delete_enable_ovr", err);
			}
		}
	}

	err = libscf_get_basic_instance_data(h, inst, v->gv_name, &enabled,
	    &enabled_ovr, &restarter_fmri);
	switch (err) {
	case 0:
		break;

	case ECONNABORTED:
	case ECANCELED:
		startd_free(restarter_fmri, max_scf_value_size);
		return (err);

	case ENOENT:
		log_framework(LOG_DEBUG,
		    "Ignoring %s because it has no general property group.\n",
		    v->gv_name);
		startd_free(restarter_fmri, max_scf_value_size);
		return (0);

	default:
		bad_error("libscf_get_basic_instance_data", err);
	}

	if ((tset = libscf_get_stn_tset(inst)) == -1) {
		log_framework(LOG_WARNING,
		    "Failed to get notification parameters for %s: %s\n",
		    v->gv_name, scf_strerror(scf_error()));
		v->gv_stn_tset = 0;
	} else {
		v->gv_stn_tset = tset;
	}
	if (strcmp(v->gv_name, SCF_INSTANCE_GLOBAL) == 0)
		stn_global = v->gv_stn_tset;

	if (enabled == -1) {
		startd_free(restarter_fmri, max_scf_value_size);
		return (0);
	}

	v->gv_flags = (v->gv_flags & ~GV_ENBLD_NOOVR) |
	    (enabled ? GV_ENBLD_NOOVR : 0);

	if (enabled_ovr != -1)
		enabled = enabled_ovr;

	v->gv_state = RESTARTER_STATE_UNINIT;

	snap = libscf_get_or_make_running_snapshot(inst, v->gv_name, B_TRUE);
	scf_snapshot_destroy(snap);

	/* Set up the restarter. (Sends _ADD_INSTANCE on success.) */
	err = graph_change_restarter(v, restarter_fmri, h, &path);
	if (err != 0) {
		instance_data_t idata;
		uint_t count = 0, msecs = ALLOC_DELAY;
		restarter_str_t reason;

		if (err == ECONNABORTED) {
			startd_free(restarter_fmri, max_scf_value_size);
			return (err);
		}

		assert(err == EINVAL || err == ELOOP);

		if (err == EINVAL) {
			log_framework(LOG_ERR, emsg_invalid_restarter,
			    v->gv_name, restarter_fmri);
			reason = restarter_str_invalid_restarter;
		} else {
			handle_cycle(v->gv_name, path);
			reason = restarter_str_dependency_cycle;
		}

		startd_free(restarter_fmri, max_scf_value_size);

		/*
		 * We didn't register the instance with the restarter, so we
		 * must set maintenance mode ourselves.
		 */
		err = libscf_instance_get_fmri(inst, (char **)&idata.i_fmri);
		if (err != 0) {
			assert(err == ECONNABORTED || err == ECANCELED);
			return (err);
		}

		idata.i_state = RESTARTER_STATE_NONE;
		idata.i_next_state = RESTARTER_STATE_NONE;

set_maint:
		switch (err = _restarter_commit_states(h, &idata,
		    RESTARTER_STATE_MAINT, RESTARTER_STATE_NONE,
		    restarter_get_str_short(reason))) {
		case 0:
			break;

		case ENOMEM:
			++count;
			if (count < ALLOC_RETRY) {
				(void) poll(NULL, 0, msecs);
				msecs *= ALLOC_DELAY_MULT;
				goto set_maint;
			}

			uu_die("Insufficient memory.\n");
			/* NOTREACHED */

		case ECONNABORTED:
			startd_free((void *)idata.i_fmri, max_scf_fmri_size);
			return (ECONNABORTED);

		case ENOENT:
			startd_free((void *)idata.i_fmri, max_scf_fmri_size);
			return (ECANCELED);

		case EPERM:
		case EACCES:
		case EROFS:
			log_error(LOG_NOTICE, "Could not initialize state for "
			    "%s: %s.\n", idata.i_fmri, strerror(err));
			break;

		case EINVAL:
		default:
			bad_error("_restarter_commit_states", err);
		}

		startd_free((void *)idata.i_fmri, max_scf_fmri_size);

		v->gv_state = RESTARTER_STATE_MAINT;

		goto out;
	}
	startd_free(restarter_fmri, max_scf_value_size);

	/* Add all the other dependencies. */
	err = refresh_vertex(v, inst);
	if (err != 0) {
		assert(err == ECONNABORTED);
		return (err);
	}

out:
	v->gv_flags |= GV_CONFIGURED;

	graph_enable_by_vertex(v, enabled, 0);

	return (0);
}


static void
kill_user_procs(void)
{
	(void) fputs("svc.startd: Killing user processes.\n", stdout);

	/*
	 * Despite its name, killall's role is to get select user processes--
	 * basically those representing terminal-based logins-- to die.  Victims
	 * are located by killall in the utmp database.  Since these are most
	 * often shell based logins, and many shells mask SIGTERM (but are
	 * responsive to SIGHUP) we first HUP and then shortly thereafter
	 * kill -9.
	 */
	(void) fork_with_timeout("/usr/sbin/killall HUP", 1, 5);
	(void) fork_with_timeout("/usr/sbin/killall KILL", 1, 5);

	/*
	 * Note the selection of user id's 0, 1 and 15, subsequently
	 * inverted by -v.  15 is reserved for dladmd.  Yes, this is a
	 * kludge-- a better policy is needed.
	 *
	 * Note that fork_with_timeout will only wait out the 1 second
	 * "grace time" if pkill actually returns 0.  So if there are
	 * no matches, this will run to completion much more quickly.
	 */
	(void) fork_with_timeout("/usr/bin/pkill -TERM -v -u 0,1,15", 1, 5);
	(void) fork_with_timeout("/usr/bin/pkill -KILL -v -u 0,1,15", 1, 5);
}

static void
do_uadmin(void)
{
	const char * const resetting = "/etc/svc/volatile/resetting";
	int fd;
	struct statvfs vfs;
	time_t now;
	struct tm nowtm;
	char down_buf[256], time_buf[256];
	uintptr_t mdep;
#if defined(__i386)
	grub_boot_args_t fbarg;
#endif	/* __i386 */

	mdep = NULL;
	fd = creat(resetting, 0777);
	if (fd >= 0)
		startd_close(fd);
	else
		uu_warn("Could not create \"%s\"", resetting);

	/* Kill dhcpagent if we're not using nfs for root */
	if ((statvfs("/", &vfs) == 0) &&
	    (strncmp(vfs.f_basetype, "nfs", sizeof ("nfs") - 1) != 0))
		fork_with_timeout("/usr/bin/pkill -x -u 0 dhcpagent", 0, 5);

	/*
	 * Call sync(2) now, before we kill off user processes.  This takes
	 * advantage of the several seconds of pause we have before the
	 * killalls are done.  Time we can make good use of to get pages
	 * moving out to disk.
	 *
	 * Inside non-global zones, we don't bother, and it's better not to
	 * anyway, since sync(2) can have system-wide impact.
	 */
	if (getzoneid() == 0)
		sync();

	kill_user_procs();

	/*
	 * Note that this must come after the killing of user procs, since
	 * killall relies on utmpx, and this command affects the contents of
	 * said file.
	 */
	if (access("/usr/lib/acct/closewtmp", X_OK) == 0)
		fork_with_timeout("/usr/lib/acct/closewtmp", 0, 5);

	/*
	 * For patches which may be installed as the system is shutting
	 * down, we need to ensure, one more time, that the boot archive
	 * really is up to date.
	 */
	if (getzoneid() == 0 && access("/usr/sbin/bootadm", X_OK) == 0)
		fork_with_timeout("/usr/sbin/bootadm -ea update_all", 0, 3600);

	/*
	 * Right now, fast reboot is supported only on i386.
	 * scf_is_fastboot_default() should take care of it.
	 * If somehow we got there on unsupported platform -
	 * print warning and fall back to regular reboot.
	 */
	if (halting == AD_FASTREBOOT) {
#if defined(__i386)
		int rc;

		if ((rc = grub_get_boot_args(&fbarg, NULL,
		    GRUB_ENTRY_DEFAULT)) == 0) {
			mdep = (uintptr_t)&fbarg.gba_bootargs;
		} else {
			/*
			 * Failed to read GRUB menu, fall back to normal reboot
			 */
			halting = AD_BOOT;
			uu_warn("Failed to process GRUB menu entry "
			    "for fast reboot.\n\t%s\n"
			    "Falling back to regular reboot.\n",
			    grub_strerror(rc));
		}
#else	/* __i386 */
		halting = AD_BOOT;
		uu_warn("Fast reboot configured, but not supported by "
		    "this ISA\n");
#endif	/* __i386 */
	}

	fork_with_timeout("/sbin/umountall -l", 0, 5);
	fork_with_timeout("/sbin/umount /tmp /var/adm /var/run /var "
	    ">/dev/null 2>&1", 0, 5);

	/*
	 * Try to get to consistency for whatever UFS filesystems are left.
	 * This is pretty expensive, so we save it for the end in the hopes of
	 * minimizing what it must do.  The other option would be to start in
	 * parallel with the killall's, but lockfs tends to throw out much more
	 * than is needed, and so subsequent commands (like umountall) take a
	 * long time to get going again.
	 *
	 * Inside of zones, we don't bother, since we're not about to terminate
	 * the whole OS instance.
	 *
	 * On systems using only ZFS, this call to lockfs -fa is a no-op.
	 */
	if (getzoneid() == 0) {
		if (access("/usr/sbin/lockfs", X_OK) == 0)
			fork_with_timeout("/usr/sbin/lockfs -fa", 0, 30);

		sync();	/* once more, with feeling */
	}

	fork_with_timeout("/sbin/umount /usr >/dev/null 2>&1", 0, 5);

	/*
	 * Construct and emit the last words from userland:
	 * "<timestamp> The system is down.  Shutdown took <N> seconds."
	 *
	 * Normally we'd use syslog, but with /var and other things
	 * potentially gone, try to minimize the external dependencies.
	 */
	now = time(NULL);
	(void) localtime_r(&now, &nowtm);

	if (strftime(down_buf, sizeof (down_buf),
	    "%b %e %T The system is down.", &nowtm) == 0) {
		(void) strlcpy(down_buf, "The system is down.",
		    sizeof (down_buf));
	}

	if (halting_time != 0 && halting_time <= now) {
		(void) snprintf(time_buf, sizeof (time_buf),
		    "  Shutdown took %lu seconds.", now - halting_time);
	} else {
		time_buf[0] = '\0';
	}
	(void) printf("%s%s\n", down_buf, time_buf);

	(void) uadmin(A_SHUTDOWN, halting, mdep);
	uu_warn("uadmin() failed");

#if defined(__i386)
	/* uadmin fail, cleanup grub_boot_args */
	if (halting == AD_FASTREBOOT)
		grub_cleanup_boot_args(&fbarg);
#endif	/* __i386 */

	if (remove(resetting) != 0 && errno != ENOENT)
		uu_warn("Could not remove \"%s\"", resetting);
}

/*
 * If any of the up_svcs[] are online or satisfiable, return true.  If they are
 * all missing, disabled, in maintenance, or unsatisfiable, return false.
 */
boolean_t
can_come_up(void)
{
	int i;

	assert(MUTEX_HELD(&dgraph_lock));

	/*
	 * If we are booting to single user (boot -s),
	 * SCF_MILESTONE_SINGLE_USER is needed to come up because startd
	 * spawns sulogin after single-user is online (see specials.c).
	 */
	i = (booting_to_single_user ? 0 : 1);

	for (; up_svcs[i] != NULL; ++i) {
		if (up_svcs_p[i] == NULL) {
			up_svcs_p[i] = vertex_get_by_name(up_svcs[i]);

			if (up_svcs_p[i] == NULL)
				continue;
		}

		/*
		 * Ignore unconfigured services (the ones that have been
		 * mentioned in a dependency from other services, but do
		 * not exist in the repository).  Services which exist
		 * in the repository but don't have general/enabled
		 * property will be also ignored.
		 */
		if (!(up_svcs_p[i]->gv_flags & GV_CONFIGURED))
			continue;

		switch (up_svcs_p[i]->gv_state) {
		case RESTARTER_STATE_ONLINE:
		case RESTARTER_STATE_DEGRADED:
			/*
			 * Deactivate verbose boot once a login service has been
			 * reached.
			 */
			st->st_log_login_reached = 1;
			/*FALLTHROUGH*/
		case RESTARTER_STATE_UNINIT:
			return (B_TRUE);

		case RESTARTER_STATE_OFFLINE:
			if (instance_satisfied(up_svcs_p[i], B_TRUE) != -1)
				return (B_TRUE);
			log_framework(LOG_DEBUG,
			    "can_come_up(): %s is unsatisfiable.\n",
			    up_svcs_p[i]->gv_name);
			continue;

		case RESTARTER_STATE_DISABLED:
		case RESTARTER_STATE_MAINT:
			log_framework(LOG_DEBUG,
			    "can_come_up(): %s is in state %s.\n",
			    up_svcs_p[i]->gv_name,
			    instance_state_str[up_svcs_p[i]->gv_state]);
			continue;

		default:
#ifndef NDEBUG
			uu_warn("%s:%d: Unexpected vertex state %d.\n",
			    __FILE__, __LINE__, up_svcs_p[i]->gv_state);
#endif
			abort();
		}
	}

	/*
	 * In the seed repository, console-login is unsatisfiable because
	 * services are missing.  To behave correctly in that case we don't want
	 * to return false until manifest-import is online.
	 */

	if (manifest_import_p == NULL) {
		manifest_import_p = vertex_get_by_name(manifest_import);

		if (manifest_import_p == NULL)
			return (B_FALSE);
	}

	switch (manifest_import_p->gv_state) {
	case RESTARTER_STATE_ONLINE:
	case RESTARTER_STATE_DEGRADED:
	case RESTARTER_STATE_DISABLED:
	case RESTARTER_STATE_MAINT:
		break;

	case RESTARTER_STATE_OFFLINE:
		if (instance_satisfied(manifest_import_p, B_TRUE) == -1)
			break;
		/* FALLTHROUGH */

	case RESTARTER_STATE_UNINIT:
		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Runs sulogin.  Returns
 *   0 - success
 *   EALREADY - sulogin is already running
 *   EBUSY - console-login is running
 */
static int
run_sulogin(const char *msg)
{
	graph_vertex_t *v;

	assert(MUTEX_HELD(&dgraph_lock));

	if (sulogin_running)
		return (EALREADY);

	v = vertex_get_by_name(console_login_fmri);
	if (v != NULL && inst_running(v))
		return (EBUSY);

	sulogin_running = B_TRUE;

	MUTEX_UNLOCK(&dgraph_lock);

	fork_sulogin(B_FALSE, msg);

	MUTEX_LOCK(&dgraph_lock);

	sulogin_running = B_FALSE;

	if (console_login_ready) {
		v = vertex_get_by_name(console_login_fmri);

		if (v != NULL && v->gv_state == RESTARTER_STATE_OFFLINE) {
			if (v->gv_start_f == NULL)
				vertex_send_event(v,
				    RESTARTER_EVENT_TYPE_START);
			else
				v->gv_start_f(v);
		}

		console_login_ready = B_FALSE;
	}

	return (0);
}

/*
 * The sulogin thread runs sulogin while can_come_up() is false.  run_sulogin()
 * keeps sulogin from stepping on console-login's toes.
 */
/* ARGSUSED */
static void *
sulogin_thread(void *unused)
{
	MUTEX_LOCK(&dgraph_lock);

	assert(sulogin_thread_running);

	do {
		(void) run_sulogin("Console login service(s) cannot run\n");
	} while (!can_come_up());

	sulogin_thread_running = B_FALSE;
	MUTEX_UNLOCK(&dgraph_lock);

	return (NULL);
}

/* ARGSUSED */
void *
single_user_thread(void *unused)
{
	uint_t left;
	scf_handle_t *h;
	scf_instance_t *inst;
	scf_property_t *prop;
	scf_value_t *val;
	const char *msg;
	char *buf;
	int r;

	MUTEX_LOCK(&single_user_thread_lock);
	single_user_thread_count++;

	if (!booting_to_single_user)
		kill_user_procs();

	if (go_single_user_mode || booting_to_single_user) {
		msg = "SINGLE USER MODE\n";
	} else {
		assert(go_to_level1);

		fork_rc_script('1', "start", B_TRUE);

		uu_warn("The system is ready for administration.\n");

		msg = "";
	}

	MUTEX_UNLOCK(&single_user_thread_lock);

	for (;;) {
		MUTEX_LOCK(&dgraph_lock);
		r = run_sulogin(msg);
		MUTEX_UNLOCK(&dgraph_lock);
		if (r == 0)
			break;

		assert(r == EALREADY || r == EBUSY);

		left = 3;
		while (left > 0)
			left = sleep(left);
	}

	MUTEX_LOCK(&single_user_thread_lock);

	/*
	 * If another single user thread has started, let it finish changing
	 * the run level.
	 */
	if (single_user_thread_count > 1) {
		single_user_thread_count--;
		MUTEX_UNLOCK(&single_user_thread_lock);
		return (NULL);
	}

	h = libscf_handle_create_bound_loop();
	inst = scf_instance_create(h);
	prop = safe_scf_property_create(h);
	val = safe_scf_value_create(h);
	buf = startd_alloc(max_scf_fmri_size);

lookup:
	if (scf_handle_decode_fmri(h, SCF_SERVICE_STARTD, NULL, NULL, inst,
	    NULL, NULL, SCF_DECODE_FMRI_EXACT) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
			r = libscf_create_self(h);
			if (r == 0)
				goto lookup;
			assert(r == ECONNABORTED);
			/* FALLTHROUGH */

		case SCF_ERROR_CONNECTION_BROKEN:
			libscf_handle_rebind(h);
			goto lookup;

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_NOT_BOUND:
		case SCF_ERROR_HANDLE_MISMATCH:
		default:
			bad_error("scf_handle_decode_fmri", scf_error());
		}
	}

	MUTEX_LOCK(&dgraph_lock);

	r = scf_instance_delete_prop(inst, SCF_PG_OPTIONS_OVR,
	    SCF_PROPERTY_MILESTONE);
	switch (r) {
	case 0:
	case ECANCELED:
		break;

	case ECONNABORTED:
		MUTEX_UNLOCK(&dgraph_lock);
		libscf_handle_rebind(h);
		goto lookup;

	case EPERM:
	case EACCES:
	case EROFS:
		log_error(LOG_WARNING, "Could not clear temporary milestone: "
		    "%s.\n", strerror(r));
		break;

	default:
		bad_error("scf_instance_delete_prop", r);
	}

	MUTEX_UNLOCK(&dgraph_lock);

	r = libscf_get_milestone(inst, prop, val, buf, max_scf_fmri_size);
	switch (r) {
	case ECANCELED:
	case ENOENT:
	case EINVAL:
		(void) strcpy(buf, "all");
		/* FALLTHROUGH */

	case 0:
		uu_warn("Returning to milestone %s.\n", buf);
		break;

	case ECONNABORTED:
		libscf_handle_rebind(h);
		goto lookup;

	default:
		bad_error("libscf_get_milestone", r);
	}

	r = dgraph_set_milestone(buf, h, B_FALSE);
	switch (r) {
	case 0:
	case ECONNRESET:
	case EALREADY:
	case EINVAL:
	case ENOENT:
		break;

	default:
		bad_error("dgraph_set_milestone", r);
	}

	/*
	 * See graph_runlevel_changed().
	 */
	MUTEX_LOCK(&dgraph_lock);
	utmpx_set_runlevel(target_milestone_as_runlevel(), 'S', B_TRUE);
	MUTEX_UNLOCK(&dgraph_lock);

	startd_free(buf, max_scf_fmri_size);
	scf_value_destroy(val);
	scf_property_destroy(prop);
	scf_instance_destroy(inst);
	scf_handle_destroy(h);

	/*
	 * We'll give ourselves 3 seconds to respond to all of the enablings
	 * that setting the milestone should have created before checking
	 * whether to run sulogin.
	 */
	left = 3;
	while (left > 0)
		left = sleep(left);

	MUTEX_LOCK(&dgraph_lock);
	/*
	 * Clearing these variables will allow the sulogin thread to run.  We
	 * check here in case there aren't any more state updates anytime soon.
	 */
	go_to_level1 = go_single_user_mode = booting_to_single_user = B_FALSE;
	if (!sulogin_thread_running && !can_come_up()) {
		(void) startd_thread_create(sulogin_thread, NULL);
		sulogin_thread_running = B_TRUE;
	}
	MUTEX_UNLOCK(&dgraph_lock);
	single_user_thread_count--;
	MUTEX_UNLOCK(&single_user_thread_lock);
	return (NULL);
}


/*
 * Dependency graph operations API.  These are handle-independent thread-safe
 * graph manipulation functions which are the entry points for the event
 * threads below.
 */

/*
 * If a configured vertex exists for inst_fmri, return EEXIST.  If no vertex
 * exists for inst_fmri, add one.  Then fetch the restarter from inst, make
 * this vertex dependent on it, and send _ADD_INSTANCE to the restarter.
 * Fetch whether the instance should be enabled from inst and send _ENABLE or
 * _DISABLE as appropriate.  Finally rummage through inst's dependency
 * property groups and add vertices and edges as appropriate.  If anything
 * goes wrong after sending _ADD_INSTANCE, send _ADMIN_MAINT_ON to put the
 * instance in maintenance.  Don't send _START or _STOP until we get a state
 * update in case we're being restarted and the service is already running.
 *
 * To support booting to a milestone, we must also make sure all dependencies
 * encountered are configured, if they exist in the repository.
 *
 * Returns 0 on success, ECONNABORTED on repository disconnection, EINVAL if
 * inst_fmri is an invalid (or not canonical) FMRI, ECANCELED if inst is
 * deleted, or EEXIST if a configured vertex for inst_fmri already exists.
 */
int
dgraph_add_instance(const char *inst_fmri, scf_instance_t *inst,
    boolean_t lock_graph)
{
	graph_vertex_t *v;
	int err;

	if (strcmp(inst_fmri, SCF_SERVICE_STARTD) == 0)
		return (0);

	/* Check for a vertex for inst_fmri. */
	if (lock_graph) {
		MUTEX_LOCK(&dgraph_lock);
	} else {
		assert(MUTEX_HELD(&dgraph_lock));
	}

	v = vertex_get_by_name(inst_fmri);

	if (v != NULL) {
		assert(v->gv_type == GVT_INST);

		if (v->gv_flags & GV_CONFIGURED) {
			if (lock_graph)
				MUTEX_UNLOCK(&dgraph_lock);
			return (EEXIST);
		}
	} else {
		/* Add the vertex. */
		err = graph_insert_vertex_unconfigured(inst_fmri, GVT_INST, 0,
		    RERR_NONE, &v);
		if (err != 0) {
			assert(err == EINVAL);
			if (lock_graph)
				MUTEX_UNLOCK(&dgraph_lock);
			return (EINVAL);
		}
	}

	err = configure_vertex(v, inst);

	if (lock_graph)
		MUTEX_UNLOCK(&dgraph_lock);

	return (err);
}

/*
 * Locate the vertex for this property group's instance.  If it doesn't exist
 * or is unconfigured, call dgraph_add_instance() & return.  Otherwise fetch
 * the restarter for the instance, and if it has changed, send
 * _REMOVE_INSTANCE to the old restarter, remove the dependency, make sure the
 * new restarter has a vertex, add a new dependency, and send _ADD_INSTANCE to
 * the new restarter.  Then fetch whether the instance should be enabled, and
 * if it is different from what we had, or if we changed the restarter, send
 * the appropriate _ENABLE or _DISABLE command.
 *
 * Returns 0 on success, ENOTSUP if the pg's parent is not an instance,
 * ECONNABORTED on repository disconnection, ECANCELED if the instance is
 * deleted, or -1 if the instance's general property group is deleted or if
 * its enabled property is misconfigured.
 */
static int
dgraph_update_general(scf_propertygroup_t *pg)
{
	scf_handle_t *h;
	scf_instance_t *inst;
	char *fmri;
	char *restarter_fmri;
	graph_vertex_t *v;
	int err;
	int enabled, enabled_ovr;
	int oldflags;

	/* Find the vertex for this service */
	h = scf_pg_handle(pg);

	inst = safe_scf_instance_create(h);

	if (scf_pg_get_parent_instance(pg, inst) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONSTRAINT_VIOLATED:
			return (ENOTSUP);

		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			return (ECONNABORTED);

		case SCF_ERROR_DELETED:
			return (0);

		case SCF_ERROR_NOT_SET:
			bad_error("scf_pg_get_parent_instance", scf_error());
		}
	}

	err = libscf_instance_get_fmri(inst, &fmri);
	switch (err) {
	case 0:
		break;

	case ECONNABORTED:
		scf_instance_destroy(inst);
		return (ECONNABORTED);

	case ECANCELED:
		scf_instance_destroy(inst);
		return (0);

	default:
		bad_error("libscf_instance_get_fmri", err);
	}

	log_framework(LOG_DEBUG,
	    "Graph engine: Reloading general properties for %s.\n", fmri);

	MUTEX_LOCK(&dgraph_lock);

	v = vertex_get_by_name(fmri);
	if (v == NULL || !(v->gv_flags & GV_CONFIGURED)) {
		/* Will get the up-to-date properties. */
		MUTEX_UNLOCK(&dgraph_lock);
		err = dgraph_add_instance(fmri, inst, B_TRUE);
		startd_free(fmri, max_scf_fmri_size);
		scf_instance_destroy(inst);
		return (err == ECANCELED ? 0 : err);
	}

	/* Read enabled & restarter from repository. */
	restarter_fmri = startd_alloc(max_scf_value_size);
	err = libscf_get_basic_instance_data(h, inst, v->gv_name, &enabled,
	    &enabled_ovr, &restarter_fmri);
	if (err != 0 || enabled == -1) {
		MUTEX_UNLOCK(&dgraph_lock);
		scf_instance_destroy(inst);
		startd_free(fmri, max_scf_fmri_size);

		switch (err) {
		case ENOENT:
		case 0:
			startd_free(restarter_fmri, max_scf_value_size);
			return (-1);

		case ECONNABORTED:
		case ECANCELED:
			startd_free(restarter_fmri, max_scf_value_size);
			return (err);

		default:
			bad_error("libscf_get_basic_instance_data", err);
		}
	}

	oldflags = v->gv_flags;
	v->gv_flags = (v->gv_flags & ~GV_ENBLD_NOOVR) |
	    (enabled ? GV_ENBLD_NOOVR : 0);

	if (enabled_ovr != -1)
		enabled = enabled_ovr;

	/*
	 * If GV_ENBLD_NOOVR has changed, then we need to re-evaluate the
	 * subgraph.
	 */
	if (milestone > MILESTONE_NONE && v->gv_flags != oldflags)
		(void) eval_subgraph(v, h);

	scf_instance_destroy(inst);

	/* Ignore restarter change for now. */

	startd_free(restarter_fmri, max_scf_value_size);
	startd_free(fmri, max_scf_fmri_size);

	/*
	 * Always send _ENABLE or _DISABLE.  We could avoid this if the
	 * restarter didn't change and the enabled value didn't change, but
	 * that's not easy to check and improbable anyway, so we'll just do
	 * this.
	 */
	graph_enable_by_vertex(v, enabled, 1);

	MUTEX_UNLOCK(&dgraph_lock);

	return (0);
}

/*
 * Delete all of the property group dependencies of v, update inst's running
 * snapshot, and add the dependencies in the new snapshot.  If any of the new
 * dependencies would create a cycle, send _ADMIN_MAINT_ON.  Otherwise
 * reevaluate v's dependencies, send _START or _STOP as appropriate, and do
 * the same for v's dependents.
 *
 * Returns
 *   0 - success
 *   ECONNABORTED - repository connection broken
 *   ECANCELED - inst was deleted
 *   EINVAL - inst is invalid (e.g., missing general/enabled)
 *   -1 - libscf_snapshots_refresh() failed
 */
static int
dgraph_refresh_instance(graph_vertex_t *v, scf_instance_t *inst)
{
	int r;
	int enabled;
	int32_t tset;

	assert(MUTEX_HELD(&dgraph_lock));
	assert(v->gv_type == GVT_INST);

	/* Only refresh services with valid general/enabled properties. */
	r = libscf_get_basic_instance_data(scf_instance_handle(inst), inst,
	    v->gv_name, &enabled, NULL, NULL);
	switch (r) {
	case 0:
		break;

	case ECONNABORTED:
	case ECANCELED:
		return (r);

	case ENOENT:
		log_framework(LOG_DEBUG,
		    "Ignoring %s because it has no general property group.\n",
		    v->gv_name);
		return (EINVAL);

	default:
		bad_error("libscf_get_basic_instance_data", r);
	}

	if ((tset = libscf_get_stn_tset(inst)) == -1) {
		log_framework(LOG_WARNING,
		    "Failed to get notification parameters for %s: %s\n",
		    v->gv_name, scf_strerror(scf_error()));
		tset = 0;
	}
	v->gv_stn_tset = tset;
	if (strcmp(v->gv_name, SCF_INSTANCE_GLOBAL) == 0)
		stn_global = tset;

	if (enabled == -1)
		return (EINVAL);

	r = libscf_snapshots_refresh(inst, v->gv_name);
	if (r != 0) {
		if (r != -1)
			bad_error("libscf_snapshots_refresh", r);

		/* error logged */
		return (r);
	}

	r = refresh_vertex(v, inst);
	if (r != 0 && r != ECONNABORTED)
		bad_error("refresh_vertex", r);
	return (r);
}

/*
 * Returns true only if none of this service's dependents are 'up' -- online
 * or degraded (offline is considered down in this situation). This function
 * is somehow similar to is_nonsubgraph_leaf() but works on subtrees.
 */
static boolean_t
insubtree_dependents_down(graph_vertex_t *v)
{
	graph_vertex_t *vv;
	graph_edge_t *e;

	assert(MUTEX_HELD(&dgraph_lock));

	for (e = uu_list_first(v->gv_dependents); e != NULL;
	    e = uu_list_next(v->gv_dependents, e)) {
		vv = e->ge_vertex;
		if (vv->gv_type == GVT_INST) {
			if ((vv->gv_flags & GV_CONFIGURED) == 0)
				continue;

			if ((vv->gv_flags & GV_TOOFFLINE) == 0)
				continue;

			if ((vv->gv_state == RESTARTER_STATE_ONLINE) ||
			    (vv->gv_state == RESTARTER_STATE_DEGRADED))
				return (B_FALSE);
		} else {
			/*
			 * Skip all excluded dependents and decide whether
			 * to offline the service based on the restart_on
			 * on attribute.
			 */
			if (is_depgrp_bypassed(vv))
				continue;

			/*
			 * For dependency groups or service vertices, keep
			 * traversing to see if instances are running.
			 */
			if (insubtree_dependents_down(vv) == B_FALSE)
				return (B_FALSE);
		}
	}

	return (B_TRUE);
}

/*
 * Returns true only if none of this service's dependents are 'up' -- online,
 * degraded, or offline.
 */
static int
is_nonsubgraph_leaf(graph_vertex_t *v)
{
	graph_vertex_t *vv;
	graph_edge_t *e;

	assert(MUTEX_HELD(&dgraph_lock));

	for (e = uu_list_first(v->gv_dependents);
	    e != NULL;
	    e = uu_list_next(v->gv_dependents, e)) {

		vv = e->ge_vertex;
		if (vv->gv_type == GVT_INST) {
			if ((vv->gv_flags & GV_CONFIGURED) == 0)
				continue;

			if (vv->gv_flags & GV_INSUBGRAPH)
				continue;

			if (up_state(vv->gv_state))
				return (0);
		} else {
			/*
			 * For dependency group or service vertices, keep
			 * traversing to see if instances are running.
			 *
			 * We should skip exclude_all dependencies otherwise
			 * the vertex will never be considered as a leaf
			 * if the dependent is offline. The main reason for
			 * this is that disable_nonsubgraph_leaves() skips
			 * exclusion dependencies.
			 */
			if (vv->gv_type == GVT_GROUP &&
			    vv->gv_depgroup == DEPGRP_EXCLUDE_ALL)
				continue;

			if (!is_nonsubgraph_leaf(vv))
				return (0);
		}
	}

	return (1);
}

/*
 * Disable v temporarily.  Attempt to do this by setting its enabled override
 * property in the repository.  If that fails, send a _DISABLE command.
 * Returns 0 on success and ECONNABORTED if the repository connection is
 * broken.
 */
static int
disable_service_temporarily(graph_vertex_t *v, scf_handle_t *h)
{
	const char * const emsg = "Could not temporarily disable %s because "
	    "%s.  Will stop service anyways.  Repository status for the "
	    "service may be inaccurate.\n";
	const char * const emsg_cbroken =
	    "the repository connection was broken";

	scf_instance_t *inst;
	int r;

	inst = scf_instance_create(h);
	if (inst == NULL) {
		char buf[100];

		(void) snprintf(buf, sizeof (buf),
		    "scf_instance_create() failed (%s)",
		    scf_strerror(scf_error()));
		log_error(LOG_WARNING, emsg, v->gv_name, buf);

		graph_enable_by_vertex(v, 0, 0);
		return (0);
	}

	r = scf_handle_decode_fmri(h, v->gv_name, NULL, NULL, inst,
	    NULL, NULL, SCF_DECODE_FMRI_EXACT);
	if (r != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
			log_error(LOG_WARNING, emsg, v->gv_name, emsg_cbroken);
			graph_enable_by_vertex(v, 0, 0);
			return (ECONNABORTED);

		case SCF_ERROR_NOT_FOUND:
			return (0);

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_NOT_BOUND:
		default:
			bad_error("scf_handle_decode_fmri",
			    scf_error());
		}
	}

	r = libscf_set_enable_ovr(inst, 0);
	switch (r) {
	case 0:
		scf_instance_destroy(inst);
		return (0);

	case ECANCELED:
		scf_instance_destroy(inst);
		return (0);

	case ECONNABORTED:
		log_error(LOG_WARNING, emsg, v->gv_name, emsg_cbroken);
		graph_enable_by_vertex(v, 0, 0);
		return (ECONNABORTED);

	case EPERM:
		log_error(LOG_WARNING, emsg, v->gv_name,
		    "the repository denied permission");
		graph_enable_by_vertex(v, 0, 0);
		return (0);

	case EROFS:
		log_error(LOG_WARNING, emsg, v->gv_name,
		    "the repository is read-only");
		graph_enable_by_vertex(v, 0, 0);
		return (0);

	default:
		bad_error("libscf_set_enable_ovr", r);
		/* NOTREACHED */
	}
}

/*
 * Of the transitive instance dependencies of v, offline those which are
 * in the subtree and which are leaves (i.e., have no dependents which are
 * "up").
 */
void
offline_subtree_leaves(graph_vertex_t *v, void *arg)
{
	assert(MUTEX_HELD(&dgraph_lock));

	/* If v isn't an instance, recurse on its dependencies. */
	if (v->gv_type != GVT_INST) {
		graph_walk_dependencies(v, offline_subtree_leaves, arg);
		return;
	}

	/*
	 * If v is not in the subtree, so should all of its dependencies,
	 * so do nothing.
	 */
	if ((v->gv_flags & GV_TOOFFLINE) == 0)
		return;

	/* If v isn't a leaf because it's already down, recurse. */
	if (!up_state(v->gv_state)) {
		graph_walk_dependencies(v, offline_subtree_leaves, arg);
		return;
	}

	/* if v is a leaf, offline it or disable it if it's the last one */
	if (insubtree_dependents_down(v) == B_TRUE) {
		if (v->gv_flags & GV_TODISABLE)
			vertex_send_event(v,
			    RESTARTER_EVENT_TYPE_ADMIN_DISABLE);
		else
			offline_vertex(v);
	}
}

void
graph_offline_subtree_leaves(graph_vertex_t *v, void *h)
{
	graph_walk_dependencies(v, offline_subtree_leaves, (void *)h);
}


/*
 * Of the transitive instance dependencies of v, disable those which are not
 * in the subgraph and which are leaves (i.e., have no dependents which are
 * "up").
 */
static void
disable_nonsubgraph_leaves(graph_vertex_t *v, void *arg)
{
	assert(MUTEX_HELD(&dgraph_lock));

	/*
	 * We must skip exclusion dependencies because they are allowed to
	 * complete dependency cycles.  This is correct because A's exclusion
	 * dependency on B doesn't bear on the order in which they should be
	 * stopped.  Indeed, the exclusion dependency should guarantee that
	 * they are never online at the same time.
	 */
	if (v->gv_type == GVT_GROUP && v->gv_depgroup == DEPGRP_EXCLUDE_ALL)
		return;

	/* If v isn't an instance, recurse on its dependencies. */
	if (v->gv_type != GVT_INST)
		goto recurse;

	if ((v->gv_flags & GV_CONFIGURED) == 0)
		/*
		 * Unconfigured instances should have no dependencies, but in
		 * case they ever get them,
		 */
		goto recurse;

	/*
	 * If v is in the subgraph, so should all of its dependencies, so do
	 * nothing.
	 */
	if (v->gv_flags & GV_INSUBGRAPH)
		return;

	/* If v isn't a leaf because it's already down, recurse. */
	if (!up_state(v->gv_state))
		goto recurse;

	/* If v is disabled but not down yet, be patient. */
	if ((v->gv_flags & GV_ENABLED) == 0)
		return;

	/* If v is a leaf, disable it. */
	if (is_nonsubgraph_leaf(v))
		(void) disable_service_temporarily(v, (scf_handle_t *)arg);

	return;

recurse:
	graph_walk_dependencies(v, disable_nonsubgraph_leaves, arg);
}

static int
stn_restarter_state(restarter_instance_state_t rstate)
{
	static const struct statemap {
		restarter_instance_state_t restarter_state;
		int scf_state;
	} map[] = {
		{ RESTARTER_STATE_UNINIT, SCF_STATE_UNINIT },
		{ RESTARTER_STATE_MAINT, SCF_STATE_MAINT },
		{ RESTARTER_STATE_OFFLINE, SCF_STATE_OFFLINE },
		{ RESTARTER_STATE_DISABLED, SCF_STATE_DISABLED },
		{ RESTARTER_STATE_ONLINE, SCF_STATE_ONLINE },
		{ RESTARTER_STATE_DEGRADED, SCF_STATE_DEGRADED }
	};

	int i;

	for (i = 0; i < sizeof (map) / sizeof (map[0]); i++) {
		if (rstate == map[i].restarter_state)
			return (map[i].scf_state);
	}

	return (-1);
}

/*
 * State transition counters
 * Not incremented atomically - indicative only
 */
static uint64_t stev_ct_maint;
static uint64_t stev_ct_hwerr;
static uint64_t stev_ct_service;
static uint64_t stev_ct_global;
static uint64_t stev_ct_noprefs;
static uint64_t stev_ct_from_uninit;
static uint64_t stev_ct_bad_state;
static uint64_t stev_ct_ovr_prefs;

static void
dgraph_state_transition_notify(graph_vertex_t *v,
    restarter_instance_state_t old_state, restarter_str_t reason)
{
	restarter_instance_state_t new_state = v->gv_state;
	int stn_transition, maint;
	int from, to;
	nvlist_t *attr;
	fmev_pri_t pri = FMEV_LOPRI;
	int raise = 0;

	if ((from = stn_restarter_state(old_state)) == -1 ||
	    (to = stn_restarter_state(new_state)) == -1) {
		stev_ct_bad_state++;
		return;
	}

	stn_transition = from << 16 | to;

	maint = (to == SCF_STATE_MAINT || from == SCF_STATE_MAINT);

	if (maint) {
		/*
		 * All transitions to/from maintenance state must raise
		 * an event.
		 */
		raise++;
		pri = FMEV_HIPRI;
		stev_ct_maint++;
	} else if (reason == restarter_str_ct_ev_hwerr) {
		/*
		 * All transitions caused by hardware fault must raise
		 * an event
		 */
		raise++;
		pri = FMEV_HIPRI;
		stev_ct_hwerr++;
	} else if (stn_transition & v->gv_stn_tset) {
		/*
		 * Specifically enabled event.
		 */
		raise++;
		stev_ct_service++;
	} else if (from == SCF_STATE_UNINIT) {
		/*
		 * Only raise these if specifically selected above.
		 */
		stev_ct_from_uninit++;
	} else if (stn_transition & stn_global &&
	    (IS_ENABLED(v) == 1 || to == SCF_STATE_DISABLED)) {
		raise++;
		stev_ct_global++;
	} else {
		stev_ct_noprefs++;
	}

	if (info_events_all) {
		stev_ct_ovr_prefs++;
		raise++;
	}
	if (!raise)
		return;

	if (nvlist_alloc(&attr, NV_UNIQUE_NAME, 0) != 0 ||
	    nvlist_add_string(attr, "fmri", v->gv_name) != 0 ||
	    nvlist_add_uint32(attr, "reason-version",
	    restarter_str_version()) || nvlist_add_string(attr, "reason-short",
	    restarter_get_str_short(reason)) != 0 ||
	    nvlist_add_string(attr, "reason-long",
	    restarter_get_str_long(reason)) != 0 ||
	    nvlist_add_int32(attr, "transition", stn_transition) != 0) {
		log_framework(LOG_WARNING,
		    "FMEV: %s could not create nvlist for transition "
		    "event: %s\n", v->gv_name, strerror(errno));
		nvlist_free(attr);
		return;
	}

	if (fmev_rspublish_nvl(FMEV_RULESET_SMF, "state-transition",
	    instance_state_str[new_state], pri, attr) != FMEV_SUCCESS) {
		log_framework(LOG_DEBUG,
		    "FMEV: %s failed to publish transition event: %s\n",
		    v->gv_name, fmev_strerror(fmev_errno));
		nvlist_free(attr);
	}
}

/*
 * Find the vertex for inst_name.  If it doesn't exist, return ENOENT.
 * Otherwise set its state to state.  If the instance has entered a state
 * which requires automatic action, take it (Uninitialized: do
 * dgraph_refresh_instance() without the snapshot update.  Disabled: if the
 * instance should be enabled, send _ENABLE.  Offline: if the instance should
 * be disabled, send _DISABLE, and if its dependencies are satisfied, send
 * _START.  Online, Degraded: if the instance wasn't running, update its start
 * snapshot.  Maintenance: no action.)
 *
 * Also fails with ECONNABORTED, or EINVAL if state is invalid.
 */
static int
dgraph_set_instance_state(scf_handle_t *h, const char *inst_name,
    protocol_states_t *states)
{
	graph_vertex_t *v;
	int err = 0;
	restarter_instance_state_t old_state;
	restarter_instance_state_t state = states->ps_state;
	restarter_error_t serr = states->ps_err;

	MUTEX_LOCK(&dgraph_lock);

	v = vertex_get_by_name(inst_name);
	if (v == NULL) {
		MUTEX_UNLOCK(&dgraph_lock);
		return (ENOENT);
	}

	assert(v->gv_type == GVT_INST);

	switch (state) {
	case RESTARTER_STATE_UNINIT:
	case RESTARTER_STATE_DISABLED:
	case RESTARTER_STATE_OFFLINE:
	case RESTARTER_STATE_ONLINE:
	case RESTARTER_STATE_DEGRADED:
	case RESTARTER_STATE_MAINT:
		break;

	default:
		MUTEX_UNLOCK(&dgraph_lock);
		return (EINVAL);
	}

	log_framework(LOG_DEBUG, "Graph noting %s %s -> %s.\n", v->gv_name,
	    instance_state_str[v->gv_state], instance_state_str[state]);

	old_state = v->gv_state;
	v->gv_state = state;

	v->gv_reason = states->ps_reason;
	err = gt_transition(h, v, serr, old_state);
	if (err == 0 && v->gv_state != old_state) {
		dgraph_state_transition_notify(v, old_state, states->ps_reason);
	}

	MUTEX_UNLOCK(&dgraph_lock);
	return (err);
}

/*
 * Handle state changes during milestone shutdown.  See
 * dgraph_set_milestone().  If the repository connection is broken,
 * ECONNABORTED will be returned, though a _DISABLE command will be sent for
 * the vertex anyway.
 */
int
vertex_subgraph_dependencies_shutdown(scf_handle_t *h, graph_vertex_t *v,
    restarter_instance_state_t old_state)
{
	int was_up, now_up;
	int ret = 0;

	assert(v->gv_type == GVT_INST);

	/* Don't care if we're not going to a milestone. */
	if (milestone == NULL)
		return (0);

	/* Don't care if we already finished coming down. */
	if (non_subgraph_svcs == 0)
		return (0);

	/* Don't care if the service is in the subgraph. */
	if (v->gv_flags & GV_INSUBGRAPH)
		return (0);

	/*
	 * Update non_subgraph_svcs.  It is the number of non-subgraph
	 * services which are in online, degraded, or offline.
	 */

	was_up = up_state(old_state);
	now_up = up_state(v->gv_state);

	if (!was_up && now_up) {
		++non_subgraph_svcs;
	} else if (was_up && !now_up) {
		--non_subgraph_svcs;

		if (non_subgraph_svcs == 0) {
			if (halting != -1) {
				do_uadmin();
			} else if (go_single_user_mode || go_to_level1) {
				(void) startd_thread_create(single_user_thread,
				    NULL);
			}
			return (0);
		}
	}

	/* If this service is a leaf, it should be disabled. */
	if ((v->gv_flags & GV_ENABLED) && is_nonsubgraph_leaf(v)) {
		int r;

		r = disable_service_temporarily(v, h);
		switch (r) {
		case 0:
			break;

		case ECONNABORTED:
			ret = ECONNABORTED;
			break;

		default:
			bad_error("disable_service_temporarily", r);
		}
	}

	/*
	 * If the service just came down, propagate the disable to the newly
	 * exposed leaves.
	 */
	if (was_up && !now_up)
		graph_walk_dependencies(v, disable_nonsubgraph_leaves,
		    (void *)h);

	return (ret);
}

/*
 * Decide whether to start up an sulogin thread after a service is
 * finished changing state.  Only need to do the full can_come_up()
 * evaluation if an instance is changing state, we're not halfway through
 * loading the thread, and we aren't shutting down or going to the single
 * user milestone.
 */
void
graph_transition_sulogin(restarter_instance_state_t state,
    restarter_instance_state_t old_state)
{
	assert(MUTEX_HELD(&dgraph_lock));

	if (state != old_state && st->st_load_complete &&
	    !go_single_user_mode && !go_to_level1 &&
	    halting == -1) {
		if (!sulogin_thread_running && !can_come_up()) {
			(void) startd_thread_create(sulogin_thread, NULL);
			sulogin_thread_running = B_TRUE;
		}
	}
}

/*
 * Propagate a start, stop event, or a satisfiability event.
 *
 * PROPAGATE_START and PROPAGATE_STOP simply propagate the transition event
 * to direct dependents.  PROPAGATE_SAT propagates a start then walks the
 * full dependent graph to check for newly satisfied nodes.  This is
 * necessary for cases when non-direct dependents may be effected but direct
 * dependents may not (e.g. for optional_all evaluations, see the
 * propagate_satbility() comments).
 *
 * PROPAGATE_SAT should be used whenever a non-running service moves into
 * a state which can satisfy optional dependencies, like disabled or
 * maintenance.
 */
void
graph_transition_propagate(graph_vertex_t *v, propagate_event_t type,
    restarter_error_t rerr)
{
	if (type == PROPAGATE_STOP) {
		graph_walk_dependents(v, propagate_stop, (void *)rerr);
	} else if (type == PROPAGATE_START || type == PROPAGATE_SAT) {
		graph_walk_dependents(v, propagate_start, (void *)RERR_NONE);

		if (type == PROPAGATE_SAT)
			propagate_satbility(v);
	} else {
#ifndef NDEBUG
		uu_warn("%s:%d: Unexpected type value %d.\n",  __FILE__,
		    __LINE__, type);
#endif
		abort();
	}
}

/*
 * If a vertex for fmri exists and it is enabled, send _DISABLE to the
 * restarter.  If it is running, send _STOP.  Send _REMOVE_INSTANCE.  Delete
 * all property group dependencies, and the dependency on the restarter,
 * disposing of vertices as appropriate.  If other vertices depend on this
 * one, mark it unconfigured and return.  Otherwise remove the vertex.  Always
 * returns 0.
 */
static int
dgraph_remove_instance(const char *fmri, scf_handle_t *h)
{
	graph_vertex_t *v;
	graph_edge_t *e;
	uu_list_t *old_deps;
	int err;

	log_framework(LOG_DEBUG, "Graph engine: Removing %s.\n", fmri);

	MUTEX_LOCK(&dgraph_lock);

	v = vertex_get_by_name(fmri);
	if (v == NULL) {
		MUTEX_UNLOCK(&dgraph_lock);
		return (0);
	}

	/* Send restarter delete event. */
	if (v->gv_flags & GV_CONFIGURED)
		graph_unset_restarter(v);

	if (milestone > MILESTONE_NONE) {
		/*
		 * Make a list of v's current dependencies so we can
		 * reevaluate their GV_INSUBGRAPH flags after the dependencies
		 * are removed.
		 */
		old_deps = startd_list_create(graph_edge_pool, NULL, 0);

		err = uu_list_walk(v->gv_dependencies,
		    (uu_walk_fn_t *)append_svcs_or_insts, old_deps, 0);
		assert(err == 0);
	}

	delete_instance_dependencies(v, B_TRUE);

	/*
	 * Deleting an instance can both satisfy and unsatisfy dependencies,
	 * depending on their type.  First propagate the stop as a RERR_RESTART
	 * event -- deletion isn't a fault, just a normal stop.  This gives
	 * dependent services the chance to do a clean shutdown.  Then, mark
	 * the service as unconfigured and propagate the start event for the
	 * optional_all dependencies that might have become satisfied.
	 */
	graph_walk_dependents(v, propagate_stop, (void *)RERR_RESTART);

	v->gv_flags &= ~GV_CONFIGURED;
	v->gv_flags &= ~GV_DEATHROW;

	graph_walk_dependents(v, propagate_start, (void *)RERR_NONE);
	propagate_satbility(v);

	/*
	 * If there are no (non-service) dependents, the vertex can be
	 * completely removed.
	 */
	if (v != milestone && v->gv_refs == 0 &&
	    uu_list_numnodes(v->gv_dependents) == 1)
		remove_inst_vertex(v);

	if (milestone > MILESTONE_NONE) {
		void *cookie = NULL;

		while ((e = uu_list_teardown(old_deps, &cookie)) != NULL) {
			v = e->ge_vertex;

			if (vertex_unref(v) == VERTEX_INUSE)
				while (eval_subgraph(v, h) == ECONNABORTED)
					libscf_handle_rebind(h);

			startd_free(e, sizeof (*e));
		}

		uu_list_destroy(old_deps);
	}

	MUTEX_UNLOCK(&dgraph_lock);

	return (0);
}

/*
 * Return the eventual (maybe current) milestone in the form of a
 * legacy runlevel.
 */
static char
target_milestone_as_runlevel()
{
	assert(MUTEX_HELD(&dgraph_lock));

	if (milestone == NULL)
		return ('3');
	else if (milestone == MILESTONE_NONE)
		return ('0');

	if (strcmp(milestone->gv_name, multi_user_fmri) == 0)
		return ('2');
	else if (strcmp(milestone->gv_name, single_user_fmri) == 0)
		return ('S');
	else if (strcmp(milestone->gv_name, multi_user_svr_fmri) == 0)
		return ('3');

#ifndef NDEBUG
	(void) fprintf(stderr, "%s:%d: Unknown milestone name \"%s\".\n",
	    __FILE__, __LINE__, milestone->gv_name);
#endif
	abort();
	/* NOTREACHED */
}

static struct {
	char	rl;
	int	sig;
} init_sigs[] = {
	{ 'S', SIGBUS },
	{ '0', SIGINT },
	{ '1', SIGQUIT },
	{ '2', SIGILL },
	{ '3', SIGTRAP },
	{ '4', SIGIOT },
	{ '5', SIGEMT },
	{ '6', SIGFPE },
	{ 0, 0 }
};

static void
signal_init(char rl)
{
	pid_t init_pid;
	int i;

	assert(MUTEX_HELD(&dgraph_lock));

	if (zone_getattr(getzoneid(), ZONE_ATTR_INITPID, &init_pid,
	    sizeof (init_pid)) != sizeof (init_pid)) {
		log_error(LOG_NOTICE, "Could not get pid to signal init.\n");
		return;
	}

	for (i = 0; init_sigs[i].rl != 0; ++i)
		if (init_sigs[i].rl == rl)
			break;

	if (init_sigs[i].rl != 0) {
		if (kill(init_pid, init_sigs[i].sig) != 0) {
			switch (errno) {
			case EPERM:
			case ESRCH:
				log_error(LOG_NOTICE, "Could not signal init: "
				    "%s.\n", strerror(errno));
				break;

			case EINVAL:
			default:
				bad_error("kill", errno);
			}
		}
	}
}

/*
 * This is called when one of the major milestones changes state, or when
 * init is signalled and tells us it was told to change runlevel.  We wait
 * to reach the milestone because this allows /etc/inittab entries to retain
 * some boot ordering: historically, entries could place themselves before/after
 * the running of /sbin/rcX scripts but we can no longer make the
 * distinction because the /sbin/rcX scripts no longer exist as punctuation
 * marks in /etc/inittab.
 *
 * Also, we only trigger an update when we reach the eventual target
 * milestone: without this, an /etc/inittab entry marked only for
 * runlevel 2 would be executed for runlevel 3, which is not how
 * /etc/inittab entries work.
 *
 * If we're single user coming online, then we set utmpx to the target
 * runlevel so that legacy scripts can work as expected.
 */
static void
graph_runlevel_changed(char rl, int online)
{
	char trl;

	assert(MUTEX_HELD(&dgraph_lock));

	trl = target_milestone_as_runlevel();

	if (online) {
		if (rl == trl) {
			current_runlevel = trl;
			signal_init(trl);
		} else if (rl == 'S') {
			/*
			 * At boot, set the entry early for the benefit of the
			 * legacy init scripts.
			 */
			utmpx_set_runlevel(trl, 'S', B_FALSE);
		}
	} else {
		if (rl == '3' && trl == '2') {
			current_runlevel = trl;
			signal_init(trl);
		} else if (rl == '2' && trl == 'S') {
			current_runlevel = trl;
			signal_init(trl);
		}
	}
}

/*
 * Move to a backwards-compatible runlevel by executing the appropriate
 * /etc/rc?.d/K* scripts and/or setting the milestone.
 *
 * Returns
 *   0 - success
 *   ECONNRESET - success, but handle was reset
 *   ECONNABORTED - repository connection broken
 *   ECANCELED - pg was deleted
 */
static int
dgraph_set_runlevel(scf_propertygroup_t *pg, scf_property_t *prop)
{
	char rl;
	scf_handle_t *h;
	int r;
	const char *ms = NULL;	/* what to commit as options/milestone */
	boolean_t rebound = B_FALSE;
	int mark_rl = 0;

	const char * const stop = "stop";

	r = libscf_extract_runlevel(prop, &rl);
	switch (r) {
	case 0:
		break;

	case ECONNABORTED:
	case ECANCELED:
		return (r);

	case EINVAL:
	case ENOENT:
		log_error(LOG_WARNING, "runlevel property is misconfigured; "
		    "ignoring.\n");
		/* delete the bad property */
		goto nolock_out;

	default:
		bad_error("libscf_extract_runlevel", r);
	}

	switch (rl) {
	case 's':
		rl = 'S';
		/* FALLTHROUGH */

	case 'S':
	case '2':
	case '3':
		/*
		 * These cases cause a milestone change, so
		 * graph_runlevel_changed() will eventually deal with
		 * signalling init.
		 */
		break;

	case '0':
	case '1':
	case '4':
	case '5':
	case '6':
		mark_rl = 1;
		break;

	default:
		log_framework(LOG_NOTICE, "Unknown runlevel '%c'.\n", rl);
		ms = NULL;
		goto nolock_out;
	}

	h = scf_pg_handle(pg);

	MUTEX_LOCK(&dgraph_lock);

	/*
	 * Since this triggers no milestone changes, force it by hand.
	 */
	if (current_runlevel == '4' && rl == '3')
		mark_rl = 1;

	/*
	 * 1. If we are here after an "init X":
	 *
	 * init X
	 *	init/lscf_set_runlevel()
	 *		process_pg_event()
	 *		dgraph_set_runlevel()
	 *
	 * then we haven't passed through graph_runlevel_changed() yet,
	 * therefore 'current_runlevel' has not changed for sure but 'rl' has.
	 * In consequence, if 'rl' is lower than 'current_runlevel', we change
	 * the system runlevel and execute the appropriate /etc/rc?.d/K* scripts
	 * past this test.
	 *
	 * 2. On the other hand, if we are here after a "svcadm milestone":
	 *
	 * svcadm milestone X
	 *	dgraph_set_milestone()
	 *		handle_graph_update_event()
	 *		dgraph_set_instance_state()
	 *		graph_post_X_[online|offline]()
	 *		graph_runlevel_changed()
	 *		signal_init()
	 *			init/lscf_set_runlevel()
	 *				process_pg_event()
	 *				dgraph_set_runlevel()
	 *
	 * then we already passed through graph_runlevel_changed() (by the way
	 * of dgraph_set_milestone()) and 'current_runlevel' may have changed
	 * and already be equal to 'rl' so we are going to return immediately
	 * from dgraph_set_runlevel() without changing the system runlevel and
	 * without executing the /etc/rc?.d/K* scripts.
	 */
	if (rl == current_runlevel) {
		ms = NULL;
		goto out;
	}

	log_framework(LOG_DEBUG, "Changing to runlevel '%c'.\n", rl);

	/*
	 * Make sure stop rc scripts see the new settings via who -r.
	 */
	utmpx_set_runlevel(rl, current_runlevel, B_TRUE);

	/*
	 * Some run levels don't have a direct correspondence to any
	 * milestones, so we have to signal init directly.
	 */
	if (mark_rl) {
		current_runlevel = rl;
		signal_init(rl);
	}

	switch (rl) {
	case 'S':
		uu_warn("The system is coming down for administration.  "
		    "Please wait.\n");
		fork_rc_script(rl, stop, B_FALSE);
		ms = single_user_fmri;
		go_single_user_mode = B_TRUE;
		break;

	case '0':
		halting_time = time(NULL);
		fork_rc_script(rl, stop, B_TRUE);
		halting = AD_HALT;
		goto uadmin;

	case '5':
		halting_time = time(NULL);
		fork_rc_script(rl, stop, B_TRUE);
		halting = AD_POWEROFF;
		goto uadmin;

	case '6':
		halting_time = time(NULL);
		fork_rc_script(rl, stop, B_TRUE);
		if (scf_is_fastboot_default() && getzoneid() == GLOBAL_ZONEID)
			halting = AD_FASTREBOOT;
		else
			halting = AD_BOOT;

uadmin:
		uu_warn("The system is coming down.  Please wait.\n");
		ms = "none";

		/*
		 * We can't wait until all services are offline since this
		 * thread is responsible for taking them offline.  Instead we
		 * set halting to the second argument for uadmin() and call
		 * do_uadmin() from dgraph_set_instance_state() when
		 * appropriate.
		 */
		break;

	case '1':
		if (current_runlevel != 'S') {
			uu_warn("Changing to state 1.\n");
			fork_rc_script(rl, stop, B_FALSE);
		} else {
			uu_warn("The system is coming up for administration.  "
			    "Please wait.\n");
		}
		ms = single_user_fmri;
		go_to_level1 = B_TRUE;
		break;

	case '2':
		if (current_runlevel == '3' || current_runlevel == '4')
			fork_rc_script(rl, stop, B_FALSE);
		ms = multi_user_fmri;
		break;

	case '3':
	case '4':
		ms = "all";
		break;

	default:
#ifndef NDEBUG
		(void) fprintf(stderr, "%s:%d: Uncaught case %d ('%c').\n",
		    __FILE__, __LINE__, rl, rl);
#endif
		abort();
	}

out:
	MUTEX_UNLOCK(&dgraph_lock);

nolock_out:
	switch (r = libscf_clear_runlevel(pg, ms)) {
	case 0:
		break;

	case ECONNABORTED:
		libscf_handle_rebind(h);
		rebound = B_TRUE;
		goto nolock_out;

	case ECANCELED:
		break;

	case EPERM:
	case EACCES:
	case EROFS:
		log_error(LOG_NOTICE, "Could not delete \"%s/%s\" property: "
		    "%s.\n", SCF_PG_OPTIONS, "runlevel", strerror(r));
		break;

	default:
		bad_error("libscf_clear_runlevel", r);
	}

	return (rebound ? ECONNRESET : 0);
}

/*
 * mark_subtree walks the dependents and add the GV_TOOFFLINE flag
 * to the instances that are supposed to go offline during an
 * administrative disable operation.
 */
static int
mark_subtree(graph_edge_t *e, void *arg)
{
	graph_vertex_t *v;
	int r;

	v = e->ge_vertex;

	/* If it's already in the subgraph, skip. */
	if (v->gv_flags & GV_TOOFFLINE)
		return (UU_WALK_NEXT);

	switch (v->gv_type) {
	case GVT_INST:
		/* If the instance is already disabled, skip it. */
		if (!(v->gv_flags & GV_ENABLED))
			return (UU_WALK_NEXT);

		v->gv_flags |= GV_TOOFFLINE;
		log_framework(LOG_DEBUG, "%s added to subtree\n", v->gv_name);
		break;
	case GVT_GROUP:
		/*
		 * Skip all excluded dependents and decide whether to offline
		 * the service based on the restart_on attribute.
		 */
		if (is_depgrp_bypassed(v))
			return (UU_WALK_NEXT);
		break;
	}

	r = uu_list_walk(v->gv_dependents, (uu_walk_fn_t *)mark_subtree, arg,
	    0);
	assert(r == 0);
	return (UU_WALK_NEXT);
}

static int
mark_subgraph(graph_edge_t *e, void *arg)
{
	graph_vertex_t *v;
	int r;
	int optional = (int)arg;

	v = e->ge_vertex;

	/* If it's already in the subgraph, skip. */
	if (v->gv_flags & GV_INSUBGRAPH)
		return (UU_WALK_NEXT);

	/*
	 * Keep track if walk has entered an optional dependency group
	 */
	if (v->gv_type == GVT_GROUP && v->gv_depgroup == DEPGRP_OPTIONAL_ALL) {
		optional = 1;
	}
	/*
	 * Quit if we are in an optional dependency group and the instance
	 * is disabled
	 */
	if (optional && (v->gv_type == GVT_INST) &&
	    (!(v->gv_flags & GV_ENBLD_NOOVR)))
		return (UU_WALK_NEXT);

	v->gv_flags |= GV_INSUBGRAPH;

	/* Skip all excluded dependencies. */
	if (v->gv_type == GVT_GROUP && v->gv_depgroup == DEPGRP_EXCLUDE_ALL)
		return (UU_WALK_NEXT);

	r = uu_list_walk(v->gv_dependencies, (uu_walk_fn_t *)mark_subgraph,
	    (void *)optional, 0);
	assert(r == 0);
	return (UU_WALK_NEXT);
}

/*
 * Bring down all services which are not dependencies of fmri.  The
 * dependencies of fmri (direct & indirect) will constitute the "subgraph",
 * and will have the GV_INSUBGRAPH flag set.  The rest must be brought down,
 * which means the state is "disabled", "maintenance", or "uninitialized".  We
 * could consider "offline" to be down, and refrain from sending start
 * commands for such services, but that's not strictly necessary, so we'll
 * decline to intrude on the state machine.  It would probably confuse users
 * anyway.
 *
 * The services should be brought down in reverse-dependency order, so we
 * can't do it all at once here.  We initiate by override-disabling the leaves
 * of the dependency tree -- those services which are up but have no
 * dependents which are up.  When they come down,
 * vertex_subgraph_dependencies_shutdown() will override-disable the newly
 * exposed leaves.  Perseverance will ensure completion.
 *
 * Sometimes we need to take action when the transition is complete, like
 * start sulogin or halt the system.  To tell when we're done, we initialize
 * non_subgraph_svcs here to be the number of services which need to come
 * down.  As each does, we decrement the counter.  When it hits zero, we take
 * the appropriate action.  See vertex_subgraph_dependencies_shutdown().
 *
 * In case we're coming up, we also remove any enable-overrides for the
 * services which are dependencies of fmri.
 *
 * If norepository is true, the function will not change the repository.
 *
 * The decision to change the system run level in accordance with the milestone
 * is taken in dgraph_set_runlevel().
 *
 * Returns
 *   0 - success
 *   ECONNRESET - success, but handle was rebound
 *   EINVAL - fmri is invalid (error is logged)
 *   EALREADY - the milestone is already set to fmri
 *   ENOENT - a configured vertex does not exist for fmri (an error is logged)
 */
static int
dgraph_set_milestone(const char *fmri, scf_handle_t *h, boolean_t norepository)
{
	const char *cfmri, *fs;
	graph_vertex_t *nm, *v;
	int ret = 0, r;
	scf_instance_t *inst;
	boolean_t isall, isnone, rebound = B_FALSE;

	/* Validate fmri */
	isall = (strcmp(fmri, "all") == 0);
	isnone = (strcmp(fmri, "none") == 0);

	if (!isall && !isnone) {
		if (fmri_canonify(fmri, (char **)&cfmri, B_FALSE) == EINVAL)
			goto reject;

		if (strcmp(cfmri, single_user_fmri) != 0 &&
		    strcmp(cfmri, multi_user_fmri) != 0 &&
		    strcmp(cfmri, multi_user_svr_fmri) != 0) {
			startd_free((void *)cfmri, max_scf_fmri_size);
reject:
			log_framework(LOG_WARNING,
			    "Rejecting request for invalid milestone \"%s\".\n",
			    fmri);
			return (EINVAL);
		}
	}

	inst = safe_scf_instance_create(h);

	MUTEX_LOCK(&dgraph_lock);

	if (milestone == NULL) {
		if (isall) {
			log_framework(LOG_DEBUG,
			    "Milestone already set to all.\n");
			ret = EALREADY;
			goto out;
		}
	} else if (milestone == MILESTONE_NONE) {
		if (isnone) {
			log_framework(LOG_DEBUG,
			    "Milestone already set to none.\n");
			ret = EALREADY;
			goto out;
		}
	} else {
		if (!isall && !isnone &&
		    strcmp(cfmri, milestone->gv_name) == 0) {
			log_framework(LOG_DEBUG,
			    "Milestone already set to %s.\n", cfmri);
			ret = EALREADY;
			goto out;
		}
	}

	if (!isall && !isnone) {
		nm = vertex_get_by_name(cfmri);
		if (nm == NULL || !(nm->gv_flags & GV_CONFIGURED)) {
			log_framework(LOG_WARNING, "Cannot set milestone to %s "
			    "because no such service exists.\n", cfmri);
			ret = ENOENT;
			goto out;
		}
	}

	log_framework(LOG_DEBUG, "Changing milestone to %s.\n", fmri);

	/*
	 * Set milestone, removing the old one if this was the last reference.
	 */
	if (milestone > MILESTONE_NONE)
		(void) vertex_unref(milestone);

	if (isall)
		milestone = NULL;
	else if (isnone)
		milestone = MILESTONE_NONE;
	else {
		milestone = nm;
		/* milestone should count as a reference */
		vertex_ref(milestone);
	}

	/* Clear all GV_INSUBGRAPH bits. */
	for (v = uu_list_first(dgraph); v != NULL; v = uu_list_next(dgraph, v))
		v->gv_flags &= ~GV_INSUBGRAPH;

	if (!isall && !isnone) {
		/* Set GV_INSUBGRAPH for milestone & descendents. */
		milestone->gv_flags |= GV_INSUBGRAPH;

		r = uu_list_walk(milestone->gv_dependencies,
		    (uu_walk_fn_t *)mark_subgraph, NULL, 0);
		assert(r == 0);
	}

	/* Un-override services in the subgraph & override-disable the rest. */
	if (norepository)
		goto out;

	non_subgraph_svcs = 0;
	for (v = uu_list_first(dgraph);
	    v != NULL;
	    v = uu_list_next(dgraph, v)) {
		if (v->gv_type != GVT_INST ||
		    (v->gv_flags & GV_CONFIGURED) == 0)
			continue;

again:
		r = scf_handle_decode_fmri(h, v->gv_name, NULL, NULL, inst,
		    NULL, NULL, SCF_DECODE_FMRI_EXACT);
		if (r != 0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				libscf_handle_rebind(h);
				rebound = B_TRUE;
				goto again;

			case SCF_ERROR_NOT_FOUND:
				continue;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_CONSTRAINT_VIOLATED:
			case SCF_ERROR_NOT_BOUND:
				bad_error("scf_handle_decode_fmri",
				    scf_error());
			}
		}

		if (isall || (v->gv_flags & GV_INSUBGRAPH)) {
			r = libscf_delete_enable_ovr(inst);
			fs = "libscf_delete_enable_ovr";
		} else {
			assert(isnone || (v->gv_flags & GV_INSUBGRAPH) == 0);

			/*
			 * Services which are up need to come down before
			 * we're done, but we can only disable the leaves
			 * here.
			 */

			if (up_state(v->gv_state))
				++non_subgraph_svcs;

			/* If it's already disabled, don't bother. */
			if ((v->gv_flags & GV_ENABLED) == 0)
				continue;

			if (!is_nonsubgraph_leaf(v))
				continue;

			r = libscf_set_enable_ovr(inst, 0);
			fs = "libscf_set_enable_ovr";
		}
		switch (r) {
		case 0:
		case ECANCELED:
			break;

		case ECONNABORTED:
			libscf_handle_rebind(h);
			rebound = B_TRUE;
			goto again;

		case EPERM:
		case EROFS:
			log_error(LOG_WARNING,
			    "Could not set %s/%s for %s: %s.\n",
			    SCF_PG_GENERAL_OVR, SCF_PROPERTY_ENABLED,
			    v->gv_name, strerror(r));
			break;

		default:
			bad_error(fs, r);
		}
	}

	if (halting != -1) {
		if (non_subgraph_svcs > 1)
			uu_warn("%d system services are now being stopped.\n",
			    non_subgraph_svcs);
		else if (non_subgraph_svcs == 1)
			uu_warn("One system service is now being stopped.\n");
		else if (non_subgraph_svcs == 0)
			do_uadmin();
	}

	ret = rebound ? ECONNRESET : 0;

out:
	MUTEX_UNLOCK(&dgraph_lock);
	if (!isall && !isnone)
		startd_free((void *)cfmri, max_scf_fmri_size);
	scf_instance_destroy(inst);
	return (ret);
}


/*
 * Returns 0, ECONNABORTED, or EINVAL.
 */
static int
handle_graph_update_event(scf_handle_t *h, graph_protocol_event_t *e)
{
	int r;

	switch (e->gpe_type) {
	case GRAPH_UPDATE_RELOAD_GRAPH:
		log_error(LOG_WARNING,
		    "graph_event: reload graph unimplemented\n");
		break;

	case GRAPH_UPDATE_STATE_CHANGE: {
		protocol_states_t *states = e->gpe_data;

		switch (r = dgraph_set_instance_state(h, e->gpe_inst, states)) {
		case 0:
		case ENOENT:
			break;

		case ECONNABORTED:
			return (ECONNABORTED);

		case EINVAL:
		default:
#ifndef NDEBUG
			(void) fprintf(stderr, "dgraph_set_instance_state() "
			    "failed with unexpected error %d at %s:%d.\n", r,
			    __FILE__, __LINE__);
#endif
			abort();
		}

		startd_free(states, sizeof (protocol_states_t));
		break;
	}

	default:
		log_error(LOG_WARNING,
		    "graph_event_loop received an unknown event: %d\n",
		    e->gpe_type);
		break;
	}

	return (0);
}

/*
 * graph_event_thread()
 *    Wait for state changes from the restarters.
 */
/*ARGSUSED*/
void *
graph_event_thread(void *unused)
{
	scf_handle_t *h;
	int err;

	h = libscf_handle_create_bound_loop();

	/*CONSTCOND*/
	while (1) {
		graph_protocol_event_t *e;

		MUTEX_LOCK(&gu->gu_lock);

		while (gu->gu_wakeup == 0)
			(void) pthread_cond_wait(&gu->gu_cv, &gu->gu_lock);

		gu->gu_wakeup = 0;

		while ((e = graph_event_dequeue()) != NULL) {
			MUTEX_LOCK(&e->gpe_lock);
			MUTEX_UNLOCK(&gu->gu_lock);

			while ((err = handle_graph_update_event(h, e)) ==
			    ECONNABORTED)
				libscf_handle_rebind(h);

			if (err == 0)
				graph_event_release(e);
			else
				graph_event_requeue(e);

			MUTEX_LOCK(&gu->gu_lock);
		}

		MUTEX_UNLOCK(&gu->gu_lock);
	}

	/*
	 * Unreachable for now -- there's currently no graceful cleanup
	 * called on exit().
	 */
	MUTEX_UNLOCK(&gu->gu_lock);
	scf_handle_destroy(h);
	return (NULL);
}

static void
set_initial_milestone(scf_handle_t *h)
{
	scf_instance_t *inst;
	char *fmri, *cfmri;
	size_t sz;
	int r;

	inst = safe_scf_instance_create(h);
	fmri = startd_alloc(max_scf_fmri_size);

	/*
	 * If -m milestone= was specified, we want to set options_ovr/milestone
	 * to it.  Otherwise we want to read what the milestone should be set
	 * to.  Either way we need our inst.
	 */
get_self:
	if (scf_handle_decode_fmri(h, SCF_SERVICE_STARTD, NULL, NULL, inst,
	    NULL, NULL, SCF_DECODE_FMRI_EXACT) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
			libscf_handle_rebind(h);
			goto get_self;

		case SCF_ERROR_NOT_FOUND:
			if (st->st_subgraph != NULL &&
			    st->st_subgraph[0] != '\0') {
				sz = strlcpy(fmri, st->st_subgraph,
				    max_scf_fmri_size);
				assert(sz < max_scf_fmri_size);
			} else {
				fmri[0] = '\0';
			}
			break;

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_HANDLE_MISMATCH:
		default:
			bad_error("scf_handle_decode_fmri", scf_error());
		}
	} else {
		if (st->st_subgraph != NULL && st->st_subgraph[0] != '\0') {
			scf_propertygroup_t *pg;

			pg = safe_scf_pg_create(h);

			sz = strlcpy(fmri, st->st_subgraph, max_scf_fmri_size);
			assert(sz < max_scf_fmri_size);

			r = libscf_inst_get_or_add_pg(inst, SCF_PG_OPTIONS_OVR,
			    SCF_PG_OPTIONS_OVR_TYPE, SCF_PG_OPTIONS_OVR_FLAGS,
			    pg);
			switch (r) {
			case 0:
				break;

			case ECONNABORTED:
				libscf_handle_rebind(h);
				goto get_self;

			case EPERM:
			case EACCES:
			case EROFS:
				log_error(LOG_WARNING, "Could not set %s/%s: "
				    "%s.\n", SCF_PG_OPTIONS_OVR,
				    SCF_PROPERTY_MILESTONE, strerror(r));
				/* FALLTHROUGH */

			case ECANCELED:
				sz = strlcpy(fmri, st->st_subgraph,
				    max_scf_fmri_size);
				assert(sz < max_scf_fmri_size);
				break;

			default:
				bad_error("libscf_inst_get_or_add_pg", r);
			}

			r = libscf_clear_runlevel(pg, fmri);
			switch (r) {
			case 0:
				break;

			case ECONNABORTED:
				libscf_handle_rebind(h);
				goto get_self;

			case EPERM:
			case EACCES:
			case EROFS:
				log_error(LOG_WARNING, "Could not set %s/%s: "
				    "%s.\n", SCF_PG_OPTIONS_OVR,
				    SCF_PROPERTY_MILESTONE, strerror(r));
				/* FALLTHROUGH */

			case ECANCELED:
				sz = strlcpy(fmri, st->st_subgraph,
				    max_scf_fmri_size);
				assert(sz < max_scf_fmri_size);
				break;

			default:
				bad_error("libscf_clear_runlevel", r);
			}

			scf_pg_destroy(pg);
		} else {
			scf_property_t *prop;
			scf_value_t *val;

			prop = safe_scf_property_create(h);
			val = safe_scf_value_create(h);

			r = libscf_get_milestone(inst, prop, val, fmri,
			    max_scf_fmri_size);
			switch (r) {
			case 0:
				break;

			case ECONNABORTED:
				libscf_handle_rebind(h);
				goto get_self;

			case EINVAL:
				log_error(LOG_WARNING, "Milestone property is "
				    "misconfigured.  Defaulting to \"all\".\n");
				/* FALLTHROUGH */

			case ECANCELED:
			case ENOENT:
				fmri[0] = '\0';
				break;

			default:
				bad_error("libscf_get_milestone", r);
			}

			scf_value_destroy(val);
			scf_property_destroy(prop);
		}
	}

	if (fmri[0] == '\0' || strcmp(fmri, "all") == 0)
		goto out;

	if (strcmp(fmri, "none") != 0) {
retry:
		if (scf_handle_decode_fmri(h, fmri, NULL, NULL, inst, NULL,
		    NULL, SCF_DECODE_FMRI_EXACT) != 0) {
			switch (scf_error()) {
			case SCF_ERROR_INVALID_ARGUMENT:
				log_error(LOG_WARNING,
				    "Requested milestone \"%s\" is invalid.  "
				    "Reverting to \"all\".\n", fmri);
				goto out;

			case SCF_ERROR_CONSTRAINT_VIOLATED:
				log_error(LOG_WARNING, "Requested milestone "
				    "\"%s\" does not specify an instance.  "
				    "Reverting to \"all\".\n", fmri);
				goto out;

			case SCF_ERROR_CONNECTION_BROKEN:
				libscf_handle_rebind(h);
				goto retry;

			case SCF_ERROR_NOT_FOUND:
				log_error(LOG_WARNING, "Requested milestone "
				    "\"%s\" not in repository.  Reverting to "
				    "\"all\".\n", fmri);
				goto out;

			case SCF_ERROR_HANDLE_MISMATCH:
			default:
				bad_error("scf_handle_decode_fmri",
				    scf_error());
			}
		}

		r = fmri_canonify(fmri, &cfmri, B_FALSE);
		assert(r == 0);

		r = dgraph_add_instance(cfmri, inst, B_TRUE);
		startd_free(cfmri, max_scf_fmri_size);
		switch (r) {
		case 0:
			break;

		case ECONNABORTED:
			goto retry;

		case EINVAL:
			log_error(LOG_WARNING,
			    "Requested milestone \"%s\" is invalid.  "
			    "Reverting to \"all\".\n", fmri);
			goto out;

		case ECANCELED:
			log_error(LOG_WARNING,
			    "Requested milestone \"%s\" not "
			    "in repository.  Reverting to \"all\".\n",
			    fmri);
			goto out;

		case EEXIST:
		default:
			bad_error("dgraph_add_instance", r);
		}
	}

	log_console(LOG_INFO, "Booting to milestone \"%s\".\n", fmri);

	r = dgraph_set_milestone(fmri, h, B_FALSE);
	switch (r) {
	case 0:
	case ECONNRESET:
	case EALREADY:
		break;

	case EINVAL:
	case ENOENT:
	default:
		bad_error("dgraph_set_milestone", r);
	}

out:
	startd_free(fmri, max_scf_fmri_size);
	scf_instance_destroy(inst);
}

void
set_restart_milestone(scf_handle_t *h)
{
	scf_instance_t *inst;
	scf_property_t *prop;
	scf_value_t *val;
	char *fmri;
	int r;

	inst = safe_scf_instance_create(h);

get_self:
	if (scf_handle_decode_fmri(h, SCF_SERVICE_STARTD, NULL, NULL,
	    inst, NULL, NULL, SCF_DECODE_FMRI_EXACT) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
			libscf_handle_rebind(h);
			goto get_self;

		case SCF_ERROR_NOT_FOUND:
			break;

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_HANDLE_MISMATCH:
		default:
			bad_error("scf_handle_decode_fmri", scf_error());
		}

		scf_instance_destroy(inst);
		return;
	}

	prop = safe_scf_property_create(h);
	val = safe_scf_value_create(h);
	fmri = startd_alloc(max_scf_fmri_size);

	r = libscf_get_milestone(inst, prop, val, fmri, max_scf_fmri_size);
	switch (r) {
	case 0:
		break;

	case ECONNABORTED:
		libscf_handle_rebind(h);
		goto get_self;

	case ECANCELED:
	case ENOENT:
	case EINVAL:
		goto out;

	default:
		bad_error("libscf_get_milestone", r);
	}

	r = dgraph_set_milestone(fmri, h, B_TRUE);
	switch (r) {
	case 0:
	case ECONNRESET:
	case EALREADY:
	case EINVAL:
	case ENOENT:
		break;

	default:
		bad_error("dgraph_set_milestone", r);
	}

out:
	startd_free(fmri, max_scf_fmri_size);
	scf_value_destroy(val);
	scf_property_destroy(prop);
	scf_instance_destroy(inst);
}

/*
 * void *graph_thread(void *)
 *
 * Graph management thread.
 */
/*ARGSUSED*/
void *
graph_thread(void *arg)
{
	scf_handle_t *h;
	int err;

	h = libscf_handle_create_bound_loop();

	if (st->st_initial)
		set_initial_milestone(h);

	MUTEX_LOCK(&dgraph_lock);
	initial_milestone_set = B_TRUE;
	err = pthread_cond_broadcast(&initial_milestone_cv);
	assert(err == 0);
	MUTEX_UNLOCK(&dgraph_lock);

	libscf_populate_graph(h);

	if (!st->st_initial)
		set_restart_milestone(h);

	MUTEX_LOCK(&st->st_load_lock);
	st->st_load_complete = 1;
	(void) pthread_cond_broadcast(&st->st_load_cv);
	MUTEX_UNLOCK(&st->st_load_lock);

	MUTEX_LOCK(&dgraph_lock);
	/*
	 * Now that we've set st_load_complete we need to check can_come_up()
	 * since if we booted to a milestone, then there won't be any more
	 * state updates.
	 */
	if (!go_single_user_mode && !go_to_level1 &&
	    halting == -1) {
		if (!sulogin_thread_running && !can_come_up()) {
			(void) startd_thread_create(sulogin_thread, NULL);
			sulogin_thread_running = B_TRUE;
		}
	}
	MUTEX_UNLOCK(&dgraph_lock);

	(void) pthread_mutex_lock(&gu->gu_freeze_lock);

	/*CONSTCOND*/
	while (1) {
		(void) pthread_cond_wait(&gu->gu_freeze_cv,
		    &gu->gu_freeze_lock);
	}

	/*
	 * Unreachable for now -- there's currently no graceful cleanup
	 * called on exit().
	 */
	(void) pthread_mutex_unlock(&gu->gu_freeze_lock);
	scf_handle_destroy(h);

	return (NULL);
}


/*
 * int next_action()
 *   Given an array of timestamps 'a' with 'num' elements, find the
 *   lowest non-zero timestamp and return its index. If there are no
 *   non-zero elements, return -1.
 */
static int
next_action(hrtime_t *a, int num)
{
	hrtime_t t = 0;
	int i = 0, smallest = -1;

	for (i = 0; i < num; i++) {
		if (t == 0) {
			t = a[i];
			smallest = i;
		} else if (a[i] != 0 && a[i] < t) {
			t = a[i];
			smallest = i;
		}
	}

	if (t == 0)
		return (-1);
	else
		return (smallest);
}

/*
 * void process_actions()
 *   Process actions requested by the administrator. Possibilities include:
 *   refresh, restart, maintenance mode off, maintenance mode on,
 *   maintenance mode immediate, and degraded.
 *
 *   The set of pending actions is represented in the repository as a
 *   per-instance property group, with each action being a single property
 *   in that group.  This property group is converted to an array, with each
 *   action type having an array slot.  The actions in the array at the
 *   time process_actions() is called are acted on in the order of the
 *   timestamp (which is the value stored in the slot).  A value of zero
 *   indicates that there is no pending action of the type associated with
 *   a particular slot.
 *
 *   Sending an action event multiple times before the restarter has a
 *   chance to process that action will force it to be run at the last
 *   timestamp where it appears in the ordering.
 *
 *   Turning maintenance mode on trumps all other actions.
 *
 *   Returns 0 or ECONNABORTED.
 */
static int
process_actions(scf_handle_t *h, scf_propertygroup_t *pg, scf_instance_t *inst)
{
	scf_property_t *prop = NULL;
	scf_value_t *val = NULL;
	scf_type_t type;
	graph_vertex_t *vertex;
	admin_action_t a;
	int i, ret = 0, r;
	hrtime_t action_ts[NACTIONS];
	char *inst_name;

	r = libscf_instance_get_fmri(inst, &inst_name);
	switch (r) {
	case 0:
		break;

	case ECONNABORTED:
		return (ECONNABORTED);

	case ECANCELED:
		return (0);

	default:
		bad_error("libscf_instance_get_fmri", r);
	}

	MUTEX_LOCK(&dgraph_lock);

	vertex = vertex_get_by_name(inst_name);
	if (vertex == NULL) {
		MUTEX_UNLOCK(&dgraph_lock);
		log_framework(LOG_DEBUG, "%s: Can't find graph vertex. "
		    "The instance must have been removed.\n", inst_name);
		startd_free(inst_name, max_scf_fmri_size);
		return (0);
	}

	prop = safe_scf_property_create(h);
	val = safe_scf_value_create(h);

	for (i = 0; i < NACTIONS; i++) {
		if (scf_pg_get_property(pg, admin_actions[i], prop) != 0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_DELETED:
				goto out;

			case SCF_ERROR_NOT_FOUND:
				action_ts[i] = 0;
				continue;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_NOT_SET:
				bad_error("scf_pg_get_property", scf_error());
			}
		}

		if (scf_property_type(prop, &type) != 0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_DELETED:
				action_ts[i] = 0;
				continue;

			case SCF_ERROR_NOT_SET:
				bad_error("scf_property_type", scf_error());
			}
		}

		if (type != SCF_TYPE_INTEGER) {
			action_ts[i] = 0;
			continue;
		}

		if (scf_property_get_value(prop, val) != 0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_DELETED:
				goto out;

			case SCF_ERROR_NOT_FOUND:
			case SCF_ERROR_CONSTRAINT_VIOLATED:
				action_ts[i] = 0;
				continue;

			case SCF_ERROR_NOT_SET:
			case SCF_ERROR_PERMISSION_DENIED:
				bad_error("scf_property_get_value",
				    scf_error());
			}
		}

		r = scf_value_get_integer(val, &action_ts[i]);
		assert(r == 0);
	}

	a = ADMIN_EVENT_MAINT_ON_IMMEDIATE;
	if (action_ts[ADMIN_EVENT_MAINT_ON_IMMEDIATE] ||
	    action_ts[ADMIN_EVENT_MAINT_ON]) {
		a = action_ts[ADMIN_EVENT_MAINT_ON_IMMEDIATE] ?
		    ADMIN_EVENT_MAINT_ON_IMMEDIATE : ADMIN_EVENT_MAINT_ON;

		vertex_send_event(vertex, admin_events[a]);
		r = libscf_unset_action(h, pg, a, action_ts[a]);
		switch (r) {
		case 0:
		case EACCES:
			break;

		case ECONNABORTED:
			ret = ECONNABORTED;
			goto out;

		case EPERM:
			uu_die("Insufficient privilege.\n");
			/* NOTREACHED */

		default:
			bad_error("libscf_unset_action", r);
		}
	}

	while ((a = next_action(action_ts, NACTIONS)) != -1) {
		log_framework(LOG_DEBUG,
		    "Graph: processing %s action for %s.\n", admin_actions[a],
		    inst_name);

		if (a == ADMIN_EVENT_REFRESH) {
			r = dgraph_refresh_instance(vertex, inst);
			switch (r) {
			case 0:
			case ECANCELED:
			case EINVAL:
			case -1:
				break;

			case ECONNABORTED:
				/* pg & inst are reset now, so just return. */
				ret = ECONNABORTED;
				goto out;

			default:
				bad_error("dgraph_refresh_instance", r);
			}
		}

		vertex_send_event(vertex, admin_events[a]);

		r = libscf_unset_action(h, pg, a, action_ts[a]);
		switch (r) {
		case 0:
		case EACCES:
			break;

		case ECONNABORTED:
			ret = ECONNABORTED;
			goto out;

		case EPERM:
			uu_die("Insufficient privilege.\n");
			/* NOTREACHED */

		default:
			bad_error("libscf_unset_action", r);
		}

		action_ts[a] = 0;
	}

out:
	MUTEX_UNLOCK(&dgraph_lock);

	scf_property_destroy(prop);
	scf_value_destroy(val);
	startd_free(inst_name, max_scf_fmri_size);
	return (ret);
}

/*
 * inst and pg_name are scratch space, and are unset on entry.
 * Returns
 *   0 - success
 *   ECONNRESET - success, but repository handle rebound
 *   ECONNABORTED - repository connection broken
 */
static int
process_pg_event(scf_handle_t *h, scf_propertygroup_t *pg, scf_instance_t *inst,
    char *pg_name)
{
	int r;
	scf_property_t *prop;
	scf_value_t *val;
	char *fmri;
	boolean_t rebound = B_FALSE, rebind_inst = B_FALSE;

	if (scf_pg_get_name(pg, pg_name, max_scf_value_size) < 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			return (ECONNABORTED);

		case SCF_ERROR_DELETED:
			return (0);

		case SCF_ERROR_NOT_SET:
			bad_error("scf_pg_get_name", scf_error());
		}
	}

	if (strcmp(pg_name, SCF_PG_GENERAL) == 0 ||
	    strcmp(pg_name, SCF_PG_GENERAL_OVR) == 0) {
		r = dgraph_update_general(pg);
		switch (r) {
		case 0:
		case ENOTSUP:
		case ECANCELED:
			return (0);

		case ECONNABORTED:
			return (ECONNABORTED);

		case -1:
			/* Error should have been logged. */
			return (0);

		default:
			bad_error("dgraph_update_general", r);
		}
	} else if (strcmp(pg_name, SCF_PG_RESTARTER_ACTIONS) == 0) {
		if (scf_pg_get_parent_instance(pg, inst) != 0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
				return (ECONNABORTED);

			case SCF_ERROR_DELETED:
			case SCF_ERROR_CONSTRAINT_VIOLATED:
				/* Ignore commands on services. */
				return (0);

			case SCF_ERROR_NOT_BOUND:
			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_NOT_SET:
			default:
				bad_error("scf_pg_get_parent_instance",
				    scf_error());
			}
		}

		return (process_actions(h, pg, inst));
	}

	if (strcmp(pg_name, SCF_PG_OPTIONS) != 0 &&
	    strcmp(pg_name, SCF_PG_OPTIONS_OVR) != 0)
		return (0);

	/*
	 * We only care about the options[_ovr] property groups of our own
	 * instance, so get the fmri and compare.  Plus, once we know it's
	 * correct, if the repository connection is broken we know exactly what
	 * property group we were operating on, and can look it up again.
	 */
	if (scf_pg_get_parent_instance(pg, inst) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
			return (ECONNABORTED);

		case SCF_ERROR_DELETED:
		case SCF_ERROR_CONSTRAINT_VIOLATED:
			return (0);

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_NOT_BOUND:
		case SCF_ERROR_NOT_SET:
		default:
			bad_error("scf_pg_get_parent_instance",
			    scf_error());
		}
	}

	switch (r = libscf_instance_get_fmri(inst, &fmri)) {
	case 0:
		break;

	case ECONNABORTED:
		return (ECONNABORTED);

	case ECANCELED:
		return (0);

	default:
		bad_error("libscf_instance_get_fmri", r);
	}

	if (strcmp(fmri, SCF_SERVICE_STARTD) != 0) {
		startd_free(fmri, max_scf_fmri_size);
		return (0);
	}

	/*
	 * update the information events flag
	 */
	if (strcmp(pg_name, SCF_PG_OPTIONS) == 0)
		info_events_all = libscf_get_info_events_all(pg);

	prop = safe_scf_property_create(h);
	val = safe_scf_value_create(h);

	if (strcmp(pg_name, SCF_PG_OPTIONS_OVR) == 0) {
		/* See if we need to set the runlevel. */
		/* CONSTCOND */
		if (0) {
rebind_pg:
			libscf_handle_rebind(h);
			rebound = B_TRUE;

			r = libscf_lookup_instance(SCF_SERVICE_STARTD, inst);
			switch (r) {
			case 0:
				break;

			case ECONNABORTED:
				goto rebind_pg;

			case ENOENT:
				goto out;

			case EINVAL:
			case ENOTSUP:
				bad_error("libscf_lookup_instance", r);
			}

			if (scf_instance_get_pg(inst, pg_name, pg) != 0) {
				switch (scf_error()) {
				case SCF_ERROR_DELETED:
				case SCF_ERROR_NOT_FOUND:
					goto out;

				case SCF_ERROR_CONNECTION_BROKEN:
					goto rebind_pg;

				case SCF_ERROR_HANDLE_MISMATCH:
				case SCF_ERROR_NOT_BOUND:
				case SCF_ERROR_NOT_SET:
				case SCF_ERROR_INVALID_ARGUMENT:
				default:
					bad_error("scf_instance_get_pg",
					    scf_error());
				}
			}
		}

		if (scf_pg_get_property(pg, "runlevel", prop) == 0) {
			r = dgraph_set_runlevel(pg, prop);
			switch (r) {
			case ECONNRESET:
				rebound = B_TRUE;
				rebind_inst = B_TRUE;
				/* FALLTHROUGH */

			case 0:
				break;

			case ECONNABORTED:
				goto rebind_pg;

			case ECANCELED:
				goto out;

			default:
				bad_error("dgraph_set_runlevel", r);
			}
		} else {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				goto rebind_pg;

			case SCF_ERROR_DELETED:
				goto out;

			case SCF_ERROR_NOT_FOUND:
				break;

			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_NOT_BOUND:
			case SCF_ERROR_NOT_SET:
				bad_error("scf_pg_get_property", scf_error());
			}
		}
	}

	if (rebind_inst) {
lookup_inst:
		r = libscf_lookup_instance(SCF_SERVICE_STARTD, inst);
		switch (r) {
		case 0:
			break;

		case ECONNABORTED:
			libscf_handle_rebind(h);
			rebound = B_TRUE;
			goto lookup_inst;

		case ENOENT:
			goto out;

		case EINVAL:
		case ENOTSUP:
			bad_error("libscf_lookup_instance", r);
		}
	}

	r = libscf_get_milestone(inst, prop, val, fmri, max_scf_fmri_size);
	switch (r) {
	case 0:
		break;

	case ECONNABORTED:
		libscf_handle_rebind(h);
		rebound = B_TRUE;
		goto lookup_inst;

	case EINVAL:
		log_error(LOG_NOTICE,
		    "%s/%s property of %s is misconfigured.\n", pg_name,
		    SCF_PROPERTY_MILESTONE, SCF_SERVICE_STARTD);
		/* FALLTHROUGH */

	case ECANCELED:
	case ENOENT:
		(void) strcpy(fmri, "all");
		break;

	default:
		bad_error("libscf_get_milestone", r);
	}

	r = dgraph_set_milestone(fmri, h, B_FALSE);
	switch (r) {
	case 0:
	case ECONNRESET:
	case EALREADY:
		break;

	case EINVAL:
		log_error(LOG_WARNING, "Milestone %s is invalid.\n", fmri);
		break;

	case ENOENT:
		log_error(LOG_WARNING, "Milestone %s does not exist.\n", fmri);
		break;

	default:
		bad_error("dgraph_set_milestone", r);
	}

out:
	startd_free(fmri, max_scf_fmri_size);
	scf_value_destroy(val);
	scf_property_destroy(prop);

	return (rebound ? ECONNRESET : 0);
}

/*
 * process_delete() deletes an instance from the dgraph if 'fmri' is an
 * instance fmri or if 'fmri' matches the 'general' property group of an
 * instance (or the 'general/enabled' property).
 *
 * 'fmri' may be overwritten and cannot be trusted on return by the caller.
 */
static void
process_delete(char *fmri, scf_handle_t *h)
{
	char *lfmri, *end_inst_fmri;
	const char *inst_name = NULL;
	const char *pg_name = NULL;
	const char *prop_name = NULL;

	lfmri = safe_strdup(fmri);

	/* Determine if the FMRI is a property group or instance */
	if (scf_parse_svc_fmri(lfmri, NULL, NULL, &inst_name, &pg_name,
	    &prop_name) != SCF_SUCCESS) {
		log_error(LOG_WARNING,
		    "Received invalid FMRI \"%s\" from repository server.\n",
		    fmri);
	} else if (inst_name != NULL && pg_name == NULL) {
		(void) dgraph_remove_instance(fmri, h);
	} else if (inst_name != NULL && pg_name != NULL) {
		/*
		 * If we're deleting the 'general' property group or
		 * 'general/enabled' property then the whole instance
		 * must be removed from the dgraph.
		 */
		if (strcmp(pg_name, SCF_PG_GENERAL) != 0) {
			free(lfmri);
			return;
		}

		if (prop_name != NULL &&
		    strcmp(prop_name, SCF_PROPERTY_ENABLED) != 0) {
			free(lfmri);
			return;
		}

		/*
		 * Because the instance has already been deleted from the
		 * repository, we cannot use any scf_ functions to retrieve
		 * the instance FMRI however we can easily reconstruct it
		 * manually.
		 */
		end_inst_fmri = strstr(fmri, SCF_FMRI_PROPERTYGRP_PREFIX);
		if (end_inst_fmri == NULL)
			bad_error("process_delete", 0);

		end_inst_fmri[0] = '\0';

		(void) dgraph_remove_instance(fmri, h);
	}

	free(lfmri);
}

/*ARGSUSED*/
void *
repository_event_thread(void *unused)
{
	scf_handle_t *h;
	scf_propertygroup_t *pg;
	scf_instance_t *inst;
	char *fmri = startd_alloc(max_scf_fmri_size);
	char *pg_name = startd_alloc(max_scf_value_size);
	int r;

	h = libscf_handle_create_bound_loop();

	pg = safe_scf_pg_create(h);
	inst = safe_scf_instance_create(h);

retry:
	if (_scf_notify_add_pgtype(h, SCF_GROUP_FRAMEWORK) != SCF_SUCCESS) {
		if (scf_error() == SCF_ERROR_CONNECTION_BROKEN) {
			libscf_handle_rebind(h);
		} else {
			log_error(LOG_WARNING,
			    "Couldn't set up repository notification "
			    "for property group type %s: %s\n",
			    SCF_GROUP_FRAMEWORK, scf_strerror(scf_error()));

			(void) sleep(1);
		}

		goto retry;
	}

	/*CONSTCOND*/
	while (1) {
		ssize_t res;

		/* Note: fmri is only set on delete events. */
		res = _scf_notify_wait(pg, fmri, max_scf_fmri_size);
		if (res < 0) {
			libscf_handle_rebind(h);
			goto retry;
		} else if (res == 0) {
			/*
			 * property group modified.  inst and pg_name are
			 * pre-allocated scratch space.
			 */
			if (scf_pg_update(pg) < 0) {
				switch (scf_error()) {
				case SCF_ERROR_DELETED:
					continue;

				case SCF_ERROR_CONNECTION_BROKEN:
					log_error(LOG_WARNING,
					    "Lost repository event due to "
					    "disconnection.\n");
					libscf_handle_rebind(h);
					goto retry;

				case SCF_ERROR_NOT_BOUND:
				case SCF_ERROR_NOT_SET:
				default:
					bad_error("scf_pg_update", scf_error());
				}
			}

			r = process_pg_event(h, pg, inst, pg_name);
			switch (r) {
			case 0:
				break;

			case ECONNABORTED:
				log_error(LOG_WARNING, "Lost repository event "
				    "due to disconnection.\n");
				libscf_handle_rebind(h);
				/* FALLTHROUGH */

			case ECONNRESET:
				goto retry;

			default:
				bad_error("process_pg_event", r);
			}
		} else {
			/*
			 * Service, instance, or pg deleted.
			 * Don't trust fmri on return.
			 */
			process_delete(fmri, h);
		}
	}

	/*NOTREACHED*/
	return (NULL);
}

void
graph_engine_start()
{
	int err;

	(void) startd_thread_create(graph_thread, NULL);

	MUTEX_LOCK(&dgraph_lock);
	while (!initial_milestone_set) {
		err = pthread_cond_wait(&initial_milestone_cv, &dgraph_lock);
		assert(err == 0);
	}
	MUTEX_UNLOCK(&dgraph_lock);

	(void) startd_thread_create(repository_event_thread, NULL);
	(void) startd_thread_create(graph_event_thread, NULL);
}
