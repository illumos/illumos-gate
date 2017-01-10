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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 */

/*
 * Service state explanation.  For select services, display a description, the
 * state, and possibly why the service is in that state, what's causing it to
 * be in that state, and what other services it is keeping offline (impact).
 *
 * Explaining states other than offline is easy.  For maintenance and
 * degraded, we just use the auxiliary state.  For offline, we must determine
 * which dependencies are unsatisfied and recurse.  If a causal service is not
 * offline, then a svcptr to it is added to the offline service's causes list.
 * If a causal service is offline, then we recurse to determine its causes and
 * merge them into the causes list of the service in question (see
 * add_causes()).  Note that by adding a self-pointing svcptr to the causes
 * lists of services which are not offline or are offline for unknown reasons,
 * we can always merge the unsatisfied dependency's causes into the
 * dependent's list.
 *
 * Computing an impact list is more involved because the dependencies in the
 * repository are unidirectional; it requires determining the causes of all
 * offline services.  For each unsatisfied dependency of an offline service,
 * a svcptr to the dependent is added to the dependency's impact_dependents
 * list (see add_causes()).  determine_impact() uses the lists to build an
 * impact list.  The direct dependency is used so that a path from the
 * affected service to the causal service can be constructed (see
 * print_dependency_reasons()).
 *
 * Because we always need at least impact counts, we always run
 * determine_causes() on all services.
 *
 * If no arguments are given, we must select the services which are causing
 * other services to be offline.  We do so by adding services which are not
 * running for any reason other than another service to the g_causes list in
 * determine_causes().
 *
 * Since all services must be examined, and their states may be consulted
 * a lot, it is important that we only read volatile data (like states) from
 * the repository once.  add_instance() reads data for an instance from the
 * repository into an inst_t and puts it into the "services" cache, which is
 * organized as a hash table of svc_t's, each of which has a list of inst_t's.
 */

#include "svcs.h"

#include <sys/stat.h>
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <libintl.h>
#include <libuutil.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>


#define	DC_DISABLED	"SMF-8000-05"
#define	DC_TEMPDISABLED	"SMF-8000-1S"
#define	DC_RSTRINVALID	"SMF-8000-2A"
#define	DC_RSTRABSENT	"SMF-8000-3P"
#define	DC_UNINIT	"SMF-8000-4D"
#define	DC_RSTRDEAD	"SMF-8000-5H"
#define	DC_ADMINMAINT	"SMF-8000-63"
#define	DC_SVCREQMAINT	"SMF-8000-R4"
#define	DC_REPTFAIL	"SMF-8000-7Y"
#define	DC_METHFAIL	"SMF-8000-8Q"
#define	DC_NONE		"SMF-8000-9C"
#define	DC_UNKNOWN	"SMF-8000-AR"
#define	DC_STARTING	"SMF-8000-C4"
#define	DC_ADMINDEGR	"SMF-8000-DX"
#define	DC_DEPABSENT	"SMF-8000-E2"
#define	DC_DEPRUNNING	"SMF-8000-FJ"
#define	DC_DEPOTHER	"SMF-8000-GE"
#define	DC_DEPCYCLE	"SMF-8000-HP"
#define	DC_INVALIDDEP	"SMF-8000-JA"
#define	DC_STARTFAIL	"SMF-8000-KS"
#define	DC_TOOQUICKLY	"SMF-8000-L5"
#define	DC_INVALIDSTATE	"SMF-8000-N3"
#define	DC_TRANSITION	"SMF-8000-PH"

#define	DEFAULT_MAN_PATH	"/usr/share/man"

#define	AUX_STATE_INVALID	"invalid_aux_state"

#define	uu_list_append(lst, e)	uu_list_insert_before(lst, NULL, e)

#define	bad_error(func, err)						\
	uu_panic("%s:%d: %s() failed with unknown error %d.\n",		\
	    __FILE__, __LINE__, func, err);

typedef struct {
	const char *svcname;
	const char *instname;

	/* restarter pg properties */
	char state[MAX_SCF_STATE_STRING_SZ];
	char next_state[MAX_SCF_STATE_STRING_SZ];
	struct timeval stime;
	const char *aux_state;
	const char *aux_fmri;
	int64_t start_method_waitstatus;

	uint8_t enabled;
	int temporary;
	const char *restarter;
	uu_list_t *dependencies;	/* list of dependency_group's */

	int active;			/* In use?  (cycle detection) */
	int restarter_bad;
	const char *summary;
	uu_list_t *baddeps;		/* list of dependency's */
	uu_list_t *causes;		/* list of svcptrs */
	uu_list_t *impact_dependents;	/* list of svcptrs */
	uu_list_t *impact;		/* list of svcptrs */

	uu_list_node_t node;
} inst_t;

typedef struct service {
	const char *svcname;
	uu_list_t *instances;
	struct service *next;
} svc_t;

struct svcptr {
	inst_t *svcp;
	inst_t *next_hop;
	uu_list_node_t node;
};

struct dependency_group {
	enum { DGG_REQALL, DGG_REQANY, DGG_OPTALL, DGG_EXCALL } grouping;
	const char *type;
	uu_list_t *entities;		/* List of struct dependency's */
	uu_list_node_t node;
};

struct dependency {
	const char *fmri;
	uu_list_node_t node;
};

/* Hash table of service names -> svc_t's */
#define	SVC_HASH_NBUCKETS	256
#define	SVC_HASH_MASK		(SVC_HASH_NBUCKETS - 1)

static svc_t **services;

static uu_list_pool_t *insts, *svcptrs, *depgroups, *deps;
static uu_list_t *g_causes;		/* list of svcptrs */

static scf_scope_t *g_local_scope;
static scf_service_t *g_svc;
static scf_instance_t *g_inst;
static scf_snapshot_t *g_snap;
static scf_propertygroup_t *g_pg;
static scf_property_t *g_prop;
static scf_value_t *g_val;
static scf_iter_t *g_iter, *g_viter;
static char *g_fmri, *g_value;
static size_t g_fmri_sz, g_value_sz;
static const char *g_msgbase = "http://illumos.org/msg/";

static char *emsg_nomem;
static char *emsg_invalid_dep;

extern scf_handle_t *h;
extern char *g_zonename;

/* ARGSUSED */
static int
svcptr_compare(struct svcptr *a, struct svcptr *b, void *data)
{
	return (b->svcp - a->svcp);
}

static uint32_t
hash_name(const char *name)
{
	uint32_t h = 0, g;
	const char *p;

	for (p = name; *p != '\0'; ++p) {
		h = (h << 4) + *p;
		if ((g = (h & 0xf0000000)) != 0) {
			h ^= (g >> 24);
			h ^= g;
		}
	}

	return (h);
}

static void
x_init(void)
{
	emsg_nomem = gettext("Out of memory.\n");
	emsg_invalid_dep =
	    gettext("svc:/%s:%s has invalid dependency \"%s\".\n");

	services = calloc(SVC_HASH_NBUCKETS, sizeof (*services));
	if (services == NULL)
		uu_die(emsg_nomem);

	insts = uu_list_pool_create("insts", sizeof (inst_t),
	    offsetof(inst_t, node), NULL, UU_LIST_POOL_DEBUG);
	svcptrs = uu_list_pool_create("svcptrs", sizeof (struct svcptr),
	    offsetof(struct svcptr, node), (uu_compare_fn_t *)svcptr_compare,
	    UU_LIST_POOL_DEBUG);
	depgroups = uu_list_pool_create("depgroups",
	    sizeof (struct dependency_group),
	    offsetof(struct dependency_group, node), NULL, UU_LIST_POOL_DEBUG);
	deps = uu_list_pool_create("deps", sizeof (struct dependency),
	    offsetof(struct dependency, node), NULL, UU_LIST_POOL_DEBUG);
	g_causes = uu_list_create(svcptrs, NULL, UU_LIST_DEBUG);
	if (insts == NULL || svcptrs == NULL || depgroups == NULL ||
	    deps == NULL || g_causes == NULL)
		uu_die(emsg_nomem);

	if ((g_local_scope = scf_scope_create(h)) == NULL ||
	    (g_svc = scf_service_create(h)) == NULL ||
	    (g_inst = scf_instance_create(h)) == NULL ||
	    (g_snap = scf_snapshot_create(h)) == NULL ||
	    (g_pg = scf_pg_create(h)) == NULL ||
	    (g_prop = scf_property_create(h)) == NULL ||
	    (g_val = scf_value_create(h)) == NULL ||
	    (g_iter = scf_iter_create(h)) == NULL ||
	    (g_viter = scf_iter_create(h)) == NULL)
		scfdie();

	if (scf_handle_get_scope(h, SCF_SCOPE_LOCAL, g_local_scope) != 0)
		scfdie();

	g_fmri_sz = max_scf_fmri_length + 1;
	g_fmri = safe_malloc(g_fmri_sz);

	g_value_sz = max_scf_value_length + 1;
	g_value = safe_malloc(g_value_sz);
}

/*
 * Repository loading routines.
 */

/*
 * Returns
 *   0 - success
 *   ECANCELED - inst was deleted
 *   EINVAL - inst is invalid
 */
static int
load_dependencies(inst_t *svcp, scf_instance_t *inst)
{
	scf_snapshot_t *snap;
	struct dependency_group *dg;
	struct dependency *d;
	int r;

	assert(svcp->dependencies == NULL);
	svcp->dependencies = uu_list_create(depgroups, svcp, UU_LIST_DEBUG);
	if (svcp->dependencies == NULL)
		uu_die(emsg_nomem);

	if (scf_instance_get_snapshot(inst, "running", g_snap) == 0) {
		snap = g_snap;
	} else {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();

		snap = NULL;
	}

	if (scf_iter_instance_pgs_typed_composed(g_iter, inst, snap,
	    SCF_GROUP_DEPENDENCY) != 0) {
		if (scf_error() != SCF_ERROR_DELETED)
			scfdie();
		return (ECANCELED);
	}

	for (;;) {
		r = scf_iter_next_pg(g_iter, g_pg);
		if (r == 0)
			break;
		if (r != 1) {
			if (scf_error() != SCF_ERROR_DELETED)
				scfdie();
			return (ECANCELED);
		}

		dg = safe_malloc(sizeof (*dg));
		(void) memset(dg, 0, sizeof (*dg));
		dg->entities = uu_list_create(deps, dg, UU_LIST_DEBUG);
		if (dg->entities == NULL)
			uu_die(emsg_nomem);

		if (pg_get_single_val(g_pg, SCF_PROPERTY_GROUPING,
		    SCF_TYPE_ASTRING, g_value, g_value_sz, 0) != 0)
			return (EINVAL);

		if (strcmp(g_value, "require_all") == 0)
			dg->grouping = DGG_REQALL;
		else if (strcmp(g_value, "require_any") == 0)
			dg->grouping = DGG_REQANY;
		else if (strcmp(g_value, "optional_all") == 0)
			dg->grouping = DGG_OPTALL;
		else if (strcmp(g_value, "exclude_all") == 0)
			dg->grouping = DGG_EXCALL;
		else {
			(void) fprintf(stderr, gettext("svc:/%s:%s has "
			    "dependency with unknown type \"%s\".\n"),
			    svcp->svcname, svcp->instname, g_value);
			return (EINVAL);
		}

		if (pg_get_single_val(g_pg, SCF_PROPERTY_TYPE, SCF_TYPE_ASTRING,
		    g_value, g_value_sz, 0) != 0)
			return (EINVAL);
		dg->type = safe_strdup(g_value);

		if (scf_pg_get_property(g_pg, SCF_PROPERTY_ENTITIES, g_prop) !=
		    0) {
			switch (scf_error()) {
			case SCF_ERROR_NOT_FOUND:
				(void) fprintf(stderr, gettext("svc:/%s:%s has "
				    "dependency without an entities "
				    "property.\n"), svcp->svcname,
				    svcp->instname);
				return (EINVAL);

			case SCF_ERROR_DELETED:
				return (ECANCELED);

			default:
				scfdie();
			}
		}

		if (scf_iter_property_values(g_viter, g_prop) != 0) {
			if (scf_error() != SCF_ERROR_DELETED)
				scfdie();
			return (ECANCELED);
		}

		for (;;) {
			r = scf_iter_next_value(g_viter, g_val);
			if (r == 0)
				break;
			if (r != 1) {
				if (scf_error() != SCF_ERROR_DELETED)
					scfdie();
				return (ECANCELED);
			}

			d = safe_malloc(sizeof (*d));
			d->fmri = safe_malloc(max_scf_fmri_length + 1);

			if (scf_value_get_astring(g_val, (char *)d->fmri,
			    max_scf_fmri_length + 1) < 0)
				scfdie();

			uu_list_node_init(d, &d->node, deps);
			(void) uu_list_append(dg->entities, d);
		}

		uu_list_node_init(dg, &dg->node, depgroups);
		r = uu_list_append(svcp->dependencies, dg);
		assert(r == 0);
	}

	return (0);
}

static void
add_instance(const char *svcname, const char *instname, scf_instance_t *inst)
{
	inst_t *instp;
	svc_t *svcp;
	int have_enabled = 0;
	uint8_t i;
	uint32_t h;
	int r;

	h = hash_name(svcname) & SVC_HASH_MASK;
	for (svcp = services[h]; svcp != NULL; svcp = svcp->next) {
		if (strcmp(svcp->svcname, svcname) == 0)
			break;
	}

	if (svcp == NULL) {
		svcp = safe_malloc(sizeof (*svcp));
		svcp->svcname = safe_strdup(svcname);
		svcp->instances = uu_list_create(insts, svcp, UU_LIST_DEBUG);
		if (svcp->instances == NULL)
			uu_die(emsg_nomem);
		svcp->next = services[h];
		services[h] = svcp;
	}

	instp = safe_malloc(sizeof (*instp));
	(void) memset(instp, 0, sizeof (*instp));
	instp->svcname = svcp->svcname;
	instp->instname = safe_strdup(instname);
	instp->impact_dependents =
	    uu_list_create(svcptrs, instp, UU_LIST_DEBUG);
	if (instp->impact_dependents == NULL)
		uu_die(emsg_nomem);

	if (scf_instance_get_pg(inst, SCF_PG_RESTARTER, g_pg) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_DELETED:
			return;

		case SCF_ERROR_NOT_FOUND:
			(void) fprintf(stderr, gettext("svc:/%s:%s has no "
			    "\"%s\" property group; ignoring.\n"),
			    instp->svcname, instp->instname, SCF_PG_RESTARTER);
			return;

		default:
			scfdie();
		}
	}

	if (pg_get_single_val(g_pg, SCF_PROPERTY_STATE, SCF_TYPE_ASTRING,
	    (void *)instp->state, sizeof (instp->state), 0) != 0)
		return;

	if (pg_get_single_val(g_pg, SCF_PROPERTY_NEXT_STATE, SCF_TYPE_ASTRING,
	    (void *)instp->next_state, sizeof (instp->next_state), 0) != 0)
		return;

	if (pg_get_single_val(g_pg, SCF_PROPERTY_STATE_TIMESTAMP,
	    SCF_TYPE_TIME, &instp->stime, 0, 0) != 0)
		return;

	/* restarter may not set aux_state, allow to continue in that case */
	if (pg_get_single_val(g_pg, SCF_PROPERTY_AUX_STATE, SCF_TYPE_ASTRING,
	    g_fmri, g_fmri_sz, 0) == 0)
		instp->aux_state = safe_strdup(g_fmri);
	else
		instp->aux_state = safe_strdup(AUX_STATE_INVALID);

	(void) pg_get_single_val(g_pg, SCF_PROPERTY_START_METHOD_WAITSTATUS,
	    SCF_TYPE_INTEGER, &instp->start_method_waitstatus, 0, 0);

	/* Get the optional auxiliary_fmri */
	if (pg_get_single_val(g_pg, SCF_PROPERTY_AUX_FMRI, SCF_TYPE_ASTRING,
	    g_fmri, g_fmri_sz, 0) == 0)
		instp->aux_fmri = safe_strdup(g_fmri);

	if (scf_instance_get_pg(inst, SCF_PG_GENERAL_OVR, g_pg) == 0) {
		if (pg_get_single_val(g_pg, SCF_PROPERTY_ENABLED,
		    SCF_TYPE_BOOLEAN, &instp->enabled, 0, 0) == 0)
			have_enabled = 1;
	} else {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
			break;

		case SCF_ERROR_DELETED:
			return;

		default:
			scfdie();
		}
	}

	if (scf_instance_get_pg_composed(inst, NULL, SCF_PG_GENERAL, g_pg) !=
	    0) {
		switch (scf_error()) {
		case SCF_ERROR_DELETED:
		case SCF_ERROR_NOT_FOUND:
			return;

		default:
			scfdie();
		}
	}

	if (pg_get_single_val(g_pg, SCF_PROPERTY_ENABLED, SCF_TYPE_BOOLEAN,
	    &i, 0, 0) != 0)
		return;
	if (!have_enabled) {
		instp->enabled = i;
		instp->temporary = 0;
	} else {
		instp->temporary = (instp->enabled != i);
	}

	if (pg_get_single_val(g_pg, SCF_PROPERTY_RESTARTER, SCF_TYPE_ASTRING,
	    g_fmri, g_fmri_sz, 0) == 0)
		instp->restarter = safe_strdup(g_fmri);
	else
		instp->restarter = SCF_SERVICE_STARTD;

	if (strcmp(instp->state, SCF_STATE_STRING_OFFLINE) == 0 &&
	    load_dependencies(instp, inst) != 0)
		return;

	uu_list_node_init(instp, &instp->node, insts);
	r = uu_list_append(svcp->instances, instp);
	assert(r == 0);
}

static void
load_services(void)
{
	scf_iter_t *siter, *iiter;
	int r;
	char *svcname, *instname;

	if ((siter = scf_iter_create(h)) == NULL ||
	    (iiter = scf_iter_create(h)) == NULL)
		scfdie();

	svcname = safe_malloc(max_scf_name_length + 1);
	instname = safe_malloc(max_scf_name_length + 1);

	if (scf_iter_scope_services(siter, g_local_scope) != 0)
		scfdie();

	for (;;) {
		r = scf_iter_next_service(siter, g_svc);
		if (r == 0)
			break;
		if (r != 1)
			scfdie();

		if (scf_service_get_name(g_svc, svcname,
		    max_scf_name_length + 1) < 0) {
			if (scf_error() != SCF_ERROR_DELETED)
				scfdie();
			continue;
		}

		if (scf_iter_service_instances(iiter, g_svc) != 0) {
			if (scf_error() != SCF_ERROR_DELETED)
				scfdie();
			continue;
		}

		for (;;) {
			r = scf_iter_next_instance(iiter, g_inst);
			if (r == 0)
				break;
			if (r != 1) {
				if (scf_error() != SCF_ERROR_DELETED)
					scfdie();
				break;
			}

			if (scf_instance_get_name(g_inst, instname,
			    max_scf_name_length + 1) < 0) {
				if (scf_error() != SCF_ERROR_DELETED)
					scfdie();
				continue;
			}

			add_instance(svcname, instname, g_inst);
		}
	}

	free(svcname);
	free(instname);
	scf_iter_destroy(siter);
	scf_iter_destroy(iiter);
}

/*
 * Dependency analysis routines.
 */

static void
add_svcptr(uu_list_t *lst, inst_t *svcp)
{
	struct svcptr *spp;
	uu_list_index_t idx;
	int r;

	spp = safe_malloc(sizeof (*spp));
	spp->svcp = svcp;
	spp->next_hop = NULL;

	if (uu_list_find(lst, spp, NULL, &idx) != NULL) {
		free(spp);
		return;
	}

	uu_list_node_init(spp, &spp->node, svcptrs);
	r = uu_list_append(lst, spp);
	assert(r == 0);
}

static int determine_causes(inst_t *, void *);

/*
 * Determine the causes of src and add them to the causes list of dst.
 * Returns ELOOP if src is active, and 0 otherwise.
 */
static int
add_causes(inst_t *dst, inst_t *src)
{
	struct svcptr *spp, *copy;
	uu_list_index_t idx;

	if (determine_causes(src, (void *)1) != UU_WALK_NEXT) {
		/* Dependency cycle. */
		(void) fprintf(stderr, "  svc:/%s:%s\n", dst->svcname,
		    dst->instname);
		return (ELOOP);
	}

	add_svcptr(src->impact_dependents, dst);

	for (spp = uu_list_first(src->causes);
	    spp != NULL;
	    spp = uu_list_next(src->causes, spp)) {
		if (uu_list_find(dst->causes, spp, NULL, &idx) != NULL)
			continue;

		copy = safe_malloc(sizeof (*copy));
		copy->svcp = spp->svcp;
		copy->next_hop = src;
		uu_list_node_init(copy, &copy->node, svcptrs);
		uu_list_insert(dst->causes, copy, idx);

		add_svcptr(g_causes, spp->svcp);
	}

	return (0);
}

static int
inst_running(inst_t *ip)
{
	return (strcmp(ip->state, SCF_STATE_STRING_ONLINE) == 0 ||
	    strcmp(ip->state, SCF_STATE_STRING_DEGRADED) == 0);
}

static int
inst_running_or_maint(inst_t *ip)
{
	return (inst_running(ip) ||
	    strcmp(ip->state, SCF_STATE_STRING_MAINT) == 0);
}

static svc_t *
get_svc(const char *sn)
{
	uint32_t h;
	svc_t *svcp;

	h = hash_name(sn) & SVC_HASH_MASK;

	for (svcp = services[h]; svcp != NULL; svcp = svcp->next) {
		if (strcmp(svcp->svcname, sn) == 0)
			break;
	}

	return (svcp);
}

/* ARGSUSED */
static inst_t *
get_inst(svc_t *svcp, const char *in)
{
	inst_t *instp;

	for (instp = uu_list_first(svcp->instances);
	    instp != NULL;
	    instp = uu_list_next(svcp->instances, instp)) {
		if (strcmp(instp->instname, in) == 0)
			return (instp);
	}

	return (NULL);
}

static int
get_fmri(const char *fmri, svc_t **spp, inst_t **ipp)
{
	const char *sn, *in;
	svc_t *sp;
	inst_t *ip;

	if (strlcpy(g_fmri, fmri, g_fmri_sz) >= g_fmri_sz)
		return (EINVAL);

	if (scf_parse_svc_fmri(g_fmri, NULL, &sn, &in, NULL, NULL) != 0)
		return (EINVAL);

	if (sn == NULL)
		return (EINVAL);

	sp = get_svc(sn);
	if (sp == NULL)
		return (ENOENT);

	if (in != NULL) {
		ip = get_inst(sp, in);
		if (ip == NULL)
			return (ENOENT);
	}

	if (spp != NULL)
		*spp = sp;
	if (ipp != NULL)
		*ipp = ((in == NULL) ? NULL : ip);

	return (0);
}

static int
process_reqall(inst_t *svcp, struct dependency_group *dg)
{
	uu_list_walk_t *walk;
	struct dependency *d;
	int r, svcrunning;
	svc_t *sp;
	inst_t *ip;

	walk = uu_list_walk_start(dg->entities, UU_WALK_ROBUST);
	if (walk == NULL)
		uu_die(emsg_nomem);

	while ((d = uu_list_walk_next(walk)) != NULL) {
		r = get_fmri(d->fmri, &sp, &ip);
		switch (r) {
		case EINVAL:
			/* LINTED */
			(void) fprintf(stderr, emsg_invalid_dep, svcp->svcname,
			    svcp->instname, d->fmri);
			continue;

		case ENOENT:
			uu_list_remove(dg->entities, d);
			r = uu_list_append(svcp->baddeps, d);
			assert(r == 0);
			continue;

		case 0:
			break;

		default:
			bad_error("get_fmri", r);
		}

		if (ip != NULL) {
			if (inst_running(ip))
				continue;
			r = add_causes(svcp, ip);
			if (r != 0) {
				assert(r == ELOOP);
				return (r);
			}
			continue;
		}

		svcrunning = 0;

		for (ip = uu_list_first(sp->instances);
		    ip != NULL;
		    ip = uu_list_next(sp->instances, ip)) {
			if (inst_running(ip))
				svcrunning = 1;
		}

		if (!svcrunning) {
			for (ip = uu_list_first(sp->instances);
			    ip != NULL;
			    ip = uu_list_next(sp->instances, ip)) {
				r = add_causes(svcp, ip);
				if (r != 0) {
					assert(r == ELOOP);
					uu_list_walk_end(walk);
					return (r);
				}
			}
		}
	}

	uu_list_walk_end(walk);
	return (0);
}

static int
process_reqany(inst_t *svcp, struct dependency_group *dg)
{
	svc_t *sp;
	inst_t *ip;
	struct dependency *d;
	int r;
	uu_list_walk_t *walk;

	for (d = uu_list_first(dg->entities);
	    d != NULL;
	    d = uu_list_next(dg->entities, d)) {
		r = get_fmri(d->fmri, &sp, &ip);
		switch (r) {
		case 0:
			break;

		case EINVAL:
			/* LINTED */
			(void) fprintf(stderr, emsg_invalid_dep, svcp->svcname,
			    svcp->instname, d->fmri);
			continue;

		case ENOENT:
			continue;

		default:
			bad_error("eval_svc_dep", r);
		}

		if (ip != NULL) {
			if (inst_running(ip))
				return (0);
			continue;
		}

		for (ip = uu_list_first(sp->instances);
		    ip != NULL;
		    ip = uu_list_next(sp->instances, ip)) {
			if (inst_running(ip))
				return (0);
		}
	}

	/*
	 * The dependency group is not satisfied.  Add all unsatisfied members
	 * to the cause list.
	 */

	walk = uu_list_walk_start(dg->entities, UU_WALK_ROBUST);
	if (walk == NULL)
		uu_die(emsg_nomem);

	while ((d = uu_list_walk_next(walk)) != NULL) {
		r = get_fmri(d->fmri, &sp, &ip);
		switch (r) {
		case 0:
			break;

		case ENOENT:
			uu_list_remove(dg->entities, d);
			r = uu_list_append(svcp->baddeps, d);
			assert(r == 0);
			continue;

		case EINVAL:
			/* Should have caught above. */
		default:
			bad_error("eval_svc_dep", r);
		}

		if (ip != NULL) {
			if (inst_running(ip))
				continue;
			r = add_causes(svcp, ip);
			if (r != 0) {
				assert(r == ELOOP);
				return (r);
			}
			continue;
		}

		for (ip = uu_list_first(sp->instances);
		    ip != NULL;
		    ip = uu_list_next(sp->instances, ip)) {
			if (inst_running(ip))
				continue;
			r = add_causes(svcp, ip);
			if (r != 0) {
				assert(r == ELOOP);
				return (r);
			}
		}
	}

	return (0);
}

static int
process_optall(inst_t *svcp, struct dependency_group *dg)
{
	uu_list_walk_t *walk;
	struct dependency *d;
	int r;
	inst_t *ip;
	svc_t *sp;

	walk = uu_list_walk_start(dg->entities, UU_WALK_ROBUST);
	if (walk == NULL)
		uu_die(emsg_nomem);

	while ((d = uu_list_walk_next(walk)) != NULL) {
		r = get_fmri(d->fmri, &sp, &ip);

		switch (r) {
		case 0:
			break;

		case EINVAL:
			/* LINTED */
			(void) fprintf(stderr, emsg_invalid_dep, svcp->svcname,
			    svcp->instname, d->fmri);
			continue;

		case ENOENT:
			continue;

		default:
			bad_error("get_fmri", r);
		}

		if (ip != NULL) {
			if ((ip->enabled != 0) && !inst_running_or_maint(ip)) {
				r = add_causes(svcp, ip);
				if (r != 0) {
					assert(r == ELOOP);
					uu_list_walk_end(walk);
					return (r);
				}
			}
			continue;
		}

		for (ip = uu_list_first(sp->instances);
		    ip != NULL;
		    ip = uu_list_next(sp->instances, ip)) {
			if ((ip->enabled != 0) && !inst_running_or_maint(ip)) {
				r = add_causes(svcp, ip);
				if (r != 0) {
					assert(r == ELOOP);
					uu_list_walk_end(walk);
					return (r);
				}
			}
		}
	}

	uu_list_walk_end(walk);
	return (0);
}

static int
process_excall(inst_t *svcp, struct dependency_group *dg)
{
	struct dependency *d;
	int r;
	svc_t *sp;
	inst_t *ip;

	for (d = uu_list_first(dg->entities);
	    d != NULL;
	    d = uu_list_next(dg->entities, d)) {
		r = get_fmri(d->fmri, &sp, &ip);

		switch (r) {
		case 0:
			break;

		case EINVAL:
			/* LINTED */
			(void) fprintf(stderr, emsg_invalid_dep, svcp->svcname,
			    svcp->instname, d->fmri);
			continue;

		case ENOENT:
			continue;

		default:
			bad_error("eval_svc_dep", r);
		}

		if (ip != NULL) {
			if (inst_running(ip)) {
				r = add_causes(svcp, ip);
				if (r != 0) {
					assert(r == ELOOP);
					return (r);
				}
			}
			continue;
		}

		for (ip = uu_list_first(sp->instances);
		    ip != NULL;
		    ip = uu_list_next(sp->instances, ip)) {
			if (inst_running(ip)) {
				r = add_causes(svcp, ip);
				if (r != 0) {
					assert(r == ELOOP);
					return (r);
				}
			}
		}
	}

	return (0);
}

static int
process_svc_dg(inst_t *svcp, struct dependency_group *dg)
{
	switch (dg->grouping) {
	case DGG_REQALL:
		return (process_reqall(svcp, dg));

	case DGG_REQANY:
		return (process_reqany(svcp, dg));

	case DGG_OPTALL:
		return (process_optall(svcp, dg));

	case DGG_EXCALL:
		return (process_excall(svcp, dg));

	default:
#ifndef NDEBUG
		(void) fprintf(stderr,
		    "%s:%d: Unknown dependency grouping %d.\n", __FILE__,
		    __LINE__, dg->grouping);
#endif
		abort();
		/* NOTREACHED */
	}
}

/*
 * Returns
 *   EINVAL - fmri is not a valid FMRI
 *   0 - the file indicated by fmri is missing
 *   1 - the file indicated by fmri is present
 */
static int
eval_file_dep(const char *fmri)
{
	const char *path;
	struct stat st;

	if (strncmp(fmri, "file:", sizeof ("file:") - 1) != 0)
		return (EINVAL);

	path = fmri + (sizeof ("file:") - 1);

	if (path[0] != '/')
		return (EINVAL);

	if (path[1] == '/') {
		path += 2;
		if (strncmp(path, "localhost/", sizeof ("localhost/") - 1) == 0)
			path += sizeof ("localhost") - 1;
		else if (path[0] != '/')
			return (EINVAL);
	}

	return (stat(path, &st) == 0 ? 1 : 0);
}

static void
process_file_dg(inst_t *svcp, struct dependency_group *dg)
{
	uu_list_walk_t *walk;
	struct dependency *d, **deps;
	int r, i = 0, any_satisfied = 0;

	if (dg->grouping == DGG_REQANY) {
		deps = calloc(uu_list_numnodes(dg->entities), sizeof (*deps));
		if (deps == NULL)
			uu_die(emsg_nomem);
	}

	walk = uu_list_walk_start(dg->entities, UU_WALK_ROBUST);
	if (walk == NULL)
		uu_die(emsg_nomem);

	while ((d = uu_list_walk_next(walk)) != NULL) {
		r = eval_file_dep(d->fmri);
		if (r == EINVAL) {
			/* LINTED */
			(void) fprintf(stderr, emsg_invalid_dep, svcp->svcname,
			    svcp->instname, d->fmri);
			continue;
		}

		assert(r == 0 || r == 1);

		switch (dg->grouping) {
		case DGG_REQALL:
		case DGG_OPTALL:
			if (r == 0) {
				uu_list_remove(dg->entities, d);
				r = uu_list_append(svcp->baddeps, d);
				assert(r == 0);
			}
			break;

		case DGG_REQANY:
			if (r == 1)
				any_satisfied = 1;
			else
				deps[i++] = d;
			break;

		case DGG_EXCALL:
			if (r == 1) {
				uu_list_remove(dg->entities, d);
				r = uu_list_append(svcp->baddeps, d);
				assert(r == 0);
			}
			break;

		default:
#ifndef NDEBUG
			(void) fprintf(stderr, "%s:%d: Unknown grouping %d.\n",
			    __FILE__, __LINE__, dg->grouping);
#endif
			abort();
		}
	}

	uu_list_walk_end(walk);

	if (dg->grouping != DGG_REQANY)
		return;

	if (!any_satisfied) {
		while (--i >= 0) {
			uu_list_remove(dg->entities, deps[i]);
			r = uu_list_append(svcp->baddeps, deps[i]);
			assert(r == 0);
		}
	}

	free(deps);
}

/*
 * Populate the causes list of svcp.  This function should not return with
 * causes empty.
 */
static int
determine_causes(inst_t *svcp, void *canfailp)
{
	struct dependency_group *dg;
	int r;

	if (svcp->active) {
		(void) fprintf(stderr, gettext("Dependency cycle detected:\n"
		    "  svc:/%s:%s\n"), svcp->svcname, svcp->instname);
		return ((int)canfailp != 0 ? UU_WALK_ERROR : UU_WALK_NEXT);
	}

	if (svcp->causes != NULL)
		return (UU_WALK_NEXT);

	svcp->causes = uu_list_create(svcptrs, svcp, UU_LIST_DEBUG);
	svcp->baddeps = uu_list_create(deps, svcp, UU_LIST_DEBUG);
	if (svcp->causes == NULL || svcp->baddeps == NULL)
		uu_die(emsg_nomem);

	if (inst_running(svcp) ||
	    strcmp(svcp->state, SCF_STATE_STRING_UNINIT) == 0) {
		/*
		 * If we're running, add a self-pointer in case we're
		 * excluding another service.
		 */
		add_svcptr(svcp->causes, svcp);
		return (UU_WALK_NEXT);
	}

	if (strcmp(svcp->state, SCF_STATE_STRING_MAINT) == 0) {
		add_svcptr(svcp->causes, svcp);
		add_svcptr(g_causes, svcp);
		return (UU_WALK_NEXT);
	}

	if (strcmp(svcp->state, SCF_STATE_STRING_DISABLED) == 0) {
		add_svcptr(svcp->causes, svcp);
		if (svcp->enabled != 0)
			add_svcptr(g_causes, svcp);

		return (UU_WALK_NEXT);
	}

	if (strcmp(svcp->state, SCF_STATE_STRING_OFFLINE) != 0) {
		(void) fprintf(stderr,
		    gettext("svc:/%s:%s has invalid state \"%s\".\n"),
		    svcp->svcname, svcp->instname, svcp->state);
		add_svcptr(svcp->causes, svcp);
		add_svcptr(g_causes, svcp);
		return (UU_WALK_NEXT);
	}

	if (strcmp(svcp->next_state, SCF_STATE_STRING_NONE) != 0) {
		add_svcptr(svcp->causes, svcp);
		add_svcptr(g_causes, svcp);
		return (UU_WALK_NEXT);
	}

	svcp->active = 1;

	/*
	 * Dependency analysis can add elements to our baddeps list (absent
	 * dependency, unsatisfied file dependency), or to our cause list
	 * (unsatisfied dependency).
	 */
	for (dg = uu_list_first(svcp->dependencies);
	    dg != NULL;
	    dg = uu_list_next(svcp->dependencies, dg)) {
		if (strcmp(dg->type, "path") == 0) {
			process_file_dg(svcp, dg);
		} else if (strcmp(dg->type, "service") == 0) {
			int r;

			r = process_svc_dg(svcp, dg);
			if (r != 0) {
				assert(r == ELOOP);
				svcp->active = 0;
				return ((int)canfailp != 0 ?
				    UU_WALK_ERROR : UU_WALK_NEXT);
			}
		} else {
			(void) fprintf(stderr, gettext("svc:/%s:%s has "
			    "dependency group with invalid type \"%s\".\n"),
			    svcp->svcname, svcp->instname, dg->type);
		}
	}

	if (uu_list_numnodes(svcp->causes) == 0) {
		if (uu_list_numnodes(svcp->baddeps) > 0) {
			add_svcptr(g_causes, svcp);
			add_svcptr(svcp->causes, svcp);
		} else {
			inst_t *restarter;

			r = get_fmri(svcp->restarter, NULL, &restarter);
			if (r == 0 && !inst_running(restarter)) {
				r = add_causes(svcp, restarter);
				if (r != 0) {
					assert(r == ELOOP);
					svcp->active = 0;
					return ((int)canfailp != 0 ?
					    UU_WALK_ERROR : UU_WALK_NEXT);
				}
			} else {
				svcp->restarter_bad = r;
				add_svcptr(svcp->causes, svcp);
				add_svcptr(g_causes, svcp);
			}
		}
	}

	assert(uu_list_numnodes(svcp->causes) > 0);

	svcp->active = 0;
	return (UU_WALK_NEXT);
}

static void
determine_all_causes(void)
{
	svc_t *svcp;
	int i;

	for (i = 0; i < SVC_HASH_NBUCKETS; ++i) {
		for (svcp = services[i]; svcp != NULL; svcp = svcp->next)
			(void) uu_list_walk(svcp->instances,
			    (uu_walk_fn_t *)determine_causes, 0, 0);
	}
}

/*
 * Returns
 *   0 - success
 *   ELOOP - dependency cycle detected
 */
static int
determine_impact(inst_t *ip)
{
	struct svcptr *idsp, *spp, *copy;
	uu_list_index_t idx;

	if (ip->active) {
		(void) fprintf(stderr, gettext("Dependency cycle detected:\n"
		    "  svc:/%s:%s\n"), ip->svcname, ip->instname);
		return (ELOOP);
	}

	if (ip->impact != NULL)
		return (0);

	ip->impact = uu_list_create(svcptrs, ip, UU_LIST_DEBUG);
	if (ip->impact == NULL)
		uu_die(emsg_nomem);
	ip->active = 1;

	for (idsp = uu_list_first(ip->impact_dependents);
	    idsp != NULL;
	    idsp = uu_list_next(ip->impact_dependents, idsp)) {
		if (determine_impact(idsp->svcp) != 0) {
			(void) fprintf(stderr, "  svc:/%s:%s\n",
			    ip->svcname, ip->instname);
			return (ELOOP);
		}

		add_svcptr(ip->impact, idsp->svcp);

		for (spp = uu_list_first(idsp->svcp->impact);
		    spp != NULL;
		    spp = uu_list_next(idsp->svcp->impact, spp)) {
			if (uu_list_find(ip->impact, spp, NULL, &idx) != NULL)
				continue;

			copy = safe_malloc(sizeof (*copy));
			copy->svcp = spp->svcp;
			copy->next_hop = NULL;
			uu_list_node_init(copy, &copy->node, svcptrs);
			uu_list_insert(ip->impact, copy, idx);
		}
	}

	ip->active = 0;
	return (0);
}

/*
 * Printing routines.
 */

static void
check_msgbase(void)
{
	if (scf_handle_decode_fmri(h, SCF_SERVICE_STARTD, NULL, NULL, g_inst,
	    NULL, NULL, SCF_DECODE_FMRI_EXACT) != 0) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();

		return;
	}

	if (scf_instance_get_pg_composed(g_inst, NULL, "msg", g_pg) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
		case SCF_ERROR_DELETED:
			return;

		default:
			scfdie();
		}
	}

	if (scf_pg_get_property(g_pg, "base", g_prop) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
		case SCF_ERROR_DELETED:
			return;

		default:
			scfdie();
		}
	}

	if (scf_property_get_value(g_prop, g_val) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
		case SCF_ERROR_CONSTRAINT_VIOLATED:
		case SCF_ERROR_PERMISSION_DENIED:
			g_msgbase = NULL;
			return;

		case SCF_ERROR_DELETED:
			return;

		default:
			scfdie();
		}
	}

	if (scf_value_get_astring(g_val, g_value, g_value_sz) < 0) {
		if (scf_error() != SCF_ERROR_TYPE_MISMATCH)
			scfdie();
		return;
	}

	g_msgbase = safe_strdup(g_value);
}

static void
determine_summary(inst_t *ip)
{
	if (ip->summary != NULL)
		return;

	if (inst_running(ip)) {
		ip->summary = gettext("is running.");
		return;
	}

	if (strcmp(ip->state, SCF_STATE_STRING_UNINIT) == 0) {
		ip->summary = gettext("is uninitialized.");
	} else if (strcmp(ip->state, SCF_STATE_STRING_DISABLED) == 0) {
		if (!ip->temporary)
			ip->summary = gettext("is disabled.");
		else
			ip->summary = gettext("is temporarily disabled.");
	} else if (strcmp(ip->state, SCF_STATE_STRING_OFFLINE) == 0) {
		if (uu_list_numnodes(ip->baddeps) != 0)
			ip->summary = gettext("has missing dependencies.");
		else if (strcmp(ip->next_state, SCF_STATE_STRING_ONLINE) == 0)
			ip->summary = gettext("is starting.");
		else
			ip->summary = gettext("is offline.");
	} else if (strcmp(ip->state, SCF_STATE_STRING_MAINT) == 0) {
		if (strcmp(ip->aux_state, "administrative_request") == 0) {
			ip->summary = gettext("was taken down for maintenace "
			    "by an administrator.");
		} else if (strcmp(ip->aux_state, "dependency_cycle") == 0) {
			ip->summary = gettext("completed a dependency cycle.");
		} else if (strcmp(ip->aux_state, "fault_threshold_reached") ==
		    0) {
			ip->summary = gettext("is not running because "
			    "a method failed repeatedly.");
		} else if (strcmp(ip->aux_state, "invalid_dependency") == 0) {
			ip->summary = gettext("has an invalid dependency.");
		} else if (strcmp(ip->aux_state, "invalid_restarter") == 0) {
			ip->summary = gettext("has an invalid restarter.");
		} else if (strcmp(ip->aux_state, "method_failed") == 0) {
			ip->summary = gettext("is not running because "
			    "a method failed.");
		} else if (strcmp(ip->aux_state, "none") == 0) {
			ip->summary =
			    gettext("is not running for an unknown reason.");
		} else if (strcmp(ip->aux_state, "restarting_too_quickly") ==
		    0) {
			ip->summary = gettext("was restarting too quickly.");
		} else {
			ip->summary = gettext("requires maintenance.");
		}
	} else {
		ip->summary = gettext("is in an invalid state.");
	}
}

static void
print_method_failure(const inst_t *ip, const char **dcp)
{
	char buf[50];
	int stat = ip->start_method_waitstatus;

	if (stat != 0) {
		if (WIFEXITED(stat)) {
			if (WEXITSTATUS(stat) == SMF_EXIT_ERR_CONFIG) {
				(void) strlcpy(buf, gettext(
				    "exited with $SMF_EXIT_ERR_CONFIG"),
				    sizeof (buf));
			} else if (WEXITSTATUS(stat) == SMF_EXIT_ERR_FATAL) {
				(void) strlcpy(buf, gettext(
				    "exited with $SMF_EXIT_ERR_FATAL"),
				    sizeof (buf));
			} else {
				(void) snprintf(buf, sizeof (buf),
				    gettext("exited with status %d"),
				    WEXITSTATUS(stat));
			}
		} else if (WIFSIGNALED(stat)) {
			if (WCOREDUMP(stat)) {
				if (strsignal(WTERMSIG(stat)) != NULL)
					(void) snprintf(buf, sizeof (buf),
					    gettext("dumped core on %s (%d)"),
					    strsignal(WTERMSIG(stat)),
					    WTERMSIG(stat));
				else
					(void) snprintf(buf, sizeof (buf),
					    gettext("dumped core signal %d"),
					    WTERMSIG(stat));
			} else {
				if (strsignal(WTERMSIG(stat)) != NULL) {
					(void) snprintf(buf, sizeof (buf),
					    gettext("died on %s (%d)"),
					    strsignal(WTERMSIG(stat)),
					    WTERMSIG(stat));
				} else {
					(void) snprintf(buf, sizeof (buf),
					    gettext("died on signal %d"),
					    WTERMSIG(stat));
				}
			}
		} else {
			goto fail;
		}

		if (strcmp(ip->aux_state, "fault_threshold_reached") != 0)
			(void) printf(gettext("Reason: Start method %s.\n"),
			    buf);
		else
			(void) printf(gettext("Reason: "
			    "Start method failed repeatedly, last %s.\n"), buf);
		*dcp = DC_STARTFAIL;
	} else {
fail:
		if (strcmp(ip->aux_state, "fault_threshold_reached") == 0)
			(void) puts(gettext(
			    "Reason: Method failed repeatedly."));
		else
			(void) puts(gettext("Reason: Method failed."));
		*dcp = DC_METHFAIL;
	}
}

static void
print_dependency_reasons(const inst_t *svcp, int verbose)
{
	struct dependency *d;
	struct svcptr *spp;
	const char *dc;

	/*
	 * If we couldn't determine why the service is offline, then baddeps
	 * will be empty and causes will have a pointer to self.
	 */
	if (uu_list_numnodes(svcp->baddeps) == 0 &&
	    uu_list_numnodes(svcp->causes) == 1) {
		spp = uu_list_first(svcp->causes);
		if (spp->svcp == svcp) {
			switch (svcp->restarter_bad) {
			case 0:
				(void) puts(gettext("Reason: Unknown."));
				dc = DC_UNKNOWN;
				break;

			case EINVAL:
				(void) printf(gettext("Reason: "
				    "Restarter \"%s\" is invalid.\n"),
				    svcp->restarter);
				dc = DC_RSTRINVALID;
				break;

			case ENOENT:
				(void) printf(gettext("Reason: "
				    "Restarter \"%s\" does not exist.\n"),
				    svcp->restarter);
				dc = DC_RSTRABSENT;
				break;

			default:
#ifndef NDEBUG
				(void) fprintf(stderr, "%s:%d: Bad "
				    "restarter_bad value %d.  Aborting.\n",
				    __FILE__, __LINE__, svcp->restarter_bad);
#endif
				abort();
			}

			if (g_msgbase)
				(void) printf(gettext("   See: %s%s\n"),
				    g_msgbase, dc);
			return;
		}
	}

	for (d = uu_list_first(svcp->baddeps);
	    d != NULL;
	    d = uu_list_next(svcp->baddeps, d)) {
		(void) printf(gettext("Reason: Dependency %s is absent.\n"),
		    d->fmri);
		if (g_msgbase)
			(void) printf(gettext("   See: %s%s\n"), g_msgbase,
			    DC_DEPABSENT);
	}

	for (spp = uu_list_first(svcp->causes);
	    spp != NULL && spp->svcp != svcp;
	    spp = uu_list_next(svcp->causes, spp)) {
		determine_summary(spp->svcp);

		if (inst_running(spp->svcp)) {
			(void) printf(gettext("Reason: "
			    "Service svc:/%s:%s is running.\n"),
			    spp->svcp->svcname, spp->svcp->instname);
			dc = DC_DEPRUNNING;
		} else {
			if (snprintf(NULL, 0,
			    gettext("Reason: Service svc:/%s:%s %s"),
			    spp->svcp->svcname, spp->svcp->instname,
			    spp->svcp->summary) <= 80) {
				(void) printf(gettext(
				    "Reason: Service svc:/%s:%s %s\n"),
				    spp->svcp->svcname, spp->svcp->instname,
				    spp->svcp->summary);
			} else {
				(void) printf(gettext(
				    "Reason: Service svc:/%s:%s\n"
				    "        %s\n"), spp->svcp->svcname,
				    spp->svcp->instname, spp->svcp->summary);
			}

			dc = DC_DEPOTHER;
		}

		if (g_msgbase != NULL)
			(void) printf(gettext("   See: %s%s\n"), g_msgbase, dc);

		if (verbose) {
			inst_t *pp;
			int indent;

			(void) printf(gettext("  Path: svc:/%s:%s\n"),
			    svcp->svcname, svcp->instname);

			indent = 1;
			for (pp = spp->next_hop; ; ) {
				struct svcptr *tmp;

				(void) printf(gettext("%6s  %*ssvc:/%s:%s\n"),
				    "", indent++ * 2, "", pp->svcname,
				    pp->instname);

				if (pp == spp->svcp)
					break;

				/* set pp to next_hop of cause with same svcp */
				tmp = uu_list_find(pp->causes, spp, NULL, NULL);
				pp = tmp->next_hop;
			}
		}
	}
}

static void
print_logs(scf_instance_t *inst)
{
	if (scf_instance_get_pg(inst, SCF_PG_RESTARTER, g_pg) != 0)
		return;

	if (pg_get_single_val(g_pg, SCF_PROPERTY_ALT_LOGFILE,
	    SCF_TYPE_ASTRING, (void *)g_value, g_value_sz, 0) == 0)
		(void) printf(gettext("   See: %s\n"), g_value);

	if (pg_get_single_val(g_pg, SCF_PROPERTY_LOGFILE,
	    SCF_TYPE_ASTRING, (void *)g_value, g_value_sz, 0) == 0)
		(void) printf(gettext("   See: %s\n"), g_value);
}

static void
print_aux_fmri_logs(const char *fmri)
{
	scf_instance_t *scf_inst = scf_instance_create(h);
	if (scf_inst == NULL)
		return;

	if (scf_handle_decode_fmri(h, fmri, NULL, NULL, scf_inst,
	    NULL, NULL, SCF_DECODE_FMRI_EXACT) == 0)
		print_logs(scf_inst);

	scf_instance_destroy(scf_inst);
}

static void
print_reasons(const inst_t *svcp, int verbose)
{
	int r;
	const char *dc = NULL;

	if (strcmp(svcp->state, SCF_STATE_STRING_ONLINE) == 0)
		return;

	if (strcmp(svcp->state, SCF_STATE_STRING_UNINIT) == 0) {
		inst_t *rsp;

		r = get_fmri(svcp->restarter, NULL, &rsp);
		switch (r) {
		case 0:
			if (rsp != NULL)
				break;
			/* FALLTHROUGH */

		case EINVAL:
			(void) printf(gettext("Reason: "
			    "Restarter \"%s\" is invalid.\n"), svcp->restarter);
			dc = DC_RSTRINVALID;
			goto diagcode;

		case ENOENT:
			(void) printf(gettext("Reason: "
			    "Restarter \"%s\" does not exist.\n"),
			    svcp->restarter);
			dc = DC_RSTRABSENT;
			goto diagcode;

		default:
			bad_error("get_fmri", r);
		}

		if (inst_running(rsp)) {
			(void) printf(gettext("Reason: Restarter %s "
			    "has not initialized service state.\n"),
			    svcp->restarter);
			dc = DC_UNINIT;
		} else {
			(void) printf(gettext(
			    "Reason: Restarter %s is not running.\n"),
			    svcp->restarter);
			dc = DC_RSTRDEAD;
		}

	} else if (strcmp(svcp->state, SCF_STATE_STRING_DISABLED) == 0) {
		if (!svcp->temporary) {
			(void) puts(gettext(
			    "Reason: Disabled by an administrator."));
			dc = DC_DISABLED;
		} else {
			(void) puts(gettext("Reason: "
			    "Temporarily disabled by an administrator."));
			dc = DC_TEMPDISABLED;
		}

	} else if (strcmp(svcp->state, SCF_STATE_STRING_MAINT) == 0) {
		if (strcmp(svcp->aux_state, "administrative_request") == 0) {
			(void) puts(gettext("Reason: "
			    "Maintenance requested by an administrator."));
			dc = DC_ADMINMAINT;
		} else if (strcmp(svcp->aux_state, "dependency_cycle") == 0) {
			(void) puts(gettext(
			    "Reason: Completes a dependency cycle."));
			dc = DC_DEPCYCLE;
		} else if (strcmp(svcp->aux_state, "fault_threshold_reached") ==
		    0) {
			print_method_failure(svcp, &dc);
		} else if (strcmp(svcp->aux_state, "service_request") == 0) {
			if (svcp->aux_fmri) {
				(void) printf(gettext("Reason: Maintenance "
				    "requested by \"%s\"\n"), svcp->aux_fmri);
				print_aux_fmri_logs(svcp->aux_fmri);
			} else {
				(void) puts(gettext("Reason: Maintenance "
				    "requested by another service."));
			}
			dc = DC_SVCREQMAINT;
		} else if (strcmp(svcp->aux_state, "invalid_dependency") == 0) {
			(void) puts(gettext("Reason: Has invalid dependency."));
			dc = DC_INVALIDDEP;
		} else if (strcmp(svcp->aux_state, "invalid_restarter") == 0) {
			(void) printf(gettext("Reason: Restarter \"%s\" is "
			    "invalid.\n"), svcp->restarter);
			dc = DC_RSTRINVALID;
		} else if (strcmp(svcp->aux_state, "method_failed") == 0) {
			print_method_failure(svcp, &dc);
		} else if (strcmp(svcp->aux_state, "restarting_too_quickly") ==
		    0) {
			(void) puts(gettext("Reason: Restarting too quickly."));
			dc = DC_TOOQUICKLY;
		} else if (strcmp(svcp->aux_state, "none") == 0) {
			(void) printf(gettext(
			    "Reason: Restarter %s gave no explanation.\n"),
			    svcp->restarter);
			dc = DC_NONE;
		} else {
			(void) puts(gettext("Reason: Unknown."));
			dc = DC_UNKNOWN;
		}

	} else if (strcmp(svcp->state, SCF_STATE_STRING_OFFLINE) == 0) {
		if (strcmp(svcp->next_state, SCF_STATE_STRING_ONLINE) == 0) {
			(void) puts(gettext(
			    "Reason: Start method is running."));
			dc = DC_STARTING;
		} else if (strcmp(svcp->next_state, SCF_STATE_STRING_NONE) ==
		    0) {
			print_dependency_reasons(svcp, verbose);
			/* Function prints diagcodes. */
			return;
		} else {
			(void) printf(gettext(
			    "Reason: Transitioning to state %s.\n"),
			    svcp->next_state);
			dc = DC_TRANSITION;
		}

	} else if (strcmp(svcp->state, SCF_STATE_STRING_DEGRADED) == 0) {
		(void) puts(gettext("Reason: Degraded by an administrator."));
		dc = DC_ADMINDEGR;

	} else {
		(void) printf(gettext("Reason: Not in valid state (%s).\n"),
		    svcp->state);
		dc = DC_INVALIDSTATE;
	}

diagcode:
	if (g_msgbase != NULL)
		(void) printf(gettext("   See: %s%s\n"), g_msgbase, dc);
}

static void
print_manpage(int verbose)
{
	static char *title = NULL;
	static char *section = NULL;

	if (title == NULL) {
		title = safe_malloc(g_value_sz);
		section = safe_malloc(g_value_sz);
	}

	if (pg_get_single_val(g_pg, SCF_PROPERTY_TM_TITLE, SCF_TYPE_ASTRING,
	    (void *)title, g_value_sz, 0) != 0)
		return;

	if (pg_get_single_val(g_pg, SCF_PROPERTY_TM_SECTION,
	    SCF_TYPE_ASTRING, (void *)section, g_value_sz, 0) != 0)
		return;

	if (!verbose) {
		(void) printf(gettext("   See: %s(%s)\n"), title, section);
		return;
	}

	if (pg_get_single_val(g_pg, SCF_PROPERTY_TM_MANPATH, SCF_TYPE_ASTRING,
	    (void *)g_value, g_value_sz, 0) != 0)
		return;

	if (strcmp(g_value, ":default") == 0) {
		assert(sizeof (DEFAULT_MAN_PATH) < g_value_sz);
		(void) strcpy(g_value, DEFAULT_MAN_PATH);
	}

	(void) printf(gettext("   See: man -M %s -s %s %s\n"), g_value,
	    section, title);
}

static void
print_doclink()
{
	static char *uri = NULL;

	if (uri == NULL) {
		uri = safe_malloc(g_value_sz);
	}

	if (pg_get_single_val(g_pg, SCF_PROPERTY_TM_URI, SCF_TYPE_ASTRING,
	    (void *)uri, g_value_sz, 0) != 0)
		return;

	(void) printf(gettext("   See: %s\n"), uri);
}


/*
 * Returns
 *   0 - success
 *   1 - inst was deleted
 */
static int
print_docs(scf_instance_t *inst, int verbose)
{
	scf_snapshot_t *snap;
	int r;

	if (scf_instance_get_snapshot(inst, "running", g_snap) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
			break;

		case SCF_ERROR_DELETED:
			return (1);

		default:
			scfdie();
		}

		snap = NULL;
	} else {
		snap = g_snap;
	}

	if (scf_iter_instance_pgs_typed_composed(g_iter, inst, snap,
	    SCF_GROUP_TEMPLATE) != 0) {
		if (scf_error() != SCF_ERROR_DELETED)
			scfdie();

		return (1);
	}

	for (;;) {
		r = scf_iter_next_pg(g_iter, g_pg);
		if (r == 0)
			break;
		if (r != 1) {
			if (scf_error() != SCF_ERROR_DELETED)
				scfdie();

			return (1);
		}

		if (scf_pg_get_name(g_pg, g_fmri, g_fmri_sz) < 0) {
			if (scf_error() != SCF_ERROR_DELETED)
				scfdie();

			continue;
		}

		if (strncmp(g_fmri, SCF_PG_TM_MAN_PREFIX,
		    strlen(SCF_PG_TM_MAN_PREFIX)) == 0) {
			print_manpage(verbose);
			continue;
		}

		if (strncmp(g_fmri, SCF_PG_TM_DOC_PREFIX,
		    strlen(SCF_PG_TM_DOC_PREFIX)) == 0) {
			print_doclink();
			continue;
		}
	}
	return (0);
}

static int first = 1;

/*
 * Explain why the given service is in the state it's in.
 */
static void
print_service(inst_t *svcp, int verbose)
{
	struct svcptr *spp;
	time_t stime;
	char *timebuf;
	size_t tbsz;
	struct tm *tmp;
	int deleted = 0;

	if (first)
		first = 0;
	else
		(void) putchar('\n');

	(void) printf(gettext("svc:/%s:%s"), svcp->svcname, svcp->instname);

	if (scf_scope_get_service(g_local_scope, svcp->svcname, g_svc) != 0) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();
		deleted = 1;
	} else if (scf_service_get_instance(g_svc, svcp->instname, g_inst) !=
	    0) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();
		deleted = 1;
	}

	if (!deleted) {
		if (inst_get_single_val(g_inst, SCF_PG_TM_COMMON_NAME, locale,
		    SCF_TYPE_USTRING, g_value, g_value_sz, 0, 0, 1) == 0)
			/* EMPTY */;
		else if (inst_get_single_val(g_inst, SCF_PG_TM_COMMON_NAME, "C",
		    SCF_TYPE_USTRING, g_value, g_value_sz, 0, 0, 1) != 0)
			(void) strcpy(g_value, "?");

		(void) printf(gettext(" (%s)\n"), g_value);
	} else {
		(void) putchar('\n');
	}

	if (g_zonename != NULL)
		(void) printf(gettext("  Zone: %s\n"), g_zonename);

	stime = svcp->stime.tv_sec;
	tmp = localtime(&stime);

	for (tbsz = 50; ; tbsz *= 2) {
		timebuf = safe_malloc(tbsz);
		if (strftime(timebuf, tbsz, NULL, tmp) != 0)
			break;
		free(timebuf);
	}

	(void) printf(gettext(" State: %s since %s\n"), svcp->state, timebuf);

	free(timebuf);

	/* Reasons */
	print_reasons(svcp, verbose);

	if (!deleted)
		deleted = print_docs(g_inst, verbose);
	if (!deleted)
		print_logs(g_inst);

	(void) determine_impact(svcp);

	switch (uu_list_numnodes(svcp->impact)) {
	case 0:
		if (inst_running(svcp))
			(void) puts(gettext("Impact: None."));
		else
			(void) puts(gettext(
			    "Impact: This service is not running."));
		break;

	case 1:
		if (!verbose)
			(void) puts(gettext("Impact: 1 dependent service "
			    "is not running.  (Use -v for list.)"));
		else
			(void) puts(gettext(
			    "Impact: 1 dependent service is not running:"));
		break;

	default:
		if (!verbose)
			(void) printf(gettext("Impact: %d dependent services "
			    "are not running.  (Use -v for list.)\n"),
			    uu_list_numnodes(svcp->impact));
		else
			(void) printf(gettext(
			    "Impact: %d dependent services are not running:\n"),
			    uu_list_numnodes(svcp->impact));
	}

	if (verbose) {
		for (spp = uu_list_first(svcp->impact);
		    spp != NULL;
		    spp = uu_list_next(svcp->impact, spp))
			(void) printf(gettext("        svc:/%s:%s\n"),
			    spp->svcp->svcname, spp->svcp->instname);
	}
}

/*
 * Top level routine.
 */

static int
impact_compar(const void *a, const void *b)
{
	int n, m;

	n = uu_list_numnodes((*(inst_t **)a)->impact);
	m = uu_list_numnodes((*(inst_t **)b)->impact);

	return (m - n);
}

static int
print_service_cb(void *verbose, scf_walkinfo_t *wip)
{
	int r;
	inst_t *ip;

	assert(wip->pg == NULL);

	r = get_fmri(wip->fmri, NULL, &ip);
	assert(r != EINVAL);
	if (r == ENOENT)
		return (0);

	assert(r == 0);
	assert(ip != NULL);

	print_service(ip, (int)verbose);

	return (0);
}

void
explain(int verbose, int argc, char **argv)
{
	/*
	 * Initialize globals.  If we have been called before (e.g., for a
	 * different zone), this will clobber the previous globals -- keeping
	 * with the proud svcs(1) tradition of not bothering to ever clean
	 * anything up.
	 */
	x_init();

	/* Walk the graph and populate services with inst_t's */
	load_services();

	/* Populate causes for services. */
	determine_all_causes();

	if (argc > 0) {
		scf_error_t err;

		check_msgbase();

		/* Call print_service() for each operand. */

		err = scf_walk_fmri(h, argc, argv, SCF_WALK_MULTIPLE,
		    print_service_cb, (void *)verbose, &exit_status, uu_warn);
		if (err != 0) {
			uu_warn(gettext(
			    "failed to iterate over instances: %s\n"),
			    scf_strerror(err));
			exit_status = UU_EXIT_FATAL;
		}
	} else {
		struct svcptr *spp;
		int n, i;
		inst_t **ary;

		/* Sort g_causes. */

		n = uu_list_numnodes(g_causes);
		if (n == 0)
			return;

		check_msgbase();

		ary = calloc(n, sizeof (*ary));
		if (ary == NULL)
			uu_die(emsg_nomem);

		i = 0;
		for (spp = uu_list_first(g_causes);
		    spp != NULL;
		    spp = uu_list_next(g_causes, spp)) {
			(void) determine_impact(spp->svcp);
			ary[i++] = spp->svcp;
		}

		qsort(ary, n, sizeof (*ary), impact_compar);

		/* Call print_service() for each service. */

		for (i = 0; i < n; ++i)
			print_service(ary[i], verbose);
	}
}
