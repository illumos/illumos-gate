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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>
#include <errno.h>
#include <libintl.h>
#include <libuutil.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>

#include "svccfg.h"

/*
 * Internal representation manipulation routines for svccfg(1)
 */

static uu_list_pool_t	*entity_pool;
static uu_list_pool_t	*pgroup_pool;
static uu_list_pool_t	*property_pool;
static uu_list_pool_t	*value_pool;

/* ARGSUSED */
static int
entity_cmp(const void *a, const void *b, void *p)
{
	entity_t *A = (entity_t *)a;
	entity_t *B = (entity_t *)b;

	return (strcmp(A->sc_name, B->sc_name));
}

/*ARGSUSED*/
static int
pgroup_cmp(const void *a, const void *b, void *p)
{
	pgroup_t *A = (pgroup_t *)a;
	pgroup_t *B = (pgroup_t *)b;

	return (strcmp(A->sc_pgroup_name, B->sc_pgroup_name));
}

/* ARGSUSED */
static int
property_cmp(const void *a, const void *b, void *p)
{
	property_t *A = (property_t *)a;
	property_t *B = (property_t *)b;

	return (strcmp(A->sc_property_name, B->sc_property_name));
}

/* ARGSUSED */
int
value_cmp(const void *a, const void *b, void *p)
{
	const value_t *A = a;
	const value_t *B = b;

	if (A->sc_type != B->sc_type)
		return (B->sc_type - A->sc_type);

	switch (A->sc_type) {
	case SCF_TYPE_BOOLEAN:
	case SCF_TYPE_COUNT:
		return (B->sc_u.sc_count - A->sc_u.sc_count);

	case SCF_TYPE_INTEGER:
		return (B->sc_u.sc_integer - A->sc_u.sc_integer);

	default:
		return (strcmp(A->sc_u.sc_string, B->sc_u.sc_string));
	}
}

void
internal_init()
{
	if ((entity_pool = uu_list_pool_create("entities", sizeof (entity_t),
	    offsetof(entity_t, sc_node), entity_cmp, 0)) == NULL)
		uu_die(gettext("entity list pool creation failed: %s\n"),
		    uu_strerror(uu_error()));

	if ((pgroup_pool = uu_list_pool_create("property_groups",
	    sizeof (pgroup_t), offsetof(pgroup_t, sc_node), pgroup_cmp, 0)) ==
	    NULL)
		uu_die(
		    gettext("property group list pool creation failed: %s\n"),
		    uu_strerror(uu_error()));

	if ((property_pool = uu_list_pool_create("properties",
	    sizeof (property_t), offsetof(property_t, sc_node), property_cmp,
	    0)) == NULL)
		uu_die(gettext("property list pool creation failed: %s\n"),
		    uu_strerror(uu_error()));

	if ((value_pool = uu_list_pool_create("property_values",
	    sizeof (value_t), offsetof(value_t, sc_node), value_cmp, 0)) ==
	    NULL)
		uu_die(
		    gettext("property value list pool creation failed: %s\n"),
		    uu_strerror(uu_error()));
}

/*ARGSUSED*/
static int
internal_value_dump(void *v, void *pvt)
{
	value_t *val = v;

	switch (val->sc_type) {
	case SCF_TYPE_BOOLEAN:
		(void) printf("	value = %s\n",
		    val->sc_u.sc_count ? "true" : "false");
		break;
	case SCF_TYPE_COUNT:
		(void) printf("	value = %llu\n", val->sc_u.sc_count);
		break;
	case SCF_TYPE_INTEGER:
		(void) printf("	value = %lld\n", val->sc_u.sc_integer);
		break;
	case SCF_TYPE_ASTRING:
	case SCF_TYPE_FMRI:
	case SCF_TYPE_HOST:
	case SCF_TYPE_HOSTNAME:
	case SCF_TYPE_NET_ADDR_V4:
	case SCF_TYPE_NET_ADDR_V6:
	case SCF_TYPE_OPAQUE:
	case SCF_TYPE_TIME:
	case SCF_TYPE_URI:
	case SCF_TYPE_USTRING:
		(void) printf("	value = %s\n",
		    val->sc_u.sc_string ? val->sc_u.sc_string : "(nil)");
		break;
	default:
		uu_die(gettext("unknown value type (%d)\n"), val->sc_type);
		break;
	}

	return (UU_WALK_NEXT);
}

/*ARGSUSED*/
static int
internal_property_dump(void *v, void *pvt)
{
	property_t *p = v;

	(void) printf("property\n	name = %s\n", p->sc_property_name);
	(void) printf("	type = %d\n", p->sc_value_type);

	(void) uu_list_walk(p->sc_property_values, internal_value_dump,
	    NULL, UU_DEFAULT);

	return (UU_WALK_NEXT);
}

/*ARGSUSED*/
static int
internal_pgroup_dump(void *v, void *pvt)
{
	pgroup_t *pg = v;

	(void) printf("pgroup	name = %s\n", pg->sc_pgroup_name);
	(void) printf("	type = %s\n", pg->sc_pgroup_type);

	(void) uu_list_walk(pg->sc_pgroup_props, internal_property_dump,
	    NULL, UU_DEFAULT);

	return (UU_WALK_NEXT);
}

/*ARGSUSED*/
static int
internal_instance_dump(void *v, void *pvt)
{
	entity_t *i = v;

	(void) printf("instance	name = %s\n", i->sc_name);

	(void) uu_list_walk(i->sc_pgroups, internal_pgroup_dump, NULL,
	    UU_DEFAULT);

	return (UU_WALK_NEXT);
}

/*ARGSUSED*/
static int
internal_service_dump(void *v, void *pvt)
{
	entity_t *s = v;

	(void) printf("service	name = %s\n", s->sc_name);
	(void) printf("	type = %x\n", s->sc_u.sc_service.sc_service_type);
	(void) printf("	version = %u\n", s->sc_u.sc_service.sc_service_version);

	(void) uu_list_walk(s->sc_pgroups, internal_pgroup_dump, NULL,
	    UU_DEFAULT);

	(void) uu_list_walk(s->sc_u.sc_service.sc_service_instances,
	    internal_instance_dump, NULL, UU_DEFAULT);

	return (UU_WALK_NEXT);
}

void
internal_dump(bundle_t *b)
{
	(void) printf("bundle	name = %s\n", b->sc_bundle_name);
	(void) printf("	type = %x\n", b->sc_bundle_type);

	(void) uu_list_walk(b->sc_bundle_services, internal_service_dump,
	    NULL, UU_DEFAULT);
}

bundle_t *
internal_bundle_new()
{
	bundle_t	*b;

	if ((b = uu_zalloc(sizeof (bundle_t))) == NULL)
		uu_die(gettext("couldn't allocate memory"));

	b->sc_bundle_type = SVCCFG_UNKNOWN_BUNDLE;
	b->sc_bundle_services = uu_list_create(entity_pool, b, 0);

	return (b);
}

void
internal_bundle_free(bundle_t *b)
{
	void *cookie = NULL;
	entity_t *service;

	while ((service = uu_list_teardown(b->sc_bundle_services, &cookie)) !=
	    NULL)
		internal_service_free(service);

	free(b);
}

entity_t *
internal_service_new(const char *name)
{
	entity_t *s;

	if ((s = uu_zalloc(sizeof (entity_t))) == NULL)
		uu_die(gettext("couldn't allocate memory"));

	uu_list_node_init(s, &s->sc_node, entity_pool);

	s->sc_name = name;
	s->sc_fmri = uu_msprintf("svc:/%s", name);
	if (s->sc_fmri == NULL)
		uu_die(gettext("couldn't allocate memory"));

	s->sc_etype = SVCCFG_SERVICE_OBJECT;
	s->sc_pgroups = uu_list_create(pgroup_pool, s, 0);
	s->sc_dependents = uu_list_create(pgroup_pool, s, 0);

	s->sc_u.sc_service.sc_service_type = SVCCFG_UNKNOWN_SERVICE;
	s->sc_u.sc_service.sc_service_instances = uu_list_create(entity_pool, s,
	    0);

	return (s);
}

void
internal_service_free(entity_t *s)
{
	entity_t *inst;
	pgroup_t *pg;
	void *cookie;

	cookie = NULL;
	while ((pg = uu_list_teardown(s->sc_pgroups, &cookie)) != NULL)
		internal_pgroup_free(pg);

	cookie = NULL;
	while ((pg = uu_list_teardown(s->sc_dependents, &cookie)) != NULL)
		internal_pgroup_free(pg);

	cookie = NULL;
	while ((inst = uu_list_teardown(s->sc_u.sc_service.sc_service_instances,
	    &cookie)) != NULL)
		internal_instance_free(inst);

	free(s);
}

entity_t *
internal_instance_new(const char *name)
{
	entity_t *i;

	if ((i = uu_zalloc(sizeof (entity_t))) == NULL)
		uu_die(gettext("couldn't allocate memory"));

	uu_list_node_init(i, &i->sc_node, entity_pool);

	i->sc_name = name;
	/* Can't set i->sc_fmri until we're attached to a service. */
	i->sc_etype = SVCCFG_INSTANCE_OBJECT;
	i->sc_pgroups = uu_list_create(pgroup_pool, i, 0);
	i->sc_dependents = uu_list_create(pgroup_pool, i, 0);

	return (i);
}

void
internal_instance_free(entity_t *i)
{
	pgroup_t *pg;
	void *cookie = NULL;

	while ((pg = uu_list_teardown(i->sc_pgroups, &cookie)) != NULL)
		internal_pgroup_free(pg);

	cookie = NULL;
	while ((pg = uu_list_teardown(i->sc_dependents, &cookie)) != NULL)
		internal_pgroup_free(pg);

	free(i);
}

entity_t *
internal_template_new()
{
	entity_t *t;

	if ((t = uu_zalloc(sizeof (entity_t))) == NULL)
		uu_die(gettext("couldn't allocate memory"));

	uu_list_node_init(t, &t->sc_node, entity_pool);

	t->sc_etype = SVCCFG_TEMPLATE_OBJECT;
	t->sc_pgroups = uu_list_create(pgroup_pool, t, 0);

	return (t);
}

pgroup_t *
internal_pgroup_new()
{
	pgroup_t *p;

	if ((p = uu_zalloc(sizeof (pgroup_t))) == NULL)
		uu_die(gettext("couldn't allocate memory"));

	uu_list_node_init(p, &p->sc_node, pgroup_pool);

	p->sc_pgroup_props = uu_list_create(property_pool, p, UU_LIST_SORTED);
	p->sc_pgroup_name = "<unset>";
	p->sc_pgroup_type = "<unset>";

	return (p);
}

void
internal_pgroup_free(pgroup_t *pg)
{
	property_t *prop;
	void *cookie = NULL;

	while ((prop = uu_list_teardown(pg->sc_pgroup_props, &cookie)) != NULL)
		internal_property_free(prop);

	uu_free(pg);
}

static pgroup_t *
find_pgroup(uu_list_t *list, const char *name, const char *type)
{
	pgroup_t *pg;

	for (pg = uu_list_first(list);
	    pg != NULL;
	    pg = uu_list_next(list, pg)) {
		if (strcmp(pg->sc_pgroup_name, name) != 0)
			continue;

		if (type == NULL)
			return (pg);

		if (strcmp(pg->sc_pgroup_type, type) == 0)
			return (pg);
	}

	return (NULL);
}

pgroup_t *
internal_dependent_find(entity_t *e, const char *name)
{
	return (find_pgroup(e->sc_dependents, name, NULL));
}

pgroup_t *
internal_pgroup_find(entity_t *e, const char *name, const char *type)
{
	return (find_pgroup(e->sc_pgroups, name, type));
}

pgroup_t *
internal_pgroup_find_or_create(entity_t *e, const char *name, const char *type)
{
	pgroup_t *pg;

	pg = internal_pgroup_find(e, name, type);
	if (pg != NULL)
		return (pg);

	pg = internal_pgroup_new();
	(void) internal_attach_pgroup(e, pg);
	pg->sc_pgroup_name = strdup(name);
	pg->sc_pgroup_type = strdup(type);
	pg->sc_pgroup_flags = 0;

	if (pg->sc_pgroup_name == NULL || pg->sc_pgroup_type == NULL)
		uu_die(gettext("Could not duplicate string"));

	return (pg);
}

property_t *
internal_property_new()
{
	property_t *p;

	if ((p = uu_zalloc(sizeof (property_t))) == NULL)
		uu_die(gettext("couldn't allocate memory"));

	uu_list_node_init(p, &p->sc_node, property_pool);

	p->sc_property_values = uu_list_create(value_pool, p, UU_LIST_SORTED);
	p->sc_property_name = "<unset>";

	return (p);
}

void
internal_property_free(property_t *p)
{
	value_t *val;
	void *cookie = NULL;

	while ((val = uu_list_teardown(p->sc_property_values, &cookie)) !=
	    NULL) {
		if (val->sc_free != NULL)
			val->sc_free(val);
		free(val);
	}

	free(p);
}

property_t *
internal_property_find(pgroup_t *pg, const char *name)
{
	property_t *p;

	for (p = uu_list_first(pg->sc_pgroup_props);
	    p != NULL;
	    p = uu_list_next(pg->sc_pgroup_props, p))
		if (strcmp(p->sc_property_name, name) == 0)
			return (p);

	return (NULL);
}

value_t *
internal_value_new()
{
	value_t *v;

	if ((v = uu_zalloc(sizeof (value_t))) == NULL)
		uu_die(gettext("couldn't allocate memory"));

	uu_list_node_init(v, &v->sc_node, value_pool);

	return (v);
}

static void
internal_value_free_str(value_t *v)
{
	free(v->sc_u.sc_string);
}

property_t *
internal_property_create(const char *name, scf_type_t vtype, uint_t nvals, ...)
{
	va_list args;
	property_t *p;
	value_t *v;

	p = internal_property_new();

	p->sc_property_name = (char *)name;
	p->sc_value_type = vtype;

	va_start(args, nvals);
	for (; nvals > 0; nvals--) {

		v = internal_value_new();
		v->sc_type = vtype;

		switch (vtype) {
		case SCF_TYPE_BOOLEAN:
		case SCF_TYPE_COUNT:
			v->sc_u.sc_count = va_arg(args, uint64_t);
			break;
		case SCF_TYPE_INTEGER:
			v->sc_u.sc_integer = va_arg(args, int64_t);
			break;
		case SCF_TYPE_ASTRING:
		case SCF_TYPE_FMRI:
		case SCF_TYPE_HOST:
		case SCF_TYPE_HOSTNAME:
		case SCF_TYPE_NET_ADDR_V4:
		case SCF_TYPE_NET_ADDR_V6:
		case SCF_TYPE_OPAQUE:
		case SCF_TYPE_TIME:
		case SCF_TYPE_URI:
		case SCF_TYPE_USTRING:
			v->sc_u.sc_string = (char *)va_arg(args, uchar_t *);
			break;
		default:
			va_end(args);
			uu_die(gettext("unknown property type (%d)\n"), vtype);
			break;
		}

		internal_attach_value(p, v);
	}
	va_end(args);

	return (p);
}

/*
 * Some of these attach functions use uu_list_append() to maintain the
 * same order across import/export, whereas others are always sorted
 * anyway, or the order is irrelevant.
 */

int
internal_attach_service(bundle_t *bndl, entity_t *svc)
{
	if (uu_list_find(bndl->sc_bundle_services, svc, NULL, NULL) != NULL) {
		semerr(gettext("Multiple definitions for service %s in "
		    "bundle %s.\n"), svc->sc_name, bndl->sc_bundle_name);
		return (-1);
	}

	(void) uu_list_append(bndl->sc_bundle_services, svc);

	return (0);
}

int
internal_attach_entity(entity_t *svc, entity_t *ent)
{
	if (ent->sc_etype == SVCCFG_TEMPLATE_OBJECT) {
		svc->sc_u.sc_service.sc_service_template = ent;
		return (0);
	}

	if (svc->sc_etype != SVCCFG_SERVICE_OBJECT)
		uu_die(gettext("bad entity attach: %s is not a service\n"),
		    svc->sc_name);

	if (uu_list_find(svc->sc_u.sc_service.sc_service_instances, ent, NULL,
	    NULL) != NULL) {
		semerr(gettext("Multiple definitions of entity %s in service "
		    "%s.\n"), ent->sc_name, svc->sc_name);
		return (-1);
	}

	(void) uu_list_prepend(svc->sc_u.sc_service.sc_service_instances, ent);
	ent->sc_parent = svc;
	ent->sc_fmri = uu_msprintf("%s:%s", svc->sc_fmri, ent->sc_name);
	if (ent->sc_fmri == NULL)
		uu_die(gettext("couldn't allocate memory"));

	return (0);
}

int
internal_attach_pgroup(entity_t *ent, pgroup_t *pgrp)
{
	if (uu_list_find(ent->sc_pgroups, pgrp, NULL, NULL) != NULL) {
		semerr(gettext("Multiple definitions of property group %s in "
		    "entity %s.\n"), pgrp->sc_pgroup_name, ent->sc_name);
		return (-1);
	}

	(void) uu_list_append(ent->sc_pgroups, pgrp);

	pgrp->sc_parent = ent;

	return (0);
}

int
internal_attach_dependent(entity_t *ent, pgroup_t *pg)
{
	if (uu_list_find(ent->sc_dependents, pg, NULL, NULL) != NULL) {
		semerr(gettext("Multiple definitions of dependent %s in "
		    "entity %s.\n"), pg->sc_pgroup_name, ent->sc_name);
		return (-1);
	}

	(void) uu_list_append(ent->sc_dependents, pg);

	pg->sc_parent = ent;

	return (0);
}

/*
 * Returns
 *   0 - success
 *   -1 - prop already exists in pgrp
 */
int
internal_attach_property(pgroup_t *pgrp, property_t *prop)
{
	uu_list_index_t idx;

	if (uu_list_find(pgrp->sc_pgroup_props, prop, NULL, &idx) != NULL) {
		semerr(gettext("Multiple definitions for property %s in "
		    "property group %s.\n"), prop->sc_property_name,
		    pgrp->sc_pgroup_name);
		return (-1);
	}

	uu_list_insert(pgrp->sc_pgroup_props, prop, idx);

	return (0);
}

void
internal_attach_value(property_t *prop, value_t *val)
{
	uu_list_index_t idx;

	(void) uu_list_find(prop->sc_property_values, val, NULL, &idx);
	uu_list_insert(prop->sc_property_values, val, idx);
}

/*
 * These functions create an internal representation of a property group
 * (pgroup_t) from the repository (scf_propertygroup_t).  They are used by the
 * import functions in svccfg_libscf.c .
 *
 * load_init() must be called first to initialize these globals, and
 * load_fini() should be called afterwards to destroy them.
 */

static char *loadbuf = NULL;
static size_t loadbuf_sz;
static scf_property_t *load_prop = NULL;
static scf_value_t *load_val = NULL;
static scf_iter_t *load_propiter = NULL, *load_valiter = NULL;

/*
 * Initialize the global state for the load_*() routines.
 * Returns
 *   0 - success
 *   ENOMEM - out of memory
 */
int
load_init(void)
{
	loadbuf_sz = ((max_scf_value_len > max_scf_pg_type_len) ?
	    max_scf_value_len : max_scf_pg_type_len) + 1;

	loadbuf = malloc(loadbuf_sz);
	if (loadbuf == NULL)
		return (ENOMEM);

	if ((load_prop = scf_property_create(g_hndl)) == NULL ||
	    (load_val = scf_value_create(g_hndl)) == NULL ||
	    (load_propiter = scf_iter_create(g_hndl)) == NULL ||
	    (load_valiter = scf_iter_create(g_hndl)) == NULL) {
		load_fini();
		return (ENOMEM);
	}

	return (0);
}

void
load_fini(void)
{
	scf_iter_destroy(load_propiter);
	load_propiter = NULL;
	scf_iter_destroy(load_valiter);
	load_valiter = NULL;
	scf_value_destroy(load_val);
	load_val = NULL;
	scf_property_destroy(load_prop);
	load_prop = NULL;
	free(loadbuf);
	loadbuf = NULL;
}

/*
 * Create a property_t which represents an scf_property_t.  Returns
 *   0 - success
 *   ECANCELED - prop's pg was deleted
 *   ECONNABORTED - repository disconnected
 *   ENOMEM - out of memory
 *   EACCES - permission denied when reading property
 */
static int
load_property(scf_property_t *prop, property_t **ipp)
{
	property_t *iprop;
	int r;
	ssize_t ssz;

	/* get name */
	if (scf_property_get_name(prop, loadbuf, loadbuf_sz) < 0) {
		switch (scf_error()) {
		case SCF_ERROR_DELETED:
			return (ECANCELED);

		case SCF_ERROR_CONNECTION_BROKEN:
			return (ECONNABORTED);

		case SCF_ERROR_NOT_BOUND:
		case SCF_ERROR_NOT_SET:
		default:
			bad_error("scf_property_get_name", scf_error());
		}
	}

	iprop = internal_property_new();
	iprop->sc_property_name = strdup(loadbuf);
	if (iprop->sc_property_name == NULL) {
		internal_property_free(iprop);
		return (ENOMEM);
	}

	/* get type */
	if (scf_property_type(prop, &iprop->sc_value_type) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_DELETED:
			r = ECANCELED;
			goto out;

		case SCF_ERROR_CONNECTION_BROKEN:
			r = ECONNABORTED;
			goto out;

		case SCF_ERROR_NOT_BOUND:
		case SCF_ERROR_NOT_SET:
		default:
			bad_error("scf_property_type", scf_error());
		}
	}

	/* get values */
	if (scf_iter_property_values(load_valiter, prop) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_DELETED:
			r = ECANCELED;
			goto out;

		case SCF_ERROR_CONNECTION_BROKEN:
			r = ECONNABORTED;
			goto out;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_NOT_BOUND:
		case SCF_ERROR_NOT_SET:
		default:
			bad_error("scf_iter_property_values", scf_error());
		}
	}

	for (;;) {
		value_t *ival;

		r = scf_iter_next_value(load_valiter, load_val);
		if (r == 0)
			break;
		if (r != 1) {
			switch (scf_error()) {
			case SCF_ERROR_DELETED:
				r = ECANCELED;
				goto out;

			case SCF_ERROR_CONNECTION_BROKEN:
				r = ECONNABORTED;
				goto out;

			case SCF_ERROR_PERMISSION_DENIED:
				r = EACCES;
				goto out;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_NOT_BOUND:
			case SCF_ERROR_NOT_SET:
			case SCF_ERROR_INVALID_ARGUMENT:
			default:
				bad_error("scf_iter_next_value", scf_error());
			}
		}

		ival = internal_value_new();
		ival->sc_type = scf_value_type(load_val);
		assert(ival->sc_type != SCF_TYPE_INVALID);

		switch (ival->sc_type) {
		case SCF_TYPE_BOOLEAN: {
			uint8_t b;

			r = scf_value_get_boolean(load_val, &b);
			if (r != 0)
				bad_error("scf_value_get_boolean", scf_error());
			ival->sc_u.sc_count = b;
			break;
		}

		case SCF_TYPE_COUNT:
			r = scf_value_get_count(load_val, &ival->sc_u.sc_count);
			if (r != 0)
				bad_error("scf_value_get_count", scf_error());
			break;

		case SCF_TYPE_INTEGER:
			r = scf_value_get_integer(load_val,
			    &ival->sc_u.sc_integer);
			if (r != 0)
				bad_error("scf_value_get_integer", scf_error());
			break;

		default:
			ssz = scf_value_get_as_string(load_val, loadbuf,
			    loadbuf_sz);
			if (ssz < 0)
				bad_error("scf_value_get_as_string",
				    scf_error());

			ival->sc_u.sc_string = strdup(loadbuf);
			if (ival->sc_u.sc_string == NULL) {
				r = ENOMEM;
				goto out;
			}

			ival->sc_free = internal_value_free_str;
		}

		internal_attach_value(iprop, ival);
	}

	*ipp = iprop;
	return (0);

out:
	free(iprop->sc_property_name);
	internal_property_free(iprop);
	return (r);
}

/*
 * Returns
 *   0 - success
 *   ECANCELED - pg was deleted
 *   ECONNABORTED - repository disconnected
 *   ENOMEM - out of memory
 */
int
load_pg_attrs(const scf_propertygroup_t *pg, pgroup_t **ipgp)
{
	pgroup_t *ipg;

	ipg = internal_pgroup_new();

	if (scf_pg_get_flags(pg, &ipg->sc_pgroup_flags) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_DELETED:
			internal_pgroup_free(ipg);
			return (ECANCELED);

		case SCF_ERROR_CONNECTION_BROKEN:
			internal_pgroup_free(ipg);
			return (ECONNABORTED);

		case SCF_ERROR_NOT_SET:
		case SCF_ERROR_NOT_BOUND:
		default:
			bad_error("scf_pg_get_name", scf_error());
		}
	}

	if (scf_pg_get_name(pg, loadbuf, loadbuf_sz) < 0) {
		switch (scf_error()) {
		case SCF_ERROR_DELETED:
			internal_pgroup_free(ipg);
			return (ECANCELED);

		case SCF_ERROR_CONNECTION_BROKEN:
			internal_pgroup_free(ipg);
			return (ECONNABORTED);

		case SCF_ERROR_NOT_SET:
		case SCF_ERROR_NOT_BOUND:
		default:
			bad_error("scf_pg_get_name", scf_error());
		}
	}

	ipg->sc_pgroup_name = strdup(loadbuf);
	if (ipg->sc_pgroup_name == NULL) {
		internal_pgroup_free(ipg);
		return (ENOMEM);
	}

	if (scf_pg_get_type(pg, loadbuf, loadbuf_sz) < 0) {
		switch (scf_error()) {
		case SCF_ERROR_DELETED:
			free((char *)ipg->sc_pgroup_name);
			internal_pgroup_free(ipg);
			return (ECANCELED);

		case SCF_ERROR_CONNECTION_BROKEN:
			free((char *)ipg->sc_pgroup_name);
			internal_pgroup_free(ipg);
			return (ECONNABORTED);

		case SCF_ERROR_NOT_SET:
		case SCF_ERROR_NOT_BOUND:
		default:
			bad_error("scf_pg_get_name", scf_error());
		}
	}

	ipg->sc_pgroup_type = strdup(loadbuf);
	if (ipg->sc_pgroup_type == NULL) {
		free((char *)ipg->sc_pgroup_name);
		internal_pgroup_free(ipg);
		return (ENOMEM);
	}

	*ipgp = ipg;
	return (0);
}

/*
 * Load a property group into a pgroup_t.  Returns
 *   0 - success
 *   ECANCELED - pg was deleted
 *   ECONNABORTED - repository disconnected
 *   EBADF - pg is corrupt (error printed if fmri is given)
 *   ENOMEM - out of memory
 *   EACCES - permission denied when reading property
 */
int
load_pg(const scf_propertygroup_t *pg, pgroup_t **ipgp, const char *fmri,
    const char *snapname)
{
	pgroup_t *ipg;
	int r;

	if (scf_iter_pg_properties(load_propiter, pg) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_DELETED:
			return (ECANCELED);

		case SCF_ERROR_CONNECTION_BROKEN:
			return (ECONNABORTED);

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_NOT_SET:
		case SCF_ERROR_NOT_BOUND:
		default:
			bad_error("scf_iter_pg_properties", scf_error());
		}
	}

	r = load_pg_attrs(pg, &ipg);
	switch (r) {
	case 0:
		break;

	case ECANCELED:
	case ECONNABORTED:
	case ENOMEM:
		return (r);

	default:
		bad_error("load_pg_attrs", r);
	}

	for (;;) {
		property_t *iprop;

		r = scf_iter_next_property(load_propiter, load_prop);
		if (r == 0)
			break;
		if (r != 1) {
			switch (scf_error()) {
			case SCF_ERROR_DELETED:
				r = ECANCELED;
				goto out;

			case SCF_ERROR_CONNECTION_BROKEN:
				r = ECONNABORTED;
				goto out;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_NOT_BOUND:
			case SCF_ERROR_NOT_SET:
			case SCF_ERROR_INVALID_ARGUMENT:
			default:
				bad_error("scf_iter_next_property",
				    scf_error());
			}
		}

		r = load_property(load_prop, &iprop);
		switch (r) {
		case 0:
			break;

		case ECANCELED:
		case ECONNABORTED:
		case ENOMEM:
		case EACCES:
			goto out;

		default:
			bad_error("load_property", r);
		}

		r = internal_attach_property(ipg, iprop);
		if (r != 0) {
			if (fmri != NULL) {
				if (snapname == NULL)
					warn(gettext("Property group \"%s\" of "
					    "%s has multiple definitions of "
					    "property \"%s\".\n"),
					    ipg->sc_pgroup_name, fmri,
					    iprop->sc_property_name);
				else
					warn(gettext("Property group \"%s\" of "
					    "the \"%s\" snapshot of %s has "
					    "multiple definitions of property "
					    "\"%s\".\n"),
					    ipg->sc_pgroup_name, snapname, fmri,
					    iprop->sc_property_name);
			}
			r = EBADF;
			goto out;
		}
	}

	*ipgp = ipg;
	return (0);

out:
	internal_pgroup_free(ipg);
	return (r);
}

/*
 * These functions compare internal property groups and properties (pgroup_t
 * & property_t).  They return 1 if the given structures are equal and
 * 0 otherwise.  Some will report the differences between the two structures.
 * They are used by the import functions in svccfg_libscf.c .
 */

int
prop_equal(property_t *p1, property_t *p2, const char *fmri, const char *pgname,
    int new)
{
	value_t *v1, *v2;

	const char * const values_diff = gettext("Conflict upgrading %s "
	    "(property \"%s/%s\" has different values).\n");
	const char * const values_diff_new = gettext("Conflict upgrading %s "
	    "(new property \"%s/%s\" has different values).\n");

	assert((fmri == NULL) == (pgname == NULL));

	if (fmri != NULL) {
		/*
		 * If we find any differences, we'll report conflicts.  But
		 * conflict messages won't make any sense if the names don't
		 * match.  If the caller supplied fmri, assert that the names
		 * match.
		 */
		assert(strcmp(p1->sc_property_name, p2->sc_property_name) == 0);
	} else {
		if (strcmp(p1->sc_property_name, p2->sc_property_name) != 0)
			return (0);
	}

	if (p1->sc_value_type != p2->sc_value_type) {
		if (fmri != NULL) {
			if (new)
				warn(gettext("Conflict upgrading %s "
				    "(new property \"%s/%s\" has different "
				    "type).\n"), fmri, pgname,
				    p1->sc_property_name);
			else
				warn(gettext("Conflict upgrading %s "
				    "(property \"%s/%s\" has different "
				    "type).\n"), fmri, pgname,
				    p1->sc_property_name);
		}
		return (0);
	}

	if (uu_list_numnodes(p1->sc_property_values) !=
	    uu_list_numnodes(p2->sc_property_values)) {
		if (fmri != NULL)
			warn(new ? values_diff_new : values_diff, fmri,
			    pgname, p1->sc_property_name);
		return (0);
	}

	v1 = uu_list_first(p1->sc_property_values);
	v2 = uu_list_first(p2->sc_property_values);

	while (v1 != NULL) {
		assert(v2 != NULL);

		if (value_cmp(v1, v2, NULL) != 0) {
			if (fmri != NULL)
				warn(new ? values_diff_new : values_diff,
				    fmri, pgname, p1->sc_property_name);
			return (0);
		}

		v1 = uu_list_next(p1->sc_property_values, v1);
		v2 = uu_list_next(p2->sc_property_values, v2);
	}

	return (1);
}

int
pg_attrs_equal(const pgroup_t *pg1, const pgroup_t *pg2, const char *fmri,
    int new)
{
	if (strcmp(pg1->sc_pgroup_name, pg2->sc_pgroup_name) != 0) {
		assert(fmri == NULL);
		return (0);
	}

	if (pg1->sc_pgroup_flags != pg2->sc_pgroup_flags) {
		if (fmri) {
			if (new)
				warn(gettext("Conflict upgrading %s "
				    "(new property group \"%s\" has different "
				    "flags).\n"), fmri, pg1->sc_pgroup_name);
			else
				warn(gettext("Conflict upgrading %s "
				    "(property group \"%s\" has different "
				    "flags).\n"), fmri, pg1->sc_pgroup_name);
		}
		return (0);
	}

	if (strcmp(pg1->sc_pgroup_type, pg2->sc_pgroup_type) != 0) {
		if (fmri) {
			if (new)
				warn(gettext("Conflict upgrading %s "
				    "(new property group \"%s\" has different "
				    "type).\n"), fmri, pg1->sc_pgroup_name);
			else
				warn(gettext("Conflict upgrading %s "
				    "(property group \"%s\" has different "
				    "type).\n"), fmri, pg1->sc_pgroup_name);
		}
		return (0);
	}

	return (1);
}

int
pg_equal(pgroup_t *pg1, pgroup_t *pg2)
{
	property_t *p1, *p2;

	if (!pg_attrs_equal(pg1, pg2, NULL, 0))
		return (0);

	if (uu_list_numnodes(pg1->sc_pgroup_props) !=
	    uu_list_numnodes(pg2->sc_pgroup_props))
		return (0);

	p1 = uu_list_first(pg1->sc_pgroup_props);
	p2 = uu_list_first(pg2->sc_pgroup_props);

	while (p1 != NULL) {
		assert(p2 != NULL);

		if (!prop_equal(p1, p2, NULL, NULL, 0))
			return (0);

		p1 = uu_list_next(pg1->sc_pgroup_props, p1);
		p2 = uu_list_next(pg2->sc_pgroup_props, p2);
	}

	return (1);
}
