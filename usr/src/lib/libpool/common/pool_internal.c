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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <limits.h>
#include <pool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <synch.h>
#include <thread.h>

#include <sys/loadavg.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include "dict.h"
#include "pool_internal.h"
#include "pool_impl.h"

/*
 * Atom structure, used to reference count string atoms.
 */
typedef struct {
	char *a_string;				/* String atom */
	uint_t a_count;				/* String reference count */
} atom_t;

/*
 * The _internal_lock is used to lock the state of libpool during
 * internal initialisation operations.
 */
mutex_t		_internal_lock;

static int _libpool_debug = 0;			/* debugging messages */
static dict_hdl_t *_pv_atoms;			/* pool_value_t atoms */
static mutex_t _atom_lock;			/* atom table lock */
static int _libpool_internal_initialised = PO_FALSE;

/*
 * Various useful constant strings which are often encountered
 */
const char *c_a_dtype = "a-dtype";
const char *c_name = "name";
const char *c_type = "type";
const char *c_ref_id = "ref_id";
const char *c_max_prop = "max";
const char *c_min_prop = "min";
const char *c_size_prop = "size";
const char *c_sys_prop = "sys_id";

/*
 * prop_is_type() checks the supplied property and returns PO_TRUE if the
 * property value is set for the property else PO_FALSE
 */
static int prop_is_type(int, const pool_prop_t *);
static int resource_get_common(const pool_resource_t *, const char *,
    uint64_t *);
static int64_t elem_get_expected_int64(const pool_elem_t *, const char *);

/*
 * The following returns a malloc'ed string which must be free'd by the
 * caller.
 */
static char *elem_get_expected_string(const pool_elem_t *, const char *);
static int element_props_init(pool_prop_t *);

/*
 * Each element class/sub-class has a set of properties and behaviours
 * which are used to create the element with appropriate property
 * values and to ensure correct property manipulations. The details
 * are all stored in the following arrays.
 */

static int elem_name_init(pool_prop_t *);
static int elem_comment_init(pool_prop_t *);

static int pool_importance_init(pool_prop_t *);
static int pool_active_init(pool_prop_t *);

static int res_max_init(pool_prop_t *);
static int res_min_init(pool_prop_t *);
static int res_size_init(pool_prop_t *);
static int res_load_init(pool_prop_t *);

static int pset_units_init(pool_prop_t *);

static int cpu_status_init(pool_prop_t *);

static int elem_no_set(pool_elem_t *, const pool_value_t *);
static int elem_set_name(pool_elem_t *, const pool_value_t *);
static int elem_get_type(const pool_elem_t *, pool_value_t *);
static int elem_set_string(pool_elem_t *, const pool_value_t *);
static int elem_set_bool(pool_elem_t *, const pool_value_t *);
static int elem_set_uint(pool_elem_t *, const pool_value_t *);

static int system_set_allocate(pool_elem_t *, const pool_value_t *);

static int pool_set_scheduler(pool_elem_t *, const pool_value_t *);
static int pool_set_active(pool_elem_t *, const pool_value_t *);

static int res_set_max(pool_elem_t *, const pool_value_t *);
static int res_set_min(pool_elem_t *, const pool_value_t *);

static int cpu_set_status(pool_elem_t *, const pool_value_t *);

static const char *pool_elem_class_name[] = {
	"invalid",
	"system",
	"pool",
	"component resource",
	"aggregate resource",
	"component"
};

/*
 * This must be kept in sync with the pool_resource_elem_ctl array and
 * the "enum pool_resource_elem_class" type.
 */
static const char *pool_resource_elem_class_name[] = {
	"invalid",
	"pset"
};

static const char *pool_component_elem_class_name[] = {
	"invalid",
	"cpu"
};

static pool_prop_t system_props[] = {
	{ "system.name", POOL_VALUE_INITIALIZER, PP_STORED, NULL,
	    { NULL, elem_set_name } },
	{ "system.ref_id", POOL_VALUE_INITIALIZER,
	    PP_HIDDEN | PP_STORED | PP_READ, NULL, { NULL, elem_no_set } },
	{ "system.comment", POOL_VALUE_INITIALIZER, PP_STORED, NULL, NULL },
	{ "system.version", POOL_VALUE_INITIALIZER,
	    PP_STORED | PP_READ, NULL, NULL },
	{ "system.bind-default", POOL_VALUE_INITIALIZER,
	    PP_STORED, NULL, NULL },
	{ "system.allocate-method", POOL_VALUE_INITIALIZER,
	    PP_STORED | PP_OPTIONAL, NULL, { NULL, system_set_allocate } },
	{ "system.poold.log-level", POOL_VALUE_INITIALIZER,
	    PP_STORED | PP_OPTIONAL, NULL, { NULL, elem_set_string } },
	{ "system.poold.log-location", POOL_VALUE_INITIALIZER,
	    PP_STORED | PP_OPTIONAL, NULL, { NULL, elem_set_string } },
	{ "system.poold.monitor-interval", POOL_VALUE_INITIALIZER,
	    PP_STORED | PP_OPTIONAL, NULL, { NULL, elem_set_uint } },
	{ "system.poold.history-file", POOL_VALUE_INITIALIZER,
	    PP_STORED | PP_OPTIONAL, NULL, { NULL, elem_set_string } },
	{ "system.poold.objectives", POOL_VALUE_INITIALIZER,
	    PP_STORED | PP_OPTIONAL, NULL, { NULL, elem_set_string } },
	NULL
};

static pool_prop_t pool_props[] = {
	{ "pool.sys_id", POOL_VALUE_INITIALIZER,
	    PP_STORED | PP_READ, NULL, NULL },
	{ "pool.name", POOL_VALUE_INITIALIZER,
	    PP_STORED | PP_INIT, elem_name_init, { NULL, elem_set_name } },
	{ "pool.res", POOL_VALUE_INITIALIZER,
	    PP_HIDDEN | PP_STORED | PP_READ, NULL, { NULL, elem_no_set } },
	{ "pool.ref_id", POOL_VALUE_INITIALIZER,
	    PP_HIDDEN | PP_STORED | PP_READ, NULL, { NULL, elem_no_set } },
	{ "pool.active", POOL_VALUE_INITIALIZER, PP_STORED | PP_INIT,
	    pool_active_init, { NULL, pool_set_active } },
	{ "pool.default", POOL_VALUE_INITIALIZER,
	    PP_STORED | PP_READ, NULL, NULL },
	{ "pool.scheduler", POOL_VALUE_INITIALIZER,
	    PP_STORED | PP_OPTIONAL, NULL,
	    { NULL, pool_set_scheduler } },
	{ "pool.importance", POOL_VALUE_INITIALIZER, PP_STORED | PP_INIT,
	    pool_importance_init, NULL },
	{ "pool.comment", POOL_VALUE_INITIALIZER, PP_STORED | PP_INIT,
	    elem_comment_init, NULL },
	NULL
};

static pool_prop_t pset_props[] = {
	{ "type", POOL_VALUE_INITIALIZER, PP_HIDDEN | PP_STORED | PP_READ, NULL,
	    { elem_get_type, NULL }  },
	{ "pset.sys_id", POOL_VALUE_INITIALIZER,
	    PP_STORED | PP_READ, NULL, NULL },
	{ "pset.name", POOL_VALUE_INITIALIZER,
	    PP_STORED | PP_INIT, elem_name_init, { NULL, elem_set_name } },
	{ "pset.ref_id", POOL_VALUE_INITIALIZER,
	    PP_HIDDEN | PP_STORED | PP_READ, NULL, { NULL, elem_no_set } },
	{ "pset.default", POOL_VALUE_INITIALIZER,
	    PP_STORED | PP_READ, NULL, NULL },
	{ "pset.min", POOL_VALUE_INITIALIZER, PP_STORED | PP_INIT, res_min_init,
	    { NULL, res_set_min } },
	{ "pset.max", POOL_VALUE_INITIALIZER, PP_STORED | PP_INIT, res_max_init,
	    { NULL, res_set_max } },
	{ "pset.units", POOL_VALUE_INITIALIZER,
	    PP_STORED | PP_INIT, pset_units_init, NULL },
	{ "pset.load", POOL_VALUE_INITIALIZER, PP_READ | PP_INIT,
	    res_load_init, NULL },
	{ "pset.size", POOL_VALUE_INITIALIZER, PP_STORED | PP_INIT | PP_READ,
	    res_size_init, NULL },
	{ "pset.comment", POOL_VALUE_INITIALIZER, PP_STORED | PP_INIT,
	    elem_comment_init, NULL },
	{ "pset.poold.objectives", POOL_VALUE_INITIALIZER,
	    PP_STORED | PP_OPTIONAL, NULL, { NULL, elem_set_string } },
	NULL
};

static pool_prop_t cpu_props[] = {
	{ "type", POOL_VALUE_INITIALIZER, PP_HIDDEN | PP_STORED | PP_READ, NULL,
	    { elem_get_type, NULL }  },
	{ "cpu.sys_id", POOL_VALUE_INITIALIZER, PP_STORED | PP_READ, NULL,
	    NULL },
	{ "cpu.ref_id", POOL_VALUE_INITIALIZER,
	    PP_HIDDEN | PP_STORED | PP_READ, NULL, { NULL, elem_no_set } },
	{ "cpu.comment", POOL_VALUE_INITIALIZER, PP_STORED | PP_INIT,
	    elem_comment_init, NULL },
	{ "cpu.status", POOL_VALUE_INITIALIZER, PP_INIT, cpu_status_init,
	    { NULL, cpu_set_status } },
	{ "cpu.pinned", POOL_VALUE_INITIALIZER, PP_STORED | PP_OPTIONAL, NULL,
	    { NULL, elem_set_bool } },
	NULL
};

static pool_prop_t *pool_elem_ctl[] = {
	NULL,
	system_props,
	pool_props,
	NULL,
	NULL,
	NULL
};

/*
 * This must be kept in sync with the pool_resource_elem_class_name array and
 * the "enum pool_resource_elem_class" type.
 */
static pool_prop_t *pool_resource_elem_ctl[] = {
	NULL,
	pset_props
};

static pool_prop_t *pool_component_elem_ctl[] = {
	NULL,
	cpu_props
};

static void
atom_init(void)
{
	(void) mutex_lock(&_atom_lock);
	/*
	 * Initialize pool_value_t atom dictionary
	 */
	if (_pv_atoms == NULL)
		if ((_pv_atoms = dict_new((int (*)(const void *, const void *))
		    strcmp, (uint64_t (*)(const void *))hash_str)) == NULL)
			abort();
	(void) mutex_unlock(&_atom_lock);
}

/*
 * Initializer, called when the library is initialized.
 */
void
internal_init(void)
{
	(void) mutex_lock(&_internal_lock);
	if (_libpool_internal_initialised == PO_TRUE) {
		(void) mutex_unlock(&_internal_lock);
		return;
	}
	atom_init();
	/*
	 * Initialize all available property arrays.
	 */
	if (element_props_init(system_props) == PO_FAIL)
		abort();
	if (element_props_init(pool_props) == PO_FAIL)
		abort();
	if (element_props_init(pset_props) == PO_FAIL)
		abort();
	if (element_props_init(cpu_props) == PO_FAIL)
		abort();
	_libpool_internal_initialised = PO_TRUE;
	(void) mutex_unlock(&_internal_lock);

}

static int
element_props_init(pool_prop_t *props)
{
	int i;

	for (i = 0; props[i].pp_pname != NULL; i++) {
		/*
		 * Initialise each of the properties
		 */
		if (pool_value_set_name(&props[i].pp_value,
		    props[i].pp_pname) != PO_SUCCESS) {
			return (PO_FAIL);
		}
		if (props[i].pp_init &&
		    props[i].pp_init(&props[i]) != PO_SUCCESS) {
			return (PO_FAIL);
		}
	}
	return (PO_SUCCESS);
}


/*
 * These functions intialise the properties of this plugin. The only reason
 * they exist is because the ability to perform the static initialisation of
 * union members properly was only introduced in the C99 standard. i.e. if you
 * could do {.f = 1.0} like in the proposed C99 standard then that would
 * be the preferred way to do this as it keeps the data in the array and
 * minimises the scope for errors. However, until that time these functions
 * are the best way to minimise the scope for errors and to maximise
 * maintainability.
 *
 * There is one function for each property, and the initial value for each
 * property is hard-coded into each function.
 */

static int
elem_name_init(pool_prop_t *prop)
{
	return (string_init(prop, "default"));
}

static int
elem_comment_init(pool_prop_t *prop)
{
	return (string_init(prop, ""));
}

static int
pool_importance_init(pool_prop_t *prop)
{
	return (int_init(prop, 1));
}

static int
pool_active_init(pool_prop_t *prop)
{
	return (bool_init(prop, PO_TRUE));
}

static int
res_max_init(pool_prop_t *prop)
{
	return (uint_init(prop, 0));
}

static int
res_min_init(pool_prop_t *prop)
{
	return (uint_init(prop, 0));
}

static int
res_size_init(pool_prop_t *prop)
{
	return (uint_init(prop, 0));
}

static int
res_load_init(pool_prop_t *prop)
{
	return (uint_init(prop, 0));
}

static int
pset_units_init(pool_prop_t *prop)
{
	return (string_init(prop, "population"));
}

static int
cpu_status_init(pool_prop_t *prop)
{
	return (string_init(prop, PS_ONLINE));
}

/*
 * Individual property manipulation routines for use by the generic
 * get/put property routines
 */

/*
 * Many properties cannot be modified. This function prevents property
 * modification.
 */
/* ARGSUSED */
static int
elem_no_set(pool_elem_t *elem, const pool_value_t *pval)
{
	return (PO_FAIL);
}

/*
 * Duplicate names for a pool or resource type are illegal.
 */
static int
elem_set_name(pool_elem_t *elem, const pool_value_t *pval)
{
	const char *nm;
	pool_t *pool;
	pool_resource_t *res;

	if (pool_value_get_string(pval, &nm) != PO_SUCCESS) {
		return (PO_FAIL);
	}
	if (!is_valid_name(nm)) {
		pool_seterror(POE_PUTPROP);
		return (PO_FAIL);
	}
	switch (pool_elem_class(elem)) {
	case PEC_SYSTEM:
		break;
	case PEC_POOL:
		pool = pool_get_pool(TO_CONF(elem), nm);
		if (pool != NULL && pool != pool_elem_pool(elem)) {
			pool_seterror(POE_PUTPROP);
			return (PO_FAIL);
		}
		break;
	case PEC_RES_COMP:
	case PEC_RES_AGG:
		res = pool_get_resource(TO_CONF(elem),
		    pool_elem_class_string(elem), nm);
		if (res != NULL && res != pool_elem_res(elem)) {
			pool_seterror(POE_PUTPROP);
			return (PO_FAIL);
		}
		break;
	default:
		return (PO_FAIL);
	}
	return (PO_SUCCESS);
}

/*
 * Ensure the type is a string.
 */
/* ARGSUSED */
static int
elem_set_string(pool_elem_t *elem, const pool_value_t *pval)
{
	if (pool_value_get_type(pval) == POC_STRING)
		return (PO_SUCCESS);
	else {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
}

/*
 * Ensure the type is a boolean.
 */
/* ARGSUSED */
static int
elem_set_bool(pool_elem_t *elem, const pool_value_t *pval)
{
	if (pool_value_get_type(pval) == POC_BOOL)
		return (PO_SUCCESS);
	else {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
}

/*
 * Ensure the type is an unsigned int.
 */
/* ARGSUSED */
static int
elem_set_uint(pool_elem_t *elem, const pool_value_t *pval)
{
	if (pool_value_get_type(pval) == POC_UINT)
		return (PO_SUCCESS);
	else {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
}

/* ARGSUSED */
int
system_set_allocate(pool_elem_t *elem, const pool_value_t *pval)
{
	const char *sval;

	if (pool_value_get_string(pval, &sval) != PO_SUCCESS) {
		pool_seterror(POE_PUTPROP);
		return (PO_FAIL);
	}
	if (strcmp(POA_IMPORTANCE, sval) != 0 &&
	    strcmp(POA_SURPLUS_TO_DEFAULT, sval) != 0) {
			pool_seterror(POE_PUTPROP);
			return (PO_FAIL);
	}
	return (PO_SUCCESS);
}

/* ARGSUSED */
int
pool_set_active(pool_elem_t *elem, const pool_value_t *pval)
{
	uchar_t bval;

	if (pool_value_get_type(pval) != POC_BOOL) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
	(void) pool_value_get_bool(pval, &bval);
	if (bval != 1) {
		/*
		 * "active" must be true on pools for
		 * now.
		 */
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
	return (PO_SUCCESS);
}

/* ARGSUSED */
int
pool_set_scheduler(pool_elem_t *elem, const pool_value_t *pval)
{
	pcinfo_t pcinfo;
	const char *sched;

	if (pool_value_get_string(pval, &sched) != 0) {
		pool_seterror(POE_PUTPROP);
		return (PO_FAIL);
	}
	(void) strncpy(pcinfo.pc_clname, sched, PC_CLNMSZ);
	if (priocntl(0, 0, PC_GETCID, &pcinfo) == -1) {
		pool_seterror(POE_PUTPROP);
		return (PO_FAIL);
	}
	return (PO_SUCCESS);
}

static int
res_set_max(pool_elem_t *elem, const pool_value_t *pval)
{
	uint64_t min, max;
	pool_value_t val = POOL_VALUE_INITIALIZER;

	/*
	 * max must be a uint
	 */
	if (pool_value_get_uint64(pval, &max) != PO_SUCCESS) {
		pool_seterror(POE_PUTPROP);
		return (PO_FAIL);
	}
	/*
	 * max can't be less than min (if it exists)
	 */
	if (pool_get_ns_property(elem, c_min_prop, &val) == POC_INVAL)
		return (PO_SUCCESS);
	if (pool_value_get_uint64(&val, &min) != PO_SUCCESS) {
		pool_seterror(POE_PUTPROP);
		return (PO_FAIL);
	}
	if (max < min) {
		pool_seterror(POE_PUTPROP);
		return (PO_FAIL);
	}
	/*
	 * Ensure that changes to the max in a dynamic configuration
	 * are still valid.
	 */
	if (conf_is_dynamic(TO_CONF(elem)) == PO_TRUE) {
		uint64_t oldmax;

		if (pool_get_ns_property(elem, c_max_prop, &val) == POC_INVAL) {
			pool_seterror(POE_PUTPROP);
			return (PO_FAIL);
		}
		if (pool_value_get_uint64(&val, &oldmax) != PO_SUCCESS) {
			pool_seterror(POE_PUTPROP);
			return (PO_FAIL);
		}
		/*
		 * Ensure that the modified total max is >= size
		 * of all resources of this type
		 */
		if (max < oldmax) {
			return (pool_validate_resource(TO_CONF(elem),
			    pool_elem_class_string(elem), c_max_prop,
			    max - oldmax));
		}
	}
	return (PO_SUCCESS);
}

static int
res_set_min(pool_elem_t *elem, const pool_value_t *pval)
{
	uint64_t min, max;
	pool_value_t val = POOL_VALUE_INITIALIZER;

	/*
	 * min must be a uint
	 */
	if (pool_value_get_uint64(pval, &min) != PO_SUCCESS) {
		pool_seterror(POE_PUTPROP);
		return (PO_FAIL);
	}
	/*
	 * min can't be more than max (if it exists)
	 */
	if (pool_get_ns_property(elem, c_max_prop, &val) == POC_INVAL)
		return (PO_SUCCESS);
	if (pool_value_get_uint64(&val, &max) != PO_SUCCESS) {
		pool_seterror(POE_PUTPROP);
		return (PO_FAIL);
	}
	if (min > max) {
		pool_seterror(POE_PUTPROP);
		return (PO_FAIL);
	}

	switch (pool_resource_elem_class(elem)) {
	case PREC_PSET:
		if (resource_is_default(pool_elem_res(elem))) {
			if (min < 1) {
				pool_seterror(POE_PUTPROP);
				return (PO_FAIL);
			}
		}
		break;
	default:
		break;
	}

	/*
	 * Ensure that changes to the min in a dynamic configuration
	 * are still valid.
	 */
	if (conf_is_dynamic(TO_CONF(elem)) == PO_TRUE) {
		uint64_t oldmin;

		if (pool_get_ns_property(elem, c_min_prop, &val) == POC_INVAL) {
			pool_seterror(POE_PUTPROP);
			return (PO_FAIL);
		}
		if (pool_value_get_uint64(&val, &oldmin) != PO_SUCCESS) {
			pool_seterror(POE_PUTPROP);
			return (PO_FAIL);
		}
		/*
		 * Ensure that the modified total min is <= size
		 * of all resources of this type
		 */
		if (min > oldmin) {
			return (pool_validate_resource(TO_CONF(elem),
			    pool_elem_class_string(elem), c_min_prop,
			    min - oldmin));
		}
	}
	return (PO_SUCCESS);
}

/* ARGSUSED */
int
cpu_set_status(pool_elem_t *elem, const pool_value_t *pval)
{
	const char *status;

	if (pool_value_get_string(pval, &status) != 0) {
		pool_seterror(POE_PUTPROP);
		return (PO_FAIL);
	}

	if (strcmp(PS_ONLINE, status) != 0 &&
	    strcmp(PS_OFFLINE, status) != 0 &&
	    strcmp(PS_NOINTR, status) != 0 &&
	    strcmp(PS_SPARE, status) != 0 &&
	    strcmp(PS_FAULTED, status) != 0) {
		pool_seterror(POE_PUTPROP);
		return (PO_FAIL);
	}
	return (PO_SUCCESS);
}

static int
elem_get_type(const pool_elem_t *elem, pool_value_t *pval)
{
	if (pool_value_set_string(pval, pool_elem_class_string(elem)) ==
	    PO_FAIL)
		return (PO_FAIL);
	return (PO_SUCCESS);
}

/*
 * More general utilities
 */
/*
 * Is the supplied configuration the dynamic configuration
 * Return: PO_TRUE/PO_FALSE
 */
int
conf_is_dynamic(const pool_conf_t *conf)
{
	if (strcmp(pool_conf_location(conf), pool_dynamic_location()) == 0)
		return (PO_TRUE);
	return (PO_FALSE);
}

/*
 * uint_init() initialises the value of the supplied property with the
 * supplied value.
 * Returns PO_SUCCESS
 */
int
uint_init(pool_prop_t *prop, uint64_t val)
{
	pool_value_set_uint64(&prop->pp_value, val);
	return (PO_SUCCESS);
}

/*
 * int_init() initialises the value of the supplied property with the
 * supplied value.
 * Returns PO_SUCCESS
 */
int
int_init(pool_prop_t *prop, int64_t val)
{
	pool_value_set_int64(&prop->pp_value, val);
	return (PO_SUCCESS);
}

/*
 * double_init() initialises the value of the supplied property with the
 * supplied value.
 * Returns PO_SUCCESS
 */
int
double_init(pool_prop_t *prop, double val)
{
	pool_value_set_double(&prop->pp_value, val);
	return (PO_SUCCESS);
}

/*
 * bool_init() initialises the value of the supplied property with the
 * supplied value.
 * Returns PO_SUCCESS
 */
int
bool_init(pool_prop_t *prop, uchar_t val)
{
	pool_value_set_bool(&prop->pp_value, val);
	return (PO_SUCCESS);
}

/*
 * string_init() initialises the value of the supplied property with the
 * supplied value.
 * Returns PO_SUCCESS/PO_FAIL
 */
int
string_init(pool_prop_t *prop, const char *val)
{
	return (pool_value_set_string(&prop->pp_value, val));
}

/*
 * pool_get_provider_count() returns the count of registered providers.
 *
 * Returns count of registered providers
 */
uint_t
pool_get_provider_count(void)
{
	uint_t count = 0;
	int i;

	for (i = 0; i < sizeof (pool_resource_elem_ctl) /
	    sizeof (pool_resource_elem_ctl[0]); i++) {
		if (pool_resource_elem_ctl[i] != NULL)
			count++;
	}
	return (count);
}

/*
 * Return all the props for a specified provider
 */
const pool_prop_t *
provider_get_props(const pool_elem_t *elem)
{
	const pool_prop_t *prop_list = NULL;
	pool_elem_class_t elem_class = pool_elem_class(elem);

	switch (elem_class) {
	case PEC_SYSTEM:
	case PEC_POOL:
		prop_list = pool_elem_ctl[elem_class];
		break;
	case PEC_RES_AGG:
	case PEC_RES_COMP:
		prop_list = pool_resource_elem_ctl
		    [pool_resource_elem_class(elem)];
		break;
	case PEC_COMP:
		prop_list = pool_component_elem_ctl
		    [pool_component_elem_class(elem)];
		break;
	}
	return (prop_list);
}

/*
 * provider_get_prop() return the pool_prop_t structure which
 * describes the supplied property name for the supplied provider.
 *
 * Returns the property description or NULL if it doesn't exist.
 */
const pool_prop_t *
provider_get_prop(const pool_elem_t *elem, const char *name)
{
	int i;
	const pool_prop_t *prop_list;

	if ((prop_list = provider_get_props(elem)) == NULL)
		return (NULL);

	for (i = 0; prop_list[i].pp_pname != NULL; i++) {
		if (strcmp(name, prop_list[i].pp_pname) == 0) {
			return (&prop_list[i]);
		}
	}
	return (NULL);
}

/*
 * prop_is_type() checks the supplied property and returns PO_TRUE if the
 * property value is 1 else PO_FALSE
 */
static int
prop_is_type(int prop_type, const pool_prop_t *prop)
{
	return ((prop->pp_perms & prop_type) ? PO_TRUE : PO_FALSE);
}

/*
 * prop_is_stored() returns PO_TRUE if the property is stored in the backing
 * configuration and PO_FALSE else.
 */
int
prop_is_stored(const pool_prop_t *prop)
{
	return (prop_is_type(PP_STORED, prop));
}

/*
 * prop_is_readonly() returns PO_TRUE if the property is a read-only property
 * and PO_FALSE else.
 */
int
prop_is_readonly(const pool_prop_t *prop)
{
	return (prop_is_type(PP_READ, prop));
}

/*
 * prop_is_init() returns PO_TRUE if the property should be
 * initialised when an element of this type is created and PO_FALSE
 * else.
 */
int
prop_is_init(const pool_prop_t *prop)
{
	return (prop_is_type(PP_INIT, prop));
}

/*
 * prop_is_hidden() returns PO_TRUE if the property should be hidden
 * from access by the external property access mechanisms.
 */
int
prop_is_hidden(const pool_prop_t *prop)
{
	return (prop_is_type(PP_HIDDEN, prop));
}

/*
 * prop_is_optional() returns PO_TRUE if the property is optional and
 * can be removed by external property access mechanisms.
 */
int
prop_is_optional(const pool_prop_t *prop)
{
	return (prop_is_type(PP_OPTIONAL, prop));
}

int
cpu_is_requested(pool_component_t *component)
{
	pool_value_t val = POOL_VALUE_INITIALIZER;
	uchar_t requested;

	if (pool_get_property(TO_CONF(TO_ELEM(component)), TO_ELEM(component),
	    "cpu.requested", &val) != POC_BOOL) {
		return (PO_FALSE);
	}
	if (pool_value_get_bool(&val, &requested) != PO_SUCCESS) {
		return (PO_FALSE);
	}
	return ((int)requested);
}

/*
 * Common code for various resource get functions
 */
static int
resource_get_common(const pool_resource_t *res, const char *name,
    uint64_t *uval)
{
	pool_value_t val = POOL_VALUE_INITIALIZER;
	pool_value_class_t pvc;
	int retval = PO_SUCCESS;

	pvc = pool_get_ns_property(TO_ELEM(res), name, &val);
	if (pvc == POC_INVAL) {
		*uval = 0;
#ifdef DEBUG
		pool_dprintf("can't retrieve %s\n");
		pool_elem_dprintf(TO_ELEM(res));
#endif	/* DEBUG */
	} else if (pvc == POC_UINT) {
		retval = pool_value_get_uint64(&val, uval);
	}
	return (retval);
}

/*
 * resource_get_size() updates size with the size of the supplied resource.
 *
 * Returns PO_SUCCESS/PO_FAIL
 */
int
resource_get_size(const pool_resource_t *res, uint64_t *size)
{
	return (resource_get_common(res, c_size_prop, size));
}

/*
 * resource_get_pinned() updates pinned with the size of the
 * pinned part of a supplied resource. Resource is not available for
 * allocation if it is marked as "pinned".
 *
 * Returns PO_SUCCESS/PO_FAIL
 */
int
resource_get_pinned(const pool_resource_t *res, uint64_t *pinned)
{
	pool_value_t *props[] = { NULL, NULL };
	pool_value_t val = POOL_VALUE_INITIALIZER;
	pool_component_t **cs = NULL;
	uint_t ncompelem;

	props[0] = &val;

	pool_value_set_bool(props[0], PO_TRUE);
	if (pool_value_set_name(props[0], "cpu.pinned") != PO_SUCCESS)
		return (PO_FAIL);

	if ((cs = pool_query_resource_components(TO_CONF(TO_ELEM(res)), res,
	    &ncompelem, props)) != NULL) {
		*pinned = ncompelem;
		free(cs);
	} else
		*pinned = 0;
	return (PO_SUCCESS);
}

/*
 * resource_get_min() updates min with the minimum size of the supplied
 * resource.
 *
 * Returns PO_SUCCESS/PO_FAIL
 */
int
resource_get_min(const pool_resource_t *res, uint64_t *min)
{
	return (resource_get_common(res, c_min_prop, min));
}

/*
 * resource_get_max() updates max with the maximum size of the supplied
 * resource.
 *
 * Returns PO_SUCCESS/PO_FAIL
 */
int
resource_get_max(const pool_resource_t *res, uint64_t *max)
{
	return (resource_get_common(res, c_max_prop, max));
}

/*
 * TODO: This is pset specific
 *
 * get_default_resource() returns the default resource for type of the supplied
 * resource.
 *
 * Returns A pointer to the default resource of the same type as the supplied
 * resource.
 */
const pool_resource_t *
get_default_resource(const pool_resource_t *res)
{
	return (resource_by_sysid(TO_CONF(TO_ELEM(res)), PS_NONE,
	    pool_elem_class_string(TO_ELEM(res))));
}

/*
 * resource_is_default() returns 1 if the supplied resource is the default
 * resource for it's type.
 */
int
resource_is_default(const pool_resource_t *res)
{

	return (get_default_resource(res) == res);
}

/*
 * resource_is_system() determines if the resource is a system resource.
 */
int
resource_is_system(const pool_resource_t *res)
{
	return (res->pr_is_system(res));

}

/*
 * resource_can_associate() determines if it is possible to associate
 * with the supplied resource.
 */
int
resource_can_associate(const pool_resource_t *res)
{
	return (res->pr_can_associate(res));
}

/*
 * Common code to get an int64 property.
 * Unfortunately (-1) is a valid psetid, so we'll return (-2) in case of
 * error.
 */
static int64_t
elem_get_expected_int64(const pool_elem_t *elem, const char *name)
{
	int64_t val64;
	pool_value_t val = POOL_VALUE_INITIALIZER;

	if (pool_get_ns_property(elem, name, &val) != POC_INT) {
		return (POOL_SYSID_BAD);
	}
	(void) pool_value_get_int64(&val, &val64);

	return (val64);
}

/*
 * The following returns a malloc'ed string which must be free'd by the
 * caller.
 */
static char *
elem_get_expected_string(const pool_elem_t *elem, const char *name)
{
	pool_value_t val = POOL_VALUE_INITIALIZER;
	char *retval;

	if (pool_get_ns_property(elem, name, &val) != POC_STRING) {
		return (NULL);
	}
	(void) pool_value_get_string(&val, (const char **)&retval);
	retval = strdup(retval);
	return (retval);
}

/*
 * elem_get_sysid() returns the sys_id for the supplied elem.
 */
id_t
elem_get_sysid(const pool_elem_t *elem)
{
	return ((id_t)elem_get_expected_int64(elem, c_sys_prop));
}

/*
 * elem_get_name() returns the name for the supplied elem. Note that
 * it is the caller's responsibility to free this memory.
 */
char *
elem_get_name(const pool_elem_t *elem)
{
	return (elem_get_expected_string(elem, c_name));
}

/*
 * elem_is_default() returns 1 if the supplied elem is the default
 * elem for it's type.
 */
int
elem_is_default(const pool_elem_t *res)
{

	return (get_default_elem(res) == res);
}

/*
 * Return B_TRUE if the element has the 'temporary' property set.
 */
boolean_t
elem_is_tmp(const pool_elem_t *elem)
{
	pool_value_t val = POOL_VALUE_INITIALIZER;
	uchar_t bval;

	if (pool_get_ns_property(elem, "temporary", &val) != POC_BOOL)
		return (B_FALSE);

	(void) pool_value_get_bool(&val, &bval);

	return (bval != 0);
}

/*
 * get_default_elem() returns the default elem for type of the supplied
 * elem.
 *
 * Returns A pointer to the default elem of the same type as the
 * supplied elem or NULL on error. Trying to access the default elem
 * for a type of element which doesn't support the notion of default
 * is an error.
 */
const pool_elem_t *
get_default_elem(const pool_elem_t *pe)
{
	pool_result_set_t *rs;
	pool_value_t *props[] = { NULL, NULL };
	pool_value_t val = POOL_VALUE_INITIALIZER;
	char_buf_t *cb;
	const pool_elem_t *pe_default;

	props[0] = &val;
	if ((cb = alloc_char_buf(CB_DEFAULT_LEN)) == NULL) {
		return (NULL);
	}
	if (set_char_buf(cb, "%s.default", pool_elem_class_string(pe)) !=
	    PO_SUCCESS) {
		free_char_buf(cb);
		return (NULL);
	}
	if (pool_value_set_name(props[0], cb->cb_buf) != PO_SUCCESS) {
		free_char_buf(cb);
		return (NULL);
	}
	free_char_buf(cb);
	pool_value_set_bool(props[0], PO_TRUE);

	if ((rs = pool_exec_query(TO_CONF(pe), NULL, NULL,
	    PEC_QRY_ELEM(pe), props)) == NULL) {
		pool_seterror(POE_INVALID_CONF);
		return (NULL);
	}
	if (pool_rs_count(rs) != 1) {
		(void) pool_rs_close(rs);
		pool_seterror(POE_INVALID_CONF);
		return (NULL);
	}

	pe_default = rs->prs_next(rs);
	(void) pool_rs_close(rs);
	return (pe_default);
}

/*
 * is_a_known_prefix() determines if the supplied prop_name is a known
 * name for the supplied class.
 *
 * Returns a pointer to the prefix if it is found or NULL
 */
const char *
is_a_known_prefix(pool_elem_class_t class, const char *prop_name)
{
	int i;
	int len;

	switch (class) {
	case PEC_SYSTEM:
	case PEC_POOL:
		len = strlen(pool_elem_class_name[class]);
		if (strncmp(prop_name, pool_elem_class_name[class], len) == 0 &&
		    prop_name[len] == '.' || strcmp(prop_name, c_type) == 0)
			return (pool_elem_class_name[class]);
		break;
	case PEC_RES_COMP:
	case PEC_RES_AGG:
		for (i = 0; i < sizeof (pool_resource_elem_class_name) /
		    sizeof (pool_resource_elem_class_name[0]); i++) {
			len = strlen(pool_resource_elem_class_name[i]);
			if (strncmp(prop_name,
			    pool_resource_elem_class_name[i], len) == 0 &&
			    prop_name[len] == '.' ||
			    strcmp(prop_name, c_type) == 0)
				return (pool_resource_elem_class_name[i]);
		}
		break;
	case PEC_COMP:
		for (i = 0; i < sizeof (pool_component_elem_class_name) /
		    sizeof (pool_component_elem_class_name[0]); i++) {
			len = strlen(pool_component_elem_class_name[i]);
			if (strncmp(prop_name,
			    pool_component_elem_class_name[i], len) == 0 &&
			    prop_name[len] == '.' ||
			    strcmp(prop_name, c_type) == 0)
				return (pool_component_elem_class_name[i]);
		}
		break;
	default:
		break;
	}
	return (NULL);
}


const char *
pool_elem_class_string(const pool_elem_t *pe)
{
	switch (pool_elem_class(pe)) {
	case PEC_SYSTEM:
	case PEC_POOL:
		return (pool_elem_class_name[pool_elem_class(pe)]);
	case PEC_RES_COMP:
	case PEC_RES_AGG:
		return (pool_resource_elem_class_name
		    [pool_resource_elem_class(pe)]);
	case PEC_COMP:
		return (pool_component_elem_class_name
		    [pool_component_elem_class(pe)]);
	default:
		return (pool_elem_class_name[PEC_INVALID]);
	}
}

const char *
pool_resource_type_string(pool_resource_elem_class_t type)
{
	return (pool_resource_elem_class_name[type]);
}

const char *
pool_component_type_string(pool_component_elem_class_t type)
{
	return (pool_component_elem_class_name[type]);
}

/*
 * resource_by_sysid() finds a resource from it's supplied sysid and type.
 *
 * Returns a pointer to the resource or NULL if it doesn't exist.
 */
pool_resource_t *
resource_by_sysid(const pool_conf_t *conf, id_t sysid, const char *type)
{
	pool_value_t *props[] = { NULL, NULL, NULL };
	pool_resource_t **resources = NULL;
	pool_resource_t *retval = NULL;
	uint_t nelem;
	char_buf_t *cb;
	pool_value_t val0 = POOL_VALUE_INITIALIZER;
	pool_value_t val1 = POOL_VALUE_INITIALIZER;

	props[0] = &val0;
	props[1] = &val1;

	if (pool_value_set_string(props[0], type) != PO_SUCCESS ||
	    pool_value_set_name(props[0], c_type) != PO_SUCCESS)
		return (NULL);

	if ((cb = alloc_char_buf(CB_DEFAULT_LEN)) == NULL) {
		return (NULL);
	}
	if (set_char_buf(cb, "%s.sys_id", type) != PO_SUCCESS) {
		free_char_buf(cb);
		return (NULL);
	}
	if (pool_value_set_name(props[1], cb->cb_buf) != PO_SUCCESS) {
		free_char_buf(cb);
		return (NULL);
	}
	free_char_buf(cb);
	pool_value_set_int64(props[1], sysid);

	resources = pool_query_resources(conf, &nelem, props);

	if (resources != NULL) {
		retval = resources[0];
		free(resources);
	}
	return (retval);
}

pool_elem_class_t
pool_elem_class_from_string(const char *type)
{
	int i;

	for (i = 0; i < sizeof (pool_elem_class_name) /
	    sizeof (pool_elem_class_name[0]); i++) {
		if (strcmp(pool_elem_class_name[i], type) == 0)
			break;
	}
	if (i == sizeof (pool_elem_class_name) /
	    sizeof (pool_elem_class_name[0]))
		return (PEC_INVALID);
	return ((pool_elem_class_t)i);
}

pool_resource_elem_class_t
pool_resource_elem_class_from_string(const char *type)
{
	int i;

	for (i = 0; i < sizeof (pool_resource_elem_class_name) /
	    sizeof (pool_resource_elem_class_name[0]); i++) {
		if (strcmp(pool_resource_elem_class_name[i], type) == 0)
			break;
	}
	if (i == sizeof (pool_resource_elem_class_name) /
	    sizeof (pool_resource_elem_class_name[0]))
		return (PREC_INVALID);
	return ((pool_resource_elem_class_t)i);
}

pool_component_elem_class_t
pool_component_elem_class_from_string(const char *type)
{
	int i;

	for (i = 0; i < sizeof (pool_component_elem_class_name) /
	    sizeof (pool_component_elem_class_name[0]); i++) {
		if (strcmp(pool_component_elem_class_name[i], type) == 0)
			break;
	}
	if (i == sizeof (pool_component_elem_class_name) /
	    sizeof (pool_component_elem_class_name[0]))
		return (PCEC_INVALID);
	return ((pool_component_elem_class_t)i);
}

/*
 * pool_resource_type_list() populates the supplied array of pointers
 * with the names of the available resource types on this system.
 */
int
pool_resource_type_list(const char **types, uint_t *numtypes)
{
	int i, j;
	uint_t maxnum = *numtypes;

	*numtypes = pool_get_provider_count();

	if (types) {
		for (i = 0, j = 0; i < sizeof (pool_resource_elem_ctl) /
		    sizeof (pool_resource_elem_ctl[0]) && j < maxnum; i++) {
			if (pool_resource_elem_ctl[i] != NULL)
				types[j++] = pool_resource_elem_class_name[i];
		}
	}
	return (PO_SUCCESS);
}

/*
 * Return the system element for the supplied conf.
 * NULL is returned if an error is detected and the error code is updated
 * to indicate the cause of the error.
 */
pool_system_t *
pool_conf_system(const pool_conf_t *conf)
{
	pool_elem_t *system;
	pool_result_set_t *rs;

	if ((rs = pool_exec_query(conf, NULL, NULL, PEC_QRY_SYSTEM, NULL)) ==
	    NULL) {
		pool_seterror(POE_INVALID_CONF);
		return (NULL);
	}
	/* There should only be one system record */
	if (pool_rs_count(rs) != 1) {
		pool_seterror(POE_INVALID_CONF);
		(void) pool_rs_close(rs);
		return (NULL);
	}
	system = rs->prs_next(rs);
	(void) pool_rs_close(rs);
	return (pool_elem_system(system));
}

pool_system_t *
pool_elem_system(const pool_elem_t *pe)
{
	if (pe->pe_class != PEC_SYSTEM) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}
	return ((pool_system_t *)pe);
}

pool_t *
pool_elem_pool(const pool_elem_t *pe)
{
	if (pe->pe_class != PEC_POOL) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}
	return ((pool_t *)pe);
}

pool_resource_t *
pool_elem_res(const pool_elem_t *pe)
{
	if (pe->pe_class != PEC_RES_COMP &&
	    pool_elem_class(pe) != PEC_RES_AGG) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}
	return ((pool_resource_t *)pe);
}

pool_component_t *
pool_elem_comp(const pool_elem_t *pe)
{
	if (pe->pe_class != PEC_COMP) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}
	return ((pool_component_t *)pe);
}

/*
 * qsort_elem_compare() is used for qsort elemement comparison.
 *
 * Returns see qsort(3c)
 */
int
qsort_elem_compare(const void *a, const void *b)
{
	const pool_elem_t *e1 = *(const pool_elem_t **)a;
	const pool_elem_t *e2 = *(const pool_elem_t **)b;

	/*
	 * Special case for handling name changes on default elements
	 * If both elements are default elements then always return 0
	 */
	if (pool_elem_same_class(e1, e2) == PO_TRUE &&
	    (elem_is_default(e1) && elem_is_default(e2)))
			return (0);
	else
		return (pool_elem_compare_name(e1, e2));
}

/*
 * Dynamic character buffers.
 */

/*
 * Resize the supplied character buffer to the new size.
 */
static int
resize_char_buf(char_buf_t *cb, size_t size)
{
	char *re_cb = NULL;

	if ((re_cb = realloc(cb->cb_buf, size)) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	/* If inital allocation, make sure buffer is zeroed */
	if (cb->cb_buf == NULL)
		(void) memset(re_cb, 0, sizeof (re_cb));
	/* If resized smaller, make sure buffer NULL terminated */
	if (size < cb->cb_size)
		re_cb[size] = 0;
	cb->cb_buf = re_cb;
	cb->cb_size = size;
	return (PO_SUCCESS);
}

/*
 * Allocate a new char_buf_t structure. If there isn't enough memory, return
 * NULL. Initialise the new char_buf_t to 0 and then call resize_char_buf
 * to initialise the character buffer. Return a pointer to the new
 * char_buf_t if the operation succeeds.
 */
char_buf_t *
alloc_char_buf(size_t size)
{
	char_buf_t *cb;

	if ((cb = malloc(sizeof (char_buf_t))) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (NULL);
	}
	(void) memset(cb, 0, sizeof (char_buf_t));

	if (resize_char_buf(cb, size + 1) == PO_FAIL) {
		free(cb);
		return (NULL);
	}
	return (cb);
}

/*
 * Free the character buffer and then free the char_buf_t.
 */
void
free_char_buf(char_buf_t *cb)
{
	free((void *)cb->cb_buf);
	free(cb);
}

/*
 * Set the character buffer to the supplied data. The user supplies a printf
 * like format string and then an appropriate number of parameters for the
 * specified format. The character buffer is automatically resized to fit
 * the data as determined by resize_char_buf.
 */
/*PRINTFLIKE2*/
int
set_char_buf(char_buf_t *cb, const char *fmt, ...)
{
	va_list ap;
	int new_size;

	va_start(ap, fmt);
	if ((new_size = vsnprintf(cb->cb_buf, cb->cb_size, fmt, ap)) >=
	    cb->cb_size) {
		if (resize_char_buf(cb, new_size + 1) != PO_SUCCESS) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
		(void) vsnprintf(cb->cb_buf, cb->cb_size, fmt, ap);
	}
	va_end(ap);
	return (PO_SUCCESS);
}

/*
 * Append the supplied data to the character buffer. The user supplies a printf
 * like format string and then an appropriate number of parameters for the
 * specified format. The character buffer is automatically resized to fit
 * the data as determined by resize_char_buf.
 */
/*PRINTFLIKE2*/
int
append_char_buf(char_buf_t *cb, const char *fmt, ...)
{
	va_list ap;
	int new_len;
	char size_buf[1];
	int old_len = 0;

	if (cb->cb_buf != NULL)
		old_len = strlen(cb->cb_buf);
	va_start(ap, fmt);
	new_len = vsnprintf(size_buf, sizeof (size_buf), fmt, ap);
	if (new_len + old_len >= cb->cb_size) {
		if (resize_char_buf(cb, old_len + new_len + 1) !=
		    PO_SUCCESS) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}
	}
	/*
	 * Resized the buffer to the right size, now append the new data
	 */
	(void) vsnprintf(&cb->cb_buf[old_len], cb->cb_size - old_len, fmt, ap);
	va_end(ap);
	return (PO_SUCCESS);
}

/*
 * Return the class for the supplied elem.
 * If the return is PEC_INVALID, the error code will be set to reflect cause.
 */
pool_elem_class_t
pool_elem_class(const pool_elem_t *elem)
{
	return (elem->pe_class);
}


/*
 * Return the resource class for the supplied elem.
 */
pool_resource_elem_class_t
pool_resource_elem_class(const pool_elem_t *elem)
{
	return (elem->pe_resource_class);
}

/*
 * Return the component class for the supplied elem.
 */
pool_component_elem_class_t
pool_component_elem_class(const pool_elem_t *elem)
{
	return (elem->pe_component_class);
}

pool_elem_t *
pool_get_pair(const pool_elem_t *pe)
{
	return (pe->pe_pair);
}

void
pool_set_pair(pool_elem_t *pe1, pool_elem_t *pe2)
{
	pe1->pe_pair = pe2;
}

int
pool_validate_resource(const pool_conf_t *conf, const char *type,
    const char *prop, int64_t delta)
{
	pool_conf_t *dyn;
	uint_t nelem;
	uint64_t available, required, uval;
	int i;
	pool_resource_t **rl;
	pool_value_t val = POOL_VALUE_INITIALIZER;
	pool_value_t val1 = POOL_VALUE_INITIALIZER;
	pool_value_t *pvals[] = { NULL, NULL };

	if (strcmp(prop, c_min_prop) && strcmp(prop, c_max_prop)) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}

	pvals[0] = &val;
	(void) pool_value_set_string(&val, type);
	(void) pool_value_set_name(&val, c_type);

	/*
	 * Check that there are available resources on this
	 * system for this configuration to be applied. Find
	 * each resource type and then find all resources of
	 * each type and total ".min". Find all available
	 * resources and ensure >= total min.
	 */

	available = 0;
	required = delta;

	if ((rl = (pool_query_resources(conf, &nelem, pvals))) == NULL)
		return (PO_FAIL);

	for (i = 0; i < nelem; i++) {
		if (pool_get_ns_property(TO_ELEM(rl[i]), prop,
		    &val1) == POC_INVAL ||
		    pool_value_get_uint64(&val1, &uval) != PO_SUCCESS) {
			free(rl);
			return (PO_FAIL);
		}
		/*
		 * Watch out for overflow
		 */
		if (required + uval < required) {
			required = UINT64_MAX;
			break;
		} else
			required += uval;
	}

	if (conf_is_dynamic(conf) == PO_TRUE) {
		dyn = (pool_conf_t *)conf;
	} else {
		free(rl);
		if ((dyn = pool_conf_alloc()) == NULL)
			return (PO_FAIL);
		if (pool_conf_open(dyn, pool_dynamic_location(), PO_RDONLY) !=
		    PO_SUCCESS) {
			pool_conf_free(dyn);
			return (PO_FAIL);
		}
		if ((rl = (pool_query_resources(dyn, &nelem, pvals))) ==
		    NULL) {
			(void) pool_conf_close(dyn);
			pool_conf_free(dyn);
			return (PO_FAIL);
		}
	}
	for (i = 0; i < nelem; i++) {
		if (pool_get_ns_property(TO_ELEM(rl[i]), c_size_prop,
		    &val1) == POC_INVAL ||
		    pool_value_get_uint64(&val1, &uval) != PO_SUCCESS) {
			free(rl);
			if (conf != dyn) {
				(void) pool_conf_close(dyn);
				pool_conf_free(dyn);
			}
			return (PO_FAIL);
		}
		available += uval;
	}
	free(rl);
	if (conf != dyn) {
		(void) pool_conf_close(dyn);
		pool_conf_free(dyn);
	}
	if (strcmp(prop, c_min_prop) == 0) {
		if (available < required) {
			pool_seterror(POE_INVALID_CONF);
			return (PO_FAIL);
		}
	} else {
		if (available > required) {
			pool_seterror(POE_INVALID_CONF);
			return (PO_FAIL);
		}
	}
	return (PO_SUCCESS);
}

/*
 * If _libpool_debug is set, printf the debug message to stderr with an
 * appropriate prefix in front of it.
 */
void
do_dprintf(const char *format, va_list ap)
{
	if (_libpool_debug) {
		(void) fputs("libpool DEBUG: ", stderr);
		(void) vfprintf(stderr, format, ap);
	}
}

/*PRINTFLIKE1*/
void
pool_dprintf(const char *format, ...)
{
	if (_libpool_debug) {
		va_list alist;
		va_start(alist, format);
		do_dprintf(format, alist);
		va_end(alist);
	}
}

/*
 * log_alloc() allocates a new, empty transaction log.
 *
 * Returns a pointer to the new log or NULL on failure.
 */
log_t *
log_alloc(pool_conf_t *conf)
{
	log_t *l;

	if ((l = calloc(1, sizeof (log_t))) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (NULL);
	}
	l->l_state = LS_DO;
	l->l_conf = conf;
	if ((l->l_sentinel = log_item_alloc(l, 0, NULL))
	    == NULL) {
		free(l);
		pool_seterror(POE_SYSTEM);
		return (NULL);
	}
	l->l_sentinel->li_next = l->l_sentinel;
	l->l_sentinel->li_prev = l->l_sentinel;

	return (l);
}

/*
 * log_free() reclaims the resources associated with a transaction log.
 */
void
log_free(log_t *l)
{
	(void) log_walk(l, log_item_free);
	(void) log_item_free(l->l_sentinel);
	free(l);
}
/*
 * log_empty() removes all items from a transaction log. It is the
 * users responsibility to ensure that any resources associated with
 * an item are reclaimed before this function is invoked.
 */
void
log_empty(log_t *l)
{
	(void) log_walk(l, log_item_free);
}

/*
 * log_walk() visits each log item in turn and executes the supplied action
 * using the item as a parameter. If no action is supplied, then the item
 * uses it's own stored action.
 *
 * Returns PO_SUCCESS/PO_FAIL
 */
int
log_walk(log_t *l, log_item_action_t action)
{
	log_item_t *li, *li_next;

	li = l->l_sentinel->li_next;
	while (li != l->l_sentinel) {
		li_next = li->li_next;
		if ((action(li)) != PO_SUCCESS)
			return (PO_FAIL);
		li = li_next;
	}
	return (PO_SUCCESS);
}

/*
 * log_reverse_walk() visits each log item in turn (in reverse order)
 * and executes the supplied action using the item as a parameter.
 *
 * Returns PO_SUCCESS/PO_FAIL
 */
int
log_reverse_walk(log_t *l, log_item_action_t action)
{
	log_item_t *li, *li_prev;

	li = l->l_sentinel->li_prev;
	while (li != l->l_sentinel) {
		li_prev = li->li_prev;
		if ((action(li)) != PO_SUCCESS)
			return (PO_FAIL);
		li = li_prev;
	}
	return (PO_SUCCESS);
}

/*
 * log_size() returns the size of the log, i.e. the number of items pending in
 * the log.
 */
uint_t
log_size(log_t *l)
{
	log_item_t *li;
	uint_t size = 0;

	for (li = l->l_sentinel->li_next; li != l->l_sentinel; li = li->li_next)
		size++;
	return (size);
}

/*
 * log_append() allocates a new log item to hold the supplied details and
 * appends the newly created item to the supplied log.
 *
 * Returns PO_SUCCESS/PO_FAIL
 */
int
log_append(log_t *l, int op, void *details)
{
	log_item_t *li;

	if ((li = log_item_alloc(l, op, details)) == NULL) {
		l->l_state = LS_UNDO;
		return (PO_FAIL);
	}
	/*
	 * Link it in
	 */
	li->li_prev = l->l_sentinel->li_prev;
	li->li_next = l->l_sentinel;
	l->l_sentinel->li_prev->li_next = li;
	l->l_sentinel->li_prev = li;
	return (PO_SUCCESS);
}

/*
 * log_item_alloc() allocates a new transaction log item. The item should be
 * used to store details about a transaction which may need to be undone if
 * commit processing fails.
 *
 * Returns a pointer to a new transaction log item or NULL.
 */
log_item_t *
log_item_alloc(log_t *l, int op, void *details)
{
	log_item_t *li;

	if ((li = malloc(sizeof (log_item_t))) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (NULL);
	}

	(void) memset(li, 0, sizeof (log_item_t));
	li->li_log = l;
	li->li_op = op;
	li->li_details = details;
	li->li_state = LS_DO;

	return (li);
}

/*
 * log_item_free() reclaims the resources associated with a log_item_t.
 */
int
log_item_free(log_item_t *li)
{
	li->li_prev->li_next = li->li_next;
	li->li_next->li_prev = li->li_prev;
	free(li);
	return (PO_SUCCESS);
}

/*
 * atom_string() checks the string table to see if a string is already
 * stored. If it is, return a pointer to it. If not, duplicate the
 * string and return a pointer to the duplicate.
 */
const char *
atom_string(const char *s)
{
	atom_t *atom;

	/*
	 * atom_init() must have completed successfully
	 */
	atom_init();
	(void) mutex_lock(&_atom_lock);
	if ((atom = dict_get(_pv_atoms, s)) == NULL) {
		if ((atom = calloc(1, sizeof (atom_t))) == NULL) {
			pool_seterror(POE_SYSTEM);
			(void) mutex_unlock(&_atom_lock);
			return (NULL);
		}
		if ((atom->a_string = strdup(s)) == NULL) {
			(void) mutex_unlock(&_atom_lock);
			free(atom);
			pool_seterror(POE_SYSTEM);
			return (NULL);
		}
		(void) dict_put(_pv_atoms, atom->a_string, atom);
	}
	atom->a_count++;
	(void) mutex_unlock(&_atom_lock);
	return (atom->a_string);
}

/*
 * atom_free() decrements the reference count for the supplied
 * string. If the reference count reaches zero, then the atom is
 * destroyed.
 */
void
atom_free(const char *s)
{
	atom_t *atom;

	(void) mutex_lock(&_atom_lock);
	if ((atom = dict_get(_pv_atoms, s)) != NULL) {
		if (--atom->a_count == 0) {
			(void) dict_remove(_pv_atoms, s);
			free(atom->a_string);
			free(atom);
		}
	}
	(void) mutex_unlock(&_atom_lock);
}

#ifdef DEBUG
/*
 * log_item_dprintf() prints the contents of the supplied log item using the
 * pools pool_dprintf() trace mechanism.
 *
 * Returns PO_SUCCESS
 */
void
log_item_dprintf(log_item_t *li)
{
	pool_dprintf("LOGDUMP: %d operation, %p\n", li->li_op, li->li_details);
}

/*
 * log_item_dprintf() prints the contents of the supplied log item using the
 * pools pool_dprintf() trace mechanism.
 *
 * Returns PO_SUCCESS
 */
void
pool_elem_dprintf(const pool_elem_t *pe)
{
	if (pool_elem_class(pe) != PEC_COMP) {
		const char *name = elem_get_name(pe);
		pool_dprintf("element type: %s name: %s\n",
		    pool_elem_class_string(pe), name);
		free((void *)name);
	} else {
		id_t sys_id = elem_get_sysid(pe);
		pool_dprintf("element type: %s sys_id: %d\n",
		    pool_elem_class_string(pe), sys_id);
	}
}
#endif	/* DEBUG */
