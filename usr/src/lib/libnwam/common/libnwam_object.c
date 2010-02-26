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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <assert.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>

#include "libnwam_impl.h"
#include <libintl.h>
#include <libnwam.h>

/*
 * Generic object manipulation functions. Given an object handle and
 * other parameters, create/destroy objects, walk them, walk their
 * properties, modify/retrieve/delete properties, enable/disable them,
 * etc. All object handles are "struct nwam_handle *" objects, sharing
 * the same description based on the object type, name, original name
 * (used in renaming) and associated data representing properties.
 */

nwam_error_t
nwam_handle_create(nwam_object_type_t type, const char *name,
    struct nwam_handle **hpp)
{

	assert(name != NULL && hpp != NULL);

	if (strnlen(name, NWAM_MAX_NAME_LEN) > NWAM_MAX_NAME_LEN) {
		*hpp = NULL;
		return (NWAM_INVALID_ARG);
	}

	if ((*hpp = calloc(1, sizeof (struct nwam_handle))) == NULL)
		return (NWAM_NO_MEMORY);

	(*hpp)->nwh_object_type = type;
	(void) strlcpy((*hpp)->nwh_name, name, strlen(name) + 1);
	(*hpp)->nwh_committed = B_FALSE;
	(*hpp)->nwh_data = NULL;

	return (NWAM_SUCCESS);
}

/*
 * Read object of specified type from dbname.
 */
nwam_error_t
nwam_read(nwam_object_type_t type, const char *dbname, const char *name,
    uint64_t flags, struct nwam_handle **hpp)
{
	nwam_error_t err;
	char dbname_copy[MAXPATHLEN];

	assert(name != NULL && hpp != NULL);

	if (dbname != NULL)
		(void) strlcpy(dbname_copy, dbname, sizeof (dbname_copy));

	if ((err = nwam_valid_flags(flags, NWAM_FLAG_BLOCKING)) != NWAM_SUCCESS)
		return (err);
	if ((err = nwam_handle_create(type, name, hpp)) != NWAM_SUCCESS)
		return (err);

	if ((err = nwam_read_object_from_backend
	    (dbname != NULL ? dbname_copy : NULL,
	    type == NWAM_OBJECT_TYPE_NCP ? NULL : (*hpp)->nwh_name, flags,
	    &(*hpp)->nwh_data)) != NWAM_SUCCESS) {
		free(*hpp);
		*hpp = NULL;
		return (err);
	}
	if (type == NWAM_OBJECT_TYPE_NCP && dbname != NULL) {
		char *ncpname;

		/*
		 * dbname_copy may have been changed due to case-insensitive
		 * match against the actual NCP configuration file.
		 */
		if (nwam_ncp_file_to_name(dbname_copy, &ncpname)
		    == NWAM_SUCCESS) {
			(void) strlcpy((*hpp)->nwh_name, ncpname,
			    sizeof ((*hpp)->nwh_name));
			free(ncpname);
		}
	}

	(*hpp)->nwh_committed = B_TRUE;

	return (NWAM_SUCCESS);
}

/*
 * Create simply creates the handle - the object-specific function must
 * then fill in property values.
 */
nwam_error_t
nwam_create(nwam_object_type_t type, const char *dbname, const char *name,
    struct nwam_handle **hpp)
{
	struct nwam_handle *hp;

	assert(hpp != NULL && name != NULL);

	if (nwam_read(type, dbname, name, 0, &hp) == NWAM_SUCCESS) {
		nwam_free(hp);
		return (NWAM_ENTITY_EXISTS);
	}
	/* Create handle */
	return (nwam_handle_create(type, name, hpp));
}

nwam_error_t
nwam_get_name(struct nwam_handle *hp, char **namep)
{
	assert(hp != NULL && namep != NULL);

	if ((*namep = strdup(hp->nwh_name)) == NULL) {
		*namep = NULL;
		return (NWAM_NO_MEMORY);
	}
	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_set_name(struct nwam_handle *hp, const char *name)
{
	assert(hp != NULL && name != NULL);

	if (hp->nwh_committed)
		return (NWAM_ENTITY_READ_ONLY);

	if (strlen(name) >= sizeof (hp->nwh_name))
		return (NWAM_INVALID_ARG);

	(void) strcpy(hp->nwh_name, name);

	return (NWAM_SUCCESS);
}

/* Compare object names c1 and c2 using strcasecmp() */
static int
name_cmp(const void *c1, const void *c2)
{
	nwam_ncu_type_t t1, t2;
	char		*n1, *n2;

	/* If c1 and c2 are typed NCU names, compare names without the types */
	if (nwam_ncu_typed_name_to_name(*(const char **)c1, &t1, &n1)
	    == NWAM_SUCCESS &&
	    nwam_ncu_typed_name_to_name(*(const char **)c2, &t2, &n2)
	    == NWAM_SUCCESS) {
		int ret = strcasecmp(n1, n2);
		free(n1);
		free(n2);

		/* For NCUs with the same name, compare their types */
		if (ret == 0) {
			if (t1 < t2)
				ret = -1;
			else if (t1 > t2)
				ret = 1;
		}
		return (ret);
	}

	return (strcasecmp(*(const char **)c1, *(const char **)c2));
}

/*
 * Generic walk function takes the standard walk arguments, and in addition
 * takes a selection callback that is object-specific. If this returns
 * 0, the object is a valid selection for the walk and the callback is called.
 * Otherwise, it is skipped.
 */
nwam_error_t
nwam_walk(nwam_object_type_t type, const char *dbname,
    int(*cb)(struct nwam_handle *, void *),
    void *data, uint64_t flags, int *retp,
    int(*selectcb)(struct nwam_handle *, uint64_t, void *))
{
	void *objlist;
	nwam_value_t value;
	char **object_names;
	uint_t i, num_objects = 0;
	struct nwam_handle *hp;
	nwam_error_t err;
	int ret = 0;

	assert(cb != NULL);

	/*
	 * To walk a set of objects, call nwam_read_object_from_backend()
	 * with a "dbname" argument set to the container db name and
	 * the object name set to NULL. This returns an nvlist with one
	 * member - the NWAM_OBJECT_NAMES_STRING - and the values it contains
	 * represent the names of the objects.  Read each in turn, calling
	 * the callback function.
	 */
	if ((err = nwam_read_object_from_backend((char *)dbname, NULL, flags,
	    &objlist)) != NWAM_SUCCESS) {
		if (err == NWAM_ENTITY_NOT_FOUND) {
			/*
			 * This indicates the dbname container is not present.
			 * Do not pass back an error in this case, since it is
			 * valid for a container not to exist.
			 */
			return (NWAM_SUCCESS);
		}
		return (err);
	}

	if ((err = nwam_get_prop_value(objlist, NWAM_OBJECT_NAMES_STRING,
	    &value)) != NWAM_SUCCESS) {
		nwam_free_object_list(objlist);
		return (err);
	}
	err = nwam_value_get_string_array(value, &object_names, &num_objects);
	nwam_free_object_list(objlist);
	if (err != NWAM_SUCCESS) {
		nwam_value_free(value);
		return (err);
	}

	/* sort the object names alphabetically */
	qsort(object_names, num_objects, sizeof (char *), name_cmp);

	for (i = 0; i < num_objects; i++) {
		err = nwam_read(type, dbname, object_names[i],
		    flags & NWAM_FLAG_GLOBAL_MASK, &hp);
		/* An object may have disappeared.  If so, skip it. */
		if (err == NWAM_ENTITY_NOT_FOUND)
			continue;
		if (err != NWAM_SUCCESS) {
			nwam_value_free(value);
			return (err);
		}
		if ((selectcb == NULL) || (selectcb(hp, flags, data) == 0)) {
			ret = cb(hp, data);
			if (ret != 0) {
				nwam_free(hp);
				nwam_value_free(value);
				if (retp != NULL)
					*retp = ret;
				return (NWAM_WALK_HALTED);
			}
		}
		nwam_free(hp);
	}
	nwam_value_free(value);

	if (retp != NULL)
		*retp = ret;
	return (err);
}

void
nwam_free(struct nwam_handle *hp)
{
	if (hp != NULL) {
		if (hp->nwh_data != NULL)
			nwam_free_object_list(hp->nwh_data);
		free(hp);
	}
}

/*
 * Copy object represented by oldhp to an object newname, all in container
 * dbname.
 */
nwam_error_t
nwam_copy(const char *dbname, struct nwam_handle *oldhp, const char *newname,
    struct nwam_handle **newhpp)
{
	nwam_error_t err;
	struct nwam_handle *hp;

	assert(oldhp != NULL && newname != NULL && newhpp != NULL);

	if (nwam_read(oldhp->nwh_object_type, dbname, newname, 0, &hp)
	    == NWAM_SUCCESS) {
		nwam_free(hp);
		return (NWAM_ENTITY_EXISTS);
	}

	if ((err = nwam_handle_create(oldhp->nwh_object_type, newname, newhpp))
	    != NWAM_SUCCESS)
		return (err);
	if ((err = nwam_dup_object_list(oldhp->nwh_data,
	    &((*newhpp)->nwh_data))) != NWAM_SUCCESS) {
		nwam_free(*newhpp);
		*newhpp = NULL;
		return (err);
	}

	return (NWAM_SUCCESS);
}

/* ARGSUSED3 */
nwam_error_t
nwam_walk_props(struct nwam_handle *hp,
    int (*cb)(const char *, nwam_value_t, void *),
    void *data, uint64_t flags, int *retp)
{
	char *lastpropname = NULL, *propname;
	nwam_value_t value;
	nwam_error_t err;
	int ret = 0;

	assert(hp != NULL && hp->nwh_data != NULL && cb != NULL);

	if ((err = nwam_valid_flags(flags, 0)) != NWAM_SUCCESS)
		return (err);
	while ((err = nwam_next_object_prop(hp->nwh_data, lastpropname,
	    &propname, &value)) == NWAM_SUCCESS) {

		ret = cb(propname, value, data);
		if (ret != 0)
			err = NWAM_WALK_HALTED;

		/* Free value */
		nwam_value_free(value);

		if (err != NWAM_SUCCESS)
			break;

		lastpropname = propname;
	}

	if (retp != NULL)
		*retp = ret;
	if (err == NWAM_SUCCESS || err == NWAM_LIST_END)
		return (NWAM_SUCCESS);
	return (err);
}

/*
 * Note that prior to calling the generic commit function, object-specific
 * validation should be carried out.
 */
nwam_error_t
nwam_commit(const char *dbname, struct nwam_handle *hp, uint64_t flags)
{
	nwam_error_t err;
	uint64_t iflags = flags;
	boolean_t is_ncu;
	struct nwam_handle *testhp;
	nwam_action_t action;

	assert(hp != NULL);

	/*
	 * NWAM_FLAG_ENTITY_KNOWN_WLAN is only used for Known WLANs and
	 * NWAM_FLAG_ENTITY_ENABLE is used for other objects (during enable
	 * and disable).
	 */
	if ((err = nwam_valid_flags(flags,
	    NWAM_FLAG_BLOCKING | NWAM_FLAG_CREATE |
	    (hp->nwh_object_type == NWAM_OBJECT_TYPE_KNOWN_WLAN ?
	    NWAM_FLAG_ENTITY_KNOWN_WLAN : NWAM_FLAG_ENTITY_ENABLE)))
	    != NWAM_SUCCESS)
		return (err);

	is_ncu = (hp->nwh_object_type == NWAM_OBJECT_TYPE_NCU);

	/*
	 * Does object already exist? If not, action is ADD, otherwise REFRESH.
	 */
	switch (nwam_read(hp->nwh_object_type, (char *)dbname, hp->nwh_name, 0,
	    &testhp)) {
	case NWAM_ENTITY_NOT_FOUND:
		action = NWAM_ACTION_ADD;
		break;
	case NWAM_SUCCESS:
		nwam_free(testhp);
		if (hp->nwh_object_type == NWAM_OBJECT_TYPE_NCP)
			return (NWAM_ENTITY_EXISTS);
		/* FALLTHRU */
	default:
		action = NWAM_ACTION_REFRESH;
		break;
	}

	err = nwam_update_object_in_backend((char *)dbname,
	    hp->nwh_object_type == NWAM_OBJECT_TYPE_NCP ? NULL : hp->nwh_name,
	    iflags, hp->nwh_data);
	if (err != NWAM_SUCCESS)
		return (err);

	hp->nwh_committed = B_TRUE;

	/*
	 * Tell nwamd to reread this object.  For NCUs, we need to convert
	 * the dbname to the NCP name in order to pass it to nwamd.
	 */
	if (is_ncu) {
		char *ncpname;

		if (nwam_ncp_file_to_name(dbname, &ncpname) == NWAM_SUCCESS) {
			(void) nwam_request_action(hp->nwh_object_type,
			    hp->nwh_name, ncpname, action);
			free(ncpname);
		}
	} else {
		(void) nwam_request_action(hp->nwh_object_type, hp->nwh_name,
		    NULL, action);
	}
	return (NWAM_SUCCESS);
}

static boolean_t
nwam_is_active(struct nwam_handle *hp)
{
	nwam_state_t state;
	nwam_aux_state_t aux;

	return ((nwam_get_state(NULL, hp, &state, &aux) == NWAM_SUCCESS &&
	    state == NWAM_STATE_ONLINE));
}

nwam_error_t
nwam_destroy(const char *dbname, struct nwam_handle *hp, uint64_t flags)
{
	nwam_error_t err;
	char *name;
	boolean_t is_ncp, is_ncu;

	assert(hp != NULL);

	/* NWAM_FLAG_ENTITY_KNOWN_WLAN is only used for Known WLANs */
	if ((err = nwam_valid_flags(flags,
	    NWAM_FLAG_BLOCKING | NWAM_FLAG_DO_NOT_FREE |
	    (hp->nwh_object_type == NWAM_OBJECT_TYPE_KNOWN_WLAN ?
	    NWAM_FLAG_ENTITY_KNOWN_WLAN : 0))) != NWAM_SUCCESS)
		return (err);

	is_ncp = hp->nwh_object_type == NWAM_OBJECT_TYPE_NCP;
	is_ncu = hp->nwh_object_type == NWAM_OBJECT_TYPE_NCU;
	name = hp->nwh_name;

	/* Check if object is active */
	if (!is_ncp && !is_ncu && nwam_is_active(hp))
		return (NWAM_ENTITY_IN_USE);

	/* For NCPs, just remove the dbname file, otherwise remove the object */
	err = nwam_remove_object_from_backend((char *)dbname,
	    is_ncp ? NULL : name, flags);

	/*
	 * Tell nwamd to remove this object.  For NCUs, we need to convert the
	 * dbname filename to the NCP name to pass it to nwamd.
	 */
	if (is_ncu) {
		char *ncpname;

		if (nwam_ncp_file_to_name(dbname, &ncpname) == NWAM_SUCCESS) {
			(void) nwam_request_action(hp->nwh_object_type, name,
			    ncpname, NWAM_ACTION_DESTROY);
			free(ncpname);
		}
	} else {
		(void) nwam_request_action(hp->nwh_object_type, name, NULL,
		    NWAM_ACTION_DESTROY);
	}

	if ((err == NWAM_SUCCESS) && !(flags & NWAM_FLAG_DO_NOT_FREE))
		nwam_free(hp);

	return (err);
}

/*
 * Enable/disable functions assume prior checking of activation mode
 * to ensure an enable/disable action is valid for the object. "parent" in these
 * functions specifies the NCP for NCUs.
 */
nwam_error_t
nwam_enable(const char *parent, struct nwam_handle *hp)
{
	return (nwam_request_action(hp->nwh_object_type, hp->nwh_name,
	    parent, NWAM_ACTION_ENABLE));
}

nwam_error_t
nwam_disable(const char *parent, struct nwam_handle *hp)
{
	return (nwam_request_action(hp->nwh_object_type, hp->nwh_name,
	    parent, NWAM_ACTION_DISABLE));
}

nwam_error_t
nwam_get_state(const char *parent, struct nwam_handle *hp, nwam_state_t *statep,
    nwam_aux_state_t *auxp)
{
	return (nwam_request_state(hp->nwh_object_type, hp->nwh_name, parent,
	    statep, auxp));
}

struct nwam_prop_table_entry *
nwam_get_prop_table_entry(struct nwam_prop_table table, const char *propname)
{
	struct nwam_prop_table_entry *cur = table.entries;
	struct nwam_prop_table_entry *end = cur + table.num_entries;

	assert(propname != NULL);

	for (; cur < end; cur++) {
		if (strcmp(propname, cur->prop_name) == 0)
			return (cur);
	}
	return (NULL);
}

nwam_error_t
nwam_get_prop_description(struct nwam_prop_table table, const char *propname,
    const char **descriptionp)
{
	struct nwam_prop_table_entry *pte;

	assert(propname != NULL && descriptionp != NULL);

	if ((pte = nwam_get_prop_table_entry(table, propname)) == NULL) {
		*descriptionp = NULL;
		return (NWAM_INVALID_ARG);
	}

	*descriptionp = dgettext(TEXT_DOMAIN, pte->prop_description);
	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_get_prop_type(struct nwam_prop_table table, const char *propname,
    nwam_value_type_t *typep)
{
	struct nwam_prop_table_entry *pte;

	assert(propname != NULL && typep != NULL);

	if ((pte = nwam_get_prop_table_entry(table, propname)) == NULL)
		return (NWAM_INVALID_ARG);

	*typep = pte->prop_type;

	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_prop_multivalued(struct nwam_prop_table table, const char *propname,
    boolean_t *multip)
{
	struct nwam_prop_table_entry *pte;

	assert(propname != NULL && multip != NULL);

	if ((pte = nwam_get_prop_table_entry(table, propname)) == NULL)
		return (NWAM_INVALID_ARG);

	if (pte->prop_max_numvalues > 1)
		*multip = B_TRUE;
	else
		*multip = B_FALSE;

	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_prop_read_only(struct nwam_prop_table table, const char *propname,
    boolean_t *readp)
{
	struct nwam_prop_table_entry *pte;

	assert(propname != NULL && readp != NULL);

	if ((pte = nwam_get_prop_table_entry(table, propname)) == NULL)
		return (NWAM_INVALID_ARG);

	*readp = (pte->prop_is_readonly && !nwam_uid_is_netadm());

	return (NWAM_SUCCESS);
}

/*
 * Structure used to pass in prop table and errprop string pointer to internal
 * validate function.
 */
struct validate_internal_arg {
	struct nwam_prop_table table;
	const char **errpropp;
};

/*
 * Callback used by nwam_walk_props() in nwam_validate(), and
 * by nwam_validate_prop() to determine that the number, type and
 * range of values are correct, and that validation function (if present)
 * succeeds.
 */
static int
nwam_validate_prop_internal(const char *propname, nwam_value_t value,
    void *arg)
{
	struct validate_internal_arg *via = arg;
	struct nwam_prop_table table = via->table;
	const char **errpropp = via->errpropp;
	struct nwam_prop_table_entry *pte;
	nwam_error_t err;
	nwam_value_type_t type;
	uint_t numvalues;
	int i;

	if ((err = nwam_value_get_numvalues(value, &numvalues))
	    != NWAM_SUCCESS ||
	    (err = nwam_value_get_type(value, &type)) != NWAM_SUCCESS) {
		if (errpropp != NULL)
			*errpropp = propname;
		return (err);
	}
	if ((pte = nwam_get_prop_table_entry(table, propname)) == NULL)
		return (NWAM_INVALID_ARG);

	/* have we get expected number of values? */
	if (numvalues < pte->prop_min_numvalues ||
	    numvalues > pte->prop_max_numvalues) {
		if (errpropp != NULL)
			*errpropp = propname;
		if (numvalues < 1)
			return (NWAM_ENTITY_NO_VALUE);
		else
			return (NWAM_ENTITY_INVALID_VALUE);
	}
	/* Ensure type matches */
	if (numvalues > 0) {
		for (i = 0; i < numvalues; i++) {
			if (pte->prop_type != type) {
				if (errpropp != NULL)
					*errpropp = propname;
				return (NWAM_ENTITY_TYPE_MISMATCH);

			}
		}
	}
	/* Call property-specific validation function */
	if (pte->prop_validate != NULL) {
		err = pte->prop_validate(value);
		if (err != NWAM_SUCCESS && errpropp != NULL)
			*errpropp = propname;
		return (err);
	}

	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_validate_prop(struct nwam_prop_table table, struct nwam_handle *hp,
    const char *propname, nwam_value_t value)
{
	struct validate_internal_arg via;

	assert(hp != NULL && propname != NULL);

	via.table = table;
	via.errpropp = NULL;

	return ((nwam_error_t)nwam_validate_prop_internal(propname,
	    value, &via));
}

nwam_error_t
nwam_validate(struct nwam_prop_table table, struct nwam_handle *hp,
    const char **errpropp)
{
	struct validate_internal_arg via;
	nwam_error_t err1, err2;

	assert(hp != NULL);

	via.table = table;
	via.errpropp = errpropp;

	err1 = nwam_walk_props(hp, nwam_validate_prop_internal, &via,
	    0, (int *)&err2);
	if (err1 != NWAM_SUCCESS)
		return (err2);
	return (NWAM_SUCCESS);
}

/*
 * Given the type and class flag representations, return the list of properties
 * that can be set for that type/class combination. Note this list is a complete
 * property list that includes both the required and the optional properties.
 * The type and class flags are only used for NCU objects at present.
 *
 * Caller needs to free prop_list.
 */
nwam_error_t
nwam_get_default_proplist(struct nwam_prop_table table,
    uint64_t type, uint64_t class, const char ***prop_list, uint_t *numvalues)
{
	struct nwam_prop_table_entry *cur = table.entries;
	struct nwam_prop_table_entry *end = cur + table.num_entries;
	int i = 0;
	const char **list = NULL;

	assert(prop_list != NULL && numvalues != NULL);

	/* Construct a list of all properties for required type/class */
	list = calloc(table.num_entries, sizeof (char *));
	if (list == NULL) {
		*prop_list = NULL;
		*numvalues = 0;
		return (NWAM_NO_MEMORY);
	}
	for (; cur < end; cur++) {
		if (((type & cur->prop_type_membership) == 0) ||
		    ((class & cur->prop_class_membership) == 0))
			continue;
		list[i++] = cur->prop_name;
	}
	*numvalues = i;
	*prop_list = list;
	return (NWAM_SUCCESS);
}
