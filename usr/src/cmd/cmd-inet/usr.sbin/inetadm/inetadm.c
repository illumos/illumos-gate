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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * inetadm - administer services controlled by inetd and print out inetd
 * service related information.
 */

#include <locale.h>
#include <libintl.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <libuutil.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <inetsvc.h>
#include <errno.h>

#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif /* TEXT_DOMAIN */

/* Strings for output to the user, and checking user's input */

#define	INETADM_TRUE_STR		"TRUE"
#define	INETADM_FALSE_STR		"FALSE"
#define	INETADM_ENABLED_STR		"enabled"
#define	INETADM_DISABLED_STR		"disabled"
#define	INETADM_DEFAULT_STR		"default"

/* String for checking if an instance is under inetd's control. */

#define	INETADM_INETD_STR		"network/inetd"

/*
 * Used to hold a list of scf_value_t's whilst performing a transaction
 * to write a proto list back.
 */
typedef struct scf_val_el {
	scf_value_t		*val;
	uu_list_node_t		link;
} scf_val_el_t;

/*
 * Structure used to encapsulate argc and argv so they can be passed using the
 * single data argument supplied by scf_walk_fmri() for the consumption of
 * modify_inst_props_cb().
 */
typedef struct arglist {
	int	argc;
	char	**argv;
} arglist_t;

static scf_handle_t *h;

static void
scfdie()
{
	uu_die(gettext("Unexpected libscf error: %s.  Exiting.\n"),
	    scf_strerror(scf_error()));
}

static void
usage(boolean_t detailed)
{

	uu_warn(gettext(
	    "Usage:\n"
	    "  inetadm\n"
	    "  inetadm -?\n"
	    "  inetadm -p\n"
	    "  inetadm -l {FMRI | pattern}...\n"
	    "  inetadm -e {FMRI | pattern}...\n"
	    "  inetadm -d {FMRI | pattern}...\n"
	    "  inetadm -m {FMRI | pattern}... {name=value}...\n"
	    "  inetadm -M {name=value}...\n"));

	if (!detailed)
		exit(UU_EXIT_USAGE);

	(void) fprintf(stdout, gettext(
	    "\n"
	    "Without any options inetadm lists all inetd managed services.\n"
	    "\n"
	    "Options:\n"
	    "  -?	Print help.\n"
	    "  -p	List all default inetd property values.\n"
	    "  -l 	List all inetd property values for the inet "
	    "service(s).\n"
	    "  -e	Enable the inet service(s).\n"
	    "  -d	Disable the inet service(s).\n"
	    "  -m	Modify the inet service(s) inetd property values.\n"
	    "  -M	Modify default inetd property values.\n"));
}

/*
 * Add the proto list contained in array 'plist' to entry 'entry', storing
 * aside the scf_value_t's created and added to the entry in a list that the
 * pointer referenced by sv_list is made to point at.
 */
static void
add_proto_list(scf_transaction_entry_t *entry, scf_handle_t *hdl,
    char **plist, uu_list_t **sv_list)
{
	scf_val_el_t		*sv_el;
	int			i;

	static uu_list_pool_t	*sv_pool = NULL;

	if ((sv_pool == NULL) &&
	    ((sv_pool = uu_list_pool_create("sv_pool",
	    sizeof (scf_val_el_t), offsetof(scf_val_el_t, link), NULL,
	    UU_LIST_POOL_DEBUG)) == NULL))
		uu_die(gettext("Error: %s.\n"), uu_strerror(uu_error()));

	if ((*sv_list = uu_list_create(sv_pool, NULL, 0)) == NULL)
		uu_die(gettext("Error: %s.\n"), uu_strerror(uu_error()));

	for (i = 0; plist[i] != NULL; i++) {
		if ((sv_el = malloc(sizeof (scf_val_el_t))) == NULL)
			uu_die(gettext("Error:"));

		if (((sv_el->val = scf_value_create(hdl)) == NULL) ||
		    (scf_value_set_astring(sv_el->val, plist[i]) != 0) ||
		    (scf_entry_add_value(entry, sv_el->val) != 0))
			scfdie();

		uu_list_node_init(sv_el, &sv_el->link, sv_pool);
		(void) uu_list_insert_after(*sv_list, NULL, sv_el);
	}
}

/*
 * A counterpart to add_proto_list(), this function removes and frees the
 * scf_value_t's it added to entry 'entry'.
 */
static void
remove_proto_list(scf_transaction_entry_t *entry, uu_list_t *sv_list)
{
	scf_val_el_t	*sv_el;
	void		*cookie = NULL;

	scf_entry_reset(entry);

	while ((sv_el = uu_list_teardown(sv_list, &cookie)) != NULL) {
		scf_value_destroy(sv_el->val);
		free(sv_el);
	}

	uu_list_destroy(sv_list);
}

/*
 * modify_prop takes an instance, property group, property name, type, and
 * value, and modifies the specified property in the repository to the
 * submitted value.
 */

static void
modify_prop(const scf_instance_t *inst, const char *pg, const char *prop,
    scf_type_t type, void *value)
{
	scf_transaction_t		*tx;
	scf_transaction_entry_t		*ent;
	scf_propertygroup_t		*gpg;
	scf_property_t			*eprop;
	scf_value_t			*v;
	int				ret, create = 0;
	char				*fmri;
	ssize_t				max_fmri_len;

	if ((gpg = scf_pg_create(h)) == NULL ||
	    (eprop = scf_property_create(h)) == NULL ||
	    (v = scf_value_create(h)) == NULL)
		scfdie();

	/* Get the property group or create it if it is missing. */
	if (scf_instance_get_pg(inst, pg, gpg) == -1) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();

		max_fmri_len = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH);
		if ((fmri = malloc(max_fmri_len + 1)) == NULL)
			uu_die(gettext("Error: Out of memory.\n"));

		if (scf_instance_to_fmri(inst, fmri, max_fmri_len + 1) < 0)
			scfdie();

		syslog(LOG_NOTICE, "inetadm: Property group \"%s\" missing "
		    "from \"%s\", attempting to add it.\n", pg, fmri);
		free(fmri);

		if (scf_instance_add_pg(inst, pg, SCF_GROUP_FRAMEWORK, 0,
		    gpg) == -1) {
			switch (scf_error()) {
			case SCF_ERROR_EXISTS:
				break;
			case SCF_ERROR_PERMISSION_DENIED:
				uu_die(gettext("Error: Permission denied.\n"));
			default:
				scfdie();
			}
		}
	}

	if (scf_pg_get_property(gpg, prop, eprop) == -1) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();

		create = 1;
	}

	if ((tx = scf_transaction_create(h)) == NULL ||
	    (ent = scf_entry_create(h)) == NULL)
		scfdie();

	do {
		uu_list_t	*sv_list;

		if (scf_transaction_start(tx, gpg) == -1) {
			if (scf_error() != SCF_ERROR_PERMISSION_DENIED)
				scfdie();

			uu_die(gettext("Error: Permission denied.\n"));
		}

		/* Modify the property or create it if it is missing */
		if (create)
			ret = scf_transaction_property_new(tx, ent, prop, type);
		else
			ret = scf_transaction_property_change_type(tx, ent,
			    prop, type);
		if (ret == -1)
			scfdie();

		switch (type) {
		case SCF_TYPE_BOOLEAN:
			scf_value_set_boolean(v, *(uint8_t *)value);
			break;
		case SCF_TYPE_INTEGER:
			scf_value_set_integer(v, *(int64_t *)value);
			break;
		case SCF_TYPE_ASTRING:
			if (strcmp(prop, PR_PROTO_NAME) == 0) {
				add_proto_list(ent, h, (char **)value,
				    &sv_list);
			} else if (scf_value_set_astring(v, value) == -1) {
				scfdie();
			}
			break;
		default:
			uu_die(gettext("Error: Internal inetadm error"));
		}

		if ((strcmp(prop, PR_PROTO_NAME) != 0) &&
		    (scf_entry_add_value(ent, v) == -1))
			scfdie();

		ret = scf_transaction_commit(tx);
		if (ret == -1) {
			if (scf_error() != SCF_ERROR_PERMISSION_DENIED)
				scfdie();

			uu_die(gettext("Error: Permission denied.\n"));
		}

		scf_transaction_reset(tx);

		if (ret == 0) {
			if (scf_pg_update(gpg) == -1)
				scfdie();
		}

		if (strcmp(prop, PR_PROTO_NAME) == 0)
			remove_proto_list(ent, sv_list);

	} while (ret == 0);

	scf_value_destroy(v);
	scf_entry_destroy(ent);
	scf_transaction_destroy(tx);
	scf_property_destroy(eprop);
	scf_pg_destroy(gpg);
}

/*
 * delete_prop takes an instance, property group name and property, and
 * deletes the specified property from the repository.
 */

static void
delete_prop(const scf_instance_t *inst, const char *pg, const char *prop)
{
	scf_transaction_t		*tx;
	scf_transaction_entry_t		*ent;
	scf_propertygroup_t		*gpg;
	scf_property_t			*eprop;
	int				ret;

	if ((gpg = scf_pg_create(h)) == NULL ||
	    (eprop = scf_property_create(h)) == NULL ||
	    (tx = scf_transaction_create(h)) == NULL ||
	    (ent = scf_entry_create(h)) == NULL)
		scfdie();

	if (scf_instance_get_pg(inst, pg, gpg) != SCF_SUCCESS) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();

		uu_die(gettext("Error: \"%s\" property group missing.\n"), pg);
	}

	do {
		if (scf_transaction_start(tx, gpg) != SCF_SUCCESS) {
			if (scf_error() != SCF_ERROR_PERMISSION_DENIED)
				scfdie();

			uu_die(gettext("Error: Permission denied.\n"));
		}

		if (scf_transaction_property_delete(tx, ent,
		    prop) != SCF_SUCCESS) {
			if (scf_error() != SCF_ERROR_NOT_FOUND)
				scfdie();

			uu_die(
			    gettext("Error: \"%s\" property does not exist.\n"),
			    prop);
		}

		ret = scf_transaction_commit(tx);
		if (ret < 0) {
			if (scf_error() != SCF_ERROR_PERMISSION_DENIED)
				scfdie();

			uu_die(gettext("Error: Permission denied.\n"));
		}
		if (ret == 0) {
			scf_transaction_reset(tx);
			if (scf_pg_update(gpg) == -1)
				scfdie();
		}
	} while (ret == 0);

	(void) scf_entry_destroy(ent);
	scf_transaction_destroy(tx);
	scf_property_destroy(eprop);
	scf_pg_destroy(gpg);
}

/*
 * commit_props evaluates an entire property list that has been created
 * based on command line options, and either deletes or modifies properties
 * as requested.
 */

static void
commit_props(const scf_instance_t *inst, inetd_prop_t *mod, boolean_t defaults)
{
	int			i;
	uint8_t			new_bool;

	for (i = 0; mod[i].ip_name != NULL; i++) {
		switch (mod[i].ip_error) {
		case IVE_UNSET:
			break;
		case IVE_INVALID:
			delete_prop(inst, mod[i].ip_pg, mod[i].ip_name);
			break;
		case IVE_VALID:
			switch (mod[i].ip_type) {
			case INET_TYPE_STRING:
				modify_prop(inst,
				    defaults ? PG_NAME_SERVICE_DEFAULTS :
				    mod[i].ip_pg, mod[i].ip_name,
				    SCF_TYPE_ASTRING,
				    mod[i].ip_value.iv_string);
				break;
			case INET_TYPE_STRING_LIST:
				modify_prop(inst,
				    defaults ? PG_NAME_SERVICE_DEFAULTS :
				    mod[i].ip_pg, mod[i].ip_name,
				    SCF_TYPE_ASTRING,
				    mod[i].ip_value.iv_string_list);
				break;
			case INET_TYPE_INTEGER:
				modify_prop(inst,
				    defaults ? PG_NAME_SERVICE_DEFAULTS :
				    mod[i].ip_pg, mod[i].ip_name,
				    SCF_TYPE_INTEGER, &mod[i].ip_value.iv_int);
				break;
			case INET_TYPE_BOOLEAN:
				new_bool = (mod[i].ip_value.iv_boolean) ? 1 : 0;

				modify_prop(inst,
				    defaults ? PG_NAME_SERVICE_DEFAULTS :
				    mod[i].ip_pg, mod[i].ip_name,
				    SCF_TYPE_BOOLEAN, &new_bool);
				break;
			}
		}
	}
}

/*
 * list_callback is the callback function to be handed to simple_walk_instances
 * in list_services.  It is called once on every instance on a machine.  If
 * that instance is controlled by inetd, it prints enabled/disabled, state,
 * and instance FMRI.
 */

/*ARGSUSED*/
static int
list_callback(scf_handle_t *hin, scf_instance_t *inst, void *buf)
{
	ssize_t			max_name_length;
	char			*inst_name;
	scf_simple_prop_t	*prop = NULL, *prop2 = NULL;
	const uint8_t		*enabled;
	const char		*state, *restart_str;

	max_name_length = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH);
	if ((inst_name = malloc(max_name_length + 1)) == NULL)
		uu_die(gettext("Error: Out of memory.\n"));

	/*
	 * Get the FMRI of the instance, and check if its delegated restarter
	 * is inetd.
	 */

	if (scf_instance_to_fmri(inst, inst_name, max_name_length + 1) < 0)
		return (SCF_FAILED);

	if ((prop = scf_simple_prop_get(hin, inst_name, SCF_PG_GENERAL,
	    SCF_PROPERTY_RESTARTER)) == NULL)
		goto out;

	if ((restart_str = scf_simple_prop_next_ustring(prop)) == NULL)
		goto out;

	if (strstr(restart_str, INETADM_INETD_STR) == NULL)
		goto out;

	/* Free restarter prop so it can be reused below */
	scf_simple_prop_free(prop);

	/*
	 * We know that this instance is managed by inetd.
	 * Now get the enabled and state properties.
	 */

	if (((prop = scf_simple_prop_get(hin, inst_name, SCF_PG_GENERAL,
	    SCF_PROPERTY_ENABLED)) == NULL) ||
	    ((enabled = scf_simple_prop_next_boolean(prop)) == NULL)) {
		(void) uu_warn(gettext("Error: Instance %s is missing enabled "
		    "property.\n"), inst_name);
		goto out;
	}

	if (((prop2 = scf_simple_prop_get(hin, inst_name, SCF_PG_RESTARTER,
	    SCF_PROPERTY_STATE)) == NULL) ||
	    ((state = scf_simple_prop_next_astring(prop2)) == NULL)) {
		(void) uu_warn(gettext("Error: Instance %s is missing state "
		    "property.\n"), inst_name);
		goto out;
	}

	/* Print enabled/disabled, state, and FMRI for the instance. */

	if (*enabled)
		(void) printf("%-10s%-15s%s\n", INETADM_ENABLED_STR, state,
		    inst_name);
	else
		(void) printf("%-10s%-15s%s\n", INETADM_DISABLED_STR, state,
		    inst_name);

out:
	free(inst_name);
	scf_simple_prop_free(prop);
	scf_simple_prop_free(prop2);
	return (SCF_SUCCESS);
}

/*
 * list_services calls list_callback on every instance on the machine.
 */

static void
list_services()
{
	(void) printf("%-10s%-15s%s\n", "ENABLED", "STATE", "FMRI");

	if (scf_simple_walk_instances(SCF_STATE_ALL, NULL, list_callback) ==
	    SCF_FAILED)
		scfdie();
}

static void
print_prop_val(inetd_prop_t *prop)
{
	switch (prop->ip_type) {
	case INET_TYPE_STRING:
		(void) printf("\"%s\"\n", prop->ip_value.iv_string);
		break;
	case INET_TYPE_STRING_LIST:
		{
			int	j = 0;
			char	**cpp = prop->ip_value.iv_string_list;

			/*
			 * Print string list as comma separated list.
			 */

			(void) printf("\"%s", cpp[j]);
			while (cpp[++j] != NULL)
				(void) printf(",%s", cpp[j]);
			(void) printf("\"\n");
		}
		break;
	case INET_TYPE_INTEGER:
		(void) printf("%lld\n", prop->ip_value.iv_int);
		break;
	case INET_TYPE_BOOLEAN:
		if (prop->ip_value.iv_boolean)
			(void) printf("%s\n", INETADM_TRUE_STR);
		else
			(void) printf("%s\n", INETADM_FALSE_STR);
		break;
	}
}

/*
 * list_props_cb is a callback function for scf_walk_fmri that lists all
 * relevant inetd properties for an instance managed by inetd.
 */

/* ARGSUSED0 */
static int
list_props_cb(void *data, scf_walkinfo_t *wip)
{
	int			i;
	const char		*instname = wip->fmri;
	scf_simple_prop_t	*prop;
	inetd_prop_t		*proplist;
	const char		*restart_str;
	boolean_t		is_rpc = B_FALSE;
	size_t			numprops;
	scf_handle_t		*h;
	scf_error_t		err;

	if (((h = scf_handle_create(SCF_VERSION)) == NULL) ||
	    (scf_handle_bind(h) == -1))
		scfdie();

	/*
	 * Get the property that holds the name of this instance's
	 * restarter, and make sure that it is inetd.
	 */
	if ((prop = scf_simple_prop_get(h, instname, SCF_PG_GENERAL,
	    SCF_PROPERTY_RESTARTER)) == NULL) {
		if (scf_error() == SCF_ERROR_NOT_FOUND)
			uu_die(gettext("Error: Specified service instance "
			    "\"%s\" has no restarter property.  inetd is not "
			    "the delegated restarter of this instance.\n"),
			    instname);
		if (scf_error() == SCF_ERROR_INVALID_ARGUMENT)
			uu_die(gettext("Error: \"%s\" is not a valid service "
			    "instance.\n"), instname);

		scfdie();
	}

	if (((restart_str = scf_simple_prop_next_ustring(prop)) == NULL) ||
	    (strstr(restart_str, INETADM_INETD_STR) == NULL)) {
		uu_die(gettext("Error: inetd is not the delegated restarter of "
		    "specified service instance \"%s\".\n"), instname);
	}

	scf_simple_prop_free(prop);

	/*
	 * This instance is controlled by inetd, so now we display all
	 * of its properties.  First the mandatory properties, and then
	 * the properties that have default values, substituting the
	 * default values inherited from inetd as necessary (this is done
	 * for us by read_instance_props()).
	 */

	if ((proplist = read_instance_props(h, instname, &numprops, &err)) ==
	    NULL) {
		uu_die(gettext("Unexpected libscf error: %s.  Exiting.\n"),
		    scf_strerror(err));
	}
	scf_handle_destroy(h);

	(void) printf("%-9s%s\n", "SCOPE", "NAME=VALUE");

	for (i = 0; i < numprops; i++) {
		/* Skip rpc version properties if it's not an RPC service */
		if ((strcmp(PR_RPC_LW_VER_NAME, proplist[i].ip_name) == 0) ||
		    (strcmp(PR_RPC_HI_VER_NAME, proplist[i].ip_name) == 0))
			if (!is_rpc)
				continue;

		/* If it's not an unset property, print it out. */
		if (proplist[i].ip_error != IVE_UNSET) {
			if (strcmp(PR_ISRPC_NAME, proplist[i].ip_name) == 0)
				is_rpc = proplist[i].ip_value.iv_boolean;

			(void) printf("%-9s%s=",
			    proplist[i].from_inetd ? INETADM_DEFAULT_STR : "",
			    proplist[i].ip_name);
			print_prop_val(&proplist[i]);
			continue;
		}

		/* arg0 is non-default, but also doesn't have to be set. */

		if (i == PT_ARG0_INDEX)
			continue;

		/* all other properties should have values. */
		if (proplist[i].ip_default) {
			(void) uu_warn(gettext("Error: Property %s is missing "
			    "and has no defined default value.\n"),
			    proplist[i].ip_name);
		} else {
			(void) uu_warn(gettext("Error: Required property %s is "
			    "missing.\n"), proplist[i].ip_name);
		}
	}

	free_instance_props(proplist);
	return (0);
}

/*
 * set_svc_enable_cb is a callback function for scf_walk_fmri that sets the
 * enabled property in the repository for an instance based on the value given
 * by 'data'.
 */

static int
set_svc_enable_cb(void *data, scf_walkinfo_t *wip)
{
	uint8_t			desired = *(uint8_t *)data;
	const char		*instname = wip->fmri;

	if (desired) {
		if (smf_enable_instance(instname, 0) == 0)
			return (0);
	} else {
		if (smf_disable_instance(instname, 0) == 0)
			return (0);
	}

	switch (scf_error()) {
	case SCF_ERROR_INVALID_ARGUMENT:
		uu_die(gettext("Error: \"%s\" is not a valid service "
		    "instance.\n"), instname);
		break;
	case SCF_ERROR_NOT_FOUND:
		uu_die(gettext("Error: Service instance \"%s\" not found.\n"),
		    instname);
		break;
	default:
		scfdie();
	}

	return (0);
}

/*
 * list_defaults lists all the default property values being provided by
 * inetd.
 */

static void
list_defaults()
{
	scf_handle_t		*h;
	scf_error_t		err;
	int			i;
	inetd_prop_t		*proptable;
	size_t			numprops;

	if (((h = scf_handle_create(SCF_VERSION)) == NULL) ||
	    (scf_handle_bind(h) == -1))
		scfdie();

	if ((proptable = read_default_props(h, &numprops, &err)) == NULL) {
		uu_die(gettext("Unexpected libscf error: %s.  Exiting.\n"),
		    scf_strerror(err));
	}

	(void) printf("NAME=VALUE\n");

	for (i = 0; i < numprops; i++) {
		if (!proptable[i].ip_default)
			continue;

		if (proptable[i].ip_error == IVE_UNSET) {
			(void) uu_warn(gettext("Error: Default property %s "
			    "missing.\n"), proptable[i].ip_name);
			continue;
		}

		(void) printf("%s=", proptable[i].ip_name);
		print_prop_val(&proptable[i]);
	}

	free_instance_props(proptable);
}

/*
 * modify_inst_props_cb is a callback function for scf_walk_fmri that modifies
 * the properties that are given as name=value pairs on the command line
 * to the requested value.
 */

static int
modify_inst_props_cb(void *data, scf_walkinfo_t *wip)
{
	int			i, j;
	char			*value;
	const char		*fmri = wip->fmri;
	scf_instance_t		*inst = wip->inst;
	inetd_prop_t		*mod, *prop_table;
	size_t			numprops;
	ssize_t			max_val;
	int64_t			new_int;
	int			argc = ((arglist_t *)data)->argc;
	char			**argv = ((arglist_t *)data)->argv;

	if ((max_val = scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH)) < 0)
		scfdie();

	prop_table = get_prop_table(&numprops);

	if ((mod = malloc(numprops * sizeof (inetd_prop_t))) == NULL)
		uu_die(gettext("Error: Out of memory.\n"));

	(void) memcpy(mod, prop_table, numprops * sizeof (inetd_prop_t));

	/*
	 * For each property to be changed, look up the property name in the
	 * property table.  Change each property in the mod array, and then
	 * write the entire thing back.
	 */
	for (i = 0; i < argc; i++) {
		/* Separate argument into name and value pair */
		if ((value = strchr(argv[i], '=')) == NULL)
			uu_die(gettext("Error: Malformed name=value pair "
			    "\"%s\"\n"), argv[i]);

		*value = '\0';
		value++;

		/* Find property name in array of properties */
		for (j = 0; mod[j].ip_name != NULL; j++) {
			if (strcmp(mod[j].ip_name, argv[i]) == 0)
				break;
		}

		if (mod[j].ip_name == NULL)
			uu_die(gettext("Error: \"%s\" is not a valid "
			    "property.\n"), argv[i]);

		if (*value == '\0') {
			if ((mod[j].ip_default) || (j == PT_ARG0_INDEX)) {
				/* mark property for deletion */
				mod[j].ip_error = IVE_INVALID;

				/* return the '=' taken out above */
				*(--value) = '=';

				continue;
			} else {
				uu_die(gettext("\"%s\" is a mandatory "
				    "property and can not be deleted.\n"),
				    argv[i]);
			}
		}

		switch (mod[j].ip_type) {
		case INET_TYPE_INTEGER:
			if (uu_strtoint(value, &new_int, sizeof (new_int), NULL,
			    NULL, NULL) == -1)
				uu_die(gettext("Error: \"%s\" is not a valid "
				    "integer value.\n"), value);

			mod[j].ip_value.iv_int = new_int;
			break;
		case INET_TYPE_STRING:
			if (strlen(value) >= max_val) {
				uu_die(gettext("Error: String value is longer "
				    "than %l characters.\n"), max_val);
			} else if ((mod[j].ip_value.iv_string = strdup(value))
			    == NULL) {
				uu_die(gettext("Error: Out of memory.\n"));
			}
			break;
		case INET_TYPE_STRING_LIST:
			if ((mod[j].ip_value.iv_string_list =
			    get_protos(value)) == NULL) {
				if (errno == ENOMEM) {
					uu_die(gettext(
					    "Error: Out of memory.\n"));
				} else if (errno == E2BIG) {
					uu_die(gettext(
					    "Error: String value in "
					    "%s property longer than "
					    "%l characters.\n"),
					    PR_PROTO_NAME, max_val);
				} else {
					uu_die(gettext(
					    "Error: No values "
					    "specified for %s "
					    "property.\n"),
					    PR_PROTO_NAME);
				}
			}
			break;
		case INET_TYPE_BOOLEAN:
			if (strcasecmp(value, INETADM_TRUE_STR) == 0)
				mod[j].ip_value.iv_boolean = B_TRUE;
			else if (strcasecmp(value, INETADM_FALSE_STR) == 0)
				mod[j].ip_value.iv_boolean = B_FALSE;
			else
				uu_die(gettext("Error: \"%s\" is not a valid "
				    "boolean value. (TRUE or FALSE)\n"), value);
		}
		/* mark property for modification */
		mod[j].ip_error = IVE_VALID;

		/* return the '=' taken out above */
		*(--value) = '=';
	}

	commit_props(inst, mod, B_FALSE);
	free(mod);
	if (smf_refresh_instance(fmri) != 0)
		uu_die(gettext("Error: Unable to refresh instance %s.\n"),
		    fmri);

	return (0);
}

/*
 * modify_defaults takes n name=value pairs for inetd default property values,
 * parses them, and then modifies the values in the repository.
 */

static void
modify_defaults(int argc, char *argv[])
{
	int			i, j;
	char			*value;
	scf_instance_t		*inst;
	inetd_prop_t		*mod, *prop_table;
	size_t			numprops;
	ssize_t			max_val;
	int64_t			new_int;

	if ((inst = scf_instance_create(h)) == NULL)
		scfdie();

	if (scf_handle_decode_fmri(h, INETD_INSTANCE_FMRI, NULL, NULL,
	    inst, NULL, NULL, SCF_DECODE_FMRI_EXACT) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			uu_die(gettext("inetd instance missing in repository."
			    "\n"));
		} else {
			scfdie();
		}
	}

	if ((max_val = scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH)) < 0)
		scfdie();

	prop_table = get_prop_table(&numprops);

	if ((mod = malloc(numprops * sizeof (inetd_prop_t))) == NULL)
		uu_die(gettext("Error: Out of memory.\n"));

	(void) memcpy(mod, prop_table, numprops * sizeof (inetd_prop_t));

	for (i = 0; i < argc; i++) {
		/* Separate argument into name and value pair */
		if ((value = strchr(argv[i], '=')) == NULL)
			uu_die(gettext("Error: Malformed name=value pair \"%s"
			    "\"\n"), argv[i]);

		*value = '\0';
		value++;

		/* Find property name in array of defaults */
		for (j = 0; mod[j].ip_name != NULL; j++) {
			if (!mod[j].ip_default)
				continue;
			if (strcmp(mod[j].ip_name, argv[i]) == 0)
				break;
		}

		if (mod[j].ip_name == NULL)
			uu_die(gettext("Error: \"%s\" is not a default inetd "
			    "property.\n"), argv[i]);

		if (*value == '\0')
			uu_die(gettext("Cannot accept NULL values for default "
			    "properties.\n"));

		switch (mod[j].ip_type) {
		case INET_TYPE_INTEGER:
			if (uu_strtoint(value, &new_int, sizeof (new_int), NULL,
			    NULL, NULL) == -1)
				uu_die(gettext("Error: \"%s\" is not a valid "
				    "integer value.\n"), value);

			mod[j].ip_value.iv_int = new_int;
			break;
		case INET_TYPE_STRING:
			if (strlen(value) >= max_val)
				uu_die(gettext("Error: String value is longer "
				    "than %l characters.\n"), max_val);
			if ((mod[j].ip_value.iv_string = strdup(value))
			    == NULL)
				uu_die(gettext("Error: Out of memory.\n"));
			break;
		case INET_TYPE_BOOLEAN:
			if (strcasecmp(value, INETADM_TRUE_STR) == 0)
				mod[j].ip_value.iv_boolean = B_TRUE;
			else if (strcasecmp(value, INETADM_FALSE_STR) == 0)
				mod[j].ip_value.iv_boolean = B_FALSE;
			else
				uu_die(gettext("Error: \"%s\" is not a valid "
				    "boolean value. (TRUE or FALSE)\n"), value);
		}
		/* mark property for modification */
		mod[j].ip_error = IVE_VALID;
	}

	commit_props(inst, mod, B_TRUE);
	free(mod);
	scf_instance_destroy(inst);
	if (refresh_inetd() != 0)
		uu_warn(gettext("Warning: Unable to refresh inetd.\n"));
}

int
main(int argc, char *argv[])
{
	int		opt;
	uint_t		lflag, eflag, dflag, pflag, mflag, Mflag;
	uint8_t		enable;
	scf_error_t	serr;
	int		exit_status = 0;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if ((h = scf_handle_create(SCF_VERSION)) == NULL)
		scfdie();

	if (scf_handle_bind(h) == -1)
		uu_die(gettext("Error: Couldn't bind to svc.configd.\n"));

	if (argc == 1) {
		list_services();
		goto out;
	}

	lflag = eflag = dflag = pflag = mflag = Mflag = 0;
	while ((opt = getopt(argc, argv, "ledpMm?")) != -1) {
		switch (opt) {
		case 'l':
			lflag = 1;
			break;
		case 'e':
			eflag = 1;
			break;
		case 'd':
			dflag = 1;
			break;
		case 'p':
			pflag = 1;
			break;
		case 'M':
			Mflag = 1;
			break;
		case 'm':
			mflag = 1;
			break;
		case '?':
			if (optopt == '?') {
				usage(B_TRUE);
				goto out;
			} else {
				usage(B_FALSE);
			}
			break;
		default:
			usage(B_FALSE);
		}
	}

	/*
	 * All options are mutually exclusive, and we must have an option
	 * if we reached here.
	 */
	if (lflag + eflag + dflag + pflag + mflag + Mflag != 1)
		usage(B_FALSE);

	argv += optind;
	argc -= optind;
	if ((pflag == 0) && (argc == 0))
		usage(B_FALSE);

	serr = 0;
	if (lflag) {
		serr = scf_walk_fmri(h, argc, argv, 0, list_props_cb, NULL,
		    &exit_status, uu_warn);
	} else if (dflag) {
		enable = 0;
		serr = scf_walk_fmri(h, argc, argv, 0, set_svc_enable_cb,
		    &enable, &exit_status, uu_warn);
	} else if (eflag) {
		enable = 1;
		serr = scf_walk_fmri(h, argc, argv, 0, set_svc_enable_cb,
		    &enable, &exit_status, uu_warn);
	} else if (mflag) {
		arglist_t	args;
		char		**cpp = argv;
		uint_t		fmri_args = 0;

		/* count number of fmri arguments */
		while ((fmri_args < argc) && (strchr(*cpp, '=') == NULL)) {
			fmri_args++;
			cpp++;
		}

		/* if no x=y args or no fmri, show usage */
		if ((fmri_args == argc) || (fmri_args == 0))
			usage(B_FALSE);

		/* setup args for modify_inst_props_cb */
		args.argc = argc - fmri_args;
		args.argv = argv + fmri_args;

		serr = scf_walk_fmri(h, fmri_args, argv, 0,
		    modify_inst_props_cb, &args, &exit_status, uu_warn);
	} else if (Mflag) {
		modify_defaults(argc, argv);
	} else if (pflag) {
		/* ensure there's no trailing garbage */
		if (argc != 0)
			usage(B_FALSE);
		list_defaults();
	}
	if (serr != 0) {
		uu_warn(gettext("failed to iterate over instances: %s"),
		    scf_strerror(serr));
		exit(UU_EXIT_FATAL);
	}

out:
	(void) scf_handle_unbind(h);
	scf_handle_destroy(h);

	return (exit_status);
}
