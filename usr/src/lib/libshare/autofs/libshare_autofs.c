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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * AUTOMOUNT specific functions
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <zone.h>
#include <errno.h>
#include <locale.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include "libshare.h"
#include "libshare_impl.h"
#include <pwd.h>
#include <limits.h>
#include <libscf.h>
#include <strings.h>
#include <libdlpi.h>
#include "smfcfg.h"


static int autofs_init();
static void autofs_fini();
static int autofs_validate_property(sa_handle_t, sa_property_t, sa_optionset_t);
static int autofs_set_proto_prop(sa_property_t);
static sa_protocol_properties_t autofs_get_proto_set();
static char *autofs_get_status();
static uint64_t autofs_features();

static int initautofsprotofromsmf();
static int true_false_validator(int index, char *value);
static int strlen_validator(int index, char *value);
static int range_check_validator(int index, char *value);

/*
 * ops vector that provides the protocol specific info and operations
 * for share management.
 */
struct sa_plugin_ops sa_plugin_ops = {
	SA_PLUGIN_VERSION,
	"autofs",
	autofs_init, 		/* Init autofs */
	autofs_fini, 		/* Fini autofs */
	NULL,			/* Start Sharing */
	NULL,			/* stop sharing */
	autofs_validate_property,
	NULL,			/* valid_space */
	NULL,			/* security_prop */
	NULL,			/* parse optstring */
	NULL,			/* format optstring */
	autofs_set_proto_prop,	/* Set properties */
	autofs_get_proto_set,	/* get properties */
	autofs_get_status,	/* get status */
	NULL,			/* space_alias */
	NULL,			/* update_legacy */
	NULL,			/* delete_legacy */
	NULL,			/* change notify */
	NULL,			/* enable resource */
	NULL,			/* disable resource */
	autofs_features,	/* features */
	NULL,			/* transient shares */
	NULL,			/* notify resource */
	NULL,			/* rename resource */
	NULL,			/* run_command */
	NULL,			/* command_help */
	NULL			/* delete_proto_section */
};


static sa_protocol_properties_t protoset;

#define	AUTOMOUNT_VERBOSE_DEFAULT	0
#define	AUTOMOUNTD_VERBOSE_DEFAULT	0
#define	AUTOMOUNT_NOBROWSE_DEFAULT	0
#define	AUTOMOUNT_TIMEOUT_DEFAULT	600
#define	AUTOMOUNT_TRACE_DEFAULT		0
/*
 * Protocol Management functions
 */
struct proto_option_defs {
	char *tag;
	char *name;	/* display name -- remove protocol identifier */
	int index;
	scf_type_t type;
	union {
	    int intval;
	    char *string;
	} defvalue;
	int32_t minval;
	int32_t maxval;
	int (*check)(int, char *);
} proto_options[] = {
#define	PROTO_OPT_AUTOMOUNT_TIMEOUT	0
	{ "timeout",
	    "timeout",	PROTO_OPT_AUTOMOUNT_TIMEOUT,
	    SCF_TYPE_INTEGER, AUTOMOUNT_TIMEOUT_DEFAULT,
	    1, INT32_MAX, range_check_validator},
#define	PROTO_OPT_AUTOMOUNT_VERBOSE	1
	{ "automount_verbose",
	    "automount_verbose", PROTO_OPT_AUTOMOUNT_VERBOSE,
	    SCF_TYPE_BOOLEAN, AUTOMOUNT_VERBOSE_DEFAULT, 0, 1,
	    true_false_validator},
#define	PROTO_OPT_AUTOMOUNTD_VERBOSE	2
	{ "automountd_verbose",
	    "automountd_verbose", PROTO_OPT_AUTOMOUNTD_VERBOSE,
	    SCF_TYPE_BOOLEAN, AUTOMOUNTD_VERBOSE_DEFAULT, 0, 1,
	    true_false_validator},
#define	PROTO_OPT_AUTOMOUNTD_NOBROWSE	3
	{ "nobrowse",
	    "nobrowse", PROTO_OPT_AUTOMOUNTD_NOBROWSE, SCF_TYPE_BOOLEAN,
	    AUTOMOUNT_NOBROWSE_DEFAULT, 0, 1, true_false_validator},
#define	PROTO_OPT_AUTOMOUNTD_TRACE	4
	{ "trace",
	    "trace", PROTO_OPT_AUTOMOUNTD_TRACE,
	    SCF_TYPE_INTEGER, AUTOMOUNT_TRACE_DEFAULT,
	    0, 20, range_check_validator},
#define	PROTO_OPT_AUTOMOUNTD_ENV	5
	{ "environment",
	    "environment", PROTO_OPT_AUTOMOUNTD_ENV, SCF_TYPE_ASTRING,
	    NULL, 0, 1024, strlen_validator},
	{NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL}
};

#define	AUTOFS_PROP_MAX	(sizeof (proto_options) / sizeof (proto_options[0]))

static void
add_defaults()
{
	int i;
	char number[MAXDIGITS];

	for (i = 0; proto_options[i].tag != NULL; i++) {
		sa_property_t prop;
		prop = sa_get_protocol_property(protoset,
		    proto_options[i].name);
		if (prop == NULL) {
			/* add the default value */
			switch (proto_options[i].type) {
			case SCF_TYPE_INTEGER:
				(void) snprintf(number, sizeof (number), "%d",
				    proto_options[i].defvalue.intval);
				prop = sa_create_property(proto_options[i].name,
				    number);
				break;

			case SCF_TYPE_BOOLEAN:
				prop = sa_create_property(proto_options[i].name,
				    proto_options[i].defvalue.intval ?
				    "true" : "false");
				break;

			default:
				/* treat as strings of zero length */
				prop = sa_create_property(proto_options[i].name,
				    "");
				break;
			}
			if (prop != NULL)
				(void) sa_add_protocol_property(protoset, prop);
		}
	}
}

static int
autofs_init()
{
	int ret = SA_OK;

	if (sa_plugin_ops.sa_init != autofs_init) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "AUTOFS plugin not installed properly\n"));
		return (SA_CONFIG_ERR);
	}

	ret = initautofsprotofromsmf();
	if (ret != SA_OK) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "AUTOFS plugin problem with SMF properties: %s\n"),
		    sa_errorstr(ret));
		ret = SA_OK;
	}
	add_defaults();
	return (ret);
}

static void
free_protoprops()
{
	if (protoset != NULL) {
		xmlFreeNode(protoset);
		protoset = NULL;
	}
}

static void
autofs_fini()
{
	free_protoprops();
}

static int
findprotoopt(char *propname)
{
	int i;

	for (i = 0; proto_options[i].tag != NULL; i++)
		if (strcmp(proto_options[i].name, propname) == 0)
			return (i);
	return (-1);
}

static int
autofs_validate_property(sa_handle_t handle, sa_property_t property,
    sa_optionset_t parent)
{
	int ret = SA_OK;
	char *propname;
	int optionindex;
	char *value;

#ifdef lint
	handle = handle;
	parent = parent;
#endif
	propname = sa_get_property(property, "type");
	if (propname == NULL)
		return (SA_NO_SUCH_PROP);

	if ((optionindex = findprotoopt(propname)) < 0)
		ret = SA_NO_SUCH_PROP;

	if (ret != SA_OK) {
		if (propname != NULL)
			sa_free_attr_string(propname);
		return (ret);
	}

	value = sa_get_property_attr(property, "value");
	if (value != NULL) {
		/*
		 * If any property is added to AUTOFS, which is a different
		 * type than the below list, a case needs to be added for that
		 * to check the values. For now AUTOFS type are just integers,
		 * string and boolean properties. Just taking care of them.
		 */
		switch (proto_options[optionindex].type) {
		case SCF_TYPE_INTEGER:
		case SCF_TYPE_BOOLEAN:
		case SCF_TYPE_ASTRING:
			ret = proto_options[optionindex].check(optionindex,
			    value);
			break;
		default:
			break;
		}
	}

	/* Free the value */
	if (value != NULL)
		sa_free_attr_string(value);
	if (propname != NULL)
		sa_free_attr_string(propname);
	return (ret);
}

/*
 * service_in_state(service, chkstate)
 *
 * Want to know if the specified service is in the desired state
 * (chkstate) or not. Return true (1) if it is and false (0) if it
 * isn't.
 */
static int
service_in_state(char *service, const char *chkstate)
{
	char *state;
	int ret = B_FALSE;

	state = smf_get_state(service);
	if (state != NULL) {
		/* got the state so get the equality for the return value */
		ret = strcmp(state, chkstate) == 0 ? B_TRUE : B_FALSE;
		free(state);
	}
	return (ret);
}

static void
restart_service(char *service)
{
	int ret = -1;

	/*
	 * Only attempt to restart the service if it is
	 * currently running. In the future, it may be
	 * desirable to use smf_refresh_instance if the AUTOFS
	 * services ever implement the refresh method.
	 */
	if (service_in_state(service, SCF_STATE_STRING_ONLINE)) {
		ret = smf_restart_instance(service);
		/*
		 * There are only a few SMF errors at this point, but
		 * it is also possible that a bad value may have put
		 * the service into maintenance if there wasn't an
		 * SMF level error.
		 */
		if (ret != 0) {
			(void) fprintf(stderr,
			    dgettext(TEXT_DOMAIN,
			    "%s failed to restart: %s\n"),
			    scf_strerror(scf_error()));
		} else {
			/*
			 * Check whether it has gone to "maintenance"
			 * mode or not. Maintenance implies something
			 * went wrong.
			 */
			if (service_in_state(service,
			    SCF_STATE_STRING_MAINT)) {
				(void) fprintf(stderr,
				    dgettext(TEXT_DOMAIN,
				    "%s failed to restart\n"),
				    service);
			}
		}
	}
}

static int
is_a_number(char *number)
{
	int ret = 1;
	int hex = 0;

	if (strncmp(number, "0x", 2) == 0) {
		number += 2;
		hex = 1;
	} else if (*number == '-') {
		number++; /* skip the minus */
	}
	while (ret == 1 && *number != '\0') {
		if (hex) {
			ret = isxdigit(*number++);
		} else {
			ret = isdigit(*number++);
		}
	}
	return (ret);
}

/*
 * fixcaselower(str)
 *
 * convert a string to lower case (inplace).
 */

static void
fixcaselower(char *str)
{
	while (*str) {
		*str = tolower(*str);
		str++;
	}
}

/*
 * skipwhitespace(str)
 *
 * Skip leading white space. It is assumed that it is called with a
 * valid pointer.
 */
static char *
skipwhitespace(char *str)
{
	while (*str && isspace(*str))
		str++;

	return (str);
}

/*
 * extractprop()
 *
 * Extract the property and value out of the line and create the
 * property in the optionset.
 */
static int
extractprop(char *name, char *value)
{
	sa_property_t prop;
	int index;
	int ret = SA_OK;
	/*
	 * Remove any leading
	 * white space.
	 */
	name = skipwhitespace(name);

	index = findprotoopt(name);
	if (index >= 0) {
		fixcaselower(name);
		prop = sa_create_property(proto_options[index].name, value);
		if (prop != NULL)
			ret = sa_add_protocol_property(protoset, prop);
		else
			ret = SA_NO_MEMORY;
	}
	return (ret);
}

static int
initautofsprotofromsmf(void)
{
	char name[PATH_MAX];
	char value[PATH_MAX];
	int ret = SA_OK, bufsz = 0, i;
	char *instance = NULL;
	scf_type_t sctype;

	protoset = sa_create_protocol_properties("autofs");
	if (protoset != NULL) {
		for (i = 0; proto_options[i].tag != NULL; i++) {
			bzero(value, PATH_MAX);
			(void) strncpy(name, proto_options[i].name, PATH_MAX);
			sctype = proto_options[i].type;
			bufsz = PATH_MAX;
			ret = autofs_smf_get_prop(name, value,
			    instance, sctype, AUTOFS_FMRI, &bufsz);
			if (ret == SA_OK) {
				ret = extractprop(name, value);
			}
		}
	} else {
		ret = SA_NO_MEMORY;
	}
	return (ret);
}

static int
range_check_validator(int index, char *value)
{
	int ret = SA_OK;
	if (!is_a_number(value)) {
		ret = SA_BAD_VALUE;
	} else {
		int val;
		errno = 0;
		val = strtoul(value, NULL, 0);
		if (errno != 0)
			return (SA_BAD_VALUE);

		if (val < proto_options[index].minval ||
		    val > proto_options[index].maxval)
			ret = SA_BAD_VALUE;
	}
	return (ret);
}

static int
true_false_validator(int index, char *value)
{

#ifdef lint
	index = index;
#endif
	if ((strcasecmp(value, "true") == 0) ||
	    (strcasecmp(value, "on") == 0) ||
	    (strcasecmp(value, "yes") == 0) ||
	    (strcmp(value, "1") == 0) ||
	    (strcasecmp(value, "false") == 0) ||
	    (strcasecmp(value, "off") == 0) ||
	    (strcasecmp(value, "no") == 0) ||
	    (strcmp(value, "0") == 0)) {
		return (SA_OK);
	}
	return (SA_BAD_VALUE);
}

static int
strlen_validator(int index, char *value)
{
	int ret = SA_OK;
	if (value == NULL) {
		if (proto_options[index].minval == 0) {
			return (ret);
		} else {
			return (SA_BAD_VALUE);
		}
	}
	if (strlen(value) > proto_options[index].maxval ||
	    strlen(value) < proto_options[index].minval)
		ret = SA_BAD_VALUE;
	return (ret);
}

static int
autofs_validate_proto_prop(int index, char *name, char *value)
{
#ifdef lint
	name = name;
#endif
	return (proto_options[index].check(index, value));
}

static int
autofs_set_proto_prop(sa_property_t prop)
{
	int ret = SA_OK;
	char *name;
	char *value, *instance = NULL;
	scf_type_t sctype;

	name = sa_get_property_attr(prop, "type");
	value = sa_get_property_attr(prop, "value");
	if (name != NULL && value != NULL) {
		int index = findprotoopt(name);
		if (index >= 0) {
			ret = autofs_validate_proto_prop(index, name, value);
			if (ret == SA_OK) {
				sctype = proto_options[index].type;
				if (sctype == SCF_TYPE_BOOLEAN) {
					if (value != NULL)
						sa_free_attr_string(value);
					if (string_to_boolean(value) == 0)
						value = strdup("0");
					else
						value = strdup("1");
				}
				ret = autofs_smf_set_prop(name, value,
				    instance, sctype, AUTOFS_FMRI);
				/*
				 * Make an instance based FMRI.
				 * For now its DEFAULT_AUTOFS_FMRI.
				 */
				if (ret == SA_OK)
					restart_service(AUTOFS_DEFAULT_FMRI);
			}
		} else {
			ret = SA_NO_SUCH_PROP;
		}
	} else {
		ret = SA_CONFIG_ERR;
	}

	if (name != NULL)
		sa_free_attr_string(name);
	if (value != NULL)
		sa_free_attr_string(value);
	return (ret);
}


static sa_protocol_properties_t
autofs_get_proto_set(void)
{
	return (protoset);
}

static uint64_t
autofs_features(void)
{
	return (0);
}

static char *
autofs_get_status(void)
{
	return (smf_get_state(AUTOFS_DEFAULT_FMRI));
}
